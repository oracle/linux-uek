/*
 * vcc.c: sun4v virtual channel concentrator
 *
 * Copyright (C) 2014 Oracle. All rights reserved.
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <asm/vio.h>
#include <asm/ldc.h>

#define DRV_MODULE_NAME		"vcc"
#define DRV_MODULE_VERSION	"1.0"
#define DRV_MODULE_RELDATE	"July 20, 2014"

static char version[] =
	DRV_MODULE_NAME ".c:v" DRV_MODULE_VERSION " (" DRV_MODULE_RELDATE ")\n";
MODULE_DESCRIPTION("Sun LDOM virtual console concentrator driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_MODULE_VERSION);

struct vcc {
	struct tty_port port;	/* must be first element */
	spinlock_t lock;
	char *domain;

	/*
	 * This buffer is required to support the tty write_room interface
	 * and guarantee that any characters that the driver accepts will
	 * be eventually sent, either immediately or later.
	 */
	int chars_in_buffer;
	struct vio_vcc buffer;

	struct timer_list rx_timer;
	struct timer_list tx_timer;
	struct vio_driver_state	vio;
};

#define VCC_MAX_PORTS	256
#define VCC_MINOR_START	0
#define VCC_BUFF_LEN	VIO_VCC_MTU_SIZE

#define	VCC_CTL_BREAK	-1
#define	VCC_CTL_HUP	-2

#define	TIMER_SET(v, x, t)	((v)->x##_timer.expires = (t))
#define	TIMER_CLEAR(v, x)	((v)->x##_timer.expires = 0)
#define	TIMER_ACTIVE(v, x)	((v)->x##_timer.expires)

static const char vcc_driver_name[] = "vcc";
static const char vcc_device_node[] = "vcc";
static struct tty_driver *vcc_tty_driver;

int vcc_dbg;
int vcc_dbg_ldc;
int vcc_dbg_vio;

module_param(vcc_dbg, uint, 0664);
module_param(vcc_dbg_ldc, uint, 0664);
module_param(vcc_dbg_vio, uint, 0664);

#define	VCC_DBG_DRV	0x1
#define	VCC_DBG_LDC	0x2
#define	VCC_DBG_PKT	0x4

#define vccdbg(f, a...)							\
	do {								\
		if (vcc_dbg & VCC_DBG_DRV)				\
			pr_info(f, ## a);				\
	} while (0)							\

#define vccdbgl(l)							\
	do {								\
		if (vcc_dbg & VCC_DBG_LDC)				\
			ldc_print(l);					\
	} while (0)							\

#define vccdbgp(pkt)							\
	do {								\
		if (vcc_dbg & VCC_DBG_PKT) {				\
			int i;						\
			for (i = 0; i < pkt.tag.stype; i++)		\
				pr_info("[%c]", pkt.data[i]);		\
		}							\
	} while (0)							\

/*
 * xxx Be careful when adding flags to this line discipline.  Don't add anything
 * that will cause echoing or we'll go into recursive loop echoing chars back
 * and forth with the console drivers.
 */
static struct ktermios vcc_tty_termios = {
	.c_iflag = IGNBRK | IGNPAR,
	.c_oflag = OPOST,
	.c_cflag = B38400 | CS8 | CREAD | HUPCL,
	.c_cc = INIT_C_CC,
	.c_ispeed = 38400,
	.c_ospeed = 38400
};

static void vcc_kick_rx(struct vcc *vcc)
{
	struct vio_driver_state *vio = &vcc->vio;

	vccdbg("%s\n", __func__);

	assert_spin_locked(&vcc->lock);

	if (TIMER_ACTIVE(vcc, rx))
		return;

	/*
	 * Disable interrupts until we can read the data again.
	 */
	ldc_disable_hv_intr(vio->lp);

	TIMER_SET(vcc, rx, jiffies + 1);
	add_timer(&vcc->rx_timer);
}

static void vcc_kick_tx(struct vcc *vcc)
{
	vccdbg("%s\n", __func__);

	assert_spin_locked(&vcc->lock);

	if (TIMER_ACTIVE(vcc, tx))
		return;

	TIMER_SET(vcc, tx, jiffies + 1);
	add_timer(&vcc->tx_timer);
}

static int vcc_rx_check(struct tty_struct *tty, int size)
{
	BUG_ON(!tty);

	/*
	 * tty_buffer_request_room eventually calls kmalloc with GFP_ATOMIC
	 * so it won't sleep.
	 */
	if (test_bit(TTY_THROTTLED, &tty->flags) ||
	    tty_buffer_request_room(tty->port, VCC_BUFF_LEN) < VCC_BUFF_LEN)
		return 0;

	return 1;
}

static int vcc_rx(struct tty_struct *tty, char *buf, int size)
{
	int len;

	BUG_ON(!tty);

	/*
	 * tty_insert_flig_string... calls __tty_buffer_request_room.
	 */
	len = tty_insert_flip_string(tty->port, buf, size);

	/* This is synch because tty->low_latency == 1 */
	if (len)
		tty_flip_buffer_push(tty->port);

	vccdbg("%s: rv=%d\n", __func__, len);

	return len;
}

static int vcc_ldc_read(struct vcc *vcc)
{
	struct vio_driver_state *vio = &vcc->vio;
	struct tty_struct *tty;
	struct vio_vcc pkt;
	int rv = 0;
	vccdbg("%s\n", __func__);

	tty = vcc->port.tty;
	if (!tty) {
		rv = ldc_rx_reset(vio->lp);
		vccdbg("%s: reset rx q: rv=%d\n", __func__, rv);
		goto done;
	}

	/*
	 * Read as long as the LDC has incoming data.
	 * xxx Since we read in interrupt context, should we defer to
	 * a lower IRQ level?
	 */
	while (1) {
		if (!vcc_rx_check(tty, VIO_VCC_MTU_SIZE)) {
			vcc_kick_rx(vcc);
			break;
		}
		vccdbgl(vio->lp);
		rv = ldc_read(vio->lp, &pkt, sizeof(pkt));
		if (rv <= 0)
			break;

		vccdbg("%s: ldc_read()=%d\n", __func__, rv);
		vccdbg("TAG [%02x:%02x:%04x:%08x]\n",
		       pkt.tag.type,
		       pkt.tag.stype,
		       pkt.tag.stype_env,
		       pkt.tag.sid);

		if (pkt.tag.type == VIO_TYPE_DATA) {
			/*
			 * We called vcc_rx_check before which should allocate
			 * space so this should not fail.
			 */
			vccdbgp(pkt);
			vcc_rx(tty, pkt.data, pkt.tag.stype);
		} else {
			pr_err("%s: unknown msg [%02x:%02x:%04x:%08x]\n",
				__func__, pkt.tag.type, pkt.tag.stype,
				pkt.tag.stype_env, pkt.tag.sid);

			rv = -ECONNRESET;
			break;
		}
		BUG_ON(rv != LDC_PACKET_SIZE);
	}
done:
	vccdbg("%s: rv=%d\n", __func__, rv);
	return rv;
}

static void vcc_rx_timer(unsigned long arg)
{
	struct vcc *vcc = (struct vcc *)arg;
	struct vio_driver_state *vio = &vcc->vio;
	unsigned long flags;
	int rv;

	vccdbg("%s\n", __func__);
	spin_lock_irqsave(&vcc->lock, flags);
	TIMER_CLEAR(vcc, rx);

	/*
	 * Re-enable interrupts.
	 */
	ldc_enable_hv_intr(vio->lp);

	rv = vcc_ldc_read(vcc);
	if (rv < 0) {
		struct vio_driver_state *vio = &vcc->vio;

		if (rv == -ECONNRESET)
			vio_conn_reset(vio);	/* xxx noop */
	}
	spin_unlock_irqrestore(&vcc->lock, flags);
	vccdbg("%s done\n", __func__);
}

static void vcc_tx_timer(unsigned long arg)
{
	struct vcc *vcc = (struct vcc *)arg;
	struct vio_vcc *pkt;
	unsigned long flags;
	int tosend = 0;
	int rv;

	vccdbg("%s\n", __func__);
	if (!vcc) {
		pr_err("%s: vcc not found\n", __func__);
		return;
	}

	spin_lock_irqsave(&vcc->lock, flags);
	TIMER_CLEAR(vcc, tx);

	tosend = min(VCC_BUFF_LEN, vcc->chars_in_buffer);
	if (!tosend)
		goto done;

	pkt = &vcc->buffer;
	pkt->tag.type = VIO_TYPE_DATA;
	pkt->tag.stype = tosend;
	vccdbgl(vcc->vio.lp);

	/* won't send partial writes */
	rv = ldc_write(vcc->vio.lp, pkt, VIO_TAG_SIZE + tosend);
	BUG_ON(!rv);

	if (rv < 0) {
		vccdbg("%s: ldc_write()=%d\n", __func__, rv);
		vcc_kick_tx(vcc);
	} else {
		struct tty_struct *tty = vcc->port.tty;

		vcc->chars_in_buffer = 0;

		/*
		 * We are still obligated to deliver the data to the
		 * hypervisor even if the tty has been closed because
		 * we committed to delivering it.  But don't try to wake
		 * a non-existent tty.
		 */
		if (tty)
			tty_wakeup(tty);
	}
done:
	spin_unlock_irqrestore(&vcc->lock, flags);
	vccdbg("%s done\n", __func__);
}

static void vcc_event(void *arg, int event)
{
	struct vcc *vcc = arg;
	struct vio_driver_state *vio = &vcc->vio;
	unsigned long flags;
	int rv;

	vccdbg("%s(%d)\n", __func__, event);
	spin_lock_irqsave(&vcc->lock, flags);

	if (event == LDC_EVENT_RESET || event == LDC_EVENT_UP) {
		vio_link_state_change(vio, event);
		spin_unlock_irqrestore(&vcc->lock, flags);
		return;
	}

	if (event != LDC_EVENT_DATA_READY) {
		pr_err("%s: unexpected LDC event %d\n", __func__, event);
		spin_unlock_irqrestore(&vcc->lock, flags);
		return;
	}

	rv = vcc_ldc_read(vcc);
	if (rv < 0) {
		if (rv == -ECONNRESET)
			vio_conn_reset(vio);	/* xxx noop */
	}
	spin_unlock_irqrestore(&vcc->lock, flags);
}

static struct ldc_channel_config vcc_ldc_cfg = {
	.event		= vcc_event,
	.mtu		= VIO_VCC_MTU_SIZE,
	.mode		= LDC_MODE_RAW,
	.debug		= 0,
};

/* Ordered from largest major to lowest */
static struct vio_version vcc_versions[] = {
	{ .major = 1, .minor = 0 },
};

static struct tty_port_operations vcc_port_ops = { 0 };

static ssize_t vcc_sysfs_domain_show(struct device *device,
	struct device_attribute *attr, char *buf)
{
	int rv;
	unsigned long flags;
	struct vcc *vcc = dev_get_drvdata(device);

	spin_lock_irqsave(&vcc->lock, flags);
	rv = scnprintf(buf, PAGE_SIZE, "%s\n", vcc->domain);
	spin_unlock_irqrestore(&vcc->lock, flags);

	return rv;
}

static int vcc_send_ctl(struct vcc *vcc, int ctl)
{
	int rv;
	struct vio_vcc pkt;

	pkt.tag.type = VIO_TYPE_CTRL;
	pkt.tag.sid = ctl;	/* ctrl_msg */
	pkt.tag.stype = 0;	/* size */

	rv = ldc_write(vcc->vio.lp, &pkt, sizeof(pkt.tag));
	BUG_ON(!rv);
	vccdbg("%s: ldc_write(%ld)=%d\n", __func__, sizeof(pkt.tag), rv);

	return rv;
}

static ssize_t vcc_sysfs_break_store(struct device *device,
	struct device_attribute *attr, const char *buf, size_t count)
{
	int rv = count;
	int brk;
	unsigned long flags;
	struct vcc *vcc = dev_get_drvdata(device);

	spin_lock_irqsave(&vcc->lock, flags);

	if (sscanf(buf, "%ud", &brk) != 1 || brk != 1)
		rv = -EINVAL;
	else if (vcc_send_ctl(vcc, VCC_CTL_HUP) < 0)
		vcc_kick_tx(vcc);

	spin_unlock_irqrestore(&vcc->lock, flags);

	return count;
}

static DEVICE_ATTR(domain, S_IRUSR, vcc_sysfs_domain_show, NULL);
static DEVICE_ATTR(break, S_IWUSR, NULL, vcc_sysfs_break_store);

static struct attribute *vcc_sysfs_entries[] = {
	&dev_attr_domain.attr,
	&dev_attr_break.attr,
	NULL
};

static struct attribute_group vcc_attribute_group = {
	.name = NULL, 	/* put in device directory */
	.attrs = vcc_sysfs_entries,
};

static void print_version(void)
{
	printk_once(KERN_INFO "%s", version);
}

static int vcc_probe(struct vio_dev *vdev,
	const struct vio_device_id *id)
{
	int rv;
	char *name;
	const char *domain;
	struct vcc *vcc;
	struct device *dev;
	struct mdesc_handle *hp;
	u64 node;

	print_version();

	vccdbg("%s: name=%s port=%ld\n", __func__, dev_name(&vdev->dev),
	       vdev->port_id);

	if (vdev->port_id >= VCC_MAX_PORTS)
		return -ENXIO;

	if (!vcc_tty_driver) {
		pr_err("%s: vcc tty driver not registered\n", __func__);
		return -ENODEV;
	}

	vcc = kzalloc(sizeof(*vcc), GFP_KERNEL);
	if (!vcc) {
		pr_err("%s: cannot allocate vcc\n", __func__);
		return -ENOMEM;
	}

	name = kstrdup(dev_name(&vdev->dev), GFP_KERNEL);
	rv = vio_driver_init(&vcc->vio, vdev, VDEV_CONSOLE_CON,
			      vcc_versions, ARRAY_SIZE(vcc_versions),
			      NULL, name);
	if (rv)
		goto free_port;

	vcc->vio.debug = vcc_dbg_vio;
	vcc_ldc_cfg.debug = vcc_dbg_ldc;

	rv = vio_ldc_alloc(&vcc->vio, &vcc_ldc_cfg, vcc);
	if (rv)
		goto free_port;

	tty_port_init(&vcc->port);
	spin_lock_init(&vcc->lock);
	vcc->port.ops = &vcc_port_ops;

	dev = tty_port_register_device(&vcc->port, vcc_tty_driver,
		vdev->port_id, &vdev->dev);
	if (IS_ERR(dev)) {
		rv = PTR_ERR(dev);
		goto free_ldc;
	}

	hp = mdesc_grab();

	node = vio_vdev_node(hp, vdev);
	if (node == MDESC_NODE_NULL) {
		rv = -ENXIO;
		mdesc_release(hp);
		goto unreg_tty;
	}

	domain = mdesc_get_property(hp, node, "vcc-domain-name", NULL);
	if (!domain) {
		rv  = -ENXIO;
		mdesc_release(hp);
		goto unreg_tty;
	}
	vcc->domain = kstrdup(domain, GFP_KERNEL);

	mdesc_release(hp);

	rv = sysfs_create_group(&vdev->dev.kobj, &vcc_attribute_group);
	if (rv)
		goto remove_sysfs;

	init_timer(&vcc->rx_timer);
	vcc->rx_timer.function = vcc_rx_timer;
	vcc->rx_timer.data = (unsigned long)vcc;

	init_timer(&vcc->tx_timer);
	vcc->tx_timer.function = vcc_tx_timer;
	vcc->tx_timer.data = (unsigned long)vcc;

	dev_set_drvdata(&vdev->dev, vcc);

	/*
	 * Disable interrupts before the port is up.
	 *
	 * We can get an interrupt during vio_port_up() -> ldc_bind().
	 * vio_port_up() grabs the vio->lock beforehand so we cannot
	 * grab it in vcc_event().
	 *
	 * Once the port is up and the lock released, we can field
	 * interrupts.
	 */
	ldc_disable_hv_intr(vcc->vio.lp);
	vio_port_up(&vcc->vio);
	ldc_enable_hv_intr(vcc->vio.lp);

	return 0;

remove_sysfs:
	sysfs_remove_group(&vdev->dev.kobj, &vcc_attribute_group);
	kfree(vcc->domain);

unreg_tty:
	tty_unregister_device(vcc_tty_driver, vdev->port_id);

free_ldc:
	vio_ldc_free(&vcc->vio);

free_port:
	kfree(name);
	kfree(vcc);

	return rv;
}

static int vcc_remove(struct vio_dev *vdev)
{
	struct vcc *vcc = dev_get_drvdata(&vdev->dev);
	struct tty_struct *tty;
	unsigned long flags;

	vccdbg("%s\n", __func__);

	if (!vcc)
		return -ENODEV;

	del_timer_sync(&vcc->rx_timer);
	del_timer_sync(&vcc->tx_timer);

	spin_lock_irqsave(&vcc->lock, flags);
	tty = vcc->port.tty;
	spin_unlock_irqrestore(&vcc->lock, flags);

	if (tty)
		tty_hangup(tty);

	tty_unregister_device(vcc_tty_driver, vdev->port_id);

	del_timer_sync(&vcc->vio.timer);
	vio_ldc_free(&vcc->vio);
	sysfs_remove_group(&vdev->dev.kobj, &vcc_attribute_group);
	dev_set_drvdata(&vdev->dev, NULL);

	kfree(vcc->vio.name);
	kfree(vcc->domain);
	kfree(vcc);

	return 0;
}

static const struct vio_device_id vcc_match[] = {
	{
		.type = "vcc-port",
	},
	{},
};
MODULE_DEVICE_TABLE(vio, vcc_match);

static struct vio_driver vcc_driver = {
	.id_table	= vcc_match,
	.probe		= vcc_probe,
	.remove		= vcc_remove,
	.name		= "vcc",
};

static int vcc_open(struct tty_struct *tty, struct file *filp)
{
	struct vcc *vcc;
	int rv, count;

	vccdbg("%s\n", __func__);
	if (!tty) {
		pr_err("%s: NULL tty\n", __func__);
		return -ENXIO;
	}

	if (!tty->port) {
		pr_err("%s: NULL tty port\n", __func__);
		return -ENXIO;
	}
	if (!tty->port->ops) {
		pr_err("%s: NULL tty port ops\n", __func__);
		return -ENXIO;
	}

	vcc = container_of(tty->port, struct vcc, port);

	if (!vcc->vio.lp) {
		pr_err("%s: NULL lp\n", __func__);
		return -ENXIO;
	}
	vccdbgl(vcc->vio.lp);

	/*
	 * vcc_close is called even if vcc_open fails so call
	 * tty_port_open() regardless in case of -EBUSY.
	 */
	count = tty->port->count;
	if (count)
		pr_err("%s: tty port busy\n", __func__);
	rv = tty_port_open(tty->port, tty, filp);
	if (rv == 0 && count != 0)
		rv = -EBUSY;

	return rv;

}

static void vcc_close(struct tty_struct *tty, struct file *filp)
{
	vccdbg("%s\n", __func__);
	if (!tty) {
		pr_err("%s: NULL tty\n", __func__);
		return;
	}
	if (!tty->port) {
		pr_err("%s: NULL tty port\n", __func__);
		return;
	}
	tty_port_close(tty->port, tty, filp);
}

static void vcc_ldc_hup(struct vcc *vcc)
{
	unsigned long flags;

	vccdbg("%s\n", __func__);

	spin_lock_irqsave(&vcc->lock, flags);

	if (vcc_send_ctl(vcc, VCC_CTL_HUP) < 0)
		vcc_kick_tx(vcc);

	spin_unlock_irqrestore(&vcc->lock, flags);
}

static void vcc_hangup(struct tty_struct *tty)
{
	struct vcc *vcc = container_of(tty->port, struct vcc, port);

	vcc_ldc_hup(vcc);
	tty_port_hangup(tty->port);
}

static int vcc_write(struct tty_struct *tty,
		const unsigned char *buf, int count)
{
	struct vcc *vcc = container_of(tty->port, struct vcc, port);
	struct vio_vcc *pkt;
	unsigned long flags;
	int total_sent = 0;
	int tosend = 0;
	int rv = -EINVAL;

	vccdbg("%s\n", __func__);

	spin_lock_irqsave(&vcc->lock, flags);

	pkt = &vcc->buffer;
	pkt->tag.type = VIO_TYPE_DATA;

	while (count > 0) {
		tosend = min(count, (VCC_BUFF_LEN - vcc->chars_in_buffer));
		/*
		 * No more space, this probably means that the last call to
		 * vcc_write() didn't succeed and the buffer was filled up.
		 */
		if (!tosend)
			break;

		memcpy(&pkt->data[vcc->chars_in_buffer],
			&buf[total_sent],
			tosend);

		vcc->chars_in_buffer += tosend;

		pkt->tag.stype = tosend;
		vccdbg("TAG [%02x:%02x:%04x:%08x]\n",
		       pkt->tag.type,
		       pkt->tag.stype,
		       pkt->tag.stype_env,
		       pkt->tag.sid);
		vccdbg("DATA [%s]\n", pkt->data);
		vccdbgl(vcc->vio.lp);

		/* won't send partial writes */
		rv = ldc_write(vcc->vio.lp, pkt, VIO_TAG_SIZE + tosend);
		vccdbg("%s: ldc_write(%ld)=%d\n", __func__,
		       VIO_TAG_SIZE + tosend, rv);

		/*
		 * Since we know we have enough room in vcc->buffer for
		 * tosend we record that it was sent regardless of whether the
		 * hypervisor actually took it because we have it buffered.
		 */
		total_sent += tosend;
		count -= tosend;
		if (rv < 0) {
			vcc_kick_tx(vcc);
			break;
		}

		vcc->chars_in_buffer = 0;
	}

	spin_unlock_irqrestore(&vcc->lock, flags);

	vccdbg("%s: total=%d rv=%d\n", __func__, total_sent, rv);

	return total_sent ? total_sent : rv;
}

static int vcc_write_room(struct tty_struct *tty)
{
	struct vcc *vcc = container_of(tty->port, struct vcc, port);

	return VCC_BUFF_LEN - vcc->chars_in_buffer;
}

static int vcc_chars_in_buffer(struct tty_struct *tty)
{
	struct vcc *vcc = container_of(tty->port, struct vcc, port);

	return vcc->chars_in_buffer;
}

static int vcc_break_ctl(struct tty_struct *tty, int state)
{
	struct vcc *vcc = container_of(tty->port, struct vcc, port);
	unsigned long flags;

	vccdbg("%s(%d)\n", __func__, state);

	if (state == 0)		/* turn off break */
		return 0;

	spin_lock_irqsave(&vcc->lock, flags);

	if (vcc_send_ctl(vcc, VCC_CTL_BREAK) < 0)
		vcc_kick_tx(vcc);

	spin_unlock_irqrestore(&vcc->lock, flags);

	return 0;
}

static const struct tty_operations vcc_ops = {
	.open = vcc_open,
	.close = vcc_close,
	.hangup = vcc_hangup,
	.write = vcc_write,
	.write_room = vcc_write_room,
	.chars_in_buffer = vcc_chars_in_buffer,
	.break_ctl = vcc_break_ctl
};

/*
 * We want to dynamically manage our ports through the tty_port_*
 * interfaces so we allocate and register/unregister on our own.
 */
#define	VCC_TTY_FLAGS	(TTY_DRIVER_DYNAMIC_DEV | TTY_DRIVER_REAL_RAW)

static int vcc_tty_init(void)
{
	int rv;

	vcc_tty_driver = tty_alloc_driver(VCC_MAX_PORTS, VCC_TTY_FLAGS);

	if (!vcc_tty_driver) {
		pr_err("%s: tty driver alloc failed\n", __func__);
		return -ENOMEM;
	}

	vcc_tty_driver->driver_name = vcc_driver_name;
	vcc_tty_driver->name = vcc_device_node;

	/*
	 * We'll let the system assign us a major number, indicated by leaving
	 * it blank.
	 */
	vcc_tty_driver->minor_start = VCC_MINOR_START;
	vcc_tty_driver->type = TTY_DRIVER_TYPE_SYSTEM;
	vcc_tty_driver->init_termios = vcc_tty_termios;

	tty_set_operations(vcc_tty_driver, &vcc_ops);

	/*
	 * The following call will result in sysfs entries that denote the
	 * dynamically assigned major and minor numbers for our devices.
	 */
	rv = tty_register_driver(vcc_tty_driver);
	if (!rv) {
		vccdbg("%s: tty driver registered\n", __func__);
		return 0;
	}

	pr_err("%s: tty driver register failed\n", __func__);

	tty_unregister_driver(vcc_tty_driver);
	put_tty_driver(vcc_tty_driver);
	vcc_tty_driver = NULL;

	return rv;
}

static void vcc_tty_exit(void)
{
	vccdbg("%s\n", __func__);

	tty_unregister_driver(vcc_tty_driver);
	put_tty_driver(vcc_tty_driver);
	vccdbg("%s: tty driver unregistered\n", __func__);

	vcc_tty_driver = NULL;
}

static int __init vcc_init(void)
{
	int rv;

	vccdbg("%s\n", __func__);

	rv = vcc_tty_init();
	if (rv) {
		pr_err("%s: vcc_tty_init failed (%d)\n", __func__, rv);
		return rv;
	}

	rv = vio_register_driver(&vcc_driver);
	if (rv) {
		pr_err("%s: vcc driver register failed (%d)\n", __func__, rv);
		vcc_tty_exit();
	} else {
		vccdbg("%s: vcc driver registered\n", __func__);
	}

	return rv;
}

static void __exit vcc_exit(void)
{
	vccdbg("%s\n", __func__);
	vio_unregister_driver(&vcc_driver);
	vccdbg("%s: vcc vio driver unregistered\n", __func__);
	vcc_tty_exit();
	vccdbg("%s: vcc tty driver unregistered\n", __func__);
}

module_init(vcc_init);
module_exit(vcc_exit);
