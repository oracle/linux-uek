/*
 * vldc.c: Sun4v Virtual LDC (Logical Domain Channel) Driver
 *
 * Copyright (C) 2014 Oracle. All rights reserved.
 */

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/sysfs.h>
#include <linux/ioctl.h>
#include <linux/vldc.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <asm/mdesc.h>
#include <asm/vio.h>
#include <asm/ldc.h>


#define VLDC_DEBUG 1   /* force VLDC_DEBUG on for development */

#ifdef VLDC_DEBUG
static bool vldcdbg;
module_param(vldcdbg, bool, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(vldcdbg, "Boolean to enable debug messages (0 == off, 1 == on)");

#define dprintk(fmt, args...) do {\
if (vldcdbg)\
	printk(KERN_ERR "%s: " fmt, __func__, ##args);\
} while (0)

#else
#define dprintk(fmt, args...)
#endif /* VLDC_DEBUG */

#define DRV_NAME		"vldc"
#define DRV_VERSION		"1.0"
#define VLDC_DEVICE_NAME DRV_NAME

#define VLDC_MINOR_BASE 0
#define VLDC_MAX_DEVS 64  /* Arbitrary # - hopefully enough */

#define	VLDC_DEFAULT_MTU	0x1000   /* default mtu size 4K */
#define VLDC_MAX_MTU		(256 * 1024) /* 256K */
#define	VLDC_DEFAULT_MODE	LDC_MODE_RAW
#define VLDC_MAX_COOKIE         (256 * 1024) /* 256K */

/* Time (in ms) to sleep waiting for write space to become available */
#define VLDC_WRITE_BLOCK_SLEEP_DELAY 1

/* Timeout (in ms) to sleep waiting for LDC connection to complete */
#define VLDC_CONNECTION_TIMEOUT 10000

static char driver_version[] = DRV_NAME ".c:v" DRV_VERSION "\n";

/* Global driver data struct for data common to all devices */
struct vldc_driver_data {
	struct list_head	vldc_dev_list; /* list of all vldc devices */
	int			num_vldc_dev_list;
	struct class		*chrdev_class;
	dev_t			devt;
};
struct vldc_driver_data vldc_data;
static DEFINE_MUTEX(vldc_data_mutex); /* protect vldc_data */

/*
 * VLDC device struct. Each vldc device which is probed
 * will have one of these structs associated with it.
 * Integer type fields which could possibly be accessed by more
 * than 1 thread simultaneously are declared as type atomic_t
 * to assure atomic access.
 */
struct vldc_dev {
	/* link into the global driver data dev list */
	struct list_head	list;

	struct mutex            vldc_mutex;
	struct cdev		cdev;
	char			*tx_buf;
	char			*rx_buf;
	dev_t			devt;
	char			*name;
	struct device		*device;
	struct vio_dev		*vdev;
	struct ldc_channel	*lp;
	atomic_t		mtu;
	atomic_t		mode;

	/* each device gets its own read cookie buf */
	void                    *cookie_read_buf;

	/* each device gets its own write cookie buf */
	void                    *cookie_write_buf;

	/* waitqueue for poll() or blocking read() operations */
	wait_queue_head_t	waitqueue;

	/* atomic var to indicate if the device is released - i.e. not open */
	atomic_t		is_released;

	/* atomic var to indicate if reset has been asserted on the device */
	atomic_t		is_reset_asserted;
};

static bool vldc_will_write_block(struct vldc_dev *vldc, size_t count)
{
	if (atomic_read(&vldc->is_released) ||
	    atomic_read(&vldc->is_reset_asserted)) {
		/* device was released or reset, exit */
		return false;
	}

	return !ldc_tx_space_available(vldc->lp, count);
}

static int vldc_ldc_send(struct vldc_dev *vldc, void *data, int len)
{
	int err, limit = 1000;

	err = -EINVAL;
	while (limit-- > 0) {
		err = ldc_write(vldc->lp, data, len);
		if (!err || (err != -EAGAIN))
			break;
		udelay(1);
	}

	return err;
}

static ssize_t vldc_fops_write(struct file *filp, const char __user *ubuf,
			       size_t count, loff_t *off)
{
	struct vldc_dev *vldc;
	int rv;
	char *ubufp;
	int nbytes_written;
	int nbytes_left;
	size_t size;

	dprintk("entered.\n");

	/* validate args */
	if (filp == NULL || ubuf == NULL)
		return -EINVAL;

	nbytes_written = 0; /* number of bytes written */

	vldc = filp->private_data;
	rv = 0;

	/*
	 * If the device has been released/closed
	 * or has been reset, exit with error.
	 */
	if (atomic_read(&vldc->is_released)) {
		rv = -ENODEV;
		goto done;
	}

	if (atomic_read(&vldc->is_reset_asserted)) {
		rv = -EIO;
		goto done;
	}

	if (vldc_will_write_block(vldc, count) &&
	    (filp->f_flags & O_NONBLOCK)) {
		rv = -EAGAIN;
		goto done;
	}

	/*
	 * Loop here waiting for write space to become available.
	 * NOTE: we can't wait on an event here because there is no event
	 * to indicate that write space has become available.
	 */
	while (vldc_will_write_block(vldc, count)) {
		msleep_interruptible(VLDC_WRITE_BLOCK_SLEEP_DELAY);
		if (signal_pending(current)) {
			/* task caught a signal during the sleep - abort. */
			rv = -EINTR;
			goto done;
		}
	}

	/*
	 * Check again if the device has been released/closed
	 * or has been reset while we were waiting.
	 */
	if (atomic_read(&vldc->is_released)) {
		rv = -ENODEV;
		goto done;
	}

	if (atomic_read(&vldc->is_reset_asserted)) {
		rv = -EIO;
		goto done;
	}

	nbytes_left = count; /* number of bytes left to write */
	ubufp = (char *)ubuf;

	while (nbytes_left > 0) {

		/* NOTE: RAW mode can only write max size of LDC_PACKET_SIZE */
		if (atomic_read(&vldc->mode) == LDC_MODE_RAW)
			size = min_t(int, LDC_PACKET_SIZE, nbytes_left);
		else
			size = min_t(int, atomic_read(&vldc->mtu), nbytes_left);

		if (copy_from_user(vldc->tx_buf, ubufp, size) != 0) {
			rv = -EFAULT;
			goto done;
		}

		rv = vldc_ldc_send(vldc, vldc->tx_buf, size);

		dprintk("(%s) ldc_write() returns %d\n", vldc->name, rv);

		if (unlikely(rv < 0))
			break;

		if (unlikely(rv == 0))
			break;

		ubufp += rv;
		nbytes_written += rv;
		nbytes_left -= rv;
	}

	/* Return any data written (even if we got a subsequent error) */
	if (nbytes_written > 0)
		rv = nbytes_written;

done:

	dprintk("(%s) num bytes written=%d, return value=%d\n",
		vldc->name, nbytes_written, rv);

	return (ssize_t)rv;
}

static bool vldc_will_read_block(struct vldc_dev *vldc)
{

	if (atomic_read(&vldc->is_released) ||
	    atomic_read(&vldc->is_reset_asserted)) {
		/* device was released or reset, exit */
		return false;
	}

	return !ldc_rx_data_available(vldc->lp);
}

static ssize_t vldc_fops_read(struct file *filp, char __user *ubuf,
			      size_t count, loff_t *offp)
{
	struct vldc_dev *vldc;
	int rv;
	char *ubufp;
	int nbytes_read;
	int nbytes_left;
	size_t size;

	dprintk("entered.\n");

	/* validate args */
	if (filp == NULL || ubuf == NULL)
		return -EINVAL;

	nbytes_read = 0; /* number of bytes read */

	vldc = filp->private_data;
	rv = 0;

	/*  Per spec if reading 0 bytes, just return 0. */
	if (count == 0) {
		rv = 0;
		goto done;
	}

	/*
	 * If the device has been released/closed or
	 * has been reset, exit with error.
	 */
	if (atomic_read(&vldc->is_released)) {
		rv = -ENODEV;
		goto done;
	}

	if (atomic_read(&vldc->is_reset_asserted)) {
		rv = -EIO;
		goto done;
	}

	if (vldc_will_read_block(vldc) && (filp->f_flags & O_NONBLOCK)) {
		rv = -EAGAIN;
		goto done;
	}

	/*
	 * NOTE: this will only wait if the vldc_will_read_block
	 * initially returns true
	 */
	rv = wait_event_interruptible(vldc->waitqueue,
				      !vldc_will_read_block(vldc));
	if (rv < 0)
		goto done;

	/*
	 * Check again if the device has been released/closed
	 * or has been reset while we were waiting
	 */
	if (atomic_read(&vldc->is_released)) {
		/* device was released, exit */
		rv = -ENODEV;
		goto done;
	}

	if (atomic_read(&vldc->is_reset_asserted)) {
		rv = -EIO;
		goto done;
	}

	nbytes_left = count; /* number of bytes left to read */
	ubufp = (char *)ubuf;

	/* read count bytes or until LDC has no more read data (or error) */
	while (nbytes_left > 0) {

		/* NOTE: RAW mode can only read min size of LDC_PACKET_SIZE */
		if (atomic_read(&vldc->mode) == LDC_MODE_RAW)
			size = max_t(int, LDC_PACKET_SIZE, nbytes_left);
		else
			size = min_t(int, atomic_read(&vldc->mtu), nbytes_left);

		rv = ldc_read(vldc->lp, vldc->rx_buf, size);

		dprintk("(%s) ldc_read() returns %d\n", vldc->name, rv);

		if (unlikely(rv < 0))
			break;

		if (unlikely(rv == 0))
			break;

		if (copy_to_user(ubufp, vldc->rx_buf, rv) != 0) {
			rv = -EFAULT;
			goto done;
		}

		ubufp += rv;
		nbytes_read += rv;
		nbytes_left -= rv;
	}

	/* Return any data read (even if we got a subsequent error) */
	if (nbytes_read > 0)
		rv = nbytes_read;

done:

	dprintk("(%s) num bytes read=%d, return value=%d\n",
		vldc->name, nbytes_read, rv);

	/* re-enable interrupts */
	ldc_enable_hv_intr(vldc->lp);

	return (ssize_t)rv;

}

static unsigned int vldc_fops_poll(struct file *filp, poll_table *wait)
{
	struct vldc_dev *vldc;
	int mask;

	dprintk("entered.\n");

	vldc = filp->private_data;

	/*
	 * XXX For the error cases, should return error codes or POLLHUP?
	 * If the device has been released/closed or has been reset,
	 * exit with error.
	 */
	if (atomic_read(&vldc->is_released))
		return -ENODEV;

	if (atomic_read(&vldc->is_reset_asserted))
		return -EIO;

	poll_wait(filp, &vldc->waitqueue, wait);

	/*
	 * Check again if the device has been released/closed
	 * or has been reset while we were waiting
	 */
	if (atomic_read(&vldc->is_released))
		return -ENODEV;

	if (atomic_read(&vldc->is_reset_asserted))
		return -EIO;

	mask = 0;

	if (!vldc_will_read_block(vldc))
		mask |= POLLIN | POLLRDNORM;

	/* Check that we can write at least MTU bytes */
	if (!vldc_will_write_block(vldc, (size_t)atomic_read(&vldc->mtu)))
		mask |= POLLOUT | POLLWRNORM;

	return mask;
}

static long vldc_read_cookie(struct vldc_dev *vldc, u64 src_addr, u64 dst_addr,
			     u64 len)
{
	struct ldc_trans_cookie cookie;
	int rv;
	char *ubufp;
	u32 nbytes_read;
	u32 nbytes_left;

	dprintk("entered.\n");

	nbytes_read = 0; /* number of bytes read */

	/* validate args */
	if (vldc == NULL || src_addr == 0 || dst_addr == 0) {
		rv = -EINVAL;
		goto done;
	}

	dprintk("(%s) src_addr=0x%llx dst_addr=0x%llx len=0x%llx\n",
		vldc->name, src_addr, dst_addr, len);

	if (atomic_read(&vldc->is_released)) {
		rv = -ENODEV;
		goto done;
	}

	if (atomic_read(&vldc->is_reset_asserted)) {
		rv = -EIO;
		goto done;
	}

	if (len == 0) {
		rv = 0;
		goto done;
	}

	if (unlikely(len > VLDC_MAX_COOKIE)) {
		rv = -E2BIG;
		goto done;
	}

	rv = 0;
	nbytes_left = (u32)len; /* number of bytes left to read */
	ubufp = (char *)src_addr;

	/* copy in len bytes or until LDC has no more read data (or error) */
	while (nbytes_left > 0) {

		cookie.cookie_addr = dst_addr;
		cookie.cookie_size = nbytes_left;

		rv = ldc_copy(vldc->lp, LDC_COPY_IN, vldc->cookie_read_buf,
			      nbytes_left, 0, &cookie, 1);

		dprintk("(%s) ldc_copy() returns %d\n", vldc->name, rv);

		if (unlikely(rv < 0))
			goto done;

		if (unlikely(rv == 0))
			break;

		if (copy_to_user(ubufp, vldc->cookie_read_buf, rv) != 0) {
			rv = -EFAULT;
			goto done;
		}

		ubufp += rv;
		dst_addr += rv;
		nbytes_read += rv;
		nbytes_left -= rv;
	}

	rv = nbytes_read;

done:

	dprintk("(%s) num bytes read=%d, return value=%d\n",
		vldc->name, nbytes_read, rv);

	return rv;

}

static long vldc_write_cookie(struct vldc_dev *vldc, u64 src_addr, u64 dst_addr,
			      u64 len)
{
	struct ldc_trans_cookie cookie;
	int rv;
	char *ubufp;
	u32 nbytes_written;
	u32 nbytes_left;

	dprintk("entered.\n");

	nbytes_written = 0; /* number of bytes written */

	/* validate args */
	if (vldc == NULL || src_addr == 0 || dst_addr == 0) {
		rv = -EINVAL;
		goto done;
	}

	dprintk("(%s) src_addr=0x%llx dst_addr=0x%llx len=0x%llx\n",
		vldc->name, src_addr, dst_addr, len);

	if (atomic_read(&vldc->is_released)) {
		rv = -ENODEV;
		goto done;
	}

	if (atomic_read(&vldc->is_reset_asserted)) {
		rv = -EIO;
		goto done;
	}

	if (len == 0) {
		rv = 0;
		goto done;
	}

	if (unlikely(len > VLDC_MAX_COOKIE)) {
		rv = -E2BIG;
		goto done;
	}

	rv = 0;
	nbytes_left = (u32)len; /* number of bytes left to write */
	ubufp = (char *)src_addr;

	/* copy in len bytes or until LDC has no more read data (or error) */
	while (nbytes_left > 0) {

		if (copy_from_user(vldc->cookie_write_buf,
		    ubufp, nbytes_left) != 0) {
			rv = -EFAULT;
			goto done;
		}

		cookie.cookie_addr = dst_addr;
		cookie.cookie_size = nbytes_left;

		rv = ldc_copy(vldc->lp, LDC_COPY_OUT, vldc->cookie_write_buf,
			      nbytes_left, 0, &cookie, 1);

		dprintk("(%s) ldc_copy() returns %d\n", vldc->name, rv);

		if (unlikely(rv < 0))
			goto done;

		if (unlikely(rv == 0))
			break;

		ubufp += rv;
		dst_addr += rv;
		nbytes_written += rv;
		nbytes_left -= rv;
	}

	rv = nbytes_written;

done:

	dprintk("(%s) num bytes written=%d, return value=%d\n",
		vldc->name, nbytes_written, rv);

	return rv;

}

static long vldc_fops_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long arg)
{

	struct vldc_dev *vldc;
	struct vldc_data_t __user *uarg;
	u64 src_addr;
	u64 dst_addr;
	u64 len;
	int rv;

	dprintk("entered.\n");

	rv = 0;
	src_addr = 0;
	dst_addr = 0;
	len = 0;

	vldc = filp->private_data;

	/* get the arg for the read/write cookie ioctls */
	if (cmd == VLDC_IOCTL_READ_COOKIE || cmd == VLDC_IOCTL_WRITE_COOKIE) {
		uarg = (struct vldc_data_t __user *)arg;
		if (get_user(src_addr, &uarg->src_addr) != 0 ||
		    get_user(dst_addr, &uarg->dst_addr) != 0 ||
		    get_user(len, &uarg->length) != 0) {
			rv = -EFAULT;
			goto done;
		}
	}

	switch (cmd) {
	case VLDC_IOCTL_READ_COOKIE:

		rv = vldc_read_cookie(vldc, src_addr, dst_addr, len);

		break;

	case VLDC_IOCTL_WRITE_COOKIE:

		rv = vldc_write_cookie(vldc, src_addr, dst_addr, len);

		break;

	default:
		rv = -EINVAL;
		break;
	}

done:

	return rv;

}

/*
 * Event function does the following:
 * 1. If data is ready from the LDC, indicate it
 *    in the corresponding device struct.
 * 2. Wake up any (poll or read) waiters on this device
 *
 * NOTE - this routine is called in interrupt context.
 */
static void vldc_event(void *arg, int event)
{
	struct vldc_dev *vldc = arg;

	dprintk("entered.\n");

	dprintk("%s: LDC event %d\n", vldc->name, event);

	if (event == LDC_EVENT_RESET) {
		atomic_set(&vldc->is_reset_asserted, 1);
		return;
	}

	if (event == LDC_EVENT_UP)
		return;

	if (unlikely(event != LDC_EVENT_DATA_READY)) {
		dprintk("Unexpected LDC event %d\n", event);
		return;
	}

	/*
	 *  disable interrupts until we have completed reading the data.
	 *  NOTE: this will hold off all types of events including RESET
	 *  until read has complete. If a device reset occurs within this
	 *  window (while interrupts are disabled), attempts to read/write
	 *  the device should/will fail at the LDC level (since a check is
	 *  at that level - via an HV call - to first ensure the LDC is UP).
	 */

	ldc_disable_hv_intr(vldc->lp);

	/* walkup any read or poll waiters */
	wake_up_interruptible(&vldc->waitqueue);

}


static int vldc_connect(struct ldc_channel *lp)
{
	int timeout;
	int state;

	/* no connection required in RAW mode */
	if (ldc_mode(lp) == LDC_MODE_RAW)
		return 0;

	/*
	 * Issue a ldc_connect to make sure the handshake is initiated.
	 * NOTE: ldc_connect can fail if the LDC connection handshake
	 * completed since we called bind(). So, ignore
	 * ldc_connect() failures.
	 */
	(void) ldc_connect(lp);

	/* wait for the connection to complete */
	timeout = VLDC_CONNECTION_TIMEOUT;
	do {
		state = ldc_state(lp);
		if (state == LDC_STATE_CONNECTED)
			break;
		msleep_interruptible(1);
	} while (timeout-- > 0);

	if (state == LDC_STATE_CONNECTED)
		return 0;
	else
		return -ETIMEDOUT;
}

/*
 * Open function does the following:
 * 1. Alloc and bind LDC to the device (using sysfs parameters)
 */
static int vldc_fops_open(struct inode *inode, struct file *filp)
{
	struct vldc_dev *vldc;
	char *tbuffer;
	char *rbuffer;
	char *crbuffer;
	char *cwbuffer;
	struct ldc_channel_config ldc_cfg;
	struct ldc_channel *lp;
	u32 mtu;
	int rv;
	int err;
	bool ldc_bound;

	dprintk("entered.\n");

	rv = 0;
	ldc_bound = false;
	tbuffer = NULL;
	rbuffer = NULL;
	crbuffer = NULL;
	cwbuffer = NULL;

	vldc = container_of(inode->i_cdev, struct vldc_dev, cdev);

	/* just to be safe, if the device is in reset, deny the open. */
	if (atomic_read(&vldc->is_reset_asserted))
		return -EIO;

	dprintk("(%s)\n", vldc->name);

	/*
	 * We hold the vldc_mutex during the open to prevent
	 * a race with vldc_sysfs_mode_store() and vldc_sysfs_mtu_store().
	 * See comments in those routines for more detail.
	 */
	mutex_lock(&vldc->vldc_mutex);

	/*
	 * Atomically test and mark the device as opened.
	 * This limits the usage of the device to one process at
	 * a time which is good enough for our purposes (and which
	 * simplifies locking).
	 */
	if (!atomic_dec_and_test(&vldc->is_released)) {
		atomic_inc(&vldc->is_released);
		dprintk("failed: Multiple open.\n");
		mutex_unlock(&vldc->vldc_mutex);
		return -EBUSY;
	}

	mutex_unlock(&vldc->vldc_mutex);

	mtu = (u32) atomic_read(&vldc->mtu);

	tbuffer = kzalloc(mtu, GFP_KERNEL);
	if (tbuffer == NULL) {
		dprintk("failed to allocate tbuffer.\n");
		rv = -ENOMEM;
		goto error;
	}
	vldc->tx_buf = tbuffer;

	rbuffer = kzalloc(mtu, GFP_KERNEL);
	if (rbuffer == NULL) {
		dprintk("failed to allocate rbuffer.\n");
		rv = -ENOMEM;
		goto error;
	}
	vldc->rx_buf = rbuffer;

	crbuffer = kzalloc(VLDC_MAX_COOKIE, GFP_KERNEL);
	if (crbuffer == NULL) {
		dprintk("failed to allocate crbuffer.\n");
		rv = -ENOMEM;
		goto error;
	}
	vldc->cookie_read_buf = crbuffer;

	cwbuffer = kzalloc(VLDC_MAX_COOKIE, GFP_KERNEL);
	if (cwbuffer == NULL) {
		dprintk("failed to allocate cwbuffer.\n");
		rv = -ENOMEM;
		goto error;
	}
	vldc->cookie_write_buf = cwbuffer;

	ldc_cfg.event = vldc_event;
	ldc_cfg.mtu = mtu;
	ldc_cfg.mode = atomic_read(&vldc->mode);
	ldc_cfg.debug = 0;
	ldc_cfg.tx_irq = vldc->vdev->tx_irq;
	ldc_cfg.rx_irq = vldc->vdev->rx_irq;
	ldc_cfg.rx_ino = vldc->vdev->rx_ino;
	ldc_cfg.tx_ino = vldc->vdev->tx_ino;
	ldc_cfg.dev_handle = vldc->vdev->dev_handle;

	/* Alloc and init the associated LDC */
	lp = ldc_alloc(vldc->vdev->channel_id, &ldc_cfg, vldc, vldc->name);
	if (IS_ERR(lp)) {
		err = PTR_ERR(lp);
		dprintk("ldc_alloc() failed. err=%d\n", err);
		rv = err;
		goto error;
	}
	vldc->lp = lp;

	rv = ldc_bind(vldc->lp);
	if (rv != 0) {
		dprintk("ldc_bind() failed, err=%d.\n", rv);
		goto error;
	}
	ldc_bound = true;

	rv = vldc_connect(vldc->lp);
	if (rv != 0) {
		dprintk("vldc_connect() failed, err=%d.\n", rv);
		goto error;
	}

	/* tuck away the vldc device for subsequent fops */
	filp->private_data = vldc;

	dprintk("Success.\n");

	return 0;

error:

	if (ldc_bound)
		ldc_unbind(vldc->lp);

	if (vldc->lp != NULL)
		ldc_free(vldc->lp);

	if (cwbuffer != NULL)
		kfree(cwbuffer);

	if (crbuffer != NULL)
		kfree(crbuffer);

	if (rbuffer != NULL)
		kfree(rbuffer);

	if (tbuffer != NULL)
		kfree(tbuffer);

	atomic_inc(&vldc->is_released);

	return rv;

}

static int vldc_fops_release(struct inode *inode, struct file *filp)
{
	struct vldc_dev *vldc;

	dprintk("entered.\n");

	vldc = filp->private_data;

	ldc_unbind(vldc->lp);

	ldc_free(vldc->lp);

	kfree(vldc->cookie_write_buf);

	kfree(vldc->cookie_read_buf);

	kfree(vldc->rx_buf);

	kfree(vldc->tx_buf);

	/* mark the device as released */
	atomic_inc(&vldc->is_released);

	/*
	 * User must close and re-open the device to clear
	 * the reset asserted flag.
	 */
	atomic_set(&vldc->is_reset_asserted, 0);

	/*
	 * Wake up any rogue read or poll waiters.
	 * They will exit (with an error) since is_released is now set.
	 */
	wake_up_interruptible(&vldc->waitqueue);

	return 0;
}

static const struct file_operations vldc_fops = {
	.owner		= THIS_MODULE,
	.open		= vldc_fops_open,
	.release	= vldc_fops_release,
	.poll		= vldc_fops_poll,
	.read		= vldc_fops_read,
	.write		= vldc_fops_write,
	.unlocked_ioctl	= vldc_fops_ioctl,
};

static int vldc_get_next_avail_minor(void)
{
	struct vldc_dev *vldc;
	bool found;
	int i;

	/*
	 * walk the vldc_dev_list list to find the next
	 * lowest available minor.
	 */
	mutex_lock(&vldc_data_mutex);
	for (i = VLDC_MINOR_BASE; i < VLDC_MAX_DEVS; i++) {
		found = false;
		list_for_each_entry(vldc, &vldc_data.vldc_dev_list, list) {
			if (i == MINOR(vldc->devt)) {
				found = true;
				break;
			}
		}
		if (!found) {
			/* found a free minor, use it */
			break;
		}
	}
	mutex_unlock(&vldc_data_mutex);

	if (i == VLDC_MAX_DEVS) {
		dprintk("no more minors left for allocation!\n");
		return -1;
	}

	return i;
}

static ssize_t vldc_sysfs_mode_show(struct device *device,
			      struct device_attribute *attr, char *buffer)
{
	struct vldc_dev *vldc;

	dprintk("entered.\n");

	vldc = dev_get_drvdata(device);

	return scnprintf(buffer, PAGE_SIZE, "%d\n", atomic_read(&vldc->mode));
}

static ssize_t vldc_sysfs_mode_store(struct device *device,
		 struct device_attribute *attr, const char *buf, size_t count)
{
	struct vldc_dev *vldc;
	unsigned int mode;

	dprintk("entered.\n");

	if (sscanf(buf, "%ud", &mode) != 1)
		return -EINVAL;

	/* validate the value from the user */
	if (!(mode == LDC_MODE_RAW ||
	      mode == LDC_MODE_UNRELIABLE ||
	      mode == LDC_MODE_STREAM)) {
		return -EINVAL;
	}

	vldc = dev_get_drvdata(device);

	/*
	 * Only allow the mode to be set if the device is closed.
	 * Use vldc_mutex to ensure that an open does not
	 * come in between the check for is_released and the set
	 * of the mode.
	 */
	mutex_lock(&vldc->vldc_mutex);

	if (!atomic_read(&vldc->is_released)) {
		/* can't change the mode while the device is open */
		mutex_unlock(&vldc->vldc_mutex);
		return -EBUSY;
	}

	atomic_set(&vldc->mode, mode);

	mutex_unlock(&vldc->vldc_mutex);

	dprintk("mode changed to %d.\n", mode);

	return strnlen(buf, count);
}


static ssize_t vldc_sysfs_mtu_show(struct device *device,
			      struct device_attribute *attr, char *buffer)
{
	struct vldc_dev *vldc;

	dprintk("entered.\n");

	vldc = dev_get_drvdata(device);

	return scnprintf(buffer, PAGE_SIZE, "%d\n", atomic_read(&vldc->mtu));
}

static ssize_t vldc_sysfs_mtu_store(struct device *device,
		 struct device_attribute *attr, const char *buf, size_t count)
{
	struct vldc_dev *vldc;
	unsigned int mtu;
	int rv;

	dprintk("entered.\n");

	rv = 0;

	if (sscanf(buf, "%ud", &mtu) != 1)
		return -EINVAL;

	/* validate the value from the user */
	if (mtu < LDC_PACKET_SIZE || mtu > VLDC_MAX_MTU)
		return -EINVAL;

	vldc = dev_get_drvdata(device);

	/*
	 * Only allow the mtu to be set if the device is closed.
	 * Use vldc_mutex to ensure that an open does not
	 * come in between the check for is_released and the set
	 * of the mtu.
	 */
	mutex_lock(&vldc->vldc_mutex);

	if (!atomic_read(&vldc->is_released)) {
		/* can't change the mtu while the device is open */
		mutex_unlock(&vldc->vldc_mutex);
		return -EBUSY;
	}

	atomic_set(&vldc->mtu, mtu);

	mutex_unlock(&vldc->vldc_mutex);

	dprintk("mtu changed to %d.\n", mtu);

	return strnlen(buf, count);

}



static DEVICE_ATTR(mode, (S_IRUSR|S_IWUSR), vldc_sysfs_mode_show,
		   vldc_sysfs_mode_store);
static DEVICE_ATTR(mtu, (S_IRUSR|S_IWUSR), vldc_sysfs_mtu_show,
		   vldc_sysfs_mtu_store);

static struct attribute *vldc_sysfs_entries[] = {
	&dev_attr_mode.attr,
	&dev_attr_mtu.attr,
	NULL
};

static struct attribute_group vldc_attribute_group = {
	.name = NULL,		/* put in device directory */
	.attrs = vldc_sysfs_entries,
};

/*
 * Probe function does the following:
 * 1. Create/Init vldc_dev for newly probed device
 * 2. Create /dev entry for the device
 * 3. Create sysfs entries for the device
 */
static int vldc_probe(struct vio_dev *vdev, const struct vio_device_id *vio_did)
{
	struct vldc_dev *vldc;
	struct mdesc_handle *hp;
	const char *valstr;
	const u64 *id;
	int rv, slen;
	dev_t devt;
	struct device *device;
	int next_minor;
	bool created_sysfs_group;
	u64 node;
#ifdef VLDC_DEBUG
	unsigned char devt_buf[32];
#endif

	dprintk("entered.\n");

	vldc = NULL;
	hp = NULL;
	valstr = NULL;
	devt = 0;
	device = NULL;
	created_sysfs_group = false;

	vldc = kzalloc(sizeof(struct vldc_dev), GFP_KERNEL);
	if (vldc == NULL) {
		dprintk("failed to allocate vldc_dev\n");
		rv = -ENOMEM;
		goto error;
	}

	mutex_init(&vldc->vldc_mutex);

	hp = mdesc_grab();

	node = vio_vdev_node(hp, vdev);
	if (node == MDESC_NODE_NULL) {
		dprintk("Failed to get vdev MD node.\n");
		mdesc_release(hp);
		rv = -ENXIO;
		goto error;
	}

	id = mdesc_get_property(hp, node, "id", NULL);
	if (id == NULL) {
		dprintk("failed to get id property.\n");
		mdesc_release(hp);
		rv = -ENXIO;
		goto error;
	}

	/* get the name of the service this vldc-port provides */
	valstr = mdesc_get_property(hp, node, "vldc-svc-name", &slen);
	if (valstr == NULL) {
		dprintk("failed to get vldc-svc-name property.\n");
		mdesc_release(hp);
		rv = -ENXIO;
		goto error;
	}

	mdesc_release(hp);

	vldc->name = kzalloc(slen+1, GFP_KERNEL); /* +1 for NUll byte */
	if (vldc->name == NULL) {
		dprintk("failed to alloc vldc->name.\n");
		rv = -ENOMEM;
		goto error;
	}
	memcpy(vldc->name, valstr, slen);
	vldc->name[slen] = '\0';

	dprintk("%s: cfg_handle=%llu, id=%llu\n", vldc->name,
		vdev->dev_no, *id);

	init_waitqueue_head(&vldc->waitqueue);

	/* mark the device as initially released (e.g. closed) */
	atomic_set(&vldc->is_released, 1);

	/* clear the reset asserted flag */
	atomic_set(&vldc->is_reset_asserted, 0);

	dev_set_drvdata(&vdev->dev, vldc);

	/* create the devt for this device */
	next_minor = vldc_get_next_avail_minor();
	if (next_minor == -1) {
		dprintk("vldc_get_next_avail_minor() failed.\n");
		rv = -ENXIO;
		goto error;
	}
	devt = MKDEV(MAJOR(vldc_data.devt), next_minor);
	vldc->devt = devt;

	dprintk("%s: dev_t=%s\n", vldc->name, format_dev_t(devt_buf,
		vldc->devt));

	/*
	 * Use the default mode and mtu for starters.
	 * They are exported via sysfs for modification by the user
	 */
	atomic_set(&vldc->mode, VLDC_DEFAULT_MODE);
	atomic_set(&vldc->mtu, VLDC_DEFAULT_MTU);

	/* create/add the associated cdev */
	cdev_init(&vldc->cdev, &vldc_fops);
	vldc->cdev.owner = THIS_MODULE;
	rv = cdev_add(&vldc->cdev, devt, 1);
	if (rv != 0) {
		dprintk("cdev_add() failed.\n");
		devt = 0;
		goto error;
	}

	/* create the associated /sys and /dev entries */
	device = device_create(vldc_data.chrdev_class, &vdev->dev, devt,
			       vldc, "%s", vldc->name);
	if (IS_ERR(device)) {
		dprintk("device_create() failed.\n");
		rv = PTR_ERR(device);
		device = NULL;
		goto error;
	}
	vldc->device = device;

	vldc->vdev = vdev;

	rv = sysfs_create_group(&device->kobj, &vldc_attribute_group);
	if (rv)
		goto error;

	created_sysfs_group = true;

	/* add the vldc to the global vldc_data device list */
	mutex_lock(&vldc_data_mutex);
	list_add_tail(&vldc->list, &vldc_data.vldc_dev_list);
	vldc_data.num_vldc_dev_list++;
	mutex_unlock(&vldc_data_mutex);

	dprintk("%s: probe successful\n", vldc->name);

	return 0;

error:

	if (!created_sysfs_group)
		sysfs_remove_group(&device->kobj, &vldc_attribute_group);

	if (device)
		device_destroy(vldc_data.chrdev_class, devt);

	if (devt)
		cdev_del(&vldc->cdev);

	if (vldc->name)
		kfree(vldc->name);

	if (vldc != NULL) {
		mutex_destroy(&vldc->vldc_mutex);
		kfree(vldc);
	}

	dprintk("probe failed (rv=%d)\n", rv);

	return rv;
}

static int vldc_free_vldc_dev(struct vldc_dev *vldc)
{

	dprintk("entered. (%s)\n", vldc->name);

	mutex_lock(&vldc_data_mutex);
	list_del(&vldc->list);
	vldc_data.num_vldc_dev_list--;
	mutex_unlock(&vldc_data_mutex);

	sysfs_remove_group(&vldc->device->kobj, &vldc_attribute_group);
	device_destroy(vldc_data.chrdev_class, vldc->devt);
	cdev_del(&vldc->cdev);
	kfree(vldc->name);
	mutex_destroy(&vldc->vldc_mutex);
	kfree(vldc);

	return 0;
}

static int vldc_remove(struct vio_dev *vdev)
{
	int rv;
	struct vldc_dev *vldc;

	dprintk("entered.\n");

	vldc = dev_get_drvdata(&vdev->dev);

	if (vldc == NULL) {
		dprintk("failed to get vldc_dev from vio_dev.\n");
		rv = -ENXIO;
	} else {
		dprintk("removing (%s)\n", vldc->name);
		rv = vldc_free_vldc_dev(vldc);
	}

	return rv;
}

static const struct vio_device_id vldc_match[] = {
	{
		.type = "vldc-port",
	},
	{},
};

static struct vio_driver vldc_driver = {
	.id_table	= vldc_match,
	.probe		= vldc_probe,
	.remove		= vldc_remove,
	.name		= VLDC_DEVICE_NAME,
};

static char *vldc_devnode(struct device *dev, umode_t *mode)
{
	if (mode != NULL)
		*mode = 0600;

	return kasprintf(GFP_KERNEL, "vldc/%s", dev_name(dev));
}

/*
 * Init function does the following
 * 1. Init vldc_data struct fields
 * 2. Register VIO driver
 */
static int __init vldc_init(void)
{
	int rv;
#ifdef VLDC_DEBUG
	unsigned char devt_buf[32];
#endif

	dprintk("entered. (DEBUG enabled)\n");

	printk(KERN_INFO "%s", driver_version);

	INIT_LIST_HEAD(&vldc_data.vldc_dev_list);
	vldc_data.num_vldc_dev_list = 0;

	rv = alloc_chrdev_region(&vldc_data.devt, VLDC_MINOR_BASE,
				 VLDC_MAX_DEVS, VLDC_DEVICE_NAME);
	if (rv < 0) {
		dprintk("alloc_chrdev_region failed: %d\n", rv);
		return rv;
	}

	if (vldc_data.devt == (dev_t)0) {
		dprintk("alloc_chrdev_region failed: (vldc_data.devt == 0)\n");
		rv = -ENXIO;
		return rv;
	}

	dprintk("dev_t allocated = %s\n",
		format_dev_t(devt_buf, vldc_data.devt));

	vldc_data.chrdev_class = class_create(THIS_MODULE, VLDC_DEVICE_NAME);
	if (IS_ERR(vldc_data.chrdev_class)) {
		rv = PTR_ERR(vldc_data.chrdev_class);
		dprintk("class_create() failed: %d\n", rv);
		vldc_data.chrdev_class = NULL;
		goto error;
	}

	/* set callback to create devices under /dev/vldc directory */
	vldc_data.chrdev_class->devnode = vldc_devnode;

	rv = vio_register_driver(&vldc_driver);
	if (rv != 0) {
		dprintk("vio_register_driver() failed: %d\n", rv);
		goto error;
	}

	return 0;

error:
	if (vldc_data.chrdev_class)
		class_destroy(vldc_data.chrdev_class);

	if (vldc_data.devt)
		unregister_chrdev_region(vldc_data.devt, VLDC_MAX_DEVS);

	return rv;
}

static void __exit vldc_exit(void)
{

	dprintk("entered.\n");

	/*
	 * Note - vio_unregister_driver() will invoke a call to
	 * vldc_remove() for every successfully probed device.
	 */
	vio_unregister_driver(&vldc_driver);

	if (vldc_data.chrdev_class)
		class_destroy(vldc_data.chrdev_class);

	if (vldc_data.devt)
		unregister_chrdev_region(vldc_data.devt, VLDC_MAX_DEVS);
}

module_init(vldc_init);
module_exit(vldc_exit);

MODULE_AUTHOR("Oracle");
MODULE_DESCRIPTION("Sun4v Virtual LDC Driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_VERSION);

