/* sunvdc.c: Sun LDOM Virtual Disk Client.
 *
 * Copyright (C) 2007, 2008 David S. Miller <davem@davemloft.net>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/hdreg.h>
#include <linux/genhd.h>
#include <linux/cdrom.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/bitmap.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/scatterlist.h>
#include <linux/wait.h>

#include <asm/vio.h>
#include <asm/ldc.h>

#define DRV_MODULE_NAME		"sunvdc"
#define PFX DRV_MODULE_NAME	": "
#define DRV_MODULE_VERSION	"1.3"
#define DRV_MODULE_RELDATE	"September 24, 2016"

static char version[] =
	DRV_MODULE_NAME ".c:v" DRV_MODULE_VERSION " (" DRV_MODULE_RELDATE ")\n";
MODULE_AUTHOR("David S. Miller (davem@davemloft.net)");
MODULE_DESCRIPTION("Sun LDOM virtual disk client driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_MODULE_VERSION);

#define VDC_TX_RING_SIZE	512
#define VDC_DEFAULT_BLK_SIZE	512

#define WAITING_FOR_LINK_UP	0x01
#define WAITING_FOR_TX_SPACE	0x02
#define WAITING_FOR_GEN_CMD	0x04
#define WAITING_FOR_ANY		-1

static struct workqueue_struct *sunvdc_wq;

struct vdc_req_entry {
	struct bio		*req;
	u64			size;
	int			sent;
};

struct vdc_port {
	struct vio_driver_state	vio;

	struct gendisk		*disk;

	struct vio_completion	*cmp;

	u64			req_id;
	u64			seq;
	struct vdc_req_entry	rq_arr[VDC_TX_RING_SIZE];

	unsigned long		ring_cookies;
	wait_queue_head_t	wait;

	u64			max_xfer_size;
	u32			vdisk_block_size;

	u64			ldc_timeout;
	struct timer_list	ldc_reset_timer;
	struct work_struct	ldc_reset_work;

	/* The server fills these in for us in the disk attribute
	 * ACK packet.
	 */
	u64			operations;
	u32			vdisk_size;
	u8			vdisk_type;
	u8			vdisk_mtype;
	u32			vdisk_phys_blksz;

	u8			flags;

	char			disk_name[32];
};

#define	VDC_PORT_RESET	0x1

static void vdc_ldc_reset(struct vdc_port *port);
static void vdc_ldc_reset_work(struct work_struct *work);
static void vdc_ldc_reset_timer(unsigned long _arg);
static struct bio *vdc_desc_put(struct vdc_port *port, unsigned int idx);
static inline void vdc_desc_set_state(struct vio_disk_desc *, int);

static inline struct vdc_port *to_vdc_port(struct vio_driver_state *vio)
{
	return container_of(vio, struct vdc_port, vio);
}

/* Ordered from largest major to lowest */
static struct vio_version vdc_versions[] = {
	{ .major = 1, .minor = 3 },
	{ .major = 1, .minor = 2 },
	{ .major = 1, .minor = 1 },
	{ .major = 1, .minor = 0 },
};

static inline int vdc_version_supported(struct vdc_port *port,
					u16 major, u16 minor)
{
	return port->vio.ver.major == major && port->vio.ver.minor >= minor;
}

#define VDCBLK_NAME	"vdisk"
static int vdc_major;
#define PARTITION_SHIFT	3

static int vdc_getgeo(struct block_device *bdev, struct hd_geometry *geo)
{
	struct gendisk *disk = bdev->bd_disk;
	sector_t nsect = get_capacity(disk);
	sector_t cylinders = nsect;

	geo->heads = 0xff;
	geo->sectors = 0x3f;
	sector_div(cylinders, geo->heads * geo->sectors);
	geo->cylinders = cylinders;
	if ((sector_t)(geo->cylinders + 1) * geo->heads * geo->sectors < nsect)
		geo->cylinders = 0xffff;

	return 0;
}

/* Add ioctl/CDROM_GET_CAPABILITY to support cdrom_id in udev
 * when vdisk_mtype is VD_MEDIA_TYPE_CD or VD_MEDIA_TYPE_DVD.
 * Needed to be able to install inside an ldom from an iso image.
 */
static int vdc_ioctl(struct block_device *bdev, fmode_t mode,
		     unsigned command, unsigned long argument)
{
	int i;
	struct gendisk *disk;

	switch (command) {
	case CDROMMULTISESSION:
		pr_debug(PFX "Multisession CDs not supported\n");
		for (i = 0; i < sizeof(struct cdrom_multisession); i++)
			if (put_user(0, (char __user *)(argument + i)))
				return -EFAULT;
		return 0;

	case CDROM_GET_CAPABILITY:
		disk = bdev->bd_disk;

		if (bdev->bd_disk && (disk->flags & GENHD_FL_CD))
			return 0;
		return -EINVAL;

	default:
		pr_debug(PFX "ioctl %08x not supported\n", command);
		return -EINVAL;
	}
}

static const struct block_device_operations vdc_fops = {
	.owner		= THIS_MODULE,
	.getgeo		= vdc_getgeo,
	.ioctl		= vdc_ioctl,
};

static void vdc_finish(struct vio_completion *cmp, int err, int waiting_for)
{
	if (cmp && (waiting_for == -1 || cmp->waiting_for == waiting_for)) {
		cmp->err = err;
		complete_all(&cmp->com);
	} else
		pr_debug(PFX "skip err=%d wait=%d\n", err, waiting_for);
}

static void vdc_handshake_complete(struct vio_driver_state *vio)
{
	struct vdc_port *port = to_vdc_port(vio);

	del_timer(&port->ldc_reset_timer);
	vdc_finish(vio->cmp, 0, WAITING_FOR_LINK_UP);
	vio->cmp = NULL;
}

static int vdc_handle_unknown(struct vdc_port *port, void *arg)
{
	struct vio_msg_tag *pkt = arg;

	printk(KERN_ERR PFX "Received unknown msg [%02x:%02x:%04x:%08x]\n",
	       pkt->type, pkt->stype, pkt->stype_env, pkt->sid);
	printk(KERN_ERR PFX "Resetting connection.\n");

	ldc_disconnect(port->vio.lp);

	return -ECONNRESET;
}

static int vdc_send_attr(struct vio_driver_state *vio)
{
	struct vdc_port *port = to_vdc_port(vio);
	struct vio_disk_attr_info pkt;

	memset(&pkt, 0, sizeof(pkt));

	pkt.tag.type = VIO_TYPE_CTRL;
	pkt.tag.stype = VIO_SUBTYPE_INFO;
	pkt.tag.stype_env = VIO_ATTR_INFO;
	pkt.tag.sid = vio_send_sid(vio);

	pkt.xfer_mode = VIO_DRING_MODE;
	pkt.vdisk_block_size = port->vdisk_block_size;
	pkt.max_xfer_size = port->max_xfer_size;

	viodbg(HS, "SEND ATTR xfer_mode[0x%x] blksz[%u] max_xfer[%llu]\n",
	       pkt.xfer_mode, pkt.vdisk_block_size, pkt.max_xfer_size);

	return vio_ldc_send(&port->vio, &pkt, sizeof(pkt));
}

static int vdc_handle_attr(struct vio_driver_state *vio, void *arg)
{
	struct vdc_port *port = to_vdc_port(vio);
	struct vio_disk_attr_info *pkt = arg;

	viodbg(HS, "GOT ATTR stype[0x%x] ops[%llx] disk_size[%llu] disk_type[%x] "
	       "mtype[0x%x] xfer_mode[0x%x] blksz[%u] max_xfer[%llu]\n",
	       pkt->tag.stype, pkt->operations,
	       pkt->vdisk_size, pkt->vdisk_type, pkt->vdisk_mtype,
	       pkt->xfer_mode, pkt->vdisk_block_size,
	       pkt->max_xfer_size);

	if (pkt->tag.stype == VIO_SUBTYPE_ACK) {
		switch (pkt->vdisk_type) {
		case VD_DISK_TYPE_DISK:
		case VD_DISK_TYPE_SLICE:
			break;

		default:
			printk(KERN_ERR PFX "%s: Bogus vdisk_type 0x%x\n",
			       vio->name, pkt->vdisk_type);
			return -ECONNRESET;
		}

		if (pkt->vdisk_block_size > port->vdisk_block_size) {
			printk(KERN_ERR PFX "%s: BLOCK size increased "
			       "%u --> %u\n",
			       vio->name,
			       port->vdisk_block_size, pkt->vdisk_block_size);
			return -ECONNRESET;
		}

		port->operations = pkt->operations;
		port->vdisk_type = pkt->vdisk_type;
		if (vdc_version_supported(port, 1, 1)) {
			port->vdisk_size = pkt->vdisk_size;
			port->vdisk_mtype = pkt->vdisk_mtype;
		}
		if (pkt->max_xfer_size < port->max_xfer_size)
			port->max_xfer_size = pkt->max_xfer_size;
		port->vdisk_block_size = pkt->vdisk_block_size;

		port->vdisk_phys_blksz = VDC_DEFAULT_BLK_SIZE;
		if (vdc_version_supported(port, 1, 2))
			port->vdisk_phys_blksz = pkt->phys_block_size;

		return 0;
	} else {
		printk(KERN_ERR PFX "%s: Attribute NACK\n", vio->name);

		return -ECONNRESET;
	}
}

static void vdc_end_special(struct vdc_port *port, int err)
{
	vdc_finish(port->cmp, -err, WAITING_FOR_GEN_CMD);
	port->cmp = NULL;
}

static void vdc_end_one(struct vdc_port *port, struct vio_dring_state *dr,
			unsigned int index, int err)
{
	struct vio_disk_desc *desc = vio_dring_entry(dr, index);
	struct vio_driver_state *vio = &port->vio;
	struct vdc_req_entry *rqe = &port->rq_arr[index];
	struct bio *req;

	assert_spin_locked(&vio->lock);

	if (err)
		vdc_desc_set_state(desc, VIO_DESC_DONE);
	else if (unlikely(desc->hdr.state != VIO_DESC_DONE)) {
		pr_err("%s idx=%u err=%d state=%d\n",
			__func__, index, err, desc->hdr.state);
		return;
	} else
		err = desc->status;

	req = vdc_desc_put(port, index);
	if (req == NULL) {
		vdc_end_special(port, err);
		return;
	}

	if (rqe->size != desc->size) {
		pr_err("%s idx=%u err=%d state=%d size=%lld rsize=%lld\n",
			__func__, index, err, desc->hdr.state,
			desc->size, rqe->size);
		BUG();
	}

	bio_endio(req, err ? -EIO : 0);
	rqe->size = 0;
}

static int vdc_ack(struct vdc_port *port, void *msgbuf)
{
	struct vio_dring_state *dr = &port->vio.drings[VIO_DRIVER_TX_RING];
	struct vio_dring_data *pkt = msgbuf;

	if (unlikely(pkt->dring_ident != dr->ident ||
		     pkt->start_idx != pkt->end_idx ||
		     pkt->start_idx >= VDC_TX_RING_SIZE))
		return 0;

	vdc_end_one(port, dr, pkt->start_idx, 0);

	return 0;
}

static int vdc_nack(struct vdc_port *port, void *msgbuf)
{
	/* XXX Implement me XXX */
	return 0;
}

static void vdc_event(void *arg, int event)
{
	struct vdc_port *port = arg;
	struct vio_driver_state *vio = &port->vio;
	unsigned long flags;
	int err;

	spin_lock_irqsave(&vio->lock, flags);

	if (unlikely(event == LDC_EVENT_RESET)) {
		vio_link_state_change(vio, event);
		queue_work(sunvdc_wq, &port->ldc_reset_work);
		goto out;
	}

	if (unlikely(event == LDC_EVENT_UP)) {
		vio_link_state_change(vio, event);
		goto out;
	}

	if (unlikely(event != LDC_EVENT_DATA_READY)) {
		pr_warn(PFX "Unexpected LDC event %d\n", event);
		goto out;
	}

	err = 0;
	while (1) {
		union {
			struct vio_msg_tag tag;
			u64 raw[8];
		} msgbuf;

		err = ldc_read(vio->lp, &msgbuf, sizeof(msgbuf));
		if (unlikely(err < 0)) {
			if (err == -ECONNRESET)
				vio_conn_reset(vio);
			break;
		}
		if (err == 0)
			break;
		viodbg(DATA, "TAG [%02x:%02x:%04x:%08x]\n",
		       msgbuf.tag.type,
		       msgbuf.tag.stype,
		       msgbuf.tag.stype_env,
		       msgbuf.tag.sid);
		err = vio_validate_sid(vio, &msgbuf.tag);
		if (err < 0)
			break;

		if (likely(msgbuf.tag.type == VIO_TYPE_DATA)) {
			if (msgbuf.tag.stype == VIO_SUBTYPE_ACK)
				err = vdc_ack(port, &msgbuf);
			else if (msgbuf.tag.stype == VIO_SUBTYPE_NACK)
				err = vdc_nack(port, &msgbuf);
			else
				err = vdc_handle_unknown(port, &msgbuf);
		} else if (msgbuf.tag.type == VIO_TYPE_CTRL) {
			err = vio_control_pkt_engine(vio, &msgbuf);
		} else {
			err = vdc_handle_unknown(port, &msgbuf);
		}
		if (err < 0)
			break;
	}

	/*
	 * If there is an error, reset the link.  All inflight
	 * requests will be resent once the port is up again.
	 */
	if (err < 0) {
		vio_link_state_change(vio, LDC_EVENT_RESET);
		queue_work(sunvdc_wq, &port->ldc_reset_work);
	}
out:
	spin_unlock_irqrestore(&vio->lock, flags);
}

static int __vdc_tx_trigger(struct vdc_port *port, unsigned int idx, int new)
{
	struct vdc_req_entry *rqe = &port->rq_arr[idx];
	struct vio_driver_state *vio = &port->vio;
	struct vio_dring_state *dr = &vio->drings[VIO_DRIVER_TX_RING];
	struct vio_dring_data hdr = {
		.tag = {
			.type		= VIO_TYPE_DATA,
			.stype		= VIO_SUBTYPE_INFO,
			.stype_env	= VIO_DRING_DATA,
			.sid		= vio_send_sid(vio),
		},
		.dring_ident		= dr->ident,
		.start_idx		= idx,
		.end_idx		= idx,
	};
	unsigned long flags = 0;
	int err, delay;

	delay = 1;
	do {
		/*
		 * We can get here for a new or an inflight request.
		 * In the former case, we must explicity hold the vio lock.
		 * In the latter case, the lock is already held as part
		 * reset processing.  Sending the request and setting the
		 * related fields in case of success must be atomic.
		 * First, snd_nxt and req_id must be incremented atomically.
		 * Second, if the thread is preempted after vio_ldc_send()
		 * but before setting rqe->sent and the service resets,
		 * the request may not be resent during reset processing.
		 */
		if (new)
			spin_lock_irqsave(&vio->lock, flags);
		else
			assert_spin_locked(&vio->lock);
		hdr.seq = dr->snd_nxt;
		err = vio_ldc_send(vio, &hdr, sizeof(hdr));
		if (err > 0) {
			rqe->sent = 1;
			dr->snd_nxt++;
			port->req_id++;
			if (new)
				spin_unlock_irqrestore(&vio->lock, flags);
			break;
		}
		if (new)
			spin_unlock_irqrestore(&vio->lock, flags);

		udelay(delay);
		if ((delay <<= 1) > 128)
			delay = 128;
	} while (err == -EAGAIN);

	if (err < 0)
		pr_err(PFX "vio_ldc_send() failed, idx=%d err=%d.\n", idx, err);

	return err;
}

static struct vio_disk_desc *vdc_desc_get(struct vdc_port *port,
					  struct bio *req,
					  unsigned int *idxp)
{
	unsigned int idx;
	struct vio_disk_desc *desc = NULL;
	struct vio_driver_state *vio = &port->vio;
	struct vio_dring_state *dr = &vio->drings[VIO_DRIVER_TX_RING];
	DEFINE_WAIT(wait);
	unsigned long flags;

	while (1) {
		prepare_to_wait(&port->wait, &wait, TASK_INTERRUPTIBLE);

		spin_lock_irqsave(&vio->lock, flags);
		idx = find_first_zero_bit(dr->txmap, dr->nr_txmap);
		if (idx < VDC_TX_RING_SIZE) {
			bitmap_set(dr->txmap, idx, 1);
			desc = dr->base + (dr->entry_size * idx);
			if (req) {
				BUG_ON(port->rq_arr[idx].req);
				port->rq_arr[idx].req = req;
			}
			*idxp = idx;

			spin_unlock_irqrestore(&vio->lock, flags);
			finish_wait(&port->wait, &wait);
			break;
		}
		spin_unlock_irqrestore(&vio->lock, flags);
		schedule();
		finish_wait(&port->wait, &wait);
	}

	BUG_ON(!desc);

	return desc;
}

static struct bio *vdc_desc_put(struct vdc_port *port, unsigned int idx)
{
	struct vio_driver_state *vio = &port->vio;
	struct vio_dring_state *dr = &vio->drings[VIO_DRIVER_TX_RING];
	struct vio_disk_desc *desc = vio_dring_entry(dr, idx);
	struct vdc_req_entry *rqe;
	struct bio *req;

	assert_spin_locked(&vio->lock);

	ldc_unmap(vio->lp, desc->cookies, desc->ncookies);

	bitmap_clear(dr->txmap, idx, 1);
	vdc_desc_set_state(desc, VIO_DESC_FREE);

	rqe = &port->rq_arr[idx];
	req = rqe->req;
	rqe->req = NULL;
	rqe->sent = 0;
	wake_up_all(&port->wait);

	return req;
}

static inline void vdc_desc_set_state(struct vio_disk_desc *desc, int state)
{
	desc->hdr.state = state;
	/*
	 * This has to be a non-SMP write barrier because we are writing
	 * to memory which is shared with the peer LDOM.
	 */
	wmb();
}

static void __create_flush_desc(struct vdc_port *port,
	struct vio_disk_desc *desc)
{
	memset(desc, 0, sizeof(struct vio_disk_desc));
	desc->hdr.ack = VIO_ACK_ENABLE;
	desc->req_id = port->req_id;
	desc->operation = VD_OP_FLUSH;
}

static int __create_rw_desc(struct vdc_port *port, struct request *req,
			    struct vio_disk_desc *desc, unsigned int idx)
{
	struct vio_driver_state *vio = &port->vio;
	struct scatterlist sg[port->ring_cookies];
	struct vdc_req_entry *rqe;
	DEFINE_WAIT(wait);
	unsigned int map_perm;
	unsigned long flags;
	int nsg, err, i;
	u64 len;
	u8 op;

	map_perm = LDC_MAP_SHADOW | LDC_MAP_DIRECT | LDC_MAP_IO;

	if (rq_data_dir(req) == READ) {
		map_perm |= LDC_MAP_W;
		op = VD_OP_BREAD;
	} else {
		map_perm |= LDC_MAP_R;
		op = VD_OP_BWRITE;
	}

	sg_init_table(sg, port->ring_cookies);
	nsg = blk_rq_map_sg(req->q, req, sg);
	if (!nsg) {
		pr_err(PFX "blk_rq_map_sg() failed, nsg=%d.\n", nsg);
		return -EIO;
	}

	memset(desc, 0, sizeof(struct vio_disk_desc));

	while (1) {
		prepare_to_wait(&port->wait, &wait, TASK_INTERRUPTIBLE);

		spin_lock_irqsave(&vio->lock, flags);
		err = ldc_map_sg(port->vio.lp, sg, nsg, desc->cookies,
				 port->ring_cookies, map_perm);

		if (err >= 0 || err != -ENOMEM) {
			spin_unlock_irqrestore(&vio->lock, flags);
			finish_wait(&port->wait, &wait);
			break;
		}

		spin_unlock_irqrestore(&vio->lock, flags);
		schedule();
		finish_wait(&port->wait, &wait);
	}

	if (err <= 0) {
		pr_err(PFX "ldc_map_sg() failed, err=%d.\n", err);
		return err;
	}

	len = 0;
	for (i = 0; i < nsg; i++)
		len += sg[i].length;

	desc->hdr.ack = VIO_ACK_ENABLE;
	desc->req_id = port->req_id;
	desc->operation = op;
	if (port->vdisk_type == VD_DISK_TYPE_DISK)
		desc->slice = 0xff;
	else
		desc->slice = 0;
	desc->status = ~0;
	desc->offset = (blk_rq_pos(req) << 9) / port->vdisk_block_size;
	desc->size = len;
	desc->ncookies = err;

	rqe = &port->rq_arr[idx];
	rqe->size = len;

	return 0;
}

static int __send_request(struct vdc_port *port, unsigned int idx)
{
	struct vio_driver_state *vio = &port->vio;
	struct vio_dring_state *dr = &vio->drings[VIO_DRIVER_TX_RING];
	struct vio_disk_desc *desc = vio_dring_entry(dr, idx);
	int err;

	vdc_desc_set_state(desc, VIO_DESC_READY);

	while (1) {
		err = __vdc_tx_trigger(port, idx, 1);

		if (err == -ECONNRESET || err == -ENOTCONN) {
			vdc_ldc_reset(port);
			pr_info(PFX "%s retry, idx=%d err=%d\n",
				__func__, idx, err);
		} else if (err < 0) {
			pr_err(PFX "%s error, idx=%d err=%d\n",
				__func__, idx, err);
		} else
			break;
	}

	return err;
}

/*
 * IO requests are handed off directly to vdc without any queueing at
 * the blk layer.
 *
 * A dring entry is first allocated and then mapped for a request,
 * and the request is then sent to the server. A recoverable error,
 * e.g. reset, is continuously retried until success.
 *
 * A reset error can be sync or async, i.e., it can be a direct result
 * of a send, or fielded indirectly via an interrupt.  In either case
 * the connection is reset and all inflight request are resent immediately
 * after the connection is re-established at the end of the reset processing.
 *
 * The tx dring acts effectively as a request queue. An incoming request
 * will continuously retry until it gets a tx ring descriptor and proceeds.
 * The descriptor is freed in interrupt context and the vio spinlock is used
 * for synchronization.
 */
static void vdc_make_request(struct request_queue *q, struct bio *bio)
{
	struct vdc_port *port = q->queuedata;
	struct vio_driver_state *vio = &port->vio;
	struct vio_dring_state *dr = &vio->drings[VIO_DRIVER_TX_RING];
	struct vio_disk_desc *desc;
	struct request req;
	unsigned int idx;
	unsigned long flags;
	int err = 0;

	BUG_ON(!port);

	desc = vdc_desc_get(port, bio, &idx);

	if (bio->bi_rw & REQ_FLUSH)
		__create_flush_desc(port, desc);
	else {
		memset(&req, 0, sizeof(req));
		/*
		 * XXX We should be able to use init_request_from_bio()
		 * but it is not an exported symbol.
		 */
		req.bio = bio;
		req.cmd_flags = bio->bi_rw & REQ_COMMON_MASK;
		req.errors = 0;
		req.__sector = bio->bi_iter.bi_sector;
		req.q = q;
		err = __create_rw_desc(port, &req, desc, idx);
		if (err)
			pr_err(PFX "__create_rw_desc() failed, err=%d\n", err);
	}

	if (!err)
		err = __send_request(port, idx);

	/*
	 * Terminate the request unless a descriptor was
	 * successfully allocated and sent to the server.
	 */
	if (err < 0) {
		spin_lock_irqsave(&vio->lock, flags);
		vdc_end_one(port, dr, idx, err);
		spin_unlock_irqrestore(&vio->lock, flags);
	}
}

static int generic_request(struct vdc_port *port, u8 op, void *buf, int len)
{
	struct vio_completion comp;
	struct vio_disk_desc *desc;
	unsigned int map_perm;
	unsigned int idx;
	int op_len, err;
	void *req_buf;

	if (!(((u64)1 << (u64)op) & port->operations))
		return -EOPNOTSUPP;

	switch (op) {
	case VD_OP_BREAD:
	case VD_OP_BWRITE:
	default:
		return -EINVAL;

	case VD_OP_FLUSH:
		op_len = 0;
		map_perm = 0;
		break;

	case VD_OP_GET_WCE:
		op_len = sizeof(u32);
		map_perm = LDC_MAP_W;
		break;

	case VD_OP_SET_WCE:
		op_len = sizeof(u32);
		map_perm = LDC_MAP_R;
		break;

	case VD_OP_GET_VTOC:
		op_len = sizeof(struct vio_disk_vtoc);
		map_perm = LDC_MAP_W;
		break;

	case VD_OP_SET_VTOC:
		op_len = sizeof(struct vio_disk_vtoc);
		map_perm = LDC_MAP_R;
		break;

	case VD_OP_GET_DISKGEOM:
		op_len = sizeof(struct vio_disk_geom);
		map_perm = LDC_MAP_W;
		break;

	case VD_OP_SET_DISKGEOM:
		op_len = sizeof(struct vio_disk_geom);
		map_perm = LDC_MAP_R;
		break;

	case VD_OP_SCSICMD:
		op_len = 16;
		map_perm = LDC_MAP_RW;
		break;

	case VD_OP_GET_DEVID:
		op_len = sizeof(struct vio_disk_devid);
		map_perm = LDC_MAP_W;
		break;

	case VD_OP_GET_EFI:
	case VD_OP_SET_EFI:
		return -EOPNOTSUPP;
	};

	map_perm |= LDC_MAP_SHADOW | LDC_MAP_DIRECT | LDC_MAP_IO;

	op_len = (op_len + 7) & ~7;
	req_buf = kzalloc(op_len, GFP_KERNEL);
	if (!req_buf)
		return -ENOMEM;

	if (len > op_len)
		len = op_len;

	if (map_perm & LDC_MAP_R)
		memcpy(req_buf, buf, len);

	desc = vdc_desc_get(port, NULL, &idx);
	if (!desc) {
		err = -ENOMEM;
		goto done;
	}

	err = ldc_map_single(port->vio.lp, req_buf, op_len,
			     desc->cookies, port->ring_cookies,
			     map_perm);
	if (err < 0)
		goto done;

	init_completion(&comp.com);
	comp.waiting_for = WAITING_FOR_GEN_CMD;
	port->cmp = &comp;

	desc->hdr.ack = VIO_ACK_ENABLE;
	desc->req_id = port->req_id;
	desc->operation = op;
	desc->slice = 0;
	desc->status = ~0;
	desc->offset = 0;
	desc->size = op_len;
	desc->ncookies = err;

	err = __send_request(port, idx);
	if (err >= 0) {
		wait_for_completion(&comp.com);
		err = comp.err;
	} else {
		port->cmp = NULL;
		goto done;
	}

	if (map_perm & LDC_MAP_W)
		memcpy(buf, req_buf, len);

done:
	(void) vdc_desc_put(port, idx);
	kfree(req_buf);
	return err;
}

static int vio_txring_alloc(struct vio_dring_state *dr, unsigned int nr_tx)
{
	unsigned int sz;

	sz = BITS_TO_LONGS(nr_tx) * sizeof(unsigned long);
	dr->txmap = kzalloc(sz, GFP_KERNEL);

	if (!dr->txmap)
		return -ENOMEM;

	dr->nr_txmap = nr_tx;
	return 0;
}

static int vdc_alloc_tx_ring(struct vdc_port *port)
{
	struct vio_dring_state *dr = &port->vio.drings[VIO_DRIVER_TX_RING];
	unsigned long len, entry_size;
	int ncookies;
	void *dring;
	int ret;

	entry_size = sizeof(struct vio_disk_desc) +
		(sizeof(struct ldc_trans_cookie) * port->ring_cookies);
	len = (VDC_TX_RING_SIZE * entry_size);

	ret = vio_txring_alloc(dr, VDC_TX_RING_SIZE);
	if (ret)
		return ret;

	ncookies = VIO_MAX_RING_COOKIES;
	dring = ldc_alloc_exp_dring(port->vio.lp, len,
				    dr->cookies, &ncookies,
				    (LDC_MAP_SHADOW |
				     LDC_MAP_DIRECT |
				     LDC_MAP_RW));
	if (IS_ERR(dring))
		return PTR_ERR(dring);

	dr->base = dring;
	dr->entry_size = entry_size;
	dr->num_entries = VDC_TX_RING_SIZE;
	dr->pending = VDC_TX_RING_SIZE;
	dr->ncookies = ncookies;

	return 0;
}

static void vdc_free_tx_ring(struct vdc_port *port)
{
	struct vio_dring_state *dr = &port->vio.drings[VIO_DRIVER_TX_RING];

	if (dr->base) {
		ldc_free_exp_dring(port->vio.lp, dr->base,
				   (dr->entry_size * dr->num_entries),
				   dr->cookies, dr->ncookies);
		dr->base = NULL;
		dr->entry_size = 0;
		dr->num_entries = 0;
		dr->pending = 0;
		dr->ncookies = 0;
	}
}

static int vdc_port_up(struct vdc_port *port)
{
	struct vio_completion comp;

	init_completion(&comp.com);
	comp.err = 0;
	comp.waiting_for = WAITING_FOR_LINK_UP;
	port->vio.cmp = &comp;

	vio_port_up(&port->vio);
	wait_for_completion(&comp.com);
	return comp.err;
}

static int probe_disk(struct vdc_port *port)
{
	struct request_queue *q;
	struct gendisk *g;
	int err;

	err = vdc_port_up(port);
	if (err)
		return err;

	/* Using version 1.2 means vdisk_phys_blksz should be set unless the
	 * disk is reserved by another system.
	 */
	if (vdc_version_supported(port, 1, 2) && !port->vdisk_phys_blksz)
		return -ENODEV;

	if (vdc_version_supported(port, 1, 1)) {
		/* vdisk_size should be set during the handshake, if it wasn't
		 * then the underlying disk is reserved by another system
		 */
		if (port->vdisk_size == -1)
			return -ENODEV;
	} else {
		struct vio_disk_geom geom;

		err = generic_request(port, VD_OP_GET_DISKGEOM,
				      &geom, sizeof(geom));
		if (err < 0) {
			printk(KERN_ERR PFX "VD_OP_GET_DISKGEOM returns "
			       "error %d\n", err);
			return err;
		}
		port->vdisk_size = ((u64)geom.num_cyl *
				    (u64)geom.num_hd *
				    (u64)geom.num_sec);
	}

	q = blk_alloc_queue(GFP_KERNEL);
	if (!q) {
		printk(KERN_ERR PFX "%s: Could not allocate queue.\n",
		       port->vio.name);
		return -ENOMEM;
	}
	blk_queue_make_request(q, vdc_make_request);
	q->queuedata = port;

	g = alloc_disk(1 << PARTITION_SHIFT);
	if (!g) {
		printk(KERN_ERR PFX "%s: Could not allocate gendisk.\n",
		       port->vio.name);
		blk_cleanup_queue(q);
		return -ENOMEM;
	}

	port->disk = g;

	/* Each segment in a request is up to an aligned page in size. */
	blk_queue_segment_boundary(q, PAGE_SIZE - 1);
	blk_queue_max_segment_size(q, PAGE_SIZE);

	blk_queue_max_segments(q, port->ring_cookies);
	blk_queue_max_hw_sectors(q, port->max_xfer_size);
	g->major = vdc_major;
	g->first_minor = port->vio.vdev->dev_no << PARTITION_SHIFT;
	strcpy(g->disk_name, port->disk_name);

	g->fops = &vdc_fops;
	g->queue = q;
	g->private_data = port;
	g->driverfs_dev = &port->vio.vdev->dev;

	set_capacity(g, port->vdisk_size);

	if (vdc_version_supported(port, 1, 1)) {
		switch (port->vdisk_mtype) {
		case VD_MEDIA_TYPE_CD:
			pr_info(PFX "Virtual CDROM %s\n", port->disk_name);
			g->flags |= GENHD_FL_CD;
			g->flags |= GENHD_FL_REMOVABLE;
			set_disk_ro(g, 1);
			break;

		case VD_MEDIA_TYPE_DVD:
			pr_info(PFX "Virtual DVD %s\n", port->disk_name);
			g->flags |= GENHD_FL_CD;
			g->flags |= GENHD_FL_REMOVABLE;
			set_disk_ro(g, 1);
			break;

		case VD_MEDIA_TYPE_FIXED:
			pr_info(PFX "Virtual Hard disk %s\n", port->disk_name);
			break;
		}
	}

	blk_queue_physical_block_size(q, port->vdisk_phys_blksz);

	pr_info(PFX "%s: %u sectors (%u MB) protocol %d.%d\n",
	       g->disk_name,
	       port->vdisk_size, (port->vdisk_size >> (20 - 9)),
	       port->vio.ver.major, port->vio.ver.minor);

	add_disk(g);

	return 0;
}

static struct ldc_channel_config vdc_ldc_cfg = {
	.event		= vdc_event,
	.mtu		= 512,
	.mode		= LDC_MODE_UNRELIABLE,
};

static struct vio_driver_ops vdc_vio_ops = {
	.send_attr		= vdc_send_attr,
	.handle_attr		= vdc_handle_attr,
	.handshake_complete	= vdc_handshake_complete,
};

static void print_version(void)
{
	static int version_printed;

	if (version_printed++ == 0)
		printk(KERN_INFO "%s", version);
}

static int vdc_port_probe(struct vio_dev *vdev, const struct vio_device_id *id)
{
	struct mdesc_handle *hp;
	struct vdc_port *port;
	int err;
	const u64 *ldc_timeout;
	u64 node;

	print_version();

	hp = mdesc_grab();

	node = vio_vdev_node(hp, vdev);
	if (node == MDESC_NODE_NULL) {
		printk(KERN_ERR PFX "Failed to get vdev MD node.\n");
		err = -ENXIO;
		goto err_out_release_mdesc;
	}

	err = -ENODEV;
	if ((vdev->dev_no << PARTITION_SHIFT) & ~(u64)MINORMASK) {
		printk(KERN_ERR PFX "Port id [%llu] too large.\n",
		       vdev->dev_no);
		goto err_out_release_mdesc;
	}

	port = kzalloc(sizeof(*port), GFP_KERNEL);
	err = -ENOMEM;
	if (!port) {
		printk(KERN_ERR PFX "Cannot allocate vdc_port.\n");
		goto err_out_release_mdesc;
	}

	if (vdev->dev_no >= 26)
		snprintf(port->disk_name, sizeof(port->disk_name),
			 VDCBLK_NAME "%c%c",
			 'a' + ((int)vdev->dev_no / 26) - 1,
			 'a' + ((int)vdev->dev_no % 26));
	else
		snprintf(port->disk_name, sizeof(port->disk_name),
			 VDCBLK_NAME "%c", 'a' + ((int)vdev->dev_no % 26));
	port->vdisk_size = -1;

	/* Actual wall time may be double due to do_generic_file_read() doing
	 * a readahead I/O first, and once that fails it will try to read a
	 * single page.
	 */
	ldc_timeout = mdesc_get_property(hp, node, "vdc-timeout", NULL);
	port->ldc_timeout = ldc_timeout ? *ldc_timeout : 0;
	setup_timer(&port->ldc_reset_timer, vdc_ldc_reset_timer,
		    (unsigned long)port);
	INIT_WORK(&port->ldc_reset_work, vdc_ldc_reset_work);
	init_waitqueue_head(&port->wait);

	err = vio_driver_init(&port->vio, vdev, VDEV_DISK,
			      vdc_versions, ARRAY_SIZE(vdc_versions),
			      &vdc_vio_ops, port->disk_name);
	if (err)
		goto err_out_free_port;

	port->vdisk_block_size = VDC_DEFAULT_BLK_SIZE;
	port->max_xfer_size = ((128 * 1024) / port->vdisk_block_size);
	port->ring_cookies = ((port->max_xfer_size *
			       port->vdisk_block_size) / PAGE_SIZE) + 2;

	err = vio_ldc_alloc(&port->vio, &vdc_ldc_cfg, port);
	if (err)
		goto err_out_free_port;

	err = vdc_alloc_tx_ring(port);
	if (err)
		goto err_out_free_ldc;

	err = probe_disk(port);
	if (err)
		goto err_out_free_tx_ring;

	dev_set_drvdata(&vdev->dev, port);

	mdesc_release(hp);

	return 0;

err_out_free_tx_ring:
	vdc_free_tx_ring(port);

err_out_free_ldc:
	flush_work(&port->ldc_reset_work);
	del_timer_sync(&port->ldc_reset_timer);
	vio_ldc_free(&port->vio);

err_out_free_port:
	kfree(port);

err_out_release_mdesc:
	mdesc_release(hp);
	return err;
}

static int vdc_port_remove(struct vio_dev *vdev)
{
	struct vdc_port *port = dev_get_drvdata(&vdev->dev);

	if (port) {
		unsigned long flags;

		spin_lock_irqsave(&port->vio.lock, flags);
		spin_unlock_irqrestore(&port->vio.lock, flags);

		flush_work(&port->ldc_reset_work);
		del_timer_sync(&port->ldc_reset_timer);
		del_timer_sync(&port->vio.timer);

		del_gendisk(port->disk);
		put_disk(port->disk);
		port->disk = NULL;

		vdc_free_tx_ring(port);
		vio_ldc_free(&port->vio);

		dev_set_drvdata(&vdev->dev, NULL);

		kfree(port);
	}
	return 0;
}

static void vdc_resend_inflight(struct vdc_port *port)
{
	struct vio_driver_state *vio = &port->vio;
	struct vio_dring_state *dr = &vio->drings[VIO_DRIVER_TX_RING];
	struct vio_disk_desc *desc;
	struct vdc_req_entry *rqe;
	unsigned int idx;

	assert_spin_locked(&vio->lock);

	for (idx = find_first_bit(dr->txmap, dr->nr_txmap);
	     idx < dr->nr_txmap;
	     idx = find_next_bit(dr->txmap, dr->nr_txmap, idx + 1)) {
		rqe = &port->rq_arr[idx];
		if (rqe->sent) {
			desc = vio_dring_entry(dr, idx);
			vdc_desc_set_state(desc, VIO_DESC_READY);
			if (__vdc_tx_trigger(port, idx, 0) < 0)
				break;
		}
	}
}

static void vdc_queue_drain(struct vdc_port *port)
{
	struct vio_dring_state *dr = &port->vio.drings[VIO_DRIVER_TX_RING];
	unsigned int idx;

	for (idx = find_first_bit(dr->txmap, dr->nr_txmap);
	     idx < dr->nr_txmap;
	     idx = find_next_bit(dr->txmap, dr->nr_txmap, idx + 1)) {
			vdc_end_one(port, dr, idx, -EIO);
	}
}

static void vdc_ldc_reset_timer(unsigned long _arg)
{
	struct vdc_port *port = (struct vdc_port *) _arg;
	struct vio_driver_state *vio = &port->vio;
	unsigned long flags;

	if (!port->disk)
		return;

	spin_lock_irqsave(&vio->lock, flags);
	if (!(port->vio.hs_state & VIO_HS_COMPLETE)) {
		pr_warn(PFX "%s ldc down %llu seconds, draining queue\n",
			port->disk_name, port->ldc_timeout);
		vdc_queue_drain(port);
	}
	spin_unlock_irqrestore(&vio->lock, flags);
}

static void vdc_ldc_reset_work(struct work_struct *work)
{
	struct vdc_port *port;

	port = container_of(work, struct vdc_port, ldc_reset_work);

	vdc_ldc_reset(port);
}

/*
 * Reset the connection by disconnecting and reconnecting the LDC.
 * There is no need to free and reallocate the LDC; in fact this
 * causes various race conditions unless the channel is freed/allocated
 * under a mutex (see ldc.c:__ldc_channel_exits()).
 */
static void vdc_ldc_reset(struct vdc_port *port)
{
	struct vio_driver_state *vio = &port->vio;
	unsigned long flags;
	int err;

	pr_warn(PFX "%s ldc link reset\n", port->disk_name);

	spin_lock_irqsave(&vio->lock, flags);

	if (port->flags & VDC_PORT_RESET) {
		spin_unlock_irqrestore(&vio->lock, flags);
		wait_for_completion(&port->vio.cmp->com);
		return;
	}

	if (!port->disk)
		goto done;

	vio_link_state_change(vio, LDC_EVENT_RESET);
	port->flags |= VDC_PORT_RESET;
	spin_unlock_irqrestore(&vio->lock, flags);
	err = vdc_port_up(port);
	spin_lock_irqsave(&vio->lock, flags);
	if (err)
		pr_err(PFX "%s vdc_port_up() failed, err=%d\n",
		       port->disk_name, err);
	else
		vdc_resend_inflight(port);

	if (port->ldc_timeout)
		mod_timer(&port->ldc_reset_timer,
			  round_jiffies(jiffies + HZ * port->ldc_timeout));
	mod_timer(&vio->timer, round_jiffies(jiffies + HZ));

	port->flags &= ~VDC_PORT_RESET;
done:
	spin_unlock_irqrestore(&vio->lock, flags);
}

static const struct vio_device_id vdc_port_match[] = {
	{
		.type = "vdc-port",
	},
	{},
};
MODULE_DEVICE_TABLE(vio, vdc_port_match);

static struct vio_driver vdc_port_driver = {
	.id_table	= vdc_port_match,
	.probe		= vdc_port_probe,
	.remove		= vdc_port_remove,
	.name		= "vdc_port",
};

static int __init vdc_init(void)
{
	int err;

	sunvdc_wq = alloc_workqueue("sunvdc", 0, 0);
	if (!sunvdc_wq)
		return -ENOMEM;

	err = register_blkdev(0, VDCBLK_NAME);
	if (err < 0)
		goto out_free_wq;

	vdc_major = err;

	err = vio_register_driver(&vdc_port_driver);
	if (err)
		goto out_unregister_blkdev;

	return 0;

out_unregister_blkdev:
	unregister_blkdev(vdc_major, VDCBLK_NAME);
	vdc_major = 0;

out_free_wq:
	destroy_workqueue(sunvdc_wq);
	return err;
}

static void __exit vdc_exit(void)
{
	vio_unregister_driver(&vdc_port_driver);
	unregister_blkdev(vdc_major, VDCBLK_NAME);
	destroy_workqueue(sunvdc_wq);
}

module_init(vdc_init);
module_exit(vdc_exit);
