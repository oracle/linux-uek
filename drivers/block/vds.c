/* vds.c: LDOM Virtual Disk Server.
 *
 * Copyright (C) 2014 Oracle. All rights reserved.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/blkdev.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/device-mapper.h>

#include <asm/vio.h>
#include <asm/ldc.h>

#define DRV_MOD_NAME		"vds"
#define PFX DRV_MOD_NAME	": "
#define DRV_MOD_VERSION		"1.0"

static char version[] = DRV_MOD_NAME ".c:v" DRV_MOD_VERSION "\n";
MODULE_DESCRIPTION("LDOM virtual disk server driver");
MODULE_LICENSE("GPL");
MODULE_VERSION(DRV_MOD_VERSION);

#define VDS_TX_RING_SIZE	1024
#define	VDS_FMODE		(FMODE_READ|FMODE_WRITE|FMODE_EXCL)
#define	VDS_RETRIES		5
#define VDS_DEV_DELAY           1000000 /* 1 sec */

#define	VD_OP_BREAD		0x01	/* Block Read */
#define	VD_OP_BWRITE		0x02	/* Block Write */

#ifdef	VDS_CONNECT
#define WAITING_FOR_LINK_UP	0x01
#define WAITING_FOR_ANY		-1
#endif

#define	VDS_SEQ			0x1

#define VDS_DEBUG_INIT		0x01
#define VDS_DEBUG_HS		0x02
#define VDS_DEBUG_DATA		0x04
#define VDS_DEBUG_LOCK		0x08
#define VDS_DEBUG_WQ		0x10

int vds_dbg;
int vds_dbg_ldc;
int vds_dbg_vio;

module_param(vds_dbg, uint, 0664);
module_param(vds_dbg_ldc, uint, 0664);
module_param(vds_dbg_vio, uint, 0664);

#define vdsdbg(TYPE, f, a...)					\
	do {							\
		if (vds_dbg & VDS_DEBUG_##TYPE)			\
			pr_info("vds: ID[%lu] " f,		\
				 vio->vdev->channel_id, ## a);	\
	} while (0)

/*
 * Issues and workarounds.
 *
 * VDS_ALLOC_PAGES	disabled	Apparent page list corruption after
 *					allocating/freeing IO pages at once
 * VDS_CONNECT		disabled	LDC double handshake issues
 * VDS_WQ		enabled		Use vds workq instead of events workq
 *					The recommended value is 0 but that
 *					creates threads which scale with ncpu
 *					and becuase of some apparent flow
 *					control issues cause scsi timeouts so
 *					limit to 1 thread for now.
 */
#define	VDS_MAX_IO_PAGES	64
#define	VDS_WQ			1

int vds_wq = 1;
module_param(vds_wq, uint, 0664);

/*
 * I/O struct allocated dynamically per client request.
 * A request is scheduled in interrupt context and executed later
 * in a worker kernel thread in process context.  The default events
 * worker threads are used (1 per cpu).
 * A client request may cause a number bio operations which
 * are tracked by count below.
 */
struct vds_io {
	int ack;
	int error;
	u32 msglen;
	atomic_t count;
	void *msgbuf;
	void *desc_buf;
	struct vio_driver_state *vio;
	struct page *pages[VDS_MAX_IO_PAGES];
	struct completion event;
	struct work_struct vds_work;
	struct list_head list;
};

struct vds_port {
	struct vio_driver_state	vio;
	u8			flags;
	u8			xfer_mode;
	u64			max_xfer_size;
	u32			vdisk_block_size;
	u32			msglen;
	u64			seq;
	void			*msgbuf;
	const char		*bpath;
	struct block_device	*bdev;
#ifdef	VDS_WQ
	struct workqueue_struct	*wq;
#endif
	struct list_head	io_list;
};

static inline struct vds_port *to_vds_port(struct vio_driver_state *vio)
{
	return container_of(vio, struct vds_port, vio);
}

/* Ordered from largest major to lowest */
static struct vio_version vds_versions[] = {
	{ .major = 1, .minor = 0 },
};

#ifdef	VDS_CONNECT
static void vds_finish(struct vio_driver_state *vio, int err, int event)
{
	if (vio->cmp && (event == -1 || vio->cmp->waiting_for == event)) {
		vio->cmp->err = err;
		complete(&vio->cmp->com);
		vio->cmp = NULL;
	}
}
#endif

static void vds_handshake_complete(struct vio_driver_state *vio)
{
	struct vio_dring_state *dr;

	dr = &vio->drings[VIO_DRIVER_RX_RING];
	dr->snd_nxt = dr->rcv_nxt = 1;
#ifdef	VDS_CONNECT
	vds_finish(vio, 0, WAITING_FOR_LINK_UP);
#endif
}

static int vds_handle_unknown(struct vds_port *port)
{
	struct vio_msg_tag *pkt = port->msgbuf;

	pr_err(PFX "Received unknown msg [%02x:%02x:%04x:%08x]\n",
	       pkt->type, pkt->stype, pkt->stype_env, pkt->sid);
	pr_err(PFX "Resetting connection.\n");

	ldc_disconnect(port->vio.lp);

	return -ECONNRESET;
}

/* vio_driver_init() expects this. */
static int vds_send_attr(struct vio_driver_state *vio)
{
	return 0;
}

static int vds_handle_attr(struct vio_driver_state *vio, void *arg)
{
	struct vds_port *port = to_vds_port(vio);
	struct vio_disk_attr_info *pkt = arg;

	/* checkpatch.pl doesn't like split format strings */
	vdsdbg(HS, "GOT ATTR stype[0x%x] stype_env[0x%x] ",
	       pkt->tag.stype, pkt->tag.stype_env);

	vdsdbg(HS, "xfer_mode[0x%x] blksz[%u] max_xfer[%llu]\n",
	       pkt->xfer_mode, pkt->vdisk_block_size,
	       pkt->max_xfer_size);

	if (pkt->tag.type != VIO_TYPE_CTRL ||
	    pkt->tag.stype != VIO_SUBTYPE_INFO ||
	    pkt->tag.stype_env != VIO_ATTR_INFO ||
	    pkt->max_xfer_size == 0)
		goto nack;

	if (pkt->xfer_mode == VIO_DESC_MODE) {
		struct vio_disk_attr_info tmp;

		/*
		 * vio_disk_dring_inband contains no cookies; need room
		 * for up to n cookies, where "n" is the number of full
		 * pages plus possibly one partial page required to cover
		 * "max_xfer_size".  Add room for one more cookie if
		 * "max_xfer_size" isn't an integral multiple of the page size.
		 * Must first get the maximum transfer size in bytes.
		 */
		size_t max_xfer_bytes = pkt->vdisk_block_size ?
		    pkt->vdisk_block_size * pkt->max_xfer_size :
		    pkt->max_xfer_size;

		size_t max_inband_msglen =
		    sizeof(struct vio_disk_desc_inband) +
		    (((roundup(max_xfer_bytes, PAGE_SIZE) / PAGE_SIZE) + 1) *
		    sizeof(struct ldc_trans_cookie));

		vdsdbg(HS, "DESC ATTR max_ibm=%ld\n", max_inband_msglen);

		/*
		 * Set the maximum expected message length to
		 * accommodate in-band-descriptor messages with all
		 * their cookies.
		 */
		vio->desc_buf_len = max_inband_msglen;

		/*
		 * Reallocate before responding to the message since
		 * the next request in the handshake will use this size
		 * and a small msgbuf would make the ldc read fail.
		 */
		tmp = *pkt;
		kfree(port->msgbuf);
		port->msglen = max_inband_msglen;
		port->msgbuf = kzalloc(port->msglen, GFP_ATOMIC);
		memcpy(port->msgbuf, &tmp, sizeof(tmp));
		pkt = port->msgbuf;

	}

	port->xfer_mode = pkt->xfer_mode;

	BUG_ON(pkt->vdisk_block_size != port->vdisk_block_size);
	pkt->vdisk_block_size = port->vdisk_block_size;

	/* XXX OBP doesn't seem to honor max_xfer_size */
	pkt->max_xfer_size = port->max_xfer_size;
	pkt->vdisk_size = i_size_read(port->bdev->bd_inode) /
				      port->vdisk_block_size;
	pkt->vdisk_type = VD_DISK_TYPE_DISK;
	pkt->vdisk_mtype = VD_MEDIA_TYPE_FIXED;
	pkt->operations = VD_OP_BREAD | VD_OP_BWRITE;
	pkt->tag.stype = VIO_SUBTYPE_ACK;
	pkt->tag.sid = vio_send_sid(vio);

	vdsdbg(HS, "SEND ATTR dksz[%llu] blksz[%u] max_xfer[%llu]\n",
	       pkt->vdisk_size, pkt->vdisk_block_size,
	       pkt->max_xfer_size);

	return vio_ldc_send(&port->vio, pkt, sizeof(*pkt));

nack:
	pr_err("%s: Attribute NACK\n", vio->name);
	return -ECONNRESET;
}

static struct vio_driver_ops vds_vio_ops = {
	.send_attr		= vds_send_attr,
	.handle_attr		= vds_handle_attr,
	.handshake_complete	= vds_handshake_complete,
};

static void vds_end_io(struct bio *bio, int error)
{
	struct vds_io *io = bio->bi_private;
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);
	unsigned long flags;
	int done;

	vdsdbg(DATA, "bio_put(%p), count=%d\n", bio, atomic_read(&io->count));
	bio_put(bio);

	if (error) {
		pr_err("%s: IO error (%d)\n", __func__, error);
		if (!io->error)
			io->error = error;
	}

	/*
	 * Make sure complete() is called atomically for
	 * io.count == 0 and the IO operation is completely
	 * finished in case vds_event checks io.count.
	 */
	BUG_ON(atomic_read(&io->count) <= 0);
	vdsdbg(LOCK, "%s: lock\n", __func__);
	spin_lock_irqsave(&port->vio.lock, flags);
	vdsdbg(WQ, "%s: cpu=%d work=%p\n",
	       __func__, smp_processor_id(), &io->vds_work);
	done = atomic_dec_and_test(&io->count);
	mb();	/* XXX need barrier? */
	if (done)
		complete(&io->event);
	spin_unlock_irqrestore(&port->vio.lock, flags);
	vdsdbg(LOCK, "%s: unlock\n", __func__);
}

static void vds_start_io(struct work_struct *work);

static struct vds_io *
vds_io_alloc(struct vio_driver_state *vio)
{
	struct vds_port *port = to_vds_port(vio);
	struct vds_io *io;

	io = kzalloc(sizeof(*io), GFP_ATOMIC);
	if (!io)
		goto err;

	io->msgbuf = kzalloc(port->msglen, GFP_ATOMIC);
	if (!io->msgbuf)
		goto err;
	BUG_ON(!vio->desc_buf_len);
	io->desc_buf = kzalloc(vio->desc_buf_len, GFP_ATOMIC);
	if (!io->desc_buf)
		goto err;
	io->vio = vio;
	INIT_WORK(&io->vds_work, vds_start_io);
	INIT_LIST_HEAD(&io->list);

	return io;

err:
	kfree(io->msgbuf);
	kfree(io->desc_buf);
	kfree(io);

	return NULL;
}

static void
vds_io_free(struct vds_io *io)
{
	kfree(io->msgbuf);
	kfree(io->desc_buf);
	kfree(io);
}

static int vds_dring_done(struct vds_io *io)
{
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);
	struct vio_dring_data *pkt = io->msgbuf;
	struct vio_dring_state *dr = &vio->drings[VIO_DRIVER_RX_RING];
	struct vio_disk_desc *desc;
	int rv;
	int idx;

	desc = io->desc_buf;
	desc->status = io->error;
	desc->hdr.state = VIO_DESC_DONE;

	vdsdbg(DATA, "DRING DONE [%08llx:%08x:%08x:%02x:%08llx:%08llx]\n",
	       pkt->dring_ident,
	       pkt->start_idx,
	       pkt->end_idx,
	       pkt->state,
	       pkt->seq,
	       port->seq);

	vdsdbg(DATA,
	       "DRING DONE"
	       " [%02x:%02x:%08llx:%02x:%02x:%04d:%08llx:%08llx:%08x]\n",
	       desc->hdr.state,
	       desc->hdr.ack,
	       desc->req_id,
	       desc->operation,
	       desc->slice,
	       desc->status,
	       desc->offset,
	       desc->size,
	       desc->ncookies);

	idx = pkt->start_idx;
	rv = ldc_put_dring_entry(vio->lp, io->desc_buf, dr->entry_size,
				  (idx * dr->entry_size), dr->cookies,
				  dr->ncookies);
	if (rv != dr->entry_size)
		goto reset;

	/*
	 * If we successfully responded to the request (ack or nack),
	 * then return the actual IO operation return value, otherwise
	 * reset the connection.
	 */
	pkt->tag.stype = io->ack;
	rv = vio_ldc_send(vio, pkt, sizeof(*pkt));
	if (rv > 0) {
		rv = io->error;
		vds_io_free(io);
		vdsdbg(DATA, "DRING RET %d\n", rv);
		return rv;
	}

reset:
	pr_err("Reset VDS LDC rv[%d]\n", rv);
	vio_link_state_change(vio, LDC_EVENT_RESET);
	vds_io_free(io);

	vdsdbg(DATA, "DRING RESET\n");
	return -ECONNRESET;
}

static int vds_desc_done(struct vds_io *io)
{
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);
	struct vio_disk_desc_inband *pkt = io->msgbuf;
	struct vio_desc_data *hdr = &pkt->hdr;
	int rv;

	pkt->payload.status = io->error;
	hdr->tag.stype = io->ack;

	vdsdbg(DATA, "DESC DONE [%02x:%02x:%04x:%08x:%08llx:%08llx:%08llx]\n",
	       hdr->tag.type,
	       hdr->tag.stype,
	       hdr->tag.stype_env,
	       hdr->tag.sid,
	       hdr->desc_handle,
	       hdr->seq,
	       port->seq);

	vdsdbg(DATA, "DESC DONE [%08llx:%02x:%02x:%04d:%08llx:%08llx:%08x]\n",
	       pkt->payload.req_id,
	       pkt->payload.operation,
	       pkt->payload.slice,
	       pkt->payload.status,
	       pkt->payload.offset,
	       pkt->payload.size,
	       pkt->payload.ncookies);

	rv = vio_ldc_send(vio, pkt, io->msglen);
	if (rv <= 0) {
		pr_err("Reset VDS LDC rv[%d]\n", rv);
		vio_link_state_change(vio, LDC_EVENT_RESET);
		rv = -ECONNRESET;
	} else {
		rv = io->error;
	}

	vds_io_free(io);
	return rv;
}

#ifdef	VDS_ALLOC_PAGES
static int vds_ldc_copy(struct vio_driver_state *vio, int dir, void *buf,
			struct vio_disk_dring_payload *desc)
{
	int rv, err;

	rv = ldc_copy(vio->lp, dir, buf, desc->size, 0, desc->cookies,
		      desc->ncookies);
	if (rv > 0) {
		if (rv == desc->size)
			err = 0;
		else
			err = -EIO;
	} else
		err = rv;

	vdsdbg(DATA, "dir=%d size=%llu rv=%d err=%d\n",
	       dir, desc->size, rv, err);

	return err;
}
#else
static int vds_ldc_copy(struct vio_driver_state *vio, int dir,
			struct page **pages,
			struct vio_disk_dring_payload *desc)
{
	int i;
	int rv, err;
	u64 resid;
	void *buf;
	struct ldc_trans_cookie *cookie;

	rv = err = 0;
	resid = desc->size;

	for (i = 0; i < desc->ncookies; i++) {

		cookie = &desc->cookies[i];
		if (cookie->cookie_size > PAGE_SIZE) {
			err = -EMSGSIZE;
			break;
		}
		buf = page_address(pages[i]);
		BUG_ON(!buf);
		rv = ldc_copy(vio->lp, dir, buf, resid, 0, cookie, 1);
		if (rv > 0) {
			resid -= rv;
			if (!resid)
				break;
		} else {
			err = rv;
			break;
		}
	}

	if (resid != 0 && rv == 0)
		err = -EIO;

	vdsdbg(DATA, "dir=%d size=%llu rv=%d err=%d resid=%llu\n",
	       dir, desc->size, rv, err, resid);

	return err;
}
#endif

static void vds_start_io(struct work_struct *work)
{
	int i;
	int rw;
	int done;
	int nack = 1;
	int err = 0;
	struct bio *bio;
	struct page *page;
	unsigned npages;
	unsigned long len;
	unsigned long flags;
	sector_t offset, size, resid;
	struct blk_plug plug;
	struct vds_io *io = container_of(work, struct vds_io, vds_work);
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);
	struct vio_disk_dring_payload *desc;
#ifdef	VDS_ALLOC_PAGES
	void *buf;
	struct page *pages;
	unsigned ord;
#endif
	/*
	 * Dequeue the request.
	 */
	vdsdbg(DATA, "%s: io=%p\n", __func__, io);
	vdsdbg(LOCK, "%s: lock\n", __func__);
	spin_lock_irqsave(&vio->lock, flags);
	vdsdbg(WQ, "%s: cpu=%d work=%p\n",
	       __func__, smp_processor_id(), &io->vds_work);
	list_del(&io->list);
	spin_unlock_irqrestore(&vio->lock, flags);
	vdsdbg(LOCK, "%s: unlock\n", __func__);

	io->ack = VIO_SUBTYPE_ACK;
	io->error = 0;

	/*
	 * Get the request descriptor.
	 */
	switch (port->xfer_mode) {
	case VIO_DRING_MODE: {
		struct vio_disk_desc *d = io->desc_buf;
		desc = (struct vio_disk_dring_payload *)&d->req_id;

		vdsdbg(DATA, "DRING desc[%08llx:%08x:%08llx:%08llx]\n",
		       desc->size, desc->ncookies,
		       desc->cookies[0].cookie_addr,
		       desc->cookies[0].cookie_size);
		break;
	}
	case VIO_DESC_MODE: {
		struct vio_disk_desc_inband *d = io->desc_buf;
		desc = &d->payload;
		for (i = 0; i < desc->ncookies; i++)
			vdsdbg(DATA, "DESC desc[%08llx:%04x:%08llx:%08llx]\n",
			       desc->size, desc->ncookies,
			       desc->cookies[i].cookie_addr,
			       desc->cookies[i].cookie_size);
		break;
	}
	default:
		goto done;
	}

	switch (desc->operation) {
	case VD_OP_BREAD:
		rw = 0;
		break;
	case VD_OP_BWRITE:
		rw = WRITE;
		break;
	default:
		goto done;
	}

	/*
	 * Get the request size and block offset.
	 */
	offset = to_sector((desc->offset * port->vdisk_block_size));
	size = to_sector(desc->size);
	if (!size)
		goto done;

	/*
	 * Allocate pages for bio.
	 *
	 * Calculate one page per cookie rather using desc->size because
	 * for example a PAGE_SIZE request may be split across number of
	 * cookies.
	 *
	 * XXX Coalesce cookies with contiguous addresses in order to
	 * reduce the number of page allocations and bio requests.
	 */
	len = desc->ncookies * PAGE_SIZE;
	npages = len >> PAGE_SHIFT;
	nack = 0;
#ifdef	VDS_ALLOC_PAGES
	ord = get_order(len);
	pages = alloc_pages(GFP_KERNEL, ord);
	if (!pages) {
		err = -ENOMEM;
		goto done;
	}
	buf = page_address(pages);
	vdsdbg(DATA, "alloc_pages(%d)=%p va=%p\n", ord, pages, buf);

	for (i = 0; i < (1 << ord); i++) {
		page = pages + i;
		get_page(page);
		vdsdbg(DATA, "%p: count=%d flags=0x%lx\n",
		       page, page_count(page), page->flags);
	}

	if (rw & WRITE) {
		err = vds_ldc_copy(vio, LDC_COPY_IN, buf, desc);
		if (err)
			goto free;
	}
#else
	if (npages > VDS_MAX_IO_PAGES) {
		err = -ENOMEM;
		goto done;
	}
	for (i = 0; i < npages; i++) {
		page = alloc_page(GFP_KERNEL);
		if (!page) {
			int j;
			for (j = 0; j < i; j++) {
				__free_page(page);
				io->pages[i] = NULL;
			}
			goto done;
		}
		io->pages[i] = page;
	}

	if (rw & WRITE) {
		err = vds_ldc_copy(vio, LDC_COPY_IN, io->pages, desc);
		if (err)
			goto free;
	}
#endif
	rw |= REQ_SYNC;	/* device IO is always sync */
	resid = size;
	i = 0;

	BUG_ON(atomic_read(&io->count));
	atomic_set(&io->count, 1);
	init_completion(&io->event);

	/*
	 * Tell the driver to coalesce bio operations if possible.
	 */
	blk_start_plug(&plug);

	/*
	 * Break up the request into bio operations and submit them.
	 */
	while (resid) {
#ifdef	VDS_ALLOC_PAGES
		bio = bio_alloc_bioset(GFP_NOIO, npages, NULL);
#else
		bio = bio_alloc_bioset(GFP_NOIO, 1, NULL);
#endif
		bio->bi_sector = offset + (size - resid);
		bio->bi_bdev = port->bdev;
		bio->bi_end_io = vds_end_io;
		bio->bi_private = io;

		while (resid) {
			int rv;
			/*
			 * Try and add as many pages as possible.
			 */
			len = min(PAGE_SIZE, to_bytes(resid));
#ifdef	VDS_ALLOC_PAGES
			page = pages + i;
#else
			page = io->pages[i];
#endif

			/*
			 * XXX Can offset be non-zero?
			 */
			rv = bio_add_page(bio, page, len, 0);
			if (!rv)
				break;

			vdsdbg(DATA, "bio_add_page(%p, %p, %lx)=%d\n",
			       bio, page, len, rv);

			i++;
			npages--;
			resid -= to_sector(len);
			vdsdbg(DATA, "npages=%d, resid=%lu\n", npages, resid);
		}

		atomic_inc(&io->count);
		mb();	/* XXX need barrier? */
		vdsdbg(DATA, "submit_bio(%d, %p) count=%d\n",
		       rw, bio, atomic_read(&io->count));
		submit_bio(rw, bio);
	}

	blk_finish_plug(&plug);	/* let the bio ops go... */

	/*
	 * If the last bio completes after the dec_and_test check
	 * wait_for_completion() should not block and just return.
	 */
	done = atomic_dec_and_test(&io->count);
	mb();	/* XXX need barrier? */
	if (!done)
		wait_for_completion(&io->event);
	vdsdbg(DATA, "io complete count=%d\n", atomic_read(&io->count));

	if (!(rw & WRITE))
#ifdef	VDS_ALLOC_PAGES
		err = vds_ldc_copy(vio, LDC_COPY_OUT, buf, desc);
#else
		err = vds_ldc_copy(vio, LDC_COPY_OUT, io->pages, desc);
#endif

free:
#ifdef	VDS_ALLOC_PAGES
	vdsdbg(DATA, "Before __free_pages(%p, %u)\n", pages, ord);
	for (i = 0; i < (1 << ord); i++) {
		page = pages + i;
		put_page(page);
		vdsdbg(DATA, "%p: count=%d flags=0x%lx\n",
			page, page_count(page), page->flags);
	}

	__free_pages(pages, ord);

	vdsdbg(DATA, "After __free_pages(%p, %u)\n", pages, ord);
	for (i = 0; i < (1 << ord); i++) {
		page = pages + i;
		vdsdbg(DATA, "%p: count=%d flags=0x%lx\n",
			page, page_count(page), page->flags);
	}
#else
	for (i = 0; i < npages; i++) {
		__free_page(io->pages[i]);
		io->pages[i] = NULL;
	}
#endif

done:
	if (nack)
		io->ack = VIO_SUBTYPE_NACK;
	else if (err != 0 && io->error == 0)
		io->error = err > 0 ? err : -err;

	if (port->xfer_mode == VIO_DRING_MODE)
		(void) vds_dring_done(io);
	else if (port->xfer_mode == VIO_DESC_MODE)
		(void) vds_desc_done(io);
	else
		BUG();
}

static int vds_dring_io(struct vio_driver_state *vio)
{
	struct vds_port *port = to_vds_port(vio);
	struct vio_dring_data *pkt = port->msgbuf;
	struct vio_dring_state *dr = &vio->drings[VIO_DRIVER_RX_RING];
	struct vio_disk_desc *desc;
	struct vds_io *io = NULL;
	int reset = 0;
	int rv;
	int idx;

	vdsdbg(DATA, "DRING [%08llx:%08x:%08x:%02x:%08llx:%08llx]\n",
	       pkt->dring_ident,
	       pkt->start_idx,
	       pkt->end_idx,
	       pkt->state,
	       pkt->seq,
	       port->seq);

	io = vds_io_alloc(vio);
	if (!io)
		return -ENOMEM;

	memcpy(io->msgbuf, port->msgbuf, port->msglen);

	if ((port->flags & VDS_SEQ) && (pkt->seq != port->seq + 1)) {
		pr_err("Message out of sequence seq[0x%llx] vds_seq[0x%llx]\n",
		       pkt->seq, port->seq);
		goto err;
	}
	port->seq = pkt->seq;
	port->flags |= VDS_SEQ;
	reset = 1;

	if (port->xfer_mode != VIO_DRING_MODE) {
		pr_err("Invalid xfer mode pkt[0x%x] port[0x%x]\n",
		       pkt->tag.stype_env, port->xfer_mode);
		goto err;
	}

	idx = pkt->start_idx;
	if (idx != pkt->end_idx) {
		pr_err("Invalid idx start[%d] end[%d]\n", idx, pkt->end_idx);
		goto err;
	}

	rv = ldc_get_dring_entry(vio->lp, io->desc_buf, dr->entry_size,
				  (idx * dr->entry_size), dr->cookies,
				  dr->ncookies);
	if (rv != dr->entry_size)
		goto err;

	desc = (struct vio_disk_desc *)io->desc_buf;

	vdsdbg(DATA,
	       "DRING [%02x:%02x:%08llx:%02x:%02x:%04d:%08llx:%08llx:%08x]\n",
	       desc->hdr.state,
	       desc->hdr.ack,
	       desc->req_id,
	       desc->operation,
	       desc->slice,
	       desc->status,
	       desc->offset,
	       desc->size,
	       desc->ncookies);

	/*
	 * Queue the request.
	 */
	if (desc->hdr.state == VIO_DESC_READY) {
		list_add_tail(&io->list, &port->io_list);
#ifdef	VDS_WQ
		rv = queue_work(port->wq, &io->vds_work);
#else
		rv = schedule_work(&io->vds_work);
#endif
		vdsdbg(WQ, "%s: cpu=%d work=%p\n",
		       __func__, smp_processor_id(), &io->vds_work);
		BUG_ON(!rv);
		return 0;
	}

err:
	if (reset) {
		pr_err("Reset VDS LDC\n");
		vds_io_free(io);
		vio_link_state_change(vio, LDC_EVENT_RESET);
		rv = -ECONNRESET;
	} else {
		pr_err("NACK request io=%p\n", io);
		io->ack = VIO_SUBTYPE_NACK;
		io->error = 0;
		rv = vds_dring_done(io);
	}
	return rv;
}

static int vds_desc_io(struct vio_driver_state *vio, int msglen)
{
	struct vds_port *port = to_vds_port(vio);
	struct vio_disk_desc_inband *pkt = port->msgbuf;
	struct vio_desc_data *hdr = &pkt->hdr;
	struct vds_io *io = NULL;
	int rv;

	vdsdbg(DATA, "DESC [%02x:%02x:%04x:%08x:%08llx:%08llx:%08llx]\n",
	       hdr->tag.type,
	       hdr->tag.stype,
	       hdr->tag.stype_env,
	       hdr->tag.sid,
	       hdr->desc_handle,
	       hdr->seq,
	       port->seq);

	vdsdbg(DATA, "DESC [%08llx:%02x:%02x:%04d:%08llx:%08llx:%08x]\n",
	       pkt->payload.req_id,
	       pkt->payload.operation,
	       pkt->payload.slice,
	       pkt->payload.status,
	       pkt->payload.offset,
	       pkt->payload.size,
	       pkt->payload.ncookies);

	io = vds_io_alloc(vio);
	if (!io)
		return -ENOMEM;

	memcpy(io->msgbuf, port->msgbuf, msglen);

	if ((port->flags & VDS_SEQ) && (hdr->seq != port->seq + 1)) {
		pr_err("Message out of sequence seq[0x%llx] vds_seq[0x%llx]\n",
		       hdr->seq, port->seq);
#if 0
		/* XXX OBP seems to send out of sequence messages */
		goto nack;
#endif
	}
	port->seq = hdr->seq;
	port->flags |= VDS_SEQ;

	if (port->xfer_mode != VIO_DESC_MODE) {
		pr_err("Invalid xfer mode pkt[0x%x] port[0x%x]\n",
		       hdr->tag.stype_env, port->xfer_mode);
		goto nack;
	}

	/*
	 * Queue the request.
	 */
	memcpy(io->desc_buf, port->msgbuf, msglen);
	io->msglen = msglen;
	list_add_tail(&io->list, &port->io_list);
#ifdef	VDS_WQ
	queue_work(port->wq, &io->vds_work);
#else
	schedule_work(&io->vds_work);
#endif
	return 0;

nack:
	io->ack = VIO_SUBTYPE_NACK;
	io->error = 0;
	rv = vds_desc_done(io);
	return rv;
}

static void vds_event(void *arg, int event)
{
	struct vds_port *port = arg;
	struct vio_driver_state *vio = &port->vio;
	struct vio_msg_tag *tag;
	unsigned long flags;
	int rv;
	int msglen;

	vdsdbg(DATA, "%s: event=%d cpu=%d\n",
		     __func__, event, smp_processor_id());
	vdsdbg(LOCK, "%s: lock\n", __func__);
	spin_lock_irqsave(&vio->lock, flags);

	if (event == LDC_EVENT_RESET) {
		vio_link_state_change(vio, event);
		vio->desc_buf_len = 0;
		/*
		 * No need to free port->msgbuf here.  It was set to
		 * LDC_PACKET_SIZE at probe time and possibly increased
		 * for desc mode so its size is either sufficient or
		 * will be properly increased during attr exchange.
		 */
		kfree(port->msgbuf);
		port->msglen = LDC_PACKET_SIZE;
		port->msgbuf = kzalloc(port->msglen, GFP_ATOMIC);
		port->flags = 0;
#ifdef	VDS_CONNECT
		rv = ldc_connect(vio->lp);
		if (rv)
			pr_warn("%s: Port %lu connect failed, err=%d\n",
				 vio->name, vio->vdev->channel_id, rv);
#else
		ldc_clr_reset(vio->lp);
#endif
		goto done;
	} else if (event == LDC_EVENT_UP) {
		vio_link_state_change(vio, event);
		/*
		 * This is needed in dring mode.
		 */
		vio->dr_state &= ~VIO_DR_STATE_RXREQ;
		goto done;
	}

	if (event != LDC_EVENT_DATA_READY) {
		pr_warn(PFX "Unexpected LDC event %d\n", event);
		spin_unlock_irqrestore(&vio->lock, flags);
		vdsdbg(LOCK, "%s: unlock\n", __func__);
		return;
	}

	while (1) {
		rv = ldc_read(vio->lp, port->msgbuf, port->msglen);
		vdsdbg(DATA, "ldc_read(%d)=%d\n", port->msglen, rv);
		if (rv < 0) {
			if (rv == -ECONNRESET)
				vio_conn_reset(vio);
			break;
		}
		if (rv == 0)
			break;
		tag = port->msgbuf;
		vdsdbg(DATA, "TAG [%02x:%02x:%04x:%08x]\n",
		       tag->type,
		       tag->stype,
		       tag->stype_env,
		       tag->sid);
		msglen = rv;
		rv = vio_validate_sid(vio, tag);
		if (rv < 0)
			break;
		switch (tag->type) {
		case VIO_TYPE_CTRL:
			/*
			 * This is needed in dring mode.
			 */
			if (tag->stype == VIO_SUBTYPE_INFO &&
			    tag->stype_env == VIO_DRING_REG)
				vio->dr_state |= VIO_DR_STATE_RXREQ;
			rv = vio_control_pkt_engine(vio, port->msgbuf);
			break;
		case VIO_TYPE_DATA:
			switch (tag->stype) {
			case VIO_SUBTYPE_INFO:
				switch (tag->stype_env) {
				case VIO_DRING_DATA:
					rv = vds_dring_io(vio);
					break;
				case VIO_DESC_DATA:
					rv = vds_desc_io(vio, msglen);
					break;
				default:
					rv = -EINVAL;
					break;
				}
				break;
			default:
				rv = vds_handle_unknown(port);
				break;
			}
			break;
		default:
			rv = vds_handle_unknown(port);
			break;
		}
		if (rv < 0)
			break;
	}
#ifdef	VDS_CONNECT
	if (rv < 0)
		vds_finish(&port->vio, rv, WAITING_FOR_ANY);
#endif

done:
	spin_unlock_irqrestore(&vio->lock, flags);
	vdsdbg(LOCK, "%s: unlock\n", __func__);
}

static struct ldc_channel_config vds_ldc_cfg = {
	.event		= vds_event,
	.mtu		= 64,
	.mode		= LDC_MODE_UNRELIABLE,
};

static int bk_init(struct vds_port *port)
{
	struct vio_driver_state *vio = &port->vio;
	int i, rv;

	for (i = 0; i < VDS_RETRIES; i++) {
		port->bdev = blkdev_get_by_path(port->bpath, VDS_FMODE,
						(void *)port);
		if (!IS_ERR(port->bdev)) {
			rv = 0;
			break;
		}
		rv = PTR_ERR(port->bdev);
		if (rv != -EAGAIN)
			break;
		udelay(VDS_DEV_DELAY);
	}
	if (rv) {
		pr_err("%s: access failed (%d)\n", port->bpath, rv);
		port->bdev = NULL;
	} else {
		port->vdisk_block_size = bdev_logical_block_size(port->bdev);
		port->max_xfer_size = blk_queue_get_max_sectors(
				      bdev_get_queue(port->bdev), 0) /
				      port->vdisk_block_size;
		vdsdbg(INIT, "vdisk_block_size=%d max_xfer_size=%llu\n",
		       port->vdisk_block_size, port->max_xfer_size);
	}

	return rv;
}

#ifdef	VDS_CONNECT
static int vds_port_up(struct vio_driver_state *vio)
{
	struct vio_completion comp;

	init_completion(&comp.com);
	comp.err = 0;
	comp.waiting_for = WAITING_FOR_LINK_UP;
	vio->cmp = &comp;

	vio_port_up(vio);

	wait_for_completion(&comp.com);
	if (comp.err)
		return comp.err;

	return 0;
}
#endif

static void print_version(void)
{
	printk_once(KERN_INFO "%s", version);
}

static int vds_port_probe(struct vio_dev *vdev, const struct vio_device_id *id)
{
	struct mdesc_handle *hp;
	struct vds_port *port;
	struct vio_driver_state *vio;
	const char *bpath;
	int err;

	print_version();

	hp = mdesc_grab();

	port = kzalloc(sizeof(*port), GFP_KERNEL);
	if (!port) {
		pr_err(PFX "Cannot allocate vds_port.\n");
		err = -ENOMEM;
		goto release_mdesc;
	}

	port->msglen = LDC_PACKET_SIZE;
	port->msgbuf = kzalloc(port->msglen, GFP_KERNEL);
	if (!port->msgbuf) {
		err = -ENOMEM;
		goto free_port;
	}

	vio = &port->vio;

	err = vio_driver_init(vio, vdev, VDEV_DISK_SERVER,
			      vds_versions, ARRAY_SIZE(vds_versions),
			      &vds_vio_ops, (char *)dev_name(&vdev->dev));
	if (err)
		goto free_msgbuf;

	vio->debug = vds_dbg_vio;
	vds_ldc_cfg.debug = vds_dbg_ldc;

	err = vio_ldc_alloc(vio, &vds_ldc_cfg, port);
	if (err)
		goto free_msgbuf;

	bpath = mdesc_get_property(hp, vdev->mp, "vds-block-device", NULL);
	if (!bpath) {
		err = -ENXIO;
		goto free_ldc;
	}
	port->bpath = kstrdup(bpath, GFP_KERNEL);

#ifdef	VDS_WQ
	vdsdbg(WQ, "vds_wq=%d\n", vds_wq);
	port->wq = alloc_workqueue("vds", WQ_UNBOUND, vds_wq);
	if (!port->wq)
		goto free_bpath;
#endif

	err = bk_init(port);
	if (err)
		goto free_bpath;

	dev_set_drvdata(&vdev->dev, port);

#ifdef	VDS_CONNECT
	err = vds_port_up(vio);
#else
	err = ldc_bind(vio->lp, vio->name);
#endif
	if (err)
		goto put_blkdev;

	INIT_LIST_HEAD(&port->io_list);
	mdesc_release(hp);

	return 0;

put_blkdev:
	if (port->bdev)
		blkdev_put(port->bdev, VDS_FMODE);
free_bpath:
	kfree(port->bpath);

free_ldc:
	vio_ldc_free(&port->vio);

free_msgbuf:
	kfree(port->msgbuf);

free_port:
	kfree(port);

release_mdesc:
	mdesc_release(hp);

	return err;
}

static int vds_port_remove(struct vio_dev *vdev)
{
	struct vds_port *port = dev_get_drvdata(&vdev->dev);

	if (!port)
		return 0;

#ifdef	VDS_WQ
	flush_workqueue(port->wq);
#else
	flush_scheduled_work();
#endif

	if (port->bdev)
		blkdev_put(port->bdev, VDS_FMODE);

	del_timer_sync(&port->vio.timer);
#ifndef	VDS_CONNECT
	ldc_unbind(port->vio.lp);	/* XXX vds_port_down() for connect */
#endif
	vio_ldc_free(&port->vio);
	dev_set_drvdata(&vdev->dev, NULL);
	kfree(port->bpath);
	kfree(port->msgbuf);
	kfree(port);

	return 0;
}

static const struct vio_device_id vds_port_match[] = {
	{
		.type = "vds-port",
	},
	{},
};

static struct vio_driver vds_port_driver = {
	.id_table	= vds_port_match,
	.probe		= vds_port_probe,
	.remove		= vds_port_remove,
	.name		= "vds_port",
};

static int __init vds_init(void)
{
	return vio_register_driver(&vds_port_driver);
}

static void __exit vds_exit(void)
{
	vio_unregister_driver(&vds_port_driver);
}

module_init(vds_init);
module_exit(vds_exit);
