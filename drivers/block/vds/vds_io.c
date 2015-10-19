/*
 * vds_io.c: LDOM Virtual Disk Server.
 *
 * Copyright (C) 2014 Oracle. All rights reserved.
 */

#include "vds.h"
#include "vds_io.h"

#define	VDS_MAX_XFER_SIZE	(128 * 1024)
#define	VDS_RETRIES		5
#define VDS_DEV_DELAY           1000000 /* 1 sec */
#define	VDS_SLICE_NONE		0xff

static struct kmem_cache *vds_io_cache;
static int vds_ioc_size;
static char *vds_ioc_name = "vds_io";

int vds_io_init(void)
{
	int max_entry;
	int max_cookies;
	int max_dring_mode;
	int max_desc_mode;

	/*
	 * Create a kmem_cache for vds_io allocations.
	 *
	 * The size of the cache object accomdate the largest possible
	 * IO transfer initiated from either dring or descriptor mode.
	 */
	max_cookies = (roundup(VDS_MAX_XFER_SIZE, PAGE_SIZE) / PAGE_SIZE) + 1;
	max_cookies = max(max_cookies, VIO_MAX_RING_COOKIES);
	max_entry = max_cookies * sizeof(struct ldc_trans_cookie);

	max_dring_mode = LDC_PACKET_SIZE + sizeof(struct vio_disk_desc) +
			 max_entry;
	max_desc_mode = sizeof(struct vio_disk_desc_inband) + max_entry;

	vds_ioc_size = sizeof(struct vds_io) +
		       max(max_dring_mode, max_desc_mode);

	vds_io_cache = kmem_cache_create(vds_ioc_name, vds_ioc_size, 0,
					 0, NULL);
	if (!vds_io_cache) {
		vdsmsg(err, "Failed to create vds_io_cache\n");
		return -ENOMEM;
	}

	return 0;
}

void vds_io_fini(void)
{
	kmem_cache_destroy(vds_io_cache);
}

/*
 * Allocate a vds_io request structure.
 *
 * Allocate the structure from vds_io_cache if the total required
 * space fits within a vds_io_cache object; otherwise use kmalloc().
 *
 * XXX In principle, the kmalloc() method should not be required
 * since vds_io_cache should accommodate the largest supported IO
 * transfer size defined as VDS_MAX_XFER_SIZE.  The max_xfer_size
 * parameter is negotiated during the handshake and should be honored
 * by all clients; however, it seems that OBP does not do that.
 * This should not be an issue since VDS_MAX_XFER_SIZE should
 * always be larger than any OBP transfer size but the kmalloc()
 * option is there since an OBP transfer size > VDS_MAX_XFER_SIZE
 * could theoretically cause memory corruption.
 *
 * The proper thing to do would be nack an non-conforming transfer size.
 */
struct vds_io *vds_io_alloc(struct vio_driver_state *vio,
			    void (*func)(struct work_struct *))
{
	struct vds_port *port = to_vds_port(vio);
	struct vds_io *io;
	int size;

	size = sizeof(*io) + port->msglen + vio->desc_buf_len;
	vdsdbg(MEM, "size=%d ioc_size=%d\n", size, vds_ioc_size);

	if (size <= vds_ioc_size) {
		io = kmem_cache_zalloc(vds_io_cache, GFP_ATOMIC);

		if (!io)
			return NULL;
		io->flags = VDS_IO_CACHE;
		io->msgbuf = io->buf;
		io->desc_buf = io->buf + port->msglen;
	} else {
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
	}
	io->vio = vio;
	if (func)
		INIT_WORK(&io->vds_work, func);

	return io;

err:
	kfree(io->msgbuf);
	kfree(io->desc_buf);
	kfree(io);

	return NULL;
}

void vds_io_free(struct vds_io *io)
{
	if (io->flags & VDS_IO_CACHE) {
		kmem_cache_free(vds_io_cache, io);
	} else {
		kfree(io->msgbuf);
		kfree(io->desc_buf);
		kfree(io);
	}
}

static int vds_io_alloc_pages(struct vds_io *io, unsigned long len)
{
	struct vio_driver_state *vio = io->vio;

	BUG_ON(len % PAGE_SIZE != 0);
	io->ord = get_order(len);
	io->pages = alloc_pages(GFP_KERNEL | __GFP_COMP, io->ord);
	if (!io->pages)
		return -ENOMEM;
	io->npages = len >> PAGE_SHIFT;

	vdsdbg(MEM, "ord=%d pages=%p npages=%d\n", io->ord, io->pages,
	       io->npages);

	return 0;
}

static void vds_io_free_pages(struct vds_io *io)
{
	__free_pages(io->pages, io->ord);

	io->pages = NULL;
	io->npages = 0;
	io->ord = 0;
}

void vds_io_enq(struct vds_io *io)
{
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);

	vdsdbg(WQ, "cpu=%d\n", smp_processor_id());

	BUG_ON(!in_interrupt());

	if (io->flags & VDS_IO_FINI)
		queue_work(port->rtq, &io->vds_work);
	else
		queue_work(port->ioq, &io->vds_work);
}

static int vds_io_rw(struct vds_io *io)
{
	int err;
	void *buf;
	unsigned long len;
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);

	vdsdbg(IO, "(0x%p, %lld, %ld, %d)\n", io->addr, io->size,
	       io->offset, io->rw);

	if (!to_sector(io->size))
		return -EINVAL;

	if (!port->be_ops)
		return -EIO;

	len = (unsigned long)roundup(io->size, PAGE_SIZE);
	err = vds_io_alloc_pages(io, len);
	if (err)
		return err;

	buf = page_address(io->pages);

	BUG_ON(!buf);
	BUG_ON(!io->addr);

	if (io->rw & WRITE)
		memcpy(buf, io->addr, io->size);

	err = port->be_ops->rw(io);

	if (!err && !(io->rw & WRITE))
		memcpy(io->addr, buf, io->size);

	vds_io_free_pages(io);

	return err;
}

/*
 * Common routine for read/write/clear interfaces.
 */
static int vds_rw(struct vds_port *port, void *addr, sector_t offset, u64 size,
		  int rw)
{
	int rv = -ENOMEM;
	struct vds_io *io;
	struct vio_driver_state *vio = &port->vio;

	io = vds_io_alloc(vio, NULL);
	if (io) {
		io->addr = addr;
		io->offset = offset;
		io->size = size;
		io->rw = rw;
		rv = vds_io_rw(io);
		vds_io_free(io);
	}

	vdsdbg(IO, "addr=%p offset=%lu size=%llu rw=%d rv=%d\n",
	       addr, offset, size, rw, rv);

	return rv;
}

inline int vds_read(struct vds_port *port, void *addr, sector_t off, u64 size)
{
	return vds_rw(port, addr, off, size, 0);
}

inline int vds_write(struct vds_port *port, void *addr, sector_t off, u64 size)
{
	return vds_rw(port, addr, off, size, WRITE);
}

inline int vds_clear(struct vds_port *port, sector_t offset, u64 size)
{
	int rv;
	void *addr;

	addr = kzalloc(size, GFP_KERNEL);
	if (!addr)
		return -ENOMEM;

	rv = vds_rw(port, addr, offset, size, WRITE);

	kfree(addr);

	return rv;
}

static int vds_copy(struct vio_driver_state *vio, int dir, void *buf,
		    struct vio_disk_dring_payload *desc, u64 size, u64 offset)
{
	int rv, err;

	if (!size)
		size = desc->size;

	rv = ldc_copy(vio->lp, dir, buf, size, offset, desc->cookies,
		      desc->ncookies);
	if (rv > 0) {
		if (rv == size)
			err = 0;
		else
			err = -EIO;
	} else
		err = rv;

	vdsdbg(BIO, "dir=%d size=%llu offset=%llu rv=%d err=%d\n",
	       dir, size, offset, rv, err);

	return err;
}

int vd_op_get_vtoc(struct vds_io *io)
{
	int rv;
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);

	rv = vds_label_get_vtoc(port);
	if (rv)
		vdsdbg(IOC, "vds_label_get_vtoc rv=%d\n", rv);

	if (rv == 0 || rv == -EINVAL)
		rv = vds_copy(vio, LDC_COPY_OUT, port->vtoc, io->desc, 0, 0);

	vdsdbg(IOC, "VD_OP_GET_VTOC ascii=%s\n", port->vtoc->ascii_label);
	vdsdbg(IOC, "VD_OP_GET_VTOC rv=%d\n", rv);

	return rv;
}

int vd_op_set_vtoc(struct vds_io *io)
{
	int rv = 0;
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);

	vds_label_lock(port, vio);

	rv = vds_copy(vio, LDC_COPY_IN, port->vtoc, io->desc, 0, 0);

	if (rv == 0 && port->label_type == VDS_LABEL_EFI)
		rv = vds_efi_clear(port);

	if (!rv)
		rv = vds_vtoc_set(port, port->vtoc);

	vds_label_unlock(port, vio);

	vdsdbg(IOC, "VD_OP_SET_VTOC ascii=%s\n", port->vtoc->ascii_label);
	vdsdbg(IOC, "VD_OP_SET_VTOC rv=%d\n", rv);
	return rv;
}

int vd_op_get_geom(struct vds_io *io)
{
	int rv;
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);

	rv = vds_label_get_vtoc(port);
	if (rv)
		vdsdbg(IOC, "vds_label_get_vtoc rv=%d\n", rv);

	if (rv == 0 || rv == -EINVAL) {
		struct vio_disk_geom *geom = port->geom;

		vdsdbg(IOC, "ncyl=%u nhd=%u nsec=%u\n",
		       geom->phy_cyl, geom->num_hd, geom->num_sec);

		rv = vds_copy(vio, LDC_COPY_OUT, geom, io->desc, 0, 0);
	}

	vdsdbg(IOC, "VD_OP_GET_DISKGEOM rv=%d\n", rv);

	return rv;
}

int vd_op_set_geom(struct vds_io *io)
{
	int rv;
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);

	rv = vds_copy(vio, LDC_COPY_IN, port->geom, io->desc, 0, 0);

	vdsdbg(IOC, "VD_OP_SET_DISKGEOM rv=%d\n", rv);

	return rv;
}

int vd_op_get_efi(struct vds_io *io)
{
	int rv;
	size_t len;
	void *data;
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);
	struct vio_disk_efi efi_in;
	struct vio_disk_efi *efi_out = NULL;

	rv = vds_copy(vio, LDC_COPY_IN, &efi_in, io->desc, sizeof(efi_in), 0);
	if (rv)
		goto done;

	vds_label_lock(port, vio);

	/*
	 * Adjust the required len by an additional VIO EFI header
	 * so that the returned results are contiguous and can be
	 * copied out all at once.
	 */
	len = efi_in.len + sizeof(struct vio_disk_efi);
	efi_out = kzalloc(len, GFP_KERNEL);
	if (efi_out) {
		data = (void *)efi_out + sizeof(struct vio_disk_efi);
		rv = vds_efi_get(port, efi_in.lba, efi_in.len, data);
	} else
		rv = -ENOMEM;

	if (!rv) {
		efi_out->lba = efi_in.lba;
		efi_out->len = efi_in.len;
		rv = vds_copy(vio, LDC_COPY_OUT, efi_out, io->desc, len, 0);
	}

	vds_label_unlock(port, vio);

done:
	vdsdbg(IOC, "VD_OP_GET_EFI rv=%d\n", rv);
	kfree(efi_out);

	return rv;
}

int vd_op_set_efi(struct vds_io *io)
{
	int rv;
	struct vio_disk_efi *efi;
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);

	efi = kzalloc(roundup(io->desc->size, 8), GFP_KERNEL);
	if (!efi) {
		rv = -ENOMEM;
		goto done;
	}

	vds_label_lock(port, vio);

	rv = vds_copy(vio, LDC_COPY_IN, efi, io->desc, 0, 0);

	if (rv == 0 && port->label_type == VDS_LABEL_VTOC)
		rv = vds_vtoc_clear(port);

	if (!rv)
		rv = vds_efi_set(port, efi->lba, efi->len, efi->data);

	vds_label_unlock(port, vio);

done:
	vdsdbg(IOC, "VD_OP_SET_EFI rv=%d\n", rv);
	kfree(efi);

	return rv;
}

int vd_op_flush(struct vio_driver_state *vio)
{
	int rv;
	struct vds_port *port = to_vds_port(vio);

	if (port->be_ops) {
		flush_workqueue(port->ioq);
		rv = port->be_ops->flush(port);
	} else
		rv = -EIO;

	vdsdbg(FLUSH, "VD_OP_FLUSH rv=%d\n", rv);
	return rv;
}

int vd_op_rw(struct vds_io *io)
{
	int err = 0;
	u8 slice;
	unsigned long len, dsz;
	sector_t offset, size, start;
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);
	struct vio_disk_dring_payload *desc;
	void *buf;

	desc = io->desc;

	/*
	 * Get the request size and block offset.
	 */
	offset = to_sector((desc->offset * port->vdisk_bsize));
	size = to_sector(desc->size);
	if (!size) {
		io->ack = VIO_SUBTYPE_NACK;
		goto done;
	}

	/*
	 * If a slice is provided, make sure there is label info
	 * to read the slice offset from.
	 */
	slice = desc->slice;
	if (slice != VDS_SLICE_NONE) {
		err = vds_label_get_start(port, slice, &start);
		if (err) {
			io->ack = VIO_SUBTYPE_NACK;
			goto done;
		}
		offset += start;
	}

	/*
	 * Allocate pages for io.
	 *
	 * Calculate one page per cookie rather using desc->size because
	 * for example a PAGE_SIZE request may be split across number of
	 * cookies.
	 *
	 * XXX Coalesce cookies with contiguous addresses in order to
	 * reduce the number of page allocations and bio requests.
	 */
	len = (unsigned long)desc->ncookies * PAGE_SIZE;
	dsz = (unsigned long)roundup(desc->size, PAGE_SIZE);
	len = max(len, dsz);
	err = vds_io_alloc_pages(io, len);
	if (err)
		goto done;

	buf = page_address(io->pages);

	if (io->rw & WRITE) {
		err = vds_copy(vio, LDC_COPY_IN, buf, desc, 0, 0);
		if (err)
			goto free;
	}

	/*
	 * Call the backend to perform the actual operation.
	 */
	io->size = desc->size;
	io->offset = offset;

	if (port->be_ops)
		err = port->be_ops->rw(io);
	else
		err = -EIO;

	if (!err && !(io->rw & WRITE))
		err = vds_copy(vio, LDC_COPY_OUT, buf, desc, 0, 0);

free:
	vds_io_free_pages(io);

	if (offset <= 1 && (io->rw & WRITE))
		vds_label_init(port);

done:
	return err;
}

/*
 * Backend operations.
 */
int vds_be_init(struct vds_port *port)
{
	int i, rv;
	bool iso;
	umode_t mode;
	struct path path;
	struct inode *inode;
	struct vio_driver_state *vio = &port->vio;

	rv = kern_path(port->path, LOOKUP_FOLLOW, &path);
	if (rv)
		goto done;

	inode = path.dentry->d_inode;
	mode = inode->i_mode;
	path_put(&path);

	if (S_ISREG(mode))
		port->be_ops = vds_reg_get_ops();
	else if (S_ISBLK(mode))
		port->be_ops = vds_blk_get_ops();
	else
		rv = -ENODEV;

	if (!rv)
		for (i = 0; i < VDS_RETRIES; i++) {
			rv = port->be_ops->init(port);
			if (rv == 0 || rv != -EAGAIN)
				break;
			udelay(VDS_DEV_DELAY);
		}

	vdsdbg(HS, "vdisk_blk_sz=%u vdisk_sz=%llu max_xfer_sz=%llu\n",
	       port->vdisk_bsize, port->vdisk_size, port->max_xfer_size);

	if (!(port->vdisk_bsize && port->vdisk_size && port->max_xfer_size)) {
		rv = -EINVAL;
		goto done;
	}

	rv = vds_label_chk_iso(port, &iso);
	if (rv) {
		vdsmsg(err, "media check error\n");
		goto done;
	}

	/*
	 * Indicate whether to call this a CD or DVD from the size
	 * of the ISO image (images for both drive types are stored
	 * in the ISO-9600 format). CDs can store up to just under 1Gb
	 */
	if (!iso)
		port->media_type = VD_MEDIA_TYPE_FIXED;
	else if ((port->vdisk_size * port->vdisk_bsize) > ONE_GIGABYTE)
		port->media_type = VD_MEDIA_TYPE_DVD;
	else
		port->media_type = VD_MEDIA_TYPE_CD;

	vds_label_init(port);

done:
	if (rv)
		vdsmsg(err, "%s: init failed (%d)\n", port->path, rv);

	return rv;
}

void vds_be_fini(struct vds_port *port)
{
	flush_workqueue(port->ioq);
	vds_label_fini(port);
	if (port->be_ops) {
		port->be_ops->fini(port);
		port->be_data = NULL;
	}
}
