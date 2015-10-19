/*
 * vds_blk.c: LDOM Virtual Disk Server.
 *
 * Copyright (C) 2014 Oracle. All rights reserved.
 */

#include "vds.h"
#include "vds_io.h"

#define	VDS_FMODE		(FMODE_READ | FMODE_WRITE | FMODE_EXCL)

static int vds_blk_init(struct vds_port *port)
{
	struct block_device *bdev;

	bdev = blkdev_get_by_path(port->path, VDS_FMODE, (void *)port);
	if (IS_ERR(bdev))
		return (int)(PTR_ERR(bdev));

	port->vdisk_bsize = bdev_logical_block_size(bdev);
	port->vdisk_size = i_size_read(bdev->bd_inode) / port->vdisk_bsize;
	port->max_xfer_size = to_bytes(blk_queue_get_max_sectors(
			      bdev_get_queue(bdev), 0)) / port->vdisk_bsize;

	port->be_data = bdev;

	return 0;
}

static void vds_blk_fini(struct vds_port *port)
{
	struct block_device *bdev = port->be_data;

	if (bdev)
		blkdev_put(bdev, VDS_FMODE);
}

static void vds_blk_end_io(struct bio *bio, int error)
{
	struct vds_io *io = bio->bi_private;
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);
	unsigned long flags;
	int done;

	vdsdbg(BIO, "bio_put(%p), count=%d\n", bio, atomic_read(&io->count));
	bio_put(bio);

	if (error) {
		vdsmsg(err, "IO error (%d)\n", error);
		if (!io->error)
			io->error = error;
	}

	/*
	 * Make sure complete() is called atomically for
	 * io.count == 0 and the IO operation is completely
	 * finished in case vds_event checks io.count.
	 */
	BUG_ON(atomic_read(&io->count) <= 0);
	vdsdbg(LOCK, "lock\n");
	spin_lock_irqsave(&port->vio.lock, flags);
	vdsdbg(WQ, "cpu=%d work=%p\n", smp_processor_id(), &io->vds_work);
	done = atomic_dec_and_test(&io->count);
	mb();	/* XXX need barrier? */
	if (done)
		complete(&io->event);
	spin_unlock_irqrestore(&port->vio.lock, flags);
	vdsdbg(LOCK, "unlock\n");
}

static int vds_blk_rw(struct vds_io *io)
{
	int i;
	int rw;
	int done;
	int err = 0;
	struct bio *bio;
	struct page *page, *pages;
	unsigned npages;
	unsigned long len;
	unsigned long biolen, biomax;
	sector_t offset, size, resid;
	struct blk_plug plug;
	struct vio_driver_state *vio = io->vio;
	struct vds_port *port = to_vds_port(vio);
	struct block_device *bdev = port->be_data;

	vdsdbg(BIO, "(0x%p, %lld, %ld, %d)\n", io->pages, io->size,
	       io->offset, io->rw);

	rw = io->rw;
	size = to_sector(io->size);
	offset = io->offset;
	pages = io->pages;
	npages = io->npages;
	len = npages << PAGE_SHIFT;

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

	biomax = port->max_xfer_size * port->vdisk_bsize;

	/*
	 * Break up the request into bio operations and submit them.
	 */
	while (resid) {
		bio = bio_alloc(GFP_NOIO, npages);
		bio->bi_iter.bi_sector = offset + (size - resid);
		bio->bi_bdev = bdev;
		bio->bi_end_io = vds_blk_end_io;
		bio->bi_private = io;

		for (biolen = 0; resid; biolen += len) {
			int rv;

			/*
			 * Try and add as many pages as possible.
			 */
			BUG_ON(biolen > biomax);
			len = min(PAGE_SIZE, to_bytes(resid));
			len = min(len, biomax - biolen);
			if (!len)
				break;
			page = pages + i;

			/*
			 * XXX Can offset be non-zero?
			 */
			rv = bio_add_page(bio, page, len, 0);
			vdsdbg(BIO, "bio_add_page(%p, %p, %lx)=%d\n",
			       bio, page, len, rv);
			vdsdbg(BIO, "bi_sector=%lu, bi_size=%u\n",
			       bio->bi_iter.bi_sector, bio->bi_iter.bi_size);

			if (!rv) {
				vdsmsg(err,
				       "bio_add_page: resid=%ld biolen=%ld\n",
				       resid, biolen);
				err = -EIO;
				break;
			}

			i++;
			npages--;
			resid -= to_sector(len);
			vdsdbg(BIO, "npages=%d, resid=%lu\n", npages, resid);
		}

		if (err)
			break;

		atomic_inc(&io->count);
		mb();	/* XXX need barrier? */
		vdsdbg(BIO, "submit_bio(%d, %p) count=%d\n",
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
	vdsdbg(BIO, "io complete count=%d\n", atomic_read(&io->count));

	return err;
}

static int vds_blk_flush(struct vds_port *port)
{
	struct block_device *bdev = port->be_data;

	return blkdev_issue_flush(bdev, GFP_KERNEL, NULL);
}

struct vds_be_ops vds_blk_ops = {
	vds_blk_init,
	vds_blk_fini,
	vds_blk_rw,
	vds_blk_flush,
};

struct vds_be_ops *vds_blk_get_ops()
{
	return &vds_blk_ops;
}
