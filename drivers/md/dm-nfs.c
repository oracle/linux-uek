/*
 * Copyright (C) 2008 Oracle.  All rights reserved.
 *
 * Prototype dm-nfs by Chuck Lever <chuck.lever@oracle.com>
 * based on dm-loop written by Bryn Reeves <breeves@redhat.com>.
 *
 * This file is released under the GPL.
 *
 * "dm-nfs" provides loopback-style emulation of a block device
 * using a regular file as backing storage.  The backing file
 * resides on a remote system and is accessed via the NFS protocol.
 * The NFS server on which the file resides must already be locally
 * mounted when an individual dm-nfs target is set up, and cannot
 * be unmounted until such a target is destroyed.
 *
 * This driver is separate from dm-loop for several reasons.
 *
 * 1. Provide good data integrity and reasonable performance given
 *    the write delaying behavior of the NFS client.
 *
 * 2. Reduce or eliminate double caching.  Data for the target is
 *    already cached above the emulated block device; caching the
 *    backing file's data will pollute the page cache, risk exposing
 *    the data to others who can view pages in the cache, and risk
 *    data integrity when the backing file is accessed by multiple
 *    targets (eg. offline backup).
 *
 * 3. Local file-based targets require extra logic that is not
 *    needed for NFS file-based targets.  Extent management is
 *    entirely unnecessary for NFS files, for example.
 *
 * 4. There is no need to protect against file truncation.  In
 *    the dm-loop case, truncation could result in writes into
 *    unallocated blocks or blocks allocated to other files.  For
 *    NFS files, this is entirely the NFS server's problem.
 *
 *    In any case, setting S_SWAPFILE on an NFS file will cause
 *    the NFS client to reject all write requests to that file.
 *
 *    The best we might do is set up an advisory file lock on the
 *    backing file, but for now that appears to be unnecessary.
 */

/*
 * TODO:
 *
 * 1. Asynch I/O - submit all I/O at once and allow asynchronous
 *    completion of bios.
 *
 * 2. Direct I/O - teach the NFS client's direct I/O engine to deal
 *    with non-user-space buffers intelligently, then use direct I/O
 *    to avoid the page cache entirely
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/syscalls.h>
#include <linux/workqueue.h>
#include <linux/file.h>
#include <linux/bio.h>

#include "dm.h"

#define DM_NFS_DAEMON "kdmnfsd"
#define DM_MSG_PREFIX "nfs"


struct nfs_c {
	unsigned long flags;

	/* These fields describe this target's backing store */

	struct file		*filp;
	char			*path;
	loff_t			offset;
	loff_t			size;
	sector_t		mapped_sectors;

	/* These fields describe this target's work queue */

	struct workqueue_struct	*wq;
	struct work_struct	ws;

	spinlock_t		lock;
	struct bio_list		input;
	struct bio_list		work;
};


/*--------------------------------------------------------------------
 * dm-nfs helpers
 *--------------------------------------------------------------------*/

static int _check_file(struct dm_target *ti)
{
	struct nfs_c *nc = ti->private;
	struct file *filp = nc->filp;
	struct inode *inode = filp->f_mapping->host;

	if (!inode)
		return -ENXIO;

	ti->error = "backing file must be a regular file";
	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	ti->error = "backing file is mapped into userspace for writing";
	if (mapping_writably_mapped(filp->f_mapping))
		return -EBUSY;

	if (mapping_mapped(filp->f_mapping))
		DMWARN("%s is mapped into userspace", nc->path);

	ti->error = "backing file does not reside on an NFS mount";
	if (strncmp(inode->i_sb->s_type->name, "nfs", 3) != 0)
		return -EBADF;

	return 0;
}

static int _check_size(struct dm_target *ti)
{
	struct nfs_c *nc = ti->private;
	struct inode *inode = nc->filp->f_mapping->host;
	loff_t end, size;
	int r = -EINVAL;

	nc->size = i_size_read(inode);

	ti->error = "backing file is empty";
	if (!nc->size)
		goto out;

	DMDEBUG("set backing file size to %llu", (unsigned long long) nc->size);

	ti->error = "backing file cannot be less than one block in size";
	size = (1 << (inode->i_blkbits - SECTOR_SHIFT)) << SECTOR_SHIFT;
	if (nc->size < size)
		goto out;

	ti->error = "dm-nfs file offset must be a multiple of fs blocksize";
	if (nc->offset & ((1 << inode->i_blkbits) - 1))
		goto out;

	ti->error = "dm-nfs file offset too large";
	if (nc->offset > (nc->size - (1 << SECTOR_SHIFT)))
		goto out;

	nc->mapped_sectors = (nc->size - nc->offset) >> SECTOR_SHIFT;
	DMDEBUG("set mapped sectors to %llu (%lld bytes)",
		(unsigned long long) nc->mapped_sectors,
		nc->size - nc->offset);

	end = ti->len << SECTOR_SHIFT;
	ti->error = "mapped region cannot be smaller than target size";
	if (nc->size - nc->offset < end)
		goto out;

	end = nc->offset + (nc->mapped_sectors << SECTOR_SHIFT);
	if (end < nc->size)
		DMWARN("not using %lld bytes in incomplete block at EOF",
		       nc->size - end);

	r = 0;

out:
	return r;
}

static int dm_nfs_io_get_file(struct dm_target *ti, uid_t uid)
{
	int flags = ((dm_table_get_mode(ti->table) & FMODE_WRITE) ?
		     O_RDWR : O_RDONLY) | O_LARGEFILE;
	struct nfs_c *nc = ti->private;
	struct file *filp;
	uid_t save;
	int r = 0;
	struct cred *new;

	/*
	 * To prevent the server from squashing our I/O because
	 * we are root, force all I/O from our kthread to use
	 * the given user's credentials instead.
	 */
	save = current_fsuid();
	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	new->fsuid = uid;
	commit_creds(new);

	ti->error = "could not open backing file";
	filp = filp_open(nc->path, flags, 0);
	if (IS_ERR(filp))
		return PTR_ERR(filp);
	nc->filp = filp;

	r = _check_file(ti);
	if (r)
		goto err;

	r = _check_size(ti);
	if (r)
		goto err;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	new->fsuid = save;
	commit_creds(new);

	return 0;

err:
	fput(filp);
	return r;
}

static void dm_nfs_io_put_file(struct file *filp)
{
	if (filp)
		filp_close(filp, NULL);
}

/*
 * Force an efficient page cache fill with the equivalent of
 * fadvise(POSIX_FADV_WILLNEED) on the backing pages to be read
 * in next.  force_page_cache_readahead will generate two megabyte
 * ->readpages calls against the backing file until all requested
 *  pages are populated.
 *
 * Since this is no more than a hint to the VFS, don't bother
 * looking for returned errors.
 */
static void dm_nfs_io_populate_cache(struct file *filp, loff_t offset,
				     loff_t len)
{
	loff_t endbyte;
	pgoff_t start_index, end_index;
	unsigned long nrpages;
	struct file_ra_state *ra = NULL;

        ra = kzalloc(sizeof(*ra), GFP_NOFS);
        if (!ra) 
	    goto dm_ra;

	/* Careful about overflows. Len == 0 means "as much as possible" */
	endbyte = offset + len;
	if (!len || endbyte < len)
		endbyte = -1;
	else
		endbyte--;		/* inclusive */

	start_index = offset >> PAGE_CACHE_SHIFT;
	end_index = endbyte >> PAGE_CACHE_SHIFT;

	/* Careful about overflow on the "+1" */
	nrpages = end_index - start_index + 1;
	if (!nrpages)
		nrpages = ~0UL;

	file_ra_state_init(ra, filp->f_mapping);
	page_cache_sync_readahead(filp->f_mapping, ra,filp, start_index, nrpages);

dm_ra:
	if (ra)
	    kfree(ra);
	else
	    DMERR("populate cache failed to allocate ra memory");
}

static int dm_nfs_io_fsync(struct file *filp)
{
	int r;

	r = filp->f_op->flush(filp, NULL);
	if (r)
		DMERR("backing file flush failed: %d", r);
	return r;
}

/*
 * Invalidate all unlocked cache pages for a backing file
 *
 * As long as I/O and invalidation for a given backing file
 * are performed serially in a single thread and there are
 * no other accessors of the backing file, this should
 * effectively invalidate all cached backing file pages each
 * time it is invoked.
 */
static void dm_nfs_io_invalidate_pages(struct file *filp)
{
	unmap_mapping_range(filp->f_mapping, 0, ~0UL, 0);

	if (filemap_write_and_wait(filp->f_mapping))
		return;

	invalidate_inode_pages2_range(filp->f_mapping, 0, ~0UL);
}

static void dm_nfs_io_retry_wait(struct kiocb *iocb)
{
	set_current_state(TASK_UNINTERRUPTIBLE);
	if (!kiocbIsKicked(iocb))
		schedule();
	else
		kiocbClearKicked(iocb);
	__set_current_state(TASK_RUNNING);
}


/*--------------------------------------------------------------------
 * dm-nfs functions that run in a separate kernel thread
 *--------------------------------------------------------------------*/

/*
 * Normally, the NFS client's aio_{read,write} methods will validate
 * the page cache for this file before invoking the generic aio
 * routines.  Since we just invalidated the backing file's page
 * cache, we don't need to revalidate it here.  And, we know this
 * is not an O_APPEND or O_SYNC write, so we also don't need any
 * of the extra processing done in nfs_file_write.  Thus we invoke
 * the generic aio routines directly.
 *
 * If we ever switch to using O_DIRECT, we will need to change this
 * to call the aio_{read,write} methods instead.  The NFS client
 * hooks O_DIRECT I/O in those methods because the generic aio
 * routines serialize direct I/O unnecessarily.
 */
static ssize_t dm_nfs_kthread_iov_start(int rw, struct kiocb *kiocb,
					struct iovec *iov)
{
	if (rw == READ)
		return generic_file_aio_read(kiocb, iov, 1, kiocb->ki_pos);
	else
		return generic_file_aio_write(kiocb, iov, 1, kiocb->ki_pos);
}

/*
 * Convert a biovec to an iovec, and start I/O on it.
 * Wait here until it is complete.
 */
static int dm_nfs_kthread_biovec_start(int rw, struct file *filp,
					loff_t pos, struct bio_vec *bv)
{
	mm_segment_t old_fs = get_fs();
	struct iovec iov = {
		.iov_base = kmap(bv->bv_page) + bv->bv_offset,
		.iov_len = bv->bv_len,
	};
	struct kiocb kiocb;
	ssize_t r;

	set_fs(get_ds());

	init_sync_kiocb(&kiocb, filp);
	kiocb.ki_pos = pos;
	kiocb.ki_left = bv->bv_len;

	for (;;) {
		r = dm_nfs_kthread_iov_start(rw, &kiocb, &iov);
		if (r != -EIOCBRETRY)
			break;
		dm_nfs_io_retry_wait(&kiocb);
	}

	if (-EIOCBQUEUED == r)
		r = wait_on_sync_kiocb(&kiocb);

	set_fs(old_fs);
	kunmap(bv->bv_page);

	if (r < 0)
		return r;
	if ((unsigned int)r != bv->bv_len)
		return -EIO;
	return 0;
}

static void dm_nfs_kthread_bio_readahead(struct nfs_c *nc, struct bio *bio)
{
	struct bio_vec *bv, *bv_end = bio->bi_io_vec + bio->bi_vcnt;
	loff_t pos;
	size_t len;

	if (bio_data_dir(bio) != READ)
		return;

	len = 0;
	for (bv = bio->bi_io_vec; bv < bv_end; bv++)
		len += bv->bv_len;

	pos = (bio->bi_sector << 9) + nc->offset;
	dm_nfs_io_populate_cache(nc->filp, pos, len);
}

/*
 * Split a bio into its biovecs, and start I/O on each.
 * Any error will stop the loop immediately and cause the
 * whole request to fail.
 */
static int dm_nfs_kthread_bio_start(struct nfs_c *nc, struct bio *bio)
{
	struct file *filp = nc->filp;
	loff_t pos = (bio->bi_sector << 9) + nc->offset;
	struct bio_vec *bv, *bv_end = bio->bi_io_vec + bio->bi_vcnt;
	int r = 0;

	for (bv = bio->bi_io_vec; bv < bv_end; bv++) {
		r = dm_nfs_kthread_biovec_start(bio_data_dir(bio),
							filp, pos, bv);
		if (r)
			break;
		pos += bv->bv_len;
	}

	return r;
}

/*
 * When awoken, this thread moves bios queued on nc->input to a
 * private list, submits the requests, and invokes the completion
 * callbacks.
 */
static void dm_nfs_kthread_worker(struct work_struct *ws)
{
	struct nfs_c *nc = container_of(ws, struct nfs_c, ws);
	struct bio_list writes;
	struct bio *bio;
	int r;

	spin_lock_irq(&nc->lock);
	bio_list_merge(&nc->work, &nc->input);
	bio_list_init(&nc->input);
	spin_unlock_irq(&nc->lock);

	/*
	 * Use the proper UID when submitting these requests
	 */

	/*
	 * Invalidate all cached pages for our backing file
	 * before submitting these requests.  This eliminates
	 * any locally cached data so each set of requests
	 * behaves as if it is direct I/O.
	 */
	dm_nfs_io_invalidate_pages(nc->filp);

	/*
	 * Try to kick off all the reads now before we
	 * fill individual biovecs.
	 */
	bio_list_for_each(bio, &nc->work)
		dm_nfs_kthread_bio_readahead(nc, bio);

	/*
	 * Submit bios.
	 *
	 * Reads and unsuccessful writes complete immediately
	 * upon return.
	 *
	 * Successful writes are held until we know the final
	 * flush also worked.
	 */
	bio_list_init(&writes);
	while ((bio = bio_list_pop(&nc->work))) {
		r = dm_nfs_kthread_bio_start(nc, bio);
		if (bio_data_dir(bio) == READ || r < 0)
			bio_endio(bio, r);
		else
			bio_list_add(&writes, bio);
	}

	/*
	 * After submitting all the writes in this set of requests,
	 * flush them all now. The NFS client aggressively caches
	 * writes to open files, so we must explicitly flush them
	 * out _before_ signalling completion.
	 */
	r = dm_nfs_io_fsync(nc->filp);
	while ((bio = bio_list_pop(&writes)))
		bio_endio(bio, r);
}


/*--------------------------------------------------------------------
 * Externally visible dm-nfs target methods
 *--------------------------------------------------------------------*/

/**
 * dm_nfs_ctr - Parse arguments and construct a dm-nfs target device
 * @ti: target context to construct
 * @argc: count of incoming arguments
 * @argv: vector of incoming argument strings
 *
 * Arguments are "<path> <offset> [<uid>]" where:
 *
 * <path> is	The pathname of an NFS backing file to associate
 *		with this dm target
 *
 * <offset> is	The byte offset in the backing file where the
 *		device data begins (usually 0)
 *
 * <uid> is	The numeric user ID to use for all I/O against
 * 		the backing file (defaults to root); specify
 * 		a non-zero value to avoid root squashing on the
 * 		server
 */
static int dm_nfs_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct nfs_c *nc = NULL;
	uid_t uid = 0;
	int r = -EINVAL;

	ti->error = "invalid argument count";
	if (argc < 2 || argc > 3)
		goto err;

	r = -ENOMEM;
	ti->error = "cannot allocate dm-nfs context";
	nc = kzalloc(sizeof(*nc), GFP_KERNEL);
	if (!nc)
		goto err;

	ti->error = "cannot allocate dm-nfs path";
	nc->path = kstrdup(argv[0], GFP_KERNEL);
	if (!nc->path)
		goto err;

	ti->private = nc;

	r = -EINVAL;
	ti->error = "invalid file offset";
	if (sscanf(argv[1], "%lld", &nc->offset) != 1)
		goto err;
	if (nc->offset)
		DMDEBUG("setting file offset to %lld", nc->offset);

	if (argc == 3) {
		r = -EACCES;
		ti->error = "invalid uid";
		if (sscanf(argv[2], "%u", &uid) != 1)
			goto err;
		if (nc->offset)
			DMDEBUG("setting uid to %u", uid);
	}

	/* dm_nfs_io_get_file sets ti->error */
	r = dm_nfs_io_get_file(ti, uid);
	if (r)
		goto err;

	r = -ENOMEM;
	ti->error = "could not create dm-nfs mapping";
	spin_lock_init(&nc->lock);
	bio_list_init(&nc->input);
	bio_list_init(&nc->work);
	INIT_WORK(&nc->ws, dm_nfs_kthread_worker);

	nc->wq = create_singlethread_workqueue(DM_NFS_DAEMON);
	if (!nc->wq)
		goto err_putf;

	/* Let the NFS client choose how to split requests */
	ti->split_io = 0;

	DMDEBUG("constructed dm-nfs target on %s "
		"(%lldk, %llu sectors)", nc->path,
		(nc->size >> 10), (unsigned long long)nc->mapped_sectors);
	ti->error = NULL;

	return 0;

err_putf:
	dm_nfs_io_put_file(nc->filp);
err:
	kfree(nc);
	return r;
}

/**
 * dm_nfs_dtr - dm-nfs target destructor
 * @ti: dm target to destroy
 *
 */
static void dm_nfs_dtr(struct dm_target *ti)
{
	struct nfs_c *nc = ti->private;

	if ((dm_table_get_mode(ti->table) & FMODE_WRITE))
		flush_workqueue(nc->wq);

	if (nc->wq)
		destroy_workqueue(nc->wq);

	dm_nfs_io_put_file(nc->filp);
	DMINFO("released file %s", nc->path);

	kfree(nc);
}

/**
 * dm_nfs_map - start I/O on a dm-nfs target
 * @ti: target of I/O request
 * @bio: control block describing parameters of I/O request
 * @context: ignored
 *
 */
static int dm_nfs_map(struct dm_target *ti, struct bio *bio,
			union map_info *context)
{
	struct nfs_c *nc = ti->private;
	int need_wakeup;

	bio->bi_sector -= ti->begin;

	spin_lock_irq(&nc->lock);
	need_wakeup = bio_list_empty(&nc->input);
	bio_list_add(&nc->input, bio);
	spin_unlock_irq(&nc->lock);

	if (need_wakeup)
		queue_work(nc->wq, &nc->ws);

	return 0;
}

/**
 * dm_nfs_flush - wait for outstanding I/O on a dm-nfs target to drain
 * @ti: target to flush
 *
 */
static void dm_nfs_flush(struct dm_target *ti)
{
	struct nfs_c *nc = ti->private;

	flush_workqueue(nc->wq);
}

/**
 * dm_nfs_status - report status information about a dm-nfs target
 * @ti: target to report on
 * @type: type of info requested
 * @result: buffer for results
 * @maxlen: length of buffer
 *
 * Note: DMEMIT uses "result", "maxlen", and "sz", but they are not
 *       passed as arguments.
 */
static int dm_nfs_status(struct dm_target *ti, status_type_t type,
				char *result, unsigned int maxlen)
{
	struct nfs_c *nc = ti->private;
	unsigned int qlen, sz = 0;

	switch (type) {
	case STATUSTYPE_INFO:
		spin_lock_irq(&nc->lock);
		qlen = bio_list_size(&nc->work);
		qlen += bio_list_size(&nc->input);
		spin_unlock_irq(&nc->lock);

		DMEMIT("nfs %u", qlen);
		break;

	case STATUSTYPE_TABLE:
		DMEMIT("%s %llu", nc->path, nc->offset);
		break;
	}

	return 0;
}

static struct target_type nfs_target = {
	.name = "nfs",
	.version = {1, 0, 0},
	.module = THIS_MODULE,
	.ctr = dm_nfs_ctr,
	.dtr = dm_nfs_dtr,
	.map = dm_nfs_map,
	.presuspend = dm_nfs_flush,
	.flush = dm_nfs_flush,
	.status = dm_nfs_status,
};


/*--------------------------------------------------------------------
 * dm-nfs module bits
 *--------------------------------------------------------------------*/

static int __init dm_nfs_mod_init(void)
{
	int r;

	r = dm_register_target(&nfs_target);
	if (r < 0) {
		DMERR("register failed %d", r);
		return r;
	}

	DMINFO("version %u.%u.%u loaded",
	       nfs_target.version[0], nfs_target.version[1],
	       nfs_target.version[2]);

	return 0;
}

static void __exit dm_nfs_mod_exit(void)
{
        dm_unregister_target(&nfs_target); /* now returns void */
	DMINFO("version %u.%u.%u unloaded",
	       nfs_target.version[0], nfs_target.version[1],
	       nfs_target.version[2]);
}

module_init(dm_nfs_mod_init);
module_exit(dm_nfs_mod_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Chuck Lever <chuck.lever@oracle.com>");
MODULE_DESCRIPTION("device-mapper NFS target");
