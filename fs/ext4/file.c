// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/ext4/file.c
 *
 * Copyright (C) 1992, 1993, 1994, 1995
 * Remy Card (card@masi.ibp.fr)
 * Laboratoire MASI - Institut Blaise Pascal
 * Universite Pierre et Marie Curie (Paris VI)
 *
 *  from
 *
 *  linux/fs/minix/file.c
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *
 *  ext4 fs regular file handling primitives
 *
 *  64-bit file support on 64-bit platforms by Jakub Jelinek
 *	(jj@sunsite.ms.mff.cuni.cz)
 */

#include <linux/time.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/path.h>
#include <linux/dax.h>
#include <linux/quotaops.h>
#include <linux/pagevec.h>
#include <linux/uio.h>
#include <linux/mman.h>
#include <linux/backing-dev.h>
#include "ext4.h"
#include "ext4_jbd2.h"
#include "xattr.h"
#include "acl.h"

#ifdef CONFIG_FS_DAX
static ssize_t ext4_dax_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!inode_trylock_shared(inode))
			return -EAGAIN;
	} else {
		inode_lock_shared(inode);
	}
	/*
	 * Recheck under inode lock - at this point we are sure it cannot
	 * change anymore
	 */
	if (!IS_DAX(inode)) {
		inode_unlock_shared(inode);
		/* Fallback to buffered IO in case we cannot support DAX */
		return generic_file_read_iter(iocb, to);
	}
	ret = dax_iomap_rw(iocb, to, &ext4_iomap_ops);
	inode_unlock_shared(inode);

	file_accessed(iocb->ki_filp);
	return ret;
}
#endif

static ssize_t ext4_file_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	if (unlikely(ext4_forced_shutdown(EXT4_SB(file_inode(iocb->ki_filp)->i_sb))))
		return -EIO;

	if (!iov_iter_count(to))
		return 0; /* skip atime */

#ifdef CONFIG_FS_DAX
	if (IS_DAX(file_inode(iocb->ki_filp)))
		return ext4_dax_read_iter(iocb, to);
#endif
	return generic_file_read_iter(iocb, to);
}

/*
 * Called when an inode is released. Note that this is different
 * from ext4_file_open: open gets called at every open, but release
 * gets called only when /all/ the files are closed.
 */
static int ext4_release_file(struct inode *inode, struct file *filp)
{
	if (ext4_test_inode_state(inode, EXT4_STATE_DA_ALLOC_CLOSE)) {
		ext4_alloc_da_blocks(inode);
		ext4_clear_inode_state(inode, EXT4_STATE_DA_ALLOC_CLOSE);
	}
	/* if we are the last writer on the inode, drop the block reservation */
	if ((filp->f_mode & FMODE_WRITE) &&
			(atomic_read(&inode->i_writecount) == 1) &&
		        !EXT4_I(inode)->i_reserved_data_blocks)
	{
		down_write(&EXT4_I(inode)->i_data_sem);
		ext4_discard_preallocations(inode);
		up_write(&EXT4_I(inode)->i_data_sem);
	}
	if (is_dx(inode) && filp->private_data)
		ext4_htree_free_dir_info(filp->private_data);

	return 0;
}

static void ext4_unwritten_wait(struct inode *inode)
{
	wait_queue_head_t *wq = ext4_ioend_wq(inode);

	wait_event(*wq, (atomic_read(&EXT4_I(inode)->i_unwritten) == 0));
}

static bool
ext4_unaligned_io(struct inode *inode, struct iov_iter *from, loff_t pos)
{
	struct super_block *sb = inode->i_sb;
	unsigned long blockmask = sb->s_blocksize - 1;

	if ((pos | iov_iter_alignment(from)) & blockmask)
		return true;

	return false;
}

static bool
ext4_extending_io(struct inode *inode, loff_t offset, size_t len)
{
	if (offset + len > i_size_read(inode) ||
			offset + len > EXT4_I(inode)->i_disksize)
		return true;
	return false;
}

/* Is IO overwriting allocated and initialized blocks? */
static bool ext4_overwrite_io(struct inode *inode, loff_t pos, loff_t len)
{
	struct ext4_map_blocks map;
	unsigned int blkbits = inode->i_blkbits;
	int err, blklen;

	if (pos + len > i_size_read(inode))
		return false;

	map.m_lblk = pos >> blkbits;
	map.m_len = EXT4_MAX_BLOCKS(len, pos, blkbits);
	blklen = map.m_len;

	err = ext4_map_blocks(NULL, inode, &map, 0);
	/*
	 * 'err==len' means that all of the blocks have been preallocated,
	 * regardless of whether they have been initialized or not. To exclude
	 * unwritten extents, we need to check m_flags.
	 */
	return err == blklen && (map.m_flags & EXT4_MAP_MAPPED);
}

static ssize_t ext4_write_checks(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		return ret;

	if (unlikely(IS_IMMUTABLE(inode)))
		return -EPERM;

	/*
	 * If we have encountered a bitmap-format file, the size limit
	 * is smaller than s_maxbytes, which is for extent-mapped files.
	 */
	if (!(ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS))) {
		struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);

		if (iocb->ki_pos >= sbi->s_bitmap_maxbytes)
			return -EFBIG;
		iov_iter_truncate(from, sbi->s_bitmap_maxbytes - iocb->ki_pos);
	}
	return iov_iter_count(from);
}

#ifdef CONFIG_FS_DAX
static ssize_t
ext4_dax_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);
	ssize_t ret;

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!inode_trylock(inode))
			return -EAGAIN;
	} else {
		inode_lock(inode);
	}
	ret = ext4_write_checks(iocb, from);
	if (ret <= 0)
		goto out;
	ret = file_remove_privs(iocb->ki_filp);
	if (ret)
		goto out;
	ret = file_update_time(iocb->ki_filp);
	if (ret)
		goto out;

	ret = dax_iomap_rw(iocb, from, &ext4_iomap_ops);
out:
	inode_unlock(inode);
	if (ret > 0)
		ret = generic_write_sync(iocb, ret);
	return ret;
}
#endif

static ssize_t ext4_buffered_write_iter(struct kiocb *iocb,
						struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	ssize_t ret;

	if (iocb->ki_flags & IOCB_NOWAIT)
		return -EOPNOTSUPP;

	if (!inode_trylock(inode)) {
		if (iocb->ki_flags & IOCB_NOWAIT)
			return -EAGAIN;
		inode_lock(inode);
	}

	ret = ext4_write_checks(iocb, from);
	if (ret <= 0)
		goto out;

	ret = file_remove_privs(file);
	if (ret)
		goto out;

	ret = file_update_time(file);
	if (ret)
		goto out;

	/* We can write back this queue in page reclaim */
	current->backing_dev_info = inode_to_bdi(inode);
	ret = generic_perform_write(file, from, iocb->ki_pos);
	if (likely(ret > 0))
		iocb->ki_pos += ret;
	current->backing_dev_info = NULL;

out:
	inode_unlock(inode);

	if (ret > 0)
		ret = generic_write_sync(iocb, ret);

	return ret;
}

/*
 * The intention here is to start with shared lock acquired then see if any
 * condition requires an exclusive inode lock. If yes, then we restart the
 * whole operation by releasing the shared lock and acquiring exclusive lock.
 *
 * - For unaligned_io we never take shared lock as it may cause data corruption
 *   when two unaligned IO tries to modify the same block e.g. while zeroing.
 *
 * - For extending writes case we don't take the shared lock, since it requires
 *   updating inode i_disksize and/or orphan handling with exclusive lock.
 */
static ssize_t ext4_dio_write_checks(struct kiocb *iocb, struct iov_iter *from,
				     bool *ilock_shared, bool *extend)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	loff_t offset;
	size_t count;
	ssize_t ret;
	bool overwrite;

restart:
	ret = ext4_write_checks(iocb, from);
	if (ret <= 0)
		goto out;

	offset = iocb->ki_pos;
	count = ret;
	if (ext4_extending_io(inode, offset, count))
		*extend = true;

	overwrite = ext4_overwrite_io(inode, offset, count);
	if ((iocb->ki_flags & IOCB_NOWAIT) && (extend || !overwrite)) {
		ret = -EAGAIN;
		goto out;
	}
	/*
	 * Determine whether the IO operation will overwrite allocated
	 * and initialized blocks.
	 *
	 * We need exclusive i_rwsem for changing security info
	 * in file_modified().
	 */
	if (*ilock_shared && (!IS_NOSEC(inode) || *extend || !overwrite)) {
		inode_unlock_shared(inode);
		*ilock_shared = false;
		inode_lock(inode);
		goto restart;
	}

	return count;
out:
	if (*ilock_shared)
		inode_unlock_shared(inode);
	else
		inode_unlock(inode);
	return ret;
}

static ssize_t ext4_dio_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	ssize_t ret;
	struct address_space *mapping = file->f_mapping;
	ssize_t	status;
	loff_t pos, endbyte;
	ssize_t	err;
	loff_t offset = iocb->ki_pos;
	size_t count = iov_iter_count(from);
	bool extend = false, unaligned_io = false;
	bool ilock_shared = true;
	int dio_unlocking = 0;

	/*
	 * We initially start with shared inode lock unless it is
	 * unaligned IO which needs exclusive lock anyways.
	 */
	if (ext4_unaligned_io(inode, from, offset)) {
		unaligned_io = true;
		ilock_shared = false;
	}
	/*
	 * Quick check here without any i_rwsem lock to see if it is extending
	 * IO. A more reliable check is done in ext4_dio_write_checks() with
	 * proper locking in place.
	 */
	if (offset + count > i_size_read(inode))
		ilock_shared = false;

	if (ilock_shared) {
		if (!inode_trylock_shared(inode)) {
			if (iocb->ki_flags & IOCB_NOWAIT)
				return -EAGAIN;
			inode_lock_shared(inode);
		}
	} else {
		if (!inode_trylock(inode)) {
			if (iocb->ki_flags & IOCB_NOWAIT)
				return -EAGAIN;
			inode_lock(inode);
		}
	}

	ret = ext4_dio_write_checks(iocb, from, &ilock_shared, &extend);
	if (ret <= 0)
		return ret;
	/*
	 * Unaligned direct IO must be serialized among each other as zeroing
	 * of partial blocks of two competing unaligned IOs can result in data
	 * corruption.
	 *
	 * So we make sure we don't allow any unaligned IO in flight.
	 * For IOs where we need not wait (like unaligned non-AIO DIO),
	 * below ext4_unwritten_wait() may anyway become a no-op, since we start
	 * with exclusive lock.
	 */
	if (unaligned_io)
		ext4_unwritten_wait(inode);

	ret = file_remove_privs(file);
	if (ret)
		goto err_out;

	ret = file_update_time(file);
	if (ret)
		goto err_out;

	/* dio_unlock is always zero which will skip all unlocking in dio overwrite case. */
	iocb->private = &dio_unlocking;
	ret = generic_file_direct_write(iocb, from);
	/*
	 * If the write stopped short of completing, fall back to
	 * buffered writes.  Some filesystems do this for writes to
	 * holes, for example.  For DAX files, a buffered write will
	 * not succeed (even if it did, DAX does not handle dirty
	 * page-cache pages correctly).
	 */
	if (ret < 0 || !iov_iter_count(from) || IS_DAX(inode))
		goto out;

	if (ilock_shared)
		inode_unlock_shared(inode);
	else
		inode_unlock(inode);

	/*direct io partial done, fallen into buffer io. */
	pos = iocb->ki_pos;
	status = ext4_buffered_write_iter(iocb, from);
	if (status < 0)
		return ret ? ret : status;

	/*
	 * We need to ensure that the page cache pages are written to
	 * disk and invalidated to preserve the expected O_DIRECT
	 * semantics.
	 */
	endbyte = pos + status - 1;
	err = filemap_write_and_wait_range(mapping, pos, endbyte);
	if (err == 0) {
		iocb->ki_pos = endbyte + 1;
		ret += status;
		invalidate_mapping_pages(mapping,
				pos >> PAGE_SHIFT,
				endbyte >> PAGE_SHIFT);
	} else {
		/*
		 * We don't know how much we wrote, so just return
		 * the number of bytes which were direct-written
		 */
	}
	return ret;

out:
	/*
	 * Unaligned direct AIO must be the only IO in flight. Otherwise
	 * overlapping aligned IO after unaligned might result in data
	 * corruption.
	 */
	if (ret == -EIOCBQUEUED && unaligned_io)
		ext4_unwritten_wait(inode);
	if (ilock_shared)
		inode_unlock_shared(inode);
	else
		inode_unlock(inode);

	if (ret > 0)
		ret = generic_write_sync(iocb, ret);

	return ret;

err_out:
	if (ilock_shared)
		inode_unlock_shared(inode);
	else
		inode_unlock(inode);
	return ret;
}

static ssize_t
ext4_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct inode *inode = file_inode(iocb->ki_filp);

	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

#ifdef CONFIG_FS_DAX
	if (IS_DAX(inode))
		return ext4_dax_write_iter(iocb, from);
#endif

	if (iocb->ki_flags & IOCB_DIRECT)
		return ext4_dio_write_iter(iocb, from);

	return ext4_buffered_write_iter(iocb, from);
}

#ifdef CONFIG_FS_DAX
static int ext4_dax_huge_fault(struct vm_fault *vmf,
		enum page_entry_size pe_size)
{
	int result;
	handle_t *handle = NULL;
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct super_block *sb = inode->i_sb;

	/*
	 * We have to distinguish real writes from writes which will result in a
	 * COW page; COW writes should *not* poke the journal (the file will not
	 * be changed). Doing so would cause unintended failures when mounted
	 * read-only.
	 *
	 * We check for VM_SHARED rather than vmf->cow_page since the latter is
	 * unset for pe_size != PE_SIZE_PTE (i.e. only in do_cow_fault); for
	 * other sizes, dax_iomap_fault will handle splitting / fallback so that
	 * we eventually come back with a COW page.
	 */
	bool write = (vmf->flags & FAULT_FLAG_WRITE) &&
		(vmf->vma->vm_flags & VM_SHARED);
	pfn_t pfn;

	if (write) {
		sb_start_pagefault(sb);
		file_update_time(vmf->vma->vm_file);
		down_read(&EXT4_I(inode)->i_mmap_sem);
		handle = ext4_journal_start_sb(sb, EXT4_HT_WRITE_PAGE,
					       EXT4_DATA_TRANS_BLOCKS(sb));
		if (IS_ERR(handle)) {
			up_read(&EXT4_I(inode)->i_mmap_sem);
			sb_end_pagefault(sb);
			return VM_FAULT_SIGBUS;
		}
	} else {
		down_read(&EXT4_I(inode)->i_mmap_sem);
	}
	result = dax_iomap_fault(vmf, pe_size, &pfn, NULL, &ext4_iomap_ops);
	if (write) {
		ext4_journal_stop(handle);
		/* Handling synchronous page fault? */
		if (result & VM_FAULT_NEEDDSYNC)
			result = dax_finish_sync_fault(vmf, pe_size, pfn);
		up_read(&EXT4_I(inode)->i_mmap_sem);
		sb_end_pagefault(sb);
	} else {
		up_read(&EXT4_I(inode)->i_mmap_sem);
	}

	return result;
}

static int ext4_dax_fault(struct vm_fault *vmf)
{
	return ext4_dax_huge_fault(vmf, PE_SIZE_PTE);
}

static const struct vm_operations_struct ext4_dax_vm_ops = {
	.fault		= ext4_dax_fault,
	.huge_fault	= ext4_dax_huge_fault,
	.page_mkwrite	= ext4_dax_fault,
	.pfn_mkwrite	= ext4_dax_fault,
};
#else
#define ext4_dax_vm_ops	ext4_file_vm_ops
#endif

static const struct vm_operations_struct ext4_file_vm_ops = {
	.fault		= ext4_filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite   = ext4_page_mkwrite,
};

static int ext4_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file->f_mapping->host;

	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

	/*
	 * We don't support synchronous mappings for non-DAX files. At least
	 * until someone comes with a sensible use case.
	 */
	if (!IS_DAX(file_inode(file)) && (vma->vm_flags & VM_SYNC))
		return -EOPNOTSUPP;

	file_accessed(file);
	if (IS_DAX(file_inode(file))) {
		vma->vm_ops = &ext4_dax_vm_ops;
		vma->vm_flags |= VM_MIXEDMAP | VM_HUGEPAGE;
	} else {
		vma->vm_ops = &ext4_file_vm_ops;
	}
	return 0;
}

static int ext4_file_open(struct inode * inode, struct file * filp)
{
	struct super_block *sb = inode->i_sb;
	struct ext4_sb_info *sbi = EXT4_SB(inode->i_sb);
	struct vfsmount *mnt = filp->f_path.mnt;
	struct dentry *dir;
	struct path path;
	char buf[64], *cp;
	int ret;

	if (unlikely(ext4_forced_shutdown(EXT4_SB(inode->i_sb))))
		return -EIO;

	if (unlikely(!(sbi->s_mount_flags & EXT4_MF_MNTDIR_SAMPLED) &&
		     !sb_rdonly(sb))) {
		sbi->s_mount_flags |= EXT4_MF_MNTDIR_SAMPLED;
		/*
		 * Sample where the filesystem has been mounted and
		 * store it in the superblock for sysadmin convenience
		 * when trying to sort through large numbers of block
		 * devices or filesystem images.
		 */
		memset(buf, 0, sizeof(buf));
		path.mnt = mnt;
		path.dentry = mnt->mnt_root;
		cp = d_path(&path, buf, sizeof(buf));
		if (!IS_ERR(cp)) {
			handle_t *handle;
			int err;

			handle = ext4_journal_start_sb(sb, EXT4_HT_MISC, 1);
			if (IS_ERR(handle))
				return PTR_ERR(handle);
			BUFFER_TRACE(sbi->s_sbh, "get_write_access");
			err = ext4_journal_get_write_access(handle, sbi->s_sbh);
			if (err) {
				ext4_journal_stop(handle);
				return err;
			}
			strlcpy(sbi->s_es->s_last_mounted, cp,
				sizeof(sbi->s_es->s_last_mounted));
			ext4_handle_dirty_super(handle, sb);
			ext4_journal_stop(handle);
		}
	}
	if (ext4_encrypted_inode(inode)) {
		ret = fscrypt_get_encryption_info(inode);
		if (ret)
			return -EACCES;
		if (!fscrypt_has_encryption_key(inode))
			return -ENOKEY;
	}

	dir = dget_parent(file_dentry(filp));
	if (ext4_encrypted_inode(d_inode(dir)) &&
			!fscrypt_has_permitted_context(d_inode(dir), inode)) {
		ext4_warning(inode->i_sb,
			     "Inconsistent encryption contexts: %lu/%lu",
			     (unsigned long) d_inode(dir)->i_ino,
			     (unsigned long) inode->i_ino);
		dput(dir);
		return -EPERM;
	}
	dput(dir);
	/*
	 * Set up the jbd2_inode if we are opening the inode for
	 * writing and the journal is present
	 */
	if (filp->f_mode & FMODE_WRITE) {
		ret = ext4_inode_attach_jinode(inode);
		if (ret < 0)
			return ret;
	}

	filp->f_mode |= FMODE_NOWAIT;
	return dquot_file_open(inode, filp);
}

/*
 * Here we use ext4_map_blocks() to get a block mapping for a extent-based
 * file rather than ext4_ext_walk_space() because we can introduce
 * SEEK_DATA/SEEK_HOLE for block-mapped and extent-mapped file at the same
 * function.  When extent status tree has been fully implemented, it will
 * track all extent status for a file and we can directly use it to
 * retrieve the offset for SEEK_DATA/SEEK_HOLE.
 */

/*
 * When we retrieve the offset for SEEK_DATA/SEEK_HOLE, we would need to
 * lookup page cache to check whether or not there has some data between
 * [startoff, endoff] because, if this range contains an unwritten extent,
 * we determine this extent as a data or a hole according to whether the
 * page cache has data or not.
 */
static int ext4_find_unwritten_pgoff(struct inode *inode,
				     int whence,
				     ext4_lblk_t end_blk,
				     loff_t *offset)
{
	struct pagevec pvec;
	unsigned int blkbits;
	pgoff_t index;
	pgoff_t end;
	loff_t endoff;
	loff_t startoff;
	loff_t lastoff;
	int found = 0;

	blkbits = inode->i_sb->s_blocksize_bits;
	startoff = *offset;
	lastoff = startoff;
	endoff = (loff_t)end_blk << blkbits;

	index = startoff >> PAGE_SHIFT;
	end = (endoff - 1) >> PAGE_SHIFT;

	pagevec_init(&pvec);
	do {
		int i;
		unsigned long nr_pages;

		nr_pages = pagevec_lookup_range(&pvec, inode->i_mapping,
					&index, end);
		if (nr_pages == 0)
			break;

		for (i = 0; i < nr_pages; i++) {
			struct page *page = pvec.pages[i];
			struct buffer_head *bh, *head;

			/*
			 * If current offset is smaller than the page offset,
			 * there is a hole at this offset.
			 */
			if (whence == SEEK_HOLE && lastoff < endoff &&
			    lastoff < page_offset(pvec.pages[i])) {
				found = 1;
				*offset = lastoff;
				goto out;
			}

			lock_page(page);

			if (unlikely(page->mapping != inode->i_mapping)) {
				unlock_page(page);
				continue;
			}

			if (!page_has_buffers(page)) {
				unlock_page(page);
				continue;
			}

			if (page_has_buffers(page)) {
				lastoff = page_offset(page);
				bh = head = page_buffers(page);
				do {
					if (lastoff + bh->b_size <= startoff)
						goto next;
					if (buffer_uptodate(bh) ||
					    buffer_unwritten(bh)) {
						if (whence == SEEK_DATA)
							found = 1;
					} else {
						if (whence == SEEK_HOLE)
							found = 1;
					}
					if (found) {
						*offset = max_t(loff_t,
							startoff, lastoff);
						unlock_page(page);
						goto out;
					}
next:
					lastoff += bh->b_size;
					bh = bh->b_this_page;
				} while (bh != head);
			}

			lastoff = page_offset(page) + PAGE_SIZE;
			unlock_page(page);
		}

		pagevec_release(&pvec);
	} while (index <= end);

	/* There are no pages upto endoff - that would be a hole in there. */
	if (whence == SEEK_HOLE && lastoff < endoff) {
		found = 1;
		*offset = lastoff;
	}
out:
	pagevec_release(&pvec);
	return found;
}

/*
 * ext4_seek_data() retrieves the offset for SEEK_DATA.
 */
static loff_t ext4_seek_data(struct file *file, loff_t offset, loff_t maxsize)
{
	struct inode *inode = file->f_mapping->host;
	struct extent_status es;
	ext4_lblk_t start, last, end;
	loff_t dataoff, isize;
	int blkbits;
	int ret;

	inode_lock(inode);

	isize = i_size_read(inode);
	if (offset < 0 || offset >= isize) {
		inode_unlock(inode);
		return -ENXIO;
	}

	blkbits = inode->i_sb->s_blocksize_bits;
	start = offset >> blkbits;
	last = start;
	end = isize >> blkbits;
	dataoff = offset;

	do {
		ret = ext4_get_next_extent(inode, last, end - last + 1, &es);
		if (ret <= 0) {
			/* No extent found -> no data */
			if (ret == 0)
				ret = -ENXIO;
			inode_unlock(inode);
			return ret;
		}

		last = es.es_lblk;
		if (last != start)
			dataoff = (loff_t)last << blkbits;
		if (!ext4_es_is_unwritten(&es))
			break;

		/*
		 * If there is a unwritten extent at this offset,
		 * it will be as a data or a hole according to page
		 * cache that has data or not.
		 */
		if (ext4_find_unwritten_pgoff(inode, SEEK_DATA,
					      es.es_lblk + es.es_len, &dataoff))
			break;
		last += es.es_len;
		dataoff = (loff_t)last << blkbits;
		cond_resched();
	} while (last <= end);

	inode_unlock(inode);

	if (dataoff > isize)
		return -ENXIO;

	return vfs_setpos(file, dataoff, maxsize);
}

/*
 * ext4_seek_hole() retrieves the offset for SEEK_HOLE.
 */
static loff_t ext4_seek_hole(struct file *file, loff_t offset, loff_t maxsize)
{
	struct inode *inode = file->f_mapping->host;
	struct extent_status es;
	ext4_lblk_t start, last, end;
	loff_t holeoff, isize;
	int blkbits;
	int ret;

	inode_lock(inode);

	isize = i_size_read(inode);
	if (offset < 0 || offset >= isize) {
		inode_unlock(inode);
		return -ENXIO;
	}

	blkbits = inode->i_sb->s_blocksize_bits;
	start = offset >> blkbits;
	last = start;
	end = isize >> blkbits;
	holeoff = offset;

	do {
		ret = ext4_get_next_extent(inode, last, end - last + 1, &es);
		if (ret < 0) {
			inode_unlock(inode);
			return ret;
		}
		/* Found a hole? */
		if (ret == 0 || es.es_lblk > last) {
			if (last != start)
				holeoff = (loff_t)last << blkbits;
			break;
		}
		/*
		 * If there is a unwritten extent at this offset,
		 * it will be as a data or a hole according to page
		 * cache that has data or not.
		 */
		if (ext4_es_is_unwritten(&es) &&
		    ext4_find_unwritten_pgoff(inode, SEEK_HOLE,
					      last + es.es_len, &holeoff))
			break;

		last += es.es_len;
		holeoff = (loff_t)last << blkbits;
		cond_resched();
	} while (last <= end);

	inode_unlock(inode);

	if (holeoff > isize)
		holeoff = isize;

	return vfs_setpos(file, holeoff, maxsize);
}

/*
 * ext4_llseek() handles both block-mapped and extent-mapped maxbytes values
 * by calling generic_file_llseek_size() with the appropriate maxbytes
 * value for each.
 */
loff_t ext4_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	loff_t maxbytes;

	if (!(ext4_test_inode_flag(inode, EXT4_INODE_EXTENTS)))
		maxbytes = EXT4_SB(inode->i_sb)->s_bitmap_maxbytes;
	else
		maxbytes = inode->i_sb->s_maxbytes;

	switch (whence) {
	case SEEK_SET:
	case SEEK_CUR:
	case SEEK_END:
		return generic_file_llseek_size(file, offset, whence,
						maxbytes, i_size_read(inode));
	case SEEK_DATA:
		return ext4_seek_data(file, offset, maxbytes);
	case SEEK_HOLE:
		return ext4_seek_hole(file, offset, maxbytes);
	}

	return -EINVAL;
}

const struct file_operations ext4_file_operations = {
	.llseek		= ext4_llseek,
	.read_iter	= ext4_file_read_iter,
	.write_iter	= ext4_file_write_iter,
	.unlocked_ioctl = ext4_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= ext4_compat_ioctl,
#endif
	.mmap		= ext4_file_mmap,
	.mmap_supported_flags = MAP_SYNC,
	.open		= ext4_file_open,
	.release	= ext4_release_file,
	.fsync		= ext4_sync_file,
	.get_unmapped_area = thp_get_unmapped_area,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.fallocate	= ext4_fallocate,
};

const struct inode_operations ext4_file_inode_operations = {
	.setattr	= ext4_setattr,
	.getattr	= ext4_file_getattr,
	.listxattr	= ext4_listxattr,
	.get_acl	= ext4_get_acl,
	.set_acl	= ext4_set_acl,
	.fiemap		= ext4_fiemap,
};

