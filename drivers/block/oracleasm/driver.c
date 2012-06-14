/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * NAME
 *	oracleasm.c - ASM library kernel driver.
 *
 * AUTHOR
 * 	Joel Becker <joel.becker@oracle.com>
 *
 * DESCRIPTION
 *      This file contains the kernel driver of the Oracle Automatic
 *      Storage Managment userspace library.  It provides the routines
 *      required to support the userspace library.
 *
 * MODIFIED   (YYYY/MM/DD)
 *	2008/09/01 - Martin K. Petersen <martin.petersen@oracle.com>
 *		Data integrity changes.
 *      2004/01/02 - Joel Becker <joel.becker@oracle.com>
 *		Initial GPL header.
 *      2004/09/10 - Joel Becker <joel.becker@oracle.com>
 *		First port to 2.6.
 *      2004/12/16 - Joel Becker <joel.becker@oracle.com>
 *		Change from ioctl to transaction files.
 *
 * Copyright (c) 2002-2004 Oracle Corporation.  All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License, version 2 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have recieved a copy of the GNU General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

/*
 * This driver's filesystem code is based on the ramfs filesystem.
 * Copyright information for the original source appears below.
 */

/* Simple VFS hooks based on: */
/*
 * Resizable simple ram filesystem for Linux.
 *
 * Copyright (C) 2000 Linus Torvalds.
 *		 2000 Transmeta Corp.
 *
 * Usage limits added by David Gibson, Linuxcare Australia.
 * This file is released under the GPL.
 */


#include <linux/fs.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/mount.h>
#include <linux/parser.h>
#include <linux/backing-dev.h>
#include <linux/compat.h>

#include <asm/uaccess.h>
#include <linux/spinlock.h>

#include "linux/oracleasm/compat32.h"
#include "linux/oracleasm/kernel.h"
#include "linux/oracleasm/abi.h"
#include "linux/oracleasm/disk.h"
#include "linux/oracleasm/manager.h"
#include "linux/oracleasm/error.h"

#include "linux/oracleasm/module_version.h"

#include "compat.h"
#include "masklog.h"
#include "proc.h"
#include "transaction_file.h"
#include "request.h"
#include "integrity.h"

#if PAGE_CACHE_SIZE % 1024
#error Oh no, PAGE_CACHE_SIZE is not divisible by 1k! I cannot cope.
#endif  /* PAGE_CACHE_SIZE % 1024 */



/*
 * Compat32
 */
#define ASM_BPL_32		32
#if BITS_PER_LONG == 32
# define asm_submit_io_32	asm_submit_io_native
# define asm_maybe_wait_io_32	asm_maybe_wait_io_native
# define asm_complete_ios_32	asm_complete_ios_native
#else
# if BITS_PER_LONG == 64
#  define ASM_BPL_64		64
#  define asm_submit_io_32	asm_submit_io_thunk
#  define asm_submit_io_64	asm_submit_io_native
#  define asm_maybe_wait_io_32	asm_maybe_wait_io_thunk
#  define asm_maybe_wait_io_64	asm_maybe_wait_io_native
#  define asm_complete_ios_32	asm_complete_ios_thunk
#  define asm_complete_ios_64	asm_complete_ios_native
# endif  /* BITS_PER_LONG == 64 */
#endif  /* BITS_PER_LONG == 32 */


static struct super_operations asmfs_ops;
static struct file_operations asmfs_dir_operations;
static struct file_operations asmfs_file_operations;
static struct inode_operations asmfs_file_inode_operations;
static struct inode_operations asmfs_disk_dir_inode_operations;
static struct inode_operations asmfs_iid_dir_inode_operations;

static struct kmem_cache	*asm_request_cachep;
static struct kmem_cache	*asmfs_inode_cachep;
static struct kmem_cache	*asmdisk_cachep;

/*
 * asmfs super-block data in memory
 */
struct asmfs_sb_info {
	struct super_block *asmfs_super;
	/* Prevent races accessing the used block
	 * counts. Conceptually, this could probably be a semaphore,
	 * but the only thing we do while holding the lock is
	 * arithmetic, so there's no point */
	spinlock_t asmfs_lock;

	/* It is important that at least the free counts below be
	   signed.  free_XXX may become negative if a limit is changed
	   downwards (by a remount) below the current usage. */

	/* max number of inodes - controls # of instances */
	long max_inodes;
	/* free_inodes = max_inodes - total number of inodes currently in use */
	long free_inodes;

	unsigned long next_iid;
};

#define ASMFS_SB(sb) ((struct asmfs_sb_info *)((sb)->s_fs_info))


struct asmfs_file_info {
	struct file *f_file;
	spinlock_t f_lock;		/* Lock on the structure */
	wait_queue_head_t f_wait;	/* Folks waiting on I/O */
	struct list_head f_ctx;		/* Hook into the i_threads list */
	struct list_head f_ios;		/* Outstanding I/Os for this thread */
	struct list_head f_complete;	/* Completed I/Os for this thread */
	struct list_head f_disks;	/* List of disks opened */
	struct bio *f_bio_free;		/* bios to free */
};

#define ASMFS_FILE(_f) ((struct asmfs_file_info *)((_f)->private_data))


/*
 * asmfs inode data in memory
 *
 * Note that 'thread' here can mean 'process' too :-)
 */
struct asmfs_inode_info {
	spinlock_t i_lock;		/* lock on the asmfs_inode_info structure */
	struct list_head i_disks;	/* List of disk handles */
	struct list_head i_threads;	/* list of context structures for each calling thread */
	struct inode vfs_inode;
};

static inline struct asmfs_inode_info *ASMFS_I(struct inode *inode)
{
	return container_of(inode, struct asmfs_inode_info, vfs_inode);
}

static inline struct inode *ASMFS_F2I(struct file *file)
{
	return file->f_dentry->d_inode;
}

/*
 * asm disk info
 */
struct asm_disk_info {
	struct asmfs_inode_info *d_inode;
	struct block_device *d_bdev;	/* Block device we I/O to */
	int d_max_sectors;		/* Maximum sectors per I/O */
	int d_live;			/* Is the disk alive? */
	atomic_t d_ios;			/* Count of in-flight I/Os */
	struct list_head d_open;	/* List of assocated asm_disk_heads */
	struct inode vfs_inode;
};

/* Argument to iget5_locked()/ilookup5() to map bdev to disk_inode */
struct asmdisk_find_inode_args {
	unsigned long fa_handle;
	struct asmfs_inode_info *fa_inode;
};

static inline struct asm_disk_info *ASMDISK_I(struct inode *inode)
{
	return container_of(inode, struct asm_disk_info, vfs_inode);
}


/*
 * asm disk info lists
 *
 * Each file_info struct has a list of disks it has opened.  As this
 * is an M->N mapping, an intermediary structure is needed
 */
struct asm_disk_head {
	struct asm_disk_info *h_disk;	/* Pointer to associated disk */
	struct asmfs_file_info *h_file;	/* Pointer to owning file */
	struct list_head h_flist;	/* Hook into file's list */
	struct list_head h_dlist;	/* Hook into disk's list */
};


/*
 * Transaction file contexts.
 */
static ssize_t asmfs_svc_query_version(struct file *file, char *buf, size_t size);
static ssize_t asmfs_svc_get_iid(struct file *file, char *buf, size_t size);
static ssize_t asmfs_svc_check_iid(struct file *file, char *buf, size_t size);
static ssize_t asmfs_svc_query_disk(struct file *file, char *buf, size_t size);
static ssize_t asmfs_svc_open_disk(struct file *file, char *buf, size_t size);
static ssize_t asmfs_svc_close_disk(struct file *file, char *buf, size_t size);
static ssize_t asmfs_svc_io32(struct file *file, char *buf, size_t size);
#if BITS_PER_LONG == 64
static ssize_t asmfs_svc_io64(struct file *file, char *buf, size_t size);
#endif

static struct transaction_context trans_contexts[] = {
	[ASMOP_QUERY_VERSION]		= {asmfs_svc_query_version},
	[ASMOP_GET_IID]			= {asmfs_svc_get_iid},
	[ASMOP_CHECK_IID]		= {asmfs_svc_check_iid},
	[ASMOP_QUERY_DISK]		= {asmfs_svc_query_disk},
	[ASMOP_OPEN_DISK]		= {asmfs_svc_open_disk},
	[ASMOP_CLOSE_DISK]		= {asmfs_svc_close_disk},
	[ASMOP_IO32]			= {asmfs_svc_io32},
#if BITS_PER_LONG == 64
	[ASMOP_IO64]			= {asmfs_svc_io64},
#endif
};

static struct backing_dev_info memory_backing_dev_info = {
	.ra_pages	= 0,	/* No readahead */
	.capabilities   = BDI_CAP_NO_ACCT_DIRTY | BDI_CAP_NO_WRITEBACK,
};


static struct inode *asmdisk_alloc_inode(struct super_block *sb)
{
	struct asm_disk_info *d = kmem_cache_alloc(asmdisk_cachep, GFP_KERNEL);
	if (!d)
		return NULL;

	mlog(ML_DISK, "Allocated disk 0x%p\n", d);
	return &d->vfs_inode;
}

static void asmdisk_destroy_inode(struct inode *inode)
{
	struct asm_disk_info *d = ASMDISK_I(inode);

	mlog_bug_on_msg(atomic_read(&d->d_ios),
			"Disk 0x%p has outstanding I/Os\n", d);

	mlog_bug_on_msg(!list_empty(&d->d_open),
			"Disk 0x%p has openers\n", d);

	mlog(ML_DISK, "Destroying disk 0x%p\n", d);

	kmem_cache_free(asmdisk_cachep, d);
}

static void init_asmdisk_once(void *foo)
{
	struct asm_disk_info *d = foo;

	memset(d, 0, sizeof(*d));
	INIT_LIST_HEAD(&d->d_open);

	inode_init_once(&d->vfs_inode);
}

static void asmdisk_evict_inode(struct inode *inode)
{
	struct asm_disk_info *d = ASMDISK_I(inode);

	mlog_entry("(0x%p)\n", inode);

	end_writeback(inode);

	mlog_bug_on_msg(atomic_read(&d->d_ios),
			"Disk 0x%p has outstanding I/Os\n", d);

	mlog_bug_on_msg(!list_empty(&d->d_open),
			"Disk 0x%p has openers\n", d);

	mlog_bug_on_msg(d->d_live,
			"Disk 0x%p is live\n", d);

	mlog(ML_DISK, "Clearing disk 0x%p\n", d);

	if (d->d_bdev) {
		mlog(ML_DISK,
		     "Releasing disk 0x%p (bdev 0x%p, dev %X)\n",
		     d, d->d_bdev, d->d_bdev->bd_dev);
		blkdev_put(d->d_bdev, FMODE_WRITE | FMODE_READ);
		d->d_bdev = NULL;
	}

	mlog_exit_void();
}


static struct super_operations asmdisk_sops = {
	.statfs			= simple_statfs,
	.alloc_inode		= asmdisk_alloc_inode,
	.destroy_inode		= asmdisk_destroy_inode,
	.drop_inode		= generic_delete_inode,
	.evict_inode		= asmdisk_evict_inode,
};


static struct dentry * asmdisk_mount(struct file_system_type *fs_type, int flags,
			      const char *dev_name, void *data)
{
	return mount_pseudo(fs_type, "asmdisk:", &asmdisk_sops, NULL, 0x61736D64);
}

static struct file_system_type asmdisk_type = {
	.name		= "asmdisk",
	.mount		= asmdisk_mount,
	.kill_sb	= kill_anon_super,
};

static struct vfsmount *asmdisk_mnt;

static int __init init_asmdiskcache(void)
{
	int err;
	asmdisk_cachep =
		kmem_cache_create("asmdisk_cache",
				  sizeof(struct asm_disk_info),
				  0, SLAB_HWCACHE_ALIGN|SLAB_RECLAIM_ACCOUNT,
				  init_asmdisk_once);
	if (!asmdisk_cachep)
		return -ENOMEM;
	err = register_filesystem(&asmdisk_type);
	if (err) {
		kmem_cache_destroy(asmdisk_cachep);
		return err;
	}
	asmdisk_mnt = kern_mount(&asmdisk_type);
	if (IS_ERR(asmdisk_mnt)) {
		err = PTR_ERR(asmdisk_mnt);
		unregister_filesystem(&asmdisk_type);
		kmem_cache_destroy(asmdisk_cachep);
		return err;
	}

	return 0;
}

static void destroy_asmdiskcache(void)
{
	unregister_filesystem(&asmdisk_type);
	mntput(asmdisk_mnt);
	kmem_cache_destroy(asmdisk_cachep);
}

static int asmdisk_test(struct inode *inode, void *data)
{
	struct asmdisk_find_inode_args *args = data;
	struct asm_disk_info *d = ASMDISK_I(inode);
	unsigned long handle = (unsigned long)(d->d_bdev);

	return (d->d_inode == args->fa_inode) && (handle == args->fa_handle);
}

static int asmdisk_set(struct inode *inode, void *data)
{
	struct asmdisk_find_inode_args *args = data;
	struct asm_disk_info *d = ASMDISK_I(inode);

	d->d_bdev = (struct block_device *)(args->fa_handle);
	d->d_inode = args->fa_inode;

	return 0;
}



/*
 * Resource limit helper functions
 */


/* Decrements the free inode count and returns true, or returns false
 * if there are no free inodes */
static struct inode *asmfs_alloc_inode(struct super_block *sb)
{
	struct asmfs_sb_info *asb = ASMFS_SB(sb);
	struct asmfs_inode_info *aii;

	aii = (struct asmfs_inode_info *)kmem_cache_alloc(asmfs_inode_cachep, GFP_KERNEL);

	if (!aii)
		return NULL;

	spin_lock_irq(&asb->asmfs_lock);
	if (!asb->max_inodes || asb->free_inodes > 0) {
		asb->free_inodes--;
		spin_unlock_irq(&asb->asmfs_lock);
	} else {
		spin_unlock_irq(&asb->asmfs_lock);
		kmem_cache_free(asmfs_inode_cachep, aii);
		return NULL;
	}

	return &aii->vfs_inode;
}

/* Increments the free inode count */
static void asmfs_destroy_inode(struct inode *inode)
{
	spin_lock_irq(&ASMFS_SB(inode->i_sb)->asmfs_lock);
	ASMFS_SB(inode->i_sb)->free_inodes++;
	spin_unlock_irq(&ASMFS_SB(inode->i_sb)->asmfs_lock);

	kmem_cache_free(asmfs_inode_cachep, ASMFS_I(inode));
}

static void instance_init_once(void *foo)
{
	struct asmfs_inode_info *aii = foo;

	INIT_LIST_HEAD(&aii->i_disks);
	INIT_LIST_HEAD(&aii->i_threads);
	spin_lock_init(&aii->i_lock);

	inode_init_once(&aii->vfs_inode);
}
static int init_inodecache(void)
{
	asmfs_inode_cachep =
		kmem_cache_create("asmfs_inode_cache",
				  sizeof(struct asmfs_inode_info),
				  0, SLAB_HWCACHE_ALIGN|SLAB_RECLAIM_ACCOUNT,
				  instance_init_once);

	if (asmfs_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_inodecache(void)
{
	kmem_cache_destroy(asmfs_inode_cachep);
}

static int init_requestcache(void)
{
	asm_request_cachep =
		kmem_cache_create("asm_request",
				  sizeof(struct asm_request),
				  0, SLAB_HWCACHE_ALIGN, NULL);
	if (asm_request_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_requestcache(void)
{
	kmem_cache_destroy(asm_request_cachep);
}


/*
 * Disk file creation in the disks directory.
 */
static int asmfs_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{
	struct inode * inode;

	if (!S_ISBLK(mode))
		return -EINVAL;

	inode = new_inode(dir->i_sb);
	if (!inode)
		return -ENOMEM;

	inode->i_ino = (unsigned long)inode;
	inode->i_mode = mode;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	set_i_blksize(inode, PAGE_CACHE_SIZE);
	inode->i_blocks = 0;
	inode->i_rdev = 0;
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	init_special_inode(inode, mode, dev);

	d_instantiate(dentry, inode);

	/* Extra count - pin the dentry in core */
	dget(dentry);

	return 0;
}

/*
 * Instance file creation in the iid directory.
 */
static int asmfs_create(struct inode *dir, struct dentry *dentry, int mode, struct nameidata *nd)
{
	struct inode *inode;

	if ((mode & S_IFMT) && !S_ISREG(mode))
		return -EINVAL;

	mode |= S_IFREG;

	inode = new_inode(dir->i_sb);
	if (!inode)
		return -ENOMEM;

	inode->i_ino = (unsigned long)inode;
	inode->i_mode = mode;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	set_i_blksize(inode, PAGE_CACHE_SIZE);
	inode->i_blocks = 0;
	inode->i_rdev = 0;
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	inode->i_op = &asmfs_file_inode_operations;
	inode->i_fop = &asmfs_file_operations;
	inode->i_mapping->backing_dev_info = &memory_backing_dev_info;

	d_instantiate(dentry, inode);

	/* Extra count - pin the dentry in core */
	dget(dentry);

	return 0;
}

static void asmfs_put_super(struct super_block *sb)
{
	kfree(ASMFS_SB(sb));
}

enum {
	OPT_MAX_INSTANCES,
	OPT_ERR,
};

static match_table_t tokens = {
	{OPT_MAX_INSTANCES, "maxinstances=%d"},
	{OPT_ERR, NULL},
};

struct asmfs_params {
	long inodes;
};

static int parse_options(char * options, struct asmfs_params *p)
{
	char *s;
	substring_t args[MAX_OPT_ARGS];
	int option;

	p->inodes = -1;

	while ((s = strsep(&options,",")) != NULL) {
		int token;
		if (!*s)
			continue;
		token = match_token(s, tokens, args);
		switch (token) {
			case OPT_MAX_INSTANCES:
				if (match_int(&args[0], &option))
					return -EINVAL;
				p->inodes = option;
				break;

			default:
				return -EINVAL;
		}
	}

	return 0;
}

static void init_limits(struct asmfs_sb_info *asb, struct asmfs_params *p)
{
	struct sysinfo si;

	si_meminfo(&si);

	asb->max_inodes = 0;
	if (p->inodes >= 0)
		asb->max_inodes = p->inodes;

	asb->free_inodes = asb->max_inodes;

	return;
}

/* reset_limits is called during a remount to change the usage limits.

   This will suceed, even if the new limits are lower than current
   usage. This is the intended behaviour - new allocations will fail
   until usage falls below the new limit */
static void reset_limits(struct asmfs_sb_info *asb, struct asmfs_params *p)
{
	spin_lock_irq(&asb->asmfs_lock);

	if (p->inodes >= 0) {
		int used_inodes = asb->max_inodes - asb->free_inodes;

		asb->max_inodes = p->inodes;
		asb->free_inodes = asb->max_inodes - used_inodes;
	}

	spin_unlock_irq(&asb->asmfs_lock);
}

static int asmfs_remount(struct super_block * sb, int * flags, char * data)
{
	struct asmfs_params params;
	struct asmfs_sb_info * asb = ASMFS_SB(sb);

	if (parse_options((char *)data, &params) != 0)
		return -EINVAL;

	reset_limits(asb, &params);

	printk(KERN_DEBUG
	       "ASM: oracleasmfs remounted with options: %s\n",
	       data ? (char *)data : "<defaults>" );
	printk(KERN_DEBUG "ASM:	maxinstances=%ld\n",
	       asb->max_inodes);

	return 0;
}

/*
 * Compute the maximum number of sectors the bdev can handle in one bio,
 * as a power of two.
 */
static int compute_max_sectors(struct block_device *bdev)
{
	int max_pages, max_sectors, pow_two_sectors;
	char b[BDEVNAME_SIZE];

	struct request_queue *q;

	q = bdev_get_queue(bdev);
	mlog(ML_DISK, "Computing limits for block device \%s\":\n",
	     bdevname(bdev, b));
	mlog(ML_DISK,
	     "\tq->max_sectors = %u, q->max_segments = %u\n",
	     queue_max_sectors(q), queue_max_segments(q));
	max_pages = queue_max_sectors(q) >> (PAGE_SHIFT - 9);
	mlog(ML_DISK, "\tmax_pages = %d, BIO_MAX_PAGES = %d\n",
	     max_pages, BIO_MAX_PAGES);
	if (max_pages > BIO_MAX_PAGES)
		max_pages = BIO_MAX_PAGES;
	if (max_pages > queue_max_segments(q))
		max_pages = queue_max_segments(q);
	max_pages--; /* Handle I/Os that straddle a page */
	max_sectors = max_pages << (PAGE_SHIFT - 9);

	/* Why is fls() 1-based???? */
	pow_two_sectors = 1 << (fls(max_sectors) - 1);
	mlog(ML_DISK,
	     "\tresulting max_pages = %d, max_sectors = %d, "
	     "pow_two_sectors = %d\n",
	     max_pages, max_sectors, pow_two_sectors);

	return pow_two_sectors;
}

static int asm_open_disk(struct file *file, struct block_device *bdev)
{
	int ret;
	struct asm_disk_info *d;
	struct asm_disk_head *h;
	struct inode *inode = ASMFS_F2I(file);
	struct inode *disk_inode;
	struct asmdisk_find_inode_args args;

	mlog_entry("(0x%p, 0x%p)\n", file, bdev);

	ret = blkdev_get(bdev, FMODE_WRITE | FMODE_READ, inode->i_sb);
	if (ret)
		goto out;

	ret = set_blocksize(bdev, bdev_physical_block_size(bdev));
	if (ret)
		goto out_get;

	ret = -ENOMEM;
	h = kmalloc(sizeof(struct asm_disk_head), GFP_KERNEL);
	if (!h)
		goto out_get;

	mlog(ML_DISK, "Looking up disk for bdev %p (dev %X)\n", bdev,
	     bdev->bd_dev);

	args.fa_handle = (unsigned long)bdev;
	args.fa_inode = ASMFS_I(inode);
	disk_inode = iget5_locked(asmdisk_mnt->mnt_sb,
				  (unsigned long)bdev, asmdisk_test,
				  asmdisk_set, &args);
	if (!disk_inode)
		goto out_head;

	d = ASMDISK_I(disk_inode);

	if (disk_inode->i_state & I_NEW) {
		mlog_bug_on_msg(atomic_read(&d->d_ios) != 0,
				"Supposedly new disk 0x%p (dev %X) has outstanding I/O\n",
				d, bdev->bd_dev);
		mlog_bug_on_msg(d->d_live,
				"Supposedly new disk 0x%p (dev %X) is live\n",
				d, bdev->bd_dev);

		mlog_bug_on_msg(d->d_bdev != bdev,
				"New disk 0x%p has set bdev 0x%p but we were opening 0x%p\n",
				d, d->d_bdev, bdev);

		disk_inode->i_mapping->backing_dev_info =
			&memory_backing_dev_info;
		d->d_max_sectors = compute_max_sectors(bdev);
		d->d_live = 1;

		mlog(ML_DISK,
		     "First open of disk 0x%p (bdev 0x%p, dev %X)\n",
		     d, d->d_bdev, d->d_bdev->bd_dev);
		unlock_new_inode(disk_inode);
	} else {
		/* Already claimed on first open */
		mlog(ML_DISK,
		     "Open of disk 0x%p (bdev 0x%p, dev %X)\n",
		     d, d->d_bdev, d->d_bdev->bd_dev);
		blkdev_put(bdev, FMODE_WRITE | FMODE_READ);
	}

	h->h_disk = d;
	h->h_file = ASMFS_FILE(file);

	spin_lock_irq(&ASMFS_FILE(file)->f_lock);
	list_add(&h->h_flist, &ASMFS_FILE(file)->f_disks);
	spin_unlock_irq(&ASMFS_FILE(file)->f_lock);

	spin_lock_irq(&ASMFS_I(inode)->i_lock);
	list_add(&h->h_dlist, &d->d_open);
	spin_unlock_irq(&ASMFS_I(inode)->i_lock);

	mlog_exit(0);
	return 0;

out_head:
	kfree(h);

out_get:
	blkdev_put(bdev, FMODE_WRITE | FMODE_READ);

out:
	mlog_exit(ret);
	return ret;
}

static int asm_close_disk(struct file *file, unsigned long handle)
{
	struct inode *inode = ASMFS_F2I(file);
	struct asmdisk_find_inode_args args;
	struct asm_disk_info *d;
	struct block_device *bdev;
	struct inode *disk_inode;
	struct list_head *p;
	struct asm_disk_head *h;
	struct task_struct *tsk = current;
	DECLARE_WAITQUEUE(wait, tsk);

	mlog_entry("(0x%p, %lu)\n", file, handle);

	mlog_bug_on_msg(!ASMFS_FILE(file) || !ASMFS_I(inode),
			"Garbage arguments\n");

	args.fa_handle = handle;
	args.fa_inode = ASMFS_I(inode);
	disk_inode = ilookup5(asmdisk_mnt->mnt_sb, handle,
			      asmdisk_test, &args);
	if (!disk_inode) {
		mlog_exit(-EINVAL);
		return -EINVAL;
	}

	d = ASMDISK_I(disk_inode);
	bdev = d->d_bdev;

	mlog(ML_DISK, "Closing disk 0x%p (bdev 0x%p, dev %X)\n",
	     d, d->d_bdev, d->d_bdev->bd_dev);

	/*
	 * If an additional thread raced us to close the disk, it
	 * will have removed the disk from the list already.
	 */

	spin_lock_irq(&ASMFS_FILE(file)->f_lock);
	h = NULL;
	list_for_each(p, &ASMFS_FILE(file)->f_disks) {
		h = list_entry(p, struct asm_disk_head, h_flist);
		if (h->h_disk == d)
			break;
		h = NULL;
	}
	if (!h) {
		spin_unlock_irq(&ASMFS_FILE(file)->f_lock);
		iput(disk_inode);
		mlog_exit(-EINVAL);
		return -EINVAL;
	}
	list_del(&h->h_flist);
	spin_unlock_irq(&ASMFS_FILE(file)->f_lock);

	spin_lock_irq(&ASMFS_I(inode)->i_lock);
	list_del(&h->h_dlist);

	/* Last close */
	if (list_empty(&d->d_open)) {
		mlog(ML_DISK,
		     "Last close of disk 0x%p (bdev 0x%p, dev %X)\n",
		     d, d->d_bdev, d->d_bdev->bd_dev);

		/* I/O path can't look up this disk anymore */
		mlog_bug_on_msg(!d->d_live,
				"Disk 0x%p (bdev 0x%p, dev %X) isn't live at last close\n",
				d, d->d_bdev, d->d_bdev->bd_dev);
		d->d_live = 0;
		spin_unlock_irq(&ASMFS_I(inode)->i_lock);

		/* No need for a fast path */
		add_wait_queue(&ASMFS_FILE(file)->f_wait, &wait);
		do {
			set_task_state(tsk, TASK_UNINTERRUPTIBLE);

			if (!atomic_read(&d->d_ios))
				break;

			/*
			 * Timeout of one second.  This is slightly
			 * subtle.  In this wait, and *only* this wait,
			 * we are waiting on I/Os that might have been
			 * initiated by another process.  In that case,
			 * the other process's afi will be signaled,
			 * not ours, so the wake_up() never happens
			 * here and we need the timeout.
			 */
			schedule_timeout(HZ);
		} while (1);
		set_task_state(tsk, TASK_RUNNING);
		remove_wait_queue(&ASMFS_FILE(file)->f_wait, &wait);
	}
	else
		spin_unlock_irq(&ASMFS_I(inode)->i_lock);

	kfree(h);

	/* Drop the ref from ilookup5() */
	iput(disk_inode);

	/* Real put */
	iput(disk_inode);

	mlog_exit(0);
	return 0;
}  /* asm_close_disk() */


/* Timeout stuff ripped from aio.c - thanks Ben */
struct timeout {
	struct timer_list	timer;
	int			timed_out;
	wait_queue_head_t	wait;
};

static void timeout_func(unsigned long data)
{
	struct timeout *to = (struct timeout *)data;

	to->timed_out = 1;
	wake_up(&to->wait);
}

static inline void init_timeout(struct timeout *to)
{
	init_timer(&to->timer);
	to->timer.data = (unsigned long)to;
	to->timer.function = timeout_func;
	to->timed_out = 0;
	init_waitqueue_head(&to->wait);
}

static inline void set_timeout(struct timeout *to, const struct timespec *ts)
{
	unsigned long how_long;

	if (!ts->tv_sec && !ts->tv_nsec) {
		to->timed_out = 1;
		return;
	}

	how_long = ts->tv_sec * HZ;
#define HZ_NS (1000000000 / HZ)
	how_long += (ts->tv_nsec + HZ_NS - 1) / HZ_NS;

	to->timer.expires = jiffies + how_long;
	add_timer(&to->timer);
}

static inline void clear_timeout(struct timeout *to)
{
	del_timer_sync(&to->timer);
}

/* Must be called with asm_file_info->f_lock held */
static struct block_device *find_io_bdev(struct file *file)
{
	struct asmfs_file_info *afi = ASMFS_FILE(file);
	struct asm_request *r;
	struct asm_disk_info *d;
	struct block_device *bdev = NULL;

	list_for_each_entry(r, &afi->f_ios, r_list) {
		d = r->r_disk;
		if (d && d->d_bdev) {
			bdev = d->d_bdev;
			break;
		}
	}

	return bdev;
}

static int asm_update_user_ioc(struct file *file, struct asm_request *r)
{
	int ret = 0;
	struct asm_request copy;
	asm_ioc __user *ioc;
	u16 tmp_status;
	unsigned long flags;

	mlog_entry("(0x%p)\n", r);

	ioc = r->r_ioc;
	mlog(ML_IOC, "User IOC is 0x%p\n", ioc);

	/* Need to get the current userspace bits because ASM_CANCELLED is currently set there */
	mlog(ML_IOC, "Getting tmp_status\n");
	if (get_user(tmp_status, &(ioc->status_asm_ioc))) {
		ret = -EFAULT;
		goto out;
	}

	/*
	 * We're going to store off a copy of the request so we can
	 * provide a consistent view to userspace.
	 *
	 * And so we can get/put_user() without locking :-)
	 */
	spin_lock_irqsave(&ASMFS_FILE(file)->f_lock, flags);
	r->r_status |= tmp_status;
	copy = *r;
	spin_unlock_irqrestore(&ASMFS_FILE(file)->f_lock, flags);

	/* From here on, ONLY TRUST copy */

	mlog(ML_IOC, "Putting r_status (0x%08X)\n", copy.r_status);
	if (put_user(copy.r_status, &(ioc->status_asm_ioc))) {
		ret = -EFAULT;
		goto out;
	}
	if (copy.r_status & ASM_ERROR) {
		mlog(ML_IOC, "Putting r_error (0x%08X)\n", copy.r_error);
		if (put_user(copy.r_error, &(ioc->error_asm_ioc))) {
			ret = -EFAULT;
			goto out;
		}
	}
	if (copy.r_status & ASM_COMPLETED) {
		if (put_user(copy.r_elapsed, &(ioc->elaptime_asm_ioc))) {
			ret = -EFAULT;
			goto out;
		}
	}
	mlog(ML_IOC,
	     "r_status:0x%08X, bitmask:0x%08X, combined:0x%08X\n",
	     copy.r_status,
	     (ASM_SUBMITTED | ASM_COMPLETED | ASM_ERROR),
	     (copy.r_status & (ASM_SUBMITTED | ASM_COMPLETED | ASM_ERROR)));
	if (copy.r_status & ASM_FREE) {
		u64 z = 0ULL;
		if (copy_to_user(&(ioc->reserved_asm_ioc),
				 &z, sizeof(ioc->reserved_asm_ioc))) {
			ret = -EFAULT;
			goto out;
		}
	} else if (copy.r_status &
		   (ASM_SUBMITTED | ASM_ERROR)) {
		u64 key = (u64)(unsigned long)r;
		mlog(ML_IOC, "Putting key 0x%p on asm_ioc 0x%p\n",
		     r, ioc);
		/* Only on first submit */
		if (copy_to_user(&(ioc->reserved_asm_ioc),
				 &key, sizeof(ioc->reserved_asm_ioc))) {
			ret = -EFAULT;
			goto out;
		}
	}

out:
	mlog_exit(ret);
	return ret;
}  /* asm_update_user_ioc() */


static struct asm_request *asm_request_alloc(void)
{
	struct asm_request *r;

	r = kmem_cache_zalloc(asm_request_cachep, GFP_KERNEL);

	if (r)
		r->r_status = ASM_SUBMITTED;

	return r;
}  /* asm_request_alloc() */


static void asm_request_free(struct asm_request *r)
{
	/* FIXME: Clean up bh and buffer stuff */

	kmem_cache_free(asm_request_cachep, r);
}  /* asm_request_free() */


static void asm_finish_io(struct asm_request *r)
{
	struct asm_disk_info *d;
	struct asmfs_file_info *afi = r->r_file;
	unsigned long flags;

	mlog_bug_on_msg(!afi, "Request 0x%p has no file pointer\n", r);

	mlog_entry("(0x%p)\n", r);

	spin_lock_irqsave(&afi->f_lock, flags);

	if (r->r_bio) {
		mlog(ML_REQUEST|ML_BIO,
		     "Moving bio 0x%p from request 0x%p to the free list\n",
		     r->r_bio, r);
		r->r_bio->bi_private = afi->f_bio_free;
		afi->f_bio_free = r->r_bio;
		r->r_bio = NULL;
	}

	d = r->r_disk;
	r->r_disk = NULL;

	list_del(&r->r_list);
	list_add(&r->r_list, &afi->f_complete);
	if (r->r_error)
		r->r_status |= ASM_ERROR;
	r->r_status |= ASM_COMPLETED;

	spin_unlock_irqrestore(&afi->f_lock, flags);

	if (d) {
		atomic_dec(&d->d_ios);
		if (atomic_read(&d->d_ios) < 0) {
			mlog(ML_ERROR,
			     "d_ios underflow on disk 0x%p (dev %X)\n",
			     d, d->d_bdev->bd_dev);
			atomic_set(&d->d_ios, 0);
		}
	}

	r->r_elapsed = ((jiffies - r->r_elapsed) * 1000000) / HZ;

	mlog(ML_REQUEST, "Finished request 0x%p\n", r);

	wake_up(&afi->f_wait);

	mlog_exit_void();
}  /* asm_finish_io() */


static void asm_end_ioc(struct asm_request *r, unsigned int bytes_done,
			int error)
{
	mlog_entry("(0x%p, %u, %d)\n", r, bytes_done, error);

	mlog_bug_on_msg(!r, "No request\n");

	mlog_bug_on_msg(!(r->r_status & ASM_SUBMITTED),
			"Request 0x%p wasn't submitted\n", r);

	mlog(ML_REQUEST,
	     "Ending request 0x%p, bytes_done = %u, error = %d\n",
	     r, bytes_done, error);
	mlog(ML_REQUEST|ML_BIO,
	     "Ending request 0x%p, bio 0x%p, len = %u\n",
	     r, r->r_bio,
	     bytes_done + (r->r_bio ? r->r_bio->bi_size : 0));

	switch (error) {
		default:
			mlog(ML_REQUEST|ML_ERROR,
			     "Invalid error of %d on request 0x%p!\n",
			     error, r);
			r->r_error = ASM_ERR_INVAL;
			r->r_status |= ASM_LOCAL_ERROR;
			break;

		case 0:
			break;

		case -EFAULT:
			r->r_error = ASM_ERR_FAULT;
			r->r_status |= ASM_LOCAL_ERROR;
			break;

		case -EIO:
			r->r_error = ASM_ERR_IO;
			break;

		case -EILSEQ:
			r->r_error = asm_integrity_error(r);
			break;

		case -ENODEV:
			r->r_error = ASM_ERR_NODEV;
			r->r_status |= ASM_LOCAL_ERROR;
			break;

		case -ENOMEM:
			r->r_error = ASM_ERR_NOMEM;
			r->r_status |= ASM_LOCAL_ERROR;
			break;

		case -EINVAL:
			r->r_error = ASM_ERR_INVAL;
			r->r_status |= ASM_LOCAL_ERROR;
			break;
	}

	asm_finish_io(r);

	mlog_exit_void();
}  /* asm_end_ioc() */


static void asm_end_bio_io(struct bio *bio, int error)
{
	struct asm_request *r;

	mlog_entry("(0x%p, %d)\n", bio, error);

	mlog(ML_BIO, "bio 0x%p, bi_size is %u\n", bio, bio->bi_size);

	r = bio->bi_private;

	mlog(ML_REQUEST|ML_BIO,
	     "Completed bio 0x%p for request 0x%p\n", bio, r);
	if (atomic_dec_and_test(&r->r_bio_count)) {
		asm_end_ioc(r, r->r_count - (r->r_bio ?
					     r->r_bio->bi_size : 0),
			    error);
	}

	mlog_exit_void();
}  /* asm_end_bio_io() */

static int asm_submit_io(struct file *file,
			 asm_ioc __user *user_iocp,
			 asm_ioc *ioc)
{
	int ret, rw = READ;
	struct inode *inode = ASMFS_F2I(file);
	struct asmdisk_find_inode_args args;
	struct asm_request *r;
	struct asm_disk_info *d;
	struct inode *disk_inode;
	struct block_device *bdev;
	struct oracleasm_integrity_v2 *it;

	mlog_entry("(0x%p, 0x%p, 0x%p)\n", file, user_iocp, ioc);

	if (!ioc) {
		mlog_exit(-EINVAL);
		return -EINVAL;
	}

	if (ioc->status_asm_ioc) {
		mlog_exit(-EINVAL);
		return -EINVAL;
	}

	r = asm_request_alloc();
	if (!r) {
		u16 status = ASM_FREE | ASM_ERROR | ASM_LOCAL_ERROR |
			ASM_BUSY;
		if (put_user(status, &(user_iocp->status_asm_ioc))) {
			mlog_exit(-EFAULT);
			return -EFAULT;
		}
		if (put_user(ASM_ERR_NOMEM, &(user_iocp->error_asm_ioc))) {
			mlog_exit(-EFAULT);
			return -EFAULT;
		}

		mlog_exit(0);
		return 0;
	}

	mlog(ML_REQUEST,
	     "New request at 0x%p alloc()ed for user ioc at 0x%p\n",
	     r, user_iocp);

	r->r_file = ASMFS_FILE(file);
	r->r_ioc = user_iocp;  /* Userspace asm_ioc */

	spin_lock_irq(&ASMFS_FILE(file)->f_lock);
	list_add(&r->r_list, &ASMFS_FILE(file)->f_ios);
	spin_unlock_irq(&ASMFS_FILE(file)->f_lock);

	ret = -ENODEV;
	args.fa_handle = (unsigned long)ioc->disk_asm_ioc &
		~ASM_INTEGRITY_HANDLE_MASK;
	args.fa_inode = ASMFS_I(inode);
	disk_inode = ilookup5(asmdisk_mnt->mnt_sb,
			      (unsigned long)args.fa_handle,
			      asmdisk_test, &args);
	if (!disk_inode)
		goto out_error;

	spin_lock_irq(&ASMFS_I(inode)->i_lock);

	d = ASMDISK_I(disk_inode);
	if (!d->d_live) {
		/* It's in the middle of closing */
		spin_unlock_irq(&ASMFS_I(inode)->i_lock);
		iput(disk_inode);
		goto out_error;
	}

	atomic_inc(&d->d_ios);
	r->r_disk = d;

	spin_unlock_irq(&ASMFS_I(inode)->i_lock);
	iput(disk_inode);

	bdev = d->d_bdev;

	r->r_count = ioc->rcount_asm_ioc * bdev_physical_block_size(bdev);

	/* linux only supports unsigned long size sector numbers */
	mlog(ML_IOC,
	     "user_iocp 0x%p: first = 0x%llX, masked = 0x%08lX status = %u, buffer_asm_ioc = 0x%08lX, count = %lu\n",
	     user_iocp,
	     (unsigned long long)ioc->first_asm_ioc,
	     (unsigned long)ioc->first_asm_ioc,
	     ioc->status_asm_ioc,
	     (unsigned long)ioc->buffer_asm_ioc,
	     (unsigned long)r->r_count);
	/* Note that priority is ignored for now */
	ret = -EINVAL;
	if (!ioc->buffer_asm_ioc ||
	    (ioc->buffer_asm_ioc != (unsigned long)ioc->buffer_asm_ioc) ||
	    (ioc->first_asm_ioc != (unsigned long)ioc->first_asm_ioc) ||
	    (ioc->rcount_asm_ioc != (unsigned long)ioc->rcount_asm_ioc) ||
	    (ioc->priority_asm_ioc > 7) ||
	    (r->r_count > (queue_max_sectors(bdev_get_queue(bdev)) << 9)) ||
	    (r->r_count < 0))
		goto out_error;

	/* Test device size, when known. (massaged from ll_rw_blk.c) */
	if (bdev->bd_inode->i_size >> 9) {
		sector_t maxsector = bdev->bd_inode->i_size >> 9;
		sector_t sector = (sector_t)ioc->first_asm_ioc;
		sector_t blks = (sector_t)ioc->rcount_asm_ioc;

		if (maxsector < blks || maxsector - blks < sector) {
			char b[BDEVNAME_SIZE];
			mlog(ML_NOTICE|ML_IOC,
			     "Attempt to access beyond end of device\n");
			mlog(ML_NOTICE|ML_IOC,
			     "dev %s: want=%llu, limit=%llu\n",
			     bdevname(bdev, b),
			     (unsigned long long)(sector + blks),
			     (unsigned long long)maxsector);
			goto out_error;
		}
	}


	mlog(ML_REQUEST|ML_IOC,
	     "Request 0x%p (user_ioc 0x%p) passed validation checks\n",
	     r, user_iocp);

	if (bdev_get_integrity(bdev))
		it = (struct oracleasm_integrity_v2 *)ioc->check_asm_ioc;
	else
		it = NULL;

	switch (ioc->operation_asm_ioc) {
		default:
			goto out_error;
			break;

		case ASM_READ:
			rw = READ;

			if (it && asm_integrity_check(it, bdev) < 0)
				goto out_error;

			break;

		case ASM_WRITE:
			rw = WRITE;

			if (it && asm_integrity_check(it, bdev) < 0)
				goto out_error;

			break;

		case ASM_NOOP:
			/* Trigger an errorless completion */
			r->r_count = 0;
			break;
	}

	/* Not really an error, but hey, it's an end_io call */
	ret = 0;
	if (r->r_count == 0)
		goto out_error;

	ret = -ENOMEM;
	r->r_bio = bio_map_user(bdev_get_queue(bdev), bdev,
				(unsigned long)ioc->buffer_asm_ioc,
				r->r_count, rw == READ, GFP_KERNEL);
	if (IS_ERR(r->r_bio)) {
		ret = PTR_ERR(r->r_bio);
		r->r_bio = NULL;
		goto out_error;
	}

	if (r->r_bio->bi_size != r->r_count) {
		mlog(ML_ERROR|ML_BIO, "Only mapped partial ioc buffer\n");
		bio_unmap_user(r->r_bio);
		r->r_bio = NULL;
		ret = -ENOMEM;
		goto out_error;
	}

	mlog(ML_BIO, "Mapped bio 0x%p to request 0x%p\n", r->r_bio, r);

	/* Block layer always uses 512-byte sector addressing,
	 * regardless of logical and physical block size.
	 */
	r->r_bio->bi_sector = ioc->first_asm_ioc *
		(bdev_physical_block_size(bdev) >> 9);

	if (it) {
		ret = asm_integrity_map(it, r, rw == READ);

		if (ret < 0) {
			mlog(ML_ERROR|ML_BIO,
			     "Could not attach integrity payload\n");
			bio_unmap_user(r->r_bio);
			goto out_error;
		}
	}

	/*
	 * If the bio is a bounced bio, we have to put the
	 * end_io on the child "real" bio
	 */
	r->r_bio->bi_end_io = asm_end_bio_io;
	r->r_bio->bi_private = r;

	r->r_elapsed = jiffies;  /* Set start time */

	atomic_set(&r->r_bio_count, 1);

	mlog(ML_REQUEST|ML_BIO,
	     "Submitting bio 0x%p for request 0x%p\n", r->r_bio, r);
	submit_bio(rw, r->r_bio);

out:
	ret = asm_update_user_ioc(file, r);

	mlog_exit(ret);
	return ret;

out_error:
	mlog(ML_REQUEST, "Submit-side error %d for request 0x%p\n",
	     ret,  r);
	asm_end_ioc(r, 0, ret);
	goto out;
}  /* asm_submit_io() */


static int asm_maybe_wait_io(struct file *file,
			     asm_ioc *iocp,
			     struct timeout *to)
{
	long ret;
	u64 p;
	struct asmfs_file_info *afi = ASMFS_FILE(file);
	struct asmdisk_find_inode_args args;
	struct asm_request *r;
	struct task_struct *tsk = current;
	DECLARE_WAITQUEUE(wait, tsk);
	DECLARE_WAITQUEUE(to_wait, tsk);

	mlog_entry("(0x%p, 0x%p, 0x%p)\n", file, iocp, to);

	if (copy_from_user(&p, &(iocp->reserved_asm_ioc),
			   sizeof(p))) {
		ret = -EFAULT;
		goto out;
	}

	mlog(ML_REQUEST|ML_IOC, "User asm_ioc 0x%p has key 0x%p\n",
	     iocp, (struct asm_request *)(unsigned long)p);
	r = (struct asm_request *)(unsigned long)p;
	if (!r) {
		ret = -EINVAL;
		goto out;
	}

	spin_lock_irq(&afi->f_lock);
	/* Is it valid? It's surely ugly */
	if (!r->r_file || (r->r_file != afi) ||
	    list_empty(&r->r_list) || !(r->r_status & ASM_SUBMITTED)) {
		spin_unlock_irq(&afi->f_lock);
		ret = -EINVAL;
		goto out;
	}

	mlog(ML_REQUEST|ML_IOC,
	     "asm_request 0x%p is valid...we think\n", r);
	if (!(r->r_status & (ASM_COMPLETED |
			     ASM_BUSY | ASM_ERROR))) {
		spin_unlock_irq(&afi->f_lock);
		add_wait_queue(&afi->f_wait, &wait);
		add_wait_queue(&to->wait, &to_wait);
		do {
			struct asm_disk_info *d;
			struct block_device *bdev = NULL;
			struct inode *disk_inode;

			ret = 0;
			set_task_state(tsk, TASK_INTERRUPTIBLE);

			spin_lock_irq(&afi->f_lock);
			if (r->r_status & (ASM_COMPLETED |
					   ASM_BUSY | ASM_ERROR))
				break;
			d = r->r_disk;
			if (d && d->d_bdev)
				bdev = d->d_bdev;
			spin_unlock_irq(&afi->f_lock);

			args.fa_handle = (unsigned long)bdev;
			args.fa_inode = ASMFS_I(ASMFS_F2I(file));
			disk_inode = ilookup5(asmdisk_mnt->mnt_sb,
					      (unsigned long)bdev,
					      asmdisk_test, &args);
			if (disk_inode) {
				d = ASMDISK_I(disk_inode);
				iput(&d->vfs_inode);
			}

			ret = -ETIMEDOUT;
			if (to->timed_out)
				break;
			io_schedule();
			if (signal_pending(tsk)) {
				mlog(ML_REQUEST,
				     "Signal pending waiting for request 0x%p\n",
				     r);
				ret = -EINTR;
				break;
			}
		} while (1);
		set_task_state(tsk, TASK_RUNNING);
		remove_wait_queue(&afi->f_wait, &wait);
		remove_wait_queue(&to->wait, &to_wait);

		if (ret)
			goto out;
	}

	ret = 0;

	/* Somebody got here first */
	/*
	 * FIXME: This race means that we cannot be shared by two
	 * threads/processes (this struct file).  If everyone does
	 * their own open and gets their own struct file, this never
	 * happens and we're safe.
	 */
	if (r->r_status & ASM_FREE)
		goto out;  /* FIXME: Eek, holding lock */
	mlog_bug_on_msg(list_empty(&afi->f_complete),
			"Completion list is empty\n");

	mlog(ML_REQUEST|ML_IOC,
	     "Removing request 0x%p for asm_ioc 0x%p\n", r, iocp);
	list_del_init(&r->r_list);
	r->r_file = NULL;
	r->r_status |= ASM_FREE;

	spin_unlock_irq(&afi->f_lock);

	ret = asm_update_user_ioc(file, r);

	mlog(ML_REQUEST, "Freeing request 0x%p\n", r);
	asm_request_free(r);

out:
	mlog_exit(ret);
	return ret;
}  /* asm_maybe_wait_io() */


static int asm_complete_io(struct file *file,
			   asm_ioc **ioc)
{
	int ret = 0;
	struct list_head *l;
	struct asm_request *r;
	struct asmfs_file_info *afi = ASMFS_FILE(file);

	mlog_entry("(0x%p, 0x%p)\n", file, ioc);

	spin_lock_irq(&afi->f_lock);

	if (list_empty(&afi->f_complete)) {
		spin_unlock_irq(&afi->f_lock);
		*ioc = NULL;
		mlog_exit(0);
		return 0;
	}

	l = afi->f_complete.prev;
	r = list_entry(l, struct asm_request, r_list);
	list_del_init(&r->r_list);
	r->r_file = NULL;
	r->r_status |= ASM_FREE;

	spin_unlock_irq(&afi->f_lock);

	*ioc = r->r_ioc;

	ret = asm_update_user_ioc(file, r);

	asm_request_free(r);

	mlog_exit(ret);
	return ret;
}  /* asm_complete_io() */


static int asm_wait_completion(struct file *file,
			       struct oracleasm_io_v2 *io,
			       struct timeout *to,
			       u32 *status)
{
	int ret;
	struct asmfs_file_info *afi = ASMFS_FILE(file);
	struct task_struct *tsk = current;
	DECLARE_WAITQUEUE(wait, tsk);
	DECLARE_WAITQUEUE(to_wait, tsk);

	mlog_entry("(0x%p, 0x%p, 0x%p, 0x%p)\n", file, io, to, status);

	/* Early check - expensive stuff follows */
	ret = -ETIMEDOUT;
	if (to->timed_out)
		goto out;

	spin_lock_irq(&afi->f_lock);
	if (list_empty(&afi->f_ios) &&
	    list_empty(&afi->f_complete)) {
		/* No I/Os left */
		spin_unlock_irq(&afi->f_lock);
		ret = 0;
		*status |= ASM_IO_IDLE;
		goto out;
	}
	spin_unlock_irq(&afi->f_lock);

	add_wait_queue(&afi->f_wait, &wait);
	add_wait_queue(&to->wait, &to_wait);
	do {
		struct block_device *bdev;
		struct asm_disk_info *d;
		struct inode *disk_inode;
		struct asmdisk_find_inode_args args;

		ret = 0;
		set_task_state(tsk, TASK_INTERRUPTIBLE);

		spin_lock_irq(&afi->f_lock);
		if (!list_empty(&afi->f_complete)) {
			spin_unlock_irq(&afi->f_lock);
			break;
		}

		bdev = find_io_bdev(file);
		spin_unlock_irq(&afi->f_lock);

		args.fa_handle = (unsigned long)bdev;
		args.fa_inode = ASMFS_I(ASMFS_F2I(file));
		disk_inode = ilookup5(asmdisk_mnt->mnt_sb,
				      (unsigned long)bdev,
				      asmdisk_test, &args);
		if (disk_inode) {
			d = ASMDISK_I(disk_inode);
			iput(&d->vfs_inode);
		}

		ret = -ETIMEDOUT;
		if (to->timed_out)
			break;
		io_schedule();
		if (signal_pending(tsk)) {
			ret = -EINTR;
			break;
		}
	} while (1);
	set_task_state(tsk, TASK_RUNNING);
	remove_wait_queue(&afi->f_wait, &wait);
	remove_wait_queue(&to->wait, &to_wait);

out:
	mlog_exit(ret);
	return ret;
}  /* asm_wait_completion() */


static inline int asm_submit_io_native(struct file *file,
       				       struct oracleasm_io_v2 *io)
{
	int ret = 0;
	u32 i;
	asm_ioc *iocp;
	asm_ioc tmp;

	mlog_entry("(0x%p, 0x%p)\n", file, io);

	for (i = 0; i < io->io_reqlen; i++) {
		ret = -EFAULT;
		if (get_user(iocp,
			     ((asm_ioc **)((unsigned long)(io->io_requests))) + i))
			break;

		if (copy_from_user(&tmp, iocp, sizeof(tmp)))
			break;

		mlog(ML_IOC, "Submitting user asm_ioc 0x%p\n", iocp);
		ret = asm_submit_io(file, iocp, &tmp);
		if (ret)
			break;
	}

	mlog_exit(ret);
	return ret;
}  /* asm_submit_io_native() */


static inline int asm_maybe_wait_io_native(struct file *file,
					   struct oracleasm_io_v2 *io,
					   struct timeout *to)
{
	int ret = 0;
	u32 i;
	asm_ioc *iocp;

	mlog_entry("(0x%p, 0x%p, 0x%p)\n", file, io, to);

	for (i = 0; i < io->io_waitlen; i++) {
		if (get_user(iocp,
			     ((asm_ioc **)((unsigned long)(io->io_waitreqs))) + i)) {
			ret = -EFAULT;
			break;
		}

		ret = asm_maybe_wait_io(file, iocp, to);
		if (ret)
			break;
	}

	mlog_exit(ret);
	return ret;
}  /* asm_maybe_wait_io_native() */


static inline int asm_complete_ios_native(struct file *file,
					  struct oracleasm_io_v2 *io,
					  struct timeout *to,
					  u32 *status)
{
	int ret = 0;
	u32 i;
	asm_ioc *iocp;

	mlog_entry("(0x%p, 0x%p, 0x%p, 0x%p)\n", file, io, to, status);

	for (i = 0; i < io->io_complen; i++) {
		ret = asm_complete_io(file, &iocp);
		if (ret)
			break;
		if (iocp) {
			ret = put_user(iocp,
				       ((asm_ioc **)((unsigned long)(io->io_completions))) + i);
			       if (ret)
				   break;
			continue;
		}

		/* We had waiters that are full */
		if (*status & ASM_IO_WAITED)
			break;

		ret = asm_wait_completion(file, io, to, status);
		if (ret)
			break;
		if (*status & ASM_IO_IDLE)
			break;

		i--; /* Reset this completion */

	}

	mlog_exit(ret ? ret : i);
	return (ret ? ret : i);
}  /* asm_complete_ios_native() */


#if BITS_PER_LONG == 64
static inline void asm_promote_64(asm_ioc64 *ioc)
{
	asm_ioc32 *ioc_32 = (asm_ioc32 *)ioc;

	mlog_entry("(0x%p)\n", ioc);

	/*
	 * Promote the 32bit pointers at the end of the asm_ioc32
	 * into the asm_ioc64.
	 *
	 * Promotion must be done from the tail backwards.
	 */
	mlog(ML_IOC, "Promoting (0x%X, 0x%X)\n",
	     ioc_32->check_asm_ioc,
	     ioc_32->buffer_asm_ioc);
	ioc->check_asm_ioc = (u64)ioc_32->check_asm_ioc;
	ioc->buffer_asm_ioc = (u64)ioc_32->buffer_asm_ioc;
	mlog(ML_IOC, "Promoted to (0x%"MLFu64", 0x%"MLFu64")\n",
	     ioc->check_asm_ioc,
	     ioc->buffer_asm_ioc);

	mlog_exit_void();
}  /* asm_promote_64() */


static inline int asm_submit_io_thunk(struct file *file,
	       			      struct oracleasm_io_v2 *io)
{
	int ret = 0;
	u32 i;
	u32 iocp_32;
	asm_ioc32 *iocp;
	asm_ioc tmp;

	mlog_entry("(0x%p, 0x%p)\n", file, io);

	for (i = 0; i < io->io_reqlen; i++) {
		ret = -EFAULT;
		/*
		 * io->io_requests is an asm_ioc32**, but the pointers
		 * are 32bit pointers.
		 */
		if (get_user(iocp_32,
			     ((u32 *)((unsigned long)(io->io_requests))) + i))
			break;

		iocp = (asm_ioc32 *)(unsigned long)iocp_32;

		if (copy_from_user(&tmp, iocp, sizeof(*iocp)))
			break;

		asm_promote_64(&tmp);

		mlog(ML_IOC, "Submitting user asm_ioc 0x%p\n", iocp);
		ret = asm_submit_io(file, (asm_ioc *)iocp, &tmp);
		if (ret)
			break;
	}

	mlog_exit(ret);
	return ret;
}  /* asm_submit_io_thunk() */


static inline int asm_maybe_wait_io_thunk(struct file *file,
					  struct oracleasm_io_v2 *io,
					  struct timeout *to)
{
	int ret = 0;
	u32 i;
	u32 iocp_32;
	asm_ioc *iocp;

	mlog_entry("(0x%p, 0x%p, 0x%p)\n", file, io, to);

	for (i = 0; i < io->io_waitlen; i++) {
		/*
		 * io->io_waitreqs is an asm_ioc32**, but the pointers
		 * are 32bit pointers.
		 */
		if (get_user(iocp_32,
			     ((u32 *)((unsigned long)(io->io_waitreqs))) + i)) {
			ret = -EFAULT;
			break;
		}

		/* Remember, the this is pointing to 32bit userspace */
		iocp = (asm_ioc *)(unsigned long)iocp_32;

		ret = asm_maybe_wait_io(file, iocp, to);
		if (ret)
			break;
	}

	mlog_exit(ret);
	return ret;
}  /* asm_maybe_wait_io_thunk() */


static inline int asm_complete_ios_thunk(struct file *file,
					 struct oracleasm_io_v2 *io,
					 struct timeout *to,
					 u32 *status)
{
	int ret = 0;
	u32 i;
	u32 iocp_32;
	asm_ioc *iocp;

	mlog_entry("(0x%p, 0x%p, 0x%p, 0x%p)\n", file, io, to, status);

	for (i = 0; i < io->io_complen; i++) {
		ret = asm_complete_io(file, &iocp);
		if (ret)
			break;
		if (iocp) {
			iocp_32 = (u32)(unsigned long)iocp;

			ret = put_user(iocp_32,
				       ((u32 *)((unsigned long)(io->io_completions))) + i);
			       if (ret)
				   break;
			continue;
		}

		/* We had waiters that are full */
		if (*status & ASM_IO_WAITED)
			break;

		ret = asm_wait_completion(file, io, to, status);
		if (ret)
			break;
		if (*status & ASM_IO_IDLE)
			break;

		i--; /* Reset this completion */
	}

	mlog_exit(ret ? ret : i);
	return (ret ? ret : i);
}  /* asm_complete_ios_thunk() */

#endif  /* BITS_PER_LONG == 64 */


static int asm_fill_timeout(struct timespec *ts, unsigned long timeout,
			    int bpl)
{
	struct timespec __user *ut = (struct timespec __user *)timeout;

#if (BITS_PER_LONG == 64) && defined(CONFIG_COMPAT)
	struct compat_timespec __user *cut =
		(struct compat_timespec __user *)timeout;

	/* We open-code get_compat_timespec() because it's not exported */
	if (bpl == ASM_BPL_32)
		return (!access_ok(VERIFY_READ, cut,
				   sizeof(*cut)) ||
			__get_user(ts->tv_sec, &cut->tv_sec) ||
			__get_user(ts->tv_nsec, &cut->tv_nsec)) ? -EFAULT : 0;

#endif  /* BITS_PER_LONG == 64 && defined(CONFIG_COMPAT) */

	return copy_from_user(ts, ut, sizeof(struct timespec));
}

static int asm_do_io(struct file *file, struct oracleasm_io_v2 *io,
		     int bpl)
{
	int ret = 0;
	u32 status = 0;
	struct timeout to;

	mlog_entry("(0x%p, 0x%p, %d)\n", file, io, bpl);

	init_timeout(&to);

	if (io->io_timeout) {
		struct timespec ts;

		mlog(ML_ABI, "Passed timeout 0x%"MLFu64"\n",
		     io->io_timeout);
		ret = -EFAULT;
		if (asm_fill_timeout(&ts, (unsigned long)(io->io_timeout),
				     bpl))
			goto out;

		set_timeout(&to, &ts);
		if (to.timed_out) {
			io->io_timeout = (u64)0;
			clear_timeout(&to);
		}
	}

	ret = 0;
	if (io->io_requests) {
		mlog(ML_ABI,
		     "oracleasm_io_v2 has requests; reqlen %d\n",
		     io->io_reqlen);
		ret = -EINVAL;
		if (bpl == ASM_BPL_32)
			ret = asm_submit_io_32(file, io);
#if BITS_PER_LONG == 64
		else if (bpl == ASM_BPL_64)
			ret = asm_submit_io_64(file, io);
#endif  /* BITS_PER_LONG == 64 */

		if (ret)
			goto out_to;
	}

	if (io->io_waitreqs) {
		mlog(ML_ABI, "oracleasm_io_v2 has waits; waitlen %d\n",
		     io->io_waitlen);
		ret = -EINVAL;
		if (bpl == ASM_BPL_32)
			ret = asm_maybe_wait_io_32(file, io, &to);
#if BITS_PER_LONG == 64
		else if (bpl == ASM_BPL_64)
			ret = asm_maybe_wait_io_64(file, io, &to);
#endif  /* BITS_PER_LONG == 64 */

		if (ret)
			goto out_to;

		status |= ASM_IO_WAITED;
	}

	if (io->io_completions) {
		mlog(ML_ABI,
		     "oracleasm_io_v2 has completes; complen %d\n",
		     io->io_complen);
		ret = -EINVAL;
		if (bpl == ASM_BPL_32)
			ret = asm_complete_ios_32(file, io, &to,
						  &status);
#if BITS_PER_LONG == 64
		else if (bpl == ASM_BPL_64)
			ret = asm_complete_ios_64(file, io, &to,
						  &status);
#endif  /* BITS_PER_LONG == 64 */

		if (ret < 0)
			goto out_to;
		if (ret >= io->io_complen)
			status |= ASM_IO_FULL;
		ret = 0;
	}

out_to:
	if (io->io_timeout)
		clear_timeout(&to);

out:
	if (put_user(status, (u32 *)(unsigned long)(io->io_statusp)))
		ret = -EFAULT;
	mlog_exit(ret);
	return ret;
}  /* asm_do_io() */

static void asm_cleanup_bios(struct file *file)
{
	struct asmfs_file_info *afi = ASMFS_FILE(file);
	struct bio *bio;

	mlog_entry("(0x%p)\n", file);

	spin_lock_irq(&afi->f_lock);
	while (afi->f_bio_free) {
		bio = afi->f_bio_free;
		afi->f_bio_free = bio->bi_private;

		spin_unlock_irq(&afi->f_lock);
		mlog(ML_BIO, "Unmapping bio 0x%p\n", bio);
		asm_integrity_unmap(bio);
		bio_unmap_user(bio);
		spin_lock_irq(&afi->f_lock);
	}
	spin_unlock_irq(&afi->f_lock);

	mlog_exit_void();
}

static int asmfs_file_open(struct inode * inode, struct file * file)
{
	struct asmfs_inode_info * aii;
	struct asmfs_file_info * afi;

	mlog_entry("(0x%p, 0x%p)\n", inode, file);

	mlog_bug_on_msg(ASMFS_FILE(file),
			"Trying to reopen filp 0x%p\n", file);

	mlog(ML_ABI, "Opening filp 0x%p\n", file);
	afi = (struct asmfs_file_info *)kmalloc(sizeof(*afi),
						GFP_KERNEL);
	if (!afi) {
		mlog_exit(-ENOMEM);
		return -ENOMEM;
	}

	afi->f_file = file;
	afi->f_bio_free = NULL;
	spin_lock_init(&afi->f_lock);
	INIT_LIST_HEAD(&afi->f_ctx);
	INIT_LIST_HEAD(&afi->f_disks);
	INIT_LIST_HEAD(&afi->f_ios);
	INIT_LIST_HEAD(&afi->f_complete);
	init_waitqueue_head(&afi->f_wait);

	aii = ASMFS_I(ASMFS_F2I(file));
	spin_lock_irq(&aii->i_lock);
	list_add(&afi->f_ctx, &aii->i_threads);
	spin_unlock_irq(&aii->i_lock);

	file->private_data = afi;

	mlog(ML_ABI, "Filp 0x%p has afi 0x%p\n", file, afi);

	mlog_exit(0);
	return 0;
}  /* asmfs_file_open() */


static int asmfs_file_release(struct inode *inode, struct file *file)
{
	struct asmfs_inode_info *aii;
	struct asmfs_file_info *afi;
	struct asm_disk_head *h, *n;
	struct list_head *p;
	struct asm_disk_info *d;
	struct asm_request *r;
	struct task_struct *tsk = current;
	DECLARE_WAITQUEUE(wait, tsk);

	mlog_entry("(0x%p, 0x%p)\n", inode, file);

	aii = ASMFS_I(ASMFS_F2I(file));
	afi = ASMFS_FILE(file);

	mlog(ML_ABI, "Release for filp 0x%p (afi = 0x%p)\n", file, afi);

	/*
	 * Shouldn't need the lock, no one else has a reference
	 * asm_close_disk will need to take it when completing I/O
	 */
	list_for_each_entry_safe(h, n, &afi->f_disks, h_flist) {
		d = h->h_disk;
		asm_close_disk(file, (unsigned long)d->d_bdev);
	}

	/* FIXME: Clean up things that hang off of afi */

	spin_lock_irq(&aii->i_lock);
	list_del(&afi->f_ctx);
	spin_unlock_irq(&aii->i_lock);

	/* No need for a fastpath */
	add_wait_queue(&afi->f_wait, &wait);
	do {
		struct block_device *bdev;
		struct asm_disk_info *d;
		struct inode *disk_inode;
		struct asmdisk_find_inode_args args;

		set_task_state(tsk, TASK_UNINTERRUPTIBLE);

		spin_lock_irq(&afi->f_lock);
		if (list_empty(&afi->f_ios))
		    break;

		bdev = find_io_bdev(file);
		spin_unlock_irq(&afi->f_lock);

		args.fa_handle = (unsigned long)bdev;
		args.fa_inode = aii;
		disk_inode = ilookup5(asmdisk_mnt->mnt_sb,
				      (unsigned long)bdev,
				      asmdisk_test, &args);
		if (disk_inode) {
			d = ASMDISK_I(disk_inode);
			iput(&d->vfs_inode);
		}

		mlog(ML_ABI|ML_REQUEST,
		     "There are still I/Os hanging off of afi 0x%p\n",
		     afi);
		io_schedule();
	} while (1);
	set_task_state(tsk, TASK_RUNNING);
	remove_wait_queue(&afi->f_wait, &wait);

	/* I don't *think* we need the lock here anymore, but... */

	/* Clear unreaped I/Os */
	while (!list_empty(&afi->f_complete)) {
		p = afi->f_complete.prev;
		r = list_entry(p, struct asm_request, r_list);
		list_del(&r->r_list);
		r->r_file = NULL;
		asm_request_free(r);
	}
	spin_unlock_irq(&afi->f_lock);

	/* And cleanup any pages from those I/Os */
	asm_cleanup_bios(file);

	mlog(ML_ABI, "Done with afi 0x%p from filp 0x%p\n", afi, file);
	file->private_data = NULL;
	kfree(afi);

	mlog_exit(0);
	return 0;
}  /* asmfs_file_release() */

/*
 * Verify that the magic and ABI versions are valid.  Future
 * drivers might support more than one ABI version, so ESRCH is returned
 * for "valid ABI version not found"
 */
static int asmfs_verify_abi(struct oracleasm_abi_info *abi_info)
{
	if (abi_info->ai_magic != ASM_ABI_MAGIC)
		return -EBADR;
	if (abi_info->ai_version != ASM_ABI_VERSION)
		return -ESRCH;

	return 0;
}

static ssize_t asmfs_svc_query_version(struct file *file, char *buf, size_t size)
{
	struct oracleasm_abi_info *abi_info;
	int ret;

	mlog_entry("(0x%p, 0x%p, %u)\n", file, buf, (unsigned int)size);

	if (size != sizeof(struct oracleasm_abi_info)) {
		mlog_exit(-EINVAL);
		return -EINVAL;
	}

       	abi_info = (struct oracleasm_abi_info *)buf;

	ret = asmfs_verify_abi(abi_info);
	if (ret) {
	       	if (ret == -ESRCH) {
			abi_info->ai_version = ASM_ABI_VERSION;
			abi_info->ai_status = -ESRCH;
		} else
			goto out;
	}

	ret = -EBADR;
	if (abi_info->ai_size != sizeof(struct oracleasm_abi_info))
		goto out;
	ret = -EBADRQC;
	if (abi_info->ai_type != ASMOP_QUERY_VERSION)
		goto out;

	ret = 0;

out:
	if (!abi_info->ai_status)
		abi_info->ai_status = ret;

	mlog_exit(size);
	return size;
}

static ssize_t asmfs_svc_get_iid(struct file *file, char *buf, size_t size)
{
	struct oracleasm_get_iid_v2 *iid_info;
	struct asmfs_sb_info *asb = ASMFS_SB(ASMFS_F2I(file)->i_sb);
	int ret;

	mlog_entry("(0x%p, 0x%p, %u)\n", file, buf, (unsigned int)size);

	if (size != sizeof(struct oracleasm_get_iid_v2)) {
		mlog_exit(-EINVAL);
		return -EINVAL;
	}

	iid_info = (struct oracleasm_get_iid_v2 *)buf;

	ret = asmfs_verify_abi(&iid_info->gi_abi);
	if (ret)
		goto out;
	ret = -EBADR;
	if (iid_info->gi_abi.ai_size !=
	    sizeof(struct oracleasm_get_iid_v2))
		goto out;
	ret = -EBADRQC;
	if (iid_info->gi_abi.ai_type != ASMOP_GET_IID)
		goto out;

	spin_lock_irq(&asb->asmfs_lock);
	iid_info->gi_iid = (u64)asb->next_iid;
	asb->next_iid++;
	spin_unlock_irq(&asb->asmfs_lock);

	ret = 0;

out:
	iid_info->gi_abi.ai_status = ret;

	mlog_exit(size);
	return size;
}

static ssize_t asmfs_svc_check_iid(struct file *file, char *buf, size_t size)
{
	struct oracleasm_get_iid_v2 *iid_info;
	struct asmfs_sb_info *asb = ASMFS_SB(ASMFS_F2I(file)->i_sb);
	int ret;

	mlog_entry("(0x%p, 0x%p, %u)\n", file, buf, (unsigned int)size);

	if (size != sizeof(struct oracleasm_get_iid_v2)) {
		mlog_exit(-EINVAL);
		return -EINVAL;
	}

	iid_info = (struct oracleasm_get_iid_v2 *)buf;

	ret = asmfs_verify_abi(&iid_info->gi_abi);
	if (ret)
		goto out;

	ret = -EBADR;
	if (iid_info->gi_abi.ai_size !=
	    sizeof(struct oracleasm_get_iid_v2))
		goto out;
	ret = -EBADRQC;
	if (iid_info->gi_abi.ai_type != ASMOP_CHECK_IID)
		goto out;

	spin_lock_irq(&asb->asmfs_lock);
	if (iid_info->gi_iid >= (u64)asb->next_iid)
		iid_info->gi_iid = (u64)0;
	spin_unlock_irq(&asb->asmfs_lock);

	ret = 0;

out:
	iid_info->gi_abi.ai_status = ret;

	mlog_exit(size);
	return size;
}

static ssize_t asmfs_svc_query_disk(struct file *file, char *buf, size_t size)
{
	struct oracleasm_query_disk_v2 *qd_info;
	struct file *filp;
	struct block_device *bdev;
	int ret;

	mlog_entry("(0x%p, 0x%p, %u)\n", file, buf, (unsigned int)size);

	if (size != sizeof(struct oracleasm_query_disk_v2)) {
		mlog_exit(-EINVAL);
		return -EINVAL;
	}

	qd_info = (struct oracleasm_query_disk_v2 *)buf;

	ret = asmfs_verify_abi(&qd_info->qd_abi);
	if (ret)
		goto out;

	ret = -EBADR;
	if (qd_info->qd_abi.ai_size !=
	    sizeof(struct oracleasm_query_disk_v2))
		goto out;
	ret = -EBADRQC;
	if (qd_info->qd_abi.ai_type != ASMOP_QUERY_DISK)
		goto out;

	ret = -ENODEV;
	filp = fget(qd_info->qd_fd);
	if (!filp)
		goto out;

	ret = -ENOTBLK;
	if (!S_ISBLK(filp->f_mapping->host->i_mode))
		goto out_put;

	bdev = I_BDEV(filp->f_mapping->host);

	qd_info->qd_max_sectors = compute_max_sectors(bdev);
	qd_info->qd_hardsect_size = bdev_physical_block_size(bdev);
	qd_info->qd_feature = asm_integrity_format(bdev) &
		ASM_INTEGRITY_QDF_MASK;
	mlog(ML_ABI|ML_DISK,
	     "Querydisk returning qd_max_sectors = %u and "
	     "qd_hardsect_size = %u, qd_integrity = %u\n",
	     qd_info->qd_max_sectors, qd_info->qd_hardsect_size,
	     asm_integrity_format(bdev));

	ret = 0;

out_put:
	fput(filp);

out:
	qd_info->qd_abi.ai_status = ret;

	mlog_exit(size);
	return size;
}

static ssize_t asmfs_svc_open_disk(struct file *file, char *buf, size_t size)
{
	struct oracleasm_open_disk_v2 od_info;
	struct block_device *bdev = NULL;
	struct file *filp;
	int ret;

	mlog_entry("(0x%p, 0x%p, %u)\n", file, buf, (unsigned int)size);

	if (size != sizeof(struct oracleasm_open_disk_v2)) {
		mlog_exit(-EINVAL);
		return -EINVAL;
	}

	if (copy_from_user(&od_info,
			   (struct oracleasm_open_disk_v2 __user *)buf,
			   sizeof(struct oracleasm_open_disk_v2))) {
		mlog_exit(-EFAULT);
		return -EFAULT;
	}

	od_info.od_handle = 0; /* Unopened */

	ret = asmfs_verify_abi(&od_info.od_abi);
	if (ret)
		goto out_error;

	ret = -EBADR;
	if (od_info.od_abi.ai_size !=
	    sizeof(struct oracleasm_open_disk_v2))
		goto out_error;
	ret = -EBADRQC;
	if (od_info.od_abi.ai_type != ASMOP_OPEN_DISK)
		goto out_error;

	ret = -ENODEV;
	filp = fget(od_info.od_fd);
	if (!filp)
		goto out_error;

	if (igrab(filp->f_mapping->host)) {
		ret = -ENOTBLK;
		if (S_ISBLK(filp->f_mapping->host->i_mode)) {
			bdev = I_BDEV(filp->f_mapping->host);

			ret = asm_open_disk(file, bdev);
		}
	}
	fput(filp);
	if (ret)
		goto out_error;

	od_info.od_handle = (u64)(unsigned long)bdev;
out_error:
	od_info.od_abi.ai_status = ret;
	if (copy_to_user((struct oracleasm_open_disk_v2 __user *)buf,
			 &od_info,
			 sizeof(struct oracleasm_open_disk_v2))) {
		if (od_info.od_handle)
			asm_close_disk(file,
				       (unsigned long)od_info.od_handle);
		/* Ignore close errors, this is the real error */
		mlog_exit(-EFAULT);
		return -EFAULT;
	}

	mlog_exit(size);
	return size;
}

static ssize_t asmfs_svc_close_disk(struct file *file, char *buf, size_t size)
{
	struct oracleasm_close_disk_v2 cd_info;
	int ret;

	mlog_entry("(0x%p, 0x%p, %u)\n", file, buf, (unsigned int)size);

	if (size != sizeof(struct oracleasm_close_disk_v2)) {
		mlog_exit(-EINVAL);
		return -EINVAL;
	}

	if (copy_from_user(&cd_info,
			   (struct oracleasm_close_disk_v2 __user *)buf,
			   sizeof(struct oracleasm_close_disk_v2))) {
		mlog_exit(-EFAULT);
		return -EFAULT;
	}

	ret = asmfs_verify_abi(&cd_info.cd_abi);
	if (ret)
		goto out_error;

	ret = -EBADR;
	if (cd_info.cd_abi.ai_size !=
	    sizeof(struct oracleasm_close_disk_v2))
		goto out_error;
	ret = -EBADRQC;
	if (cd_info.cd_abi.ai_type != ASMOP_CLOSE_DISK)
		goto out_error;

	ret = asm_close_disk(file, (unsigned long)cd_info.cd_handle);

out_error:
	cd_info.cd_abi.ai_status = ret;
	if (copy_to_user((struct oracleasm_close_disk_v2 __user *)buf,
			 &cd_info,
			 sizeof(struct oracleasm_close_disk_v2))) {
		mlog_exit(-EFAULT);
		return -EFAULT;
	}

	mlog_exit(size);
	return size;
}

static ssize_t asmfs_svc_io32(struct file *file, char *buf, size_t size)
{
	struct oracleasm_abi_info __user *user_abi_info;
	struct oracleasm_io_v2 io_info;
	int ret;

	mlog_entry("(0x%p, 0x%p, %u)\n", file, buf, (unsigned int)size);

	if (size != sizeof(struct oracleasm_io_v2)) {
		mlog_exit(-EINVAL);
		return -EINVAL;
	}

	if (copy_from_user(&io_info,
			   (struct oracleasm_io_v2 __user *)buf,
			   sizeof(struct oracleasm_io_v2))) {
		mlog_exit(-EFAULT);
		return -EFAULT;
	}

	ret = asmfs_verify_abi(&io_info.io_abi);
	if (ret)
		goto out_error;

	ret = -EBADR;
	if (io_info.io_abi.ai_size !=
	    sizeof(struct oracleasm_io_v2))
		goto out_error;
	ret = -EBADRQC;
	if (io_info.io_abi.ai_type != ASMOP_IO32)
		goto out_error;

#if (BITS_PER_LONG == 64) && !defined(CONFIG_COMPAT)
	ret = -EINVAL;
#else
	ret = asm_do_io(file, &io_info, ASM_BPL_32);
#endif  /* (BITS_PER_LONG == 64) && !defined(CONFIG_COMPAT) */

out_error:
	user_abi_info = (struct oracleasm_abi_info __user *)buf;
	if (put_user(ret, &(user_abi_info->ai_status))) {
		mlog_exit(-EFAULT);
		return -EFAULT;
	}

	mlog_exit(size);
	return size;
}

#if BITS_PER_LONG == 64
static ssize_t asmfs_svc_io64(struct file *file, char *buf, size_t size)
{
	struct oracleasm_abi_info __user *user_abi_info;
	struct oracleasm_io_v2 io_info;
	int ret;

	mlog_entry("(0x%p, 0x%p, %u)\n", file, buf, (unsigned int)size);

	if (size != sizeof(struct oracleasm_io_v2)) {
		mlog_exit(-EINVAL);
		return -EINVAL;
	}

	if (copy_from_user(&io_info,
			   (struct oracleasm_io_v2 __user *)buf,
			   sizeof(struct oracleasm_io_v2))) {
		mlog_exit(-EFAULT);
		return -EFAULT;
	}

	ret = asmfs_verify_abi(&io_info.io_abi);
	if (ret)
		goto out_error;

	ret = -EBADR;
	if (io_info.io_abi.ai_size !=
	    sizeof(struct oracleasm_io_v2))
		goto out_error;
	ret = -EBADRQC;
	if (io_info.io_abi.ai_type != ASMOP_IO64)
		goto out_error;

	ret = asm_do_io(file, &io_info, ASM_BPL_64);

out_error:
	user_abi_info = (struct oracleasm_abi_info __user *)buf;
	if (put_user(ret, &(user_abi_info->ai_status))) {
		mlog_exit(-EFAULT);
		return -EFAULT;
	}

	mlog_exit(size);
	return size;
}
#endif  /* BITS_PER_LONG == 64 */


/*
 * Because each of these operations need to access the filp->private,
 * we must multiplex.
 */
static ssize_t asmfs_file_read(struct file *file, char *buf, size_t size, loff_t *pos)
{
	struct oracleasm_abi_info __user *user_abi_info;
	ssize_t ret;
	int op;

	asm_cleanup_bios(file);

	user_abi_info = (struct oracleasm_abi_info __user *)buf;
	if (get_user(op, &((user_abi_info)->ai_type))) {
		mlog_exit(-EFAULT);
		return -EFAULT;
	}

	switch (op) {
		default:
			ret = -EBADRQC;
			break;

		case ASMOP_OPEN_DISK:
			ret = asmfs_svc_open_disk(file, (char *)buf,
						  size);
			break;

		case ASMOP_CLOSE_DISK:
			ret = asmfs_svc_close_disk(file, (char *)buf,
						   size);
			break;

		case ASMOP_IO32:
			ret = asmfs_svc_io32(file, (char *)buf, size);
			break;

#if BITS_PER_LONG == 64
		case ASMOP_IO64:
			ret = asmfs_svc_io64(file, (char *)buf, size);
			break;
#endif  /* BITS_PER_LONG == 64 */
	}

	return ret;
}

static struct file_operations asmfs_file_operations = {
	.open		= asmfs_file_open,
	.release	= asmfs_file_release,
	.read		= asmfs_file_read,
};

static struct inode_operations asmfs_file_inode_operations = {
	.getattr	= simple_getattr,
};

/*  See init_asmfs_dir_operations() */
static struct file_operations asmfs_dir_operations = {0, };

static struct inode_operations asmfs_disk_dir_inode_operations = {
	.lookup		= simple_lookup,
	.unlink		= simple_unlink,
	.mknod		= asmfs_mknod,
};
static struct inode_operations asmfs_iid_dir_inode_operations = {
	.create		= asmfs_create,
	.lookup		= simple_lookup,
	.unlink		= simple_unlink,
};

static struct super_operations asmfs_ops = {
	.statfs		= simple_statfs,
	.alloc_inode	= asmfs_alloc_inode,
	.destroy_inode	= asmfs_destroy_inode,
	.drop_inode	= generic_delete_inode,
	/* These last three only required for limited maxinstances */
	.put_super	= asmfs_put_super,
	.remount_fs     = asmfs_remount,
};

/*
 * Initialisation
 */

static int asmfs_fill_super(struct super_block *sb,
			    void *data, int silent)
{
	struct inode *inode, *parent;
	struct dentry *root, *dentry;
	struct asmfs_sb_info *asb;
	struct asmfs_params params;
	struct qstr name;

	sb->s_blocksize = PAGE_CACHE_SIZE;
	sb->s_blocksize_bits = PAGE_CACHE_SHIFT;
	sb->s_magic = ASMFS_MAGIC;
	sb->s_op = &asmfs_ops;
	sb->s_maxbytes = MAX_NON_LFS;	/* Why? */

	asb = kmalloc(sizeof(struct asmfs_sb_info), GFP_KERNEL);
	if (!asb)
		return -ENOMEM;
	sb->s_fs_info = asb;

	asb->asmfs_super = sb;
	asb->next_iid = 1;
	spin_lock_init(&asb->asmfs_lock);

	if (parse_options((char *)data, &params) != 0)
		goto out_free_asb;

	init_limits(asb, &params);

	inode = new_inode(sb);
	if (!inode)
		goto out_free_asb;

	inode->i_ino = (unsigned long)inode;
	inode->i_mode = S_IFDIR | 0755;
	inode->i_uid = inode->i_gid = 0;
	set_i_blksize(inode, PAGE_CACHE_SIZE);
	inode->i_blocks = 0;
	inode->i_rdev = 0;
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	inode->i_op = &simple_dir_inode_operations;
	inode->i_fop = &asmfs_dir_operations;
	inode->i_mapping->backing_dev_info = &memory_backing_dev_info;
	/* directory inodes start off with i_nlink == 2 (for "." entry) */
	inode->i_nlink++;
	parent = inode;

	root = d_alloc_root(inode);
	if (!root) {
		iput(inode);
		goto out_free_asb;
	}

	name.name = ASM_MANAGER_DISKS;
	name.len = strlen(ASM_MANAGER_DISKS);
	name.hash = full_name_hash(name.name, name.len);
	dentry = d_alloc(root, &name);
	if (!dentry)
		goto out_genocide;
	parent->i_nlink++;
	inode = new_inode(sb);
	if (!inode)
		goto out_genocide;
	inode->i_ino = (unsigned long)inode;
	inode->i_mode = S_IFDIR | 0755;
	inode->i_uid = inode->i_gid = 0;
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	inode->i_op = &asmfs_disk_dir_inode_operations;
	inode->i_fop = &asmfs_dir_operations;
	inode->i_mapping->backing_dev_info = &memory_backing_dev_info;
	d_add(dentry, inode);

	name.name = ASM_MANAGER_INSTANCES;
	name.len = strlen(ASM_MANAGER_INSTANCES);
	name.hash = full_name_hash(name.name, name.len);
	dentry = d_alloc(root, &name);
	if (!dentry)
		goto out_genocide;
	parent->i_nlink++;
	inode = new_inode(sb);
	if (!inode)
		goto out_genocide;
	inode->i_ino = (unsigned long)inode;
	inode->i_mode = S_IFDIR | 0770;
	inode->i_uid = inode->i_gid = 0;
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	inode->i_op = &asmfs_iid_dir_inode_operations;
	inode->i_fop = &asmfs_dir_operations;
	inode->i_mapping->backing_dev_info = &memory_backing_dev_info;
	d_add(dentry, inode);

	name.name = asm_operation_files[ASMOP_QUERY_VERSION];
	name.len = strlen(asm_operation_files[ASMOP_QUERY_VERSION]);
	name.hash = full_name_hash(name.name, name.len);
	dentry = d_alloc(root, &name);
	if (!dentry)
		goto out_genocide;
	inode = new_transaction_inode(sb, 0770,
				      &trans_contexts[ASMOP_QUERY_VERSION]);
	if (!inode)
		goto out_genocide;
	inode->i_mapping->backing_dev_info = &memory_backing_dev_info;
	d_add(dentry, inode);

	name.name = asm_operation_files[ASMOP_GET_IID];
	name.len = strlen(asm_operation_files[ASMOP_GET_IID]);
	name.hash = full_name_hash(name.name, name.len);
	dentry = d_alloc(root, &name);
	if (!dentry)
		goto out_genocide;
	inode = new_transaction_inode(sb, 0770,
				      &trans_contexts[ASMOP_GET_IID]);
	if (!inode)
		goto out_genocide;
	inode->i_mapping->backing_dev_info = &memory_backing_dev_info;
	d_add(dentry, inode);

	name.name = asm_operation_files[ASMOP_CHECK_IID];
	name.len = strlen(asm_operation_files[ASMOP_CHECK_IID]);
	name.hash = full_name_hash(name.name, name.len);
	dentry = d_alloc(root, &name);
	if (!dentry)
		goto out_genocide;
	inode = new_transaction_inode(sb, 0770,
				      &trans_contexts[ASMOP_CHECK_IID]);
	if (!inode)
		goto out_genocide;
	inode->i_mapping->backing_dev_info = &memory_backing_dev_info;
	d_add(dentry, inode);

	name.name = asm_operation_files[ASMOP_QUERY_DISK];
	name.len = strlen(asm_operation_files[ASMOP_QUERY_DISK]);
	name.hash = full_name_hash(name.name, name.len);
	dentry = d_alloc(root, &name);
	if (!dentry)
		goto out_genocide;
	inode = new_transaction_inode(sb, 0770,
				      &trans_contexts[ASMOP_QUERY_DISK]);
	if (!inode)
		goto out_genocide;
	inode->i_mapping->backing_dev_info = &memory_backing_dev_info;
	d_add(dentry, inode);

	sb->s_root = root;


	printk(KERN_DEBUG "ASM: oracleasmfs mounted with options: %s\n",
	       data ? (char *)data : "<defaults>" );
	printk(KERN_DEBUG "ASM:	maxinstances=%ld\n", asb->max_inodes);
	return 0;

out_genocide:
	d_genocide(root);
	dput(root);

out_free_asb:
	sb->s_fs_info = NULL;
	kfree(asb);

	return -EINVAL;
}


/*
 * We want all the simple_dir_operations, but we cannot reference them
 * directly -- they are not EXPORT_SYMBOL()d.  So, we just copy the
 * exported simple_dir_operations before adding any specific functions
 * of our own.
 *
 * This means that asmfs_dir_operations can't be const.  Oh, well.
 */
static void __init init_asmfs_dir_operations(void) {
	asmfs_dir_operations		= simple_dir_operations;
	asmfs_dir_operations.fsync	= noop_fsync;
};

static struct dentry *asmfs_mount(struct file_system_type *fs_type,
				       int flags, const char *dev_name,
				       void *data)
{
	return mount_nodev(fs_type, flags, data, asmfs_fill_super);
}

static struct file_system_type asmfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "oracleasmfs",
	.mount		= asmfs_mount,
	.kill_sb	= kill_litter_super,
};

static int __init init_asmfs_fs(void)
{
	int ret;

	ret = init_inodecache();
	if (ret) {
		printk("oracleasmfs: Unable to create asmfs_inode_cache\n");
		goto out_inodecache;
	}

	ret = init_requestcache();
	if (ret) {
		printk("oracleasmfs: Unable to create asm_request cache\n");
		goto out_requestcache;
	}

	ret = init_asmdiskcache();
	if (ret) {
		printk("oracleasmfs: Unable to initialize the disk cache\n");
		goto out_diskcache;
	}

	ret = init_oracleasm_proc();
	if (ret) {
		printk("oracleasmfs: Unable to register proc entries\n");
		goto out_proc;
	}

	init_asmfs_dir_operations();
	ret = register_filesystem(&asmfs_fs_type);
	if (ret) {
		printk("oracleasmfs: Unable to register filesystem\n");
		goto out_register;
	}

	return 0;

out_register:
	exit_oracleasm_proc();

out_proc:
	destroy_asmdiskcache();

out_diskcache:
	destroy_requestcache();

out_requestcache:
	destroy_inodecache();

out_inodecache:
	return ret;
}

static void __exit exit_asmfs_fs(void)
{
	unregister_filesystem(&asmfs_fs_type);
	exit_oracleasm_proc();
	destroy_asmdiskcache();
	destroy_requestcache();
	destroy_inodecache();
}

module_init(init_asmfs_fs)
module_exit(exit_asmfs_fs)
MODULE_LICENSE("GPL");
MODULE_VERSION(ASM_MODULE_VERSION);
MODULE_AUTHOR("Joel Becker <joel.becker@oracle.com>");
MODULE_DESCRIPTION("Kernel driver backing the Generic Linux ASM Library.");
