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
#include <linux/pseudo_fs.h>
#include <linux/parser.h>
#include <linux/backing-dev.h>
#include <linux/compat.h>
#include <linux/log2.h>
#include <linux/bug.h>

#include <asm/uaccess.h>
#include <linux/spinlock.h>

#include "linux/oracleasm/compat32.h"
#include "linux/oracleasm/kernel.h"
#include "linux/oracleasm/abi.h"
#include "linux/oracleasm/disk.h"
#include "linux/oracleasm/manager.h"
#include "linux/oracleasm/error.h"

#include "linux/oracleasm/module_version.h"

#include "transaction_file.h"
#include "request.h"
#include "integrity.h"

#define CREATE_TRACE_POINTS
#include "trace.h"

#if PAGE_SIZE % 1024
#error Oh no, PAGE_SIZE is not divisible by 1k! I cannot cope.
#endif  /* PAGE_SIZE % 1024 */



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

static bool use_logical_block_size = false;
module_param(use_logical_block_size, bool, 0644);
MODULE_PARM_DESC(use_logical_block_size,
	"Prefer logical block size over physical (Y=logical, N=physical [default])");

static inline unsigned int asm_block_size(struct block_device *bdev)
{
	if (use_logical_block_size)
		return bdev_logical_block_size(bdev);

	return bdev_physical_block_size(bdev);
}

void asm_bio_unmap(struct bio *bio)
{
	struct bio_vec *bvec;
	struct bvec_iter_all iter_all;

	bio_for_each_segment_all(bvec, bio, iter_all) {
		if (bio_data_dir(bio) == READ)
			set_page_dirty_lock(bvec->bv_page);

		put_page(bvec->bv_page);
	}

	bio_put(bio);
	bio_put(bio);
}

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
	return file->f_path.dentry->d_inode;
}

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
static ssize_t asmfs_svc_query_handle(struct file *file, char *buf, size_t size);
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
	[ASMOP_QUERY_HANDLE]		= {asmfs_svc_query_handle},
};

static struct inode *asmdisk_alloc_inode(struct super_block *sb)
{
	struct asm_disk_info *d = kmem_cache_alloc(asmdisk_cachep, GFP_KERNEL);
	if (!d)
		return NULL;

	trace_disk(d, "alloc");
	return &d->vfs_inode;
}

static void asmdisk_destroy_inode(struct inode *inode)
{
	struct asm_disk_info *d = ASMDISK_I(inode);

	BUG_ON(atomic_read(&d->d_ios));
	BUG_ON(!list_empty(&d->d_open));

	trace_disk(d, "destroy");
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

	trace_disk(d, "evict");
	clear_inode(inode);

	BUG_ON(atomic_read(&d->d_ios));
	BUG_ON(!list_empty(&d->d_open));
	BUG_ON(d->d_live);

	if (d->d_bdev) {
		blkdev_put(d->d_bdev, FMODE_WRITE | FMODE_READ | FMODE_EXCL);
		d->d_bdev = NULL;
	}
}


static struct super_operations asmdisk_sops = {
	.statfs			= simple_statfs,
	.alloc_inode		= asmdisk_alloc_inode,
	.destroy_inode		= asmdisk_destroy_inode,
	.drop_inode		= generic_delete_inode,
	.evict_inode		= asmdisk_evict_inode,
};


static int asmdisk_init_fs_context(struct fs_context *fc)
{
	struct pseudo_fs_context *ctx = init_pseudo(fc, 0x61736D64);

	if (!ctx)
		return -ENOMEM;
	ctx->ops = &asmdisk_sops;

	return 0;
}

static struct file_system_type asmdisk_type = {
	.name		= "asmdisk",
	.kill_sb	= kill_anon_super,
	.init_fs_context = asmdisk_init_fs_context,
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
	kern_unmount(asmdisk_mnt);
	unregister_filesystem(&asmdisk_type);
	kmem_cache_destroy(asmdisk_cachep);
}

static int asmdisk_test(struct inode *inode, void *data)
{
	struct asmdisk_find_inode_args *args = data;
	struct asm_disk_info *d = ASMDISK_I(inode);
	unsigned long handle = (unsigned long)(d->d_bdev);

	return (d->d_inode == args->fa_inode) && (handle == args->fa_handle);
}

static int asmdisk_test_noinode(struct inode *inode, void *data)
{
	struct asmdisk_find_inode_args *args = data;
	struct asm_disk_info *d = ASMDISK_I(inode);
	unsigned long handle = (unsigned long)(d->d_bdev);

	return handle == args->fa_handle;
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
static int asmfs_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
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
	inode->i_blocks = 0;
	inode->i_rdev = 0;
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(dir);
	init_special_inode(inode, mode, dev);

	d_instantiate(dentry, inode);

	/* Extra count - pin the dentry in core */
	dget(dentry);

	return 0;
}

/*
 * Instance file creation in the iid directory.
 */
static int asmfs_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
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
	inode->i_blocks = 0;
	inode->i_rdev = 0;
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(dir);
	inode->i_op = &asmfs_file_inode_operations;
	inode->i_fop = &asmfs_file_operations;

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

	pr_debug("ASM: oracleasmfs remounted with options: %s\n",
		 data ? (char *)data : "<defaults>" );
	pr_debug("ASM:	maxinstances=%ld\n", asb->max_inodes);

	return 0;
}

/*
 * Compute the maximum number of sectors the bdev can handle in one bio,
 * as a power of two.
 */
static int compute_max_sectors(struct block_device *bdev)
{
	int max_pages, max_sectors, pow_two_sectors;

	struct request_queue *q;

	q = bdev_get_queue(bdev);
	max_pages = queue_max_sectors(q) >> (PAGE_SHIFT - 9);
	if (max_pages > BIO_MAX_PAGES)
		max_pages = BIO_MAX_PAGES;
	if (max_pages > queue_max_segments(q))
		max_pages = queue_max_segments(q);
	max_pages--; /* Handle I/Os that straddle a page */
	max_sectors = max_pages << (PAGE_SHIFT - 9);

	/* Why is fls() 1-based???? */
	pow_two_sectors = 1 << (fls(max_sectors) - 1);

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

	ret = blkdev_get(bdev, FMODE_WRITE | FMODE_READ | FMODE_EXCL, inode->i_sb);
	if (ret)
		goto out;

	ret = set_blocksize(bdev, asm_block_size(bdev));
	if (ret)
		goto out_get;

	ret = -ENOMEM;
	h = kmalloc(sizeof(struct asm_disk_head), GFP_KERNEL);
	if (!h)
		goto out_get;

	args.fa_handle = (unsigned long)bdev;
	args.fa_inode = ASMFS_I(inode);
	disk_inode = iget5_locked(asmdisk_mnt->mnt_sb,
				  (unsigned long)bdev, asmdisk_test,
				  asmdisk_set, &args);
	if (!disk_inode)
		goto out_head;

	d = ASMDISK_I(disk_inode);

	if (disk_inode->i_state & I_NEW) {
		struct backing_dev_info *bdi = inode_to_bdi(inode);

		bdi->ra_pages = 0;	/* No readahead */
		bdi->capabilities = BDI_CAP_NO_ACCT_DIRTY | BDI_CAP_NO_WRITEBACK;

		BUG_ON(atomic_read(&d->d_ios) != 0);
		BUG_ON(d->d_live);
		BUG_ON(d->d_bdev != bdev);

		d->d_max_sectors = compute_max_sectors(bdev);
		d->d_live = 1;

		unlock_new_inode(disk_inode);

		trace_disk(d, "open");
	} else {
		/* Already claimed on first open */
		blkdev_put(bdev, FMODE_WRITE | FMODE_READ | FMODE_EXCL);
		trace_disk(d, "reopen");
	}

	h->h_disk = d;
	h->h_file = ASMFS_FILE(file);

	spin_lock_irq(&ASMFS_FILE(file)->f_lock);
	list_add(&h->h_flist, &ASMFS_FILE(file)->f_disks);
	spin_unlock_irq(&ASMFS_FILE(file)->f_lock);

	spin_lock_irq(&ASMFS_I(inode)->i_lock);
	list_add(&h->h_dlist, &d->d_open);
	spin_unlock_irq(&ASMFS_I(inode)->i_lock);

	return 0;

out_head:
	kfree(h);

out_get:
	blkdev_put(bdev, FMODE_WRITE | FMODE_READ | FMODE_EXCL);

out:
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

	BUG_ON(!ASMFS_FILE(file) || !ASMFS_I(inode));

	args.fa_handle = handle;
	args.fa_inode = ASMFS_I(inode);
	disk_inode = ilookup5(asmdisk_mnt->mnt_sb, handle,
			      asmdisk_test, &args);
	if (!disk_inode)
		return -EINVAL;

	d = ASMDISK_I(disk_inode);
	bdev = d->d_bdev;

	trace_disk(d, "close");

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
		return -EINVAL;
	}
	list_del(&h->h_flist);
	spin_unlock_irq(&ASMFS_FILE(file)->f_lock);

	spin_lock_irq(&ASMFS_I(inode)->i_lock);
	list_del(&h->h_dlist);

	/* Last close */
	if (list_empty(&d->d_open)) {
		trace_disk(d, "last");
		BUG_ON(!d->d_live);
		d->d_live = 0;
		spin_unlock_irq(&ASMFS_I(inode)->i_lock);

		/* No need for a fast path */
		add_wait_queue(&ASMFS_FILE(file)->f_wait, &wait);
		do {
			set_current_state(TASK_UNINTERRUPTIBLE);

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
		set_current_state(TASK_RUNNING);
		remove_wait_queue(&ASMFS_FILE(file)->f_wait, &wait);
	}
	else
		spin_unlock_irq(&ASMFS_I(inode)->i_lock);

	kfree(h);

	/* Drop the ref from ilookup5() */
	iput(disk_inode);

	/* Real put */
	iput(disk_inode);

	return 0;
}  /* asm_close_disk() */


/* Timeout stuff ripped from aio.c - thanks Ben */
struct timeout {
	struct timer_list	timer;
	int			timed_out;
	wait_queue_head_t	wait;
};

static void timeout_func(struct timer_list *tl)
{
	struct timeout *to = from_timer(to, tl, timer);

	to->timed_out = 1;
	wake_up(&to->wait);
}

static inline void init_timeout(struct timeout *to)
{
	timer_setup(&to->timer, timeout_func, 0);
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

	ioc = r->r_ioc;

	/* Need to get the current userspace bits because ASM_CANCELLED is currently set there */
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

	if (put_user(copy.r_status, &(ioc->status_asm_ioc))) {
		ret = -EFAULT;
		goto out;
	}
	if (copy.r_status & ASM_ERROR) {
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
	if (copy.r_status & ASM_FREE) {
		u64 z = 0ULL;
		if (copy_to_user(&(ioc->reserved_asm_ioc),
				 &z, sizeof(ioc->reserved_asm_ioc))) {
			ret = -EFAULT;
			goto out;
		}
	} else if (copy.r_status & (ASM_SUBMITTED | ASM_ERROR)) {
		u64 key = (u64)(unsigned long)r;
		/* Only on first submit */
		if (copy_to_user(&(ioc->reserved_asm_ioc),
				 &key, sizeof(ioc->reserved_asm_ioc))) {
			ret = -EFAULT;
			goto out;
		}
	}

out:
	trace_ioc(ioc, ret, "update");
	return ret;
}  /* asm_update_user_ioc() */


static struct asm_request *asm_request_alloc(void)
{
	struct asm_request *r;

	r = kmem_cache_zalloc(asm_request_cachep, GFP_KERNEL);

	if (r)
		r->r_status = ASM_SUBMITTED;

	trace_req(r, 0, 0, "alloc");

	return r;
}  /* asm_request_alloc() */


static void asm_request_free(struct asm_request *r)
{
	trace_req(r, 0, 0, "free");

	kmem_cache_free(asm_request_cachep, r);
}  /* asm_request_free() */


static void asm_finish_io(struct asm_request *r)
{
	struct asm_disk_info *d;
	struct asmfs_file_info *afi = r->r_file;
	unsigned long flags;

	BUG_ON(!afi);

	trace_req(r, 0, 0, "finish");

	spin_lock_irqsave(&afi->f_lock, flags);

	if (r->r_bio) {
		trace_bio(r->r_bio, "freelist");
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
	r->r_elapsed = ((jiffies - r->r_elapsed) * 1000000) / HZ;

	spin_unlock_irqrestore(&afi->f_lock, flags);

	if (d) {
		atomic_dec(&d->d_ios);
		if (atomic_read(&d->d_ios) < 0) {
			pr_err("d_ios underflow on disk 0x%p (dev %X)\n",
			       d, d->d_bdev->bd_dev);
			atomic_set(&d->d_ios, 0);
		}
	}

	wake_up(&afi->f_wait);
}  /* asm_finish_io() */


static void asm_end_ioc(struct asm_request *r, unsigned int bytes_done,
			int status)
{
	int error = blk_status_to_errno(status);
	BUG_ON(!r);
	BUG_ON(!(r->r_status & ASM_SUBMITTED));

	trace_req(r, bytes_done, error, "end");

	switch (error) {
		default:
			pr_err("Invalid error of %d on request 0x%p!\n",
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
		case -ENODATA:
		case -EREMOTEIO:
			r->r_error = ASM_ERR_IO;
			break;

		case -EILSEQ:
			r->r_error = ASM_ERR_INTEGRITY;
			break;

		case -ENOLINK:
		case -EBADE:
		case -ENODEV:
		case -ENXIO:
			r->r_error = ASM_ERR_NODEV;
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
}  /* asm_end_ioc() */


static void asm_end_bio_io(struct bio *bio)
{
	struct asm_request *r;

	trace_bio(bio, "end_bio_io");

	r = bio->bi_private;

	if (atomic_dec_and_test(&r->r_bio_count)) {
		asm_end_ioc(r, r->r_count - (r->r_bio ?
					     r->r_bio->bi_iter.bi_size : 0),
			    bio->bi_status);
	}
}  /* asm_end_bio_io() */

static int asm_submit_io(struct file *file,
			 asm_ioc __user *user_iocp,
			 asm_ioc *ioc)
{
	int ret = 0, rw = REQ_OP_READ;
	struct inode *inode = ASMFS_F2I(file);
	struct asmdisk_find_inode_args args;
	struct asm_request *r;
	struct asm_disk_info *d;
	struct inode *disk_inode;
	struct block_device *bdev;
	struct oracleasm_integrity_v2 it;
	struct iov_iter iter;
	struct iovec iov;
	bool integrity = false;

	if (!ioc || ioc->status_asm_ioc)
		return -EINVAL;

	r = asm_request_alloc();
	if (!r) {
		u16 status = ASM_FREE | ASM_ERROR | ASM_LOCAL_ERROR | ASM_BUSY;

		if (put_user(status, &(user_iocp->status_asm_ioc)))
			return -EFAULT;

		if (put_user(ASM_ERR_NOMEM, &(user_iocp->error_asm_ioc)))
			return -EFAULT;

		return 0;
	}

	r->r_file = ASMFS_FILE(file);
	r->r_ioc = user_iocp;  /* Userspace asm_ioc */
	trace_req(r, 0, 0, "submit");

	spin_lock_irq(&ASMFS_FILE(file)->f_lock);
	list_add(&r->r_list, &ASMFS_FILE(file)->f_ios);
	spin_unlock_irq(&ASMFS_FILE(file)->f_lock);

	args.fa_handle = (unsigned long)ioc->disk_asm_ioc &
		~ASM_INTEGRITY_HANDLE_MASK;
	args.fa_inode = ASMFS_I(inode);
	disk_inode = ilookup5(asmdisk_mnt->mnt_sb,
			      (unsigned long)args.fa_handle,
			      asmdisk_test, &args);
	if (!disk_inode) {
		ret = -ENODEV;
		goto out_error;
	}

	spin_lock_irq(&ASMFS_I(inode)->i_lock);

	d = ASMDISK_I(disk_inode);
	if (!d->d_live) {
		/* It's in the middle of closing */
		spin_unlock_irq(&ASMFS_I(inode)->i_lock);
		iput(disk_inode);
		ret = -ENODEV;
		goto out_error;
	}

	atomic_inc(&d->d_ios);
	r->r_disk = d;

	spin_unlock_irq(&ASMFS_I(inode)->i_lock);
	iput(disk_inode);

	bdev = d->d_bdev;

	r->r_count = ioc->rcount_asm_ioc * asm_block_size(bdev);

	if (!ioc->buffer_asm_ioc ||
	    (ioc->buffer_asm_ioc != (unsigned long)ioc->buffer_asm_ioc) ||
	    (ioc->first_asm_ioc != (unsigned long)ioc->first_asm_ioc) ||
	    (ioc->rcount_asm_ioc != (unsigned long)ioc->rcount_asm_ioc) ||
	    (ioc->priority_asm_ioc > 7) ||
	    (r->r_count > (queue_max_sectors(bdev_get_queue(bdev)) << 9)) ||
	    (r->r_count < 0)) {
		ret = -EINVAL;
		goto out_error;
	}

	if (bdev_get_integrity(bdev) && ioc->check_asm_ioc) {

		if (copy_from_user(&it, (struct oracleasm_integrity_v2 *)
				   ioc->check_asm_ioc, sizeof(it))) {
			pr_err("%s: Failed to copy integrity descriptor\n",
			       __func__);
			ret = -EFAULT;
			goto out_error;
		}

		if (asm_integrity_check(&it, bdev) < 0) {
			ret = -EINVAL;
			goto out_error;
		}

		integrity = true;
	}

	switch (ioc->operation_asm_ioc) {
		default:
			goto out_error;
			break;

		case ASM_READ:
			rw = REQ_OP_READ;
			break;

		case ASM_WRITE:
			rw = REQ_OP_WRITE;
			break;

		case ASM_NOOP:
			/* Trigger an errorless completion */
			r->r_count = 0;
			goto out_error;
	}

	iov.iov_base = (void __user *)ioc->buffer_asm_ioc;
	iov.iov_len = r->r_count;
	iov_iter_init(&iter, rw, &iov, 1, r->r_count);
	r->r_bio = bio_map_user_iov(bdev_get_queue(bdev), &iter, GFP_KERNEL);

	if (IS_ERR(r->r_bio)) {
		ret = PTR_ERR(r->r_bio);
		r->r_bio = NULL;
		ret = -ENOMEM;
		goto out_error;
	}

	r->r_bio->bi_private = r;
	r->r_bio->bi_opf = rw;
	bio_set_dev(r->r_bio, bdev);

	if (r->r_bio->bi_iter.bi_size != r->r_count) {
		pr_err("%s: Only mapped partial ioc buffer\n", __func__);
		asm_bio_unmap(r->r_bio);
		r->r_bio = NULL;
		ret = -ENOMEM;
		goto out_error;
	}

	trace_bio(r->r_bio, "map");

	/* Block layer always uses 512-byte sector addressing,
	 * regardless of logical and physical block size.
	 */
	r->r_bio->bi_iter.bi_sector =
		ioc->first_asm_ioc * (asm_block_size(bdev) >> 9);

	if (integrity) {
		ret = asm_integrity_map(&it, r, rw == READ);

		if (ret < 0) {
			pr_err("%s: Could not attach integrity payload\n",
			       __func__);
			asm_bio_unmap(r->r_bio);
			ret = -ENOMEM;
			goto out_error;
		}
	}

	/*
	 * If the bio is a bounced bio, we have to put the
	 * end_io on the child "real" bio
	 */
	r->r_bio->bi_end_io = asm_end_bio_io;

	r->r_elapsed = jiffies;  /* Set start time */

	atomic_set(&r->r_bio_count, 1);

	submit_bio(r->r_bio);

out_error:
	if (ret)
		asm_end_ioc(r, 0, ret);
	else
		ret = asm_update_user_ioc(file, r);

	trace_ioc(ioc, ret, "submit");

	return ret;
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

	trace_ioc(iocp, 0, "maybe_wait");

	if (copy_from_user(&p, &(iocp->reserved_asm_ioc),
			   sizeof(p)))
		return -EFAULT;

	r = (struct asm_request *)(unsigned long)p;
	if (!r)
		return -EINVAL;

	spin_lock_irq(&afi->f_lock);
	/* Is it valid? It's surely ugly */
	if (!r->r_file || (r->r_file != afi) ||
	    list_empty(&r->r_list) || !(r->r_status & ASM_SUBMITTED)) {
		spin_unlock_irq(&afi->f_lock);
		return -EINVAL;
	}

	if (!(r->r_status & (ASM_COMPLETED | ASM_BUSY | ASM_ERROR))) {
		spin_unlock_irq(&afi->f_lock);
		add_wait_queue(&afi->f_wait, &wait);
		add_wait_queue(&to->wait, &to_wait);
		do {
			struct asm_disk_info *d;
			struct block_device *bdev = NULL;
			struct inode *disk_inode;

			ret = 0;
			set_current_state(TASK_INTERRUPTIBLE);

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
				ret = -EINTR;
				break;
			}
		} while (1);
		set_current_state(TASK_RUNNING);
		remove_wait_queue(&afi->f_wait, &wait);
		remove_wait_queue(&to->wait, &to_wait);

		if (ret)
			return ret;
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
		return 0;

	BUG_ON(list_empty(&afi->f_complete)); /* Completion list is empty */

	trace_req(r, 0, 0, "delist");
	list_del_init(&r->r_list);
	r->r_file = NULL;
	r->r_status |= ASM_FREE;

	spin_unlock_irq(&afi->f_lock);

	ret = asm_update_user_ioc(file, r);

	asm_request_free(r);

	return ret;
}  /* asm_maybe_wait_io() */


static int asm_complete_io(struct file *file,
			   asm_ioc **ioc)
{
	int ret = 0;
	struct list_head *l;
	struct asm_request *r;
	struct asmfs_file_info *afi = ASMFS_FILE(file);

	spin_lock_irq(&afi->f_lock);

	if (list_empty(&afi->f_complete)) {
		spin_unlock_irq(&afi->f_lock);
		*ioc = NULL;
		return 0;
	}

	l = afi->f_complete.prev;
	r = list_entry(l, struct asm_request, r_list);
	list_del_init(&r->r_list);
	r->r_file = NULL;
	r->r_status |= ASM_FREE;

	spin_unlock_irq(&afi->f_lock);

	*ioc = r->r_ioc;
	trace_ioc(r->r_ioc, 0, "complete");

	ret = asm_update_user_ioc(file, r);

	asm_request_free(r);

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
		set_current_state(TASK_INTERRUPTIBLE);

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
	set_current_state(TASK_RUNNING);
	remove_wait_queue(&afi->f_wait, &wait);
	remove_wait_queue(&to->wait, &to_wait);

out:
	return ret;
}  /* asm_wait_completion() */


static inline int asm_submit_io_native(struct file *file,
       				       struct oracleasm_io_v2 *io)
{
	int ret = 0;
	u32 i;
	asm_ioc *iocp;
	asm_ioc tmp;

	for (i = 0; i < io->io_reqlen; i++) {
		ret = -EFAULT;
		if (get_user(iocp,
			     ((asm_ioc **)((unsigned long)(io->io_requests))) + i))
			break;

		if (copy_from_user(&tmp, iocp, sizeof(tmp)))
			break;

		ret = asm_submit_io(file, iocp, &tmp);
		if (ret)
			break;
	}

	return ret;
}  /* asm_submit_io_native() */


static inline int asm_maybe_wait_io_native(struct file *file,
					   struct oracleasm_io_v2 *io,
					   struct timeout *to)
{
	int ret = 0;
	u32 i;
	asm_ioc *iocp;

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

	return (ret ? ret : i);
}  /* asm_complete_ios_native() */


#if BITS_PER_LONG == 64
static inline void asm_promote_64(asm_ioc64 *ioc)
{
	asm_ioc32 *ioc_32 = (asm_ioc32 *)ioc;

	/*
	 * Promote the 32bit pointers at the end of the asm_ioc32
	 * into the asm_ioc64.
	 *
	 * Promotion must be done from the tail backwards.
	 */
	ioc->check_asm_ioc = (u64)ioc_32->check_asm_ioc;
	ioc->buffer_asm_ioc = (u64)ioc_32->buffer_asm_ioc;
}  /* asm_promote_64() */


static inline int asm_submit_io_thunk(struct file *file,
	       			      struct oracleasm_io_v2 *io)
{
	int ret = 0;
	u32 i;
	u32 iocp_32;
	asm_ioc32 *iocp;
	asm_ioc tmp;

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

		ret = asm_submit_io(file, (asm_ioc *)iocp, &tmp);
		if (ret)
			break;
	}

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
		return (!access_ok(cut, sizeof(*cut)) ||
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

	init_timeout(&to);

	if (io->io_timeout) {
		struct timespec ts;

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
	return ret;
}  /* asm_do_io() */

static void asm_cleanup_bios(struct file *file)
{
	struct asmfs_file_info *afi = ASMFS_FILE(file);
	struct bio *bio;

	spin_lock_irq(&afi->f_lock);
	while (afi->f_bio_free) {
		bio = afi->f_bio_free;
		afi->f_bio_free = bio->bi_private;

		spin_unlock_irq(&afi->f_lock);
		trace_bio(bio, "unmap");
		asm_integrity_unmap(bio);
		asm_bio_unmap(bio);
		spin_lock_irq(&afi->f_lock);
	}
	spin_unlock_irq(&afi->f_lock);
}

static int asmfs_file_open(struct inode * inode, struct file * file)
{
	struct asmfs_inode_info * aii;
	struct asmfs_file_info *afi;

	BUG_ON(ASMFS_FILE(file));

	afi = (struct asmfs_file_info *)kmalloc(sizeof(*afi), GFP_KERNEL);
	if (!afi)
		return -ENOMEM;

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

	aii = ASMFS_I(ASMFS_F2I(file));
	afi = ASMFS_FILE(file);

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

		set_current_state(TASK_UNINTERRUPTIBLE);

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

		io_schedule();
	} while (1);
	set_current_state(TASK_RUNNING);
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

	file->private_data = NULL;
	kfree(afi);

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

	if (size != sizeof(struct oracleasm_abi_info))
		return -EINVAL;

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

	return size;
}

static ssize_t asmfs_svc_get_iid(struct file *file, char *buf, size_t size)
{
	struct oracleasm_get_iid_v2 *iid_info;
	struct asmfs_sb_info *asb = ASMFS_SB(ASMFS_F2I(file)->i_sb);
	int ret;

	if (size != sizeof(struct oracleasm_get_iid_v2))
		return -EINVAL;

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

	return size;
}

static ssize_t asmfs_svc_check_iid(struct file *file, char *buf, size_t size)
{
	struct oracleasm_get_iid_v2 *iid_info;
	struct asmfs_sb_info *asb = ASMFS_SB(ASMFS_F2I(file)->i_sb);
	int ret;

	if (size != sizeof(struct oracleasm_get_iid_v2))
		return -EINVAL;

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

	return size;
}

static ssize_t asmfs_svc_query_disk(struct file *file, char *buf, size_t size)
{
	struct oracleasm_query_disk_v2 *qd_info;
	struct file *filp;
	struct block_device *bdev;
	unsigned int lsecsz = 0;
	int ret;

	if (size != sizeof(struct oracleasm_query_disk_v2))
		return -EINVAL;

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
	qd_info->qd_hardsect_size = asm_block_size(bdev);
	qd_info->qd_feature = asm_integrity_format(bdev) &
		ASM_INTEGRITY_QDF_MASK;
	if (use_logical_block_size == false) {
		lsecsz = ilog2(bdev_logical_block_size(bdev));
		qd_info->qd_feature |= lsecsz << ASM_LSECSZ_SHIFT
			& ASM_LSECSZ_MASK;
	}

	trace_querydisk(bdev, qd_info);

	ret = 0;

out_put:
	fput(filp);

out:
	qd_info->qd_abi.ai_status = ret;

	return size;
}

static ssize_t asmfs_svc_open_disk(struct file *file, char *buf, size_t size)
{
	struct oracleasm_open_disk_v2 od_info;
	struct block_device *bdev = NULL;
	struct file *filp;
	int ret;

	if (size != sizeof(struct oracleasm_open_disk_v2))
		return -EINVAL;

	if (copy_from_user(&od_info,
			   (struct oracleasm_open_disk_v2 __user *)buf,
			   sizeof(struct oracleasm_open_disk_v2)))
		return -EFAULT;

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
		return -EFAULT;
	}

	return size;
}

static ssize_t asmfs_svc_close_disk(struct file *file, char *buf, size_t size)
{
	struct oracleasm_close_disk_v2 cd_info;
	int ret;

	if (size != sizeof(struct oracleasm_close_disk_v2))
		return -EINVAL;

	if (copy_from_user(&cd_info,
			   (struct oracleasm_close_disk_v2 __user *)buf,
			   sizeof(struct oracleasm_close_disk_v2)))
		return -EFAULT;

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
			 sizeof(struct oracleasm_close_disk_v2)))
		return -EFAULT;

	return size;
}

static ssize_t asmfs_svc_io32(struct file *file, char *buf, size_t size)
{
	struct oracleasm_abi_info __user *user_abi_info;
	struct oracleasm_io_v2 io_info;
	int ret;

	if (size != sizeof(struct oracleasm_io_v2))
		return -EINVAL;

	if (copy_from_user(&io_info,
			   (struct oracleasm_io_v2 __user *)buf,
			   sizeof(struct oracleasm_io_v2)))
		return -EFAULT;

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
	if (put_user(ret, &(user_abi_info->ai_status)))
		return -EFAULT;

	return size;
}

#if BITS_PER_LONG == 64
static ssize_t asmfs_svc_io64(struct file *file, char *buf, size_t size)
{
	struct oracleasm_abi_info __user *user_abi_info;
	struct oracleasm_io_v2 io_info;
	int ret;

	if (size != sizeof(struct oracleasm_io_v2))
		return -EINVAL;

	if (copy_from_user(&io_info,
			   (struct oracleasm_io_v2 __user *)buf,
			   sizeof(struct oracleasm_io_v2)))
		return -EFAULT;

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
	if (put_user(ret, &(user_abi_info->ai_status)))
		return -EFAULT;

	return size;
}
#endif  /* BITS_PER_LONG == 64 */


static ssize_t asmfs_svc_query_handle(struct file *file, char *buf, size_t size)
{
	struct oracleasm_query_handle_v2 *qh_info;
	struct asmdisk_find_inode_args args;
	struct inode *disk_inode;
	struct asm_disk_info *d;
	struct block_device *bdev;
	unsigned int lsecsz = 0;
	int ret;

	if (size != sizeof(struct oracleasm_query_handle_v2))
		return -EINVAL;

	qh_info = (struct oracleasm_query_handle_v2 *)buf;

	ret = asmfs_verify_abi(&qh_info->qh_abi);
	if (ret)
		goto out;

	ret = -EBADR;
	if (qh_info->qh_abi.ai_size != sizeof(struct oracleasm_query_handle_v2))
		goto out;

	ret = -EBADRQC;
	if (qh_info->qh_abi.ai_type != ASMOP_QUERY_HANDLE)
		goto out;

	args.fa_handle = (unsigned long)qh_info->qh_handle;
	args.fa_inode = 0;
	disk_inode = ilookup5(asmdisk_mnt->mnt_sb, qh_info->qh_handle,
			      asmdisk_test_noinode, &args);
	if (!disk_inode) {
		ret = -ENODEV;
		goto out;
	}

	d = ASMDISK_I(disk_inode);
	bdev = d->d_bdev;

	qh_info->qh_max_sectors = compute_max_sectors(bdev);
	qh_info->qh_hardsect_size = asm_block_size(bdev);
	qh_info->qh_feature = asm_integrity_format(bdev) & ASM_INTEGRITY_QDF_MASK;
	if (use_logical_block_size == false) {
		lsecsz = ilog2(bdev_logical_block_size(bdev));
		qh_info->qh_feature |= lsecsz << ASM_LSECSZ_SHIFT
			& ASM_LSECSZ_MASK;
	}

	trace_queryhandle(bdev, qh_info);
	ret = 0;

	/*
	 * Dropping the reference to disk_inode could result in d and
	 * disk_inode being evicted and freed. This will further drop the
	 * reference to bdev, which could be the last one. Thus, we must
	 * delay the iput() until all accesses to disk_inode, d, and bdev
	 * are complete.
	 */
	iput(disk_inode);

out:
	qh_info->qh_abi.ai_status = ret;
	return size;
}


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
	if (get_user(op, &((user_abi_info)->ai_type)))
		return -EFAULT;

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

		case ASMOP_QUERY_HANDLE:
			ret = asmfs_svc_query_handle(file, (char *)buf, size);
			break;
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

	sb->s_blocksize = PAGE_SIZE;
	sb->s_blocksize_bits = PAGE_SHIFT;
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
	inode->i_uid = GLOBAL_ROOT_UID;
	inode->i_gid = GLOBAL_ROOT_GID;
	inode->i_blocks = 0;
	inode->i_rdev = 0;
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
	inode->i_op = &simple_dir_inode_operations;
	inode->i_fop = &asmfs_dir_operations;
	/* directory inodes start off with i_nlink == 2 (for "." entry) */
	set_nlink(inode, inode->i_nlink + 1);
	parent = inode;

	root = d_make_root(inode);
	if (!root)
		goto out_free_asb;

	name.name = ASM_MANAGER_DISKS;
	name.len = strlen(ASM_MANAGER_DISKS);
	name.hash = full_name_hash(root, name.name, name.len);
	dentry = d_alloc(root, &name);
	if (!dentry)
		goto out_genocide;
	set_nlink(parent, parent->i_nlink + 1);
	inode = new_inode(sb);
	if (!inode)
		goto out_genocide;
	inode->i_ino = (unsigned long)inode;
	inode->i_mode = S_IFDIR | 0755;
	inode->i_uid = GLOBAL_ROOT_UID;
	inode->i_gid = GLOBAL_ROOT_GID;
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
	inode->i_op = &asmfs_disk_dir_inode_operations;
	inode->i_fop = &asmfs_dir_operations;
	d_add(dentry, inode);

	name.name = ASM_MANAGER_INSTANCES;
	name.len = strlen(ASM_MANAGER_INSTANCES);
	name.hash = full_name_hash(root, name.name, name.len);
	dentry = d_alloc(root, &name);
	if (!dentry)
		goto out_genocide;
	set_nlink(parent, parent->i_nlink + 1);
	inode = new_inode(sb);
	if (!inode)
		goto out_genocide;
	inode->i_ino = (unsigned long)inode;
	inode->i_mode = S_IFDIR | 0770;
	inode->i_uid = GLOBAL_ROOT_UID;
	inode->i_gid = GLOBAL_ROOT_GID;
	inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
	inode->i_op = &asmfs_iid_dir_inode_operations;
	inode->i_fop = &asmfs_dir_operations;
	d_add(dentry, inode);

	name.name = asm_operation_files[ASMOP_QUERY_VERSION];
	name.len = strlen(asm_operation_files[ASMOP_QUERY_VERSION]);
	name.hash = full_name_hash(root, name.name, name.len);
	dentry = d_alloc(root, &name);
	if (!dentry)
		goto out_genocide;
	inode = new_transaction_inode(sb, 0770,
				      &trans_contexts[ASMOP_QUERY_VERSION]);
	if (!inode)
		goto out_genocide;
	d_add(dentry, inode);

	name.name = asm_operation_files[ASMOP_GET_IID];
	name.len = strlen(asm_operation_files[ASMOP_GET_IID]);
	name.hash = full_name_hash(root, name.name, name.len);
	dentry = d_alloc(root, &name);
	if (!dentry)
		goto out_genocide;
	inode = new_transaction_inode(sb, 0770,
				      &trans_contexts[ASMOP_GET_IID]);
	if (!inode)
		goto out_genocide;
	d_add(dentry, inode);

	name.name = asm_operation_files[ASMOP_CHECK_IID];
	name.len = strlen(asm_operation_files[ASMOP_CHECK_IID]);
	name.hash = full_name_hash(root, name.name, name.len);
	dentry = d_alloc(root, &name);
	if (!dentry)
		goto out_genocide;
	inode = new_transaction_inode(sb, 0770,
				      &trans_contexts[ASMOP_CHECK_IID]);
	if (!inode)
		goto out_genocide;
	d_add(dentry, inode);

	name.name = asm_operation_files[ASMOP_QUERY_DISK];
	name.len = strlen(asm_operation_files[ASMOP_QUERY_DISK]);
	name.hash = full_name_hash(root, name.name, name.len);
	dentry = d_alloc(root, &name);
	if (!dentry)
		goto out_genocide;
	inode = new_transaction_inode(sb, 0770,
				      &trans_contexts[ASMOP_QUERY_DISK]);
	if (!inode)
		goto out_genocide;
	d_add(dentry, inode);

	name.name = asm_operation_files[ASMOP_QUERY_HANDLE];
	name.len = strlen(asm_operation_files[ASMOP_QUERY_HANDLE]);
	name.hash = full_name_hash(root, name.name, name.len);
	dentry = d_alloc(root, &name);
	if (!dentry)
		goto out_genocide;
	inode = new_transaction_inode(sb, 0770,
				      &trans_contexts[ASMOP_QUERY_HANDLE]);
	if (!inode)
		goto out_genocide;
	d_add(dentry, inode);

	sb->s_root = root;


	pr_debug("ASM: oracleasmfs mounted with options: %s\n",
		 data ? (char *)data : "<defaults>" );
	pr_debug("ASM: maxinstances=%ld\n", asb->max_inodes);
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
		pr_err("oracleasmfs: Unable to create asmfs_inode_cache\n");
		goto out_inodecache;
	}

	ret = init_requestcache();
	if (ret) {
		pr_err("oracleasmfs: Unable to create asm_request cache\n");
		goto out_requestcache;
	}

	ret = init_asmdiskcache();
	if (ret) {
		pr_err("oracleasmfs: Unable to initialize the disk cache\n");
		goto out_diskcache;
	}

	init_asmfs_dir_operations();
	ret = register_filesystem(&asmfs_fs_type);
	if (ret) {
		pr_err("oracleasmfs: Unable to register filesystem\n");
		goto out_register;
	}

	return 0;

out_register:
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
	destroy_asmdiskcache();
	destroy_requestcache();
	destroy_inodecache();
}

module_init(init_asmfs_fs)
module_exit(exit_asmfs_fs)
MODULE_LICENSE("GPL");
MODULE_VERSION(ASM_MODULE_VERSION);
MODULE_AUTHOR("Joel Becker, Martin K. Petersen <martin.petersen@oracle.com>");
MODULE_DESCRIPTION("Kernel driver backing the Generic Linux ASM Library.");
