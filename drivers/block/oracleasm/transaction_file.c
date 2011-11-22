/* -*- mode: c; c-basic-offset: 8; -*-
 * vim: noexpandtab sw=8 ts=8 sts=0:
 *
 * transaction_file.c - Genericization of the transaction file
 * operations from linux/fs/nfsd/nfsctl.c
 *
 * Copyright (C) 2004 Oracle Corporation.  All rights reserved.
 *
 * linux/fs/nfsd/nfsctl.c
 * Copyright (C) 1995, 1996 Olaf Kirch <okir@monad.swb.de>
 */

#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/sched.h>

#include <asm/uaccess.h>

#include "transaction_file.h"
#include "compat.h"

#define TRANSACTION_CONTEXT(i) ((i)->i_private)

/* an argresp is stored in an allocated page and holds the 
 * size of the argument or response, along with its content
 */
struct argresp {
	ssize_t size;
	char data[0];
};

/*
 * transaction based IO methods.
 * The file expects a single write which triggers the transaction, and then
 * possibly a read which collects the result - which is stored in a 
 * file-local buffer.
 */
static ssize_t TA_write(struct file *file, const char *buf, size_t size, loff_t *pos)
{
	struct transaction_context *tctxt = TRANSACTION_CONTEXT(file->f_dentry->d_inode);
	struct argresp *ar;
	ssize_t rv = 0;

	if (!tctxt || !tctxt->write_op)
		return -EINVAL;
	if (file->private_data) 
		return -EINVAL; /* only one write allowed per open */
	if (size > PAGE_SIZE - sizeof(struct argresp))
		return -EFBIG;

	ar = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!ar)
		return -ENOMEM;
	ar->size = 0;
	mutex_lock(&file->f_dentry->d_inode->i_mutex);
	if (file->private_data)
		rv = -EINVAL;
	else
		file->private_data = ar;
	mutex_unlock(&file->f_dentry->d_inode->i_mutex);
	if (rv) {
		kfree(ar);
		return rv;
	}
	if (copy_from_user(ar->data, buf, size))
		return -EFAULT;
	
	rv =  tctxt->write_op(file, ar->data, size);
	if (rv>0) {
		ar->size = rv;
		rv = size;
	}
	return rv;
}


static ssize_t TA_read(struct file *file, char *buf, size_t size, loff_t *pos)
{
	struct argresp *ar;
	ssize_t rv = 0;
	
	if (file->private_data == NULL)
		rv = TA_write(file, buf, 0, pos);
	if (rv < 0)
		return rv;

	ar = file->private_data;
	if (!ar)
		return 0;
	if (*pos >= ar->size)
		return 0;
	if (*pos + size > ar->size)
		size = ar->size - *pos;
	if (copy_to_user(buf, ar->data + *pos, size))
		return -EFAULT;
	*pos += size;
	return size;
}

static int TA_open(struct inode *inode, struct file *file)
{
	file->private_data = NULL;
	return 0;
}

static int TA_release(struct inode *inode, struct file *file)
{
	void *p = file->private_data;
	file->private_data = NULL;
	kfree(p);
	return 0;
}

static struct file_operations transaction_ops = {
	.write		= TA_write,
	.read		= TA_read,
	.open		= TA_open,
	.release	= TA_release,
};


/*
 * Take an existing transaction inode (from simple_fill_super(), say)
 * and set up its transaction context.  If you need a new inode as
 * well, use new_transaction_inode().
 */
int init_transaction_inode(struct inode *inode, struct transaction_context *tctxt)
{

	if (!inode || !tctxt)
		return -EINVAL;

	TRANSACTION_CONTEXT(inode) = tctxt;

	return 0;
}

/*
 * Allocate a new transaction inode, filling in the transaction context.
 * If you already have an inode (say, from simple_fill_super()), you
 * want init_transaction_inode().
 */
struct inode *new_transaction_inode(struct super_block *sb, int mode, struct transaction_context *tctxt)
{
	struct inode *inode;

	inode = new_inode(sb);
	if (!inode)
		return NULL;
	inode->i_mode = S_IFREG | mode;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	set_i_blksize(inode, PAGE_CACHE_SIZE);
	inode->i_blocks = 0;
	inode->i_atime = inode->i_mtime = inode->i_ctime = CURRENT_TIME;
	inode->i_fop = &transaction_ops;
	inode->i_ino = (unsigned long)inode;

	init_transaction_inode(inode, tctxt);

	return inode;
}
