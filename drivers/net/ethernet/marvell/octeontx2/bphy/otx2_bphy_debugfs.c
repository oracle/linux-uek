// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 BPHY RFOE/CPRI Ethernet Driver
 *
 * Copyright (C) 2021 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/debugfs.h>

#include "otx2_bphy_debugfs.h"
#include "otx2_bphy.h"

#define OTX2_BPHY_DEBUGFS_MODE 0400

struct otx2_bphy_debugfs_reader_info {
	atomic_t			refcnt;
	size_t				buffer_size;
	void				*priv;
	otx2_bphy_debugfs_reader	reader;
	struct dentry			*entry;
	char				buffer[1];
};

static struct dentry *otx2_bphy_debugfs;

static int otx2_bphy_debugfs_open(struct inode *inode, struct file *file);

static int otx2_bphy_debugfs_release(struct inode *inode, struct file *file);

static ssize_t otx2_bphy_debugfs_read(struct file *file, char __user *buffer,
				      size_t count, loff_t *offset);

static const struct file_operations otx2_bphy_debugfs_foper = {
	.owner		= THIS_MODULE,
	.open		= otx2_bphy_debugfs_open,
	.release	= otx2_bphy_debugfs_release,
	.read		= otx2_bphy_debugfs_read,
};

void __init otx2_bphy_debugfs_init(void)
{
	otx2_bphy_debugfs = debugfs_create_dir(DRV_NAME, NULL);
	if (!otx2_bphy_debugfs)
		pr_info("%s: debugfs is not enabled\n", DRV_NAME);
}

void *otx2_bphy_debugfs_add_file(const char *name,
				 size_t buffer_size,
				 void *priv,
				 otx2_bphy_debugfs_reader reader)
{
	struct otx2_bphy_debugfs_reader_info *info = NULL;
	size_t total_size = 0;

	if (!otx2_bphy_debugfs) {
		pr_info("%s: debugfs not enabled, ignoring %s\n", DRV_NAME,
			name);
		goto out;
	}

	total_size = buffer_size +
		offsetof(struct otx2_bphy_debugfs_reader_info,
			 buffer);

	info = kzalloc(total_size, GFP_KERNEL);

	if (!info)
		goto out;

	info->buffer_size = buffer_size;
	info->priv = priv;
	info->reader = reader;

	atomic_set(&info->refcnt, 0);

	info->entry = debugfs_create_file(name, OTX2_BPHY_DEBUGFS_MODE,
					  otx2_bphy_debugfs, info,
					  &otx2_bphy_debugfs_foper);

	if (!info->entry) {
		pr_err("%s: debugfs failed to add file %s\n", DRV_NAME, name);
		kfree(info);
		info = NULL;
		goto out;
	}

	pr_info("%s: debugfs created successfully for %s\n", DRV_NAME, name);

out:
	return info;
}

void otx2_bphy_debugfs_remove_file(void *entry)
{
	struct otx2_bphy_debugfs_reader_info *info = entry;

	debugfs_remove(info->entry);

	kfree(info);
}

void __exit otx2_bphy_debugfs_exit(void)
{
	debugfs_remove_recursive(otx2_bphy_debugfs);
}

static int otx2_bphy_debugfs_open(struct inode *inode, struct file *file)
{
	struct otx2_bphy_debugfs_reader_info *info = NULL;

	info = inode->i_private;

	if (!atomic_cmpxchg(&info->refcnt, 0, 1)) {
		file->private_data = info;
		return 0;
	}

	return -EBUSY;
}

static int otx2_bphy_debugfs_release(struct inode *inode, struct file *file)
{
	struct otx2_bphy_debugfs_reader_info *info = NULL;

	info = inode->i_private;

	atomic_cmpxchg(&info->refcnt, 1, 0);

	return 0;
}

static ssize_t otx2_bphy_debugfs_read(struct file *file, char __user *buffer,
				      size_t count, loff_t *offset)
{
	struct otx2_bphy_debugfs_reader_info *info = NULL;
	ssize_t retval = 0;

	info = file->private_data;

	if (!(*offset))
		info->reader(&info->buffer[0], info->buffer_size, info->priv);

	if (*offset >= info->buffer_size)
		goto out;

	if (*offset + count > info->buffer_size)
		count = info->buffer_size - *offset;

	if (copy_to_user((void __user *)buffer, info->buffer + *offset,
			 count)) {
		retval = -EFAULT;
		goto out;
	}

	*offset += count;
	retval = count;

out:
	return retval;
}
