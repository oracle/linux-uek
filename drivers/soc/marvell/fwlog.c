// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021 Marvell.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/of.h>
#include <linux/of_fdt.h>

#define DEFAULT_FWLOG_MEMBASE	(60 * 1024 * 1024)
#define DEFAULT_FWLOG_MEMSIZE	(4 * 1024 * 1024)

static u64 fwlog_mem_base, fwlog_mem_size;
static char *fwlog_buf, *fwlog_mem;
static int dev_major;

struct fw_logbuf_header {
	u64 fwlog_base;
	u64 fwlog_end;
	u64 fwlog_ptr;
	u64 wraparound;
} __packed;

static ssize_t fwlogs_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
	char *rdbuf;
	int rdlen;
	struct fw_logbuf_header *fwlog_hdr = (struct fw_logbuf_header *)fwlog_mem;

	if (!fwlog_hdr->wraparound) {
		rdlen = fwlog_hdr->fwlog_ptr - fwlog_hdr->fwlog_base;
		if (*ppos >= rdlen)
			return 0;
		rdbuf = fwlog_buf + *ppos;
		rdlen -= *ppos;
	} else {
		/* If the buffer is wrappedaround , rdlen is always max buffer size */
		if (*ppos >= (fwlog_hdr->fwlog_end - fwlog_hdr->fwlog_base))
			return 0;

		/* adjust the bytes left to read */
		if (fwlog_hdr->fwlog_ptr + *ppos >= fwlog_hdr->fwlog_end)
			rdbuf = fwlog_buf + fwlog_hdr->fwlog_ptr + *ppos - fwlog_hdr->fwlog_end;
		else
			rdbuf = (char *)(fwlog_buf +
					(fwlog_hdr->fwlog_ptr - fwlog_hdr->fwlog_base) +
					*ppos);

		rdlen = fwlog_hdr->fwlog_end - fwlog_hdr->fwlog_base -
				max_t(size_t, rdbuf - fwlog_buf, *ppos);
	}

	count = min_t(size_t, count, rdlen);
	count = min_t(ssize_t, count, PAGE_SIZE);

	if (copy_to_user(buf, rdbuf, count))
		return -EFAULT;

	*ppos += count;

	return count;
}

static int fwlogs_open(struct inode *inode, struct file *filep)
{
	struct fw_logbuf_header *fwlog_hdr;

	fwlog_mem = memremap(fwlog_mem_base, fwlog_mem_size, MEMREMAP_WB);
	if (!fwlog_mem) {
		pr_err("Could not map FWLOG Memory\n");
		return -ENOMEM;
	}

	fwlog_hdr = (struct fw_logbuf_header *)fwlog_mem;
	fwlog_buf = fwlog_mem + sizeof(struct fw_logbuf_header);

	return 0;
}

static int fwlogs_release(struct inode *inode, struct file *filep)
{
	if (!fwlog_mem)
		memunmap((void *)fwlog_mem);

	return 0;
}

const struct file_operations fwlogs_ops = {
	.open = fwlogs_open,
	.read = fwlogs_read,
	.release = fwlogs_release,
};

struct fwifdev {
	const char *name;
	umode_t mode;
	const struct file_operations *fops;
};

static const struct fwifdev fwlog_dev = {
	.name = "fwlogs",
	.mode = 0644,
	.fops = &fwlogs_ops,
};

static int fwlog_dev_open(struct inode *inode, struct file *filp)
{
	int minor;
	const struct fwifdev *dev;

	minor = iminor(inode);
	if (minor < 0)
		return -ENXIO;

	dev = &fwlog_dev;
	filp->f_op = dev->fops;

	if (dev->fops->open)
		return dev->fops->open(inode, filp);

	return 0;
}

static const struct file_operations fwlog_dev_fops = {
	.open = fwlog_dev_open,
	.llseek = noop_llseek,
};

static char *fwlog_devnode(struct device *dev, umode_t *mode)
{
	if (mode && fwlog_dev.mode)
		*mode = fwlog_dev.mode;
	return NULL;
}

static struct class *fwif_class;

static int __init fwlog_dev_init(void)
{
	struct device_node *parent, *node;

	dev_major = register_chrdev(0, "fwif", &fwlog_dev_fops);

	parent = of_find_node_by_path("/reserved-memory");
	if (!parent) {
		unregister_chrdev(dev_major, "fwif");
	} else {
		for_each_child_of_node(parent, node) {
			const __be32 *prop;
			u64 size;

			if (of_node_name_prefix(node, "fwlogs")) {
				prop = of_get_property(node, "reg", NULL);
				if (!prop)
					break;
				fwlog_mem_base = be32_to_cpu(prop[1]) |
					(unsigned long long)be32_to_cpu(prop[0]) << 32;
				size = be32_to_cpu(prop[3]) |
					(unsigned long long)be32_to_cpu(prop[2]) << 32;
				if (fwlog_mem_base == 0ULL)
					fwlog_mem_base = DEFAULT_FWLOG_MEMBASE;

				if (size == 0ULL)
					size = DEFAULT_FWLOG_MEMSIZE;

				fwlog_mem_size = size;
			}
		}
	}

	fwif_class = class_create(THIS_MODULE, "fwif");
	if (IS_ERR(fwif_class)) {
		unregister_chrdev(dev_major, "fwif");
		return PTR_ERR(fwif_class);
	}

	fwif_class->devnode = fwlog_devnode;

	device_create(fwif_class, NULL, MKDEV(dev_major, 0),
		      NULL, fwlog_dev.name);

	return 0;
}

static void __exit fwlog_dev_exit(void)
{
	unregister_chrdev(dev_major, "fwif");
}

module_init(fwlog_dev_init);
module_exit(fwlog_dev_exit);
