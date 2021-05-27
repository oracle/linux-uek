// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/arm-smccc.h>

/* Default size */
#define MIN_USERDEF_PRESERVE_MEMSZ	16 /* in MB, 16MB is minimum */
#define MAX_USERDEF_PRESERVE_MEMSZ	1024 /* in MB, 1GB is maximum */

/* SMC function id to update persistent memory */
#define PLAT_OCTEONTX_PERSIST_DATA_COMMAND	0xc2000b0d
/* Arg 0: UPDATE_USERDEF_PRESERVE_MEMSZ, Update user defined
 *	preserve memory size
 * Arg 1: Size of the preserved memory size
 */
#define UPDATE_USERDEF_PRESERVE_MEMSZ		1

static u32 preserve_mem_size = MIN_USERDEF_PRESERVE_MEMSZ;
static struct dentry *preserve_mem_root;

static int otx_debugfs_open(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t otx_debugfs_read(struct file *f, char __user *user_buf,
		size_t count, loff_t *off)
{
	char *buf = (char *)&preserve_mem_size;
	ssize_t out;

	out = simple_read_from_buffer(user_buf, count, off,
			buf, sizeof(preserve_mem_size));

	return out;
}

static ssize_t otx_debugfs_write(struct file *f, const char __user *user_buf,
		size_t count, loff_t *off)
{
	struct arm_smccc_res res;
	unsigned long function_id, arg0, arg1;
	u32 value;
	ssize_t rc;
	char buf[20];

	if (count > sizeof(buf) - 1)
		goto ret_err;

	if (copy_from_user(buf, user_buf, count))
		goto ret_err;

	buf[count] = 0;

	rc = kstrtouint(buf, 10, &value);
	if (rc)
		return rc;

	/* size should be multiples of 16 in MB */
	if ((value < MIN_USERDEF_PRESERVE_MEMSZ) || (value > MAX_USERDEF_PRESERVE_MEMSZ)
		|| (value % MIN_USERDEF_PRESERVE_MEMSZ))
		goto ret_err;

	preserve_mem_size = value;

	function_id = PLAT_OCTEONTX_PERSIST_DATA_COMMAND;
	arg0 = UPDATE_USERDEF_PRESERVE_MEMSZ;
	arg1 = preserve_mem_size;

	/* Secure firmware call to update the size of user defined memory */
	arm_smccc_smc(function_id, arg0, arg1, 0, 0, 0, 0, 0, &res);
	return count;

ret_err:
	pr_err("Invalid size, valid values: min 16, max 1024, multiples of 16\n");
	return -EINVAL;
}

static const struct file_operations otx_debugfs_fops = {
	.open = otx_debugfs_open,
	.read = otx_debugfs_read,
	.write = otx_debugfs_write,
};

/* module init */
static int __init otx_rpram_init(void)
{
	struct dentry *root, *entry;

	/* root directory : rpram */
	root = debugfs_create_dir("rpram", NULL);
	if (!root) {
		pr_err("rpram debugfs creation failed\n");
		return -ENOMEM;
	}

	preserve_mem_root = root;

	/* root/preserve_memsz_inMB creation */
	entry = debugfs_create_file("preserve_memsz_inMB", 0600, root,
			&preserve_mem_size, &otx_debugfs_fops);

	if (!entry) {
		pr_err("rpram->preserve_memsz_inMB debugfs file creation failed\n");
		return -ENOMEM;
	}

	return 0;
}

/* module exit */
static void __exit otx_rpram_exit(void)
{
	if (preserve_mem_root != NULL)
		debugfs_remove_recursive(preserve_mem_root);
}

module_init(otx_rpram_init);
module_exit(otx_rpram_exit);

MODULE_DESCRIPTION("Marvell driver for managing rpram");
MODULE_AUTHOR("Jayanthi Annadurai <jannadurai@marvell.com>");
MODULE_LICENSE("GPL");
