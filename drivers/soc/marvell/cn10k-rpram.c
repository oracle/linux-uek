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
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/arm-smccc.h>
#include <soc/marvell/octeontx/octeontx_smc.h>

/* Minimum size in MB, 0 means region is disabled
 * 16 MB is the minimum size when it is eanbled.
 */
#define MIN_USERDEF_PRESERVE_MEMSZ	0

/* Maximum size is 1GB */
#define MAX_USERDEF_PRESERVE_MEMSZ	1024

/* Region size must be multiples of 16 MB */
#define PRESERVE_MEMSZ_ALIGN		16

/* SMC function id to check the platform type is CN10K */
#define ARM_SMC_SVC_UID				0xc200ff01
/* SMC function id to update persistent memory */
#define PLAT_OCTEONTX_PERSIST_DATA_COMMAND	0xc2000b0d
/* Arg 0: UPDATE_USERDEF_PRESERVE_MEMSZ, Update user defined
 *	preserve memory size
 * Arg 1: Size of the preserved memory size
 */
#define UPDATE_USERDEF_PRESERVE_MEMSZ		1

static u32 current_rpram_size;
static u32 nextboot_rpram_size;
static u64 current_rpram_base;
static struct dentry *preserve_mem_root;
static const size_t len = PAGE_SIZE;

static ssize_t cn10k_rpram_info_read(struct file *f, char __user *user_buf,
		size_t count, loff_t *off)
{
	ssize_t out, pos = 0;
	unsigned long addr = get_zeroed_page(GFP_KERNEL);
	char *buf = (char *)addr;

	if (!buf)
		return -ENOMEM;

	pos += snprintf(buf+pos, len - pos, "RPRAM size %d MB @0x%llx\n",
		current_rpram_size, (unsigned long long) current_rpram_base);

	out = simple_read_from_buffer(user_buf, count, off,
			buf, pos);

	free_page(addr);
	return out;
}

static ssize_t cn10k_rpram_info_write(struct file *f, const char __user *user_buf,
		size_t count, loff_t *off)
{
	return 0;
}

static ssize_t cn10k_rpram_config_read(struct file *f, char __user *user_buf,
		size_t count, loff_t *off)
{
	ssize_t out, pos = 0;
	unsigned long addr = get_zeroed_page(GFP_KERNEL);
	char *buf = (char *)addr;

	if (!buf)
		return -ENOMEM;

	pos += snprintf(buf+pos, len - pos, "Next boot RPRAM size %d MB\n",
		nextboot_rpram_size);

	out = simple_read_from_buffer(user_buf, count, off,
			buf, pos);

	free_page(addr);
	return out;
}

static ssize_t cn10k_rpram_config_write(struct file *f, const char __user *user_buf,
		size_t count, loff_t *off)
{
	struct arm_smccc_res res;
	unsigned long function_id, arg0, arg1;
	int value;
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
		|| (value % PRESERVE_MEMSZ_ALIGN))
		goto ret_err;

	nextboot_rpram_size = value;

	function_id = PLAT_OCTEONTX_PERSIST_DATA_COMMAND;
	arg0 = UPDATE_USERDEF_PRESERVE_MEMSZ;
	arg1 = nextboot_rpram_size;

	/* Secure firmware call to update the size of user defined memory */
	arm_smccc_smc(function_id, arg0, arg1, 0, 0, 0, 0, 0, &res);
	return count;

ret_err:
	pr_err("Invalid size, max 1024, multiples of 16\n");
	return -EINVAL;
}

static const struct file_operations rpram_config_fops = {
	.read = cn10k_rpram_config_read,
	.write = cn10k_rpram_config_write,
};

static const struct file_operations rpram_currentsz_ops = {
	.read = cn10k_rpram_info_read,
	.write = cn10k_rpram_info_write,
};

/* module init */
static int __init cn10k_rpram_init(void)
{
	struct dentry *root, *entry;
	struct device_node *parent, *node;
	int ret;

	ret = octeontx_soc_check_smc();

	if (ret != 2) {
		pr_debug("%s: Not supported\n", __func__);
		return -EPERM;
	}

	parent = of_find_node_by_path("/reserved-memory");
	if (!parent) {
		current_rpram_size = 0;
	} else {
		for_each_child_of_node(parent, node) {
			const __be32 *prop;
			u64 size;

			if (of_node_name_prefix(node, "user-def")) {
				prop = of_get_property(node, "reg", NULL);
				if (!prop)
					break;
				current_rpram_base = be32_to_cpu(prop[1]) |
					(unsigned long long)be32_to_cpu(prop[0]) << 32;
				size = be32_to_cpu(prop[3]) |
					(unsigned long long)be32_to_cpu(prop[2]) << 32;
				current_rpram_size = size / 1024 / 1024;
			}
		}
	}

	/* root directory : rpram */
	root = debugfs_create_dir("rpram", NULL);
	if (!root) {
		pr_err("rpram debugfs creation failed\n");
		return -ENOMEM;
	}

	preserve_mem_root = root;
	nextboot_rpram_size = current_rpram_size;

	/* root/preserve_memsz_inMB creation */
	entry = debugfs_create_file("rpram_config_szMB", 0600, root,
			&nextboot_rpram_size, &rpram_config_fops);

	if (!entry) {
		pr_err("rpram->rpram_config_szMB debugfs file creation failed\n");
		debugfs_remove_recursive(preserve_mem_root);
		preserve_mem_root = NULL;
		return -ENOMEM;
	}

	entry = debugfs_create_file("rpram_info", 0444, root,
			&current_rpram_size, &rpram_currentsz_ops);

	if (!entry) {
		pr_err("rpram->rpram_info debugfs file creation failed\n");
		debugfs_remove_recursive(preserve_mem_root);
		preserve_mem_root = NULL;
		return -ENOMEM;
	}

	return 0;
}

/* module exit */
static void __exit cn10k_rpram_exit(void)
{
	if (preserve_mem_root != NULL)
		debugfs_remove_recursive(preserve_mem_root);
}

module_init(cn10k_rpram_init);
module_exit(cn10k_rpram_exit);

MODULE_DESCRIPTION("Marvell driver for managing rpram");
MODULE_AUTHOR("Jayanthi Annadurai <jannadurai@marvell.com>");
MODULE_LICENSE("GPL");
