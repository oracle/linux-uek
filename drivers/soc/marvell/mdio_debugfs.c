// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifdef CONFIG_DEBUG_FS

#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/arm-smccc.h>

#define OCTEONTX_MDIO_DBG_READ            0xc2000d01
#define OCTEONTX_MDIO_DBG_WRITE           0xc2000d02

struct dentry *pfile;
static int parse_cmd_buffer_ctx(char *cmd_buf, size_t *count,
				const char __user *buffer,
				int *a, bool *write)
{
	int bytes_not_copied;
	char *subtoken;
	int ret, i;

	bytes_not_copied = copy_from_user(cmd_buf, buffer, *count);
	if (bytes_not_copied)
		return -EFAULT;

	cmd_buf[*count] = '\0';
	for (i = 0; i < 5; i++) {
		subtoken = strsep(&cmd_buf, " ");
		ret = subtoken ? kstrtoint(subtoken, 10, &a[i]) : -EINVAL;
		if (ret < 0)
			return ret;
	}
	if (cmd_buf) {
		subtoken = strsep(&cmd_buf, " ");
		ret = subtoken ? kstrtoint(subtoken, 10, &a[i]) : -EINVAL;
		if (ret < 0)
			return ret;
		*write = true;
	}
	if (cmd_buf)
		return -EINVAL;
	return ret;
}

static ssize_t dbg_mdio_write(struct file *filp,
			      const char __user *buffer,
			      size_t count, loff_t *ppos)
{
	struct arm_smccc_res res;
	bool write = false;
	char *cmd_buf;
	int ret, a[6];

	if ((*ppos != 0) || !count)
		return -EINVAL;

	cmd_buf = kzalloc(count + 1, GFP_KERNEL);
	if (!cmd_buf)
		return count;

	ret = parse_cmd_buffer_ctx(cmd_buf, &count, buffer, a, &write);
	if (ret < 0) {
		pr_info("Usage: echo  <cgxlmac> <mode> <addr> <devad> <reg> [value] > mdio_cmd\n");
		goto done;
	} else {
		if (write)
			arm_smccc_smc(OCTEONTX_MDIO_DBG_WRITE, a[0], a[1], a[2],
				      a[3], a[4], a[5], 0, &res);
		else
			arm_smccc_smc(OCTEONTX_MDIO_DBG_READ, a[0], a[1], a[2],
				      a[3], a[4], 0, 0, &res);
		pr_info("MDIO COMMAND RESULT\n");
		pr_info("===================\n");
		pr_info("res[0]:\t%ld\n", res.a0);
		pr_info("res[1]:\t%ld\n", res.a1);
		pr_info("res[2]:\t%ld\n", res.a2);
		pr_info("res[3]:\t%ld\n", res.a3);
	}
done:
	kfree(cmd_buf);
	return ret ? ret : count;
}

static const struct file_operations dbg_mdio_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = dbg_mdio_write,
};

static int dbg_mdio_init(void)
{
	pfile = debugfs_create_file("mdio_cmd", 0644, NULL, NULL,
				    &dbg_mdio_fops);
	if (!pfile)
		goto create_failed;
	return 0;
create_failed:
	pr_err("Failed to create debugfs dir/file for mdio_cmd\n");
	debugfs_remove_recursive(pfile);
	return 0;
}

static void dbg_mdio_exit(void)
{
	debugfs_remove_recursive(pfile);
}
module_init(dbg_mdio_init);
module_exit(dbg_mdio_exit);
#endif /* CONFIG_DEBUG_FS */
