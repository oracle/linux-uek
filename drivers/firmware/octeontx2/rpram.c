// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021-2022  Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt)	"rpram: " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/of.h>
#include <linux/spinlock.h>
#include <linux/firmware/octeontx2/mub.h>

struct rpram_info {
	unsigned long long base;
	size_t size;
	size_t new_size;
	spinlock_t new_size_lock;
	/* Handle to the device */
	struct mub_device *dev;
};

/*
 * User defined preserve region size is between 16MB and 1GB.
 * Size 0 means the region is disabled.
 */
#define MAX_USERDEF_REG_SIZE	1024
#define USERDEF_REG_SIZE_STEP	16

/* Define megabyte */
#define MEGABYTE		(1ULL << 20)

/* Function to control persistent memory region.
 *
 * Arguments:
 *      update_flag, set to 1
 *      region size
 */
#define PLAT_OCTEONTX_PERSIST_DATA_COMMAND	0xc2000b0d

/* For simplicity, we could avoid kmalloc() */
static struct rpram_info rpram_info;

static ssize_t info_show(struct mub_device *dev, char *buf)
{
	struct rpram_info *info = (struct rpram_info *)mub_get_data(dev);

	return sysfs_emit(buf, "RPRAM size %llu MB @ %#llx\n",
			  info->size / MEGABYTE, info->base);
}

MUB_ATTR_RO(info, info_show);

static ssize_t config_show(struct mub_device *dev, char *buf)
{
	struct rpram_info *info = (struct rpram_info *)mub_get_data(dev);
	size_t new_size;

	spin_lock(&info->new_size_lock);
	new_size = info->new_size;
	spin_unlock(&info->new_size_lock);

	return sysfs_emit(buf, "Next boot RPRAM size %llu MB\n",
			  new_size / MEGABYTE);
}

static size_t config_store(struct mub_device *dev, const char *buf,
			   size_t count)
{
	struct rpram_info *info = (struct rpram_info *)mub_get_data(dev);
	struct arm_smccc_res res;
	unsigned int value;
	int ret;

	ret = kstrtouint(buf, 10, &value);
	if (ret)
		return ret;

	if (value > MAX_USERDEF_REG_SIZE || (value % USERDEF_REG_SIZE_STEP)) {
		pr_info("Value %u should be < 1024, must be multiple of 16\n",
			value);
		return -EINVAL;
	}

	ret = mub_do_smc(dev, PLAT_OCTEONTX_PERSIST_DATA_COMMAND,
			 1, value, 0, 0, 0, 0, 0, &res);
	if (!ret) {
		spin_lock(&info->new_size_lock);
		info->new_size = value * MEGABYTE;
		spin_unlock(&info->new_size_lock);
	}

	return ret ? ret : count;
}

MUB_ATTR_RW(config, config_show, config_store);

static struct attribute *rpram_attrs[] = {
	MUB_TO_ATTR(info),
	MUB_TO_ATTR(config),
	NULL,
};

static const struct attribute_group rpram_attrs_group = {
	.attrs = rpram_attrs,
};

static const struct attribute_group *rpram_attrs_groups[] = {
	&rpram_attrs_group,
	NULL,
};

/* Get user defined preserve region information.
 *
 * Returns: true when find, false otherwise.
 *
 */
static bool __init rpram_get_info(struct rpram_info *info)
{
	struct device_node *root, *it, *np;
	int aw, sw;  /* Address cell size, size cell size */
	const unsigned int *reg;

	root = of_find_node_by_path("/reserved-memory");
	if (!root)
		return false;
	/* Check for address and size of preserved region */
	aw = of_n_addr_cells(root);
	sw = of_n_size_cells(root);
	/* Try to find user-def@XXXX node in reserved-memory */
	np = NULL;
	for_each_child_of_node(root, it) {
		if (of_node_name_prefix(it, "user-def")) {
			np = it;
			break;
		}
	}
	/* No user defined preserved memory region */
	if (!np)
		goto not_found;

	reg = (const unsigned int *)of_get_property(np, "reg", NULL);
	if (!reg)
		goto not_found;

	info->base = of_read_number(reg, aw);
	reg += aw;
	info->size = of_read_number(reg, sw);

	of_node_put(root);
	return true;

not_found:
	of_node_put(root);
	return false;
}


static int __init rpram_init(void)
{
	struct rpram_info *info;

	info = &rpram_info;

	/* Initialize data lock */
	spin_lock_init(&info->new_size_lock);
	/* Ensure no random data */
	info->base = 0;
	info->size = 0;
	info->new_size = 0;

	if (!rpram_get_info(info))
		pr_debug("/reserved-memory/user-def has been not found!\n");
	/* Set the value to reflect the current setting, before first change */
	info->new_size = info->size;

	info->dev = mub_device_register("rpram", MUB_SOC_TYPE_10X,
					rpram_attrs_groups);
	if (IS_ERR(info->dev))
		return PTR_ERR(info->dev);

	mub_set_data(info->dev, info);

	return 0;
}
module_init(rpram_init);

static void __exit rpram_exit(void)
{
	struct rpram_info *info;

	info = &rpram_info;
	mub_device_unregister(info->dev);
}
module_exit(rpram_exit);

MODULE_DESCRIPTION("Marvell driver for managing rpram");
MODULE_AUTHOR("Jayanthi Annadurai <jannadurai@marvell.com>");
MODULE_LICENSE("GPL");
