// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Marvell
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Module provides a simple sysfs interface to configure self test feature
 * for memory subsystem done at cold/warm boot.
 */

#define pr_fmt(fmt) "fw memtest: " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/spinlock.h>
#include <linux/arm-smccc.h>
#include <linux/firmware/octeontx2/mub.h>

/* SMC call used to communicate with ATF */
#define FWMT_OCTEONTX_MEM_TEST_CONFIG   0xc2000b15

/* SMC call first argument is type of operation */
enum fw_memtest_smc_op {
	FWMT_SO_GET = 0, /* Retrieve configuration */
	FWMT_SO_SET = 1, /* Set configuration */
	FWMT_SO_LAST
};

/* Type of the test, please keep it in sync with EBF. */
enum fw_memtest_test_type {
	FWMT_NONE = 0,
	FWMT_NOMINAL,
	FWMT_EXTENDED,
	FWMT_LAST
};

/* Test descriptor, keeps most important settings for the tests */
struct mub_fw_memtest_desc {
	uint32_t memory_length; /* Expressed in megabytes */
	uint32_t reboot;
	uint32_t power_on;

	spinlock_t lock; /* Keep data in sync */
	struct mub_device *device;
};
/* Use static storage */
static struct mub_fw_memtest_desc test_desc;

/* Lookup table to translate between user input and internal representation */
struct fw_memtest_entry {
	char const *name; /* Name of the memory test configuration */
	size_t sz; /* Size of the string used for memory test conf. */
	uint32_t idx; /* Index associated with the name */
};

/* Keep elements in the same order as fw_memtest_test_type items */
static const struct fw_memtest_entry xlat_tbl[] = {
	{ "none", sizeof("none") - 1, FWMT_NONE },
	{ "nominal", sizeof("nominal") - 1,  FWMT_NOMINAL },
	{ "extended", sizeof("extended") - 1, FWMT_EXTENDED },
	{ NULL, 0, FWMT_LAST }
};

static int fw_memtest_get_config(struct mub_fw_memtest_desc *desc)
{
	struct arm_smccc_res res;
	int ret;

	ret = mub_do_smc(desc->device,
			 FWMT_OCTEONTX_MEM_TEST_CONFIG, FWMT_SO_GET,
			 0, 0, 0, 0, 0, 0, &res);
	if (ret)
		return ret;

	if (res.a0)
		return (int)res.a0;

	spin_lock(&desc->lock);
	desc->reboot = (uint32_t)res.a1;
	desc->power_on = (uint32_t)res.a2;
	desc->memory_length = (uint32_t)res.a3;
	spin_unlock(&desc->lock);

	pr_debug("Values are reboot: %u, power_on: %u, memory_length: %u KB\n",
		 desc->reboot, desc->power_on, desc->memory_length);

	return 0;
}

static int fw_memtest_set_config(struct mub_fw_memtest_desc *desc)
{
	struct arm_smccc_res res;
	uint32_t reboot, power_on, memory_length;
	int ret;

	spin_lock(&desc->lock);
	reboot = desc->reboot;
	power_on = desc->power_on;
	memory_length = desc->memory_length;
	spin_unlock(&desc->lock);

	ret = mub_do_smc(desc->device,
			 FWMT_OCTEONTX_MEM_TEST_CONFIG, FWMT_SO_SET,
			 reboot, power_on, memory_length, 0, 0, 0, &res);
	if (ret)
		return ret;

	if (res.a0)
		return (int)res.a0;

	pr_debug("New values are reboot: %u, power_on: %u, memory_length: %u KB\n",
		 reboot, power_on, memory_length);
	return 0;
}

static ssize_t at_reboot_show(struct mub_device *dev, char *buf)
{
	const char *mt_name;
	struct mub_fw_memtest_desc *desc =
		(struct mub_fw_memtest_desc *)mub_get_data(dev);

	mt_name = desc->reboot < FWMT_LAST ?
		  xlat_tbl[desc->reboot].name : "unknown";

	return sysfs_emit(buf, "%s\n", mt_name);
}

static ssize_t at_reboot_store(struct mub_device *dev, const char *buf,
				   size_t count)
{
	struct mub_fw_memtest_desc *desc =
		(struct mub_fw_memtest_desc *)mub_get_data(dev);
	const struct fw_memtest_entry *e;
	size_t sz;
	int ret;

	e = &xlat_tbl[0];
	while (e != &xlat_tbl[ARRAY_SIZE(xlat_tbl) - 1]) {
		sz = count > e->sz ? e->sz : count;
		if (!strncmp(buf, e->name, sz))
			break;
		e++;
	}

	/* Are we looking at the sentinel? */
	if (!e->name && !e->sz)
		return -EINVAL;

	spin_lock(&desc->lock);
	desc->reboot = e->idx;
	spin_unlock(&desc->lock);

	ret = fw_memtest_set_config(desc);
	if (ret) {
		pr_warn("Firmware can't set memory test configuration. (%d)\n",
			ret);
		return ret;
	}

	pr_debug("reboot set to %s(%u)\n", e->name, e->idx);

	return count;
}
MUB_ATTR_RW(reboot, at_reboot_show, at_reboot_store);

static ssize_t poweron_show(struct mub_device *dev, char *buf)
{
	const char *mt_name;
	struct mub_fw_memtest_desc *desc =
		(struct mub_fw_memtest_desc *)mub_get_data(dev);

	mt_name = desc->power_on < FWMT_LAST ?
		  xlat_tbl[desc->power_on].name : "unknown";
	return sysfs_emit(buf, "%s\n", mt_name);
}

static ssize_t poweron_store(struct mub_device *dev, const char *buf,
			     size_t count)
{
	struct mub_fw_memtest_desc *desc =
		(struct mub_fw_memtest_desc *)mub_get_data(dev);
	const struct fw_memtest_entry *e;
	size_t sz;
	int ret;

	e = &xlat_tbl[0];
	while (e != &xlat_tbl[ARRAY_SIZE(xlat_tbl) - 1]) {
		sz = count > e->sz ? e->sz : count;
		if (!strncmp(buf, e->name, sz))
			break;
		e++;
	}

	/* Are we looking at the sentinel? */
	if (!e->name && !e->sz)
		return -EINVAL;

	spin_lock(&desc->lock);
	desc->power_on = e->idx;
	spin_unlock(&desc->lock);

	ret = fw_memtest_set_config(desc);
	if (ret) {
		pr_warn("Firmware can't set memory test configuration. (%d)\n",
			ret);
		return ret;
	}

	pr_debug("power_on set to %s(%u)\n", e->name, e->idx);

	return count;
}
MUB_ATTR_RW(power_on, poweron_show, poweron_store);

static ssize_t mem_length_show(struct mub_device *dev, char *buf)
{
	struct mub_fw_memtest_desc *desc =
		(struct mub_fw_memtest_desc *)mub_get_data(dev);

	return sysfs_emit(buf, "%u MB\n", desc->memory_length);
}

static ssize_t mem_length_store(struct mub_device *dev, const char *buf,
				size_t count)
{
	struct mub_fw_memtest_desc *desc =
		(struct mub_fw_memtest_desc *)mub_get_data(dev);
	unsigned long v;
	int ret;

	ret = kstrtoul(buf, 10, &v);
	if (ret < 0)
		return ret;

	spin_lock(&desc->lock);
	desc->memory_length = (uint32_t)(v & 0xffffffff); /* No overflow */
	spin_unlock(&desc->lock);

	ret = fw_memtest_set_config(desc);
	if (ret) {
		pr_warn("Firmware can't set memory test configuration. (%d)\n",
			ret);
		return ret;
	}

	pr_debug("memory_length: %u MB\n", desc->memory_length);

	return count;
}
MUB_ATTR_RW(mem_length, mem_length_show, mem_length_store);

static struct attribute *fw_memtest_attrs[] = {
	MUB_TO_ATTR(reboot),
	MUB_TO_ATTR(power_on),
	MUB_TO_ATTR(mem_length),
	NULL,
};

static const struct attribute_group fw_memtest_attr_group = {
	.attrs = fw_memtest_attrs,
};

static const struct attribute_group *fw_memtest_attr_groups[] = {
	&fw_memtest_attr_group,
	NULL,
};

static int __init fw_memtest_init(void)
{
	struct mub_fw_memtest_desc *desc;
	int ret;

	desc = &test_desc;
	desc->device = mub_device_register("memtest",
					   MUB_SOC_TYPE_10X | MUB_SOC_TYPE_ASIM,
					   fw_memtest_attr_groups);
	if (IS_ERR_OR_NULL(desc->device)) {
		if (!desc->device)
			return -EINVAL;
		return PTR_ERR(desc->device);
	}

	spin_lock_init(&desc->lock);
	mub_set_data(desc->device, desc);
	ret = fw_memtest_get_config(desc);
	if (ret) {
		pr_warn("Firmware can't get memory test configuration. (%d)\n",
			ret);
		mub_device_unregister(desc->device);
		return ret;
	}

	/* Check data validity */
	if (desc->reboot >= FWMT_LAST || desc->power_on >= FWMT_LAST)
		pr_info("Power on self test configuration for memory is not set!\n");

	return ret;
}
module_init(fw_memtest_init);

static void __exit fw_memtest_exit(void)
{
	struct mub_fw_memtest_desc *desc;

	desc = &test_desc;
	mub_device_unregister(desc->device);
}
module_exit(fw_memtest_exit);

MODULE_DESCRIPTION("Marvell CN10K memory test config. utility");
MODULE_AUTHOR("Wojciech Bartczak <wbartczak@marvell.com>");
MODULE_LICENSE("GPL");
