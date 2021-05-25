// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Marvell
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/arm-smccc.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/debugfs.h>

#include "mrvl_swup.h"

/* Buffer for SMC call */
struct smc_version_info swup_info;
struct dentry *mrvl_swup_root;

/* IOCTL mapping to fw name */
const struct {
	const char *str;
	uint8_t bit;
} name_to_sel_obj[] = {
	{"tim0", 0},
	{"rom-script0.fw", 1},
	{"scp_bl1.bin", 2},
	{"mcp_bl1.bin", 3},
	{"ecp_bl1.bin", 4},
	{"init.bin", 5},
	{"gserm.fw", 6},
	{"bl2.bin", 7},
	{"bl31.bin", 8},
	{"u-boot-nodtb.bin", 9},
	{"npc_mkex-cn10xx.fw", 10},
	{"efi_app1.efi", 11},
	{"switch_fw_ap.fw", 12},
	{"switch_fw_super.fw", 13},
};

const char *obj_bit_to_str(uint32_t bit)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(name_to_sel_obj); i++) {
		if (name_to_sel_obj[i].bit == bit)
			return name_to_sel_obj[i].str;
	}
	return NULL;
}

/* Prepare objects for limited read */
void prepare_names(struct smc_version_info *info, uint32_t objects)
{
	int i;
	int obj_count = 0;
	const char *tmp = NULL;

	for (i = 0; i < SMC_MAX_VERSION_ENTRIES; i++) {
		if (objects & (1<<i)) {
			tmp = obj_bit_to_str((i));
			if (tmp == NULL) {
				pr_info("incorrect object selected!\n");
			} else {
				memcpy(info->objects[obj_count].name, tmp, VER_MAX_NAME_LENGTH);
				obj_count++;
			}
		}
	}
}

enum smc_version_entry_retcode get_version(unsigned long arg, uint8_t calculate_hash)
{
	int i, ret = 0;
	uint64_t x0_addr, x1_size;
	struct marlin_bootflash_get_versions *user_desc;
	struct arm_smccc_res res;

	user_desc = kzalloc(sizeof(struct marlin_bootflash_get_versions), GFP_KERNEL);
	if (!user_desc)
		return -ENOMEM;

	if (copy_from_user(user_desc,
			  (struct marlin_bootflash_get_versions *)arg,
			  sizeof(struct marlin_bootflash_get_versions))) {
		pr_err("Data Read Error\n");
		ret = -EFAULT;
		goto mem_error;
	}

	/* We have to perform conversion from IOCTL interface to smc */
	memset(&swup_info, 0x00, sizeof(struct smc_version_info));

	swup_info.magic_number = VERSION_MAGIC;
	swup_info.version      = VERSION_INFO_VERSION;
	swup_info.bus          = user_desc->bus;
	swup_info.cs           = user_desc->cs;

	if (calculate_hash)
		swup_info.version_flags |= SMC_VERSION_CHECK_VALIDATE_HASH;

	if (user_desc->version_flags & MARLIN_CHECK_PREDEFINED_OBJ) {
		swup_info.version_flags |= SMC_VERSION_CHECK_SPECIFIC_OBJECTS;
		prepare_names(&swup_info, user_desc->selected_objects);
		swup_info.num_objects = hweight_long(user_desc->selected_objects);
	} else {
		swup_info.num_objects = SMC_MAX_OBJECTS;
	}

	//SMC call
	x0_addr = virt_to_phys(&swup_info);
	x1_size = sizeof(swup_info);
	arm_smccc_smc(PLAT_CN10K_VERIFY_FIRMWARE, x0_addr, x1_size, 0, 0, 0, 0, 0, &res);

	if (res.a0) {
		pr_err("Error during SMC processing\n");
		ret = res.a0;
		goto mem_error;
	}

	user_desc->retcode = swup_info.retcode;
	for (i = 0; i < SMC_MAX_VERSION_ENTRIES; i++)
		memcpy(&user_desc->desc[i],
		       &swup_info.objects[i],
		       sizeof(struct smc_version_info_entry));

	if (copy_to_user((struct marlin_bootflash_get_versions *)arg,
			user_desc,
			sizeof(struct marlin_bootflash_get_versions))) {
		pr_err("Data Write Error\n");
		ret = -EFAULT;
	}

mem_error:
	kfree(user_desc);
	return ret;
}

static long mrvl_swup_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case GET_VERSION:
		return get_version(arg, 0);
	case VERIFY_HASH:
		return get_version(arg, 1);
	default:
		pr_err("Not supported IOCTL\n");
		return -ENXIO;
	}
	return 0;
}

static const struct file_operations mrvl_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl		= mrvl_swup_ioctl,
	.llseek			= no_llseek,
};

static int mrvl_swup_setup_debugfs(void)
{
	struct dentry *pfile;

	mrvl_swup_root = debugfs_create_dir("cn10k_swup", NULL);

	pfile = debugfs_create_file("verification", 0644, mrvl_swup_root, NULL,
				    &mrvl_fops);
	if (!pfile)
		goto create_failed;

	return 0;

create_failed:
	pr_err("Failed to create debugfs dir/file for firmware update\n");
	debugfs_remove_recursive(mrvl_swup_root);
	return 1;
}

static int __init mrvl_swup_init(void)
{
	return mrvl_swup_setup_debugfs();
}

static void __exit mrvl_swup_exit(void)
{
	debugfs_remove_recursive(mrvl_swup_root);
}

module_init(mrvl_swup_init)
module_exit(mrvl_swup_exit)

MODULE_DESCRIPTION("Marvell firmware update");
MODULE_AUTHOR("Witold Sadowski <wsadowski@marvell.com>");
MODULE_LICENSE("GPL");
