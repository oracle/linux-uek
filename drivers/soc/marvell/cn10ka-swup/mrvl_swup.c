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

#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/device.h>

#include <soc/marvell/octeontx/octeontx_smc.h>
#include "mrvl_swup.h"

/*Debugfs interface root */;
struct dentry *mrvl_swup_root;

/* Buffers for SMC call
 * 0 -> 25MB for SW update CPIO blob
 * 1 -> 1MB for passing data structures
 */
#define BUF_CPIO 0
#define BUF_DATA 1
#define BUF_SIGNATURE 2
static struct memory_desc memdesc[] = {
	{0, 0, 25*1024*1024, "cpio buffer"},
	{0, 0, 1*1024*1024,  "data buffer"},
	{0, 0, 1*1024*1024,  "signature buffer"},
};

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

static void mrvl_fw_dev_release(struct device *dev)
{
	pr_info("releasing firmware device\n");
}

static struct device dev = {
	.release = mrvl_fw_dev_release
};


enum smc_version_entry_retcode mrvl_get_version(unsigned long arg, uint8_t calculate_hash)
{
	int i, ret = 0;
	uint64_t x0_addr, x1_size;
	struct marlin_bootflash_get_versions *user_desc;
	struct arm_smccc_res res;
	struct smc_version_info *swup_info = (struct smc_version_info *)memdesc[BUF_DATA].virt;

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
	memset(swup_info, 0x00, sizeof(struct smc_version_info));

	swup_info->magic_number = VERSION_MAGIC;
	swup_info->version      = VERSION_INFO_VERSION;
	swup_info->bus          = user_desc->bus;
	swup_info->cs           = user_desc->cs;

	if (calculate_hash)
		swup_info->version_flags |= SMC_VERSION_CHECK_VALIDATE_HASH;

	if (user_desc->version_flags & MARLIN_CHECK_PREDEFINED_OBJ) {
		swup_info->version_flags |= SMC_VERSION_CHECK_SPECIFIC_OBJECTS;
		prepare_names(swup_info, user_desc->selected_objects);
		swup_info->num_objects = hweight_long(user_desc->selected_objects);
	} else {
		swup_info->num_objects = SMC_MAX_OBJECTS;
	}

	//SMC call
	x0_addr = memdesc[BUF_DATA].phys;
	x1_size = sizeof(struct smc_version_info);

	arm_smccc_smc(PLAT_CN10K_VERIFY_FIRMWARE, x0_addr, x1_size, 0, 0, 0, 0, 0, &res);

	if (res.a0) {
		pr_err("Error during SMC processing\n");
		ret = res.a0;
		goto mem_error;
	}

	user_desc->retcode = swup_info->retcode;
	for (i = 0; i < SMC_MAX_VERSION_ENTRIES; i++)
		memcpy(&user_desc->desc[i],
		       &swup_info->objects[i],
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

static int mrvl_get_membuf(unsigned long arg)
{
	struct marlin_bootflash_phys_buffer buf;

	buf.cpio_buf = memdesc[BUF_CPIO].phys;
	buf.cpio_buf_size = memdesc[BUF_CPIO].size;
	buf.sign_buf = memdesc[BUF_SIGNATURE].phys;
	buf.sign_buf_size = memdesc[BUF_SIGNATURE].size;
	buf.reserved_buf = 0;
	buf.reserved_buf_size = 0;


	if (copy_to_user((struct marlin_bootflash_phys_buffer *)arg,
			  &buf,
			  sizeof(struct marlin_bootflash_phys_buffer))) {
		pr_err("Data Write Error\n");
		return -EFAULT;
	}
	return 0;
}

static int mrvl_run_fw_update(unsigned long arg)
{
	struct marlin_bootflash_update ioctl_desc = {0};
	struct smc_update_descriptor *smc_desc;
	struct arm_smccc_res res;

	smc_desc = (struct smc_update_descriptor *)memdesc[BUF_DATA].virt;
	memset(smc_desc, 0x00, sizeof(struct smc_update_descriptor));

	if (copy_from_user(&ioctl_desc,
			  (struct marlin_bootflash_update *)arg,
			  sizeof(struct marlin_bootflash_update))) {
		pr_err("Data Read Error\n");
		return -EFAULT;
	}

	pr_info("Update request: SPI: %d, CS: %d, image size: %lld\n",
							ioctl_desc.bus,
							ioctl_desc.cs,
							ioctl_desc.image_size);

	/*Verify data size*/
	if (ioctl_desc.image_size > memdesc[BUF_CPIO].size) {
		pr_err("Incorrect CPIO data size\n");
		return -EFAULT;
	}

	/* Verify userdata */
	if (ioctl_desc.user_size > memdesc[BUF_SIGNATURE].size) {
		pr_err("Incorrect user data size\n");
		return -EFAULT;
	}

	smc_desc->magic      = UPDATE_MAGIC;
	smc_desc->version    = UPDATE_VERSION;

	/* Set addresses and flags*/
	smc_desc->image_addr = memdesc[BUF_CPIO].phys;
	smc_desc->image_size = ioctl_desc.image_size;
	if (ioctl_desc.user_size != 0) {
		smc_desc->user_addr = memdesc[BUF_SIGNATURE].phys;
		smc_desc->user_size = ioctl_desc.user_size;
	}
	smc_desc->user_flags = ioctl_desc.user_flags;
	smc_desc->update_flags = ioctl_desc.flags;

	/* SPI config */
	smc_desc->bus        = ioctl_desc.bus;
	smc_desc->cs	     = ioctl_desc.cs;

	arm_smccc_smc(PLAT_OCTEONTX_SPI_SECURE_UPDATE, memdesc[BUF_DATA].phys,
			sizeof(struct smc_update_descriptor),
			0, 0, 0, 0, 0, &res);

	ioctl_desc.ret = res.a0;
	if (copy_to_user((struct marlin_bootflash_update *)arg,
			 &ioctl_desc,
			 sizeof(struct marlin_bootflash_update))) {
		pr_err("Data Write Error\n");
		return -EFAULT;
	}
	return 0;
}

static long mrvl_swup_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case GET_VERSION:
		return mrvl_get_version(arg, 0);
	case VERIFY_HASH:
		return mrvl_get_version(arg, 1);
	case GET_MEMBUF:
		return mrvl_get_membuf(arg);
	case RUN_UPDATE:
		return mrvl_run_fw_update(arg);
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

static int setup_cma(struct device *dev, struct memory_desc *memdesc)
{
	memdesc->virt = dma_alloc_coherent(dev, memdesc->size, &memdesc->phys, GFP_KERNEL);
	memset(memdesc->virt, 0x01, memdesc->size);
	pr_info("Allocated %llx b for pool: %s. Virt: %llx. Phys: %llx\n",
						memdesc->size,
						memdesc->pool_name,
						(uint64_t)memdesc->virt,
						(uint64_t)memdesc->phys);

	return 0;
}
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
	int i, ret;

	ret = octeontx_soc_check_smc();
	if (ret) {
		pr_err("SMC signature doesn't match OcteonTX. Failed to create device\n");
		return ret;
	}

	dev_set_name(&dev, "mrvl_swup_dev");
	ret = device_register(&dev);

	if (ret) {
		pr_err("Failed to register device\n");
		return ret;
	}

	/* Will not be used bt any HW, so use mask with ones only */
	dev.coherent_dma_mask = ~0;

	/* Allocate memory */
	for (i = 0; i < ARRAY_SIZE(memdesc); i++)
		setup_cma(&dev, &memdesc[i]);

	return mrvl_swup_setup_debugfs();
}

static void __exit mrvl_swup_exit(void)
{
	int i;

	debugfs_remove_recursive(mrvl_swup_root);
	for (i = 0; i < ARRAY_SIZE(memdesc); i++) {
		if (memdesc[i].phys != 0)
			dma_free_coherent(&dev, memdesc[i].size,
					  memdesc[i].virt, memdesc[i].phys);
	}
}

module_init(mrvl_swup_init)
module_exit(mrvl_swup_exit)

MODULE_DESCRIPTION("Marvell firmware update");
MODULE_AUTHOR("Witold Sadowski <wsadowski@marvell.com>");
MODULE_LICENSE("GPL");
