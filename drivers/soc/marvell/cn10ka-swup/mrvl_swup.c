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
#include <linux/smp.h>
#include <linux/delay.h>

#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/device.h>
#include <linux/gfp.h>

#include <soc/marvell/octeontx/octeontx_smc.h>
#include "mrvl_swup.h"

#define TO_VERSION_DESC(x) ((struct mrvl_get_versions *)(x))
#define TO_CLONE_DESC(x) ((struct mrvl_clone_fw *)(x))
#define TO_UPDATE_DESC(x) ((struct mrvl_update *)(x))
#define TO_PHYS_BUFFER(x) ((struct mrvl_phys_buffer *)(x))
#define TO_READ_FLASH_DESC(x) ((struct mrvl_read_flash *)(x))

static int alloc_buffers(struct memory_desc *memdesc, uint32_t required_buf);
static void free_buffers(void);

static int alloc_readbuf(uint64_t rd_size);

/*Debugfs interface root */;
struct dentry *mrvl_swup_root;

/* Buffers for SMC call
 * 0 -> 25MB for SW update CPIO blob
 * 1 -> 1MB for passing data structures
 */
#define BUF_CPIO 0
#define BUF_DATA 1
#define BUF_SIGNATURE 2
#define BUF_READ 3
#define BUF_COUNT 4
static struct memory_desc memdesc[BUF_COUNT] = {
	{0, 0, 32*1024*1024, "cpio buffer"},
	{0, 0, 1*1024*1024,  "data buffer"},
	{0, 0, 1*1024*1024,  "signature buffer"},
	{0, 0, 0, "read buffer"},
};

static struct allocated_pages {
	struct page *p;
	int order;
} page_handler = {0};
/* IOCTL mapping to fw name */
static const struct {
	const char *str;
	uint8_t bit;
} name_to_sel_obj[] = {
	{"tim0", 0},
	{"gserp-cn10xx.fw", 1},
	{"scp_bl1.bin", 2},
	{"mcp_bl1.bin", 3},
	{"ecp_bl1.bin", 4},
	{"init.bin", 5},
	{"gserm-cn10xx.fw", 6},
	{"bl2.bin", 7},
	{"bl31.bin", 8},
	{"u-boot-nodtb.bin", 9},
	{"npc_mkex-cn10xx.fw", 10},
	{"efi_app1.efi", 11},
	{"switch_fw_ap.fw", 12},
	{"switch_fw_super.fw", 13},
};

static const char *obj_bit_to_str(uint32_t bit)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(name_to_sel_obj); i++) {
		if (name_to_sel_obj[i].bit == bit)
			return name_to_sel_obj[i].str;
	}
	return NULL;
}

/* Prepare objects for limited read */
static void prepare_names(struct smc_version_info *info, uint32_t objects)
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

struct arm_smccc_res mrvl_exec_smc(uint64_t smc, uint64_t buf, uint64_t size)
{
	struct arm_smccc_res res;

	arm_smccc_smc(smc, buf, size, 0, 0, 0, 0, 0, &res);
	return res;
}

static enum smc_version_entry_retcode mrvl_get_version(unsigned long arg, uint8_t calculate_hash)
{
	int i, ret = 0;
	struct mrvl_get_versions *user_desc;
	struct arm_smccc_res res;
	struct smc_version_info *swup_info = (struct smc_version_info *)memdesc[BUF_DATA].virt;

	user_desc = kzalloc(sizeof(*user_desc), GFP_KERNEL);
	if (!user_desc)
		return -ENOMEM;

	if (copy_from_user(user_desc,
			  TO_VERSION_DESC(arg),
			  sizeof(*user_desc))) {
		pr_err("Data Read Error\n");
		ret = -EFAULT;
		goto mem_error;
	}

	/* We have to perform conversion from IOCTL interface to smc */
	memset(swup_info, 0x00, sizeof(*swup_info));

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

	res = mrvl_exec_smc(PLAT_CN10K_VERIFY_FIRMWARE,
			    memdesc[BUF_DATA].phys,
			    sizeof(struct smc_version_info));

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

	if (copy_to_user(TO_VERSION_DESC(arg),
			user_desc,
			sizeof(*user_desc))) {
		pr_err("Data Write Error\n");
		ret = -EFAULT;
	}

mem_error:
	kfree(user_desc);
	return ret;
}

static int mrvl_clone_fw(unsigned long arg)
{
	int i, ret = 0;
	struct mrvl_clone_fw *user_desc;
	struct arm_smccc_res res;
	struct smc_version_info *swup_info = (struct smc_version_info *)memdesc[BUF_DATA].virt;

	user_desc = kzalloc(sizeof(*user_desc), GFP_KERNEL);
	if (!user_desc)
		return -ENOMEM;

	if (copy_from_user(user_desc,
			  TO_CLONE_DESC(arg),
			  sizeof(*user_desc))) {
		pr_err("Data Read Error\n");
		ret = -EFAULT;
		goto mem_error;
	}

	memset(swup_info, 0x00, sizeof(*swup_info));

	swup_info->magic_number = VERSION_MAGIC;
	swup_info->version      = VERSION_INFO_VERSION;
	swup_info->bus = user_desc->bus;
	swup_info->cs = user_desc->cs;
	swup_info->version_flags |= SMC_VERSION_CHECK_VALIDATE_HASH;

	if (user_desc->version_flags & MARLIN_CHECK_PREDEFINED_OBJ) {
		swup_info->version_flags |= SMC_VERSION_CHECK_SPECIFIC_OBJECTS;
		prepare_names(swup_info, user_desc->selected_objects);
		swup_info->num_objects = hweight_long(user_desc->selected_objects);
	} else {
		swup_info->num_objects = SMC_MAX_OBJECTS;
	}


	switch (user_desc->clone_op) {
	case CLONE_SPI:
		swup_info->target_bus = user_desc->target_bus;
		swup_info->target_cs = user_desc->target_cs;
		swup_info->version_flags |= SMC_VERSION_COPY_TO_BACKUP_FLASH;
		break;
	case CLONE_MMC:
		swup_info->version_flags |= SMC_VERSION_COPY_TO_BACKUP_EMMC;
		break;
	case CLONE_OFFSET:
		swup_info->version_flags |= SMC_VERSION_COPY_TO_BACKUP_OFFSET;
		break;
	default:
		pr_err("Incorrect clone parameter.\n");
		goto mem_error;
	}

	res = mrvl_exec_smc(PLAT_CN10K_VERIFY_FIRMWARE,
			    memdesc[BUF_DATA].phys,
			    sizeof(struct smc_version_info));

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

	if (copy_to_user(TO_CLONE_DESC(arg),
			user_desc,
			sizeof(*user_desc))) {
		pr_err("Data Write Error\n");
		ret = -EFAULT;
	}

mem_error:
	kfree(user_desc);
	return ret;
}

static int mrvl_get_membuf(unsigned long arg)
{
	struct mrvl_phys_buffer buf;

	buf.cpio_buf = memdesc[BUF_CPIO].phys;
	buf.cpio_buf_size = memdesc[BUF_CPIO].size;
	buf.sign_buf = memdesc[BUF_SIGNATURE].phys;
	buf.sign_buf_size = memdesc[BUF_SIGNATURE].size;
	buf.reserved_buf = 0;
	buf.reserved_buf_size = 0;
	buf.read_buf = memdesc[BUF_READ].phys;
	buf.read_buf_size = memdesc[BUF_READ].size;


	if (copy_to_user(TO_PHYS_BUFFER(arg),
			  &buf,
			  sizeof(buf))) {
		pr_err("Data Write Error\n");
		return -EFAULT;
	}
	return 0;
}

static int mrvl_run_fw_update(unsigned long arg)
{
	struct mrvl_update ioctl_desc = {0};
	struct smc_update_descriptor *smc_desc;
	struct arm_smccc_res res;
	int spi_in_progress = 0;

	smc_desc = (struct smc_update_descriptor *)memdesc[BUF_DATA].virt;
	memset(smc_desc, 0x00, sizeof(*smc_desc));

	if (copy_from_user(&ioctl_desc,
			  TO_UPDATE_DESC(arg),
			  sizeof(ioctl_desc))) {
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

	/* In linux use asynchronus SPI operation */
	smc_desc->async_spi = 1;

	/* SPI config */
	smc_desc->bus        = ioctl_desc.bus;
	smc_desc->cs	     = ioctl_desc.cs;

	res = mrvl_exec_smc(PLAT_OCTEONTX_SPI_SECURE_UPDATE,
			    memdesc[BUF_DATA].phys,
			    sizeof(struct smc_update_descriptor));

	ioctl_desc.ret = res.a0;
	if (copy_to_user(TO_UPDATE_DESC(arg),
			 &ioctl_desc,
			 sizeof(ioctl_desc))) {
		pr_err("Data Write Error\n");
		return -EFAULT;
	}

	do {
		msleep(500);
		res = mrvl_exec_smc(0xc2000b0e, 0, 0);
		spi_in_progress = res.a0;
	} while (spi_in_progress);

	return 0;
}

static int alloc_readbuf(uint64_t rd_size)
{
	int i, required_mem = 0, page_order;
	void *page_addr;
	uint32_t required_buf = 1<<BUF_DATA | 1<<BUF_READ;

	memdesc[BUF_READ].size = rd_size;
	required_mem += memdesc[BUF_READ].size;
	required_mem += memdesc[BUF_DATA].size;

	if (!required_mem)
		return 0;

	page_order = get_order(required_mem);
	page_handler.p = alloc_pages(GFP_KERNEL, page_order);
	if (!page_handler.p)
		return -ENOMEM;

	page_handler.order = page_order;
	page_addr = page_address(page_handler.p);
	memset(page_addr, 0x00, 1<<page_order);

	for (i = 0; i < BUF_COUNT; i++) {
		if (required_buf & 1<<i) {
			memdesc[i].virt = page_addr;
			memdesc[i].phys = virt_to_phys(page_addr);
			page_addr += memdesc[i].size;
		}
	}
	pr_debug("Alloc Read : size: %llx, required_mem: %x pg order %d addr %p\n",
							rd_size,
							required_mem,
							page_order,
							page_addr);
	return 0;
}

static int mrvl_read_flash_data(unsigned long arg)
{
	struct mrvl_read_flash ioctl_desc = {0};
	struct smc_read_flash_descriptor *smc_desc;
	struct arm_smccc_res res;
	int ret, spi_in_progress = 0;

	if (copy_from_user(&ioctl_desc,
			  TO_READ_FLASH_DESC(arg),
			  sizeof(ioctl_desc))) {
		pr_err("Data Read Error\n");
		return -EFAULT;
	}

	ret = alloc_readbuf(ioctl_desc.len);
	if (ret) {
		pr_err("Memory Alloc Error\n");
		return -ENOMEM;
	}
	smc_desc = (struct smc_read_flash_descriptor *)memdesc[BUF_DATA].virt;
	memset(smc_desc, 0x00, sizeof(*smc_desc));

	pr_info("Read request: SPI: %d, CS: %d, offset: %llx, Length: %llx\n",
							ioctl_desc.bus,
							ioctl_desc.cs,
							ioctl_desc.offset,
							ioctl_desc.len);


	/* Set location and length */
	smc_desc->offset = ioctl_desc.offset;
	smc_desc->length = ioctl_desc.len;

	/* In linux use asynchronus SPI operation */
	smc_desc->async_spi = 1;

	/* SPI config */
	smc_desc->bus        = ioctl_desc.bus;
	smc_desc->cs	     = ioctl_desc.cs;
	smc_desc->addr       = memdesc[BUF_READ].phys;

	res = mrvl_exec_smc(PLAT_CN10K_SPI_READ_FLASH,
			    memdesc[BUF_DATA].phys,
			    sizeof(struct smc_read_flash_descriptor));

	ioctl_desc.ret = res.a0;
	if (copy_to_user(TO_READ_FLASH_DESC(arg),
			 &ioctl_desc,
			 sizeof(ioctl_desc))) {
		pr_err("Data Write Error\n");
		return -EFAULT;
	}

	do {
		msleep(500);
		res = mrvl_exec_smc(0xc2000b0e, 0, 0);
		spi_in_progress = res.a0;
	} while (spi_in_progress);

	return 0;
}

static void mrvl_free_rd_buf(unsigned long arg)
{
	free_buffers();
}

static long mrvl_swup_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret;

	switch (cmd) {
	case GET_VERSION:
	case VERIFY_HASH:
	case CLONE_FW:
		ret = alloc_buffers(memdesc, 1<<BUF_DATA | 1<<BUF_SIGNATURE);
		break;
	case GET_MEMBUF:
		ret = alloc_buffers(memdesc, 1<<BUF_DATA | 1<<BUF_SIGNATURE | 1<<BUF_CPIO);
		break;
	case RUN_UPDATE:
	case READ_FLASH:
	case FREE_RD_BUF:
		ret = 0;
		break;
	default:
		ret = -ENXIO; /* Illegal cmd */
		break;
	}

	if (ret)
		return ret;

	switch (cmd) {
	case GET_VERSION:
		ret = mrvl_get_version(arg, 0);
		free_buffers();
		break;
	case VERIFY_HASH:
		ret = mrvl_get_version(arg, 1);
		free_buffers();
		break;
	case GET_MEMBUF:
		ret = mrvl_get_membuf(arg);
		break;
	case RUN_UPDATE:
		ret = mrvl_run_fw_update(arg);
		free_buffers();
		break;
	case CLONE_FW:
		ret = mrvl_clone_fw(arg);
		free_buffers();
		break;
	case READ_FLASH:
		ret = mrvl_read_flash_data(arg);
		break;
	case FREE_RD_BUF:
		mrvl_free_rd_buf(arg);
		break;
	default:
		pr_err("Not supported IOCTL\n");
		return -ENXIO;
	}
	return ret;
}

static const struct file_operations mrvl_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl		= mrvl_swup_ioctl,
	.llseek			= no_llseek,
};

static int alloc_buffers(struct memory_desc *memdesc, uint32_t required_buf)
{
	int i, required_mem = 0, page_order;
	void *page_addr;

	for (i = 0; i < BUF_COUNT; i++) {
		if (required_buf & 1<<i)
			required_mem += memdesc[i].size;
	}

	if (!required_mem)
		return 0;

	page_order = get_order(required_mem);
	page_handler.p = alloc_pages(GFP_KERNEL, page_order);
	if (!page_handler.p)
		return -ENOMEM;

	page_handler.order = page_order;
	page_addr = page_address(page_handler.p);
	memset(page_addr, 0x00, 1<<page_order);

	for (i = 0; i < BUF_COUNT; i++) {
		if (required_buf & 1<<i) {
			memdesc[i].virt = page_addr;
			memdesc[i].phys = virt_to_phys(page_addr);
			page_addr += memdesc[i].size;
		}
	}
	return 0;
}

static void free_buffers(void)
{
	int i;

	for (i = 0; i < BUF_COUNT; i++) {
		memdesc[i].phys = 0;
		memdesc[i].virt = 0;
	}

	if (page_handler.p) {
		__free_pages(page_handler.p, page_handler.order);
		page_handler.p = NULL;
		page_handler.order = 0;
	}
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
	int ret;

	ret = octeontx_soc_check_smc();
	if (ret != 2) {
		pr_debug("%s: Not supported\n", __func__);
		return -EPERM;
	}

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
