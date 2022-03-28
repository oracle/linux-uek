// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Marvell
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 *
 * Module provides a simple sysfs interface to dump SFP module information
 * in similar way as the 'ethtool -m <etxX>' command, except that ethtool
 * can only be called for NIX connected interfaces, and interface implemented
 * here has no such limitation.
 */

#define pr_fmt(fmt) "sfp-info: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/ctype.h>
#include <linux/io.h>
#include <linux/firmware/octeontx2/mub.h>

#define PLAT_OCTEONTX_GET_FWDATA_BASE 0xc2000b12
#define PLAT_OCTEONTX_GET_SFP_INFO_OFFSET 0xc2000b13

struct sfp_eeprom_s {
#define SFP_EEPROM_SIZE 256
	u16 sff_id;
	u8 buf[SFP_EEPROM_SIZE];
	u64 reserved;
};

static struct sfp_info_data {
	u32 portm;
	void __iomem *fwdata_base;
	struct mub_device *mdev;
} sfp_info_data;

static int dump_eeprom_data(const uint8_t *eeprom_data,
			    const size_t eeprom_size,
			    char *pr_buf)
{
#define OUT_LINE_LEN 16
#define MEM_DUMP_MAX 512
	size_t total = 0, line = 0;
	size_t lines_cnt;

	if (eeprom_size > MEM_DUMP_MAX || (eeprom_size % OUT_LINE_LEN))
		return -EINVAL;

	lines_cnt = eeprom_size / OUT_LINE_LEN;

	total += scnprintf(pr_buf + total, PAGE_SIZE - total,
		"        0  1  2  3  4  5  6  7   8  9  a  b  c  d  e  f\n");

	total += scnprintf(pr_buf + total, PAGE_SIZE - total,
		"        -----------------------------------------------\n");

	while (line < lines_cnt) {
		int cnt;
		size_t row_offs = line * OUT_LINE_LEN;

		total += scnprintf(pr_buf + total, PAGE_SIZE - total, "0x%04lx  ",
			row_offs);

		for (cnt = 0; cnt < OUT_LINE_LEN; cnt++) {
			const uint8_t num = eeprom_data[row_offs + cnt];

			total += scnprintf(pr_buf + total, PAGE_SIZE - total, "%02x ", num);

			if (cnt == OUT_LINE_LEN / 2 - 1)
				total += scnprintf(pr_buf + total, PAGE_SIZE - total, " ");
		}

		total += scnprintf(pr_buf + total, PAGE_SIZE - total, " |");

		for (cnt = 0; cnt < OUT_LINE_LEN; cnt++) {
			const uint8_t num = eeprom_data[row_offs + cnt];

			total += scnprintf(pr_buf + total, PAGE_SIZE - total, "%c",
				isalnum(num) ? num : '.');
		}

		total += scnprintf(pr_buf + total, PAGE_SIZE - total, "|\n");
		line++;
	}

	return total;
}

static ssize_t eeprom_show(struct mub_device *mdev, char *buf)
{
	int ret;
	u32 portm;
	struct sfp_eeprom_s *sfp_eeprom;
	struct arm_smccc_res res;
	size_t offset, cnt;

	struct sfp_info_data *data = mub_get_data(mdev);

	portm = data->portm;
	cnt = scnprintf(buf, PAGE_SIZE, "\nSFP eeprom dump [PORTM%d]:\n\n", portm);

	arm_smccc_smc(PLAT_OCTEONTX_GET_SFP_INFO_OFFSET, portm,
		0, 0, 0, 0, 0, 0, &res);

	if (res.a0 != SMCCC_RET_SUCCESS)
		return cnt;

	offset = res.a1;
	sfp_eeprom = data->fwdata_base + offset;

	ret = dump_eeprom_data(&sfp_eeprom->buf[0], SFP_EEPROM_SIZE, buf + cnt);
	return ret + cnt;
}
MUB_ATTR_RO(eeprom, eeprom_show);

static ssize_t portm_store(struct mub_device *mdev,
			   const char *buf, size_t count)
{
	int ret;
	u32 val;
	struct sfp_info_data *data = mub_get_data(mdev);

	ret = kstrtou32(buf, 10, &val);
	if (ret)
		return ret;

	data->portm = val;
	return count;
}

static ssize_t portm_show(struct mub_device *mdev, char *buf)
{
	struct sfp_info_data *data = mub_get_data(mdev);

	return scnprintf(buf, PAGE_SIZE, "%u\n", data->portm);
}
MUB_ATTR_RW(portm, portm_show, portm_store);

static struct attribute *sfp_info_attributes[] = {
	MUB_TO_ATTR(eeprom),
	MUB_TO_ATTR(portm),
	NULL
};

static const struct attribute_group sfp_info_group = {
	.attrs = sfp_info_attributes,
};

__ATTRIBUTE_GROUPS(sfp_info);

static int __init sfp_info_init(void)
{
	int ret = 0;
	size_t fwdata_size;
	struct arm_smccc_res res;
	struct mub_device *mdev;

	sfp_info_data.portm = 0;

	arm_smccc_smc(PLAT_OCTEONTX_GET_FWDATA_BASE, 0, 0,
		0, 0, 0, 0, 0, &res);

	if (res.a0 != SMCCC_RET_SUCCESS)
		return -ENOMEM;

	fwdata_size = res.a2;

	sfp_info_data.fwdata_base =
		ioremap_wc(res.a1, fwdata_size);

	if (!sfp_info_data.fwdata_base)
		return -ENOMEM;

	mdev = mub_device_register("sfp-info",
				    MUB_SOC_TYPE_10X,
				    sfp_info_groups);
	if (IS_ERR(mdev)) {
		iounmap(sfp_info_data.fwdata_base);
		return PTR_ERR(mdev);
	}

	mub_set_data(mdev, &sfp_info_data);
	sfp_info_data.mdev = mdev;
	return ret;
}
module_init(sfp_info_init);

static void __exit sfp_info_exit(void)
{
	mub_device_unregister(sfp_info_data.mdev);
	iounmap(sfp_info_data.fwdata_base);
}
module_exit(sfp_info_exit);

MODULE_DESCRIPTION("Marvell CN10K SFP info sysfs interface");
MODULE_AUTHOR("Damian Eppel <deppel@marvell.com>");
MODULE_LICENSE("GPL");
