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

enum port_type {
	PORTM,
	ETH_LMAC
};

static struct sfp_info_data {
	u32 portm;
	u16 eth;
	u16 lmac;
	enum port_type ptype;
	spinlock_t lock;
	void __iomem *fwdata_base;
	struct mub_device *mdev;
} sfp_info_data;

#define eth_lmac2port(_eth, _lmac) ((_eth << 16) | _lmac)

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
	int cnt;
	u32 port;
	int ptype;
	struct sfp_eeprom_s *sfp_eeprom;
	struct arm_smccc_res res;
	size_t offset;

	struct sfp_info_data *data = mub_get_data(mdev);

	spin_lock(&data->lock);
	ptype = data->ptype;
	port = ptype == PORTM ?
		data->portm : eth_lmac2port(data->eth, data->lmac);
	spin_unlock(&data->lock);

	arm_smccc_smc(PLAT_OCTEONTX_GET_SFP_INFO_OFFSET, port, ptype,
		0, 0, 0, 0, 0, &res);

	if (res.a0 == -2)
		return scnprintf(buf, PAGE_SIZE, "non-ethernet port requested\n");

	if (res.a0 != SMCCC_RET_SUCCESS)
		return 0;

	offset = res.a1;
	sfp_eeprom = data->fwdata_base + offset;

	cnt = dump_eeprom_data(&sfp_eeprom->buf[0], SFP_EEPROM_SIZE, buf);
	return cnt;
}
MUB_ATTR_RO(eeprom, eeprom_show);

static ssize_t port_store(struct mub_device *mdev,
			   const char *buf, size_t count)
{
	u32 val1, val2;
	int cnt, ptype;
	struct sfp_info_data *data = mub_get_data(mdev);

	cnt = sscanf(buf, "%u %u", &val1, &val2);

	if (cnt == 2)
		ptype = ETH_LMAC;
	else if (cnt == 1)
		ptype = PORTM;
	else
		return -EINVAL;

	spin_lock(&data->lock);
	if (ptype == PORTM) {
		data->portm = val1;
	} else {
		data->eth = val1;
		data->lmac = val2;
	}
	data->ptype = ptype;
	spin_unlock(&data->lock);

	return count;
}

static ssize_t port_show(struct mub_device *mdev, char *buf)
{
	struct sfp_info_data *data = mub_get_data(mdev);
	u32 portm;
	u16 eth, lmac;
	int ptype;

	spin_lock(&data->lock);
	ptype = data->ptype;
	portm = data->portm;
	eth = data->eth;
	lmac = data->lmac;
	spin_unlock(&data->lock);

	return ptype == PORTM ?
		scnprintf(buf, PAGE_SIZE, "%u\n", portm) :
		scnprintf(buf, PAGE_SIZE, "%u:%u\n", eth, lmac);
}
MUB_ATTR_RW(port, port_show, port_store);

static struct attribute *sfp_info_attributes[] = {
	MUB_TO_ATTR(eeprom),
	MUB_TO_ATTR(port),
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

	sfp_info_data.eth = 0;
	sfp_info_data.lmac = 0;
	sfp_info_data.ptype = ETH_LMAC;
	spin_lock_init(&sfp_info_data.lock);

	mdev = mub_device_register("sfp-info",
				    MUB_SOC_TYPE_10X |
				    MUB_SOC_TYPE_9X,
				    sfp_info_groups);
	if (IS_ERR(mdev))
		return PTR_ERR(mdev);

	sfp_info_data.mdev = mdev;

	arm_smccc_smc(PLAT_OCTEONTX_GET_FWDATA_BASE, 0, 0,
		0, 0, 0, 0, 0, &res);

	if (res.a0 != SMCCC_RET_SUCCESS) {
		mub_device_unregister(sfp_info_data.mdev);
		return -ENOMEM;
	}

	fwdata_size = res.a2;

	sfp_info_data.fwdata_base =
		ioremap_wc(res.a1, fwdata_size);

	if (!sfp_info_data.fwdata_base) {
		mub_device_unregister(sfp_info_data.mdev);
		return -ENOMEM;
	}

	mub_set_data(mdev, &sfp_info_data);
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
