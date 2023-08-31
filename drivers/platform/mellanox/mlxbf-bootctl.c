// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 *  Mellanox boot control driver
 *  This driver provides a sysfs interface for systems management
 *  software to manage reset-time actions.
 *
 *  Copyright (C) 2020 Mellanox Technologies.  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License v2.0 as published by
 *  the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#include <linux/acpi.h>
#include <linux/arm-smccc.h>
#include <linux/delay.h>
#include <linux/if_ether.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include "mlxbf-bootctl.h"

#define DRIVER_NAME		"mlxbf-bootctl"
#define DRIVER_VERSION		"1.5"
#define DRIVER_DESCRIPTION	"Mellanox boot control driver"

#define SB_MODE_SECURE_MASK	0x03
#define SB_MODE_TEST_MASK	0x0c
#define SB_MODE_DEV_MASK	0x10

#define SB_KEY_NUM		4

struct boot_name {
	int value;
	const char name[12];
};

static struct boot_name boot_names[] = {
	{ MLNX_BOOT_EXTERNAL,		"external"	},
	{ MLNX_BOOT_EMMC,		"emmc"		},
	{ MLNX_BOOT_SWAP_EMMC,		"swap_emmc"	},
	{ MLNX_BOOT_EMMC_LEGACY,	"emmc_legacy"	},
	{ MLNX_BOOT_NONE,		"none"		},
	{ -1,				""		}
};

enum {
	SB_LIFECYCLE_PRODUCTION = 0,
	SB_LIFECYCLE_GA_SECURE = 1,
	SB_LIFECYCLE_GA_NON_SECURE = 2,
	SB_LIFECYCLE_RMA = 3
};

static char lifecycle_states[][16] = {
	[SB_LIFECYCLE_PRODUCTION] = "Production",
	[SB_LIFECYCLE_GA_SECURE] = "GA Secured",
	[SB_LIFECYCLE_GA_NON_SECURE] = "GA Non-Secured",
	[SB_LIFECYCLE_RMA] = "RMA",
};

/* ctl/data register within the resource. */
#define RSH_SCRATCH_BUF_CTL_OFF		0
#define RSH_SCRATCH_BUF_DATA_OFF	0x10

static void __iomem *rsh_boot_data;
static void __iomem *rsh_boot_cnt;
static void __iomem *rsh_semaphore;
static void __iomem *rsh_scratch_buf_ctl;
static void __iomem *rsh_scratch_buf_data;

static int rsh_log_clear_on_read;
module_param(rsh_log_clear_on_read, int, 0644);
MODULE_PARM_DESC(rsh_log_clear_on_read, "Clear rshim logging buffer after read.");

/*
 * Objects are stored within the MFG partition per type. Type 0 is not
 * supported.
 */
enum {
	MLNX_MFG_TYPE_OOB_MAC = 1,
	MLNX_MFG_TYPE_OPN_0,
	MLNX_MFG_TYPE_OPN_1,
	MLNX_MFG_TYPE_OPN_2,
	MLNX_MFG_TYPE_SKU_0,
	MLNX_MFG_TYPE_SKU_1,
	MLNX_MFG_TYPE_SKU_2,
	MLNX_MFG_TYPE_MODL_0,
	MLNX_MFG_TYPE_MODL_1,
	MLNX_MFG_TYPE_MODL_2,
	MLNX_MFG_TYPE_SN_0,
	MLNX_MFG_TYPE_SN_1,
	MLNX_MFG_TYPE_SN_2,
	MLNX_MFG_TYPE_UUID_0,
	MLNX_MFG_TYPE_UUID_1,
	MLNX_MFG_TYPE_UUID_2,
	MLNX_MFG_TYPE_UUID_3,
	MLNX_MFG_TYPE_UUID_4,
	MLNX_MFG_TYPE_REV,
};

/* This mutex is used to serialize MFG write and lock operations. */
static DEFINE_MUTEX(mfg_ops_lock);
static DEFINE_MUTEX(icm_ops_lock);

#define MLNX_MFG_OOB_MAC_LEN         ETH_ALEN
#define MLNX_MFG_OPN_VAL_LEN         24
#define MLNX_MFG_SKU_VAL_LEN         24
#define MLNX_MFG_MODL_VAL_LEN        24
#define MLNX_MFG_SN_VAL_LEN          24
#define MLNX_MFG_UUID_VAL_LEN        40
#define MLNX_MFG_REV_VAL_LEN         8
#define MLNX_MFG_VAL_QWORD_CNT(type) \
	(MLNX_MFG_##type##_VAL_LEN / sizeof(u64))

/*
 * The MAC address consists of 6 bytes (2 digits each) separated by ':'.
 * The expected format is: "XX:XX:XX:XX:XX:XX"
 */
#define MLNX_MFG_OOB_MAC_FORMAT_LEN \
	((MLNX_MFG_OOB_MAC_LEN * 2) + (MLNX_MFG_OOB_MAC_LEN - 1))

/* The SMC calls in question are atomic, so we don't have to lock here. */
static int smc_call1(unsigned int smc_op, int smc_arg)
{
	struct arm_smccc_res res;

	arm_smccc_smc(smc_op, smc_arg, 0, 0, 0, 0, 0, 0, &res);

	return res.a0;
}

/* Syntactic sugar to avoid having to specify an unused argument. */
#define smc_call0(smc_op) smc_call1(smc_op, 0)

static int reset_action_to_val(const char *action, size_t len)
{
	struct boot_name *bn;

	/* Accept string either with or without a newline terminator */
	if (action[len-1] == '\n')
		--len;

	for (bn = boot_names; bn->value >= 0; ++bn)
		if (strncmp(bn->name, action, len) == 0)
			break;

	return bn->value;
}

static const char *reset_action_to_string(int action)
{
	struct boot_name *bn;

	for (bn = boot_names; bn->value >= 0; ++bn)
		if (bn->value == action)
			break;

	return bn->name;
}

static ssize_t post_reset_wdog_show(struct device_driver *drv,
				    char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%d\n",
			smc_call0(MLNX_GET_POST_RESET_WDOG));
}

static ssize_t post_reset_wdog_store(struct device_driver *drv,
				     const char *buf, size_t count)
{
	int err;
	unsigned long watchdog;

	err = kstrtoul(buf, 10, &watchdog);
	if (err)
		return err;

	if (smc_call1(MLNX_SET_POST_RESET_WDOG, watchdog) < 0)
		return -EINVAL;

	return count;
}

static ssize_t reset_action_show(struct device_driver *drv,
				 char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", reset_action_to_string(
			smc_call0(MLNX_GET_RESET_ACTION)));
}

static ssize_t reset_action_store(struct device_driver *drv,
				  const char *buf, size_t count)
{
	int action = reset_action_to_val(buf, count);

	if (action < 0 || action == MLNX_BOOT_NONE)
		return -EINVAL;

	if (smc_call1(MLNX_SET_RESET_ACTION, action) < 0)
		return -EINVAL;

	return count;
}

static ssize_t second_reset_action_show(struct device_driver *drv,
					char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", reset_action_to_string(
			smc_call0(MLNX_GET_SECOND_RESET_ACTION)));
}

static ssize_t second_reset_action_store(struct device_driver *drv,
					 const char *buf, size_t count)
{
	int action = reset_action_to_val(buf, count);

	if (action < 0)
		return -EINVAL;

	if (smc_call1(MLNX_SET_SECOND_RESET_ACTION, action) < 0)
		return -EINVAL;

	return count;
}

static ssize_t lifecycle_state_show(struct device_driver *drv,
				    char *buf)
{
	int lc_state = smc_call1(MLNX_GET_TBB_FUSE_STATUS,
				 MLNX_FUSE_STATUS_LIFECYCLE);

	if (lc_state < 0)
		return -EINVAL;

	lc_state &= (SB_MODE_TEST_MASK |
		     SB_MODE_SECURE_MASK |
		     SB_MODE_DEV_MASK);

	/*
	 * If the test bits are set, we specify that the current state may be
	 * due to using the test bits.
	 */
	if ((lc_state & SB_MODE_TEST_MASK) != 0) {

		lc_state &= SB_MODE_SECURE_MASK;

		return snprintf(buf, PAGE_SIZE, "%s(test)\n",
				lifecycle_states[lc_state]);
	} else if ((lc_state & SB_MODE_SECURE_MASK) == SB_LIFECYCLE_GA_SECURE
		   && (lc_state & SB_MODE_DEV_MASK)) {
		return snprintf(buf, PAGE_SIZE, "Secured (development)\n");
	}

	return snprintf(buf, PAGE_SIZE, "%s\n", lifecycle_states[lc_state]);
}

static ssize_t secure_boot_fuse_state_show(struct device_driver *drv,
					   char *buf)
{
	int key;
	int buf_len = 0;
	int upper_key_used = 0;
	int sb_key_state = smc_call1(MLNX_GET_TBB_FUSE_STATUS,
				     MLNX_FUSE_STATUS_KEYS);

	if (sb_key_state < 0)
		return -EINVAL;

	for (key = SB_KEY_NUM - 1; key >= 0; key--) {
		int burnt = ((sb_key_state & (1 << key)) != 0);
		int valid = ((sb_key_state & (1 << (key + SB_KEY_NUM))) != 0);

		buf_len += sprintf(buf + buf_len, "Ver%d:", key);
		if (upper_key_used) {
			if (burnt) {
				if (valid)
					buf_len += sprintf(buf + buf_len,
							  "Used");
				else
					buf_len += sprintf(buf + buf_len,
							  "Wasted");
			} else {
				if (valid)
					buf_len += sprintf(buf + buf_len,
							  "Invalid");
				else
					buf_len += sprintf(buf + buf_len,
							  "Skipped");
			}
		} else {
			if (burnt) {
				if (valid) {
					upper_key_used = 1;
					buf_len += sprintf(buf + buf_len,
							  "In use");
				} else
					buf_len += sprintf(buf + buf_len,
							  "Burn incomplete");
			} else {
				if (valid)
					buf_len += sprintf(buf + buf_len,
							  "Invalid");
				else
					buf_len += sprintf(buf + buf_len,
							  "Free");
			}
		}
		buf_len += sprintf(buf + buf_len, "\n");
	}

	return buf_len;
}

static ssize_t fw_reset_store(struct device_driver *drv,
			      const char *buf, size_t count)
{
	int err;
	unsigned long key;

	err = kstrtoul(buf, 16, &key);
	if (err)
		return err;

	if (smc_call1(MLNX_HANDLE_FW_RESET, key) < 0)
		return -EINVAL;

	return count;
}

static ssize_t oob_mac_show(struct device_driver *drv, char *buf)
{
	char mac_str[MLNX_MFG_OOB_MAC_FORMAT_LEN + 1] = { 0 };
	struct arm_smccc_res res;
	u8 *mac_byte_ptr;

	mutex_lock(&mfg_ops_lock);
	arm_smccc_smc(MLNX_HANDLE_GET_MFG_INFO, MLNX_MFG_TYPE_OOB_MAC, 0, 0, 0,
		      0, 0, 0, &res);
	mutex_unlock(&mfg_ops_lock);
	if (res.a0)
		return -EPERM;

	mac_byte_ptr = (u8 *)&res.a1;

	sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
		mac_byte_ptr[0], mac_byte_ptr[1], mac_byte_ptr[2],
		mac_byte_ptr[3], mac_byte_ptr[4], mac_byte_ptr[5]);

	return snprintf(buf, PAGE_SIZE, "%s", mac_str);
}

static ssize_t oob_mac_store(struct device_driver *drv, const char *buf,
			     size_t count)
{
	int byte[MLNX_MFG_OOB_MAC_FORMAT_LEN] = { 0 };
	struct arm_smccc_res res;
	u64 mac_addr = 0;
	u8 *mac_byte_ptr;
	int byte_idx, len;

	if ((count - 1) != MLNX_MFG_OOB_MAC_FORMAT_LEN)
		return -EINVAL;

	len = sscanf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		     &byte[0], &byte[1], &byte[2],
		     &byte[3], &byte[4], &byte[5]);
	if (len != MLNX_MFG_OOB_MAC_LEN)
		return -EINVAL;

	mac_byte_ptr = (u8 *)&mac_addr;

	for (byte_idx = 0; byte_idx < MLNX_MFG_OOB_MAC_LEN; byte_idx++)
		mac_byte_ptr[byte_idx] = (u8) byte[byte_idx];

	mutex_lock(&mfg_ops_lock);
	arm_smccc_smc(MLNX_HANDLE_SET_MFG_INFO, MLNX_MFG_TYPE_OOB_MAC,
		  MLNX_MFG_OOB_MAC_LEN, mac_addr, 0, 0, 0, 0, &res);
	mutex_unlock(&mfg_ops_lock);

	return res.a0 ? -EPERM : count;
}

static ssize_t large_icm_show(struct device_driver *drv, char *buf)
{
	char icm_str[MAX_ICM_BUFFER_SIZE] = { 0 };
	struct arm_smccc_res res;

	arm_smccc_smc(MLNX_HANDLE_GET_ICM_INFO, 0, 0, 0, 0,
		      0, 0, 0, &res);
	if (res.a0)
		return -EPERM;

	sprintf(icm_str, "0x%lx", res.a1);

	return snprintf(buf, sizeof(icm_str), "%s", icm_str);
}

static ssize_t large_icm_store(struct device_driver *drv, const char *buf,
			     size_t count)
{
	struct arm_smccc_res res;
	unsigned long icm_data;
	int err;

	err = kstrtoul(buf, 16, &icm_data);
	if (err)
		return err;

	if (((icm_data != 0) && (icm_data < 0x80)) ||
	    (icm_data > 0x100000) || (icm_data % 128))
		return -EPERM;

	mutex_lock(&icm_ops_lock);
	arm_smccc_smc(MLNX_HANDLE_SET_ICM_INFO, icm_data, 0, 0, 0, 0, 0, 0, &res);
	mutex_unlock(&icm_ops_lock);

	return res.a0 ? -EPERM : count;
}

static ssize_t opn_show(struct device_driver *drv, char *buf)
{
	u64 opn_data[MLNX_MFG_VAL_QWORD_CNT(OPN)] = { 0 };
	char opn[MLNX_MFG_OPN_VAL_LEN + 1] = { 0 };
	struct arm_smccc_res res;
	int word;

	mutex_lock(&mfg_ops_lock);
	for (word = 0; word < MLNX_MFG_VAL_QWORD_CNT(OPN); word++) {
		arm_smccc_smc(MLNX_HANDLE_GET_MFG_INFO,
			      MLNX_MFG_TYPE_OPN_0 + word,
			      0, 0, 0, 0, 0, 0, &res);
		if (res.a0) {
			mutex_unlock(&mfg_ops_lock);
			return -EPERM;
		}
		opn_data[word] = res.a1;
	}
	mutex_unlock(&mfg_ops_lock);
	memcpy(opn, opn_data, MLNX_MFG_OPN_VAL_LEN);

	return snprintf(buf, PAGE_SIZE, "%s", opn);
}

static ssize_t opn_store(struct device_driver *drv, const char *buf,
			 size_t count)
{
	u64 opn[MLNX_MFG_VAL_QWORD_CNT(OPN)] = { 0 };
	struct arm_smccc_res res;
	int word;

	if (count > MLNX_MFG_OPN_VAL_LEN)
		return -EINVAL;

	memcpy(opn, buf, count);

	mutex_lock(&mfg_ops_lock);
	for (word = 0; word < MLNX_MFG_VAL_QWORD_CNT(OPN); word++) {
		arm_smccc_smc(MLNX_HANDLE_SET_MFG_INFO,
			      MLNX_MFG_TYPE_OPN_0 + word,
			      sizeof(u64), opn[word], 0, 0, 0, 0, &res);
		if (res.a0) {
			mutex_unlock(&mfg_ops_lock);
			return -EPERM;
		}
	}
	mutex_unlock(&mfg_ops_lock);

	return count;
}

static ssize_t sku_show(struct device_driver *drv, char *buf)
{
	u64 sku_data[MLNX_MFG_VAL_QWORD_CNT(SKU)] = { 0 };
	char sku[MLNX_MFG_SKU_VAL_LEN + 1] = { 0 };
	struct arm_smccc_res res;
	int word;

	mutex_lock(&mfg_ops_lock);
	for (word = 0; word < MLNX_MFG_VAL_QWORD_CNT(SKU); word++) {
		arm_smccc_smc(MLNX_HANDLE_GET_MFG_INFO,
			      MLNX_MFG_TYPE_SKU_0 + word,
			      0, 0, 0, 0, 0, 0, &res);
		if (res.a0) {
			mutex_unlock(&mfg_ops_lock);
			return -EPERM;
		}
		sku_data[word] = res.a1;
	}
	mutex_unlock(&mfg_ops_lock);
	memcpy(sku, sku_data, MLNX_MFG_SKU_VAL_LEN);

	return snprintf(buf, PAGE_SIZE, "%s", sku);
}

static ssize_t sku_store(struct device_driver *drv, const char *buf,
			 size_t count)
{
	u64 sku[MLNX_MFG_VAL_QWORD_CNT(SKU)] = { 0 };
	struct arm_smccc_res res;
	int word;

	if (count > MLNX_MFG_SKU_VAL_LEN)
		return -EINVAL;

	memcpy(sku, buf, count);

	mutex_lock(&mfg_ops_lock);
	for (word = 0; word < MLNX_MFG_VAL_QWORD_CNT(SKU); word++) {
		arm_smccc_smc(MLNX_HANDLE_SET_MFG_INFO,
			      MLNX_MFG_TYPE_SKU_0 + word,
			      sizeof(u64), sku[word], 0, 0, 0, 0, &res);
		if (res.a0) {
			mutex_unlock(&mfg_ops_lock);
			return -EPERM;
		}
	}
	mutex_unlock(&mfg_ops_lock);

	return count;
}

static ssize_t modl_show(struct device_driver *drv, char *buf)
{
	u64 modl_data[MLNX_MFG_VAL_QWORD_CNT(MODL)] = { 0 };
	char modl[MLNX_MFG_MODL_VAL_LEN + 1] = { 0 };
	struct arm_smccc_res res;
	int word;

	mutex_lock(&mfg_ops_lock);
	for (word = 0; word < MLNX_MFG_VAL_QWORD_CNT(MODL); word++) {
		arm_smccc_smc(MLNX_HANDLE_GET_MFG_INFO,
			      MLNX_MFG_TYPE_MODL_0 + word,
			      0, 0, 0, 0, 0, 0, &res);
		if (res.a0) {
			mutex_unlock(&mfg_ops_lock);
			return -EPERM;
		}
		modl_data[word] = res.a1;
	}
	mutex_unlock(&mfg_ops_lock);
	memcpy(modl, modl_data, MLNX_MFG_MODL_VAL_LEN);

	return snprintf(buf, PAGE_SIZE, "%s", modl);
}

static ssize_t modl_store(struct device_driver *drv, const char *buf,
			  size_t count)
{
	u64 modl[MLNX_MFG_VAL_QWORD_CNT(MODL)] = { 0 };
	struct arm_smccc_res res;
	int word;

	if (count > MLNX_MFG_MODL_VAL_LEN)
		return -EINVAL;

	memcpy(modl, buf, count);

	mutex_lock(&mfg_ops_lock);
	for (word = 0; word < MLNX_MFG_VAL_QWORD_CNT(MODL); word++) {
		arm_smccc_smc(MLNX_HANDLE_SET_MFG_INFO,
			      MLNX_MFG_TYPE_MODL_0 + word,
			      sizeof(u64), modl[word], 0, 0, 0, 0, &res);
		if (res.a0) {
			mutex_unlock(&mfg_ops_lock);
			return -EPERM;
		}
	}
	mutex_unlock(&mfg_ops_lock);

	return count;
}

static ssize_t sn_show(struct device_driver *drv, char *buf)
{
	u64 sn_data[MLNX_MFG_VAL_QWORD_CNT(SN)] = { 0 };
	char sn[MLNX_MFG_SN_VAL_LEN + 1] = { 0 };
	struct arm_smccc_res res;
	int word;

	mutex_lock(&mfg_ops_lock);
	for (word = 0; word < MLNX_MFG_VAL_QWORD_CNT(SN); word++) {
		arm_smccc_smc(MLNX_HANDLE_GET_MFG_INFO,
			      MLNX_MFG_TYPE_SN_0 + word,
			      0, 0, 0, 0, 0, 0, &res);
		if (res.a0) {
			mutex_unlock(&mfg_ops_lock);
			return -EPERM;
		}
		sn_data[word] = res.a1;
	}
	mutex_unlock(&mfg_ops_lock);
	memcpy(sn, sn_data, MLNX_MFG_SN_VAL_LEN);

	return snprintf(buf, PAGE_SIZE, "%s", sn);
}

static ssize_t sn_store(struct device_driver *drv, const char *buf,
			size_t count)
{
	u64 sn[MLNX_MFG_VAL_QWORD_CNT(SN)] = { 0 };
	struct arm_smccc_res res;
	int word;

	if (count > MLNX_MFG_SN_VAL_LEN)
		return -EINVAL;

	memcpy(sn, buf, count);

	mutex_lock(&mfg_ops_lock);
	for (word = 0; word < MLNX_MFG_VAL_QWORD_CNT(SN); word++) {
		arm_smccc_smc(MLNX_HANDLE_SET_MFG_INFO,
			      MLNX_MFG_TYPE_SN_0 + word,
			      sizeof(u64), sn[word], 0, 0, 0, 0, &res);
		if (res.a0) {
			mutex_unlock(&mfg_ops_lock);
			return -EPERM;
		}
	}
	mutex_unlock(&mfg_ops_lock);

	return count;
}

static ssize_t uuid_show(struct device_driver *drv, char *buf)
{
	u64 uuid_data[MLNX_MFG_VAL_QWORD_CNT(UUID)] = { 0 };
	char uuid[MLNX_MFG_UUID_VAL_LEN + 1] = { 0 };
	struct arm_smccc_res res;
	int word;

	mutex_lock(&mfg_ops_lock);
	for (word = 0; word < MLNX_MFG_VAL_QWORD_CNT(UUID); word++) {
		arm_smccc_smc(MLNX_HANDLE_GET_MFG_INFO,
			      MLNX_MFG_TYPE_UUID_0 + word,
			      0, 0, 0, 0, 0, 0, &res);
		if (res.a0) {
			mutex_unlock(&mfg_ops_lock);
			return -EPERM;
		}
		uuid_data[word] = res.a1;
	}
	mutex_unlock(&mfg_ops_lock);
	memcpy(uuid, uuid_data, MLNX_MFG_UUID_VAL_LEN);

	return snprintf(buf, PAGE_SIZE, "%s", uuid);
}

static ssize_t uuid_store(struct device_driver *drv, const char *buf,
			  size_t count)
{
	u64 uuid[MLNX_MFG_VAL_QWORD_CNT(UUID)] = { 0 };
	struct arm_smccc_res res;
	int word;

	if (count > MLNX_MFG_UUID_VAL_LEN)
		return -EINVAL;

	memcpy(uuid, buf, count);

	mutex_lock(&mfg_ops_lock);
	for (word = 0; word < MLNX_MFG_VAL_QWORD_CNT(UUID); word++) {
		arm_smccc_smc(MLNX_HANDLE_SET_MFG_INFO,
			      MLNX_MFG_TYPE_UUID_0 + word,
			      sizeof(u64), uuid[word], 0, 0, 0, 0, &res);
		if (res.a0) {
			mutex_unlock(&mfg_ops_lock);
			return -EPERM;
		}
	}
	mutex_unlock(&mfg_ops_lock);

	return count;
}

static ssize_t rev_show(struct device_driver *drv, char *buf)
{
	u64 rev_data[MLNX_MFG_VAL_QWORD_CNT(REV)] = { 0 };
	char rev[MLNX_MFG_REV_VAL_LEN + 1] = { 0 };
	struct arm_smccc_res res;
	int word;

	mutex_lock(&mfg_ops_lock);
	for (word = 0; word < MLNX_MFG_VAL_QWORD_CNT(REV); word++) {
		arm_smccc_smc(MLNX_HANDLE_GET_MFG_INFO,
			      MLNX_MFG_TYPE_REV + word,
			      0, 0, 0, 0, 0, 0, &res);
		if (res.a0) {
			mutex_unlock(&mfg_ops_lock);
			return -EPERM;
		}
		rev_data[word] = res.a1;
	}
	mutex_unlock(&mfg_ops_lock);
	memcpy(rev, rev_data, MLNX_MFG_REV_VAL_LEN);

	return snprintf(buf, PAGE_SIZE, "%s", rev);
}

static ssize_t rev_store(struct device_driver *drv, const char *buf,
			 size_t count)
{
	u64 rev[MLNX_MFG_VAL_QWORD_CNT(REV)] = { 0 };
	struct arm_smccc_res res;
	int word;

	if (count > MLNX_MFG_REV_VAL_LEN)
		return -EINVAL;

	memcpy(rev, buf, count);

	mutex_lock(&mfg_ops_lock);
	for (word = 0; word < MLNX_MFG_VAL_QWORD_CNT(REV); word++) {
		arm_smccc_smc(MLNX_HANDLE_SET_MFG_INFO,
			      MLNX_MFG_TYPE_REV + word,
			      sizeof(u64), rev[word], 0, 0, 0, 0, &res);
		if (res.a0) {
			mutex_unlock(&mfg_ops_lock);
			return -EPERM;
		}
	}
	mutex_unlock(&mfg_ops_lock);

	return count;
}

static ssize_t mfg_lock_store(struct device_driver *drv, const char *buf,
			      size_t count)
{
	unsigned long val;
	int err;

	err = kstrtoul(buf, 10, &val);
	if (err)
		return err;

	if (val != 1)
		return -EINVAL;

	mutex_lock(&mfg_ops_lock);
	smc_call0(MLNX_HANDLE_LOCK_MFG_INFO);
	mutex_unlock(&mfg_ops_lock);

	return count;
}

/* Log header format. */
#define RSH_LOG_TYPE_SHIFT	56
#define RSH_LOG_LEN_SHIFT	48
#define RSH_LOG_LEVEL_SHIFT	0

/* Module ID and type used here. */
#define BF_RSH_LOG_TYPE_UNKNOWN		0x00ULL
#define BF_RSH_LOG_TYPE_PANIC		0x01ULL
#define BF_RSH_LOG_TYPE_EXCEPTION	0x02ULL
#define BF_RSH_LOG_TYPE_UNUSED		0x03ULL
#define BF_RSH_LOG_TYPE_MSG		0x04ULL

/* Utility macro. */
#define BF_RSH_LOG_MOD_MASK		0x0FULL
#define BF_RSH_LOG_MOD_SHIFT		60
#define BF_RSH_LOG_TYPE_MASK		0x0FULL
#define BF_RSH_LOG_TYPE_SHIFT		56
#define BF_RSH_LOG_LEN_MASK		0x7FULL
#define BF_RSH_LOG_LEN_SHIFT		48
#define BF_RSH_LOG_ARG_MASK		0xFFFFFFFFULL
#define BF_RSH_LOG_ARG_SHIFT		16
#define BF_RSH_LOG_HAS_ARG_MASK		0xFFULL
#define BF_RSH_LOG_HAS_ARG_SHIFT	8
#define BF_RSH_LOG_LEVEL_MASK		0xFFULL
#define BF_RSH_LOG_LEVEL_SHIFT		0
#define BF_RSH_LOG_PC_MASK		0xFFFFFFFFULL
#define BF_RSH_LOG_PC_SHIFT		0
#define BF_RSH_LOG_SYNDROME_MASK	0xFFFFFFFFULL
#define BF_RSH_LOG_SYNDROME_SHIFT	0

#define BF_RSH_LOG_HEADER_GET(f, h) \
	(((h) >> BF_RSH_LOG_##f##_SHIFT) & BF_RSH_LOG_##f##_MASK)

/* Log message level. */
enum {
	RSH_LOG_INFO,
	RSH_LOG_WARN,
	RSH_LOG_ERR
};

/* Log module */
const char * const rsh_log_mod[] = {
	"MISC", "BL1", "BL2", "BL2R", "BL31", "UEFI"
};

const char *rsh_log_level[] = {"INFO", "WARN", "ERR", "ASSERT"};

#define AARCH64_MRS_REG_SHIFT 5
#define AARCH64_MRS_REG_MASK  0xffff
#define AARCH64_ESR_ELX_EXCEPTION_CLASS_SHIFT 26

struct rsh_log_reg {
	char *name;
	u32 opcode;
} rsh_log_reg;

static struct rsh_log_reg rsh_log_regs[] = {
	{"actlr_el1",		0b1100000010000001},
	{"actlr_el2",		0b1110000010000001},
	{"actlr_el3",		0b1111000010000001},
	{"afsr0_el1",		0b1100001010001000},
	{"afsr0_el2",		0b1110001010001000},
	{"afsr0_el3",		0b1111001010001000},
	{"afsr1_el1",		0b1100001010001001},
	{"afsr1_el2",		0b1110001010001001},
	{"afsr1_el3",		0b1111001010001001},
	{"amair_el1",		0b1100010100011000},
	{"amair_el2",		0b1110010100011000},
	{"amair_el3",		0b1111010100011000},
	{"ccsidr_el1",		0b1100100000000000},
	{"clidr_el1",		0b1100100000000001},
	{"cntkctl_el1",		0b1100011100001000},
	{"cntp_ctl_el0",	0b1101111100010001},
	{"cntp_cval_el0",	0b1101111100010010},
	{"cntv_ctl_el0",	0b1101111100011001},
	{"cntv_cval_el0",	0b1101111100011010},
	{"contextidr_el1",	0b1100011010000001},
	{"cpacr_el1",		0b1100000010000010},
	{"cptr_el2",		0b1110000010001010},
	{"cptr_el3",		0b1111000010001010},
	{"vtcr_el2",		0b1110000100001010},
	{"ctr_el0",		0b1101100000000001},
	{"currentel",		0b1100001000010010},
	{"dacr32_el2",		0b1110000110000000},
	{"daif",		0b1101101000010001},
	{"dczid_el0",		0b1101100000000111},
	{"dlr_el0",		0b1101101000101001},
	{"dspsr_el0",		0b1101101000101000},
	{"elr_el1",		0b1100001000000001},
	{"elr_el2",		0b1110001000000001},
	{"elr_el3",		0b1111001000000001},
	{"esr_el1",		0b1100001010010000},
	{"esr_el2",		0b1110001010010000},
	{"esr_el3",		0b1111001010010000},
	{"esselr_el1",		0b1101000000000000},
	{"far_el1",		0b1100001100000000},
	{"far_el2",		0b1110001100000000},
	{"far_el3",		0b1111001100000000},
	{"fpcr",		0b1101101000100000},
	{"fpexc32_el2",		0b1110001010011000},
	{"fpsr",		0b1101101000100001},
	{"hacr_el2",		0b1110000010001111},
	{"har_el2",		0b1110000010001000},
	{"hpfar_el2",		0b1110001100000100},
	{"hstr_el2",		0b1110000010001011},
	{"far_el1",		0b1100001100000000},
	{"far_el2",		0b1110001100000000},
	{"far_el3",		0b1111001100000000},
	{"hcr_el2",		0b1110000010001000},
	{"hpfar_el2",		0b1110001100000100},
	{"id_aa64afr0_el1",	0b1100000000101100},
	{"id_aa64afr1_el1",	0b1100000000101101},
	{"id_aa64dfr0_el1",	0b1100000000101100},
	{"id_aa64isar0_el1",	0b1100000000110000},
	{"id_aa64isar1_el1",	0b1100000000110001},
	{"id_aa64mmfr0_el1",	0b1100000000111000},
	{"id_aa64mmfr1_el1",	0b1100000000111001},
	{"id_aa64pfr0_el1",	0b1100000000100000},
	{"id_aa64pfr1_el1",	0b1100000000100001},
	{"ifsr32_el2",		0b1110001010000001},
	{"isr_el1",		0b1100011000001000},
	{"mair_el1",		0b1100010100010000},
	{"mair_el2",		0b1110010100010000},
	{"mair_el3",		0b1111010100010000},
	{"midr_el1",		0b1100000000000000},
	{"mpidr_el1",		0b1100000000000101},
	{"nzcv",		0b1101101000010000},
	{"revidr_el1",		0b1100000000000110},
	{"rmr_el3",		0b1111011000000010},
	{"par_el1",		0b1100001110100000},
	{"rvbar_el3",		0b1111011000000001},
	{"scr_el3",		0b1111000010001000},
	{"sctlr_el1",		0b1100000010000000},
	{"sctlr_el2",		0b1110000010000000},
	{"sctlr_el3",		0b1111000010000000},
	{"sp_el0",		0b1100001000001000},
	{"sp_el1",		0b1110001000001000},
	{"spsel",		0b1100001000010000},
	{"spsr_abt",		0b1110001000011001},
	{"spsr_el1",		0b1100001000000000},
	{"spsr_el2",		0b1110001000000000},
	{"spsr_el3",		0b1111001000000000},
	{"spsr_fiq",		0b1110001000011011},
	{"spsr_irq",		0b1110001000011000},
	{"spsr_und",		0b1110001000011010},
	{"tcr_el1",		0b1100000100000010},
	{"tcr_el2",		0b1110000100000010},
	{"tcr_el3",		0b1111000100000010},
	{"tpidr_el0",		0b1101111010000010},
	{"tpidr_el1",		0b1100011010000100},
	{"tpidr_el2",		0b1110011010000010},
	{"tpidr_el3",		0b1111011010000010},
	{"tpidpro_el0",		0b1101111010000011},
	{"vbar_el1",		0b1100011000000000},
	{"vbar_el2",		0b1110011000000000},
	{"vbar_el3",		0b1111011000000000},
	{"vmpidr_el2",		0b1110000000000101},
	{"vpidr_el2",		0b1110000000000000},
	{"ttbr0_el1",		0b1100000100000000},
	{"ttbr0_el2",		0b1110000100000000},
	{"ttbr0_el3",		0b1111000100000000},
	{"ttbr1_el1",		0b1100000100000001},
	{"vtcr_el2",		0b1110000100001010},
	{"vttbr_el2",		0b1110000100001000},
	{NULL,			0b0000000000000000},
};

/* Size(8-byte words) of the log buffer. */
#define RSH_SCRATCH_BUF_CTL_IDX_MASK	0x7f

static int rsh_log_sem_lock(void)
{
	unsigned long timeout;

	/* Take the semaphore. */
	timeout = jiffies + msecs_to_jiffies(100);
	while (readq(rsh_semaphore)) {
		if (time_after(jiffies, timeout))
			return -ETIMEDOUT;
	}

	return 0;
}

static void rsh_log_sem_unlock(void)
{
	writeq(0, rsh_semaphore);
}

static ssize_t rsh_log_store(struct device_driver *drv, const char *buf,
			     size_t count)
{
	int idx, num, len, size = (int)count, level = RSH_LOG_INFO, rc;
	u64 data;

	if (!size)
		return -EINVAL;

	if (!rsh_semaphore || !rsh_scratch_buf_ctl)
		return -EOPNOTSUPP;

	/* Ignore line break at the end. */
	if (buf[size-1] == 0xa)
		size--;

	/* Check the message prefix. */
	for (idx = 0; idx < ARRAY_SIZE(rsh_log_level); idx++) {
		len = strlen(rsh_log_level[idx]);
		if (len + 1 < size && !strncmp(buf, rsh_log_level[idx], len)) {
			buf += len + 1;
			size -= len + 1;
			level = idx;
			break;
		}
	}

	/* Ignore leading spaces. */
	while (size > 0 && buf[0] == ' ') {
		size--;
		buf++;
	}

	/* Take the semaphore. */
	rc = rsh_log_sem_lock();
	if (rc)
		return rc;

	/* Calculate how many words are available. */
	num = (size + sizeof(u64) - 1) / sizeof(u64);
	idx = readq(rsh_scratch_buf_ctl);
	if (idx + num + 1 >= RSH_SCRATCH_BUF_CTL_IDX_MASK)
		num = RSH_SCRATCH_BUF_CTL_IDX_MASK - idx - 1;
	if (num <= 0)
		goto done;

	/* Write Header. */
	data = (BF_RSH_LOG_TYPE_MSG << RSH_LOG_TYPE_SHIFT) |
		((u64)num << RSH_LOG_LEN_SHIFT) |
		((u64)level << RSH_LOG_LEVEL_SHIFT);
	writeq(data, rsh_scratch_buf_data);

	/* Write message. */
	for (idx = 0, len = size; idx < num && len > 0; idx++) {
		if (len <= sizeof(u64)) {
			data = 0;
			memcpy(&data, buf, len);
			len = 0;
		} else {
			memcpy(&data, buf, sizeof(u64));
			len -= sizeof(u64);
			buf += sizeof(u64);
		}
		writeq(data, rsh_scratch_buf_data);
	}

done:
	/* Release the semaphore. */
	rsh_log_sem_unlock();

	/* Ignore the rest if no more space. */
	return count;
}

static char *rsh_log_get_reg_name(u64 opcode)
{
	struct rsh_log_reg *reg = rsh_log_regs;

	while (reg->name) {
		if (reg->opcode == opcode)
			return reg->name;
		reg++;
	}

	return "unknown";
}

static int rsh_log_show_crash(u64 hdr, char *buf, int size)
{
	int i, module, type, len, n = 0;
	u32 pc, syndrome, ec;
	u64 opcode, data;
	char *p = buf;

	module = BF_RSH_LOG_HEADER_GET(MOD, hdr);
	if (module >= ARRAY_SIZE(rsh_log_mod))
		module = 0;
	type = BF_RSH_LOG_HEADER_GET(TYPE, hdr);
	len = BF_RSH_LOG_HEADER_GET(LEN, hdr);

	if (type == BF_RSH_LOG_TYPE_EXCEPTION) {
		syndrome = BF_RSH_LOG_HEADER_GET(SYNDROME, hdr);
		ec = syndrome >> AARCH64_ESR_ELX_EXCEPTION_CLASS_SHIFT;
		n = snprintf(p, size, " Exception(%s): syndrome = 0x%x%s\n",
			    rsh_log_mod[module], syndrome,
			    (ec == 0x24 || ec == 0x25) ? "(Data Abort)" :
			    (ec == 0x2f) ? "(SError)" : "");
	} else if (type == BF_RSH_LOG_TYPE_PANIC) {
		pc = BF_RSH_LOG_HEADER_GET(PC, hdr);
		n = snprintf(p, size,
			     " PANIC(%s): PC = 0x%x\n", rsh_log_mod[module],
			     pc);
	}
	if (n > 0) {
		p += n;
		size -= n;
	}

	/*
	 * Read the registers in a loop. 'len' is the total number of words in
	 * 8-bytes. Two words are read in each loop.
	 */
	for (i = 0; i < len/2; i++) {
		opcode = readq(rsh_scratch_buf_data);
		data = readq(rsh_scratch_buf_data);

		opcode = (opcode >> AARCH64_MRS_REG_SHIFT) &
			AARCH64_MRS_REG_MASK;
		n = snprintf(p, size,
			     "   %-16s0x%llx\n", rsh_log_get_reg_name(opcode),
			     (unsigned long long)data);
		if (n > 0) {
			p += n;
			size -= n;
		}
	}

	return p - buf;
}

static int rsh_log_format_msg(char *buf, int size, const char *msg, ...)
{
	va_list args;
	int len;

	va_start(args, msg);
	len = vsnprintf(buf, size, msg, args);
	va_end(args);

	return len;
}

static int rsh_log_show_msg(u64 hdr, char *buf, int size)
{
	int has_arg = BF_RSH_LOG_HEADER_GET(HAS_ARG, hdr);
	int level = BF_RSH_LOG_HEADER_GET(LEVEL, hdr);
	int module = BF_RSH_LOG_HEADER_GET(MOD, hdr);
	int len = BF_RSH_LOG_HEADER_GET(LEN, hdr);
	u32 arg = BF_RSH_LOG_HEADER_GET(ARG, hdr);
	char *msg, *p;
	u64 data;

	if (len <= 0)
		return -EINVAL;

	if (module >= ARRAY_SIZE(rsh_log_mod))
		module = 0;

	if (level >= ARRAY_SIZE(rsh_log_level))
		level = 0;

	msg = kmalloc(len * sizeof(u64) + 1, GFP_KERNEL);
	if (!msg)
		return 0;
	p = msg;

	while (len--) {
		data = readq(rsh_scratch_buf_data);
		memcpy(p, &data, sizeof(data));
		p += sizeof(data);
	}
	*p = '\0';
	if (!has_arg) {
		len = snprintf(buf, size, " %s[%s]: %s\n", rsh_log_level[level],
			       rsh_log_mod[module], msg);
	} else {
		len = snprintf(buf, size, " %s[%s]: ", rsh_log_level[level],
			       rsh_log_mod[module]);
		len += rsh_log_format_msg(buf + len, size - len, msg, arg);
		len += snprintf(buf + len, size - len, "\n");
	}

	kfree(msg);
	return len;
}

static ssize_t rsh_log_show(struct device_driver *drv, char *buf)
{
	u64 hdr;
	char *p = buf;
	int i, n, rc, idx, type, len, size = PAGE_SIZE;

	if (!rsh_semaphore || !rsh_scratch_buf_ctl)
		return -EOPNOTSUPP;

	/* Take the semaphore. */
	rc = rsh_log_sem_lock();
	if (rc)
		return rc;

	/* Save the current index and read from 0. */
	idx = readq(rsh_scratch_buf_ctl) & RSH_SCRATCH_BUF_CTL_IDX_MASK;
	if (!idx)
		goto done;
	writeq(0, rsh_scratch_buf_ctl);

	i = 0;
	while (i < idx) {
		hdr = readq(rsh_scratch_buf_data);
		type = BF_RSH_LOG_HEADER_GET(TYPE, hdr);
		len = BF_RSH_LOG_HEADER_GET(LEN, hdr);
		i += 1 + len;
		if (i > idx)
			break;

		switch (type) {
		case BF_RSH_LOG_TYPE_PANIC:
		case BF_RSH_LOG_TYPE_EXCEPTION:
			n = rsh_log_show_crash(hdr, p, size);
			p += n;
			size -= n;
			break;
		case BF_RSH_LOG_TYPE_MSG:
			n = rsh_log_show_msg(hdr, p, size);
			p += n;
			size -= n;
			break;
		default:
			/* Drain this message. */
			while (len--)
				(void) readq(rsh_scratch_buf_data);
			break;
		}
	}

	if (rsh_log_clear_on_read)
		writeq(0, rsh_scratch_buf_ctl);
	else
		writeq(idx, rsh_scratch_buf_ctl);

done:
	/* Release the semaphore. */
	rsh_log_sem_unlock();

	return p - buf;
}

static DRIVER_ATTR_RW(post_reset_wdog);
static DRIVER_ATTR_RW(reset_action);
static DRIVER_ATTR_RW(second_reset_action);
static DRIVER_ATTR_RO(lifecycle_state);
static DRIVER_ATTR_RO(secure_boot_fuse_state);
static DRIVER_ATTR_WO(fw_reset);
static DRIVER_ATTR_RW(oob_mac);
static DRIVER_ATTR_RW(opn);
static DRIVER_ATTR_RW(sku);
static DRIVER_ATTR_RW(modl);
static DRIVER_ATTR_RW(sn);
static DRIVER_ATTR_RW(uuid);
static DRIVER_ATTR_RW(rev);
static DRIVER_ATTR_WO(mfg_lock);
static DRIVER_ATTR_RW(rsh_log);
static DRIVER_ATTR_RW(large_icm);

static struct attribute *mbc_dev_attrs[] = {
	&driver_attr_post_reset_wdog.attr,
	&driver_attr_reset_action.attr,
	&driver_attr_second_reset_action.attr,
	&driver_attr_lifecycle_state.attr,
	&driver_attr_secure_boot_fuse_state.attr,
	&driver_attr_fw_reset.attr,
	&driver_attr_oob_mac.attr,
	&driver_attr_opn.attr,
	&driver_attr_sku.attr,
	&driver_attr_modl.attr,
	&driver_attr_sn.attr,
	&driver_attr_uuid.attr,
	&driver_attr_rev.attr,
	&driver_attr_mfg_lock.attr,
	&driver_attr_rsh_log.attr,
	&driver_attr_large_icm.attr,
	NULL
};

static struct attribute_group mbc_attr_group = {
	.attrs = mbc_dev_attrs
};

static const struct attribute_group *mbc_attr_groups[] = {
	&mbc_attr_group,
	NULL
};

static const struct of_device_id mbc_dt_ids[] = {
	{.compatible = "mellanox,bootctl"},
	{},
};

MODULE_DEVICE_TABLE(of, mbc_dt_ids);

static const struct acpi_device_id mbc_acpi_ids[] = {
	{"MLNXBF04", 0},
	{},
};

MODULE_DEVICE_TABLE(acpi, mbc_acpi_ids);

static ssize_t mbc_bootfifo_read_raw(struct file *filp, struct kobject *kobj,
				     struct bin_attribute *bin_attr,
				     char *buf, loff_t pos, size_t count)
{
	unsigned long timeout = jiffies + HZ / 2;
	char *p = buf;
	int cnt = 0;
	u64 data;

	/* Give up reading if no more data within 500ms. */
	while (count >= sizeof(data)) {
		if (!cnt) {
			cnt = readq(rsh_boot_cnt);
			if (!cnt) {
				if (time_after(jiffies, timeout))
					break;
				udelay(10);
				continue;
			}
		}

		data = readq(rsh_boot_data);
		memcpy(p, &data, sizeof(data));
		count -= sizeof(data);
		p += sizeof(data);
		cnt--;
		timeout = jiffies + HZ / 2;
	}

	return p - buf;
}

static struct bin_attribute mbc_bootfifo_sysfs_attr = {
	.attr = { .name = "bootfifo", .mode = 0400 },
	.read = mbc_bootfifo_read_raw,
};

static int mbc_probe(struct platform_device *pdev)
{
	struct resource *resource;
	struct arm_smccc_res res;
	void __iomem *data;
	int err;

	resource = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!resource)
		return -ENODEV;
	rsh_boot_data = devm_ioremap_resource(&pdev->dev, resource);
	if (IS_ERR(rsh_boot_data))
		return PTR_ERR(rsh_boot_data);

	resource = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!resource)
		return -ENODEV;
	rsh_boot_cnt = devm_ioremap_resource(&pdev->dev, resource);
	if (IS_ERR(rsh_boot_cnt))
		return PTR_ERR(rsh_boot_cnt);

	resource = platform_get_resource(pdev, IORESOURCE_MEM, 2);
	if (resource) {
		data = devm_ioremap_resource(&pdev->dev, resource);
		if (!IS_ERR(data))
			rsh_semaphore = data;
	}

	resource = platform_get_resource(pdev, IORESOURCE_MEM, 3);
	if (resource) {
		data = devm_ioremap_resource(&pdev->dev, resource);
		if (!IS_ERR(data)) {
			rsh_scratch_buf_ctl = data + RSH_SCRATCH_BUF_CTL_OFF;
			rsh_scratch_buf_data = data + RSH_SCRATCH_BUF_DATA_OFF;
		}
	}

	/*
	 * Ensure we have the UUID we expect for this service.
	 * Note that the functionality we want is present in the first
	 * released version of this service, so we don't check the version.
	 */
	arm_smccc_smc(MLNX_SIP_SVC_UID, 0, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0 != 0x89c036b4 || res.a1 != 0x11e6e7d7 ||
	    res.a2 != 0x1a009787 || res.a3 != 0xc4bf00ca)
		return -ENODEV;

	/*
	 * When watchdog is used, it sets the boot mode to MLNX_BOOT_SWAP_EMMC
	 * in case of boot failures. However it doesn't clear the state if there
	 * is no failure. Restore the default boot mode here to avoid any
	 * unnecessary boot partition swapping.
	 */
	if (smc_call1(MLNX_SET_RESET_ACTION, MLNX_BOOT_EMMC) < 0)
		pr_err("Unable to reset the EMMC boot mode\n");

	err = sysfs_create_bin_file(&pdev->dev.kobj, &mbc_bootfifo_sysfs_attr);
	if (err) {
		pr_err("Unable to create bootfifo sysfs file, error %d\n", err);
		return err;
	}

	pr_info("%s (version %s)\n", DRIVER_DESCRIPTION, DRIVER_VERSION);

	return 0;
}

static int mbc_remove(struct platform_device *pdev)
{
	sysfs_remove_bin_file(&pdev->dev.kobj, &mbc_bootfifo_sysfs_attr);

	return 0;
}

static struct platform_driver mbc_driver = {
	.probe = mbc_probe,
	.remove = mbc_remove,
	.driver = {
		.name = DRIVER_NAME,
		.groups = mbc_attr_groups,
		.of_match_table = mbc_dt_ids,
		.acpi_match_table = ACPI_PTR(mbc_acpi_ids),
	}
};

module_platform_driver(mbc_driver);

MODULE_DESCRIPTION(DRIVER_DESCRIPTION);
MODULE_VERSION(DRIVER_VERSION);
MODULE_AUTHOR("Shravan Kumar Ramani <shravankr@nvidia.com>");
MODULE_LICENSE("Dual BSD/GPL");
