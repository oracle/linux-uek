// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021-2022 Marvell
 *
 *
 * The module presents simple sysfs interface to control
 * MAC address assigned to network devices.
 *
 */

#define pr_fmt(fmt)	"mac_mgmt: " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/firmware/octeontx2/mub.h>

/* Maximum number of MAC addressess to pass */
#define MAC_MGMT_MAX_MACS_NUM	32

/* Single entry description */
struct mac_info {
	u32	index;
	u32	reserved; /* Must be zero */
	union {
		u64	mac_addr;
		u8      bytes[8];
	} s;
};

/* SMC call number used to set MAC address */
#define PLAT_OCTEONTX_MAC_MGMT_SET_ADDR	0xc2000e10

/** Set MAC address given by user
 *
 * The attribute handler parses and passes MAC address information to ATF.
 * ATF is responsible for further data processing.
 * Information contains index and MAC address itself. Data are validated
 * in this call.
 *
 */
static ssize_t mac_addr_store(struct mub_device *mdev, const char *buf,
			      ssize_t count)
{
	struct arm_smccc_res res;
	int processed, ret;
	struct mac_info minfo;

	ret = sscanf(buf, "%u %llx %n", &minfo.index, &minfo.s.mac_addr, &processed);
	if (ret <= 0)
		return -EINVAL;

	if (processed < 2)  /* Expect at least two characters in input */
		return -EINVAL;

	if (minfo.index > MAC_MGMT_MAX_MACS_NUM)
		return -EINVAL;

	if (!minfo.s.mac_addr)
		return -EINVAL;

	pr_debug("Idx: %u, addr: %llx\n", minfo.index, minfo.s.mac_addr);

	ret = mub_do_smc(mdev, PLAT_OCTEONTX_MAC_MGMT_SET_ADDR,
			 minfo.index, minfo.s.mac_addr, 0, 0, 0, 0, 0, &res);
	if (ret)
		return ret;

	if (res.a0)
		return -EINVAL;

	return count;
}

MUB_ATTR_WO(set_mac_addr, mac_addr_store);

static struct attribute *mac_addr_attrs[] = {
	MUB_TO_ATTR(set_mac_addr),
	NULL,
};

static const struct attribute_group mac_addr_attr_group = {
	.attrs = mac_addr_attrs,
};

static const struct attribute_group *mac_addr_attr_groups[] = {
	&mac_addr_attr_group,
	NULL,
};

static struct mub_device *mac_addr_device;

static int __init mac_mgmt_init(void)
{
	mac_addr_device = mub_device_register("mac-management",
					      MUB_SOC_TYPE_10X |
					      MUB_SOC_TYPE_ASIM,
					      mac_addr_attr_groups);
	if (IS_ERR(mac_addr_device))
		return PTR_ERR(mac_addr_device);

	pr_debug("Marvell CN10K MAC management\n");

	return 0;
}
module_init(mac_mgmt_init);

static void __exit mac_mgmt_exit(void)
{
	mub_device_unregister(mac_addr_device);
}
module_exit(mac_mgmt_exit);

MODULE_AUTHOR("Wojciech Bartczak <wbartczak@marvell.com>");
MODULE_DESCRIPTION("MAC address management for Marvell CN10K");
MODULE_LICENSE("GPL");
