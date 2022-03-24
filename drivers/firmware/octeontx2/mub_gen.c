// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Following module provides generic driver for Marvell Utility Bus.
 * Generic driver abstracts the platform for runtime services.
 * It is responsible for services binding based on the platform characteristics.
 *
 */

#define pr_fmt(fmt)	"mub-gen: " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/arm-smccc.h>
#include <linux/firmware/octeontx2/mub.h>
#include <asm/cputype.h>

/* SMC call to ID the Arm trusted firmware */
#define OCTEONTX_ARM_SMC_SVC_UID			0xc200ff01
/* Discover type of the platform */
const int octeontx_svc_uuid[] = {
	0x6ff498cf,
	0x5a4e9cfa,
	0x2f2a3aa4,
	0x5945b105
};

/* Detects compatible firmware using SMC call */
static bool is_fw_compatible(void)
{
	struct arm_smccc_res res;

	/* Is it Arm Trusted firmware for OcetonTX2 ? */
	arm_smccc_smc(OCTEONTX_ARM_SMC_SVC_UID,
		      0, 0, 0, 0, 0, 0, 0, &res);

	if (res.a0 != octeontx_svc_uuid[0] || res.a1 != octeontx_svc_uuid[1] ||
	    res.a2 != octeontx_svc_uuid[2] || res.a3 != octeontx_svc_uuid[3])
		return false;

	return true;
}

static int mub_gen_probe(struct mub_device *mdev)
{
	/* Allow all devices, the bus checks SoC compatibility */
	return 0;
}

static void mub_gen_remove(struct mub_device *mdev)
{
	/* No action to be done for now */
}

/* Single mutex protecting ATF */
static DEFINE_MUTEX(smc_op_lock);

static int mub_gen_smc(struct mub_device *mdev, unsigned long a0,
		       unsigned long a1, unsigned long a2, unsigned long a3,
		       unsigned long a4, unsigned long a5, unsigned long a6,
		       unsigned long a7, struct arm_smccc_res *res)
{
	int ret;

	ret = mutex_lock_interruptible(&smc_op_lock);
	if (ret)
		return ret;

	arm_smccc_smc(a0, a1, a2, a3, a4, a5, a6, a7, res);
	mutex_unlock(&smc_op_lock);

	return 0;
}


static struct mub_driver mub_gen_driver = {
	.drv = {
		.name = "mub_generic",
		.owner = THIS_MODULE,
	},
	.probe = mub_gen_probe,
	.remove = mub_gen_remove,
	.smc = mub_gen_smc,
};

static int __init mub_gen_init(void)
{
	int ret;

	if (!is_fw_compatible()) {
		pr_err("Firmware is not compatible with MUB\n");
		return -ENOTSUPP;
	}

	ret = mub_driver_register(&mub_gen_driver);
	if (ret)
		pr_err("Can't register the driver. %d\n", ret);

	return ret;
}
module_init(mub_gen_init);

static void __exit mub_gen_exit(void)
{
	mub_driver_unregister(&mub_gen_driver);
}
module_exit(mub_gen_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Marvell Utility Bus generic driver");
MODULE_AUTHOR("Wojciech Bartczak <wbartczak@marvell.com>");
