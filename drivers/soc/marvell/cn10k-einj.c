// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Marvell
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/arm-smccc.h>

#define PLAT_OCTEONTX_INJECT_ERROR	(0xc2000b10)

#define PLAT_OCTEONTX_EINJ_DSS		(0xd)

#define EINJ_MAX_PARAMS 7

static int einj_setup(const char *val, const struct kernel_param *kp);

static const struct kernel_param_ops einj_ops = {
		.set = einj_setup,
		.get = param_get_ullong,
};

static u64 params[EINJ_MAX_PARAMS];
module_param_cb(smc, &einj_ops, &params, 0644);
MODULE_PARM_DESC(smc, "Setup error injection parameters "
		"		0xd: Injecting error to DSS controller"
		"		address: Physical Address to corrupt"
		"		flags:"
		"			[0:7] bit position to corrupt"
		"			[8] error type 0 = DED (double), 1 = SEC (single)"
		"		echo \"0xd,0x3fffff000,0x101\" > /sys/module/cn10k_einj/parameters/smc");

static int einj_setup(const char *val, const struct kernel_param *kp)
{
	struct arm_smccc_res res;
	char *str = (char *) val;
	int rc = 0;
	int i = 0;

	if (!str)
		return -EINVAL;

	for (i = 0; i < EINJ_MAX_PARAMS; i++)
		params[i] = 0;

	for (i = 0; i < EINJ_MAX_PARAMS && *str; i++) {

		int len = strcspn(str, ",");
		char *nxt = len ? str + len + 1 : "";

		if (len)
			str[len] = '\0';

		rc = kstrtoull(str, 0, &params[i]);

		pr_debug("%s: (%s/%s) smc_params[%d]=%llx e?%d\n", __func__, str, nxt,
				i, params[i], rc);
		if (len)
			str[len] = ',';
		str = nxt;
	}

	switch (params[0]) {
	case PLAT_OCTEONTX_EINJ_DSS:
		params[3] = params[2];
		params[2] >>= 8;
		params[2] &= 1;
		params[3] &= 0xFF;
		break;
	default:
		return -EINVAL;
	}

	pr_debug("%s %llx %llx %llx %llx %llx %llx %llx\n", __func__, params[0],
			params[1], params[2], params[3], params[4], params[5], params[6]);

	arm_smccc_smc(PLAT_OCTEONTX_INJECT_ERROR, params[0], params[1], params[2],
			params[3], params[4], params[5], params[6], &res);

	if (kp)
		WRITE_ONCE(*(ulong *)kp->arg, res.a0);

	return 0;
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marvell Ink");
MODULE_DESCRIPTION("Marvell CN10K ECC Injector");
