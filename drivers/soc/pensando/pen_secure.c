/*
 * Copyright (c) 2022, Pensando Systems Inc.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/io.h>
#include <linux/spinlock.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/delay.h>
#include <linux/arm-smccc.h>
#include <asm/ptrace.h>
#include <linux/of_platform.h>
#include "pen_secure.h"


static bool secure_mode = false;
static bool secure_mode_init = false;

void pen_secure_regwrite(void __iomem *addr, uint32_t val)
{
	struct arm_smccc_res res = {0};

	arm_smccc_smc(PEN_SECREG_SMC_CALL_FID,
		      PEN_SECREG_SMC_REG_WRITE, (uint64_t)addr,
		      val, 0, 0, 0, 0, &res);

	if (res.a0 != PEN_SECREG_SMC_ERR_NONE) {
		pr_err("pensando-secreg: failed to write data! ret=%d\n", (int)res.a0);
	}
}

uint32_t pen_secure_regread(void __iomem *addr)
{
	struct arm_smccc_res res = {0};

	arm_smccc_smc(PEN_SECREG_SMC_CALL_FID,
		      PEN_SECREG_SMC_REG_READ, (uint64_t)addr,
		      0, 0, 0, 0, 0, &res);

	if (res.a0 != PEN_SECREG_SMC_ERR_NONE) {
		pr_err("pensando-secreg: read failed! ret=%d\n", (int)res.a0);
		return (uint32_t)-1;
	}

	/* result passed back in a1 reg */
	return (uint32_t)res.a1;
}

static int of_get_secure_mode(void)
{
	struct device_node *of_secure;
	int enable = 0;

	/* Get secure mode from OF */
	of_secure = of_find_node_by_path("/secure_mode");
	if (of_secure) {
		if (of_property_read_u32(of_secure, "enable", &enable)) {
			return 0; /* non-secure */
		} else {
			return enable;
		}
	}
	return 0; /* non-secure */
}

bool pen_secure_mode_enabled(void)
{
	if (!secure_mode_init) {
		secure_mode = of_get_secure_mode();
		secure_mode_init = true;
	}

	return secure_mode;
}
