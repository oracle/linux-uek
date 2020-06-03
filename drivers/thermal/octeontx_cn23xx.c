// SPDX-License-Identifier: GPL-2.0-only
/*
 * Temperature sensor device definition for CN23XX SoC
 *
 * Author: Eric Saint Etienne <eric.saint.etienne@oracle.com>
 *
 * Copyright (c) 1991, 2020, Oracle and/or its affiliates.
 */

#include <linux/device.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/thermal.h>
#include <linux/slab.h>
#include <linux/string.h>

#include <asm/octeon/cvmx.h>

/*
 * CN23XX contains one on-die calibrated (± 5° Celsius)
 * temperature sensor named VRM.
 */

#define VRM_TS_INSTANCE_BASE_ADDR 0x1180021000000ULL
#define VRM_TS_INSTANCE_SIZE      0x1000000

static struct resource resource = {
	.start = VRM_TS_INSTANCE_BASE_ADDR,
	.end   = VRM_TS_INSTANCE_BASE_ADDR + VRM_TS_INSTANCE_SIZE - 1,
	.flags = IORESOURCE_MEM
};

#define DRIVER_NAME "octeontx_thermal"

static struct platform_device device = {
	.name	       = "sensor",
	.resource      = &resource,
	.num_resources = 1,
	.driver_override = DRIVER_NAME
};

static int __init cn23xx_thermal_init(void)
{
	if (!OCTEON_IS_MODEL(OCTEON_CN23XX)) {
		pr_err("machine not a Marvell Octeon CN23XX\n");
		return -EINVAL;
	}

	return platform_device_register(&device);
}

device_initcall(cn23xx_thermal_init);
