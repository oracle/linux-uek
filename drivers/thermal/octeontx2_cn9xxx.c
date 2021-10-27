// SPDX-License-Identifier: GPL-2.0-only
/*
 * Temperature sensor devices definition for CN96XX and CN98XX SoCs
 *
 * Author: Eric Saint Etienne <eric.saint.etienne@oracle.com>
 *
 * Copyright (c) 2020, Oracle and/or its affiliates.
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
#include <asm/cputype.h>

/*
 * CN96XX contains ten and CN98XX contains sixteen on-die calibrated
 * (± 5° Celsius) temperature sensors named TSN.
 */

#define TSN_TS_INSTANCES_BASE_ADDR 0x87e0c0000000ULL
#define TSN_TS_INSTANCE_SIZE       0x1000000

#define TSN_TS_INSTANCE_START(num) \
	(TSN_TS_INSTANCES_BASE_ADDR + (num) * TSN_TS_INSTANCE_SIZE)

#define TSN_TS_INSTANCE_END(num) \
	(TSN_TS_INSTANCE_START(num) + TSN_TS_INSTANCE_SIZE - 1)

#define TSN_INSTANCE_RESOURCE(num) \
	{ \
		.start = TSN_TS_INSTANCE_START(num), \
		.end   = TSN_TS_INSTANCE_END(num), \
		.flags = IORESOURCE_MEM \
	}

struct resource resources[] = {
	TSN_INSTANCE_RESOURCE(0),
	TSN_INSTANCE_RESOURCE(1),
	TSN_INSTANCE_RESOURCE(2),
	TSN_INSTANCE_RESOURCE(3),
	TSN_INSTANCE_RESOURCE(4),
	TSN_INSTANCE_RESOURCE(5),
	TSN_INSTANCE_RESOURCE(6),
	TSN_INSTANCE_RESOURCE(7),
	TSN_INSTANCE_RESOURCE(8),
	TSN_INSTANCE_RESOURCE(9),
	TSN_INSTANCE_RESOURCE(10),
	TSN_INSTANCE_RESOURCE(11),
	TSN_INSTANCE_RESOURCE(12),
	TSN_INSTANCE_RESOURCE(13),
	TSN_INSTANCE_RESOURCE(14),
	TSN_INSTANCE_RESOURCE(15),
};

#define DRIVER_NAME "octeontx2_thermal"

#define TSN_INSTANCE_DEVICE(num) \
	{ \
		.name	       = "sensor" #num, \
		.resource      = &resources[(num)], \
		.num_resources = 1, \
		.driver_override = DRIVER_NAME \
	}

struct platform_device devices[] = {
	TSN_INSTANCE_DEVICE(0),
	TSN_INSTANCE_DEVICE(1),
	TSN_INSTANCE_DEVICE(2),
	TSN_INSTANCE_DEVICE(3),
	TSN_INSTANCE_DEVICE(4),
	TSN_INSTANCE_DEVICE(5),
	TSN_INSTANCE_DEVICE(6),
	TSN_INSTANCE_DEVICE(7),
	TSN_INSTANCE_DEVICE(8),
	TSN_INSTANCE_DEVICE(9),
	TSN_INSTANCE_DEVICE(10),
	TSN_INSTANCE_DEVICE(11),
	TSN_INSTANCE_DEVICE(12),
	TSN_INSTANCE_DEVICE(13),
	TSN_INSTANCE_DEVICE(14),
	TSN_INSTANCE_DEVICE(15),
};

static __initdata struct platform_device *pdevs[] = {
	&devices[0],
	&devices[1],
	&devices[2],
	&devices[3],
	&devices[4],
	&devices[5],
	&devices[6],
	&devices[7],
	&devices[8],
	&devices[9],
	&devices[10],
	&devices[11],
	&devices[12],
	&devices[13],
	&devices[14],
	&devices[15],
};

static inline int machine_is_octeon_cn96xx(void)
{
	return (read_cpuid_id() & MIDR_CPU_MODEL_MASK) ==
		MIDR_OCTX2_96XX;
}

static inline int machine_is_octeon_cn98xx(void)
{
	return (read_cpuid_id() & MIDR_CPU_MODEL_MASK) ==
		MIDR_OCTX2_98XX;
}

static int __init cn9xxx_thermal_init(void)
{
	int n_pdevs;

	if (machine_is_octeon_cn96xx()) {
		n_pdevs = 10;
	} else if (machine_is_octeon_cn98xx()) {
		n_pdevs = 16;
	} else {
		pr_err("machine not a Marvell Octeon CN9XXX\n");
		return -EINVAL;
	}

	return platform_add_devices(pdevs, n_pdevs);
}

device_initcall(cn9xxx_thermal_init);
