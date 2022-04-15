// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Following module provides implementation for Marvell Utility Bus.
 * The bus is set of devices (firmware services) and drivers (platform drivers)
 * That form a channel to configure and manage different aspects of firmware
 * operation on OcteonTX2 platforms.
 *
 */

#define pr_fmt(fmt)	"mub: " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/idr.h>
#include <linux/firmware/octeontx2/mub.h>

/* Platform detection */
#define CPU_MODEL_CN10KX_PART				0xd49
#define ASIM_PLAT_NAME  "ASIM_PLATFORM"

static bool is_soc_cn10x(void)
{
	return MIDR_PARTNUM(read_cpuid_id()) == CPU_MODEL_CN10KX_PART;
}

static bool is_soc_cn9x(void)
{
	u32 partnum;

	partnum = MIDR_PARTNUM(read_cpuid_id());

	if ((partnum & 0xbf) || (partnum & 0xaf))
		return true;

	return false;
}

/* Detect ASIM platform */
static bool is_platform_asim(void)
{
	int ret;
	struct device_node *np;
	const char *runplatform;

	np = of_find_node_by_name(NULL, "soc");
	if (!np)
		return false;

	ret = of_property_read_string(np, "runplatform", &runplatform);
	if (!ret) {
		if (!strncmp(runplatform, ASIM_PLAT_NAME,
			     sizeof(ASIM_PLAT_NAME) - 1))
			return true;
	}

	return false;
}

/* Properties used to allow or disallow specific device (function) for
 * the platform
 */
static u64 mub_properties;

static ssize_t compatibility_show(struct bus_type *bus, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%#016llx\n", mub_properties);
}

static BUS_ATTR_RO(compatibility);

static struct attribute *mub_bus_attrs[] = {
	&bus_attr_compatibility.attr,
	NULL,
};

ATTRIBUTE_GROUPS(mub_bus);

static void detect_platform(void)
{
	mub_properties = 0;
	if (is_platform_asim())
		mub_properties |= MUB_SOC_TYPE_ASIM;
	if (is_soc_cn10x())
		mub_properties |= MUB_SOC_TYPE_10X;
	else if (is_soc_cn9x())
		mub_properties |= MUB_SOC_TYPE_9X;
}

/* Bus implementation */
static DEFINE_IDA(mub_ida);

static int mub_probe(struct device *dev)
{
	struct mub_device *mdev = dev_to_mub(dev);
	struct mub_driver *mdrv = drv_to_mub(mdev->dev.driver);

	if (!mdev || !mdrv)
		return -EINVAL;

	return mdrv->probe(mdev);
}

static int mub_remove(struct device *dev)
{
	struct mub_device *mdev = dev_to_mub(dev);
	struct mub_driver *mdrv = drv_to_mub(mdev->dev.driver);

	if (!mdev || !mdrv)
		return -EINVAL;

	mdrv->remove(mdev);

	return 0;
}

static struct bus_type mub_bus_type = {
	.name = "mub",
	.bus_groups = mub_bus_groups,
	.probe = mub_probe,
	.remove = mub_remove,
};

/* Device and driver APIs */
int mub_driver_register(struct mub_driver *mdrv)
{
	mdrv->drv.bus = &mub_bus_type;
	return driver_register(&mdrv->drv);
}
EXPORT_SYMBOL_GPL(mub_driver_register);

void mub_driver_unregister(struct mub_driver *mdrv)
{
	driver_unregister(&mdrv->drv);
}
EXPORT_SYMBOL_GPL(mub_driver_unregister);

/* Release operation for all MUB devices */
static void mub_device_release(struct device *dev)
{
	struct mub_device *mdev = dev_to_mub(dev);

	kfree(mdev);
}

struct mub_device *mub_device_register(const char *name, u64 dev_properties,
				       const struct attribute_group **grps)
{
	struct mub_device *mdev;
	int ret;

	/* Check device requirements against platform properties */
	if (!(dev_properties & mub_properties)) {
		pr_debug("function %s with req: %#llx doesn't match prop: %#llx\n",
			 name, dev_properties, mub_properties);
		return ERR_PTR(-ENOTSUPP);
	}

	mdev = kzalloc(sizeof(*mdev), GFP_KERNEL);
	if (!mdev)
		return ERR_PTR(-ENOMEM);

	ret = ida_simple_get(&mub_ida, 0, 0, GFP_KERNEL);
	if (ret < 0)
		goto no_ida;

	mdev->id = ret;
	mdev->properties = dev_properties;
	mdev->dev.bus = &mub_bus_type;
	mdev->dev.groups = grps;
	mdev->dev.release = mub_device_release;

	if (name)
		dev_set_name(&mdev->dev, "%s", name);
	else
		dev_set_name(&mdev->dev, "mub%d", mdev->id);

	ret = device_register(&mdev->dev);
	if (!ret)
		return mdev;

	ida_simple_remove(&mub_ida, mdev->id);
	put_device(&mdev->dev);
	mdev = NULL;
no_ida:
	kfree(mdev);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(mub_device_register);

void mub_device_unregister(struct mub_device *mdev)
{
	ida_simple_remove(&mub_ida, mdev->id);

	device_unregister(&mdev->dev);
}
EXPORT_SYMBOL_GPL(mub_device_unregister);

/* SMC call API. This functions allows to call SMC for attributes */
int mub_do_smc(struct mub_device *mdev, unsigned long a0, unsigned long a1,
	       unsigned long a2, unsigned long a3, unsigned long a4,
	       unsigned long a5, unsigned long a6, unsigned long a7,
	       struct arm_smccc_res *res)
{
	struct mub_driver *mdrv;

	if (!mdev->dev.driver)
		return -ENXIO;

	mdrv = drv_to_mub(mdev->dev.driver);

	if (!mdrv->smc)
		return mdrv->smc(mdev, a0, a1, a2, a3, a4, a5, a6, a7, res);

	return -ENODEV;

}
EXPORT_SYMBOL_GPL(mub_do_smc);

static int __init mub_init(void)
{
	detect_platform();

	return bus_register(&mub_bus_type);
}
subsys_initcall(mub_init);

static void __exit mub_exit(void)
{
	bus_unregister(&mub_bus_type);
}
module_exit(mub_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Marvell Utility Bus core");
MODULE_AUTHOR("Wojciech Bartczak <wbartczak@marvell.com>");
