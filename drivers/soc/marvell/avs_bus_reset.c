// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2021 Marvell
 *
 */

#define pr_fmt(fmt)	"otx_avs_bus_reset: " fmt

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/device.h>
#include <linux/mod_devicetable.h>
#include <linux/platform_device.h>
#include <linux/sysfs.h>
#include <linux/mutex.h>
#include <linux/arm-smccc.h>
#include <soc/marvell/octeontx/octeontx_smc.h>


/* Define SMC call to perform AVS actions */
#define PLAT_OCTEONTX_SET_AVS_STATUS  0xc2000b08

/* In case of ASIM as platform */
#define ASIM_PLAT_NAME  "ASIM_PLATFORM"

/* Initial information about AVS. Used internally only */
struct otx_avs_reset_info {
	int avs_status;
};


/* Detect ASIM platform in runtime */
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

/* Protects calls to ATF and integrity of the data used by the device */
static DEFINE_MUTEX(smc_op_lock);

/* Basic attributes for AVS reset */
static ssize_t reset_store(struct device *dev, struct device_attribute *attr,
			   const char *buf, size_t count)
{
	int avs_status, ret;
	struct arm_smccc_res res;
	struct platform_device *pdev;
	struct otx_avs_reset_info *info;

	pdev = container_of(dev, struct platform_device, dev);
	info = pdev->dev.platform_data;

	if (!strncmp(buf, "start", sizeof("start") - 1))
		avs_status = 1;
	else if (!strncmp(buf, "stop", sizeof("stop") - 1))
		avs_status = 0;
	else {
		pr_debug("Unknown value for reset!\n");
		return -EINVAL;
	}

	/* Call SMC to set new status, store the value platform data for device */
	ret = mutex_lock_interruptible(&smc_op_lock);
	if (ret)
		return ret;

	arm_smccc_smc(PLAT_OCTEONTX_SET_AVS_STATUS, avs_status,
		      0, 0, 0, 0, 0, 0, &res);
	if (!res.a0)
		info->avs_status = avs_status;

	mutex_unlock(&smc_op_lock);

	/* In case of error */
	if (res.a0)
		ret = -EFAULT;

	return ret ? ret : count;
}

static ssize_t reset_show(struct device *dev, struct device_attribute *attr,
			  char *buf)
{
	int avs_status, ret;
	struct platform_device *pdev;
	struct otx_avs_reset_info *info;

	pdev = container_of(dev, struct platform_device, dev);
	info = pdev->dev.platform_data;

	ret = mutex_lock_interruptible(&smc_op_lock);
	if (ret)
		return ret;

	avs_status = info->avs_status;
	mutex_unlock(&smc_op_lock);

	return sprintf(buf, "%s\n", avs_status ? "started" : "stopped");
}

static DEVICE_ATTR_RW(reset);

static struct attribute *otx_avs_bus_reset_attrs[] = {
	&dev_attr_reset.attr,
	NULL,
};

static const struct attribute_group otx_avs_bus_reset_attr_group = {
	.attrs = otx_avs_bus_reset_attrs,
};

static int otx_avs_bus_reset_probe(struct platform_device *pdev)
{
	int ret;

	ret = sysfs_create_group(&pdev->dev.kobj, &otx_avs_bus_reset_attr_group);
	if (ret) {
		pr_err("AVS bus reset is unavailable!\n");
		return ret;
	}

	return 0;
}

static int otx_avs_bus_reset_remove(struct platform_device *pdev)
{
	sysfs_remove_group(&pdev->dev.kobj, &otx_avs_bus_reset_attr_group);

	return 0;
}


static const struct platform_device_id otx_avs_bus_reset_ids[] = {
	{
		.name = "soc-avs-bus-reset",
	},
	{},
};

static struct platform_driver otx_avs_bus_reset_driver = {
	.driver = {
			.name = "otx-avs-bus-reset",
		  },
	.probe = otx_avs_bus_reset_probe,
	.remove = otx_avs_bus_reset_remove,
	.id_table = otx_avs_bus_reset_ids,
};

/* Create single reset device for AVS */
static struct otx_avs_reset_info avs_bus_reset_info = {
	.avs_status = 1,  /* AVS bus is active by default, no reset done */
};

static struct platform_device otx_avs_bus_reset_device = {
	.name = "soc-avs-bus-reset",
	.id = -1,
	.dev = {
		.platform_data = &avs_bus_reset_info,
	},
};


static int __init otx_avs_bus_reset_init(void)
{
	int ret;

	/* ASIM ? Don't load this driver */
	if (is_platform_asim())
		return -EPERM;

	/* Chech firmware compatibility */
	ret = octeontx_soc_check_smc();
	if (ret < 0) {
		pr_debug("Platform not supported\n");
		return ret;
	}

	ret = platform_device_register(&otx_avs_bus_reset_device);
	if (ret)
		goto fail_device;

	ret = platform_driver_register(&otx_avs_bus_reset_driver);
	if (ret)
		goto fail_driver;

	return 0;

fail_driver:
	platform_device_unregister(&otx_avs_bus_reset_device);
fail_device:
	pr_err("AVS bus reset is not available! (%d)\n", ret);
	return ret;
}

static void __exit otx_avs_bus_reset_exit(void)
{
	platform_driver_unregister(&otx_avs_bus_reset_driver);
	platform_device_unregister(&otx_avs_bus_reset_device);
}

module_init(otx_avs_bus_reset_init);
module_exit(otx_avs_bus_reset_exit);

MODULE_ALIAS("platform: otx-avs-bus-reset");
MODULE_AUTHOR("Wojciech Bartczak <wbartczak@marvell.com>");
MODULE_DESCRIPTION("Allows to reset AVS bus from userspace");
MODULE_LICENSE("GPL");
