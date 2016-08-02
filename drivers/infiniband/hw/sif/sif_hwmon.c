/*
 * Copyright (c) 2016, Oracle and/or its affiliates. All rights reserved.
 *    Author: Francisco Triviño <francisco.trivino@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_hwmon.c: SIF Hardware Monitoring
 */

#include "sif_dev.h"
#include "sif_query.h"
#include "sif_defs.h"
#include "psif_hw_setget.h"
#include "sif_hwmon.h"
#include "psif_hw_data.h"
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>


enum sif_hwmon_attr_type {
	SIF_HWMON_ATTR_TEMP_MAX,
	SIF_HWMON_ATTR_TEMP_MAIN,
	SIF_HWMON_ATTR_TEMP_EPS,
	SIF_HWMON_ATTR_TEMP_IBU,
	SIF_HWMON_ATTR_TEMP_PEU,
	SIF_HWMON_ATTR_TEMP_TSU,
};

static u64 sensor_show(const struct device *device,
		struct device_attribute *attr,
		char *buf,
		int sif_hwmon_attr_temp)
{
        struct sif_dev *sdev = dev_get_drvdata(device);
	struct psif_epsc_csr_req req;
	struct psif_epsc_csr_rsp rsp;

	/* EPSC supports the new requests starting from v.2.8 */
	if (eps_version_ge(&sdev->es[sdev->mbox_epsc], 2, 8)) {
		int ret = 0;

		memset(&req, 0, sizeof(req));
		memset(&rsp, 0, sizeof(rsp));
		req.opcode = EPSC_QUERY;
		req.u.query.data.op = EPSC_QUERY_ON_CHIP_TEMP;
		ret = sif_epsc_wr(sdev, &req, &rsp);

		if (!ret) {
			u16 t = 0;
			struct psif_epsc_query_on_chip_temp *temp =
				(struct psif_epsc_query_on_chip_temp *)&rsp.data;
			switch (sif_hwmon_attr_temp) {
			case SIF_HWMON_ATTR_TEMP_MAX:
				t = temp->max;
				break;
			case SIF_HWMON_ATTR_TEMP_MAIN:
				t = temp->main;
				break;
			case SIF_HWMON_ATTR_TEMP_EPS:
				t = temp->eps;
				break;
			case SIF_HWMON_ATTR_TEMP_IBU:
				t = temp->ibu;
				break;
			case SIF_HWMON_ATTR_TEMP_PEU:
				t = temp->peu;
				break;
			case SIF_HWMON_ATTR_TEMP_TSU:
				t = temp->tsu;
				break;
			default:
				WARN_ON(1);
			}
			sprintf(buf, "%u\n", t);
		}
		else
			sif_log(sdev, SIF_INFO, "Failed to query on chip temperature\n");
	}
	return strlen(buf);
}

/* hwmon-sysfs attributes */
#define SENSOR_DEVICE_SHOW(field)					\
static ssize_t show_sensor_##field(struct device *dev,			\
				struct device_attribute *attr,		\
				char *buf)				\
{									\
	return sensor_show(dev, attr, buf, SIF_HWMON_ATTR_TEMP_##field);\
}

SENSOR_DEVICE_SHOW(MAX);
SENSOR_DEVICE_SHOW(MAIN);
SENSOR_DEVICE_SHOW(EPS);
SENSOR_DEVICE_SHOW(IBU);
SENSOR_DEVICE_SHOW(PEU);
SENSOR_DEVICE_SHOW(TSU);


static SENSOR_DEVICE_ATTR(temp1_max, S_IRUGO, show_sensor_MAX, NULL, 1);
static SENSOR_DEVICE_ATTR(temp1_main, S_IRUGO, show_sensor_MAIN, NULL, 1);
static SENSOR_DEVICE_ATTR(temp1_eps, S_IRUGO, show_sensor_EPS, NULL, 1);
static SENSOR_DEVICE_ATTR(temp1_ibu, S_IRUGO, show_sensor_IBU, NULL, 1);
static SENSOR_DEVICE_ATTR(temp1_peu, S_IRUGO, show_sensor_PEU, NULL, 1);
static SENSOR_DEVICE_ATTR(temp1_tsu, S_IRUGO, show_sensor_TSU, NULL, 1);


static struct attribute *sif_hwmon_attrs[] = {
	&sensor_dev_attr_temp1_max.dev_attr.attr,
	&sensor_dev_attr_temp1_main.dev_attr.attr,
	&sensor_dev_attr_temp1_eps.dev_attr.attr,
	&sensor_dev_attr_temp1_ibu.dev_attr.attr,
	&sensor_dev_attr_temp1_peu.dev_attr.attr,
	&sensor_dev_attr_temp1_tsu.dev_attr.attr,
	NULL,
};

ATTRIBUTE_GROUPS(sif_hwmon);

void sif_register_hwmon_dev(struct sif_dev *sdev)
{
	struct device *dev = &sdev->pdev->dev;
	struct device *hwmon_dev;

	/* Skip hwmon registration for a VF device */
	if (sdev->is_vf) {
		sdev->hwmon_dev = NULL;
		return;
	}
	hwmon_dev = hwmon_device_register_with_groups(dev, sdev->ib_dev.name,
						sdev,
						sif_hwmon_groups);
	if (IS_ERR(hwmon_dev)) {
		dev_err(dev, "Cannot register with hwmon, err=%ld\n",
			PTR_ERR(hwmon_dev));
		hwmon_dev = NULL;
	}
	sdev->hwmon_dev = hwmon_dev;
}

void sif_unregister_hwmon_dev(struct sif_dev *sdev)
{
	struct device *hwmon_dev = sdev->hwmon_dev;
	if (hwmon_dev) {
		hwmon_device_unregister(hwmon_dev);
		sdev->hwmon_dev = NULL;
	}
}

