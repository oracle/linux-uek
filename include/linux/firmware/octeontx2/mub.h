/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Marvell International Ltd.
 *
 * Marvell Utility Bus
 */

#ifndef _FIRMWARE_MUB_H
#define _FIRMWARE_MUB_H

#include <linux/types.h>
#include <linux/device.h>
#include <linux/sysfs.h>
#include <linux/arm-smccc.h>

struct mub_device {
	/* Properties used to match the device by the driver */
	u64 properties;
#define MUB_SOC_TYPE_ASIM	0x0001
#define MUB_SOC_TYPE_9X		0x0002
#define MUB_SOC_TYPE_10X	0x0004

	int id;
	struct device dev;

	void *p; /* Private field used by the structure owner */
};

struct mub_driver {
	struct device_driver drv;
	int (*probe)(struct mub_device *mdev);
	void (*remove)(struct mub_device *mdev);
	/* Allows to do SMC call on behalf of the device */
	int (*smc)(struct mub_device *mdev, unsigned long a0, unsigned long a1,
	       unsigned long a2, unsigned long a3, unsigned long a4,
	       unsigned long a5, unsigned long a6, unsigned long a7,
	       struct arm_smccc_res *res);
};

/* Driver related side */
int mub_driver_register(struct mub_driver *mdrv);
void mub_driver_unregister(struct mub_driver *mdrv);

/* SMC related functions */
int mub_do_smc(struct mub_device *mdev, unsigned long a0, unsigned long a1,
	       unsigned long a2, unsigned long a3, unsigned long a4,
	       unsigned long a5, unsigned long a6, unsigned long a7,
	       struct arm_smccc_res *res);

/* Helper macros and functions */
static inline struct mub_device *dev_to_mub(struct device *mdev)
{
	return container_of(mdev, struct mub_device, dev);
}

static inline struct mub_driver *drv_to_mub(struct device_driver *mdrv)
{
	return container_of(mdrv, struct mub_driver, drv);
}

/* Device related functions */
static inline void mub_set_data(struct mub_device *mdev, void *data)
{
	mdev->p = data;
}

static inline void *mub_get_data(struct mub_device *mdev)
{
	return mdev->p;
}


#define MUB_ATTR_RW(_name, _show, _store) \
static ssize_t _name##_show(struct device *dev, struct device_attribute *attr, \
			    char *buf)					\
{									\
	struct mub_device *mdev = dev_to_mub(dev);			\
									\
	return _show(mdev, buf);					\
}									\
									\
static ssize_t _name##_store(struct device *dev, struct device_attribute *attr,\
			     const char *buf, size_t count)		\
{									\
	struct mub_device *mdev = dev_to_mub(dev);			\
									\
	return _store(mdev, buf, count);				\
}									\
									\
static DEVICE_ATTR(_name, 0640, _name##_show, _name##_store)

#define MUB_ATTR_RO(_name, _show) \
static ssize_t _name##_show(struct device *dev, struct device_attribute *attr, \
			    char *buf)					\
{									\
	struct mub_device *mdev = dev_to_mub(dev);			\
									\
	return _show(mdev, buf);					\
}									\
									\
static DEVICE_ATTR(_name, 0440, _name##_show, NULL)

#define MUB_ATTR_WO(_name, _store) \
static ssize_t _name##_store(struct device *dev, struct device_attribute *attr,\
			     const char *buf, size_t count)		\
{									\
	struct mub_device *mdev = dev_to_mub(dev);			\
									\
	return _store(mdev, buf, count);				\
}									\
									\
static DEVICE_ATTR(_name, 0200, NULL, _name##_store)

#define MUB_TO_ATTR(a) (&(dev_attr_##a.attr))

struct mub_device *mub_device_register(const char *name, u64 properties,
				       const struct attribute_group **grps);
void mub_device_unregister(struct mub_device *mdev);

#endif /* _FIRMWARE_MUB_H */
