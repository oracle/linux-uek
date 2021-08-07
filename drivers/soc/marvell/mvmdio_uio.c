// SPDX-License-Identifier: GPL-2.0
/* Marvell's MDIO bus uio driver
 *
 * Copyright (C) 2021 Marvell
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) "mvmdio-uio: " fmt

#include <linux/of_mdio.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#define MVMDIO_DEV_NAME "mvmdio-uio"
#define MVMDIO_CLASS_NAME "mvmdio-uio-class"
#define MAX_MDIO_BUS 8

static struct mii_bus *mv_mii_buses[MAX_MDIO_BUS];
static struct class *mv_cl;
static int major;

struct mii_data {
	int bus_id;
	int phy_id;
	int reg;
	u16 data;
};

/* Create character device */
static int mv_mdio_device_open(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t mv_mdio_device_read(struct file *file,
		char *buf, size_t count, loff_t *f_pos)
{
	int ret;
	struct mii_data mii;
	struct mii_bus *bus;

	if (copy_from_user(&mii, (struct mii_data *)buf, sizeof(struct mii_data))) {
		pr_err("copy_from_user failed\n");
		return -EFAULT;
	}

	if (mii.bus_id < 0 || mii.bus_id >= MAX_MDIO_BUS)
		return -EINVAL;

	bus = mv_mii_buses[mii.bus_id];
	if (!bus) {
		pr_err("invalid bus_id\n");
		return -EINVAL;
	}

	ret = mdiobus_read(bus, mii.phy_id, mii.reg);
	if (ret < 0) {
		pr_err("smi read failed at Bus: %X, devAddr: %X, regAddr: %X\n",
			mii.bus_id, mii.phy_id, mii.reg);
		return ret;
	}
	mii.data = (u16)ret;

	if (copy_to_user((struct mii_data *)buf, &mii, sizeof(struct mii_data))) {
		pr_err("copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static ssize_t mv_mdio_device_write(struct file *file,
		const char *buf, size_t count, loff_t *f_pos)
{
	int ret;
	struct mii_data mii;
	struct mii_bus *bus;

	if (copy_from_user(&mii, (struct mii_data *)buf, sizeof(struct mii_data))) {
		pr_err("copy_from_user failed\n");
		return -EFAULT;
	}

	if (mii.bus_id < 0 || mii.bus_id >= MAX_MDIO_BUS)
		return -EINVAL;

	bus = mv_mii_buses[mii.bus_id];
	if (!bus) {
		pr_err("invalid bus_id\n");
		return -EINVAL;
	}

	ret = mdiobus_write(bus, mii.phy_id, mii.reg, mii.data);
	if (ret < 0) {
		pr_err("smi write failed at bus: %X, devAddr: %X, regAddr: %X\n",
			mii.bus_id, mii.phy_id, mii.reg);
		return ret;
	}

	return 0;
}

static int mv_mdio_device_close(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations mvmdio_fops = {
	.owner                = THIS_MODULE,
	.open                 = mv_mdio_device_open,
	.read                 = mv_mdio_device_read,
	.write                = mv_mdio_device_write,
	.release              = mv_mdio_device_close,
};

static int __init mv_mdio_device_init(void)
{
	struct device_node *np;
	struct device_node *mdio;
	struct mii_bus *mv_mii_bus;
	static struct device *mvmdio_dev;
	int bus_count = 0;
	int ret;

	memset(mv_mii_buses, 0, sizeof(mv_mii_buses));
	for_each_compatible_node(np, NULL, "marvell,mvmdio-uio") {
		if (bus_count == MAX_MDIO_BUS)
			break;

		mdio = of_parse_phandle(np, "mii-bus", 0);
		if (mdio == NULL) {
			pr_err("parse handle failed\n");
			continue;
		}
		mv_mii_bus = of_mdio_find_bus(mdio);
		if (mv_mii_bus == NULL) {
			pr_err("mdio find bus failed\n");
			continue;
		}
		pr_info("bus %d added at %s\n",
			bus_count, mdio->name);
		mv_mii_buses[bus_count++] = mv_mii_bus;
	}

	if (bus_count == 0) {
		pr_err("no useful mdio bus found\n");
		return -ENODEV;
	}


	ret = register_chrdev(0, MVMDIO_DEV_NAME, &mvmdio_fops);
	if (ret < 0) {
		pr_err("failed to register a char device\n");
		return ret;
	}

	major = ret;

	mv_cl = class_create(THIS_MODULE, MVMDIO_CLASS_NAME);
	if (IS_ERR(mv_cl)) {
		ret = PTR_ERR(mv_cl);
		goto error_class;
	}

	mvmdio_dev = device_create(mv_cl, NULL,
		MKDEV(major, 0), NULL, MVMDIO_DEV_NAME);

	if (IS_ERR(mvmdio_dev)) {
		ret = PTR_ERR(mvmdio_dev);
		goto error_device;
	}

	return 0;

error_device:
	class_destroy(mv_cl);
error_class:
	unregister_chrdev(major, MVMDIO_DEV_NAME);

	pr_err("driver registration failed\n");
	return ret;
}

static void __exit mv_mdio_device_exit(void)
{
	device_destroy(mv_cl, MKDEV(major, 0));
	class_destroy(mv_cl);
	unregister_chrdev(major, MVMDIO_DEV_NAME);
}

late_initcall(mv_mdio_device_init);
module_exit(mv_mdio_device_exit);

MODULE_DESCRIPTION("Marvell MDIO uio driver");
MODULE_LICENSE("GPL v2");
