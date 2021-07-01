// SPDX-License-Identifier: GPL-2.0
/* Hardware device CSR Access driver
 * Copyright (C) 2021 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* This driver supports Read/Write of only OcteonTx2/OcteonTx3 HW device
 * config registers. Read/Write of System Registers are not supported.
 */

#include <linux/device.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#define DEVICE_NAME			"hw_access"
#define CLASS_NAME			"hw_access_class"
/* Smallest start physical address of all HW devices */
#define REG_PHYS_BASEADDR		0x802000000000
/* Last physical address - First phsycial address + 1 will be the
 * length of IO remapped block
 * 0x87E0E24FFFFF - 0x802000000000 + 1 = 0x7C0E2500000
 * Last phsyical address is the highest end physical address of all HW devices.
 * First physical address is the smallest start physical address of all HW
 * devices.
 */
#define REG_SPACE_MAPSIZE		0x7C0E2500000
#define CSR_READ_IOCTL			0
#define CSR_WRITE_IOCTL			1

struct hw_reg_cfg {
	u64	regaddr; /* Register physical address within a hw device */
	u64	regval; /* Register value to be read or to write */
};

static struct class *hw_reg_class;
static int majorNumber;

static int hw_access_open(struct inode *inode, struct file *filp)
{
	void __iomem *reg_base = NULL;
	int err;

	reg_base = ioremap(REG_PHYS_BASEADDR, REG_SPACE_MAPSIZE);
	if (!reg_base) {
		pr_err("Unable to map Physical Base Address\n");
		err = -ENOMEM;
		return err;
	}

	filp->private_data = reg_base;

	return 0;
}

static long hw_access_ioctl(struct file *filp, unsigned int cmd,
			   unsigned long arg)
{
	void __iomem *regbase = filp->private_data;
	struct hw_reg_cfg reg_cfg;
	u64 regoff;

	switch (cmd) {
	case CSR_READ_IOCTL:
		if (copy_from_user(&reg_cfg, (void __user *)arg,
				   sizeof(struct hw_reg_cfg))) {
			pr_err("Read Fault copy from user\n");

			return -EFAULT;
		}

		if (reg_cfg.regaddr < REG_PHYS_BASEADDR ||
		    reg_cfg.regaddr >= REG_PHYS_BASEADDR + REG_SPACE_MAPSIZE) {
			pr_err("Address [0x%llx] out of range "
			       "[0x%lx - 0x%lx]\n", reg_cfg.regaddr,
			       REG_PHYS_BASEADDR,
			       REG_PHYS_BASEADDR + REG_SPACE_MAPSIZE);

			return -EFAULT;
		}

		/* Only 64 bit reads/writes are allowed */
		reg_cfg.regaddr &= ~0x07ULL;
		regoff = reg_cfg.regaddr - REG_PHYS_BASEADDR;
		reg_cfg.regval = readq(regbase + regoff);

		if (copy_to_user((void __user *)(unsigned long)arg,
				 &reg_cfg,
				 sizeof(struct hw_reg_cfg))) {
			pr_err("Fault in copy to user\n");

			return -EFAULT;
		}

		return 0;
	case CSR_WRITE_IOCTL:
		if (copy_from_user(&reg_cfg, (void __user *)arg,
				   sizeof(struct hw_reg_cfg))) {
			pr_err("Write Fault in copy from user\n");

			return -EFAULT;
		}

		if (reg_cfg.regaddr < REG_PHYS_BASEADDR ||
		    reg_cfg.regaddr >= REG_PHYS_BASEADDR + REG_SPACE_MAPSIZE) {
			pr_err("Address [0x%llx] out of range "
			       "[0x%lx - 0x%lx]\n", reg_cfg.regaddr,
			       REG_PHYS_BASEADDR,
			       REG_PHYS_BASEADDR + REG_SPACE_MAPSIZE);

			return -EFAULT;
		}

		/* Only 64 bit reads/writes are allowed */
		reg_cfg.regaddr &= ~0x07ULL;
		regoff = reg_cfg.regaddr - REG_PHYS_BASEADDR;
		writeq(reg_cfg.regval, regbase + regoff);

		return 0;
	default:
		pr_info("Invalid IOCTL: %d\n", cmd);

		return -EINVAL;
	}
}

static int hw_access_release(struct inode *inode, struct file *filp)
{
	iounmap(filp->private_data);
	filp->private_data = NULL;

	return 0;
}

static const struct file_operations mmap_fops = {
	.open = hw_access_open,
	.unlocked_ioctl = hw_access_ioctl,
	.release = hw_access_release,
};

static int __init hw_access_module_init(void)
{
	static struct device *hw_reg_device;

	majorNumber = register_chrdev(0, DEVICE_NAME, &mmap_fops);
	if (majorNumber < 0) {
		pr_err("failed to register a major number for %s\n",
		       DEVICE_NAME);
		return majorNumber;
	}

	hw_reg_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(hw_reg_class)) {
		unregister_chrdev(majorNumber, DEVICE_NAME);
		return PTR_ERR(hw_reg_class);
	}

	hw_reg_device = device_create(hw_reg_class, NULL,
				      MKDEV(majorNumber, 0), NULL,
				      DEVICE_NAME);
	if (IS_ERR(hw_reg_device)) {
		class_destroy(hw_reg_class);
		unregister_chrdev(majorNumber, DEVICE_NAME);
		return PTR_ERR(hw_reg_device);
	}

	return 0;
}

static void __exit hw_access_module_exit(void)
{
	device_destroy(hw_reg_class, MKDEV(majorNumber, 0));
	class_destroy(hw_reg_class);
	unregister_chrdev(majorNumber, DEVICE_NAME);
}

module_init(hw_access_module_init);
module_exit(hw_access_module_exit);
MODULE_AUTHOR("Marvell International Ltd.");
MODULE_LICENSE("GPL v2");
