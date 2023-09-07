/*
 * Copyright (c) 2021, Pensando Systems Inc.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/arm-smccc.h>

#include "penfw.h"
#include "penfw_sysfs.h"

#define  DEVICE_NAME "penfw"
#define  CLASS_NAME  "penfw"

static int    majorNumber;
static struct class *penfw_class;
static struct device *penfw_dev;
static DEFINE_MUTEX(penfw_mutex);

static int penfw_open(struct inode *inodep, struct file *filep)
{
	return 0;
}

static long penfw_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret = 0;
	void __user *argp = (void __user *)arg;
	struct penfw_call_args penfw_args_ob;

	mutex_lock(&penfw_mutex);

	if (copy_from_user(&penfw_args_ob, argp, sizeof(penfw_args_ob))) {
		dev_err(penfw_dev, "copy from user failed\n");
		ret = -EFAULT;
		goto err;
	}

	if (cmd != PENFW_FWCALL) {
		dev_err(penfw_dev, "received unsupported ioctl %u\n", cmd);
		ret = -EOPNOTSUPP;
		goto err;
	}

	penfw_smc(&penfw_args_ob);

	// copy back data to user space struct
	if (copy_to_user(argp, &penfw_args_ob, sizeof(penfw_args_ob))) {
		dev_err(penfw_dev, "copy to user failed\n");
		ret = -EFAULT;
		goto err;
	}

err:
	mutex_unlock(&penfw_mutex);

	return ret;
}

static const struct file_operations fops = {
	.open = penfw_open,
	.unlocked_ioctl = penfw_ioctl
};

static int penfw_probe(struct platform_device *pdev)
{
	int ret;

	pr_info("penfw: initializing the device\n");
	mutex_init(&penfw_mutex);
	majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
	if (majorNumber < 0) {
		pr_err("penfw: failed to register a major number\n");
		return majorNumber;
	}
	pr_info("penfw: registered correctly with major number %d\n",
			 majorNumber);

	// register the device class
	penfw_class = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(penfw_class)) {
		unregister_chrdev(majorNumber, DEVICE_NAME);
		pr_err("penfw: failed to register device class\n");
		return PTR_ERR(penfw_class);
	}
	pr_info("penfw: device class registered correctly\n");

	// register the device driver
	penfw_dev = device_create(penfw_class, NULL, MKDEV(majorNumber, 0),
				  NULL, DEVICE_NAME);
	if (IS_ERR(penfw_dev)) {
		class_destroy(penfw_class);
		unregister_chrdev(majorNumber, DEVICE_NAME);
		dev_err(penfw_dev, "failed to create the device\n");
		return PTR_ERR(penfw_dev);
	}
	dev_info(penfw_dev, "device class created correctly\n");

	ret = penfw_sysfs_init(penfw_dev);
	if (ret != 0) {
		dev_err(penfw_dev, "penfw sys initialization failed\n");
		return -1;
	}
	dev_info(penfw_dev, "penfw sys initialization success\n");

	return 0;
}

static int penfw_remove(struct platform_device *pd)
{
	mutex_destroy(&penfw_mutex);
	device_destroy(penfw_class, MKDEV(majorNumber, 0));
	class_unregister(penfw_class);
	class_destroy(penfw_class);
	unregister_chrdev(majorNumber, DEVICE_NAME);
	penfw_sysfs_deinit();
	pr_info("penfw: Exiting!\n");

	return 0;
}

static const struct of_device_id penfw_of_match[] = {
	{ .compatible = "pensando,penfw" },
	{ /* end of table */ }
};

static struct platform_driver penfw_driver = {
	.probe = penfw_probe,
	.remove = penfw_remove,
	.driver = {
		.name = "penfw",
		.owner = THIS_MODULE,
		.of_match_table = penfw_of_match,
	},
};

module_platform_driver(penfw_driver);
