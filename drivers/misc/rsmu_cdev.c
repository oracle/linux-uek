// SPDX-License-Identifier: GPL-2.0+
/*
 * This driver is developed for the IDT ClockMatrix(TM) and 82P33xxx families
 * of timing and synchronization devices. It will be used by Renesas PTP Clock
 * Manager for Linux (pcm4l) software to provide support to GNSS assisted
 * partial timing support (APTS) and other networking timing functions.
 *
 * Please note it must work with Renesas MFD driver to access device through
 * I2C/SPI.
 *
 * Copyright (C) 2019 Integrated Device Technology, Inc., a Renesas Company.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/mfd/rsmu.h>
#include <uapi/linux/rsmu.h>

#include "rsmu_cdev.h"

#define DRIVER_NAME	"rsmu"
#define DRIVER_MAX_DEV	BIT(MINORBITS)

static struct class *rsmu_class;
static dev_t rsmu_cdevt;
static struct rsmu_ops *ops_array[] = {
	[RSMU_CM] = &cm_ops,
	[RSMU_SABRE] = &sabre_ops,
};

static int
rsmu_set_combomode(struct rsmu_cdev *rsmu, void __user *arg)
{
	struct rsmu_ops *ops = rsmu->ops;
	struct rsmu_combomode mode;
	int err;

	if (copy_from_user(&mode, arg, sizeof(mode)))
		return -EFAULT;

	if (ops->set_combomode == NULL)
		return -ENOTSUPP;

	mutex_lock(rsmu->lock);
	err = ops->set_combomode(rsmu, mode.dpll, mode.mode);
	mutex_unlock(rsmu->lock);

	return err;
}

static int
rsmu_get_dpll_state(struct rsmu_cdev *rsmu, void __user *arg)
{
	struct rsmu_ops *ops = rsmu->ops;
	struct rsmu_get_state state_request;
	u8 state;
	int err;

	if (copy_from_user(&state_request, arg, sizeof(state_request)))
		return -EFAULT;

	if (ops->get_dpll_state == NULL)
		return -ENOTSUPP;

	mutex_lock(rsmu->lock);
	err = ops->get_dpll_state(rsmu, state_request.dpll, &state);
	mutex_unlock(rsmu->lock);

	state_request.state = state;
	if (copy_to_user(arg, &state_request, sizeof(state_request)))
		return -EFAULT;

	return err;
}

static int
rsmu_get_dpll_ffo(struct rsmu_cdev *rsmu, void __user *arg)
{
	struct rsmu_ops *ops = rsmu->ops;
	struct rsmu_get_ffo ffo_request;
	int err;

	if (copy_from_user(&ffo_request, arg, sizeof(ffo_request)))
		return -EFAULT;

	if (ops->get_dpll_ffo == NULL)
		return -ENOTSUPP;

	mutex_lock(rsmu->lock);
	err = ops->get_dpll_ffo(rsmu, ffo_request.dpll, &ffo_request);
	mutex_unlock(rsmu->lock);

	if (copy_to_user(arg, &ffo_request, sizeof(ffo_request)))
		return -EFAULT;

	return err;
}

static int
rsmu_reg_read(struct rsmu_cdev *rsmu, void __user *arg)
{
	struct rsmu_reg_rw data;
	int err;

	if (copy_from_user(&data, arg, sizeof(data)))
		return -EFAULT;

	mutex_lock(rsmu->lock);
	//err = regmap_bulk_read(rsmu->regmap, data.offset, &data.bytes[0], data.byte_count);
	err = rsmu_read(rsmu->mfd, data.offset, &data.bytes[0], data.byte_count);
	mutex_unlock(rsmu->lock);
    if (err)
		return err;

	if (copy_to_user(arg, &data, sizeof(data)))
		return -EFAULT;

	return err;
}

static int
rsmu_reg_write(struct rsmu_cdev *rsmu, void __user *arg)
{
	struct rsmu_reg_rw data;
	int err;

	if (copy_from_user(&data, arg, sizeof(data)))
		return -EFAULT;

    mutex_lock(rsmu->lock);
    //err = regmap_bulk_write(rsmu->regmap, data.offset, &data.bytes[0], data.byte_count);
    err = rsmu_write(rsmu->mfd, data.offset, &data.bytes[0], data.byte_count);
	mutex_unlock(rsmu->lock);

	if (copy_to_user(arg, &data, sizeof(data)))
		return -EFAULT;

	return err;
}


static int
rsmu_open(struct inode *iptr, struct file *fptr)
{
	struct rsmu_cdev *rsmu;

	rsmu = container_of(iptr->i_cdev, struct rsmu_cdev, rsmu_cdev);
	if (!rsmu)
		return -EAGAIN;

	fptr->private_data = rsmu;
	return 0;
}

static int
rsmu_release(struct inode *iptr, struct file *fptr)
{
	struct rsmu_cdev *rsmu;

	rsmu = container_of(iptr->i_cdev, struct rsmu_cdev, rsmu_cdev);
	if (!rsmu)
		return -EAGAIN;

	return 0;
}



static long
rsmu_ioctl(struct file *fptr, unsigned int cmd, unsigned long data)
{
	struct rsmu_cdev *rsmu = fptr->private_data;
	void __user *arg = (void __user *)data;
	int err = 0;

	if (!rsmu)
		return -EINVAL;

	switch (cmd) {
	case RSMU_SET_COMBOMODE:
		err = rsmu_set_combomode(rsmu, arg);
		break;
	case RSMU_GET_STATE:
		err = rsmu_get_dpll_state(rsmu, arg);
		break;
	case RSMU_GET_FFO:
		err = rsmu_get_dpll_ffo(rsmu, arg);
		break;
	case RSMU_REG_READ:
		err = rsmu_reg_read(rsmu, arg);
		break;
	case RSMU_REG_WRITE:
		err = rsmu_reg_write(rsmu, arg);
		break;
	default:
		/* Should not get here */
        pr_err("%lu %u",  RSMU_REG_READ, cmd);
		dev_err(rsmu->dev, "Undefined RSMU IOCTL");
		err = -EINVAL;
		break;
	}

	return err;
}

static long rsmu_compat_ioctl(struct file *fptr, unsigned int cmd,
			      unsigned long data)
{
	return rsmu_ioctl(fptr, cmd, data);
}

static const struct file_operations rsmu_fops = {
	.owner = THIS_MODULE,
	.open = rsmu_open,
	.release = rsmu_release,
	.unlocked_ioctl = rsmu_ioctl,
	.compat_ioctl =	rsmu_compat_ioctl,
};

static int rsmu_init_ops(struct rsmu_cdev *rsmu)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ops_array); i++)
		if (ops_array[i]->type == rsmu->type)
			break;

	if (i == ARRAY_SIZE(ops_array))
		return -EINVAL;

	rsmu->ops = ops_array[i];
	return 0;
}

static int
rsmu_probe(struct platform_device *pdev)
{
	struct rsmu_pdata *pdata = dev_get_platdata(&pdev->dev);
	struct rsmu_cdev *rsmu;
	struct device *rsmu_cdev;
	int err;

	rsmu = devm_kzalloc(&pdev->dev, sizeof(*rsmu), GFP_KERNEL);
	if (!rsmu)
		return -ENOMEM;

	rsmu->dev = &pdev->dev;
	rsmu->mfd = pdev->dev.parent;
	rsmu->type = pdata->type;
	rsmu->lock = pdata->lock;
	rsmu->index = pdata->index;

	/* Save driver private data */
	platform_set_drvdata(pdev, rsmu);

	cdev_init(&rsmu->rsmu_cdev, &rsmu_fops);
	rsmu->rsmu_cdev.owner = THIS_MODULE;
	err = cdev_add(&rsmu->rsmu_cdev,
		       MKDEV(MAJOR(rsmu_cdevt), 0), 1);
	if (err < 0) {
		dev_err(rsmu->dev, "cdev_add failed");
		err = -EIO;
		goto err_rsmu_dev;
	}

	if (!rsmu_class) {
		err = -EIO;
		dev_err(rsmu->dev, "rsmu class not created correctly");
		goto err_rsmu_cdev;
	}

	rsmu_cdev = device_create(rsmu_class, rsmu->dev,
				  MKDEV(MAJOR(rsmu_cdevt), 0),
				  rsmu, "rsmu%d", rsmu->index);
	if (IS_ERR(rsmu_cdev)) {
		dev_err(rsmu->dev, "Unable to create char device");
		err = PTR_ERR(rsmu_cdev);
		goto err_rsmu_cdev;
	}

	err = rsmu_init_ops(rsmu);
	if (err) {
		dev_err(rsmu->dev, "Unable to match type %d", rsmu->type);
		goto err_rsmu_cdev;
	}

	dev_info(rsmu->dev, "Probe SMU type %d successful\n", rsmu->type);
	return 0;

	/* Failure cleanup */
err_rsmu_cdev:
	cdev_del(&rsmu->rsmu_cdev);
err_rsmu_dev:
	return err;
}

static int
rsmu_remove(struct platform_device *pdev)
{
	struct rsmu_cdev *rsmu = platform_get_drvdata(pdev);
	struct device *dev = &pdev->dev;

	if (!rsmu)
		return -ENODEV;

	if (!rsmu_class) {
		dev_err(dev, "rsmu_class is NULL");
		return -EIO;
	}

	device_destroy(rsmu_class, MKDEV(MAJOR(rsmu_cdevt), 0));
	cdev_del(&rsmu->rsmu_cdev);

	return 0;
}

static const struct platform_device_id rsmu_id_table[] = {
	{ "rsmu-cdev0", },
	{ "rsmu-cdev1", },
	{ "rsmu-cdev2", },
	{ "rsmu-cdev3", },
	{}
};
MODULE_DEVICE_TABLE(platform, rsmu_id_table);

static struct platform_driver rsmu_driver = {
	.driver = {
		.name = DRIVER_NAME,
	},
	.probe = rsmu_probe,
	.remove =  rsmu_remove,
	.id_table = rsmu_id_table,
};

static int __init rsmu_init(void)
{
	int err;

	rsmu_class = class_create(THIS_MODULE, DRIVER_NAME);
	if (IS_ERR(rsmu_class)) {
		err = PTR_ERR(rsmu_class);
		pr_err("Unable to register rsmu class");
		return err;
	}

	err = alloc_chrdev_region(&rsmu_cdevt, 0, DRIVER_MAX_DEV, DRIVER_NAME);
	if (err < 0) {
		pr_err("Unable to get major number");
		goto err_rsmu_class;
	}

	err = platform_driver_register(&rsmu_driver);
	if (err < 0) {
		pr_err("Unabled to register %s driver", DRIVER_NAME);
		goto err_rsmu_drv;
	}
	return 0;

	/* Error Path */
err_rsmu_drv:
	unregister_chrdev_region(rsmu_cdevt, DRIVER_MAX_DEV);
err_rsmu_class:
	class_destroy(rsmu_class);
	return err;
}

static void __exit rsmu_exit(void)
{
	platform_driver_unregister(&rsmu_driver);
	unregister_chrdev_region(rsmu_cdevt, DRIVER_MAX_DEV);
	class_destroy(rsmu_class);
	rsmu_class = NULL;
}

module_init(rsmu_init);
module_exit(rsmu_exit);

MODULE_DESCRIPTION("Renesas SMU character device driver");
MODULE_LICENSE("GPL");
