// SPDX-License-Identifier: (GPL-2.0+ OR MIT)
/*
 * Copyright (c) 2025 Advanced Micro Devices, Inc.
 */

#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/poll.h>
#include <linux/reset-controller.h>
#include <linux/wait.h>

#define SALINA_RESET_NOTIFY_DEV "sdhci_notify"
#define RESET_MSG "reset_triggered\n"
#define RESET_MSG_LEN 16

struct salina_reset_priv {
	struct reset_controller_dev rcdev;
	struct device *dev;
};

static DECLARE_WAIT_QUEUE_HEAD(salina_reset_wait);
static int reset_triggered;

static ssize_t salina_reset_read(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	if (wait_event_interruptible(salina_reset_wait, reset_triggered != 0))
		return -ERESTARTSYS;

	/* Only one read per event */
	if (*ppos > 0)
		return 0;

	if (count < RESET_MSG_LEN)
		return -EINVAL;

	/* Notify userspace */
	if (copy_to_user(buf, RESET_MSG, RESET_MSG_LEN))
		return -EFAULT;

	*ppos += RESET_MSG_LEN;
	reset_triggered = 0;
	return RESET_MSG_LEN;
}

static unsigned int salina_reset_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &salina_reset_wait, wait);
	return reset_triggered ? POLLIN | POLLRDNORM : 0;
}

static const struct file_operations salina_reset_fops = {
	.owner = THIS_MODULE,
	.read = salina_reset_read,
	.poll = salina_reset_poll,
};

static struct miscdevice salina_reset_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = SALINA_RESET_NOTIFY_DEV,
	.fops = &salina_reset_fops,
};

/* Reset controller ops */
static int salina_reset_assert(struct reset_controller_dev *rcdev,
			       unsigned long id)
{
	struct salina_reset_priv *priv = container_of(rcdev, struct salina_reset_priv, rcdev);
	static int init;

	/* Kernel init does emmc reset if there is a reset driver and
	 * the eMMC responds to hwreset.  The CPLD does an eMMC hwreset
	 * during reboot and the userspace program is started after the
	 * kernel is booted.  No need to request the first hwreset.
	 */
	if (!init) {
		init = 1;
		return 0;
	}

	dev_info(priv->dev, "emmc reset requested\n");
	reset_triggered = 1;
	wake_up_interruptible(&salina_reset_wait);
	return 0;
}

static int salina_reset_deassert(struct reset_controller_dev *rcdev,
				 unsigned long id)
{
	return 0;
}

static const struct reset_control_ops salina_reset_ops = {
	.assert = salina_reset_assert,
	.deassert = salina_reset_deassert,
};

static int salina_reset_probe(struct platform_device *pdev)
{
	struct salina_reset_priv *priv;
	int ret;

	priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->dev = &pdev->dev;
	priv->rcdev.owner = THIS_MODULE;
	priv->rcdev.nr_resets = 1;
	priv->rcdev.ops = &salina_reset_ops;
	priv->rcdev.of_node = pdev->dev.of_node;

	ret = devm_reset_controller_register(&pdev->dev, &priv->rcdev);
	if (ret) {
		dev_err(&pdev->dev, "Failed to register reset controller: %d\n", ret);
		return ret;
	}

	ret = misc_register(&salina_reset_misc);
	if (ret) {
		dev_err(&pdev->dev, "Failed to register misc device %s: %d\n",
			SALINA_RESET_NOTIFY_DEV, ret);
		return ret;
	}

	return 0;
}

static void salina_reset_remove(struct platform_device *pdev)
{
	misc_deregister(&salina_reset_misc);
}

static const struct of_device_id salina_reset_dt_match[] = {
	{ .compatible = "amd,pensando-salinasr-reset" },
	{ /* sentinel */ },
};
MODULE_DEVICE_TABLE(of, salina_reset_of_match);

static struct platform_driver salina_reset_driver = {
	.probe = salina_reset_probe,
	.remove = salina_reset_remove,
	.driver = {
		.name = "salina-reset",
		.of_match_table = salina_reset_dt_match,
	},
};
builtin_platform_driver(salina_reset_driver);
