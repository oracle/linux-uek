// SPDX-License-Identifier: GPL-2.0
/*
 * Pensando restart cause driver
 *
 * Copyright (c) 2021, Pensando Systems Inc.
 */

#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/sysfs.h>
#include <linux/export.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/init.h>
#include <linux/reboot.h>
#include <linux/mfd/syscon.h>
#include <linux/regmap.h>
#include "cap_rstcause.h"

struct kobject *pensando_fw_kobj_get(void);

struct cap_rstdev {
	struct platform_device *pdev;
	struct regmap *regs;
	unsigned int regs_offset;
	u32 this_cause;
	struct notifier_block panic_nb;
	struct notifier_block reboot_nb;
	struct kobject *pensando_kobj;
};

static struct cap_rstdev *g_rdev;

static inline u32 read_cause_reg(struct cap_rstdev *rdev)
{
	u32 val;

	regmap_read(rdev->regs, rdev->regs_offset, &val);
	return val;
}

static inline u32 read_next_cause_reg(struct cap_rstdev *rdev)
{
	u32 val;

	regmap_read(rdev->regs, rdev->regs_offset + 4, &val);
	return val;
}

static inline void set_next_cause_reg(struct cap_rstdev *rdev, u32 mask)
{
	regmap_update_bits(rdev->regs, rdev->regs_offset + 4, mask, ~0U);
}

void cap_rstcause_set(u32 mask)
{
	if (g_rdev)
		set_next_cause_reg(g_rdev, mask);
}

EXPORT_SYMBOL_GPL(cap_rstcause_set);

static int rstcause_reboot_handler(struct notifier_block *this,
				   unsigned long code, void *unused)
{
	cap_rstcause_set(CAP_RSTCAUSE_EV_REBOOT);
	return NOTIFY_OK;
}

static int rstcause_panic_handler(struct notifier_block *this,
				  unsigned long code, void *unused)
{
	cap_rstcause_set(CAP_RSTCAUSE_EV_PANIC);
	return NOTIFY_OK;
}

static ssize_t this_cause_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct cap_rstdev *rdev;

	rdev = platform_get_drvdata(to_platform_device(dev));
	return sprintf(buf, "0x%08x\n", rdev->this_cause);
}

static DEVICE_ATTR_RO(this_cause);

static ssize_t next_cause_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct cap_rstdev *rdev;

	rdev = platform_get_drvdata(to_platform_device(dev));
	return sprintf(buf, "0x%08x\n", read_next_cause_reg(rdev));
}

static ssize_t next_cause_store(struct device *dev,
				struct device_attribute *attr, const char *buf,
				size_t count)
{
	struct cap_rstdev *rdev;
	unsigned long val;

	rdev = platform_get_drvdata(to_platform_device(dev));
	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;
	if (val)
		set_next_cause_reg(rdev, val);

	return count;
}

static DEVICE_ATTR_RW(next_cause);

static const struct device_attribute *rstcause_attrs[] = {
	&dev_attr_this_cause,
	&dev_attr_next_cause,
};

static int rstcause_probe(struct platform_device *pdev)
{
	struct of_phandle_args args;
	struct cap_rstdev *rdev;
	struct regmap *regs;
	int r, i;

	if (g_rdev)
		return -ENODEV;

	r = of_parse_phandle_with_fixed_args(pdev->dev.of_node,
					     "pensando,causeregs", 1, 0, &args);
	if (r) {
		dev_err(&pdev->dev, "could not find causeregs\n");
		return r;
	}

	regs = syscon_node_to_regmap(args.np);
	if (IS_ERR(regs)) {
		dev_err(&pdev->dev, "could not map causeregs\n");
		return PTR_ERR(regs);
	}

	rdev = devm_kzalloc(&pdev->dev, sizeof(*rdev), GFP_KERNEL);
	if (!rdev)
		return -ENOMEM;
	rdev->pdev = pdev;
	platform_set_drvdata(pdev, rdev);

	rdev->regs = regs;
	rdev->regs_offset = args.args[0];
	rdev->reboot_nb.notifier_call = rstcause_reboot_handler;
	register_reboot_notifier(&rdev->reboot_nb);

	rdev->panic_nb.notifier_call = rstcause_panic_handler;
	atomic_notifier_chain_register(&panic_notifier_list, &rdev->panic_nb);

	rdev->this_cause = read_cause_reg(rdev);

	g_rdev = rdev;

	rdev->pensando_kobj = pensando_fw_kobj_get();
	if (rdev->pensando_kobj) {
		for (i = 0; i < ARRAY_SIZE(rstcause_attrs); i++) {
			r = device_create_file(&pdev->dev, rstcause_attrs[i]);
			if (r) {
				dev_err(&pdev->dev,
					"failed to create sysfs file\n");
				return r;
			}
		}
		r = sysfs_create_link(rdev->pensando_kobj,
				      &pdev->dev.kobj, "rstcause");
		if (r) {
			dev_err(&pdev->dev, "failed to create sysfs symlink\n");
			kobject_put(rdev->pensando_kobj);
			rdev->pensando_kobj = NULL;
		}
	}
	return 0;
}

static int rstcause_remove(struct platform_device *pdev)
{
	struct cap_rstdev *rdev = platform_get_drvdata(pdev);

	unregister_reboot_notifier(&rdev->reboot_nb);
	atomic_notifier_chain_unregister(&panic_notifier_list,
					 &rdev->panic_nb);
	if (g_rdev == rdev) {
		g_rdev = NULL;
		if (rdev->pensando_kobj)
			kobject_put(rdev->pensando_kobj);
	}

	return 0;
}

static const struct of_device_id rstcause_of_match[] = {
	{.compatible = "pensando,rstcause"},
	{ /* end of table */ }
};

static struct platform_driver rstcause_driver = {
	.probe = rstcause_probe,
	.remove = rstcause_remove,
	.driver = {
		   .name = "pensando-rstcause",
		   .owner = THIS_MODULE,
		   .of_match_table = rstcause_of_match,
		   },
};

module_platform_driver(rstcause_driver);
MODULE_DESCRIPTION("Pensando SoC Reset Cause Driver");
MODULE_LICENSE("GPL");
