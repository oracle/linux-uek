// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019-2021, Pensando Systems Inc.
 */

#include <linux/export.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/io.h>
#include "bsm_dev.h"

extern struct kobject *pensando_fw_kobj_get(void);

struct bsm {
	void __iomem *base;
	uint32_t val;
};
static struct bsm bsm;

#define BSM_SHOW_INT(n, s) \
	static ssize_t n##_show(struct device *dev,			\
			struct device_attribute *attr, char *buf)	\
	{								\
		int val = (bsm.val >> BSM_##s##_LSB) & BSM_##s##_MASK;	\
		return sprintf(buf, "%d\n", val);			\
	}								\
	static DEVICE_ATTR_RO(n);

BSM_SHOW_INT(wdt,      WDT)
BSM_SHOW_INT(attempt,  ATTEMPT)
BSM_SHOW_INT(stage,    STAGE)
BSM_SHOW_INT(running,  RUNNING)
BSM_SHOW_INT(autoboot, AUTOBOOT)

static const char *fwnames[4] = {
	"mainfwa", "mainfwb", "goldfw", "diagfw"
};

#define BSM_SHOW_FWID(n, s) \
	static ssize_t n##_show(struct device *dev,			\
			struct device_attribute *attr, char *buf)	\
	{								\
		int val = (bsm.val >> BSM_##s##_LSB) & BSM_##s##_MASK;	\
		return sprintf(buf, "%s\n", fwnames[val & 0x3]);	\
	}								\
	static DEVICE_ATTR_RO(n);

BSM_SHOW_FWID(fwid,  FWID)
BSM_SHOW_FWID(track, TRACK)

static ssize_t success_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	long val;

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;
	if (val) {
		bsm.val &= ~(1 << BSM_RUNNING_LSB);
		writel(bsm.val, bsm.base);
	}

	return count;
}
static DEVICE_ATTR_WO(success);

static const struct device_attribute *bsm_attrs[] = {
	&dev_attr_wdt,
	&dev_attr_fwid,
	&dev_attr_attempt,
	&dev_attr_track,
	&dev_attr_stage,
	&dev_attr_running,
	&dev_attr_autoboot,
	&dev_attr_success,
};

static int bsm_probe(struct platform_device *pdev)
{
	struct kobject *pensando_kobj;
	int i, r = 0;

	if (bsm.base == NULL) {
		/* bsm not in device-tree */
		return -ENODEV;
	}
	pensando_kobj = pensando_fw_kobj_get();
	if (!pensando_kobj)
		return -ENOMEM;
	for (i = 0; i < ARRAY_SIZE(bsm_attrs); i++) {
		r = device_create_file(&pdev->dev, bsm_attrs[i]);
		if (r) {
			pr_err("failed to create sysfs file\n");
			return r;
		}
	}
	r = sysfs_create_link(pensando_kobj, &pdev->dev.kobj, "bsm");
	if (r) {
		pr_err("failed to create sysfs symlink\n");
		kobject_put(pensando_kobj);
		return r;
	}
	return 0;
}

static const struct of_device_id bsm_of_match[] = {
	{ .compatible = "pensando,bsm" },
};

static struct platform_driver bsm_driver = {
	.driver = {
		.name = "capri-bsm",
		.of_match_table = bsm_of_match,
		.suppress_bind_attrs = true,
	},
	.probe = bsm_probe,
};
builtin_platform_driver(bsm_driver);

/*
 * Boot State Machine init.
 * If auto-booting, then set the BSM_RUNNING bit in the BSM register
 * to continue BSM protection.	The bit will be cleared when userland comes up.
 */
static int __init cap_bsm_init(void)
{
	const struct of_device_id *match;
	struct device_node *np;
	struct resource res;

	np = of_find_matching_node_and_match(NULL, bsm_of_match, &match);
	if (!np) {
		/* Not found in the device-tree.  Quietly resign */
		return 0;
	}
	if (of_address_to_resource(np, 0, &res) < 0) {
		pr_err("failed to get BSM registers\n");
		of_node_put(np);
		return -ENXIO;
	}
	of_node_put(np);

	bsm.base = ioremap(res.start, resource_size(&res));
	if (!bsm.base) {
		pr_err("failed to map BSM register\n");
		return -ENXIO;
	}

	bsm.val = readl(bsm.base);
#ifdef CONFIG_PENSANDO_SOC_BSM_ENABLE
	if (bsm.val & (1 << BSM_AUTOBOOT_LSB)) {
		bsm.val |= 1 << BSM_RUNNING_LSB;
		writel(bsm.val, bsm.base);
	}
#endif
	return 0;
}
early_initcall(cap_bsm_init);
