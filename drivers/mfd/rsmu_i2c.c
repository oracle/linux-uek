// SPDX-License-Identifier: GPL-2.0+
/*
 * Multi-function driver for the IDT ClockMatrix(TM) and 82P33xxx families of
 * timing and synchronization devices.
 *
 * Copyright (C) 2019 Integrated Device Technology, Inc., a Renesas Company.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/i2c.h>
#include <linux/regmap.h>
#include <linux/of.h>
#include <linux/mfd/core.h>
#include <linux/mfd/rsmu.h>
#include "rsmu_private.h"

/*
 * 16-bit register address: the lower 8 bits of the register address come
 * from the offset addr byte and the upper 8 bits come from the page register.
 */
#define	RSMU_CM_PAGE_ADDR		0xFD
#define	RSMU_CM_PAGE_WINDOW		256

/*
 * 15-bit register address: the lower 7 bits of the register address come
 * from the offset addr byte and the upper 8 bits come from the page register.
 */
#define	RSMU_SABRE_PAGE_ADDR		0x7F
#define	RSMU_SABRE_PAGE_WINDOW		128

static bool rsmu_cm_volatile_reg(struct device *dev, unsigned int reg);
static bool rsmu_sabre_volatile_reg(struct device *dev, unsigned int reg);

/* Current mfd device index */
static atomic_t rsmu_ndevs = ATOMIC_INIT(0);

/* Platform data */
static struct rsmu_pdata rsmu_pdata[RSMU_MAX_MFD_DEV];

/* clockmatrix phc devices */
static struct mfd_cell rsmu_cm_pdev[RSMU_MAX_MFD_DEV] = {
	[0] = {
		.name = "idtcm-ptp0",
		.of_compatible	= "renesas,idtcm-ptp0",
	},
	[1] = {
		.name = "idtcm-ptp1",
		.of_compatible	= "renesas,idtcm-ptp1",
	},
	[2] = {
		.name = "idtcm-ptp2",
		.of_compatible	= "renesas,idtcm-ptp2",
	},
	[3] = {
		.name = "idtcm-ptp3",
		.of_compatible	= "renesas,idtcm-ptp3",
	},
};

/* sabre phc devices */
static struct mfd_cell rsmu_sabre_pdev[RSMU_MAX_MFD_DEV] = {
	[0] = {
		.name = "idt82p33-ptp0",
		.of_compatible	= "renesas,idt82p33-ptp0",
	},
	[1] = {
		.name = "idt82p33-ptp1",
		.of_compatible	= "renesas,idt82p33-ptp1",
	},
	[2] = {
		.name = "idt82p33-ptp2",
		.of_compatible	= "renesas,idt82p33-ptp2",
	},
	[3] = {
		.name = "idt82p33-ptp3",
		.of_compatible	= "renesas,idt82p33-ptp3",
	},
};

/* rsmu character devices */
static struct mfd_cell rsmu_cdev[RSMU_MAX_MFD_DEV] = {
	[0] = {
		.name = "rsmu-cdev0",
		.of_compatible	= "renesas,rsmu-cdev0",
	},
	[1] = {
		.name = "rsmu-cdev1",
		.of_compatible	= "renesas,rsmu-cdev1",
	},
	[2] = {
		.name = "rsmu-cdev2",
		.of_compatible	= "renesas,rsmu-cdev2",
	},
	[3] = {
		.name = "rsmu-cdev3",
		.of_compatible	= "renesas,rsmu-cdev3",
	},
};

static const struct regmap_range_cfg rsmu_cm_range_cfg[] = {
	{
		.range_min = 0,
		.range_max = 0xD000,
		.selector_reg = RSMU_CM_PAGE_ADDR,
		.selector_mask = 0xFF,
		.selector_shift = 0,
		.window_start = 0,
		.window_len = RSMU_CM_PAGE_WINDOW,
	}
};

static const struct regmap_range_cfg rsmu_sabre_range_cfg[] = {
	{
		.range_min = 0,
		.range_max = 0x400,
		.selector_reg = RSMU_SABRE_PAGE_ADDR,
		.selector_mask = 0xFF,
		.selector_shift = 0,
		.window_start = 0,
		.window_len = RSMU_SABRE_PAGE_WINDOW,
	}
};

static const struct regmap_config rsmu_regmap_configs[] = {
	[RSMU_CM] = {
		.reg_bits = 8,
		.val_bits = 8,
		.max_register = 0xD000,
		.ranges = rsmu_cm_range_cfg,
		.num_ranges = ARRAY_SIZE(rsmu_cm_range_cfg),
		.volatile_reg = rsmu_cm_volatile_reg,
		.cache_type = REGCACHE_RBTREE,
		.can_multi_write = true,
	},
	[RSMU_SABRE] = {
		.reg_bits = 8,
		.val_bits = 8,
		.max_register = 0x400,
		.ranges = rsmu_sabre_range_cfg,
		.num_ranges = ARRAY_SIZE(rsmu_sabre_range_cfg),
		.volatile_reg = rsmu_sabre_volatile_reg,
		.cache_type = REGCACHE_RBTREE,
		.can_multi_write = true,
	},
};

static bool rsmu_cm_volatile_reg(struct device *dev, unsigned int reg)
{
	switch (reg) {
	case RSMU_CM_PAGE_ADDR:
		return false;
	default:
		return true;
	}
}

static bool rsmu_sabre_volatile_reg(struct device *dev, unsigned int reg)
{
	switch (reg) {
	case RSMU_SABRE_PAGE_ADDR:
		return false;
	default:
		return true;
	}
}

int rsmu_read(struct device *dev, u16 reg, u8 *buf, u16 size)
{
	struct rsmu_dev *rsmu = dev_get_drvdata(dev);

	return regmap_bulk_read(rsmu->regmap, reg, buf, size);
}
EXPORT_SYMBOL_GPL(rsmu_read);

int rsmu_write(struct device *dev, u16 reg, u8 *buf, u16 size)
{
	struct rsmu_dev *rsmu = dev_get_drvdata(dev);

	return regmap_bulk_write(rsmu->regmap, reg, buf, size);
}
EXPORT_SYMBOL_GPL(rsmu_write);

static int rsmu_mfd_init(struct rsmu_dev *rsmu, struct mfd_cell *mfd,
			 struct rsmu_pdata *pdata)
{
	int ret;

	mfd->platform_data = pdata;
	mfd->pdata_size = sizeof(struct rsmu_pdata);

	ret = mfd_add_devices(rsmu->dev, -1, mfd, 1, NULL, 0, NULL);
	if (ret < 0) {
		dev_err(rsmu->dev, "mfd_add_devices failed with %s\n",
			mfd->name);
		return ret;
	}

	return ret;
}

static int rsmu_dev_init(struct rsmu_dev *rsmu)
{
	struct rsmu_pdata *pdata;
	struct mfd_cell *pmfd;
	struct mfd_cell *cmfd;
	int ret;

	/* Initialize regmap */
	rsmu->regmap = devm_regmap_init_i2c(rsmu->client,
					    &rsmu_regmap_configs[rsmu->type]);
	if (IS_ERR(rsmu->regmap)) {
		ret = PTR_ERR(rsmu->regmap);
		dev_err(rsmu->dev, "Failed to allocate register map: %d\n",
			ret);
		return ret;
	}

	/* Initialize device index */
	rsmu->index = atomic_read(&rsmu_ndevs);
	if (rsmu->index >= RSMU_MAX_MFD_DEV)
		return -ENODEV;

	/* Initialize platform data */
	pdata = &rsmu_pdata[rsmu->index];
	pdata->lock = &rsmu->lock;
	pdata->type = rsmu->type;
	pdata->index = rsmu->index;

	/* Initialize MFD devices */
	cmfd = &rsmu_cdev[rsmu->index];
	if (rsmu->type == RSMU_CM)
		pmfd = &rsmu_cm_pdev[rsmu->index];
	else if (rsmu->type == RSMU_SABRE)
		pmfd = &rsmu_sabre_pdev[rsmu->index];
	else
		return -EINVAL;

	ret = rsmu_mfd_init(rsmu, pmfd, pdata);
	if (ret)
		return ret;

	return rsmu_mfd_init(rsmu, cmfd, pdata);
}

static int rsmu_dt_init(struct rsmu_dev *rsmu)
{
	struct device_node *np = rsmu->dev->of_node;

	rsmu->type = RSMU_NONE;
	if (of_device_is_compatible(np, "idt,8a34000")) {
		rsmu->type = RSMU_CM;
	} else if (of_device_is_compatible(np, "idt,82p33810")) {
		rsmu->type = RSMU_SABRE;
	} else {
		dev_err(rsmu->dev, "unknown RSMU device\n");
		return -EINVAL;
	}

	return 0;
}

static int rsmu_probe(struct i2c_client *client, const struct i2c_device_id *id)
{
	struct rsmu_dev *rsmu;
	int ret;

	rsmu = devm_kzalloc(&client->dev, sizeof(struct rsmu_dev),
			       GFP_KERNEL);
	if (rsmu == NULL)
		return -ENOMEM;

	i2c_set_clientdata(client, rsmu);
	mutex_init(&rsmu->lock);
	rsmu->dev = &client->dev;
	rsmu->client = client;

	ret = rsmu_dt_init(rsmu);
	if (ret)
		return ret;

	mutex_lock(&rsmu->lock);

	ret = rsmu_dev_init(rsmu);
	if (ret == 0)
		atomic_inc(&rsmu_ndevs);

	mutex_unlock(&rsmu->lock);

	return ret;
}

static int rsmu_remove(struct i2c_client *client)
{
	struct rsmu_dev *rsmu = i2c_get_clientdata(client);

	mfd_remove_devices(&client->dev);
	mutex_destroy(&rsmu->lock);
	atomic_dec(&rsmu_ndevs);

	return 0;
}

static const struct i2c_device_id rsmu_id[] = {
	{ "8a34000", 0 },
	{ "82p33810", 0 },
	{ }
};
MODULE_DEVICE_TABLE(i2c, rsmu_id);

static const struct of_device_id rsmu_of_match[] = {
	{.compatible = "idt,8a34000", },
	{.compatible = "idt,82p33810", },
	{},
};
MODULE_DEVICE_TABLE(of, rsmu_of_match);

static struct i2c_driver rsmu_driver = {
	.driver = {
		   .name = "rsmu-i2c",
		   .of_match_table = of_match_ptr(rsmu_of_match),
	},
	.probe = rsmu_probe,
	.remove	= rsmu_remove,
	.id_table = rsmu_id,
};

static int __init rsmu_init(void)
{
	return i2c_add_driver(&rsmu_driver);
}
/* init early so consumer devices can complete system boot */
subsys_initcall(rsmu_init);

static void __exit rsmu_exit(void)
{
	i2c_del_driver(&rsmu_driver);
}
module_exit(rsmu_exit);

MODULE_DESCRIPTION("Renesas SMU I2C multi-function driver");
MODULE_LICENSE("GPL");
