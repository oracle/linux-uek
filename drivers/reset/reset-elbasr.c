// SPDX-License-Identifier: (GPL-2.0+ OR MIT)
/*
 * Copyright (c) 2022 Advanced Micro Devices, Inc.
 */

#include <linux/mfd/pensando-elbasr.h>
#include <linux/platform_device.h>
#include <linux/reset-controller.h>
#include <linux/regmap.h>
#include <linux/err.h>
#include <linux/of.h>

#include <dt-bindings/reset/amd,pensando-elba-reset.h>

struct elbasr_reset {
	struct reset_controller_dev rcdev;
	struct regmap *regmap;
};

static inline struct elbasr_reset *to_elbasr_rst(struct reset_controller_dev *rc)
{
	return container_of(rc, struct elbasr_reset, rcdev);
}

static int elbasr_reset_assert(struct reset_controller_dev *rcdev,
			       unsigned long id)
{
	struct elbasr_reset *elbar = to_elbasr_rst(rcdev);

	return regmap_update_bits(elbar->regmap, ELBASR_CTRL0_REG, BIT(6), BIT(6));
}

static int elbasr_reset_deassert(struct reset_controller_dev *rcdev,
				 unsigned long id)
{
	struct elbasr_reset *elbar = to_elbasr_rst(rcdev);

	return regmap_update_bits(elbar->regmap, ELBASR_CTRL0_REG, BIT(6), 0);
}

static const struct reset_control_ops elbasr_reset_ops = {
	.assert	= elbasr_reset_assert,
	.deassert = elbasr_reset_deassert,
};

static int elbasr_reset_probe(struct platform_device *pdev)
{
	struct elbasr_data *elbasr = dev_get_drvdata(pdev->dev.parent);
	struct elbasr_reset *elbar;
	int ret;

	elbar = devm_kzalloc(&pdev->dev, sizeof(struct elbasr_reset),
			     GFP_KERNEL);
	if (!elbar)
		return -ENOMEM;

	elbar->rcdev.owner = THIS_MODULE;
	elbar->rcdev.nr_resets = ELBASR_NR_RESETS;
	elbar->rcdev.ops = &elbasr_reset_ops;
	elbar->rcdev.of_node = pdev->dev.of_node;
	elbar->regmap = elbasr->elbasr_regs;

	platform_set_drvdata(pdev, elbar);

	ret = devm_reset_controller_register(&pdev->dev, &elbar->rcdev);

	return ret;
}

static const struct of_device_id elba_reset_dt_match[] = {
	{ .compatible = "amd,pensando-elbasr-reset", },
	{ /* sentinel */ },
};

static struct platform_driver elbasr_reset_driver = {
	.probe	= elbasr_reset_probe,
	.driver = {
		.name = "pensando_elbasr_reset",
		.of_match_table	= elba_reset_dt_match,
	},
};
builtin_platform_driver(elbasr_reset_driver);
