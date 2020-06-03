// SPDX-License-Identifier: GPL-2.0-only
/*
 * Thermal driver for Marvell Octeon TX SoC
 *
 * Author: Eric Saint Etienne <eric.saint.etienne@oracle.com>
 *
 * Copyright (c) 1991, 2020, Oracle and/or its affiliates.
 */

#include <linux/device.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/bitfield.h>
#include <linux/of.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/thermal.h>

#define DRIVER_NAME "octeontx_thermal"

/* Registers offsets (in bytes from the instance base) */
#define VRM_TS_TEMP_CONV_RESULT_OFFSET	0x68
#define VRM_TS_TEMP_NOFF_MC_OFFSET	0x88

#define VRM_TS_TEMP_CONV_RESULT_TEMP_CORRECTED_MASK GENMASK_ULL(8, 0)
#define VRM_TS_TEMP_CONV_RESULT_TEMP_CORRECTED(reg) \
	FIELD_GET(VRM_TS_TEMP_CONV_RESULT_TEMP_CORRECTED_MASK, (reg))

#define VRM_TS_TEMP_NOFF_MC_NOFF_MASK GENMASK_ULL(10, 0)
#define VRM_TS_TEMP_NOFF_MC_NOFF(reg) \
	FIELD_GET(VRM_TS_TEMP_NOFF_MC_NOFF_MASK, (reg))

#define READ_REG(priv, offset) \
	readq_relaxed((priv)->sensor + (offset) / sizeof(u64))

#define MSG_CALIBRATION_WARNING \
	"sensor at %p does not appear to be calibrated. Readings are unpredictable.\n"

/* Sensor dev private structure */
struct octeontx_thermal_priv {
	u64 __iomem *sensor;
};

static void octeontx_init_temp_sensor(struct platform_device *pdev,
				      const struct octeontx_thermal_priv *priv)
{
	u64 reg;

	reg = READ_REG(priv, VRM_TS_TEMP_NOFF_MC_OFFSET);
	if (reg == 0x000)
		dev_notice(&pdev->dev, MSG_CALIBRATION_WARNING, priv->sensor);
}

/*
 * Octeon TX has only 9 bits of unsigned temperature of which
 * the two lsb form the decimal part (quarter degrees celsius)
 */
static int octeontx_get_temp(struct thermal_zone_device *thermal, int *temp)
{
	struct octeontx_thermal_priv *priv = thermal->devdata;
	u64 reg;

	reg = READ_REG(priv, VRM_TS_TEMP_CONV_RESULT_OFFSET);

	/*
	 * Convert signed temperature from quarter-Celsius to milli-Celsius
	 */
	*temp = 250 * VRM_TS_TEMP_CONV_RESULT_TEMP_CORRECTED(reg);

	return 0;
}

static struct thermal_zone_device_ops octeontx_thermal_ops = {
	.get_temp = octeontx_get_temp,
};

static const struct of_device_id octeontx_thermal_id_table[] = {
	{ .compatible = "octeontx-thermal" },
	{}
};

static int octeontx_thermal_probe(struct platform_device *pdev)
{
	struct thermal_zone_device *thermal = NULL;
	struct octeontx_thermal_priv *priv;
	struct resource *res;
	int ret;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (IS_ERR(res))
		return PTR_ERR(res);

	priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->sensor = devm_ioremap(&pdev->dev, res->start,
				    res->end - res->start);
	if (IS_ERR(priv->sensor)) {
		ret = PTR_ERR(priv->sensor);
		goto probe_cleanup;
	}

	octeontx_init_temp_sensor(pdev, priv);

	thermal = thermal_zone_device_register(DRIVER_NAME, 0, 0, priv,
					       &octeontx_thermal_ops,
					       NULL, 0, 0);
	if (IS_ERR(thermal)) {
		dev_err(&pdev->dev, "Failed to register thermal zone device\n");
		ret = PTR_ERR(thermal);
		goto probe_cleanup;
	}

	dev_notice(&pdev->dev, "registered temperature sensor @%llx\n",
		   res->start);

	platform_set_drvdata(pdev, thermal);

	return 0;

probe_cleanup:
	if (!IS_ERR(priv->sensor))
		devm_iounmap(&pdev->dev, priv->sensor);
	kfree(priv);

	return ret;
}

MODULE_DEVICE_TABLE(of, octeontx_thermal_id_table);

static struct platform_driver octeontx_thermal_driver = {
	.probe = octeontx_thermal_probe,
	.driver = {
		.name = DRIVER_NAME,
		.of_match_table = octeontx_thermal_id_table,
	},
};

builtin_platform_driver(octeontx_thermal_driver);
