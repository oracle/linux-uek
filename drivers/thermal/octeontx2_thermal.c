// SPDX-License-Identifier: GPL-2.0-only
/*
 * Thermal driver for Marvell Octeon TX2 SoC
 *
 * Author: Eric Saint Etienne <eric.saint.etienne@oracle.com>
 *
 * Copyright (c) 2020, Oracle and/or its affiliates.
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

#define DRIVER_NAME "octeontx2_thermal"

/* Registers offsets (in bytes from the instance base) */
#define TSN_CONST_OFFSET		0x08
#define TSN_TS_TEMP_CONV_RESULT_OFFSET	0x68
#define TSN_TS_TEMP_NOFF_MC_OFFSET	0x88

#define TSN_TS_TEMP_CONV_RESULT_TEMP_CORRECTED_MASK GENMASK_ULL(10, 0)
#define TSN_TS_TEMP_CONV_RESULT_TEMP_CORRECTED(reg) \
	FIELD_GET(TSN_TS_TEMP_CONV_RESULT_TEMP_CORRECTED_MASK, (reg))
#define TSN_TS_TEMP_CONV_RESULT_TEMP_CORRECTED_SIGN_MASK BIT_ULL(10)

static inline s64 u64_signed_field(u64 uval, u64 mask, u64 sign_bit_mask)
{
	if ((uval & sign_bit_mask) == 0)
		return uval;
	return ((0xFFFFFFFFFFFFFFFFULL & ~mask) | (uval & mask));
}

#define TSN_TS_TEMP_CONV_RESULT_TEMP_VALID_MASK	 BIT_ULL(11)
#define TSN_TS_TEMP_CONV_RESULT_TEMP_VALID(reg) \
	FIELD_GET(TSN_TS_TEMP_CONV_RESULT_TEMP_VALID_MASK, (reg))

#define TSN_TS_TEMP_NOFF_MC_NOFF_MASK GENMASK_ULL(10, 0)
#define TSN_TS_TEMP_NOFF_MC_NOFF(reg) \
	FIELD_GET(TSN_TS_TEMP_NOFF_MC_NOFF_MASK, (reg))

#define READ_REG(priv, offset) \
	readq_relaxed((priv)->sensor + ((offset) / sizeof(u64)))

#define MSG_CALIBRATION_WARNING \
	"sensor at %p does not appear to be calibrated. Readings are unpredictable.\n"

/* Sensor dev private structure */
struct octeontx2_thermal_priv {
	u64 __iomem *sensor;
};

static int octeontx2_init_temp_sensor(struct platform_device *pdev,
				      const struct octeontx2_thermal_priv *priv)
{
	u64 reg;

	reg = READ_REG(priv, TSN_CONST_OFFSET);
	if (reg != 0x0ULL)
		return -EIO;

	reg = READ_REG(priv, TSN_TS_TEMP_NOFF_MC_OFFSET);
	if (reg == 0x000)
		dev_notice(&pdev->dev, MSG_CALIBRATION_WARNING, priv->sensor);

	return 0;
}

/*
 * Octeon TX2 has 11 bits of signed temperature of which
 * the two lsb form the decimal part (quarter degrees celsius)
 * According to Marvell TEMP_VALID should very rarely be unset.
 *
 * Usually if temp_valid is not set the first time, it will be on the next.
 * So we retry a few times, 5 attempts should be ample enough.
 */
static int octeontx2_get_temp(struct thermal_zone_device *thermal, int *temp)
{
	struct octeontx2_thermal_priv *priv = thermal->devdata;
	u16 temp_field;
	int retry = 0;
	u64 reg;

try_again:
	reg = READ_REG(priv, TSN_TS_TEMP_CONV_RESULT_OFFSET);
	if (unlikely(!TSN_TS_TEMP_CONV_RESULT_TEMP_VALID(reg))) {
		if (++retry == 5)
			return -EINVAL;
		goto try_again;
	}

	/*
	 * Convert signed temperature from quarter-Celsius to milli-Celsius
	 */
	temp_field = TSN_TS_TEMP_CONV_RESULT_TEMP_CORRECTED(reg);
	*temp = 250 * u64_signed_field(temp_field,
		TSN_TS_TEMP_CONV_RESULT_TEMP_CORRECTED_MASK,
		TSN_TS_TEMP_CONV_RESULT_TEMP_CORRECTED_SIGN_MASK);

	return 0;
}

static struct thermal_zone_device_ops octeontx2_thermal_ops = {
	.get_temp = octeontx2_get_temp,
};

static const struct of_device_id octeontx2_thermal_id_table[] = {
	{ .compatible = "octeontx2-thermal" },
	{}
};

static int octeontx2_thermal_probe(struct platform_device *pdev)
{
	struct thermal_zone_device *thermal = NULL;
	struct octeontx2_thermal_priv *priv;
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

	ret = octeontx2_init_temp_sensor(pdev, priv);
	if (ret) {
		dev_err(&pdev->dev, "Failed (%d) to initialize sensor @%p\n",
			ret, priv->sensor);
		goto probe_cleanup;
	}

	thermal = thermal_zone_device_register(DRIVER_NAME, 0, 0, priv,
					       &octeontx2_thermal_ops,
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

MODULE_DEVICE_TABLE(of, octeontx2_thermal_id_table);

static struct platform_driver octeontx2_thermal_driver = {
	.probe = octeontx2_thermal_probe,
	.driver = {
		.name = DRIVER_NAME,
		.of_match_table = octeontx2_thermal_id_table,
	},
};

builtin_platform_driver(octeontx2_thermal_driver);
