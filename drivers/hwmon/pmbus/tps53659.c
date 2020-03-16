/*
 * Hardware monitoring driver for Texas Instruments TPS53659
 *
 * Copyright (c) 2018 Pensando Systems. All rights reserved.
 * Copyright (c) 2018 Rahul Shekhar <rahulshekhar@pensando.io>
 * Based on the Vadim Pasternak's TPS53679.c driver.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include "pmbus.h"

#define TPS53659_PROT_VR12_5MV		0x01 /* VR12.0 mode, 5-mV DAC */
#define TPS53659_PROT_VR12_5_10MV	0x02 /* VR12.5 mode, 10-mV DAC */
#define TPS53659_PROT_VR13_10MV		0x04 /* VR13.0 mode, 10-mV DAC */
#define TPS53659_PROT_IMVP8_5MV		0x05 /* IMVP8 mode, 5-mV DAC */
#define TPS53659_PROT_VR13_5MV		0x07 /* VR13.0 mode, 5-mV DAC */
#define TPS53659_PAGE_NUM		2

static int tps53659_identify(struct i2c_client *client,
			     struct pmbus_driver_info *info)
{
	u8 vout_params;
	int ret;

	/* Read the register with VOUT scaling value.*/
	ret = pmbus_read_byte_data(client, 0, PMBUS_VOUT_MODE);
	if (ret < 0)
		return ret;

	vout_params = ret & GENMASK(4, 0);

	switch (vout_params) {
	case TPS53659_PROT_VR13_10MV:
	case TPS53659_PROT_VR12_5_10MV:
		info->vrm_version = vr13;
		break;
	case TPS53659_PROT_VR13_5MV:
	case TPS53659_PROT_VR12_5MV:
	case TPS53659_PROT_IMVP8_5MV:
		info->vrm_version = vr12;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static struct pmbus_driver_info tps53659_info = {
	.pages = TPS53659_PAGE_NUM,
	.format[PSC_VOLTAGE_IN] = linear,
	.format[PSC_VOLTAGE_OUT] = vid,
	.format[PSC_TEMPERATURE] = linear,
	.format[PSC_CURRENT_OUT] = linear,
	.format[PSC_POWER] = linear,
	.func[0] = PMBUS_HAVE_VIN | PMBUS_HAVE_VOUT | PMBUS_HAVE_STATUS_VOUT |
		PMBUS_HAVE_IOUT | PMBUS_HAVE_STATUS_IOUT |
		PMBUS_HAVE_TEMP | PMBUS_HAVE_STATUS_TEMP |
		PMBUS_HAVE_POUT | PMBUS_HAVE_PIN,
	.func[1] = PMBUS_HAVE_VIN | PMBUS_HAVE_VOUT | PMBUS_HAVE_STATUS_VOUT |
		PMBUS_HAVE_IOUT | PMBUS_HAVE_STATUS_IOUT |
		PMBUS_HAVE_TEMP | PMBUS_HAVE_STATUS_TEMP |
		PMBUS_HAVE_POUT,
	.identify = tps53659_identify,
};

static int tps53659_probe(struct i2c_client *client,
			  const struct i2c_device_id *id)
{
	return pmbus_do_probe(client, id, &tps53659_info);
}

static const struct i2c_device_id tps53659_id[] = {
	{"tps53659", 0},
	{}
};

MODULE_DEVICE_TABLE(i2c, tps53659_id);

static const struct of_device_id tps53659_of_match[] = {
	{.compatible = "ti,tps53659"},
	{}
};
MODULE_DEVICE_TABLE(of, tps53659_of_match);

static struct i2c_driver tps53659_driver = {
	.driver = {
		.name = "tps53659",
		.of_match_table = of_match_ptr(tps53659_of_match),
	},
	.probe = tps53659_probe,
	.remove = pmbus_do_remove,
	.id_table = tps53659_id,
};

module_i2c_driver(tps53659_driver);

MODULE_AUTHOR("Rahul Shekhar <rahulshekhar@pensando.io>");
MODULE_DESCRIPTION("PMBus driver for Texas Instruments TPS53659");
MODULE_LICENSE("GPL");
