// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Hardware monitoring driver for MPS Multi-phase Digital VR Controllers(MP2855)
 *
 * Copyright (C) 2023 MPS
 */

#include <linux/err.h>
#include <linux/i2c.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/module.h>
#include "pmbus.h"

#define MP2855_MFR_VR_CONFIG1	0xc1

#define MP2855_VOUT_CONFIG_OFF	14
#define MP2891_OV_TH_MASK	GENMASK(9, 8)
#define MP2891_OV_TH_POS	8
#define MP2891_UV_TH_MASK	GENMASK(10, 8)
#define MP2891_UV_TH_POS	8

#define MP2855_PAGE_NUM		2
#define MP2855_IOUT_SCALE_MASK	GENMASK	(31, 27)

#define MP2855_RAIL1_FUNC	(PMBUS_HAVE_VIN | PMBUS_HAVE_VOUT | PMBUS_HAVE_TEMP | \
				 PMBUS_HAVE_IOUT | PMBUS_HAVE_STATUS_VOUT | \
				 PMBUS_HAVE_STATUS_IOUT | PMBUS_HAVE_STATUS_INPUT | \
				 PMBUS_HAVE_STATUS_TEMP)
																 
#define MP2855_RAIL2_FUNC	(PMBUS_HAVE_VOUT | PMBUS_HAVE_TEMP | PMBUS_HAVE_IOUT | \
				 PMBUS_HAVE_STATUS_VOUT | PMBUS_HAVE_STATUS_IOUT | \
				 PMBUS_HAVE_STATUS_INPUT | PMBUS_HAVE_STATUS_TEMP)


#define MP2891_TMP_TH_GET(ret)	DIV_ROUND_CLOSEST(DIV_ROUND_CLOSEST(((ret) & GENMASK(7, 0)) * \
						  3125, 1000) - 275, 3);

struct mp2855_data {
	struct pmbus_driver_info info;
	struct i2c_client client;
	int iout_scale[MP2855_PAGE_NUM];
	int vout_scale[MP2855_PAGE_NUM];
	int vout_shift[MP2855_PAGE_NUM];
	int uv_off[MP2855_PAGE_NUM];
	int ov_off[MP2855_PAGE_NUM];
};

struct mp2855_data data;

#define to_mp2855_data(x) container_of(x, struct mp2855_data, info)

static int mp2855_read_byte_data(struct i2c_client *client, int page, int reg)
{
	switch (reg) {
	case PMBUS_VOUT_MODE:
		/*
		 * Enforce VOUT direct format, since device allows to set the
		 * different formats for the different rails. Conversion from
		 * VID to direct provided by driver internally, in case it is
		 * necessary.
		 */
		return PB_VOUT_MODE_DIRECT;
	default:
		return -ENODATA;
	}
}

static int mp2855_read_word_data(struct i2c_client *client, int page, int phase, int reg)
{
	const struct pmbus_driver_info *info = pmbus_get_driver_info(client);
	struct mp2855_data *data = to_mp2855_data(info);
	int ret;

	switch (reg) {
	case PMBUS_READ_VIN:
		ret = pmbus_read_word_data(client, page, phase, reg);
		return (ret < 0) ? ret : (ret & 0x3ff) * 3125 / 100;
	case PMBUS_READ_VOUT:
		ret = pmbus_read_word_data(client, page, phase, reg);
		if (ret < 0)
			return ret;

		if (data->vout_shift[page] > 0)
			return ret & GENMASK(10, 0) >> -data->vout_shift[page];
		else if (data->vout_shift[page] < 0)
			return ret & GENMASK(10, 0) << data->vout_shift[page];
		return (ret & GENMASK(10, 0)) * data->vout_scale[page] / 100;
	case PMBUS_READ_TEMPERATURE_1:
		ret = pmbus_read_word_data(client, page, phase, reg);
		return (ret < 0) ? ret : ret & GENMASK(7, 0);
	case PMBUS_READ_IOUT:
		ret = pmbus_read_word_data(client, page, phase, reg);
		return (ret < 0) ? ret : (ret & GENMASK(7, 0)) * data->iout_scale[page];
	case PMBUS_VOUT_OV_FAULT_LIMIT:
		ret = pmbus_read_word_data(client, page, phase, PMBUS_READ_VOUT);
		if (ret <= 0)
			return ret;

		return (ret & GENMASK(10, 0)) * data->vout_scale[page] / 100 + data->ov_off[page];
	case PMBUS_VOUT_UV_FAULT_LIMIT:
		ret = pmbus_read_word_data(client, page, phase, PMBUS_READ_VOUT);
		if (ret <= 0)
			return ret;

		return (ret & GENMASK(10, 0)) * data->vout_scale[page] / 100 - data->uv_off[page];
	case PMBUS_OT_FAULT_LIMIT:
		ret = pmbus_read_word_data(client, 1, phase, reg);
		return (ret <= 0) ? ret : MP2891_TMP_TH_GET(ret);
	case PMBUS_UT_WARN_LIMIT:
	case PMBUS_UT_FAULT_LIMIT:
	case PMBUS_OT_WARN_LIMIT:
	case PMBUS_VIN_OV_WARN_LIMIT:
	case PMBUS_VIN_OV_FAULT_LIMIT:
	case PMBUS_VIN_UV_WARN_LIMIT:
	case PMBUS_VIN_UV_FAULT_LIMIT:
	case PMBUS_VOUT_OV_WARN_LIMIT:
	case PMBUS_VOUT_UV_WARN_LIMIT:
	case PMBUS_POUT_OP_WARN_LIMIT:
	case PMBUS_IIN_OC_FAULT_LIMIT:
	case PMBUS_POUT_MAX:
	case PMBUS_POUT_OP_FAULT_LIMIT:
	case PMBUS_IOUT_OC_WARN_LIMIT:
	case PMBUS_IOUT_OC_FAULT_LIMIT:
	case PMBUS_IOUT_UC_FAULT_LIMIT:
	case PMBUS_MFR_VIN_MIN:
	case PMBUS_MFR_VOUT_MIN:
	case PMBUS_MFR_VIN_MAX:
	case PMBUS_MFR_VOUT_MAX:
	case PMBUS_MFR_IIN_MAX:
	case PMBUS_MFR_IOUT_MAX:
	case PMBUS_MFR_PIN_MAX:
	case PMBUS_MFR_POUT_MAX:
	case PMBUS_MFR_MAX_TEMP_1:
		return -ENXIO;
	default:
		return -ENODATA;
	}
	
	return ret;
}

static struct pmbus_driver_info mp2855_info = {
	.pages = MP2855_PAGE_NUM,
	.phases[0] = 1,
	.phases[1] = 1,
	.format[PSC_VOLTAGE_IN] = direct,
	.format[PSC_VOLTAGE_OUT] = direct,
	.format[PSC_TEMPERATURE] = direct,
	.format[PSC_CURRENT_OUT] = direct,
	.m[PSC_VOLTAGE_IN] = 1,
	.R[PSC_VOLTAGE_IN] = 3,
	.b[PSC_VOLTAGE_IN] = 0,
	.m[PSC_VOLTAGE_OUT] = 1,
	.R[PSC_VOLTAGE_OUT] = 3,
	.b[PSC_VOLTAGE_OUT] = 0,
	.m[PSC_TEMPERATURE] = 1,
	.R[PSC_TEMPERATURE] = 0,
	.b[PSC_TEMPERATURE] = 0,
	.m[PSC_CURRENT_OUT] = 1,
	.R[PSC_CURRENT_OUT] = 3,
	.b[PSC_CURRENT_OUT] = 0,
	.func[0] = MP2855_RAIL1_FUNC,
	.func[1] = MP2855_RAIL2_FUNC,
	.read_byte_data = mp2855_read_byte_data,
	.read_word_data = mp2855_read_word_data,
};

static int mp2855_vout_scale_get(struct i2c_client *client, struct mp2855_data *data,
				 int vout_mode, int page)
{
	int ret;

	if (vout_mode & GENMASK(7, 5)) {
		/* Direct mode. */
		ret = i2c_smbus_read_word_data(client, MP2855_MFR_VR_CONFIG1);
		if (ret < 0)
			return ret;

		switch (ret >> MP2855_VOUT_CONFIG_OFF) {
		case 0 :
			data->vout_scale[page] = 625;
			break;
		case 1:
			data->vout_scale[page] = 500;
			break;
		default:
			data->vout_scale[page] = 500;
			break;
		}
		return 0;
	}

	/* Linear mode. */
	vout_mode &= GENMASK(4, 0);
	vout_mode = vout_mode >= 16 ? vout_mode - 32 : vout_mode;
	if (vout_mode == -9)
		data->vout_scale[page] = 200;
	else if (vout_mode < 0)
		data->vout_shift[page] = -vout_mode;
	else
		data->vout_shift[page] = vout_mode;

	return 0;
}

static int mp2855_rails_vout_scale_get(struct i2c_client *client, struct mp2855_data *data)
{
	int vout_mode, ret;

	ret = i2c_smbus_write_byte_data(client, PMBUS_PAGE, 0);
	if (ret < 0)
		return ret;

	vout_mode = i2c_smbus_read_word_data(client, PMBUS_VOUT_MODE);
	if (vout_mode < 0)
		return vout_mode;

	/* Get iout_scale for rail 1. */
	ret = mp2855_vout_scale_get(client, data, vout_mode, 0);
	/* Get iout_scale for rail 2. */
	return ret < 0 ? ret : mp2855_vout_scale_get(client, data, vout_mode, 1);
}

static int
mp2855_iout_scale_get(struct i2c_client *client, struct mp2855_data *data, u32 reg, int page)
{
	int ret;

	ret = i2c_smbus_write_byte_data(client, PMBUS_PAGE, page);
	if (ret < 0)
		return ret;

	ret = i2c_smbus_read_word_data(client, reg);
	if (ret < 0)
		return ret;

	data->iout_scale[page] = (ret & MP2855_IOUT_SCALE_MASK) == MP2855_IOUT_SCALE_MASK ?
				 500 : 250;

	return 0;
}

static int mp2855_rails_iout_scale_get(struct i2c_client *client, struct mp2855_data *data)
{
	int ret;

	/* Get iout_scale for rail 1. */
	ret = mp2855_iout_scale_get(client, data, PMBUS_READ_IOUT, 0);
	/* Get iout_scale for rail 2. */
	return ret < 0 ? ret : mp2855_iout_scale_get(client, data, PMBUS_READ_IOUT, 1);
}

static int
mp2855_vout_thresholds_get(struct i2c_client *client, struct mp2855_data *data, int page)
{
	int ret;

	ret = i2c_smbus_write_byte_data(client, PMBUS_PAGE, page);
	if (ret < 0)
		return ret;

	ret = i2c_smbus_read_word_data(client, PMBUS_VOUT_OV_FAULT_LIMIT);
	if (ret < 0)
		return ret;

	switch ((ret & MP2891_OV_TH_MASK) >> MP2891_OV_TH_POS) {
	case 0:
		data->ov_off[page] = 200;
		break;
	case 1:
		data->ov_off[page] = 325;
		break;
	case 2:
		data->ov_off[page] = 450;
		break;
	default:
		return -EINVAL;
	}

	ret = i2c_smbus_read_word_data(client, PMBUS_VOUT_UV_FAULT_LIMIT);
	if (ret < 0)
		return ret;

	switch ((ret & MP2891_UV_TH_MASK) >> MP2891_UV_TH_POS) {
	case 0:
		data->uv_off[page] = 425;
		break;
	case 1:
		data->uv_off[page] = 375;
		break;
	case 2:
		data->uv_off[page] = 325;
		break;
	case 3:
		data->uv_off[page] = 275;
		break;
	case 4:
		data->uv_off[page] = 225;
		break;
	case 5:
		data->uv_off[page] = 175;
		break;
	case 6:
		data->uv_off[page] = 125;
		break;
	case 7:
		data->uv_off[page] = 75;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int mp2855_rails_vout_thresholds_get(struct i2c_client *client, struct mp2855_data *data)
{
	int ret;

	/* Get vout thresholds for rail 1. */
	ret = mp2855_vout_thresholds_get(client, data, 0);
	/* Get vout thresholds for rail 2. */
	return ret < 0 ? ret : mp2855_vout_thresholds_get(client, data, 1);
}

static int mp2855_probe(struct i2c_client *client)
{
	struct pmbus_driver_info *info;
	struct mp2855_data *data;
	int ret;

	data = devm_kzalloc(&client->dev, sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	memcpy(&data->info, &mp2855_info, sizeof(*info));
	info = &data->info;

	ret = mp2855_rails_iout_scale_get(client, data);
	if (ret < 0)
		return ret;
	ret = mp2855_rails_vout_scale_get(client, data);
	if (ret < 0)
		return ret;

	mp2855_rails_vout_thresholds_get(client, data);
	if (ret < 0)
		return ret;

	return pmbus_do_probe(client, info);
}

static const struct i2c_device_id mp2855_id[] = {
	{"mp2855", 0},
	{}
};
MODULE_DEVICE_TABLE(i2c, mp2855_id);

static const struct of_device_id mp2855_of_match[] = {
	{.compatible = "mps,mp2855"},
	{}
};
MODULE_DEVICE_TABLE(of, mp2855_of_match);

static struct i2c_driver mp2855_driver = {
	.driver = {
		.name = "mp2855",
		.of_match_table = mp2855_of_match,
	},
	.probe_new = mp2855_probe,
	.id_table = mp2855_id,
};

module_i2c_driver(mp2855_driver);

MODULE_DESCRIPTION("PMBus driver for MPS MP2855 device");
MODULE_LICENSE("GPL");
MODULE_IMPORT_NS(PMBUS);
