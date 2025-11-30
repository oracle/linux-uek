// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * max31790.c - Part of lm_sensors, Linux kernel modules for hardware
 *             monitoring.
 *
 * This driver is a reuse of the official max31790 available upstream.
 * Because the max31790 chip is highly configurable, the version available in the
 * open source didn't fit our needs.
 * Changing the open source version of the driver was kept out of the picture
 * because we want to expose a different interface to the userland.
 * The mapping between pwm/tach pins is managed by the kernel driver instead of
 * requiring userland software to make sense of which sysfs entry correspond to
 * which fan.
 * Each fan has a pwm and tach sysfs entry even though some fans can share the same
 * pwm register. This decision was made consciently as a mean to ease the userland
 * programming model.
 *
 * (C) 2015 by Il Han <corone.il.han@gmail.com>
 */

#include <linux/err.h>
#include <linux/hwmon.h>
#include <linux/i2c.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/version.h>

/* MAX31790 registers */
#define MAX31790_REG_GLOBAL_CONFIG	0x00
#define MAX31790_REG_FAN_CONFIG(ch)	(0x02 + (ch))
#define MAX31790_REG_FAN_DYNAMICS(ch)	(0x08 + (ch))
#define MAX31790_REG_FAN_FAULT_STATUS2	0x10
#define MAX31790_REG_FAN_FAULT_STATUS1	0x11
#define MAX31790_REG_FAN_FAILED_OPTIONS	0x14
#define MAX31790_REG_TACH_COUNT(ch)	(0x18 + (ch) * 2)
#define MAX31790_REG_PWM_DUTY_CYCLE(ch)	(0x30 + (ch) * 2)
#define MAX31790_REG_PWMOUT(ch)		(0x40 + (ch) * 2)
#define MAX31790_REG_TARGET_COUNT(ch)	(0x50 + (ch) * 2)
#define MAX31790_REG_TARGET_COUNT_MSB(ch)	(0x50 + (ch) * 2)
#define MAX31790_REG_TARGET_COUNT_LSB(ch)	(0x51 + (ch) * 2)

/* Fan Config register bits */
#define MAX31790_FAN_CFG_RPM_MODE	0x80
#define MAX31790_FAN_CFG_TACH_INPUT_EN	0x08
#define MAX31790_FAN_CFG_TACH_INPUT	0x01

/* Fan Dynamics register bits */
#define MAX31790_FAN_DYN_SR_SHIFT	5
#define MAX31790_FAN_DYN_SR_MASK	0xE0
#define SR_FROM_REG(reg)		(((reg) & MAX31790_FAN_DYN_SR_MASK) \
					 >> MAX31790_FAN_DYN_SR_SHIFT)

#define FAN_RPM_MIN			120
#define FAN_RPM_MAX			7864320

#define RPM_FROM_REG(reg, sr)		(((reg) >> 4) ? \
					 ((60 * (sr) * 8192) / ((reg) >> 4)) : \
					 FAN_RPM_MAX)
#define RPM_TO_REG(rpm, sr)		((60 * (sr) * 8192) / ((rpm) * 2))

#define NR_CHANNEL			6

/*
 * Fan configuration within the chip
 */
struct max31790_fan_config {
	u8 pwm;
	u8 tach; // tach has a value > 6 it means pwm (tach - 6) configured as tach
};

struct max31790_fan {
	u8 pwm_idx;
	u8 tach_idx;
	u8 config;
	u8 dynamics;
	u8 fault;
	u16 tach;
	u16 pwm;
	u16 target_count;
};

/*
 * Client data (each client gets its own)
 */
struct max31790_data {
	struct i2c_client *client;
	struct mutex update_lock;
	struct max31790_fan fans[NR_CHANNEL * 2];
	unsigned long fan_count;
	bool valid; /* zero until following fields are valid */
	unsigned long last_updated; /* in jiffies */
};

static int __max31790_update_device(struct i2c_client *client,
				    struct max31790_data *data)
{
	struct max31790_fan *fan;
	int i;
	int rv;
	u16 fault_status;
	u16 pwm[NR_CHANNEL] = { 0 };

	rv = i2c_smbus_read_byte_data(client,
			MAX31790_REG_FAN_FAULT_STATUS1);
	if (rv < 0)
		goto abort;
	fault_status = rv & 0x3F;

	rv = i2c_smbus_read_byte_data(client,
			MAX31790_REG_FAN_FAULT_STATUS2);
	if (rv < 0)
		goto abort;
	fault_status |= (rv & 0x3F) << 6;

	for (i = 0; i < data->fan_count; i++) {
		fan = &data->fans[i];
		fan->fault = !!(fault_status & (1 << fan->tach_idx));

		rv = i2c_smbus_read_word_swapped(client,
				MAX31790_REG_TACH_COUNT(fan->tach_idx));
		if (rv < 0)
			goto abort;
		fan->tach = rv;

		if (!pwm[fan->pwm_idx]) {
			rv = i2c_smbus_read_word_swapped(client,
					MAX31790_REG_PWMOUT(fan->pwm_idx));
			if (rv < 0)
				goto abort;
			pwm[fan->pwm_idx] = rv;
		}
		fan->pwm = pwm[fan->pwm_idx];
	}

abort:
	return rv;
}

static struct max31790_data *max31790_update_device(struct device *dev)
{
	struct max31790_data *data = dev_get_drvdata(dev);
	struct i2c_client *client = data->client;
	struct max31790_data *ret = data;
	int rv;

	mutex_lock(&data->update_lock);

	if (time_after(jiffies, data->last_updated + HZ) || !data->valid) {
		rv = __max31790_update_device(client, data);
		if (rv < 0) {
			data->valid = false;
			ret = ERR_PTR(rv);
		} else {
			data->valid = true;
			data->last_updated = jiffies;
		}
	}

	mutex_unlock(&data->update_lock);

	return ret;
}

static const u8 tach_period[8] = { 1, 2, 4, 8, 16, 32, 32, 32 };

static u8 get_tach_period(u8 fan_dynamics)
{
	return tach_period[SR_FROM_REG(fan_dynamics)];
}

static int max31790_read_fan(struct device *dev, u32 attr, int channel,
			     long *val)
{
	const struct max31790_data *data = max31790_update_device(dev);
	const struct max31790_fan *fan;
	int sr, rpm;

	if (IS_ERR(data))
		return PTR_ERR(data);

	fan = &data->fans[channel];

	switch (attr) {
	case hwmon_fan_input:
		sr = get_tach_period(fan->dynamics);
		rpm = RPM_FROM_REG(fan->tach, sr);
		*val = rpm;
		return 0;
	case hwmon_fan_fault:
		*val = fan->fault;
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static int max31790_write_fan(struct device *dev, u32 attr, int channel,
			      long val)
{
	return -EOPNOTSUPP;
}

static umode_t max31790_fan_is_visible(const void *_data, u32 attr, int channel)
{
	const struct max31790_data *data = _data;

	switch (attr) {
	case hwmon_fan_input:
	case hwmon_fan_fault:
		if (channel < data->fan_count)
			return 0444;
		return 0;
	default:
		return 0;
	}
}

static int max31790_read_pwm(struct device *dev, u32 attr, int channel,
			     long *val)
{
	const struct max31790_data *data = max31790_update_device(dev);
	const struct max31790_fan *fan;

	if (IS_ERR(data))
		return PTR_ERR(data);

	fan = &data->fans[channel];

	switch (attr) {
	case hwmon_pwm_input:
		*val = fan->pwm >> 8;
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static int max31790_write_pwm(struct device *dev, u32 attr, int channel,
			      long val)
{
	struct max31790_data *data = dev_get_drvdata(dev);
	struct max31790_fan *fan = &data->fans[channel];
	struct i2c_client *client = data->client;
	int err = 0;

	mutex_lock(&data->update_lock);

	switch (attr) {
	case hwmon_pwm_input:
		if (val < 0 || val > 255) {
			err = -EINVAL;
			break;
		}
		fan->pwm = val << 8; // FIXME: change related entries for other fans
		err = i2c_smbus_write_word_swapped(client,
						   MAX31790_REG_PWMOUT(fan->pwm_idx),
						   fan->pwm);
		break;
	default:
		err = -EOPNOTSUPP;
		break;
	}

	mutex_unlock(&data->update_lock);

	return err;
}

static umode_t max31790_pwm_is_visible(const void *_data, u32 attr, int channel)
{
	const struct max31790_data *data = _data;

	switch (attr) {
	case hwmon_pwm_input:
		if (channel < data->fan_count)
			return 0644;
		return 0;
	default:
		return 0;
	}
}

static int max31790_read(struct device *dev, enum hwmon_sensor_types type,
			 u32 attr, int channel, long *val)
{
	switch (type) {
	case hwmon_fan:
		return max31790_read_fan(dev, attr, channel, val);
	case hwmon_pwm:
		return max31790_read_pwm(dev, attr, channel, val);
	default:
		return -EOPNOTSUPP;
	}
}

static int max31790_write(struct device *dev, enum hwmon_sensor_types type,
			  u32 attr, int channel, long val)
{
	switch (type) {
	case hwmon_fan:
		return max31790_write_fan(dev, attr, channel, val);
	case hwmon_pwm:
		return max31790_write_pwm(dev, attr, channel, val);
	default:
		return -EOPNOTSUPP;
	}
}

static umode_t max31790_is_visible(const void *data,
				   enum hwmon_sensor_types type,
				   u32 attr, int channel)
{
	switch (type) {
	case hwmon_fan:
		return max31790_fan_is_visible(data, attr, channel);
	case hwmon_pwm:
		return max31790_pwm_is_visible(data, attr, channel);
	default:
		return 0;
	}
}

static const u32 max31790_fan_config[] = {
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	HWMON_F_INPUT | HWMON_F_FAULT,
	0
};

static const struct hwmon_channel_info max31790_fan = {
	.type = hwmon_fan,
	.config = max31790_fan_config,
};

static const u32 max31790_pwm_config[] = {
	HWMON_PWM_INPUT,
	HWMON_PWM_INPUT,
	HWMON_PWM_INPUT,
	HWMON_PWM_INPUT,
	HWMON_PWM_INPUT,
	HWMON_PWM_INPUT,
	HWMON_PWM_INPUT,
	HWMON_PWM_INPUT,
	HWMON_PWM_INPUT,
	HWMON_PWM_INPUT,
	HWMON_PWM_INPUT,
	HWMON_PWM_INPUT,
	0
};

static const struct hwmon_channel_info max31790_pwm = {
	.type = hwmon_pwm,
	.config = max31790_pwm_config,
};

static const struct hwmon_channel_info *max31790_info[] = {
	&max31790_fan,
	&max31790_pwm,
	NULL
};

static const struct hwmon_ops max31790_hwmon_ops = {
	.is_visible = max31790_is_visible,
	.read = max31790_read,
	.write = max31790_write,
};

static const struct hwmon_chip_info max31790_chip_info = {
	.ops = &max31790_hwmon_ops,
	.info = max31790_info,
};

static int max31790_init_client(struct i2c_client *client,
				struct max31790_data *data,
				const struct max31790_fan_config *configs)
{
	const struct max31790_fan_config *cfg;
	int i, err;
	struct max31790_fan *fan;
	u8 fan_config = 0x08; // tach input enable
	u8 fan_dynamics = 0xe8; // speed range 0b111, pwm rate of change 0b010
	u16 target_count = 0xffc0;

	// busTimeout = 1
	err = i2c_smbus_write_byte_data(client, MAX31790_REG_GLOBAL_CONFIG, 0x20);
	if (err)
		return err;

	// failed fan options = 0b01
	i2c_smbus_write_byte_data(client, MAX31790_REG_FAN_FAILED_OPTIONS, 0x40);

	// Initialize all fans with the same configuration
	for (i = 0; i < NR_CHANNEL; i++) {
		i2c_smbus_write_byte_data(client, MAX31790_REG_FAN_CONFIG(i),
					  fan_config);
		i2c_smbus_write_byte_data(client, MAX31790_REG_FAN_DYNAMICS(i),
					  fan_dynamics);
		i2c_smbus_write_byte_data(client, MAX31790_REG_TARGET_COUNT_MSB(i),
					  target_count >> 8);
		i2c_smbus_write_byte_data(client, MAX31790_REG_TARGET_COUNT_LSB(i),
					  target_count & 0xff);
	}

	// Abstract fans from the pins they use and reconfigure pwm to tach regs
	for (i = 0; configs[i].pwm; i++) {
		cfg = &configs[i];
		fan = &data->fans[i];

		fan->pwm_idx = cfg->pwm - 1;
		fan->tach_idx = cfg->tach - 1;
		// tach input enable
		fan->config = fan_config;
		// speed range 0b111, pwm rate of change 0b010
		fan->dynamics = fan_dynamics;
		fan->target_count = target_count;

		if (fan->tach_idx >= NR_CHANNEL) {
			i2c_smbus_write_byte_data(client,
						  MAX31790_REG_FAN_CONFIG(fan->tach_idx % NR_CHANNEL),
						  fan->config | 0x01);
		}
	}

	data->fan_count = i;

	return err;
}

static int max31790_probe(struct i2c_client *client
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
			, const struct i2c_device_id *id
#endif
			 )
{
	struct i2c_adapter *adapter = client->adapter;
	struct device *dev = &client->dev;
	struct max31790_data *data;
	struct device *hwmon_dev;
	const struct max31790_fan_config *config;
	int err;

	if (!i2c_check_functionality(adapter,
			I2C_FUNC_SMBUS_BYTE_DATA | I2C_FUNC_SMBUS_WORD_DATA))
		return -ENODEV;

	data = devm_kzalloc(dev, sizeof(struct max31790_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	data->client = client;
	mutex_init(&data->update_lock);

	/*
	 * Initialize the max31790 chip
	 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	config = (const struct max31790_fan_config *)id->driver_data;
#else
	config = (const struct max31790_fan_config *)i2c_get_match_data(client);
#endif
	err = max31790_init_client(client, data, config);
	if (err)
		return err;

	hwmon_dev = devm_hwmon_device_register_with_info(dev, client->name,
							 data,
							 &max31790_chip_info,
							 NULL);

	return PTR_ERR_OR_ZERO(hwmon_dev);
}

static const struct max31790_fan_config fan_config_a1[] = {
	{ .pwm = 1, .tach = 1 },
	{ .pwm = 1, .tach = 2 },
	{ .pwm = 3, .tach = 3 },
	{ .pwm = 3, .tach = 8 },
	{ .pwm = 4, .tach = 4 },
	{ .pwm = 4, .tach = 5 },
	{ .pwm = 6, .tach = 6 },
	{ .pwm = 6, .tach = 11 },
	{}
};

static const struct max31790_fan_config fan_config_a2[] = {
	{ .pwm = 1, .tach = 1 },
	{ .pwm = 1, .tach = 2 },
	{ .pwm = 4, .tach = 4 },
	{ .pwm = 4, .tach = 5 },
	{ .pwm = 3, .tach = 3 },
	{ .pwm = 3, .tach = 8 },
	{ .pwm = 6, .tach = 6 },
	{ .pwm = 6, .tach = 11 },
	{}
};

static const struct i2c_device_id max31790_id[] = {
	{ "amax31790_4u", (kernel_ulong_t)fan_config_a1 },
	{ "amax31790_8u", (kernel_ulong_t)fan_config_a2 },
	{}
};
MODULE_DEVICE_TABLE(i2c, max31790_id);

static struct i2c_driver max31790_driver = {
	.class		= I2C_CLASS_HWMON,
	.probe		= max31790_probe,
	.driver = {
		.name	= "amax31790",
	},
	.id_table	= max31790_id,
};

module_i2c_driver(max31790_driver);

MODULE_AUTHOR("Il Han <corone.il.han@gmail.com>");
MODULE_DESCRIPTION("MAX31790 sensor driver for Arista");
MODULE_LICENSE("GPL");
