/* Copyright (c) 2016 Arista Networks, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/i2c.h>
#include <linux/device.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/leds.h>
#include <linux/io.h>
#include <linux/version.h>

#define DRIVER_NAME "crow-cpld-fans"

#define NUM_FANS 4
#define LED_NAME_MAX_SZ 20

#define TACH1LOWREG 0
#define TACH1HIGHREG 1
#define TACH2LOWREG 2
#define TACH2HIGHREG 3
#define TACH3LOWREG 4
#define TACH3HIGHREG 5
#define TACH4LOWREG 6
#define TACH4HIGHREG 7

#define FAN_PWM_BASE 0x10
#define FAN_PWM_REG(Num) (FAN_PWM_BASE + (Num))

#define FAN1PWMREG 0x10
#define FAN1IDREG 0x18
#define FAN2PWMREG 0x11
#define FAN2IDREG 0x19
#define FAN3PWMREG 0x12
#define FAN3IDREG 0x1A
#define FAN4PWMREG 0x13
#define FAN4IDREG 0x1B

#define FANPRESENTREG 0x21
#define FANGREENLEDREG 0x24
#define FANREDLEDREG 0x25
#define CROWCPLDREVREG 0x40
#define SCRATCHREG 0x41

#define FAN_LED_OFF 0
#define FAN_LED_GREEN 1
#define FAN_LED_RED 2
#define FAN_LED_AMBER 3

#define FAN_MAX_PWM 255

static bool safe_mode = true;
module_param(safe_mode, bool, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(safe_mode, "force fan speed to 100% during probe");

struct crow_led {
    char name[LED_NAME_MAX_SZ];
    struct led_classdev cdev;
    int fan_index;
};

struct crow_cpld_data {
    struct i2c_client *client;
    struct crow_led leds[NUM_FANS];
};

static s32 read_cpld(struct device *dev, u8 reg, char *buf)
{
    int err;
    struct crow_cpld_data *data = dev_get_drvdata(dev);
    struct i2c_client *client = data->client;

    err = i2c_smbus_read_byte_data(client, reg);
    if (err < 0) {
        dev_err(dev, "failed to read reg %d of with error code: %d\n", reg, err);
        return err;
    }

    *buf = (err & 0xFF);
    return 0;
}

static s32 write_cpld(struct device *dev, u8 reg, u8 byte)
{
    int err;
    struct crow_cpld_data *data = dev_get_drvdata(dev);
    struct i2c_client *client = data->client;

    err = i2c_smbus_write_byte_data(client, reg, byte);
    if (err) {
        dev_err(dev, "failed to write %02x in reg %02x of with error code: %d\n",
                byte, reg, err);
    }

    return err;
}

static s32 read_cpld_buf(struct device *dev, u8 reg, char *buf)
{
    s32 status;
    u8 data;

    status = read_cpld(dev, reg, &data);
    if (status) {
        return status;
    }

    return sprintf(buf, "%hhu\n", data);
}

static s32 write_cpld_buf(struct device *dev, u8 reg, const char *buf)
{
    u8 data;
    s32 status;

    if (sscanf(buf, "%hhu", &data) != 1) {
        return -EINVAL;
    }

    status = write_cpld(dev, reg, data);

    return status;
}

static s32 read_led_color(struct device *dev, int index, u8 *color)
{
    s32 err;
    u8 data;
    unsigned char read_value_g = 0;
    unsigned char read_value_r = 0;

    err = read_cpld(dev, FANGREENLEDREG, &data);
    if (err)
        return err;
    read_value_g = (data >> index) & 0x01;

    err = read_cpld(dev, FANREDLEDREG, &data);
    if (err)
        return err;
    read_value_r = (data >> index) & 0x01;

    *color = FAN_LED_OFF;
    if((!read_value_g) && read_value_r) {
       *color = FAN_LED_GREEN;
    } else if (read_value_g && (!read_value_r)) {
       *color = FAN_LED_RED;
    } else if((!read_value_g) && (!read_value_r)) {
       *color = FAN_LED_AMBER;
    }

    return 0;
}

static s32 read_led_color_buf(struct device *dev, char *buf, int index)
{
    int err;
    u8 val;

    err = read_led_color(dev, index, &val);
    if (err)
        return err;

    return sprintf(buf, "%d\n", val);
}

static s32 write_led_color(struct device *dev, u8 value, int index)
{
    s32 status;
    u8 red_value;
    u8 green_value;
    u8 green_led;
    u8 red_led;

    if (value > 3)
        return -EINVAL;

    switch (value) {
    case FAN_LED_GREEN:
        green_led = 1;
        red_led = 0;
        break;
    case FAN_LED_RED:
        green_led = 0;
        red_led = 1;
        break;
    case FAN_LED_AMBER:
        green_led = 1;
        red_led = 1;
        break;
    case FAN_LED_OFF:
    default:
        green_led = 0;
        red_led = 0;
        break;
    }

    status = read_cpld(dev, FANGREENLEDREG, &green_value);
    if (status) {
        return status;
    }

    status = read_cpld(dev, FANREDLEDREG, &red_value);
    if (status) {
        return status;
    }

    if (green_led) {
        green_value &= ~(1u << index);
    } else {
        green_value |= (1u << index);
    }

    if (red_led) {
        red_value &= ~(1u << index);
    } else {
        red_value |= (1u << index);
    }

    status = write_cpld(dev, FANGREENLEDREG, green_value);
    status |= write_cpld(dev, FANREDLEDREG, red_value);

    return status;
}

static s32 write_led_color_buf(struct device *dev, const char *buf, int index)
{
    u8 value;

    if (sscanf(buf, "%hhu", &value) != 1) {
        return -EINVAL;
    }

    return write_led_color(dev, value, index);
}

static s32 read_tach(struct device *dev, u8 tachHigh, u8 tachLow, u32 *speed)
{
    s32 status;
    u8 dataHigh;
    u8 dataLow;
    u32 tachData;

    status = read_cpld(dev, tachLow, &dataLow);
    status |= read_cpld(dev, tachHigh, &dataHigh);
    if (status) {
        return status;
    }

    tachData = (dataHigh << 8) + dataLow;
    if (!tachData) {
        tachData = 1;
    }
    *speed = 6000000 / tachData;
    *speed = *speed / 2;

    return 0;
}

static s32 read_tach_buf(struct device *dev, u8 tachHigh, u8 tachLow,
                         char *buf)
{
    u32 speed;
    int err;

    err = read_tach(dev, tachHigh, tachLow, &speed);
    if (err)
        return err;

    return sprintf(buf, "%d\n", speed);
}

static s32 read_fan_present(struct device *dev, int index, u8 *present)
{
    s32 status;
    u8 data;

    *present = 0;
    status = read_cpld(dev, FANPRESENTREG, &data);
    if (status) {
        return status;
    }

    *present = ~(data >> index) & 0x01;
    return 0;
}

static s32 read_fan_present_buf(struct device *dev, char *buf, int index)
{
    int err;
    u8 present;

    err = read_fan_present(dev, index, &present);
    if (err)
        return err;

    return sprintf(buf, "%d\n", present);
}

static s32 read_fan_airflow(struct device *dev, u8 reg, char *buf)
{
    s32 status;
    u8 id;

    status = read_cpld(dev, reg, &id);
    if (status) {
        return status;
    }

    return sprintf(buf, "%s\n", (id & 0x4) ? "forward" : "reverse");
}

#define GENERIC_FAN_READ(_name, _dev, _reg)                                         \
static ssize_t fan_##_name##_##_dev##_show(struct device *dev,                      \
                                           struct device_attribute *attr,           \
                                           char *buf)                               \
{                                                                                   \
    return read_cpld_buf(dev, _reg, buf);                                           \
}                                                                                   \

#define GENERIC_FAN_WRITE(_name, _dev, _reg)                                        \
static ssize_t fan_##_name##_##_dev##_store(struct device *dev,                     \
                                            struct device_attribute *attr,          \
                                            const char *buf, size_t count)          \
{                                                                                   \
    write_cpld_buf(dev, _reg, buf);                                                 \
    return count;                                                                   \
}                                                                                   \

#define GENERIC_LED(_name)                                                          \
static ssize_t fan_##_name##_led_show(struct device *dev,                           \
                                      struct device_attribute *attr, char *buf)     \
{                                                                                   \
    return read_led_color_buf(dev, buf, _name-1);                                   \
}                                                                                   \
static ssize_t fan_##_name##_led_store(struct device *dev,                          \
                                       struct device_attribute *attr,               \
                                       const char *buf, size_t count)               \
{                                                                                   \
    write_led_color_buf(dev, buf, _name-1);                                         \
    return count;                                                                   \
}                                                                                   \
DEVICE_ATTR(fan##_name##_led, S_IRUGO|S_IWGRP|S_IWUSR,                              \
            fan_##_name##_led_show, fan_##_name##_led_store);                       \


#define FAN_DEVICE_ATTR(_name)                                                      \
static ssize_t tach_##_name##_show(struct device *dev,                              \
                                   struct device_attribute *attr, char *buf)        \
{                                                                                   \
    return read_tach_buf(dev, TACH##_name##HIGHREG, TACH##_name##LOWREG, buf);      \
}                                                                                   \
DEVICE_ATTR(fan##_name##_input, S_IRUGO, tach_##_name##_show, NULL);                \
                                                                                    \
GENERIC_FAN_READ(_name, id, FAN##_name##IDREG);                                     \
DEVICE_ATTR(fan##_name##_id, S_IRUGO, fan_##_name##_id_show, NULL);                 \
                                                                                    \
static ssize_t fan_##_name##_airflow_show(struct device *dev,                       \
                                          struct device_attribute *attr, char *buf) \
{                                                                                   \
    return read_fan_airflow(dev, FAN##_name##IDREG, buf);                           \
}                                                                                   \
DEVICE_ATTR(fan##_name##_airflow, S_IRUGO, fan_##_name##_airflow_show, NULL);       \
                                                                                    \
GENERIC_FAN_READ(_name, pwm, FAN##_name##PWMREG);                                   \
GENERIC_FAN_WRITE(_name, pwm, FAN##_name##PWMREG);                                  \
DEVICE_ATTR(pwm##_name, S_IRUGO|S_IWGRP|S_IWUSR,                                    \
            fan_##_name##_pwm_show, fan_##_name##_pwm_store);                       \
                                                                                    \
static ssize_t fan_##_name##_present_show(struct device *dev,                       \
                                          struct device_attribute *attr, char *buf) \
{                                                                                   \
    return read_fan_present_buf(dev, buf, _name-1);                                 \
}                                                                                   \
DEVICE_ATTR(fan##_name##_present, S_IRUGO, fan_##_name##_present_show, NULL);       \
                                                                                    \
GENERIC_LED(_name)                                                                  \


static ssize_t crow_cpld_rev_show(struct device *dev,
                                  struct device_attribute *attr, char *buf)
{
    return read_cpld_buf(dev, CROWCPLDREVREG, buf);
}

DEVICE_ATTR(crow_cpld_rev, S_IRUGO, crow_cpld_rev_show, NULL);

FAN_DEVICE_ATTR(1);
FAN_DEVICE_ATTR(2);
FAN_DEVICE_ATTR(3);
FAN_DEVICE_ATTR(4);

#define FANATTR(_name)                   \
    &dev_attr_pwm##_name.attr,           \
    &dev_attr_fan##_name##_id.attr,      \
    &dev_attr_fan##_name##_airflow.attr, \
    &dev_attr_fan##_name##_input.attr,   \
    &dev_attr_fan##_name##_present.attr, \
    &dev_attr_fan##_name##_led.attr,     \


static struct attribute *fan_attrs[] = {
    FANATTR(1)
    FANATTR(2)
    FANATTR(3)
    FANATTR(4)
    &dev_attr_crow_cpld_rev.attr,
    NULL,
};

ATTRIBUTE_GROUPS(fan);

static void brightness_set(struct led_classdev *led_cdev,
                           enum led_brightness value)
{
    struct crow_led *pled = container_of(led_cdev, struct crow_led, cdev);
    struct device *dev = led_cdev->dev->parent;

    write_led_color(dev, value, pled->fan_index);
}

static enum led_brightness brightness_get(struct led_classdev *led_cdev)
{
    struct crow_led *pled = container_of(led_cdev, struct crow_led, cdev);
    struct device *dev = led_cdev->dev->parent;
    u8 val;
    int err;

    err =  read_led_color(dev, pled->fan_index, &val);
    if (err)
        return 0;

    return val;
}

static void leds_unregister(struct crow_cpld_data *data, int num_leds)
{
   int i = 0;

   for (i = 0; i < num_leds; i++)
      led_classdev_unregister(&data->leds[i].cdev);
}

static int leds_init(struct crow_led *leds, struct i2c_client *client)
{
    int i;
    int err;
    struct crow_cpld_data *data = i2c_get_clientdata(client);

    for (i = 0; i < NUM_FANS; i++) {
        leds[i].fan_index = i;
        leds[i].cdev.brightness_set = brightness_set;
        leds[i].cdev.brightness_get = brightness_get;
        scnprintf(leds[i].name, LED_NAME_MAX_SZ, "fan%d", leds[i].fan_index + 1);
        leds[i].cdev.name = leds[i].name;
    }

    // fan leds initialized to green because no fan fault reg on crow
    for (i = 0 ; i < NUM_FANS; i++) {
        err = led_classdev_register(&client->dev, &leds[i].cdev);
        if (err) {
            dev_err(&client->dev, "failed to register led fan%d", i);
            goto fail;
        }
        err = write_led_color(&client->dev, FAN_LED_GREEN, i);
        if (err) {
            dev_err(&client->dev, "failed to set led fan%d", i);
            // this is not considered as a critical error, fans are more important
        }
    }

    return 0;

fail:
    for (; i >= 0; i--) {
        leds_unregister(data, i);
    }
    return err;
}

static void crow_print_version(struct i2c_client *client)
{
    char version;
    int err;

    err = read_cpld(&client->dev, CROWCPLDREVREG, &version);
    if (err) {
       dev_warn(&client->dev, "failed to obtain CPLD version");
    } else {
       dev_info(&client->dev, "CPLD version 0x%02x", version);
    }
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
static int
#else
static void
#endif
crow_cpld_remove(struct i2c_client *client)
{
    struct crow_cpld_data *data = i2c_get_clientdata(client);

    leds_unregister(data, NUM_FANS);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
    return 0;
#endif
}

static void crow_force_fan_speed(struct i2c_client *client, u8 pwm)
{
   int i;

   dev_info(&client->dev, "forcing fan speed to %hhu (safe_mode)", pwm);
   for (i = 0; i < NUM_FANS; i++) {
      write_cpld(&client->dev, FAN_PWM_REG(i), pwm);
   }
}

static int crow_cpld_probe(struct i2c_client *client
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
                           , const struct i2c_device_id *id
#endif
                          )
{
    int err;
    struct device *dev = &client->dev;
    struct device *hwmon_dev;
    struct crow_cpld_data *data;

    data = devm_kzalloc(dev, sizeof(struct crow_cpld_data), GFP_KERNEL);
    if (!data)
        return -ENOMEM;

    i2c_set_clientdata(client, data);
    data->client = client;
    hwmon_dev = devm_hwmon_device_register_with_groups(dev, client->name,
                                                       data, fan_groups);
    if (IS_ERR(hwmon_dev))
        return PTR_ERR(hwmon_dev);

    crow_print_version(client);

    if (safe_mode)
       crow_force_fan_speed(client, FAN_MAX_PWM);

    err = leds_init(data->leds, client);
    if (err)
        return err;

    return 0;
}

static const struct i2c_device_id crow_cpld_id[] = {
    { "crow_cpld", 0 },
    { }
};

MODULE_DEVICE_TABLE(i2c, crow_cpld_id);

static struct i2c_driver crow_cpld_driver = {
    .driver = {
        .name = DRIVER_NAME
    },
    .id_table = crow_cpld_id,
    .probe = crow_cpld_probe,
    .remove = crow_cpld_remove,
};

module_i2c_driver(crow_cpld_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arista Networks");
MODULE_DESCRIPTION("Crow Fan driver");
