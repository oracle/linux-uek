/* Copyright (c) 2017 Arista Networks, Inc.
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
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/i2c.h>
#include <linux/leds.h>
#include <linux/version.h>

// led -> gpio pin mapping
#define PS2_STATUS_LEDR	0
#define PS2_STATUS_LEDG	1
#define PS1_STATUS_LEDR	2
#define PS1_STATUS_LEDG	3
#define FAN_STATUS_LEDR	4
#define FAN_STATUS_LEDG	5
#define STATUS_LEDR	6
#define STATUS_LEDG	7
#define STATUS_LEDB	8

// pca9555 register mapping
#define INPUT_PORT_0	0
#define INPUT_PORT_1	1
#define OUTPUT_PORT_0	2
#define OUTPUT_PORT_1	3
#define POL_INV_PORT_0	4
#define POL_INV_PORT_1	5
#define CONFIG_PORT_0	6
#define CONFIG_PORT_1	7

// pca9555 bank info
#define BANK_SZ		8
#define NGPIO		16
#define NUM_BANKS	2
#define BANK_SHIFT	1
#define NUM_LEDS	9

#define LED_ON		1
#define OUTPUT		0
#define INPUT		1

#define LED_NAME_MAX_SZ	40

struct pca9555_led {
	char name[LED_NAME_MAX_SZ];
	int pin;
	int on; // value to write to pin for led to turn on
	struct led_classdev cdev;
};

struct pca9555_chip {
	u8 reg_output[NUM_BANKS];
	u8 reg_direction[NUM_BANKS];
	int num_leds;
	char *dev_name;
	struct mutex i2c_lock;
	struct i2c_client *client;
	struct pca9555_led leds[NUM_LEDS];
};

static u8 new_reg_val(u8 reg_val_prev, int pin, int val)
{
	if (val)
		return reg_val_prev | (1u << (pin % BANK_SZ));
	else
		return reg_val_prev & ~(1u << (pin % BANK_SZ));
}

static int pca9555_write_single(struct pca9555_chip *chip, int reg, int val)
{
	int ret;

	ret = i2c_smbus_write_byte_data(chip->client, reg, val);
	if (ret < 0) {
		dev_err(&chip->client->dev, "Failed writing register %d\n", reg);
		return ret;
	}

	return 0;
}

static int pca9555_set_value(struct pca9555_chip *chip, int pin, int val)
{
	int reg, ret;
	u8 reg_val;

	mutex_lock(&chip->i2c_lock);

	reg_val = new_reg_val(chip->reg_output[pin / BANK_SZ], pin, val);
	if (pin >= BANK_SZ)
		reg = OUTPUT_PORT_1;
	else
		reg = OUTPUT_PORT_0;
	ret = pca9555_write_single(chip, reg, reg_val);

	if (!ret)
		chip->reg_output[pin / BANK_SZ] = reg_val;

	mutex_unlock(&chip->i2c_lock);

	return ret;
}

static void brightness_set(struct led_classdev *led_cdev,
			   enum led_brightness value)
{
	struct pca9555_led *pled = container_of(led_cdev, struct pca9555_led,
						cdev);
	struct pca9555_chip *chip = dev_get_drvdata(led_cdev->dev->parent);

	if ((int)value == LED_ON)
		pca9555_set_value(chip, pled->pin, pled->on);
	else
		pca9555_set_value(chip, pled->pin, !pled->on);
}

static void set_led_name(struct i2c_client *client, char *name, const char *color,
			 const char *fun)
{
	struct pca9555_chip *chip = dev_get_drvdata(&client->dev);

	scnprintf(name, LED_NAME_MAX_SZ, "%s:%s:%s", chip->dev_name, color, fun);
}

static void led_init(struct pca9555_led *led, struct i2c_client *client,
		     const char *color, const char *fun, int pin, int on)
{
	set_led_name(client, led->name, color, fun);
	led->cdev.name = led->name;
	led->pin = pin;
	led->on = on;
	led->cdev.brightness_set = brightness_set;
}

static void leds_init(struct pca9555_led *leds, struct i2c_client *client)
{
	led_init(&leds[0], client, "green", "status", STATUS_LEDG, 0);
	led_init(&leds[1], client, "red", "status", STATUS_LEDR, 0);
	led_init(&leds[2], client, "green", "fan_status", FAN_STATUS_LEDG, 0);
	led_init(&leds[3], client, "red", "fan_status", FAN_STATUS_LEDR, 0);
	led_init(&leds[4], client, "green", "psu1_status", PS1_STATUS_LEDG, 0);
	led_init(&leds[5], client, "red", "psu1_status", PS1_STATUS_LEDR, 0);
	led_init(&leds[6], client, "green", "psu2_status", PS2_STATUS_LEDG, 0);
	led_init(&leds[7], client, "red", "psu2_status", PS2_STATUS_LEDR, 0);
	led_init(&leds[8], client, "blue", "beacon", STATUS_LEDB, 1);
}

static int leds_pca9555_detect(struct i2c_client *client)
{
	if (i2c_smbus_read_byte_data(client, CONFIG_PORT_0) < 0)
		return -ENODEV;
	return 0;
}

static int leds_pca9555_all_output(struct i2c_client *client)
{
	int err;
	struct pca9555_chip *chip;

	chip = dev_get_drvdata(&client->dev);

	err = i2c_smbus_write_byte_data(client, CONFIG_PORT_0, OUTPUT);
	if (err)
		return err;
	chip->reg_direction[0] = OUTPUT;

	err = i2c_smbus_write_byte_data(client, CONFIG_PORT_1, OUTPUT);
	if (err)
		return err;
	chip->reg_direction[1] = OUTPUT;

	return 0;
}

static int leds_pca9555_all_set(struct i2c_client *client, u8 bank1_val,
				u8 bank2_val)
{
	int err;
	struct pca9555_chip *chip;

	chip = dev_get_drvdata(&client->dev);

	err = i2c_smbus_write_byte_data(client, OUTPUT_PORT_0, bank1_val);
	if (err)
		return err;
	chip->reg_output[0] = bank1_val;

	err = i2c_smbus_write_byte_data(client, OUTPUT_PORT_1, bank2_val);
	if (err)
		return err;
	chip->reg_output[1] = bank2_val;

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
static int
#else
static void
#endif
leds_pca9555_remove(struct i2c_client *client)
{
	int i;
	struct pca9555_chip *chip = i2c_get_clientdata(client);

	for (i = 0; i < chip->num_leds; i++)
		led_classdev_unregister(&chip->leds[i].cdev);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
	return 0;
#endif
}

static int leds_pca9555_probe(struct i2c_client *client
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
			      , const struct i2c_device_id *id
#endif
			     )
{
	int i, err;
	struct pca9555_chip *chip;

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_SMBUS_BYTE_DATA)) {
		dev_err(&client->dev, "adapter doesn't support byte transactions\n");
		return -ENODEV;
	}

	err = leds_pca9555_detect(client);
	if (err)
		return err;

	chip = devm_kzalloc(&client->dev, sizeof(struct pca9555_chip),
			    GFP_KERNEL);
	if (chip == NULL)
		return -ENOMEM;

	mutex_init(&chip->i2c_lock);
	chip->client = client;
	chip->dev_name = client->name;
	i2c_set_clientdata(client, chip);

	leds_init(chip->leds, client);

	// configure all pins as output and off from the start
	err = leds_pca9555_all_output(client);
	if (err)
		return err;

	err = leds_pca9555_all_set(client, 0xff, 0);
	if (err)
		return err;

	// then set all leds to green
	err = leds_pca9555_all_set(client, 0x55, 0);
	if (err)
		return err;

	chip->num_leds = 0;
	for (i = 0; i < NUM_LEDS; i++) {
		err = led_classdev_register(&client->dev, &chip->leds[i].cdev);
		if (err) {
			leds_pca9555_remove(client);
			return err;
		}
		chip->num_leds += 1;
	}

	return 0;
}

static const struct i2c_device_id leds_pca9555_id[] = {
	{"rook_leds", 0},
	{},
};

MODULE_DEVICE_TABLE(i2c, leds_pca9555_id);

static struct i2c_driver leds_pca9555_driver = {
	.driver = {
		.name = "rook_leds"
	},
	.probe = leds_pca9555_probe,
	.remove = leds_pca9555_remove,
	.id_table = leds_pca9555_id,
};

module_i2c_driver(leds_pca9555_driver);

MODULE_AUTHOR("Arista Networks");
MODULE_DESCRIPTION("Driver to manage Rook status leds");
MODULE_LICENSE("GPL");
