/* Copyright (c) 2024 Arista Networks, Inc.
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
#include <linux/device.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/i2c.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/leds.h>
#include <linux/version.h>

#define DRIVER_NAME "minke-fan-cpld"

#define LED_NAME_MAX_SZ 20
#define MAX_SLOT_COUNT 8
#define MAX_FAN_COUNT 8

#define MINOR_VERSION_REG  0x00
#define MAJOR_VERSION_REG  0x01
#define SCRATCHPAD_REG     0x02

#define FAN_BASE_REG(Id)           (0x10 * (1 + (Id)))

#define FAN_PWM_REG(Id)            ((FAN_BASE_REG(Id)))
#define FAN_TACH_REG_LOW(Id, Num)  ((FAN_BASE_REG(Id) + 1 + ((Num) * 2)))
#define FAN_TACH_REG_HIGH(Id, Num) ((FAN_BASE_REG(Id) + 2 + ((Num) * 2)))

#define FAN_LR_PWM_REG(Slot, Fan, Inner) \
   ((FAN_BASE_REG((Slot)->index)) + ((Fan)->index) * 8 + (Inner))
#define FAN_LR_TACH_REG_LOW(Slot, Fan, Inner) \
   ((FAN_BASE_REG((Slot)->index)) + ((Fan)->index) * 8 + (Inner) * 2 + 2)
#define FAN_LR_TACH_REG_HIGH(Slot, Fan, Inner) \
   ((FAN_BASE_REG((Slot)->index)) + ((Fan)->index) * 8 + (Inner) * 2 + 3)

#define FAN_ID_REG(Slot)  ((Slot)->cpld->info->id_base_reg + (Slot)->index)

#define FAN_INT_OK   BIT(0)
#define FAN_INT_PRES BIT(1)
#define FAN_INT_ID   BIT(2)

#define FAN_LED_GREEN BIT(0)
#define FAN_LED_RED   BIT(1)
#define FAN_LED_AMBER ((FAN_LED_GREEN) | (FAN_LED_RED))
#define FAN_LED_BLUE  BIT(2)

#define FAN_MAX_PWM 255

#define FAN_ID_MASK    0x3F
#define FAN_ID_UNKNOWN (FAN_ID_MASK + 1)

#define IS_LR_CPLD(Cpld) ((Cpld)->fans_per_slot == 2)

#define FAN_OUTER 0
#define FAN_INNER 1

#define pali_dbg(cpld, ...) dev_dbg(&(cpld->client->dev), __VA_ARGS__)
#define pali_err(cpld, ...) dev_err(&(cpld->client->dev), __VA_ARGS__)
#define pali_info(cpld, ...) dev_info(&(cpld->client->dev), __VA_ARGS__)
#define pali_warn(cpld, ...) dev_warn(&(cpld->client->dev), __VA_ARGS__)

static bool safe_mode = true;
module_param(safe_mode, bool, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(safe_mode, "force fan speed to 100% during probe");

static bool managed_leds = true;
module_param(managed_leds, bool, S_IRUSR | S_IWUSR);
MODULE_PARM_DESC(managed_leds, "let the driver handle the leds");

static unsigned long poll_interval = 0;
module_param(poll_interval, ulong, S_IRUSR);
MODULE_PARM_DESC(poll_interval, "interval between two polling in ms");

static struct workqueue_struct *pali_cpld_workqueue;

enum cpld_type {
   PALI2_CPLD = 0,
   MINKE_CPLD = 1,
   RUNDLE_CPLD = 2,
};

struct fan_id {
   const char *model;
   unsigned pulses;
};

struct cpld_info {
   const char *name;
   u8 slot_count;
   u8 fan_count;
   u32 tach_hz;
   bool left_right;
   const struct fan_id *fan_ids;
   u8 id_base_reg;
   u8 present_reg;
   u8 ok_reg;
   u8 blue_led_reg;
   u8 amber_led_reg;
   u8 green_led_reg;
   u8 red_led_reg;
   u8 int_reg;
   u8 id_chng_reg;
   u8 pres_chng_reg;
   u8 ok_chng_reg;
};

struct cpld_fan {
   struct cpld_slot *slot;
   u8 index;
   u8 global_index;
   u16 tach_outer;
   u16 tach_inner;
   u8 pwm_outer;
   u8 pwm_inner;
};

struct cpld_slot {
   const struct fan_id *fan_id;
   struct cpld_data *cpld;
   struct led_classdev cdev;
   bool ok;
   bool present;
   bool forward;
   bool dual;
   u8 ident;
   u8 index;
   char led_name[LED_NAME_MAX_SZ];
   struct cpld_fan fans[2];
};

struct cpld_data {
   const struct cpld_info *info;
   struct mutex lock;
   struct i2c_client *client;
   struct device *hwmon_dev;
   struct delayed_work dwork;
   struct cpld_slot slots[MAX_SLOT_COUNT];
   const struct attribute_group *groups[1 + MAX_FAN_COUNT + 1];
   u8 minor;
   u8 major;
   u8 present;
   u8 ok;
   u8 blue_led;
   u8 amber_led;
   u8 green_led;
   u8 red_led;
   u8 fans_per_slot;
};

static const struct fan_id mk_fan_ids[] = {
   [0b000000]       = { "FAN-7021H-RED",   2 },
   [0b000001]       = { "FAN-7021H-RED",   2 },
   [0b001000]       = { "FAN-7022HQ-RED",  2 },
   [0b001001]       = { "FAN-7022HQ-RED",  2 },
   [0b010000]       = { "FAN-7021H-BLUE",  2 },
   [0b010001]       = { "FAN-7021H-BLUE",  2 },
   [0b011000]       = { "FAN-7022HQ-BLUE", 2 },
   [0b011001]       = { "FAN-7022HQ-BLUE", 2 },
   [0b100000]       = { "FAN-7311H-RED",   2 },
   [0b100001]       = { "FAN-7311H-RED",   2 },
   [FAN_ID_UNKNOWN] = { "Unknown",         2 },
};

static const struct fan_id minke_fan_ids[] = {
   [0b000000]       = { "FAN-7016H-BLUE",  2 },
   [0b000001]       = { "FAN-7016H-BLUE",  2 },
   [FAN_ID_UNKNOWN] = { "Unknown",         2 },
};

static const struct fan_id rundle_fan_ids[] = {
   [0b000010]       = { "FAN-7310H-RED",   2 },
   [0b000011]       = { "FAN-7310H-RED",   2 },
   [FAN_ID_UNKNOWN] = { "Unknown",         2 },
};

static const struct cpld_info cpld_infos[] = {
   [PALI2_CPLD] = {
      .name = "pali2",
      .slot_count = 4,
      .fan_count = 4,
      .tach_hz = 100000,
      .left_right = false,
      .fan_ids = mk_fan_ids,
      .id_base_reg = 0x61,
      .present_reg = 0x70,
      .ok_reg = 0x71,
      .blue_led_reg = 0x73,
      .amber_led_reg = 0x74,
      .green_led_reg = 0x75,
      .red_led_reg = 0x76,
      .int_reg = 0x77,
      .id_chng_reg = 0x78,
      .pres_chng_reg = 0x80,
      .ok_chng_reg = 0x82,
   },
   [MINKE_CPLD] = {
      .name = "minke",
      .slot_count = 3,
      .fan_count = 6,
      .tach_hz = 100000,
      .left_right = true,
      .fan_ids = minke_fan_ids,
      .id_base_reg = 0x60,
      .present_reg = 0x70,
      .ok_reg = 0x71,
      .blue_led_reg = 0x73,
      .amber_led_reg = 0x74,
      .green_led_reg = 0x75,
      .red_led_reg = 0x76,
      .int_reg = 0x77,
      .id_chng_reg = 0x78,
      .pres_chng_reg = 0x80,
      .ok_chng_reg = 0x82,
   },
   [RUNDLE_CPLD] = {
      .name = "rundle",
      .slot_count = 8,
      .fan_count = 8,
      .tach_hz = 100000,
      .left_right = false,
      .fan_ids = rundle_fan_ids,
      .id_base_reg = 0x91,
      .present_reg = 0xA0,
      .ok_reg = 0xA1,
      .blue_led_reg = 0xA3,
      .amber_led_reg = 0xA4,
      .green_led_reg = 0xA5,
      .red_led_reg = 0xA6,
      .int_reg = 0xA7,
      .id_chng_reg = 0xB0,
      .pres_chng_reg = 0xB1,
      .ok_chng_reg = 0xB2,
   },
};


static struct cpld_slot *slot_from_fan(struct cpld_fan *fan)
{
   return fan->slot;
}

static struct cpld_data *cpld_from_slot(struct cpld_slot *slot)
{
   return slot->cpld;
}

static struct cpld_slot *slot_from_cpld(struct cpld_data *cpld, u8 slot_id)
{
   return &cpld->slots[slot_id];
}

static struct cpld_fan *fan_from_cpld(struct cpld_data *cpld, u8 fan_id)
{
   struct cpld_slot *slot = slot_from_cpld(cpld, fan_id / cpld->fans_per_slot);
   return &slot->fans[fan_id % cpld->fans_per_slot];
}

static struct cpld_fan *fan_from_dev(struct device *dev, u8 fan_id)
{
   struct cpld_data *cpld = dev_get_drvdata(dev);
   return fan_from_cpld(cpld, fan_id);
}

static unsigned fan_mask_for_slot(struct cpld_slot *slot) {
   struct cpld_data *cpld = cpld_from_slot(slot);
   int mask = 0;
   int i;

   for (i = 0; i < cpld->fans_per_slot; i++) {
      mask |= 1 << (slot->index * cpld->fans_per_slot + i);
   }

   return mask;
}

static bool fan_mask_for_slot_fmatch(struct cpld_slot *slot, unsigned value) {
   int mask = fan_mask_for_slot(slot);
   return (value & mask) == mask;
}

static s32 cpld_read_byte(struct cpld_data *cpld, u8 reg, u8 *res)
{
   int err;

   err = i2c_smbus_read_byte_data(cpld->client, reg);
   if (err < 0) {
      pali_err(cpld, "failed to read reg 0x%02x error=%d\n", reg, err);
      return err;
   }

   *res = (err & 0xff);

   return 0;
}

static s32 cpld_write_byte(struct cpld_data *cpld, u8 reg, u8 byte)
{
   int err;

   err = i2c_smbus_write_byte_data(cpld->client, reg, byte);
   if (err) {
      pali_err(cpld, "failed to write 0x%02x in reg 0x%02x error=%d\n", byte, reg, err);
   }

   return err;
}

static void cpld_work_start(struct cpld_data *cpld)
{
   if (poll_interval) {
      queue_delayed_work(pali_cpld_workqueue, &cpld->dwork,
                         msecs_to_jiffies(poll_interval));
   }
}

static s32 cpld_read_slot_id(struct cpld_slot *slot)
{
   struct cpld_data *cpld = cpld_from_slot(slot);
   s32 err;
   u8 tmp;

   err = cpld_read_byte(cpld, FAN_ID_REG(slot), &tmp);
   if (err)
      return err;

   slot->ident   = tmp & FAN_ID_MASK;
   slot->dual    = !((tmp >> 3) & 0x1);
   slot->forward = !((tmp >> 4) & 0x1);
   slot->fan_id  = &cpld->info->fan_ids[slot->ident];

   if (!slot->fan_id->model) {
      slot->fan_id = &cpld->info->fan_ids[FAN_ID_UNKNOWN];
      pali_warn(cpld, "Unknown fan id: 0x%02x for slot %d", slot->ident,
                slot->index + 1);
   }

   return 0;
}

static int cpld_update_leds(struct cpld_data *cpld)
{
   struct cpld_slot *slot;
   int err;
   int i;

   cpld->blue_led = 0;
   cpld->amber_led = 0;
   cpld->green_led = 0;
   cpld->red_led = 0;

   for (i = 0; i < cpld->info->slot_count; ++i) {
      slot = slot_from_cpld(cpld, i);
      if (slot->ok && slot->present)
         cpld->green_led |= (1 << i);
      else
         cpld->red_led |= (1 << i);
   }

   err = cpld_write_byte(cpld, cpld->info->blue_led_reg, cpld->blue_led);
   if (err)
      return err;

   err = cpld_write_byte(cpld, cpld->info->amber_led_reg, cpld->amber_led);
   if (err)
      return err;

   err = cpld_write_byte(cpld, cpld->info->green_led_reg, cpld->green_led);
   if (err)
      return err;

   err = cpld_write_byte(cpld, cpld->info->red_led_reg, cpld->red_led);
   if (err)
      return err;

   return 0;
}

static int cpld_update(struct cpld_data *cpld)
{
   struct cpld_slot *slot;
   const char *str;
   int fans_inserted = 0;
   int err;
   int i;
   u8 interrupt, id_chng, ok_chng, pres_chng;

   pali_dbg(cpld, "polling cpld information\n");

   err = cpld_read_byte(cpld, cpld->info->int_reg, &interrupt);
   if (err)
      goto fail;

   if (interrupt & FAN_INT_ID) {
      err = cpld_read_byte(cpld, cpld->info->id_chng_reg, &id_chng);
      if (err)
         goto fail;
   }

   if (interrupt & FAN_INT_OK) {
      err = cpld_read_byte(cpld, cpld->info->ok_chng_reg, &ok_chng);
      if (err)
         goto fail;
      err = cpld_read_byte(cpld, cpld->info->ok_reg, &cpld->ok);
      if (err)
         goto fail;
   }

   if (interrupt & FAN_INT_PRES) {
      err = cpld_read_byte(cpld, cpld->info->pres_chng_reg, &pres_chng);
      if (err)
         goto fail;
      err = cpld_read_byte(cpld, cpld->info->present_reg, &cpld->present);
      if (err)
         goto fail;
   }

   for (i = 0; i < cpld->info->slot_count; ++i) {
      slot = slot_from_cpld(cpld, i);

      if ((interrupt & FAN_INT_PRES) && (pres_chng & (1 << i))) {
         if (slot->present && (cpld->present & (1 << i))) {
            str = "hotswapped";
         } else if (!slot->present && (cpld->present & (1 << i))) {
            str = "plugged";
            slot->present = true;
         } else {
            str = "unplugged";
            slot->present = false;
         }
         pali_info(cpld, "fan in slot %d was %s\n", i + 1, str);
      }

      if ((interrupt & FAN_INT_OK) && (fan_mask_for_slot(slot) & ok_chng)) {
         if (slot->ok && fan_mask_for_slot_fmatch(slot, cpld->ok)) {
            pali_warn(cpld, "fan in slot %d had a small snag\n", i + 1);
         } else if (slot->ok && !fan_mask_for_slot_fmatch(slot, cpld->ok)) {
            pali_warn(cpld, "fan in slot %d is in fault, likely stuck\n", i + 1);
            slot->ok = false;
         } else {
            pali_info(cpld, "fan in slot %d has recovered a running state\n", i + 1);
            slot->ok = true;
         }
      }

      if ((interrupt & FAN_INT_ID) && (id_chng & (1 << i))) {
         pali_info(cpld, "fan in slot %d kind has changed\n", i + 1);
         cpld_read_slot_id(slot);
      }

      if (slot->present)
         fans_inserted += 1;
   }

   if (cpld->info->fan_count - fans_inserted > 1) {
      pali_warn(cpld, "it is not recommended to have more than one fan "
               "unplugged. (%d/%d inserted)\n",
               fans_inserted, cpld->info->slot_count);
   }

   // FIXME: clear registers by setting them to 0
   cpld_write_byte(cpld, cpld->info->id_chng_reg, id_chng);
   cpld_write_byte(cpld, cpld->info->ok_chng_reg, ok_chng);
   cpld_write_byte(cpld, cpld->info->pres_chng_reg, pres_chng);

   if (managed_leds)
      err = cpld_update_leds(cpld);

fail:
   return err;
}

static s32 cpld_write_fan_pwm(struct cpld_fan *fan, u8 pwm)
{
   struct cpld_slot *slot = slot_from_fan(fan);
   struct cpld_data *cpld = cpld_from_slot(slot);
   int err;

   if (IS_LR_CPLD(cpld)) {
      err = cpld_write_byte(cpld, FAN_LR_PWM_REG(slot, fan, 0), pwm);
      if (err)
         return err;
      err = cpld_write_byte(cpld, FAN_LR_PWM_REG(slot, fan, 1), pwm);
      if (err)
         return err;
   } else {
      err = cpld_write_byte(cpld, FAN_PWM_REG(slot->index), pwm);
      if (err)
         return err;
   }

   fan->pwm_inner = pwm;
   fan->pwm_outer = pwm;

   return 0;
}

static int cpld_read_present(struct cpld_data *cpld)
{
   struct cpld_slot *slot;
   int err;
   int i;

   err = cpld_read_byte(cpld, cpld->info->present_reg, &cpld->present);
   if (err)
      return err;

   for (i = 0; i < cpld->info->slot_count; ++i) {
      slot = slot_from_cpld(cpld, i);
      slot->present = !!(cpld->present & (1 << i));
   }

   return 0;
}

static int cpld_read_fault(struct cpld_data *cpld)
{
   struct cpld_slot *slot;
   int err;
   int i;

   err = cpld_read_byte(cpld, cpld->info->ok_reg, &cpld->ok);
   if (err)
      return err;

   for (i = 0; i < cpld->info->slot_count; ++i) {
      slot = slot_from_cpld(cpld, i);
      slot->ok = !!(cpld->ok & fan_mask_for_slot(slot));
   }

   return 0;
}

static s32 cpld_read_fan_tach_single(struct cpld_fan *fan, u8 inner, u16 *tach)
{
   struct cpld_slot *slot = slot_from_fan(fan);
   struct cpld_data *cpld = cpld_from_slot(slot);
   int err;
   u8 lo_reg, hi_reg;
   u8 low, high;

   if (IS_LR_CPLD(cpld)) {
      lo_reg = FAN_LR_TACH_REG_LOW(slot, fan, inner);
      hi_reg = FAN_LR_TACH_REG_HIGH(slot, fan, inner);
   } else {
      lo_reg = FAN_TACH_REG_LOW(slot->index, inner);
      hi_reg = FAN_TACH_REG_HIGH(slot->index, inner);
   }

   err = cpld_read_byte(cpld, lo_reg, &low);
   if (err)
      return err;

   err = cpld_read_byte(cpld, hi_reg, &high);
   if (err)
      return err;

   *tach = ((u16)high << 8) | low;

   pali_dbg(cpld, "slot %d fan %d/%d tach=0x%04x\n",
            slot->index + 1, fan->index + 1, inner, *tach);

   if (*tach == 0xffff) {
      cpld_read_present(cpld);
      cpld_read_fault(cpld);
      if (managed_leds)
         cpld_update_leds(cpld);

      if (!slot->present)
         return -ENODEV;

      pali_warn(cpld,
         "Invalid tach information read from fan in slot %d, this is likely "
         "a hardware issue (stuck fan or broken register)\n", slot->index + 1);

      return -EIO;
   }

   return 0;
}

static s32 cpld_read_fan_tach(struct cpld_fan *fan)
{
   struct cpld_slot *slot = slot_from_fan(fan);
   s32 err = 0;

   err = cpld_read_fan_tach_single(fan, FAN_INNER, &fan->tach_inner);
   if (err)
      return err;

   if (slot->dual) {
      err = cpld_read_fan_tach_single(fan, FAN_OUTER, &fan->tach_outer);
      if (err)
         return err;
   }

   return err;
}

static s32 cpld_read_fan_pwm(struct cpld_fan *fan)
{
   struct cpld_slot *slot = slot_from_fan(fan);
   struct cpld_data *cpld = cpld_from_slot(slot);
   int err;
   u8 pwm_inner;
   u8 pwm_outer;

   if (IS_LR_CPLD(cpld)) {
      err = cpld_read_byte(cpld, FAN_LR_PWM_REG(slot, fan, 0), &pwm_outer);
      if (err)
         return err;
      err = cpld_read_byte(cpld, FAN_LR_PWM_REG(slot, fan, 1), &pwm_inner);
      if (err)
         return err;
   } else {
      err = cpld_read_byte(cpld, FAN_PWM_REG(slot->index), &pwm_outer);
      if (err)
         return err;
      pwm_inner = pwm_outer;
   }

   fan->pwm_outer = pwm_outer;
   fan->pwm_inner = pwm_inner;

   return 0;
}

static s32 cpld_read_slot_led(struct cpld_slot *slot, u8 *val)
{
   struct cpld_data *cpld = cpld_from_slot(slot);
   bool blue = cpld->blue_led & (1 << slot->index);
   bool amber = cpld->amber_led & (1 << slot->index);
   bool red = cpld->red_led & (1 << slot->index);
   bool green = cpld->green_led & (1 << slot->index);

   *val = 0;
   if (blue)
      *val |= FAN_LED_BLUE;
   if (amber)
      *val |= FAN_LED_AMBER;
   if (green)
      *val |= FAN_LED_GREEN;
   if (red)
      *val |= FAN_LED_RED;

   return 0;
}

static s32 cpld_write_slot_led(struct cpld_slot *slot, u8 val)
{
   struct cpld_data *cpld = cpld_from_slot(slot);
   int err;

   if (val > 7)
      return -EINVAL;

   if (val & FAN_LED_BLUE)
      cpld->blue_led |= (1 << slot->index);
   else
      cpld->blue_led &= ~(1 << slot->index);

   if ((val & FAN_LED_AMBER) == FAN_LED_AMBER)
      cpld->amber_led |= (1 << slot->index);
   else
      cpld->amber_led &= ~(1 << slot->index);

   if (val & FAN_LED_GREEN && (val & FAN_LED_AMBER) != FAN_LED_AMBER)
      cpld->green_led |= (1 << slot->index);
   else
      cpld->green_led &= ~(1 << slot->index);

   if (val & FAN_LED_RED && (val & FAN_LED_AMBER) != FAN_LED_AMBER)
      cpld->red_led |= (1 << slot->index);
   else
      cpld->red_led &= ~(1 << slot->index);

   err = cpld_write_byte(cpld, cpld->info->blue_led_reg, cpld->blue_led);
   if (err)
      return err;

   err = cpld_write_byte(cpld, cpld->info->amber_led_reg, cpld->amber_led);
   if (err)
      return err;

   err = cpld_write_byte(cpld, cpld->info->green_led_reg, cpld->green_led);
   if (err)
      return err;

   err = cpld_write_byte(cpld, cpld->info->red_led_reg, cpld->red_led);

   return err;
}

static void brightness_set(struct led_classdev *led_cdev,
                           enum led_brightness val)
{
   struct cpld_slot *slot = container_of(led_cdev, struct cpld_slot, cdev);

   cpld_write_slot_led(slot, val);
}

static enum led_brightness brightness_get(struct led_classdev *led_cdev)
{
   struct cpld_slot *slot = container_of(led_cdev, struct cpld_slot, cdev);
   int err;
   u8 val;

   err = cpld_read_slot_led(slot, &val);
   if (err)
      return 0;

   return val;
}

static int cpld_slot_led_init(struct cpld_slot *slot)
{
   struct cpld_data *cpld = cpld_from_slot(slot);
   struct i2c_client *client = cpld->client;

   slot->cdev.brightness_set = brightness_set;
   slot->cdev.brightness_get = brightness_get;
   // FIXME: is it ok to change the name ?
   scnprintf(slot->led_name, LED_NAME_MAX_SZ, "fan_slot%d", slot->index + 1);
   slot->cdev.name = slot->led_name;

   return led_classdev_register(&client->dev, &slot->cdev);
}

static void cpld_leds_unregister(struct cpld_data *cpld, int num_leds)
{
   struct cpld_slot *slot;
   int i = 0;

   for (i = 0; i < num_leds; i++) {
      slot = slot_from_cpld(cpld, i);
      led_classdev_unregister(&slot->cdev);
   }
}

static ssize_t cpld_fan_pwm_show(struct device *dev, struct device_attribute *da,
                                 char *buf)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct cpld_data *cpld = dev_get_drvdata(dev);
   struct cpld_fan *fan = fan_from_cpld(cpld, attr->index);
   struct cpld_slot *slot = slot_from_fan(fan);
   u8 pwm;
   int err;

   mutex_lock(&cpld->lock);
   err = cpld_read_fan_pwm(fan);
   mutex_unlock(&cpld->lock);
   if (err)
      return err;

   pwm = slot->dual ? fan->pwm_outer : fan->pwm_inner;
   return sprintf(buf, "%hhu\n", pwm);
}

static ssize_t cpld_fan_pwm_store(struct device *dev, struct device_attribute *da,
                                  const char *buf, size_t count)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct cpld_data *cpld = dev_get_drvdata(dev);
   struct cpld_fan *fan = fan_from_cpld(cpld, attr->index);
   u8 val;
   int err;

   if (sscanf(buf, "%hhu", &val) != 1)
      return -EINVAL;

   mutex_lock(&cpld->lock);
   err = cpld_write_fan_pwm(fan, val);
   mutex_unlock(&cpld->lock);
   if (err)
      return err;

   return count;
}

static ssize_t cpld_fan_present_show(struct device *dev,
                                     struct device_attribute *da,
                                     char *buf)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct cpld_data *cpld = dev_get_drvdata(dev);
   struct cpld_fan *fan = fan_from_cpld(cpld, attr->index);
   struct cpld_slot *slot = slot_from_fan(fan);
   int err;

   if (!poll_interval) {
      mutex_lock(&cpld->lock);
      err = cpld_read_present(cpld);
      mutex_unlock(&cpld->lock);
      if (err)
         return err;
   }

   return sprintf(buf, "%d\n", slot->present);
}

static ssize_t cpld_fan_id_show(struct device *dev, struct device_attribute *da,
                                char *buf)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct cpld_data *cpld = dev_get_drvdata(dev);
   struct cpld_fan *fan = fan_from_cpld(cpld, attr->index);
   struct cpld_slot *slot = slot_from_fan(fan);
   int err = 0;

   if (!poll_interval) {
      mutex_lock(&cpld->lock);
      err = cpld_read_slot_id(slot);
      mutex_unlock(&cpld->lock);
      if (err)
         return err;
   }

   return sprintf(buf, "%hhu\n", slot->ident);
}

static ssize_t cpld_fan_fault_show(struct device *dev, struct device_attribute *da,
                                   char *buf)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct cpld_data *cpld = dev_get_drvdata(dev);
   struct cpld_fan *fan = fan_from_cpld(cpld, attr->index);
   struct cpld_slot *slot = slot_from_fan(fan);
   int err;

   if (!poll_interval) {
      mutex_lock(&cpld->lock);
      err = cpld_read_fault(cpld);
      mutex_unlock(&cpld->lock);
      if (err)
         return err;
   }

   return sprintf(buf, "%d\n", !slot->ok);
}

static ssize_t cpld_fan_tach_show(struct device *dev, struct device_attribute *da,
                                  char *buf)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct cpld_data *cpld = dev_get_drvdata(dev);
   struct cpld_fan *fan = fan_from_cpld(cpld, attr->index);
   struct cpld_slot *slot = slot_from_fan(fan);
   int err;
   u16 tach;
   int rpms;

   mutex_lock(&cpld->lock);
   err = cpld_read_fan_tach(fan);
   mutex_unlock(&cpld->lock);
   if (err)
      return err;

   tach = slot->dual ? fan->tach_outer : fan->tach_inner;
   if (!tach) {
      return -EINVAL;
   }

   rpms = ((cpld->info->tach_hz * 60) / tach) / slot->fan_id->pulses;

   return sprintf(buf, "%d\n", rpms);
}

static ssize_t cpld_fan_led_show(struct device *dev, struct device_attribute *da,
                                 char *buf)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct cpld_fan *fan = fan_from_dev(dev, attr->index);
   struct cpld_slot *slot = slot_from_fan(fan);
   int err;
   u8 val;

   err = cpld_read_slot_led(slot, &val);
   if (err)
      return err;

   return sprintf(buf, "%hhu\n", val);
}

static ssize_t cpld_fan_led_store(struct device *dev, struct device_attribute *da,
                                  const char *buf, size_t count)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct cpld_data *cpld = dev_get_drvdata(dev);
   struct cpld_fan *fan = fan_from_cpld(cpld, attr->index);
   struct cpld_slot *slot = slot_from_fan(fan);
   int err;
   u8 val;

   if (managed_leds)
      return -EPERM;

   if (sscanf(buf, "%hhu", &val) != 1)
      return -EINVAL;

   mutex_lock(&cpld->lock);
   err = cpld_write_slot_led(slot, val);
   mutex_unlock(&cpld->lock);
   if (err)
      return err;

   return count;
}

static ssize_t cpld_fan_airflow_show(struct device *dev,
                                     struct device_attribute *da,
                                     char *buf)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct cpld_fan *fan = fan_from_dev(dev, attr->index);
   struct cpld_slot *slot = slot_from_fan(fan);
   return sprintf(buf, "%s\n", (slot->forward) ? "forward" : "reverse");
}

static ssize_t cpld_fan_model_show(struct device *dev,
                                   struct device_attribute *da,
                                   char *buf)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct cpld_fan *fan = fan_from_dev(dev, attr->index);
   struct cpld_slot *slot = slot_from_fan(fan);
   return sprintf(buf, "%s\n", (slot->present) ? slot->fan_id->model : "Not present");
}

#define FAN_DEVICE_ATTR(_name)                                                \
   static SENSOR_DEVICE_ATTR(pwm## _name, S_IRUGO|S_IWGRP|S_IWUSR,            \
                             cpld_fan_pwm_show, cpld_fan_pwm_store, _name-1); \
   static SENSOR_DEVICE_ATTR(fan##_name##_id, S_IRUGO,                        \
                             cpld_fan_id_show, NULL, _name-1);                \
   static SENSOR_DEVICE_ATTR(fan##_name##_input, S_IRUGO,                     \
                             cpld_fan_tach_show, NULL, _name-1);              \
   static SENSOR_DEVICE_ATTR(fan##_name##_fault, S_IRUGO,                     \
                             cpld_fan_fault_show, NULL, _name-1);             \
   static SENSOR_DEVICE_ATTR(fan##_name##_present, S_IRUGO,                   \
                             cpld_fan_present_show, NULL, _name-1);           \
   static SENSOR_DEVICE_ATTR(fan##_name##_led, S_IRUGO|S_IWGRP|S_IWUSR,       \
                             cpld_fan_led_show, cpld_fan_led_store, _name-1); \
   static SENSOR_DEVICE_ATTR(fan##_name##_airflow, S_IRUGO,                   \
                             cpld_fan_airflow_show, NULL, _name-1);           \
   static SENSOR_DEVICE_ATTR(fan##_name##_model, S_IRUGO,                     \
                             cpld_fan_model_show, NULL, _name-1);

#define FAN_ATTR(_name)                                  \
    &sensor_dev_attr_pwm##_name.dev_attr.attr,           \
    &sensor_dev_attr_fan##_name##_id.dev_attr.attr,      \
    &sensor_dev_attr_fan##_name##_input.dev_attr.attr,   \
    &sensor_dev_attr_fan##_name##_fault.dev_attr.attr,   \
    &sensor_dev_attr_fan##_name##_present.dev_attr.attr, \
    &sensor_dev_attr_fan##_name##_led.dev_attr.attr,     \
    &sensor_dev_attr_fan##_name##_airflow.dev_attr.attr, \
    &sensor_dev_attr_fan##_name##_model.dev_attr.attr


#define FAN_ATTR_GROUP(_name) &fan##_name##_attr_group

#define DEVICE_FAN_ATTR_GROUP(_name)                                          \
   FAN_DEVICE_ATTR(_name);                                                    \
   static struct attribute *fan##_name##_attrs[] = { FAN_ATTR(_name), NULL }; \
   static struct attribute_group fan##_name##_attr_group = {                  \
      .attrs = fan##_name##_attrs,                                            \
   }

DEVICE_FAN_ATTR_GROUP(1);
DEVICE_FAN_ATTR_GROUP(2);
DEVICE_FAN_ATTR_GROUP(3);
DEVICE_FAN_ATTR_GROUP(4);
DEVICE_FAN_ATTR_GROUP(5);
DEVICE_FAN_ATTR_GROUP(6);
DEVICE_FAN_ATTR_GROUP(7);
DEVICE_FAN_ATTR_GROUP(8);

static struct attribute_group *fan_groups[] = {
   FAN_ATTR_GROUP(1),
   FAN_ATTR_GROUP(2),
   FAN_ATTR_GROUP(3),
   FAN_ATTR_GROUP(4),
   FAN_ATTR_GROUP(5),
   FAN_ATTR_GROUP(6),
   FAN_ATTR_GROUP(7),
   FAN_ATTR_GROUP(8),
   NULL,
};

static ssize_t cpld_revision_show(struct device *dev, struct device_attribute *attr,
                                  char *buf)
{
   struct cpld_data *cpld = dev_get_drvdata(dev);
   return sprintf(buf, "%02x.%02x\n", cpld->major, cpld->minor);
}

DEVICE_ATTR(cpld_revision, S_IRUGO, cpld_revision_show, NULL);

static ssize_t cpld_update_show(struct device *dev, struct device_attribute *attr,
                                char *buf)
{
   struct cpld_data *cpld = dev_get_drvdata(dev);
   int err;

   mutex_lock(&cpld->lock);
   err = cpld_update(cpld);
   mutex_unlock(&cpld->lock);

   return err;
}

DEVICE_ATTR(update, S_IRUGO, cpld_update_show, NULL);

static struct attribute *cpld_attrs[] = {
    &dev_attr_cpld_revision.attr,
    &dev_attr_update.attr,
    NULL,
};

static struct attribute_group cpld_group = {
   .attrs = cpld_attrs,
};

static void cpld_work_fn(struct work_struct *work)
{
   struct delayed_work *dwork = to_delayed_work(work);
   struct cpld_data *cpld = container_of(dwork, struct cpld_data, dwork);

   mutex_lock(&cpld->lock);
   cpld_update(cpld);
   cpld_work_start(cpld);
   mutex_unlock(&cpld->lock);
}

static int cpld_init(struct cpld_data *cpld)
{
   struct cpld_slot *slot;
   struct cpld_fan *fan;
   int err;
   int i, j;

   err = cpld_read_byte(cpld, MINOR_VERSION_REG, &cpld->minor);
   if (err)
      return -ENODEV;

   err = cpld_read_byte(cpld, MAJOR_VERSION_REG, &cpld->major);
   if (err)
      return err;

   pali_info(cpld, "%s CPLD version %02x.%02x\n",
             cpld->info->name, cpld->major, cpld->minor);

   err = cpld_read_byte(cpld, cpld->info->present_reg, &cpld->present);
   if (err)
      return err;

   err = cpld_read_byte(cpld, cpld->info->ok_reg, &cpld->ok);
   if (err)
      return err;

   for (i = 0; i < cpld->info->slot_count; ++i) {
      slot = slot_from_cpld(cpld, i);
      slot->cpld = cpld;
      slot->index = i;
      slot->present = !!(cpld->present & (1 << i));
      slot->ok = !!(cpld->ok & (1 << i));
      if (slot->present) {
         cpld_read_slot_id(slot);
         for (j = 0; j < cpld->fans_per_slot; j++) {
            fan = &slot->fans[j];
            fan->slot = slot;
            fan->index = j;
            fan->global_index = i * cpld->fans_per_slot + j;
            cpld_read_fan_tach(fan);
            cpld_read_fan_pwm(fan);
            if (safe_mode)
               cpld_write_fan_pwm(fan, FAN_MAX_PWM);
         }

         err = cpld_slot_led_init(slot);
         if (err) {
            cpld_leds_unregister(cpld, i);
            return err;
         }
      }
   }

   cpld_write_byte(cpld, cpld->info->ok_chng_reg, 0x00);
   cpld_write_byte(cpld, cpld->info->pres_chng_reg, 0x00);
   cpld_write_byte(cpld, cpld->info->id_chng_reg, 0x00);

   if (managed_leds) {
      err = cpld_update_leds(cpld);
      if (err)
         return err;
   }

   INIT_DELAYED_WORK(&cpld->dwork, cpld_work_fn);
   cpld_work_start(cpld);

   return err;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
static int
#else
static void
#endif
cpld_remove(struct i2c_client *client)
{
   struct cpld_data *cpld = i2c_get_clientdata(client);

   mutex_lock(&cpld->lock);
   cancel_delayed_work_sync(&cpld->dwork);
   mutex_unlock(&cpld->lock);

   cpld_leds_unregister(cpld, cpld->info->fan_count);

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
   return 0;
#endif
}

static int cpld_probe(struct i2c_client *client
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
                      , const struct i2c_device_id *id
#endif
                      )
{
   struct device *dev = &client->dev;
   struct device *hwmon_dev;
   struct cpld_data *cpld;
   int err;
   int i;

   if (!i2c_check_functionality(client->adapter, I2C_FUNC_SMBUS_BYTE_DATA)) {
      pali_err(cpld, "adapter doesn't support byte transactions\n");
      return -ENODEV;
   }

   cpld = devm_kzalloc(dev, sizeof(*cpld), GFP_KERNEL);
   if (!cpld)
      return -ENOMEM;

   i2c_set_clientdata(client, cpld);
   cpld->client = client;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
   cpld->info = &cpld_infos[id->driver_data];
#else
   cpld->info = &cpld_infos[(uintptr_t)i2c_get_match_data(client)];
#endif
   cpld->fans_per_slot = cpld->info->fan_count / cpld->info->slot_count;
   mutex_init(&cpld->lock);

   cpld->groups[0] = &cpld_group;
   for (i = 0; i < cpld->info->fan_count; ++i) {
      cpld->groups[i + 1] = fan_groups[i];
   }

   mutex_lock(&cpld->lock);
   err = cpld_init(cpld);
   mutex_unlock(&cpld->lock);
   if (err)
      return err;

   hwmon_dev = devm_hwmon_device_register_with_groups(dev, client->name,
                                                      cpld, cpld->groups);
   if (IS_ERR(hwmon_dev)) {
      cpld_remove(client);
      return PTR_ERR(hwmon_dev);
   }

   cpld->hwmon_dev = hwmon_dev;

   return err;
}

static const struct i2c_device_id cpld_id[] = {
   { "pali2_cpld", PALI2_CPLD },
   { "minke_cpld", MINKE_CPLD },
   { "rundle_cpld", RUNDLE_CPLD },
   {}
};

MODULE_DEVICE_TABLE(i2c, cpld_id);

static struct i2c_driver cpld_driver = {
   .class = I2C_CLASS_HWMON,
   .driver = {
      .name = DRIVER_NAME,
   },
   .id_table = cpld_id,
   .probe = cpld_probe,
   .remove = cpld_remove,
};

static int __init pali_cpld_init(void)
{
   int err;

   pali_cpld_workqueue = create_singlethread_workqueue(DRIVER_NAME);
   if (IS_ERR_OR_NULL(pali_cpld_workqueue)) {
      pr_err("failed to initialize workqueue\n");
      return PTR_ERR(pali_cpld_workqueue);
   }

   err = i2c_add_driver(&cpld_driver);
   if (err < 0) {
      destroy_workqueue(pali_cpld_workqueue);
      pali_cpld_workqueue = NULL;
      return err;
   }

   return 0;
}

static void __exit pali_cpld_exit(void)
{
   i2c_del_driver(&cpld_driver);
   destroy_workqueue(pali_cpld_workqueue);
   pali_cpld_workqueue = NULL;
}

module_init(pali_cpld_init);
module_exit(pali_cpld_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arista Networks");
MODULE_DESCRIPTION("Pali fan cpld");
