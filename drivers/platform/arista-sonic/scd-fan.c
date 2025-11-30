/* Copyright (c) 2018 Arista Networks, Inc.
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

#include <linux/module.h>
#include <linux/pci.h>

#include "scd.h"
#include "scd-attrs.h"
#include "scd-fan.h"
#include "scd-hwmon.h"
#include "scd-led.h"

#define to_scd_fan_attr(_sensor_attr) \
   container_of(_sensor_attr, struct scd_fan_attribute, sensor_attr)

#define SCD_FAN_ATTR(_attr, _fan, _name, _index, _suffix, _mode, _show, _store)  \
   do {                                                                          \
      snprintf(_attr.name, sizeof(_attr.name), "%s%zu%s", _name,                 \
               _index + 1, _suffix);                                             \
      _attr.sensor_attr = (struct sensor_device_attribute)                       \
         __SENSOR_ATTR_NAME_PTR(_attr.name, _mode, _show, _store, _index);       \
      _attr.fan = _fan;                                                          \
   } while(0)

/* List of fan infos for platform 0 */
static const struct fan_info p0_fan_infos[] = {
   {
      .id = FAN_7010_F,
      .hz = 100000,
      .rotors = 1,
      .pulses = 2,
      .forward = true,
      .present = true,
      .model = "FAN-7010"
   },
   {
      .id = FAN_7010_F_Z,
      .hz = 100000,
      .rotors = 1,
      .pulses = 2,
      .forward = true,
      .present = true,
      .model = "FAN-7010"
   },
   {
      .id = FAN_7010_R,
      .hz = 100000,
      .rotors = 1,
      .pulses = 2,
      .forward = false,
      .present = true,
      .model = "FAN-7010"
   },
   {
      .id = FAN_7010_R_Z,
      .hz = 100000,
      .rotors = 1,
      .pulses = 2,
      .forward = false,
      .present = true,
      .model = "FAN-7010"
   },
};

/* List of fan infos for platform 3 */
static const struct fan_info p3_fan_infos[] = {
   {
      .id = FAN_7011H_F,
      .hz = 100000,
      .rotors = 2,
      .pulses = 2,
      .forward = true,
      .present = true,
      .model = "FAN-7011H-F",
   },
   {
      .id = FAN_7011S_F,
      .hz = 100000,
      .rotors = 1,
      .pulses = 2,
      .forward = true,
      .present = true,
      .model = "FAN-7011S-F",
   },
   {
      .id = FAN_7011M_F,
      .hz = 100000,
      .rotors = 1,
      .pulses = 2,
      .forward = true,
      .present = true,
      .model = "FAN-7011M-F",
   },
   {
      .id = FAN_7011H_R,
      .hz = 100000,
      .rotors = 2,
      .pulses = 2,
      .forward = false,
      .present = true,
      .model = "FAN-7011H-R",
   },
   {
      .id = FAN_7011S_R,
      .hz = 100000,
      .rotors = 1,
      .pulses = 2,
      .forward = false,
      .present = true,
      .model = "FAN-7011S-R",
   },
   {
      .id = FAN_7011M_R,
      .hz = 100000,
      .rotors = 1,
      .pulses = 2,
      .forward = false,
      .present = true,
      .model = "FAN-7011M-R",
   },
   {
      .id = NOT_PRESENT_40,
      .hz = 100000,
      .rotors = 1,
      .pulses = 2,
      .forward = true,
      .present = false,
      .model = "Not Present",
   },
   {
      .id = FAN_7012HP_RED,
      .hz = 100000,
      .rotors = 2,
      .pulses = 2,
      .forward = true,
      .present = true,
      .model = "FAN-7012HP-RED",
   },
   {
      .id = FAN_7012H_RED,
      .hz = 100000,
      .rotors = 2,
      .pulses = 2,
      .forward = true,
      .present = true,
      .model = "FAN-7012H-RED",
   },
   {
      .id = FAN_7012MP_RED,
      .hz = 100000,
      .rotors = 1,
      .pulses = 2,
      .forward = true,
      .present = true,
      .model = "FAN-7012MP-RED",
   },
   {
      .id = FAN_7012S_RED,
      .hz = 100000,
      .rotors = 1,
      .pulses = 2,
      .forward = true,
      .present = true,
      .model = "FAN-7012S-RED",
   },
   {
      .id = FAN_7012M_RED,
      .hz = 100000,
      .rotors = 1,
      .pulses = 2,
      .forward = true,
      .present = true,
      .model = "FAN-7012M-RED",
   },
   {
      .id = FAN_7012H_BLUE,
      .hz = 100000,
      .rotors = 2,
      .pulses = 2,
      .forward = false,
      .present = true,
      .model = "FAN-7012H-BLUE",
   },
   {
      .id = FAN_7012S_BLUE,
      .hz = 100000,
      .rotors = 1,
      .pulses = 2,
      .forward = false,
      .present = true,
      .model = "FAN-7012S-BLUE",
   },
   {
      .id = FAN_7012M_BLUE,
      .hz = 100000,
      .rotors = 1,
      .pulses = 2,
      .forward = false,
      .present = true,
      .model = "FAN-7012M-BLUE"
   },
   {
      .id = NOT_PRESENT_80,
      .hz = 100000,
      .rotors = 1,
      .pulses = 2,
      .forward = true,
      .present = false,
      .model = "Not Present"
   },
};

static const struct fan_info p4_fan_infos[] = {
   {
      .id = 0,
      .hz = 100000,
      .rotors = 1,
      .pulses = 2,
      .forward = true,
      .present = true,
      .model = "FAN-147-F",
   },
};

/* List of fan platforms */
static const struct fan_platform fan_platforms[] = {
   {
      .id = 0,
      .max_slot_count = 1,
      .max_attr_count = 2,
      .fan_infos = p0_fan_infos,
      .fan_info_count = ARRAY_SIZE(p0_fan_infos),

      .size_offset = 0x170,

      .id_offset = 0x180,
      .id_step = 0x0, // unused

      .platform_offset = OFFSET_UNAVAIL,
      .present_offset = 0x1c0,
      .ok_offset = OFFSET_UNAVAIL,
      .green_led_offset = 0xffffe550,
      .red_led_offset = 0xffffe550,

      .speed_offset = 0x10,
      .speed_pwm_offset = 0x0,
      .speed_pwm_steps = {
         0x0,
         0x0,
         0x60,
      },
      .speed_tach_outer_offset = 0x10,
      .speed_tach_outer_steps = {
         0x0,
         0x0,
         0x60,
      },
      .speed_tach_inner_offset = OFFSET_UNAVAIL,

      .mask_platform = MASK_UNAVAIL,
      .mask_id = GENMASK(2, 0),
      .mask_pwm = GENMASK(7, 0),
      .mask_tach = GENMASK(15, 0),
      .mask_green_led = 1,
      .mask_red_led = 2,
   },
   {
      .id = 3,
      .max_slot_count = 4,
      .max_attr_count = 7,
      .fan_infos = p3_fan_infos,
      .fan_info_count = ARRAY_SIZE(p3_fan_infos),

      .size_offset = 0x170,

      .id_offset = 0x180,
      .id_step = 0x10,

      .platform_offset = 0x0,
      .present_offset = 0x1c0,
      .ok_offset = 0x1d0,
      .green_led_offset = 0x1e0,
      .red_led_offset = 0x1f0,

      .speed_offset = 0x10,
      .speed_pwm_offset = 0x0,
      .speed_pwm_steps = {
         0x0,
         0x60,
         0x30,
      },
      .speed_tach_outer_offset = 0x10,
      .speed_tach_outer_steps = {
         0x0,
         0x60,
         0x30,
      },
      .speed_tach_inner_offset = 0x20,
      .speed_tach_inner_steps = {
         0x0,
         0x60,
         0x30,
      },

      .mask_platform = GENMASK(1, 0),
      .mask_size = GENMASK(0, 0),
      .mask_id = GENMASK(4, 0),
      .mask_pwm = GENMASK(7, 0),
      .mask_tach = GENMASK(15, 0),
      .mask_green_led = 1,
      .mask_red_led = 2
   },
   {
      .id = 4,
      .max_slot_count = 1,
      .max_attr_count = 2,
      .fan_infos = p4_fan_infos,
      .fan_info_count = ARRAY_SIZE(p4_fan_infos),

      .size_offset = OFFSET_UNAVAIL,

      .id_offset = OFFSET_UNAVAIL,
      .id_step = 0x0,

      .platform_offset = 0x0,
      .present_offset = OFFSET_UNAVAIL,
      .ok_offset = OFFSET_UNAVAIL,
      .green_led_offset = OFFSET_UNAVAIL,
      .red_led_offset = OFFSET_UNAVAIL,

      .speed_offset = 0x10,
      .speed_pwm_offset = 0x0,
      .speed_pwm_steps = {
         0x0,
         0x0,
         0x0,
      },
      .speed_tach_outer_offset = 0x10,
      .speed_tach_outer_steps = {
         0x0,
         0x0,
         0x10,
      },
      .speed_tach_inner_offset = OFFSET_UNAVAIL,

      .mask_platform = GENMASK(1, 0),
      .mask_size = MASK_UNAVAIL,
      .mask_id = MASK_UNAVAIL,
      .mask_pwm = GENMASK(7, 0),
      .mask_tach = GENMASK(15, 0),
      .mask_green_led = MASK_UNAVAIL,
      .mask_red_led = MASK_UNAVAIL
   }
};

static const struct fan_platform *fan_platform_find(u32 id) {
   size_t i;

   for (i = 0; i < ARRAY_SIZE(fan_platforms); ++i) {
      if (fan_platforms[i].id == id) {
         return &fan_platforms[i];
      }
   }
   return NULL;
}

static const struct fan_info *fan_info_find(const struct fan_info * infos,
                                            size_t num, u32 fan_id,
                                            u32 size) {
   size_t i;

   for (i = 0; i < num; ++i) {
      if ((infos[i].id & FAN_INFO_ID_MASK) == fan_id &&
          (infos[i].id & FAN_INFO_SIZE_MASK) >> FAN_INFO_SIZE_POS == size) {
         return &infos[i];
      }
   }
   return NULL;
}

/*
 * Sysfs handlers for fans
 */

static ssize_t scd_fan_pwm_show(struct device *dev, struct device_attribute *da,
                                char *buf)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct scd_fan_group *group = dev_get_drvdata(dev);
   u32 address = FAN_SPEED_TYPE_ADDR(group, attr->index, pwm);
   u32 reg = scd_read_register(group->ctx->pdev, address);

   reg &= group->platform->mask_pwm;
   return sprintf(buf, "%u\n", reg);
}

static ssize_t scd_fan_pwm_store(struct device *dev, struct device_attribute *da,
                                 const char *buf, size_t count)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct scd_fan_group *group = dev_get_drvdata(dev);
   u32 address = FAN_SPEED_TYPE_ADDR(group, attr->index, pwm);
   u8 val;

   if (kstrtou8(buf, 0, &val))
      return -EINVAL;

   scd_write_register(group->ctx->pdev, address, val);
   return count;
}

static ssize_t scd_fan_present_show(struct device *dev,
                                    struct device_attribute *da,
                                    char *buf)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct scd_fan_group *group = dev_get_drvdata(dev);
   struct scd_fan *fan = to_scd_fan_attr(attr)->fan;
   u32 address = FAN_ADDR(group, present);
   u32 reg = scd_read_register(group->ctx->pdev, address);

   if (!FAN_HAS_REG(group, present)) {
      return sprintf(buf, "1\n");
   }
   return sprintf(buf, "%u\n", !!(reg & (1 << fan->index)));
}

static u32 scd_fan_id_read(struct scd_fan_group *fan_group, u32 index)
{
   u32 address = FAN_ADDR_2(fan_group, id, index);
   u32 reg = scd_read_register(fan_group->ctx->pdev, address);

   reg &= fan_group->platform->mask_id;
   return reg;
}

static ssize_t scd_fan_id_show(struct device *dev, struct device_attribute *da,
                               char *buf)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct scd_fan_group *group = dev_get_drvdata(dev);
   struct scd_fan *fan = to_scd_fan_attr(attr)->fan;
   u32 reg = scd_fan_id_read(group, fan->index);

   return sprintf(buf, "%u\n", reg);
}

static u32 scd_fan_size_read(struct scd_fan_group *fan_group)
{
   u32 address = FAN_ADDR(fan_group, size);
   u32 reg = scd_read_register(fan_group->ctx->pdev, address);

   reg &= fan_group->platform->mask_size;
   return reg;
}

static ssize_t scd_fan_fault_show(struct device *dev, struct device_attribute *da,
                                  char *buf)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct scd_fan_group *group = dev_get_drvdata(dev);
   struct scd_fan *fan = to_scd_fan_attr(attr)->fan;
   u32 address = FAN_ADDR(group, ok);
   u32 reg = scd_read_register(group->ctx->pdev, address);
   // TODO: platforms without OK register should have alternate way of reporting
   // fault, e.g. if tach reading is invalid
   if (!FAN_HAS_REG(group, ok)) {
      return sprintf(buf, "0\n");
   }
   return sprintf(buf, "%u\n", !(reg & (1 << fan->index)));
}

static ssize_t scd_fan_input_show(struct device *dev, struct device_attribute *da,
                                  char *buf)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct scd_fan_group *group = dev_get_drvdata(dev);
   struct scd_fan *fan = to_scd_fan_attr(attr)->fan;
   u32 outer_address = FAN_SPEED_TYPE_ADDR(group, attr->index, tach_outer);
   u32 inner_address = FAN_SPEED_TYPE_ADDR(group, attr->index, tach_inner);
   u32 mask = group->platform->mask_tach;
   u32 avg = 0, val = 0;

   avg += scd_read_register(group->ctx->pdev, outer_address) & mask;
   if (fan->info->rotors > 1) {
      avg += scd_read_register(group->ctx->pdev, inner_address) & mask;
   }
   avg /= fan->info->rotors;
   if (avg && fan->info->pulses)
      val = fan->info->hz * 60 / avg / fan->info->pulses;
   else
      return -EDOM;

   return sprintf(buf, "%u\n", val);
}

static u32 scd_fan_led_read(struct scd_fan *fan) {
   struct scd_fan_group *group = fan->fan_group;
   u32 addr_g = FAN_ADDR(group, green_led);
   u32 addr_r = FAN_ADDR(group, red_led);
   u32 reg_g = scd_read_register(group->ctx->pdev, addr_g);
   u32 reg_r = scd_read_register(group->ctx->pdev, addr_r);
   u32 val = 0;

   if ((reg_g & (1 << fan->index)) == 0)
      val += group->platform->mask_green_led;
   if ((reg_r & (1 << fan->index)) == 0)
      val += group->platform->mask_red_led;

   return val;
}

static void scd_fan_led_write(struct scd_fan *fan, u32 val)
{
   struct scd_fan_group *group = fan->fan_group;
   u32 addr_g = FAN_ADDR(group, green_led);
   u32 addr_r = FAN_ADDR(group, red_led);
   u32 reg_g = scd_read_register(group->ctx->pdev, addr_g);
   u32 reg_r = scd_read_register(group->ctx->pdev, addr_r);

   if ((val & group->platform->mask_green_led) == 0)
      reg_g |= (1 << fan->index);
   else
      reg_g &= ~(1 << fan->index);

   if ((val & group->platform->mask_red_led) == 0)
      reg_r |= (1 << fan->index);
   else
      reg_r &= ~(1 << fan->index);

   scd_write_register(group->ctx->pdev, addr_g, reg_g);
   scd_write_register(group->ctx->pdev, addr_r, reg_r);
}

static ssize_t scd_fan_led_show(struct device *dev, struct device_attribute *da,
                                char *buf)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct scd_fan *fan = to_scd_fan_attr(attr)->fan;
   u32 val = scd_fan_led_read(fan);

   return sprintf(buf, "%u\n", val);
}

static ssize_t scd_fan_led_store(struct device *dev, struct device_attribute *da,
                                 const char *buf, size_t count)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct scd_fan *fan = to_scd_fan_attr(attr)->fan;
   u32 val;

   if (kstrtou32(buf, 0, &val))
      return -EINVAL;

   scd_fan_led_write(fan, val);
   return count;
}

static enum led_brightness fan_led_brightness_get(struct led_classdev *led_cdev)
{
   struct scd_fan *fan = container_of(led_cdev, struct scd_fan, led_cdev);

   return scd_fan_led_read(fan);
}

static void fan_led_brightness_set(struct led_classdev *led_cdev,
                                   enum led_brightness value)
{
   struct scd_fan *fan = container_of(led_cdev, struct scd_fan, led_cdev);

   scd_fan_led_write(fan, value);
}

static ssize_t scd_fan_airflow_show(struct device *dev,
                                    struct device_attribute *da,
                                    char *buf)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct scd_fan *fan = to_scd_fan_attr(attr)->fan;

   return sprintf(buf, "%s\n", (fan->info->forward) ? "forward" : "reverse");
}

static ssize_t scd_fan_slot_show(struct device *dev,
                                 struct device_attribute *da,
                                 char *buf)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct scd_fan *fan = to_scd_fan_attr(attr)->fan;

   return sprintf(buf, "%u\n", fan->index + 1);
}

static ssize_t scd_fan_model_show(struct device *dev,
                                  struct device_attribute *da,
                                  char *buf)
{
   struct sensor_device_attribute *attr = to_sensor_dev_attr(da);
   struct scd_fan *fan = to_scd_fan_attr(attr)->fan;

   return sprintf(buf, "%s\n", fan->info->model);
}

/*
 * Register / Unregister functions
 */

static void scd_fan_group_unregister(struct scd_context *ctx,
                                     struct scd_fan_group *fan_group)
{
   struct scd_fan *tmp_fan;
   struct scd_fan *fan;

   if (fan_group->hwmon_dev) {
      hwmon_device_unregister(fan_group->hwmon_dev);
      fan_group->hwmon_dev = NULL;
      kfree(fan_group->group.attrs);
   }

   list_for_each_entry_safe(fan, tmp_fan, &fan_group->slot_list, list) {
      if (!IS_ERR_OR_NULL(fan->led_cdev.dev)) {
         led_classdev_unregister(&fan->led_cdev);
      }

      if (fan->attrs) {
         kfree(fan->attrs);
         fan->attrs = NULL;
      }

      list_del(&fan->list);
      kfree(fan);
   }
}

void scd_fan_group_remove_all(struct scd_context *ctx)
{
   struct scd_fan_group *tmp_group;
   struct scd_fan_group *group;

   list_for_each_entry_safe(group, tmp_group, &ctx->fan_group_list, list) {
      scd_fan_group_unregister(ctx, group);
      list_del(&group->list);
      kfree(group);
   }
}

static int scd_fan_group_register(struct scd_context *ctx,
                                  struct scd_fan_group *fan_group)
{
   struct device *hwmon_dev;
   struct scd_fan *fan;
   size_t i;
   size_t attr = 0;
   int err;

   fan_group->group.attrs = kcalloc(fan_group->attr_count + 1,
                                    sizeof(*fan_group->group.attrs), GFP_KERNEL);
   if (!fan_group->group.attrs)
      return -ENOMEM;

   list_for_each_entry(fan, &fan_group->slot_list, list) {
      for (i = 0; i < fan->attr_count; ++i) {
         fan_group->group.attrs[attr++] = &fan->attrs[i].sensor_attr.dev_attr.attr;
      }
   }
   fan_group->groups[0] = &fan_group->group;

   hwmon_dev = hwmon_device_register_with_groups(get_scd_dev(ctx), fan_group->name,
                                                 fan_group, fan_group->groups);
   if (IS_ERR(hwmon_dev)) {
      kfree(fan_group->group.attrs);
      return PTR_ERR(hwmon_dev);
   }

   fan_group->hwmon_dev = hwmon_dev;

   list_for_each_entry(fan, &fan_group->slot_list, list) {
      fan->led_cdev.name = fan->led_name;
      fan->led_cdev.brightness_set = fan_led_brightness_set;
      fan->led_cdev.brightness_get = fan_led_brightness_get;
      err = led_classdev_register(get_scd_dev(ctx), &fan->led_cdev);
      if (err) {
         dev_warn(get_scd_dev(ctx),
                  "failed to create sysfs entry of led class for %s", fan->led_name);
      }
      scd_fan_led_write(fan, FAN_LED_COLOR_GREEN(fan));
   }

   return 0;
}

#define SCD_FAN_ATTR_COUNT 9
static void scd_fan_add_attrs(struct scd_fan *fan, size_t index) {
   struct scd_fan_attribute *attrs = fan->attrs;

   SCD_FAN_ATTR(attrs[fan->attr_count], fan, "pwm", index, "" ,
                S_IRUGO|S_IWGRP|S_IWUSR, scd_fan_pwm_show, scd_fan_pwm_store);
   fan->attr_count++;
   SCD_FAN_ATTR(attrs[fan->attr_count], fan, "fan", index, "_id",
                S_IRUGO, scd_fan_id_show, NULL);
   fan->attr_count++;
   SCD_FAN_ATTR(attrs[fan->attr_count], fan, "fan", index, "_input",
                S_IRUGO, scd_fan_input_show, NULL);
   fan->attr_count++;
   SCD_FAN_ATTR(attrs[fan->attr_count], fan, "fan", index, "_fault",
                S_IRUGO, scd_fan_fault_show, NULL);
   fan->attr_count++;
   SCD_FAN_ATTR(attrs[fan->attr_count], fan, "fan", index, "_present",
                S_IRUGO, scd_fan_present_show, NULL);
   fan->attr_count++;
   SCD_FAN_ATTR(attrs[fan->attr_count], fan, "fan", index, "_led" ,
                S_IRUGO|S_IWGRP|S_IWUSR, scd_fan_led_show, scd_fan_led_store);
   fan->attr_count++;
   SCD_FAN_ATTR(attrs[fan->attr_count], fan, "fan", index, "_airflow",
                S_IRUGO, scd_fan_airflow_show, NULL);
   fan->attr_count++;
   SCD_FAN_ATTR(attrs[fan->attr_count], fan, "fan", index, "_slot",
                S_IRUGO, scd_fan_slot_show, NULL);
   fan->attr_count++;
   SCD_FAN_ATTR(attrs[fan->attr_count], fan, "fan", index, "_model",
                S_IRUGO, scd_fan_model_show, NULL);
   fan->attr_count++;
}

static int scd_fan_add(struct scd_fan_group *fan_group, u32 index) {
   struct scd_context *ctx = fan_group->ctx;
   struct scd_fan *fan;
   const struct fan_info *fan_info;
   size_t i;

   if (FAN_HAS_REG(fan_group, id) && FAN_HAS_REG(fan_group, size)) {
      u32 fan_id = scd_fan_id_read(fan_group, index);
      u32 size = scd_fan_size_read(fan_group);

      fan_info = fan_info_find(fan_group->platform->fan_infos,
                              fan_group->platform->fan_info_count, fan_id, size);
      if (!fan_info) {
         dev_err(get_scd_dev(ctx), "no infomation for fan%u with id=%u", index + 1,
               fan_id);
         return -EINVAL;
      } else if (!fan_info->present) {
         dev_warn(get_scd_dev(ctx), "fan%u with id=%u is not present", index + 1,
                  fan_id);
      }
   }
   else {
      fan_info = &fan_group->platform->fan_infos[0];
   }

   fan = kzalloc(sizeof(*fan), GFP_KERNEL);
   if (!fan)
      return -ENOMEM;

   fan->fan_group = fan_group;
   fan->index = index;
   fan->info = fan_info;
   scnprintf(fan->led_name, LED_NAME_MAX_SZ, "fan%d", fan->index + 1);

   fan->attrs = kcalloc(SCD_FAN_ATTR_COUNT * fan_group->fan_count,
                        sizeof(*fan->attrs), GFP_KERNEL);
   if (!fan->attrs) {
      kfree(fan);
      return -ENOMEM;
   }

   for (i = 0; i < fan_group->fan_count; ++i) {
      scd_fan_add_attrs(fan, fan_group->attr_index_count++);
      if (fan_group->attr_index_count >= fan_group->platform->max_attr_count) {
         break;
      }
   }
   fan_group->attr_count += fan->attr_count;

   list_add_tail(&fan->list, &fan_group->slot_list);

   return 0;
}

int scd_fan_group_add(struct scd_context *ctx, u32 addr, u32 platform_id,
                      u32 slot_count, u32 fan_count)
{
   struct scd_fan_group *fan_group;
   const struct fan_platform *platform;
   size_t i;
   int err;

   platform = fan_platform_find(platform_id);
   if (!platform) {
      dev_warn(get_scd_dev(ctx), "no known fan group for platform id=%u",
               platform_id);
      return -EINVAL;
   }

   if (slot_count > platform->max_slot_count) {
      dev_warn(get_scd_dev(ctx), "the fan slot_count argument is larger than %zu",
               platform->max_slot_count);
      return -EINVAL;
   }

   fan_group = kzalloc(sizeof(*fan_group), GFP_KERNEL);
   if (!fan_group) {
      return -ENOMEM;
   }

   scnprintf(fan_group->name, sizeof_field(typeof(*fan_group), name),
             "scd_fan_p%u", platform_id);
   fan_group->ctx = ctx;
   fan_group->addr_base = addr;
   fan_group->slot_count = slot_count;
   fan_group->fan_count = fan_count;
   fan_group->platform = platform;
   INIT_LIST_HEAD(&fan_group->slot_list);

   for (i = 0; i < slot_count; ++i) {
      err = scd_fan_add(fan_group, i);
      if (err)
         goto fail;
   }

   err = scd_fan_group_register(ctx, fan_group);
   if (err)
      goto fail;

   list_add_tail(&fan_group->list, &ctx->fan_group_list);

   return 0;

fail:
   scd_fan_group_unregister(ctx, fan_group);
   kfree(fan_group);
   return err;
}
