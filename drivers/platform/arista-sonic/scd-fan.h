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

#ifndef _LINUX_DRIVER_SCD_FAN_H_
#define _LINUX_DRIVER_SCD_FAN_H_

#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>

#include "scd-led.h"

struct scd_context;

struct scd_fan;
struct scd_fan_group;

#define FAN_ATTR_NAME_MAX_SZ 16
#define MASK_UNAVAIL 0
#define OFFSET_UNAVAIL 0xFFFFFFFF
struct scd_fan_attribute {
   struct sensor_device_attribute sensor_attr;
   struct scd_fan *fan;

   char name[FAN_ATTR_NAME_MAX_SZ];
};

/* Driver data for each fan slot */
struct scd_fan {
   struct scd_fan_group *fan_group;
   struct list_head list;

   u8 index;
   const struct fan_info *info;

   struct scd_fan_attribute *attrs;
   size_t attr_count;

   struct led_classdev led_cdev;
   char led_name[LED_NAME_MAX_SZ];
};

#define FAN_GROUP_NAME_MAX_SZ 50
/* Driver data for each fan group */
struct scd_fan_group {
   struct scd_context *ctx;
   struct list_head list;

   char name[FAN_GROUP_NAME_MAX_SZ];
   const struct fan_platform *platform;
   struct list_head slot_list;

   struct device *hwmon_dev;
   const struct attribute_group *groups[2];
   struct attribute_group group;

   size_t attr_count;
   size_t attr_index_count;

   u32 addr_base;
   size_t slot_count;
   size_t fan_count;
};

/* Fan info is for each fan slot */
#define FAN_INFO_ID_MASK GENMASK(4, 0)
#define FAN_INFO_SIZE_POS 5
#define FAN_INFO_SIZE_MASK GENMASK(FAN_INFO_SIZE_POS, FAN_INFO_SIZE_POS)
enum fan_info_type {
   FAN_NA = 0b000000,
   FAN_7010_F = 0b000011,
   FAN_7010_F_Z = 0b000010,
   FAN_7010_R = 0b000111,
   FAN_7010_R_Z = 0b000110,

   FAN_7011H_F = 0b000111,
   FAN_7011S_F = 0b001101,
   FAN_7011M_F = 0b001110,
   NOT_PRESENT_40 = 0b011111,
   FAN_7011H_R = 0b010111,
   FAN_7011S_R = 0b011101,
   FAN_7011M_R = 0b011110,

   FAN_7012HP_RED = 0b100011,
   FAN_7012H_RED = 0b100111,
   FAN_7012MP_RED = 0b101010,
   FAN_7012S_RED = 0b101101,
   FAN_7012M_RED = 0b101110,
   FAN_7012H_BLUE = 0b110111,
   FAN_7012S_BLUE = 0b111101,
   FAN_7012M_BLUE = 0b111110,
   NOT_PRESENT_80 = 0b111111,
};

struct fan_info {
   enum fan_info_type id;
   u32 hz;
   u8 rotors;
   u8 pulses;
   bool forward;
   bool present;
   char *model;
};

/* For each fan platform, there are multiple fan slots */
struct fan_platform {
   u32 id;
   size_t max_slot_count;
   size_t max_attr_count;
   const struct fan_info *fan_infos;
   size_t fan_info_count;

   u32 size_offset;

   u32 id_offset;
   u32 id_step;

   u32 platform_offset;
   u32 present_offset;
   u32 ok_offset;
   u32 green_led_offset;
   u32 red_led_offset;

   u32 speed_offset;
   u32 speed_pwm_offset;
   u32 speed_pwm_steps[3];
   u32 speed_tach_outer_offset;
   u32 speed_tach_outer_steps[3];
   u32 speed_tach_inner_offset;
   u32 speed_tach_inner_steps[3];

   u32 mask_platform;
   u32 mask_size;
   u32 mask_id;
   u32 mask_pwm;
   u32 mask_tach;
   u32 mask_green_led;
   u32 mask_red_led;
};

/* Constants */
#define FAN_LED_COLOR_GREEN(_fan) \
    (0xff & (_fan)->fan_group->platform->mask_green_led)
#define FAN_LED_COLOR_RED(_fan) \
    (0xff & (_fan)->fan_group->platform->mask_red_led)

#define FAN_HAS_REG(_group, _type) \
   ((_group)->platform->_type##_offset != OFFSET_UNAVAIL)
/* Helpers to calculate register address */
#define FAN_ADDR(_group, _type) \
    ((_group)->addr_base + (_group)->platform->_type##_offset)
#define FAN_ADDR_2(_group, _type, _index) \
    (FAN_ADDR(_group, _type) + (_group)->platform->_type##_step * (_index))
#define FAN_SPEED_ADDR(_group, _index, _type) \
    (FAN_ADDR(_group, speed) + \
    (_group)->platform->speed##_##_type##_steps[(_group)->fan_count] * (_index))
#define FAN_SPEED_TYPE_ADDR(_group, _index, _type) \
    (FAN_SPEED_ADDR(_group, _index, _type) + \
    (_group)->platform->speed##_##_type##_offset)

extern int scd_fan_group_add(struct scd_context *ctx, u32 addr, u32 platform_id,
                             u32 slot_count, u32 fan_count);
extern void scd_fan_group_remove_all(struct scd_context *ctx);

#endif /* !_LINUX_DRIVER_SCD_FAN_H_ */
