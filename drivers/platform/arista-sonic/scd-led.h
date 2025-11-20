/* Copyright (c) 2020 Arista Networks, Inc.
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

#ifndef _LINUX_DRIVER_SCD_LED_H_
#define _LINUX_DRIVER_SCD_LED_H_

#include <linux/leds.h>
#include <linux/led-class-multicolor.h>

struct scd_context;

/* Sync with led.py! */
enum led_kind {
   /* Legacy LED behavior. */
   LED_KIND_LEGACY = 0,

   /* Single color LEDs. */
   LED_KIND_BLUE = 1,

   /* Legacy multi-colour LEDs. */
   LED_KIND_RA = 2,        /* Red+Amber */
   LED_KIND_RG = 3,        /* Red+Green */
   LED_KIND_RG_F = 4,      /* Red+Green, hw flash */
   LED_KIND_GY = 5,        /* Green+Yellow */
   LED_KIND_GY_F = 6,      /* Green+Yellow, hw flash */
   LED_KIND_GY_1F = 7,     /* Green+Yellow, only one lit, hw flash */

   /* Paletted multi-color LEDs. */
   LED_KIND_RGB_P3F = 8,   /* RGB, with 3-bit (8 entry) palette, hw flash */

   /* Fully-controllable multi-color LEDs. */
   LED_KIND_RGB_8_F = 9,   /* RGB, 8 bits per channel, hw flash */
};

#define LED_NAME_MAX_SZ 40
#define LED_MAX_SUBLEDS 3
struct scd_led {
   struct scd_context *ctx;
   struct list_head list;

   u32 addr;
   char name[LED_NAME_MAX_SZ];
   enum led_kind kind;

   union {
      /* struct led_classdev is the first member of led_classdev_mc. */
      struct led_classdev cdev;
      struct led_classdev_mc cdev_mc;
   };

   struct mc_subled subleds[LED_MAX_SUBLEDS];
};

extern int scd_led_add(struct scd_context *ctx, const char *name, u32 addr, enum led_kind kind);
extern void scd_led_remove_all(struct scd_context *ctx);

struct scd_led_ctrl {
   u32 flash_addr;
   u32 palette_addr;
};

extern int scd_led_ctrl_add(struct scd_context *ctx, u32 flash_addr, u32 palette_addr);

#endif /* !_LINUX_DRIVER_SCD_LED_H_ */
