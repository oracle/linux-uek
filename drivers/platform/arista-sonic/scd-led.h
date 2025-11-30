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

struct scd_context;

#define LED_NAME_MAX_SZ 40
struct scd_led {
   struct scd_context *ctx;
   struct list_head list;

   u32 addr;
   char name[LED_NAME_MAX_SZ];
   struct led_classdev cdev;
};

extern int scd_led_add(struct scd_context *ctx, const char *name, u32 addr);
extern void scd_led_remove_all(struct scd_context *ctx);

#endif /* !_LINUX_DRIVER_SCD_LED_H_ */
