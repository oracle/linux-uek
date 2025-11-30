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

#include <linux/module.h>
#include <linux/pci.h>

#include "scd.h"
#include "scd-hwmon.h"
#include "scd-led.h"

static void scd_led_pmw_config_set(struct scd_context *ctx, u32 regbase)
{
   u32 red_addr = regbase + 0x30;
   u32 green_addr = regbase + 0x34;
   u32 blue_addr = regbase + 0x38;
   u32 blue_reg = 0x0;
   u32 red_reg = 0x0;
   u32 green_reg = 0x1FFFFFF;
   scd_write_register(ctx->pdev, green_addr, green_reg);
   scd_write_register(ctx->pdev, red_addr, red_reg);
   scd_write_register(ctx->pdev, blue_addr, blue_reg);
}

static void led_brightness_set(struct led_classdev *led_cdev,
                               enum led_brightness value)
{
   struct scd_led *led = container_of(led_cdev, struct scd_led, cdev);
   u32 reg;

   switch ((int)value) {
   case 0:
      reg = 0x0006ff00;
      break;
   case 1:
      reg = 0x1006ff00;
      break;
   case 2:
      reg = 0x0806ff00;
      break;
   case 3:
      reg = 0x1806ff00;
      break;
   case 4:
      reg = 0x1406ff00;
      break;
   case 5:
      reg = 0x0C06ff00;
      break;
   case 6:
      reg = 0x1C06ff00;
      break;
   case 7:
      scd_led_pmw_config_set(led->ctx, 0x6f00);
      return;
   case 10:
      reg = 0x0;
      break;
   case 11:
      reg = 0xA000000;
      break;
   case 13:
      reg = 0xE000000;
      break;
   default:
      reg = 0x1806ff00;
      break;
   }
   scd_write_register(led->ctx->pdev, led->addr, reg);
}

/*
 * Must be called with the scd lock held.
 */
void scd_led_remove_all(struct scd_context *ctx)
{
   struct scd_led *led;
   struct scd_led *led_tmp;

   list_for_each_entry_safe(led, led_tmp, &ctx->led_list, list) {
      led_classdev_unregister(&led->cdev);
      list_del(&led->list);
      kfree(led);
   }
}

static struct scd_led *scd_led_find(struct scd_context *ctx, u32 addr)
{
   struct scd_led *led;

   list_for_each_entry(led, &ctx->led_list, list) {
      if (led->addr == addr)
         return led;
   }
   return NULL;
}

int scd_led_add(struct scd_context *ctx, const char *name, u32 addr)
{
   struct scd_led *led;
   int ret;

   if (scd_led_find(ctx, addr))
      return -EEXIST;

   led = kzalloc(sizeof(*led), GFP_KERNEL);
   if (!led)
      return -ENOMEM;

   led->ctx = ctx;
   led->addr = addr;
   strncpy(led->name, name, sizeof_field(typeof(*led), name));
   INIT_LIST_HEAD(&led->list);

   led->cdev.name = led->name;
   led->cdev.brightness_set = led_brightness_set;

   ret = led_classdev_register(get_scd_dev(ctx), &led->cdev);
   if (ret) {
      kfree(led);
      return ret;
   }

   list_add_tail(&led->list, &ctx->led_list);

   return 0;
}
