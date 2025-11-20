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
#include <linux/version.h>

#include "scd.h"
#include "scd-hwmon.h"
#include "scd-led.h"

#define SCD_BLINK_MASK BIT(25)
#define SCD_ALL_LANES_SAME BIT(27)

static int led_legacy_multicolors[][2] = {
   { 0, 0 },
   { 0, 0 },
   { LED_COLOR_ID_RED, LED_COLOR_ID_AMBER },
   { LED_COLOR_ID_RED, LED_COLOR_ID_GREEN },
   { LED_COLOR_ID_RED, LED_COLOR_ID_GREEN },
   { LED_COLOR_ID_YELLOW, LED_COLOR_ID_GREEN },
   { LED_COLOR_ID_YELLOW, LED_COLOR_ID_GREEN },
   { LED_COLOR_ID_YELLOW, LED_COLOR_ID_GREEN },
   { 0, 0 },
};

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

static void scd_led_tricolor_config_set(struct scd_context *ctx, u32 regbase)
{
   struct regs {
      u32 offset;
      u32 value;
   };

   struct regs palette[12] = {
      {.offset = 0x20, .value = 0x00000000},
      {.offset = 0x30, .value = 0x00000000},
      {.offset = 0x40, .value = 0x00ffffff},
      {.offset = 0x50, .value = 0x00ffffff},
      {.offset = 0x24, .value = 0x00000000},
      {.offset = 0x34, .value = 0x00ffffff},
      {.offset = 0x44, .value = 0x00000000},
      {.offset = 0x54, .value = 0x00ffffff},
      {.offset = 0x28, .value = 0x00fff000},
      {.offset = 0x38, .value = 0x00fff000},
      {.offset = 0x48, .value = 0x00fff000},
      {.offset = 0x58, .value = 0x00fff000},
   };

   for (int i = 0; i < 12; ++i)
      scd_write_register(ctx->pdev, regbase + palette[i].offset, palette[i].value);
}

static void led_brightness_set_legacy(struct led_classdev *led_cdev,
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
      reg = 0x0A000000;
      break;
   case 13:
      reg = 0x0E000000;
      break;
   default:
      reg = 0x1806ff00;
      break;
   }
   scd_write_register(led->ctx->pdev, led->addr, reg);
}

static void led_brightness_set_mono(struct led_classdev *led_cdev,
                                    enum led_brightness brightness)
{
   struct scd_led *led = container_of(led_cdev, struct scd_led, cdev);
   u32 reg = (brightness > 0) * BIT(27);

   scd_write_register(led->ctx->pdev, led->addr, reg);
}

static void led_brightness_set_multi(struct led_classdev *led_cdev,
                                     enum led_brightness brightness)
{
   struct scd_led *led = container_of(led_cdev, struct scd_led, cdev);
   u32 reg;
   int ret;

   ret = led_mc_calc_color_components(&led->cdev_mc, brightness);
   if (ret)
      return;

   /* Maintain blink state. */
   reg = scd_read_register(led->ctx->pdev, led->addr);
   reg &= SCD_BLINK_MASK * ((int)brightness > 0);

   reg |= (led->subleds[0].brightness > 0) * BIT(27);
   reg |= (led->subleds[1].brightness > 0) * BIT(28);
   if (led->cdev_mc.num_colors > 2)
      reg |= (led->subleds[2].brightness > 0) * BIT(29);

   if (led->kind == LED_KIND_GY_1F) {
      /* Green and yellow LEDs are mutually-exclusive. */
      if (led->subleds[0].brightness > 0)
         reg &= BIT(27);
   }

   scd_write_register(led->ctx->pdev, led->addr, reg);
}

static void led_brightness_set_tricolor(struct led_classdev *led_cdev,
                                        enum led_brightness brightness)
{
   struct scd_led *led = container_of(led_cdev, struct scd_led, cdev);
   u32 reg = 0;
   int ret;

   ret = led_mc_calc_color_components(&led->cdev_mc, brightness);
   if (ret)
      return;

   /* No support for flash or different status per lane yet. */
   reg |= SCD_ALL_LANES_SAME;
   reg |= !!(led->subleds[0].brightness) << 26;
   reg |= !!(led->subleds[1].brightness) << 25;
   reg |= !!(led->subleds[2].brightness) << 24;

   scd_write_register(led->ctx->pdev, led->addr, reg);
}

static void led_brightness_set_rgb8(struct led_classdev *led_cdev,
                                    enum led_brightness brightness)
{
   struct scd_led *led = container_of(led_cdev, struct scd_led, cdev);
   u32 reg;
   int ret;

   ret = led_mc_calc_color_components(&led->cdev_mc, brightness);
   if (ret)
      return;

   /* Maintain blink state. */
   reg = scd_read_register(led->ctx->pdev, led->addr);
   reg &= SCD_BLINK_MASK * ((int)brightness > 0);

   reg |= led->subleds[0].brightness
          | (led->subleds[1].brightness << 8)
          | (led->subleds[2].brightness << 16);

   reg |= !!(led->subleds[0].brightness) << 27;
   reg |= !!(led->subleds[1].brightness) << 28;
   reg |= !!(led->subleds[2].brightness) << 29;

   scd_write_register(led->ctx->pdev, led->addr, reg);
}

static int scd_led_blink_set(struct led_classdev* led_cdev,
                             unsigned long *delay_on,
                             unsigned long *delay_off)
{
   struct scd_led *led = container_of(led_cdev, struct scd_led, cdev);
   u32 blink_addr = led->ctx->led_ctrl.flash_addr;
   u32 rate;
   u32 reg;

   if (blink_addr == 0)
      return -ENODEV;

   rate = scd_read_register(led->ctx->pdev, blink_addr);
   *delay_on = rate;
   *delay_off = rate;

   reg = scd_read_register(led->ctx->pdev, led->addr);
   reg |= SCD_BLINK_MASK;
   scd_write_register(led->ctx->pdev, led->addr, reg);

   return 0;
}

static int scd_led_blink_set_tricolor(struct led_classdev* led_cdev,
                                      unsigned long *delay_on,
                                      unsigned long *delay_off)
{
   /* Not yet implemented. */
   return -ENOTSUPP;
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

static int scd_led_init_mono(struct scd_led *led)
{
   switch (led->kind) {
      case LED_KIND_LEGACY:
         led->cdev.max_brightness = 255;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
         led->cdev.color = LED_COLOR_ID_MULTI;
#endif
         led->cdev.brightness_set = led_brightness_set_legacy;
         break;

      case LED_KIND_BLUE:
         led->cdev.max_brightness = 1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
         led->cdev.color = LED_COLOR_ID_BLUE;
#endif
         led->cdev.brightness_set = led_brightness_set_mono;
         break;

      default:
         return -EINVAL;
   }

   return led_classdev_register(get_scd_dev(led->ctx), &led->cdev);
}

static int scd_led_init_mc(struct scd_led *led)
{
   led->cdev_mc.led_cdev.name = led->name;
   led->cdev_mc.subled_info = led->subleds;

   switch (led->kind) {
      case LED_KIND_RA:
      case LED_KIND_RG:
      case LED_KIND_RG_F:
      case LED_KIND_GY:
      case LED_KIND_GY_F:
      case LED_KIND_GY_1F:
         led->cdev_mc.led_cdev.max_brightness = 1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
         led->cdev_mc.led_cdev.color = LED_COLOR_ID_MULTI;
#endif
         led->cdev_mc.led_cdev.brightness_set = led_brightness_set_multi;
         led->cdev_mc.num_colors = 2;
         led->subleds[0].color_index = led_legacy_multicolors[led->kind][0];
         led->subleds[0].channel = 0;
         led->subleds[1].color_index = led_legacy_multicolors[led->kind][1];
         led->subleds[1].channel = 1;
         break;

      case LED_KIND_RGB_P3F:
         led->cdev_mc.led_cdev.max_brightness = 1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
         led->cdev_mc.led_cdev.color = LED_COLOR_ID_RGB;
#endif
         led->cdev_mc.led_cdev.brightness_set = led_brightness_set_tricolor;
         led->cdev_mc.num_colors = 3;
         led->subleds[0].color_index = LED_COLOR_ID_RED;
         led->subleds[0].channel = 0;
         led->subleds[1].color_index = LED_COLOR_ID_GREEN;
         led->subleds[1].channel = 1;
         led->subleds[2].color_index = LED_COLOR_ID_BLUE;
         led->subleds[2].channel = 2;
         break;

      case LED_KIND_RGB_8_F:
         led->cdev_mc.led_cdev.max_brightness = 255;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
         led->cdev_mc.led_cdev.color = LED_COLOR_ID_RGB;
#endif
         led->cdev_mc.led_cdev.brightness_set = led_brightness_set_rgb8;
         led->cdev_mc.num_colors = 3;
         led->subleds[0].color_index = LED_COLOR_ID_RED;
         led->subleds[0].channel = 0;
         led->subleds[1].color_index = LED_COLOR_ID_GREEN;
         led->subleds[1].channel = 1;
         led->subleds[2].color_index = LED_COLOR_ID_BLUE;
         led->subleds[2].channel = 2;
         break;

      default:
         return -EINVAL;
   }

   switch (led->kind) {
      case LED_KIND_RG_F:
      case LED_KIND_GY_F:
      case LED_KIND_GY_1F:
      case LED_KIND_RGB_8_F:
         led->cdev_mc.led_cdev.blink_set = scd_led_blink_set;
         break;

      case LED_KIND_RGB_P3F:
         led->cdev_mc.led_cdev.blink_set = scd_led_blink_set_tricolor;

      default:
         break;
   }

   return led_classdev_multicolor_register(get_scd_dev(led->ctx), &led->cdev_mc);
}

int scd_led_add(struct scd_context *ctx, const char *name, u32 addr,
                enum led_kind kind)
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
   led->kind = kind;
   strncpy(led->name, name, sizeof_field(typeof(*led), name));
   led->cdev.name = led->name;
   INIT_LIST_HEAD(&led->list);

   if (kind >= LED_KIND_RA)
      ret = scd_led_init_mc(led);
   else
      ret = scd_led_init_mono(led);

   if (ret < 0) {
      kfree(led);
      return ret;
   }

   list_add_tail(&led->list, &ctx->led_list);

   return 0;
}

int scd_led_ctrl_add(struct scd_context *ctx, u32 flash_addr, u32 palette_addr)
{
   if (ctx->led_ctrl.flash_addr != 0 && flash_addr != 0)
      return -EEXIST;

   if (ctx->led_ctrl.palette_addr != 0 && palette_addr != 0)
      return -EEXIST;

   ctx->led_ctrl.flash_addr = flash_addr;
   ctx->led_ctrl.palette_addr = palette_addr;

   if (palette_addr != 0)
      scd_led_tricolor_config_set(ctx, palette_addr);

   return 0;
}
