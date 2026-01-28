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
#include "scd-gpio.h"

static ssize_t attribute_gpio_get(struct device *dev,
                                  struct device_attribute *devattr, char *buf)
{
   const struct scd_gpio_attribute *gpio = to_scd_gpio_attr(devattr);
   u32 reg = scd_read_register(gpio->ctx->pdev, gpio->addr);
   u32 res = !!(reg & (1 << gpio->bit));
   res = (gpio->active_low) ? !res : res;
   return sprintf(buf, "%u\n", res);
}

static ssize_t attribute_gpio_set(struct device *dev,
                                  struct device_attribute *devattr,
                                  const char *buf, size_t count)
{
   const struct scd_gpio_attribute *gpio = to_scd_gpio_attr(devattr);
   long value;
   int res;
   u32 reg;

   res = kstrtol(buf, 10, &value);
   if (res < 0)
      return res;

   if (value != 0 && value != 1)
      return -EINVAL;

   reg = scd_read_register(gpio->ctx->pdev, gpio->addr);
   if (gpio->active_low) {
      if (value)
         reg &= ~(1 << gpio->bit);
      else
         reg |= 1 << gpio->bit;
   } else {
      if (value)
         reg |= 1 << gpio->bit;
      else
         reg &= ~(1 << gpio->bit);
   }
   scd_write_register(gpio->ctx->pdev, gpio->addr, reg);

   return count;
}

static void scd_gpio_unregister(struct scd_context *ctx, struct scd_gpio *gpio)
{
   sysfs_remove_file(get_scd_kobj(ctx), &gpio->attr.dev_attr.attr);
}

static int scd_gpio_register(struct scd_context *ctx, struct scd_gpio *gpio)
{
   int res;

   res = sysfs_create_file(get_scd_kobj(ctx), &gpio->attr.dev_attr.attr);
   if (res) {
      dev_err(get_scd_dev(ctx), "could not create %s attribute for gpio: %d",
              gpio->attr.dev_attr.attr.name, res);
      return res;
   }

   list_add_tail(&gpio->list, &ctx->gpio_list);
   return 0;
}

void scd_gpio_remove_all(struct scd_context *ctx)
{
   struct scd_gpio *tmp_gpio;
   struct scd_gpio *gpio;

   list_for_each_entry_safe(gpio, tmp_gpio, &ctx->gpio_list, list) {
      scd_gpio_unregister(ctx, gpio);
      list_del(&gpio->list);
      kfree(gpio);
   }
}


int scd_gpio_add(struct scd_context *ctx, const char *name,
                 u32 addr, u32 bitpos, bool read_only, bool active_low)
{
   int err;
   struct scd_gpio *gpio;

   gpio = kzalloc(sizeof(*gpio), GFP_KERNEL);
   if (!gpio) {
      return -ENOMEM;
   }

   snprintf(gpio->name, sizeof_field(typeof(*gpio), name), name);
   if (read_only)
      gpio->attr = (struct scd_gpio_attribute)SCD_RO_GPIO_ATTR(
                           gpio->name, ctx, addr, bitpos, active_low);
   else
      gpio->attr = (struct scd_gpio_attribute)SCD_RW_GPIO_ATTR(
                           gpio->name, ctx, addr, bitpos, active_low);

   err = scd_gpio_register(ctx, gpio);
   if (err) {
      kfree(gpio);
      return err;
   }

   return 0;
}
