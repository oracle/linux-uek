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
#include "scd-xcvr.h"

static u32 scd_xcvr_read_register(const struct scd_xcvr_attribute *gpio)
{
   struct scd_xcvr *xcvr = gpio->xcvr;
   int i;
   u32 reg;

   reg = scd_read_register(gpio->xcvr->ctx->pdev, gpio->xcvr->addr);
   for (i = 0; i < XCVR_ATTR_MAX_COUNT; i++) {
      if (xcvr->attr[i].clear_on_read) {
         xcvr->attr[i].clear_on_read_value =
            xcvr->attr[i].clear_on_read_value | !!(reg & (1 << i));
      }
   }
   return reg;
}

static ssize_t attribute_xcvr_get(struct device *dev,
                                  struct device_attribute *devattr, char *buf)
{
   struct scd_xcvr_attribute *gpio = to_scd_xcvr_attr(devattr);
   u32 res;
   u32 reg;

   reg = scd_xcvr_read_register(gpio);
   res = !!(reg & (1 << gpio->bit));
   res = (gpio->active_low) ? !res : res;
   if (gpio->clear_on_read) {
      res = gpio->clear_on_read_value | res;
      gpio->clear_on_read_value = 0;
   }
   return sprintf(buf, "%u\n", res);
}

static ssize_t attribute_xcvr_set(struct device *dev,
                                  struct device_attribute *devattr,
                                  const char *buf, size_t count)
{
   const struct scd_xcvr_attribute *gpio = to_scd_xcvr_attr(devattr);
   long value;
   int res;
   u32 reg;

   res = kstrtol(buf, 10, &value);
   if (res < 0)
      return res;

   if (value != 0 && value != 1)
      return -EINVAL;

   reg = scd_xcvr_read_register(gpio);
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
   scd_write_register(gpio->xcvr->ctx->pdev, gpio->xcvr->addr, reg);

   return count;
}

static void scd_xcvr_unregister(struct scd_context *ctx, struct scd_xcvr *xcvr)
{
   int i;

   for (i = 0; i < XCVR_ATTR_MAX_COUNT; i++) {
      if (xcvr->attr[i].xcvr) {
         sysfs_remove_file(get_scd_kobj(ctx), &xcvr->attr[i].dev_attr.attr);
      }
   }
}


struct gpio_cfg {
   u32 bitpos;
   bool read_only;
   bool active_low;
   bool clear_on_read;
   const char *name;
};

static int scd_xcvr_register(struct scd_xcvr *xcvr, const struct gpio_cfg *cfgs,
                             size_t gpio_count)
{
   struct gpio_cfg gpio;
   int res;
   size_t i;
   size_t name_size;
   char name[GPIO_NAME_MAX_SZ];

   for (i = 0; i < gpio_count; i++) {
      gpio = cfgs[i];
      name_size = strlen(xcvr->name) + strlen(gpio.name) + 2;
      BUG_ON(name_size > GPIO_NAME_MAX_SZ);
      snprintf(name, name_size, "%s_%s", xcvr->name, gpio.name);
      if (gpio.read_only) {
         SCD_RO_XCVR_ATTR(xcvr->attr[gpio.bitpos], name, name_size, xcvr,
                          gpio.bitpos, gpio.active_low, gpio.clear_on_read);
      } else {
         SCD_RW_XCVR_ATTR(xcvr->attr[gpio.bitpos], name, name_size, xcvr,
                          gpio.bitpos, gpio.active_low, gpio.clear_on_read);
      }
      res = sysfs_create_file(get_scd_kobj(xcvr->ctx),
                              &xcvr->attr[gpio.bitpos].dev_attr.attr);
      if (res) {
         dev_err(get_scd_dev(xcvr->ctx), "could not create %s attribute for xcvr: %d",
                 xcvr->attr[gpio.bitpos].dev_attr.attr.name, res);
         return res;
      }
   }

   return 0;
}

void scd_xcvr_remove_all(struct scd_context *ctx)
{
   struct scd_xcvr *tmp_xcvr;
   struct scd_xcvr *xcvr;

   list_for_each_entry_safe(xcvr, tmp_xcvr, &ctx->xcvr_list, list) {
      scd_xcvr_unregister(ctx, xcvr);
      list_del(&xcvr->list);
      kfree(xcvr);
   }
}

/*
 * Must be called with the scd lock held.
 */
static int scd_xcvr_add(struct scd_context *ctx, const char *prefix,
                        const struct gpio_cfg *cfgs, size_t gpio_count,
                        u32 addr, u32 id)
{
   struct scd_xcvr *xcvr;
   int err;

   xcvr = kzalloc(sizeof(*xcvr), GFP_KERNEL);
   if (!xcvr) {
      err = -ENOMEM;
      goto fail;
   }

   err = snprintf(xcvr->name, sizeof_field(typeof(*xcvr), name),
                  "%s%u", prefix, id);
   if (err < 0) {
      goto fail;
   }

   xcvr->addr = addr;
   xcvr->ctx = ctx;

   err = scd_xcvr_register(xcvr, cfgs, gpio_count);
   if (err) {
      goto fail;
   }

   list_add_tail(&xcvr->list, &ctx->xcvr_list);
   return 0;

fail:
   if (xcvr)
      kfree(xcvr);

   return err;
}

int scd_xcvr_sfp_add(struct scd_context *ctx, u32 addr, u32 id)
{
   static const struct gpio_cfg sfp_gpios[] = {
      {0, true,  false, false, "rxlos"},
      {1, true,  false, false, "txfault"},
      {2, true,  true,  false, "present"},
      {3, true,  false, true,  "rxlos_changed"},
      {4, true,  false, true,  "txfault_changed"},
      {5, true,  false, true,  "present_changed"},
      {6, false, false, false, "txdisable"},
      {7, false, false, false, "rate_select0"},
      {8, false, false, false, "rate_select1"},
   };

   dev_dbg(get_scd_dev(ctx), "sfp %u @ 0x%04x\n", id, addr);
   return scd_xcvr_add(ctx, "sfp", sfp_gpios, ARRAY_SIZE(sfp_gpios), addr, id);
}

int scd_xcvr_qsfp_add(struct scd_context *ctx, u32 addr, u32 id)
{
   static const struct gpio_cfg qsfp_gpios[] = {
      {0, true,  true,  false, "interrupt"},
      {2, true,  true,  false, "present"},
      {3, true,  false, true,  "interrupt_changed"},
      {5, true,  false, true,  "present_changed"},
      {6, false, false, false, "lp_mode"},
      {7, false, false, false, "reset"},
      {8, false, true,  false, "modsel"},
   };

   dev_dbg(get_scd_dev(ctx), "qsfp %u @ 0x%04x\n", id, addr);
   return scd_xcvr_add(ctx, "qsfp", qsfp_gpios, ARRAY_SIZE(qsfp_gpios), addr, id);
}

int scd_xcvr_osfp_add(struct scd_context *ctx, u32 addr, u32 id)
{
   static const struct gpio_cfg osfp_gpios[] = {
      {0, true,  true,  false, "interrupt"},
      {2, true,  true,  false, "present"},
      {3, true,  false, true,  "interrupt_changed"},
      {5, true,  false, true,  "present_changed"},
      {6, false, false, false, "lp_mode"},
      {7, false, false, false, "reset"},
      {8, false, true,  false, "modsel"},
   };

   dev_dbg(get_scd_dev(ctx), "osfp %u @ 0x%04x\n", id, addr);
   return scd_xcvr_add(ctx, "osfp", osfp_gpios, ARRAY_SIZE(osfp_gpios), addr, id);
}

