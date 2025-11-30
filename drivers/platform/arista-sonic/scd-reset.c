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

#include "scd-reset.h"

static ssize_t attribute_reset_get(struct device *dev,
                                   struct device_attribute *devattr, char *buf)
{
   const struct scd_reset_attribute *reset = to_scd_reset_attr(devattr);
   u32 reg = scd_read_register(reset->ctx->pdev, reset->addr);
   u32 res = !!(reg & (1 << reset->bit));
   return sprintf(buf, "%u\n", res);
}

// write 1 -> set, 0 -> clear
static ssize_t attribute_reset_set(struct device *dev,
                                   struct device_attribute *devattr,
                                   const char *buf, size_t count)
{
   const struct scd_reset_attribute *reset = to_scd_reset_attr(devattr);
   u32 offset = RESET_SET_OFFSET;
   long value;
   int res;
   u32 reg;

   res = kstrtol(buf, 10, &value);
   if (res < 0)
      return res;

   if (value != 0 && value != 1)
      return -EINVAL;

   if (!value)
      offset = RESET_CLEAR_OFFSET;

   reg = 1 << reset->bit;
   scd_write_register(reset->ctx->pdev, reset->addr + offset, reg);

   return count;
}

static void scd_reset_unregister(struct scd_context *ctx, struct scd_reset *reset)
{
   sysfs_remove_file(get_scd_kobj(ctx), &reset->attr.dev_attr.attr);
}

static int scd_reset_register(struct scd_context *ctx, struct scd_reset *reset)
{
   int res;

   res = sysfs_create_file(get_scd_kobj(ctx), &reset->attr.dev_attr.attr);
   if (res) {
      dev_err(get_scd_dev(ctx), "could not create %s attribute for reset: %d",
              reset->attr.dev_attr.attr.name, res);
      return res;
   }

   list_add_tail(&reset->list, &ctx->reset_list);
   return 0;
}

void scd_reset_remove_all(struct scd_context *ctx)
{
   struct scd_reset *tmp_reset;
   struct scd_reset *reset;

   list_for_each_entry_safe(reset, tmp_reset, &ctx->reset_list, list) {
      scd_reset_unregister(ctx, reset);
      list_del(&reset->list);
      kfree(reset);
   }
}

int scd_reset_add(struct scd_context *ctx, const char *name, u32 addr, u32 bitpos)
{
   int err;
   struct scd_reset *reset;

   reset = kzalloc(sizeof(*reset), GFP_KERNEL);
   if (!reset) {
      return -ENOMEM;
   }

   snprintf(reset->name, sizeof_field(typeof(*reset), name), name);
   reset->attr = (struct scd_reset_attribute)SCD_RESET_ATTR(
                                                reset->name, ctx, addr, bitpos);

   err = scd_reset_register(ctx, reset);
   if (err) {
      kfree(reset);
      return err;
   }
   return 0;
}

