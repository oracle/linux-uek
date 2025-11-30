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

#ifndef _LINUX_DRIVER_SCD_GPIO_H_
#define _LINUX_DRIVER_SCD_GPIO_H_

#include <linux/list.h>

#include "scd-attrs.h"

#define GPIO_NAME_MAX_SZ 32

struct scd_gpio_attribute {
   struct device_attribute dev_attr;
   struct scd_context *ctx;

   u32 addr;
   u32 bit;
   u32 active_low;
};

struct scd_gpio {
   char name[GPIO_NAME_MAX_SZ];
   struct scd_gpio_attribute attr;
   struct list_head list;
};

#define to_scd_gpio_attr(_dev_attr) \
   container_of(_dev_attr, struct scd_gpio_attribute, dev_attr)

#define to_scd_xcvr_attr(_dev_attr) \
   container_of(_dev_attr, struct scd_xcvr_attribute, dev_attr)

#define SCD_GPIO_ATTR(_name, _mode, _show, _store, _ctx, _addr, _bit, _active_low) \
   { .dev_attr = __ATTR_NAME_PTR(_name, _mode, _show, _store),                     \
     .ctx = _ctx,                                                                  \
     .addr = _addr,                                                                \
     .bit = _bit,                                                                  \
     .active_low = _active_low                                                     \
   }

#define SCD_RW_GPIO_ATTR(_name, _ctx, _addr, _bit, _active_low)                    \
   SCD_GPIO_ATTR(_name, S_IRUGO | S_IWUSR, attribute_gpio_get, attribute_gpio_set, \
                 _ctx, _addr, _bit, _active_low)

#define SCD_RO_GPIO_ATTR(_name, _ctx, _addr, _bit, _active_low) \
   SCD_GPIO_ATTR(_name, S_IRUGO, attribute_gpio_get, NULL,      \
                 _ctx, _addr, _bit, _active_low)

extern int scd_gpio_add(struct scd_context *ctx, const char *name,
                        u32 addr, u32 bitpos, bool read_only, bool active_low);
extern void scd_gpio_remove_all(struct scd_context *ctx);

#endif /* _LINUX_DRIVER_SCD_GPIO_H_ */
