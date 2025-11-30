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

#ifndef _LINUX_DRIVER_SCD_RESET_H_
#define _LINUX_DRIVER_SCD_RESET_H_

#include <linux/list.h>

#include "scd-attrs.h"

#define RESET_SET_OFFSET 0x00
#define RESET_CLEAR_OFFSET 0x10

struct scd_reset_attribute {
   struct device_attribute dev_attr;
   struct scd_context *ctx;

   u32 addr;
   u32 bit;
};

#define RESET_NAME_MAX_SZ 50
struct scd_reset {
   char name[RESET_NAME_MAX_SZ];
   struct scd_reset_attribute attr;
   struct list_head list;
};

#define to_scd_reset_attr(_dev_attr) \
   container_of(_dev_attr, struct scd_reset_attribute, dev_attr)

#define SCD_RESET_ATTR(_name, _ctx, _addr, _bit)                                \
   { .dev_attr = __ATTR_NAME_PTR(_name, S_IRUGO | S_IWUSR, attribute_reset_get, \
                                 attribute_reset_set),                          \
     .ctx = _ctx,                                                               \
     .addr = _addr,                                                             \
     .bit = _bit,                                                               \
   }

extern int scd_reset_add(struct scd_context *ctx, const char *name, u32 addr,
                         u32 bitpos);
extern void scd_reset_remove_all(struct scd_context *ctx);

#endif /* _LINUX_DRIVER_SCD_RESET_H_ */
