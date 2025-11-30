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

#ifndef _LINUX_DRIVER_SCD_XCVR_H_
#define _LINUX_DRIVER_SCD_XCVR_H_

#include <linux/list.h>

#include "scd-attrs.h"
#include "scd-gpio.h"

struct scd_xcvr_attribute {
   struct device_attribute dev_attr;
   struct scd_xcvr *xcvr;

   char name[GPIO_NAME_MAX_SZ];
   u32 bit;
   u32 active_low;
   u32 clear_on_read;
   u32 clear_on_read_value;
};

#define XCVR_ATTR_MAX_COUNT 9
struct scd_xcvr {
   struct scd_context *ctx;
   struct scd_xcvr_attribute attr[XCVR_ATTR_MAX_COUNT];
   struct list_head list;

   char name[GPIO_NAME_MAX_SZ];
   u32 addr;
};

#define SCD_XCVR_ATTR(_xcvr_attr, _name, _name_size, _mode, _show, _store, _xcvr, \
                      _bit, _active_low, _clear_on_read)                          \
   do {                                                                           \
      snprintf(_xcvr_attr.name, _name_size, _name);                               \
      _xcvr_attr.dev_attr =                                                       \
         (struct device_attribute)__ATTR_NAME_PTR(_xcvr_attr.name, _mode, _show,  \
                                                  _store);                        \
      _xcvr_attr.xcvr = _xcvr;                                                    \
      _xcvr_attr.bit = _bit;                                                      \
      _xcvr_attr.active_low = _active_low;                                        \
      _xcvr_attr.clear_on_read = _clear_on_read;                                  \
   } while(0);

#define SCD_RW_XCVR_ATTR(_xcvr_attr, _name, _name_size, _xcvr, _bit,  \
                         _active_low, _clear_on_read)                 \
   SCD_XCVR_ATTR(_xcvr_attr, _name, _name_size, S_IRUGO | S_IWUSR,    \
                 attribute_xcvr_get, attribute_xcvr_set, _xcvr, _bit, \
                 _active_low, _clear_on_read)

#define SCD_RO_XCVR_ATTR(_xcvr_attr, _name, _name_size, _xcvr, _bit,         \
                         _active_low, _clear_on_read)                        \
   SCD_XCVR_ATTR(_xcvr_attr, _name, _name_size, S_IRUGO, attribute_xcvr_get, \
                 NULL, _xcvr, _bit, _active_low, _clear_on_read)

extern int scd_xcvr_sfp_add(struct scd_context *ctx, u32 addr, u32 id);
extern int scd_xcvr_qsfp_add(struct scd_context *ctx, u32 addr, u32 id);
extern int scd_xcvr_osfp_add(struct scd_context *ctx, u32 addr, u32 id);
extern void scd_xcvr_remove_all(struct scd_context *ctx);

#endif /* _LINUX_DRIVER_SCD_XCVR_H_ */
