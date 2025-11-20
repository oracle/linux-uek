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

#ifndef LINUX_DRIVER_SCD_HWMON_H_
#define LINUX_DRIVER_SCD_HWMON_H_

#include <linux/printk.h>
#include <linux/pci.h>

#include "scd-led.h"
#include "scd-uart.h"

// sizeof_field was introduced in v4.15 and FIELD_SIZEOF removed in 4.20
#ifndef sizeof_field
# define sizeof_field FIELD_SIZEOF
#endif

struct scd_context {
   struct pci_dev *pdev;
   size_t res_size;

   struct list_head list;

   struct mutex mutex;
   bool initialized;

   struct list_head gpio_list;
   struct list_head reset_list;
   struct list_head led_list;
   struct list_head smbus_master_list;
   struct list_head spi_controller_list;
   struct list_head mdio_master_list;
   struct list_head xcvr_list;
   struct list_head fan_group_list;

   struct scd_uart uart;
   struct scd_led_ctrl led_ctrl;
};

static inline struct device *get_scd_dev(struct scd_context *ctx)
{
   return &ctx->pdev->dev;
}


static inline struct kobject *get_scd_kobj(struct scd_context *ctx)
{
   return &ctx->pdev->dev.kobj;
}

#endif /* !LINUX_DRIVER_SCD_HWMON_H_ */
