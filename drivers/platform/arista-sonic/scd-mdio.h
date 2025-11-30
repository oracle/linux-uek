/* Copyright (c) 2019 Arista Networks, Inc.
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

#ifndef _LINUX_DRIVER_SCD_MDIO_H_
#define _LINUX_DRIVER_SCD_MDIO_H_

#include <linux/mii.h>
#include <linux/netdevice.h>
#include <linux/phy.h>

#define MDIO_REQUEST_LO_OFFSET 0x00
#define MDIO_REQUEST_HI_OFFSET 0x10
#define MDIO_CONTROL_STATUS_OFFSET 0x20
#define MDIO_RESPONSE_OFFSET 0x30

#define MDIO_WAIT_INITIAL 1UL
#define MDIO_WAIT_MAX (1000UL * 1000)
#define MDIO_WAIT_MAX_UDELAY (10UL * 1000)
#define MDIO_WAIT_NEXT(cur) \
   min((cur) * 2, MDIO_WAIT_MAX)
#define MDIO_WAIT_END(cur) ((cur) >= MDIO_WAIT_MAX)

#define MDIO_RESET_DELAY 20

union mdio_ctrl_status_reg {
   u32 reg;
   struct {
      u32 res_count:10;
      u32 fs:3;
      u32 pbd:3;
      u32 req_count:10;
      u32 sp:2;
      u32 reserved:2;
      u32 fe:1;
      u32 reset:1;
   } __packed;
};

union mdio_request_lo_reg {
   u32 reg;
   struct {
      u32 d:16;
      u32 dt:5;
      u32 pa:5;
      u32 op:2;
      u32 t:1;
      u32 bs:3;
   } __packed;
};

union mdio_request_hi_reg {
   u32 reg;
   struct {
      u32 reserved1:16;
      u32 ri:8;
      u32 reserved2:4;
      u32 tbd:3;
      u32 be:1;
   } __packed;
};

union mdio_response_reg {
   u32 reg;
   struct {
      u32 d:16;
      u32 ri:8;
      u32 reserved1:6;
      u32 fe:1;
      u32 ts:1;
   } __packed;
};

enum mdio_operation {
   SCD_MDIO_SET = 0,
   SCD_MDIO_WRITE = 1,
   SCD_MDIO_READ = 3,
};

struct scd_mdio_master {
   struct scd_context *ctx;
   struct list_head list;

   u16 req_lo;
   u16 req_hi;
   u16 cs;
   u16 resp;

   u16 id;
   u8 speed;
   u8 req_id;
   struct mutex mutex;
   struct list_head bus_list;
};

struct scd_mdio_bus {
   struct scd_mdio_master *master;
   struct list_head list;

   u16 id;
   u32 dev_id_to_addr[PHY_MAX_ADDR];
   struct mii_bus *mii_bus;
   struct list_head device_list;
};

struct scd_mdio_device {
   struct scd_mdio_bus *mdio_bus;
   struct list_head list;

   u16 id;
   u16 prtad;
   u16 devad;
   u16 mode_support;
   struct mdio_if_info mdio_if;
   struct net_device *net_dev;
   struct mdio_device *mdio_dev;
};

extern int scd_mdio_device_add(struct scd_context *ctx, u16 master_id, u16 bus_id,
                               u16 dev_id, u16 prtad, u16 devad, u16 clause);
extern int scd_mdio_master_add(struct scd_context *ctx, u32 addr, u16 id,
                               u16 bus_count, u16 speed);
extern void scd_mdio_remove_all(struct scd_context *ctx);

#endif /* !_LINUX_DRIVER_SCD_MDIO_H_ */
