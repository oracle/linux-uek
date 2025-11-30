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

#ifndef _LINUX_DRIVER_SCD_SMBUS_H_
#define _LINUX_DRIVER_SCD_SMBUS_H_

#include <linux/list.h>
#include <linux/i2c.h>

struct scd_context;

#define SMBUS_REQUEST_OFFSET 0x10
#define SMBUS_CONTROL_STATUS_OFFSET 0x20
#define SMBUS_RESPONSE_OFFSET 0x30

#define MASTER_DEFAULT_BUS_COUNT 8
#define MASTER_DEFAULT_MAX_RETRIES 6

struct scd_smbus_master {
   struct scd_context *ctx;
   struct list_head list;

   u32 id;
   u32 req;
   u32 cs;
   u32 resp;
   struct mutex mutex;
   struct list_head bus_list;

   int max_retries;
};

struct bus_params {
   struct list_head list;
   u16 addr;
   u8 t;
   u8 datw;
   u8 datr;
   u8 ed;
};

struct scd_smbus {
   struct scd_smbus_master *master;
   struct list_head list;

   u32 id;
   struct list_head params;

   struct i2c_adapter adap;
};

union smbus_ctrl_status_reg {
   u32 reg;
   struct {
      u32 nrs:10;
      u32 fsz:3;
      u32 foe:1;
      u32 sp:2;
      u32 nrq:10;
      u32 brb:1;
      u32 rsv:1;
      u32 ver:2;
      u32 fe:1;
      u32 rst:1;
   } __packed;
};

static inline int
scd_smbus_cs_fsz(union smbus_ctrl_status_reg cs)
{
   return ((int[]){127, 255, 511, 1023, -1, -1, -1, -1})[cs.fsz];
}

#define CS_FMT      \
   "{"              \
   " .reg=0x%08x,"  \
   " .rst=%d"       \
   " .fe=%d,"       \
   " .ver=%d,"      \
   " .brb=%d,"      \
   " .nrq=%d,"      \
   " .sp=%#x,"      \
   " .foe=%d,"      \
   " .fsz=%d,"      \
   " .nrs=%d"       \
   " }"

#define CS_ARGS(_cs)  \
   (_cs).reg,         \
   (_cs).rst,         \
   (_cs).fe,          \
   (_cs).ver,         \
   (_cs).brb,         \
   (_cs).nrq,         \
   (_cs).sp,          \
   (_cs).foe,         \
   (_cs).fsz,         \
   (_cs).nrs

union smbus_request_reg {
   u32 reg;
   struct {
      u32 d:8;
      u32 ss:6;
      u32 ed:1;
      u32 br:1;
      u32 dat:2;
      u32 t:2;
      u32 sp:1;
      u32 da:1;
      u32 dod:1;
      u32 st:1;
      u32 bs:4;
      u32 ti:4;
   } __packed;
};

#define REQ_FMT     \
   "{"              \
   " .reg=0x%08x,"  \
   " .ti=%02d,"     \
   " .bs=%#x,"      \
   " .st=%d,"       \
   " .dod=%d,"      \
   " .da=%d,"       \
   " .sp=%d,"       \
   " .t=%d,"        \
   " .dat=%#x,"     \
   " .br=%d,"       \
   " .ed=%d,"       \
   " .ss=%02d,"     \
   " .d=0x%02x"    \
   " }"

#define REQ_ARGS(_req)  \
   (_req).reg,          \
   (_req).ti,           \
   (_req).bs,           \
   (_req).st,           \
   (_req).dod,          \
   (_req).da,           \
   (_req).sp,           \
   (_req).t,            \
   (_req).dat,          \
   (_req).br,           \
   (_req).ed,           \
   (_req).ss,           \
   (_req).d

union smbus_response_reg {
   u32 reg;
   struct {
      u32 d:8;
      u32 bus_conflict_error:1;
      u32 timeout_error:1;
      u32 ack_error:1;
      u32 flushed:1;
      u32 ti:4;
      u32 ss:6;
      u32 reserved2:8;
      u32 foe:1;
      u32 fe:1;
   } __packed;
};

#define RSP_FMT                \
   "{"                         \
   " .reg=0x%08x,"             \
   " .fe=%d,"                  \
   " .foe=%d,"                 \
   " .ss=%02d,"                \
   " .ti=%02d,"                \
   " .flushed=%d,"             \
   " .ack_error=%d,"           \
   " .timeout_error=%d,"       \
   " .bus_conflict_error=%d,"  \
   " .d=0x%02x"                \
   " }"

#define RSP_ARGS(_rsp)        \
   (_rsp).reg,                \
   (_rsp).fe,                 \
   (_rsp).foe,                \
   (_rsp).ss,                 \
   (_rsp).ti,                 \
   (_rsp).flushed,            \
   (_rsp).ack_error,          \
   (_rsp).timeout_error,      \
   (_rsp).bus_conflict_error, \
   (_rsp).d

extern int scd_smbus_master_add(struct scd_context *ctx, u32 addr, u32 id,
                                u32 bus_count);
extern void scd_smbus_remove_all(struct scd_context *ctx);
extern ssize_t scd_set_smbus_params(struct scd_context *ctx, u16 bus,
                                    struct bus_params *params);

#endif /* _LINUX_DRIVER_SCD_SMBUS_H_ */
