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

#ifndef _LINUX_DRIVER_SCD_UART_H_
#define _LINUX_DRIVER_SCD_UART_H_

#include <linux/serial.h>
#include <linux/serial_core.h>

struct scd_context;

struct scd_uart {
   struct uart_driver driver;

   struct list_head port_list;

   bool initialized;
};

struct scd_uart_port {
   struct scd_uart *uart;
   struct list_head list;

   struct uart_port port;

   struct hrtimer timer;
   ktime_t poll_interval;

   u32 addr_rx;
   u32 addr_tx;
   u32 id;
   speed_t baud;
   int no_rx_since;
   bool tx_started;
};

#define PORT_SCD 42 // Value available in include/uapi/linux/serial_core.h
#define SCD_UART_FIFO_DEPTH 120
#define SCD_UART_MAX_PORT_NR 16

#define SCD_UART_RX_ADDR_OFFSET 0
#define SCD_UART_TX_ADDR_OFFSET 0x100

#define SCD_UART_RX_CTL_OFFSET    0x0
#define SCD_UART_RX_SM_CTL_OFFSET 0x4
#define SCD_UART_RX_SM_RES_OFFSET 0x8

#define SCD_UART_TX_CTL_OFFSET    0x0
#define SCD_UART_TX_SM_REQ_OFFSET 0x4
#define SCD_UART_TX_SM_RES_OFFSET 0x8

#define SCD_UART_RX_CTL_ADDR(Port) (((Port)->addr_rx) + SCD_UART_RX_CTL_OFFSET)
#define SCD_UART_RX_SM_CTL_ADDR(Port) (((Port)->addr_rx) + SCD_UART_RX_SM_CTL_OFFSET)
#define SCD_UART_RX_SM_RES_ADDR(Port) (((Port)->addr_rx) + SCD_UART_RX_SM_RES_OFFSET)

#define SCD_UART_TX_CTL_ADDR(Port) (((Port)->addr_tx) + SCD_UART_TX_CTL_OFFSET)
#define SCD_UART_TX_SM_REQ_ADDR(Port) (((Port)->addr_tx) + SCD_UART_TX_SM_REQ_OFFSET)
#define SCD_UART_TX_SM_RES_ADDR(Port) (((Port)->addr_tx) + SCD_UART_TX_SM_RES_OFFSET)

union uart_rx_ctl {
   u32 reg;
   struct {
      u32 reserved1:7;
      u32 debugs:9;
      u32 reserved2:4;
      u32 parity:1;
      u32 reserved3:3;
      u32 brs:4;
      u32 stb:2;
      u32 reserved4:2;
   } __packed;
};

union uart_rx_sm_ctl {
   u32 reg;
   struct {
      u32 reserved1:24;
      u32 intc:8;
   } __packed;
};

union uart_rx_sm_res {
   u32 reg;
   struct {
      u32 d:8;
      u32 reserved1:8;
      u32 nrs:8;
      u32 reserved2:7;
      u32 fe:1;
   } __packed;
};

union uart_tx_ctl {
   u32 reg;
   struct {
      u32 reserved1:7;
      u32 debugs:9;
      u32 reserved2:4;
      u32 parity:1;
      u32 reserved3:3;
      u32 brs:4;
      u32 stb:2;
      u32 reserved4:2;
   } __packed;
};

union uart_tx_sm_req {
   u32 reg;
   struct {
      u32 d:8;
      u32 reserved1:19;
      u32 push:1;
      u32 reserved2:3;
      u32 st:1;
   } __packed;
};

union uart_tx_sm_res {
   u32 reg;
   struct {
      u32 reserved1:16;
      u32 nrs:7;
      u32 reserved2:8;
      u32 fe:1;
   } __packed;
};

extern int scd_uart_add(struct scd_context *ctx, u32 addr, u32 id);
extern void scd_uart_remove_all(struct scd_context *ctx);

#endif /* !_LINUX_DRIVER_SCD_UART_H_ */
