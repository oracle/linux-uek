/* Copyright (c) 2025 Arista Networks, Inc.
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

#ifndef _LINUX_DRIVER_SCD_SPI_H_
#define _LINUX_DRIVER_SCD_SPI_H_

#include <linux/pci.h>
#include <linux/spi/spi.h>

struct scd_context;

struct scd_spi_controller {
   struct scd_context *ctx;
   struct spi_controller *controller;
   struct list_head list;

   u32 csr_addr;

   u32 reg_stride;
   u32 cmd_fifo_addr;
   u32 read_fifo_addr;
   u32 ctrl_addr;
   u32 fifo_size;

};

union scd_spi_cmd_fifo {
   u32 reg;
   struct {
      u32 write_data : 8;
      u32 byte2 : 4;
      u32 record_output : 1;
      u32 byte1 : 17;
      u32 irq : 1;
      u32 chip_select_end : 1;
   } __packed;
};

union scd_spi_read_fifo {
   u32 reg;
   struct {
      u32 read_data : 8;
      u32 byte1 : 23;
      u32 data_valid : 1;
   } __packed;
};

union scd_spi_ctrl {
   u32 reg;
   struct {
      u32 read_fifo_count : 6;
      u32 byte1 : 10;
      u32 write_fifo_count : 6;
      u32 byte2 : 7;
      u32 read_fifo_underflow : 1;
      u32 cmd_fifo_overflow : 1;
      u32 spi_interrupt : 1;
   } __packed;
};

extern int scd_spi_controller_add(struct scd_context *ctx, u32 addr, u32 stride,
                                  s16 bus, u16 num_chipselect);
extern void scd_spi_controller_remove_all(struct scd_context *ctx);
extern int scd_spi_device_add(struct scd_context *ctx, s16 bus,
                              u16 chip_select, const char *modalias);

#endif /* _LINUX_DRIVER_SCD_SPI_H_ */
