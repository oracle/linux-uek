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

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "scd.h"
#include "scd-spi.h"
#include "scd-hwmon.h"

#define spi_prefix(_func, _spi, _fmt, _args...)            \
   _func(&(_spi)->ctx->pdev->dev,    \
         "spi @ %#x: " _fmt, (_spi)->csr_addr, ##_args)
#define spi_dbg(_spi, _fmt, _args...)                       \
   spi_prefix(dev_dbg, _spi, _fmt, ##_args)
#define spi_notice(_spi, _fmt, _args...)                    \
   spi_prefix(dev_notice, _spi, _fmt, ##_args)
#define spi_warn(_spi, _fmt, _args...)                      \
   spi_prefix(dev_warn, _spi, _fmt " (%s:%d)", ##_args, __func__, __LINE__)
#define spi_err(_spi, _fmt, _args...)                      \
   spi_prefix(dev_err, _spi, _fmt " (%s:%d)", ##_args, __func__, __LINE__)

static struct spi_controller *scd_spi_get_controller(struct scd_context *ctx,
                                                     s16 bus)
{
   struct scd_spi_controller *spi;
   list_for_each_entry(spi, &ctx->spi_controller_list, list){
      if (spi->controller->bus_num == bus)
         return spi->controller;
   }
   return NULL;
}

static u32 spi_csr_read(struct scd_spi_controller *spi, u32 reg_offset)
{
   return scd_read_register(spi->ctx->pdev, spi->csr_addr + reg_offset);
}

static void spi_csr_write(struct scd_spi_controller *spi,
                          u32 reg_offset, u32 val)
{
   scd_write_register(spi->ctx->pdev,
                      spi->csr_addr + reg_offset, val);
}

static int scd_spi_tx_wait(struct scd_spi_controller *spi, int entries,
                           int orig_entries)
{
   union scd_spi_ctrl ctrl;
   unsigned long timeout;

   timeout = jiffies + msecs_to_jiffies((10 * orig_entries) + 10);
   do {
      ctrl.reg = spi_csr_read(spi, spi->ctrl_addr);
      if (ctrl.write_fifo_count <= entries) {
         return 0;
      }
      usleep_range(1, 50);
   } while (!time_after(jiffies, timeout));

   spi_err(spi, "write timeout, %d entries left\n",
           ctrl.write_fifo_count);

   return 1;
}

static int scd_spi_rx_wait(struct scd_spi_controller *spi, int entries)
{
   union scd_spi_ctrl ctrl;
   unsigned long timeout;

   timeout = jiffies + msecs_to_jiffies((10 * entries) + 10);
   do {
      ctrl.reg = spi_csr_read(spi, spi->ctrl_addr);
      if (ctrl.read_fifo_count >= entries) {
         return 0;
      }
      usleep_range(1, 50);
   } while (!time_after(jiffies, timeout));

   spi_err(spi, "read timeout, %d entries expecting %d\n",
           ctrl.read_fifo_count, entries);

   return 1;
}

static int scd_spi_discover_fifo_size(struct scd_spi_controller *spi)
{
   union scd_spi_ctrl ctrl;
   union scd_spi_cmd_fifo cmd;
   u16 max_fifo_size = 256;

   ctrl.reg = spi_csr_read(spi, spi->ctrl_addr);
   if (ctrl.write_fifo_count != 0 || ctrl.read_fifo_count != 0) {
      spi_warn(spi, "controller may detect incorrect fifo size");
   }

   for (u16 i = 0; ctrl.cmd_fifo_overflow == 0 && i < max_fifo_size; i++) {
      cmd.reg = 0x05; //SPI_CMD_READSTATUSREGISTER;
      spi_csr_write(spi, spi->cmd_fifo_addr, cmd.reg);

      cmd.reg = 0;
      cmd.record_output = 1;
      cmd.chip_select_end = 1;
      spi_csr_write(spi, spi->cmd_fifo_addr, cmd.reg);

      ctrl.reg = spi_csr_read(spi, spi->ctrl_addr);
   }
   if (ctrl.cmd_fifo_overflow != 1) {
      spi->fifo_size = max_fifo_size;
   } else {
      spi->fifo_size = ctrl.read_fifo_count;
   }

   spi_dbg(spi, "discovered fifo size: %u\n",
           spi->fifo_size);
   return 0;
}

static int scd_spi_sanitize(struct scd_spi_controller *spi)
{
   union scd_spi_ctrl ctrl;
   union scd_spi_cmd_fifo cmd;

   ctrl.reg = 0;
   ctrl.read_fifo_underflow = 1;
   ctrl.cmd_fifo_overflow = 1;
   spi_csr_write(spi, spi->ctrl_addr, ctrl.reg);

   ctrl.reg = spi_csr_read(spi, spi->ctrl_addr);
   while( ctrl.read_fifo_count || ctrl.write_fifo_count ){
      spi_csr_read(spi, spi->read_fifo_addr);
      ctrl.reg = spi_csr_read(spi, spi->ctrl_addr);
   }

   cmd.reg = 0;
   cmd.record_output = 1;
   cmd.chip_select_end = 1;
   spi_csr_write(spi, spi->cmd_fifo_addr, cmd.reg);
   if (scd_spi_tx_wait(spi, 0, 1)) {
      return 1;
   }
   if (scd_spi_rx_wait(spi, 1)) {
      return 1;
   }
   spi_csr_read(spi, spi->read_fifo_addr);
   return 0;
}

static int scd_spi_transfer_one(struct scd_spi_controller *spi,
                                struct spi_transfer *t, bool last_xfer)
{
   const u8 *tx_buf;
   u8 *rx_buf;
   bool read;
   bool last_entry;
   int i;
   int j;
   int fifo_count;
   union scd_spi_cmd_fifo write_val;
   union scd_spi_read_fifo read_val;

   tx_buf = t->tx_buf;
   rx_buf = t->rx_buf;
   fifo_count = 0;
   read = (rx_buf != NULL);

   for (i = 0; i < t->len; i++) {
      last_entry = (i == (t->len - 1));
      write_val.reg = 0;
      if (tx_buf) {
         write_val.write_data = *(tx_buf++);
      }
      write_val.chip_select_end = last_entry && (last_xfer ^ t->cs_change);
      write_val.record_output = read;

      spi_dbg(spi, "fifo write data 0x%08x\n", write_val.reg);
      spi_csr_write(spi, spi->cmd_fifo_addr, write_val.reg);
      fifo_count++;

      if (last_entry || fifo_count == spi->fifo_size) {
         scd_spi_tx_wait(spi, 0, fifo_count);

         if (read) {
            scd_spi_rx_wait(spi, fifo_count);
            for (j = 0; j < fifo_count; j++) {
               read_val.reg = spi_csr_read(spi,
                                           spi->read_fifo_addr);
               spi_dbg(spi, "fifo read data 0x%08x\n",
                       read_val.reg);
               *(rx_buf++) = read_val.read_data;
            }
         }
         fifo_count = 0;
      }
   }

   spi_delay_exec(&t->delay, t);
   return 0;
}

static int scd_spi_transfer_one_message(struct spi_controller *controller,
                                        struct spi_message *msg)
{
   struct scd_spi_controller *spi;
   struct spi_transfer *t;
   bool last_xfer;
   unsigned int total_len = 0;

   spi = spi_controller_get_devdata(controller);

   list_for_each_entry(t, &msg->transfers, transfer_list){
      last_xfer = list_is_last(&t->transfer_list, &msg->transfers);

      scd_spi_transfer_one(spi, t, last_xfer);
      total_len += t->len;
   }

   msg->status = 0;
   msg->actual_length = total_len;
   spi_finalize_current_message(controller);

   return 0;
}

int scd_spi_controller_add(struct scd_context *ctx, u32 addr, u32 reg_stride,
                           s16 bus, u16 num_chipselect)
{
   struct spi_controller *controller;
   struct scd_spi_controller *spi;
   struct device *dev = get_scd_dev(ctx);
   int err;

   dev_dbg(dev, "adding spi controller %d at addr %#x\n",
           bus, addr);

   controller = spi_alloc_master(dev, sizeof(struct scd_spi_controller));
   if (!controller) {
      return -ENOMEM;
   }
   spi = spi_controller_get_devdata(controller);

   spi->csr_addr = addr;
   spi->reg_stride = reg_stride;
   spi->cmd_fifo_addr = 0x0;
   spi->read_fifo_addr = 0x1 * spi->reg_stride;
   spi->ctrl_addr = 0x2 * spi->reg_stride;
   spi->ctx = ctx;
   INIT_LIST_HEAD(&spi->list);

   controller->bus_num = bus;
   controller->num_chipselect = num_chipselect;
   controller->flags = SPI_CONTROLLER_MUST_TX;
   controller->transfer_one_message = scd_spi_transfer_one_message;

   if (scd_spi_discover_fifo_size(spi)) {
      spi_err(spi, "failed to discover fifo size\n");
      err = -ENOPROTOOPT;
   }

   if (scd_spi_sanitize(spi)) {
      spi_err(spi, "failed to sanitize accelerator\n");
      err = -ENOPROTOOPT;
      goto fail_controller;
   }

   err = spi_register_controller(controller);
   if (err < 0) {
      spi_err(spi, "failed to register controller %d\n", bus);
      goto fail_controller;
   }

   spi->controller = controller;
   list_add_tail(&spi->list, &ctx->spi_controller_list);
   spi_notice(spi, "controller created\n");
   return 0;

fail_controller:
   spi_controller_put(controller);
   return err;
}

static int __unregister_spi_dev(struct device *dev, void *data)
{
   if (dev->bus == &spi_bus_type) {
      struct spi_device *spi = to_spi_device(dev);
      spi_unregister_device(spi);
   }
   return 0;
}

static void scd_spi_controller_remove(struct scd_spi_controller *spi)
{
   device_for_each_child(&spi->controller->dev, NULL,
                         __unregister_spi_dev);
   spi_unregister_controller(spi->controller);
   spi_notice(spi, "controller removed\n");
}

void scd_spi_controller_remove_all(struct scd_context *ctx)
{
   struct scd_spi_controller *spi;
   struct scd_spi_controller *tmp_spi;

   list_for_each_entry_safe(spi, tmp_spi, &ctx->spi_controller_list, list) {
      scd_spi_controller_remove(spi);
      list_del(&spi->list);
      kfree(spi);
   }
}

int scd_spi_device_add(struct scd_context *ctx, s16 bus, u16 chip_select,
                       const char* modalias)
{
   struct spi_controller *controller;
   struct spi_device *device;
   struct spi_board_info info = {{ 0 }};

   dev_dbg(get_scd_dev(ctx),
           "creating device bus: %d, cs: %u\n",
           bus, chip_select);

   strscpy(info.modalias, modalias, sizeof(info.modalias));
   info.max_speed_hz = 25000000;
   info.chip_select = chip_select;

   controller = scd_spi_get_controller(ctx, bus);
   if (!controller) {
      dev_err(get_scd_dev(ctx), "no controller on bus %d\n", bus);
      return -ENODEV;
   }

   device = spi_new_device(controller, &info);
   if (!device) {
      dev_err(get_scd_dev(ctx),
              "failed to create device bus: %d, cs: %u\n",
              bus, chip_select);
      return -ENODEV;
   }

   dev_notice(get_scd_dev(ctx),
              "modalias: %s, bus: %d, cs: %u\n",
              info.modalias, bus, info.chip_select);
   return 0;
}
