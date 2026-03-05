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

#undef TRACE_SYSTEM
#define TRACE_SYSTEM scd_smbus

#if !defined(_SCD_SMBUS_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _SCD_SMBUS_TRACE_H

#include <linux/tracepoint.h>

#define DEV_ID_BUF_SIZE 32

/*
 * Fills buf with a human-readable device identifier.
 * For PCI devices: "<bus>:<slot>.<func>" (e.g. "01:00.0")
 * For other devices (e.g. I2C): the kernel dev_name() string
 */
#define SCD_SMBUS_FILL_DEV_ID(dev, buf)                                 \
   do {                                                                 \
      if ((dev)->bus == &pci_bus_type) {                                \
         struct pci_dev *_pdev = to_pci_dev(dev);                       \
         snprintf(buf, sizeof(buf), "%02x:%02x.%d",                     \
                  _pdev->bus->number,                                   \
                  PCI_SLOT(_pdev->devfn),                               \
                  PCI_FUNC(_pdev->devfn));                              \
      } else {                                                          \
         snprintf(buf, sizeof(buf), "%s", dev_name(dev));               \
      }                                                                 \
   } while (0)


DECLARE_EVENT_CLASS(
        scd_smbus_cs,
        TP_PROTO(struct scd_smbus_master *master,
                 union smbus_ctrl_status_reg cs),
        TP_ARGS(master, cs),
        TP_STRUCT__entry(
                __array(char, devId, DEV_ID_BUF_SIZE)
                __field(__u16, accId)
                __field(__u32, reg)),
        TP_fast_assign(
                SCD_SMBUS_FILL_DEV_ID(master->ctx->dev, __entry->devId);
                __entry->accId = master->id;
                __entry->reg = cs.reg;),
        TP_printk("%s-%d " CS_FMT,
                  __entry->devId,
                  __entry->accId,
                  CS_ARGS((union smbus_ctrl_status_reg) {
                                  .reg = __entry->reg })))

DEFINE_EVENT(
        scd_smbus_cs, scd_smbus_cs_rd,
        TP_PROTO(struct scd_smbus_master *master,
                 union smbus_ctrl_status_reg cs),
        TP_ARGS(master, cs));

DEFINE_EVENT(
        scd_smbus_cs, scd_smbus_cs_wr,
        TP_PROTO(struct scd_smbus_master *master,
                 union smbus_ctrl_status_reg cs),
        TP_ARGS(master, cs));

TRACE_EVENT(
        scd_smbus_req_wr,
        TP_PROTO(struct scd_smbus_master *master,
                 union smbus_request_reg req),
        TP_ARGS(master, req),
        TP_STRUCT__entry(
                __array(char, devId, DEV_ID_BUF_SIZE)
                __field(__u16, accId)
                __field(__u32, reg)),
        TP_fast_assign(
                SCD_SMBUS_FILL_DEV_ID(master->ctx->dev, __entry->devId);
                __entry->accId = master->id;
                __entry->reg = req.reg;),
        TP_printk("%s-%d " REQ_FMT,
                  __entry->devId,
                  __entry->accId,
                  REQ_ARGS((union smbus_request_reg) {
                                  .reg = __entry->reg })))

TRACE_EVENT(
        scd_smbus_rsp_rd,
        TP_PROTO(struct scd_smbus_master *master,
                 union smbus_response_reg req),
        TP_ARGS(master, req),
        TP_STRUCT__entry(
                __array(char, devId, DEV_ID_BUF_SIZE)
                __field(__u16, accId)
                __field(__u32, reg)),
        TP_fast_assign(
                SCD_SMBUS_FILL_DEV_ID(master->ctx->dev, __entry->devId);
                __entry->accId = master->id;
                __entry->reg = req.reg;),
        TP_printk("%s-%d " RSP_FMT,
                  __entry->devId,
                  __entry->accId,
                  RSP_ARGS((union smbus_response_reg) {
                                  .reg = __entry->reg })))

DECLARE_EVENT_CLASS(
        scd_smbus_sp,
        TP_PROTO(struct scd_smbus_master *master,
                 union smbus_speed_reg sp),
        TP_ARGS(master, sp),
        TP_STRUCT__entry(
                __array(char, devId, DEV_ID_BUF_SIZE)
                __field(__u16, accId)
                __field(__u32, reg)),
        TP_fast_assign(
                SCD_SMBUS_FILL_DEV_ID(master->ctx->dev, __entry->devId);
                __entry->accId = master->id;
                __entry->reg = sp.reg;),
        TP_printk("%s-%d " SP_FMT,
                  __entry->devId,
                  __entry->accId,
                  SP_ARGS((union smbus_speed_reg) {
                                  .reg = __entry->reg })))
DEFINE_EVENT(
        scd_smbus_sp, scd_smbus_sp_rd,
        TP_PROTO(struct scd_smbus_master *master,
                 union smbus_speed_reg sp),
        TP_ARGS(master, sp));

DEFINE_EVENT(
        scd_smbus_sp, scd_smbus_sp_wr,
        TP_PROTO(struct scd_smbus_master *master,
                 union smbus_speed_reg sp),
        TP_ARGS(master, sp));

#endif /* _SCD_SMBUS_TRACE_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE scd-smbus-trace
#include <trace/define_trace.h>
