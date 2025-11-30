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

DECLARE_EVENT_CLASS(
        scd_smbus_cs,
        TP_PROTO(struct scd_smbus_master *master,
                 union smbus_ctrl_status_reg cs),
        TP_ARGS(master, cs),
        TP_STRUCT__entry(
                __field(__u16, pciId)
                __field(__u16, accId)
                __field(__u32, reg)),
        TP_fast_assign(
                __entry->pciId = PCI_DEVID(
                        master->ctx->pdev->bus->number,
                        master->ctx->pdev->devfn),
                __entry->accId = master->id,
                __entry->reg = cs.reg),
        TP_printk("%02x:%02x.%d-%d " CS_FMT,
                  PCI_BUS_NUM(__entry->pciId),
                  PCI_SLOT(__entry->pciId),
                  PCI_FUNC(__entry->pciId),
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
                __field(__u16, pciId)
                __field(__u16, accId)
                __field(__u32, reg)),
        TP_fast_assign(
                __entry->pciId = PCI_DEVID(
                        master->ctx->pdev->bus->number,
                        master->ctx->pdev->devfn),
                __entry->accId = master->id,
                __entry->reg = req.reg),
        TP_printk("%02x:%02x.%d-%d " REQ_FMT,
                  PCI_BUS_NUM(__entry->pciId),
                  PCI_SLOT(__entry->pciId),
                  PCI_FUNC(__entry->pciId),
                  __entry->accId,
                  REQ_ARGS((union smbus_request_reg) {
                                  .reg = __entry->reg })))

TRACE_EVENT(
        scd_smbus_rsp_rd,
        TP_PROTO(struct scd_smbus_master *master,
                 union smbus_response_reg req),
        TP_ARGS(master, req),
        TP_STRUCT__entry(
                __field(__u16, pciId)
                __field(__u16, accId)
                __field(__u32, reg)),
        TP_fast_assign(
                __entry->pciId = PCI_DEVID(
                        master->ctx->pdev->bus->number,
                        master->ctx->pdev->devfn),
                __entry->accId = master->id,
                __entry->reg = req.reg),
        TP_printk("%02x:%02x.%d-%d " RSP_FMT,
                  PCI_BUS_NUM(__entry->pciId),
                  PCI_SLOT(__entry->pciId),
                  PCI_FUNC(__entry->pciId),
                  __entry->accId,
                  RSP_ARGS((union smbus_response_reg) {
                                  .reg = __entry->reg })))

#endif /* _SCD_SMBUS_TRACE_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE scd-smbus-trace
#include <trace/define_trace.h>
