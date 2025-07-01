/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2020 Marvell.
 *
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM rvu

#if !defined(__RVU_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define __RVU_TRACE_H

#include <linux/types.h>
#include <linux/tracepoint.h>
#include <linux/pci.h>

#include "mbox.h"

TRACE_EVENT(otx2_msg_alloc,
	    TP_PROTO(const struct pci_dev *pdev, u16 id, u64 size, u16 pcifunc),
	    TP_ARGS(pdev, id, size, pcifunc),
	    TP_STRUCT__entry(__string(dev, pci_name(pdev))
			     __field(u16, id)
			     __field(u64, size)
			     __field(u16, pcifunc)
	    ),
	    TP_fast_assign(__assign_str(dev);
			   __entry->id = id;
			   __entry->size = size;
			   __entry->pcifunc = pcifunc;
	    ),
	    TP_printk("[%s] msg:(%s) size:%lld pcifunc:0x%x\n", __get_str(dev),
		      otx2_mbox_id2name(__entry->id), __entry->size,
		      __entry->pcifunc)
);

TRACE_EVENT(otx2_msg_send,
	    TP_PROTO(const struct pci_dev *pdev, u16 num_msgs, u64 msg_size,
		     u16 id, u16 pcifunc),
	    TP_ARGS(pdev, num_msgs, msg_size, id, pcifunc),
	    TP_STRUCT__entry(__string(dev, pci_name(pdev))
			     __field(u16, num_msgs)
			     __field(u64, msg_size)
			     __field(u16, id)
			     __field(u16, pcifunc)
	    ),
	    TP_fast_assign(__assign_str(dev);
			   __entry->num_msgs = num_msgs;
			   __entry->msg_size = msg_size;
			   __entry->id = id;
			   __entry->pcifunc = pcifunc;
	    ),
	    TP_printk("[%s] sent %d msg(s) of size:%lld msg:(%s) pcifunc:0x%x\n",
		      __get_str(dev), __entry->num_msgs, __entry->msg_size,
		      otx2_mbox_id2name(__entry->id), __entry->pcifunc)
);

TRACE_EVENT(otx2_msg_check,
	    TP_PROTO(const struct pci_dev *pdev, u16 reqid, u16 rspid, int rc),
	    TP_ARGS(pdev, reqid, rspid, rc),
	    TP_STRUCT__entry(__string(dev, pci_name(pdev))
			     __field(u16, reqid)
			     __field(u16, rspid)
			     __field(int, rc)
	    ),
	    TP_fast_assign(__assign_str(dev);
			   __entry->reqid = reqid;
			   __entry->rspid = rspid;
			   __entry->rc = rc;
	    ),
	    TP_printk("[%s] req->id:0x%x rsp->id:0x%x resp_code:%d\n",
		      __get_str(dev), __entry->reqid,
		      __entry->rspid, __entry->rc)
);

TRACE_EVENT(otx2_msg_interrupt,
	    TP_PROTO(const struct pci_dev *pdev, const char *msg, u64 intr),
	    TP_ARGS(pdev, msg, intr),
	    TP_STRUCT__entry(__string(dev, pci_name(pdev))
			     __string(str, msg)
			     __field(u64, intr)
	    ),
	    TP_fast_assign(__assign_str(dev);
			   __assign_str(str);
			   __entry->intr = intr;
	    ),
	    TP_printk("[%s] mbox interrupt %s (0x%llx)\n", __get_str(dev),
		      __get_str(str), __entry->intr)
);

TRACE_EVENT(otx2_msg_process,
	    TP_PROTO(const struct pci_dev *pdev, u16 id, int err, u16 pcifunc),
	    TP_ARGS(pdev, id, err, pcifunc),
	    TP_STRUCT__entry(__string(dev, pci_name(pdev))
			     __field(u16, id)
			     __field(int, err)
			     __field(u16, pcifunc)
	    ),
	    TP_fast_assign(__assign_str(dev);
			   __entry->id = id;
			   __entry->err = err;
			   __entry->pcifunc = pcifunc;
	    ),
	    TP_printk("[%s] msg:(%s) error:%d pcifunc:0x%x\n", __get_str(dev),
		      otx2_mbox_id2name(__entry->id),
		      __entry->err, __entry->pcifunc)
);

TRACE_EVENT(otx2_msg_wait_rsp,
	    TP_PROTO(const struct pci_dev *pdev),
	    TP_ARGS(pdev),
	    TP_STRUCT__entry(__string(dev, pci_name(pdev))
	    ),
	    TP_fast_assign(__assign_str(dev)
	    ),
	    TP_printk("[%s] timed out while waiting for response\n",
		      __get_str(dev))
);

TRACE_EVENT(otx2_msg_status,
	    TP_PROTO(const struct pci_dev *pdev, const char *msg, u16 num_msgs),
	    TP_ARGS(pdev, msg, num_msgs),
	    TP_STRUCT__entry(__string(dev, pci_name(pdev))
			     __string(str, msg)
			     __field(u16, num_msgs)
	    ),
	    TP_fast_assign(__assign_str(dev);
			   __assign_str(str);
			   __entry->num_msgs = num_msgs;
	    ),
	    TP_printk("[%s] %s num_msgs:%d\n", __get_str(dev),
		      __get_str(str), __entry->num_msgs)
);

TRACE_EVENT(otx2_parse_dump,
	    TP_PROTO(const struct pci_dev *pdev, char *msg, u64 *word),
	    TP_ARGS(pdev, msg, word),
	    TP_STRUCT__entry(__string(dev, pci_name(pdev))
			     __string(str, msg)
			     __field(u64, w0)
			     __field(u64, w1)
			     __field(u64, w2)
			     __field(u64, w3)
			     __field(u64, w4)
			     __field(u64, w5)
	    ),
	    TP_fast_assign(__assign_str(dev);
			   __assign_str(str);
			   __entry->w0 = *(word + 0);
			   __entry->w1 = *(word + 1);
			   __entry->w2 = *(word + 2);
			   __entry->w3 = *(word + 3);
			   __entry->w4 = *(word + 4);
			   __entry->w5 = *(word + 5);
	    ),
	    TP_printk("[%s] nix parse %s W0:%#llx W1:%#llx W2:%#llx W3:%#llx W4:%#llx W5:%#llx\n",
		      __get_str(dev), __get_str(str), __entry->w0, __entry->w1, __entry->w2,
		      __entry->w3, __entry->w4, __entry->w5)
);

TRACE_EVENT(otx2_npc_mcam_alloc_entries,
	    TP_PROTO(u16 pcifunc,
		     struct npc_mcam_alloc_entry_req *req,
		     struct npc_mcam_alloc_entry_rsp *rsp),
	    TP_ARGS(pcifunc, req, rsp),
	    TP_STRUCT__entry(__field(u16, pcifunc)
			     __field(u8, contig)
			     __field(u8, ref_prio)
			     __field(u16, ref_entry)
			     __field(u16, req_count)
			     __field(u8, kw_type)
			     __field(u8, virt)
			     __field(u16, start_mcam_idx)
			     __field(u16, rsp_count)
			     __field(u16, free_count)
	    ),
	    TP_fast_assign(__entry->contig = req->contig;
			   __entry->ref_prio = req->ref_prio;
			   __entry->ref_entry = req->ref_entry;
			   __entry->req_count = req->count;
			   __entry->kw_type = req->kw_type;
			   __entry->virt = req->virt;
			   __entry->start_mcam_idx = rsp->entry;
			   __entry->rsp_count = rsp->count;
			   __entry->free_count = rsp->free_count;
	    ),
	    TP_printk("pcifunc:%d req_contig:%d req_ref_prio:%d req->ref_entry:%d req->req_count:%d req->kw_type:%d req->virt:%d rsp_start_mcam_idx:%d rsp_count:%d rsp_free_count:%d\n",
		      __entry->pcifunc, __entry->contig, __entry->ref_prio,
		      __entry->ref_entry, __entry->req_count, __entry->kw_type,
		      __entry->virt, __entry->start_mcam_idx, __entry->rsp_count,
		      __entry->free_count)
);

TRACE_EVENT(otx2_npc_enable_mcam_entry,
	    TP_PROTO(u16 index, u8 enable),
	    TP_ARGS(index, enable),
	    TP_STRUCT__entry(__field(u16, mcam_index)
			     __field(u8, ena)
	    ),
	    TP_fast_assign(__entry->mcam_index = index;
			   __entry->ena = enable;
	    ),
	    TP_printk("mcam_index:%d enable:%d\n", __entry->mcam_index, __entry->ena)
);

TRACE_EVENT(otx2_npc_cam,
	    TP_PROTO(u16 index, u8 bank,
		     u64 w0_cam0,
		     u64 w0_cam1,
		     u64 w1_cam0,
		     u64 w1_cam1),
	    TP_ARGS(index, bank,
		    w0_cam0, w0_cam1,
		    w1_cam0, w1_cam1),
	    TP_STRUCT__entry(__field(u16, mcam_index)
			     __field(u8, bank)
			     __field(u64, w0_cam0)
			     __field(u64, w0_cam1)
			     __field(u64, w1_cam0)
			     __field(u64, w1_cam1)
	    ),
	    TP_fast_assign(__entry->mcam_index = index;
			   __entry->bank = bank;
			   __entry->w0_cam0 = w0_cam0;
			   __entry->w0_cam1 = w0_cam1;
			   __entry->w1_cam0 = w1_cam0;
			   __entry->w1_cam1 = w1_cam1;
	    ),
	    TP_printk("mcam_index:%d bank:%d w0_cam0:0x%llx w0_cam1:0x%llx, w1_cam0:0x%llx, w1_cam1:0x%llx\n",
		      __entry->mcam_index, __entry->bank, __entry->w0_cam0, __entry->w0_cam1,
		      __entry->w1_cam0, __entry->w1_cam1)
);

TRACE_EVENT(otx2_npc_action,
	    TP_PROTO(u16 index, u8 bank,
		     u8 tx_intf, u8 enable,
		     u64 act, u64 vtag_act),
	    TP_ARGS(index, bank,
		    tx_intf, enable,
		    act, vtag_act),
	    TP_STRUCT__entry(__field(u16, mcam_index)
			     __field(u8, bank)
			     __field(u8, tx_intf)
			     __field(u8, enable)
			     __field(u64, act)
			     __field(u64, vtag_act)
	    ),
	    TP_fast_assign(__entry->mcam_index = index;
			   __entry->bank = bank;
			   __entry->tx_intf = tx_intf;
			   __entry->enable = enable;
			   __entry->act = act;
			   __entry->vtag_act = vtag_act;
	    ),
	    TP_printk("mcam_index:%d bank:%d tx_intf:%d enable:%d action:0x%llx vtag_action:0x%llx\n",
		      __entry->mcam_index, __entry->bank, __entry->tx_intf,
		      __entry->enable, __entry->act, __entry->vtag_act)
);

#endif /* __RVU_TRACE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE rvu_trace

#include <trace/define_trace.h>
