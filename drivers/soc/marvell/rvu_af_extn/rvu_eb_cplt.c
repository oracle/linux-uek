// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#include <linux/bitfield.h>
#include <linux/pci.h>
#include "rvu.h"
#include "rvu_reg.h"
#include "rvu_eblock.h"
#include "rvu_cplt_mbox.h"
#include "mbox.h"
#include "rvu_trace.h"

#define LMAC_BMAP_MASK 0xff

struct cplt_drvdata {
	int res_idx;
};

#define M(_name, _id, _fn_name, _req_type, _rsp_type)			\
static struct _req_type __maybe_unused					\
*otx2_mbox_alloc_msg_ ## _fn_name(struct rvu *rvu, int devid)		\
{									\
	struct _req_type *req;						\
									\
	req = (struct _req_type *)otx2_mbox_alloc_msg_rsp(		\
		&rvu->afpf_wq_info.mbox_up, devid, sizeof(struct _req_type), \
		sizeof(struct _rsp_type));				\
	if (!req)							\
		return NULL;						\
	req->hdr.sig = OTX2_MBOX_REQ_SIG;				\
	req->hdr.id = _id;						\
	trace_otx2_msg_alloc(rvu->pdev, _id, sizeof(*req), 0);		\
	return req;							\
}

MBOX_UP_CGX_MESSAGES
MBOX_EBLOCK_UP_CPLT_MESSAGES
#undef M

#define CPLT_OFFSET(x, y)	((((x) * (rvu->fwdata->num_rpm_in_chiplet)) \
					+ (y)) * (rvu->hw->lmac_per_cplt))

/* Returns bitmap of mapped PF/s */
static u64 cpltlmac_to_pfmap(struct rvu *rvu, u8 cplt_id, u8 rpm, u8 lmac)
{
	return rvu->cplt_rpm->cpltlmac2pf_map[CPLT_OFFSET(cplt_id, rpm) + lmac];
}

void pf_bmap_to_cpltlmac(u16 pf2cpltlmac_map, u8 *chiplet_id,
			 u8 *rpm_id, u8 *lmac_id)
{
	*chiplet_id = (pf2cpltlmac_map >> 12) & 0xf;
	*rpm_id = (pf2cpltlmac_map >> 8) & 0xf;
	*lmac_id = (pf2cpltlmac_map & 0xff);
}

int rvu_mbox_handler_cplt_rpm_port_ready(struct rvu *rvu,
					 struct cplt_rpm_port_ready_req *req,
					 struct msg_rsp *rsp)
{
	if (req->num_bphy_chiplets && req->valid_interface_bitmap)
		rvu->cplt_rpm->ready = 1;

	return 0;
}

int rvu_mbox_handler_cplt_rpm_link_event(struct rvu *rvu,
					 struct cplt_rpm_link_event_req *req,
					 struct msg_rsp *rsp)
{
	struct cplt_evq_entry *qentry;
	unsigned long flags;
	int err;

	qentry = kmalloc(sizeof(*qentry), GFP_KERNEL);
	if (!qentry)
		return -ENOMEM;

	/* Lock the event queue before we read the local link status */
	spin_lock_irqsave(&rvu->cplt_rpm->cplt_evq_lock, flags);
	memcpy(&qentry->link_event.link_uinfo, &req->link_info,
	       sizeof(struct cplt_link_user_info));
	qentry->link_event.chiplet_id = req->chiplet_id;
	qentry->link_event.rpm_id = req->rpm_id;
	qentry->link_event.lmac_id = req->lmac_id;
	if (err) {
		kfree(qentry);
		goto skip_add;
	}
	list_add_tail(&qentry->evq_node, &rvu->cplt_rpm->cplt_evq_head);
skip_add:
	spin_unlock_irqrestore(&rvu->cplt_rpm->cplt_evq_lock, flags);

	/* start worker to process the events */
	queue_work(rvu->cplt_rpm->cplt_evh_wq, &rvu->cplt_rpm->cplt_evh_work);

	return 0;
}

static void cplt_notify_up_ptp_info(struct rvu *rvu, int pf, bool enable)
{
	struct cgx_ptp_rx_info_msg *msg;

	/* Send mbox message to PF */
	msg = otx2_mbox_alloc_msg_cgx_ptp_rx_info(rvu, pf);
	if (!msg) {
		dev_err(rvu->dev, "failed to alloc message\n");
		return;
	}

	msg->ptp_en = enable;

	otx2_mbox_wait_for_zero(&rvu->afpf_wq_info.mbox_up, pf);

	otx2_mbox_msg_send_up(&rvu->afpf_wq_info.mbox_up, pf);
}

int rvu_mbox_handler_cplt_rpm_ptp_rx_info(struct rvu *rvu,
					  struct cplt_rpm_ptp_rx_info_req *req,
					  struct msg_rsp *rsp)
{
	u8 chiplet_id, rpm_id, lmac_id;
	unsigned long pf_map;
	int pf;

	chiplet_id = req->chiplet_id;
	rpm_id = req->rpm_id;
	lmac_id = req->lmac_id;

	pf_map = cpltlmac_to_pfmap(rvu, chiplet_id, rpm_id, lmac_id);

	pf = find_first_bit(&pf_map, 64);

	cplt_notify_up_ptp_info(rvu, pf, req->ptp_en);

	return 0;
}

static void cplt_rpm_ptp_en_req(struct rvu *rvu, int pf, u8 chiplet_id,
				u8 rpm_id, u8 lmac_id)
{
	struct cplt_rpm_ptp_en_req *msg;

	/* Send mbox message to PF 25 */
	msg = otx2_mbox_alloc_msg_cplt_rpm_ptp_en(rvu, pf);
	if (!msg) {
		dev_err(rvu->dev, "failed to alloc message\n");
		return;
	}

	msg->chiplet_id = chiplet_id;
	msg->rpm_id = rpm_id;
	msg->lmac_id = lmac_id;

	msg->ptp_en = 1;

	otx2_mbox_wait_for_zero(&rvu->afpf_wq_info.mbox_up, pf);

	otx2_mbox_msg_send_up(&rvu->afpf_wq_info.mbox_up, pf);
}

int rvu_mbox_handler_cplt_ptp_rx_enable(struct rvu *rvu,
					struct msg_req *req,
					struct msg_rsp *rsp)
{
	u8 chiplet_id, rpm_id, lmac_id;
	u16 pcifunc = req->hdr.pcifunc;
	int pf = rvu_get_pf(pcifunc);

	pf_bmap_to_cpltlmac(rvu->cplt_rpm->pf2cpltlmac_map[pf], &chiplet_id,
			    &rpm_id, &lmac_id);

	cplt_rpm_ptp_en_req(rvu, pf, chiplet_id, rpm_id, lmac_id);

	return 0;
}

int rvu_mbox_handler_cplt_rpm_get_chan_info(struct rvu *rvu,
					    struct cplt_rpm_get_chan_info_req *req,
					    struct cplt_rpm_get_chan_info_rsp *rsp)
{
	u8 chiplet_id, rpm_id, lmac_id;
	unsigned long pf_map;
	u64 lmac_exist;
	u16 base;
	int pf;

	chiplet_id = req->chiplet_id;
	rpm_id = req->rpm_id;
	lmac_id = req->lmac_id;

	if (!rvu->fwdata)
		return false;

	/* Excluding compute chiplet, If no. of chiplets are 2,
	 * RPM2 is fused out, for now consider as 2 chiplets.
	 */
	lmac_exist = rvu->fwdata->csr_rpmx_cmr_num_lmacs[chiplet_id][0];

	if (!(lmac_exist & BIT_ULL(req->lmac_id)))
		return CPLT_AF_ERR_PARAM;

	if (chiplet_id == 0 || chiplet_id == 1)
		base = rvu->hw->cplt_chan_base;
	else
		return CPLT_AF_ERR_PARAM;

	pf_map = cpltlmac_to_pfmap(rvu, chiplet_id, rpm_id, lmac_id);

	pf = find_first_bit(&pf_map, 64);

	rsp->chan_base = base + (CPLT_OFFSET(chiplet_id, rpm_id) +
				 (lmac_id)) * 16;
	rsp->pkind = rvu_npc_get_pkind(rvu, pf);
	rsp->chiplet_id = req->chiplet_id;
	rsp->rpm_id = req->rpm_id;
	rsp->lmac_id = req->lmac_id;

	return 0;
}

int rvu_mbox_handler_cplt_rpm_eb_ready(struct rvu *rvu,
				       struct cplt_rpm_eb_ready_req *req,
				       struct msg_rsp *rsp)
{
	return !rvu->cplt_rpm->ready;
}

static void rvu_cplt_unregister_interrupts_block(struct rvu_block *block,
						 void *data)
{
	(void)block;
	(void)data;
}

static int rvu_cplt_register_interrupts_block(struct rvu_block *block,
					      void *data)
{
	(void)block;
	(void)data;

	return 0;
}

static u16 cpltlmac_id_map(u8 cplt_id, u8 rpm_id, u8 lmac_id)
{
	return (((cplt_id & 0xF) << 12) | ((rpm_id & 0xF) << 8) |
		(lmac_id & 0xFF));
}

static void __rvu_map_cplt_lmac_pf(struct rvu *rvu, int pf, int cplt,
				   int rpm, int lmac)
{
	rvu->cplt_rpm->pf2cpltlmac_map[pf] = cpltlmac_id_map(cplt, rpm, lmac);
	rvu->cplt_rpm->cpltlmac2pf_map[CPLT_OFFSET((cplt - 1), rpm) + lmac] =
		BIT_ULL(pf);

	rvu->cplt_rpm->cplt_mapped_pfs++;
	set_bit(pf, &rvu->cplt_rpm->cplt_pf_notify_bmap);
}

static int cplt_get_lmacid(struct rvu *rvu, int cplt, int iter)
{
	return iter;
}

unsigned long cplt_prepare_lmac_bmap(struct rvu *rvu, u8 max_lmac, int n_cplts)
{
	unsigned long lmac_bmap = 0;
	u16 lmac_exist;
	u8 node, rpm;
	u8 cnt = 0;

	/* Excluding compute chiplet */
	for (node = 1; node <= n_cplts; node++) {
		for (rpm = 0; rpm < rvu->fwdata->num_rpm_in_chiplet; rpm++) {
			lmac_exist = rvu->fwdata->csr_rpmx_cmr_num_lmacs
				[node][rpm] & LMAC_BMAP_MASK;
			if (lmac_exist) {
				lmac_bmap |= (((uint64_t)lmac_exist) <<
					      (cnt * max_lmac));
			}
			cnt++;
		}
	}

	return lmac_bmap;
}

static void cplt_notify_pfs(struct cplt_link_event *event, struct rvu *rvu)
{
	struct cplt_link_user_info *linfo;
	struct cgx_link_info_msg *msg;
	unsigned long pfmap;
	int pfid;

	linfo = &event->link_uinfo;
	pfmap = cpltlmac_to_pfmap(rvu, event->chiplet_id, event->rpm_id,
				  event->lmac_id);

	if (!pfmap) {
		dev_err(rvu->dev, "RPM port%d:%d:%d not mapped with PF\n",
			event->chiplet_id, event->rpm_id, event->lmac_id);
		return;
	}

	do {
		pfid = find_first_bit(&pfmap, 64);
		clear_bit(pfid, &pfmap);

		/* check if notification is enabled */
		if (!test_bit(pfid, &rvu->cplt_rpm->cplt_pf_notify_bmap)) {
			dev_info(rvu->dev, "cplt %d: rpm %d: lmac %d "
				 "Link status %s\n", event->chiplet_id,
				 event->rpm_id, event->lmac_id,
				 linfo->link_up ? "UP" : "DOWN");
			continue;
		}

		mutex_lock(&rvu->mbox_lock);

		/* Send mbox message to PF */
		msg = otx2_mbox_alloc_msg_cgx_link_event(rvu, pfid);
		if (!msg) {
			mutex_unlock(&rvu->mbox_lock);
			continue;
		}

		memcpy(&msg->link_info, (struct cgx_link_user_info *)linfo,
		       sizeof(struct cgx_link_user_info));

		otx2_mbox_wait_for_zero(&rvu->afpf_wq_info.mbox_up, pfid);

		otx2_mbox_msg_send_up(&rvu->afpf_wq_info.mbox_up, pfid);

		otx2_mbox_wait_for_rsp(&rvu->afpf_wq_info.mbox_up, pfid);

		mutex_unlock(&rvu->mbox_lock);

	} while (pfmap);
}

static void cplt_evhandler_task(struct work_struct *work)
{
	struct rvu_cplt_rpm *cplt_rpm = container_of(work, struct rvu_cplt_rpm,
						     cplt_evh_work);
	struct rvu *rvu = cplt_rpm->rvu;
	struct cplt_evq_entry *qentry;
	struct cplt_link_event *event;
	unsigned long flags;

	do {
		/* Dequeue an event */
		spin_lock_irqsave(&rvu->cplt_rpm->cplt_evq_lock, flags);
		qentry = list_first_entry_or_null(&rvu->cplt_rpm->cplt_evq_head,
						  struct cplt_evq_entry,
						  evq_node);
		if (qentry)
			list_del(&qentry->evq_node);
		spin_unlock_irqrestore(&rvu->cplt_rpm->cplt_evq_lock, flags);
		if (!qentry)
			break; /* nothing more to process */

		event = &qentry->link_event;

		/* process event */
		cplt_notify_pfs(event, rvu);
		kfree(qentry);
	} while (1);
}

static int cplt_lmac_event_handler_init(struct rvu *rvu)
{
	spin_lock_init(&rvu->cplt_rpm->cplt_evq_lock);
	INIT_LIST_HEAD(&rvu->cplt_rpm->cplt_evq_head);
	INIT_WORK(&rvu->cplt_rpm->cplt_evh_work, cplt_evhandler_task);
	rvu->cplt_rpm->cplt_evh_wq = alloc_workqueue("rvu_evh_wq", 0, 0);
	if (!rvu->cplt_rpm->cplt_evh_wq) {
		dev_err(rvu->dev, "alloc workqueue failed");
		return -ENOMEM;
	}

	return 0;
}

static int rvu_map_cplt_rpm_lmac_pf(struct rvu *rvu)
{
	int cplt, lmac, iter, lmac_cnt;
	int pf = PF_CPLTMAP_BASE;
	unsigned long lmac_bmap;
	u32 num_rpm_in_chiplet;
	u8 lmac_in_n1_rpm0;
	u8 cplt_cnt_max;
	u64 rpmx_const;
	int size;

	cplt_cnt_max = rvu->cplt_rpm->cplt_cnt_max;
	num_rpm_in_chiplet = rvu->fwdata->num_rpm_in_chiplet;

	if (!num_rpm_in_chiplet)
		return -EINVAL;

	/* Assume all RPMs has same max number of LMACs */
	lmac_in_n1_rpm0 = FIELD_GET(GENMASK_ULL(31, 24),
				    rvu->fwdata->csr_rpmx_const[1][0]);

	rvu->hw->lmac_per_cplt = lmac_in_n1_rpm0;
	/* Alloc map table */
	size = (cplt_cnt_max * num_rpm_in_chiplet *
		rvu->hw->lmac_per_cplt) * sizeof(u16);
	rvu->cplt_rpm->pf2cpltlmac_map = devm_kmalloc(rvu->dev, size,
						      GFP_KERNEL);
	if (!rvu->cplt_rpm->pf2cpltlmac_map)
		return -ENOMEM;

	/* Initialize all entries with an invalid cplt and lmac id */
	memset(rvu->cplt_rpm->pf2cpltlmac_map, 0xFFFF, size);

	/* Reverse map table */
	rvu->cplt_rpm->cpltlmac2pf_map =
		devm_kzalloc(rvu->dev,
			     cplt_cnt_max * num_rpm_in_chiplet *
			     rvu->hw->lmac_per_cplt * sizeof(u64),
			     GFP_KERNEL);
	if (!rvu->cplt_rpm->cpltlmac2pf_map)
		return -ENOMEM;

	rvu->cplt_rpm->cplt_mapped_pfs = 0;
	lmac_bmap = cplt_prepare_lmac_bmap(rvu, lmac_in_n1_rpm0, cplt_cnt_max);
	rvu->cplt_rpm->lmac_bmap = lmac_bmap;
	for (cplt = 1; cplt <= cplt_cnt_max; cplt++) {
		for (int rpm = 0; rpm < num_rpm_in_chiplet; rpm++) {
			rpmx_const = rvu->fwdata->csr_rpmx_const[cplt][rpm];
			lmac_cnt = FIELD_GET(GENMASK_ULL(31, 24), rpmx_const);
			for_each_set_bit(iter, &lmac_bmap, lmac_cnt) {
				lmac = cplt_get_lmacid(rvu, cplt, iter);
				__rvu_map_cplt_lmac_pf(rvu, pf, cplt, rpm,
						       lmac);
				pf++;
			}
			lmac_bmap >>= lmac_in_n1_rpm0;
		}
	}
	return 0;
}

static int rvu_cplt_init(struct rvu *rvu)
{
	struct rvu_cplt_rpm *cplt_rpm_data;
	int err;

	if (!rvu->fwdata)
		return -EINVAL;

	cplt_rpm_data = kzalloc(sizeof(*cplt_rpm_data), GFP_KERNEL);
	if (!cplt_rpm_data)
		return -ENOMEM;

	rvu->cplt_rpm = cplt_rpm_data;
	if (!rvu->fwdata->csr_rpmx_cmr_num_lmacs[2][0])
		rvu->cplt_rpm->cplt_cnt_max = 1;
	else
		rvu->cplt_rpm->cplt_cnt_max = NODE_MAX - 1;

	cplt_rpm_data->rvu = rvu;

	/* Map CPLT LMAC interfaces to CPLT PFs */
	err = rvu_map_cplt_rpm_lmac_pf(rvu);
	if (err)
		return err;

	/* Register for RPM events */
	err = cplt_lmac_event_handler_init(rvu);
	if (err)
		return err;

	rvu->cplt_rpm->ready = 0;

	mutex_init(&rvu->cplt_rpm->cplt_cfg_lock);

	return 0;
}

static int cplt_exit(struct rvu *rvu)
{
	return 0;
}

static int rvu_cplt_init_block(struct rvu_block *block, void *data)
{
	struct rvu *rvu = block->rvu;

	if (!data)
		return -EINVAL;

	return rvu_cplt_init(rvu);
}

static void rvu_cplt_freemem_block(struct rvu_block *block, void *data)
{
	(void)block;
	(void)data;

	/* Free up resources related to CPLT etc.. */
}

static int rvu_setup_cplt_hw_resource(struct rvu_block *block, void *data)
{
	struct cplt_drvdata *drvdata = data;
	struct rvu *rvu = block->rvu;
	struct rvu_hwinfo *hw = rvu->hw;
	int blkid, blkaddr;

	blkid = drvdata->res_idx;
	blkaddr = blkid ? BLKADDR_RFOE1 : BLKADDR_RFOE0;
	block = &hw->block[blkaddr];

	if (!block->implemented)
		return 0;
	block->addr = blkaddr;
	block->type = BLKTYPE_RFOE;
	block->rvu = rvu;
	sprintf(block->name, "RFOE%d", blkid);
	block->multislot = true;

	return 0;
}

static int rvu_cplt_mbox_handler(struct otx2_mbox *mbox, int devid,
				 struct mbox_msghdr *req)
{
	struct rvu *rvu = pci_get_drvdata(mbox->pdev);
	int _id = req->id;

	switch (_id) {
	#define M(_name, _id, _fn_name, _req_type, _rsp_type)		\
	{								\
	case _id: {							\
		struct _rsp_type *rsp;					\
		int err;						\
									\
		rsp = (struct _rsp_type *)otx2_mbox_alloc_msg(		\
			mbox, devid,					\
			sizeof(struct _rsp_type));			\
		if (rsp) {						\
			rsp->hdr.id = _id;				\
			rsp->hdr.sig = OTX2_MBOX_RSP_SIG;		\
			rsp->hdr.pcifunc = req->pcifunc;		\
			rsp->hdr.rc = 0;				\
		}							\
									\
		err = rvu_mbox_handler_ ## _fn_name(rvu,		\
						    (struct _req_type *)req, \
						    rsp);		\
		if (rsp && err)						\
			rsp->hdr.rc = err;				\
									\
		trace_otx2_msg_process(mbox->pdev, _id, err, req->pcifunc); \
		return rsp ? err : -ENOMEM;				\
	}								\
	}
		MBOX_EBLOCK_CPLT_MESSAGES

	default :
		otx2_reply_invalid_msg(mbox, devid, req->pcifunc, req->id);
		return -ENODEV;
	}

	return 0;
}

static void *rvu_cplt_probe(struct rvu *rvu, int blkaddr)
{
	struct cplt_drvdata *data;
	static int res_idx;

	switch (blkaddr) {
	case BLKADDR_RFOE0:
		data = devm_kzalloc(rvu->dev, sizeof(struct cplt_drvdata),
				    GFP_KERNEL);
		if (!data)
			return ERR_PTR(-ENOMEM);
		data->res_idx = res_idx++;
		break;
	default:
		data = NULL;
	}

	return data;
}

static void rvu_cplt_remove(struct rvu_block *hwblock, void *data)
{
	cplt_exit(hwblock->rvu);
	devm_kfree(hwblock->rvu->dev, data);
}

struct mbox_op cplt_mbox_op = {
	.start = 0xD000,
	.end = 0xDFFF,
	.handler = rvu_cplt_mbox_handler,
};

static struct rvu_eblock_driver_ops cplt_ops = {
	.probe	= rvu_cplt_probe,
	.remove	= rvu_cplt_remove,
	.init	= rvu_cplt_init_block,
	.setup	= rvu_setup_cplt_hw_resource,
	.free	= rvu_cplt_freemem_block,
	.register_interrupt = rvu_cplt_register_interrupts_block,
	.unregister_interrupt = rvu_cplt_unregister_interrupts_block,
	.mbox_op = &cplt_mbox_op,
};

void cplt_eb_module_init(void)
{
	rvu_eblock_register_driver(&cplt_ops);
}

void cplt_eb_module_exit(void)
{
	rvu_eblock_unregister_driver(&cplt_ops);
}
