// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "cpt_debug.h"
#include "cpt8x_pf.h"

static void cpt_send_msg_to_vf(struct cpt_device *cpt, int vf,
			       struct cpt_mbox *mbx)
{
	/* Writing mbox(0) causes interrupt */
	writeq(mbx->data, cpt->reg_base + CPT_PF_VFX_MBOXX(vf, 1));
	writeq(mbx->msg, cpt->reg_base + CPT_PF_VFX_MBOXX(vf, 0));
}

/* ACKs VF's mailbox message
 * @vf: VF to which ACK to be sent
 */
static void cpt_mbox_send_ack(struct cpt_device *cpt, int vf,
			      struct cpt_mbox *mbx)
{
	mbx->data = 0ull;
	mbx->msg = CPT_MSG_ACK;
	cpt_send_msg_to_vf(cpt, vf, mbx);
}

/* NACKs VF's mailbox message that PF is not able to complete the action */
void cptpf_mbox_send_nack(struct cpt_device *cpt,  int vf,
			  struct cpt_mbox *mbx)
{
	mbx->data = 0ull;
	mbx->msg = CPT_MSG_NACK;
	cpt_send_msg_to_vf(cpt, vf, mbx);
}

static void cpt_clear_mbox_intr(struct cpt_device *cpt, u32 vf)
{
	/* W1C for the VF */
	writeq(1ull << vf, cpt->reg_base + CPT_PF_MBOX_INTX(0));
}

/*
 *  Configure QLEN/Chunk sizes for VF
 */
static void cpt_cfg_qlen_for_vf(struct cpt_device *cpt, int vf, u32 size)
{
	union cptx_pf_qx_ctl pf_qx_ctl;

	pf_qx_ctl.u = readq(cpt->reg_base + CPT_PF_QX_CTL(vf));
	pf_qx_ctl.s.size = size;
	pf_qx_ctl.s.cont_err = true;
	writeq(pf_qx_ctl.u, cpt->reg_base + CPT_PF_QX_CTL(vf));
}

/*
 * Configure VQ priority
 */
static void cpt_cfg_vq_priority(struct cpt_device *cpt, int vf, u32 pri)
{
	union cptx_pf_qx_ctl pf_qx_ctl;

	pf_qx_ctl.u = readq(cpt->reg_base + CPT_PF_QX_CTL(vf));
	pf_qx_ctl.s.pri = pri;
	writeq(pf_qx_ctl.u, cpt->reg_base + CPT_PF_QX_CTL(vf));
}

static int cpt_bind_vq_to_grp(struct cpt_device *cpt, u8 q, u8 grp)
{
	struct device *dev = &cpt->pdev->dev;
	struct engine_group_info *eng_grp;
	union cptx_pf_qx_ctl pf_qx_ctl;
	struct microcode *ucode;

	if (q >= cpt->max_vfs) {
		dev_err(dev, "Requested queue %d is > than maximum avail %d",
			q, cpt->max_vfs);
		return -EINVAL;
	}

	if (grp >= CPT_MAX_ENGINE_GROUPS) {
		dev_err(dev, "Requested group %d is > than maximum avail %d",
			grp, CPT_MAX_ENGINE_GROUPS);
		return -EINVAL;
	}

	eng_grp = &cpt->eng_grps.grp[grp];
	if (!eng_grp->is_enabled) {
		dev_err(dev, "Requested engine group %d is disabled", grp);
		return -EINVAL;
	}

	pf_qx_ctl.u = readq(cpt->reg_base + CPT_PF_QX_CTL(q));
	pf_qx_ctl.s.grp = grp;
	writeq(pf_qx_ctl.u, cpt->reg_base + CPT_PF_QX_CTL(q));

	if (eng_grp->mirror.is_ena)
		ucode = &eng_grp->g->grp[eng_grp->mirror.idx].ucode[0];
	else
		ucode = &eng_grp->ucode[0];

	if (cpt_uc_supports_eng_type(ucode, SE_TYPES))
		return SE_TYPES;
	else if (cpt_uc_supports_eng_type(ucode, AE_TYPES))
		return AE_TYPES;
	else
		return BAD_CPT_VF_TYPE;
}

/* Interrupt handler to handle mailbox messages from VFs */
static void cpt_handle_mbox_intr(struct cpt_device *cpt, int vf)
{
	int vftype = 0;
	struct cpt_mbox mbx = {};
	struct device *dev = &cpt->pdev->dev;
	/*
	 * MBOX[0] contains msg
	 * MBOX[1] contains data
	 */
	mbx.msg  = readq(cpt->reg_base + CPT_PF_VFX_MBOXX(vf, 0));
	mbx.data = readq(cpt->reg_base + CPT_PF_VFX_MBOXX(vf, 1));

	if (cpt_is_dbg_level_en(CPT_DBG_MBOX_MSGS))
		dump_mbox_msg(&cpt->pdev->dev, &mbx, vf);

	switch (mbx.msg) {
	case CPT_MSG_VF_UP:
		try_module_get(THIS_MODULE);
		mbx.msg  = CPT_MSG_VF_UP;
		mbx.data = cpt->vfs_enabled;
		cpt_send_msg_to_vf(cpt, vf, &mbx);
		break;
	case CPT_MSG_READY:
		mbx.msg  = CPT_MSG_READY;
		mbx.data = vf;
		cpt_send_msg_to_vf(cpt, vf, &mbx);
		break;
	case CPT_MSG_VF_DOWN:
		/* First msg in VF teardown sequence */
		module_put(THIS_MODULE);
		cpt_mbox_send_ack(cpt, vf, &mbx);
		break;
	case CPT_MSG_QLEN:
		cpt_cfg_qlen_for_vf(cpt, vf, mbx.data);
		cpt_mbox_send_ack(cpt, vf, &mbx);
		break;
	case CPT_MSG_QBIND_GRP:
		vftype = cpt_bind_vq_to_grp(cpt, vf, (u8)mbx.data);
		if ((vftype != AE_TYPES) && (vftype != SE_TYPES)) {
			dev_err(dev, "VF%d binding to eng group %llu failed",
				vf, mbx.data);
			cptpf_mbox_send_nack(cpt, vf, &mbx);
		} else {
			mbx.msg = CPT_MSG_QBIND_GRP;
			mbx.data = vftype;
			cpt_send_msg_to_vf(cpt, vf, &mbx);
		}
		break;
	case CPT_MSG_PF_TYPE:
		mbx.msg = CPT_MSG_PF_TYPE;
		mbx.data = cpt->pf_type;
		cpt_send_msg_to_vf(cpt, vf, &mbx);
		break;
	case CPT_MSG_VQ_PRIORITY:
		cpt_cfg_vq_priority(cpt, vf, mbx.data);
		cpt_mbox_send_ack(cpt, vf, &mbx);
		break;
	default:
		dev_err(&cpt->pdev->dev, "Invalid msg from VF%d, msg 0x%llx\n",
			vf, mbx.msg);
		break;
	}
}

void cpt_mbox_intr_handler (struct cpt_device *cpt, int mbx)
{
	u64 intr;
	u8  vf;

	intr = readq(cpt->reg_base + CPT_PF_MBOX_INTX(0));
	if (cpt_is_dbg_level_en(CPT_DBG_MBOX_MSGS))
		dev_info(&cpt->pdev->dev,
			 "PF interrupt mbox%d mask 0x%llx\n", mbx, intr);
	for (vf = 0; vf < cpt->max_vfs; vf++) {
		if (intr & (1ULL << vf)) {
			cpt_handle_mbox_intr(cpt, vf);
			cpt_clear_mbox_intr(cpt, vf);
		}
	}
}
