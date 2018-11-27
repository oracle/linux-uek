// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/delay.h>
#include "cpt8x_vf.h"

static void cptvf_send_msg_to_pf(struct cpt_vf *cptvf, struct cpt_mbox *mbx)
{
	/* Writing mbox(1) causes interrupt */
	writeq(mbx->msg, cptvf->reg_base + CPT_VFX_PF_MBOXX(0, 0));
	writeq(mbx->data, cptvf->reg_base + CPT_VFX_PF_MBOXX(0, 1));
}

/* ACKs PF's mailbox message
 */
void cptvf_mbox_send_ack(struct cpt_vf *cptvf, struct cpt_mbox *mbx)
{
	mbx->msg = CPT_MSG_ACK;
	cptvf_send_msg_to_pf(cptvf, mbx);
}

/* NACKs PF's mailbox message that VF is not able to
 * complete the action
 */
void cptvf_mbox_send_nack(struct cpt_vf *cptvf, struct cpt_mbox *mbx)
{
	mbx->msg = CPT_MSG_NACK;
	cptvf_send_msg_to_pf(cptvf, mbx);
}

/* Interrupt handler to handle mailbox messages from VFs */
void cptvf_handle_mbox_intr(struct cpt_vf *cptvf)
{
	struct cpt_mbox mbx = {};

	/*
	 * MBOX[0] contains msg
	 * MBOX[1] contains data
	 */
	mbx.msg  = readq(cptvf->reg_base + CPT_VFX_PF_MBOXX(0, 0));
	mbx.data = readq(cptvf->reg_base + CPT_VFX_PF_MBOXX(0, 1));

	if (cpt_is_dbg_level_en(CPT_DBG_MBOX_MSGS))
		dump_mbox_msg(&cptvf->pdev->dev, &mbx, -1);

	switch (mbx.msg) {
	case CPT_MSG_VF_UP:
		cptvf->pf_acked = true;
		cptvf->num_vfs = mbx.data;
		break;
	case CPT_MSG_READY:
		cptvf->pf_acked = true;
		cptvf->vfid = mbx.data;
		dev_dbg(&cptvf->pdev->dev, "Received VFID %d\n", cptvf->vfid);
		break;
	case CPT_MSG_QBIND_GRP:
		cptvf->pf_acked = true;
		cptvf->vftype = mbx.data;
		dev_dbg(&cptvf->pdev->dev, "VF %d type %s group %d\n",
			cptvf->vfid, ((mbx.data == SE_TYPES) ? "SE" : "AE"),
			cptvf->vfgrp);
		break;
	case CPT_MSG_ACK:
		cptvf->pf_acked = true;
		break;
	case CPT_MSG_NACK:
		cptvf->pf_nacked = true;
		break;
	default:
		dev_err(&cptvf->pdev->dev, "Invalid msg from PF, msg 0x%llx\n",
			mbx.msg);
		break;
	}
}

static int cptvf_send_msg_to_pf_timeout(struct cpt_vf *cptvf,
					struct cpt_mbox *mbx)
{
	int timeout = CPT_MBOX_MSG_TIMEOUT;
	int sleep = 10;

	cptvf->pf_acked = false;
	cptvf->pf_nacked = false;
	cptvf_send_msg_to_pf(cptvf, mbx);
	/* Wait for previous message to be acked, timeout 2sec */
	while (!cptvf->pf_acked) {
		if (cptvf->pf_nacked)
			return -EINVAL;
		msleep(sleep);
		if (cptvf->pf_acked)
			break;
		timeout -= sleep;
		if (!timeout) {
			dev_err(&cptvf->pdev->dev, "PF didn't ack to mbox msg %llx from VF%u\n",
				(mbx->msg & 0xFF), cptvf->vfid);
			return -EBUSY;
		}
	}

	return 0;
}

/*
 * Checks if VF is able to comminicate with PF
 * and also gets the CPT number this VF is associated to.
 */
int cptvf_check_pf_ready(struct cpt_vf *cptvf)
{
	struct pci_dev *pdev = cptvf->pdev;
	struct cpt_mbox mbx = {};

	mbx.msg = CPT_MSG_READY;
	if (cptvf_send_msg_to_pf_timeout(cptvf, &mbx)) {
		dev_err(&pdev->dev, "PF didn't respond to ready msg\n");
		return -EBUSY;
	}

	return 0;
}

/*
 * Communicate VQs size to PF to program CPT(0)_PF_Q(0-15)_CTL of the VF.
 * Must be ACKed.
 */
int cptvf_send_vq_size_msg(struct cpt_vf *cptvf)
{
	struct pci_dev *pdev = cptvf->pdev;
	struct cpt_mbox mbx = {};

	mbx.msg = CPT_MSG_QLEN;
	mbx.data = cptvf->qsize;
	if (cptvf_send_msg_to_pf_timeout(cptvf, &mbx)) {
		dev_err(&pdev->dev, "PF didn't respond to vq size msg\n");
		return -EBUSY;
	}

	return 0;
}

/*
 * Communicate VF group required to PF and get the VQ binded to that group
 */
int cptvf_send_vf_to_grp_msg(struct cpt_vf *cptvf, int group)
{
	struct pci_dev *pdev = cptvf->pdev;
	struct cpt_mbox mbx = {};

	mbx.msg = CPT_MSG_QBIND_GRP;
	/* Convey group of the VF */
	mbx.data = group;
	if (cptvf_send_msg_to_pf_timeout(cptvf, &mbx)) {
		dev_err(&pdev->dev, "PF didn't respond to group msg\n");
		return -EBUSY;
	}

	cptvf->vfgrp = group;
	return 0;
}

/*
 * Communicate VF group required to PF and get the VQ binded to that group
 */
int cptvf_send_vf_priority_msg(struct cpt_vf *cptvf)
{
	struct pci_dev *pdev = cptvf->pdev;
	struct cpt_mbox mbx = {};

	mbx.msg = CPT_MSG_VQ_PRIORITY;
	/* Convey group of the VF */
	mbx.data = cptvf->priority;
	if (cptvf_send_msg_to_pf_timeout(cptvf, &mbx)) {
		dev_err(&pdev->dev, "PF didn't respond to priority msg\n");
		return -EBUSY;
	}
	return 0;
}

/*
 * Communicate to PF that VF is UP and running
 */
int cptvf_send_vf_up(struct cpt_vf *cptvf)
{
	struct pci_dev *pdev = cptvf->pdev;
	struct cpt_mbox mbx = {};

	mbx.msg = CPT_MSG_VF_UP;
	if (cptvf_send_msg_to_pf_timeout(cptvf, &mbx)) {
		dev_err(&pdev->dev, "PF didn't respond to up msg\n");
		return -EBUSY;
	}

	return 0;
}

/*
 * Communicate to PF that VF is DOWN and running
 */
int cptvf_send_vf_down(struct cpt_vf *cptvf)
{
	struct pci_dev *pdev = cptvf->pdev;
	struct cpt_mbox mbx = {};

	mbx.msg = CPT_MSG_VF_DOWN;
	if (cptvf_send_msg_to_pf_timeout(cptvf, &mbx)) {
		dev_err(&pdev->dev, "PF didn't respond to DOWN msg\n");
		return -EBUSY;
	}

	return 0;
}
