// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "otx2_cpt_mbox_common.h"
#include "rvu_reg.h"

static void dump_mbox_msg(struct mbox_msghdr *msg, int size)
{
	u16 pf_id, vf_id;

	pf_id = (msg->pcifunc >> RVU_PFVF_PF_SHIFT) & RVU_PFVF_PF_MASK;
	vf_id = (msg->pcifunc >> RVU_PFVF_FUNC_SHIFT) & RVU_PFVF_FUNC_MASK;

	pr_debug("MBOX opcode %s received from (PF%d/VF%d), size %d, rc %d",
		 otx2_cpt_get_mbox_opcode_str(msg->id), pf_id, vf_id, size,
		 msg->rc);
	print_hex_dump_debug("", DUMP_PREFIX_OFFSET, 16, 2, msg, size, false);
}

irqreturn_t otx2_cptvf_pfvf_mbox_intr(int __always_unused irq, void *arg)
{
	struct otx2_cptvf_dev *cptvf = arg;
	u64 intr;

	/* Read the interrupt bits */
	intr = otx2_cpt_read64(cptvf->reg_base, BLKADDR_RVUM, 0,
			       OTX2_RVU_VF_INT);

	if (intr & 0x1ULL) {
		/* Schedule work queue function to process the MBOX request */
		queue_work(cptvf->pfvf_mbox_wq, &cptvf->pfvf_mbox_work);
		/* Clear and ack the interrupt */
		otx2_cpt_write64(cptvf->reg_base, BLKADDR_RVUM, 0,
				 OTX2_RVU_VF_INT, 0x1ULL);
	}
	return IRQ_HANDLED;
}

void otx2_cptvf_pfvf_mbox_handler(struct work_struct *work)
{
	struct otx2_cpt_kcrypto_limits_rsp *rsp_limits;
	struct otx2_cpt_eng_grp_num_rsp *rsp_grp;
	struct cpt_rd_wr_reg_msg *rsp_reg;
	struct msix_offset_rsp *rsp_msix;
	struct otx2_cptvf_dev *cptvf;
	struct otx2_mbox *pfvf_mbox;
	struct mbox_hdr *rsp_hdr;
	struct mbox_msghdr *msg;
	int offset, i, j, size;

	/* Read latest mbox data */
	smp_rmb();

	cptvf = container_of(work, struct otx2_cptvf_dev, pfvf_mbox_work);
	pfvf_mbox = &cptvf->pfvf_mbox;
	rsp_hdr = (struct mbox_hdr *)(pfvf_mbox->dev->mbase +
		   pfvf_mbox->rx_start);
	if (rsp_hdr->num_msgs == 0)
		return;
	offset = ALIGN(sizeof(struct mbox_hdr), MBOX_MSG_ALIGN);

	for (i = 0; i < rsp_hdr->num_msgs; i++) {
		msg = (struct mbox_msghdr *)(pfvf_mbox->dev->mbase +
					     pfvf_mbox->rx_start + offset);
		size = msg->next_msgoff - offset;

		if (msg->id >= MBOX_MSG_MAX) {
			dev_err(&cptvf->pdev->dev,
				"MBOX msg with unknown ID %d\n", msg->id);
			goto error;
		}

		if (msg->sig != OTX2_MBOX_RSP_SIG) {
			dev_err(&cptvf->pdev->dev,
				"MBOX msg with wrong signature %x, ID %d\n",
				msg->sig, msg->id);
			goto error;
		}

		dump_mbox_msg(msg, size);

		offset = msg->next_msgoff;
		switch (msg->id) {
		case MBOX_MSG_READY:
			cptvf->vf_id = ((msg->pcifunc >> RVU_PFVF_FUNC_SHIFT)
					& RVU_PFVF_FUNC_MASK) - 1;
			break;

		case MBOX_MSG_ATTACH_RESOURCES:
			/* Check if resources were successfully attached */
			if (!msg->rc)
				cptvf->lfs.are_lfs_attached = 1;
			break;

		case MBOX_MSG_DETACH_RESOURCES:
			/* Check if resources were successfully detached */
			if (!msg->rc)
				cptvf->lfs.are_lfs_attached = 0;
			break;

		case MBOX_MSG_MSIX_OFFSET:
			rsp_msix = (struct msix_offset_rsp *) msg;
			for (j = 0; j < rsp_msix->cptlfs; j++)
				cptvf->lfs.lf[j].msix_offset =
						rsp_msix->cptlf_msixoff[j];

			for (j = 0; j < rsp_msix->cpt1_lfs; j++)
				cptvf->lfs.lf[j].msix_offset =
						rsp_msix->cpt1_lf_msixoff[j];
			break;

		case MBOX_MSG_CPT_RD_WR_REGISTER:
			rsp_reg = (struct cpt_rd_wr_reg_msg *) msg;
			if (msg->rc) {
				dev_err(&cptvf->pdev->dev,
					"Reg %llx rd/wr(%d) failed %d\n",
					rsp_reg->reg_offset, rsp_reg->is_write,
					msg->rc);
				continue;
			}

			if (!rsp_reg->is_write)
				*rsp_reg->ret_val = rsp_reg->val;
			break;

		case MBOX_MSG_GET_ENG_GRP_NUM:
			rsp_grp = (struct otx2_cpt_eng_grp_num_rsp *) msg;
			cptvf->lfs.kcrypto_eng_grp_num = rsp_grp->eng_grp_num;
			break;

		case MBOX_MSG_GET_KCRYPTO_LIMITS:
			rsp_limits = (struct otx2_cpt_kcrypto_limits_rsp *) msg;
			cptvf->lfs.kcrypto_limits = rsp_limits->kcrypto_limits;
			break;

		default:
			dev_err(&cptvf->pdev->dev,
				"Unsupported msg %d received.\n",
				msg->id);
			break;
		}
error:
		pfvf_mbox->dev->msgs_acked++;
	}
	otx2_mbox_reset(pfvf_mbox, 0);
}

int otx2_cptvf_send_eng_grp_num_msg(struct otx2_cptvf_dev *cptvf, int eng_type)
{
	struct otx2_cpt_eng_grp_num_msg *req;
	struct pci_dev *pdev = cptvf->pdev;
	int ret;

	req = (struct otx2_cpt_eng_grp_num_msg *)
		otx2_mbox_alloc_msg_rsp(&cptvf->pfvf_mbox, 0,
				sizeof(*req),
				sizeof(struct otx2_cpt_eng_grp_num_rsp));
	if (req == NULL) {
		dev_err(&pdev->dev, "RVU MBOX failed to get message.\n");
		return -EFAULT;
	}
	req->hdr.id = MBOX_MSG_GET_ENG_GRP_NUM;
	req->hdr.sig = OTX2_MBOX_REQ_SIG;
	req->hdr.pcifunc = OTX2_CPT_RVU_PFFUNC(cptvf->vf_id, 0);
	req->eng_type = eng_type;

	ret = otx2_cpt_send_mbox_msg(pdev);

	return ret;
}

int otx2_cptvf_send_kcrypto_limits_msg(struct otx2_cptvf_dev *cptvf)
{
	struct pci_dev *pdev = cptvf->pdev;
	struct mbox_msghdr *req;
	int ret;

	req = (struct mbox_msghdr *)
		otx2_mbox_alloc_msg_rsp(&cptvf->pfvf_mbox, 0,
				sizeof(*req),
				sizeof(struct otx2_cpt_kcrypto_limits_rsp));
	if (req == NULL) {
		dev_err(&pdev->dev, "RVU MBOX failed to get message.\n");
		return -EFAULT;
	}
	req->id = MBOX_MSG_GET_KCRYPTO_LIMITS;
	req->sig = OTX2_MBOX_REQ_SIG;
	req->pcifunc = OTX2_CPT_RVU_PFFUNC(cptvf->vf_id, 0);

	ret = otx2_cpt_send_mbox_msg(pdev);

	return ret;
}
