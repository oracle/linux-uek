// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "rvu_reg.h"
#include "cpt9x_mbox_common.h"

static int forward_to_af(struct cptpf_dev *cptpf, struct cptvf_info *vf,
			 struct mbox_msghdr *req, int size)
{
	struct mbox_msghdr *msg;
	int ret = 0;

	msg = otx2_mbox_alloc_msg(&cptpf->afpf_mbox, 0, size);
	if (msg == NULL)
		return -ENOMEM;

	memcpy((uint8_t *)msg + sizeof(struct mbox_msghdr),
	       (uint8_t *)req + sizeof(struct mbox_msghdr), size);
	msg->id = req->id;
	msg->pcifunc = req->pcifunc;
	msg->sig = req->sig;
	msg->ver = req->ver;

	otx2_mbox_msg_send(&cptpf->afpf_mbox, 0);
	ret = otx2_mbox_wait_for_rsp(&cptpf->afpf_mbox, 0);
	if (ret == -EIO) {
		dev_err(&cptpf->pdev->dev, "RVU MBOX timeout.\n");
		goto error;
	} else if (ret) {
		dev_err(&cptpf->pdev->dev, "RVU MBOX error: %d.\n", ret);
		ret = -EFAULT;
		goto error;
	}
error:
	return ret;
}

static int check_attach_rsrcs_req(struct cptpf_dev *cptpf,
				  struct cptvf_info *vf,
				  struct mbox_msghdr *req, int size)
{
	struct rsrc_attach *rsrc_req = (struct rsrc_attach *)req;

	mutex_lock(&cptpf->vf_limits.lock);

	if (rsrc_req->sso > 0 || rsrc_req->ssow > 0 || rsrc_req->npalf > 0 ||
	    rsrc_req->timlfs > 0 || rsrc_req->nixlf > 0 ||
	    rsrc_req->cptlfs > cptpf->vf_limits.cpt->a[vf->vf_id].val) {
		dev_err(&cptpf->pdev->dev,
			"Invalid ATTACH_RESOURCES request from %s\n",
			dev_name(&vf->vf_dev->dev));

		mutex_unlock(&cptpf->vf_limits.lock);
		return -EINVAL;
	}

	mutex_unlock(&cptpf->vf_limits.lock);
	return forward_to_af(cptpf, vf, req, size);
}

static int reply_free_rsrc_cnt(struct cptpf_dev *cptpf, struct cptvf_info *vf,
			       struct mbox_msghdr *req)
{
	struct free_rsrcs_rsp *rsp;

	rsp = (struct free_rsrcs_rsp *) otx2_mbox_alloc_msg(&cptpf->vfpf_mbox,
							    vf->vf_id,
							    sizeof(*rsp));
	if (rsp == NULL)
		return -ENOMEM;

	memset(rsp + sizeof(*req), 0, sizeof(*rsp) - sizeof(*req));
	rsp->hdr.id = MBOX_MSG_FREE_RSRC_CNT;
	rsp->hdr.pcifunc = req->pcifunc;
	rsp->hdr.sig = OTX2_MBOX_RSP_SIG;

	mutex_lock(&cptpf->vf_limits.lock);
	rsp->cpt = cptpf->vf_limits.cpt->a[vf->vf_id].val;
	mutex_unlock(&cptpf->vf_limits.lock);
	return 0;
}

static int reply_ready_msg(struct cptpf_dev *cptpf, struct cptvf_info *vf,
			   struct mbox_msghdr *req)
{
	struct mbox_msghdr *rsp;

	rsp = otx2_mbox_alloc_msg(&cptpf->vfpf_mbox, vf->vf_id, sizeof(*rsp));
	if (!rsp)
		return -ENOMEM;

	rsp->id = MBOX_MSG_READY;
	rsp->sig = OTX2_MBOX_RSP_SIG;
	rsp->pcifunc = req->pcifunc;

	return 0;
}

static int reply_eng_grp_num_msg(struct cptpf_dev *cptpf,
				 struct cptvf_info *vf,
				 struct mbox_msghdr *req)
{
	struct eng_grp_num_msg *grp_req = (struct eng_grp_num_msg *)req;
	struct engine_group_info *grp;
	struct eng_grp_num_rsp *rsp;
	int i;

	rsp = (struct eng_grp_num_rsp *)
			      otx2_mbox_alloc_msg(&cptpf->vfpf_mbox, vf->vf_id,
						  sizeof(*rsp));
	if (!rsp)
		return -ENOMEM;

	rsp->hdr.id = MBOX_MSG_GET_ENG_GRP_NUM;
	rsp->hdr.sig = OTX2_MBOX_RSP_SIG;
	rsp->hdr.pcifunc = req->pcifunc;
	rsp->eng_type = grp_req->eng_type;
	rsp->eng_grp_num = INVALID_CRYPTO_ENG_GRP;

	mutex_lock(&cptpf->eng_grps.lock);

	switch (grp_req->eng_type) {
	case SE_TYPES:
		/* Find engine group for kernel crypto functionality, select
		 * first engine group which is configured and has only
		 * SE engines attached
		 */
		for (i = 0; i < CPT_MAX_ENGINE_GROUPS; i++) {
			grp = &cptpf->eng_grps.grp[i];
			if (!grp->is_enabled)
				continue;

			if (cpt_eng_grp_has_eng_type(grp, SE_TYPES) &&
			    !cpt_eng_grp_has_eng_type(grp, IE_TYPES) &&
			    !cpt_eng_grp_has_eng_type(grp, AE_TYPES)) {
				rsp->eng_grp_num = i;
				break;
			}
		}
	break;

	case AE_TYPES:
	case IE_TYPES:
		for (i = 0; i < CPT_MAX_ENGINE_GROUPS; i++) {
			grp = &cptpf->eng_grps.grp[i];
			if (!grp->is_enabled)
				continue;

			if (cpt_eng_grp_has_eng_type(grp, grp_req->eng_type)) {
				rsp->eng_grp_num = i;
				break;
			}
		}
	break;

	default:
		dev_err(&cptpf->pdev->dev, "Invalid engine type %d",
			grp_req->eng_type);
	}

	mutex_unlock(&cptpf->eng_grps.lock);
	return 0;
}

static int cptpf_handle_vf_req(struct cptpf_dev *cptpf, struct cptvf_info *vf,
			       struct mbox_msghdr *req, int size)
{
	int err = 0;

	/* Check if msg is valid, if not reply with an invalid msg */
	if (req->sig != OTX2_MBOX_REQ_SIG)
		return otx2_reply_invalid_msg(&cptpf->vfpf_mbox, vf->vf_id,
					      req->pcifunc, req->id);
	switch (req->id) {
	case MBOX_MSG_READY:
		err = reply_ready_msg(cptpf, vf, req);
		break;

	case MBOX_MSG_FREE_RSRC_CNT:
		err = reply_free_rsrc_cnt(cptpf, vf, req);
		break;

	case MBOX_MSG_ATTACH_RESOURCES:
		err = check_attach_rsrcs_req(cptpf, vf, req, size);
		break;

	case MBOX_MSG_GET_ENG_GRP_NUM:
		err = reply_eng_grp_num_msg(cptpf, vf, req);
		break;

	default:
		err = forward_to_af(cptpf, vf, req, size);
		break;
	}

	return err;
}

int cptpf_send_crypto_eng_grp_msg(struct cptpf_dev *cptpf, int crypto_eng_grp)
{
	struct cpt_set_crypto_grp_req_msg *req;
	struct pci_dev *pdev = cptpf->pdev;
	int tmp_crypto_eng_grp;
	int ret = 0;

	req = (struct cpt_set_crypto_grp_req_msg *)
			otx2_mbox_alloc_msg_rsp(&cptpf->afpf_mbox, 0,
						sizeof(*req),
						sizeof(struct msg_rsp));
	if (req == NULL) {
		dev_err(&pdev->dev, "RVU MBOX failed to get message.\n");
		ret = -EFAULT;
		goto error;
	}

	req->hdr.id = MBOX_MSG_CPT_SET_CRYPTO_GRP;
	req->hdr.sig = OTX2_MBOX_REQ_SIG;
	req->hdr.pcifunc = RVU_PFFUNC(cptpf->pf_id, 0);
	req->crypto_eng_grp = crypto_eng_grp;

	tmp_crypto_eng_grp = cptpf->crypto_eng_grp;
	ret = cpt_send_mbox_msg(pdev);
	if (ret)
		goto error;

	if (!cptpf->crypto_eng_grp) {
		cptpf->crypto_eng_grp = tmp_crypto_eng_grp;
		ret = -EINVAL;
	}
		cptpf->crypto_eng_grp = crypto_eng_grp;
error:
	return ret;
}

irqreturn_t cptpf_afpf_mbox_intr(int irq, void *arg)
{
	struct cptpf_dev *cptpf = (struct cptpf_dev *) arg;
	u64 intr;

	/* Read the interrupt bits */
	intr = cpt_read64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_INT);

	if (intr & 0x1ULL) {
		/* Schedule work queue function to process the MBOX request */
		queue_work(cptpf->afpf_mbox_wq, &cptpf->afpf_mbox_work);
		/* Clear and ack the interrupt */
		cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_INT,
			    0x1ULL);
	}
	return IRQ_HANDLED;
}

irqreturn_t cptpf_vfpf_mbox_intr(int irq, void *arg)
{
	struct cptpf_dev *cptpf = (struct cptpf_dev *) arg;
	struct cptvf_info *vf;
	int i, vf_idx;
	u64 intr;

	/* Check which VF has raised an interrupt and schedule
	 * corresponding work queue to process the messages
	 */
	for (i = 0; i < 2; i++) {
		/* Read the interrupt bits */
		intr = cpt_read64(cptpf->reg_base, BLKADDR_RVUM, 0,
				  RVU_PF_VFPF_MBOX_INTX(i));

		for (vf_idx = i * 64; vf_idx < cptpf->enabled_vfs; vf_idx++) {
			vf = &cptpf->vf[vf_idx];
			if (intr & (1ULL << vf->intr_idx)) {
				queue_work(cptpf->vfpf_mbox_wq,
					   &vf->vfpf_mbox_work);
				/* Clear the interrupt */
				cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
					    RVU_PF_VFPF_MBOX_INTX(i),
					    BIT_ULL(vf->intr_idx));
			}
		}
	}

	return IRQ_HANDLED;
}

void cptpf_afpf_mbox_handler(struct work_struct *work)
{
	struct cpt_set_crypto_grp_req_msg *rsp_set_grp;
	struct cpt_rd_wr_reg_msg *rsp_rd_wr;
	struct otx2_mbox *afpf_mbox;
	struct otx2_mbox *vfpf_mbox;
	struct mbox_hdr *rsp_hdr;
	struct mbox_msghdr *msg;
	struct mbox_msghdr *fwd;
	struct cptpf_dev *cptpf;
	int offset, size;
	int vf_id, i;

	/* Read latest mbox data */
	smp_rmb();

	cptpf = container_of(work, struct cptpf_dev, afpf_mbox_work);
	afpf_mbox = &cptpf->afpf_mbox;
	vfpf_mbox = &cptpf->vfpf_mbox;
	rsp_hdr = (struct mbox_hdr *)(afpf_mbox->dev->mbase +
		   afpf_mbox->rx_start);
	if (rsp_hdr->num_msgs == 0)
		return;
	offset = ALIGN(sizeof(struct mbox_hdr), MBOX_MSG_ALIGN);

	for (i = 0; i < rsp_hdr->num_msgs; i++) {
		msg = (struct mbox_msghdr *)(afpf_mbox->dev->mbase +
					     afpf_mbox->rx_start + offset);
		size = msg->next_msgoff - offset;

		if (msg->id >= MBOX_MSG_MAX) {
			dev_err(&cptpf->pdev->dev,
				"MBOX msg with unknown ID %d\n", msg->id);
			goto error;
		}

		if (msg->sig != OTX2_MBOX_RSP_SIG) {
			dev_err(&cptpf->pdev->dev,
				"MBOX msg with wrong signature %x, ID %d\n",
				msg->sig, msg->id);
			goto error;
		}

		offset = msg->next_msgoff;
		vf_id = (msg->pcifunc >> RVU_PFVF_FUNC_SHIFT) &
			 RVU_PFVF_FUNC_MASK;
		if (vf_id > 0) {
			vf_id--;
			if (vf_id >= cptpf->enabled_vfs) {
				dev_err(&cptpf->pdev->dev,
					"MBOX msg to unknown VF: %d >= %d\n",
					vf_id, cptpf->enabled_vfs);
				goto error;
			}
			fwd = otx2_mbox_alloc_msg(vfpf_mbox, vf_id, size);
			if (!fwd) {
				dev_err(&cptpf->pdev->dev,
					"Forwarding to VF%d failed.\n", vf_id);
				goto error;
			}
			memcpy((uint8_t *)fwd + sizeof(struct mbox_msghdr),
			       (uint8_t *)msg + sizeof(struct mbox_msghdr),
			       size);
			fwd->id = msg->id;
			fwd->pcifunc = msg->pcifunc;
			fwd->sig = msg->sig;
			fwd->ver = msg->ver;
			fwd->rc = msg->rc;
		} else {
			if (cpt_is_dbg_level_en(CPT_DBG_MBOX_MSGS))
				cpt9x_dump_mbox_msg(&cptpf->pdev->dev, msg,
						    size);
			switch (msg->id) {
			case MBOX_MSG_READY:
				cptpf->pf_id =
					(msg->pcifunc >> RVU_PFVF_PF_SHIFT) &
					RVU_PFVF_PF_MASK;
				break;

			case MBOX_MSG_FREE_RSRC_CNT:
				memcpy(&cptpf->limits, msg,
				       sizeof(struct free_rsrcs_rsp));
				break;

			case MBOX_MSG_CPT_RD_WR_REGISTER:
				rsp_rd_wr = (struct cpt_rd_wr_reg_msg *) msg;
				if (msg->rc) {
					dev_err(&cptpf->pdev->dev,
						"Reg %llx rd/wr(%d) failed %d",
						rsp_rd_wr->reg_offset,
						rsp_rd_wr->is_write,
						msg->rc);
					continue;
				}

				if (!rsp_rd_wr->is_write)
					*rsp_rd_wr->ret_val = rsp_rd_wr->val;
				break;

			case MBOX_MSG_CPT_SET_CRYPTO_GRP:
				rsp_set_grp =
				    (struct cpt_set_crypto_grp_req_msg *) msg;
				if (msg->rc) {
					dev_err(&cptpf->pdev->dev,
						"Crypto grp %d set failed %d",
						rsp_set_grp->crypto_eng_grp,
						msg->rc);
					cptpf->crypto_eng_grp = 0;
					continue;
				} else
					cptpf->crypto_eng_grp = 1;
				break;

			default:
				dev_err(&cptpf->pdev->dev,
					"Unsupported msg %d received.\n",
					msg->id);
				break;
			}
		}
error:
		afpf_mbox->dev->msgs_acked++;
	}

	otx2_mbox_reset(afpf_mbox, 0);
}

void cptpf_vfpf_mbox_handler(struct work_struct *work)
{
	struct cptvf_info *vf = container_of(work, struct cptvf_info,
					      vfpf_mbox_work);
	struct cptpf_dev *cptpf = vf->cptpf;
	struct otx2_mbox *mbox = &cptpf->vfpf_mbox;
	struct otx2_mbox_dev *mdev = &mbox->dev[vf->vf_id];
	struct mbox_hdr *req_hdr;
	struct mbox_msghdr *msg;
	int offset, id, err;

	/* sync with mbox memory region */
	rmb();

	/* Process received mbox messages */
	req_hdr = (struct mbox_hdr *)(mdev->mbase + mbox->rx_start);
	offset = ALIGN(sizeof(*req_hdr), MBOX_MSG_ALIGN);
	id = 0;
	while (id < req_hdr->num_msgs) {
		while (id < req_hdr->num_msgs) {
			msg = (struct mbox_msghdr *)(mdev->mbase +
						     mbox->rx_start + offset);

			/* Set which VF sent this message based on mbox IRQ */
			msg->pcifunc = ((u16)cptpf->pf_id << RVU_PFVF_PF_SHIFT)
				| ((vf->vf_id + 1) & RVU_PFVF_FUNC_MASK);

			err = cptpf_handle_vf_req(cptpf, vf, msg,
						  msg->next_msgoff - offset);

			/* Behave as the AF, drop the msg if there is
			 * no memory, timeout handling also goes here
			 */
			if (err == -ENOMEM ||
			    err == -EIO)
				break;

			offset = msg->next_msgoff;
			id++;
		}

		/* Send mbox responses to VF */
		if (mdev->num_msgs)
			otx2_mbox_msg_send(mbox, vf->vf_id);
	}
}
