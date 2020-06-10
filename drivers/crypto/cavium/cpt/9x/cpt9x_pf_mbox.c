// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "cpt9x_mbox_common.h"
#include "otx2_reg.h"
#include "rvu_reg.h"

/* Fastpath ipsec opcode with inplace processing */
#define CPT_INLINE_RX_OPCODE  (0x26 | (1 << 6))
/*
 * CPT PF driver version, It will be incremented by 1 for every feature
 * addition in CPT PF driver.
 */
#define CPT_PF_DRV_VERSION     0x3

static void dump_mbox_msg(struct mbox_msghdr *msg, int size)
{
	u16 pf_id, vf_id;

	pf_id = (msg->pcifunc >> RVU_PFVF_PF_SHIFT) & RVU_PFVF_PF_MASK;
	vf_id = (msg->pcifunc >> RVU_PFVF_FUNC_SHIFT) & RVU_PFVF_FUNC_MASK;

	pr_debug("MBOX opcode %s received from (PF%d/VF%d), size %d, rc %d",
		 cpt_get_mbox_opcode_str(msg->id), pf_id, vf_id, size, msg->rc);
	print_hex_dump_debug("", DUMP_PREFIX_OFFSET, 16, 2, msg, size, false);
}

static int get_eng_grp(struct cptpf_dev *cptpf, u8 eng_type)
{
	int eng_grp_num = INVALID_CRYPTO_ENG_GRP;
	struct engine_group_info *grp;
	int i;


	mutex_lock(&cptpf->eng_grps.lock);

	switch (eng_type) {
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
				eng_grp_num = i;
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

			if (cpt_eng_grp_has_eng_type(grp, eng_type)) {
				eng_grp_num = i;
				break;
			}
		}
		break;

	default:
		dev_err(&cptpf->pdev->dev, "Invalid engine type %d", eng_type);
	}
	mutex_unlock(&cptpf->eng_grps.lock);

	return eng_grp_num;
}

static int cptlf_set_pri(struct pci_dev *pdev, struct cptlf_info *lf, int pri)
{
	union cptx_af_lf_ctrl lf_ctrl;
	int ret;

	ret = cpt_read_af_reg(pdev, CPT_AF_LFX_CTL(lf->slot), &lf_ctrl.u);
	if (ret)
		return ret;

	lf_ctrl.s.pri = pri ? 1 : 0;

	ret = cpt_write_af_reg(pdev, CPT_AF_LFX_CTL(lf->slot), lf_ctrl.u);

	return ret;
}

static int cptlf_set_eng_grps_mask(struct pci_dev *pdev, struct cptlf_info *lf,
				   u8 eng_grp_mask)
{
	union cptx_af_lf_ctrl lf_ctrl;
	int ret;

	ret = cpt_read_af_reg(pdev, CPT_AF_LFX_CTL(lf->slot), &lf_ctrl.u);
	if (ret)
		return ret;

	lf_ctrl.s.grp = eng_grp_mask;

	ret = cpt_write_af_reg(pdev, CPT_AF_LFX_CTL(lf->slot), lf_ctrl.u);

	return ret;
}

static int cptlf_set_grp_and_pri(struct pci_dev *pdev, struct cptlfs_info *lfs,
				 u8 eng_grp_mask, int pri)
{
	int slot, ret;

	for (slot = 0; slot < lfs->lfs_num; slot++) {
		ret = cptlf_set_pri(pdev, &lfs->lf[slot], pri);
		if (ret)
			return ret;

		ret = cptlf_set_eng_grps_mask(pdev, &lfs->lf[slot],
					      eng_grp_mask);
		if (ret)
			return ret;
	}
	return 0;
}

void cptpf_lf_cleanup(struct cptlfs_info *lfs)
{
	cptlf_disable_iqueues(lfs);
	free_instruction_queues(lfs);
	cpt_detach_rscrs_msg(lfs->pdev);
	lfs->lfs_num = 0;
}

int cptpf_lf_init(struct cptpf_dev *cptpf, u8 eng_grp_mask, int pri,
		  int lfs_num)
{
	struct cptlfs_info *lfs = &cptpf->lfs;
	struct pci_dev *pdev = cptpf->pdev;
	int ret, slot;

	lfs->reg_base = cptpf->reg_base;
	lfs->lfs_num = lfs_num;
	lfs->pdev = pdev;

	for (slot = 0; slot < lfs->lfs_num; slot++) {
		lfs->lf[slot].lfs = lfs;
		lfs->lf[slot].slot = slot;
		lfs->lf[slot].lmtline = lfs->reg_base +
			RVU_FUNC_ADDR_S(BLKADDR_LMT, slot, LMT_LF_LMTLINEX(0));
		lfs->lf[slot].ioreg = lfs->reg_base +
			RVU_FUNC_ADDR_S(BLKADDR_CPT0, slot, CPT_LF_NQX(0));
	}

	if (cptpf->limits.cpt < lfs_num) {
		dev_err(&pdev->dev, "Not enough CPT LFs\n");
		ret = -ENOENT;
		goto cpt_err;
	}

	ret = cpt_attach_rscrs_msg(pdev);
	if (ret)
		goto cpt_err;

	ret = alloc_instruction_queues(lfs);
	if (ret) {
		dev_err(&pdev->dev,
			"Allocating instruction queues failed\n");
		goto cpt_err_detach;
	}
	cptlf_disable_iqueues(lfs);

	cptlf_set_iqueues_base_addr(lfs);

	cptlf_set_iqueues_size(lfs);

	cptlf_enable_iqueues(lfs);

	ret = cptlf_set_grp_and_pri(pdev, lfs, eng_grp_mask, pri);
	if (ret)
		goto cpt_err_free_iqueue;

	return 0;

cpt_err_free_iqueue:
	cptlf_disable_iqueues(lfs);
	free_instruction_queues(lfs);
cpt_err_detach:
	cpt_detach_rscrs_msg(pdev);
cpt_err:
	lfs->lfs_num = 0;
	return ret;
}

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
	struct ready_msg_rsp *rsp;

	rsp = (struct ready_msg_rsp *)
	       otx2_mbox_alloc_msg(&cptpf->vfpf_mbox, vf->vf_id, sizeof(*rsp));
	if (!rsp)
		return -ENOMEM;

	rsp->hdr.id = MBOX_MSG_READY;
	rsp->hdr.sig = OTX2_MBOX_RSP_SIG;
	rsp->hdr.pcifunc = req->pcifunc;

	return 0;
}

static int reply_eng_grp_num_msg(struct cptpf_dev *cptpf,
				 struct cptvf_info *vf,
				 struct mbox_msghdr *req)
{
	struct eng_grp_num_msg *grp_req = (struct eng_grp_num_msg *)req;
	struct eng_grp_num_rsp *rsp;

	rsp = (struct eng_grp_num_rsp *)
			      otx2_mbox_alloc_msg(&cptpf->vfpf_mbox, vf->vf_id,
						  sizeof(*rsp));
	if (!rsp)
		return -ENOMEM;

	rsp->hdr.id = MBOX_MSG_GET_ENG_GRP_NUM;
	rsp->hdr.sig = OTX2_MBOX_RSP_SIG;
	rsp->hdr.pcifunc = req->pcifunc;
	rsp->eng_type = grp_req->eng_type;
	rsp->eng_grp_num = get_eng_grp(cptpf, grp_req->eng_type);

	return 0;
}

static int rx_inline_ipsec_lf_cfg(struct cptpf_dev *cptpf, u8 egrp,
				  u16 sso_pf_func, bool enable)
{
	struct cpt_inline_ipsec_cfg_msg *req;
	struct nix_inline_ipsec_cfg *nix_req;
	struct pci_dev *pdev = cptpf->pdev;
	int ret;

	nix_req = (struct nix_inline_ipsec_cfg *)
			otx2_mbox_alloc_msg_rsp(&cptpf->afpf_mbox, 0,
						sizeof(*nix_req),
						sizeof(struct msg_rsp));
	if (nix_req == NULL) {
		dev_err(&pdev->dev, "RVU MBOX failed to get message.\n");
		return -EFAULT;
	}
	memset(nix_req, 0, sizeof(*nix_req));
	nix_req->hdr.id = MBOX_MSG_NIX_INLINE_IPSEC_CFG;
	nix_req->hdr.sig = OTX2_MBOX_REQ_SIG;
	nix_req->enable = enable;
	nix_req->cpt_credit = CPT_INST_QLEN_MSGS - 1;
	nix_req->gen_cfg.egrp = egrp;
	nix_req->gen_cfg.opcode = CPT_INLINE_RX_OPCODE;
	nix_req->inst_qsel.cpt_pf_func = RVU_PFFUNC(cptpf->pf_id, 0);
	nix_req->inst_qsel.cpt_slot = 0;
	ret = cpt_send_mbox_msg(pdev);
	if (ret)
		return ret;

	req = (struct cpt_inline_ipsec_cfg_msg *)
			otx2_mbox_alloc_msg_rsp(&cptpf->afpf_mbox, 0,
						sizeof(*req),
						sizeof(struct msg_rsp));
	if (req == NULL) {
		dev_err(&pdev->dev, "RVU MBOX failed to get message.\n");
		return -EFAULT;
	}
	memset(req, 0, sizeof(*req));
	req->hdr.id = MBOX_MSG_CPT_INLINE_IPSEC_CFG;
	req->hdr.sig = OTX2_MBOX_REQ_SIG;
	req->hdr.pcifunc = RVU_PFFUNC(cptpf->pf_id, 0);
	req->dir = CPT_INLINE_INBOUND;
	req->slot = 0;
	req->sso_pf_func_ovrd = cptpf->sso_pf_func_ovrd;
	req->sso_pf_func = sso_pf_func;
	req->enable = enable;
	ret = cpt_send_mbox_msg(pdev);

	return ret;
}

static int rx_inline_ipsec_lf_enable(struct cptpf_dev *cptpf,
				     struct mbox_msghdr *req)
{
	struct rx_inline_lf_cfg *cfg_req = (struct rx_inline_lf_cfg *)req;
	u8 egrp;
	int ret;

	if (cptpf->lfs.lfs_num) {
		dev_err(&cptpf->pdev->dev,
			"LF is already configured for RX inline ipsec.\n");
		ret = -EEXIST;
		goto cpt_err;
	}
	/* Allow LFs to execute requests destined to only grp IE_TYPES and
	 * set queue priority of each LF to high
	 */
	egrp = get_eng_grp(cptpf, IE_TYPES);
	cptpf->blkaddr = BLKADDR_CPT0;

	ret = cptpf_lf_init(cptpf, 1 << egrp, QUEUE_HI_PRIO, 1);
	if (ret)
		goto cpt_err;

	ret = rx_inline_ipsec_lf_cfg(cptpf, egrp, cfg_req->sso_pf_func, true);
	if (ret)
		goto cpt_err_lf_cleanup;

	return ret;

cpt_err_lf_cleanup:
	cptpf_lf_cleanup(&cptpf->lfs);
cpt_err:
	return ret;
}

static int reply_caps_msg(struct cptpf_dev *cptpf, struct cptvf_info *vf,
			  struct mbox_msghdr *req)
{
	struct cpt_caps_rsp *rsp;

	rsp = (struct cpt_caps_rsp *)
			      otx2_mbox_alloc_msg(&cptpf->vfpf_mbox, vf->vf_id,
						  sizeof(*rsp));
	if (!rsp)
		return -ENOMEM;

	rsp->hdr.id = MBOX_MSG_GET_CAPS;
	rsp->hdr.sig = OTX2_MBOX_RSP_SIG;
	rsp->hdr.pcifunc = req->pcifunc;
	rsp->cpt_pf_drv_version = CPT_PF_DRV_VERSION;
	rsp->cpt_revision = cptpf->pdev->revision;
	memcpy(&rsp->eng_caps, &cptpf->eng_caps, sizeof(rsp->eng_caps));

	return 0;
}

static int check_cpt_lf_alloc_req(struct cptpf_dev *cptpf,
				  struct cptvf_info *vf,
				  struct mbox_msghdr *req, int size)
{
	struct cpt_lf_alloc_req_msg *alloc_req =
					(struct cpt_lf_alloc_req_msg *)req;

	if (alloc_req->eng_grpmsk == 0x0)
		alloc_req->eng_grpmsk = ALL_ENG_GRPS_MASK;

	return forward_to_af(cptpf, vf, req, size);
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

	case MBOX_MSG_RX_INLINE_IPSEC_LF_CFG:
		err = rx_inline_ipsec_lf_enable(cptpf, req);
		break;

	case MBOX_MSG_GET_CAPS:
		err = reply_caps_msg(cptpf, vf, req);
		break;

	case MBOX_MSG_CPT_LF_ALLOC:
		err = check_cpt_lf_alloc_req(cptpf, vf, req, size);
		break;

	default:
		err = forward_to_af(cptpf, vf, req, size);
		break;
	}

	return err;
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
			dump_mbox_msg(msg, size);
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

			case MBOX_MSG_ATTACH_RESOURCES:
				if (!msg->rc)
					cptpf->lfs.are_lfs_attached = 1;
				break;

			case MBOX_MSG_DETACH_RESOURCES:
				if (!msg->rc)
					cptpf->lfs.are_lfs_attached = 0;
				break;
			case MBOX_MSG_CPT_INLINE_IPSEC_CFG:
			case MBOX_MSG_NIX_INLINE_IPSEC_CFG:
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
