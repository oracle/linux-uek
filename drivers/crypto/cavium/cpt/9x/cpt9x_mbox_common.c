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

static inline struct otx2_mbox *get_mbox(struct pci_dev *pdev)
{
	struct cptpf_dev *cptpf;
	struct cptvf_dev *cptvf;

	if (pdev->is_physfn) {
		cptpf = (struct cptpf_dev *) pci_get_drvdata(pdev);
		return &cptpf->afpf_mbox;
	}

	cptvf = (struct cptvf_dev *) pci_get_drvdata(pdev);
	return &cptvf->pfvf_mbox;
}

static inline int get_pf_id(struct pci_dev *pdev)
{
	struct cptpf_dev *cptpf;

	if (pdev->is_physfn) {
		cptpf = (struct cptpf_dev *) pci_get_drvdata(pdev);
		return cptpf->pf_id;
	}

	return 0;
}

static inline int get_vf_id(struct pci_dev *pdev)
{
	struct cptvf_dev *cptvf;

	if (pdev->is_virtfn) {
		cptvf = (struct cptvf_dev *) pci_get_drvdata(pdev);
		return cptvf->vf_id;
	}

	return 0;
}

static inline struct free_rsrcs_rsp *get_limits(struct pci_dev *pdev)
{
	struct cptpf_dev *cptpf;
	struct cptvf_dev *cptvf;

	if (pdev->is_physfn) {
		cptpf = (struct cptpf_dev *) pci_get_drvdata(pdev);
		return &cptpf->limits;
	}

	cptvf = (struct cptvf_dev *) pci_get_drvdata(pdev);
	return &cptvf->limits;
}

u8 cpt_get_blkaddr(struct pci_dev *pdev)
{
	struct cptpf_dev *cptpf;
	struct cptvf_dev *cptvf;

	if (pdev->is_physfn) {
		cptpf = (struct cptpf_dev *) pci_get_drvdata(pdev);
		return cptpf->blkaddr;
	}

	cptvf = (struct cptvf_dev *) pci_get_drvdata(pdev);
	return cptvf->blkaddr;
}

char *cpt_get_mbox_opcode_str(int msg_opcode)
{
	char *str = "Unknown";

	switch (msg_opcode) {
	case MBOX_MSG_READY:
		str = "READY";
	break;

	case MBOX_MSG_FREE_RSRC_CNT:
		str = "FREE_RSRC_CNT";
	break;

	case MBOX_MSG_ATTACH_RESOURCES:
		str = "ATTACH_RESOURCES";
	break;

	case MBOX_MSG_DETACH_RESOURCES:
		str = "DETACH_RESOURCES";
	break;

	case MBOX_MSG_MSIX_OFFSET:
		str = "MSIX_OFFSET";
	break;

	case MBOX_MSG_CPT_RD_WR_REGISTER:
		str = "RD_WR_REGISTER";
	break;

	case MBOX_MSG_GET_ENG_GRP_NUM:
		str = "GET_ENG_GRP_NUM";
	break;
	}

	return str;
}

int cpt_send_mbox_msg(struct pci_dev *pdev)
{
	struct otx2_mbox *mbox = get_mbox(pdev);
	int ret = 0;

	otx2_mbox_msg_send(mbox, 0);
	ret = otx2_mbox_wait_for_rsp(mbox, 0);
	if (ret == -EIO) {
		dev_err(&pdev->dev, "RVU MBOX timeout.\n");
		goto error;
	} else if (ret) {
		dev_err(&pdev->dev, "RVU MBOX error: %d.\n", ret);
		ret = -EFAULT;
		goto error;
	}
error:
	return ret;
}

int cpt_send_ready_msg(struct pci_dev *pdev)
{
	struct otx2_mbox *mbox = get_mbox(pdev);
	struct mbox_msghdr *req;
	int ret = 0;

	req = otx2_mbox_alloc_msg_rsp(mbox, 0, sizeof(*req),
				      sizeof(struct ready_msg_rsp));

	if (req == NULL) {
		dev_err(&pdev->dev, "RVU MBOX failed to get message.\n");
		ret = -EFAULT;
		goto error;
	}

	req->id = MBOX_MSG_READY;
	req->sig = OTX2_MBOX_REQ_SIG;
	req->pcifunc = RVU_PFFUNC(get_pf_id(pdev), get_vf_id(pdev));
	ret = cpt_send_mbox_msg(pdev);
	if (ret)
		goto error;
error:
	return ret;
}

int cpt_get_rsrc_cnt(struct pci_dev *pdev)
{
	struct free_rsrcs_rsp *limits = get_limits(pdev);
	struct otx2_mbox *mbox = get_mbox(pdev);
	struct mbox_msghdr *rsrc_req;
	int ret = 0;

	rsrc_req = otx2_mbox_alloc_msg_rsp(mbox, 0, sizeof(*rsrc_req),
					   sizeof(struct free_rsrcs_rsp));
	if (rsrc_req == NULL) {
		dev_err(&pdev->dev, "RVU MBOX failed to get message.\n");
		ret = -EFAULT;
		goto error;
	}

	rsrc_req->id = MBOX_MSG_FREE_RSRC_CNT;
	rsrc_req->sig = OTX2_MBOX_REQ_SIG;
	rsrc_req->pcifunc = RVU_PFFUNC(get_pf_id(pdev), get_vf_id(pdev));
	ret = cpt_send_mbox_msg(pdev);
	if (ret)
		goto error;

	if (!limits->cpt)
		ret = -ENOENT;
error:
	return ret;
}

int cpt_attach_rscrs_msg(struct pci_dev *pdev)
{
	struct cptlfs_info *lfs = get_lfs_info(pdev);
	struct otx2_mbox *mbox = get_mbox(pdev);
	u8 blkaddr = cpt_get_blkaddr(pdev);
	struct rsrc_attach *req;
	int ret = 0;

	req = (struct rsrc_attach *)
			otx2_mbox_alloc_msg_rsp(mbox, 0, sizeof(*req),
						sizeof(struct msg_rsp));
	if (req == NULL) {
		dev_err(&pdev->dev, "RVU MBOX failed to get message.\n");
		ret = -EFAULT;
		goto error;
	}

	req->hdr.id = MBOX_MSG_ATTACH_RESOURCES;
	req->hdr.sig = OTX2_MBOX_REQ_SIG;
	req->hdr.pcifunc = RVU_PFFUNC(get_pf_id(pdev), get_vf_id(pdev));
	req->cptlfs = lfs->lfs_num;
	req->cpt_blkaddr = blkaddr;
	ret = cpt_send_mbox_msg(pdev);
	if (ret)
		goto error;

	if (!lfs->are_lfs_attached)
		ret = -EINVAL;
error:
	return ret;
}

int cpt_detach_rscrs_msg(struct pci_dev *pdev)
{
	struct cptlfs_info *lfs = get_lfs_info(pdev);
	struct otx2_mbox *mbox = get_mbox(pdev);
	struct rsrc_detach *req;
	int ret = 0;

	req = (struct rsrc_detach *)
				otx2_mbox_alloc_msg_rsp(mbox, 0, sizeof(*req),
							sizeof(struct msg_rsp));
	if (req == NULL) {
		dev_err(&pdev->dev, "RVU MBOX failed to get message.\n");
		ret = -EFAULT;
		goto error;
	}

	req->hdr.id = MBOX_MSG_DETACH_RESOURCES;
	req->hdr.sig = OTX2_MBOX_REQ_SIG;
	req->hdr.pcifunc = RVU_PFFUNC(get_pf_id(pdev), get_vf_id(pdev));
	ret = cpt_send_mbox_msg(pdev);
	if (ret)
		goto error;

	if (lfs->are_lfs_attached)
		ret = -EINVAL;
error:
	return ret;
}

int cpt_msix_offset_msg(struct pci_dev *pdev)
{
	struct cptlfs_info *lfs = get_lfs_info(pdev);
	struct otx2_mbox *mbox = get_mbox(pdev);
	struct mbox_msghdr *req;
	int ret = 0, i;

	req = otx2_mbox_alloc_msg_rsp(mbox, 0, sizeof(*req),
				      sizeof(struct msix_offset_rsp));
	if (req == NULL) {
		dev_err(&pdev->dev, "RVU MBOX failed to get message.\n");
		ret = -EFAULT;
		goto error;
	}

	req->id = MBOX_MSG_MSIX_OFFSET;
	req->sig = OTX2_MBOX_REQ_SIG;
	req->pcifunc = RVU_PFFUNC(get_pf_id(pdev), get_vf_id(pdev));
	ret = cpt_send_mbox_msg(pdev);
	if (ret)
		goto error;

	for (i = 0; i < lfs->lfs_num; i++)
		if (lfs->lf[i].msix_offset == MSIX_VECTOR_INVALID) {
			dev_err(&pdev->dev,
				"Invalid msix offset %d for LF %d\n",
				lfs->lf[i].msix_offset, i);
			ret = -EINVAL;
			goto error;
		}
error:
	return ret;
}

int cpt_send_af_reg_requests(struct pci_dev *pdev)
{
	return cpt_send_mbox_msg(pdev);
}

int cpt_add_read_af_reg(struct pci_dev *pdev, u64 reg, u64 *val)
{
	struct otx2_mbox *mbox = get_mbox(pdev);
	u8 blkaddr = cpt_get_blkaddr(pdev);
	struct cpt_rd_wr_reg_msg *reg_msg;
	int ret = 0;

	reg_msg = (struct cpt_rd_wr_reg_msg *)
			otx2_mbox_alloc_msg_rsp(mbox, 0, sizeof(*reg_msg),
						sizeof(*reg_msg));
	if (reg_msg == NULL) {
		dev_err(&pdev->dev, "RVU MBOX failed to get message.\n");
		ret = -EFAULT;
		goto error;
	}

	reg_msg->hdr.id = MBOX_MSG_CPT_RD_WR_REGISTER;
	reg_msg->hdr.sig = OTX2_MBOX_REQ_SIG;
	reg_msg->hdr.pcifunc = RVU_PFFUNC(get_pf_id(pdev), get_vf_id(pdev));
	reg_msg->is_write = 0;
	reg_msg->reg_offset = reg;
	reg_msg->ret_val = val;
	reg_msg->blkaddr = blkaddr;
error:
	return ret;
}

int cpt_add_write_af_reg(struct pci_dev *pdev, u64 reg, u64 val)
{
	struct otx2_mbox *mbox = get_mbox(pdev);
	u8 blkaddr = cpt_get_blkaddr(pdev);
	struct cpt_rd_wr_reg_msg *reg_msg;
	int ret = 0;

	reg_msg = (struct cpt_rd_wr_reg_msg *)
			otx2_mbox_alloc_msg_rsp(mbox, 0, sizeof(*reg_msg),
						sizeof(*reg_msg));
	if (reg_msg == NULL) {
		dev_err(&pdev->dev, "RVU MBOX failed to get message.\n");
		ret = -EFAULT;
		goto error;
	}

	reg_msg->hdr.id = MBOX_MSG_CPT_RD_WR_REGISTER;
	reg_msg->hdr.sig = OTX2_MBOX_REQ_SIG;
	reg_msg->hdr.pcifunc = RVU_PFFUNC(get_pf_id(pdev), get_vf_id(pdev));
	reg_msg->is_write = 1;
	reg_msg->reg_offset = reg;
	reg_msg->val = val;
	reg_msg->blkaddr = blkaddr;
error:
	return ret;
}

int cpt_read_af_reg(struct pci_dev *pdev, u64 reg, u64 *val)
{
	int ret = 0;

	ret = cpt_add_read_af_reg(pdev, reg, val);
	if (ret)
		goto error;
	ret = cpt_send_mbox_msg(pdev);
	if (ret)
		goto error;
error:
	return ret;
}

int cpt_write_af_reg(struct pci_dev *pdev, u64 reg, u64 val)
{
	int ret = 0;

	ret = cpt_add_write_af_reg(pdev, reg, val);
	if (ret)
		goto error;
	ret = cpt_send_mbox_msg(pdev);
	if (ret)
		goto error;
error:
	return ret;
}
