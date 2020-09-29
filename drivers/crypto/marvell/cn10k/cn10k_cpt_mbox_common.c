// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020 Marvell. */

#include "cn10k_cpt_mbox_common.h"

static inline struct otx2_mbox *get_mbox(struct pci_dev *pdev)
{
	struct cn10k_cptpf_dev *cptpf;
	struct cn10k_cptvf_dev *cptvf;

	if (pdev->is_physfn) {
		cptpf = pci_get_drvdata(pdev);
		return &cptpf->afpf_mbox;
	}
	cptvf = pci_get_drvdata(pdev);
	return &cptvf->pfvf_mbox;
}

static inline int get_pf_id(struct pci_dev *pdev)
{
	struct cn10k_cptpf_dev *cptpf;

	if (pdev->is_physfn) {
		cptpf = pci_get_drvdata(pdev);
		return cptpf->pf_id;
	}
	return 0;
}

static inline int get_vf_id(struct pci_dev *pdev)
{
	struct cn10k_cptvf_dev *cptvf;

	if (pdev->is_virtfn) {
		cptvf = pci_get_drvdata(pdev);
		return cptvf->vf_id;
	}
	return 0;
}

char *cn10k_cpt_get_mbox_opcode_str(int msg_opcode)
{
	char *str = "Unknown";

	switch (msg_opcode) {
	case MBOX_MSG_READY:
		str = "READY";
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

	case MBOX_MSG_RX_INLINE_IPSEC_LF_CFG:
		str = "RX_INLINE_IPSEC_LF_CFG";
		break;

	case MBOX_MSG_GET_CAPS:
		str = "GET_CAPS";
		break;

	case MBOX_MSG_GET_KCRYPTO_LIMITS:
		str = "GET_KCRYPTO_LIMITS";
		break;
	}
	return str;
}

int cn10k_cpt_send_mbox_msg(struct pci_dev *pdev)
{
	struct otx2_mbox *mbox = get_mbox(pdev);
	int ret;

	otx2_mbox_msg_send(mbox, 0);
	ret = otx2_mbox_wait_for_rsp(mbox, 0);
	if (ret == -EIO) {
		dev_err(&pdev->dev, "RVU MBOX timeout.\n");
		return ret;
	} else if (ret) {
		dev_err(&pdev->dev, "RVU MBOX error: %d.\n", ret);
		return -EFAULT;
	}
	return ret;
}

int cn10k_cpt_send_ready_msg(struct pci_dev *pdev)
{
	struct otx2_mbox *mbox = get_mbox(pdev);
	struct mbox_msghdr *req;

	req = otx2_mbox_alloc_msg_rsp(mbox, 0, sizeof(*req),
				      sizeof(struct ready_msg_rsp));

	if (req == NULL) {
		dev_err(&pdev->dev, "RVU MBOX failed to get message.\n");
		return -EFAULT;
	}

	req->id = MBOX_MSG_READY;
	req->sig = OTX2_MBOX_REQ_SIG;
	req->pcifunc = CN10K_CPT_RVU_PFFUNC(get_pf_id(pdev), get_vf_id(pdev));

	return cn10k_cpt_send_mbox_msg(pdev);
}

int cn10k_cpt_attach_rscrs_msg(struct pci_dev *pdev)
{
	struct cn10k_cptlfs_info *lfs = cn10k_cpt_get_lfs_info(pdev);
	struct otx2_mbox *mbox = get_mbox(pdev);
	struct rsrc_attach *req;
	int ret;

	req = (struct rsrc_attach *)
			otx2_mbox_alloc_msg_rsp(mbox, 0, sizeof(*req),
						sizeof(struct msg_rsp));
	if (req == NULL) {
		dev_err(&pdev->dev, "RVU MBOX failed to get message.\n");
		return -EFAULT;
	}

	req->hdr.id = MBOX_MSG_ATTACH_RESOURCES;
	req->hdr.sig = OTX2_MBOX_REQ_SIG;
	req->hdr.pcifunc = CN10K_CPT_RVU_PFFUNC(get_pf_id(pdev),
						get_vf_id(pdev));
	req->cptlfs = lfs->lfs_num;
	ret = cn10k_cpt_send_mbox_msg(pdev);
	if (ret)
		return ret;

	if (!lfs->are_lfs_attached)
		ret = -EINVAL;

	return ret;
}

int cn10k_cpt_detach_rsrcs_msg(struct pci_dev *pdev)
{
	struct cn10k_cptlfs_info *lfs = cn10k_cpt_get_lfs_info(pdev);
	struct otx2_mbox *mbox = get_mbox(pdev);
	struct rsrc_detach *req;
	int ret;

	req = (struct rsrc_detach *)
				otx2_mbox_alloc_msg_rsp(mbox, 0, sizeof(*req),
							sizeof(struct msg_rsp));
	if (req == NULL) {
		dev_err(&pdev->dev, "RVU MBOX failed to get message.\n");
		return -EFAULT;
	}

	req->hdr.id = MBOX_MSG_DETACH_RESOURCES;
	req->hdr.sig = OTX2_MBOX_REQ_SIG;
	req->hdr.pcifunc = CN10K_CPT_RVU_PFFUNC(get_pf_id(pdev),
						get_vf_id(pdev));
	ret = cn10k_cpt_send_mbox_msg(pdev);
	if (ret)
		return ret;

	if (lfs->are_lfs_attached)
		ret = -EINVAL;

	return ret;
}

int cn10k_cpt_msix_offset_msg(struct pci_dev *pdev)
{
	struct cn10k_cptlfs_info *lfs = cn10k_cpt_get_lfs_info(pdev);
	struct otx2_mbox *mbox = get_mbox(pdev);
	struct mbox_msghdr *req;
	int ret, i;

	req = otx2_mbox_alloc_msg_rsp(mbox, 0, sizeof(*req),
				      sizeof(struct msix_offset_rsp));
	if (req == NULL) {
		dev_err(&pdev->dev, "RVU MBOX failed to get message.\n");
		return -EFAULT;
	}

	req->id = MBOX_MSG_MSIX_OFFSET;
	req->sig = OTX2_MBOX_REQ_SIG;
	req->pcifunc = CN10K_CPT_RVU_PFFUNC(get_pf_id(pdev), get_vf_id(pdev));
	ret = cn10k_cpt_send_mbox_msg(pdev);
	if (ret)
		return ret;

	for (i = 0; i < lfs->lfs_num; i++) {
		if (lfs->lf[i].msix_offset == MSIX_VECTOR_INVALID) {
			dev_err(&pdev->dev,
				"Invalid msix offset %d for LF %d\n",
				lfs->lf[i].msix_offset, i);
			return -EINVAL;
		}
	}
	return ret;
}

int cn10k_cpt_add_read_af_reg(struct pci_dev *pdev, u64 reg, u64 *val)
{
	struct otx2_mbox *mbox = get_mbox(pdev);
	struct cpt_rd_wr_reg_msg *reg_msg;

	reg_msg = (struct cpt_rd_wr_reg_msg *)
			otx2_mbox_alloc_msg_rsp(mbox, 0, sizeof(*reg_msg),
						sizeof(*reg_msg));
	if (reg_msg == NULL) {
		dev_err(&pdev->dev, "RVU MBOX failed to get message.\n");
		return -EFAULT;
	}

	reg_msg->hdr.id = MBOX_MSG_CPT_RD_WR_REGISTER;
	reg_msg->hdr.sig = OTX2_MBOX_REQ_SIG;
	reg_msg->hdr.pcifunc = CN10K_CPT_RVU_PFFUNC(get_pf_id(pdev),
						    get_vf_id(pdev));
	reg_msg->is_write = 0;
	reg_msg->reg_offset = reg;
	reg_msg->ret_val = val;

	return 0;
}

int cn10k_cpt_add_write_af_reg(struct pci_dev *pdev, u64 reg, u64 val)
{
	struct otx2_mbox *mbox = get_mbox(pdev);
	struct cpt_rd_wr_reg_msg *reg_msg;

	reg_msg = (struct cpt_rd_wr_reg_msg *)
			otx2_mbox_alloc_msg_rsp(mbox, 0, sizeof(*reg_msg),
						sizeof(*reg_msg));
	if (reg_msg == NULL) {
		dev_err(&pdev->dev, "RVU MBOX failed to get message.\n");
		return -EFAULT;
	}

	reg_msg->hdr.id = MBOX_MSG_CPT_RD_WR_REGISTER;
	reg_msg->hdr.sig = OTX2_MBOX_REQ_SIG;
	reg_msg->hdr.pcifunc = CN10K_CPT_RVU_PFFUNC(get_pf_id(pdev),
						    get_vf_id(pdev));
	reg_msg->is_write = 1;
	reg_msg->reg_offset = reg;
	reg_msg->val = val;

	return 0;
}

int cn10k_cpt_read_af_reg(struct pci_dev *pdev, u64 reg, u64 *val)
{
	int ret;

	ret = cn10k_cpt_add_read_af_reg(pdev, reg, val);
	if (ret)
		return ret;

	return cn10k_cpt_send_mbox_msg(pdev);
}

int cn10k_cpt_write_af_reg(struct pci_dev *pdev, u64 reg, u64 val)
{
	int ret;

	ret = cn10k_cpt_add_write_af_reg(pdev, reg, val);
	if (ret)
		return ret;

	return cn10k_cpt_send_mbox_msg(pdev);
}
