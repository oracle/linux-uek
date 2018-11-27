// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CPT9X_MBOX_COMMON_H
#define __CPT9X_MBOX_COMNON_H

#include "cpt9x_pf.h"
#include "cpt9x_vf.h"

#define INVALID_KCRYPTO_ENG_GRP	0xFF

/* Extended ready message response with engine group
 * number for kernel crypto functionality
 */
struct ready_msg_rsp_ex {
	struct ready_msg_rsp msg;
	int eng_grp_num;
};

static inline struct cptlfs_info *get_lfs_info(struct pci_dev *pdev)
{
	struct cptpf_dev *cptpf;
	struct cptvf_dev *cptvf;

	if (pdev->is_physfn) {
		cptpf = (struct cptpf_dev *) pci_get_drvdata(pdev);
		return &cptpf->lfs;
	}

	cptvf = (struct cptvf_dev *) pci_get_drvdata(pdev);
	return &cptvf->lfs;
}

int cpt_send_ready_msg(struct pci_dev *pdev);
int cpt_get_rsrc_cnt(struct pci_dev *pdev);
int cpt_attach_rscrs_msg(struct pci_dev *pdev);
int cpt_detach_rscrs_msg(struct pci_dev *pdev);
int cpt_msix_offset_msg(struct pci_dev *pdev);

int cpt_send_af_reg_requests(struct pci_dev *pdev);
int cpt_add_read_af_reg(struct pci_dev *pdev, u64 reg, u64 *val);
int cpt_add_write_af_reg(struct pci_dev *pdev, u64 reg, u64 val);
int cpt_read_af_reg(struct pci_dev *pdev, u64 reg, u64 *val);
int cpt_write_af_reg(struct pci_dev *pdev, u64 reg, u64 val);

int cpt_send_mbox_msg(struct pci_dev *pdev);
void dump_mbox_msg(struct device *dev, struct mbox_msghdr *msg, int size);

#endif /* __CPT9X_MBOX_COMMON_H */
