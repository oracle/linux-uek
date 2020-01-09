/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX2 CPT driver
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

#define INVALID_CRYPTO_ENG_GRP		0xFF
/* Take mbox id from end of CPT mbox range in AF (range 0xA00 - 0xBFF) */
#define MBOX_MSG_GET_ENG_GRP_NUM	0xBFF
#define MBOX_MSG_RX_INLINE_IPSEC_LF_CFG	0xBFE
#define MBOX_MSG_GET_CAPS		0xBFD

/*
 * Message request and response to get engine group number
 * which has attached a given type of engines (SE, AE, IE)
 * This messages are only used between CPT PF <-> CPT VF
 */
struct eng_grp_num_msg {
	struct mbox_msghdr hdr;
	u8 eng_type;
};

struct eng_grp_num_rsp {
	struct mbox_msghdr hdr;
	u8 eng_type;
	u8 eng_grp_num;
};

/*
 * Message request to config cpt lf for inline inbound ipsec.
 * This message is only used between CPT PF <-> CPT VF
 */
struct rx_inline_lf_cfg {
	struct mbox_msghdr hdr;
	u16 sso_pf_func;
};

/*
 * Message request and response to get HW capabilities for each
 * engine type (SE, IE, AE).
 * This messages are only used between CPT PF <-> CPT VF
 */
struct cpt_caps_msg {
	struct mbox_msghdr hdr;
};

struct cpt_caps_rsp {
	struct mbox_msghdr hdr;
	u16 cpt_pf_drv_version;
	u8 cpt_revision;
	union cpt_eng_caps eng_caps[CPT_MAX_ENG_TYPES];
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
char *cpt_get_mbox_opcode_str(int msg_opcode);

#endif /* __CPT9X_MBOX_COMMON_H */
