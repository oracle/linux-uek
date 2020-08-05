/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2020 Marvell.
 */

#ifndef __CN10K_CPT_MBOX_COMMON_H
#define __CN10K_CPT_MBOX_COMMON_H

#include "cn10k_cptpf.h"
#include "cn10k_cptvf.h"

/* Take mbox id from end of CPT mbox range in AF (range 0xA00 - 0xBFF) */
#define MBOX_MSG_RX_INLINE_IPSEC_LF_CFG 0xBFE
#define MBOX_MSG_GET_ENG_GRP_NUM        0xBFF
#define MBOX_MSG_GET_CAPS               0xBFD
#define MBOX_MSG_GET_KCRYPTO_LIMITS     0xBFC

/*
 * Message request and response to get engine group number
 * which has attached a given type of engines (SE, AE, IE)
 * This messages are only used between CPT PF <-> CPT VF
 */
struct cn10k_cpt_eng_grp_num_msg {
	struct mbox_msghdr hdr;
	u8 eng_type;
};

struct cn10k_cpt_eng_grp_num_rsp {
	struct mbox_msghdr hdr;
	u8 eng_type;
	u8 eng_grp_num;
};

/*
 * Message request to config cpt lf for inline inbound ipsec.
 * This message is only used between CPT PF <-> CPT VF
 */
struct cn10k_cpt_rx_inline_lf_cfg {
	struct mbox_msghdr hdr;
	u16 sso_pf_func;
};

/*
 * Message request and response to get HW capabilities for each
 * engine type (SE, IE, AE).
 * This messages are only used between CPT PF <-> CPT VF
 */
struct cn10k_cpt_caps_msg {
	struct mbox_msghdr hdr;
};

struct cn10k_cpt_caps_rsp {
	struct mbox_msghdr hdr;
	u16 cpt_pf_drv_version;
	u8 cpt_revision;
	union cn10k_cpt_eng_caps eng_caps[CN10K_CPT_MAX_ENG_TYPES];
};

/*
 * Message request and response to get kernel crypto limits
 * This messages are only used between CPT PF <-> CPT VF
 */
struct cn10k_cpt_kcrypto_limits_msg {
	struct mbox_msghdr hdr;
};

struct cn10k_cpt_kcrypto_limits_rsp {
	struct mbox_msghdr hdr;
	u8 kcrypto_limits;
};

static inline struct cn10k_cptlfs_info *
		     cn10k_cpt_get_lfs_info(struct pci_dev *pdev)
{
	struct cn10k_cptpf_dev *cptpf;
	struct cn10k_cptvf_dev *cptvf;

	if (pdev->is_physfn) {
		cptpf = (struct cn10k_cptpf_dev *) pci_get_drvdata(pdev);
		return &cptpf->lfs;
	}

	cptvf = (struct cn10k_cptvf_dev *) pci_get_drvdata(pdev);
	return &cptvf->lfs;
}

int cn10k_cpt_send_ready_msg(struct pci_dev *pdev);
int cn10k_cpt_attach_rscrs_msg(struct pci_dev *pdev);
int cn10k_cpt_detach_rsrcs_msg(struct pci_dev *pdev);
int cn10k_cpt_msix_offset_msg(struct pci_dev *pdev);

int cn10k_cpt_send_af_reg_requests(struct pci_dev *pdev);
int cn10k_cpt_add_read_af_reg(struct pci_dev *pdev, u64 reg, u64 *val);
int cn10k_cpt_add_write_af_reg(struct pci_dev *pdev, u64 reg, u64 val);
int cn10k_cpt_read_af_reg(struct pci_dev *pdev, u64 reg, u64 *val);
int cn10k_cpt_write_af_reg(struct pci_dev *pdev, u64 reg, u64 val);

int cn10k_cpt_send_mbox_msg(struct pci_dev *pdev);
char *cn10k_cpt_get_mbox_opcode_str(int msg_opcode);

#endif /* __CN10K_CPT_MBOX_COMMON_H */
