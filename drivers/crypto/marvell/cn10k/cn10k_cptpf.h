/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2020 Marvell.
 */

#ifndef __CN10K_CPTPF_H
#define __CN10K_CPTPF_H

#include "cn10k_cptpf_ucode.h"
#include "cn10k_cptlf.h"

struct cn10k_cptpf_dev;
struct cn10k_cptvf_info {
	struct cn10k_cptpf_dev *cptpf;	/* PF pointer this VF belongs to */
	struct work_struct vfpf_mbox_work;
	struct pci_dev *vf_dev;
	int vf_id;
	int intr_idx;
};

struct cn10k_cpt_kvf_limits {
	struct device_attribute kvf_limits_attr;
	int lfs_num; /* Number of LFs allocated for kernel VF driver */
};

/* CPT HW capabilities */
union cn10k_cpt_eng_caps {
	u64 u;
	struct {
		u64 reserved_0_4:5;
		u64 mul:1;
		u64 sha1_sha2:1;
		u64 chacha20:1;
		u64 zuc_snow3g:1;
		u64 sha3:1;
		u64 aes:1;
		u64 kasumi:1;
		u64 des:1;
		u64 crc:1;
		u64 reserved_14_63:50;
	};
};

struct cn10k_cptpf_dev {
	void __iomem *reg_base;		/* CPT PF registers start address */
	void __iomem *afpf_mbox_base;	/* PF-AF mbox start address */
	void __iomem *vfpf_mbox_base;   /* VF-PF mbox start address */
	void __iomem *pf_lmtline_base;  /* PF LMTLINE start address */
	struct pci_dev *pdev;		/* PCI device handle */
	struct cn10k_cptvf_info vf[CN10K_CPT_MAX_VFS_NUM];
	struct cn10k_cptlfs_info lfs;	/* CPT LFs attached to this PF */
	struct cn10k_cpt_eng_grps eng_grps;/* Engine groups information */
	/* HW capabilities for each engine type */
	union cn10k_cpt_eng_caps eng_caps[CN10K_CPT_MAX_ENG_TYPES];
	bool is_eng_caps_discovered;

	/* AF <=> PF mbox */
	struct otx2_mbox	afpf_mbox;
	struct work_struct	afpf_mbox_work;
	struct workqueue_struct *afpf_mbox_wq;

	/* VF <=> PF mbox */
	struct otx2_mbox	vfpf_mbox;
	struct workqueue_struct *vfpf_mbox_wq;

	u8 pf_id;		/* RVU PF number */
	u8 max_vfs;		/* Maximum number of VFs supported by CPT */
	u8 enabled_vfs;		/* Number of enabled VFs */
	u8 sso_pf_func_ovrd;	/* SSO PF_FUNC override bit */
	u8 kvf_limits;		/* Kernel VF limits */
};

irqreturn_t cn10k_cptpf_afpf_mbox_intr(int irq, void *arg);
irqreturn_t cn10k_cptpf_vfpf_mbox_intr(int irq, void *arg);
void cn10k_cptpf_afpf_mbox_handler(struct work_struct *work);
void cn10k_cptpf_vfpf_mbox_handler(struct work_struct *work);
int cn10k_cptpf_lf_init(struct cn10k_cptpf_dev *cptpf, u8 eng_grp_mask,
			int pri, int lfs_num);
void cn10k_cptpf_lf_cleanup(struct cn10k_cptlfs_info *lfs);

#endif /* __CN10K_CPTPF_H */
