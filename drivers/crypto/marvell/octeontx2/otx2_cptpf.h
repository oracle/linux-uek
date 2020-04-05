/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __OTX2_CPTPF_H
#define __OTX2_CPTPF_H

#include "otx2_cptpf_ucode.h"
#include "otx2_cptlf.h"

struct otx2_cptpf_dev;
struct otx2_cptvf_info {
	struct otx2_cptpf_dev *cptpf;	/* PF pointer this VF belongs to */
	struct work_struct vfpf_mbox_work;
	struct pci_dev *vf_dev;
	int vf_id;
	int intr_idx;
};

struct otx2_cpt_kvf_limits {
	struct device_attribute kvf_limits_attr;
	int lfs_num; /* Number of LFs allocated for kernel VF driver */
};

/* CPT HW capabilities */
union otx2_cpt_eng_caps {
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

struct otx2_cptpf_dev {
	void __iomem *reg_base;		/* CPT PF registers start address */
	void __iomem *afpf_mbox_base;	/* PF-AF mbox start address */
	void __iomem *vfpf_mbox_base;   /* VF-PF mbox start address */
	struct pci_dev *pdev;		/* PCI device handle */
	struct otx2_cptvf_info vf[OTX2_CPT_MAX_VFS_NUM];
	struct otx2_cptlfs_info lfs;	/* CPT LFs attached to this PF */
	struct otx2_cpt_eng_grps eng_grps;/* Engine groups information */
	/* HW capabilities for each engine type */
	union otx2_cpt_eng_caps eng_caps[OTX2_CPT_MAX_ENG_TYPES];
	bool is_eng_caps_discovered;

	/* AF <=> PF mbox */
	struct otx2_mbox	afpf_mbox;
	struct work_struct	afpf_mbox_work;
	struct workqueue_struct *afpf_mbox_wq;

	/* VF <=> PF mbox */
	struct otx2_mbox	vfpf_mbox;
	struct workqueue_struct *vfpf_mbox_wq;

	bool irq_registered[OTX2_CPT_PF_MSIX_VECTORS];	/* Is IRQ registered */
	u8 pf_id;		/* RVU PF number */
	u8 max_vfs;		/* Maximum number of VFs supported by CPT */
	u8 enabled_vfs;		/* Number of enabled VFs */
	u8 crypto_eng_grp;	/* Symmetric crypto engine group number */
	u8 sso_pf_func_ovrd;	/* SSO PF_FUNC override bit */
	u8 kvf_limits;		/* Kernel VF limits */
};

irqreturn_t otx2_cptpf_afpf_mbox_intr(int irq, void *arg);
irqreturn_t otx2_cptpf_vfpf_mbox_intr(int irq, void *arg);
void otx2_cptpf_afpf_mbox_handler(struct work_struct *work);
void otx2_cptpf_vfpf_mbox_handler(struct work_struct *work);
int otx2_cptpf_lf_init(struct otx2_cptpf_dev *cptpf, u8 eng_grp_mask,
		       int pri, int lfs_num);
void otx2_cptpf_lf_cleanup(struct otx2_cptlfs_info *lfs);

#endif /* __OTX2_CPTPF_H */
