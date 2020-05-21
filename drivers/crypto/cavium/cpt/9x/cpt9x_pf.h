/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CPT9X_PF_H
#define __CPT9X_PF_H

#include "cpt_ucode.h"
#include "cpt9x_lf.h"
#include "cpt9x_quota.h"

struct cptpf_dev;
struct cptvf_info {
	struct cptpf_dev	*cptpf;	/* PF pointer this VF belongs to */
	struct work_struct	vfpf_mbox_work;
	struct kobject		*limits_kobj;
	struct pci_dev		*vf_dev;
	int			vf_id;
	int			intr_idx; /* vf_id % 64 */
};

struct cpt_limits {
	struct mutex lock;
	struct quotas *cpt;
};

struct cpt_kvf_limits {
	struct device_attribute kvf_limits_attr;
	int lfs_num; /* Number of LFs allocated for kernel VF driver */
};

/* CPT HW capabilities */
union cpt_eng_caps {
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

struct cptpf_dev {
	void __iomem *reg_base;		/* CPT PF registers start address */
	void __iomem *afpf_mbox_base;	/* PF-AF mbox start address */
	void __iomem *vfpf_mbox_base;   /* VF-PF mbox start address */
	struct pci_dev *pdev;		/* PCI device handle */
	struct cptvf_info vf[CPT_9X_MAX_VFS_NUM];
	struct cptlfs_info lfs;		/* CPT LFs attached to this PF */
	struct free_rsrcs_rsp limits;   /* Maximum limits for all VFs and PF */
	struct cpt_limits vf_limits;	/* Limits for each VF */
	struct engine_groups eng_grps;	/* Engine groups information */
	/* HW capabilities for each engine type */
	union cpt_eng_caps eng_caps[CPT_MAX_ENG_TYPES];
	bool is_eng_caps_discovered;

	/* AF <=> PF mbox */
	struct otx2_mbox	afpf_mbox;
	struct work_struct	afpf_mbox_work;
	struct workqueue_struct *afpf_mbox_wq;

	/* VF <=> PF mbox */
	struct otx2_mbox	vfpf_mbox;
	struct workqueue_struct *vfpf_mbox_wq;

	bool irq_registered[CPT_96XX_PF_MSIX_VECTORS];	/* Is IRQ registered */
	u8 pf_id;		/* RVU PF number */
	u8 max_vfs;		/* Maximum number of VFs supported by CPT */
	u8 enabled_vfs;		/* Number of enabled VFs */
	u8 sso_pf_func_ovrd;	/* SSO PF_FUNC override bit */
	u8 kvf_limits;		/* Kernel VF limits */
	/* BLKADDR_CPT0/BLKADDR_CPT1 or 0 for BLKADDR_CPT0 */
	u8 blkaddr;
	bool cpt1_implemented;
};

irqreturn_t cptpf_afpf_mbox_intr(int irq, void *arg);
irqreturn_t cptpf_vfpf_mbox_intr(int irq, void *arg);
void cptpf_afpf_mbox_handler(struct work_struct *work);
void cptpf_vfpf_mbox_handler(struct work_struct *work);
int cptpf_send_crypto_eng_grp_msg(struct cptpf_dev *cptpf,
				  int crypto_eng_grp);
int cpt9x_disable_all_cores(struct cptpf_dev *cptpf);
int cpt9x_discover_eng_capabilities(void *obj);
struct ucode_ops cpt9x_get_ucode_ops(void);
int cptpf_lf_init(struct cptpf_dev *cptpf, u8 eng_grp_mask,
		  int pri, int lfs_num);
void cptpf_lf_cleanup(struct cptlfs_info *lfs);

#endif /* __CPT9X_PF_H */
