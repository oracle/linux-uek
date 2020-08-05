/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2020 Marvell.
 */

#ifndef __CN10K_CPTVF_H
#define __CN10K_CPTVF_H

#include "mbox.h"
#include "cn10k_cptlf.h"

struct cn10k_cptvf_dev {
	void __iomem *reg_base;		/* Register start address */
	void __iomem *pfvf_mbox_base;	/* PF-VF mbox start address */
	struct pci_dev *pdev;		/* PCI device handle */
	struct cn10k_cptlfs_info lfs;	/* CPT LFs attached to this VF */
	u8 vf_id;			/* Virtual function index */

	/* PF <=> VF mbox */
	struct otx2_mbox	pfvf_mbox;
	struct work_struct	pfvf_mbox_work;
	struct workqueue_struct *pfvf_mbox_wq;
};

#endif /* __CN10K_CPTVF_H */
