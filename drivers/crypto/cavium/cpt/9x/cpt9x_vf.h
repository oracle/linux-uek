/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CPT9X_VF_H
#define __CPT9X_VF_H

#include "mbox.h"
#include "cpt9x_lf.h"

struct cptvf_dev {
	void __iomem *reg_base;		/* Register start address */
	void __iomem *pfvf_mbox_base;	/* PF-VF mbox start address */
	struct pci_dev *pdev;		/* PCI device handle */
	struct cptlfs_info lfs;		/* CPT LFs attached to this VF */
	struct free_rsrcs_rsp limits;   /* Resource limits for this VF */
	u8 vf_id;			/* Virtual function index */

	/* PF <=> VF mbox */
	struct otx2_mbox	pfvf_mbox;
	struct work_struct	pfvf_mbox_work;
	struct workqueue_struct *pfvf_mbox_wq;
	int blkaddr;
};

irqreturn_t cptvf_pfvf_mbox_intr(int irq, void *arg);
void cptvf_pfvf_mbox_handler(struct work_struct *work);
int cptvf_send_eng_grp_num_msg(struct cptvf_dev *cptvf, int eng_type);
struct algs_ops cpt9x_get_algs_ops(void);

#endif /* __CPT9X_VF_H */
