/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __OTX2_CPTVF_H
#define __OTX2_CPTVF_H

#include "mbox.h"
#include "otx2_cptlf.h"

struct otx2_cptvf_dev {
	void __iomem *reg_base;		/* Register start address */
	void __iomem *pfvf_mbox_base;	/* PF-VF mbox start address */
	struct pci_dev *pdev;		/* PCI device handle */
	struct otx2_cptlfs_info lfs;	/* CPT LFs attached to this VF */
	u8 vf_id;			/* Virtual function index */

	/* PF <=> VF mbox */
	struct otx2_mbox	pfvf_mbox;
	struct work_struct	pfvf_mbox_work;
	struct workqueue_struct *pfvf_mbox_wq;
};

#endif /* __OTX2_CPTVF_H */
