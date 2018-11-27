// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CPT8X_PF_H
#define __CPT8X_PF_H

#include "cpt8x_common.h"
#include "cpt_ucode.h"

/**
 * cpt device structure
 */
struct cpt_device {
	void __iomem *reg_base; /* Register start address */
	struct pci_dev *pdev; /* Pci device handle */
	struct engine_groups eng_grps;	/* Engine groups information */
	struct list_head list;
	u32 flags;	/* Flags to hold device status bits */
	u8 pf_type;	/* PF type 83xx_SE or 83xx_AE */
	u8 max_vfs;	/* Maximum number of VFs supported by the CPT */
	u8 vfs_enabled;	/* Number of enabled VFs */
	u8 vfs_in_use;	/* Number of VFs in use */
};

void cpt_mbox_intr_handler(struct cpt_device *cpt, int mbx);
void cpt_disable_all_cores(struct cpt_device *cpt);

#endif /* __CPT8X_PF_H */
