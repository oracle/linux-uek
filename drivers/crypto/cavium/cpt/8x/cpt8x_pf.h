/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX CPT driver
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
#include "octeontx.h"

#define CPT_MAX_VF_NUM	64

struct cptpf_vf {
	struct octeontx_pf_vf domain;
};

/**
 * cpt device structure
 */
struct cpt_device {
	struct cptpf_vf vf[CPT_MAX_VF_NUM]; /* Per VF info */
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
void cpt8x_disable_all_cores(struct cpt_device *cpt);
struct ucode_ops cpt8x_get_ucode_ops(void);

#endif /* __CPT8X_PF_H */
