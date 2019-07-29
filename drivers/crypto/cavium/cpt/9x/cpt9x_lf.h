/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CPT9X_LF_H
#define __CPT9X_LF_H

#include "cpt_hw_types.h"
#include "cpt9x_common.h"
#include "cpt_reqmgr.h"

/*
 * CPT instruction and pending queues user requested length in CPT_INST_S msgs
 */
#define CPT_USER_REQUESTED_QLEN_MSGS	8200

/*
 * CPT instruction queue size passed to HW is in units of 40*CPT_INST_S
 * messages.
 *
 * The 96XX HRM (chapter 19.14 CPT LF BAR Registers - CPT_LF_Q_SIZE) states:
 * "The effective queue size to software is ([SIZE_DIV40]-1)*40 CPT_INST_S's"
 */
#define DIV40	40
#define CPT_SIZE_DIV40	((CPT_USER_REQUESTED_QLEN_MSGS + DIV40 - 1)/DIV40)

/*
 * CPT instruction and pending queues length in CPT_INST_S messages
 */
#define CPT_INST_QLEN_MSGS	((CPT_SIZE_DIV40 - 1) * DIV40)

/*
 * CPT instruction queue length in bytes
 */
#define CPT_INST_QLEN_BYTES	(CPT_SIZE_DIV40 * DIV40 * CPT_INST_SIZE)

/*
 * CPT instruction group queue length in bytes
 */
#define CPT_INST_GRP_QLEN_BYTES (CPT_SIZE_DIV40 * 16)

/*
 * CPT FC length in bytes
 */
#define CPT_Q_FC_LEN  128

/*
 * Mask which selects all engine groups
 */
#define ALL_ENG_GRPS_MASK	0xFF

/*
 * Queue priority
 */
#define QUEUE_HI_PRIO	0x1
#define QUEUE_LOW_PRIO	0x0

struct lf_sysfs_cfg {
	char name[NAME_LENGTH];
	struct device_attribute eng_grps_mask_attr;
	struct device_attribute coalesc_tw_attr;
	struct device_attribute coalesc_nw_attr;
	struct device_attribute prio_attr;
#define ATTRS_NUM 5
	struct attribute *attrs[ATTRS_NUM];
	struct attribute_group attr_grp;
	bool is_sysfs_grp_created;
};

struct instruction_queue {
	u8 *vaddr;
	u8 *real_vaddr;
	dma_addr_t dma_addr;
	dma_addr_t real_dma_addr;
	u32 size;
};

struct cptlfs_info;
struct cptlf_wqe {
	struct tasklet_struct work;
	struct cptlfs_info *lfs;
	u8 lf_num;
};

struct cptlf_info {
	struct cptlfs_info *lfs;		/* Ptr to cptlfs_info struct */
	struct lf_sysfs_cfg sysfs_cfg;		/* LF sysfs config entries */
	void *lmtline;				/* Address of LMTLINE */
	void *ioreg;                            /* LMTLINE send register */
	int msix_offset;			/* MSI-X interrupts offset */
	cpumask_var_t affinity_mask;		/* IRQs affinity mask */
	u8 irq_name[CPT_9X_LF_MSIX_VECTORS][32];/* Interrupts name */
	u8 is_irq_reg[CPT_9X_LF_MSIX_VECTORS];  /* Is interrupt registered */
	u8 slot;				/* Slot number of this LF */

	/* Command and pending queues */
	struct instruction_queue iqueue;/* Instruction queue */
	struct pending_queue pqueue;	/* Pending queue */
	struct cptlf_wqe *wqe;		/* Tasklet work info */
};

struct cptlfs_info {
	/* Registers start address of VF/PF LFs are attached to */
	void __iomem *reg_base;
	struct pci_dev *pdev;   /* Device LFs are attached to */
	struct cptlf_info lf[CPT_9X_MAX_LFS_NUM];
	struct reqmgr_ops ops;	/* Request manager operations */
	u8 kcrypto_eng_grp_num;	/* Kernel crypto engine group number */
	u8 are_lfs_attached;	/* Whether CPT LFs are attached */
	u8 lfs_num;		/* Number of CPT LFs */
};

int cptlf_init(struct pci_dev *pdev, void __iomem *reg_base,
	       struct cptlfs_info *lfs, int lfs_num);
int cptlf_shutdown(struct pci_dev *pdev, struct cptlfs_info *lfs);

#endif /* __CPT9X_LF_H */
