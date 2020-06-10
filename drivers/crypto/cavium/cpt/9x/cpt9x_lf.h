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

static inline void free_instruction_queues(struct cptlfs_info *lfs)
{
	int i;

	for (i = 0; i < lfs->lfs_num; i++) {
		if (lfs->lf[i].iqueue.real_vaddr)
			dma_free_coherent(&lfs->pdev->dev,
					  lfs->lf[i].iqueue.size,
					  lfs->lf[i].iqueue.real_vaddr,
					  lfs->lf[i].iqueue.real_dma_addr);
		lfs->lf[i].iqueue.real_vaddr = NULL;
		lfs->lf[i].iqueue.vaddr = NULL;
	}
}

static inline int alloc_instruction_queues(struct cptlfs_info *lfs)
{
	int ret = 0, i;

	if (!lfs->lfs_num)
		return -EINVAL;

	for (i = 0; i < lfs->lfs_num; i++) {

		lfs->lf[i].iqueue.size = CPT_INST_QLEN_BYTES + CPT_Q_FC_LEN +
					 CPT_INST_GRP_QLEN_BYTES +
					 CPT_INST_Q_ALIGNMENT;
		lfs->lf[i].iqueue.real_vaddr =
			(u8 *) dma_zalloc_coherent(&lfs->pdev->dev,
					lfs->lf[i].iqueue.size,
					&lfs->lf[i].iqueue.real_dma_addr,
					GFP_KERNEL);
		if (!lfs->lf[i].iqueue.real_vaddr) {
			dev_err(&lfs->pdev->dev,
				"Inst queue allocation failed for LF %d\n", i);
			ret = -ENOMEM;
			goto error;
		}
		lfs->lf[i].iqueue.vaddr = lfs->lf[i].iqueue.real_vaddr +
					  CPT_INST_GRP_QLEN_BYTES;
		lfs->lf[i].iqueue.dma_addr = lfs->lf[i].iqueue.real_dma_addr +
					     CPT_INST_GRP_QLEN_BYTES;

		/* Align pointers */
		lfs->lf[i].iqueue.vaddr =
			(uint8_t *) PTR_ALIGN(lfs->lf[i].iqueue.vaddr,
					      CPT_INST_Q_ALIGNMENT);
		lfs->lf[i].iqueue.dma_addr =
			(dma_addr_t) PTR_ALIGN(lfs->lf[i].iqueue.dma_addr,
					       CPT_INST_Q_ALIGNMENT);
	}

	return 0;
error:
	free_instruction_queues(lfs);
	return ret;
}

static inline void cptlf_set_iqueues_base_addr(struct cptlfs_info *lfs)
{
	u8 blkaddr = cpt_get_blkaddr(lfs->pdev);
	union cptx_lf_q_base lf_q_base;
	int slot;

	for (slot = 0; slot < lfs->lfs_num; slot++) {
		lf_q_base.u = lfs->lf[slot].iqueue.dma_addr;
		cpt_write64(lfs->reg_base, blkaddr, slot, CPT_LF_Q_BASE,
			    lf_q_base.u);
	}
}

static inline void cptlf_do_set_iqueue_size(struct cptlf_info *lf)
{
	union cptx_lf_q_size lf_q_size = { .u = 0x0 };
	u8 blkaddr = cpt_get_blkaddr(lf->lfs->pdev);

	lf_q_size.s.size_div40 = CPT_SIZE_DIV40;
	cpt_write64(lf->lfs->reg_base, blkaddr, lf->slot, CPT_LF_Q_SIZE,
		    lf_q_size.u);
}

static inline void cptlf_set_iqueues_size(struct cptlfs_info *lfs)
{
	int slot;

	for (slot = 0; slot < lfs->lfs_num; slot++)
		cptlf_do_set_iqueue_size(&lfs->lf[slot]);
}

static inline void cptlf_do_disable_iqueue(struct cptlf_info *lf)
{
	u8 blkaddr = cpt_get_blkaddr(lf->lfs->pdev);
	union cptx_lf_ctl lf_ctl = { .u = 0x0 };
	union cptx_lf_inprog lf_inprog;
	int timeout = 20;

	/* Disable instructions enqueuing */
	cpt_write64(lf->lfs->reg_base, blkaddr, lf->slot, CPT_LF_CTL,
		    lf_ctl.u);

	/* Wait for instruction queue to become empty */
	do {
		lf_inprog.u = cpt_read64(lf->lfs->reg_base, blkaddr,
					 lf->slot, CPT_LF_INPROG);
		if (!lf_inprog.s.inflight)
			break;

		usleep_range(10000, 20000);
		if (timeout-- < 0) {
			dev_err(&lf->lfs->pdev->dev,
				"Error LF %d is still busy.\n", lf->slot);
			break;
		}

	} while (1);

	/* Disable executions in the LF's queue,
	 * the queue should be empty at this point
	 */
	lf_inprog.s.eena = 0x0;
	cpt_write64(lf->lfs->reg_base, blkaddr, lf->slot, CPT_LF_INPROG,
		    lf_inprog.u);
}

static inline void cptlf_disable_iqueues(struct cptlfs_info *lfs)
{
	int slot;

	for (slot = 0; slot < lfs->lfs_num; slot++)
		cptlf_do_disable_iqueue(&lfs->lf[slot]);
}

static inline void cptlf_set_iqueue_enq(struct cptlf_info *lf, bool enable)
{
	u8 blkaddr = cpt_get_blkaddr(lf->lfs->pdev);
	union cptx_lf_ctl lf_ctl;

	lf_ctl.u = cpt_read64(lf->lfs->reg_base, blkaddr, lf->slot,
			      CPT_LF_CTL);

	/* Set iqueue's enqueuing */
	lf_ctl.s.ena = enable ? 0x1 : 0x0;
	cpt_write64(lf->lfs->reg_base, blkaddr, lf->slot, CPT_LF_CTL,
		    lf_ctl.u);
}

static inline void cptlf_enable_iqueue_enq(struct cptlf_info *lf)
{
	cptlf_set_iqueue_enq(lf, true);
}

static inline void cptlf_set_iqueue_exec(struct cptlf_info *lf, bool enable)
{
	u8 blkaddr = cpt_get_blkaddr(lf->lfs->pdev);
	union cptx_lf_inprog lf_inprog;

	lf_inprog.u = cpt_read64(lf->lfs->reg_base, blkaddr, lf->slot,
				 CPT_LF_INPROG);

	/* Set iqueue's execution */
	lf_inprog.s.eena = enable ? 0x1 : 0x0;
	cpt_write64(lf->lfs->reg_base, blkaddr, lf->slot, CPT_LF_INPROG,
		    lf_inprog.u);
}

static inline void cptlf_enable_iqueue_exec(struct cptlf_info *lf)
{
	cptlf_set_iqueue_exec(lf, true);
}

static inline void cptlf_disable_iqueue_exec(struct cptlf_info *lf)
{
	cptlf_set_iqueue_exec(lf, false);
}

static inline void cptlf_enable_iqueues(struct cptlfs_info *lfs)
{
	int slot;

	for (slot = 0; slot < lfs->lfs_num; slot++) {
		cptlf_enable_iqueue_exec(&lfs->lf[slot]);
		cptlf_enable_iqueue_enq(&lfs->lf[slot]);
	}
}

int cptlf_init(struct pci_dev *pdev, void __iomem *reg_base,
	       struct cptlfs_info *lfs, int lfs_num);
int cptlf_shutdown(struct pci_dev *pdev, struct cptlfs_info *lfs);

#endif /* __CPT9X_LF_H */
