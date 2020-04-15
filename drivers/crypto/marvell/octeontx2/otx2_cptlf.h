/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __OTX2_CPTLF_H
#define __OTX2_CPTLF_H

#include "otx2_cpt_reqmgr.h"

/*
 * CPT instruction and pending queues user requested length in CPT_INST_S msgs
 */
#define OTX2_CPT_USER_REQUESTED_QLEN_MSGS 8200

/*
 * CPT instruction queue size passed to HW is in units of 40*CPT_INST_S
 * messages.
 */
#define DIV40 40
#define OTX2_CPT_SIZE_DIV40 ((OTX2_CPT_USER_REQUESTED_QLEN_MSGS + \
			      DIV40 - 1)/DIV40)

/*
 * CPT instruction and pending queues length in CPT_INST_S messages
 */
#define OTX2_CPT_INST_QLEN_MSGS	((OTX2_CPT_SIZE_DIV40 - 1) * DIV40)

/* CPT instruction queue length in bytes */
#define OTX2_CPT_INST_QLEN_BYTES (OTX2_CPT_SIZE_DIV40 * DIV40 * \
				  OTX2_CPT_INST_SIZE)

/* CPT instruction group queue length in bytes */
#define OTX2_CPT_INST_GRP_QLEN_BYTES (OTX2_CPT_SIZE_DIV40 * 16)

/* CPT FC length in bytes */
#define OTX2_CPT_Q_FC_LEN 128

/* CPT instruction queue alignment */
#define OTX2_CPT_INST_Q_ALIGNMENT 128

/* Mask which selects all engine groups */
#define OTX2_CPT_ALL_ENG_GRPS_MASK 0xFF

/* Queue priority */
#define OTX2_CPT_QUEUE_HI_PRIO	0x1
#define OTX2_CPT_QUEUE_LOW_PRIO	0x0


struct otx2_cptlf_sysfs_cfg {
	char name[OTX2_CPT_NAME_LENGTH];
	struct device_attribute eng_grps_mask_attr;
	struct device_attribute coalesc_tw_attr;
	struct device_attribute coalesc_nw_attr;
	struct device_attribute prio_attr;
#define ATTRS_NUM 5
	struct attribute *attrs[ATTRS_NUM];
	struct attribute_group attr_grp;
	bool is_sysfs_grp_created;
};

struct otx2_cpt_inst_queue {
	u8 *vaddr;
	u8 *real_vaddr;
	dma_addr_t dma_addr;
	dma_addr_t real_dma_addr;
	u32 size;
};

struct otx2_cptlfs_info;
struct otx2_cptlf_wqe {
	struct tasklet_struct work;
	struct otx2_cptlfs_info *lfs;
	u8 lf_num;
};

struct otx2_cptlf_info {
	struct otx2_cptlfs_info *lfs;		/* Ptr to cptlfs_info struct */
	struct otx2_cptlf_sysfs_cfg sysfs_cfg;	/* LF sysfs config entries */
	void *lmtline;				/* Address of LMTLINE */
	void *ioreg;                            /* LMTLINE send register */
	int msix_offset;			/* MSI-X interrupts offset */
	cpumask_var_t affinity_mask;		/* IRQs affinity mask */
	u8 irq_name[OTX2_CPT_LF_MSIX_VECTORS][32];/* Interrupts name */
	u8 is_irq_reg[OTX2_CPT_LF_MSIX_VECTORS];  /* Is interrupt registered */
	u8 slot;				/* Slot number of this LF */

	struct otx2_cpt_inst_queue iqueue;/* Instruction queue */
	struct otx2_cpt_pending_queue pqueue; /* Pending queue */
	struct otx2_cptlf_wqe *wqe;	/* Tasklet work info */
};

struct otx2_cptlfs_info {
	/* Registers start address of VF/PF LFs are attached to */
	void __iomem *reg_base;
	struct pci_dev *pdev;   /* Device LFs are attached to */
	struct otx2_cptlf_info lf[OTX2_CPT_MAX_LFS_NUM];
	u8 kcrypto_eng_grp_num;	/* Kernel crypto engine group number */
	u8 are_lfs_attached;	/* Whether CPT LFs are attached */
	u8 lfs_num;		/* Number of CPT LFs */
	u8 kcrypto_limits;      /* Kernel crypto limits */
};

static inline void otx2_cpt_free_instruction_queues(
					struct otx2_cptlfs_info *lfs)
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

static inline int otx2_cpt_alloc_instruction_queues(
					struct otx2_cptlfs_info *lfs)
{
	int ret = 0, i;

	if (!lfs->lfs_num)
		return -EINVAL;

	for (i = 0; i < lfs->lfs_num; i++) {

		lfs->lf[i].iqueue.size = OTX2_CPT_INST_QLEN_BYTES +
					 OTX2_CPT_Q_FC_LEN +
					 OTX2_CPT_INST_GRP_QLEN_BYTES +
					 OTX2_CPT_INST_Q_ALIGNMENT;
		lfs->lf[i].iqueue.real_vaddr =
				dma_alloc_coherent(&lfs->pdev->dev,
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
					  OTX2_CPT_INST_GRP_QLEN_BYTES;
		lfs->lf[i].iqueue.dma_addr = lfs->lf[i].iqueue.real_dma_addr +
					     OTX2_CPT_INST_GRP_QLEN_BYTES;

		/* Align pointers */
		lfs->lf[i].iqueue.vaddr =
			(uint8_t *) PTR_ALIGN(lfs->lf[i].iqueue.vaddr,
					      OTX2_CPT_INST_Q_ALIGNMENT);
		lfs->lf[i].iqueue.dma_addr =
			(dma_addr_t) PTR_ALIGN(lfs->lf[i].iqueue.dma_addr,
					       OTX2_CPT_INST_Q_ALIGNMENT);
	}

	return 0;
error:
	otx2_cpt_free_instruction_queues(lfs);
	return ret;
}

static inline void otx2_cptlf_set_iqueues_base_addr(
					struct otx2_cptlfs_info *lfs)
{
	union otx2_cptx_lf_q_base lf_q_base;
	int slot;

	for (slot = 0; slot < lfs->lfs_num; slot++) {
		lf_q_base.u = lfs->lf[slot].iqueue.dma_addr;
		otx2_cpt_write64(lfs->reg_base, BLKADDR_CPT0, slot,
				 OTX2_CPT_LF_Q_BASE, lf_q_base.u);
	}
}

static inline void otx2_cptlf_do_set_iqueue_size(struct otx2_cptlf_info *lf)
{
	union otx2_cptx_lf_q_size lf_q_size = { .u = 0x0 };

	lf_q_size.s.size_div40 = OTX2_CPT_SIZE_DIV40;
	otx2_cpt_write64(lf->lfs->reg_base, BLKADDR_CPT0, lf->slot,
			 OTX2_CPT_LF_Q_SIZE, lf_q_size.u);
}

static inline void otx2_cptlf_set_iqueues_size(struct otx2_cptlfs_info *lfs)
{
	int slot;

	for (slot = 0; slot < lfs->lfs_num; slot++)
		otx2_cptlf_do_set_iqueue_size(&lfs->lf[slot]);
}

static inline void otx2_cptlf_do_disable_iqueue(struct otx2_cptlf_info *lf)
{
	union otx2_cptx_lf_ctl lf_ctl = { .u = 0x0 };
	union otx2_cptx_lf_inprog lf_inprog;
	int timeout = 20;

	/* Disable instructions enqueuing */
	otx2_cpt_write64(lf->lfs->reg_base, BLKADDR_CPT0, lf->slot,
			 OTX2_CPT_LF_CTL, lf_ctl.u);

	/* Wait for instruction queue to become empty */
	do {
		lf_inprog.u = otx2_cpt_read64(lf->lfs->reg_base, BLKADDR_CPT0,
					      lf->slot, OTX2_CPT_LF_INPROG);
		if (!lf_inprog.s.inflight)
			break;

		usleep_range(10000, 20000);
		if (timeout-- < 0) {
			dev_err(&lf->lfs->pdev->dev,
				"Error LF %d is still busy.\n", lf->slot);
			break;
		}

	} while (1);

	/*
	 * Disable executions in the LF's queue,
	 * the queue should be empty at this point
	 */
	lf_inprog.s.eena = 0x0;
	otx2_cpt_write64(lf->lfs->reg_base, BLKADDR_CPT0, lf->slot,
			 OTX2_CPT_LF_INPROG, lf_inprog.u);
}

static inline void otx2_cptlf_disable_iqueues(struct otx2_cptlfs_info *lfs)
{
	int slot;

	for (slot = 0; slot < lfs->lfs_num; slot++)
		otx2_cptlf_do_disable_iqueue(&lfs->lf[slot]);
}

static inline void otx2_cptlf_set_iqueue_enq(struct otx2_cptlf_info *lf,
					     bool enable)
{
	union otx2_cptx_lf_ctl lf_ctl;

	lf_ctl.u = otx2_cpt_read64(lf->lfs->reg_base, BLKADDR_CPT0, lf->slot,
				   OTX2_CPT_LF_CTL);

	/* Set iqueue's enqueuing */
	lf_ctl.s.ena = enable ? 0x1 : 0x0;
	otx2_cpt_write64(lf->lfs->reg_base, BLKADDR_CPT0, lf->slot,
			 OTX2_CPT_LF_CTL, lf_ctl.u);
}

static inline void otx2_cptlf_enable_iqueue_enq(struct otx2_cptlf_info *lf)
{
	otx2_cptlf_set_iqueue_enq(lf, true);
}

static inline void otx2_cptlf_set_iqueue_exec(struct otx2_cptlf_info *lf,
					      bool enable)
{
	union otx2_cptx_lf_inprog lf_inprog;

	lf_inprog.u = otx2_cpt_read64(lf->lfs->reg_base, BLKADDR_CPT0, lf->slot,
				      OTX2_CPT_LF_INPROG);

	/* Set iqueue's execution */
	lf_inprog.s.eena = enable ? 0x1 : 0x0;
	otx2_cpt_write64(lf->lfs->reg_base, BLKADDR_CPT0, lf->slot,
			 OTX2_CPT_LF_INPROG, lf_inprog.u);
}

static inline void otx2_cptlf_enable_iqueue_exec(struct otx2_cptlf_info *lf)
{
	otx2_cptlf_set_iqueue_exec(lf, true);
}

static inline void otx2_cptlf_disable_iqueue_exec(struct otx2_cptlf_info *lf)
{
	otx2_cptlf_set_iqueue_exec(lf, false);
}

static inline void otx2_cptlf_enable_iqueues(struct otx2_cptlfs_info *lfs)
{
	int slot;

	for (slot = 0; slot < lfs->lfs_num; slot++) {
		otx2_cptlf_enable_iqueue_exec(&lfs->lf[slot]);
		otx2_cptlf_enable_iqueue_enq(&lfs->lf[slot]);
	}
}

static inline void otx2_cpt_fill_inst(union otx2_cpt_inst_s *cptinst,
				      struct otx2_cpt_iq_command *iq_cmd,
				      u64 comp_baddr)
{
	cptinst->u[0] = 0x0;
	cptinst->s.doneint = true;
	cptinst->s.res_addr = comp_baddr;
	cptinst->u[2] = 0x0;
	cptinst->u[3] = 0x0;
	cptinst->s.ei0 = iq_cmd->cmd.u64;
	cptinst->s.ei1 = iq_cmd->dptr;
	cptinst->s.ei2 = iq_cmd->rptr;
	cptinst->s.ei3 = iq_cmd->cptr.u64;
}

/*
 * On OcteonTX2 platform the parameter insts_num is used as a count of
 * instructions to be enqueued. The valid values for insts_num are:
 * 1 - 1 CPT instruction will be enqueued during LMTST operation
 * 2 - 2 CPT instructions will be enqueued during LMTST operation
 */
static inline void otx2_cpt_send_cmd(union otx2_cpt_inst_s *cptinst,
				     u32 insts_num, void *obj)
{
	struct otx2_cptlf_info *lf = obj;
	void *lmtline = lf->lmtline;
	void *ioreg = lf->ioreg;
	long ret;

	/*
	 * Make sure memory areas pointed in CPT_INST_S
	 * are flushed before the instruction is sent to CPT
	 */
	smp_wmb();

	do {
		/* Copy CPT command to LMTLINE */
		memcpy(lmtline, cptinst, insts_num * OTX2_CPT_INST_SIZE);

		/*
		 * Make sure compiler does not reorder memcpy and ldeor.
		 * LMTST transactions are always flushed from the write
		 * buffer immediately, a DMB is not required to push out
		 * LMTSTs.
		 */
		barrier();
		/*
		 * LDEOR initiates atomic transfer to I/O device
		 * The following will cause the LMTST to fail (the LDEOR
		 * returns zero):
		 * - No stores have been performed to the LMTLINE since it was
		 * last invalidated.
		 * - The bytes which have been stored to LMTLINE since it was
		 * last invalidated form a pattern that is non-contiguous, does
		 * not start at byte 0, or does not end on a 8-byte boundary.
		 * (i.e.comprises a formation of other than 1–16 8-byte
		 * words.)
		 *
		 * These rules are designed such that an operating system
		 * context switch or hypervisor guest switch need have no
		 * knowledge of the LMTST operations; the switch code does not
		 * need to store to LMTCANCEL. Also note as LMTLINE data cannot
		 * be read, there is no information leakage between processes.
		 */
		__asm__ volatile(
			"  .cpu		generic+lse\n"
			"  ldeor	xzr, %0, [%1]\n"
			: "=r" (ret) : "r" (ioreg) : "memory");
	} while (!ret);
}

int otx2_cptvf_lf_init(struct pci_dev *pdev, void *reg_base,
		       struct otx2_cptlfs_info *lfs, int lfs_num);
int otx2_cptvf_lf_shutdown(struct pci_dev *pdev, struct otx2_cptlfs_info *lfs);

#endif /* __OTX2_CPTLF_H */
