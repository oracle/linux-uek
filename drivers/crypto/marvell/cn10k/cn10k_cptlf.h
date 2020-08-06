/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2020 Marvell.
 */

#ifndef __CN10K_CPTLF_H
#define __CN10K_CPTLF_H

#include "cn10k_cpt_reqmgr.h"

/*
 * CPT instruction and pending queues user requested length in CPT_INST_S msgs
 */
#define CN10K_CPT_USER_REQUESTED_QLEN_MSGS 8200

/*
 * CPT instruction queue size passed to HW is in units of 40*CPT_INST_S
 * messages.
 */
#define CN10K_CPT_SIZE_DIV40 (CN10K_CPT_USER_REQUESTED_QLEN_MSGS/40)

/*
 * CPT instruction and pending queues length in CPT_INST_S messages
 */
#define CN10K_CPT_INST_QLEN_MSGS  ((CN10K_CPT_SIZE_DIV40 - 1) * 40)

/* CPT instruction queue length in bytes */
#define CN10K_CPT_INST_QLEN_BYTES (CN10K_CPT_SIZE_DIV40 * 40 * \
				  CN10K_CPT_INST_SIZE)

/* CPT instruction group queue length in bytes */
#define CN10K_CPT_INST_GRP_QLEN_BYTES (CN10K_CPT_SIZE_DIV40 * 16)

/* CPT FC length in bytes */
#define CN10K_CPT_Q_FC_LEN 128

/* CPT instruction queue alignment */
#define CN10K_CPT_INST_Q_ALIGNMENT  128

/* Mask which selects all engine groups */
#define CN10K_CPT_ALL_ENG_GRPS_MASK 0xFF

/* Queue priority */
#define CN10K_CPT_QUEUE_HI_PRIO  0x1
#define CN10K_CPT_QUEUE_LOW_PRIO 0x0

#define CN10K_CPT_LMTLINE_SIZE  128

enum cn10k_cptlf_state {
	CN10K_CPTLF_IN_RESET,
	CN10K_CPTLF_STARTED,
};

struct cn10k_cptlf_sysfs_cfg {
	char name[CN10K_CPT_NAME_LENGTH];
	struct device_attribute eng_grps_mask_attr;
	struct device_attribute coalesc_tw_attr;
	struct device_attribute coalesc_nw_attr;
	struct device_attribute prio_attr;
#define CN10K_CPT_ATTRS_NUM 5
	struct attribute *attrs[CN10K_CPT_ATTRS_NUM];
	struct attribute_group attr_grp;
	bool is_sysfs_grp_created;
};

struct cn10k_cpt_inst_queue {
	u8 *vaddr;
	u8 *real_vaddr;
	dma_addr_t dma_addr;
	dma_addr_t real_dma_addr;
	u32 size;
};

struct cn10k_cptlfs_info;
struct cn10k_cptlf_wqe {
	struct tasklet_struct work;
	struct cn10k_cptlfs_info *lfs;
	u8 lf_num;
};

struct cn10k_cptlf_info {
	struct cn10k_cptlfs_info *lfs;		/* Ptr to cptlfs_info struct */
	struct cn10k_cptlf_sysfs_cfg sysfs_cfg;	/* LF sysfs config entries */
	void __iomem *lmtline;			/* Address of LMTLINE */
	void __iomem *ioreg;			/* LMTLINE send register */
	int msix_offset;			/* MSI-X interrupts offset */
	cpumask_var_t affinity_mask;		/* IRQs affinity mask */
	u8 irq_name[CN10K_CPT_LF_MSIX_VECTORS][32];/* Interrupts name */
	u8 is_irq_reg[CN10K_CPT_LF_MSIX_VECTORS];  /* Is interrupt registered */
	u8 slot;				/* Slot number of this LF */

	struct cn10k_cpt_inst_queue iqueue;/* Instruction queue */
	struct cn10k_cpt_pending_queue pqueue; /* Pending queue */
	struct cn10k_cptlf_wqe *wqe;	/* Tasklet work info */
};

struct cn10k_cptlfs_info {
	/* Registers start address of VF/PF LFs are attached to */
	void __iomem *reg_base;
	void __iomem *lmtline_base;
	struct pci_dev *pdev;   /* Device LFs are attached to */
	struct cn10k_cptlf_info lf[CN10K_CPT_MAX_LFS_NUM];
	u8 kcrypto_eng_grp_num;	/* Kernel crypto engine group number */
	u8 are_lfs_attached;	/* Whether CPT LFs are attached */
	u8 lfs_num;		/* Number of CPT LFs */
	u8 kcrypto_limits;      /* Kernel crypto limits */
	atomic_t state;         /* LF's state. started/reset */
};

union cn10k_cpt_lmtst_info {
	u64 u;
	struct {
		u64 lmt_id:11;
		u64 reserved11:1;
		u64 burstm1:4;
		u64 reserved_16_18:3;
		u64 size_vec:3;
		u64 reserved_22_63:42;
	};
};

static inline void cn10k_cpt_free_instruction_queues(
					struct cn10k_cptlfs_info *lfs)
{
	struct cn10k_cpt_inst_queue *iq;
	int i;

	for (i = 0; i < lfs->lfs_num; i++) {
		iq = &lfs->lf[i].iqueue;
		if (iq->real_vaddr)
			dma_free_coherent(&lfs->pdev->dev,
					  iq->size,
					  iq->real_vaddr,
					  iq->real_dma_addr);
		iq->real_vaddr = NULL;
		iq->vaddr = NULL;
	}
}

static inline int cn10k_cpt_alloc_instruction_queues(
					struct cn10k_cptlfs_info *lfs)
{
	struct cn10k_cpt_inst_queue *iq;
	int ret = 0, i;

	if (!lfs->lfs_num)
		return -EINVAL;

	for (i = 0; i < lfs->lfs_num; i++) {
		iq = &lfs->lf[i].iqueue;
		iq->size = CN10K_CPT_INST_QLEN_BYTES +
			   CN10K_CPT_Q_FC_LEN +
			   CN10K_CPT_INST_GRP_QLEN_BYTES +
			   CN10K_CPT_INST_Q_ALIGNMENT;
		iq->real_vaddr = dma_alloc_coherent(&lfs->pdev->dev, iq->size,
					&iq->real_dma_addr, GFP_KERNEL);
		if (!iq->real_vaddr) {
			ret = -ENOMEM;
			goto error;
		}
		iq->vaddr = iq->real_vaddr + CN10K_CPT_INST_GRP_QLEN_BYTES;
		iq->dma_addr = iq->real_dma_addr +
			       CN10K_CPT_INST_GRP_QLEN_BYTES;

		/* Align pointers */
		iq->vaddr = PTR_ALIGN(iq->vaddr, CN10K_CPT_INST_Q_ALIGNMENT);
		iq->dma_addr = PTR_ALIGN(iq->dma_addr,
					 CN10K_CPT_INST_Q_ALIGNMENT);
	}

	return 0;
error:
	cn10k_cpt_free_instruction_queues(lfs);
	return ret;
}

static inline void cn10k_cptlf_set_iqueues_base_addr(
					struct cn10k_cptlfs_info *lfs)
{
	union cn10k_cptx_lf_q_base lf_q_base;
	int slot;

	for (slot = 0; slot < lfs->lfs_num; slot++) {
		lf_q_base.u = lfs->lf[slot].iqueue.dma_addr;
		cn10k_cpt_write64(lfs->reg_base, BLKADDR_CPT0, slot,
				  CN10K_CPT_LF_Q_BASE, lf_q_base.u);
	}
}

static inline void cn10k_cptlf_do_set_iqueue_size(struct cn10k_cptlf_info *lf)
{
	union cn10k_cptx_lf_q_size lf_q_size = { .u = 0x0 };

	lf_q_size.s.size_div40 = CN10K_CPT_SIZE_DIV40;
	cn10k_cpt_write64(lf->lfs->reg_base, BLKADDR_CPT0, lf->slot,
			  CN10K_CPT_LF_Q_SIZE, lf_q_size.u);
}

static inline void cn10k_cptlf_set_iqueues_size(struct cn10k_cptlfs_info *lfs)
{
	int slot;

	for (slot = 0; slot < lfs->lfs_num; slot++)
		cn10k_cptlf_do_set_iqueue_size(&lfs->lf[slot]);
}

static inline void cn10k_cptlf_do_disable_iqueue(struct cn10k_cptlf_info *lf)
{
	union cn10k_cptx_lf_ctl lf_ctl = { .u = 0x0 };
	union cn10k_cptx_lf_inprog lf_inprog;
	int timeout = 20;

	/* Disable instructions enqueuing */
	cn10k_cpt_write64(lf->lfs->reg_base, BLKADDR_CPT0, lf->slot,
			  CN10K_CPT_LF_CTL, lf_ctl.u);

	/* Wait for instruction queue to become empty */
	do {
		lf_inprog.u = cn10k_cpt_read64(lf->lfs->reg_base, BLKADDR_CPT0,
					       lf->slot, CN10K_CPT_LF_INPROG);
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
	cn10k_cpt_write64(lf->lfs->reg_base, BLKADDR_CPT0, lf->slot,
			  CN10K_CPT_LF_INPROG, lf_inprog.u);
}

static inline void cn10k_cptlf_disable_iqueues(struct cn10k_cptlfs_info *lfs)
{
	int slot;

	for (slot = 0; slot < lfs->lfs_num; slot++)
		cn10k_cptlf_do_disable_iqueue(&lfs->lf[slot]);
}

static inline void cn10k_cptlf_set_iqueue_enq(struct cn10k_cptlf_info *lf,
					      bool enable)
{
	union cn10k_cptx_lf_ctl lf_ctl;

	lf_ctl.u = cn10k_cpt_read64(lf->lfs->reg_base, BLKADDR_CPT0, lf->slot,
				    CN10K_CPT_LF_CTL);

	/* Set iqueue's enqueuing */
	lf_ctl.s.ena = enable ? 0x1 : 0x0;
	cn10k_cpt_write64(lf->lfs->reg_base, BLKADDR_CPT0, lf->slot,
			  CN10K_CPT_LF_CTL, lf_ctl.u);
}

static inline void cn10k_cptlf_enable_iqueue_enq(struct cn10k_cptlf_info *lf)
{
	cn10k_cptlf_set_iqueue_enq(lf, true);
}

static inline void cn10k_cptlf_set_iqueue_exec(struct cn10k_cptlf_info *lf,
					       bool enable)
{
	union cn10k_cptx_lf_inprog lf_inprog;

	lf_inprog.u = cn10k_cpt_read64(lf->lfs->reg_base, BLKADDR_CPT0,
				       lf->slot, CN10K_CPT_LF_INPROG);

	/* Set iqueue's execution */
	lf_inprog.s.eena = enable ? 0x1 : 0x0;
	cn10k_cpt_write64(lf->lfs->reg_base, BLKADDR_CPT0, lf->slot,
			  CN10K_CPT_LF_INPROG, lf_inprog.u);
}

static inline void cn10k_cptlf_enable_iqueue_exec(struct cn10k_cptlf_info *lf)
{
	cn10k_cptlf_set_iqueue_exec(lf, true);
}

static inline void cn10k_cptlf_disable_iqueue_exec(struct cn10k_cptlf_info *lf)
{
	cn10k_cptlf_set_iqueue_exec(lf, false);
}

static inline void cn10k_cptlf_enable_iqueues(struct cn10k_cptlfs_info *lfs)
{
	int slot;

	for (slot = 0; slot < lfs->lfs_num; slot++) {
		cn10k_cptlf_enable_iqueue_exec(&lfs->lf[slot]);
		cn10k_cptlf_enable_iqueue_enq(&lfs->lf[slot]);
	}
}

static inline void cn10k_cpt_fill_inst(union cn10k_cpt_inst_s *cptinst,
				       struct cn10k_cpt_iq_command *iq_cmd,
				       u64 comp_baddr)
{
	cptinst->u[0] = 0x0;
	cptinst->s.doneint = true;
	cptinst->s.res_addr = comp_baddr;
	cptinst->u[2] = 0x0;
	cptinst->u[3] = 0x0;
	cptinst->s.ei0 = iq_cmd->cmd.u;
	cptinst->s.ei1 = iq_cmd->dptr;
	cptinst->s.ei2 = iq_cmd->rptr;
	cptinst->s.ei3 = iq_cmd->cptr.u;
}

#if defined(CONFIG_ARM64)
static inline void cn10k_lmt_flush(void *ioreg, union cn10k_cpt_lmtst_info info)
{
	__asm__ volatile(".cpu  generic+lse\n"
			 "steorl %0, [%1]\n"
			 :: "r" (info), "r"(ioreg));
}

#else
#define cn10k_lmt_flush(addr)     ({ 0; })
#endif

/*
 * On CN10K platform the parameter insts_num is used as a count of
 * instructions to be enqueued. The valid values for insts_num are:
 * 1 - 1 CPT instruction will be enqueued during LMTST operation
 * 2 - 2 CPT instructions will be enqueued during LMTST operation
 */
static inline void cn10k_cpt_send_cmd(union cn10k_cpt_inst_s *cptinst,
				      u32 insts_num,
				      struct cn10k_cptlf_info *lf)
{
	union cn10k_cpt_lmtst_info info = { .u = 0x0 };
	void __iomem *lmtline = lf->lmtline;
	void __iomem *ioreg = lf->ioreg;

	info.lmt_id = lf->slot;
	/*
	 * PA<6:4> = LMTST size-1 in units of 128 bits. Size of the first
	 *  LMTST in burst.
	 */
	ioreg = (void *)((u64)ioreg |
			 (((CN10K_CPT_INST_SIZE/16) - 1) & 0x7) << 4);
	/*
	 * Make sure memory areas pointed in CPT_INST_S
	 * are flushed before the instruction is sent to CPT
	 */
	dma_wmb();

	/* Copy CPT command to LMTLINE */
	memcpy_toio(lmtline, cptinst, insts_num * CN10K_CPT_INST_SIZE);

	cn10k_lmt_flush(ioreg, info);
}

static inline bool cn10k_cptlf_started(struct cn10k_cptlfs_info *lfs)
{
	return atomic_read(&lfs->state) == CN10K_CPTLF_STARTED;
}

int cn10k_cptvf_lf_init(struct pci_dev *pdev, void *reg_base,
			struct cn10k_cptlfs_info *lfs, int lfs_num);
int cn10k_cptvf_lf_shutdown(struct pci_dev *pdev,
			    struct cn10k_cptlfs_info *lfs);

#endif /* __CN10K_CPTLF_H */
