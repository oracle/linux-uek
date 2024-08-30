// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#include <linux/module.h>
#include <linux/pci.h>

#include "../rvu.h"
#include "rvu_eblock.h"
#include "reg.h"
#include "rvum.h"
#include "api.h"

int rvu_cn20k_get_blk_addr(struct rvu *rvu, int blktype,
			   int devnum, bool is_pf)
{
	u64 reg, val;

	reg = is_pf ? RVU_PRIV_PFX_DISC(devnum) : RVU_PRIV_HWVFX_DISC(devnum);
	val = rvu_read64(rvu, BLKADDR_RVUM, reg);

	switch (blktype) {
	case BLKTYPE_NIX:
		if (val & BIT_ULL(BLKADDR_NIX0))
			return BLKADDR_NIX0;
		else
			return BLKADDR_NIX1;
	case BLKTYPE_CPT:
		if (val & BIT_ULL(BLKADDR_CPT0))
			return BLKADDR_CPT0;
		else
			return BLKADDR_CPT1;
	case BLKTYPE_DPI:
		if (val & BIT_ULL(BLKADDR_DPI0))
			return BLKADDR_DPI0;
		else
			return BLKADDR_DPI1;
	}
	return -ENODEV;
}

void rvu_cn20k_set_blk_bit(struct rvu *rvu, struct rvu_block *block,
			   int devnum, bool is_pf, bool attach)
{
	u64 reg, val;

	reg = is_pf ? RVU_PRIV_PFX_DISC(devnum) : RVU_PRIV_HWVFX_DISC(devnum);
	val = rvu_read64(rvu, BLKADDR_RVUM, reg);
	if (attach)
		val |= BIT_ULL(block->addr);
	else
		val &= ~BIT_ULL(block->addr);

	rvu_write64(rvu, BLKADDR_RVUM, reg, val);
}

void rvu_cn20k_set_af_ready_bit(struct rvu *rvu, bool set)
{
	u64 val;
	int pf;

	/* Notify the PFs about AF status by setting 0th Bit */
	for (pf = 1; pf < rvu->hw->total_pfs; pf++) {
		val = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_PFX_DISC(pf));
		rvu_write64(rvu, BLKADDR_RVUM,
			    RVU_PRIV_PFX_DISC(pf), val | (set ? BIT_ULL(0) : 0x0));
	}
}

void rvu_cn20k_check_block_implemented(struct rvu *rvu)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	int blkid;
	u64 cfg;

	/* For each block check if 'implemented' bit is set */
	cfg = rvupf_read64(rvu, RVU_PF_DISC);
	for (blkid = 0; blkid < BLK_COUNT; blkid++) {
		block = &hw->block[blkid];
		if (cfg & BIT_ULL(blkid)) {
			block->implemented = true;
			rvu_eblock_device_add(rvu, block, blkid);
		}
	}
}

void rvu_cn20k_set_pfvf_cnt(struct rvu *rvu)
{
	struct rvu_hwinfo *hw = rvu->hw;
	u64 cfg;

	/* Get HW supported max RVU PF & VF count */
	cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_CONST);
	hw->max_msix = cfg & 0x1FFFFF;
	hw->total_pfs = (cfg >> 33) & 0xFF;
	hw->total_vfs = (cfg >> 21) & 0xFFF;
	hw->max_vfs_per_pf = (cfg >> 41) & 0xFF;
}

/* Handles FLR interrupts from PFs */
static irqreturn_t cn20k_flr_intr_handler(int irq, void *rvu_irq)
{
	struct rvu *rvu = (struct rvu *)rvu_irq;
	u64 intr[2];
	int idx;
	u8  pf;

	intr[0] = rvu_read64(rvu, BLKADDR_RVUM, RVU_AF_PFFLR_INTX(0));
	intr[1] = rvu_read64(rvu, BLKADDR_RVUM, RVU_AF_PFFLR_INTX(1));

	if (!intr[0] && !intr[1])
		goto afvf_flr;

	for (pf = 0; pf < rvu->hw->total_pfs; pf++) {
		idx = PF_TO_REGIDX(pf);
		if (intr[idx] & (1ULL << pf)) {
			/* clear interrupt */
			rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFFLR_INTX(idx),
				    BIT_ULL(pf));
			/* Disable the interrupt */
			rvu_write64(rvu, BLKADDR_RVUM,
				    RVU_AF_PFFLR_INT_ENA_W1CX(idx),
				    BIT_ULL(pf));
			/* PF is already dead do only AF related operations */
			queue_work(rvu->flr_wq, &rvu->flr_wrk[pf].work);
		}
	}

afvf_flr:
	rvu_afvf_queue_flr_work(rvu, 0, 64);
	if (rvu->vfs > 64)
		rvu_afvf_queue_flr_work(rvu, 64, rvu->vfs - 64);

	return IRQ_HANDLED;
}

/* Handles ME interrupts from PFs */
static irqreturn_t cn20k_me_pf_intr_handler(int irq, void *rvu_irq)
{
	struct rvu *rvu = (struct rvu *)rvu_irq;
	int idx, pfbit;
	u64 intr[2];
	u8  pf;

	intr[0] = rvu_read64(rvu, BLKADDR_RVUM, RVU_AF_PFME_INTX(0));
	intr[1] = rvu_read64(rvu, BLKADDR_RVUM, RVU_AF_PFME_INTX(1));

	/* Nothing to be done here other than clearing the
	 * TRPEND bit.
	 */
	for (pf = 0; pf < rvu->hw->total_pfs; pf++) {
		idx = PF_TO_REGIDX(pf);
		pfbit = pf_to_bitoff(pf);

		if (intr[idx] & (1ULL << pfbit)) {
			/* clear the trpend due to ME(master enable) */
			rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFTRPENDX(idx),
				    BIT_ULL(pfbit));
			/* clear interrupt */
			rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFME_INTX(idx),
				    BIT_ULL(pfbit));
		}
	}

	return IRQ_HANDLED;
}

static inline int flr_me_register_op(struct rvu *rvu, u64 vec, u64 total_pfs,
				     u64 statreg, u64 enreg, char *vecname,
				     void *handler)
{
	u64 en_mask;
	int ret;

	/* Register interrupt handler */
	sprintf(&rvu->irq_name[vec * NAME_SIZE], vecname);
	ret = request_irq(pci_irq_vector(rvu->pdev, vec), handler, 0,
			  &rvu->irq_name[vec * NAME_SIZE], rvu);
	if (ret) {
		dev_err(rvu->dev,
			"RVUAF: IRQ registration failed for %s\n", vecname);
		return ret;
	}
	rvu->irq_allocated[vec] = true;

	/* Clear all pending interrupts */
	rvu_write64(rvu, BLKADDR_RVUM, statreg, INTR_MASK(total_pfs));

	/* Enable interrupt for all PFs except PF0 */
	if (total_pfs > PF_BITMAX) /* Implies PFFLR/ME_INTX(0) */
		en_mask = INTR_MASK(total_pfs) & ~1ULL;
	else
		en_mask = INTR_MASK(total_pfs);

	rvu_write64(rvu, BLKADDR_RVUM, enreg, en_mask);

	return ret;
}

int cn20k_register_flr_me_afpf_interrupts(struct rvu *rvu)
{
	int ret, total_pfs;

	total_pfs = rvu->hw->total_pfs;

	/* Clear TRPEND bit for all PF */
	rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFTRPENDX(0),
		    INTR_MASK(total_pfs));
	rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFTRPENDX(1),
		    INTR_MASK(total_pfs - PF_BITMAX));

	/* Register FLR interrupts */
	ret = flr_me_register_op(rvu, RVU_AF_CN20K_INT_VEC_PFFLR0,
				 total_pfs, RVU_AF_PFFLR_INTX(0),
				 RVU_AF_PFFLR_INT_ENA_W1SX(0), "RVUAF_FLR0",
				 cn20k_flr_intr_handler);
	if (ret)
		return ret;

	ret = flr_me_register_op(rvu, RVU_AF_CN20K_INT_VEC_PFFLR1,
				 total_pfs - PF_BITMAX, RVU_AF_PFFLR_INTX(1),
				 RVU_AF_PFFLR_INT_ENA_W1SX(1), " RVUAF_FLR1",
				 cn20k_flr_intr_handler);
	if (ret)
		return ret;

	/* Register ME interrupts */
	ret = flr_me_register_op(rvu, RVU_AF_CN20K_INT_VEC_PFME0,
				 total_pfs, RVU_AF_PFME_INTX(0),
				 RVU_AF_PFME_INT_ENA_W1SX(0), "RVUAF_ME0",
				 cn20k_me_pf_intr_handler);

	ret = flr_me_register_op(rvu, RVU_AF_CN20K_INT_VEC_PFME1,
				 total_pfs - PF_BITMAX, RVU_AF_PFME_INTX(1),
				 RVU_AF_PFME_INT_ENA_W1SX(1), "RVUAF_ME1",
				 cn20k_me_pf_intr_handler);

	return 0;
}

void cn20k_flr_finish(struct rvu *rvu, int pf)
{
	int idx, pfbit;

	idx = PF_TO_REGIDX(pf);
	pfbit = pf_to_bitoff(pf);

	/* Signal FLR finish */
	rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFTRPENDX(idx), BIT_ULL(pfbit));

	/* Re enable interrupt */
	rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFFLR_INT_ENA_W1SX(idx),
		    BIT_ULL(pfbit));
}

void cn20k_disable_flr_me(struct rvu *rvu)
{
	/* Disable the PF FLR interrupt */
	rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFFLR_INT_ENA_W1CX(0),
		    INTR_MASK(rvu->hw->total_pfs) & ~1ULL);
	rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFFLR_INT_ENA_W1CX(1),
		    INTR_MASK(rvu->hw->total_pfs - PF_BITMAX));

	/* Disable the PF ME interrupt */
	rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFME_INT_ENA_W1CX(0),
		    INTR_MASK(rvu->hw->total_pfs) & ~1ULL);
	rvu_write64(rvu, BLKADDR_RVUM, RVU_AF_PFME_INT_ENA_W1CX(1),
		    INTR_MASK(rvu->hw->total_pfs - PF_BITMAX));
}
