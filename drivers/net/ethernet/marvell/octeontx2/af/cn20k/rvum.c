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
	int pf;

	/* Notify the PFs about AF status by setting 0th Bit */
	for (pf = 1; pf < rvu->hw->total_pfs; pf++)
		rvu_write64(rvu, BLKADDR_RVUM,
			    RVU_PRIV_PFX_DISC(pf), set ? BIT_ULL(0) : 0x00);
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
