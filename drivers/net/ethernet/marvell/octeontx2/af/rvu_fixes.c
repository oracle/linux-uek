// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kthread.h>
#include <linux/pci.h>
#include <linux/cpu.h>
#include <linux/sched/signal.h>

#include "rvu_struct.h"
#include "rvu_reg.h"
#include "common.h"
#include "mbox.h"
#include "rvu.h"
#include "cgx.h"

int rvu_tim_lookup_rsrc(struct rvu *rvu, struct rvu_block *block,
			u16 pcifunc, int slot)
{
	int lf, blkaddr;
	u64 val;

	/* Due to a HW issue LF_CFG_DEBUG register cannot be used to
	 * find PF_FUNC <=> LF mapping, hence scan through LFX_CFG
	 * registers to find mapped LF for a given PF_FUNC.
	 */
	if (is_rvu_96xx_B0(rvu)) {
		blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_TIM, pcifunc);
		if (blkaddr < 0)
			return TIM_AF_LF_INVALID;

		for (lf = 0; lf < block->lf.max; lf++) {
			val = rvu_read64(rvu, block->addr, block->lfcfg_reg |
					 (lf << block->lfshift));
			if ((((val >> 8) & 0xffff) == pcifunc) &&
			    (val & 0xff) == slot)
				return lf;
		}
		return -1;
	}

	val = ((u64)pcifunc << 24) | (slot << 16) | (1ULL << 13);
	rvu_write64(rvu, block->addr, block->lookup_reg, val);

	/* Wait for the lookup to finish */
	while (rvu_read64(rvu, block->addr, block->lookup_reg) & (1ULL << 13))
		;

	val = rvu_read64(rvu, block->addr, block->lookup_reg);

	/* Check LF valid bit */
	if (!(val & (1ULL << 12)))
		return -1;

	return (val & 0xFFF);
}

void rvu_tim_hw_fixes(struct rvu *rvu, int blkaddr)
{
	u64 cfg;
	/* Due wrong clock gating, TIM expire counter is updated wrongly.
	 * Workaround is to enable force clock (FORCE_CSCLK_ENA = 1).
	 */
	cfg = rvu_read64(rvu, blkaddr, TIM_AF_FLAGS_REG);
	cfg |= BIT_ULL(1);
	rvu_write64(rvu, blkaddr, TIM_AF_FLAGS_REG, cfg);
}
