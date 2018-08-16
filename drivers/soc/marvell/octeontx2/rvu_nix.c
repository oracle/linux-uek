// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/pci.h>

#include "rvu_struct.h"
#include "rvu_reg.h"
#include "rvu.h"
#include "cgx.h"

static int nix_aq_init(struct rvu *rvu, struct rvu_block *block)
{
	u64 cfg;
	int err;

	/* Set admin queue endianness */
	cfg = rvu_read64(rvu, block->addr, NIX_AF_CFG);
#ifdef __BIG_ENDIAN
	cfg |= BIT_ULL(1);
	rvu_write64(rvu, block->addr, NIX_AF_CFG, cfg);
#else
	cfg &= ~BIT_ULL(1);
	rvu_write64(rvu, block->addr, NIX_AF_CFG, cfg);
#endif

	/* Do not bypass NDC cache */
	cfg = rvu_read64(rvu, block->addr, NIX_AF_NDC_CFG);
	cfg &= ~0x3FFEULL;
	rvu_write64(rvu, block->addr, NIX_AF_NDC_CFG, cfg);

	/* Result structure can be followed by RQ/SQ/CQ context at
	 * RES + 128bytes and a write mask at RES + 256 bytes, depending on
	 * operation type. Alloc sufficient result memory for all operations.
	 */
	err = rvu_aq_alloc(rvu, &block->aq,
			   Q_COUNT(AQ_SIZE), sizeof(struct nix_aq_inst_s),
			   ALIGN(sizeof(struct nix_aq_res_s), 128) + 256);
	if (err)
		return err;

	rvu_write64(rvu, block->addr, NIX_AF_AQ_CFG, AQ_SIZE);
	rvu_write64(rvu, block->addr,
		    NIX_AF_AQ_BASE, (u64)block->aq->inst->iova);
	return 0;
}

int rvu_nix_init(struct rvu *rvu)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	int blkaddr, err;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NIX, 0);
	if (blkaddr < 0)
		return 0;
	block = &hw->block[blkaddr];

	/* Initialize admin queue */
	err = nix_aq_init(rvu, block);
	if (err)
		return err;

	/* Restore CINT timer delay to HW reset values */
	rvu_write64(rvu, blkaddr, NIX_AF_CINT_DELAY, 0x0ULL);

	return 0;
}
