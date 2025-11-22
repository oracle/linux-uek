// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#include "rvu.h"
#include "rvu_eblock.h"
#include "rvu_eb_sdp.h"

struct sdp_drvdata sdp_data; /*global struct to hold mbox_wqs */

static int rvu_sdp_init_block(struct rvu_block *block, void *data)
{
	struct rvu *rvu = block->rvu;
	int  num_chan;
	int blkaddr;
	u64 regval;

	/* Channel Configuration */
	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_NIX, 0);
	num_chan = rvu_read64(rvu, blkaddr, NIX_AF_CONST1) & 0XFFFUL;
	regval = rvu->hw->sdp_chan_base;
	regval |= ilog2(num_chan) << 16;
	rvu_write64(rvu, block->addr, SDP_AF_LINK_CFG, regval);

	/* BPFLR_D disable clearing BP in FLR */
	regval = rvu_read64(rvu, block->addr, SDP_AF_GBL_CONTROL);
	regval |= (1 << 2);
	rvu_write64(rvu, block->addr, SDP_AF_GBL_CONTROL, regval);

	return 0;
}

static int rvu_setup_sdp_hw_resource(struct rvu_block *block, void *data)
{
	block->type = BLKTYPE_SDP;
	block->addr = BLKADDR_SDP;
	sprintf(block->name, "SDP");
	return 0;
}

static void *rvu_sdp_probe(struct rvu *rvu, int blkaddr)
{
	struct sdp_drvdata *data;

	switch (blkaddr) {
	case BLKADDR_SDP:
		data = devm_kzalloc(rvu->dev, sizeof(struct sdp_drvdata),
				    GFP_KERNEL);
		if (!data)
			return ERR_PTR(-ENOMEM);
		break;
	default:
		data = NULL;
	}

	return data;
}

static void rvu_sdp_remove(struct rvu_block *hwblock, void *data)
{
	devm_kfree(hwblock->rvu->dev, data);
}

static struct rvu_eblock_driver_ops sdp_ops = {
	.probe	= rvu_sdp_probe,
	.remove	= rvu_sdp_remove,
	.init	= rvu_sdp_init_block,
	.setup	= rvu_setup_sdp_hw_resource,
};

void sdp_eb_module_init(void)
{
	rvu_eblock_register_driver(&sdp_ops);
}

void sdp_eb_module_exit(void)
{
	rvu_eblock_unregister_driver(&sdp_ops);
}
