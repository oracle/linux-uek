// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU AF ML extension
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#include "rvu.h"
#include "rvu_reg.h"
#include "rvu_eblock.h"
#include "rvu_trace.h"

struct ml_drvdata {
	int res_idx;
};

static int rvu_ml_mbox_handler(struct otx2_mbox *mbox, int devid,
		struct mbox_msghdr *req)
{
	(void) mbox;
	(void) devid;
	(void) req;

	return 0;
}

static int rvu_ml_init_block(struct rvu_block *block, void *data)
{
	(void) block;
	(void) data;

	return 0;
}

static int rvu_setup_ml_hw_resource(struct rvu_block *block, void *data)
{
	(void) block;
	(void) data;

	return 0;
}

static void rvu_ml_freemem_block(struct rvu_block *block, void *data)
{
	(void) block;
	(void) data;
}

static int rvu_ml_register_interrupts_block(struct rvu_block *block, void *data)
{
	(void) block;
	(void) data;

	return 0;
}

static void rvu_ml_unregister_interrupts_block(struct rvu_block *block, void *data)
{
	(void) block;
	(void) data;
}

static void *rvu_ml_probe(struct rvu *rvu, int blkaddr)
{
	struct ml_drvdata *data;
	static int res_idx;

	switch (blkaddr) {
	case BLKADDR_ML:
		data = devm_kzalloc(rvu->dev, sizeof(struct ml_drvdata),
				    GFP_KERNEL);
		if (!data)
			return ERR_PTR(-ENOMEM);

		data->res_idx = res_idx++;
		break;
	default:
		data = NULL;
	}

	return data;
}

static void rvu_ml_remove(struct rvu_block *hwblock, void *data)
{
	devm_kfree(hwblock->rvu->dev, data);
}

struct mbox_op ml_mbox_op = {
	.start = 0xB00,
	.end = 0xBFF,
	.handler = rvu_ml_mbox_handler,
};

static struct rvu_eblock_driver_ops ml_ops = {
	.probe = rvu_ml_probe,
	.remove = rvu_ml_remove,
	.init = rvu_ml_init_block,
	.setup = rvu_setup_ml_hw_resource,
	.free = rvu_ml_freemem_block,
	.register_interrupt = rvu_ml_register_interrupts_block,
	.unregister_interrupt = rvu_ml_unregister_interrupts_block,
	.mbox_op = &ml_mbox_op,
};

void ml_eb_module_init(void)
{
	rvu_eblock_register_driver(&ml_ops);
}

void ml_eb_module_exit(void)
{
	rvu_eblock_unregister_driver(&ml_ops);
}
