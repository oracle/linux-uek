// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU AF ML extension
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#include "rvu.h"
#include "rvu_reg.h"
#include "rvu_eb_ml.h"
#include "rvu_eblock.h"
#include "rvu_eblock_reg.h"
#include "rvu_trace.h"

struct ml_drvdata {
	int res_idx;
};

static int get_ml_pf_num(struct rvu *rvu)
{
	int i, ml_pf_num = -1;
	u64 id_cfg, cfg;
	u8 pf_devid;

	pf_devid = PCI_DEVID_CN20K_ML_PF & 0xFF;
	for (i = 0; i < rvu->hw->total_pfs; i++) {
		cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_PFX_CFG(i));
		if (!(cfg & BIT_ULL(20)))
			continue;

		id_cfg = rvu_read64(rvu, BLKADDR_RVUM, RVU_PRIV_PFX_ID_CFG(i));
		if ((id_cfg & 0xFF) == pf_devid) {
			ml_pf_num = i;
			break;
		}
	}

	return ml_pf_num;
}

static int rvu_ml_mbox_handler(struct otx2_mbox *mbox, int devid,
		struct mbox_msghdr *req)
{
	(void) mbox;
	(void) devid;
	(void) req;

	return 0;
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

static int rvu_ml_init_block(struct rvu_block *block, void *data)
{
	struct rvu *rvu = block->rvu;
	u16 pid;

	(void)data;

	/* Retrieve ML PF number */
	rvu->ml_pf_num = get_ml_pf_num(rvu);

	/* Configure ML_PRIV_AF_CFG register */
	rvu_write64(rvu, block->addr, ML_PRIV_AF_CFG, (rvu->ml_pf_num & 0x2F));

	/* Reset LF and PID map */
	for (pid = 0; pid < ML_MAX_PARTITIONS; pid++)
		rvu_write64(rvu, block->addr, ML_AF_PIDX_LF_ALLOW(pid), 0x0);

	return 0;
}

static int rvu_ml_setup_hw_resource(struct rvu_block *block, void *data)
{
	struct rvu *rvu = block->rvu;
	struct rvu_hwinfo *hw = rvu->hw;
	u64 cfg;
	int err;

	block = &hw->block[BLKADDR_ML];
	if (!block->implemented)
		return 0;

	cfg = rvu_read64(rvu, block->addr, ML_AF_CONST);
	block->lf.max = cfg & 0xFF;
	block->type = BLKTYPE_ML;
	block->multislot = true;
	block->lfshift = 3;
	block->lookup_reg = ML_AF_RVU_LF_CFG_DEBUG;
	block->lfcfg_reg = ML_PRIV_LFX_CFG;
	block->msixcfg_reg = ML_PRIV_LFX_INT_CFG;
	block->lfreset_reg = ML_AF_LF_RST;
	block->rvu = rvu;
	sprintf(block->name, "ML");

	err = rvu_alloc_bitmap(&block->lf);
	if (err) {
		dev_err(rvu->dev, "Failed to allocate ML LF bitmap\n");
		return err;
	}
	/* Allocate memory for block LF/slot to pcifunc mapping info */
	block->fn_map =
		devm_kcalloc(rvu->dev, block->lf.max, sizeof(u16), GFP_KERNEL);
	if (!block->fn_map) {
		err = -ENOMEM;
		goto free_bmap;
	}

	rvu_reset_blk_lfcfg(rvu, block);

	rvu_scan_block(rvu, block);

	return 0;

free_bmap:
	rvu_free_bitmap(&block->lf);

	return err;
}

static void rvu_ml_freemem_block(struct rvu_block *block, void *data)
{
	(void)data;

	rvu_free_bitmap(&block->lf);
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
	.setup = rvu_ml_setup_hw_resource,
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
