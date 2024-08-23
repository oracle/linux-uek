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

static const char *ml_irq_name[MAX_ML_BLOCKS][ML_AF_INT_VEC_CNT] = {
	{ "ML0_AF_CORE_INT_LO", "ML0_AF_CORE_INT_HI", "ML0_AF_WRAP_ERR_INT",
	  "ML0_AF_RVU_INT" },
};

struct ml_drvdata {
	int res_idx;
};

static void rvu_ml_unregister_interrupts_block(struct rvu_block *block,
					       void *data);

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

static irqreturn_t rvu_ml_af_core_int_lo_intr_handler(int irq, void *ptr)
{
	struct rvu_block *block = ptr;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 intr;

	if (blkaddr < 0)
		return IRQ_NONE;

	intr = rvu_read64(block->rvu, blkaddr, ML_AF_CORE_INT_LO);
	if (intr & ML_AF_CORE_INT_LO_INT_LO)
		dev_err_ratelimited(rvu->dev,
				    "ML: Low priority interrupt from MLIP\n");

	/* Clear interrupts */
	rvu_write64(rvu, blkaddr, ML_AF_CORE_INT_LO, intr);

	return IRQ_HANDLED;
}

static irqreturn_t rvu_ml_af_core_int_hi_intr_handler(int irq, void *ptr)
{
	struct rvu_block *block = ptr;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 intr;

	if (blkaddr < 0)
		return IRQ_NONE;

	intr = rvu_read64(block->rvu, blkaddr, ML_AF_CORE_INT_HI);
	if (intr & ML_AF_CORE_INT_HI_INT_HI)
		dev_err_ratelimited(rvu->dev,
				    "ML: High priority interrupt from MLIP\n");

	/* Clear interrupts */
	rvu_write64(rvu, blkaddr, ML_AF_CORE_INT_HI, intr);

	return IRQ_HANDLED;
}

static irqreturn_t rvu_ml_af_wrap_err_intr_handler(int irq, void *ptr)
{
	struct rvu_block *block = ptr;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 intr;

	if (blkaddr < 0)
		return IRQ_NONE;

	intr = rvu_read64(block->rvu, blkaddr, ML_AF_WRAP_ERR_INT);
	if (intr & ML_AF_WRAP_ERR_INT_JCEQ_P0_OVFL)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLW Partition 0 job completion queue overflow\n");
	if (intr & ML_AF_WRAP_ERR_INT_JCEQ_P1_OVFL)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLW Partition 1 job completion queue overflow\n");
	if (intr & ML_AF_WRAP_ERR_INT_JCEQ_P2_OVFL)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLW Partition 2 job completion queue overflow\n");
	if (intr & ML_AF_WRAP_ERR_INT_JCEQ_P3_OVFL)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLW Partition 3 job completion queue overflow\n");
	if (intr & ML_AF_WRAP_ERR_INT_ACC_RADDR_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP ACC read request address out of bound\n");
	if (intr & ML_AF_WRAP_ERR_INT_ACC_WADDR_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP ACC write request address out of bound.\n");
	if (intr & ML_AF_WRAP_ERR_INT_ACC_NCB_RRESP_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP ACC read response error from NCB bus.\n");
	if (intr & ML_AF_WRAP_ERR_INT_ACC_NCB_WRESP_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP ACC write response error from NCB bus\n");
	if (intr & ML_AF_WRAP_ERR_INT_ACC_CSR_RRESP_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP ACC read response error from CSR bus\n");
	if (intr & ML_AF_WRAP_ERR_INT_ACC_CSR_WRESP_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP ACC write response error from CSR bus\n");
	if (intr & ML_AF_WRAP_ERR_INT_DMA_RADDR_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP DMA read request address out of bound\n");
	if (intr & ML_AF_WRAP_ERR_INT_DMA_WADDR_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP DMA write request address out of bound\n");
	if (intr & ML_AF_WRAP_ERR_INT_DMA_NCB_RRESP_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP DMA read response error from NCB bus\n");
	if (intr & ML_AF_WRAP_ERR_INT_DMA_NCB_WRESP_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP DMA write response error from NCB bus\n");
	if (intr & ML_AF_WRAP_ERR_INT_DMA_CSR_RRESP_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP DMA read response error from CSR bus\n");
	if (intr & ML_AF_WRAP_ERR_INT_DMA_CSR_WRESP_ERR)
		dev_err_ratelimited(
			rvu->dev,
			"ML: MLIP DMA write response error from CSR bus\n");

	/* Clear interrupts */
	rvu_write64(rvu, blkaddr, ML_AF_WRAP_ERR_INT, intr);

	return IRQ_HANDLED;
}

static irqreturn_t rvu_ml_af_rvu_intr_handler(int irq, void *ptr)
{
	struct rvu_block *block = ptr;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 intr;

	if (blkaddr < 0)
		return IRQ_NONE;

	intr = rvu_read64(block->rvu, blkaddr, ML_AF_RVU_INT);
	if (intr & ML_AF_RVU_INT_UNMAPPED_SLOT)
		dev_err_ratelimited(rvu->dev, "ML: Unmapped slot\n");

	/* Clear interrupts */
	rvu_write64(rvu, blkaddr, ML_AF_RVU_INT, intr);

	return IRQ_HANDLED;
}

static int rvu_ml_af_request_irq(struct rvu_block *block, int offset,
				 irq_handler_t handler, const char *name)
{
	int ret = 0;
	struct rvu *rvu = block->rvu;

	WARN_ON(rvu->irq_allocated[offset]);
	rvu->irq_allocated[offset] = false;
	sprintf(&rvu->irq_name[offset * NAME_SIZE], "%s", name);
	ret = request_irq(pci_irq_vector(rvu->pdev, offset), handler, 0,
			  &rvu->irq_name[offset * NAME_SIZE], block);
	if (ret)
		dev_warn(block->rvu->dev, "Failed to register %s irq\n", name);
	else
		rvu->irq_allocated[offset] = true;

	return rvu->irq_allocated[offset];
}

static int rvu_ml_register_interrupts_block(struct rvu_block *block, void *data)
{
	struct ml_drvdata *drvdata = data;
	int offs, blkid, blkaddr, ret = 0;
	struct rvu *rvu = block->rvu;

	blkid = drvdata->res_idx;
	blkaddr = block->addr;

	/* Read interrupt vector */
	offs = rvu_read64(rvu, blkaddr, ML_PRIV_AF_INT_CFG) & 0x7FF;
	if (!offs) {
		dev_warn(rvu->dev, "Failed to get ML_AF_INT vector offsets");
		return 0;
	}

	/* Register and enable CORE_INT_LO interrupt */
	ret = rvu_ml_af_request_irq(
		block, offs + ML_AF_INT_VEC_CORE_INT_LO,
		rvu_ml_af_core_int_lo_intr_handler,
		ml_irq_name[blkid][ML_AF_INT_VEC_CORE_INT_LO]);
	if (!ret)
		goto err;

	rvu_write64(rvu, blkaddr, ML_AF_CORE_INT_LO_ENA_W1S, ~0ULL);

	/* Register and enable CORE_INT_HI interrupt */
	ret = rvu_ml_af_request_irq(
		block, offs + ML_AF_INT_VEC_CORE_INT_HI,
		rvu_ml_af_core_int_hi_intr_handler,
		ml_irq_name[blkid][ML_AF_INT_VEC_CORE_INT_HI]);
	if (!ret)
		goto err;

	rvu_write64(rvu, blkaddr, ML_AF_CORE_INT_HI_ENA_W1S, ~0ULL);

	/* Register and enable WRAP_ERR_INT interrupt */
	ret = rvu_ml_af_request_irq(
		block, offs + ML_AF_INT_VEC_WRAP_ERR_INT,
		rvu_ml_af_wrap_err_intr_handler,
		ml_irq_name[blkid][ML_AF_INT_VEC_WRAP_ERR_INT]);
	if (!ret)
		goto err;

	rvu_write64(rvu, blkaddr, ML_AF_WRAP_ERR_INT_ENA_W1S, ~0ULL);

	/* Register and enable RVU interrupt */
	ret = rvu_ml_af_request_irq(block, offs + ML_AF_INT_VEC_RVU_INT,
				    rvu_ml_af_rvu_intr_handler,
				    ml_irq_name[blkid][ML_AF_INT_VEC_RVU_INT]);
	if (!ret)
		goto err;

	rvu_write64(rvu, blkaddr, ML_AF_RVU_INT_ENA_W1S, ~0ULL);

	return 0;
err:
	rvu_ml_unregister_interrupts_block(block, data);

	return ret;
}

static void rvu_ml_unregister_interrupts_block(struct rvu_block *block,
					       void *data)
{
	int i, offs, blkaddr;
	struct rvu *rvu = block->rvu;

	blkaddr = block->addr;

	offs = rvu_read64(rvu, blkaddr, ML_PRIV_AF_INT_CFG) & 0x7FF;
	if (!offs) {
		dev_warn(rvu->dev, "Failed to get ML_AF_INT vector offsets");
		return;
	}

	/* Disable all ML AF interrupts */
	rvu_write64(rvu, blkaddr, ML_AF_CORE_INT_LO_ENA_W1C, 0x1);
	rvu_write64(rvu, blkaddr, ML_AF_CORE_INT_HI_ENA_W1C, 0x1);
	rvu_write64(rvu, blkaddr, ML_AF_WRAP_ERR_INT_ENA_W1C, 0x1);
	rvu_write64(rvu, blkaddr, ML_AF_RVU_INT_ENA_W1C, 0x1);

	for (i = 0; i < ML_AF_INT_VEC_CNT; i++) {
		if (rvu->irq_allocated[offs + i]) {
			free_irq(pci_irq_vector(rvu->pdev, offs + i), block);
			rvu->irq_allocated[offs + i] = false;
		}
	}
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
