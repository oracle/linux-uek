// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2020 Marvell Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "rvu.h"
#include "rvu_reg.h"

/* Maximum number of REE blocks */
#define MAX_REE_BLKS		2

/* Administrative instruction queue size */
#define REE_AQ_SIZE		128

static void ree_reex_force_clock(struct rvu *rvu, struct rvu_block *block,
				 bool force_on)
{
	u64 reg;

	/* Force ON or OFF for SCLK / RXPCLK */
	reg = rvu_read64(rvu, block->addr, REE_AF_CMD_CTL);
	if (force_on)
		reg = reg | REE_AF_FORCE_CCLK | REE_AF_FORCE_CSCLK;
	else
		reg = reg & ~(REE_AF_FORCE_CCLK | REE_AF_FORCE_CSCLK);
	rvu_write64(rvu, block->addr, REE_AF_CMD_CTL, reg);
}

static int ree_aq_inst_alloc(struct rvu *rvu, struct admin_queue **ad_queue,
			     int qsize, int inst_size, int res_size)
{
	struct admin_queue *aq;
	int err;

	*ad_queue = devm_kzalloc(rvu->dev, sizeof(*aq), GFP_KERNEL);
	if (!*ad_queue)
		return -ENOMEM;
	aq = *ad_queue;

	/* Allocate memory for instructions i.e AQ */
	err = qmem_alloc(rvu->dev, &aq->inst, qsize, inst_size);
	if (err) {
		devm_kfree(rvu->dev, aq);
		return err;
	}

	/* REE AF AQ does not have result and lock is not used */
	aq->res = NULL;

	return 0;
}

static irqreturn_t rvu_ree_af_ras_intr_handler(int irq, void *ptr)
{
	struct rvu_block *block = ptr;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 intr;

	if (blkaddr < 0)
		return IRQ_NONE;

	intr = rvu_read64(block->rvu, blkaddr, REE_AF_RAS);
	if (intr & REE_AF_RAS_DAT_PSN)
		dev_err(rvu->dev, "REE: Poison received on a NCB data response\n");
	if (intr & REE_AF_RAS_LD_CMD_PSN)
		dev_err(rvu->dev, "REE: Poison received on a NCB instruction response\n");
	if (intr & REE_AF_RAS_LD_REEX_PSN)
		dev_err(rvu->dev, "REE: Poison received on a REEX response\n");

	/* Clear interrupts */
	rvu_write64(rvu, blkaddr, REE_AF_RAS, intr);
	return IRQ_HANDLED;
}

static irqreturn_t rvu_ree_af_rvu_intr_handler(int irq, void *ptr)
{
	struct rvu_block *block = ptr;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 intr;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_REE, 0);
	if (blkaddr < 0)
		return IRQ_NONE;

	intr = rvu_read64(rvu, blkaddr, REE_AF_RVU_INT);
	if (intr & REE_AF_RVU_INT_UNMAPPED_SLOT)
		dev_err(rvu->dev, "REE: Unmapped slot error\n");

	/* Clear interrupts */
	rvu_write64(rvu, blkaddr, REE_AF_RVU_INT, intr);
	return IRQ_HANDLED;
}

static irqreturn_t rvu_ree_af_aq_intr_handler(int irq, void *ptr)
{
	struct rvu_block *block = ptr;
	struct rvu *rvu = block->rvu;
	int blkaddr = block->addr;
	u64 intr;

	blkaddr = rvu_get_blkaddr(rvu, BLKTYPE_REE, 0);
	if (blkaddr < 0)
		return IRQ_NONE;

	intr = rvu_read64(rvu, blkaddr, REE_AF_AQ_INT);

	if (intr & REE_AF_AQ_INT_DOVF)
		dev_err(rvu->dev, "REE: DOORBELL overflow\n");
	if (intr & REE_AF_AQ_INT_IRDE)
		dev_err(rvu->dev, "REE: Instruction NCB read response error\n");
	if (intr & REE_AF_AQ_INT_PRDE)
		dev_err(rvu->dev, "REE: Payload NCB read response error\n");
	if (intr & REE_AF_AQ_INT_PLLE)
		dev_err(rvu->dev, "REE: Payload length error\n");

	/* Clear interrupts */
	rvu_write64(rvu, blkaddr, REE_AF_AQ_INT, intr);
	return IRQ_HANDLED;
}

void rvu_ree_unregister_interrupts_block(struct rvu *rvu, int blkaddr)
{
	int i, offs;

	if (!is_block_implemented(rvu->hw, blkaddr))
		return;

	offs = rvu_read64(rvu, blkaddr, REE_PRIV_AF_INT_CFG) & 0x7FF;
	if (!offs) {
		dev_warn(rvu->dev,
			 "Failed to get REE_AF_INT vector offsets");
		return;
	}

	/* Disable all REE AF interrupts */
	rvu_write64(rvu, blkaddr, REE_AF_RAS_ENA_W1C, 0x1);
	rvu_write64(rvu, blkaddr, REE_AF_RVU_INT_ENA_W1C, 0x1);
	rvu_write64(rvu, blkaddr, REE_AF_AQ_DONE_INT_ENA_W1C, 0x1);
	rvu_write64(rvu, blkaddr, REE_AF_AQ_INT_ENA_W1C, 0x1);

	for (i = 0; i < REE_AF_INT_VEC_CNT; i++)
		if (rvu->irq_allocated[offs + i]) {
			free_irq(pci_irq_vector(rvu->pdev, offs + i), rvu);
			rvu->irq_allocated[offs + i] = false;
		}
}

void rvu_ree_unregister_interrupts(struct rvu *rvu)
{
	rvu_ree_unregister_interrupts_block(rvu, BLKADDR_REE0);
	rvu_ree_unregister_interrupts_block(rvu, BLKADDR_REE1);
}

static int rvu_ree_af_request_irq(struct rvu_block *block,
				  int offset, irq_handler_t handler,
				  const char *name)
{
	int ret = 0;
	struct rvu *rvu = block->rvu;

	WARN_ON(rvu->irq_allocated[offset]);
	rvu->irq_allocated[offset] = false;
	sprintf(&rvu->irq_name[offset * NAME_SIZE], name);
	ret = request_irq(pci_irq_vector(rvu->pdev, offset), handler, 0,
			  &rvu->irq_name[offset * NAME_SIZE], block);
	if (ret)
		dev_warn(block->rvu->dev, "Failed to register %s irq\n", name);
	else
		rvu->irq_allocated[offset] = true;

	return rvu->irq_allocated[offset];
}

int rvu_ree_register_interrupts_block(struct rvu *rvu, int blkaddr)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	int offs, ret = 0;

	if (!is_block_implemented(rvu->hw, blkaddr))
		return 0;

	block = &hw->block[blkaddr];

	/* Read interrupt vector */
	offs = rvu_read64(rvu, blkaddr, REE_PRIV_AF_INT_CFG) & 0x7FF;
	if (!offs) {
		dev_warn(rvu->dev,
			 "Failed to get REE_AF_INT vector offsets");
		return 0;
	}

	/* Register and enable RAS interrupt */
	ret = rvu_ree_af_request_irq(block, offs + REE_AF_INT_VEC_RAS,
				     rvu_ree_af_ras_intr_handler,
				     "REEAF RAS");
	if (!ret)
		goto err;
	rvu_write64(rvu, blkaddr, REE_AF_RAS_ENA_W1S, ~0ULL);

	/* Register and enable RVU interrupt */
	ret = rvu_ree_af_request_irq(block, offs + REE_AF_INT_VEC_RVU,
				     rvu_ree_af_rvu_intr_handler,
				     "REEAF RVU");
	if (!ret)
		goto err;
	rvu_write64(rvu, blkaddr, REE_AF_RVU_INT_ENA_W1S, ~0ULL);

	/* QUE DONE */
	/* Interrupt for QUE DONE is not required, software is polling
	 * DONE count to get indication that all instructions are completed
	 */

	/* Register and enable AQ interrupt */
	ret = rvu_ree_af_request_irq(block, offs + REE_AF_INT_VEC_AQ,
				     rvu_ree_af_aq_intr_handler,
				     "REEAF RVU");
	if (!ret)
		goto err;
	rvu_write64(rvu, blkaddr, REE_AF_AQ_INT_ENA_W1S, ~0ULL);

	return 0;
err:
	rvu_ree_unregister_interrupts(rvu);
	return ret;
}

int rvu_ree_register_interrupts(struct rvu *rvu)
{
	int ret;

	ret = rvu_ree_register_interrupts_block(rvu, BLKADDR_REE0);
	if (ret)
		return ret;

	return rvu_ree_register_interrupts_block(rvu, BLKADDR_REE1);
}

static int rvu_ree_init_block(struct rvu *rvu, int blkaddr)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	struct ree_rsrc *ree;
	int err, blkid = 0;
	u64 val;

	if (!is_block_implemented(rvu->hw, blkaddr))
		return 0;

	block = &hw->block[blkaddr];
	if (blkaddr == BLKADDR_REE1)
		blkid = 1;
	ree = &rvu->hw->ree[blkid];

	/* Administrative instruction queue allocation */
	err = ree_aq_inst_alloc(rvu, &block->aq,
				REE_AQ_SIZE,
				sizeof(struct ree_af_aq_inst_s),
				0);
	if (err)
		return err;

	/* Administrative instruction queue address */
	rvu_write64(rvu, block->addr, REE_AF_AQ_SBUF_ADDR,
		    (u64)block->aq->inst->iova);

	/* Move head to start only when a new AQ is allocated and configured.
	 * Otherwise head is wrap around
	 */
	ree->aq_head = 0;

	/* Administrative queue instruction buffer size, in units of 128B
	 * (8 * REE_AF_AQ_INST_S)
	 */
	val = REE_AQ_SIZE >> 3;
	rvu_write64(rvu, block->addr, REE_AF_AQ_SBUF_CTL,
		    (val << REE_AF_AQ_SBUF_CTL_SIZE_SHIFT));

	/* Enable instruction queue */
	rvu_write64(rvu, block->addr, REE_AF_AQ_ENA, 0x1);

	/* Force Clock ON
	 * Force bits should be set throughout the REEX Initialization
	 */
	ree_reex_force_clock(rvu, block, true);

	/* REEX MAIN_CSR configuration */
	rvu_write64(rvu, block->addr, REE_AF_REEXM_MAX_MATCH,
		    REE_AF_REEXM_MAX_MATCH_MAX);
	rvu_write64(rvu, block->addr, REE_AF_REEXM_MAX_PRE_CNT,
		    REE_AF_REEXM_MAX_PRE_CNT_COUNT);
	rvu_write64(rvu, block->addr, REE_AF_REEXM_MAX_PTHREAD_CNT,
		    REE_AF_REEXM_MAX_PTHREAD_COUNT);
	rvu_write64(rvu, block->addr, REE_AF_REEXM_MAX_LATENCY_CNT,
		    REE_AF_REEXM_MAX_LATENCY_COUNT);

	/* REEX Set & Clear MAIN_CSR init */
	rvu_write64(rvu, block->addr, REE_AF_REEXM_CTRL, 0x1);
	rvu_write64(rvu, block->addr, REE_AF_REEXM_CTRL, 0x0);

	/* REEX Poll MAIN_CSR INIT_DONE */
	err = rvu_poll_reg(rvu, block->addr, REE_AF_REEXM_STATUS,
			   BIT_ULL(0), false);
	if (err) {
		dev_err(rvu->dev, "REE reexm poll for init done failed");
		return err;
	}

	/* Force Clock OFF */
	ree_reex_force_clock(rvu, block, false);

	return 0;
}

int rvu_ree_init(struct rvu *rvu)
{
	struct rvu_hwinfo *hw = rvu->hw;

	hw->ree = devm_kcalloc(rvu->dev, MAX_REE_BLKS, sizeof(struct ree_rsrc),
			       GFP_KERNEL);
	if (!hw->ree)
		return -ENOMEM;

	rvu_ree_init_block(rvu, BLKADDR_REE0);
	rvu_ree_init_block(rvu, BLKADDR_REE1);
	return 0;
}

void rvu_ree_freemem_block(struct rvu *rvu, int blkaddr, int blkid)
{
	struct rvu_hwinfo *hw = rvu->hw;
	struct rvu_block *block;
	struct ree_rsrc *ree;
	int i = 0;

	if (!is_block_implemented(rvu->hw, blkaddr))
		return;

	block = &hw->block[blkaddr];
	ree  = &hw->ree[blkid];

	rvu_aq_free(rvu, block->aq);
	if (ree->graph_ctx)
		qmem_free(rvu->dev, ree->graph_ctx);
	if (ree->prefix_ctx)
		qmem_free(rvu->dev, ree->prefix_ctx);
	if (ree->ruledb) {
		for (i = 0; i < ree->ruledb_blocks; i++)
			kfree(ree->ruledb[i]);
		kfree(ree->ruledb);
	}
	kfree(ree->ruledbi);
}

void rvu_ree_freemem(struct rvu *rvu)
{
	rvu_ree_freemem_block(rvu, BLKADDR_REE0, 0);
	rvu_ree_freemem_block(rvu, BLKADDR_REE1, 1);
}
