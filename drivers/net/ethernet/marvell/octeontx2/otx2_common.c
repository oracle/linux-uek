// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Ethernet driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/interrupt.h>
#include <linux/pci.h>

#include "otx2_reg.h"
#include "otx2_common.h"
#include "otx2_struct.h"

static dma_addr_t otx2_alloc_rbuf(struct otx2_nic *pfvf, struct otx2_pool *pool)
{
	dma_addr_t iova;

	/* Check if request can be accommodated in previous allocated page */
	if (pool->page &&
	    ((pool->page_offset + pool->rbsize) <= PAGE_SIZE)) {
		pool->pageref++;
		goto ret;
	}

	otx2_get_page(pool);

	/* Allocate a new page */
	pool->page = alloc_pages(GFP_KERNEL | __GFP_COMP | __GFP_NOWARN, 0);
	if (!pool->page)
		return -ENOMEM;

	pool->page_offset = 0;
ret:
	iova = (u64)dma_map_page_attrs(pfvf->dev, pool->page,
				       pool->page_offset, pool->rbsize,
				       DMA_FROM_DEVICE, DMA_ATTR_SKIP_CPU_SYNC);
	if (dma_mapping_error(pfvf->dev, iova)) {
		if (!pool->page_offset)
			__free_pages(pool->page, 0);
		pool->page = NULL;
		return -ENOMEM;
	}
	pool->page_offset += pool->rbsize;
	return iova;
}

static int otx2_rq_init(struct otx2_nic *pfvf, u16 qidx)
{
	struct nix_aq_enq_req *aq;

	/* Get memory to put this msg */
	aq = otx2_mbox_alloc_msg_NIX_AQ_ENQ(&pfvf->mbox);
	if (!aq)
		return -ENOMEM;

	aq->rq.cq = qidx;
	aq->rq.ena = 1;
	aq->rq.pb_caching = 1;
	aq->rq.lpb_aura = qidx; /* Use large packet buffer aura */
	aq->rq.lpb_sizem1 = (DMA_BUFFER_LEN / 8) - 1;
	aq->rq.xqe_imm_size = 0; /* Copying of packet to CQE not needed */

	/* Fill AQ info */
	aq->qidx = qidx;
	aq->ctype = NIX_AQ_CTYPE_RQ;
	aq->op = NIX_AQ_INSTOP_INIT;

	return otx2_sync_mbox_msg(&pfvf->mbox);
}

static int otx2_sq_init(struct otx2_nic *pfvf, u16 qidx)
{
	struct nix_aq_enq_req *aq;

	/* Get memory to put this msg */
	aq = otx2_mbox_alloc_msg_NIX_AQ_ENQ(&pfvf->mbox);
	if (!aq)
		return -ENOMEM;

	aq->sq.cq = pfvf->hw.rx_queues + qidx;
	aq->sq.max_sqe_size = NIX_MAXSQESZ_W16; /* 128 byte */
	aq->sq.cq_ena = 1;
	aq->sq.ena = 1;
	aq->sq.smq = 0;
	aq->sq.smq_rr_quantum = DMA_BUFFER_LEN / 4;
	aq->sq.default_chan = pfvf->tx_chan_base;
	aq->sq.sqe_stype = NIX_STYPE_STF; /* Cache SQB */
	aq->sq.sqb_aura = pfvf->hw.rx_queues + qidx;

	/* Fill AQ info */
	aq->qidx = qidx;
	aq->ctype = NIX_AQ_CTYPE_SQ;
	aq->op = NIX_AQ_INSTOP_INIT;

	return otx2_sync_mbox_msg(&pfvf->mbox);
}

static int otx2_cq_init(struct otx2_nic *pfvf, u16 qidx)
{
	struct nix_aq_enq_req *aq;

	/* Get memory to put this msg */
	aq = otx2_mbox_alloc_msg_NIX_AQ_ENQ(&pfvf->mbox);
	if (!aq)
		return -ENOMEM;

	aq->cq.ena = 1;
	aq->cq.qsize = Q_SIZE_4K;
	aq->cq.caching = 1;
	aq->cq.base = 1;

	/* Fill AQ info */
	aq->qidx = qidx;
	aq->ctype = NIX_AQ_CTYPE_CQ;
	aq->op = NIX_AQ_INSTOP_INIT;

	return otx2_sync_mbox_msg(&pfvf->mbox);
}

int otx2_config_nix_queues(struct otx2_nic *pfvf)
{
	int qidx, err;

	/* Initialize RX queues */
	for (qidx = 0; qidx < pfvf->hw.rx_queues; qidx++) {
		err = otx2_rq_init(pfvf, qidx);
		if (err)
			return err;
	}

	/* Initialize TX queues */
	for (qidx = 0; qidx < pfvf->hw.tx_queues; qidx++) {
		err = otx2_sq_init(pfvf, qidx);
		if (err)
			return err;
	}

	/* Initialize completion queues */
	for (qidx = 0; qidx < pfvf->qset.cq_cnt; qidx++) {
		err = otx2_cq_init(pfvf, qidx);
		if (err)
			return err;
	}

	return 0;
}

int otx2_config_nix(struct otx2_nic *pfvf)
{
	struct nix_lf_alloc_req  *nixlf;

	pfvf->qset.xqe_size = NIX_XQESZ_W16 ? 128 : 512;

	/* Get memory to put this msg */
	nixlf = otx2_mbox_alloc_msg_NIX_LF_ALLOC(&pfvf->mbox);
	if (!nixlf)
		return -ENOMEM;

	/* Set RQ/SQ/CQ counts */
	nixlf->rq_cnt = pfvf->hw.rx_queues;
	nixlf->sq_cnt = pfvf->hw.tx_queues;
	nixlf->cq_cnt = pfvf->qset.cq_cnt;
	nixlf->xqe_sz = NIX_XQESZ_W16;
	/* We don't know absolute NPA LF idx attached.
	 * AF will replace 'RVU_DEFAULT_PF_FUNC' with
	 * NPA LF attached to this RVU PF/VF.
	 */
	nixlf->npa_func = RVU_DEFAULT_PF_FUNC;
	/* Disable alignment pad, enable L2 length check,
	 * enable L4 TCP/UDP checksum verification.
	 */
	nixlf->rx_cfg = BIT_ULL(33) | BIT_ULL(35) | BIT_ULL(37);

	return otx2_sync_mbox_msg(&pfvf->mbox);
}

static void otx2_aura_pool_free(struct otx2_nic *pfvf)
{
	struct otx2_pool *pool;
	int pool_id;

	if (!pfvf->qset.pool)
		return;

	for (pool_id = 0; pool_id < pfvf->hw.pool_cnt; pool_id++) {
		pool = &pfvf->qset.pool[pool_id];
		qmem_free(pfvf->dev, pool->stack);
		qmem_free(pfvf->dev, pool->fc_addr);
	}
	devm_kfree(pfvf->dev, pfvf->qset.pool);
}

static int otx2_aura_init(struct otx2_nic *pfvf, int aura_id,
			  int pool_id, int numptrs)
{
	struct npa_aq_enq_req *aq;
	struct otx2_pool *pool;
	int err;

	pool = &pfvf->qset.pool[pool_id];

	/* Allocate memory for HW to update Aura count.
	 * Alloc one cache line, so that it fits all FC_STYPE modes.
	 */
	if (!pool->fc_addr) {
		err = qmem_alloc(pfvf->dev, &pool->fc_addr, 1, OTX2_ALIGN);
		if (err)
			return err;
	}

	/* Initialize this aura's context via AF */
	aq = otx2_mbox_alloc_msg_NPA_AQ_ENQ(&pfvf->mbox);
	if (!aq) {
		/* Shared mbox memory buffer is full, flush it and retry */
		err = otx2_sync_mbox_msg(&pfvf->mbox);
		if (err)
			return err;
		aq = otx2_mbox_alloc_msg_NPA_AQ_ENQ(&pfvf->mbox);
		if (!aq)
			return -ENOMEM;
	}

	aq->aura_id = aura_id;
	/* Will be filled by AF with correct pool context address */
	aq->aura.pool_addr = pool_id;
	aq->aura.pool_caching = 1;
	aq->aura.shift = ilog2(numptrs) - 8;
	aq->aura.count = numptrs;
	aq->aura.limit = numptrs;
	aq->aura.ena = 1;
	aq->aura.fc_ena = 1;
	aq->aura.fc_addr = pool->fc_addr->iova;
	aq->aura.fc_hyst_bits = 0; /* Store count on all updates */

	/* Fill AQ info */
	aq->ctype = NPA_AQ_CTYPE_AURA;
	aq->op = NPA_AQ_INSTOP_INIT;

	return 0;
}

static int otx2_pool_init(struct otx2_nic *pfvf, u16 pool_id,
			  int stack_pages, int numptrs, int buf_size)
{
	struct npa_aq_enq_req *aq;
	struct otx2_pool *pool;
	int err;

	pool = &pfvf->qset.pool[pool_id];
	/* Alloc memory for stack which is used to store buffer pointers */
	err = qmem_alloc(pfvf->dev, &pool->stack,
			 stack_pages, pfvf->hw.stack_pg_bytes);
	if (err)
		return err;

	pool->rbsize = buf_size;

	/* Initialize this pool's context via AF */
	aq = otx2_mbox_alloc_msg_NPA_AQ_ENQ(&pfvf->mbox);
	if (!aq) {
		/* Shared mbox memory buffer is full, flush it and retry */
		err = otx2_sync_mbox_msg(&pfvf->mbox);
		if (err) {
			qmem_free(pfvf->dev, pool->stack);
			return err;
		}
		aq = otx2_mbox_alloc_msg_NPA_AQ_ENQ(&pfvf->mbox);
		if (!aq) {
			qmem_free(pfvf->dev, pool->stack);
			return -ENOMEM;
		}
	}

	aq->aura_id = pool_id;
	aq->pool.stack_base = pool->stack->iova;
	aq->pool.stack_caching = 1;
	aq->pool.ena = 1;
	aq->pool.buf_size = buf_size / 128;
	aq->pool.stack_max_pages = stack_pages;
	aq->pool.shift = ilog2(numptrs) - 8;
	aq->pool.ptr_start = 0;
	aq->pool.ptr_end = ~0ULL;

	/* Fill AQ info */
	aq->ctype = NPA_AQ_CTYPE_POOL;
	aq->op = NPA_AQ_INSTOP_INIT;

	return 0;
}

int otx2_sq_aura_pool_init(struct otx2_nic *pfvf)
{
	int pool_id, stack_pages, num_sqbs;
	struct otx2_hw *hw = &pfvf->hw;
	struct otx2_pool *pool;
	int err, ptr;
	s64 bufptr;

	/* Calculate number of SQBs needed.
	 *
	 * For a 128byte SQE, and 4K size SQB, 31 SQEs will fit in one SQB.
	 * Last SQE is used for pointing to next SQB.
	 */
	num_sqbs = (hw->sqb_size / 128) - 1;
	num_sqbs = (SQ_QLEN + num_sqbs) / num_sqbs;

	/* Get no of stack pages needed */
	stack_pages =
		(num_sqbs + hw->stack_pg_ptrs - 1) / hw->stack_pg_ptrs;

	for (pool_id = hw->rx_queues; pool_id < hw->pool_cnt; pool_id++) {
		/* Initialize aura context */
		err = otx2_aura_init(pfvf, pool_id, pool_id, num_sqbs);
		if (err)
			goto fail;

		/* Initialize pool context */
		err = otx2_pool_init(pfvf, pool_id, stack_pages,
				     num_sqbs, hw->sqb_size);
		if (err)
			goto fail;
	}

	/* Flush accumulated messages */
	err = otx2_sync_mbox_msg(&pfvf->mbox);
	if (err)
		goto fail;

	/* Allocate pointers and free them to aura/pool */
	for (pool_id = hw->rx_queues; pool_id < hw->pool_cnt; pool_id++) {
		pool = &pfvf->qset.pool[pool_id];
		for (ptr = 0; ptr < num_sqbs; ptr++) {
			bufptr = otx2_alloc_rbuf(pfvf, pool);
			if (bufptr <= 0)
				return bufptr;
			otx2_aura_freeptr(pfvf, pool_id, bufptr);
		}
		otx2_get_page(pool);
	}

	return 0;
fail:
	otx2_aura_pool_free(pfvf);
	return err;
}

int otx2_rq_aura_pool_init(struct otx2_nic *pfvf)
{
	struct otx2_hw *hw = &pfvf->hw;
	int stack_pages, pool_id;
	struct otx2_pool *pool;
	int err, ptr;
	s64 bufptr;

	stack_pages =
		(RQ_QLEN + hw->stack_pg_ptrs - 1) / hw->stack_pg_ptrs;

	for (pool_id = 0; pool_id < hw->rx_queues; pool_id++) {
		/* Initialize aura context */
		err = otx2_aura_init(pfvf, pool_id, pool_id, RQ_QLEN);
		if (err)
			goto fail;

		err = otx2_pool_init(pfvf, pool_id, stack_pages,
				     RQ_QLEN, RCV_FRAG_LEN);
		if (err)
			goto fail;
	}

	/* Flush accumulated messages */
	err = otx2_sync_mbox_msg(&pfvf->mbox);
	if (err)
		goto fail;

	/* Allocate pointers and free them to aura/pool */
	for (pool_id = 0; pool_id < hw->rx_queues; pool_id++) {
		pool = &pfvf->qset.pool[pool_id];
		for (ptr = 0; ptr < RQ_QLEN; ptr++) {
			bufptr = otx2_alloc_rbuf(pfvf, pool);
			if (bufptr <= 0)
				return bufptr;
			otx2_aura_freeptr(pfvf, pool_id, bufptr);
		}
		otx2_get_page(pool);
	}

	return 0;
fail:
	otx2_aura_pool_free(pfvf);
	return err;
}

int otx2_config_npa(struct otx2_nic *pfvf)
{
	struct otx2_qset *qset = &pfvf->qset;
	struct npa_lf_alloc_req  *npalf;
	struct otx2_hw *hw = &pfvf->hw;
	int aura_cnt;

	/* Pool - Stack of free buffer pointers
	 * Aura - Alloc/frees pointers from/to pool for NIX DMA.
	 */

	/* Rx and Tx queues will have their own aura & pool in a 1:1 config */
	hw->pool_cnt = hw->rx_queues + hw->tx_queues;

	qset->pool = devm_kzalloc(pfvf->dev, sizeof(struct otx2_pool) *
				  hw->pool_cnt, GFP_KERNEL);
	if (!qset->pool)
		return -ENOMEM;

	/* Get memory to put this msg */
	npalf = otx2_mbox_alloc_msg_NPA_LF_ALLOC(&pfvf->mbox);
	if (!npalf)
		return -ENOMEM;

	/* Set aura and pool counts */
	npalf->nr_pools = hw->pool_cnt;
	aura_cnt = ilog2(roundup_pow_of_two(hw->pool_cnt));
	npalf->aura_sz = (aura_cnt >= ilog2(128)) ? (aura_cnt - 6) : 1;

	return otx2_sync_mbox_msg(&pfvf->mbox);
}

int otx2_detach_resources(struct mbox *mbox)
{
	struct rsrc_detach *detach;

	detach = otx2_mbox_alloc_msg_DETACH_RESOURCES(mbox);
	if (!detach)
		return -ENOMEM;

	/* detach all */
	detach->partial = false;

	/* Send detach request to AF */
	otx2_mbox_msg_send(&mbox->mbox, 0);
	return 0;
}

int otx2_attach_npa_nix(struct otx2_nic *pfvf)
{
	struct rsrc_attach *attach;
	struct msg_req *msix;
	int err;

	/* Get memory to put this msg */
	attach = otx2_mbox_alloc_msg_ATTACH_RESOURCES(&pfvf->mbox);
	if (!attach)
		return -ENOMEM;

	attach->npalf = true;
	attach->nixlf = true;

	/* Send attach request to AF */
	err = otx2_sync_mbox_msg(&pfvf->mbox);
	if (err)
		return err;

	/* Get NPA and NIX MSIX vector offsets */
	msix = otx2_mbox_alloc_msg_MSIX_OFFSET(&pfvf->mbox);
	if (!msix)
		return -ENOMEM;

	err = otx2_sync_mbox_msg(&pfvf->mbox);
	if (err)
		return err;

	if (pfvf->hw.npa_msixoff == MSIX_VECTOR_INVALID ||
	    pfvf->hw.nix_msixoff == MSIX_VECTOR_INVALID) {
		dev_err(pfvf->dev,
			"RVUPF: Invalid MSIX vector offset for NPA/NIX\n");
		return -EINVAL;
	}
	return 0;
}

/* Mbox message handlers */
void mbox_handler_NPA_LF_ALLOC(struct otx2_nic *pfvf,
			       struct npa_lf_alloc_rsp *rsp)
{
	pfvf->hw.stack_pg_ptrs = rsp->stack_pg_ptrs;
	pfvf->hw.stack_pg_bytes = rsp->stack_pg_bytes;
}

void mbox_handler_NIX_LF_ALLOC(struct otx2_nic *pfvf,
			       struct nix_lf_alloc_rsp *rsp)
{
	pfvf->hw.sqb_size = rsp->sqb_size;
	pfvf->rx_chan_base = rsp->rx_chan_base;
	pfvf->tx_chan_base = rsp->tx_chan_base;
	ether_addr_copy(pfvf->netdev->dev_addr, rsp->mac_addr);
}

void mbox_handler_MSIX_OFFSET(struct otx2_nic *pfvf,
			      struct msix_offset_rsp *rsp)
{
	pfvf->hw.npa_msixoff = rsp->npa_msixoff;
	pfvf->hw.nix_msixoff = rsp->nix_msixoff;
}

void otx2_disable_msix(struct otx2_nic *pfvf)
{
	struct otx2_hw *hw = &pfvf->hw;
	int irq;

	if (!hw->irq_allocated)
		goto freemem;

	/* Free all registered IRQ handlers */
	for (irq = 0; irq < hw->num_vec; irq++) {
		if (!hw->irq_allocated[irq])
			continue;
		free_irq(pci_irq_vector(hw->pdev, irq), pfvf);
	}

	pci_free_irq_vectors(hw->pdev);

freemem:
	hw->num_vec = 0;
	kfree(hw->irq_allocated);
	kfree(hw->irq_name);
	hw->irq_allocated = NULL;
	hw->irq_name = NULL;
}

int otx2_enable_msix(struct otx2_hw *hw)
{
	int ret;

	hw->num_vec = pci_msix_vec_count(hw->pdev);

	hw->irq_name = kmalloc_array(hw->num_vec, NAME_SIZE, GFP_KERNEL);
	if (!hw->irq_name)
		return -ENOMEM;

	hw->irq_allocated = kcalloc(hw->num_vec, sizeof(bool), GFP_KERNEL);
	if (!hw->irq_allocated) {
		kfree(hw->irq_name);
		return -ENOMEM;
	}

	/* Enable MSI-X */
	ret = pci_alloc_irq_vectors(hw->pdev, hw->num_vec, hw->num_vec,
				    PCI_IRQ_MSIX);
	if (ret < 0) {
		dev_err(&hw->pdev->dev,
			"Request for #%d msix vectors failed, ret %d\n",
			hw->num_vec, ret);
		kfree(hw->irq_allocated);
		kfree(hw->irq_name);
	}

	return 0;
}
