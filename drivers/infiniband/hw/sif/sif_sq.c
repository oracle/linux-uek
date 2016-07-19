/*
 * Copyright (c) 2014, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_sq.c: Implementation of the send queue side of an IB queue pair
 */

#include <rdma/ib_verbs.h>
#include "sif_dev.h"
#include "sif_base.h"
#include "sif_defs.h"
#include "sif_dma.h"
#include "sif_mmu.h"
#include "sif_pt.h"
#include "sif_mr.h"
#include "sif_qp.h"
#include "sif_sq.h"
#include "sif_hwi.h"
#include "psif_hw_setget.h"
#include <linux/seq_file.h>
#include <linux/slab.h>

/* Figure out the minimal space needed in each send queue element
 * given the input sizes.
 *
 * We also use this space to collapse sg entries if we need to emulate more
 * sg entries in software than what hardware supports.
 *
 * TBD: Note that the SQS sometimes checksums more data
 * (up to 256 bytes depending on max_inline??) which we then cannot use
 * as sg list data area.
 * Note also that no sgl is needed in PSIF for the single sg entry case:
 */

static u32 compute_sq_extent(u32 sge_entries, u32 max_inline_data,
			u32 *sgl_offset, u32 *min_extent_p,
			u32 *sgl_size_p, u32 *max_inline_p)
{
	u32 hw_sge_entries = min_t(u32, SIF_HW_MAX_SEND_SGE, sge_entries);
	u32 sgl_size = sge_entries > 1 ? hw_sge_entries * sizeof(struct psif_wr_local) : 0;
	u32 xsge = sge_entries - hw_sge_entries;

	/* This amount must be reserved for 0-padded inline data due to
	 * restrictions in the SQS:
	 */
	u32 sqs_headroom = min(256U, ((max_inline_data + 63U) & ~63U));
	u32 sqs_inline_extra =
		max_inline_data > sqs_headroom ? max_inline_data - sqs_headroom : 0;

	/* This applies to UD only, with max 4K message size:
	 * Set aside room for inlining of @xsge sg entries.
	 * Average size of an sge entry will be max 256 bytes, add an extra
	 * 256 to handle the case where we cannot use the initial inline space:
	 */
	u32 xsge_space = !xsge ? 0 : (xsge + 2) * 256;

	u32 min_extent = sizeof(struct psif_wr)
		+ sqs_headroom
		+ max(max(sqs_inline_extra, sgl_size), xsge_space);

	u32 real_extent = roundup_pow_of_two(min_extent);

	if (sgl_offset)
		*sgl_offset = real_extent - sgl_size;
	if (sgl_size_p)
		*sgl_size_p = sgl_size;
	if (min_extent_p)
		*min_extent_p = min_extent;
	if (max_inline_p)
		*max_inline_p = max_t(int, xsge_space - sqs_headroom, sqs_inline_extra);
	return real_extent;
}


int sif_alloc_sq(struct sif_dev *sdev, struct sif_pd *pd,
	struct sif_qp *qp, struct ib_qp_cap *cap,
		bool user_mode, int wr_hdl_sz)
{
	/* Send queues always uses same indexes as the corresponding qp */
	int ret = 0;
	int extent_log2;
	struct sif_sq *sq;
	struct sif_sq_sw *sq_sw;
	struct psif_sq_hw *sq_hw_p;
	struct psif_sq_rspq *sq_rspq_p;
	struct psif_sq_sw lsq_sw;
	struct psif_sq_hw lsq_hw;
	struct psif_sq_entry sqe;

	u32 min_entries = cap->max_send_wr;
	u32 max_entries;
	u32 entries_log2;
	u32 min_extent;
	u32 sgl_size;
	u32 max_inline;
	u64 alloc_sz;
	dma_addr_t dma_start;
	bool need_page_aligned;
	bool need_wa_4049 = PSIF_REVISION(sdev) <= 3;


	max_entries = roundup_pow_of_two(max(2U, min_entries));
	entries_log2 = order_base_2(max_entries);

	if (entries_log2 > SIF_SW_MAX_SQE_LOG2) {
		sif_log(sdev, SIF_INFO,
			"requested %d entries -> %d but sif only supports %d",
			cap->max_send_wr, max_entries, SIF_SW_MAX_SQE);
		return -ENFILE; /* Limited by 4 bit size_log2 field in sq desc */
	}

	sq = get_sif_sq(sdev, qp->qp_idx);
	sq_sw = get_sif_sq_sw(sdev, qp->qp_idx);
	sq->index = qp->qp_idx;
	sq->wr_hdl_sz = wr_hdl_sz;

	/* Due to IB standard requirements for ssn = 1 on the first packet
	 * on a QP and that psif now uses send queue sequence number == ssn
	 * we must initialize so the first packet is sent on index 1.
	 * Also the send queue in psif uses last_seq == last used seq instead of
	 * next_seq == next seq to use..
	 * NB! This applies only to the send queue - we start at index 0 on all the others!
	 */
	sq_sw->last_seq = sq_sw->head_seq = 0;

	sq_hw_p = get_sq_hw(sdev, qp->qp_idx);

	sq->entries = max_entries;
	sq->mask = max_entries - 1;
	sq->sg_entries = need_wa_4049 ? roundup_pow_of_two(cap->max_send_sge) : cap->max_send_sge;

	sq->extent = compute_sq_extent(sq->sg_entries, cap->max_inline_data,
				&sq->sgl_offset, &min_extent, &sgl_size, &max_inline);

	qp->max_inline_data = cap->max_inline_data;
	if (sq->extent > min_extent) {
		int extra_extent = sq->extent - min_extent;

		if (sq->sg_entries > SIF_HW_MAX_SEND_SGE) {
			qp->max_inline_data = max_inline + extra_extent;
		} else if (cap->max_inline_data >= 256) {
			sif_log(sdev, SIF_QP, "QP %d has room for %d bytes of extra inline space",
				qp->qp_idx, extra_extent);
			qp->max_inline_data += extra_extent;
		}
	}

	extent_log2 = order_base_2(sq->extent);
	alloc_sz = max_entries * sq->extent;

	/* Only whole pages must be exposed to user space.
	 * For simplicity we impose the same for reliable QPs as their SQs
	 * have to be page aligned to ensure proper access from SQ_CMPL:
	 */
	need_page_aligned = user_mode || is_reliable_qp(qp->type);

	if (need_page_aligned && (alloc_sz & ~PAGE_MASK))
		alloc_sz = (alloc_sz + ~PAGE_MASK) & PAGE_MASK;
	sq->user_mode = user_mode;

	if (alloc_sz <= SIF_MAX_CONT)
		sq->mem = sif_mem_create_dmacont(sdev, alloc_sz, GFP_KERNEL, DMA_BIDIRECTIONAL);
	else {
		alloc_sz = (alloc_sz + ~PMD_MASK) & PMD_MASK;
		sq->mem = sif_mem_create(sdev, alloc_sz >> PMD_SHIFT,
					alloc_sz, SIFMT_2M, GFP_KERNEL | __GFP_ZERO,
					DMA_BIDIRECTIONAL);
	}
	if (!sq->mem) {
		sif_log(sdev, SIF_INFO,	"Failed to allocate %llu bytes of SQ buffer pool",
			alloc_sz);
		ret = -ENOMEM;
		goto err_alloc_dma;
	}

	dma_start = sif_mem_dma(sq->mem, 0);

	sif_log(sdev, SIF_QP, "SQ dma %pad va 0x%p, sz %d, min_extent %d -> extent %d",
		&dma_start, sif_mem_kaddr(sq->mem, 0), sq->entries, min_extent, sq->extent);
	sif_log(sdev, SIF_SQ, "SQ wr sz %ld, sgl_offset/sz %d/%d, max_inline %d, max sge %d",
		sizeof(sqe.wr), sq->sgl_offset, sgl_size,
		qp->max_inline_data, sq->sg_entries);

	sq->wr_hdl = kzalloc(max_entries * sq->wr_hdl_sz, GFP_KERNEL);
	if (!sq->wr_hdl) {
		sif_log(sdev, SIF_INFO, "Failed to allocate wr_hdl table!");
		ret = -ENOMEM;
		goto err_alloc_wrid;
	}

	if (qp->type != PSIF_QP_TRANSPORT_MANSP1 && (qp->max_inline_data || sgl_size)) {
		/* Allocate a DMA validation entry to be used for sif to access
		 * s/g lists, which we put in the spare space between entries
		 * in the send queue. This MR is also used by the SQS to access
		 * inline data.
		 */
		sq->sg_mr = alloc_mr(sdev, pd, sq->mem, dma_start, 0);
		if (IS_ERR(sq->sg_mr)) {
			ret = PTR_ERR(sq->sg_mr);
			sif_log(sdev, SIF_INFO, "Failed to allocate lkey for s/g list (%d)",
				ret);
			goto err_alloc_sg_mr;
		}
	}

	/* Initialize hw part of descriptor */
	memset(&lsq_hw, 0, sizeof(lsq_hw));

	lsq_hw.size_log2 = entries_log2;
	lsq_hw.extent_log2 = extent_log2;
	/* TBD: mmu_context */

	/* See comment above */
	lsq_hw.last_seq = 0;
	lsq_hw.base_addr = dma_start;
	lsq_hw.sq_max_inline = min(256U, qp->max_inline_data);
	lsq_hw.sq_max_sge = sq->sg_entries - 1;

	/* These are needed for sq mode to work */
	lsq_hw.sq_next.next_qp_num = 0xffffff;
	lsq_hw.sq_next.next_null = 0xff;

	/* Allocate mmu context for the send queue - only read access needed
	 * for the queue itself:
	 */
	ret = sif_map_ctx(sdev, &sq->mmu_ctx, sq->mem, lsq_hw.base_addr,
			alloc_sz, false);
	if (ret) {
		sif_log(sdev, SIF_INFO, "Failed to set mmu context for sq %d",
			sq->index);
		goto err_map_ctx;
	}


	lsq_hw.mmu_cntx = sq->mmu_ctx.mctx;

	/* Write network byte order copy */
	copy_conv_to_hw(sq_hw_p, &lsq_hw, sizeof(lsq_hw));

	/* Initialize sw part of descriptor */
	memset(&lsq_sw, 0, sizeof(lsq_sw));

	copy_conv_to_hw(&sq_sw->d, &lsq_sw, sizeof(lsq_sw));

	spin_lock_init(&sq->lock);

	sq_rspq_p = get_sq_rspq(sdev, qp->qp_idx);

	/* We need to set the (network byte order)
	 * fields next_qp_num and rspq_next to all 1's (see bug 3479)
	 * TBD: This needs to be properly set up in psifapi
	 */
	sq_rspq_p->something_tbd[0] = (u64)-1;
	return 0;

	sif_unmap_ctx(sdev, &sq->mmu_ctx);
err_map_ctx:
	if (sq->sg_mr)
		dealloc_mr(sdev, sq->sg_mr);
err_alloc_sg_mr:
	kfree(sq->wr_hdl);
err_alloc_wrid:
	sif_mem_free(sq->mem);
err_alloc_dma:
	return ret;
}


int sif_flush_sqs(struct sif_dev *sdev, struct sif_sq *sq)
{
	ulong start_time = jiffies;
	ulong timeout = start_time + sdev->min_resp_ticks * 2;
	struct sif_qp *qp = get_sif_qp(sdev, sq->index);
	bool sqs_idle = false;
	u32 sq_next;
	u32 prev_sq_next;
	struct psif_wr wr;
	struct sif_sq_sw *sq_sw = get_sif_sq_sw(sdev, sq->index);

	if (qp->ibqp.xrcd) /* XRC target QPs dont have any valid sqs setup */
		return 0;

	memset(&wr, 0, sizeof(struct psif_wr));
	wr.local_qp = sq->index;

	/* Trigger a stop of SQS (rev2 feature) */
	sif_doorbell_write(qp, &wr, false);

	prev_sq_next = sq_next = get_psif_sq_hw__sq_next(&sq->d);

	sif_log(sdev, SIF_SQ, "Entering sq_hw poll for sq %d: last_seq %d head_seq %d sq_next %x",
		sq->index, sq_sw->last_seq, sq_sw->head_seq, sq_next);
	for (;;) {
		if (!sqs_idle) {
			sqs_idle = get_psif_sq_hw__destroyed(&sq->d);
			if (sqs_idle) {
				rmb(); /* Make sure we observe sq_next after the
					* destroyed bit has been set
					*/
				sq_next = get_psif_sq_hw__sq_next(&sq->d);
			}
		}
		if (sqs_idle && sq_next == 0xffffffff)
			break;
		if (sq_next != prev_sq_next) {
			/* Reset timeout */
			timeout = jiffies + sdev->min_resp_ticks * 2;
			sif_log(sdev, SIF_SQ, "sq %d: sq_next moved from %d -> %d",
				sq->index, prev_sq_next, sq_next);
		} else if (time_is_before_jiffies(timeout)) {
			if (sif_feature(pcie_trigger))
				force_pcie_link_retrain(sdev);
			sif_log(sdev, SIF_INFO,
				"Error: sq %d timed out - waited %d ms for SQ flush. Idle:%d sq_next:%x",
				sq->index, jiffies_to_msecs(jiffies - start_time), sqs_idle, sq_next);
			return -ETIMEDOUT;
		}
		/* TBD: No sleep necessary as this should be really quick (?) */
		cpu_relax();
		prev_sq_next = sq_next;
		sq_next = get_psif_sq_hw__sq_next(&sq->d);
	}

	sif_log(sdev, SIF_SQ, " sq %d: done waiting for SQS to finish", sq->index);
	return 0;
}


void sif_free_sq(struct sif_dev *sdev, struct sif_qp *qp)
{
	struct sif_sq *sq = get_sq(sdev, qp);
	volatile struct psif_sq_hw *sq_hw_p;
	volatile struct psif_sq_sw *sq_sw_p;

	if (is_xtgt_qp(qp))
		return;

	sif_log(sdev, SIF_SQ, "idx %d", sq->index);

	sq_sw_p = get_sq_sw(sdev, qp->qp_idx);
	sq_hw_p = &sq->d;

	if (is_reliable_qp(qp->type) && qp->sq_cmpl_map_valid)
		sif_sq_cmpl_unmap_sq(sdev, sq);

	sif_unmap_ctx(sdev, &sq->mmu_ctx);

	/* We clear the whole sq field including sq_hw below */
	sif_clear_sq_sw(sdev, qp->qp_idx);

	if (sq->sg_mr)
		dealloc_mr(sdev, sq->sg_mr);

	sif_mem_free(sq->mem);
	kfree(sq->wr_hdl);
	memset(sq, 0, sizeof(struct sif_sq));
}


/* Setup of the root node(s) of a page table mapping all
 * active send queues:
 */
int sif_sq_cmpl_setup(struct sif_table *tp)
{
	u32 max_sq_extent = compute_sq_extent(16, sif_max_inline,
					NULL, NULL, NULL, NULL);
	struct sif_dev *sdev = tp->sdev;

	tp->ext_sz = SIF_SW_MAX_SQE * max_sq_extent; /* Largest possible send queue */
	tp->table_sz = (size_t)tp->ext_sz * tp->entry_cnt;
	tp->sif_base = SIF_SQ_CMPL_START;
	tp->mem = sif_mem_create_ref(sdev, SIFMT_CS, tp->sif_base, tp->table_sz,
				GFP_KERNEL);

	sif_log(sdev, SIF_SQ, "ext.sz %d entry cnt %d max sq extent 0x%x tbl.sz 0x%lx",
		tp->ext_sz, tp->entry_cnt, max_sq_extent, tp->table_sz);
	return 0;
}


/* Map/unmap the page table of a send queue in the sq_cmpl mapping
 * The way to map it depends on the map type of the send queue itself:
 */
int sif_sq_cmpl_map_sq(struct sif_dev *sdev, struct sif_sq *sq)
{
	struct sif_table *sctp = &sdev->ba[sq_cmpl];

	/* Start offset of this send queue in the large virtual sq_cmpl mapping: */
	u64 virt_base = sctp->mmu_ctx.base + (u64)sq->index * sctp->ext_sz;
	u64 size = sq->mem->size;

	return sif_map_ctx_part(sdev, &sctp->mmu_ctx, sq->mem, virt_base, size);
}


int sif_sq_cmpl_unmap_sq(struct sif_dev *sdev, struct sif_sq *sq)
{
	struct sif_table *sctp = &sdev->ba[sq_cmpl];

	/* Start offset of this send queue in the large virtual sq_cmpl mapping: */
	u64 virt_base = sctp->mmu_ctx.base + (u64)sq->index * sctp->ext_sz;
	u64 size = sq->mem->size;

	sif_log(sdev, SIF_SQ, "sq %d, virt_base 0x%llx size 0x%llx", sq->index, virt_base, size);
	return sif_unmap_gva_ctx_part(sdev, &sctp->mmu_ctx, virt_base, size);
}


void sif_dfs_print_sq_hw(struct seq_file *s, struct sif_dev *sdev, loff_t pos)
{
	struct sif_sq *sq;
	int qlen;
	u32 head, tail;
	struct psif_sq_hw lhw;
	struct sif_sq_sw *sq_sw;
	struct sif_qp *qp;
	int tsv;

	if (unlikely(pos < 0)) {
		seq_puts(s, "# N = next_null, T = sq_timestamp_valid, D = sq_done, X = destroyed\n");
		seq_puts(s, "#                    [----------------------- sw view ----------------------]  [----------- hw view ------------]\n");
		seq_puts(s, "# Index  cq_idx     head     tail     q_sz     q_len    q_high max_sge inline    head    tail   n.qp  N  T  D  X\n");
		return;
	}
	sq = get_sif_sq(sdev, pos);
	sq_sw = get_sif_sq_sw(sdev, pos);
	qp = get_sif_qp(sdev, pos);

	/* Check for QP0/1 which is reserved but not initialized */
	if (sq->entries == 0)
		return;

	head = sq_sw->head_seq;
	tail = sq_sw->last_seq;
	qlen = sq_length(sq, head, tail);

	copy_conv_to_sw(&lhw, &sq->d, sizeof(lhw));
	tsv = lhw.sq_timestamp_valid;

	seq_printf(s, "%7lld %7d %8d %8d %8d %9d %9d %7d %6d %8d%8d %06x %2x  %d  %d  %d\n",
		pos,
		sq->cq_idx, head, tail, sq->entries, qlen, sq->max_outstanding,
		sq->sg_entries, qp->max_inline_data,
		get_psif_sq_sw__tail_indx(&sq_sw->d), lhw.last_seq,
		lhw.sq_next.next_qp_num, lhw.sq_next.next_null,
		tsv, lhw.sq_done, lhw.destroyed);
}


void sif_dfs_print_sq_cmpl(struct seq_file *s, struct sif_dev *sdev, loff_t pos)
{
	struct sif_sq *sq;
	struct sif_qp *qp;
	struct sif_table *sctp = &sdev->ba[sq_cmpl];
	u64 virt_base;
	dma_addr_t val;
	u64 pte_cnt, i;
	dma_addr_t dma_start;
	struct sif_mmu_ctx *ctx = &sctp->mmu_ctx;

	if (unlikely(pos < 0)) {
		u64 table_ptr = sif_pt_dma_root(ctx->pt);

		seq_printf(s, "# - mmu_cntx: root %016llx, level %d\n",
			table_ptr, sctp->mmu_ctx.mctx.table_level);
		seq_puts(s, "# Index  psif vaddr         #pages   @pte[0]          pte[0..]\n");
		return;
	}
	sq = get_sif_sq(sdev, pos);
	qp = get_sif_qp(sdev, pos);
	virt_base = sctp->mmu_ctx.base + (u64)sq->index * sctp->ext_sz;

	/* Check for QP0/1 which is reserved but not initialized */
	if (sq->entries == 0)
		return;

	/* Only QPs with multipacket support is mapped here; */
	if (!is_reliable_qp(qp->type))
		return;

	if (sif_pt_entry(ctx->pt, virt_base, &dma_start, &val))
		return;

	pte_cnt = 1;  /* TBD: read the correct value to report all pages the pt refers to */
	seq_printf(s, " %6lld  %016llx  %6lld  @%pad: [", pos, virt_base, pte_cnt, &dma_start);
	for (i = 0; i < pte_cnt; i++) {
		if (i > 0)
			seq_puts(s, ",");
		seq_printf(s, "%pad", &val);
	}
	seq_puts(s, "]\n");
}
