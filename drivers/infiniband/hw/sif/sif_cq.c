/*
 * Copyright (c) 2011, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_cq.c: Implementation of completion queue logic for SIF
 */
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/random.h>
#include <rdma/ib_verbs.h>

#include "sif_dev.h"
#include "psif_hw_data.h"
#include "psif_hw_setget.h"
#include "sif_defs.h"
#include "sif_base.h"
#include "sif_mmu.h"
#include "sif_ibcq.h"
#include "sif_cq.h"
#include "sif_hwi.h"
#include "sif_dma.h"
#include "sif_user.h"
#include "sif_qp.h"
#include "sif_pqp.h"
#include "sif_hwi.h"
#include "sif_ibqp.h"
#include <linux/bitmap.h>
#include <linux/seq_file.h>

static inline int translate_wr_id(
	uint64_t *wr_id,
	struct sif_dev *sdev,
	struct sif_cq *cq,
	struct sif_sq *sq,
	struct psif_cq_entry *cqe,
	u32 sq_seq_num, int qpn)
{
	struct sif_sq_hdl *wh = get_sq_hdl(sq, sq_seq_num);

	if (unlikely(!wh)) {
		sif_log(sdev, SIF_INFO,
			"cqe 0x%x for cq %d refers sq(qp) %d (not initialized), sts %d opc 0x%x",
			cqe->seq_num, cq->index, qpn, cqe->status, cqe->opcode);
		return -EFAULT;
	}
	if (!unlikely(wh->used)) {
		if (sq_seq_num == wh->sq_seq)
			sif_log(sdev, SIF_INFO,
			"dupl cqe 0x%x for cq %d: got sq_seq 0x%x, last exp.0x%x, sts %d opc 0x%x",
				cqe->seq_num, cq->index, sq_seq_num, wh->sq_seq,
				cqe->status, cqe->opcode);
		else
			sif_log(sdev, SIF_INFO,
			"unexp. cqe 0x%x for cq %d: got sq_seq 0x%x, last exp.0x%x, sts %d opc 0x%x",
				cqe->seq_num, cq->index, sq_seq_num, wh->sq_seq,
				cqe->status, cqe->opcode);
		return -EFAULT;
	}
	if (unlikely(wh->sq_seq != sq_seq_num)) {
		sif_log(sdev, SIF_INFO,
			"wrong cqe 0x%x for cq %d: got sq_seq 0x%x, expected 0x%x, sts %d opc 0x%x",
			cqe->seq_num, cq->index, sq_seq_num, wh->sq_seq, cqe->status, cqe->opcode);
		return -EFAULT;
	}
	*wr_id = wh->wr_id;
	wh->used = false;

	return 0;
}


struct ib_cq *sif_create_cq(struct ib_device *ibdev, int entries,
			int comp_vector,
			struct ib_ucontext *context,
			struct ib_udata *udata,
			enum sif_proxy_type proxy)
{
	struct sif_cq *cq = NULL;
	struct sif_dev *sdev = to_sdev(ibdev);
	struct sif_ucontext *uc = to_sctx(context);
	struct sif_pd *pd = context ? uc->pd : sdev->pd;
	ulong user_flags = 0;
	bool user_mode = udata != NULL;

	if (entries < 1)
		return ERR_PTR(-EINVAL);

	if (udata) {
		struct sif_create_cq_ext cmd;
		int rv = ib_copy_from_udata(&cmd, udata, sizeof(cmd));

		if (rv)
			return ERR_PTR(rv);
		user_flags = cmd.flags;
		if (sif_vendor_enable(proxy_mode, user_flags))
			proxy = cmd.proxy;
		if (sif_vendor_enable(SVF_kernel_mode, user_flags))
			user_mode = false;
		if (uc->abi_version < 0x0302) /* TBD: Remove - bw comp */
			user_mode = !user_mode;
	}

	cq = create_cq(pd, entries, comp_vector, proxy, user_mode);
	if (IS_ERR(cq))
		return (struct ib_cq *)cq;

	if (udata) {
		struct sif_create_cq_resp_ext resp;
		int ret;

		memset(&resp, 0, sizeof(resp));
		resp.cq_idx = cq->index;
		ret = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (ret) {
			destroy_cq(cq);
			return ERR_PTR(-EFAULT);
		}
	}
	atomic_inc(&sdev->cq_count);
	sif_log(sdev, SIF_CQ, "new cq at %p entries %d (used %d)%s",
		cq, entries, atomic_read(&sdev->cq_count),
		(user_mode ? " (user mode)" : ""));
	return &cq->ibcq;
}


struct sif_cq *create_cq(struct sif_pd *pd, int entries,
			int comp_vector,
			enum sif_proxy_type proxy,
			bool user_mode)
{
	struct sif_dev *sdev = to_sdev(pd->ibpd.device);
	struct sif_cq_sw *cq_sw;
	struct psif_cq_sw lcq_sw;
	struct psif_cq_entry *cqe;
	struct sif_cq *cq;
	struct sif_cq *ecq;
	u32 entries_log2;
	u64 alloc_sz;
	int ret;
	int index = sif_alloc_cq_hw_idx(pd);

	if (index < 0) {
		ecq = ERR_PTR(-ENOMEM);
		goto err_alloc_index;
	}

	cq = get_sif_cq(sdev, index);
	/* Use entries field to determine if entry has been used before */
	if (cq->entries) {
		ret = poll_wait_for_cq_writeback(sdev, cq);
		if (ret)
			return ERR_PTR(ret);
	}

	memset(cq, 0, sizeof(*cq));
	cq->pd = pd;
	cq->index = index;

	cq_sw = get_sif_cq_sw(sdev, index);
	cq_sw->next_seq = 0;
	cq_sw->last_hw_seq = 0;

	/* Make sure we never fill the CQ completely on rev 1-3 - Bug #3657 */
	if (PSIF_REVISION(sdev) <= 3)
		entries++;

	cq->entries = roundup_pow_of_two(entries);
	cq->ibcq.cqe = cq->entries;
	entries_log2 = order_base_2(cq->entries);

	/* Adjust available cqes on rev 1-3 - Bug #3657 */
	if (PSIF_REVISION(sdev) <= 3)
		cq->ibcq.cqe--;

	/* See #2965: 5 bit size_log2 field in cq desc
	 * but counter is 32 bit. For simplicity to distinguish full from empty
	 * SIF can allow allocation of up to 2^30 (size_log2 = 0x1e) entries.
	 * Use the largest value tested, which should be enough
	 *
	 * TBD: Should perhaps limit to some fraction of physical memory available?
	 */
	if (entries_log2 > SIF_SW_MAX_CQE_LOG2) {
		sif_log(sdev, SIF_INFO,
			"requested %d entries -> %d but sif only supports %d",
			entries, cq->entries, 1 << SIF_SW_MAX_CQE_LOG2);
		return ERR_PTR(-ENFILE);
	}

	cq->mask = cq->entries - 1;
	cq->extent = sizeof(struct psif_cq_entry);

	alloc_sz = cq->entries * cq->extent;

	/* Only whole pages must be exposed to user space */
	if (user_mode && (alloc_sz & ~PAGE_MASK))
		alloc_sz = (alloc_sz + PAGE_SIZE) & PAGE_MASK;
	cq->user_mode = user_mode;

	if (alloc_sz <= SIF_MAX_CONT)
		cq->mem = sif_mem_create_dmacont(sdev, alloc_sz, GFP_KERNEL | __GFP_ZERO, DMA_BIDIRECTIONAL);
	else
		cq->mem = sif_mem_create(sdev, alloc_sz >> PMD_SHIFT,
					alloc_sz, SIFMT_2M, GFP_KERNEL | __GFP_ZERO, DMA_BIDIRECTIONAL);
	if (!cq->mem) {
		sif_log(sdev, SIF_INFO,	"Failed to allocate %d CQ entries", entries);
		ecq = ERR_PTR(-ENOMEM);
		goto err_cdt_invalid;
	}

	sif_log(sdev, SIF_CQ, "CQ: hw %p sw %p, base_adr %p, alloc_sz 0x%llx",
		cq, cq_sw, sif_mem_kaddr(cq->mem, 0), alloc_sz);

	/* Since we assume seq.0 as the first valid sequence number,
	 * we must assume that the first entry we poll against is invalid to
	 * start with:
	 */
	cqe = get_cq_entry(cq, 0);
	set_psif_cq_entry__seq_num(cqe, (u32)-1);
	cq->cq_hw.size_log2 = entries_log2;

	/* Prefetch cq_sw when queue is half full: */
	cq->cq_hw.prefetch_threshold_log2 = entries_log2 - 1;

	cq->cq_hw.valid = 1;
	cq->cq_hw.base_addr = sif_mem_dma(cq->mem, 0);
	cq->cq_hw.sequence_number = cq_sw->next_seq;

	if (proxy != SIFPX_OFF) {
		/* This is a proxy CQ */
		cq->cq_hw.proxy_en = 1;
		cq->cq_hw.eps_core = (enum psif_eps_a_core)(proxy - 1);
	}

	/* Allocate mmu context */
	ret = sif_map_ctx(sdev, &cq->mmu_ctx, cq->mem, cq->cq_hw.base_addr,
			alloc_sz, true);
	if (ret) {
		ecq = ERR_PTR(-ENOMEM);
		goto err_map_ctx;
	}

	/* Designate an EQ to this CQ:
	 * Note that the two first queues as seen by the driver in rev2
	 * - index 0 and 1, is reserved for EPSC and async events respectively.
	 * The index here refers to the first "normal" eq, e.g. eq[2] in
	 * driver sense:
	 */
	cq->cq_hw.int_channel = (sif_check_valid_eq_channel(sdev, comp_vector)) ?
		comp_vector : sif_get_eq_channel(sdev, cq);
	cq->eq_idx = cq->cq_hw.int_channel + 2;

	init_completion(&cq->cleanup_ok);
	cq->cq_hw.mmu_cntx = cq->mmu_ctx.mctx;

	copy_conv_to_hw(&cq->d, &cq->cq_hw, sizeof(cq->cq_hw));

	/* Initialize sw part of descriptor */
	memset(&lcq_sw, 0, sizeof(lcq_sw));
	lcq_sw.head_indx = cq_sw->next_seq;
	copy_conv_to_hw(&cq_sw->d, &lcq_sw, sizeof(lcq_sw));

	spin_lock_init(&cq->lock);

	wmb();

	/* to sync with event handling.
	 * NB! Must be the final operation here as there may events
	 * pending that only handles either a fully valid CQ or refcnt == 0
	 */
	atomic_set(&cq->refcnt, 1);

	sif_log(sdev, SIF_CQ, "Exit: success cq %p index %d", cq,
		 cq->index);
	return cq;

err_map_ctx:
	sif_mem_free(cq->mem);
err_cdt_invalid:
	sif_free_cq_hw_idx(pd, cq->index);
err_alloc_index:
	return ecq;
}

int sif_modify_cq(struct ib_cq *ibcq, u16 cq_count, u16 cq_period)
{
	struct sif_dev *sdev = to_sdev(ibcq->device);

	sif_log(sdev, SIF_CQ, "Not implemented");
	return -EOPNOTSUPP;
}


int sif_destroy_cq(struct ib_cq *ibcq)
{
	struct sif_cq *cq = to_scq(ibcq);
	struct sif_dev *sdev = to_sdev(ibcq->device);
	int ret = destroy_cq(cq);

	if (!ret)
		atomic_dec(&sdev->cq_count);
	return ret;
}


int destroy_cq(struct sif_cq *cq)
{
	struct sif_dev *sdev = to_sdev(cq->ibcq.device);
	u32 index = cq->index;
	struct sif_cq_sw *cq_sw = get_sif_cq_sw(sdev, index);
	int ret = 0;
	u32 miss_cnt = cq_sw->miss_cnt;
	u32 miss_occ = cq_sw->miss_occ;

	BUG_ON(atomic_read(&cq->ibcq.usecnt));

	if (cq_sw->miss_cnt) {
		atomic_add(miss_cnt, &sdev->cq_miss_cnt);
		atomic_add(miss_occ, &sdev->cq_miss_occ);
	}

	/* Wait for any in-progress event queue entry for this CQ to be finished */
	if (atomic_dec_and_test(&cq->refcnt))
		complete(&cq->cleanup_ok);
	wait_for_completion(&cq->cleanup_ok);

	ret = sif_invalidate_cq_hw(sdev, index, PCM_WAIT);
	if (ret) {
		sif_log(sdev, SIF_INFO,
			"Releasing index %d in dirty state - ret %d", index, ret);
		return 0;
	}

	ret = sif_release_cq(sdev, index);

	sif_log(sdev, SIF_CQ, "Exit index %d ret %d miss cnt/occ %d/%d",
		index, ret, miss_cnt, miss_occ);
	return ret;
}



int sif_release_cq(struct sif_dev *sdev, int index)
{
	struct sif_cq *cq = get_sif_cq(sdev, index);
	struct sif_pd *pd = cq->pd;
	struct sif_cq_sw *cq_sw = get_sif_cq_sw(sdev, index);

	/* Make sure any completions on the cq TLB invalidate
	 * for priv.qp does arrive before the cq is destroyed..
	 */
	sif_unmap_ctx(sdev, &cq->mmu_ctx);
	sif_mem_free(cq->mem);

	/* Clear sw descriptor - hw descriptor is cleared by hw write-back
	 * We verify that the write-back has been received before making
	 * use of the cq again.
	 */
	memset(cq_sw, 0, sizeof(*cq_sw));

	if (!sif_feature(disable_invalidate_cq))
		sif_free_cq_hw_idx(pd, index);
	return 0;
}


int sif_resize_cq(struct ib_cq *ibcq, int cqe, struct ib_udata *udata)
{
	sif_logi(ibcq->device, SIF_CQ, "Not implemented");
	return -EOPNOTSUPP;
}


/* @cqe contains little endian local copy of the associated
 * completion queue entry
 */
static int handle_send_wc(struct sif_dev *sdev, struct sif_cq *cq,
		struct ib_wc *wc, struct psif_cq_entry *cqe, bool qp_is_destroyed)
{
	/* send queue descriptor aligned with qp */
	struct sif_sq *sq = get_sif_sq(sdev, cqe->qp);
	struct sif_sq_sw *sq_sw = sq ? get_sif_sq_sw(sdev, cqe->qp) : NULL;
	int ret;

	/* This is a full 32 bit seq.num */
	u32 sq_seq_num = cqe->wc_id.sq_id.sq_seq_num;

	if (unlikely(!sq)) {
		sif_log(sdev, SIF_INFO,
			"sq doesn't exists for qp %d", cqe->qp);
		return -EFAULT;
	}

	if (qp_is_destroyed) {
		wc->wr_id = cqe->wc_id.rq_id;

		/* No more work, when QP is gone */
		return 0;
	}

	ret = translate_wr_id(&wc->wr_id, sdev, cq, sq, cqe, sq_seq_num, cqe->qp);
	if (ret)
		return ret;

	wmb();
	/* Update head_seq after we have marked entry as unused since
	 * head_seq is used by post_send in the queue full check:
	 */
	sq_sw->head_seq = sq_seq_num;

	sif_log(sdev, SIF_CQ,
		"wr_id 0x%llx on qp/sq %d sq_seq_num %d",
		wc->wr_id, cqe->qp, sq_seq_num);
	return 0;
}

/* @cqe contains a host endian local copy of the associated
 * completion queue entry.
 */
static struct sif_rq *find_rq(struct sif_dev *sdev, struct sif_cq *cq,
		struct psif_cq_entry *cqe)
{
	struct sif_qp *qp = get_sif_qp(sdev, cqe->qp);

	if (qp->type == PSIF_QP_TRANSPORT_XRC)
		return cq->xsrq;
	else
		return get_sif_rq(sdev, qp->rq_idx);
}

/* @cqe contains a host endian local copy of the associated
 * completion queue entry
 */
static int handle_recv_wc(struct sif_dev *sdev, struct sif_cq *cq, struct ib_wc *wc,
		struct psif_cq_entry *cqe, bool qp_is_destroyed)
{
	struct sif_rq *rq = find_rq(sdev, cq, cqe);
	struct sif_rq_sw *rq_sw = get_sif_rq_sw(sdev, rq->index);
	u32 rq_len;

	wc->wr_id = cqe->wc_id.rq_id;

	/* If no QP, no further work */
	if (qp_is_destroyed)
		return 0;

	rq_len = atomic_dec_return(&rq_sw->length);

	/* WA #622: For Responder Class A & C error, QP should have been
	 * marked in ERROR, flush RQ for remaining posted entries.
	 *
	 * Note: PSIF doesn't generate FLUSH_ERR completions, we see
	 * them due to s/w WA #622, do not flush again.
	 */
	if ((wc->status != IB_WC_WR_FLUSH_ERR) &&
		(wc->status != IB_WC_SUCCESS)) {
		struct sif_qp *qp = to_sqp(wc->qp);

		/* As QP is in ERROR, the only scenario that
		 * rq shouldn't be flushed by SW is when the QP
		 * is in RESET state.
		 */
		if (rq && !rq->is_srq
		    && !test_bit(SIF_QPS_IN_RESET, &qp->persistent_state)) {
			if (sif_flush_rq_wq(sdev, rq, qp, rq_len))
				sif_log(sdev, SIF_INFO,
					"failed to flush RQ %d", rq->index);
		}
	}

	sif_log(sdev, SIF_CQ, "wr_id 0x%llx queue len %d", wc->wr_id, rq_len);
	return 0;
}

static bool fatal_err(enum ib_qp_type type, struct ib_wc *wc)
{
	if (wc->opcode == IB_WC_SEND ||
		wc->opcode == IB_WC_RDMA_WRITE ||
		wc->opcode == IB_WC_RDMA_READ ||
		wc->opcode == IB_WC_COMP_SWAP ||
		wc->opcode == IB_WC_FETCH_ADD ||
		wc->opcode == IB_WC_RECV ||
		wc->opcode == IB_WC_RECV_RDMA_WITH_IMM) {
		switch (type) {
		case IB_QPT_UD:
			return	wc->status == IB_WC_LOC_QP_OP_ERR ||
				wc->status == IB_WC_LOC_PROT_ERR;
		case IB_QPT_RC:
			return  wc->status == IB_WC_LOC_LEN_ERR ||
				wc->status == IB_WC_LOC_QP_OP_ERR ||
				wc->status == IB_WC_LOC_PROT_ERR ||
				wc->status == IB_WC_BAD_RESP_ERR ||
				wc->status == IB_WC_REM_INV_REQ_ERR ||
				wc->status == IB_WC_REM_ACCESS_ERR ||
				wc->status == IB_WC_REM_OP_ERR ||
				wc->status == IB_WC_RETRY_EXC_ERR ||
				wc->status == IB_WC_RNR_RETRY_EXC_ERR;
		case IB_QPT_UC:
			return	wc->status == IB_WC_LOC_QP_OP_ERR;
		default:
			/* Any other supported QP transport? */
			return false;
		}
	} else if (wc->status == IB_WC_FATAL_ERR ||
		wc->status == IB_WC_REM_ABORT_ERR) {
		return true;
	}
	return false;
}

/* Handle a single completion queue entry at pos @head
 */
static int handle_wc(struct sif_dev *sdev, struct sif_cq *cq,
	volatile struct psif_cq_entry *cqe_p, struct ib_wc *wc)
{
	int ret = 0;
	struct psif_cq_entry lcqe;
	struct sif_qp *qp;
	int qpn;
	bool qp_is_destroyed;

	mb();

	/* Read into local copy in host memory and order */
	copy_conv_to_sw(&lcqe, cqe_p, sizeof(lcqe));

	/* Completion status ok - store generic info
	 * in ib_wc
	 */
	qpn = lcqe.qp;

	/* For qp 0/1 decode actual qp index: */
	if (qpn < 2) {
		/* pkey_index only valid for qp 1 */
		if (qpn == IB_QPT_GSI)
			wc->pkey_index = lcqe.pkey_indx;
	       qpn |= (lcqe.port << 1);
	       lcqe.qp = qpn;
	}

	qp = get_sif_qp(sdev, qpn);

	sif_log(sdev, SIF_CQ, "CQ %d: Received cq seqn %d for QP %d opcode %s status %s",
		cq->index, lcqe.seq_num, qpn,
		string_enum_psif_wc_opcode(lcqe.opcode),
		string_enum_psif_wc_status(lcqe.status));

	wc->qp = &qp->ibqp;
	wc->status = sif2ib_wc_status(lcqe.status);
	qp_is_destroyed = lcqe.opcode & SIF_WC_QP_DESTROYED;
	lcqe.opcode &= ~SIF_WC_QP_DESTROYED;
	wc->opcode = sif2ib_wc_opcode(lcqe.opcode);
	wc->wc_flags = 0;

	if (unlikely(is_epsa_tunneling_qp(qp->ibqp.qp_type))) {
		/* if this is EPSA tunneling QP, always return 0. */
		wc->vendor_err = lcqe.vendor_err;
		wc->wr_id = lcqe.wc_id.rq_id;
		return 0;
	}

	if (wc->status != IB_WC_SUCCESS) {
		/*
		 * IBTA: only wr_id, status, qp_num, and vendor_err are valid
		 * when status != SUCCESS.
		 *
		 * Magne 2015-08-25: opcode is also always valid (this
		 * is required in order to deliver wr_id correct for
		 * sends when status != SUCCESS)
		 */

		/* WA #3850: generate LAST_WQE event on SRQ*/
		struct sif_rq *rq = get_rq(sdev, qp);

		int log_level =
			(wc->status == IB_WC_WR_FLUSH_ERR) ? SIF_WCE_V : SIF_WCE;


		if (!qp_is_destroyed && rq && rq->is_srq) {
			if (fatal_err(qp->ibqp.qp_type, wc)) {
				struct ib_event ibe = {
					.device = &sdev->ib_dev,
					.event = IB_EVENT_QP_LAST_WQE_REACHED,
					.element.qp = &qp->ibqp
				};

				if (qp->ibqp.event_handler)
					qp->ibqp.event_handler(&ibe, qp->ibqp.qp_context);
			}
		}

		sif_log(sdev, log_level,
			"Err.compl on cq %d seq %d raw wr_id %lld raw stat %s(%d) sif op %s(0x%x) qp# %d vendor_err 0x%x %s",
			cq->index, lcqe.seq_num, lcqe.wc_id.rq_id,
			string_enum_psif_wc_status(lcqe.status)+15, lcqe.status,
			string_enum_psif_wc_opcode(lcqe.opcode)+15, lcqe.opcode,
			qpn, lcqe.vendor_err, string_enum_psif_tsu_error_types(lcqe.vendor_err));

		sif_logs(SIF_DUMP, write_struct_psif_cq_entry(NULL, 0, &lcqe));
		atomic_inc(&cq->error_cnt);
	}

	/* then handle different types */
	switch (lcqe.opcode) {
	case PSIF_WC_OPCODE_LSO:
	case PSIF_WC_OPCODE_SEND:
	case PSIF_WC_OPCODE_RDMA_WR:
	/* Do send completions pass immd data ? */
	/* Answer: Send completions do not report back immediate data */
	if (lcqe.with_imm)
		wc->wc_flags |= IB_WC_WITH_IMM;
	case PSIF_WC_OPCODE_RDMA_READ:
	case PSIF_WC_OPCODE_CMP_SWAP:
	case PSIF_WC_OPCODE_FETCH_ADD:
		ret = handle_send_wc(sdev, cq, wc, &lcqe, qp_is_destroyed);
		break;
	case PSIF_WC_OPCODE_RECEIVE_SEND:
	case PSIF_WC_OPCODE_RECEIVE_RDMA_WR_IMM:
		/* A heuristic mechanism to determine the traffic pattern. */
		qp->traffic_patterns.mask = (qp->traffic_patterns.mask << 1) &
			HEUR_RX_DIRECTION;
		ret = handle_recv_wc(sdev, cq, wc, &lcqe, qp_is_destroyed);
	if (lcqe.with_imm) {
		wc->ex.imm_data = be32_to_cpu(lcqe.seq_num_imm.imm);
		wc->wc_flags |= IB_WC_WITH_IMM;
	}
		break;

	case PSIF_WC_OPCODE_MASKED_CMP_SWAP:
	case PSIF_WC_OPCODE_MASKED_FETCH_ADD:
	case PSIF_WC_OPCODE_INVALIDATE_RKEY:
	case PSIF_WC_OPCODE_INVALIDATE_LKEY:
	case PSIF_WC_OPCODE_INVALIDATE_BOTH_KEYS:
	case PSIF_WC_OPCODE_INVALIDATE_TLB:
	case PSIF_WC_OPCODE_RESIZE_CQ:
	case PSIF_WC_OPCODE_SET_SRQ_LIM:
	case PSIF_WC_OPCODE_SET_XRCSRQ_LIM:
	case PSIF_WC_OPCODE_CMPL_NOTIFY_RCVD:
	case PSIF_WC_OPCODE_REARM_CMPL_EVENT:
	case PSIF_WC_OPCODE_INVALIDATE_RQ:
	case PSIF_WC_OPCODE_INVALIDATE_CQ:
	case PSIF_WC_OPCODE_INVALIDATE_RB:
	case PSIF_WC_OPCODE_INVALIDATE_XRCSRQ:
	case PSIF_WC_OPCODE_INVALIDATE_SGL_CACHE:
	default:
		sif_log(sdev, SIF_INFO,
			"Unhandled wc opcode %s", string_enum_psif_wc_opcode(lcqe.opcode));
		ret = -EINVAL;
		break;
	}

	/* Need sif2ib_flags() */
	if (lcqe.grh == 1) {
		wc->wc_flags |= IB_WC_GRH;
		sif_log(sdev, SIF_CQ, "GRH present in payload");
	}

	wc->vendor_err = lcqe.vendor_err;
	wc->byte_len = lcqe.byte_len;

	/*
	 * Brian Manula 2-august-2015: src_qp is zero on connected QP transports.
	 *
	 * IBTA: Remote node address and QP. Returned only for Datagram services.
	 */
	wc->src_qp = lcqe.src_qp;
	wc->slid = lcqe.slid;
	wc->sl = lcqe.sl;
	wc->dlid_path_bits = lcqe.dlid_path_bits;
	wc->port_num = lcqe.port + 1; /* Sif port numbers start at 0 */

	if (qp->flags & (SIF_QPF_IPOIB | SIF_QPF_EOIB)) {
		bool do_l3_csum;
		bool do_l4_csum;
		bool csum_l3_ok;
		bool csum_l4_ok;
		bool csum_ok;
		struct psif_offload_info *oinfo;

		oinfo = &lcqe.offload_wc_id.offload;
		do_l3_csum  =
			oinfo->packet_classification_ipv4  ||
			oinfo->packet_classification_ipv6;
		do_l4_csum =
			oinfo->packet_classification_tcp  ||
			oinfo->packet_classification_udp;

		csum_l3_ok = do_l3_csum ? oinfo->l3_checksum_ok : true;
		csum_l4_ok = do_l4_csum ? oinfo->l4_checksum_ok : true;
		csum_ok = csum_l3_ok & csum_l4_ok;

		qp->ipoib_rx_csum_l3_ok  += !!(do_l3_csum &&  csum_l3_ok);
		qp->ipoib_rx_csum_l3_err += !!(do_l3_csum && !csum_l3_ok);

		qp->ipoib_rx_csum_l4_ok  += !!(do_l4_csum &&  csum_l4_ok);
		qp->ipoib_rx_csum_l4_err += !!(do_l4_csum && !csum_l4_ok);
		/* set flag; could be ignored by next level if disabled */
		wc->wc_flags |= (csum_ok) ? IB_WC_IP_CSUM_OK : 0;
		if (!csum_ok) {
			sif_log(sdev,
				SIF_WCE,
				"checksum not ok for ipv4/ipv6 eth2 %d ip4 %d ip6 %d frag %d options %d arp %d arp_reply %d exthdr %d tcp %d udp %d l3_ok %d l4_ok %d",
				oinfo->packet_classification_eth2,
				oinfo->packet_classification_ipv4,
				oinfo->packet_classification_ipv6,
				oinfo->packet_classification_ip_frag,
				oinfo->packet_classification_ip_options,
				oinfo->packet_classification_arp,
				oinfo->packet_classification_arp_reply,
				oinfo->packet_classification_ip6_unsupported_exthdr,
				oinfo->packet_classification_tcp,
				oinfo->packet_classification_udp,
				oinfo->l3_checksum_ok,
				oinfo->l4_checksum_ok
				);
		}
	}
	return ret;
}


/*
 * When a QP is taken down and it has send completions that are not
 * polled, we need to walk through the send CQ and update the wr_id,
 * before the QP's SQ handle are de-allocated. To signal that the
 * wr_id is correct, we set the SIF_WC_QP_DESTROYED bit in the wc
 * opcode.
 *
 * Further, for a receive completion, we normally need the QP in order
 * to retrieve the RQ number. Again, the QP might not exist. Hence, we
 * mark receive CQEs the same way.
 *
 * Negative return implies an error, errno is set. Zero or greater
 * return indicates numbers of CQEs that were marked with
 * SIF_WC_QP_DESTROYED.
 */

int sif_fixup_cqes(struct sif_cq *cq, struct sif_sq *sq, struct sif_qp *qp)
{
	volatile struct psif_cq_entry *cqe;
	struct sif_dev *sdev = to_sdev(cq->ibcq.device);
	struct sif_cq_sw *cq_sw = get_sif_cq_sw(sdev, cq->index);
	u32 seqno;
	u32 polled_value;
	int n = 0;
	int ret = 0;
	unsigned long flags = 0;


	spin_lock_irqsave(&cq->lock, flags);

	for (seqno = cq_sw->next_seq;; ++seqno) {
		struct psif_cq_entry lcqe;
		uint64_t wr_id_host_order = 0;

		/* TBD - maybe should hide this as a function in sif_r3.c */
		if ((test_bit(CQ_POLLING_NOT_ALLOWED, &cq_sw->flags)))
			break;

		cqe = get_cq_entry(cq, seqno);
		polled_value = get_psif_cq_entry__seq_num(cqe);

		/* More CQEs to check? */
		if (seqno != polled_value)
			break;

		/* Fixup only for this QP */
		if (get_psif_cq_entry__qp(cqe) != qp->qp_idx)
			continue;

		/* Read into local copy in host memory order */
		copy_conv_to_sw(&lcqe, cqe, sizeof(lcqe));

		/* Receive completion? */
		if (lcqe.opcode & PSIF_WC_OPCODE_RECEIVE_SEND) {
			struct sif_post_mortem_qp_info_in_cqe *post_mortem_info =
				(struct sif_post_mortem_qp_info_in_cqe *) cqe->reserved + 0;

			/* if a receive completion, record some info to be used when cqe is polled */
			post_mortem_info->was_srq = has_srq(sdev, qp);
			post_mortem_info->srq_idx = qp->rq_idx;
			post_mortem_info->qpn     = qp->qp_idx;
		} else {
			/* If a send completion, handle the wr_id */
			ret = translate_wr_id(&wr_id_host_order, sdev, cq, sq, &lcqe,
					lcqe.wc_id.sq_id.sq_seq_num, lcqe.qp);
			if (ret)
				goto err;

			set_psif_cq_entry__wc_id(cqe, wr_id_host_order);
		}

		/* Tell sub-sequent poll_cq() that the wr_id is OK */
		set_psif_cq_entry__opcode(cqe, get_psif_cq_entry__opcode(cqe) | SIF_WC_QP_DESTROYED);
		++n;
	}

	ret = n;

err:
	spin_unlock_irqrestore(&cq->lock, flags);


	return ret;
}


/* standard poll function called from ib_poll_cq
 * driver internal completion handling uses special logic in sif_pqp.c
 *
 * All types of QP ownership can use this function for peek operations
 * [ via sif_peek_cq (with @wc = NULL) ]
 */
int sif_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc)
{
	struct sif_cq *cq = to_scq(ibcq);
	struct sif_dev *sdev = to_sdev(ibcq->device);
	volatile struct psif_cq_entry *cqe;
	struct sif_cq_sw *cq_sw = get_sif_cq_sw(sdev, cq->index);

	u32 seqno;
	u32 polled_value = 0;
	int npolled = 0;
	unsigned long flags = 0;
	int ret = 0;
	/* TBD: Replace lock with atomic ops */
	spin_lock_irqsave(&cq->lock, flags);

	seqno = cq_sw->next_seq;
	cqe = get_cq_entry(cq, seqno);

	sif_log_rlim(sdev, SIF_POLL, "cq %d (requested %d entries), next_seq %d %s",
		cq->index, num_entries, cq_sw->next_seq, (wc ? "" : "(peek)"));

	while (npolled < num_entries) {
		/* TBD - maybe should hide this as a function in sif_r3.c */
		if ((test_bit(CQ_POLLING_NOT_ALLOWED, &cq_sw->flags)))
			break;

		polled_value = get_psif_cq_entry__seq_num(cqe);

		if ((test_bit(CQ_POLLING_IGNORED_SEQ, &cq_sw->flags)) && ~seqno == polled_value) {
			seqno = ++cq_sw->next_seq;
			clear_bit(CQ_POLLING_IGNORED_SEQ, &cq_sw->flags);
			continue;
		}

		if (seqno == polled_value)
			npolled++;
		else
			break;

		if (likely(wc)) {
			ret = handle_wc(sdev, cq, cqe, wc);
			if (ret < 0)
				goto handle_failed;
			wc++;
			seqno = ++cq_sw->next_seq;
		} else /* peek_cq semantics */
			++seqno;

		cqe = get_cq_entry(cq, seqno);
	}

	if (likely(wc)) {
		if (cq_length(cq, cq_sw->cached_head, seqno) >= cq->high_watermark) {
			/* Update CQ software pointer */
			set_psif_cq_sw__head_indx(&cq_sw->d, seqno);
			cq_sw->cached_head = seqno;
		}
	}

handle_failed:
	spin_unlock_irqrestore(&cq->lock, flags);

	if (npolled)
		sif_log(sdev, SIF_CQ, "done - %d completions - seq_no of next entry: %d",
			npolled, polled_value);
	else
		sif_log_rlim(sdev, SIF_POLL, "no completions polled - seq_no of next entry: %d",
			polled_value);
	return !ret ? npolled : ret;
}


int sif_peek_cq(struct ib_cq *ibcq, int wc_cnt)
{
	return sif_poll_cq(ibcq, wc_cnt, NULL);
}


int sif_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags)
{
	struct sif_cq *cq = to_scq(ibcq);
	struct sif_dev *sdev = to_sdev(ibcq->device);
	struct sif_cq_sw *cq_sw = get_sif_cq_sw(sdev, cq->index);
	struct psif_wr wr;
	int ret;
	DECLARE_SIF_CQE_WITH_SAME_EQ(sdev, lcqe, cq->eq_idx);

	sif_log(sdev, SIF_NCQ, "cq_idx %d, flags 0x%x", cq->index, flags);

	memset(&wr, 0, sizeof(struct psif_wr));

	if (flags & IB_CQ_SOLICITED)
		wr.se = 1;

	/* If a CQ is not valid, do not rearm the CQ. */
	if (!get_psif_cq_hw__valid(&cq->d))
		return 0;

	/* We should never miss events in psif so we have no need for a separate
	 *  handling of IB_CQ_REPORT_MISSED_EVENTS - ignore it.
	 */

	wr.op = cq->rcn_sent ? PSIF_WR_REARM_CMPL_EVENT : PSIF_WR_REQ_CMPL_NOTIFY;
	wr.completion = 1;
	wr.details.su.u2.cq_id = cq->index;

	ret = sif_pqp_poll_wr(sdev, &wr, &lcqe);

	cq->rcn_sent = ret >= 0;

	if (lcqe.cqe.status != PSIF_WC_STATUS_SUCCESS) {
		if (ret >= 0)
			ret = -EINVAL;
		sif_log(sdev, SIF_INFO,
			" cq %d: last_hw_seq %u next_seq %u failed with status %s",
			cq->index, cq_sw->last_hw_seq, cq_sw->next_seq,
			string_enum_psif_wc_status(lcqe.cqe.status));
	} else
		sif_log(sdev, SIF_NCQ, "cq %d: last_hw_seq %u next_seq %u status %s",
			cq->index, cq_sw->last_hw_seq, cq_sw->next_seq,
			string_enum_psif_wc_status(lcqe.cqe.status));

	if ((ret > 0) && (flags & IB_CQ_REPORT_MISSED_EVENTS)) {
		/* peek to see if there is any outstanding completion.
		 * By checking for this flag, the application
		 * does  not required to call poll_cq again to
		 * avoid race condition.
		 */
		return sif_peek_cq(ibcq, 1);
	}

	return ret > 0 ? 0 : ret;
}


int sif_req_ncomp_notif(struct ib_cq *ibcq, int wc_cnt)
{
	struct sif_dev *sdev = to_sdev(ibcq->device);

	sif_log(sdev, SIF_VERBS, "Not implemented");
	return -EOPNOTSUPP;
}


void sif_dfs_print_cq_hw(struct seq_file *s, struct sif_dev *sdev,
			loff_t pos)
{
	struct sif_cq *cq;
	volatile struct psif_cq_hw *cq_hw_p;
	volatile struct sif_cq_sw *cq_sw;
	int qlen;

	if (unlikely(pos < 0)) {
		seq_printf(s, "#    Destroyed cq miss_cnt/occ %u/%u\n",
			atomic_read(&sdev->cq_miss_cnt),
			atomic_read(&sdev->cq_miss_occ));

		seq_puts(s, "# Index  actual_head  cached_head  hw_tail  entries ");
		seq_puts(s, "queue_len next_seq eq  #events timeouts   errors  miss_cnt/occ\n");
		return;
	}

	cq = get_sif_cq(sdev, pos);
	cq_hw_p = &cq->d;
	cq_sw = get_sif_cq_sw(sdev, cq->index);

	/* TBD: Must peek for new entries to report accurately, but it is unsafe
	 * unless we ref.cnt the cq
	 */
	qlen = 0;

	seq_printf(s, "%7llu %12u %12d %8u %8u %9u %8u %2u %8u %8u %8u %8u %4u", pos,
		get_psif_cq_sw__head_indx(&cq_sw->d), cq_sw->cached_head,
		get_psif_cq_hw__tail_indx(cq_hw_p),
		cq->entries, qlen, cq_sw->next_seq, cq->eq_idx, atomic_read(&cq->event_cnt),
		atomic_read(&cq->timeout_cnt),
		atomic_read(&cq->error_cnt),
		cq_sw->miss_cnt, cq_sw->miss_occ);

	if (get_psif_cq_hw__proxy_en(cq_hw_p))
		seq_printf(s, " [proxy to %s]",
			string_enum_psif_eps_a_core(get_psif_cq_hw__eps_core(cq_hw_p)));
	if (cq_sw->armed)
		seq_puts(s, " [armed]\n");
	else
		seq_puts(s, "\n");
}


/* Poll wait for a cq descriptor to be written back in invalid state */
int poll_wait_for_cq_writeback(struct sif_dev *sdev, struct sif_cq *cq)
{
	int ret = 0;
	ulong timeout = jiffies + sdev->min_resp_ticks * 2;
	u8 valid;

	while ((valid = get_psif_cq_hw__valid(&cq->d))) {
		if (time_after(jiffies, timeout)) {
			sif_log(sdev, SIF_INFO,
				"timeout waiting for cq_hw write-back cq %d", cq->index);
			atomic_inc(&cq->timeout_cnt);
			return -ETIMEDOUT;
		}
		cpu_relax();
	}
	sif_log(sdev, SIF_CQ, "exit - write-back observed on cq %d", cq->index);
	return ret;
}
