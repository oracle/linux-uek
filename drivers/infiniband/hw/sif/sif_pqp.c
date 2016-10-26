/*
 * Copyright (c) 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_pqp.c: Privileged QP handling
 *   The privileged QPs are SIFs internal send only QPs for management operations
 */

#include "sif_dev.h"
#include "sif_cq.h"
#include "sif_sq.h"
#include "sif_base.h"
#include "psif_hw_data.h"
#include "psif_hw_setget.h"
#include "sif_pqp.h"
#include "sif_qp.h"
#include "sif_query.h"
#include "sif_hwi.h"
#include "sif_ibqp.h"
#include "sif_checksum.h"
#include "sif_defs.h"
#include <linux/seq_file.h>

static int _pqp_queue_resurrect(struct sif_pqp *pqp);
static void pqp_resurrect(struct work_struct *work);

static inline struct sif_qp *__create_init_qp(struct sif_dev *sdev, struct sif_cq *cq)
{
	struct sif_qp *qp;
	struct ib_qp_init_attr init_attr = {
		.event_handler = NULL,
		.send_cq = &cq->ibcq,
		.recv_cq = NULL, /* receive side not used */
		.srq = NULL,
		.cap = {
			.max_send_wr = sif_max_pqp_wr,
			.max_recv_wr = 0,
			.max_send_sge = 0,
			.max_recv_sge = 0,
			.max_inline_data = 0
		},
		.qp_type = IB_QPT_UD,
	};
	struct sif_qp_init_attr sif_attr = {
		.pd = sdev->pd,
		.qp_type = PSIF_QP_TRANSPORT_MANSP1,
		.qosl = QOSL_LOW_LATENCY,
		.sq_hdl_sz = sizeof(struct sif_sq_hdl),
	};

	qp = create_qp(sdev, &init_attr, &sif_attr);
	if (!IS_ERR(qp))
		qp->ibqp.pd = &sdev->pd->ibpd;
	return qp;
}


/* Sync HW pointers to the first req we did not receive any completion for.
 * This must be done from INIT state, eg. before we attempt to move to
 * a HW owned state again, but after the implicit logic for resetting values
 * in the qp state:
 */
static inline void _resync_pointers(struct sif_qp *qp)
{
	unsigned long flags;
	struct sif_dev *sdev = to_sdev(qp->ibqp.device);
	struct sif_sq *sq = get_sq(sdev, qp);
	struct sif_cq *cq = get_sif_cq(sdev, qp->send_cq_indx);
	struct sif_cq_sw *cq_sw = get_sif_cq_sw(sdev, qp->send_cq_indx);
	struct sif_sq_sw *sq_sw = get_sif_sq_sw(sdev, qp->qp_idx);
	struct sif_sq_hdl *wh;

	spin_lock_irqsave(&cq->lock, flags);
	sq_sw->head_seq++;
	spin_unlock_irqrestore(&cq->lock, flags);

	spin_lock_irqsave(&sq->lock, flags);

	/* Terminate the failed request in error, then replay any
	 * inflicted 3rd party reqs:
	 */
	wh = get_sq_hdl(sq, sq_sw->head_seq);
	if (wh) {
		struct sif_cqe *lcqe = (struct sif_cqe *)wh->wr_id;

		if (lcqe) {
			sif_log(sdev, SIF_PQP, "Complete cqe %p for sq_seq %d for qp %d",
				lcqe, wh->sq_seq, qp->qp_idx);
			lcqe->cqe.status = PSIF_WC_STATUS_SUCCESS;
			WRITE_ONCE(lcqe->written, true);
			wh->wr_id = 0;
			wh->used = false;
		}
	}

	/* This seqno got reset by the generic RESET->INIT code, set it back
	 * to the value we want here, which is +1 compared to sq_hw::last_seq
	 */
	set_psif_qp_core__sq_seq(&qp->d.state, sq_sw->head_seq + 1);
	set_psif_qp_core__retry_sq_seq(&qp->d.state, sq_sw->head_seq + 1);

	/* We also need to set QP::cq_seq back to where we expect it: */
	set_psif_qp_core__cq_seq(&qp->d.state, cq_sw->next_seq);

	set_psif_sq_sw__tail_indx(&sq_sw->d, sq_sw->last_seq + 1);
	set_psif_sq_hw__destroyed(&sq->d, 0);
	set_psif_sq_hw__last_seq(&sq->d, sq_sw->head_seq + 1);
	spin_unlock_irqrestore(&sq->lock, flags);
	mb();
}

/* Take a priv.QP from RESET to RTS */
static int _modify_reset_to_rts(struct sif_dev *sdev, struct sif_qp *qp, bool resurrect)
{
	int ret;

	/* The privileged QP only supports state in modify_qp */
	struct ib_qp_attr mod_attr = {
		.qp_state        = IB_QPS_INIT
	};

	/* Run the required qp modify sequence */
	ret = _modify_qp(sdev, qp, &mod_attr, IB_QP_STATE, true, NULL);
	if (ret)
		return ret;

	if (resurrect)
		_resync_pointers(qp);

	mod_attr.qp_state = IB_QPS_RTR;
	ret = _modify_qp(sdev, qp, &mod_attr, IB_QP_STATE, true, NULL);
	if (ret)
		return ret;

	mod_attr.qp_state = IB_QPS_RTS;
	mod_attr.sq_psn	= 0;

	/* Modify the QP to RTS, but don't reflect it to last_set_state yet.. */
	ret = _modify_qp(sdev, qp, &mod_attr, IB_QP_STATE, true, NULL);
	return ret;
}


static struct sif_pqp *_sif_create_pqp(struct sif_dev *sdev, size_t alloc_sz, int comp_vector)
{
	struct sif_pqp *pqp;
	struct sif_cq *cq;
	struct sif_qp *qp;
	struct sif_sq *sq = NULL;
	int ret = 0;

	pqp = kzalloc(alloc_sz, GFP_KERNEL);
	if (!pqp) {
		sif_log(sdev, SIF_INFO, "Failed to allocate memory for priv.qp");
		return NULL;
	}

	cq = create_cq(sdev->pd, sif_max_pqp_wr, comp_vector, SIFPX_OFF, false, 0);
	if (IS_ERR(cq)) {
		ret = PTR_ERR(cq);
		goto cq_alloc_failed;
	}
	cq->ibcq.device = &sdev->ib_dev;
	pqp->cq = cq;
	cq->pqp = pqp;
	init_completion(&pqp->nonfull);

	/* Now create a queue pair.
	 * TBD: Use a separate pqp for req_notify_cq and use low latency..
	 */
	qp = __create_init_qp(sdev, cq);
	if (IS_ERR(qp)) {
		ret = PTR_ERR(qp);
		goto qp_alloc_failed;
	}

	pqp->qp = qp;
	qp->pqp = pqp;
	sq = get_sif_sq(sdev, qp->qp_idx);
	/* Reserve 1/2 or at least 1 entry for pqp requests with completion on the PQP */
	pqp->lowpri_lim = sq->entries - min_t(int, sq->entries/2, 2);

	mutex_lock(&qp->lock);
	ret = _modify_reset_to_rts(sdev, qp, false);
	if (ret)
		goto qp_alloc_failed;
	atomic64_set(&pqp->qp->arm_srq_holdoff_time, 0);

	mutex_unlock(&qp->lock);
	sif_log(sdev, SIF_QP, "success");
	return pqp;

qp_alloc_failed:
	mutex_unlock(&qp->lock);

	/* Special destruction order, see below: */
	destroy_cq(cq);
	if (sq)
		sq->cq_idx = -1;

	if (pqp->qp)
		destroy_qp(sdev, qp);
cq_alloc_failed:
	kfree(pqp);
	sif_log(sdev, SIF_QP, "failed with %d", ret);
	return ERR_PTR(ret);
}


int sif_destroy_pqp(struct sif_dev *sdev, struct sif_pqp *pqp)
{
	struct sif_sq *sq = get_sif_sq(sdev, pqp->qp->qp_idx);
	bool self_destruct = get_pqp(sdev) == pqp;
	/* For the last pqp we make an exception from the IB std reqs
	 * in that we keep the PQP itself up to invalidate the CQ using the
	 * PQP to send the invalidate, **before** we take down the QP itself.
	 * The hardware will make sure that for this special case
	 * the completion is sent before the CQ entry is invalidated.
	 */
	int ret;

	if (self_destruct) {
		sif_log(sdev, SIF_PQP, "self destruct CQ %d", pqp->cq->index);
		ret = destroy_cq(pqp->cq);
		if (ret < 0)
			return ret;

		if (sq)
			sq->cq_idx = -1;
	}

	ret = destroy_qp(sdev, pqp->qp);
	if (ret < 0)
		return ret;

	/* Support the normal destruction order as long as we have
	 * other PQPs in the system:
	 */
	if (!self_destruct) {
		ret = destroy_cq(pqp->cq);
		if (ret < 0)
			return ret;

		if (sq)
			sq->cq_idx = -1;
	}
	kfree(pqp);
	return 0;
}


struct sif_pqp *sif_create_pqp(struct sif_dev *sdev, int comp_vector)
{
	return _sif_create_pqp(sdev, sizeof(struct sif_pqp), comp_vector);
}


static void pqp_complete_nonfull(struct sif_pqp *pqp)
{
	int ql;
	unsigned long flags;
	struct sif_dev *sdev = to_sdev(pqp->cq->ibcq.device);
	struct sif_sq *sq = get_sif_sq(sdev, pqp->qp->qp_idx);
	struct sif_sq_sw *sq_sw = get_sif_sq_sw(sdev, pqp->qp->qp_idx);
return;
	spin_lock_irqsave(&sq->lock, flags);
	ql = sq_length(sq, sq_sw->head_seq, sq_sw->last_seq);
	if (ql <= sq->mask && atomic_read(&pqp->waiters))
		complete(&pqp->nonfull);
	spin_unlock_irqrestore(&sq->lock, flags);
}


static inline void __pqp_complete_sq(struct sif_sq *sq, u32 sq_seq)
{
	/* TBD: Allow pqp posters to wait for completions */
}



static void pqp_reset_cmpl(struct sif_cqe *lcqe)
{
	struct sif_pqp *pqp = lcqe->pqp;
	struct sif_cq *cq = pqp->cq;
	struct sif_dev *sdev = to_sdev(cq->ibcq.device);
	struct sif_sq *sq = get_sif_sq(sdev, pqp->qp->qp_idx);
	struct sif_sq_hdl *wh = get_sq_hdl(sq, lcqe->sq_seq);
	unsigned long flags;

	spin_lock_irqsave(&cq->lock, flags);
	wh->wr_id = 0;
	wh->used = false;
	spin_unlock_irqrestore(&cq->lock, flags);
}



/* Process all received completions on @cq - must be only PQP completions!
 * Return the number processed, or -errno upon errors:
 * Assumes the cq lock is held.
 * If first_err is set, check for completion errors and return the first one with errors:
 */

/* TBD: Clean up memory barriers in this function */
static int __pqp_process_cqe(struct sif_pqp *pqp, struct sif_cqe *first_err)
{
	struct sif_cq *cq = pqp->cq;
	struct sif_dev *sdev = to_sdev(cq->ibcq.device);
	struct sif_sq_sw *sq_sw;
	volatile struct sif_cq_sw *cq_sw = get_sif_cq_sw(sdev, cq->index);
	struct sif_sq *sq;
	u32 seqno = cq_sw->next_seq;
	volatile struct psif_cq_entry *cqe_be = get_cq_entry(cq, seqno);
	int npolled = 0;
	int cqe_cnt = 0;
	u64 wci;
	struct psif_send_completion_id *wc_id = (struct psif_send_completion_id *)&wci;
	int sq_seq;
	struct sif_cqe *lcqe;
	struct sif_sq_hdl *wh;
	int ql = 0;
	u64 dbg_mask;
	bool err_seen = false;

	for (; seqno == get_psif_cq_entry__seq_num(cqe_be); npolled++) {
		enum psif_wc_status status = get_psif_cq_entry__status(cqe_be);
		int sq_idx = get_psif_cq_entry__qp(cqe_be);
		bool dump_it = false;

		sq = get_sif_sq(sdev, sq_idx);
		sq_sw = get_sif_sq_sw(sdev, sq_idx);
		wci = get_psif_cq_entry__wc_id(cqe_be);
		sq_seq = wc_id->sq_seq_num;
		wh = get_sq_hdl(sq, sq_seq);

		if (unlikely(status != PSIF_WC_STATUS_SUCCESS)) {
			sif_log(sdev, SIF_INFO, "error completion polled");
			dump_it = true;
		}

		if (pqp->qp->flags & SIF_QPF_KI_STENCIL)
			goto cont_check_first_err;

		if (unlikely(!wh)) {
			sif_log(sdev, SIF_INFO,
				"cqe %d for cq %d refers sq(qp) %d which has not been initialized",
				seqno, cq->index, sq_idx);
			dump_it = true;
			goto cont_no_wh;
		}
		if (unlikely(!wh->used)) {
			sif_log(sdev, SIF_INFO,
				"ignoring unused cqe %d for cq %d, sq %d, sq_seq %d",
				seqno, cq->index, sq_idx, sq_seq);
			dump_it = true;
			goto cont;
		}
		if (unlikely(wh->sq_seq != sq_seq)) {
			sif_log(sdev, SIF_INFO,
				"wrong cqe %d for cq %d: got sq_seq %d, expected %d",
				seqno, cq->index, sq_seq, wh->sq_seq);
			dump_it = true;
			goto cont;
		}

		lcqe = (struct sif_cqe *)wh->wr_id;
		if (lcqe) {
			unsigned long elapsed = jiffies - lcqe->t_start;

			if (unlikely(elapsed > pqp->max_cmpl_time))
				pqp->max_cmpl_time = elapsed;
			wh->wr_id = 0;
			cqe_cnt++;
			mb();
			sif_log(sdev, SIF_PQP, "copying to caller cqe at %p", &lcqe->cqe);
			copy_conv_to_sw(&lcqe->cqe, cqe_be, sizeof(struct psif_cq_entry));
			wmb();
			lcqe->written = true;
			if (lcqe->need_complete)
				complete(&lcqe->cmpl);
		}
cont_check_first_err:
		if (unlikely(first_err && (status != PSIF_WC_STATUS_SUCCESS))) {
			sif_log(sdev, SIF_PQP, "error completion received - aborting");
			copy_conv_to_sw(&first_err->cqe, cqe_be, sizeof(struct psif_cq_entry));
			err_seen = true;
			first_err->written = true;
			npolled++;
		}
cont:
		wh->used = 0;
cont_no_wh:
		if (dump_it) {
			sif_logs(SIF_INFO,
				write_struct_psif_cq_entry(NULL, 1,
						(const struct psif_cq_entry *)cqe_be);
				printk("\n"));
		}

		mb();
		sq_sw->head_seq = sq_seq;
		seqno = ++cq_sw->next_seq;

		if (cq_length(cq, cq_sw->cached_head, seqno) >= cq->high_watermark) {
			/* Update CQ hardware pointer */
			set_psif_cq_sw__head_indx(&cq_sw->d, seqno);
			cq_sw->cached_head = seqno;
		}

		ql = sq_length(sq, sq_seq, sq_sw->last_seq);
		if (unlikely(ql > pqp->max_qlen))
			pqp->max_qlen = ql;
		if (ql <= sq->mask)
			pqp_complete_nonfull(pqp);
		mb();
		if (unlikely(err_seen))
			break;
		cqe_be = get_cq_entry(cq, seqno);
	}

	dbg_mask = npolled ? SIF_PQP : SIF_IPOLL;
	sif_log(sdev, dbg_mask, "processed %d (%d with waiters) requests - seqno 0x%x, ql %d",
		npolled, atomic_read(&pqp->waiters),
		seqno, ql);

	if (npolled > 0) {
		/* reset timeout each time we see a new completion: */
		pqp->timeout = jiffies + sdev->min_resp_ticks * 4;
	}
	return npolled;
}


static int pqp_process_cqe(struct sif_pqp *pqp, struct sif_cqe *first_err)
{
	unsigned long flags;
	int npolled;
	struct sif_cq *cq = pqp->cq;

	/* If someone else holds the lock, the CQEs are handled */
	if (!spin_trylock_irqsave(&cq->lock, flags))
		return -EBUSY;
	npolled = __pqp_process_cqe(pqp, first_err);
	spin_unlock_irqrestore(&cq->lock, flags);
	return npolled;
}


static struct sif_pqp *find_any_pqp(struct sif_dev *sdev)
{
	int cpu;

	for (cpu = 0; cpu < sdev->pqi.cnt; cpu++)
		if (sdev->pqi.pqp[cpu])
			return sdev->pqi.pqp[cpu];
	return NULL;
}

/* Get the right PQP for the same EQ*/
struct sif_pqp *get_pqp_same_eq(struct sif_dev *sdev, int comp_vector)
{
	unsigned int pqp_index = comp_vector - 2;
	struct sif_pqp *pqp = sdev->pqi.cnt ? sdev->pqi.pqp[pqp_index % sdev->pqi.cnt] : NULL;

	if (unlikely(!pqp)) {
		/* Typically during take down */
		return find_any_pqp(sdev);
	}
	return pqp;
}


/* Get the right PQP for the current CPU */
struct sif_pqp *get_pqp(struct sif_dev *sdev)
{
	unsigned int cpu = smp_processor_id();
	struct sif_pqp *pqp = sdev->pqi.cnt ? sdev->pqi.pqp[cpu % sdev->pqi.cnt] : NULL;

	if (unlikely(!pqp)) {
		/* Typically during take down */
		return find_any_pqp(sdev);
	}
	return pqp;
}

/* Get the next PQP in a round robin fashion */
struct sif_pqp *get_next_pqp(struct sif_dev *sdev)
{
	struct sif_pqp *pqp;
	int next = atomic_inc_return(&sdev->pqi.next) % sdev->pqi.cnt;

	pqp = sdev->pqi.pqp[next];
	if (unlikely(!pqp)) {
		/* Typically during take down */
		return find_any_pqp(sdev);
	}
	return pqp;
}

struct sif_cb *get_cb(struct sif_qp *qp, struct psif_wr *wr)
{
	struct sif_dev *sdev = to_sdev(qp->ibqp.pd->device);
	unsigned int cpu = smp_processor_id();
	enum psif_tsu_qos cb_type = qp->qosl;
	/* Only use low latency CBs for the frequently occuring notify events (REARM) */
	if (cb_type == QOSL_LOW_LATENCY && wr->op != PSIF_WR_REARM_CMPL_EVENT)
		cb_type = QOSL_HIGH_BANDWIDTH;

	return sdev->kernel_cb[cb_type][cpu % sdev->kernel_cb_cnt[cb_type]];
}

inline bool pqp_req_gets_completion(struct sif_pqp *pqp, struct psif_wr *wr, enum post_mode mode)
{
	return mode == PM_WRITE || (wr->op != PSIF_WR_GENERATE_COMPLETION && wr->completion) ||
		wr->cq_desc_vlan_pri_union.cqd_id == pqp->cq->index;
}

/* Fill in common parts and post a work request to the management QP for the current CPU
 * If @cqe is non-null, a completion will be requested and the result put there in
 * host order when it is found (by __pqp_process_cqe())
 */
int sif_pqp_write_send(struct sif_pqp *pqp, struct psif_wr *wr, struct sif_cqe *cqe,
		enum post_mode mode)
{
	struct sif_qp *qp = pqp->qp;
	u32 qp_idx = qp->qp_idx;
	struct sif_dev *sdev = to_sdev(pqp->qp->ibqp.device);
	struct sif_pd *pd = sdev->pd;
	struct sif_sq *sq = get_sif_sq(sdev, qp_idx);
	struct psif_sq_entry *sqe;
	struct sif_sq_hdl *wh;
	unsigned long flags;
	bool ring_doorbell;
	int q_sz;
	int ret = 0;
	u16 head, sq_seq;
	struct sif_sq_sw *sq_sw = get_sif_sq_sw(sdev, qp_idx);
	unsigned long timeout = sdev->min_resp_ticks * 4;
	u16 limit = pqp_req_gets_completion(pqp, wr, mode) ? sq->entries : pqp->lowpri_lim;

	pqp->timeout = jiffies + timeout;

	wr->local_qp = qp_idx;
	wr->tsu_qosl = qp->qosl;
	wr->tsu_sl = qp->tsl;

restart:
	/* Make sure emptying the queue takes preference over filling it up.
	 * This will also make us exit if the pqp is not up and running:
	 */
	if (mode != PM_WRITE)
		ret = pqp_process_cqe(pqp, NULL);
	if (ret > 0 || ret == -EBUSY)
		ret = 0; /* Got some reqs */
	else if (ret < 0)
		return ret;

	spin_lock_irqsave(&sq->lock, flags);
	sq_seq = sq_sw->last_seq;
	head = sq_sw->head_seq;
	q_sz = sq_length(sq, head, sq_seq);

	if (q_sz >= limit) {
		if (sq_seq != pqp->last_full_seq) {
			sif_log(sdev, SIF_PQP,
				"Privileged qp full - head %d sq_seq %d q_sz %d/%d",
				head, sq_seq, q_sz, sq->entries);
			pqp->last_full_seq = sq_seq;
		}
		spin_unlock_irqrestore(&sq->lock, flags);

		if (limit < sq->entries && sq_seq != pqp->last_nc_full) {
			/* Avoid spinning creating more sync completions
			 * - block on next try unless sequence number has changed:
			 */
			pqp->last_nc_full = sq_seq;
			return -EAGAIN;
		}

		/* PQP requests to a full queue should not be generated at interrupt level */
		BUG_ON(in_interrupt());
		if (time_is_after_jiffies(pqp->timeout)) {
			goto restart;
			if (sq_seq != pqp->last_full_seq)
				sif_log(sdev, SIF_PQP, "priv.qp %d: spin waiting for slot in queue",
					pqp->qp->qp_idx);
		} else {
			sif_log(sdev, SIF_INFO,
				"Timeout waiting for previous response (seq %d) to complete",
				sq_sw->head_seq);
			return -ETIMEDOUT;
		}
	}
	sq_seq = ++sq_sw->last_seq;

	/* Store longest send queue observed */
	if (unlikely(q_sz > sq->max_outstanding && mode != PM_WRITE))
		sq->max_outstanding = q_sz;

	/* For GENERATE_COMPLETION the CQ id to generate in is put here
	 * and no completion is expected on the PQP.
	 */
	if (wr->op == PSIF_WR_GENERATE_COMPLETION) {
		/* Are we generating a completion on our own QP? */
		if (wr->details.su.u2.target_qp == pqp->qp->qp_idx)
			wr->details.su.wc_id.sq_id.sq_seq_num = sq_seq;
	} else
		wr->cq_desc_vlan_pri_union.cqd_id = sq->cq_idx;

	wh = get_sq_hdl(sq, sq_seq);
	wh->wr_id = (u64)cqe;
	wh->sq_seq = sq_seq;
	wh->used = true;

	if (cqe) {
		if ((wr->op != PSIF_WR_GENERATE_COMPLETION) || (wr->se)) {
			cqe->sq_seq = sq_seq;
			wr->completion = 1;
		}
		BUG_ON(cqe->written);
	}

	sqe = get_sq_entry(sq, sq_seq);

	if (likely(mode != PM_WRITE)) {
		u64 csum;

		sif_log(sdev, SIF_PQP, "pd %d cq_idx %d sq_idx %d sq.seqn %d op %s",
			pd->idx, wr->cq_desc_vlan_pri_union.cqd_id, sq->index, sq_seq,
			string_enum_psif_wr_type(wr->op));

		wr->sq_seq = sq_seq;

		/* Collect_length is always 0 for privileged wr's - they have no data */
		csum = csum32_partial(wr, sizeof(*wr), qp->magic);
		csum = csum32_fold(csum);
		wr->checksum = csum;

		sif_log(sdev, SIF_PQP, "PQP checksum %x", wr->checksum);
	}

	sif_logs(SIF_DUMP, write_struct_psif_wr(NULL, 0, wr));

	/* update send queue */
	copy_conv_to_hw(sqe, wr, sizeof(struct psif_wr));

	if (unlikely(READ_ONCE(pqp->write_only)))
		wmb();
	else if (likely(mode != PM_WRITE)) {
		/* Flush writes before updating the sw pointer,
		 * This is necessary to ensure that the sqs do not see
		 * an incomplete entry:
		 */
		wmb();

		/* Update sw pointer visible to hw */
		set_psif_sq_sw__tail_indx(&sq_sw->d, sq_seq);

		/* Finally write to collect buffer - implicit barriers before/after I/O writes
		 *
		 * Workaround #3595: ring doorbell if SQS in SQ-mode
		 */
		ring_doorbell = qp->flags & SIF_QPF_FORCE_SQ_MODE ||
			!(get_psif_sq_hw__sq_next(&sq->d) & 0x1) ||
			mode == PM_DOORBELL;

		if (ring_doorbell)
			sif_doorbell_from_sqe(qp, sq_seq, true);
		else if (sif_cb_write(qp, wr, sizeof(struct psif_wr))) {
			/* vcb lock busy, use db mode instead */
			sif_doorbell_from_sqe(qp, sq_seq, true);
		}
	}

	spin_unlock_irqrestore(&sq->lock, flags);
	return ret;
}


int sif_pqp_post_send(struct sif_dev *sdev, struct psif_wr *wr, struct sif_cqe *cqe)
{
	struct sif_pqp *pqp = cqe ? cqe->pqp : get_pqp(sdev);
	enum post_mode mode = pqp->qp->flags & SIF_QPF_FORCE_SQ_MODE ? PM_DOORBELL : PM_CB;

	return sif_pqp_write_send(pqp, wr, cqe, mode);
}

int sif_pqp_poll_wr(struct sif_dev *sdev, struct psif_wr *wr, struct sif_cqe *cqe)
{
	int ret = sif_pqp_post_send(sdev, wr, cqe);

	if (ret) {
		sif_log(sdev, SIF_INFO, "PQP wr %d post failed on QP %d, CQ %d",
			cqe->pqp->qp->qp_idx, cqe->pqp->cq->index, wr->sq_seq);
		return ret;
	}

	ret = poll_cq_waitfor(cqe);
	if (ret < 0)
		sif_log(sdev, SIF_INFO, "poll_cq_waitfor, pqp QP %d, CQ %d failed with %d",
			cqe->pqp->qp->qp_idx, cqe->pqp->cq->index, ret);
	return ret;
}


/* Poll and process incoming (internal) completions
 * while waiting for this particular completion
 */
int poll_cq_waitfor(struct sif_cqe *lcqe)
{
	struct sif_pqp *pqp = lcqe->pqp;
	struct sif_cq *cq = pqp->cq;
	struct sif_dev *sdev = to_sdev(cq->ibcq.device);
	int ret = 0;
	int waitcnt = 0;
	volatile bool *written = &lcqe->written;
	u64 min_resp_ticks = sdev->min_resp_ticks;

	/* TBD: This timeout is unsafe - we just keep it now to allow runs be aborted
	 * without having to reboot. Keep value for it a factor larger than other timeouts:
	 */
	pqp->timeout = jiffies + min_resp_ticks * 4;

	while (!(*written)) {
		ret = pqp_process_cqe(pqp, NULL);
		if (ret == -EBUSY) {
			ret = 0;
			continue;
		} else if (ret < 0)
			break;
		else if (ret == 0) {
			waitcnt++;
			if (time_is_before_jiffies(pqp->timeout)) {
				if (sif_feature(pcie_trigger))
					force_pcie_link_retrain(sdev);
				sif_log(sdev, SIF_INFO,
					"cq %d: poll for cqe for sq %d, sq.seq %d timed out",
					cq->index, pqp->qp->qp_idx, lcqe->sq_seq);
				atomic_inc(&cq->timeout_cnt);

				sif_logs(SIF_PQPT,
					struct sif_sq *sq = get_sif_sq(sdev, pqp->qp->qp_idx);
					struct psif_sq_entry *sqe =
						get_sq_entry(sq, lcqe->sq_seq);
					write_struct_psif_sq_entry(NULL, 1, sqe));
				ret = -ETIMEDOUT;
				break;
			}

			/* Allow some pure busy wait before we attempt to reschedule/relax */
			if (waitcnt < 10)
				continue;

			if (!irqs_disabled())
				cond_resched();
			else
				cpu_relax();

			if (sdev->min_resp_ticks != min_resp_ticks) {
				/* Give us a quick way out by changing min_resp_ticks */
				pqp->timeout -= (min_resp_ticks - sdev->min_resp_ticks) * 4;
				min_resp_ticks = sdev->min_resp_ticks;
			}
			continue;
		}
	}

	if (ret < 0)
		pqp_reset_cmpl(lcqe);
	return ret;
}


/* Poll for any pqp completion, return the number of completions polled */
static int poll_cq_waitfor_any(struct sif_pqp *pqp, struct sif_cqe *first_err)
{
	struct sif_cq *cq = pqp->cq;
	struct sif_dev *sdev = to_sdev(cq->ibcq.device);
	int ret = 0;
	u64 min_resp_ticks = sdev->min_resp_ticks;

	pqp->timeout = jiffies + min_resp_ticks * 4;

	while (!ret) {
		ret = pqp_process_cqe(pqp, first_err);
		if (ret == -EBUSY) {
			ret = 0;
			continue;
		} else if (ret < 0)
			break;
		else if (ret == 0) {
			if (time_is_before_jiffies(pqp->timeout)) {
				if (sif_feature(pcie_trigger))
					force_pcie_link_retrain(sdev);
				sif_log(sdev, SIF_INFO,
					"cq %d: poll timed out", cq->index);
				atomic_inc(&cq->timeout_cnt);
				ret = -ETIMEDOUT;
				break;
			}
			if (!irqs_disabled())
				cond_resched();
			else
				cpu_relax();

			if (sdev->min_resp_ticks != min_resp_ticks) {
				/* Give us a quick way out by changing min_resp_ticks */
				pqp->timeout -= (min_resp_ticks - sdev->min_resp_ticks) * 4;
				min_resp_ticks = sdev->min_resp_ticks;
			}
		}
	}
	sif_log(sdev, SIF_PQP, "ret = %d", ret);
	return ret;
}


/***** Generic completion generation *****/

static int __gen_cqe(struct sif_dev *sdev, u32 target_cq, u64 wc_id, u32 target_qp,
	      enum psif_wc_opcode opcode, enum psif_wc_status status, struct sif_cqe *cqe,
	      bool event)
{
	struct psif_wr wr;

	memset(&wr, 0, sizeof(struct psif_wr));
	wr.op = PSIF_WR_GENERATE_COMPLETION;
	wr.cq_desc_vlan_pri_union.cqd_id = target_cq;
	wr.details.su.completion_status = status;
	wr.details.su.completion_opcode = opcode;

	if (opcode >= PSIF_WC_OPCODE_RECEIVE_SEND)
		wr.details.su.wc_id.rq_id = wc_id;
	else
		wr.details.su.wc_id.sq_id.sq_seq_num = wc_id;

	wr.details.su.u2.target_qp = target_qp;
	/* set the IB_CQ_SOLICITED flag because the CQ might be armed
	 * and the consumer might be interested in getting these events.
	 * Setting IB_CQ_SOLICITED is generally safe because it is a
	 * subset of IB_CQ_NEXT_COMP.
	 */
	if (event)
		wr.se = 1;

	return sif_pqp_post_send(sdev, &wr, cqe);
}


/* Generate a SUCCESS completion on the PQP itself
 * We use this to be able to wait for a set of generated completions to other
 * CQs to have been completed:
 */
int gen_pqp_cqe(struct sif_cqe *cqe)
{
	struct sif_pqp *pqp = cqe->pqp;
	struct sif_dev *sdev = to_sdev(pqp->cq->ibcq.device);
	struct sif_sq_sw *sq_sw = get_sif_sq_sw(sdev, pqp->qp->qp_idx);

	if (cqe)
		cqe->written = false;

	sif_log(sdev, SIF_PQP, " for sq %d, last_nc_full %d, head_seq %d last_seq %d",
		pqp->qp->qp_idx, pqp->last_nc_full, sq_sw->head_seq, sq_sw->last_seq);
	return __gen_cqe(sdev, pqp->cq->index, 0, pqp->qp->qp_idx,
			PSIF_WC_OPCODE_GENERATE_COMPLETION, PSIF_WC_STATUS_SUCCESS,
			 cqe, true);
}


/* Post a request to generate a completion with the given values
 * on the cq identified by @target_cq.
 * This request generates no completion on the PQP itself:
 */
static int sif_gen_cqe(struct sif_dev *sdev, u32 target_cq, u64 wc_id, u32 target_qp,
		enum psif_wc_opcode opcode, enum psif_wc_status status, bool event)
{
	return __gen_cqe(sdev, target_cq, wc_id, target_qp, opcode, status, NULL, event);
}

/* Post a request to generate a completion for an outstanding rq entry
 * on the given qp. This request generates no completion on the PQP itself:
 */

static int sif_gen_rq_cqe(struct sif_dev *sdev, struct sif_rq *rq, u32 rq_seq,
		struct sif_qp *target_qp, enum psif_wc_opcode opcode,
		enum psif_wc_status status)
{
	struct psif_rq_entry *rqe = get_rq_entry(rq, rq_seq);
	u64 wc_id = get_psif_rq_entry__rqe_id(rqe);
	u32 cq_idx = get_psif_qp_core__rcv_cq_indx(&target_qp->d.state);

	sif_log(sdev, SIF_PQP, "on rq %d, rq_seq %d, wc_id %llx, cq %d (target_qp %d)",
		rq->index, rq_seq, wc_id, cq_idx, target_qp->qp_idx);

	return sif_gen_cqe(sdev, cq_idx, wc_id, target_qp->qp_idx, opcode, status, true);
}


int sif_gen_rq_flush_cqe(struct sif_dev *sdev, struct sif_rq *rq,
			u32 rq_seq, struct sif_qp *target_qp)
{
	return sif_gen_rq_cqe(sdev, rq, rq_seq, target_qp,
			PSIF_WC_OPCODE_RECEIVE_SEND, PSIF_WC_STATUS_WR_FLUSH_ERR);
}

/* Post a request to generate a completion for an outstanding sq entry
 * on the given qp. This request generates no completion on the PQP itself:
 */

static int sif_gen_sq_cqe(struct sif_dev *sdev, struct sif_sq *sq, u32 sq_seq, u32 target_qp,
		   enum psif_wc_opcode opcode, enum psif_wc_status status, bool event)
{
	struct psif_sq_entry *sqe = get_sq_entry(sq, sq_seq);
	u64 wc_id = get_psif_wr__sq_seq(&sqe->wr);

	sif_log(sdev, SIF_PQP, "on sq %d, sq_seq %d, wc_id %llx, cq %d (target_qp %d)",
		sq->index, sq_seq, wc_id, sq->cq_idx, target_qp);

	return sif_gen_cqe(sdev, sq->cq_idx, wc_id, target_qp, opcode, status, event);
}


int sif_gen_sq_flush_cqe(struct sif_dev *sdev, struct sif_sq *sq,
			 u32 sq_seq, u32 target_qp, bool event)
{
	return sif_gen_sq_cqe(sdev, sq, sq_seq, target_qp,
			      PSIF_WC_OPCODE_SEND, PSIF_WC_STATUS_WR_FLUSH_ERR, event);
}


/***** Stencil PQP support ****
 *
 *  A stencil PQP is a PQP set up fully populated with WRs ready
 *  for parallel batch processing (using SQSes) of particularly performance
 *  critical PQP operations.
 *
 *  The idea is to lay this out to allow the WRs to be reused with minimal
 *  updates:
 */

struct sif_st_pqp *sif_create_inv_key_st_pqp(struct sif_dev *sdev)
{
	int i;
	struct sif_st_pqp *spqp = (struct sif_st_pqp *)_sif_create_pqp(sdev, sizeof(*spqp), 0);
	struct sif_pqp *pqp;
	int qp_idx;
	struct sif_sq *sq;
	struct sif_sq_sw *sq_sw;
	struct psif_sq_entry *sqe;
	struct psif_wr lwr;
	u16 max_db_int;

	if (IS_ERR(spqp))
		return spqp;

	pqp = &spqp->pqp;
	qp_idx = pqp->qp->qp_idx;
	sq = get_sif_sq(sdev, qp_idx);
	sq_sw = get_sif_sq_sw(sdev, qp_idx);
	max_db_int = (sq->entries >> 3);

	/* Pre-populate the SQ */
	for (i = 0; i < sq->entries; i++)
		sif_write_invalidate(pqp, key, 0, NULL, PCM_POST, PM_WRITE);

	/* Now, to start using the stencil at seq.1 (as normal SQs)
	 * we must reset the sw tail pointer which
	 * was updated by sif_write_invalidate:
	 */
	sq_sw->last_seq = 0;
	spqp->doorbell_seq = 1;

	spqp->doorbell_interval = min_t(u16, SPQP_DOORBELL_INTERVAL, max_db_int);
	spqp->next_doorbell_seq = spqp->doorbell_interval + 1;
	spqp->req_compl = 0;
	spqp->next_poll_seq = (sq->entries >> 1);
	spqp->sq = sq;
	spqp->sq_sw = sq_sw;
	spqp->pqp.qp->flags |= SIF_QPF_KI_STENCIL;

	/* Calculate a partial checksum
	 * - they are all the same since the fields we change
	 * are calculated with 0-values to ease checksum mod. later:
	 */
	sqe = get_sq_entry(sq, 0);
	copy_conv_to_sw(&lwr, &sqe->wr, sizeof(lwr));
	spqp->checksum = csum32_partial(&lwr, sizeof(lwr), pqp->qp->magic);

	sif_log(sdev, SIF_PQPT, "done qp %d, sq sz %d, next_poll_seq %d", qp_idx,
		sq->entries, spqp->next_poll_seq);
	return spqp;
}


int sif_destroy_st_pqp(struct sif_dev *sdev, struct sif_st_pqp *spqp)
{
	return sif_destroy_pqp(sdev, &spqp->pqp);
}


/* Update a new invalidate key request into a preconfigured stencil pqp
 * Assumes exclusive access to the PQP SQ.
 */
int sif_inv_key_update_st(struct sif_st_pqp *spqp, int index, enum wr_mode mode)
{
	struct sif_sq *sq = spqp->sq;
	struct sif_sq_sw *sq_sw = spqp->sq_sw;
	u16 sq_seq = ++sq_sw->last_seq;
	struct psif_sq_entry *sqe = get_sq_entry(sq, sq_seq);
	struct sif_dev *sdev = to_sdev(spqp->pqp.cq->ibcq.device);
	bool poll_prev = false;
	int ret = 1;
	u64 csum_inc = (u64)index + (u64)sq_seq;
	u64 csum;
	int q_sz;
	u16 head;
	DECLARE_SIF_CQE_POLL(sdev, first_err);

	/* Modify the request to our need */
	set_psif_wr_su__key(&sqe->wr.details.su, index);
	set_psif_wr__sq_seq(&sqe->wr, sq_seq);

	head = sq_sw->head_seq;
	q_sz = sq_length(sq, head, sq_seq);

	if (unlikely(q_sz > (int)sq->entries)) {
		sif_log(sdev, SIF_INFO,	"Error: Stencil pqp (qp %d) is full at seq %d, head %d",
			sq->index, sq_seq, sq_sw->head_seq);
		sq_sw->last_seq--;
		return -ENOMEM;
	}

	/* Store longest send queue observed */
	if (unlikely(q_sz > sq->max_outstanding))
		sq->max_outstanding = q_sz;

	if (unlikely(mode == PCM_WAIT || sq_seq == spqp->next_poll_seq)) {
		set_psif_wr__completion(&sqe->wr, 1);
		spqp->req_compl++;
		sif_log(sdev, SIF_PQPT, "sq %d: requesting completion for seq %d (%d)",
			sq->index, sq_seq, spqp->req_compl);
		poll_prev = spqp->req_compl > 1;
		if (sq_seq == spqp->next_poll_seq)
			spqp->next_poll_seq += (sq->entries >> 1);
		csum_inc += 0x80000000;
	} else {
		/* Reset the completion bit in case it was set in the previous generation! */
		set_psif_wr__completion(&sqe->wr, 0);
	}

	/* Add the changes to the checksum */
	csum = csum32_partial(&csum_inc, 8, spqp->checksum);
	csum = csum32_fold(csum);
	set_psif_wr__checksum(&sqe->wr, csum);

	sif_log(sdev, SIF_PQP, "cq %d, sq %d, sq seq %d%s", spqp->pqp.cq->index,
		sq->index, sq_seq, (poll_prev ? " (poll prev)" : ""));

	if (unlikely(mode == PCM_WAIT || sq_seq == spqp->next_doorbell_seq)) {
		sif_log(sdev, SIF_PQPT, "sq %d: writing doorbell at seq %d - tail at %d%s",
			sq->index, spqp->doorbell_seq, sq_seq, (mode == PCM_WAIT ? " [wait]" : ""));
		wmb();
		set_psif_sq_sw__tail_indx(&sq_sw->d, sq_seq);
		sif_doorbell_from_sqe(spqp->pqp.qp, spqp->doorbell_seq, true);
		spqp->doorbell_seq = sq_seq + 1;
		spqp->next_doorbell_seq = sq_seq + spqp->doorbell_interval + 1;
	}

	if (poll_prev) {
		sif_log(sdev, SIF_PQPT, "enter wait (poll_prev) (%d)", spqp->req_compl);
		ret = poll_cq_waitfor_any(&spqp->pqp, &first_err);
		if (ret < 0)
			goto out;
		if (unlikely(first_err.written)) {
			sif_log(sdev, SIF_INFO, "error completion with status %s",
				string_enum_psif_wc_status(first_err.cqe.status));
			goto out;
		}
		sif_log(sdev, SIF_PQPT, "polled %d completions", ret);
		spqp->req_compl -= ret;
	}

	if (unlikely(mode == PCM_WAIT)) {
		while (sq_sw->head_seq != sq_seq) {
			sif_log(sdev, SIF_PQPT, "enter wait (%d) seq %d/%d",
				spqp->req_compl, sq_sw->head_seq, sq_seq);
			ret = poll_cq_waitfor_any(&spqp->pqp, &first_err);
			if (ret < 0)
				break;
			spqp->req_compl -= ret;
			sif_log(sdev, SIF_PQPT, "done wait - head now %d - rem.cmpl %d",
				sq_sw->head_seq, spqp->req_compl);
		}
	}

	if (ret == 0)
		ret = -ENOMEM;
	else if (ret > 0)
		ret = 0;

out:
	sif_log(sdev, SIF_PQP, "done ret = %d", ret);
	return ret;
}


/* get exclusive access to a stencil pqp */
struct sif_st_pqp *sif_alloc_ki_spqp(struct sif_dev *sdev)
{
	int index;
	struct sif_st_pqp *spqp = NULL;

	mutex_lock(&sdev->pqi.ki_s.lock);
	index = find_next_zero_bit(sdev->pqi.ki_s.bitmap, sdev->pqi.ki_s.pool_sz, 0);
	if (index < sdev->pqi.ki_s.pool_sz) {
		set_bit(index, sdev->pqi.ki_s.bitmap);
		spqp = sdev->pqi.ki_s.spqp[index];
	}
	mutex_unlock(&sdev->pqi.ki_s.lock);
	sif_log(sdev, SIF_PQPT, "bit index %d", index);
	return spqp;
}

void sif_release_ki_spqp(struct sif_st_pqp *spqp)
{
	struct sif_dev *sdev = to_sdev(spqp->pqp.cq->ibcq.device);

	mutex_lock(&sdev->pqi.ki_s.lock);
	clear_bit(spqp->index, sdev->pqi.ki_s.bitmap);
	mutex_unlock(&sdev->pqi.ki_s.lock);
	sif_log(sdev, SIF_PQPT, "bit index %d", spqp->index);
}


static void sif_ki_spqp_fini(struct sif_dev *sdev);

static int sif_ki_spqp_init(struct sif_dev *sdev)
{
	int i;
	int ret = 0;
	int n = max(sif_ki_spqp_size, 0U);
	int bm_len = max(1, n/8);
	struct sif_pqp_info *pqi = &sdev->pqi;

	mutex_init(&pqi->ki_s.lock);
	pqi->ki_s.spqp =
#ifdef CONFIG_NUMA
		kmalloc_node(sizeof(struct sif_st_pqp *) * n, GFP_KERNEL | __GFP_ZERO,
			sdev->pdev->dev.numa_node);
#else
		kmalloc(sizeof(struct sif_st_pqp *) * n, GFP_KERNEL | __GFP_ZERO);
#endif
	if (!pqi->ki_s.spqp)
		return -ENOMEM;

	pqi->ki_s.bitmap =
#ifdef CONFIG_NUMA
		kmalloc_node(sizeof(ulong) * bm_len, GFP_KERNEL | __GFP_ZERO,
			sdev->pdev->dev.numa_node);
#else
		kmalloc(sizeof(ulong) * bm_len, GFP_KERNEL | __GFP_ZERO);
#endif
	if (!pqi->ki_s.bitmap) {
		ret = -ENOMEM;
		goto bm_failed;
	}

	for (i = 0; i < n; i++) {
		struct sif_st_pqp *spqp = sif_create_inv_key_st_pqp(sdev);

		if (IS_ERR(spqp)) {
			ret = PTR_ERR(spqp);
			break;
		}
		pqi->ki_s.spqp[i] = spqp;
		spqp->index = i;
	}
	pqi->ki_s.pool_sz = i;
	if (ret && i) {
		sif_log(sdev, SIF_INFO, "Failed to create %d INVALIDATE_KEY stencil QPs", i);
		sif_ki_spqp_fini(sdev);
	}

	if (i)
		sif_log(sdev, SIF_INIT, "Created %d INVALIDATE_KEY stencil QPs", i);
bm_failed:
	if (ret)
		kfree(pqi->ki_s.spqp);
	return 0;  /* Never fail on stencil PQP allocation */
}


static void sif_ki_spqp_fini(struct sif_dev *sdev)
{
	struct sif_pqp_info *pqi = &sdev->pqi;
	int i;

	if (!pqi->ki_s.spqp)
		return;
	for (i = pqi->ki_s.pool_sz - 1; i >= 0; i--)
		sif_destroy_st_pqp(sdev, pqi->ki_s.spqp[i]);
	kfree(pqi->ki_s.bitmap);
	kfree(pqi->ki_s.spqp);
	pqi->ki_s.spqp = NULL;
}

int sif_pqp_init(struct sif_dev *sdev)
{
	struct sif_pqp *pqp;
	struct sif_pqp_info *pqi = &sdev->pqi;
	struct sif_eps *es = &sdev->es[sdev->mbox_epsc];
	int i;
	int ret = 0;
	uint n_pqps = es->eqs.cnt - 2;

	/* Use a sensible default value for when to query a PQP to see if it got
	 * set to error without an event - will be adjusted dynamically:
	 */
	pqi->pqp_query_ticks = max(1ULL, sdev->min_resp_ticks / 50);

	pqi->pqp = sif_kmalloc(sdev, sizeof(struct sif_pqp *) * n_pqps, GFP_KERNEL | __GFP_ZERO);
	if (!pqi->pqp)
		return -ENOMEM;

	for (i = 0; i < n_pqps; i++) {
		pqp = sif_create_pqp(sdev, i);
		if (IS_ERR(pqp)) {
			if ((i > 0) &&
			    !(eps_version_ge(es, 0, 42))) {
				sif_log(sdev, SIF_INFO,
				"SIF device has an old FW version that only supports one pqp");
				break;
			}
			ret = PTR_ERR(pqp);
			goto failed;
		}
		pqi->pqp[i] = pqp;
	}
	pqi->cnt = i;
	atomic_set(&pqi->next, 0);

	ret = sif_ki_spqp_init(sdev);
	if (ret)
		goto failed;
	return 0;

failed:
	pqi->cnt = i;
	sif_pqp_fini(sdev);
	return ret;
}

void sif_pqp_fini(struct sif_dev *sdev)
{
	struct sif_pqp_info *pqi = &sdev->pqi;

	sif_ki_spqp_fini(sdev);

	/* we must maintain a consistent state of the PQP array
	 * during takedown as these operations themselves
	 * generate PQP requests..
	 */
	while (pqi->cnt > 0) {
		int i = pqi->cnt - 1;
		struct sif_pqp *pqp = pqi->pqp[i];

		if (i > 0) {
			/* Remove ourselves first, except the final PQP */
			pqi->pqp[i] = NULL;
			pqi->cnt--;
		}
		sif_destroy_pqp(sdev, pqp);
		if (i == 0)
			pqi->cnt--;
	}
	kfree(pqi->pqp);
	pqi->pqp = NULL;
}

void handle_pqp_event(struct sif_eq *eq, struct psif_eq_entry *eqe, struct sif_qp *qp)
{
	struct sif_dev *sdev = eq->ba.sdev;
	unsigned long flags;
	struct sif_pqp *pqp = qp->pqp;

	if (eqe->event_status_cq_error) {
		struct sif_cq *cq = get_sif_cq(sdev, eqe->cqd_id);

		if (eqe->vendor_error == TSU_CBLD_CQ_FULL_ERR)
			sif_log(sdev, SIF_INFO, "PQP error due to CQ overrun on CQ %d", cq->index);
		else if (eqe->vendor_error == TSU_CBLD_CQ_ALREADY_IN_ERR)
			sif_log(sdev, SIF_INFO, "PQP error due to CQ %d already in error event",
				cq->index);
		else
			dump_eq_entry(SIF_INFO, "Got unexpected cq_error", eqe);

		WRITE_ONCE(qp->last_set_state, IB_QPS_ERR);
		WRITE_ONCE(pqp->write_only, true);

		spin_lock_irqsave(&pqp->cq->lock, flags);
		_pqp_queue_resurrect(pqp);
		spin_unlock_irqrestore(&pqp->cq->lock, flags);
	} else {
		sif_log(sdev, SIF_INFO, "Received unexpected async event on PQP %d: ", qp->qp_idx);
		sif_logs(SIF_INFO, write_struct_psif_eq_entry(NULL, 0, eqe); printk("\n"));
	}
	atomic_inc(&pqp->ev_cnt);
}

/* NB! Assumed called with cq lock held:
 * Trigger a resurrect operation on the PQP -
 * if necessary - eg. if the QP is in error
 * and no resurrect operation is already queued:
 */
static int _pqp_queue_resurrect(struct sif_pqp *pqp)
{
	enum ib_qp_state s;
	struct pqp_work *work;
	struct sif_dev *sdev = to_sdev(pqp->qp->ibqp.device);
	struct sif_qp *qp = pqp->qp;

	if (READ_ONCE(pqp->res_queued))
		return -EAGAIN;
	s = qp->last_set_state;
	if (s != IB_QPS_ERR && s != IB_QPS_SQE)
		return 0;

	work = kzalloc(sizeof(*work), GFP_ATOMIC);
	if (!work)
		return -ENOMEM;

	work->pqp = pqp;
	INIT_WORK(&work->ws, pqp_resurrect);
	WRITE_ONCE(pqp->res_queued, true);

	queue_work(sdev->wq, &work->ws);
	return -EAGAIN;
}

/* Simplified version of _reset_qp() for PQPs already in error
 * as none of the other workarounds are needed for PQPs in error
 * due to a CQ error. Assumes QP lock is held.
 */
static int _reset_qp_pqp(struct sif_pqp *pqp)
{
	struct sif_dev *sdev = to_sdev(pqp->qp->ibqp.device);
	struct sif_qp *qp = pqp->qp;
	struct sif_sq *sq = get_sq(sdev, qp);
	int ret = 0;
	struct ib_qp_attr mod_attr = {
		.qp_state        = IB_QPS_RESET
	};

	ret = _modify_qp(sdev, qp, &mod_attr, IB_QP_STATE, true, NULL);
	if (ret)
		goto out;

	/* Bring down order needed by rev2 according to bug #3480 */
	ret = poll_wait_for_qp_writeback(sdev, qp);
	if (ret)
		goto out;

	ret = sif_flush_sqs(sdev, sq);
	if (ret)
		goto out;

	/* Re-initialize the HW QP state as after create_qp() */
	init_hw_qp_state(sdev, qp);
out:
	return ret;
}


/* Called with QP lock held. Check SQ state and
 * trigger SQ mode if there are outstanding requests
 * that failed in the previous "life" of this PQP.
 * The QP is already in RTS but new reqs are held back
 * by pqp->write_only being set:
 */
static int _retrigger_sq(struct sif_pqp *pqp)
{
	unsigned long flags;
	struct sif_dev *sdev = to_sdev(pqp->qp->ibqp.device);
	struct sif_sq *sq = get_sq(sdev, pqp->qp);
	struct sif_sq_sw *sq_sw = get_sif_sq_sw(sdev, pqp->qp->qp_idx);
	int ql;

	spin_lock_irqsave(&sq->lock, flags);
	ql = sq_length(sq, sq_sw->head_seq, sq_sw->last_seq);

	if (ql > 0) {
		u32 sq_seq = sq_sw->head_seq + 1;

		sif_log(sdev, SIF_INFO, "Queue length %d, start at %u", ql, sq_seq);

		/* Outstanding requests, must trigger SQ mode: */
		sif_doorbell_from_sqe(pqp->qp, sq_seq, true);

		sif_logs(SIF_PQPT,
			struct sif_sq *sq = get_sif_sq(sdev, pqp->qp->qp_idx);
			struct psif_sq_entry *sqe = get_sq_entry(sq, sq_seq);

			write_struct_psif_sq_entry(NULL, 1, sqe));
	}

	/* Finally reset the write only flag:
	 * While the flag is set, post operations will just be written
	 * to the send queue without any collect buffer write:
	 */
	WRITE_ONCE(pqp->write_only, false);
	spin_unlock_irqrestore(&sq->lock, flags);
	return 0;
}


/* Process a pqp_work work element to resurrect a PQP that is in error.
 * This function assumes this is due to a CQ error on a user CQ:
 */
static void pqp_resurrect(struct work_struct *work)
{
	struct pqp_work *rw = container_of(work, struct pqp_work, ws);
	struct sif_pqp *pqp = rw->pqp;
	struct sif_qp *qp = pqp->qp;
	struct sif_dev *sdev = to_sdev(pqp->qp->ibqp.device);
	unsigned long flags;
	int ret;

	sif_log(sdev, SIF_PQP, " PQP %d", qp->qp_idx);

	mutex_lock(&qp->lock);
	ret = _reset_qp_pqp(pqp);
	if (ret)
		goto out;

	ret = _modify_reset_to_rts(sdev, qp, true);
	if (ret)
		goto out;

	/* Now retrigger any accidental 3rd party requests
	 * that failed in the previous "life" of the PQP:
	 */
	ret = _retrigger_sq(pqp);
	if (ret)
		goto out;

	spin_lock_irqsave(&pqp->cq->lock, flags);
	/* Avoid losing an acciental update to the state */
	if (qp->last_set_state == IB_QPS_RTS)
		WRITE_ONCE(pqp->res_queued, false);
	spin_unlock_irqrestore(&pqp->cq->lock, flags);
out:
	mutex_unlock(&qp->lock);
	kfree(rw);
	if (ret)
		sif_log(sdev, SIF_INFO, "Fatal error: Failed to resurrect PQP %d",
			qp->qp_idx);

	sif_log(sdev, SIF_PQP, " PQP %d done", qp->qp_idx);
}

void sif_dfs_print_pqp(struct seq_file *s, struct sif_dev *sdev, loff_t pos)
{
	struct sif_qp *qp;
	struct sif_pqp *pqp;
	struct sif_pqp_info *pqi = &sdev->pqi;

	if (unlikely(pos < 0)) {
		seq_printf(s, "# Global PQP config:\n# Number of normal PQPs: %u\n# Next PQP in RR: %u\n"
			"#\n# Per PQP stats:\n# qmax = Longest PQP send queue observed (during poll)\n"
			"# tmax = Max time in msec observed for a PQP req\n"
			"# evc = #of PQP async events seen\n#\n"
			"#Index State %6s qmax   tmax  evc\n", pqi->cnt,
			atomic_read(&pqi->next), "CQ");
		return;
	}

	qp = get_sif_qp(sdev, pos);
	if (qp->type != PSIF_QP_TRANSPORT_MANSP1)
		return;
	pqp = qp->pqp;

	seq_printf(s, "%6llu %5u %6u %4u %6u  %u", pos, qp->last_set_state,
		get_psif_qp_core__send_cq_indx(&qp->d.state),
		pqp->max_qlen, jiffies_to_msecs(pqp->max_cmpl_time), atomic_read(&pqp->ev_cnt));
	if (qp->flags & SIF_QPF_KI_STENCIL)
		seq_puts(s, "  [ki_stencil]\n");
	else
		seq_puts(s, "\n");
}
