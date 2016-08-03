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
 * sif_r3.c: Special handling specific for psif revision 3 and earlier
 */
#include "sif_dev.h"
#include "sif_r3.h"
#include "sif_base.h"
#include "sif_query.h"
#include "sif_qp.h"
#include "sif_ibqp.h"
#include "sif_sndrcv.h"
#include "sif_ibcq.h"
#include "sif_defs.h"
#include "psif_hw_setget.h"

/* Declared below: */
static void sif_hw_free_flush_qp(struct sif_dev *sdev, u8 flush_idx);
static int sif_hw_allocate_flush_qp(struct sif_dev *sdev, u8 flush_idx);
static int sif_hw_allocate_dne_qp(struct sif_dev *sdev);
static void sif_hw_free_dne_qp(struct sif_dev *sdev);

static int outstanding_wqes(struct sif_dev *sdev, struct sif_qp *qp, u16 *head);
static u16 cq_walk_wa4074(struct sif_dev *sdev, struct sif_qp *qp, bool *last_seq_set);
static u16 walk_and_update_cqes(struct sif_dev *sdev, struct sif_qp *qp, u16 head, u16 end);

void sif_r3_pre_init(struct sif_dev *sdev)
{
	/* Init the flush_retry qp lock */
	u8 flush_idx;
	for (flush_idx = 0; flush_idx < 2; ++flush_idx)
		mutex_init(&sdev->flush_lock[flush_idx]);
}

int sif_r3_init(struct sif_dev *sdev)
{
	int ret;
	u8 flush_idx;
	bool dne_qp_alloc = false;

	if (sdev->limited_mode)
		return 0;

	if (eps_fw_version_lt(&sdev->es[sdev->mbox_epsc], 0, 58)) {
		ret = sif_hw_allocate_dne_qp(sdev);
		if (ret)
			return ret;
		dne_qp_alloc = true;
	}
	for (flush_idx = 0; flush_idx < 2; ++flush_idx) {
		ret = sif_hw_allocate_flush_qp(sdev, flush_idx);
		if (ret)
			goto flush_retry_failed;
	}

	return 0;
flush_retry_failed:
	if (dne_qp_alloc)
		sif_hw_free_dne_qp(sdev);
	return ret;
}


void sif_r3_deinit(struct sif_dev *sdev)
{
	u8 flush_idx;
	for (flush_idx = 0; flush_idx < 2; ++flush_idx)
		sif_hw_free_flush_qp(sdev, flush_idx);

	if (eps_fw_version_lt(&sdev->es[sdev->mbox_epsc], 0, 58))
		sif_hw_free_dne_qp(sdev);
}


static int sif_hw_allocate_dne_qp(struct sif_dev *sdev)
{
	int ret;
	u32 idx = sif_alloc_qp_idx(sdev->pd);
	struct sif_qp *qp;
	struct psif_qp lqp;
	struct psif_query_qp lqqp;

	if (idx < 0) {
		sif_log(sdev, SIF_INFO, "Unable to reserve QP index for the do-not-evict qp");
		return -ENOMEM;
	}
	sdev->dne_qp = idx;
	qp = get_sif_qp(sdev, idx);
	/* Make dfs and query_qp happy: */
	qp->qp_idx = idx;
	qp->ibqp.device = &sdev->ib_dev;
	qp->ibqp.pd = &sdev->pd->ibpd;
	qp->rq_idx = -1;
	qp->last_set_state = IB_QPS_RTS;
	qp->flags = SIF_QPF_NO_EVICT;
	mutex_init(&qp->lock);

	memset(&lqp, 0, sizeof(struct psif_qp));

	lqp.state.do_not_evict = 1;
	lqp.state.timeout_time = 0xffffffffffffULL; /* 48 bits */
	lqp.state.state = PSIF_QP_STATE_RTS;
	lqp.state.timer_running = 1;
	lqp.state.transport_type = PSIF_QP_TRANSPORT_RC;

	/* Write composed entry to shared area */
	copy_conv_to_hw(&qp->d, &lqp, sizeof(struct psif_qp));

	/* Do a query_qp to make PSIF fill it's cache with it
	 *- we dont care about the results from the query other than
	 * that the operation succeeds:
	 */
	ret = epsc_query_qp(qp, &lqqp);
	if (ret) {
		sif_log(sdev, SIF_INFO, "query_qp failed with status %d", ret);
		return ret;
	}
	ret = sif_dfs_add_qp(sdev, qp);
	if (ret) {
		sif_log(sdev, SIF_INFO, "Failed to allocate do-not-evict qp, index %d", idx);
		return ret;
	}
	sif_log(sdev, SIF_INFO, "Allocated do-not-evict qp, index %d", idx);
	return 0;
}



static void sif_hw_free_dne_qp(struct sif_dev *sdev)
{
	if (sdev->dne_qp) {
		/* Modify it to reset via error to flush it out.
		 * We cannot use destroy_qp since it is not a "fully configured" QP:
		 */
		struct sif_qp *qp = get_sif_qp(sdev, sdev->dne_qp);
		struct ib_qp_attr mod_attr = {
			.qp_state        = IB_QPS_RESET,
		};
		modify_qp_hw_wa_qp_retry(sdev, qp, &mod_attr, IB_QP_STATE);
		sif_dfs_remove_qp(qp);
		sif_free_qp_idx(sdev->pd, sdev->dne_qp);
		sdev->dne_qp = 0;
	}
}


static int sif_hw_allocate_flush_qp(struct sif_dev *sdev, u8 flush_idx)
{
	int ret = 0;
	struct sif_qp *qp = NULL;
	struct sif_cq *cq = NULL;
	u8 port = flush_idx + 1;

	struct ib_qp_init_attr init_attr = {
		.event_handler = NULL,
		.srq = NULL,
		.cap = {
			.max_send_wr = 64,
			.max_recv_wr = 64,
			.max_send_sge = 1,
			.max_recv_sge = 1,
		},
		.sq_sig_type = IB_SIGNAL_ALL_WR,
		.qp_type = IB_QPT_RC,
	};

	struct sif_qp_init_attr sif_attr = {
		.pd = sdev->pd,
		.qp_type = ib2sif_qp_type(init_attr.qp_type),
		.user_mode = NULL,
		.sq_hdl_sz = sizeof(struct sif_sq_hdl),
		.qosl = QOSL_LOW_LATENCY,
	};

	enum ib_qp_attr_mask qp_attr_mask =
		IB_QP_STATE |
		IB_QP_PKEY_INDEX |
		IB_QP_PORT |
		IB_QP_ACCESS_FLAGS;

	struct ib_qp_attr qp_attr = {
		.qp_state = IB_QPS_INIT,
		.pkey_index = 0,
		.port_num = port,
		.qp_access_flags =
		IB_ACCESS_REMOTE_WRITE |
		IB_ACCESS_REMOTE_READ |
		IB_ACCESS_REMOTE_ATOMIC,
	};

	struct ib_port_attr lpa;

	/* No QPs when running in limited mode */
	if (sdev->limited_mode)
		return 0;

	ret = sif_query_port(&sdev->ib_dev, port, &lpa);
	if (unlikely(ret)) {
		sif_log(sdev, SIF_INFO, "Failed to query port %d", port);
		goto err_query_port;
	}

	/* CQ */
	cq = create_cq(sdev->pd,
		init_attr.cap.max_send_wr + init_attr.cap.max_recv_wr,
		1, SIFPX_OFF, false);
	if (IS_ERR(cq)) {
		sif_log(sdev, SIF_INFO, "Failed to create CQ for flush_retry QP port %d", port);
		return -EINVAL;
	}
	init_attr.send_cq = &cq->ibcq;
	init_attr.recv_cq = &cq->ibcq;
	cq->ibcq.device = &sdev->ib_dev; /* Make destroy cq happy */

	/* QP */
	qp = create_qp(sdev, &init_attr, &sif_attr);
	if (IS_ERR(qp)) {
		sif_log(sdev, SIF_INFO, "Failed to create flush_retry QP port %d", port);
		ret = -EINVAL;
		goto err_create_qp;
	}

	sif_log(sdev, SIF_QP, "Exit: success flush_retry qp 0x%p  ib qp %d - real qp %d",
		&qp->ibqp, qp->ibqp.qp_num, qp->qp_idx);


	/* Make query & modify qp happy */
	qp->ibqp.qp_num = qp->qp_idx;
	qp->ibqp.device = &sdev->ib_dev;
	qp->ibqp.pd = &sdev->pd->ibpd;
	qp->ibqp.qp_type = init_attr.qp_type;
	qp->type = sif_attr.qp_type;
	qp->port = port;
	qp->flags = SIF_QPF_FLUSH_RETRY;

	ret = sif_modify_qp(&qp->ibqp, &qp_attr, qp_attr_mask, NULL);
	if (ret) {
		sif_log(sdev, SIF_INFO, "modify_qp to init failed with status %d", ret);
		goto err_modify_qp;
	}

	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IB_QPS_RTR;
	qp_attr.path_mtu = IB_MTU_2048;
	qp_attr.dest_qp_num = qp->qp_idx;
	qp_attr.rq_psn = 0;
	qp_attr.max_dest_rd_atomic = 1;
	qp_attr.min_rnr_timer = 1;
	qp_attr.ah_attr.dlid = lpa.lid;
	qp_attr.ah_attr.port_num = port;
	qp_attr_mask =
		IB_QP_STATE |
		IB_QP_AV |
		IB_QP_PATH_MTU |
		IB_QP_DEST_QPN |
		IB_QP_RQ_PSN |
		IB_QP_MAX_DEST_RD_ATOMIC |
		IB_QP_MIN_RNR_TIMER;

	ret = sif_modify_qp(&qp->ibqp, &qp_attr, qp_attr_mask, NULL);
	if (ret) {
		sif_log(sdev, SIF_INFO, "modify_qp to RTR failed with status %d", ret);
		goto err_modify_qp;
	}

	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state = IB_QPS_RTS;
	qp_attr.sq_psn = 0;
	qp_attr.timeout = 0;
	qp_attr.retry_cnt = 7;
	qp_attr.rnr_retry = 7;
	qp_attr.max_rd_atomic = 1;
	qp_attr_mask =
		IB_QP_STATE |
		IB_QP_TIMEOUT |
		IB_QP_RETRY_CNT |
		IB_QP_RNR_RETRY |
		IB_QP_SQ_PSN |
		IB_QP_MAX_QP_RD_ATOMIC;

	ret = sif_modify_qp(&qp->ibqp, &qp_attr, qp_attr_mask, NULL);
	if (ret) {
		sif_log(sdev, SIF_INFO, "modify_qp to RTS failed with status %d", ret);
		goto err_modify_qp;
	}

	sdev->flush_qp[flush_idx] = qp->qp_idx;
	sif_log(sdev, SIF_QP, "Allocated flush-retry qp port %d, index %d", port, sdev->flush_qp[flush_idx]);

	return ret;

err_modify_qp:
	destroy_qp(sdev, qp);
err_create_qp:
	destroy_cq(cq);
err_query_port:
	sdev->flush_qp[flush_idx] = 0;
	sif_log(sdev, SIF_INFO, "Allocated flush-retry qp port %d failed", port);

	return ret;
}

static void sif_hw_free_flush_qp(struct sif_dev *sdev, u8 flush_idx)
{
	struct sif_qp *qp = NULL;
	struct sif_sq *sq = NULL;
	struct sif_cq *cq = NULL;

	if (sdev->flush_qp[flush_idx]) {
		qp = get_sif_qp(sdev, sdev->flush_qp[flush_idx]);
		sq = get_sif_sq(sdev, sdev->flush_qp[flush_idx]);
		cq = get_sif_cq(sdev, sq->cq_idx);

		destroy_qp(sdev, qp);
		destroy_cq(cq);
		sdev->flush_qp[flush_idx] = 0;

		sif_log(sdev, SIF_QP, "destroy_qp %d success", qp->qp_idx);
	}
}

void sif_r3_recreate_flush_qp(struct sif_dev *sdev, u8 flush_idx)
{
	/* For simplicity we just destroy the old
	 * and allocate a new flush_retry qp.
	 */
	mutex_lock(&sdev->flush_lock[flush_idx]);
	sif_hw_free_flush_qp(sdev, flush_idx);
	sif_hw_allocate_flush_qp(sdev, flush_idx);
	mutex_unlock(&sdev->flush_lock[flush_idx]);
}

int reset_qp_flush_retry(struct sif_dev *sdev, u8 flush_idx)
{
	struct sif_qp *qp = NULL;
	struct psif_query_qp lqqp;

	struct ib_send_wr *sbad_wr;
	struct ib_send_wr snd_wr = {
		.wr_id   = 0x1,
		.sg_list = NULL,
		.opcode  = IB_WR_SEND,
		.num_sge = 0, /* ZERO byte */
		.next    = NULL,
	};
	struct ib_recv_wr *rbad_wr;
	struct ib_recv_wr rcv_wr = {
		.wr_id   = 0x2,
		.sg_list = NULL,
		.next    = NULL,
		.num_sge = 0,
	};

	struct sif_rq *rq = NULL;
	struct sif_cq *cq = NULL;

	int ret = 0;
	int rte, rtc;
	int count;
	unsigned long timeout = sdev->min_resp_ticks;
	unsigned long timeout_real;
	u8 port = flush_idx + 1;

	/* Get access to the flush_retry QP */
	mutex_lock(&sdev->flush_lock[flush_idx]);

	if (!sdev->flush_qp[flush_idx]) {
		sif_log(sdev, SIF_INFO,
			"special handling WA_3714 failed: flush_qp port %d does not exist",
			port);
		ret = -EINVAL;
		goto err_flush_qp;
	}

	qp = get_sif_qp(sdev, sdev->flush_qp[flush_idx]);

	/* Query flush_retry QP */
	ret = epsc_query_qp(qp, &lqqp);
	if (ret) {
		sif_log(sdev, SIF_INFO, "epsc_query_qp failed with status %d", ret);
		goto fail;
	}

	/* Store retry_tag_err and retry_tag_committed */
	rte = lqqp.qp.retry_tag_err;
	rtc = lqqp.qp.retry_tag_committed;

	/* Post one zero byte send */
	ret = sif_post_send(&qp->ibqp, &snd_wr, &sbad_wr);
	if (ret) {
		sif_log(sdev, SIF_INFO, "sif_post_send failed with status %d", ret);
		goto fail;
	}

	timeout_real = jiffies + timeout;
	while (rte == lqqp.qp.retry_tag_err || rtc == lqqp.qp.retry_tag_committed) {
		if (time_is_after_jiffies(timeout_real)) {
			cond_resched();
			ret = epsc_query_qp(qp, &lqqp);
			if (ret) {
				sif_log(sdev, SIF_INFO, "epsc_query_qp failed with status %d", ret);
				goto fail;
			}
		} else {
			sif_log(sdev, SIF_INFO, "Timeout waiting for flush retry");
			ret = -ETIMEDOUT;
			goto fail;
		}
	}

	/* Post an RQE to the RQ */
	ret = sif_post_recv(&qp->ibqp, &rcv_wr, &rbad_wr);
	if (ret) {
		sif_log(sdev, SIF_INFO, "sif_post_recv failed with status %d", ret);
		goto fail;
	}

	/* Poll out the completions of the CQ */
	rq = get_sif_rq(sdev, qp->rq_idx);
	cq = get_sif_cq(sdev, rq->cq_idx);

	count = 0;
	timeout_real = jiffies + timeout;
	while (count < 2) {
		struct ib_wc wcs[2];
		int sts = sif_poll_cq(&cq->ibcq, 2, wcs);

		if (sts < 0) {
			sif_log(sdev, SIF_INFO, "sif_poll_cq failed with status %d", sts);
			ret = sts;
			goto fail;
		} else
			count += sts;

		if (time_is_after_jiffies(timeout_real))
			cond_resched();
		else {
			sif_log(sdev, SIF_INFO, "Timeout waiting for completions");
			for (sts = 0; sts < count; sts++)
				sif_log(sdev, SIF_INFO, "wr_id %lld status %d opcode %d",
					wcs[sts].wr_id, wcs[sts].status, wcs[sts].opcode);
			ret = epsc_query_qp(qp, &lqqp);
			if (ret)
				sif_log(sdev, SIF_INFO, "epsc_query_qp failed with status %d", ret);

			sif_logs(SIF_INFO, write_struct_psif_query_qp(NULL, 0, &lqqp));
			goto fail;
		}
	}

	atomic64_inc(&sdev->wa_stats.wa3714[FLUSH_RETRY_WA3714_CNT]);
	mutex_unlock(&sdev->flush_lock[flush_idx]);
	return ret;
fail:
	atomic64_inc(&sdev->wa_stats.wa3714[FLUSH_RETRY_WA3714_ERR_CNT]);
	sif_hw_free_flush_qp(sdev, flush_idx);
	sif_hw_allocate_flush_qp(sdev, flush_idx);
	mutex_unlock(&sdev->flush_lock[flush_idx]);
	return ret;

err_flush_qp:
	atomic64_inc(&sdev->wa_stats.wa3714[FLUSH_RETRY_WA3714_ERR_CNT]);
	mutex_unlock(&sdev->flush_lock[flush_idx]);
	return ret;
}

static int outstanding_wqes(struct sif_dev *sdev, struct sif_qp *qp, u16 *head)
{
	struct sif_sq *sq = get_sif_sq(sdev, qp->qp_idx);
	struct sif_sq_sw *sq_sw = get_sif_sq_sw(sdev, qp->qp_idx);
	struct psif_query_qp lqqp;
	int ret = 0;

	ret = epsc_query_qp(qp, &lqqp);
	if (ret) {
		sif_log(sdev, SIF_INFO, "epsc_query_qp failed with status %d", ret);
		return ret;
	}
	if (head)
		*head = lqqp.qp.retry_sq_seq;

	return sq_length(sq, lqqp.qp.retry_sq_seq, sq_sw->last_seq);
}

int pre_process_wa4074(struct sif_dev *sdev, struct sif_qp *qp)
{
	struct sif_sq *sq = get_sq(sdev, qp);
	struct psif_sq_entry *sqe;
	u16 head;
	int len;
	unsigned long flags;
	struct sif_cq *cq = (sq && sq->cq_idx >= 0) ? get_sif_cq(sdev, sq->cq_idx) : NULL;
	struct sif_cq_sw *cq_sw = cq ? get_sif_cq_sw(sdev, cq->index) : NULL;

	if (qp->flags & SIF_QPF_NO_EVICT)
		return 0; /* do-not-evict QPs don't have any SQs */

	if (unlikely(!sq)) {
		sif_log(sdev, SIF_INFO, "sq not defined for qp %d (type %s)",
			qp->qp_idx, string_enum_psif_qp_trans(qp->type));
		return -1;
	}

	len = outstanding_wqes(sdev, qp, &head);
	if (len <= 0)
		return -1;

	spin_lock_irqsave(&sq->lock, flags);
	while (len) {
		head++;
		sqe = get_sq_entry(sq, head);
		set_psif_wr__checksum(&sqe->wr, ~get_psif_wr__checksum(&sqe->wr));
		len--;
	}
	atomic64_add(len, &sdev->wa_stats.wa4074[WRS_CSUM_CORR_WA4074_CNT]);
	spin_unlock_irqrestore(&sq->lock, flags);
	if (cq)
		set_bit(CQ_POLLING_NOT_ALLOWED, &cq_sw->flags);

	atomic64_inc(&sdev->wa_stats.wa4074[PRE_WA4074_CNT]);

	return 0;
}

/* QP is in RESET state, its now safe to do a cq_walk and
 * flush any completions.
 */
int post_process_wa4074(struct sif_dev *sdev, struct sif_qp *qp)
{
	struct sif_sq *sq = get_sq(sdev, qp);
	struct sif_sq_sw *sq_sw = sq ? get_sif_sq_sw(sdev, qp->qp_idx) : NULL;
	struct psif_qp lqqp;
	bool last_seq_set = false;
	u16 last_seq, fence_seq, last_gen_seq;
	unsigned long flags;
	DECLARE_SIF_CQE_POLL(sdev, lcqe);
	int ret = 0;
	bool need_gen_fence_completion = true;
	struct sif_cq *cq = (sq && sq->cq_idx >= 0) ? get_sif_cq(sdev, sq->cq_idx) : NULL;
	struct sif_cq_sw *cq_sw = cq ? get_sif_cq_sw(sdev, cq->index) : NULL;

	if (unlikely(!sq || !cq)) {
		sif_log(sdev, SIF_INFO, "sq/cq not defined for qp %d (type %s)",
			qp->qp_idx, string_enum_psif_qp_trans(qp->type));
		return -1;
	}

	if (qp->flags & SIF_QPF_HW_OWNED) {
		sif_log(sdev, SIF_INFO, "qp %d is not in SHADOWED ERR state yet",
			qp->qp_idx);
		return ret;
	}

	/* if flush SQ is in progress, set FLUSH_SQ_IN_FLIGHT.
	 */
	if (test_bit(FLUSH_SQ_IN_PROGRESS, &sq_sw->flags)) {
		set_bit(FLUSH_SQ_IN_FLIGHT, &sq_sw->flags);
		return ret;
	}

	if (test_and_set_bit(FLUSH_SQ_IN_PROGRESS, &sq_sw->flags)) {
		set_bit(FLUSH_SQ_IN_FLIGHT, &sq_sw->flags);
		return ret;
	}

	if ((sq_sw->last_seq - sq_sw->head_seq) == 0)
		goto err_post_wa4074;

	/* if SQ has been flushed before, continue to generate
	 * the remaining completions.
	 */
	if (test_and_set_bit(FLUSH_SQ_FIRST_TIME, &sq_sw->flags)) {
		sif_log(sdev, SIF_WCE_V, "flush sq not the first time");
		last_seq = sq_sw->trusted_seq;
		goto flush_sq_again;
	}

	copy_conv_to_sw(&lqqp, &qp->d, sizeof(lqqp));
	last_seq = sq_sw->last_seq;

	set_bit(CQ_POLLING_NOT_ALLOWED, &cq_sw->flags);

	sif_log(sdev, SIF_WCE_V, "sq_retry_seq %x sq_seq %x last_seq %x head_seq %x",
		lqqp.state.retry_sq_seq, lqqp.state.sq_seq, sq_sw->last_seq, sq_sw->head_seq);

	/* need_gen_fence_completion is used to flush any cqes in the pipeline.
	 * If this is a good case, no fence completion is needed.
	 * Proceed directly to walk and update the CQE. The good case
	 * is only true if retry_tag_committed == retry_tag_err &&
	 * retry_sq_seq + 1 == sq_seq && !flush_started.
	 */

	need_gen_fence_completion = ((lqqp.state.retry_tag_committed != lqqp.state.retry_tag_err) ||
				     (lqqp.state.retry_sq_seq + 1 != lqqp.state.sq_seq) ||
				     (lqqp.state.flush_started));

	if (need_gen_fence_completion) {

		/* This is just a sequence number that we use to flush any cqes in the pipeline.
		 * Before walking the CQ, we need to ensure that we receive a cqe with fence_seq.
		 */
		fence_seq = sq_sw->head_seq + 1;

		sif_log(sdev, SIF_WCE_V, "fence_seq %x",
			fence_seq);

		/* Completion fence, this also flushes any cqes in pipeline */
		ret = sif_gen_sq_flush_cqe(sdev, sq, fence_seq, qp->qp_idx, false);
		if (ret)
			sif_log(sdev, SIF_INFO, "sq %d, sif_gen_sq_flush_cqe returned %d",
				sq->index, ret);

		if (ret == -EAGAIN) {
			ret = gen_pqp_cqe(&lcqe);
			if (ret < 0)
				goto err_post_wa4074;

			ret = poll_cq_waitfor(&lcqe);
			if (ret < 0)
				goto err_post_wa4074;

			lcqe.written = false;
		}

		/* Generate a sync.completion for us on the PQP */
		ret = gen_pqp_cqe(&lcqe);
		if (ret < 0) {
			sif_log(sdev, SIF_INFO, "SQ %d, gen_pqp_cqe ret %d", sq->index, ret);
			goto err_post_wa4074;
		}
		ret = poll_cq_waitfor(&lcqe);
		if (ret < 0) {
			sif_log(sdev, SIF_INFO, "SQ %d, poll_cq_waitfor failed, ret %d",
				sq->index, ret);
			goto err_post_wa4074;
		}

		last_seq = cq_walk_wa4074(sdev, qp, &last_seq_set);

		if (!last_seq_set) {
			sif_log(sdev, SIF_INFO, "failed to generate a completion to cq");
			goto err_post_wa4074;
		}

		if (last_seq != fence_seq) {
			sif_log(sdev, SIF_INFO, "last seq (%x) is different than fenced completion (%x)!",
				last_seq, fence_seq);
			/* As the Fenced completion cannot be guaranteed to be the last, software
			 * still needs to walk and update the CQ to avoid unexpected
			 * completion/duplicated completion even thought the last completion is
			 * the CQ is not generated fenced completion.
			 */
		}

	sif_log(sdev, SIF_WCE_V, "after: sq_retry_seq %x sq_seq %x last_seq %x head_seq %x",
		lqqp.state.retry_sq_seq, lqqp.state.sq_seq, sq_sw->last_seq, sq_sw->head_seq);

	}
	last_seq = walk_and_update_cqes(sdev, qp, sq_sw->head_seq + 1, sq_sw->last_seq);
	sq_sw->trusted_seq = last_seq;

	clear_bit(CQ_POLLING_NOT_ALLOWED, &cq_sw->flags);

	if (GREATER_16(last_seq, sq_sw->last_seq)) {
		sif_log(sdev, SIF_WCE_V, "last seq %x > sq_sw->last_seq %x\n", last_seq, sq_sw->last_seq);
		if (!(qp->flags & SIF_QPF_USER_MODE) && (cq->ibcq.comp_handler)) {
			if (atomic_add_unless(&cq->refcnt, 1, 0)) {
				sif_log(sdev, SIF_WCE_V, "need to generate an event to cq %d\n", cq->index);
				cq->ibcq.comp_handler(&cq->ibcq, cq->ibcq.cq_context);
				if (atomic_dec_and_test(&cq->refcnt))
					complete(&cq->cleanup_ok);
			}
		}
		goto check_in_flight_and_return;
	}

flush_sq_again:
	/* We need lock here to retrieve the sq_sw->last_seq
	 * to make sure that post_send with sq_sw->last_seq is
	 * completed before generating a sq_flush_cqe.
	 */
	spin_lock_irqsave(&sq->lock, flags);
	last_gen_seq = sq_sw->last_seq;
	spin_unlock_irqrestore(&sq->lock, flags);

	sif_log(sdev, SIF_WCE_V, "generate completion from %x to %x",
		last_seq, last_gen_seq);

	for (; (!GREATER_16(last_seq, last_gen_seq)); ++last_seq) {
		sif_log(sdev, SIF_WCE_V, "generate completion %x",
			last_seq);

		ret = sif_gen_sq_flush_cqe(sdev, sq, last_seq, qp->qp_idx, true);
		if (ret)
			sif_log(sdev, SIF_INFO,
				"sq %d, last_seq %x, sif_gen_sq_flush_cqe returned %d",
				sq->index, last_seq, ret);

		atomic64_inc(&sdev->wa_stats.wa4074[RCV_SND_GEN_WA4074_CNT]);

		if (ret == -EAGAIN) {
			ret = gen_pqp_cqe(&lcqe);
			if (ret < 0)
				goto err_post_wa4074;

			ret = poll_cq_waitfor(&lcqe);
			if (ret < 0)
				goto err_post_wa4074;

			lcqe.written = false;
			continue;
		}

		if (ret < 0)
			goto err_post_wa4074;
	}

	/* Generate a sync.completion for us on the PQP itself
	 * to allow us to wait for the whole to complete:
	 */
	ret = gen_pqp_cqe(&lcqe);
	if (ret < 0) {
		sif_log(sdev, SIF_INFO, "SQ %d, gen_pqp_cqe ret %d", sq->index, ret);
		goto err_post_wa4074;
	}
	ret = poll_cq_waitfor(&lcqe);
	if (ret < 0) {
		sif_log(sdev, SIF_INFO, "SQ %d, poll_cq_waitfor failed, ret %d",
			sq->index, ret);
		goto err_post_wa4074;
	}

	sif_log(sdev, SIF_INFO_V, "SQ %d: recv'd completion on cq %d seq 0x%x - done, ret %d",
		sq->index, sq->cq_idx, lcqe.cqe.seq_num, ret);
	sq_sw->trusted_seq = last_seq;

check_in_flight_and_return:
	if (test_and_clear_bit(FLUSH_SQ_IN_FLIGHT, &sq_sw->flags))
		goto flush_sq_again;

err_post_wa4074:
	clear_bit(CQ_POLLING_NOT_ALLOWED, &cq_sw->flags);
	clear_bit(FLUSH_SQ_IN_FLIGHT, &sq_sw->flags);
	clear_bit(FLUSH_SQ_IN_PROGRESS, &sq_sw->flags);

	if (ret < 0)
		atomic64_inc(&sdev->wa_stats.wa4074[POST_WA4074_ERR_CNT]);
	else
		atomic64_inc(&sdev->wa_stats.wa4074[POST_WA4074_CNT]);

	return ret = ret > 0 ? 0 : ret;
}

/* Walk the CQ, update the cqe from head to end and return the last_seq */
static u16 walk_and_update_cqes(struct sif_dev *sdev, struct sif_qp *qp, u16 head, u16 end)
{
	struct sif_sq *sq = get_sif_sq(sdev, qp->qp_idx);
	struct sif_cq *cq = sq->cq_idx >= 0 ? get_sif_cq(sdev, sq->cq_idx) : NULL;
	struct sif_cq_sw *cq_sw = get_sif_cq_sw(sdev, cq->index);
	volatile struct psif_cq_entry *cqe;
	u16 last_seq = 0, updated_seq;
	u32 seqno, polled_value;
	unsigned long flags = 0;
	int n = 0;

	updated_seq = head;
	last_seq = head;

	spin_lock_irqsave(&cq->lock, flags);

	for (seqno = cq_sw->next_seq;; ++seqno) {
		struct psif_cq_entry lcqe;

		cqe = get_cq_entry(cq, seqno);
		polled_value = get_psif_cq_entry__seq_num(cqe);

		if (seqno != polled_value)
			break;

		if (get_psif_cq_entry__qp(cqe) != qp->qp_idx)
			continue;

		copy_conv_to_sw(&lcqe, cqe, sizeof(lcqe));

		if (!(lcqe.opcode & PSIF_WC_OPCODE_RECEIVE_SEND)) {
			last_seq = lcqe.wc_id.sq_id.sq_seq_num;
			sif_log(sdev, SIF_WCE_V, "last_seq %x updated_seq %x lcqe.seq_num %x",
				last_seq, updated_seq, lcqe.seq_num);
			if (last_seq != updated_seq) {
				lcqe.wc_id.sq_id.sq_seq_num = updated_seq;
				if (GREATER_16(updated_seq, end)) {
					/* A scenario might be that an additional CQE
					 * must be generated to flush all the HW
					 * generated completions. Thus, ignore the polling of the cqe.
					 */
					lcqe.seq_num = ~lcqe.seq_num;
					sif_log(sdev, SIF_WCE_V, "corrupt: lcqe.seq_num %x",
						lcqe.seq_num);
					set_bit(CQ_POLLING_IGNORED_SEQ, &cq_sw->flags);
				}
				copy_conv_to_hw(cqe, &lcqe, sizeof(lcqe));
			}
			if (!GREATER_16(updated_seq, end))
				updated_seq++;
			++n;
		}
	}
	sif_log(sdev, SIF_WCE_V, "sq/cq %d/%d: %d entries not being pulled yet",
		sq->index, cq->index, n);

	spin_unlock_irqrestore(&cq->lock, flags);

	return updated_seq;
}

/* Walk the CQ and return the last completed sq_seq */
static u16 cq_walk_wa4074(struct sif_dev *sdev, struct sif_qp *qp, bool *last_seq_set)
{
	struct sif_sq *sq = get_sif_sq(sdev, qp->qp_idx);
	struct sif_cq *cq = sq->cq_idx >= 0 ? get_sif_cq(sdev, sq->cq_idx) : NULL;
	struct sif_cq_sw *cq_sw = get_sif_cq_sw(sdev, cq->index);
	volatile struct psif_cq_entry *cqe;
	u32 seqno, polled_value;
	unsigned long flags = 0;
	u16 last_seq = 0, prev_seq = 0;
	bool prev_seq_set = false;
	int n = 0;

	spin_lock_irqsave(&cq->lock, flags);

	for (seqno = cq_sw->next_seq;; ++seqno) {
		struct psif_cq_entry lcqe;

		cqe = get_cq_entry(cq, seqno);
		polled_value = get_psif_cq_entry__seq_num(cqe);

		if (seqno != polled_value)
			break;

		if (get_psif_cq_entry__qp(cqe) != qp->qp_idx)
			continue;

		copy_conv_to_sw(&lcqe, cqe, sizeof(lcqe));

		if (!(lcqe.opcode & PSIF_WC_OPCODE_RECEIVE_SEND)) {
			last_seq = lcqe.wc_id.sq_id.sq_seq_num;

			if (!(*last_seq_set))
				*last_seq_set = true;

			if (unlikely(prev_seq_set && prev_seq >= last_seq))
				sif_log(sdev, SIF_INFO_V,
					"sq/cq %d/%d: prev sq_seq (0x%x) >= curr sq_seq (0x%x)",
					sq->index, cq->index, prev_seq, last_seq);

			prev_seq = last_seq;
			if (!(prev_seq_set))
				prev_seq_set = true;
			n++;
		}
	}
	sif_log(sdev, SIF_WCE_V, "sq/cq %d/%d: %d entries not being pulled yet",
		sq->index, cq->index, n);

	spin_unlock_irqrestore(&cq->lock, flags);
	return last_seq;
}

void sif_dfs_print_wa_stats(struct sif_dev *sdev, char *buf)
{
	/* Header WA#3714 */
	sprintf(buf, "\nWA3714: Destroying QPs with a retry in progress\n");
	/* Content WA#3714 */
	sprintf(buf + strlen(buf), "%s: %lu\n%s: %lu\n",
		"ok", atomic64_read(&sdev->wa_stats.wa3714[FLUSH_RETRY_WA3714_CNT]),
		"err", atomic64_read(&sdev->wa_stats.wa3714[FLUSH_RETRY_WA3714_ERR_CNT]));
	/* Header WA#4074 */
	sprintf(buf + strlen(buf), "\nWA4074: Duplicate flushed in error completions\n");
	/* Content WA#4074 */
	sprintf(buf + strlen(buf), "%s: %lu\n%s: %lu\n%s: %lu\n%s: %lu\n%s: %lu\n",
		"pre-ok", atomic64_read(&sdev->wa_stats.wa4074[PRE_WA4074_CNT]),
		"post-ok", atomic64_read(&sdev->wa_stats.wa4074[POST_WA4074_CNT]),
		"post-err", atomic64_read(&sdev->wa_stats.wa4074[POST_WA4074_ERR_CNT]),
		"wr-csum-corr", atomic64_read(&sdev->wa_stats.wa4074[WRS_CSUM_CORR_WA4074_CNT]),
		"rcv-snd-gen", atomic64_read(&sdev->wa_stats.wa4074[RCV_SND_GEN_WA4074_CNT]));
	/* Header WA#4059 */
	sprintf(buf + strlen(buf), "\nWA4059: Mailbox writes from host to EPS sometimes get misplaced\n");
	/* Content WA#4059 */
	sprintf(buf + strlen(buf), "%s: %lu\n%s: %lu\n",
		"keep-alive-int", atomic64_read(&sdev->wa_stats.wa4059[SND_INTR_KEEP_ALIVE_WA4059_CNT]),
		"keep-alive-thread", atomic64_read(&sdev->wa_stats.wa4059[SND_THREAD_KEEP_ALIVE_WA4059_CNT]));
}
