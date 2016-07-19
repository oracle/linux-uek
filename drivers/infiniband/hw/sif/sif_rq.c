/*
 * Copyright (c) 2011, 2016, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_rq.c: Implementation of sif receive queues
 */

#include <rdma/ib_verbs.h>
#include "sif_dev.h"
#include "psif_hw_data.h"
#include "psif_hw_setget.h"
#include "sif_dma.h"
#include "sif_rq.h"
#include "sif_xrc.h"
#include "sif_base.h"
#include "sif_defs.h"
#include <linux/seq_file.h>

static void sif_flush_rq(struct work_struct *work);

int poll_wait_for_rq_writeback(struct sif_dev *sdev, struct sif_rq *rq)
{
	unsigned long timeout = sdev->min_resp_ticks;
	unsigned long timeout_real = jiffies + timeout;
	u8 valid;

	sif_log(sdev, SIF_RQ, "enter rq %d", rq->index);
	do {
		/* Make sure the update from hw is observed in correct order */
		smp_rmb();
		valid = get_psif_rq_hw__valid(&rq->d);

		if (!valid)
			break;

		if (time_is_after_jiffies(timeout_real))
			cpu_relax();
		else {
			sif_log(sdev, SIF_INFO,
				"Timeout waiting for write back for RQ %d - still valid",
				rq->index);
			return -ETIMEDOUT;
		}
	} while (true);

	sif_log(sdev, SIF_RQ, "exit - write-back observed on rq %d", rq->index);
	return 0;
}

int alloc_rq(struct sif_dev *sdev, struct sif_pd *pd,
	u32 entries, u32 sg_entries,
	struct ib_srq_init_attr *srq_init_attr,
	bool user_mode)
{
	int ret = 0;
	bool mark_dirty = false;
	/* Access to receive queue descriptor elements */
	struct sif_rq *rq;
	struct sif_rq_sw *rq_sw;
	volatile struct psif_rq_hw *rq_hw_p;
	struct psif_rq_sw lrq_sw;
	struct psif_xrq_hw lrq_hw;
	int extent_log2;
	struct psif_rq_entry rqe; /* Receive queue element for size calc only */
	u32 max_entries;
	u32 entries_log2;
	int rq_idx;
	u64 alloc_sz;

	max_entries = roundup_pow_of_two(entries);
	entries_log2 = order_base_2(max_entries);

	/* Meaningless with 0 sge */
	if (!sg_entries)
		sg_entries = 1;
	if (sg_entries > 16) {
		sif_log(sdev, SIF_INFO,
			"requested %d but sif only supports 16 receive sg entries",
			sg_entries);
		return -ENOMEM;
	}

	/* Max supporter nmbr of RQ WRs are 2^14 - 1 */
	if (entries > 0x3fff) {
		sif_log(sdev, SIF_INFO,
			"requested %d entries, but sif only supports %d",
			entries, 0x3fff);
		return -ENFILE; /* 4 bit size_log2 field in rqs but highest value not supported (#2965) */
	}

	rq_idx = sif_alloc_rq_hw_idx(pd);

	if (rq_idx < 0) {
		sif_log(sdev, SIF_INFO,
			"unable to allocate a receive queue, consider increasing rq_size");
		ret = -ENOMEM;
		return ret;
	}
	rq = get_sif_rq(sdev, rq_idx);

	/* Make sure the RQ is sofware owned: */
	ret = poll_wait_for_rq_writeback(sdev, rq);
	if (ret) {
		mark_dirty = true;
		goto err_alloc;
	}
	rq->index = rq_idx;
	rq->pd = pd;

	rq_hw_p = &rq->d;
	rq_sw = get_sif_rq_sw(sdev, rq_idx);

	/* Initialize driver/user space state within sw extent */
	atomic_set(&rq_sw->length, 0);
	rq_sw->next_seq = 0;

	rq->entries = max_entries;
	/* Ref. #2965 */
	rq->entries_user = (entries_log2 == 0xe ? max_entries - 1 : max_entries);
	rq->mask = max_entries - 1;
	rq->extent =
		roundup_pow_of_two(sizeof(rqe.rqe_id)
				+ sizeof(struct psif_rq_scatter) * sg_entries);

	/* Now recalculate sge space from the extent to offer any extra room "for free" */
	sg_entries = min((rq->extent - sizeof(rqe.rqe_id)) / sizeof(struct psif_rq_scatter), 16UL);
	extent_log2 = order_base_2(rq->extent);
	alloc_sz = max_entries * rq->extent;

	/* Only whole pages must be exposed to user space */
	if (user_mode && (alloc_sz & ~PAGE_MASK))
		alloc_sz = (alloc_sz + PAGE_SIZE) & PAGE_MASK;
	rq->user_mode = user_mode;

	sif_log(sdev, SIF_QP, "RQ:sw 0x%p, hw 0x%p entries %d index %d extent %d max sge %d",
		rq_sw, rq_hw_p, rq->entries, rq_idx, rq->extent, sg_entries);

	if (alloc_sz <= SIF_MAX_CONT)
		rq->mem = sif_mem_create_dmacont(sdev, alloc_sz, GFP_KERNEL | __GFP_ZERO, DMA_BIDIRECTIONAL);
	else
		rq->mem = sif_mem_create(sdev, alloc_sz >> PMD_SHIFT,
					alloc_sz, SIFMT_2M, GFP_KERNEL | __GFP_ZERO, DMA_BIDIRECTIONAL);
	if (!rq->mem) {
		sif_log(sdev, SIF_INFO, "Failed RQ buffer pool allocation!");
		ret = -ENOMEM;
		goto err_alloc;
	}

	rq->sg_entries = sg_entries;
	init_completion(&rq->can_reset);
	atomic_set(&rq->refcnt, 1);
	atomic_set(&rq->flush_in_progress, 1);

	/* Initialize hw part of descriptor */
	memset(&lrq_hw, 0, sizeof(lrq_hw));

	/* For normal RQs we use the valid bit as follows:
	 *
	 *  - If the QP is in RESET state, the RQ is invalid.
	 *  - The RQ is set to valid as part of transitioning to INIT.
	 *  - The RQ is still valid when the QP is in ERROR state
	 *  - A modify to RESET resets the valid bit again.
	 */

	lrq_hw.size_log2 = entries_log2;
	lrq_hw.prefetch_threshold_log2 = 1;

	/* scatter = 0 means a single entry etc. */
	lrq_hw.scatter = rq->sg_entries - 1;
	lrq_hw.pd = pd->idx;

	lrq_hw.head_indx = 0;
	lrq_hw.base_addr = sif_mem_dma(rq->mem, 0);
	lrq_hw.extent_log2 = extent_log2;

	/* Allocate mmu context without wr_access set */
	ret = sif_map_ctx(sdev, &rq->mmu_ctx, rq->mem, lrq_hw.base_addr,
			alloc_sz, false);
	if (ret) {
		sif_log(sdev, SIF_INFO, "Failed to set mmu context for rq %d",
			rq->index);
		goto err_map_ctx;
	}

	if (srq_init_attr) {
		/* Request for an SRQ */
		lrq_hw.valid = 1; /* SRQs are valid for their entire lifetime */
		lrq_hw.srq = 1;
		lrq_hw.srq_lim = srq_init_attr->attr.srq_limit;
		rq->is_srq = true;

		if (srq_init_attr->srq_type == IB_SRQT_XRC) {
			struct sif_cq *cq = to_scq(srq_init_attr->ext.xrc.cq);
			struct sif_xrcd *xrcd = to_sxrcd(srq_init_attr->ext.xrc.xrcd);
			ulong flags;

			rq->cq_idx = cq->index;
			rq->xrc_domain = lrq_hw.xrc_domain = xrcd->index;
			lrq_hw.cqd_id = rq->cq_idx;
			spin_lock_irqsave(&cq->lock, flags);
			/* We only allow a CQ to be used for one single XSRQ
			 * This is a violation of the IB standard but one
			 * that probably should not have practical conseqences:
			 * See #3521 for details:
			 */
			if (cq->xsrq) {
				sif_log(sdev, SIF_INFO,
					"xsrq %d: cq %d already used with xsrq %d - please use another cq for this xsrq",
					rq->index, cq->index, cq->xsrq->index);
				ret = -EBUSY;
			} else
				cq->xsrq = rq;
			spin_unlock_irqrestore(&cq->lock, flags);
			if (ret)
				goto err_map_ctx;
		}
	}

	/* Get the hw mmu context populated by sif_map_ctx */
	lrq_hw.mmu_cntx = rq->mmu_ctx.mctx;

	/* Write network byte order hw copy */
	copy_conv_to_hw(rq_hw_p, &lrq_hw, sizeof(lrq_hw));

	/* Initialize sw part of descriptor */
	memset(&lrq_sw, 0, sizeof(lrq_sw));
	lrq_sw.tail_indx = rq_sw->next_seq;

	copy_conv_to_hw(&rq_sw->d, &lrq_sw, sizeof(lrq_sw));

	spin_lock_init(&rq->lock);

	return rq_idx;

err_map_ctx:
	sif_mem_free(rq->mem);
err_alloc:
	if (!mark_dirty)
		sif_free_rq_hw_idx(pd, rq_idx);
	return ret;
}


static int find_recv_cqes_in_cq(struct sif_dev *sdev, struct sif_cq *cq, struct sif_qp *qp)
{
	struct sif_cq_sw *cq_sw = get_sif_cq_sw(sdev, cq->index);
	volatile struct psif_cq_entry *cqe;
	u32 seqno;
	u32 polled_value;
	int n = 0;
	unsigned long flags = 0;

	spin_lock_irqsave(&cq->lock, flags);

	for (seqno = cq_sw->next_seq;; ++seqno) {
		cqe = get_cq_entry(cq, seqno);
		polled_value = get_psif_cq_entry__seq_num(cqe);

		/* More CQEs to check? */
		if (seqno != polled_value)
			break;

		/* Look only for this QP */
		if (get_psif_cq_entry__qp(cqe) != qp->qp_idx)
			continue;

		/* Receive completion? */
		if (get_psif_cq_entry__opcode(cqe) & PSIF_WC_OPCODE_RECEIVE_SEND)
			++n;
	}

	spin_unlock_irqrestore(&cq->lock, flags);

	return n;
}


int sif_flush_rq_wq(struct sif_dev *sdev, struct sif_rq *rq, struct sif_qp *target_qp,
		    int max_flushed_in_err)
{
	struct flush_rq_work *work;

	work = kzalloc(sizeof(*work), GFP_ATOMIC);
	if (!work)
		return -ENOMEM;


	memset(work, 0, sizeof(*work));
	work->qp = target_qp;
	work->sdev = sdev;
	work->rq = rq;
	work->entries = max_flushed_in_err;

	INIT_WORK(&work->ws, sif_flush_rq);

	queue_work(sdev->misc_wq, &work->ws);

	return 0;
}

/* Invalidate the RQ cache and flush a desired amount of
 * the remaining entries in the given receive queue.
 * @target_qp indicates the value of the local_qp field in the generated
 * completion. The qp itself would already have been modified to RESET
 * to avoid any more traffic;
 *
 * Workaround #622: PSIF doesn't generate "FLUSHED IN ERROR" completions.
 * In order to maintain OFED verbs-programming and IB spec. compatibility,
 * RQEs needs to be "flushed in error" when
 *  - Verbs layer modifies QP to error
 *  - Hardware sends an async event, after setting the QP in error
 *  - Poll CQ on IB client(kernel/user) receives an error completion
 *    (Responder class A & C) with QP set to error
 *  - More WQEs are posted by IB client(kernel/user) when QP in error
 *  - QP is destroyed
 *
 * Note: No locking of the RQ is neccessary as there are multiple trigger points
 * for flushing RQEs within OFED verbs model.
 */
static void sif_flush_rq(struct work_struct *work)
{
	int len, real_len;
	struct flush_rq_work *rq_work = container_of(work, struct flush_rq_work, ws);
	struct sif_dev *sdev = rq_work->sdev;
	struct sif_qp *target_qp = rq_work->qp;
	struct sif_rq *rq = rq_work->rq;
	int max_flushed_in_err = rq_work->entries;
	struct sif_rq_sw *rq_sw = get_sif_rq_sw(sdev, rq->index);
	int ret = 0;
	u32 head, tail;
	unsigned long flags;
	enum sif_mqp_type mqp_type = SIF_MQP_SW;
	DECLARE_SIF_CQE_POLL(sdev, lcqe);

	/* if flush RQ is in progress, set FLUSH_RQ_IN_FLIGHT.
	 */
	if (test_bit(FLUSH_RQ_IN_PROGRESS, &rq_sw->flags)) {
		set_bit(FLUSH_RQ_IN_FLIGHT, &rq_sw->flags);
		goto done;
	}

	/* if race condition happened while trying to flush RQ,
	 * set the FLUSH_RQ_IN_FLIGHT, and let the other party does the job.
	 */
	if (test_and_set_bit(FLUSH_RQ_IN_PROGRESS, &rq_sw->flags)) {
		set_bit(FLUSH_RQ_IN_FLIGHT, &rq_sw->flags);
		goto done;
	}

	if (!sif_feature(disable_rq_flush))
		len = min(max_flushed_in_err, atomic_read(&rq_sw->length));
	else
		len = 0;
	if (len == 0)
		goto error;

	if (atomic_add_unless(&rq->flush_in_progress, 1, 0)) {
		sif_log(sdev, SIF_INFO_V, "flushing %d entries out of %d/%d entries remaining",
			len, atomic_read(&rq_sw->length), rq->entries);

		/* Workaround #622 v2 step 1: ModifyQP to RESET
		 * The QP must be in the RESET state to avoid race condition.
		 * sif_flush_rq will only be called when the QP is
		 * in ERROR state. As for now, keeping the same coding style to
		 * check whether the qp flags SIF_QPF_HW_OWNED is clear.
		 * If it is clear, it means that the QP is in the shadowed
		 * software error state (actual hw state is in RESET).
		 *
		 * TBD - Should we add new PSIF_QP_STATE_SHADOWED_ERROR state,
		 * at least to me it is more readable?
		 */
		mutex_lock(&target_qp->lock);
		/* qp lock must be held to make sure not other thread is trying to
		 * do modify_qp_hw to RESET.
		 */
		mqp_type = sif_modify_qp_is_ok(target_qp, target_qp->last_set_state,
					       IB_QPS_RESET, IB_QP_STATE);

		if (mqp_type == SIF_MQP_HW) {
			struct ib_qp_attr attr = {
				.qp_state = IB_QPS_ERR
			};

			ret = modify_qp_hw_wa_qp_retry(sdev, target_qp, &attr, IB_QP_STATE);

			if (ret)
				sif_log(sdev, SIF_INFO, "qp %d RESET failed, ret %d",
					target_qp->qp_idx, ret);

		}
		mutex_unlock(&target_qp->lock);

		/* Workaround #622 v2 step 2: Invalidate RQ
		 * Invalidation of an RQ causes PSIF to flush it's caches for that RQ.
		 * If PSIF finds the RQ invalid, it will attempt to fetch it.
		 * It is then required to be valid (otherwise it will be interpreted as an error
		 * by PSIF (see #2134). So software cannot rely upon the completion of the invalidate
		 * to signal that the descriptor can be re-used, instead it will have to
		 * verify by checking the final write-back of the descriptor, which will have
		 * valid set to 0 by PSIF. In the general case we handle this lazy and check before we
		 * try to re-use. The request is posted with no completion requested as we
		 * do not need the completion:
		 */
		if (!(test_bit(RQ_IS_INVALIDATED, &rq_sw->flags))) {
			ret = sif_invalidate_rq_hw(sdev, rq->index, PCM_POST);
			if (ret) {
				sif_log(sdev, SIF_INFO,
					"Invalidate rq_hw failed, status %d", ret);
				goto free_rq_error;
			}
			set_bit(RQ_IS_INVALIDATED, &rq_sw->flags);
		}

		/* Make sure the RQ is sofware owned: */
		ret = poll_wait_for_rq_writeback(sdev, rq);
		if (ret)
			goto free_rq_error;

		/* The RQ is now software owned and the (after a successful invalidate) so we
		 * should be able to trust rq_hw::head_indx - better than scanning the CQ
		 * for unprocessed elements:
		 * Note that only the lowest 14 bits of the sequence number in head_indx is
		 * valid:
		 */
flush_rq_again:
		spin_lock_irqsave(&rq->lock, flags);
		head = get_psif_rq_hw__head_indx(&rq->d);
		tail = rq_sw->next_seq;
		real_len = rq_length(rq, head, tail & ((1 << 14) - 1)) & ((1 << 14) - 1);

		/* Workaround #622 v2 step 3: Check the last completion on the CQ
		 * The rq_sw->length is used to track the length of a queue
		 * with #posted - #completed. If the calculated real_len is
		 * smaller than the len, it means that a completion is missing.
		 * Instead of loooping RQ to find rqe of the completed wc_id, the
		 * rq_sw->length represents the #posted - #completed, and nfixup
		 * represents the remaining completions after the QP moved to RESET.
		 * Thus, the number of flush-in error that must be generated is
		 * rq_sw->length - nfixup.
		 */
		if (!(test_bit(FLUSH_RQ_FIRST_TIME, &rq_sw->flags))) {
			/* need to use a flag to differentiate between the first call of
			 * sif_flush_rq or the subsequent call. The race condition where
			 * HW acquired a RWQE but does not generate a completion can
			 * only happen at the first call of sif_flush_rq. This is because
			 * the QP state is moved to RESET.
			 * Besides, if the generated completion arrived later and
			 * FLUSH_RQ_IN_FLIGHT is set, the test of real_len < len
			 * might be true.
			 */
			len = atomic_read(&rq_sw->length);
			if (real_len < len) {
				struct psif_qp lqps;

				copy_conv_to_sw(&lqps, &target_qp->d, sizeof(lqps));

				/* from Brian - This is a scenario where the first packet is received,
				 * the RQ is claimed but the Last packet is not received after the QP
				 * is in Error. Then, nothing will come up the pipe to complete the
				 * Received and it will be dangling.
				 */
				if ((lqps.state.expected_opcode != NO_OPERATION_IN_PROGRESS) &&
				    (lqps.state.committed_received_psn + 1 == lqps.state.expected_psn)) {
					int entries;
					struct sif_cq *cq = get_sif_cq(sdev, lqps.state.rcv_cq_indx);
					struct sif_cq_sw *cq_sw;
					unsigned long timeout;

					if (!cq) {
						sif_log(sdev, SIF_RQ,
							"recevied cq is NULL");
						spin_unlock_irqrestore(&rq->lock, flags);
						goto free_rq_error;
					}
					cq_sw = get_sif_cq_sw(sdev, cq->index);

					/* wait for 1 second to ensure that all the completions are back */
					timeout = jiffies + HZ;
					do {
						cpu_relax();
					} while (time_is_after_jiffies(timeout));

					/* use the software counter (rq_sw->length) */
					entries = find_recv_cqes_in_cq(sdev, cq, target_qp);
					len = atomic_read(&rq_sw->length);
					sif_log(sdev, SIF_RQ,
						"RQ %d: updating calculated entries from %d to %d - %d (%d)",
						rq->index, real_len, len, entries, len - entries);
					real_len = real_len < len ? len - entries : real_len;
				}
			}
			set_bit(FLUSH_RQ_FIRST_TIME, &rq_sw->flags);
		}
		spin_unlock_irqrestore(&rq->lock, flags);

		/* Now find the actual 32 bit seq.no */
		head = tail - real_len;

		sif_log(sdev, SIF_RQ,
			"RQ %d not empty: sz %d, head %d, next_seq %d, %d/%d entries at exit",
			rq->index, rq->entries, head, tail, len, real_len);

		if (!real_len)
			goto free_rq_error;

		/* Workaround #622 v2 step 4: generate flush in error completion
		 * Generate flushed in error completions:
		 * these give no pqp completions but may in theory fail
		 */
		while (real_len > 0) {
			sif_log(sdev, SIF_PQP, "rq %d, len %d", rq->index, real_len);
			ret = sif_gen_rq_flush_cqe(sdev, rq, head, target_qp);
			if (ret)
				sif_log(sdev, SIF_INFO, "rq %d, len %d, sif_gen_rq_flush_cqe returned %d",
					rq->index, real_len, ret);
			if (ret == -EAGAIN) {
				ret = gen_pqp_cqe(&lcqe);
				if (ret < 0)
					goto free_rq_error;
				ret = poll_cq_waitfor(&lcqe);
				if (ret < 0)
					goto free_rq_error;
				lcqe.written = false;
				continue;
			}
			if (ret < 0)
				goto free_rq_error;
			real_len--;
			head++;
		}

		/* Finally generate a sync.completion for us on the PQP itself
		 * to allow us to wait for the whole to complete:
		 */
		ret = gen_pqp_cqe(&lcqe);
		if (ret < 0) {
			sif_log(sdev, SIF_INFO, "rq %d, cqe %p gen_pqp_cqe returned %d",
				rq->index, &lcqe, ret);
			goto free_rq_error;
		}

		ret = poll_cq_waitfor(&lcqe);
		if (ret < 0) {
			sif_log(sdev, SIF_INFO, "rq %d, cqe %p poll_cq_waitfor returned %d",
				rq->index, &lcqe, ret);
			goto free_rq_error;
		}

		sif_log(sdev, SIF_INFO_V, "RQ %d: received completion on cq %d seq 0x%x - done",
			rq->index, rq->cq_idx, lcqe.cqe.seq_num);

		/* Make sure hardware pointer reflects the flushed situation */
		set_psif_rq_hw__head_indx(&rq->d, head);
		wmb();

		/* if FLUSH_RQ_IN_FLIGHT is set, it means another party is trying to
		 * flush the rq at the same time. This should be retried
		 * once as no more than one asynchronous event will be generated if
		 * QP is in ERROR state. This is to take care of a scenario where
		 * QP is modified to ERROR explicitly and at the same time received
		 * the asynchronous event. Nevertheless, the RQ entry changes in between
		 * of these two scenario that can trigger flush rq.
		 */
		if (test_and_clear_bit(FLUSH_RQ_IN_FLIGHT, &rq_sw->flags))
			goto flush_rq_again;
free_rq_error:
		if (atomic_dec_and_test(&rq->flush_in_progress))
			complete(&rq->can_reset);
	}
error:
	clear_bit(FLUSH_RQ_IN_PROGRESS, &rq_sw->flags);
done:
	kfree(rq_work);
}


int free_rq(struct sif_dev *sdev, int rq_idx)
{
	struct sif_rq *rq = get_sif_rq(sdev, rq_idx);
	struct sif_rq_sw *rq_sw = get_sif_rq_sw(sdev, rq_idx);

	sif_log(sdev, SIF_RQ, "entry %d", rq_idx);

	if (!atomic_dec_and_test(&rq->refcnt)) {
		sif_log(sdev, SIF_RQ, "rq %d still in use - ref.cnt %d",
			rq_idx, atomic_read(&rq->refcnt));
		return -EBUSY;
	}

	/* Reset rq pointers, for srq and the error path in create_qp.
	 * This also means that rq_sw will be reset twice in the
	 * happy path for !srq.
	 */
	memset(rq_sw, 0, sizeof(*rq_sw));
	set_psif_rq_hw__head_indx(&rq->d, 0);

	sif_release_rq(sdev, rq->index);
	return 0;
}


void sif_release_rq(struct sif_dev *sdev, int index)
{
	struct sif_rq *rq = get_sif_rq(sdev, index);
	struct sif_pd *pd = rq->pd;

	if (!pd) {
		sif_log(sdev, SIF_INFO, "Internal error: no pd associated with rq %d", index);
		return;
	}

	sif_unmap_ctx(sdev, &rq->mmu_ctx);

	sif_mem_free(rq->mem);
	sif_clear_rq_sw(sdev, index);

	if (!sif_feature(disable_invalidate_rq))
		sif_free_rq_hw_idx(pd, index);
}

void sif_dfs_print_rq_hw(struct seq_file *s, struct sif_dev *sdev, loff_t pos)
{
	struct sif_rq *rq;
	struct sif_rq_sw *rq_sw;
	volatile struct psif_rq_hw *rq_hw;
	u32 tail, head;
	int qlen;

	if (unlikely(pos < 0)) {
		seq_puts(s, "# Index  head  sw_tail  entries queue_len nmbr_sge next_seq srq_lim\n");
		return;
	}
	rq = get_sif_rq(sdev, pos);
	rq_hw = &rq->d;
	rq_sw = get_sif_rq_sw(sdev, pos);

	head = get_psif_rq_hw__head_indx(rq_hw);
	tail = get_psif_rq_sw__tail_indx(&rq_sw->d);
	qlen = atomic_read(&rq_sw->length);

	seq_printf(s, "%7llu %5u %8u %8u %9u %8u %8u %7u", pos,
		head, tail, rq->entries, qlen, rq->sg_entries, rq_sw->next_seq, rq->srq_limit);
	if (rq->is_srq & rq->xrc_domain) {
		seq_puts(s, "\t[XRCSRQ -> CQ:");
		seq_printf(s, "%u", rq->cq_idx);
		seq_puts(s, "]\n");
	}
	else if (rq->is_srq)
		seq_puts(s, "\t[SRQ]\n");
	else
		seq_puts(s, "\n");
}
