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
 * sif_sndrcv.c: Implementation of post send/recv logic for SIF
 */
#include <linux/sched.h>
#include <net/checksum.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_smi.h>

#include "sif_dev.h"
#include "sif_query.h"
#include "sif_defs.h"
#include "sif_base.h"
#include "sif_sndrcv.h"
#include "sif_qp.h"
#include "sif_mr.h"
#include "sif_tqp.h"
#include "sif_r3.h"
#include "psif_hw_setget.h"
#include "sif_checksum.h"
#include <linux/kgdb.h>


/* Handle a NULL terminated array of send work requests */
#define SQS_ACTIVE (get_psif_sq_hw__sq_next(&sq->d) != 0xFFFFFFFF)
int sif_post_send(struct ib_qp *ibqp, struct ib_send_wr *wr,
		  struct ib_send_wr **bad_wr)
{
	struct sif_dev *sdev = to_sdev(ibqp->device);
	struct sif_qp *qp = to_sqp(ibqp);
	struct sif_sq *sq = get_sq(sdev, qp);
	struct sif_sq_sw *sq_sw = sq ? get_sif_sq_sw(sdev, qp->qp_idx) : NULL;
	unsigned long flags;
	bool doorbell_mode;
	bool last;
	u16 first_seq;
	const int nmbr_wrs_to_bulk_process = 32;
	int ret = 0;
	int n;

	if (unlikely(!sq)) {
		sif_log(sdev, SIF_INFO, "sq not defined for qp %d (type %s)",
			qp->qp_idx, string_enum_psif_qp_trans(qp->type));
		return -EINVAL;
	}

	sif_log(sdev, SIF_SND, "on qp_idx %d wr 0x%p ibv type %d",
		qp->qp_idx, wr, wr->opcode);

	if (unlikely(qp->type > PSIF_QP_TRANSPORT_MANSP2)) {
		sif_log(sdev, SIF_INFO, "Invalid QP type");
		ret = -EINVAL;
		goto err_post_send_unlocked;
	}

	if (unlikely(is_epsa_tunneling_qp(ibqp->qp_type))) {
		sif_log(sdev, SIF_QP, "epsa tunneling post_send");
		return sif_epsa_tunneling_post_send(ibqp, wr, bad_wr);
	}

	/* PSIF does not support SQD. Per IBTA 11.4.1.1, error is only returned
	 * when the QP is in the RESET, INIT or RTR states.
	 */
	if (unlikely(qp->last_set_state < IB_QPS_RTS)) {
		sif_log(sdev, SIF_INFO, "Invalid QP state - expected RTS(%d) found %d!",
			(int)IB_QPS_RTS, qp->last_set_state);
		ret = -EINVAL;
		goto err_post_send_unlocked;
	}

	while (wr) {
		/* Workaround #3595: ring doorbell if SQS active */
		doorbell_mode = qp->flags & SIF_QPF_FORCE_SQ_MODE || SQS_ACTIVE;

		/* We need to serialize sends on the same send queue
		 * so we need to keep sq->lock around it all
		 */
		spin_lock_irqsave(&sq->lock, flags);
		first_seq = sq_sw->last_seq + 1;
		for (n = 0; wr && n < nmbr_wrs_to_bulk_process; ++n, wr = wr->next) {
			last = !wr->next || n == (nmbr_wrs_to_bulk_process - 1);
			ret = sif_post_send_single(ibqp, wr, &doorbell_mode, last, &first_seq);
			if (ret < 0)
			goto err_post_send;
		}
		spin_unlock_irqrestore(&sq->lock, flags);
	}

	if ((qp->type != PSIF_QP_TRANSPORT_MANSP1)
	    && (qp->last_set_state == IB_QPS_ERR)) {
		ret = 0;
		goto flush_sq_wa4074;
	}


	sif_log(sdev, SIF_SND, "Exit: success");
	return 0;

err_post_send:
	spin_unlock_irqrestore(&sq->lock, flags);

err_post_send_unlocked:
	*bad_wr = wr;

flush_sq_wa4074:
	if ((qp->type != PSIF_QP_TRANSPORT_MANSP1)
	    && (qp->last_set_state == IB_QPS_ERR)) {
		if (post_process_wa4074(sdev, qp))
			sif_log(sdev, SIF_INFO, "failed to flush SQ %d", qp->qp_idx);
	}

	sif_log(sdev, SIF_SND, "Exit: error %d", ret);
	return ret;

}
#undef SQS_ACTIVE


/* The copy_from_user function on x86_64 calls might_fault() to verify that
 * it is not called from interrupt context. However with our use case the memory is guaranteed
 * to be pinned, so no faults will ever happen.
 *
 * TBD: Sparc does not define _copy_from_user - just use copy_from _user for now
 */
inline unsigned long sif_copy_from_user(void *to, const void __user *from, unsigned int n)
{
#ifdef __x86_64__
	return _copy_from_user(to, from, n);
#else
	return copy_from_user(to, from, n);
#endif
}


static int copy_sg(struct sif_qp *qp, void *dest, u64 vaddr, u32 len)
{
	struct sif_dev *sdev = to_sdev(qp->ibqp.device);

	if (qp->ibqp.uobject) {
		unsigned long not_copied;

		sif_log(sdev, SIF_SND, "Copy sg len %d from user addr 0x%llx to %p",
			len, vaddr, dest);
		not_copied = sif_copy_from_user(dest, (void __user *)vaddr, len);
		if (not_copied) {
			sif_log(sdev, SIF_INFO,
				"copy_from_user: Failed to copy %ld/%d bytes from uaddr %llx",
				not_copied, len, vaddr);
			return -EFAULT;
		}
	} else {
		sif_log(sdev, SIF_SND, "Copy sge len %d from kernel addr 0x%llx to %p",
			len, vaddr, dest);
		memcpy(dest, (void *)vaddr, len);
	}
	return 0;
}


/* Copy the first @sg_cnt sg entries of @wr into the inline space
 */

/* TBD: Consider cleaning up/unrolling this into one copy
 * into temp buffer for csumming/cb copy_convert
 * and one other plain copy into send queue:
 */
static int prep_inline_part(struct sif_qp *qp, struct ib_send_wr *wr, int sg_cnt,
		struct psif_cb *wqe, struct psif_wr_local *la, u32 sqe_seq,
		bool is_phys_addr)
{
	int ret;
	int wr_len = 0;
	struct sif_sq *sq;
	struct psif_sq_entry *sqe;
	struct psif_key *key;

	/* collect buffer only supports 256 byte inlined, this first part
	 * of the inline data must be handled in host byte order to
	 * make sure the checksum gets right:
	 */
	int cb_len = min_t(int, ((qp->max_inline_data + CB_KICK_MASK) & ~CB_KICK_MASK), CB_LENGTH);
	int space = qp->max_inline_data;
	int copy = 0;
	int remaining = -1;
	int i;
	u32 len = 0;
	u64 addr = 0;
	struct sif_dev *sdev = to_sdev(qp->ibqp.device);

	u8 buf[CB_LENGTH];
	u8 *dbuf = buf;

	if (wr->send_flags & IB_SEND_IP_CSUM) {
		/* Cannot use collect-buffer for inline data when offloading */
		cb_len = 0;
	}

	sq = get_sif_sq(sdev, qp->qp_idx);
	sqe = get_sq_entry(sq, sqe_seq);

	sif_log(sdev, SIF_SND, "inline from %d sges, buf at %p sqe at %p", sg_cnt, buf, sqe);

	for (i = 0; i < sg_cnt; ++i) {
		if (unlikely(remaining >= 0)) {
			/* Switch to copying directly into send queue
			 * @copy already holds the offset
			 */
			dbuf = ((u8 *)sqe->payload);
			if (remaining > 0) {
				addr += len;
				len = remaining;
				remaining = -1;
				goto do_copy;
			} else
				remaining = -1;
		}
		len = wr->sg_list[i].length;
		addr = wr->sg_list[i].addr;

		if (len > 0) {
			u32 lkey = wr->sg_list[i].lkey;

			key = safe_get_key(sdev, lkey);
			if (!key || PSIF_DMA_KEY_INVALID == get_psif_key__lkey_state(key)) {
				sif_log(sdev, SIF_INFO,
					"Attempt to do inline copying from an invalid MR with lkey %d at addr 0x%llx",
					lkey, addr);
				return -EPERM;
			}
		}

do_copy:
		wr_len += len;
		if (unlikely(dbuf == buf && wr_len >= cb_len)) {
			remaining = wr_len - cb_len;
			len -= remaining;
			wr_len -= remaining;
			if (remaining)
				i--;  /* Run an extra iter to copy remainder */
		} else if (unlikely(copy + len > space)) {
			sif_log(sdev, SIF_INFO,
				"Inline space exhausted: available %d, copied %d, len %d",
				space, copy, len);
			return -ENOMEM;
		}
		if (is_phys_addr) {
			u64 *kva = phys_to_virt(addr);

			sif_log(sdev, SIF_SND,
				"Phys-addr %llx -> %llx copy %d len %d",
				addr, (u64)kva, copy, len);
			memcpy((void *)&dbuf[copy], (void *)kva, len);
			ret = 0;
		} else {
			ret = copy_sg(qp, &dbuf[copy], addr, len);
		}
		if (ret < 0)
			return ret;
		copy += len;
	}

	if (buf == dbuf && copy & CB_KICK_MASK) {
		/* Pad out the misaligned end data */
		memset(&buf[copy], 0, CB_KICK_ALIGN - (copy & CB_KICK_MASK));
	}

	sif_log(sdev, SIF_QP, "wr_len is %d bytes, cb_len %d bytes", wr_len, cb_len);
	if (cb_len > 0) {
		/* Convert payload twice to get checksum right.
		 * The 32 bit version of the checksumming in PSIF does not
		 * have the property that checksumming of the same data
		 * on different endian hosts yields the same checksum..
		 */
		copy_conv_to_sw(wqe->payload, buf, cb_len);
	}
	wqe->wr.collect_length = min(wr_len, cb_len);
	return wr_len;
}

static inline int prep_inline(struct sif_qp *qp, struct ib_send_wr *wr, struct psif_cb *wqe,
			struct psif_wr_local *la, u32 sqe_seq,
			bool is_phys_addr)
{
	struct sif_dev *sdev = to_sdev(qp->ibqp.device);
	struct sif_sq *sq = get_sif_sq(sdev, qp->qp_idx);
	int wr_len = prep_inline_part(qp, wr, wr->num_sge, wqe, la, sqe_seq, is_phys_addr);

	if (wr_len < 0)
		return wr_len;
	if (wr_len) {
		/* la must point to the start of the payload in the send queue
		 * to have the whole message available in case of retries:
		 */
		la->addr = get_sqe_dma(sq, sqe_seq) + offsetof(struct psif_sq_entry, payload);
		la->lkey = sq->sg_mr->index;
	}
	la->length = wr_len;
	return wr_len;
}

/* Helper funcs declared below */
static void prep_atomic(struct sif_qp *qp, struct ib_send_wr *wr, struct psif_cb *wqe);
static int prep_send(struct sif_qp *qp, struct ib_send_wr *wr, struct psif_cb *wqe,
		bool inlined, struct psif_wr_local *la, u32 sqe_idx);
static int prep_send_lso(struct sif_qp *qp, struct ib_send_wr *wr, struct psif_cb *wqe,
			 bool inlined, struct psif_wr_local *la, u32 sqe_idx);
static int prep_remote_addr(struct sif_qp *qp, struct ib_send_wr *wr, struct psif_cb *wqe);


/* Return bypass mode offset or 0 if invalid for post_sends (see below)
 * (PSIF will take care of rejecting the post)
 */

inline u64 mr_uv2dma(struct sif_dev *sdev, int idx)
{
	struct sif_mr *mr = safe_get_sif_mr(sdev, idx);

	if (mr)
		return mr->mmu_ctx.uv2dma;
	return 0;
}


/*
 * Handle send of a single wr - can be called from any context.
 *
 * Use either CB mode or DB mode. In CB mode, wqe is allocated,
 * written to SQ, SW pointer updated, and finally the wqe is written
 * to the CB.  In DB mode, the wqe is allocated and written to the
 * SQ. On the last wqe, SW pointer is updated and the doorbell is rung
 * with the seq number of the first sqe.
 */
int sif_post_send_single(struct ib_qp *ibqp, struct ib_send_wr *wr, bool *use_db, bool last, u16 *first_seq)
{
	bool inlined = false;
	u64 csum;
	struct psif_cb wqe;
	struct psif_sq_entry *sqe;
	int cb_len = 0;
	int cb_len_8 = 0;
	struct sif_dev *sdev = to_sdev(ibqp->device);
	struct sif_qp *qp = to_sqp(ibqp);
	struct sif_sq *sq = get_sif_sq(sdev, qp->qp_idx);
	int ret = 0;
	u16 head, sq_seq, q_sz;
	struct sif_sq_sw *sq_sw = get_sif_sq_sw(sdev, qp->qp_idx);
	bool is_ud = qp->type == PSIF_QP_TRANSPORT_UD;
	struct sif_sq_hdl *wh;

	if (wr->num_sge > sq->sg_entries) {
		sif_log(sdev, SIF_SND, "attempt to post wr with %d/%d sg entries",
			wr->num_sge, sq->sg_entries);
		return -EINVAL;
	}

	sq_seq = ++sq_sw->last_seq;
	head = sq_sw->head_seq;
	q_sz = sq_length(sq, head, sq_seq);

	if (q_sz > sq->entries) {
		sif_log(sdev, SIF_INFO,
			"Send Queue %d full - head %d, tail %d, entries %d, sge_entries %u, sq->user_mode: %s, sq->alloc_sz: %llu",
			sq->cq_idx, head, sq_seq, sq->entries, sq->sg_entries,
			(sq->user_mode) ? "[yes]" : "[no]", sq->mem->size);
		ret = -EAGAIN;
		goto fail;
	}


	sqe = get_sq_entry(sq, sq_seq);

	memset(&wqe, 0, sizeof(wqe));

	wqe.wr.tsu_qosl = qp->qosl;
	wqe.wr.eps_tag = qp->eps_tag;

	ret = prep_remote_addr(qp, wr, &wqe);
	if (ret)
		goto fail;

	if (wr->send_flags & IB_SEND_FENCE) /* RC only */
		wqe.wr.fence = 1;

	if (qp->flags & SIF_QPF_DYNAMIC_MTU)
		wqe.wr.dynamic_mtu_enable = 1;

	wqe.wr.completion = sq->complete_all;
	if (wr->send_flags & IB_SEND_SIGNALED)
		wqe.wr.completion = 1;

	inlined = wr->send_flags & IB_SEND_INLINE;

	if (qp->qp_idx < 4) {
		/* Field valid for QP0/1 only */
		wqe.wr.port = qp->port - 1;

		/* and in the work request we must use "real" QP numbers as well */
		wqe.wr.local_qp = qp->qp_idx & 1;
	} else
		wqe.wr.local_qp = qp->qp_idx;

	if (wr->opcode == IB_WR_SEND_WITH_IMM ||
		wr->opcode == IB_WR_RDMA_WRITE_WITH_IMM) {
		wqe.wr.imm = cpu_to_be32(wr->ex.imm_data);
	}

	/* TBD: only set if wr opcode allows it */
	if (wr->send_flags & IB_SEND_SOLICITED)
		wqe.wr.se = 1;

	if (wr->send_flags & IB_SEND_IP_CSUM) {
		wqe.wr.l3_checksum_en = 1;
		wqe.wr.l4_checksum_en = 1;
		qp->ipoib_tx_csum_l3++;
		qp->ipoib_tx_csum_l4++;
	}
	switch (wr->opcode) {
	case IB_WR_LSO:
	{
		struct psif_wr_local *la = &wqe.wr.details.send.ud.local_addr;

		if (!supports_offload(qp)) {
			sif_log(sdev, SIF_INFO,
				"LSO WR on qp %d which does not support offloading",
				qp->qp_idx);
			ret = -EINVAL;
			goto fail;
		}
		ret = prep_send_lso(qp, wr, &wqe, inlined, la, sq_seq);
		if (ret < 0)
			goto fail;
		break;
	}
	case IB_WR_SEND:
	case IB_WR_SEND_WITH_IMM:
	{
		struct psif_wr_local *la = (is_ud ?
					&wqe.wr.details.send.ud.local_addr :
					&wqe.wr.details.send.uc_rc_xrc.local_addr);
		ret = prep_send(qp, wr, &wqe, inlined, la, sq_seq);
		if (ret < 0)
			goto fail;
		break;
	}
	case IB_WR_RDMA_READ:
		/* RDMA READ does not support dynamic MTU */
		wqe.wr.dynamic_mtu_enable = 0;
	case IB_WR_RDMA_WRITE:
	case IB_WR_RDMA_WRITE_WITH_IMM:
	{
		struct psif_wr_local *la = &wqe.wr.details.rdma.local_addr;
		struct psif_wr_remote *ra = &wqe.wr.details.rdma.remote_addr;

		ra->addr = wr->wr.rdma.remote_addr;
		ra->rkey = wr->wr.rdma.rkey;

		ret = prep_send(qp, wr, &wqe, inlined, la, sq_seq);
		if (ret < 0)
			goto fail;

		ra->length = ret;
		break;
	}
	case IB_WR_ATOMIC_CMP_AND_SWP:
	case IB_WR_ATOMIC_FETCH_AND_ADD:
		prep_atomic(qp, wr, &wqe);
		break;
	case IB_WR_SEND_WITH_INV:
	case IB_WR_RDMA_READ_WITH_INV:
		sif_log(sdev, SIF_SND, "Opcode not implemented");
		ret = -EOPNOTSUPP;
		goto fail;
	case IB_WR_MASKED_ATOMIC_CMP_AND_SWP:
	case IB_WR_MASKED_ATOMIC_FETCH_AND_ADD:
	{
		/* Bug 3844, WA for HW bug 3683 */
		bool masked_atomics_defeatured  = PSIF_REVISION(sdev) <= 3;

		if (masked_atomics_defeatured)
			sif_log(sdev, SIF_SND, "Opcode not supported");
		else
			sif_log(sdev, SIF_SND, "Opcode not yet implemented");
		ret = -EOPNOTSUPP;
		goto fail;
	}
	default:
		sif_log(sdev, SIF_SND, "Unsupported opcode");
		ret = -EINVAL;
		goto fail;
	}

	sif_log(sdev, SIF_SND,
		"copied %d bytes inline, num_sgl %d, sqe at %p",
		wqe.wr.collect_length, wqe.wr.num_sgl, sqe);
	cb_len_8 = sizeof(struct psif_wr)
		+ ((wqe.wr.collect_length + 7) & ~7);
	cb_len = sizeof(struct psif_wr)
		+ ((wqe.wr.collect_length + CB_KICK_MASK) & ~CB_KICK_MASK);

	wqe.wr.sq_seq = sq_seq;
	wqe.wr.tsu_sl = qp->tsl;

	/* Map sqe (repr.by index in sq) to this wr_id */
	wh = get_sq_hdl(sq, sq_seq);
	wh->wr_id = wr->wr_id;
	wh->sq_seq = sq_seq;
	wh->used = true;

	sif_log(sdev, SIF_SND, "wr_id %llx at tail 0x%x sq_seq_num %d%s",
		wr->wr_id, sq_seq & sq->mask, wqe.wr.sq_seq, (wqe.wr.completion ? " [req.compl]" : ""));

	/* We can safely checksum any "hole" due to end misalignment + byte swap
	 * towards the end of the inline data
	 * as prep_inline has nil'ed these bytes out:
	 */
	if (qp->nocsum) {
		wqe.wr.checksum = qp->magic;
	} else {
		csum = csum32_partial(&wqe, cb_len_8, qp->magic);
		csum = csum32_fold(csum);
		wqe.wr.checksum = csum;
	}
	sif_log(sdev, SIF_SND, "op %s checksum %x cb_len 0x%x",
		string_enum_psif_wr_type(wqe.wr.op),
		wqe.wr.checksum, cb_len);
	sif_logs(SIF_DUMP, write_struct_psif_wr(NULL, 0, &wqe.wr));

	/* First update send queue (any further inline data beyond cb_len
	 * has already been copied in prep_inline:
	 */
	copy_conv_to_hw(sqe, &wqe, cb_len);

	/* A heuristic mechanism to determine the traffic pattern. */
	/* Even though traffic_patterns.mask is being set by handle_wc, no
	 * lock is used.The reason is that the mask is used to get a "rough"
	 * idea about the underlying traffic pattern without adding latency
	 * in the driver.
	 */
	qp->traffic_patterns.mask = (qp->traffic_patterns.mask << 1) |
		HEUR_TX_DIRECTION;
	sif_log_rlim(sdev, SIF_PERF_V, "qp:traffic_pattern %x",
		qp->traffic_patterns.mask);
	/* If the traffic pattern shows that it's not latency sensitive,
	 * use SQ mode by ringing the doorbell.
	 * In a latency sensitive traffic pattern, a SEND should
	 * be accompanied by a WC_OPCODE_RECEIVE_SEND. Thus,
	 * a latency sensitve traffic pattern should have
	 * half_of_bits(sizeof(traffic_patterns.submask[n)) set.
	 * The constant 7 and 9 are used below as we are adding one
	 * to half_of_bits(sizeof(traffic_patterns.submask[n]))
	 * as the tolerance.
	 */
	if (((hweight16(qp->traffic_patterns.submask[0]) < 7)  ||
	     (hweight16(qp->traffic_patterns.submask[0]) > 9)) ||
	    ((hweight16(qp->traffic_patterns.submask[1]) < 7)  ||
	     (hweight16(qp->traffic_patterns.submask[1]) > 9)))
		*use_db = true;

	/* Flush writes before updating the sw pointer,
	 * This is necessary to ensure that the sqs do not see
	 * an incomplete entry.
	 * NB! Note that as opposed to software consuming
	 * queues this value should point to the last used entry, not the first
	 * unused:
	 */
	if (!*use_db || last) {
		wmb();
		set_psif_sq_sw__tail_indx(&sq_sw->d, sq_seq);
	}

	/* Finally write to collect buffer or ring doorbell if last */
	if (*use_db && last)
		/* Write doorbell for first WR when we process the last request */
		sif_doorbell_from_sqe(qp, *first_seq, true);
	else if (!*use_db)
		if (sif_cb_write(qp, &wqe.wr, cb_len)) {
			/*vcb lock busy, convert to db mode */
			if (last)
				sif_doorbell_from_sqe(qp, sq_seq, true);
			else {
				*use_db = true;
				*first_seq = sq_seq;
			}
		}

	return ret;
fail:
	sif_log(sdev, SIF_SND, "Exit: Fail to post_send a WR");
	sif_logs(SIF_DUMP, write_struct_psif_wr(NULL, 0, &wqe.wr));

	/* Avoid "using" the allocated entry */
	sq_sw->last_seq--;
	return ret;
}  /* end sif_post_send_single */


static int get_gsi_qp_idx(struct sif_qp *qp)
{
	struct sif_dev *sdev = to_sdev(qp->ibqp.device);
	int pma_qp_idx = sdev->pma_qp_idxs[!!(qp->qp_idx & 2)];
	struct sif_qp *pma_qp = get_sif_qp(sdev, pma_qp_idx);
	struct sif_rq_sw *rq_sw;
	int gsi_qlen, pma_qlen;

	rq_sw = get_sif_rq_sw(sdev, qp->rq_idx);
	gsi_qlen = atomic_read(&rq_sw->length);
	rq_sw = get_sif_rq_sw(sdev, pma_qp->rq_idx);
	pma_qlen = atomic_read(&rq_sw->length);

	return (gsi_qlen <= pma_qlen) ? qp->qp_idx : pma_qp->qp_idx;
}


int sif_post_recv(struct ib_qp *ibqp, struct ib_recv_wr *wr,
		  struct ib_recv_wr **bad_wr)
{
	struct sif_dev *sdev = to_sdev(ibqp->device);
	struct sif_eps *es = &sdev->es[sdev->mbox_epsc];
	struct sif_qp *qp = to_sqp(ibqp);
	struct sif_rq *rq = NULL;
	bool need_pma_pxy_qp = eps_version_ge(es, 0, 57)
		&& (qp->qp_idx == 1 || qp->qp_idx == 3);

	sif_log(sdev, SIF_RCV, "Enter: wr_id 0x%llx qp_idx %d",
		wr->wr_id, qp->qp_idx);

	if (need_pma_pxy_qp) {
		qp = get_sif_qp(sdev, get_gsi_qp_idx(qp));
		sif_log(sdev, SIF_RCV, "Redirect wr_id 0x%llx to qp_idx %d",
			wr->wr_id, qp->qp_idx);
	}

	rq = get_rq(sdev, qp);
	if (unlikely(!rq)) {
		sif_log(sdev, SIF_INFO, "rq not defined for qp_idx %d (type %s)",
			qp->qp_idx, string_enum_psif_qp_trans(qp->type));
		return -EINVAL;
	}

	if (qp->last_set_state == IB_QPS_RESET) {
		sif_log(sdev, SIF_INFO, "Invalid QP state (IB_QPS_RESET)");
		return -EINVAL;
	}

	if (wr->num_sge > rq->sg_entries) {
		sif_log(sdev, SIF_INFO, "qp only supports %d receive sg entries - wr has %d",
			rq->sg_entries, wr->num_sge);
		return -ENOMEM;
	}

	return post_recv(sdev, qp, rq, wr, bad_wr);
}


/* Post a list of receives - can be called from any context */
int post_recv(struct sif_dev *sdev, struct sif_qp *qp, struct sif_rq *rq,
		struct ib_recv_wr *wr, struct ib_recv_wr **bad_wr)
{
	struct sif_rq_sw *rq_sw = get_sif_rq_sw(sdev, rq->index);
	int ret = 0;
	u32 rq_len;

	unsigned long flags;

	if (unlikely(rq->user_mode)) {
		sif_log(sdev, SIF_INFO,
			"rq %d: Attempt to use kernel API to post to user mode receive queue",
			rq->index);
		return -EINVAL;
	}

	if (!wr)
		return ret;

	/* TBD: Revisit locking scheme again later
	 * to allow more parallelism. For now serialize to avoid
	 * having to handle "holes":
	 */
	spin_lock_irqsave(&rq->lock, flags);

	for (; wr; wr = wr->next) {
		struct psif_rq_entry *rqe;
		struct psif_rq_entry lrqe;
		struct psif_rq_scatter *sge;
		int i = 0;
		int rqe_sz = 8 + wr->num_sge*sizeof(struct psif_rq_scatter);
		int max_rqe_sz = 8 + rq->sg_entries*sizeof(struct psif_rq_scatter);

		rq_len = atomic_inc_return(&rq_sw->length);
		if (rq_len > rq->entries) {
			sif_log(sdev, SIF_INFO, "queue full - rq %d entries %d len %d",
				rq->index, rq->entries, rq_len);
			atomic_dec(&rq_sw->length);
			ret = -ENOMEM;
			goto err_post_recv;
		}
		if (wr->num_sge > rq->sg_entries) {
			sif_log(sdev, SIF_INFO, "too many sges - rq %d sges configured %d, sges in wr %d",
				rq->index, rq->sg_entries, wr->num_sge);
			atomic_dec(&rq_sw->length);
			ret = -EINVAL;
			goto err_post_recv;
		}

		rqe = get_rq_entry(rq, rq_sw->next_seq++);

		/* On the receive side we use the full wr_id directly */
		lrqe.rqe_id = wr->wr_id;

		sge = lrqe.scatter;
		for (i = 0; i < wr->num_sge; i++) {
			u32 lkey = wr->sg_list[i].lkey;

			sge[i].lkey = lkey;
			sge[i].base_addr = wr->sg_list[i].addr + mr_uv2dma(sdev, lkey);
			sge[i].length = wr->sg_list[i].length;
			sif_log(sdev, SIF_RCV,
				"sg_adr 0x%llx sg_len %d lkey %d",
				wr->sg_list[i].addr, wr->sg_list[i].length, lkey);
		}

		copy_conv_to_hw(rqe, &lrqe, rqe_sz);

		/* As per PRM, unused sges shall be zero, which is endian neutral */
		if (max_rqe_sz > rqe_sz)
			memset(rqe->scatter + wr->num_sge, 0, max_rqe_sz - rqe_sz);

		sif_log(sdev, SIF_RCV,
			" entries %u extent %u RQ %d next_seq %x length %d",
			rq->entries, rq->extent, rq->index,
			rq_sw->next_seq, atomic_read(&rq_sw->length));
	}
	/* Enforce reordering of new rq entries and tail */
	wmb();
	set_psif_rq_sw__tail_indx(&rq_sw->d, rq_sw->next_seq);
	/* Enforce visibility of rq tail on hw */
	smp_wmb();

	sif_log(sdev, SIF_RCV, "Exit: success");
err_post_recv:
	spin_unlock_irqrestore(&rq->lock, flags);
	*bad_wr = wr;

	/* WA #622, Check if QP in ERROR, flush RQ */
	if (!rq->is_srq && qp->last_set_state == IB_QPS_ERR) {
		if (sif_flush_rq_wq(sdev, rq, qp, atomic_read(&rq_sw->length)))
			sif_log(sdev, SIF_INFO, "failed to flush RQ %d", rq->index);
	}

	return ret;
}

int sif_multicast_attach(struct ib_qp *ibqp, union ib_gid *gid, u16 lid)
{
	struct sif_dev *sdev = to_sdev(ibqp->device);
	struct sif_qp *qp = to_sqp(ibqp);
	struct psif_epsc_csr_rsp rsp;
	struct psif_epsc_csr_req req;

	sif_log(sdev, SIF_MC, "qp %d mc gid %llx.%llx lid 0x%x",
		qp->qp_idx, gid->global.subnet_prefix, gid->global.interface_id, lid);

	memset(&req, 0, sizeof(req));
	req.opcode = EPSC_MC_ATTACH;
	req.u.mc.qp = qp->qp_idx;
	req.u.mc.port = qp->port; /* The EPS uses IB port space */
	/* union ib_gid contains BE gids and we do copy_convert later.. */
	req.u.mc.mgid_0 = be64_to_cpu(gid->global.subnet_prefix);
	req.u.mc.mgid_1 = be64_to_cpu(gid->global.interface_id);
	return sif_epsc_wr(sdev, &req, &rsp);
}

int sif_multicast_detach(struct ib_qp *ibqp, union ib_gid *gid, u16 lid)
{
	struct sif_dev *sdev = to_sdev(ibqp->device);
	struct sif_qp *qp = to_sqp(ibqp);
	struct psif_epsc_csr_rsp rsp;
	struct psif_epsc_csr_req req;

	sif_log(sdev, SIF_MC, "qp %d mc gid %llx.%llx lid 0x%x",
		qp->qp_idx, gid->global.subnet_prefix, gid->global.interface_id, lid);

	memset(&req, 0, sizeof(req));
	req.opcode = EPSC_MC_DETACH;
	req.u.mc.qp = qp->qp_idx;
	req.u.mc.port = qp->port; /* The EPS uses IB port space */
	/* union ib_gid contains BE gids and we do copy_convert later.. */
	req.u.mc.mgid_0 = be64_to_cpu(gid->global.subnet_prefix);
	req.u.mc.mgid_1 = be64_to_cpu(gid->global.interface_id);
	return sif_epsc_wr(sdev, &req, &rsp);
}

static int prep_send(struct sif_qp *qp, struct ib_send_wr *wr, struct psif_cb *wqe,
		bool inlined, struct psif_wr_local *la, u32 sqe_seq)
{
	struct sif_dev *sdev = to_sdev(qp->ibqp.device);
	int ret = 0;
	int num_sge;
	int use_inline_first_sge  = 0;

	if (inlined)
		return prep_inline(qp, wr, wqe, la, sqe_seq, false);

	la->length = 0;
	num_sge = wr->num_sge;
	if (num_sge == 0) {
		sif_log(sdev, SIF_SND, "no sge entries - local_addr left as 0");
		return 0;
	}
	if (!sif_feature(disable_inline_first_sge) && qp->ulp_type == RDS_ULP && num_sge == 2
	    && wr->sg_list[0].length <= qp->max_inline_data) {
		use_inline_first_sge = 1;
	}

	if (use_inline_first_sge) {
		int wr_len;
		u32 lkey = wr->sg_list[0].lkey;
		struct sif_mr *mr = safe_get_sif_mr(sdev, lkey);
		int mem_type = mr ?  mr->mem->mem_type : 0;
		bool is_phys_addr = mem_type != SIFMT_UMEM;

		sif_log(sdev, SIF_SND, "qp_%d handle special case; "
			"#sge == 2 && sg[0].len == 48 max_inline_data %d, mem_type %d",
			qp->qp_idx, qp->max_inline_data, mem_type);
		/* Copy first sge inline */
		if ((wr->sg_list[0].length + wr->sg_list[1].length) <= qp->max_inline_data) {
			sif_log(sdev, SIF_SND, "qp_%d Inlining both %d + %d = %d",
				qp->qp_idx,
				wr->sg_list[0].length,
				wr->sg_list[1].length,
				(wr->sg_list[0].length + wr->sg_list[1].length));
			return prep_inline(qp, wr, wqe, la, sqe_seq, is_phys_addr);
		}
		wr_len = prep_inline_part(qp, wr, 1, wqe, la, sqe_seq, is_phys_addr);
		if (wr_len < 0)
			return wr_len;
		lkey = wr->sg_list[1].lkey;
		/* Subtract to get address "correct" for hw-usage */
		la->addr   = wr->sg_list[1].addr + mr_uv2dma(sdev, lkey) - wr_len;
		la->lkey   = lkey;
		la->length = wr_len + wr->sg_list[1].length;
		num_sge = 1;
		sif_log(sdev, SIF_SND,
			"Changed to single sge user addr 0x%llx dma addr 0x%llx, message len %d,  key %d collect_len %d wr_len %d",
			wr->sg_list[1].addr, la->addr, la->length, lkey, wqe->wr.collect_length, wr_len);
	} else if (num_sge == 1) {
		/* Single entry S/G list result after inlining */
		u32 lkey = wr->sg_list[0].lkey;

		la->addr   = wr->sg_list[0].addr + mr_uv2dma(sdev, lkey);
		la->lkey   = lkey;
		la->length += wr->sg_list[0].length;
		sif_log(sdev, SIF_SND,
			"single sge user addr 0x%llx dma addr 0x%llx, message len %d, key %d",
			wr->sg_list[0].addr, la->addr, la->length, lkey);
	} else if (unlikely(wr->num_sge > SIF_HW_MAX_SEND_SGE)) {
		sif_log(sdev, SIF_SND, "num_sge > %d", SIF_HW_MAX_SEND_SGE);
		return 0;
	} else {
		struct sif_sq *sq = get_sif_sq(sdev, qp->qp_idx);
		struct psif_sq_entry *sqe = get_sq_entry(sq, sqe_seq);
		void *sgl_start = sq_sgl_offset(sq, sqe);
		struct psif_rq_scatter *sge = sq->tmp_sge;
		int i;

		la->addr   = get_sqe_dma(sq, sqe_seq) + sq->sgl_offset;
		la->lkey = sq->sg_mr->index;

		for (i = 0; i < num_sge; i++) {
			u32 lkey = wr->sg_list[i].lkey;

			sge[i].base_addr = wr->sg_list[i].addr
				+ mr_uv2dma(sdev, lkey);
			sge[i].lkey      = wr->sg_list[i].lkey;
			sge[i].length    = wr->sg_list[i].length;
			la->length += sge[i].length;
			sif_log(sdev, SIF_SND,
				"sg_list[%d]: sge entry: dma addr 0x%llx, len = %d, lkey %d",
				i, sge[i].base_addr, sge[i].length, sge[i].lkey);
		}
		sif_log(sdev, SIF_SND,
			"ready with sgl_start %p, sg list addr 0x%llx, message len %d, lkey %d, sge %p",
			sgl_start, la->addr, la->length, la->lkey, sge);

		copy_conv_to_hw(sgl_start, sge,
				sizeof(struct psif_rq_scatter) * wr->num_sge);
		ret = la->length;
	}
	/* 0 here means a single entry, but input 0 must also be 0 */
	wqe->wr.num_sgl = num_sge ? num_sge - 1 : 0;
	return ret;
}
static int prep_send_lso(struct sif_qp *qp, struct ib_send_wr *wr, struct psif_cb *wqe,
			bool inlined, struct psif_wr_local *la, u32 sqe_seq)
{
	struct sif_dev *sdev = to_sdev(qp->ibqp.device);
	void *sgl_start;
	int ret = 0;
	int i;
	u8 *p8;
	struct sif_sq *sq;
	struct psif_sq_entry *sqe;
	struct psif_rq_scatter *sge;
	const int stencil_sge = 1;
	int ud_hlen;

	sq = get_sif_sq(sdev, qp->qp_idx);
	sqe = get_sq_entry(sq, sqe_seq);
	sge = sq->tmp_sge;
	sgl_start = sq_sgl_offset(sq, sqe);

	if (unlikely(wr->num_sge >= SIF_HW_MAX_SEND_SGE || wr->num_sge < 1)) {
		sif_log(sdev, SIF_INFO, "attempt to post lso wr with %d/%d sg entries",
			wr->num_sge, sq->sg_entries);
		return -EINVAL;
	}

	ud_hlen = wr->wr.ud.hlen;
	wqe->wr.details.send.ud.mss = wr->wr.ud.mss;
	/* Check if stencil is larger than max_inline_data */
	if (ud_hlen > qp->max_inline_data) {
		sif_log(sdev, SIF_INFO, "attempt to post lso wr with too big header  %d > %d",
			ud_hlen, qp->max_inline_data);
		return -EINVAL;
	}

	la->addr   = get_sqe_dma(sq, sqe_seq) + sq->sgl_offset;
	la->lkey = sq->sg_mr->index;
	la->length = 0;

	/* copy stencil to payload-area in send_queue */
	p8 = (u8 *)wr->wr.ud.header;
	memcpy((u8 *)sqe->payload, p8, ud_hlen);

	sge[0].base_addr = get_sqe_dma(sq, sqe_seq)
		+ offsetof(struct psif_sq_entry, payload) + mr_uv2dma(sdev, la->lkey);
	sge[0].lkey = sq->sg_mr->index;
	sge[0].length = ud_hlen;
	la->length += sge[0].length;

	sif_log(sdev, SIF_SND,
		"sg_list[%d]: sge entry: dma addr 0x%llx, len = %d, lkey %d",
		0, sge[0].base_addr, sge[0].length, sge[0].lkey);

	for (i = 0; i < wr->num_sge; i++) {
		u32 lkey = wr->sg_list[i].lkey;

		sge[i+1].base_addr = wr->sg_list[i].addr + mr_uv2dma(sdev, lkey);
		sge[i+1].lkey      = wr->sg_list[i].lkey;
		sge[i+1].length    = wr->sg_list[i].length;
		la->length += sge[i+1].length;
		sif_log(sdev, SIF_SND,
			"sg_list[%d]: sge entry: dma addr 0x%llx, len = %d, lkey %d",
			i+1, sge[i+1].base_addr, sge[i+1].length, sge[i+1].lkey);
	}
	copy_conv_to_hw(sgl_start, sge,
			sizeof(struct psif_rq_scatter) * (wr->num_sge+1));

	wmb();
	wqe->wr.num_sgl = wr->num_sge - 1 + stencil_sge;
	sif_log(sdev, SIF_SND,
		"num_sgl %d, sqe at %p la ->addr 0x%llx ->lkey %d ->length %d %d", wqe->wr.num_sgl, sqe,
		la->addr, la->lkey, la->length, la->length-sge[0].length);
	qp->ipoib_tx_lso_pkt++;
	qp->ipoib_tx_lso_bytes += (la->length - sge[0].length);
	return ret;
}


static int prep_remote_addr(struct sif_qp *qp, struct ib_send_wr *wr, struct psif_cb *wqe)
{
	struct sif_ah *ah = NULL;
	struct psif_ah *ah_p;
	bool is_dr = false;
	struct sif_dev *sdev = to_sdev(qp->ibqp.device);

	sif_log(sdev, SIF_SND, "");
	switch (qp->type) {
	case PSIF_QP_TRANSPORT_UD:
		if (!wr->wr.ud.ah) {
			sif_log(sdev, SIF_INFO, "No ah supplied for ud packet");
			return -EINVAL;
		}
		ah = to_sah(wr->wr.ud.ah);
		ah_p = get_ah(sdev, ah->index);
		is_dr = get_psif_ah__remote_lid(ah_p) == 0xffff;

		/* Direct routed packets are destined for the SMA at uf 33.
		 * For all other packets this field is ignored by the hw:
		 */
		if (is_dr)
			wqe->wr.destuf = 33;
		wqe->wr.details.send.ud.remote_addr.ah_indx
			= ah->index;
		wqe->wr.details.send.ud.qp.qkey = wr->wr.ud.remote_qkey;
		wqe->wr.details.send.ud.qp.remote_qp = wr->wr.ud.remote_qpn;
		wqe->wr.ud_pkt = 1;
		break;
	case PSIF_QP_TRANSPORT_UC:
	case PSIF_QP_TRANSPORT_RC:
		break;
	case PSIF_QP_TRANSPORT_XRC:
		wqe->wr.xrc_hdr.xrqd_id = wr->xrc_remote_srq_num;
		break;
	default:
		sif_log(sdev, SIF_INFO,
			"unhandled transport type %s", string_enum_psif_qp_trans(qp->type));
		return -EINVAL;
	}
	wqe->wr.op = ib2sif_wr_op(wr->opcode, is_dr);
	return 0;
}



static void prep_atomic(struct sif_qp *qp, struct ib_send_wr *wr, struct psif_cb *wqe)
{
	struct psif_wr_local  *la = &wqe->wr.details.atomic.local_addr;
	struct psif_wr_remote *ra = &wqe->wr.details.atomic.remote_addr;

	la->addr = wr->sg_list[0].addr;
	la->lkey = wr->sg_list[0].lkey;
	la->length = sizeof(long);

	ra->addr = wr->wr.atomic.remote_addr;
	ra->rkey = wr->wr.atomic.rkey;
	ra->length = sizeof(long);

	/* Payload order as in IB header */
	if (wr->opcode == IB_WR_ATOMIC_CMP_AND_SWP) {
		wqe->payload[0] = cpu_to_be64(wr->wr.atomic.swap);
		wqe->payload[1] = cpu_to_be64(wr->wr.atomic.compare_add);
		wqe->wr.collect_length = 16;
	} else {
		wqe->payload[0] = cpu_to_be64(wr->wr.atomic.compare_add);
		wqe->wr.collect_length = 8;
	}
}
