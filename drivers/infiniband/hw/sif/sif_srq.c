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
 * sif_srq.c: Interface to shared receive queues for SIF
 */

#include <rdma/ib_verbs.h>
#include "sif_dev.h"
#include "sif_qp.h"
#include "sif_srq.h"
#include "sif_base.h"
#include "sif_defs.h"
#include "sif_sndrcv.h"

struct ib_srq *sif_create_srq(struct ib_pd *ibpd,
			      struct ib_srq_init_attr *srq_init_attr,
			      struct ib_udata *udata)
{
	int rq_idx;
	struct sif_dev *sdev = to_sdev(ibpd->device);
	struct sif_rq *rq;
	ulong user_flags = 0;
	int ret = 0;
	bool user_mode = udata != NULL;

	if (sif_feature(disable_srq))
		return ERR_PTR(-EOPNOTSUPP);

	if (udata) {
		struct sif_create_srq_ext cmd;

		ret = ib_copy_from_udata(&cmd, udata, sizeof(cmd));
		if (ret)
			goto err_create_srq;
		user_flags = cmd.flags;

		if (sif_vendor_enable(SVF_kernel_mode, user_flags))
			user_mode = false;
	}

	sif_log(sdev, SIF_SRQ, "%s", (user_mode ? "(user)" : "(kernel)"));

	rq_idx = alloc_rq(sdev, to_spd(ibpd), srq_init_attr->attr.max_wr,
			srq_init_attr->attr.max_sge, srq_init_attr, user_mode);
	if (rq_idx < 0) {
		ret = rq_idx;
		goto err_create_srq;
	}

	rq = get_sif_rq(sdev, rq_idx);

	if (udata) {
		struct sif_create_srq_resp_ext resp;

		memset(&resp, 0, sizeof(resp));
		resp.index = rq_idx;
		resp.extent = rq->extent;
		ret = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (ret)
			goto err_udata;
	}

	srq_init_attr->attr.max_wr = rq->entries_user;

	return &rq->ibsrq;
err_udata:
	free_rq(sdev, rq->index);
err_create_srq:
	return ERR_PTR(ret);
}

#define ARM_SRQ_HOLDOFF (10 + jiffies)

static int sif_arm_srq(struct sif_dev *sdev, struct sif_rq *srq, u32 srq_limit)
{
	int ret;
	struct psif_wr wr;
	struct psif_cq_entry *cqe;
	DECLARE_SIF_CQE_POLL_WITH_RR_PQP(sdev, lcqe);
	struct sif_pqp *pqp = lcqe.pqp;

	if (unlikely(!pqp))
		return -EAGAIN;

	memset(&wr, 0, sizeof(struct psif_wr));

	wr.completion = 1;
	wr.op = PSIF_WR_SET_SRQ_LIM;
	wr.details.su.srq_lim = srq_limit;
	wr.details.su.u2.rq_id = srq->index;

try_again:
	if (time_is_after_jiffies((unsigned long)atomic64_read(&pqp->qp->arm_srq_holdoff_time))) {
		cpu_relax();
		goto try_again;
	}

	atomic64_set(&pqp->qp->arm_srq_holdoff_time, ARM_SRQ_HOLDOFF);
	pqp->qp->srq_idx = srq->index;

	ret = sif_pqp_poll_wr(sdev, &wr, &lcqe);
	if (ret < 0) {
		sif_log(sdev, SIF_INFO, "pqp request failed with errno %d", ret);
		return ret;
	}

	cqe = &lcqe.cqe;
	if (cqe->status != PSIF_WC_STATUS_SUCCESS) {
		sif_log(sdev, SIF_INFO, "failed with status %s(%d) for cq_seq %d",
			string_enum_psif_wc_status(cqe->status), cqe->status, cqe->seq_num);
		return -EIO;
	}

	srq->srq_limit = srq_limit;

	return 0;
}

int sif_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr,
		   enum ib_srq_attr_mask attr_mask, struct ib_udata *udata)
{
	struct sif_dev *sdev = to_sdev(ibsrq->device);
	struct sif_rq *srq = to_srq(ibsrq);
	u16 srq_limit;
	int ret;

	if (attr_mask & IB_SRQ_MAX_WR) {
		sif_log(sdev, SIF_SRQ, "SRQ_MAX_WR not supported");
		return -EINVAL;
	}

	if (attr_mask & IB_SRQ_LIMIT) {
		srq_limit = attr->srq_limit & 0x3fff;
		if (srq_limit >= srq->entries)
			return -EINVAL;

		ret = sif_arm_srq(sdev, srq, srq_limit);
		if (ret)
			return ret;
	}
	return 0;
}

int sif_query_srq(struct ib_srq *ibsrq, struct ib_srq_attr *attr)
{
	struct sif_rq *srq = to_srq(ibsrq);

	attr->max_wr	= srq->entries;
	attr->max_sge	= srq->sg_entries;
	attr->srq_limit = srq->srq_limit;

	return 0;
}

int sif_destroy_srq(struct ib_srq *ibsrq)
{
	int sts;
	struct sif_dev *sdev = to_sdev(ibsrq->device);
	struct sif_rq *rq = to_srq(ibsrq);

	sif_log(sdev, SIF_SRQ, "rq %d", rq->index);

	if (atomic_read(&rq->refcnt) > 1)
		return -EBUSY;

	/* An SRQ cannot be flushed with flushed-in-error completions
	 * as we don't know which completion queue to generate
	 * the flushed-in-error completions for, and this should be fine
	 * from a standards perspective:
	 * IB spec refs: 10.2.9.4, 11.2.3.4.
	 */
	sts = sif_invalidate_rq_hw(sdev, rq->index, PCM_WAIT);
	if (sts) {
		sif_log(sdev, SIF_INFO,
			"Invalidate rq_hw failed");
	}

	return free_rq(sdev, rq->index);
}

int sif_post_srq_recv(struct ib_srq *ibsrq, struct ib_recv_wr *recv_wr,
		      struct ib_recv_wr **bad_recv_wr)
{
	struct sif_dev *sdev = to_sdev(ibsrq->device);
	struct sif_rq *rq = to_srq(ibsrq);

	sif_logi(ibsrq->device, SIF_SRQ, "rq %d (SRQ)", rq->index);

	return post_recv(sdev, NULL, rq, recv_wr, bad_recv_wr);
}
