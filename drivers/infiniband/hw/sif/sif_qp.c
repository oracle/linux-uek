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
 * sif_qp.c: Implementation of IB queue pair logic for sif
 */

#include <linux/random.h>
#include <rdma/ib_verbs.h>
#include "sif_dev.h"
#include "sif_defs.h"
#include "sif_qp.h"
#include "sif_ah.h"
#include "sif_sq.h"
#include "sif_pqp.h"
#include "sif_dma.h"
#include "sif_user.h"
#include "sif_base.h"
#include "sif_mr.h"
#include "sif_xrc.h"
#include "sif_query.h"
#include "sif_hwi.h"
#include "sif_user.h"
#include "psif_hw_data.h"
#include "psif_hw_setget.h"
#include "psif_hw_csr.h"
#include "sif_ibcq.h"
#include "sif_sndrcv.h"
#include <linux/delay.h>
#include <linux/seq_file.h>

/* Work-around for bz 3646 */
static unsigned char bug_3646_conv_table[32] = {
	0,
	18,
	20,
	21,
	22,
	23,
	24,
	25,
	26,
	27,
	28,
	29,
	30,
	31,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
};

static int reset_qp(struct sif_dev *sdev, struct sif_qp *qp);

static int sif_create_pma_qp(struct ib_pd *ibpd,
			struct ib_qp_init_attr *init_attr,
			struct sif_qp_init_attr sif_attr);

struct sif_sq *get_sq(struct sif_dev *sdev, struct sif_qp *qp)
{
	return is_xtgt_qp(qp) ? NULL : get_sif_sq(sdev, qp->qp_idx);
}

/* Get RQ associated to QP */
struct sif_rq *get_rq(struct sif_dev *sdev, struct sif_qp *qp)
{
	return is_xrc_qp(qp) || qp->type == PSIF_QP_TRANSPORT_MANSP1 ?
			NULL : get_sif_rq(sdev, qp->rq_idx);
}

static int poll_wait_for_qp_writeback(struct sif_dev *sdev, struct sif_qp *qp)
{
	unsigned long timeout = sdev->min_resp_ticks;
	unsigned long timeout_real = jiffies + timeout;
	enum psif_qp_state state = PSIF_QP_STATE_INIT;

	sif_log(sdev, SIF_QP, "enter qp %d", qp->qp_idx);
	do {
		/* Make sure the update from hw is observed in correct order */
		smp_rmb();
		state = get_psif_qp_core__state(&qp->d.state);

		if (state == PSIF_QP_STATE_RESET)
			break;

		if (time_is_before_jiffies(timeout_real))
			cond_resched();
		else {
			sif_log(sdev, SIF_INFO,
				"Timeout waiting for write back for QP %d - last state %s",
				qp->qp_idx, string_enum_psif_qp_state(state));

			if (unlikely(sif_debug_mask & SIF_QP_V)) {
				struct psif_query_qp lqqp;
				int ret;

				ret = epsc_query_qp(qp, &lqqp);
				if (ret)
					sif_log(sdev, SIF_QP_V,
						"Unable to retrieve qp state for qp %d from epsc, status %d",
						qp->qp_idx, ret);
				else
					sif_logs(SIF_QP_V, write_struct_psif_query_qp(NULL, 0, &lqqp));
			}

			return -ETIMEDOUT;
		}
	} while (true);

	sif_log(sdev, SIF_QP, "exit - write-back observed on qp %d", qp->qp_idx);
	return 0;
}

static int send_epsa_proxy_qp_sq_key(struct sif_dev *sdev, u32 lkey,
				     int qpnum,
				    enum psif_mbox_type eps_num)
{
	struct psif_epsc_csr_req req;
	struct psif_epsc_csr_rsp rsp;
	int ret;

	memset(&req, 0, sizeof(req));
	req.opcode = EPSC_A_COMMAND;
	req.u.epsa_cmd.cmd = EPSA_GET_PROXY_QP_SQ_KEY;
	req.u.epsa_cmd.key = lkey;
	req.u.epsa_cmd.qpnum = qpnum;
	ret = sif_eps_wr(sdev, eps_num, &req, &rsp);

	return ret;
}

struct sif_qp *create_qp(struct sif_dev *sdev,
			struct ib_qp_init_attr *init_attr,
			struct sif_qp_init_attr *sif_attr)
{
	struct sif_qp *qp, *rqp = NULL;
	struct sif_sq *sq = NULL;
	struct sif_rq *rq = NULL;
	struct psif_qp qpi;
	struct sif_pd *pd = sif_attr->pd;

	int ret = 0;
	int rq_idx = -1;
	int request_qpn = -1;
	int index;
	bool mark_dirty = false;
	struct sif_cq *send_cq = NULL;
	struct sif_cq *recv_cq = NULL;
	u32 flags = init_attr->create_flags;
	u32 max_sge;
	int min_tso_inline;

	/* In limited mode QPs are not usable and possibly hazardous as nothing is set up
	 * avoid any creation of any such:
	 */
	if (unlikely(sdev->limited_mode)) {
		sif_log(sdev, SIF_INFO, "limited mode does not support QP creation!");
		return ERR_PTR(-ENODEV);
	}

	if (init_attr->send_cq)
		send_cq = to_scq(init_attr->send_cq);
	if (init_attr->recv_cq)
		recv_cq = to_scq(init_attr->recv_cq);


	max_sge = SIF_HW_MAX_SEND_SGE;

	/* We need to be able to add sge for stencil with LSO */
	max_sge -= !!(flags & IB_QP_CREATE_IPOIB_UD_LSO);

	if (init_attr->cap.max_send_sge > max_sge) {
		sif_log(sdev, SIF_INFO, "illegal max send sge %d, SIF only supports %d %s",
			init_attr->cap.max_send_sge, max_sge,
			flags & IB_QP_CREATE_IPOIB_UD_LSO ? "with LSO" : "");
		return ERR_PTR(-EINVAL);
	}

	if (init_attr->cap.max_inline_data > sif_max_inline) {
		sif_log(sdev, SIF_INFO,
			"%d bytes of inline data requested - supported max %u - this limit is defined by module parameter max_inline",
			init_attr->cap.max_inline_data, sif_max_inline);
		return ERR_PTR(-EINVAL);
	}

	if (init_attr->qp_type <= IB_QPT_GSI) {
		/* IB verbs port numbers start at 1 while psif starts w/port 0 */
		int qpn = init_attr->qp_type + ((init_attr->port_num - 1) << 1);
		int ok = atomic_add_unless(&sdev->sqp_usecnt[qpn], 1, 1);

		if (!ok) {
			sif_log(sdev, SIF_INFO,
				"Attempt to create QP %d for port %d more than once",
				init_attr->qp_type, init_attr->port_num);
			return ERR_PTR(-EBUSY);
		}
		request_qpn = qpn;
		sif_log(sdev, SIF_QP, "Requested qp %d, port %d",
			init_attr->qp_type, init_attr->port_num);
	}

	/* Allow allocation of qp 0/1 */
	index = request_qpn >= 0 ? request_qpn : sif_alloc_qp_idx(pd);
	if (index < 0) {
		rqp = ERR_PTR(-ENOMEM);
		sif_log(sdev, SIF_QP, "sif_alloc_qp_idx failed");
		goto err_alloc_index;
	}
	qp = get_sif_qp(sdev, index);

	/* Set this temporarily - needed by reporting of qp write-back check */
	qp->qp_idx = index;
	/*
	 * We add a sge (with the stencil) when sending with TSO. The stencil is stored at
	 * the beginning of the inline-area. TSO implies checksumming which again has
	 * a requirement that no inline can be used. 
	 * To be able to accomodate as large L3/L4-headers as possible we allocate 192
	 * bytes for inlining;
	 * entry size 512 bytes
	 * 16*16 bytes sge
	 * request 64 bytes
	 * inline_bufer = 512 - 256 -64 = 192
	 */
	min_tso_inline = 192;
	if (flags & IB_QP_CREATE_IPOIB_UD_LSO) {
		if (init_attr->cap.max_inline_data < min_tso_inline) {
			sif_log(sdev, SIF_INFO,
				"Create LSO QP; qp_%d max_sge %d inline_size %d qp_type %d; modifying max_inline_size to %d",
				index, init_attr->cap.max_send_sge, init_attr->cap.max_inline_data,
				init_attr->qp_type, min_tso_inline);
			init_attr->cap.max_inline_data = min_tso_inline;
		}
		init_attr->cap.max_send_sge ++;
	}

	if (init_attr->qp_type == IB_QPT_RC || init_attr->qp_type == IB_QPT_XRC_INI) {
		/* Required in anticipation of Atomics use */
		init_attr->cap.max_inline_data = max(init_attr->cap.max_inline_data, 16U);
	}

	/* Now, before we can write the QP state - we must ensure that any previous usage
	 * has been completed (the writeback after modify_qp to RESET happens asynchronously
	 * after the modify_qp request completes.
	 */
	ret = poll_wait_for_qp_writeback(sdev, qp);
	if (ret) {
		/* Dont release this desc as it is probably not safe to use anymore */
		mark_dirty = true;
		rqp = ERR_PTR(ret);
		goto err_lazy_wb;
	}

	memset(qp, 0, sizeof(struct sif_qp));
	qp->qp_idx = index;
	qp->ulp_type = sif_attr->ulp_type;

	if (qp->ulp_type == RDS_ULP) {
		int new_max_inline = CB_LENGTH; /* collectbuffer_length is max 256 */

		sif_log(sdev, SIF_QP,
			"Create QP; qp_%d max_sge %d inline_size %d qp_type %d; modifing max_inline_size to %d",
			index, init_attr->cap.max_send_sge, init_attr->cap.max_inline_data,
			init_attr->qp_type, new_max_inline);
		init_attr->cap.max_inline_data = new_max_inline;
	}

	if (init_attr->qp_type <= IB_QPT_GSI) {
		qp->port = init_attr->port_num;
		if (init_attr->qp_type == IB_QPT_SMI)
			qp->flags |= SIF_QPF_SMI;
		else if (init_attr->qp_type == IB_QPT_GSI)
			qp->flags |= SIF_QPF_GSI;
	} else {
		/* Let port 1 be default: init_attr->port_num is only valid for qp 0/1 */
		qp->port = 1;
	}

	qp->last_set_state = IB_QPS_RESET;
	qp->tracked_state = IB_QPS_RESET;
	qp->mtu = IB_MTU_4096;
	qp->type = sif_attr->qp_type;

	/* TBD: Optimize this log to a single stmt */
	if (send_cq)
		sif_log(sdev, SIF_QP, "qpn %d, qp 0x%p send cq %d (type %s) port %d, pd %d",
			index, qp, send_cq->index, string_enum_psif_qp_trans(qp->type),
			qp->port, pd->idx);
	else
		sif_log(sdev, SIF_QP, "qpn %d, qp 0x%p [no send cq] (type %s) port %d, pd %d",
			index, qp, string_enum_psif_qp_trans(qp->type), qp->port, pd->idx);

	/* The PQP and XRC QPs do not have receive queues */
	if (qp->type != PSIF_QP_TRANSPORT_MANSP1 && qp->type != PSIF_QP_TRANSPORT_XRC) {
		if (init_attr->srq) {
			rq = to_srq(init_attr->srq);
			if (atomic_add_unless(&rq->refcnt, 1, 0)) {
				rq_idx = rq->index;
				sif_log(sdev, SIF_QP, "Connected qp %d to SRQ %d",
					index, rq_idx);
			} else {
				sif_log(sdev, SIF_INFO,
					"failed to connect qp %d to SRQ %d, rq invalid",
					index, rq_idx);
				rqp = ERR_PTR(-ENODEV);
				goto err_rq_fail;
			}
		} else {
			rq_idx = alloc_rq(sdev, pd, init_attr->cap.max_recv_wr,
					init_attr->cap.max_recv_sge, NULL,
					sif_attr->user_mode);
			if (rq_idx >= 0)
				rq = get_sif_rq(sdev, rq_idx);
		}
		if (rq_idx < 0) {
			rqp = ERR_PTR(rq_idx);
			goto err_rq_fail;
		}

		/* Adjust requested values based on what we got: */
		init_attr->cap.max_recv_wr = rq->entries_user;
	}
	qp->rq_idx = rq_idx;

	if (rq && !init_attr->srq) {
		/* Check/update max sge cap: */
		if (rq->sg_entries > init_attr->cap.max_recv_sge) {
			sif_log(sdev, SIF_QP, "recv sge adjusted (%d -> %d)",
				init_attr->cap.max_recv_sge, rq->sg_entries);
			init_attr->cap.max_recv_sge = rq->sg_entries;
		}

		/* Store cq reference for cleanup purposes */
		if (recv_cq)
			rq->cq_idx = recv_cq->index;
	}

	if (init_attr->qp_type != IB_QPT_XRC_TGT) {
		/* sq always gets same index as QP.. */
		ret = sif_alloc_sq(sdev, pd, qp, &init_attr->cap,
				sif_attr->user_mode, sif_attr->sq_hdl_sz);
		if (ret < 0) {
			rqp = ERR_PTR(ret);
			goto err_sq_fail;
		}

		/* Store send completion queue index default since
		 * for psif send cq number is a parameter in the work request
		 */
		sq = get_sif_sq(sdev, qp->qp_idx);
		sq->cq_idx = send_cq ? send_cq->index : (u32)-1; /* XRC recv only */
		sq->complete_all = init_attr->sq_sig_type == IB_SIGNAL_ALL_WR ? 1 : 0;

		/* Adjust requested values based on what we got: */
		init_attr->cap.max_send_wr = sq->entries;
	}

	/* Initialization of qp state via local copy */
	memset(&qpi, 0, sizeof(struct psif_qp));

	if (is_reliable_qp(qp->type) && init_attr->qp_type != IB_QPT_XRC_TGT) {
		qpi.state.sq_clog2_extent = order_base_2(sq->extent);
		qpi.state.sq_clog2_size = order_base_2(sq->entries);
	}
	qpi.state.retry_sq_seq = 0;
	qpi.state.state = ib2sif_qp_state(IB_QPS_RESET);
	qpi.state.pd = pd->idx;
	if (!sif_feature(zero_magic)) {
		qp->magic = prandom_u32();
		qpi.state.magic = qp->magic;
	}
	qpi.state.transport_type = qp->type;
	if (qp->type == PSIF_QP_TRANSPORT_XRC && init_attr->xrcd)
		qpi.state.xrc_domain = to_sxrcd(init_attr->xrcd)->index;
	qpi.state.rq_indx = rq_idx;
	qpi.state.rq_is_srq = !!init_attr->srq || (init_attr->qp_type == IB_QPT_XRC_TGT);
	qpi.state.send_cq_indx = send_cq ? send_cq->index : (u32)-1;
	qpi.state.rcv_cq_indx = recv_cq ? recv_cq->index : (u32)-1;

	qpi.state.mstate = APM_MIGRATED;
	qpi.state.path_mtu = ib2sif_path_mtu(qp->mtu);
	/* Last acked psn must be initialized to one less than xmit_psn
	 * and it is a 24 bit value. See issue #1011
	 */
	qpi.state.xmit_psn = 0;
	qpi.state.last_acked_psn = 0xffffff;
	qpi.state.qosl = qp->qosl = sif_attr->qosl;

	/* See #2402/#2770 */
	if (sif_feature(infinite_rnr)) {
		qpi.state.rnr_retry_init = 7;
		qpi.state.rnr_retry_count = 7;
		qpi.state.min_rnr_nak_time = 26; /* Bug 3646, this is about 160 us */
	}

	if (flags & IB_QP_NO_CSUM)
		qpi.state.no_checksum = 1;

	if (sif_attr->proxy != SIFPX_OFF) {
		/* This is a proxy QP */
		qpi.state.proxy_qp_enable = 1;
		qp->eps_tag |= EPS_TAG_FROM_HOST;
		ret = send_epsa_proxy_qp_sq_key(sdev, sq->sg_mr->index,
						qp->qp_idx,
						proxy_to_mbox(sif_attr->proxy));
		if (ret)
			sif_log(sdev, SIF_QP, "send_epsa_proxy_qp_sq_key failed");
	}

	if (sif_attr->user_mode)
		qp->flags |= SIF_QPF_USER_MODE;

	if (flags & IB_QP_CREATE_IPOIB_UD_LSO) {
		qp->flags |= SIF_QPF_IPOIB;
		qpi.state.ipoib_enable = 1;
		qpi.state.ipoib = 1;
	}

	/* PSIF extensions */
	if (flags & IB_QP_CREATE_EOIB) {
		qp->flags |= SIF_QPF_EOIB;
		qpi.state.eoib_enable = 1;
		qpi.state.eoib = 1;
		qpi.state.eoib_type = EOIB_QKEY_ONLY;
	}
	if (flags & IB_QP_CREATE_RSS)
		qpi.state.rss_enable = 1;
	if (flags & IB_QP_CREATE_HDR_SPLIT)
		qpi.state.hdr_split_enable = 1;
	if (flags & IB_QP_CREATE_RCV_DYNAMIC_MTU)
		qpi.state.rcv_dynamic_mtu_enable = 1;
	if (flags & IB_QP_CREATE_SND_DYNAMIC_MTU)
		qpi.state.send_dynamic_mtu_enable = 1;

	/* according to ib_verbs.h init_attr->port_num is only valid for QP0/1 */
	if (init_attr->qp_type <= IB_QPT_GSI)
		qpi.path_a.port = init_attr->port_num - 1;

	sif_log(sdev, SIF_QP, "qp %d path_a.port = %d", qp->qp_idx, qpi.path_a.port);

	/* Write composed entry to shared area */
	copy_conv_to_hw(&qp->d, &qpi, sizeof(struct psif_qp));

	mutex_init(&qp->lock); /* TBD: Sync scheme! */
	set_bit(SIF_QPS_IN_RESET, &qp->persistent_state);

	/* Users should see qp 0/1 even though qp 0/1 is mapped to qp 2/3 for
	 * port 2
	 */
	qp->ibqp.qp_num = qp->qp_idx > 3 ?  qp->qp_idx : (qp->qp_idx & 0x1);

	/* For the priv. QP types we need to set some other elements in the
	 * ib verbs struct as well
	 */
	if (qp->type == PSIF_QP_TRANSPORT_MANSP1) {
		qp->ibqp.device = &sdev->ib_dev;
		qp->ibqp.qp_num = qp->qp_idx;
		qp->ibqp.qp_type = IB_QPT_UD;
	}


	ret = sif_dfs_add_qp(sdev, qp);
	if (ret)
		goto err_dfs_qp;
	/* initialize the sychronization between destroy qp and event handling.*/
	init_completion(&qp->can_destroy);

	/* a qp can only be destroyed if refcnt == 0.*/
	atomic_set(&qp->refcnt, 1);

	return qp;

err_dfs_qp:
	sif_free_sq(sdev, qp);
err_sq_fail:
	if (rq && !rq->is_srq)
		free_rq(sdev, rq_idx);
err_rq_fail:
err_lazy_wb:
	if (!mark_dirty)
		sif_free_qp_idx(pd, qp->qp_idx);
err_alloc_index:
	return rqp;
}

/* PMA proxy QP */
static int sif_create_pma_qp(struct ib_pd *ibpd,
			struct ib_qp_init_attr *init_attr,
			struct sif_qp_init_attr sif_attr)
{
	struct ib_qp *ret = NULL;
	struct sif_dev *sdev;
	struct sif_pd *pd;
	struct sif_qp *qp;

	sdev = to_sdev(ibpd->device);
	pd = to_spd(ibpd);
	/* Let's override IB_QPT_GSI by IB_QPT_UD*/
	init_attr->qp_type = IB_QPT_UD;

	qp = create_qp(sdev, init_attr, &sif_attr);

	if (IS_ERR(qp)) {
		/* Convert interior error to right type: */
		ret = (struct ib_qp *)qp;
		goto err_create_qp;
	}
	qp->flags |= SIF_QPF_PMA_PXY;
	qp->port = init_attr->port_num;
	sdev->pma_qp_idxs[qp->port - 1] = qp->qp_idx;

	/* Init ibqp side of things */
	qp->ibqp.device = &sdev->ib_dev;
	qp->ibqp.real_qp = &qp->ibqp;
	qp->ibqp.uobject = NULL;
	qp->ibqp.qp_type = IB_QPT_GSI;
	atomic_set(&qp->ibqp.usecnt, 0);
	qp->ibqp.event_handler = init_attr->event_handler;
	qp->ibqp.qp_context = init_attr->qp_context;
	qp->ibqp.recv_cq = init_attr->recv_cq;
	qp->ibqp.srq = init_attr->srq;
	qp->ibqp.pd = &sdev->pd->ibpd;
	qp->ibqp.send_cq = init_attr->send_cq;
	qp->ibqp.xrcd = NULL;

	/* Set back IB_QPT_GSI */
	init_attr->qp_type = IB_QPT_GSI;

	sif_log(sdev, SIF_QP, "Exit: success 0x%p  proxy qp %d - real qp %d",
		&qp->ibqp, qp->ibqp.qp_num, qp->qp_idx);
	return qp->qp_idx;

err_create_qp:
	sif_log(sdev, SIF_QP, "Exit: failed");
	return 0;
}

struct ib_qp *sif_create_qp(struct ib_pd *ibpd,
			    struct ib_qp_init_attr *init_attr,
			    struct ib_udata *udata)
{
	struct sif_dev *sdev;
	struct sif_qp *qp;
	struct sif_pd *pd;
	struct sif_xrcd *xrcd = NULL;
	struct ib_qp *ret = NULL;
	enum ib_qp_create_flags flags = init_attr->create_flags;
	ulong user_flags = 0;

	struct sif_qp_init_attr sif_attr = {
		.qp_type = ib2sif_qp_type(init_attr->qp_type),
		.user_mode = udata != NULL,
		.sq_hdl_sz = sizeof(struct sif_sq_hdl),
	};


	/* First we need to locate the device pointer -
	 * if this is an XRC QP ibpd will be NULL:
	 */
	if (init_attr->qp_type == IB_QPT_XRC_TGT) {
		if (!init_attr->xrcd) {
			sif_log0(SIF_INFO, "Error: missing XRC domain for XRC qp");
			return ERR_PTR(-EINVAL);
		}

		xrcd = to_sxrcd(init_attr->xrcd);
		sdev = to_sdev(init_attr->xrcd->device);

		pd = xrcd->pd;
	} else {
		sdev = to_sdev(ibpd->device);
		pd = to_spd(ibpd);
	}

	sif_attr.pd = pd;

	sif_log(sdev, SIF_QP, "Enter qp_type %d%s", init_attr->qp_type,
		(udata ? " (user call)" : ""));

	/* TBD: How to handle this? */
	if (flags & IB_QP_CREATE_BLOCK_MULTICAST_LOOPBACK)
		sif_log(sdev, SIF_QP, "flag IB_QP_CREATE_BLOCK_MULTICAST_LOOPBACK set (ignored)");

	if (flags & IB_QP_CREATE_PROXY) {
		/* We don't know the actual EPSA to use here but QPs dont care */
		sif_attr.proxy = SIFPX_EPSA_1;
	}

	/* TBD: Verify that user params such as the send cq are authorized?? */
	if (!xrcd && !init_attr->send_cq) {
		sif_log(sdev, SIF_INFO, "No send completion queue specified");
		ret = ERR_PTR(-EINVAL);
		goto err_create_qp;
	}

	if (!xrcd && !init_attr->recv_cq) {
		sif_log(sdev, SIF_INFO, "No receive completion queue specified");
		ret = ERR_PTR(-EINVAL);
		goto err_create_qp;
	}

	if (udata && init_attr->qp_type <= IB_QPT_GSI) {
		sif_log(sdev, SIF_INFO, "Attempt to create SMI/GSI QP %d from user space",
			init_attr->qp_type);
		return ERR_PTR(-EINVAL);
	}

	if (udata) {
		struct sif_create_qp_ext cmd;
		int rv = ib_copy_from_udata(&cmd, udata, sizeof(cmd));

		if (rv) {
			ret = ERR_PTR(rv);
			goto err_create_qp;
		}
		user_flags = cmd.flags;
		if (sif_vendor_enable(proxy_mode, user_flags))
			sif_attr.proxy = cmd.proxy;

		if (sif_vendor_enable(SVF_kernel_mode, user_flags))
			sif_attr.user_mode = false;

		if (sif_vendor_enable(tsu_qosl, user_flags))
			sif_attr.qosl = QOSL_LOW_LATENCY;

		if (sif_vendor_enable(no_checksum, user_flags)) {
			/* update the init_attr->create_flags directly.
			 * This will allow the same code path if umem can pass this as a
			 * create_qp flag via struct ibv_qp_init_attr_ex in the future:
			 */
			init_attr->create_flags |= IB_QP_NO_CSUM;
		}
	}

	/* TBD: check init_attr params against device cap-limits */
	/* TBD update ib_qp_cap? */
	if (sif_vendor_enable(dynamic_mtu, user_flags)) {
		/* TBD - check the device capabilities to determine whether to
		 * create qp with the support of send/receive dynamic MTU.
		 */
		init_attr->create_flags |= IB_QP_CREATE_RCV_DYNAMIC_MTU;
		init_attr->create_flags |= IB_QP_CREATE_SND_DYNAMIC_MTU;
	}

	/* best effort to determine the ULP caller. */
	if (!sif_attr.user_mode)
		sif_attr.ulp_type = sif_find_kernel_ulp_caller();

	qp = create_qp(sdev, init_attr, &sif_attr);

	if (IS_ERR(qp)) {
		/* Convert interior error to right type: */
		ret = (struct ib_qp *)qp;
		goto err_create_qp;
	} else {
		sif_log(sdev, SIF_QP, "Exit: success 0x%p  ib qp %d - real qp %d%s",
			&qp->ibqp, qp->ibqp.qp_num, qp->qp_idx,
			(sif_attr.user_mode ? " (user mode)" : ""));
	}

	qp->qosl = sif_attr.qosl;
	qp->nocsum = init_attr->create_flags & IB_QP_NO_CSUM;



	if (sif_vendor_enable(dynamic_mtu, user_flags)) {
		/* TBD - dynamic mtu flag should only be set during modify_qp in CM
		 * or OOB establishment. It is only set if remote dynamic_mtu_supported &&
		 * local dynamic_send_mtu_supported. As create_qp should not be in
		 * the critical path, split this code from the setting of
		 * IB_QP_CREATE_RCV_DYNAMIC_MTU and IB_QP_CREATE_SND_DYNAMIC_MTU flags
		 * to remind ourself that this need to be implemented separately.
		 */
		sif_log(sdev, SIF_QP, "Enabling forced dynamic MTU for qp %d", qp->qp_idx);
		qp->flags |= SIF_QPF_DYNAMIC_MTU;
	}

	if (sif_vendor_enable(SQ_mode, user_flags)) {
		sif_log(sdev, SIF_QP, "Enabling forced SQ mode for qp %d", qp->qp_idx);
		qp->flags |= SIF_QPF_FORCE_SQ_MODE;
	}

	if (udata) {
		struct sif_create_qp_resp_ext resp;
		struct sif_sq *sq = (init_attr->qp_type != IB_QPT_XRC_TGT) ?
					get_sif_sq(sdev, qp->qp_idx) : NULL;
		struct sif_rq *rq = get_rq(sdev, qp);
		int rv;

		memset(&resp, 0, sizeof(resp));
		resp.qp_idx = qp->qp_idx;

		if (sq) {
			resp.sq_extent = sq->extent;
			resp.sq_sgl_offset = sq->sgl_offset;
			resp.sq_mr_idx = sq->sg_mr ? sq->sg_mr->index : 0;
			resp.sq_dma_handle = sif_mem_dma(sq->mem, 0);
		}

		if (rq) {
			resp.rq_idx = qp->rq_idx;
			resp.rq_extent = rq->extent;
		}

		resp.magic = get_psif_qp_core__magic(&qp->d.state);
		rv = ib_copy_to_udata(udata, &resp, sizeof(resp));
		if (rv) {
			ret = ERR_PTR(rv);
			goto err_udata;
		}
	}
	/* Support for PMA_PXY QP bug #3357 */
	if (init_attr->qp_type == IB_QPT_GSI
		&& eps_version_ge(&sdev->es[sdev->mbox_epsc], 0, 57)) {
		int pma_qp_idx = sif_create_pma_qp(ibpd, init_attr, sif_attr);

		if (!pma_qp_idx)
			sif_log(sdev, SIF_INFO, "Create PMA_PXY qp %d port %d failed",
				qp->qp_idx, init_attr->port_num);
	}

	return &qp->ibqp;
err_udata:
	destroy_qp(sdev, qp);
err_create_qp:
	sif_log(sdev, SIF_QP, "Exit: failed");
	return ret;
}


/* Modify qp implementation related: */


enum sif_mqp_type sif_modify_qp_is_ok(struct sif_qp *qp, enum ib_qp_state cur_state,
				enum ib_qp_state next_state, enum ib_qp_attr_mask mask)
{
	struct sif_dev *sdev = to_sdev(qp->ibqp.device);
	enum ib_qp_type type = qp->ibqp.qp_type;
	int ret;
	enum rdma_link_layer ll = IB_LINK_LAYER_INFINIBAND;

	ret = ((qp->type == PSIF_QP_TRANSPORT_MANSP1 || is_epsa_tunneling_qp(type)) ? 1 :
		ib_modify_qp_is_ok(cur_state, next_state, type, mask, ll));
	if (!ret)
		return SIF_MQP_ERR;
	switch (cur_state) {
	case IB_QPS_RESET:
		if (qp->tracked_state == IB_QPS_SQD)
			qp->tracked_state = IB_QPS_RESET;
		return SIF_MQP_SW;
	case IB_QPS_INIT:
		if (next_state == IB_QPS_INIT || next_state == IB_QPS_RESET ||
			next_state == IB_QPS_ERR)
			return SIF_MQP_SW;
		/* else fall-through */
	case IB_QPS_RTS:
		/* TBD: Elim.hack to behave like mlx on this: */
		if (unlikely(qp->tracked_state == IB_QPS_SQD &&
				next_state != IB_QPS_RESET && next_state != IB_QPS_ERR))
			return SIF_MQP_ERR;
		if (unlikely(next_state == IB_QPS_SQD)) {
			qp->tracked_state = next_state; /* To fail on future transitions */
			return SIF_MQP_IGN; /* Allow, but ignore as MLX does */
		}
		/* else fall-through */
	case IB_QPS_RTR:
		if (unlikely(next_state == IB_QPS_SQD))
			return SIF_MQP_ERR;
		return SIF_MQP_HW;
	case IB_QPS_SQE:
		return SIF_MQP_HW;
	case IB_QPS_ERR:
		/* Bug #3933 WA for HW bug 3928
		 * For this specific transition, modify qp must be done based
		 * on current qp ownership (towards HW only if HW owned)
		 */
		return (PSIF_REVISION(sdev) <= 3)
			&& !(qp->flags & SIF_QPF_HW_OWNED) ?
			SIF_MQP_SW : SIF_MQP_HW;
	default:
		return SIF_MQP_IGN;
	}
}



static int modify_qp_sw(struct sif_dev *sdev, struct sif_qp *qp,
		 struct ib_qp_attr *qp_attr, int qp_attr_mask);
static int modify_qp_hw(struct sif_dev *sdev, struct sif_qp *qp,
		 struct ib_qp_attr *qp_attr, int qp_attr_mask);



int modify_qp_hw_wa_qp_retry(struct sif_dev *sdev, struct sif_qp *qp,
			struct ib_qp_attr *qp_attr, int qp_attr_mask)
{
	struct ib_qp_attr mod_attr = {
		.qp_state        = IB_QPS_ERR
	};

	bool need_wa_3714 = PSIF_REVISION(sdev) <= 3
		&& IS_PSIF(sdev)
		&& qp_attr_mask & IB_QP_STATE && qp_attr->qp_state == IB_QPS_RESET;

	/* WA for duplicate CQEs */
	bool need_wa_4074 = PSIF_REVISION(sdev) <= 3
		&& (qp->type != PSIF_QP_TRANSPORT_MANSP1)
		&& qp_attr_mask & IB_QP_STATE && qp_attr->qp_state == IB_QPS_ERR
		&& IS_PSIF(sdev);

	int ret = 0;

	if (need_wa_3714 || need_wa_4074) {
		if (qp->type != PSIF_QP_TRANSPORT_MANSP1 && !is_xtgt_qp(qp))
			ret = pre_process_wa4074(sdev, qp);

		if (ret) {
			if (ret != -1)
				sif_log(sdev, SIF_INFO, "Failed to pre-process WA4074, ret - %d", ret);
		}
	}

	if (need_wa_3714) {
		/* WA#3714 part 2 - see bug #3714 */
		ret = modify_qp_hw(sdev, qp, &mod_attr, IB_QP_STATE);
		if (ret)
			sif_log(sdev, SIF_INFO, "implicit modify qp %d to ERR failed - ignoring",
				qp->qp_idx);
	}

	ret = modify_qp_hw(sdev, qp, qp_attr, qp_attr_mask);

	if (need_wa_3714 || need_wa_4074) {
		struct ib_qp_attr attr = {
			.qp_state = IB_QPS_RESET
		};

		if (need_wa_4074) {
			ret = modify_qp_hw(sdev, qp, &attr, IB_QP_STATE);
			if (ret) {
				sif_log(sdev, SIF_INFO, "qp %d RESET failed, ret %d", qp->qp_idx, ret);
				goto err_modify_qp_wa;
			}
			/* Restore QP SW state to ERROR */
			qp->last_set_state = qp->tracked_state = IB_QPS_ERR;
		}

		qp->flags &= ~SIF_QPF_HW_OWNED;

		if (qp->type != PSIF_QP_TRANSPORT_MANSP1 && !is_xtgt_qp(qp))
			ret = post_process_wa4074(sdev, qp);

		if (ret)
			sif_log(sdev, SIF_INFO, "Failed to post-process WA #4074 %d", ret);
	}
err_modify_qp_wa:

	return ret;
}

int notify_epsc_pma_qp(struct sif_dev *sdev, int qp_idx, short port)
{
	struct sif_eps *es = &sdev->es[sdev->mbox_epsc];
	struct psif_epsc_csr_req req;
	struct psif_epsc_csr_rsp rsp;
	int ret = -1;

	if (eps_version_ge(es, 0, 57)) {
		memset(&req, 0, sizeof(req));
		memset(&rsp, 0, sizeof(rsp));
		req.opcode = EPSC_SET;
		req.u.set.data.op = EPSC_QUERY_PMA_REDIRECT_QP;
		req.u.set.data.index = port;
		req.u.set.data.value = qp_idx;

		ret = sif_epsc_wr_poll(sdev, &req, &rsp);
		if (ret) {
			sif_log(sdev, SIF_INFO, "Failed to configure epsc PMA_PXY QP\n");
			return ret;
		}
		return ret;
	} else
		return -EINVAL;
}

int sif_modify_qp(struct ib_qp *ibqp,
	struct ib_qp_attr *qp_attr,
	int qp_attr_mask, struct ib_udata *udata)
{
	struct sif_qp *qp = to_sqp(ibqp);
	struct sif_dev *sdev = to_sdev(ibqp->device);
	struct sif_qp *pma_qp = NULL;
	struct sif_eps *es = &sdev->es[sdev->mbox_epsc];
	int ret = 0;
	bool need_pma_pxy_qp = eps_version_ge(es, 0, 57)
		&& (qp_attr->qp_state != IB_QPS_RTS)
		&& (qp->qp_idx == 1 || qp->qp_idx == 3);

	if (need_pma_pxy_qp) {
		pma_qp = get_sif_qp(sdev, sdev->pma_qp_idxs[!!(qp->qp_idx & 2)]);
		ret = modify_qp(sdev, pma_qp, qp_attr, qp_attr_mask, true, udata);
		if (ret)
			sif_log(sdev, SIF_INFO, "Modify PMA_PXY QP %d failed",
				pma_qp->qp_idx);
		else if (qp_attr->qp_state == IB_QPS_RTR) {
			ret = notify_epsc_pma_qp(sdev, pma_qp->qp_idx, pma_qp->port);
			if (ret)
				sif_log(sdev, SIF_INFO, "Notify epsc PMA_PXY QP %d failed",
					pma_qp->qp_idx);
		}
	}

	return modify_qp(sdev, qp, qp_attr, qp_attr_mask,
			true, udata);
}


int modify_qp(struct sif_dev *sdev, struct sif_qp *qp,
	struct ib_qp_attr *qp_attr, int qp_attr_mask,
	bool fail_on_same_state, struct ib_udata *udata)
{
	int ret = 0;
	struct ib_qp *ibqp = &qp->ibqp;
	struct sif_rq *rq = get_rq(sdev, qp);
	struct sif_sq *sq = get_sq(sdev, qp);
	enum ib_qp_state cur_state, new_state;
	enum sif_mqp_type mqp_type = SIF_MQP_IGN;

	sif_log(sdev, SIF_QP, "Enter: qpn %d qp_idx %d mask 0x%x",
		ibqp->qp_num, qp->qp_idx, qp_attr_mask);

	/* WA for Bug 622, RQ flush from error completion in userspace */
	if (udata) {
		struct sif_modify_qp_ext cmd;

		ret = ib_copy_from_udata(&cmd, udata, sizeof(cmd));
		if (ret) {
			sif_log(sdev, SIF_INFO, "ib_copy_from_udata failed, sts %d, qp %d, size %ld",
				ret, qp->qp_idx, sizeof(cmd));
			return ret;
		}

		switch (cmd.flush) {
		case FLUSH_RQ:
			if (unlikely(!rq)) {
				ret = -EINVAL;
				sif_log(sdev, SIF_INFO,
					"flush requested for qp(type %s) with no rq defined",
					string_enum_psif_qp_trans(qp->type));
			} else {
				ret = sif_flush_rq_wq(sdev, rq, qp, rq->entries);
				if (ret)
					sif_log(sdev, SIF_INFO, "failed to flush RQ %d", rq->index);
			}
			return ret;
		case FLUSH_SQ:
			if (unlikely(!sq)) {
				ret = -EINVAL;
				sif_log(sdev, SIF_INFO,
					"flush requested for qp(type %s) with no sq defined",
					string_enum_psif_qp_trans(qp->type));
			} else {
				ret = post_process_wa4074(sdev, qp);
				if (ret)
					sif_log(sdev, SIF_INFO, "failed to flush SQ %d", qp->qp_idx);
			}
			return ret;
		default:
			break;
		}
	}

	mutex_lock(&qp->lock);

	cur_state = qp_attr_mask & IB_QP_CUR_STATE ?
		qp_attr->cur_qp_state : qp->last_set_state;

	new_state = qp_attr_mask & IB_QP_STATE ? qp_attr->qp_state : cur_state;

	sif_log(sdev, SIF_QP, "qpn %d qp_idx %d requested state 0x%x cur state 0x%x",
		ibqp->qp_num, qp->qp_idx, new_state, cur_state);

	if (!fail_on_same_state && cur_state == qp_attr->qp_state) {
		/* Silently ignore.. (used at destroy time) */
		goto sif_mqp_ret;
	}

	mqp_type = sif_modify_qp_is_ok(qp, cur_state, new_state, qp_attr_mask);
	switch (mqp_type) {
	case SIF_MQP_SW:
		ret = modify_qp_sw(sdev, qp, qp_attr, qp_attr_mask);
		break;
	case SIF_MQP_HW:
		ret = modify_qp_hw_wa_qp_retry(sdev, qp, qp_attr, qp_attr_mask);
		break;
	case SIF_MQP_IGN:
		break;
	case SIF_MQP_ERR:
	default:
		sif_log(sdev, SIF_INFO, "illegal state change from %d to %d for qp %d",
			cur_state, new_state, qp->qp_idx);
		ret = -EINVAL;
	}

sif_mqp_ret:
	if (!ret && !(mqp_type == SIF_MQP_IGN)) {
		/* TBD: Is this needed? */
		qp_attr->cur_qp_state = new_state;
	}

	/* QP ownership flag must be updated before release
	 * the lock in order to avoid race conditions
	 */
	switch (new_state) {
	case IB_QPS_RESET:
		set_bit(SIF_QPS_IN_RESET, &qp->persistent_state);
		qp->flags &= ~SIF_QPF_HW_OWNED;
		break;
	case IB_QPS_RTR:
		clear_bit(SIF_QPS_IN_RESET, &qp->persistent_state);
		qp->flags |= SIF_QPF_HW_OWNED;
		break;
	default:
		/* No extra actions needed */
		break;
	}

	mutex_unlock(&qp->lock);

	if (ret)
		return ret;

	/* Bug #3933 - WA for HW bug 3928
	 * enable/disable the HW ownership QP flag
	 */
	switch (new_state) {
	case IB_QPS_ERR:
		if (rq) {
			/* WA #3850:if SRQ, generate LAST_WQE event */
			if (rq->is_srq && qp->ibqp.event_handler) {
				struct ib_event ibe = {
					.device = &sdev->ib_dev,
					.event = IB_EVENT_QP_LAST_WQE_REACHED,
					.element.qp = &qp->ibqp
				};

				qp->ibqp.event_handler(&ibe, qp->ibqp.qp_context);
			} else if (!rq->is_srq) {
				/* WA #622: if reqular RQ, flush */
				ret = sif_flush_rq_wq(sdev, rq, qp, rq->entries);
				if (ret) {
					sif_log(sdev, SIF_INFO, "failed to flush RQ %d",
						rq->index);
					return ret;
				}
			}
		}
		break;
	case IB_QPS_RESET:
		/* clean all state associated with this QP */
		ret = reset_qp(sdev, qp);
		break;
	default:
		/* No extra actions needed */
		break;
	}
	return ret;
}


static void set_qp_path_hw(struct sif_qp *qp, struct psif_epsc_csr_modify_qp *mct,
			struct ib_qp_attr *qp_attr, int qp_attr_mask, bool alternate)
{
	struct psif_qp_path *path;
	struct ib_ah_attr *ah_attr;
	struct sif_dev *sdev = to_sdev(qp->ibqp.device);
	struct psif_csr_modify_qp_ctrl *ctrl_attr = &mct->ctrl;
	u8 ipd = 0;

	/* IBV_QP_ALT_PATH  Set the alternative path via:
	 * alt_ah_attr, alt_pkey_index, alt_port_num and
	 * alt_timeout.
	 */
	if (alternate) {
		ctrl_attr->alt_path = 1;
		path = &mct->data.alternate_path;
		ah_attr = &qp_attr->alt_ah_attr;
		path->pkey_indx = qp_attr->alt_pkey_index;
		path->local_ack_timeout = qp_attr->alt_timeout;
		path->port = qp_attr->alt_port_num - 1;
		sif_log(sdev, SIF_QP, "Alternate pkey_indx %d local_ack_timeout %d, port %d",
			qp_attr->alt_pkey_index, qp_attr->alt_timeout, qp_attr->alt_port_num + 1);
	} else {
		ctrl_attr->prim_path = 1;
		/* TBD: Does this belong here? */
		ctrl_attr->pkey_index = 1;
		path = &mct->data.primary_path;
		ah_attr = &qp_attr->ah_attr;
		path->pkey_indx = qp->pkey_index;
		/* Use the value set by IB_QP_PORT: */
		path->port = qp->port - 1;
		sif_log(sdev, SIF_QP, "Primary pkey_indx %d local_ack_timeout %d, port %d",
			qp_attr->pkey_index, qp_attr->timeout, qp_attr->port_num + 1);
	}
	path->sl = ah_attr->sl;
	path->remote_lid = ah_attr->dlid;
	path->local_lid_path = ah_attr->src_path_bits;

	path->loopback =
		(sdev->port[path->port].lid | path->local_lid_path) == ah_attr->dlid ?
		LOOPBACK : NO_LOOPBACK;

	/* sif_calc_ipd do not set ipd if sif_calc_ipd failed. In that case, ipd = 0.*/
	sif_calc_ipd(sdev, qp->port, (enum ib_rate) ah_attr->static_rate, &ipd);
	path->ipd = ipd;

	if (ah_attr->ah_flags & IB_AH_GRH) {
		path->use_grh = USE_GRH;
		path->remote_gid_0 = cpu_to_be64(ah_attr->grh.dgid.global.subnet_prefix);
		path->remote_gid_1 = cpu_to_be64(ah_attr->grh.dgid.global.interface_id);
		path->flowlabel = ah_attr->grh.flow_label;
		path->hoplmt = ah_attr->grh.hop_limit;
		/* TBD: ah_attr->grh.sgid_index? */

		sif_log(sdev, SIF_QP, " - with grh dgid %llx.%llx",
			ah_attr->grh.dgid.global.subnet_prefix,
			ah_attr->grh.dgid.global.interface_id);
	}

	if (qp_attr_mask & IB_QP_TIMEOUT) {
		path->local_ack_timeout = qp_attr->timeout;
		sif_log(sdev, SIF_QP, " - with timeout %d", qp_attr->timeout);
	}

	sif_log(sdev, SIF_QP, "local_lid_path %d, remote_lid %d %s, QP(ipd):%d %s",
		path->local_lid_path, path->remote_lid, (path->loopback ? "(loopback)" : ""),
		path->ipd, (alternate ? "(alternate)" : ""));
}

static int modify_qp_hw(struct sif_dev *sdev, struct sif_qp *qp,
		 struct ib_qp_attr *qp_attr, int qp_attr_mask)
{
	struct psif_epsc_csr_rsp resp;
	struct psif_epsc_csr_req req;
	struct psif_epsc_csr_modify_qp *mct = &req.u.modify_qp;
	struct psif_csr_modify_qp_ctrl *ctrl_attr = &mct->ctrl;
	struct psif_csr_modify_qp_ctrl *cmd = &mct->ctrl;
	int ret = 0;

	memset(&req, 0, sizeof(req));

	req.opcode = EPSC_MODIFY_QP;

	cmd->cmd = QP_CMD_MODIFY;

	if (qp->qp_idx <= 3) {
		/* sif requires "real" QP numbers in modify_qp */
		cmd->qp_num = qp->qp_idx & 1;
		cmd->port_num = qp->qp_idx >> 1;
	} else
		cmd->qp_num = qp->qp_idx;

	if (qp_attr_mask & IB_QP_STATE) {
		ctrl_attr->qp_state = 1;
		mct->data.state = ib2sif_qp_state(qp_attr->qp_state);
	}

	if (qp->last_set_state == IB_QPS_INIT && qp_attr->qp_state == IB_QPS_RTR) {
		/* Bug #3933 - WA for HW bug 3928
		 * QP hw state must be set to INIT before modify_qp_hw to RTR
		 */
		volatile struct psif_qp *qps;

		qps = &qp->d;
		set_psif_qp_core__state(&qps->state, PSIF_QP_STATE_INIT);

		/* For INIT -> RTR the rest of the attrs are set directly in the descriptor: */
		ret = modify_qp_sw(sdev, qp, qp_attr, qp_attr_mask & ~IB_QP_STATE);

		/* Flag to the FW that this is the PQP */
		if (qp->type == PSIF_QP_TRANSPORT_MANSP1)
			req.flags |= EPSC_FL_PQP;
		if (ret)
			goto err_modify_qp;
		else
			goto ok_modify_qp_sw;
	}

	if (qp_attr_mask & IB_QP_CUR_STATE) {
		ctrl_attr->use_current_state = 1;
		cmd->current_state = ib2sif_qp_state(qp_attr->cur_qp_state);

		/* TBD: Remove this sanity check later: */
		if (qp_attr->cur_qp_state != qp->last_set_state)
			sif_log(sdev, SIF_QP,
				"** WARNING: possible state inconsistency (user %d, driver %d)",
				qp->last_set_state, qp_attr->cur_qp_state);
	}

	if (qp_attr_mask & IB_QP_EN_SQD_ASYNC_NOTIFY) {
		/* TBD: Needed? */
		sif_log(sdev, SIF_QP,
			"IB_QP_EN_SQD_ASYNC_NOTIFY needed!");
		goto err_modify_qp;
	}

	if (qp_attr_mask & IB_QP_ACCESS_FLAGS) {
		/* TBD: qp_rcv_cap must be set and the whole struct psif_qp_rcv_cap
		 * must be set if any of it's values are modified..
		 * - must keep driver copies of this
		 */

		/* TBD: (qp_attr->qp_access_flags & IB_ACCESS_LOCAL_WRITE) ? 1 : 0; ? */
		mct->data.rdma_rd_enable =
			(qp_attr->qp_access_flags & IB_ACCESS_REMOTE_READ) ? 1 : 0;
		mct->data.rdma_wr_enable =
			(qp_attr->qp_access_flags & IB_ACCESS_REMOTE_WRITE) ? 1 : 0;
		mct->data.atomic_enable =
			(qp_attr->qp_access_flags & IB_ACCESS_REMOTE_ATOMIC) ? 1 : 0;
		/* IB_ACCESS_MW_BIND not supported (?) */
	}

	/* This section must be before IB_QP_AV */
	if (qp_attr_mask & IB_QP_PKEY_INDEX) {
		/* TBD: Argument check on index value ? */
		qp->pkey_index = qp_attr->pkey_index;
	}

	/* This section must be before IB_QP_AV */
	if (qp_attr_mask & IB_QP_PORT) {
		if (qp_attr->port_num < 1 || qp_attr->port_num > 2) {
			sif_log(sdev, SIF_INFO, "Modify port: Illegal port %d specified for qp %d",
				qp_attr->port_num, qp->qp_idx);
			ret = -EINVAL;
			goto err_modify_qp;
		}
		sif_log(sdev, SIF_QP, "Modify port to %d for qp %d",
			qp_attr->port_num, qp->qp_idx);
		qp->port = qp_attr->port_num;
	}

	if (qp_attr_mask & IB_QP_QKEY) {
		ctrl_attr->qkey = 1;
		mct->data.rx_qkey = qp_attr->qkey;

		sif_log(sdev, SIF_QP, "Assign QKEY 0x%x for qp %d",
			qp_attr->qkey, qp->qp_idx);

	}

	if (qp_attr_mask & IB_QP_AV)
		set_qp_path_hw(qp, mct, qp_attr, qp_attr_mask, false);

	if (qp_attr_mask & IB_QP_PATH_MTU) {
		if (!ib_legal_path_mtu(qp_attr->path_mtu)) {
			sif_log(sdev, SIF_INFO, "Illegal MTU encoding %d", qp_attr->path_mtu);
			ret = EINVAL;
			goto err_modify_qp;
		}
		ctrl_attr->path_mtu = 1;
		if ((qp->type == PSIF_QP_TRANSPORT_RC) && sif_feature(force_rc_2048_mtu)) {
			if (qp_attr->path_mtu > IB_MTU_2048)
				qp_attr->path_mtu = IB_MTU_2048;
		}
		mct->data.path_mtu = ib2sif_path_mtu(qp_attr->path_mtu);
		qp->mtu = qp_attr->path_mtu;
	}

	if (qp_attr_mask & IB_QP_TIMEOUT) {
		ctrl_attr->local_ack_timeout = 1;
		if (!(qp_attr_mask & (IB_QP_AV|IB_QP_ALT_PATH)))
			mct->data.primary_path.local_ack_timeout = qp_attr->timeout;
	}

	if (qp_attr_mask & IB_QP_RETRY_CNT) {
		ctrl_attr->error_retry_count = 1;
		mct->data.error_retry_count = qp_attr->retry_cnt;
	}

	if (qp_attr_mask & IB_QP_RNR_RETRY) {
		ctrl_attr->rnr_retry_count = 1;
		mct->data.rnr_retry_count = qp_attr->rnr_retry;
	}

	if (qp_attr_mask & IB_QP_RQ_PSN) {
		/* expected receive PSN */
		ctrl_attr->expected_psn = 1;
		mct->data.expected_psn = qp_attr->rq_psn;
	}

	if (qp_attr_mask & IB_QP_MAX_QP_RD_ATOMIC) {
		/* This is the sending side */
		ctrl_attr->max_outstanding = 1;
		if (qp_attr->max_rd_atomic == 0) {
			sif_log(sdev, SIF_QP,
				"IB_QP_MAX_QP_RD_ATOMIC value 0 incrementing to 1");
			qp_attr->max_rd_atomic = 1;
		}
		if (qp_attr->max_rd_atomic > 16 || qp_attr->max_rd_atomic < 0) {
			/* As per IBTA 9.4.4 & 11.2.4.2 */
			sif_log(sdev, SIF_INFO,
				"IB_QP_MAX_QP_RD_ATOMIC value %u out of range",
				qp_attr->max_rd_atomic);
			ret = -EINVAL;
			goto err_modify_qp;
		}
		mct->data.max_outstanding = qp_attr->max_rd_atomic;
	}

	if (qp_attr_mask & IB_QP_ALT_PATH) {
		if (qp_attr->alt_port_num < 1 || qp_attr->alt_port_num > 2) {
			sif_log(sdev, SIF_INFO, "Illegal alternate port %d specified for qp %d",
				qp_attr->alt_port_num, qp->qp_idx);
			ret = -EINVAL;
			goto err_modify_qp;
		}
		set_qp_path_hw(qp, mct, qp_attr, qp_attr_mask, true);
	}

	if (qp_attr_mask & IB_QP_MIN_RNR_TIMER) {
		ctrl_attr->min_rnr_nak_time = 1;
		mct->data.min_rnr_nak_time = sif_feature(force_wa_3646) ?
			bug_3646_conv_table[qp_attr->min_rnr_timer & 0x1F] :
			qp_attr->min_rnr_timer & 0x1F;
	}

	if (qp_attr_mask & IB_QP_SQ_PSN) {
		/* Send packet sequence number */
		ctrl_attr->xmit_psn = 1;
		mct->data.xmit_psn = qp_attr->sq_psn;
	}

	if (qp_attr_mask & IB_QP_MAX_DEST_RD_ATOMIC) {
		/* Currently hard coded to 16 in psif */
		if (unlikely(qp_attr->max_dest_rd_atomic > 16)) {
			sif_log(sdev, SIF_QP,
				"IB_QP_MAX_DEST_RD_ATOMIC value %u out of range - psif supports 16 as a hard coded value",
				qp_attr->max_dest_rd_atomic);
			goto err_modify_qp;
		} else if (qp_attr->max_dest_rd_atomic < 16) {
			sif_log(sdev, SIF_QP,
				"IB_QP_MAX_DEST_RD_ATOMIC value %u ignored - psif supports 16 as a hard coded value",
				qp_attr->max_dest_rd_atomic);
		}
	}

	if (qp_attr_mask & IB_QP_PATH_MIG_STATE) {
		ctrl_attr->mig_state = 1;
		mct->data.mstate = ib2sif_mig_state(qp_attr->path_mig_state);
	}

	if (qp_attr_mask & IB_QP_CAP) {
		sif_log(sdev, SIF_QP, "IB_QP_CAP not supported by PSIF");
		goto err_modify_qp;
	}

	if (qp_attr_mask & IB_QP_DEST_QPN) {
		/* Since this is only valid from the init state which is
		 * owned by software anyway, we set it directly from software
		 * (see issues #929, #1027)
		 */
		qp->remote_qp = qp_attr->dest_qp_num;
		set_psif_qp_core__remote_qp(&qp->d.state, qp_attr->dest_qp_num);
		sif_log(sdev, SIF_QP, "Modified remote qp (hw), qp_idx: %d, value %d\n",
		    qp->qp_idx, qp_attr->dest_qp_num);
	}

	/* PSIF requires additional attributes to transition XRC-QP to RTS */
	if (is_xrc_qp(qp) && qp_attr->qp_state == IB_QPS_RTS) {
		ctrl_attr->error_retry_count = 1;
		mct->data.error_retry_count = 7;
		ctrl_attr->rnr_retry_count = 1;
		mct->data.rnr_retry_count = 7;
		ctrl_attr->max_outstanding = 1;
		mct->data.max_outstanding = 16;
	}

ok_modify_qp_sw:

	/*
	 * On modify to RTR, we set the TSU SL (tsl), because we have
	 * port # and sl present in the QP state at this point.
	 */
	if ((qp_attr_mask & IB_QP_STATE) && (qp_attr->qp_state == IB_QPS_RTR)) {
		int sl = get_psif_qp_path__sl(&qp->d.path_a);
		int port = qp->port - 1;
		enum psif_tsu_qos qosl = qp->qosl;

		if (cmd->qp_num == 0)
			qp->tsl = sdev->qp0_tsl[qp->port - 1];
		else if (qp->type == PSIF_QP_TRANSPORT_MANSP1)
			qp->tsl = sdev->pqp_rcn_tsl[qp->port - 1];
		else
			qp->tsl = sdev->sl2tsl[sl][port][(int)qosl];

		set_psif_qp_core__tsl(&qp->d.state, qp->tsl);

		/* Tell user-lib about tsl to use */
		if (qp->flags & SIF_QPF_USER_MODE) {
			struct sif_sq_sw *sq_sw = get_sif_sq_sw(sdev, qp->qp_idx);

			sq_sw->tsl = qp->tsl;
		}

		sif_log(sdev, SIF_TSL,
			"%s qp_idx: %d with sl: %d, port: %d, qosl: %s tsl: %d",
			qp->type == PSIF_QP_TRANSPORT_MANSP1 ? "privileged" : "regular",
			qp->qp_idx, sl, qp->port, string_enum_psif_tsu_qos(qosl) + 5, qp->tsl);
	}

	{
		struct sif_eps_cqe lcqe;
		u16 seq_num;

		lcqe.rsp = &resp;
		init_completion(&lcqe.cmpl);

		ret = sif_post_epsc_wr(sdev, &req, &seq_num, &lcqe, true);
		if (ret)
			goto err_modify_qp;

		if (!is_xtgt_qp(qp) && is_reliable_qp(qp->type) && (qp_attr_mask & IB_QP_STATE)) {
			if ((qp->last_set_state == IB_QPS_INIT) && (qp_attr->qp_state == IB_QPS_RTR)) {
				/* Map the new send queue into the global sq_cmpl PSIF
				 * only address map, see #944
				 */
				ret = sif_sq_cmpl_map_sq(sdev, get_sif_sq(sdev, qp->qp_idx));
				if (ret)
					goto err_modify_qp;

				qp->sq_cmpl_map_valid = true;

			} else if ((qp->sq_cmpl_map_valid) && (qp_attr->qp_state == IB_QPS_RESET)) {
				/* Unmap the send queue from the global sq_cmpl PSIF */
				ret = sif_sq_cmpl_unmap_sq(sdev, get_sif_sq(sdev, qp->qp_idx));
				if (ret)
					goto err_modify_qp;

				qp->sq_cmpl_map_valid = false;
			}
		}

		ret = sif_epsc_waitfor(sdev, seq_num, &lcqe);
		if (ret)
			goto err_modify_qp;
	}

	if (resp.status != EPSC_SUCCESS) {
		sif_log(sdev, SIF_INFO, "qp %d failed with status %s",
			qp->qp_idx, string_enum_psif_epsc_csr_status(resp.status));
		goto err_modify_qp;
	}

	/* sif_logs(SIF_DUMP, write_struct_psif_qp(0, 1, (const struct psif_qp *)&qp->d)); */
	sif_log(sdev, SIF_QP, "qp %d done QP state %d -> %d",
		qp->qp_idx, qp->last_set_state,
		(qp_attr_mask & IB_QP_STATE ? qp_attr->qp_state : qp->last_set_state));

	if (qp_attr_mask & IB_QP_STATE)
		qp->last_set_state = qp_attr->qp_state;

	return ret;

err_modify_qp:
	if (resp.status == EPSC_MODIFY_INVALID_QP_STATE)
		ret = -ESPIPE;

	if (!ret)
		ret = -EINVAL;
	if (qp_attr_mask & IB_QP_STATE)
		sif_log(sdev, SIF_QPE,
			"qp %d failed - mask 0x%x cur.state %d, requested state %d, ret %d",
			qp->qp_idx, qp_attr_mask, qp->last_set_state,
			qp_attr->qp_state,
			ret);
	else
		sif_log(sdev, SIF_QPE, "qp %d failed - mask 0x%x no state trans requested, ret %d",
			qp->qp_idx, qp_attr_mask, ret);

	sif_logs(SIF_DUMP, write_struct_psif_qp(NULL, 1, (const struct psif_qp *)&qp->d));
	return ret;
}


static void set_qp_path_sw(struct sif_qp *qp, struct ib_qp_attr *qp_attr,
			int qp_attr_mask, bool alternate)
{
	volatile struct psif_qp_path *path;
	struct ib_ah_attr *ah_attr;
	struct sif_dev *sdev = to_sdev(qp->ibqp.device);
	unsigned int local_lid_path;
	u8 psif_port;
	u8 ipd = 0;

	if (alternate) {
		path =  &qp->d.path_b;
		ah_attr = &qp_attr->alt_ah_attr;
		set_psif_qp_path__pkey_indx(path, qp_attr->alt_pkey_index);
		set_psif_qp_path__local_ack_timeout(path, qp_attr->alt_timeout);
		set_psif_qp_path__port(path, qp_attr->alt_port_num - 1);
	} else {
		path = &qp->d.path_a;
		ah_attr = &qp_attr->ah_attr;
		set_psif_qp_path__pkey_indx(path, qp->pkey_index);
		/* Use the value set by IB_QP_PORT: */
		set_psif_qp_path__port(path, qp->port - 1);
	}
	set_psif_qp_path__sl(path, ah_attr->sl);

	if (ah_attr->ah_flags & IB_AH_GRH) {
		set_psif_qp_path__use_grh(path, USE_GRH);
		set_psif_qp_path__remote_gid_0(path, cpu_to_be64(ah_attr->grh.dgid.global.subnet_prefix));
		set_psif_qp_path__remote_gid_1(path, cpu_to_be64(ah_attr->grh.dgid.global.interface_id));
		set_psif_qp_path__flowlabel(path, ah_attr->grh.flow_label);
		set_psif_qp_path__hoplmt(path, ah_attr->grh.hop_limit);
		/* TBD: ah_attr->grh.sgid_index? */

		sif_log(sdev, SIF_QP, " - with grh dgid %llx.%llx",
			be64_to_cpu(path->remote_gid_0),
			be64_to_cpu(path->remote_gid_1));
	}

	if (qp_attr_mask & IB_QP_TIMEOUT) {
		set_psif_qp_path__local_ack_timeout(path, qp_attr->timeout);
		sif_log(sdev, SIF_QP, " - with timeout %d", qp_attr->timeout);
	}

	qp->remote_lid = ah_attr->dlid;
	set_psif_qp_path__remote_lid(path, ah_attr->dlid);
	local_lid_path = ah_attr->src_path_bits;
	psif_port = get_psif_qp_path__port(path);
	set_psif_qp_path__local_lid_path(path, local_lid_path);
	set_psif_qp_path__loopback(path,
		(sdev->port[psif_port].lid | local_lid_path) == ah_attr->dlid ?
		LOOPBACK : NO_LOOPBACK);

	/* sif_calc_ipd do not set ipd if sif_calc_ipd failed. In that case, ipd = 0.*/
	sif_calc_ipd(sdev, qp->port, (enum ib_rate) ah_attr->static_rate, &ipd);
	set_psif_qp_path__ipd(path, ipd);

	sif_log(sdev, SIF_QP, "port %d lid %d(%#x) local_lid_path %d(%#x) remote_lid %d(%#x)",
		ah_attr->port_num,
		sdev->port[psif_port].lid,
		sdev->port[psif_port].lid,
		ah_attr->src_path_bits,
		ah_attr->src_path_bits,
		ah_attr->dlid,
		ah_attr->dlid);

	sif_log(sdev, SIF_QP, "(path_%c) psif_port %d, remote_lid %d(%#x) %s",
		(alternate ? 'b' : 'a'),
		psif_port,
		get_psif_qp_path__remote_lid(path), get_psif_qp_path__remote_lid(path),
		(get_psif_qp_path__loopback(path) == LOOPBACK ? "(loopback)" : "(not loopback)"));
}

static int modify_qp_sw(struct sif_dev *sdev, struct sif_qp *qp,
		 struct ib_qp_attr *qp_attr, int qp_attr_mask)
{
	int ret = 0;
	volatile struct psif_qp *qps;
	struct sif_rq *rq = NULL;

	if (qp->rq_idx >= 0)
		rq = get_sif_rq(sdev, qp->rq_idx);

	qps = &qp->d;

	if ((qp_attr_mask & IB_QP_STATE)
		&& (qp->last_set_state == IB_QPS_RESET)
		&& (qp_attr->qp_state == IB_QPS_INIT)) {
		set_psif_qp_core__bytes_received(&qps->state, 0);
		set_psif_qp_core__committed_received_psn(&qps->state, 0);
		set_psif_qp_core__expected_psn(&qps->state, 0);
		set_psif_qp_core__last_committed_msn(&qps->state, 0);
		set_psif_qp_core__last_received_outstanding_msn(&qps->state, 0);
		set_psif_qp_core__msn(&qps->state, 0); /* According to Brian 11.9.2012 */
		set_psif_qp_core__scatter_indx(&qps->state, 0);
		set_psif_qp_core__spin_hit(&qps->state, 0);
		set_psif_qp_core__sq_seq(&qps->state, 1);
		set_psif_qp_core__srq_pd(&qps->state, 0);
	}

	if (qp_attr_mask & IB_QP_CUR_STATE && qp_attr->cur_qp_state != qp->last_set_state) {
		sif_log(sdev, SIF_INFO,
			"Error: current state %d - user expected %d",
			qp->last_set_state, qp_attr->cur_qp_state);
		ret = -EINVAL;
		goto err_modify_qp;
	}

	/* Bug #3933 - WA for HW bug 3928
	 * ibv_query_qp might report wrong state when in state IBV_QPS_ERR
	 * QP hw state keeps in RESET for modify_qp_sw to INIT or ERR states
	 */
	if (qp_attr_mask & IB_QP_STATE)
		if ((qp_attr->qp_state != IB_QPS_INIT && qp_attr->qp_state != IB_QPS_ERR)
			|| (PSIF_REVISION(sdev) > 3))
			set_psif_qp_core__state(&qps->state, ib2sif_qp_state(qp_attr->qp_state));

	if (qp_attr_mask & IB_QP_EN_SQD_ASYNC_NOTIFY) {
		sif_log(sdev, SIF_INFO,
			"IB_QP_EN_SQD_ASYNC_NOTIFY needed!");
		ret = -EINVAL;
		goto err_modify_qp;
	}

	if (qp_attr_mask & IB_QP_ACCESS_FLAGS) {

		set_psif_qp_core__rdma_rd_enable(&qps->state,
			((qp_attr->qp_access_flags & IB_ACCESS_REMOTE_READ)
				? 1 : 0));
		set_psif_qp_core__rdma_wr_enable(&qps->state,
			((qp_attr->qp_access_flags & IB_ACCESS_REMOTE_WRITE)
				? 1 : 0));
		set_psif_qp_core__atomic_enable(&qps->state,
			((qp_attr->qp_access_flags & IB_ACCESS_REMOTE_ATOMIC)
				? 1 : 0));
	}

	/* This section must be before IB_QP_AV */
	if (qp_attr_mask & IB_QP_PKEY_INDEX) {
		volatile struct psif_qp_path *path =  &qp->d.path_a;

		/* TBD: Argument check on index value ? */
		qp->pkey_index = qp_attr->pkey_index;
		set_psif_qp_path__pkey_indx(path, qp->pkey_index);
		sif_log(sdev, SIF_QP, "pkey_indx in primary path set to %d", qp->pkey_index);

	}

	/* This section must be before IB_QP_AV */
	if (qp_attr_mask & IB_QP_PORT) {
		if (qp_attr->port_num < 1 || qp_attr->port_num > 2) {
			sif_log(sdev, SIF_INFO, "Modify port: Illegal port %d specified for qp %d",
				qp_attr->port_num, qp->qp_idx);
			ret = -EINVAL;
			goto err_modify_qp;
		}
		sif_log(sdev, SIF_QP, "Modify port to %d for qp %d",
			qp_attr->port_num, qp->qp_idx);
		qp->port = qp_attr->port_num;
	}

	if (qp_attr_mask & IB_QP_QKEY) {

		/* Set the 'ipoib' and 'ipoib_enable' fields for UD QPs with the IPoIB QKey */
		/* TBD: The IPoIB QKEY value is hardcoded. We need to figured out how ask the
		 * driver to ask the FW for this value
		 */
		if (qp_attr->qkey == 0x00000b1b) {
			set_psif_qp_core__ipoib(&qps->state, 1);
			set_psif_qp_core__ipoib_enable(&qps->state, 1);
		}

		set_psif_qp_core__qkey(&qps->state, qp_attr->qkey);

		sif_log(sdev, SIF_QP, "Assign QKEY 0x%x for qp %d",
			qp_attr->qkey, qp->qp_idx);
	}

	if (qp_attr_mask & IB_QP_AV)
		set_qp_path_sw(qp, qp_attr, qp_attr_mask, false);

	if (qp_attr_mask & IB_QP_PATH_MTU) {
		if (!ib_legal_path_mtu(qp_attr->path_mtu)) {
			sif_log(sdev, SIF_INFO, "Illegal MTU encoding %d", qp_attr->path_mtu);
			ret = EINVAL;
			goto err_modify_qp;
		}
		if ((qp->type == PSIF_QP_TRANSPORT_RC) && sif_feature(force_rc_2048_mtu)) {
			if (qp_attr->path_mtu > IB_MTU_2048)
				qp_attr->path_mtu = IB_MTU_2048;
		}
		sif_log(sdev, SIF_QP, "Modify path_mtu to %d for qp %d",
			qp_attr->path_mtu, qp->qp_idx);
		set_psif_qp_core__path_mtu(&qps->state,
			ib2sif_path_mtu(qp_attr->path_mtu));
		qp->mtu = qp_attr->path_mtu;
	}

	if (!(qp_attr_mask & (IB_QP_AV|IB_QP_ALT_PATH))) {
		/* Set these values also if a path does not get set */
		if (qp_attr_mask & IB_QP_TIMEOUT)
			set_psif_qp_path__local_ack_timeout(&qps->path_a, qp_attr->timeout);
	}

	if (qp_attr_mask & IB_QP_RETRY_CNT) {
		set_psif_qp_core__error_retry_init(&qps->state, qp_attr->retry_cnt);
		set_psif_qp_core__error_retry_count(&qps->state, qp_attr->retry_cnt);
	}

	if (qp_attr_mask & IB_QP_RNR_RETRY) {
		int rnr_value = qp_attr->retry_cnt;

		set_psif_qp_core__rnr_retry_init(&qps->state, rnr_value);
		set_psif_qp_core__rnr_retry_count(&qps->state, qp_attr->rnr_retry);
	}

	if (qp_attr_mask & IB_QP_RQ_PSN)
		set_psif_qp_core__expected_psn(&qps->state, qp_attr->rq_psn);

	if (qp_attr_mask & IB_QP_MAX_QP_RD_ATOMIC) {
		/* This is the sending side */
		if (unlikely(qp_attr->max_rd_atomic > 16)) {
			sif_log(sdev, SIF_QP,
				"IB_QP_MAX_QP_RD_ATOMIC value %u out of range - psif supports no more than 16",
				qp_attr->max_rd_atomic);
			qp_attr->max_rd_atomic = 16;
		}
		set_psif_qp_core__max_outstanding(&qps->state, qp_attr->max_rd_atomic);
	}

	if (qp_attr_mask & IB_QP_ALT_PATH) {
		if (qp_attr->alt_port_num < 1 || qp_attr->alt_port_num > 2) {
			sif_log(sdev, SIF_INFO, "Illegal alternate port %d specified for qp %d",
				qp_attr->alt_port_num, qp->qp_idx);
			ret = -EINVAL;
			goto err_modify_qp;
		}
		set_qp_path_sw(qp, qp_attr, qp_attr_mask, true);
	}

	if (qp_attr_mask & IB_QP_MIN_RNR_TIMER)
		set_psif_qp_core__min_rnr_nak_time(&qps->state,
			bug_3646_conv_table[qp_attr->min_rnr_timer & 0x1F]);

	if (qp_attr_mask & IB_QP_SQ_PSN) {
		/* last_acked_psn must be 1 less (modulo 24 bit) than xmit_psn
		 * (see issue #1011)
		 */
		u32 prev = qp_attr->sq_psn == 0 ? 0xFFFFFF : qp_attr->sq_psn - 1;

		set_psif_qp_core__xmit_psn(&qps->state, qp_attr->sq_psn);
		set_psif_qp_core__last_acked_psn(&qps->state, prev);
	}

	if (qp_attr_mask & IB_QP_MAX_DEST_RD_ATOMIC) {
		/* Currently hard coded to 16 in psif */
		if (unlikely(qp_attr->max_dest_rd_atomic > 16)) {
			sif_log(sdev, SIF_INFO,
				"IB_QP_MAX_DEST_RD_ATOMIC value %u out of range - psif supports 16 as a hard coded value",
				qp_attr->max_dest_rd_atomic);
			ret = -EINVAL;
			goto err_modify_qp;
		} else if (qp_attr->max_dest_rd_atomic < 16) {
			sif_log(sdev, SIF_QP,
				"IB_QP_MAX_DEST_RD_ATOMIC value %u ignored - psif supports 16 as a hard coded value",
				qp_attr->max_dest_rd_atomic);
		}
	}

	if (qp_attr_mask & IB_QP_PATH_MIG_STATE)
		set_psif_qp_core__mstate(&qps->state,
			ib2sif_mig_state(qp_attr->path_mig_state));

	if (qp_attr_mask & IB_QP_CAP) {
		sif_log(sdev, SIF_INFO, "resizing QP not implemented");
		sif_log(sdev, SIF_INFO, "IB_QP_CAP needed!");
		ret = -EOPNOTSUPP;
		goto err_modify_qp;
	}

	if (qp_attr_mask & IB_QP_DEST_QPN) {
		set_psif_qp_core__remote_qp(&qps->state, qp_attr->dest_qp_num);
		sif_log(sdev, SIF_QP, "Modified remote qp (sw), local qp_idx: %d, remote_qp %d\n",
		    qp->qp_idx, qp_attr->dest_qp_num);
	}

	/* Set the valid bit whenever we transition to INIT */
	if (rq && !rq->is_srq && qp_attr_mask & IB_QP_STATE && qp_attr->qp_state == IB_QPS_INIT)
		set_psif_rq_hw__valid(&rq->d, 1);

	sif_log(sdev, SIF_QP, "qp %d done QP state %d -> %d",
		qp->qp_idx, qp->last_set_state,
		(qp_attr_mask & IB_QP_STATE ? qp_attr->qp_state : qp->last_set_state));

	if (qp_attr_mask & IB_QP_STATE)
		qp->last_set_state = qp_attr->qp_state;

	return ret;
err_modify_qp:
	return ret;
}


static int sif_query_qp_sw(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr,
		int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr);
static int sif_query_qp_hw(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr,
		int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr);

int sif_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr,
		int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr)
{
	bool use_hw = false;
	struct sif_qp *qp = to_sqp(ibqp);
	struct sif_dev *sdev = to_sdev(ibqp->device);
	int ret;

	/* Take QP lock to avoid any race condition on updates to last_set_state: */
	mutex_lock(&qp->lock);

	sif_logi(ibqp->device, SIF_QP, "last_set_state %d", qp->last_set_state);

	switch (qp->last_set_state) {
	case IB_QPS_RESET:
	case IB_QPS_INIT:
		break;
	default:
		/* Bug #3933 - WA for HW bug 3928
		 * ibv_query_qp might report wrong state when in state IBV_QPS_ERR
		 * Query must be done based on current ownership (towards HW only if HW owned)
		 */
		if (PSIF_REVISION(sdev) <= 3)
			use_hw = (qp->flags & SIF_QPF_HW_OWNED);
		else
			use_hw = true;
		break;
	}

	ret = use_hw ?
		sif_query_qp_hw(ibqp, qp_attr, qp_attr_mask, qp_init_attr) :
		sif_query_qp_sw(ibqp, qp_attr, qp_attr_mask, qp_init_attr);

	mutex_unlock(&qp->lock);

	return ret;

}

static void get_qp_path_sw(struct sif_qp *qp, struct ib_qp_attr *qp_attr, bool alternate)
{
	volatile struct psif_qp_path *path;
	struct ib_ah_attr *ah_attr;
	enum psif_use_grh use_grh;
	volatile struct psif_qp_path *alt_path;
	struct ib_ah_attr *alt_ah_attr;

	alt_path =  &qp->d.path_b;
	alt_ah_attr = &qp_attr->alt_ah_attr;
	path = &qp->d.path_a;
	ah_attr = &qp_attr->ah_attr;

	ah_attr->sl = get_psif_qp_path__sl(path);
	use_grh = get_psif_qp_path__use_grh(path);

	if (use_grh == USE_GRH) {
		ah_attr->ah_flags |= IB_AH_GRH;
		ah_attr->grh.dgid.global.subnet_prefix = get_psif_qp_path__remote_gid_0(path);
		ah_attr->grh.dgid.global.interface_id = get_psif_qp_path__remote_gid_1(path);
		ah_attr->grh.flow_label = get_psif_qp_path__flowlabel(path);
		ah_attr->grh.hop_limit = get_psif_qp_path__hoplmt(path);
		/* TBD: ah_attr->grh.sgid_index? */
	}

	qp_attr->pkey_index = get_psif_qp_path__pkey_indx(path);
	qp_attr->timeout = get_psif_qp_path__local_ack_timeout(path);

	ah_attr->port_num = get_psif_qp_path__port(path);
	ah_attr->dlid =	get_psif_qp_path__remote_lid(path);
	ah_attr->src_path_bits = get_psif_qp_path__local_lid_path(path);

	alt_ah_attr->port_num = get_psif_qp_path__port(alt_path);
	alt_ah_attr->dlid =	get_psif_qp_path__remote_lid(alt_path);
	alt_ah_attr->src_path_bits = get_psif_qp_path__local_lid_path(alt_path);
}



static int sif_query_qp_sw(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr,
		    int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr)
{
	struct sif_dev *sdev = to_sdev(ibqp->device);
	struct sif_qp *qp = to_sqp(ibqp);
	volatile struct psif_qp *qps = &qp->d;
	struct sif_rq *rq = get_rq(sdev, qp);
	struct sif_sq *sq = get_sq(sdev, qp);
	int ret = 0;

	/* Mellanox almost completely ignores the mask on both
	 * input and output and reports all attributes regardlessly..
	 * as opposed to what man ibv_query_qp indicates.
	 * Since this behavour is utilized by a.o. qperf
	 * we probably have no other meaningful choice than
	 * to report back everything even with mask 0.
	 */
	sif_log(sdev, SIF_QP, "qp_attr_mask 0x%x", qp_attr_mask);

	memset(qp_init_attr, 0, sizeof(struct ib_qp_init_attr));
	memset(qp_attr, 0, sizeof(struct ib_qp_attr));

	qp_attr->qp_state = qp_attr->cur_qp_state = qp->last_set_state;
	qp_attr->qp_access_flags |=
		get_psif_qp_core__rdma_rd_enable(&qps->state) ? IB_ACCESS_REMOTE_READ : 0;
	qp_attr->qp_access_flags |=
		get_psif_qp_core__rdma_wr_enable(&qps->state) ? IB_ACCESS_REMOTE_WRITE : 0;
	qp_attr->qp_access_flags |=
		get_psif_qp_core__atomic_enable(&qps->state) ? IB_ACCESS_REMOTE_ATOMIC : 0;

	qp_attr->pkey_index = get_psif_qp_path__pkey_indx(&qps->path_a);
	qp_attr->port_num = qp->port;
	qp_attr->qkey = get_psif_qp_core__qkey(&qps->state);
	get_qp_path_sw(qp, qp_attr, qp_attr_mask & IB_QP_ALT_PATH);

	qp_attr->path_mtu = sif2ib_path_mtu(get_psif_qp_core__path_mtu(&qps->state));
	qp_attr->timeout = get_psif_qp_path__local_ack_timeout(&qps->path_a);
	qp_attr->retry_cnt = get_psif_qp_core__error_retry_count(&qps->state);
	qp_attr->rnr_retry = get_psif_qp_core__rnr_retry_count(&qps->state);
	qp_attr->rq_psn = get_psif_qp_core__expected_psn(&qps->state);
	qp_attr->min_rnr_timer = get_psif_qp_core__min_rnr_nak_time(&qps->state);
	qp_attr->sq_psn = get_psif_qp_core__xmit_psn(&qps->state);
	qp_attr->path_mig_state = sif2ib_mig_state(get_psif_qp_core__mstate(&qps->state));
	qp_attr->dest_qp_num = get_psif_qp_core__remote_qp(&qps->state);

	/* TBD: Revisit this: This value is currently hard coded to 16 in psif */
	qp_attr->max_dest_rd_atomic = 16;

	qp_init_attr->port_num = qp->port;
	if (rq) {
		if (rq->is_srq)
			qp_init_attr->srq = &rq->ibsrq;
		qp_init_attr->cap.max_recv_wr     = rq->entries_user;
		qp_init_attr->cap.max_recv_sge    = rq->sg_entries;
	}

	if (sq) {
		qp_init_attr->cap.max_send_wr     = sq->entries;
		qp_init_attr->cap.max_send_sge    = sq->sg_entries;
	}
	qp_init_attr->cap.max_inline_data = qp->max_inline_data;

	/* TBD: What to do with this:
	 * IB_QP_MAX_QP_RD_ATOMIC		= (1<<13),
	 */
	return ret;
}

static void get_qp_path_hw(struct psif_query_qp *qqp, struct ib_qp_attr *qp_attr, bool alternate)
{
	struct psif_qp_path *path;
	struct ib_ah_attr *ah_attr;
	enum psif_use_grh use_grh;
	struct psif_qp_path *alt_path;
	struct ib_ah_attr *alt_ah_attr;

	alt_path =  &qqp->alternate_path;
	alt_ah_attr = &qp_attr->alt_ah_attr;
	path = &qqp->primary_path;
	ah_attr = &qp_attr->ah_attr;

	ah_attr->sl = path->sl;
	use_grh = path->use_grh;

	if (use_grh == USE_GRH) {
		ah_attr->ah_flags |= IB_AH_GRH;
		ah_attr->grh.dgid.global.subnet_prefix = path->remote_gid_0;
		ah_attr->grh.dgid.global.interface_id = path->remote_gid_1;
		ah_attr->grh.flow_label = path->flowlabel;
		ah_attr->grh.hop_limit = path->hoplmt;
		/* TBD: ah_attr->grh.sgid_index? */
	}
	qp_attr->pkey_index = path->pkey_indx;
	qp_attr->timeout = path->local_ack_timeout;
	qp_attr->port_num = path->port + 1;

	qp_attr->alt_pkey_index = alt_path->pkey_indx;
	qp_attr->alt_timeout = alt_path->local_ack_timeout;
	qp_attr->alt_port_num = alt_path->port + 1;



	ah_attr->port_num = path->port + 1;
	ah_attr->dlid =	path->remote_lid;
	ah_attr->src_path_bits = path->local_lid_path;

	alt_ah_attr->port_num = alt_path->port + 1;
	alt_ah_attr->dlid =	alt_path->remote_lid;
	alt_ah_attr->src_path_bits = alt_path->local_lid_path;
}

u64 sif_qqp_dma_addr(struct sif_dev *sdev, struct sif_qp *qps)
{
	struct sif_table *tp = &sdev->ba[qp];
	u64 offset = qps->qp_idx * tp->ext_sz + offsetof(struct sif_qp, qqp);

	if (tp->mmu_ctx.mt == SIFMT_BYPASS)
		return sif_mem_dma(tp->mem, offset);
	else if (!epsc_gva_permitted(sdev))
		return sif_mem_dma(tp->mem, offset);
	else
		return tp->mmu_ctx.base + offset;
}

/* Internal query qp implementation - updates the local query qp state for this QP */
int epsc_query_qp(struct sif_qp *sqp, struct psif_query_qp *lqqp)
{
	int ret;
	struct psif_epsc_csr_rsp cqe;
	struct psif_epsc_csr_req req;
	struct psif_csr_modify_qp_ctrl *cmd = &req.u.query_qp.ctrl;
	struct sif_dev *sdev = to_sdev(sqp->ibqp.device);

	/* This function can potentially use the same qqp data structure reentrant
	 * but we dont care as we know that EPSC operations gets sequenced
	 */

	memset(&req, 0, sizeof(req));
	req.opcode = EPSC_QUERY_QP;
	cmd->cmd = QP_CMD_QUERY;
	if (sqp->qp_idx <= 3) {
		cmd->qp_num = sqp->qp_idx & 1;
		cmd->port_num = sqp->qp_idx >> 1;
	} else
		cmd->qp_num = sqp->qp_idx;
	req.u.query_qp.address = sif_qqp_dma_addr(sdev, sqp);

	if (!epsc_gva_permitted(sdev))
		req.u.query_qp.mmu_cntx = sif_mmu_ctx_passthrough(true);
	else
		req.u.query_qp.mmu_cntx = sdev->ba[qp].mmu_ctx.mctx;
	ret = sif_epsc_wr_poll(sdev, &req, &cqe);

	/* Copy data irrespective of how the EPSC operation went */
	if (eps_version_ge(&sdev->es[sdev->mbox_epsc], 0, 31))
		copy_conv_to_sw(lqqp, &sqp->qqp, sizeof(*lqqp));
	else
		memcpy(lqqp, &sqp->qqp, sizeof(*lqqp));

	return ret;
}


static int sif_query_qp_hw(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr,
		int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr)
{
	int ret = 0;
	struct sif_qp *qp = to_sqp(ibqp);
	struct sif_dev *sdev = to_sdev(ibqp->device);
	struct sif_rq *rq = get_rq(sdev, qp);
	struct sif_sq *sq = get_sq(sdev, qp);
	struct psif_query_qp lqqp;


	ret = epsc_query_qp(qp, &lqqp);
	if (!ret)
		qp->last_set_state = sif2ib_qp_state(lqqp.qp.state);

	if (ret)
		return ret;

	/* Mellanox almost completely ignores the mask on both
	 * input and output and reports all attributes regardlessly..
	 * as opposed to what man ibv_query_qp indicates.
	 * Since this behavour is utilized by a.o. qperf
	 * we probably have no other meaningful choice than
	 * to report back everything even with mask 0.
	 */
	sif_log(sdev, SIF_QP|SIF_DUMP, "qp %d,  qp_attr_mask 0x%x", qp->qp_idx, qp_attr_mask);
	sif_logs(SIF_DUMP, write_struct_psif_query_qp(NULL, 0, &lqqp));


	memset(qp_init_attr, 0, sizeof(struct ib_qp_init_attr));
	memset(qp_attr, 0, sizeof(struct ib_qp_attr));

	qp_attr->qp_state = qp_attr->cur_qp_state = qp->last_set_state;
	qp_attr->qp_access_flags |= lqqp.qp.rdma_rd_enable ? IB_ACCESS_REMOTE_READ : 0;
	qp_attr->qp_access_flags |= lqqp.qp.rdma_wr_enable ? IB_ACCESS_REMOTE_WRITE : 0;
	qp_attr->qp_access_flags |= lqqp.qp.atomic_enable  ? IB_ACCESS_REMOTE_ATOMIC : 0;

	qp_attr->pkey_index = lqqp.primary_path.pkey_indx;
	qp_attr->port_num = lqqp.primary_path.port + 1;
	qp_attr->qkey = lqqp.qp.qkey;
	get_qp_path_hw(&lqqp, qp_attr, qp_attr_mask & IB_QP_ALT_PATH);

	qp_attr->path_mtu = sif2ib_path_mtu(lqqp.qp.path_mtu);
	qp_attr->timeout = lqqp.primary_path.local_ack_timeout;
	qp_attr->retry_cnt = lqqp.qp.error_retry_count;
	qp_attr->rnr_retry = lqqp.qp.rnr_retry_count;
	qp_attr->rq_psn = lqqp.qp.expected_psn;
	qp_attr->min_rnr_timer = lqqp.qp.min_rnr_nak_time;
	qp_attr->sq_psn = lqqp.qp.xmit_psn;
	qp_attr->path_mig_state = sif2ib_mig_state(lqqp.qp.mstate);
	qp_attr->dest_qp_num = lqqp.qp.remote_qp;

	/* TBD: Revisit this: This value is currently hard coded to 16 in psif */
	qp_attr->max_dest_rd_atomic = 16;

	qp_init_attr->port_num = qp->port; /* TBD: Use primary path info here as well? */

	if (rq) {
		if (rq->is_srq)
			qp_init_attr->srq = &rq->ibsrq;
		qp_init_attr->cap.max_recv_wr     = rq->entries_user;
		qp_init_attr->cap.max_recv_sge    = rq->sg_entries;
	}

	if (sq) {
		qp_init_attr->cap.max_send_wr     = sq->entries;
		qp_init_attr->cap.max_send_sge    = sq->sg_entries;
	}
	qp_init_attr->cap.max_inline_data = qp->max_inline_data;

	/* TBD: What to do with these..
	 * IB_QP_MAX_QP_RD_ATOMIC		= (1<<13),
	 */
	return ret;
}


int sif_destroy_qp(struct ib_qp *ibqp)
{
	struct sif_qp *qp = to_sqp(ibqp);
	struct sif_dev *sdev = to_sdev(ibqp->device);
	struct sif_eps *es = &sdev->es[sdev->mbox_epsc];
	bool need_pma_pxy_qp = eps_version_ge(es, 0, 57)
		&& (qp->qp_idx == 1 || qp->qp_idx == 3);

	sif_log(sdev, SIF_QP, "qp_num %d", ibqp->qp_num);

	/* Destroy PMA_PXY QPs associated with QP1/3 */
	if (need_pma_pxy_qp) {
		struct sif_qp *pma_qp = NULL;
		int pma_qp_idx;
		int ret;

		pma_qp_idx = sdev->pma_qp_idxs[!!(qp->qp_idx & 2)];
		pma_qp = get_sif_qp(sdev, pma_qp_idx);

		/* clearing epsc PMA_PXY QP redirection */
		ret = notify_epsc_pma_qp(sdev, -1, qp->port);
		if (ret)
			sif_log(sdev, SIF_QP,
				"Failed to clear epsc PMA_PXY rerirect for qp_num %d", pma_qp_idx);
		destroy_qp(sdev, pma_qp);
	}

	return destroy_qp(sdev, qp);
}


int destroy_qp(struct sif_dev *sdev, struct sif_qp *qp)
{
	int ret;
	int index = qp->qp_idx;
	struct sif_pd *pd = qp->ibqp.pd ? to_spd(qp->ibqp.pd) : to_sxrcd(qp->ibqp.xrcd)->pd;
	struct ib_qp_attr mod_attr = {
		.qp_state        = IB_QPS_RESET
	};
	struct sif_rq *rq = get_rq(sdev, qp);
	bool reuse_ok = true;

	/* See bug #3496 */
	if (sif_feature(no_multipacket_qp_reuse)) {
		switch (qp->type) {
		case PSIF_QP_TRANSPORT_UD:
		case PSIF_QP_TRANSPORT_MANSP1:
			reuse_ok = true;
			break;
		default:
			reuse_ok = false;
			break;
		}
	}

	sif_log(sdev, SIF_QP, "## Enter qp_idx %d", index);

	/* make sure event handling is performed before reset the qp.*/
	if (atomic_dec_and_test(&qp->refcnt))
		complete(&qp->can_destroy);
	wait_for_completion(&qp->can_destroy);

	/* Modify to reset causes an implicit reset_qp() if state is RESET */
	ret = modify_qp(sdev, qp, &mod_attr, IB_QP_STATE, false, NULL);
	if (ret)
		sif_log(sdev, SIF_INFO, "modify qp %d to RESET failed, sts %d", index, ret);

	if (!(qp->flags & SIF_QPF_USER_MODE)) {
		int nfixup;
		struct sif_sq *sq = get_sq(sdev, qp);
		u32 cq_idx = get_psif_qp_core__rcv_cq_indx(&qp->d.state);
		struct sif_cq *send_cq = (sq && sq->cq_idx >= 0) ? get_sif_cq(sdev, sq->cq_idx) : NULL;
		struct sif_cq *recv_cq = rq ? get_sif_cq(sdev, cq_idx) : NULL;

		if (send_cq) {
			ret = post_process_wa4074(sdev, qp);
			if (ret) {
				sif_log(sdev, SIF_INFO,
					"post_process_wa4074 failed for qp %d send cq %d with error %d",
					qp->qp_idx, sq->cq_idx, ret);
				goto fixup_failed;
			}

			nfixup = sif_fixup_cqes(send_cq, sq, qp);
			if (nfixup < 0) {
				sif_log(sdev, SIF_INFO,
					"fixup cqes on qp %d send cq %d failed with error %d",
					qp->qp_idx, sq->cq_idx, nfixup);
				goto fixup_failed;
			}
			sif_log(sdev, SIF_QP, "fixup cqes fixed %d CQEs in sq.cq %d",
				nfixup, sq->cq_idx);
		}
		if (recv_cq && recv_cq != send_cq) {
			nfixup = sif_fixup_cqes(recv_cq, sq, qp);
			if (nfixup < 0) {
				sif_log(sdev, SIF_INFO,
					"fixup cqes on qp %d recv cq %d failed with error %d",
					qp->qp_idx, cq_idx, nfixup);
				goto fixup_failed;
			}
			sif_log(sdev, SIF_QP, "fixup cqes fixed %d CQEs in rq.cq %d",
				nfixup, cq_idx);

		}
	}

fixup_failed:
	if (qp->qp_idx < 4) {
		/* Special QP cleanup */
		int ok = atomic_add_unless(&sdev->sqp_usecnt[qp->qp_idx], -1, 0);

		if (!ok) {
			sif_log(sdev, SIF_INFO,
				"Attempt to destroy an uncreated QP %d", qp->qp_idx);
			return -EINVAL;
		}
	}

	sif_dfs_remove_qp(qp);

	sif_free_sq(sdev, qp);

	if (rq) {
		if (rq->is_srq)
			atomic_dec(&rq->refcnt);
		else
			ret = free_rq(sdev, qp->rq_idx);
			if (ret && ret != -EBUSY)
				return ret;
	}

	if (index > 3 && reuse_ok)
		sif_free_qp_idx(pd, index);

	sif_log(sdev, SIF_QP, "## Exit success (qp_idx %d)", index);
	return 0;
}

/* Set this QP back to the initial state
 * (called by modify_qp after a successful modify to reset
 */
static int reset_qp(struct sif_dev *sdev, struct sif_qp *qp)
{
	volatile struct psif_qp *qps = &qp->d;
	struct sif_rq *rq = get_rq(sdev, qp);
	struct sif_sq *sq = get_sq(sdev, qp);
	bool need_wa_3714 = 0;

	/* Bring down order needed by rev2 according to bug #3480 */
	int ret = poll_wait_for_qp_writeback(sdev, qp);

	if (ret)
		goto failed;

	/* WA 3714 special handling */
	need_wa_3714 = (PSIF_REVISION(sdev) <= 3)
		&& IS_PSIF(sdev) /* Next check if there is a retry outstanding */
		&& (get_psif_qp_core__retry_tag_committed(&qp->d.state) !=
			get_psif_qp_core__retry_tag_err(&qp->d.state))
		&& (qp->qp_idx != sdev->flush_qp[qp->port - 1]);

	if (need_wa_3714) {
		ret = reset_qp_flush_retry(sdev, qp->port - 1);
		if (ret < 0)
			sif_log(sdev, SIF_INFO,	"Flush_retry special handling failed with ret %d", ret);

	}


	/* if the send queue scheduler is running, wait for
	 * it to terminate:
	 */
	ret = 0;
	if (qp->ibqp.qp_type != IB_QPT_XRC_TGT) {
		ret = sif_flush_sqs(sdev, sq);
		if (ret)
			goto failed;
	}

	sif_logs(SIF_DUMP,
		write_struct_psif_qp(NULL, 1, (struct psif_qp *)&qp->d));

failed:
	if (ret) {
		/* TBD: Debug case - should never fail? */
		if (qp->type != PSIF_QP_TRANSPORT_MANSP1)
			return ret;
	}

	/* Reset the SQ pointers */
	if (!is_xtgt_qp(qp)) {
		struct sif_sq_sw *sq_sw = get_sif_sq_sw(sdev, qp->qp_idx);

		memset(sq_sw, 0, sizeof(*sq_sw));
		set_psif_sq_sw__tail_indx(&sq_sw->d, 0);
		set_psif_sq_hw__last_seq(&sq->d, 0);
		set_psif_sq_hw__destroyed(&sq->d, 0);
	}

	/* Invalidate the RQ and set it in a consistent state for reuse */
	if (rq && !rq->is_srq) {
		struct sif_rq_sw *rq_sw = get_sif_rq_sw(sdev, rq->index);

		if (!(test_bit(RQ_IS_INVALIDATED, &rq_sw->flags))) {
			ret = sif_invalidate_rq_hw(sdev, rq->index, PCM_POST);
			if (ret) {
				sif_log(sdev, SIF_INFO,
					"Invalidate rq_hw failed, status %d", ret);
				return ret;
			}
			set_bit(RQ_IS_INVALIDATED, &rq_sw->flags);
		}

		/* Make sure the RQ is sofware owned: */
		ret = poll_wait_for_rq_writeback(sdev, rq);
		if (ret)
			return ret;

		/* Make sure the in-progress rq flush has
		 * completed before reset the rq tail
		 * and head.
		 */
		if (atomic_dec_and_test(&rq->flush_in_progress))
			complete(&rq->can_reset);
		wait_for_completion(&rq->can_reset);

		/* Reset pointers */
		memset(rq_sw, 0, sizeof(*rq_sw));
		set_psif_rq_hw__head_indx(&rq->d, 0);

		/* reset the flush_in_progress, if the qp is reset
		 * and the qp can be reused again.
		 * Thus, reset the flush_in_progress to 1.
		 */
		atomic_set(&rq->flush_in_progress, 1);
	}

	mb();

	if (multipacket_qp(qp->type) && IS_PSIF(sdev) && PSIF_REVISION(sdev) > 2) {
		int i;
		int loop_count = 1;

		/* bz #3794: WA for HW bug 3198, VAL issuing read to uninitialized DMA VT entry */
		if (qp->type == PSIF_QP_TRANSPORT_UC && PSIF_REVISION(sdev) <= 3)
			loop_count = 64;

		/* Invalidate the SGL cache (mapped to the qp type)
		 * TBD: We can consider a posted inv.req and check lazy upon reuse
		 */

		for (i = 0; i < loop_count; ++i) {
			ret = sif_invalidate_qp(sdev, qp->qp_idx, PCM_WAIT);
			if (ret) {
				sif_log(sdev, SIF_INFO,
					"Invalidate SGL cache failed");
				return ret;
			}
			cpu_relax();
		}
	}

	/* Reset counters to same values used at QP create
	 * Last acked psn must be initialized to one less than xmit_psn
	 * and it is a 24 bit value. See issue #1011
	 */
	set_psif_qp_core__xmit_psn(&qps->state, 0);
	set_psif_qp_core__last_acked_psn(&qps->state, 0xffffff);

	return ret;
}



void sif_dfs_print_qp(struct seq_file *s, struct sif_dev *sdev,
		loff_t pos)
{
	struct sif_qp *qp;
	struct sif_sq *sq;
	struct sif_rq *rq;
	volatile struct psif_qp *qps;
	struct psif_qp lqps;

	if (unlikely(pos < 0)) {
		seq_puts(s, "Index\tState\tRecvCQ\tSendCQ\tRQ\tRemQP\tType\n");
		return;
	}

	qp = get_sif_qp(sdev, pos);
	qps = &qp->d;
	copy_conv_to_sw(&lqps, qps, sizeof(struct psif_qp));

	if (pos <= 3 && atomic_read(&sdev->sqp_usecnt[pos]) != 1)
		return;

	sq = get_sq(sdev, qp);
	rq = get_rq(sdev, qp);

	seq_printf(s, "%llu\t%d\t", pos,	qp->last_set_state);

	if (!rq)
		seq_puts(s, "[none]");
	else
		seq_printf(s, "%u", lqps.state.rcv_cq_indx);

	if (!sq)
		seq_puts(s, "[none]");
	else
		seq_printf(s, "\t%u\t", lqps.state.send_cq_indx);

	if (!rq)
		if (!sq)
			seq_puts(s, "\t[none]");
		else
			seq_puts(s, "[none]");
	else
		seq_printf(s, "%u", lqps.state.rq_indx);

	seq_printf(s, "\t%u", lqps.state.remote_qp);
	seq_printf(s, "\t%s", string_enum_psif_qp_trans(lqps.state.transport_type)+18);
	if (lqps.state.proxy_qp_enable)
		seq_puts(s, "\t[proxy]\n");
	else if (is_epsa_tunneling_qp(qp->ibqp.qp_type))
		seq_puts(s, "\t[EPSA tunneling]\n");
	else if (qp->ulp_type == RDS_ULP)
		seq_puts(s, "\t[RDS]\n");
	else if (qp->ulp_type == IPOIB_CM_ULP)
		seq_puts(s, "\t[IPOIB_CM]\n");
	else if (qp->flags & SIF_QPF_EOIB)
		seq_puts(s, "\t[EoIB]\n");
	else if (qp->flags & SIF_QPF_IPOIB)
		seq_puts(s, "\t[IPoIB]\n");
	else if (qp->flags & SIF_QPF_NO_EVICT)
		seq_puts(s, "\t[no_evict]\n");
	else if (qp->flags & SIF_QPF_FLUSH_RETRY)
		if (qp->port == 1)
			seq_puts(s, "\t[flush_retry_p1]\n");
		else
			seq_puts(s, "\t[flush_retry_p2]\n");
	else if (qp->flags & SIF_QPF_KI_STENCIL)
		seq_puts(s, "\t[ki_stencil]\n");
	else if (qp->flags & SIF_QPF_PMA_PXY)
		if (qp->port == 1)
			seq_puts(s, "\t[PMA_PXY_QP_P1]\n");
		else
			seq_puts(s, "\t[PMA_PXY_QP_P2]\n");
	else if (qp->flags & SIF_QPF_SMI)
		if (qp->port == 1)
			seq_puts(s, "\t[SMI_QP_P1]\n");
		else
			seq_puts(s, "\t[SMI_QP_P2]\n");
	else if (qp->flags & SIF_QPF_GSI)
		if (qp->port == 1)
			seq_puts(s, "\t[GSI_QP_P1]\n");
		else
			seq_puts(s, "\t[GSI_QP_P2]\n");
	else if (qp->ibqp.qp_type == IB_QPT_XRC_TGT)
		seq_puts(s, "\t[RECV]\n");
	else if (qp->ibqp.qp_type == IB_QPT_XRC_INI)
		seq_puts(s, "\t[SEND]\n");
	else
		seq_puts(s, "\n");
}

void sif_dfs_print_ipoffload(struct seq_file *s, struct sif_dev *sdev, loff_t pos)
{
	struct sif_qp *qp;

	if (unlikely(pos < 0)) {
		seq_printf(s, "#%7s %10s %21s %21s %21s\n",
			"", "TX csum", "---- RX l3_csum ----", "---- RX l4_csum ----",
			"-------- LSO --------");
		seq_printf(s, "#%7s %10s %10s %10s %10s %10s %10s %10s\n",
			"Index", "", "ok", "err", "ok", "err", "pkt", "bytes");
		return;
	}

	qp = get_sif_qp(sdev, pos);

	if (qp->flags & SIF_QPF_IPOIB || qp->flags & SIF_QPF_EOIB) {
		if (pos <= 3 && atomic_read(&sdev->sqp_usecnt[pos]) != 1)
			return;

		seq_printf(s, "%8llu ", pos);
		seq_printf(s, "%10llu ",
			qp->ipoib_tx_csum_l3);
		seq_printf(s, "%10llu %10llu ",
			qp->ipoib_rx_csum_l3_ok, qp->ipoib_rx_csum_l3_err);
		seq_printf(s, "%10llu %10llu ",
			qp->ipoib_rx_csum_l4_ok, qp->ipoib_rx_csum_l4_err);
		seq_printf(s, "%10llu %10llu\n",
			qp->ipoib_tx_lso_pkt, qp->ipoib_tx_lso_bytes);
	}
}

bool has_srq(struct sif_dev *sdev, struct sif_qp *qp)
{
	struct sif_rq *rq = has_rq(qp) ? get_sif_rq(sdev, qp->rq_idx) : NULL;

	return rq && rq->is_srq;
}
