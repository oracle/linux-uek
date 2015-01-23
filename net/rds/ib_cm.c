/*
 * Copyright (c) 2006 Oracle.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
#include <linux/kernel.h>
#include <linux/in.h>
#include <linux/vmalloc.h>
#include <linux/version.h>
#include <rdma/rdma_cm_ib.h>
#include <rdma/ib_cache.h>

#include "rds.h"
#include "ib.h"
#include "tcp.h"

static char *rds_ib_event_type_strings[] = {
#define RDS_IB_EVENT_STRING(foo)[IB_EVENT_##foo] = __stringify(foo)
	RDS_IB_EVENT_STRING(CQ_ERR),
	RDS_IB_EVENT_STRING(QP_FATAL),
	RDS_IB_EVENT_STRING(QP_REQ_ERR),
	RDS_IB_EVENT_STRING(QP_ACCESS_ERR),
	RDS_IB_EVENT_STRING(COMM_EST),
	RDS_IB_EVENT_STRING(SQ_DRAINED),
	RDS_IB_EVENT_STRING(PATH_MIG),
	RDS_IB_EVENT_STRING(PATH_MIG_ERR),
	RDS_IB_EVENT_STRING(DEVICE_FATAL),
	RDS_IB_EVENT_STRING(PORT_ACTIVE),
	RDS_IB_EVENT_STRING(PORT_ERR),
	RDS_IB_EVENT_STRING(LID_CHANGE),
	RDS_IB_EVENT_STRING(PKEY_CHANGE),
	RDS_IB_EVENT_STRING(SM_CHANGE),
	RDS_IB_EVENT_STRING(SRQ_ERR),
	RDS_IB_EVENT_STRING(SRQ_LIMIT_REACHED),
	RDS_IB_EVENT_STRING(QP_LAST_WQE_REACHED),
	RDS_IB_EVENT_STRING(CLIENT_REREGISTER),
#undef RDS_IB_EVENT_STRING
};

static char *rds_ib_event_str(enum ib_event_type type)
{
	if (type < ARRAY_SIZE(rds_ib_event_type_strings) &&
	    rds_ib_event_type_strings[type])
		return rds_ib_event_type_strings[type];
	else
		return "unknown";
};

/*
 * Set the selected protocol version
 */
static void rds_ib_set_protocol(struct rds_connection *conn, unsigned int version)
{
	conn->c_version = version;
}

/*
 * Set up flow control
 */
static void rds_ib_set_flow_control(struct rds_connection *conn, u32 credits)
{
	struct rds_ib_connection *ic = conn->c_transport_data;

	if (rds_ib_sysctl_flow_control && credits != 0) {
		/* We're doing flow control */
		ic->i_flowctl = 1;
		rds_ib_send_add_credits(conn, credits);
	} else {
		ic->i_flowctl = 0;
	}
}

/*
 * Tune RNR behavior. Without flow control, we use a rather
 * low timeout, but not the absolute minimum - this should
 * be tunable.
 *
 * We already set the RNR retry count to 7 (which is the
 * smallest infinite number :-) above.
 * If flow control is off, we want to change this back to 0
 * so that we learn quickly when our credit accounting is
 * buggy.
 *
 * Caller passes in a qp_attr pointer - don't waste stack spacv
 * by allocation this twice.
 */
static void
rds_ib_tune_rnr(struct rds_ib_connection *ic, struct ib_qp_attr *attr)
{
	int ret;

	attr->min_rnr_timer = IB_RNR_TIMER_000_32;
	ret = ib_modify_qp(ic->i_cm_id->qp, attr, IB_QP_MIN_RNR_TIMER);
	if (ret)
		printk(KERN_NOTICE "ib_modify_qp(IB_QP_MIN_RNR_TIMER): err=%d\n", -ret);
}

/*
 * Connection established.
 * We get here for both outgoing and incoming connection.
 */
void rds_ib_cm_connect_complete(struct rds_connection *conn, struct rdma_cm_event *event)
{
	const struct rds_ib_connect_private *dp = NULL;
	struct rds_ib_connection *ic = conn->c_transport_data;
	struct ib_qp_attr qp_attr;
	int err;

	if (event->param.conn.private_data_len >= sizeof(*dp)) {
		dp = event->param.conn.private_data;

		/* make sure it isn't empty data */
		if (dp->dp_protocol_major) {
			rds_ib_set_protocol(conn,
				RDS_PROTOCOL(dp->dp_protocol_major,
				dp->dp_protocol_minor));
			rds_ib_set_flow_control(conn, be32_to_cpu(dp->dp_credit));
		}
	}

	if (conn->c_version < RDS_PROTOCOL(3, 2)) {
		if (conn->c_version == RDS_PROTOCOL(3, 1)) {
			if (conn->c_tos) {
				printk(KERN_NOTICE "RDS: Connection to"
					" %pI4 version %u.%u Tos %d"
					" failed, not supporting QoS\n",
					&conn->c_faddr,
					RDS_PROTOCOL_MAJOR(conn->c_version),
					RDS_PROTOCOL_MINOR(conn->c_version),
					conn->c_tos);
				rds_conn_drop(conn);
				return;
			}
		} else {
			/*
			   * BUG: destroying connection here can deadlock with
			   * the CM event handler on the c_cm_lock.
			*/
			printk(KERN_NOTICE "RDS/IB: Connection to"
				" %pI4 version %u.%u failed,"
				" no longer supported\n",
				&conn->c_faddr,
				RDS_PROTOCOL_MAJOR(conn->c_version),
				RDS_PROTOCOL_MINOR(conn->c_version));
			rds_conn_destroy(conn);
			return;
		}
	}

	printk(KERN_NOTICE
		"RDS/IB: connected to %pI4 version %u.%u%s Tos %d\n",
		&conn->c_faddr,
		RDS_PROTOCOL_MAJOR(conn->c_version),
		RDS_PROTOCOL_MINOR(conn->c_version),
		ic->i_flowctl ? ", flow control" : "",
		conn->c_tos);

	ic->i_sl = ic->i_cm_id->route.path_rec->sl;

	/*
	 * Init rings and fill recv. this needs to wait until protocol negotiation
	 * is complete, since ring layout is different from 3.0 to 3.1.
	 */
	rds_ib_send_init_ring(ic);

	if (!rds_ib_srq_enabled)
		rds_ib_recv_init_ring(ic);

	/* Post receive buffers - as a side effect, this will update
	 * the posted credit count. */
	if (!rds_ib_srq_enabled)
		rds_ib_recv_refill(conn, 1, 1);

	/* Tune RNR behavior */
	rds_ib_tune_rnr(ic, &qp_attr);

	qp_attr.qp_state = IB_QPS_RTS;
	err = ib_modify_qp(ic->i_cm_id->qp, &qp_attr, IB_QP_STATE);
	if (err)
		printk(KERN_NOTICE "ib_modify_qp(IB_QP_STATE, RTS): err=%d\n", err);

	/* update ib_device with this local ipaddr */
	err = rds_ib_update_ipaddr(ic->rds_ibdev, conn->c_laddr);
	if (err)
		printk(KERN_ERR "rds_ib_update_ipaddr failed (%d)\n",
			err);

	/* If the peer gave us the last packet it saw, process this as if
	 * we had received a regular ACK. */
	if (dp && dp->dp_ack_seq)
		rds_send_drop_acked(conn, be64_to_cpu(dp->dp_ack_seq), NULL);

	if (rds_ib_apm_enabled && !ic->conn->c_reconnect) {
		memcpy(&ic->i_pri_path.p_sgid,
			&ic->i_cm_id->route.path_rec[0].sgid,
			sizeof(union ib_gid));

		memcpy(&ic->i_pri_path.p_dgid,
			&ic->i_cm_id->route.path_rec[0].dgid,
			sizeof(union ib_gid));

		memcpy(&ic->i_cur_path.p_sgid,
			&ic->i_cm_id->route.path_rec[0].sgid,
			sizeof(union ib_gid));

		memcpy(&ic->i_cur_path.p_dgid,
			&ic->i_cm_id->route.path_rec[0].dgid,
			sizeof(union ib_gid));

		printk(KERN_NOTICE "RDS/IB: connection "
			"<%pI4,%pI4,%d> primary path "
			"<"RDS_IB_GID_FMT","RDS_IB_GID_FMT">\n",
			&conn->c_laddr,
			&conn->c_faddr,
			conn->c_tos,
			RDS_IB_GID_ARG(ic->i_pri_path.p_sgid),
			RDS_IB_GID_ARG(ic->i_pri_path.p_dgid));
	}

	rds_connect_complete(conn);
}

static void rds_ib_cm_fill_conn_param(struct rds_connection *conn,
			struct rdma_conn_param *conn_param,
			struct rds_ib_connect_private *dp,
			u32 protocol_version,
			u32 max_responder_resources,
			u32 max_initiator_depth)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	struct rds_ib_device *rds_ibdev = ic->rds_ibdev;

	memset(conn_param, 0, sizeof(struct rdma_conn_param));

	conn_param->responder_resources =
		min_t(u32, rds_ibdev->max_responder_resources, max_responder_resources);
	conn_param->initiator_depth =
		min_t(u32, rds_ibdev->max_initiator_depth, max_initiator_depth);
	conn_param->retry_count =
		min_t(unsigned int, rds_ib_retry_count, rds_ib_rnr_retry_count);
	conn_param->rnr_retry_count = rds_ib_rnr_retry_count;

	if (dp) {
		memset(dp, 0, sizeof(*dp));
		dp->dp_saddr = conn->c_laddr;
		dp->dp_daddr = conn->c_faddr;
		dp->dp_protocol_major = RDS_PROTOCOL_MAJOR(protocol_version);
		dp->dp_protocol_minor = RDS_PROTOCOL_MINOR(protocol_version);
		dp->dp_protocol_minor_mask = cpu_to_be16(RDS_IB_SUPPORTED_PROTOCOLS);
		dp->dp_ack_seq = rds_ib_piggyb_ack(ic);
		dp->dp_tos = conn->c_tos;

		/* Advertise flow control */
		if (ic->i_flowctl) {
			unsigned int credits;

			credits = IB_GET_POST_CREDITS(atomic_read(&ic->i_credits));
			dp->dp_credit = cpu_to_be32(credits);
			atomic_sub(IB_SET_POST_CREDITS(credits), &ic->i_credits);
		}

		conn_param->private_data = dp;
		conn_param->private_data_len = sizeof(*dp);
	}
}

static void rds_ib_cq_event_handler(struct ib_event *event, void *data)
{
	rdsdebug("event %u (%s) data %p\n",
		 event->event, rds_ib_event_str(event->event), data);
}

static void rds_ib_cq_comp_handler_send(struct ib_cq *cq, void *context)
{
	struct rds_connection *conn = context;
	struct rds_ib_connection *ic = conn->c_transport_data;

	rdsdebug("conn %p cq %p\n", conn, cq);

	rds_ib_stats_inc(s_ib_evt_handler_call);

	tasklet_schedule(&ic->i_stasklet);
}

static void rds_ib_cq_comp_handler_recv(struct ib_cq *cq, void *context)
{
	struct rds_connection *conn = context;
	struct rds_ib_connection *ic = conn->c_transport_data;

	rdsdebug("conn %p cq %p\n", conn, cq);

	rds_ib_stats_inc(s_ib_evt_handler_call);

	tasklet_schedule(&ic->i_rtasklet);
}

static void poll_cq(struct rds_ib_connection *ic, struct ib_cq *cq,
		   struct ib_wc *wcs,
		   struct rds_ib_ack_state *ack_state)
{
	int nr;
	int i;
	struct ib_wc *wc;

	while ((nr = ib_poll_cq(cq, RDS_WC_MAX, wcs)) > 0) {
		for (i = 0; i < nr; i++) {
			wc = wcs + i;
			rdsdebug("wc wr_id 0x%llx status %u byte_len %u imm_data %u\n",
				 (unsigned long long)wc->wr_id, wc->status, wc->byte_len,
				 be32_to_cpu(wc->ex.imm_data));

			if (wc->wr_id & RDS_IB_SEND_OP)
				rds_ib_send_cqe_handler(ic, wc);
			else
				rds_ib_recv_cqe_handler(ic, wc, ack_state);
		}
	}
}

void rds_ib_tasklet_fn_send(unsigned long data)
{
	struct rds_ib_connection *ic = (struct rds_ib_connection *) data;
	struct rds_connection *conn = ic->conn;
	struct rds_ib_ack_state ack_state;

	memset(&ack_state, 0, sizeof(ack_state));
	rds_ib_stats_inc(s_ib_tasklet_call);

	poll_cq(ic, ic->i_scq, ic->i_send_wc, &ack_state);
	ib_req_notify_cq(ic->i_scq, IB_CQ_NEXT_COMP);
	poll_cq(ic, ic->i_scq, ic->i_send_wc, &ack_state);

	if (rds_conn_up(conn) &&
	   (!test_bit(RDS_LL_SEND_FULL, &conn->c_flags) ||
	    test_bit(0, &conn->c_map_queued)))
		rds_send_xmit(ic->conn);
}

void rds_ib_tasklet_fn_recv(unsigned long data)
{
	struct rds_ib_connection *ic = (struct rds_ib_connection *) data;
	struct rds_connection *conn = ic->conn;
	struct rds_ib_ack_state ack_state;
	struct rds_ib_device *rds_ibdev = ic->rds_ibdev;

	BUG_ON(conn->c_tos && !rds_ibdev);

	rds_ib_stats_inc(s_ib_tasklet_call);

	memset(&ack_state, 0, sizeof(ack_state));

	poll_cq(ic, ic->i_rcq, ic->i_recv_wc, &ack_state);
	ib_req_notify_cq(ic->i_rcq, IB_CQ_SOLICITED);
	poll_cq(ic, ic->i_rcq, ic->i_recv_wc, &ack_state);

	if (ack_state.ack_next_valid)
		rds_ib_set_ack(ic, ack_state.ack_next, ack_state.ack_required);
	if (ack_state.ack_recv_valid && ack_state.ack_recv > ic->i_ack_recv) {
		rds_send_drop_acked(conn, ack_state.ack_recv, NULL);
		ic->i_ack_recv = ack_state.ack_recv;
	}
	if (rds_conn_up(conn))
		rds_ib_attempt_ack(ic);

	if (rds_ib_srq_enabled)
		if ((atomic_read(&rds_ibdev->srq->s_num_posted) <
					rds_ib_srq_hwm_refill) &&
			!test_and_set_bit(0, &rds_ibdev->srq->s_refill_gate))
				queue_delayed_work(rds_wq, &rds_ibdev->srq->s_refill_w, 0);
}

static void rds_ib_qp_event_handler(struct ib_event *event, void *data)
{
	struct rds_connection *conn = data;
	struct rds_ib_connection *ic = conn->c_transport_data;

	rdsdebug("conn %p ic %p event %u (%s)\n", conn, ic, event->event,
		 rds_ib_event_str(event->event));

	switch (event->event) {
	case IB_EVENT_COMM_EST:
		rdma_notify(ic->i_cm_id, IB_EVENT_COMM_EST);
		break;
	case IB_EVENT_QP_LAST_WQE_REACHED:
		complete(&ic->i_last_wqe_complete);
		break;
	case IB_EVENT_PATH_MIG:
		memcpy(&ic->i_cur_path.p_sgid,
			&ic->i_cm_id->route.path_rec[ic->i_alt_path_index].sgid,
			sizeof(union ib_gid));

		memcpy(&ic->i_cur_path.p_dgid,
			&ic->i_cm_id->route.path_rec[ic->i_alt_path_index].dgid,
			sizeof(union ib_gid));

		if (!memcmp(&ic->i_pri_path.p_sgid, &ic->i_cur_path.p_sgid,
				sizeof(union ib_gid)) &&
			!memcmp(&ic->i_pri_path.p_dgid, &ic->i_cur_path.p_dgid,
				sizeof(union ib_gid))) {
			printk(KERN_NOTICE
				"RDS/IB: connection "
				"<%pI4,%pI4,%d> migrated back to path "
				"<"RDS_IB_GID_FMT","RDS_IB_GID_FMT">\n",
				&conn->c_laddr,
				&conn->c_faddr,
				conn->c_tos,
				RDS_IB_GID_ARG(ic->i_cur_path.p_sgid),
				RDS_IB_GID_ARG(ic->i_cur_path.p_dgid));
		} else {
			printk(KERN_NOTICE
				"RDS/IB: connection "
				"<%pI4,%pI4,%d> migrated over to path "
				"<"RDS_IB_GID_FMT","RDS_IB_GID_FMT">\n",
				&conn->c_laddr,
				&conn->c_faddr,
				conn->c_tos,
				RDS_IB_GID_ARG(ic->i_cur_path.p_sgid),
				RDS_IB_GID_ARG(ic->i_cur_path.p_dgid));
		}

		break;
	case IB_EVENT_PATH_MIG_ERR:
		rdsdebug("RDS: Path migration error\n");
		break;
	default:
		rdsdebug("Fatal QP Event %u (%s) "
			"- connection %pI4->%pI4, reconnecting\n",
			event->event, rds_ib_event_str(event->event),
			&conn->c_laddr, &conn->c_faddr);
		rds_conn_drop(conn);
		break;
	}
}

static int rds_ib_find_least_loaded_vector(struct rds_ib_device *rds_ibdev)
{
	int i;
	int index = rds_ibdev->dev->num_comp_vectors - 1;
	int min = rds_ibdev->vector_load[rds_ibdev->dev->num_comp_vectors - 1];

#if IB_RDS_CQ_VECTOR_SUPPORTED
	if (!rds_ib_cq_balance_enabled)
		return IB_CQ_VECTOR_LEAST_ATTACHED;
#endif

	for (i = rds_ibdev->dev->num_comp_vectors - 1; i >= 0; i--) {
		if (rds_ibdev->vector_load[i] < min) {
			index = i;
			min = rds_ibdev->vector_load[i];
		}
	}

	rds_ibdev->vector_load[index]++;
	return index;
}

/*
 * This needs to be very careful to not leave IS_ERR pointers around for
 * cleanup to trip over.
 */
static int rds_ib_setup_qp(struct rds_connection *conn)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	struct ib_device *dev = ic->i_cm_id->device;
	struct ib_cq_init_attr cq_attr;
	struct ib_qp_init_attr qp_attr;
	struct rds_ib_device *rds_ibdev;
	int ret;

	/*
	 * It's normal to see a null device if an incoming connection races
	 * with device removal, so we don't print a warning.
	 */
	rds_ibdev = rds_ib_get_client_data(dev);
	if (!rds_ibdev)
		return -EOPNOTSUPP;

	/* add the conn now so that connection establishment has the dev */
	rds_ib_add_conn(rds_ibdev, conn);

	if (rds_ibdev->max_wrs < ic->i_send_ring.w_nr + 1)
		rds_ib_ring_resize(&ic->i_send_ring, rds_ibdev->max_wrs - 1);
	if (rds_ibdev->max_wrs < ic->i_recv_ring.w_nr + 1)
		rds_ib_ring_resize(&ic->i_recv_ring, rds_ibdev->max_wrs - 1);

	/* Protection domain and memory range */
	ic->i_pd = rds_ibdev->pd;
	ic->i_mr = rds_ibdev->mr;

	ic->i_scq_vector = rds_ib_find_least_loaded_vector(rds_ibdev);
	memset(&cq_attr, 0, sizeof(cq_attr));
	cq_attr.cqe = ic->i_send_ring.w_nr + 1;
	cq_attr.comp_vector = ic->i_scq_vector;
	ic->i_scq = ib_create_cq(dev, rds_ib_cq_comp_handler_send,
				 rds_ib_cq_event_handler, conn,
				 &cq_attr);
	if (IS_ERR(ic->i_scq)) {
		ret = PTR_ERR(ic->i_scq);
		ic->i_scq = NULL;
		rdsdebug("ib_create_cq send failed: %d\n", ret);
#if IB_RDS_CQ_VECTOR_SUPPORTED
		if (ic->i_scq_vector != IB_CQ_VECTOR_LEAST_ATTACHED)
			rds_ibdev->vector_load[ic->i_scq_vector]--;
#endif
		goto out;
	}

	ic->i_rcq_vector = rds_ib_find_least_loaded_vector(rds_ibdev);
	memset(&cq_attr, 0, sizeof(cq_attr));
	if (rds_ib_srq_enabled) {
		cq_attr.cqe = rds_ib_srq_max_wr - 1;
		cq_attr.comp_vector = ic->i_rcq_vector;
		ic->i_rcq = ib_create_cq(dev, rds_ib_cq_comp_handler_recv,
					 rds_ib_cq_event_handler, conn,
					 &cq_attr);
	} else {
		cq_attr.cqe = ic->i_recv_ring.w_nr;
		cq_attr.comp_vector = ic->i_rcq_vector;
		ic->i_rcq = ib_create_cq(dev, rds_ib_cq_comp_handler_recv,
					 rds_ib_cq_event_handler, conn,
					 &cq_attr);
	}
	if (IS_ERR(ic->i_rcq)) {
		ret = PTR_ERR(ic->i_rcq);
		ic->i_rcq = NULL;
		rdsdebug("ib_create_cq recv failed: %d\n", ret);
#if IB_RDS_CQ_VECTOR_SUPPORTED
		if (ic->i_scq_vector != IB_CQ_VECTOR_LEAST_ATTACHED)
			rds_ibdev->vector_load[ic->i_rcq_vector]--;
#endif
		goto out;
	}

	ret = ib_req_notify_cq(ic->i_scq, IB_CQ_NEXT_COMP);
	if (ret) {
		rdsdebug("ib_req_notify_cq send failed: %d\n", ret);
		goto out;
	}

	ret = ib_req_notify_cq(ic->i_rcq, IB_CQ_SOLICITED);
	if (ret) {
		rdsdebug("ib_req_notify_cq recv failed: %d\n", ret);
		goto out;
	}

	/* XXX negotiate max send/recv with remote? */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.event_handler = rds_ib_qp_event_handler;
	qp_attr.qp_context = conn;
	/* + 1 to allow for the single ack message */
	qp_attr.cap.max_send_wr = ic->i_send_ring.w_nr + 1;
	qp_attr.cap.max_recv_wr = ic->i_recv_ring.w_nr + 1;
	qp_attr.cap.max_send_sge = rds_ibdev->max_sge;
	qp_attr.cap.max_recv_sge = RDS_IB_RECV_SGE;
	qp_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	qp_attr.qp_type = IB_QPT_RC;
	qp_attr.send_cq = ic->i_scq;
	qp_attr.recv_cq = ic->i_rcq;

	if (rds_ib_srq_enabled) {
		qp_attr.cap.max_recv_wr = 0;
		qp_attr.srq = rds_ibdev->srq->s_srq;
	}

	/*
	 * XXX this can fail if max_*_wr is too large?  Are we supposed
	 * to back off until we get a value that the hardware can support?
	 */
	ret = rdma_create_qp(ic->i_cm_id, ic->i_pd, &qp_attr);
	if (ret) {
		rdsdebug("rdma_create_qp failed: %d\n", ret);
		goto out;
	}

	ic->i_send_hdrs = ib_dma_alloc_coherent(dev,
					   ic->i_send_ring.w_nr *
						sizeof(struct rds_header),
					   &ic->i_send_hdrs_dma, GFP_KERNEL);
	if (!ic->i_send_hdrs) {
		ret = -ENOMEM;
		rdsdebug("ib_dma_alloc_coherent send failed\n");
		goto out;
	}

	if (!rds_ib_srq_enabled) {
		ic->i_recv_hdrs = ib_dma_alloc_coherent(dev,
					ic->i_recv_ring.w_nr *
					sizeof(struct rds_header),
					&ic->i_recv_hdrs_dma, GFP_KERNEL);
		if (!ic->i_recv_hdrs) {
			ret = -ENOMEM;
			rdsdebug("ib_dma_alloc_coherent recv failed\n");
			goto out;
		}
	}

	ic->i_ack = ib_dma_alloc_coherent(dev, sizeof(struct rds_header),
				       &ic->i_ack_dma, GFP_KERNEL);
	if (!ic->i_ack) {
		ret = -ENOMEM;
		rdsdebug("ib_dma_alloc_coherent ack failed\n");
		goto out;
	}

	ic->i_sends = vmalloc_node(ic->i_send_ring.w_nr * sizeof(struct rds_ib_send_work),
				   ibdev_to_node(dev));
	if (!ic->i_sends) {
		ret = -ENOMEM;
		rdsdebug("send allocation failed\n");
		goto out;
	}
	memset(ic->i_sends, 0, ic->i_send_ring.w_nr * sizeof(struct rds_ib_send_work));

	if (!rds_ib_srq_enabled) {
		ic->i_recvs = vmalloc(ic->i_recv_ring.w_nr *
				sizeof(struct rds_ib_recv_work));
		if (!ic->i_recvs) {
			ret = -ENOMEM;
			rdsdebug("recv allocation failed\n");
			goto out;
		}
		memset(ic->i_recvs, 0, ic->i_recv_ring.w_nr * sizeof(struct rds_ib_recv_work));
	}

	rds_ib_recv_init_ack(ic);

	rdsdebug("conn %p pd %p mr %p cq %p\n", conn, ic->i_pd, ic->i_mr, ic->i_rcq);

out:
	conn->c_reconnect_err = ret;
	rds_ib_dev_put(rds_ibdev);
	return ret;
}

static u32 rds_ib_protocol_compatible(struct rdma_cm_event *event)
{
	const struct rds_ib_connect_private *dp = event->param.conn.private_data;
	u16 common;
	u32 version = 0;

	/*
	 * rdma_cm private data is odd - when there is any private data in the
	 * request, we will be given a pretty large buffer without telling us the
	 * original size. The only way to tell the difference is by looking at
	 * the contents, which are initialized to zero.
	 * If the protocol version fields aren't set, this is a connection attempt
	 * from an older version. This could could be 3.0 or 2.0 - we can't tell.
	 * We really should have changed this for OFED 1.3 :-(
	 */

	/* Be paranoid. RDS always has privdata */
	if (!event->param.conn.private_data_len) {
		printk(KERN_NOTICE "RDS incoming connection has no private data, "
			"rejecting\n");
		return 0;
	}

	/* Even if len is crap *now* I still want to check it. -ASG */
	if (event->param.conn.private_data_len < sizeof(*dp)
	    || dp->dp_protocol_major == 0)
		return RDS_PROTOCOL_3_0;

	common = be16_to_cpu(dp->dp_protocol_minor_mask) & RDS_IB_SUPPORTED_PROTOCOLS;
	if (dp->dp_protocol_major == 3 && common) {
		version = RDS_PROTOCOL_3_0;
		while ((common >>= 1) != 0)
			version++;
	} else if (printk_ratelimit()) {
		printk(KERN_NOTICE "RDS: Connection from %pI4 using "
			"incompatible protocol version %u.%u\n",
			&dp->dp_saddr,
			dp->dp_protocol_major,
			dp->dp_protocol_minor);
	}
	return version;
}

int rds_ib_cm_handle_connect(struct rdma_cm_id *cm_id,
				    struct rdma_cm_event *event)
{
	__be64 lguid = cm_id->route.path_rec->sgid.global.interface_id;
	__be64 fguid = cm_id->route.path_rec->dgid.global.interface_id;
	const struct rds_ib_connect_private *dp = event->param.conn.private_data;
	struct rds_ib_connect_private dp_rep;
	struct rds_connection *conn = NULL;
	struct rds_ib_connection *ic = NULL;
	struct rdma_conn_param conn_param;
	u32 version;
	int err = 1, destroy = 1;

	/* Check whether the remote protocol version matches ours. */
	version = rds_ib_protocol_compatible(event);
	if (!version)
		goto out;

	rdsdebug("saddr %pI4 daddr %pI4 RDSv%u.%u lguid 0x%llx fguid "
		 "0x%llx\n", &dp->dp_saddr, &dp->dp_daddr,
		 RDS_PROTOCOL_MAJOR(version), RDS_PROTOCOL_MINOR(version),
		 (unsigned long long)be64_to_cpu(lguid),
		 (unsigned long long)be64_to_cpu(fguid));

	conn = rds_conn_create(dp->dp_daddr, dp->dp_saddr, &rds_ib_transport,
			       dp->dp_tos, GFP_KERNEL);
	if (IS_ERR(conn)) {
		rdsdebug("rds_conn_create failed (%ld)\n", PTR_ERR(conn));
		conn = NULL;
		goto out;
	}

	/*
	 * The connection request may occur while the
	 * previous connection exist, e.g. in case of failover.
	 * But as connections may be initiated simultaneously
	 * by both hosts, we have a random backoff mechanism -
	 * see the comment above rds_queue_reconnect()
	 */
	mutex_lock(&conn->c_cm_lock);
	if (!rds_conn_transition(conn, RDS_CONN_DOWN, RDS_CONN_CONNECTING)) {
		/*
		 * in both of the cases below, the conn is half setup.
		 * we need to make sure the lower layers don't destroy it
		 */
		ic = conn->c_transport_data;
		if (ic && ic->i_cm_id == cm_id)
			destroy = 0;
		if (rds_conn_state(conn) == RDS_CONN_UP) {
			rdsdebug("incoming connect while connecting\n");
			rds_conn_drop(conn);
			rds_ib_stats_inc(s_ib_listen_closed_stale);
		} else if (rds_conn_state(conn) == RDS_CONN_CONNECTING) {
			unsigned long now = get_seconds();

			/*
			 * after 15 seconds, give up on existing connection
			 * attempts and make them try again.  At this point
			 * it's no longer a race but something has gone
			 * horribly wrong
			 */
			if (now > conn->c_connection_start &&
			    now - conn->c_connection_start > 15) {
				printk(KERN_CRIT "rds connection racing for 15s, forcing reset "
					"connection %pI4->%pI4\n",
					&conn->c_laddr, &conn->c_faddr);
				rds_conn_drop(conn);
				rds_ib_stats_inc(s_ib_listen_closed_stale);
			} else {
				/* Wait and see - our connect may still be succeeding */
				rds_ib_stats_inc(s_ib_connect_raced);
			}
		}
		goto out;
	}

	ic = conn->c_transport_data;

	/*
	 * record the time we started trying to connect so that we can
	 * drop the connection if it doesn't work out after a while
	 */
	conn->c_connection_start = get_seconds();

	rds_ib_set_protocol(conn, version);
	rds_ib_set_flow_control(conn, be32_to_cpu(dp->dp_credit));

	/* If the peer gave us the last packet it saw, process this as if
	 * we had received a regular ACK. */
	if (dp->dp_ack_seq)
		rds_send_drop_acked(conn, be64_to_cpu(dp->dp_ack_seq), NULL);

	BUG_ON(cm_id->context);
	BUG_ON(ic->i_cm_id);

	ic->i_cm_id = cm_id;
	cm_id->context = conn;

	/* We got halfway through setting up the ib_connection, if we
	 * fail now, we have to take the long route out of this mess. */
	destroy = 0;

	err = rds_ib_setup_qp(conn);
	if (err) {
		rds_ib_conn_error(conn, "rds_ib_setup_qp failed (%d)\n", err);
		goto out;
	}

	rds_ib_cm_fill_conn_param(conn, &conn_param, &dp_rep, version,
		event->param.conn.responder_resources,
		event->param.conn.initiator_depth);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	if (rds_ib_apm_enabled)
		rdma_set_timeout(cm_id, rds_ib_apm_timeout);
#endif /* LINUX_VERSION < 4.12.0 */

	/* rdma_accept() calls rdma_reject() internally if it fails */
	err = rdma_accept(cm_id, &conn_param);
	if (err)
		rds_ib_conn_error(conn, "rdma_accept failed (%d)\n", err);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	else if (rds_ib_apm_enabled && !conn->c_loopback) {
		err = rdma_enable_apm(cm_id, RDMA_ALT_PATH_BEST);
		if (err)
			printk(KERN_WARNING "RDS/IB: APM couldn't be enabled for passive side: %d\n", err);
	}
#endif /* LINUX_VERSION < 4.12.0 */

out:
	if (conn)
		mutex_unlock(&conn->c_cm_lock);
	if (err)
		rdma_reject(cm_id, NULL, 0);
	return destroy;
}


int rds_ib_cm_initiate_connect(struct rdma_cm_id *cm_id)
{
	struct rds_connection *conn = cm_id->context;
	struct rds_ib_connection *ic = conn->c_transport_data;
	struct rdma_conn_param conn_param;
	struct rds_ib_connect_private dp;
	int ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	if (rds_ib_apm_enabled && !conn->c_loopback) {
		ret = rdma_enable_apm(cm_id, RDMA_ALT_PATH_BEST);
		if (ret)
			printk(KERN_WARNING "RDS/IB: APM couldn't be enabled for active side: %d\n", ret);
	}
#endif /* LINUX_VERSION < 4.12.0 */

	/* If the peer doesn't do protocol negotiation, we must
	 * default to RDSv3.0 */
	rds_ib_set_protocol(conn, RDS_PROTOCOL_3_0);
	ic->i_flowctl = rds_ib_sysctl_flow_control;	/* advertise flow control */

	ret = rds_ib_setup_qp(conn);
	if (ret) {
		rds_ib_conn_error(conn, "rds_ib_setup_qp failed (%d)\n", ret);
		goto out;
	}

	rds_ib_cm_fill_conn_param(conn, &conn_param, &dp, RDS_PROTOCOL_VERSION,
		UINT_MAX, UINT_MAX);
	ret = rdma_connect(cm_id, &conn_param);
	if (ret)
		rds_ib_conn_error(conn, "rdma_connect failed (%d)\n", ret);

out:
	/* Beware - returning non-zero tells the rdma_cm to destroy
	 * the cm_id. We should certainly not do it as long as we still
	 * "own" the cm_id. */
	if (ret) {
		if (ic->i_cm_id == cm_id)
			ret = 0;
	}

	ic->i_active_side = 1;
	return ret;
}

static void rds_ib_migrate(struct work_struct *_work)
{
	struct rds_ib_migrate_work *work =
		container_of(_work, struct rds_ib_migrate_work, work.work);
	struct rds_ib_connection *ic = work->ic;
	struct ib_qp_attr qp_attr;
	struct ib_qp_init_attr  qp_init_attr;
	enum ib_mig_state path_mig_state;
	struct rdma_cm_id *cm_id = ic->i_cm_id;
	int ret = 0;

	if (!rds_ib_apm_fallback)
		return;

	if (!ic->i_active_side) {
		ret = ib_query_qp(cm_id->qp, &qp_attr, IB_QP_PATH_MIG_STATE,
				&qp_init_attr);
		if (ret) {
			printk(KERN_ERR "RDS/IB: failed to query QP\n");
			return;
		}

		path_mig_state = qp_attr.path_mig_state;
		if (!path_mig_state) {
			printk(KERN_NOTICE
				"RDS/IB: Migration in progress..skip\n");
			return;
		}

		qp_attr.path_mig_state = 0;
		ret = ib_modify_qp(cm_id->qp, &qp_attr, IB_QP_PATH_MIG_STATE);
		if (ret) {
			printk(KERN_ERR "RDS/IB: failed to modify QP from %s"
				" to  MIGRATED state\n",
				(!path_mig_state) ? "MIGRATED" :
				(path_mig_state == 1) ? "REARM" :
			(path_mig_state == 2) ? "ARMED" : "UNKNOWN");
		}
	}
}

void rds_ib_check_migration(struct rds_connection *conn,
			struct rdma_cm_event *event)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	union ib_gid sgid;
	union ib_gid dgid;
	struct ib_qp_init_attr qp_init_attr;
	struct ib_qp_attr qp_attr;
	struct rdma_cm_id *cm_id = ic->i_cm_id;
	int err;

	if (!rds_ib_apm_enabled || !rds_conn_up(ic->conn))
		return ;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	ic->i_alt_path_index = event->param.ud.alt_path_index;

	memcpy(&sgid, &cm_id->route.path_rec[event->param.ud.alt_path_index].
		sgid, sizeof(union ib_gid));
	memcpy(&dgid, &cm_id->route.path_rec[event->param.ud.alt_path_index].
		dgid, sizeof(union ib_gid));
#else /* LINUX_VERSION >= 4.12.0 */
	return;
#endif /* LINUX_VERSION >= 4.12.0 */

	printk(KERN_NOTICE
		"RDS/IB: connection "
		"<%pI4,%pI4,%d> loaded alternate path "
		"<"RDS_IB_GID_FMT","RDS_IB_GID_FMT">\n",
		&conn->c_laddr,
		&conn->c_faddr,
		conn->c_tos,
		RDS_IB_GID_ARG(sgid), RDS_IB_GID_ARG(dgid));

	err = ib_query_qp(cm_id->qp, &qp_attr, IB_QP_ALT_PATH, &qp_init_attr);
	if (err) {
		printk(KERN_ERR "RDS/IB: ib_query_qp failed (%d)\n", err);
		return;
	}
	qp_attr.alt_timeout = rds_ib_apm_timeout;
	err = ib_modify_qp(cm_id->qp, &qp_attr, IB_QP_ALT_PATH);
	if (err) {
		printk(KERN_ERR "RDS/IB: ib_modify_qp failed (%d)\n", err);
		return;
	}

	if (!memcmp(&ic->i_pri_path.p_sgid, &sgid, sizeof(union ib_gid)) &&
		!memcmp(&ic->i_pri_path.p_dgid, &dgid, sizeof(union ib_gid))) {
		if (memcmp(&ic->i_cur_path.p_sgid, &ic->i_pri_path.p_sgid,
				sizeof(union ib_gid)) ||
			memcmp(&ic->i_cur_path.p_dgid, &ic->i_pri_path.p_dgid,
				sizeof(union ib_gid))) {

			ic->i_migrate_w.ic = ic;
			queue_delayed_work(rds_wq, &ic->i_migrate_w.work, 0);
		}
	}
}

static void rds_ib_destroy_id(struct work_struct *_work)
{
	struct rds_ib_destroy_id_work *work =
		container_of(_work, struct rds_ib_destroy_id_work, work.work);
	struct rdma_cm_id        *cm_id = work->cm_id;

	rdma_destroy_id(cm_id);

	kfree(work);
}

int rds_ib_conn_connect(struct rds_connection *conn)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	struct sockaddr_in src, dest;
	struct rds_ib_destroy_id_work *work;
	int ret;

	/* XXX I wonder what affect the port space has */
	/* delegate cm event handler to rdma_transport */
	ic->i_cm_id = rdma_create_id(&init_net,
				     rds_rdma_cm_event_handler, conn,
				     RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(ic->i_cm_id)) {
		ret = PTR_ERR(ic->i_cm_id);
		ic->i_cm_id = NULL;
		rdsdebug("rdma_create_id() failed: %d\n", ret);
		goto out;
	}

	rdsdebug("created cm id %p for conn %p\n", ic->i_cm_id, conn);

	src.sin_family = AF_INET;
	src.sin_addr.s_addr = (__force u32)conn->c_laddr;
	src.sin_port = (__force u16)htons(0);

	dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = (__force u32)conn->c_faddr;
	dest.sin_port = (__force u16)htons(RDS_PORT);

	ret = rdma_resolve_addr(ic->i_cm_id, (struct sockaddr *)&src,
				(struct sockaddr *)&dest,
				RDS_RDMA_RESOLVE_TIMEOUT_MS);
	if (ret) {
		rdsdebug("addr resolve failed for cm id %p: %d\n", ic->i_cm_id,
			 ret);
		work = kzalloc(sizeof *work, GFP_KERNEL);
		if (work) {
			work->cm_id = ic->i_cm_id;
			INIT_DELAYED_WORK(&work->work, rds_ib_destroy_id);
			queue_delayed_work(rds_aux_wq, &work->work, 0);
		} else
			rdma_destroy_id(ic->i_cm_id);

		ic->i_cm_id = NULL;
	}

out:
	return ret;
}

/*
 * This is so careful about only cleaning up resources that were built up
 * so that it can be called at any point during startup.  In fact it
 * can be called multiple times for a given connection.
 */
void rds_ib_conn_shutdown(struct rds_connection *conn)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	struct rds_ib_destroy_id_work *work;
	int err = 0;

	rdsdebug("cm %p pd %p cq %p qp %p\n", ic->i_cm_id,
		 ic->i_pd, ic->i_rcq, ic->i_cm_id ? ic->i_cm_id->qp : NULL);

	if (ic->i_cm_id) {
		struct ib_device *dev = ic->i_cm_id->device;

		rdsdebug("disconnecting cm %p\n", ic->i_cm_id);
		err = rdma_disconnect(ic->i_cm_id);
		if (err) {
			/* Actually this may happen quite frequently, when
			 * an outgoing connect raced with an incoming connect.
			 */
			rdsdebug("failed to disconnect, cm: %p err %d\n",
				ic->i_cm_id, err);
		} else if (rds_ib_srq_enabled && ic->rds_ibdev) {
			/*
			   wait for the last wqe to complete, then schedule
			   the recv tasklet to drain the RX CQ.
			*/
			wait_for_completion(&ic->i_last_wqe_complete);
			tasklet_schedule(&ic->i_rtasklet);
		}

		/* quiesce tx and rx completion before tearing down */
		wait_event(rds_ib_ring_empty_wait,
			   rds_ib_ring_empty(&ic->i_recv_ring) &&
			   (atomic_read(&ic->i_signaled_sends) == 0));
		tasklet_kill(&ic->i_stasklet);
		tasklet_kill(&ic->i_rtasklet);

		/* first destroy the ib state that generates callbacks */
		if (ic->i_cm_id->qp)
			rdma_destroy_qp(ic->i_cm_id);

		if (ic->i_rcq) {
#if IB_RDS_CQ_VECTOR_SUPPORTED
			if (ic->rds_ibdev &&
				ic->i_rcq_vector != IB_CQ_VECTOR_LEAST_ATTACHED)
				ic->rds_ibdev->vector_load[ic->i_rcq_vector]--;
#endif
			ib_destroy_cq(ic->i_rcq);
		}

		if (ic->i_scq) {
#if IB_RDS_CQ_VECTOR_SUPPORTED
			if (ic->rds_ibdev &&
				ic->i_scq_vector != IB_CQ_VECTOR_LEAST_ATTACHED)
				ic->rds_ibdev->vector_load[ic->i_scq_vector]--;
#endif
			ib_destroy_cq(ic->i_scq);
		}

		/* then free the resources that ib callbacks use */
		if (ic->i_send_hdrs)
			ib_dma_free_coherent(dev,
					   ic->i_send_ring.w_nr *
						sizeof(struct rds_header),
					   ic->i_send_hdrs,
					   ic->i_send_hdrs_dma);

		if (ic->i_recv_hdrs)
			ib_dma_free_coherent(dev,
					   ic->i_recv_ring.w_nr *
						sizeof(struct rds_header),
					   ic->i_recv_hdrs,
					   ic->i_recv_hdrs_dma);

		if (ic->i_ack)
			ib_dma_free_coherent(dev, sizeof(struct rds_header),
					     ic->i_ack, ic->i_ack_dma);

		if (ic->i_sends)
			rds_ib_send_clear_ring(ic);
		if (ic->i_recvs)
			rds_ib_recv_clear_ring(ic);

		/*
		 * rdma_destroy_id may block so offload it to the aux
		 * thread for processing.
		 */
		work = kzalloc(sizeof *work, GFP_KERNEL);
		if (work) {
			work->cm_id = ic->i_cm_id;
			INIT_DELAYED_WORK(&work->work, rds_ib_destroy_id);
			queue_delayed_work(rds_aux_wq, &work->work, 0);
		} else
			rdma_destroy_id(ic->i_cm_id);

		/*
		 * Move connection back to the nodev list.
		 */
		if (ic->rds_ibdev)
			rds_ib_remove_conn(ic->rds_ibdev, conn);

		ic->i_cm_id = NULL;
		ic->i_pd = NULL;
		ic->i_mr = NULL;
		ic->i_scq = NULL;
		ic->i_rcq = NULL;
		ic->i_send_hdrs = NULL;
		ic->i_recv_hdrs = NULL;
		ic->i_ack = NULL;
	}
	BUG_ON(ic->rds_ibdev);

	/* Clear pending transmit */
	if (ic->i_data_op) {
		struct rds_message *rm;

		rm = container_of(ic->i_data_op, struct rds_message, data);
		rds_message_put(rm);
		ic->i_data_op = NULL;
	}

	/* Clear the ACK state */
	clear_bit(IB_ACK_IN_FLIGHT, &ic->i_ack_flags);
#ifdef KERNEL_HAS_ATOMIC64
	atomic64_set(&ic->i_ack_next, 0);
#else
	ic->i_ack_next = 0;
#endif
	ic->i_ack_recv = 0;

	/* Clear flow control state */
	ic->i_flowctl = 0;
	atomic_set(&ic->i_credits, 0);

	rds_ib_ring_init(&ic->i_send_ring, rds_ib_sysctl_max_send_wr);
	rds_ib_ring_init(&ic->i_recv_ring, rds_ib_sysctl_max_recv_wr);

	if (ic->i_ibinc) {
		rds_inc_put(&ic->i_ibinc->ii_inc);
		ic->i_ibinc = NULL;
	}

	vfree(ic->i_sends);
	ic->i_sends = NULL;
	if (!rds_ib_srq_enabled)
		vfree(ic->i_recvs);

	ic->i_recvs = NULL;

	init_completion(&ic->i_last_wqe_complete);

	ic->i_active_side = 0;
}

int rds_ib_conn_alloc(struct rds_connection *conn, gfp_t gfp)
{
	struct rds_ib_connection *ic;
	unsigned long flags;
	int ret;

	/* XXX too lazy? */
	ic = kzalloc(sizeof(struct rds_ib_connection), GFP_KERNEL);
	if (!ic)
		return -ENOMEM;

	ret = rds_ib_recv_alloc_caches(ic);
	if (ret) {
		kfree(ic);
		return ret;
	}

	INIT_LIST_HEAD(&ic->ib_node);
	tasklet_init(&ic->i_stasklet, rds_ib_tasklet_fn_send, (unsigned long) ic);
	tasklet_init(&ic->i_rtasklet, rds_ib_tasklet_fn_recv, (unsigned long) ic);
	mutex_init(&ic->i_recv_mutex);
#ifndef KERNEL_HAS_ATOMIC64
	spin_lock_init(&ic->i_ack_lock);
#endif
	atomic_set(&ic->i_signaled_sends, 0);

	/*
	 * rds_ib_conn_shutdown() waits for these to be emptied so they
	 * must be initialized before it can be called.
	 */
	rds_ib_ring_init(&ic->i_send_ring, rds_ib_sysctl_max_send_wr);
	rds_ib_ring_init(&ic->i_recv_ring, rds_ib_sysctl_max_recv_wr);

	ic->conn = conn;
	conn->c_transport_data = ic;

	init_completion(&ic->i_last_wqe_complete);

	INIT_DELAYED_WORK(&ic->i_migrate_w.work, rds_ib_migrate);

	spin_lock_irqsave(&ib_nodev_conns_lock, flags);
	list_add_tail(&ic->ib_node, &ib_nodev_conns);
	spin_unlock_irqrestore(&ib_nodev_conns_lock, flags);

	rdsdebug("conn %p conn ic %p\n", conn, conn->c_transport_data);
	return 0;
}

/*
 * Free a connection. Connection must be shut down and not set for reconnect.
 */
void rds_ib_conn_free(void *arg)
{
	struct rds_ib_connection *ic = arg;
	spinlock_t	*lock_ptr;

	rdsdebug("ic %p\n", ic);

	/*
	 * Conn is either on a dev's list or on the nodev list.
	 * A race with shutdown() or connect() would cause problems
	 * (since rds_ibdev would change) but that should never happen.
	 */

	lock_ptr = ic->rds_ibdev ? &ic->rds_ibdev->spinlock : &ib_nodev_conns_lock;

	spin_lock_irq(lock_ptr);
	list_del(&ic->ib_node);
	spin_unlock_irq(lock_ptr);

	rds_ib_recv_free_caches(ic);

	kfree(ic);
}


/*
 * An error occurred on the connection
 */
void
__rds_ib_conn_error(struct rds_connection *conn, const char *fmt, ...)
{
	va_list ap;

	rds_conn_drop(conn);

	va_start(ap, fmt);
	vprintk(fmt, ap);
	va_end(ap);
}
