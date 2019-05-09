/*
 * Copyright (c) 2006, 2018 Oracle and/or its affiliates. All rights reserved.
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
#include <linux/kconfig.h>
#include <asm-generic/sizes.h>
#include <rdma/rdma_cm_ib.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_cm.h>
#include <net/addrconf.h>

#include "rds.h"
#include "ib.h"
#include "rds_single_path.h"

static unsigned int rds_ib_max_frag = RDS_MAX_FRAG_SIZE;
static unsigned int ib_init_frag_size = RDS_FRAG_SIZE;

module_param(rds_ib_max_frag, int, 0444);
MODULE_PARM_DESC(rds_ib_max_frag, " RDS IB maximum fragment size");

static char *rds_ib_event_type_strings[] = {
#define RDS_IB_EVENT_STRING(foo) \
		[IB_EVENT_##foo] = __stringify(IB_EVENT_##foo)
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
	RDS_IB_EVENT_STRING(GID_CHANGE),
#undef RDS_IB_EVENT_STRING
};

static char *rds_ib_event_str(enum ib_event_type type)
{
	return rds_str_array(rds_ib_event_type_strings,
			     ARRAY_SIZE(rds_ib_event_type_strings), type);
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

static inline u16 rds_ib_get_frag(unsigned int version, u16 ib_frag)
{
	u16 frag = RDS_FRAG_SIZE;

	if (version < RDS_PROTOCOL_4_1) {
		pr_err("RDS/IB: Protocol %x default frag %uKB\n",
			 version, frag / SZ_1K);
		return frag;
	}

	switch (ib_frag) {
	case RDS_MAX_FRAG_SIZE:
		frag = RDS_MAX_FRAG_SIZE;
		break;
	case SZ_8K:
		frag = SZ_8K;
		break;
	default:
		frag = RDS_FRAG_SIZE;
	}

	return frag;
}

/* Initialise the RDS IB frag size with host_ib_max_frag */
void rds_ib_init_frag(unsigned int version)
{
	/* Initialise using Host module parameter */
	ib_init_frag_size = rds_ib_get_frag(version, rds_ib_max_frag);

	pr_debug("RDS/IB: fragment size initialised to %uKB\n",
		 ib_init_frag_size / SZ_1K);
}

/* Update the RDS IB frag size */
static u16 rds_ib_set_frag_size(struct rds_connection *conn, u16 dp_frag)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	u16 current_frag = ic->i_frag_sz;
	u16 frag;

	frag = min_t(unsigned int, ib_init_frag_size,
		     PAGE_ALIGN((ic->i_hca_sge - 1) * PAGE_SIZE));

	if (frag != dp_frag) {
		frag = min_t(unsigned int, dp_frag, frag);
		ic->i_frag_sz = rds_ib_get_frag(conn->c_version, frag);
	} else {
		ic->i_frag_sz = frag;
	}

	ic->i_frag_pages =  ceil(ic->i_frag_sz, PAGE_SIZE);

	pr_debug("RDS/IB: conn <%pI6c, %pI6c,%d>, Frags <init,ic,dp>: {%d,%d,%d}, updated {%d -> %d}\n",
		 &conn->c_laddr, &conn->c_faddr, conn->c_tos,
		 ib_init_frag_size / SZ_1K, ic->i_frag_sz / SZ_1K, dp_frag /  SZ_1K,
		 current_frag / SZ_1K, ic->i_frag_sz / SZ_1K);

	return ic->i_frag_sz;
}

/* Init per IC frag size */
static inline void rds_ib_init_ic_frag(struct rds_ib_connection *ic)
{
	if (ic)
		ic->i_frag_sz = ib_init_frag_size;
}

#ifdef CONFIG_RDS_ACL

/*
*  0 - all good
*  1 - acl is not enabled
* -1 - acl match failed
*/
static int rds_ib_match_acl(struct rdma_cm_id *cm_id,
			    const struct in6_addr *saddr)
{
	struct ib_cm_acl *acl = 0;
	struct ib_cm_acl_elem *acl_elem = 0;
	__be64 fguid = cm_id->route.path_rec->dgid.global.interface_id;
	__be64 fsubnet = cm_id->route.path_rec->dgid.global.subnet_prefix;
	struct ib_cm_dpp dpp;

	ib_cm_dpp_init(&dpp, cm_id->device, cm_id->port_num,
		       ntohs(cm_id->route.path_rec->pkey));
	acl = ib_cm_dpp_acl_lookup(&dpp);
	if (!acl)
		return 0;

	if (!acl->enabled)
		return 0;

	acl_elem = ib_cm_acl_lookup(acl, be64_to_cpu(fsubnet),
				    be64_to_cpu(fguid));
	if (!acl_elem) {
		pr_err_ratelimited("RDS/IB: GUID ib_cm_acl_lookup() failed\n");
		goto out;
	}

	acl_elem = ib_cm_acl_lookup_uuid_ip(acl, acl_elem->uuid, saddr);
	if (!acl_elem) {
		pr_err_ratelimited("RDS/IB: IP %pI6c ib_cm_acl_lookup_uuid_ip() failed\n",
				   saddr);
		goto out;
	}

	return 1;
out:
	pr_err_ratelimited("RDS/IB: %s failed due to ACLs. Check ACLs\n",
			    __func__);
	return -1;
}

#endif /* CONFIG_RDS_ACL */

/*
 * Connection established.
 * We get here for both outgoing and incoming connection.
 */
void rds_ib_cm_connect_complete(struct rds_connection *conn, struct rdma_cm_event *event)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	const union rds_ib_conn_priv *dp = NULL;
	struct ib_qp_attr qp_attr;
	__be16 frag_sz = 0;
	__be64 ack_seq = 0;
	__be32 credit = 0;
	u8 major = 0;
	u8 minor = 0;
	int err;

	dp = event->param.conn.private_data;
	if (conn->c_isv6) {
		if (event->param.conn.private_data_len >=
		    sizeof(struct rds6_ib_connect_private)) {
			major = dp->ricp_v6.dp_protocol_major;
			minor = dp->ricp_v6.dp_protocol_minor;
			credit = dp->ricp_v6.dp_credit;
			frag_sz = dp->ricp_v6.dp_frag_sz;
			/* dp structure start is not guaranteed to be 8 bytes
			 * aligned.  Since dp_ack_seq is 64-bit extended load
			 * operations can be used so go through get_unaligned
			 * to avoid unaligned errors.
			 */
			ack_seq = get_unaligned(&dp->ricp_v6.dp_ack_seq);
		}
	} else if (event->param.conn.private_data_len >=
		   sizeof(struct rds_ib_connect_private)) {
		major = dp->ricp_v4.dp_protocol_major;
		minor = dp->ricp_v4.dp_protocol_minor;
		credit = dp->ricp_v4.dp_credit;
		frag_sz = dp->ricp_v4.dp_frag_sz;
		ack_seq = get_unaligned(&dp->ricp_v4.dp_ack_seq);
	}

	/* make sure it isn't empty data */
	if (major) {
		rds_ib_set_protocol(conn, RDS_PROTOCOL(major, minor));
		rds_ib_set_flow_control(conn, be32_to_cpu(credit));
		rds_ib_set_frag_size(conn, be16_to_cpu(frag_sz));
	}

	if (conn->c_version < RDS_PROTOCOL_VERSION) {
		if (conn->c_version != RDS_PROTOCOL_COMPAT_VERSION) {
			printk(KERN_NOTICE "RDS/IB: Connection to %pI6c version %u.%u failed, no longer supported\n",
			       &conn->c_faddr,
			       RDS_PROTOCOL_MAJOR(conn->c_version),
			       RDS_PROTOCOL_MINOR(conn->c_version));
			rds_ib_conn_destroy_init(conn);
			return;
		}
	}

	printk(KERN_NOTICE "RDS/IB: %s conn %p i_cm_id %p, frag %dKB, connected <%pI6c,%pI6c,%d> version %u.%u%s%s\n",
	       ic->i_active_side ? "Active " : "Passive",
	       conn, ic->i_cm_id, ic->i_frag_sz / SZ_1K,
	       &conn->c_laddr, &conn->c_faddr, conn->c_tos,
	       RDS_PROTOCOL_MAJOR(conn->c_version),
	       RDS_PROTOCOL_MINOR(conn->c_version),
	       ic->i_flowctl ? ", flow control" : "",
	       conn->c_acl_en ? ", ACL Enabled" : "");

	/* The connection might have been dropped under us*/
	if (!ic->i_cm_id) {
		rds_rtd(RDS_RTD_CM,
			"ic->i_cm_id is NULL, ic: %p, calling rds_conn_drop\n",
			ic);
		rds_conn_drop(conn, DR_IB_CONN_DROP_RACE);
		return;
	}

	ic->i_sl = ic->i_cm_id->route.path_rec->sl;
	atomic_set(&ic->i_cq_quiesce, 0);
	ic->i_flags &= ~RDS_IB_CQ_ERR;

	/*
	 * Init rings and fill recv. this needs to wait until protocol negotiation
	 * is complete, since ring layout is different from 3.0 to 3.1.
	 */
	rds_ib_send_init_ring(ic);

	if (!rds_ib_srq_enabled) {
		rds_ib_recv_rebuild_caches(ic);
		rds_ib_recv_init_ring(ic);
	}

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
	err = rds_ib_update_ipaddr(ic->rds_ibdev, &conn->c_laddr);
	if (err)
		printk(KERN_ERR "rds_ib_update_ipaddr failed (%d)\n",
			err);

	/* If the peer gave us the last packet it saw, process this as if
	 * we had received a regular ACK. */
	if (dp) {
		if (ack_seq)
			rds_send_drop_acked(conn, be64_to_cpu(ack_seq),
					    NULL);
	}

	rds_connect_complete(conn);
}

static void rds_ib_cm_fill_conn_param(struct rds_connection *conn,
				      struct rdma_conn_param *conn_param,
				      union rds_ib_conn_priv *dp,
				      u32 protocol_version,
				      u32 max_responder_resources,
				      u32 max_initiator_depth, u16 frag,
				      bool isv6, u8 seq)
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
		if (isv6) {
			dp->ricp_v6.dp_saddr = conn->c_laddr;
			dp->ricp_v6.dp_daddr = conn->c_faddr;
			dp->ricp_v6.dp_protocol_major =
			    RDS_PROTOCOL_MAJOR(protocol_version);
			dp->ricp_v6.dp_protocol_minor =
			    RDS_PROTOCOL_MINOR(protocol_version);
			dp->ricp_v6.dp_protocol_minor_mask =
			    cpu_to_be16(RDS_IB_SUPPORTED_PROTOCOLS);
			dp->ricp_v6.dp_ack_seq =
			    cpu_to_be64(rds_ib_piggyb_ack(ic));
			dp->ricp_v6.dp_tos = conn->c_tos;
			dp->ricp_v6.dp_frag_sz = cpu_to_be16(frag);
			dp->ricp_v6.dp_cm_seq = seq;

			conn_param->private_data = &dp->ricp_v6;
			conn_param->private_data_len = sizeof(dp->ricp_v6);
		} else {
			dp->ricp_v4.dp_saddr = conn->c_laddr.s6_addr32[3];
			dp->ricp_v4.dp_daddr = conn->c_faddr.s6_addr32[3];
			dp->ricp_v4.dp_protocol_major =
			    RDS_PROTOCOL_MAJOR(protocol_version);
			dp->ricp_v4.dp_protocol_minor =
			    RDS_PROTOCOL_MINOR(protocol_version);
			dp->ricp_v4.dp_protocol_minor_mask =
			    cpu_to_be16(RDS_IB_SUPPORTED_PROTOCOLS);
			dp->ricp_v4.dp_ack_seq =
			    cpu_to_be64(rds_ib_piggyb_ack(ic));
			dp->ricp_v4.dp_tos = conn->c_tos;
			dp->ricp_v4.dp_frag_sz = cpu_to_be16(frag);
			dp->ricp_v4.dp_cm_seq = seq;

			conn_param->private_data = &dp->ricp_v4;
			conn_param->private_data_len = sizeof(dp->ricp_v4);
		}

		/* Advertise flow control */
		if (ic->i_flowctl) {
			unsigned int credits;

			credits = IB_GET_POST_CREDITS(
			    atomic_read(&ic->i_credits));
			if (isv6)
				dp->ricp_v6.dp_credit = cpu_to_be32(credits);
			else
				dp->ricp_v4.dp_credit = cpu_to_be32(credits);
			atomic_sub(IB_SET_POST_CREDITS(credits),
				   &ic->i_credits);
		}
	}
}

static void rds_ib_cq_event_handler(struct ib_event *event, void *data)
{
	struct rds_connection *conn = data;
	struct rds_ib_connection *ic = conn->c_transport_data;

	pr_info("RDS/IB: event %u (%s) data %p\n",
		 event->event, rds_ib_event_str(event->event), data);

	ic->i_flags |= RDS_IB_CQ_ERR;
	if (waitqueue_active(&rds_ib_ring_empty_wait))
		wake_up(&rds_ib_ring_empty_wait);
}

static void rds_ib_cq_comp_handler_fastreg(struct ib_cq *cq, void *context)
{
	struct rds_ib_device *rds_ibdev = context;

	tasklet_schedule(&rds_ibdev->fastreg_tasklet);
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

static void poll_fcq(struct rds_ib_device *rds_ibdev, struct ib_cq *cq,
		     struct ib_wc *wcs)
{
	int nr, i;
	struct ib_wc *wc;

	while ((nr = ib_poll_cq(cq, RDS_WC_MAX, wcs)) > 0) {
		for (i = 0; i < nr; i++) {
			wc = wcs + i;
			rds_ib_fcq_handler(rds_ibdev, wc);
		}
	}
}

static void poll_scq(struct rds_ib_connection *ic, struct ib_cq *cq,
		     struct ib_wc *wcs)
{
	int nr, i;
	struct ib_wc *wc;

	while ((nr = ib_poll_cq(cq, RDS_WC_MAX, wcs)) > 0) {
		for (i = 0; i < nr; i++) {
			wc = wcs + i;
			rdsdebug("wc wr_id 0x%llx status %u byte_len %u imm_data %u\n",
				 (unsigned long long)wc->wr_id, wc->status, wc->byte_len,
				 be32_to_cpu(wc->ex.imm_data));

			if (wc->wr_id < (u64)ic->i_send_ring.w_nr ||
			    wc->wr_id == RDS_IB_ACK_WR_ID)
				rds_ib_send_cqe_handler(ic, wc);
			else
				rds_ib_mr_cqe_handler(ic, wc);
		}
	}
}

static void poll_rcq(struct rds_ib_connection *ic, struct ib_cq *cq,
		     struct ib_wc *wcs,
		     struct rds_ib_ack_state *ack_state)
{
	int nr, i;
	struct ib_wc *wc;

	while ((nr = ib_poll_cq(cq, RDS_WC_MAX, wcs)) > 0) {
		for (i = 0; i < nr; i++) {
			if ((++ic->i_rx_poll_cq % RDS_IB_RX_LIMIT) == 0) {
				rdsdebug("connection <%pI6c,%pI6c,%d> RX poll_cq processed %d\n",
					 &ic->conn->c_laddr,
					 &ic->conn->c_faddr,
					 ic->conn->c_tos,
					 ic->i_rx_poll_cq);
			}
			wc = wcs + i;
			rdsdebug("wc wr_id 0x%llx status %u byte_len %u imm_data %u\n",
				 (unsigned long long)wc->wr_id, wc->status,
				 wc->byte_len, be32_to_cpu(wc->ex.imm_data));
			rds_ib_recv_cqe_handler(ic, wc, ack_state);
		}

		if (ic->i_rx_poll_cq >= RDS_IB_RX_LIMIT)
			break;
	}
}

static void rds_ib_tasklet_fn_fastreg(unsigned long data)
{
	struct rds_ib_device *rds_ibdev = (struct rds_ib_device *)data;

	poll_fcq(rds_ibdev, rds_ibdev->fastreg_cq, rds_ibdev->fastreg_wc);
	ib_req_notify_cq(rds_ibdev->fastreg_cq, IB_CQ_NEXT_COMP);
	poll_fcq(rds_ibdev, rds_ibdev->fastreg_cq, rds_ibdev->fastreg_wc);
}

void rds_ib_tasklet_fn_send(unsigned long data)
{
	struct rds_ib_connection *ic = (struct rds_ib_connection *) data;
	struct rds_connection *conn = ic->conn;

	rds_ib_stats_inc(s_ib_tasklet_call);

	/* if cq has been already reaped, ignore incoming cq event */
	 if (atomic_read(&ic->i_cq_quiesce))
		return;

	poll_scq(ic, ic->i_scq, ic->i_send_wc);
	ib_req_notify_cq(ic->i_scq, IB_CQ_NEXT_COMP);
	poll_scq(ic, ic->i_scq, ic->i_send_wc);

	if (rds_conn_up(conn) &&
	   (!test_bit(RDS_LL_SEND_FULL, &conn->c_flags) ||
	    test_bit(RCMQ_BITOFF_CONGU_PENDING, &conn->c_map_queued)))
		rds_send_xmit(&ic->conn->c_path[0]);
}

/*
 * Note: rds_ib_rx(): don't call with irqs disabled.
 * It calls rds_send_drop_acked() which calls other
 * routines that reach into rds_rdma_free_op()
 * where irqs_disabled() warning is asserted!
 */
static void rds_ib_rx(struct rds_ib_connection *ic)
{
	struct rds_connection *conn = ic->conn;
	struct rds_ib_ack_state ack_state;
	struct rds_ib_device *rds_ibdev = ic->rds_ibdev;

	BUG_ON(conn->c_tos && !rds_ibdev);

	rds_ib_stats_inc(s_ib_tasklet_call);

	/* if cq has been already reaped, ignore incoming cq event */
	if (atomic_read(&ic->i_cq_quiesce))
		return;

	memset(&ack_state, 0, sizeof(ack_state));

	ic->i_rx_poll_cq = 0;
	poll_rcq(ic, ic->i_rcq, ic->i_recv_wc, &ack_state);
	ib_req_notify_cq(ic->i_rcq, IB_CQ_SOLICITED);
	poll_rcq(ic, ic->i_rcq, ic->i_recv_wc, &ack_state);

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
				queue_delayed_work(conn->c_path[0].cp_wq,
					&rds_ibdev->srq->s_refill_w, 0);

	if (ic->i_rx_poll_cq >= RDS_IB_RX_LIMIT) {
		ic->i_rx_w.ic = ic;
		/* Delay 10 msecs until the RX worker starts reaping again */
		queue_delayed_work(rds_aux_wq, &ic->i_rx_w.work,
					msecs_to_jiffies(10));
		ic->i_rx_wait_for_handler = 1;
	}
}

void rds_ib_tasklet_fn_recv(unsigned long data)
{
	struct rds_ib_connection *ic = (struct rds_ib_connection *) data;

	spin_lock_bh(&ic->i_rx_lock);
	if (ic->i_rx_wait_for_handler)
		goto out;
	rds_ib_rx(ic);
out:
	spin_unlock_bh(&ic->i_rx_lock);
}

static void rds_ib_rx_handler(struct work_struct *_work)
{
        struct rds_ib_rx_work *work =
                container_of(_work, struct rds_ib_rx_work, work.work);
	struct rds_ib_connection *ic = work->ic;

	spin_lock_bh(&ic->i_rx_lock);
	ic->i_rx_wait_for_handler = 0;
	rds_ib_rx(ic);
	spin_unlock_bh(&ic->i_rx_lock);
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
	default:
		rds_rtd_ptr(RDS_RTD_ERR,
			    "Fatal QP Event %u (%s) - conn %p <%pI6c,%pI6c,%d>, reconnecting\n",
			    event->event, rds_ib_event_str(event->event),
			    conn, &conn->c_laddr, &conn->c_faddr, conn->c_tos);
		rds_conn_drop(conn, DR_IB_QP_EVENT);
		break;
	}
}

static inline int ibdev_get_unused_vector(struct rds_ib_device *rds_ibdev)
{
	int index;
	int min;
	int i;

	mutex_lock(&rds_ibdev->vector_load_lock);
	min = rds_ibdev->vector_load[rds_ibdev->dev->num_comp_vectors - 1];
	index = rds_ibdev->dev->num_comp_vectors - 1;

	for (i = rds_ibdev->dev->num_comp_vectors - 1; i >= 0; i--) {
		if (rds_ibdev->vector_load[i] < min) {
			index = i;
			min = rds_ibdev->vector_load[i];
		}
	}

	rds_ibdev->vector_load[index]++;
	mutex_unlock(&rds_ibdev->vector_load_lock);

	return index;
}

static inline void ibdev_put_vector(struct rds_ib_device *rds_ibdev, int index)
{
	mutex_lock(&rds_ibdev->vector_load_lock);
	rds_ibdev->vector_load[index]--;
	mutex_unlock(&rds_ibdev->vector_load_lock);
}

static void rds_ib_check_cq(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
			    int *vector, struct ib_cq **cqp, ib_comp_handler comp_handler,
			    void (*event_handler)(struct ib_event *, void *),
			    void *ctx, int n, const char str[5])
{
	struct ib_wc wc;
	int spurious_completions = 0;

	if (!*cqp) {
		struct ib_cq_init_attr cq_attr = {};

		cq_attr.cqe = n;
		cq_attr.comp_vector = ibdev_get_unused_vector(rds_ibdev);
		*vector = cq_attr.comp_vector;
		*cqp = ib_create_cq(dev, comp_handler, event_handler, ctx, &cq_attr);
		if (IS_ERR(*cqp)) {
			ibdev_put_vector(rds_ibdev, cq_attr.comp_vector);
			rdsdebug("ib_create_cq %s failed: %ld\n", str, PTR_ERR(*cqp));
			return;
		}
	}

	while (ib_poll_cq(*cqp, 1, &wc) > 0)
		++spurious_completions;

	if (spurious_completions)
		pr_err("RDS/IB: %d spurious completions in %s cq for conn %p. We have memory leak!\n",
		       spurious_completions, str, ctx);
}

/*
 * This needs to be very careful to not leave IS_ERR pointers around for
 * cleanup to trip over.
 */
static int rds_ib_setup_qp(struct rds_connection *conn)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	struct ib_device *dev = ic->i_cm_id->device;
	struct ib_qp_init_attr qp_attr;
	struct rds_ib_device *rds_ibdev;
	int ret;
	int mr_reg;

	/*
	 * It's normal to see a null device if an incoming connection races
	 * with device removal, so we don't print a warning.
	 */
	rds_ibdev = rds_ib_get_client_data(dev);
	if (!rds_ibdev)
		return -EOPNOTSUPP;

	/* In the case of FRWR, mr registration wrs use the
	 * same work queue as the send wrs. To make sure that we are not
	 * overflowing the workqueue, we allocate separately for each operation.
	 * mr_reg is the wr numbers allocated for reg.
	 */
	if (rds_ibdev->use_fastreg)
		mr_reg = RDS_IB_DEFAULT_FREG_WR;
	else
		mr_reg = 0;

	/* add the conn now so that connection establishment has the dev */
	rds_ib_add_conn(rds_ibdev, conn);

	if (rds_ibdev->max_wrs < ic->i_send_ring.w_nr + 1 + mr_reg)
		rds_ib_ring_resize(&ic->i_send_ring,
				   rds_ibdev->max_wrs - 1 - mr_reg);
	if (rds_ibdev->max_wrs < ic->i_recv_ring.w_nr + 1)
		rds_ib_ring_resize(&ic->i_recv_ring, rds_ibdev->max_wrs - 1);

	/* Protection domain and memory range */
	ic->i_pd = rds_ibdev->pd;
	ic->i_mr = rds_ibdev->mr;

	rds_ib_check_cq(dev, rds_ibdev, &ic->i_scq_vector, &ic->i_scq,
			rds_ib_cq_comp_handler_send,
			rds_ib_cq_event_handler, conn,
			ic->i_send_ring.w_nr + 1 + mr_reg,
			"send");
	if (IS_ERR(ic->i_scq)) {
		ret = PTR_ERR(ic->i_scq);
		ic->i_scq = NULL;
		goto out;
	}

	rds_ib_check_cq(dev, rds_ibdev, &ic->i_rcq_vector, &ic->i_rcq,
			rds_ib_cq_comp_handler_recv,
			rds_ib_cq_event_handler, conn,
			rds_ib_srq_enabled ? rds_ib_srq_max_wr - 1 : ic->i_recv_ring.w_nr,
			"recv");
	if (IS_ERR(ic->i_rcq)) {
		ret = PTR_ERR(ic->i_rcq);
		ic->i_rcq = NULL;
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
	qp_attr.cap.max_send_wr = ic->i_send_ring.w_nr + 1 + mr_reg;
	qp_attr.cap.max_recv_wr = ic->i_recv_ring.w_nr + 1;
	qp_attr.cap.max_send_sge = rds_ibdev->max_sge;
	qp_attr.cap.max_recv_sge = rds_ibdev->max_sge;
	qp_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	qp_attr.qp_type = IB_QPT_RC;
	qp_attr.send_cq = ic->i_scq;
	qp_attr.recv_cq = ic->i_rcq;

	if (rds_ib_srq_enabled) {
		qp_attr.cap.max_recv_wr = 0;
		qp_attr.srq = rds_ibdev->srq->s_srq;
	}

	ic->i_hca_sge = rds_ibdev->max_sge;
	/*
	 * XXX this can fail if max_*_wr is too large?  Are we supposed
	 * to back off until we get a value that the hardware can support?
	 */
	ret = rdma_create_qp(ic->i_cm_id, ic->i_pd, &qp_attr);
	if (ret) {
		rds_rtd(RDS_RTD_ERR, "rdma_create_qp failed: %d\n", ret);
		goto out;
	}

	ic->i_send_hdrs = ib_dma_alloc_coherent(dev,
					   ic->i_send_ring.w_nr *
						sizeof(struct rds_header),
					   &ic->i_send_hdrs_dma, GFP_KERNEL);
	if (!ic->i_send_hdrs) {
		ret = -ENOMEM;
		rds_rtd(RDS_RTD_ERR, "ib_dma_alloc_coherent send failed\n");
		goto out;
	}

	if (!rds_ib_srq_enabled) {
		ic->i_recv_hdrs = ib_dma_alloc_coherent(dev,
					ic->i_recv_ring.w_nr *
					sizeof(struct rds_header),
					&ic->i_recv_hdrs_dma, GFP_KERNEL);
		if (!ic->i_recv_hdrs) {
			ret = -ENOMEM;
			rds_rtd(RDS_RTD_ERR,
				"ib_dma_alloc_coherent recv failed\n");
			goto out;
		}
	}

	ic->i_ack = ib_dma_alloc_coherent(dev, sizeof(struct rds_header),
				       &ic->i_ack_dma, GFP_KERNEL);
	if (!ic->i_ack) {
		ret = -ENOMEM;
		rds_rtd(RDS_RTD_ERR, "ib_dma_alloc_coherent ack failed\n");
		goto out;
	}

	ic->i_sends = vmalloc_node(ic->i_send_ring.w_nr * sizeof(struct rds_ib_send_work),
				   ibdev_to_node(dev));
	if (!ic->i_sends) {
		ret = -ENOMEM;
		rds_rtd(RDS_RTD_ERR, "send allocation failed\n");
		goto out;
	}
	memset(ic->i_sends, 0, ic->i_send_ring.w_nr * sizeof(struct rds_ib_send_work));

	if (!rds_ib_srq_enabled) {
		ic->i_recvs = vmalloc(ic->i_recv_ring.w_nr *
				sizeof(struct rds_ib_recv_work));
		if (!ic->i_recvs) {
			ret = -ENOMEM;
			rds_rtd(RDS_RTD_ERR, "recv allocation failed\n");
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

static u32 rds_ib_protocol_compatible(struct rdma_cm_event *event, bool isv6)
{
	const union rds_ib_conn_priv *dp = event->param.conn.private_data;
	u8 data_len, major, minor;
	u32 version = 0;
	__be16 mask;
	u16 common;

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

	if (isv6) {
		data_len = sizeof(struct rds6_ib_connect_private);
		major = dp->ricp_v6.dp_protocol_major;
		minor = dp->ricp_v6.dp_protocol_minor;
		mask = dp->ricp_v6.dp_protocol_minor_mask;
	} else {
		data_len = sizeof(struct rds_ib_connect_private);
		major = dp->ricp_v4.dp_protocol_major;
		minor = dp->ricp_v4.dp_protocol_minor;
		mask = dp->ricp_v4.dp_protocol_minor_mask;
	}
	/* Even if len is crap *now* I still want to check it. -ASG */
	if (event->param.conn.private_data_len < data_len || major == 0)
		return RDS_PROTOCOL_4_0;

	common = be16_to_cpu(mask) & RDS_IB_SUPPORTED_PROTOCOLS;
	if (major == 4 && common) {
		version = RDS_PROTOCOL_4_0;
		while ((common >>= 1) != 0)
			version++;
	} else if (RDS_PROTOCOL_COMPAT_VERSION == RDS_PROTOCOL(major, minor)) {
		version = RDS_PROTOCOL_COMPAT_VERSION;
	} else {
		if (isv6) {
			printk_ratelimited(KERN_NOTICE "RDS: Connection from %pI6c using incompatible protocol version %u.%u\n",
					   &dp->ricp_v6.dp_saddr, major, minor);
		} else {
			printk_ratelimited(KERN_NOTICE "RDS: Connection from %pI4 using incompatible protocol version %u.%u\n",
					   &dp->ricp_v4.dp_saddr, major, minor);
		}
	}
	return version;
}

#if IS_ENABLED(CONFIG_IPV6)
/* Given an IPv6 address, find the net_device which hosts that address and
 * return its index.  This is used by the rds_ib_cm_handle_connect() code to
 * find the interface index of where an incoming request comes from when
 * the request is using a link local address.
 *
 * Note one problem in this search.  It is possible that two interfaces have
 * the same link local address.  Unfortunately, this cannot be solved unless
 * the underlying layer gives us the interface which an incoming RDMA connect
 * request comes from.
 */
static u32 __rds_find_ifindex(struct net *net, const struct in6_addr *addr)
{
	struct net_device *dev;
	int idx = 0;

	rcu_read_lock();
	for_each_netdev_rcu(net, dev) {
		if (ipv6_chk_addr(net, addr, dev, 1)) {
			idx = dev->ifindex;
			break;
		}
	}
	rcu_read_unlock();

	return idx;
}
#endif

int rds_ib_cm_handle_connect(struct rdma_cm_id *cm_id,
			     struct rdma_cm_event *event, bool isv6)
{
	__be64 lguid = cm_id->route.path_rec->sgid.global.interface_id;
	__be64 fguid = cm_id->route.path_rec->dgid.global.interface_id;
	const struct rds_ib_conn_priv_cmn *dp_cmn;
	struct rds_ib_connection *ic = NULL;
	struct rds_connection *conn = NULL;
	struct rdma_conn_param conn_param;
	const union rds_ib_conn_priv *dp;
	union rds_ib_conn_priv dp_rep;
	struct in6_addr s_mapped_addr;
	struct in6_addr d_mapped_addr;
	const struct in6_addr *saddr6;
	const struct in6_addr *daddr6;
	int destroy = 1;
	int acl_ret = 0;
	u32 ifindex = 0;
	u32 version;
	int err = 1;
	u16 frag;
	u8 cm_req_seq = 0;
	bool cm_seq_check_enable = false;

	/* Check whether the remote protocol version matches ours. */
	version = rds_ib_protocol_compatible(event, isv6);
	if (!version)
		goto out;

	dp = event->param.conn.private_data;
	if (isv6) {
#if IS_ENABLED(CONFIG_IPV6)
		dp_cmn = &dp->ricp_v6.dp_cmn;
		saddr6 = &dp->ricp_v6.dp_saddr;
		daddr6 = &dp->ricp_v6.dp_daddr;
		/* If either address is link local, need to find the
		 * interface index in order to create a proper RDS
		 * connection.
		 */
		if (ipv6_addr_type(daddr6) & IPV6_ADDR_LINKLOCAL ||
		    ipv6_addr_type(saddr6) & IPV6_ADDR_LINKLOCAL) {
			/* Using init_net for now ..  If peer address is
			 * link local, we also use our address to find the
			 * correct index.
			 */
			ifindex = __rds_find_ifindex(&init_net, daddr6);
			/* No index found...  Need to bail out. */
			if (ifindex == 0) {
				err = -EOPNOTSUPP;
				goto out;
			}
		}
		cm_seq_check_enable = dp->ricp_v6.dp_cm_seq & RDS_CM_RETRY_SEQ_EN;
		cm_req_seq = IB_GET_CM_SEQ_NUM(dp->ricp_v6.dp_cm_seq);
#else
		err = -EOPNOTSUPP;
		goto out;
#endif
	} else {
		dp_cmn = &dp->ricp_v4.dp_cmn;
		ipv6_addr_set_v4mapped(dp->ricp_v4.dp_saddr, &s_mapped_addr);
		ipv6_addr_set_v4mapped(dp->ricp_v4.dp_daddr, &d_mapped_addr);
		saddr6 = &s_mapped_addr;
		daddr6 = &d_mapped_addr;
		cm_seq_check_enable = dp->ricp_v4.dp_cm_seq & RDS_CM_RETRY_SEQ_EN;
		cm_req_seq = IB_GET_CM_SEQ_NUM(dp->ricp_v4.dp_cm_seq);
	}

	rds_rtd_ptr(RDS_RTD_CM,
		    "<%pI6c,%pI6c,%d> RDSv%u.%u lguid 0x%llx fguid 0x%llx\n",
		    saddr6, daddr6, dp_cmn->ricpc_tos,
		    RDS_PROTOCOL_MAJOR(version),
		    RDS_PROTOCOL_MINOR(version),
		    (unsigned long long)be64_to_cpu(lguid),
		    (unsigned long long)be64_to_cpu(fguid));

#ifdef CONFIG_RDS_ACL

	acl_ret = rds_ib_match_acl(cm_id, saddr6);
	if (acl_ret < 0) {
		err = RDS_ACL_FAILURE;
		rdsdebug("RDS: IB: passive: rds_ib_match_acl failed\n");
		goto out;
	}

#else /* !CONFIG_RDS_ACL */

	acl_ret = 0;

#endif /* !CONFIG_RDS_ACL */

	/* RDS/IB is not currently netns aware, thus init_net */
	conn = rds_conn_create(&init_net, daddr6, saddr6,
			       &rds_ib_transport, dp_cmn->ricpc_tos,
			       GFP_KERNEL, ifindex);

	if (IS_ERR(conn)) {
		rds_rtd(RDS_RTD_ERR, "rds_conn_create failed (%ld)\n",
			PTR_ERR(conn));
		conn = NULL;
		goto out;
	}

	rds_ib_set_protocol(conn, version);

	conn->c_acl_en = acl_ret;
	conn->c_acl_init = 1;

	/*
	 * The connection request may occur while the
	 * previous connection exist, e.g. in case of failover.
	 * But as connections may be initiated simultaneously
	 * by both hosts, we have a random backoff mechanism -
	 * see the comment above rds_queue_reconnect()
	 */
	mutex_lock(&conn->c_cm_lock);
	ic = conn->c_transport_data;

	if (ic && cm_seq_check_enable) {
		if (cm_req_seq != ic->i_prev_seq) {
			rds_rtd(RDS_RTD_CM_EXT_P,
				"cm_id %p conn %p updating ic->i_prev_seq %d cm_req_seq %d\n",
				cm_id, conn, ic->i_prev_seq, cm_req_seq);
			ic->i_prev_seq = cm_req_seq;
		} else if (cm_req_seq == ic->i_prev_seq && ic->i_last_rej_seq == cm_req_seq) {
			rds_rtd(RDS_RTD_CM_EXT_P,
				"duplicated REQ cm_id %p conn %p reject! ic->i_last_rej_seq %d cm_req_seq %d\n",
				cm_id, conn, ic->i_last_rej_seq, cm_req_seq);
			goto out;
		}
	}

	if (!rds_conn_transition(conn, RDS_CONN_DOWN, RDS_CONN_CONNECTING)) {
		/*
		 * in both of the cases below, the conn is half setup.
		 * we need to make sure the lower layers don't destroy it
		 */
		if (rds_ib_same_cm_id(ic, cm_id))
			destroy = 0;
		if (rds_conn_state(conn) == RDS_CONN_UP) {
			rds_rtd(RDS_RTD_CM_EXT_P,
				"conn %p <%pI6c,%pI6c,%d> incoming connect in UP state\n",
				conn, &conn->c_laddr, &conn->c_faddr, conn->c_tos);
			rds_conn_drop(conn, DR_IB_REQ_WHILE_CONN_UP);
			rds_ib_stats_inc(s_ib_listen_closed_stale);
			conn->c_reconnect_racing++;
		} else if (rds_conn_state(conn) == RDS_CONN_CONNECTING) {
			unsigned long now = get_seconds();
			conn->c_reconnect_racing++;

			/* When a race is detected, one side should fall back
			 * to passive and let the active side to reconnect.
			 * If the connection is in CONNECTING and still receive
			 * multiple back-to-back REQ, it means something is
			 * horribly wrong. Thus, drop the connection.
			 */
			if (conn->c_reconnect_racing > 5) {
				rds_rtd_ptr(RDS_RTD_CM,
					    "conn %p <%pI6c,%pI6c,%d> back-to-back REQ, reset\n",
					    conn, &conn->c_laddr, &conn->c_faddr, conn->c_tos);
				conn->c_reconnect_racing = 0;
				rds_conn_drop(conn, DR_IB_REQ_WHILE_CONNECTING);
			/* After 15 seconds, give up on existing connection
			 * attempts and make them try again.  At this point
			 * it's no longer a race but something has gone
			 * horribly wrong.
			 */
			} else if (now > conn->c_connection_start &&
			    now - conn->c_connection_start > 15) {
				rds_rtd_ptr(RDS_RTD_CM,
					    "conn %p <%pI6c,%pI6c,%d> racing for 15s, forcing reset\n",
					    conn, &conn->c_laddr, &conn->c_faddr, conn->c_tos);
				rds_conn_drop(conn, DR_IB_REQ_WHILE_CONNECTING);
				rds_ib_stats_inc(s_ib_listen_closed_stale);
			} else {
				/* Wait and see - our connect may still be succeeding */
				rds_rtd_ptr(RDS_RTD_CM,
					    "conn %p <%pI6c,%pI6c,%d> racing, wait and see\n",
					    conn, &conn->c_laddr, &conn->c_faddr, conn->c_tos);
				rds_ib_stats_inc(s_ib_connect_raced);
			}
		}
		if (ic && cm_seq_check_enable)
			ic->i_last_rej_seq = cm_req_seq;
		goto out;
	}

	ic = conn->c_transport_data;

	/*
	 * record the time we started trying to connect so that we can
	 * drop the connection if it doesn't work out after a while
	 */
	conn->c_connection_start = get_seconds();

	rds_ib_set_flow_control(conn, be32_to_cpu(dp_cmn->ricpc_credit));
	/* Use ic->i_flowctl as the first post credit to enable
	 * IB transport flow control. This first post credit is
	 * deducted after advertise the credit to the remote
	 * connection.
	 */
	atomic_set(&ic->i_credits, IB_SET_POST_CREDITS(ic->i_flowctl));

	/* If the peer gave us the last packet it saw, process this as if
	 * we had received a regular ACK. */
	if (dp_cmn->ricpc_ack_seq)
		rds_send_drop_acked(conn, be64_to_cpu(dp_cmn->ricpc_ack_seq),
				    NULL);

	BUG_ON(rds_ib_get_conn(cm_id));
	BUG_ON(ic->i_cm_id);

	ic->i_cm_id = cm_id;
	cm_id->context = rds_ib_map_conn(conn);

	/* We got halfway through setting up the ib_connection, if we
	 * fail now, we have to take the long route out of this mess. */
	destroy = 0;

	err = rds_ib_setup_qp(conn);
	if (err) {
		pr_warn("RDS/IB: rds_ib_setup_qp failed with err(%d) for conn <%pI6c,%pI6c,%d>\n",
			err, &conn->c_laddr, &conn->c_faddr, conn->c_tos);
		rds_conn_drop(conn, DR_IB_PAS_SETUP_QP_FAIL);
		goto out;
	}
	frag = rds_ib_set_frag_size(conn, be16_to_cpu(dp_cmn->ricpc_frag_sz));

	rds_ib_cm_fill_conn_param(conn, &conn_param, &dp_rep, version,
				  event->param.conn.responder_resources,
				  event->param.conn.initiator_depth,
				  frag, isv6, cm_req_seq);

	/* rdma_accept() calls rdma_reject() internally if it fails */
	err = rdma_accept(cm_id, &conn_param);
	if (err) {
		pr_warn("RDS/IB: rdma_accept failed with err(%d) for conn <%pI6c,%pI6c,%d>\n",
			err, &conn->c_laddr, &conn->c_faddr, conn->c_tos);
		rds_conn_drop(conn, DR_IB_RDMA_ACCEPT_FAIL);
	}

out:
	if (conn)
		mutex_unlock(&conn->c_cm_lock);
	if (err)
		rdma_reject(cm_id, &err, sizeof(int));
	return destroy;
}

void rds_ib_conn_destroy_worker(struct work_struct *_work)
{
	struct rds_ib_conn_destroy_work    *work =
		container_of(_work, struct rds_ib_conn_destroy_work, work.work);
	struct rds_connection   *conn = work->conn;

	rds_conn_destroy(conn, 0);

	kfree(work);
}

void rds_ib_conn_destroy_init(struct rds_connection *conn)
{
	struct rds_ib_conn_destroy_work *work;

	work = kzalloc(sizeof *work, GFP_ATOMIC);
	if (!work) {
		pr_err("RDS/IB: failed to allocate connection destroy work\n");
		return;
	}

	work->conn = conn;
	INIT_DELAYED_WORK(&work->work, rds_ib_conn_destroy_worker);
	queue_delayed_work(rds_aux_wq, &work->work, 0);
}

int rds_ib_cm_initiate_connect(struct rdma_cm_id *cm_id, bool isv6)
{
	struct rds_connection *conn = rds_ib_get_conn(cm_id);
	struct rds_ib_connection *ic = conn->c_transport_data;
	struct rdma_conn_param conn_param;
	union rds_ib_conn_priv dp;
	u16 frag;
	int ret;
	u8 seq;

#ifdef CONFIG_RDS_ACL

	ret = rds_ib_match_acl(ic->i_cm_id, &conn->c_faddr);
	if (ret < 0) {
		pr_err("RDS: IB: active conn %p <%pI6c,%pI6c,%d> destroyed due ACL violation\n",
		       conn, &conn->c_laddr, &conn->c_faddr, conn->c_tos);
		rds_rtd_ptr(RDS_RTD_CM,
			    "active conn %p <%pI6c,%pI6c,%d> destroyed due ACL violation\n",
			    conn, &conn->c_laddr, &conn->c_faddr, conn->c_tos);
		rds_ib_conn_destroy_init(conn);
		return 0;
	}

#else /* !CONFIG_RDS_ACL */

	ret = 0;

#endif /* !CONFIG_RDS_ACL */

	conn->c_acl_en = ret;
	conn->c_acl_init = 1;

	rds_ib_set_protocol(conn, RDS_PROTOCOL_4_1);
	ic->i_flowctl = rds_ib_sysctl_flow_control;	/* advertise flow control */
	/* Use ic->i_flowctl as the first post credit to enable
	 * IB transport flow control. This first post credit is
	 * deducted after advertise the credit to the remote
	 * connection.
	 */
	atomic_set(&ic->i_credits, IB_SET_POST_CREDITS(ic->i_flowctl));

	rds_rtd_ptr(RDS_RTD_CM,
		    "RDS/IB: Initiate conn %p <%pI6c,%pI6c,%d> with Frags <init,ic>: {%d,%d}\n",
		    conn, &conn->c_laddr, &conn->c_faddr, conn->c_tos,
		    ib_init_frag_size / SZ_1K, ic->i_frag_sz / SZ_1K);

	ret = rds_ib_setup_qp(conn);
	if (ret) {
		rds_rtd(RDS_RTD_CM, "RDS/IB: rds_ib_setup_qp failed (%d)\n", ret);
		rds_conn_drop(conn, DR_IB_ACT_SETUP_QP_FAIL);
		goto out;
	}
	frag = rds_ib_set_frag_size(conn, ib_init_frag_size);
	ic->i_req_sequence = IB_GET_CM_SEQ_NUM(ic->i_req_sequence + 1);
	seq = RDS_CM_RETRY_SEQ_EN | ic->i_req_sequence;
	rds_ib_cm_fill_conn_param(conn, &conn_param, &dp,
				  conn->c_proposed_version, UINT_MAX, UINT_MAX,
				  frag, isv6, seq);
	ret = rdma_connect(cm_id, &conn_param);
	if (ret) {
		rds_rtd(RDS_RTD_CM, "RDS/IB: rdma_connect failed (%d)\n", ret);
		rds_conn_drop(conn, DR_IB_RDMA_CONNECT_FAIL);
	}

out:
	/* Beware - returning non-zero tells the rdma_cm to destroy
	 * the cm_id. We should certainly not do it as long as we still
	 * "own" the cm_id. */
	if (ret) {
		if (rds_ib_same_cm_id(ic, cm_id))
			ret = 0;
	}

	ic->i_active_side = 1;
	return ret;
}

int rds_ib_conn_path_connect(struct rds_conn_path *cp)
{
	struct rds_connection *conn = cp->cp_conn;
	struct sockaddr_storage src, dest;
	rdma_cm_event_handler handler;
	struct rds_ib_connection *ic;
	int ret;

	ic = conn->c_transport_data;

	rds_rtd(RDS_RTD_CM, "conn: %p now start:%lu\n", conn, jiffies);
	conn->c_path->cp_conn_start_jf = jiffies;

	/* XXX I wonder what affect the port space has */
	/* delegate cm event handler to rdma_transport */
#if IS_ENABLED(CONFIG_IPV6)
	if (conn->c_isv6)
		handler = rds6_rdma_cm_event_handler;
	else
#endif
		handler = rds_rdma_cm_event_handler;
	ic->i_cm_id = rds_ib_rdma_create_id(rds_conn_net(conn),
					    handler, conn, RDMA_PS_TCP, IB_QPT_RC);

	if (IS_ERR(ic->i_cm_id)) {
		ret = PTR_ERR(ic->i_cm_id);
		ic->i_cm_id = NULL;
		rds_rtd(RDS_RTD_ERR, "rds_ib_rdma_create_id() failed: %d\n", ret);
		goto out;
	}

	rds_rtd(RDS_RTD_CM_EXT,
		"RDS/IB: conn init <%pI6c,%pI6c,%d> cm_id %p\n",
		&conn->c_laddr, &conn->c_faddr,
		conn->c_tos, ic->i_cm_id);

	if (ipv6_addr_v4mapped(&conn->c_faddr)) {
		struct sockaddr_in *sin;

		sin = (struct sockaddr_in *)&src;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = conn->c_laddr.s6_addr32[3];
		sin->sin_port = 0;

		sin = (struct sockaddr_in *)&dest;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = conn->c_faddr.s6_addr32[3];
		sin->sin_port = htons(RDS_PORT);
	} else {
		struct sockaddr_in6 *sin6;

		sin6 = (struct sockaddr_in6 *)&src;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = conn->c_laddr;
		sin6->sin6_port = 0;
		sin6->sin6_scope_id = conn->c_dev_if;

		sin6 = (struct sockaddr_in6 *)&dest;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = conn->c_faddr;
		sin6->sin6_port = htons(RDS_CM_PORT);
		sin6->sin6_scope_id = conn->c_dev_if;
	}

	ret = rdma_resolve_addr(ic->i_cm_id, (struct sockaddr *)&src,
				(struct sockaddr *)&dest,
				RDS_RDMA_RESOLVE_TIMEOUT_MS);
	if (ret) {
		rds_rtd(RDS_RTD_ERR, "addr resolve failed for cm id %p: %d\n",
			ic->i_cm_id, ret);
		rds_ib_rdma_destroy_id(ic->i_cm_id);

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
void rds_ib_conn_path_shutdown(struct rds_conn_path *cp)
{
	struct rds_connection *conn = cp->cp_conn;
	struct rds_ib_connection *ic = conn->c_transport_data;
	int err = 0;

	rds_rtd_ptr(RDS_RTD_CM_EXT, "conn %p cm_id %p pd %p cq %p qp %p\n",
		    conn, ic->i_cm_id, ic->i_pd, ic->i_rcq, ic->i_cm_id ? ic->i_cm_id->qp : NULL);

	if (ic->i_cm_id) {
		struct ib_device *dev = ic->i_cm_id->device;

		rds_rtd_ptr(RDS_RTD_CM_EXT, "disconnecting conn %p cm_id %p\n", conn, ic->i_cm_id);
		err = rdma_disconnect(ic->i_cm_id);
		if (err) {
			/* Actually this may happen quite frequently, when
			 * an outgoing connect raced with an incoming connect.
			 */
			rds_rtd(RDS_RTD_CM_EXT_P,
				"failed to disconnect, cm: %p err %d\n",
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
		while (!wait_event_timeout(rds_ib_ring_empty_wait,
				(rds_ib_ring_empty(&ic->i_recv_ring) &&
				 (atomic_read(&ic->i_signaled_sends) == 0) &&
				 (atomic_read(&ic->i_fastreg_wrs) ==
				  RDS_IB_DEFAULT_FREG_WR)) ||
				(ic->i_flags & RDS_IB_CQ_ERR),
				 msecs_to_jiffies(5000))) {

			if (ic->i_flags & RDS_IB_CQ_ERR)
				break;

			/* Try to reap pending RX completions every 5 secs */
			if (!rds_ib_ring_empty(&ic->i_recv_ring)) {
				spin_lock_bh(&ic->i_rx_lock);
				rds_ib_rx(ic);
				spin_unlock_bh(&ic->i_rx_lock);
			}
		}

		tasklet_kill(&ic->i_stasklet);
		tasklet_kill(&ic->i_rtasklet);

		atomic_set(&ic->i_cq_quiesce, 1);
		ic->i_flags &= ~RDS_IB_CQ_ERR;

		/* first destroy the ib state that generates callbacks */
		if (ic->i_cm_id->qp)
			rdma_destroy_qp(ic->i_cm_id);

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

		rds_ib_rdma_destroy_id(ic->i_cm_id);

		/*
		 * Move connection back to the nodev list.
		 */
		if (ic->rds_ibdev)
			rds_ib_remove_conn(ic->rds_ibdev, conn);

		ic->i_cm_id = NULL;
		ic->i_pd = NULL;
		ic->i_mr = NULL;
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
	rds_ib_init_ic_frag(ic);

	if (ic->i_ibinc) {
		rds_inc_put(&ic->i_ibinc->ii_inc);
		ic->i_ibinc = NULL;
	}

	vfree(ic->i_sends);
	ic->i_sends = NULL;
	if (!rds_ib_srq_enabled)
		vfree(ic->i_recvs);

	ic->i_recvs = NULL;

	reinit_completion(&ic->i_last_wqe_complete);

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
	spin_lock_init(&ic->i_rx_lock);

	/*
	 * rds_ib_conn_path_shutdown() waits for these to be emptied so they
	 * must be initialized before it can be called.
	 */
	rds_ib_ring_init(&ic->i_send_ring, rds_ib_sysctl_max_send_wr);
	rds_ib_ring_init(&ic->i_recv_ring, rds_ib_sysctl_max_recv_wr);

	/* Might want to change this hard-coded value to a variable in future.
	 * Updating this atomic counter will need an update to qp/cq size too.
	 */
	atomic_set(&ic->i_fastreg_wrs, RDS_IB_DEFAULT_FREG_WR);

	rds_ib_init_ic_frag(ic);

	ic->conn = conn;
	conn->c_transport_data = ic;

	init_completion(&ic->i_last_wqe_complete);

	INIT_DELAYED_WORK(&ic->i_rx_w.work, rds_ib_rx_handler);

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

	if (ic->i_rcq) {
		if (ic->rds_ibdev)
			ibdev_put_vector(ic->rds_ibdev, ic->i_rcq_vector);
		ib_destroy_cq(ic->i_rcq);
	}

	if (ic->i_scq) {
		if (ic->rds_ibdev)
			ibdev_put_vector(ic->rds_ibdev, ic->i_scq_vector);
		ib_destroy_cq(ic->i_scq);
	}

	kfree(ic);
}

void rds_ib_destroy_fastreg(struct rds_ib_device *rds_ibdev)
{
	/* Because we are using rw_lock, by this point we should have
	 * received completions for all the wrs posted
	 */
	WARN_ON(atomic_read(&rds_ibdev->fastreg_wrs) != RDS_IB_DEFAULT_FREG_WR);

	tasklet_kill(&rds_ibdev->fastreg_tasklet);
	if (rds_ibdev->fastreg_qp) {
		/* Destroy qp */
		if (ib_destroy_qp(rds_ibdev->fastreg_qp))
			pr_err("Error destroying fastreg qp for rds_ibdev: %p\n",
			       rds_ibdev);
		rds_ibdev->fastreg_qp = NULL;
	}

	if (rds_ibdev->fastreg_cq) {
		/* Destroy cq and cq_vector */
		if (ib_destroy_cq(rds_ibdev->fastreg_cq))
			pr_err("Error destroying fastreg cq for rds_ibdev: %p\n",
			       rds_ibdev);
		rds_ibdev->fastreg_cq = NULL;
		ibdev_put_vector(rds_ibdev, rds_ibdev->fastreg_cq_vector);
	}
}

int rds_ib_setup_fastreg(struct rds_ib_device *rds_ibdev)
{
	int ret = 0;
	struct ib_cq_init_attr cq_attr;
	struct ib_qp_init_attr qp_init_attr;
	struct ib_qp_attr qp_attr;
	struct ib_port_attr port_attr;
	int gid_index = 0;
	union ib_gid dgid;

	rds_ibdev->fastreg_cq_vector = ibdev_get_unused_vector(rds_ibdev);
	memset(&cq_attr, 0, sizeof(cq_attr));
	cq_attr.cqe = RDS_IB_DEFAULT_FREG_WR + 1;
	cq_attr.comp_vector = rds_ibdev->fastreg_cq_vector;
	rds_ibdev->fastreg_cq = ib_create_cq(rds_ibdev->dev,
					     rds_ib_cq_comp_handler_fastreg,
					     rds_ib_cq_event_handler,
					     rds_ibdev,
					     &cq_attr);
	if (IS_ERR(rds_ibdev->fastreg_cq)) {
		ret = PTR_ERR(rds_ibdev->fastreg_cq);
		rds_ibdev->fastreg_cq = NULL;
		ibdev_put_vector(rds_ibdev, rds_ibdev->fastreg_cq_vector);
		rds_rtd(RDS_RTD_ERR, "ib_create_cq failed: %d\n", ret);
		goto clean_up;
	}

	ret = ib_req_notify_cq(rds_ibdev->fastreg_cq, IB_CQ_NEXT_COMP);
	if (ret)
		goto clean_up;
	rds_rtd(RDS_RTD_RDMA_IB,
		"Successfully created fast reg cq for ib_device: %p\n",
		rds_ibdev->dev);

	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.send_cq		= rds_ibdev->fastreg_cq;
	qp_init_attr.recv_cq		= rds_ibdev->fastreg_cq;
	qp_init_attr.qp_type		= IB_QPT_RC;
	/* 1 WR is used for invalidaton */
	qp_init_attr.cap.max_send_wr	= RDS_IB_DEFAULT_FREG_WR + 1;
	qp_init_attr.cap.max_recv_wr	= 0;
	qp_init_attr.cap.max_send_sge	= 0;
	qp_init_attr.cap.max_recv_sge	= 0;
	qp_init_attr.sq_sig_type	= IB_SIGNAL_REQ_WR;

	rds_ibdev->fastreg_qp = ib_create_qp(rds_ibdev->pd, &qp_init_attr);
	if (IS_ERR(rds_ibdev->fastreg_qp)) {
		ret = PTR_ERR(rds_ibdev->fastreg_qp);
		rds_ibdev->fastreg_qp = NULL;
		rds_rtd(RDS_RTD_ERR, "ib_create_qp failed: %d\n", ret);
		goto clean_up;
	}
	rds_rtd(RDS_RTD_RDMA_IB,
		"Successfully created fast reg qp for ib_device: %p\n",
		rds_ibdev->dev);

	/* Use modify_qp verb to change the state from RESET to INIT */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state	= IB_QPS_INIT;
	qp_attr.pkey_index	= 0;
	qp_attr.qp_access_flags	= IB_ACCESS_REMOTE_READ |
				  IB_ACCESS_REMOTE_WRITE;
	qp_attr.port_num	= RDS_IB_DEFAULT_FREG_PORT_NUM;

	ret = ib_modify_qp(rds_ibdev->fastreg_qp, &qp_attr, IB_QP_STATE	|
						IB_QP_PKEY_INDEX	|
						IB_QP_ACCESS_FLAGS	|
						IB_QP_PORT);
	if (ret) {
		rds_rtd(RDS_RTD_ERR, "ib_modify_qp to IB_QPS_INIT failed: %d\n",
			ret);
		goto clean_up;
	}
	rds_rtd(RDS_RTD_RDMA_IB,
		"Successfully moved qp to INIT state for ib_device: %p\n",
		rds_ibdev->dev);

	/* query port to get the lid */
	ret = ib_query_port(rds_ibdev->dev, RDS_IB_DEFAULT_FREG_PORT_NUM,
			    &port_attr);
	if (ret) {
		rds_rtd(RDS_RTD_ERR, "ib_query_port failed: %d\n", ret);
		goto clean_up;
	}
	rds_rtd(RDS_RTD_RDMA_IB,
		"Successfully queried the port and the port is in %d state\n",
		port_attr.state);

	ret = ib_query_gid(rds_ibdev->dev, RDS_IB_DEFAULT_FREG_PORT_NUM,
			   gid_index, &dgid, NULL);
	if (ret) {
		rds_rtd(RDS_RTD_ERR, "ib_query_gid failed: %d\n", ret);
		goto clean_up;
	}
	rds_rtd(RDS_RTD_RDMA_IB,
		"Successfully queried the gid_index %d and the gid is " RDS_IB_GID_FMT "\n",
		gid_index, RDS_IB_GID_ARG(dgid));

	/* Use modify_qp verb to change the state from INIT to RTR */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state	= IB_QPS_RTR;
	qp_attr.path_mtu	= IB_MTU_256;
	qp_attr.dest_qp_num	= rds_ibdev->fastreg_qp->qp_num;
	qp_attr.rq_psn		= 1;
	qp_attr.ah_attr.sl		= 0;
	qp_attr.ah_attr.port_num	= RDS_IB_DEFAULT_FREG_PORT_NUM;
	if (rdma_protocol_roce(rds_ibdev->dev, RDS_IB_DEFAULT_FREG_PORT_NUM)) {
		qp_attr.ah_attr.type		= RDMA_AH_ATTR_TYPE_ROCE;
		qp_attr.ah_attr.ah_flags        = IB_AH_GRH;
		qp_attr.ah_attr.grh.dgid	= dgid;
		qp_attr.ah_attr.grh.sgid_index	= gid_index;
	} else if (rdma_protocol_ib(rds_ibdev->dev, RDS_IB_DEFAULT_FREG_PORT_NUM)) {
		qp_attr.ah_attr.type		= RDMA_AH_ATTR_TYPE_IB;
		qp_attr.ah_attr.ib.dlid		= port_attr.lid;
	} else {
		rds_rtd(RDS_RTD_ERR, "Unexpected port type\n");
		goto clean_up;
	}

	ret = ib_modify_qp(rds_ibdev->fastreg_qp, &qp_attr, IB_QP_STATE	|
						IB_QP_AV		|
						IB_QP_PATH_MTU		|
						IB_QP_DEST_QPN		|
						IB_QP_RQ_PSN		|
						IB_QP_MAX_DEST_RD_ATOMIC |
						IB_QP_MIN_RNR_TIMER);
	if (ret) {
		rds_rtd(RDS_RTD_ERR, "ib_modify_qp to IB_QPS_RTR failed: %d\n",
			ret);
		goto clean_up;
	}
	rds_rtd(RDS_RTD_RDMA_IB,
		"Successfully moved qp to RTR state for ib_device: %p\n",
		rds_ibdev->dev);

	/* Use modify_qp verb to change the state from RTR to RTS */
	memset(&qp_attr, 0, sizeof(qp_attr));
	qp_attr.qp_state	= IB_QPS_RTS;
	qp_attr.sq_psn		= 1;
	qp_attr.timeout		= 14;
	qp_attr.retry_cnt	= 6;
	qp_attr.rnr_retry	= 6;
	qp_attr.max_rd_atomic	= 1;

	ret = ib_modify_qp(rds_ibdev->fastreg_qp, &qp_attr, IB_QP_STATE	|
						IB_QP_TIMEOUT		|
						IB_QP_RETRY_CNT		|
						IB_QP_RNR_RETRY		|
						IB_QP_SQ_PSN		|
						IB_QP_MAX_QP_RD_ATOMIC);
	if (ret) {
		rds_rtd(RDS_RTD_ERR, "ib_modify_qp to IB_QPS_RTS failed: %d\n",
			ret);
		goto clean_up;
	}
	rds_rtd(RDS_RTD_RDMA_IB,
		"Successfully moved qp to RTS state for ib_device: %p\n",
		rds_ibdev->dev);

	tasklet_init(&rds_ibdev->fastreg_tasklet, rds_ib_tasklet_fn_fastreg,
		     (unsigned long)rds_ibdev);
	atomic_set(&rds_ibdev->fastreg_wrs, RDS_IB_DEFAULT_FREG_WR);

clean_up:
	if (ret)
		rds_ib_destroy_fastreg(rds_ibdev);
	return ret;
}

void rds_ib_reset_fastreg(struct work_struct *work)
{
	struct rds_ib_device *rds_ibdev = container_of(work,
						       struct rds_ib_device,
						       fastreg_reset_w);

	pr_warn("RDS: IB: Resetting fastreg qp\n");
	/* Acquire write lock to stop posting on fastreg qp before resetting */
	down_write(&rds_ibdev->fastreg_lock);

	rds_ib_destroy_fastreg(rds_ibdev);
	if (rds_ib_setup_fastreg(rds_ibdev)) {
		/* Failing to setup fastreg qp at this stage is unexpected.
		 * If it happens, throw a warning, and return immediately,
		 * without up_writing the fastreg_lock.
		 */
		pr_err("RDS: IB: Failed to setup fastreg resources in %s\n",
		       __func__);
		WARN_ON(1);
		return;
	}

	up_write(&rds_ibdev->fastreg_lock);
	pr_warn("RDS: IB: Finished resetting fastreg qp\n");
}
