/* SPDX-License-Identifier: GPL-2.0-only */
/* Trace point definitions for RDS (Reliable Datagram Socket) events.
 *
 * Author: Alan Maguire <alan.maguire@oracle.com>
 *
 * Copyright (c) 2020, Oracle and/or its affiliates.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM rds
#if !defined(_TRACE_RDS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_RDS_H

#include <linux/tracepoint.h>
#include <linux/in6.h>
#include <linux/rds.h>
#include <linux/tcp.h>
#include <linux/cgroup.h>
#include "rds.h"
#include "ib.h"
#include "tcp.h"

#define show_state(state)						\
	__print_symbolic(state,						\
		{ -1,				"invalid" },		\
		{ RDS_CONN_DOWN,		"down" },		\
		{ RDS_CONN_CONNECTING,		"connecting" },		\
		{ RDS_CONN_DISCONNECTING,	"disconnecting" },	\
		{ RDS_CONN_UP,			"up" },			\
		{ RDS_CONN_RESETTING,		"resetting" },		\
		{ RDS_CONN_ERROR,		"error" })

#define show_transport(transport)					\
	__print_symbolic(transport,					\
		{ RDS_TRANS_NONE,		"?" },			\
		{ RDS_TRANS_IB,			"IB" },			\
		{ RDS_TRANS_TCP,		"TCP" },		\
		{ RDS_TRANS_COUNT,		"LOOPBACK" })

#define show_flags(flags)						\
	__print_flags(flags, "|",					\
		{ 1 << RDS_LL_SEND_FULL,	"ll_send_full" },	\
		{ 1 << RDS_RECONNECT_PENDING,	"reconnect_pending" },	\
		{ 1 << RDS_IN_XMIT,		"in_xmit" },		\
		{ 1 << RDS_RECV_REFILL,		"recv_refill" },	\
		{ 1 << RDS_DESTROY_PENDING,	"destroy_pending" })

#define show_send_status(status)					\
	__print_symbolic(status,					\
		{ RDS_RDMA_SEND_SUCCESS,	"success" },		\
		{ RDS_RDMA_REMOTE_ERROR,	"remote error" },	\
		{ RDS_RDMA_SEND_CANCELED,	"send canceled" },	\
		{ RDS_RDMA_SEND_DROPPED,	"send dropped" },	\
		{ RDS_RDMA_SEND_OTHER_ERROR,	"other error" })

#define show_tcp_state(state)						\
	__print_symbolic(state,						\
		{ TCP_ESTABLISHED,		"established" },	\
		{ TCP_SYN_SENT,			"syn-sent" },		\
		{ TCP_SYN_RECV,			"syn-recv" },		\
		{ TCP_FIN_WAIT1,		"fin-wait1" },		\
		{ TCP_FIN_WAIT2,		"fin-wait2" },		\
		{ TCP_TIME_WAIT,		"time-wait" },		\
		{ TCP_CLOSE,			"close" },		\
		{ TCP_CLOSE_WAIT,		"close-wait" },		\
		{ TCP_LAST_ACK,			"last-ack" },		\
		{ TCP_LISTEN,			"listen" },		\
		{ TCP_CLOSING,			"closing" })

#define RDS_STRSIZE	64
#define RDS_STRSCPY(dst, src)   strscpy(dst, src ? src : "<none>",	\
					ARRAY_SIZE(dst))

/*
 * Fields common to all tracepoints.  Sharing a common set of fields
 * simplifies BPF programs which attach to RDS tracepoints.
 */
#define RDS_TRACE_COMMON_FIELDS			\
	__array(__u8, laddr, 16)		\
	__array(__u8, faddr, 16)		\
	__field(__u8, tos)			\
	__field(unsigned int, transport)	\
	__field(__u16, lport)			\
	__field(__u16, fport)			\
	__field(__u64, netns_inum)		\
	__field(__u32, qp_num)			\
	__field(__u32, remote_qp_num)		\
	__field(unsigned long, flags)		\
	__field(int, err)			\
	__array(char, reason, RDS_STRSIZE)	\
	__field(__u64, cgroup_id)		\
	__field(void *, cgroup)			\
	__field(void *, rm)			\
	__field(void *, rs)			\
	__field(void *, conn)			\
	__field(void *, cp)

#define rds_cgroup_id(cgrp)	((cgrp) ? cgroup_id(cgrp) : 0)

#define rds_netns_inum(rs)	(rs ? rds_rs_to_ns_inum(rs) : 0)

DECLARE_EVENT_CLASS(rds_state,

	TP_PROTO(struct rds_conn_path *cp, char *reason, int err,
		 int last, int curr),

	TP_ARGS(cp, reason, err, last, curr),

	TP_STRUCT__entry(
		RDS_TRACE_COMMON_FIELDS
		__field(int, last)
		__field(int, curr)
	),

	TP_fast_assign(
		struct rds_connection *conn = cp->cp_conn;
		struct rds_message *rm = cp->cp_xmit_rm;
		struct rds_sock *rs = rm ? rm->m_rs : NULL;
		struct cgroup *cgrp;
		struct in6_addr *in6;

		in6 = (struct in6_addr *)__entry->laddr;
		*in6 = conn ? conn->c_laddr : in6addr_any;
		in6 = (struct in6_addr *)__entry->faddr;
		*in6 = conn ? conn->c_faddr : in6addr_any;
		__entry->tos = conn ? conn->c_tos : 0;
		__entry->transport = conn ? conn->c_trans->t_type :
					    RDS_TRANS_NONE;
		__entry->lport = rs ? rs->rs_bound_port : 0;
		__entry->fport = rs ? rs->rs_conn_port : 0;
		__entry->netns_inum = rds_netns_inum(rs);
		__entry->qp_num = rds_qp_num(conn, 0);
		__entry->remote_qp_num = rds_qp_num(conn, 1);
		__entry->flags = cp->cp_flags;
		RDS_STRSCPY(__entry->reason, reason);
		__entry->err = err;
		cgrp = rds_rs_to_cgroup(rs);
		__entry->cgroup = cgrp;
		__entry->cgroup_id = rds_cgroup_id(cgrp);
		__entry->rm = cp->cp_xmit_rm;
		__entry->rs = rs;
		__entry->conn = conn;
		__entry->cp = cp;
		__entry->last = last;
		__entry->curr = curr;
	),

	TP_printk("RDS/%s: <%pI6c,%pI6c,%d> state [%s -> %s], flags [%s] reason [%s] err [%d]",
		  show_transport(__entry->transport),
		  __entry->laddr, __entry->faddr, __entry->tos,
		  show_state(__entry->last), show_state(__entry->curr),
		  show_flags(__entry->flags), __entry->reason, __entry->err)
);

DEFINE_EVENT(rds_state, rds_state_change,

	TP_PROTO(struct rds_conn_path *cp, char *reason, int err,
		 int last, int curr),

	TP_ARGS(cp, reason, err, last, curr)

);

DEFINE_EVENT(rds_state, rds_state_change_err,

	TP_PROTO(struct rds_conn_path *cp, char *reason, int err,
		 int last, int curr),

	TP_ARGS(cp, reason, err, last, curr)

);

DECLARE_EVENT_CLASS(rds_status,

	TP_PROTO(struct rds_sock *rs, struct rds_connection *conn,
		 struct rds_conn_path *cp, char *reason, int err),

	TP_ARGS(rs, conn, cp, reason, err),

	TP_STRUCT__entry(
		RDS_TRACE_COMMON_FIELDS
	),

	TP_fast_assign(
		struct in6_addr *in6;
		struct cgroup *cgrp;

		in6 = (struct in6_addr *)__entry->laddr;
		*in6 = conn ? conn->c_laddr : in6addr_any;
		in6 = (struct in6_addr *)__entry->faddr;
		*in6 = conn ? conn->c_faddr : in6addr_any;
		__entry->tos = conn ? conn->c_tos : 0;
		__entry->transport = conn ? conn->c_trans->t_type :
					    RDS_TRANS_NONE;
		__entry->lport = rs ? rs->rs_bound_port : 0;
		__entry->fport = rs ? rs->rs_conn_port : 0;
		__entry->netns_inum = rds_netns_inum(rs);
		__entry->qp_num = rds_qp_num(conn, 0);
		__entry->remote_qp_num = rds_qp_num(conn, 1);
		__entry->flags = cp ? cp->cp_flags : 0;
		RDS_STRSCPY(__entry->reason, reason);
		__entry->err = err;
		cgrp = rds_rs_to_cgroup(rs);
		__entry->cgroup = cgrp;
		__entry->cgroup_id = rds_cgroup_id(cgrp);
		__entry->rm = NULL;
		__entry->rs = rs;
		__entry->conn = conn;
		__entry->cp = cp;
	),

	TP_printk("RDS/%s: <%pI6c,%pI6c,%d>, flags [%s] reason [%s] err [%d]",
		  show_transport(__entry->transport),
		  __entry->laddr, __entry->faddr, __entry->tos,
		  show_flags(__entry->flags),
		  __entry->reason, __entry->err)
);

DEFINE_EVENT(rds_status, rds_conn_create,

	TP_PROTO(struct rds_sock *rs, struct rds_connection *conn,
		 struct rds_conn_path *cp, char *reason, int err),

	TP_ARGS(rs, conn, cp, reason, err)

);

DEFINE_EVENT(rds_status, rds_conn_create_err,

	TP_PROTO(struct rds_sock *rs, struct rds_connection *conn,
		 struct rds_conn_path *cp, char *reason, int err),

	TP_ARGS(rs, conn, cp, reason, err)

);

DEFINE_EVENT(rds_status, rds_conn_destroy,

	TP_PROTO(struct rds_sock *rs, struct rds_connection *conn,
		 struct rds_conn_path *cp, char *reason, int err),

	TP_ARGS(rs, conn, cp, reason, err)

);

DEFINE_EVENT(rds_status, rds_conn_drop,

	TP_PROTO(struct rds_sock *rs, struct rds_connection *conn,
		 struct rds_conn_path *cp, char *reason, int err),

	TP_ARGS(rs, conn, cp, reason, err)

);

DEFINE_EVENT(rds_status, rds_conn_update_connect_time,

	TP_PROTO(struct rds_sock *rs, struct rds_connection *conn,
		 struct rds_conn_path *cp, char *reason, int err),

	TP_ARGS(rs, conn, cp, reason, err)

);

DEFINE_EVENT(rds_status, rds_send_err,

	TP_PROTO(struct rds_sock *rs, struct rds_connection *conn,
		 struct rds_conn_path *cp, char *reason, int err),

	TP_ARGS(rs, conn, cp, reason, err)

);

DEFINE_EVENT(rds_status, rds_send_worker_err,

	TP_PROTO(struct rds_sock *rs, struct rds_connection *conn,
		 struct rds_conn_path *cp, char *reason, int err),

	TP_ARGS(rs, conn, cp, reason, err)

);

DEFINE_EVENT(rds_status, rds_send_lock_contention,

	TP_PROTO(struct rds_sock *rs, struct rds_connection *conn,
		 struct rds_conn_path *cp, char *reason, int err),

	TP_ARGS(rs, conn, cp, reason, err)
);

DEFINE_EVENT(rds_status, rds_receive_err,

	TP_PROTO(struct rds_sock *rs, struct rds_connection *conn,
		 struct rds_conn_path *cp, char *reason, int err),

	TP_ARGS(rs, conn, cp, reason, err)

);

DEFINE_EVENT(rds_status, rds_receive_worker_err,

	TP_PROTO(struct rds_sock *rs, struct rds_connection *conn,
		 struct rds_conn_path *cp, char *reason, int err),

	TP_ARGS(rs, conn, cp, reason, err)

);

DEFINE_EVENT(rds_status, rds_cong_seen,

	TP_PROTO(struct rds_sock *rs, struct rds_connection *conn,
		 struct rds_conn_path *cp, char *reason, int err),

	TP_ARGS(rs, conn, cp, reason, err)
);

DEFINE_EVENT(rds_status, rds_cong_cleared,

	TP_PROTO(struct rds_sock *rs, struct rds_connection *conn,
		 struct rds_conn_path *cp, char *reason, int err),

	TP_ARGS(rs, conn, cp, reason, err)
);

DEFINE_EVENT(rds_status, rds_cong_notify,

	TP_PROTO(struct rds_sock *rs, struct rds_connection *conn,
		 struct rds_conn_path *cp, char *reason, int err),

	TP_ARGS(rs, conn, cp, reason, err)
);

TRACE_EVENT(rds_receive,

	TP_PROTO(struct rds_incoming *inc, struct rds_sock *rs,
		 struct rds_connection *conn, struct rds_conn_path *cp,
		 struct in6_addr *saddr, struct in6_addr *daddr),

	TP_ARGS(inc, rs, conn, cp, saddr, daddr),

	/*
	 * fields here are intended to match as much of rds_state_change[_err]
	 * as is possible so the same struct can be used to access key
	 * tracepoint data from all rds-related tracepoints.
	 */
	TP_STRUCT__entry(
		RDS_TRACE_COMMON_FIELDS
		__field(void *, hdr)
		__field(void *, inc)
		__field(__u64, seq)
		__field(__u64, next_rx_seq)
		__field(bool, forward)
		__field(__u32, len)
		__field(unsigned long, rx_jiffies)
	),

	TP_fast_assign(
		struct in6_addr *in6;
		struct cgroup *cgrp;

		in6 = (struct in6_addr *)__entry->faddr;
		*in6 = saddr ? *saddr : in6addr_any;
		in6 = (struct in6_addr *)__entry->laddr;
		*in6 = daddr ? *daddr : in6addr_any;
		__entry->tos = conn ? conn->c_tos : 0;
		__entry->transport = conn ? conn->c_trans->t_type :
					    RDS_TRANS_NONE;
		__entry->fport = inc ? be16_to_cpu(inc->i_hdr.h_sport) : 0;
		__entry->lport = inc ? be16_to_cpu(inc->i_hdr.h_dport) : 0;
		__entry->netns_inum = rds_netns_inum(rs);
		__entry->qp_num = rds_qp_num(conn, 0);
		__entry->remote_qp_num = rds_qp_num(conn, 1);
		__entry->flags = inc ? inc->i_hdr.h_flags : 0;
		__entry->err = 0;
		RDS_STRSCPY(__entry->reason, NULL);
		cgrp = rds_rs_to_cgroup(rs);
		__entry->cgroup = cgrp;
		__entry->cgroup_id = rds_cgroup_id(cgrp);
		__entry->inc = inc;
		__entry->rs = rs;
		__entry->conn = conn;
		__entry->cp = cp;
		__entry->hdr = inc ? &inc->i_hdr : NULL;
		__entry->seq = inc ? be64_to_cpu(inc->i_hdr.h_sequence) : 0;
		__entry->next_rx_seq = cp ? cp->cp_next_rx_seq : 0;
		__entry->forward = !cp;
		__entry->len = inc ? be32_to_cpu(inc->i_hdr.h_len) : 0;
		__entry->rx_jiffies = inc ? inc->i_rx_jiffies : 0;
	),

	TP_printk("RDS/%s: <%pI6c,%pI6c,%d> next %llu seq %llu len %u sport %u dport %u flags 0x%lx rx_jiffies %lu forward %d",
		  show_transport(__entry->transport),
		  __entry->laddr, __entry->faddr, __entry->tos,
		  __entry->next_rx_seq, __entry->seq, __entry->len,
		  __entry->fport, __entry->lport, __entry->flags,
		  __entry->rx_jiffies, __entry->forward)
);

TRACE_EVENT(rds_drop_ingress,

	TP_PROTO(struct rds_incoming *inc, struct rds_sock *rs,
		 struct rds_connection *conn, struct rds_conn_path *cp,
		 struct in6_addr *saddr, struct in6_addr *daddr,
		 char *reason),

	TP_ARGS(inc, rs, conn, cp, saddr, daddr, reason),

	/*
	 * fields here are intended to match rds_receive, and as much of
	 * rds_state_change[_err] as is possible.
	 */
	TP_STRUCT__entry(
		RDS_TRACE_COMMON_FIELDS
		__field(void *, hdr)
		__field(void *, inc)
		__field(__u64, seq)
		__field(__u64, next_rx_seq)
		__field(bool, forward)
		__field(__u32, len)
		__field(unsigned long, rx_jiffies)
	),

	TP_fast_assign(
		struct in6_addr *in6;
		struct cgroup *cgrp;

		in6 = (struct in6_addr *)__entry->faddr;
		*in6 = saddr ? *saddr : in6addr_any;
		in6 = (struct in6_addr *)__entry->laddr;
		*in6 = daddr ? *daddr : in6addr_any;
		__entry->tos = conn ? conn->c_tos : 0;
		__entry->transport = conn ? conn->c_trans->t_type :
					    RDS_TRANS_NONE;
		__entry->fport = inc ? be16_to_cpu(inc->i_hdr.h_sport) : 0;
		__entry->lport = inc ? be16_to_cpu(inc->i_hdr.h_dport) : 0;
		__entry->netns_inum = rds_netns_inum(rs);
		__entry->qp_num = rds_qp_num(conn, 0);
		__entry->remote_qp_num = rds_qp_num(conn, 1);
		__entry->flags = inc ? inc->i_hdr.h_flags : 0;
		RDS_STRSCPY(__entry->reason, reason);
		__entry->err = 0;
		cgrp = rds_rs_to_cgroup(rs);
		__entry->cgroup = cgrp;
		__entry->cgroup_id = rds_cgroup_id(cgrp);
		__entry->inc = inc;
		__entry->rs = rs;
		__entry->conn = conn;
		__entry->cp = cp;
		__entry->hdr = inc ? &inc->i_hdr : NULL;
		__entry->seq = inc ? be64_to_cpu(inc->i_hdr.h_sequence) : 0;
		__entry->next_rx_seq = cp ? cp->cp_next_rx_seq : 0;
		__entry->forward = !cp;
		__entry->len = inc ? be32_to_cpu(inc->i_hdr.h_len) : 0;
		__entry->rx_jiffies = inc ? inc->i_rx_jiffies : 0;
	),

	TP_printk("RDS/%s: <%pI6c,%pI6c,%d> dropping request, reason [%s]",
		  show_transport(__entry->transport),
		  __entry->faddr, __entry->laddr, __entry->tos,
		  __entry->reason)
);

TRACE_EVENT(rds_send,

	TP_PROTO(struct rds_message *rm, struct rds_sock *rs,
		 struct rds_connection *conn, struct rds_conn_path *cp,
		 struct in6_addr *saddr, struct in6_addr *daddr),

	TP_ARGS(rm, rs, conn, cp, saddr, daddr),

	TP_STRUCT__entry(
		RDS_TRACE_COMMON_FIELDS
		__field(void *, hdr)
	),

	TP_fast_assign(
		struct in6_addr *in6;
		struct cgroup *cgrp;

		in6 = (struct in6_addr *)__entry->laddr;
		*in6 = saddr ? *saddr : in6addr_any;
		in6 = (struct in6_addr *)__entry->faddr;
		*in6 = daddr ? *daddr : in6addr_any;
		__entry->tos = conn ? conn->c_tos : 0;
		__entry->transport = conn ? conn->c_trans->t_type :
					    RDS_TRANS_NONE;
		__entry->lport = rm ? be16_to_cpu(rm->m_inc.i_hdr.h_sport) : 0;
		__entry->fport = rm ? be16_to_cpu(rm->m_inc.i_hdr.h_dport) : 0;
		__entry->netns_inum = rds_netns_inum(rs);
		__entry->qp_num = rds_qp_num(conn, 0);
		__entry->remote_qp_num = rds_qp_num(conn, 1);
		__entry->flags = rm ? rm->m_flags : 0;
		__entry->err = 0;
		RDS_STRSCPY(__entry->reason, NULL);
		cgrp = rds_rs_to_cgroup(rs);
		__entry->cgroup = cgrp;
		__entry->cgroup_id = rds_cgroup_id(cgrp);
		__entry->rs = rs;
		__entry->conn = conn;
		__entry->cp = cp;
		__entry->hdr = rm ? &rm->m_inc.i_hdr : NULL;
		__entry->rm = rm;
	),

	TP_printk("RDS/%s: <%pI6c,%pI6c,%d> flags 0x%lxu",
		  show_transport(__entry->transport),
		  __entry->laddr, __entry->faddr, __entry->tos,
		  __entry->flags)
);

TRACE_EVENT(rds_send_complete,

	TP_PROTO(struct rds_message *rm, struct rds_sock *rs,
		 struct rds_connection *conn, struct rds_conn_path *cp,
		 struct in6_addr *saddr, struct in6_addr *daddr,
		 char *reason, int err),

	TP_ARGS(rm, rs, conn, cp, saddr, daddr, reason, err),

	TP_STRUCT__entry(
		RDS_TRACE_COMMON_FIELDS
		__field(void *, hdr)
	),

	TP_fast_assign(
		struct in6_addr *in6;
		struct cgroup *cgrp;

		in6 = (struct in6_addr *)__entry->laddr;
		*in6 = saddr ? *saddr : in6addr_any;
		in6 = (struct in6_addr *)__entry->faddr;
		*in6 = daddr ? *daddr : in6addr_any;
		__entry->tos = conn ? conn->c_tos : 0;
		__entry->transport = conn ? conn->c_trans->t_type :
					    RDS_TRANS_NONE;
		__entry->lport = rm ? be16_to_cpu(rm->m_inc.i_hdr.h_sport) : 0;
		__entry->fport = rm ? be16_to_cpu(rm->m_inc.i_hdr.h_dport) : 0;
		__entry->qp_num = rds_qp_num(conn, 0);
		__entry->remote_qp_num = rds_qp_num(conn, 1);
		__entry->flags = rm ? rm->m_flags : 0;
		RDS_STRSCPY(__entry->reason, reason);
		__entry->err = err;
		cgrp = rds_rs_to_cgroup(rs);
		__entry->cgroup = cgrp;
		__entry->cgroup_id = rds_cgroup_id(cgrp);
		__entry->rs = rs;
		__entry->conn = conn;
		__entry->cp = cp;
		__entry->hdr = rm ? &rm->m_inc.i_hdr : NULL;
		__entry->rm = rm;
	),

	TP_printk("RDS/%s: <%pI6c,%pI6c,%d> flags 0x%lxu reason [%s] status [%s]",
		  show_transport(__entry->transport),
		  __entry->laddr, __entry->faddr, __entry->tos,
		  __entry->flags, __entry->reason,
		  show_send_status(__entry->err))
);

TRACE_EVENT(rds_drop_egress,

	TP_PROTO(struct rds_message *rm, struct rds_sock *rs,
		 struct rds_connection *conn, struct rds_conn_path *cp,
		 struct in6_addr *saddr, struct in6_addr *daddr,
		 char *reason),

	TP_ARGS(rm, rs, conn, cp, saddr, daddr, reason),

	TP_STRUCT__entry(
		RDS_TRACE_COMMON_FIELDS
		__field(void *, hdr)
	),

	TP_fast_assign(
		struct in6_addr *in6;
		struct cgroup *cgrp;

		in6 = (struct in6_addr *)__entry->laddr;
		*in6 = saddr ? *saddr : in6addr_any;
		in6 = (struct in6_addr *)__entry->faddr;
		*in6 = daddr ? *daddr : in6addr_any;
		__entry->tos = conn ? conn->c_tos : 0;
		__entry->transport = conn ? conn->c_trans->t_type :
					    RDS_TRANS_NONE;
		__entry->lport = rm ? be16_to_cpu(rm->m_inc.i_hdr.h_sport) : 0;
		__entry->fport = rm ? be16_to_cpu(rm->m_inc.i_hdr.h_dport) : 0;
		__entry->netns_inum = rds_netns_inum(rs);
		__entry->qp_num = rds_qp_num(conn, 0);
		__entry->remote_qp_num = rds_qp_num(conn, 1);
		__entry->flags = rm ? rm->m_flags : 0;
		RDS_STRSCPY(__entry->reason, reason);
		__entry->err = 0;
		cgrp = rds_rs_to_cgroup(rs);
		__entry->cgroup = cgrp;
		__entry->cgroup_id = rds_cgroup_id(cgrp);
		__entry->rs = rs;
		__entry->conn = conn;
		__entry->cp = cp;
		__entry->hdr = rm ? &rm->m_inc.i_hdr : NULL;
		__entry->rm = rm;
	),

	TP_printk("RDS/%s: <%pI6c,%pI6c,%d> dropping message, flags 0x%lxu reason [%s]",
		  show_transport(__entry->transport), __entry->laddr,
		  __entry->faddr, __entry->tos, __entry->flags,
		 __entry->reason)
);

DECLARE_EVENT_CLASS(rds_ib,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err),

	TP_STRUCT__entry(
		RDS_TRACE_COMMON_FIELDS
		__field(void *, dev)
		__field(void *, rds_ibdev)
		__field(void *, cm_id)
		__field(void *, pd)
		__field(void *, rcq)
		__field(void *, qp)
		__field(__u64, lguid)
		__field(__u64, fguid)
		__array(char, dev_name, RDS_STRSIZE)
	),

	TP_fast_assign(
		struct rds_ib_connection *ic;
		struct rdma_cm_id *cm_id;
		struct rds_conn_path *cp;
		struct in6_addr *in6;
		struct cgroup *cgrp;
		struct rds_sock *rs;

		in6 = (struct in6_addr *)__entry->laddr;
		*in6 = conn ? conn->c_laddr : in6addr_any;
		in6 = (struct in6_addr *)__entry->faddr;
		*in6 = conn ? conn->c_faddr : in6addr_any;
		__entry->tos = conn ? conn->c_tos : 0;
		__entry->transport = conn ? conn->c_trans->t_type :
					    RDS_TRANS_NONE;
		__entry->lport = 0;
		__entry->fport = 0;
		__entry->qp_num = rds_qp_num(conn, 0);
		__entry->remote_qp_num = rds_qp_num(conn, 1);
		__entry->flags = 0;
		RDS_STRSCPY(__entry->dev_name, dev ? dev->name : NULL);
		RDS_STRSCPY(__entry->reason, reason);
		__entry->err = err;
		cp = conn && conn->c_npaths == 1 ? &conn->c_path[0] : NULL;
		rs = cp && cp->cp_xmit_rm ? cp->cp_xmit_rm->m_rs : NULL;
		__entry->rs = rs;
		__entry->netns_inum = rds_netns_inum(rs);
		cgrp = rds_rs_to_cgroup(rs);
		__entry->cgroup = cgrp;
		__entry->cgroup_id = rds_cgroup_id(cgrp);
		__entry->conn = conn;
		__entry->cp = cp;
		__entry->dev = dev;
		__entry->rds_ibdev = rds_ibdev;
		cm_id = ic ? ic->i_cm_id : NULL;
		__entry->cm_id = cm_id;
		__entry->pd = ic ? ic->i_pd : NULL;
		__entry->rcq = ic ? ic->i_rcq : NULL;
		__entry->qp = cm_id ? cm_id->qp : NULL;
		__entry->lguid = cm_id && cm_id->route.path_rec ?
			cm_id->route.path_rec->sgid.global.interface_id : 0;
		__entry->fguid = cm_id && cm_id->route.path_rec ?
			cm_id->route.path_rec->dgid.global.interface_id : 0;
	),

	TP_printk("RDS/IB: <%pI6c,%pI6c,%d> lguid 0x%llx fguid 0x%llx qps <%d,%d> dev %s reason [%s], err [%d]",
		__entry->laddr, __entry->faddr, __entry->tos,
		__entry->lguid, __entry->fguid,
		__entry->qp_num, __entry->remote_qp_num, __entry->dev_name,
		__entry->reason, __entry->err)
);

DEFINE_EVENT(rds_ib, rds_ib_add_device,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_add_device_err,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_remove_device,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_remove_device_err,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_shutdown_device,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_cm_accept_err,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_cm_handle_connect,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_cm_handle_connect_err,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_cm_initiate_connect,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_cm_initiate_connect_err,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_conn_path_connect,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_conn_path_connect_err,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_conn_path_shutdown_prepare,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_conn_path_shutdown_prepare_err,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_conn_yield_yielding,

       TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		struct rds_connection *conn, struct rds_ib_connection *ic,
		char *reason, int err),

       TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_conn_yield_right_of_way,

       TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		struct rds_connection *conn, struct rds_ib_connection *ic,
		char *reason, int err),

       TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_conn_yield_stale,

       TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		struct rds_connection *conn, struct rds_ib_connection *ic,
		char *reason, int err),

       TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_conn_yield_expired,

       TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		struct rds_connection *conn, struct rds_ib_connection *ic,
		char *reason, int err),

       TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_conn_yield_accepting,

       TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		struct rds_connection *conn, struct rds_ib_connection *ic,
		char *reason, int err),

       TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_conn_yield_success,

       TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		struct rds_connection *conn, struct rds_ib_connection *ic,
		char *reason, int err),

       TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_conn_yield_accept_err,

       TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		struct rds_connection *conn, struct rds_ib_connection *ic,
		char *reason, int err),

       TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_setup_fastreg,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_setup_fastreg_err,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_setup_qp,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_setup_qp_err,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_send_cqe_handler,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_send_cqe_handler_err,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_rdma_cm_event_handler,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_rdma_cm_event_handler_err,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_srqs_create_one_err,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_srq_get_err,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DEFINE_EVENT(rds_ib, rds_ib_srqs_destroy_one_err,

	TP_PROTO(struct ib_device *dev, struct rds_ib_device *rds_ibdev,
		 struct rds_connection *conn, struct rds_ib_connection *ic,
		 char *reason, int err),

	TP_ARGS(dev, rds_ibdev, conn, ic, reason, err)

);

DECLARE_EVENT_CLASS(rds_ib_flow_cntrl,

	TP_PROTO(struct rds_ib_device *rds_ibdev, struct rds_connection *conn,
		 struct rds_ib_connection *ic, int oldval, int newval),

	TP_ARGS(rds_ibdev, conn, ic, oldval, newval),

	/*
	 * fields here are intended to match as much of other RDS
	 * tracepoints as possible so the same struct can be used to
	 * access key tracepoint data from all rds-related tracepoints.
	 */
	TP_STRUCT__entry(
		RDS_TRACE_COMMON_FIELDS
		__field(void *, dev)
		__field(void *, rds_ibdev)
		__field(long, old_send_credits)
		__field(long, old_post_credits)
		__field(long, new_send_credits)
		__field(long, new_post_credits)
		__array(char, dev_name, RDS_STRSIZE)
	),

	TP_fast_assign(
		struct rds_conn_path *cp;
		struct in6_addr *in6;
		struct cgroup *cgrp;
		struct rds_sock *rs;

		in6 = (struct in6_addr *)__entry->laddr;
		*in6 = conn ? conn->c_laddr : in6addr_any;
		in6 = (struct in6_addr *)__entry->faddr;
		*in6 = conn ? conn->c_faddr : in6addr_any;
		__entry->tos = conn ? conn->c_tos : 0;
		__entry->transport = conn ? conn->c_trans->t_type :
					    RDS_TRANS_NONE;
		__entry->lport = 0;
		__entry->fport = 0;
		__entry->qp_num = rds_qp_num(conn, 0);
		__entry->remote_qp_num = rds_qp_num(conn, 1);
		__entry->flags = 0;
		__entry->err = 0;
		RDS_STRSCPY(__entry->reason, NULL);
		cp = conn && conn->c_npaths == 1 ? &conn->c_path[0] : NULL;
		rs = cp && cp->cp_xmit_rm ? cp->cp_xmit_rm->m_rs : NULL;
		__entry->rs = rs;
		__entry->netns_inum = rds_netns_inum(rs);
		cgrp = rds_rs_to_cgroup(rs);
		__entry->cgroup = cgrp;
		__entry->cgroup_id = rds_cgroup_id(cgrp);
		__entry->conn = conn;
		__entry->cp = cp;
		__entry->dev = rds_ibdev ? rds_ibdev->dev : NULL;
		__entry->rds_ibdev = rds_ibdev;
		RDS_STRSCPY(__entry->dev_name, rds_ibdev && rds_ibdev->dev ?
					       rds_ibdev->dev->name : NULL);
		__entry->old_send_credits = IB_GET_SEND_CREDITS(oldval);
		__entry->old_post_credits = IB_GET_POST_CREDITS(oldval);
		__entry->new_send_credits = IB_GET_SEND_CREDITS(newval);
		__entry->new_post_credits = IB_GET_POST_CREDITS(newval);
	),

	TP_printk("RDS/IB: <%pI6c,%pI6c,%d> dev %s send_credits [%ld -> %ld], post_credits [%ld -> %ld]",
		  __entry->laddr, __entry->faddr, __entry->tos,
		  __entry->dev_name, __entry->old_send_credits,
		  __entry->new_send_credits, __entry->old_post_credits,
		  __entry->new_post_credits)
);

DEFINE_EVENT(rds_ib_flow_cntrl, rds_ib_flow_cntrl_add_credits,

	TP_PROTO(struct rds_ib_device *rds_ibdev, struct rds_connection *conn,
		 struct rds_ib_connection *ic, int oldval, int newval),

	TP_ARGS(rds_ibdev, conn, ic, oldval, newval)

);

DEFINE_EVENT(rds_ib_flow_cntrl, rds_ib_flow_cntrl_advertise_credits,

	TP_PROTO(struct rds_ib_device *rds_ibdev, struct rds_connection *conn,
		 struct rds_ib_connection *ic, int oldval, int newval),

	TP_ARGS(rds_ibdev, conn, ic, oldval, newval)

);

DEFINE_EVENT(rds_ib_flow_cntrl, rds_ib_flow_cntrl_grab_credits,

	TP_PROTO(struct rds_ib_device *rds_ibdev, struct rds_connection *conn,
		 struct rds_ib_connection *ic, int oldval, int newval),

	TP_ARGS(rds_ibdev, conn, ic, oldval, newval)

);

DECLARE_EVENT_CLASS(rds_queue,

	TP_PROTO(struct rds_connection *conn, struct rds_conn_path *cp,
		 struct workqueue_struct *wq, struct work_struct *work,
		 unsigned long delay, char *reason),

	TP_ARGS(conn, cp, wq, work, delay, reason),

	TP_STRUCT__entry(
		RDS_TRACE_COMMON_FIELDS
		__field(void *, wq)
		__field(void *, work)
		__field(unsigned long, delay)
	),

	TP_fast_assign(
		struct in6_addr *in6;
		struct rds_sock *rs;
		struct cgroup *cgrp;

		in6 = (struct in6_addr *)__entry->laddr;
		*in6 = conn ? conn->c_laddr : in6addr_any;
		in6 = (struct in6_addr *)__entry->faddr;
		*in6 = conn ? conn->c_faddr : in6addr_any;
		__entry->tos = conn ? conn->c_tos : 0;
		__entry->transport = conn ? conn->c_trans->t_type :
					    RDS_TRANS_NONE;
		__entry->lport = 0;
		__entry->fport = 0;
		__entry->qp_num = rds_qp_num(conn, 0);
		__entry->remote_qp_num = rds_qp_num(conn, 1);
		__entry->flags = 0;
		RDS_STRSCPY(__entry->reason, reason);
		__entry->err = 0;
		rs = cp && cp->cp_xmit_rm ? cp->cp_xmit_rm->m_rs :
					    NULL;
		__entry->rs = rs;
		__entry->netns_inum = rds_netns_inum(rs);
		cgrp = rds_rs_to_cgroup(rs);
		__entry->cgroup = cgrp;
		__entry->cgroup_id = rds_cgroup_id(cgrp);
		__entry->conn = conn;
		__entry->cp = cp;
		__entry->wq = wq;
		__entry->work = work;
		__entry->delay = delay;
	),

	TP_printk("RDS/%s: <%pI6c,%pI6c,%d> delay %ld reason [%s]",
		  show_transport(__entry->transport),
		  __entry->laddr, __entry->faddr, __entry->tos,
		  __entry->delay, __entry->reason)
);

DEFINE_EVENT(rds_queue, rds_queue_cancel,

	TP_PROTO(struct rds_connection *conn, struct rds_conn_path *cp,
		 struct workqueue_struct *wq, struct work_struct *work,
		 unsigned long delay, char *reason),

	TP_ARGS(conn, cp, wq, work, delay, reason)
);

DEFINE_EVENT(rds_queue, rds_queue_work,

	TP_PROTO(struct rds_connection *conn, struct rds_conn_path *cp,
		 struct workqueue_struct *wq, struct work_struct *work,
		 unsigned long delay, char *reason),

	TP_ARGS(conn, cp, wq, work, delay, reason)
);

DEFINE_EVENT(rds_queue, rds_queue_worker,

	TP_PROTO(struct rds_connection *conn, struct rds_conn_path *cp,
		 struct workqueue_struct *wq, struct work_struct *work,
		 unsigned long delay, char *reason),

	TP_ARGS(conn, cp, wq, work, delay, reason)
);

DEFINE_EVENT(rds_queue, rds_queue_cancel_work,

	TP_PROTO(struct rds_connection *conn, struct rds_conn_path *cp,
		 struct workqueue_struct *wq, struct work_struct *work,
		 unsigned long delay, char *reason),

	TP_ARGS(conn, cp, wq, work, delay, reason)
);

DEFINE_EVENT(rds_queue, rds_queue_flush_work,

	TP_PROTO(struct rds_connection *conn, struct rds_conn_path *cp,
		 struct workqueue_struct *wq, struct work_struct *work,
		 unsigned long delay, char *reason),

	TP_ARGS(conn, cp, wq, work, delay, reason)
);

DEFINE_EVENT(rds_queue, rds_queue_noop,

	TP_PROTO(struct rds_connection *conn, struct rds_conn_path *cp,
		 struct workqueue_struct *wq, struct work_struct *work,
		 unsigned long delay, char *reason),

	TP_ARGS(conn, cp, wq, work, delay, reason)
);

DECLARE_EVENT_CLASS(rds_ib_queue,

	TP_PROTO(struct rds_ib_device *rds_ibdev, struct workqueue_struct *wq,
		 struct work_struct *work, unsigned long delay, char *reason),

	TP_ARGS(rds_ibdev, wq, work, delay, reason),

	TP_STRUCT__entry(
		RDS_TRACE_COMMON_FIELDS
		__field(void *, dev)
		__field(void *, rds_ibdev)
		__field(void *, wq)
		__field(void *, work)
		__field(unsigned long, delay)
		__array(char, dev_name, RDS_STRSIZE)
	),

	TP_fast_assign(
		struct in6_addr *in6;

		in6 = (struct in6_addr *)__entry->laddr;
		*in6 = in6addr_any;
		in6 = (struct in6_addr *)__entry->faddr;
		*in6 = in6addr_any;
		__entry->tos = 0;
		__entry->transport = RDS_TRANS_IB;
		__entry->lport = 0;
		__entry->fport = 0;
		__entry->flags = 0;
		RDS_STRSCPY(__entry->reason, reason);
		__entry->err = 0;
		__entry->rs = NULL;
		__entry->cgroup = NULL;
		__entry->cgroup_id = 0;
		__entry->conn = NULL;
		__entry->cp = NULL;
		__entry->dev = rds_ibdev ? rds_ibdev->dev : NULL;
		__entry->rds_ibdev = rds_ibdev;
		RDS_STRSCPY(__entry->dev_name, rds_ibdev && rds_ibdev->dev ?
					       rds_ibdev->dev->name : NULL);
		__entry->wq = wq;
		__entry->work = work;
		__entry->delay = delay;
	),

	TP_printk("RDS/IB: dev %s %s delay %ld",
		  __entry->dev_name, __entry->reason, __entry->delay)
);

DEFINE_EVENT(rds_ib_queue, rds_ib_queue_work,

	TP_PROTO(struct rds_ib_device *rds_ibdev, struct workqueue_struct *wq,
		 struct work_struct *work, unsigned long delay, char *reason),

	TP_ARGS(rds_ibdev, wq, work, delay, reason)
);

DEFINE_EVENT(rds_ib_queue, rds_ib_queue_worker,

	TP_PROTO(struct rds_ib_device *rds_ibdev, struct workqueue_struct *wq,
		 struct work_struct *work, unsigned long delay, char *reason),

	TP_ARGS(rds_ibdev, wq, work, delay, reason)
);

DEFINE_EVENT(rds_ib_queue, rds_ib_queue_cancel_work,

	TP_PROTO(struct rds_ib_device *rds_ibdev, struct workqueue_struct *wq,
		 struct work_struct *work, unsigned long delay, char *reason),

	TP_ARGS(rds_ibdev, wq, work, delay, reason)
);

DEFINE_EVENT(rds_ib_queue, rds_ib_queue_flush_work,

	TP_PROTO(struct rds_ib_device *rds_ibdev, struct workqueue_struct *wq,
		 struct work_struct *work, unsigned long delay, char *reason),

	TP_ARGS(rds_ibdev, wq, work, delay, reason)

);

DECLARE_EVENT_CLASS(rds_mr,

	TP_PROTO(struct rds_sock *rs, struct rds_connection *conn,
		 struct rds_mr *mr, int refcount, char *reason, int err),

	TP_ARGS(rs, conn, mr, refcount, reason, err),

	TP_STRUCT__entry(
		RDS_TRACE_COMMON_FIELDS
		__field(void *, mr)
		__field(u32, key)
		__field(bool, use_once)
		__field(bool, invalidate)
		__field(bool, write)
		__field(int, refcount)
	),

	TP_fast_assign(
		struct in6_addr *in6;
		struct cgroup *cgrp;

		in6 = (struct in6_addr *)__entry->laddr;
		*in6 = conn ? conn->c_laddr : in6addr_any;
		in6 = (struct in6_addr *)__entry->faddr;
		*in6 = conn ? conn->c_faddr : in6addr_any;
		__entry->tos = conn ? conn->c_tos : 0;
		__entry->transport = conn ? conn->c_trans->t_type :
					    RDS_TRANS_NONE;
		__entry->lport = rs ? rs->rs_bound_port : 0;
		__entry->fport = rs ? rs->rs_conn_port : 0;
		__entry->netns_inum = rds_netns_inum(rs);
		__entry->qp_num = rds_qp_num(conn, 0);
		__entry->remote_qp_num = rds_qp_num(conn, 1);
		__entry->flags = 0;
		RDS_STRSCPY(__entry->reason, reason);
		__entry->err = err;
		cgrp = rds_rs_to_cgroup(rs);
		__entry->cgroup = cgrp;
		__entry->cgroup_id = rds_cgroup_id(cgrp);
		__entry->rm = NULL;
		__entry->rs = rs;
		__entry->conn = conn;
		__entry->cp = NULL;
		__entry->mr = mr;
		__entry->key = mr->r_key;
		__entry->use_once = mr->r_use_once;
		__entry->invalidate = mr->r_invalidate;
		__entry->write = mr->r_write;
		__entry->refcount = refcount;
	),

	TP_printk("RDS/%s: <%pI6c,%pI6c,%d>, key %#x (%s%s%s) refcount %d reason [%s] err [%d]",
		  show_transport(__entry->transport),
		  __entry->laddr, __entry->faddr, __entry->tos,
		  __entry->key, __entry->use_once ? ",use once" : "",
		  __entry->invalidate ? ",invalidate" : "",
		  __entry->write ? ",write" : "",
		  __entry->refcount, __entry->reason,
		  __entry->err)
);

DEFINE_EVENT(rds_mr, rds_mr_destroy,

	TP_PROTO(struct rds_sock *rs, struct rds_connection *conn,
		 struct rds_mr *mr, int refcount, char *reason, int err),

	TP_ARGS(rs, conn, mr, refcount, reason, err)
);

DEFINE_EVENT(rds_mr, rds_mr_get,

	TP_PROTO(struct rds_sock *rs, struct rds_connection *conn,
		 struct rds_mr *mr, int refcount, char *reason, int err),

	TP_ARGS(rs, conn, mr, refcount, reason, err)
);

DEFINE_EVENT(rds_mr, rds_mr_get_err,

	TP_PROTO(struct rds_sock *rs, struct rds_connection *conn,
		 struct rds_mr *mr, int refcount, char *reason, int err),

	TP_ARGS(rs, conn, mr, refcount, reason, err)
);

DECLARE_EVENT_CLASS(rds_tcp,

	TP_PROTO(struct rds_connection *conn, struct rds_conn_path *cp,
		 struct rds_tcp_connection *tc, struct sock *sk,
		 char *reason, int err),

	TP_ARGS(conn, cp, tc, sk, reason, err),

	TP_STRUCT__entry(
		RDS_TRACE_COMMON_FIELDS
		__field(void *, tc)
		__field(void *, sk)
		__field(int, state)
	),

	TP_fast_assign(
		struct in6_addr *in6;
		struct cgroup *cgrp;

		in6 = (struct in6_addr *)__entry->laddr;
		*in6 = conn ? conn->c_laddr : in6addr_any;
		in6 = (struct in6_addr *)__entry->faddr;
		*in6 = conn ? conn->c_faddr : in6addr_any;
		__entry->tos = conn ? conn->c_tos : 0;
		__entry->transport = conn ? conn->c_trans->t_type :
					    RDS_TRANS_NONE;
		__entry->lport = 0;
		__entry->fport = 0;
		__entry->flags = 0;
		RDS_STRSCPY(__entry->reason, reason);
		__entry->err = err;
		cgrp = sk ? sock_cgroup_ptr(&sk->sk_cgrp_data) : NULL;
		__entry->cgroup = cgrp;
		__entry->cgroup_id = rds_cgroup_id(cgrp);
		__entry->rm = NULL;
		__entry->rs = NULL;
		__entry->conn = conn;
		__entry->cp = cp;
		__entry->tc = tc;
		__entry->sk = sk;
		__entry->state = sk ? sk->sk_state : 0;
	),

	TP_printk("RDS/tcp: <%pI6c,%pI6c,%d>, state [%s] reason [%s] err [%d]",
		  __entry->laddr, __entry->faddr, __entry->tos,
		 show_tcp_state(__entry->state),
		  __entry->reason, __entry->err)
);

DEFINE_EVENT(rds_tcp, rds_tcp_connect,

	TP_PROTO(struct rds_connection *conn, struct rds_conn_path *cp,
		 struct rds_tcp_connection *tc, struct sock *sk,
		 char *reason, int err),

	TP_ARGS(conn, cp, tc, sk, reason, err)
);

DEFINE_EVENT(rds_tcp, rds_tcp_connect_err,

	TP_PROTO(struct rds_connection *conn, struct rds_conn_path *cp,
		 struct rds_tcp_connection *tc, struct sock *sk,
		 char *reason, int err),

	TP_ARGS(conn, cp, tc, sk, reason, err)
);

DEFINE_EVENT(rds_tcp, rds_tcp_accept,

	TP_PROTO(struct rds_connection *conn, struct rds_conn_path *cp,
	 struct rds_tcp_connection *tc, struct sock *sk,
		 char *reason, int err),

	TP_ARGS(conn, cp, tc, sk, reason, err)
);

DEFINE_EVENT(rds_tcp, rds_tcp_accept_err,

	TP_PROTO(struct rds_connection *conn, struct rds_conn_path *cp,
		 struct rds_tcp_connection *tc, struct sock *sk,
		 char *reason, int err),

	TP_ARGS(conn, cp, tc, sk, reason, err)
);

DEFINE_EVENT(rds_tcp, rds_tcp_listen,

	TP_PROTO(struct rds_connection *conn, struct rds_conn_path *cp,
		 struct rds_tcp_connection *tc, struct sock *sk,
		 char *reason, int err),

	TP_ARGS(conn, cp, tc, sk, reason, err)
);

DEFINE_EVENT(rds_tcp, rds_tcp_listen_err,

	TP_PROTO(struct rds_connection *conn, struct rds_conn_path *cp,
		 struct rds_tcp_connection *tc, struct sock *sk,
		 char *reason, int err),

	TP_ARGS(conn, cp, tc, sk, reason, err)
);

DEFINE_EVENT(rds_tcp, rds_tcp_state_change,

	TP_PROTO(struct rds_connection *conn, struct rds_conn_path *cp,
		 struct rds_tcp_connection *tc, struct sock *sk,
		 char *reason, int err),

	TP_ARGS(conn, cp, tc, sk, reason, err)
);

DEFINE_EVENT(rds_tcp, rds_tcp_shutdown,

	TP_PROTO(struct rds_connection *conn, struct rds_conn_path *cp,
		 struct rds_tcp_connection *tc, struct sock *sk,
		 char *reason, int err),

	TP_ARGS(conn, cp, tc, sk, reason, err)
);

TRACE_EVENT(rds_ib_free_cache_one,

	    TP_PROTO(struct rds_ib_cache_head *chead,
		     int cpu,
		     char *type),

	    TP_ARGS(chead, cpu, type),

	    TP_STRUCT__entry(
		    __field(__u16, cpu)
		    __field(__u16, count)
		    __array(char, type, RDS_STRSIZE)
		    ),

	    TP_fast_assign(
		    __entry->cpu = cpu;
		    __entry->count = atomic_read(&chead->count);
		    RDS_STRSCPY(__entry->type, type);
		    ),

	    TP_printk("RDS/IB: Free %d %s from percpu-%d",
		      __entry->count, __entry->type,  __entry->cpu)
);

#endif /* _TRACE_RDS_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE trace

/* This part must be outside protection */
#include <trace/define_trace.h>
