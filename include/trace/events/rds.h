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

#include <linux/in6.h>
#include <linux/rds.h>
#include <linux/cgroup.h>
#include "../../../net/rds/rds.h"
#include "../../../net/rds/ib.h"
#include <linux/tracepoint.h>

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

#define RDS_STRSIZE	64
#define RDS_STRLCPY(dst, src)   strlcpy(dst, src ? src : "<none>",	\
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

#define rds_cgroup_id(cgrp)	(cgrp ? (__u64)cgroup_get_kernfs_id(cgrp) : 0)

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
		RDS_STRLCPY(__entry->reason, reason);
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


#endif /* _TRACE_RDS_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
