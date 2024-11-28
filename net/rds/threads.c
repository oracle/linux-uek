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
#include <linux/random.h>

#include "rds.h"

static unsigned int rds_conn_hb_timeout = 0;
module_param(rds_conn_hb_timeout, int, 0444);
MODULE_PARM_DESC(rds_conn_hb_timeout, " Connection heartbeat timeout");


/*
 * All of connection management is simplified by serializing it through
 * work queues that execute in a connection managing thread.
 *
 * TCP wants to send acks through sendpage() in response to data_ready(),
 * but it needs a process context to do so.
 *
 * The receive paths need to allocate but can't drop packets (!) so we have
 * a thread around to block allocating if the receive fast path sees an
 * allocation failure.
 */

/* Grand Unified Theory of connection life cycle:
 * At any point in time, the connection can be in one of these states:
 * DOWN, CONNECTING, UP, DISCONNECTING, ERROR
 *
 * The following transitions are possible:
 *  ANY		  -> ERROR
 *  UP		  -> DISCONNECTING
 *  ERROR	  -> DISCONNECTING
 *  DISCONNECTING -> DOWN
 *  DOWN	  -> CONNECTING
 *  CONNECTING	  -> UP
 *
 * Transition to state DISCONNECTING/DOWN:
 *  -	Inside the shutdown worker; synchronizes with xmit path
 *	through RDS_IN_XMIT, and with connection management callbacks
 *	via c_cm_lock.
 *
 *	For receive callbacks, we rely on the underlying transport
 *	(TCP, IB/RDMA) to provide the necessary synchronisation.
 */
struct workqueue_struct *rds_wq;
EXPORT_SYMBOL_GPL(rds_wq);
struct workqueue_struct *rds_local_wq;
EXPORT_SYMBOL_GPL(rds_local_wq);

static inline void rds_update_avg_connect_time(struct rds_conn_path *cp)
{
	/* Implement:
	 *    new_avg = (1 - tau) * old_avg + tau * new_conn_time
	 * with tau = 0.5
	 */
	unsigned long new_conn_jf;
	unsigned long old_avg_jf;
	unsigned long new_avg_jf;

	if (!cp->cp_conn_start_jf)
		return;

	new_conn_jf = get_jiffies_64() - cp->cp_conn_start_jf;
	old_avg_jf = atomic64_read(&cp->cp_conn->c_trans->rds_avg_conn_jf);
	new_avg_jf = (old_avg_jf >> 1) + (new_conn_jf >> 1);

	rds_rtd(RDS_RTD_CM_EXT,
		"trans %p old_avg %u (ms) new_avg %u (ms)\n",
		cp->cp_conn->c_trans,
		jiffies_to_msecs(old_avg_jf),
		jiffies_to_msecs(new_avg_jf));

	atomic64_set(&cp->cp_conn->c_trans->rds_avg_conn_jf, new_avg_jf);
}

void rds_connect_path_complete(struct rds_conn_path *cp, int curr)
{
	struct rds_connection *conn = cp->cp_conn;

	if (!rds_conn_path_transition(cp, curr, RDS_CONN_UP)) {
		rds_rtd_ptr(RDS_RTD_CM,
			    "conn %p <%pI6c,%pI6c,%d> cannot transition to state UP, current state is %s\n",
			    conn, &conn->c_laddr, &conn->c_faddr, conn->c_tos,
			    conn_state_mnem(atomic_read(&cp->cp_state)));
		rds_conn_path_drop(cp, DR_IB_NOT_CONNECTING_STATE);
		return;
	}

	rds_rtd_ptr(RDS_RTD_CM_EXT,
		    "conn %p <%pI6c,%pI6c,%d> complete\n",
		    conn, &conn->c_laddr, &conn->c_faddr, conn->c_tos);

	cp->cp_reconnect_jiffies = 0;
	set_bit(RCMQ_BITOFF_CONGU_PENDING, &conn->c_map_queued);
	queue_delayed_work(cp->cp_wq, &cp->cp_send_w, 0);
	queue_delayed_work(cp->cp_wq, &cp->cp_recv_w, 0);
	queue_delayed_work(cp->cp_wq, &cp->cp_hb_w, 0);
	cancel_delayed_work(&cp->cp_reconn_w);
	cp->cp_hb_start = 0;

	rds_update_avg_connect_time(cp);
	cp->cp_connection_start = get_seconds();
	cp->cp_reconnect = 1;
	conn->c_proposed_version = RDS_PROTOCOL_VERSION;
}
EXPORT_SYMBOL_GPL(rds_connect_path_complete);

void rds_connect_complete(struct rds_connection *conn)
{
	rds_connect_path_complete(&conn->c_path[0], RDS_CONN_CONNECTING);
}
EXPORT_SYMBOL_GPL(rds_connect_complete);

static bool rds_conn_is_active_peer(struct rds_connection *conn)
{
	bool greater_ip = rds_addr_cmp(&conn->c_laddr, &conn->c_faddr) > 0;
	bool self_loopback = rds_conn_self_loopback_passive(conn);
	bool passive = greater_ip || self_loopback;

	return !passive;
}

/*
 * This random exponential backoff is relied on to eventually resolve racing
 * connects.
 *
 * If connect attempts race then both parties drop both connections and come
 * here to wait for a random amount of time before trying again.  Eventually
 * the backoff range will be so much greater than the time it takes to
 * establish a connection that one of the pair will establish the connection
 * before the other's random delay fires.
 *
 * Connection attempts that arrive while a connection is already established
 * are also considered to be racing connects.  This lets a connection from
 * a rebooted machine replace an existing stale connection before the transport
 * notices that the connection has failed.
 *
 * We should *always* start with a random backoff; otherwise a broken connection
 * will always take several iterations to be re-established.
 */
void rds_queue_reconnect(struct rds_conn_path *cp)
{
	struct rds_connection *conn = cp->cp_conn;
	bool is_tcp = conn->c_trans->t_type == RDS_TRANS_TCP;
	bool active = rds_conn_is_active_peer(conn);
	uint64_t delay = 0;

	rds_rtd_ptr(RDS_RTD_CM_EXT,
		    "conn %p:%d <%pI6c,%pI6c,%d> reconnect jiffies %lu\n",
		    conn, active, &conn->c_laddr, &conn->c_faddr, conn->c_tos,
		    cp->cp_reconnect_jiffies);

	/* let peer with smaller addr initiate reconnect, to avoid duels */
	if (is_tcp && rds_addr_cmp(&conn->c_laddr, &conn->c_faddr) >= 0)
		return;

	/* If we're the passive initiator and we're racing, let the
	 * active peer drive the reconnect
	 */
	if (!active && cp->cp_reconnect_racing)
		return;

	if (cp->cp_reconnect_jiffies == 0)
		cp->cp_reconnect_jiffies = rds_sysctl_reconnect_min_jiffies;
	else
		delay = cp->cp_reconnect_jiffies;

	if (!active) {
		delay = max_t(uint64_t,
			      rds_sysctl_passive_connect_delay_percent *
			      atomic64_read(&conn->c_trans->rds_avg_conn_jf) / 100,
			      msecs_to_jiffies(1000));
		/* The heuristics may be very long, e.g., node reboots */
		delay = min_t(uint64_t, delay, msecs_to_jiffies(15000));
	}

	rds_rtd_ptr(RDS_RTD_CM_EXT,
		    "conn %p:%d <%pI6c,%pI6c,%d> delay %llu reconnect jiffies %lu\n",
		    conn, active, &conn->c_laddr, &conn->c_faddr, conn->c_tos,
		    delay, cp->cp_reconnect_jiffies);

	set_bit(RDS_RECONNECT_PENDING, &cp->cp_flags);
	queue_delayed_work(cp->cp_wq, &cp->cp_conn_w, delay);
	cp->cp_reconnect_jiffies = min(cp->cp_reconnect_jiffies * 2,
				       rds_sysctl_reconnect_max_jiffies);
}

void rds_connect_worker(struct work_struct *work)
{
	struct rds_conn_path *cp = container_of(work,
						struct rds_conn_path,
						cp_conn_w.work);
	struct rds_connection *conn = cp->cp_conn;
	int ret;
	bool is_tcp = conn->c_trans->t_type == RDS_TRANS_TCP;

	if (is_tcp && cp->cp_index > 0 &&
	    rds_addr_cmp(&cp->cp_conn->c_laddr, &cp->cp_conn->c_faddr) > 0)
		return;
	clear_bit(RDS_RECONNECT_PENDING, &cp->cp_flags);
	ret = rds_conn_path_transition(cp, RDS_CONN_DOWN, RDS_CONN_CONNECTING);
	if (ret) {
		/*
		 * record the time we started trying to connect so that we can
		 * drop the connection if it doesn't work out after a while
		 */
		cp->cp_connection_start = get_seconds();
		cp->cp_drop_source = DR_DEFAULT;

		ret = conn->c_trans->conn_path_connect(cp);
		rds_rtd_ptr(RDS_RTD_CM_EXT,
			    "conn %p for <%pI6c,%pI6c,%d> dispatched, ret %d\n",
			    conn, &conn->c_laddr, &conn->c_faddr, conn->c_tos,
			    ret);

		if (ret) {
			if (rds_conn_path_transition(cp,
						     RDS_CONN_CONNECTING,
						     RDS_CONN_DOWN)) {
				rds_rtd(RDS_RTD_CM_EXT,
					"reconnecting..., conn %p\n", conn);
				rds_queue_reconnect(cp);
			} else {
				rds_conn_path_drop(cp, DR_CONN_CONNECT_FAIL);
			}
		}
	} else {
		rds_rtd(RDS_RTD_CM,
			"conn %p cannot transition from allegedly DOWN(act %s) to CONNECTING state\n",
			conn, conn_state_mnem(atomic_read(&cp->cp_state)));
	}
}

void rds_send_worker(struct work_struct *work)
{
	struct rds_conn_path *cp = container_of(work,
						struct rds_conn_path,
						cp_send_w.work);
	int ret;

	if (rds_conn_path_state(cp) == RDS_CONN_UP) {
		clear_bit(RDS_LL_SEND_FULL, &cp->cp_flags);
		ret = rds_send_xmit(cp);
		cond_resched();
		rds_rtd(RDS_RTD_SND_EXT, "conn %p ret %d\n", cp->cp_conn, ret);
		switch (ret) {
		case -EAGAIN:
			rds_stats_inc(s_send_immediate_retry);
			queue_delayed_work(cp->cp_wq, &cp->cp_send_w, 0);
			break;
		case -ENOMEM:
			rds_stats_inc(s_send_delayed_retry);
			queue_delayed_work(cp->cp_wq, &cp->cp_send_w, 2);
		default:
			break;
		}
	}
}

void rds_recv_worker(struct work_struct *work)
{
	struct rds_conn_path *cp = container_of(work,
						struct rds_conn_path,
						cp_recv_w.work);
	int ret;

	if (rds_conn_path_state(cp) == RDS_CONN_UP) {
		ret = cp->cp_conn->c_trans->recv_path(cp);
		rds_rtd(RDS_RTD_RCV_EXT, "conn %p ret %d\n", cp->cp_conn, ret);
		switch (ret) {
		case -EAGAIN:
			rds_stats_inc(s_recv_immediate_retry);
			queue_delayed_work(cp->cp_wq, &cp->cp_recv_w, 0);
			break;
		case -ENOMEM:
			rds_stats_inc(s_recv_delayed_retry);
			queue_delayed_work(cp->cp_wq, &cp->cp_recv_w, 2);
		default:
			break;
		}
	}
}

void rds_hb_worker(struct work_struct *work)
{
	struct rds_conn_path *cp = container_of(work,
						struct rds_conn_path,
						cp_hb_w.work);
	unsigned long now = get_seconds();
	int ret;
	struct rds_connection *conn = cp->cp_conn;

	if (!rds_conn_hb_timeout || conn->c_loopback ||
	    conn->c_trans->t_type == RDS_TRANS_TCP)
		return;

	if (rds_conn_path_state(cp) == RDS_CONN_UP) {
		if (!cp->cp_hb_start) {
			ret = rds_send_hb(cp->cp_conn, 0);
			if (ret) {
				rds_rtd(RDS_RTD_ERR_EXT,
					"RDS/IB: rds_hb_worker: failed %d\n",
					ret);
				return;
			}
			cp->cp_hb_start = now;
		} else if (now - cp->cp_hb_start > rds_conn_hb_timeout) {
			rds_rtd_ptr(RDS_RTD_CM,
				    "RDS/IB: connection <%pI6c,%pI6c,%d> timed out (0x%lx,0x%lx)..discon and recon\n",
				    &conn->c_laddr, &conn->c_faddr,
				    conn->c_tos, cp->cp_hb_start, now);
			rds_conn_path_drop(cp, DR_HB_TIMEOUT);
			return;
		}
		queue_delayed_work(cp->cp_wq, &cp->cp_hb_w, HZ);
	}
}

void rds_reconnect_timeout(struct work_struct *work)
{
	struct rds_conn_path *cp = container_of(work,
						struct rds_conn_path,
						cp_reconn_w.work);
	struct rds_connection *conn = cp->cp_conn;

	if (!rds_conn_path_up(cp)) {
		rds_rtd_ptr(RDS_RTD_CM,
			    "conn %p <%pI6c,%pI6c,%d> not up, retry(%d)\n",
			    conn, &conn->c_laddr, &conn->c_faddr, conn->c_tos,
			    cp->cp_reconnect_retry_count);
		cp->cp_reconnect_racing = 0;
		rds_conn_path_drop(cp, DR_RECONNECT_TIMEOUT);
	}
}

void rds_shutdown_worker(struct work_struct *work)
{
	struct rds_conn_path *cp = container_of(work,
						struct rds_conn_path,
						cp_down_w);
	unsigned long now = get_seconds();
	bool is_tcp = cp->cp_conn->c_trans->t_type == RDS_TRANS_TCP;
	struct rds_connection *conn = cp->cp_conn;
	bool restart = true;

	if ((now - cp->cp_reconnect_start >
		rds_sysctl_shutdown_trace_start_time) &&
	    (now - cp->cp_reconnect_start <
		rds_sysctl_shutdown_trace_end_time))
		pr_info("RDS/%s: connection <%pI6c,%pI6c,%d> shutdown init due to '%s'\n",
			(is_tcp ? "TCP" : "IB"),
			&conn->c_laddr,
			&conn->c_faddr,
			conn->c_tos,
			conn_drop_reason_str(cp->cp_drop_source));

	/* If racing is detected, the bigger IP backs off and lets the
	 * smaller IP drive the reconnect (one-sided reconnect).
	 */
	if (cp->cp_reconnect_racing)
		restart = rds_conn_is_active_peer(conn);

	rds_rtd_ptr(RDS_RTD_CM,
		    "calling rds_conn_shutdown, conn %p restart: %d racing: %d <%pI6c,%pI6c,%d>\n",
		    conn, restart, cp->cp_reconnect_racing,
		    &conn->c_laddr, &conn->c_faddr, conn->c_tos);
	rds_conn_shutdown(cp, restart);
	if (!restart)
		queue_delayed_work(cp->cp_wq, &cp->cp_reconn_w,
				   msecs_to_jiffies(RDS_RECONNECT_RETRY_MS));
}

void rds_threads_exit(void)
{
	destroy_workqueue(rds_wq);
	destroy_workqueue(rds_local_wq);
}

int rds_threads_init(void)
{
	rds_wq = create_singlethread_workqueue("krdsd");
	if (!rds_wq)
		return -ENOMEM;

	rds_local_wq = create_singlethread_workqueue("krdsd_local");
	if (!rds_local_wq)
		return -ENOMEM;

	return 0;
}

/* Compare two IPv6 addresses.  Return 0 if the two addresses are equal.
 * Return 1 if the first is greater.  Return -1 if the second is greater.
 */
int rds_addr_cmp(const struct in6_addr *addr1,
		 const struct in6_addr *addr2)
{
#if defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS) && BITS_PER_LONG == 64
	const __be64 *a1, *a2;
	u64 x, y;

	a1 = (__be64 *)addr1;
	a2 = (__be64 *)addr2;

	if (*a1 != *a2) {
		if (be64_to_cpu(*a1) < be64_to_cpu(*a2))
			return -1;
		else
			return 1;
	} else {
		x = be64_to_cpu(*++a1);
		y = be64_to_cpu(*++a2);
		if (x < y)
			return -1;
		else if (x > y)
			return 1;
		else
			return 0;
	}
#else
	u32 a, b;
	int i;

	for (i = 0; i < 4; i++) {
		if (addr1->s6_addr32[i] != addr2->s6_addr32[i]) {
			a = ntohl(addr1->s6_addr32[i]);
			b = ntohl(addr2->s6_addr32[i]);
			if (a < b)
				return -1;
			else if (a > b)
				return 1;
		}
	}
	return 0;
#endif
}
EXPORT_SYMBOL_GPL(rds_addr_cmp);
