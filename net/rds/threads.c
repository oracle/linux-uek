/*
 * Copyright (c) 2006, 2020 Oracle and/or its affiliates.
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
#include <linux/workqueue.h>

#include "trace.h"

#include "rds.h"

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

	atomic64_set(&cp->cp_conn->c_trans->rds_avg_conn_jf, new_avg_jf);

	trace_rds_conn_update_connect_time(NULL, cp->cp_conn, cp, NULL, 0);
}

void rds_queue_work(struct rds_conn_path *cp,
		    struct workqueue_struct *wq,
		    struct work_struct *work,
		    char *reason)
{
	trace_rds_queue_work(cp ? cp->cp_conn : NULL, cp, wq, work, 0, reason);
	queue_work(wq, work);
}
EXPORT_SYMBOL_GPL(rds_queue_work);

void rds_queue_delayed_work(struct rds_conn_path *cp,
			    struct workqueue_struct *wq,
			    struct delayed_work *dwork,
			    unsigned long delay,
			    char *reason)
{
	trace_rds_queue_work(cp ? cp->cp_conn : NULL, cp, wq, &dwork->work,
			     delay, reason);
	queue_delayed_work(wq, dwork, delay);
}
EXPORT_SYMBOL_GPL(rds_queue_delayed_work);

void rds_queue_delayed_work_on(struct rds_conn_path *cp,
			       int cpu,
			       struct workqueue_struct *wq,
			       struct delayed_work *dwork,
			       unsigned long delay,
			       char *reason)
{
	trace_rds_queue_work(cp ? cp->cp_conn : NULL, cp, wq, &dwork->work,
			     delay, reason);
	queue_delayed_work_on(cpu, wq, dwork, delay);
}
EXPORT_SYMBOL_GPL(rds_queue_delayed_work_on);

void rds_queue_cancel_work(struct rds_conn_path *cp,
			   struct delayed_work *dwork, char *reason)
{
	trace_rds_queue_cancel_work(cp ? cp->cp_conn : NULL, cp, NULL,
				    &dwork->work, 0, reason);
	cancel_delayed_work_sync(dwork);
}
EXPORT_SYMBOL_GPL(rds_queue_cancel_work);

void rds_queue_flush_work(struct rds_conn_path *cp,
			  struct work_struct *work, char *reason)
{
	trace_rds_queue_flush_work(cp ? cp->cp_conn : NULL, cp, NULL,
				   work, 0, reason);
	flush_work(work);
}
EXPORT_SYMBOL_GPL(rds_queue_flush_work);

void rds_connect_path_complete(struct rds_conn_path *cp, int curr)
{
	struct rds_connection *conn = cp->cp_conn;

	if (!rds_conn_path_transition(cp, curr, RDS_CONN_UP, DR_DEFAULT)) {
		rds_conn_path_drop(cp, DR_IB_NOT_CONNECTING_STATE, 0);
		return;
	}

	cp->cp_reconnect_jiffies = 0;
	set_bit(RCMQ_BITOFF_CONGU_PENDING, &conn->c_map_queued);
	rds_clear_queued_send_work_bit(cp);
	rds_cond_queue_send_work(cp, 0);
	rds_clear_queued_recv_work_bit(cp);
	rds_cond_queue_recv_work(cp, 0);
	WRITE_ONCE(cp->cp_hb_start, 0);
	WRITE_ONCE(cp->cp_hb_state, HB_PONG_RCVD);
	rds_queue_delayed_work(cp, cp->cp_wq, &cp->cp_hb_w, 0,
			       "hb worker");

	rds_update_avg_connect_time(cp);
	cp->cp_reconnect = 1;
	cp->cp_connection_established = ktime_get_real_seconds();
	conn->c_proposed_version = RDS_PROTOCOL_VERSION;
}
EXPORT_SYMBOL_GPL(rds_connect_path_complete);

void rds_connect_complete(struct rds_connection *conn)
{
	rds_connect_path_complete(&conn->c_path[0], RDS_CONN_CONNECTING);
}
EXPORT_SYMBOL_GPL(rds_connect_complete);

void rds_queue_reconnect(struct rds_conn_path *cp, bool immediate)
{
	struct rds_connection *conn = cp->cp_conn;
	bool is_tcp = conn->c_trans->t_type == RDS_TRANS_TCP;
	uint64_t delay;

	/* let peer with smaller addr initiate reconnect, to avoid duels */
	if (is_tcp && rds_addr_cmp(&conn->c_laddr, &conn->c_faddr) >= 0) {
		trace_rds_queue_noop(conn, cp, NULL, NULL, 0,
				     "no reconnect; tcp with smaller addr");
		return;
	}

	if (immediate || cp->cp_reconnect_jiffies == 0) {
		cp->cp_reconnect_jiffies = rds_sysctl_reconnect_min_jiffies;
		delay = cp->cp_reconnect_jiffies;
	} else {
		delay = cp->cp_reconnect_jiffies;
	}

	if (!immediate &&
	    (!conn->c_trans->conn_has_alt_conn ||
	     !conn->c_trans->conn_has_alt_conn(conn)) &&
	    rds_addr_cmp(&conn->c_faddr, &conn->c_laddr) < 0) {
		/* we're the passive side with no request to yield to */
		if (delay < rds_sysctl_reconnect_passive_min_jiffies)
			delay = rds_sysctl_reconnect_passive_min_jiffies;
	}

	if (rds_cond_queue_reconnect_work(cp, delay))
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

	trace_rds_queue_worker(cp->cp_conn, cp, cp->cp_wq, work, 0,
			       "connect worker");

	if (is_tcp && cp->cp_index > 0 &&
	    rds_addr_cmp(&cp->cp_conn->c_laddr, &cp->cp_conn->c_faddr) > 0)
		goto out;

	ret = rds_conn_path_transition(cp, RDS_CONN_DOWN, RDS_CONN_CONNECTING,
				       DR_DEFAULT);
	if (ret) {
		/*
		 * record the time we started trying to connect so that we can
		 * drop the connection if it doesn't work out after a while
		 */
		cp->cp_connection_initiated = ktime_get_real_seconds();
		cp->cp_connection_attempts++;
		cp->cp_drop_source = DR_DEFAULT;

		ret = conn->c_trans->conn_path_connect(cp);
		if (ret)
			rds_conn_path_drop(cp, DR_CONN_CONNECT_FAIL, ret);
	}

out:
	rds_clear_reconnect_pending_work_bit(cp);
}

void rds_send_worker(struct work_struct *work)
{
	struct rds_conn_path *cp = container_of(work,
						struct rds_conn_path,
						cp_send_w.work);
	unsigned long delay;
	int ret;

	trace_rds_queue_worker(cp->cp_conn, cp, cp->cp_wq, work, 0,
			       "send worker");

	if (rds_conn_path_state(cp) == RDS_CONN_UP) {
		rds_clear_queued_send_work_bit(cp);
		clear_bit(RDS_LL_SEND_FULL, &cp->cp_flags);
		ret = rds_send_xmit(cp);
		cond_resched();
		if (ret)
			trace_rds_send_worker_err(NULL, cp->cp_conn, cp,
						  "send worker err", ret);

		switch (ret) {
		case -EAGAIN:
			rds_stats_inc(s_send_immediate_retry);
			delay = 0;
			break;
		case -ENOMEM:
			rds_stats_inc(s_send_delayed_retry);
			delay = 2;
			break;
		default:
			return;
		}

		rds_cond_queue_send_work(cp, delay);
	}
}

void rds_recv_worker(struct work_struct *work)
{
	struct rds_conn_path *cp = container_of(work,
						struct rds_conn_path,
						cp_recv_w.work);
	unsigned long delay;
	int ret;

	trace_rds_queue_worker(cp->cp_conn, cp, cp->cp_wq, work, 0,
			       "recv worker");

	if (rds_conn_path_state(cp) == RDS_CONN_UP) {
		rds_clear_queued_recv_work_bit(cp);
		ret = cp->cp_conn->c_trans->recv_path(cp);

		if (ret)
			trace_rds_receive_worker_err(NULL, cp->cp_conn, cp,
						     "recv worker err", ret);

		switch (ret) {
		case -EAGAIN:
			rds_stats_inc(s_recv_immediate_retry);
			delay = 0;
			break;
		case -ENOMEM:
			rds_stats_inc(s_recv_delayed_retry);
			delay = 2;
		default:
			return;
		}
		rds_cond_queue_recv_work(cp, delay);
	}
}

void rds_hb_worker(struct work_struct *work)
{
	struct rds_conn_path *cp = container_of(work,
						struct rds_conn_path,
						cp_hb_w.work);
	time64_t now = ktime_get_real_seconds();
	unsigned long delay = HZ;
	int ret;
	struct rds_connection *conn = cp->cp_conn;

	trace_rds_queue_worker(cp->cp_conn, cp, cp->cp_wq, work, 0,
			       "hb worker");

	if (!rds_sysctl_conn_hb_timeout || conn->c_loopback ||
	    conn->c_trans->t_type == RDS_TRANS_TCP)
		return;

	if (rds_conn_path_state(cp) == RDS_CONN_UP) {
		switch (READ_ONCE(cp->cp_hb_state)) {
		case HB_PING_SENT:
			if (!READ_ONCE(cp->cp_hb_start)) {
				WRITE_ONCE(cp->cp_hb_state, HB_PONG_RCVD);
				/* Pseudo random from 50% to 150% of interval */
				delay = msecs_to_jiffies(rds_sysctl_conn_hb_interval * 1000 / 2) +
					msecs_to_jiffies(get_random_u32() % rds_sysctl_conn_hb_interval * 1000);
			} else if (now - READ_ONCE(cp->cp_hb_start) > rds_sysctl_conn_hb_timeout) {
				rds_conn_path_drop(cp, DR_HB_TIMEOUT, 0);
				return;
			}
			break;

		case HB_PONG_RCVD:
			ret = rds_send_hb(cp->cp_conn, 0);

			if (ret) {
				/* rds_send_hb() will call rds_send_probe();
				 * if the latter fails, drop-out trace events
				 * will occur.
				 */
				return;
			}
			WRITE_ONCE(cp->cp_hb_start, now);
			WRITE_ONCE(cp->cp_hb_state, HB_PING_SENT);
			break;
		}

		rds_queue_delayed_work(cp, cp->cp_wq, &cp->cp_hb_w, delay,
				       "hb worker");
	}
}

void rds_shutdown_worker(struct work_struct *work)
{
	struct rds_conn_path *cp = container_of(work,
						struct rds_conn_path,
						cp_down_w);
	time64_t now = ktime_get_real_seconds();
	bool is_tcp = cp->cp_conn->c_trans->t_type == RDS_TRANS_TCP;
	struct rds_connection *conn = cp->cp_conn;

	trace_rds_queue_worker(cp->cp_conn, cp, cp->cp_wq, work, 0,
			       "shutdown worker");

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

	rds_conn_init_shutdown(cp);
}

void rds_threads_exit(void)
{
	destroy_workqueue(rds_wq);
}

int rds_threads_init(void)
{
	rds_wq = create_singlethread_workqueue("krdsd");
	if (!rds_wq)
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
