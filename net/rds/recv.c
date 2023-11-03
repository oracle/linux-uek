/*
 * Copyright (c) 2006, 2023 Oracle and/or its affiliates.
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
#include <net/sock.h>
#include <linux/in.h>
#include <linux/time.h>
#include <linux/rds.h>
#include <linux/sched/clock.h>

#include "rds.h"
#include "loop.h"

#include "trace.h"

void rds_inc_init(struct rds_incoming *inc, struct rds_connection *conn,
		  struct in6_addr *saddr)
{
	int i;

	atomic_set(&inc->i_refcount, 1);
	INIT_LIST_HEAD(&inc->i_item);
	inc->i_conn = conn;
	inc->i_saddr = *saddr;
	inc->i_usercopy.rdma_cookie = 0;
	inc->i_usercopy.rx_tstamp.tv_sec = 0;
	inc->i_usercopy.rx_tstamp.tv_usec = 0;
	inc->i_payload_csum.csum_val.raw = 0;
	inc->i_payload_csum.csum_enabled = false;

	for (i = 0; i < RDS_RX_MAX_TRACES; i++)
		inc->i_rx_lat_trace[i] = 0;
}
EXPORT_SYMBOL_GPL(rds_inc_init);

void rds_inc_path_init(struct rds_incoming *inc, struct rds_conn_path *cp,
		       struct in6_addr *saddr)
{
	int i;

	atomic_set(&inc->i_refcount, 1);
	INIT_LIST_HEAD(&inc->i_item);
	inc->i_conn = cp->cp_conn;
	inc->i_conn_path = cp;
	inc->i_saddr = *saddr;
	inc->i_usercopy.rdma_cookie = 0;
	inc->i_usercopy.rx_tstamp.tv_sec = 0;
	inc->i_usercopy.rx_tstamp.tv_usec = 0;
	inc->i_payload_csum.csum_val.raw = 0;
	inc->i_payload_csum.csum_enabled = false;

	for (i = 0; i < RDS_RX_MAX_TRACES; i++)
		inc->i_rx_lat_trace[i] = 0;
}
EXPORT_SYMBOL_GPL(rds_inc_path_init);

void rds_inc_addref(struct rds_incoming *inc)
{
	rdsdebug("addref inc %p ref %d\n", inc, atomic_read(&inc->i_refcount));
	atomic_inc(&inc->i_refcount);
}
EXPORT_SYMBOL_GPL(rds_inc_addref);

void rds_inc_put(struct rds_incoming *inc)
{
	rdsdebug("put inc %p ref %d\n", inc, atomic_read(&inc->i_refcount));
	if (atomic_dec_and_test(&inc->i_refcount)) {
		BUG_ON(!list_empty(&inc->i_item));

		inc->i_conn->c_trans->inc_free(inc);
	}
}
EXPORT_SYMBOL_GPL(rds_inc_put);

static void rds_recv_rcvbuf_delta(struct rds_sock *rs, struct sock *sk,
				  struct rds_connection *conn,
				  int delta, __be16 port)
{
	int now_congested;
	struct rds_cong_map *map;

	if (delta == 0)
		return;

	/* Note: For loopback transport, the 'conn' passed is the
	 * sending endpoint, not the receiving endpoint.
	 * We want the congestion that corresponds to the
	 * destination(receiving)endpoint which is "local" for the
	 * receiving endpoint but "foreign" for the sending endpoint.
	 */
	if (conn->c_loopback && conn->c_trans == &rds_loop_transport)
		map = conn->c_fcong;
	else
		map = conn->c_lcong;

	rs->rs_rcv_bytes += delta;
	if (delta > 0)
		rds_stats_add(s_recv_bytes_added_to_socket, delta);
	else
		rds_stats_add(s_recv_bytes_removed_from_socket, -delta);
	now_congested = rs->rs_rcv_bytes > rds_sk_rcvbuf(rs);

	rdsdebug("rs %p (%pI6c:%u) recv bytes %d buf %d "
	  "now_cong %d delta %d\n",
	  rs, &rs->rs_bound_addr,
	  ntohs(rs->rs_bound_port), rs->rs_rcv_bytes,
	  rds_sk_rcvbuf(rs), now_congested, delta);

	/* wasn't -> am congested */
	if (!rs->rs_congested && now_congested) {
		rs->rs_congested = 1;
		rds_cong_set_bit(map, port);
		trace_rds_cong_seen(rs, conn, NULL,
				    "receive bytes > rcvbuf size", 0);
		rds_cong_queue_updates(map);
	}
	/* was -> aren't congested */
	/* Require more free space before reporting uncongested to prevent
	   bouncing cong/uncong state too often */
	else if (rs->rs_congested && (rs->rs_rcv_bytes < (rds_sk_rcvbuf(rs)/2))) {
		rs->rs_congested = 0;
		rds_cong_clear_bit(map, port);
		trace_rds_cong_cleared(rs, conn, NULL,
				       "receive bytes < rcvbuf size/2", 0);
		rds_cong_queue_updates(map);
	}

	/* do nothing if no change in cong state */
}

/*
 * Process all extension headers that come with this message.
 */
static void rds_recv_incoming_exthdrs(struct rds_incoming *inc, struct rds_sock *rs)
{
	struct rds_header *hdr = &inc->i_hdr;
	unsigned int pos = 0, type, len;
	union {
		struct rds_ext_header_version version;
		struct rds_ext_header_rdma rdma;
		struct rds_ext_header_rdma_dest rdma_dest;
		struct rds_ext_header_cap_bits cap_bits;
		struct rds_ext_header_rdma_csum rdma_csum;
	} buffer;

	while (1) {
		len = sizeof(buffer);
		type = rds_message_next_extension(hdr, &pos, &buffer, &len);
		if (type == RDS_EXTHDR_NONE)
			break;
		/* Process extension header here */
		switch (type) {
		case RDS_EXTHDR_RDMA:
			rds_rdma_unuse(rs, be32_to_cpu(buffer.rdma.h_rdma_rkey), 0);
			break;

		case RDS_EXTHDR_RDMA_DEST:
			/* We ignore the size for now. We could stash it
			 * somewhere and use it for error checking. */
			inc->i_usercopy.rdma_cookie = rds_rdma_make_cookie(
					be32_to_cpu(buffer.rdma_dest.h_rdma_rkey),
					be32_to_cpu(buffer.rdma_dest.h_rdma_offset));

			break;

		case RDS_EXTHDR_CSUM:
			if (unlikely(rds_sysctl_enable_payload_csum)) {
				inc->i_payload_csum.csum_enabled =
					buffer.rdma_csum.h_rdma_csum_enabled;
				inc->i_payload_csum.csum_val.raw =
					be32_to_cpu(buffer.rdma_csum.h_rdma_csum_val);
			} else {
				inc->i_payload_csum.csum_enabled = false;
				inc->i_payload_csum.csum_val.raw = 0;
				rds_stats_inc(s_recv_payload_csum_ignored);
			}

			break;
		}
	}
}

/* Process heartbeat extension header that comes with this message. */
static void rds_recv_incoming_hb_exthdr(struct rds_incoming *inc)
{
	struct rds_header *hdr = &inc->i_hdr;
	unsigned int pos = 0;
	unsigned int type;
	unsigned int len;
	u32 cap_bits = 0;
	union {
		struct rds_ext_header_version version;
		struct rds_ext_header_rdma rdma;
		struct rds_ext_header_rdma_dest rdma_dest;
		struct rds_ext_header_cap_bits cap_bits;
	} buffer;

	while (1) {
		len = sizeof(buffer);
		type = rds_message_next_extension(hdr, &pos, &buffer, &len);
		if (type == RDS_EXTHDR_NONE)
			break;
		/* Process extension header here */
		if (type == RDS_EXTHDR_CAP_BITS) {
			/* Enable HB if an incoming PING/PONG has the ext header cap bit */
			cap_bits = be32_to_cpu(buffer.cap_bits.h_cap_bits);
			inc->i_conn->c_is_hb_enabled =
				cap_bits & RDS_FLAG_EXTHDR_CAP_BITS_HB;
			break;
		}
	}
}

static void rds_recv_hs_exthdrs(struct rds_header *hdr,
				struct rds_connection *conn)
{
	unsigned int pos = 0, type, len;
	union {
		struct rds_ext_header_version version;
		__be16 rds_npaths;
		u8     dummy;
	} buffer;
	bool new_with_sport_idx = false;
	int new_npaths;
	bool fan_out;

	new_npaths = conn->c_npaths;

	while (1) {
		len = sizeof(buffer);
		type = rds_message_next_extension(hdr, &pos, &buffer, &len);
		if (type == RDS_EXTHDR_NONE)
			break;
		/* Process extension header here */
		switch (type) {
		case RDS_EXTHDR_NPATHS:
			new_npaths = min_t(int, RDS_MPATH_WORKERS,
					   be16_to_cpu(buffer.rds_npaths));
			break;
		case RDS_EXTHDR_SPORT_IDX:
			new_with_sport_idx = true;
			break;
		default:
			pr_warn_ratelimited("rds: ignoring unknown exthdr "
					    "(type 0x%x, len %u)\n", type, len);
		}
	}

	conn->c_with_sport_idx = new_with_sport_idx;

	if (new_npaths > 1 && new_npaths != conn->c_npaths) {
		/* We're about to fan-out.
		 * Make sure that messages from cp_index#0
		 * are sent prior to handling other lanes.
		 */
		struct rds_conn_path *cp0 = conn->c_path;
		unsigned long flags;

		spin_lock_irqsave(&cp0->cp_lock, flags);
		conn->c_cp0_mprds_catchup_tx_seq = cp0->cp_next_tx_seq;
		spin_unlock_irqrestore(&cp0->cp_lock, flags);
		fan_out = true;
	} else {
		fan_out = false;
	}

	/* if RDS_EXTHDR_NPATHS was not found, default to a single-path */
	conn->c_npaths = max_t(int, new_npaths, 1);

	conn->c_ping_triggered = 0;

	if (conn->c_npaths > 1 && conn->c_trans->conn_slots_available)
		conn->c_trans->conn_slots_available(conn, fan_out);
}

/* rds_start_mprds() will synchronously start multiple paths when appropriate.
 * The scheme is based on the following rules:
 *
 * 1. rds_sendmsg on first connect attempt sends the probe ping, with the
 *    sender's npaths (s_npaths)
 * 2. rcvr of probe-ping knows the mprds_paths = min(s_npaths, r_npaths). It
 *    sends back a probe-pong with r_npaths. After that, if rcvr is the
 *    smaller ip addr, it starts rds_conn_path_connect_if_down on all
 *    mprds_paths.
 * 3. sender gets woken up, and can move to rds_conn_path_connect_if_down.
 *    If it is the smaller ipaddr, rds_conn_path_connect_if_down can be
 *    called after reception of the probe-pong on all mprds_paths.
 *    Otherwise (sender of probe-ping is not the smaller ip addr): just call
 *    rds_conn_path_connect_if_down on the hashed path. (see rule 4)
 * 4. rds_connect_worker must only trigger a connection if laddr < faddr.
 * 5. sender may end up queuing the packet on the cp. will get sent out later.
 *    when connection is completed.
 */
static void rds_start_mprds(struct rds_connection *conn)
{
	int i;
	struct rds_conn_path *cp;

	if (conn->c_npaths > 1 &&
	    rds_addr_cmp(&conn->c_laddr, &conn->c_faddr) < 0) {
		for (i = 0; i < conn->c_npaths; i++) {
			cp = &conn->c_path[i];
			rds_conn_path_connect_if_down(cp);
		}
	}
}

/*
 * The transport must make sure that this is serialized against other
 * rx and conn reset on this specific conn.
 *
 * We currently assert that only one fragmented message will be sent
 * down a connection at a time.  This lets us reassemble in the conn
 * instead of per-flow which means that we don't have to go digging through
 * flows to tear down partial reassembly progress on conn failure and
 * we save flow lookup and locking for each frag arrival.  It does mean
 * that small messages will wait behind large ones.  Fragmenting at all
 * is only to reduce the memory consumption of pre-posted buffers.
 *
 * The caller passes in saddr and daddr instead of us getting it from the
 * conn.  This lets loopback, who only has one conn for both directions,
 * tell us which roles the addrs in the conn are playing for this message.
 */
void rds_recv_incoming(struct rds_connection *conn, struct in6_addr *saddr,
		       struct in6_addr *daddr,
		       struct rds_incoming *inc, gfp_t gfp)
{
	struct rds_conn_path *cp = rds_conn_to_path(conn, inc);
	struct rds_sock *rs = NULL;
	char *dropreason = NULL;
	struct sock *sk;
	u64 inc_hdr_h_sequence;
	unsigned long flags;

	rdsdebug(KERN_ALERT "incoming:  conn %p, inc %p, %pI6c : %d -> %pI6c : %d\n",
		 conn, inc, saddr, inc->i_hdr.h_sport, daddr,
		 inc->i_hdr.h_dport);

	inc->i_conn = conn;
	inc->i_rx_jiffies = jiffies;

	/*
	 * Sequence numbers should only increase.  Messages get their
	 * sequence number as they're queued in a sending conn.  They
	 * can be dropped, though, if the sending socket is closed before
	 * they hit the wire.  So sequence numbers can skip forward
	 * under normal operation.  They can also drop back in the conn
	 * failover case as previously sent messages are resent down the
	 * new instance of a conn.  We drop those, otherwise we have
	 * to assume that the next valid seq does not come after a
	 * hole in the fragment stream.
	 *
	 * The headers don't give us a way to realize if fragments of
	 * a message have been dropped.  We assume that frags that arrive
	 * to a flow are part of the current message on the flow that is
	 * being reassembled.  This means that senders can't drop messages
	 * from the sending conn until all their frags are sent.
	 *
	 * XXX we could spend more on the wire to get more robust failure
	 * detection, arguably worth it to avoid data corruption.
	 */
	inc_hdr_h_sequence = be64_to_cpu(inc->i_hdr.h_sequence);

	if (inc_hdr_h_sequence < cp->cp_next_rx_seq
	 && (inc->i_hdr.h_flags & RDS_FLAG_RETRANSMITTED)) {
		rds_stats_inc(s_recv_drop_old_seq);
		dropreason = "dropping old sequence number";
		goto out;
	}
	cp->cp_next_rx_seq = inc_hdr_h_sequence + 1;

	if (rds_sysctl_ping_enable && inc->i_hdr.h_dport == 0) {
		bool is_hb_ping = (inc->i_hdr.h_flags & RDS_FLAG_ANY_HB) == RDS_FLAG_HB_PING;
		bool is_hb_pong = (inc->i_hdr.h_flags & RDS_FLAG_ANY_HB) == RDS_FLAG_HB_PONG;

		if (inc->i_hdr.h_len) {
			dropreason = "ignore ping with non-zero length";
			goto out;
		}

		/* One and only one of the heart-beat flags must be set */
		if (inc->i_hdr.h_sport == 0 && !(is_hb_ping ^ is_hb_pong)) {
			dropreason = "ignore ping with 0 sport";
			goto out;
		}
		if (is_hb_ping) {
			rds_stats_inc(s_recv_hb_ping);
			trace_rds_heartbeat_receive_ping(conn, cp, saddr, daddr);
			rds_recv_incoming_hb_exthdr(inc);
			rds_send_hb(conn, 1);
		} else if (is_hb_pong) {
			rds_stats_inc(s_recv_hb_pong);
			trace_rds_heartbeat_receive_pong(conn, cp, saddr, daddr);
			rds_recv_incoming_hb_exthdr(inc);
			WRITE_ONCE(cp->cp_hb_start, 0);
		} else {
			if (be16_to_cpu(inc->i_hdr.h_sport) == RDS_FLAG_PROBE_PORT)
				rds_stats_inc(s_recv_mprds_ping);
			else
				rds_stats_inc(s_recv_ping);

			rds_send_pong(cp, inc->i_hdr.h_sport);
			/* if this is a handshake ping,
			 * start multipath if necessary
			 */
			if (conn->c_trans->t_mp_capable &&
			    RDS_HS_PROBE(be16_to_cpu(inc->i_hdr.h_sport),
					 be16_to_cpu(inc->i_hdr.h_dport))) {
				rds_recv_hs_exthdrs(&inc->i_hdr, cp->cp_conn);
				rds_start_mprds(cp->cp_conn);
			}
		}
		goto out;
	}
	if (conn->c_trans->t_mp_capable &&
	    be16_to_cpu(inc->i_hdr.h_dport) ==  RDS_FLAG_PROBE_PORT &&
	    inc->i_hdr.h_sport == 0) {
		rds_stats_inc(s_recv_mprds_pong);
		rds_recv_hs_exthdrs(&inc->i_hdr, cp->cp_conn);
		/* if this is a handshake pong, start multipath if necessary */
		rds_start_mprds(cp->cp_conn);
		wake_up(&cp->cp_conn->c_hs_waitq);
		goto out;
	}

	if (!inc->i_hdr.h_sport)
		rds_stats_inc(s_recv_pong);

	rs = rds_find_bound(conn->c_rns, daddr, inc->i_hdr.h_dport, conn->c_bound_if);
	if (!rs) {
		rds_stats_inc(s_recv_drop_no_sock);
		dropreason = "no socket";
		goto out;
	}

	/* Process extension headers */
	rds_recv_incoming_exthdrs(inc, rs);

	/* We can be racing with rds_release() which marks the socket dead. */
	sk = rds_rs_to_sk(rs);

	/* serialize with rds_release -> sock_orphan */
	write_lock_irqsave(&rs->rs_recv_lock, flags);
	if (!sock_flag(sk, SOCK_DEAD)) {
		/* only queue the incoming once. when rds netfilter hook
		 * is  enabled, the follow code path can cause us to send
		 * rds_incoming twice to rds_recv_local: rds_recv_incoming
		 * call NF_HOOK, hook decide to send rds incoming to both,
		 * local & remote, rds_recv_local queue the inc msg,
		 * rds_recv_forward fail to send the inc to remote & call
		 * rds_recv_local again with the same rds inc. calling list
		 * on alredy added list item w/o calling list_del_init in
		 * between cause list corruption */
		if (list_empty(&inc->i_item)) {
			rdsdebug("adding inc %p to rs %p's recv queue\n",
				inc, rs);
			rds_stats_inc(s_recv_queued);
			rds_recv_rcvbuf_delta(rs, sk, inc->i_conn,
					      be32_to_cpu(inc->i_hdr.h_len),
					      inc->i_hdr.h_dport);
			if (sock_flag(sk, SOCK_RCVTSTAMP)) {
				struct timespec64 now;
				ktime_get_real_ts64(&now);
				inc->i_usercopy.rx_tstamp.tv_sec = now.tv_sec;
				inc->i_usercopy.rx_tstamp.tv_usec = now.tv_nsec / 1000;
			}
			rds_inc_addref(inc);
			list_add_tail(&inc->i_item, &rs->rs_recv_queue);
			inc->i_rx_lat_trace[RDS_MSG_RX_END] = local_clock();
			__rds_wake_sk_sleep(sk);
		}
	} else {
		dropreason = "dead socket";
		rds_stats_inc(s_recv_drop_dead_sock);
	}
	write_unlock_irqrestore(&rs->rs_recv_lock, flags);

out:
	if (dropreason)
		trace_rds_drop_ingress(inc, rs, conn, cp, saddr, daddr,
				       dropreason);
	else
		trace_rds_receive(inc, rs, conn, cp, saddr, daddr);

	if (rs)
		rds_sock_put(rs);
}
EXPORT_SYMBOL_GPL(rds_recv_incoming);

/*
 * be very careful here.  This is being called as the condition in
 * wait_event_*() needs to cope with being called many times.
 */
static int rds_next_incoming(struct rds_sock *rs, struct rds_incoming **inc)
{
	unsigned long flags;

	if (!*inc) {
		read_lock_irqsave(&rs->rs_recv_lock, flags);
		if (!list_empty(&rs->rs_recv_queue)) {
			*inc = list_entry(rs->rs_recv_queue.next,
					  struct rds_incoming,
					  i_item);
			rds_inc_addref(*inc);
		}
		read_unlock_irqrestore(&rs->rs_recv_lock, flags);
	}

	return *inc != NULL;
}

static int rds_still_queued(struct rds_sock *rs, struct rds_incoming *inc,
			    int drop)
{
	struct sock *sk = rds_rs_to_sk(rs);
	int ret = 0;
	unsigned long flags;

	write_lock_irqsave(&rs->rs_recv_lock, flags);
	if (!list_empty(&inc->i_item)) {
		ret = 1;
		if (drop) {
			/* XXX make sure this i_conn is reliable */
			rds_recv_rcvbuf_delta(rs, sk, inc->i_conn,
					      -be32_to_cpu(inc->i_hdr.h_len),
					      inc->i_hdr.h_dport);
			list_del_init(&inc->i_item);
			rds_inc_put(inc);
		}
	}
	write_unlock_irqrestore(&rs->rs_recv_lock, flags);

	rdsdebug("inc %p rs %p still %d dropped %d\n", inc, rs, ret, drop);
	return ret;
}

/*
 * Pull errors off the error queue.
 * If msghdr is NULL, we will just purge the error queue.
 */
int rds_notify_queue_get(struct rds_sock *rs, struct msghdr *msghdr)
{
	struct rds_notifier *notifier;
	struct rds_rdma_send_notify cmsg;
	unsigned int count = 0, max_messages = ~0U;
	unsigned long flags;
	LIST_HEAD(copy);
	int err = 0;


	/* put_cmsg copies to user space and thus may sleep. We can't do this
	 * with rs_lock held, so first grab as many notifications as we can stuff
	 * in the user provided cmsg buffer. We don't try to copy more, to avoid
	 * losing notifications - except when the buffer is so small that it wouldn't
	 * even hold a single notification. Then we give him as much of this single
	 * msg as we can squeeze in, and set MSG_CTRUNC.
	 */
	if (msghdr) {
		max_messages = msghdr->msg_controllen / CMSG_SPACE(sizeof(cmsg));
		if (!max_messages)
			max_messages = 1;
	}

	spin_lock_irqsave(&rs->rs_lock, flags);
	while (!list_empty(&rs->rs_notify_queue) && count < max_messages) {
		notifier = list_entry(rs->rs_notify_queue.next,
				struct rds_notifier, n_list);
		list_move_tail(&notifier->n_list, &copy);
		count++;
	}
	spin_unlock_irqrestore(&rs->rs_lock, flags);

	if (!count)
		return 0;

	while (!list_empty(&copy)) {
		notifier = list_entry(copy.next, struct rds_notifier, n_list);

		if (msghdr) {
			cmsg.user_token = notifier->n_user_token;
			cmsg.status = notifier->n_status;

			err = put_cmsg(msghdr, SOL_RDS,
					RDS_CMSG_RDMA_SEND_STATUS,
				       sizeof(cmsg), &cmsg);
			if (err)
				break;
		}

		/* If this is the last failed op, re-open the connection for
		   traffic */
		if (notifier->n_conn) {
			struct rds_conn_path *ncp;

			ncp = &notifier->n_conn->c_path[0];
			spin_lock_irqsave(&ncp->cp_lock, flags);
			if (ncp->cp_pending_flush)
				ncp->cp_pending_flush--;
			else
				printk(KERN_ERR "rds_notify_queue_get: OOPS!\n");
			spin_unlock_irqrestore(&ncp->cp_lock, flags);
		}

		list_del_init(&notifier->n_list);
		kfree(notifier);
	}

	/* If we bailed out because of an error in put_cmsg,
	 * we may be left with one or more notifications that we
	 * didn't process. Return them to the head of the list. */
	if (!list_empty(&copy)) {
		spin_lock_irqsave(&rs->rs_lock, flags);
		list_splice(&copy, &rs->rs_notify_queue);
		spin_unlock_irqrestore(&rs->rs_lock, flags);
	}

	return err;
}

/*
 * Queue a congestion notification
 */
static int rds_notify_cong(struct rds_sock *rs, struct msghdr *msghdr)
{
	u64 notify = atomic64_read(&rs->rs_cong_notify);
	int err;

	err = put_cmsg(msghdr, SOL_RDS, RDS_CMSG_CONG_UPDATE,
			sizeof(notify), &notify);
	if (err)
		return err;

	atomic64_and(~notify, &rs->rs_cong_notify);

	return 0;
}

/*
 * Receive any control messages.
 */
static int rds_cmsg_recv(struct rds_incoming *inc, struct msghdr *msg,
			 struct rds_sock *rs)
{
	int ret = 0;

	if (inc->i_usercopy.rdma_cookie) {
		ret = put_cmsg(msg, SOL_RDS, RDS_CMSG_RDMA_DEST,
				sizeof(inc->i_usercopy.rdma_cookie),
				&inc->i_usercopy.rdma_cookie);
		if (ret)
			goto out;
	}

	if ((inc->i_usercopy.rx_tstamp.tv_sec != 0) &&
	    sock_flag(rds_rs_to_sk(rs), SOCK_RCVTSTAMP)) {
		ret = put_cmsg(msg, SOL_SOCKET,
			       SO_TIMESTAMP_OLD,
			       sizeof(inc->i_usercopy.rx_tstamp),
			       &inc->i_usercopy.rx_tstamp);
		if (ret)
			goto out;
	}

	if (rs->rs_rx_traces) {
		struct rds_cmsg_rx_trace t;
		int i, j;

		inc->i_rx_lat_trace[RDS_MSG_RX_CMSG] = local_clock();
		t.rx_traces =  rs->rs_rx_traces;
		for (i = 0; i < rs->rs_rx_traces; i++) {
			j = rs->rs_rx_trace[i];
			t.rx_trace_pos[i] = j;
			t.rx_trace[i] = inc->i_rx_lat_trace[j + 1] -
					  inc->i_rx_lat_trace[j];
		}

		ret = put_cmsg(msg, SOL_RDS, RDS_CMSG_RXPATH_LATENCY,
				sizeof(t), &t);
		if (ret)
			goto out;
	}

	if (rs->rs_inq) {
		unsigned long flags;
		int rcv_bytes;

		read_lock_irqsave(&rs->rs_recv_lock, flags);
		rcv_bytes = rs->rs_rcv_bytes;
		ret = put_cmsg(msg, SOL_RDS, RDS_CMSG_INQ,
			       sizeof(rcv_bytes), &rcv_bytes);
		read_unlock_irqrestore(&rs->rs_recv_lock, flags);
		if (ret)
			goto out;
	}

out:
	return ret;
}

int rds_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
		int msg_flags)
{
	struct sock *sk = sock->sk;
	struct rds_sock *rs = rds_sk_to_rs(sk);
	long timeo;
	int ret = 0, nonblock = msg_flags & MSG_DONTWAIT;
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	struct rds_incoming *inc = NULL;

	/* udp_recvmsg()->sock_recvtimeo() gets away without locking too.. */
	timeo = sock_rcvtimeo(sk, nonblock);

	rdsdebug("size %zu flags 0x%x timeo %ld\n", size, msg_flags, timeo);

	msg->msg_namelen = 0;

	if (msg_flags & MSG_OOB)
		goto out;

	while (1) {
		struct iov_iter save;
		/* If there are pending notifications, do those - and nothing else */
		if (!list_empty(&rs->rs_notify_queue)) {
			ret = rds_notify_queue_get(rs, msg);
			break;
		}

		if (atomic64_read(&rs->rs_cong_notify)) {
			ret = rds_notify_cong(rs, msg);
			break;
		}

		if (!rds_next_incoming(rs, &inc)) {
			if (nonblock) {
				ret = -EAGAIN;
				break;
			}

			timeo =	wait_event_interruptible_timeout(*sk_sleep(sk),
								 (!list_empty(&rs->rs_notify_queue) ||
								  atomic64_read(&rs->rs_cong_notify) ||
								  rds_next_incoming(rs, &inc)),
								 timeo);
			rdsdebug("recvmsg woke inc %p timeo %ld\n", inc,
				 timeo);
			if (timeo > 0 || timeo == MAX_SCHEDULE_TIMEOUT)
				continue;

			ret = timeo;
			if (ret == 0)
				ret = -ETIMEDOUT;
			break;
		}

		rdsdebug("copying inc %p from %pI6c:%u to user\n", inc,
			 &inc->i_conn->c_faddr,
			 ntohs(inc->i_hdr.h_sport));
		save = msg->msg_iter;
		ret = inc->i_conn->c_trans->inc_copy_to_user(inc, &msg->msg_iter);
		if (ret < 0)
			break;

		/*
		 * if the message we just copied isn't at the head of the
		 * recv queue then someone else raced us to return it, try
		 * to get the next message.
		 */
		if (!rds_still_queued(rs, inc, !(msg_flags & MSG_PEEK))) {
			rds_inc_put(inc);
			inc = NULL;
			rds_stats_inc(s_recv_deliver_raced);
			msg->msg_iter = save;
			continue;
		}

		if (ret < be32_to_cpu(inc->i_hdr.h_len)) {
			if (msg_flags & MSG_TRUNC)
				ret = be32_to_cpu(inc->i_hdr.h_len);
			msg->msg_flags |= MSG_TRUNC;
		}

		if (rds_cmsg_recv(inc, msg, rs)) {
			ret = -EFAULT;
			break;
		}

		rds_stats_inc(s_recv_delivered);

		if (msg->msg_name) {
			if (ipv6_addr_v4mapped(&inc->i_saddr)) {
				sin = (struct sockaddr_in *)msg->msg_name;

				sin->sin_family = AF_INET;
				sin->sin_port = inc->i_hdr.h_sport;
				sin->sin_addr.s_addr =
				    inc->i_saddr.s6_addr32[3];
				memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
				msg->msg_namelen = sizeof(*sin);
			} else {
				sin6 = (struct sockaddr_in6 *)msg->msg_name;

				sin6->sin6_family = AF_INET6;
				sin6->sin6_port = inc->i_hdr.h_sport;
				sin6->sin6_addr = inc->i_saddr;
				sin6->sin6_flowinfo = 0;
				sin6->sin6_scope_id = rs->rs_bound_scope_id;
				msg->msg_namelen = sizeof(*sin6);
			}
		}
		break;
	}

	if (inc)
		rds_inc_put(inc);

out:
	return ret;
}

/*
 * The socket is being shut down and we're asked to drop messages that were
 * queued for recvmsg.  The caller has unbound the socket so the receive path
 * won't queue any more incoming fragments or messages on the socket.
 */
void rds_clear_recv_queue(struct rds_sock *rs)
{
	struct sock *sk = rds_rs_to_sk(rs);
	struct rds_incoming *inc, *tmp;
	unsigned long flags;

	write_lock_irqsave(&rs->rs_recv_lock, flags);
	list_for_each_entry_safe(inc, tmp, &rs->rs_recv_queue, i_item) {
		rds_recv_rcvbuf_delta(rs, sk, inc->i_conn,
				      -be32_to_cpu(inc->i_hdr.h_len),
				      inc->i_hdr.h_dport);
		list_del_init(&inc->i_item);
		rds_inc_put(inc);
	}
	write_unlock_irqrestore(&rs->rs_recv_lock, flags);
}

/* C wrapper for call to tracepoint in case of RDS receive checksum error */
void do_rds_receive_csum_err(struct rds_incoming *inc, u32 csum_calc)
{
	struct rds_message *rm = container_of(inc, struct rds_message, m_inc);

	trace_rds_receive_csum_err(inc, rm->m_rs, inc->i_conn, inc->i_conn_path,
				   &inc->i_saddr, &rm->m_daddr, csum_calc);
}
EXPORT_SYMBOL(do_rds_receive_csum_err);

/*
 * inc->i_saddr isn't used here because it is only set in the receive
 * path.
 */
void rds_inc_info_copy(struct rds_incoming *inc,
		       struct rds_info_iterator *iter,
		       __be32 saddr, __be32 daddr, int flip)
{
	struct rds_info_message minfo;

	minfo.seq = be64_to_cpu(inc->i_hdr.h_sequence);
	minfo.len = be32_to_cpu(inc->i_hdr.h_len);
	minfo.tos = inc->i_conn->c_tos;

	if (flip) {
		minfo.laddr = daddr;
		minfo.faddr = saddr;
		minfo.lport = inc->i_hdr.h_dport;
		minfo.fport = inc->i_hdr.h_sport;
	} else {
		minfo.laddr = saddr;
		minfo.faddr = daddr;
		minfo.lport = inc->i_hdr.h_sport;
		minfo.fport = inc->i_hdr.h_dport;
	}

	minfo.flags = 0;

	rds_info_copy(iter, &minfo, sizeof(minfo));
}

#if IS_ENABLED(CONFIG_IPV6)
void rds6_inc_info_copy(struct rds_incoming *inc,
			struct rds_info_iterator *iter,
			struct in6_addr *saddr, struct in6_addr *daddr,
			int flip)
{
	struct rds6_info_message minfo6;

	minfo6.seq = be64_to_cpu(inc->i_hdr.h_sequence);
	minfo6.len = be32_to_cpu(inc->i_hdr.h_len);
	minfo6.tos = inc->i_conn->c_tos;

	if (flip) {
		minfo6.laddr = *daddr;
		minfo6.faddr = *saddr;
		minfo6.lport = inc->i_hdr.h_dport;
		minfo6.fport = inc->i_hdr.h_sport;
	} else {
		minfo6.laddr = *saddr;
		minfo6.faddr = *daddr;
		minfo6.lport = inc->i_hdr.h_sport;
		minfo6.fport = inc->i_hdr.h_dport;
	}

	minfo6.flags = 0;

	rds_info_copy(iter, &minfo6, sizeof(minfo6));
}
#endif
