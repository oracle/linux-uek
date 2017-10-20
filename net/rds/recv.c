/*
 * Copyright (c) 2006, 2017 Oracle and/or its affiliates. All rights reserved.
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
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/time.h>
#include <linux/rds.h>

#include "rds.h"
#include "tcp.h"

/* forward prototypes */
static void
rds_recv_drop(struct rds_connection *conn, struct in6_addr *saddr,
	      struct in6_addr *daddr,
	      struct rds_incoming *inc, gfp_t gfp);

static void
rds_recv_route(struct rds_connection *conn, struct rds_incoming *inc,
	       gfp_t gfp);

static void
rds_recv_forward(struct rds_conn_path *cp, struct rds_incoming *inc,
		 gfp_t gfp);

static void
rds_recv_local(struct rds_conn_path *cp, struct in6_addr *saddr,
	       struct in6_addr *daddr,
	       struct rds_incoming *inc, gfp_t gfp, struct rds_sock *rs);

static int
rds_recv_ok(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	/* don't do anything here, just continue along */
	return NF_ACCEPT;
}

void rds_inc_init(struct rds_incoming *inc, struct rds_connection *conn,
		  struct in6_addr *saddr)
{
	int i;

	atomic_set(&inc->i_refcount, 1);
	INIT_LIST_HEAD(&inc->i_item);
	inc->i_conn = conn;
	inc->i_saddr = *saddr;
	inc->i_rdma_cookie = 0;
	inc->i_oconn = NULL;
	inc->i_skb   = NULL;
	inc->i_rx_tstamp.tv_sec = 0;
	inc->i_rx_tstamp.tv_usec = 0;

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
	inc->i_rdma_cookie = 0;
	inc->i_oconn = NULL;
	inc->i_skb   = NULL;
	inc->i_rx_tstamp.tv_sec = 0;
	inc->i_rx_tstamp.tv_usec = 0;

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

		/* free up the skb if any were created */
		if (NULL != inc->i_skb) {
			/* wipe out any fragments so they don't get released */
			skb_shinfo(inc->i_skb)->nr_frags = 0;

			/* and free the whole skb */
			kfree_skb(inc->i_skb);
			inc->i_skb = NULL;
		}

		inc->i_conn->c_trans->inc_free(inc);
	}
}
EXPORT_SYMBOL_GPL(rds_inc_put);

static void rds_recv_rcvbuf_delta(struct rds_sock *rs, struct sock *sk,
				  struct rds_cong_map *map,
				  int delta, __be16 port)
{
	int now_congested;

	if (delta == 0)
		return;

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
		rds_cong_queue_updates(map);
	}
	/* was -> aren't congested */
	/* Require more free space before reporting uncongested to prevent
	   bouncing cong/uncong state too often */
	else if (rs->rs_congested && (rs->rs_rcv_bytes < (rds_sk_rcvbuf(rs)/2))) {
		rs->rs_congested = 0;
		rds_cong_clear_bit(map, port);
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
			inc->i_rdma_cookie = rds_rdma_make_cookie(
					be32_to_cpu(buffer.rdma_dest.h_rdma_rkey),
					be32_to_cpu(buffer.rdma_dest.h_rdma_offset));

			break;
		}
	}
}

static void rds_conn_peer_gen_update(struct rds_connection *conn,
				     u32 peer_gen_num)
{
	int i;
	struct rds_message *rm, *tmp;
	unsigned long flags;
	int flushed;

	WARN_ON(conn->c_trans->t_type != RDS_TRANS_TCP);
	if (peer_gen_num != 0) {
		if (conn->c_peer_gen_num != 0 &&
		    peer_gen_num != conn->c_peer_gen_num) {
			for (i = 0; i < RDS_MPATH_WORKERS; i++) {
				struct rds_conn_path *cp;

				cp = &conn->c_path[i];
				spin_lock_irqsave(&cp->cp_lock, flags);
				cp->cp_next_tx_seq = 1;
				cp->cp_next_rx_seq = 0;
				flushed = 0;
				list_for_each_entry_safe(rm, tmp,
							 &cp->cp_retrans,
							 m_conn_item) {
					set_bit(RDS_MSG_FLUSH, &rm->m_flags);
					flushed++;
				}
				spin_unlock_irqrestore(&cp->cp_lock, flags);
				pr_info("%s:%d flushed %d\n",
					__FILE__, __LINE__, flushed);
			}
		}
		conn->c_peer_gen_num = peer_gen_num;
		pr_info("peer gen num %x\n", peer_gen_num);
	}
}

static void rds_recv_hs_exthdrs(struct rds_header *hdr,
				struct rds_connection *conn)
{
	unsigned int pos = 0, type, len;
	union {
		struct rds_ext_header_version version;
		u16 rds_npaths;
		u32 rds_gen_num;
	} buffer;
	u32 new_peer_gen_num = 0;

	while (1) {
		len = sizeof(buffer);
		type = rds_message_next_extension(hdr, &pos, &buffer, &len);
		if (type == RDS_EXTHDR_NONE)
			break;
		/* Process extension header here */
		switch (type) {
		case RDS_EXTHDR_NPATHS:
			conn->c_npaths = min_t(int, RDS_MPATH_WORKERS,
					       be16_to_cpu(buffer.rds_npaths));
			break;
		case RDS_EXTHDR_GEN_NUM:
			new_peer_gen_num = be32_to_cpu(buffer.rds_gen_num);
			break;
		default:
			pr_warn_ratelimited("ignoring unknown exthdr type "
					     "0x%x\n", type);
		}
	}
	/* if RDS_EXTHDR_NPATHS was not found, default to a single-path */
	conn->c_npaths = max_t(int, conn->c_npaths, 1);
	conn->c_ping_triggered = 0;
	rds_conn_peer_gen_update(conn, new_peer_gen_num);
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
	struct sk_buff *skb;
	struct rds_sock *rs;
	struct sock *sk;
	struct rds_nf_hdr *dst, *org;
	int    ret;
	struct rds_conn_path *cp;

	rdsdebug(KERN_ALERT "incoming:  conn %p, inc %p, %pI6c : %d -> %pI6c : %d\n",
		 conn, inc, saddr, inc->i_hdr.h_sport, daddr,
		 inc->i_hdr.h_dport);

	/* initialize some globals */
	rs = NULL;
	sk = NULL;

	/* save off the original connection against which the request arrived */
	inc->i_oconn = conn;
	inc->i_skb   = NULL;
	if (conn->c_trans->t_mp_capable)
		cp = inc->i_conn_path;
	else
		cp = &conn->c_path[0];

	/* lets find a socket to which this request belongs */
	rs = rds_find_bound(daddr, inc->i_hdr.h_dport, conn->c_dev_if);

	/* pass it on locally if there is no socket bound, or if netfilter is
	 * disabled for this socket */
	if (NULL == rs || !rs->rs_netfilter_enabled) {
		rds_recv_local(cp, saddr, daddr, inc, gfp, rs);

		/* drop the reference if we had taken one */
		if (NULL != rs)
			rds_sock_put(rs);

		return;
	}

	/* otherwise pull out the socket */
	sk = rds_rs_to_sk(rs);

	/* create an skb with some additional space to store our rds_nf_hdr info */
	skb = alloc_skb(sizeof(struct rds_nf_hdr) * 2, gfp);
	if (NULL == skb) {
		/* if we have allocation problems, then we just need to depart */
		rds_rtd(RDS_RTD_ERR,
			"failure to allocate space for inc %p, %pI6c -> %pI6c tos %d\n",
			inc, saddr, daddr, conn->c_tos);
		rds_recv_local(cp, saddr, daddr, inc, gfp, rs);
		/* drop the reference if we had taken one */
		if (NULL != rs)
			rds_sock_put(rs);
		return;
	}

	/* once we've allocated an skb, also store it in our structures */
	inc->i_skb = skb;

	/* now pull out the rds headers */
	dst = rds_nf_hdr_dst(skb);
	org = rds_nf_hdr_org(skb);

	/* now update our rds_nf_hdr for tracking locations of the request */
	dst->saddr = *saddr;
	dst->daddr = *daddr;
	dst->sport = inc->i_hdr.h_sport;
	dst->dport = inc->i_hdr.h_dport;
	dst->flags = 0;

	/* assign the appropriate protocol if any */
	if (NULL != sk) {
		dst->protocol = sk->sk_protocol;
		dst->sk = sk;
	} else {
		dst->protocol = 0;
		dst->sk = NULL;
	}

	/* cleanup any references taken */
	if (NULL != rs)
		rds_sock_put(rs);
	rs = NULL;

	/* the original info is just a copy */
	memcpy(org, dst, sizeof(struct rds_nf_hdr));

	/* convert our local data structures in the message to a generalized skb form */
	if (conn->c_trans->inc_to_skb(inc, skb)) {
		rdsdebug("handing off to PRE_ROUTING hook\n");
		/* call down through the hook layers */
		ret = NF_HOOK(PF_RDS_HOOK, NF_RDS_PRE_ROUTING,
			      rds_conn_net(conn),
			      sk, skb, NULL, NULL, rds_recv_ok);
	}
	/* if we had a failure to convert, then just assuming to continue as local */
	else {
		rds_rtd(RDS_RTD_RCV_EXT,
			"failed to create skb form, conn %p, inc %p, %pI6c -> %pI6c tos %d\n",
			conn, inc, saddr, daddr, conn->c_tos);
		ret = 1;
	}

	/* pull back out the rds headers */
	dst = rds_nf_hdr_dst(skb);
	org = rds_nf_hdr_org(skb);

	/* now depending upon we got back we can perform appropriate activities */
	if (dst->flags & RDS_NF_HDR_FLAG_DONE) {
		rds_recv_drop(conn, saddr, daddr, inc, gfp);
	}
	/* this is the normal good processed state */
	else if (ret >= 0) {
		/* check the original header and if changed do the needful */
		if (ipv6_addr_equal(&dst->saddr, &org->saddr) &&
		    ipv6_addr_equal(&dst->daddr, &org->daddr) &&
		    conn->c_trans->skb_local(skb)) {
			rds_recv_local(cp, saddr, daddr, inc, gfp, NULL);
		}
		/* the send both case does both a local recv and a reroute */
		else if (dst->flags & RDS_NF_HDR_FLAG_BOTH) {
			/* we must be sure to take an extra reference on the inc
			 * to be sure it doesn't accidentally get freed in between */
			rds_inc_addref(inc);

			/* send it up the stream locally */
			rds_recv_local(cp, saddr, daddr, inc, gfp, NULL);

			/* and also reroute the request */
			rds_recv_route(conn, inc, gfp);

			/* since we are done with processing we can drop this additional reference */
			rds_inc_put(inc);

		}
		/* anything else is a change in possible destination so pass to route */
		else
			rds_recv_route(conn, inc, gfp);
	}
	/* we don't really expect an error state from this call that isn't the done above */
	else {
		/* we don't really know how to handle this yet - just ignore for now */
		printk(KERN_ERR "unacceptible state for skb ret %d, conn %p, inc %p, %pI6c -> %pI6c\n",
		       ret, conn, inc, saddr, daddr);
	}
}
EXPORT_SYMBOL_GPL(rds_recv_incoming);

static void
rds_recv_drop(struct rds_connection *conn, struct in6_addr *saddr,
	      struct in6_addr *daddr,
	      struct rds_incoming *inc, gfp_t gfp)
{
	/* drop the existing incoming message */
	rdsdebug("dropping request on conn %p, inc %p, %pI6c -> %pI6c",
		 conn, inc, saddr, daddr);
}

static void
rds_recv_route(struct rds_connection *conn, struct rds_incoming *inc,
	       gfp_t gfp)
{
	struct rds_connection *nconn;
	struct rds_nf_hdr  *dst, *org;

	/* pull out the rds header */
	dst = rds_nf_hdr_dst(inc->i_skb);
	org = rds_nf_hdr_org(inc->i_skb);

	/* special case where we are swapping the message back on the same connection */
	if (ipv6_addr_equal(&dst->saddr, &org->daddr) &&
	    ipv6_addr_equal(&dst->daddr, &org->saddr)) {
		nconn = conn;
	} else {
		/* reroute to a new conn structure, possibly the same one */
		nconn = rds_conn_find(rds_conn_net(conn),
				      &dst->saddr, &dst->daddr, conn->c_trans,
				      conn->c_tos, conn->c_dev_if);
	}

	/* cannot find a matching connection so drop the request */
	if (NULL == nconn) {
		printk(KERN_ALERT "cannot find matching conn for inc %p, %pI6c -> %pI6c\n",
		       inc, &dst->saddr, &dst->daddr);

		rdsdebug("cannot find matching conn for inc %p, %pI6c -> %pI6c",
			 inc, &dst->saddr, &dst->daddr);
		rds_recv_drop(conn, &dst->saddr, &dst->daddr, inc, gfp);
	}
	/* this is a request for our local node, but potentially a different source
	 * either way we process it locally */
	else if (conn->c_trans->skb_local(inc->i_skb)) {
		WARN_ON(nconn->c_trans->t_mp_capable);
		rds_recv_local(&nconn->c_path[0],
			       &dst->saddr, &dst->daddr, inc, gfp, NULL);
	}
	/* looks like this request is going out to another node */
	else {
		WARN_ON(nconn->c_trans->t_mp_capable);
		rds_recv_forward(&nconn->c_path[0], inc, gfp);
	}
}

static void
rds_recv_forward(struct rds_conn_path *cp, struct rds_incoming *inc,
		 gfp_t gfp)
{
	int len, ret;
	struct rds_nf_hdr *dst, *org;
	struct rds_sock *rs;
	struct sock *sk = NULL;
	struct rds_connection *conn = cp->cp_conn;

	/* initialize some bits */
	rs = NULL;

	/* pull out the destination and original rds headers */
	dst = rds_nf_hdr_dst(inc->i_skb);
	org = rds_nf_hdr_org(inc->i_skb);

	/* find the proper output socket - it should be the local one on which we originated */
	rs = rds_find_bound(&dst->saddr, dst->sport, conn->c_dev_if);
	if (!rs) {
		rds_rtd(RDS_RTD_RCV,
			"failed to find output rds_socket dst %pI6c : %u, inc %p, conn %p tos %d\n",
			&dst->daddr, dst->dport, inc, conn,
			conn->c_tos);
		rds_stats_inc(s_recv_drop_no_sock);
		goto out;
	}

	/* pull out the actual message len */
	len = be32_to_cpu(inc->i_hdr.h_len);

	/* now lets see if we can send it all */
	ret = rds_send_internal(conn, rs, inc->i_skb, gfp);
	if (len != ret) {
		rds_rtd(RDS_RTD_RCV,
			"failed to send rds_data dst %pI6c : %u, inc %p, conn %p tos %d, len %d != ret %d\n",
			&dst->daddr, dst->dport, inc, conn, conn->c_tos,
			len, ret);
		goto out;
	}

	if (NULL != rs)
		rds_sock_put(rs);

	/* all good so we are done */
	return;

out:
	/* cleanup any handles */
	if (NULL != rs) {
		sk = rds_rs_to_sk(rs);
		rds_sock_put(rs);
	}

	/* on error lets take a shot at hook cleanup */
	NF_HOOK(PF_RDS_HOOK, NF_RDS_FORWARD_ERROR,
		rds_conn_net(conn),
		sk, inc->i_skb, NULL, NULL, rds_recv_ok);

	/* then hand the request off to normal local processing on the old connection */
	rds_recv_local(&inc->i_oconn->c_path[0], &org->saddr, &org->daddr,
		       inc, gfp, NULL);
}

static void
rds_recv_local(struct rds_conn_path *cp, struct in6_addr *saddr,
	       struct in6_addr *daddr, struct rds_incoming *inc, gfp_t gfp,
	       struct rds_sock *rs)
{
	struct sock *sk;
	unsigned long flags;
	u64 inc_hdr_h_sequence = 0;
	bool rs_local = (!rs);
	struct rds_connection *conn = cp->cp_conn;

	inc->i_conn = conn;
	inc->i_rx_jiffies = jiffies;

	rdsdebug("conn %p next %llu inc %p seq %llu len %u sport %u dport %u "
		 "flags 0x%x rx_jiffies %lu\n", conn,
		 (unsigned long long)cp->cp_next_rx_seq,
		 inc,
		 (unsigned long long)be64_to_cpu(inc->i_hdr.h_sequence),
		 be32_to_cpu(inc->i_hdr.h_len),
		 be16_to_cpu(inc->i_hdr.h_sport),
		 be16_to_cpu(inc->i_hdr.h_dport),
		 inc->i_hdr.h_flags,
		 inc->i_rx_jiffies);

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

	if (inc_hdr_h_sequence != cp->cp_next_rx_seq) {
		rds_rtd(RDS_RTD_RCV,
			"conn %p <%pI6c,%pI6c,%d> expect seq# %llu, recved seq# %llu, retrans bit %d\n",
			conn, &conn->c_laddr, &conn->c_faddr,
			conn->c_tos, cp->cp_next_rx_seq, inc_hdr_h_sequence,
			inc->i_hdr.h_flags & RDS_FLAG_RETRANSMITTED);
	}

	if (inc_hdr_h_sequence < cp->cp_next_rx_seq
	 && (inc->i_hdr.h_flags & RDS_FLAG_RETRANSMITTED)) {
		rds_stats_inc(s_recv_drop_old_seq);
		goto out;
	}
	cp->cp_next_rx_seq = inc_hdr_h_sequence + 1;

	if (rds_sysctl_ping_enable && inc->i_hdr.h_dport == 0) {
		if (inc->i_hdr.h_sport == 0) {
			rdsdebug("ignore ping with 0 sport from %pI6c\n",
				 &saddr);
			goto out;
		}
		if (inc->i_hdr.h_flags & RDS_FLAG_HB_PING) {
			rds_send_hb(conn, 1);
		} else if (inc->i_hdr.h_flags & RDS_FLAG_HB_PONG) {
			cp->cp_hb_start = 0;
		} else {
			rds_stats_inc(s_recv_ping);
			rds_send_pong(cp, inc->i_hdr.h_sport);
			/* if this is a handshake ping,
			 * start multipath if necessary
			 */
			if (RDS_HS_PROBE(be16_to_cpu(inc->i_hdr.h_sport),
					 be16_to_cpu(inc->i_hdr.h_dport))) {
				rds_recv_hs_exthdrs(&inc->i_hdr, cp->cp_conn);
				rds_start_mprds(cp->cp_conn);
			}
		}
		goto out;
	}
	if (be16_to_cpu(inc->i_hdr.h_dport) ==  RDS_FLAG_PROBE_PORT &&
	    inc->i_hdr.h_sport == 0) {
		rds_recv_hs_exthdrs(&inc->i_hdr, cp->cp_conn);
		/* if this is a handshake pong, start multipath if necessary */
		rds_start_mprds(cp->cp_conn);
		wake_up(&cp->cp_conn->c_hs_waitq);
		goto out;
	}

	if (!rs)
		rs = rds_find_bound(daddr, inc->i_hdr.h_dport, conn->c_dev_if);
	if (!rs) {
		rds_stats_inc(s_recv_drop_no_sock);
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
			rds_recv_rcvbuf_delta(rs, sk, inc->i_conn->c_lcong,
				      be32_to_cpu(inc->i_hdr.h_len),
				      inc->i_hdr.h_dport);
			if (sock_flag(sk, SOCK_RCVTSTAMP))
				do_gettimeofday(&inc->i_rx_tstamp);
			rds_inc_addref(inc);
			list_add_tail(&inc->i_item, &rs->rs_recv_queue);
			inc->i_rx_lat_trace[RDS_MSG_RX_END] = local_clock();
			__rds_wake_sk_sleep(sk);
		}
	} else {
		rds_stats_inc(s_recv_drop_dead_sock);
	}
	write_unlock_irqrestore(&rs->rs_recv_lock, flags);

out:
	if (rs_local && rs)
		rds_sock_put(rs);
}

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
			rds_recv_rcvbuf_delta(rs, sk, inc->i_conn->c_lcong,
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
	uint64_t notify = rs->rs_cong_notify;
	unsigned long flags;
	int err;

	err = put_cmsg(msghdr, SOL_RDS, RDS_CMSG_CONG_UPDATE,
			sizeof(notify), &notify);
	if (err)
		return err;

	spin_lock_irqsave(&rs->rs_lock, flags);
	rs->rs_cong_notify &= ~notify;
	spin_unlock_irqrestore(&rs->rs_lock, flags);

	return 0;
}

/*
 * Receive any control messages.
 */
static int rds_cmsg_recv(struct rds_incoming *inc, struct msghdr *msg,
			 struct rds_sock *rs)
{
	int ret = 0;

	if (inc->i_rdma_cookie) {
		ret = put_cmsg(msg, SOL_RDS, RDS_CMSG_RDMA_DEST,
				sizeof(inc->i_rdma_cookie), &inc->i_rdma_cookie);
		if (ret)
			goto out;
	}

	if ((inc->i_rx_tstamp.tv_sec != 0) &&
	    sock_flag(rds_rs_to_sk(rs), SOCK_RCVTSTAMP)) {
		ret = put_cmsg(msg, SOL_SOCKET, SCM_TIMESTAMP,
			       sizeof(struct timeval),
			       &inc->i_rx_tstamp);
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

		if (rs->rs_cong_notify) {
			ret = rds_notify_cong(rs, msg);
			break;
		}

		if (!rds_next_incoming(rs, &inc)) {
			if (nonblock) {
				ret = -EAGAIN;
				break;
			}

			timeo = wait_event_interruptible_timeout(*sk_sleep(sk),
						(!list_empty(&rs->rs_notify_queue)
						|| rs->rs_cong_notify
						|| rds_next_incoming(rs, &inc)),
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
			goto out;
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
		rds_recv_rcvbuf_delta(rs, sk, inc->i_conn->c_lcong,
				      -be32_to_cpu(inc->i_hdr.h_len),
				      inc->i_hdr.h_dport);
		list_del_init(&inc->i_item);
		rds_inc_put(inc);
	}
	write_unlock_irqrestore(&rs->rs_recv_lock, flags);
}

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

	rds_info_copy(iter, &minfo, sizeof(minfo));
}

int rds_skb_local(struct sk_buff *skb)
{
	struct rds_nf_hdr *dst, *org;

	/* pull out the headers */
	dst = rds_nf_hdr_dst(skb);
	org = rds_nf_hdr_org(skb);

	/* Just check to see that the destination is still the same.
	 * Otherwise, the sport/dport have likely swapped so consider
	 * it a different node.
	 */
	if (ipv6_addr_equal(&dst->daddr, &org->daddr) &&
	    dst->dport == org->dport)
		return 1;
	else
		return 0;
}
EXPORT_SYMBOL(rds_skb_local);
