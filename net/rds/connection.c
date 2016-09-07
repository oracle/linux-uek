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
#include <linux/list.h>
#include <net/inet_hashtables.h>

#include "rds.h"
#include "loop.h"
#include "tcp.h"

#define RDS_CONNECTION_HASH_BITS 12
#define RDS_CONNECTION_HASH_ENTRIES (1 << RDS_CONNECTION_HASH_BITS)
#define RDS_CONNECTION_HASH_MASK (RDS_CONNECTION_HASH_ENTRIES - 1)

/* converting this to RCU is a chore for another day.. */
static DEFINE_SPINLOCK(rds_conn_lock);
static unsigned long rds_conn_count;
static struct hlist_head rds_conn_hash[RDS_CONNECTION_HASH_ENTRIES];
static struct kmem_cache *rds_conn_slab;

static struct hlist_head *rds_conn_bucket(__be32 laddr, __be32 faddr)
{
	static u32 rds_hash_secret __read_mostly;

	unsigned long hash;

	net_get_random_once(&rds_hash_secret, sizeof(rds_hash_secret));

	/* Pass NULL, don't need struct net for hash */
	hash = __inet_ehashfn(be32_to_cpu(laddr), 0,
			be32_to_cpu(faddr), 0,
			rds_hash_secret);
	return &rds_conn_hash[hash & RDS_CONNECTION_HASH_MASK];
}

#define rds_conn_info_set(var, test, suffix) do {		\
	if (test)						\
		var |= RDS_INFO_CONNECTION_FLAG_##suffix;	\
} while (0)

/* rcu read lock must be held or the connection spinlock */
static struct rds_connection *rds_conn_lookup(struct net *net,
					      struct hlist_head *head,
					      __be32 laddr, __be32 faddr,
					      struct rds_transport *trans,
					      u8 tos)
{
	struct rds_connection *conn, *ret = NULL;

	hlist_for_each_entry_rcu(conn, head, c_hash_node) {
		if (conn->c_faddr == faddr && conn->c_laddr == laddr &&
				conn->c_tos == tos &&
				conn->c_trans == trans &&
		    net == rds_conn_net(conn)) {
			ret = conn;
			break;
		}
	}
	rdsdebug("returning conn %p for %pI4 -> %pI4\n", ret,
		 &laddr, &faddr);
	return ret;
}

void rds_conn_laddr_list(__be32 laddr, struct list_head *laddr_conns)
{
	struct rds_connection *conn;
	struct hlist_head *head;
	int i;

	rcu_read_lock();

	for (i = 0, head = rds_conn_hash; i < ARRAY_SIZE(rds_conn_hash);
	     i++, head++) {
		hlist_for_each_entry_rcu(conn, head, c_hash_node)
			if (conn->c_laddr == laddr)
				list_add(&conn->c_laddr_node, laddr_conns);
	}

	rcu_read_unlock();
}

/*
 * This is called by transports as they're bringing down a connection.
 * It clears partial message state so that the transport can start sending
 * and receiving over this connection again in the future.  It is up to
 * the transport to have serialized this call with its send and recv.
 */
void rds_conn_reset(struct rds_connection *conn)
{
	rdsdebug("connection %pI4 to %pI4 reset\n",
	  &conn->c_laddr, &conn->c_faddr);

	rds_stats_inc(s_conn_reset);
	rds_send_reset(conn);
	conn->c_flags = 0;

	/* Do not clear next_rx_seq here, else we cannot distinguish
	 * retransmitted packets from new packets, and will hand all
	 * of them to the application. That is not consistent with the
	 * reliability guarantees of RDS. */
}

/*
 * There is only every one 'conn' for a given pair of addresses in the
 * system at a time.  They contain messages to be retransmitted and so
 * span the lifetime of the actual underlying transport connections.
 *
 * For now they are not garbage collected once they're created.  They
 * are torn down as the module is removed, if ever.
 */
static struct rds_connection *__rds_conn_create(struct net *net,
						__be32 laddr, __be32 faddr,
				       struct rds_transport *trans, gfp_t gfp,
				       u8 tos,
				       int is_outgoing)
{
	struct rds_connection *conn, *parent = NULL;
	struct hlist_head *head = rds_conn_bucket(laddr, faddr);
	struct rds_transport *loop_trans;
	unsigned long flags;
	int ret;

	rcu_read_lock();
	conn = rds_conn_lookup(net, head, laddr, faddr, trans, tos);
	if (conn
	 && conn->c_loopback
	 && conn->c_trans != &rds_loop_transport
	 && laddr == faddr
	 && !is_outgoing) {
		/* This is a looped back IB connection, and we're
		 * called by the code handling the incoming connect.
		 * We need a second connection object into which we
		 * can stick the other QP. */
		parent = conn;
		conn = parent->c_passive;
	}
	rcu_read_unlock();
	if (conn)
		goto out;

	conn = kmem_cache_alloc(rds_conn_slab, gfp);
	if (!conn) {
		conn = ERR_PTR(-ENOMEM);
		goto out;
	}

	memset(conn, 0, sizeof(*conn));

	INIT_HLIST_NODE(&conn->c_hash_node);
	conn->c_laddr = laddr;
	conn->c_faddr = faddr;
	spin_lock_init(&conn->c_lock);
	conn->c_next_tx_seq = 1;
	rds_conn_net_set(conn, net);

	init_waitqueue_head(&conn->c_waitq);
	INIT_LIST_HEAD(&conn->c_send_queue);
	INIT_LIST_HEAD(&conn->c_retrans);

	conn->c_tos = tos;

	ret = rds_cong_get_maps(conn);
	if (ret) {
		kmem_cache_free(rds_conn_slab, conn);
		conn = ERR_PTR(ret);
		goto out;
	}

	/*
	 * This is where a connection becomes loopback.  If *any* RDS sockets
	 * can bind to the destination address then we'd rather the messages
	 * flow through loopback rather than either transport.
	 */
	loop_trans = rds_trans_get_preferred(net, faddr);
	if (loop_trans) {
		rds_trans_put(loop_trans);
		conn->c_loopback = 1;
		if (is_outgoing && trans->t_prefer_loopback) {
			/* "outgoing" connection - and the transport
			 * says it wants the connection handled by the
			 * loopback transport. This is what TCP does.
			 */
			trans = &rds_loop_transport;
		}
	}

	conn->c_trans = trans;
	conn->c_reconnect_retry = rds_sysctl_reconnect_retry_ms;
	conn->c_reconnect_retry_count = 0;

	if (conn->c_loopback)
		conn->c_wq = rds_local_wq;
	else
		conn->c_wq = rds_wq;

	ret = trans->conn_alloc(conn, gfp);
	if (ret) {
		kmem_cache_free(rds_conn_slab, conn);
		conn = ERR_PTR(ret);
		goto out;
	}

	atomic_set(&conn->c_state, RDS_CONN_DOWN);
	conn->c_send_gen = 0;
	conn->c_outgoing = (is_outgoing ? 1 : 0);
	conn->c_reconnect_jiffies = 0;
	conn->c_reconnect_start = get_seconds();
	conn->c_reconnect_warn = 1;
	conn->c_reconnect_drops = 0;
	conn->c_reconnect_err = 0;
	conn->c_proposed_version = RDS_PROTOCOL_VERSION;
	conn->c_route_resolved = 1;

	INIT_DELAYED_WORK(&conn->c_send_w, rds_send_worker);
	INIT_DELAYED_WORK(&conn->c_recv_w, rds_recv_worker);
	INIT_DELAYED_WORK(&conn->c_conn_w, rds_connect_worker);
	INIT_DELAYED_WORK(&conn->c_hb_w, rds_hb_worker);
	INIT_DELAYED_WORK(&conn->c_reconn_w, rds_reconnect_timeout);
	INIT_DELAYED_WORK(&conn->c_reject_w, rds_reject_worker);
	INIT_WORK(&conn->c_down_w, rds_shutdown_worker);
	mutex_init(&conn->c_cm_lock);
	conn->c_flags = 0;

	rdsdebug("allocated conn %p for %pI4 -> %pI4 over %s %s\n",
	  conn, &laddr, &faddr,
	  trans->t_name ? trans->t_name : "[unknown]",
	  is_outgoing ? "(outgoing)" : "");

	/*
	 * Since we ran without holding the conn lock, someone could
	 * have created the same conn (either normal or passive) in the
	 * interim. We check while holding the lock. If we won, we complete
	 * init and return our conn. If we lost, we rollback and return the
	 * other one.
	 */
	spin_lock_irqsave(&rds_conn_lock, flags);
	if (parent) {
		/* Creating passive conn */
		if (parent->c_passive) {
			trans->conn_free(conn->c_transport_data);
			kmem_cache_free(rds_conn_slab, conn);
			conn = parent->c_passive;
		} else {
			parent->c_passive = conn;
			rds_cong_add_conn(conn);
			rds_conn_count++;
		}
	} else {
		/* Creating normal conn */
		struct rds_connection *found;

		found = rds_conn_lookup(net, head, laddr, faddr, trans, tos);
		if (found) {
			trans->conn_free(conn->c_transport_data);
			kmem_cache_free(rds_conn_slab, conn);
			conn = found;
		} else {
			hlist_add_head_rcu(&conn->c_hash_node, head);
			rds_cong_add_conn(conn);
			rds_conn_count++;
		}
	}
	spin_unlock_irqrestore(&rds_conn_lock, flags);

out:
	return conn;
}

struct rds_connection *rds_conn_create(struct net *net,
				       __be32 laddr, __be32 faddr,
					struct rds_transport *trans,
					u8 tos, gfp_t gfp)
{
	return __rds_conn_create(net, laddr, faddr, trans, gfp, tos, 0);
}
EXPORT_SYMBOL_GPL(rds_conn_create);

struct rds_connection *rds_conn_create_outgoing(struct net *net,
						__be32 laddr, __be32 faddr,
					struct rds_transport *trans,
					u8 tos, gfp_t gfp)
{
	return __rds_conn_create(net, laddr, faddr, trans, gfp, tos, 1);
}
EXPORT_SYMBOL_GPL(rds_conn_create_outgoing);

struct rds_connection *rds_conn_find(struct net *net, __be32 laddr,
				     __be32 faddr, struct rds_transport *trans,
				     u8 tos)
{
	struct rds_connection *conn;
	struct hlist_head *head = rds_conn_bucket(laddr, faddr);

	rcu_read_lock();
	conn = rds_conn_lookup(net, head, laddr, faddr, trans, tos);
	rcu_read_unlock();

	return conn;
}
EXPORT_SYMBOL_GPL(rds_conn_find);

void rds_conn_shutdown(struct rds_connection *conn, int restart)
{
	/* shut it down unless it's down already */
	if (!rds_conn_transition(conn, RDS_CONN_DOWN, RDS_CONN_DOWN)) {
		rds_rtd(RDS_RTD_CM_EXT,
			"RDS/IB: shutdown init <%pI4,%pI4,%d>, cn %p, cn->c_p %p\n",
			&conn->c_laddr, &conn->c_faddr,
			conn->c_tos, conn, conn->c_passive);
		/*
		 * Quiesce the connection mgmt handlers before we start tearing
		 * things down. We don't hold the mutex for the entire
		 * duration of the shutdown operation, else we may be
		 * deadlocking with the CM handler. Instead, the CM event
		 * handler is supposed to check for state DISCONNECTING
		 */
		mutex_lock(&conn->c_cm_lock);
		if (!rds_conn_transition(conn, RDS_CONN_UP, RDS_CONN_DISCONNECTING)
		 && !rds_conn_transition(conn, RDS_CONN_ERROR, RDS_CONN_DISCONNECTING)) {
			pr_warn("RDS: shutdown called in state %d\n",
				atomic_read(&conn->c_state));
			rds_conn_drop(conn, DR_INV_CONN_STATE);
			mutex_unlock(&conn->c_cm_lock);
			return;
		}
		mutex_unlock(&conn->c_cm_lock);

		wait_event(conn->c_waitq,
			   !test_bit(RDS_IN_XMIT, &conn->c_flags));
		wait_event(conn->c_waitq,
			   !test_bit(RDS_RECV_REFILL, &conn->c_flags));

		conn->c_trans->conn_shutdown(conn);
		rds_conn_reset(conn);

		if (!rds_conn_transition(conn, RDS_CONN_DISCONNECTING, RDS_CONN_DOWN)) {
			/* This can happen - eg when we're in the middle of tearing
			 * down the connection, and someone unloads the rds module.
			 * Quite reproduceable with loopback connections.
			 * Mostly harmless.
			 */
			pr_warn("RDS: %s: failed to transition to state DOWN, current state is %d\n",
				__func__, atomic_read(&conn->c_state));
			rds_conn_drop(conn, DR_DOWN_TRANSITION_FAIL);
			return;
		}
	}

	/* Then reconnect if it's still live.
	 * The passive side of an IB loopback connection is never added
	 * to the conn hash, so we never trigger a reconnect on this
	 * conn - the reconnect is always triggered by the active peer. */
	cancel_delayed_work_sync(&conn->c_conn_w);
	rcu_read_lock();
	if (!hlist_unhashed(&conn->c_hash_node) && restart) {
		rcu_read_unlock();
		if (conn->c_trans->t_type != RDS_TRANS_TCP ||
		    conn->c_outgoing == 1) {
			rds_rtd(RDS_RTD_CM_EXT,
				"queueing reconnect request... "
				"<%pI4,%pI4,%d>\n",
				&conn->c_laddr,
				&conn->c_faddr,
				conn->c_tos);
			rds_queue_reconnect(conn);
		}
	} else {
		rcu_read_unlock();
	}
}

/*
 * Stop and free a connection.
 *
 * This can only be used in very limited circumstances.  It assumes that once
 * the conn has been shutdown that no one else is referencing the connection.
 * We can only ensure this in the rmmod path in the current code.
 */
void rds_conn_destroy(struct rds_connection *conn, int shutdown)
{
	struct rds_message *rm, *rtmp;
	unsigned long flags;
	LIST_HEAD(to_be_dropped);

	rds_rtd(RDS_RTD_CM, "freeing conn %p <%pI4,%pI4,%d>\n",
		conn, &conn->c_laddr, &conn->c_faddr,
		conn->c_tos);

	set_bit(RDS_DESTROY_PENDING, &conn->c_flags);

	/* Ensure conn will not be scheduled for reconnect */
	spin_lock_irq(&rds_conn_lock);
	hlist_del_init_rcu(&conn->c_hash_node);
	spin_unlock_irq(&rds_conn_lock);
	synchronize_rcu();

	/* shut the connection down */
	rds_conn_drop(conn, DR_CONN_DESTROY);
	flush_work(&conn->c_down_w);

	/* now that conn down worker is flushed; there cannot be any
	 * more posting of reconn timeout work. But cancel any already
	 * posted reconn timeout worker as there is a race between rds
	 * module unload and a pending reconn delay work.
	 */
	cancel_delayed_work_sync(&conn->c_reconn_w);

	/* make sure lingering queued work won't try to ref the conn */
	cancel_delayed_work_sync(&conn->c_send_w);
	cancel_delayed_work_sync(&conn->c_recv_w);

	/* tear down queued messages */
	list_for_each_entry_safe(rm, rtmp,
				 &conn->c_send_queue,
				 m_conn_item) {
		if (shutdown) {
			list_del_init(&rm->m_conn_item);
			BUG_ON(!list_empty(&rm->m_sock_item));
			rds_message_put(rm);
		} else {
			list_move_tail(&rm->m_conn_item, &to_be_dropped);
		}
	}

	if (!list_empty(&to_be_dropped))
		rds_send_remove_from_sock(&to_be_dropped, RDS_RDMA_SEND_DROPPED);

	if (conn->c_xmit_rm)
		rds_message_put(conn->c_xmit_rm);

	conn->c_trans->conn_free(conn->c_transport_data);

	/*
	 * The congestion maps aren't freed up here.  They're
	 * freed by rds_cong_exit() after all the connections
	 * have been freed.
	 */
	rds_cong_remove_conn(conn);

	BUG_ON(!list_empty(&conn->c_retrans));
	kmem_cache_free(rds_conn_slab, conn);

	spin_lock_irqsave(&rds_conn_lock, flags);
	rds_conn_count--;
	spin_unlock_irqrestore(&rds_conn_lock, flags);
}
EXPORT_SYMBOL_GPL(rds_conn_destroy);

static void rds_conn_message_info(struct socket *sock, unsigned int len,
				  struct rds_info_iterator *iter,
				  struct rds_info_lengths *lens,
				  int want_send)
{
	struct hlist_head *head;
	struct list_head *list;
	struct rds_connection *conn;
	struct rds_message *rm;
	unsigned int total = 0;
	unsigned long flags;
	size_t i;

	len /= sizeof(struct rds_info_message);

	rcu_read_lock();

	for (i = 0, head = rds_conn_hash; i < ARRAY_SIZE(rds_conn_hash);
	     i++, head++) {
		hlist_for_each_entry_rcu(conn, head, c_hash_node) {
			if (want_send)
				list = &conn->c_send_queue;
			else
				list = &conn->c_retrans;

			spin_lock_irqsave(&conn->c_lock, flags);
			conn->c_rdsinfo_pending = 1;

			/* XXX too lazy to maintain counts.. */
			list_for_each_entry(rm, list, m_conn_item) {
				total++;
				if (total <= len)
					rds_inc_info_copy(&rm->m_inc, iter,
							  conn->c_laddr,
							  conn->c_faddr, 0);
			}

			conn->c_rdsinfo_pending = 0;
			spin_unlock_irqrestore(&conn->c_lock, flags);
		}
	}
	rcu_read_unlock();

	lens->nr = total;
	lens->each = sizeof(struct rds_info_message);
}

static void rds_conn_message_info_send(struct socket *sock, unsigned int len,
				       struct rds_info_iterator *iter,
				       struct rds_info_lengths *lens)
{
	rds_conn_message_info(sock, len, iter, lens, 1);
}

static void rds_conn_message_info_retrans(struct socket *sock,
					  unsigned int len,
					  struct rds_info_iterator *iter,
					  struct rds_info_lengths *lens)
{
	rds_conn_message_info(sock, len, iter, lens, 0);
}

void rds_for_each_conn_info(struct socket *sock, unsigned int len,
			  struct rds_info_iterator *iter,
			  struct rds_info_lengths *lens,
			  int (*visitor)(struct rds_connection *, void *),
			  size_t item_len)
{
	uint64_t buffer[(item_len + 7) / 8];
	struct hlist_head *head;
	struct rds_connection *conn;
	size_t i;

	rcu_read_lock();

	lens->nr = 0;
	lens->each = item_len;

	for (i = 0, head = rds_conn_hash; i < ARRAY_SIZE(rds_conn_hash);
	     i++, head++) {
		hlist_for_each_entry_rcu(conn, head, c_hash_node) {

			/* XXX no c_lock usage.. */
			if (!visitor(conn, buffer))
				continue;

			/* We copy as much as we can fit in the buffer,
			 * but we count all items so that the caller
			 * can resize the buffer. */
			if (len >= item_len) {
				rds_info_copy(iter, buffer, item_len);
				len -= item_len;
			}
			lens->nr++;
		}
	}
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(rds_for_each_conn_info);

static int rds_conn_info_visitor(struct rds_connection *conn,
				  void *buffer)
{
	struct rds_info_connection *cinfo = buffer;

	cinfo->next_tx_seq = conn->c_next_tx_seq;
	cinfo->next_rx_seq = conn->c_next_rx_seq;
	cinfo->laddr = conn->c_laddr;
	cinfo->faddr = conn->c_faddr;
	cinfo->tos = conn->c_tos;
	strncpy(cinfo->transport, conn->c_trans->t_name,
		sizeof(cinfo->transport));
	cinfo->flags = 0;

	rds_conn_info_set(cinfo->flags, test_bit(RDS_IN_XMIT, &conn->c_flags),
			  SENDING);
	/* XXX Future: return the state rather than these funky bits */
	rds_conn_info_set(cinfo->flags,
			  atomic_read(&conn->c_state) == RDS_CONN_CONNECTING,
			  CONNECTING);
	rds_conn_info_set(cinfo->flags,
			  atomic_read(&conn->c_state) == RDS_CONN_UP,
			  CONNECTED);
	rds_conn_info_set(cinfo->flags, conn->c_pending_flush,
			  ERROR);
	return 1;
}

static void rds_conn_info(struct socket *sock, unsigned int len,
			  struct rds_info_iterator *iter,
			  struct rds_info_lengths *lens)
{
	rds_for_each_conn_info(sock, len, iter, lens,
				rds_conn_info_visitor,
				sizeof(struct rds_info_connection));
}

int rds_conn_init(void)
{
	rds_conn_slab = kmem_cache_create("rds_connection",
					  sizeof(struct rds_connection),
					  0, 0, NULL);
	if (!rds_conn_slab)
		return -ENOMEM;

	rds_info_register_func(RDS_INFO_CONNECTIONS, rds_conn_info);
	rds_info_register_func(RDS_INFO_SEND_MESSAGES,
			       rds_conn_message_info_send);
	rds_info_register_func(RDS_INFO_RETRANS_MESSAGES,
			       rds_conn_message_info_retrans);

	return 0;
}

void rds_conn_exit(void)
{
	rds_loop_exit();

	WARN_ON(!hlist_empty(rds_conn_hash));

	kmem_cache_destroy(rds_conn_slab);

	rds_info_deregister_func(RDS_INFO_CONNECTIONS, rds_conn_info);
	rds_info_deregister_func(RDS_INFO_SEND_MESSAGES,
				 rds_conn_message_info_send);
	rds_info_deregister_func(RDS_INFO_RETRANS_MESSAGES,
				 rds_conn_message_info_retrans);
}

static char *conn_drop_reasons[] = {
	[DR_DEFAULT]			= "unknown reason (default_state)",
	[DR_USER_RESET]			= "user reset",
	[DR_INV_CONN_STATE]		= "invalid connection state",
	[DR_DOWN_TRANSITION_FAIL]	= "failure to move to DOWN state",
	[DR_CONN_DESTROY]		= "connection destroy",
	[DR_ZERO_LANE_DOWN]		= "zero lane went down",
	[DR_CONN_CONNECT_FAIL]		= "conn_connect failure",
	[DR_HB_TIMEOUT]			= "hb timeout",
	[DR_RECONNECT_TIMEOUT]		= "reconnect timeout",
	[DR_SOCK_CANCEL]		= "cancel operation on socket",
	[DR_IB_CONN_DROP_RACE]		= "race between ESTABLISHED event and drop",
	[DR_IB_NOT_CONNECTING_STATE]	= "conn is not in CONNECTING state",
	[DR_IB_QP_EVENT]		= "qp event",
	[DR_IB_BASE_CONN_DOWN]		= "base conn down",
	[DR_IB_REQ_WHILE_CONN_UP]	= "incoming REQ in CONN_UP state",
	[DR_IB_REQ_WHILE_CONNECTING]	= "incoming REQ in CONNECTING state",
	[DR_IB_PAS_SETUP_QP_FAIL]	= "passive setup_qp failure",
	[DR_IB_RDMA_ACCEPT_FAIL]	= "rdma_accept failure",
	[DR_IB_ACT_SETUP_QP_FAIL]	= "active setup_qp failure",
	[DR_IB_RDMA_CONNECT_FAIL]	= "rdma_connect failure",
	[DR_IB_SET_IB_PATH_FAIL]	= "rdma_set_ib_paths failure",
	[DR_IB_RESOLVE_ROUTE_FAIL]	= "resolve_route failure",
	[DR_IB_RDMA_CM_ID_MISMATCH]	= "detected rdma_cm_id mismatch",
	[DR_IB_ROUTE_ERR]		= "ROUTE_ERROR event",
	[DR_IB_ADDR_ERR]		= "ADDR_ERROR event",
	[DR_IB_CONNECT_ERR]		= "CONNECT_ERROR or UNREACHABLE or DEVICE_REMOVE event",
	[DR_IB_CONSUMER_DEFINED_REJ]	= "CONSUMER_DEFINED reject",
	[DR_IB_REJECTED_EVENT]		= "REJECTED event",
	[DR_IB_ADDR_CHANGE]		= "ADDR_CHANGE event",
	[DR_IB_DISCONNECTED_EVENT]	= "DISCONNECTED event",
	[DR_IB_TIMEWAIT_EXIT]		= "TIMEWAIT_EXIT event",
	[DR_IB_POST_RECV_FAIL]		= "post_recv failure",
	[DR_IB_SEND_ACK_FAIL]		= "send_ack failure",
	[DR_IB_HEADER_MISSING]		= "no header in incoming msg",
	[DR_IB_HEADER_CORRUPTED]	= "corrupted header in incoming msg",
	[DR_IB_FRAG_HEADER_MISMATCH]	= "fragment header mismatch",
	[DR_IB_RECV_COMP_ERR]		= "recv completion error",
	[DR_IB_SEND_COMP_ERR]		= "send completion error",
	[DR_IB_POST_SEND_FAIL]		= "post_send failure",
	[DR_IB_UMMOD]			= "rds_rdma module unload",
	[DR_IB_ACTIVE_BOND_FAILOVER]	= "active bonding failover",
	[DR_IB_LOOPBACK_CONN_DROP]	= "corresponding loopback conn drop",
	[DR_IB_ACTIVE_BOND_FAILBACK]	= "active bonding failback",
	[DR_IW_QP_EVENT]		= "qp_event",
	[DR_IW_REQ_WHILE_CONNECTING]	= "incoming REQ in connecting state",
	[DR_IW_PAS_SETUP_QP_FAIL]	= "passive setup_qp failure",
	[DR_IW_RDMA_ACCEPT_FAIL]	= "rdma_accept failure",
	[DR_IW_ACT_SETUP_QP_FAIL]	= "active setup_qp failure",
	[DR_IW_RDMA_CONNECT_FAIL]	= "rdma_connect failure",
	[DR_IW_POST_RECV_FAIL]		= "post_recv failure",
	[DR_IW_SEND_ACK_FAIL]		= "send_ack failure",
	[DR_IW_HEADER_MISSING]		= "no header in incoming msg",
	[DR_IW_HEADER_CORRUPTED]	= "corrupted header in incoming msg",
	[DR_IW_FRAG_HEADER_MISMATCH]	= "fragment header mismatch",
	[DR_IW_RECV_COMP_ERR]		= "recv completion error",
	[DR_IW_SEND_COMP_ERR]		= "send completion error",
	[DR_TCP_STATE_CLOSE]		= "sk_state to TCP_CLOSE",
	[DR_TCP_SEND_FAIL]		= "tcp_send failure",
};

char *conn_drop_reason_str(enum rds_conn_drop_src reason)
{
	return rds_str_array(conn_drop_reasons,
			     ARRAY_SIZE(conn_drop_reasons), reason);
}

static void rds_conn_probe_lanes(struct rds_connection *conn)
{
	struct hlist_head *head =
		rds_conn_bucket(conn->c_laddr, conn->c_faddr);
	struct rds_connection *tmp;

	rcu_read_lock();
	hlist_for_each_entry_rcu(tmp, head, c_hash_node) {
		if (tmp->c_faddr == conn->c_faddr &&
			tmp->c_laddr == conn->c_laddr &&
			tmp->c_tos != 0 &&
			tmp->c_trans == conn->c_trans) {
			if (rds_conn_up(tmp))
				rds_send_hb(tmp, 0);
			else if (rds_conn_connecting(tmp) && (tmp->c_route_resolved == 0)) {
				printk(KERN_INFO "RDS/IB: connection "
				       "<%pI4,%pI4,%d> "
				       "connecting, force reset\n",
				       &tmp->c_laddr,
				       &tmp->c_faddr,
				       tmp->c_tos);

				rds_conn_drop(tmp, DR_ZERO_LANE_DOWN);
			}
		}
	}
	rcu_read_unlock();
}

/*
 * Force a disconnect
 */
void rds_conn_drop(struct rds_connection *conn, int reason)
{
	unsigned long now = get_seconds();

	conn->c_drop_source = reason;
	if (rds_conn_state(conn) == RDS_CONN_UP) {
		conn->c_reconnect_start = now;
		conn->c_reconnect_warn = 1;
		conn->c_reconnect_drops = 0;
		conn->c_reconnect_err = 0;
		printk(KERN_INFO "RDS/IB: connection "
			"<%pI4,%pI4,%d> dropped due to '%s'\n",
			&conn->c_laddr,
			&conn->c_faddr,
			conn->c_tos,
			conn_drop_reason_str(reason));

		if (conn->c_tos == 0)
			rds_conn_probe_lanes(conn);

	} else if ((conn->c_reconnect_warn) &&
		   (now - conn->c_reconnect_start > 60)) {
		printk(KERN_INFO "RDS/IB: re-connect "
			"<%pI4,%pI4,%d> stalling "
			"for more than 1 min...(drops=%u err=%d)\n",
			&conn->c_laddr,
			&conn->c_faddr,
			conn->c_tos,
			conn->c_reconnect_drops,
			conn->c_reconnect_err);
		conn->c_reconnect_warn = 0;

		if (conn->c_tos == 0)
			rds_conn_probe_lanes(conn);
	}
	conn->c_reconnect_drops++;

	atomic_set(&conn->c_state, RDS_CONN_ERROR);

	rds_rtd(RDS_RTD_CM_EXT,
		"RDS/IB: queueing shutdown work, conn %p, <%pI4,%pI4,%d>\n",
		conn, &conn->c_laddr, &conn->c_faddr,
		conn->c_tos);

	queue_work(conn->c_wq, &conn->c_down_w);
}
EXPORT_SYMBOL_GPL(rds_conn_drop);

/*
 * If the connection is down, trigger a connect. We may have scheduled a
 * delayed reconnect however - in this case we should not interfere.
 */
void rds_conn_connect_if_down(struct rds_connection *conn)
{
	if (rds_conn_state(conn) == RDS_CONN_DOWN &&
	    !test_and_set_bit(RDS_RECONNECT_PENDING, &conn->c_flags)) {
		rds_rtd(RDS_RTD_CM_EXT,
			"queueing connect work, conn %p, <%pI4,%pI4,%d>\n",
			conn, &conn->c_laddr, &conn->c_faddr,
			conn->c_tos);
		queue_delayed_work(conn->c_wq, &conn->c_conn_w, 0);
	}
}
EXPORT_SYMBOL_GPL(rds_conn_connect_if_down);
