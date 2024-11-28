/*
 * Copyright (c) 2006, 2021 Oracle and/or its affiliates.
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
#include <net/ipv6.h>
#include <net/inet6_hashtables.h>

#include "rds.h"
#include "loop.h"

#include "trace.h"

#define RDS_CONNECTION_HASH_BITS 12
#define RDS_CONNECTION_HASH_ENTRIES (1 << RDS_CONNECTION_HASH_BITS)
#define RDS_CONNECTION_HASH_MASK (RDS_CONNECTION_HASH_ENTRIES - 1)

#define RDS_CONN_FADDR_HASH_ENTRIES 256

/* converting this to RCU is a chore for another day.. */
static DEFINE_SPINLOCK(rds_conn_lock);
static struct hlist_head rds_conn_hash[RDS_CONNECTION_HASH_ENTRIES];
static struct hlist_head rds_conn_faddr_hash[RDS_CONN_FADDR_HASH_ENTRIES];
static struct kmem_cache *rds_conn_slab;

/* Loop through the rds_conn_hash table and set head to the hlist_head
 * of each element.
 */
#define	for_each_conn_hash_bucket(head)				\
    for ((head) = rds_conn_hash;				\
	 (head) < rds_conn_hash + ARRAY_SIZE(rds_conn_hash);	\
	 (head)++)

static void rds_conn_ha_changed_task(struct work_struct *work);
static void rds_conn_shutdown_check_wait(struct work_struct *work);

static u32 rds_conn_bucket_hash(const struct in6_addr *laddr,
				const struct in6_addr *faddr,
				u8 tos)
{
	static u32 rds6_hash_secret __read_mostly;
	static u32 rds_hash_secret __read_mostly;

	u32 lhash, fhash, hash;

	net_get_random_once(&rds_hash_secret, sizeof(rds_hash_secret));
	net_get_random_once(&rds6_hash_secret, sizeof(rds6_hash_secret));

	if (laddr)
		lhash = (__force u32)laddr->s6_addr32[3];
	else
		lhash = 0;

	if (faddr) {
#if IS_ENABLED(CONFIG_IPV6)
		fhash = __ipv6_addr_jhash(faddr, rds6_hash_secret);
#else
		fhash = (__force u32)faddr->s6_addr32[3];
#endif
	} else
		fhash = 0;

	hash = __inet_ehashfn((__force __be32)lhash, tos,
			      (__force __be32)fhash, 0, rds_hash_secret);

	return hash;
}

static struct hlist_head *rds_conn_bucket(const struct in6_addr *laddr,
					  const struct in6_addr *faddr,
					  u8 tos)
{
	u32 hash = rds_conn_bucket_hash(laddr, faddr, tos);
	return &rds_conn_hash[hash & RDS_CONNECTION_HASH_MASK];
}

static struct hlist_head *rds_conn_faddr_bucket(const struct in6_addr *faddr)
{
	u32 hash = rds_conn_bucket_hash(NULL, faddr, 0);
	return &rds_conn_faddr_hash[hash % RDS_CONN_FADDR_HASH_ENTRIES];
}

#define rds_conn_info_set(var, test, suffix) do {		\
	if (test)						\
		var |= RDS_INFO_CONNECTION_FLAG_##suffix;	\
} while (0)

/* rcu read lock must be held or the connection spinlock */
static struct rds_connection *rds_conn_lookup(struct net *net,
					      struct hlist_head *head,
					      const struct in6_addr *laddr,
					      const struct in6_addr *faddr,
					      struct rds_transport *trans,
					      u8 tos,
					      int dev_if)
{
	struct rds_connection *conn, *ret = NULL;

	hlist_for_each_entry_rcu(conn, head, c_hash_node) {
		if (ipv6_addr_equal(&conn->c_faddr, faddr) &&
		    ipv6_addr_equal(&conn->c_laddr, laddr) &&
		    conn->c_tos == tos && conn->c_trans == trans &&
		    net == rds_conn_net(conn) &&
		    conn->c_dev_if == dev_if) {
			ret = conn;
			break;
		}
	}
	rdsdebug("returning conn %p for %pI6c -> %pI6c\n", ret, laddr, faddr);
	return ret;
}

void rds_conn_laddr_list(struct net *net, struct in6_addr *laddr,
			 struct list_head *laddr_conns)
{
	struct rds_connection *conn;
	struct hlist_head *head;

	rcu_read_lock();

	for_each_conn_hash_bucket(head) {
		hlist_for_each_entry_rcu(conn, head, c_hash_node)
			if (ipv6_addr_equal(&conn->c_laddr, laddr) &&
			    net == rds_conn_net(conn))
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
static void rds_conn_path_reset(struct rds_conn_path *cp)
{
	struct rds_connection *conn = cp->cp_conn;

	rdsdebug("connection %pI6c to %pI6c reset\n",
		 &conn->c_laddr, &conn->c_faddr);

	rds_stats_inc(s_conn_reset);
	rds_send_path_reset(cp);

	/* This function used to just set "cp->cp_flags = 0".
	 *
	 * That causes various race-conditions with flags that
	 * are explicitly cleared in "rds_conn_shutdown_final":
	 * "RDS_RECONNECT_PENDING" + "RDS_SHUTDOWN_WORK_QUEUED",
	 * and also clears "RDS_SHUTDOWN_WAITING" which
	 * must stay on for "rds_conn_shutdown_check_wait" to
	 * make progress.
	 * Also, "RDS_DESTROY_PENDING" should never be turned off.
	 *
	 * So instead we no longer clear all flags, but only
	 * those that should be safe to be cleared here.
	 */
	clear_bit(RDS_LL_SEND_FULL, &cp->cp_flags);
	clear_bit(RDS_IN_XMIT, &cp->cp_flags);
	clear_bit(RDS_RECV_REFILL, &cp->cp_flags);
	clear_bit(RDS_SEND_WORK_QUEUED, &cp->cp_flags);
	clear_bit(RDS_RECV_WORK_QUEUED, &cp->cp_flags);

	/* Do not clear next_rx_seq here, else we cannot distinguish
	 * retransmitted packets from new packets, and will hand all
	 * of them to the application. That is not consistent with the
	 * reliability guarantees of RDS. */
}

static void __rds_conn_path_init(struct rds_connection *conn,
				 struct rds_conn_path *cp, bool is_outgoing)
{
	spin_lock_init(&cp->cp_lock);
	cp->cp_next_tx_seq = 1;
	init_waitqueue_head(&cp->cp_waitq);
	INIT_LIST_HEAD(&cp->cp_send_queue);
	INIT_LIST_HEAD(&cp->cp_retrans);

	cp->cp_conn = conn;
	rds_conn_path_state_change(cp, RDS_CONN_DOWN, DR_DEFAULT, 0);
	cp->cp_reconnect_start = ktime_get_real_seconds();
	cp->cp_reconnect_warn = 1;
	cp->cp_conn->c_proposed_version = RDS_PROTOCOL_VERSION;

	INIT_DELAYED_WORK(&cp->cp_send_w, rds_send_worker);
	INIT_DELAYED_WORK(&cp->cp_recv_w, rds_recv_worker);
	INIT_DELAYED_WORK(&cp->cp_conn_w, rds_connect_worker);
	INIT_DELAYED_WORK(&cp->cp_hb_w, rds_hb_worker);
	INIT_WORK(&cp->cp_down_w, rds_shutdown_worker);
	INIT_DELAYED_WORK(&cp->cp_down_wait_w, rds_conn_shutdown_check_wait);
	mutex_init(&cp->cp_cm_lock);
	atomic_set(&cp->cp_rdma_map_pending, 0);
	init_waitqueue_head(&cp->cp_up_waitq);
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
						const struct in6_addr *laddr,
						const struct in6_addr *faddr,
						struct rds_transport *trans,
						gfp_t gfp, u8 tos,
						int is_outgoing,
						int dev_if)
{
	struct rds_connection *conn, *parent = NULL;
	struct hlist_head *head = rds_conn_bucket(laddr, faddr, tos);
	struct hlist_head *faddr_head = rds_conn_faddr_bucket(faddr);
	struct rds_transport *loop_trans;
	char *reason = NULL;
	unsigned long flags;
	int ret, i;
	int npaths;

	rcu_read_lock();
	conn = rds_conn_lookup(net, head, laddr, faddr, trans, tos, dev_if);
	if (conn &&
	    conn->c_loopback &&
	    conn->c_trans != &rds_loop_transport &&
	    ipv6_addr_equal(laddr, faddr) &&
	    !is_outgoing) {
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
		reason = "could not allocate conn";
		goto out;
	}
	memset(conn, 0, sizeof(*conn));

	INIT_HLIST_NODE(&conn->c_hash_node);
	INIT_HLIST_NODE(&conn->c_faddr_node);
	conn->c_laddr = *laddr;
	conn->c_isv6 = !ipv6_addr_v4mapped(laddr);
	conn->c_faddr = *faddr;
	conn->c_dev_if = dev_if;

	INIT_WORK(&conn->c_ha_changed.work, rds_conn_ha_changed_task);
	INIT_DELAYED_WORK(&conn->c_dr_sock_cancel_w, rds_conn_drop_sock_cancel_worker);

#if IS_ENABLED(CONFIG_IPV6)
	/* If the local address is link local, set c_bound_if to be the
	 * index used for this connection.  Otherwise, set it to 0 as
	 * the socket is not bound to an interface.  c_bound_if is used
	 * to look up a socket when a packet is received
	 */
	if (ipv6_addr_type(laddr) & IPV6_ADDR_LINKLOCAL)
		conn->c_bound_if = dev_if;
	else
#endif
		conn->c_bound_if = 0;

	rds_conn_net_set(conn, net);

	conn->c_tos = tos;

	ret = rds_cong_get_maps(conn);
	if (ret) {
		kmem_cache_free(rds_conn_slab, conn);
		conn = ERR_PTR(ret);
		reason = "rds_cong_get_maps failed";
		goto out;
	}

	/*
	 * This is where a connection becomes loopback.  If *any* RDS sockets
	 * can bind to the destination address then we'd rather the messages
	 * flow through loopback rather than either transport.
	 */
	loop_trans = rds_trans_get_preferred(net, faddr, conn->c_dev_if);
	if (loop_trans) {
		rds_trans_put(loop_trans);
		conn->c_loopback = 1;
		if (trans->t_prefer_loopback) {
			if (likely(is_outgoing)) {
				/* "outgoing" connection to local address.
				 * Protocol says it wants the connection
				 * handled by the loopback transport.
				 * This is what TCP does.
				 */
				trans = &rds_loop_transport;
			} else {
				/* No transport currently in use
				 * should end up here, but if it
				 * does, reset/destroy the connection.
				 */
				kmem_cache_free(rds_conn_slab, conn);
				conn = ERR_PTR(-EOPNOTSUPP);
				goto out;
			}
		}
	}

	npaths = (trans->t_mp_capable ? RDS_MPATH_WORKERS : 1);
	conn->c_path = kcalloc(npaths, sizeof(struct rds_conn_path), gfp);
	if (!conn->c_path) {
		kmem_cache_free(rds_conn_slab, conn);
		conn = ERR_PTR(-ENOMEM);
		reason = "conn path alloc failed";
		goto out;
	}

	conn->c_trans = trans;

	init_waitqueue_head(&conn->c_hs_waitq);
	for (i = 0; i < npaths; i++) {
		struct rds_conn_path *cp;

		cp = &conn->c_path[i];

		__rds_conn_path_init(conn, cp, is_outgoing);
		cp->cp_index = i;

		cp->cp_wq = alloc_ordered_workqueue("krds_cp_wq#%d/%d", 0,
						    atomic_read(&conn->c_trans->t_conn_count), i);
		if (!cp->cp_wq) {
			while (--i >= 0) {
				cp = conn->c_path + i;
				destroy_workqueue(cp->cp_wq);
			}
			kfree(conn->c_path);
			kmem_cache_free(rds_conn_slab, conn);
			conn = ERR_PTR(-ENOMEM);
			reason = "alloc_ordered_workqueue failed";
			goto out;
		}
	}
	ret = trans->conn_alloc(conn, gfp);
	if (ret) {
		kfree(conn->c_path);
		kmem_cache_free(rds_conn_slab, conn);
		conn = ERR_PTR(ret);
		reason = "conn alloc failed";
		goto out;
	}

	trace_rds_conn_create(NULL, conn, NULL, NULL, 0);

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
			trans->conn_free(conn->c_path[0].cp_transport_data);
			kfree(conn->c_path);
			kmem_cache_free(rds_conn_slab, conn);
			conn = parent->c_passive;
		} else {
			/* Note that for loopback connection, only one
			 * rds_connection is added to the conn hash table.
			 */
			parent->c_passive = conn;
			rds_cong_add_conn(conn);
			atomic_inc(&conn->c_trans->t_conn_count);
		}
	} else {
		/* Creating normal conn */
		struct rds_connection *found;

		found = rds_conn_lookup(net, head, laddr, faddr, trans, tos,
					dev_if);
		if (found) {
			struct rds_conn_path *cp;
			int i;

			for (i = 0; i < npaths; i++) {
				cp = &conn->c_path[i];
				/* The ->conn_alloc invocation may have
				 * allocated resource for all paths, so all
				 * of them may have to be freed here.
				 */
				if (cp->cp_transport_data)
					trans->conn_free(cp->cp_transport_data);
			}
			kfree(conn->c_path);
			kmem_cache_free(rds_conn_slab, conn);
			conn = found;
		} else {
			hlist_add_head_rcu(&conn->c_hash_node, head);
			hlist_add_head_rcu(&conn->c_faddr_node, faddr_head);
			rds_cong_add_conn(conn);
			atomic_inc(&conn->c_trans->t_conn_count);
		}
	}
	spin_unlock_irqrestore(&rds_conn_lock, flags);

out:
	if (reason)
		trace_rds_conn_create_err(NULL, conn, NULL, reason,
					  PTR_ERR(conn));

	return conn;
}

struct rds_connection *rds_conn_create(struct net *net,
				       const struct in6_addr *laddr,
				       const struct in6_addr *faddr,
				       struct rds_transport *trans,
				       u8 tos, gfp_t gfp, int dev_if)
{
	return __rds_conn_create(net, laddr, faddr, trans, gfp, tos, 0, dev_if);
}
EXPORT_SYMBOL_GPL(rds_conn_create);

struct rds_connection *rds_conn_create_outgoing(struct net *net,
						struct in6_addr *laddr,
						struct in6_addr *faddr,
						struct rds_transport *trans,
						u8 tos, gfp_t gfp, int dev_if)
{
	return __rds_conn_create(net, laddr, faddr, trans, gfp, tos, 1, dev_if);
}
EXPORT_SYMBOL_GPL(rds_conn_create_outgoing);

struct rds_connection *rds_conn_find(struct net *net, struct in6_addr *laddr,
				     struct in6_addr *faddr,
				     struct rds_transport *trans, u8 tos,
				     int dev_if)
{
	struct rds_connection *conn;
	struct hlist_head *head = rds_conn_bucket(laddr, faddr, tos);

	rcu_read_lock();
	conn = rds_conn_lookup(net, head, laddr, faddr, trans, tos, dev_if);
	rcu_read_unlock();

	return conn;
}
EXPORT_SYMBOL_GPL(rds_conn_find);

static void rds_conn_shutdown_final(struct rds_conn_path *cp)
{
	struct rds_connection *conn = cp->cp_conn;
	bool reconnect;

	/* Then reconnect if it's still live.
	 * The passive side of an IB loopback connection is never added
	 * to the conn hash, so we only trigger a reconnect on this
	 * conn if there's a pending yield.
	 * Otherwise, the reconnect is always triggered by the active peer.
	 */

	rds_queue_cancel_work(cp, &cp->cp_conn_w, "final shutdown");
	rds_clear_reconnect_pending_work_bit(cp);

	rcu_read_lock();
	reconnect = !hlist_unhashed(&conn->c_hash_node);
	rcu_read_unlock();

	/* also reconnect if we've got a pending yield */
	if (conn->c_trans->conn_has_alt_conn &&
	    conn->c_trans->conn_has_alt_conn(conn))
		reconnect = true;

	if (reconnect)
		rds_queue_reconnect(cp, false);

	rds_clear_shutdown_pending_work_bit(cp);

	if (cp->cp_shutdown_final)
		complete(cp->cp_shutdown_final);

	if (conn->c_trans->conn_slots_available)
		conn->c_trans->conn_slots_available(conn);
}

static void rds_conn_shutdown_check_wait(struct work_struct *work)
{
	struct rds_conn_path *cp = container_of(work,
						struct rds_conn_path,
						cp_down_wait_w.work);
	struct rds_connection *conn = cp->cp_conn;
	unsigned long delay;

	if (!test_bit(RDS_SHUTDOWN_WAITING, &cp->cp_flags))
		return;

	if (!test_bit(RDS_SHUTDOWN_WAIT1_DONE, &cp->cp_flags)) {
		if (test_bit(RDS_IN_XMIT, &cp->cp_flags) ||
		    test_and_set_bit(RDS_RECV_REFILL, &cp->cp_flags))
			return;

		set_bit(RDS_SHUTDOWN_WAIT1_DONE, &cp->cp_flags);
		smp_mb__after_atomic();
	}

	if (atomic_read(&cp->cp_rdma_map_pending) != 0)
		return;

	if (conn->c_trans->conn_path_shutdown_check_wait) {
		if (!test_bit(RDS_SHUTDOWN_PREPARE_DONE, &cp->cp_flags)) {
			if (conn->c_trans->conn_path_shutdown_prepare)
				conn->c_trans->conn_path_shutdown_prepare(cp);

			set_bit(RDS_SHUTDOWN_PREPARE_DONE, &cp->cp_flags);
			smp_mb__after_atomic();
		}

		delay = conn->c_trans->conn_path_shutdown_check_wait(cp);

		if (delay > 0) {
			rds_queue_delayed_work(cp, cp->cp_wq,
					       &cp->cp_down_wait_w, delay,
					       "shutdown check wait");

			if (conn->c_trans->conn_path_shutdown_tidy_up) {
				conn->c_trans->conn_path_shutdown_tidy_up(cp);

				delay = conn->c_trans->conn_path_shutdown_check_wait(cp);
				if (delay == 0)
					mod_delayed_work(cp->cp_wq, &cp->cp_down_wait_w, 0);
			}

			return;
		}

		if (conn->c_trans->conn_path_shutdown_final)
			conn->c_trans->conn_path_shutdown_final(cp);
	} else
		conn->c_trans->conn_path_shutdown(cp);

	clear_bit(RDS_SHUTDOWN_WAITING, &cp->cp_flags);
	smp_mb__after_atomic();

	clear_bit(RDS_RECV_REFILL, &cp->cp_flags);
	rds_conn_path_reset(cp);

	if (!rds_conn_path_transition(cp, RDS_CONN_DISCONNECTING,
				      RDS_CONN_DOWN, DR_DEFAULT) &&
	    !rds_conn_path_transition(cp, RDS_CONN_ERROR,
				      RDS_CONN_DOWN, DR_DEFAULT)) {
		/* This can happen - eg when we're in the middle of tearing
		 * down the connection, and someone unloads the rds module.
		 * Quite reproducible with loopback connections.
		 * Mostly harmless.
		 *
		 * Note that this also happens with rds-tcp because
		 * we could have triggered rds_conn_path_drop in irq
		 * mode from rds_tcp_state change on the receipt of
		 * a FIN, thus we need to recheck for RDS_CONN_ERROR
		 * here.
		 *
		 */
		pr_warn("RDS: %s: failed to transition to state DOWN, current state is %d\n",
			__func__, atomic_read(&cp->cp_state));
		rds_conn_path_drop(cp, DR_DOWN_TRANSITION_FAIL, 0);
		return;
	}

	rds_conn_shutdown_final(cp);
}

void rds_conn_init_shutdown(struct rds_conn_path *cp)
{
	cancel_delayed_work(&cp->cp_conn->c_dr_sock_cancel_w);

	/* shut it down unless it's down already */
	if (!rds_conn_path_transition(cp, RDS_CONN_DOWN, RDS_CONN_DOWN,
				      DR_DEFAULT)) {
		/*
		 * Quiesce the connection mgmt handlers before we start tearing
		 * things down. We don't hold the mutex for the entire
		 * duration of the shutdown operation, else we may be
		 * deadlocking with the CM handler. Instead, the CM event
		 * handler is supposed to check for state DISCONNECTING
		 */
		mutex_lock(&cp->cp_cm_lock);
		if (!rds_conn_path_transition(cp, RDS_CONN_UP,
					      RDS_CONN_DISCONNECTING,
					      DR_DEFAULT) &&
		    !rds_conn_path_transition(cp, RDS_CONN_CONNECTING,
					      RDS_CONN_DISCONNECTING,
					      DR_DEFAULT) &&
		    !rds_conn_path_transition(cp, RDS_CONN_ERROR,
					      RDS_CONN_DISCONNECTING,
					      DR_DEFAULT) &&
		    !rds_conn_path_transition(cp, RDS_CONN_RESETTING,
					      RDS_CONN_DISCONNECTING,
					      DR_DEFAULT)) {
			rds_conn_path_drop(cp, DR_INV_CONN_STATE, 0);
			mutex_unlock(&cp->cp_cm_lock);
			return;
		}
		mutex_unlock(&cp->cp_cm_lock);

		clear_bit(RDS_SHUTDOWN_WAIT1_DONE, &cp->cp_flags);
		clear_bit(RDS_SHUTDOWN_PREPARE_DONE, &cp->cp_flags);
		set_bit(RDS_SHUTDOWN_WAITING, &cp->cp_flags);
		smp_mb__after_atomic();
		queue_delayed_work(cp->cp_wq, &cp->cp_down_wait_w, 0);
	} else
		rds_conn_shutdown_final(cp);
}

/* destroy a single rds_conn_path. rds_conn_destroy() iterates over
 * all paths using rds_conn_path_destroy()
 */
static void rds_conn_path_destroy(struct rds_conn_path *cp, int shutdown)
{
	DECLARE_COMPLETION_ONSTACK(shutdown_final);
	struct rds_message *rm, *rtmp;
	LIST_HEAD(to_be_dropped);

	cp->cp_drop_source = DR_CONN_DESTROY;
	set_bit(RDS_DESTROY_PENDING, &cp->cp_flags);

	if (!cp->cp_transport_data)
		return;

	/* quiesce heartbeats */
	if (cp->cp_conn->c_is_hb_enabled)
		rds_queue_cancel_work(cp, &cp->cp_hb_w,
				      "conn path destroy hb worker");

	/* make sure lingering queued work won't try to ref the
	 * conn. If there is work queued, we cancel it (and set the
	 * bit to avoid any re-queueing)
	 */
	if (test_and_set_bit(RDS_SEND_WORK_QUEUED, &cp->cp_flags))
		rds_queue_cancel_work(cp, &cp->cp_send_w,
				      "conn path destroy send work");
	if (test_and_set_bit(RDS_RECV_WORK_QUEUED, &cp->cp_flags))
		rds_queue_cancel_work(cp, &cp->cp_recv_w,
				      "conn path destroy recv work");

	cp->cp_shutdown_final = &shutdown_final;
	rds_conn_path_drop(cp, DR_CONN_DESTROY, 0);
	rds_queue_flush_work(cp, &cp->cp_down_w, "conn path destroy down work");
	wait_for_completion(&shutdown_final);

	/* tear down queued messages */
	list_for_each_entry_safe(rm, rtmp,
				 &cp->cp_send_queue,
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
		rds_send_remove_from_sock(&to_be_dropped,
					  RDS_RDMA_SEND_DROPPED);
	if (cp->cp_xmit_rm)
		rds_message_put(cp->cp_xmit_rm);

	cp->cp_conn->c_trans->conn_free(cp->cp_transport_data);

	destroy_workqueue(cp->cp_wq);
	cp->cp_wq = NULL;
}

/* Stop and free a connection.
 *
 * This can only be used in very limited circumstances.  It assumes that once
 * the conn has been shutdown that no one else is referencing the connection.
 * We can only ensure this in the rmmod path in the current code.
 */
void rds_conn_destroy(struct rds_connection *conn, int shutdown)
{
	int npaths = (conn->c_trans->t_mp_capable ? RDS_MPATH_WORKERS : 1);
	int i;

	trace_rds_conn_destroy(NULL, conn, NULL, NULL, 0);

	conn->c_destroy_in_prog = 1;
	smp_mb();
	cancel_work_sync(&conn->c_ha_changed.work);
	cancel_delayed_work_sync(&conn->c_dr_sock_cancel_w);

	/* Ensure conn will not be scheduled for reconnect */
	spin_lock_irq(&rds_conn_lock);
	hlist_del_init_rcu(&conn->c_hash_node);
	hlist_del_init_rcu(&conn->c_faddr_node);
	spin_unlock_irq(&rds_conn_lock);
	synchronize_rcu();

	/* shut the connection down */
	for (i = 0; i < npaths; i++) {
		struct rds_conn_path *cp;

		cp = &conn->c_path[i];
		rds_conn_path_destroy(cp, shutdown);
		BUG_ON(!list_empty(&cp->cp_retrans));
	}

	/*
	 * The congestion maps aren't freed up here.  They're
	 * freed by rds_cong_exit() after all the connections
	 * have been freed.
	 */
	rds_cong_remove_conn(conn);

	atomic_dec(&conn->c_trans->t_conn_count);

	put_net(conn->c_net);
	kfree(conn->c_path);
	kmem_cache_free(rds_conn_slab, conn);
}
EXPORT_SYMBOL_GPL(rds_conn_destroy);

static void __rds_inc_msg_cp(struct rds_incoming *inc,
			     struct rds_info_iterator *iter,
			     struct in6_addr *saddr, struct in6_addr *daddr,
			     int flip, bool isv6)
{
#if IS_ENABLED(CONFIG_IPV6)
	if (isv6)
		rds6_inc_info_copy(inc, iter, saddr, daddr, flip);
	else
#endif
		rds_inc_info_copy(inc, iter, saddr->s6_addr32[3],
				  daddr->s6_addr32[3], flip);
}

static void rds_conn_message_info_cmn(struct socket *sock, unsigned int len,
				      struct rds_info_iterator *iter,
				      struct rds_info_lengths *lens,
				      int want_send, bool isv6)
{
	struct hlist_head *head;
	struct list_head *list;
	struct rds_connection *conn;
	struct rds_message *rm;
	unsigned int total = 0;
	unsigned long flags;
	int j;

	if (isv6)
		len /= sizeof(struct rds6_info_message);
	else
		len /= sizeof(struct rds_info_message);

	rcu_read_lock();

	for_each_conn_hash_bucket(head) {
		hlist_for_each_entry_rcu(conn, head, c_hash_node) {
			struct rds_conn_path *cp;
			int npaths;

			if (!isv6 && conn->c_isv6)
				continue;

			npaths = (conn->c_trans->t_mp_capable ?
				 RDS_MPATH_WORKERS : 1);

			for (j = 0; j < npaths; j++) {
				cp = &conn->c_path[j];
				if (want_send)
					list = &cp->cp_send_queue;
				else
					list = &cp->cp_retrans;

				spin_lock_irqsave(&cp->cp_lock, flags);
				/* XXX too lazy to maintain counts.. */
				list_for_each_entry(rm, list, m_conn_item) {
					total++;
					if (total <= len)
						__rds_inc_msg_cp(&rm->m_inc,
								 iter,
								 &conn->c_laddr,
								 &conn->c_faddr,
								 0, isv6);
				}
				spin_unlock_irqrestore(&cp->cp_lock, flags);
			}
		}
	}
	rcu_read_unlock();

	lens->nr = total;
	if (isv6)
		lens->each = sizeof(struct rds6_info_message);
	else
		lens->each = sizeof(struct rds_info_message);
}

static void rds_conn_message_info(struct socket *sock, unsigned int len,
				  struct rds_info_iterator *iter,
				  struct rds_info_lengths *lens,
				  int want_send)
{
	rds_conn_message_info_cmn(sock, len, iter, lens, want_send, false);
}

#if IS_ENABLED(CONFIG_IPV6)
static void rds6_conn_message_info(struct socket *sock, unsigned int len,
				   struct rds_info_iterator *iter,
				   struct rds_info_lengths *lens,
				   int want_send)
{
	rds_conn_message_info_cmn(sock, len, iter, lens, want_send, true);
}
#endif

static void rds_conn_message_info_send(struct socket *sock, unsigned int len,
				       struct rds_info_iterator *iter,
				       struct rds_info_lengths *lens)
{
	rds_conn_message_info(sock, len, iter, lens, 1);
}

#if IS_ENABLED(CONFIG_IPV6)
static void rds6_conn_message_info_send(struct socket *sock, unsigned int len,
					struct rds_info_iterator *iter,
					struct rds_info_lengths *lens)
{
	rds6_conn_message_info(sock, len, iter, lens, 1);
}
#endif

static void rds_conn_message_info_retrans(struct socket *sock,
					  unsigned int len,
					  struct rds_info_iterator *iter,
					  struct rds_info_lengths *lens)
{
	rds_conn_message_info(sock, len, iter, lens, 0);
}

#if IS_ENABLED(CONFIG_IPV6)
static void rds6_conn_message_info_retrans(struct socket *sock,
					   unsigned int len,
					   struct rds_info_iterator *iter,
					   struct rds_info_lengths *lens)
{
	rds6_conn_message_info(sock, len, iter, lens, 0);
}
#endif

void rds_for_each_conn_info(struct socket *sock, unsigned int len,
			    struct rds_info_iterator *iter,
			    struct rds_info_lengths *lens,
			    int (*visitor)(struct rds_connection *, void *),
			    u64 *buffer,
			    size_t item_len)
{
	struct hlist_head *head;
	struct rds_connection *conn;

	rcu_read_lock();

	lens->nr = 0;
	lens->each = item_len;

	for_each_conn_hash_bucket(head) {
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

static void rds_walk_conn_path_info(struct socket *sock, unsigned int len,
				    struct rds_info_iterator *iter,
				    struct rds_info_lengths *lens,
				    int (*visitor)(struct rds_conn_path *,
						   void *),
				    u64 *buffer,
				    size_t item_len)
{
	struct hlist_head *head;
	struct rds_connection *conn;

	rcu_read_lock();

	lens->nr = 0;
	lens->each = item_len;

	for_each_conn_hash_bucket(head) {
		hlist_for_each_entry_rcu(conn, head, c_hash_node) {
			struct rds_conn_path *cp;

			/* XXX We only copy the information from the first
			 * path for now.  The problem is that if there are
			 * more than one underlying paths, we cannot report
			 * information of all of them using the exisitng
			 * API.  For example, there is only one next_tx_seq,
			 * which path's next_tx_seq should we report?  It is
			 * a bug in the design of MPRDS.
			 */
			cp = conn->c_path;

			/* XXX no cp_lock usage.. */
			if (!visitor(cp, buffer))
				continue;

			/* We copy as much as we can fit in the buffer,
			 * but we count all items so that the caller
			 * can resize the buffer.
			 */
			if (len >= item_len) {
				rds_info_copy(iter, buffer, item_len);
				len -= item_len;
			}
			lens->nr++;
		}
	}
	rcu_read_unlock();
}

static int rds_conn_info_visitor(struct rds_conn_path *cp, void *buffer)
{
	struct rds_info_connection *cinfo = buffer;
	struct rds_connection *conn = cp->cp_conn;

	if (conn->c_isv6)
		return 0;

	cinfo->next_tx_seq = cp->cp_next_tx_seq;
	cinfo->next_rx_seq = cp->cp_next_rx_seq;
	cinfo->laddr = conn->c_laddr.s6_addr32[3];
	cinfo->faddr = conn->c_faddr.s6_addr32[3];
	cinfo->tos = conn->c_tos;
	strncpy(cinfo->transport, conn->c_trans->t_name,
		sizeof(cinfo->transport));
	cinfo->flags = 0;

	rds_conn_info_set(cinfo->flags, test_bit(RDS_IN_XMIT, &cp->cp_flags),
			  SENDING);
	/* XXX Future: return the state rather than these funky bits */
	rds_conn_info_set(cinfo->flags,
			  atomic_read(&cp->cp_state) == RDS_CONN_CONNECTING,
			  CONNECTING);
	rds_conn_info_set(cinfo->flags,
			  atomic_read(&cp->cp_state) == RDS_CONN_UP,
			  CONNECTED);
	rds_conn_info_set(cinfo->flags, cp->cp_pending_flush,
			  ERROR);
	return 1;
}

static void fill_path_info(struct rds_connection *conn, void *buffer)
{
	int i = 0;
	struct rds_info_connection_paths *cinfo =
				(struct rds_info_connection_paths *)buffer;
	struct rds_path_info *pinfo = cinfo->paths;

	memset(cinfo, 0, sizeof(struct rds_info_connection_paths));
	cinfo->local_addr = conn->c_laddr;
	cinfo->peer_addr = conn->c_faddr;
	cinfo->tos = conn->c_tos;
	strncpy(cinfo->transport, conn->c_trans->t_name,
		sizeof(cinfo->transport));
	cinfo->npaths = conn->c_npaths;
	do {
		struct rds_conn_path *cp = &conn->c_path[i];

		memset(pinfo, 0, sizeof(struct rds_path_info));
		rds_conn_info_set(pinfo->flags,
				  test_bit(RDS_IN_XMIT, &cp->cp_flags),
				  SENDING);
		rds_conn_info_set(pinfo->flags,
				  atomic_read(&cp->cp_state) == RDS_CONN_UP,
				  CONNECTED);
		rds_conn_info_set(pinfo->flags, cp->cp_pending_flush,
				  ERROR);
		pinfo->attempt_time = cp->cp_connection_initiated;
		pinfo->connect_time = cp->cp_connection_established;
		pinfo->connect_attempts = cp->cp_connection_attempts;
		pinfo->reset_time = cp->cp_connection_reset;
		pinfo->disconnect_reason = cp->cp_drop_source;
		pinfo->index = cp->cp_index;
		pinfo++;
	} while (++i < conn->c_npaths);
}

static int rds_info_paths_visitor(struct rds_conn_path *cp, void *buffer)
{
	struct rds_connection *conn = cp->cp_conn;

	if (conn->c_isv6)
		return 0;

	fill_path_info(conn, buffer);

	return 1;
}

#if IS_ENABLED(CONFIG_IPV6)
static int rds6_conn_info_visitor(struct rds_conn_path *cp, void *buffer)
{
	struct rds6_info_connection *cinfo6 = buffer;
	struct rds_connection *conn = cp->cp_conn;

	cinfo6->next_tx_seq = cp->cp_next_tx_seq;
	cinfo6->next_rx_seq = cp->cp_next_rx_seq;
	cinfo6->laddr = conn->c_laddr;
	cinfo6->faddr = conn->c_faddr;
	cinfo6->tos = conn->c_tos;
	strncpy(cinfo6->transport, conn->c_trans->t_name,
		sizeof(cinfo6->transport));
	cinfo6->flags = 0;

	rds_conn_info_set(cinfo6->flags, test_bit(RDS_IN_XMIT, &cp->cp_flags),
			  SENDING);
	/* XXX Future: return the state rather than these funky bits */
	rds_conn_info_set(cinfo6->flags,
			  atomic_read(&cp->cp_state) == RDS_CONN_CONNECTING,
			  CONNECTING);
	rds_conn_info_set(cinfo6->flags,
			  atomic_read(&cp->cp_state) == RDS_CONN_UP,
			  CONNECTED);
	rds_conn_info_set(cinfo6->flags, cp->cp_pending_flush,
			  ERROR);
	/* Just return 1 as there is no error case. This is a helper function
	 * for rds_walk_conn_path_info() and it wants a return value.
	 */
	return 1;
}

static int rds6_info_paths_visitor(struct rds_conn_path *cp, void *buffer)
{
	struct rds_connection *conn = cp->cp_conn;

	fill_path_info(conn, buffer);
	return 1;
}
#endif

static void rds_conn_info(struct socket *sock, unsigned int len,
			  struct rds_info_iterator *iter,
			  struct rds_info_lengths *lens)
{
	u64 buffer[(sizeof(struct rds_info_connection) + 7) / 8];

	rds_walk_conn_path_info(sock, len, iter, lens,
				rds_conn_info_visitor, buffer,
				sizeof(struct rds_info_connection));
}

static void rds_info_conn_paths(struct socket *sock, unsigned int len,
				struct rds_info_iterator *iter,
				struct rds_info_lengths *lens)
{
#define	paths_info_size (sizeof(struct rds_path_info) * RDS_MPATH_WORKERS)
#define	conn_path_info_size	\
	(sizeof(struct rds_info_connection_paths) + paths_info_size)

	u64 path_buffer[(conn_path_info_size + 7) / 8];

	rds_walk_conn_path_info(sock, len, iter, lens,
				rds_info_paths_visitor, path_buffer,
				conn_path_info_size);
}

#if IS_ENABLED(CONFIG_IPV6)
static void rds6_conn_info(struct socket *sock, unsigned int len,
			   struct rds_info_iterator *iter,
			   struct rds_info_lengths *lens)
{
	u64 buffer[(sizeof(struct rds6_info_connection) + 7) / 8];

	rds_walk_conn_path_info(sock, len, iter, lens,
				rds6_conn_info_visitor, buffer,
				sizeof(struct rds6_info_connection));
}

static void rds6_info_conn_paths(struct socket *sock, unsigned int len,
				 struct rds_info_iterator *iter,
				 struct rds_info_lengths *lens)
{
#define	paths_info_size (sizeof(struct rds_path_info) * RDS_MPATH_WORKERS)
#define	conn_path_info_size	\
	(sizeof(struct rds_info_connection_paths) + paths_info_size)

	u64 path6_buffer[(conn_path_info_size + 7) / 8];

	rds_walk_conn_path_info(sock, len, iter, lens,
				rds6_info_paths_visitor, path6_buffer,
				conn_path_info_size);
}
#endif

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
	rds_info_register_func(RDS_INFO_CONN_PATHS, rds_info_conn_paths);
#if IS_ENABLED(CONFIG_IPV6)
	rds_info_register_func(RDS6_INFO_CONNECTIONS, rds6_conn_info);
	rds_info_register_func(RDS6_INFO_SEND_MESSAGES,
			       rds6_conn_message_info_send);
	rds_info_register_func(RDS6_INFO_RETRANS_MESSAGES,
			       rds6_conn_message_info_retrans);
	rds_info_register_func(RDS6_INFO_CONN_PATHS, rds6_info_conn_paths);
#endif

	return 0;
}

void rds_conn_exit(void)
{
	struct hlist_head *head;

	rds_loop_exit();

	for_each_conn_hash_bucket(head)
		WARN_ON(!hlist_empty(head));

	kmem_cache_destroy(rds_conn_slab);

	rds_info_deregister_func(RDS_INFO_CONNECTIONS, rds_conn_info);
	rds_info_deregister_func(RDS_INFO_SEND_MESSAGES,
				 rds_conn_message_info_send);
	rds_info_deregister_func(RDS_INFO_RETRANS_MESSAGES,
				 rds_conn_message_info_retrans);
#if IS_ENABLED(CONFIG_IPV6)
	rds_info_deregister_func(RDS6_INFO_CONNECTIONS, rds6_conn_info);
	rds_info_deregister_func(RDS6_INFO_SEND_MESSAGES,
				 rds6_conn_message_info_send);
	rds_info_deregister_func(RDS6_INFO_RETRANS_MESSAGES,
				 rds6_conn_message_info_retrans);
#endif
}

static char *conn_drop_reasons[] = {
	[DR_DEFAULT]			= "unknown reason (default_state)",
	[DR_USER_RESET]			= "user reset",
	[DR_INV_CONN_STATE]		= "invalid connection state",
	[DR_DOWN_TRANSITION_FAIL]	= "failure to move to DOWN state",
	[DR_CONN_DESTROY]		= "connection destroy",
	[DR_CONN_CONNECT_FAIL]		= "conn_connect failure",
	[DR_HB_TIMEOUT]			= "hb timeout",
	[DR_RECONNECT_TIMEOUT]		= "reconnect timeout",
	[DR_SOCK_CANCEL]		= "cancel operation on socket",
	[DR_IB_CONN_DROP_RACE]		= "race between ESTABLISHED event and drop",
	[DR_IB_NOT_CONNECTING_STATE]	= "conn is not in CONNECTING state",
	[DR_IB_QP_EVENT]		= "qp event",
	[DR_IB_REQ_WHILE_CONN_UP]	= "incoming REQ in CONN_UP state",
	[DR_IB_REQ_WHILE_CONNECTING_MULTI]
						= "back-to-back REQ in CONNECTING state",
	[DR_IB_REQ_WHILE_CONNECTING_TIME]
					= "REQ racing for 15s in CONNECTING state",
	[DR_IB_PAS_SETUP_QP_FAIL]	= "passive setup_qp failure",
	[DR_IB_RDMA_ACCEPT_FAIL]	= "rdma_accept failure",
	[DR_IB_ACT_SETUP_QP_FAIL]	= "active setup_qp failure",
	[DR_IB_RDMA_CONNECT_FAIL]	= "rdma_connect failure",
	[DR_IB_CONN_DROP_YIELD]		= "yield to incoming request",
	[DR_IB_CONN_DROP_CM_WATCHDOG]	= "CM watchdog triggered",
	[DR_IB_RESOLVE_ROUTE_FAIL]	= "resolve_route failure",
	[DR_IB_RDMA_CM_ID_MISMATCH]	= "detected rdma_cm_id mismatch",
	[DR_IB_ROUTE_ERR]		= "ROUTE_ERROR event",
	[DR_IB_ADDR_ERR]		= "ADDR_ERROR event",
	[DR_IB_CONNECT_ERR]		= "CONNECT_ERROR or UNREACHABLE or DEVICE_REMOVE event",
	[DR_IB_CONSUMER_DEFINED_REJ]	= "CONSUMER_DEFINED reject",
	[DR_IB_REJECTED_EVENT]		= "REJECTED event",
	[DR_IB_ADDR_CHANGE]		= "ADDR_CHANGE event",
	[DR_IB_PEER_ADDR_CHANGE]	= "peer ADDR_CHANGE event",
	[DR_IB_DISCONNECTED_EVENT]	= "DISCONNECTED event",
	[DR_IB_TIMEWAIT_EXIT]		= "TIMEWAIT_EXIT event",
	[DR_IB_SHUTDOWN_NEEDED]		= "rdma_cm_id error and RDS_IB_NEED_SHUTDOWN is set",
	[DR_IB_POST_RECV_FAIL]		= "post_recv failure",
	[DR_IB_SEND_ACK_FAIL]		= "send_ack failure",
	[DR_IB_HEADER_MISSING]		= "no header in incoming msg",
	[DR_IB_HEADER_CORRUPTED]	= "corrupted header in incoming msg",
	[DR_IB_FRAG_HEADER_MISMATCH]	= "fragment header mismatch",
	[DR_IB_RECV_COMP_ERR]		= "recv completion error",
	[DR_IB_SEND_COMP_ERR]		= "send completion error",
	[DR_IB_POST_SEND_FAIL]		= "post_send failure",
	[DR_RDMA_DEV_REM]		= "RDMA device removal",
	[DR_IB_ACTIVE_BOND_FAILOVER]	= "active bonding failover",
	[DR_IB_LOOPBACK_CONN_DROP]	= "corresponding loopback conn drop",
	[DR_IB_ACTIVE_BOND_FAILBACK]	= "active bonding failback",
	[DR_TCP_STATE_CLOSE]		= "sk_state to TCP_CLOSE",
	[DR_TCP_SEND_FAIL]		= "tcp_send failure",
	[DR_TCP_STATE_ACCEPT_CLOSED]	= "accept with TCP_CLOSE_WAIT",
};

char *conn_drop_reason_str(enum rds_conn_drop_src reason)
{
	return rds_str_array(conn_drop_reasons,
			     ARRAY_SIZE(conn_drop_reasons), reason);
}

void rds_conn_path_trace_state_change(int changed, struct rds_conn_path *cp,
				      int old, int new, int reason, int err)
{
	char *reason_str = conn_drop_reason_str(reason);

	if (changed)
		trace_rds_state_change(cp, reason_str, err, old, new);
	else
		trace_rds_state_change_err(cp, reason_str, err, old, new);
}
EXPORT_SYMBOL_GPL(rds_conn_path_trace_state_change);

/*
 * Force a disconnect
 */
void rds_conn_path_drop(struct rds_conn_path *cp, int reason, int err)
{
	struct rds_connection *conn = cp->cp_conn;
	unsigned long now = ktime_get_real_seconds();

	if (conn->c_trans->conn_path_reset) {
		unsigned flags = RDS_CONN_PATH_RESET_WATCHDOG;

		if (reason == DR_IB_ADDR_CHANGE || reason == DR_IB_PEER_ADDR_CHANGE ||
		    reason == DR_IB_DISCONNECTED_EVENT)
			flags |= RDS_CONN_PATH_RESET_ALT_CONN;

		conn->c_trans->conn_path_reset(cp, flags);
	}

	cp->cp_drop_source = reason;
	trace_rds_conn_drop(NULL, conn, cp, conn_drop_reason_str(reason), err);

	if (rds_conn_path_state(cp) == RDS_CONN_UP) {
		cp->cp_reconnect_start = now;
		cp->cp_reconnect_warn = 1;
		cp->cp_reconnect_err = 0;
		cp->cp_connection_reset = ktime_get_real_seconds();
		/* Restart counting */
		cp->cp_connection_attempts = 0;
		if (conn->c_trans->t_type != RDS_TRANS_TCP)
			printk(KERN_INFO "RDS/IB: connection <%pI6c,%pI6c,%d> dropped due to '%s'\n",
			       &conn->c_laddr,
			       &conn->c_faddr,
			       conn->c_tos,
			       conn_drop_reason_str(reason));

	} else if ((cp->cp_reconnect_warn) &&
		   (now - cp->cp_reconnect_start > 60)) {
		printk(KERN_INFO "RDS/%s: re-connect <%pI6c,%pI6c,%d> stalling for more than 1 min...(drops=%u err=%d)\n",
		       conn->c_trans->t_type == RDS_TRANS_TCP ? "TCP" : "IB",
		       &conn->c_laddr,
		       &conn->c_faddr,
		       conn->c_tos,
		       cp->cp_connection_attempts,
		       cp->cp_reconnect_err);
		cp->cp_reconnect_warn = 0;
	}
	cp->cp_conn_start_jf = 0;

	rds_conn_path_state_change(cp, RDS_CONN_ERROR, reason, err);

	if (reason != DR_CONN_DESTROY && test_bit(RDS_DESTROY_PENDING, &cp->cp_flags)) {
		trace_rds_queue_noop(conn, cp, NULL, NULL, 0,
				     "not queueing work, destroy pending");
		return;
	}

	rds_cond_queue_shutdown_work(cp);
}
EXPORT_SYMBOL_GPL(rds_conn_path_drop);

void rds_conn_drop(struct rds_connection *conn, int reason, int err)
{
	WARN_ON(conn->c_trans->t_mp_capable);
	rds_conn_path_drop(&conn->c_path[0], reason, err);
}
EXPORT_SYMBOL_GPL(rds_conn_drop);

static void rds_conn_ha_changed_task(struct work_struct *work)
{
	struct rds_connection *conn = container_of(work,
						   struct rds_connection,
						   c_ha_changed.work);

	conn->c_trans->conn_ha_changed(conn,
				       conn->c_ha_changed.ha,
				       conn->c_ha_changed.ha_len);
}

void rds_conn_faddr_ha_changed(const struct in6_addr *faddr,
			       const unsigned char *ha,
			       unsigned ha_len)
{
	struct hlist_head *head = rds_conn_faddr_bucket(faddr);
	struct rds_connection *conn;

	rcu_read_lock();

	hlist_for_each_entry_rcu(conn, head, c_faddr_node) {
		smp_mb();
		if (conn->c_destroy_in_prog)
			continue;

		if (conn->c_trans->conn_ha_changed &&
		    ipv6_addr_equal(&conn->c_faddr, faddr)) {
			/* In order to not disturb the delicate RCU read lock
			 * we don't acquire any locks to protect against
			 * concurrent access to c_ha_changed here.
			 *
			 * We can afford to to so because:
			 * o The only thing we care about is whether an address was changed or not
			 * o Concurrent access with an unchanged address doesn't matter:
			 *   No matter how many times we overwrite memory with unchanged data,
			 *   it's still unchanged.
			 * o If a changed address is updated partially, and the half-update
			 *   only included unchanged data thus far, the concurrent
			 *   "rds_conn_ha_changed_task" will see the data as unchanged
			 *   and the subsequent "queue_work" will take care of the address change.
			 *   We know it will be scheduled in this case, since we have concurrency
			 *   so the work wasn't PENDING anymore, but RUNNING.
			 * o If a changed address is updated partially, and the half-update
			 *   already included changed data, the concurrent
			 *   "rds_conn_ha_changed_task" will already see the changed data.
			 *   The subsequent "queue_work" will see it again, and issue another drop
			 *   which happens with a lock also, as the code doesn't remember if a drop
			 *   was already issued.
			 * o The only "weird" case is if a changed address is updated partially
			 *   but then falls back to unchanged.
			 *   Depending on where the change was with regards to the partial update,
			 *   the entire event may be missed or not.
			 *   If it's missed, that's probably a good thing:
			 *   The peer managed to failover and failback quicker than we were able
			 *   to memcpy MAC addresses and execute delayed work.
			 */
			memcpy(&conn->c_ha_changed.ha, ha, ha_len);
			conn->c_ha_changed.ha_len = ha_len;

			queue_work(system_unbound_wq, &conn->c_ha_changed.work);
		}
	}

	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(rds_conn_faddr_ha_changed);

/*
 * If the connection is down, trigger a connect. We may have scheduled a
 * delayed reconnect however - in this case we should not interfere.
 */
void rds_conn_path_connect_if_down(struct rds_conn_path *cp)
{
	if (rds_conn_path_down(cp))
		rds_queue_reconnect(cp, true);
}
EXPORT_SYMBOL_GPL(rds_conn_path_connect_if_down);

/* Check connectivity of all paths
 */
void rds_check_all_paths(struct rds_connection *conn)
{
	int i = 0;

	do {
		rds_conn_path_connect_if_down(&conn->c_path[i]);
	} while (++i < conn->c_npaths);
}

void rds_conn_connect_if_down(struct rds_connection *conn)
{
	WARN_ON(conn->c_trans->t_mp_capable);
	rds_conn_path_connect_if_down(&conn->c_path[0]);
}
EXPORT_SYMBOL_GPL(rds_conn_connect_if_down);
