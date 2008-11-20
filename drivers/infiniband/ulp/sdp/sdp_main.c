/*
 * Copyright (c) 2006 Mellanox Technologies Ltd.  All rights reserved.
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
 */
/*
 *  This file is based on net/ipv4/tcp.c
 *  under the following permission notice:
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either  version
 *  2 of the License, or(at your option) any later version.
 */

#if defined(__ia64__)
/* csum_partial_copy_from_user is not exported on ia64.
   We don't really need it for SDP - skb_copy_to_page happens to call it
   but for SDP HW checksum is always set, so ... */

#include <linux/errno.h>
#include <linux/types.h>
#include <asm/checksum.h>

static inline
unsigned int csum_partial_copy_from_user_new (const char *src, char *dst,
						 int len, unsigned int sum,
						 int *errp)
{
	*errp = -EINVAL;
	return 0;
}

#define csum_partial_copy_from_user csum_partial_copy_from_user_new
#endif

#include <linux/tcp.h>
#include <asm/ioctls.h>
#include <linux/workqueue.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/protocol.h>
#include <net/inet_common.h>
#include <linux/proc_fs.h>
#include <rdma/rdma_cm.h>
#include <rdma/ib_verbs.h>
/* TODO: remove when sdp_socket.h becomes part of include/linux/socket.h */
#include "sdp_socket.h"
#include "sdp.h"
#include <linux/delay.h>

MODULE_AUTHOR("Michael S. Tsirkin");
MODULE_DESCRIPTION("InfiniBand SDP module");
MODULE_LICENSE("Dual BSD/GPL");

#ifdef CONFIG_INFINIBAND_SDP_DEBUG
int sdp_debug_level;

module_param_named(debug_level, sdp_debug_level, int, 0644);
MODULE_PARM_DESC(debug_level, "Enable debug tracing if > 0.");
#endif
#ifdef CONFIG_INFINIBAND_SDP_DEBUG
int sdp_data_debug_level;

module_param_named(data_debug_level, sdp_data_debug_level, int, 0644);
MODULE_PARM_DESC(data_debug_level, "Enable data path debug tracing if > 0.");
#endif

static int send_poll_hit;

module_param_named(send_poll_hit, send_poll_hit, int, 0644);
MODULE_PARM_DESC(send_poll_hit, "How many times send poll helped.");

static int send_poll_miss;

module_param_named(send_poll_miss, send_poll_miss, int, 0644);
MODULE_PARM_DESC(send_poll_miss, "How many times send poll missed.");

static int recv_poll_hit;

module_param_named(recv_poll_hit, recv_poll_hit, int, 0644);
MODULE_PARM_DESC(recv_poll_hit, "How many times recv poll helped.");

static int recv_poll_miss;

module_param_named(recv_poll_miss, recv_poll_miss, int, 0644);
MODULE_PARM_DESC(recv_poll_miss, "How many times recv poll missed.");

static int send_poll = 100;

module_param_named(send_poll, send_poll, int, 0644);
MODULE_PARM_DESC(send_poll, "How many times to poll send.");

static int recv_poll = 1000;

module_param_named(recv_poll, recv_poll, int, 0644);
MODULE_PARM_DESC(recv_poll, "How many times to poll recv.");

static int send_poll_thresh = 8192;

module_param_named(send_poll_thresh, send_poll_thresh, int, 0644);
MODULE_PARM_DESC(send_poll_thresh, "Send message size thresh hold over which to start polling.");

static unsigned int sdp_keepalive_time = SDP_KEEPALIVE_TIME;

module_param_named(sdp_keepalive_time, sdp_keepalive_time, uint, 0644);
MODULE_PARM_DESC(sdp_keepalive_time, "Default idle time in seconds before keepalive probe sent.");

static int sdp_zcopy_thresh = 65536;
module_param_named(sdp_zcopy_thresh, sdp_zcopy_thresh, int, 0644);
MODULE_PARM_DESC(sdp_zcopy_thresh, "Zero copy send threshold; 0=0ff.");

struct workqueue_struct *sdp_workqueue;

static struct list_head sock_list;
static spinlock_t sock_list_lock;

static DEFINE_RWLOCK(device_removal_lock);

static inline unsigned int sdp_keepalive_time_when(const struct sdp_sock *ssk)
{
	return ssk->keepalive_time ? : sdp_keepalive_time;
}

inline void sdp_add_sock(struct sdp_sock *ssk)
{
	spin_lock_irq(&sock_list_lock);
	list_add_tail(&ssk->sock_list, &sock_list);
	spin_unlock_irq(&sock_list_lock);
}

inline void sdp_remove_sock(struct sdp_sock *ssk)
{
	spin_lock_irq(&sock_list_lock);
	BUG_ON(list_empty(&sock_list));
	list_del_init(&(ssk->sock_list));
	spin_unlock_irq(&sock_list_lock);
}

static int sdp_get_port(struct sock *sk, unsigned short snum)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	struct sockaddr_in *src_addr;
	int rc;

	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(snum),
		.sin_addr.s_addr = inet_sk(sk)->rcv_saddr,
	};

	sdp_dbg(sk, "%s: %u.%u.%u.%u:%hu\n", __func__,
		NIPQUAD(addr.sin_addr.s_addr), ntohs(addr.sin_port));

	if (!ssk->id)
		ssk->id = rdma_create_id(sdp_cma_handler, sk, RDMA_PS_SDP);

	if (!ssk->id)
	       return -ENOMEM;

	/* IP core seems to bind many times to the same address */
	/* TODO: I don't really understand why. Find out. */
	if (!memcmp(&addr, &ssk->id->route.addr.src_addr, sizeof addr))
		return 0;

	rc = rdma_bind_addr(ssk->id, (struct sockaddr *)&addr);
	if (rc) {
		rdma_destroy_id(ssk->id);
		ssk->id = NULL;
		return rc;
	}

	src_addr = (struct sockaddr_in *)&(ssk->id->route.addr.src_addr);
	inet_sk(sk)->num = ntohs(src_addr->sin_port);
	return 0;
}

static void sdp_destroy_qp(struct sdp_sock *ssk)
{
	struct ib_pd *pd = NULL;
	struct ib_cq *cq = NULL;

	if (ssk->qp) {
		pd = ssk->qp->pd;
		cq = ssk->cq;
		ssk->cq = NULL;
		ib_destroy_qp(ssk->qp);

		while (ssk->rx_head != ssk->rx_tail) {
			struct sk_buff *skb;
			skb = sdp_recv_completion(ssk, ssk->rx_tail);
			if (!skb)
				break;
			atomic_sub(SDP_MAX_SEND_SKB_FRAGS, &sdp_current_mem_usage);
			__kfree_skb(skb);
		}
		while (ssk->tx_head != ssk->tx_tail) {
			struct sk_buff *skb;
			skb = sdp_send_completion(ssk, ssk->tx_tail);
			if (!skb)
				break;
			__kfree_skb(skb);
		}
	}

	if (cq)
		ib_destroy_cq(cq);

	if (ssk->mr)
		ib_dereg_mr(ssk->mr);

	if (pd)
		ib_dealloc_pd(pd);

	sdp_remove_large_sock(ssk);

	kfree(ssk->rx_ring);
	kfree(ssk->tx_ring);
}


static void sdp_reset_keepalive_timer(struct sock *sk, unsigned long len)
{
	struct sdp_sock *ssk = sdp_sk(sk);

	sdp_dbg(sk, "%s\n", __func__);

	ssk->keepalive_tx_head = ssk->tx_head;
	ssk->keepalive_rx_head = ssk->rx_head;

	sk_reset_timer(sk, &sk->sk_timer, jiffies + len);
}

static void sdp_delete_keepalive_timer(struct sock *sk)
{
	struct sdp_sock *ssk = sdp_sk(sk);

	sdp_dbg(sk, "%s\n", __func__);

	ssk->keepalive_tx_head = 0;
	ssk->keepalive_rx_head = 0;

	sk_stop_timer(sk, &sk->sk_timer);
}

static void sdp_keepalive_timer(unsigned long data)
{
	struct sock *sk = (struct sock *)data;
	struct sdp_sock *ssk = sdp_sk(sk);

	sdp_dbg(sk, "%s\n", __func__);

	/* Only process if the socket is not in use */
	bh_lock_sock(sk);
	if (sock_owned_by_user(sk)) {
		sdp_reset_keepalive_timer(sk, HZ / 20);
		goto out;
	}

	if (!sock_flag(sk, SOCK_KEEPOPEN) || sk->sk_state == TCP_LISTEN ||
	    sk->sk_state == TCP_CLOSE)
		goto out;

	if (ssk->keepalive_tx_head == ssk->tx_head &&
	    ssk->keepalive_rx_head == ssk->rx_head)
		sdp_post_keepalive(ssk);

	sdp_reset_keepalive_timer(sk, sdp_keepalive_time_when(ssk));

out:
	bh_unlock_sock(sk);
	sock_put(sk, SOCK_REF_BORN);
}

static void sdp_init_timer(struct sock *sk)
{
	init_timer(&sk->sk_timer);

	sk->sk_timer.function = sdp_keepalive_timer;
	sk->sk_timer.data = (unsigned long)sk;
}

static void sdp_set_keepalive(struct sock *sk, int val)
{
	sdp_dbg(sk, "%s %d\n", __func__, val);

	if ((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN))
		return;

	if (val && !sock_flag(sk, SOCK_KEEPOPEN))
		sdp_start_keepalive_timer(sk);
	else if (!val)
		sdp_delete_keepalive_timer(sk);
}

void sdp_start_keepalive_timer(struct sock *sk)
{
	sdp_reset_keepalive_timer(sk, sdp_keepalive_time_when(sdp_sk(sk)));
}

void sdp_reset_sk(struct sock *sk, int rc)
{
	struct sdp_sock *ssk = sdp_sk(sk);

	sdp_dbg(sk, "%s\n", __func__);

	read_lock(&device_removal_lock);

	if (ssk->cq)
		sdp_poll_cq(ssk, ssk->cq);

	if (!(sk->sk_shutdown & RCV_SHUTDOWN) || !sk_stream_memory_free(sk))
		sdp_set_error(sk, rc);

	sdp_destroy_qp(ssk);

	memset((void *)&ssk->id, 0, sizeof(*ssk) - offsetof(typeof(*ssk), id));

	sk->sk_state_change(sk);

	/* Don't destroy socket before destroy work does its job */
	sock_hold(sk, SOCK_REF_RESET);
	queue_work(sdp_workqueue, &ssk->destroy_work);

	read_unlock(&device_removal_lock);
}

/* Like tcp_reset */
/* When we get a reset (completion with error) we do this. */
void sdp_reset(struct sock *sk)
{
	int err;

	sdp_dbg(sk, "%s state=%d\n", __func__, sk->sk_state);

	if (sk->sk_state != TCP_ESTABLISHED)
		return;

	/* We want the right error as BSD sees it (and indeed as we do). */

	/* On fin we currently only set RCV_SHUTDOWN, so .. */
	err = (sk->sk_shutdown & RCV_SHUTDOWN) ? EPIPE : ECONNRESET;

	sdp_set_error(sk, -err);
	wake_up(&sdp_sk(sk)->wq);
	sk->sk_state_change(sk);
}

/* TODO: linger? */
static void sdp_close_sk(struct sock *sk)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	struct rdma_cm_id *id = NULL;
	sdp_dbg(sk, "%s\n", __func__);

	lock_sock(sk);

	sk->sk_send_head = NULL;
	skb_queue_purge(&sk->sk_write_queue);
        /*
         * If sendmsg cached page exists, toss it.
         */
        if (sk->sk_sndmsg_page) {
                __free_page(sk->sk_sndmsg_page);
                sk->sk_sndmsg_page = NULL;
        }

	id = ssk->id;
	if (ssk->id) {
		id->qp = NULL;
		ssk->id = NULL;
		release_sock(sk);
		rdma_destroy_id(id);
		lock_sock(sk);
	}

	skb_queue_purge(&sk->sk_receive_queue);

	sdp_destroy_qp(ssk);

	sdp_dbg(sk, "%s done; releasing sock\n", __func__);
	release_sock(sk);

	flush_scheduled_work();
}

static void sdp_destruct(struct sock *sk)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	struct sdp_sock *s, *t;

	sdp_dbg(sk, "%s\n", __func__);
	if (ssk->destructed_already) {
		sdp_warn(sk, "redestructing sk!");
		return;
	}

	ssk->destructed_already = 1;

	sdp_remove_sock(ssk);
	
	sdp_close_sk(sk);

	if (ssk->parent)
		goto done;

	list_for_each_entry_safe(s, t, &ssk->backlog_queue, backlog_queue) {
		sk_common_release(&s->isk.sk);
	}
	list_for_each_entry_safe(s, t, &ssk->accept_queue, accept_queue) {
		sk_common_release(&s->isk.sk);
	}

done:
	sdp_dbg(sk, "%s done\n", __func__);
}

static void sdp_send_disconnect(struct sock *sk)
{
	sock_hold(sk, SOCK_REF_DREQ_TO);
	queue_delayed_work(sdp_workqueue, &sdp_sk(sk)->dreq_wait_work,
			   SDP_FIN_WAIT_TIMEOUT);
	sdp_sk(sk)->dreq_wait_timeout = 1;

	sdp_sk(sk)->sdp_disconnect = 1;
	sdp_post_sends(sdp_sk(sk), 0);
}

/*
 *	State processing on a close.
 *	TCP_ESTABLISHED -> TCP_FIN_WAIT1 -> TCP_CLOSE
 */
static int sdp_close_state(struct sock *sk)
{
	switch (sk->sk_state) {
	case TCP_ESTABLISHED:
		sdp_exch_state(sk, TCPF_ESTABLISHED, TCP_FIN_WAIT1);
		break;
	case TCP_CLOSE_WAIT:
		sdp_exch_state(sk, TCPF_CLOSE_WAIT, TCP_LAST_ACK);
		break;
	default:
		return 0;
	}

	return 1;
}

/* Like tcp_close */
static void sdp_close(struct sock *sk, long timeout)
{
	struct sk_buff *skb;
	int data_was_unread = 0;

	lock_sock(sk);

	sdp_dbg(sk, "%s\n", __func__);

	sdp_delete_keepalive_timer(sk);

	sk->sk_shutdown = SHUTDOWN_MASK;

	if ((1 << sk->sk_state) & (TCPF_TIME_WAIT | TCPF_CLOSE)) {
		/* this could happen if socket was closed by a CM teardown
		   and after that the user called close() */
		goto out;
	}

	if (sk->sk_state == TCP_LISTEN || sk->sk_state == TCP_SYN_SENT) {
		sdp_exch_state(sk, TCPF_LISTEN | TCPF_SYN_SENT, TCP_CLOSE);

		/* Special case: stop listening.
		   This is done by sdp_destruct. */
		goto adjudge_to_death;
	}

	sock_hold(sk, SOCK_REF_CM_TW);

	/*  We need to flush the recv. buffs.  We do this only on the
	 *  descriptor close, not protocol-sourced closes, because the
	 *  reader process may not have drained the data yet!
	 */
	while ((skb = __skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		data_was_unread = 1;
		__kfree_skb(skb);
	}

	sk_mem_reclaim(sk);

	/* As outlined in draft-ietf-tcpimpl-prob-03.txt, section
	 * 3.10, we send a RST here because data was lost.  To
	 * witness the awful effects of the old behavior of always
	 * doing a FIN, run an older 2.1.x kernel or 2.0.x, start
	 * a bulk GET in an FTP client, suspend the process, wait
	 * for the client to advertise a zero window, then kill -9
	 * the FTP client, wheee...  Note: timeout is always zero
	 * in such a case.
	 */
	if (data_was_unread ||
		(sock_flag(sk, SOCK_LINGER) && !sk->sk_lingertime)) {
		/* Unread data was tossed, zap the connection. */
		NET_INC_STATS_USER(sock_net(sk), LINUX_MIB_TCPABORTONCLOSE);
		sdp_exch_state(sk, TCPF_CLOSE_WAIT | TCPF_ESTABLISHED,
			       TCP_TIME_WAIT);

		/* Go into abortive close */
		sk->sk_prot->disconnect(sk, 0);
	} else if (sdp_close_state(sk)) {
		/* We FIN if the application ate all the data before
		 * zapping the connection.
		 */

		sdp_send_disconnect(sk);
	}

	/* TODO: state should move to CLOSE or CLOSE_WAIT etc on disconnect.
	   Since it currently doesn't, do it here to avoid blocking below. */
	if (!sdp_sk(sk)->id)
		sdp_exch_state(sk, TCPF_FIN_WAIT1 | TCPF_LAST_ACK |
			       TCPF_CLOSE_WAIT, TCP_CLOSE);

	sk_stream_wait_close(sk, timeout);

adjudge_to_death:
	/* It is the last release_sock in its life. It will remove backlog. */
	release_sock(sk);
	/* Now socket is owned by kernel and we acquire lock
	   to finish close. No need to check for user refs.
	 */
	lock_sock(sk);

	sock_orphan(sk);

	/*	This is a (useful) BSD violating of the RFC. There is a
	 *	problem with TCP as specified in that the other end could
	 *	keep a socket open forever with no application left this end.
	 *	We use a 3 minute timeout (about the same as BSD) then kill
	 *	our end. If they send after that then tough - BUT: long enough
	 *	that we won't make the old 4*rto = almost no time - whoops
	 *	reset mistake.
	 *
	 *	Nope, it was not mistake. It is really desired behaviour
	 *	f.e. on http servers, when such sockets are useless, but
	 *	consume significant resources. Let's do it with special
	 *	linger2	option.					--ANK
	 */
	if (sk->sk_state == TCP_FIN_WAIT1) {
		/* TODO: liger2 unimplemented.
		   We should wait 3.5 * rto. How do I know rto? */
		/* TODO: tcp_fin_time to get timeout */
		sdp_dbg(sk, "%s: entering time wait refcnt %d\n", __func__,
			atomic_read(&sk->sk_refcnt));
		atomic_inc(sk->sk_prot->orphan_count);
	}

	/* TODO: limit number of orphaned sockets.
	   TCP has sysctl_tcp_mem and sysctl_tcp_max_orphans */

out:
	release_sock(sk);

	sk_common_release(sk);
}

static int sdp_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	struct sockaddr_in src_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(inet_sk(sk)->sport),
		.sin_addr.s_addr = inet_sk(sk)->saddr,
	};
	int rc;

        if (addr_len < sizeof(struct sockaddr_in))
                return -EINVAL;

        if (uaddr->sa_family != AF_INET && uaddr->sa_family != AF_INET_SDP)
                return -EAFNOSUPPORT;

	if (!ssk->id) {
		rc = sdp_get_port(sk, 0);
		if (rc)
			return rc;
		inet_sk(sk)->sport = htons(inet_sk(sk)->num);
	}

	sdp_dbg(sk, "%s %u.%u.%u.%u:%hu -> %u.%u.%u.%u:%hu\n", __func__,
		NIPQUAD(src_addr.sin_addr.s_addr),
		ntohs(src_addr.sin_port),
		NIPQUAD(((struct sockaddr_in *)uaddr)->sin_addr.s_addr),
		ntohs(((struct sockaddr_in *)uaddr)->sin_port));

	if (!ssk->id) {
		printk("??? ssk->id == NULL. Ohh\n");
		return -EINVAL;
	}

	rc = rdma_resolve_addr(ssk->id, (struct sockaddr *)&src_addr,
			       uaddr, SDP_RESOLVE_TIMEOUT);
	if (rc) {
		sdp_warn(sk, "rdma_resolve_addr failed: %d\n", rc);
		return rc;
	}

	sdp_exch_state(sk, TCPF_CLOSE, TCP_SYN_SENT);
	return 0;
}

static int sdp_disconnect(struct sock *sk, int flags)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	int rc = 0;
	int old_state = sk->sk_state;
	struct sdp_sock *s, *t;
	struct rdma_cm_id *id;

	sdp_dbg(sk, "%s\n", __func__);

	if (old_state != TCP_LISTEN) {
		if (ssk->id)
			rc = rdma_disconnect(ssk->id);

		return rc;
	}

	sdp_exch_state(sk, TCPF_LISTEN, TCP_CLOSE);
	id = ssk->id;
	ssk->id = NULL;
	release_sock(sk); /* release socket since locking semantics is parent
			     inside child */
	if (id)
		rdma_destroy_id(id);

	list_for_each_entry_safe(s, t, &ssk->backlog_queue, backlog_queue) {
		sk_common_release(&s->isk.sk);
	}
	list_for_each_entry_safe(s, t, &ssk->accept_queue, accept_queue) {
		sk_common_release(&s->isk.sk);
	}

	lock_sock(sk);

	return 0;
}

/* Like inet_csk_wait_for_connect */
static int sdp_wait_for_connect(struct sock *sk, long timeo)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	DEFINE_WAIT(wait);
	int err;

	sdp_dbg(sk, "%s\n", __func__);
	/*
	 * True wake-one mechanism for incoming connections: only
	 * one process gets woken up, not the 'whole herd'.
	 * Since we do not 'race & poll' for established sockets
	 * anymore, the common case will execute the loop only once.
	 *
	 * Subtle issue: "add_wait_queue_exclusive()" will be added
	 * after any current non-exclusive waiters, and we know that
	 * it will always _stay_ after any new non-exclusive waiters
	 * because all non-exclusive waiters are added at the
	 * beginning of the wait-queue. As such, it's ok to "drop"
	 * our exclusiveness temporarily when we get woken up without
	 * having to remove and re-insert us on the wait queue.
	 */
	for (;;) {
		prepare_to_wait_exclusive(sk->sk_sleep, &wait,
					  TASK_INTERRUPTIBLE);
		release_sock(sk);
		if (list_empty(&ssk->accept_queue)) {
			sdp_dbg(sk, "%s schedule_timeout\n", __func__);
			timeo = schedule_timeout(timeo);
			sdp_dbg(sk, "%s schedule_timeout done\n", __func__);
		}
		sdp_dbg(sk, "%s lock_sock\n", __func__);
		lock_sock(sk);
		sdp_dbg(sk, "%s lock_sock done\n", __func__);
		err = 0;
		if (!list_empty(&ssk->accept_queue))
			break;
		err = -EINVAL;
		if (sk->sk_state != TCP_LISTEN)
			break;
		err = sock_intr_errno(timeo);
		if (signal_pending(current))
			break;
		err = -EAGAIN;
		if (!timeo)
			break;
	}
	finish_wait(sk->sk_sleep, &wait);
	sdp_dbg(sk, "%s returns %d\n", __func__, err);
	return err;
}

/* Consider using request_sock_queue instead of duplicating all this */
/* Like inet_csk_accept */
static struct sock *sdp_accept(struct sock *sk, int flags, int *err)
{
	struct sdp_sock *newssk, *ssk;
	struct sock *newsk;
	int error;

	sdp_dbg(sk, "%s state %d expected %d *err %d\n", __func__,
		sk->sk_state, TCP_LISTEN, *err);

	ssk = sdp_sk(sk);
	lock_sock(sk);

	/* We need to make sure that this socket is listening,
	 * and that it has something pending.
	 */
	error = -EINVAL;
	if (sk->sk_state != TCP_LISTEN)
		goto out_err;

	/* Find already established connection */
	if (list_empty(&ssk->accept_queue)) {
		long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

		/* If this is a non blocking socket don't sleep */
		error = -EAGAIN;
		if (!timeo)
			goto out_err;

		error = sdp_wait_for_connect(sk, timeo);
		if (error)
			goto out_err;
	}

	newssk = list_entry(ssk->accept_queue.next, struct sdp_sock, accept_queue);
	list_del_init(&newssk->accept_queue);
	newssk->parent = NULL;
	sk_acceptq_removed(sk);
	newsk = &newssk->isk.sk;
out:
	release_sock(sk);
	if (newsk) {
		lock_sock(newsk);
		if (newssk->cq) {
			sdp_dbg(newsk, "%s: ib_req_notify_cq\n", __func__);
			newssk->poll_cq = 1;
			ib_req_notify_cq(newssk->cq, IB_CQ_NEXT_COMP);
			sdp_poll_cq(newssk, newssk->cq);
		}
		release_sock(newsk);
	}
	sdp_dbg(sk, "%s: status %d sk %p newsk %p\n", __func__,
		*err, sk, newsk);
	return newsk;
out_err:
	sdp_dbg(sk, "%s: error %d\n", __func__, error);
	newsk = NULL;
	*err = error;
	goto out;
}

/* Like tcp_ioctl */
static int sdp_ioctl(struct sock *sk, int cmd, unsigned long arg)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	int answ;

	sdp_dbg(sk, "%s\n", __func__);

	switch (cmd) {
	case SIOCINQ:
		if (sk->sk_state == TCP_LISTEN)
			return -EINVAL;

		lock_sock(sk);
		if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))
			answ = 0;
		else if (sock_flag(sk, SOCK_URGINLINE) ||
			 !ssk->urg_data ||
			 before(ssk->urg_seq, ssk->copied_seq) ||
			 !before(ssk->urg_seq, ssk->rcv_nxt)) {
			answ = ssk->rcv_nxt - ssk->copied_seq;

			/* Subtract 1, if FIN is in queue. */
			if (answ && !skb_queue_empty(&sk->sk_receive_queue))
				answ -=
			(skb_transport_header(sk->sk_receive_queue.prev))[0]
		        == SDP_MID_DISCONN ? 1 : 0;
		} else
			answ = ssk->urg_seq - ssk->copied_seq;
		release_sock(sk);
		break;
	case SIOCATMARK:
		answ = ssk->urg_data && ssk->urg_seq == ssk->copied_seq;
		break;
	case SIOCOUTQ:
		if (sk->sk_state == TCP_LISTEN)
			return -EINVAL;

		if ((1 << sk->sk_state) & (TCPF_SYN_SENT | TCPF_SYN_RECV))
			answ = 0;
		else
			answ = ssk->write_seq - ssk->snd_una;
		break;
	default:
		return -ENOIOCTLCMD;
	}
	/* TODO: Need to handle:
	   case SIOCOUTQ:
	 */
	return put_user(answ, (int __user *)arg); 
}

void sdp_cancel_dreq_wait_timeout(struct sdp_sock *ssk)
{
	if (!ssk->dreq_wait_timeout)
		return;

	sdp_dbg(&ssk->isk.sk, "cancelling dreq wait timeout #####\n");

	ssk->dreq_wait_timeout = 0;
	if (cancel_delayed_work(&ssk->dreq_wait_work)) {
		/* The timeout hasn't reached - need to clean ref count */
		sock_put(&ssk->isk.sk, SOCK_REF_DREQ_TO);
	}
	atomic_dec(ssk->isk.sk.sk_prot->orphan_count);
}

void sdp_destroy_work(struct work_struct *work)
{
	struct sdp_sock *ssk = container_of(work, struct sdp_sock, destroy_work);
	struct sock *sk = &ssk->isk.sk;
	sdp_dbg(sk, "%s: refcnt %d\n", __func__, atomic_read(&sk->sk_refcnt));

	sdp_cancel_dreq_wait_timeout(ssk);

	if (sk->sk_state == TCP_TIME_WAIT)
		sock_put(sk, SOCK_REF_CM_TW);

	/* In normal close current state is TCP_TIME_WAIT or TCP_CLOSE
	   but if a CM connection is dropped below our legs state could
	   be any state */
	sdp_exch_state(sk, ~0, TCP_CLOSE);
	sock_put(sk, SOCK_REF_RESET);
}

void sdp_dreq_wait_timeout_work(struct work_struct *work)
{
	struct sdp_sock *ssk =
		container_of(work, struct sdp_sock, dreq_wait_work.work);
	struct sock *sk = &ssk->isk.sk;

	lock_sock(sk);

	if (!sdp_sk(sk)->dreq_wait_timeout ||
	    !((1 << sk->sk_state) & (TCPF_FIN_WAIT1 | TCPF_LAST_ACK))) {
		release_sock(sk);
		goto out;
	}

	sdp_warn(sk, "timed out waiting for FIN/DREQ. "
		 "going into abortive close.\n");

	sdp_sk(sk)->dreq_wait_timeout = 0;

	if (sk->sk_state == TCP_FIN_WAIT1)
		atomic_dec(ssk->isk.sk.sk_prot->orphan_count);

	sdp_exch_state(sk, TCPF_LAST_ACK | TCPF_FIN_WAIT1, TCP_TIME_WAIT);

	release_sock(sk);

	if (sdp_sk(sk)->id)
		rdma_disconnect(sdp_sk(sk)->id);

out:
	sock_put(sk, SOCK_REF_DREQ_TO);
}

static int sdp_init_sock(struct sock *sk)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	struct inet_sock *isk = (struct inet_sock *)sk;

	sdp_dbg(sk, "%s\n", __func__);

	memset(isk + 1, 0, sizeof(struct sdp_sock) - sizeof(*isk));

	INIT_LIST_HEAD(&ssk->accept_queue);
	INIT_LIST_HEAD(&ssk->backlog_queue);
	INIT_DELAYED_WORK(&ssk->dreq_wait_work, sdp_dreq_wait_timeout_work);
	INIT_WORK(&ssk->destroy_work, sdp_destroy_work);

	sk->sk_route_caps |= NETIF_F_SG | NETIF_F_NO_CSUM;

	ssk->sdp_disconnect = 0;
	ssk->destructed_already = 0;
	spin_lock_init(&ssk->lock);

	return 0;
}

static void sdp_shutdown(struct sock *sk, int how)
{
	struct sdp_sock *ssk = sdp_sk(sk);

	sdp_dbg(sk, "%s\n", __func__);
	if (!(how & SEND_SHUTDOWN))
		return;

	/* If we've already sent a FIN, or it's a closed state, skip this. */
	if (!((1 << sk->sk_state) &
	    (TCPF_ESTABLISHED | TCPF_SYN_SENT |
	     TCPF_SYN_RECV | TCPF_CLOSE_WAIT))) {
		return;
	}

	if (!sdp_close_state(sk))
	    return;

	/*
	 * Just turn off CORK here.
	 *   We could check for socket shutting down in main data path,
	 * but this costs no extra cycles there.
	 */
	ssk->nonagle &= ~TCP_NAGLE_CORK;
	if (ssk->nonagle & TCP_NAGLE_OFF)
		ssk->nonagle |= TCP_NAGLE_PUSH;

	sdp_send_disconnect(sk);
}

static void sdp_mark_push(struct sdp_sock *ssk, struct sk_buff *skb)
{
	TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_PSH;
	ssk->pushed_seq = ssk->write_seq;
	sdp_post_sends(ssk, 0);
}

static inline void sdp_push_pending_frames(struct sock *sk)
{
	struct sk_buff *skb = sk->sk_send_head;
	if (skb) {
		sdp_mark_push(sdp_sk(sk), skb);
		sdp_post_sends(sdp_sk(sk), 0);
	}
}

/* SOL_SOCKET level options are handled by sock_setsockopt */
static int sdp_setsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int optlen)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	int val;
	int err = 0;

	sdp_dbg(sk, "%s\n", __func__);
	if (optlen < sizeof(int))
		return -EINVAL;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	lock_sock(sk);

	/* SOCK_KEEPALIVE is really a SOL_SOCKET level option but there
	 * is a problem handling it at that level.  In order to start
	 * the keepalive timer on an SDP socket, we must call an SDP
	 * specific routine.  Since sock_setsockopt() can not be modifed
	 * to understand SDP, the application must pass that option
	 * through to us.  Since SO_KEEPALIVE and TCP_DEFER_ACCEPT both
	 * use the same optname, the level must not be SOL_TCP or SOL_SOCKET
	 */
	if (level == PF_INET_SDP && optname == SO_KEEPALIVE) {
		sdp_set_keepalive(sk, val);
		if (val)
			sock_set_flag(sk, SOCK_KEEPOPEN);
		else
			sock_reset_flag(sk, SOCK_KEEPOPEN);
		goto out;
	}

	if (level != SOL_TCP) {
		err = -ENOPROTOOPT;
		goto out;
	}

	switch (optname) {
	case TCP_NODELAY:
		if (val) {
			/* TCP_NODELAY is weaker than TCP_CORK, so that
			 * this option on corked socket is remembered, but
			 * it is not activated until cork is cleared.
			 *
			 * However, when TCP_NODELAY is set we make
			 * an explicit push, which overrides even TCP_CORK
			 * for currently queued segments.
			 */
			ssk->nonagle |= TCP_NAGLE_OFF|TCP_NAGLE_PUSH;
			sdp_push_pending_frames(sk);
		} else {
			ssk->nonagle &= ~TCP_NAGLE_OFF;
		}
		break;
	case TCP_CORK:
		/* When set indicates to always queue non-full frames.
		 * Later the user clears this option and we transmit
		 * any pending partial frames in the queue.  This is
		 * meant to be used alongside sendfile() to get properly
		 * filled frames when the user (for example) must write
		 * out headers with a write() call first and then use
		 * sendfile to send out the data parts.
		 *
		 * TCP_CORK can be set together with TCP_NODELAY and it is
		 * stronger than TCP_NODELAY.
		 */
		if (val) {
			ssk->nonagle |= TCP_NAGLE_CORK;
		} else {
			ssk->nonagle &= ~TCP_NAGLE_CORK;
			if (ssk->nonagle&TCP_NAGLE_OFF)
				ssk->nonagle |= TCP_NAGLE_PUSH;
			sdp_push_pending_frames(sk);
		}
		break;
	case TCP_KEEPIDLE:
		if (val < 1 || val > MAX_TCP_KEEPIDLE)
			err = -EINVAL;
		else {
			ssk->keepalive_time = val * HZ;

			if (sock_flag(sk, SOCK_KEEPOPEN) &&
			    !((1 << sk->sk_state) & (TCPF_CLOSE | TCPF_LISTEN)))
				sdp_reset_keepalive_timer(sk, ssk->keepalive_time);
		}
		break;
	case SDP_ZCOPY_THRESH:
		if (val < SDP_MIN_ZCOPY_THRESH || val > SDP_MAX_ZCOPY_THRESH)
			err = -EINVAL;
		else
			ssk->zcopy_thresh = val;
		break;
	default:
		err = -ENOPROTOOPT;
		break;
	}

out:
	release_sock(sk);
	return err;
}

/* SOL_SOCKET level options are handled by sock_getsockopt */
static int sdp_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *option)
{
	/* TODO */
	struct sdp_sock *ssk = sdp_sk(sk);
	int val, len;

	sdp_dbg(sk, "%s\n", __func__);

	if (level != SOL_TCP)
		return -EOPNOTSUPP;

	if (get_user(len, option))
		return -EFAULT;

	len = min_t(unsigned int, len, sizeof(int));

	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case TCP_NODELAY:
		val = !!(ssk->nonagle&TCP_NAGLE_OFF);
		break;
	case TCP_CORK:
		val = !!(ssk->nonagle&TCP_NAGLE_CORK);
		break;
	case TCP_KEEPIDLE:
		val = (ssk->keepalive_time ? : sdp_keepalive_time) / HZ;
		break;
	case SDP_ZCOPY_THRESH:
		val = ssk->zcopy_thresh ? ssk->zcopy_thresh : sdp_zcopy_thresh;
		break;
	default:
		return -ENOPROTOOPT;
	}

	if (put_user(len, option))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;
	return 0;
}

static inline int poll_recv_cq(struct sock *sk)
{
	int i;
	if (sdp_sk(sk)->cq) {
		for (i = 0; i < recv_poll; ++i)
			if (!sdp_poll_cq(sdp_sk(sk), sdp_sk(sk)->cq)) {
				++recv_poll_hit;
				return 0;
			}
		++recv_poll_miss;
	}
	return 1;
}

static inline void poll_send_cq(struct sock *sk)
{
	int i;
	if (sdp_sk(sk)->cq) {
		for (i = 0; i < send_poll; ++i)
			if (!sdp_poll_cq(sdp_sk(sk), sdp_sk(sk)->cq)) {
				++send_poll_hit;
				return;
			}
		++send_poll_miss;
	}
}

/* Like tcp_recv_urg */
/*
 *	Handle reading urgent data. BSD has very simple semantics for
 *	this, no blocking and very strange errors 8)
 */

static int sdp_recv_urg(struct sock *sk, long timeo,
			struct msghdr *msg, int len, int flags,
			int *addr_len)
{
	struct sdp_sock *ssk = sdp_sk(sk);

	poll_recv_cq(sk);

	/* No URG data to read. */
	if (sock_flag(sk, SOCK_URGINLINE) || !ssk->urg_data ||
	    ssk->urg_data == TCP_URG_READ)
		return -EINVAL;	/* Yes this is right ! */

	if (sk->sk_state == TCP_CLOSE && !sock_flag(sk, SOCK_DONE))
		return -ENOTCONN;

	if (ssk->urg_data & TCP_URG_VALID) {
		int err = 0;
		char c = ssk->urg_data;

		if (!(flags & MSG_PEEK))
			ssk->urg_data = TCP_URG_READ;

		/* Read urgent data. */
		msg->msg_flags |= MSG_OOB;

		if (len > 0) {
			if (!(flags & MSG_TRUNC))
				err = memcpy_toiovec(msg->msg_iov, &c, 1);
			len = 1;
		} else
			msg->msg_flags |= MSG_TRUNC;

		return err ? -EFAULT : len;
	}

	if (sk->sk_state == TCP_CLOSE || (sk->sk_shutdown & RCV_SHUTDOWN))
		return 0;

	/* Fixed the recv(..., MSG_OOB) behaviour.  BSD docs and
	 * the available implementations agree in this case:
	 * this call should never block, independent of the
	 * blocking state of the socket.
	 * Mike <pall@rz.uni-karlsruhe.de>
	 */
	return -EAGAIN;
}

static void sdp_rcv_space_adjust(struct sock *sk)
{
	sdp_post_recvs(sdp_sk(sk));
	sdp_post_sends(sdp_sk(sk), 0);
}

static unsigned int sdp_current_mss(struct sock *sk, int large_allowed)
{
	/* TODO */
	return PAGE_SIZE;
}

static int forced_push(struct sdp_sock *sk)
{
	/* TODO */
	return 0;
}

static inline int select_size(struct sock *sk, struct sdp_sock *ssk)
{
	return 0;
}

static inline void sdp_mark_urg(struct sock *sk, struct sdp_sock *ssk, int flags)
{
	if (unlikely(flags & MSG_OOB)) {
		struct sk_buff *skb = sk->sk_write_queue.prev;
		TCP_SKB_CB(skb)->flags |= TCPCB_FLAG_URG;
	}
}

static inline void sdp_push(struct sock *sk, struct sdp_sock *ssk, int flags,
			    int mss_now, int nonagle)
{
	if (sk->sk_send_head)
		sdp_mark_urg(sk, ssk, flags);
	sdp_post_sends(ssk, nonagle);
}

static inline void skb_entail(struct sock *sk, struct sdp_sock *ssk,
                              struct sk_buff *skb)
{
        skb_header_release(skb);
        __skb_queue_tail(&sk->sk_write_queue, skb);
	sk->sk_wmem_queued += skb->truesize;
        sk_mem_charge(sk, skb->truesize);
        if (!sk->sk_send_head)
                sk->sk_send_head = skb;
        if (ssk->nonagle & TCP_NAGLE_PUSH)
                ssk->nonagle &= ~TCP_NAGLE_PUSH;
}

static void sdp_push_one(struct sock *sk, unsigned int mss_now)
{
}

static inline struct bzcopy_state *sdp_bz_cleanup(struct bzcopy_state *bz)
{
	int i, max_retry;
	struct sdp_sock *ssk = (struct sdp_sock *)bz->ssk;

	/* Wait for in-flight sends; should be quick */
	if (bz->busy) {
		struct sock *sk = &ssk->isk.sk;

		for (max_retry = 0; max_retry < 10000; max_retry++) {
			poll_send_cq(sk);

			if (!bz->busy)
				break;
		}

		if (bz->busy)
			sdp_warn(sk, "Could not reap %d in-flight sends\n",
				 bz->busy);
	}

	if (bz->pages) {
		for (i = bz->cur_page; i < bz->page_cnt; i++)
			put_page(bz->pages[i]);

		kfree(bz->pages);
	}

	kfree(bz);

	return NULL;
}


static struct bzcopy_state *sdp_bz_setup(struct sdp_sock *ssk,
					 unsigned char __user *base,
					 int len,
					 int size_goal)
{
	struct bzcopy_state *bz;
	unsigned long addr;
	int done_pages;
	int thresh;

	thresh = ssk->zcopy_thresh ? : sdp_zcopy_thresh;
	if (thresh == 0 || len < thresh)
		return NULL;

	if (!can_do_mlock())
		return NULL;

	/*
	 *   Since we use the TCP segmentation fields of the skb to map user
	 * pages, we must make sure that everything we send in a single chunk
	 * fits into the frags array in the skb.
	 */
	size_goal = size_goal / PAGE_SIZE + 1;
	if (size_goal >= MAX_SKB_FRAGS)
		return NULL;

	bz = kzalloc(sizeof(*bz), GFP_KERNEL);
	if (!bz)
		return NULL;

	addr = (unsigned long)base;

	bz->u_base     = base;
	bz->u_len      = len;
	bz->left       = len;
	bz->cur_offset = addr & ~PAGE_MASK;
	bz->busy       = 0;
	bz->ssk        = ssk;
	bz->page_cnt   = PAGE_ALIGN(len + bz->cur_offset) >> PAGE_SHIFT;
	bz->pages      = kcalloc(bz->page_cnt, sizeof(struct page *), GFP_KERNEL);

	if (!bz->pages)
		goto out_1;

	down_write(&current->mm->mmap_sem);

	if (!capable(CAP_IPC_LOCK))
		goto out_2;

	addr &= PAGE_MASK;

	done_pages = get_user_pages(current, current->mm, addr, bz->page_cnt,
				    0, 0, bz->pages, NULL);
	if (unlikely(done_pages != bz->page_cnt)){
		bz->page_cnt = done_pages;
		goto out_2;
	}

	up_write(&current->mm->mmap_sem);

	return bz;

out_2:
	up_write(&current->mm->mmap_sem);
	kfree(bz->pages);
out_1:
	kfree(bz);

	return NULL;
}


#define TCP_PAGE(sk)	(sk->sk_sndmsg_page)
#define TCP_OFF(sk)	(sk->sk_sndmsg_off)
static inline int sdp_bcopy_get(struct sock *sk, struct sk_buff *skb,
				unsigned char __user *from, int copy)
{
	int err;
	struct sdp_sock *ssk = sdp_sk(sk);

	/* Where to copy to? */
	if (skb_tailroom(skb) > 0) {
		/* We have some space in skb head. Superb! */
		if (copy > skb_tailroom(skb))
			copy = skb_tailroom(skb);
		if ((err = skb_add_data(skb, from, copy)) != 0)
			return SDP_ERR_FAULT;
	} else {
		int merge = 0;
		int i = skb_shinfo(skb)->nr_frags;
		struct page *page = TCP_PAGE(sk);
		int off = TCP_OFF(sk);

		if (skb_can_coalesce(skb, i, page, off) &&
		    off != PAGE_SIZE) {
			/* We can extend the last page
			 * fragment. */
			merge = 1;
		} else if (i == ssk->send_frags ||
			   (!i &&
			   !(sk->sk_route_caps & NETIF_F_SG))) {
			/* Need to add new fragment and cannot
			 * do this because interface is non-SG,
			 * or because all the page slots are
			 * busy. */
			sdp_mark_push(ssk, skb);
			return SDP_NEW_SEG;
		} else if (page) {
			if (off == PAGE_SIZE) {
				put_page(page);
				TCP_PAGE(sk) = page = NULL;
				off = 0;
			}
		} else
			off = 0;

		if (copy > PAGE_SIZE - off)
			copy = PAGE_SIZE - off;

		if (!sk_wmem_schedule(sk, copy))
			return SDP_DO_WAIT_MEM;

		if (!page) {
			/* Allocate new cache page. */
			if (!(page = sk_stream_alloc_page(sk)))
				return SDP_DO_WAIT_MEM;
		}

		/* Time to copy data. We are close to
		 * the end! */
		err = skb_copy_to_page(sk, from, skb, page,
				       off, copy);
		if (err) {
			/* If this page was new, give it to the
			 * socket so it does not get leaked.
			 */
			if (!TCP_PAGE(sk)) {
				TCP_PAGE(sk) = page;
				TCP_OFF(sk) = 0;
			}
			return SDP_ERR_ERROR;
		}

		/* Update the skb. */
		if (merge) {
			skb_shinfo(skb)->frags[i - 1].size +=
							copy;
		} else {
			skb_fill_page_desc(skb, i, page, off, copy);
			if (TCP_PAGE(sk)) {
				get_page(page);
			} else if (off + copy < PAGE_SIZE) {
				get_page(page);
				TCP_PAGE(sk) = page;
			}
		}

		TCP_OFF(sk) = off + copy;
	}

	return copy;
}


static inline int sdp_bzcopy_get(struct sock *sk, struct sk_buff *skb,
				 unsigned char __user *from, int copy,
				 struct bzcopy_state *bz)
{
	int this_page, left;
	struct sdp_sock *ssk = sdp_sk(sk);

	/* Push the first chunk to page align all following - TODO: review */
	if (skb_shinfo(skb)->nr_frags == ssk->send_frags) {
		sdp_mark_push(ssk, skb);
		return SDP_NEW_SEG;
	}

	left = copy;
	BUG_ON(left > bz->left);

	while (left) {
		if (skb_shinfo(skb)->nr_frags == ssk->send_frags) {
			copy = copy - left;
			break;
		}

		this_page = PAGE_SIZE - bz->cur_offset;

		if (left <= this_page)
			this_page = left;

		if (!sk_wmem_schedule(sk, copy))
			return SDP_DO_WAIT_MEM;

		skb_fill_page_desc(skb, skb_shinfo(skb)->nr_frags,
				   bz->pages[bz->cur_page], bz->cur_offset,
				   this_page);

		BUG_ON(skb_shinfo(skb)->nr_frags >= MAX_SKB_FRAGS);

		bz->cur_offset += this_page;
		if (bz->cur_offset == PAGE_SIZE) {
			bz->cur_offset = 0;
			bz->cur_page++;

			BUG_ON(bz->cur_page > bz->page_cnt);
		} else {
			BUG_ON(bz->cur_offset > PAGE_SIZE);

			if (bz->cur_page != bz->page_cnt || left != this_page)
				get_page(bz->pages[bz->cur_page]);
		}

		left -= this_page;

		skb->len             += this_page;
		skb->data_len         = skb->len;
		skb->truesize        += this_page;
		sk->sk_wmem_queued   += this_page;
		sk->sk_forward_alloc -= this_page;
	}

	bz->left -= copy;
	bz->busy++;
	return copy;
}

static inline int slots_free(struct sdp_sock *ssk)
{
	int min_free;

	min_free = SDP_TX_SIZE - (ssk->tx_head - ssk->tx_tail);
	if (ssk->bufs < min_free)
		min_free = ssk->bufs;
	min_free -= (min_free < SDP_MIN_BUFS) ? min_free : SDP_MIN_BUFS;

	return min_free;
};

/* like sk_stream_memory_free - except measures remote credits */
static inline int sdp_bzcopy_slots_avail(struct sdp_sock *ssk,
					 struct bzcopy_state *bz)
{
	return slots_free(ssk) > bz->busy;
}

/* like sk_stream_wait_memory - except waits on remote credits */
static int sdp_bzcopy_wait_memory(struct sdp_sock *ssk, long *timeo_p,
				  struct bzcopy_state *bz)
{
	struct sock *sk = &ssk->isk.sk;
	int err = 0;
	long vm_wait = 0;
	long current_timeo = *timeo_p;
	DEFINE_WAIT(wait);

	BUG_ON(!bz);

	if (sdp_bzcopy_slots_avail(ssk, bz))
		current_timeo = vm_wait = (net_random() % (HZ / 5)) + 2;

	while (1) {
		set_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

		prepare_to_wait(sk->sk_sleep, &wait, TASK_INTERRUPTIBLE);

		if (unlikely(sk->sk_err | (sk->sk_shutdown & SEND_SHUTDOWN))) {
			err = -EPIPE;
			break;
		}

		if (unlikely(!*timeo_p)) {
			err = -EAGAIN;
			break;
		}

		if (unlikely(signal_pending(current))) {
			err = sock_intr_errno(*timeo_p);
			break;
		}

		clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

		if (sdp_bzcopy_slots_avail(ssk, bz))
			break;

		set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
		sk->sk_write_pending++;
		sk_wait_event(sk, &current_timeo,
			sdp_bzcopy_slots_avail(ssk, bz) && vm_wait);
		sk->sk_write_pending--;

		if (vm_wait) {
			vm_wait -= current_timeo;
			current_timeo = *timeo_p;
			if (current_timeo != MAX_SCHEDULE_TIMEOUT &&
			    (current_timeo -= vm_wait) < 0)
				current_timeo = 0;
			vm_wait = 0;
		}
		*timeo_p = current_timeo;
	}

	finish_wait(sk->sk_sleep, &wait);
	return err;
}

/* like sk_stream_write_space - execpt measures remote credits */
void sdp_bzcopy_write_space(struct sdp_sock *ssk)
{
	struct sock *sk = &ssk->isk.sk;
	struct socket *sock = sk->sk_socket;

	if (ssk->bufs >= ssk->min_bufs &&
	    ssk->tx_head == ssk->tx_tail &&
	   sock != NULL) {
		clear_bit(SOCK_NOSPACE, &sock->flags);

		if (sk->sk_sleep && waitqueue_active(sk->sk_sleep))
			wake_up_interruptible(sk->sk_sleep);
		if (sock->fasync_list && !(sk->sk_shutdown & SEND_SHUTDOWN))
			sock_wake_async(sock, 2, POLL_OUT);
	}
}


/* Like tcp_sendmsg */
/* TODO: check locking */
static int sdp_sendmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		size_t size)
{
	struct iovec *iov;
	struct sdp_sock *ssk = sdp_sk(sk);
	struct sk_buff *skb;
	int iovlen, flags;
	int mss_now, size_goal;
	int err, copied;
	long timeo;
	struct bzcopy_state *bz = NULL;

	lock_sock(sk);
	sdp_dbg_data(sk, "%s\n", __func__);

	flags = msg->msg_flags;
	timeo = sock_sndtimeo(sk, flags & MSG_DONTWAIT);

	/* Wait for a connection to finish. */
	if ((1 << sk->sk_state) & ~(TCPF_ESTABLISHED | TCPF_CLOSE_WAIT))
		if ((err = sk_stream_wait_connect(sk, &timeo)) != 0)
			goto out_err;

	/* This should be in poll */
	clear_bit(SOCK_ASYNC_NOSPACE, &sk->sk_socket->flags);

	mss_now = sdp_current_mss(sk, !(flags&MSG_OOB));
	size_goal = ssk->xmit_size_goal;

	/* Ok commence sending. */
	iovlen = msg->msg_iovlen;
	iov = msg->msg_iov;
	copied = 0;

	err = -EPIPE;
	if (sk->sk_err || (sk->sk_shutdown & SEND_SHUTDOWN))
		goto do_error;

	while (--iovlen >= 0) {
		int seglen = iov->iov_len;
		unsigned char __user *from = iov->iov_base;

		iov++;

		/* Limmiting the size_goal is reqired when using 64K pages*/
		if (size_goal > SDP_MAX_PAYLOAD)
			size_goal = SDP_MAX_PAYLOAD;

		bz = sdp_bz_setup(ssk, from, seglen, size_goal);

		while (seglen > 0) {
			int copy;

			skb = sk->sk_write_queue.prev;

			if (!sk->sk_send_head ||
			    (copy = size_goal - skb->len) <= 0 ||
			    bz != *(struct bzcopy_state **)skb->cb) {

new_segment:
				/*
				 * Allocate a new segment
				 *   For bcopy, we stop sending once we have
				 * SO_SENDBUF bytes in flight.  For bzcopy
				 * we stop sending once we run out of remote
				 * receive credits.
				 */
				if (bz) {
					if (!sdp_bzcopy_slots_avail(ssk, bz))
						goto wait_for_sndbuf;
				} else {
					if (!sk_stream_memory_free(sk))
						goto wait_for_sndbuf;
				}

				skb = sdp_stream_alloc_skb(sk, select_size(sk, ssk),
							   sk->sk_allocation);
				if (!skb)
					goto wait_for_memory;

				*((struct bzcopy_state **)skb->cb) = bz;

				/*
				 * Check whether we can use HW checksum.
				 */
				if (sk->sk_route_caps &
				    (NETIF_F_IP_CSUM | NETIF_F_NO_CSUM |
				     NETIF_F_HW_CSUM))
					skb->ip_summed = CHECKSUM_PARTIAL;

				skb_entail(sk, ssk, skb);
				copy = size_goal;
			}

			/* Try to append data to the end of skb. */
			if (copy > seglen)
				copy = seglen;

			/* OOB data byte should be the last byte of
			   the data payload */
			if (unlikely(TCP_SKB_CB(skb)->flags & TCPCB_FLAG_URG) &&
			    !(flags & MSG_OOB)) {
				sdp_mark_push(ssk, skb);
				goto new_segment;
			}

			copy = (bz) ? sdp_bzcopy_get(sk, skb, from, copy, bz) :
				      sdp_bcopy_get(sk, skb, from, copy);
			if (unlikely(copy < 0)) {
				if (!++copy)
					goto wait_for_memory;
				if (!++copy)
					goto new_segment;
				if (!++copy)
					goto do_fault;
				goto do_error;
			}

			if (!copied)
				TCP_SKB_CB(skb)->flags &= ~TCPCB_FLAG_PSH;

			ssk->write_seq += copy;
			TCP_SKB_CB(skb)->end_seq += copy;
			/*unused: skb_shinfo(skb)->gso_segs = 0;*/

			from += copy;
			copied += copy;
			if ((seglen -= copy) == 0 && iovlen == 0)
				goto out;

			if (skb->len < mss_now || (flags & MSG_OOB))
				continue;

			if (forced_push(ssk)) {
				sdp_mark_push(ssk, skb);
				/* TODO: and push pending frames mss_now */
				/* sdp_push_pending(sk, ssk, mss_now, TCP_NAGLE_PUSH); */
			} else if (skb == sk->sk_send_head)
				sdp_push_one(sk, mss_now);
			continue;

wait_for_sndbuf:
			set_bit(SOCK_NOSPACE, &sk->sk_socket->flags);
wait_for_memory:
			if (copied)
				sdp_push(sk, ssk, flags & ~MSG_MORE, mss_now, TCP_NAGLE_PUSH);

			err = (bz) ? sdp_bzcopy_wait_memory(ssk, &timeo, bz) :
				     sk_stream_wait_memory(sk, &timeo);
			if (err)
				goto do_error;

			mss_now = sdp_current_mss(sk, !(flags&MSG_OOB));
			size_goal = ssk->xmit_size_goal;
		}
	}

out:
	if (copied) {
		sdp_push(sk, ssk, flags, mss_now, ssk->nonagle);

		if (bz)
			bz = sdp_bz_cleanup(bz);
		else
			if (size > send_poll_thresh)
				poll_send_cq(sk);
	}

	release_sock(sk);
	return copied;

do_fault:
	if (!skb->len) {
		if (sk->sk_send_head == skb)
			sk->sk_send_head = NULL;
		__skb_unlink(skb, &sk->sk_write_queue);
		sk_wmem_free_skb(sk, skb);
	}

do_error:
	if (copied)
		goto out;
out_err:
	if (bz)
		bz = sdp_bz_cleanup(bz);
	err = sk_stream_error(sk, flags, err);
	release_sock(sk);
	return err;
}

/* Like tcp_recvmsg */
/* Maybe use skb_recv_datagram here? */
/* Note this does not seem to handle vectored messages. Relevant? */
static int sdp_recvmsg(struct kiocb *iocb, struct sock *sk, struct msghdr *msg,
		       size_t len, int noblock, int flags, 
		       int *addr_len)
{
	struct sk_buff *skb = NULL;
	struct sdp_sock *ssk = sdp_sk(sk);
	long timeo;
	int target;
	unsigned long used;
	int err;
	u32 peek_seq;
	u32 *seq;
	int copied = 0;
	int rc;

	lock_sock(sk);
	sdp_dbg_data(sk, "%s\n", __func__);

	err = -ENOTCONN;
	if (sk->sk_state == TCP_LISTEN)
		goto out;

	timeo = sock_rcvtimeo(sk, noblock);
	/* Urgent data needs to be handled specially. */
	if (flags & MSG_OOB)
		goto recv_urg;

	seq = &ssk->copied_seq;
	if (flags & MSG_PEEK) {
		peek_seq = ssk->copied_seq;
		seq = &peek_seq;
	}

	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);

	do {
		u32 offset;

		/* Are we at urgent data? Stop if we have read anything or have SIGURG pending. */
		if (ssk->urg_data && ssk->urg_seq == *seq) {
			if (copied)
				break;
			if (signal_pending(current)) {
				copied = timeo ? sock_intr_errno(timeo) : -EAGAIN;
				break;
			}
		}

		skb = skb_peek(&sk->sk_receive_queue);
		do {
			if (!skb)
				break;

			if ((skb_transport_header(skb))[0] == SDP_MID_DISCONN)
				goto found_fin_ok;

			if (before(*seq, TCP_SKB_CB(skb)->seq)) {
				printk(KERN_INFO "recvmsg bug: copied %X "
				       "seq %X\n", *seq, TCP_SKB_CB(skb)->seq);
				break;
			}

			offset = *seq - TCP_SKB_CB(skb)->seq;
			if (offset < skb->len)
				goto found_ok_skb;

			WARN_ON(!(flags & MSG_PEEK));
			skb = skb->next;
		} while (skb != (struct sk_buff *)&sk->sk_receive_queue);

		if (copied >= target)
			break;

		if (copied) {
			if (sk->sk_err ||
			    sk->sk_state == TCP_CLOSE ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
			    !timeo ||
			    signal_pending(current) ||
			    (flags & MSG_PEEK))
				break;
		} else {
			if (sock_flag(sk, SOCK_DONE))
				break;

			if (sk->sk_err) {
				copied = sock_error(sk);
				break;
			}

			if (sk->sk_shutdown & RCV_SHUTDOWN)
				break;

			if (sk->sk_state == TCP_CLOSE) {
				if (!sock_flag(sk, SOCK_DONE)) {
					/* This occurs when user tries to read
					 * from never connected socket.
					 */
					copied = -ENOTCONN;
					break;
				}
				break;
			}

			if (!timeo) {
				copied = -EAGAIN;
				break;
			}

			if (signal_pending(current)) {
				copied = sock_intr_errno(timeo);
				break;
			}
		}

		rc = poll_recv_cq(sk);

		if (copied >= target && !recv_poll) {
			/* Do not sleep, just process backlog. */
			release_sock(sk);
			lock_sock(sk);
		} else if (rc) {
			sdp_dbg_data(sk, "%s: sk_wait_data %ld\n", __func__, timeo);
			sk_wait_data(sk, &timeo);
		}
		continue;

	found_ok_skb:
		sdp_dbg_data(sk, "%s: found_ok_skb len %d\n", __func__, skb->len);
		sdp_dbg_data(sk, "%s: len %Zd offset %d\n", __func__, len, offset);
		sdp_dbg_data(sk, "%s: copied %d target %d\n", __func__, copied, target);
		used = skb->len - offset;
		if (len < used)
			used = len;

		sdp_dbg_data(sk, "%s: used %ld\n", __func__, used);

		if (ssk->urg_data) {
			u32 urg_offset = ssk->urg_seq - *seq;
			if (urg_offset < used) {
				if (!urg_offset) {
					if (!sock_flag(sk, SOCK_URGINLINE)) {
						++*seq;
						offset++;
						used--;
						if (!used)
							goto skip_copy;
					}
				} else
					used = urg_offset;
			}
		}
		if (!(flags & MSG_TRUNC)) {
			err = skb_copy_datagram_iovec(skb, offset,
						      /* TODO: skip header? */
						      msg->msg_iov, used);
			if (err) {
				sdp_dbg(sk, "%s: skb_copy_datagram_iovec failed"
					"offset %d size %ld status %d\n",
					__func__, offset, used, err);
				/* Exception. Bailout! */
				if (!copied)
					copied = -EFAULT;
				break;
			}
		}

		copied += used;
		len -= used;
		*seq += used;

		sdp_dbg_data(sk, "%s: done copied %d target %d\n", __func__, copied, target);

		sdp_rcv_space_adjust(sk);
skip_copy:
		if (ssk->urg_data && after(ssk->copied_seq, ssk->urg_seq))
			ssk->urg_data = 0;
		if (used + offset < skb->len)
			continue;
		offset = 0;

		if (!(flags & MSG_PEEK))
			sk_eat_skb(sk, skb, 0);

		continue;
found_fin_ok:
		++*seq;
		if (!(flags & MSG_PEEK))
			sk_eat_skb(sk, skb, 0);

		break;
	} while (len > 0);

	release_sock(sk);
	return copied;

out:
	release_sock(sk);
	return err;

recv_urg:
	err = sdp_recv_urg(sk, timeo, msg, len, flags, addr_len);
	goto out;
}

static int sdp_listen(struct sock *sk, int backlog)
{
	struct sdp_sock *ssk = sdp_sk(sk);
	int rc;

	sdp_dbg(sk, "%s\n", __func__);

	if (!ssk->id) {
		rc = sdp_get_port(sk, 0);
		if (rc)
			return rc;
		inet_sk(sk)->sport = htons(inet_sk(sk)->num);
	}

	rc = rdma_listen(ssk->id, backlog);
	if (rc) {
		sdp_warn(sk, "rdma_listen failed: %d\n", rc);
		sdp_set_error(sk, rc);
	} else
		sdp_exch_state(sk, TCPF_CLOSE, TCP_LISTEN);
	return rc;
}

/* We almost could use inet_listen, but that calls
   inet_csk_listen_start. Longer term we'll want to add
   a listen callback to struct proto, similiar to bind. */
static int sdp_inet_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	unsigned char old_state;
	int err;

	lock_sock(sk);

	err = -EINVAL;
	if (sock->state != SS_UNCONNECTED)
		goto out;

	old_state = sk->sk_state;
	if (!((1 << old_state) & (TCPF_CLOSE | TCPF_LISTEN)))
		goto out;

	/* Really, if the socket is already in listen state
	 * we can only allow the backlog to be adjusted.
	 */
	if (old_state != TCP_LISTEN) {
		err = sdp_listen(sk, backlog);
		if (err)
			goto out;
	}
	sk->sk_max_ack_backlog = backlog;
	err = 0;

out:
	release_sock(sk);
	return err;
}

static void sdp_unhash(struct sock *sk)
{
        sdp_dbg(sk, "%s\n", __func__);
}

static inline unsigned int sdp_listen_poll(const struct sock *sk)
{
	        return !list_empty(&sdp_sk(sk)->accept_queue) ?
			(POLLIN | POLLRDNORM) : 0;
}

static unsigned int sdp_poll(struct file *file, struct socket *socket,
			     struct poll_table_struct *wait)
{
       unsigned int     mask;
       struct sock     *sk  = socket->sk;
       struct sdp_sock *ssk = sdp_sk(sk);

	sdp_dbg_data(socket->sk, "%s\n", __func__);

	mask = datagram_poll(file, socket, wait);

       /*
        * Adjust for memory in later kernels
        */
       if (!sk_stream_memory_free(sk) || !slots_free(ssk))
               mask &= ~(POLLOUT | POLLWRNORM | POLLWRBAND);

	/* TODO: Slightly ugly: it would be nicer if there was function
	 * like datagram_poll that didn't include poll_wait,
	 * then we could reverse the order. */
       if (sk->sk_state == TCP_LISTEN)
               return sdp_listen_poll(sk);

       if (ssk->urg_data & TCP_URG_VALID)
		mask |= POLLPRI;
	return mask;
}

static void sdp_enter_memory_pressure(struct sock *sk)
{
	sdp_dbg(sk, "%s\n", __func__);
}

void sdp_urg(struct sdp_sock *ssk, struct sk_buff *skb)
{
	struct sock *sk = &ssk->isk.sk;
	u8 tmp;
	u32 ptr = skb->len - 1;

	ssk->urg_seq = TCP_SKB_CB(skb)->seq + ptr;

	if (skb_copy_bits(skb, ptr, &tmp, 1))
		BUG();
	ssk->urg_data = TCP_URG_VALID | tmp;
	if (!sock_flag(sk, SOCK_DEAD))
		sk->sk_data_ready(sk, 0);
}

static atomic_t sockets_allocated;
static atomic_t memory_allocated;
static atomic_t orphan_count;
static int memory_pressure;
struct proto sdp_proto = {
        .close       = sdp_close,
        .connect     = sdp_connect,
        .disconnect  = sdp_disconnect,
        .accept      = sdp_accept,
        .ioctl       = sdp_ioctl,
        .init        = sdp_init_sock,
        .shutdown    = sdp_shutdown,
        .setsockopt  = sdp_setsockopt,
        .getsockopt  = sdp_getsockopt,
        .sendmsg     = sdp_sendmsg,
        .recvmsg     = sdp_recvmsg,
	.unhash      = sdp_unhash,
        .get_port    = sdp_get_port,
	/* Wish we had this: .listen   = sdp_listen */
	.enter_memory_pressure = sdp_enter_memory_pressure,
	.sockets_allocated = &sockets_allocated,
	.memory_allocated = &memory_allocated,
	.memory_pressure = &memory_pressure,
	.orphan_count = &orphan_count,
        .sysctl_mem             = sysctl_tcp_mem,
        .sysctl_wmem            = sysctl_tcp_wmem,
        .sysctl_rmem            = sysctl_tcp_rmem,
	.max_header  = sizeof(struct sdp_bsdh),
        .obj_size    = sizeof(struct sdp_sock),
	.owner	     = THIS_MODULE,
	.name	     = "SDP",
};

static struct proto_ops sdp_proto_ops = {
	.family     = PF_INET,
	.owner      = THIS_MODULE,
	.release    = inet_release,
	.bind       = inet_bind,
	.connect    = inet_stream_connect, /* TODO: inet_datagram connect would
					      autobind, but need to fix get_port
					      with port 0 first. */
	.socketpair = sock_no_socketpair,
	.accept     = inet_accept,
	.getname    = inet_getname,
	.poll       = sdp_poll,
	.ioctl      = inet_ioctl,
	.listen     = sdp_inet_listen,
	.shutdown   = inet_shutdown,
	.setsockopt = sock_common_setsockopt,
	.getsockopt = sock_common_getsockopt,
	.sendmsg    = inet_sendmsg,
	.recvmsg    = sock_common_recvmsg,
	.mmap       = sock_no_mmap,
	.sendpage   = sock_no_sendpage,
};

static int sdp_create_socket(struct net *net, struct socket *sock, int protocol)
{
	struct sock *sk;
	int rc;

	sdp_dbg(NULL, "%s: type %d protocol %d\n", __func__, sock->type, protocol);

	if (net != &init_net)
		return -EAFNOSUPPORT;

	if (sock->type != SOCK_STREAM) {
		sdp_warn(NULL, "SDP: unsupported type %d.\n", sock->type);
		return -ESOCKTNOSUPPORT;
	}

	/* IPPROTO_IP is a wildcard match */
	if (protocol != IPPROTO_TCP && protocol != IPPROTO_IP) {
		sdp_warn(NULL, "SDP: unsupported protocol %d.\n", protocol);
		return -EPROTONOSUPPORT;
	}

	sk = sk_alloc(net, PF_INET_SDP, GFP_KERNEL, &sdp_proto);
	if (!sk) {
		sdp_warn(NULL, "SDP: failed to allocate socket.\n");
		return -ENOMEM;
	}
	sock_init_data(sock, sk);
	sk->sk_protocol = 0x0 /* TODO: inherit tcp socket to use IPPROTO_TCP */;

	rc = sdp_init_sock(sk);
	if (rc) {
		sdp_warn(sk, "SDP: failed to init sock.\n");
		sk_common_release(sk);
		return -ENOMEM;
	}

	sk->sk_destruct = sdp_destruct;

	sdp_init_timer(sk);

	sock->ops = &sdp_proto_ops;
	sock->state = SS_UNCONNECTED;

	sdp_add_sock(sdp_sk(sk));

	return 0;
}

#ifdef CONFIG_PROC_FS

static void *sdp_get_idx(struct seq_file *seq, loff_t pos)
{
	int i = 0;
	struct sdp_sock *ssk;

	if (!list_empty(&sock_list))
		list_for_each_entry(ssk, &sock_list, sock_list) {
			if (i == pos)
				return ssk;
			i++;
		}

	return NULL;
}

static void *sdp_seq_start(struct seq_file *seq, loff_t *pos)
{
	void *start = NULL;
	struct sdp_iter_state* st = seq->private;

	st->num = 0;

	if (!*pos)
		return SEQ_START_TOKEN;

	spin_lock_irq(&sock_list_lock);
	start = sdp_get_idx(seq, *pos - 1);
	if (start)
		sock_hold((struct sock *)start, SOCK_REF_SEQ);
	spin_unlock_irq(&sock_list_lock);

	return start;
}

static void *sdp_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct sdp_iter_state* st = seq->private;
	void *next = NULL;

	spin_lock_irq(&sock_list_lock);
	if (v == SEQ_START_TOKEN)
		next = sdp_get_idx(seq, 0);
	else
		next = sdp_get_idx(seq, *pos);
	if (next)
		sock_hold((struct sock *)next, SOCK_REF_SEQ);
	spin_unlock_irq(&sock_list_lock);

	*pos += 1;
	st->num++;

	return next;
}

static void sdp_seq_stop(struct seq_file *seq, void *v)
{
}

#define TMPSZ 150

static int sdp_seq_show(struct seq_file *seq, void *v)
{
	struct sdp_iter_state* st;
	struct sock *sk = v;
	char tmpbuf[TMPSZ + 1];
	unsigned int dest;
	unsigned int src;
	int uid;
	unsigned long inode;
	__u16 destp;
	__u16 srcp;
	__u32 rx_queue, tx_queue;

	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "%-*s\n", TMPSZ - 1,
				"  sl  local_address rem_address        uid inode"
				"   rx_queue tx_queue state");
		goto out;
	}

	st = seq->private;

	dest = inet_sk(sk)->daddr;
	src = inet_sk(sk)->rcv_saddr;
	destp = ntohs(inet_sk(sk)->dport);
	srcp = ntohs(inet_sk(sk)->sport);
	uid = sock_i_uid(sk);
	inode = sock_i_ino(sk);
	rx_queue = sdp_sk(sk)->rcv_nxt - sdp_sk(sk)->copied_seq;
	tx_queue = sdp_sk(sk)->write_seq - sdp_sk(sk)->snd_una;

	sprintf(tmpbuf, "%4d: %08X:%04X %08X:%04X %5d %lu	%08X:%08X %X",
		st->num, src, srcp, dest, destp, uid, inode,
		rx_queue, tx_queue, sk->sk_state);

	seq_printf(seq, "%-*s\n", TMPSZ - 1, tmpbuf);

	sock_put(sk, SOCK_REF_SEQ);
out:
	return 0;
}

static int sdp_seq_open(struct inode *inode, struct file *file)
{
	struct sdp_seq_afinfo *afinfo = PDE(inode)->data;
	struct seq_file *seq;
	struct sdp_iter_state *s;
	int rc;

	if (unlikely(afinfo == NULL))
		return -EINVAL;

	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	s->family               = afinfo->family;
	s->seq_ops.start        = sdp_seq_start;
	s->seq_ops.next         = sdp_seq_next;
	s->seq_ops.show         = afinfo->seq_show;
	s->seq_ops.stop         = sdp_seq_stop;

	rc = seq_open(file, &s->seq_ops);
	if (rc)
		goto out_kfree;
	seq          = file->private_data;
	seq->private = s;
out:
	return rc;
out_kfree:
	kfree(s);
	goto out;
}


static struct file_operations sdp_seq_fops;
static struct sdp_seq_afinfo sdp_seq_afinfo = {
	.owner          = THIS_MODULE,
	.name           = "sdp",
	.family         = AF_INET_SDP,
	.seq_show       = sdp_seq_show,
	.seq_fops       = &sdp_seq_fops,
};


static int __init sdp_proc_init(void)
{
	int rc = 0;
	struct proc_dir_entry *p;

	sdp_seq_afinfo.seq_fops->owner         = sdp_seq_afinfo.owner;
	sdp_seq_afinfo.seq_fops->open          = sdp_seq_open;
	sdp_seq_afinfo.seq_fops->read          = seq_read;
	sdp_seq_afinfo.seq_fops->llseek        = seq_lseek;
	sdp_seq_afinfo.seq_fops->release       = seq_release_private;

	p = proc_net_fops_create(&init_net, sdp_seq_afinfo.name, S_IRUGO,
				 sdp_seq_afinfo.seq_fops);
	if (p)
		p->data = &sdp_seq_afinfo;
	else
		rc = -ENOMEM;

	return rc;
}

static void sdp_proc_unregister(void)
{
	proc_net_remove(&init_net, sdp_seq_afinfo.name);
	memset(sdp_seq_afinfo.seq_fops, 0, sizeof(*sdp_seq_afinfo.seq_fops));
}

#else /* CONFIG_PROC_FS */

static int __init sdp_proc_init(void)
{
	return 0;
}

static void sdp_proc_unregister(void)
{

}
#endif /* CONFIG_PROC_FS */

static void sdp_add_device(struct ib_device *device)
{
}

static void sdp_remove_device(struct ib_device *device)
{
	struct list_head  *p;
	struct sdp_sock   *ssk;
	struct sock       *sk;
	struct rdma_cm_id *id;

do_next:
	write_lock(&device_removal_lock);

	spin_lock_irq(&sock_list_lock);
	list_for_each(p, &sock_list) {
		ssk = list_entry(p, struct sdp_sock, sock_list);
		if (ssk->ib_device == device) {
			sk = &ssk->isk.sk;
			id = ssk->id;

			if (id) {
				ssk->id = NULL;

				spin_unlock_irq(&sock_list_lock);
				write_unlock(&device_removal_lock);
				rdma_destroy_id(id);

				goto do_next;
			}
		}
	}

	list_for_each(p, &sock_list) {
		ssk = list_entry(p, struct sdp_sock, sock_list);
		if (ssk->ib_device == device) {
			sk = &ssk->isk.sk;

			sk->sk_shutdown |= RCV_SHUTDOWN;
			sdp_reset(sk);
		}
	}

	spin_unlock_irq(&sock_list_lock);

	write_unlock(&device_removal_lock);
}

static struct net_proto_family sdp_net_proto = {
	.family = AF_INET_SDP,
	.create = sdp_create_socket,
	.owner  = THIS_MODULE,
};

static struct ib_client sdp_client = {
	.name   = "sdp",
	.add    = sdp_add_device,
	.remove = sdp_remove_device
};

static int __init sdp_init(void)
{
	int rc;

	INIT_LIST_HEAD(&sock_list);
	spin_lock_init(&sock_list_lock);
	spin_lock_init(&sdp_large_sockets_lock);

	sdp_workqueue = create_singlethread_workqueue("sdp");
	if (!sdp_workqueue) {
		return -ENOMEM;
	}

	rc = proto_register(&sdp_proto, 1);
	if (rc) {
		printk(KERN_WARNING "%s: proto_register failed: %d\n", __func__, rc);
		destroy_workqueue(sdp_workqueue);
		return rc;
	}

	rc = sock_register(&sdp_net_proto);
	if (rc) {
		printk(KERN_WARNING "%s: sock_register failed: %d\n", __func__, rc);
		proto_unregister(&sdp_proto);
		destroy_workqueue(sdp_workqueue);
		return rc;
	}

	sdp_proc_init();

	atomic_set(&sdp_current_mem_usage, 0);

	ib_register_client(&sdp_client);

	return 0;
}

static void __exit sdp_exit(void)
{
	sock_unregister(PF_INET_SDP);
	proto_unregister(&sdp_proto);

	if (atomic_read(&orphan_count))
		printk(KERN_WARNING "%s: orphan_count %d\n", __func__,
		       atomic_read(&orphan_count));
	destroy_workqueue(sdp_workqueue);
	flush_scheduled_work();

	BUG_ON(!list_empty(&sock_list));

	if (atomic_read(&sdp_current_mem_usage))
		printk(KERN_WARNING "%s: current mem usage %d\n", __func__,
		       atomic_read(&sdp_current_mem_usage));

	sdp_proc_unregister();

	ib_unregister_client(&sdp_client);
}

module_init(sdp_init);
module_exit(sdp_exit);
