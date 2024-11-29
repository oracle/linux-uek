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
#include <linux/in.h>
#include <net/tcp.h>

#include "trace.h"

#include "rds.h"
#include "tcp.h"

void rds_tcp_state_change(struct sock *sk)
{
	void (*state_change)(struct sock *sk);
	struct rds_conn_path *cp;
	struct rds_tcp_connection *tc;

	read_lock(&sk->sk_callback_lock);
	cp = sk->sk_user_data;
	if (!cp) {
		state_change = sk->sk_state_change;
		goto out;
	}
	tc = cp->cp_transport_data;
	state_change = tc->t_orig_state_change;

	trace_rds_tcp_state_change(cp->cp_conn, cp, tc, sk, "state change", 0);

	switch (sk->sk_state) {
	/* ignore connecting sockets as they make progress */
	case TCP_SYN_SENT:
	case TCP_SYN_RECV:
		break;
	case TCP_ESTABLISHED:
		if (rds_addr_cmp(&cp->cp_conn->c_laddr,
				 &cp->cp_conn->c_faddr) >= 0 &&
		    rds_conn_path_transition(cp, RDS_CONN_CONNECTING,
					     RDS_CONN_ERROR,
					     DR_TCP_STATE_DISCONNECT_ADDR_CMP)) {
			rds_conn_path_drop(cp, DR_TCP_STATE_DISCONNECT_ADDR_CMP, 0);
		} else {
			rds_connect_path_complete(cp, RDS_CONN_CONNECTING);
			wake_up(&cp->cp_up_waitq);
		}
		break;
	case TCP_CLOSING:
	case TCP_TIME_WAIT:
		if (wq_has_sleeper(&tc->t_recv_done_waitq))
			wake_up(&tc->t_recv_done_waitq);
		break;
	case TCP_CLOSE_WAIT:
	case TCP_LAST_ACK:
	case TCP_CLOSE:
		if (wq_has_sleeper(&tc->t_recv_done_waitq))
			wake_up(&tc->t_recv_done_waitq);
		rds_conn_path_drop(cp, DR_TCP_STATE_CLOSE, 0);
	default:
		break;
	}
out:
	read_unlock(&sk->sk_callback_lock);
	state_change(sk);
}

int rds_tcp_conn_path_connect(struct rds_conn_path *cp)
{
	struct socket *sock = NULL;
	struct sockaddr_in6 sin6;
	struct sockaddr_in sin;
	struct sockaddr *addr;
	char *reason = NULL;
	int port_low, port_high, port;
	int port_groups, groups_left;
	int addrlen;
	bool isv6;
	int ret;
	struct rds_connection *conn = cp->cp_conn;
	struct rds_tcp_connection *tc = cp->cp_transport_data;

	/* for multipath rds,we only trigger the connection after
	 * the handshake probe has determined the number of paths.
	 */
	if (cp->cp_index > 0 && cp->cp_conn->c_npaths < 2) {
		reason = "cp index > 0 but npaths < 2";
		ret = -EAGAIN;
		goto out_nolock;
	}

	mutex_lock(&tc->t_conn_path_lock);

	if (rds_conn_path_up(cp)) {
		mutex_unlock(&tc->t_conn_path_lock);
		reason = "conn path already up";
		ret = 0;
		goto out_nolock;
	}

	if (ipv6_addr_v4mapped(&conn->c_laddr)) {
		ret = sock_create_kern(rds_conn_net(conn), PF_INET,
				       SOCK_STREAM, IPPROTO_TCP, &sock);
		isv6 = false;
	} else {
		ret = sock_create_kern(rds_conn_net(conn), PF_INET6,
				       SOCK_STREAM, IPPROTO_TCP, &sock);
		isv6 = true;
	}
	if (ret < 0) {
		reason = "sock_create_kern failed";
		goto out;
	}

	rds_tcp_tune(sock);

	if (isv6) {
		sin6.sin6_family = AF_INET6;
		sin6.sin6_addr = conn->c_laddr;
		sin6.sin6_port = 0;
		sin6.sin6_flowinfo = 0;
		sin6.sin6_scope_id = conn->c_dev_if;
		addr = (struct sockaddr *)&sin6;
		addrlen = sizeof(sin6);
	} else {
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = conn->c_laddr.s6_addr32[3];
		sin.sin_port = 0;
		addr = (struct sockaddr *)&sin;
		addrlen = sizeof(sin);
	}

	/* encode cp->cp_index in lowest bits of source-port */
	inet_get_local_port_range(rds_conn_net(conn), &port_low, &port_high);
	port_low = ALIGN(port_low, RDS_MPATH_WORKERS);
	port_groups = (port_high - port_low + 1) / RDS_MPATH_WORKERS;
	ret = -EADDRINUSE;
	groups_left = port_groups;
	while (groups_left-- > 0 && ret) {
		if (++tc->t_client_port_group >= port_groups)
			tc->t_client_port_group = 0;
		port =  port_low +
			tc->t_client_port_group * RDS_MPATH_WORKERS +
			cp->cp_index; 

		if (isv6)
			sin6.sin6_port = htons(port);
		else
			sin.sin_port = htons(port);
		ret = sock->ops->bind(sock, addr, addrlen);
	}
	if (ret) {
		reason = "bind failed";
		goto out;
	}

	if (isv6) {
		sin6.sin6_family = AF_INET6;
		sin6.sin6_addr = conn->c_faddr;
		sin6.sin6_port = htons(RDS_TCP_PORT);
		sin6.sin6_flowinfo = 0;
		sin6.sin6_scope_id = conn->c_dev_if;
		addr = (struct sockaddr *)&sin6;
		addrlen = sizeof(sin6);
	} else {
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = conn->c_faddr.s6_addr32[3];
		sin.sin_port = htons(RDS_TCP_PORT);
		addr = (struct sockaddr *)&sin;
		addrlen = sizeof(sin);
	}

	/*
	 * once we call connect() we can start getting callbacks and they
	 * own the socket
	 */
	rds_tcp_set_callbacks(sock, cp);
	ret = sock->ops->connect(sock, addr, addrlen, O_NONBLOCK);
	if (ret == -EINPROGRESS) {
		reason = "connect already in progress";
		ret = 0;
	}

	if (ret == 0) {
		rds_tcp_keepalive(sock);
		sock = NULL;
	} else {
		reason = "connect returned nonzero value";
		rds_tcp_restore_callbacks(sock, cp->cp_transport_data);
	}
out:
	mutex_unlock(&tc->t_conn_path_lock);
out_nolock:
	if (reason)
		trace_rds_tcp_connect_err(conn, cp, tc, sock ? sock->sk : NULL,
					  reason, ret);
	else
		trace_rds_tcp_connect(conn, cp, tc, sock ? sock->sk : NULL,
				      "connect", ret);

	if (sock)
		sock_release(sock);
	return ret;
}

/*
 * Before killing the tcp socket this needs to serialize with callbacks.  The
 * caller has already grabbed the sending sem so we're serialized with other
 * senders.
 *
 * TCP calls the callbacks with the sock lock so we hold it while we reset the
 * callbacks to those set by TCP.  Our callbacks won't execute again once we
 * hold the sock lock.
 */
void rds_tcp_conn_path_shutdown(struct rds_conn_path *cp)
{
	struct rds_tcp_connection *tc = cp->cp_transport_data;
	struct socket *sock;
	unsigned int rounds;

	cancel_work_sync(&tc->t_fan_out_w);

	mutex_lock(&tc->t_conn_path_lock);
	sock = tc->t_sock;

	trace_rds_tcp_shutdown(cp->cp_conn, cp, tc, sock ? sock->sk : NULL,
			       "shutting down", 0);

	if (sock) {
		if (cp->cp_conn->c_destroy_in_prog)
			rds_tcp_set_linger(sock);

		sock->ops->shutdown(sock, SHUT_WR);

		/* after sending FIN,
		 * wait until we processed all incoming messages
		 * and we're sure that there won't be any more:
		 * i.e. state CLOSING, TIME_WAIT, CLOSE_WAIT,
		 * LAST_ACK, or CLOSE (RFC 793).
		 *
		 * Give up waiting after 5 seconds and allow messages
		 * to theoretically get dropped, if the TCP transition
		 * didn't happen.
		 */
		rounds = 0;
		do {
			/* we need to ensure messages are dequeued here
			 * since "rds_recv_worker" only dispatches messages
			 * while the connection is still in RDS_CONN_UP
			 * and there is no guarantee that "rds_tcp_data_ready"
			 * was called nor that "sk_data_ready" still points to it.
			 */
			rds_tcp_recv_path(cp);
		} while (!wait_event_timeout(tc->t_recv_done_waitq,
					     (sock->sk->sk_state == TCP_CLOSING ||
					      sock->sk->sk_state == TCP_TIME_WAIT ||
					      sock->sk->sk_state == TCP_CLOSE_WAIT ||
					      sock->sk->sk_state == TCP_LAST_ACK ||
					      sock->sk->sk_state == TCP_CLOSE) &&
					     skb_queue_empty_lockless(&sock->sk->sk_receive_queue),
					     msecs_to_jiffies(100)) &&
			 ++rounds < 50);

		lock_sock(sock->sk);

		/* discard messages that the peer received already */
		tc->t_last_seen_una = rds_tcp_snd_una(tc);
		rds_send_path_drop_acked(cp, rds_tcp_snd_una(tc), rds_tcp_is_acked);

		rds_tcp_restore_callbacks(sock, tc); /* tc->tc_sock = NULL */

		release_sock(sock->sk);
		sock_release(sock);
	}
	mutex_unlock(&tc->t_conn_path_lock);

	if (tc->t_tinc) {
		rds_inc_put(&tc->t_tinc->ti_inc);
		tc->t_tinc = NULL;
	}
	tc->t_tinc_hdr_rem = sizeof(struct rds_header);
	tc->t_tinc_data_rem = 0;
}
