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
#include <net/net_namespace.h>
#include <net/netns/generic.h>

#include "trace.h"

#include "rds.h"
#include "tcp.h"

int rds_tcp_keepalive(struct socket *sock)
{
	/* values below based on xs_udp_default_timeout */
	int keepidle = 5; /* send a probe 'keepidle' secs after last data */
	int keepcnt = 5; /* number of unack'ed probes before declaring dead */
	sock_set_keepalive(sock->sk);
	tcp_sock_set_keepcnt(sock->sk, keepcnt);
	tcp_sock_set_keepidle(sock->sk, keepidle);
	/* KEEPINTVL is the interval between successive probes. We follow
	 * the model in xs_tcp_finish_connecting() and re-use keepidle.
	 */
	tcp_sock_set_keepintvl(sock->sk, keepidle);

	return 0;
}

static int
rds_tcp_get_peer_sport(struct socket *sock)
{
	union {
		struct sockaddr_storage storage;
		struct sockaddr addr;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} saddr;
	int sport;

	if (kernel_getpeername(sock, &saddr.addr) == 0) {
		switch (saddr.addr.sa_family) {
		case AF_INET:
			sport = ntohs(saddr.sin.sin_port);
			break;
		case AF_INET6:
			sport = ntohs(saddr.sin6.sin6_port);
			break;
		default:
			sport = -1;
		}
	} else {
		sport = -1;
	}

	return sport;
}

/* rds_tcp_accept_one_path(): if accepting on cp_index > 0, make sure the
 * client's ipaddr < server's ipaddr. Otherwise, close the accepted
 * socket and force a reconneect from smaller -> larger ip addr. The reason
 * we special case cp_index 0 is to allow the rds probe ping itself to itself
 * get through efficiently.
 */
static struct rds_tcp_connection *
rds_tcp_accept_one_path(struct rds_connection *conn, struct socket *sock)
{
	int sport, npaths, i_min, i_max, i;

	if (conn->c_with_sport_idx)
		/* cp->cp_index is encoded in lowest bits of source-port */
		sport = rds_tcp_get_peer_sport(sock);
	else
		sport = -1;

	npaths = max_t(int, 1, conn->c_npaths);

	if (sport >= 0) {
		i_min = i_max = sport % npaths;
	} else {
		i_min = 0;
		i_max = npaths - 1;
	}

	for (i = i_min; i <= i_max; i++) {
		struct rds_conn_path *cp = &conn->c_path[i];

		if (rds_conn_path_transition(cp, RDS_CONN_DOWN,
					     RDS_CONN_CONNECTING, DR_DEFAULT))
			return cp->cp_transport_data;
	}

	return NULL;
}

void rds_tcp_set_linger(struct socket *sock)
{
	sock_no_linger(sock->sk);
}

void rds_tcp_conn_slots_available(struct rds_connection *conn, bool fan_out)
{
	struct rds_tcp_connection *tc;
	struct rds_tcp_net *rtn;
	struct socket *sock;
	int sport, npaths;

	smp_rmb();
	if (conn->c_destroy_in_prog)
		return;

	tc = conn->c_path->cp_transport_data;
	rtn = tc->t_rtn;
	if (!rtn)
		return;

	sock = tc->t_sock;

	/* During fan-out, check that the connection we already
	 * accepted in slot#0 carried the proper source port modulo.
	 */
	if (fan_out && conn->c_with_sport_idx && sock &&
	    rds_addr_cmp(&conn->c_laddr, &conn->c_faddr) > 0) {
		/* cp->cp_index is encoded in lowest bits of source-port */
		sport = rds_tcp_get_peer_sport(sock);
		npaths = max_t(int, 1, conn->c_npaths);
		if (sport >= 0 && sport % npaths != 0)
			/* peer initiated with a non-#0 lane first */
			rds_conn_path_drop(conn->c_path, DR_TCP_INVALID_SLOT0, 0);
	}

	/* As soon as a connection went down,
	 * it is safe to schedule a "rds_tcp_accept_one"
	 * attempt even if there are no connections pending:
	 * Function "rds_tcp_accept_one" won't block
	 * but simply return -EAGAIN in that case.
	 *
	 * Doing so is necessary to address the case where an
	 * incoming connection on "rds_tcp_listen_sock" is ready
	 * to be acccepted prior to a free slot being available:
	 * the -ENOBUFS case in "rds_tcp_accept_one".
	 */
	rds_tcp_accept_work(rtn);
}

int rds_tcp_accept_one(struct rds_tcp_net *rtn)
{
	struct socket *listen_sock = rtn->rds_tcp_listen_sock;
	struct socket *new_sock = NULL;
	struct rds_connection *conn = NULL;
	int ret;
	struct rds_tcp_connection *rs_tcp = NULL;
	int conn_state;
	struct rds_conn_path *cp = NULL;
	struct in6_addr *my_addr, *peer_addr;
	struct proto_accept_arg accept_arg = {
		.flags = O_NONBLOCK,
		.kern = true,
	};
#if !IS_ENABLED(CONFIG_IPV6)
	struct inet_sock *inet;
	struct in6_addr saddr, daddr;
#endif
	int dev_if = 0;
	char *reason = NULL;

	mutex_lock(&rtn->rds_tcp_accept_lock);

	if (!listen_sock) {
		reason = "module unload/netns delete in progress";
		ret = -ENETUNREACH;
		goto out;
	}

	new_sock = rtn->rds_tcp_accepted_sock;
	rtn->rds_tcp_accepted_sock = NULL;

	if (!new_sock) {
		ret = sock_create_lite(listen_sock->sk->sk_family,
				       listen_sock->sk->sk_type,
				       listen_sock->sk->sk_protocol,
				       &new_sock);
		if (ret) {
			reason = "socket creation failed";
			goto out;
		}

		/* Function "rds_tcp_conn_slots_available" depends on O_NONBLOCK */
		ret = listen_sock->ops->accept(listen_sock, new_sock, &accept_arg);
		if (ret < 0) {
			reason = "accept sock op failed";
			goto out;
		}

		/* sock_create_lite() does not get a hold on the owner module so we
		 * need to do it here.  Note that sock_release() uses sock->ops to
		 * determine if it needs to decrement the reference count.  So set
		 * sock->ops after calling accept() in case that fails.  And there's
		 * no need to do try_module_get() as the listener should have a hold
		 * already.
		 */
		new_sock->ops = listen_sock->ops;
		__module_get(new_sock->ops->owner);

		ret = rds_tcp_keepalive(new_sock);
		if (ret < 0) {
			reason = "keepalive setting failed";
			goto out;
		}

		rds_tcp_tune(new_sock);
	}


#if IS_ENABLED(CONFIG_IPV6)
	my_addr = &new_sock->sk->sk_v6_rcv_saddr;
	peer_addr = &new_sock->sk->sk_v6_daddr;
#else
	inet = inet_sk(new_sock->sk);
	ipv6_addr_set_v4mapped(inet->inet_saddr, &saddr);
	ipv6_addr_set_v4mapped(inet->inet_daddr, &daddr);
	my_addr = &saddr;
	peer_addr = &daddr;
#endif

#if IS_ENABLED(CONFIG_IPV6)
	/* sk_bound_dev_if is not set if the peer address is not link local
	 * address.  In this case, it happens that mcast_oif is set.  So
	 * just use it.
	 */
	if ((ipv6_addr_type(my_addr) & IPV6_ADDR_LINKLOCAL) &&
	    !(ipv6_addr_type(peer_addr) & IPV6_ADDR_LINKLOCAL)) {
		struct ipv6_pinfo *inet6;

		inet6 = inet6_sk(new_sock->sk);
		dev_if = inet6->mcast_oif;
	} else {
		dev_if = new_sock->sk->sk_bound_dev_if;
	}
#endif

	if (!rds_tcp_laddr_check(sock_net(listen_sock->sk), peer_addr, dev_if)) {
		/* local address connection is only allowed via loopback */
		ret = -EOPNOTSUPP;
		goto out;
	}

	conn = rds_conn_create(sock_net(listen_sock->sk),
			       my_addr, peer_addr,
			       &rds_tcp_transport, 0, GFP_KERNEL, dev_if);
	if (IS_ERR(conn)) {
		reason = "conn creation failed";
		ret = PTR_ERR(conn);
		goto out;
	}

	/* An incoming SYN request came in, and TCP just accepted it.
	 *
	 * If the client reboots, this conn will need to be cleaned up.
	 * rds_tcp_state_change() will do that cleanup
	 */
	if (rds_addr_cmp(&conn->c_faddr, &conn->c_laddr) < 0) {
		/* Try to obtain a free connection slot.
		 * If unsuccessful, we need to preserve "new_sock"
		 * that we just accepted, since its "sk_receive_queue"
		 * may contain messages already that have been acknowledged
		 * to and discarded by the sender.
		 * We must not throw those away!
		 */
		rs_tcp = rds_tcp_accept_one_path(conn, new_sock);
		if (!rs_tcp) {
			/* It's okay to stash "new_sock", since
			 * "rds_tcp_conn_slots_available" triggers "rds_tcp_accept_one"
			 * again as soon as one of the connection slots
			 * becomes available again
			 */
			rtn->rds_tcp_accepted_sock = new_sock;
			new_sock = NULL;
			reason = "no connection slot available right now";
			ret = -ENOBUFS;
			goto out;
		}
	} else {
		/* This connection request came from a peer with
		 * a larger address.
		 * Function "rds_tcp_state_change" makes sure
		 * that the connection doesn't transition
		 * to state "RDS_CONN_UP", and therefore
		 * we should not have received any messages
		 * on this socket yet.
		 * This is the only case where it's okay to
		 * not dequeue messages from "sk_receive_queue".
		 */
		if (conn->c_npaths <= 1)
			rds_conn_path_connect_if_down(&conn->c_path[0]);
		rs_tcp = NULL;
		reason = "force reconnect from smaller IP";
		goto rst_nsk;
	}

	mutex_lock(&rs_tcp->t_conn_path_lock);
	cp = rs_tcp->t_cpath;
	conn_state = rds_conn_path_state(cp);
	BUG_ON(conn_state == RDS_CONN_UP);
	if (conn_state != RDS_CONN_CONNECTING && conn_state != RDS_CONN_ERROR) {
		rds_conn_path_drop(cp, DR_INV_CONN_STATE, 0);
		reason = "unexpected conn state";
		goto rst_nsk;
	}
	if (rs_tcp->t_sock) {
		/* Duelling SYN resolution has already been done in
		 * rds_tcp_accept_one_path.
		 */
		rds_tcp_reset_callbacks(new_sock, cp);
		/* rds_connect_path_complete() marks RDS_CONN_UP */
		rds_connect_path_complete(cp, RDS_CONN_RESETTING);
		reason = "conn resetting";
	} else {
		rds_tcp_set_callbacks(new_sock, cp);
		rds_connect_path_complete(cp, RDS_CONN_CONNECTING);
		wake_up(&cp->cp_up_waitq);
		reason = "conn connecting";
	}

	/* Since "rds_tcp_set_callbacks" happens this late
	 * the connection may already have been closed without
	 * "rds_tcp_state_change" doing its due dilligence.
	 *
	 * If that's the case, we simply drop the path,
	 * knowing that "rds_tcp_conn_path_shutdown" will
	 * dequeue pending messages.
	 */
	if (new_sock->sk->sk_state == TCP_CLOSE_WAIT ||
	    new_sock->sk->sk_state == TCP_LAST_ACK ||
	    new_sock->sk->sk_state == TCP_CLOSE)
		rds_conn_path_drop(cp, DR_TCP_STATE_ACCEPT_CLOSED, 0);
	else
		rds_cond_queue_recv_work(cp, 0);

	new_sock = NULL;
	ret = 0;
	if (conn->c_npaths == 0)
		rds_send_hs_ping(cp->cp_conn, cp->cp_index);
	goto out;
rst_nsk:
	/* reset the newly returned accept sock and bail.
	 * It is safe to set linger on new_sock because the RDS connection
	 * has not been brought up on new_sock, so no RDS-level data could
	 * be pending on it. By setting linger, we achieve the side-effect
	 * of avoiding TIME_WAIT state on new_sock.
	 */
	rds_tcp_set_linger(new_sock);
	kernel_sock_shutdown(new_sock, SHUT_RDWR);
	ret = 0;
out:
	if (ret)
		trace_rds_tcp_accept_err(conn, cp, rs_tcp,
					 listen_sock ? listen_sock->sk : NULL,
					 reason, ret);
	else
		trace_rds_tcp_accept(conn, cp, rs_tcp, listen_sock->sk, "accept", ret);
	if (rs_tcp)
		mutex_unlock(&rs_tcp->t_conn_path_lock);
	if (new_sock)
		sock_release(new_sock);

	mutex_unlock(&rtn->rds_tcp_accept_lock);

	return ret;
}

void rds_tcp_listen_data_ready(struct sock *sk)
{
	void (*ready)(struct sock *sk);

	rdsdebug("listen data ready sk %p\n", sk);

	read_lock(&sk->sk_callback_lock);
	ready = sk->sk_user_data;
	if (!ready) { /* check for teardown race */
		ready = sk->sk_data_ready;
		goto out;
	}

	/*
	 * ->sk_data_ready is also called for a newly established child socket
	 * before it has been accepted and the accepter has set up their
	 * data_ready.. we only want to queue listen work for our listening
	 * socket
	 *
	 * (*ready)() may be null if we are racing with netns delete, and
	 * the listen socket is being torn down.
	 */
	if (sk->sk_state == TCP_LISTEN)
		rds_tcp_accept_work(net_generic(sock_net(sk), rds_tcp_netid));
	else
		ready = rds_tcp_listen_sock_def_readable(sock_net(sk));

out:
	read_unlock(&sk->sk_callback_lock);
	if (ready)
		ready(sk);
}

struct socket *rds_tcp_listen_init(struct net *net, bool isv6)
{
	struct socket *sock = NULL;
	struct sockaddr_storage ss;
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	char *reason = NULL;
	int addr_len;
	int ret;

	ret = sock_create_kern(net, isv6 ? PF_INET6 : PF_INET, SOCK_STREAM,
			       IPPROTO_TCP, &sock);
	if (ret < 0) {
		reason = "could not create kernel socket";
		goto out;
	}

	sock->sk->sk_reuse = 1;
	tcp_sock_set_nodelay(sock->sk);

	write_lock_bh(&sock->sk->sk_callback_lock);
	sock->sk->sk_user_data = sock->sk->sk_data_ready;
	sock->sk->sk_data_ready = rds_tcp_listen_data_ready;
	write_unlock_bh(&sock->sk->sk_callback_lock);

	if (isv6) {
		sin6 = (struct sockaddr_in6 *)&ss;
		sin6->sin6_family = PF_INET6;
		sin6->sin6_addr = in6addr_any;
		sin6->sin6_port = htons(RDS_TCP_PORT);
		sin6->sin6_scope_id = 0;
		sin6->sin6_flowinfo = 0;
		addr_len = sizeof(*sin6);
	} else {
		sin = (struct sockaddr_in *)&ss;
		sin->sin_family = PF_INET;
		sin->sin_addr.s_addr = htonl(INADDR_ANY);
		sin->sin_port = htons(RDS_TCP_PORT);
		addr_len = sizeof(*sin);
	}

	ret = sock->ops->bind(sock, (struct sockaddr *)&ss, addr_len);
	if (ret < 0) {
		reason = "could not bind listener socket";
		goto out;
	}

	ret = sock->ops->listen(sock, 64);
	if (ret < 0) {
		reason = "listen op failed";
		goto out;
	}

	trace_rds_tcp_listen(NULL, NULL, NULL, sock->sk, "listen", 0);

	return sock;
out:
	trace_rds_tcp_listen_err(NULL, NULL, NULL, sock ? sock->sk : NULL,
				 reason, ret);

	if (sock)
		sock_release(sock);
	return NULL;
}

void rds_tcp_listen_stop(struct socket *sock, struct work_struct *acceptor)
{
	struct sock *sk;

	if (!sock)
		return;

	sk = sock->sk;

	/* serialize with and prevent further callbacks */
	lock_sock(sk);
	write_lock_bh(&sk->sk_callback_lock);
	if (sk->sk_user_data) {
		sk->sk_data_ready = sk->sk_user_data;
		sk->sk_user_data = NULL;
	}
	write_unlock_bh(&sk->sk_callback_lock);
	release_sock(sk);

	/* wait for accepts to stop and close the socket */
	rds_queue_flush_work(NULL, acceptor, "tcp listen stopping");
	sock_release(sock);
}
