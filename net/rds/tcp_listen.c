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

/* rds_tcp_accept_one_path(): if accepting on cp_index > 0, make sure the
 * client's ipaddr < server's ipaddr. Otherwise, close the accepted
 * socket and force a reconneect from smaller -> larger ip addr. The reason
 * we special case cp_index 0 is to allow the rds probe ping itself to itself
 * get through efficiently.
 */
static struct rds_tcp_connection *
rds_tcp_accept_one_path(struct rds_connection *conn)
{
	int i;
	int npaths = max_t(int, 1, conn->c_npaths);

	if (rds_addr_cmp(&conn->c_faddr, &conn->c_laddr) >= 0) {
		if (npaths <= 1)
			rds_conn_path_connect_if_down(&conn->c_path[0]);
		return NULL;
	}

	for (i = 0; i < npaths; i++) {
		struct rds_conn_path *cp = &conn->c_path[i];

		if (rds_conn_path_transition(cp, RDS_CONN_DOWN,
					     RDS_CONN_CONNECTING, DR_DEFAULT)) {
			return cp->cp_transport_data;
		}

		/* only proceed to the next path if all prior paths are up */
		if (!rds_conn_path_up(cp))
			break;
	}

	return NULL;
}

void rds_tcp_set_linger(struct socket *sock)
{
	sock_no_linger(sock->sk);
}

int rds_tcp_accept_one(struct socket *sock)
{
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

	if (!sock) {
		reason = "module unload/netns delete in progress";
		ret = -ENETUNREACH;
		goto out;
	}

	ret = sock_create_lite(sock->sk->sk_family,
			       sock->sk->sk_type, sock->sk->sk_protocol,
			       &new_sock);
	if (ret) {
		reason = "socket creation failed";
		goto out;
	}

	ret = sock->ops->accept(sock, new_sock, &accept_arg);
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
	new_sock->ops = sock->ops;
	__module_get(new_sock->ops->owner);

	ret = rds_tcp_keepalive(new_sock);
	if (ret < 0) {
		reason = "keepalive setting failed";
		goto out;
	}

	rds_tcp_tune(new_sock);


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

	if (!rds_tcp_laddr_check(sock_net(sock->sk), peer_addr, dev_if)) {
		/* local address connection is only allowed via loopback */
		ret = -EOPNOTSUPP;
		goto out;
	}

	conn = rds_conn_create(sock_net(sock->sk),
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
	rs_tcp = rds_tcp_accept_one_path(conn);
	if (!rs_tcp) {
		reason = "force reconnect from smaller IP";
		goto rst_nsk;
	}
	mutex_lock(&rs_tcp->t_conn_path_lock);
	cp = rs_tcp->t_cpath;
	conn_state = rds_conn_path_state(cp);
	BUG_ON(conn_state == RDS_CONN_UP);
	if (conn_state != RDS_CONN_CONNECTING && conn_state != RDS_CONN_ERROR) {
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
					 sock ? sock->sk : NULL, reason, ret);
	else
		trace_rds_tcp_accept(conn, cp, rs_tcp, sock->sk, "accept", ret);
	if (rs_tcp)
		mutex_unlock(&rs_tcp->t_conn_path_lock);
	if (new_sock)
		sock_release(new_sock);

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
		rds_tcp_accept_work(sk);
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
