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
#include <linux/string.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/poll.h>
#include <linux/version.h>
#include <linux/random.h>
#include <net/sock.h>

#include "rds.h"

/* UNUSED for backwards compat only */
static unsigned int rds_ib_retry_count = 0xdead;
module_param(rds_ib_retry_count, int, 0444);
MODULE_PARM_DESC(rds_ib_retry_count, "UNUSED, set param in rds_rdma instead");

static char *rds_qos_threshold = NULL;
module_param(rds_qos_threshold, charp, 0444);
MODULE_PARM_DESC(rds_qos_threshold, "<tos>:<max_msg_size>[,<tos>:<max_msg_size>]*");

static	int rds_qos_threshold_action = 0;
module_param(rds_qos_threshold_action, int, 0444);
MODULE_PARM_DESC(rds_qos_threshold_action,
	"0=Ignore,1=Error,2=Statistic,3=Error_Statistic");

u32 kernel_rds_rt_debug_bitmap = 0x488B;
EXPORT_SYMBOL(kernel_rds_rt_debug_bitmap);
module_param_named(rds_rt_debug_bitmap, kernel_rds_rt_debug_bitmap, uint, 0644);
MODULE_PARM_DESC(rds_rt_debug_bitmap,
		 "RDS Runtime Debug Message Enabling Bitmap [default 0x488B]");

static unsigned long rds_qos_threshold_tbl[256];

char *rds_str_array(char **array, size_t elements, size_t index)
{
	if ((index < elements) && array[index])
		return array[index];
	else
		return "unknown";
}
EXPORT_SYMBOL(rds_str_array);

/* this is just used for stats gathering :/ */
static DEFINE_SPINLOCK(rds_sock_lock);
static unsigned long rds_sock_count;
static LIST_HEAD(rds_sock_list);
DECLARE_WAIT_QUEUE_HEAD(rds_poll_waitq);

/*
 * This is called as the final descriptor referencing this socket is closed.
 * We have to unbind the socket so that another socket can be bound to the
 * address it was using.
 *
 * We have to be careful about racing with the incoming path.  sock_orphan()
 * sets SOCK_DEAD and we use that as an indicator to the rx path that new
 * messages shouldn't be queued.
 */
static int rds_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct rds_sock *rs;

	if (!sk)
		goto out;

	rs = rds_sk_to_rs(sk);

	sock_orphan(sk);
	/* Note - rds_clear_recv_queue grabs rs_recv_lock, so
	 * that ensures the recv path has completed messing
	 * with the socket. */
	rds_clear_recv_queue(rs);
	rds_cong_remove_socket(rs);

	rds_remove_bound(rs);

	rds_send_drop_to(rs, NULL);
	rds_rdma_drop_keys(rs);
	rds_notify_queue_get(rs, NULL);

	spin_lock_bh(&rds_sock_lock);
	list_del_init(&rs->rs_item);
	rds_sock_count--;
	spin_unlock_bh(&rds_sock_lock);

	rds_trans_put(rs->rs_transport);

	sock->sk = NULL;
	debug_sock_put(sk);
out:
	return 0;
}

/*
 * Careful not to race with rds_release -> sock_orphan which clears sk_sleep.
 * _bh() isn't OK here, we're called from interrupt handlers.  It's probably OK
 * to wake the waitqueue after sk_sleep is clear as we hold a sock ref, but
 * this seems more conservative.
 * NB - normally, one would use sk_callback_lock for this, but we can
 * get here from interrupts, whereas the network code grabs sk_callback_lock
 * with _lock_bh only - so relying on sk_callback_lock introduces livelocks.
 */
void rds_wake_sk_sleep(struct rds_sock *rs)
{
	unsigned long flags;

	read_lock_irqsave(&rs->rs_recv_lock, flags);
	__rds_wake_sk_sleep(rds_rs_to_sk(rs));
	read_unlock_irqrestore(&rs->rs_recv_lock, flags);
}

static int rds_getname(struct socket *sock, struct sockaddr *uaddr,
		       int *uaddr_len, int peer)
{
	struct rds_sock *rs = rds_sk_to_rs(sock->sk);
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;

	/* racey, don't care */
	if (peer) {
		if (ipv6_addr_any(&rs->rs_conn_addr))
			return -ENOTCONN;

		if (ipv6_addr_v4mapped(&rs->rs_conn_addr)) {
			sin = (struct sockaddr_in *)uaddr;
			memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
			sin->sin_family = AF_INET;
			sin->sin_port = rs->rs_conn_port;
			sin->sin_addr.s_addr = rs->rs_conn_addr_v4;
			*uaddr_len = sizeof(*sin);
		} else {
			sin6 = (struct sockaddr_in6 *)uaddr;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = rs->rs_conn_port;
			sin6->sin6_addr = rs->rs_conn_addr;
			sin6->sin6_flowinfo = 0;
			/* scope_id is the same as in the bound address. */
			sin6->sin6_scope_id = rs->rs_bound_scope_id;
			*uaddr_len = sizeof(*sin6);
		}
	} else {
		/* If socket is not yet bound and the socket is connected,
		 * set the return address family to be the same as the
		 * connected address, but with 0 address value.  If it is not
		 * connected, set the family to be AF_UNSPEC (value 0) and
		 * the address size to be that of an IPv4 address.
		 */
		if (ipv6_addr_any(&rs->rs_bound_addr)) {
			if (ipv6_addr_any(&rs->rs_conn_addr)) {
				sin = (struct sockaddr_in *)uaddr;
				memset(sin, 0, sizeof(*sin));
				sin->sin_family = AF_UNSPEC;
				*uaddr_len = sizeof(*sin);
				return 0;
			}

#if IS_ENABLED(CONFIG_IPV6)
			if (!(ipv6_addr_type(&rs->rs_conn_addr) &
			      IPV6_ADDR_MAPPED)) {
				sin6 = (struct sockaddr_in6 *)uaddr;
				memset(sin, 0, sizeof(*sin6));
				sin->sin_family = AF_INET6;
				*uaddr_len = sizeof(*sin6);
				return 0;
			}
#endif

			sin = (struct sockaddr_in *)uaddr;
			memset(sin, 0, sizeof(*sin));
			sin->sin_family = AF_INET;
			*uaddr_len = sizeof(*sin);
			return 0;
		}
		if (ipv6_addr_v4mapped(&rs->rs_bound_addr)) {
			sin = (struct sockaddr_in *)uaddr;
			memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
			sin->sin_family = AF_INET;
			sin->sin_port = rs->rs_bound_port;
			sin->sin_addr.s_addr = rs->rs_bound_addr_v4;
			*uaddr_len = sizeof(*sin);
		} else {
			sin6 = (struct sockaddr_in6 *)uaddr;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = rs->rs_bound_port;
			sin6->sin6_addr = rs->rs_bound_addr;
			sin6->sin6_flowinfo = 0;
			sin6->sin6_scope_id = rs->rs_bound_scope_id;
			*uaddr_len = sizeof(*sin6);
		}
	}

	return 0;
}

/*
 * RDS' poll is without a doubt the least intuitive part of the interface,
 * as POLLIN and POLLOUT do not behave entirely as you would expect from
 * a network protocol.
 *
 * POLLIN is asserted if
 *  -	there is data on the receive queue.
 *  -	to signal that a previously congested destination may have become
 *	uncongested
 *  -	A notification has been queued to the socket (this can be a congestion
 *	update, or a RDMA completion).
 *
 * POLLOUT is asserted if there is room on the send queue. This does not mean
 * however, that the next sendmsg() call will succeed. If the application tries
 * to send to a congested destination, the system call may still fail (and
 * return ENOBUFS).
 */
static unsigned int rds_poll(struct file *file, struct socket *sock,
			     poll_table *wait)
{
	struct sock *sk = sock->sk;
	struct rds_sock *rs = rds_sk_to_rs(sk);
	unsigned int mask = 0;
	unsigned long flags;

	poll_wait(file, sk_sleep(sk), wait);

	if (rs->rs_seen_congestion)
		poll_wait(file, &rds_poll_waitq, wait);

	read_lock_irqsave(&rs->rs_recv_lock, flags);
	if (!rs->rs_cong_monitor) {
		/* When a congestion map was updated, we signal POLLIN for
		 * "historical" reasons. Applications can also poll for
		 * WRBAND instead. */
		if (rds_cong_updated_since(&rs->rs_cong_track))
			mask |= (POLLIN | POLLRDNORM | POLLWRBAND);
	} else {
		spin_lock(&rs->rs_lock);
		if (rs->rs_cong_notify)
			mask |= (POLLIN | POLLRDNORM);
		spin_unlock(&rs->rs_lock);
	}
	if (!list_empty(&rs->rs_recv_queue)
	 || !list_empty(&rs->rs_notify_queue))
		mask |= (POLLIN | POLLRDNORM);
	if (rs->rs_snd_bytes < rds_sk_sndbuf(rs))
		mask |= (POLLOUT | POLLWRNORM);
	read_unlock_irqrestore(&rs->rs_recv_lock, flags);

	/* clear state any time we wake a seen-congested socket */
	if (mask)
		rs->rs_seen_congestion = 0;

	return mask;
}

static int rds_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct rds_sock *rs = rds_sk_to_rs(sock->sk);
	rds_tos_t tos;

	switch (cmd) {
	case SIOCRDSSETTOS:
		if (get_user(tos, (rds_tos_t __user *)arg))
			return -EFAULT;

		if (rs->rs_transport &&
		    rs->rs_transport->t_type == RDS_TRANS_TCP)
			tos = 0;

		spin_lock_bh(&rds_sock_lock);
		if (rs->rs_tos || rs->rs_conn) {
			spin_unlock_bh(&rds_sock_lock);
			return -EINVAL;
		}
		rs->rs_tos = tos;
		spin_unlock_bh(&rds_sock_lock);
		break;
        case SIOCRDSGETTOS:
                spin_lock_bh(&rds_sock_lock);
                tos = rs->rs_tos;
                spin_unlock_bh(&rds_sock_lock);
                if (put_user(tos, (rds_tos_t __user *)arg))
                        return -EFAULT;
                break;
	case SIOCRDSENABLENETFILTER:
		spin_lock_bh(&rds_sock_lock);
		rs->rs_netfilter_enabled = 1;
		spin_unlock_bh(&rds_sock_lock);
		break;
	default:
		return -ENOIOCTLCMD;
	}

	return 0;
}

static int rds_cancel_sent_to(struct rds_sock *rs, char __user *optval,
			      int len)
{
	struct sockaddr_in6 sin6;
	int cpy_len;
	int ret = 0;
	bool is_v4;

	/* racing with another thread binding seems ok here */
	if (ipv6_addr_any(&rs->rs_bound_addr)) {
		ret = -ENOTCONN; /* XXX not a great errno */
		goto out;
	}

	if (len < sizeof(struct sockaddr_in)) {
		ret = -EINVAL;
		goto out;
	}

	/* Lets restrict copying to at most sizeof(sin6) */
	cpy_len = min_t(int, (int)sizeof(sin6), len);
	if (copy_from_user(&sin6, optval, cpy_len)) {
		ret = -EFAULT;
		goto out;
	}

	/* We only support IPv4 and IPv6 */
	if (sin6.sin6_family != AF_INET && sin6.sin6_family != AF_INET6) {
		ret = -EINVAL;
		goto out;
	}

	is_v4 = (sin6.sin6_family == AF_INET);

	/* Check that the bound address matches the supplied af */
	if (ipv6_addr_v4mapped(&rs->rs_bound_sin6.sin6_addr) != is_v4) {
		ret = -EINVAL;
		goto out;
	}

	if (is_v4) {
		const struct sockaddr_in *sin4p = (struct sockaddr_in *)&sin6;

		ipv6_addr_set_v4mapped(sin4p->sin_addr.s_addr, &sin6.sin6_addr);
		sin6.sin6_port = sin4p->sin_port;
	} else if (cpy_len != sizeof(sin6)) {
		ret = -EINVAL;
		goto out;
	}

	rds_send_drop_to(rs, &sin6);
out:
	return ret;
}

static int rds_set_bool_option(unsigned char *optvar, char __user *optval,
			       int optlen)
{
	int value;

	if (optlen < sizeof(int))
		return -EINVAL;
	if (get_user(value, (int __user *) optval))
		return -EFAULT;
	*optvar = !!value;
	return 0;
}

static int rds_cong_monitor(struct rds_sock *rs, char __user *optval,
			    int optlen)
{
	int ret;

	ret = rds_set_bool_option(&rs->rs_cong_monitor, optval, optlen);
	if (ret == 0) {
		if (rs->rs_cong_monitor) {
			rds_cong_add_socket(rs);
		} else {
			rds_cong_remove_socket(rs);
			rs->rs_cong_mask = 0;
			rs->rs_cong_notify = 0;
		}
	}
	return ret;
}

static void rds_user_conn_paths_drop(struct rds_connection *conn, int reason)
{
	int i;
	struct rds_conn_path *cp;

	if (!conn->c_trans->t_mp_capable || conn->c_npaths == 1) {
		cp = &conn->c_path[0];
		cp->cp_drop_source = reason;
		rds_conn_path_drop(cp, DR_USER_RESET);
	} else {
		for (i = 0; i < RDS_MPATH_WORKERS; i++) {
			cp = &conn->c_path[i];
			cp->cp_drop_source = reason;
			rds_conn_path_drop(cp, DR_USER_RESET);
		}
	}
}

static int rds_user_reset(struct rds_sock *rs, char __user *optval, int optlen)
{
	struct rds_reset reset;
	struct rds_connection *conn;
	struct in6_addr src6, dst6;
	LIST_HEAD(s_addr_conns);

	if (optlen != sizeof(struct rds_reset))
		return -EINVAL;

	if (copy_from_user(&reset, (struct rds_reset __user *)optval,
				sizeof(struct rds_reset)))
		return -EFAULT;

	/* Reset all conns associated with source addr */
	ipv6_addr_set_v4mapped(reset.src.s_addr, &src6);
	if (reset.dst.s_addr ==  0) {
		pr_info("RDS: Reset ALL conns for Source %pI4\n",
			 &reset.src.s_addr);

		rds_conn_laddr_list(sock_net(rds_rs_to_sk(rs)),
				    &src6, &s_addr_conns);
		if (list_empty(&s_addr_conns))
			goto done;

		list_for_each_entry(conn, &s_addr_conns, c_laddr_node)
			if (conn)
				rds_conn_drop(conn, DR_USER_RESET);
		goto done;
	}

	ipv6_addr_set_v4mapped(reset.dst.s_addr, &dst6);
	conn = rds_conn_find(sock_net(rds_rs_to_sk(rs)), &src6, &dst6,
			     rs->rs_transport, reset.tos,
			     rs->rs_bound_scope_id);

	if (conn) {
		bool is_tcp = conn->c_trans->t_type == RDS_TRANS_TCP;

		printk(KERN_NOTICE "Resetting RDS/%s connection <%pI4,%pI4,%d>\n",
		       is_tcp ? "TCP" : "IB",
		       &reset.src.s_addr,
		       &reset.dst.s_addr, conn->c_tos);
		rds_user_conn_paths_drop(conn, DR_USER_RESET);
	}
done:
	return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
static int rds6_user_reset(struct rds_sock *rs, char __user *optval, int optlen)
{
	struct rds6_reset reset;
	struct rds_connection *conn;
	LIST_HEAD(s_addr_conns);

	if (optlen != sizeof(struct rds6_reset))
		return -EINVAL;

	if (copy_from_user(&reset, (struct rds6_reset __user *)optval,
			   sizeof(struct rds6_reset)))
		return -EFAULT;

	/* Reset all conns associated with source addr */
	if (ipv6_addr_any(&reset.dst)) {
		pr_info("RDS: Reset ALL conns for Source %pI6c\n",
			&reset.src);

		rds_conn_laddr_list(sock_net(rds_rs_to_sk(rs)),
				    &reset.src, &s_addr_conns);
		if (list_empty(&s_addr_conns))
			goto done;

		list_for_each_entry(conn, &s_addr_conns, c_laddr_node)
			if (conn)
				rds_user_conn_paths_drop(conn, 1);
		goto done;
	}

	conn = rds_conn_find(sock_net(rds_rs_to_sk(rs)),
			     &reset.src, &reset.dst, rs->rs_transport,
			     reset.tos, rs->rs_bound_scope_id);

	if (conn) {
		bool is_tcp = conn->c_trans->t_type == RDS_TRANS_TCP;

		printk(KERN_NOTICE "Resetting RDS/%s connection <%pI6c,%pI6c,%d>\n",
		       is_tcp ? "tcp" : "IB",
		       &reset.src, &reset.dst, conn->c_tos);
		rds_user_conn_paths_drop(conn, DR_USER_RESET);
	}
done:
	return 0;
}
#endif

static int rds_set_transport(struct rds_sock *rs, char __user *optval,
			     int optlen)
{
	int t_type;

	if (rs->rs_transport)
		return -EOPNOTSUPP; /* previously attached to transport */

	if (optlen != sizeof(int))
		return -EINVAL;

	if (copy_from_user(&t_type, (int __user *)optval, sizeof(t_type)))
		return -EFAULT;

	if (t_type < 0 || t_type >= RDS_TRANS_COUNT)
		return -EINVAL;

	rs->rs_transport = rds_trans_get(t_type);

	return rs->rs_transport ? 0 : -ENOPROTOOPT;
}

static int rds_enable_recvtstamp(struct sock *sk, char __user *optval,
				 int optlen)
{
	int val, valbool;

	if (optlen != sizeof(int))
		return -EFAULT;

	if (get_user(val, (int __user *)optval))
		return -EFAULT;

	valbool = val ? 1 : 0;

	if (valbool)
		sock_set_flag(sk, SOCK_RCVTSTAMP);
	else
		sock_reset_flag(sk, SOCK_RCVTSTAMP);

	return 0;
}

static int rds_recv_track_latency(struct rds_sock *rs, char __user *optval,
				 int optlen)
{
	struct rds_rx_trace_so trace;
	int i;

	if (optlen != sizeof(struct rds_rx_trace_so))
		return -EFAULT;

	if (copy_from_user(&trace, optval, sizeof(trace)))
		return -EFAULT;

	rs->rs_rx_traces = trace.rx_traces;
	for (i = 0; i < rs->rs_rx_traces; i++) {
		if (trace.rx_trace_pos[i] > RDS_MSG_RX_DGRAM_TRACE_MAX) {
			rs->rs_rx_traces = 0;
			return -EFAULT;
		}
		rs->rs_rx_trace[i] = trace.rx_trace_pos[i];
	}

	return 0;
}


static int rds_setsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, unsigned int optlen)
{
	struct rds_sock *rs = rds_sk_to_rs(sock->sk);
	struct net *net = sock_net(sock->sk);
	int ret;

	if (level != SOL_RDS) {
		ret = -ENOPROTOOPT;
		goto out;
	}

	switch (optname) {
	case RDS_CANCEL_SENT_TO:
		ret = rds_cancel_sent_to(rs, optval, optlen);
		break;
	case RDS_GET_MR:
		ret = rds_get_mr(rs, optval, optlen);
		break;
	case RDS_GET_MR_FOR_DEST:
		ret = rds_get_mr_for_dest(rs, optval, optlen);
		break;
	case RDS_FREE_MR:
		ret = rds_free_mr(rs, optval, optlen);
		break;
	case RDS_RECVERR:
		ret = rds_set_bool_option(&rs->rs_recverr, optval, optlen);
		break;
	case RDS_CONG_MONITOR:
		ret = rds_cong_monitor(rs, optval, optlen);
		break;
	case RDS_CONN_RESET:
		if (!ns_capable(net->user_ns, CAP_NET_ADMIN)) {
			ret =  -EACCES;
			break;
		}
		ret = rds_user_reset(rs, optval, optlen);
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case RDS6_CONN_RESET:
		if (!ns_capable(net->user_ns, CAP_NET_ADMIN)) {
			ret =  -EACCES;
			break;
		}
		ret = rds6_user_reset(rs, optval, optlen);
		break;
#endif
	case SO_RDS_TRANSPORT:
		lock_sock(sock->sk);
		ret = rds_set_transport(rs, optval, optlen);
		release_sock(sock->sk);
		break;
	case SO_TIMESTAMP:
		lock_sock(sock->sk);
		ret = rds_enable_recvtstamp(sock->sk, optval, optlen);
		release_sock(sock->sk);
		break;
	case SO_RDS_MSG_RXPATH_LATENCY:
		ret = rds_recv_track_latency(rs, optval, optlen);
		break;
	default:
		ret = -ENOPROTOOPT;
	}
out:
	return ret;
}

static int rds_getsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	struct rds_sock *rs = rds_sk_to_rs(sock->sk);
	int ret = -ENOPROTOOPT, len;
	int trans;

	if (level != SOL_RDS)
		goto out;

	if (get_user(len, optlen)) {
		ret = -EFAULT;
		goto out;
	}

	switch (optname) {
	case RDS_INFO_FIRST ... RDS_INFO_LAST:
		ret = rds_info_getsockopt(sock, optname, optval,
					  optlen);
		break;

	case RDS_RECVERR:
		if (len < sizeof(int))
			ret = -EINVAL;
		else
		if (put_user(rs->rs_recverr, (int __user *) optval)
		 || put_user(sizeof(int), optlen))
			ret = -EFAULT;
		else
			ret = 0;
		break;
	case SO_RDS_TRANSPORT:
		if (len < sizeof(int)) {
			ret = -EINVAL;
			break;
		}
		trans = (rs->rs_transport ? rs->rs_transport->t_type :
			 RDS_TRANS_NONE); /* unbound */
		if (put_user(trans, (int __user *)optval) ||
		    put_user(sizeof(int), optlen))
			ret = -EFAULT;
		else
			ret = 0;
		break;
	default:
		break;
	}

out:
	return ret;

}

static int rds_connect(struct socket *sock, struct sockaddr *uaddr,
		       int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	struct sockaddr_in *sin;
	struct rds_sock *rs = rds_sk_to_rs(sk);
	int ret = 0;

	lock_sock(sk);

	switch (uaddr->sa_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)uaddr;
		if (addr_len < sizeof(struct sockaddr_in)) {
			ret = -EINVAL;
			break;
		}
		if (sin->sin_addr.s_addr == htonl(INADDR_ANY)) {
			ret = -EDESTADDRREQ;
			break;
		}
		if (IN_MULTICAST(ntohl(sin->sin_addr.s_addr)) ||
		    sin->sin_addr.s_addr == htonl(INADDR_BROADCAST)) {
			ret = -EINVAL;
			break;
		}
		ipv6_addr_set_v4mapped(sin->sin_addr.s_addr, &rs->rs_conn_addr);
		rs->rs_conn_port = sin->sin_port;
		break;

#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6: {
		struct sockaddr_in6 *sin6;
		int addr_type;

		sin6 = (struct sockaddr_in6 *)uaddr;
		if (addr_len < sizeof(struct sockaddr_in6)) {
			ret = -EINVAL;
			break;
		}
		addr_type = ipv6_addr_type(&sin6->sin6_addr);
		if (!(addr_type & IPV6_ADDR_UNICAST)) {
			__be32 addr4;

			if (!(addr_type & IPV6_ADDR_MAPPED)) {
				ret = -EPROTOTYPE;
				break;
			}

			/* It is a mapped address.  Need to do some sanity
			 * checks.
			 */
			addr4 = sin6->sin6_addr.s6_addr32[3];
			if (addr4 == htonl(INADDR_ANY) ||
			    addr4 == htonl(INADDR_BROADCAST) ||
			    IN_MULTICAST(ntohl(addr4))) {
				ret = -EPROTOTYPE;
				break;
			}
		}
		if (addr_type & IPV6_ADDR_LINKLOCAL) {
			/* If socket is arleady bound to a link local address,
			 * the peer address must be on the same link.
			 */
			if (sin6->sin6_scope_id == 0 ||
			    (!ipv6_addr_any(&rs->rs_bound_addr) &&
			     rs->rs_bound_scope_id &&
			     sin6->sin6_scope_id != rs->rs_bound_scope_id)) {
				ret = -EINVAL;
				break;
			}
			/* Remember the connected address scope ID.  It will
			 * be checked against the binding local address when
			 * the socket is bound.
			 */
			rs->rs_bound_scope_id = sin6->sin6_scope_id;
		}
		rs->rs_conn_addr = sin6->sin6_addr;
		rs->rs_conn_port = sin6->sin6_port;
		break;
	}
#endif

	default:
		ret = -EINVAL;
		break;
	}

	release_sock(sk);
	return ret;
}

static struct proto rds_proto = {
	.name	  = "RDS",
	.owner	  = THIS_MODULE,
	.obj_size = sizeof(struct rds_sock),
};

static struct proto_ops rds_proto_ops = {
	.family =	AF_RDS,
	.owner =	THIS_MODULE,
	.release =	rds_release,
	.bind =		rds_bind,
	.connect =	rds_connect,
	.socketpair =	sock_no_socketpair,
	.accept =	sock_no_accept,
	.getname =	rds_getname,
	.poll =		rds_poll,
	.ioctl =	rds_ioctl,
	.listen =	sock_no_listen,
	.shutdown =	sock_no_shutdown,
	.setsockopt =	rds_setsockopt,
	.getsockopt =	rds_getsockopt,
	.sendmsg =	rds_sendmsg,
	.recvmsg =	rds_recvmsg,
	.mmap =		sock_no_mmap,
	.sendpage =	sock_no_sendpage,
};

static void rds_sock_destruct(struct sock *sk)
{
	struct rds_sock *rs = rds_sk_to_rs(sk);

	BUG_ON((&rs->rs_item != rs->rs_item.next ||
	    &rs->rs_item != rs->rs_item.prev));
}

static int __rds_create(struct socket *sock, struct sock *sk, int protocol)
{
	struct rds_sock *rs;

	sock_init_data(sock, sk);
	sock->ops		= &rds_proto_ops;
	sk->sk_protocol		= protocol;
	sk->sk_destruct		= rds_sock_destruct;

	rs = rds_sk_to_rs(sk);
	spin_lock_init(&rs->rs_lock);
	rwlock_init(&rs->rs_recv_lock);
	INIT_LIST_HEAD(&rs->rs_send_queue);
	INIT_LIST_HEAD(&rs->rs_recv_queue);
	INIT_LIST_HEAD(&rs->rs_notify_queue);
	INIT_LIST_HEAD(&rs->rs_cong_list);
	spin_lock_init(&rs->rs_rdma_lock);
	rs->rs_rdma_keys = RB_ROOT;
	rs->poison = 0xABABABAB;
	rs->rs_tos = 0;
	rs->rs_conn = NULL;
	rs->rs_netfilter_enabled = 0;
	rs->rs_rx_traces = 0;

	if (!ipv6_addr_any(&rs->rs_bound_addr)) {
		printk(KERN_CRIT "bound addr %pI6c at create\n",
		       &rs->rs_bound_addr);
	}

	spin_lock_bh(&rds_sock_lock);
	list_add_tail(&rs->rs_item, &rds_sock_list);
	rds_sock_count++;
	spin_unlock_bh(&rds_sock_lock);

	return 0;
}

static int rds_create(struct net *net, struct socket *sock, int protocol, int kern)
{
	struct sock *sk;

	if (sock->type != SOCK_SEQPACKET ||
	    (protocol && IPPROTO_OKA != protocol))
		return -ESOCKTNOSUPPORT;

	sk = sk_alloc(net, AF_RDS, GFP_KERNEL, &rds_proto, kern);
	if (!sk)
		return -ENOMEM;

	return __rds_create(sock, sk, protocol);
}

void debug_sock_hold(struct sock *sk)
{
	struct rds_sock *rs = rds_sk_to_rs(sk);
	if ((refcount_read(&sk->sk_refcnt) == 0)) {
		printk(KERN_CRIT "zero refcnt on sock hold\n");
		WARN_ON(1);
	}
	if (rs->poison != 0xABABABAB) {
		printk(KERN_CRIT "bad poison on hold %x\n", rs->poison);
		WARN_ON(1);
	}
	sock_hold(sk);
}


void rds_sock_addref(struct rds_sock *rs)
{
	debug_sock_hold(rds_rs_to_sk(rs));
}

void debug_sock_put(struct sock *sk)
{
	if ((refcount_read(&sk->sk_refcnt) == 0)) {
		printk(KERN_CRIT "zero refcnt on sock put\n");
		WARN_ON(1);
	}
	if (refcount_dec_and_test(&sk->sk_refcnt)) {
		struct rds_sock *rs = rds_sk_to_rs(sk);
		if (rs->poison != 0xABABABAB) {
			printk(KERN_CRIT "bad poison on put %x\n", rs->poison);
			WARN_ON(1);
		}
		rs->poison = 0xDEADBEEF;
		rs->rs_netfilter_enabled = 0;
		sk_free(sk);
	}
}


void rds_sock_put(struct rds_sock *rs)
{
	debug_sock_put(rds_rs_to_sk(rs));
}

static struct net_proto_family rds_family_ops = {
	.family =	AF_RDS,
	.create =	rds_create,
	.owner	=	THIS_MODULE,
};

static void rds_sock_inc_info(struct socket *sock, unsigned int len,
			      struct rds_info_iterator *iter,
			      struct rds_info_lengths *lens)
{
	struct rds_sock *rs;
	struct sock *sk;
	struct rds_incoming *inc;
	unsigned int total = 0;

	len /= sizeof(struct rds_info_message);

	spin_lock_bh(&rds_sock_lock);

	list_for_each_entry(rs, &rds_sock_list, rs_item) {
		sk = rds_rs_to_sk(rs);
		read_lock(&rs->rs_recv_lock);

		/* XXX too lazy to maintain counts.. */
		list_for_each_entry(inc, &rs->rs_recv_queue, i_item) {
			total++;
			if (total <= len)
				rds_inc_info_copy(inc, iter,
						  inc->i_saddr.s6_addr32[3],
						  rs->rs_bound_addr_v4,
						  1);
		}

		read_unlock(&rs->rs_recv_lock);
	}

	spin_unlock_bh(&rds_sock_lock);

	lens->nr = total;
	lens->each = sizeof(struct rds_info_message);
}

#if IS_ENABLED(CONFIG_IPV6)
static void rds6_sock_inc_info(struct socket *sock, unsigned int len,
			       struct rds_info_iterator *iter,
			       struct rds_info_lengths *lens)
{
	struct rds_sock *rs;
	struct rds_incoming *inc;
	unsigned int total = 0;

	len /= sizeof(struct rds6_info_message);

	spin_lock_bh(&rds_sock_lock);

	list_for_each_entry(rs, &rds_sock_list, rs_item) {
		read_lock(&rs->rs_recv_lock);

		/* XXX too lazy to maintain counts.. */
		list_for_each_entry(inc, &rs->rs_recv_queue, i_item) {
			total++;
			if (total <= len)
				rds6_inc_info_copy(inc, iter, &inc->i_saddr,
						   &rs->rs_bound_addr, 1);
		}

		read_unlock(&rs->rs_recv_lock);
	}

	spin_unlock_bh(&rds_sock_lock);

	lens->nr = total;
	lens->each = sizeof(struct rds6_info_message);
}
#endif

static void rds_sock_info(struct socket *sock, unsigned int len,
			  struct rds_info_iterator *iter,
			  struct rds_info_lengths *lens)
{
	struct rds_info_socket sinfo;
	struct rds_sock *rs;

	len /= sizeof(struct rds_info_socket);

	spin_lock_bh(&rds_sock_lock);

	if (len < rds_sock_count)
		goto out;

	list_for_each_entry(rs, &rds_sock_list, rs_item) {
		sinfo.sndbuf = rds_sk_sndbuf(rs);
		sinfo.rcvbuf = rds_sk_rcvbuf(rs);
		sinfo.bound_addr = rs->rs_bound_addr_v4;
		sinfo.connected_addr = rs->rs_conn_addr_v4;
		sinfo.bound_port = rs->rs_bound_port;
		sinfo.connected_port = rs->rs_conn_port;
		sinfo.inum = sock_i_ino(rds_rs_to_sk(rs));

		rds_info_copy(iter, &sinfo, sizeof(sinfo));
	}

out:
	lens->nr = rds_sock_count;
	lens->each = sizeof(struct rds_info_socket);

	spin_unlock_bh(&rds_sock_lock);
}

#if IS_ENABLED(CONFIG_IPV6)
static void rds6_sock_info(struct socket *sock, unsigned int len,
			   struct rds_info_iterator *iter,
			   struct rds_info_lengths *lens)
{
	struct rds6_info_socket sinfo6;
	struct rds_sock *rs;

	len /= sizeof(struct rds6_info_socket);

	spin_lock_bh(&rds_sock_lock);

	if (len < rds_sock_count)
		goto out;

	list_for_each_entry(rs, &rds_sock_list, rs_item) {
		sinfo6.sndbuf = rds_sk_sndbuf(rs);
		sinfo6.rcvbuf = rds_sk_rcvbuf(rs);
		sinfo6.bound_addr = rs->rs_bound_addr;
		sinfo6.connected_addr = rs->rs_conn_addr;
		sinfo6.bound_port = rs->rs_bound_port;
		sinfo6.connected_port = rs->rs_conn_port;
		sinfo6.inum = sock_i_ino(rds_rs_to_sk(rs));

		rds_info_copy(iter, &sinfo6, sizeof(sinfo6));
	}

out:
	lens->nr = rds_sock_count;
	lens->each = sizeof(struct rds6_info_socket);

	spin_unlock_bh(&rds_sock_lock);
}
#endif

static unsigned long parse_ul(char *ptr, unsigned long max)
{
	unsigned long val;
	char *endptr;

	val = simple_strtoul(ptr, &endptr, 0);
	switch (*endptr) {
	case 'k': case 'K':
		val <<= 10;
		endptr++;
		break;
	case 'm': case 'M':
		val <<= 20;
		endptr++;
		break;
	}

	if (*ptr && !*endptr && val <= max)
		return val;

	printk(KERN_WARNING "RDS: Invalid threshold number\n");
	return 0;
}

int rds_check_qos_threshold(u8 tos, size_t payload_len)
{
	if (rds_qos_threshold_action == 0)
		return 0;

	if (rds_qos_threshold_tbl[tos] && payload_len &&
		rds_qos_threshold_tbl[tos] < payload_len) {
		if (rds_qos_threshold_action == 1)
			return 1;
		else if (rds_qos_threshold_action == 2) {
			rds_stats_inc(s_qos_threshold_exceeded);
			return 0;
		} else if (rds_qos_threshold_action == 3) {
			rds_stats_inc(s_qos_threshold_exceeded);
			return 1;
		} else
			return 0;
	} else
		return 0;
}

static void rds_qos_threshold_init(void)
{
	char *tok, *nxt_tok, *end;
	char str[1024];
	int	i;

	for (i = 0; i < 256; i++)
		rds_qos_threshold_tbl[i] = 0;

	if (rds_qos_threshold == NULL)
		return;

	strcpy(str, rds_qos_threshold);
	nxt_tok = strchr(str, ',');
	if (nxt_tok) {
		*nxt_tok = '\0';
		nxt_tok++;
	}

	tok = str;
	while (tok) {
		char *qos_str, *threshold_str;

		qos_str = tok;
		threshold_str = strchr(tok, ':');
		if (threshold_str) {
			unsigned long qos, threshold;

			*threshold_str = '\0';
			threshold_str++;
			qos = simple_strtol(qos_str, &end, 0);
			if (*end) {
				printk(KERN_WARNING "RDS: Warning: QoS "
					"%s is improperly formatted\n", qos_str);
			} else if (qos > 255) {
				printk(KERN_WARNING "RDS: Warning: QoS "
					"%s out of range\n", qos_str);
			}
			threshold = parse_ul(threshold_str, (u32)~0);
			rds_qos_threshold_tbl[qos] = threshold;
		} else {
			printk(KERN_WARNING "RDS: Warning: QoS:Threshold "
				"%s is improperly formatted\n", tok);
		}

		tok = nxt_tok;
		nxt_tok = strchr(str, ',');
		if (nxt_tok) {
			*nxt_tok = '\0';
			nxt_tok++;
		}
	}
}

static void __exit rds_exit(void)
{
	sock_unregister(rds_family_ops.family);
	proto_unregister(&rds_proto);
	rds_conn_exit();
	rds_cong_exit();
	rds_sysctl_exit();
	rds_threads_exit();
	rds_stats_exit();
	rds_page_exit();
	rds_info_deregister_func(RDS_INFO_SOCKETS, rds_sock_info);
	rds_info_deregister_func(RDS_INFO_RECV_MESSAGES, rds_sock_inc_info);
#if IS_ENABLED(CONFIG_IPV6)
	rds_info_deregister_func(RDS6_INFO_SOCKETS, rds6_sock_info);
	rds_info_deregister_func(RDS6_INFO_RECV_MESSAGES, rds6_sock_inc_info);
#endif
}

module_exit(rds_exit);

u32 rds_gen_num;

static int __init rds_init(void)
{
	int ret;

	net_get_random_once(&rds_gen_num, sizeof(rds_gen_num));

	rds_bind_lock_init();

	ret = rds_conn_init();
	if (ret)
		goto out;
	ret = rds_threads_init();
	if (ret)
		goto out_conn;
	ret = rds_sysctl_init();
	if (ret)
		goto out_threads;
	ret = rds_stats_init();
	if (ret)
		goto out_sysctl;
	ret = proto_register(&rds_proto, 1);
	if (ret)
		goto out_stats;
	ret = sock_register(&rds_family_ops);
	if (ret)
		goto out_proto;

	rds_info_register_func(RDS_INFO_SOCKETS, rds_sock_info);
	rds_info_register_func(RDS_INFO_RECV_MESSAGES, rds_sock_inc_info);
#if IS_ENABLED(CONFIG_IPV6)
	rds_info_register_func(RDS6_INFO_SOCKETS, rds6_sock_info);
	rds_info_register_func(RDS6_INFO_RECV_MESSAGES, rds6_sock_inc_info);
#endif

	rds_qos_threshold_init();

	goto out;

out_sock:
	sock_unregister(rds_family_ops.family);
out_proto:
	proto_unregister(&rds_proto);
out_stats:
	rds_stats_exit();
out_sysctl:
	rds_sysctl_exit();
out_threads:
	rds_threads_exit();
out_conn:
	rds_conn_exit();
	rds_cong_exit();
	rds_page_exit();
out:
	return ret;
}
module_init(rds_init);

#define DRV_VERSION     "4.1"
#define DRV_RELDATE     "Jan 04, 2013"

MODULE_AUTHOR("Oracle Corporation <rds-devel@oss.oracle.com>");
MODULE_DESCRIPTION("RDS: Reliable Datagram Sockets"
		   " v" DRV_VERSION " (" DRV_RELDATE ")");
MODULE_VERSION(DRV_VERSION);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_ALIAS_NETPROTO(PF_RDS);
