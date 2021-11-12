/*
 * Copyright (c) 2006, 2019 Oracle and/or its affiliates. All rights reserved.
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
#include <linux/ipv6.h>
#include <linux/if_arp.h>
#include <linux/jhash.h>
#include "rds.h"

struct bind_bucket {
	rwlock_t                lock;
	struct hlist_head	head;
};

#define BIND_HASH_SIZE 8192

static struct bind_bucket *hash_to_bucket(struct rds_net *rds_ns,
					  struct in6_addr *addr, __be16 port)
{
	return rds_ns->rns_bind_hash_table +
		(jhash_3words((__force u32)(addr->s6_addr32[0] ^
					    addr->s6_addr32[1]),
			      (__force u32)(addr->s6_addr32[2] ^
					    addr->s6_addr32[3]),
			      (__force u32)port, 0) & (BIND_HASH_SIZE - 1));
}

/*
 * must hold either read or write lock (write lock for insert != NULL)
 */
static struct rds_sock *rds_bind_lookup(struct bind_bucket *bucket,
					const struct in6_addr *addr,
					__be16 port,
					struct rds_sock *insert,
					__u32 scope_id)
{
	struct rds_sock *rs;
	struct hlist_head *head = &bucket->head;
	u16 lport = be16_to_cpu(port);

	hlist_for_each_entry(rs, head, rs_bound_node) {
		if (lport == be16_to_cpu(rs->rs_bound_port) &&
		    ipv6_addr_equal(addr, &rs->rs_bound_addr) &&
		    rs->rs_bound_scope_id == scope_id) {
			rds_sock_addref(rs);
			return rs;
		}
	}

	if (insert) {
		/*
		 * make sure our addr and port are set before
		 * we are added to the list.
		 */
		insert->rs_bound_addr = *addr;
		insert->rs_bound_port = port;
		insert->rs_bound_scope_id = scope_id;
		rds_sock_addref(insert);

		hlist_add_head(&insert->rs_bound_node, head);
	}
	return NULL;
}

/*
 * Return the rds_sock bound at the given local address.
 *
 * The rx path can race with rds_release.  We notice if rds_release() has
 * marked this socket and don't return a rs ref to the rx path.
 */
struct rds_sock *rds_find_bound(struct rds_net *rds_ns,
				struct in6_addr *addr, __be16 port,
				__u32 scope_id)
{
	struct rds_sock *rs;
	unsigned long flags;
	struct bind_bucket *bucket = hash_to_bucket(rds_ns, addr, port);

	read_lock_irqsave(&bucket->lock, flags);
	rs = rds_bind_lookup(bucket, addr, port, NULL, scope_id);
	read_unlock_irqrestore(&bucket->lock, flags);

	if (rs && sock_flag(rds_rs_to_sk(rs), SOCK_DEAD)) {
		rds_sock_put(rs);
		rs = NULL;
	}

	rdsdebug("returning rs %p for %pI6c:%u\n", rs, addr,
		 ntohs(port));

	return rs;
}

/* returns -ve errno or +ve port */
static int rds_add_bound(struct rds_net *rds_ns, struct rds_sock *rs,
			 struct in6_addr *addr, __be16 *port, __u32 scope_id)
{
	unsigned long flags;
	int ret = -EADDRINUSE;
	u16 rover, last;
	struct bind_bucket *bucket;

	if (*port != 0) {
		rover = be16_to_cpu(*port);
		last = rover;
	} else {
		rover = max_t(u16, get_random_u32(), 2);
		last = rover - 1;
	}

	do {
		struct rds_sock *rrs;
		if (rover == 0)
			rover++;

		bucket = hash_to_bucket(rds_ns, addr, cpu_to_be16(rover));

		write_lock_irqsave(&bucket->lock, flags);
		rrs = rds_bind_lookup(bucket, addr, cpu_to_be16(rover), rs,
				      scope_id);
		write_unlock_irqrestore(&bucket->lock, flags);

		if (!rrs) {
			*port = rs->rs_bound_port;
			ret = 0;
			rdsdebug("rs %p binding to %pI6c:%d\n",
				 rs, addr, (int)ntohs(*port));
			break;
		} else
			rds_sock_put(rrs);
	} while (rover++ != last);

	return ret;
}

void rds_remove_bound(struct rds_net *rds_ns, struct rds_sock *rs)
{
	unsigned long flags;
	struct bind_bucket *bucket =
		hash_to_bucket(rds_ns, &rs->rs_bound_addr, rs->rs_bound_port);

	write_lock_irqsave(&bucket->lock, flags);

	if (!ipv6_addr_any(&rs->rs_bound_addr)) {
		rdsdebug("rs %p unbinding from %pI6c:%d\n",
			 rs, &rs->rs_bound_addr,
			 ntohs(rs->rs_bound_port));

		hlist_del_init(&rs->rs_bound_node);
		rds_sock_put(rs);
		rs->rs_bound_addr = in6addr_any;
	}

	write_unlock_irqrestore(&bucket->lock, flags);
}

int rds_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sock *sk = sock->sk;
	struct rds_sock *rs = rds_sk_to_rs(sk);
	struct in6_addr v6addr, *binding_addr;
	struct rds_transport *trans;
	struct rds_net *rds_ns;
	__u32 scope_id = 0;
	struct net *net;
	int ret = 0;
	__be16 port;
	bool release_trans_on_error;

	/* We allow an RDS socket to be bound to either IPv4 or IPv6
	 * address.
	 */
	if (addr_len < offsetofend(struct sockaddr, sa_family))
		return -EINVAL;
	if (uaddr->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;

		if (addr_len < sizeof(struct sockaddr_in) ||
		    sin->sin_addr.s_addr == htonl(INADDR_ANY) ||
		    sin->sin_addr.s_addr == htonl(INADDR_BROADCAST) ||
		    IN_MULTICAST(ntohl(sin->sin_addr.s_addr)))
			return -EINVAL;
		ipv6_addr_set_v4mapped(sin->sin_addr.s_addr, &v6addr);
		binding_addr = &v6addr;
		port = sin->sin_port;
#if IS_ENABLED(CONFIG_IPV6)
	} else if (uaddr->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)uaddr;
		int addr_type;

		if (addr_len < sizeof(struct sockaddr_in6))
			return -EINVAL;
		addr_type = ipv6_addr_type(&sin6->sin6_addr);
		if (!(addr_type & IPV6_ADDR_UNICAST)) {
			__be32 addr4;

			if (!(addr_type & IPV6_ADDR_MAPPED))
				return -EINVAL;

			/* It is a mapped address.  Need to do some sanity
			 * checks.
			 */
			addr4 = sin6->sin6_addr.s6_addr32[3];
			if (addr4 == htonl(INADDR_ANY) ||
			    addr4 == htonl(INADDR_BROADCAST) ||
			    IN_MULTICAST(ntohl(addr4)))
				return -EINVAL;
		}
		/* The scope ID must be specified for link local address. */
		if (addr_type & IPV6_ADDR_LINKLOCAL) {
			if (sin6->sin6_scope_id == 0)
				return -EINVAL;
			scope_id = sin6->sin6_scope_id;
		}
		binding_addr = &sin6->sin6_addr;
		port = sin6->sin6_port;
#endif
	} else {
		return -EINVAL;
	}

	lock_sock(sk);

	/* RDS socket does not allow re-binding. */
	if (!ipv6_addr_any(&rs->rs_bound_addr)) {
		ret = -EINVAL;
		goto out;
	}
	/* Socket is connected.  The binding address should have the same
	 * scope ID as the connected address, except the case when one is
	 * non-link local address (scope_id is 0).
	 */
	if (!ipv6_addr_any(&rs->rs_conn_addr) && scope_id &&
	    rs->rs_bound_scope_id &&
	    scope_id != rs->rs_bound_scope_id) {
		ret = -EINVAL;
		goto out;
	}

	net = sock_net(sock->sk);
	/* The transport can be set using SO_RDS_TRANSPORT option before the
	 * socket is bound.
	 */
	if (rs->rs_transport) {
		trans = rs->rs_transport;
		if (!trans->laddr_check ||
		    trans->laddr_check(net, binding_addr, scope_id) != 0) {
			ret = -ENOPROTOOPT;
			goto out;
		}
		release_trans_on_error = false;
	} else {
		trans = rds_trans_get_preferred(net, binding_addr, scope_id);
		if (!trans) {
			ret = -EADDRNOTAVAIL;
			pr_info_ratelimited("RDS: %s could not find a transport for %pI6c, load rds_tcp or rds_rdma?\n",
					    __func__, binding_addr);
			goto out;
		}
		rs->rs_transport = trans;
		release_trans_on_error = true;
	}

	rds_ns = rs->rs_rns;
	ret = rds_add_bound(rds_ns, rs, binding_addr, &port, scope_id);
	if (ret && release_trans_on_error) {
		rds_trans_put(rs->rs_transport);
		rs->rs_transport = NULL;
	}

out:
	release_sock(sk);
	return ret;
}

int rds_bind_tbl_net_init(struct rds_net *rds_ns)
{
	struct bind_bucket *bind_hash_table;
	int i;

	bind_hash_table = kzalloc(sizeof(*bind_hash_table) *
				  BIND_HASH_SIZE, GFP_KERNEL);
	if (!bind_hash_table)
		return -ENOMEM;

	for (i = 0; i < BIND_HASH_SIZE; i++) {
		rwlock_init(&bind_hash_table[i].lock);
		INIT_HLIST_HEAD(&bind_hash_table[i].head);
	}
	rds_ns->rns_bind_hash_table = bind_hash_table;

	return 0;
}

void rds_bind_tbl_net_exit(struct rds_net *rds_ns)
{
	struct bind_bucket *bind_hash_table;
	int i;

	bind_hash_table = rds_ns->rns_bind_hash_table;
	for (i = 0; i < BIND_HASH_SIZE; i++)
		WARN_ON(!hlist_empty(&bind_hash_table[i].head));
	kfree(bind_hash_table);
	rds_ns->rns_bind_hash_table = NULL;
}
