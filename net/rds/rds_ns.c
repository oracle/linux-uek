/*
 * Copyright (c) 2007, 2024 Oracle and/or its affiliates.
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
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include "rds.h"
#include "loop.h"

static int rds_netid;

struct rds_net *rds_ns(struct net *net)
{
	struct rds_net *rns = net_generic(net, rds_netid);

	return rns;
}
EXPORT_SYMBOL(rds_ns);

static __net_init int rds_init_net(struct net *net)
{
	struct rds_net *rns;
	int ret;

	rns = rds_ns(net);

	memset(rns, 0, sizeof(*rns));

	mutex_init(&rns->rns_mod_mutex);

	spin_lock_init(&rns->rns_sock_lock);
	INIT_LIST_HEAD(&rns->rns_sock_list);

	ret = rds_bind_tbl_net_init(rns);
	if (ret)
		goto err;

	ret = rds_stats_net_init(net);
	if (ret)
		goto err_stats;

	ret = rds_conn_tbl_net_init(rns);
	if (ret)
		goto err_conn;

	ret = rds_cong_net_init(rns);
	if (ret)
		goto err_cong;

	ret = rds_loop_net_init(rns);
	if (ret)
		goto err_loop;

	return 0;

err_loop:
	rds_cong_net_exit(rns);

err_cong:
	rds_conn_tbl_net_exit(rns);

err_conn:
	rds_stats_net_exit(net);

err_stats:
	rds_bind_tbl_net_exit(rns);

err:
	mutex_destroy(&rns->rns_mod_mutex);
	return ret;
}

static void rds_exit_net(struct net *net)
{
	struct rds_net *rns = rds_ns(net);

	rds_loop_net_exit(rns);
	rds_bind_tbl_net_exit(rns);
	rds_cong_net_exit(rns);
	rds_conn_tbl_net_exit(rns);
	rds_stats_net_exit(net);
	mutex_destroy(&rns->rns_mod_mutex);
}

static struct pernet_operations rds_net_ops = {
	.init = rds_init_net,
	.exit = rds_exit_net,
	.id = &rds_netid,
	.size = sizeof(struct rds_net),
};

int rds_reg_pernet(void)
{
	return register_pernet_device(&rds_net_ops);
}

void rds_unreg_pernet(void)
{
	unregister_pernet_device(&rds_net_ops);
}
