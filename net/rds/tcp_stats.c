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
#include <linux/percpu.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>

#include "rds.h"
#include "tcp.h"

DEFINE_PER_CPU(struct rds_tcp_statistics, rds_tcp_stats)
	____cacheline_aligned;

static char *rds_tcp_stat_names[] = {
	"tcp_data_ready_calls",
	"tcp_write_space_calls",
	"tcp_sndbuf_full",
	"tcp_connect_raced",
	"tcp_listen_closed_stale",
	"tcp_ka_timeout",
};

unsigned int rds_tcp_stats_info_copy(struct rds_info_iterator *iter,
				     unsigned int avail)
{
	struct rds_tcp_statistics stats = {0, };
	struct rds_tcp_statistics *per_cpu_ns_ptr;
	struct rds_net *rns;
	uint64_t *src;
	uint64_t *sum;
	size_t i;
	int cpu;

	if (avail < ARRAY_SIZE(rds_tcp_stat_names))
		goto out;

	rns = rds_ns(iter->net);
	per_cpu_ns_ptr = __rds_get_mod_stats(rns, RDS_MOD_TCP);

	for_each_possible_cpu(cpu) {
		src = (uint64_t *)per_cpu_ptr(per_cpu_ns_ptr, cpu);
		sum = (uint64_t *)&stats;
		for (i = 0; i < sizeof(stats) / sizeof(uint64_t); i++)
			*(sum++) += *(src++);
	}

	rds_stats_info_copy(iter, (uint64_t *)&stats, rds_tcp_stat_names,
			    ARRAY_SIZE(rds_tcp_stat_names));
out:
	return ARRAY_SIZE(rds_tcp_stat_names);
}

void rds_tcp_stats_net_exit(struct net *net)
{
	struct rds_stats_struct *stats;

	stats = rds_mod_stats_unregister(net, RDS_MOD_TCP);
	if (!net_eq(net, &init_net))
		free_percpu(stats->rs_stats);
	kfree(stats);
}

int rds_tcp_stats_net_init(struct net *net)
{
	struct rds_stats_struct *stats;
	int ret = 0;

	stats = kmalloc(sizeof(*stats), GFP_KERNEL);
	if (!stats)
		return -ENOMEM;

	stats->rs_names = rds_tcp_stat_names;
	stats->rs_num_stats = sizeof(struct rds_tcp_statistics) /
		sizeof(uint64_t);

	if (net_eq(net, &init_net)) {
		stats->rs_stats = &rds_tcp_stats;
		ret = rds_mod_stats_register(net, RDS_MOD_TCP, stats);
	} else {
		stats->rs_stats =
			__alloc_percpu(sizeof(struct rds_tcp_statistics),
				       cache_line_size());
		if (stats->rs_stats) {
			ret = rds_mod_stats_register(net, RDS_MOD_TCP, stats);
			if (ret)
				free_percpu(stats->rs_stats);
		} else {
			ret = -ENOMEM;
		}
	}

	if (ret)
		kfree(stats);
	return ret;
}
