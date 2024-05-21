/*
 * Copyright (c) 2006, 2024, Oracle and/or its affiliates.
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

DEFINE_PER_CPU_SHARED_ALIGNED(struct rds_statistics, rds_stats);
EXPORT_PER_CPU_SYMBOL_GPL(rds_stats);

/* :.,$s/unsigned long\>.*\<s_\(.*\);/"\1",/g */

/* WARNING: struct rds_info_counter specifies the maximum length of a
 * rds_stat_names[] string to be 32, including the terminating NULL byte.
 *
 * Exceeding that length will trigger a WARN_ONCE in rds_stats_info_copy().
 *
 *	 0000000001111111111222222222233
 *	 1234567890123456789012345678901
 */
static char *rds_stat_names[] = {
	"conn_reset",
	"recv_drop_bad_checksum",
	"recv_drop_old_seq",
	"recv_drop_no_sock",
	"recv_drop_dead_sock",
	"recv_deliver_raced",
	"recv_delivered",
	"recv_queued",
	"recv_immediate_retry",
	"recv_delayed_retry",
	"recv_ack_required",
	"recv_rdma_bytes",
	"recv_payload_csum_bad",
	"recv_payload_csum_ib",
	"recv_payload_csum_ib_badlen",
	"recv_payload_csum_loopback",
	"recv_payload_csum_loop_badlen",
	"recv_payload_csum_tcp",
	"recv_payload_csum_tcp_badlen",
	"recv_payload_csum_old_ignored",
	"recv_payload_csum_ignored",
	"recv_payload_csum_trunc",
	"recv_payload_csum_old_rcvd",
	"recv_payload_csum_rcvd",
	"recv_ping",
	"recv_pong",
	"recv_hb_ping",
	"recv_hb_pong",
	"recv_mprds_ping",
	"recv_mprds_pong",
	"send_queue_empty",
	"send_queue_full",
	"send_lock_contention",
	"send_lock_queue_raced",
	"send_immediate_retry",
	"send_delayed_retry",
	"send_drop_acked",
	"send_ack_required",
	"send_queued",
	"send_rdma",
	"send_rdma_bytes",
	"send_ping",
	"send_pong",
	"send_hb_ping",
	"send_hb_pong",
	"send_mprds_ping",
	"send_mprds_pong",
	"send_payload_csum_added",
	"page_remainder_hit",
	"page_remainder_miss",
	"copy_to_user",
	"copy_from_user",
	"copy_from_user_cache_get",
	"copy_from_user_cache_put",
	"cong_update_queued",
	"cong_update_received",
	"cong_send_error",
	"cong_send_blocked",
	"qos_threshold_exceeded",
	"recv_bytes_added_to_sock",
	"recv_bytes_freed_fromsock",
	"send_stuck_rm",
	"page_allocs",
	"page_frees",
	"page_gets",
	"mprds_catchup_tx0_retries",
};

void rds_stats_info_copy(struct rds_info_iterator *iter,
			 uint64_t *values, char **names, size_t nr)
{
	struct rds_info_counter ctr;
	size_t i;

	for (i = 0; i < nr; i++) {
		WARN_ONCE(strlen(names[i]) >= sizeof(ctr.name),
			  "name[%zu] (\"%s\") exceeds max length (%lu > %lu)\n",
			  i, names[i], strlen(names[i]), sizeof(ctr.name) - 1);
		strncpy(ctr.name, names[i], sizeof(ctr.name) - 1);
		ctr.name[(sizeof(ctr.name) - 1)] = '\0';
		ctr.value = values[i];

		rds_info_copy(iter, &ctr, sizeof(ctr));
	}
}
EXPORT_SYMBOL_GPL(rds_stats_info_copy);

/*
 * This gives global counters across all the transports.  The strings
 * are copied in so that the tool doesn't need knowledge of the specific
 * stats that we're exporting.  Some are pretty implementation dependent
 * and may change over time.  That doesn't stop them from being useful.
 *
 * This is the only function in the chain that knows about the byte granular
 * length in userspace.  It converts it to number of stat entries that the
 * rest of the functions operate in.
 */
static void rds_stats_info(struct socket *sock, unsigned int len,
			   struct rds_info_iterator *iter,
			   struct rds_info_lengths *lens)
{
	struct rds_statistics stats = {0, };
	struct rds_statistics *per_cpu_ns_ptr;
	struct rds_net *rns;
	uint64_t *src;
	uint64_t *sum;
	size_t i;
	int cpu;
	unsigned int avail;

	avail = len / sizeof(struct rds_info_counter);

	if (avail < ARRAY_SIZE(rds_stat_names)) {
		avail = 0;
		goto trans;
	}
	rns = rds_ns(iter->net);
	per_cpu_ns_ptr = __rds_get_mod_stats(rns, RDS_MOD_RDS);

	for_each_possible_cpu(cpu) {
		src = (uint64_t *)per_cpu_ptr(per_cpu_ns_ptr, cpu);
		sum = (uint64_t *)&stats;
		for (i = 0; i < sizeof(stats) / sizeof(uint64_t); i++)
			*(sum++) += *(src++);
	}

	rds_stats_info_copy(iter, (uint64_t *)&stats, rds_stat_names,
			    ARRAY_SIZE(rds_stat_names));
	avail -= ARRAY_SIZE(rds_stat_names);

trans:
	lens->each = sizeof(struct rds_info_counter);
	lens->nr = rds_trans_stats_info_copy(iter, avail) +
		   ARRAY_SIZE(rds_stat_names);
}

struct rds_stats_struct *rds_mod_stats_unregister(struct net *net,
						  int module)
{
	struct rds_stats_struct *stats;
	struct rds_net *rns;

	WARN_ON(module < 0 || module >= RDS_MOD_MAX);

	rns = rds_ns(net);

	mutex_lock(&rns->rns_mod_mutex);
	stats = rns->rns_mod_stats[module];
	rns->rns_mod_stats[module] = NULL;
	mutex_unlock(&rns->rns_mod_mutex);

	return stats;
}
EXPORT_SYMBOL_GPL(rds_mod_stats_unregister);

int rds_mod_stats_register(struct net *net, int module,
			   struct rds_stats_struct *stats)
{
	struct rds_net *rns;
	int ret = 0;

	WARN_ON(module < 0 || module >= RDS_MOD_MAX);

	rns = rds_ns(net);

	mutex_lock(&rns->rns_mod_mutex);
	if (rns->rns_mod_stats[module])
		ret = -EINVAL;
	else
		rns->rns_mod_stats[module] = stats;
	mutex_unlock(&rns->rns_mod_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(rds_mod_stats_register);

void rds_stats_net_exit(struct net *net)
{
	struct rds_stats_struct *stats;

	stats = rds_mod_stats_unregister(net, RDS_MOD_RDS);
	if (net_eq(net, &init_net))
		rds_info_deregister_func(RDS_INFO_COUNTERS, rds_stats_info);
	else
		free_percpu(stats->rs_stats);
	kfree(stats);
}

int rds_stats_net_init(struct net *net)
{
	struct rds_stats_struct *stats;
	int ret;

	stats = kmalloc(sizeof(*stats), GFP_KERNEL);
	if (!stats)
		return -ENOMEM;

	stats->rs_names = rds_stat_names;
	stats->rs_num_stats = sizeof(struct rds_statistics) / sizeof(uint64_t);

	if (net_eq(net, &init_net)) {
		stats->rs_stats = &rds_stats;
		ret = rds_mod_stats_register(net, RDS_MOD_RDS, stats);
		if (ret)
			goto err;
		rds_info_register_func(RDS_INFO_COUNTERS, rds_stats_info);
	} else {
		stats->rs_stats = __alloc_percpu(sizeof(struct rds_statistics),
						 cache_line_size());
		if (!stats->rs_stats) {
			ret = -ENOMEM;
			goto err;
		}
		ret = rds_mod_stats_register(net, RDS_MOD_RDS, stats);
		if (ret) {
			free_percpu(stats->rs_stats);
			goto err;
		}
	}

	return 0;

err:
	kfree(stats);
	return ret;
}

void rds_stats_print(const char *where)
{
	struct rds_statistics stats = {};
	uint64_t *src;
	uint64_t *sum;
	size_t i;
	int cpu;
	size_t nstats = sizeof(stats) / sizeof(uint64_t);

	for_each_possible_cpu(cpu) {
		src = (uint64_t *)&(per_cpu(rds_stats, cpu));
		sum = (uint64_t *)&stats;
		for (i = 0; i < nstats; i++)
			*(sum++) += *(src++);
	}

	sum = (uint64_t *)&stats;
	for (i = 0; i < nstats; i++)
		if (sum[i])
			pr_info("%s %s %lld\n", where, rds_stat_names[i], sum[i]);
}
EXPORT_SYMBOL_GPL(rds_stats_print);
