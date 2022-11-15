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
#include <linux/sysctl.h>
#include <linux/proc_fs.h>

#include "rds.h"

static struct ctl_table_header *rds_sysctl_reg_table;

static unsigned long rds_sysctl_reconnect_min = 1;
static unsigned long rds_sysctl_reconnect_max = ~0UL;

unsigned long rds_sysctl_reconnect_min_jiffies;
unsigned long rds_sysctl_reconnect_max_jiffies = HZ;
unsigned long rds_sysctl_reconnect_passive_min_jiffies;

unsigned int  rds_sysctl_max_unacked_packets = 8;
unsigned int  rds_sysctl_max_unacked_bytes = (16 << 20);

unsigned int rds_sysctl_ping_enable = 1;

unsigned int rds_sysctl_shutdown_trace_start_time;
unsigned int rds_sysctl_shutdown_trace_end_time;

unsigned int rds_sock_max_peers_min = 128;
unsigned int rds_sock_max_peers_max = 65536;
unsigned int rds_sock_max_peers = 8192;

/* Heartbeat timeout in seconds. That is the time from a heartbeat ping
 * is sent, before the heartbeat mechanism drops the connection, unless
 * a heartbeat pong has been received.
 */
unsigned int rds_sysctl_min_conn_hb_timeout;
unsigned int rds_sysctl_max_conn_hb_timeout = 60;
unsigned int rds_sysctl_conn_hb_timeout = 10;

/* Heartbeat interval in seconds. The time from a successful heartbeat
 * pong has been received until a new heartbeat ping is sent out is
 * pseudo randomly chosen in the interval 50% to 150% of
 * rds_sysctl_min_conn_hb_interval.
 */
unsigned int rds_sysctl_min_conn_hb_interval = 10;
unsigned int rds_sysctl_max_conn_hb_interval = 600;
unsigned int rds_sysctl_conn_hb_interval = 60;

/* Upper bound to how long "rds_send_drop_to"
 * (and therefore "RDS_CANCEL_SENT_TO") waits for messages to be unmapped.
 */
unsigned long rds_sysctl_dr_sock_cancel_jiffies;

/*
 * We have official values, but must maintain the sysctl interface for existing
 * software that expects to find these values here.
 */
static int rds_sysctl_pf_rds = PF_RDS;
static int rds_sysctl_sol_rds = SOL_RDS;

unsigned int rds_sysctl_enable_payload_csums;

static struct ctl_table rds_sysctl_rds_table[] = {
	{
		.procname       = "reconnect_min_delay_ms",
		.data		= &rds_sysctl_reconnect_min_jiffies,
		.maxlen         = sizeof(unsigned long),
		.mode           = 0644,
		.proc_handler   = proc_doulongvec_ms_jiffies_minmax,
		.extra1		= &rds_sysctl_reconnect_min,
		.extra2		= &rds_sysctl_reconnect_max_jiffies,
	},
	{
		.procname       = "reconnect_max_delay_ms",
		.data		= &rds_sysctl_reconnect_max_jiffies,
		.maxlen         = sizeof(unsigned long),
		.mode           = 0644,
		.proc_handler   = proc_doulongvec_ms_jiffies_minmax,
		.extra1		= &rds_sysctl_reconnect_min_jiffies,
		.extra2		= &rds_sysctl_reconnect_max,
	},
	{
		.procname       = "reconnect_passive_min_delay_ms",
		.data		= &rds_sysctl_reconnect_passive_min_jiffies,
		.maxlen         = sizeof(unsigned long),
		.mode           = 0644,
		.proc_handler   = proc_doulongvec_ms_jiffies_minmax,
	},
	{
		.procname       = "pf_rds",
		.data		= &rds_sysctl_pf_rds,
		.maxlen         = sizeof(int),
		.mode           = 0444,
		.proc_handler   = proc_dointvec,
	},
	{
		.procname       = "sol_rds",
		.data		= &rds_sysctl_sol_rds,
		.maxlen         = sizeof(int),
		.mode           = 0444,
		.proc_handler   = proc_dointvec,
	},
	{
		.procname	= "max_unacked_packets",
		.data		= &rds_sysctl_max_unacked_packets,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
	{
		.procname	= "max_unacked_bytes",
		.data		= &rds_sysctl_max_unacked_bytes,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
	{
		.procname	= "ping_enable",
		.data		= &rds_sysctl_ping_enable,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
	{
		.procname       = "shutdown_trace_start_time",
		.data           = &rds_sysctl_shutdown_trace_start_time,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = &proc_dointvec,
	},
	{
		.procname       = "shutdown_trace_end_time",
		.data           = &rds_sysctl_shutdown_trace_end_time,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = &proc_dointvec,
	},
	{
		.procname       = "sock_max_peers",
		.data           = &rds_sock_max_peers,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = &proc_dointvec_minmax,
		.extra1		= &rds_sock_max_peers_min,
		.extra2		= &rds_sock_max_peers_max
	},
	{
		.procname       = "conn_heartbeat_timeout_secs",
		.data           = &rds_sysctl_conn_hb_timeout,
		.maxlen         = sizeof(rds_sysctl_conn_hb_timeout),
		.mode           = 0644,
		.proc_handler   = proc_douintvec_minmax,
		.extra1		= &rds_sysctl_min_conn_hb_timeout,
		.extra2		= &rds_sysctl_max_conn_hb_timeout,
	},
	{
		.procname       = "conn_heartbeat_interval_secs",
		.data           = &rds_sysctl_conn_hb_interval,
		.maxlen         = sizeof(rds_sysctl_conn_hb_interval),
		.mode           = 0644,
		.proc_handler   = proc_douintvec_minmax,
		.extra1		= &rds_sysctl_min_conn_hb_interval,
		.extra2		= &rds_sysctl_max_conn_hb_interval,
	},
	{
		.procname       = "dr_sock_cancel_delay_ms",
		.data           = &rds_sysctl_dr_sock_cancel_jiffies,
		.maxlen         = sizeof(unsigned long),
		.mode           = 0644,
		.proc_handler   = proc_doulongvec_ms_jiffies_minmax,
	},
	{
		.procname       = "enable_payload_csums",
		.data           = &rds_sysctl_enable_payload_csums,
		.maxlen         = sizeof(rds_sysctl_enable_payload_csums),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
};

void rds_sysctl_exit(void)
{
	unregister_net_sysctl_table(rds_sysctl_reg_table);
}

int rds_sysctl_init(void)
{
	rds_sysctl_reconnect_min = msecs_to_jiffies(1);
	rds_sysctl_reconnect_min_jiffies = rds_sysctl_reconnect_min;
	rds_sysctl_reconnect_passive_min_jiffies = msecs_to_jiffies(3000);
	rds_sysctl_dr_sock_cancel_jiffies = msecs_to_jiffies(6000);

	rds_sysctl_reg_table = register_net_sysctl(&init_net, "net/rds", rds_sysctl_rds_table);
	if (!rds_sysctl_reg_table)
		return -ENOMEM;
	return 0;
}
