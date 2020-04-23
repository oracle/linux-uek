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
#include <linux/sysctl.h>
#include <linux/proc_fs.h>

#include "ib.h"

static struct ctl_table_header *rds_ib_sysctl_hdr;

unsigned long rds_ib_sysctl_max_send_wr = RDS_IB_DEFAULT_SEND_WR;
unsigned long rds_ib_sysctl_max_recv_wr = RDS_IB_DEFAULT_RECV_WR;
unsigned long rds_ib_sysctl_max_recv_allocation = (128 * 1024 * 1024) / RDS_FRAG_SIZE;
static unsigned long rds_ib_sysctl_max_wr_min = 1;
/* hardware will fail CQ creation long before this */
static unsigned long rds_ib_sysctl_max_wr_max = (u32)~0;

unsigned long rds_ib_sysctl_max_unsig_wrs = 16;
static unsigned long rds_ib_sysctl_max_unsig_wr_min = 1;
static unsigned long rds_ib_sysctl_max_unsig_wr_max = 64;

unsigned long rds_ib_sysctl_max_unsolicited_wrs = 16;

/* Zero means inserting SEND_SOLICITED in the middle of an RDS message
 * is disabled
 */
static unsigned long rds_ib_sysctl_max_unsolicited_wr_min;
/* Nmbr frags of 1MB + 256B RDBMS hdr */
static unsigned long rds_ib_sysctl_max_unsolicited_wr_max =
	(1 * 1024 * 1024 + RDS_FRAG_SIZE) / RDS_FRAG_SIZE;

/* Default FRWR garbage collection worker wakeup interval, in msec. */
u32 rds_frwr_wake_intrvl = 5000;

/* Default FRWR ibmr idle time before garbage collection, in msec. */
u32 rds_frwr_ibmr_gc_time = 1000;

/* Default funky FRWR ibmr quarantine time to give to device, in msec. */
u32 rds_frwr_ibmr_qrtn_time = 300000;
/*
 * This sysctl does nothing.
 *
 * Backwards compatibility with RDS 3.0 wire protocol
 * disables initial FC credit exchange.
 * If it's ever possible to drop 3.0 support,
 * setting this to 1 and moving init/refill of send/recv
 * rings from ib_cm_connect_complete() back into ib_setup_qp()
 * will cause credits to be added before protocol negotiation.
 */

unsigned int rds_ib_sysctl_flow_control = 0;
unsigned int rds_ib_sysctl_disable_unmap_fmr_cpu; /* = 0 */

/* Min/max from IBTA spec C9-140 */
static int rds_ib_sysctl_min_local_ack_timeout;
static int rds_ib_sysctl_max_local_ack_timeout = 31;
int rds_ib_sysctl_local_ack_timeout = 17; /* 0.5 secs */

/* Time (in millisec) to wait before deallocating connection resources tied to
 * a device.
 */
u32 rds_dev_free_wait_ms = 10000;

/* Time (in milliseconds) after which an incoming
 * connection request is honored, even though we have
 * the right of way.
 *
 * Refer to 'ib.h' variable 'i_connecting_ts' for more details.
 */
unsigned rds_ib_sysctl_yield_after_ms = 2000;

static struct ctl_table rds_ib_sysctl_table[] = {
	{
		.procname       = "max_send_wr",
		.data		= &rds_ib_sysctl_max_send_wr,
		.maxlen         = sizeof(unsigned long),
		.mode           = 0644,
		.proc_handler   = proc_doulongvec_minmax,
		.extra1		= &rds_ib_sysctl_max_wr_min,
		.extra2		= &rds_ib_sysctl_max_wr_max,
	},
	{
		.procname       = "max_recv_wr",
		.data		= &rds_ib_sysctl_max_recv_wr,
		.maxlen         = sizeof(unsigned long),
		.mode           = 0644,
		.proc_handler   = proc_doulongvec_minmax,
		.extra1		= &rds_ib_sysctl_max_wr_min,
		.extra2		= &rds_ib_sysctl_max_wr_max,
	},
	{
		.procname       = "max_unsignaled_wr",
		.data		= &rds_ib_sysctl_max_unsig_wrs,
		.maxlen         = sizeof(unsigned long),
		.mode           = 0644,
		.proc_handler   = proc_doulongvec_minmax,
		.extra1		= &rds_ib_sysctl_max_unsig_wr_min,
		.extra2		= &rds_ib_sysctl_max_unsig_wr_max,
	},
	{
		.procname       = "max_unsolicited_wr",
		.data		= &rds_ib_sysctl_max_unsolicited_wrs,
		.maxlen         = sizeof(unsigned long),
		.mode           = 0644,
		.proc_handler   = &proc_doulongvec_minmax,
		.extra1		= &rds_ib_sysctl_max_unsolicited_wr_min,
		.extra2		= &rds_ib_sysctl_max_unsolicited_wr_max,
	},
	{
		.procname       = "max_recv_allocation",
		.data		= &rds_ib_sysctl_max_recv_allocation,
		.maxlen         = sizeof(unsigned long),
		.mode           = 0644,
		.proc_handler   = proc_doulongvec_minmax,
	},
	{
		.procname	= "flow_control",
		.data		= &rds_ib_sysctl_flow_control,
		.maxlen		= sizeof(rds_ib_sysctl_flow_control),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname       = "disable_unmap_fmr_cpu_assignment",
		.data           = &rds_ib_sysctl_disable_unmap_fmr_cpu,
		.maxlen         = sizeof(rds_ib_sysctl_disable_unmap_fmr_cpu),
		.mode           = 0644,
		.proc_handler   = &proc_dointvec,
	},
	{
		.procname       = "local_ack_timeout",
		.data           = &rds_ib_sysctl_local_ack_timeout,
		.maxlen         = sizeof(rds_ib_sysctl_local_ack_timeout),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1		= &rds_ib_sysctl_min_local_ack_timeout,
		.extra2		= &rds_ib_sysctl_max_local_ack_timeout,
	},
	{
		.procname       = "frwr_gc_interval",
		.data           = &rds_frwr_wake_intrvl,
		.maxlen         = sizeof(rds_frwr_wake_intrvl),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "frwr_ibmr_gc_idle_time",
		.data           = &rds_frwr_ibmr_gc_time,
		.maxlen         = sizeof(rds_frwr_ibmr_gc_time),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "frwr_ibmr_qrtn_time",
		.data           = &rds_frwr_ibmr_qrtn_time,
		.maxlen         = sizeof(rds_frwr_ibmr_qrtn_time),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname	= "conn_dev_free_delay",
		.data           = &rds_dev_free_wait_ms,
		.maxlen         = sizeof(rds_dev_free_wait_ms),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{
		.procname       = "yield_after_ms",
		.data           = &rds_ib_sysctl_yield_after_ms,
		.maxlen         = sizeof(rds_ib_sysctl_yield_after_ms),
		.mode           = 0644,
		.proc_handler   = proc_douintvec,
	},
	{ }
};

void rds_ib_sysctl_exit(void)
{
	unregister_net_sysctl_table(rds_ib_sysctl_hdr);
}

int rds_ib_sysctl_init(void)
{
	rds_ib_sysctl_hdr = register_net_sysctl(&init_net, "net/rds/ib", rds_ib_sysctl_table);
	if (!rds_ib_sysctl_hdr) {
		pr_err("%s: register_net_sysctl() failed\n", __func__);
		return -ENOMEM;
	}
	return 0;
}
