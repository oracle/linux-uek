/*
 * Copyright (c) 2006-2012 Xsigo Systems Inc.  All rights reserved.
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

#ifndef _XSMP_H_
#define _XSMP_H_

enum {
	XSMP_REG_SENT_COUNTER,
	XSMP_REG_CONF_COUNTER,
	XSMP_RES_LIST_COUNTER,
	XSMP_HELLO_RCVD_COUNTER,
	XSMP_HELLO_INTERRUPT_COUNTER,
	XSMP_REJ_RCVD_COUNTER,
	XSMP_HELLO_SENT_COUNTER,
	XSMP_SEQ_MISMATCH_COUNTER,
	XSMP_SESSION_TIMEOUT_COUNTER,
	XSMP_SHUTDOWN_RCVD_COUNTER,
	XSMP_SHUTDOWN_SENT_COUNTER,
	XSMP_VNIC_MESSAGE_COUNTER,
	XSMP_VHBA_MESSAGE_COUNTER,
	XSMP_USPACE_MESSAGE_COUNTER,
	XSMP_XVE_MESSAGE_COUNTER,
	XSMP_SESSION_MESSAGE_COUNTER,
	XSMP_VNIC_MESSAGE_SENT_COUNTER,
	XSMP_VHBA_MESSAGE_SENT_COUNTER,
	XSMP_USPACE_MESSAGE_SENT_COUNTER,
	XSMP_XVE_MESSAGE_SENT_COUNTER,
	XSMP_SESSION_MESSAGE_SENT_COUNTER,
	XSMP_SESSION_RING_FULL_COUNTER,
	XSMP_SESSION_SEND_ERROR_COUNTER,
	XSMP_SESSION_CONN_DOWN_COUNTER,
	XSMP_TOTAL_MSG_SENT_COUNTER,
	XSMP_CONN_RETRY_COUNTER,
	XSMP_CONN_FAILED_COUNTER,
	XSMP_CONN_SUCCESS_COUNTER,
	XSMP_MAX_COUNTERS
};

enum {
	XSMP_SESSION_ERROR,
	XSMP_SESSION_INIT,
	XSMP_SESSION_TPT_CONNECTING,
	XSMP_SESSION_TPT_CONNECTED,
	XSMP_SESSION_CONNECTING,
	XSMP_SESSION_CONNECTED,
	XSMP_SESSION_DISCONNECTING,
	XSMP_SESSION_DISCONNECTED,
};

struct xsmp_ctx {
	spinlock_t lock;
	int state;
	atomic_t ref_cnt;
	unsigned long flags;
#define	XSMP_DELETE_BIT		1
#define	XSMP_SHUTTINGDOWN_BIT	2
#define	XSMP_REG_SENT		3
#define	XSMP_REG_CONFIRM_RCVD	4
#define	XSMP_IBLINK_DOWN	5
	struct list_head list;
	struct list_head glist;
	int idr;
	unsigned long jiffies;
	unsigned long hello_jiffies;
	struct xscore_port *port;
	struct xscore_conn_ctx conn_ctx;
	u64 dguid;
	u16 dlid;
	struct delayed_work sm_work;
	int sm_delay;
	int hello_timeout;
	struct workqueue_struct *wq;
	int seq_number;
	u32 counters[XSMP_MAX_COUNTERS];
	u32 rcv_seq_number;
	u32 xsigo_xsmp_version;
	int datapath_timeout;
	char chassis_name[CHASSIS_NAME_LEN];
	char session_name[SESSION_NAME_LEN];
};

void xcpm_xsmp_add_proc_entry(struct xsmp_ctx *xsmp_ctx);
void xcpm_xsmp_remove_proc_entry(struct xsmp_ctx *xsmp_ctx);
#endif
