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

#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/moduleparam.h>

#include "xsvnic.h"

static int xs_seq_file;
module_param(xs_seq_file, int, 0644);

MODULE_PARM_DESC(xs_seq_file,
		 "Enabling the sequence files to print data in /proc entries");

static char *glob_counter_name[XSVNIC_MAX_GLOB_COUNTERS] = {
	"sync end del count:\t\t",
	"vnic install count:\t\t",
	"vnic del count:\t\t\t",
	"vnic del novid count:\t\t",
	"vnic update count:\t\t",
	"vnic sync begin count:\t\t",
	"vnic sync end count:\t\t",
	"vnic oper req count:\t\t",
	"vnic unsup cmd count:\t\t",
	"iscsi info count:\t\t",
	"xscore device remove count:\t",
};

static char *counter_name[XSVNIC_MAX_COUNTERS] = {
	"ctrl_heartbeat_count:\t\t",
	"data_heartbeat_count:\t\t",
	"hbeat send error count:\t\t",
	"napi_poll_count:\t\t",
	"short_tx_pkt_count:\t\t",
	"tx_skb_count:\t\t\t",
	"tx_skb_tso_count:\t\t",
	"tx_skb_noheadroom_count:\t",
	"tx skb free count:\t\t",
	"tx skb free count (reaped):\t",
	"tx head expand count:\t\t",
	"tx head expand error count:\t",
	"tx vlan count:\t\t\t",
	"tx error count:\t\t\t",
	"tx wrb exhaust:\t\t\t",
	"tx drop oper down count:\t",
	"tx drop skb error count:\t",
	"tx skb expand error count:\t",
	"tx drop ring full count:\t",
	"rx_skb_count:\t\t\t",
	"rx_skb_alloc_count:\t\t",
	"rx_skb_sendtovlangrp:\t\t",
	"rx_skb_batched_count:\t\t",
	"rx_skb_freed_count:\t\t",
	"rx_bat_maxsegs_count:\t\t",
	"rx_bat_numsegs_below_5:\t\t",
	"rx_bat_numsegs_between_5_10:\t",
	"rx_bat_numsegs_between_10_20:\t",
	"rx_bat_numsegs_above_20:\t",
	"rx_bat_8k_segs_count:\t\t",
	"rx skb offload count:\t\t",
	"rx skb offl frag count:\t\t",
	"rx skb offlnonipv4 count:\t",
	"rx error count:\t\t\t",
	"rx quota exceeded count:\t",
	"rx no buf count:\t\t",
	"rx max packet:\t\t\t",
	"rx min packet:\t\t\t",
	"rx lro Aggregated Packet count:\t",
	"rx lro Flushed count:\t\t",
	"rx lro Average Aggregated Count:\t",
	"rx lro No Descriptor Count:\t",
	"tx max packet:\t\t\t",
	"tx min packet:\t\t\t",
	"tx max time spent:\t\t",
	"tx min time spent:\t\t",
	"napi sched count:\t\t",
	"napi notsched count:\t\t",
	"io port up count:\t\t",
	"io port down count:\t\t",
	"io dup port up count:\t\t",
	"io dup port down count:\t\t",
	"start rx sent count:\t\t",
	"stop rx sent count:\t\t",
	"start rx resp count:\t\t",
	"rx bad resp count:\t\t",
	"open count:\t\t\t",
	"stop count:\t\t\t",
	"getstats count:\t\t\t",
	"set mcast count:\t\t",
	"multicast resp count:\t\t",
	"multicast no resp count:\t",
	"vlan add count:\t\t\t",
	"vlan del count:\t\t\t",
	"ioctl count:\t\t\t",
	"mac addr change:\t\t",
	"wdog timeout count:\t\t",
	"oper req count:\t\t\t",
	"xt down count:\t\t\t",
	"xt update count:\t\t",
	"xt lid change  count:\t\t",
	"admin up count:\t\t\t",
	"admin down count:\t\t",
	"sm poll count:\t\t\t",
	"qp error count:\t\t\t",
	"IB recovery count:\t\t",
	"IB recovered count:\t\t",
	"IB link down count:\t\t",
	"IB link up count:\t\t",
	"ctrl conn ok count:\t\t",
	"ctrl rdisc count:\t\t",
	"ctrl conn err count:\t\t",
	"ctrl recv err count:\t\t",
	"data conn ok count:\t\t",
	"data rdisc count:\t\t",
	"data conn err count:\t\t",
	"sent oper up count:\t\t",
	"sent oper down count:\t\t",
	"sent oper state failure count:\t",
	"sent oper state success count:\t",
	"drop rx standby count:\t\t",
	"drop tx standby count:\t\t",
};

#define XS_RESCHED_NAPI			"napi_sched"
#define XS_READIB_BUF			"read_ibbuf"
#define XS_RXBATCHING_ON		"rbatch on"
#define XS_RXBATCHING_OFF		"rbatch off"
#define XS_SLAVE_ACTIVE			"slave active"
#define XS_SLAVE_BACKUP			"slave backup"

struct proc_dir_entry *proc_root_xsvnic;
struct proc_dir_entry *proc_root_xsvnic_dev;
struct proc_dir_entry *iscsi_boot;

static int xsvnic_proc_read_device(char *page, char **start, off_t off,
				   int count, int *eof, void *data)
{
	char *start_page = page;
	struct xsvnic *vp = data;
	unsigned long tsecs = 0, tmins = 0, thrs = 0;
	char tmp_buf[512];

	page += sprintf(page, "Admin state:\t\t\t%s\n",
			test_bit(XSVNIC_CHASSIS_ADMIN_UP,
				 &vp->state) ? "Up" : "Down");
	page += sprintf(page, "Chassis Name:\t\t\t%s\n",
		    vp->xsmp_info.chassis_name);
	page += sprintf(page, "Chassis Version:\t\t%x\n",
			vp->xsmp_info.version);
	page += sprintf(page, "Server-Profile Name:\t\t%s\n",
		    vp->xsmp_info.session_name);

	page += sprintf(page, "Config parameters:\n");
	page += sprintf(page, "TCA GUID:\t\t\t0x%Lx\n", vp->tca_guid);
	page += sprintf(page, "TCA lid:\t\t\t0x%x\n", vp->tca_lid);
	page += sprintf(page, "MAC addr:\t\t\t0x%Lx\n", vp->mac);
	page += sprintf(page, "VID:\t\t\t\t0x%Lx\n", vp->resource_id);
	page += sprintf(page, "mtu:\t\t\t\t%d\n", vp->mtu);
	page += sprintf(page, "ring size:\t\t\t%d\n", vp->rx_ring_size);
	page += sprintf(page, "bandwidth:\t\t\t%d\n", vp->bandwidth);
	page += sprintf(page, "\n");
	page += sprintf(page, "link/xsmp hndl:\t\t\t%p\n", vp->xsmp_hndl);
	page += sprintf(page, "Port link state: \t\t%s\n",
			test_bit(XSVNIC_PORT_LINK_UP,
				 &vp->state) ? "Up" : "Down");
	page += sprintf(page, "Port link speed: \t\t%d Mbps\n", vp->port_speed);

	strcpy(tmp_buf, "None");
	if (vp->mp_flag & MP_XSVNIC_PRIMARY) {
		strcpy(tmp_buf, "Primary");
		if (vp->mp_flag & MP_XSVNIC_AUTO_SWITCH)
			strcat(tmp_buf, " + AutoSwitchover");
	} else if (vp->mp_flag & MP_XSVNIC_SECONDARY) {
		strcpy(tmp_buf, "Secondary");
		if (vp->mp_flag & MP_XSVNIC_AUTO_SWITCH)
			strcat(tmp_buf, " + AutoSwitchover");
	}

	page += sprintf(page, "HA flags:\t\t\t%s\n", tmp_buf);

	page += sprintf(page, "netdev features:\t\t0x%x\n",
		    (u32) vp->netdev->features);

	page += sprintf(page, "Checksum offload:\t\t%s\n",
			(vp->install_flag &
			 (XSVNIC_INSTALL_TCP_OFFL | XSVNIC_INSTALL_UDP_OFFL))
			? "Enabled" : "Disabled");

	page += sprintf(page, "TSO:\t\t\t\t%s\n",
			(vp->netdev->features & NETIF_F_TSO)
			? "Enabled" : "Disabled");

	page += sprintf(page, "LRO:\t\t\t\t%s\n",
			(vp->lro_mode) ? "Enabled" : "Disabled");

	page += sprintf(page, "RX batching :\t\t\t%s\n",
			(vp->is_rxbatching) ? "Enabled" : "Disabled");

	page += sprintf(page, "8k IB mtu :\t\t\t%s\n",
			((vp->install_flag & XSVNIC_8K_IBMTU)
			 && vp->xsmp_info.is_shca)
			? "Enabled" : "Disabled");
	page += sprintf(page, "VLAN offload :\t\t\t%s\n",
			(xsvnic_vlanaccel != 0) ? "Enabled" : "Disabled");
	page += sprintf(page, "vlan count:\t\t\t%d\n", vp->vlan_count);
	page += sprintf(page, "mcast count:\t\t\t%d (promisc: %s)\n",
			vp->mc_count, vp->iff_promisc ? "on" : "off");

	page += sprintf(page,
			"Data Connection:\t\t%s (%d), Mode: %s InterruptMode"
			" for TX: %s RX: %s\n",
			vp->data_conn.state ==
			XSVNIC_CONN_CONNECTED ? "Connected" : "Not connected",
			vp->data_conn.state,
			vp->data_conn.ctx.features & XSCORE_USE_CHECKSUM ?
			"Checksum" : "ICRC",
			vp->data_conn.ctx.features &
			XSCORE_NO_SEND_COMPL_INTR ? "Disabled" : "Enabled",
			vp->data_conn.ctx.features &
			XSCORE_NO_RECV_COMPL_INTR ? "Disabled" : "Enabled");

	page += sprintf(page, "Control Connection:\t\t%s (%d), Mode: %s\n",
			vp->ctrl_conn.state == XSVNIC_CONN_CONNECTED ?
			"Connected" : "Not connected", vp->ctrl_conn.state,
			vp->ctrl_conn.ctx.
			features & XSCORE_USE_CHECKSUM ? "Checksum" : "ICRC");
	page += sprintf(page, "Interrupt Coalescing parameters\n");
	page += sprintf(page, "TX:\t\t\t\t MaxUSeconds: %d MaxFrames: %d\n",
			vp->data_conn.ctx.tx_coalesce_usecs,
			vp->data_conn.ctx.tx_max_coalesced_frames);
	page += sprintf(page, "RX:\t\t\t\t MaxUSeconds: %d MaxFrames: %d\n",
			vp->data_conn.ctx.rx_coalesce_usecs,
			vp->data_conn.ctx.rx_max_coalesced_frames);

	if (vp->data_conn.state == XSVNIC_CONN_CONNECTED &&
	    vp->ctrl_conn.state == XSVNIC_CONN_CONNECTED) {
		int lqpn, dqpn;

		tsecs = jiffies_to_msecs(jiffies - vp->jiffies) / 1000;
		thrs = tsecs / (60 * 60);
		tmins = (tsecs / 60 - (thrs * 60));
		tsecs = tsecs - (tmins * 60) - (thrs * 60 * 60);

		lqpn = vp->ctrl_conn.ctx.local_qpn;
		dqpn = vp->ctrl_conn.ctx.remote_qpn;
		page += sprintf(page,
			    "Ctrl QP end points:\t\t(0x%x, %d) : (0x%x, %d)\n",
			    lqpn, lqpn, dqpn, dqpn);

		lqpn = vp->data_conn.ctx.local_qpn;
		dqpn = vp->data_conn.ctx.remote_qpn;
		page += sprintf(page,
			    "Data QP end points:\t\t(0x%x, %d) : (0x%x, %d)\n",
			    lqpn, lqpn, dqpn, dqpn);
	}
	page += sprintf(page, "XSVNIC Uptime:\t\t\t%lu hrs ", thrs);
	page += sprintf(page, "%lu mins %lu seconds\n", tmins, tsecs);
	page += sprintf(page, "\n");

	page += sprintf(page, "Operational state:\n");
	if (vp->mp_flag & (MP_XSVNIC_PRIMARY | MP_XSVNIC_SECONDARY)) {
		page += sprintf(page, "HA VNIC state:\t\t\t%s\n",
				vp->ha_state == XSVNIC_HA_STATE_STANDBY
				? "Standby" : "Active");
		page += sprintf(page, "HA Active State:\t\t%s\n",
			    test_bit(XSVNIC_STATE_STDBY, &vp->state)
				? XS_SLAVE_BACKUP : XS_SLAVE_ACTIVE);
	}

	page += sprintf(page, "Netdev state:\t\t\t0x%lu\n", vp->netdev->state);
	page += sprintf(page, "Netdev napi state:\t\t0x%lu\n", vp->napi.state);

	tmp_buf[0] = 0;
	if (netif_running(vp->netdev))
		strcat(tmp_buf, "netdev running");
	else
		strcat(tmp_buf, "netif not running");
	if (netif_queue_stopped(vp->netdev))
		strcat(tmp_buf, " + netdev stopped");
	else
		strcat(tmp_buf, " + netdev not stopped");

	page += sprintf(page, "%s\n\n", tmp_buf);

	page += sprintf(page, "Carrier state:\t\t\t%s\n",
			netif_carrier_ok(vp->netdev) ? "Up" : "Down");

	page += sprintf(page, "VNIC up:\t\t\t%s\n",
			test_bit(XSVNIC_OPER_UP, &vp->state) ? "Yes" : "No");

	page += sprintf(page, "VNIC state:\t\t\t0x%x\n",
			(unsigned int)vp->state);
	tmp_buf[0] = 0;
	if (test_bit(XSVNIC_OPER_UP, &vp->state))
		strcat(tmp_buf, "Oper Up");
	else
		strcat(tmp_buf, "Oper Down");
	if (test_bit(XSVNIC_OS_ADMIN_UP, &vp->state))
		strcat(tmp_buf, " + OS Admin Up");
	else
		strcat(tmp_buf, " + OS Admin Down");
	if (test_bit(XSVNIC_CHASSIS_ADMIN_UP, &vp->state))
		strcat(tmp_buf, " + Chassis Admin Up");
	else
		strcat(tmp_buf, " + Chassis Admin Down");
	if (test_bit(XSVNIC_PORT_LINK_UP, &vp->state))
		strcat(tmp_buf, " + Port Link Up");
	else
		strcat(tmp_buf, " + Port Link Down");
	if (test_bit(XSVNIC_START_RX_SENT, &vp->state))
		strcat(tmp_buf, " + Start Rx Sent");
	else
		strcat(tmp_buf, " + No Start Rx");
	if (test_bit(XSVNIC_START_RESP_RCVD, &vp->state))
		strcat(tmp_buf, " + Start Rx Resp Rcvd");
	else
		strcat(tmp_buf, " + No Start Rx Resp");

	if (test_bit(XSVNIC_INTR_ENABLED, &vp->state))
		strcat(tmp_buf, " + Rx Intr Enabled");
	else
		strcat(tmp_buf, " + Rx Intr Disabled");

	if (test_bit(XSVNIC_RX_NOBUF, &vp->state))
		strcat(tmp_buf, " + Rx No Buf");

	if (test_bit(XSVNIC_XT_DOWN, &vp->state))
		strcat(tmp_buf, " + XT Down");

	if (test_bit(XSVNIC_IBLINK_DOWN, &vp->state))
		strcat(tmp_buf, " +  IB Link Down");

	if (test_bit(XSVNIC_OVER_QUOTA, &vp->state))
		strcat(tmp_buf, " +  No RX Quota");

	page += sprintf(page, "%s\n\n", tmp_buf);

	/* Get LRO statistics */
	if (vp->lro_mode) {
		vp->counters[XSVNIC_RX_LRO_AGGR_PKTS] +=
		    vp->lro.lro_mgr.stats.aggregated;
		vp->counters[XSVNIC_RX_LRO_FLUSHED_PKT] +=
		    vp->lro.lro_mgr.stats.flushed;
		if (vp->lro.lro_mgr.stats.flushed)
			vp->counters[XSVNIC_RX_LRO_AVG_AGGR_PKTS] +=
			    vp->lro.lro_mgr.stats.aggregated /
			    vp->lro.lro_mgr.stats.flushed;
		else
			vp->counters[XSVNIC_RX_LRO_AVG_AGGR_PKTS] = 0;
		vp->counters[XSVNIC_RX_LRO_NO_DESCRIPTORS] +=
		    vp->lro.lro_mgr.stats.no_desc;
	}

	page += sprintf(page, "Counters cleared count:\t\t%u\n",
		    vp->counters_cleared);
	return page - start_page;
}

static int xsvnic_proc_write_device(struct file *file, const char *buffer,
				    unsigned long count, void *data)
{
	struct xsvnic *vp = data;
	int ret;
	char action[64];
	unsigned long action_ul;

	sscanf(buffer, "%s", action);
	ret = kstrtoul(((action != NULL) ? action : ""), 0, &action_ul);

	if ((strlen(action) == 1) && (action_ul == 0)) {
		/* Clear counters */
		memset(vp->counters, 0, sizeof(vp->counters));
		vp->counters_cleared++;
		return count;
	}

	/*
	 * sscanf cannot copies spaces as in "rbatch on" so do a copy
	 */
	memset(action, 0, sizeof(action));
	strncpy(action, buffer, 12);

	if (strcmp(action, XS_RESCHED_NAPI) == 0)
		set_bit(XSVNIC_TRIGGER_NAPI_SCHED, &vp->state);
	else if (strcmp(action, XS_READIB_BUF) == 0) {
		struct xscore_buf_info binfo;
		struct xscore_conn_ctx *ctx = &vp->data_conn.ctx;

		ret = xscore_read_buf(ctx, &binfo);
		if (ret != 1 || binfo.status)
			pr_err("xsvnic: %s No data found, status %d\n",
			       vp->vnic_name, binfo.status);
		else {
			pr_info("xsvnic: %s Data found, status  %d,",
				 vp->vnic_name, binfo.status);
			pr_info("length %d\n", binfo.sz);
			dev_kfree_skb_any(binfo.cookie);
		}
	} else if (strncmp(action, XS_RXBATCHING_ON, 9) == 0) {
		ret = xsvnic_change_rxbatch(vp, 1);
		if (ret != 1)
			pr_err("xsvnic: %s Cannot turn on rx batching %x\n",
				vp->vnic_name, ret);
	} else if (strcmp(action, XS_RXBATCHING_OFF) == 0) {
		ret = xsvnic_change_rxbatch(vp, 0);
		if (ret != 1)
			pr_err("xsvnic: %s Cannot turn off rx batching %x\n",
				vp->vnic_name, ret);
	} else if (strcmp(action, XS_SLAVE_ACTIVE) == 0) {
		pr_info("%s XSVNIC[%s] Setting as active slave\n",
			 __func__, vp->vnic_name);
		clear_bit(XSVNIC_STATE_STDBY, &vp->state);
	} else if (strcmp(action, XS_SLAVE_BACKUP) == 0) {
		pr_info("%s XSVNIC[%s] Setting as standby slave\n",
		       __func__, vp->vnic_name);
		set_bit(XSVNIC_STATE_STDBY, &vp->state);
	} else {
		pr_err("xsvnic: %s  echo'ing %s is not valid\n",
			vp->vnic_name, action);
	}

	return count;
}

static int xsvnic_proc_read_device_counters(char *page, char **start, off_t off,
					    int count, int *eof, void *data)
{
	char *start_page = page;
	struct xsvnic *vp = data;
	int i;

	if (off) {
		*eof = 1;
		return 0;
	}

	for (i = 0; i < XSVNIC_MAX_COUNTERS; i++)
		page +=
		    sprintf(page, "%s%u\n", counter_name[i], vp->counters[i]);
	page += sprintf(page, "Counters cleared count:\t\t%u\n",
		    vp->counters_cleared);

	return page - start_page;
}

static int xsvnic_proc_write_device_counters(struct file *file,
					     const char *buffer,
					     unsigned long count, void *data)
{
	struct xsvnic *vp = data;
	char action[64];
	unsigned long action_ul;
	int ret;

	sscanf(buffer, "%s", action);
	ret = kstrtoul(((action != NULL) ? action : ""), 0, &action_ul);

	if ((strlen(action) == 1) && (action_ul == 0)) {
		/* Clear counters */
		memset(vp->counters, 0, sizeof(vp->counters));
		vp->counters_cleared++;
	}
	return count;
}

static void *xsvnic_seq_start(struct seq_file *seq, loff_t *pos)
{
	return (*pos < XSVNIC_MAX_COUNTERS) ? &counter_name[*pos] : 0;
}

static void *xsvnic_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	return (*pos < XSVNIC_MAX_COUNTERS) ? &counter_name[*pos] : 0;
}

static int xsvnic_seq_show(struct seq_file *seq, void *v)
{
	struct xsvnic *vp = seq->private;

	if (vp->ix == XSVNIC_MAX_COUNTERS)
		vp->ix = 0;

	seq_printf(seq, "%s %u\n", counter_name[vp->ix], vp->counters[vp->ix]);
	vp->ix++;

	return 0;
}

static void xsvnic_seq_stop(struct seq_file *seq, void *v)
{
	/* Nothing to be done here */
}

static const struct seq_operations xsvnic_seq_ops = {
	.start = xsvnic_seq_start,
	.next = xsvnic_seq_next,
	.stop = xsvnic_seq_stop,
	.show = xsvnic_seq_show
};

static int xsvnic_open(struct inode *inode, struct file *sfile)
{
	struct seq_file *seq;
	struct proc_dir_entry *proc;
	int ret_val;

	ret_val = seq_open(sfile, &xsvnic_seq_ops);
	if (!ret_val) {
		/* recover the pointer buried in proc_dir_entry data */
		seq = sfile->private_data;
		proc = PDE(inode);
		seq->private = proc->data;
	}

	return ret_val;
};

static const struct file_operations xsvnic_file_ops = {
	.owner = THIS_MODULE,
	.open = xsvnic_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};

int xsvnic_add_proc_entry(struct xsvnic *vp)
{
	struct proc_dir_entry *file, *counter;

	vp->vnic_dir = create_proc_entry(vp->vnic_name, S_IFDIR,
					 proc_root_xsvnic_dev);

	file = create_proc_entry(vp->vnic_name, S_IFREG, vp->vnic_dir);
	if (!file) {
		pr_err("Unable to create the xsvnic /proc entry\n");
		return -ENOMEM;
	}
	SET_NLINK(file, 1);
	file->read_proc = xsvnic_proc_read_device;
	file->write_proc = xsvnic_proc_write_device;
	SET_OWNER(file);
	file->data = (void *)vp;
	counter = create_proc_entry("counters", S_IFREG, vp->vnic_dir);
	if (!counter) {
		pr_err("Unable to create the xsvnic /proc entry\n");
		return -ENOMEM;
	}
	SET_NLINK(file, 1);

	if (xs_seq_file) {
		if (counter) {
			/* Using seq_file for OVM */
			counter->proc_fops = &xsvnic_file_ops;
		}
	} else
		counter->read_proc = xsvnic_proc_read_device_counters;

	counter->write_proc = xsvnic_proc_write_device_counters;
	SET_OWNER(counter);
	counter->data = (void *)vp;

	return 0;
}

void xsvnic_remove_proc_entry(struct xsvnic *vp)
{
	remove_proc_entry(vp->vnic_name, vp->vnic_dir);
	remove_proc_entry("counters", vp->vnic_dir);
	remove_proc_entry(vp->vnic_name, proc_root_xsvnic_dev);
}

static int xsvnic_proc_write_debug(struct file *file, const char *buffer,
				   unsigned long count, void *data)
{
	int newval;

	sscanf(buffer, "%x", &newval);
	xsvnic_debug = newval;
	return count;
}

static int xsvnic_proc_read_debug(char *page, char **start, off_t off,
				  int count, int *eof, void *data)
{
	int i;
	char *start_page = page;

	page += sprintf(page, "Total Wait time(secs): %ld\n",
		    (xsvnic_wait_time / HZ));
	page += sprintf(page, "Debug bitmask        : 0x%x\n\n", xsvnic_debug);
	for (i = 0; i < XSVNIC_MAX_GLOB_COUNTERS; i++)
		page += sprintf(page, "%s%d\n", glob_counter_name[i],
			    xsvnic_counters[i]);
	return page - start_page;
}

static int xsvnic_proc_read_iscsi_boot(char *page, char **start, off_t off,
				       int count, int *eof, void *data)
{
	char *start_page = page;
	struct xsvnic *vp;

	mutex_lock(&xsvnic_mutex);

	list_for_each_entry(vp, &xsvnic_list, xsvnic_list) {
		if (vp->iscsi_boot_info.initiator_iqn[0] == '\0')
			continue;
		page += sprintf(page, "iscsiserver=%d.%d.%d.%d:%d\n",
			(vp->iscsi_boot_info.target_ip_address >> 24) & 0xff,
			(vp->iscsi_boot_info.target_ip_address >> 16) & 0xff,
			(vp->iscsi_boot_info.target_ip_address >> 8) & 0xff,
			(vp->iscsi_boot_info.target_ip_address >> 0) & 0xff,
			vp->iscsi_boot_info.port);
		page += sprintf(page, "iscsiinitiator=%s\n",
			    vp->iscsi_boot_info.initiator_iqn);
		page += sprintf(page, "iscsitarget=%s:%d\n",
			    vp->iscsi_boot_info.target_iqn,
			    vp->iscsi_boot_info.lun);

		if (vp->iscsi_boot_info.ip_addr == 0)
			page += sprintf(page, "iscsiboot=%s\n",
				    vp->iscsi_boot_info.vnic_name);
		else {
			page += sprintf(page,
				    "iscsiboot=%s:%d.%d.%d.%d:%d.%d.%d.%d:%d.%d.%d.%d:%d.%d.%d.%d\n",
				    vp->iscsi_boot_info.vnic_name,
				    (vp->iscsi_boot_info.ip_addr >> 24) & 0xff,
				    (vp->iscsi_boot_info.ip_addr >> 16) & 0xff,
				    (vp->iscsi_boot_info.ip_addr >> 8) & 0xff,
				    (vp->iscsi_boot_info.ip_addr >> 0) & 0xff,
				    (vp->iscsi_boot_info.netmask >> 24) & 0xff,
				    (vp->iscsi_boot_info.netmask >> 16) & 0xff,
				    (vp->iscsi_boot_info.netmask >> 8) & 0xff,
				    (vp->iscsi_boot_info.netmask >> 0) & 0xff,
				    (vp->iscsi_boot_info.
				     gateway_ip_address >> 24) & 0xff,
				    (vp->iscsi_boot_info.
				     gateway_ip_address >> 16) & 0xff,
				    (vp->iscsi_boot_info.
				     gateway_ip_address >> 8) & 0xff,
				    (vp->iscsi_boot_info.
				     gateway_ip_address >> 0) & 0xff,
				    (vp->iscsi_boot_info.
				     dns_ip_address >> 24) & 0xff,
				    (vp->iscsi_boot_info.
				     dns_ip_address >> 16) & 0xff,
				    (vp->iscsi_boot_info.
				     dns_ip_address >> 8) & 0xff,
				    (vp->iscsi_boot_info.
				     dns_ip_address >> 0) & 0xff);
		}

		if (vp->iscsi_boot_info.mount_type == SAN_MOUNT_TYPE_LVM) {
			if (vp->iscsi_boot_info.vol_group[0] != '\0')
				page += sprintf(page, "sanmount=lvm:%s:%s\n",
						vp->iscsi_boot_info.vol_group,
						vp->iscsi_boot_info.
						vol_group_name);
		} else if (vp->iscsi_boot_info.mount_type ==
			   SAN_MOUNT_TYPE_DIRECT) {
			/* direct mount device */
			if (vp->iscsi_boot_info.mount_dev[0] != '\0')
				page += sprintf(page, "sanmount=%s\n",
						vp->iscsi_boot_info.mount_dev);
		}
		page += sprintf(page, "iscsitpg=%s\n",
			    vp->iscsi_boot_info.target_portal_group);
	}

	mutex_unlock(&xsvnic_mutex);

	return page - start_page;
}

int xsvnic_create_procfs_root_entries(void)
{
	struct proc_dir_entry *debug_file;
	int ret = 0;

	proc_root_xsvnic = create_proc_entry("driver/xsvnic", S_IFDIR,
					     PROC_ROOT);
	if (!proc_root_xsvnic) {
		pr_err("Unable to create /proc/driver/xsvnic\n");
		return -ENOMEM;
	}
	proc_root_xsvnic_dev = create_proc_entry("devices", S_IFDIR,
						 proc_root_xsvnic);
	if (!proc_root_xsvnic_dev) {
		pr_err("Unable to create /proc/driver/xsvnic/devices\n");
		ret = -ENOMEM;
		goto create_proc_end_1;
	}
	debug_file = create_proc_entry("debug", S_IFREG, proc_root_xsvnic);
	if (!debug_file) {
		pr_err("Unable to create /proc/driver/xsvnic/debug\n");
		ret = -ENOMEM;
		goto create_proc_end_2;
	}
	SET_NLINK(debug_file, 1);
	debug_file->read_proc = xsvnic_proc_read_debug;
	debug_file->write_proc = xsvnic_proc_write_debug;
	SET_OWNER(debug_file);

	iscsi_boot = create_proc_entry("boot-info", S_IFREG, proc_root_xsvnic);
	if (!iscsi_boot) {
		pr_err("Unable to create /proc/driver/xsvnic/boot-info\n");
		ret = -ENOMEM;
		goto create_proc_end_3;
	}

	SET_NLINK(iscsi_boot, 1);
	iscsi_boot->read_proc = xsvnic_proc_read_iscsi_boot;
	SET_OWNER(iscsi_boot);

	return 0;

create_proc_end_3:
	remove_proc_entry("debug", proc_root_xsvnic);
create_proc_end_2:
	remove_proc_entry("devices", proc_root_xsvnic_dev);
create_proc_end_1:
	remove_proc_entry("driver/xsvnic", PROC_ROOT);
	return ret;
}

void xsvnic_remove_procfs_root_entries(void)
{
	remove_proc_entry("debug", proc_root_xsvnic);
	remove_proc_entry("devices", proc_root_xsvnic);
	remove_proc_entry("boot-info", proc_root_xsvnic);
	remove_proc_entry("driver/xsvnic", PROC_ROOT);
}
