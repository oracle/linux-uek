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

#include "xve.h"
#include "xve_compat.h"

static int xs_seq_file;
module_param(xs_seq_file, int, 0644);

MODULE_PARM_DESC(xs_seq_file,
		 "Enabling the sequence files to print large data in /proc entries");

static char *glob_counter_name[XVE_MAX_GLOB_COUNTERS] = {
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
	"vnic stats req count:\t",
	"number of pages allocated:\t",
};

static char *counter_name[XVE_MAX_COUNTERS] = {
	"heartbeat_count:\t\t",
	"hbeat send error count:\t\t",
	"state_machine count:\t\t",
	"state_machine_up count:\t\t",
	"state_machine_down count:\t",
	"napi_poll_count:\t\t",
	"short_tx_pkt_count:\t\t",
	"tx_skb_count:\t\t\t",
	"tx skb free count:\t\t",
	"tx vlan count:\t\t\t",
	"tx error count:\t\t\t",
	"tx wrb exhaust:\t\t\t",
	"tx drop oper down count:\t",
	"tx drop skb error count:\t",
	"tx drop ring full count:\t",
	"tx wake up count\t\t",
	"tx queue stop count:\t\t",
	"rx_skb_count:\t\t\t",
	"rx_skb_alloc_count:\t\t",
	"rx_smallskb_alloc_count:\t",
	"rx_skb_freed_count:\t\t",
	"rx skb offload count:\t\t",
	"rx skb offl frag count:\t\t",
	"rx skb offlnonipv4 count:\t",
	"rx error count:\t\t\t",
	"rx quota exceeded count:\t",
	"rx no buf count:\t\t",
	"napi sched count:\t\t",
	"napi notsched count:\t\t",
	"napi resched count:\t\t",
	"open count:\t\t\t",
	"stop count:\t\t\t",
	"getstats count:\t\t\t",
	"set mcast count:\t\t",
	"vlan add count:\t\t\t",
	"vlan del count:\t\t\t",
	"ioctl count:\t\t\t",
	"wdog timeout count:\t\t",
	"oper req count:\t\t\t",
	"admin up count:\t\t\t",
	"admin down count:\t\t",
	"sm poll count:\t\t\t",
	"qp error count:\t\t\t",
	"IB recovery count:\t\t",
	"IB recovered count:\t\t",
	"IB link down count:\t\t",
	"IB link up count:\t\t",
	"IB HCA port not active:\t\t",
	"sent oper up count:\t\t",
	"sent oper down count:\t\t",
	"sent oper state failure count:\t",
	"sent oper state success count:\t",
	"drop standby count:\t\t",
	"mac learn count:\t\t",
	"mac aged count:\t\t\t",
	"mac aged check count:\t\t",
	"mac aged match not found:\t",
	"mac aged still in use:\t\t",
	"mac moved count:\t\t",
	"mcast join task count:\t\t",
	"mcast leave task count:\t\t",
	"mcast carrier task count:\t",
	"tx ud count:\t\t\t",
	"tx rc count:\t\t\t",
	"tx mcast count:\t\t\t",
	"tx arp count:\t\t\t",
	"tx ndp count:\t\t\t",
	"tx arp vlan count:\t\t",
	"tx ndp vlan count:\t\t",
	"tx ud flood count:\t\t",
	"tx rc flood count:\t\t",
	"tx queue count:\t\t\t",
	"tx path not found:\t\t",
	"rx path not setup:\t\t",
	"tx ah not found:\t\t",
	"pathrec query count:\t\t",
	"pathrec resp count:\t\t",
	"pathrec resp err count:\t\t",
	"ib sm_change count:\t\t",
	"ib client_reregister count:\t",
	"ib port_err count:\t\t",
	"ib port_active count:\t\t",
	"ib lid_active count:\t\t",
	"ib pkey_change count:\t\t",
	"ib invalid count:\t\t",
};

static char *misc_counter_name[XVE_MISC_MAX_COUNTERS] = {
	"start  pkey poll:\t\t",
	"complete  pkey poll:\t\t",
	"start ah reap:\t\t\t",
	"complete reap:\t\t\t",
	"start fwt_aging:\t\t",
	"complete fwt_aging:\t\t",
	"start mcast join:\t\t",
	"complete mcast join\t\t",
	"start mcast leave:\t\t",
	"complete mcast leave:\t\t",
	"start mcast on:\t\t\t",
	"complete mcast on:\t\t",
	"start mcast restart:\t\t",
	"complete mcast restart:\t\t",
	"start  flush light:\t\t",
	"complete  flush light:\t\t",
	"start  flush normal:\t\t",
	"complete flush normal:\t\t",
	"start  flush heavy:\t\t",
	"complete flush heavy:\t\t",
	"start  cm stale:\t\t",
	"complete cm stale:\t\t",
	"start  cm tx start:\t\t",
	"complete cm work start:\t\t",
	"start  cm tx reap:\t\t",
	"complete cm work tx reap:\t",
	"start  cm rx reap:\t\t",
	"complete cm work rx reap:\t",
	"Workqueue not scheded:\t\t",
	"Workqueue sched invalid:\t",
	"WorkQueue sched failed:\t\t",
};

#define XS_RESCHED_NAPI				"napi_sched"
#define XS_READIB_BUF				"read_ibbuf"
#define XS_RXBATCHING_ON			"rbatch on"
#define XS_RXBATCHING_OFF			"rbatch off"

struct proc_dir_entry *proc_root_xve;
struct proc_dir_entry *proc_root_xve_dev;

static int xve_proc_l2_read_device(char *page, char **start, off_t off,
				   int count, int *eof, void *data)
{
	char *start_page = page;
	struct xve_fwt_entry *fwt_entry;
	struct xve_dev_priv *vp = data;
	struct xve_fwt_s *xve_fwt;
	struct hlist_head *head;
	struct hlist_node *h, *n;
	int i, j, k;
	u8 beyond_page = 0;
	char tmp_buf[512];
	char *smac;

	if (off) {
		*eof = 1;
		return 0;
	}

	xve_fwt = &vp->xve_fwt;
	page +=
	    sprintf(page,
		    "Id\tVLAN\tHash\tMAC\t\t\tGUID\t\t\tCMState\t\tQP\tVersion\t\tTx Mb/s\tRx Mb/s\n");
	page +=
	    sprintf(page,
		    "==============================================================="
		    "===============================================================\n");

	for (i = vp->sindex, j = vp->jindex; i < XVE_FWT_HASH_LISTS; i++) {
		head = &xve_fwt->fwt[i];
		k = 0;
		hlist_for_each_entry_safe(fwt_entry, h, n, head, hlist) {
			/*
			 * Make sure we do not go beyond 3K (vmware limitation)
			 */
			if ((page - start_page) >= (3072 - 64)) {
				beyond_page = 1;
				/*
				* Make sure that we print the correct
				* numbers for duplicates
				*/
				j -= k;
				break;
			}

			if (xve_fwt_entry_valid(xve_fwt, fwt_entry) == true) {
				char *cmstr = "Not Connected";
				u16 printed = 0;
				struct xve_cm_ctx *tx = NULL, *rx = NULL;

				j++;
				k++;
				smac = fwt_entry->smac_addr;
				tmp_buf[0] = 0;
				print_mgid_buf(tmp_buf,
					       (char *)(fwt_entry->dgid.raw));
				if (fwt_entry->path) {
					tx = xve_cmtx_get(fwt_entry->path);
					rx = xve_cmrx_get(fwt_entry->path);
					if (tx) {
						u32 rx_rate = 0;
						if (test_bit
						    (XVE_FLAG_OPER_UP,
						     &tx->flags))
							cmstr = "Connected";
						if (rx)
							rx_rate =
							    rx->stats.rx_rate;
						page += sprintf(page,
							    "%d\t%d\t%d\t%2x:%2x:%2x:%2x:%2x:%2x\t%s\t%s\t%x\t%s\t%d\t%d\n",
							    j, fwt_entry->vlan,
							    fwt_entry->
							    hash_value,
							    ALIGN_TO_FF(smac
									[0]),
							    ALIGN_TO_FF(smac
									[1]),
							    ALIGN_TO_FF(smac
									[2]),
							    ALIGN_TO_FF(smac
									[3]),
							    ALIGN_TO_FF(smac
									[4]),
							    ALIGN_TO_FF(smac
									[5]),
							    tmp_buf + 8, cmstr,
							    tx->qp ? tx->qp->
							    qp_num : 0,
							    tx->version,
							    tx->stats.tx_rate,
							    rx_rate);
						printed = 1;
					}
				}

				if (!printed) {
					char buffer[512];
					buffer[0] = 0;
					sprintf(buffer,
						"NC Path-%s CM(Tx-%s Rx-%s) ",
						(fwt_entry->path !=
						 NULL) ? "Yes" : "No",
						(tx != NULL) ? "Yes" : "No",
						(rx != NULL) ? "Yes" : "No");
					page +=
					    sprintf(page,
						    "%d\t%d\t%d\t%2x:%2x:%2x:%2x:%2x:%2x\t%s\t%s\n",
						    j, fwt_entry->vlan,
						    fwt_entry->hash_value,
						    ALIGN_TO_FF(smac[0]),
						    ALIGN_TO_FF(smac[1]),
						    ALIGN_TO_FF(smac[2]),
						    ALIGN_TO_FF(smac[3]),
						    ALIGN_TO_FF(smac[4]),
						    ALIGN_TO_FF(smac[5]),
						    tmp_buf + 8, buffer);
				}
				xve_fwt_put_ctx(&vp->xve_fwt, fwt_entry);
			}
		}

		if (beyond_page)
			break;
	}

	if (i >= XVE_FWT_HASH_LISTS) {
		vp->sindex = 0;
		vp->jindex = 0;
		page += sprintf(page, "\n End of L2 Table\n");
	} else {
		page += sprintf(page, "\n Table incomplete\n");
		vp->sindex = i;
		vp->jindex = j;
	}
	*eof = 1;
	return page - start_page;
}

static int xve_proc_read_device(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	char *start_page = page;
	struct xve_dev_priv *vp = data;
	int i;
	unsigned long tsecs = 0, tmins = 0, thrs = 0;
	char tmp_buf[512];
	char *bcast_mgid_token = vp->bcast_mgid.raw;
	char *local_gid_token = vp->local_gid.raw;

	if (off) {
		*eof = 1;
		return 0;
	}

	if (xve_get_misc_info()) {
		if (vp->next_page) {
			for (i = 0; i < XVE_MISC_MAX_COUNTERS; i++)
				page +=
				    sprintf(page, "%s%u\n",
					    misc_counter_name[i],
					    vp->misc_counters[i]);
			vp->next_page = 0;
			goto out;
		}
	}

	page +=
	    sprintf(page, "Chassis Name:\t\t\t%s\n",
		    vp->xsmp_info.chassis_name);
	page +=
	    sprintf(page, "Chassis Version  :\t\t%x\n", vp->xsmp_info.version);
	page +=
	    sprintf(page, "Server-Profile:\t\t\t%s\n",
		    vp->xsmp_info.session_name);
	page += sprintf(page, "Config parameters:\n");
	page += sprintf(page, "Mode :\t\t\t\t%s\n", vp->mode);
	page += sprintf(page, "Netid :\t\t\t\t0x%x\n", vp->net_id);
	if (vp->qp)
		page += sprintf(page, "UD Queue pair Number(QP): \t%d\n",
			    (vp->qp->qp_num));
	else
		page += sprintf(page,
			"UD Queue pair Number(QP) Not established yet \t\t\n");

	page +=
	    sprintf(page, "PortDetails:\t\t\tPort:%d pkey:%d  pkey_index:%d\n",
		    vp->port, vp->pkey, vp->pkey_index);

	tmp_buf[0] = 0;
	print_mgid_buf(tmp_buf, bcast_mgid_token);
	page += sprintf(page, "Bcast Mgid:\t\t\t%s\n", tmp_buf);

	tmp_buf[0] = 0;
	print_mgid_buf(tmp_buf, local_gid_token);

	page += sprintf(page, "Local gid:\t\t\t%s\n", tmp_buf);
	page += sprintf(page, "MAC addr:\t\t\t0x%Lx\n", vp->mac);
	page += sprintf(page, "VID:\t\t\t\t0x%Lx\n", vp->resource_id);
	page += sprintf(page, "mtu:\t\t\t\t%d\n", vp->netdev->mtu);
	page += sprintf(page, "Admin mtu:\t\t\t%d\n", vp->admin_mtu);
	page += sprintf(page, "MCAST mtu:\t\t\t%d\n", vp->mcast_mtu);
	page += sprintf(page, "IB MAX MTU: \t\t\t%d\n", vp->max_ib_mtu);

	page += sprintf(page, "Receive Queue size: \t\t%d\n", xve_recvq_size);
	page += sprintf(page, "Transmit Queue size: \t\t%d\n", xve_sendq_size);

	if (vp->cm_supported) {
		page +=
		    sprintf(page, "Num of cm frags: \t\t%d\n",
			    vp->cm.num_frags);
		page += sprintf(page, "CM mtu  \t\t\t%d\n", vp->cm.max_cm_mtu);
	}

	page += sprintf(page, "\n");
	page += sprintf(page, "link/xsmp hndl:\t\t\t%p\n", vp->xsmp_hndl);
	page += sprintf(page, "Port link state: \t\t%s\n",
			test_bit(XVE_PORT_LINK_UP, &vp->state) ? "Up" : "Down");

	if (vp->broadcast) {
		page += sprintf(page, "Multicast Report:\n");
		page +=
		    sprintf(page, "Flag:	            \t\t%lx\n",
			    vp->broadcast->flags);
		page += sprintf(page, "join state:\t\t%s\n",
				test_bit(XVE_MCAST_FLAG_ATTACHED,
				&vp->broadcast->flags) ?
				"Joined" : "Not joined");
	} else {
		page += sprintf(page, "Multicast Not created:\n");
	}

	strcpy(tmp_buf, "None");
	if (vp->mp_flag & MP_XVE_PRIMARY) {
		strcpy(tmp_buf, "Primary");
		if (vp->mp_flag & MP_XVE_AUTO_SWITCH)
			strcat(tmp_buf, " + AutoSwitchover");
	} else if (vp->mp_flag & MP_XVE_SECONDARY) {
		strcpy(tmp_buf, "Secondary");
		if (vp->mp_flag & MP_XVE_AUTO_SWITCH)
			strcat(tmp_buf, " + AutoSwitchover");
	}

	page += sprintf(page, "HA flags:\t\t\t%s\n", tmp_buf);
	page += sprintf(page, "TSO:\t\t\t\t%s\n",
			(vp->netdev->
			 features & NETIF_F_TSO) ? "Enabled" : "Disabled");
	page +=
	    sprintf(page, "LRO:\t\t\t\t%s\n",
		    (vp->netdev->
		     features & NETIF_F_LRO) ? "Enabled" : "Disabled");

	if (test_bit(XVE_OPER_REP_SENT, &vp->state)) {

		tsecs = jiffies_to_msecs(jiffies - vp->jiffies) / 1000;
		thrs = tsecs / (60 * 60);
		tmins = (tsecs / 60 - (thrs * 60));
		tsecs = tsecs - (tmins * 60) - (thrs * 60 * 60);
	}

	page += sprintf(page, "XVE Uptime:\t\t\t%lu hrs %lu mins %lu seconds\n",
			thrs, tmins, tsecs);
	page += sprintf(page, "\n");

	page += sprintf(page, "Netdev state:\t\t\t0x%lu\n", vp->netdev->state);
	page += sprintf(page, "Netdev napi state:\t\t0x%lu\n", vp->napi.state);
	page +=
	    sprintf(page, "VNIC state:\t\t\t0x%x\n", (unsigned int)vp->state);
	page +=
	    sprintf(page, "VNIC Flag:\t\t\t0x%x\n", (unsigned int)vp->flags);

	tmp_buf[0] = 0;
	if (netif_running(vp->netdev))
		strcat(tmp_buf, "dev running");
	else
		strcat(tmp_buf, "netif not running");
	if (netif_queue_stopped(vp->netdev))
		strcat(tmp_buf, " + dev stopped");
	else
		strcat(tmp_buf, " + dev not stopped");

	page += sprintf(page, "%s\n\n", tmp_buf);

	page += sprintf(page, "Carrier state:\t\t\t%s\n",
			netif_carrier_ok(vp->netdev) ? "Up" : "Down");

	page += sprintf(page, "VNIC up:\t\t\t%s\n",
			test_bit(XVE_OPER_UP, &vp->state) ? "Yes" : "No");

	tmp_buf[0] = 0;
	if (test_bit(XVE_OPER_UP, &vp->state))
		strcat(tmp_buf, "Oper Up");
	else
		strcat(tmp_buf, "Oper Down");
	if (test_bit(XVE_OS_ADMIN_UP, &vp->state))
		strcat(tmp_buf, " + OS Admin Up");
	else
		strcat(tmp_buf, " + OS Admin Down");
	if (test_bit(XVE_PORT_LINK_UP, &vp->state))
		strcat(tmp_buf, " + Port Link Up");
	else
		strcat(tmp_buf, " + Port Link Down");
	if (test_bit(XVE_OPER_REP_SENT, &vp->state))
		strcat(tmp_buf, " + Oper Sent");
	else
		strcat(tmp_buf, " + No Oper Rep");

	if (test_bit(XVE_INTR_ENABLED, &vp->state))
		strcat(tmp_buf, " + Rx Intr Enabled");
	else
		strcat(tmp_buf, " + Rx Intr Disabled");

	if (test_bit(XVE_RX_NOBUF, &vp->state))
		strcat(tmp_buf, " + Rx No Buf");

	if (test_bit(XVE_IBLINK_DOWN, &vp->state))
		strcat(tmp_buf, " +  IB Link Down");
	else
		strcat(tmp_buf, " +  IB Link Up");

	if (test_bit(XVE_IB_DEV_OPEN, &vp->flags))
		strcat(tmp_buf, " +  IB Device Opened");
	else
		strcat(tmp_buf, " +  IB Device Not Opened");

	if (test_bit(XVE_OVER_QUOTA, &vp->state))
		strcat(tmp_buf, " +  No RX Quota");

	page += sprintf(page, "%s\n\n", tmp_buf);

	if (vp->work_queue_failed != 0)
		page += sprintf(page, "WQ Failed:\t\t\t%ld\n",
			    vp->work_queue_failed);

	page += sprintf(page, "Counters cleared count:\t\t%u\n",
		    vp->counters_cleared);
	vp->next_page = 1;
out:
	*eof = 1;
	return page - start_page;
}

static int xve_proc_write_device(struct file *file, const char *buffer,
				 unsigned long count, void *data)
{
	struct xve_dev_priv *vp = data;
	char action[64];
	unsigned long action_ul;
	int ret;

	sscanf(buffer, "%s", action);
	ret = kstrtoul(((action != NULL) ? action : ""), 0, &action_ul);

	if ((strlen(action) == 1) && (action_ul == 0)) {
		/* Clear counters */
		memset(vp->counters, 0, sizeof(vp->counters));
		vp->counters_cleared++;
		return count;
	}

	/* sscanf cannot copies spaces as in "rbatch on" so do a copy */
	memset(action, 0, sizeof(action));
	strncpy(action, buffer, 10);

	if (strcmp(action, XS_RESCHED_NAPI) == 0)
		set_bit(XVE_TRIGGER_NAPI_SCHED, &vp->state);

	return count;
}

static int xve_proc_read_device_counters(char *page, char **start, off_t off,
					 int count, int *eof, void *data)
{
	char *start_page = page;
	struct xve_dev_priv *vp = data;
	int i;

	if (off) {
		*eof = 1;
		return 0;
	}

	for (i = 0; i < XVE_MAX_COUNTERS; i++)
		page +=
		    sprintf(page, "%s%u\n", counter_name[i], vp->counters[i]);
	page +=
	    sprintf(page, "Counters cleared count:\t\t%u\n",
		    vp->counters_cleared);

	return page - start_page;
}

static int xve_proc_write_device_counters(struct file *file, const char *buffer,
					  unsigned long count, void *data)
{
	struct xve_dev_priv *vp = data;
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

static int xve_proc_read_l2_flush(char *page, char **start, off_t off,
				  int count, int *eof, void *data)
{
	char *start_page = page;

	if (off) {
		*eof = 1;
		return 0;
	}
	page += sprintf(page, "flush: Nothing to read\n");
	*eof = 1;
	return page - start_page;
}

static int xve_proc_write_l2_flush(struct file *file, const char *buffer,
				   unsigned long count, void *data)
{
	struct xve_dev_priv *priv = data;

	pr_err("%s XVE flushing l2 %s\n", __func__, priv->xve_name);
	xve_queue_work(priv, XVE_WQ_START_FLUSHNORMAL);

	return count;
}

static void *xve_seq_start(struct seq_file *seq, loff_t *pos)
{
	return (*pos < XVE_MAX_COUNTERS) ? &counter_name[*pos] : 0;
}

static void *xve_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	++*pos;
	return (*pos < XVE_MAX_COUNTERS) ? &counter_name[*pos] : 0;
}

static int xve_seq_show(struct seq_file *seq, void *v)
{
	struct xve_dev_priv *vp = seq->private;

	if (vp->ix == XVE_MAX_COUNTERS)
		vp->ix = 0;

	seq_printf(seq, "%s %u\n", counter_name[vp->ix], vp->counters[vp->ix]);
	vp->ix++;

	return 0;
}

static void xve_seq_stop(struct seq_file *seq, void *v)
{
	/* Nothing to be done here */
}

static const struct seq_operations xve_seq_ops = {
	.start = xve_seq_start,
	.next = xve_seq_next,
	.stop = xve_seq_stop,
	.show = xve_seq_show
};

static int xve_seq_open(struct inode *inode, struct file *sfile)
{
	struct seq_file *seq;
	struct proc_dir_entry *proc;
	int ret_val;

	ret_val = seq_open(sfile, &xve_seq_ops);
	if (!ret_val) {
		/* recover the pointer buried in proc_dir_entry data */
		seq = sfile->private_data;
		proc = PDE(inode);
		seq->private = proc->data;
	}

	return ret_val;
};

static const struct file_operations xve_file_ops = {
	.owner = THIS_MODULE,
	.open = xve_seq_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};

int xve_add_proc_entry(struct xve_dev_priv *vp)
{
	struct proc_dir_entry *file, *l2, *flush, *counter;
	int ret = 0;

	vp->nic_dir = xg_create_proc_entry(vp->proc_name, S_IFDIR,
					   proc_root_xve_dev, 1);

	if (!vp->nic_dir) {
		pr_err("Unable to create the xve nicentry\n");
		return -ENOMEM;
	}
	file = create_proc_entry(vp->xve_name, S_IFREG, vp->nic_dir);
	if (!file) {
		pr_err("Unable to create the xve /proc entry\n");
		ret = -ENOMEM;
		goto err_dev_entry;
	}
	SET_NLINK(file, 1);
	file->read_proc = xve_proc_read_device;
	file->write_proc = xve_proc_write_device;
	SET_OWNER(file);
	file->data = (void *)vp;

	counter = create_proc_entry("counters", S_IFREG, vp->nic_dir);
	if (!counter) {
		pr_err("Unable to create the xve /proc entry\n");
		return -ENOMEM;
		goto err_counter;
	}
	SET_NLINK(file, 1);
	if (xs_seq_file) {
		if (counter) {
			/* Using proc seq_file for OVM */
			counter->proc_fops = &xve_file_ops;
		}
	} else
		counter->read_proc = xve_proc_read_device_counters;
	counter->write_proc = xve_proc_write_device_counters;
	SET_OWNER(counter);
	counter->data = (void *)vp;

	l2 = create_proc_entry("l2table", S_IFREG, vp->nic_dir);
	if (!l2) {
		pr_err("Unable to create the xve /proc l2 entry\n");
		ret = -ENOMEM;
		goto err_l2table;
	}
	SET_NLINK(l2, 1);
	l2->read_proc = xve_proc_l2_read_device;
	l2->write_proc = 0;
	SET_OWNER(l2);
	l2->data = (void *)vp;

	/*
	 * Create flush entry
	 */
	flush = create_proc_entry("flush_l2", S_IFREG, vp->nic_dir);
	if (!flush) {
		pr_err("Unable to create the xve /proc flush entry\n");
		ret = -ENOMEM;
		goto err_flush;
	}
	SET_NLINK(flush, 1);
	flush->write_proc = xve_proc_write_l2_flush;
	flush->read_proc = xve_proc_read_l2_flush;
	SET_OWNER(flush);
	flush->data = (void *)vp;

	return 0;
err_counter:
	remove_proc_entry("counters", vp->nic_dir);
err_flush:
	remove_proc_entry("l2table", vp->nic_dir);
err_l2table:
	remove_proc_entry(vp->xve_name, vp->nic_dir);
err_dev_entry:
	remove_proc_entry(vp->proc_name, proc_root_xve_dev);
	return ret;
}

void xve_remove_proc_entry(struct xve_dev_priv *vp)
{
	remove_proc_entry("counters", vp->nic_dir);
	remove_proc_entry("flush_l2", vp->nic_dir);
	remove_proc_entry("l2table", vp->nic_dir);
	remove_proc_entry(vp->xve_name, vp->nic_dir);
	remove_proc_entry(vp->proc_name, proc_root_xve_dev);
}

static int xve_proc_write_debug(struct file *file, const char *buffer,
				unsigned long count, void *data)
{
	int newval;

	sscanf(buffer, "%x", &newval);
	xve_debug_level = newval;
	return count;
}

static int xve_proc_read_debug(char *page, char **start, off_t off, int count,
			       int *eof, void *data)
{
	int i;
	char *start_page = page;

	if (off) {
		*eof = 1;
		return 0;
	}
	page += sprintf(page, "Debug bitmask: 0x%x\n\n", xve_debug_level);
	for (i = 0; i < XVE_MAX_GLOB_COUNTERS; i++)
		page += sprintf(page, "%s%d\n", glob_counter_name[i],
			    xve_counters[i]);
	*eof = 1;
	return page - start_page;
}

int xve_create_procfs_root_entries(void)
{
	struct proc_dir_entry *debug_file;
	int ret = 0;

	proc_root_xve =
	    xg_create_proc_entry("driver/xve", S_IFDIR, PROC_ROOT, 0);

	if (!proc_root_xve) {
		pr_err("Unable to create /proc/driver/xve\n");
		return -ENOMEM;
	}

	proc_root_xve_dev = xg_create_proc_entry("devices", S_IFDIR,
						 proc_root_xve, 1);
	if (!proc_root_xve_dev) {
		pr_err("Unable to create /proc/driver/xve/devices\n");
		ret = -ENOMEM;
		goto create_proc_end_1;
	}
	debug_file = create_proc_entry("debug", S_IFREG, proc_root_xve);
	if (!debug_file) {
		pr_err("Unable to create /proc/driver/xve/debug\n");
		ret = -ENOMEM;
		goto create_proc_end_2;
	}
	SET_NLINK(debug_file, 1);
	debug_file->read_proc = xve_proc_read_debug;
	debug_file->write_proc = xve_proc_write_debug;
	SET_OWNER(debug_file);

	return 0;

create_proc_end_2:
	remove_proc_entry("devices", proc_root_xve_dev);
create_proc_end_1:
	remove_proc_entry("driver/xve", PROC_ROOT);

	return ret;
}

void xve_remove_procfs_root_entries(void)
{
	remove_proc_entry("debug", proc_root_xve);
	remove_proc_entry("devices", proc_root_xve);
	xg_remove_proc_entry("driver/xve", PROC_ROOT);
}
