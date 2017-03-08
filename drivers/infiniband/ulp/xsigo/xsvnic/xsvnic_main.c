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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <asm/byteorder.h>
#include <linux/mii.h>
#include <linux/tcp.h>
#include <linux/if_arp.h>
#include <linux/if_vlan.h>
#include <linux/netdevice.h>
#include "xsvnic.h"
#include "xscore.h"
#include <xs_compat.h>

MODULE_AUTHOR("Oracle corp (OVN-linux-drivers@oracle.com)");
MODULE_DESCRIPTION("OVN XSVNIC network driver");
MODULE_VERSION(XSVNIC_DRIVER_VERSION);
MODULE_LICENSE("Dual BSD/GPL");

#ifndef NETIF_F_LRO
#define NETIF_F_LRO        NETIF_F_SW_LRO
#endif
static int napi_weight = 64;
module_param(napi_weight, int, 0644);

static int xsigo_session_service_id = -1;
static int xsvnic_havnic = 1;
module_param(xsvnic_havnic, int, 0644);

int xsvnic_debug = 0x0;
module_param(xsvnic_debug, int, 0644);

static int xsvnic_force_csum_offload = 0x0;
module_param(xsvnic_force_csum_offload, int, 0644);

/*lro specifics*/
int lro;
static int lro_max_aggr = XSVNIC_LRO_MAX_AGGR;
module_param(lro, int, 0444);
module_param(lro_max_aggr, int, 0644);
MODULE_PARM_DESC(lro, "Enable LRO (Large Receive Offload)");
MODULE_PARM_DESC(lro_max_aggr,
		 "LRO: Max packets to be aggregated (default = 64)");

static int multicast_list_disable;
module_param(multicast_list_disable, int, 0644);

static int xsvnic_hbeat_enable = 2;
module_param(xsvnic_hbeat_enable, int, 0644);

int xsvnic_rxring_size = 2048;
module_param(xsvnic_rxring_size, int, 0444);

int xsvnic_txring_size = 2048;
module_param(xsvnic_txring_size, int, 0444);

int xsvnic_highdma;
module_param(xsvnic_highdma, int, 0644);

int xsvnic_vlanaccel;
module_param(xsvnic_vlanaccel, int, 0644);

int xsvnic_rxbatching = 1;
module_param(xsvnic_rxbatching, int, 0644);

int xsvnic_report_10gbps;
module_param(xsvnic_report_10gbps, int, 0644);

int xsvnic_reclaim_count = XSVNIC_RECLAIM_COUNT;
module_param(xsvnic_reclaim_count, int, 0644);

int xsvnic_tx_queue_len = 1000;
module_param(xsvnic_tx_queue_len, int, 0644);

int xsvnic_tx_intr_mode = 1;
module_param(xsvnic_tx_intr_mode, int, 0644);

int xsvnic_max_coal_frames;
module_param(xsvnic_max_coal_frames, int, 0644);

int xsvnic_coal_usecs = 100;
module_param(xsvnic_coal_usecs, int, 0644);

int xsvnic_rx_intr_mode;
module_param(xsvnic_rx_intr_mode, int, 0644);

int xsvnic_wait_in_boot = 1;
module_param(xsvnic_wait_in_boot, int, 0644);

int xsvnic_wait_per_vnic = 30;
module_param(xsvnic_wait_per_vnic, int, 0644);

unsigned long xsvnic_wait_time;
static int xsvnic_xsmp_service_id = -1;
struct list_head xsvnic_list;
static spinlock_t xsvnic_lock;
struct mutex xsvnic_mutex;
static struct workqueue_struct *xsvnic_wq;
static struct workqueue_struct *xsvnic_io_wq;
u32 xsvnic_counters[XSVNIC_MAX_GLOB_COUNTERS];

static void queue_sm_work(struct xsvnic *xsvnicp, int msecs);
static void _xsvnic_set_multicast(struct xsvnic *xsvnicp);
static void xsvnic_send_msg_to_xsigod(xsmp_cookie_t xsmp_hndl, void *data,
				      int len);
static int xsvnic_remove_vnic(struct xsvnic *xsvnicp);
static void xsvnic_send_cmd_to_xsigod(struct xsvnic *xsvnicp, int cmd);
static void xsvnic_reclaim_tx_buffers(struct xsvnic *xsvnicp);
static void handle_ring_size_change(struct xsvnic *xsvnicp);
static void handle_rxbatch_change(struct xsvnic *xsvnicp);
static int xsvnic_start_xmit(struct sk_buff *skb, struct net_device *netdev);
static void xsvnic_update_oper_state(struct xsvnic *xsvnicp);
static void xsvnic_update_tca_info(struct xsvnic *xsvnicp,
				   struct xsvnic_xsmp_msg *xmsgp,
				   int set_oper_down);
char *xsvnic_get_rxbat_pkts(struct xsvnic *xsvnicp, int *curr_seg_len,
			    char *start, char *is_last_pkt, int total_pkt_len);

static inline int xsvnic_esx_preregister_setup(struct net_device *netdev)
{
	return 0;
}

static inline int xsvnic_esx_postregister_setup(struct net_device *netdev)
{
	return 0;
}

static inline void vmk_notify_uplink(struct net_device *netdev)
{
}

static inline void xsvnic_process_pages(struct xsvnic *xsvnicp,
					struct xscore_buf_info *binfo)
{
	struct page *page;
	struct sk_buff *skb;
	int tot_pkt_len, hdr_len, curr_pkt_len, page_offset = 0;
	char *start, *copy_start;
	char nr_segs = 0, is_last_seg = 1;

	tot_pkt_len = binfo->sz;
	page = binfo->cookie;
	start = page_address(page) + page_offset;

	do {
		curr_pkt_len = 0;
		copy_start = xsvnic_get_rxbat_pkts(xsvnicp, &curr_pkt_len,
						   start, &is_last_seg,
						   tot_pkt_len);

		hdr_len = min((int)(XSVNIC_MIN_PACKET_LEN), curr_pkt_len);
		skb = dev_alloc_skb(hdr_len + NET_IP_ALIGN);
		if (!skb) {
			pr_err("XSVNIC: %s unable to allocate skb\n", __func__);
			put_page(page);
			break;
		}
		skb_reserve(skb, NET_IP_ALIGN);
		memcpy(skb->data, copy_start, hdr_len);

		skb_fill_page_desc(skb, 0, page,
				   page_offset + hdr_len + XS_RXBAT_HDRLEN,
				   curr_pkt_len - hdr_len);

		skb->data_len = curr_pkt_len - hdr_len;
		skb->len += curr_pkt_len;
		skb->tail += hdr_len;

		if (!is_last_seg) {
			start = copy_start + curr_pkt_len;
			page_offset += XS_RXBAT_HDRLEN + curr_pkt_len +
			    xsvnic_align_addr(&start);
			get_page(page);
		}

		xsvnic_send_skb(xsvnicp, skb, curr_pkt_len, 0);
		nr_segs++;
	} while (!is_last_seg);

	xsvnic_count_segs(xsvnicp, nr_segs, tot_pkt_len);
}

static inline void xsvnic_dev_kfree_skb_any(struct sk_buff *skb)
{
	if (skb != NULL)
		dev_kfree_skb_any(skb);
	else
		pr_err("%s Error skb is null\n", __func__);
}

/*
 * All XSMP related protocol messages
 */

static void xsvnic_put_ctx(struct xsvnic *xsvnicp)
{
	atomic_dec(&xsvnicp->ref_cnt);
}

static int xsvnic_xsmp_send_msg(xsmp_cookie_t xsmp_hndl, void *data, int length)
{
	struct xsmp_message_header *m_header = data;
	int ret;

	m_header->length = cpu_to_be16(m_header->length);
	ret = xcpm_send_message(xsmp_hndl, xsvnic_xsmp_service_id, data,
				length);
	if (ret)
		xcpm_free_msg(data);
	return ret;
}

static int xsvnic_xsmp_send_ack(xsmp_cookie_t xsmp_hndl,
				struct xsvnic_xsmp_msg *xmsgp)
{
	void *msg;
	struct xsmp_message_header *m_header;
	int total_len = sizeof(*xmsgp) + sizeof(*m_header);

	msg = xcpm_alloc_msg(total_len);
	if (!msg)
		return -ENOMEM;
	m_header = (struct xsmp_message_header *)msg;
	m_header->type = XSMP_MESSAGE_TYPE_VNIC;
	m_header->length = total_len;

	xmsgp->code = 0;

	memcpy(msg + sizeof(*m_header), xmsgp, sizeof(*xmsgp));

	return xsvnic_xsmp_send_msg(xsmp_hndl, msg, total_len);
}

static int xsvnic_xsmp_send_nack(xsmp_cookie_t xsmp_hndl, void *data,
				 int length, u8 code)
{
	void *msg;
	struct xsmp_message_header *m_header;
	int total_len = length + sizeof(struct xsmp_message_header);
	struct xsvnic_xsmp_msg *xsmsgp = (struct xsvnic_xsmp_msg *)data;

	msg = xcpm_alloc_msg(total_len);
	if (!msg)
		return -ENOMEM;
	m_header = (struct xsmp_message_header *)msg;
	m_header->type = XSMP_MESSAGE_TYPE_VNIC;
	m_header->length = total_len;

	xsmsgp->code = XSMP_XSVNIC_NACK | code;
	memcpy(msg + sizeof(*m_header), data, length);
	return xsvnic_xsmp_send_msg(xsmp_hndl, msg, total_len);
}

static int xsvnic_xsmp_send_notification(xsmp_cookie_t xsmp_hndl, u64 vid,
					 int notifycmd)
{
	int length = sizeof(struct xsmp_message_header) +
	    sizeof(struct xsvnic_xsmp_msg);
	void *msg;
	struct xsmp_message_header *header;
	struct xsvnic_xsmp_msg *xsmp_msg;

	msg = xcpm_alloc_msg(length);
	if (!msg)
		return -ENOMEM;

	memset(msg, 0, length);

	header = (struct xsmp_message_header *)msg;
	xsmp_msg = (struct xsvnic_xsmp_msg *)(msg + sizeof(*header));

	header->type = XSMP_MESSAGE_TYPE_VNIC;
	header->length = length;

	xsmp_msg->type = notifycmd;
	xsmp_msg->length = cpu_to_be16(sizeof(*xsmp_msg));
	xsmp_msg->resource_id = cpu_to_be64(vid);

	return xsvnic_xsmp_send_msg(xsmp_hndl, msg, length);
}

static int xsvnic_xsmp_send_ha_state(struct xsvnic *xsvnicp, int ha_state)
{
	struct xsmp_message_header *header;
	void *msg;
	struct xsvnic_ha_info_msg *ha_info_msgp;
	int length = sizeof(struct xsmp_message_header) +
	    sizeof(struct xsvnic_ha_info_msg);

	msg = xcpm_alloc_msg(length);
	if (!msg)
		return -ENOMEM;

	memset(msg, 0, length);
	header = (struct xsmp_message_header *)msg;
	header->type = XSMP_MESSAGE_TYPE_VNIC;
	header->length = length;
	ha_info_msgp = msg + sizeof(struct xsmp_message_header);
	ha_info_msgp->type = XSMP_XSVNIC_HA_INFO;
	ha_info_msgp->length = cpu_to_be16(sizeof(*ha_info_msgp));
	ha_info_msgp->resource_id = cpu_to_be64(xsvnicp->resource_id);
	ha_info_msgp->ha_state = ha_state;
	return xsvnic_xsmp_send_msg(xsvnicp->xsmp_hndl, msg, length);
}

static int xsvnic_xsmp_send_oper_state(struct xsvnic *xsvnicp,
				       u64 vid, int state)
{
	int ret;
	xsmp_cookie_t xsmp_hndl = xsvnicp->xsmp_hndl;
	char *str = state == XSMP_XSVNIC_OPER_UP ? "UP" : "DOWN";

	ret = xsvnic_xsmp_send_notification(xsmp_hndl, vid, state);
	switch (state) {
	case XSMP_XSVNIC_OPER_UP:
		xsvnicp->counters[XSVNIC_SENT_OPER_UP_COUNTER]++;
		break;
	case XSMP_XSVNIC_OPER_DOWN:
		xsvnicp->counters[XSVNIC_SENT_OPER_DOWN_COUNTER]++;
		break;
	}
	if (ret) {
		xsvnicp->counters[XSVNIC_SENT_OPER_STATE_FAILURE_COUNTER]++;
		XSMP_INFO("%s:Oper %s notification failed for", __func__, str);
		XSMP_INFO("resource_id: 0x%Lx\n", vid);
	} else {
		xsvnicp->counters[XSVNIC_SENT_OPER_STATE_SUCCESS_COUNTER]++;
		XSMP_INFO("%s:Oper %s notification succeeded ", __func__, str);
		XSMP_INFO("for resource_id: 0x%Lx\n", vid);
	}

	return ret;
}

/*
 * Handle all IO path messaging here
 * Called with mutex held
 */
static int xsvnic_send_start_stop(struct xsvnic *xsvnicp, int opcode)
{
	struct xsvnic_control_msg *header;
	int len = sizeof(*header);
	int ret;

	if (xsvnicp->ctrl_conn.state != XSVNIC_CONN_CONNECTED)
		return -ENOTCONN;
	header = kmalloc(len, GFP_ATOMIC);
	if (!header)
		return -ENOMEM;

	header->type = opcode;
	/*
	 * Bug here where it needs to be swapped
	 */
	header->length = sizeof(*header);
	/*
	 * This is called with interrupts not disabled
	 */
	ret = xscore_post_send(&xsvnicp->ctrl_conn.ctx, header, len, 0);
	if (ret)
		kfree(header);
	if (opcode == XSVNIC_START_RX)
		xsvnicp->counters[XSVNIC_START_RX_COUNTER]++;
	else
		xsvnicp->counters[XSVNIC_STOP_RX_COUNTER]++;
	return ret;
}

static int xsvnic_send_vlan_list(struct xsvnic *xsvnicp, u16 *vlanp, int count,
				 int opcode)
{
	u8 *msg;
	struct xsvnic_control_msg *header;
	u16 *vp;
	int len, i;
	int ret;

	if (xsvnicp->ctrl_conn.state != XSVNIC_CONN_CONNECTED)
		return -ENOTCONN;
	len = sizeof(*header) + (count * sizeof(u16));
	msg = kmalloc(len, GFP_ATOMIC);
	if (!msg)
		return -ENOMEM;
	vp = (u16 *) (msg + sizeof(*header));
	for (i = 0; i < count; i++)
		*vp++ = cpu_to_be16(*vlanp++);
	header = (struct xsvnic_control_msg *)msg;
	header->type = opcode;
	header->length = cpu_to_be16(len);
	ret = xscore_post_send(&xsvnicp->ctrl_conn.ctx, msg, len,
			       XSCORE_DEFER_PROCESS);
	if (ret)
		kfree(msg);
	return ret;
}

static int xsvnic_send_allvlan_list(struct xsvnic *xsvnicp)
{
	int count = xsvnicp->vlan_count;
	u16 *vlan_listp, *vp;
	struct vlan_entry *vlan;
	int ret;

	if (count == 0)
		return 0;

	vlan_listp = kmalloc_array(count, sizeof(u16), GFP_ATOMIC);
	if (!vlan_listp)
		return -ENOMEM;
	vp = vlan_listp;
	list_for_each_entry(vlan, &xsvnicp->vlan_list, vlan_list)
		* vp++ = vlan->vlan_id;
	ret = xsvnic_send_vlan_list(xsvnicp, vlan_listp, count,
				    XSVNIC_ASSIGN_VLAN);
	kfree(vlan_listp);
	return ret;
}

/*
 * Called with spin lock held
 */

static int xsvnic_send_multicast_list(struct xsvnic *xsvnicp, u8 *msg, int len,
				      int promisc)
{
	int ret;
	struct xsvnic_control_msg *header;

	header = (struct xsvnic_control_msg *)msg;
	header->type = XSVNIC_MULTICAST_LIST_SEND;
	/*
	 * This is a bug, needs swapping unfortunately the bug is in
	 * xvnd code and we need to carry the bug forward for backward
	 * compatibility
	 */
	header->length = len;
	header->data = promisc;
	clear_bit(XSVNIC_MCAST_LIST_TIMEOUT, &xsvnicp->state);
	ret = xscore_post_send(&xsvnicp->ctrl_conn.ctx, msg, len,
			       XSCORE_DEFER_PROCESS);
	if (ret) {
		kfree(msg);
		return ret;
	} else
		set_bit(XSVNIC_MCAST_LIST_SENT, &xsvnicp->state);
	return 0;
}

static void handle_port_link_change(struct xsvnic *xsvnicp, int linkup)
{
	if (linkup) {
		set_bit(XSVNIC_PORT_LINK_UP, &xsvnicp->state);
		netif_carrier_on(xsvnicp->netdev);
		netif_wake_queue(xsvnicp->netdev);
	} else {
		clear_bit(XSVNIC_PORT_LINK_UP, &xsvnicp->state);
		netif_carrier_off(xsvnicp->netdev);
		netif_stop_queue(xsvnicp->netdev);
	}
}

static int speed_arr[] = { 0, 100, 10, 20, 500, 800, 1000, 2000, 3000, 4000,
	5000, 6000, 7000, 8000, 9000, 10000
};

static int xsvnic_convert_speed(int sp)
{
	if (sp < 0 || sp >= (sizeof(speed_arr) / sizeof(int)))
		return 1000;
	return speed_arr[sp];
}

static void handle_vnic_control_msgs(struct work_struct *work)
{
	struct xsvnic_work *xwork = container_of(work, struct xsvnic_work,
						 work);
	struct xsvnic *xsvnicp = xwork->xsvnicp;
	struct xsvnic_control_msg *header =
	    (struct xsvnic_control_msg *)xwork->msg;
	struct xsvnic_start_rx_resp_msg *resp;
	struct xsvnic_link_up_msg *linkp;
	unsigned long flags;

	switch (header->type) {
	case XSVNIC_START_RX_RESPONSE:
		IOCTRL_INFO("VNIC: %s Start Rx Response\n", xsvnicp->vnic_name);
		resp = (struct xsvnic_start_rx_resp_msg *)&header->data;
		if (test_bit(XSVNIC_START_RX_SENT, &xsvnicp->state) &&
		    !test_bit(XSVNIC_START_RESP_RCVD, &xsvnicp->state)) {
			xsvnicp->counters[XSVNIC_START_RX_RESP_COUNTER]++;
			set_bit(XSVNIC_START_RESP_RCVD, &xsvnicp->state);
			xsvnicp->port_speed =
			    xsvnic_convert_speed(resp->port_speed);
			xsvnicp->jiffies = jiffies;
			pr_info("XSVNIC: %s Port Speed %d Mbps\n",
				xsvnicp->vnic_name, xsvnicp->port_speed);
			/*
			 * Alright port is UP now enable carrier state
			 */
			if (test_bit(XSVNIC_PORT_LINK_UP, &xsvnicp->state))
				handle_port_link_change(xsvnicp, 1);
			complete(&xsvnicp->done);
		} else
			xsvnicp->counters[XSVNIC_BAD_RX_RESP_COUNTER]++;
		break;
	case XSVNIC_LINK_UP:
		if (!test_bit(XSVNIC_PORT_LINK_UP, &xsvnicp->state)) {
			linkp = (struct xsvnic_link_up_msg *)&header->data;
			xsvnicp->port_speed =
			    xsvnic_convert_speed(linkp->port_speed);
			handle_port_link_change(xsvnicp, 1);
			xsvnicp->counters[XSVNIC_PORT_LINK_UP_COUNTER]++;
			pr_info("XSVNIC: %s Link Up, speed: %d Mbps\n",
				xsvnicp->vnic_name, xsvnicp->port_speed);
		} else {
			xsvnicp->counters[XSVNIC_DUP_PORT_LINK_UP_COUNTER]++;
			IOCTRL_INFO("VNIC: %s Duplicate Link Up message\n",
				    xsvnicp->vnic_name);
		}
		break;
	case XSVNIC_LINK_DOWN:
		if (test_bit(XSVNIC_PORT_LINK_UP, &xsvnicp->state)) {
			handle_port_link_change(xsvnicp, 0);
			xsvnicp->counters[XSVNIC_PORT_LINK_DOWN_COUNTER]++;
			pr_info("XSVNIC: %s Link Down (Eth)\n",
				xsvnicp->vnic_name);
		} else {
			xsvnicp->counters[XSVNIC_DUP_PORT_LINK_DOWN_COUNTER]++;
			IOCTRL_INFO("VNIC: %s Duplicate Link Down message\n",
				    xsvnicp->vnic_name);
		}
		break;
	case XSVNIC_MULTICAST_LIST_RESPONSE:
		spin_lock_irqsave(&xsvnicp->lock, flags);
		clear_bit(XSVNIC_MCAST_LIST_SENT, &xsvnicp->state);
		clear_bit(XSVNIC_MCAST_LIST_TIMEOUT, &xsvnicp->state);
		xsvnicp->counters[XSVNIC_MCAST_LIST_RESP_COUNTER]++;
		if (test_and_clear_bit(XSVNIC_MCAST_LIST_PENDING,
				       &xsvnicp->state))
			_xsvnic_set_multicast(xsvnicp);
		spin_unlock_irqrestore(&xsvnicp->lock, flags);
		break;
	default:
		IOCTRL_ERROR("VNIC: %s Unknown message type %d\n",
			     xsvnicp->vnic_name, header->type);
		break;
	}
	kfree(xwork->msg);
	kfree(xwork);
	xsvnic_put_ctx(xsvnicp);
}

static void xsvnic_set_oper_down(struct xsvnic *xsvnicp, int lock)
{
	unsigned long flags = 0;

	if (lock)
		spin_lock_irqsave(&xsvnicp->lock, flags);
	if (test_and_clear_bit(XSVNIC_OPER_UP, &xsvnicp->state)) {
		netif_carrier_off(xsvnicp->netdev);
		netif_stop_queue(xsvnicp->netdev);
		clear_bit(XSVNIC_START_RX_SENT, &xsvnicp->state);
		clear_bit(XSVNIC_START_RESP_RCVD, &xsvnicp->state);
		clear_bit(XSVNIC_PORT_LINK_UP, &xsvnicp->state);
		clear_bit(XSVNIC_OPER_UP, &xsvnicp->state);
		clear_bit(XSVNIC_MCAST_LIST_SENT, &xsvnicp->state);
		clear_bit(XSVNIC_MCAST_LIST_PENDING, &xsvnicp->state);
		clear_bit(XSVNIC_OVER_QUOTA, &xsvnicp->state);
		xsvnicp->ctrl_conn.state = XSVNIC_CONN_ERROR;
		xsvnicp->data_conn.state = XSVNIC_CONN_ERROR;
		xsvnic_xsmp_send_oper_state(xsvnicp, xsvnicp->resource_id,
					    XSMP_XSVNIC_OPER_DOWN);
		xsvnicp->ha_state = XSVNIC_HA_STATE_UNKNOWN;
	}
	if (lock)
		spin_unlock_irqrestore(&xsvnicp->lock, flags);
}

static void xsvnic_ctrl_send_handler(void *client_arg, void *msg, int status,
				     int n)
{
	struct xsvnic *xsvnicp = client_arg;

	IOCTRL_INFO("%s:Send Status %d, vnic: %s\n", __func__, status,
		    xsvnicp->vnic_name);
	if (status) {
		IOCTRL_ERROR("VNIC: %s Ctrl Send Completion error: %d\n",
			     xsvnicp->vnic_name, status);
		xsvnicp->counters[XSVNIC_QP_ERROR_COUNTER]++;
		xsvnic_set_oper_down(xsvnicp, 1);
	}
	kfree(msg);
}

/*
 * Called from interrupt context
 */
static void xsvnic_ctrl_recv_handler(void *client_arg, void *msg, int sz,
				     int status, int n)
{
	struct xsvnic *xsvnicp = client_arg;
	struct xsvnic_work *work;
	unsigned long flags;

	if (status) {
		IOCTRL_ERROR("%s: Recv Completion error: status %d\n",
			     xsvnicp->vnic_name, status);
		xsvnicp->counters[XSVNIC_CTRL_RECV_ERR_COUNTER]++;
		xsvnic_set_oper_down(xsvnicp, 1);
		kfree(msg);
		return;
	}
	work = kmalloc(sizeof(*work), GFP_ATOMIC);
	if (!work) {
		kfree(msg);
		return;
	}
	INIT_WORK(&work->work, handle_vnic_control_msgs);
	work->xsvnicp = xsvnicp;
	work->msg = msg;
	work->len = sz;
	work->status = status;

	spin_lock_irqsave(&xsvnicp->lock, flags);
	if (!test_bit(XSVNIC_DELETING, &xsvnicp->state)) {
		atomic_inc(&xsvnicp->ref_cnt);
		queue_work(xsvnic_io_wq, &work->work);
	} else {
		kfree(msg);
		kfree(work);
	}
	spin_unlock_irqrestore(&xsvnicp->lock, flags);
}

/*
 * Data is pending, in interrupt context
 */
static void xsvnic_data_recv_handler(void *client_arg)
{
	struct xsvnic *xsvnicp = client_arg;
	unsigned long flags;

	spin_lock_irqsave(&xsvnicp->lock, flags);
	if (test_bit(XSVNIC_OS_ADMIN_UP, &xsvnicp->state) &&
	    test_bit(XSVNIC_CHASSIS_ADMIN_UP, &xsvnicp->state) &&
	    test_bit(XSVNIC_OPER_UP, &xsvnicp->state) &&
	    !test_bit(XSVNIC_DELETING, &xsvnicp->state)) {
		xsvnicp->counters[XSVNIC_NAPI_SCHED_COUNTER]++;
		clear_bit(XSVNIC_INTR_ENABLED, &xsvnicp->state);
		napi_schedule(&xsvnicp->napi);
	} else
		xsvnicp->counters[XSVNIC_NAPI_NOTSCHED_COUNTER]++;
	spin_unlock_irqrestore(&xsvnicp->lock, flags);
}

static inline void xsvnic_conn_disconnect(struct xsvnic *xsvnicp,
					  struct xsvnic_conn *conn)
{
	conn->state = XSVNIC_CONN_DISCONNECTED;
	/*
	 * Whenever we call xscore_conn_disconnect,
	 * make sure there are no mutexes held
	 */
	mutex_unlock(&xsvnicp->mutex);
	xscore_conn_disconnect(&conn->ctx, 0);
	mutex_lock(&xsvnicp->mutex);
}

static void xsvnic_io_disconnect(struct xsvnic *xsvnicp)
{
	xsvnic_set_oper_down(xsvnicp, 1);
	if (test_bit(XSVNIC_OS_ADMIN_UP, &xsvnicp->state))
		napi_synchronize(&xsvnicp->napi);
	xsvnic_conn_disconnect(xsvnicp, &xsvnicp->ctrl_conn);
	xsvnic_conn_disconnect(xsvnicp, &xsvnicp->data_conn);
	if (test_bit(XSVNIC_RING_SIZE_CHANGE, &xsvnicp->state))
		handle_ring_size_change(xsvnicp);
	if (test_bit(XSVNIC_RXBATCH_CHANGE, &xsvnicp->state))
		handle_rxbatch_change(xsvnicp);
}

static int xsvnic_send_data_hbeat(struct xsvnic *xsvnicp)
{
	struct sk_buff *skb;
	struct arphdr *arp;
	unsigned char *arp_ptr, *eth_ptr;
	int ret;

	skb = alloc_skb(XSVNIC_MIN_PACKET_LEN, GFP_ATOMIC);
	if (skb == NULL)
		return -ENOMEM;

	eth_ptr = (unsigned char *)skb_put(skb, XSVNIC_MIN_PACKET_LEN);
	ether_addr_copy(eth_ptr, xsvnicp->netdev->dev_addr);
	eth_ptr += ETH_ALEN;
	ether_addr_copy(eth_ptr, xsvnicp->netdev->dev_addr);
	eth_ptr += ETH_ALEN;
	*eth_ptr++ = (ETH_P_RARP >> 8) & 0xff;
	*eth_ptr++ = ETH_P_RARP & 0xff;

	arp = (struct arphdr *)eth_ptr;
	arp->ar_hrd = htons(xsvnicp->netdev->type);
	arp->ar_hln = xsvnicp->netdev->addr_len;
	arp->ar_pln = 4;
	arp->ar_op = htons(ARPOP_RREPLY);

	arp_ptr = (unsigned char *)(arp + 1);

	ether_addr_copy(arp_ptr, xsvnicp->netdev->dev_addr);
	arp_ptr += xsvnicp->netdev->addr_len;
	arp_ptr += 4;
	ether_addr_copy(arp_ptr, xsvnicp->netdev->dev_addr);

	skb_reset_network_header(skb);
	skb->dev = xsvnicp->netdev;
	skb->protocol = htons(ETH_P_RARP);

	ret = xsvnic_start_xmit(skb, xsvnicp->netdev);
	if (ret)
		dev_kfree_skb_any(skb);

	return 0;
}

static int xsvnic_send_ctrl_hbeat(struct xsvnic *xsvnicp)
{
	struct xsmp_message_header *header;
	int ret;

	header = kmalloc(sizeof(*header), GFP_ATOMIC);
	if (!header)
		return -ENOMEM;
	header->type = XSVNIC_HEART_BEAT;
	header->length = sizeof(*header);
	ret = xscore_post_send(&xsvnicp->ctrl_conn.ctx, header,
			       sizeof(*header), 0);
	if (ret)
		kfree(header);
	return ret;
}

/*
 * Send heartbeat over control channel or data channel
 */
static int xsvnic_send_hbeat(struct xsvnic *xsvnicp)
{
	int ret = 0;

	if (!xsvnic_hbeat_enable)
		return 0;
	if (xsvnic_hbeat_enable == 1) {
		ret = xsvnic_send_ctrl_hbeat(xsvnicp);
		xsvnicp->counters[XSVNIC_CTRL_HBEAT_COUNTER]++;
	} else {
		xsvnic_send_data_hbeat(xsvnicp);
		xsvnicp->counters[XSVNIC_DATA_HBEAT_COUNTER]++;
	}
	return ret;
}

static void handle_ha_sm(struct xsvnic *xsvnicp)
{
	if ((xsvnicp->mp_flag & (MP_XSVNIC_PRIMARY |
		MP_XSVNIC_SECONDARY)) == 0) {
		xsvnicp->ha_state = XSVNIC_HA_STATE_ACTIVE;
		return;
	}
	/*
	 * Check HA state and send update if things have changed
	 */
	if (xsvnicp->ha_state == XSVNIC_HA_STATE_UNKNOWN) {
		xsvnicp->ha_state = test_bit(XSVNIC_STATE_STDBY,
					     &xsvnicp->state)
		    ? XSVNIC_HA_STATE_STANDBY : XSVNIC_HA_STATE_ACTIVE;
		xsvnic_xsmp_send_ha_state(xsvnicp, xsvnicp->ha_state);
	} else if (xsvnicp->ha_state == XSVNIC_HA_STATE_ACTIVE &&
		   (test_bit(XSVNIC_STATE_STDBY, &xsvnicp->state))) {
		xsvnicp->ha_state = XSVNIC_HA_STATE_STANDBY;
		xsvnic_xsmp_send_ha_state(xsvnicp, xsvnicp->ha_state);
	} else if (xsvnicp->ha_state == XSVNIC_HA_STATE_STANDBY &&
		   (!test_bit(XSVNIC_STATE_STDBY, &xsvnicp->state))) {
		xsvnicp->ha_state = XSVNIC_HA_STATE_ACTIVE;
		xsvnic_xsmp_send_ha_state(xsvnicp, xsvnicp->ha_state);
	}
}

static void handle_hbeat_sm(struct xsvnic *xsvnicp)
{
	unsigned long flags;
	/*
	 * Send heartbeat if send_hbeat_flag is set
	 */
	if (xsvnicp->send_hbeat_flag) {
		spin_lock_irqsave(&xsvnicp->lock, flags);
		xsvnic_reclaim_tx_buffers(xsvnicp);
		spin_unlock_irqrestore(&xsvnicp->lock, flags);
		if (xsvnicp->ha_state == XSVNIC_HA_STATE_ACTIVE
		    && xsvnic_send_hbeat(xsvnicp)) {
			xsvnicp->counters[XSVNIC_HBEAT_ERR_COUNTER]++;
			xsvnic_set_oper_down(xsvnicp, 1);
		}
	}
	xsvnicp->send_hbeat_flag = 1;
}

static void handle_ring_size_change(struct xsvnic *xsvnicp)
{
	int ret;

	clear_bit(XSVNIC_RING_SIZE_CHANGE, &xsvnicp->state);
	/*
	 * Now destroy ctx
	 */
	xscore_conn_destroy(&xsvnicp->data_conn.ctx);
	xsvnicp->data_conn.ctx.rx_ring_size = xsvnicp->rx_ring_size;
	xsvnicp->data_conn.ctx.tx_ring_size = xsvnicp->tx_ring_size;

	ret = xscore_conn_init(&xsvnicp->data_conn.ctx,
			       xsvnicp->xsmp_info.port);
	if (ret)
		DRV_ERROR("xscore_conn_init data error for VNIC %s, ret = %d\n",
			  xsvnicp->vnic_name, ret);
}

static void handle_multicast(struct xsvnic *xsvnicp)
{
	unsigned long flags;

	if (test_bit(XSVNIC_MCAST_LIST_SENT, &xsvnicp->state)) {
		if (test_bit(XSVNIC_MCAST_LIST_TIMEOUT, &xsvnicp->state)) {
			spin_lock_irqsave(&xsvnicp->lock, flags);
			xsvnicp->counters[XSVNIC_MCAST_LIST_NORESP_COUNTER]++;
			clear_bit(XSVNIC_MCAST_LIST_SENT, &xsvnicp->state);
			if (test_and_clear_bit
			    (XSVNIC_MCAST_LIST_PENDING, &xsvnicp->state))
				_xsvnic_set_multicast(xsvnicp);
			spin_unlock_irqrestore(&xsvnicp->lock, flags);
		} else
			set_bit(XSVNIC_MCAST_LIST_TIMEOUT, &xsvnicp->state);
	}
}

static void handle_action_flags(struct xsvnic *xsvnicp)
{
	if (test_bit(XSVNIC_TRIGGER_NAPI_SCHED, &xsvnicp->state)) {
		xsvnic_data_recv_handler(xsvnicp);
		clear_bit(XSVNIC_TRIGGER_NAPI_SCHED, &xsvnicp->state);
	}
}

static void handle_post_conn_setup(struct xsvnic *xsvnicp)
{
	int ret;
	unsigned long flags;

	xsvnicp->counters[XSVNIC_IB_RECOVERED_COUNTER]++;
	xsvnicp->send_hbeat_flag = 0;
	set_bit(XSVNIC_OPER_UP, &xsvnicp->state);
	xsvnic_xsmp_send_oper_state(xsvnicp, xsvnicp->resource_id,
				    XSMP_XSVNIC_OPER_UP);
	/*
	 * Now send multicast list & vlan list
	 */
	spin_lock_irqsave(&xsvnicp->lock, flags);
	_xsvnic_set_multicast(xsvnicp);
	xsvnic_send_allvlan_list(xsvnicp);
	spin_unlock_irqrestore(&xsvnicp->lock, flags);
	init_completion(&xsvnicp->done);
	set_bit(XSVNIC_START_RX_SENT, &xsvnicp->state);
	clear_bit(XSVNIC_START_RESP_RCVD, &xsvnicp->state);
	ret = xsvnic_send_start_stop(xsvnicp, XSVNIC_START_RX);
	if (ret || !wait_for_completion_timeout(&xsvnicp->done,
						msecs_to_jiffies(1000 * 5))) {
		IOCTRL_ERROR("%s: start send failed ", xsvnicp->vnic_name);
		IOCTRL_ERROR("%d or did not get rx start resp\n", ret);
		xsvnic_set_oper_down(xsvnicp, 1);
	} else {
		napi_schedule(&xsvnicp->napi);
		if (xsvnicp->mp_flag &
		    (MP_XSVNIC_PRIMARY | MP_XSVNIC_SECONDARY))
			xsvnic_xsmp_send_ha_state(xsvnicp, xsvnicp->ha_state);
	}
}

static void xsvnic_conn_state_machine(struct xsvnic *xsvnicp)
{
	struct xsvnic_conn *cconn = &xsvnicp->ctrl_conn;
	struct xsvnic_conn *dconn = &xsvnicp->data_conn;
	int ret;

	switch (cconn->state) {
	case XSVNIC_CONN_ERROR:
		xsvnic_io_disconnect(xsvnicp);
		break;
	case XSVNIC_CONN_DISCONNECTED:
	case XSVNIC_CONN_INIT:
		xsvnicp->counters[XSVNIC_IB_RECOVERY_COUNTER]++;
		set_bit(XSVNIC_PORT_LINK_UP, &xsvnicp->state);
		clear_bit(XSVNIC_INTR_ENABLED, &xsvnicp->state);
		clear_bit(XSVNIC_MCAST_LIST_SENT, &xsvnicp->state);
		clear_bit(XSVNIC_MCAST_LIST_PENDING, &xsvnicp->state);
		clear_bit(XSVNIC_MCAST_LIST_TIMEOUT, &xsvnicp->state);
		cconn->state = XSVNIC_CONN_CONNECTING;
		ret = xscore_conn_connect(&cconn->ctx, 0);
		if (ret)
			cconn->state = XSVNIC_CONN_ERROR;
		break;
	case XSVNIC_CONN_CONNECTED:
		switch (dconn->state) {
		case XSVNIC_CONN_ERROR:
			xsvnic_io_disconnect(xsvnicp);
			break;
		case XSVNIC_CONN_DISCONNECTED:
		case XSVNIC_CONN_INIT:
			dconn->state = XSVNIC_CONN_CONNECTING;
			ret = xscore_conn_connect(&dconn->ctx, 0);
			if (ret) {
				dconn->state = XSVNIC_CONN_ERROR;
				cconn->state = XSVNIC_CONN_ERROR;
			}
			break;
		case XSVNIC_CONN_CONNECTED:
			handle_post_conn_setup(xsvnicp);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
}

/*
 * This function can get called from workqueue/thread context
 */
static int xsvnic_state_machine(struct xsvnic *xsvnicp)
{
	if (!test_bit(XSVNIC_OS_ADMIN_UP, &xsvnicp->state) ||
	    !test_bit(XSVNIC_CHASSIS_ADMIN_UP, &xsvnicp->state) ||
	    test_bit(XSVNIC_XT_DOWN, &xsvnicp->state) ||
	    test_bit(XSVNIC_IBLINK_DOWN, &xsvnicp->state) ||
	    test_bit(XSVNIC_DELETING, &xsvnicp->state)) {
		xsvnic_io_disconnect(xsvnicp);
		if (test_bit(XSVNIC_SEND_ADMIN_STATE, &xsvnicp->state)) {
			clear_bit(XSVNIC_SEND_ADMIN_STATE, &xsvnicp->state);
			xsvnic_xsmp_send_notification(xsvnicp->xsmp_hndl,
						      xsvnicp->resource_id,
						      XSMP_XSVNIC_UPDATE);
		}
		if (test_bit(XSVNIC_CHASSIS_ADMIN_SHADOW_UP, &xsvnicp->state))
			set_bit(XSVNIC_CHASSIS_ADMIN_UP, &xsvnicp->state);
		else
			clear_bit(XSVNIC_CHASSIS_ADMIN_UP, &xsvnicp->state);
		xsvnicp->sm_delay = 2000;
		handle_ha_sm(xsvnicp);
		return 0;
	}
	/*
	 * If it is operationally up done with it
	 */
	if (test_bit(XSVNIC_OPER_UP, &xsvnicp->state)) {
		xsvnicp->counters[XSVNIC_OPER_UP_STATE_COUNTER]++;
		handle_hbeat_sm(xsvnicp);
		handle_ha_sm(xsvnicp);
		handle_multicast(xsvnicp);
		handle_action_flags(xsvnicp);
		if (test_bit(XSVNIC_RX_NOBUF, &xsvnicp->state)) {
			if (!xscore_refill_recv
			    (&xsvnicp->data_conn.ctx, GFP_KERNEL))
				clear_bit(XSVNIC_RX_NOBUF, &xsvnicp->state);
			else
				xsvnicp->counters[XSVNIC_RX_NOBUF_COUNTER]++;
		}
		xsvnicp->sm_delay = 2000;
		return 0;
	}
	xsvnic_conn_state_machine(xsvnicp);
	xsvnicp->sm_delay = 1000;
	return 0;
}

static void xsvnic_state_machine_work(struct work_struct *work)
{
	struct xsvnic *xsvnicp = container_of(work, struct xsvnic,
					      sm_work.work);

	mutex_lock(&xsvnicp->mutex);
	xsvnic_state_machine(xsvnicp);
	mutex_unlock(&xsvnicp->mutex);
	queue_sm_work(xsvnicp, xsvnicp->sm_delay);
}

static void queue_sm_work(struct xsvnic *xsvnicp, int msecs)
{
	unsigned long flags;
	int del = 0;

	spin_lock_irqsave(&xsvnicp->lock, flags);
	if (!test_bit(XSVNIC_DELETING, &xsvnicp->state))
		queue_delayed_work(xsvnic_wq, &xsvnicp->sm_work,
				   msecs_to_jiffies(msecs));
	else
		del = 1;
	spin_unlock_irqrestore(&xsvnicp->lock, flags);
	if (del)
		xsvnic_remove_vnic(xsvnicp);
}

static void xsvnic_ctrl_event_handler(void *client_arg, int event)
{
	struct xsvnic *xsvnicp = client_arg;

	mutex_lock(&xsvnicp->mutex);
	switch (event) {
	case XSCORE_CONN_CONNECTED:
		xsvnicp->counters[XSVNIC_CTRL_CONN_OK_COUNTER]++;
		xsvnicp->ctrl_conn.state = XSVNIC_CONN_CONNECTED;
		break;
	case XSCORE_CONN_ERR:
		xsvnicp->counters[XSVNIC_CTRL_ERR_COUNTER]++;
		xsvnicp->ctrl_conn.state = XSVNIC_CONN_ERROR;
		break;
	case XSCORE_CONN_RDISCONNECTED:
		xsvnicp->counters[XSVNIC_CTRL_RDISC_COUNTER]++;
		xsvnicp->ctrl_conn.state = XSVNIC_CONN_DISCONNECTED;
		xsvnic_set_oper_down(xsvnicp, 1);
		break;
	default:
		break;
	}
	mutex_unlock(&xsvnicp->mutex);
}

static void xsvnic_data_event_handler(void *client_arg, int event)
{
	struct xsvnic *xsvnicp = client_arg;

	mutex_lock(&xsvnicp->mutex);
	switch (event) {
	case XSCORE_CONN_CONNECTED:
		xsvnicp->counters[XSVNIC_DATA_CONN_OK_COUNTER]++;
		xsvnicp->data_conn.state = XSVNIC_CONN_CONNECTED;
		break;
	case XSCORE_CONN_ERR:
		xsvnicp->counters[XSVNIC_DATA_ERR_COUNTER]++;
		xsvnicp->data_conn.state = XSVNIC_CONN_ERROR;
		break;
	case XSCORE_CONN_RDISCONNECTED:
		xsvnicp->counters[XSVNIC_DATA_RDISC_COUNTER]++;
		xsvnicp->data_conn.state = XSVNIC_CONN_DISCONNECTED;
		xsvnic_set_oper_down(xsvnicp, 1);
		break;
	default:
		break;
	}
	mutex_unlock(&xsvnicp->mutex);
}

static struct page *xsvnic_alloc_pages(int *size, int *page_order)
{
	gfp_t alloc_flags = GFP_ATOMIC;
	u16 order = get_order(*size);
	int chan_size = (1 << get_order(*size)) * PAGE_SIZE;

	*size = chan_size;
	*page_order = order;

	if (order > 0)
		alloc_flags |= __GFP_COMP;

	return alloc_pages(alloc_flags, order);
}

static u8 *xsvnic_skb_alloc(void *client_arg, void **cookie, int len)
{
	struct xsvnic *xsvnicp = client_arg;
	struct sk_buff *skb;

	skb = dev_alloc_skb(len);
	if (!skb)
		return NULL;

	skb_reserve(skb, NET_IP_ALIGN);
	skb->dev = xsvnicp->netdev;
	*cookie = skb;
	xsvnicp->counters[XSVNIC_RX_SKB_ALLOC_COUNTER]++;
	return skb->data;
}

static struct page *xsvnic_page_alloc(void *client_arg, void **cookie,
				      int *rsize, int element)
{
	struct xsvnic *xsvnicp = client_arg;
	struct page *page = xsvnic_alloc_pages(rsize, &xsvnicp->page_order);

	if (!page) {
		pr_info("XSVNIC: Unable to allocate page size %d\n", *rsize);
		return NULL;
	}

	xsvnicp->counters[XSVNIC_RX_SKB_ALLOC_COUNTER]++;
	*cookie = page;

	return page;
}

static void xsvnic_page_free(void *client_arg, void *cookie, int dir)
{
	struct sk_buff *skb = NULL;
	struct page *page = NULL;
	struct xsvnic *xsvnicp = client_arg;

	if (dir == XSCORE_SEND_BUF) {
		skb = cookie;
		xsvnic_dev_kfree_skb_any(skb);
		xsvnicp->counters[XSVNIC_TX_SKB_FREE_COUNTER]++;
	} else {
		xsvnicp->counters[XSVNIC_RX_SKB_FREE_COUNTER]++;
		page = cookie;
		put_page(page);
	}

}

static void xsvnic_skb_free(void *client_arg, void *cookie, int dir)
{
	struct sk_buff *skb = cookie;
	struct xsvnic *xsvnicp = client_arg;

	xsvnic_dev_kfree_skb_any(skb);
	if (dir == XSCORE_SEND_BUF)
		xsvnicp->counters[XSVNIC_TX_SKB_FREE_COUNTER]++;
	else
		xsvnicp->counters[XSVNIC_RX_SKB_FREE_COUNTER]++;

}

static inline void xsvnic_process_rbuf_error(struct xsvnic *xsvnicp,
					     struct xscore_buf_info *binfo)
{
	struct page *page;
	struct sk_buff *skb;

	if (xsvnicp->is_rxbatching) {
		page = binfo->cookie;
		put_page(page);
	} else {
		skb = binfo->cookie;
		xsvnic_dev_kfree_skb_any(skb);
	}

}

static u8 *xsvnic_ctrl_alloc(void *client_arg, void **cookie, int sz)
{
	return kmalloc(sz, GFP_ATOMIC);
}

static void xsvnic_ctrl_free(void *client_arg, void *cookie, int dir)
{
	kfree(cookie);
}

static void xsvnic_buf_init(struct xsvnic *xsvnicp,
			    struct xscore_conn_ctx *cctx)
{
	if (xsvnicp->is_rxbatching) {
		cctx->rx_buf_size = (PAGE_SIZE * 2);
		cctx->alloc_page_bufs = xsvnic_page_alloc;
		cctx->alloc_buf = 0;
		cctx->free_buf = xsvnic_page_free;
	} else {
		cctx->rx_buf_size = xsvnicp->mtu + NET_IP_ALIGN + ETH_HLEN + 12;
		cctx->alloc_page_bufs = 0;
		cctx->alloc_buf = xsvnic_skb_alloc;
		cctx->free_buf = xsvnic_skb_free;
	}
}

int check_rxbatch_possible(struct xsvnic *xsvnicp, int flag)
{
	if (flag && (xsvnicp->install_flag & XSVNIC_INSTALL_RX_BAT)
	    && (xsvnicp->install_flag & XSVNIC_8K_IBMTU)
	    && (xsvnicp->mtu <= (PAGE_SIZE * 2)) && xsvnicp->xsmp_info.is_shca)
		return 1;
	else
		return 0;
}

static void handle_rxbatch_change(struct xsvnic *xsvnicp)
{
	int ret;
	struct xscore_conn_ctx *ctx = &xsvnicp->data_conn.ctx;
	struct xt_cm_private_data *cmp =
	    (struct xt_cm_private_data *)ctx->priv_data;

	clear_bit(XSVNIC_RXBATCH_CHANGE, &xsvnicp->state);
	xscore_conn_destroy(ctx);

	/*
	 * Change rx batching settings
	 */
	xsvnicp->is_rxbatching = xsvnicp->is_rxbat_operational;
	xsvnic_buf_init(xsvnicp, ctx);

	if (xsvnicp->is_rxbatching) {
		cmp->data_qp_type |= cpu_to_be32(XSVNIC_RXBAT_BIT);
		cmp->data_qp_type |= cpu_to_be32(XSVNIC_RXBAT_TIMER_BIT);
	} else {
		cmp->data_qp_type &= ~(cpu_to_be32(XSVNIC_RXBAT_BIT));
		cmp->data_qp_type &= ~(cpu_to_be32(XSVNIC_RXBAT_TIMER_BIT));
	}

	ret = xscore_conn_init(ctx, xsvnicp->xsmp_info.port);
	if (ret)
		DRV_ERROR("xscore_conn_init data error for VNIC %s, ret = %d\n",
			  xsvnicp->vnic_name, ret);
}

static int xsvnic_conn_init(struct xsvnic *xsvnicp)
{
	struct xsvnic_conn *cp;
	struct xscore_conn_ctx *cctx;
	struct xt_cm_private_data *cmp;
	int ret;

	cp = &xsvnicp->ctrl_conn;
	cctx = &cp->ctx;
	/*
	 * Control connection
	 */
	cp->type = XSVNIC_IO_QP_TYPE_CONTROL;
	cctx->tx_ring_size = 4;
	cctx->rx_ring_size = 4;
	cctx->rx_buf_size = XSVNIC_MAX_BUF_SIZE;
	cctx->client_arg = xsvnicp;
	cctx->alloc_buf = xsvnic_ctrl_alloc;
	cctx->free_buf = xsvnic_ctrl_free;
	cctx->send_compl_handler = xsvnic_ctrl_send_handler;
	cctx->recv_msg_handler = xsvnic_ctrl_recv_handler;
	cctx->event_handler = xsvnic_ctrl_event_handler;
	cctx->dguid = xsvnicp->tca_guid;
	cctx->dlid = xsvnicp->tca_lid;
	cctx->service_id = be64_to_cpu(TCA_SERVICE_ID);

	cmp = (struct xt_cm_private_data *)cctx->priv_data;
	cmp->vid = cpu_to_be64(xsvnicp->resource_id);
	cmp->qp_type = cpu_to_be16(XSVNIC_IO_QP_TYPE_CONTROL);

	cctx->priv_data_len = sizeof(*cmp);

	ret = xscore_conn_init(cctx, xsvnicp->xsmp_info.port);
	if (ret) {
		DRV_ERROR("xscore_conn_init ctrl error for VID %llx %d\n",
			  xsvnicp->resource_id, ret);
		return ret;
	}

	cp = &xsvnicp->data_conn;
	cctx = &cp->ctx;

	cp->type = XSVNIC_IO_QP_TYPE_DATA;
	cctx->tx_ring_size = xsvnicp->tx_ring_size;
	cctx->rx_ring_size = xsvnicp->rx_ring_size;
	cctx->client_arg = xsvnicp;

	/*
	 * 8K IB MTU is for softhca only
	 */
	if (xsvnicp->install_flag & XSVNIC_8K_IBMTU
	    && xsvnicp->xsmp_info.is_shca)
		cctx->features |= XSCORE_8K_IBMTU_SUPPORT;

	if (check_rxbatch_possible(xsvnicp, xsvnic_rxbatching))
		xsvnicp->is_rxbatching = 1;

	xsvnic_buf_init(xsvnicp, cctx);

	cctx->send_compl_handler = 0;
	cctx->recv_compl_handler = xsvnic_data_recv_handler;
	cctx->event_handler = xsvnic_data_event_handler;
	cctx->dguid = xsvnicp->tca_guid;
	cctx->dlid = xsvnicp->tca_lid;
	cctx->service_id = be64_to_cpu(TCA_SERVICE_ID);
	cctx->features |= XSCORE_SG_SUPPORT;
	if (!xsvnic_tx_intr_mode) {
		cctx->features |= XSCORE_NO_SEND_COMPL_INTR;
	} else {
		cctx->tx_max_coalesced_frames = xsvnic_max_coal_frames;
		cctx->tx_coalesce_usecs = xsvnic_coal_usecs;
	}

	if (!xsvnic_rx_intr_mode) {
		cctx->features |= XSCORE_NO_RECV_COMPL_INTR;
	} else {
		cctx->rx_max_coalesced_frames = xsvnic_max_coal_frames;
		cctx->rx_coalesce_usecs = xsvnic_coal_usecs;
	}

	cmp = (struct xt_cm_private_data *)cctx->priv_data;
	cmp->vid = cpu_to_be64(xsvnicp->resource_id);
	cmp->qp_type = cpu_to_be16(XSVNIC_IO_QP_TYPE_DATA);

	if (xsvnicp->is_tso && (xsvnicp->netdev->features & NETIF_F_TSO))
		cmp->data_qp_type |= cpu_to_be32(XSVNIC_TSO_BIT);

	if (xsvnicp->is_rxbatching) {
		cmp->data_qp_type |= cpu_to_be32(XSVNIC_RXBAT_BIT);
		cmp->data_qp_type |= cpu_to_be32(XSVNIC_RXBAT_TIMER_BIT);
	}

	cctx->priv_data_len = sizeof(*cmp);

	ret = xscore_conn_init(cctx, xsvnicp->xsmp_info.port);
	if (ret) {
		DRV_ERROR("xscore_conn_init data error for VID %llx %d\n",
			  xsvnicp->resource_id, ret);
		xscore_conn_destroy(&xsvnicp->ctrl_conn.ctx);
	}
	return ret;
}

/*
 * All the functions related to the stack
 */

static void xsvnic_setup(struct net_device *netdev)
{
	ether_setup(netdev);
}

static int xsvnic_open(struct net_device *netdev)
{
	struct xsvnic *xsvnicp = netdev_priv(netdev);

	xsvnicp->counters[XSVNIC_OPEN_COUNTER]++;
	mutex_lock(&xsvnicp->mutex);
	napi_enable(&xsvnicp->napi);
	set_bit(XSVNIC_OS_ADMIN_UP, &xsvnicp->state);
	mutex_unlock(&xsvnicp->mutex);
	return 0;
}

static int xsvnic_stop(struct net_device *netdev)
{
	struct xsvnic *xsvnicp = netdev_priv(netdev);
	unsigned long flags;

#ifdef __VMKLNX__
	/* set trans_start so we don't get spurious watchdogs during reset */
	netdev->trans_start = jiffies;
#endif

	xsvnicp->counters[XSVNIC_STOP_COUNTER]++;
	mutex_lock(&xsvnicp->mutex);
	spin_lock_irqsave(&xsvnicp->lock, flags);
	clear_bit(XSVNIC_OS_ADMIN_UP, &xsvnicp->state);
	spin_unlock_irqrestore(&xsvnicp->lock, flags);
	xsvnic_io_disconnect(xsvnicp);
	napi_disable(&xsvnicp->napi);
	mutex_unlock(&xsvnicp->mutex);
	return 0;
}

static struct net_device_stats *xsvnic_get_stats(struct net_device *netdev)
{
	struct xsvnic *xsvnicp = netdev_priv(netdev);

	xsvnicp->counters[XSVNIC_GETSTATS_COUNTER]++;
	return &xsvnicp->stats;
}

static void xsvnic_tx_timeout(struct net_device *dev)
{
	struct xsvnic *xsvnicp = netdev_priv(dev);

	xsvnicp->counters[XSVNIC_WDOG_TIMEOUT_COUNTER]++;
	xsvnic_set_oper_down(xsvnicp, 1);
}

static int xsvnic_change_mtu(struct net_device *netdev, int new_mtu)
{
	return 0;
}

static int xsvnic_set_mac_address(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;
	struct xsvnic *xsvnicp = netdev_priv(dev);

	if (!is_valid_ether_addr((u8 *) (addr->sa_data)))
		return -EINVAL;

	if (memcmp(dev->dev_addr, addr->sa_data, dev->addr_len) != 0) {
		memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
		xsvnicp->counters[XSVNIC_MAC_ADDR_CHNG]++;
	}

	return 0;
}

/*
 * Copy all the Multicast addresses from src to the xsvnic device dst
 */
static int xsvnic_mc_list_copy(struct xsvnic *xsvnicp)
{
	struct net_device *netdev = xsvnicp->netdev;

	if (xsvnicp->mc_addrs != NULL)
		kfree(xsvnicp->mc_addrs);

	xsvnicp->mc_addrs = kmalloc(netdev_mc_count(netdev) *
				    sizeof(struct ether_addr), GFP_ATOMIC);

	if (!xsvnicp->mc_addrs)
		return -ENOMEM;
	xsvnicp->mc_count = netdev_mc_count(netdev);
	netdev_mc_list_copy(xsvnicp);
	return 0;
}

static void _xsvnic_set_multicast(struct xsvnic *xsvnicp)
{
	int count = xsvnicp->mc_count;
	int i;
	u8 *msg, *pay;
	int tlen;

	if (multicast_list_disable || xsvnicp->ctrl_conn.state
	    != XSVNIC_CONN_CONNECTED)
		return;

	if (test_bit(XSVNIC_MCAST_LIST_SENT, &xsvnicp->state)) {
		/*
		 * Once response comes back for sent list, this will trigger
		 * another send operation
		 */
		set_bit(XSVNIC_MCAST_LIST_PENDING, &xsvnicp->state);
		return;
	}

	xsvnicp->counters[XSVNIC_SET_MCAST_COUNTER]++;
	/*
	 * Copy over the multicast list and send it over
	 */
	xsvnicp->iff_promisc = 0;
	if ((xsvnicp->netdev->flags & (IFF_ALLMULTI | IFF_PROMISC))
	    || count > XSVNIC_MACLIST_MAX)
		xsvnicp->iff_promisc = 1;
	if (count > XSVNIC_MACLIST_MAX)
		count = XSVNIC_MACLIST_MAX;
	tlen = ETH_ALEN * count + sizeof(struct xsvnic_control_msg);
	msg = kmalloc(tlen, GFP_ATOMIC);
	if (!msg)
		return;
	pay = msg + sizeof(struct xsvnic_control_msg);
	for (i = 0; i < count; i++) {
		ether_addr_copy(pay, (u8 *)&(xsvnicp->mc_addrs[i]));
		pay += ETH_ALEN;
	}
	xsvnic_send_multicast_list(xsvnicp, msg, tlen, xsvnicp->iff_promisc);
}

static void xsvnic_set_multicast(struct net_device *netdev)
{
	struct xsvnic *xsvnicp = netdev_priv(netdev);
	unsigned long flags;

	spin_lock_irqsave(&xsvnicp->lock, flags);
	xsvnic_mc_list_copy(xsvnicp);
	_xsvnic_set_multicast(xsvnicp);
	spin_unlock_irqrestore(&xsvnicp->lock, flags);
}

static int  xsvnic_vlan_rx_add_vlanid(struct net_device *netdev, __be16 proto,
				u16 vlanid)
{
	struct xsvnic *xsvnicp = netdev_priv(netdev);
	struct vlan_entry *vlan;
	unsigned long flags;

	xsvnicp->counters[XSVNIC_VLAN_RX_ADD_COUNTER]++;
	/*
	 * The control message to IOP can accommodate 1024 size
	 * We restrict the number of vlans to 500
	 * Ideally we do not need it since it was for legacy reasons
	 */
	if (xsvnicp->vlan_count >= XSVNIC_VLANLIST_MAX)
		return -1;
	vlan = kmalloc(sizeof(struct vlan_entry), GFP_ATOMIC);
	if (!vlan)
		return -1;
	INIT_LIST_HEAD(&vlan->vlan_list);
	vlan->vlan_id = vlanid;
	spin_lock_irqsave(&xsvnicp->lock, flags);
	list_add_tail(&vlan->vlan_list, &xsvnicp->vlan_list);
	xsvnicp->vlan_count++;
	spin_unlock_irqrestore(&xsvnicp->lock, flags);
	xsvnic_send_vlan_list(xsvnicp, &vlanid, 1, XSVNIC_ASSIGN_VLAN);
	return 0;
}

static int xsvnic_vlan_rx_kill_vlanid(struct net_device *netdev, __be16 proto,
				u16 vlanid)
{
	struct xsvnic *xsvnicp = netdev_priv(netdev);
	struct vlan_entry *vlan;
	unsigned long flags;

	xsvnicp->counters[XSVNIC_VLAN_RX_DEL_COUNTER]++;

	spin_lock_irqsave(&xsvnicp->lock, flags);
	list_for_each_entry(vlan, &xsvnicp->vlan_list, vlan_list) {
		if (vlan->vlan_id == vlanid) {
			list_del(&vlan->vlan_list);
			kfree(vlan);
			xsvnicp->vlan_count--;
			xsvnic_send_vlan_list(xsvnicp, &vlanid, 1,
					      XSVNIC_UNASSIGN_VLAN);
			break;
		}
	}
	spin_unlock_irqrestore(&xsvnicp->lock, flags);
	return 0;
}

int xsvnic_change_rxbatch(struct xsvnic *xsvnicp, int flag)
{

	if (xsvnicp->is_rxbatching != flag) {
		if (flag && !check_rxbatch_possible(xsvnicp, flag))
			return -EINVAL;

		set_bit(XSVNIC_RXBATCH_CHANGE, &xsvnicp->state);
		xsvnic_set_oper_down(xsvnicp, 1);
		xsvnicp->is_rxbat_operational = flag;
	}

	return 1;
}
/*
static int xsvnic_get_settings(struct net_device *netdev,
			       struct ethtool_cmd *ecmd)
{
	struct xsvnic *xsvnicp = netdev_priv(netdev);

	ecmd->autoneg = 0;
	ecmd->speed = SPEED_1000;
	ecmd->duplex = DUPLEX_FULL;
	if (netif_carrier_ok(netdev)) {
		if ((xsvnicp->port_speed == SPEED_1000) && xsvnic_report_10gbps)
			ecmd->speed = SPEED_10000;
		else
			ecmd->speed = xsvnicp->port_speed;

		if (ecmd->speed > SPEED_1000) {
			ecmd->advertising = ADVERTISED_10000baseT_Full;
			ecmd->supported = SUPPORTED_10000baseT_Full |
			    SUPPORTED_FIBRE | SUPPORTED_Autoneg;
			ecmd->port = PORT_FIBRE;
			ecmd->transceiver = XCVR_EXTERNAL;
		} else {
			ecmd->advertising = ADVERTISED_1000baseT_Full |
			    ADVERTISED_100baseT_Full;
			ecmd->supported =
			    SUPPORTED_10baseT_Full | SUPPORTED_10baseT_Half |
			    SUPPORTED_100baseT_Full | SUPPORTED_100baseT_Half |
			    SUPPORTED_1000baseT_Full | SUPPORTED_1000baseT_Half
			    | SUPPORTED_TP | SUPPORTED_Autoneg;
			ecmd->transceiver = XCVR_INTERNAL;
			ecmd->port = PORT_TP;
		}
	}
	return 0;
}
*/
/*
static int xsvnic_set_ringparam(struct net_device *netdev,
				struct ethtool_ringparam *ering)
{
	struct xsvnic *xsvnicp = netdev_priv(netdev);

	if (ering->rx_pending >= 32
	    && ering->rx_pending <= ering->rx_max_pending)
		xsvnicp->rx_ring_size = ering->rx_pending;

	if (ering->tx_pending >= 32
	    && ering->tx_pending <= ering->tx_max_pending)
		xsvnicp->tx_ring_size = ering->tx_pending;

	set_bit(XSVNIC_RING_SIZE_CHANGE, &xsvnicp->state);
	xsvnic_set_oper_down(xsvnicp, 1);
	return 0;
}
*/
/*
static void xsvnic_get_ringparam(struct net_device *netdev,
				 struct ethtool_ringparam *ering)
{
	struct xsvnic *xsvnicp = netdev_priv(netdev);

	ering->rx_max_pending = 2048;
	ering->rx_mini_max_pending = 0;
	ering->rx_jumbo_max_pending = 384;
	ering->rx_pending = xsvnicp->data_conn.ctx.rx_ring_size;
	ering->rx_mini_pending = 0;
	ering->rx_jumbo_pending = xsvnicp->data_conn.ctx.rx_ring_size;
	ering->tx_max_pending = 2048;
	ering->tx_pending = xsvnicp->data_conn.ctx.tx_ring_size;
}
*/
/*
static void xsvnic_get_drvinfo(struct net_device *netdev,
			       struct ethtool_drvinfo *drvinfo)
{
	strncpy(drvinfo->driver, "xsvnic", 32);
	strncpy(drvinfo->version, XSVNIC_DRIVER_VERSION, 32);
	strncpy(drvinfo->fw_version, "N/A", 32);
	strncpy(drvinfo->bus_info, "N/A", 32);
}
*/

u32 xsvnic_op_get_rx_csum(struct net_device *dev)
{
	return (dev->features & NETIF_F_IP_CSUM) != 0;
}

int xsvnic_get_coalesce(struct net_device *dev, struct ethtool_coalesce *coal)
{
	struct xsvnic *xsvnicp = netdev_priv(dev);

	if (xsvnic_tx_intr_mode) {
		coal->tx_coalesce_usecs =
		    xsvnicp->data_conn.ctx.tx_coalesce_usecs;
		coal->tx_max_coalesced_frames =
		    xsvnicp->data_conn.ctx.tx_max_coalesced_frames;
	}

	if (xsvnic_rx_intr_mode) {
		coal->rx_coalesce_usecs =
		    xsvnicp->data_conn.ctx.rx_coalesce_usecs;
		coal->rx_max_coalesced_frames =
		    xsvnicp->data_conn.ctx.rx_max_coalesced_frames;
	}

	return 0;
}

int xsvnic_set_coalesce(struct net_device *dev, struct ethtool_coalesce *coal)
{

	struct xsvnic *xsvnicp = netdev_priv(dev);
	u32 tx_usecs, tx_frames;
	u32 rx_usecs, rx_frames;
	u32 ret;
	struct xscore_conn_ctx *ctx;

	if (coal->rx_coalesce_usecs > 0xffff ||
	    coal->rx_max_coalesced_frames > 0xffff)
		return -EINVAL;

	ctx = &xsvnicp->data_conn.ctx;

	tx_usecs = ctx->tx_coalesce_usecs;
	tx_frames = ctx->tx_max_coalesced_frames;
	rx_usecs = ctx->rx_coalesce_usecs;
	rx_frames = ctx->rx_max_coalesced_frames;

	/* Modify TX cq */
	if (xsvnic_tx_intr_mode && ((tx_usecs != coal->tx_coalesce_usecs) ||
				    (tx_frames !=
				     coal->tx_max_coalesced_frames))) {
		ret = xscore_modify_cq(ctx->scq, coal->tx_max_coalesced_frames,
				       coal->tx_coalesce_usecs);
		if (ret && ret != -ENOSYS) {
			pr_info("failed modifying Send CQ (%d) vnic ", ret);
			pr_info("%s\n", xsvnicp->vnic_name);
			return ret;
		}

		ctx->tx_coalesce_usecs = coal->tx_coalesce_usecs;
		ctx->tx_max_coalesced_frames = coal->tx_max_coalesced_frames;
	}

	/* Modify RX cq */
	if (xsvnic_rx_intr_mode && ((rx_usecs != coal->rx_coalesce_usecs) ||
				    (rx_frames !=
				     coal->rx_max_coalesced_frames))) {
		ret = xscore_modify_cq(ctx->rcq, coal->rx_max_coalesced_frames,
				       coal->rx_coalesce_usecs);
		if (ret && ret != -ENOSYS) {
			pr_err("failed modifying Recv CQ (%d) vnic ", ret);
			pr_err("%s\n", xsvnicp->vnic_name);
			return ret;
		}
		ctx->rx_coalesce_usecs = coal->rx_coalesce_usecs;
		ctx->rx_max_coalesced_frames = coal->rx_max_coalesced_frames;
	}

	return 0;
}

/*
static struct ethtool_ops xsvnic_ethtool_ops = {
	.get_settings = xsvnic_get_settings,
	.get_drvinfo = xsvnic_get_drvinfo,
	.get_link = ethtool_op_get_link,
	.get_ringparam = xsvnic_get_ringparam,
	.set_ringparam = xsvnic_set_ringparam,
	.set_coalesce = xsvnic_set_coalesce,
};
*/

static int xsvnic_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	struct mii_ioctl_data *data = if_mii(ifr);
	int ret = 0;
	struct xsvnic *xsvnicp;

	if (!netif_running(netdev))
		return -EAGAIN;

	xsvnicp = netdev_priv(netdev);
	xsvnicp->counters[XSVNIC_IOCTL_COUNTER]++;

	switch (cmd) {
	case SIOCGMIIPHY:
		data->phy_id = 5;
		break;
	case SIOCGMIIREG:
		/*
		 * Mainly used by mii monitor
		 */
		switch (data->reg_num) {
		case 0:
			data->val_out = 0x2100;
			break;
		case 1:
			data->val_out = 0xfe00 |
			    (netif_carrier_ok(netdev) << 2);
			break;
		default:
			break;
		}
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}
	return ret;
}

/*
 * Needs to be clled with spin_lock held
 */
static void handle_qp_error(struct xsvnic *xsvnicp, int qp_error)
{
	pr_info("XSVNIC %s: Link Down ", xsvnicp->vnic_name);
	pr_info("(QP error %d)\n", qp_error);
	xsvnicp->counters[XSVNIC_QP_ERROR_COUNTER]++;
	xsvnic_set_oper_down(xsvnicp, 0);
}

static void xsvnic_reclaim_tx_buffers(struct xsvnic *xsvnicp)
{
	struct xscore_buf_info binfo;
	int qp_error = 0;
	/*
	 * Now reap completions
	 */
	while (xscore_poll_send(&xsvnicp->data_conn.ctx, &binfo) > 0) {
		CALC_MAX_MIN_TXTIME(xsvnicp, binfo.time_stamp);
		xsvnicp->counters[XSVNIC_TX_SKB_FREE_COUNTER_REAP]++;
		xsvnic_dev_kfree_skb_any(binfo.cookie);
		if (binfo.status) {
			IOCTRL_INFO("VNIC: %s Data Send Completion error: %d\n",
				    xsvnicp->vnic_name, binfo.status);
			qp_error = binfo.status;
		}
	}
	if (qp_error)
		handle_qp_error(xsvnicp, qp_error);
}

int xsvnic_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct xsvnic *xsvnicp = netdev_priv(netdev);
	int ret = NETDEV_TX_OK;
	int slen = skb->len;
	unsigned long flags;
	u8 skb_need_tofree = 0;

	spin_lock_irqsave(&xsvnicp->lock, flags);

	/* Stop sending packet if standby interface */
	if (xsvnicp->mp_flag
	    && unlikely(test_bit(XSVNIC_STATE_STDBY, &xsvnicp->state))) {
		dev_kfree_skb_any(skb);
		xsvnicp->counters[XSVNIC_TX_DROP_STANDBY_COUNTER]++;
		goto out;
	}

	if (!test_bit(XSVNIC_OPER_UP, &xsvnicp->state)) {
		ret = NETDEV_TX_BUSY;
		xsvnicp->stats.tx_dropped++;
		xsvnicp->counters[XSVNIC_TX_DROP_OPER_DOWN_COUNT]++;
		goto out;
	}

	if (skb->len < XSVNIC_MIN_PACKET_LEN) {
		xsvnicp->counters[XSVNIC_SHORT_PKT_COUNTER]++;
		if (skb_padto(skb, XSVNIC_MIN_PACKET_LEN)) {
			ret = 0;
			xsvnicp->stats.tx_dropped++;
			xsvnicp->counters[XSVNIC_TX_SKB_ALLOC_ERROR_COUNTER]++;
			goto reclaim;
		}
		skb->len = XSVNIC_MIN_PACKET_LEN;

	}
	CALC_MAX_PKT_TX(xsvnicp, skb->len);
	/*
	 * Check if it is a gso packet
	 */
	if (xsvnicp->is_tso) {
		int mss, hroom;
		int doff = 0;
		struct xs_tsovlan_header *hdrp;
		u16 vid = 0;

		if (skb_vlan_tag_present(skb)) {
			hroom = sizeof(struct xs_tsovlan_header);
			vid = skb_vlan_tag_get(skb);
			xsvnicp->counters[XSVNIC_TX_VLAN_COUNTER]++;
		} else {
			hroom = sizeof(struct xs_tso_header);
		}
		if (unlikely(skb_headroom(skb) < hroom)) {
			if (skb_cow(skb, hroom) < 0) {
				xsvnicp->stats.tx_dropped++;
				xsvnicp->counters[XSVNIC_TX_EXPANDSKB_ERROR]++;
				skb_need_tofree = 1;
				goto free_skb;
			}
			xsvnicp->counters[XSVNIC_TX_SKB_NOHEAD_COUNTER]++;
		}

		mss = skb_is_gso(skb);
		if (mss) {
			if (skb_header_cloned(skb)) {
				xsvnicp->counters
				    [XSVNIC_TX_EXPAND_HEAD_COUNTER]++;
				ret = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
				if (ret) {
					xsvnicp->counters
					    [XSVNIC_TX_EXPAND_HEAD_ECNTR]++;
					skb_need_tofree = 1;
					goto free_skb;
				}
			}
			hdrp = (struct xs_tsovlan_header *)skb_push(skb, hroom);
			/*
			 * Now add the MSS and data offset into the 4 byte
			 * pre-header Into gso_header
			 */
			doff =
			    skb_transport_offset(skb) + tcp_hdrlen(skb) - hroom;
			xsvnicp->counters[XSVNIC_TX_SKB_TSO_COUNTER]++;
			hdrp->tso_info =
			    cpu_to_be32((1 << 30) | (doff << 16) | mss);
		} else {
			hdrp = (struct xs_tsovlan_header *)skb_push(skb, hroom);
			hdrp->tso_info = cpu_to_be32((1 << 30) | (1 << 28));
		}

		if (vid) {
			hdrp->vlan_info = cpu_to_be32(vid);
			hdrp->tso_info =
			    be32_to_cpu(hdrp->tso_info) | (3 << 30);
		}
	}
	/*
	 * Spin lock has to be released for soft-HCA to work correctly
	 */
	spin_unlock_irqrestore(&xsvnicp->lock, flags);
	ret = xscore_post_send_sg(&xsvnicp->data_conn.ctx, skb, 0);
	spin_lock_irqsave(&xsvnicp->lock, flags);
	if (ret) {
		if (ret == -ENOBUFS) {
			xsvnicp->stats.tx_dropped++;
			xsvnicp->counters[XSVNIC_TX_RING_FULL_COUNTER]++;
		} else {
			handle_qp_error(xsvnicp, ret);
		}
		ret = NETDEV_TX_OK;
		skb_need_tofree = 1;
		goto free_skb;
	}
	netdev->trans_start = jiffies;
	xsvnicp->send_hbeat_flag = 0;
	xsvnicp->stats.tx_packets++;
	xsvnicp->stats.tx_bytes += slen;
	xsvnicp->counters[XSVNIC_TX_COUNTER]++;

free_skb:
	if (skb_need_tofree)
		dev_kfree_skb(skb);

	if (!xsvnic_tx_intr_mode
	    && (xsvnicp->reclaim_count++ > xsvnic_reclaim_count)) {
reclaim:
		xsvnicp->reclaim_count = 0;
		xsvnic_reclaim_tx_buffers(xsvnicp);
	}
out:
	spin_unlock_irqrestore(&xsvnicp->lock, flags);

	return ret;
}

static inline void xsvnic_untag_vlan(struct xsvnic *xsvnicp,
				     struct sk_buff *skb, u16 *vlan_tci)
{
	struct ethhdr *eh = (struct ethhdr *)(skb->data);

	if (eh->h_proto == htons(ETH_P_8021Q)) {
		struct vlan_ethhdr *veth = (struct vlan_ethhdr *)(skb->data);
		/*
		 * Grab VLAN information and TCI fields and populate SKB
		 * Strip the vlan tag
		 */
		*vlan_tci = be16_to_cpu(veth->h_vlan_TCI);
		memmove((u8 *) eh + VLAN_HLEN, eh, ETH_ALEN * 2);
		skb_pull(skb, VLAN_HLEN);
	}
}

static inline void xsvnic_verify_checksum(struct xsvnic *xsvnicp,
					  struct sk_buff *skb, int sz)
{
	u32 trailer;

	if (xsvnic_force_csum_offload) {
		xsvnicp->counters[XSVNIC_RX_SKB_OFFLOAD_COUNTER]++;
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb_trim(skb, sz - sizeof(int));
		return;
	} else
		skb->ip_summed = CHECKSUM_NONE;

	trailer = be32_to_cpu(*(u32 *) ((u8 *) skb->data + sz - 4));

	skb_trim(skb, sz - sizeof(int));

	if (!(trailer & XSIGO_IPV4_BIT)) {
		xsvnicp->counters[XSVNIC_RX_SKB_OFFLOAD_NONIPV4_COUNTER]++;
		return;
	}

	if (trailer & (XSIGO_TCP_CHKSUM_GOOD_BIT | XSIGO_UDP_CHKSUM_GOOD_BIT)) {
		xsvnicp->counters[XSVNIC_RX_SKB_OFFLOAD_COUNTER]++;
		if (trailer & XSIGO_IP_FRAGMENT_BIT) {
			skb->csum = (trailer >> 16);
			skb->ip_summed = CHECKSUM_PARTIAL;
			xsvnicp->counters[XSVNIC_RX_SKB_OFFLOAD_FRAG_COUNTER]++;
		} else
			skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
}

char *xsvnic_get_rxbat_pkts(struct xsvnic *xsvnicp, int *curr_seg_len,
			    char *start, char *is_last_pkt, int total_pkt_len)
{
	int rxbat_hdr = be32_to_cpu(*(u32 *) start);
	*curr_seg_len = RXBAT_FRAG_LEN(rxbat_hdr);
	*is_last_pkt = (RXBAT_FINAL_BIT(rxbat_hdr) ? 1 : 0);
	return start + XS_RXBAT_HDRLEN;

}

void xsvnic_send_skb(struct xsvnic *xsvnicp, struct sk_buff *skb,
		     int curr_pkt_len, char chksum_offload)
{
	struct net_device *netdev = xsvnicp->netdev;
	u16 vlan_tci = 0xFFFF;

	skb->dev = netdev;
	if ((netdev->features & NETIF_F_IP_CSUM) && chksum_offload)
		xsvnic_verify_checksum(xsvnicp, skb, curr_pkt_len);
	else
		skb->ip_summed = CHECKSUM_NONE;
	/*
	 * Software based VLAN acceleration enabled, so process it
	 */
	if (netdev->features & NETIF_F_HW_VLAN_CTAG_RX)
		xsvnic_untag_vlan(xsvnicp, skb, &vlan_tci);

	skb->protocol = eth_type_trans(skb, netdev);
	xsvnicp->stats.rx_packets++;
	xsvnicp->stats.rx_bytes += curr_pkt_len;
	CALC_MAX_PKT_RX(xsvnicp, skb->len);
	/* Enable dumping packets on Demand */
	XSIGO_DUMP_PKT(skb->data, skb->len, "xsvnic_process_rx_skb");
	/*
	 * Check if it is HA and standby and drop the packet
	 */
	if (xsvnicp->mp_flag
	    && unlikely(test_bit(XSVNIC_STATE_STDBY, &xsvnicp->state))) {
		dev_kfree_skb_any(skb);
		xsvnicp->counters[XSVNIC_RX_DROP_STANDBY_COUNTER]++;
	} else {
		if (xsvnic_vlanaccel && (vlan_tci != 0xFFFF)) {
			__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q),
					       vlan_tci);
			xsvnicp->counters[XSVNIC_RX_SENDTO_VLANGRP]++;
		}

		if (netdev->features & NETIF_F_LRO)
			lro_receive_skb(&xsvnicp->lro.lro_mgr, skb, NULL);
		else
			netif_receive_skb(skb);
	}
	netdev->last_rx = jiffies;
}

void xsvnic_count_segs(struct xsvnic *xsvnicp, char nr_segs, int pkt_len)
{
	if (nr_segs > 1) {
		xsvnicp->counters[XSVNIC_RXBAT_PKTS]++;
		if (nr_segs <= 5)
			xsvnicp->counters[XSVNIC_RXBAT_BELOW_5SEGS]++;
		else if (nr_segs > 5 && nr_segs <= 10)
			xsvnicp->counters[XSVNIC_RXBAT_BTW_5_10SEGS]++;
		else if (nr_segs > 10 && nr_segs <= 20)
			xsvnicp->counters[XSVNIC_RXBAT_BTW_10_20SEGS]++;
		else
			xsvnicp->counters[XSVNIC_RXBAT_ABOVE_20SEGS]++;

		if (nr_segs > xsvnicp->counters[XSVNIC_RX_MAXBATED_COUNTER])
			xsvnicp->counters[XSVNIC_RX_MAXBATED_COUNTER] = nr_segs;
	}
	if (pkt_len > PAGE_SIZE)
		xsvnicp->counters[XSVNIC_8KBAT_PKTS]++;
}

int xsvnic_align_addr(char **start)
{
	int align_diff;
	char *align_addr = (char *)((unsigned long)(*start + 3) & ~0x3);

	align_diff = align_addr - *start;
	*start = align_addr;
	return align_diff;
}

void xsvnic_process_rx_skb(struct xsvnic *xsvnicp,
			   struct xscore_buf_info *binfo)
{
	struct sk_buff *skb;
	int tot_pkt_len;

	tot_pkt_len = binfo->sz;
	skb = binfo->cookie;
	skb_put(skb, tot_pkt_len);
	xsvnic_send_skb(xsvnicp, skb, tot_pkt_len, 1);

}

int xsvnic_poll(struct napi_struct *napi, int budget)
{
	struct xsvnic *xsvnicp = container_of(napi, struct xsvnic, napi);
	struct xscore_conn_ctx *ctx = &xsvnicp->data_conn.ctx;
	struct xscore_buf_info binfo;
	int ret, done = 0, qp_error = 0;
	unsigned long flags;

	/*
	 * If not connected complete it
	 */
	xsvnicp->counters[XSVNIC_NAPI_POLL_COUNTER]++;
	if (!test_bit(XSVNIC_OPER_UP, &xsvnicp->state)) {
		napi_complete(&xsvnicp->napi);
		clear_bit(XSVNIC_INTR_ENABLED, &xsvnicp->state);
		return 0;
	}
again:
	while (done < budget) {
		ret = xscore_read_buf(ctx, &binfo);
		if (ret != 1 || binfo.status) {
			if (binfo.status) {
				qp_error = 1;
				handle_qp_error(xsvnicp, binfo.status);
				xsvnic_process_rbuf_error(xsvnicp, &binfo);
			}
			break;
		}

		if (xsvnicp->is_rxbatching)
			xsvnic_process_pages(xsvnicp, &binfo);
		else
			xsvnic_process_rx_skb(xsvnicp, &binfo);

		xsvnicp->counters[XSVNIC_RX_SKB_COUNTER]++;
		done++;
	}

	napi_update_budget(&xsvnicp->napi, done);

	if (!qp_error && !test_bit(XSVNIC_RX_NOBUF, &xsvnicp->state)) {
		if (xscore_refill_recv(&xsvnicp->data_conn.ctx, GFP_ATOMIC)) {
			xsvnicp->counters[XSVNIC_RX_NOBUF_COUNTER]++;
			set_bit(XSVNIC_RX_NOBUF, &xsvnicp->state);
		}
	}
	if (done < budget) {
		if (xsvnicp->netdev->features & NETIF_F_LRO)
			lro_flush_all(&xsvnicp->lro.lro_mgr);
		napi_complete(&xsvnicp->napi);
		clear_bit(XSVNIC_OVER_QUOTA, &xsvnicp->state);
	} else {
		set_bit(XSVNIC_OVER_QUOTA, &xsvnicp->state);
		xsvnicp->counters[XSVNIC_RX_QUOTA_EXCEEDED_COUNTER]++;
		return done;
	}
	spin_lock_irqsave(&xsvnicp->lock, flags);
	if (test_bit(XSVNIC_OS_ADMIN_UP, &xsvnicp->state) &&
	    test_bit(XSVNIC_CHASSIS_ADMIN_UP, &xsvnicp->state) &&
	    test_bit(XSVNIC_OPER_UP, &xsvnicp->state) &&
	    !test_bit(XSVNIC_DELETING, &xsvnicp->state)) {
		set_bit(XSVNIC_INTR_ENABLED, &xsvnicp->state);
		if (xscore_enable_rxintr(ctx)) {
			if (napi_reschedule(&xsvnicp->napi)) {
				spin_unlock_irqrestore(&xsvnicp->lock, flags);
				goto again;
			}
		}
	}
	spin_unlock_irqrestore(&xsvnicp->lock, flags);
	return done;
}

static int get_skb_hdr(struct sk_buff *skb, void **iphdr,
		       void **tcph, u64 *hdr_flags, void *xsvnicp)
{
	unsigned int ip_len;
	struct iphdr *iph;

	if (unlikely(skb->protocol != htons(ETH_P_IP)))
		return -1;

	/* Check for non-TCP packet */
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return -1;

	ip_len = ip_hdrlen(skb);
	skb_set_transport_header(skb, ip_len);
	*tcph = tcp_hdr(skb);

	/* check if IP header and TCP header are complete */
	if (ntohs(iph->tot_len) < ip_len + tcp_hdrlen(skb))
		return -1;

	*hdr_flags = LRO_IPV4 | LRO_TCP;
	*iphdr = iph;

	return 0;
}

static void xsvnic_lro_setup(struct xsvnic *xsvnicp)
{
	xsvnicp->lro.lro_mgr.max_aggr = lro_max_aggr;
	xsvnicp->lro.lro_mgr.max_desc = XSVNIC_MAX_LRO_DESCRIPTORS;
	xsvnicp->lro.lro_mgr.lro_arr = xsvnicp->lro.lro_desc;
	xsvnicp->lro.lro_mgr.get_skb_header = get_skb_hdr;
	xsvnicp->lro.lro_mgr.features = LRO_F_NAPI;
	xsvnicp->lro.lro_mgr.dev = xsvnicp->netdev;
	xsvnicp->lro.lro_mgr.ip_summed_aggr = CHECKSUM_UNNECESSARY;
}

static struct net_device_ops xsvnic_netdev_ops = {
	.ndo_open = xsvnic_open,
	.ndo_stop = xsvnic_stop,
	.ndo_start_xmit = xsvnic_start_xmit,
	.ndo_get_stats = xsvnic_get_stats,
	.ndo_set_rx_mode = xsvnic_set_multicast,
	.ndo_change_mtu = xsvnic_change_mtu,
	.ndo_set_mac_address = xsvnic_set_mac_address,
	.ndo_do_ioctl = xsvnic_ioctl,
	.ndo_tx_timeout = xsvnic_tx_timeout,
	.ndo_vlan_rx_add_vid = xsvnic_vlan_rx_add_vlanid,
	.ndo_vlan_rx_kill_vid = xsvnic_vlan_rx_kill_vlanid
};

static int setup_netdev_info(struct net_device *netdev)
{
	struct xsvnic *xsvnicp = netdev_priv(netdev);
	struct ib_device *hca = xsvnicp->xsmp_info.ib_device;
	u64 mac;

	netdev->watchdog_timeo = 10 * HZ;
	netdev->tx_queue_len = xsvnic_tx_queue_len;
	netdev->features |=
	    NETIF_F_HW_VLAN_CTAG_FILTER | NETIF_F_SG | NETIF_F_GSO |
	    NETIF_F_GRO;
	if (xsvnic_highdma)
		netdev->features |= NETIF_F_HIGHDMA;
	if (xsvnic_vlanaccel) {
		pr_info("XSVNIC:%s Enabling vlan offloading ", __func__);
		pr_info("[xsvnic %s]\n", xsvnicp->vnic_name);
		netdev->features |= NETIF_F_HW_VLAN_CTAG_RX;
	}
	if (lro)
		xsvnicp->lro_mode = 1;
	/*
	 * based on install_flag setting setup TSO flag.
	 * Checksun & SG must be enabled by default
	 * also in case of TSO
	 * NETIF_F_HW_VLAN_TX | NETIF_F_TSO
	 */
	if (xsvnicp->install_flag & (XSVNIC_INSTALL_TCP_OFFL |
				     XSVNIC_INSTALL_UDP_OFFL)
	    || xsvnic_force_csum_offload)
		netdev->features |= NETIF_F_IP_CSUM;

	if (xsvnicp->lro_mode) {
		xsvnic_lro_setup(xsvnicp);
		netdev->features |= NETIF_F_LRO;
	}
	xg_setup_pseudo_device(netdev, hca);

	SET_NETDEV_OPS(netdev, &xsvnic_netdev_ops);
	mac = be64_to_cpu(xsvnicp->mac);
	memcpy(netdev->dev_addr, (u8 *) (&mac) + 2, ETH_ALEN);
	netif_napi_add(netdev, &xsvnicp->napi, xsvnic_poll, napi_weight);
	if (xsvnic_esx_preregister_setup(netdev))
		return -EINVAL;
	return register_netdev(netdev);
}

struct xsvnic *xsvnic_get_xsvnic_by_vid(u64 resource_id)
{
	struct xsvnic *xsvnicp;

	list_for_each_entry(xsvnicp, &xsvnic_list, xsvnic_list) {
		if (xsvnicp->resource_id == resource_id)
			return xsvnicp;
	}
	return NULL;
}

struct xsvnic *xsvnic_get_xsvnic_by_name(char *vnic_name)
{
	struct xsvnic *xsvnicp;

	list_for_each_entry(xsvnicp, &xsvnic_list, xsvnic_list) {
		if (strcmp(xsvnicp->vnic_name, vnic_name) == 0)
			return xsvnicp;
	}
	return NULL;
}

/*
 * Handle install message
 */

static int xsvnic_xsmp_install(xsmp_cookie_t xsmp_hndl,
			       struct xsvnic_xsmp_msg *xmsgp, void *data,
			       int len)
{
	struct net_device *netdev;
	struct xsvnic *xsvnicp;
	u16 mp_flag;
	char vnic_name[128];
	int ret = 0;
	u64 m;
	u8 update_state = 0;
	u8 ecode = 0;
	u8 is_ha = 0;

	XSMP_FUNCTION("%s:\n", __func__);

	xsvnicp = xsvnic_get_xsvnic_by_vid(be64_to_cpu(xmsgp->resource_id));
	if (xsvnicp) {
		/*
		 * Duplicate VID, send ACK, send oper state update
		 */
		XSMP_ERROR("%s: Duplicate VNIC install message name", __func__);
		XSMP_ERROR(",: %s, ", xmsgp->vnic_name);
		XSMP_ERROR("VID=0x%llx\n", be64_to_cpu(xmsgp->resource_id));
		ret = -EEXIST;
		clear_bit(XSVNIC_SYNC_DIRTY, &xsvnicp->state);
		update_state = 1;
		xsvnicp->xsmp_hndl = xsmp_hndl;
		xsvnic_update_tca_info(xsvnicp, xmsgp, 0);
		goto send_ack;
	}

	XSMP_INFO("Installing VNIC : %s, VID=0x%llx\n",
		  xmsgp->vnic_name, be64_to_cpu(xmsgp->resource_id));

	mp_flag = be16_to_cpu(xmsgp->mp_flag);
	/*
	 * Append .P and .S to vnics
	 */
	strncpy(vnic_name, xmsgp->vnic_name, sizeof(vnic_name) - 1);
	if (mp_flag & (MP_XSVNIC_PRIMARY | MP_XSVNIC_SECONDARY)) {
		if (xsvnic_havnic) {
			char *pos;

			strcpy(vnic_name, xmsgp->mp_group);

			pos = strchr(vnic_name, '.');
			if (pos != 0)
				*pos = 0;
			is_ha = 1;
			strncpy(xmsgp->vnic_name, vnic_name,
				sizeof(xmsgp->vnic_name) - 1);
			if (mp_flag & MP_XSVNIC_PRIMARY)
				strcat(vnic_name, "_P");
			else
				strcat(vnic_name, "_S");
		} else {
			pr_warn("XSVNIC: %s HA vnic not ", xmsgp->vnic_name);
			pr_warn("supported\n");
			ret = -EINVAL;
			ecode = XSVNIC_NACK_ALLOCATION_ERROR;
			goto dup_error;
		}
	}

	if (xcpm_check_duplicate_names(xsmp_hndl, vnic_name,
				       XSMP_MESSAGE_TYPE_XVE) != 0) {
		pr_info("%s Duplicate name %s\n", __func__, vnic_name);
		goto dup_error;
	}

	xsvnicp = xsvnic_get_xsvnic_by_name(vnic_name);
	if (xsvnicp) {
		XSMP_ERROR("%s: Duplicate name: %s, VID=0x%llx\n",
			   __func__, xmsgp->vnic_name,
			   be64_to_cpu(xmsgp->resource_id));
		ret = -EEXIST;
		ecode = XSVNIC_NACK_DUP_NAME;
		goto dup_error;
	}
	/*
	 * Check for the long name vnic
	 */
	if (strlen(vnic_name) > XSVNIC_VNIC_NAMELENTH) {
		pr_err("XSVNIC: vnic_name %s,", xmsgp->vnic_name);
		pr_err("length > 15 not supported\n");
		ret = -EINVAL;
		ecode = XSVNIC_NACK_INVALID;
		goto dup_error;
	}

	netdev = alloc_netdev(sizeof(*xsvnicp), vnic_name, NET_NAME_UNKNOWN,
			      &xsvnic_setup);
	if (netdev == NULL) {
		XSMP_ERROR("%s: alloc_netdev error name: %s, VID=0x%llx\n",
			   __func__, xmsgp->vnic_name,
			   be64_to_cpu(xmsgp->resource_id));
		ret = -ENOMEM;
		ecode = XSVNIC_NACK_ALLOCATION_ERROR;
		goto dup_error;
	}
	xsvnicp = netdev_priv(netdev);
	memset(xsvnicp, 0, sizeof(*xsvnicp));
	xsvnicp->netdev = netdev;
	INIT_LIST_HEAD(&xsvnicp->vlan_list);
	INIT_LIST_HEAD(&xsvnicp->xsvnic_list);
	init_completion(&xsvnicp->done);
	mutex_init(&xsvnicp->mutex);
	spin_lock_init(&xsvnicp->lock);
	xsvnicp->resource_id = be64_to_cpu(xmsgp->resource_id);
	xsvnicp->bandwidth = be16_to_cpu(xmsgp->vn_admin_rate);
	m = xmsgp->mac_high;
	xsvnicp->mac = m << 32 | xmsgp->mac_low;
	memcpy(xsvnicp->vnic_name, vnic_name, XSVNIC_MAX_NAME_SIZE - 1);
	xsvnicp->vnic_name[XSVNIC_MAX_NAME_SIZE - 1] = 0;
	memcpy(xsvnicp->mp_group, xmsgp->mp_group, XSVNIC_MAX_NAME_SIZE - 1);
	xsvnicp->mp_group[XSVNIC_MAX_NAME_SIZE - 1] = 0;
	xsvnicp->sl = be16_to_cpu(xmsgp->service_level);
	xsvnicp->mp_flag = be16_to_cpu(xmsgp->mp_flag);
	xsvnicp->install_flag = be32_to_cpu(xmsgp->install_flag);
	xsvnicp->mtu = be16_to_cpu(xmsgp->vn_mtu);
	xsvnicp->tca_guid = be64_to_cpu(xmsgp->tca_guid);
	xsvnicp->tca_lid = be16_to_cpu(xmsgp->tca_lid);
	xsvnicp->xsmp_hndl = xsmp_hndl;
	xcpm_get_xsmp_session_info(xsmp_hndl, &xsvnicp->xsmp_info);

	/*
	 * In case of Non-HA set state to ACTIVE
	 */
	if (!is_ha)
		xsvnicp->ha_state = XSVNIC_HA_STATE_ACTIVE;
	/*
	 * If MTU is JUMBO ot if it is LLE use default 256
	 */
	if (xsvnicp->mtu > 1518 || !xsvnicp->xsmp_info.is_shca) {
		xsvnicp->rx_ring_size = xsvnic_rxring_size;
		xsvnicp->tx_ring_size = xsvnic_txring_size;
	} else {
		xsvnicp->rx_ring_size = xsvnic_rxring_size;
		xsvnicp->tx_ring_size = xsvnic_txring_size;
	}

	netdev->mtu = xsvnicp->mtu;
	/*
	 * Always set chassis ADMIN up by default
	 */
	set_bit(XSVNIC_CHASSIS_ADMIN_UP, &xsvnicp->state);
	set_bit(XSVNIC_CHASSIS_ADMIN_SHADOW_UP, &xsvnicp->state);

	INIT_DELAYED_WORK(&xsvnicp->sm_work, xsvnic_state_machine_work);

	if (xsvnicp->install_flag & XSVNIC_INSTALL_TSO) {
		xsvnicp->is_tso = 1;
		/* BUG 22267 */
		/* xsvnicp->lro_mode = 1; */
		/*
		 * Add additional 8 bytes data for TSO header
		 */
		netdev->hard_header_len += 8;
		netdev->features |= NETIF_F_TSO;
	}

	if (xsvnic_conn_init(xsvnicp)) {
		XSMP_ERROR("%s: xsvnic_conn_init error name: %s, VID=0x%llx\n",
			   __func__, vnic_name,
			   be64_to_cpu(xmsgp->resource_id));
		ecode = XSVNIC_NACK_ALLOCATION_ERROR;
		goto proc_error;
	}

	ret = xsvnic_add_proc_entry(xsvnicp);
	if (ret) {
		XSMP_ERROR("%s: procfs error name: %s, VID=0x%llx\n",
			   __func__, vnic_name,
			   be64_to_cpu(xmsgp->resource_id));
		goto proc_error;
	}

	ret = setup_netdev_info(netdev);
	if (ret) {
		XSMP_ERROR("%s: setup_netdev_info error name: ,", __func__);
		XSMP_ERROR("%s VID=0x%llx ret %x\n",
			   vnic_name, be64_to_cpu(xmsgp->resource_id), ret);
		ecode = XSVNIC_NACK_ALLOCATION_ERROR;
		goto setup_netdev_info_error;
	}

	netif_carrier_off(netdev);
	netif_stop_queue(netdev);

	if (xsvnic_esx_postregister_setup(netdev)) {
		ecode = XSVNIC_NACK_ALLOCATION_ERROR;
		goto post_reg_err;
	}
	/*
	 * Add it to the list, mutex held for all XSMP processing
	 */
	list_add_tail(&xsvnicp->xsvnic_list, &xsvnic_list);
	pr_info("Installed XSVNIC vnic %s, ", vnic_name);
	pr_info("VID=0x%llx, tca_guid: 0x%llx, tca lid: 0x%x tso %d\n",
		xsvnicp->resource_id, xsvnicp->tca_guid,
		xsvnicp->tca_lid, xsvnicp->is_tso);
	/*
	 * Send ADMIN down and OPER down
	 */
	xsvnic_send_msg_to_xsigod(xsmp_hndl, data, len);
	atomic_inc(&xsvnicp->ref_cnt);
	xsvnicp->sm_delay = 1000;
	queue_sm_work(xsvnicp, 0);
	/*
	 * Send ACK
	 */
send_ack:
	ret = xsvnic_xsmp_send_ack(xsmp_hndl, xmsgp);
	if (ret) {
		XSMP_ERROR
		    ("%s: xsvnic_xsmp_send_ack error name: %s, VID=0x%llx\n",
		     __func__, xmsgp->vnic_name,
		     be64_to_cpu(xmsgp->resource_id));
	}
	if (update_state)
		xsvnic_update_oper_state(xsvnicp);

	return 0;

post_reg_err:
	unregister_netdev(netdev);
setup_netdev_info_error:
	xsvnic_remove_proc_entry(xsvnicp);
proc_error:
	free_netdev(netdev);
dup_error:
	(void)xsvnic_xsmp_send_nack(xsmp_hndl, xmsgp, sizeof(*xmsgp), ecode);
	return ret;
}

static int xsvnic_remove_vnic(struct xsvnic *xsvnicp)
{
	struct vlan_entry *vlan, *tvlan;

	mutex_lock(&xsvnicp->mutex);
	xsvnic_io_disconnect(xsvnicp);
	mutex_unlock(&xsvnicp->mutex);

	xsvnic_put_ctx(xsvnicp);
	/*
	 * Wait for refernce count to goto zero
	 */
	while (atomic_read(&xsvnicp->ref_cnt)) {
		DRV_ERROR("%s: Waiting for refcnt to become zero %d\n",
			  __func__, atomic_read(&xsvnicp->ref_cnt));
		msleep(100);
	}
	mutex_lock(&xsvnic_mutex);
	list_del(&xsvnicp->xsvnic_list);
	mutex_unlock(&xsvnic_mutex);
	vmk_notify_uplink(xsvnicp->netdev);
	unregister_netdev(xsvnicp->netdev);
	pr_info("XSVNIC: %s deleted\n", xsvnicp->vnic_name);
	xscore_conn_destroy(&xsvnicp->ctrl_conn.ctx);
	xscore_conn_destroy(&xsvnicp->data_conn.ctx);
	list_for_each_entry_safe(vlan, tvlan, &xsvnicp->vlan_list, vlan_list) {
		list_del(&vlan->vlan_list);
		kfree(vlan);
	}

	if (xsvnicp->mc_addrs != NULL)
		kfree(xsvnicp->mc_addrs);

	xsvnic_remove_proc_entry(xsvnicp);
	if (!test_bit(XSVNIC_SHUTDOWN, &xsvnicp->state)) {
		if (xsvnicp->mp_flag &
		    (MP_XSVNIC_PRIMARY | MP_XSVNIC_SECONDARY)) {
			/*
			 * Punt the message to xsigod to handle
			 */
			xsvnic_send_cmd_to_xsigod(xsvnicp, XSMP_XSVNIC_DELETE);
		}
		/*
		 * Ideally need to figure out why userspace ACK is not working
		 */
		xsvnic_xsmp_send_notification(xsvnicp->xsmp_hndl,
					      xsvnicp->resource_id,
					      XSMP_XSVNIC_DELETE);
	}
	free_netdev(xsvnicp->netdev);
	return 0;
}

static int handle_admin_state_change(struct xsvnic *xsvnicp,
				     struct xsvnic_xsmp_msg *xmsgp)
{
	if (xmsgp->admin_state) {
		XSMP_INFO("%s: VNIC %s Admin state up message\n", __func__,
			  xsvnicp->vnic_name);
		if (!test_bit(XSVNIC_CHASSIS_ADMIN_UP, &xsvnicp->state)) {
			xsvnicp->counters[XSVNIC_ADMIN_UP_COUNTER]++;
			set_bit(XSVNIC_CHASSIS_ADMIN_SHADOW_UP,
				&xsvnicp->state);
			set_bit(XSVNIC_SEND_ADMIN_STATE, &xsvnicp->state);
		}
	} else {		/* Admin Down */
		XSMP_INFO("%s: VNIC %s Admin state down message\n",
			  __func__, xsvnicp->vnic_name);
		if (test_bit(XSVNIC_CHASSIS_ADMIN_UP, &xsvnicp->state)) {
			xsvnicp->counters[XSVNIC_ADMIN_DOWN_COUNTER]++;
			clear_bit(XSVNIC_CHASSIS_ADMIN_UP, &xsvnicp->state);
			clear_bit(XSVNIC_CHASSIS_ADMIN_SHADOW_UP,
				  &xsvnicp->state);
			set_bit(XSVNIC_SEND_ADMIN_STATE, &xsvnicp->state);
		}
	}
	return 0;
}

static void xsvnic_xsmp_handle_oper_req(xsmp_cookie_t xsmp_hndl,
					u64 resource_id)
{
	struct xsvnic *xsvnicp;

	xsvnicp = xsvnic_get_xsvnic_by_vid(resource_id);
	if (!xsvnicp) {
		XSMP_ERROR("%s: request for invalid vid: 0x%llx\n",
			   __func__, resource_id);
		return;
	}
	XSMP_INFO("VNIC: %s Oper Req from chassis\n", xsvnicp->vnic_name);
	xsvnicp->counters[XSVNIC_OPER_REQ_COUNTER]++;
	xsvnic_xsmp_send_oper_state(xsvnicp, resource_id,
				    test_bit(XSVNIC_OPER_UP, &xsvnicp->state)
				    ? XSMP_XSVNIC_OPER_UP :
				    XSMP_XSVNIC_OPER_DOWN);
}

static void xsvnic_update_tca_info(struct xsvnic *xsvnicp,
				   struct xsvnic_xsmp_msg *xmsgp,
				   int set_oper_down)
{
	/*
	 * Ignore invalid tca info
	 */
	if (be64_to_cpu(xmsgp->tca_guid) == 0
	    || be16_to_cpu(xmsgp->tca_lid) == 0)
		return;
	if (xsvnicp->tca_guid != be64_to_cpu(xmsgp->tca_guid) ||
	    xsvnicp->tca_lid != be16_to_cpu(xmsgp->tca_lid)) {
		xsvnicp->counters[XSVNIC_XT_LID_CHANGE_COUNTER]++;
		pr_info("XSVNIC %s TCA id changed from", xsvnicp->vnic_name);
		pr_info("(0x%Lx:0x%d) to (0x%Lx:0x%d)\n",
			xsvnicp->tca_guid,
			xsvnicp->tca_lid,
			be64_to_cpu(xmsgp->tca_guid),
			be16_to_cpu(xmsgp->tca_lid));
		xsvnicp->tca_guid = be64_to_cpu(xmsgp->tca_guid);
		xsvnicp->tca_lid = be16_to_cpu(xmsgp->tca_lid);
		xsvnicp->ctrl_conn.ctx.dguid = xsvnicp->tca_guid;
		xsvnicp->data_conn.ctx.dguid = xsvnicp->tca_guid;
		xsvnicp->ctrl_conn.ctx.dlid = xsvnicp->tca_lid;
		xsvnicp->data_conn.ctx.dlid = xsvnicp->tca_lid;
		if (set_oper_down)
			xsvnic_set_oper_down(xsvnicp, 1);
	}
}

static int xsvnic_xsmp_update(xsmp_cookie_t xsmp_hndl,
			      struct xsvnic_xsmp_msg *xmsgp)
{
	u32 bitmask = be32_to_cpu(xmsgp->bitmask);
	struct xsvnic *xsvnicp;
	int ret = 0;
	int send_ack = 1;

	xsvnicp = xsvnic_get_xsvnic_by_vid(be64_to_cpu(xmsgp->resource_id));
	if (!xsvnicp) {
		XSMP_ERROR("%s: request for invalid vid: 0x%llx\n",
			   __func__, be64_to_cpu(xmsgp->resource_id));
		return -EINVAL;
	}

	XSMP_INFO("%s: VNIC: %s bit mask: 0x%x\n", __func__,
		  xsvnicp->vnic_name, bitmask);

	mutex_lock(&xsvnicp->mutex);

	if (bitmask & XSVNIC_UPDATE_ADMIN_STATE) {
		ret = handle_admin_state_change(xsvnicp, xmsgp);
		/*
		 * Ack will be sent once QP's are brought down
		 */
		send_ack = 0;
	}

	if (bitmask & XSVNIC_XT_STATE_DOWN) {
		XSMP_INFO("%s: VNIC %s XT state down message\n",
			  __func__, xsvnicp->vnic_name);
		xsvnicp->counters[XSVNIC_XT_DOWN_COUNTER]++;
		set_bit(XSVNIC_XT_DOWN, &xsvnicp->state);
		xsvnic_set_oper_down(xsvnicp, 1);
	}

	if (bitmask & XSVNIC_UPDATE_XT_CHANGE) {
		XSMP_INFO("%s: VNIC %s XT state change message\n",
			  __func__, xsvnicp->vnic_name);
		xsvnicp->counters[XSVNIC_XT_UPDATE_COUNTER]++;
		xsvnic_update_tca_info(xsvnicp, xmsgp, 1);
		clear_bit(XSVNIC_XT_DOWN, &xsvnicp->state);
	}

	if (send_ack && xsvnic_xsmp_send_ack(xsmp_hndl, xmsgp)) {
		XSMP_ERROR
		    ("%s: xsvnic_xsmp_send_ack error name: %s, VID=0x%llx\n",
		     __func__, xmsgp->vnic_name,
		     be64_to_cpu(xmsgp->resource_id));
	}
	mutex_unlock(&xsvnicp->mutex);

	return ret;
}

/*
 * Called with global mutex held to protect xsvnic_list
 */
static void xsvnic_xsmp_sync_begin(xsmp_cookie_t xsmp_hndl, void *msg)
{
	struct xsvnic *xsvnicp;

	list_for_each_entry(xsvnicp, &xsvnic_list, xsvnic_list) {
		if (xsmp_sessions_match(&xsvnicp->xsmp_info, xsmp_hndl)) {
			xsvnicp->xsmp_hndl = xsmp_hndl;
			/*
			 * Do not handle SYNC_BEGIN end. SOmetimes bug
			 * on IO director causes unnecessary delete
			 */
#if 0
			set_bit(XSVNIC_SYNC_DIRTY, &xsvnicp->state);
#endif
		}
	}
}

static void xsvnic_update_oper_state(struct xsvnic *xsvnicp)
{
	if (xsvnicp->mp_flag & (MP_XSVNIC_PRIMARY | MP_XSVNIC_SECONDARY))
		xsvnic_xsmp_send_ha_state(xsvnicp, xsvnicp->ha_state);
	xsvnic_xsmp_send_oper_state(xsvnicp, xsvnicp->resource_id,
				    test_bit(XSVNIC_OPER_UP, &xsvnicp->state) ?
				    XSMP_XSVNIC_OPER_UP :
				    XSMP_XSVNIC_OPER_DOWN);
}

/*
 * Called with global mutex held to protect xsvnic_list
 */
static void xsvnic_xsmp_sync_end(xsmp_cookie_t xsmp_hndl)
{
	struct xsvnic *xsvnicp;
	unsigned long flags;

	list_for_each_entry(xsvnicp, &xsvnic_list, xsvnic_list) {
		if (xsmp_sessions_match(&xsvnicp->xsmp_info, xsmp_hndl)) {
			if (test_bit(XSVNIC_SYNC_DIRTY, &xsvnicp->state)) {
				pr_info("XSVNIC %s ", xsvnicp->vnic_name);
				pr_info("deleted due to sync end condition\n");
				xsvnic_counters[XSVNIC_SYNC_END_DEL_COUNTER]++;
				spin_lock_irqsave(&xsvnicp->lock, flags);
				set_bit(XSVNIC_DELETING, &xsvnicp->state);
				spin_unlock_irqrestore(&xsvnicp->lock, flags);
			} else
				xsvnic_update_oper_state(xsvnicp);
		}
	}
}

/*
 * We set the DELETING bit and let sm_work thread handle delete
 */
static void xsvnic_handle_del_message(xsmp_cookie_t xsmp_hndl,
				      struct xsvnic_xsmp_msg *xmsgp)
{
	struct xsvnic *xsvnicp;
	unsigned long flags;

	xsvnicp = xsvnic_get_xsvnic_by_vid(be64_to_cpu(xmsgp->resource_id));
	if (!xsvnicp) {
		xsvnic_counters[XSVNIC_VNIC_DEL_NOVID_COUNTER]++;
		return;
	}
	spin_lock_irqsave(&xsvnicp->lock, flags);
	set_bit(XSVNIC_DELETING, &xsvnicp->state);
	spin_unlock_irqrestore(&xsvnicp->lock, flags);
}

static void xsvnic_send_cmd_to_xsigod(struct xsvnic *xsvnicp, int cmd)
{
	struct xsmp_message_header *xhdr;
	struct xsvnic_xsmp_msg *xmsgp;
	int tlen = sizeof(*xmsgp) + sizeof(*xhdr);

	xhdr = xcpm_alloc_msg(tlen);
	if (!xhdr)
		return;
	memset(xhdr, 0, tlen);
	xhdr->type = XSMP_MESSAGE_TYPE_VNIC;
	xhdr->length = tlen;
	xmsgp = (struct xsvnic_xsmp_msg *)(xhdr + 1);
	xmsgp->type = cmd;
	strcpy(xmsgp->vnic_name, xsvnicp->vnic_name);
	xmsgp->resource_id = cpu_to_be64(xsvnicp->resource_id);
	xmsgp->mp_flag = cpu_to_be16(xsvnicp->mp_flag);
	xmsgp->code = 0;
	xmsgp->length = cpu_to_be16(sizeof(*xmsgp));
	if (xcpm_send_msg_xsigod(xsvnicp->xsmp_hndl, xhdr, tlen))
		xcpm_free_msg(xhdr);
}

static void xsvnic_send_msg_to_xsigod(xsmp_cookie_t xsmp_hndl, void *data,
				      int len)
{
	void *tmsg;

	tmsg = xcpm_alloc_msg(len);
	if (!tmsg)
		return;
	memcpy(tmsg, data, len);
	if (xcpm_send_msg_xsigod(xsmp_hndl, tmsg, len))
		xcpm_free_msg(tmsg);
}

static void xsvnic_handle_ip_req(xsmp_cookie_t xsmp_hndl, u8 *data, int len)
{
	struct xsvnic_xsmp_vlanip_msg *msgp =
	    (struct xsvnic_xsmp_vlanip_msg *)(data + sizeof(struct
		xsmp_message_header));
	struct xsvnic *xsvnicp;

	XSMP_INFO("%s:XSMP message type VLAN IP\n", __func__);

	xsvnicp = xsvnic_get_xsvnic_by_vid(be64_to_cpu(msgp->resource_id));
	if (!xsvnicp) {
		xsvnic_counters[XSVNIC_VNIC_DEL_NOVID_COUNTER]++;
		return;
	}
	strcpy(msgp->ifname, xsvnicp->vnic_name);
	msgp->mp_flag = cpu_to_be16(xsvnicp->mp_flag);
	/*
	 * Punt this message to userspace
	 */
	xsvnic_send_msg_to_xsigod(xsmp_hndl, data, len);
}

static void xsvnic_process_iscsi_info(xsmp_cookie_t xsmp_hndl, u8 *data,
				      int len)
{
	struct xsvnic_iscsi_msg *iscsi_msg = (struct xsvnic_iscsi_msg *)
	    (data + sizeof(struct xsmp_message_header));
	struct xsvnic_iscsi_info *isp;
	struct xsvnic *xsvnicp;

	XSMP_INFO("%s:XSMP message type iscsi info\n", __func__);
	xsvnicp =
	    xsvnic_get_xsvnic_by_vid(be64_to_cpu(iscsi_msg->iscsi_info.vid));
	if (!xsvnicp) {
		xsvnic_counters[XSVNIC_VNIC_DEL_NOVID_COUNTER]++;
		return;
	}
	/*
	 * Now copy over iSCSI information
	 */
	isp = &xsvnicp->iscsi_boot_info;
	isp->vid = be64_to_cpu(iscsi_msg->iscsi_info.vid);
	isp->vlan_id = be16_to_cpu(iscsi_msg->iscsi_info.vlan_id);
	isp->mac = be64_to_cpu(iscsi_msg->iscsi_info.mac);
	isp->protocol = be16_to_cpu(iscsi_msg->iscsi_info.protocol);
	isp->port = be16_to_cpu(iscsi_msg->iscsi_info.port);
	isp->lun = be16_to_cpu(iscsi_msg->iscsi_info.lun);
	isp->mount_type = be16_to_cpu(iscsi_msg->iscsi_info.mount_type);
	isp->role = iscsi_msg->iscsi_info.role;
	isp->ip_type = iscsi_msg->iscsi_info.ip_type;
	isp->ip_addr = iscsi_msg->iscsi_info.ip_addr;
	isp->netmask = iscsi_msg->iscsi_info.netmask;
	isp->gateway_ip_address = iscsi_msg->iscsi_info.gateway_ip_address;
	isp->dns_ip_address = iscsi_msg->iscsi_info.dns_ip_address;
	isp->target_ip_address = iscsi_msg->iscsi_info.target_ip_address;
	memcpy(isp->vnic_name, iscsi_msg->iscsi_info.vnic_name,
	       XSVNIC_MAX_NAME_SIZE);
	memcpy(isp->domain_name, iscsi_msg->iscsi_info.domain_name,
	       MAX_DOMAIN_NAME_LEN);
	memcpy(isp->target_iqn, iscsi_msg->iscsi_info.target_iqn,
	       ISCSI_MOUNT_DEV_NAME_LEN);
	memcpy(isp->target_portal_group,
	       iscsi_msg->iscsi_info.target_portal_group,
	       ISCSI_MOUNT_DEV_NAME_LEN);
	memcpy(isp->initiator_iqn, iscsi_msg->iscsi_info.initiator_iqn,
	       ISCSI_MOUNT_DEV_NAME_LEN);
	memcpy(isp->mount_dev, iscsi_msg->iscsi_info.mount_dev,
	       ISCSI_MOUNT_DEV_NAME_LEN);
	memcpy(isp->mount_options, iscsi_msg->iscsi_info.mount_options,
	       ISCSI_MOUNT_DEV_NAME_LEN);
	memcpy(isp->vol_group, iscsi_msg->iscsi_info.vol_group,
	       ISCSI_MOUNT_DEV_NAME_LEN);
	memcpy(isp->vol_group_name, iscsi_msg->iscsi_info.vol_group_name,
	       ISCSI_MOUNT_DEV_NAME_LEN);
}

static void handle_xsvnic_xsmp_messages(xsmp_cookie_t xsmp_hndl, u8 *data,
					int length)
{
	int hlen;
	struct xsmp_message_header *header = (struct xsmp_message_header *)data;
	struct xsvnic_xsmp_msg *xmsgp =
	    (struct xsvnic_xsmp_msg *)(data + sizeof(*header));

	XSMP_FUNCTION("%s:\n", __func__);

	if (length < sizeof(*header)) {
		XSMP_ERROR("%s:XSMP message too short: act length: %d\n",
			   __func__, length);
		return;
	}
	hlen = be16_to_cpu(header->length);
	if (hlen > length) {
		XSMP_ERROR
		    ("%s:XSMP header length greater than payload length %d\n",
		     __func__, length);
		return;
	}
	if (header->type != XSMP_MESSAGE_TYPE_VNIC) {
		XSMP_ERROR("%s:XSMP message type not VNIC type: %d\n",
			   __func__, header->type);
		return;
	}

	XSMP_INFO("%s: XSMP message type: %d\n", __func__, xmsgp->type);

	mutex_lock(&xsvnic_mutex);

	switch (xmsgp->type) {
	case XSMP_XSVNIC_VLANIP:
		xsvnic_handle_ip_req(xsmp_hndl, data, length);
		break;
	case XSMP_XSVNIC_INFO_REQUEST:
		break;
	case XSMP_XSVNIC_INSTALL:
		xsvnic_counters[XSVNIC_VNIC_INSTALL_COUNTER]++;
		xsvnic_xsmp_install(xsmp_hndl, xmsgp, data, length);
		break;
	case XSMP_XSVNIC_DELETE:
		xsvnic_handle_del_message(xsmp_hndl, xmsgp);
		xsvnic_counters[XSVNIC_VNIC_DEL_COUNTER]++;
		break;
	case XSMP_XSVNIC_UPDATE:
		xsvnic_counters[XSVNIC_VNIC_UPDATE_COUNTER]++;
		xsvnic_xsmp_update(xsmp_hndl, xmsgp);
		break;
	case XSMP_XSVNIC_SYNC_BEGIN:
		xsvnic_counters[XSVNIC_VNIC_SYNC_BEGIN_COUNTER]++;
		xsvnic_xsmp_sync_begin(xsmp_hndl, xmsgp);
		break;
	case XSMP_XSVNIC_SYNC_END:
		xsvnic_counters[XSVNIC_VNIC_SYNC_END_COUNTER]++;
		xsvnic_xsmp_sync_end(xsmp_hndl);
		break;
	case XSMP_XSVNIC_OPER_REQ:
		xsvnic_counters[XSVNIC_VNIC_OPER_REQ_COUNTER]++;
		(void)xsvnic_xsmp_handle_oper_req(xsmp_hndl,
						  be64_to_cpu(xmsgp->
							      resource_id));
		break;
	case XSMP_XSVNIC_ISCSI_INFO:
		xsvnic_counters[XSVNIC_ISCSI_INFO_COUNTER]++;
		xsvnic_process_iscsi_info(xsmp_hndl, data, length);
		break;
	default:
		xsvnic_counters[XSVNIC_VNIC_UNSUP_XSMP_COUNTER]++;
		XSMP_ERROR("%s: Unsupported VNIX XSMP message: %d\n",
			   __func__, xmsgp->type);
		break;
	}
	mutex_unlock(&xsvnic_mutex);
}

static void handle_xsvnic_xsmp_messages_work(struct work_struct *work)
{
	struct xsvnic_work *xwork = container_of(work, struct xsvnic_work,
						 work);

	(void)handle_xsvnic_xsmp_messages(xwork->xsmp_hndl, xwork->msg,
					  xwork->len);
	kfree(xwork->msg);
	kfree(xwork);
}

/*
 * Called from thread context
 */
static void xsvnic_receive_handler(xsmp_cookie_t xsmp_hndl, u8 *msg,
				   int length)
{
	struct xsvnic_work *work;
	unsigned long flags;

	XSMP_FUNCTION("%s:\n", __func__);

	work = kmalloc(sizeof(*work), GFP_KERNEL);
	if (!work) {
		XSMP_ERROR("%s: Out of memory\n", __func__);
		kfree(msg);
		return;
	}
	INIT_WORK(&work->work, handle_xsvnic_xsmp_messages_work);
	work->xsmp_hndl = xsmp_hndl;
	work->msg = msg;
	work->len = length;
	spin_lock_irqsave(&xsvnic_lock, flags);
	/*
	 * Do some checks here
	 * Add counter
	 */
	queue_work(xsvnic_wq, &work->work);
	spin_unlock_irqrestore(&xsvnic_lock, flags);
}

/*
 * Needs to be called with xsvnic_mutex lock held
 */
static void xsvnic_wait_for_removal(xsmp_cookie_t xsmp_hndl)
{
	int is_pres;
	struct xsvnic *xsvnicp;

	while (1) {
		is_pres = 0;
		list_for_each_entry(xsvnicp, &xsvnic_list, xsvnic_list) {
			if (xsmp_sessions_match(&xsvnicp->xsmp_info, xsmp_hndl))
				is_pres = 1;
		}
		if (is_pres) {
			mutex_unlock(&xsvnic_mutex);
			msleep(100);
			mutex_lock(&xsvnic_mutex);
		} else
			break;
	}
}

/*
 * Called from thread context
 */
static void xsvnic_xsmp_event_handler(xsmp_cookie_t xsmp_hndl, int event)
{
	struct xsvnic *xsvnicp;
	unsigned long flags;

	mutex_lock(&xsvnic_mutex);

	switch (event) {
	case XSCORE_PORT_UP:
	case XSCORE_PORT_DOWN:
		list_for_each_entry(xsvnicp, &xsvnic_list, xsvnic_list) {
			if (xsmp_sessions_match(&xsvnicp->xsmp_info,
				xsmp_hndl)) {
				if (event == XSCORE_PORT_DOWN) {
					set_bit(XSVNIC_IBLINK_DOWN,
						&xsvnicp->state);
					xsvnic_set_oper_down(xsvnicp, 1);
					xsvnicp->counters
					    [XSVNIC_IBLINK_DOWN_COUNTER]++;
				} else {
					clear_bit(XSVNIC_IBLINK_DOWN,
						  &xsvnicp->state);
					xsvnicp->counters
					    [XSVNIC_IBLINK_UP_COUNTER]++;
				}
			}
		}
		break;
	case XSCORE_DEVICE_REMOVAL:
		xsvnic_counters[XSVNIC_DEVICE_REMOVAL_COUNTER]++;
		list_for_each_entry(xsvnicp, &xsvnic_list, xsvnic_list) {
			if (xsmp_sessions_match(&xsvnicp->xsmp_info,
				xsmp_hndl)) {
				spin_lock_irqsave(&xsvnicp->lock, flags);
				set_bit(XSVNIC_DELETING, &xsvnicp->state);
				spin_unlock_irqrestore(&xsvnicp->lock, flags);
			}
		}
		/*
		 * Now wait for all the vnics to be deleted
		 */
		xsvnic_wait_for_removal(xsmp_hndl);
		break;
	case XSCORE_CONN_CONNECTED:
		list_for_each_entry(xsvnicp, &xsvnic_list, xsvnic_list) {
			if (xsmp_sessions_match(&xsvnicp->xsmp_info, xsmp_hndl))
				xsvnicp->xsmp_hndl = xsmp_hndl;
		}
		break;
	default:
		break;
	}

	mutex_unlock(&xsvnic_mutex);
}

static int xsvnic_xsmp_callout_handler(char *name)
{
	struct xsvnic *xsvnicp;
	int ret = 0;

	mutex_lock(&xsvnic_mutex);
	list_for_each_entry(xsvnicp, &xsvnic_list, xsvnic_list) {
		/* CHECK for duplicate name */
		if (strcmp(xsvnicp->vnic_name, name) == 0) {
			ret = -EINVAL;
			break;
		}
	}
	mutex_unlock(&xsvnic_mutex);
	return ret;
}

int xsvnic_xsmp_init(void)
{
	struct xsmp_service_reg_info service_info = {
		.receive_handler = xsvnic_receive_handler,
		.event_handler = xsvnic_xsmp_event_handler,
		.callout_handler = xsvnic_xsmp_callout_handler,
		.ctrl_message_type = XSMP_MESSAGE_TYPE_VNIC,
		.resource_flag_index = RESOURCE_FLAG_INDEX_VNIC
	};

	struct xsmp_service_reg_info service_info_ha = {
		.ctrl_message_type = XSMP_MESSAGE_TYPE_SESSION
	};

	xsvnic_xsmp_service_id = xcpm_register_service(&service_info);
	if (xsvnic_xsmp_service_id < 0)
		return xsvnic_xsmp_service_id;

	if (!xsvnic_havnic) {
		service_info_ha.resource_flag_index = RESOURCE_FLAG_INDEX_NO_HA;
		xsigo_session_service_id =
		    xcpm_register_service(&service_info_ha);
		if (xsigo_session_service_id < 0)
			return xsigo_session_service_id;
	}

	return 0;
}

void xsvnic_xsmp_exit(void)
{
	(void)xcpm_unregister_service(xsvnic_xsmp_service_id);
	xsvnic_xsmp_service_id = -1;
	if (!xsvnic_havnic) {
		(void)xcpm_unregister_service(xsigo_session_service_id);
		xsigo_session_service_id = -1;
	}

}

int xsvnic_wait_for_first(void)
{
	int secs = xsvnic_wait_per_vnic;

	/* Total wait is xsvnic_wait_for_vnic seconds */
	mutex_lock(&xsvnic_mutex);
	DRV_INFO("%s: Checking for first Vnic to be up\n", __func__);
	while (list_empty(&xsvnic_list) && secs) {
		mutex_unlock(&xsvnic_mutex);
		msleep(1000);
		secs--;
		mutex_lock(&xsvnic_mutex);
	}
	mutex_unlock(&xsvnic_mutex);
	DRV_INFO("%s: Finished Waiting for first Vnic to be up\n", __func__);
	return secs > 0;
}

int xsvnic_all_up(void)
{
	int allup = 1;
	struct xsvnic *xsvnicp;

	mutex_lock(&xsvnic_mutex);
	list_for_each_entry(xsvnicp, &xsvnic_list, xsvnic_list) {
		if (!test_bit(XSVNIC_OPER_UP, &xsvnicp->state))
			allup = 0;
	}
	mutex_unlock(&xsvnic_mutex);
	return allup;
}

static int xsvnic_wait_for_all_vnics_up(void)
{
	int time, delayms = 200;

	/* Total wait is xsvnic_wait_for_vnic seconds */
	DRV_INFO("%s: Checking for VNIC's to be up\n", __func__);
	for (time = 0; time < xsvnic_wait_per_vnic * 1000; time += delayms) {
		if (xsvnic_all_up()) {
			DRV_INFO("%s: VNIC's are up\n", __func__);
			return 1;
		}
		msleep(delayms);
	}
	DRV_INFO("%s: VNIC's are not up\n", __func__);
	return 0;
}

static void xsvnic_wait_for_vnics(void)
{
	unsigned long wait_time = jiffies;

	if (xsvnic_wait_in_boot && xscore_wait_for_sessions(0)) {
		pr_info("XSVNIC: Waiting for VNIC's to come up .....\n");
		if (xsvnic_wait_for_first())
			xsvnic_wait_for_all_vnics_up();
		else
			DRV_INFO("%s: No VNIC's present\n", __func__);
	}
	xsvnic_wait_time = jiffies - wait_time;
}

/*
 * Module initialization entry point
 */

static int __init xsvnic_init(void)
{
	int ret;

	DRV_FUNCTION("%s\n", __func__);

	spin_lock_init(&xsvnic_lock);
	INIT_LIST_HEAD(&xsvnic_list);
	mutex_init(&xsvnic_mutex);
	xsvnic_wq = create_singlethread_workqueue("xsv_wq");
	if (!xsvnic_wq) {
		DRV_ERROR("%s: create_singlethread_workqueue failed\n",
			  __func__);
		return -ENOMEM;
	}
	xsvnic_io_wq = create_singlethread_workqueue("xsviowq");
	if (!xsvnic_io_wq) {
		DRV_ERROR("%s: create_singlethread_workqueue failed\n",
			  __func__);
		ret = -ENOMEM;
		goto io_wq_error;
	}
	ret = xsvnic_create_procfs_root_entries();
	if (ret) {
		DRV_ERROR("%s: xsvnic_create_procfs_root_entries failed %d\n",
			  __func__, ret);
		goto proc_error;
	}
	ret = xsvnic_xsmp_init();
	if (ret) {
		DRV_ERROR("%s: xsvnic_xsmp_init failed %d\n", __func__, ret);
		goto xsmp_err;
	}
	/* Wait for VNIC's to come up */
	xsvnic_wait_for_vnics();
	return ret;

xsmp_err:
	xsvnic_remove_procfs_root_entries();
io_wq_error:
	destroy_workqueue(xsvnic_io_wq);
proc_error:
	destroy_workqueue(xsvnic_wq);
	return ret;
}

static void __exit xsvnic_exit(void)
{
	struct xsvnic *xsvnicp;
	unsigned long flags;

	DRV_FUNCTION("%s\n", __func__);
	xsvnic_xsmp_exit();
	mutex_lock(&xsvnic_mutex);
	list_for_each_entry(xsvnicp, &xsvnic_list, xsvnic_list) {
		spin_lock_irqsave(&xsvnicp->lock, flags);
		set_bit(XSVNIC_DELETING, &xsvnicp->state);
		set_bit(XSVNIC_SHUTDOWN, &xsvnicp->state);
		spin_unlock_irqrestore(&xsvnicp->lock, flags);
	}
	while (!list_empty(&xsvnic_list)) {
		mutex_unlock(&xsvnic_mutex);
		msleep(100);
		mutex_lock(&xsvnic_mutex);
	}
	mutex_unlock(&xsvnic_mutex);
	flush_workqueue(xsvnic_wq);
	destroy_workqueue(xsvnic_wq);
	flush_workqueue(xsvnic_io_wq);
	destroy_workqueue(xsvnic_io_wq);
	xsvnic_remove_procfs_root_entries();
}

int xsvnic_iscsi_present(void)
{
	int pres = 0;
	struct xsvnic *xsvnicp;

	mutex_lock(&xsvnic_mutex);
	list_for_each_entry(xsvnicp, &xsvnic_list, xsvnic_list) {
		if (xsvnicp->iscsi_boot_info.initiator_iqn[0] != '\0')
			pres = 1;
	}
	mutex_unlock(&xsvnic_mutex);
	return pres;
}
EXPORT_SYMBOL(xsvnic_iscsi_present);

int xsvnic_get_all_names(char **names, int max)
{
	struct xsvnic *xsvnicp;
	int count = 0;

	mutex_lock(&xsvnic_mutex);
	list_for_each_entry(xsvnicp, &xsvnic_list, xsvnic_list) {
		if (count < max)
			names[count++] =
			    kstrdup(xsvnicp->vnic_name, GFP_KERNEL);
	}
	mutex_unlock(&xsvnic_mutex);
	return count;
}
EXPORT_SYMBOL(xsvnic_get_all_names);

module_init(xsvnic_init);
module_exit(xsvnic_exit);
