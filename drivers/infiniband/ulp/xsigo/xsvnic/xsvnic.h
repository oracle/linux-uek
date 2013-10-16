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

#ifndef __XSVNIC_H__
#define __XSVNIC_H__

#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/skbuff.h>
#include <linux/inet_lro.h>
#include <linux/dma-mapping.h>
#include <linux/workqueue.h>

#include "xscore.h"
#include "xsmp_common.h"
#include "xsvnic_xsmp_msgs.h"
#include "xsmp_session.h"

#ifndef	XSIGO_LOCAL_VERSION
#define XSVNIC_DRIVER_VERSION "0.31"
#else
#define XSVNIC_DRIVER_VERSION XSIGO_LOCAL_VERSION
#endif

#define XSVNIC_MIN_PACKET_LEN	60
#define XSVNIC_MAX_BUF_SIZE	1024
#define	XSVNIC_MACLIST_MAX	128
#define TCA_SERVICE_ID		0x1001ULL
#define	XSVNIC_VLANLIST_MAX	500
#define XS_RXBAT_HDRLEN		4
#define RXBAT_FORMAT_OFFSET(a)  ((a >> 30) & 0x3)
#define RXBAT_FINAL_BIT(a)	((a >> 29) & 0x1)
#define RXBAT_FRAG_LEN(a)	(a & 0x3fff)

#define  GET_MAX(val, len)						\
	do {								\
		if ((val == 0) || ((len > val) && (len != 0)))		\
			val = len;					\
	} while (0)

#define  GET_MIN(val, len)						\
	do {								\
		if ((val == 0) || ((len < val) && (len != 0)))		\
			val = len;					\
	} while (0)

#define CALC_MAX_PKT_RX(p, len)						\
	do {								\
		GET_MAX(p->counters[XSVNIC_RX_MAX_PKT], len);		\
		GET_MIN(p->counters[XSVNIC_RX_MIN_PKT], len);		\
	} while (0)

#define CALC_MAX_PKT_TX(p, len)						\
	do {								\
		GET_MAX(p->counters[XSVNIC_TX_MAX_PKT], len);		\
		GET_MIN(p->counters[XSVNIC_TX_MIN_PKT], len);		\
	} while (0)

#define CALC_MAX_MIN_TXTIME(p, time)					\
	do {								\
		unsigned long tot_time = (jiffies - time);		\
		GET_MAX(p->counters[XSVNIC_TX_MAX_TIME], tot_time);	\
		GET_MIN(p->counters[XSVNIC_TX_MIN_TIME], tot_time);	\
	} while (0)

#define XSIGO_DUMP_PKT(a, b, c)						\
	do {								\
		if (xsvnic_debug & DEBUG_DUMP_PKTS)			\
			DumpPkt(a, b, c);				\
	} while (0)

#define	XSIGO_DEVICE_PREFIX	""

#define XSVNIC_IO_QP_TYPE_CONTROL	0
#define XSVNIC_IO_QP_TYPE_DATA		1

enum {
	XSVNIC_CONN_INIT,
	XSVNIC_CONN_CONNECTING,
	XSVNIC_CONN_CONNECTED,
	XSVNIC_CONN_DISCONNECTING,
	XSVNIC_CONN_DISCONNECTED,
	XSVNIC_CONN_ERROR
};

struct xsvnic_conn {
	u8 type;
	int state;
	struct xscore_conn_ctx ctx;
};

/*
 * Private data format passed in a connection request
 */

struct xt_cm_private_data {
	u64 vid;
	u16 qp_type;
	u16 max_ctrl_msg_size;
	u32 data_qp_type;
#define	XSVNIC_TSO_BIT		(1 << 1)
#define	XSVNIC_RXBAT_BIT	(1 << 2)
#define	XSVNIC_RXBAT_TIMER_BIT	(1 << 3)
} __packed;

struct xsvnic_control_msg {
	u8 type;
	u8 _reserved;
	u16 length;
	u32 data;
} __packed;

/*lro specifics*/
enum {
	XSVNIC_MAX_LRO_DESCRIPTORS = 8,
	XSVNIC_LRO_MAX_AGGR = 64,
};

/*
 * Types for the control messages, events, and statistics
 * sent using the 'struct xsvnic_control_msg' above
 */
enum xsvnic_control_msg_type {
	XSVNIC_START_TX = 16,
	XSVNIC_STOP_TX,
	XSVNIC_START_RX,
	XSVNIC_STOP_RX,
	XSVNIC_RX_COALESCE_NUM_PACKETS,
	XSVNIC_RX_COALESCE_MSECS,
	XSVNIC_LINK_UP,
	XSVNIC_LINK_DOWN,
	XSVNIC_ASSIGN_IP,
	XSVNIC_ASSIGN_VLAN,
	XSVNIC_UNASSIGN_VLAN,
	XSVNIC_STATS_REQUEST,
	XSVNIC_STATS_RESPONSE,
	XSVNIC_MAC_ADDRESS_REPORT,
	XSVNIC_MULTICAST_LIST_SEND,
	XSVNIC_START_RX_RESPONSE,
	XSVNIC_VPORT_STATUS_UPDATE,
	XSVNIC_MULTICAST_LIST_RESPONSE,
	XSVNIC_HEART_BEAT,
	MAX_XSVNIC_CTL_MSG_TYPE
};

struct xsvnic_start_rx_resp_msg {
	u8 port_speed;
};

struct xsvnic_link_up_msg {
	u8 port_speed;
};

enum xnic_bw {
	XNIC_BW_0,		/* link down state */
	XNIC_BW_100MbPS,
	XNIC_BW_10MbPS,
	XNIC_BW_200MbPS,
	XNIC_BW_500MbPS,
	XNIC_BW_800MbPS,
	XNIC_BW_1GbPS,
	XNIC_BW_2GbPS,
	XNIC_BW_3GbPS,
	XNIC_BW_4GbPS,
	XNIC_BW_5GbPS,
	XNIC_BW_6GbPS,
	XNIC_BW_7GbPS,
	XNIC_BW_8GbPS,
	XNIC_BW_9GbPS,
	XNIC_BW_10GbPS,
	XNIC_BW_UNKNOWN,
};

struct vlan_entry {
	struct list_head vlan_list;
	unsigned short vlan_id;
};

enum {
	XSVNIC_SYNC_END_DEL_COUNTER,
	XSVNIC_VNIC_INSTALL_COUNTER,
	XSVNIC_VNIC_DEL_COUNTER,
	XSVNIC_VNIC_DEL_NOVID_COUNTER,
	XSVNIC_VNIC_UPDATE_COUNTER,
	XSVNIC_VNIC_SYNC_BEGIN_COUNTER,
	XSVNIC_VNIC_SYNC_END_COUNTER,
	XSVNIC_VNIC_OPER_REQ_COUNTER,
	XSVNIC_VNIC_UNSUP_XSMP_COUNTER,
	XSVNIC_ISCSI_INFO_COUNTER,
	XSVNIC_DEVICE_REMOVAL_COUNTER,
	XSVNIC_MAX_GLOB_COUNTERS
};

enum {
	XSVNIC_CTRL_HBEAT_COUNTER,
	XSVNIC_DATA_HBEAT_COUNTER,
	XSVNIC_HBEAT_ERR_COUNTER,
	XSVNIC_NAPI_POLL_COUNTER,
	XSVNIC_SHORT_PKT_COUNTER,
	XSVNIC_TX_COUNTER,
	XSVNIC_TX_SKB_TSO_COUNTER,
	XSVNIC_TX_SKB_NOHEAD_COUNTER,
	XSVNIC_TX_SKB_FREE_COUNTER,
	XSVNIC_TX_SKB_FREE_COUNTER_REAP,
	XSVNIC_TX_EXPAND_HEAD_COUNTER,
	XSVNIC_TX_EXPAND_HEAD_ECNTR,
	XSVNIC_TX_VLAN_COUNTER,
	XSVNIC_TX_ERROR_COUNTER,
	XSVNIC_TX_WRB_EXHAUST,
	XSVNIC_TX_DROP_OPER_DOWN_COUNT,
	XSVNIC_TX_SKB_ALLOC_ERROR_COUNTER,
	XSVNIC_TX_EXPANDSKB_ERROR,
	XSVNIC_TX_RING_FULL_COUNTER,
	XSVNIC_RX_SKB_COUNTER,
	XSVNIC_RX_SKB_ALLOC_COUNTER,
	XSVNIC_RX_SENDTO_VLANGRP,
	XSVNIC_RXBAT_PKTS,
	XSVNIC_RX_SKB_FREE_COUNTER,
	XSVNIC_RX_MAXBATED_COUNTER,
	XSVNIC_RXBAT_BELOW_5SEGS,
	XSVNIC_RXBAT_BTW_5_10SEGS,
	XSVNIC_RXBAT_BTW_10_20SEGS,
	XSVNIC_RXBAT_ABOVE_20SEGS,
	XSVNIC_8KBAT_PKTS,
	XSVNIC_RX_SKB_OFFLOAD_COUNTER,
	XSVNIC_RX_SKB_OFFLOAD_FRAG_COUNTER,
	XSVNIC_RX_SKB_OFFLOAD_NONIPV4_COUNTER,
	XSVNIC_RX_ERROR_COUNTER,
	XSVNIC_RX_QUOTA_EXCEEDED_COUNTER,
	XSVNIC_RX_NOBUF_COUNTER,
	XSVNIC_RX_MAX_PKT,
	XSVNIC_RX_MIN_PKT,
	XSVNIC_RX_LRO_AGGR_PKTS,
	XSVNIC_RX_LRO_FLUSHED_PKT,
	XSVNIC_RX_LRO_AVG_AGGR_PKTS,
	XSVNIC_RX_LRO_NO_DESCRIPTORS,
	XSVNIC_TX_MAX_PKT,
	XSVNIC_TX_MIN_PKT,
	XSVNIC_TX_MAX_TIME,
	XSVNIC_TX_MIN_TIME,
	XSVNIC_NAPI_SCHED_COUNTER,
	XSVNIC_NAPI_NOTSCHED_COUNTER,
	XSVNIC_PORT_LINK_UP_COUNTER,
	XSVNIC_PORT_LINK_DOWN_COUNTER,
	XSVNIC_DUP_PORT_LINK_UP_COUNTER,
	XSVNIC_DUP_PORT_LINK_DOWN_COUNTER,
	XSVNIC_START_RX_COUNTER,
	XSVNIC_STOP_RX_COUNTER,
	XSVNIC_START_RX_RESP_COUNTER,
	XSVNIC_BAD_RX_RESP_COUNTER,
	XSVNIC_OPEN_COUNTER,
	XSVNIC_STOP_COUNTER,
	XSVNIC_GETSTATS_COUNTER,
	XSVNIC_SET_MCAST_COUNTER,
	XSVNIC_MCAST_LIST_RESP_COUNTER,
	XSVNIC_MCAST_LIST_NORESP_COUNTER,
	XSVNIC_VLAN_RX_ADD_COUNTER,
	XSVNIC_VLAN_RX_DEL_COUNTER,
	XSVNIC_IOCTL_COUNTER,
	XSVNIC_MAC_ADDR_CHNG,
	XSVNIC_WDOG_TIMEOUT_COUNTER,
	XSVNIC_OPER_REQ_COUNTER,
	XSVNIC_XT_DOWN_COUNTER,
	XSVNIC_XT_UPDATE_COUNTER,
	XSVNIC_XT_LID_CHANGE_COUNTER,
	XSVNIC_ADMIN_UP_COUNTER,
	XSVNIC_ADMIN_DOWN_COUNTER,
	XSVNIC_OPER_UP_STATE_COUNTER,
	XSVNIC_QP_ERROR_COUNTER,
	XSVNIC_IB_RECOVERY_COUNTER,
	XSVNIC_IB_RECOVERED_COUNTER,
	XSVNIC_IBLINK_DOWN_COUNTER,
	XSVNIC_IBLINK_UP_COUNTER,
	XSVNIC_CTRL_CONN_OK_COUNTER,
	XSVNIC_CTRL_RDISC_COUNTER,
	XSVNIC_CTRL_ERR_COUNTER,
	XSVNIC_CTRL_RECV_ERR_COUNTER,
	XSVNIC_DATA_CONN_OK_COUNTER,
	XSVNIC_DATA_RDISC_COUNTER,
	XSVNIC_DATA_ERR_COUNTER,
	XSVNIC_SENT_OPER_UP_COUNTER,
	XSVNIC_SENT_OPER_DOWN_COUNTER,
	XSVNIC_SENT_OPER_STATE_FAILURE_COUNTER,
	XSVNIC_SENT_OPER_STATE_SUCCESS_COUNTER,
	XSVNIC_RX_DROP_STANDBY_COUNTER,
	XSVNIC_TX_DROP_STANDBY_COUNTER,
	XSVNIC_MAX_COUNTERS
};

struct ether_addr {
	unsigned char addr[ETH_ALEN];
};

struct xsvnic_lro {
	struct net_lro_mgr lro_mgr;
	struct net_lro_desc lro_desc[XSVNIC_MAX_LRO_DESCRIPTORS];
};

struct xsvnic {
	spinlock_t lock;
	struct mutex mutex;
	atomic_t ref_cnt;
	struct completion done;
	struct delayed_work sm_work;
	unsigned long state;
#define	XSVNIC_SYNC_DIRTY		1
#define	XSVNIC_OS_ADMIN_UP		2
#define	XSVNIC_CHASSIS_ADMIN_UP		3
#define	XSVNIC_DELETING			4
#define	XSVNIC_SEND_ADMIN_STATE		5
#define	XSVNIC_PORT_LINK_UP		6
#define	XSVNIC_START_RX_SENT		7
#define	XSVNIC_START_RESP_RCVD		8
#define	XSVNIC_OPER_UP			9
#define	XSVNIC_STOP_RX_SENT		10
#define	XSVNIC_XT_DOWN			11
#define	XSVNIC_XT_STATE_CHANGE		12
#define	XSVNIC_SHUTDOWN			13
#define	XSVNIC_MCAST_LIST_SENT		14
#define	XSVNIC_RING_SIZE_CHANGE		15
#define	XSVNIC_RX_NOBUF			16
#define	XSVNIC_INTR_ENABLED		17
#define	XSVNIC_TRIGGER_NAPI_SCHED	18
#define	XSVNIC_IBLINK_DOWN		19
#define	XSVNIC_MCAST_LIST_PENDING	20
#define	XSVNIC_MCAST_LIST_TIMEOUT	21
#define	XSVNIC_CHASSIS_ADMIN_SHADOW_UP	22
#define	XSVNIC_OVER_QUOTA		23
#define	XSVNIC_TSO_CHANGE		24
#define	XSVNIC_RXBATCH_CHANGE		25
#define	XSVNIC_STATE_STDBY		26
	struct list_head xsvnic_list;
	struct list_head vlan_list;
	struct ether_addr *mc_addrs;
	int mc_count;
	struct net_device *netdev;
	struct net_device_stats stats;
	struct napi_struct napi;
	u8 lro_mode;
	struct xsvnic_lro lro;
#define	XSVNIC_RECLAIM_COUNT	4
	int reclaim_count;
	u8 send_hbeat_flag;
	int vlan_count;
	xsmp_cookie_t xsmp_hndl;
	u64 tca_guid;
	u16 tca_lid;
	struct xsvnic_conn ctrl_conn;
	struct xsvnic_conn data_conn;
	u32 counters[XSVNIC_MAX_COUNTERS];
	u64 resource_id;
	u32 bandwidth;
	u32 mtu;
	u64 mac;
	char vnic_name[XSVNIC_MAX_NAME_SIZE];
	u8 sl;
	u16 mp_flag;
	u8 mp_group[XSVNIC_MAX_NAME_SIZE];
	u32 install_flag;
	int port_speed;
	struct xsmp_session_info xsmp_info;
	struct xsvnic_iscsi_info iscsi_boot_info;
	u8 ha_state;
	int rx_ring_size;
	int tx_ring_size;
	int *budget;
	unsigned long jiffies;
	int sm_delay;
	u8 iff_promisc;
	u16 counters_cleared;
	int page_order;
	int is_tso;
	int is_rxbatching;
	int is_rxbat_operational;
	void *pci;
	struct vlan_group *vlgrp;
	struct proc_dir_entry *vnic_dir;
	int ix;
};

struct xsvnic_work {
	struct work_struct work;
	xsmp_cookie_t xsmp_hndl;
	struct xsvnic *xsvnicp;
	u8 *msg;
	int len;
	int status;
};

extern int xsvnic_debug;
extern unsigned long xsvnic_wait_time;
extern struct mutex xsvnic_mutex;
extern struct list_head xsvnic_list;
extern u32 xsvnic_counters[];
extern int xsvnic_vlanaccel;

extern void xsvnic_remove_procfs_root_entries(void);
extern int xsvnic_create_procfs_root_entries(void);
extern int xsvnic_add_proc_entry(struct xsvnic *vp);
extern void xsvnic_remove_proc_entry(struct xsvnic *vp);
extern int xsvnic_change_rxbatch(struct xsvnic *xsvnicp, int flag);

int check_rxbatch_possible(struct xsvnic *xsvnicp, int flag);
void xsvnic_count_segs(struct xsvnic *xsvnicp, char nr_segs, int pkt_len);
int xsvnic_align_addr(char **start);
void xsvnic_send_skb(struct xsvnic *xsvnicp, struct sk_buff *skb,
			int curr_pkt_len, char chksum_offload);

#define MODULE_NAME "XSVNIC"

enum {
	DEBUG_DRV_INFO = 0x00000001,
	DEBUG_DRV_FUNCTION = 0x00000002,
	DEBUG_XSMP_INFO = 0x00000004,
	DEBUG_XSMP_FUNCTION = 0x00000008,
	DEBUG_IOCTRL_INFO = 0x00000010,
	DEBUG_IOCTRL_FUNCTION = 0x00000020,
	DEBUG_RXBAT_FUNCTION = 0x00000040,
	DEBUG_DUMP_PKTS = 0x00000080,
};

static inline void DumpPkt(unsigned char *pkt, unsigned short len, char *name)
{
	int i = 0;
	unsigned char *p = (unsigned char *)pkt;
	char line[64] = { 0 };
	char *cp = line;
	char filter[] = "0123456789abcdef";
	int printed_line = 0;

	printk(KERN_INFO "%s DumpPacket of %d\n", name, len);

	for (i = 0; i < (len - 1); i++) {
		if ((i != 0) && (i % 8 == 0)) {
			printk(KERN_INFO "%s\n", line);
			memset(line, 0, sizeof(line));
			cp = line;
			printed_line = 1;
		} else {
			printed_line = 0;
		}

		if (*p > 0x0f)
			*cp++ = filter[*p >> 4];
		else
			*cp++ = filter[0];

		*cp++ = filter[*p++ & 0xf];
		*cp++ = ':';
		if (((len - i) == 1) && !printed_line) {
			printk(KERN_INFO "%s\n", line);
			memset(line, 0, sizeof(line));
			cp = line;
		}
	}
	*--cp = 0;
}

#define PRINT(level, x, fmt, arg...)				\
	printk(level "%s: " fmt, MODULE_NAME, ##arg)

#define PRINT_CONDITIONAL(level, x, condition, fmt, arg...)	\
	do {							\
		if (condition)					\
			printk(level "%s: %s: "fmt,		\
				MODULE_NAME, x, ##arg);		\
	} while (0)

#define DRV_PRINT(fmt, arg...)					\
	PRINT(KERN_INFO, "DRV", fmt, ##arg)
#define DRV_ERROR(fmt, arg...)					\
	PRINT(KERN_ERR, "DRV", fmt, ##arg)

#define DRV_FUNCTION(fmt, arg...)				\
	PRINT_CONDITIONAL(KERN_INFO,				\
			"DRV",					\
			(xsvnic_debug & DEBUG_DRV_FUNCTION),	\
			fmt, ##arg)

#define DRV_INFO(fmt, arg...)					\
	PRINT_CONDITIONAL(KERN_INFO,				\
			"DRV",					\
			(xsvnic_debug & DEBUG_DRV_INFO),	\
			fmt, ##arg)

#define XSMP_PRINT(fmt, arg...)					\
	PRINT(KERN_INFO, "XSMP", fmt, ##arg)
#define XSMP_ERROR(fmt, arg...)					\
	PRINT(KERN_ERR, "XSMP", fmt, ##arg)

#define XSMP_FUNCTION(fmt, arg...)				\
	PRINT_CONDITIONAL(KERN_INFO,				\
			"XSMP",					\
			(xsvnic_debug & DEBUG_XSMP_FUNCTION),	\
			fmt, ##arg)

#define XSMP_INFO(fmt, arg...)					\
	PRINT_CONDITIONAL(KERN_INFO,				\
			"XSMP",					\
			(xsvnic_debug & DEBUG_XSMP_INFO),	\
			fmt, ##arg)
#define IOCTRL_PRINT(fmt, arg...)				\
	PRINT(KERN_INFO, "IOCTRL", fmt, ##arg)
#define IOCTRL_ERROR(fmt, arg...)				\
	PRINT(KERN_ERR, "IOCTRL", fmt, ##arg)

#define IOCTRL_FUNCTION(fmt, arg...)				\
	PRINT_CONDITIONAL(KERN_INFO,				\
			"IOCTRL",				\
			(xsvnic_debug & DEBUG_IOCTRL_FUNCTION),	\
			fmt, ##arg)

#define IOCTRL_INFO(fmt, arg...)				\
	PRINT_CONDITIONAL(KERN_INFO,				\
			"IOCTRL",				\
			(xsvnic_debug & DEBUG_IOCTRL_INFO),	\
			fmt, ##arg)
#define IORXBAT_FUNC(fmt, arg...)				\
	PRINT_CONDITIONAL(KERN_INFO,				\
			"RXBAT",				\
			(xsvnic_debug & DEBUG_RXBAT_FUNCTION),	\
			fmt, ##arg)

#if !defined(NETDEV_HW_ADDR_T_MULTICAST)

static inline void netdev_mc_list_copy(struct xsvnic *xsvnicp)
{
	struct dev_mc_list *ha;
	struct net_device *netdev = xsvnicp->netdev;
	struct ether_addr *eaddr = xsvnicp->mc_addrs;

	netdev_for_each_mc_addr(ha, netdev) {
		memcpy(eaddr->addr, ha->dmi_addr, ETH_ALEN);
		eaddr++;
	}
}

#else

static inline void netdev_mc_list_copy(struct xsvnic *xsvnicp)
{
	struct netdev_hw_addr *ha;
	struct net_device *netdev = xsvnicp->netdev;
	struct ether_addr *eaddr = xsvnicp->mc_addrs;

	netdev_for_each_mc_addr(ha, netdev) {
		memcpy(eaddr->addr, ha->addr, ETH_ALEN);
		eaddr++;
	}
}

#endif

struct xs_vlan_header {
	u32 tso_info;
} __packed;

struct xs_tso_header {
	u32 tso_info;
} __packed;

struct xs_tsovlan_header {
	u32 tso_info;
	u32 vlan_info;
} __packed;

#endif /* __XSVNIC_H__ */
