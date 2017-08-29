/*
 * Copyright (c) 2011-2012 Xsigo Systems. All rights reserved
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
 */

#ifndef _XVE_H
#define _XVE_H

#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/icmpv6.h>
#include <linux/vmalloc.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/workqueue.h>
#include <linux/kref.h>
#include <linux/if_vlan.h>
#include <linux/if_infiniband.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/if_arp.h>
#include <linux/inet_lro.h>
#include <linux/kernel.h>
#include <linux/ethtool.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/ethtool.h>
#include <linux/netdevice.h>
#include <linux/err.h>
#include <linux/seq_file.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/device.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/mii.h>

#include <net/neighbour.h>
#include <net/dst.h>

#include <linux/atomic.h>
#include <asm/unaligned.h>

#include <rdma/ib_cm.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_pack.h>
#include <rdma/ib_sa.h>
#include <rdma/ib_cache.h>
#include <rdma/sif_verbs.h>

#include "xscore.h"
#include "hash.h"
#include "xsmp_common.h"
#include "xsmp_session.h"
#include "xve_xsmp_msgs.h"

#ifndef XSIGO_LOCAL_VERSION
#define XVE_DRIVER_VERSION "0.31"
#else
#define XVE_DRIVER_VERSION "0.31" XSIGO_LOCAL_VERSION
#endif

#ifndef NETIF_F_LRO
#define NETIF_F_LRO        NETIF_F_SW_LRO
#endif

#ifndef bool
#define bool int
#define true 1
#define false 0
#endif

/* macros for ipv6 support */

/* 86 bytes */
#define XVE_IPV6_MIN_PACK_LEN   86
/* as per the protocol */
#define IPV6_HDR_LEN            40
/* 128 bits IP address length for ipv6 */
#define IPV6_ADDR_LEN           16
/* next header (icmp-ndp) in ipv6 header */
#define NEXTHDR_ICMP            58
/* Neighbor solicitation packet type */
#define ICMP_NDP_TYPE           135
/* payload length in ipv6 (icmp header + optional header 24 + 8 ) */
#define PAYLOAD_LEN             32
/* as per the protocol */
#define ICMP_CODE               0
/* length of ICMP-NDP header */
#define ICMP_NDP_HDR_LEN        24
/* source link layer address type */
#define ICMP_OPTION_TYPE        1
/* 8 bytes length of ICMP option header */
#define ICMP_OPTION_LEN         1
/* prefix for destination multicast address */
#define PREFIX_MULTI_ADDR	0x33
/* ethernet header length */
#define ETH_HDR_LEN		14
#define	XVE_EOIB_MAGIC	0x8919
#define	ETH_P_XVE_CTRL	0x8919
#define	XVE_EOIB_LEN	4

#define XVE_VNET_MODE_RC 1
#define XVE_VNET_MODE_UD 2

#define	XVE_MAX_RX_QUEUES	16
#define	XVE_MAX_TX_QUEUES	16

/* constants */
enum xve_flush_level {
	XVE_FLUSH_LIGHT,
	XVE_FLUSH_NORMAL,
	XVE_FLUSH_HEAVY
};

enum {
	XVE_UD_HEAD_SIZE = IB_GRH_BYTES + VLAN_ETH_HLEN + XVE_EOIB_LEN,
	XVE_UD_RX_OVN_SG = 2,	/* max buffer needed for 4K mtu */
	XVE_UD_RX_EDR_SG = 4,	/* max buffer needed for 10K mtu */
	XVE_CM_MTU = 0x10000 - 0x20,	/* padding to align header to 16 */
	XVE_CM_BUF_SIZE = XVE_CM_MTU + VLAN_ETH_HLEN,
	XVE_CM_HEAD_SIZE = XVE_CM_BUF_SIZE % PAGE_SIZE,
	XVE_CM_RX_SG = ALIGN(XVE_CM_BUF_SIZE, PAGE_SIZE) / PAGE_SIZE,
	XVE_RX_RING_SIZE = 2048,
	XVE_TX_RING_SIZE = 2048,
	XVE_MAX_QUEUE_SIZE = 8192,
	XVE_MIN_QUEUE_SIZE = 2,
	XVE_CM_MAX_CONN_QP = 4096,
	XVE_NUM_WC = 4,
	XVE_MAX_PATH_REC_QUEUE = 3,
	XVE_MAX_MCAST_QUEUE = 3,
	XVE_MCAST_FLAG_FOUND = 0,	/* used in set_multicast_list */
	XVE_MCAST_FLAG_SENDONLY = 1,
	XVE_MCAST_FLAG_BUSY = 2,	/* joining or already joined */
	XVE_MCAST_FLAG_ATTACHED = 3,
	XVE_MAX_LRO_DESCRIPTORS = 8,
	XVE_LRO_MAX_AGGR = 64,
	MAX_SEND_CQE = 32,
	SENDQ_LOW_WMARK = 32,
	XVE_CM_COPYBREAK = 256,
};

enum {
	XVE_FLAG_OPER_UP = 0,
	XVE_FLAG_INITIALIZED = 1,
	XVE_FLAG_ADMIN_UP = 2,
	XVE_PKEY_ASSIGNED = 3,
	XVE_PKEY_STOP = 4,
	XVE_IB_DEV_OPEN = 5,
	XVE_MCAST_RUN = 6,
	XVE_STOP_REAPER = 7,
	XVE_FLAG_ADMIN_CM = 9,
	XVE_FLAG_UMCAST = 10,
	XVE_FLAG_CSUM = 11,
	XVE_MCAST_RUN_GC = 12,
	XVE_FLAG_ADVERT_JOIN = 13,
	XVE_FLAG_IB_EVENT = 14,
	XVE_FLAG_DONT_DETACH_MCAST = 15,
	XVE_MAX_BACKOFF_SECONDS = 16,
	XVE_DRAIN_IN_PROGRESS = 17,
};

enum xve_advert_types {
	XVE_ADVERT_JOIN = 1,
	XVE_ADVERT_RESP = 2,
	XVE_ADVERT_UPD = 3,
};

enum {
	XVE_SYNC_END_DEL_COUNTER,
	XVE_VNIC_INSTALL_COUNTER,
	XVE_VNIC_DEL_COUNTER,
	XVE_VNIC_DEL_NOVID_COUNTER,
	XVE_VNIC_UPDATE_COUNTER,
	XVE_VNIC_SYNC_BEGIN_COUNTER,
	XVE_VNIC_SYNC_END_COUNTER,
	XVE_VNIC_OPER_REQ_COUNTER,
	XVE_VNIC_UNSUP_XSMP_COUNTER,
	XVE_ISCSI_INFO_COUNTER,
	XVE_DEVICE_REMOVAL_COUNTER,
	XVE_VNIC_STATS_COUNTER,
	XVE_NUM_PAGES_ALLOCED,
	XVE_MAX_GLOB_COUNTERS
};
enum {
	XVE_DATA_HBEAT_COUNTER,
	XVE_HBEAT_ERR_COUNTER,
	XVE_STATE_MACHINE,
	XVE_STATE_MACHINE_UP,
	XVE_STATE_MACHINE_DOWN,
	XVE_STATE_MACHINE_IBCLEAR,
	XVE_NAPI_POLL_COUNTER,
	XVE_NAPI_DROP_COUNTER,
	XVE_SHORT_PKT_COUNTER,
	XVE_TX_COUNTER,
	XVE_TX_SKB_FREE_COUNTER,
	XVE_TX_VLAN_COUNTER,
	XVE_TX_ERROR_COUNTER,
	XVE_TX_WRB_EXHAUST,
	XVE_TX_DROP_OPER_DOWN_COUNT,
	XVE_TX_SKB_ALLOC_ERROR_COUNTER,
	XVE_TX_RING_FULL_COUNTER,
	XVE_TX_WMARK_REACH_COUNTER,
	XVE_TX_WAKE_UP_COUNTER,
	XVE_TX_QUEUE_STOP_COUNTER,
	XVE_TX_LIN_SKB_COUNTER,
	XVE_RX_SKB_COUNTER,
	XVE_RX_SKB_ALLOC_COUNTER,
	XVE_RX_SMALLSKB_ALLOC_COUNTER,
	XVE_RX_SKB_FREE_COUNTER,
	XVE_RX_SKB_OFFLOAD_COUNTER,
	XVE_RX_SKB_OFFLOAD_FRAG_COUNTER,
	XVE_RX_SKB_OFFLOAD_NONIPV4_COUNTER,
	XVE_RX_ERROR_COUNTER,
	XVE_RX_QUOTA_EXCEEDED_COUNTER,
	XVE_RX_NOBUF_COUNTER,
	XVE_NAPI_SCHED_COUNTER,
	XVE_NAPI_NOTSCHED_COUNTER,
	XVE_NAPI_RESCHEDULE_COUNTER,
	XVE_OPEN_COUNTER,
	XVE_STOP_COUNTER,
	XVE_GETSTATS_COUNTER,
	XVE_SET_MCAST_COUNTER,
	XVE_VLAN_RX_ADD_COUNTER,
	XVE_VLAN_RX_DEL_COUNTER,
	XVE_IOCTL_COUNTER,
	XVE_WDOG_TIMEOUT_COUNTER,
	XVE_OPER_REQ_COUNTER,
	XVE_ADMIN_UP_COUNTER,
	XVE_ADMIN_DOWN_COUNTER,
	XVE_OPER_UP_STATE_COUNTER,
	XVE_QP_ERROR_COUNTER,
	XVE_IB_RECOVERY_COUNTER,
	XVE_IB_RECOVERED_COUNTER,
	XVE_IBLINK_DOWN_COUNTER,
	XVE_IBLINK_UP_COUNTER,
	XVE_IB_PORT_NOT_ACTIVE,
	XVE_SENT_OPER_UP_COUNTER,
	XVE_SENT_OPER_DOWN_COUNTER,
	XVE_SENT_OPER_STATE_FAILURE_COUNTER,
	XVE_SENT_OPER_STATE_SUCCESS_COUNTER,
	XVE_DROP_STANDBY_COUNTER,

	XVE_MAC_LEARN_COUNTER,
	XVE_MAC_AGED_COUNTER,
	XVE_MAC_AGED_CHECK,
	XVE_MAC_AGED_NOMATCHES,
	XVE_MAC_STILL_INUSE,
	XVE_MAC_MOVED_COUNTER,

	XVE_MCAST_NOTREADY,
	XVE_MCAST_JOIN_TASK,
	XVE_MCAST_LEAVE_TASK,
	XVE_MCAST_CARRIER_TASK,
	XVE_MCAST_ATTACH,
	XVE_MCAST_DETACH,

	XVE_TX_UD_COUNTER,
	XVE_TX_RC_COUNTER,
	XVE_RC_RXCOMPL_COUNTER,
	XVE_RC_TXCOMPL_COUNTER,
	XVE_RC_RXCOMPL_ERR_COUNTER,
	XVE_RC_TXCOMPL_ERR_COUNTER,
	XVE_TX_MCAST_PKT,
	XVE_TX_BCAST_PKT,
	XVE_TX_MCAST_ARP_QUERY,
	XVE_TX_MCAST_NDP_QUERY,
	XVE_TX_MCAST_ARP_VLAN_QUERY,
	XVE_TX_MCAST_NDP_VLAN_QUERY,
	XVE_TX_MCAST_FLOOD_UD,
	XVE_TX_MCAST_FLOOD_RC,
	XVE_TX_QUEUE_PKT,

	XVE_PATH_NOT_FOUND,
	XVE_PATH_NOT_SETUP,
	XVE_AH_NOT_FOUND,

	XVE_PATHREC_QUERY_COUNTER,
	XVE_PATHREC_RESP_COUNTER,
	XVE_PATHREC_RESP_ERR_COUNTER,
	XVE_PATHREC_GW_COUNTER,

	XVE_SM_CHANGE_COUNTER,
	XVE_CLIENT_REREGISTER_COUNTER,
	XVE_EVENT_PORT_ERR_COUNTER,
	XVE_EVENT_PORT_ACTIVE_COUNTER,
	XVE_EVENT_LID_CHANGE_COUNTER,
	XVE_EVENT_PKEY_CHANGE_COUNTER,
	XVE_INVALID_EVENT_COUNTER,

	XVE_GW_MCAST_TX,
	XVE_HBEAT_COUNTER,
	XVE_LINK_STATUS_COUNTER,
	XVE_RX_NOGRH,
	XVE_DUP_VID_COUNTER,

	XVE_MAX_COUNTERS
};

enum {
	/* Work queue Counters */
	XVE_WQ_START_PKEYPOLL,
	XVE_WQ_FINISH_PKEYPOLL,
	XVE_WQ_START_AHREAP,
	XVE_WQ_FINISH_AHREAP,
	XVE_WQ_START_FWT_AGING,
	XVE_WQ_FINISH_FWT_AGING,
	XVE_WQ_START_MCASTJOIN,
	XVE_WQ_FINISH_MCASTJOIN,
	XVE_WQ_START_MCASTLEAVE,
	XVE_WQ_FINISH_MCASTLEAVE,
	XVE_WQ_START_MCASTON,
	XVE_WQ_FINISH_MCASTON,
	XVE_WQ_START_MCASTRESTART,
	XVE_WQ_FINISH_MCASTRESTART,
	XVE_WQ_START_FLUSHLIGHT,
	XVE_WQ_FINISH_FLUSHLIGHT,
	XVE_WQ_START_FLUSHNORMAL,
	XVE_WQ_FINISH_FLUSHNORMAL,
	XVE_WQ_START_FLUSHHEAVY,
	XVE_WQ_FINISH_FLUSHHEAVY,
	XVE_WQ_START_CMSTALE,
	XVE_WQ_FINISH_CMSTALE,
	XVE_WQ_START_CMTXSTART,
	XVE_WQ_FINISH_CMTXSTART,
	XVE_WQ_START_CMTXREAP,
	XVE_WQ_FINISH_CMTXREAP,
	XVE_WQ_START_CMRXREAP,
	XVE_WQ_FINISH_CMRXREAP,
	XVE_WQ_DONT_SCHEDULE,
	XVE_WQ_INVALID,
	XVE_WQ_FAILED,

	XVE_MISC_MAX_COUNTERS
};

/* SPEEED CALCULATION */
enum {
	SPEED_SDR = 2500,
	SPEED_DDR = 5000,
	SPEED_QDR = 10000,
	SPEED_FDR10 = 10313,
	SPEED_FDR = 14063,
	SPEED_EDR = 25781
};

/*
 * Quoting 10.3.1 Queue Pair and EE Context States:
 *
 * Note, for QPs that are associated with an SRQ, the Consumer should take the
 * QP through the Error State before invoking a Destroy QP or a Modify QP to the
 * Reset State.  The Consumer may invoke the Destroy QP without first performing
 * a Modify QP to the Error State and waiting for the Affiliated Asynchronous
 * Last WQE Reached Event. However, if the Consumer does not wait for the
 * Affiliated Asynchronous Last WQE Reached Event, then WQE and Data Segment
 * leakage may occur. Therefore, it is good programming practice to tear down a
 * QP that is associated with an SRQ by using the following process:
 *
 * - Put the QP in the Error State
 * - Wait for the Affiliated Asynchronous Last WQE Reached Event;
 * - either:
 *       drain the CQ by invoking the Poll CQ verb and either wait for CQ
 *       to be empty or the number of Poll CQ operations has exceeded
 *       CQ capacity size;
 * - or
 *       post another WR that completes on the same CQ and wait for this
 *       WR to return as a WC;
 * - and then invoke a Destroy QP or Reset QP.
 *
 * We use the second option and wait for a completion on the
 * same CQ before destroying QPs attached to our SRQ.
 */

enum xve_cm_state {
	XVE_CM_RX_LIVE = 1,
	XVE_CM_RX_ERROR,	/* Ignored by stale task */
	XVE_CM_RX_FLUSH		/* Last WQE Reached event observed */
};

enum {
	DEBUG_DRV_INFO = 0x00000001,
	DEBUG_DRV_FUNCTION = 0x00000002,
	DEBUG_XSMP_INFO = 0x00000004,
	DEBUG_XSMP_FUNCTION = 0x00000008,
	DEBUG_IOCTRL_INFO = 0x00000010,
	DEBUG_IOCTRL_FUNCTION = 0x00000020,
	DEBUG_TEST_INFO = 0x00000040,
	DEBUG_DATA_INFO = 0x00000080,
	DEBUG_MCAST_INFO = 0x00000100,
	DEBUG_TABLE_INFO = 0x00000200,
	DEBUG_FLUSH_INFO = 0x00000400,
	DEBUG_DUMP_PKTS = 0x00000800,
	DEBUG_SEND_INFO = 0x00001000,
	DEBUG_CONTINUE_UNLOAD = 0x00002000,
	DEBUG_MISC_INFO = 0x00004000,
	DEBUG_IBDEV_INFO = 0x00008000,
	DEBUG_CM_INFO = 0x00010000,
	DEBUG_CTRL_INFO = 0x00020000,
	DEBUG_QP_INFO = 0x00040000,
	DEBUG_TX_INFO = 0x00080000,
	DEBUG_RX_INFO = 0x00100000,
	DEBUG_TXDATA_INFO = 0x00200000,
	DEBUG_INSTALL_INFO = 0x00400000,
	DEBUG_FWTABLE_INFO = 0x00800000
};

#define	XVE_OP_RECV   (1ul << 31)
#define XVE_FWT_HASH_LISTS  256
#define XVE_MACT_HASH_LISTS  32
#define XVE_ADVERT_PROTO 0x8915

#define	XVE_SYNC_DIRTY		1
#define	XVE_OS_ADMIN_UP		2
#define	XVE_CHASSIS_ADMIN_UP		3
#define	XVE_DELETING			4
#define	XVE_SEND_ADMIN_STATE		5
#define	XVE_PORT_LINK_UP		6
#define	XVE_OPER_REP_SENT		7
#define	XVE_START_RESP_RCVD		8
#define	XVE_OPER_UP			9
#define	XVE_STOP_RX_SENT		10
#define	XVE_XT_DOWN			11
#define	XVE_XT_STATE_CHANGE		12
#define	XVE_SHUTDOWN			13
#define	XVE_MCAST_LIST_SENT		14
#define	XVE_RING_SIZE_CHANGE		15
#define	XVE_RX_NOBUF			16
#define	XVE_INTR_ENABLED		17
#define	XVE_TRIGGER_NAPI_SCHED		18
#define	XVE_IBLINK_DOWN			19
#define	XVE_MCAST_LIST_PENDING		20
#define	XVE_MCAST_LIST_TIMEOUT		21
#define	XVE_CHASSIS_ADMIN_SHADOW_UP	22
#define	XVE_OVER_QUOTA			23
#define	XVE_TSO_CHANGE			24
#define	XVE_RXBATCH_CHANGE		25
#define	XVE_VNIC_READY_PENDING		26
#define	XVE_HBEAT_LOST			27
#define	XVE_GW_STATE_UP			28

#define MODULE_NAME "XVE"
#define ALIGN_TO_FF(a) (a & 0xff)
#define XVE_FWT_ENTRY_VALID 1
#define XVE_FWT_ENTRY_REFRESH 2
#define XVE_UD_MTU(ib_mtu)	(ib_mtu - (VLAN_ETH_HLEN + XVE_EOIB_LEN))
#define XVE_UD_BUF_SIZE(ib_mtu)	(ib_mtu + IB_GRH_BYTES + \
				(VLAN_ETH_HLEN + XVE_EOIB_LEN))
#define XVE_MIN_PACKET_LEN 64

enum xcm_type {
	XSMP_XCM_OVN,
	XSMP_XCM_NOUPLINK,
	XSMP_XCM_UPLINK
};

#define	xve_is_uplink(priv) ((priv)->vnic_type == XSMP_XCM_UPLINK)
#define	xve_is_ovn(priv) ((priv)->vnic_type == XSMP_XCM_OVN)
#define	xve_is_edr(priv) (!xve_is_ovn(priv))
#define xve_gw_linkup(priv) test_bit(XVE_GW_STATE_UP, &(priv)->state)
#define xve_ud_rx_sg(priv) (xve_is_edr(priv) ? XVE_UD_RX_EDR_SG : \
				XVE_UD_RX_OVN_SG)

/*Extern declarations */
extern int xve_debug_level;
extern int xve_cm_single_qp;
extern u32 xve_hash_salt;
extern int xve_sendq_size;
extern int xve_recvq_size;
extern int xve_max_send_cqe;
extern struct ib_sa_client xve_sa_client;
extern u32 xve_counters[];
extern struct workqueue_struct *xve_taskqueue;
extern struct workqueue_struct *xve_workqueue;
extern int xve_mc_sendonly_timeout;
extern int xve_wait_txcompl;

extern void xve_remove_procfs_root_entries(void);
extern int xve_create_procfs_root_entries(void);


extern struct mutex xve_mutex;
extern struct list_head xve_dev_list;

/* structs */
/* Used for all multicast joins (broadcast, IPv4 mcast and IPv6 mcast) */
struct xve_mcast {
	struct ib_sa_mcmember_rec mcmember;
	struct ib_sa_multicast *mc;
	struct xve_ah *ah;

	struct rb_node rb_node;
	struct list_head list;

	unsigned long created;
	unsigned long used;
	unsigned long backoff;
	unsigned long flags;
	unsigned char logcount;
	struct sk_buff_head pkt_queue;
	struct net_device *netdev;
};

struct xve_rx_buf {
	struct sk_buff *skb;
	u64 mapping[XVE_UD_RX_EDR_SG];
};

struct xve_tx_buf {
	struct sk_buff *skb;
	struct xve_ah *ah;
	u64 mapping[MAX_SKB_FRAGS + 1];
};

struct xve_cm_buf {
	struct sk_buff *skb;
	u64 mapping[XVE_CM_RX_SG];
};

struct ib_cm_id;

struct xve_cm_data {
	__be32 qpn;		/* High byte MUST be ignored on receive */
	__be32 mtu;
};

/* CM connection Estd Direction */
enum {
	XVE_CM_ESTD_RX = 1,
	XVE_CM_ESTD_TX
};

struct xve_cm_stats {
	unsigned long tx_jiffies;
	unsigned long rx_jiffies;
	unsigned long total_rx_bytes;
	unsigned long total_tx_bytes;
	u32 tx_rate;
	u32 rx_rate;
	u32 tx_bytes;
	u32 rx_bytes;
	u32 tx_compl_err;

};

/* Single QP structure */
struct xve_cm_ctx {
	char version[64];
	struct xve_path *path;
	struct ib_cm_id *id;
	struct ib_qp *qp;
	struct list_head list;
	struct net_device *netdev;
	struct xve_cm_buf *tx_ring;
	struct xve_cm_buf *rx_ring;
	struct xve_cm_stats stats;
	union ib_gid dgid;
	enum xve_cm_state state;
	unsigned long flags;
	unsigned long jiffies;
	u32 mtu;
	int recv_count;
	unsigned tx_head;
	unsigned tx_tail;
	u8 direction;
};

struct xve_cm_dev_priv {
	struct ib_srq *srq;
	struct xve_cm_buf *srq_ring;
	struct ib_cm_id *id;
	struct list_head passive_ids;	/* state: LIVE */
	struct list_head rx_error_list;	/* state: ERROR */
	struct list_head rx_flush_list;	/* state: FLUSH, drain not started */
	struct list_head rx_drain_list;	/* state: FLUSH, drain started */
	struct list_head rx_reap_list;	/* state: FLUSH, drain done */
	struct list_head start_list;
	struct list_head reap_list;
	struct ib_wc ibwc[XVE_NUM_WC];
	struct ib_sge rx_sge[XVE_CM_RX_SG];
	struct ib_recv_wr rx_wr;
	int nonsrq_conn_qp;
	int max_cm_mtu;
	int num_frags;
};

struct xve_ethtool_st {
	u16 coalesce_usecs;
	u16 max_coalesced_frames;
};

struct xve_lro {
	struct net_lro_mgr lro_mgr;
	struct net_lro_desc lro_desc[XVE_MAX_LRO_DESCRIPTORS];
};

struct xve_fwt_entry {
	struct list_head list;
	struct hlist_node hlist;
	struct xve_path *path;
	union ib_gid dgid;
	char smac_addr[ETH_ALEN];
	unsigned long state;
	atomic_t ref_cnt;
	atomic_t del_inprogress;
	unsigned long last_refresh;
	int hash_value;
	u32 dqpn;
	u16 vlan;
};

struct xve_fwt_s {
	struct hlist_head fwt[XVE_FWT_HASH_LISTS];
	spinlock_t lock;
	unsigned num;
};

#define XVE_VNIC_HBEAT	1
#define	XVE_VNIC_LINK_STATE 2

#define	XVE_HBEAT_LOSS_THRES	3
struct xve_keep_alive {
	uint32_t pvi_id;
	uint32_t type;
	uint64_t tca_hbeat_cnt;
	uint32_t uplink_status;
} __packed;

struct xve_gw_info {
	union ib_gid	t_gid;
	u32 t_ctrl_qp;
	u32 t_data_qp;
	u32 t_qkey;
	u16 t_pkey;
};

struct xve_eoib_hdr {
	union {
		struct { /* CX */
			__u8 encap_data;
			__u8 seg_off;
			__be16 seg_id;
		};
		struct { /* PSIF */
			__be16 magic;
			__be16 tss_mask_sz;
		};
	};
} __packed;


struct xve_rx_cm_info {
	struct ib_sge		rx_sge[XVE_CM_RX_SG];
	struct ib_recv_wr       rx_wr;
};


/*
 * Device private locking: network stack tx_lock protects members used
 * in TX fast path, lock protects everything else.  lock nests inside
 * of tx_lock (ie tx_lock must be acquired first if needed).
 */
struct xve_dev_priv {
	struct list_head list;
	spinlock_t lock;
	struct mutex mutex;
	atomic_t ref_cnt;

	struct ib_device *ca;
	struct ib_pd *pd;
	struct ib_mr *mr;
	struct ib_qp *qp;
	union ib_gid local_gid;
	union ib_gid bcast_mgid;
	__be16       bcast_mlid;
	u16 local_lid;
	u32 qkey;
	u32 port_qkey;
	u8 is_titan;

	/* Device attributes */
	struct ib_device_attr dev_attr;

	/* Netdev related attributes */
	struct net_device *netdev;
	struct net_device_stats stats;
	struct napi_struct napi;
	struct xve_ethtool_st ethtool;
	struct timer_list poll_timer;
	u8 lro_mode;
	struct xve_lro lro;
	unsigned long flags;
	unsigned long state;

	struct rb_root path_tree;
	struct list_head path_list;
	struct xve_mcast *broadcast;
	struct list_head multicast_list;
	struct rb_root multicast_tree;

	struct delayed_work sm_work;
	struct delayed_work stale_task;
	struct delayed_work mcast_leave_task;
	struct delayed_work mcast_join_task;
	int sm_delay;
	unsigned int send_hbeat_flag;
	unsigned long jiffies;
	struct xve_fwt_s xve_fwt;
	int aging_delay;
	void *pci;
	uint32_t hb_interval;
	uint64_t last_hbeat;

	struct xve_cm_dev_priv cm;
	unsigned int cm_supported;

	struct ib_port_attr port_attr;
	u8 port;
	u16 pkey;
	u16 pkey_index;
	int port_speed;
	int hca_caps;
	unsigned int admin_mtu;
	unsigned int mcast_mtu;
	unsigned int max_ib_mtu;
	char mode[64];
	/* TX and RX Ring attributes */
	int xve_recvq_size;
	int xve_sendq_size;
	int xve_rcq_size;
	int xve_scq_size;
	int xve_max_send_cqe;
	struct xve_rx_buf *rx_ring;
	struct xve_tx_buf *tx_ring;
	unsigned tx_head;
	unsigned tx_tail;
	unsigned tx_outstanding;
	struct ib_sge tx_sge[MAX_SKB_FRAGS + 1];
	struct ib_send_wr tx_wr;
	struct ib_wc send_wc[MAX_SEND_CQE];
	struct ib_recv_wr rx_wr;
	uint32_t max_send_sge;
	/* Allocate EDR SG for now */
	struct ib_sge rx_sge[XVE_UD_RX_EDR_SG];
	struct ib_wc ibwc[XVE_NUM_WC];
	struct ib_cq *recv_cq;
	struct ib_cq *send_cq;
	struct list_head dead_ahs;
	struct ib_event_handler event_handler;

	/* XSMP related attributes */
	xsmp_cookie_t xsmp_hndl;
	struct xsmp_session_info xsmp_info;
	u64 resource_id;
	u64 mac;
	u32 net_id;
	u32 install_flag;
	u16 mp_flag;
	u8 vnet_mode;
	u8 vnic_type;
	u8 is_eoib;
	u8 is_jumbo;
	char xve_name[XVE_MAX_NAME_SIZE];
	struct xve_gw_info gw;

	/* Proc related attributes */
	struct proc_dir_entry *nic_dir;
	unsigned long work_queue_failed;
	char proc_name[XVE_MAX_PROC_NAME_SIZE];
	u32 counters[XVE_MAX_COUNTERS];
	u32 misc_counters[XVE_MISC_MAX_COUNTERS];
	int sindex;
	int jindex;
	u16 counters_cleared;
	u8 next_page;
	int ix;
};

struct xve_ah {
	struct net_device *dev;
	struct ib_ah *ah;
	struct list_head list;
	struct kref ref;
	atomic_t refcnt;
};

struct ib_packed_grh {
	u8 ip_version;
	u8 traffic_class;
	u16 flow_label;
	u16 payload_length;
	u8 next_header;
	u8 hop_limit;
	union ib_gid source_gid;
	union ib_gid destination_gid;
};

struct xve_path {
	struct net_device *dev;
	struct xve_cm_ctx *cm_ctx_common;
	struct xve_cm_ctx *cm_ctx_tx;
	struct xve_cm_ctx *cm_ctx_rx;
	struct ib_sa_path_rec pathrec;
	struct xve_ah *ah;
	int query_id;
	struct ib_sa_query *query;
	struct completion done;
	struct list_head fwt_list;
	struct rb_node rb_node;
	struct list_head list;
	int valid;
	int index;
	struct sk_buff_head queue;
	struct sk_buff_head uplink_queue;
	atomic_t users;
};

struct xve_work {
	struct work_struct work;
	struct delayed_work dwork;
	xsmp_cookie_t xsmp_hndl;
	struct xve_dev_priv *priv;
	int len;
	int status;
	u8 *msg;
};

struct icmp6_ndp {
	unsigned char icmp6_type;
	unsigned char icmp6_code;
	unsigned short int icmp6_cksum;
	unsigned int icmp6_reserved;
	unsigned char icmp6_daddr[16];
	unsigned char icmp6_option_type;
	unsigned char icmp6_option_len;
	unsigned char icmp6_option_saddr[6];
};

#define INC_TX_DROP_STATS(priv, dev)            \
	do {                                    \
		++dev->stats.tx_dropped;	\
		++priv->stats.tx_dropped;	\
	} while (0)
#define INC_TX_ERROR_STATS(priv, dev)		\
	do {					\
		++priv->stats.tx_errors;	\
		++dev->stats.tx_errors;		\
	} while (0)
#define INC_TX_PKT_STATS(priv, dev)             \
	do {                                    \
		++priv->stats.tx_packets;	\
		++dev->stats.tx_packets;	\
	} while (0)
#define INC_TX_BYTE_STATS(priv, dev, len)	\
	do {                                    \
		priv->stats.tx_bytes += len;	\
		dev->stats.tx_bytes += len;	\
	} while (0)
#define INC_RX_DROP_STATS(priv, dev)            \
	do {                                    \
		++dev->stats.rx_dropped;	\
		++priv->stats.rx_dropped;	\
	} while (0)
#define INC_RX_ERROR_STATS(priv, dev)           \
	do {                                    \
		++priv->stats.rx_errors;	\
		++dev->stats.rx_errors;		\
	} while (0)
#define INC_RX_PKT_STATS(priv, dev)             \
	do {                                    \
		++priv->stats.rx_packets;	\
		++dev->stats.rx_packets;	\
	} while (0)

#define INC_RX_BYTE_STATS(priv, dev, len)			\
	do {							\
		priv->stats.rx_bytes += len;			\
		dev->stats.rx_bytes += len;			\
	} while (0)

#define PRINT(level, x, fmt, arg...)				\
	printk(level "%s: [PID%d]" fmt, MODULE_NAME, current->pid, ##arg)
#define XSMP_ERROR(fmt, arg...)					\
	PRINT(KERN_ERR, "XSMP", fmt, ##arg)
#define DRV_PRINT(fmt, arg...)                                  \
	PRINT(KERN_INFO, "DRV", fmt, ##arg)
#define xve_printk(level, priv, format, arg...)			\
	printk(level "%s: [PID%d]" format "\n",			\
		((struct xve_dev_priv *) priv)->netdev->name,	\
		current->pid,					\
		## arg)
#define xve_warn(priv, format, arg...)				\
	xve_printk(KERN_WARNING, priv, format, ## arg)
#define xve_info(priv, format, arg...)				\
	do {							\
		if (xve_debug_level & DEBUG_DRV_INFO)		\
			xve_printk(KERN_INFO, priv, format,	\
			## arg);				\
	} while (0)

#define XSMP_INFO(fmt, arg...)					\
	do {							\
		if (xve_debug_level & DEBUG_XSMP_INFO)		\
			PRINT(KERN_DEBUG, "XSMP", fmt, ## arg);\
	} while (0)

#define xve_test(fmt, arg...)					\
	do {							\
		if (xve_debug_level & DEBUG_TEST_INFO)		\
			PRINT(KERN_DEBUG, "DEBUG", fmt, ## arg); \
	} while (0)

#define xve_dbg_data(priv, format, arg...)			\
	do {							\
		if (xve_debug_level & DEBUG_DATA_INFO)		\
			xve_printk(KERN_DEBUG, priv, format,	\
			## arg);				\
	} while (0)
#define xve_dbg_ctrl(priv, format, arg...)			\
	do {							\
		if (xve_debug_level & DEBUG_CTRL_INFO)		\
			xve_printk(KERN_DEBUG, priv, format,	\
			## arg);				\
	} while (0)
#define xve_dbg_mcast(priv, format, arg...)			\
	do {							\
		if (xve_debug_level & DEBUG_MCAST_INFO)		\
			xve_printk(KERN_ERR, priv, format, ## arg); \
	} while (0)
#define xve_debug(level, priv, format, arg...)				\
	do {								\
		if (xve_debug_level & level) {				\
			if (priv)					\
				pr_info_ratelimited("%s: [PID%d] " format "\n",\
				((struct xve_dev_priv *) priv)->netdev->name, \
				current->pid,				\
				## arg);				\
			else						\
				pr_info_ratelimited("XVE" format "\n", ## arg);\
		}							\
	} while (0)

static inline void update_cm_rx_rate(struct xve_cm_ctx *rx_qp, ulong bytes)
{
	rx_qp->stats.total_rx_bytes += bytes;
	rx_qp->stats.rx_bytes += bytes;

	/* update the rate once in two seconds */
	if ((jiffies - rx_qp->stats.rx_jiffies) > 2 * (HZ)) {
		u32 r;

		r = rx_qp->stats.rx_bytes /
		    ((jiffies - rx_qp->stats.rx_jiffies) / (HZ));
		r = (r / 1000000);	/* MB/Sec */
		/* Mega Bits/Sec */
		rx_qp->stats.rx_rate = (r * 8);
		rx_qp->stats.rx_jiffies = jiffies;
		rx_qp->stats.rx_bytes = 0;
	}
}

static inline void update_cm_tx_rate(struct xve_cm_ctx *tx_qp, ulong bytes)
{
	tx_qp->stats.total_tx_bytes += bytes;
	tx_qp->stats.tx_bytes += bytes;

	/* update the rate once in two seconds */
	if ((jiffies - tx_qp->stats.tx_jiffies) > 2 * (HZ)) {
		u32 r;

		r = tx_qp->stats.tx_bytes /
		    ((jiffies - tx_qp->stats.tx_jiffies) / (HZ));
		r = (r / 1000000);	/* MB/Sec */
		/* Mega Bits/Sec */
		tx_qp->stats.tx_rate = (r * 8);
		tx_qp->stats.tx_jiffies = jiffies;
		tx_qp->stats.tx_bytes = 0;
	}
}

static inline int xve_ud_need_sg(unsigned int ib_mtu)
{
	return XVE_UD_BUF_SIZE(ib_mtu) > PAGE_SIZE;
}

static inline struct page *xve_alloc_page(gfp_t alloc_flags)
{
	xve_counters[XVE_NUM_PAGES_ALLOCED]++;
	return alloc_page(alloc_flags);
}

static inline void xve_send_skb(struct xve_dev_priv *priv, struct sk_buff *skb)
{
	struct net_device *netdev = priv->netdev;

	if (netdev->features & NETIF_F_LRO)
		lro_receive_skb(&priv->lro.lro_mgr, skb, NULL);
	else if (netdev->features & NETIF_F_GRO)
		napi_gro_receive(&priv->napi, skb);
	else
		netif_receive_skb(skb);

	netdev->last_rx = jiffies;
	INC_RX_BYTE_STATS(priv, netdev, skb->len);
	INC_RX_PKT_STATS(priv, netdev);
}

static inline struct sk_buff *xve_dev_alloc_skb(struct xve_dev_priv *priv,
						unsigned int size)
{

	struct sk_buff *skb = dev_alloc_skb(size);

	if (skb)
		priv->counters[XVE_RX_SKB_ALLOC_COUNTER]++;
	return skb;
}

static inline void xve_dev_kfree_skb_any(struct xve_dev_priv *priv,
					 struct sk_buff *skb, u8 type)
{

	if (type)
		priv->counters[XVE_TX_SKB_FREE_COUNTER]++;
	else
		priv->counters[XVE_RX_SKB_FREE_COUNTER]++;

	if (skb)
		dev_kfree_skb_any(skb);

}

static inline int xve_cm_admin_enabled(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);

	return priv->cm_supported && test_bit(XVE_FLAG_ADMIN_CM, &priv->flags);
}

static inline int xve_cm_enabled(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);

	return priv->cm_supported && test_bit(XVE_FLAG_ADMIN_CM, &priv->flags);
}

static inline int xve_cm_up(struct xve_path *path)
{
	if (xve_cm_single_qp)
		return test_bit(XVE_FLAG_OPER_UP, &path->cm_ctx_common->flags);
	else
		return test_bit(XVE_FLAG_OPER_UP, &path->cm_ctx_tx->flags);
}

static inline char *xve_cm_txstate(struct xve_cm_ctx *tx)
{
	if (test_bit(XVE_FLAG_OPER_UP, &tx->flags))
		return "Connected";
	else
		return "Not Connected";
}

static inline struct xve_cm_ctx *xve_get_cmctx(struct xve_path *path)
{
	return path->cm_ctx_common;
}

static inline struct xve_cm_ctx *xve_cmtx_get(struct xve_path *path)
{
	if (xve_cm_single_qp)
		return path->cm_ctx_common;
	else
		return path->cm_ctx_tx;
}

static inline struct xve_cm_ctx *xve_cmrx_get(struct xve_path *path)
{
	return path->cm_ctx_rx;
}

static inline void xve_cm_set(struct xve_path *path, struct xve_cm_ctx *tx)
{
	if (xve_cm_single_qp)
		path->cm_ctx_common = tx;
	else
		path->cm_ctx_tx = tx;
}

static inline int xve_cm_has_srq(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);

	return !!priv->cm.srq;
}

static inline unsigned int xve_cm_max_mtu(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);

	return priv->cm.max_cm_mtu;
}

static inline void xve_put_ctx(struct xve_dev_priv *priv)
{
	atomic_dec(&priv->ref_cnt);
}


/* functions */
int xve_poll(struct napi_struct *napi, int budget);
void xve_ib_completion(struct ib_cq *cq, void *dev_ptr);
void xve_data_recv_handler(struct xve_dev_priv *priv);
void xve_send_comp_handler(struct ib_cq *cq, void *dev_ptr);
struct xve_ah *xve_create_ah(struct net_device *dev,
			     struct ib_pd *pd, struct ib_ah_attr *attr);
void xve_free_ah(struct kref *kref);
static inline void xve_put_ah(struct xve_ah *ah)
{
	kref_put(&ah->ref, xve_free_ah);
}

static inline void xve_put_ah_refcnt(struct xve_ah *address)
{
	atomic_dec(&address->refcnt);
}
static inline void xve_get_ah_refcnt(struct xve_ah *address)
{
	atomic_inc(&address->refcnt);
}

int xve_open(struct net_device *dev);
int xve_add_pkey_attr(struct net_device *dev);

int xve_send(struct net_device *dev, struct sk_buff *skb,
	      struct xve_ah *address, u32 qpn, int type);
int poll_tx(struct xve_dev_priv *priv);
int xve_xsmp_send_oper_state(struct xve_dev_priv *priv, u64 vid, int state);
void handle_carrier_state(struct xve_dev_priv *priv, char state);
void queue_sm_work(struct xve_dev_priv *priv, int msecs);
void queue_age_work(struct xve_dev_priv *priv, int msecs);

void xve_mark_paths_invalid(struct net_device *dev);
void xve_flush_single_path_by_gid(struct net_device *dev, union ib_gid *gid,
			   struct xve_fwt_entry *fwt_entry);
struct xve_dev_priv *xve_intf_alloc(const char *format);

int xve_ib_dev_init(struct net_device *dev, struct ib_device *ca, int port);
void xve_ib_dev_cleanup(struct net_device *dev);
void xve_ib_dev_flush_light(struct work_struct *work);
void xve_ib_dev_flush_normal(struct work_struct *work);
void xve_ib_dev_flush_heavy(struct work_struct *work);
void xve_pkey_event(struct work_struct *work);
void xve_reap_ah(struct work_struct *work);
void xve_cm_stale_task(struct work_struct *work);
void xve_mcast_join_task(struct work_struct *work);
void xve_mcast_leave_task(struct work_struct *work);
void xve_mcast_restart_task(struct work_struct *work);
void xve_cm_tx_start(struct work_struct *work);
void xve_cm_tx_reap(struct work_struct *work);
void xve_cm_rx_reap(struct work_struct *work);
void xve_state_machine_work(struct work_struct *work);
void xve_pkey_poll(struct work_struct *work);
void xve_start_aging_work(struct work_struct *work);
void xve_mcast_carrier_on_task(struct work_struct *work);

int xve_ib_dev_open(struct net_device *dev);
int xve_ib_dev_up(struct net_device *dev);
int xve_ib_dev_down(struct net_device *dev, int flush);
int xve_ib_dev_stop(struct net_device *dev, int flush);

int xve_dev_init(struct net_device *dev, struct ib_device *ca, int port);
void xve_dev_cleanup(struct net_device *dev);
void xve_fwt_entry_destroy(struct xve_dev_priv *priv,
			   struct xve_fwt_entry *fwt_entry);
void xve_remove_fwt_entry(struct xve_dev_priv *priv,
			  struct xve_fwt_entry *fwt_entry);
void xve_fwt_entry_free(struct xve_dev_priv *priv,
			struct xve_fwt_entry *fwt_entry);

int xve_mcast_send(struct net_device *dev, void *mgid, struct sk_buff *skb,
		u8 bcast);
void xve_advert_mcast_join(struct xve_dev_priv *priv);
int xve_mcast_start_thread(struct net_device *dev);
int xve_mcast_stop_thread(struct net_device *dev, int flush);

void xve_mcast_dev_down(struct net_device *dev);
void xve_mcast_dev_flush(struct net_device *dev);
int xve_mcast_attach(struct net_device *dev, u16 mlid,
		     union ib_gid *mgid, int set_qkey);

int xve_init_qp(struct net_device *dev);
int xve_transport_dev_init(struct net_device *dev, struct ib_device *ca);
void xve_transport_dev_cleanup(struct net_device *dev);

void xve_event(struct ib_event_handler *handler, struct ib_event *record);

int xve_pkey_dev_delay_open(struct net_device *dev);
void xve_drain_cq(struct net_device *dev);

void xve_set_ethtool_ops(struct net_device *dev);
int xve_set_dev_features(struct xve_dev_priv *priv, struct ib_device *hca);
int xve_modify_mtu(struct net_device *netdev, int new_mtu);

struct sk_buff *xve_generate_query(struct xve_dev_priv *priv,
				   struct sk_buff *skb);
struct sk_buff *xve_create_arp(struct xve_dev_priv *priv,
			       struct sk_buff *org_skb);
struct sk_buff *xve_create_ndp(struct xve_dev_priv *priv,
			       struct sk_buff *org_skb);
int xve_send_hbeat(struct xve_dev_priv *xvep);
void xve_xsmp_handle_oper_req(xsmp_cookie_t xsmp_hndl, u64 resource_id);

/*CM */
int xve_cm_send(struct net_device *dev, struct sk_buff *skb,
		 struct xve_cm_ctx *tx);
int xve_cm_dev_open(struct net_device *dev);
void xve_cm_dev_stop(struct net_device *dev);
int xve_cm_dev_init(struct net_device *dev);
void xve_cm_dev_cleanup(struct net_device *dev);
struct xve_cm_ctx *xve_cm_create_tx(struct net_device *dev,
				    struct xve_path *path);
void xve_cm_destroy_tx_deferred(struct xve_cm_ctx *tx);
void xve_cm_skb_too_long(struct net_device *dev, struct sk_buff *skb,
			 unsigned int mtu);
void xve_cm_handle_rx_wc(struct net_device *dev, struct ib_wc *wc);
void xve_cm_handle_tx_wc(struct net_device *dev, struct ib_wc *wc);

int xve_tables_init(void);
void xve_fwt_init(struct xve_fwt_s *xve_fwt);
void xve_fwt_insert(struct xve_dev_priv *priv, struct xve_cm_ctx *ctx,
		    union ib_gid *gid, u32 qpn, char *smac, u16 vlan);
void xve_fwt_cleanup(struct xve_dev_priv *xvep);
int xve_advert_process(struct xve_dev_priv *priv, struct sk_buff *skb);
struct xve_fwt_entry *xve_fwt_lookup(struct xve_dev_priv *priv, char *mac,
				     u16 vlan, int refresh);
void xve_fwt_put_ctx(struct xve_fwt_s *xve_fwt,
		     struct xve_fwt_entry *fwt_entry);
bool xve_fwt_entry_valid(struct xve_fwt_s *xve_fwt,
			 struct xve_fwt_entry *fwt_entry);
void xve_flush_l2_entries(struct net_device *netdev, struct xve_path *path);
int xve_aging_task_machine(struct xve_dev_priv *priv);
void xve_prepare_skb(struct xve_dev_priv *priv, struct sk_buff *skb);
void xve_tables_exit(void);
void xve_remove_one(struct xve_dev_priv *priv);
struct xve_path *__path_find(struct net_device *netdev, void *gid);
int xve_add_proc_entry(struct xve_dev_priv *vp);
void xve_remove_proc_entry(struct xve_dev_priv *vp);
int xve_gw_send(struct net_device *priv, struct sk_buff *skb);
struct xve_path *xve_get_gw_path(struct net_device *dev);
void xve_set_oper_up_state(struct xve_dev_priv *priv);

static inline int xve_continue_unload(void)
{
	return !(xve_debug_level & DEBUG_CONTINUE_UNLOAD);
}

static inline int xve_get_misc_info(void)
{
	return xve_debug_level & DEBUG_MISC_INFO;
}

static inline int xg_vlan_tx_tag_present(struct sk_buff *skb)
{
	struct vlan_ethhdr *veth = (struct vlan_ethhdr *)(skb->data);

	return veth->h_vlan_proto == htons(ETH_P_8021Q);
}

static inline u16 xg_vlan_get_rxtag(struct sk_buff *skb)
{
	struct ethhdr *eh = (struct ethhdr *)(skb->data);
	u16 vlan_tci = 0xFFFF;

	if (eh->h_proto == htons(ETH_P_8021Q)) {
		struct vlan_ethhdr *veth = (struct vlan_ethhdr *)(skb->data);

		vlan_tci = be16_to_cpu(veth->h_vlan_TCI);
	} else {
		vlan_tci = 0;
	}

	return vlan_tci;

}


static inline int xve_linearize_skb(struct net_device *dev,
		struct sk_buff *skb,
		struct xve_dev_priv *priv,
		unsigned max_send_sge)
{
	unsigned usable_sge = max_send_sge - !!skb_headlen(skb);

	if (skb_shinfo(skb)->nr_frags > usable_sge) {
		if (skb_linearize(skb) < 0) {
			pr_warn_ratelimited("XVE: %s failure to linearize\n",
					priv->xve_name);
			INC_TX_DROP_STATS(priv, dev);
			INC_TX_ERROR_STATS(priv, dev);
			dev_kfree_skb_any(skb);
			return -1;
		}

		/* skb_linearize returned ok but still not reducing nr_frags */
		if (skb_shinfo(skb)->nr_frags > usable_sge) {
			pr_warn_ratelimited
				("XVE: %s too many frags after skb linearize\n",
				 priv->xve_name);
			INC_TX_DROP_STATS(priv, dev);
			INC_TX_ERROR_STATS(priv, dev);
			dev_kfree_skb_any(skb);
			return -1;
		}
		priv->counters[XVE_TX_LIN_SKB_COUNTER]++;
	}
	return 0;

}


/*
 * xve_calc_speed - calculate port speed
 *
 * @priv - device private data
 *
 * RETURNS: actual port speed
 */
static inline unsigned int xve_calc_speed(struct xve_dev_priv *priv)
{
	struct ib_port_attr *attr = &priv->port_attr;
	unsigned int link_speed;
	int port_width;

	if (!priv)
		return 0;

	switch (attr->active_speed) {
	case 0x1:
		link_speed = SPEED_SDR;
		break;
	case 0x2:
		link_speed = SPEED_DDR;
		break;
	case 0x4:
		link_speed = SPEED_QDR;
		break;
	case 0x8:
		link_speed = SPEED_FDR10;
		break;
	case 0x10:
		link_speed = SPEED_FDR;
		break;
	case 0x20:
		link_speed = SPEED_EDR;
		break;
	default:
		link_speed = 0;
	}

	port_width = ib_width_enum_to_int(attr->active_width);
	if (port_width < 0)
		port_width = 0;

	return link_speed * port_width;
}

/* Work queue functions */
static inline void xve_queue_work(struct xve_dev_priv *priv, int work_type)
{
	struct xve_work *work;

	if (test_bit(XVE_DELETING, &priv->flags)) {
		priv->misc_counters[XVE_WQ_DONT_SCHEDULE]++;
		return;
	}

	work = kmalloc(sizeof(*work), GFP_ATOMIC);
	if (!work)
		return;
	work->priv = priv;

	switch (work_type) {
	case XVE_WQ_START_CMTXSTART:
		INIT_WORK(&work->work, xve_cm_tx_start);
		break;
	case XVE_WQ_START_CMTXREAP:
		INIT_WORK(&work->work, xve_cm_tx_reap);
		break;
	case XVE_WQ_START_CMRXREAP:
		INIT_WORK(&work->work, xve_cm_rx_reap);
		break;
	case XVE_WQ_START_MCASTON:
		INIT_WORK(&work->work, xve_mcast_carrier_on_task);
		break;
	case XVE_WQ_START_MCASTRESTART:
		INIT_WORK(&work->work, xve_mcast_restart_task);
		break;
	case XVE_WQ_START_FLUSHLIGHT:
		INIT_WORK(&work->work, xve_ib_dev_flush_light);
		break;
	case XVE_WQ_START_FLUSHNORMAL:
		INIT_WORK(&work->work, xve_ib_dev_flush_normal);
		break;
	case XVE_WQ_START_FLUSHHEAVY:
		INIT_WORK(&work->work, xve_ib_dev_flush_heavy);
		break;
	default:
		priv->misc_counters[XVE_WQ_INVALID]++;
		kfree(work);
		work = NULL;
		break;
	}

	if (!work)
		return;

	if (queue_work(xve_taskqueue, &work->work) != 0) {
		atomic_inc(&priv->ref_cnt);
		priv->misc_counters[work_type]++;
	} else {
		priv->misc_counters[XVE_WQ_FAILED]++;
		priv->work_queue_failed = work_type;
	}

}

static inline void xve_queue_dwork(struct xve_dev_priv *priv, int work_type,
				   u64 time)
{

	struct xve_work *work;

	if (test_bit(XVE_DELETING, &priv->flags)) {
		priv->misc_counters[XVE_WQ_DONT_SCHEDULE]++;
		return;
	}

	work = kmalloc(sizeof(*work), GFP_ATOMIC);
	if (!work)
		return;
	work->priv = priv;

	switch (work_type) {
	case XVE_WQ_START_PKEYPOLL:
		INIT_DELAYED_WORK(&work->dwork, xve_pkey_poll);
		break;
	case XVE_WQ_START_AHREAP:
		INIT_DELAYED_WORK(&work->dwork, xve_reap_ah);
		break;
	case XVE_WQ_START_FWT_AGING:
		INIT_DELAYED_WORK(&work->dwork, xve_start_aging_work);
		break;

	default:
		priv->misc_counters[XVE_WQ_INVALID]++;
		kfree(work);
		work = NULL;
		break;
	}

	if (!work)
		return;

	if (queue_delayed_work(xve_taskqueue, &work->dwork, time) != 0) {
		atomic_inc(&priv->ref_cnt);
		priv->misc_counters[work_type]++;
	} else {
		priv->misc_counters[XVE_WQ_FAILED]++;
		priv->work_queue_failed = work_type;
	}

}

static inline void xve_queue_complete_work(struct xve_dev_priv *priv,
					   int work_type, u64 time)
{
	if (test_bit(XVE_DELETING, &priv->flags)) {
		priv->misc_counters[XVE_WQ_DONT_SCHEDULE]++;
		return;
	}

	switch (work_type) {
	case XVE_WQ_START_CMSTALE:
		queue_delayed_work(xve_taskqueue, &priv->stale_task, time);
		break;
	case XVE_WQ_START_MCASTJOIN:
		queue_delayed_work(xve_taskqueue, &priv->mcast_join_task, time);
		break;
	case XVE_WQ_START_MCASTLEAVE:
		queue_delayed_work(xve_taskqueue, &priv->mcast_leave_task,
				   time);
		break;
	default:
		priv->misc_counters[XVE_WQ_INVALID]++;
		break;
	}

	priv->misc_counters[work_type]++;

}

static inline struct xve_dev_priv *xve_get_wqctx(struct work_struct *work,
						 int work_type, u8 code)
{
	struct xve_work *xwork;
	struct xve_dev_priv *priv;

/*
 * 2 For getting work strucute complete, 1 for Delayed work and
 * 0 for Work structures
 */
	if (code == 2) {
		switch (work_type) {
		case XVE_WQ_FINISH_CMSTALE:
			priv =
			    container_of(work, struct xve_dev_priv,
					 stale_task.work);
			break;
		case XVE_WQ_FINISH_MCASTJOIN:
			priv =
			    container_of(work, struct xve_dev_priv,
					 mcast_join_task.work);
			break;
		case XVE_WQ_FINISH_MCASTLEAVE:
			priv =
			    container_of(work, struct xve_dev_priv,
					 mcast_leave_task.work);
			break;
		default:
			return NULL;
		}
	} else {
		if (code == 1)
			xwork = container_of(work, struct xve_work, dwork.work);
		else
			xwork = container_of(work, struct xve_work, work);
		priv = xwork->priv;
		kfree(xwork);
	}
	priv->misc_counters[work_type]++;
	return priv;
}

/* DEBUG FUNCTIONS */
static inline void dbg_dump_raw_pkt(unsigned char *buff, int length, char *name)
{
	int i;
	int tmp_len;
	u32 *data_ptr;
	unsigned char *tmp_data_ptr;

	if (!(xve_debug_level & DEBUG_TEST_INFO))
		return;

	pr_info("%s. Packet length is %d\n", name, length);
	tmp_len = (length >> 2) + 1;
	data_ptr = (u32 *) buff;
	for (i = 0; i < tmp_len; i++) {
		tmp_data_ptr = (unsigned char *)&data_ptr[i];
		pr_info("%02x %02x %02x %02x\n",
			tmp_data_ptr[0], tmp_data_ptr[1],
			tmp_data_ptr[2], tmp_data_ptr[3]);
	}
}

static inline void dbg_dump_skb(struct sk_buff *skb)
{
	char prefix[32];

	if (!(xve_debug_level & DEBUG_TEST_INFO))
		return;
	snprintf(prefix, 32, "%s:skb-%p", skb->dev ? skb->dev->name : "NULL ",
		 skb);

	pr_info("[%s] --- skb dump ---\n", prefix);
	pr_info("[%s] len     : %d\n", prefix, skb->len);
	pr_info("[%s] truesize: %d\n", prefix, skb->truesize);
	pr_info("[%s] data_len: %d\n", prefix, skb->data_len);
	pr_info("[%s] nr_frags: %d\n", prefix, skb_shinfo(skb)->nr_frags);
	pr_info("[%s] data    : %p\n", prefix, (void *)skb->data);
	pr_info("[%s] head    : %p\n", prefix, (void *)skb->head);
	pr_info("\n");

}

static inline void dumppkt(unsigned char *pkt, unsigned short len, char *name)
{
	int i = 0;
	unsigned char *p = (unsigned char *)pkt;
	char line[64] = { 0 };
	char *cp = line;
	char filter[] = "0123456789abcdef";
	int printed_line = 0;

	if (!(xve_debug_level & DEBUG_DUMP_PKTS))
		return;

	pr_info("%s DumpPacket of %d\n", name, len);

	for (i = 0; i < len; i++) {
		if ((i != 0) && (i % 16 == 0)) {
			pr_info("%s\n", line);
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
			pr_info("%s\n", line);
			memset(line, 0, sizeof(line));
			cp = line;
		}
	}
	*--cp = 0;
}

static inline void print_mgid(char *bcast_mgid_token, int debug)
{
	if (!debug && !(xve_debug_level & DEBUG_TEST_INFO))
		return;
	pr_info("MGID %x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x\n",
		bcast_mgid_token[0] & 0xff, bcast_mgid_token[1] & 0xff,
		bcast_mgid_token[2] & 0xff, bcast_mgid_token[3] & 0xff,
		bcast_mgid_token[4] & 0xff, bcast_mgid_token[5] & 0xff,
		bcast_mgid_token[6] & 0xff, bcast_mgid_token[7] & 0xff,
		bcast_mgid_token[8] & 0xff, bcast_mgid_token[9] & 0xff,
		bcast_mgid_token[10] & 0xff, bcast_mgid_token[11] & 0xff,
		bcast_mgid_token[12] & 0xff, bcast_mgid_token[13] & 0xff,
		bcast_mgid_token[14] & 0xff, bcast_mgid_token[15] & 0xff);
}

static inline void print_mgid_buf(char buffer[], char *bcast_mgid_token)
{
	sprintf(buffer, "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x   ",
		bcast_mgid_token[0] & 0xff, bcast_mgid_token[1] & 0xff,
		bcast_mgid_token[2] & 0xff, bcast_mgid_token[3] & 0xff,
		bcast_mgid_token[4] & 0xff, bcast_mgid_token[5] & 0xff,
		bcast_mgid_token[6] & 0xff, bcast_mgid_token[7] & 0xff,
		bcast_mgid_token[8] & 0xff, bcast_mgid_token[9] & 0xff,
		bcast_mgid_token[10] & 0xff, bcast_mgid_token[11] & 0xff,
		bcast_mgid_token[12] & 0xff, bcast_mgid_token[13] & 0xff,
		bcast_mgid_token[14] & 0xff, bcast_mgid_token[15] & 0xff);
}

#endif /* _XVE_H */
