/*
 * Copyright (c) 2009 Mellanox Technologies. All rights reserved.
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

#ifndef VNIC_H
#define VNIC_H

#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/if_vlan.h>
#include <linux/if_arp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#include <linux/if_ether.h>
#include <linux/etherdevice.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/inet_lro.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/rwsem.h>
#include <linux/vmalloc.h>
#include <net/dst.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_pack.h>
#include <rdma/ib_sa.h>

/* for mlx4_ib dev attr, used also in vnic_qp.c */
#include "../../../../infiniband/hw/mlx4/mlx4_ib.h"
#include "../../../../infiniband/hw/mlx4/user.h"

#include "vnic_utils.h"

/* driver info definition */
#define DRV_NAME  "mlx4_vnic"
#define DRV_VER   "1.4.0"
#define DRV_LIC   "Dual BSD/GPL"
#define DRV_DESC  "Mellanox BridgeX Virtual NIC Driver"
#define DRV_AUTH  "Ali Ayoub & Gabi Liron"

/* backports */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,35))
#define _BP_NO_MC_LIST

// Not sure this should be here at least this is ok for 2.6.39
#define _BP_NO_ATT_OWNER
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0))
#define _BP_NO_GRO
#endif

/* externs */
extern u32 vnic_msglvl;
extern u32 vnic_max_tx_outs;
extern u32 vnic_lro_num;
extern u32 vnic_mcast_create;
extern u32 vnic_net_admin;
extern u32 vnic_child_max;
extern u32 vnic_napi_weight;
extern u32 vnic_linear_small_pkt;
extern u32 vnic_tx_rings_num;
extern u32 vnic_rx_rings_num;
extern u32 vnic_tx_rings_len;
extern u32 vnic_rx_rings_len;
extern u32 vnic_mgid_data_type;
extern u32 vnic_encap_headroom;
extern u32 vnic_tx_polling;
extern u32 vnic_rx_linear;
extern u32 vnic_change_mac;
extern u32 vnic_learn_mac_enabled;
extern u32 vnic_synd_backlog;
extern u32 vnic_eport_state_enforce;
extern u32 vnic_src_mac_enforce;
extern u32 vnic_inline_tshold;

#define MAX_NUM_PKEYS_DISCOVERY	(24)
#define ILLEGAL_PKEY_INDEX	(0xFFFF)
extern u32 vnic_discovery_pkeys[MAX_NUM_PKEYS_DISCOVERY];
extern u32 vnic_discovery_pkeys_count;
extern u32 vnic_sa_query;


extern u32 no_bxm;

extern struct workqueue_struct *port_wq;
extern struct workqueue_struct *fip_wq;
extern struct workqueue_struct *mcast_wq;
extern struct workqueue_struct *login_wq;

extern struct ib_sa_client vnic_sa_client;

/* definitions */
#define EOIB_SERVICE_ID ((0x10ULL << 56) | (0x0002C9E01B0000ULL))
#define EOIB_CTRL_SERVICE_ID (EOIB_SERVICE_ID | 0x00FFULL)
#define VNIC_SKB_QUEUE_LEN	32
#define VNIC_CNT_MAX		32
#define VNIC_DESC_LEN		(64 + 4)
#define VNIC_NAME_LEN		16 /* by spec, use IFNAMSIZ for OS */
#define VNIC_SYSFS_FLEN		(VNIC_NAME_LEN * 2) /* SYSFS file name len, allow pre/suffix (32)*/
#define VNIC_SYSFS_LLEN		64
#define VNIC_VENDOR_LEN		8
#define GID_LEN			16
#define GUID_LEN		8
#define IPV4_LEN		4
#define IPV6_LEN		16
#define VNIC_SYSTEM_NAME_LEN	32
#define VNIC_GW_PORT_NAME_LEN	8
#define GID_PREFIX_LEN		5
#define VNIC_MAX_DENTRIES	16
#define VNIC_ID_LEN		16
#define VNIC_CHILD_MAX		128
#define VNIC_MAX_RETRIES	0 /* zero = unlimited */
#define VNIC_WATCHDOG_TIMEOUT	(25 * HZ) /* 25 sec */
#define VNIC_NAPI_SCHED_TIMEOUT (5)
#define FIP_MAX_VNICS_PER_GW	(1 << 9)
#define NOT_AVAILABLE_NUM	(-1)
#define NOT_AVAILABLE_STRING	"N/A"
#define is_valid_str(str)	(strcmp(str, NOT_AVAILABLE_STRING))
#define is_valid_num(num)	(num != NOT_AVAILABLE_NUM)
#define is_valid_guid(arr)	(!!(*((u64 *)(arr))))
#define is_valid_ipv4(arr)	(!!(*((u32 *)(arr))))
#define is_mcast_promisc(login)	(!(login->n_mac_mcgid))
#define is_ucast_promisc(login) (!!(login->dev->flags & IFF_PROMISC))
#define ARRAY_LEN(_x)		(sizeof(_x)/sizeof(_x[0]))

/* TODO: cleanup VNIC_GID_RAW_ARG and friends */
#define VNIC_GID_RAW_ARG(gid)	((u8 *)(gid))[0], \
				((u8 *)(gid))[1], \
				((u8 *)(gid))[2], \
				((u8 *)(gid))[3], \
				((u8 *)(gid))[4], \
				((u8 *)(gid))[5], \
				((u8 *)(gid))[6], \
				((u8 *)(gid))[7], \
				((u8 *)(gid))[8], \
				((u8 *)(gid))[9], \
				((u8 *)(gid))[10],\
				((u8 *)(gid))[11],\
				((u8 *)(gid))[12],\
				((u8 *)(gid))[13],\
				((u8 *)(gid))[14],\
				((u8 *)(gid))[15]
#define VNIC_GUID_RAW_ARG(gid)	((u8 *)(gid))[0], \
				((u8 *)(gid))[1], \
				((u8 *)(gid))[2], \
				((u8 *)(gid))[3], \
				((u8 *)(gid))[4], \
				((u8 *)(gid))[5], \
				((u8 *)(gid))[6], \
				((u8 *)(gid))[7]

#define VNIC_GID_ARG(gid) 	VNIC_GID_RAW_ARG((gid).raw)
#define VNIC_GID_FMT		"%.2x:%.2x:%.2x:%.2x:" \
				"%.2x:%.2x:%.2x:%.2x:" \
				"%.2x:%.2x:%.2x:%.2x:" \
				"%.2x:%.2x:%.2x:%.2x"
#define VNIC_GUID_FMT		"%.2x:%.2x:%.2x:%.2x:" \
				"%.2x:%.2x:%.2x:%.2x"

#define MAC_6_PRINT_FMT		"%.2x:%.2x:%.2x:%.2x:" \
				"%.2x:%.2x"
#define MAC_6_PRINT_ARG(mac)	(mac)[0], (mac)[1], (mac)[2], \
				(mac)[3], (mac)[4], (mac)[5]

#define IP_4_PRINT_FMT		"%d.%d.%d.%d"
#define IP_4_PRINT_ARG(ip)	(ip)[0], (ip)[1], (ip)[2], (ip)[3]

#define CREATE_VHUB_ID(be_vlan, port_id) \
	((be16_to_cpu(be_vlan) & 0xFFF) | (((port_id) & 0xFFF) << 12))
#define CREATE_VHUB_ID_BE(vlan, port_id) \
	cpu_to_be32(CREATE_VHUB_ID(vlan, port_id))
#define ROUNDUP_LOG2(x)		ilog2(roundup_pow_of_two(x))

#define VNIC_RX_COAL_TARGET	0x20000
#define VNIC_RX_COAL_TIME	0x10
#define VNIC_TX_COAL_PKTS	64
#define VNIC_TX_COAL_TIME	0x80
#define VNIC_RX_RATE_LOW	400000
#define VNIC_RX_COAL_TIME_LOW	0
#define VNIC_RX_RATE_HIGH	450000
#define VNIC_RX_COAL_TIME_HIGH	128
#define VNIC_RX_SIZE_THRESH	1024
#define VNIC_RX_RATE_THRESH	(1000000 / VNIC_RX_COAL_TIME_HIGH)
#define VNIC_SAMPLE_INTERVAL	0
#define VNIC_AVG_PKT_SMALL	256
#define VNIC_AUTO_CONF		0xffff
#define VNIC_MCAST_MAX_RETRY	60
#define VNIC_MCAST_ULIMIT_RETRY	0
#define VNIC_MCAST_BACKOF_FAC	2
#define MLX4_DEV_CAP_FLAG_UD_SWP (1 << 28)
#define VNIC_ETHTOOL_LINE_MAX	32
#define VNIC_ENCAP_LEN		4
#define VNIC_MAX_TX_SIZE	2048
#define VNIC_MAX_RX_SIZE	4096
#define ETH_LLC_SNAP_SIZE	8

#define VNIC_SM_HEADSTART			250 /* msecs to actually start handling SM events */
#define VNIC_MCAST_BACKOFF_MSEC		1000
#define VNIC_MCAST_BACKOFF_MAX_MSEC	16000

#define SYSFS_VLAN_ID_NO_VLAN		(-1)

#define VNIC_MAX_PAYLOAD_SIZE		4096
#define VNIC_BUF_SIZE(_port)		(min(_port->max_mtu_enum + \
					IB_GRH_BYTES, VNIC_MAX_PAYLOAD_SIZE))

#define VNIC_TX_QUEUE_LEN		1024 /* default, tuneable */
#define VNIC_TX_QUEUE_LEN_MIN		64
#define VNIC_TX_QUEUE_LEN_MAX		(8 * 1024)

#define VNIC_RX_QUEUE_LEN		2048 /* default, tuneable */
#define VNIC_RX_QUEUE_LEN_MIN		64
#define VNIC_RX_QUEUE_LEN_MAX		(8 * 1024)


#define VNIC_MODER_DELAY		(HZ / 4)
#define VNIC_STATS_DELAY		VNIC_MODER_DELAY

#define VNIC_AH_SL_DEFAULT		0x0

#define VNIC_DATA_QKEY			0x80020003
#define VNIC_FIP_QKEY			0x80020002
#define VNIC_VLAN_OFFSET(login)		(login->vlan_used ? VLAN_HLEN : 0)
#define VNIC_VLAN_ENABLED(login)	(login->vlan_used ? 1 : 0)
#define VNIC_MAX_TX_CQE			32	/* default, tuneable */
#define VNIC_MAX_RX_CQE			64	/* default, tuneable */
#define VNIC_MAX_NUM_CPUS		32
#define VNIC_MAX_INLINE_TSHOLD		512

#define VNIC_EOIB_HDR_VER		0x0
#define VNIC_EOIB_HDR_SIG		0x3
#define VNIC_EOIB_HDR_UDP_CHK_OK	0x2
#define VNIC_EOIB_HDR_TCP_CHK_OK	0x1
#define VNIC_EOIB_HDR_IP_CHK_OK		0x1

#define VNIC_EOIB_HDR_GET_IP_CHK(eoib_hdr)	(eoib_hdr->encap_data & 0x3)
#define VNIC_EOIB_HDR_GET_TCP_UDP_CHK(eoib_hdr)	((eoib_hdr->encap_data >> 2) & 0x3)
#define VNIC_EOIB_HDR_GET_VER(eoib_hdr)		((eoib_hdr->encap_data >> 4) & 0x3)
#define VNIC_EOIB_HDR_GET_SIG(eoib_hdr) 	((eoib_hdr->encap_data >> 6) & 0x3)

#define VNIC_EOIB_HDR_SET_IP_CHK_OK(eoib_hdr)	(eoib_hdr->encap_data = \
						(eoib_hdr->encap_data & 0xFC) | VNIC_EOIB_HDR_IP_CHK_OK)
#define VNIC_EOIB_HDR_SET_TCP_CHK_OK(eoib_hdr)	(eoib_hdr->encap_data = \
						(eoib_hdr->encap_data & 0xF3) | (VNIC_EOIB_HDR_TCP_CHK_OK << 2))
#define VNIC_EOIB_HDR_SET_UDP_CHK_OK(eoib_hdr)	(eoib_hdr->encap_data = \
						(eoib_hdr->encap_data & 0xF3) | (VNIC_EOIB_HDR_UDP_CHK_OK << 2))

#define VNIC_IP_CSUM_OK(eoib_hdr)	((VNIC_EOIB_HDR_GET_IP_CHK(eoib_hdr))  == VNIC_EOIB_HDR_IP_CHK_OK)
#define VNIC_TCP_CSUM_OK(eoib_hdr)	((VNIC_EOIB_HDR_GET_TCP_UDP_CHK(eoib_hdr)) == VNIC_EOIB_HDR_TCP_CHK_OK)
#define VNIC_UDP_CSUM_OK(eoib_hdr)	((VNIC_EOIB_HDR_GET_TCP_UDP_CHK(eoib_hdr)) == VNIC_EOIB_HDR_UDP_CHK_OK)
#define VNIC_CSUM_OK(eoib_hdr)		(VNIC_IP_CSUM_OK(eoib_hdr)  && \
					(VNIC_TCP_CSUM_OK(eoib_hdr) || \
					 VNIC_UDP_CSUM_OK(eoib_hdr)))
#define VNIC_EOIB_ZLEN_MAX		(ETH_ZLEN + VNIC_ENCAP_LEN + VLAN_HLEN)

#define VNIC_SKB_GET_HASH(_skb, _max)	((*(u32 *)(_skb->cb + sizeof _skb->cb - 4)) % _max)
#define VNIC_SKB_SET_HASH(_skb, _hash)  ((*(u32 *)(_skb->cb + sizeof _skb->cb - 4)) = _hash)
#define VNIC_SKB_GET_ENCAP_CB(_skb)	((struct eoibhdr *)(_skb->cb + sizeof _skb->cb - 12))
#define VNIC_SKB_GET_ENCAP(_skb)	(vnic_encap_headroom ? (struct eoibhdr *)(_skb->data) : VNIC_SKB_GET_ENCAP_CB(_skb))
#define VNIC_SKB_GET_ENCAP_OFFSET	(vnic_encap_headroom ? VNIC_ENCAP_LEN :0)

#define VNIC_NEIGH_GET_DQPN(_skb, _neighe) ((_neighe->rss) ? (_neighe->qpn + \
	VNIC_SKB_GET_HASH(_skb, _neighe->login->qps_num)) : (_neighe->qpn))

#define vnic_netdev_priv(netdev)	(((struct vnic_login_info *)netdev_priv(netdev))->login)
#ifndef _BP_NETDEV_NO_TMQ /* >= 2.6.27 */
#define VNIC_TXQ_GET_HASH(_skb, _max)	(skb_get_queue_mapping(_skb))
#define VNIC_TXQ_ALLOC_NETDEV(sz, nm, sp, qm) alloc_netdev_mq(sz, nm, sp, qm)
#define VNIC_TXQ_SET_ACTIVE(login, num)	(login->dev->real_num_tx_queues = \
					login->real_tx_rings_num = \
					login->ndo_tx_rings_num = num)
#define VNIC_TXQ_GET_ACTIVE(login)	(login->real_tx_rings_num)
#define VNIC_TXQ_GET(tx_res)		netdev_get_tx_queue(tx_res->login->dev, tx_res->index)
#define VNIC_TXQ_STOP(tx_res) 		netif_tx_stop_queue(VNIC_TXQ_GET(tx_res))
#define VNIC_TXQ_STOP_ALL(login)	netif_tx_stop_all_queues(login->dev)
#define VNIC_TXQ_START(tx_res)		netif_tx_start_queue(VNIC_TXQ_GET(tx_res))
#define VNIC_TXQ_START_ALL(login) 	netif_tx_start_all_queues(login->dev)
#define VNIC_TXQ_STOPPED(tx_res)	netif_tx_queue_stopped(VNIC_TXQ_GET(tx_res))
#define VNIC_TXQ_WAKE(tx_res)		netif_tx_wake_queue(VNIC_TXQ_GET(tx_res))
#else
#define VNIC_TXQ_GET_HASH(skb, _max)	VNIC_SKB_GET_HASH(skb, _max)
#define VNIC_TXQ_ALLOC_NETDEV(sz, nm, sp, qm) alloc_netdev(sz, nm, sp)
#define VNIC_TXQ_SET_ACTIVE(login, num)	do { login->real_tx_rings_num = num; \
					     login->ndo_tx_rings_num = 1;    \
					} while (0)
#define VNIC_TXQ_GET_ACTIVE(login)	(login->real_tx_rings_num)
#define VNIC_TXQ_STOP(tx_res)		netif_stop_queue(tx_res->login->dev)
#define VNIC_TXQ_STOP_ALL(login)	netif_stop_queue(login->dev)
#define VNIC_TXQ_START(tx_res)		netif_start_queue(tx_res->login->dev)
#define VNIC_TXQ_START_ALL(login) 	netif_start_queue(login->dev)
#define VNIC_TXQ_STOPPED(tx_res)	netif_queue_stopped(tx_res->login->dev)
#define VNIC_TXQ_WAKE(tx_res)		netif_wake_queue(tx_res->login->dev)
#endif

#define VNIC_ALLOC_ORDER		2
#define VNIC_ALLOC_SIZE			(PAGE_SIZE << VNIC_ALLOC_ORDER)
#define VNIC_MAX_LRO_AGGR		64
#define VNIC_MAX_RX_FRAGS		4
#define VNIC_MAX_TX_FRAGS 		(MAX_SKB_FRAGS + 2)
#define VNIC_MGID_PREFIX_LEN		5

/* TODO, when set VNIC_MAX_TX_OUTS to 16,
 * noticed that the last CQE overwrites the first one
 */
#define VNIC_MAX_TX_OUTS		8  /* default, tuneable */
#define VNIC_MAX_LRO_DESCS		32 /* default, tuneable */
#define VNIC_EOIB_HDR_SIZE		(IB_GRH_BYTES + VNIC_ENCAP_LEN)
#define SMALL_PACKET_SIZE		(256 - NET_IP_ALIGN)
#define HEADER_COPY_SIZE		(128 - NET_IP_ALIGN)
#define MAX_HEADER_SIZE			64

#define LAG_MAP_TABLE_SIZE		32
#define	MAX_LAG_MEMBERS			16

#define VNIC_FW_STR_MAX			VNIC_ETHTOOL_LINE_MAX
#define VNIC_FW_STR(u64_fw_ver, str)					\
do {									\
	snprintf(str, VNIC_FW_STR_MAX, "%d.%d.%d",			\
	(int)(u64_fw_ver >> 32),					\
	(int)(u64_fw_ver >> 16) & 0xffff,				\
	(int)(u64_fw_ver & 0xffff));					\
} while (0);
#define VNIC_STR_STRIP(str)						\
do {									\
	int i;								\
	for (i = 0; i < strlen(str); ++i)				\
		str[i] = str[i] == '\n' ? ' ' : str[i];			\
} while (0);

/* well known addresses */
static const u8 ETH_BCAST_MAC[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const u8 ETH_ZERO_MAC[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* this used in no_bxm mode only */
static const u8 NO_BXM_MGID_PREFIX[] = {
	0xff, 0x13, 0xe0, 0x1b, 0x00
};

#define IS_ZERO_MAC(mac) (!memcmp((mac), ETH_ZERO_MAC, ETH_ALEN))
#define IS_BCAST_MAC(mac) (!memcmp((mac), ETH_BCAST_MAC, ETH_ALEN))
#define IS_MCAST_MAC(mac) (((unsigned char *)(mac))[0] & 0x01)
#define IS_UCAST_MAC(mac) (!(IS_MCAST_MAC(mac)))
#define IS_NEIGH_QUERY_RUNNING(neigh) \
	(neigh->query_id >= 0 && !IS_ERR(neigh->pquery) && neigh->pquery)

struct mcast_root {
	struct rb_root 	mcast_tree;
	spinlock_t 	mcast_rb_lock;
	struct list_head reattach_list;
};

/* structs */
struct vnic_port_stats {
	unsigned long gro_held;
	unsigned long gro_merged;
	unsigned long gro_normal;
	unsigned long gro_drop;
	unsigned long lro_aggregated;
	unsigned long lro_flushed;
	unsigned long lro_no_desc;
	unsigned long tso_packets;
	unsigned long queue_stopped;
	unsigned long wake_queue;
	unsigned long tx_timeout;
	unsigned long rx_chksum_good;
	unsigned long rx_chksum_none;
	unsigned long tx_chksum_offload;
	unsigned long sig_ver_err;
	unsigned long vlan_err;
	unsigned long shared_packets;
	unsigned long runt_packets;
	unsigned long realloc_packets;
	unsigned long gw_tx_packets;
	unsigned long gw_tx_bytes;
};

#define VNIC_STATS_DO_ADD(var, val) ((var) += (unsigned long)(val))
#define VNIC_STATS_DO_INC(var)      (++(var))
#ifdef VNIC_EXTRA_STATS /* for performance */
#define VNIC_STATS_ADD(var, val)    ((var) += (unsigned long)(val))
#define VNIC_STATS_INC(var)         (++(var))
#else
#define VNIC_STATS_ADD(var, val)    do { } while (0)
#define VNIC_STATS_INC(var)         do { } while (0)
#endif

enum {
	MCAST_ATTACHED,
	MCAST_JOINED,
	MCAST_JOIN_STARTED,
	MCAST_JOIN_RUNNING,
	MCAST_ATTACH_RUNNING,
};

struct vnic_port_mcast {
	struct rb_node rb_node;
	struct list_head list;
	union ib_gid gid;
	struct vnic_port *port;
	struct completion leave_complete;
	struct completion join_event_complete;
	struct ib_sa_multicast *sa_mcast;
	struct ib_sa_mcmember_rec rec;

	atomic_t ref_cnt;
	struct delayed_work join_task;
	struct work_struct leave_task;
	unsigned long join_task_cnt;
	long int state;
	spinlock_t lock;
	u8 join_state;
	/* IN */
	unsigned long backoff;
	unsigned long backoff_init;
	unsigned long backoff_factor;
	unsigned long retry;
	u16 pkey;
	u32 qkey;
	u8 create;
};

struct vnic_mcast {
	struct vnic_port_mcast *port_mcaste;
	u32 qkey;
	u16 pkey;
	struct ib_qp *qp;
	struct vnic_port *port;
	struct ib_ah *ah;
	struct completion attach_complete;
	struct delayed_work attach_task;
	struct delayed_work detach_task;
	unsigned long attach_task_cnt;
	struct rb_node rb_node;
	struct list_head list; /* used when delete all */
	/* IN */
	u8 mac[ETH_ALEN];
	union ib_gid gid;
	union ib_gid port_gid;
	unsigned long backoff;
	unsigned long backoff_init;
	unsigned backoff_factor;
	unsigned long retry;
	unsigned long state;
	u8 blocking;
	void *attach_cb_ctx;
	void *detach_cb_ctx;
	void (*attach_cb) (struct vnic_mcast *mcaste, void *ctx);
	void (*detach_cb) (struct vnic_mcast *mcaste, void *ctx);
	u8 create;
	u8 join_state;
	void *priv_data;
	spinlock_t lock;
	int attach_bit_nr;
	unsigned long *req_attach;
	unsigned long *cur_attached;
	int sender_only;
};

struct vnic_mac {
	struct rb_node rb_node;	/* list or RB tree */
	struct list_head list;
	u16 vnic_id;		/* needed for vnic child removal */
	u8 mac[ETH_ALEN];	/* key */
	unsigned long created;
	unsigned long last_tx; // use jiffies_to_timeval
};

struct lag_properties {
	u16 	hash_mask;
	u8 	weights_policy;
	u8 	ca;		/* conjestion aware */
	u8 	ca_thresh;
};

struct vnic_neigh {
	struct neighbour *neighbour;
	struct ib_ah *ah;
	struct vnic_login *login;
	struct rb_node rb_node;
	struct ib_sa_query *pquery;
	struct completion query_comp;
	int query_id;
	struct sk_buff_head pkt_queue;
	struct delayed_work destroy_task;
	u8 valid;
	u32 qpn;
	u16 lid;
	u8 sl; /* only for debug */
	u8 mac[ETH_ALEN];
	u8 rss;
	u16 info;
};

enum lag_gw_state {
	GW_MEMBER_INFO_CREATED 	= 1 << 0,
	GW_MEMBER_INFO_EPORT_UP	= 1 << 1,
	GW_MEMBER_INFO_MCAST	= 1 << 2,
	GW_MEMBER_INFO_MAPPED	= 1 << 3,
};

struct vnic_gw_info {
	enum lag_gw_state info;
	int member_id;
	u16 gw_id;
	struct vnic_neigh neigh;
};

struct vnic_sysfs_attr {
	void *ctx;
	struct kobject *kobj;
	unsigned long data;
	char name[VNIC_SYSFS_FLEN];
	struct module_attribute dentry;
	struct device *dev;
};

enum gw_ext_lag_hash_policy {
	GW_LAG_HASH_DMAC 	= 1 << 0,
	GW_LAG_HASH_SMAC 	= 1 << 1,
	GW_LAG_HASH_TPID 	= 1 << 2,	/* ethertype */
	GW_LAG_HASH_VID 	= 1 << 3,
	GW_LAG_HASH_SIP 	= 1 << 4,
	GW_LAG_HASH_DIP 	= 1 << 5,
	GW_LAG_HASH_IP_NEXT 	= 1 << 6,
	GW_LAG_HASH_SPORT 	= 1 << 7,
	GW_LAG_HASH_DPORT 	= 1 << 8,
	GW_LAG_LAYER_2_3	= 0x1f0
};

struct vnic_tx_buf {
	struct sk_buff *skb;
	u64 mapping[VNIC_MAX_TX_FRAGS];
	u8 ip_off;
	u8 ip6_off;
	u8 tcp_off;
	u8 udp_off;
	void *phead;
	int hlen;
};

enum {
#if 1
	FRAG_SZ0 = 536 - NET_IP_ALIGN, /* so 1500 mtu fits in first 2 frags */
	FRAG_SZ1 = 1024,
	FRAG_SZ2 = 2048,
	FRAG_SZ3 = 4096 - FRAG_SZ2 - FRAG_SZ1 - FRAG_SZ0
#else
	FRAG_SZ0 = 512 - NET_IP_ALIGN,
	FRAG_SZ1 = 1024,
	FRAG_SZ2 = 2048,
	FRAG_SZ3 = 4096 << VNIC_ALLOC_ORDER
#endif
};

struct vnic_frag_info {
	u16 frag_size;
	u16 frag_prefix_size;
	u16 frag_stride;
	u16 frag_align;
	u16 last_offset;
};

struct vnic_rx_alloc {
	struct page *page;
	u16 offset;
};

struct vnic_frag_data {
	struct skb_frag_struct frags[VNIC_MAX_RX_FRAGS];
	u64 dma_addr[VNIC_MAX_RX_FRAGS];
	struct sk_buff *skb; /* used only for linear buffers mode */
};

struct vnic_rx_ring {
	struct vnic_port *port;
	int index;
	struct vnic_rx_alloc page_alloc[VNIC_MAX_RX_FRAGS];

	u32 size; /* number of RX descs */
	spinlock_t lock;
	struct vnic_frag_data *rx_info;

	struct vnic_frag_info frag_info[VNIC_MAX_RX_FRAGS];
	u32 rx_skb_size;
	u16 log_rx_info;
	u16 num_frags;

	struct ib_recv_wr wr;
	struct ib_sge sge[VNIC_MAX_RX_FRAGS];

	struct ib_srq *srq;
	struct net_device_stats stats;
};

/* vnic states
   these vlaues can be used only in struct fip_vnic_data.login_state */
enum {
	VNIC_STATE_LOGIN_OFF = 0,
	VNIC_STATE_LOGIN_PRECREATE_1,
	VNIC_STATE_LOGIN_PRECREATE_2,
	VNIC_STATE_LOGIN_CREATE_1,
	VNIC_STATE_LOGIN_CREATE_2,
	VNIC_STATE_LOGIN_BCAST_ATTACH = 31
};

/* netdevice open state, depeneds on calls to open/stop
   these vlaues can be used only in struct vnic_login.netdev_state */
enum {
	VNIC_STATE_NETDEV_OFF = 0,
	VNIC_STATE_NETDEV_OPEN_REQ,
	VNIC_STATE_NETDEV_OPEN,
	VNIC_STATE_NETDEV_CARRIER_ON,
	VNIC_STATE_NETDEV_NO_TX_ENABLE = 31
};

struct vnic_rx_res {
	struct vnic_login *login;
	struct ib_cq *cq;
	struct net_lro_mgr lro;
        struct net_lro_desc lro_desc[VNIC_MAX_LRO_DESCS];
	struct ib_wc recv_wc[VNIC_MAX_RX_CQE];
	int index;
	int stopped;
#ifndef _BP_NAPI_POLL
	struct napi_struct napi;
#else
	struct net_device *poll_dev;
#endif
};

struct vnic_tx_res {
	struct vnic_tx_buf *tx_ring;
	struct ib_sge tx_sge[VNIC_MAX_TX_FRAGS];
	struct ib_wc send_wc[VNIC_MAX_TX_CQE];
	struct ib_send_wr tx_wr;
	struct vnic_login *login;
	struct ib_cq *cq;
	unsigned tx_head;
	unsigned tx_tail;
	unsigned tx_outstanding;
	unsigned tx_stopped_cnt;
	struct net_device_stats stats;
	struct ib_ah_attr mcast_av;
	u8 lso_hdr[VNIC_MAX_PAYLOAD_SIZE];
	int index;
	int stopped;
	spinlock_t lock;
};

#ifdef VNIC_PROFILLNG
#define VNIC_PROFILLNG_SKB_MAX 100
struct vnic_prof_skb_entry {
	struct sk_buff skb;
	struct timespec tstamp;
	unsigned long jiffies;
	int cnt;
	u8 nr_frags;
};
#endif

struct vnic_qp_res {
	struct vnic_login *login;
	struct ib_qp *qp;
	struct completion last_wqe_complete;
	int tx_index;
	int rx_index;
};

/*
 * Wrapper struct for vnic_login, used as netdev private data.
 * some kernels (such as 2.6.18-194.26.1) doesn't allow private
 * data struct longer than 64KB (NETDEV_PRIV_LEN_MAX).
 * we allocate the private data separately to work-around this limit.
 */
struct vnic_login_info {
	struct vnic_login *login;
};

struct vnic_login {
	spinlock_t lock;
	spinlock_t stats_lock;
	struct net_device *dev;
	struct ethtool_drvinfo drvinfo;
	struct vnic_port *port;
	char desc[VNIC_DESC_LEN];
	struct fip_vnic_data *fip_vnic;	/* for ethtool/sysfs*/
	int queue_stopped;
	unsigned long netdev_state;
	char name[VNIC_NAME_LEN];
	char vnic_name[VNIC_NAME_LEN];
	char vendor_id[VNIC_VENDOR_LEN];
	struct vnic_neigh *gw_neigh;
	struct vnic_gw_info lag_gw_neigh[MAX_LAG_MEMBERS];
	struct 	lag_properties lag_prop;
	int is_lag;
	int lag_gw_map[LAG_MAP_TABLE_SIZE];
	int lag_member_count;
	int lag_member_active_count;
	union ib_gid gw_mgid;
	int promisc;
	union ib_gid gid;
	__be16 vid;
	u8 vlan_used;
	u32 qkey;
	u16 pkey;
	u16 pkey_index;
	u64 gw_guid;
	u8 mgid_prefix[VNIC_MGID_PREFIX_LEN];
	u8 n_mac_mcgid;
	u8 sl;
	u16 gw_port_id;
	u16 vnic_id;
	unsigned int max_mtu;
	int zlen;
	int cnt;
	unsigned qps_num;
	u32 qp_base_num;
	u8 dev_addr[ETH_ALEN];
	u8 all_vlan_gw;

	/* statistics */
	struct net_device_stats stats;
	struct vnic_port_stats port_stats;

	/* tasks */
	struct work_struct mcast_restart;
	struct delayed_work stats_task;
	struct delayed_work mcast_task;
	struct delayed_work restart_task;
	struct mutex moder_lock;
	struct mutex state_lock;

	/* data structures */
	struct workqueue_struct *neigh_wq;
	struct rb_root neigh_tree;
	struct rb_root mac_tree;
	atomic_t vnic_child_cnt;
	rwlock_t mac_rwlock;
	struct mcast_root mcast_tree;
	struct vnic_sysfs_attr dentries[VNIC_MAX_DENTRIES];
	struct list_head list;

	/* QP resources */
	struct vnic_qp_res qp_res[VNIC_MAX_NUM_CPUS];

	/* RX resouces */
	struct vnic_rx_res rx_res[VNIC_MAX_NUM_CPUS];
	struct ib_recv_wr rx_wr;
	u32 lro_num;
	unsigned lro_mng_num;
	int rx_csum;
	unsigned napi_num;
	unsigned rx_rings_num;

	/* TX resources */
	struct vnic_tx_res tx_res[VNIC_MAX_NUM_CPUS];
	unsigned tx_rings_num;
	unsigned real_tx_rings_num;
	unsigned ndo_tx_rings_num;
	u8 *pad_va;
	u64 pad_dma;

	/* for profiling */
#ifdef VNIC_PROFILLNG
	struct vnic_prof_skb_entry prof_arr[VNIC_PROFILLNG_SKB_MAX];
	int prof_arr_it;
#endif
	/* interrupt coalecence */
	u16 rx_usecs;
	u16 rx_frames;
	u32 pkt_rate_low;
	u16 rx_usecs_low;
	u32 pkt_rate_high;
	u16 rx_usecs_high;
	u16 sample_interval;
	u16 adaptive_rx_coal;
	unsigned long last_moder_packets;
	unsigned long last_moder_tx_packets;
	unsigned long last_moder_bytes;
	unsigned long last_moder_jiffies;
	unsigned long last_moder_time;
	u16 tx_usecs;
	u16 tx_frames;
	u8 shared_vnic;
	u8 shared_mac[ETH_ALEN];
};

struct eoibhdr {
	__u8 encap_data;
	__u8 seg_off;
	__be16 seg_id;
};

struct vnic_ib_dev {
	char name[VNIC_DESC_LEN];
	struct mutex mlock;
	struct list_head list;
	struct list_head port_list;
	struct ib_device *ca;
	struct mlx4_ib_dev *mdev;
	struct ib_device_attr attr;
	char fw_ver_str[VNIC_FW_STR_MAX];
};

struct fip_ring_entry {
	void *mem;
	u64 bus_addr;
	int length;
	int entry_posted;
};

struct fip_ring {
	int size;
	struct fip_ring_entry *ring;
	unsigned long head;
	unsigned long tail;
	spinlock_t ring_lock;
	spinlock_t head_tail_lock;
};

enum fip_discover_state {
	FIP_DISCOVER_OFF,
	FIP_DISCOVER_INIT,
	FIP_DISCOVER_SOLICIT,
	FIP_DISCOVER_CLEAR
};

#define MAX_INPUT_LEN 64
#define MAX_INPUT_ARG 12
struct fip_hadmin_cmd {
	u8 c_name    [MAX_INPUT_LEN];
	u8 c_mac     [MAX_INPUT_LEN];
	u8 c_vnic_id [MAX_INPUT_LEN];
	u8 c_vid     [MAX_INPUT_LEN];
	u8 c_bxname  [MAX_INPUT_LEN];
	u8 c_bxguid  [MAX_INPUT_LEN];
	u8 c_eport   [MAX_INPUT_LEN];
	u8 c_ipv4    [MAX_INPUT_LEN];
	u8 c_ipv6    [MAX_INPUT_LEN];
	u8 c_emac    [MAX_INPUT_LEN];
	u8 c_pkey    [MAX_INPUT_LEN];
	u8 c_parent  [MAX_INPUT_LEN];
};

struct fip_hadmin_cache {
	struct fip_hadmin_cmd cmd;
	u8 system_guid[GUID_LEN];
	u8 system_name[VNIC_SYSTEM_NAME_LEN];
	u8 eport_name[VNIC_GW_PORT_NAME_LEN];
	u8 mac[ETH_ALEN];
	u16 vnic_id;
	u16 gw_port_id;
	u16 vlan;
	u8 vlan_used;
	u8 all_vlan_gw;
	u8 interface_name[VNIC_NAME_LEN];
	u8 parent_name[VNIC_NAME_LEN];
	int parent_used;
	int remove;
	struct list_head next;
	u32 qp_base_num;
	u8 shared_vnic_ip[IPV4_LEN];
	u8 shared_vnic_mac[ETH_ALEN];
};

struct pkt_rcv_list {
	struct list_head list;
	spinlock_t lock;
};

struct fip_discover {
	char name[VNIC_NAME_LEN];
	struct vnic_port *port;
	struct list_head discover_list;
	spinlock_t lock;
	struct list_head gw_list;
	struct rw_semaphore l_rwsem;	/* gw list rw semaphore **/
	int hadmin_update;
	struct list_head hadmin_cache;
	enum fip_discover_state state;
	int flush;
	struct completion flush_complete;
	struct ib_cq *cq;
	struct ib_qp *qp;
	struct fip_ring rx_ring;
	struct fip_ring tx_ring;
	struct mcast_root mcast_tree;
	struct delayed_work fsm_task;
	struct delayed_work cleanup_task;
	struct delayed_work hadmin_update_task;
	struct work_struct pkt_rcv_task_bh;
	struct pkt_rcv_list rcv_list;

	int mcast_dest_mask;
	unsigned long discover_mcast_attached_jiffies;
	unsigned long discover_mcast_detached_jiffies;
	unsigned long discover_mcast_state;
	u16 pkey;
	u16 pkey_index;
	unsigned long   req_attach;
	unsigned long   cur_attached;
	unsigned new_prot_gws;
	unsigned old_prot_gws;
};

struct fip_root {
	struct list_head discover_list;
};

struct port_fs_dentry {
	struct module_attribute fs_entry;
	struct vnic_port *port;
};

struct vnic_port {
	char name[VNIC_DESC_LEN];
	u8 num;
	int rx_rings_num;
	int tx_rings_num;
	struct vnic_ib_dev *dev;
	struct mcast_root mcast_tree;
	struct list_head list;
	struct list_head login_list;
	struct delayed_work event_task;
	struct delayed_work event_task_light;
	struct delayed_work discover_restart_task;
	struct ib_event_handler event_handler;
	struct ib_port_attr attr;
	union ib_gid gid;
	int rate;
	u8 rate_enum;
	atomic_t vnic_child_ids;

	/* IB resources per port */
	struct vnic_rx_ring *rx_ring[VNIC_MAX_NUM_CPUS];
	struct ib_pd *pd;
	struct ib_mr *mr;

	/* for FIP */
	struct mutex mlock;
	struct mutex start_stop_lock;
	u16 pkey_index;
	u16 pkey;
	int max_mtu_enum;
	struct fip_root fip;
	struct vnic_sysfs_attr dentries[VNIC_MAX_DENTRIES];
};

enum fip_vnic_state {
	FIP_VNIC_CLOSED		= 0,
	FIP_VNIC_HADMIN_IDLE	= 1<<0,
	FIP_VNIC_LOGIN		= 1<<1,
	FIP_VNIC_WAIT_4_ACK	= 1<<2,
	FIP_VNIC_RINGS_INIT	= 1<<3, /* temporary, create rings */
	FIP_VNIC_MCAST_INIT	= 1<<4, /* temporary, start mcast attach */
	FIP_VNIC_MCAST_INIT_DONE= 1<<5, /* wait for mcast cb */
	FIP_VNIC_VHUB_INIT	= 1<<6,
	FIP_VNIC_VHUB_INIT_DONE	= 1<<7, /* wait for vhub table */
	FIP_VNIC_VHUB_DONE	= 1<<8,
	FIP_VNIC_VHUB_WRITE	= 1<<9,
	FIP_VNIC_CONNECTED	= 1<<10
};

enum vhub_table_state {
	VHUB_TBL_INIT,
	VHUB_TBL_UP2DATE,
	VHUB_TBL_UPDATED
};

struct vhub_elist {
	u32 tusn;
	int count;
	int total_count;
	struct list_head vnic_list;	/* chain vnics */
};

struct vnic_table_entry {
	u32 qpn;
	u16 lid;
	u8 mac[ETH_ALEN];
	u8 sl;

	struct list_head list;
	u8 rss;
	u8 valid;
};

struct vhub_table {
	enum vhub_table_state state;
	u32 checksum;
	u32 tusn;
	struct vhub_elist main_list;
	struct vhub_elist update_list;
};

struct fip_shared_vnic_data {
	u8 ip[IPV4_LEN];
	u8 emac[ETH_ALEN];
	u8 enabled;
	u8 arp_proxy;
};

struct lag_member {
	u32	qpn;
	u8	sl;
	u16	gw_port_id;
	u16	lid;
	u8	guid[GUID_LEN];
	u8	eport_state;
	u8	weight;
	u8	link_utilization;
};

struct lag_members {
	int	num;
	long	used_bitmask;
	struct 	lag_properties prop;
	struct 	lag_member memb[MAX_LAG_MEMBERS];
};

struct fip_login_data {
	u32 qpn;
	u32 ctl_qpn;
	u16 port_id;		/* must always be uptodate */
	u16 lid;		/* must always be uptodate */
	u16 vlan;
	u16 pkey;
	u16 pkey_index;
	u16 vnic_id;		/* must always be uptodate */
	u32 vhub_id;
	u16 mtu;

	u8 sl;			/* service level -- 4 bits */
	u8 guid[GUID_LEN];
	u8 mac[ETH_ALEN];
	u8 mgid_prefix[VNIC_MGID_PREFIX_LEN];
	u8 vnic_name[VNIC_NAME_LEN];
	u8 vendor_id[VNIC_VENDOR_LEN];
	u8 n_mac_mcgid;
	u8 n_rss_mgid;
	u8 syndrome;		/* must always be uptodate */

	u8 vp;			/* 1 bit: do we use vlan */
	u8 all_vlan_gw;		/* 1 bit.
				   is promisc vlan supported on this vnic */
	struct lag_members lagm;
};

enum fip_flush {
	FIP_NO_FLUSH,
	FIP_PARTIAL_FLUSH,	/* use this for events caused by vnic/gw logic will */
	FIP_FULL_FLUSH		/* use this for events caused by unload, host admin destroy */
};

struct fip_vnic_send_info {
	u32 gw_qpn;
	u32 qkey;
	u16 gw_lid;
	u8 gw_sl;
};

/*
 * This struct holds informative info about the GW that can change without
 * implecations on GW or vnic logic (only reported to user)
 */
struct fip_gw_volatile_info {
	u8 system_guid[GUID_LEN];
	u8 system_name[VNIC_SYSTEM_NAME_LEN+1];
	u8 gw_port_name[VNIC_GW_PORT_NAME_LEN+1];
};

struct fip_vnic_data {
	char name[VNIC_NAME_LEN];
	enum fip_vnic_state state;
	enum fip_flush flush;
	spinlock_t lock;
	spinlock_t ka_lock;
	struct vnic_sysfs_attr dentry;
	unsigned long login_state;

	/* data structures maintenance */
	struct fip_gw_data *gw;
	struct vnic_port *port;
	struct list_head gw_vnics;
	struct vhub_table vhub_table;

	/* execution maintenance */
	unsigned long update_jiffs;
	unsigned long keep_alive_jiffs;
	unsigned long detached_ka_jiffs;
	unsigned long vnic_mcaste_state;
	struct delayed_work vnic_task;
	struct hrtimer keepalive_timer;
	struct list_head timer;
	struct delayed_work vnic_gw_alive_task;
	struct work_struct vnic_pkt_rcv_task_bh;
	struct work_struct vnic_login_destroy_task;
	struct work_struct vnic_login_create_task;
	struct pkt_rcv_list vnic_rcv_list;
	struct fip_vnic_send_info gw_address;

	/* vnic driver API */
	struct vnic_login *login;
	unsigned long login_status;
	int qps_num;
	u32 qp_base_num;
	int parent_used;
	u8 parent_name[VNIC_NAME_LEN];

	/* rx + tx data structures */
	struct ib_cq *cq;
	struct ib_qp *qp;
	struct fip_ring rx_ring;
	struct fip_ring tx_ring;
	struct ib_ah *ah;

	/* data domain */
	union ib_gid mgid;

	/* vHub context update mcast groups */
	struct mcast_root mcast_tree;
	struct fip_login_data login_data;
	struct fip_shared_vnic_data shared_vnic;
	u16 mlid;
	/* u16 pkey_index; not used for now */

	u16 vnic_id; /* unique id for GW */
	u16 vlan;
	u8 vlan_used;
	u8 all_vlan_gw;
	u16 pkey;
	u16 pkey_index;
	u8 hadmined; /* todo, use the state for this */
	u8 interface_name[VNIC_NAME_LEN];
	u8 mac_cache[ETH_ALEN];
	atomic_t eport_state;
	unsigned long last_send_jiffs;
	int retry_count;
	int synd_backlog;
	struct fip_hadmin_cmd cmd;
	struct fip_gw_volatile_info gw_info;
	struct lag_members lm;
	unsigned long	req_attach;
	unsigned long	cur_attached;
	union ib_gid	ka_mcast_gid;
};

enum vhub_mgid_type {
	VHUB_MGID_DATA = 0,
	VHUB_MGID_UPDATE = 2,
	VHUB_MGID_TABLE = 3,
	VHUB_MGID_KA = 5,
};

enum fip_all_mgids {
	FIP_MCAST_DISCOVER,
	FIP_MCAST_SOLICIT,
	FIP_MCAST_VHUB_DATA,
	FIP_MCAST_VHUB_UPDATE,
	FIP_MCAST_TABLE,
	FIP_MCAST_VHUB_KA,
};

union vhub_mgid {
	struct mgid {
		u8 mgid_prefix[VNIC_MGID_PREFIX_LEN];
		u8 type;
		u8 dmac[ETH_ALEN];
		u8 rss_hash;
		u8 vhub_id[3];
	} mgid;
	union ib_gid ib_gid;
};

void vnic_carrier_update(struct vnic_login *login);
int vnic_param_check(void);

/* mac table funcs */
void vnic_learn_mac(struct net_device *dev, u8 *mac, int remove);
void vnic_child_flush(struct vnic_login *login, int all);
int vnic_child_update(struct vnic_login *login, u8 *mac, int remove);
int vnic_mace_update(struct vnic_login *login, u8 *mac, u16 vnic_id, int remove);
int vnic_parent_update(struct vnic_port *port, char *name, u16 vnic_id,
		       u8 *mac, u32 *qp_base_num_ptr, char *parent_name,
		       int remove);

/* mcast funcs */
int vnic_mcast_init(void);
void vnic_mcast_cleanup(void);

/*
 * A helper function to prevent code duplication. Receives a multicast mac
 * and a gw_id and attaches it (join + attach). The function also receives
 * a default_mcaste (used for the MGID over default MLID hack and a user list.
 * Returns 0 on success and non 0 on failure.
 *
 * in: mmac - to be used in creation MGID address
 * in: default_mcaste - mcaste entry of the default MGID. Can be NULL
 * in: private_data - A user pointer that can be used to identify owner
 * in: gw_id - to be used in creation MGID address
 */
int _vnic_mcast_attach_mgid(struct vnic_login *login,
			   char *mmac,
			   struct vnic_mcast *default_mcaste,
			   void *private_data,
			   u16 gw_id);

struct vnic_mcast *vnic_mcast_alloc(struct vnic_port *port,
				    unsigned long *req_attach,
				    unsigned long *cur_attach);
/*
 * A helper function to prevent code duplication. Fills vnic_mcast struct with
 * common values.
 *
 * in: mcaste - mcaste to fill
 * in: gw_id - to be used in creation MGID address
 * in: mac - to be used in creation MGID address
 * in: rss_hash - to be used in creation MGID address (ususally 0)
 * in: create - value of create field in mcaste
 */
void __vnic_mcaste_fill(struct vnic_login *login, struct vnic_mcast *mcaste,
			u16 gw_id, const u8 *mac, u8 rss_hash, int create);

void vnic_mcast_dealloc(struct vnic_mcast *mcaste);

int vnic_mcast_attach(struct mcast_root *mcast_tree, struct vnic_mcast *mcaste);
int vnic_mcast_detach(struct mcast_root *mcast_tree, struct vnic_mcast *mcaste);

/*
 * This function grabs the mcast_tree->mcast_rb_lock
*/
int vnic_mcast_add(struct mcast_root *mcast_tree,
		   struct vnic_mcast *mcaste);
int vnic_mcast_del_all(struct mcast_root *mcast_tree);
int vnic_mcast_del_user(struct mcast_root *mcast_tree, void *owner);

void vnic_tree_mcast_detach(struct mcast_root *mcast_tree);
void vnic_tree_mcast_attach(struct mcast_root *mcast_tree);

/*void vnic_port_mcast_del_all(struct mcast_root *port); */
static inline void vnic_mcast_root_init(struct mcast_root *mcast_tree)
{
	spin_lock_init(&mcast_tree->mcast_rb_lock);
	INIT_LIST_HEAD(&mcast_tree->reattach_list);
}

/* port funcs */
int vnic_ports_init(void);
void vnic_ports_cleanup(void);

/*
 * The caller must hold the mcast_tree->mcast_rb_lock lock before calling
*/
void vnic_mcast_del(struct mcast_root *mcast_tree, struct vnic_mcast *mcaste);
struct vnic_mcast *vnic_mcast_search(struct mcast_root *mcast_tree,
				     union ib_gid *gid);
void port_fip_discover_restart(struct work_struct *work);
int vnic_port_fip_init(struct vnic_port *port);
void vnic_port_fip_cleanup(struct vnic_port *port, int lock);

/* others */
void fip_refresh_mcasts(struct fip_discover *discover);
void vnic_login_refresh_mcasts(struct vnic_port *port);

/* There are 2 different create flows, for host admin and net admin.
 * In net admin we always create the vnic after connected with GW but we do not
 * yet know the vnic details (mac, vlan etc). We know the ring paramets and 
 * will need to create the RX/TX rings (before login).
 * To accomplish this we call vnic_login_pre_create_1, vnic_login_pre_create_2
 * and after login ACK we will call vnic_login_register_netdev and vnic_login_complete_ack.
 * In Host admin, we know the vnic info but not the GW info when we create the
 * vnic. So we call vnic_login_pre_create_1 and vnic_login_register_netdev, after
 * getting the login ACK we will call vnic_login_pre_create_2, vnic_login_complete_ack.
 */
int vnic_login_register_netdev(struct fip_vnic_data *vnic,
			       const char *mac,
			       const char *name);
int vnic_login_complete_ack(struct fip_vnic_data *vnic,
			    struct fip_login_data *login_data,
			    struct fip_shared_vnic_data *shared_vnic);
int vnic_login_pre_create_1(struct vnic_port *port,
			    struct fip_vnic_data *vnic);
int vnic_login_pre_create_2(struct fip_vnic_data *vnic, int qps_num, int is_lag);

/*
 * When destroying login, call to stop login wq tasks. do not call from
 * login_wq context.
*/
void vnic_login_destroy_stop_wq(struct fip_vnic_data *vnic, enum fip_flush flush);
/*
 * When destroy login data struct. Assumes all login wq tasks are stopped.
 * Can be called from any context, might block for a few secs.
*/
void vnic_login_destroy_wq_stopped(struct fip_vnic_data *vnic, enum fip_flush flush);

/*
 * Destroy a login datastructure.
 * This function can not be called from login_wq context. If you need to run
 * from login_wq use the split function vnic_login_destroy_stop_wq/wq_stopped
 * instead.
 */
static inline
void vnic_login_destroy(struct fip_vnic_data *vnic, enum fip_flush flush)
{
	vnic_login_destroy_stop_wq(vnic, flush);
	vnic_login_destroy_wq_stopped(vnic, flush);
}

/* add / remove members eports from LAG GW */
void vnic_member_prop(struct vnic_login *login, struct lag_properties *prop);
int vnic_member_add(struct vnic_login *login, int member_id,
		    struct lag_member *emember);
int vnic_member_remove(struct vnic_login *login, int member_id);
int vnic_member_modify(struct vnic_login *login, int member_id,
		       struct lag_member *emember);
void vnic_member_remove_all(struct vnic_login *login);

int vnic_vhube_add(struct fip_vnic_data *vnic, struct vnic_table_entry *vhube);
void vnic_vhube_flush(struct fip_vnic_data *vnic);
void vnic_vhube_del(struct fip_vnic_data *vnic, u8 *mac);
int vnic_neighe_path_query(struct vnic_neigh *neighe);

void vhub_mgid_create(const char *mgid_prefix,
		      const char *mmac, /* mcast mac for bcast 0xFF.. */
		      u64 n_mac,	/* bits to take from mmac */
		      u32 vhub_id,
		      enum vhub_mgid_type type,
		      u8 rss_hash,
		      union vhub_mgid *mgid);
/*
 * read the state of the gw eport. Can be called from any context.
*/
int fip_vnic_get_eport_state(struct fip_vnic_data *vnic);
/*
 * get GW info funcs.
*/
int fip_vnic_get_eport_name(struct fip_vnic_data *vnic, char *buff);
int fip_vnic_get_bx_name(struct fip_vnic_data *vnic, char *buff);
int fip_vnic_get_bx_guid(struct fip_vnic_data *vnic, char *buff);
u8 fip_vnic_get_bx_sl(struct fip_vnic_data *vnic);
int fip_vnic_get_gw_type(struct fip_vnic_data *vnic);
int fip_vnic_get_lag_eports(struct fip_vnic_data *vnic, char *buf);
int fip_vnic_get_all_vlan_mode(struct fip_vnic_data *vnic, char *buff);


/*
 * return short format string of GW info. can be called from any context.
*/
int fip_vnic_get_short_gw_info(struct fip_vnic_data *vnic, char *buff);

void vnic_data_cleanup(void);

/*
 * This function is called from the sysfs update callback function. 
 * it parses the request and adds the request to a list. It then queues a
 * work request to process the list from the fip_wq context.  
*/
int fip_hadmin_sysfs_update(struct vnic_port *port,
			    const char *buffer, int count, int remove);
int fip_gw_sysfs_show(struct vnic_port *port, char *buffer);
int vnic_login_cmd_set(char *buf, struct fip_hadmin_cmd *cmd);
void vnic_login_cmd_init(struct fip_hadmin_cmd *cmd);

int fip_hadmin_vnic_refresh(struct fip_vnic_data *vnic, struct fip_vnic_send_info *gw_address);
void fip_vnic_set_gw_param(struct fip_vnic_data *vnic, struct fip_vnic_send_info *gw_address);
void fip_vnic_create_gw_param(struct fip_vnic_send_info *gw_address, u32 gw_qpn,
			      u32 qkey, u16 gw_lid, u8 gw_sl);

int fip_vnic_hadmin_init(struct vnic_port *port, struct fip_vnic_data *vnic);

int port_fs_init(struct vnic_port *port);
void port_fs_exit(struct vnic_port *port);

int vnic_port_query(struct vnic_port *port);

#endif /* VNIC_H */
