/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell OcteonTx2 RFOE Ethernet Driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef OTX2_RFOE_H
#define OTX2_RFOE_H

#include <linux/cdev.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/ethtool.h>
#include <linux/net_tstamp.h>

#include "otx2_bphy_hw.h"
#include "rfoe_bphy_netdev_comm_if.h"

#define DEVICE_NAME		"otx2_rfoe"
#define DRV_NAME		"octeontx2-rfoe"
#define DRV_STRING		"Marvell OcteonTX2 BPHY RFOE Ethernet Driver"

/* char device ioctl numbers */
#define OTX2_RFOE_IOCTL_BASE		0xCC	/* Temporary */
#define OTX2_RFOE_IOCTL_ODP_INIT	_IOR(OTX2_RFOE_IOCTL_BASE, 0x00, int)
#define OTX2_RFOE_IOCTL_ODP_INTF_CFG	_IOR(OTX2_RFOE_IOCTL_BASE, 0x01, int)
#define OTX2_RFOE_IOCTL_ODP_DEINIT      _IO(OTX2_RFOE_IOCTL_BASE, 0x02)

//#define ASIM		/* ASIM environment */

/* CGX register offsets */
#define OTX2_CGX_REG_BASE	0x87E0E0000000
#define OTX2_CGX_REG_LEN	0x34F0000

/* GPINT(1) definitions */
#define RX_PTP_INTR			BIT(2) /* PTP packet intr */
#define RX_ECPRI_INTR			BIT(1) /* ECPRI packet intr */
#define RX_GEN_INTR			BIT(0) /* GENERIC packet intr */
#define RFOE_RX_INTR_EN			(RX_PTP_INTR	| \
					 RX_ECPRI_INTR	| \
					 RX_GEN_INTR)
#define RFOE_RX_INTR_SHIFT(a)		(32 - ((a) + 1) * 3)
#define RFOE_RX_INTR_MASK(a)		(RFOE_RX_INTR_EN << \
					 RFOE_RX_INTR_SHIFT(a))
#define RFOE_TX_PTP_INTR_MASK(a, b)	(1UL << ((a) * 4 + (b)))
#define INTR_TO_PKT_TYPE(a)		(PACKET_TYPE_OTHER - (a))
#define PKT_TYPE_TO_INTR(a)		(1UL << (PACKET_TYPE_OTHER - (a)))

/* intf definitions */
#define RFOE_NUM_INST		3
#define LMAC_PER_RFOE		4
#define RFOE_MAX_INTF		10	/* 2 rfoe x 4 lmac + 1 rfoe x 2 lmac */

/* eCPRI ethertype */
#define ETH_P_ECPRI	0xAEFE

/* max tx job entries */
#define MAX_TX_JOB_ENTRIES 64

#define OTX2_RFOE_MSG_DEFAULT	(NETIF_MSG_DRV)

/* tx job configuration */
enum tx_packet_type {
	TX_PACKET_TYPE_OTH	= 0,
	TX_PACKET_TYPE_PTP	= 1,
	TX_PACKET_TYPE_ECPRI	= 2,
	TX_PACKET_TYPE_MAX,
};

enum state {
	PTP_TX_IN_PROGRESS = 1,
};

/* char driver private data */
struct otx2_rfoe_cdev_priv {
	struct device			*dev;
	struct cdev			cdev;
	dev_t				devt;
	int				is_open;
	int				odp_intf_cfg;
	int				irq;
	struct mutex			mutex_lock;	/* mutex */
	spinlock_t			lock;		/* irq lock */
};

/* global driver context */
struct otx2_rfoe_drv_ctx {
	u8				rfoe_num;
	u8				lmac_id;
	int				valid;
	struct net_device               *netdev;
	struct rx_ft_cfg		*ft_cfg;
	int				tx_gpint_bit;
};

/* rx flow table configuration */
struct rx_ft_cfg {
	enum bphy_netdev_packet_type	pkt_type;	/* pkt_type for psw */
	enum bphy_netdev_rx_gpint	gp_int_num;
	u16				flow_id;	/* flow id */
	u16				mbt_idx;	/* mbt index */
	u16				buf_size;	/* mbt buf size */
	u16				num_bufs;	/* mbt num bufs */
	u64				mbt_iova_addr;
	void __iomem			*mbt_virt_addr;
	u16				jdt_idx;	/* jdt index */
	u8				jd_size;	/* jd size */
	u16				num_jd;		/* num jd's */
	u64				jdt_iova_addr;
	void __iomem			*jdt_virt_addr;
	u8				jd_rd_offset;	/* jd rd offset */
	u8				pkt_offset;
	int				mbt_last_idx;	/* sw head */
	struct napi_struct		napi;
	struct otx2_rfoe_ndev_priv	*priv;
};

/* tx job entry */
struct tx_job_entry {
	u64			job_cmd_lo;
	u64			job_cmd_hi;
	u64			jd_iova_addr;
	u64			rd_dma_iova_addr;
	void __iomem		*jd_ptr;
	void __iomem		*rd_dma_ptr;
	void __iomem		*jd_cfg_ptr;
};

/* tx job queue */
struct tx_job_queue_cfg {
	u8				psm_queue_id;
	struct tx_job_entry		job_entries[MAX_TX_JOB_ENTRIES];
	/* actual number of entries configured by ODP */
	int				num_entries;
	/* queue index */
	int				q_idx;
	/* lmac protection lock */
	spinlock_t			lock;
};

/* rfoe common (for all lmac's) */
struct rfoe_common_cfg {
	struct tx_job_queue_cfg		tx_oth_job_cfg;
	/* lmac protection lock */
	spinlock_t			rx_lock;
};

/* ptp pending skb list */
struct ptp_tx_skb_list {
	struct list_head		list;
	unsigned int			count;
};

/* ptp skb list entry */
struct ptp_tstamp_skb {
	struct list_head list;
	struct sk_buff *skb;
};

struct otx2_rfoe_stats {
	/* rx */
	u64 rx_packets;		/* rx packets */
	u64 ptp_rx_packets;	/* ptp rx packets */
	u64 ecpri_rx_packets;	/* ecpri rx packets */
	u64 rx_bytes;		/* rx bytes count */
	u64 rx_dropped;		/* rx dropped */
	u64 ptp_rx_dropped;	/* ptp rx dropped */
	u64 ecpri_rx_dropped;	/* ptp rx dropped */

	/* tx */
	u64 tx_packets;		/* tx packets */
	u64 ptp_tx_packets;	/* ptp rx packets */
	u64 ecpri_tx_packets;	/* ecpri rx packets */
	u64 tx_bytes;		/* tx bytes count */
	u64 tx_dropped;		/* tx dropped */
	u64 ptp_tx_dropped;	/* ptp tx dropped */
	u64 ecpri_tx_dropped;	/* ptp tx dropped */

	/* stats update lock */
	spinlock_t lock;
};

/* netdev priv */
struct otx2_rfoe_ndev_priv {
	u8				rfoe_num;
	u8				lmac_id;
	struct net_device		*netdev;
	struct pci_dev			*pdev;
	u32				msg_enable;
	void __iomem			*bphy_reg_base;
	void __iomem			*psm_reg_base;
	void __iomem			*rfoe_reg_base;
	void				*iommu_domain;
	struct rx_ft_cfg		rx_ft_cfg[PACKET_TYPE_MAX];
	struct tx_job_queue_cfg		tx_ptp_job_cfg;
	struct rfoe_common_cfg		*rfoe_common;
	/* priv lock */
	spinlock_t			lock;
	int				rx_hw_tstamp_en;
	int				tx_hw_tstamp_en;
	struct sk_buff			*ptp_tx_skb;
	u16				ptp_job_tag;
	struct timer_list		tx_timer;
	unsigned long			state;
	struct work_struct		ptp_tx_work;
	struct work_struct		ptp_queue_work;
	struct ptp_tx_skb_list		ptp_skb_list;
	struct otx2_rfoe_stats		stats;
	u8				mac_addr[ETH_ALEN];
};

/* ethtool */
void otx2_rfoe_set_ethtool_ops(struct net_device *netdev);

#endif
