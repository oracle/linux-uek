/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell CNF10K BPHY RFOE Netdev Driver
 *
 * Copyright (C) 2021 Marvell.
 */

#ifndef _CNF10K_RFOE_H_
#define _CNF10K_RFOE_H_

#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/iommu.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/if_ether.h>
#include <linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/if_vlan.h>

#include "rfoe_common.h"
#include "otx2_bphy.h"

#define DEBUG

#define CNF10K_RFOE_RX_INTR_SHIFT(a)		(32 - ((a) + 1) * 3)
#define CNF10K_RFOE_RX_INTR_MASK(a)		(RFOE_RX_INTR_EN << \
						 CNF10K_RFOE_RX_INTR_SHIFT(a))
#define CNF10K_RFOE_TX_PTP_INTR_MASK(a, b, n)	(1UL << ((a) * (n) + (b)))

#define CNF10K_RFOE_MAX_INTF			14

/* global driver context */
struct cnf10k_rfoe_drv_ctx {
	u8				rfoe_num;
	u8				lmac_id;
	int				valid;
	struct net_device               *netdev;
	struct cnf10k_rx_ft_cfg		*ft_cfg;
	int				tx_gpint_bit;
};

extern struct cnf10k_rfoe_drv_ctx cnf10k_rfoe_drv_ctx[CNF10K_RFOE_MAX_INTF];

/* rx flow table configuration */
struct cnf10k_rx_ft_cfg {
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
	struct cnf10k_rfoe_ndev_priv	*priv;
};

struct tx_ptp_ring_cfg {
	u8				ptp_ring_id;
	void __iomem			*ptp_ring_base;
	u8				ptp_ring_size;
	u8				ptp_ring_idx;
};

/* netdev priv */
struct cnf10k_rfoe_ndev_priv {
	u8				rfoe_num;
	u8				lmac_id;
	struct net_device		*netdev;
	struct pci_dev			*pdev;
	struct otx2_bphy_cdev_priv	*cdev_priv;
	u32				msg_enable;
	void __iomem			*bphy_reg_base;
	void __iomem			*psm_reg_base;
	void __iomem			*rfoe_reg_base;
	void __iomem			*bcn_reg_base;
	void __iomem			*ptp_reg_base;
	struct iommu_domain		*iommu_domain;
	struct cnf10k_rx_ft_cfg		rx_ft_cfg[PACKET_TYPE_MAX];
	struct tx_job_queue_cfg		tx_ptp_job_cfg;
	struct tx_ptp_ring_cfg		ptp_ring_cfg;
	struct rfoe_common_cfg		*rfoe_common;
	u8				pkt_type_mask;
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
	struct ptp_clock		*ptp_clock;
	struct ptp_clock_info		ptp_clock_info;
	struct otx2_rfoe_stats		stats;
	u8				mac_addr[ETH_ALEN];
	s32				sec_bcn_offset;
	int				if_type;
	u8				link_state;
	unsigned long			last_tx_jiffies;
	unsigned long			last_tx_ptp_jiffies;
	unsigned long			last_rx_jiffies;
	unsigned long			last_rx_ptp_jiffies;
	unsigned long			last_tx_dropped_jiffies;
	unsigned long			last_tx_ptp_dropped_jiffies;
	unsigned long			last_rx_dropped_jiffies;
	unsigned long			last_rx_ptp_dropped_jiffies;
};

void cnf10k_rfoe_rx_napi_schedule(int rfoe_num, u32 status);

int cnf10k_rfoe_parse_and_init_intf(struct otx2_bphy_cdev_priv *cdev,
				    struct cnf10k_rfoe_ndev_comm_intf_cfg *cfg);

void cnf10k_rfoe_disable_intf(int rfoe_num);

/* ethtool */
void cnf10k_rfoe_set_ethtool_ops(struct net_device *netdev);

/* ptp */
int cnf10k_rfoe_ptp_init(struct cnf10k_rfoe_ndev_priv *priv);
void cnf10k_rfoe_ptp_destroy(struct cnf10k_rfoe_ndev_priv *priv);

void cnf10k_bphy_intr_handler(struct otx2_bphy_cdev_priv *cdev_priv,
			      u32 status);

#endif
