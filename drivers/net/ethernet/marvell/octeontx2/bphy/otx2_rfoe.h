/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTx2 BPHY RFOE/CPRI Ethernet Driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _OTX2_RFOE_H_
#define _OTX2_RFOE_H_

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

#include "otx2_bphy.h"
#include "rfoe_common.h"

#define RFOE_RX_INTR_SHIFT(a)		(32 - ((a) + 1) * 3)
#define RFOE_RX_INTR_MASK(a)		(RFOE_RX_INTR_EN << \
					 RFOE_RX_INTR_SHIFT(a))
#define RFOE_TX_PTP_INTR_MASK(a, b)	(1UL << ((a) * 4 + (b)))

#define MAX_RFOE_INTF			3	/* Max RFOE instances */
#define RFOE_MAX_INTF			10	/* 2 rfoe x 4 lmac + 1 rfoe x 2 lmac */
#define PCI_SUBSYS_DEVID_OCTX2_95XXN	0xB400

/* ethtool msg */
#define OTX2_RFOE_MSG_DEFAULT		(NETIF_MSG_DRV)

#define OTX2_RFOE_MAX_FSIZE		9212 /* max frame size excluding FCS */
#define OTX2_RFOE_MAX_MTU		(OTX2_RFOE_MAX_FSIZE - VLAN_ETH_HLEN)

/* global driver context */
struct otx2_rfoe_drv_ctx {
	u8				rfoe_num;
	u8				lmac_id;
	int				valid;
	struct net_device               *netdev;
	struct rx_ft_cfg		*ft_cfg;
	int				tx_gpint_bit;
	void				*debugfs;
};

extern struct otx2_rfoe_drv_ctx rfoe_drv_ctx[RFOE_MAX_INTF];

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
	struct napi_struct		napi;
	struct otx2_rfoe_ndev_priv	*priv;
};

/* netdev priv */
struct otx2_rfoe_ndev_priv {
	u8				rfoe_num;
	u8				lmac_id;
	struct net_device		*netdev;
	struct pci_dev			*pdev;
	struct otx2_bphy_cdev_priv	*cdev_priv;
	u32				msg_enable;
	u32				ptp_ext_clk_rate;
	void __iomem			*bphy_reg_base;
	void __iomem			*psm_reg_base;
	void __iomem			*rfoe_reg_base;
	void __iomem			*bcn_reg_base;
	void __iomem			*ptp_reg_base;
	struct iommu_domain		*iommu_domain;
	struct rx_ft_cfg		rx_ft_cfg[PACKET_TYPE_MAX];
	struct tx_job_queue_cfg		tx_ptp_job_cfg;
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
	struct cyclecounter		cycle_counter;
	struct timecounter		time_counter;

	struct delayed_work		extts_work;
	u64				last_extts;
	u64				thresh;

	struct ptp_pin_desc		extts_config;
	/* ptp lock */
	struct mutex			ptp_lock;
	struct otx2_rfoe_stats		stats;
	u8				mac_addr[ETH_ALEN];
	struct ptp_bcn_off_cfg		*ptp_cfg;
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

void otx2_rfoe_rx_napi_schedule(int rfoe_num, u32 status);

int otx2_rfoe_parse_and_init_intf(struct otx2_bphy_cdev_priv *cdev,
				  struct bphy_netdev_comm_intf_cfg *cfg);

void otx2_bphy_rfoe_cleanup(void);

void otx2_rfoe_disable_intf(int rfoe_num);

/* ethtool */
void otx2_rfoe_set_ethtool_ops(struct net_device *netdev);

/* ptp */
void otx2_rfoe_calc_ptp_ts(struct otx2_rfoe_ndev_priv *priv, u64 *ts);
int otx2_rfoe_ptp_init(struct otx2_rfoe_ndev_priv *priv);
void otx2_rfoe_ptp_destroy(struct otx2_rfoe_ndev_priv *priv);

/* update carrier state */
void otx2_rfoe_set_link_state(struct net_device *netdev, u8 state);
int otx2_bcn_poll_reg(void __iomem *bcn_reg_base, u64 offset, u64 mask, bool zero);

#endif
