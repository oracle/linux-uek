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
#include <net/ip.h>

#include "rfoe_common.h"
#include "otx2_bphy.h"

#define DEBUG

#define CNF10K_RFOE_RX_INTR_SHIFT(a) ({ \
	typeof(a) _a = (a); \
	((_a) < 6) ? (32 - ((_a) + 1) * 3) : (((_a) - 6) * 3); \
})
#define CNF10K_RFOE_RX_INTR_MASK(a)		(RFOE_RX_INTR_EN << \
						 CNF10K_RFOE_RX_INTR_SHIFT(a))
#define CNF10K_RFOE_TX_PTP_INTR_MASK(a, b, n)	(1UL << ((a) * (n) + (b)))

#define CNF10K_RFOE_MAX_INTF			14

#define CNF10K_RFOE_MAX_FSIZE		9212 /* max frame size excluding FCS */
#define CNF10K_RFOE_MAX_MTU		(CNF10K_RFOE_MAX_FSIZE - VLAN_ETH_HLEN)

#define PCI_SUBSYS_DEVID_CNF10K_A			0xBA00
#define PCI_SUBSYS_DEVID_CNF10K_B			0xBC00
/* BCN register offsets and definitions */
#define CNF10K_BCN_CAPTURE_CFG				0x1400U
#define CNF10K_BCN_CAPTURE_N1_N2			0x1410U
#define CNF10K_BCN_CAPTURE_PTP				0x1440U
#define CNF10K_BCN_N1_N2				0xF10U
#define CNF10K_BCN_SYNC_VAL				0xF20U
#define CNF10K_BCN_DELTA_VAL				0xF30U
#define CNF10K_BCN_CFG					0xF00U
#define CNF10K_BCN_CFG2					0x2F00U

/* BCN_CAPTURE_CFG register definitions */
#define CAPT_EN					BIT(0)
#define CAPT_TRIG_SW				(3UL << 8)

#define BPHY_NDEV_TX_1S_PTP_EN_FLAG			BIT(0)

/* global driver context */
struct cnf10k_rfoe_drv_ctx {
	u8				rfoe_num;
	u8				lmac_id;
	u8				valid;
	struct net_device               *netdev;
	struct cnf10k_rx_ft_cfg		*ft_cfg;
	void				*debugfs;
};

extern struct cnf10k_rfoe_drv_ctx cnf10k_rfoe_drv_ctx[CNF10K_RFOE_MAX_INTF];

/* rx flow table configuration */
struct cnf10k_rx_ft_cfg {
	u8				jd_rd_offset;	/* jd rd offset */
	u8				pkt_offset;
	u16				mbt_idx;	/* mbt index */
	u16				num_bufs;	/* mbt num bufs */
	u16				buf_size;	/* mbt buf size */
	void __iomem			*mbt_virt_addr;
	enum bphy_netdev_packet_type	pkt_type;	/* pkt_type for psw */

	enum bphy_netdev_rx_gpint	gp_int_num;
	u8				jd_size;	/* jd size */
	u16				flow_id;	/* flow id */
	u16				jdt_idx;	/* jdt index */
	u16				num_jd;		/* num jd's */
	u64				mbt_iova_addr;
	u64				jdt_iova_addr;
	void __iomem			*jdt_virt_addr;
	struct napi_struct		napi;
	struct cnf10k_rfoe_ndev_priv	*priv;
} ____cacheline_aligned_in_smp;

struct tx_ptp_ring_cfg {
	u8				ptp_ring_id;
	void __iomem			*ptp_ring_base;
	u8				ptp_ring_size;
	u8				ptp_ring_idx;
};

struct cnf10k_tx_action_s {
	u64 start_offset  : 8;
	u64 rsvd_11_8	  : 4;
	u64 rsvd_12	  : 1;
	u64 udp_csum_crt  : 1;
	u64 update64      : 1;
	u64 rsvd_15_16    : 1;
	u64 base_ns       : 32;
	u64 step_type     : 1;
	u64 rsvd_51_49    : 3;
	u64 per_lso_seg   : 1;
	u64 wmem          : 1;
	u64 dsz           : 2;
	u64 alg           : 4;
	u64 subdc         : 4;
};

/* netdev priv */
struct cnf10k_rfoe_ndev_priv {
	u8				rfoe_num;
	u8				lmac_id;
	u8				rx_hw_tstamp_en;
	u8				tx_hw_tstamp_en;
	u8				if_type;
	u8				pkt_type_mask;
	u8				ndev_flags;
	u32				msg_enable;
	struct otx2_bphy_cdev_priv	*cdev_priv;
	struct rfoe_common_cfg		*rfoe_common;
	void __iomem			*psm_reg_base;
	struct iommu_domain		*iommu_domain;
	unsigned long			last_tx_jiffies;
	unsigned long			last_rx_jiffies;
	/* Above variables are accessed in hot path for every packet,
	 * hence keep them in single cache line (64 bytes).
	 */

	struct net_device		*netdev;
	struct pci_dev			*pdev;
	u32				ptp_ext_clk_rate;
	void __iomem			*bphy_reg_base;
	void __iomem			*rfoe_reg_base;
	void __iomem			*bcn_reg_base;
	void __iomem			*ptp_reg_base;
	struct cnf10k_rx_ft_cfg		rx_ft_cfg[PACKET_TYPE_MAX];
	struct tx_job_queue_cfg		tx_ptp_job_cfg;
	struct tx_ptp_ring_cfg		ptp_ring_cfg;
	/* priv lock */
	spinlock_t			lock;
	int				ptp_onestep_sync;
	struct sk_buff			*ptp_tx_skb;
	u16				ptp_job_tag;
	struct timer_list		tx_timer;
	unsigned long			state;
	struct work_struct		ptp_tx_work;
	struct work_struct		ptp_queue_work;
	struct ptp_tx_skb_list		ptp_skb_list;
	struct ptp_clock		*ptp_clock;
	struct ptp_clock_info		ptp_clock_info;
	struct delayed_work		extts_work;
	struct ptp_pin_desc		extts_config;
	struct cyclecounter		cycle_counter;
	struct timecounter		time_counter;
	/* ptp lock */
	struct mutex			ptp_lock;
	u8				mac_addr[ETH_ALEN];
	struct ptp_bcn_off_cfg		*ptp_cfg;
	s32				sec_bcn_offset;
	u8				link_state;
	unsigned long			last_tx_ptp_jiffies;
	unsigned long			last_rx_ptp_jiffies;
	unsigned long			last_tx_dropped_jiffies;
	unsigned long			last_tx_ptp_dropped_jiffies;
	unsigned long			last_rx_dropped_jiffies;
	unsigned long			last_rx_ptp_dropped_jiffies;
	u64				last_extts;
	u64				thresh;

	struct otx2_rfoe_stats		stats;
} ____cacheline_aligned_in_smp;

/* PTPv2 originTimestamp structure */
struct ptpv2_tstamp {
	u16 seconds_msb; /* 16 bits + */
	u32 seconds_lsb; /* 32 bits = 48 bits*/
	u32 nanoseconds;
} __packed;

void cnf10k_rfoe_rx_napi_schedule(int rfoe_num, u32 status);

int cnf10k_rfoe_parse_and_init_intf(struct otx2_bphy_cdev_priv *cdev,
				    struct cnf10k_rfoe_ndev_comm_intf_cfg *cfg);

void cnf10k_bphy_rfoe_cleanup(void);

void cnf10k_rfoe_disable_intf(int rfoe_num);

/* ethtool */
void cnf10k_rfoe_set_ethtool_ops(struct net_device *netdev);

/* ptp */
void cnf10k_rfoe_calc_ptp_ts(struct cnf10k_rfoe_ndev_priv *priv, u64 *ts);
int cnf10k_rfoe_ptp_init(struct cnf10k_rfoe_ndev_priv *priv);
void cnf10k_rfoe_ptp_destroy(struct cnf10k_rfoe_ndev_priv *priv);

void cnf10k_bphy_intr_handler(struct otx2_bphy_cdev_priv *cdev_priv,
			      u32 status);
u64 cnf10k_rfoe_read_ptp_clock(struct cnf10k_rfoe_ndev_priv *priv);
int cnf10k_rfoe_ptp_tstamp2time(struct cnf10k_rfoe_ndev_priv *priv, u64 tstamp,
				u64 *tsns);

static inline u64 cnf10k_ptp_convert_timestamp(u64 timestamp)
{
	return ((timestamp >> 32) * NSEC_PER_SEC) + (timestamp & 0xFFFFFFFFUL);
}

void cnf10k_rfoe_set_link_state(struct net_device *netdev, u8 state);
#endif
