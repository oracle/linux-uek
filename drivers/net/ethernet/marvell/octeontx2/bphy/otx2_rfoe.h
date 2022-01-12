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

/* PTP clock time operates by adding a constant increment every clock
 * cycle. That increment is expressed (MIO_PTP_CLOCK_COMP) as a Q32.32
 * number of nanoseconds (32 integer bits and 32 fractional bits). The
 * value must be equal to 1/(PTP clock frequency in Hz). If the PTP clock
 * freq is 1 GHz, there is no issue but for other input clock frequency
 * values for example 950 MHz which is SLCK or 153.6 MHz (bcn_clk/2) the
 * MIO_PTP_CLOCK_COMP register value can't be expressed exactly and there
 * will be error accumulated over the time depending on the direction the
 * PTP_CLOCK_COMP value is rounded. The accumulated error will be around
 * -70ps or +150ps per second in case of 950 MHz.
 *
 * To solve this issue, the driver calculates the PTP timestamps using
 * BCN clock as reference as per the algorithm proposed as given below.
 *
 * Set PTP tick (= MIO_PTP_CLOCK_COMP) to 1.0 ns
 * Sample once, at exactly the same time, BCN and PTP to (BCN0, PTP0).
 * Calculate (applying BCN-to-PTP epoch difference and an OAM parameter
 *            secondaryBcnOffset)
 * PTPbase[ns] = NanoSec(BCN0) + NanoSec(315964819[s]) - secondaryBcnOffset[ns]
 * When reading packet timestamp (tick count) PTPn, convert it to nanoseconds.
 * PTP pkt timestamp = PTPbase[ns] + (PTPn - PTP0) / (PTP Clock in GHz)
 *
 * The intermediate values generated need to be of pico-second precision to
 * achieve PTP accuracy < 1ns. The calculations should not overflow 64-bit
 * value at anytime. Added timer to adjust the PTP and BCN base values
 * periodically to fix the overflow issue.
 */
#define PTP_CLK_FREQ_GHZ		95	/* Clock freq GHz dividend */
#define PTP_CLK_FREQ_DIV		100	/* Clock freq GHz divisor */
#define PTP_OFF_RESAMPLE_THRESH		1800	/* resample period in seconds */
#define PICO_SEC_PER_NSEC		1000	/* pico seconds per nano sec */
#define UTC_GPS_EPOCH_DIFF		315964819UL /* UTC - GPS epoch secs */

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

/* PTP clk freq in GHz represented as integer numbers.
 * This information is passed to netdev by the ODP BPHY
 * application via ioctl. The values are used in PTP
 * timestamp calculation algorithm.
 *
 * For 950MHz PTP clock =0.95GHz, the values are:
 *     clk_freq_ghz = 95
 *     clk_freq_div = 100
 *
 * For 153.6MHz PTP clock =0.1536GHz, the values are:
 *     clk_freq_ghz = 1536
 *     clk_freq_div = 10000
 *
 */
struct ptp_clk_cfg {
	int clk_freq_ghz;	/* ptp clk freq */
	int clk_freq_div;	/* ptp clk divisor */
};

struct bcn_sec_offset_cfg {
	u8				rfoe_num;
	u8				lmac_id;
	s32				sec_bcn_offset;
};

struct ptp_bcn_ref {
	u64				ptp0_ns;	/* PTP nanosec */
	u64				bcn0_n1_ns;	/* BCN N1 nanosec */
	u64				bcn0_n2_ps;	/* BCN N2 picosec */
};

struct ptp_bcn_off_cfg {
	struct ptp_bcn_ref		old_ref;
	struct ptp_bcn_ref		new_ref;
	struct ptp_clk_cfg		clk_cfg;
	struct timer_list		ptp_timer;
	int				use_ptp_alg;
	u8				refcnt;
	/* protection lock for updating ref */
	spinlock_t			lock;
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

#endif
