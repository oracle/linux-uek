/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTx2 BPHY RFOE Ethernet Driver
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

#include "otx2_bphy.h"
#include "otx2_bphy_hw.h"
#include "rfoe_bphy_netdev_comm_if.h"

/* GPINT(1) RFOE definitions */
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

/* rfoe intf definitions */
#define RFOE_NUM_INST			3
#define LMAC_PER_RFOE			4
#define RFOE_MAX_INTF			10

/* eCPRI ethertype */
#define ETH_P_ECPRI			0xAEFE

/* max tx job entries */
#define MAX_TX_JOB_ENTRIES		64

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
#define PTP_CLK_FREQ_DIV_GHZ		1536	/* freq_div = Clock MHz x 10 */
#define PTP_CLK_FREQ_MULT_GHZ		10000	/* freq(Ghz) = freq_div/10000 */
#define PTP_OFF_RESAMPLE_THRESH		1800	/* resample period in seconds */
#define PICO_SEC_PER_NSEC		1000	/* pico seconds per nano sec */
#define UTC_GPS_EPOCH_DIFF		315964819UL /* UTC - GPS epoch secs */

enum state {
	PTP_TX_IN_PROGRESS = 1,
	RFOE_INTF_DOWN,
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

extern struct otx2_rfoe_drv_ctx rfoe_drv_ctx[RFOE_MAX_INTF];

/* rfoe rx ind register configuration */
struct otx2_rfoe_rx_ind_cfg {
	u8			rfoe_num; /* rfoe idx */
	u16			rx_ind_idx; /* RFOE(0..2)_RX_INDIRECT_INDEX */
	u64			regoff; /* RFOE(0..2)_RX_IND_* reg offset */
	u64			regval; /* input when write, output when read */
#define OTX2_RFOE_RX_IND_READ	0
#define OTX2_RFOE_RX_IND_WRITE	1
	u8			dir; /* register access dir (read/write) */
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
	struct timer_list		ptp_timer;
	int				use_ptp_alg;
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
	struct otx2_rfoe_stats		stats;
	u8				mac_addr[ETH_ALEN];
	struct ptp_bcn_off_cfg		*ptp_cfg;
	s32				sec_bcn_offset;
};

void otx2_rfoe_rx_napi_schedule(int rfoe_num, u32 status);

int otx2_rfoe_parse_and_init_intf(struct otx2_bphy_cdev_priv *cdev,
				  struct bphy_netdev_comm_intf_cfg *cfg);

void otx2_bphy_rfoe_cleanup(void);

/* ethtool */
void otx2_rfoe_set_ethtool_ops(struct net_device *netdev);

#endif
