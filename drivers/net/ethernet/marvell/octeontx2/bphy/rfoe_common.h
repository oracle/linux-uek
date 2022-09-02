/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell BPHY RFOE Netdev Driver
 *
 * Copyright (C) 2021 Marvell.
 */

#ifndef _OTX2_RFOE_COMMON_H_
#define _OTX2_RFOE_COMMON_H_

#include <linux/netdevice.h>
#include <linux/net_tstamp.h>

#include "bphy_netdev_comm_if.h"

/* PTP register offsets */
#define MIO_PTP_CLOCK_CFG		0x0
#define PTP_CLOCK_CFG_CKOUT_EN		BIT(24)
#define MIO_PTP_CLOCK_HI		0x10
#define MIO_PTP_TIMESTAMP		0x20
#define MIO_PTP_CKOUT_THRESH_HI		0x38
#define MIO_PTP_PPS_THRESH_HI		0x58ULL
#define MIO_PTP_CLOCK_COMP		0x18ULL
#define MIO_PTP_CLOCK_SEC		0xD0ULL
#define MIO_PTP_CLOCK_CFG_EXT_CLK_EN	BIT_ULL(1)
#define MIO_PTP_CLOCK_CFG_EXT_CLK_MASK  GENMASK_ULL(7, 2)

#define CYCLE_MULT			1000
#define GIGA_HZ				1000000000LL

/* max tx job entries */
#define MAX_TX_JOB_ENTRIES		64

/* GPINT(1) RFOE definitions */
#define RX_PTP_INTR			BIT(2) /* PTP packet intr */
#define RX_ECPRI_INTR			BIT(1) /* ECPRI packet intr */
#define RX_GEN_INTR			BIT(0) /* GENERIC packet intr */
#define RFOE_RX_INTR_EN			(RX_PTP_INTR	| \
					 RX_ECPRI_INTR	| \
					 RX_GEN_INTR)
/* Interrupt processing definitions */
#define INTR_TO_PKT_TYPE(a)		(PACKET_TYPE_OTHER - (a))
#define PKT_TYPE_TO_INTR(a)		(1UL << (PACKET_TYPE_OTHER - (a)))

enum state {
	PTP_TX_IN_PROGRESS = 1,
	RFOE_INTF_DOWN,
};

enum rfoe_rx_pkt_err_e {
	RE_NONE		= 0x0,
	RE_PARTIAL	= 0x1,
	RE_JABBER	= 0x2,
	RE_FCS		= 0x7,
	RE_FCS_RCV	= 0x8,
	RE_TERMINATE	= 0x9,
	RE_RX_CTL	= 0xB,
	RE_SKIP		= 0xC,
};

enum rfoe_rx_pkt_logger_idx_e {
	RX_PKT		= 0x0,
	TX_PKT		= 0x1,
};

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

/* tx job entry */
struct tx_job_entry {
	u64			job_cmd_lo;
	u64			job_cmd_hi;
	u64			jd_iova_addr;
	u64			rd_dma_iova_addr;
	void __iomem		*jd_ptr;
	void __iomem		*rd_dma_ptr;
	void __iomem		*jd_cfg_ptr;
	void __iomem		*pkt_dma_addr;
};

/* tx job queue */
struct tx_job_queue_cfg {
	u8				psm_queue_id;
	/* actual number of entries configured by ODP */
	int				num_entries;
	/* queue index */
	int				q_idx;
	/* lmac protection lock */
	spinlock_t			lock;

	struct tx_job_entry		job_entries[MAX_TX_JOB_ENTRIES];
};

/* rfoe common (for all lmac's) */
struct rfoe_common_cfg {
	struct tx_job_queue_cfg		tx_oth_job_cfg;
	int				rx_mbt_last_idx[PACKET_TYPE_MAX];
	u16				nxt_buf[PACKET_TYPE_MAX];
	u8				refcnt;
	u8				rx_vlan_fwd_refcnt[VLAN_N_VID];
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
	/* Pkt okay stats */
	u64 rx_packets;		/* rx packets */
	u64 ptp_rx_packets;	/* ptp rx packets */
	u64 ecpri_rx_packets;	/* ecpri rx packets */
	u64 rx_bytes;		/* rx bytes count */
	u64 tx_packets;		/* tx packets */
	u64 ptp_tx_packets;	/* ptp rx packets */
	u64 ecpri_tx_packets;	/* ecpri rx packets */
	u64 tx_bytes;		/* tx bytes count */

	/* Drop stats */
	u64 rx_dropped;		/* rx dropped */
	u64 ptp_rx_dropped;	/* ptp rx dropped */
	u64 ecpri_rx_dropped;	/* ptp rx dropped */
	u64 tx_dropped;		/* tx dropped */
	u64 ptp_tx_dropped;	/* ptp tx dropped */
	u64 ecpri_tx_dropped;	/* ptp tx dropped */
	u64 tx_hwtstamp_failures; /* ptp tx timestamp failures */

	/* per LMAC stats */
	u64 EthIfInFrames;
	u64 EthIfInOctets;
	u64 EthIfOutFrames;
	u64 EthIfOutOctets;
	u64 EthIfInUnknownVlan;

	/* stats update lock */
	spinlock_t lock;
} ____cacheline_aligned_in_smp;

struct otx2_rfoe_link_event {
	u8				rfoe_num;
	u8				lmac_id;
	u8				link_state;
};

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

struct ptp_clk_src_cfg {
	int clk_freq_ghz;	/* ptp clk freq */
	int clk_freq_div;	/* ptp clk divisor */
	int clk_input;		/* External or Internal */
	int clk_source;		/* Clock source */
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

struct rfoe_rx_ind_vlanx_fwd {
	u64 fwd			: 64;
};

struct bcn_ptp_cfg {
	int ptp_phc_idx;
	s64 delta;
};

#endif
