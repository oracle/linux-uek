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
#define MIO_PTP_CLOCK_HI		0x10
#define MIO_PTP_TIMESTAMP		0x20
#define MIO_PTP_PPS_THRESH_HI		0x58ULL
#define MIO_PTP_CLOCK_COMP		0x18ULL

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
	u64 tx_hwtstamp_failures; /* ptp tx timestamp failures */

	/* per LMAC stats */
	u64 EthIfInFrames;
	u64 EthIfInOctets;
	u64 EthIfOutFrames;
	u64 EthIfOutOctets;
	u64 EthIfInUnknownVlan;

	/* stats update lock */
	spinlock_t lock;
};

struct otx2_rfoe_link_event {
	u8				rfoe_num;
	u8				lmac_id;
	u8				link_state;
};

#endif
