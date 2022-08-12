/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTx2 BPHY RFOE/CPRI Ethernet Driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _OTX2_BPHY_HW_H_
#define _OTX2_BPHY_HW_H_

#include <linux/types.h>

/* RFOE MHAB register offsets */
#define RFOEX_RX_CTL(a)				(0x0818ULL | \
						 ((unsigned long)(a) << 36))
#define RFOEX_RX_VLANX_CFG(a, b)		(0x0870ULL | \
						 ((unsigned long)(a) << 36) | \
						 ((b) << 3))
#define RFOEX_RX_INDIRECT_INDEX_OFFSET(a)	(0x13F8ULL | \
						 ((unsigned long)(a) << 36))
#define RFOEX_RX_IND_FTX_CFG(a, b)	(0x1400ULL | \
					 (((unsigned long)(a) << 36)) + \
					 ((b) << 3))
#define RFOEX_RX_IND_MBT_CFG(a)			(0x1420ULL | \
						 ((unsigned long)(a) << 36))
#define RFOEX_RX_IND_MBT_ADDR(a)		(0x1428ULL | \
						 ((unsigned long)(a) << 36))
#define RFOEX_RX_IND_MBT_SEG_STATE(a)		(0x1430ULL | \
						 ((unsigned long)(a) << 36))
#define RFOEX_RX_IND_VLANX_FWD(a, b)		(0x14D0ULL | \
						 ((unsigned long)(a) << 36) | \
						 ((b) << 3))
#define RFOEX_RX_IND_JDT_CFG0(a)		(0x1440ULL | \
						 ((unsigned long)(a) << 36))
#define RFOEX_RX_IND_JDT_CFG1(a)		(0x1448ULL | \
						 ((unsigned long)(a) << 36))
#define RFOEX_RX_IND_JDT_PTR(a)			(0x1450ULL | \
						 ((unsigned long)(a) << 36))
#define RFOEX_RX_IND_JDT_STATE(a)		(0x1478ULL | \
						 ((unsigned long)(a) << 36))
#define RFOEX_RX_IND_ECPRI_FT_CFG(a)		(0x14C0ULL | \
						 ((unsigned long)(a) << 36))
#define RFOEX_TX_PTP_TSTMP_W0(a, b)	(0x7A0ULL | \
					 (((unsigned long)(a) << 36)) | \
					 ((b) << 3))
#define RFOEX_TX_PTP_TSTMP_W1(a, b)	(0x7C0ULL | \
					 (((unsigned long)(a) << 36)) | \
					 ((b) << 3))
#define RFOEX_TX_PKT_STAT(a, b)		(0x720ULL | \
					 (((unsigned long)(a) << 36)) | \
					 ((b) << 3))
#define RFOEX_TX_OCTS_STAT(a, b)	(0x740ULL | \
					 (((unsigned long)(a) << 36)) | \
					 ((b) << 3))
#define RFOEX_RX_VLAN_DROP_STAT(a, b)	(0x8A0ULL | \
					 (((unsigned long)(a) << 36)) | \
					 ((b) << 3))
#define RFOEX_RX_CGX_PKT_STAT(a, b)	(0x15C0ULL | \
					 (((unsigned long)(a) << 36)) | \
					 ((b) << 3))
#define RFOEX_RX_CGX_OCTS_STAT(a, b)	(0x15E0ULL | \
					 (((unsigned long)(a) << 36)) | \
					 ((b) << 3))

/* BCN register offsets and definitions */
#define BCN_CAPTURE_CFG			0x10400
#define BCN_CAPTURE_N1_N2		0x10410
#define BCN_CAPTURE_PTP			0x10430
#define BCN_N1_N2			0x10010
#define BCN_SYNC_VAL			0x10020
#define BCN_DELTA_VAL			0x10030
#define BCN_CFG				0x10000
#define BCN_CFG2			0x12000
#define BCN_SYNC_EN			BIT(1)
#define BCN_DELTA_EN			BIT(16)
#define BCN_DELTA_N1_FORMULA		BIT(60)
#define BCN_DELTA_WRAP_MODE		BIT(61)

/* BCN_CAPTURE_CFG register definitions */
#define CAPT_EN				BIT(0)
#define CAPT_TRIG_SW			(3UL << 8)

/* CPRI register offsets */
#define CPRIX_RXD_GMII_UL_CBUF_CFG1(a)		(0x1000ULL | \
						 ((unsigned long)(a) << 36))
#define CPRIX_RXD_GMII_UL_CBUF_CFG2(a)		(0x1008ULL | \
						 ((unsigned long)(a) << 36))
#define CPRIX_RXD_GMII_UL_RD_DOORBELL(a)	(0x1010ULL | \
						 ((unsigned long)(a) << 36))
#define CPRIX_RXD_GMII_UL_SW_RD_PTR(a)		(0x1018ULL | \
						 ((unsigned long)(a) << 36))
#define CPRIX_RXD_GMII_UL_NXT_WR_PTR(a)		(0x1020ULL | \
						 ((unsigned long)(a) << 36))
#define CPRIX_RXD_GMII_UL_PKT_COUNT(a)		(0x1028ULL | \
						 ((unsigned long)(a) << 36))
#define CPRIX_TXD_GMII_DL_CBUF_CFG1(a)		(0x1100ULL | \
						 ((unsigned long)(a) << 36))
#define CPRIX_TXD_GMII_DL_CBUF_CFG2(a)		(0x1108ULL | \
						 ((unsigned long)(a) << 36))
#define CPRIX_TXD_GMII_DL_WR_DOORBELL(a)	(0x1110ULL | \
						 ((unsigned long)(a) << 36))
#define CPRIX_TXD_GMII_DL_SW_WR_PTR(a)		(0x1118ULL | \
						 ((unsigned long)(a) << 36))
#define CPRIX_TXD_GMII_DL_NXT_RD_PTR(a)		(0x1120ULL | \
						 ((unsigned long)(a) << 36))
#define CPRIX_ETH_UL_INT(a)			(0x280ULL | \
						 ((unsigned long)(a) << 36))
#define CPRIX_ETH_UL_INT_ENA_W1S(a)		(0x288ULL | \
						 ((unsigned long)(a) << 36))
#define CPRIX_ETH_UL_INT_ENA_W1C(a)		(0x290ULL | \
						 ((unsigned long)(a) << 36))
#define CPRIX_ETH_UL_INT_W1S(a)			(0x298ULL | \
						 ((unsigned long)(a) << 36))
#define CPRIX_ETH_BAD_CRC_CNT(a, b)		(0x400ULL | \
						 ((unsigned long)(a) << 36) | \
						 ((unsigned long)(b) << 11))
#define CPRIX_ETH_UL_ERR_CNT(a, b)		(0x408ULL | \
						 ((unsigned long)(a) << 36) | \
						 ((unsigned long)(b) << 11))
#define CPRIX_ETH_UL_OSIZE_CNT(a, b)		(0x410ULL | \
						 ((unsigned long)(a) << 36) | \
						 ((unsigned long)(b) << 11))
#define CPRIX_ETH_UL_USIZE_CNT(a, b)		(0x418ULL | \
						 ((unsigned long)(a) << 36) | \
						 ((unsigned long)(b) << 11))
#define CPRIX_ETH_UL_FIFO_ORUN_CNT(a, b)	(0x420ULL | \
						 ((unsigned long)(a) << 36) | \
						 ((unsigned long)(b) << 11))
#define CPRIX_ETH_UL_GPKTS_CNT(a, b)		(0x428ULL | \
						 ((unsigned long)(a) << 36) | \
						 ((unsigned long)(b) << 11))
#define CPRIX_ETH_UL_BOCT_CNT(a, b)		(0x430ULL | \
						 ((unsigned long)(a) << 36) | \
						 ((unsigned long)(b) << 11))
#define CPRIX_ETH_UL_GOCT_CNT(a, b)		(0x438ULL | \
						 ((unsigned long)(a) << 36) | \
						 ((unsigned long)(b) << 11))
#define CPRIX_ETH_DL_GOCTETS_CNT(a, b)		(0x440ULL | \
						 ((unsigned long)(a) << 36) | \
						 ((unsigned long)(b) << 11))
#define CPRIX_ETH_DL_GPKTS_CNT(a, b)		(0x448ULL | \
						 ((unsigned long)(a) << 36) | \
						 ((unsigned long)(b) << 11))

/* MHAB definitions */
struct mhbw_jd_dma_cfg_word_0_s {
	u64 dma_mode		: 3;
	u64 target_mem		: 1;
	u64 dswap		: 3;
	u64 cmd_type		: 2;
	u64 reserved1		: 7;
	u64 chunk_size		: 16;
	u64 block_size		: 16;
	u64 thread_id		: 6;
	u64 reserved2		: 2;
	u64 group_id		: 4;
	u64 reserved3		: 4;
};

struct mhbw_jd_dma_cfg_word_1_s {
	u64 start_addr		: 53;
	u64 reserved1		: 11;
};

enum rfoe_rx_dir_ctl_pkt_type_e {
	ROE		= 0x0,
	CHI		= 0x1,
	ALT		= 0x2,
	ECPRI		= 0x3,
	GENERIC		= 0x8,
};

enum rfoe_rx_pswt_e {
	ROE_TYPE	= 0x0,
	ECPRI_TYPE	= 0x2,
};

struct psm_cmd_addjob_s {
	/* W0 */
	u64 opcode	: 6;
	u64 rsrc_set	: 2;
	u64 qid		: 8;
	u64 waitcond	: 8;
	u64 jobtag	: 16;
	u64 reserved1	: 8;
	u64 mabq	: 1;
	u64 reserved2	: 3;
	u64 tmem	: 1;
	u64 reserved3	: 3;
	u64 jobtype	: 8;
	/* W1 */
	u64 jobptr	: 53;
	u64 reserved4	: 11;
};

struct rfoe_ecpri_psw0_s {
	/* W0 */
	u64 jd_ptr		: 53;
	u64 jd_ptr_tmem		: 1;
	u64 reserved1		: 2;
	u64 src_id		: 4;
	u64 reserved2		: 2;
	u64 pswt		: 2;
	/* W1 */
	u64 msg_type		: 8;
	u64 ecpri_id		: 16;
	u64 flow_id		: 8;
	u64 reserved3		: 6;
	u64 err_sts		: 6;
	u64 reserved4		: 2;
	u64 seq_id		: 16;
};

struct rfoe_ecpri_psw1_s {
	/* W0 */
	u64 ptp_timestamp;
	/* W1 */
	u64 ethertype		: 16;
	u64 eindex		: 5;
	u64 reserved1		: 3;
	u64 dec_error		: 8;
	u64 dec_num_sections	: 8;
	u64 dec_num_syminc	: 8;
	u64 reserved2		: 8;
	u64 ptype		: 4;
	u64 reserved3		: 4;
};

struct rfoe_psw0_s {
	/* W0 */
	u64 pkt_err_sts		: 4;
	u64 dma_error		: 1;
	u64 jd_ptr		: 53;
	u64 jd_target_mem	: 1;
	u64 orderinfo_status	: 1;
	u64 lmac_id		: 2;
	u64 pswt		: 2;
	/* W1 */
	u64 roe_subtype		: 8;
	u64 roe_flowid		: 8;
	u64 fd_symbol		: 8;
	u64 fd_antid		: 8;
	u64 rfoe_timestamp	: 32;
};

struct rfoe_psw1_s {
	/* W0 */
	u64 ptp_timestamp;
	/* W1 */
	u64 ethertype		: 16;
	u64 eindex		: 5;
	u64 reserved1		: 3;
	u64 dec_error		: 8;
	u64 dec_num_sections	: 8;
	u64 dec_num_syminc	: 8;
	u64 reserved2		: 8;
	u64 ptype		: 4;
	u64 reserved3		: 4;
};

struct rfoex_tx_ptp_tstmp_w1 {
	u64 lmac_id		: 2;
	u64 rfoe_id		: 2;
	u64 jobid		: 16;
	u64 drop		: 1;
	u64 tx_err		: 1;
	u64 reserved1		: 41;
	u64 valid		: 1;
};

struct rfoex_abx_slotx_configuration {
	u64 pkt_mode		: 2;
	u64 da_sel		: 3;
	u64 sa_sel		: 3;
	u64 etype_sel		: 3;
	u64 flowid		: 8;
	u64 subtype		: 8;
	u64 lmacid		: 2;
	u64 sample_mode		: 1;
	u64 sample_widt		: 5;
	u64 sample_width_option	: 1;
	u64 sample_width_sat_bypass	: 1;
	u64 orderinfotype	: 1;
	u64 orderinfooffset	: 5;
	u64 antenna		: 8;
	u64 symbol		: 8;
	u64 sos			: 1;
	u64 eos			: 1;
	u64 orderinfo_insert	: 1;
	u64 custom_timestamp_insert	: 1;
	u64 rfoe_mode		: 1;
};

struct rfoex_abx_slotx_configuration1 {
	u64 rbmap_bytes		: 8;
	u64 pkt_len		: 16;
	u64 hdr_len		: 8;
	u64 presentation_time_offset	: 29;
	u64 reserved1		: 1;
	u64 sof_mode		: 2;
};

struct rfoex_abx_slotx_configuration2 {
	u64 vlan_sel		: 3;
	u64 vlan_num		: 2;
	u64 ptp_mode		: 1;
	u64 ecpri_id_insert	: 1;
	u64 ecpri_seq_id_insert	: 1;
	u64 ecpri_rev		: 8;
	u64 ecpri_msgtype	: 8;
	u64 ecpri_id		: 16;
	u64 ecpri_seq_id	: 16;
	u64 reserved1		: 8;
};

struct mhab_job_desc_cfg {
	struct rfoex_abx_slotx_configuration cfg;
	struct rfoex_abx_slotx_configuration1 cfg1;
	struct rfoex_abx_slotx_configuration2 cfg2;
} __packed;

#endif	/* _OTX2_BPHY_HW_H_ */
