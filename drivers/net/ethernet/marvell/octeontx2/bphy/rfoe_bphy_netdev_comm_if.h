/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTx2 BPHY RFOE/CPRI Ethernet Driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _BPHY_NETDEV_COMM_IF_H_
#define _BPHY_NETDEV_COMM_IF_H_

#define ETH_ADDR_LEN		6	/* ethernet address len */
#define MAX_RFOE_INTF		3	/* Max RFOE instances */
#define MAX_LMAC_PER_RFOE	4	/* 2 rfoe x 4 lmac, 1 rfoe x 2 lmac */
#define RFOE_MAX_INTF		10	/* 2 rfoe x 4 lmac + 1 rfoe x 2 lmac */
#define INVALID_INTF		255

#define MAX_PTP_MSG_PER_LMAC	4	/* 16 Per RFoE */
#define MAX_OTH_MSG_PER_LMAC	16	/* 64 Per RFoE */
/* 64 per RFoE; RFoE2 shall have 32 entries */
#define MAX_OTH_MSG_PER_RFOE	(MAX_OTH_MSG_PER_LMAC * MAX_LMAC_PER_RFOE)

/* CPRI ETH Macros */
#define MAX_NUM_CPRI                3
#define MAX_LANE_PER_CPRI           4
#define CPRI_ETH_PAYLOAD_SIZE_MIN   64
#define CPRI_ETH_PAYLOAD_SIZE_MAX   1536
#define CPRI_ETH_PKT_HDR_SIZE       128

#define CPRI_ETH_PKT_SIZE           (CPRI_ETH_PKT_HDR_SIZE + \
				     CPRI_ETH_PAYLOAD_SIZE_MAX)

/**
 * @enum bphy_netdev_tx_gpint
 * @brief GP_INT numbers for packet notification by netdev to BPHY.
 *
 */
enum bphy_netdev_tx_gpint {
	TX_GP_INT_RFOE0_LMAC0     = 32, //PSM_GPINT32,
	TX_GP_INT_RFOE0_LMAC1     = 33, //PSM_GPINT33,
	TX_GP_INT_RFOE0_LMAC2     = 34, //PSM_GPINT34,
	TX_GP_INT_RFOE0_LMAC3     = 35, //PSM_GPINT35,

	TX_GP_INT_RFOE1_LMAC0     = 36, //PSM_GPINT36,
	TX_GP_INT_RFOE1_LMAC1     = 37, //PSM_GPINT37,
	TX_GP_INT_RFOE1_LMAC2     = 38, //PSM_GPINT38,
	TX_GP_INT_RFOE1_LMAC3     = 39, //PSM_GPINT39,

	TX_GP_INT_RFOE2_LMAC0     = 40, //PSM_GPINT40,
	TX_GP_INT_RFOE2_LMAC1     = 41, //PSM_GPINT41
};

/**
 * @enum bphy_netdev_rx_gpint
 * @brief GP_INT numbers for packet notification by BPHY to netdev.
 *
 */
enum bphy_netdev_rx_gpint {
	RX_GP_INT_RFOE0_PTP       = 63, //PSM_GPINT63,
	RX_GP_INT_RFOE0_ECPRI     = 62, //PSM_GPINT62,
	RX_GP_INT_RFOE0_GENERIC   = 61, //PSM_GPINT61,

	RX_GP_INT_RFOE1_PTP       = 60, //PSM_GPINT60,
	RX_GP_INT_RFOE1_ECPRI     = 59, //PSM_GPINT59,
	RX_GP_INT_RFOE1_GENERIC   = 58, //PSM_GPINT58,

	RX_GP_INT_RFOE2_PTP       = 57, //PSM_GPINT57,
	RX_GP_INT_RFOE2_ECPRI     = 56, //PSM_GPINT56,
	RX_GP_INT_RFOE2_GENERIC   = 55, //PSM_GPINT55
};

/**
 * @enum bphy_netdev_cpri_rx_gpint
 * @brief GP_INT numbers for CPRI Ethernet packet Rx notification to netdev.
 *
 */
enum bphy_netdev_cpri_rx_gpint {
	RX_GP_INT_CPRI0_ETH = 45, //PSM_GPINT45,
	RX_GP_INT_CPRI1_ETH = 46, //PSM_GPINT46,
	RX_GP_INT_CPRI2_ETH = 47, //PSM_GPINT47
};

/**
 * @enum bphy_netdev_if_type
 * @brief BPHY Interface Types
 *
 */
enum bphy_netdev_if_type {
	IF_TYPE_ETHERNET    = 0,
	IF_TYPE_CPRI        = 1,
	IF_TYPE_MAX,
};

/**
 * @enum bphy_netdev_packet_type
 * @brief Packet types
 *
 */
enum bphy_netdev_packet_type {
	PACKET_TYPE_PTP     = 0,
	PACKET_TYPE_ECPRI   = 1,
	PACKET_TYPE_OTHER   = 2,
	PACKET_TYPE_MAX,
};

/**
 * @struct bphy_netdev_intf_info
 * @brief LMAC lane number, mac address and status information
 *
 */
struct bphy_netdev_intf_info {
	u8 rfoe_num;
	u8 lane_num;
	/* Source mac address */
	u8 eth_addr[ETH_ADDR_LEN];
	/* LMAC interface status */
	u8 status; //0-DOWN, 1-UP
	/* Configuration valid status; This interface shall be
	 * invalid if this field is set to 0
	 */
	u8 is_valid;
};

/**
 * @struct bphy_netdev_rbuf_info
 * @brief Information abnout the packet ring buffer which shall be used to send
 *        the packets from BPHY to netdev.
 *
 */
struct bphy_netdev_rbuf_info {
	enum bphy_netdev_packet_type pkt_type;
	/* gp_int = 0 can be treated as pkt type not enabled */
	enum bphy_netdev_rx_gpint gp_int_num;
	u16 flow_id;
	u16 mbt_index;
	/* Maximum number of buffers in the Ring/Pool */
	u16 num_bufs;
	/* MAX Buffer Size configured */
	u16 buf_size; // TBC: 1536?
	/* MBT byffer target memory */
	u8 mbt_target_mem;
	u8 reserved;
	/* Buffers starting address */
	u64 mbt_iova_addr;
	u16 jdt_index;
	/* Maximum number of JD buffers in the Ring/Pool */
	u16 num_jd;
	/* MAX JD size configured */
	u8 jd_size;
	/* MBT byffer target memory */
	u8 jdt_target_mem;
	/* Buffers starting address */
	u64 jdt_iova_addr;
};

/**
 * @brief
 *
 */
struct bphy_netdev_tx_psm_cmd_info {
	enum bphy_netdev_tx_gpint gp_int_num; /* Valid only for PTP messages */
	u64 jd_iova_addr;
	u64 rd_dma_iova_addr;
	u64 low_cmd;
	u64 high_cmd;
};

/**
 * @struct bphy_netdev_comm_if
 * @brief The communication interface defnitions which would be used by
 *        the netdev and bphy application.
 *
 */
struct bphy_netdev_comm_if {
	struct bphy_netdev_intf_info lmac_info;
	struct bphy_netdev_rbuf_info rbuf_info[PACKET_TYPE_MAX];
	/* Defining single array to handle both PTP and OTHER cmds info */
	struct bphy_netdev_tx_psm_cmd_info ptp_pkt_info[MAX_PTP_MSG_PER_LMAC];
};

/**
 * @struct bphy_netdev_cpri_if
 * @brief communication interface structure defnition to be used by
 *        BPHY and NETDEV applications for CPRI Interface.
 *
 */
struct bphy_netdev_cpri_if {
	u8 id;                 /* CPRI ID 0..2 */
	u8 active_lane_mask;   /* lane mask */
	u8 ul_gp_int_num;      /* UL GP INT NUM */
	u8 ul_int_threshold;   /* UL INT THRESHOLD */
	u8 num_ul_buf;         /* Num UL Buffers */
	u8 num_dl_buf;         /* Num DL Buffers */
	u8 reserved[2];
	u64 ul_buf_iova_addr;
	u64 dl_buf_iova_addr;
	u8 eth_addr[MAX_LANE_PER_CPRI][ETH_ADDR_LEN];
};

/**
 * @struct bphy_netdev_rfoe_if
 * @brief communication interface structure defnition to be used by
 *        BPHY and NETDEV applications for RFOE Interface.
 *
 */
struct bphy_netdev_rfoe_if {
	/* Interface configuration */
	struct bphy_netdev_comm_if if_cfg[MAX_LMAC_PER_RFOE];
	/* TX JD cmds to send packets other than PTP;
	 * These are defined per RFoE and all LMAC can share
	 */
	struct bphy_netdev_tx_psm_cmd_info oth_pkt_info[MAX_OTH_MSG_PER_RFOE];
	/* Packet types for which the RX flows are configured.*/
	u8 pkt_type_mask;
};

/**
 * @struct bphy_netdev_comm_intf_cfg
 * @brief ODP-NETDEV communication interface defnition structure to share
 *        the RX/TX intrefaces information.
 *
 */
struct bphy_netdev_comm_intf_cfg {
	enum bphy_netdev_if_type if_type;     /* 0 --> ETHERNET, 1 --> CPRI */
	struct bphy_netdev_rfoe_if rfoe_if_cfg; /* RFOE INTF configuration */
	struct bphy_netdev_cpri_if cpri_if_cfg; /* CPRI INTF configuration */
};

#endif //_BPHY_NETDEV_COMM_IF_H_
