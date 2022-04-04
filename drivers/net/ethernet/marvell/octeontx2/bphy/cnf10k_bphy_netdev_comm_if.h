/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell CNF10K BPHY Netdev Driver
 *
 * Copyright (C) 2021 Marvell.
 */

#ifndef _CNF10K_BPHY_NETDEV_COMM_IF_H_
#define _CNF10K_BPHY_NETDEV_COMM_IF_H_

#include <linux/etherdevice.h>
#include "bphy_netdev_comm_if.h"

#define BPHY_MAX_RFOE_MHAB		8	/* Max RFOE MHAB instances */
#define BPHY_MAX_CPRI_MHAB		3	/* Max CPRI MHAB instances */

#define MAX_PTP_RING			4	/* Max ptp rings per lmac */

#define CNF10KB_VERSION			2	/* chip version */
#define CNF10KA_VERSION			3	/* chip version */

#define CHIP_CNF10KB(v)			(((v) == CNF10KB_VERSION) ? 1 : 0)
#define CHIP_CNF10KA(v)			(((v) == CNF10KA_VERSION) ? 1 : 0)

#define CHIP_CNF10K(v) ({ \
	typeof(v) _v = (v); \
	(CHIP_CNF10KB(_v) | CHIP_CNF10KA(_v)); \
})

/**
 * @enum BPHY_NETDEV_CPRI_RX_GP_INT_e_
 * @brief GP_INT numbers for CPRI Ethernet packet Rx notification
 *        by BPHY to netdev.
 *
 */
enum bphy_netdev_cpri_rx_gp_int {
	CNF10K_RX_GP_INT_CPRI0_ETH = 93, //PSM_GPINT93,
	CNF10K_RX_GP_INT_CPRI1_ETH = 94, //PSM_GPINT94,
	CNF10K_RX_GP_INT_CPRI2_ETH = 95, //PSM_GPINT95
};

/**
 * @enum BPHY_NETDEV_TX_GP_INT_e_
 * @brief GP_INT numbers for packet notification by netdev to BPHY.
 *
 */
#ifdef CNF10KB
enum bphy_netdev_tx_gp_int {
	CNF10K_TX_GP_INT_RFOE0_LMAC0     = 32, //PSM_GPINT32,
	CNF10K_TX_GP_INT_RFOE0_LMAC1     = 33, //PSM_GPINT33,

	CNF10K_TX_GP_INT_RFOE1_LMAC2     = 34, //PSM_GPINT34,
	CNF10K_TX_GP_INT_RFOE1_LMAC3     = 35, //PSM_GPINT35,

	CNF10K_TX_GP_INT_RFOE2_LMAC0     = 36, //PSM_GPINT36,
	CNF10K_TX_GP_INT_RFOE2_LMAC1     = 37, //PSM_GPINT37,

	CNF10K_TX_GP_INT_RFOE3_LMAC2     = 38, //PSM_GPINT38,
	CNF10K_TX_GP_INT_RFOE3_LMAC3     = 39, //PSM_GPINT39,

	CNF10K_TX_GP_INT_RFOE4_LMAC0     = 40, //PSM_GPINT40,
	CNF10K_TX_GP_INT_RFOE4_LMAC1     = 41, //PSM_GPINT41

	CNF10K_TX_GP_INT_RFOE5_LMAC0     = 42, //PSM_GPINT42,
	CNF10K_TX_GP_INT_RFOE5_LMAC1     = 43, //PSM_GPINT43,

	CNF10K_TX_GP_INT_RFOE6_LMAC2     = 44, //PSM_GPINT44,
	CNF10K_TX_GP_INT_RFOE6_LMAC3     = 45, //PSM_GPINT45,
};
#else
enum bphy_netdev_tx_gp_int {
	CNF10K_TX_GP_INT_RFOE0_LMAC0     = 32, //PSM_GPINT32,
	CNF10K_TX_GP_INT_RFOE0_LMAC1     = 33, //PSM_GPINT33,
	CNF10K_TX_GP_INT_RFOE0_LMAC2     = 34, //PSM_GPINT34,
	CNF10K_TX_GP_INT_RFOE0_LMAC3     = 35, //PSM_GPINT35,

	CNF10K_TX_GP_INT_RFOE1_LMAC0     = 36, //PSM_GPINT36,
	CNF10K_TX_GP_INT_RFOE1_LMAC1     = 37, //PSM_GPINT37,
	CNF10K_TX_GP_INT_RFOE1_LMAC2     = 38, //PSM_GPINT38,
	CNF10K_TX_GP_INT_RFOE1_LMAC3     = 39, //PSM_GPINT39,
};
#endif

/**
 * @enum BPHY_NETDEV_CNF10K_RX_GP_INT_e_
 * @brief GP_INT numbers for packet notification by BPHY to netdev.
 *
 */
enum bphy_netdev_rx_gp_int {
	CNF10K_RX_GP_INT_RFOE0_PTP       = 63, //PSM_GPINT63,
	CNF10K_RX_GP_INT_RFOE0_ECPRI     = 62, //PSM_GPINT62,
	CNF10K_RX_GP_INT_RFOE0_GENERIC   = 61, //PSM_GPINT61,

	CNF10K_RX_GP_INT_RFOE1_PTP       = 60, //PSM_GPINT60,
	CNF10K_RX_GP_INT_RFOE1_ECPRI     = 59, //PSM_GPINT59,
	CNF10K_RX_GP_INT_RFOE1_GENERIC   = 58, //PSM_GPINT58,
#ifdef CNF10KB
	CNF10K_RX_GP_INT_RFOE2_PTP       = 57, //PSM_GPINT57,
	CNF10K_RX_GP_INT_RFOE2_ECPRI     = 56, //PSM_GPINT56,
	CNF10K_RX_GP_INT_RFOE2_GENERIC   = 55, //PSM_GPINT55,

	CNF10K_RX_GP_INT_RFOE3_PTP       = 54, //PSM_GPINT54,
	CNF10K_RX_GP_INT_RFOE3_ECPRI     = 53, //PSM_GPINT53,
	CNF10K_RX_GP_INT_RFOE3_GENERIC   = 52, //PSM_GPINT52,

	CNF10K_RX_GP_INT_RFOE4_PTP       = 51, //PSM_GPINT51,
	CNF10K_RX_GP_INT_RFOE4_ECPRI     = 50, //PSM_GPINT50,
	CNF10K_RX_GP_INT_RFOE4_GENERIC   = 49, //PSM_GPINT49,

	CNF10K_RX_GP_INT_RFOE5_PTP       = 48, //PSM_GPINT48,
	CNF10K_RX_GP_INT_RFOE5_ECPRI     = 47, //PSM_GPINT47,
	CNF10K_RX_GP_INT_RFOE5_GENERIC   = 46, //PSM_GPINT46,

	CNF10K_RX_GP_INT_RFOE6_PTP       = 66, //PSM_GPINT66,
	CNF10K_RX_GP_INT_RFOE6_ECPRI     = 65, //PSM_GPINT65,
	CNF10K_RX_GP_INT_RFOE6_GENERIC   = 64, //PSM_GPINT64,
#endif
};

/**
 * @struct BPHY_NETDEV_RBUF_INFO_s
 * @brief Information about the packet ring buffer which shall be used to
 *        send the packets from BPHY to netdev.
 *
 */
struct cnf10k_bphy_ndev_rbuf_info {
	enum bphy_netdev_packet_type pkt_type;
	enum bphy_netdev_rx_gp_int gp_int_num;
	u16 flow_id;
	u16 mbt_index;
	/**Maximum number of buffers in the Ring/Pool*/
	u16 num_bufs;
	/**MAX Buffer Size configured */
	u16 buf_size; // TBC: 1536?
	/**MBT byffer target memory*/
	u8 mbt_target_mem;
	/**Buffers starting address*/
	u64 mbt_iova_addr;
	u16 jdt_index;
	/**Maximum number of JD buffers in the Ring/Pool*/
	u16 num_jd;
	/**MAX JD size configured */
	u8 jd_size;
	/**MBT byffer target memory*/
	u8 jdt_target_mem;
	/**Buffers starting address*/
	u64 jdt_iova_addr;
	u64 reserved[4];
};

/**
 * @struct BPHY_NETDEV_TX_PSM_CMD_INFO_s
 * @brief TX PSM command information defnition to be shared with
 *        netdev for TX communication.
 *
 */
struct cnf10k_bphy_ndev_tx_psm_cmd_info {
	enum bphy_netdev_tx_gp_int gp_int_num; // Valid only for PTP messages
	u64 jd_iova_addr;
	u64 rd_dma_iova_addr;
	u64 low_cmd;
	u64 high_cmd;
	u64 reserved[4];
};

/**
 * @struct BPHY_NETDEV_TX_PTP_RING_INFO_s
 * @brief TX PTP timestamp ring buffer configuration to be shared
 *        with netdev for reading ptp timestamp.
 *
 */
struct cnf10k_bphy_ndev_tx_ptp_ring_info {
	u8 is_enable;
	u8 ring_idx;
	/**Number of TX PTP timestamp entries in ring */
	u8 ring_size;
	/**PTP Ring buffer target memory*/
	u8 ring_target_mem;
	/**PTP Ring buffer byte swap mode when TMEM is LLC/DRAM*/
	u8 dswap;
	/**Stream ID*/
	u8 gmid;
	/**Buffers starting address*/
	u64 ring_iova_addr;
	u64 reserved[4];
};

/**
 * @struct cnf10k_bphy_netdev_intf_info
 * @brief LMAC lane number, mac address and status information
 *
 */
struct cnf10k_bphy_ndev_intf_info {
	u8 rfoe_num;
	u8 lane_num;
	/* Source mac address */
	u8 eth_addr[ETH_ALEN];
	/* LMAC interface status */
	u8 status; //0-DOWN, 1-UP
	/* Configuration valid status; This interface shall be
	 * invalid if this field is set to 0
	 */
	u8 is_valid;
	u64 reserved;
};

/**
 * @struct BPHY_NETDEV_COMM_IF_s
 * @brief The communication interface defnitions which would be used
 *        by the netdev and bphy application.
 *
 */
struct cnf10k_bphy_ndev_comm_if {
	struct cnf10k_bphy_ndev_intf_info lmac_info;
	struct cnf10k_bphy_ndev_rbuf_info rbuf_info[PACKET_TYPE_MAX];
	/** Defining single array to handle both PTP and OTHER cmds info.
	 */
	struct cnf10k_bphy_ndev_tx_psm_cmd_info
					ptp_pkt_info[MAX_PTP_MSG_PER_LMAC];
	struct cnf10k_bphy_ndev_tx_ptp_ring_info
					ptp_ts_ring_info[MAX_PTP_RING];
	u64 reserved[4];
};

/**
 * @struct BPHY_NETDEV_CPRI_IF_s
 * @brief Communication interface structure defnition to be used by BPHY
 *        and NETDEV applications for CPRI Interface.
 *
 */
struct cnf10k_bphy_ndev_cpri_intf_cfg {
	u8 id;                 /**< CPRI_ID 0..2 */
	u8 active_lane_mask;   /**< Lane Id mask */
	u8 ul_gp_int_num;      /**< UL GP INT NUM */
	u8 ul_int_threshold;   /**< UL INT THRESHOLD */
	u8 num_ul_buf;         /**< Num UL Buffers */
	u8 num_dl_buf;         /**< Num DL Buffers */
	u64 ul_buf_iova_addr; /**< UL circular buffer base address */
	u64 dl_buf_iova_addr; /**< DL circular buffer base address */
	u8 eth_addr[MAX_LANE_PER_CPRI][ETH_ALEN];
	u64 reserved[4];
};

/**
 * @struct BPHY_NETDEV_RFOE_10x_IF_s
 * @brief New Communication interface structure defnition to be used
 *        by BPHY and NETDEV applications for RFOE Interface.
 *
 */
struct cnf10k_bphy_ndev_rfoe_if {
	/**< Interface configuration */
	struct cnf10k_bphy_ndev_comm_if if_cfg[MAX_LMAC_PER_RFOE];
	/**TX JD cmds to send packets other than PTP;
	 * These are defined per RFoE and all LMAC can share
	 */
	struct cnf10k_bphy_ndev_tx_psm_cmd_info
					oth_pkt_info[MAX_OTH_MSG_PER_RFOE];
	/**Packet types for which the RX flows are configured.*/
	u8 pkt_type_mask;
	u64 reserved[4];
};

/* hardware specific information */
struct bphy_hw_params {
	u32 chip_ver;		/* (version << 4) | revision */
	u32 reserved[15];	/* reserved for future extension */
};

/**
 * @struct BPHY_NETDEV_COMM_INTF_CFG_s
 * @brief ODP-NETDEV communication interface defnition structure to
 *        share the RX/TX intrefaces information.
 *
 */
struct cnf10k_rfoe_ndev_comm_intf_cfg {
	/**< BPHY Hardware parameters */
	struct bphy_hw_params hw_params;
	/**< RFOE Interface Configuration */
	struct cnf10k_bphy_ndev_rfoe_if rfoe_if_cfg[BPHY_MAX_RFOE_MHAB];
	u64 reserved[4];
};

/**
 * @struct BPHY_CPRI_NETDEV_COMM_INTF_CFG_s
 * @brief Main Communication interface structure definition to be used
 *        by BPHY and NETDEV applications for CPRI Interface.
 *
 */
struct cnf10k_bphy_cpri_netdev_comm_intf_cfg {
	/**< BPHY Hardware parameters */
	struct bphy_hw_params hw_params;
	/**< CPRI Interface Configuration */
	struct cnf10k_bphy_ndev_cpri_intf_cfg cpri_if_cfg[BPHY_MAX_CPRI_MHAB];
	u64 reserved[4];
};

#endif //_CNF10K_BPHY_NETDEV_COMM_IF_H_
