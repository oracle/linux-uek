/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell BPHY Netdev Driver
 *
 * Copyright (C) 2021 Marvell.
 */

#ifndef _BPHY_NETDEV_COMM_IF_H_
#define _BPHY_NETDEV_COMM_IF_H_

/* Max LMAC's per RFOE MHAB */
#define MAX_LMAC_PER_RFOE		4

/* Max Lanes per CPRI MHAB */
#define MAX_LANE_PER_CPRI		4

#define MAX_PTP_MSG_PER_LMAC		4	/* 16 Per RFoE */
#define MAX_OTH_MSG_PER_LMAC		16	/* 64 Per RFoE */
/* 64 per RFoE; RFoE2 shall have 32 entries */
#define MAX_OTH_MSG_PER_RFOE		(MAX_OTH_MSG_PER_LMAC * MAX_LMAC_PER_RFOE)

/**
 * @enum bphy_netdev_if_type
 * @brief BPHY Interface Types
 *
 */
enum bphy_netdev_if_type {
	IF_TYPE_ETHERNET    = 0,
	IF_TYPE_CPRI        = 1,
	IF_TYPE_NONE        = 2,
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

#endif
