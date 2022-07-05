/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell MCS driver
 *
 * Copyright (C) 2022 Marvell.
 *
 */

#ifndef MCS_REG_H
#define MCS_REG_H

#include <linux/bits.h>

/* Registers */
#define MCSX_IP_MODE					0x900c8ull
#define MCSX_MIL_GLOBAL					0x80000ull
#define MCSX_MIL_RX_GBL_STATUS				0x800c8ull
#define MCSX_LINK_LMACX_CFG(a)				(0x90000ull + (a) * 0x800ull)
#define MCSX_MCS_TOP_SLAVE_CHANNEL_CFG(a)		(0x808ull + (a) * 0x8ull)

/* PEX registers */
#define MCSX_PEX_RX_SLAVE_VLAN_CFGX(a)			(0x3b58ull + (a) * 0x8ull)
#define MCSX_PEX_TX_SLAVE_VLAN_CFGX(a)			(0x46f8ull + (a) * 0x8ull)

/* CPM RX registers */
#define MCSX_CPM_RX_SLAVE_FLOWID_TCAM_DATAX(a, b)	(0x30740ull + (a) * 0x8ull + (b) * 0x20ull)
#define MCSX_CPM_RX_SLAVE_FLOWID_TCAM_MASKX(a, b)	(0x34740ull + (a) * 0x8ull + (b) * 0x20ull)
#define MCSX_CPM_RX_SLAVE_FLOWID_TCAM_ENA_0		0x30700ull
#define MCSX_CPM_RX_SLAVE_SC_CAMX(a, b)			(0x38780ull + (a) * 0x8ull + (b) * 0x10ull)
#define MCSX_CPM_RX_SLAVE_SC_CAM_ENA(a)			(0x38740ull + (a) * 0x8ull)
#define MCSX_CPM_RX_SLAVE_SECY_MAP_MEMX(a)		(0x23ee0ull + (a) * 0x8ull)
#define MCSX_CPM_RX_SLAVE_SECY_PLCY_MEM_0X(a)		(0x246e0ull + (a) * 0x10ull)
#define MCSX_CPM_RX_SLAVE_SA_MAP_MEMX(a)		(0x256e0ull + (a) * 0x8ull)
#define MCSX_CPM_RX_SLAVE_SA_PLCY_MEMX(a, b)		(0x27700ull + (a) * 0x8ull + (b) * 0x40ull)
#define MCSX_CPM_RX_SLAVE_SA_PN_TABLE_MEMX(a)		(0x2f700ull + (a) * 0x8ull)
#define MCSX_CPM_RX_SLAVE_PN_THRESHOLD			0x23e48ull
#define MCSX_CPM_RX_SLAVE_FLOWID_TCAM_ENA_1		0x30708ull
#define MCSX_CPM_RX_SLAVE_SECY_PLCY_MEM_1X(a)		(0x246e8ull + (a) * 0x10ull)
/* CPM TX registers */
#define MCSX_CPM_TX_SLAVE_FLOWID_TCAM_DATAX(a, b)	(0x51d50ull + (a) * 0x8ull + (b) * 0x20ull)
#define MCSX_CPM_TX_SLAVE_FLOWID_TCAM_MASKX(a, b)	(0x55d50ull + (a) * 0x8ull + (b) * 0x20ull)
#define MCSX_CPM_TX_SLAVE_FLOWID_TCAM_ENA_0		0x51d10ull
#define MCSX_CPM_TX_SLAVE_SECY_MAP_MEM_0X(a)		(0x3e508ull + (a) * 0x8ull)
#define MCSX_CPM_TX_SLAVE_SECY_PLCY_MEMX(a)		(0x3ed08ull + (a) * 0x8ull)
#define MCSX_CPM_TX_SLAVE_SA_MAP_MEM_0X(a)		(0x3fd10ull + (a) * 0x10ull)
#define MCSX_CPM_TX_SLAVE_SA_PLCY_MEMX(a, b)		(0x40d10ull + (a) * 0x8ull + (b) * 0x80ull)
#define MCSX_CPM_TX_SLAVE_SA_PN_TABLE_MEMX(a)		(0x50d10ull +  (a) * 0x8ull)
#define MCSX_CPM_TX_SLAVE_PN_THRESHOLD			0x3e4b8ull
#define MCSX_CPM_TX_SLAVE_SA_MAP_MEM_1X(a)		(0x3fd18ull + (a) * 0x10ull)
#define MCSX_CPM_TX_SLAVE_SECY_MAP_MEM_1X(a)		(0x5558ull + (a) * 0x10ull)
#define MCSX_CPM_TX_SLAVE_FLOWID_TCAM_ENA_1		0x51d18ull

/* PAB */
#define MCSX_PAB_RX_SLAVE_PORT_CFGX(a)			(0x1718ull + (a) * 0x40ull)
#define MCSX_PAB_TX_SLAVE_PORT_CFGX(a)			(0x2930ull + (a) * 0x40ull)
#endif
