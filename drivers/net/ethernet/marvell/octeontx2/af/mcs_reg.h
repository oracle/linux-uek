/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell MCS driver
 *
 * Copyright (C) 2022 Marvell.
 */

#ifndef MCS_REG_H
#define MCS_REG_H

#include <linux/bits.h>

enum mcs_devtype {
	CN10KB_MCS,
	CNF10KB_MCS,
	CN20KA_MCS,
};

#define MCS_CHOOSE_OFFSET(a, b, c) ({\
	u64 off = -1;					\
							\
	switch (mcs->hw->mcs_devtype) {			\
	case CN10KB_MCS:				\
	off = a;					\
	break;						\
	case CNF10KB_MCS:				\
	off = b;					\
	break;						\
	case CN20KA_MCS:				\
	off = c;					\
	break;						\
	}						\
	off; })

/* Registers */
#define MCSX_IP_MODE					0x900c8ull
#define MCSX_MCS_TOP_SLAVE_PORT_RESET(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x408ull, 0xa28ull, 0x408ull);	\
	offset += (a) * 0x8ull;				\
	offset; })


#define MCSX_MCS_TOP_SLAVE_CHANNEL_CFG(a) ({		\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x808ull, 0xa68ull, 0x548ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_MIL_GLOBAL	({				\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x80000ull, 0x60000ull, 0x80000ull);	\
	offset; })

#define MCSX_MIL_RX_LMACX_CFG(a) ({			\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x900a8ull, 0x700a8ull, 0x900a8ull);	\
	offset += (a) * 0x800ull;			\
	offset; })

#define MCSX_HIL_GLOBAL ({				\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0xc0000ull, 0xa0000ull, 0xc0000ull);	\
	offset; })

#define MCSX_LINK_LMACX_CFG(a) ({			\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x90000ull, 0x70000ull, 0x90000ull);	\
	offset += (a) * 0x800ull;			\
	offset; })

#define MCSX_MIL_RX_GBL_STATUS ({			\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x800c8ull, 0x600c8ull, 0x800c8ull);	\
	offset; })

#define MCSX_MIL_IP_GBL_STATUS ({			\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x800d0ull, 0x600d0ull, 0x800d0ull);	\
	offset; })

/* PAB */
#define MCSX_PAB_RX_SLAVE_PORT_CFGX(a) ({	\
	u64 offset;				\
						\
	offset = MCS_CHOOSE_OFFSET(0x1718ull, 0x280ull, -1);		\
	offset += (a) * 0x40ull;		\
	offset; })

#define MCSX_PAB_TX_SLAVE_PORT_CFGX(a)			(0x2930ull + (a) * 0x40ull)

/* PEX registers */
#define MCSX_PEX_RX_SLAVE_VLAN_CFGX(a)		\
	MCS_CHOOSE_OFFSET(0x3b58ull, -1, 0x1370ull)
#define MCSX_PEX_TX_SLAVE_VLAN_CFGX(a)		\
	MCS_CHOOSE_OFFSET(0x46f8ull, -1, 0x1888ull)
#define MCSX_PEX_TX_SLAVE_CUSTOM_TAG_REL_MODE_SEL(a)	(0x788ull + (a) * 0x8ull)
#define MCSX_PEX_TX_SLAVE_PORT_CONFIG(a)	\
	MCS_CHOOSE_OFFSET(0x4738ull, -1, 0x18c8ull)
#define MCSX_PEX_RX_SLAVE_PORT_CFGX(a)		\
	MCS_CHOOSE_OFFSET(0x3b98ull, -1, 0x13b0ull)
#define MCSX_PEX_RX_SLAVE_RULE_ETYPE_CFGX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x3fc0ull, 0x558ull, -1);		\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_PEX_RX_SLAVE_RULE_DAX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x4000ull, 0x598ull, -1);		\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_PEX_RX_SLAVE_RULE_DA_RANGE_MINX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x4040ull, 0x5d8ull, -1);		\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_PEX_RX_SLAVE_RULE_DA_RANGE_MAXX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x4048ull, 0x5e0ull, -1);		\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_PEX_RX_SLAVE_RULE_COMBO_MINX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x4080ull, 0x648ull, -1);		\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_PEX_RX_SLAVE_RULE_COMBO_MAXX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x4088ull, 0x650ull, -1);		\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_PEX_RX_SLAVE_RULE_COMBO_ETX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x4090ull, 0x658ull, -1);		\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_PEX_RX_SLAVE_RULE_MAC ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x40e0ull, 0x6d8ull, -1);		\
	offset; })

#define MCSX_PEX_RX_SLAVE_RULE_ENABLE ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x40e8ull, 0x6e0ull, -1);		\
	offset; })

#define MCSX_PEX_TX_SLAVE_RULE_ETYPE_CFGX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x4b60ull, 0x7d8ull, -1);		\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_PEX_TX_SLAVE_RULE_DAX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x4ba0ull, 0x818ull, -1);		\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_PEX_TX_SLAVE_RULE_DA_RANGE_MINX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x4be0ull, 0x858ull, -1);		\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_PEX_TX_SLAVE_RULE_DA_RANGE_MAXX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x4be8ull, 0x860ull, -1);		\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_PEX_TX_SLAVE_RULE_COMBO_MINX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x4c20ull, 0x8c8ull, -1);		\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_PEX_TX_SLAVE_RULE_COMBO_MAXX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x4c28ull, 0x8d0ull, -1);		\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_PEX_TX_SLAVE_RULE_COMBO_ETX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x4c30ull, 0x8d8ull, -1);		\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_PEX_TX_SLAVE_RULE_MAC ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x4c80ull, 0x958ull, -1);		\
	offset; })

#define MCSX_PEX_TX_SLAVE_RULE_ENABLE ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x4c88ull, 0x960ull, -1);		\
	offset; })

#define MCSX_PEX_RX_SLAVE_PEX_CONFIGURATION ({		\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x3b50ull, 0x4c0ull, 0x2b030ull);	\
	offset; })

/* CNF10K-B */
#define MCSX_PEX_RX_SLAVE_CUSTOM_TAGX(a)        (0x4c8ull + (a) * 0x8ull)
#define MCSX_PEX_TX_SLAVE_CUSTOM_TAGX(a)        (0x748ull + (a) * 0x8ull)
#define MCSX_PEX_RX_SLAVE_ETYPE_ENABLE          0x6e8ull
#define MCSX_PEX_TX_SLAVE_ETYPE_ENABLE          0x968ull

/* BEE */
#define MCSX_BBE_RX_SLAVE_PADDING_CTL			0xe08ull
#define MCSX_BBE_TX_SLAVE_PADDING_CTL			0x12f8ull
#define MCSX_BBE_RX_SLAVE_CAL_ENTRY			0x180ull
#define MCSX_BBE_RX_SLAVE_CAL_LEN			0x188ull
#define MCSX_PAB_RX_SLAVE_FIFO_SKID_CFGX(a)		(0x290ull + (a) * 0x40ull)
#define MCSX_BBE_RX_SLAVE_DFIFO_OVERFLOW_0		0xe20
#define MCSX_BBE_TX_SLAVE_DFIFO_OVERFLOW_0		0x1298
#define MCSX_BBE_RX_SLAVE_PLFIFO_OVERFLOW_0		0xe40
#define MCSX_BBE_TX_SLAVE_PLFIFO_OVERFLOW_0		0x12b8
#define MCSX_BBE_RX_SLAVE_BBE_INT ({	\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0xe00ull, 0x160ull, 0xe00ull);	\
	offset; })

#define MCSX_BBE_RX_SLAVE_BBE_INT_ENB ({	\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0xe08ull, 0x168ull, 0xe08ull);	\
	offset; })

#define MCSX_BBE_RX_SLAVE_BBE_INT_INTR_RW ({	\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0xe08ull, 0x178ull, 0xe08ull);	\
	offset; })

#define MCSX_BBE_TX_SLAVE_BBE_INT ({	\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0x1278ull, 0x1e0ull, 0x1278ull);	\
	offset; })

#define MCSX_BBE_TX_SLAVE_BBE_INT_INTR_RW ({	\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0x1278ull, 0x1f8ull, 0x1278ull);	\
	offset; })

#define MCSX_BBE_TX_SLAVE_BBE_INT_ENB ({	\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0x1280ull, 0x1e8ull, 0x1280ull);	\
	offset; })

#define MCSX_PAB_RX_SLAVE_PAB_INT ({	\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0x16f0ull, 0x260ull, 0x16f0ull);	\
	offset; })

#define MCSX_PAB_RX_SLAVE_PAB_INT_ENB ({	\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0x16f8ull, 0x268ull, 0x16f8ull);	\
	offset; })

#define MCSX_PAB_RX_SLAVE_PAB_INT_INTR_RW ({	\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0x16f8ull, 0x278ull, 0x16f8ull);	\
	offset; })

#define MCSX_PAB_TX_SLAVE_PAB_INT ({	\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0x2908ull, 0x380ull, 0x2908ull);	\
	offset; })

#define MCSX_PAB_TX_SLAVE_PAB_INT_ENB ({	\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0x2910ull, 0x388ull, 0x2910ull);	\
	offset; })

#define MCSX_PAB_TX_SLAVE_PAB_INT_INTR_RW ({	\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0x16f8ull, 0x398ull, 0x16f8ull);	\
	offset; })

/* CPM registers */
#define MCSX_CPM_RX_SLAVE_FLOWID_TCAM_DATAX(a, b) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x30740ull, 0x3bf8ull, 0x1a678ull);	\
	offset += (a) * 0x8ull + (b) * 0x20ull;		\
	offset; })

#define MCSX_CPM_RX_SLAVE_FLOWID_TCAM_MASKX(a, b) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x34740ull, 0x43f8ull, 0x1b678ull);	\
	offset += (a) * 0x8ull + (b) * 0x20ull;		\
	offset; })

#define MCSX_CPM_RX_SLAVE_FLOWID_TCAM_ENA_0 ({		\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x30700ull, 0x3bd8ull, 0x1a658ull);	\
	offset; })

#define MCSX_CPM_RX_SLAVE_SC_CAMX(a, b)	({		\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x38780ull, 0x4c08ull, 0x1ce98ull);	\
	offset +=  (a) * 0x8ull + (b) * 0x10ull;	\
	offset; })

#define MCSX_CPM_RX_SLAVE_SC_CAM_ENA(a)	({		\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x38740ull, 0x4bf8ull, 0x1ce88ull);	\
	offset += (a) * 0x8ull;				\
	offset; })
#define MCSX_CPM_RX_SLAVE_SECY_MAP_MEMX(a) ({		\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x23ee0ull, 0xbd0ull, 0x12a40ll);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CPM_RX_SLAVE_SECY_PLCY_MEM_0X(a) ({	\
	u64 offset = -1;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x246e0ull, 0xdd0ull, 0x12e48ll);	\
	switch (mcs->hw->mcs_devtype) {			\
	case CN10KB_MCS:				\
	case CN20KA_MCS:				\
	offset += (a) * 0x10ull;			\
	break;						\
	case CNF10KB_MCS:				\
	offset += (a) * 0x8ull;				\
	break;						\
	}						\
	offset;						\
	})

#define SECY_PLCY_MEM_MTU_MASK	({			\
	u64 mask = 0;					\
							\
	switch (mcs->hw->mcs_devtype) {			\
	case CN10KB_MCS:				\
	case CNF10KB_MCS:				\
	mask = GENMASK_ULL(43, 28);			\
	break;						\
	case CN20KA_MCS:				\
	mask = GENMASK_ULL(44, 29);			\
	break;						\
	}						\
	mask;						\
	})

#define MCSX_CPM_RX_SLAVE_SA_KEY_LOCKOUTX(a) ({		\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x23E90ull, 0xbb0ull, 0x12a10ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CPM_RX_SLAVE_SA_MAP_MEMX(a) ({		\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x256e0ull, 0xfd0ull, 0x13648ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CPM_RX_SLAVE_SA_PLCY_MEMX(a, b) ({		\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x27700ull, 0x17d8ull, 0x14658ull);	\
	offset +=  (a) * 0x8ull + (b) * 0x40ull;	\
	offset; })

#define MCSX_CPM_RX_SLAVE_SA_PN_TABLE_MEMX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x2f700ull, 0x37d8, 0x18658ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CPM_RX_SLAVE_XPN_THRESHOLD	({		\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x23e40ull, 0xb90ull, -1);	\
	offset; })

#define MCSX_CPM_RX_SLAVE_PN_THRESHOLD	({		\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x23e48ull, 0xb98ull, -1);	\
	offset; })

#define MCSX_CPM_RX_SLAVE_PN_THRESH_REACHEDX(a)	({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x23e50ull, 0xba0ull, -1);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CPM_RX_SLAVE_FLOWID_TCAM_ENA_1		\
	MCS_CHOOSE_OFFSET(0x30708ull, -1, 0x1a660ll)

#define MCSX_CPM_RX_SLAVE_SECY_PLCY_MEM_1X(a)	({	\
	u64 offset;					\
							\
	offset =  MCS_CHOOSE_OFFSET(0x246e8ull, -1, 0x12e50ull);	\
	offset += (a) * 0x10ull;		\
	offset; })

/* TX registers */
#define MCSX_CPM_TX_SLAVE_FLOWID_TCAM_DATAX(a, b) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x51d50ull, 0xa7c0ull, 0x28608ull);	\
	offset += (a) * 0x8ull + (b) * 0x20ull;		\
	offset; })

#define MCSX_CPM_TX_SLAVE_FLOWID_TCAM_MASKX(a, b) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x55d50ull, 0xafc0ull, 0x29608ull);	\
	offset += (a) * 0x8ull + (b) * 0x20ull;		\
	offset; })

#define MCSX_CPM_TX_SLAVE_FLOWID_TCAM_ENA_0 ({		\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x51d10ull, 0xa7a0ull, 0x285e8ull);	\
	offset; })

#define MCSX_CPM_TX_SLAVE_SECY_MAP_MEM_0X(a) ({		\
	u64 offset = -1;					\
							\
	offset =  MCS_CHOOSE_OFFSET(0x3e508ull, 0x5550ull, 0x1ddb8ull);	\
	switch (mcs->hw->mcs_devtype) {			\
	case CN10KB_MCS:				\
	case CN20KA_MCS:				\
	offset += (a) * 0x8ull;				\
	break;						\
	case CNF10KB_MCS:				\
	offset += (a) * 0x10ull;			\
	break;						\
	}						\
	offset; })

#define MCSX_CPM_TX_SLAVE_SECY_PLCY_MEMX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x3ed08ull, 0x5950ull, 0x1e1b8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CPM_TX_SLAVE_SA_KEY_LOCKOUTX(a) ({		\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x3e4c0ull, 0x5538ull, 0x1dd90ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CPM_TX_SLAVE_SA_MAP_MEM_0X(a) ({		\
	u64 offset = -1;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x3fd10ull, 0x6150ull, 0x1e5b8ull);	\
	switch (mcs->hw->mcs_devtype) {			\
	case CN10KB_MCS:				\
	case CN20KA_MCS:				\
	offset += (a) * 0x10ull;			\
	break;						\
	case CNF10KB_MCS:				\
	offset += (a) * 0x8ull;				\
	break;						\
	}						\
	offset; })

#define MCSX_CPM_TX_SLAVE_SA_PLCY_MEMX(a, b) ({		\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x40d10ull, 0x63a0ull, 0x1ede8ull);	\
	offset += (a) * 0x8ull + (b) * 0x80ull;		\
	offset; })

#define MCSX_CPM_TX_SLAVE_SA_PN_TABLE_MEMX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x50d10ull, 0xa3a0ull, 0x26de8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CPM_TX_SLAVE_XPN_THRESHOLD ({		\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x3e4b0ull, 0x5528ull, 0x3e4b0ull);	\
	offset; })

#define MCSX_CPM_TX_SLAVE_PN_THRESHOLD ({		\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x3e4b8ull, 0x5530ull, 0x3e4b8ull);	\
	offset; })

#define MCSX_CPM_TX_SLAVE_SA_MAP_MEM_1X(a) ({	\
	u64 offset;					\
							\
	offset =  MCS_CHOOSE_OFFSET(0x3fd18ull, -1, 0x1e5c0ull);	\
	offset += (a) * 0x10ull;				\
	offset; })

#define MCSX_CPM_TX_SLAVE_SECY_MAP_MEM_1X(a)		(0x5558ull + (a) * 0x10ull)

#define MCSX_CPM_TX_SLAVE_FLOWID_TCAM_ENA_1 ({		\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x51d18ull, 0xa7a8ull, 0x285f0ull);	\
	offset; })

/* cnf10kb specific */
#define MCSX_CPM_TX_SLAVE_TX_SA_ACTIVEX(a)		(0x5b50 + (a) * 0x8ull)
#define MCSX_CPM_TX_SLAVE_SA_INDEX0_VLDX(a)		(0x5d50 + (a) * 0x8ull)
#define MCSX_CPM_TX_SLAVE_SA_INDEX1_VLDX(a)		(0x5f50 + (a) * 0x8ull)
#define MCSX_CPM_TX_SLAVE_AUTO_REKEY_ENABLE_0		0x5500ull

/* CSE */
#define MCSX_CSE_RX_MEM_SLAVE_IFINCTLBCPKTSX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x9e80ull, 0xc218ull, 0x41f8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_IFINCTLMCPKTSX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x9680ull, 0xc018ull, 0x3df8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_IFINCTLOCTETSX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x6e80ull, 0xbc18ull, 0x29f8ull);	\
	offset +=  (a) * 0x8ull;			\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_IFINCTLUCPKTSX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x8e80ull, 0xbe18ull, 0x39f8ull);	\
	offset +=  (a) * 0x8ull;			\
	offset; })

#define	MCSX_CSE_RX_MEM_SLAVE_IFINUNCTLBCPKTSX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x8680ull, 0xca18ull, 0x35f8ull);	\
	offset +=  (a) * 0x8ull;			\
	offset; })

#define	MCSX_CSE_RX_MEM_SLAVE_IFINUNCTLMCPKTSX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x7e80ull, 0xc818ull, 0x31f8ull);	\
	offset +=  (a) * 0x8ull;			\
	offset; })

#define	MCSX_CSE_RX_MEM_SLAVE_IFINUNCTLOCTETSX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x6680ull, 0xc418ull, 0x25f8ull);	\
	offset +=  (a) * 0x8ull;			\
	offset; })

#define	MCSX_CSE_RX_MEM_SLAVE_IFINUNCTLUCPKTSX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x7680ull, 0xc618ull, 0x2df8ull);	\
	offset +=  (a) * 0x8ull;			\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_INOCTETSSECYDECRYPTEDX(a) ({ \
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x5e80ull, 0xdc18ull, 0x21f8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_INOCTETSSECYVALIDATEX(a)({ \
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x5680ull, 0xda18ull, 0x1df8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_INPKTSCTRLPORTDISABLEDX(a) ({ \
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0xd680ull, 0xce18ull, -1);		\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_INPKTSFLOWIDTCAMHITX(a) ({ \
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x16a80ull, 0xec78ull, 0xb6d8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_INPKTSFLOWIDTCAMMISSX(a) ({ \
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x16680ull, 0xec38ull, 0xb3b8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_INPKTSPARSEERRX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x16880ull, 0xec18ull, 0xb458ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_INPKTSSCCAMHITX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0xfe80ull, 0xde18ull, 0x71f8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_INPKTSSCINVALIDX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x10680ull, 0xe418ull, 0x75f8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_INPKTSSCNOTVALIDX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x10e80ull, 0xe218ull, 0x79f8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_INPKTSSECYBADTAGX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0xae80ull, 0xd418ull, 0x49f8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_INPKTSSECYNOSAX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0xc680ull, 0xd618ull, 0x55f8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_INPKTSSECYNOSAERRORX(a) ({ \
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0xce80ull, 0xd818ull, 0x59f8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_INPKTSSECYTAGGEDCTLX(a) ({ \
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0xbe80ull, 0xcc18ull, 0x51f8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_RX_SLAVE_CTRL	({			\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x52a0ull, 0x9c0ull, 0x1d98ull);	\
	offset; })

#define MCSX_CSE_RX_SLAVE_STATS_CLEAR	({		\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x52b8ull, 0x9d8ull, 0x1db0ull);	\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_INPKTSSCUNCHECKEDX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0xee80ull, 0xe818ull, 0x69f8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_INPKTSSECYUNTAGGEDX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0xa680ull, 0xd018ull, 0x45f8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_INPKTSSCLATEORDELAYEDX(a)	({	\
	u64 offset;						\
								\
	offset = MCS_CHOOSE_OFFSET(0xf680ull, 0xe018ull, 0x6df8ull);	\
	offset += (a) * 0x8ull;					\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_INOCTETSSCDECRYPTEDX(a) ({	\
	u64 offset;						\
								\
	offset = MCS_CHOOSE_OFFSET(0xe680ull, -1, 0x65f8ull);	\
	offset += (a) * 0x8ull;					\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_INOCTETSSCVALIDATEX(a) ({	\
	u64 offset;						\
								\
	offset = MCS_CHOOSE_OFFSET(0xde80ull, -1, 0x61f8ull);	\
	offset += (a) * 0x8ull;					\
	offset; })

#define MCSX_CSE_RX_MEM_SLAVE_INPKTSSECYNOTAGX(a)	(0xd218 + (a) * 0x8ull)
#define MCSX_CSE_RX_MEM_SLAVE_INPKTSSECYCTLX(a)	 ({	\
	u64 offset;						\
								\
	offset = MCS_CHOOSE_OFFSET(0xb680ull, -1, 0x4df8ull);	\
	offset += (a) * 0x8ull;					\
	offset; })

/* Not available in cn20k */
#define MCSX_CSE_RX_MEM_SLAVE_INPKTSEARLYPREEMPTERRX(a) (0xec58ull + (a) * 0x8ull)
#define MCSX_CSE_RX_MEM_SLAVE_INPKTSSCOKX(a)		(0xea18ull + (a) * 0x8ull)
#define MCSX_CSE_RX_MEM_SLAVE_INPKTSSCDELAYEDX(a)	(0xe618ull + (a) * 0x8ull)

/* CSE TX */
#define MCSX_CSE_TX_MEM_SLAVE_IFOUTCOMMONOCTETSX(a) ({	\
	u64 offset;						\
								\
	offset = MCS_CHOOSE_OFFSET(0x18440ull, -1, 0xc2d8ull);	\
	offset += (a) * 0x8ull;					\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_IFOUTCTLBCPKTSX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x1c440ull, 0xf478ull, 0xe2d8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_IFOUTCTLMCPKTSX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x1bc40ull, 0xf278ull, 0xded8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_IFOUTCTLOCTETSX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x19440ull, 0xee78ull, 0xcad8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_IFOUTCTLUCPKTSX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x1b440ull, 0xf078ull, 0xdad8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_IFOUTUNCTLBCPKTSX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x1ac40ull, 0xfc78ull, 0xd6d8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_IFOUTUNCTLMCPKTSX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x1a440ull, 0xfa78ull, 0xd2d8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_IFOUTUNCTLOCTETSX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x18c40ull, 0xf678ull, 0xc6d8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_IFOUTUNCTLUCPKTSX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x19c40ull, 0xf878ull, 0xced8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_OUTOCTETSSECYENCRYPTEDX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x17c40ull, 0x10878ull, 0xbed8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_OUTOCTETSSECYPROTECTEDX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x17440ull, 0x10678ull, 0xbad8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_OUTPKTSCTRLPORTDISABLEDX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x1e440ull, 0xfe78ull, 0xf2d8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_OUTPKTSFLOWIDTCAMHITX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x23240ull, 0x10ed8ull, 0x12358ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_OUTPKTSFLOWIDTCAMMISSX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x22c40ull, 0x10e98ull, 0x12178ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_OUTPKTSPARSEERRX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x22e40ull, 0x10e78ull, 0x12218ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_OUTPKTSSCENCRYPTEDX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x20440ull, 0x10c78ull, 0x102d8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_OUTPKTSSCPROTECTEDX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x1fc40ull, 0x10a78ull, 0xfed8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_OUTPKTSSECTAGINSERTIONERRX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x23040ull, 0x110d8ull, 0x122b8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_OUTPKTSSECYNOACTIVESAX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x1dc40ull, 0x10278ull, 0xeed8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })
#define MCSX_CSE_TX_MEM_SLAVE_OUTPKTSSECYTOOLONGX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x1d440ull, 0x10478ull, 0xead8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_OUTPKTSSECYUNTAGGEDX(a) ({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x1cc40ull, 0x10078ull, 0xe6d8ull);	\
	offset += (a) * 0x8ull;				\
	offset; })

#define MCSX_CSE_TX_SLAVE_CTRL	({	\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x54a0ull, 0xa00ull, 0x1dd8ull);	\
	offset; })

#define MCSX_CSE_TX_SLAVE_STATS_CLEAR ({		\
	u64 offset;					\
							\
	offset = MCS_CHOOSE_OFFSET(0x54b8ull, 0xa18ull, 0x1df0ull);	\
	offset; })

#define MCSX_CSE_TX_MEM_SLAVE_OUTPKTSEARLYPREEMPTERRX(a) (0x10eb8ull + (a) * 0x8ull)

#define MCSX_IP_INT ({			\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0x80028ull, 0x60028ull, 0x80028ull);	\
	offset; })

#define MCSX_IP_INT_ENA_W1S ({		\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0x80040ull, 0x60040ull, 0x80040ull);	\
	offset; })

#define MCSX_IP_INT_ENA_W1C ({		\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0x80038ull, 0x60038ull, 0x80038ull);	\
	offset; })

#define MCSX_TOP_SLAVE_INT_SUM ({	\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0xc20ull, 0xab8ull, 0xc20ull);	\
	offset; })

#define MCSX_TOP_SLAVE_INT_SUM_ENB ({	\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0xc28ull, 0xac0ull, 0xc28ull);	\
	offset; })

#define MCSX_CPM_RX_SLAVE_RX_INT ({	\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0x23c00ull, 0x0ad8ull, 0x23c00ull);	\
	offset; })

#define MCSX_CPM_RX_SLAVE_RX_INT_ENB ({	\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0x23c08ull, 0xae0ull, 0x23c08ull);	\
	offset; })

#define MCSX_CPM_TX_SLAVE_TX_INT ({	\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0x3d490ull, 0x54a0ull, 0x3d490ull);	\
	offset; })

#define MCSX_CPM_TX_SLAVE_TX_INT_ENB ({	\
	u64 offset;			\
					\
	offset = MCS_CHOOSE_OFFSET(0x3d498ull, 0x54a8ull, 0x3d498ull);	\
	offset; })

#endif
