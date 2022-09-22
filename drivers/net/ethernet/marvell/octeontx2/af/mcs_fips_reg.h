/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell CN10K MCS driver
 *
 * Copyright (C) 2022 Marvell.
 *
 */

#define MCSX_GAE_RX_SLAVE_FIPS_RESET	({		\
	u64 offset;					\
							\
	offset = 0x18ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0x0ull;			\
	offset; })

#define MCSX_GAE_TX_SLAVE_FIPS_RESET	({		\
	u64 offset;					\
							\
	offset = 0x218ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0xB0ull;			\
	offset; })

#define MCSX_GAE_RX_SLAVE_FIPS_MODE	({		\
	u64 offset;					\
							\
	offset = 0x28ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0x8ull;			\
	offset; })

#define MCSX_GAE_TX_SLAVE_FIPS_MODE	({		\
	u64 offset;					\
							\
	offset = 0x228ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0xB8ull;			\
	offset; })

#define MCSX_GAE_RX_SLAVE_FIPS_CTL	({		\
	u64 offset;					\
							\
	offset = 0x30ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0x10ull;			\
	offset; })

#define MCSX_GAE_TX_SLAVE_FIPS_CTL	({		\
	u64 offset;					\
							\
	offset = 0x230ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0xC0ull;			\
	offset; })

#define MCSX_GAE_RX_SLAVE_FIPS_IV_BITS95_64	({	\
	u64 offset;					\
							\
	offset = 0x40ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0x18ull;			\
	offset; })

#define MCSX_GAE_RX_SLAVE_FIPS_IV_BITS63_0	({	\
	u64 offset;					\
							\
	offset = 0x48ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0x20ull;			\
	offset; })

#define MCSX_GAE_TX_SLAVE_FIPS_IV_BITS95_64	({	\
	u64 offset;					\
							\
	offset = 0x240ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0xC8ull;			\
	offset; })

#define MCSX_GAE_TX_SLAVE_FIPS_IV_BITS63_0	({	\
	u64 offset;					\
							\
	offset = 0x248ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0xD0ull;			\
	offset; })

#define MCSX_GAE_RX_SLAVE_FIPS_CTR	({		\
	u64 offset;					\
							\
	offset = 0x50ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0x28ull;			\
	offset; })

#define MCSX_GAE_TX_SLAVE_FIPS_CTR	({		\
	u64 offset;					\
							\
	offset = 0x250ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0xD8ull;			\
	offset; })

#define MCSX_GAE_RX_SLAVE_FIPS_SAK_BITS255_192	({	\
	u64 offset;					\
							\
	offset = 0x58ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0x30ull;			\
	offset; })

#define MCSX_GAE_RX_SLAVE_FIPS_SAK_BITS191_128	({	\
	u64 offset;					\
							\
	offset = 0x60ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0x38ull;			\
	offset; })

#define MCSX_GAE_RX_SLAVE_FIPS_SAK_BITS127_64	({	\
	u64 offset;					\
							\
	offset = 0x68ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0x40ull;			\
	offset; })

#define MCSX_GAE_RX_SLAVE_FIPS_SAK_BITS63_0	({	\
	u64 offset;					\
							\
	offset = 0x70ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0x48ull;			\
	offset; })

#define MCSX_GAE_TX_SLAVE_FIPS_SAK_BITS255_192	({	\
	u64 offset;					\
							\
	offset = 0x258ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0xE0ull;			\
	offset; })

#define MCSX_GAE_TX_SLAVE_FIPS_SAK_BITS191_128	({	\
	u64 offset;					\
							\
	offset = 0x260ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0xE8ull;			\
	offset; })

#define MCSX_GAE_TX_SLAVE_FIPS_SAK_BITS127_64	({	\
	u64 offset;					\
							\
	offset = 0x268ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0xF0ull;			\
	offset; })

#define MCSX_GAE_TX_SLAVE_FIPS_SAK_BITS63_0	({	\
	u64 offset;					\
							\
	offset = 0x270ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0xF8ull;			\
	offset; })

#define MCSX_GAE_RX_SLAVE_FIPS_HASHKEY_BITS127_64	({	\
	u64 offset;						\
								\
	offset = 0x78ull;					\
	if (mcs->hw->mcs_blks > 1)				\
		offset = 0x50ull;				\
	offset; })

#define MCSX_GAE_RX_SLAVE_FIPS_HASHKEY_BITS63_0	({	\
	u64 offset;					\
							\
	offset = 0x80ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0x58ull;			\
	offset; })

#define MCSX_GAE_TX_SLAVE_FIPS_HASHKEY_BITS127_64	({	\
	u64 offset;						\
								\
	offset = 0x278ull;					\
	if (mcs->hw->mcs_blks > 1)				\
		offset = 0x100ull;				\
	offset; })

#define MCSX_GAE_TX_SLAVE_FIPS_HASHKEY_BITS63_0	({	\
	u64 offset;					\
							\
	offset = 0x280ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0x108ull;			\
	offset; })

#define MCSX_GAE_RX_SLAVE_FIPS_BLOCK_BITS127_64	({	\
	u64 offset;					\
							\
	offset = 0x60ull;				\
	offset; })

#define MCSX_GAE_RX_SLAVE_FIPS_BLOCK_BITS63_0	({	\
	u64 offset;					\
							\
	offset = 0x88ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0x68ull;			\
	offset; })

#define MCSX_GAE_TX_SLAVE_FIPS_BLOCK_BITS127_64	({	\
	u64 offset;					\
							\
	offset = 0x110ull;				\
	offset; })

#define MCSX_GAE_TX_SLAVE_FIPS_BLOCK_BITS63_0	({	\
	u64 offset;					\
							\
	offset = 0x288ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0x118ull;			\
	offset; })

#define MCSX_GAE_RX_SLAVE_FIPS_START	({		\
	u64 offset;					\
							\
	offset = 0x20ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0x70ull;			\
	offset; })

#define MCSX_GAE_TX_SLAVE_FIPS_START	({		\
	u64 offset;					\
							\
	offset = 0x220ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0x120ull;			\
	offset; })

#define MCSX_GAE_RX_SLAVE_FIPS_RESULT_BLOCK_BITS127_64	({	\
	u64 offset;						\
								\
	offset = 0x78ull;					\
	offset; })

#define MCSX_GAE_RX_SLAVE_FIPS_RESULT_BLOCK_BITS63_0	({	\
	u64 offset;						\
								\
	offset = 0xA0ull;					\
	if (mcs->hw->mcs_blks > 1)				\
		offset = 0x80ull;				\
	offset; })

#define MCSX_GAE_RX_SLAVE_FIPS_RESULT_PASS	({	\
	u64 offset;					\
							\
	offset = 0xA8ull;				\
	if (mcs->hw->mcs_blks > 1)			\
		offset = 0x88ull;			\
	offset; })

#define MCSX_GAE_RX_SLAVE_FIPS_RESULT_ICV_BITS127_64	({	\
	u64 offset;						\
								\
	offset = 0xB0ull;					\
	if (mcs->hw->mcs_blks > 1)				\
		offset = 0x90ull;				\
	offset; })

#define MCSX_GAE_RX_SLAVE_FIPS_RESULT_ICV_BITS63_0	({	\
	u64 offset;						\
								\
	offset = 0xB8ull;					\
	if (mcs->hw->mcs_blks > 1)				\
		offset = 0x98ull;				\
	offset; })

#define MCSX_GAE_TX_SLAVE_FIPS_RESULT_BLOCK_BITS127_64	({	\
	u64 offset;						\
								\
	offset = 0x128ull;					\
	offset; })

#define MCSX_GAE_TX_SLAVE_FIPS_RESULT_BLOCK_BITS63_0	({	\
	u64 offset;						\
								\
	offset = 0x2A0ull;					\
	if (mcs->hw->mcs_blks > 1)				\
		offset = 0x130ull;				\
	offset; })

#define MCSX_GAE_TX_SLAVE_FIPS_RESULT_ICV_BITS127_64	({	\
	u64 offset;						\
								\
	offset = 0x2B0ull;					\
	if (mcs->hw->mcs_blks > 1)				\
		offset = 0x140ull;				\
	offset; })

#define MCSX_GAE_TX_SLAVE_FIPS_RESULT_ICV_BITS63_0	({	\
	u64 offset;						\
								\
	offset = 0x2B8ull;					\
	if (mcs->hw->mcs_blks > 1)				\
		offset = 0x148ull;				\
	offset; })
