/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU AF REE extension
 *
 * Copyright (C) 2023 Marvell.
 *
 */

#ifndef __RVU_DPI_MBOX_H__
#define __RVU_DPI_MBOX_H__

/* DPI RVU registers */
#define DPI_AF_RVU_LF_CFG_DEBUG		(0x4000ull)
#define DPI_PRIV_LFX_CFG		(0x2000ull)
#define DPI_PRIV_LFX_INT_CFG(a)		(0x3000ull | (u64)(a) << 3)
#define DPI_AF_DMA_CONTROL		(0x00ull)
#define DPI_AF_LF_RST			(0x10ull)
#define DPI_AF_CTL			(0x20ull)
#define DPI_AF_ENGX_BUF(a)		(0x40ull | (u64)(a) << 3)
#define DPI_AF_ENGX_RATE_CTRL(a)	(0x80ull | (u64)(a) << 3)
#define DPI_AF_ENGX_CFG(a)		(0xc0ull | (u64)(a) << 3)
#define DPI_AF_NCB_CFG			(0x100ull)
#define DPI_AF_ENG_BUF_TH_LIMIT		(0x110ull)
#define DPI_AF_SDP_OPKT_RATE_CTRL	(0x120ull)
#define DPI_LF_RINGX_ERR_STAT(a)	(0x120ull | (u64)(a) << 3)
#define DPI_AF_BPHYX_OPKT_RATE_CTRL(a)	(0x130ull | (u64)(a) << 3)
#define DPI_AF_PSWX_OPKT_RATE_CTRL(a)	(0x140ull | (u64)(a) << 3)
#define DPI_AF_EBUS_PORTX_CFG(a)	(0x480ull | (u64)(a) << 3)
#define DPI_AF_STAT_CTRL		(0x1000ull)
#define DPI_AF_STAT0			(0x1008ull)
#define DPI_AF_STAT1(a)			(0x1010ull)
#define DPI_AF_STAT2(a)			(0x1018ull)
#define DPI_AF_LFX_PF_VF_CFG(a)		(0x2800ull | (u64)(a) << 3)
#define DPI_AF_CHAN_INVLDT		(0x13000ull)
#define DPI_AF_CHAN_HSEL		(0x13008ull)
#define DPI_AF_LFX_ACCESS(a)		(0x14000ull | (u64)(a) << 3)
#define DPI_PRIV_AF_INT_CFG		(0x4008ull)
#define DPI_AF_BAR2_SEL			(0x9000000ull)
#define DPI_AF_CHAN_TBLX_CFG(a)		(0x10000ull | (u64)(a) << 3)
#define DPI_AF_CHAN_LFX_CFG(a)		(0x10800ull | (u64)(a) << 3)
#define DPI_AF_LFX_RINGX_CFG(a, b)	\
		(0x11000ull | ((a) * 0x10) | (u64)(b) << 3)
#define DPI_AF_LFX_RINGX_CHAN_CFG(a, b)	\
		(0x12000ull | ((a) * 0x10) | (u64)(b) << 3)
#define DPI_AF_GROUPX_KEYX(a, b)		\
		(0x18000ull | (u64)(a) << 9 | (u64)(b) << 3)
#define DPI_AF_LFX_RANGE_STARTX(a, b)	\
		(0x20000ull | (u64)(a) << 5 | (u64)(b) << 3)
#define DPI_AF_LFX_RANGE_ENDX(a, b)	\
		(0x22000ull | (u64)(a) << 5 | (u64)(b) << 3)
#define DPI_AF_BAR2_ALIASX(a)		(0x9100000ull | (u64)(a) << 3)
#define DPI_MAX_LF			256
#define DPI_MAX_CHAN_TBL		256
#define DPI_RD_FIFO_MAX_TH		32
#define DPI_NCB_MAX_MOLR		511
#define DPI_EBUS_MAX_MOLR		512

#define DPI_AF_EPFX_VF_STATX(a, b)	(0xc00ull | (0x20 * (a)) | ((b) << 3))

#define DPI_LF_RINGX_CFG(a, b)		\
		(0x20ull | (u64)(a) << 20 | (u64)(b) << 3)
#define DPI_AF_CONST			(0x1038ull)

#endif /* __RVU_DPI_MBOX_H__ */
