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

/* DPI Transfer Type Enumeration */
enum DPI_LF_XTYPE_E {
	OUTBOUND	=	0x0,
	INBOUND		=	0x1,
	INTERNAL	=	0x2,
	EXTERNAL	=	0x3,
};

/* DPI mbox IDs (range 0xC000 - 0xCFFF) */
#define MBOX_EBLOCK_DPI_MESSAGES					\
M(DPI_ATTACH_RESOURCES, 0xc000, dpi_attach_resources,			\
				dpi_rsrc_attach_req, msg_rsp)		\
M(DPI_DETACH_RESOURCES, 0xc001, dpi_detach_resources,			\
				dpi_rsrc_detach_req, msg_rsp)		\
M(DPI_LF_RING_CFG,	0xc002, dpi_lf_ring_cfg,			\
				dpi_lf_ring_cfg_req, msg_rsp)		\
M(DPI_LF_PF_FUNC_CFG,	0xc003, dpi_lf_pf_func_cfg,			\
				dpi_lf_pf_func_cfg_req, msg_rsp)	\
M(DPI_LF_FREE,		0xc004, dpi_lf_free, msg_req, msg_rsp)		\
M(DPI_FREE_RSRC_CNT,	0xc005, dpi_free_rsrc_cnt, msg_req,		\
				dpi_free_rsrcs_rsp)			\
M(DPI_LF_CHAN_CFG,	0xc006, dpi_lf_chan_cfg,			\
				dpi_lf_chan_cfg_req, msg_rsp)

enum {
#define M(_name, _id, _1, _2, _3) MBOX_MSG_ ## _name = _id,
	MBOX_EBLOCK_DPI_MESSAGES
#undef M
};

/* DPI mailbox error codes
 * Range 1201 - 1300.
 */
enum dpi_af_status {
	DPI_AF_ERR_PARAM		= -1201,
	DPI_AF_ERR_GRP_INVALID		= -1202,
	DPI_AF_ERR_LF_INVALID		= -1203,
	DPI_AF_ERR_ACCESS_DENIED	= -1204,
	DPI_AF_ERR_SSO_PF_FUNC_INVALID	= -1205,
	DPI_AF_ERR_NPA_PF_FUNC_INVALID	= -1206,
	DPI_AF_ERR_LF_NO_MORE_RESOURCES = -1207,
};

struct dpi_lf_pf_func_cfg_req {
	struct mbox_msghdr hdr;
	u32 dpi_blkaddr;
	u16 npa_pf_func;
	u16 sso_pf_func;
	u16 lf_slot;
};

struct dpi_rsrc_attach_req {
	struct mbox_msghdr hdr;
	u32  dpi_blkaddr;
	u8   modify:1;
	u8   dpilfs:1;
	u16  dpi_lfs;
};

struct dpi_rsrc_detach_req {
	struct mbox_msghdr hdr;
	u32 dpi_blkaddr;
	u8 partial:1;
	u8 dpilfs:1;
	u8 dpi1_lfs:1;
};

struct dpi_free_rsrcs_rsp {
	struct mbox_msghdr hdr;
	u8   dpi;
	u8   dpi1;
};

struct dpi_lf_ring_cfg_req {
	struct mbox_msghdr hdr;
	u32 dpi_blkaddr;
	u16 lf_slot;
	u8 xtype;
	u8 pri;
	u8 ring_idx;
	u8 err_rsp_en;
	u8 wport;
	u8 rport;
};

struct dpi_lf_chan_cfg_req {
	struct mbox_msghdr hdr;
	u64 def_config; /* DPI_CHANNEL_TABLE_S value */
	u32 dpi_blkaddr;
	u16 lf_slot;
};

#define M(_name, _id, fn_name, req, rsp)				\
int rvu_mbox_handler_ ## fn_name(struct rvu *, struct req *, struct rsp *);
MBOX_EBLOCK_DPI_MESSAGES
#undef M

#endif /* __RVU_DPI_MBOX_H__ */
