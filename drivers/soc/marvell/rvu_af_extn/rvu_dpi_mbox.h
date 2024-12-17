/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU AF REE extension
 *
 * Copyright (C) 2023 Marvell.
 *
 */

#ifndef __RVU_DPI_MBOX_H__
#define __RVU_DPI_MBOX_H__

#include "mbox.h"
#include "rvu.h"

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

/* DPI Channel table structure */
struct dpi_chan_tble_s {
	u64 vf_func		: 12;
	u64 pf_func		: 4;
	u64 st			: 8;
	u64 reserved_24_31	: 8;
	u64 pasid		: 20;
	u64 pasid_ctrl		: 2;
	u64 th			: 1;
	u64 ph			: 2;
	u64 reserved_57_62	: 6;
	u64 valid		: 1;
};

/* DPI DMA Instruction Header Structure 128B */
struct dpi_dma_128b_instr_hdr_s {
	u64 nfst		: 3;
	u64 reserved_3		: 1;
	u64 nlst		: 3;
	u64 reserved_7		: 1;
	u64 intr		: 1;
	u64 ct			: 3;
	u64 chan		: 14;
	u64 reserved_26_29	: 4;
	u64 aura		: 20;
	u64 xt			: 2;
	u64 ivec		: 9;
	u64 fe			: 1;
	u64 reserved_62		: 1;
	u64 vld			: 1;
	/* Word 0 end */
	u64 ptr			: 64;

	/* Word 1 end */
	u64 tag			: 32;
	u64 tt			: 2;
	u64 grp			: 8;
	u64 reserved_170_171	: 2;
	u64 reserved_172_191	: 20;

	/* Word 2 end */
	u64 reserved_192_255	: 64;
	/* Word 3 end */
};

/* DPI DMA Instruction Header Structure 64B */
struct dpi_dma_64b_instr_hdr_s {
	u64 nfst		: 3;
	u64 reserved_3		: 1;
	u64 nlst		: 3;
	u64 reserved_7		: 1;
	u64 intr		: 1;
	u64 ct			: 3;
	u64 chan		: 14;
	u64 reserved_26_29	: 4;
	u64 aura		: 20;
	u64 xt			: 2;
	u64 ivec		: 9;
	u64 fe			: 1;
	u64 reserved_62		: 1;
	u64 vld			: 1;
	/* Word 0 end */

	u64 ptr			: 64;
	/* Word 1 end */
};

/* DPI DMA Function Selector Structure */
struct dpi_dma_func_sel_s {
	u32 func		: 12;
	u32 pf			: 4;
	u32 reserved_16_31	: 16;
};

/* DPI DMA Local Pointer Pair Structure */
struct dpi_dma_ptr_s {
	u64 length_l		: 24;
	u64 reserved_24_26	: 3;
	u64 bed_l		: 1;
	u64 ac_l		: 2;
	u64 f_l			: 1;
	u64 fp_l		: 1;
	u64 length_h		: 24;
	u64 reserved_56_58	: 3;
	u64 bed			: 1;
	u64 ac_h		: 2;
	u64 f_h			: 1;
	u64 fp_h		: 1;
	u64 ptr_l		: 64;
	u64 ptr_h		: 64;
};

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
				dpi_lf_chan_cfg_req, msg_rsp)		\
M(DPI_LF_CHAN_TBL_ALLOC, 0xc007, dpi_lf_chan_tbl_alloc,			\
				dpi_lf_chan_tbl_alloc_req,		\
				dpi_lf_chan_tbl_alloc_rsp)		\
M(DPI_LF_CHAN_TBL_FREE,	0xc008, dpi_lf_chan_tbl_free,			\
				dpi_lf_chan_tbl_free_req, msg_rsp)	\
M(DPI_LF_CHAN_TBL_SEL,	0xc009, dpi_lf_chan_tbl_sel,			\
				dpi_lf_chan_tbl_sel_req, msg_rsp)	\
M(DPI_LF_CHAN_TBL_ENA_DIS, 0xc00a, dpi_lf_chan_tbl_ena_dis,		\
				dpi_lf_chan_tbl_ena_dis_req, msg_rsp)	\
M(DPI_LF_CHAN_TBL_UPDATE, 0xc00b, dpi_lf_chan_tbl_update,		\
				dpi_lf_chan_tbl_update_req, msg_rsp)

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

struct dpi_lf_chan_tbl_alloc_req {
	struct mbox_msghdr hdr;
	u32 dpi_blkaddr;
	u32 tbl_size;
};

struct dpi_lf_chan_tbl_alloc_rsp {
	struct mbox_msghdr hdr;
	u16 tbl_num; /* Allocated channel table num */
};

struct dpi_lf_chan_tbl_free_req {
	struct mbox_msghdr hdr;
	u32 dpi_blkaddr;
	u32 tbl_num;
};

struct dpi_lf_chan_tbl_sel_req {
	struct mbox_msghdr hdr;
	u32 dpi_blkaddr;
	u16 lf_slot;
	u16 chan_tbl; /* Channel table  */
	u8 ena;
};

struct dpi_lf_chan_tbl_ena_dis_req {
	struct mbox_msghdr hdr;
	u32 dpi_blkaddr;
	u16 lf_slot;
	u8 ena_dis;
};

struct dpi_lf_chan_tbl_update_req {
	struct mbox_msghdr hdr;
	u64 config[64]; /* DPI_CHANNEL_TABLE_S value */
	u32 dpi_blkaddr;
	u16 idx_offset; /* Channel table off */
	u16 num_entries; /* Num of valid indexes from tbl_offset */
	u16 chan_tbl;
};

#define M(_name, _id, fn_name, req, rsp)				\
int rvu_mbox_handler_ ## fn_name(struct rvu *, struct req *, struct rsp *);
MBOX_EBLOCK_DPI_MESSAGES
#undef M

#endif /* __RVU_DPI_MBOX_H__ */
