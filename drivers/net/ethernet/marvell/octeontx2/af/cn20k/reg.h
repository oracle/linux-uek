/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#ifndef RVU_MBOX_REG_H
#define RVU_MBOX_REG_H

#define PF_TO_REGIDX(pf)	((pf) >= 64 ? 1 : 0)
#define PF_BITMAX		64
static inline u64 pf_to_bitoff(u8 pf)
{
	return (pf >= 64 ? pf - 64 : pf);
}

/* RVUM block registers */
#define RVU_PF_DISC				(0x0)
#define RVU_PRIV_PFX_DISC(a)			(0x8000208 | (a) << 16)
#define RVU_PRIV_HWVFX_DISC(a)			(0xD000000 | (a) << 12)
#define RVU_CN20K_PRIV_HWVFX_INT_CFG(a)		(0xC000000 | (a) << 12)

/* Mbox Registers */
/* RVU AF BAR0 Mbox registers for AF => PFx */
#define RVU_MBOX_AF_PFX_ADDR(a)			(0x5000 | (a) << 4)
#define RVU_MBOX_AF_AFPFX_TRIGX(a)		(0x9000 | (a) << 3)
#define RVU_MBOX_AF_PFAF_INT(a)			(0x2980 | (a) << 6)
#define RVU_MBOX_AF_PFAF_INT_W1S(a)		(0x2988 | (a) << 6)
#define RVU_MBOX_AF_PFAF_INT_ENA_W1S(a)		(0x2990 | (a) << 6)
#define RVU_MBOX_AF_PFAF_INT_ENA_W1C(a)		(0x2998 | (a) << 6)
#define RVU_MBOX_AF_PFAF1_INT(a)		(0x29A0 | (a) << 6)
#define RVU_MBOX_AF_PFAF1_INT_W1S(a)		(0x29A8 | (a) << 6)
#define RVU_MBOX_AF_PFAF1_INT_ENA_W1S(a)	(0x29B0 | (a) << 6)
#define RVU_MBOX_AF_PFAF1_INT_ENA_W1C(a)	(0x29B8 | (a) << 6)
#define RVU_AF_AFPF_MBOX_CFG			(0xc70)

#define RVU_AF_PFFLR_INTX(a)                    (0x27a0 + 0x40 * (a))
#define RVU_AF_PFFLR_INT_W1SX(a)                (0x27a8 + 0x40 * (a))
#define RVU_AF_PFFLR_INT_ENA_W1SX(a)            (0x27b0 + 0x40 * (a))
#define RVU_AF_PFFLR_INT_ENA_W1CX(a)            (0x27b8 + 0x40 * (a))
#define RVU_AF_PFME_INTX(a)                     (0x28c0 + 0x20 * (a))
#define RVU_AF_PFME_INT_W1SX(a)                 (0x28c8 + 0x20 * (a))
#define RVU_AF_PFME_INT_ENA_W1SX(a)             (0x28d0 + 0x20 * (a))
#define RVU_AF_PFME_INT_ENA_W1CX(a)             (0x28d8 + 0x20 * (a))
#define RVU_AF_PFTRPENDX(a)                     (0x2810 + 0x8 * (a))

/* RVU PF => AF mbox registers */
#define RVU_MBOX_PF_PFAF_TRIGX(a)		(0xC00 | (a) << 3)
#define RVU_MBOX_PF_INT				(0xC20)
#define RVU_MBOX_PF_INT_W1S			(0xC28)
#define RVU_MBOX_PF_INT_ENA_W1S			(0xC30)
#define RVU_MBOX_PF_INT_ENA_W1C			(0xC38)

#define RVU_AF_BAR2_SEL				(0x9000000)
#define RVU_AF_BAR2_PFID			(0x16400)
#define NIX_CINTX_INT_W1S(a)			(0xd30 | (a) << 12)
#define NIX_QINTX_CNT(a)			(0xc00 | (a) << 12)

#define RVU_MBOX_AF_VFAF_INT(a)			(0x3000 | (a) << 6)
#define RVU_MBOX_AF_VFAF_INT_W1S(a)		(0x3008 | (a) << 6)
#define RVU_MBOX_AF_VFAF_INT_ENA_W1S(a)		(0x3010 | (a) << 6)
#define RVU_MBOX_AF_VFAF_INT_ENA_W1C(a)		(0x3018 | (a) << 6)
#define RVU_MBOX_AF_VFAF1_INT(a)		(0x3020 | (a) << 6)
#define RVU_MBOX_AF_VFAF1_INT_W1S(a)		(0x3028 | (a) << 6)
#define RVU_MBOX_AF_VFAF1_IN_ENA_W1S(a)		(0x3030 | (a) << 6)
#define RVU_MBOX_AF_VFAF1_IN_ENA_W1C(a)		(0x3038 | (a) << 6)

#define RVU_MBOX_AF_AFVFX_TRIG(a, b)		(0x10000 | (a) << 4 | (b) << 3)
#define RVU_MBOX_AF_VFX_ADDR(a)			(0x20000 | (a) << 4)
#define RVU_AF_AFVF_MBOX_CFG			(0x20010)

#define RVU_MBOX_PF_VFX_PFVF_TRIGX(a)		(0x2000 | (a) << 3)

#define RVU_MBOX_PF_VFPF_INTX(a)		(0x1000 | (a) << 3)
#define RVU_MBOX_PF_VFPF_INT_W1SX(a)		(0x1020 | (a) << 3)
#define RVU_MBOX_PF_VFPF_INT_ENA_W1SX(a)	(0x1040 | (a) << 3)
#define RVU_MBOX_PF_VFPF_INT_ENA_W1CX(a)	(0x1060 | (a) << 3)

#define RVU_MBOX_PF_VFPF1_INTX(a)		(0x1080 | (a) << 3)
#define RVU_MBOX_PF_VFPF1_INT_W1SX(a)		(0x10a0 | (a) << 3)
#define RVU_MBOX_PF_VFPF1_INT_ENA_W1SX(a)	(0x10c0 | (a) << 3)
#define RVU_MBOX_PF_VFPF1_INT_ENA_W1CX(a)	(0x10e0 | (a) << 3)

#define RVU_MBOX_PF_VF_ADDR			(0xC40)
#define RVU_MBOX_PF_LMTLINE_ADDR		(0xC48)
#define RVU_PF_PFVF_MBOX_CFG			(0xC60)

#define RVU_MBOX_VF_VFPF_TRIGX(a)		(0x3000 | (a) << 3)
#define RVU_MBOX_VF_INT				(0x20)
#define RVU_MBOX_VF_INT_W1S			(0x28)
#define RVU_MBOX_VF_INT_ENA_W1S			(0x30)
#define RVU_MBOX_VF_INT_ENA_W1C			(0x38)

#define RVU_MBOX_VF_VFAF_TRIGX(a)		(0x2000 | (a) << 3)

#define NIX_GINT_INT                           (0x200)
#define NIX_GINT_INT_W1S                       (0x208)
#define ALTAF_RDY				BIT_ULL(1)

#define ALTAF_FLR				BIT_ULL(0)
/* NPC registers */
#define NPC_AF_INTFX_EXTRACTORX_CFG(a, b) \
	(0x20c000ull | (a) << 16 | (b) << 8)
#define NPC_AF_INTFX_EXTRACTORX_LTX_CFG(a, b, c) \
	(0x204000ull | (a) << 16 | (b) << 8  | (c) << 3)
#define NPC_AF_KPMX_ENTRYX_CAMX(a, b, c) \
	(0x20000ull | (a) << 12 | (b) << 3 | (c) << 16)
#define NPC_AF_KPMX_ENTRYX_ACTION0(a, b) \
	(0x40000ull | (a) << 12 | (b) << 3)
#define NPC_AF_KPMX_ENTRYX_ACTION1(a, b) \
	(0x50000ull | (a) << 12 | (b) << 3)
#define NPC_AF_KPMX_ENTRY_DISX(a, b)	(0x60000ull | (a) << 12 | (b) << 3)
#define NPC_AF_KPM_PASS2_CFG	0x10210
#define NPC_AF_KPMX_PASS2_OFFSET(a)	(0x60040ull | (a) << 12)
#define NPC_AF_MCAM_SECTIONX_CFG_EXT(a)	(0xf000000ull | (a) << 3)

#define NIX_AF_LSO_ALT_FLAGS_CFG(a)	(0x4B00 | (a) << 3)
#define NIX_AF_LSO_ALT_FLAGS_CFG1(a)	(0x4B20 | (a) << 3)

/* NIX Registers */
#define NIX_AF_RX_CPT_CHAN_CFG			(0x0E8)
#define NIX_AF_RX_DEF_INLINEX(a)		(0x2c0 | (a) << 3)
#define NIX_AF_RX_INLINE_GEN_CFGX(a)		(0x340 | (a) << 3)
#define NIX_AF_RX_EXTRACT_INLINEX(a)		(0x380 | (a) << 3)
#define NIX_AF_CN20K_RX_CPTX_INST_QSEL(a)	(0x3C0 | (a) << 16)
#define NIX_AF_CN20K_RX_CPTX_CREDIT(a)		(0x3D0 | (a) << 16)
#define NIX_AF_RX_PROT_FIELDX_INLINEX(a, b)	(0x4c00 | (a) << 6 | (b) << 3)
#define NIX_AF_LFX_RX_INLINE_SA_BASE(a, b)	(0x4240 | (a) << 17 | (b) << 3)
#define NIX_AF_LFX_RX_INLINE_CFG0(a, b)		(0x4280 | (a) << 17 | (b) << 3)
#define NIX_AF_LFX_RX_INLINE_CFG1(a, b)		(0x42c0 | (a) << 17 | (b) << 3)
#define NPC_AF_CN20K_MCAMEX_BANKX_CAMX_INTF_EXT(a, b, c) ({		\
	u64 offset;							\
	offset = (0x8000000ull | (a) << 4 | (b) << 20 | (c) << 3);	\
	offset; })

#define NPC_AF_CN20K_MCAMEX_BANKX_CAMX_W0_EXT(a, b, c) ({		\
	u64 offset;							\
	offset = (0x9000000ull | (a) << 4 | (b) << 20 | (c) << 3);	\
	offset; })

#define NPC_AF_CN20K_MCAMEX_BANKX_CAMX_W1_EXT(a, b, c) ({		\
	u64 offset;							\
	offset = (0x9400000ull | (a) << 4 | (b) << 20 | (c) << 3);	\
	offset; })

#define NPC_AF_CN20K_MCAMEX_BANKX_CAMX_W2_EXT(a, b, c) ({		\
	u64 offset;							\
	offset = (0x9800000ull | (a) << 4 | (b) << 20 | (c) << 3);	\
	offset; })

#define NPC_AF_CN20K_MCAMEX_BANKX_CAMX_W3_EXT(a, b, c) ({		\
	u64 offset;							\
	offset = (0x9c00000ull | (a) << 4 | (b) << 20 | (c) << 3);	\
	offset; })

#define NPC_AF_CN20K_MCAMEX_BANKX_CFG_EXT(a, b) ({		\
	u64 offset;						\
	offset = (0xa000000ull | (a) << 4 | (b) << 20);		\
	offset; })

#define NPC_AF_CN20K_MCAMEX_BANKX_ACTIONX_EXT(a, b, c) ({		   \
	u64 offset;							   \
									   \
	offset = (0xc000000ull | (a) << 4 | (b) << 20 | (c) << 22);	   \
	offset; })

#define NPC_AF_INTFX_MISS_ACTX(a, b)	(0xf003000 | (a) << 6 | (b) << 4)

#define NPC_AF_CN20K_MCAMEX_BANKX_STAT_EXT(a, b) ({		\
	u64 offset;						\
								\
	offset = (0xb000000ull | (a) << 4 | (b) << 20);		\
	offset; })

/* NIX Registers */
#define NIX_AF_LSO_ALT_FLAGS_CFG(a)	(0x4B00 | (a) << 3)
#define NIX_AF_LSO_ALT_FLAGS_CFG1(a)	(0x4B20 | (a) << 3)
#define NIX_AF_RX_CPT_CHAN_CFG			(0x0E8)
#define NIX_AF_RX_DEF_INLINEX(a)		(0x2c0 | (a) << 3)
#define NIX_AF_RX_INLINE_GEN_CFGX(a)		(0x340 | (a) << 3)
#define NIX_AF_RX_EXTRACT_INLINEX(a)		(0x380 | (a) << 3)
#define NIX_AF_RX_PROT_FIELDX_INLINEX(a, b)	(0x4c00 | (a) << 6 | (b) << 3)
#define NIX_AF_LFX_RX_INLINE_SA_BASE(a, b)	(0x4240 | (a) << 17 | (b) << 3)
#define NIX_AF_LFX_RX_INLINE_CFG0(a, b)		(0x4280 | (a) << 17 | (b) << 3)
#define NIX_AF_LFX_RX_INLINE_CFG1(a, b)		(0x42c0 | (a) << 17 | (b) << 3)

/* NPA Registers */
#define NPA_AF_DPCX_CFG(a)		(0x800 | (a) << 6)
#define NPA_AF_DPC_PERMITX(a)		(0x1000 | (a) << 3)

#define NPA_DPC_MAX			32
#define NPA_DPC_LFS_PER_REG		64

#define NIX_AF_LSO_ALT_FLAGS_CFG(a)	(0x4B00 | (a) << 3)
#define NIX_AF_LSO_ALT_FLAGS_CFG1(a)	(0x4B20 | (a) << 3)

/* NIX Registers */
#define NIX_AF_RX_DEF_INLINEX(a)                (0x2c0 | (a) << 3)
#define NIX_AF_RX_INLINE_GEN_CFGX(a)            (0x340 | (a) << 3)
#define NIX_AF_RX_EXTRACT_INLINEX(a)            (0x380 | (a) << 3)
#define NIX_AF_RX_PROT_FIELDX_INLINEX(a, b)     (0x4c00 | (a) << 6 | (b) << 3)

/* SDP Regsiters */
#define SDP_AF_BLK_RST				0xc000030
#define SDP_AF_AP_EPFX_MBOX_SEND_INT		0x40c0000
#define SDP_AF_RX_EPF_VF_MAP(a)			(0x4091000 | (a) << 3)
#define SDP_AF_MAC_CHANX_RING_MAP(a)		(0x4098000 | (a) << 3)
#define SDP_AF_CONST				(0x4090038)
#define SDP_AF_RX_IN_PKT_CNT(a)			(0x8000460 | (a) << 16)
#define SDP_AF_RX_IN_BYTE_CNT(a)		(0x8000470 | (a) << 16)
#define SDP_AF_RX_IN_DROP_PKT_CNT(a)		(0x8000480 | (a) << 16)
#define SDP_AF_RX_IN_DROP_BYTE_CNT(a)		(0x8000490 | (a) << 16)
#define SDP_AF_RX_IN_PTP_STATS(a)		(0x8000708 | (a) << 16)

#define SDP_AF_RX_OUT_PKT_CNT(a)		(0x8000560 | (a) << 16)
#define SDP_AF_RX_OUT_BYTE_CNT(a)		(0x8000570 | (a) << 16)
#define SDP_AF_RX_OUT_DROP_PKT_CNT(a)		(0x8000580 | (a) << 16)
#define SDP_AF_RX_OUT_DROP_BYTE_CNT(a)		(0x8000590 | (a) << 16)
#define SDP_AF_RX_OUT_PTP_STATS(a)		(0x8000710 | (a) << 16)
#define SDP_AF_RX_OUT_SLIST_DBELL(a)		(0x8000120 | (a) << 16)
#define SDP_AF_RX_OUT_WMARK(a)			(0x8000128 | (a) << 16)

#define SDP_AF_OUT_BP_ENX_W1S(a)		(0x4093040 | (a) << 3)
#define SDP_AF_OUT_DROP_STATEX(a)		(0x4093080 | (a) << 3)

/* CPT Registers */
#define CPT_AF_CN20K_INST_GENERIC0_PC		(0x15000)
#define CPT_AF_CN20K_INST_GENERIC1_PC		(0x15100)
#define CPT_AF_CN20K_INST_REQ_PC		(0x15200)
#define CPT_AF_CN20K_INST_LATENCY_PC		(0x15300)
#define CPT_AF_CN20K_RD_REQ_PC			(0x15400)
#define CPT_AF_CN20K_RD_LATENCY_PC		(0x15600)
#define CPT_AF_CN20K_RD_UC_PC			(0x15700)
#define CPT_AF_CN20K_ACTIVE_CYCLES_PC		(0x15800)
#define CPT_AF_CN20K_EXEX_REQ_PC(a)		(0x17000 | (u64)(a) << 3)
#define CPT_AF_CN20K_EXEX_LATENCY_PC(a)		(0x18000 | (u64)(a) << 3)
#define CPT_AF_CN20K_EXEX_INST_PC(a)		(0x19000 | (u64)(a) << 3)
#define CPT_AF_CN20K_NIXRXX_CFG(a)		(0x2de00 | (u64)(a) << 3)
#define CPT_AF_RXC_QUEX_CFG(a)		(0x50800ull | (u64)(a) << 3)
#define CPT_AF_RXC_QUEX_DFRG(a)		(0x50080ull | (u64)(a) << 3)
#define CPT_AF_RXC_QUEX_ACTIVE_STS(a)	(0x50100ull | (u64)(a) << 3)
#define CPT_AF_RXC_QUEX_ZOMBIE_STS(a)	(0x50180ull | (u64)(a) << 3)
#define CPT_AF_RXC_QUE_X2PX_LINK_CFG(a) (0x51000ull | (u64)(a) << 3)

#define CPT_AF_CTL_RES_META_OFFSET		GENMASK_ULL(36, 32)

/* LBK Registers */
#define CN20K_LBK_CONST_CHANS			GENMASK_ULL(39, 24)
#define CN20K_LBKX_LINK_CFG_P2X			0x800
#define CN20K_LBKX_LINK_CFG_X2P			0x808
#define CN20K_LBK_LINK_CFG_RANGE_MASK		GENMASK_ULL(19, 16)
#define CN20K_LBK_LINK_CFG_BASE_MASK		GENMASK_ULL(7, 0)
#define CN20K_MAX_LBK_CHANS			128
#endif /* RVU_MBOX_REG_H */
