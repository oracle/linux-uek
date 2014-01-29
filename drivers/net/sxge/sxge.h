/* sxge.h: Definitions for SOL ethernet driver.
 * Copyright (C) 2011 Oracle Corp
 */
/* #pragma ident   "@(#)sxge.h 1.21     11/02/10 SMI" */

#ifndef _SXGE_H
#define	_SXGE_H

#define	SXGE_MAX_MTU		9216
#define	RDAT_LOW		0xFE000
#define	RDAT_HIGH		0xFE008
#define	MAX_PIOBAR_RESOURCE	0x10
#define	MAX_VNI_NUM		0xC
#define	SXGE_PIOBAR_RESOUCE_VMAC_SHIFT	4
#define	SXGE_PIOBAR_RESOUCE_DMA_MASK	0xF
/*
 * DMA HW Interfaces
 */
#define	HOST_VNI_BASE		(0x00000)
#define	TXDMA_BASE		(0x00000)
#define	RXDMA_BASE		(0x00400)
#define	RXVMAC_BASE		(0x08000)
#define	TXVMAC_BASE		(0x08200)
#define	INTR_BASE		(0x08400)
#define	SHARE_RESOURCE_BASE	(0xC0000)
#define	STAND_RESOURCE_BASE	(0xF0000)

#define	VNI_STEP		(0x10000)
#define	RXDMA_STEP		(0x02000)
#define	TXDMA_STEP		(0x02000)
#define	VMAC_STEP		(0x02000)
#define	NF_STEP			(0x02000)

/* LDG */
#define	LD_BASE(VNI, NF, ID)	(VNI * VNI_STEP + NF * NF_STEP + ID * 8ULL)

#define LD_MSK_GNUM(VNI, NF, LDN)	(LD_BASE(VNI, NF, LDN) + 0x8400)
#define	LD_MSK_GNUM_LDG_NUM		0x000000000000000fULL
#define	LD_MSK_GNUM_LDG_MSK		0x0000000000000030ULL
#define	LD_MSK_GNUM_LDG_MSK_SHIFT	4
#define	LD_MSK_GNUM_EN_LDG_WR		0x0000000000000040ULL
#define	LD_MSK_GNUM_EN_MSK_WR		0x0000000000000080ULL

#define	LDSV(VNI, NF, LDG)		(LD_BASE(VNI, NF, LDG) + 0x8480)
#define	LDSV_LDSV1_MASK			0x000000001fff0000ULL
#define	LDSV_V1_VNI_ERROR		0x0000000010000000ULL
#define	LDSV_V1_TXVMAC			0x0000000008000000ULL
#define	LDSV_V1_RXVMAC			0x0000000004000000ULL
#define	LDSV_V1_MAILBOX			0x0000000002000000ULL
#define	LDSV_V1_TXDMA			0x0000000000f00000ULL
#define	LDSV_V1_RXDMA			0x00000000000f0000ULL
#define	LDSV_LDSV0_MASK			0x0000000000001fffULL
#define	LDSV_V0_VNI_ERROR		0x0000000000001000ULL
#define	LDSV_V0_TXVMAC			0x0000000000000800ULL
#define	LDSV_V0_RXVMAC			0x0000000000000400ULL
#define	LDSV_V0_MAILBOX			0x0000000000000200ULL
#define	LDSV_V0_TXDMA			0x00000000000000f0ULL
#define	LDSV_V0_RXDMA			0x000000000000000fULL

#define	LDG_IMGMT(LDG)			(STAND_RESOURCE_BASE + LDG * 8)
#define	LDG_IMGMT_TIMER			0x00000000003f0000ULL
#define	LDG_IMGMT_TIMER_SHIFT		16
#define	LDG_IMGMT_ARM			0x0000000000001000ULL
#define	LDG_IMGMT_VNI_STAT		0x0000000000000FFFULL

/* DMA */
#define	RDC_BASE(vni, rdc)	((vni * VNI_STEP) + (rdc * RXDMA_STEP))
#define	TDC_BASE(vni, tdc)	((vni * VNI_STEP) + (tdc * TXDMA_STEP))
#define	VMAC_BASE(vni, vmac)	((vni * VNI_STEP) + (vmac * VMAC_STEP))

/* VMAC registers */
#define	TXVMAC_CONF(VNI, VMAC)	(TXVMAC_BASE + VMAC_BASE(VNI, VMAC) + 0)
#define	TXVMAC_CONF_SW_RST	0x0000000000000001ULL

#define	TXVMAC_STAT(VNI, VMAC)	(TXVMAC_BASE + VMAC_BASE(VNI, VMAC) + 0x8)
#define	TXVMAC_STAT_TX_BYTE_CNT_OVL	0x0000000000000004ULL
#define	TXVMAC_STAT_TX_FRAME_CNT_OVL	0x0000000000000002ULL
#define	TXVMAC_STAT_SW_RST_DONE		0x0000000000000001ULL

#define	TXVMAC_STAT_MSK(VNI, VMAC) (TXVMAC_BASE + VMAC_BASE(VNI, VMAC) + 0x10)

#define	TXVMAC_FRM_CNT(VNI, VMAC) (TXVMAC_BASE + VMAC_BASE(VNI, VMAC) + 0x20)
#define	TXVMAC_BYT_CNT(VNI, VMAC) (TXVMAC_BASE + VMAC_BASE(VNI, VMAC) + 0x28)

#define	RXVMAC_CONFIG(VNI, VMAC)	(RXVMAC_BASE + VMAC_BASE(VNI, VMAC) + 0)
#define	RXVMAC_CONFIG_OPCODE		0x0000000000003000ULL
#define	RXVMAC_CONFIG_OPCODE_1F4D	0x0000000000003000ULL
#define	RXVMAC_CONFIG_OPCODE_1F1D	0x0000000000000000ULL
#define	RXVMAC_CONFIG_OPCODE_1F2D	0x0000000000001000ULL
#define	RXVMAC_CONFIG_OPCODE_SHIFT	12
#define	RXVMAC_CONFIG_DMA_VECTOR	0x0000000000000F00ULL
#define	RXVMAC_CONFIG_DMA_VECTOR_SHIFT	8
#define	RXVMAC_CONFIG_PROMISC_MODE	0x0000000000000080ULL
#define	RXVMAC_CONFIG_RST		0x0000000000000008ULL
#define	RXVMAC_CONFIG_RST_STATE		0x0000000000000004ULL

#define	RXVMAC_STAT(VNI, VMAC)	(RXVMAC_BASE + VMAC_BASE(VNI, VMAC) + 0x40)
#define	RXVMAC_STAT_LINK_STATE		0x0000000000008000ULL
#define	RXVMAC_STAT_LINK_DOWN		0x0000000000000100ULL
#define	RXVMAC_STAT_LINK_UP		0x0000000000000080ULL
#define	RXVMAC_STAT_BCAST_FRAME_CNT_OVL	0x0000000000000040ULL
#define	RXVMAC_STAT_MCAST_FRAME_CNT_OVL	0x0000000000000020ULL
#define	RXVMAC_STAT_DROP_BYTE_OVL	0x0000000000000010ULL
#define	RXVMAC_STAT_DROP_CNT_OVL	0x0000000000000008ULL
#define	RXVMAC_STAT_BYTE_CNT_OVL	0x0000000000000004ULL
#define	RXVMAC_STAT_FRAME_CNT_OVL	0x0000000000000002ULL

#define	RXVMAC_INT_MASK(VNI, VMAC) (RXVMAC_BASE + VMAC_BASE(VNI, VMAC) + 0x48)
#define RXVMAC_FRMCNT_DBG(VNI, VMAC) (RXVMAC_BASE + VMAC_BASE(VNI, VMAC) + 0x10)
#define	RXVMAC_FRM_CNT(VNI, VMAC) (RXVMAC_BASE + VMAC_BASE(VNI, VMAC) + 0x60)
#define	RXVMAC_BYT_CNT(VNI, VMAC) (RXVMAC_BASE + VMAC_BASE(VNI, VMAC) + 0x68)
#define	RXVMAC_DROP_CNT(VNI, VMAC) (RXVMAC_BASE + VMAC_BASE(VNI, VMAC) + 0x70)
#define	RXVMAC_DROPBYT_CNT(VNI, VMAC) (RXVMAC_BASE + VMAC_BASE(VNI, VMAC)+0x78)
#define	RXVMAC_MCAST_CNT(VNI, VMAC) (RXVMAC_BASE + VMAC_BASE(VNI, VMAC) + 0x80)
#define	RXVMAC_BCAST_CNT(VNI, VMAC) (RXVMAC_BASE + VMAC_BASE(VNI, VMAC) + 0x88)

/* TX DMA register */
#define	TDC_RNG_CFIG(CHAN_BASE)		(TXDMA_BASE + CHAN_BASE + 0x0000)
#define	TDC_RNG_CFIG_LEN		0x1fff000000000000ULL
#define	TDC_RNG_CFIG_LEN_SHIFT		48
#define	TDC_RNG_CFIG_STADDR_BASE	0x00000ffffff80000ULL
#define	TDC_RNG_CFIG_STADDR		0x000000000007ffc0ULL

#define	TDC_PG_HDL(CHAN_BASE)		(TXDMA_BASE + CHAN_BASE + 0x0008)
#define	TDC_RING_HDL(CHAN_BASE)		(TXDMA_BASE + CHAN_BASE + 0x0010)
#define	TDC_RING_KICK(CHAN_BASE)	(TXDMA_BASE + CHAN_BASE + 0x0018)
#define	TDC_RING_KICK_WRAP		0x0000000000080000ULL
#define	TDC_RING_KICK_TAIL		0x000000000007fff8ULL

#define	TDC_DMA_ENT_MSK(CHAN_BASE)	(TXDMA_BASE + CHAN_BASE + 0x0020)

#define	TDC_CS(CHAN_BASE)		(TXDMA_BASE + CHAN_BASE + 0x0028)
#define	TDC_CS_PKT_CNT			0x0fff000000000000ULL
#define	TDC_CS_PKT_CNT_SHIFT		48
#define	TDC_CS_RST			0x0000000080000000ULL
#define	TDC_CS_RST_STATE		0x0000000040000000ULL
#define TDC_CS_STOP_N_GO		0x0000000010000000ULL
#define	TDC_CS_SNG_STATE		0x0000000008000000ULL
#define	TDC_CS_MK			0x0000000000008000ULL
#define	TDC_CS_MMK			0x0000000000004000ULL
#define	TDC_CS_REJECT_RESP_ERR		0x0000000000001000ULL
#define	TDC_CS_SOP_BIT_ERR		0x0000000000000800ULL
#define	TDC_CS_PREMATURE_SOP_ERR	0x0000000000000400ULL
#define	TDC_CS_DESC_LENGTH_ERR		0x0000000000000200ULL
#define	TDC_CS_DESC_NUM_PTR_ERR		0x0000000000000100ULL
#define	TDC_CS_MBOX_ERR			0x0000000000000080ULL
#define	TDC_CS_PKT_SIZE_ERR		0x0000000000000040ULL
#define	TDC_CS_TX_RING_OFLOW		0x0000000000000020ULL
#define	TDC_CS_PREF_BUF_PAR_ERR		0x0000000000000010ULL
#define	TDC_CS_NACK_PREF		0x0000000000000008ULL
#define	TDC_CS_NACK_PKT_RD		0x0000000000000004ULL
#define	TDC_CS_CONF_PART_ERR		0x0000000000000002ULL
#define	TDC_CS_PKT_PRT_ERR		0x0000000000000001ULL

#define	TDC_MBH(CHAN_BASE)		(TXDMA_BASE + CHAN_BASE + 0x0030)
#define	TDC_MBH_MBADDR			0x0000000000000fffULL

#define	TDC_MBL(CHAN_BASE)		(TXDMA_BASE + CHAN_BASE + 0x0038)
#define	TDC_MBL_MBADDR			0x00000000ffffffc0ULL

#define	TDC_RNG_ERR_LOGH(CHAN_BASE)	(TXDMA_BASE + CHAN_BASE + 0x0048)
#define	TDC_RNG_ERR_LOGL(CHAN_BASE)	(TXDMA_BASE + CHAN_BASE + 0x00508)

#define	TXC_DMA_MAX(CHAN_BASE)		(TXDMA_BASE + CHAN_BASE + 0x0200)
#define	TDC_PRSR_ENABLE			0x0000000080000000ULL
#define TDC_HPRSR_CSPARTIAL		0x0000000040000000ULL

/* rx dma */
#define	RDC_PAGE_HDL(CHAN_BASE)		(RXDMA_BASE + CHAN_BASE + 0x0000)

#define	RDC_CFG(CHAN_BASE)		(RXDMA_BASE + CHAN_BASE + 0x0008)
#define	RDC_CFG_BLKSIZE			0x0000000000000600ULL
#define	RDC_CFG_BLKSIZE_SHIFT		9
#define	RDC_CFG_BUFSZ2			0x0000000000000180ULL
#define	RDC_CFG_BUFSZ2_SHIFT		7
#define	RDC_CFG_VLD2			0x0000000000000040ULL
#define	RDC_CFG_BUFSZ1			0x0000000000000030ULL
#define	RDC_CFG_BUFSZ1_SHIFT		4
#define	RDC_CFG_VLD1			0x0000000000000008ULL
#define	RDC_CFG_BUFSZ0			0x0000000000000006ULL
#define	RDC_CFG_BUFSZ0_SHIFT		1
#define	RDC_CFG_VLD0			0x0000000000000001ULL

#define RBR_BLKSIZE_4K			0x0
#define RBR_BLKSIZE_8K			0x1
#define RBR_BLKSIZE_16K			0x2
#define RBR_BLKSIZE_32K			0x3
#define RBR_BUFSZ2_2K			0x0
#define RBR_BUFSZ2_4K			0x1
#define RBR_BUFSZ2_8K			0x2
#define RBR_BUFSZ2_16K			0x3
#define RBR_BUFSZ1_1K			0x0
#define RBR_BUFSZ1_2K			0x1
#define RBR_BUFSZ1_4K			0x2
#define RBR_BUFSZ1_8K			0x3
#define RBR_BUFSZ0_256			0x0
#define RBR_BUFSZ0_512			0x1
#define RBR_BUFSZ0_1K			0x2
#define RBR_BUFSZ0_2K			0x3

#define	RDC_RBR_CFG(CHAN_BASE)		(RXDMA_BASE + CHAN_BASE + 0x0010)
#define	RDC_RBR_CFG_LEN			0x01ff000000000000ULL
#define	RDC_RBR_CFG_LEN_SHIFT		48
#define	RDC_RBR_CFG_STADDR		0x00000fffffffffc0ULL

#define	RDC_RCR_CFG(CHAN_BASE)		(RXDMA_BASE + CHAN_BASE + 0x0018)
#define	RDC_RCR_CFG_LEN			0xffff000000000000ULL
#define	RDC_RCR_CFG_LEN_SHIFT		48
#define	RDC_RCR_CFG_STADDR		0x00000fffffffffc0ULL

#define	RDC_MBX_CFG(CHAN_BASE)		(RXDMA_BASE + CHAN_BASE + 0x0020)
#define	RDC_MBX_CFG_MBOX_STADDR		0x00000fffffffffc0ULL

#define	RDC_RCR_TIMER_CFG(CHAN_BASE)	(RXDMA_BASE + CHAN_BASE + 0x0028)
#define	RDC_RCR_TIMER_CFG_PTHRESH	0x00000000ffff0000ULL
#define	RDC_RCR_TIMER_CFG_PTHRESH_SHIFT	16
#define	RDC_RCR_TIMER_CFG_ENPTHRESH	0x0000000000008000ULL
#define	RDC_RCR_TIMER_CFG_ENTIMEOUT	0x0000000000000040ULL
#define	RDC_RCR_TIMER_CFG_TIMEOUT	0x000000000000003fULL
#define	RDC_RCR_TIMER_CFG_TIMEOUT_SHIFT	0

#define	RDC_MBX_UPD_CFG(CHAN_BASE)	(RXDMA_BASE + CHAN_BASE + 0x0030)
#define	RDC_MBX_UPD_CFG_ENABLE		0x0000000000010000ULL
#define	RDC_MBX_UPD_CFG_PTHRESH		0x000000000000ffffULL

#define	RDC_KICK(CHAN_BASE)		(RXDMA_BASE + CHAN_BASE + 0x0038)
#define	RDC_KICK_RCR_HEAD_UP_VLD	0x0000000080000000ULL
#define	RDC_KICK_RCR_HEAD_WRAP		0x0000000040000000ULL
#define	RDC_KICK_RCR_HEAD_WRAP_SHIFT	30
#define	RDC_KICK_RCR_HEAD_PT		0x000000003fffc000ULL
#define	RDC_KICK_RCR_HEAD_PT_SHIFT	14
#define	RDC_KICK_RBR_TAIL_UP_VLD	0x0000000000002000ULL
#define	RDC_KICK_RBR_TAIL_WRAP		0x0000000000001000ULL
#define	RDC_KICK_RBR_TAIL		0x0000000000000fffULL

#define RDC_ENT_MSK(CHAN_BASE)		(RXDMA_BASE + CHAN_BASE + 0x0040)
#define	RDC_ENT_MSK_ALL			0x000000000000e3ffULL

#define	RDC_CTL_STAT(CHAN_BASE)		(RXDMA_BASE + CHAN_BASE + 0x0050)
#define	RDC_CTL_STAT_TAIL_WRAP		0x4000000000000000ULL
#define	RDC_CTL_STAT_TAIL_WRAP_SHIFT	62
#define	RDC_CTL_STAT_TAIL		0x3fffc00000000000ULL
#define	RDC_CTL_STAT_TAIL_SHIFT		46
#define	RDC_CTL_STAT_RST		0x0000000080000000ULL
#define	RDC_CTL_STAT_RST_STATE		0x0000000040000000ULL
#define	RDC_CTL_STAT_STOP_N_GO		0x0000000010000000ULL
#define	RDC_CTL_STAT_SNG_STATE		0x0000000008000000ULL
#define	RDC_CTL_STAT_BLOCKING_MODE	0x0000000000010000ULL
#define	RDC_CTL_STAT_MBOXTHRES		0x0000000000008000ULL
#define	RDC_CTL_STAT_RCRTHRES		0x0000000000004000ULL
#define	RDC_CTL_STAT_RCRTO		0x0000000000002000ULL
#define	RDC_CTL_STAT_PKTCNT_OVERFLOW	0x0000000000001000ULL
#define	RDC_CTL_STAT_DROPCNT_OVERFLOW	0x0000000000000800ULL
#define	RDC_CTL_STAT_RBR_EMPTY		0x0000000000000400ULL
#define	RDC_CTL_STAT_FIFO_ERR		0x0000000000000200ULL
#define	RDC_CTL_STAT_RCR_SHADOW_FULL	0x0000000000000100ULL
#define	RDC_CTL_STAT_REQ_REJECT		0x0000000000000080ULL
#define	RDC_CTL_STAT_RBR_TIMEOUT	0x0000000000000040ULL
#define	RDC_CTL_STAT_RSP_DAT_ERR	0x0000000000000020ULL
#define	RDC_CTL_STAT_RCR_ACK_ERR	0x0000000000000010ULL
#define	RDC_CTL_STAT_RCR_SHA_PAR	0x0000000000000008ULL
#define	RDC_CTL_STAT_RBR_PRE_PAR	0x0000000000000004ULL
#define	RDC_CTL_STAT_RCR_UNDERFLOW	0x0000000000000002ULL
#define	RDC_CTL_STAT_RBR_OVERFLOW	0x0000000000000001ULL

#define	RDC_CTL_STAT_CHAN_FATAL		(RDC_CTL_STAT_REQ_REJECT | \
					 RDC_CTL_STAT_RBR_TIMEOUT | \
					 RDC_CTL_STAT_RSP_DAT_ERR | \
					 RDC_CTL_STAT_RCR_ACK_ERR | \
					 RDC_CTL_STAT_RCR_SHA_PAR | \
					 RDC_CTL_STAT_RBR_PRE_PAR | \
					 RDC_CTL_STAT_RCR_UNDERFLOW | \
					 RDC_CTL_STAT_RBR_OVERFLOW)

#define	RDC_CTL_STAT_WRITE_CLEAR_INT	(RDC_CTL_STAT_BLOCKING_MODE | \
					 RDC_CTL_STAT_MBOXTHRES | \
					 RDC_CTL_STAT_RCRTHRES | \
					 RDC_CTL_STAT_RCRTO | \
					 RDC_CTL_STAT_PKTCNT_OVERFLOW | \
					 RDC_CTL_STAT_DROPCNT_OVERFLOW | \
					 RDC_CTL_STAT_RBR_EMPTY)

#define	RDC_CTL_STAT_WRITE_CLEAR_ERRS	(RDC_CTL_STAT_FIFO_ERR | \
					 RDC_CTL_STAT_RCR_SHADOW_FULL)

#define	RDC_CTL_STAT_DBG(CHAN_BASE)	(RXDMA_BASE + CHAN_BASE + 0x0058)
#define	RDC_FLSH(CHAN_BASE)	(RXDMA_BASE + CHAN_BASE + 0x0060)

#define	RDC_PKTCNT(CHAN_BASE)	(RXDMA_BASE + CHAN_BASE + 0x0078)
#define	RDC_PKTCNT_COUNT	0x000000007fffffffULL

#define	RDC_PKTDROP(CHAN_BASE)	(RXDMA_BASE + CHAN_BASE + 0x0080)
#define	RDC_PKTDROP_COUNT	0x000000007fffffffULL

#define	RDC_RNG_ERR_LOG(CHAN_BASE)	(RXDMA_BASE + CHAN_BASE + 0x0088)

/* Logical devices and device groups */
#define	LDN_RXDMA(CHAN)			(0 + (CHAN))
#define	LDN_TXDMA(CHAN)			(4 + (CHAN))
#define	LDN_RSV				8
#define	LDN_MAILBOX			9
#define	LDN_RXVMAC			10
#define	LDN_TXVMAC			11
#define	LDN_VNI_ERROR			12
#define	LDN_MAX				LDN_VNI_ERROR

#define	SXGE_LDG_MIN			0
#define	SXGE_LDG_MAX			15
#define	SXGE_NUM_LDG			16

/* RCR Completion Ring */
#define	RCR_ENTRY_MULTI			0x8000000000000000ULL
#define	RCR_ENTRY_PKT_TYPE		0x7c00000000000000ULL
#define	RCR_ENTRY_PKT_TYPE_SHIFT	58
#define	RCR_ENTRY_PKT_ERR		0x0380000000000000ULL
#define	RCR_ENTRY_PKT_ERR_SHIFT		55
#define	RCR_ENTRY_PKT_CLASS_CODE	0x0003e00000000000ULL
#define	RCR_ENTRY_PKT_CLASS_CODE_SHIFT	45
#define	RCR_ENTRY_PROMISC		0x0000100000000000ULL
#define	RCR_ENTRY_RSS_HASH		0x0000080000000000ULL
#define	RCR_ENTRY_TCAM_HIT		0x0000040000000000ULL
#define	RCR_ENTRY_PKTBUFSZ		0x0000030000000000ULL
#define	RCR_ENTRY_PKTBUFSZ_SHIFT	40
#define	RCR_ENTRY_PKT_SEG_LEN		0x000000fffc000000ULL
#define	RCR_ENTRY_PKT_SEG_LEN_SHIFT	26
#define	RCR_ENTRY_LAST_PKT_PER_BUF	0x0000000002000000ULL
#define RCR_ENTRY_SUBINDEX		0x0000000001ff0000ULL
#define	RCR_ENTRY_SUBINDEX_SHIFT	16
#define RCR_ENTRY_INDEX			0x000000000000ffffULL

#define	CLS_CODE_TCP_IPV4		0x8
#define	CLS_CODE_UDP_IPV4		0x9
#define	CLS_CODE_TCP_IPV6		0xc
#define	CLS_CODE_UDP_IPV6		0xd
#define	CLS_CODE_TCP_UDP		0xd

/* host/eps mbox */
#define	SXGE_MB_STAT			(STAND_RESOURCE_BASE + 0xC0)
#define	SXGE_MB_STAT_OMB_ECC_ERR	0x0000000000000100ULL
#define	SXGE_MB_STAT_IMB_ECC_ERR	0x0000000000000080ULL
#define	SXGE_MB_STAT_FUNC_RST		0x0000000000000040ULL
#define	SXGE_MB_STAT_FUNC_RST_DONE	0x0000000000000020ULL
#define	SXGE_MB_STAT_OMB_OVL		0x0000000000000010ULL
#define	SXGE_MB_STAT_IMB_FULL		0x0000000000000008ULL
#define	SXGE_MB_STAT_OMB_ACKED		0x0000000000000004ULL
#define	SXGE_MB_STAT_OMB_FAILED		0x0000000000000002ULL
#define	SXGE_MB_STAT_OMB_FULL		0x0000000000000001ULL

#define	SXGE_MB_MSK				(STAND_RESOURCE_BASE + 0xC8)
#define	SXGE_MB_MSK_OMB_ECC_ERR_INT_MSK		0x0000000000000100ULL
#define	SXGE_MB_MSK_IMB_ECC_ERR_INT_MSK		0x0000000000000080ULL
#define	SXGE_MB_MSK_FUNC_RST_DONE_INT_MSK	0x0000000000000020ULL
#define	SXGE_MB_MSK_OMB_OVL_INT_MSK		0x0000000000000010ULL
#define	SXGE_MB_MSK_IMB_FULL_INT_MSK		0x0000000000000008ULL
#define	SXGE_MB_MSK_OMB_ACK_INT_MSK		0x0000000000000004ULL
#define	SXGE_MB_MSK_OMB_FAILED_INT_MSK		0x0000000000000002ULL

#define	SXGE_OMB(entry)		(STAND_RESOURCE_BASE + 0x80 + (8 * entry))
#define	SXGE_IMB(entry)		(STAND_RESOURCE_BASE + 0xD0 + (8 * entry))
#define	SXGE_IMB_ACK		(STAND_RESOURCE_BASE + 0x110)
#define	SXGE_IMB_ACK_IMB_NACK	0x0000000000000002ULL
#define SXGE_IMB_ACK_IMB_ACK	0x0000000000000001ULL

/* Host/EPS MBOX related data structs */
#define	SXGE_MB_MAX_LEN				0x7 /* Number of 64-bit words */
#define	SXGE_MB_GET_CAPAB			0x100
#define	SXGE_MB_GET_L2_ADDR_CAP			(SXGE_MB_GET_CAPAB + 0x01)
#define	SXGE_MB_GET_TCAM_CAP			(SXGE_MB_GET_CAPAB + 0x02)

#define	SXGE_MB_CLS_OPS			0x200
#define	SXGE_MB_L2_ADDR_ADD		(SXGE_MB_CLS_OPS + 0x0)
#define	SXGE_MB_L2_ADDR_REM		(SXGE_MB_CLS_OPS + 0x1)
#define	SXGE_MB_L2_MCAST_ADD		(SXGE_MB_CLS_OPS + 0x2)
#define	SXGE_MB_L2_MCAST_REM		(SXGE_MB_CLS_OPS + 0x3)
#define	SXGE_MB_VLAN_ADD		(SXGE_MB_CLS_OPS + 0x4)
#define	SXGE_MB_VLAN_REMOVE		(SXGE_MB_CLS_OPS + 0x5)
#define	SXGE_MB_L3L4_TCAM_ADD		(SXGE_MB_CLS_OPS + 0x6)
#define	SXGE_MB_L3L4_TCAM_REMOVE	(SXGE_MB_CLS_OPS + 0x7)
#define	SXGE_MB_RSS_HASH		(SXGE_MB_CLS_OPS + 0x8)
#define	SXGE_MB_LINK_SPEED		(SXGE_MB_CLS_OPS + 0x9)

#define	SXGE_MB_REQUEST			0x01
#define	SXGE_MB_RESPONSE		0x02

#define	MB_TAG_LEN		0x00000000000000ffULL
#define	MB_TAG_LEN_SHIFT	0
#define	MB_TAG_TYPE		0x00000000ffff0000ULL
#define	MB_TAG_TYPE_SHIFT	16
#define	MB_TAG_REQ		0x0000ffff00000000ULL
#define	MB_TAG_REQ_SHIFT	32
#define	MB_TAG_SEQ		0xffff000000000000ULL
#define	MB_TAG_SEQ_SHIFT	48

struct sxge_mb_msg {
	u64	len;
	u64	msg_data[SXGE_MB_MAX_LEN];
};

struct l2_address_req {
	u64	mb_tag;
	u64	addr;
	u64	mask;
	u64	slot;
	u64	rsv1;
	u64	rsv2;
};

#define	SXGE_MB_L2_ADDR_REQ_LEN	(sizeof(struct l2_address_req)/sizeof(u64))

struct mb_cap {
	u64	mb_tag;
	u64	n_u_addrs;
	u64	n_m_addrs;
	u64	link_speed;
	u64	rsv1;
	u64	rsv2;
	u64	rsv3;
};

#define	SXGE_MB_CAP_LEN		(sizeof (struct mb_cap) / sizeof (u64))
#define	SXGE_MB_PCS_MODE_SHIFT	16
#define	SXGE_MB_PCS_MODE_MASK	0x30000
#define	SXGE_MB_PCS_MODE_KR	0x0
#define	SXGE_MB_PCS_MODE_KX4	0x1
#define	SXGE_MB_PCS_MODE_X	0x2
#define	SXGE_MB_PCS_MODE_KR4	0x3
#define	SXGE_MB_40G_MODE_INDEX	4

#define	SXGE_MAX_TCAM_ENTRY_PER_FUNC	4

/* TX related data structs */
struct tx_pkt_hdr {
	__le64	flags;
#define TXHDR_PAD		0x0000000000000007ULL
#define  TXHDR_PAD_SHIFT	0
#define	TXHDR_FC_OFFSET		0x000000000000ff00ULL
#define  TXHDR_FC_OFFSET_SHIFT	8
#define TXHDR_LEN		0x000000003fff0000ULL
#define  TXHDR_LEN_SHIFT	16
#define TXHDR_L4STUFF		0x0000003f00000000ULL
#define  TXHDR_L4STUFF_SHIFT	32
#define TXHDR_L4START		0x00003f0000000000ULL
#define  TXHDR_L4START_SHIFT	40
#define TXHDR_L3START		0x000f000000000000ULL
#define  TXHDR_L3START_SHIFT	48
#define TXHDR_IHL		0x00f0000000000000ULL
#define  TXHDR_IHL_SHIFT	52
#define TXHDR_VLAN		0x0100000000000000ULL
#define TXHDR_LLC		0x0200000000000000ULL
#define	TXHDR_PKT_TYPE		0x0400000000000000ULL
#define TXHDR_IP_VER		0x2000000000000000ULL
#define TXHDR_CSUM_NONE		0x0000000000000000ULL
#define TXHDR_CSUM_TCP		0x4000000000000000ULL
#define TXHDR_CSUM_UDP		0x8000000000000000ULL
#define TXHDR_CSUM_SCTP		0xc000000000000000ULL
	__le64	resv;
};

#define TX_DESC_SOP		0x8000000000000000ULL
#define TX_DESC_MARK		0x4000000000000000ULL
#define TX_DESC_NUM_PTR		0x3c00000000000000ULL
#define TX_DESC_NUM_PTR_SHIFT	58
#define	TX_DESC_CKSUM_EN	0x0200000000000000ULL
#define	TX_DESC_CKSUM_EN_SHIFT	57
#define TX_DESC_TR_LEN		0x01fff00000000000ULL
#define TX_DESC_TR_LEN_SHIFT	44
#define TX_DESC_SAD		0x00000fffffffffffULL
#define TX_DESC_SAD_SHIFT	0

struct tx_buff_info {
	struct sk_buff *skb;
	u64 mapping;
};

struct txdma_mailbox {
	__le64	tx_dma_pre_st;
	__le64	tx_cs;
	__le64	tx_ring_kick;
	__le64	tx_ring_hdl;
	__le64	resv[4];
} __attribute__((aligned(64)));

#define	MAX_TX_RING_SIZE	1024
#define	MAX_TX_DESC_LEN		4076

struct tx_ring_info {
	struct tx_buff_info	tx_buffs[MAX_TX_RING_SIZE];
	struct sxge		*sxgep;
	u8			vni;
	u8			vmac;
	u32			tdc_base;
	u32			vmac_base;
	u64			tx_cs;
	int			pending;
	int			prod;
	int			cons;
	int			wrap_bit;
	u16			last_pkt_cnt;
	u16			tx_channel;
	u16			mark_counter;
	u16			mark_freq;
	u16			mark_pending;
	u16			__pad;
	struct txdma_mailbox	*mbox;
	__le64			*descr;

	u64			tx_packets;
	u64			tx_bytes;
	u64			tx_errors;

	u64			mbox_dma;
	u64			descr_dma;
	int			max_burst;
	u64			tdc_prsr_en;
};

#define NEXT_TX(tp, index) \
	(((index) + 1) < (tp)->pending ? ((index) + 1) : 0)

static inline int sxge_tx_avail(struct tx_ring_info *tp)
{
	return tp->pending -
		((tp->prod - tp->cons) & (MAX_TX_RING_SIZE - 1));
}

struct rxdma_mailbox {
	__le64  rx_dma_ctl_stat;
	__le64  rbr_stat;
	__le32  rbr_tail_rcr_head;
	__le32  resv0;
	__le64  resv1[5];
} __attribute__((aligned(64)));

#define	MAX_RBR_RING_SIZE	1024
#define	MAX_RCR_RING_SIZE	(MAX_RBR_RING_SIZE * 2)

#define	RBR_REFILL_MIN		16

#define	RX_SKB_ALLOC_SIZE	(128 + NET_IP_ALIGN)

struct rx_ring_info {
	struct sxge		*sxgep;
	u8			rx_channel;
	u8			vni;
	u8			vmac;
	u32			rdc_base;
	u32			vmac_base;
	u16			rbr_block_size;
	u16			rbr_blocks_per_page;
	u16			rbr_sizes[4];
	unsigned int		rcr_index;
	u64			rcr_head_wrap;
	u64			rcr_tail_wrap;
	unsigned int		rcr_table_size;
	unsigned int		rbr_index;
	u64			rbr_tail;
	u64			rbr_tail_wrap;
	u64			rbr_head_wrap;
	unsigned int		rbr_pending;
	unsigned int		rbr_refill_pending;
	unsigned int		rbr_kick_thresh;
	unsigned int		rbr_table_size;
	struct page		**rxpage;
	pgoff_t			saved_base[MAX_RBR_RING_SIZE * 2];
	struct rxdma_mailbox	*mbox;
	__le64			*rcr;
	__le64			*rbr;
#define	RBR_DESCR_INDEX		0x0ffff00000000000ULL
#define	RBR_DESCR_INDEX_SHIFT	44
#define	RBR_DESCR_ADDR		0x00000000ffffffffULL
#define	RBR_DESCR_ADDR_SHIFT	12

	u64			rx_packets;
	u64			rx_bytes;
	u64			rx_dropped;
	u64			rx_errors;
	u64			rx_hw_pktcnt;
	u64			rx_hw_pktdrop;
	u64			rx_rbr_empty;
	u64			rx_fifo_error;
	u64			rx_rcr_shadow_full;

	u64			mbox_dma;
	u64			rcr_dma;
	u64			rbr_dma;

	/* interrupt mitigation */
	int			rcr_pkt_threshold;
	int			rcr_timeout;
};

#define NEXT_RCR(rp, index) \
	(((index) + 1) < (rp)->rcr_table_size ? ((index) + 1) : 0)
#define NEXT_RBR(rp, index) \
	(((index) + 1) < (rp)->rbr_table_size ? ((index) + 1) : 0)

#define	SPEED_40000	40000
#define	SPEED_4000	4000

struct sxge_link_config {
	u32		supported;

	/* Describes what we're trying to get. */
	u32		advertising;
	u16		speed;
	u8		duplex;
	u8		autoneg;

	/* Describes what we actually have. */
	u32		active_advertising;
	u16		active_speed;
	u8		active_duplex;
	u8		active_autoneg;
};

struct sxge_ldg {
	struct napi_struct	napi;
	struct sxge	*sxgep;
	u8		ldg_num;
	u8		timer;
	u64		v;
	unsigned int	irq;
};

struct sxge_vmac_stats {
	u64	txvmac_frames;
	u64	txvmac_bytes;
	u64	txvmac_frame_cnt_ovl;
	u64	txvmac_byte_cnt_ovl;

	u64	rxvmac_frames;
	u64	rxvmac_bytes;
	u64	rxvmac_drops;
	u64	rxvmac_drop_bytes;
	u64	rxvmac_mcasts;
	u64	rxvmac_bcasts;
	u64	rxvmac_frames_cnt_ovl;
	u64	rxvmac_byte_cnt_ovl;
	u64	rxvmac_drop_cnt_ovl;
	u64	rxvmac_drop_byte_ovl;
	u64	rxvmac_mcast_frame_cnt_ovl;
	u64	rxvmac_bcast_frame_cnt_ovl;
	u64	rxvmac_link_up;
	u64	rxvmac_link_down;
	u64	rxvmac_link_state;
};

#define MBOX_LOOKUP_TABLE_SIZE	15
struct mailbox_lookup_t {
	u8	mac[ETH_ALEN];
	u8	history_mac[ETH_ALEN];
	u64	last_used;
	u32	flag;
};

struct sxge {
	void __iomem		*regs;
	struct net_device	*dev;
	struct pci_dev		*pdev;
	struct device		*device;
	u32			flags;
#define	SXGE_FLAGS_MSIX		0x00400000	/* MSI-X in use */
#define	SXGE_FLAGS_MCAST	0x00200000
#define	SXGE_FLAGS_PROMISC	0x00100000
#define	SXGE_FLAGS_SRIOV	0x00800000
#define	SXGE_FLAGS_HW_INIT	0x01000000

	u32			msg_enable;
	/* Protects hw programming, and ring state.  */
	spinlock_t		lock;

	const struct sxge_ops	*ops;
	struct sxge_vmac_stats	vmac_stats;

	/* RDAT resource */
	u8			piobar_resource[MAX_PIOBAR_RESOURCE];
	u8			vni;
	u8			vmac;

	struct rx_ring_info	*rx_rings;
	struct tx_ring_info	*tx_rings;
	int			num_rings;

	struct sxge_ldg		ldg[SXGE_NUM_LDG];
	int			num_ldg;
	u8			ldg_map[LDN_MAX + 1];
	u8			intmgmt_nf;

	struct sxge_link_config	link_config;

	struct work_struct	reset_task;
	u8			devfn;
	u8			dev_busnum;
	u64			sxge_mb_stat;

	struct mailbox_lookup_t mb_lookup_p[MBOX_LOOKUP_TABLE_SIZE];
};

struct sxge_ops {
	void *(*alloc_coherent)(struct device *dev, size_t size,
				u64 *handle, gfp_t flag);
	void (*free_coherent)(struct device *dev, size_t size,
				void *cpu_addr, u64 handle);
	u64 (*map_page)(struct device *dev, struct page *page,
			unsigned long offset, size_t size,
			enum dma_data_direction direction);
	void (*unmap_page)(struct device *dev, u64 dma_address,
			size_t size, enum dma_data_direction direction);
	u64 (*map_single)(struct device *dev, void *cpu_addr,
			size_t size,
			enum dma_data_direction direction);
	void (*unmap_single)(struct device *dev, u64 dma_address,
			size_t size, enum dma_data_direction direction);
};

#endif /* _SXGE_H */
