/*****************************************************************************
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
*
* Copyright 2009, 2011 Oracle America, Inc. All rights reserved.
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU General Public License version 2 only, as published by
* the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE.  See the GNU General Public License version 2 for
* more details (a copy is included in the LICENSE file that accompanied this
* code).
*
* You should have received a copy of the GNU General Public License version 2
* along with this program; If not,
* see http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*
* Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 or
* visit www.oracle.com if you need additional information or have any
* questions.
*
******************************************************************************/

#ifndef	_HXGE_HXGE_RXDMA_H
#define	_HXGE_HXGE_RXDMA_H

#include "hxge_rdc_hw.h"

#define	RXDMA_CK_DIV_DEFAULT		7500 	/* 25 usec */
#define	RXDMA_RCR_PTHRES_DEFAULT	0x20
#define	RXDMA_RCR_TO_DEFAULT		0x8
#define	RXDMA_HDR_SIZE_DEFAULT		2
#define	RXDMA_HDR_SIZE_FULL		6	/* entire header of 6B */

/*
 * Receive Completion Ring (RCR)
 */
#define	RCR_PKT_BUF_ADDR_SHIFT		0			/* bit 37:0 */
#define	RCR_PKT_BUF_ADDR_SHIFT_FULL	6	/* fulll buffer address */
#define	RCR_PKT_BUF_ADDR_MASK		0x0000003FFFFFFFFFULL
#define	RCR_PKTBUFSZ_SHIFT		38			/* bit 39:38 */
#define	RCR_PKTBUFSZ_MASK		0x000000C000000000ULL
#define	RCR_L2_LEN_SHIFT		40			/* bit 39:38 */
#define	RCR_L2_LEN_MASK			0x003fff0000000000ULL
#define	RCR_ERROR_SHIFT			54			/* bit 57:55 */
#define	RCR_ERROR_MASK			0x03C0000000000000ULL
#define	RCR_PKT_TYPE_SHIFT		61			/* bit 62:61 */
#define	RCR_PKT_TYPE_MASK		0x6000000000000000ULL
#define	RCR_MULTI_SHIFT			63			/* bit 63 */
#define	RCR_MULTI_MASK			0x8000000000000000ULL

#define	RCR_PKTBUFSZ_0			0x00
#define	RCR_PKTBUFSZ_1			0x01
#define	RCR_PKTBUFSZ_2			0x02
#define	RCR_SINGLE_BLOCK		0x03

#define	RCR_NO_ERROR			0x0
#define	RCR_CTRL_FIFO_DED		0x1
#define	RCR_DATA_FIFO_DED		0x2
#define	RCR_ERROR_RESERVE		0x4

#define RCR_PKT_TCP			0x1
#define RCR_PKT_UDP			0x2
#define	RCR_PKT_IS_TCP			0x2000000000000000ULL
#define	RCR_PKT_IS_UDP			0x4000000000000000ULL
#define	RCR_PKT_IS_SCTP			0x6000000000000000ULL

#define	RDC_INT_MASK_RBRFULL_SHIFT	34		/* bit 2: 0 to flag */
#define	RDC_INT_MASK_RBRFULL_MASK	0x0000000400000000ULL
#define	RDC_INT_MASK_RBREMPTY_SHIFT	35		/* bit 3: 0 to flag */
#define	RDC_INT_MASK_RBREMPTY_MASK	0x0000000800000000ULL
#define	RDC_INT_MASK_RCRFULL_SHIFT	36		/* bit 4: 0 to flag */
#define	RDC_INT_MASK_RCRFULL_MASK	0x0000001000000000ULL
#define	RDC_INT_MASK_RCRSH_FULL_SHIFT	39		/* bit 7: 0 to flag */
#define	RDC_INT_MASK_RCRSH_FULL_MASK	0x0000008000000000ULL
#define	RDC_INT_MASK_RBR_PRE_EMPTY_SHIFT	40	/* bit 8: 0 to flag */
#define	RDC_INT_MASK_RBR_PRE_EMPTY_MASK	0x0000010000000000ULL
#define	RDC_INT_MASK_RCR_SHA_PAR_SHIFT	43		/* bit 12: 0 to flag */
#define	RDC_INT_MASK_RCR_SHA_PAR_MASK	0x0000080000000000ULL
#define	RDC_INT_MASK_RBR_PRE_PAR_SHIFT	44		/* bit 11: 0 to flag */
#define	RDC_INT_MASK_RBR_PRE_PAR_MASK	0x0000100000000000ULL
#define	RDC_INT_MASK_RCRTO_SHIFT	45		/* bit 13: 0 to flag */
#define	RDC_INT_MASK_RCRTO_MASK		0x0000200000000000ULL
#define	RDC_INT_MASK_THRES_SHIFT	46		/* bit 14: 0 to flag */
#define	RDC_INT_MASK_THRES_MASK		0x0000400000000000ULL
#define	RDC_INT_MASK_RBR_CPL_SHIFT	53		/* bit 21: 0 to flag */
#define	RDC_INT_MASK_RBR_CPL_MASK	0x0020000000000000ULL
#define	RDC_INT_MASK_ALL	(RDC_INT_MASK_RBRFULL_MASK |		\
				RDC_INT_MASK_RBREMPTY_MASK |		\
				RDC_INT_MASK_RCRFULL_MASK |		\
				RDC_INT_MASK_RCRSH_FULL_MASK |		\
				RDC_INT_MASK_RBR_PRE_EMPTY_MASK |	\
				RDC_INT_MASK_RCR_SHA_PAR_MASK |		\
				RDC_INT_MASK_RBR_PRE_PAR_MASK |		\
				RDC_INT_MASK_RCRTO_MASK |		\
				RDC_INT_MASK_THRES_MASK |		\
				RDC_INT_MASK_RBR_CPL_MASK)

#define	RDC_LDF1		(RDC_INT_MASK_RBRFULL_MASK |		\
				RDC_INT_MASK_RBREMPTY_MASK |		\
				RDC_INT_MASK_RCRFULL_MASK |		\
				RDC_INT_MASK_RCRSH_FULL_MASK |		\
				RDC_INT_MASK_RBR_PRE_EMPTY_MASK |	\
				RDC_INT_MASK_RCR_SHA_PAR_MASK |		\
				RDC_INT_MASK_RBR_PRE_PAR_MASK |		\
				RDC_INT_MASK_RBR_CPL_MASK)
				

#define	RDC_STAT_PKTREAD_SHIFT			0	/* WO, bit 15:0 */
#define	RDC_STAT_PKTREAD_MASK			0x000000000000ffffULL
#define	RDC_STAT_PTRREAD_SHIFT			16	/* WO, bit 31:16 */
#define	RDC_STAT_PTRREAD_MASK			0x00000000FFFF0000ULL

#define	RDC_STAT_RBRFULL_SHIFT			34	/* RO, bit 34 */
#define	RDC_STAT_RBRFULL			0x0000000400000000ULL
#define	RDC_STAT_RBRFULL_MASK			0x0000000400000000ULL
#define	RDC_STAT_RBREMPTY_SHIFT			35	/* RW1C, bit 35 */
#define	RDC_STAT_RBREMPTY			0x0000000800000000ULL
#define	RDC_STAT_RBREMPTY_MASK			0x0000000800000000ULL
#define	RDC_STAT_RCR_FULL_SHIFT			36	/* RW1C, bit 36 */
#define	RDC_STAT_RCR_FULL			0x0000001000000000ULL
#define	RDC_STAT_RCR_FULL_MASK			0x0000001000000000ULL

#define	RDC_STAT_RCR_SHDW_FULL_SHIFT 		39	/* RO, bit 39 */
#define	RDC_STAT_RCR_SHDW_FULL 			0x0000008000000000ULL
#define	RDC_STAT_RCR_SHDW_FULL_MASK 		0x0000008000000000ULL
#define	RDC_STAT_RBR_PRE_EMPTY_SHIFT 		40	/* RO, bit 40 */
#define	RDC_STAT_RBR_PRE_EMPTY 			0x0000010000000000ULL
#define	RDC_STAT_RBR_PRE_EMPTY_MASK  		0x0000010000000000ULL

#define	RDC_STAT_RCR_SHA_PAR_SHIFT 		43	/* RO, bit 43 */
#define	RDC_STAT_RCR_SHA_PAR 			0x0000080000000000ULL
#define	RDC_STAT_RCR_SHA_PAR_MASK  		0x0000080000000000ULL
#define	RDC_STAT_RBR_PRE_PAR_SHIFT 		44	/* RO, bit 44 */
#define	RDC_STAT_RBR_PRE_PAR 			0x0000100000000000ULL
#define	RDC_STAT_RBR_PRE_PAR_MASK  		0x0000100000000000ULL

#define	RDC_STAT_RCR_TO_SHIFT			45	/* RW1C, bit 45 */
#define	RDC_STAT_RCR_TO				0x0000200000000000ULL
#define	RDC_STAT_RCR_TO_MASK			0x0000200000000000ULL
#define	RDC_STAT_RCR_THRES_SHIFT		46	/* RO, bit 46 */
#define	RDC_STAT_RCR_THRES			0x0000400000000000ULL
#define	RDC_STAT_RCR_THRES_MASK			0x0000400000000000ULL
#define	RDC_STAT_RCR_MEX_SHIFT			47	/* RW, bit 47 */
#define	RDC_STAT_RCR_MEX			0x0000800000000000ULL
#define	RDC_STAT_RCR_MEX_MASK			0x0000800000000000ULL

#define	RDC_STAT_RBR_CPL_SHIFT			53	/* RO, bit 53 */
#define	RDC_STAT_RBR_CPL			0x0020000000000000ULL
#define	RDC_STAT_RBR_CPL_MASK			0x0020000000000000ULL
#define	RX_DMA_CTRL_STAT_ENT_MASK_SHIFT 	32

#define	RDC_STAT_ERROR 				(RDC_INT_MASK_ALL << \
						RX_DMA_CTRL_STAT_ENT_MASK_SHIFT)

/* the following are write 1 to clear bits */
#define	RDC_STAT_WR1C		(RDC_STAT_RBREMPTY | 		\
				RDC_STAT_RCR_SHDW_FULL | 	\
				RDC_STAT_RBR_PRE_EMPTY | 	\
				RDC_STAT_RCR_TO | 		\
				RDC_STAT_RCR_THRES)

#define RCR_CFGB_ENABLE_TIMEOUT	0x8000

typedef union _rcr_entry_t {
	uint64_t value;
	struct {
#if defined(__BIG_ENDIAN)
		uint64_t multi:1;
		uint64_t pkt_type:2;
		uint64_t reserved1:3;
		uint64_t error:3;
		uint64_t reserved2:1;
		uint64_t l2_len:14;
		uint64_t pktbufsz:2;
		uint64_t pkt_buf_addr:38;
#else
		uint64_t pkt_buf_addr:38;
		uint64_t pktbufsz:2;
		uint64_t l2_len:14;
		uint64_t reserved2:1;
		uint64_t error:3;
		uint64_t reserved1:3;
		uint64_t pkt_type:2;
		uint64_t multi:1;
#endif
	} bits;
} rcr_entry_t, *p_rcr_entry_t;

typedef union _pkt_hdr_twobyte_t {
	uint16_t value;
	struct {
#if defined (_BIG_ENDIAN)
		uint16_t rsvd:1;
		uint16_t l4_cs_eq:1;
		uint16_t maccheck:1;
		uint16_t class:5;
		uint16_t vlan:1;
		uint16_t bcast_frame:1;
		uint16_t noport:1;
		uint16_t badip:1;
		uint16_t tcamhit:1;
		uint16_t drop_code:3;
#else
		uint16_t drop_code:3;
		uint16_t tcamhit:1;
		uint16_t badip:1;
		uint16_t noport:1;
		uint16_t bcast_frame:1;
		uint16_t vlan:1;
		uint16_t class:5;
		uint16_t maccheck:1;
		uint16_t l4_cs_eq:1;
		uint16_t rsvd:1;
#endif
	} bits;
} pkt_hdr_twobyte_t, *p_pkt_hdr_twobyte_t;
		

#define	RX_DMA_MAILBOX_BYTE_LENGTH	64
#define	RX_DMA_MBOX_UNUSED_1		8
#define	RX_DMA_MBOX_UNUSED_2		16

typedef struct _rxdma_mailbox_t {
	rdc_stat_t		rxdma_ctl_stat;		/* 8 bytes */
	rdc_rbr_qlen_t		rbr_qlen;		/* 8 bytes */
	rdc_rbr_head_t		rbr_hdh;		/* 8 bytes */
	uint8_t			resv_1[RX_DMA_MBOX_UNUSED_1];
	rdc_rcr_tail_t		rcr_tail;		/* 8 bytes */
	uint8_t			resv_2[RX_DMA_MBOX_UNUSED_1];
	rdc_rcr_qlen_t		rcr_qlen;		/* 8 bytes */
	uint8_t			resv_3[RX_DMA_MBOX_UNUSED_1];
} rxdma_mailbox_t, *p_rxdma_mailbox_t;

/*
 * hardware workarounds: kick 16 (was 8 before)
 */
#define	HXGE_RXDMA_POST_BATCH		16

#define	RXBUF_START_ADDR(a, index, bsize)	((a & (index * bsize))
#define	RXBUF_OFFSET_FROM_START(a, start)	(start - a)
#define	RXBUF_64B_ALIGNED		64

#define	HXGE_RXBUF_EXTRA		34

/*
 * Receive buffer thresholds and buffer types
 */
#define	HXGE_RX_BCOPY_SCALE	8	/* use 1/8 as lowest granularity */

typedef enum  {
	HXGE_RX_COPY_ALL = 0,		/* do bcopy on every packet	 */
	HXGE_RX_COPY_1,			/* bcopy on 1/8 of buffer posted */
	HXGE_RX_COPY_2,			/* bcopy on 2/8 of buffer posted */
	HXGE_RX_COPY_3,			/* bcopy on 3/8 of buffer posted */
	HXGE_RX_COPY_4,			/* bcopy on 4/8 of buffer posted */
	HXGE_RX_COPY_5,			/* bcopy on 5/8 of buffer posted */
	HXGE_RX_COPY_6,			/* bcopy on 6/8 of buffer posted */
	HXGE_RX_COPY_7,			/* bcopy on 7/8 of buffer posted */
	HXGE_RX_COPY_NONE		/* don't do bcopy at all	 */
} hxge_rxbuf_threshold_t;

typedef enum  {
	HXGE_RBR_TYPE0 = RCR_PKTBUFSZ_0,  /* bcopy buffer size 0 (small) */
	HXGE_RBR_TYPE1 = RCR_PKTBUFSZ_1,  /* bcopy buffer size 1 (medium) */
	HXGE_RBR_TYPE2 = RCR_PKTBUFSZ_2	  /* bcopy buffer size 2 (large) */
} hxge_rxbuf_type_t;

typedef	struct _rdc_errlog {
	rdc_pref_par_log_t	pre_par;
	rdc_pref_par_log_t	sha_par;
	uint8_t			compl_err_type;
} rdc_errlog_t;



/* RBR Descriptor entries are 4-bytes long */
typedef uint32_t rbr_desc_entry_t;

struct rx_desc_t {
	caddr_t		vaddr;
	dma_addr_t    dma_addr;
};

struct rx_hash_entry {
	unsigned long dma_addr;
	int index;
	struct rx_hash_entry *next;
};


/* Receive Completion Ring */
typedef struct _rx_rcr_ring_t {

        uint32_t                num_rcr_entries;
        struct rcr_desc_t {
		rcr_entry_t	*vaddr;
		dma_addr_t	dma_addr;
        } rcr_addr;

	/* Current location where processing is to take place next */
	uint32_t		rcr_curr_loc;

        /* Copies of HW registers */
        rdc_rcr_cfg_a_t         rcr_cfga;
        rdc_rcr_cfg_b_t         rcr_cfgb;
        boolean_t               cfg_set;
} rx_rcr_ring_t, *p_rx_rcr_ring_t;


struct rx_rbr_entry_t {
	struct rbr_desc_addr_t {
		rbr_desc_entry_t *vaddr;
		dma_addr_t	dma_addr;
	} addr;
	int			index;
	struct page 		*page;
	uint32_t		max_pkts;
	uint32_t		pkt_size;
	int 			in_use;
};


struct rx_ring_stats_t {
	/* Maintained by software */

	uint64_t	ipackets;
	uint64_t	ibytes;
	uint64_t	ierrors;
	uint64_t	jumbo_pkts;
	uint64_t	nomem_drop;

	uint64_t	ecc_errors;

	uint64_t	rbr_cpl_tmout;
	uint64_t	peu_resp_err;
	uint64_t	rcr_shadow_parity;
	uint64_t	rcr_prefetch_parity;
	uint64_t	rbr_prefetch_empty;
	uint64_t	rcr_shadow_full;
	uint64_t	rcr_full;
	uint64_t	rbr_empty;
	uint64_t	rbr_empty_handled;
	uint64_t	rbr_empty_posted;
	uint64_t	rbr_full;
	uint64_t	rcr_to;
	uint64_t	rcr_thres;

	/* Hardware counters */
	uint64_t	pkt_cnt; 
	uint64_t	pkt_too_long;
	uint64_t	no_rbr_avail;
	uint64_t	rvm_errors;
	uint64_t	frame_errors;
	uint64_t	ram_errors;

	uint64_t 	crc_errors;
	
};


typedef struct _rx_rbr_ring_t {

	struct rx_rbr_entry_t   *buf_blocks;
	struct rbr_desc_t {
		rbr_desc_entry_t *vaddr;
		dma_addr_t	 dma_addr;
	} rbr_addr;
	unsigned int		buf_blocks_order;
	uint32_t		num_rbr_entries;
	uint32_t		rbr_free_loc;
	uint32_t		pages_to_post;
	uint16_t		rbr_empty_threshold;
	uint16_t		rbr_empty_flag;  /* we are in empty procesing */
	struct rx_hash_entry *hash_table[HASH_TABLE_SIZE];
	
	
	/* Copies of what is in the HW registers */
        rdc_rbr_cfg_a_t         rbr_cfga;
        rdc_rbr_cfg_b_t         rbr_cfgb;
        rdc_rbr_kick_t          rbr_kick;
	boolean_t               cfg_set;

	/* what goes into RBR Configuration B register */
        uint16_t                 pkt_buf_size[4];
        uint16_t                 pkt_buf_size_bytes[4];
} rx_rbr_ring_t, *p_rx_rbr_ring_t;

struct rx_ring_t {
	uint16_t		rdc;

	/* Copies of some HW register */
        rdc_page_handle_t       page_hdl;
	uint16_t		offset;
	boolean_t		full_hdr;
	unsigned long		state;

	rx_rbr_ring_t		rbr;
	rx_rcr_ring_t		rcr;
	struct rx_desc_t	mbox;
	uint16_t		dma_clk_res;
	int			first_time; /* CR 6769038 */
	struct rx_ring_stats_t	stats;

};

#define RX_NO_ERR 	 0
#define RX_DROP_PKT	-1
#define RX_FAILURE	-2

#define RCR_INIT_PATTERN       0x5a5a6b6b7c7c8d8dULL

#define GET_RCR_ENTRY(entry) \
	&entry->rcr_addr.vaddr[entry->rcr_curr_loc]

/* SW workaround for CR 6698258: One of the side effects of this bug is to
 * push rcr entries that have already been processed, causing the packet 
 * processing routines to complain about "bad packets". Hydra could flush
 * 64B cache line into memory at particular junctures (see bug for details).
 * In order to avoid getting old packet addresses, we should initialize 
 * the entire cache line once we have processed the last entry in a cache
 * line (rcr_ring is aligned to 64B)
 */
#define INCREMENT_RCR_ENTRY_TO_NEXT(rcr_ring) \
	{ \
        if ((rcr_ring->rcr_curr_loc & 0x7) == 0x7) { \
                uint32_t tmp_loc = rcr_ring->rcr_curr_loc- 7; \
                int i; \
                for (i = 0; i < 8; i++) \
                        rcr_ring->rcr_addr.vaddr[tmp_loc+i].value = RCR_INIT_PATTERN; \
        } \
	rcr_ring->rcr_curr_loc = (rcr_ring->rcr_curr_loc+1) % rcr_ring->num_rcr_entries; \
	}
#endif 
