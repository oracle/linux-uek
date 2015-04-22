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

#ifndef	_HXGE_HXGE_TXDMA_H
#define	_HXGE_HXGE_TXDMA_H

#include "hxge_txdma_hw.h"
#include <linux/llc.h>

#define	TXDMA_RECLAIM_PENDING_DEFAULT		64
#define	TX_FULL_MARK				3

/*
 * Descriptor ring empty:
 *		(1) head index is equal to tail index.
 *		(2) wrapped around bits are the same.
 * Descriptor ring full:
 *		(1) head index is equal to tail index.
 *		(2) wrapped around bits are different.
 *
 */
#define	TXDMA_RING_EMPTY(head, head_wrap, tail, tail_wrap)	\
	((head == tail && head_wrap == tail_wrap) ? TRUE : FALSE)

#define	TXDMA_RING_FULL(head, head_wrap, tail, tail_wrap)	\
	((head == tail && head_wrap != tail_wrap) ? TRUE: FALSE)

#define	TXDMA_DESC_NEXT_INDEX(index, entries, wrap_mask) \
			((index + entries) & wrap_mask)

#define TXDMA_GET_CURR_INDEX(tx_ring) \
	tx_ring->curr_index = tx_ring->tail

#define TXDMA_GET_NEXT_INDEX(tx_ring, entries) \
	tx_ring->curr_index = (tx_ring->curr_index+entries) % tx_ring->num_tdrs;

#define TXDMA_DEC_INDEX(tx_ring) \
	tx_ring->curr_index = (tx_ring->curr_index-1); \
	if (tx_ring->curr_index < 0) \
		tx_ring->curr_index = tx_ring->num_tdrs-1;

#define TXDMA_UPDATE_INDEX(tx_ring) \
	if (tx_ring->curr_index < tx_ring->tail) \
		tx_ring->wrap = (tx_ring->wrap == TRUE) ? FALSE : TRUE; \
	tx_ring->tail = tx_ring->curr_index;


#define RECLAIM_TIMEOUT         5 /* 5 ms (in jiffies) */

#define HXGE_TX_DESCS_MIN 	32  /* 32 entries */
#define HXGE_TX_DESCS_DEFAULT	1024 /* 1024 entries */
#define HXGE_TX_DESCS_MAX	5120 /* 10 4K pages worth */

#define HXGE_TX_DESCS_PER_PACKET	15

#define HXGE_TX_BUF_SZ_MIN	256 /* in bytes */
#define HXGE_TX_BUF_SZ_MAX	4096 /* 4KB */

#define TX_FLAGS_UNUSED 0x0
#define TX_FLAGS_HDR    0x1 /* descriptor contains only internal header */
#define TX_FLAGS_ALL  0x2 /* small packet; internal header + skb */
#define TX_FLAGS_DATA 0x4 /* packet only contains data */
#define TX_FLAGS_UNMAP 0x8 /* unmap the page when skb is freed */
#define TX_FLAGS_ALLOC 0x10 /* allocated data page dynamically */


#define SKB_IS_GSO(skb) skb_shinfo(skb)->gso_size
#define SKB_GSO_SEGS(skb) skb_shinfo(skb)->gso_segs

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 19)
#define SKB_CKSUM_OFFSET(skb) skb->csum_offset
#define HXGE_CHECKSUM CHECKSUM_PARTIAL
#else
#define SKB_CKSUM_OFFSET(skb) skb->csum
#define HXGE_CHECKSUM CHECKSUM_HW
#endif

/* When we are in GSO mode, the maximum possible number of Tx descriptors 
 * required is 7. The max possible frame size is ~9KB because this is the 
 * largest MTU possible for Hydra. Then, the math breaks down as follows
 *	1 - for the L2/L3/L4 header (have 256 bytes of space available)
 *	1 - fragment starting at some random offset 
 *	2 - 4096 byte fragment (Tx descriptor can only take 4076 bytes)
 *	2 - 4096 byte fragment (     "   )
 *	1 - (potential) remnant left-over fragment 
 */
#define DESCS_PER_FRAME 7


/* Keep a copy of the Tx descriptor and information required to unmap the dma
 * address once we are done with it 
 */
struct staging_desc_t {
	tx_desc_t	entry;
	dma_addr_t	addr;
	char		*vaddr;
	int 		len;
};

struct dma_map_t
{
	dma_addr_t	dma_addr;
	caddr_t		vaddr;
	int		len;
};

/* structure that tracks the dma mappings created for the various SKB 
   fragments and the main buffer
*/
struct pci_dma_map_t {
	int	num_dma_mappings;	
	struct dma_map_t *dma_map;
};
	
#define HDR_TEMPLATE_SIZE 256
#define TCP_FLAGS_URG 1
#define TCP_FLAGS_PSH 2
#define TCP_FLAGS_RST 4
#define TCP_FLAGS_FIN 8
struct staging_info_t {
	int	desc_idx;
        tx_pkt_header_t  pkthdr;
	struct staging_desc_t *desc;
	struct dma_map_t hdr_array;
	int	l3_offset;
	int	l4_offset;
	int	l4_hdr_len;
	int	tcpip_hdr_len;
	int	max_frames;
	int 	frame_size;
	int 	dma_map_idx;
	int	dma_map_off;
	struct  pci_dma_map_t pci_map;
	uint32_t tcp_sequence;
	uint16_t ip_id;
	uint8_t  tcp_flags; /* urg=0, psh=1, rst=4, fin=9 */
	char    hdr_template[HDR_TEMPLATE_SIZE];
};

struct skb_hdr_info_t {
        struct dma_map_t        hdr_array;
	struct pci_dma_map_t	pci_map;
        uint8_t                 l4_payload_offset;
};

	
struct tx_buf_t {
	struct sk_buff		*skb;
	struct dma_map_t	map;
	uint32_t		flags;
};
	

struct tx_desc_buf_t {
	dma_addr_t	dma_addr;
	tx_desc_t       *vaddr; /* Tx descriptor ring  */
};

struct tx_mbox_t {
	dma_addr_t	dma_addr;
	txdma_mailbox_t *vaddr;
};

struct tx_data_buf_t {
	dma_addr_t dma_addr;
	caddr_t	   vaddr;
};

struct reclaim_data_t {
	struct hxge_adapter *hxgep;
	int channel;
};

struct tx_ring_stats_t {
	uint64_t	opackets;
	uint64_t	obytes;
	uint64_t	oerrors;
	uint64_t	txlock_acquire_failed;

	/* Hydra specific from control/status */
	uint64_t	marked;
	uint64_t	peu_resp_err;
	uint64_t	pkt_size_hdr_err;
	uint64_t	runt_pkt_drop_err;
	uint64_t	pkt_size_err;
	uint64_t	tx_rng_oflow;
	uint64_t	pref_par_err;
	uint64_t	tdr_pref_cpl_to;
	uint64_t	pkt_cpl_to;
	uint64_t	invalid_sop;
	uint64_t	unexpected_sop;
	uint64_t	hdr_error_cnt;
	uint64_t	abort_cnt;
	uint64_t	runt_cnt;
	uint64_t	descs_avail;
	uint64_t	descs_busy;
	uint64_t	descs_used[16];
};

struct tx_ring_t {
	int		tdc;  /* channel no */
	int 		num_tdrs; /* number of transmit desc entries */
	int 		num_tx_buffers;
	int		tx_buffer_size;
	struct hxge_adapter *hxgep;
	struct tx_desc_buf_t desc_ring;
	spinlock_t 	lock; /* per-channel lock */
	struct tx_data_buf_t   data_buf; /* pointer to packet buffers */
	struct tx_buf_t	*tx_buf;
	struct tx_mbox_t mbox; /* Tx mailbox */
	int 		curr_index; /* running index for free desc location */
	int		tail; /* entry to write next packet in ring */
	int		wrap; /* toggle every time tail wraps around */
	atomic_t        descs_avail; /* # descs available for use */
	int		descs_busy;
	unsigned long	state;
	unsigned int	mark_ints;
	

	
	/* reclaim unused tx buffers **/
	wait_queue_head_t reclaim_event;
	struct completion reclaim_complete;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 13)
	volatile boolean_t kill_reclaim;
	pid_t		  thread_pid;
#else
	struct task_struct *thread_pid;
#endif
	int		  reclaim_head;
	int 		  reclaim_wrap;

	/* stats */
	struct tx_ring_stats_t   stats;
};
	
#endif /* _HXGE_HXGE_TXDMA_H */
