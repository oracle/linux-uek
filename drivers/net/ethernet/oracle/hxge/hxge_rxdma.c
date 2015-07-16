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

#include "hpi/hpi_rxdma.h"
#include "hpi/hpi_vir.h"
#include "hxge.h"

extern wait_queue_head_t ethtool_evnt;
extern volatile int ethtool_cond;
extern struct sk_buff *ethtool_skb;
extern int hxge_get_option(const char *str, int *val);
extern int hxge_ok_to_continue(struct hxge_adapter *hxgep);
extern int hxge_block_reset(struct hxge_adapter *hxgep, int device);
extern void hxge_disable_interrupts(struct hxge_adapter *hxgep);
static int strip_crc_bytes = 0;
extern int hxge_vmac_rx_set_framesize(struct hxge_adapter *hxgep, uint16_t size);

#ifndef CONFIG_ERRINJECT

#define HXGE_KMALLOC kmalloc
#define ALLOC_SKB dev_alloc_skb
#define ALLOC_PAGES alloc_pages

#else

#define HXGE_KMALLOC hxge_kmalloc
#define ALLOC_SKB hxge_alloc_skb
#define ALLOC_PAGES hxge_alloc_pages

static void *hxge_kmalloc(struct hxge_adapter *hxgep, size_t size, gfp_t gfp)
{

	if (hxgep->err_flags & KMEM_FAILURE)
		return NULL;
	else 
		return (kmalloc(size, gfp));
}

static struct sk_buff *hxge_alloc_skb(struct hxge_adapter *hxgep, 
					unsigned int size)
{
	if (hxgep->err_flags & SKB_FAILURE)
		return NULL;
	else
		return (dev_alloc_skb(size));
}

static inline struct page *
hxge_alloc_pages(struct hxge_adapter *hxgep, gfp_t gfp_mask, unsigned int order)
{
	if (hxgep->err_flags & ALLOC_PAGES_FAILURE)
		return NULL;
	else
		return (alloc_pages(gfp_mask, order));
}
#endif

static void parse_rdc_stat(const char *prefix, rdc_stat_t cs)
{
	char rdc_str[400];
	char *str;

		rdc_str[0] = '\0';
		str = rdc_str;

		if (cs.bits.mex)
			str = strcat(str, "mex ");

		if (cs.bits.rcr_thres)
			str = strcat(str, "rcr_thres ");

		if (cs.bits.rcr_to) 
			str  = strcat(str , "rcr_to ");
	
                if (cs.bits.rbr_cpl_to) 
			str  = strcat(str , "rbr_cpl ");

                if (cs.bits.peu_resp_err)
			str  = strcat(str , "peu_resp ");
	
                if (cs.bits.rcr_shadow_par_err)
			str  = strcat(str , "rcr_shad ");

                if (cs.bits.rbr_prefetch_par_err)
			str  = strcat(str , "rbr_pre_par ");

                if (cs.bits.rbr_pre_empty)
			str  = strcat(str , "rbr_preempty ");

                if (cs.bits.rcr_shadow_full)
			str  = strcat(str , "rcr_shad_full ");

                if (cs.bits.rcr_full) 
			str  = strcat(str , "rcr_full ");

                if (cs.bits.rbr_empty)
			str  = strcat(str , "rbr_empty ");

                if (cs.bits.rbr_full)
			str  = strcat(str , "rbr_full ");
	
	HXGE_ERR_PRINT("		%s =>  %s",prefix,str);
}


/* Creating a hash entry based on the DMA address value that is assigned to
   a particular RBR block. This is the way that the receive code is able to 
   find the RBR block from a given DMA address. Note that the DMA address is a
   page-aligned address. So, the compare takes place at the page level only */
static int add_to_hash_table(
#ifdef CONFIG_ERRINJECT
		struct hxge_adapter *hxgep,
#endif
		rx_rbr_ring_t *rbr_ring, int index)
{
	struct rx_hash_entry *hash_entry;
	struct rbr_desc_addr_t desc_addr = rbr_ring->buf_blocks[index].addr;

	int bucket  = (desc_addr.dma_addr>>PAGE_SHIFT) & (HASH_TABLE_SIZE-1);

	hash_entry = HXGE_KMALLOC(
#ifdef CONFIG_ERRINJECT
			hxgep, 
#endif
			sizeof(struct rx_hash_entry), GFP_ATOMIC);
	if (!hash_entry) {
		HXGE_ERR_PRINT("Failed to get memory");
		return RX_FAILURE;
	}
	
	hash_entry->dma_addr = desc_addr.dma_addr;
	hash_entry->index = index;
       if (rbr_ring->hash_table[bucket] == NULL) 
               hash_entry->next = NULL;
       else
               hash_entry->next = rbr_ring->hash_table[bucket];

       rbr_ring->hash_table[bucket] = hash_entry;

	return RX_NO_ERR;
}

static void free_hash_table(rx_rbr_ring_t *rbr_ring)
{
	struct rx_hash_entry *ptr, *next;
	int i;
		
	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		next = ptr = rbr_ring->hash_table[i]; 
		while (next != NULL) {
			next = ptr->next;
			kfree(ptr);
			ptr = next;
		}
		rbr_ring->hash_table[i] = NULL;
	}
}

static int get_index_from_hash(rx_rbr_ring_t *rbr_ring, uint64_t pkt_addr)
{
	int bucket = (pkt_addr >> PAGE_SHIFT) & (HASH_TABLE_SIZE-1);
	struct rx_hash_entry *ptr;

        /* Look in the hash table for a match */
        for (ptr = rbr_ring->hash_table[bucket]; ptr != NULL; ptr=ptr->next)
                if (ptr->dma_addr ==  (pkt_addr & PAGE_MASK))
                        break;

        /* did not find it in the hash table. So, add it */
        if (!ptr) {
                HXGE_ERR_PRINT("Did not find mapping. pkt_addr : 0x%llx",pkt_addr);
                return RX_FAILURE;
        }

        return(ptr->index);
}

#ifdef CONFIG_SKB_SHARED
static int remove_hash_entry(rx_rbr_ring_t *rbr_ring, unsigned long pkt_addr)
{
	int bucket = (pkt_addr >> PAGE_SHIFT) & (HASH_TABLE_SIZE-1);
	struct rx_hash_entry *ptr, *prev_ptr = NULL;

        /* Look in the hash table for a match */
        for (ptr = rbr_ring->hash_table[bucket]; ptr != NULL; 
				prev_ptr=ptr, ptr=ptr->next)
		if (ptr->dma_addr == (pkt_addr & PAGE_MASK))
			break;
	
        /* Did not find it in the hash table; something wrong.. */
        if (!ptr) {
                HXGE_ERR_PRINT("Did not find mapping. pkt_addr : %lu",pkt_addr);
                return RX_FAILURE;
        }

	if (ptr == rbr_ring->hash_table[bucket])
		rbr_ring->hash_table[bucket] = ptr->next;
	else
		prev_ptr->next = ptr->next;
	kfree(ptr);
	return RX_NO_ERR;
}
#endif

static void free_dma_buffer(struct hxge_adapter *hxgep, 
	struct rx_rbr_entry_t *buf_block, boolean_t free_page)
{
	int order = (PAGE_SHIFT-12);
	if (buf_block->addr.dma_addr)
		pci_unmap_page(hxgep->pdev, buf_block->addr.dma_addr,
				PAGE_SIZE, PCI_DMA_FROMDEVICE);
	if ((free_page)  && (buf_block->page))
		__free_pages(buf_block->page, order);

	buf_block->addr.dma_addr = 0;
	buf_block->addr.vaddr = NULL;
	buf_block->page = NULL;
}


static void hxge_free_rx_channel(struct hxge_adapter *hxgep, uint16_t rdc)
{
	int i;
	struct rx_ring_t *rx_ring = &hxgep->rx_ring[rdc];
	struct rx_rbr_entry_t *buf_blocks = rx_ring->rbr.buf_blocks;

	/* Assumption: Entries filled from top down. The first null entry 
           vaddr indicates end of list */
	if (buf_blocks) {
		for (i = 0; buf_blocks[i].addr.vaddr && 
					(i < rx_ring->rbr.num_rbr_entries); i++)
			free_dma_buffer(hxgep, &buf_blocks[i], TRUE);
	}
	HXGE_DBG(hxgep, "Channel %d :",rdc);
	HXGE_DBG(hxgep, "    Freed buf blocks");

	if (rx_ring->rbr.rbr_addr.vaddr) 
		pci_free_consistent(hxgep->pdev, 
			rx_ring->rbr.num_rbr_entries*sizeof(rbr_desc_entry_t),
			rx_ring->rbr.rbr_addr.vaddr,
			rx_ring->rbr.rbr_addr.dma_addr);
	HXGE_DBG(hxgep, "    Freed RBR Descriptor Ring");

	if (rx_ring->rcr.rcr_addr.vaddr)
		pci_free_consistent(hxgep->pdev, 
			rx_ring->rcr.num_rcr_entries*sizeof(rcr_entry_t),
			rx_ring->rcr.rcr_addr.vaddr,
			rx_ring->rcr.rcr_addr.dma_addr);
	HXGE_DBG(hxgep, "    Freed RCR Descriptor Ring");

	if (rx_ring->mbox.vaddr)
		pci_free_consistent(hxgep->pdev, sizeof(rxdma_mailbox_t),
			rx_ring->mbox.vaddr,
			rx_ring->mbox.dma_addr);
	HXGE_DBG(hxgep, "    Freed Mailbox");

	if (rx_ring->rbr.buf_blocks)
		free_pages((unsigned long)rx_ring->rbr.buf_blocks, 
				rx_ring->rbr.buf_blocks_order);
	HXGE_DBG(hxgep, "    Freed Buf block Pages");

	free_hash_table(&rx_ring->rbr);
	HXGE_DBG(hxgep, "    Freed Hash Table");
}

void hxge_free_rx (struct hxge_adapter *hxgep)
{
	int i;
	
	for (i = 0; i < hxgep->max_rdcs; i++)
		hxge_free_rx_channel(hxgep, i);

	if (hxgep->rx_ring)
		kfree(hxgep->rx_ring);
	hxgep->rx_ring = NULL;
}

/* Allocate buffers (if alloc is TRUE), initialize the buf_block meta data 
 * structure and update the hydra RBR kick registers. Also, update the 
 * free location in the RBR descriptor ring where the new free buffer will
 * go 
 */
static int setup_dma_buffers(struct hxge_adapter *hxgep, int channel,
			struct rx_rbr_entry_t *buf_block, int entries, 
			boolean_t alloc, boolean_t init)
{
	struct page *page;
	int order,i;
	struct rx_rbr_entry_t *ptr;
	rx_rbr_ring_t *rbr_ring = &hxgep->rx_ring[channel].rbr;
	int rbr_loc = rbr_ring->rbr_free_loc;
        hpi_handle_t    handle = hxgep->hw.hw_addr;
	int retval = RX_NO_ERR;

        order = (PAGE_SHIFT-12);
	for (i = 0, ptr = buf_block; i < entries; i++, ptr++) {
		if (likely(alloc)) {
			BUG_ON(ptr->page);
			ptr->page = page = ALLOC_PAGES(
#ifdef CONFIG_ERRINJECT
						hxgep,	
#endif
						GFP_ATOMIC, order);
			if (!page) {
				HXGE_ERR(hxgep, "could not allocate buffer");
				retval = RX_DROP_PKT;
				goto failed;
			}
			ptr->addr.vaddr = (rbr_desc_entry_t *)page_address(page);
			ptr->addr.dma_addr = pci_map_page(hxgep->pdev,
				ptr->page, 0, PAGE_SIZE, PCI_DMA_FROMDEVICE); 

			if (!ptr->addr.dma_addr) {
				HXGE_ERR(hxgep, "pci_map_page failed");
				retval = RX_FAILURE;
				goto failed;
			}
			retval = add_to_hash_table(
#ifdef CONFIG_ERRINJECT
					hxgep,
#endif
					rbr_ring, ptr->index);
			if (retval < 0) {
				HXGE_ERR(hxgep, "add_to_hash_table failed");
				goto failed;
			}
		}
		ptr->in_use = 0;
		rbr_ring->rbr_addr.vaddr[rbr_loc] = 
					ptr->addr.dma_addr >> PAGE_SHIFT;
		rbr_loc = (rbr_loc+1) % rbr_ring->num_rbr_entries;
	}

	/* Only done when the channel is initialized */
	if (init == TRUE) {
		rbr_ring->rbr_free_loc = 0;
		rbr_ring->pages_to_post = 0; 
		hpi_rxdma_rdc_rbr_kick(handle, channel, entries);
		HXGE_ERR(hxgep, "Initially kicked %d",entries);
		return RX_NO_ERR;
	}

	rbr_ring->rbr_free_loc = rbr_loc;
	rbr_ring->pages_to_post = entries;

	if (rbr_ring->rbr_empty_flag) 
		rbr_ring->rbr_empty_threshold++;
	else
		hpi_rxdma_rdc_rbr_kick(handle, channel, rbr_ring->pages_to_post);

	return RX_NO_ERR;

failed:
	for (; alloc && i && (ptr >= buf_block); i--, ptr--)
		free_dma_buffer(hxgep, ptr, TRUE);

	return retval;
}


static void print_regs(struct hxge_adapter *hxgep, int type, int channel) 
{
        hpi_handle_t    handle = hxgep->hw.hw_addr;
	rdc_rx_cfg1_t cfg_1;
	rdc_rx_cfg2_t cfg_2;
        rdc_rbr_cfg_a_t cfga;
        rdc_rbr_cfg_b_t cfgb;
        rdc_rcr_cfg_a_t rcr_cfga;
        rdc_rcr_cfg_b_t rcr_cfgb;

	switch (type) {
	case LDV_RXDMA:
	        HXGE_DBG(hxgep, "Rx REGISTERS :");
        	RXDMA_REG_READ64(handle, RDC_RX_CFG1, channel, &cfg_1.value);
        	HXGE_DBG(hxgep, "  DMA Configuration 1 : 0x%llx",cfg_1.value);
        	RXDMA_REG_READ64(handle, RDC_RX_CFG2, channel, &cfg_2.value);
        	HXGE_DBG(hxgep, "  DMA Configuration 2 : 0x%llx", cfg_2.value);
        	RXDMA_REG_READ64(handle, RDC_RBR_CFG_A, channel, &cfga.value);
        	HXGE_DBG(hxgep, "  RBR Configuration A : 0x%llx",cfga.value);
        	RXDMA_REG_READ64(handle, RDC_RBR_CFG_B, channel, &cfgb.value);
		HXGE_DBG(hxgep, "  RBR Configuration B : 0x%llx", cfgb.value);
		RXDMA_REG_READ64(handle, RDC_RCR_CFG_A, channel, &rcr_cfga.value);
		HXGE_DBG(hxgep, "  RCR Configuration A : 0x%llx", rcr_cfga.value);
                RXDMA_REG_READ64(handle, RDC_RCR_CFG_B, channel, &rcr_cfgb.value);
		HXGE_DBG(hxgep, "  RCR Configuration B : 0x%llx", rcr_cfgb.value);
		break;
	default:
		HXGE_ERR(hxgep, "Invalid type to print_regs : %d", type);
		break;
	}
}
	

static int hxge_map_rx_to_hw(struct hxge_adapter *hxgep, int rdc)
{
	rdc_desc_cfg_t cfg_desc;
        hpi_handle_t    handle = hxgep->hw.hw_addr;
	struct rx_ring_t *rx_ring = &hxgep->rx_ring[rdc];

	/* Setup the mailbox location */
	cfg_desc.mbox_enable = 1;
	cfg_desc.mbox_addr = rx_ring->mbox.dma_addr;

	rx_ring->full_hdr = FALSE; /* 2 bytes of header */
	rx_ring->offset = 0;   /* no SW offset */
	cfg_desc.full_hdr = rx_ring->full_hdr;
	cfg_desc.offset = rx_ring->offset;
	
	cfg_desc.rbr_addr = rx_ring->rbr.rbr_addr.dma_addr;
	cfg_desc.rbr_len = rx_ring->rbr.num_rbr_entries;
	cfg_desc.page_size = hxgep->default_block_size;
	cfg_desc.valid0 = 1;
	cfg_desc.size0 = rx_ring->rbr.pkt_buf_size_bytes[0];
	cfg_desc.valid1 = 1;
	cfg_desc.size1 = rx_ring->rbr.pkt_buf_size_bytes[1];
	cfg_desc.valid2 = 1;
	cfg_desc.size2 = rx_ring->rbr.pkt_buf_size_bytes[2];

	/* RCR stuff */
	cfg_desc.rcr_addr = rx_ring->rcr.rcr_addr.dma_addr;
	cfg_desc.rcr_len = rx_ring->rcr.num_rcr_entries;
	cfg_desc.rcr_threshold = hxgep->rcr_threshold;

        /* Set the registers */	
	if (hpi_rxdma_cfg_rdc_ring(handle, rx_ring->rdc, &cfg_desc) !=
				HPI_SUCCESS) {
		HXGE_ERR(hxgep, "Configuration of Rx failed!");
		return RX_FAILURE;
	}

	if (hpi_rxdma_cfg_clock_div_set(handle, HXGE_RCR_CLK_RESO) != 
					HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hpi_rxdma_cfg_clock_div_set failed!");
		return RX_FAILURE;
	}

	/* Needed when processing RCE buffers */
	RXDMA_REG_READ64(handle, RDC_PAGE_HANDLE, rdc, &rx_ring->page_hdl.value);
	print_regs(hxgep, LDV_RXDMA, rdc);
	return RX_NO_ERR;
}

/* Initialize the Rx channel. This is called at driver initialzation time when
   channel is created and also anytime that the channel is reset (on error 
   situations, for example) */

static int hxge_init_rx_channel(struct hxge_adapter *hxgep, int channel)
{
	struct rx_ring_t *rx_ring = &hxgep->rx_ring[channel];
	struct rx_rbr_entry_t *buf_blocks = rx_ring->rbr.buf_blocks;
	int i, alloc;

	rx_ring->first_time = 1; /* CR 6769038 */
	rx_ring->rbr.pkt_buf_size[0] = RBR_BUFSZ0_256B;
	rx_ring->rbr.pkt_buf_size_bytes[0] = RBR_BUFSZ0_256_BYTES;
        rx_ring->rbr.pkt_buf_size[1] = RBR_BUFSZ0_1K;
        rx_ring->rbr.pkt_buf_size_bytes[1] = RBR_BUFSZ1_1K_BYTES;
        rx_ring->rbr.pkt_buf_size[2] = RBR_BUFSZ2_2K;
        rx_ring->rbr.pkt_buf_size_bytes[2] = RBR_BUFSZ2_2K_BYTES;
        rx_ring->rbr.pkt_buf_size[3] = -1; /* special case; block size */
	rx_ring->rbr.pkt_buf_size_bytes[3] = hxgep->default_block_size;

	/* Initialize the RCR entries. Hardware can now use it */
	memset(rx_ring->rcr.rcr_addr.vaddr, 0, 
			rx_ring->rcr.num_rcr_entries*sizeof(rcr_entry_t));
        for (i = 0; i < rx_ring->rcr.num_rcr_entries; i++)
               rx_ring->rcr.rcr_addr.vaddr[i] = (rcr_entry_t)RCR_INIT_PATTERN;
	rx_ring->rcr.rcr_curr_loc = 0;

	/* Initialize the mailbox as well */
	memset(rx_ring->mbox.vaddr, 0, sizeof(rxdma_mailbox_t));

	/* Initialize statistics */
	memset(&rx_ring->stats, 0, sizeof(struct rx_ring_stats_t));

	/* Program the hydra registers with the information about the Rx
           channels and buffers */
	if (hxge_map_rx_to_hw(hxgep, channel))
		return RX_FAILURE;

	/* hxge_init_rx_channel can be called from hxge_work_to_do during
 	 * a channel reset, in which case we do not want to allocate
 	 * new buffers (memory leak); just reuse the existing ones
 	 */
	alloc = test_bit(HXGE_DEVICE_OPENING, &hxgep->state) ? TRUE : FALSE;
        if (setup_dma_buffers(hxgep, channel, buf_blocks,
                        rx_ring->rbr.num_rbr_entries, alloc, TRUE) < 0)
        {
                HXGE_ERR(hxgep, "setup_dma_buffers failed");
                return RX_FAILURE;
        }
	set_bit(RING_INIT, &rx_ring->state);
	return RX_NO_ERR;
}

static void hxge_scrub_rx_mem(struct hxge_adapter *hxgep)
{
	int i;
	hpi_handle_t handle = hxgep->hw.hw_addr;

        /*
         * Scrub the RDC Rx DMA Prefetch Buffer Command.
         */
        for (i = 0; i < 128; i++) {
                HXGE_REG_WR64(handle, RDC_PREF_CMD, i);
        }

        /*
         * Scrub Rx DMA Shadow Tail Command.
         */
        for (i = 0; i < 64; i++) {
                HXGE_REG_WR64(handle, RDC_SHADOW_CMD, i);
        }

        /*
         * Scrub Rx DMA Control Fifo Command.
         */
        for (i = 0; i < 512; i++) {
                HXGE_REG_WR64(handle, RDC_CTRL_FIFO_CMD, i);
        }

        /*
         * Scrub Rx DMA Data Fifo Command.
         */
        for (i = 0; i < 1536; i++) {
                HXGE_REG_WR64(handle, RDC_DATA_FIFO_CMD, i);
        }
}

static int hxge_enable_rx_channel (struct hxge_adapter *hxgep, int rdc)
{
	struct rx_ring_t *rx_ring = &hxgep->rx_ring[rdc];
        hpi_handle_t    handle = hxgep->hw.hw_addr;
	rdc_int_mask_t rdc_mask;
	hpi_status_t	status;


        /* Reset the Rx DMA channel */
        if (hpi_rxdma_cfg_rdc_reset(handle, rdc) != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hpi_rxdma_cfg_rdc_reset failed");
	}

	/* Initialize Rx data structures and some of the HW registers */
        hxge_init_rx_channel(hxgep, rdc);

	/* Enable the mbox update */
	if (hpi_rxdma_channel_mex_set(handle, rdc) != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hpi_rxdma_channel_mex_set failed");
	}

	/* Enable the RCR timeout, if needed; otherwise explicitly disable */
	hxgep->rcr_cfgb_cpy = 0;
	if (hxgep->rcr_timeout > 0) {
		status = hpi_rxdma_cfg_rdc_rcr_timeout(handle, rdc, 
					hxgep->rcr_timeout);
		hxgep->rcr_cfgb_cpy = RCR_CFGB_ENABLE_TIMEOUT | hxgep->rcr_timeout;
	}
	else
		status = hpi_rxdma_cfg_rdc_rcr_timeout_disable(handle, rdc);

	if (status != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hpi_rxdma_cfg_rdc_rcr_timeout failed");
	}
	

	/* Clear all the bits in the RDC Stat and Control */
	if (hpi_rxdma_channel_cs_clear_all(handle, rdc) != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hpi_rxdma_channel_cs_clear_all failed");
	}


	/* Clear all the event masks */
	rdc_mask.value = 0;
	hpi_rxdma_event_mask(handle, OP_SET, rdc, &rdc_mask);

	/* Unmask the appropriate LDV for this Rx channel */
	hxge_enable_rx_ints(hxgep, NULL, rdc);


	/* Enable the Rx DMA channel */
	if (hpi_rxdma_cfg_rdc_enable(handle, rdc) != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hpi_rxdma_cfg_rdc_enable failed");
	}

	set_bit(RING_ENABLED, &rx_ring->state);
	HXGE_ERR(hxgep, "Channel %d enabled", rdc);


	return RX_NO_ERR;
}

static int hxge_disable_rx_channel(struct hxge_adapter *hxgep, int rdc)
{
        hpi_handle_t    handle = hxgep->hw.hw_addr;
	struct rx_ring_t  *rx_ring = &hxgep->rx_ring[rdc];

	if (!test_and_clear_bit(RING_ENABLED, &rx_ring->state))
		return RX_NO_ERR;

	/* Disable RCR timeout */
	hxgep->rcr_cfgb_cpy = 0;
	if (hpi_rxdma_cfg_rdc_rcr_timeout_disable(handle, rdc) != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hpi_rxdma_cfg_rdc_rcr_timeout_disable failed");
	}

	/* Disable the Rx DMA channel */
	if (hpi_rxdma_cfg_rdc_disable(handle, rdc) != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hpi_rxdma_cfg_rdc_disable failed");
	}
	return RX_NO_ERR;
}


int valid_alignment(uint64_t addr, uint64_t size, int shift)
{
 	uint64_t max_addr = (1 << shift);
	uint64_t mask = max_addr - 1;

	if (((addr & mask) & (0x3 << (shift-1))) != (((addr & mask) + (size-8)) & (0x3 << (shift-1))))
		return 0;

	return 1;
}


/* This routine is called once per Rx DMA channel. It allocates the requisite
   data structures for the receive ring  and sets up the hardware registers
   to point to them. For example, the RBR, RCR and mailbox structures */

static int hxge_alloc_rx_channel (struct hxge_adapter *hxgep, uint16_t rdc)
{
	struct rx_ring_t *rx_ring = &hxgep->rx_ring[rdc];
	int rbr_entries, rcr_entries;
	int i;
	unsigned int size;
	struct rx_rbr_entry_t *buf_blocks, *buf_block;

	if (hxge_get_option("rbr_entries",&rbr_entries)) {
		HXGE_ERR(hxgep, "rbr_entries invalid");
		return RX_FAILURE;
	}

	if(hxge_get_option("rcr_entries", &rcr_entries)) {
		HXGE_ERR(hxgep, "rcr_entries invalid");
		return RX_FAILURE;
	}

	rx_ring->rdc = rdc;
 	rx_ring->rbr.num_rbr_entries = rbr_entries;	
	rx_ring->rcr.num_rcr_entries = rcr_entries;

	/* Allocate metadata to keep track of buffer blocks */
	size = (rbr_entries*sizeof(struct rx_rbr_entry_t));
	rx_ring->rbr.buf_blocks_order = get_order(size);
	buf_blocks = rx_ring->rbr.buf_blocks = 
			(struct rx_rbr_entry_t *)__get_free_pages(GFP_KERNEL,
				rx_ring->rbr.buf_blocks_order);

	if (!buf_blocks) {
		HXGE_ERR(hxgep, "Failed to get buf blocks, %lu bytes", rbr_entries*sizeof(struct rx_rbr_entry_t));
		return RX_FAILURE;
	}
	for (i = 0, buf_block=&buf_blocks[0]; i < rbr_entries; 
						i++, buf_block++) {
		memset(buf_block, 0, sizeof(struct rx_rbr_entry_t));	
		buf_block->index = i;
	}

        rx_ring->rbr.pkt_buf_size[0] = RBR_BUFSZ0_256B;
        rx_ring->rbr.pkt_buf_size_bytes[0] = RBR_BUFSZ0_256_BYTES;
        rx_ring->rbr.pkt_buf_size[1] = RBR_BUFSZ0_1K;
        rx_ring->rbr.pkt_buf_size_bytes[1] = RBR_BUFSZ1_1K_BYTES;
        rx_ring->rbr.pkt_buf_size[2] = RBR_BUFSZ2_2K;
        rx_ring->rbr.pkt_buf_size_bytes[2] = RBR_BUFSZ2_2K_BYTES;
        rx_ring->rbr.pkt_buf_size[3] = -1; /* special case; block size */
        rx_ring->rbr.pkt_buf_size_bytes[3] = hxgep->default_block_size;

	/* The PRM mandates a formula to compute the RCRs based on the 
 	 * smallest possible buffer size. This guarantees the we will
 	 * see a rbr empty and not an rcr full (see CR 6779304 why this is 
 	 * important).
 	 */
	do {
		int compute_rcrs;
		compute_rcrs = rbr_entries * 
		(hxgep->default_block_size/rx_ring->rbr.pkt_buf_size_bytes[0]);
		if (compute_rcrs > rx_ring->rcr.num_rcr_entries) {
			HXGE_ERR(hxgep, "%d rcr entries not sufficient for driver to function. You need at least %d rcr entries.",rcr_entries, compute_rcrs);
			return RX_FAILURE;
		}
		else
			rx_ring->rcr.num_rcr_entries = compute_rcrs;
	} while (0);
	HXGE_DBG(hxgep, "RBR = %d, RCR = %d",rbr_entries, rx_ring->rcr.num_rcr_entries);
		
	/* Allocate the RBR descriptor ring. We allocate a power of two
         * larger than we really need to assure that we meet the alignment
         * restriction of the PRM. We do the same thing for the RCR further
         * down
         */
	rx_ring->rbr.rbr_addr.vaddr = pci_alloc_consistent( hxgep->pdev, 
		rx_ring->rbr.num_rbr_entries*sizeof(rbr_desc_entry_t),
		&rx_ring->rbr.rbr_addr.dma_addr);
	if (!rx_ring->rbr.rbr_addr.vaddr) {
		HXGE_ERR(hxgep, "Could not get DMA for RBR, channel %d",rdc);
	}

	/* Now validate the alignment */
	if (!valid_alignment(rx_ring->rbr.rbr_addr.dma_addr,
			   rbr_entries*sizeof(rbr_desc_entry_t), 18)) {
	HXGE_ERR(hxgep, "RBR Desc @ 0x%lx not aligned properly, channel %d",
			(long unsigned int)rx_ring->rbr.rbr_addr.dma_addr, rdc);
		return RX_FAILURE;
	}

	rx_ring->rcr.rcr_addr.vaddr = pci_alloc_consistent(hxgep->pdev, 
			rx_ring->rcr.num_rcr_entries*sizeof(rcr_entry_t),
			&rx_ring->rcr.rcr_addr.dma_addr);
	if (!rx_ring->rcr.rcr_addr.vaddr) {
		HXGE_ERR(hxgep, "Could not get DMA for RCR, channel %d",rdc);
		return RX_FAILURE;
	}

	if (!valid_alignment(rx_ring->rcr.rcr_addr.dma_addr,
			rx_ring->rcr.num_rcr_entries*sizeof(rcr_entry_t), 19)) {
	HXGE_ERR(hxgep, "RCR Desc @ 0x%lx not aligned properly, channel %d",
			(long unsigned int)rx_ring->rcr.rcr_addr.dma_addr, rdc);
		return RX_FAILURE;
	}
	memset(rx_ring->rcr.rcr_addr.vaddr, 0, 
			rx_ring->rcr.num_rcr_entries*sizeof(rcr_entry_t));

	HXGE_DBG(hxgep, "Allocated RBR at 0x%p (0x%llx) of size %d",rx_ring->rbr.rbr_addr.vaddr, rx_ring->rbr.rbr_addr.dma_addr, (int)(rbr_entries*sizeof(rbr_desc_entry_t)));
	HXGE_DBG(hxgep, "Allocated RCR at 0x%p (0x%llx) of size %d",rx_ring->rcr.rcr_addr.vaddr, rx_ring->rcr.rcr_addr.dma_addr, (int)(rx_ring->rcr.num_rcr_entries*sizeof(rcr_entry_t)));
	
	rx_ring->mbox.vaddr = pci_alloc_consistent(hxgep->pdev,
				 sizeof(rxdma_mailbox_t), 
				 &rx_ring->mbox.dma_addr);
	if (!rx_ring->mbox.vaddr) {
		HXGE_ERR(hxgep, "Could not get DMA for mailbox, channel %d",rdc);
	}

	return RX_NO_ERR;
}


int hxge_alloc_rx(struct hxge_adapter *hxgep)
{
	int i;
	int stripcrc = 0;

	if (hxge_get_option("strip_crc", &stripcrc)) {
		HXGE_ERR(hxgep, "Cannot get strip_crc value");
		return RX_FAILURE;
	}
	if (stripcrc)
		strip_crc_bytes = 0;
	else
		strip_crc_bytes = 4;

	hxgep->rx_ring = kzalloc(sizeof(struct rx_ring_t)*hxgep->max_rdcs,
					GFP_KERNEL);
	if (!hxgep->rx_ring) {
		HXGE_ERR(hxgep, "Could not alloc rx_ring");
		return RX_FAILURE;
	}

	for (i = 0; i < hxgep->max_rdcs; i++) {
		if (hxge_alloc_rx_channel(hxgep, i)) {
			HXGE_ERR(hxgep, "Could not alloc rx for channel");
			hxge_free_rx(hxgep);
			return RX_FAILURE;
		}
	}

	return RX_NO_ERR;
}

int hxge_enable_rx(struct hxge_adapter *hxgep)
{
	hpi_handle_t  handle = hxgep->hw.hw_addr;
	rdc_fifo_err_mask_t  fifo_mask;
	unsigned long long   reg64 = 0xfeedfacedeadbeefULL;
	int i;

	/* Scrub/initialize RDC memory */
	hxge_scrub_rx_mem(hxgep);

	/* Reset the FIFO Error Status */
	HXGE_REG_RD64(handle, RDC_FIFO_ERR_STAT, &reg64);
	if (reg64) {
		/* While an interesting case (error flags should probably
		 * not be set), do not count against hxgep->hard_errors */
		HXGE_ERR(hxgep, "RDC_FIFO_ERR_STAT 0x%16.16x hardware error flags set",
			 (unsigned int)reg64);
	}
        HXGE_REG_WR64(handle, RDC_FIFO_ERR_STAT, reg64); /* RW1C err bits */

	/* Set the error mask to receive interrupts */
	fifo_mask.value = 0;
	if (hpi_rx_fifo_mask(handle, OP_SET, &fifo_mask) != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hpi_rx_fifo_mask failed");
	}

	/* Enable all appropriate RX DMA channels */

	for (i = 0; i < hxgep->max_rdcs; i++) {
		if (hxge_enable_rx_channel(hxgep, i)) {
			HXGE_ERR(hxgep, "Could not enable Rx chan %i",i);
			return RX_FAILURE;
		}
	}

	hxge_enable_rx_ints(hxgep, NULL, -1);

	return RX_NO_ERR;
}

int hxge_disable_rx(struct hxge_adapter *hxgep)
{
	int i;

	/* Disable Rx interrupts */
	hxge_disable_rx_ints(hxgep,NULL, -1);

	/* Disable all channels. Print warning message but don't exit until
	   attempting to disable all of them */
	for (i = 0; i < hxgep->max_rdcs; i++) {
		if (hxge_disable_rx_channel(hxgep, i)) {
			HXGE_ERR(hxgep, "Could not disable Rx chan %i",i);
			return RX_FAILURE;
		}
	}
	return RX_NO_ERR;
}



/* Reset entire Rx ("RDC") subsystem */
int hxge_reset_rdc(struct hxge_adapter *hxgep)
{
	/* Shutdown all receive traffic first */

	hxge_disable_rx(hxgep);

	/* Generate rdc_core logic reset */

	hxge_block_reset(hxgep, LDV_RXDMA);

	/* Bring up all the receive channels now */

	hxge_enable_rx(hxgep);

	return RX_NO_ERR;
}


/* This routines takes a DMA pkt_addr provided in an RCR descriptor entry and
   finds out the buffer block (CPU addr) in the RBR that matches it */
static struct rx_rbr_entry_t *get_buf_block(struct rx_ring_t *rx_ring, 
				rcr_entry_t *rcr_entry, uint32_t blk_size,					uint64_t *offset, int first_rcr)
{
	rx_rbr_ring_t *rbr_ring = &rx_ring->rbr;
	int index;
	struct rx_rbr_entry_t *buf_block;
	uint64_t pkt_addr;
	int pktsz;

	/* Get 64-bit packet address */
	pkt_addr = rcr_entry->bits.pkt_buf_addr << RCR_PKT_BUF_ADDR_SHIFT_FULL;
	pkt_addr |= ((rx_ring->page_hdl.value & 0xfffff) 
					<< HXGE_MAX_ADDRESS_BITS);

	*offset = pkt_addr & (blk_size - 1);
	pktsz = ((first_rcr == 0) ?  blk_size : 
                  rbr_ring->pkt_buf_size_bytes[rcr_entry->bits.pktbufsz]);


	/* Hit CR 6698258. The workaround is to ignore this entry and call it
 	 * a success. The entry will be populated on the next interrupt */
	if ((rcr_entry->value == 0x0) || (rcr_entry->value == RCR_INIT_PATTERN)
              || ((index = get_index_from_hash(rbr_ring, pkt_addr)) < 0))
	{
		HXGE_ERR_PRINT("bad hash entry for pkt address 0x%llx",(unsigned long long)pkt_addr);
		goto fail;
	}
		
	buf_block = &rbr_ring->buf_blocks[index];
	buf_block->pkt_size = pktsz;
	return buf_block;

fail:
	HXGE_ERR_PRINT("rcr_entry 0x%p: 0x%lx, pkt_addr: 0x%lx",rcr_entry, (unsigned long)rcr_entry->value,(unsigned long)rcr_entry->bits.pkt_buf_addr);

	HXGE_ERR_PRINT("   multi=%d",rcr_entry->bits.multi);
	HXGE_ERR_PRINT("   pkt_type=%d",rcr_entry->bits.pkt_type);
	HXGE_ERR_PRINT("   error=%d",rcr_entry->bits.error);
	HXGE_ERR_PRINT("   l2_len=%d",rcr_entry->bits.l2_len);
	HXGE_ERR_PRINT("   pktbufsz=%d",rcr_entry->bits.pktbufsz);
	HXGE_ERR_PRINT("   pkt_addr=0x%lux",(unsigned long)rcr_entry->bits.pkt_buf_addr);
	return NULL;
}

static void update_buf_block(struct rx_rbr_entry_t *buf_block, 
				uint32_t blk_size)
{
	if (!buf_block->in_use) /* not in use; virgin block */ {
		buf_block->in_use = 1;
		buf_block->max_pkts = blk_size / buf_block->pkt_size;
	} else  /* already in use */
		buf_block->in_use++;

	/* Check if the buffer block is full. If so, mark it as "can be 
           freed" once the packet is copied out of it */	
	if (buf_block->in_use == buf_block->max_pkts)
		buf_block->in_use = -1;
#ifdef DBG
	HXGE_DBG_PRINT("BUF_BLOCK [%d] => %p",index,buf_block);
	HXGE_DBG_PRINT("	in_use = %d", buf_block->in_use);
	HXGE_DBG_PRINT("	pkt_size = %d", buf_block->pkt_size);
	HXGE_DBG_PRINT("	max_pkts = %d", buf_block->max_pkts);
	HXGE_DBG_PRINT("PKT_ADDR : 0x%lx, offset=0x%lx",(unsigned long)pkt_addr,(unsigned long)*offset);
#endif

}

#ifdef CONFIG_SKB_SHARED
static void unmap_dma_buffer(struct hxge_adapter *hxgep,  int channel,
				struct rx_rbr_entry_t *buf_block)
{
	struct rx_ring_t *rx_ring = &hxgep->rx_ring[channel];
	remove_hash_entry(&rx_ring->rbr, buf_block->addr.dma_addr);
	free_dma_buffer(hxgep, buf_block, FALSE);
}

/* This routine is called for jumbo packets where a packet spans more than one
 * buffer block. The routine sets up skb fragments to avoid having to do 
 * expensive copies of large buffers. */

static int setup_skb_frag(struct sk_buff *skb, struct hxge_adapter *hxgep,
	int channel, struct rx_rbr_entry_t *buf_block, uint32_t offset, 
	uint32_t len)
{
	int free = skb_shinfo(skb)->nr_frags;
	skb_frag_t *fragp;

	if (free >= MAX_SKB_FRAGS) {
		HXGE_ERR(hxgep, "Too many skb fragments attempted!");
		return RX_FAILURE;
	}
		
	/* setup the old page to a skb fragment */
	fragp = &skb_shinfo(skb)->frags[free];
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 13)
	fragp->page = buf_block->page;
#else
	fragp->page.p = buf_block->page;
#endif

	fragp->page_offset = offset;
	fragp->size = len;

	/* Unmap the DMA view from the old page (do not free it!), allocate 
	   a new page and have the buf block meta data point to it */

	unmap_dma_buffer(hxgep, channel, buf_block); /* unmap and remove hash */
	if (setup_dma_buffers(hxgep, channel, buf_block, 1, TRUE, FALSE) < 0) {
		HXGE_ERR(hxgep, "setup_dma_buffer failed");
		buf_block->in_use = 0; /* can be re-used again */
		return RX_DROP_PKT;
	}

	/* No errors. So, we can now account for this entry */
	skb_shinfo(skb)->nr_frags++;
	return RX_NO_ERR;
	
}
#endif


static inline void process_pkt_hdr (pkt_hdr_twobyte_t *pkt_hdr) 
{
	HXGE_DBG_PRINT("PKT_HDR =>");
        HXGE_DBG_PRINT("  drop_code = %d",pkt_hdr->bits.drop_code);
        HXGE_DBG_PRINT("  tcamhit = %d",pkt_hdr->bits.tcamhit);
        HXGE_DBG_PRINT("  badip = %d",pkt_hdr->bits.badip);
        HXGE_DBG_PRINT("  noport = %d",pkt_hdr->bits.noport);
        HXGE_DBG_PRINT("  bcast_frame = %d",pkt_hdr->bits.bcast_frame);
        HXGE_DBG_PRINT("  vlan = %d",pkt_hdr->bits.vlan);
        HXGE_DBG_PRINT("  class= %d",pkt_hdr->bits.class);
        HXGE_DBG_PRINT("  maccheck= %d",pkt_hdr->bits.maccheck);
        HXGE_DBG_PRINT("  l4_cs_eq= %d",pkt_hdr->bits.l4_cs_eq);
}

/* This routine processes the first RCR entry for a packet. This could be the
 * only packet (packet size <= block size) or could be the first entry in a 
 * multi entry RCR packet (jumbo frames). In either case, it sets up the skb
 * buffer and initializes it appropriately based on packet size 
 */
struct sk_buff *process_first_rcr_entry(struct hxge_adapter *hxgep, 
		struct rx_ring_t *rx_ring, int *bytes_remaining)
{
	rcr_entry_t *rcr_entry;
	rx_rcr_ring_t *rcr_ring = &rx_ring->rcr;
	struct rx_rbr_entry_t *buf_block;
	struct sk_buff *skb;
	uint32_t l2_len, hdr_len, len, data_size;
	unsigned char *cpu_addr;
	pkt_hdr_twobyte_t *pkt_hdr;
	uint64_t offset;
	uint32_t data_offset;

	*bytes_remaining = RX_NO_ERR;
	rcr_entry = GET_RCR_ENTRY(rcr_ring);

	HXGE_DBG(hxgep, "rcr_ring loc : 0x%p", rcr_ring->rcr_addr.vaddr);
        HXGE_DBG(hxgep, "rcr_curr_loc : %d",rcr_ring->rcr_curr_loc); 
        HXGE_DBG(hxgep, "rcr entry: 0x%lux",(unsigned long)rcr_ring->rcr_addr.vaddr[rcr_ring->rcr_curr_loc].value);
	/* Get index into buf_blocks meta data so that we can get to the
           CPU address from the DMA address, among other things */
	if (!(buf_block = get_buf_block(rx_ring, rcr_entry, hxgep->default_block_size, &offset, 1))) {
		HXGE_ERR(hxgep, "Bad pkt_addr");
        	HXGE_ERR(hxgep, "rcr_curr_loc : %d",rcr_ring->rcr_curr_loc); 
		return NULL;
	}

	update_buf_block(buf_block, hxgep->default_block_size);
	cpu_addr = (char *)buf_block->addr.vaddr + offset;
	pkt_hdr = (pkt_hdr_twobyte_t *)cpu_addr;

#if 0
	process_pkt_hdr(pkt_hdr);
#endif

	/* Get to the actual data part of the packet received */
	data_offset  = rx_ring->offset + (rx_ring->full_hdr ? 6 : 2);
	data_size = buf_block->pkt_size - data_offset;
	cpu_addr += data_offset;
	hdr_len = ETH_HLEN;

	len = l2_len = rcr_entry->bits.l2_len;
	*bytes_remaining = l2_len;

	rx_ring->stats.ipackets++;
	rx_ring->stats.ibytes += l2_len;
	if (l2_len > ETH_FRAME_LEN)
		rx_ring->stats.jumbo_pkts++;

	/* Create pkt_hdr structure and check for vlan */
	if (pkt_hdr->bits.vlan)
		hdr_len += 4;

	/* TODO: There is the case where we could get small packets with 
		 taking up an entire buffer block mostly wasted. This happens
		 if we the packet size options programmed into the config
                 registers are limited. For example, if only a packet size of
                 256B is set, then anything >256B will take up an entire 
	         4KB block! Need to copy out the small packet in this case */

#ifdef CONFIG_SKB_SHARED
	if (rcr_entry->bits.multi) 
		len = hdr_len;
#endif
	skb = ALLOC_SKB(
#ifdef CONFIG_ERRINJECT
			hxgep, 
#endif
			len + NET_IP_ALIGN);
	if (!skb) {
		HXGE_ERR(hxgep, "Could not allocate skb!");
		*bytes_remaining = RX_DROP_PKT;
		return NULL;
	}

	skb_reserve(skb, NET_IP_ALIGN);
	skb->dev = hxgep->netdev;

	/* Let Linux know the status of IP checksumming. If we have HW (IP) 
         * chksum available, then it's already done.  Otherwise, we let Linux 
         * know that no checksum has been done.
         */

	if ((hxgep->flags & HXGE_RX_CHKSUM_ENABLED) && 
	     !pkt_hdr->bits.noport && !rcr_entry->bits.error &&
	     ((rcr_entry->bits.pkt_type == RCR_PKT_TCP) ||
	     (rcr_entry->bits.pkt_type == RCR_PKT_UDP)) &&
	     pkt_hdr->bits.l4_cs_eq)
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	else {
		if (((rcr_entry->bits.pkt_type == RCR_PKT_TCP) || 
		    (rcr_entry->bits.pkt_type == RCR_PKT_UDP)) && 
			(!pkt_hdr->bits.l4_cs_eq) && (!pkt_hdr->bits.noport))
			HXGE_DBG(hxgep, "Checksum failed");
		skb->ip_summed = CHECKSUM_NONE;
	}

#ifndef CONFIG_SKB_SHARED
	if (rcr_entry->bits.multi)
		len = data_size;
#endif

	memcpy(skb_put(skb, len), cpu_addr, len); 
#ifdef CONFIG_SKB_SHARED
	if (rcr_entry->bits.multi) /* Copy packet data into fragment */ {
		int retval; 
		skb->len += (l2_len - len);
		skb->data_len = l2_len - len;
		skb->truesize += (l2_len - len);
		skb_shinfo(skb)->nr_frags = 0;
		retval = setup_skb_frag(skb, hxgep, rx_ring->rdc, buf_block, 
		        data_offset + len, data_size-len);
		if (retval < 0) 
			*bytes_remaining = retval;
		else 
			*bytes_remaining -= data_size;
	} else 
#endif
	{ /* in single packet case, check if buf block can be freed */ 
		if ((buf_block->in_use < 0) && (setup_dma_buffers(hxgep, 
			rx_ring->rdc, buf_block, 1, FALSE, FALSE) < 0))
			*bytes_remaining = RX_FAILURE;
		else
			*bytes_remaining -= len;
	}
	
	/* Increment to next location in the RCR descriptor table */	
	INCREMENT_RCR_ENTRY_TO_NEXT(rcr_ring);
	return skb;
}


/* This routine is called only for packets that span multiple buffer blocks 
 * and is not called for single packet cases. It processes the multiple RCR
 * entries for large packets and sets up the skb fragments for each buffer 
 * block (parts of the packet data)
 */
static int process_rcr_entries(struct hxge_adapter *hxgep, 
	struct rx_ring_t *rx_ring, struct sk_buff *skb, int bytes_remaining)
{
	struct rx_rbr_entry_t *buf_block;
	rx_rcr_ring_t *rcr_ring = &rx_ring->rcr;
	rcr_entry_t *rcr_entry;	
	int len;
	uint64_t offset;
	int retval = RX_NO_ERR;

	rcr_entry = GET_RCR_ENTRY(rcr_ring);	

	/* Get index into buf_blocks meta data so that we can get to the
           CPU address from the DMA address, among other things */
	if (!(buf_block = get_buf_block(rx_ring, rcr_entry, 
			hxgep->default_block_size, &offset, 0))) 
	{
                HXGE_ERR(hxgep, "Bad pkt_addr");
                HXGE_ERR(hxgep, "rcr_curr_loc : %d",rcr_ring->rcr_curr_loc);
		return RX_FAILURE;
	}

	update_buf_block(buf_block, hxgep->default_block_size);
	len = min(buf_block->pkt_size, (uint32_t)bytes_remaining);
#ifdef CONFIG_SKB_SHARED
	if ((retval = setup_skb_frag(skb, hxgep, rx_ring->rdc, 
			buf_block, 0, len)) < 0) {
		HXGE_ERR(hxgep, "could not get skb fragment");
		return retval;
	}
#else
	memcpy(skb_put(skb, len), (char *)buf_block->addr.vaddr + offset, len);
	if (buf_block->in_use < 0)
		if ((retval = setup_dma_buffers(hxgep, rx_ring->rdc, 
				buf_block, 1,
                                        FALSE, FALSE)) < 0) {
                HXGE_ERR(hxgep,"setup_dma_buffers failed");
                return retval;
        }

#endif
	
	INCREMENT_RCR_ENTRY_TO_NEXT(rcr_ring);
	return (bytes_remaining - len);
}

static void free_skb(struct sk_buff *skb)
{
	if (!skb)
		return;

	dev_kfree_skb_any(skb);
}


/* This routine is called by the packet processing routine in the event of
 * a failure that is related (currently) to memory allocation failure. In that
 * case, we opt to drop the packet rather than declare this a catastrophic
 * failure i.e. requiring a reset of the channel, which will flush out valid
 * packets that are awaiting processing. Instead, we just drop the current
 * packet and move ahead with processing as usual.
 *
 * NOTE: The implicit assumption in this routine is that update_buf_block has
 * already been called for the first rcr_entry that we are processing, always.
 */

int drop_packet(struct hxge_adapter *hxgep, struct rx_ring_t *rx_ring,
				struct sk_buff *skb)
{
	rx_rcr_ring_t *rcr_ring = &rx_ring->rcr;
	int rcr_processed = 0;

 	rx_ring->stats.nomem_drop++;
	if (skb) 
		free_skb(skb);
	
	/* Go through and reassign the buffer to the hardware */
	do {
		uint64_t ignore;
		struct rx_rbr_entry_t *buf_block;
		rcr_entry_t *rcr = GET_RCR_ENTRY(rcr_ring);
	
		buf_block = get_buf_block(rx_ring, rcr, 
				hxgep->default_block_size, &ignore, 1);
		if (!buf_block) {

			/* we've already cleaned up the first multi entry
			 * in setup_skb_frag by clearing the in_use bit for 
			 * re-use. So, just skip and go to the next one
			 */
			if  (!rcr_processed && rcr->bits.multi)
				continue;
			
			/* Something wrong; the buf_block should be in the 
			 * hash list for non-multi case
			 */
			HXGE_ERR(hxgep, "get_buf_block failed");
			return RX_FAILURE;
		}

		/* Use rcr_processed as "first time through this loop" 
		 * in_use count. Please see "NOTE" above
		 */
		if (rcr_processed)
			update_buf_block(buf_block, hxgep->default_block_size);

		BUG_ON(buf_block->in_use < -1);
	 	if (buf_block->in_use < 0)
			setup_dma_buffers(hxgep, rx_ring->rdc, buf_block, 
				1, FALSE, FALSE);
		rcr_processed++;
		INCREMENT_RCR_ENTRY_TO_NEXT(rcr_ring);
		if (!rcr->bits.multi)
			break;
	} while (TRUE);
	

	//HXGE_ERR(hxgep, "Dropped %d packets",rcr_processed);
	return rcr_processed;
}

/* Process one packet. This could be either a single or a multiple RCR entry
   case. 
   ASSUMPTION: The code assumes that a multi-buffer scenario implies that all 
   except the last is a full buffer block. While it does not need to be, it 
   makes coding simpler */

static int hxge_process_one_pkt (struct hxge_adapter *hxgep,
		struct rx_ring_t *rx_ring, struct sk_buff **skb_list)
{
	struct sk_buff *skb = NULL;
	int bytes_remaining;
	int rcr_entries_read = 0;
		
	/* This routine processes the first entry of the RCR for this packet,
	   including allocating a skbuff and copying the header */
	skb = process_first_rcr_entry(hxgep, rx_ring, &bytes_remaining);
	if (!skb || (bytes_remaining < 0))
		goto failed;
		
	rcr_entries_read++;

	/* This can only be true for multi-packet cases. For single packet,
	   everything processed in first rcr entry */
	while (bytes_remaining > 0) {
		bytes_remaining = process_rcr_entries(hxgep, rx_ring, skb, 
							bytes_remaining);
		if (bytes_remaining < 0)
			goto failed;
		rcr_entries_read++;
	}

        /* Remove the ethernet crc from the packet before passing to the 
 	   network stack */
	pskb_trim(skb, skb->len - strip_crc_bytes);

	if (!test_bit(HXGE_DEVICE_TESTING, &hxgep->state))
		skb->protocol = eth_type_trans(skb, hxgep->netdev);

	/* If we are running diagnostic tests, then don't pass the skb to 
	   the OS. Instead, the diag test routine will manage the skb's 
	   itself */
	if (unlikely(test_bit(HXGE_DEVICE_TESTING, &hxgep->state))) {
		if (*skb_list == NULL) {
			*skb_list = skb;
			skb->next = NULL;
		}
		else {
			skb->next = (*skb_list)->next;
			(*skb_list)->next = skb;
		}
		
	} else {
	
	/* Pass skb up the linux network stack for processing */
#ifdef CONFIG_HXGE_NAPI
		netif_receive_skb(skb);
#else
		netif_rx(skb);
#endif
		hxgep->netdev->last_rx = jiffies;
	}

	return rcr_entries_read;

failed:
	if (bytes_remaining == RX_DROP_PKT) {
		int rcrs = drop_packet(hxgep, rx_ring, skb);
		if (rcrs < 0)
			return RX_FAILURE;
		else
			return (rcrs + rcr_entries_read);
	}
	HXGE_ERR(hxgep, "Bad pkt_addr on channel %d, bytes_remaining: %d",rx_ring->rdc, bytes_remaining);
	return RX_FAILURE;
}


/* Workaroud for CR 6698258. Scan through the rcr entries that the HW
   has fully populated. The assumption in the code is that there is 
   a complete set of packets in this list. If not, the processing
   code will catch it manifested in various ways. The routine 
   converts RCR entries into number of packets, which is then used
   as a limit on the packets to process.
*/
uint32_t scan_for_last_eop(struct rx_ring_t *rx_ring, int num_rcrs)
{
	rx_rcr_ring_t *rcr_ring = &rx_ring->rcr;
	rcr_entry_t *rcr_entry = GET_RCR_ENTRY(rcr_ring);
	uint32_t loc = rcr_ring->rcr_curr_loc;
	int rcrs = 0;
	uint32_t pkts = 0;

	while ((rcrs < num_rcrs) && (rcr_entry->value != 0) && 
		(rcr_entry->value != RCR_INIT_PATTERN)) 
	{
		if (!rcr_entry->bits.multi) 
			pkts++;
		loc = (loc + 1) % rcr_ring->num_rcr_entries;
		rcr_entry = &rcr_ring->rcr_addr.vaddr[loc];
		rcrs++;
	}
	return pkts;
}



/* This routine processes the Rx channels. For each network device, all
   the Rx channels are processed for packets even though each individual 
   channel has its own interrupt handler called (NAPI case only). This is 
   because the higher network layers are unaware of channels and only work 
   with a network device. For non-NAPI case, channel processing happens in
   parallel */
#ifdef CONFIG_HXGE_NAPI
int hxge_process_packets(struct hxge_adapter *hxgep, int work_to_do,
		struct hxge_ldv *ldvp, struct sk_buff **skb_list)
#else
int hxge_process_packets(struct hxge_adapter *hxgep, struct hxge_ldv *ldvp, 
		struct sk_buff **skb_list)
#endif
{
	int channel = ldvp->ldv-HXGE_RDMA_LD_START;
	struct rx_ring_t *rx_ring = &hxgep->rx_ring[channel];
	uint32_t max_pkts, scan_pkts;
	int pkts_processed = 0, rcr_entries_read=0, rcr_entries_processed=0;
	rdc_stat_t *cs = (rdc_stat_t *)&ldvp->data;
#ifdef USE_MBOX
	rxdma_mailbox_t *mboxp;
	uint32_t mbox_rcrtail;
#endif
	uint32_t num_entries;
        hpi_handle_t    handle = hxgep->hw.hw_addr;
#ifdef USE_PIO
	uint32_t rcr_tail, rcrtail_index;
#endif

	if (channel != rx_ring->rdc) { /* should match */ 
		HXGE_ERR(hxgep, "channels do not match!");
		return RX_FAILURE;
	}
	
	/* not enabled; don't return error since no harm done */
	if (!test_bit(RING_ENABLED, &rx_ring->state)) {
		HXGE_ERR(hxgep, "Channel %d not enabled",channel);
		return RX_NO_ERR;
	} 


	/* Determine the max number of packets that can be processed */
	max_pkts = hxgep->max_rx_pkts;
#ifdef CONFIG_HXGE_NAPI
	max_pkts = min((uint32_t)work_to_do, max_pkts);
#endif
#ifdef USE_PIO
	if (hpi_rxdma_rdc_rcr_tail_get(handle, channel, &rcr_tail) 
				!= HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hpi_rxdma_rdc_rcr_tail_get failed");
	}
	
	rcrtail_index = rcr_tail  - (uint32_t)(((uint64_t)rx_ring->rcr.rcr_addr.dma_addr & 0x7ffffULL) >> 3);

	if (rcrtail_index >= rx_ring->rcr.rcr_curr_loc)
		num_entries = rcrtail_index - rx_ring->rcr.rcr_curr_loc;
	else
		num_entries = rx_ring->rcr.num_rcr_entries - 
				(rx_ring->rcr.rcr_curr_loc - rcrtail_index);
#endif

#ifdef USE_MBOX

	mboxp = (rxdma_mailbox_t *)rx_ring->mbox.vaddr;
	mbox_rcrtail = mboxp->rcr_tail.bits.tail;
	mbox_rcrtail = mbox_rcrtail - (uint32_t)(((uint64_t)rx_ring->rcr.rcr_addr.dma_addr & 0x7ffffULL) >> 3);
	if (mbox_rcrtail >= rx_ring->rcr.rcr_curr_loc)
		num_entries = mbox_rcrtail - rx_ring->rcr.rcr_curr_loc;
	else
		num_entries = rx_ring->rcr.num_rcr_entries - 
			(rx_ring->rcr.rcr_curr_loc - mbox_rcrtail);

	if  (rx_ring->rbr.rbr_empty_flag) {
		uint16_t qlen;
		if (hpi_rxdma_rdc_rcr_qlen_get(handle, channel, &qlen) 
				!= HPI_SUCCESS) {
			HXGE_ERR(hxgep, "qlen read failed for channel %i",channel);
			return RX_FAILURE;
		}
		HXGE_DBG(hxgep, "channel %d , qlen = %d",channel,qlen);
		num_entries  = qlen;
	}
#endif

	max_pkts = min(max_pkts, num_entries);
	scan_pkts = scan_for_last_eop(rx_ring, num_entries);
	max_pkts = min(max_pkts, scan_pkts);

	if (!max_pkts) 
		return RX_NO_ERR;

	do {
		rcr_entries_read = hxge_process_one_pkt(hxgep, rx_ring, skb_list);	
		HXGE_DBG(hxgep, "%d rcr entries read",rcr_entries_read);
		if (rcr_entries_read < 0) 
			break;

		rcr_entries_processed += rcr_entries_read;
		HXGE_DBG(hxgep, "%d rcr entries processed",rcr_entries_processed);
	} while ((rcr_entries_read > 0) && (++pkts_processed < max_pkts));
	
	HXGE_DBG(hxgep, "%d pkts processed",pkts_processed);

	if (rcr_entries_read <= 0) {
		HXGE_ERR(hxgep, "Channel %d =>  ",channel);
#ifdef USE_MBOX
		HXGE_ERR(hxgep, "	MBOX Info");
		HXGE_ERR(hxgep, "		RCR Tail(index) = %d",mbox_rcrtail);
		HXGE_ERR(hxgep, "		RCR Qlen = %d",mboxp->rcr_qlen.bits.qlen);
		parse_rdc_stat("MBOX RDC ", mboxp->rxdma_ctl_stat);
#endif
		parse_rdc_stat("PIO  RDC ", (rdc_stat_t)ldvp->data);
		HXGE_ERR(hxgep, "	SW  RCR Head 	            = %d",rx_ring->rcr.rcr_curr_loc);
		HXGE_ERR(hxgep, "	Num RCR Entries             = %d",num_entries);
		HXGE_ERR(hxgep, "	Packets found scan_eop      = %d",scan_pkts);
		HXGE_ERR(hxgep, "	RCR Entries Processed       = %d",rcr_entries_processed);
		HXGE_ERR(hxgep, "	Num Packets Processed       = %d",pkts_processed);
		HXGE_ERR(hxgep, "	RCR Entries Read (curr pkt) = %d",rcr_entries_read);
		return RX_FAILURE;
	}

	if (hxgep->adaptive_rx)
		RXDMA_REG_WRITE64(handle, RDC_RCR_CFG_B, channel, max_pkts << 16 | hxgep->rcr_cfgb_cpy);

	/* CR 6769038 Workaround */

	if (rx_ring->first_time && pkts_processed) {
		pkts_processed--;
		rx_ring->first_time--;
	}


	
	/* Update the RDC Status/Control with packets and rcr entries read */
	cs->bits.ptrread = rcr_entries_processed;
	cs->bits.pktread = pkts_processed;
	return pkts_processed;
}

void hxge_reset_rx_channel(struct hxge_adapter *hxgep, int rdc)
{
	struct rx_ring_t *rx_ring = &hxgep->rx_ring[rdc];

	HXGE_ERR(hxgep, "Entering routine");
	if (test_and_set_bit(RING_RESET, &rx_ring->state))
		return;

	spin_lock(&hxgep->lock);
	hxge_disable_rx_channel(hxgep, rdc);
	hxge_enable_rx_channel(hxgep, rdc);
	spin_unlock(&hxgep->lock);

	clear_bit(RING_RESET, &rx_ring->state);
	HXGE_ERR(hxgep, "Exiting routine");
}

/* Called to update the cumulative Rx stats structure. This is later used 
   to fill in the net_device_stats structure for higher level client such as
   ifconfig */
static void update_rx_err_stats(hpi_handle_t handle, struct rx_ring_t *rx_ring)
{
	struct rx_ring_stats_t *stats = &rx_ring->stats;
        rdc_drop_count_t drop_cnt;

        RXDMA_REG_READ64(handle, RDC_DROP_COUNT, rx_ring->rdc, &drop_cnt.value);

	stats->pkt_too_long += drop_cnt.bits.too_long;
	stats->no_rbr_avail += drop_cnt.bits.no_rbr_avail;
	stats->rvm_errors += drop_cnt.bits.rvm_error;
	stats->ram_errors += drop_cnt.bits.rxram_error;
	stats->frame_errors += drop_cnt.bits.frame_error;

	stats->ierrors += drop_cnt.bits.too_long
		+ drop_cnt.bits.no_rbr_avail
		+ drop_cnt.bits.rvm_error
		+ drop_cnt.bits.rxram_error
		+ drop_cnt.bits.frame_error;

}


/* Error handler, specifically for fatal errors. Report the error to the
   system log. */
static rdc_stat_t process_rx(struct hxge_ldv *ldvp, int *got_ldf1)
{
	struct hxge_adapter *hxgep = ldvp->ldgp->hxgep;
        hpi_handle_t    handle = hxgep->hw.hw_addr;
	rdc_stat_t	cs;
	int channel = ldvp->ldv-HXGE_RDMA_LD_START;
	struct rx_ring_t *rx_ring = &hxgep->rx_ring[channel];
	struct rx_ring_stats_t *stats = &rx_ring->stats;
	rdc_rbr_qlen_t rbr_qlen;

	hpi_rxdma_control_status(handle, OP_GET, channel, &cs);
	cs.bits.ptrread = 0;
	cs.bits.pktread = 0;
	hpi_rxdma_control_status(handle, OP_SET, channel, &cs);
	ldvp->data = cs.value; /* Used to store npkts and nptrs later */

	if (cs.bits.rcr_to)  
		stats->rcr_to++;

	if (cs.bits.rcr_thres) 
		stats->rcr_thres++;

	if (cs.value & RDC_LDF1) {
		*got_ldf1 = 1;
		if (cs.bits.rbr_cpl_to) {
			HXGE_ERR(hxgep, "Fatal Error: Response completion timeout from PEU");
			stats->rbr_cpl_tmout++;
			stats->ierrors++;
		} 

		if (cs.bits.peu_resp_err) {
			HXGE_ERR(hxgep, "Fatal Error: Poisoned completion from PEU");
			stats->peu_resp_err++;
			stats->ierrors++;
		} 

		if (cs.bits.rcr_shadow_par_err) {
			HXGE_ERR(hxgep, "Fatal Error: RCR shadow ram parity error");
			stats->rcr_shadow_parity++;
			stats->ierrors++;
		} 

		if (cs.bits.rbr_prefetch_par_err) {
			HXGE_ERR(hxgep, "Fatal Error: RBR prefetch parity error");
			stats->rcr_prefetch_parity++;
			stats->ierrors++;
		}

		if (cs.bits.rbr_pre_empty) {
			HXGE_ERR(hxgep, "Fatal Error: Not enough RBR buffers to prefetch!");
			stats->rbr_prefetch_empty++;
			stats->ierrors++;
		}

		if (cs.bits.rcr_shadow_full) {
			HXGE_ERR(hxgep, "Fatal Error: RCR Shadow Full");
			stats->rcr_shadow_full++;
			stats->ierrors++;
		}

		if (cs.bits.rcr_full) {
			HXGE_ERR(hxgep, "Fatal Error: No space in  RCR descriptor ring");
			stats->rcr_full++;
			stats->ierrors++;
		}

		/* Re-enable the DMA channel. But, before returing from the
		   interrupt, process as many packets from the RCR as possible
		   to minimize the number of these interrupts we will receive
		*/
		if (cs.bits.rbr_empty) {
			rdc_rx_cfg1_t cfg;
			hpi_rxdma_rdc_rbr_qlen_get(handle, channel, &rbr_qlen);
			HXGE_DBG(hxgep, "Fatal Error: No more RBR buffers available for use, chan =  %d, qlen = %d",channel, rbr_qlen.bits.qlen);
			stats->rbr_empty++;
			stats->ierrors++;
			if (hpi_rxdma_cfg_rdc_wait_for_qst(handle, channel, &cfg,1)
					!= HPI_SUCCESS) {
				HXGE_ERR(hxgep, "qst bit did not quiet down");				 
			}
			else 
				rx_ring->rbr.rbr_empty_flag++;
		}

		if (cs.bits.rbr_full) {
			HXGE_ERR(hxgep, "Fatal Error: No space for more RBR buffers in hardware!");
			stats->rbr_full++;
			stats->ierrors++;
		}

		/* Update dropped-packets counts from Hydra's counters */
		update_rx_err_stats(handle, rx_ring);
	}

	return cs;
}

#ifdef CONFIG_HXGE_NAPI
/**
 * hxge_poll  - NAPI Rx polling callback. This is called once for each
 * device. So, this routine will have to go through and process the Rx
 * packets from all the channels for the device. So, Rx interrupts for all
 * channels must be disabled at this point. 
 *
 * work_to_do - Represents total work on this call of hxge_poll
 * work_per_channel - divide the total work allowed equally between channels
 *		      to avoid starvation
 * work_in_last_iteration - used as an idicator that no more packets available
 *                    across all channels. So, we can stop
 * @adapter: board private structure
 **/
int
hxge_poll(struct net_device *netdev, int *budget)
{
        struct hxge_adapter *hxgep = netdev->priv;
        int work_to_do = min(*budget, netdev->quota);
        int work_done = 0;
	int work_per_channel;
	struct hxge_ldgv *ldgvp = hxgep->ldgvp;
	struct hxge_ldv *ldvp;
	int got_ldf0, got_ldf1, pkt_cnt = 0, work_in_last_iteration;
	

	/* Go through each Rx channel and process packets received. If there
           is an error, then reset the channel and continue with other channels
	   and then exit after all channels are processed. To avoid starving
           a specific channel, we will equally budget the work_to_do across all
           channels. If we have any left over, we will go through a second 
	   round till we hit the budget limit */

	work_per_channel = work_to_do / hxgep->max_rdcs;
	do {
		rdc_stat_t cs;

		work_in_last_iteration = 0;
		list_for_each_entry (ldvp, &ldgvp->ldvp, list) {	
			if (ldvp->dev_type != LDV_RXDMA)
				continue;
			cs = process_rx(ldvp, &got_ldf1);
        		pkt_cnt = hxge_process_packets(hxgep, 
			            work_per_channel, 
			            ldvp->ldv-HXGE_RDMA_LD_START,NULL);
			if (pkt_cnt < 0) {
				HXGE_ERR("hxge_process_packets failed");
				got_ldf1 = 1;
			} else /* keep count of packets processed */ {
				HXGE_DBG("Channel %d = Processed %d pkts",ldvp->ldv-HXGE_RDMA_LD_START,pkt_cnt);
				work_done += pkt_cnt; 
				work_in_last_iteration += pkt_cnt;
				work_to_do -= pkt_cnt;
			}
			if (got_ldf1)  {
				set_bit(RESET_RX_CHANNEL_0+ldvp->ldv-HXGE_RDMA_LD_START, &hxgep->work_q.command);
				schedule_work(&hxgep->work_to_do);
			}

		}
	} while ((work_in_last_iteration > 0) && (work_to_do > 0));


	HXGE_DBG(hxgep, "Processed %d packets for all channels",work_done);
        if ((work_to_do <= 0) || (work_in_last_iteration <= 0)) {
                netif_rx_complete(netdev);
                hxge_enable_rx_ints(hxgep, NULL, -1);
                return 0;
        }

        /* still more Rx processing to do */
        *budget -= work_done;
        netdev->quota -= work_done;
        return 1;
}
#endif

/* Rx Interrupt handling. It can be called for each channel instance if they
   assigned to separate LDGs. However, given the nature of NAPI handling
   (a device can only be queued once to a given CPU; multiple instances of 
   the same device cannot be queued, even to different CPUs), only one 
   CPU at any given time handles a given device Rx channels. However, for
   the non-NAPI case, multiple CPUs can be processing different channels 
   Rx buffers at the same time. However, careful locking will be required 
   when the skb is created and queued from different CPUs for the same
   device */
  
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
irqreturn_t hxge_rx_intr(int irq, void *data, struct pt_regs *regs)
#else
irqreturn_t hxge_rx_intr(int irq, void *data)
#endif
{
	struct hxge_ldv *ldvp = (struct hxge_ldv *)data;
        struct hxge_ldg *ldgp = ldvp->ldgp;
	struct hxge_adapter *hxgep = ldgp->hxgep;
#ifdef CONFIG_HXGE_NAPI
        struct net_device *netdev = hxgep->netdev;
#endif
        int got_ldf0, got_ldf1;
	int pkts_rcvd;
	int channel = ldvp->ldv-HXGE_RDMA_LD_START;
	rdc_stat_t cs;

	get_ldf_flags(ldvp, &got_ldf0, &got_ldf1);
	/* Check if this is our interrupt. If not, probably shared. So just
           return and let other shared handlers check and take care of it */
	if (!got_ldf0 && !got_ldf1)
		return IRQ_NONE;

#ifdef CONFIG_HXGE_NAPI
	/* Go ahead and queue  device for processing later. However, ensure
           that all Rx channel device interrupts are masked since the packets
  	   that have arrived at all channels are processed at the same time
           by one CPU */
	if (likely(netif_rx_schedule_prep(netdev))) 
	{
		HXGE_DBG(hxgep, "Disable Rx Ints and schedule poll");
        	hxge_disable_rx_ints(hxgep, NULL, -1);
                __netif_rx_schedule(netdev);
	}
#else
	/* Process errors first. If fatal, then we reset the channel
           instead of attempting to process packets */
	cs = process_rx(ldvp, &got_ldf1);

	/* If not fatal error (taken care of by the error routine), 
	   then go ahead and see if there are packets to be received. 
	   Note that Rx processing can be done by different CPUs for 
	   different channels.  hxge_process_packets must take care of 
	   synchronization in required areas */

	if (unlikely(test_bit(HXGE_DEVICE_TESTING, &hxgep->state))) {
        	pkts_rcvd = hxge_process_packets(hxgep, ldvp, &ethtool_skb);
		if (pkts_rcvd > 0) {
			HXGE_DBG(hxgep, "%d pkts rcvd",pkts_rcvd);
			ethtool_cond -= pkts_rcvd;
		}
		if (!ethtool_cond || (pkts_rcvd < 0))
			wake_up_interruptible(&ethtool_evnt);
	} else
		if (hxge_process_packets(hxgep, ldvp, NULL) < 0) {
			HXGE_ERR(hxgep, "hxge_process_packets failed");
			hxge_disable_rx_ints(hxgep, ldgp, channel);
			got_ldf1 = 1; /* fall through */
	}

	if (got_ldf1) {
		hpi_handle_t handle = hxgep->hw.hw_addr;
		struct rx_ring_t *rx_ring = &hxgep->rx_ring[channel];
		
		if (cs.bits.rbr_empty && rx_ring->rbr.rbr_empty_flag) {
			int i;
			HXGE_DBG(hxgep, "Posting %d buffers",rx_ring->rbr.rbr_empty_threshold);
			hpi_rxdma_rdc_rbr_kick(handle, channel, 
					rx_ring->rbr.rbr_empty_threshold);
			rx_ring->stats.rbr_empty_posted += rx_ring->rbr.rbr_empty_threshold;
			rx_ring->rbr.rbr_empty_flag--;
			rx_ring->rbr.rbr_empty_threshold = 0;
			hxge_vmac_rx_set_framesize(hxgep, 1);
			HXGE_DBG(hxgep, "Disabled VMAC");
			if (hpi_rxdma_cfg_rdc_enable(handle, channel)
							!= HPI_SUCCESS) {
				hxge_vmac_rx_set_framesize(hxgep, hxgep->vmac.rx_max_framesize);
				HXGE_ERR(hxgep, "hpi_rxdma_cfg_rdc_enable failed");
		                set_bit(RESET_RX_CHANNEL_0+channel,
               			         &hxgep->work_q.command);
                		schedule_work(&hxgep->work_to_do);
				goto failed;
			} else {
				HXGE_DBG(hxgep, "Re-enabled RDC Channel %d",channel);
			}

			HXGE_DBG(hxgep, "Enabled the RDC Channel");
			/* a delay loop; forcing PIO reads to cause any 
 			 * preceding PIO writes to complete??
 			 */
			for (i = 0; i < 5; i++) 
				udelay(100);
			
			HXGE_DBG(hxgep, "Completed wait cycle");

			hxge_vmac_rx_set_framesize(hxgep, hxgep->vmac.rx_max_framesize);
			rx_ring->stats.rbr_empty_handled++;
			HXGE_DBG(hxgep, "Enabled VMAC");
		} else {
			HXGE_ERR(hxgep, "Resetting on LDF1");
			/* Reset the channel. We do this for all fatal (LDF1) 
			 * errors. We assume that the reset will clear out the 
			 * error bits as well */
			set_bit(RESET_RX_CHANNEL_0+channel, 
				&hxgep->work_q.command);
			schedule_work(&hxgep->work_to_do);
			goto failed;
		}
	}
	hxge_enable_rx_ints(hxgep, ldgp, channel);
failed:
#endif
        return (IRQ_HANDLED);
}



/* Receive error interrupt handler
 *
 * Called from Device Error Interrupt (ldv 31) service, not RX DMA
 *
 * NB: *data is Device Error ldv 31, not an RX DMA channel ldv!
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
irqreturn_t hxge_rx_deverr_intr(int irq, void *data, struct pt_regs *regs)
#else
irqreturn_t hxge_rx_deverr_intr(int irq, void *data)
#endif
{
	struct hxge_ldv *ldvp = (struct hxge_ldv *)data; /* Device Error ldv */
	struct hxge_adapter *hxgep = ldvp->ldgp->hxgep;
	hpi_handle_t	handle = hxgep->hw.hw_addr;
	rdc_fifo_err_stat_t sts, clr;
	int hard_error = 0;

	if (hpi_rx_fifo_status(handle, OP_GET, &sts) 
		!= HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hpi_rx_fifo_status failed");
	}

	HXGE_ERR(hxgep, "RX hardware error interrupt (0x%16.16x)!",
		 (unsigned int)sts.value);

	clr.value = sts.value;

	if (sts.bits.rx_ctrl_fifo_sec) {
		HXGE_ERR(hxgep, "rx_ctrl_fifo_sec");
		hxgep->statsp->rx_ctrl_sec++;
		hxgep->statsp->soft_errors++; /* Soft (recovered) dev error */
		clr.bits.rx_ctrl_fifo_sec = 0;
	}

	if (sts.bits.rx_ctrl_fifo_ded) {
		HXGE_ERR(hxgep, "rx_ctrl_fifo_ded");
		hxgep->statsp->rx_ctrl_ded++;
		hxgep->statsp->rx_ierrors++; /* Rx summary count */
		hxgep->statsp->hard_errors++; /* Hard device error */
		hard_error = TRUE;
		clr.bits.rx_ctrl_fifo_ded = 0;
	}

	if (sts.bits.rx_data_fifo_sec) {
		HXGE_ERR(hxgep, "rx_data_fifo_sec");
		hxgep->statsp->rx_data_sec++;
		hxgep->statsp->soft_errors++; /* Soft (recovered) dev error */
		clr.bits.rx_data_fifo_sec = 0;
	}

	if (sts.bits.rx_data_fifo_ded) {
		HXGE_ERR(hxgep, "rx_data_fifo_ded");
		hxgep->statsp->rx_data_ded++;
		hxgep->statsp->rx_ierrors++; /* Rx summary count */
		hxgep->statsp->hard_errors++; /* Hard device error */
		hard_error = TRUE;
		clr.bits.rx_data_fifo_ded = 0;
	}

	if (clr.value) {
		HXGE_ERR(hxgep, "Unknown/unexpected/reserved RDC_FIFO_ERR_STAT bits 0x%16.16x", (unsigned int)clr.value);
		hxgep->statsp->hard_errors++; /* Unknown hard device error */
		hard_error = TRUE; /* Whatever, it's bad; hammer something */
	}

	/* Now that we have "logged" the errors, try to recover from
	 * whatever happened.  Note that "SEC" (Single Bit ECC) is
	 * recovered by hardware, and needs no further action here.
	 */

	/* Acknowledge (and clear) error status bits */

	hpi_rx_fifo_status(handle, OP_SET, &sts);

	/* Resume processing unless too many errors (hard or soft) */

	if (hxge_ok_to_continue(hxgep)) {
		if (hard_error) {
			/* Double-bit error, integrity lost, reset Rx */
			hxge_disable_rx_ints(hxgep, NULL, -1);
			set_bit(RESET_RDC, &hxgep->work_q.command);
			schedule_work(&hxgep->work_to_do);
		} /* Else single-bit error, just dismiss and continue */
	} else {
		HXGE_ERR(hxgep, "Excessive hardware error rate");
		HXGE_ERR(hxgep, "                      Taking hxge device down");
		hxge_disable_interrupts(hxgep);
		set_bit(SHUTDOWN_ADAPTER, &hxgep->work_q.command);
		schedule_work(&hxgep->work_to_do);
	}

	return (IRQ_HANDLED);
}
