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

#include "hpi/hpi_txdma.h"
#include "hxge.h"

/* failure return codes for map_skbdata_to_descs and copy_skbdata_to_descs
 * respectively */
#define MAP_DESC_FAILED  -1
#define COPY_DESC_FAILED -2

extern int hxge_ok_to_continue(struct hxge_adapter *hxgep);
extern int hxge_block_reset(struct hxge_adapter *hxgep, int device);
extern void hxge_disable_interrupts(struct hxge_adapter *hxgep);


static int start_reclaim_thread(struct tx_ring_t *tx_ring);
static int stop_reclaim_thread(struct tx_ring_t *tx_ring);

#ifdef CONFIG_ERRINJECT

#define FREE_SKB	hxge_free_skb

static atomic_t skb_count = ATOMIC_INIT(0);
void hxge_free_skb(struct sk_buff *skb)
{
	atomic_dec(&skb_count);
	dev_kfree_skb_any(skb);
}


#else
#define FREE_SKB	dev_kfree_skb_any
#endif


/* Program the Tx registers in hardware to get it ready for transmit. The 
 * enabling of the channel is done later 
 */
static int hxge_map_tx_to_hw(struct hxge_adapter *hxgep, int channel)
{
	hpi_handle_t handle = hxgep->hw.hw_addr;
	struct tx_ring_t *tx_ring = &hxgep->tx_ring[channel];
	tdc_tdr_cfg_t tdr_cfg;
	tdc_int_mask_t ev_mask;

	/* Reset already completed, so don't need to set that bit. Set the 
 	   DMA address of the Tx descriptor ring. Also the entries in the
 	   ring */
	tdr_cfg.value = 0;
	tdr_cfg.value = tx_ring->desc_ring.dma_addr & TDC_TDR_CFG_ADDR_MASK;
	tdr_cfg.bits.len = tx_ring->num_tdrs >> 5;
	if (hpi_txdma_ring_config(handle, OP_SET, channel, &tdr_cfg.value) !=
		HPI_SUCCESS)
	{
		HXGE_ERR(hxgep, "hpi_txdma_ring_config failed");
		return -1;
	}

	/* Write the mailbox register */
	if (hpi_txdma_mbox_config(handle, OP_SET, channel, 
			&tx_ring->mbox.dma_addr) != HPI_SUCCESS)
	{
		HXGE_ERR(hxgep, "hpi_txdma_mbox_config failed");
		return -1;
	}

	/* Setup the transmit event mask */
	ev_mask.value = 0;

	/* CR 6678180 workaround - Mask Tx ring overflow to avoid getting
	 * false overflow interrupts
	 */
	ev_mask.bits.tx_rng_oflow = 1; 
	if (hpi_txdma_event_mask(handle, OP_SET, channel, &ev_mask) != 
			HPI_SUCCESS)
	{
		HXGE_ERR(hxgep, "hpi_txdma_event_mask failed");
		return -1;
	}

	return 0;
}


/* Assumes that the skb->csum is prep'ed for hw checksumming. This routine
 * just completes what the hardware would have done. There is here as a 
 * workaround for a hw checksum bug
*/
static int fixup_checksum(struct sk_buff *skb
#ifdef CONFIG_ERRINJECT
			  , struct hxge_adapter *hxgep
#endif
)

{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
        unsigned int csum;
        int ret = 0;
	int offset = skb->h.raw - skb->data;

        if (skb_cloned(skb)) {
                ret = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
                if (ret)
                        goto out;
        }

        BUG_ON(offset > (int)skb->len);
        csum = skb_checksum(skb, offset, skb->len-offset, 0);

        offset = skb->tail - skb->h.raw;
        BUG_ON(offset <= 0);
        BUG_ON(skb->csum + 2 > offset);

        *(u16*)(skb->h.raw + skb->csum) = csum_fold(csum);
#ifdef CONFIG_ERRINJECT
	if (hxgep->err_flags & CHKSUM_FAILURE) {
		HXGE_ERR(hxgep, "Injecting checksum error");
        	*(u16*)(skb->h.raw + skb->csum) = 0;
	}
#endif
#else
       __wsum csum;
        int ret = 0, offset;

        offset = skb->csum_start - skb_headroom(skb);
        BUG_ON(offset >= skb_headlen(skb));
        csum = skb_checksum(skb, offset, skb->len - offset, 0);

        offset += skb->csum_offset;
        BUG_ON(offset + sizeof(__sum16) > skb_headlen(skb));

        if (skb_cloned(skb) &&
            !skb_clone_writable(skb, offset + sizeof(__sum16))) {
                ret = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
                if (ret)
                        goto out;
        }
        *(__sum16 *)(skb->data + offset) = csum_fold(csum);
#ifdef CONFIG_ERRINJECT
	if (hxgep->err_flags & CHKSUM_FAILURE) {
		 HXGE_ERR(hxgep, "Injecting checksum error");
        	*(__sum16 *)(skb->data + offset) = 0;
	}
#endif
#endif
out:
        return ret;
}


/* This routine initializes the data structures specific to a channel. 
 * Additionally, it initializes the tx channel related registers in the 
 * hydra hardware 
 */

static int hxge_init_tx_channel(struct hxge_adapter *hxgep, int channel)
{
	struct tx_ring_t *tx_ring = &hxgep->tx_ring[channel];
	int num_tdrs = tx_ring->num_tdrs;
	int buffer_size = tx_ring->tx_buffer_size, i;
	struct tx_buf_t *tx_buf;
	dma_addr_t dma_addr;
	caddr_t vaddr;
	
	HXGE_DBG(hxgep, "Calling hxge_init_tx_channel for channel %d",channel);
	
	/* initialize the Tx descriptor ring */
	memset(tx_ring->desc_ring.vaddr, 0, sizeof(tx_desc_t)*num_tdrs);
	HXGE_DBG(hxgep, "Initializing Tx Descriptor ring at 0x%p",tx_ring->desc_ring.vaddr);

	/* Initialize the Tx buffers */
	//memset(tx_ring->data_buf.vaddr, 0, sizeof(struct tx_buf_t)*num_tdrs);
	
	HXGE_DBG(hxgep, "Initializing Tx Buffers for headers");
	dma_addr = tx_ring->data_buf.dma_addr;
	vaddr    = tx_ring->data_buf.vaddr;
	for (i = 0, tx_buf=tx_ring->tx_buf; i < num_tdrs; 
		i++, tx_buf++, dma_addr += buffer_size, vaddr += buffer_size) {
		tx_buf->map.dma_addr = dma_addr;
		tx_buf->map.vaddr    = vaddr;
		tx_buf->flags	 = TX_FLAGS_UNUSED;
	}
	
	/* Entire ring available at start */
	atomic_set(&tx_ring->descs_avail, num_tdrs);
	tx_ring->tail = 0;
	tx_ring->wrap = FALSE; /* really does not matter since it's a toggle */
	tx_ring->reclaim_head = 0;
	tx_ring->reclaim_wrap = FALSE; 
	tx_ring->hxgep = hxgep;
	tx_ring->mark_ints = 0;
	
	/* Initialize the mailbox */
	memset(tx_ring->mbox.vaddr, 0, sizeof(txdma_mailbox_t));

	hxge_map_tx_to_hw(hxgep, channel);

	/* Start the reclaim thread */
	tx_ring->thread_pid = -1;
	start_reclaim_thread(tx_ring);
	return 0;
}

/* Caller must have the Tx ring lock */
static int reclaim_tx_ring(struct hxge_adapter *hxgep, 
		struct tx_ring_t *tx_ring, tdc_tdr_head_t head_reg)
{
	int descs_processed = 0;
	boolean_t head_wrap;
	int head_index;
	struct tx_buf_t *tx_buf;
	int wrapped;
	unsigned long start_time = jiffies;
	int full;

	head_wrap = head_reg.bits.wrap;
	head_index = head_reg.bits.head;
	wrapped = (head_wrap != tx_ring->reclaim_wrap);
        full = ((head_index == tx_ring->reclaim_head) && wrapped);


	if (head_index >= tx_ring->num_tdrs) {
		HXGE_ERR(hxgep, "head_index exceeds ring size! (head_index = 0x%x, Tx ring size = 0x%x",head_index, tx_ring->num_tdrs);
		BUG();
	}

        if (full && atomic_read(&tx_ring->descs_avail)) {
                HXGE_ERR(hxgep, "discrepancy in buffer mgmt: hd=0x%x,rhd=0x%x, hwrp=%d, rwrp=%d, descs_avail=%d",head_index, head_wrap, tx_ring->reclaim_head, tx_ring->reclaim_wrap, atomic_read(&tx_ring->descs_avail));
                BUG();
        }

	while (!time_after(jiffies, start_time+800) &&
		((tx_ring->reclaim_head != head_index) || wrapped))
	{
		wrapped = 0;
		tx_buf = &tx_ring->tx_buf[tx_ring->reclaim_head];
		if (tx_buf->flags & TX_FLAGS_UNMAP) /* mapped data */ {
			int len; 
			HXGE_DBG(hxgep, "Unmapping @(%p,%d)",(char *)tx_buf->map.dma_addr,tx_buf->map.len);
			len = (tx_buf->flags & TX_FLAGS_ALLOC) ? PAGE_SIZE :
					tx_buf->map.len;
			pci_unmap_page(hxgep->pdev, tx_buf->map.dma_addr, 
					len, PCI_DMA_TODEVICE);
		}

		if (tx_buf->flags & TX_FLAGS_ALLOC) {
			HXGE_DBG(hxgep, "Freeing tx_buf->map.vaddr@%p of len %d (channel %d)",tx_buf->map.vaddr, (int)PAGE_SIZE, tx_ring->tdc);
			free_page((unsigned long)tx_buf->map.vaddr);
		}

		tx_buf->map.vaddr = 0;
		tx_buf->map.dma_addr = 0;
		tx_buf->map.len = 0;
				
		if (tx_buf->skb) {
			/* free the header array for gso */
			if (SKB_IS_GSO(tx_buf->skb)) {
				int i;
				struct skb_hdr_info_t *skb_hdr = 
				    (struct skb_hdr_info_t *)tx_buf->skb->cb;
				struct pci_dma_map_t *pci_map = &skb_hdr->pci_map;
				pci_free_consistent(hxgep->pdev, 
					skb_hdr->hdr_array.len, 
					skb_hdr->hdr_array.vaddr, 
					skb_hdr->hdr_array.dma_addr);


                		if (pci_map->num_dma_mappings) {
                        		for (i = 0; 
						i < pci_map->num_dma_mappings; 
						i++)
                                		pci_unmap_page(hxgep->pdev,
                                       		   pci_map->dma_map[i].dma_addr,
                                        	   pci_map->dma_map[i].len, 
						   PCI_DMA_TODEVICE);
                        		kfree(pci_map->dma_map);
				}
			}
			FREE_SKB(tx_buf->skb);
			tx_buf->skb = NULL;
		}
		tx_buf->flags = TX_FLAGS_UNUSED;
                tx_ring->reclaim_head = (tx_ring->reclaim_head + 1) %
                                tx_ring->num_tdrs;
                if (!tx_ring->reclaim_head) {
                        if (tx_ring->reclaim_wrap == TRUE)
                                tx_ring->reclaim_wrap = FALSE;
                        else
                                tx_ring->reclaim_wrap = TRUE;
                }
                descs_processed++;
	}

	atomic_add(descs_processed, &tx_ring->descs_avail);
	if (netif_queue_stopped(hxgep->netdev))
		netif_wake_queue(hxgep->netdev);

	return descs_processed;
}

static int entries_to_process(struct hxge_adapter *hxgep, 
			struct tx_ring_t *tx_ring, tdc_tdr_head_t *head_reg)
{
	hpi_handle_t handle = hxgep->hw.hw_addr;
	int head_index;
	boolean_t head_wrap;

	if (hpi_txdma_ring_head_get(handle, tx_ring->tdc, head_reg) 
		!= HPI_SUCCESS)
	{
		HXGE_ERR(hxgep, "hpi_txdma_ring_head_get_failed for channel %d",tx_ring->tdc);
		return -1;
	}
	head_index = head_reg->bits.head;
	head_wrap  = (head_reg->bits.wrap) ? TRUE : FALSE;
	if (((head_index != tx_ring->reclaim_head) ||
		(head_wrap != tx_ring->reclaim_wrap)))
		return 1;

	return 0;
}

/* When killing the reclaim thread (either due to interface bringdown or 
 * driver unload), make sure that all pending Tx descriptors have been sent
 * before stopping the Tx channel
 */
int wait_till_empty(struct hxge_adapter *hxgep, struct tx_ring_t *tx_ring)
{
	hpi_handle_t handle = hxgep->hw.hw_addr;
	int hindex;
	boolean_t hwrap;
	tdc_tdr_head_t head_reg;
	int count = 5;

	do {
		msleep(1);
		hpi_txdma_ring_head_get(handle, tx_ring->tdc, &head_reg);
		hindex = head_reg.bits.head;
		hwrap = head_reg.bits.wrap;
	} while(!TXDMA_RING_EMPTY(hindex, hwrap, tx_ring->tail,tx_ring->wrap)
			&& --count);

	if (!count) {
		HXGE_ERR(hxgep, "Pending Tx Descriptors not all sent out!");
		return -1;
	}

	return 0;
}

	

/* There is one kernel thread per Tx channel to reclaim unused Tx descriptor
 * rings for use by the Tx channel. The thread periodically wakes up to 
 * do reclaim work. Otherwise, it is woken up immediately when a Tx completes
 * (hxge_tx_intr) when there is reclaim work for sure. It is also woken up
 * if there is high transmit traffic and an immediate need to free up 
 * space (hxge_start_xmit)
 */

static int reclaim_thread(void *data) { 
	struct tx_ring_t *tx_ring = data; 
	struct hxge_adapter *hxgep = tx_ring->hxgep;
	int ret_val;
	tdc_tdr_head_t head_reg;


	daemonize("tx_reclaim_%d", tx_ring->tdc);
	while (1) {

                wait_event_interruptible_timeout(tx_ring->reclaim_event, 
		    (ret_val = entries_to_process(hxgep, tx_ring,&head_reg)),
	            RECLAIM_TIMEOUT);

		if (ret_val < 0)
			break;

		/* Ready to get killed. make sure that any outstanding 
		 * descriptors are freed before leaving; otherwise we 
		 * can be leaking skbs
		 */
		if (tx_ring->kill_reclaim == TRUE) {
			wait_till_empty(hxgep, tx_ring);
                	reclaim_tx_ring(hxgep, tx_ring, head_reg);
			break;
		}

		/* Try to get the lock. If already taken, probably initializing 
 		   the channel due to some error. Return and try later */
		if (test_and_set_bit(RING_RECLAIM, &tx_ring->state))
			continue;

                reclaim_tx_ring(hxgep, tx_ring, head_reg);
		clear_bit(RING_RECLAIM, &tx_ring->state);
	}

	while (tx_ring->kill_reclaim == FALSE);
	complete(&tx_ring->reclaim_complete);
	return 0;

}

static int start_reclaim_thread(struct tx_ring_t *tx_ring)
{
        tx_ring->kill_reclaim = FALSE;
        init_completion(&tx_ring->reclaim_complete);
        init_waitqueue_head(&tx_ring->reclaim_event);
        tx_ring->thread_pid = kernel_thread(reclaim_thread,  tx_ring, CLONE_FS|CLONE_FILES);
        if (tx_ring->thread_pid < 0) {
                HXGE_ERR_PRINT("Failed to start kernel thread");
                return -1;
        }
        HXGE_DBG_PRINT("reclaim thread %d started", tx_ring->tdc);
        return 0;
}

static int stop_reclaim_thread(struct tx_ring_t *tx_ring)
{
        tx_ring->kill_reclaim = TRUE;
        wake_up_interruptible(&tx_ring->reclaim_event);
        wait_for_completion(&tx_ring->reclaim_complete);
	tx_ring->thread_pid = -1;
        HXGE_DBG_PRINT("reclaim thread %d killed", tx_ring->tdc);
        return 0;
}



/* Allocate data structures to manage the transmit channel including calling
 * the routine that intializes the HW registers specific to this transmit 
 * channel 
 */
static int hxge_alloc_tx_channel(struct hxge_adapter *hxgep, int channel)
{
	struct tx_ring_t *tx_ring = &hxgep->tx_ring[channel];
	uint32_t size;
	int num_tdrs;

	spin_lock_init(&tx_ring->lock);
	HXGE_DBG(hxgep, "Calling hxge_alloc_tx_channel for channel %d", channel);
	if (hxge_get_option("num_tx_descs", &num_tdrs)) {
		HXGE_ERR(hxgep, "invalid value for num_tx_descriptors");
		return -1;
	}

	tx_ring->num_tdrs = num_tdrs;
	tx_ring->hxgep = hxgep;

	if (hxge_get_option("tx_buffer_size", &tx_ring->tx_buffer_size)) {
		HXGE_ERR(hxgep, "invalid tx_buffer_size");
		return -1;
	}
	
	tx_ring->tdc = channel;
	tx_ring->desc_ring.vaddr = pci_alloc_consistent(hxgep->pdev, 
			sizeof(tx_desc_t)*tx_ring->num_tdrs, 
			&tx_ring->desc_ring.dma_addr);
	if (!tx_ring->desc_ring.vaddr) {
		HXGE_ERR(hxgep, "Could not alloate descriptor ring");
		return -1;
	}
	HXGE_DBG(hxgep, "Allocated Tx Descriptor Ring at %p, %llx", tx_ring->desc_ring.vaddr, tx_ring->desc_ring.dma_addr);

	if (!valid_alignment(tx_ring->data_buf.dma_addr, 
		sizeof(tx_desc_t)*tx_ring->num_tdrs, 19)) {
		HXGE_ERR(hxgep, "Tx Descriptor Ring not aligned");
		return -1;
	}

	/* TODO: Allocate tx buffers. All packets need to have the packet header
 	   prepended to them. The skbs coming in might not have head room 
	   for the packet header. So, these tx buffers are used to allocate
	   the header and then copy the skb header+data into them */

	tx_ring->tx_buf = kzalloc(num_tdrs*sizeof(struct tx_buf_t), GFP_KERNEL);

	if (!tx_ring->tx_buf) {
		HXGE_ERR(hxgep, "could not allocate Tx Buffers");
		return -1;
	}
	HXGE_DBG(hxgep, "Allocated Tx Buffer Array at %p", tx_ring->tx_buf);
	
	size = tx_ring->tx_buffer_size * num_tdrs; /* in bytes */
	tx_ring->data_buf.vaddr = pci_alloc_consistent(hxgep->pdev, size, 
					&tx_ring->data_buf.dma_addr);
	if (!tx_ring->data_buf.vaddr) {
		HXGE_ERR(hxgep, "could not allocate tx buffers");
		return -1;
	}
	HXGE_DBG(hxgep, "Allocated Tx Data Buffers at %p", tx_ring->data_buf.vaddr);
	


	/* Allocate mailbox */
	tx_ring->mbox.vaddr = pci_alloc_consistent(hxgep->pdev, 
			sizeof(txdma_mailbox_t), &tx_ring->mbox.dma_addr);
	if (!tx_ring->mbox.vaddr) {
		HXGE_ERR(hxgep, "could not allocate mbox");
		return -1;
	}

	return 0;

}

static void hxge_free_tx_channel(struct hxge_adapter *hxgep, int channel)
{
	struct tx_ring_t *tx_ring = &hxgep->tx_ring[channel];
	int size;

	
	if (tx_ring->desc_ring.vaddr) {
		size = sizeof(tx_desc_t) * tx_ring->num_tdrs;
		pci_free_consistent(hxgep->pdev, size, 
		    tx_ring->desc_ring.vaddr, tx_ring->desc_ring.dma_addr);
	}

	if (tx_ring->data_buf.vaddr) {
		size = tx_ring->tx_buffer_size * tx_ring->num_tdrs;
		pci_free_consistent(hxgep->pdev, size, 
		    tx_ring->data_buf.vaddr, tx_ring->data_buf.dma_addr);
	}

	if (tx_ring->mbox.vaddr) 
		pci_free_consistent(hxgep->pdev, sizeof(txdma_mailbox_t),
			tx_ring->mbox.vaddr, tx_ring->mbox.dma_addr);

	if (tx_ring->tx_buf)
		kfree(tx_ring->tx_buf);
}

void hxge_free_tx(struct hxge_adapter *hxgep)
{
	int i;

	for (i = 0; i < hxgep->max_tdcs; i++)
		hxge_free_tx_channel(hxgep, i);

	if (hxgep->tx_ring)	
		kfree(hxgep->tx_ring);

	hxgep->tx_ring = NULL;

#ifdef CONFIG_ERRINJECT
	if (atomic_read(&skb_count)) {
		HXGE_ERR(hxgep,"All SKBs have not been freed! Memory leak, skb pending = %d", atomic_read(&skb_count));
	}
#endif
}

int hxge_alloc_tx(struct hxge_adapter *hxgep)
{
	int i;

	if (hxge_get_option("tx_dma_channels", &hxgep->max_tdcs)) {
		HXGE_ERR(hxgep, "invalid value for tx_dma_channels option");
		return -1;
	}

	hxgep->tx_ring = kzalloc(hxgep->max_tdcs*sizeof(struct tx_ring_t), 
					GFP_KERNEL);
	if (!hxgep->tx_ring) {
		HXGE_ERR(hxgep, "Could not allocate tx_ring");
		return -1;
	}

	for (i = 0; i < hxgep->max_tdcs; i++) 
		if (hxge_alloc_tx_channel(hxgep, i)) {
			HXGE_ERR(hxgep, "could not alloc tx for channel");
			hxge_free_tx(hxgep);
			return -1;
		}

	return 0;
}

static int hxge_disable_tx_channel(struct hxge_adapter *hxgep, int channel)
{
	hpi_handle_t handle = hxgep->hw.hw_addr;
	struct tx_ring_t  *tx_ring = &hxgep->tx_ring[channel];

	clear_bit(RING_ENABLED, &tx_ring->state);

	/* Stop the reclaim thread */
	if (tx_ring->thread_pid >  0) 
		stop_reclaim_thread(tx_ring);
	else
		HXGE_DBG(hxgep, "Reclaim thread for Tx channel %d already stopped?",channel);

	/* Disable transmits through this channel */
	if (hpi_txdma_channel_disable(handle, channel) != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hpi_txdma_channel_disable failed");
	}
	HXGE_DBG(hxgep, "Channel %d disabled",channel);
	return 0;
}

int hxge_disable_tx(struct hxge_adapter *hxgep)
{	
	int i;
	struct tx_ring_t  *tx_ring;

	hxge_disable_tx_ints(hxgep);

	for (i = 0; i < hxgep->max_tdcs; i++) {
		tx_ring = &hxgep->tx_ring[i];
		spin_lock(&tx_ring->lock); 
		if (hxge_disable_tx_channel(hxgep, i)) {
			HXGE_ERR(hxgep, "Could not disable channel %i",i);
		}
		spin_unlock(&tx_ring->lock);
		/* Free any pending skbs that were queued up for transmission
		   but did not get a chance to be sent */
		if (tx_ring->tx_buf) {
			int j;
			for (j = 0; j < tx_ring->num_tdrs; j++) {
				struct tx_buf_t *tx_buf = &tx_ring->tx_buf[j];
				if (tx_buf->skb) {
					FREE_SKB(tx_buf->skb);
					tx_buf->skb = NULL;
				}
			}
		}
	}
	return 0;
}

static int hxge_enable_tx_channel(struct hxge_adapter *hxgep, int channel)
{
	hpi_handle_t handle = hxgep->hw.hw_addr;
	tdc_stat_t cs;
	struct tx_ring_t  *tx_ring = &hxgep->tx_ring[channel];

	/* Reset the channel */
	hpi_txdma_channel_reset(handle, channel);

	/* Explicitly set the kick register to zero because reset does not
           do it. Set tail and wrap to zero */
	hpi_txdma_desc_kick_reg_set(handle, channel, 0, 0);

	/* Explicitly clear out the Tx Stat register; some of them are 
           RW1C types. The channel reset does not seem to do it */
	cs.value = (u64)~0ULL;
	hpi_txdma_control_status(handle, OP_SET, 0, &cs);

	hxge_init_tx_channel(hxgep, channel);


	/* Make sure that reclaim thread is not running when we reinitialize
           this Tx channel. We make the assumption that the tx_ring lock 
	   WILL be locked by caller except in initialiation case. So, this
	   statement means the following :
		1. In the initialiation case, it is doing exactly that i.e
		   initializing the lock
		2. In the reset channel case (or any other case for that 
		   matter), it serves a unlocking the lock */

	spin_lock_init(&tx_ring->lock);

	/* Set the enable bit for the channel to start transmits */
	hpi_txdma_channel_enable(handle, channel);
	set_bit(RING_ENABLED, &tx_ring->state);

	HXGE_ERR(hxgep, "Channel %d enabled",channel);

	return 0;
}

/* Re-enable Tx channel (e.g., in response to LDF1 channel disable) */
static int hxge_reenable_tx_channel(struct hxge_adapter *hxgep, int channel)
{
	hpi_handle_t handle = hxgep->hw.hw_addr;
	struct tx_ring_t  *tx_ring = &hxgep->tx_ring[channel];

	/* The various TdcStat, kick, head, etc. registers should have
           remained valid and should NOT need to be re-initialized.
	   We should just "resume" from whence we were "paused". */

	if ((!test_bit(RING_ENABLED, &tx_ring->state))
	     || (test_bit(RING_RESET, &tx_ring->state)))
		return 0;	/* Explicitly disabled; leave un-enabled */

	/* Set the enable bit for the channel to re-start Tx operations */
	hpi_txdma_channel_enable(handle, channel);

	HXGE_DBG(hxgep, "Channel %d re-enabled",channel);

	return 0;
}

/* Wait for Tx channel idle (wait for QST to set) */
static int hxge_qstwait_tx_channel(struct hxge_adapter *hxgep, int channel)
{
	hpi_handle_t handle = hxgep->hw.hw_addr;
	hpi_status_t hsts;

	/* Wait for Tx operations to quiesce (QST to be set) */

	hsts = hpi_txdma_control_reset_wait(handle, channel);
	if (hsts != HPI_SUCCESS) {
		HXGE_ERR(hxgep, "Channel %d failed to idle (QST not set)", channel);
	}
		
	return 0;
}

void hxge_reset_tx_channel(struct hxge_adapter *hxgep, int channel)
{
	struct tx_ring_t  *tx_ring = &hxgep->tx_ring[channel];

	HXGE_ERR(hxgep, "Starting tx reset");
	/* If already in this code, then return */
	if (test_and_set_bit(RING_RESET, &tx_ring->state)) 
		return; 

	/* We don't want the reclaim thread to run while we resetting. If
           already in reclaim, then wait for it to finish */
	while (test_and_set_bit(RING_RECLAIM, &tx_ring->state))
		mdelay(1);

	/* Not calling unlock; hxge_init_tx_channel will initialize it
 	 * unlocked */
	spin_lock(&tx_ring->lock);

	hxge_disable_tx_channel(hxgep, channel);
	hxge_enable_tx_channel(hxgep, channel);

	clear_bit(RING_RECLAIM, &tx_ring->state);
	clear_bit(RING_RESET, &tx_ring->state);
	HXGE_ERR(hxgep, "Tx channel reset complete");
}

/* Enable Transmits. Also, enable Tx interrupts */
int hxge_enable_tx(struct hxge_adapter *hxgep)
{
	int i;
	hpi_handle_t    handle = hxgep->hw.hw_addr;
	uint64_t reg64 = 0xfeedfacedeadbeefULL;
	uint64_t data;

	/* Initialize global TX-related error handling */

	HXGE_REG_RD64(handle, TDC_FIFO_ERR_STAT, &reg64);
	if (reg64) {
		/* While an interesting case (error flags should probably
		 * not be set), do not count against hxgep->hard_errors */
		HXGE_ERR(hxgep, "TDC_FIFO_ERR_STAT 0x%16.16x hardware error flags set",
			 (unsigned int)reg64);
	}
	HXGE_REG_WR64(handle, TDC_FIFO_ERR_STAT, reg64); /* RW1C err bits */
	HXGE_REG_WR64(handle, TDC_FIFO_ERR_MASK, 0); /* 0 = no disables */


	/* Scrub rtab memory */
	HXGE_REG_WR64(handle, TDC_REORD_TBL_DATA_HI, 0);
	HXGE_REG_WR64(handle, TDC_REORD_TBL_DATA_LO, 0);
	for (i = 0; i < 256; i++) {
		HXGE_REG_WR64(handle, TDC_REORD_TBL_CMD, i);
		do {
			HXGE_REG_RD64(handle, TDC_REORD_TBL_CMD, &reg64);
		} while (!(reg64 & 0x80000000ULL));

		HXGE_REG_WR64(handle, TDC_REORD_TBL_CMD, (1ULL << 30) | i);
		do {
			HXGE_REG_RD64(handle, TDC_REORD_TBL_CMD, &reg64);
		} while (!(reg64 & 0x80000000ULL));

		
		HXGE_REG_RD64(handle, TDC_REORD_TBL_DATA_LO, &reg64);
		HXGE_REG_RD64(handle, TDC_REORD_TBL_DATA_HI, &data);
		data &= 0xffULL; /* save only data bits, not parity */
		
		if (reg64 | data) {
			HXGE_ERR(hxgep, "Error reading RTAB data regs, entry: 0x%x, data lo: 0x%llx, data hi: 0x%llx",i, reg64, data);
			HXGE_REG_RD64(handle, TDC_FIFO_ERR_STAT, &reg64);
			if (reg64) {
				HXGE_ERR(hxgep, "ReordTbl parity error, entry: %x, fifo error stat: 0x%llx", i, reg64);
			}
			return -1;
		}
	}

	/* Now enable each of the TDC DMA channels */

	for (i = 0; i < hxgep->max_tdcs; i++)
		hxge_enable_tx_channel(hxgep, i);

	/* Enable Tx interrupts */
	hxge_enable_tx_ints(hxgep, NULL);

	return 0;
}


/* Reset entire Tx ("TDC") subsystem */
int hxge_reset_tdc(struct hxge_adapter *hxgep)
{
	/* Quiesce ("shutdown") all transmit activity first */

	hxge_disable_tx(hxgep);

	/* Generate tdc_core logic reset */

	hxge_block_reset(hxgep, LDV_TXDMA);

	/* Finally, bring all the Tx channels back up */

	hxge_enable_tx(hxgep);

	return 0;
}


/* Re-enable Transmits/Tx interrupts (e.g., after LDF1 auto-disable) */
int hxge_reenable_tx(struct hxge_adapter *hxgep)
{
	int i;

	for (i = 0; i < hxgep->max_tdcs; i++)
		hxge_reenable_tx_channel(hxgep, i);

	/* We assume the Tx interrupts "enablement" was unchanged by
	 * whatever course of events led us here. */

	return 0;
}


/* Wait for Transmits/Tx to go idle (wait for Tx QST to set) */
int hxge_qstwait_tx(struct hxge_adapter *hxgep)
{
	int i;

	for (i = 0; i < hxgep->max_tdcs; i++)
		hxge_qstwait_tx_channel(hxgep, i);

	return 0;
}


static int get_desc_required(struct tx_ring_t *tx_ring, struct sk_buff *skb)
{
	int skb_len = skb->len;
	int num_descs = 0, len, tx_len;

	if ((skb_len + TX_PKT_HEADER_SIZE < tx_ring->tx_buffer_size) &&
	    !skb_shinfo(skb)->nr_frags)
		return 1;

	len = skb_headlen(skb);
	num_descs++; /* one for internal header */
	while (len) {
		tx_len = len < TX_MAX_TRANSFER_LENGTH ? 
					len : TX_MAX_TRANSFER_LENGTH;
		len -= tx_len;
		num_descs++;
	}

	/* The max size of an SKB fragment is one page size i.e 4096 bytes. 
	 * However, due to a bug, the max size that one Tx descriptor buffer
	 * can transfer is 4076 bytes. So, worst case, we might need at most
	 * two descriptors to send one fragment 
	 */ 
	if (skb_shinfo(skb)->nr_frags) {
		num_descs += (2*skb_shinfo(skb)->nr_frags);
		return num_descs;
	}

	return num_descs;
}


/* Pick the next channel to transmit on. We pick the CPU that the transmit
 * thread is running on (hoping cpu affinity helps). If that particular
 * channel does not have sufficient descriptors for this skb, then do a
 * round robin from that point till we find one that has space; better to 
 * find one than just return attempting a retransmit from higher layers
 */
static struct tx_ring_t *get_channel_to_transmit(struct hxge_adapter *hxgep, 
			struct sk_buff *skb, int *state, int *desc_required)
{	
	uint8_t tx_channel_state = 0;
	struct tx_ring_t *tx_ring = NULL;
	int channel, start_channel, channels_tried;
	int attempt = 1; /* 1 ms */

	*state = NETDEV_TX_OK;

	channel = start_channel = smp_processor_id() % hxgep->max_tdcs;
	for (channels_tried = 0; channels_tried < hxgep->max_tdcs; 
		channels_tried++, channel = (channel+1) % hxgep->max_tdcs)
	{
                tx_ring = &hxgep->tx_ring[channel];

		if (!test_bit(RING_ENABLED, &tx_ring->state)) {
			tx_channel_state |= (1 << channel); 
			continue;
		}
		/* Grab the Tx channel lock to avoid race between multiple Tx
 		 * threads using this channel. Also, synchronizes with the 
 		 * reset code since we don't want to be in here while a reset 
 		 * is happening and visa versa.
 		 */
		while (!(spin_trylock(&tx_ring->lock))) {
			mdelay(1);
			if (!attempt) {
				HXGE_ERR(hxgep, "Could not get tx lock!");
				tx_ring->stats.txlock_acquire_failed++;

				dev_kfree_skb_any(skb);
				*state = NETDEV_TX_OK;
				return NULL;
			}
			attempt--;
		}
		if (*desc_required < 0)
			*desc_required = get_desc_required(tx_ring, skb);
		if (atomic_read(&tx_ring->descs_avail) < *desc_required) {
                	wake_up_interruptible(&tx_ring->reclaim_event);
			spin_unlock(&tx_ring->lock);
			continue;
		}
		else break;
	}

	if (tx_channel_state == (1 << HXGE_MAX_TDCS) -1) {
		HXGE_ERR(hxgep, "All channels disabled!");
		dev_kfree_skb_any(skb);
		*state = NETDEV_TX_OK;
		return NULL;
	}

	if (channels_tried == hxgep->max_tdcs) {
                *state = NETDEV_TX_BUSY;
		return NULL;
	}

	return tx_ring;
}

static inline int valid_packet(struct hxge_adapter *hxgep, 
			struct tx_ring_t *tx_ring, struct sk_buff *skb)
{
	int skb_len = skb->len;

	/* Badly constructed skb */
	if (unlikely(!skb || (skb_len <= 0))) {
		HXGE_ERR(hxgep, "Badly formed skb!");
		return 0;
	}

	/* More skb fragments than we have Tx descriptor ring entries */
	if (unlikely(skb_shinfo(skb)->nr_frags + 1 > tx_ring->num_tdrs)) {
		HXGE_ERR(hxgep, "Too many skb fragments than space allows");
		return 0;
	}

	/* packet larger than MTU size. Really shoud not happen since higher 
           layer protocol probably needs to fragment the packet before sending 
           to us */
	if (skb_len > hxgep->vmac.maxframesize) {
		HXGE_ERR(hxgep, "skb_len is %d, Packet size MTU (max frame size) supported",skb_len);
		return 0;
	}

	return 1;

}

/* A utility routine to allocate a new data buffer for transmit if the 
 * current one is full. The caller must ensure that the curr_index is properly
 * updated
 */
static inline struct tx_buf_t *get_txbuf(struct hxge_adapter *hxgep, 
		struct tx_ring_t *tx_ring, int *desc_required)
{
        struct tx_buf_t *tx_buf; 
        tx_buf = &tx_ring->tx_buf[tx_ring->curr_index];

        if (!tx_buf->flags) /* unused location; allocate new buffer */
        {

#ifdef CONFIG_ERRINJECT
		if (hxgep->err_flags & ALLOC_PAGES_FAILURE) {
			HXGE_ERR(hxgep, "no page alloc'ed (errinj)");
			return NULL;
		}
#endif
	
		/* allocate new page */
                tx_buf->map.vaddr = (caddr_t) __get_free_page(GFP_DMA);

		if (!tx_buf->map.vaddr) {
			HXGE_ERR(hxgep, "no page alloc'ed");
			return NULL;
		}

#ifdef CONFIG_ERRINJECT
		if (hxgep->err_flags & PCIMAP_FAILURE) {
			HXGE_ERR(hxgep, "pci_map_page failed (errinj)");
			free_page((unsigned long)tx_buf->map.vaddr);
			return NULL;
		}
#endif

		/* grab a DMA-map for the page */
                tx_buf->map.dma_addr = pci_map_page(hxgep->pdev,
                        virt_to_page(tx_buf->map.vaddr),
                        offset_in_page(tx_buf->map.vaddr),
                        PAGE_SIZE, PCI_DMA_TODEVICE);

		if (!tx_buf->map.dma_addr)
		{
			HXGE_ERR(hxgep, "pc_map_page failed");
			free_page((unsigned long)tx_buf->map.vaddr);
			return NULL;
		}

		tx_buf->map.len = 0;
                tx_buf->flags = TX_FLAGS_DATA | TX_FLAGS_ALLOC | TX_FLAGS_UNMAP;
                tx_buf->skb = NULL; /* should be set in hdr desc */
        	++*desc_required; 
        }


	return tx_buf;
}

/* Utility routine to write the transmit descriptors into the Tx descriptor 
 * ring for the HW to process. Only the non-SOP entries are written using 
 * this routine.
 */
static int write_tx_descs(struct hxge_adapter *hxgep, struct tx_ring_t *tx_ring,
				int start, int num_descs)
{
	int i;
	tx_desc_t desc;
	desc.value = 0;

	
	for (i = start; i < (start+num_descs); i++) {
		struct tx_buf_t *tx_buf;
		hpi_handle_t handle;
		tx_desc_t *descp;

		handle = &tx_ring->desc_ring.vaddr[i % tx_ring->num_tdrs];
		tx_buf = &tx_ring->tx_buf[i % tx_ring->num_tdrs];
		if (hpi_txdma_desc_gather_set(handle, &desc, 1, 0, 0,
		    tx_buf->map.dma_addr, tx_buf->map.len) != HPI_SUCCESS)
		{
			HXGE_ERR(hxgep, "hpi_txdma_desc_gather_set failed");
			return -1;
		}
		descp = (tx_desc_t *)handle;
		HXGE_DBG(hxgep, "TX_BUF");
		HXGE_DBG(hxgep, "	tx_buf->len : %d",tx_buf->map.len);
		HXGE_DBG(hxgep, "	tx_buf->vaddr : %p",tx_buf->map.vaddr);
		HXGE_DBG(hxgep, "	tx_buf->dma_addr: %p",(void *)tx_buf->map.dma_addr);
		HXGE_DBG(hxgep, " DESC =>");
		HXGE_DBG(hxgep, "    SOP:%d, mark:%d, num_ptr:%d, len:%d, sad:0x%llx", 
			descp->bits.sop, descp->bits.mark, 
			descp->bits.num_ptr, descp->bits.tr_len,
			 (unsigned long long)descp->bits.sad);	
	}
	return 0;
}
			
/* This routine copies data from the SKB to staging buffers instead of 
 * using scatter gather lists like map_skbdata_to_descs. This routine is 
 * called when the number of skb fragments approach or exceed the 15 
 * descriptors per packet limit
 */
static int copy_skbdata_to_descs(struct hxge_adapter *hxgep, 
		struct tx_ring_t *tx_ring, char *data_ptr, uint32_t len,
		int *desc_required)
{
	struct tx_buf_t *tx_buf = NULL;
	
	while (len) {
		uint32_t max_len;
		uint32_t tx_len;

		tx_buf = get_txbuf(hxgep, tx_ring, desc_required);

		if (!tx_buf || !(tx_buf->flags & TX_FLAGS_ALLOC)) {
			HXGE_ERR(hxgep, "tx_buf (%p) alloc failed",tx_buf);
			return COPY_DESC_FAILED;
		}

		max_len = TX_MAX_TRANSFER_LENGTH - tx_buf->map.len;
		tx_len = len < max_len ?  len : max_len;

		memcpy(tx_buf->map.vaddr + tx_buf->map.len, data_ptr, tx_len);
		tx_buf->map.len += tx_len;
		data_ptr += tx_len;
		len -= tx_len;

		/* the buffer is full; start new buffer next time around */
		if (tx_buf->map.len == TX_MAX_TRANSFER_LENGTH)
			TXDMA_GET_NEXT_INDEX(tx_ring, 1);
	}

	/* corner case: When we are the last skb fragment calling in and 
         * we happened to just fill this data buffer, we don't want to bump 
         * the index in this case because we did it at the tail end of the
         * while loop above. However, we do want the caller of this routine
         * to bump to the next index a new packet
	 */
	if (tx_buf && (tx_buf->map.len < TX_MAX_TRANSFER_LENGTH))
		return 1;

	return 0;
}

/* To map skb data into Tx descriptor ring entries. The case for the internal
 * header is done separately (not here). Also, this does not include the 
 * case where the skb is copied in to the tx buffer 
 */
static int map_skbdata_to_descs(struct hxge_adapter *hxgep,
		struct tx_ring_t *tx_ring, char *data_ptr, uint32_t len,
		int *desc_required)
{
	uint32_t tx_len;
	struct tx_buf_t *tx_buf;

	while (len) {
		tx_buf = &tx_ring->tx_buf[tx_ring->curr_index];
		tx_len = len < TX_MAX_TRANSFER_LENGTH ?
                                   len : TX_MAX_TRANSFER_LENGTH;

#ifdef CONFIG_ERRINJECT
		if (hxgep->err_flags & PCIMAP_FAILURE) {
			HXGE_ERR(hxgep, "pcimap err injected");
			return MAP_DESC_FAILED;
		}
#endif
			
                tx_buf->map.dma_addr = pci_map_page(hxgep->pdev,
                                        virt_to_page(data_ptr),
                                        offset_in_page(data_ptr), tx_len,
                                        PCI_DMA_TODEVICE);

		if (!tx_buf->map.dma_addr) {
			HXGE_ERR(hxgep, "pci_map_page failed");
			return MAP_DESC_FAILED;
		}

                tx_buf->map.len = tx_len;
		tx_buf->map.vaddr = data_ptr;
                tx_buf->flags = TX_FLAGS_DATA | TX_FLAGS_UNMAP;
                tx_buf->skb = NULL; /* already set in hdr */
                data_ptr += tx_len;
                len -= tx_len;
		TXDMA_GET_NEXT_INDEX(tx_ring, 1);
                ++*desc_required;

	}

	return 0;
}

/* Cleanup up in the event of a failure either in map_skbdata_to_descs
 * or copy_skbdata_to_descs. Free up allocated pages and unmap dma
 * mappings as appropriate. Also move the curr_index back for next packet
 */

static void cleanup_descs(struct hxge_adapter *hxgep, 
			struct tx_ring_t *tx_ring, int descs)
{ 
	struct tx_buf_t *tx_buf;

	while (descs) {
		TXDMA_DEC_INDEX(tx_ring);
		tx_buf = &tx_ring->tx_buf[tx_ring->curr_index];
		if (tx_buf->flags & TX_FLAGS_UNMAP) {
			int len = (tx_buf->flags & TX_FLAGS_ALLOC) ? PAGE_SIZE :
				tx_buf->map.len;
			pci_unmap_page(hxgep->pdev, tx_buf->map.dma_addr, 
				len, PCI_DMA_TODEVICE);
		}
		if (tx_buf->flags & TX_FLAGS_ALLOC) 
			free_page((unsigned long)tx_buf->map.vaddr);

		memset(tx_buf, 0, sizeof(struct tx_buf_t));
		descs--;
	}
}



/* Fill in the internal header set up in a Tx buffer by the transmit code. This
 * requires tunneling through the ethernet payload and getting inforamtion from
 * the L2, L3 and L4 layers to fill in information required.
 * Arguments:
 *	pkt_hdr - Pointer to where the header information
 *	skb     - Contains the data payload
 *	len	- The total length of the data payload excluding internal header
 */
 
static void fill_tx_hdr(tx_pkt_header_t *pkt_hdr, struct sk_buff *skb, int len
#ifdef CONFIG_ERRINJECT
			, struct hxge_adapter *hxgep
#endif
)
{
	uint8_t                 *ip_p = NULL;
	uint16_t                eth_type;
	char			*proto_hdr = NULL;
	struct udphdr 		*udp_hdr = NULL;
	struct tcphdr		*tcp_hdr = NULL;
	struct iphdr		*ip_hdr = NULL;
	uint8_t			ip_proto = 0;
	struct ipv6hdr		*ipv6_hdr = NULL;
	struct skb_hdr_info_t   *skb_hdr_info;

	skb_hdr_info = (struct skb_hdr_info_t *)skb->cb;
	memset(pkt_hdr, 0, sizeof(tx_pkt_header_t));
	pkt_hdr->bits.tot_xfer_len = len;
	
	/* Read the type field from the ethernet frame */
	eth_type = ntohs(skb->protocol);


	/* This is when type < 1500 i.e. 802.3 type and not Ethernet III */
	if (eth_type < ETH_DATA_LEN) { 
		if (*(skb->data + ETH_HLEN) == LLC_SAP_SNAP) {
			eth_type = ntohs(*((uint16_t*)(skb->data + ETH_HLEN + 6)));
			if (eth_type == ETH_P_IP || eth_type == ETH_P_IPV6)
				ip_p = (uint8_t*)(skb->data + ETH_HLEN + 8);
		} else return;
        } else if (eth_type == ETH_P_8021Q) { /* VLAN support */

                pkt_hdr->bits.vlan = 1;
                eth_type = ntohs(((struct vlan_ethhdr *)skb->data)->h_vlan_encapsulated_proto);
                if (eth_type == ETH_P_IP || eth_type == ETH_P_IPV6)
                        ip_p = (uint8_t*)(skb->data + VLAN_ETH_HLEN);
        } else  /* Ethernet III type */
                ip_p = (uint8_t*)(skb->data + ETH_HLEN);


	/* Now we have got the "real" type value. Tunnel through the IP 
           payload to get L3 and L4 information needed in the header */
	switch (eth_type) {
	case ETH_P_IP : /* IPv4 */
		ip_hdr = (struct iphdr *)ip_p;
		pkt_hdr->bits.ip_ver = 0;
		pkt_hdr->bits.ihl = ip_hdr->ihl;
		pkt_hdr->bits.l3start = ((ulong)ip_hdr - (ulong)skb->data) >> 1;
		ip_proto = ip_hdr->protocol;
		proto_hdr = (char *)ip_hdr + (ip_hdr->ihl<<2);
		break;
	case ETH_P_IPV6: /* IPv6 */
		ipv6_hdr = (struct ipv6hdr *)ip_p;
		pkt_hdr->bits.ip_ver = 1;
		pkt_hdr->bits.ihl = 40 >> 2; /* hard-coded */
		pkt_hdr->bits.l3start = ((ulong)ipv6_hdr - (ulong)skb->data)>>1;
		ip_proto = ipv6_hdr->nexthdr;
		proto_hdr = (char *)ipv6_hdr + 40;
		break;
	default :
		return;
		break;
	}

	/* Checksumming is done only if Linux has marked for it to be done. 
 	   The driver has notified Linux that it does L4 checksumming as part
 	   of initialization but there are scenarios where Linux will have to
	   do checksumming itself (IP fragments). So, check the ip_summed field
	   to see if Linux has requested for it */

	/* TODO: Is a zero value in l4stuff a valid offset? How does one turn 
                 off checksumming on a per-packet basis on Hydra? */
	switch (ip_proto) {
	case IPPROTO_TCP : 
		tcp_hdr = (struct tcphdr *)proto_hdr;
		pkt_hdr->bits.l4start = (ulong)tcp_hdr - (ulong)skb->data;
		skb_hdr_info->l4_payload_offset  = pkt_hdr->bits.l4start + 
							(tcp_hdr->doff << 2);
		pkt_hdr->bits.l4start >>=1;
		if (skb->ip_summed == HXGE_CHECKSUM) {/* hardware do checksum */
			pkt_hdr->bits.cksum_en_pkt_type = 1;
			pkt_hdr->bits.l4stuff = pkt_hdr->bits.l4start +
						(SKB_CKSUM_OFFSET(skb) >> 1);
#ifdef CONFIG_ERRINJECT
		        if (hxgep->err_flags & CHKSUM_FAILURE) {
               			 HXGE_ERR(hxgep, "Injecting checksum error");
				 pkt_hdr->bits.l4stuff--;
        		}
#endif
		}
		break;
	case IPPROTO_UDP :
		udp_hdr = (struct udphdr *)proto_hdr;
		pkt_hdr->bits.l4start = (ulong)udp_hdr - (ulong)skb->data;
		skb_hdr_info->l4_payload_offset = pkt_hdr->bits.l4start + 
						sizeof(struct udphdr);
		pkt_hdr->bits.l4start >>= 1;



		if (skb->ip_summed == HXGE_CHECKSUM) {
			/* workaround a hw checksum offload for udp/ipv6. 
			   Complete the partial checksum that was already
  		           setup in skb->csum just like the hw would have done
			   it */

			if (eth_type == ETH_P_IPV6) {
				fixup_checksum(skb
#ifdef CONFIG_ERRINJECT
				,hxgep
#endif
				);	
				break;
			}
			pkt_hdr->bits.cksum_en_pkt_type = 2;
			pkt_hdr->bits.l4stuff = pkt_hdr->bits.l4start +
						(SKB_CKSUM_OFFSET(skb) >> 1);
#ifdef CONFIG_ERRINJECT
		        if (hxgep->err_flags & CHKSUM_FAILURE) {
               			 HXGE_ERR(hxgep, "Injecting checksum error");
				 pkt_hdr->bits.l4stuff--;
        		}
#endif

		}
		break;
	default :
		break;
	}
}


/* The main routine for transmitting a packet. It is called directly by the 
 * Linux network stack via the hard_xmit_frame network device function pointer.
 * It determines which channel to pick for transmit, maps the packet data to
 * Tx descriptor ring entries, creates the internal packet header and informs
 * hydra of the new descriptor entries via the kick register
 */

int hxge_tx_ring(struct sk_buff *skb, struct net_device *netdev)

{
	int channel, desc_required=-1, hdr_index, i;
	struct hxge_adapter *hxgep = netdev_priv(netdev);
	struct tx_ring_t *tx_ring;
	int skb_len = skb->len, tot_len;
	int len;
	struct tx_buf_t *tx_buf;
	tx_desc_t desc;
	tx_desc_t *descp;
	hpi_handle_t handle = hxgep->hw.hw_addr;
	tx_pkt_header_t *pkt_hdr;
	int state;

	/* 
 	 * Get channel to transmit on. It returns with the tx_ring->lock locked
 	 * if successful 
 	 */

	tx_ring = get_channel_to_transmit(hxgep, skb, &state, &desc_required);
	if (!tx_ring) {
                if (state == NETDEV_TX_BUSY) {
			if (!netif_queue_stopped(netdev))
	                        netif_stop_queue(netdev);
		}
		return (state);
	}

	/* Validate the packet */
	if (!valid_packet(hxgep, tx_ring, skb)) {
		HXGE_ERR(hxgep, "Freeing skb due to invalid packet");
		dev_kfree_skb_any(skb);
		spin_unlock(&tx_ring->lock);
		return (NETDEV_TX_OK);
	}


	channel = tx_ring->tdc;

	/* There is space for at least the current packet */

	TXDMA_GET_CURR_INDEX(tx_ring);
	hdr_index= tx_ring->curr_index;
	tx_buf = &tx_ring->tx_buf[hdr_index];
        tx_buf->map.vaddr = tx_ring->data_buf.vaddr + 
                               (hdr_index*tx_ring->tx_buffer_size);

        tx_buf->map.dma_addr = tx_ring->data_buf.dma_addr + 
                               (hdr_index*tx_ring->tx_buffer_size);
	tx_buf->flags = TX_FLAGS_HDR;
	tx_buf->map.len = TX_PKT_HEADER_SIZE; /* assume just header; no data content */
	tx_buf->skb = skb;
	skb_orphan(skb);
#ifdef CONFIG_ERRINJECT
	atomic_inc(&skb_count);
#endif

	tot_len = TX_PKT_HEADER_SIZE;
	/* Increment to next free entry */
	TXDMA_GET_NEXT_INDEX(tx_ring, 1);

#if 0
	HXGE_DBG(hxgep, "Have %d descs", desc_required);
	HXGE_DBG(hxgep, "SKB => ");
	HXGE_DBG(hxgep, "   skb->len = %d",skb->len);
	HXGE_DBG(hxgep, "   skb->priority = %d", skb->priority);
	HXGE_DBG(hxgep, "   skb->data_len= %d", skb->data_len);
	HXGE_DBG(hxgep, "   skb->nr_frags= %d", skb_shinfo(skb)->nr_frags);
#endif
	
	if (desc_required == 1) /* small packet */  {
		len = skb_headlen(skb);
		memcpy((char *)tx_buf->map.vaddr + TX_PKT_HEADER_SIZE, skb->data, 
					len);
		tx_buf->flags = TX_FLAGS_ALL;
		tx_buf->map.len += len; /* data len in addition to internal hdr */
		tot_len += len;
	} else {
		int ret = 0;
		desc_required = 1; /* for header */

		if (map_skbdata_to_descs(hxgep, tx_ring, 
		      (char *)skb->data, skb_headlen(skb),&desc_required) < 0)
		{
			HXGE_ERR(hxgep, "map_skbdata_to_descs failed");
			FREE_SKB(skb);
			cleanup_descs(hxgep, tx_ring, desc_required);
			spin_unlock(&tx_ring->lock);
			return (NETDEV_TX_OK);
		}   
		
		for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
			skb_frag_t *fragp = &skb_shinfo(skb)->frags[i];
			char *dat = (char *)page_address(fragp->page)+fragp->page_offset;

			HXGE_DBG(hxgep, "Frag %d @ (%p,%d), len %d",i,(char *)fragp->page, fragp->page_offset,fragp->size);


			/* CR 7104801: If the number of skb fragments are more
 			 * the number of tx descriptors available, then we
 			 * have to copy and consolidate the remaining fragments 
 			 * into newly allocated buffers. We need to make 
 			 * sure that at least 3 descriptor entries are reserved
 			 * for the copy giving us a total of 12KB (4KB page).
 			 * This should be sufficient on Hydra where the largest
 			 * packet cannot exceed 9KB
 			 */
			if (desc_required > HXGE_TX_DESCS_PER_PACKET-4) 
				ret = copy_skbdata_to_descs(hxgep, tx_ring, 
					dat, fragp->size, &desc_required);
			else 
				ret = map_skbdata_to_descs(hxgep, tx_ring, dat,
					 fragp->size, &desc_required);

			if (ret < 0)
			{
				char fn[25];
				if (ret == COPY_DESC_FAILED)
					strncpy(fn, "copy_skbdata_to_descs",21);
				else
					strncpy(fn, "map_skbdata_to_descs",20);
					
				HXGE_ERR(hxgep, "%s failed", fn);
				FREE_SKB(skb);
				cleanup_descs(hxgep, tx_ring, desc_required);
				spin_unlock(&tx_ring->lock);
				return (NETDEV_TX_OK);
			}
			
		}
		tot_len += skb_len;

		/* copy_skbdata_to_descs ends in the middle of a tx_buf; need
 		 * to point to new one for next packet
 		 */
		if (ret > 0)
			TXDMA_GET_NEXT_INDEX(tx_ring, 1);
		
	}

	/* write out the non-SOP descriptors now */
	write_tx_descs(hxgep, tx_ring, hdr_index+1, desc_required-1);

	/* Create internal header. This requires tunneling into packet
	   data. When doing ethtool testing, just fill total len and ignore
           other fields in the skb header  */
	if (unlikely(test_bit(HXGE_DEVICE_TESTING, &hxgep->state))) {
		pkt_hdr = (tx_pkt_header_t *)tx_buf->map.vaddr;
		pkt_hdr->value = 0;
		pkt_hdr->bits.tot_xfer_len = tot_len+skb->priority;
		HXGE_DBG(hxgep, "Internal header size is %d", pkt_hdr->bits.tot_xfer_len);
	}
	else 
		fill_tx_hdr((tx_pkt_header_t *)tx_buf->map.vaddr, skb, tot_len
#ifdef CONFIG_ERRINJECT
		, hxgep
#endif
);


	/* Set up and write the SOP descriptor. The length does not include 
  	 * internal packet length; just the data packet only */

	desc.value = 0;
	tx_ring->mark_ints = (tx_ring->mark_ints+1) % hxgep->tx_mark_ints;


	hpi_txdma_desc_gather_set(&tx_ring->desc_ring.vaddr[hdr_index], &desc, 
				0, (tx_ring->mark_ints == 0), desc_required,
				tx_buf->map.dma_addr, tx_buf->map.len);


	tx_ring->stats.descs_used[desc_required]++;

	/* Sanity Test: descriptors used should never exceed HW limit of 15 */
        if (desc_required > HXGE_TX_DESCS_PER_PACKET) {
		HXGE_ERR(hxgep, "BUG: desc_required > %d!! Will cause tx_reset",HXGE_TX_DESCS_PER_PACKET); 
		BUG();
	}

	HXGE_DBG(hxgep, "Sending through channel %d. Packet Info =>",channel);
	for (i = 0, descp=&tx_ring->desc_ring.vaddr[hdr_index]; i < desc_required; i++)
		HXGE_DBG(hxgep, "    SOP:%d, mark:%d, num_ptr:%d, len:%d, sad:0x%llx",
			 descp->bits.sop, descp->bits.mark,
			 descp->bits.num_ptr, descp->bits.tr_len,
			 (unsigned long long)descp->bits.sad);


	/* Update the descriptors available for use. Note that update to this
           variable races with the reclaim thread, hence an atomic operation */
	atomic_sub(desc_required, &tx_ring->descs_avail);

	if (atomic_read(&tx_ring->descs_avail) < 0) {
	    HXGE_ERR(hxgep, "Descriptors available less than zero!!");	
	}
	/* Update descriptors available. Write the SOP descriptor entry and 
           kick the number of new entries added */
	TXDMA_UPDATE_INDEX(tx_ring);
	hpi_txdma_desc_kick_reg_set(handle, channel, tx_ring->tail,
					tx_ring->wrap);

	/* Successfully queued one network packet of <skb_len> bytes */

	tx_ring->stats.opackets++;
	tx_ring->stats.obytes += skb_len;

	spin_unlock(&tx_ring->lock);
	
	return NETDEV_TX_OK;
}

static inline int compute_tot_hdrlen(struct skb_hdr_info_t *skb_hdr, 
					struct staging_info_t *si)
{
	int l4_hdr_len, l3_hdr_len;
	tx_pkt_header_t *pkt_hdr = &si->pkthdr;

	si->l3_offset = pkt_hdr->bits.l3start << 1;
	si->l4_offset = pkt_hdr->bits.l4start << 1;
	l4_hdr_len  = skb_hdr->l4_payload_offset -
				(pkt_hdr->bits.l4start<<1);
	si->l4_hdr_len = l4_hdr_len;
	l3_hdr_len = (pkt_hdr->bits.l4start-pkt_hdr->bits.l3start)<<1;
	return ((pkt_hdr->bits.l3start<<1) + l3_hdr_len + l4_hdr_len);
}

static void free_staging_info(struct hxge_adapter *hxgep, 
				struct staging_info_t *si, int failure)
{
	if (failure) {
		int i;
		struct pci_dma_map_t *pci_map = &si->pci_map;
		if (si->hdr_array.vaddr) 
			pci_free_consistent(hxgep->pdev, si->hdr_array.len, 
		    		si->hdr_array.vaddr, si->hdr_array.dma_addr);

		if (pci_map->num_dma_mappings) {
			for (i = 0; i < pci_map->num_dma_mappings; i++) 
				pci_unmap_page(hxgep->pdev, 
					pci_map->dma_map[i].dma_addr, 
					pci_map->dma_map[i].len, 
					PCI_DMA_TODEVICE);
			kfree(pci_map->dma_map);
		}
	}

	if (si->desc) 
		kfree(si->desc);

	if (si)
		kfree(si);
}

static struct staging_info_t *setup_staging_info(struct hxge_adapter *hxgep,
					struct sk_buff *skb)
{
	struct staging_info_t *si;
	struct skb_hdr_info_t *skb_hdr = (struct skb_hdr_info_t *)skb->cb;
	int frame_cnt = SKB_GSO_SEGS(skb);

	si = (struct staging_info_t *)kzalloc(sizeof(struct staging_info_t), GFP_KERNEL);
	if (!si) {
		HXGE_ERR(hxgep,"No space for staging structure");
		return NULL;
	}

	memset(skb_hdr, 0, sizeof(struct skb_hdr_info_t));
	fill_tx_hdr(&si->pkthdr, skb, 0
#ifdef CONFIG_ERRINJECT
	, hxgep
#endif
	);

	si->tcpip_hdr_len = compute_tot_hdrlen(skb_hdr, 
						si);
	si->hdr_array.len = frame_cnt* sizeof(si->hdr_template);
	si->max_frames = frame_cnt;
	si->frame_size = SKB_IS_GSO(skb);
	si->hdr_array.vaddr  = pci_alloc_consistent(hxgep->pdev, 
				si->hdr_array.len, 
				&si->hdr_array.dma_addr);
	if (!si->hdr_array.vaddr)
		goto fail;

	/* do not use until we are done setting up the entire packet */
	si->desc = kmalloc(frame_cnt*DESCS_PER_FRAME*
				sizeof(struct staging_desc_t), GFP_KERNEL);
	if (!si->desc) {
		HXGE_ERR(hxgep,"No space for staging desc");
		goto fail;
	}

	/* This is stored so that we can free the staging structure but 
 	 * keep a pointer to the  hdr array which needs to be around till
 	 * the skb is done i.e entire packet has been transmitted
 	 */
	skb_hdr->hdr_array = si->hdr_array;

	/* setup the hdr template with standard  values. This contains the
           values for l3stuff, l4stuff, l3start, l4start, etc all set up
	   by the call to fill_tx_hdr and saved to si->pkthdr */
	memcpy(si->hdr_template, (char *)&si->pkthdr, 
					sizeof(tx_pkt_header_t));
	memcpy(si->hdr_template+TX_PKT_HEADER_SIZE, skb->data,
			si->tcpip_hdr_len);

	/* Initialize some of the fields within the template with initial
	   values from the skb */
	do {
		char *hdrp  = si->hdr_template;
		struct tcphdr *tcphdrp = (struct tcphdr *)
			(hdrp + TX_PKT_HEADER_SIZE + si->l4_offset);
		struct iphdr *iphdrp  = (struct iphdr *)
			(hdrp + TX_PKT_HEADER_SIZE + si->l3_offset);
		si->tcp_sequence = ntohl(tcphdrp->seq);
		si->ip_id = ntohs(iphdrp->id);
		/* Save the initial skb state of the flags and then clear it
		   out in the template. fixup_tcpip_hdr takes care of setting
		   the vaues in the appropriate frame */
		if (tcphdrp->urg) si->tcp_flags = TCP_FLAGS_URG;
		if (tcphdrp->psh) si->tcp_flags |= TCP_FLAGS_PSH;
		if (tcphdrp->rst) si->tcp_flags |= TCP_FLAGS_RST;
		if (tcphdrp->fin) si->tcp_flags |= TCP_FLAGS_FIN;
		tcphdrp->urg = tcphdrp->psh = tcphdrp->rst = 0;
		tcphdrp->fin = 0;

	} while (0);
	   
	return si;
fail:
	free_staging_info(hxgep, si, 1);
	return NULL;
}

static inline void fixup_tcpip_hdr(struct staging_info_t *sp, int frame, int len,
				struct tcphdr *tcphdrp, struct iphdr *iphdrp)
{
	tcphdrp->seq = htonl(sp->tcp_sequence);
	iphdrp->id = htons(sp->ip_id++);
	sp->tcp_sequence += len;
	iphdrp->tot_len = htons(len + sp->l4_hdr_len + sp->l4_offset - 
					sp->l3_offset);

	/* Fix up the TCP flags; only the first and last matter. The rest of 
	   the frames have zeros for these flags */
	if (!frame)  // first frame
		tcphdrp->urg = (sp->tcp_flags & TCP_FLAGS_URG);
	else if (frame == sp->max_frames-1) {
		tcphdrp->psh = (sp->tcp_flags & TCP_FLAGS_PSH);
		tcphdrp->rst = (sp->tcp_flags & TCP_FLAGS_RST);
		tcphdrp->fin = (sp->tcp_flags & TCP_FLAGS_FIN);
	}
	/* do checksumming last after all the fields in tcp and ip
         * headers have been fixed up properly
	 */
	iphdrp->check = 0;
	iphdrp->check = ip_fast_csum((uint8_t *)iphdrp, iphdrp->ihl);
	tcphdrp->check = ~csum_tcpudp_magic(iphdrp->saddr, iphdrp->daddr, 
					sp->l4_hdr_len+len, IPPROTO_TCP, 0);
}

static int setup_frame(struct hxge_adapter *hxgep, struct staging_info_t *si, 
				int len, int frame)
{
	int ngathers = 1; // alwauys one descriptor
	char *hdrp =  si->hdr_array.vaddr+(frame*HDR_TEMPLATE_SIZE);
	struct staging_desc_t *descp = &si->desc[si->desc_idx];
	struct staging_desc_t *sop_descp = descp++;
	struct tcphdr *tcphdrp;
	struct iphdr  *iphdrp;
	tx_pkt_header_t *pkt_hdr;
	int loc_len = len;
	int idx = si->dma_map_idx;
	int off = si->dma_map_off;
	struct dma_map_t *dma_map = si->pci_map.dma_map;

		
	memcpy(hdrp, si->hdr_template, sizeof(si->hdr_template));
	tcphdrp = (struct tcphdr *)(hdrp + TX_PKT_HEADER_SIZE + 
					si->l4_offset);
	iphdrp  = (struct iphdr *)(hdrp + TX_PKT_HEADER_SIZE + 
					si->l3_offset);
	fixup_tcpip_hdr(si, frame, len, tcphdrp, iphdrp);

	while (loc_len) {
		dma_addr_t dma_addr = dma_map[idx].dma_addr+off;
		int desc_len = min(loc_len, dma_map[idx].len-off);
		if (idx >= si->pci_map.num_dma_mappings) {
			HXGE_ERR(hxgep,"idx (%d) > num_mappings (%d), dma_map = %p, si = %p, len=%d",idx,si->pci_map.num_dma_mappings,dma_map, si, len);
			BUG();
		}
		desc_len = min(desc_len, TX_MAX_TRANSFER_LENGTH);
		memset(descp, 0, sizeof(struct staging_desc_t));
		descp->entry.bits.sad = (uint64_t)dma_addr;
		descp->entry.bits.tr_len = desc_len;
		loc_len-= desc_len;
		off += desc_len;
		if (off == dma_map[idx].len) {
			off = 0;
			idx++;
		}
		descp++;
		ngathers++;
	}

	si->dma_map_idx = idx;
	si->dma_map_off = off;

	/* setup the SOP descriptor; it contains the internal packet header
	 * and the TCP/IP header information
	 */
	sop_descp->entry.bits.sop = 1;
	sop_descp->entry.bits.num_ptr = ngathers;
	sop_descp->entry.bits.tr_len = TX_PKT_HEADER_SIZE+si->tcpip_hdr_len;
	sop_descp->entry.bits.sad = si->hdr_array.dma_addr+frame*HDR_TEMPLATE_SIZE;
	pkt_hdr = (tx_pkt_header_t *)hdrp;
	pkt_hdr->bits.tot_xfer_len = len + sop_descp->entry.bits.tr_len;
	si->desc_idx += ngathers;
	HXGE_DBG(hxgep, "Frame %d : %d len, %d descriptors required",frame,len,ngathers);
	return 0;
}

static int setup_dma_mapping(struct hxge_adapter *hxgep, 
		struct sk_buff *skb, struct staging_info_t *si)
{
	/* setup the buffer in the main skb structure */
	int num_mappings = skb_shinfo(skb)->nr_frags;
	skb_frag_t *fragp;
	struct dma_map_t *dma_map;
	struct skb_hdr_info_t *skb_hdr = (struct skb_hdr_info_t *)skb->cb;
	int i = 0; /* at least one mapping */
	int main_buf_len;

	/* allocate for the main buffer + the fragments */
	main_buf_len = skb_headlen(skb) - si->tcpip_hdr_len;
	if (main_buf_len)
		num_mappings++;

	dma_map = kmalloc(num_mappings*sizeof(struct dma_map_t), GFP_KERNEL);
	if (!dma_map) {
		HXGE_ERR(hxgep, "failed to alloc dma_map");
		return MAP_DESC_FAILED;
	}

	/* First map the main buffer in skb; odd one out */
	if (main_buf_len) {
		char *data = skb->data+si->tcpip_hdr_len;
		dma_map[i].len = main_buf_len;
		dma_map[i].vaddr = data;
		dma_map[i].dma_addr = pci_map_page(hxgep->pdev, 
					virt_to_page(data),
					offset_in_page(data),
					dma_map[0].len, 
					PCI_DMA_TODEVICE);
		++i;
	}

	for (fragp = &skb_shinfo(skb)->frags[0]; i < num_mappings; 
							i++, fragp++) {
		char *data = page_address(fragp->page);
		dma_map[i].len = fragp->size;
		dma_map[i].vaddr = data + fragp->page_offset;
        	dma_map[i].dma_addr  = pci_map_page(hxgep->pdev, 
					virt_to_page(data), fragp->page_offset, 
					fragp->size, PCI_DMA_TODEVICE);
	}
	si->pci_map.num_dma_mappings = i;
	si->pci_map.dma_map = dma_map;
	skb_hdr->pci_map = si->pci_map;
	return 0;
}


static int hxge_tx_gso(struct sk_buff *skb, struct net_device *netdev)
{
	struct hxge_adapter *hxgep = netdev_priv(netdev);
	int desc_required = 0;
	struct staging_info_t *si;
	int i, state;
	struct tx_ring_t *tx_ring;
	struct staging_desc_t *desc;
	struct tx_buf_t *tx_buf;
	int tot_len, len;

	si = setup_staging_info(hxgep, skb);
	if (!si)
	{
		HXGE_ERR(hxgep, "setup_staging_info failed");
                dev_kfree_skb_any(skb);
                return (NETDEV_TX_OK);
	}

	if (setup_dma_mapping(hxgep, skb, si)) {
		HXGE_ERR(hxgep, "setup_dma_mapping failed");
		free_staging_info(hxgep, si, 1);
		dev_kfree_skb_any(skb);
		return (NETDEV_TX_OK);
	}

	tot_len = skb->len - si->tcpip_hdr_len;
	for (i = 0, len = min(tot_len,si->frame_size); i < si->max_frames;
				i++, len = min(tot_len, si->frame_size)) {
		if (setup_frame(hxgep, si, len, i)) {
				HXGE_ERR(hxgep, "setup_frame for main buffer failed");
				free_staging_info(hxgep, si, 1);
				dev_kfree_skb_any(skb);
				return (NETDEV_TX_OK);
		}
		tot_len -= len;
	}

	/* Pass in known desc_required. Success implies we have the channel
         * lock 
	 */
	desc_required = si->desc_idx;

	if (desc_required > (DESCS_PER_FRAME*si->max_frames)) {
		HXGE_ERR(hxgep,"BUG: Not enough space allocated for temporary descrpitors; only have %d, should have %d!",4*si->max_frames,desc_required);
		BUG();
	}

	tx_ring = get_channel_to_transmit(hxgep, skb, &state, &desc_required);
	if (!tx_ring) {
                if (state == NETDEV_TX_BUSY) {
			if (!netif_queue_stopped(netdev))
	                        netif_stop_queue(netdev);
		}
		free_staging_info(hxgep,si,1);
		return (state);
	}
	
	TXDMA_GET_CURR_INDEX(tx_ring);
	desc = si->desc;
	tx_buf = &tx_ring->tx_buf[tx_ring->curr_index];
	for (i = 0; i < desc_required; i++, desc++) {
        	tx_desc_t *real_desc;
		tx_buf = &tx_ring->tx_buf[tx_ring->curr_index];
		real_desc = &tx_ring->desc_ring.vaddr[tx_ring->curr_index];
		tx_buf->flags = TX_FLAGS_DATA;
		tx_buf->map.dma_addr = desc->addr;
		tx_buf->map.len = desc->len;
		tx_buf->skb = NULL;
		HXGE_MEM_PIO_WRITE64(real_desc, desc->entry.value);
		TXDMA_GET_NEXT_INDEX(tx_ring, 1);
	}

	/* We assume there is at least one descriptor. Make sure that 
	 * last tx_buf has all the requisite pointers for the reclaim thread 
	 * to be able to free the mapped header  array. It *has* to be the 
	 * last Tx descriptor to ensure that all descriptors relevant to 
	 * this skb have been sent out by the HW. No need to set the 
	 * TX_FLAGS_UNMAP; the reclaim thread knows that if the skb is
	 * valid and gso is enabled, this is the last descriptor and 
	 * consequently, there must be a header array to be unmapped and
	 * freed. Setting the unmap flag will confuse the non-gso code in
	 * reclaim_tx_thread and cause problems.
	 */
	tx_buf->skb = skb;
	skb_orphan(skb);
#ifdef CONFIG_ERRINJECT
	atomic_inc(&skb_count);
#endif

	/* Update the descriptors available for use. Note that update to this
           variable races with the reclaim thread, hence an atomic operation */
	atomic_sub(desc_required, &tx_ring->descs_avail);

	if (atomic_read(&tx_ring->descs_avail) < 0) {
	    HXGE_ERR(hxgep, "Descriptors available less than zero!!");	
	}
	/* Update descriptors available. Write the SOP descriptor entry and 
           kick the number of new entries added */
	TXDMA_UPDATE_INDEX(tx_ring);
	hpi_txdma_desc_kick_reg_set(hxgep->hw.hw_addr, tx_ring->tdc, 
				tx_ring->tail, tx_ring->wrap);

	/* Successfully queued one network packet of <skb_len> bytes */

	tx_ring->stats.opackets += si->max_frames;
	tx_ring->stats.obytes += skb->len;
	spin_unlock(&tx_ring->lock);

	free_staging_info(hxgep, si, 0);
	return NETDEV_TX_OK;
}


int hxge_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	int status;
	if (SKB_IS_GSO(skb)) {
		status = hxge_tx_gso(skb, netdev);
	} else 
		status = hxge_tx_ring(skb, netdev);

	return status;
}

static void update_tx_err_stats(hpi_handle_t handle, struct tx_ring_t *tx_ring)
{
	struct tx_ring_stats_t *stats = &tx_ring->stats;
	tdc_drop_cnt_t drop_cnt;

	TXDMA_REG_READ64(handle, TDC_DROP_CNT, tx_ring->tdc, &drop_cnt.value);

	stats->hdr_error_cnt += drop_cnt.bits.hdr_size_error_count;
	stats->abort_cnt += drop_cnt.bits.abort_count;
	stats->runt_cnt += drop_cnt.bits.runt_count;

	stats->oerrors += drop_cnt.bits.hdr_size_error_count
		+ drop_cnt.bits.abort_count
		+ drop_cnt.bits.runt_count;

}

static tdc_stat_t process_tx_status(struct hxge_ldv *ldvp, int ldf0, int ldf1)
{
	struct hxge_adapter *hxgep = ldvp->ldgp->hxgep;
	hpi_handle_t	handle = hxgep->hw.hw_addr;
	tdc_stat_t cs;
	int channel = ldvp->ldv-HXGE_TDMA_LD_START;
	struct tx_ring_t *tx_ring = &hxgep->tx_ring[channel];
	struct tx_ring_stats_t *stats = &tx_ring->stats;
	tdc_tdr_head_t head_reg;


	/* If an LDF1 error, then wait till the qst bit is asserted before
	 * reading the TdcStat register. Otherwise, all the error information 
	 * for that channel may not have been updated yet
	 */
	if (ldf1)
		hpi_txdma_control_reset_wait(handle, channel);

	if (hpi_txdma_control_status(handle, OP_GET, channel, &cs)
		!= HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hpi_txdma_control_status failed");
	}


	if (cs.bits.marked) {
		stats->marked++;
		HXGE_DBG(hxgep, "Sent marked packet - kick reclaim thread");
		wake_up_interruptible(&tx_ring->reclaim_event);
	}

	if (ldf1) {
		HXGE_ERR(hxgep, "LDF1 on channel %d, cs 0x%llx",channel,cs.value);

		if (cs.bits.peu_resp_err) {
			HXGE_ERR(hxgep, "peu_resp_error");
			stats->peu_resp_err++;
			stats->oerrors++;
		}

		if (cs.bits.pkt_size_hdr_err) {
			HXGE_ERR(hxgep, "pkt_size_hdr_err");
			stats->pkt_size_hdr_err++;
			stats->oerrors++;
		}

		if (cs.bits.runt_pkt_drop_err) {
			HXGE_ERR(hxgep, "runt_pkt_drop_err");
			stats->runt_pkt_drop_err++;
			stats->oerrors++;
		}

		if (cs.bits.pkt_size_err) {
			HXGE_ERR(hxgep, "pkt_size_err");
			stats->pkt_size_err++;
			stats->oerrors++;
		}

		if (cs.bits.tx_rng_oflow) {
			HXGE_ERR(hxgep, "tx_rng_oflow");
			stats->tx_rng_oflow++;
			stats->oerrors++;
		        if (hpi_txdma_ring_head_get(handle, channel, 
				&head_reg) != HPI_SUCCESS)
        		{
                		HXGE_ERR(hxgep, "hpi_txdma_ring_head_get_failed for channel %d",tx_ring->tdc);
        		}
			HXGE_ERR(hxgep, "head: 0x%x, tail : 0x%x, hwrap: %d, twrap: %d",head_reg.bits.head, tx_ring->tail, tx_ring->wrap, head_reg.bits.wrap);
			if (!((head_reg.bits.head == tx_ring->tail) && (
				tx_ring->wrap != head_reg.bits.wrap))) {
				HXGE_ERR(hxgep, "False overflow!");
			}
		}
			
		if (cs.bits.pref_par_err) {
			HXGE_ERR(hxgep, "pref_par_err");
			stats->pref_par_err++;
			stats->oerrors++;
		}

		if (cs.bits.tdr_pref_cpl_to) {
			HXGE_ERR(hxgep, "tdr_pref_cpl_to");
			stats->tdr_pref_cpl_to++;
			stats->oerrors++;
		}

		if (cs.bits.pkt_cpl_to) {
			HXGE_ERR(hxgep, "pkt_cpl_to");
			stats->pkt_cpl_to++;
			stats->oerrors++;
		}

		if (cs.bits.invalid_sop) {
			HXGE_ERR(hxgep, "invalid_sop");
			stats->invalid_sop++;
			stats->oerrors++;
		}

		if (cs.bits.unexpected_sop) {
			HXGE_ERR(hxgep, "unexpected_sop");
			stats->unexpected_sop++;
			stats->oerrors++;
		}

		/* Update discarded-packets counts from Hydra's counters */
		update_tx_err_stats(handle, tx_ring);
	
	}

	/* Clear out the bits that require W1C */
	hpi_txdma_control_status(handle, OP_SET, channel, &cs);

	/* Do a reset of the channel (on call side) */
	if (ldf1) {
        	set_bit(RESET_TX_CHANNEL_0+channel, &hxgep->work_q.command);
        	schedule_work(&hxgep->work_to_do);
	}

	return cs;
}

/* Transmit interrupt handler. The fact that we get here imples that this is
 * a LDG with just one LDV. Otherwise, we would end up in hxge_intr. 
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
irqreturn_t hxge_tx_intr(int irq, void *data, struct pt_regs *regs)
#else
irqreturn_t hxge_tx_intr(int irq, void *data)
#endif
{
	struct hxge_ldv *ldvp = (struct hxge_ldv *)data;
	int got_ldf0, got_ldf1;
	

	/* Determine if we have a LDF0 or LDF1 */
	get_ldf_flags(ldvp, &got_ldf0, &got_ldf1);
	
	/* Neither one. So, probably a shared interrupt? Return but don't 
 	   dimiss the interrupt but let another handler have a shot at it */
	if (!got_ldf0 && !got_ldf1)
		return IRQ_NONE;
	
	/* If LDF0, then this is probably an  interrupt  indicating a 
  	   transmit completed ("marked" bit was set and triggered an 
  	   interrupt */
	process_tx_status(ldvp, got_ldf0, got_ldf1);

	return (IRQ_HANDLED);

}


/* Transmit error interrupt handler
 *
 * Called from Device Error Interrupt (ldv 31) service, not TX DMA
 *
 * NB: *data is Device Error ldv 31, not a TX DMA channel ldv!
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
irqreturn_t hxge_tx_deverr_intr(int irq, void *data, struct pt_regs *regs)
#else
irqreturn_t hxge_tx_deverr_intr(int irq, void *data)
#endif
{
	struct hxge_ldv *ldvp = (struct hxge_ldv *)data; /* Device Error ldv */
	struct hxge_adapter *hxgep = ldvp->ldgp->hxgep;
	hpi_handle_t	handle = hxgep->hw.hw_addr;
	tdc_fifo_err_stat_t sts, clr;
	int hard_error = 0;

	if (hpi_tx_fifo_status(handle, OP_GET, &sts) 
		!= HPI_SUCCESS) {
		HXGE_ERR(hxgep, "hpi_tx_fifo_status failed");
	}

	HXGE_ERR(hxgep, "TX hardware error interrupt (0x%16.16x)!",
		 (unsigned int)sts.value);

	clr.value = sts.value;

	if (sts.bits.reord_buf_sec_err) {
		HXGE_ERR(hxgep, "reord_buf_sec_err");
		hxgep->statsp->tx_reorder_sec++;
		hxgep->statsp->soft_errors++; /* Soft (recovered) dev error */
		clr.bits.reord_buf_sec_err = 0;
	}

	if (sts.bits.reord_buf_ded_err) {
		HXGE_ERR(hxgep, "reord_buf_ded_err");
		hxgep->statsp->tx_reorder_ded++;
		hxgep->statsp->tx_oerrors++; /* Tx summary count */
		hxgep->statsp->hard_errors++; /* Hard device error */
		hard_error = TRUE;
		clr.bits.reord_buf_ded_err = 0;
	}

	if (sts.bits.reord_tbl_par_err) {
		HXGE_ERR(hxgep, "reord_tbl_par_err");
		hxgep->statsp->tx_rtab_parerr++;
		hxgep->statsp->tx_oerrors++; /* Tx summary count */
		hxgep->statsp->hard_errors++; /* Hard device error */
		hard_error = TRUE;
		clr.bits.reord_tbl_par_err = 0;
	}

	if (clr.value) {
		HXGE_ERR(hxgep, "Unknown/unexpected/reserved TDC_FIFO_ERR_STAT bits 0x%16.16x", (unsigned int)clr.value);
		hxgep->statsp->hard_errors++; /* Hard device error */
		hard_error = TRUE; /* Unknown, hope TDC reset nails it */
	}

	/* Now that we have "logged" the errors, try to recover from
	 * whatever happened.  Note that "SEC" (Single Bit ECC) is
	 * recovered by hardware, and needs no further action here.
	 */

	/* Acknowledge error status, resume processing */

	hpi_tx_fifo_status(handle, OP_SET, &sts);

	/* We're probably going to hang now... */

	if (hxge_ok_to_continue(hxgep)) {
		if (hard_error) {
			/* Hard error, data corrupt, need TDC reset */
			hxge_disable_tx_ints(hxgep);
			set_bit(RESET_TDC, &hxgep->work_q.command);
			schedule_work(&hxgep->work_to_do);
		} /* Else Corrected (single-bit) error, OK to resume */
	} else {
		HXGE_ERR(hxgep, "Excessive hardware error rate");
		HXGE_ERR(hxgep, "                      Taking hxge device down");
		hxge_disable_interrupts(hxgep);
		set_bit(SHUTDOWN_ADAPTER, &hxgep->work_q.command);
		schedule_work(&hxgep->work_to_do);
	}

	return (IRQ_HANDLED);
}
