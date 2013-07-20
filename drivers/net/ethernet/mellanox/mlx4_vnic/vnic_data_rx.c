/*
 * Copyright (c) 2009 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "vnic.h"
#include "vnic_data.h"

static inline void free_single_frag(struct vnic_rx_ring *ring, int e,int i)
{
		ib_dma_unmap_single(ring->port->dev->ca,
			ring->rx_info[e].dma_addr[i],
			ring->frag_info[i].frag_size,
			PCI_DMA_FROMDEVICE);
		ring->rx_info[e].dma_addr[i] = 0;
		put_page(ring->rx_info[e].frags[i].page.p);
}

#ifndef _BP_NETDEV_NO_TMQ
/* this functions used only in no_bxm mode,
 * it's not implemented in netdevice.h so we have it here
 * based on netif_tx_lock()
 */
static inline int vnic_netif_tx_trylock(struct net_device *dev)
{
	int i, cpu;

	spin_lock(&dev->tx_global_lock);
	cpu = smp_processor_id();
	for (i = 0; i < dev->num_tx_queues; ++i) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		if (__netif_tx_trylock(txq)) {
			set_bit(__QUEUE_STATE_FROZEN, &txq->state);
			__netif_tx_unlock(txq);
		} else {
			goto unlock;
		}
	}

	return 1;

unlock:
	/* based on netif_tx_unlock() */
	for (--i; i >= 0; --i) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);
		clear_bit(__QUEUE_STATE_FROZEN, &txq->state);
		if (!test_bit(QUEUE_STATE_ANY_XOFF, &txq->state))
			__netif_schedule(txq->qdisc);
	}
	spin_unlock(&dev->tx_global_lock);

	return 0;
}
#else
#define vnic_netif_tx_trylock(dev) netif_tx_trylock(dev)
#endif

int vnic_rx(struct vnic_login *login, struct sk_buff *skb, struct ib_wc *wc)
{
	ASSERT(skb);
	vnic_dbg_skb("RX", skb, (unsigned long)-1, (unsigned long)0);

	if (no_bxm) {
		/* In no_bxm mode, we update neigh table based on ARP reqlies
		 * QPN & LID are retrieved from the IB completion
		 * ATTENTION: on RSS mode, make sure that ARPs are
		 * sent on base QPN
		 */
		struct vnic_neigh *neighe;
		struct ethhdr *eth_hdr = (struct ethhdr *)skb->data;
		struct arphdr *arp_hdr = (struct arphdr *)(skb->data + ETH_HLEN);
		u16 eth_proto = ntohs(eth_hdr->h_proto);
		u16 arp_proto = ntohs(arp_hdr->ar_op);

		if (eth_proto != ETH_P_ARP)
			goto out;
		if (arp_proto == ARPOP_REQUEST)
			vnic_dbg_data(login->name, "ARP REQUEST\n");
		else
			vnic_dbg_data(login->name, "ARP REPLY\n");

		/* don't stop TX queue, only try, this way we avoid blocking 
		 * IRQs in TX flow (performance wise).
		 * other vnic_neighe_* functions are not called in parallel 
		 * to this flow (in no_bxm mode)
		 */
		if (!vnic_netif_tx_trylock(login->dev))
			goto out;

		neighe = vnic_neighe_search(login, eth_hdr->h_source);
		if (!IS_ERR(neighe)) {
			/* if IB address didn't change, do nothing */
			if (neighe->qpn == wc->src_qp &&
			    neighe->lid == wc->slid)
				goto unlock;
			/* else, del old neigh entry, and add a new one */
			vnic_neighe_del(login, neighe);
			vnic_neighe_dealloc(neighe);
		}

		/* RSS: assume that your neighbours are like you */
		neighe = vnic_neighe_alloc(login, eth_hdr->h_source,
					   wc->slid, wc->src_qp,
					   login->rx_rings_num > 1 ? 1 : 0);
		if (IS_ERR(neighe))
			goto unlock;
		if (vnic_neighe_add(login, neighe))
			vnic_neighe_dealloc(neighe);
unlock:
		netif_tx_unlock(login->dev);
	}
out:

	/* shared_vnic may receive PACKET_OTHERHOST
	 * we 'fix' the pkt_type here so the kernel
	 * won't drop it
	 */
	if (skb->pkt_type == PACKET_OTHERHOST && login->shared_vnic)
		skb->pkt_type = PACKET_HOST;

	netif_receive_skb(skb);

	return 0;

}

struct sk_buff *vnic_alloc_rx_skb(struct vnic_rx_ring *ring, int buf_ind,
				  gfp_t gfp_flag)
{
	struct ib_device *ca = ring->port->dev->ca;
	struct sk_buff *skb;
	u64 mapping;
	int buf_size = VNIC_BUF_SIZE(ring->port);

	skb = alloc_skb(buf_size, gfp_flag);
	if (!skb) {
		vnic_dbg_data(ring->port->name,
			      "alloc_skb for size %d failed\n", buf_size);
		goto err_alloc;
	}

	mapping = ib_dma_map_single(ca, skb->data, buf_size, DMA_FROM_DEVICE);
	if (unlikely(ib_dma_mapping_error(ca, mapping))) {
		vnic_dbg_data(ring->port->name,
			      "ib_dma_map_single len %d failed\n", buf_size);
		goto err_map;
	}

	ring->rx_info[buf_ind].skb = skb;
	ring->rx_info[buf_ind].dma_addr[0] = mapping;

	return skb;

err_map:
	dev_kfree_skb_any(skb);
err_alloc:
	return NULL;
}

static int frag_sizes[] = {
	FRAG_SZ0,
	FRAG_SZ1,
	FRAG_SZ2,
	FRAG_SZ3
};

/* Calculate the last offset position that accomodates a full fragment
 * (assuming fagment size = stride-align)
 */
static int vnic_last_alloc_offset(struct vnic_rx_ring *ring, u16 stride, u16 align)
{
	u16 res = VNIC_ALLOC_SIZE % stride;
	u16 offset = VNIC_ALLOC_SIZE - stride - res + align;

	vnic_dbg_data(ring->port->name, "calculated last offset for stride:%d align:%d "
		      "res:%d offset:%d\n", stride, align, res, offset);
	return offset;
}

static int vnic_init_allocator(struct vnic_rx_ring *ring)
{
	struct vnic_rx_alloc *page_alloc;
	int i;

	if (vnic_rx_linear)
		return 0;

	for (i = 0; i < ring->num_frags; i++) {
		page_alloc = &ring->page_alloc[i];
		page_alloc->page = alloc_pages(GFP_ATOMIC | __GFP_COMP, VNIC_ALLOC_ORDER);
		if (!page_alloc->page)
			goto out;

		page_alloc->offset = ring->frag_info[i].frag_align;
		vnic_dbg_data(ring->port->name, "Initialized allocator:%d with page:%p\n",
			      i, page_alloc->page);
	}
	return 0;

out:
	while (i--) {
		page_alloc = &ring->page_alloc[i];
		if (page_alloc->page) {
			put_page(page_alloc->page);
			page_alloc->page = NULL;
		}
	}
	return -ENOMEM;
}

static void vnic_destroy_allocator(struct vnic_rx_ring *ring)
{
	struct vnic_rx_alloc *page_alloc;
	int i;

	if (vnic_rx_linear)
		return;

	for (i = 0; i < ring->num_frags; i++) {
		page_alloc = &ring->page_alloc[i];
		vnic_dbg_data(ring->port->name, "Freeing allocator:%d count:%d\n",
			      i, page_count(page_alloc->page));
		if (page_alloc->page) {
			put_page(page_alloc->page);
			page_alloc->page = NULL;
		}
	}
}

/*
 * allocate a single fragment on a single ring entry and map it
 * to HW address.
 */
static int vnic_alloc_frag(struct vnic_rx_ring *ring,
			   struct vnic_frag_data *frags_data, int i)
{
	struct vnic_frag_info *frag_info = &ring->frag_info[i];
	struct vnic_rx_alloc *page_alloc = &ring->page_alloc[i];
	struct skb_frag_struct *skb_frags = &frags_data->frags[i];
	struct skb_frag_struct skbf = *skb_frags;
	struct page *page;	
	struct ib_device *ib_device = ring->port->dev->ca;
	u64 dma;
	int decision;

	if (vnic_rx_linear)
		return 0;

	if (page_alloc->offset >= frag_info->last_offset) {
		decision = 0;
		/* Allocate new page */
		page = alloc_pages(GFP_ATOMIC | __GFP_COMP, VNIC_ALLOC_ORDER);
		if (!page) {
			/*frags_data->dma_addr[i] = NULL;
			   ring->rx_info[wr_id].info = VNIC_FRAG_ALLOC_FAIL;
			   ring->need_refill = 1; */
			return -ENOMEM;
		}
		skbf.page.p = page_alloc->page;
		skbf.page_offset = page_alloc->offset;
	} else {
		decision = 1;
		page = page_alloc->page;
		get_page(page);
		skbf.page.p = page;
		skbf.page_offset = page_alloc->offset;
	}

	skbf.size = frag_info->frag_size;
	dma = ib_dma_map_single(ib_device, page_address(skbf.page.p) +
			     skbf.page_offset, frag_info->frag_size,
			     PCI_DMA_FROMDEVICE);
	if (unlikely(ib_dma_mapping_error(ib_device, dma))) {
		vnic_dbg_data(ring->port->name,
			      "ib_dma_map_single len %d failed\n",
			      frag_info->frag_size);
		put_page(page);
		return -ENOMEM;
	}

	if (!decision) {
		page_alloc->page = page;
		page_alloc->offset = frag_info->frag_align;
	} else
		page_alloc->offset += frag_info->frag_stride;

	*skb_frags = skbf;
	frags_data->dma_addr[i] = dma;

	return 0;
}

void vnic_calc_rx_buf(struct vnic_rx_ring *ring)
{
	int eff_mtu = VNIC_BUF_SIZE(ring->port), buf_size = 0, i = 0;

	if (vnic_rx_linear) {
		ring->num_frags = 1;
		return;
	}

	while (buf_size < eff_mtu) {
		ring->frag_info[i].frag_size =
			(eff_mtu > buf_size + frag_sizes[i]) ?
				frag_sizes[i] : eff_mtu - buf_size;
		ring->frag_info[i].frag_prefix_size = buf_size;
		if (!i)	{
			ring->frag_info[i].frag_align = NET_IP_ALIGN;
			ring->frag_info[i].frag_stride =
				ALIGN(frag_sizes[i] + NET_IP_ALIGN, SMP_CACHE_BYTES);
		} else {
			ring->frag_info[i].frag_align = 0;
			ring->frag_info[i].frag_stride =
				ALIGN(frag_sizes[i], SMP_CACHE_BYTES);
		}
		ring->frag_info[i].last_offset =
			vnic_last_alloc_offset(ring,
					       ring->frag_info[i].frag_stride,
					       ring->frag_info[i].frag_align);
		buf_size += ring->frag_info[i].frag_size;
		i++;
	}

	ring->num_frags = i;
	ring->rx_skb_size = eff_mtu;
	ring->log_rx_info = ROUNDUP_LOG2(i * sizeof(struct skb_frag_struct));

	vnic_dbg(ring->port->name, "Rx buffer scatter-list (ring %d effective-mtu:%d "
		  "num_frags:%d):\n", ring->index ,eff_mtu, ring->num_frags);
	for (i = 0; i < ring->num_frags; i++) {
		vnic_dbg(ring->port->name, "frag:%d - size:%d prefix:%d align:%d "
			 "stride:%d last_offset:%d\n", i,
			 ring->frag_info[i].frag_size,
			 ring->frag_info[i].frag_prefix_size,
			 ring->frag_info[i].frag_align,
			 ring->frag_info[i].frag_stride,
			 ring->frag_info[i].last_offset);
	}
}

static void vnic_empty_rx_entry(struct vnic_rx_ring *ring, int i)
{
	int frag_num, buf_size = VNIC_BUF_SIZE(ring->port);
	struct ib_device *ca = ring->port->dev->ca;
	struct sk_buff *skb;
	u64 mapping;

	if (vnic_rx_linear) {
		for (frag_num = 0; frag_num < ring->num_frags; frag_num++) {
			mapping = ring->rx_info[i].dma_addr[0];
			skb = ring->rx_info[i].skb;
			if (mapping)
				ib_dma_unmap_single(ca, mapping, buf_size, DMA_FROM_DEVICE);
			if (skb)
				dev_kfree_skb_any(skb);
		}

		return;
	}

	/* non linear buffers */
	for (frag_num = 0; frag_num < ring->num_frags; frag_num++)
		free_single_frag(ring, i, frag_num);
}

static int vnic_fill_rx_buffer(struct vnic_rx_ring *ring)
{
	struct vnic_frag_data *frags_data = &ring->rx_info[0];
	struct sk_buff *skb;
	struct ib_device *ca = ring->port->dev->ca;
	int buf_ind, frag_num, buf_size = VNIC_BUF_SIZE(ring->port);
	u64 mapping;

	if (vnic_rx_linear) {
		for (buf_ind = 0; buf_ind < ring->size; buf_ind++) {
			skb = vnic_alloc_rx_skb(ring, buf_ind, GFP_KERNEL);
			if (!skb)
				goto err_linear;
		}

		return 0;
	}

	/* non linear buffers */
	for (buf_ind = 0; buf_ind < ring->size; buf_ind++, frags_data++) {
		for (frag_num = 0; frag_num < ring->num_frags; frag_num++) {
			if (vnic_alloc_frag(ring, frags_data, frag_num))
				goto err_frags;
		}
	}

	return 0;

err_linear:
	for (buf_ind = 0; buf_ind < ring->size; buf_ind++) {
		mapping = ring->rx_info[buf_ind].dma_addr[0];
		skb = ring->rx_info[buf_ind].skb;
		if (mapping)
			ib_dma_unmap_single(ca, mapping, buf_size, DMA_FROM_DEVICE);
		if (skb)
			dev_kfree_skb_any(skb);
	}

	return -ENOMEM;

err_frags:
	for (--frag_num; frag_num >= 0; frag_num--)
		free_single_frag(ring, buf_ind, frag_num);

	for (--buf_ind; buf_ind >= 0; buf_ind--)
		vnic_empty_rx_entry(ring, buf_ind);

	return -ENOMEM;
}

/*
 * free entire ring full of fragments.
*/
static void vnic_empty_rx_buffer(struct vnic_rx_ring *ring)
{
	int buf_ind;

	for (buf_ind = 0; buf_ind < ring->size; buf_ind++)
		vnic_empty_rx_entry(ring, buf_ind);

	ring->size = 0;
}

void vnic_destroy_rx_ring(struct vnic_rx_ring *ring)
{
	if (!ring)
		return;
	vnic_empty_rx_buffer(ring);
	vnic_destroy_allocator(ring);
	vfree(ring->rx_info);
	vnic_ib_free_ring(ring);
	kfree(ring);
}

int vnic_unmap_and_replace_rx(struct vnic_rx_ring *ring, struct ib_device *dev,
			      struct skb_frag_struct *skb_frags_rx,
			      u64 wr_id, int length)
{
	struct vnic_frag_info *frag_info;
	struct vnic_frag_data *rx_info = &ring->rx_info[wr_id];

	int nr;
	dma_addr_t dma;

	/* Collect used fragments while replacing them in the HW descriptors */
	for (nr = 0; nr < ring->num_frags; nr++) {
		frag_info = &ring->frag_info[nr];
		if (length <= frag_info->frag_prefix_size)
			break;

		/* Save page reference in skb */
		skb_frags_rx[nr].page = rx_info->frags[nr].page;
		skb_frags_rx[nr].size = rx_info->frags[nr].size;
		skb_frags_rx[nr].page_offset = rx_info->frags[nr].page_offset;
		dma = rx_info->dma_addr[nr];

		/* Allocate a replacement page */
		if (vnic_alloc_frag(ring, rx_info, nr))
			goto fail;

		/* Unmap buffer */
		ib_dma_unmap_single(dev, dma, skb_frags_rx[nr].size,
				 PCI_DMA_FROMDEVICE);
	}

	/* Adjust size of last fragment to match actual length */
	if (nr > 0)
		skb_frags_rx[nr - 1].size = length -
			ring->frag_info[nr - 1].frag_prefix_size;
	return nr;

fail:
	/* Drop all accumulated fragments (which have already been replaced in
	 * the descriptor) of this packet; remaining fragments are reused... */
	while (nr > 0) {
		nr--;
		put_page(skb_frags_rx[nr].page.p);
	}

	return 0;
}

int vnic_rx_skb(struct vnic_login *login, struct vnic_rx_ring *ring,
		struct ib_wc *wc, int ip_summed, char *eth_hdr_va)
{
	u64 wr_id = (unsigned int)wc->wr_id;
	struct sk_buff *skb;
	int used_frags;
	char *va = eth_hdr_va;
	int length = wc->byte_len - VNIC_EOIB_HDR_SIZE - VNIC_VLAN_OFFSET(login),
	    linear_length = (length <= SMALL_PACKET_SIZE) ?
	    length : SMALL_PACKET_SIZE, hdr_len = min(length, HEADER_COPY_SIZE),
	    offest = NET_IP_ALIGN + 16;
	struct ib_device *ib_dev = login->port->dev->ca;

	/* alloc a small linear SKB */
	skb = alloc_skb(linear_length + offest, GFP_ATOMIC);
	if (unlikely(!skb))
		return -ENOMEM;

	skb_record_rx_queue(skb, ring->index);
	skb_reserve(skb, offest);

	if (vnic_linear_small_pkt && length <= SMALL_PACKET_SIZE) {
		u64 dma;

		/* We are copying all relevant data to the skb - temporarily
		 * synch buffers for the copy
		 */
		dma = ring->rx_info[wr_id].dma_addr[0] + VNIC_EOIB_HDR_SIZE +
			VNIC_VLAN_OFFSET(login);
		ib_dma_sync_single_for_cpu(ib_dev, dma, length,
					   DMA_FROM_DEVICE);
		skb_copy_to_linear_data(skb, va, length);
		ib_dma_sync_single_for_device(ib_dev, dma, length,
					      DMA_FROM_DEVICE);
		skb->tail += length;
	} else {
		/* unmap the needed fragmentand reallocate them. Fragments that
		 * were not used will not be reused as is. */
		used_frags = vnic_unmap_and_replace_rx(ring, ib_dev,
						       skb_shinfo(skb)->frags,
						       wr_id, wc->byte_len);
		if (!used_frags)
			goto free_and_repost;

		skb_shinfo(skb)->nr_frags = used_frags;

		/* Copy headers into the skb linear buffer */
		memcpy(skb->data, va, hdr_len);
		skb->tail += hdr_len;
		/* Skip headers in first fragment */
		skb_shinfo(skb)->frags[0].page_offset +=
		    (VNIC_EOIB_HDR_SIZE + VNIC_VLAN_OFFSET(login) +
		     hdr_len);

		/* Adjust size of first fragment */
		skb_shinfo(skb)->frags[0].size -=
		    (VNIC_EOIB_HDR_SIZE + VNIC_VLAN_OFFSET(login) +
		     hdr_len);
		skb->data_len = length - hdr_len;
	}

	/* update skb fields */
	skb->len = length;
	skb->truesize = length + sizeof(struct sk_buff);
	skb->ip_summed = ip_summed;
	skb->dev = login->dev;
	skb->protocol = eth_type_trans(skb, skb->dev);

	return vnic_rx(login, skb, wc);

free_and_repost:
	dev_kfree_skb(skb);
	return -ENODEV;

}

static void vnic_set_rx_sge(struct vnic_rx_ring *ring)
{
	int i;

	ring->wr.num_sge = ring->num_frags;
	ring->wr.next = NULL;
	ring->wr.sg_list = ring->sge;
	for (i = 0; i < ring->num_frags; ++i) {
		ring->sge[i].lkey = ring->port->mr->lkey;
		ring->sge[i].length = ring->frag_info[i].frag_size;
	}
}

struct vnic_rx_ring *vnic_create_rx_ring(struct vnic_port *port, int index)
{
	int rc, rx_info, size = vnic_rx_rings_len;
	struct vnic_rx_ring *ring;

	ring = kzalloc(sizeof *ring, GFP_KERNEL);
	if (!ring)
		return ERR_PTR(-ENOMEM);

	/* init attributes */
	ring->port = port;
	ring->size = size;
	ring->index = index;
	spin_lock_init(&ring->lock);

	/* init rx ring IB resources */
	if (vnic_ib_init_ring(ring)) {
		vnic_err(port->name, "vnic_ib_init_ring failed\n");
		goto free_ring;
	}

	rx_info = size * roundup_pow_of_two(sizeof(struct vnic_frag_data));
	ring->rx_info = vmalloc(rx_info);
	if (!ring->rx_info) {
		vnic_err(port->name, "Failed allocating rx_info ring"
			 " (%d bytes)\n", rx_info);
		goto free_ib;
	}
	memset(ring->rx_info, 0, rx_info);

	/* determine the sizes of the fragments as result of mtu */
	vnic_calc_rx_buf(ring);

	rc = vnic_init_allocator(ring);
	if (rc) {
		vnic_err(port->name, "Failed initializing ring"
			 " allocator %d\n", rc);
		goto free_rxinfo;
	}

	rc = vnic_fill_rx_buffer(ring);
	if (rc) {
		vnic_err(port->name, "vnic_fill_rx_buffer failed %d\n", rc);
		goto free_allocator;
	}

	/* set rx WQEs drafts */
	vnic_set_rx_sge(ring);

	/* Initailize all descriptors and post to srq */
	rc = vnic_post_recvs(ring);
	if (rc) {
		vnic_err(port->name, "vnic_post_recvs failed %d\n", rc);
		goto free_rx_buffer;
	}

	return ring;

free_rx_buffer:
	/* TODO: we are freeing posted packets need to move SRQ
	 * to error and free them first
	 */
	vnic_empty_rx_buffer(ring);
free_allocator:
	vnic_destroy_allocator(ring);
free_rxinfo:
	vfree(ring->rx_info);
free_ib:
	vnic_ib_free_ring(ring);
free_ring:
	kfree(ring);

	return ERR_PTR(-EINVAL);
}
