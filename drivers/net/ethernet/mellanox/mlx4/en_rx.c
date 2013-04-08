/*
 * Copyright (c) 2007 Mellanox Technologies. All rights reserved.
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
 *
 */

#include <linux/mlx4/cq.h>
#include <linux/slab.h>
#include <linux/mlx4/qp.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/vmalloc.h>
#include <linux/prefetch.h>
#include <linux/mlx4/driver.h>

#include "mlx4_en.h"

static void mlx4_en_init_rx_desc(struct mlx4_en_priv *priv,
				 struct mlx4_en_rx_ring *ring,
				 int index)
{
	struct mlx4_en_rx_desc *rx_desc = ring->buf + ring->stride * index;

	rx_desc->data->byte_count = cpu_to_be32(priv->rx_skb_size);
	rx_desc->data->lkey = cpu_to_be32(priv->mdev->mr.key);
}

static int mlx4_en_alloc_rx_skb(struct mlx4_en_priv *priv,
				struct mlx4_en_rx_desc *rx_desc,
				struct sk_buff **pskb, int unmap)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	dma_addr_t dma;
	int size = priv->rx_skb_size;
	struct sk_buff *new_skb = dev_alloc_skb(size + MLX4_EN_64_ALIGN);

	if (unlikely(new_skb == NULL))
		return -ENOMEM;

	if (unmap)
		pci_unmap_single(mdev->pdev, be64_to_cpu(rx_desc->data->addr),
				 be32_to_cpu(rx_desc->data->byte_count),
				 PCI_DMA_FROMDEVICE);
	new_skb->dev = priv->dev;
	skb_reserve(new_skb, MLX4_EN_64_ALIGN);
	dma = pci_map_single(priv->mdev->pdev, new_skb->data,
			     size, DMA_FROM_DEVICE);

	if (unlikely(pci_dma_mapping_error(mdev->pdev, dma))) {
		kfree_skb(new_skb);
		return -ENOMEM;
	}

	*pskb = new_skb;
	rx_desc->data->addr = cpu_to_be64(dma);
	return 0;
}

static int mlx4_en_prepare_rx_desc(struct mlx4_en_priv *priv,
				   struct mlx4_en_rx_ring *ring, int index)
{
	struct mlx4_en_rx_desc *rx_desc = ring->buf + (index * ring->stride);
	struct sk_buff **pskb = (struct sk_buff **)ring->rx_info + index;

	return mlx4_en_alloc_rx_skb(priv, rx_desc, pskb, 0);
}

static inline void mlx4_en_update_rx_prod_db(struct mlx4_en_rx_ring *ring)
{
	*ring->wqres.db.db = cpu_to_be32(ring->prod & 0xffff);
}

static void mlx4_en_free_rx_desc(struct mlx4_en_priv *priv,
				 struct mlx4_en_rx_ring *ring,
				 int index)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct sk_buff *skb;
	struct mlx4_en_rx_desc *rx_desc = ring->buf +
					  (index << ring->log_stride);
	dma_addr_t dma;

	skb = *((struct sk_buff **)ring->rx_info + index);
	dma = be64_to_cpu(rx_desc->data->addr);
	pci_unmap_single(mdev->pdev, dma,
			 priv->rx_skb_size + NET_IP_ALIGN,
			 PCI_DMA_FROMDEVICE);
	kfree_skb(skb);
}

static int mlx4_en_fill_rx_buffers(struct mlx4_en_priv *priv)
{
	struct mlx4_en_rx_ring *ring;
	int ring_ind;
	int buf_ind;
	int new_size;

	for (buf_ind = 0; buf_ind < priv->prof->rx_ring_size; buf_ind++) {
		for (ring_ind = 0; ring_ind < priv->rx_ring_num; ring_ind++) {
			ring = priv->rx_ring[ring_ind];

			if (mlx4_en_prepare_rx_desc(priv, ring,
						    ring->actual_size)) {
				if (ring->actual_size < MLX4_EN_MIN_RX_SIZE) {
					en_err(priv, "Failed to allocate enough rx buffers\n");
					return -ENOMEM;
				} else {
					new_size = rounddown_pow_of_two(ring->actual_size);
					en_warn(priv, "Only %d buffers allocated reducing ring size to %d\n",
						ring->actual_size, new_size);
					goto reduce_rings;
				}
			}
			ring->actual_size++;
			ring->prod++;
		}
	}
	return 0;

reduce_rings:
	for (ring_ind = 0; ring_ind < priv->rx_ring_num; ring_ind++) {
		ring = priv->rx_ring[ring_ind];
		while (ring->actual_size > new_size) {
			ring->actual_size--;
			ring->prod--;
			mlx4_en_free_rx_desc(priv, ring, ring->actual_size);
		}
	}
	return 0;
}

static void mlx4_en_free_rx_buf(struct mlx4_en_priv *priv,
				struct mlx4_en_rx_ring *ring)
{
	int index;

	en_dbg(DRV, priv, "Freeing Rx buf - cons:%d prod:%d\n",
	       ring->cons, ring->prod);

	/* Unmap and free Rx buffers */
	BUG_ON((u32) (ring->prod - ring->cons) > ring->actual_size);

	while (ring->cons != ring->prod) {
		index = ring->cons & ring->size_mask;
		en_dbg(DRV, priv, "Processing descriptor:%d\n", index);
		mlx4_en_free_rx_desc(priv, ring, index);
		++ring->cons;
	}
}

int mlx4_en_create_rx_ring(struct mlx4_en_priv *priv,
			   struct mlx4_en_rx_ring **pring,
			   u32 size, int node)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_en_rx_ring *ring;
	int err = -ENOMEM;
	int tmp;

	ring = kzalloc_node(sizeof(struct mlx4_en_rx_ring), GFP_KERNEL, node);
	if (!ring) {
		ring = kzalloc(sizeof(struct mlx4_en_rx_ring), GFP_KERNEL);
		if (!ring) {
			en_err(priv, "Failed to allocate RX ring structure\n");
			return -ENOMEM;
		}
	}
 
	ring->prod = 0;
	ring->cons = 0;
	ring->size = size;
	ring->size_mask = size - 1;
	ring->stride = priv->stride;
	ring->log_stride = ffs(ring->stride) - 1;
	ring->buf_size = ring->size * ring->stride + TXBB_SIZE;
	tmp = size * sizeof(struct sk_buff *);

	ring->rx_info = vmalloc_node(tmp, node);
	if (!ring->rx_info) {
		ring->rx_info = vmalloc(tmp);
		if (!ring->rx_info) {
			err = -ENOMEM;
			goto err_ring;
		}
	}

	en_dbg(DRV, priv, "Allocated rx_info ring at addr:%p size:%d\n",
		 ring->rx_info, tmp);

	/* Allocate HW buffers on provided NUMA node */
	set_dev_node(&mdev->dev->pdev->dev, node);
	err = mlx4_alloc_hwq_res(mdev->dev, &ring->wqres,
				 ring->buf_size, 2 * PAGE_SIZE);
	set_dev_node(&mdev->dev->pdev->dev, mdev->dev->numa_node);
	if (err)
		goto err_info;

	err = mlx4_en_map_buffer(&ring->wqres.buf);
	if (err) {
		en_err(priv, "Failed to map RX buffer\n");
		goto err_hwq;
	}
	ring->buf = ring->wqres.buf.direct.buf;

	ring->hwtstamp_rx_filter = priv->hwtstamp_config.rx_filter;

	*pring = ring;
	return 0;

err_hwq:
	mlx4_free_hwq_res(mdev->dev, &ring->wqres, ring->buf_size);
err_info:
	vfree(ring->rx_info);
err_ring:
	kfree(ring);

	return err;
}

int mlx4_en_activate_rx_rings(struct mlx4_en_priv *priv)
{
	struct mlx4_en_rx_ring *ring;
	int i;
	int ring_ind;
	int err;

	for (ring_ind = 0; ring_ind < priv->rx_ring_num; ring_ind++) {
		ring = priv->rx_ring[ring_ind];

		ring->prod = 0;
		ring->cons = 0;
		ring->actual_size = 0;
		ring->cqn = priv->rx_cq[ring_ind]->mcq.cqn;

		if (ring->stride <= TXBB_SIZE)
			ring->buf += TXBB_SIZE;

		ring->log_stride = ffs(ring->stride) - 1;
		ring->buf_size = ring->size * ring->stride;

		memset(ring->buf, 0, ring->buf_size);
		mlx4_en_update_rx_prod_db(ring);

		for (i = 0; i < ring->size; i++)
			mlx4_en_init_rx_desc(priv, ring, i);
	}
	err = mlx4_en_fill_rx_buffers(priv);
	if (err)
		goto err_buffers;

	for (ring_ind = 0; ring_ind < priv->rx_ring_num; ring_ind++) {
		ring = priv->rx_ring[ring_ind];

		ring->size_mask = ring->actual_size - 1;
		mlx4_en_update_rx_prod_db(ring);
	}

	return 0;

err_buffers:
	for (ring_ind = 0; ring_ind < priv->rx_ring_num; ring_ind++)
		mlx4_en_free_rx_buf(priv, priv->rx_ring[ring_ind]);

	ring_ind = priv->rx_ring_num - 1;

	while (ring_ind >= 0) {
		ring = priv->rx_ring[ring_ind];
		if (ring->stride <= TXBB_SIZE)
			ring->buf -= TXBB_SIZE;
		ring_ind--;
	}

	return err;
}

void mlx4_en_destroy_rx_ring(struct mlx4_en_priv *priv,
			     struct mlx4_en_rx_ring **pring,
			     u32 size, u16 stride)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_en_rx_ring *ring = *pring;

	mlx4_en_unmap_buffer(&ring->wqres.buf);
	mlx4_free_hwq_res(mdev->dev, &ring->wqres, size * stride + TXBB_SIZE);
	vfree(ring->rx_info);
	kfree(ring);
	*pring = NULL;
#ifdef CONFIG_RFS_ACCEL
	mlx4_en_cleanup_filters(priv, ring);
#endif
}

void mlx4_en_deactivate_rx_ring(struct mlx4_en_priv *priv,
				struct mlx4_en_rx_ring *ring)
{
	mlx4_en_free_rx_buf(priv, ring);
	if (ring->stride <= TXBB_SIZE)
		ring->buf -= TXBB_SIZE;
}

static inline int invalid_cqe(struct mlx4_en_priv *priv,
			      struct mlx4_cqe *cqe)
{
	/* Drop packet on bad receive or bad checksum */
	if (unlikely((cqe->owner_sr_opcode & MLX4_CQE_OPCODE_MASK) ==
		     MLX4_CQE_OPCODE_ERROR)) {
		en_err(priv, "CQE completed in error - vendor syndrom:%d syndrom:%d\n",
		       ((struct mlx4_err_cqe *)cqe)->vendor_err_syndrome,
		       ((struct mlx4_err_cqe *)cqe)->syndrome);
		return 1;
	}
	if (unlikely(cqe->badfcs_enc & MLX4_CQE_BAD_FCS)) {
		en_dbg(RX_ERR, priv, "Accepted frame with bad FCS\n");
		return 1;
	}

	return 0;
}

static struct sk_buff *mlx4_en_get_rx_skb(struct mlx4_en_priv *priv,
					 struct mlx4_en_rx_desc *rx_desc,
					 struct sk_buff **pskb,
					 unsigned int length)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct sk_buff *skb;
	dma_addr_t dma;

	if (length <= SMALL_PACKET_SIZE) {
		skb = dev_alloc_skb(length + MLX4_EN_64_ALIGN);
		if (unlikely(!skb))
			return NULL;

		skb->dev = priv->dev;
		skb_reserve(skb, MLX4_EN_64_ALIGN);
		/*
		 * We are copying all relevant data to the skb -
		 * temporarily synch buffers for the copy
		 */
		dma = be64_to_cpu(rx_desc->data->addr);
		dma_sync_single_range_for_cpu(&mdev->pdev->dev, dma, 0,
					      length, DMA_FROM_DEVICE);
		skb_copy_to_linear_data(skb, (*pskb)->data, length);
		dma_sync_single_range_for_device(&mdev->pdev->dev, dma, 0,
						 length, DMA_FROM_DEVICE);
	} else {
		skb = *pskb;
		if (unlikely(mlx4_en_alloc_rx_skb(priv, rx_desc, pskb, 1)))
			return NULL;
	}

	skb->tail += length;
	skb->len = length;
	skb->truesize = length + sizeof(struct sk_buff);
	return skb;
}

static void validate_loopback(struct mlx4_en_priv *priv, struct sk_buff *skb)
{
	int i;
	int offset = ETH_HLEN;

	for (i = 0; i < MLX4_LOOPBACK_TEST_PAYLOAD; i++, offset++) {
		if (*(skb->data + offset) != (unsigned char) (i & 0xff))
			goto out_loopback;
	}
	/* Loopback found */
	priv->loopback_ok = 1;

out_loopback:
	dev_kfree_skb_any(skb);
}

int mlx4_en_process_rx_cq(struct net_device *dev,
			  struct mlx4_en_cq *cq,
			  int budget)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_cqe *cqe;
	struct mlx4_cq *mcq = &cq->mcq;
	struct mlx4_en_rx_ring *ring = priv->rx_ring[cq->ring];
	struct mlx4_en_rx_desc *rx_desc;
	struct sk_buff **pskb;
	struct sk_buff *skb;
	int index;
	unsigned int length;
	int polled = 0;
	struct ethhdr *ethh;
	int factor = priv->cqe_factor;
	u32 cons_index = mcq->cons_index;
	u32 size_mask = ring->size_mask;
	int size = cq->size;
	struct mlx4_cqe *buf = cq->buf;
	u64 timestamp;

	if (!priv->port_up)
		return 0;

	/* We assume a 1:1 mapping between CQEs and Rx descriptors, so Rx
	 * descriptor offset can be deduced from the CQE index instead of
	 * reading 'cqe->index' */
	index = cons_index & size_mask;
	cqe = &buf[(index << factor) + factor];

	/* Process all completed CQEs */
	while (XNOR(cqe->owner_sr_opcode & MLX4_CQE_OWNER_MASK,
		    cons_index & size)) {

		pskb = (struct sk_buff **)ring->rx_info + index;
		rx_desc = ring->buf + (index << ring->log_stride);

		/*
		 * make sure we read the CQE after we read the ownership bit
		 */
		rmb();

		/* Drop packet on bad receive or bad checksum */
		if (unlikely(invalid_cqe(priv, cqe)))
			goto next;

		/* Packet is OK - process it */
		length = be32_to_cpu(cqe->byte_cnt);
		length -= ring->fcs_del;
		ring->bytes += length;
		ring->packets++;

		skb = mlx4_en_get_rx_skb(priv, rx_desc, pskb, length);
		if (unlikely(!skb)) {
			priv->stats.rx_dropped++;
			goto next;
		}

		if (unlikely(priv->validate_loopback)) {
			validate_loopback(priv, skb);
			goto next;
		}

		/*
		 * Before calling eth_hdr() should reset skb->mac_header
		 * to point to the address skb->data points.
		 * This is done by eth_type_trans().
		 */
		skb->protocol = eth_type_trans(skb, dev);
		ethh = eth_hdr(skb);

		/* Check if we need to drop the packet if SRIOV is not enabled
		 * and not performing the selftest or flb disabled
		 */
		if (priv->flags & MLX4_EN_FLAG_RX_FILTER_NEEDED &&
		    is_multicast_ether_addr(ethh->h_dest)) {
			struct mlx4_mac_entry *entry;
			struct hlist_node *n;
			struct hlist_head *bucket;
			unsigned int mac_hash;

			/* Drop the packet, since HW loopback-ed it */
			mac_hash = ethh->h_source[MLX4_EN_MAC_HASH_IDX];
			bucket = &priv->mac_hash[mac_hash];
			rcu_read_lock();
			hlist_for_each_entry_rcu(entry, n, bucket, hlist) {
				if (ether_addr_equal_64bits(entry->mac,
							    ethh->h_source)) {
					rcu_read_unlock();
					goto next;
				}
			}
			rcu_read_unlock();
		}
		/* avoid cache miss in tcp_gro_receive */
		prefetch((char *)ethh + 64);
		skb_record_rx_queue(skb, cq->ring);

		if (dev->features & NETIF_F_RXHASH)
			skb->rxhash = be32_to_cpu(cqe->immed_rss_invalid);

		if (likely((dev->features & NETIF_F_RXCSUM) &&
			   (cqe->status & cpu_to_be16(MLX4_CQE_STATUS_IPOK)) &&
			   (cqe->checksum == cpu_to_be16(0xffff)))) {
			ring->csum_ok++;
			skb->ip_summed = CHECKSUM_UNNECESSARY;
		} else {
			ring->csum_none++;
			skb->ip_summed = CHECKSUM_NONE;
		}

		if ((ring->hwtstamp_rx_filter == HWTSTAMP_FILTER_NONE) &&
		    (be32_to_cpu(cqe->vlan_my_qpn) &
		     MLX4_CQE_VLAN_PRESENT_MASK)) {
			__vlan_hwaccel_put_tag(skb, be16_to_cpu(cqe->sl_vid));
		} else if (ring->hwtstamp_rx_filter == HWTSTAMP_FILTER_ALL) {
			timestamp = mlx4_en_get_cqe_ts(cqe);
			mlx4_en_fill_hwtstamps(mdev, skb_hwtstamps(skb),
					       timestamp);
		}

		/* Push it up the stack */
		napi_gro_receive(&cq->napi, skb);

next:
		++cons_index;
		index = cons_index & size_mask;
		cqe = &buf[(index << factor) + factor];
		if (++polled == budget) {
			/* We are here because we reached the NAPI budget -
			 * flush only pending LRO sessions */
			goto out;
		}
	}

out:
	AVG_PERF_COUNTER(priv->pstats.rx_coal_avg, polled);
	mcq->cons_index = cons_index;
	mlx4_cq_set_ci(mcq);
	wmb(); /* ensure HW sees CQ consumer before we post new buffers */
	ring->cons = mcq->cons_index;
	ring->prod += polled;
	mlx4_en_update_rx_prod_db(ring);
	return polled;
}


void mlx4_en_rx_irq(struct mlx4_cq *mcq)
{
	struct mlx4_en_cq *cq = container_of(mcq, struct mlx4_en_cq, mcq);
	struct mlx4_en_priv *priv = netdev_priv(cq->dev);

	if (priv->port_up)
		napi_schedule(&cq->napi);
	else
		mlx4_en_arm_cq(priv, cq);
}

/* Rx CQ polling - called by NAPI */
int mlx4_en_poll_rx_cq(struct napi_struct *napi, int budget)
{
	struct mlx4_en_cq *cq = container_of(napi, struct mlx4_en_cq, napi);
	struct net_device *dev = cq->dev;
	struct mlx4_en_priv *priv = netdev_priv(dev);
	int done;

	done = mlx4_en_process_rx_cq(dev, cq, budget);

	/* If we used up all the quota - we're probably not done yet... */
	cq->tot_rx += done;
	if (done == budget) {
		INC_PERF_COUNTER(priv->pstats.napi_quota);
		if (cq->tot_rx >= MLX4_EN_MIN_RX_ARM) {
			napi_complete(napi);
			mlx4_en_arm_cq(priv, cq);
			cq->tot_rx = 0;
			return 0;
		}
	} else {
		/* Done for now */
		napi_complete(napi);
		mlx4_en_arm_cq(priv, cq);
		cq->tot_rx = 0;
		return done;
	}
	return budget;
}

/* RSS related functions */

static int mlx4_en_config_rss_qp(struct mlx4_en_priv *priv, int qpn,
				 struct mlx4_en_rx_ring *ring,
				 enum mlx4_qp_state *state,
				 struct mlx4_qp *qp)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_qp_context *context;
	int err = 0;
	int disable_vstrip = 0;

	if (priv->hwtstamp_config.rx_filter)
		disable_vstrip = 1;

	context = kmalloc(sizeof *context , GFP_KERNEL);
	if (!context) {
		en_err(priv, "Failed to allocate qp context\n");
		return -ENOMEM;
	}

	err = mlx4_qp_alloc(mdev->dev, qpn, qp);
	if (err) {
		en_err(priv, "Failed to allocate qp #%x\n", qpn);
		goto out;
	}
	qp->event = mlx4_en_sqp_event;

	memset(context, 0, sizeof *context);
	mlx4_en_fill_qp_context(priv, ring->actual_size, ring->stride, 0, 0,
				qpn, ring->cqn, -1, context, disable_vstrip);
	context->db_rec_addr = cpu_to_be64(ring->wqres.db.dma);

	/* Cancel FCS removal if FW allows */
	if (mdev->dev->caps.flags & MLX4_DEV_CAP_FLAG_FCS_KEEP) {
		context->param3 |= cpu_to_be32(1 << 29);
		ring->fcs_del = ETH_FCS_LEN;
	} else
		ring->fcs_del = 0;

	err = mlx4_qp_to_ready(mdev->dev, &ring->wqres.mtt, context, qp, state);
	if (err) {
		mlx4_qp_remove(mdev->dev, qp);
		mlx4_qp_free(mdev->dev, qp);
	}
	mlx4_en_update_rx_prod_db(ring);
out:
	kfree(context);
	return err;
}

int mlx4_en_create_drop_qp(struct mlx4_en_priv *priv)
{
	int err;
	u32 qpn;

	err = mlx4_qp_reserve_range(priv->mdev->dev, 1, 1, &qpn, 0);
	if (err) {
		en_err(priv, "Failed reserving drop qpn\n");
		return err;
	}
	err = mlx4_qp_alloc(priv->mdev->dev, qpn, &priv->drop_qp);
	if (err) {
		en_err(priv, "Failed allocating drop qp\n");
		mlx4_qp_release_range(priv->mdev->dev, qpn, 1);
		return err;
	}

	return 0;
}

void mlx4_en_destroy_drop_qp(struct mlx4_en_priv *priv)
{
	u32 qpn;

	qpn = priv->drop_qp.qpn;
	mlx4_qp_remove(priv->mdev->dev, &priv->drop_qp);
	mlx4_qp_free(priv->mdev->dev, &priv->drop_qp);
	mlx4_qp_release_range(priv->mdev->dev, qpn, 1);
}

/* Allocate rx qp's and configure them according to rss map */
int mlx4_en_config_rss_steer(struct mlx4_en_priv *priv)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_en_rss_map *rss_map = &priv->rss_map;
	struct mlx4_qp_context context;
	struct mlx4_rss_context *rss_context;
	int rss_rings;
	void *ptr;
	u8 rss_mask = (MLX4_RSS_IPV4 | MLX4_RSS_TCP_IPV4 | MLX4_RSS_IPV6 |
			MLX4_RSS_TCP_IPV6);
	int i;
	int err = 0;
	int good_qps = 0;
	static const u32 rsskey[10] = { 0xD181C62C, 0xF7F4DB5B, 0x1983A2FC,
				0x943E1ADB, 0xD9389E6B, 0xD1039C2C, 0xA74499AD,
				0x593D56D9, 0xF3253C06, 0x2ADC1FFC};

	en_dbg(DRV, priv, "Configuring rss steering\n");
	err = mlx4_qp_reserve_range(mdev->dev, priv->rx_ring_num,
				    priv->rx_ring_num,
				    &rss_map->base_qpn, 0);
	if (err) {
		en_err(priv, "Failed reserving %d qps\n", priv->rx_ring_num);
		return err;
	}

	for (i = 0; i < priv->rx_ring_num; i++) {
		priv->rx_ring[i]->qpn = rss_map->base_qpn + i;
		err = mlx4_en_config_rss_qp(priv, priv->rx_ring[i]->qpn,
					    priv->rx_ring[i],
					    &rss_map->state[i],
					    &rss_map->qps[i]);
		if (err)
			goto rss_err;

		++good_qps;
	}

	/* Configure RSS indirection qp */
	err = mlx4_qp_alloc(mdev->dev, priv->base_qpn, &rss_map->indir_qp);
	if (err) {
		en_err(priv, "Failed to allocate RSS indirection QP\n");
		goto rss_err;
	}
	rss_map->indir_qp.event = mlx4_en_sqp_event;
	mlx4_en_fill_qp_context(priv, 0, 0, 0, 1, priv->base_qpn,
				priv->rx_ring[0]->cqn, -1, &context, 0);

	if (!priv->prof->rss_rings || priv->prof->rss_rings > priv->rx_ring_num)
		rss_rings = priv->rx_ring_num;
	else
		rss_rings = priv->prof->rss_rings;

	ptr = ((void *) &context) + offsetof(struct mlx4_qp_context, pri_path)
					+ MLX4_RSS_OFFSET_IN_QPC_PRI_PATH;
	rss_context = ptr;
	rss_context->base_qpn = cpu_to_be32(ilog2(rss_rings) << 24 |
					    (rss_map->base_qpn));
	rss_context->default_qpn = cpu_to_be32(rss_map->base_qpn);
	if (priv->mdev->profile.udp_rss) {
		rss_mask |=  MLX4_RSS_UDP_IPV4 | MLX4_RSS_UDP_IPV6;
		rss_context->base_qpn_udp = rss_context->default_qpn;
	}
	rss_context->flags = rss_mask;
	rss_context->hash_fn = MLX4_RSS_HASH_TOP;
	for (i = 0; i < 10; i++)
		rss_context->rss_key[i] = cpu_to_be32(rsskey[i]);

	err = mlx4_qp_to_ready(mdev->dev, &priv->res.mtt, &context,
			       &rss_map->indir_qp, &rss_map->indir_state);
	if (err)
		goto indir_err;

	return 0;

indir_err:
	mlx4_qp_modify(mdev->dev, NULL, rss_map->indir_state,
		       MLX4_QP_STATE_RST, NULL, 0, 0, &rss_map->indir_qp);
	mlx4_qp_remove(mdev->dev, &rss_map->indir_qp);
	mlx4_qp_free(mdev->dev, &rss_map->indir_qp);
rss_err:
	for (i = 0; i < good_qps; i++) {
		mlx4_qp_modify(mdev->dev, NULL, rss_map->state[i],
			       MLX4_QP_STATE_RST, NULL, 0, 0, &rss_map->qps[i]);
		mlx4_qp_remove(mdev->dev, &rss_map->qps[i]);
		mlx4_qp_free(mdev->dev, &rss_map->qps[i]);
	}
	mlx4_qp_release_range(mdev->dev, rss_map->base_qpn, priv->rx_ring_num);
	return err;
}

void mlx4_en_release_rss_steer(struct mlx4_en_priv *priv)
{
	struct mlx4_en_dev *mdev = priv->mdev;
	struct mlx4_en_rss_map *rss_map = &priv->rss_map;
	int i;

	mlx4_qp_modify(mdev->dev, NULL, rss_map->indir_state,
		       MLX4_QP_STATE_RST, NULL, 0, 0, &rss_map->indir_qp);
	mlx4_qp_remove(mdev->dev, &rss_map->indir_qp);
	mlx4_qp_free(mdev->dev, &rss_map->indir_qp);

	for (i = 0; i < priv->rx_ring_num; i++) {
		mlx4_qp_modify(mdev->dev, NULL, rss_map->state[i],
			       MLX4_QP_STATE_RST, NULL, 0, 0, &rss_map->qps[i]);
		mlx4_qp_remove(mdev->dev, &rss_map->qps[i]);
		mlx4_qp_free(mdev->dev, &rss_map->qps[i]);
	}
	mlx4_qp_release_range(mdev->dev, rss_map->base_qpn, priv->rx_ring_num);
}
