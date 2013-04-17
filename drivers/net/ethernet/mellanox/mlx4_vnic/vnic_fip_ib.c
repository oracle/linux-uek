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
#include "vnic_fip.h"

#define	FIP_OP_RECV   (1ul << 31)
/* TODO - rethink this */
#define FIP_UD_MTU(ib_mtu)	(ib_mtu - FIP_ENCAP_LEN - FIP_ETH_HEADER_LEN)
#define FIP_UD_BUF_SIZE(ib_mtu)	(ib_mtu + IB_GRH_BYTES)

static inline void fip_wr_pepare(struct vnic_port *port,
				 struct ib_send_wr *tx_wr,
				 struct ib_sge *tx_sge,
				 unsigned int wr_id, u64 mapping,
				 int size, u16 pkey_index)
{
	/* This is a fixed part */
	memset(tx_wr, 0, sizeof(struct ib_send_wr));
	tx_wr->num_sge = 1;
	tx_wr->sg_list = tx_sge;
	tx_wr->opcode = IB_WR_SEND;
	tx_wr->send_flags = IB_SEND_SIGNALED; 
	tx_wr->wr.ud.pkey_index = pkey_index;
	tx_wr->wr_id = wr_id;

	memset(tx_sge, 0, sizeof(struct ib_sge));
	tx_sge->lkey = port->mr->lkey;
	tx_sge->addr = mapping;
	tx_sge->length = size;
}

/*
 * send a single multicast packet.
 * return 0 on success, other on failure.
*/
int fip_mcast_send(struct vnic_port *port,
		   struct ib_qp *qp,
		   unsigned int wr_id,
		   u64 mapping,
		   int size,
		   u16 pkey_index,
		   struct vnic_mcast *mcast)
{
	struct ib_send_wr *bad_wr;
	struct ib_sge tx_sge;
	struct ib_send_wr tx_wr;
	int ret;

	fip_wr_pepare(port, &tx_wr, &tx_sge, wr_id, mapping, size, pkey_index);

	tx_wr.wr.ud.ah = mcast->ah;
	tx_wr.wr.ud.remote_qpn = 0xFFFFFFFF;	/*dest_qpn; */
	tx_wr.wr.ud.remote_qkey = mcast->qkey;

	ret = ib_post_send(qp, &tx_wr, &bad_wr);

	return ret;
}

/*
 * send a single unicast packet.
 * return 0 on success, other on failure.
 */
int fip_ucast_send(struct vnic_port *port,
		   struct ib_ah *ah,
		   struct ib_qp *qp,
		   unsigned int wr_id,
		   u64 mapping,
		   int size,
		   u16 pkey_index, u32 dest_qpn, u16 dlid,
		   u32 qkey, u8 sl)
{
	struct ib_send_wr *bad_wr;
	struct ib_ah *new_ah = NULL;
	struct ib_sge tx_sge;
	struct ib_send_wr tx_wr;
	int ret;

	fip_wr_pepare(port, &tx_wr, &tx_sge, wr_id, mapping, size, pkey_index);

	if (!ah) {
		struct ib_ah_attr ah_attr = {
			.dlid = dlid,
			.port_num = port->num,
			.sl = sl & 0xf,
		};

		new_ah = ib_create_ah(port->pd, &ah_attr);
		if (IS_ERR(new_ah))
			return -1;

		tx_wr.wr.ud.ah = new_ah;
	} else
		tx_wr.wr.ud.ah = ah;

	tx_wr.wr.ud.remote_qpn = dest_qpn;
	tx_wr.wr.ud.remote_qkey = qkey;

	ret = ib_post_send(qp, &tx_wr, &bad_wr);

	if (new_ah)
		ib_destroy_ah(new_ah);

	return ret;
}

/*
 * This is a general purpose CQ completion function that handles
 * completions on RX and TX rings. It can serve all users that are
 * using RX and TX rings.
 * RX completions are destinguished from TX comp by the MSB that is set
 * for RX and clear for TX. For RX, the memory is unmapped from the PCI,
 * The head is incremented. For TX the memory is unmapped and then freed.
 * The function returns the number of packets received.
*/
int fip_comp(struct vnic_port *port,
	     struct ib_cq *cq,
	     struct fip_ring *rx_ring,
	     struct fip_ring *tx_ring,
	     char *name)
{
#define FIP_DISCOVER_WC_COUNT 4
	struct ib_wc ibwc[FIP_DISCOVER_WC_COUNT];
	int wrid, n, i;
	int mtu_size = FIP_UD_BUF_SIZE(port->max_mtu_enum);
	int rx_count = 0;
	struct ib_device *dev = port->dev->ca;

	do {
		/*
		 * poll for up to FIP_DISCOVER_WC_COUNT in one request.
		 * returns the number of WC actually polled
		 */
		n = ib_poll_cq(cq, FIP_DISCOVER_WC_COUNT, ibwc);
		for (i = 0; i < n; ++i) {
			/*
			 * use a mask on the id to decide if this is a receive
			 * or transmit WC
			 */
			if (ibwc[i].wr_id & FIP_OP_RECV) {
				wrid = ibwc[i].wr_id & ~FIP_OP_RECV;

				ib_dma_sync_single_for_cpu(dev,
							   rx_ring->ring[wrid].bus_addr,
							   mtu_size,
							   DMA_FROM_DEVICE);

				if (likely(ibwc[i].status == IB_WC_SUCCESS)) {
					rx_ring->ring[wrid].length =
					    ibwc[i].byte_len;
					rx_count++;
				} else
					rx_ring->ring[wrid].entry_posted = 0;

				rx_ring->head++;
			} else {	/* TX completion */
				unsigned long flags;
				wrid = ibwc[i].wr_id;

				/* unmap and free transmitted packet */
				ib_dma_unmap_single(dev,
						    tx_ring->ring[wrid].
						    bus_addr, tx_ring->ring[wrid].length,
						    DMA_TO_DEVICE);

				kfree(tx_ring->ring[wrid].mem);
				tx_ring->ring[wrid].mem = NULL;
				tx_ring->ring[wrid].length = 0;
				spin_lock_irqsave(&tx_ring->head_tail_lock, flags);
				tx_ring->tail++;
				spin_unlock_irqrestore(&tx_ring->head_tail_lock, flags);
			}
		}
	} while (n == FIP_DISCOVER_WC_COUNT);

	ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);

	return rx_count;
}

/* qonfigure a newly allocated QP and move it
 * from reset->init->RTR->RTS
 */
int fip_init_qp(struct vnic_port *port, struct ib_qp *qp, u16 pkey_index, char *name)
{
	struct ib_qp_attr qp_attr;
	int attr_mask;

	qp_attr.qp_state = IB_QPS_INIT;
	qp_attr.qkey = VNIC_FIP_QKEY;
	qp_attr.port_num = port->num;
	qp_attr.pkey_index = pkey_index;
	attr_mask = IB_QP_QKEY | IB_QP_PORT | IB_QP_PKEY_INDEX | IB_QP_STATE;

	if (ib_modify_qp(qp, &qp_attr, attr_mask))
		goto out_fail;

	qp_attr.qp_state = IB_QPS_RTR;
	attr_mask &= ~IB_QP_PORT;
	if (ib_modify_qp(qp, &qp_attr, attr_mask))
		goto out_fail;

	qp_attr.qp_state = IB_QPS_RTS;
	qp_attr.sq_psn = 0;
	attr_mask |= IB_QP_SQ_PSN;
	attr_mask &= ~IB_QP_PKEY_INDEX;
	if (ib_modify_qp(qp, &qp_attr, attr_mask))
		goto out_fail;

	return 0;

out_fail:
	qp_attr.qp_state = IB_QPS_RESET;
	if (ib_modify_qp(qp, &qp_attr, IB_QP_STATE))
		vnic_warn(name, "failed to modify QP to RESET state\n");

	return -EINVAL;
}

void fip_qp_to_reset(struct ib_qp *qp, char *name)
{
	struct ib_qp_attr qp_attr;

	qp_attr.qp_state = IB_QPS_RESET;
	if (ib_modify_qp(qp, &qp_attr, IB_QP_STATE))
		vnic_warn(name, "Failed to modify QP to RESET state\n");
	return;
}

/*
 * alloc a single buffer, map it and post it to the qp.
 * id used to identify entry in receive queue.
 */
int fip_post_receive(struct vnic_port *port, struct ib_qp *qp, int size,
		     int _id, struct fip_ring_entry *mem_entry, char *name)
{
	struct ib_recv_wr rx_wr, *bad_wr;
	struct ib_sge rx_sge;
	int rc;

	rx_wr.wr_id = _id | FIP_OP_RECV;
	rx_wr.next = NULL;
	rx_wr.sg_list = &rx_sge;
	rx_wr.num_sge = 1;
	rx_sge.addr = mem_entry->bus_addr;
	rx_sge.length = size;
	rx_sge.lkey = port->mr->lkey;

	ib_dma_sync_single_for_device(port->dev->ca, rx_sge.addr,
				      FIP_UD_BUF_SIZE(port->max_mtu_enum),
				      DMA_FROM_DEVICE);

	rc = ib_post_recv(qp, &rx_wr, &bad_wr);
	if (unlikely(rc)) {
		vnic_warn(name, "post receive failed for buf rc %d (id %d)\n", _id, rc);
		goto post_recv_failed;
	}
	mem_entry->entry_posted = 1;
	return 0;

post_recv_failed:
	mem_entry->entry_posted = 0;
	return -EIO;
}

void fip_flush_rings(struct vnic_port *port,
		     struct ib_cq *cq,
		     struct ib_qp *qp,
		     struct fip_ring *rx_ring,
		     struct fip_ring *tx_ring,
		     char *name)
{
	vnic_dbg_fip(name, "fip_qp_to_err called\n");
	if (qp) {
		fip_qp_to_reset(qp, name);
		fip_comp(port, cq, rx_ring, tx_ring, name);
	}
}

void fip_free_rings(struct vnic_port *port,
		    struct fip_ring *rx_ring,
		    struct fip_ring *tx_ring,
		    char *name)
{
	struct ib_device *dev = port->dev->ca;
	int i;

	for (i = rx_ring->size - 1; i >= 0; --i) {
		if (rx_ring->ring[i].mem) {
			ib_dma_unmap_single(dev,
					    rx_ring->ring[i].bus_addr,
					    FIP_UD_BUF_SIZE(port->max_mtu_enum),
					    DMA_FROM_DEVICE);
			kfree(rx_ring->ring[i].mem);
		}
	}
	rx_ring->size = 0;

	for (i = tx_ring->size - 1; i >= 0; --i)
		if (tx_ring->ring[i].length != 0) {
			ib_dma_unmap_single(dev,
					    tx_ring->ring[i].bus_addr,
					    tx_ring->ring[i].length,
					    DMA_TO_DEVICE);
			kfree(tx_ring->ring[i].mem);
		}
	tx_ring->size = 0;

	vnic_dbg_fip(name, "Done cleaning RX and TX queues\n");

	kfree(rx_ring->ring);
	rx_ring->ring = NULL;
	kfree(tx_ring->ring);
	tx_ring->ring = NULL;
}

/*
 * TODO - we can do a nicer job here. stage 2
 *  allocates memory and post receives
 * TODO2: need to handle the bad flow to free all existing entries in the ring
 */
int fip_init_rx(struct vnic_port *port,
		int ring_size,
		struct ib_qp *qp,
		struct fip_ring *rx_ring,
		char *name)
{
	struct ib_device *dev = port->dev->ca;
	int i, rc = 0, mtu_size = FIP_UD_BUF_SIZE(port->max_mtu_enum);

	rx_ring->size = ring_size;
	rx_ring->ring = kzalloc(rx_ring->size *
				sizeof(struct fip_ring_entry),
				GFP_KERNEL);
	if (!rx_ring->ring) {
		vnic_warn(name, "failed to alloc fip RX ring, size %d\n", rx_ring->size);
		rx_ring->size = 0;
		return -ENOMEM;
	}

	/* allocate the ring entries */
	for (i = 0; i < rx_ring->size; i++) {
		rx_ring->ring[i].mem = kmalloc(mtu_size, GFP_KERNEL);
		if (unlikely(!rx_ring->ring[i].mem)) {
			rc = -ENOMEM;
			goto error;
		}

		rx_ring->ring[i].entry_posted = 0;
		rx_ring->ring[i].length = mtu_size;
		rx_ring->ring[i].bus_addr = ib_dma_map_single(dev,
							      rx_ring->ring[i].mem,
							      mtu_size, DMA_FROM_DEVICE);
		if (unlikely(ib_dma_mapping_error(dev, rx_ring->ring[i].bus_addr))) {
			rc = -ENODEV;
			goto dma_error;
		}

		if (fip_post_receive(port, qp, FIP_UD_BUF_SIZE(port->max_mtu_enum),
				     i, rx_ring->ring + i, name)) {
			rc = -EIO;
			goto post_recv_failed;
		}
	}

	rx_ring->head = 0;
	rx_ring->tail = 0;
	spin_lock_init(&rx_ring->head_tail_lock);
	spin_lock_init(&rx_ring->ring_lock);
	return 0;

post_recv_failed:
	ib_dma_unmap_single(dev, rx_ring->ring[i].bus_addr,
			    mtu_size, DMA_FROM_DEVICE);
dma_error:
	kfree(rx_ring->ring[i].mem);
	rx_ring->ring[i].mem = NULL;
error:
	/* previous entries need to be freed after flushing the QP */
	return rc;
}

/*
 * This function allocates the tx buffers and initializes the head and
 * tail indexes.
 */
int fip_init_tx(int size, struct fip_ring *tx_ring, char *name)
{
	tx_ring->size = size;
	tx_ring->ring = kzalloc(tx_ring->size *
				sizeof(struct fip_ring_entry),
				GFP_KERNEL);

	if (!tx_ring->ring) {
		vnic_warn(name, "failed to alloc fip TX ring, size %d\n",
			  tx_ring->size);
		tx_ring->size = 0;
		return -ENOMEM;
	}

	tx_ring->head = 0;
	tx_ring->tail = 0;
	spin_lock_init(&tx_ring->head_tail_lock);
	spin_lock_init(&tx_ring->ring_lock);
	return 0;
}

