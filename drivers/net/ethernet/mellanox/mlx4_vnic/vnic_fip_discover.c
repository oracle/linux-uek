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
#include "vnic_fip_discover.h"
#include "vnic_fip_pkt.h"

#define FIP_MAX_PKT_PRINT_LENGTH 120

static void fip_purge_gws(struct work_struct *work);
static void fip_discover_gw_fsm(struct work_struct *work);
static void fip_discover_hadmin_update(struct work_struct *work);
static void fip_discover_fsm(struct work_struct *work);
void fip_close_gw(struct fip_gw_data *gw, enum fip_flush flush);

/* TODO - remove this: for initial debug only */
void fip_dbg_dump_raw_pkt(int level, void *buff,
			  int length, int is_tx, char *name)
{
	int i;
	int tmp_len;
	u32 *data_ptr;
	unsigned char *tmp_data_ptr;

	if (!(vnic_msglvl & VNIC_DEBUG_PKT_DUMP))
		return;

	printk(KERN_DEBUG "%s %s: packet length is %d\n",
	       is_tx ? "TX" : "RX", name, length);

	length = (length > FIP_MAX_PKT_PRINT_LENGTH) ?
		FIP_MAX_PKT_PRINT_LENGTH : length;

	tmp_len = (length >> 2) + 1;
	data_ptr = (u32 *)buff;
	for (i = 0; i < tmp_len; i++) {
		if (!is_tx && i == IB_GRH_BYTES >> 2)
			printk(KERN_DEBUG "========================\n");
		tmp_data_ptr = (unsigned char *)&data_ptr[i];
		printk(KERN_DEBUG "%02x %02x %02x %02x \n",
			   tmp_data_ptr[0], tmp_data_ptr[1],
			   tmp_data_ptr[2], tmp_data_ptr[3]);
	}
}

/*
 * Configure the discover QP. This includes configuring rx+tx
 * moving the discover QP to RTS and creating the tx and rx rings
 */
int fip_discover_start_rings(struct fip_discover *discover,
			     struct fip_ring *rx_ring,
			     struct fip_ring *tx_ring,
			     struct ib_cq *cq,
			     struct ib_qp *qp)
{
	int rc;

	rc = fip_init_tx(tx_ring->size, tx_ring, discover->name);
	if (rc) {
		vnic_warn(discover->name, "fip_init_tx failed rc %d\n", rc);
		/* set RX ring size to 0 as indication of the failure
		   so RX rings won't be freed, no need to set tx_ring->size
		   since fip_init_tx error flow will handle it */
		rx_ring->size = 0;
		return rc;
	}

	rc = fip_init_rx(discover->port, rx_ring->size, qp, rx_ring, discover->name);
	if (rc) {
		vnic_warn(discover->name, "fip_init_rx returned %d\n", rc);
		goto release_queues;
	}

	return 0;

release_queues:
	fip_flush_rings(discover->port, cq, qp, rx_ring, tx_ring, discover->name);
	fip_free_rings(discover->port, rx_ring, tx_ring, discover->name);

	return rc;
}

int fip_discover_init_rings(struct vnic_port *port,
			    struct fip_discover *discover,
			    struct fip_ring *rx_ring,
			    struct fip_ring *tx_ring,
			    struct ib_cq **cq,
			    struct ib_qp **qp,
			    ib_comp_handler comp_handler)
{
	struct ib_qp_init_attr qp_init_attr;
	struct ib_device *ca = port->dev->ca;


	*cq = ib_create_cq(ca, comp_handler, NULL, discover,
			   rx_ring->size + tx_ring->size, 0);
	if (IS_ERR(*cq)) {
		vnic_warn(discover->name, "failed to create CQ\n");
		goto out;
	}

	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.cap.max_send_wr = tx_ring->size;
	qp_init_attr.cap.max_recv_wr = rx_ring->size;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;
	qp_init_attr.sq_sig_type = IB_SIGNAL_ALL_WR;
	qp_init_attr.qp_type = IB_QPT_UD;
	qp_init_attr.send_cq = *cq;
	qp_init_attr.recv_cq = *cq;

	*qp = ib_create_qp(port->pd, &qp_init_attr);
	if (IS_ERR(*qp)) {
		vnic_warn(discover->name, "failed to create QP\n");
		goto error_free_cq;
	}

	/* move QP to RTS */
	if (fip_init_qp(discover->port, *qp, discover->pkey_index, discover->name)) {
		vnic_warn(discover->name, "fip_init_qp failed for  qp\n");
		goto error_free_qp;
	}

	/* init RX + TX rings */
	if (fip_discover_start_rings(discover, rx_ring, tx_ring, *cq, *qp)) {
		vnic_warn(discover->name, "failed to start rings\n");
		goto error_free_qp;
	}

	/* enable receiving CQ comps, triggers fip_discover_comp()  */
	if (ib_req_notify_cq(*cq, IB_CQ_NEXT_COMP)) {
		vnic_warn(discover->name, "ib_req_notify_cq failed for cq\n");
		goto error_release_rings;
	}

	return 0;

error_release_rings:
	fip_flush_rings(discover->port, *cq, *qp, rx_ring, tx_ring, discover->name);
	fip_free_rings(discover->port, rx_ring, tx_ring, discover->name);
error_free_qp:
	ib_destroy_qp(*qp);
error_free_cq:
	ib_destroy_cq(*cq);
out:
	*qp = NULL;
	*cq = NULL;
	return -ENODEV;
}

/*
 * This function handles completions of both TX and RX
 * packets. RX packets are unmapped lightly parsed moved to a list
 * and passed to thread processing. TX packets are unmapped and freed.
 * Note: this function is called from interrupt context
 */
static void fip_discover_comp(struct ib_cq *cq, void *discover_ptr)
{
	struct fip_discover *discover = discover_ptr;

	/* handle completions. On RX packets this will call discover_process_rx
	 * from thread context to continue processing */
	if (fip_comp(discover->port, discover->cq,
		     &discover->rx_ring, &discover->tx_ring,
		     discover->name))
		fip_discover_process_rx(discover);
}

/*
 * Alloc the discover CQ, QP. Configure the QP to RTS.
 * alloc the RX + TX rings and queue work for discover
 * finite state machine code.
 */
int fip_discover_init(struct vnic_port *port, struct fip_discover *discover,
		      u16 pkey, int complete)
{
	int rc;

	discover->port = port;
	discover->flush = FIP_NO_FLUSH;
	discover->state = FIP_DISCOVER_INIT;
	discover->rx_ring.size = FIP_PROTOCOL_RX_SIZE;
	discover->tx_ring.size = FIP_PROTOCOL_TX_SIZE;
	discover->new_prot_gws = 0;
	discover->old_prot_gws = 0;

	/* This is in preparation for pkey discovery */

	init_completion(&discover->flush_complete);

	INIT_DELAYED_WORK(&discover->fsm_task, fip_discover_fsm);
	INIT_DELAYED_WORK(&discover->cleanup_task, fip_purge_gws);
	INIT_DELAYED_WORK(&discover->hadmin_update_task, fip_discover_hadmin_update);
	INIT_WORK(&discover->pkt_rcv_task_bh, fip_discover_process_rx_bh);
	spin_lock_init(&discover->rcv_list.lock);
	INIT_LIST_HEAD(&discover->rcv_list.list);
	spin_lock_init(&discover->lock);


	if (complete) {
		discover->pkey = pkey;
		INIT_LIST_HEAD(&discover->gw_list);
		init_rwsem(&discover->l_rwsem);
		snprintf(discover->name, DISCOVER_NAME_LEN,
			 "%s_P%x", port->name, discover->pkey);
	}
	INIT_LIST_HEAD(&discover->hadmin_cache);
	vnic_mcast_root_init(&discover->mcast_tree);

	if (!ib_find_pkey(port->dev->ca, port->num, discover->pkey, &discover->pkey_index)) {
		rc = fip_discover_init_rings(port, discover, &discover->rx_ring,
					     &discover->tx_ring, &discover->cq,
					     &discover->qp, fip_discover_comp);
		if (rc) {
			vnic_warn(discover->name, "descovered init failed rc=%d\n", rc);
			return rc;
		}

		/* start discover FSM code */
		/* calls fip_discover_fsm() */
		queue_delayed_work(fip_wq, &discover->fsm_task, 0);
	} else {
		vnic_warn(discover->name, "Configured PKEY 0x%X is not supported on port\n", discover->pkey);
		discover->pkey_index = ILLEGAL_PKEY_INDEX;
	}


	return 0;
}

void fip_recv_list_flush(struct fip_discover *discover)
{
	struct list_head discov_recv_local;
	struct fip_rcv_pkt *rcv, *rcv1;
	unsigned long flags;

	INIT_LIST_HEAD(&discov_recv_local);

	spin_lock_irqsave(&discover->rcv_list.lock, flags);
	list_replace_init(&discover->rcv_list.list, &discov_recv_local);
	spin_unlock_irqrestore(&discover->rcv_list.lock, flags);

	list_for_each_entry_safe(rcv, rcv1, &discov_recv_local, list) {
		list_del(&rcv->list);
		kfree(rcv);
	}
	return;
}

/*
 * free the discover TX and RX rings, QP and CQ.
 * May not be called from fip wq context.
 */
int fip_discover_cleanup(struct vnic_port *port, struct fip_discover *discover, int complt)
{
	if (discover->state == FIP_DISCOVER_OFF)
		return -EINVAL;

	/* move FSM to flush state and wait for the FSM
	 * to finish whatever it is doing before we continue
	 */
	vnic_dbg_mark();
	init_completion(&discover->flush_complete);
	discover->flush = complt ? FIP_FULL_FLUSH : FIP_PARTIAL_FLUSH;
	cancel_delayed_work(&discover->fsm_task);
#ifndef _BP_WORK_SYNC
	cancel_delayed_work_sync(&discover->hadmin_update_task);
#else
	cancel_delayed_work(&discover->hadmin_update_task);
	flush_workqueue(fip_wq);
#endif
	/* flush any hadmin entries leftovers */
	{
		struct fip_hadmin_cache *hadmin, *hadmin_t;

		spin_lock_irq(&discover->lock);
		list_for_each_entry_safe(hadmin, hadmin_t,
					 &discover->hadmin_cache, next) {
			list_del(&hadmin->next);
			kfree(hadmin);
		}
		spin_unlock_irq(&discover->lock);
	}

	/* calls fip_discover_fsm() */
	queue_delayed_work(fip_wq, &discover->fsm_task, 0);
	vnic_dbg_mark();
	/* calls fip_discover_fsm() */
	wait_for_completion(&discover->flush_complete);
	vnic_dbg_mark();

	/* make sure that discover FSM is idle */
#ifndef _BP_WORK_SYNC
	cancel_delayed_work_sync(&discover->fsm_task);
#else
	cancel_delayed_work(&discover->fsm_task);
	flush_workqueue(fip_wq);
#endif

	if (discover->pkey_index != ILLEGAL_PKEY_INDEX) {
		fip_flush_rings(port, discover->cq, discover->qp,
				&discover->rx_ring, &discover->tx_ring,
				discover->name);
		fip_free_rings(port, &discover->rx_ring, &discover->tx_ring,
			       discover->name);

		fip_recv_list_flush(discover);
		if (discover->qp)
			ib_destroy_qp(discover->qp);
		discover->qp = NULL;

		if (discover->cq)
			ib_destroy_cq(discover->cq);
		discover->cq = NULL;
	}

	return 0;
}

/*
 * This function runs in interrupt context
 * It does sanity checking of the packet, moves it to a list and passes
 * handling to a thread.
 */
void fip_discover_process_rx(struct fip_discover *discover)
{
	struct vnic_port *port = discover->port;
	int mtu_size = FIP_UD_BUF_SIZE(port->max_mtu_enum);
	int rc;
	int queue_packet, one_or_more_queued = 0;
	struct fip_rcv_pkt *rcv, *rcv1;
	struct list_head discov_recv_local;
	int index;
	struct fip_content *fc;
	int err;
	struct fip_ring_entry *ring;

	INIT_LIST_HEAD(&discov_recv_local);

	if (discover->flush != FIP_NO_FLUSH)
		return;

	while (discover->rx_ring.head != discover->rx_ring.tail) {
		fc = NULL;
		queue_packet = 0;
		index = discover->rx_ring.tail & (discover->rx_ring.size - 1);
		ring = &discover->rx_ring.ring[index];

		if (ring->entry_posted == 1 &&
		    discover->state == FIP_DISCOVER_SOLICIT) {
			fc = kzalloc(sizeof *fc, GFP_ATOMIC);
			if (likely(fc)) {
				/* login is the first state we RX packets in */
				rc = fip_packet_parse(port, ring->mem + IB_GRH_BYTES,
						      ring->length - IB_GRH_BYTES, fc);
				if (!rc)
					fip_discover_rx_packet(&queue_packet, fc);
			} else
				vnic_warn(discover->name, "allocation failed\n");
		}
		if (queue_packet) {
			int length;

			length = ring->length - IB_GRH_BYTES;
			rcv = kmalloc(sizeof *rcv, GFP_ATOMIC);
			if (!rcv) {
				vnic_dbg_fip(discover->name, "failed kmalloc\n");
				kfree(fc);
			} else {
				struct fip_ring_entry me;

				err = alloc_map_fip_buffer(port->dev->ca, &me,
							   mtu_size, GFP_ATOMIC);
				if (err) {
					kfree(fc);
					kfree(rcv);
				} else {
					rcv->length = length;
					rcv->fc = fc;
					rcv->mem = ring->mem;
					list_add_tail(&rcv->list, &discov_recv_local);
					one_or_more_queued++;
					ib_dma_unmap_single(port->dev->ca,
							    ring->bus_addr,
							    mtu_size, DMA_FROM_DEVICE);
					*ring = me;
				}
			}
		} else
                        kfree(fc);

		rc = fip_post_receive(port, discover->qp,
				      FIP_UD_BUF_SIZE(discover->port->max_mtu_enum),
				      index, ring, discover->name);
		if (rc)
			vnic_warn(discover->name, "fip_post_receive rc %d\n", rc);

		discover->rx_ring.tail++;
	}

	if (one_or_more_queued) {
		spin_lock(&discover->lock);
		if (likely(discover->flush == FIP_NO_FLUSH)) {
			spin_lock(&discover->rcv_list.lock);
			list_splice_init(&discov_recv_local, discover->rcv_list.list.prev);
			spin_unlock(&discover->rcv_list.lock);
			/* calls fip_discover_process_rx_bh */
			queue_work(fip_wq, &discover->pkt_rcv_task_bh);
			spin_unlock(&discover->lock);
		} else {
			spin_unlock(&discover->lock);
			list_for_each_entry_safe(rcv, rcv1, &discov_recv_local, list) {
				list_del(&rcv->list);
				kfree(rcv->fc);
				kfree(rcv->mem);
				kfree(rcv);
			}
		}
	}

	return;
}

/*
 * This function is the RX packet handler bottom half. It runs on the fip wq.
*/
void fip_discover_process_rx_bh(struct work_struct *work)
{
	struct fip_discover *discover =
		container_of(work, struct fip_discover, pkt_rcv_task_bh);
	int rc;
	struct list_head discov_recv_local;
	struct fip_rcv_pkt *rcv, *rcv1;
	unsigned long flags;

	INIT_LIST_HEAD(&discov_recv_local);

	/* the irqsave is needed because debug kernel above 2.6.27 complains about
	 * hard irq safe to hard irq unsafe on discover.lock */
	spin_lock_irqsave(&discover->rcv_list.lock, flags);
	list_replace_init(&discover->rcv_list.list, &discov_recv_local);
	spin_unlock_irqrestore(&discover->rcv_list.lock, flags);

	if (discover->flush != FIP_NO_FLUSH) {
		list_for_each_entry_safe(rcv, rcv1, &discov_recv_local, list) {
			list_del(&rcv->list);
			kfree(rcv->fc);
			kfree(rcv->mem);
			kfree(rcv);
		}
		return;
	}

	list_for_each_entry_safe(rcv, rcv1, &discov_recv_local, list) {
			rc = fip_discover_rx_packet_bh(discover, rcv->fc);
			if (rc)
				vnic_warn(discover->name, "discover_rx_packet rc %d\n", rc);

		list_del(&rcv->list);
		kfree(rcv->fc);
		kfree(rcv->mem);
		kfree(rcv);
	}
	return;
}

static inline int fip_close_all_vnics(struct fip_gw_data *gw, enum fip_flush flush)
{
	struct fip_vnic_data *vnic;
	int open_vnics = 0;

	vnic_dbg_func(gw->discover->name);

	list_for_each_entry(vnic, &gw->vnic_list, gw_vnics) {
		open_vnics++;
		fip_vnic_close(vnic, flush);
	}
	return open_vnics;
}

static int fip_gw_create_vnics(struct fip_gw_data *gw)
{
	struct fip_vnic_data *vnic;
	unsigned long first_free_vnic;
	struct fip_vnic_send_info gw_address;
	int i;

	gw->info.gw_num_vnics = (gw->info.gw_num_vnics > FIP_MAX_VNICS_PER_GW) ?
		FIP_MAX_VNICS_PER_GW : gw->info.gw_num_vnics;


	gw->info.gw_num_vnics = vnic_net_admin ? gw->info.gw_num_vnics : 0;
	fip_vnic_create_gw_param(&gw_address, gw->info.gw_qpn, VNIC_FIP_QKEY,
				 gw->info.gw_lid,  vnic_gw_ctrl_sl(gw));
	/* for host admined  */
	list_for_each_entry(vnic, &gw->vnic_list, gw_vnics) {
		if (vnic->hadmined) {
			if (gw->info.hadmined_en)
				fip_hadmin_vnic_refresh(vnic, &gw_address);
			else {
				vnic_dbg_fip(gw->discover->name,
					     "fip_gw_create_vnics hadmin disabled, "
					     "close open hadmin vnics\n");
				fip_vnic_close(vnic, FIP_PARTIAL_FLUSH);
			}
		}
	}

	/* for network admined  */
	for (i = gw->vnic_count; i < gw->info.gw_num_vnics; i++) {
		vnic_dbg_fip(gw->discover->name, "fip_gw_create_vnics available"
			     " vnics %d needed %d\n",
			     gw->vnic_count, gw->info.gw_num_vnics);

		/* start network assigned at half array. leave first half to host admin */
		first_free_vnic = find_first_zero_bit(gw->n_bitmask,
						      FIP_MAX_VNICS_PER_GW);
		if (first_free_vnic >= FIP_MAX_VNICS_PER_GW)
			return -ENOMEM;

		vnic = fip_vnic_alloc(gw->discover->port, gw, 0 /* hadmin */, first_free_vnic);
		if (!vnic)
			return -ENOMEM;

		fip_vnic_set_gw_param(vnic, &gw_address);
		set_bit(first_free_vnic, gw->n_bitmask);
		list_add_tail(&vnic->gw_vnics, &gw->vnic_list);
		gw->vnic_count++;

		/* calls fip_vnic_fsm() */
		cancel_delayed_work(&vnic->vnic_task);
		fip_vnic_fsm(&vnic->vnic_task.work);
	}

	return 0;
}

/*
 * This function goes over vnics and closes network administrated vNics
 * that are not open and do not receive neighbor table info (there
 * is no way for the BXM to tell the vNics to close before the
 * vnic is listening to the neighbour tables).
*/
static int fip_gw_close_nonopen_vnics(struct fip_gw_data *gw)
{
	struct fip_vnic_data *vnic;
	int closed_vnics = 0;

	vnic_dbg_fip(gw->discover->name, "Try to close non open vnics\n");

	list_for_each_entry(vnic, &gw->vnic_list, gw_vnics) {
		vnic_dbg_fip(gw->discover->name, "check vnic %s, hadmin %d state %d\n",
			     vnic->name, vnic->hadmined, vnic->state);
		if (!vnic->hadmined && vnic->state < FIP_VNIC_VHUB_DONE) {
			vnic_dbg_fip(gw->discover->name, "closing vnic %s\n", vnic->name);
			fip_vnic_close(vnic, FIP_PARTIAL_FLUSH);
			closed_vnics++;
		}
	}

	return closed_vnics;
}

/* permanently delete all vnics pending delete. The function goes over
 * the list of vnics awaiting deletion and tries to delete them. If the
 * vnic destructor returns an error value (currently busy) the function
 * will requeue it self for another try. The function will also test if
 * new vnics need to be added as a result of vnic removal.
 */
static void fip_purge_vnics(struct work_struct *work)
{
	struct fip_gw_data *curr_gw =
		container_of(work,struct fip_gw_data, vnic_cleanup_task.work);
	struct fip_vnic_data *vnic, *tmp_vnic;
	int vnic_id, rc, del_cnt = 0, retry = 0;
	unsigned long *bitmask;

	vnic_dbg_fip(curr_gw->discover->name, "fip_purge_vnics\n");

	list_for_each_entry_safe(vnic, tmp_vnic, &curr_gw->vnic_list, gw_vnics) {
		enum fip_flush f;
		vnic_id = vnic->vnic_id;
		bitmask = vnic->hadmined ? NULL : curr_gw->n_bitmask;

		/* If successful vnic is removed from list and destroyed */
		f = vnic->flush;
		if (f != FIP_NO_FLUSH) {
			rc = fip_vnic_destroy(vnic);
			if (!rc) {
				del_cnt++;
				if (f == FIP_FULL_FLUSH && bitmask)
					clear_bit(vnic_id, bitmask);
			} else {
				retry |= rc;
			}
		}

		/* limit the number of vnics to purge in each loop to let other
		 * tasks on same wq to run (i.e., avoid starvation).
		 */
		if (del_cnt > 2) {
			retry = 1;
			break;
		}
	}

	/* This means we still have vnics that refuse to close retry later */
	if (retry){
		vnic_dbg_mark();
		/* calls fip_purge_vnics() */
		queue_delayed_work(fip_wq, &curr_gw->vnic_cleanup_task, HZ / 10);
	} else {
		vnic_dbg_fip(curr_gw->discover->name, "fip_purge_vnics, all GW"
			     " vnics closed\n");

		if (curr_gw->hadmin_gw && curr_gw->state == FIP_GW_HOST_ADMIN && list_empty(&curr_gw->vnic_list)) {
			vnic_warn(curr_gw->discover->name,
					  "Removing Host admin GW %s with no vnics\n",
					  (char*)curr_gw->info.vol_info.gw_port_name);
			fip_close_gw(curr_gw, FIP_FULL_FLUSH);
		}
		/* test and open new vnics if vnics are missing */
		/* ALITODO: after GW timeout, a vnic is re-created! why is that?
		if (fip_gw_create_vnics(curr_gw)) {
			vnic_dbg_mark();
			queue_delayed_work(fip_wq,
					   &curr_gw->vnic_cleanup_task, HZ);
		}
		*/
	}
}

/*
 * This function adds or removes a single host admined vnic to a GW.
 * First the function searches for the vnic. The search function
 * disregards vnics that are undergoing a complete flush.
*/
int fip_gw_update_hadmin_gw(struct fip_gw_data *gw,
			    struct fip_hadmin_cache *hadmin_entry)
{
	struct fip_vnic_data *vnic;
	int vnic_id = hadmin_entry->vnic_id, rc = 0;

	/* set bit 16 for hadmin vNics (by spec) */
	vnic_id |= (1 << (VNIC_ID_LEN - 1));

	vnic = fip_vnic_find_in_list(gw, vnic_id, hadmin_entry->mac,
				     hadmin_entry->vlan,
				     hadmin_entry->vlan_used);

	/* remove: if vNic found - remove it and exit */
	if (hadmin_entry->remove) {
		if (vnic)
			fip_vnic_close(vnic, FIP_FULL_FLUSH);
		else
			vnic_dbg_fip(gw->discover->name, "vNic to remove is"
				     " not found (name:%s mac:"MAC_6_PRINT_FMT
				     " vlan:%d id:%d)\n",
			  hadmin_entry->interface_name,
			  MAC_6_PRINT_ARG(hadmin_entry->mac),
			  hadmin_entry->vlan, vnic_id);
		goto out;
	}

	/* add: if vNic found - report error, otherwise add new vNic */
	if (vnic) {
		/* skip error reporting between child vNics conflict,
		 * as vnic_learn_mac() may learn same child while it's still
		 * pending. TODO: improve this to avoid such cases.
		 */
		if (hadmin_entry->parent_used && vnic->parent_used)
			goto out;
		vnic_warn(gw->discover->name, "vNic creation failed, duplicate"
			  " vNic detected (name:%s mac:"MAC_6_PRINT_FMT
			  " vlan:%d id:%d & existing name:%s mac:"
			  MAC_6_PRINT_FMT" vlan:%d id:%d)\n",
			  hadmin_entry->interface_name,
			  MAC_6_PRINT_ARG(hadmin_entry->mac),
			  hadmin_entry->vlan, vnic_id, vnic->interface_name,
			  MAC_6_PRINT_ARG(vnic->login_data.mac),
			  vnic->login_data.vlan, vnic->login_data.vnic_id);
		goto out;
	}

#if 0
	/* if the GW is in all_vlan mode,
	 * the host can only create vlans in this mode.
	 * However if it is not in all_vlan mode, the host must not create
	 * vlans in this mode */
	if ((gw->info.all_vlan_gw && !hadmin_entry->all_vlan_gw
	     && hadmin_entry->vlan_used) ||
	     (!gw->info.all_vlan_gw && hadmin_entry->all_vlan_gw)) {
		vnic_warn(gw->discover->name, "vnic creation failed, all_vlan"
			  " gateway policy must be enforced between the gateway"
			  "  and the host\n");
		rc = -EINVAL;
		goto out;
	}
#endif

	vnic = fip_vnic_alloc(gw->discover->port, gw, 1 /* hadmin */, vnic_id);
	if (!vnic) {
		rc = -ENOMEM;
		goto out;
	}

	/* hand over info from hadmin to vnic struct */
	memcpy(vnic->login_data.mac, hadmin_entry->mac, sizeof(vnic->login_data.mac));
	memcpy(vnic->interface_name, hadmin_entry->interface_name,
	       sizeof(vnic->interface_name));
	vnic->login_data.vlan = hadmin_entry->vlan;
	vnic->login_data.vp = hadmin_entry->vlan_used;
	vnic->login_data.all_vlan_gw = hadmin_entry->all_vlan_gw;
	memcpy(vnic->shared_vnic.ip, hadmin_entry->shared_vnic_ip,
	       sizeof(vnic->shared_vnic.ip));
	memcpy(vnic->shared_vnic.emac, hadmin_entry->shared_vnic_mac,
	       sizeof(vnic->shared_vnic.emac));
	vnic->shared_vnic.enabled = is_valid_ipv4(hadmin_entry->shared_vnic_ip);
	vnic->vnic_id = vnic_id; /* will be overwritten later */
	vnic->vlan_used = hadmin_entry->vlan_used;
	vnic->parent_used =  hadmin_entry->parent_used;
	memcpy(vnic->parent_name, hadmin_entry->parent_name,
	       sizeof(vnic->parent_name));
	vnic->qp_base_num = hadmin_entry->qp_base_num;
	vnic->vlan = hadmin_entry->vlan;
	vnic->cmd = hadmin_entry->cmd;
	vnic->all_vlan_gw = hadmin_entry->all_vlan_gw;

	/* create dentry */
	rc = vnic_create_hadmin_dentry(vnic);
	if (rc)
		goto init_failed;

	rc = fip_vnic_hadmin_init(gw->discover->port, vnic);
	if (rc)
		goto init_failed;

	list_add_tail(&vnic->gw_vnics, &gw->vnic_list);

	/* calls fip_vnic_fsm() */
	fip_vnic_fsm(&vnic->vnic_task.work);

	return 0;

init_failed:
	vnic_delete_hadmin_dentry(vnic);
	kfree(vnic);
out:
	return rc;
}

/*
 * Queue the GW for deletion. And trigger a delayed call to the cleanup
 * function.
 * Note: This deletion method insures that all pending GW work requests
 * are cleared without dependency of the calling context.
*/
void fip_close_gw(struct fip_gw_data *gw, enum fip_flush flush)
{
	enum fip_flush tmp_flush = gw->hadmin_gw ? flush : FIP_FULL_FLUSH;

	if (tmp_flush == FIP_PARTIAL_FLUSH && gw->state < FIP_GW_HOST_ADMIN)
		return;

	/* close already in process, disregard*/
	if (gw->flush >= tmp_flush)
		return;

	gw->flush = tmp_flush;
	gw->info.gw_num_vnics = 0;
	cancel_delayed_work(&gw->gw_task);

	/* This is not mandatory but will save us time because there is a
	 * better chance that all vnics would be destroyed before trying to
	 * destroy the GW */
	fip_close_all_vnics(gw, tmp_flush);

	/* calls fip_purge_gws() */
	queue_delayed_work(fip_wq, &gw->discover->cleanup_task, DELAYED_WORK_CLEANUP_JIFFS);
}

/*
 * Free GW resources. This includes destroying the vnics. If the GW can be
 * totally destroyed (no pending work for the GW and all the vnics have been
 * destroyed) the GW will be removed from the GWs list and it's memory
 * freed. If the GW can not be closed at this time it will not be freed
 * and the function will return an error.
 * In this case the caller needs to recall the unction to complete the
 * operation.
 * Do not call this function directly use: fip_close_gw
 */
static int fip_free_gw(struct fip_discover *discover, struct fip_gw_data *gw)
{
	struct fip_vnic_data *vnic;
	int vnic_close_fail = 0;

	gw->info.gw_num_vnics = 0;

	if (delayed_work_pending(&gw->gw_task))
		return -EBUSY;

	list_for_each_entry(vnic, &gw->vnic_list, gw_vnics)
		vnic_close_fail |= (vnic->flush != FIP_NO_FLUSH);

	/* true if vnics need to be closed */
	/* if some of the vnics are still open return and retry later */
	if (vnic_close_fail)
		return -EBUSY;

	if (delayed_work_pending(&gw->vnic_cleanup_task))
		return -EBUSY;

	/*
	 * it is possible that during gw removal we added the GW again. Test GW
	 * list to ensure it is not in the list already before adding it again.
	 */
	if (gw->state > FIP_GW_HOST_ADMIN) {
		if (gw->info.gw_prot_new)
			discover->new_prot_gws--;
		else
			discover->old_prot_gws--;
	}
	if (gw->flush == FIP_PARTIAL_FLUSH) {
		gw->state = FIP_GW_HOST_ADMIN;
		gw->flush = FIP_NO_FLUSH;
	} else {
		list_del(&gw->list);
		if (!IS_ERR(gw->pquery) && gw->query_id >= 0)
			ib_sa_cancel_query(gw->query_id, gw->pquery);
		wait_for_completion(&gw->query_comp);
		kfree(gw);
	}
	return 0;
}

/*
 * permanently delete all GWs pending delete. The function goes over
 * the list of GWs awaiting deletion and tries to delete them. If the
 * GW destructor returns an error value (currently busy) the function
 * will requeue it self for another try.
 */
static void fip_purge_gws(struct work_struct *work)
{
	struct fip_discover *discover =
		container_of(work, struct fip_discover, cleanup_task.work);
	struct fip_gw_data *gw, *tmp_gw;
	int gw_close_fail = 0;

	down_write(&discover->l_rwsem);
	list_for_each_entry_safe(gw, tmp_gw, &discover->gw_list, list) {
		if (gw->flush  != FIP_NO_FLUSH) {
			gw_close_fail |= fip_free_gw(discover, gw);
		}
	}
	up_write(&discover->l_rwsem);

	/* This means we still have vnics that refuse to close, retry later */
	if (gw_close_fail) {
		vnic_dbg_fip(discover->name, "still have open GWs\n");
		/* calls fip_purge_gws() */
		queue_delayed_work(fip_wq, &discover->cleanup_task,
				   DELAYED_WORK_CLEANUP_JIFFS);
	} else {
		vnic_dbg_fip(discover->name, "fip_purge_gws all gws"
			     " closed and freed\n");
	}
}

static int fip_free_gw_done(struct fip_discover *discover, enum fip_flush flush)
{
	struct fip_gw_data *curr_gw;
	int rc;

	down_read(&discover->l_rwsem);
	if (flush == FIP_FULL_FLUSH) {
		rc = list_empty(&discover->gw_list);
		up_read(&discover->l_rwsem);
		return rc;
	}

	list_for_each_entry(curr_gw, &discover->gw_list, list) {
		if (curr_gw->flush  != FIP_NO_FLUSH) {
			up_read(&discover->l_rwsem);
			return 0;
		}
	}

	up_read(&discover->l_rwsem);
	return 1;
}

/*
 * Go over the GW list and try to close the GWs. It is possible that some
 * of the GWs have pending work and therefore can not be closed. We can not
 * sleep on this because we might be running on the same context as the one
 * we are waiting for. The user should call this function once and then test
 * if the free is done by polling (must release wq context) fip_free_gw_done
 */
static int fip_free_gw_list(struct fip_discover *discover, enum fip_flush flush)
{
	struct fip_gw_data *curr_gw;

	down_read(&discover->l_rwsem);
	list_for_each_entry(curr_gw, &discover->gw_list, list)
		fip_close_gw(curr_gw, flush);
	up_read(&discover->l_rwsem);

	vnic_dbg_fip(discover->name, "fip_free_gw_list not done\n");
	return 0;
}

static inline void update_gw_address(struct fip_gw_data *gw,
				     struct fip_gw_data_info *new_gw_data)
{
	gw->info.gw_qpn = new_gw_data->gw_qpn;
	gw->info.gw_lid = new_gw_data->gw_lid;
	gw->info.gw_port_id = new_gw_data->gw_port_id;
	gw->info.gw_sl = new_gw_data->gw_sl;
	memcpy(gw->info.gw_guid, new_gw_data->gw_guid, sizeof gw->info.gw_guid);

	vnic_dbg_fip(gw->discover->name, "GW address was modified. "
		     "QPN: 0x%x, LID: 0x%x, guid: " GUID_FORMAT
		     "port id: %d, SL: %d\n", gw->info.gw_qpn,
		     gw->info.gw_lid, GUID_ARG(gw->info.gw_guid),
		     gw->info.gw_port_id, gw->info.gw_sl);
	/* restart fsm to path query */
	if (vnic_sa_query)
		fip_discover_gw_fsm_move(gw, FIP_GW_CTRL_PATH_QUERY);
}

int fip_gw_modified(struct fip_gw_data *gw,
		    struct fip_gw_data_info *new_gw_data)
{
	char *name = gw->discover->name;
	ASSERT(new_gw_data);

	vnic_dbg_fip(name, "fip_gw_modified called, gw_num_vnics %d -> %d\n",
		     gw->info.gw_num_vnics, new_gw_data->gw_num_vnics);

	if (memcmp(gw->info.gw_guid, new_gw_data->gw_guid,
		   sizeof(gw->info.gw_guid)) ||
	    gw->info.gw_lid != new_gw_data->gw_lid ||
	    gw->info.gw_port_id != new_gw_data->gw_port_id ||
	    gw->info.gw_qpn != new_gw_data->gw_qpn ||
	    (!vnic_sa_query && gw->info.gw_sl != new_gw_data->gw_sl)) {
		/* TODO: Make sure that the GW doesn't change the sl sent in solicitation */
		/* In this case the GW address might be modified even
		   in 'good flow' */
		if (gw->info.gw_type == GW_TYPE_LAG &&
		    gw->info.ext_lag.ucast)
			update_gw_address(gw, new_gw_data);
		else {
			vnic_dbg_fip(name, "fip_gw_modified changing "
				     "unsupported parameter closing GW\n");
			fip_close_gw(gw, FIP_PARTIAL_FLUSH);
		}
	} else if (gw->info.gw_num_vnics < new_gw_data->gw_num_vnics) {
		vnic_dbg_fip(name, "fip_gw_modified changing num "
			     "vnics from %d to %d\n", gw->info.gw_num_vnics,
			     new_gw_data->gw_num_vnics);
		gw->info.gw_num_vnics = new_gw_data->gw_num_vnics;
		if (fip_gw_create_vnics(gw))
			vnic_err(name, "fip_gw_create_vnics failed\n");

	}  else if (gw->info.gw_num_vnics > new_gw_data->gw_num_vnics) {
		gw->info.gw_num_vnics = new_gw_data->gw_num_vnics;
		fip_gw_close_nonopen_vnics(gw);
		if (gw->vnic_count < gw->info.gw_num_vnics)
			fip_gw_create_vnics(gw);
		vnic_dbg_fip(name, "fip_gw_modified changing num "
			     "vnics from %d to %d\n", gw->info.gw_num_vnics,
			     new_gw_data->gw_num_vnics);
	} else if (gw->info.n_rss_qpn != new_gw_data->n_rss_qpn) {
		gw->info.n_rss_qpn = new_gw_data->n_rss_qpn;
		vnic_dbg_fip(name, "fip_gw_modified changing n_rss_qpn "
			     "from %d to %d\n", gw->info.n_rss_qpn,
			     new_gw_data->n_rss_qpn);
	} else if (gw->info.hadmined_en != new_gw_data->hadmined_en) {
		if (fip_gw_create_vnics(gw))
			vnic_err(name, "fip_gw_create_vnics failed\n");
	}

	return 0;
}

static inline int is_none_zero_guid(u8 *guid)
{
	int i;
	u8 ored = 0;

	if (!guid)
		return 0;

	for (i = 0; i < 8; ++i)
		ored |= guid[i];

	return !!ored;
}

/*
 * Look for a GW in the GW list.
 * The search need one identifier to identify the Box (either GUID or system name)
 * and one identifier for the external port (port_id or eport_name).
 * This function uses what ever data is available for the search since
 * various callers do not have access to a single pair of ids.
 * use NULL for unknown strings and GW_PORT_ID_UNKNOWN for unknown port_id.
 * GW that are undergoing complete flush are disregarded by the search.
 */
struct fip_gw_data *fip_find_gw_in_list(
				struct fip_discover *discover,
				int 	port_id,
				u8	*eport_name,
				u8	*gw_guid,
				u8	*system_guid,
				u8	*system_name,
				int	is_login)
{
	struct fip_gw_data *curr_gw;
	int use_guid = is_none_zero_guid(gw_guid);
	int use_system_name = system_name && strlen(system_name) > 0;
	int use_system_guid = is_none_zero_guid(system_guid);
	int use_eport = eport_name && strlen(eport_name) > 0;
	int use_port_id = port_id >= 0;
	int port_id_pass;
	int eport_match;

	if(!((use_eport || use_port_id) && 
	     (use_guid || use_system_name || use_system_guid))) {
		vnic_dbg_fip_v(discover->name,
			       "fip_find_gw_in_list not enough param for search\n");
		return NULL;
	}

	if (use_system_name)
		vnic_dbg_fip_v(discover->name, "system name %s\n", system_name);

	if (use_guid)
		vnic_dbg_fip_v(discover->name, "gw guid "VNIC_GUID_FMT"\n",
			       VNIC_GUID_RAW_ARG(gw_guid));

	if (use_system_guid)
		vnic_dbg_fip_v(discover->name, "system guid "VNIC_GUID_FMT"\n",
			       VNIC_GUID_RAW_ARG(system_guid));

	if (use_eport)
		vnic_dbg_fip_v(discover->name, "eport %s\n", eport_name);

	if (use_port_id)
		vnic_dbg_fip_v(discover->name, "port_id 0x%x\n", port_id);

	down_read(&discover->l_rwsem);
	list_for_each_entry(curr_gw, &discover->gw_list, list) {
		vnic_dbg_fip_v(discover->name, "check gw on eport %s, gw_guid "VNIC_GUID_FMT" "
			       "system_guid "VNIC_GUID_FMT", flush %d\n",
			       curr_gw->info.vol_info.gw_port_name,
			       VNIC_GUID_RAW_ARG(curr_gw->info.gw_guid),
			       VNIC_GUID_RAW_ARG(curr_gw->info.vol_info.system_guid),
			       curr_gw->flush);

		if (curr_gw->flush == FIP_FULL_FLUSH)
			continue;

		/* for login ack, skip non connected GWs */
		if (is_login && use_port_id && curr_gw->state == FIP_GW_HOST_ADMIN) /* skip dangling hadmined GWs */
			continue;

		/* use the eport names only if you don't have port_id indexes
		 * This is in order to enable port_id changes.
		 * in case of host admin GW, ignore gw_port_id since the old GW
		 * will never be flushed and the new GW id can change */
		port_id_pass = use_port_id && (curr_gw->info.gw_port_id != (u16)-1) && !(curr_gw->hadmin_gw && use_eport);
		eport_match = (use_eport && !port_id_pass &&
			 !strncmp(curr_gw->info.vol_info.gw_port_name,
				  eport_name,VNIC_GW_PORT_NAME_LEN)) ||
			(port_id_pass && (port_id == curr_gw->info.gw_port_id));
		if (!eport_match)
			continue;

		if (use_guid && !memcmp(curr_gw->info.gw_guid, gw_guid, GUID_LEN))
			goto found;

		if (use_system_guid &&
		    !memcmp(curr_gw->info.vol_info.system_guid,
			    system_guid, GUID_LEN))
			goto found;

		if(use_system_name &&
		   !strncmp(curr_gw->info.vol_info.system_name, system_name,
			    VNIC_SYSTEM_NAME_LEN))
			goto found;
	}

	up_read(&discover->l_rwsem);
	vnic_dbg_fip(discover->name, "gw not found!\n");
	return NULL;
found:
	if (curr_gw->hadmin_gw && use_eport && use_port_id &&
		!strncmp(curr_gw->info.vol_info.gw_port_name,eport_name,VNIC_GW_PORT_NAME_LEN) &&
		curr_gw->info.gw_port_id != port_id) {
		vnic_info("%s:["VNIC_GUID_FMT"] %s eport ID changed from %d to %d\n",
				  curr_gw->info.vol_info.system_name,
				  VNIC_GUID_RAW_ARG(curr_gw->info.vol_info.system_guid),
				  curr_gw->info.vol_info.gw_port_name,
				  curr_gw->info.gw_port_id, port_id);
	}

	up_read(&discover->l_rwsem);
	return curr_gw;
}

/*
 * Alloc and init a new GW struct
 */
static struct fip_gw_data *fip_discover_create_gw(struct fip_discover *discover)
{
	struct fip_gw_data *gw_data;

	gw_data = kzalloc(sizeof(struct fip_gw_data), GFP_KERNEL);
	if (!gw_data)
		goto out;

	INIT_DELAYED_WORK(&gw_data->gw_task, fip_discover_gw_fsm);
	INIT_DELAYED_WORK(&gw_data->vnic_cleanup_task, fip_purge_vnics);
	INIT_LIST_HEAD(&gw_data->vnic_list);
	gw_data->discover = discover;
	gw_data->pquery = ERR_PTR(-ENODATA);
	gw_data->query_id = -1;
	init_completion(&gw_data->query_comp);
	complete(&gw_data->query_comp);
	mutex_init(&gw_data->mlock);

out:
	return gw_data;
}

static void fip_discover_hadmin_update(struct work_struct *work)
{
	struct fip_discover *discover =
		container_of(work, struct fip_discover,
			     hadmin_update_task.work);
	struct fip_hadmin_cache *hadmin_entry;
	struct fip_hadmin_cache *hadmin_tmp;
	struct fip_gw_data *curr_gw;
	struct list_head hadmin_head;
	char *name;
	int flush, used_guid, rc;

	/* move list from hadmin_cache to a temporary list */
	spin_lock_irq(&discover->lock);
	list_replace(&discover->hadmin_cache, &hadmin_head);
	INIT_LIST_HEAD(&discover->hadmin_cache);
	flush = discover->flush;
	spin_unlock_irq(&discover->lock);

	if (flush != FIP_NO_FLUSH)
		goto out;

	/* process hadmin list */
	list_for_each_entry_safe(hadmin_entry, hadmin_tmp, &hadmin_head, next) {
		name = (char *)(hadmin_entry->interface_name);
		vnic_dbg_mac(name, "parent_used %d, remove %d\n",
			     hadmin_entry->parent_used,
			     hadmin_entry->remove);
		if (hadmin_entry->parent_used) {
			rc = vnic_parent_update(discover->port, hadmin_entry->interface_name,
						hadmin_entry->vnic_id, hadmin_entry->mac,
						&(hadmin_entry->qp_base_num),
						hadmin_entry->parent_name,
						hadmin_entry->remove);
			if (rc)
				continue;
		}

		used_guid = is_valid_guid(hadmin_entry->system_guid);
		curr_gw = fip_find_gw_in_list(discover, NOT_AVAILABLE_NUM,
					      hadmin_entry->eport_name,
					      NULL,
					      used_guid ? hadmin_entry->system_guid : NULL,
					      used_guid ? NULL : hadmin_entry->system_name, 0/* is_login */);
		if (!hadmin_entry->remove) {
			/* in case no GW or GW is being removed create a new one */
			if (!curr_gw || curr_gw->flush == FIP_FULL_FLUSH) {
				curr_gw = fip_discover_create_gw(discover);
				if (!curr_gw) {
					vnic_warn(discover->name, "failed to create hadmin GW\n");
					continue;
				} else {
					down_write(&discover->l_rwsem);
					list_add_tail(&curr_gw->list, &discover->gw_list);
					up_write(&discover->l_rwsem);
				}

				memcpy(curr_gw->info.vol_info.system_guid,
				       hadmin_entry->system_guid, GUID_LEN);
				memcpy(curr_gw->info.vol_info.gw_port_name,
				       hadmin_entry->eport_name,
				       VNIC_GW_PORT_NAME_LEN);
				if (used_guid)
					strcpy(curr_gw->info.vol_info.system_name,
					       NOT_AVAILABLE_STRING);
				else
					memcpy(curr_gw->info.vol_info.system_name,
					       hadmin_entry->system_name,
					       VNIC_SYSTEM_NAME_LEN);

				curr_gw->info.gw_port_id = hadmin_entry->gw_port_id;
				curr_gw->state = FIP_GW_HOST_ADMIN;
			}

			curr_gw->hadmin_gw = 1;
			fip_gw_update_hadmin_gw(curr_gw, hadmin_entry);
		} else if(curr_gw)
			fip_gw_update_hadmin_gw(curr_gw, hadmin_entry);

		list_del(&hadmin_entry->next);
		kfree(hadmin_entry);
	}

out:
	/* flush hadmin_tmp list and exit */
	list_for_each_entry_safe(hadmin_entry, hadmin_tmp, &hadmin_head, next)
		kfree(hadmin_entry);
}

static const char *gw_state_to_str(enum fip_gw_state state)
{
	switch (state) {
	case FIP_GW_CONNECTED:
		return "FIP_GW_CONNECTED";
	case FIP_GW_CTRL_PATH_QUERY:
		return "FIP_GW_CTRL_PATH_QUERY";
	case FIP_GW_DATA_PATH_QUERY:
		return "FIP_GW_DATA_PATH_QUERY";
	case FIP_GW_HOST_ADMIN:
		return "FIP_GW_HOST_ADMIN";
	case FIP_GW_SEND_SOLICIT:
		return "FIP_GW_SEND_SOLICIT";
	default:
		return "UNKNOWN";
	}
}

int fip_gw_sysfs_show(struct vnic_port *port, char *buf)
{
	struct fip_gw_data *gw;
	char *p = buf;
	struct fip_discover *discover;

	mutex_lock(&port->start_stop_lock);
	list_for_each_entry(discover, &port->fip.discover_list, discover_list) {

		down_read(&discover->l_rwsem);

		list_for_each_entry(gw, &discover->gw_list, list) {
			p += _sprintf(p, buf, "IOA_PORT      %s:%d\n",
				      gw->discover->port->dev->ca->name,
				      gw->discover->port->num);
			p += _sprintf(p, buf, "BX_NAME       %s\n",
				      gw->info.vol_info.system_name);
			if (!(*(u64 *)(gw->info.vol_info.system_guid)))
				p += _sprintf(p, buf, "BX_GUID       %s\n", NOT_AVAILABLE_STRING);
			else
				p += _sprintf(p, buf, "BX_GUID       "VNIC_GUID_FMT"\n",
					      VNIC_GUID_RAW_ARG(gw->info.vol_info.system_guid));
			p += _sprintf(p, buf, "EPORT_NAME    %s\n", gw->info.vol_info.gw_port_name);
			p += _sprintf(p, buf, "EPORT_ID      %u\n", gw->info.gw_port_id);
			p += _sprintf(p, buf, "STATE         %s\n", gw_state_to_str(gw->state));
			p += _sprintf(p, buf, "GW_TYPE       %s\n", gw->info.gw_type == GW_TYPE_LAG ?
				      "AGGREGATED" : "LEGACY");
			p += _sprintf(p, buf, "PKEY          0x%x\n", discover->pkey);
			p += _sprintf(p, buf, "ALL_VLAN      %s\n",
				      gw->state == FIP_GW_CONNECTED ?
				      (gw->info.all_vlan_gw ? "yes" : "no") : NOT_AVAILABLE_STRING);
			p += _sprintf(p, buf, "CTRL_SL       %d\n", gw->ctrl_prec.sl);
			p += _sprintf(p, buf, "DATA_SL       %d\n", gw->data_prec.sl);
			p += _sprintf(p, buf, "\n");
		}

		up_read(&discover->l_rwsem);
	}

	mutex_unlock(&port->start_stop_lock);
	return (p - buf);
}

static int fip_discover_rx_advertise_bh(struct fip_discover *discover,
					struct fip_gw_data *advertise_data)
{
	struct fip_gw_data *gw_data;
	int update_entry = 0;

	/* see if we received advertise packets from this GW before */
	gw_data = fip_find_gw_in_list(discover,
				      advertise_data->info.gw_port_id,
				      advertise_data->info.vol_info.gw_port_name,
				      advertise_data->info.gw_guid,
				      advertise_data->info.vol_info.system_guid,
				      advertise_data->info.vol_info.system_name, 0/* is_login */);

	/*
	 * GW not found in GW list. Create a new GW structure
	 * and add it to the GW list. 
	 */
	if (!gw_data) {
		gw_data = fip_discover_create_gw(discover);
		if (!gw_data) {
			vnic_dbg_fip(discover->name, "Could not create gw\n");
			return -ENOMEM;
		}
		gw_data->keep_alive_jiffies = jiffies;
		
		down_write(&discover->l_rwsem);
		list_add_tail(&gw_data->list, &discover->gw_list);
		up_write(&discover->l_rwsem);
		update_entry = 1;
	} else {
		gw_data->keep_alive_jiffies = jiffies;
		vnic_dbg_fip(discover->name, "gw_data->flush %d\n", gw_data->flush);
		if (gw_data->flush != FIP_NO_FLUSH)
			return 0;

		if (gw_data->state <= FIP_GW_SEND_SOLICIT)
			update_entry = 1;
	}

	/* If GW is in multicast state (based on received mcast packet),
	 * replace it with the newer up-to-date packet info.
	 */
	if (update_entry) {
		if (gw_data->state < FIP_GW_CTRL_PATH_QUERY) {
			down_write(&discover->l_rwsem);
			if (advertise_data->info.gw_prot_new)
				discover->new_prot_gws++;
			else
				discover->old_prot_gws++;
			up_write(&discover->l_rwsem);
		}
		memcpy(&gw_data->info, &advertise_data->info,
		       sizeof(struct fip_gw_data_info));
		if (gw_data->state < FIP_GW_SEND_SOLICIT)
			gw_data->state = vnic_sa_query? FIP_GW_CTRL_PATH_QUERY : FIP_GW_SEND_SOLICIT;
	} else {
		/* If the pc_id in the adv doesn't match the one
		   saved - there was a power cycle, so we want to close
		   the GW */
		if (advertise_data->info.ext_pc_id.valid &&
		    (advertise_data->info.ext_pc_id.power_cycle_id !=
		     gw_data->info.ext_pc_id.power_cycle_id)) {
			vnic_dbg_fip_p0(discover->name, "received advertisement with "
				        "pc_id %llu when expecting %llu. closing the GW",
				         advertise_data->info.ext_pc_id.power_cycle_id,
				         gw_data->info.ext_pc_id.power_cycle_id);
			fip_close_gw(gw_data, FIP_PARTIAL_FLUSH);
			goto no_repost;
		}

		/* TBD: enforce discard ?? */
		if (gw_data->info.gw_type != advertise_data->info.gw_type)
			vnic_dbg_fip_p0(discover->name, "gateway type must not change\n");

		/* update GW descriptors that do not require additional processing.
		   These will be updated as part of GW_MODIFY flow */
		mutex_lock(&gw_data->mlock);
		if (advertise_data->info.ext_pc_id.valid)
			memcpy(&gw_data->info.ext_pc_id, &advertise_data->info.ext_pc_id,
			       sizeof(gw_data->info.ext_pc_id));

		memcpy(&gw_data->info.vol_info, &advertise_data->info.vol_info,
		       sizeof(gw_data->info.vol_info));
		if (gw_data->info.ext_lag.valid) {
			gw_data->info.ext_lag.hash = advertise_data->info.ext_lag.hash;
			gw_data->info.ext_lag.ca = advertise_data->info.ext_lag.ca;
			gw_data->info.ext_lag.ca_thresh = advertise_data->info.ext_lag.ca_thresh;
			gw_data->info.ext_lag.weights_policy = advertise_data->info.ext_lag.weights_policy;
		}
		mutex_unlock(&gw_data->mlock);
	}

	/* if multicast advertisement received */
	if (advertise_data->info.flags & FIP_RCV_MULTICAST) {
		vnic_dbg_fip(discover->name, "FIP_RCV_MULTICAST ADVERTISE, state %d\n",
			     gw_data->state);
		/* we are beyond accepting mcast advertisement */
		if (gw_data->state > FIP_GW_SEND_SOLICIT)
			goto out;

		vnic_dbg_fip(discover->name, "received mcast advertise sending"
			     " ucast solicit to GW qpn %d lid %d flags 0x%x\n",
			     gw_data->info.gw_qpn, gw_data->info.gw_lid,
			     gw_data->info.flags);
	} else { /* unicast advertisement received */
		int ack_received = advertise_data->info.flags & FIP_GW_AVAILABLE;

		vnic_dbg_fip(discover->name, "received ucast advertise from GW "
			     "qpn %d lid %d flags 0x%x, ack_received %s "
			     "gw_num_vnics %d gw->state=%d, "
			     VNIC_GUID_FMT"\n",
			     gw_data->info.gw_qpn, gw_data->info.gw_lid,
			     gw_data->info.flags, ack_received ? "yes" : "no",
			     gw_data->info.gw_num_vnics, gw_data->state,
			     VNIC_GUID_RAW_ARG(gw_data->info.gw_guid));

		if (ack_received) {
			/* if this is first ACK received */
			switch (gw_data->state) {
			case FIP_GW_CTRL_PATH_QUERY:
				/*
				* in case we are in FIP_GW_CTRL_PATH_QUERY we wait until it completes
				* to move us to FIP_GW_SEND_SOLICIT
				*/
				break;
			case FIP_GW_SEND_SOLICIT:
				/* in case we received an ack in this state we move to DATA_PATH_QUERY */
				gw_data->state = vnic_sa_query ? FIP_GW_DATA_PATH_QUERY : FIP_GW_CONNECTED;
				break;
			case FIP_GW_CONNECTED:
				 /*
				* received an ACK and we are connected. we need to
				* check for changes in GW and apply them if needed
				*/
				if (!fip_gw_modified(gw_data, &advertise_data->info))
					gw_data->state = FIP_GW_CONNECTED;
				goto no_repost;
			default:
				break;
			}
		} else  /* !ack_received */ {
			fip_close_gw(gw_data, FIP_PARTIAL_FLUSH);
			goto no_repost;
		}
		/*
		 * we don't accept ACKs in transient states.
		 * This should not be a problem since crowded multiple ACKs
		 * is not an expected flow, and if the packets are similar
		 * (no updates) it doesn't matter anyway.
		 */
	}

out:
	vnic_dbg_fip(discover->name, "out gw->state=%d\n", gw_data->state);
	/*
	 * we will call the GW FSM to hadle
	 */
	cancel_delayed_work(&gw_data->gw_task);
	fip_discover_gw_fsm(&gw_data->gw_task.work);
no_repost:
	return 0;
}

/*
 * This function handles a single received packet that are expected to be
 * GW advertisements or login ACK packets. The function first parses the
 * packet and decides what is the packet type and then validates the packet
 * according to its type. This functions runs in ka_wq task context.
 */
void fip_discover_rx_packet(int *queue, struct fip_content *fc)
{
	*queue = 0;
	switch (fc->fh->subcode) {
	case FIP_GW_ADV_SUB_OPCODE:
	case FIP_GW_LOGIN_SUB_OPCODE:
		*queue = 1;
		break;
	default:
		break;
	}
}

/*
 * Print FIP syndrome number and string
 */
static void fip_print_syndrome(struct fip_vnic_data *vnic, int synd) {
	char *syndstr;

	switch (synd) {
	case FIP_SYNDROM_HADMIN_REJECT:
		syndstr = "FIP_SYNDROM_HADMIN_REJECT";
		break;
	case FIP_SYNDROM_GW_RESRC:
		syndstr = "FIP_SYNDROM_GW_RESRC";
		break;
	case FIP_SYNDROM_NO_NADMIN:
		syndstr = "FIP_SYNDROM_NO_NADMIN";
		break;
	case FIP_SYNDROM_UNRECOGNISED_HOST:
		syndstr = "FIP_SYNDROM_UNRECOGNISED_HOST";
		break;
	case FIP_SYNDROM_UNSUPPORTED_PARAM:
		syndstr = "FIP_SYNDROM_UNSUPPORTED_PARAM";
		break;
	case FIP_SYNDROM_GW_IS_LAG_MEMBER:
		syndstr = "FIP_SYNDROM_GW_IS_LAG_MEMBER";
		break;
	case FIP_SYNDROM_DUPLICATE_ADDRESS:
		syndstr = "FIP_SYNDROM_DUPLICATE_ADDRESS";
		break;
	default:
		syndstr = "FIP_OTHER";
	}

	vnic_warn(vnic->name, "SYNDROME 0x%x: %s\n",
		  synd, syndstr);
}

static void handle_login_packet(struct fip_discover *discover,
				struct fip_login_data *login_data)
{
	struct fip_gw_data *gw;
	struct fip_vnic_data *vnic;
	int mac_vlan_refused = 0;
	int synd;

	/* find the GW that this login belongs to */
	gw = fip_find_gw_in_list(discover,
				 login_data->port_id,
				 NULL,
				 login_data->guid,
				 NULL, NULL, 1/* is_login */);

	if (!gw){
		vnic_warn(discover->name,"dropping login ack with vnic_id:%d mac:"MAC_6_PRINT_FMT
				  "  BX port_id:%d GUID: "VNIC_GUID_FMT", GW not found!\n",
				  login_data->vnic_id,
				  MAC_6_PRINT_ARG(login_data->mac),
				  login_data->port_id,
				  VNIC_GUID_RAW_ARG(login_data->guid));
		return;
	}
	vnic = fip_vnic_find_in_list(gw, login_data->vnic_id,
				     login_data->mac,
				     login_data->vlan,
				     login_data->vp);
	if (!vnic){
		vnic_warn(discover->name,"dropping login ack with vnic_id:%d mac:"MAC_6_PRINT_FMT
				  "  BX port_id:%d GUID: "VNIC_GUID_FMT", vnic not found!\n",
				  login_data->vnic_id,
				  MAC_6_PRINT_ARG(login_data->mac),
				  login_data->port_id,
				  VNIC_GUID_RAW_ARG(login_data->guid));
		return;
	}

	/*
	 * For host administered vNICs we must have login and login ack
	 * macs equal and different than all zeros. login and and login
	 * ack must agree on vlan presence. And if vlan is present, vlans
	 * must be indentical. Otherwise, the request is rejected.
	 */
	if (vnic->hadmined) {
		if (!IS_ZERO_MAC(vnic->login_data.mac) &&
		    memcmp(vnic->login_data.mac, login_data->mac, ETH_ALEN)) {
			vnic_dbg_fip(discover->name, "fip_discover_rx_packet"
				     " host admined mac refused\n");
			mac_vlan_refused = 1;
		} else if (vnic->login_data.all_vlan_gw != login_data->all_vlan_gw)
			vnic_dbg_fip(discover->name,
				     "fip_discover_rx_packet host"
				     " host and GW disagree on all_vlan mode\n");
		/* If the host is not working in all_vlan_gw policy -
		   check the requested vlan against the accepted */
		else if (!gw->info.all_vlan_gw &&
			   (vnic->login_data.vp != login_data->vp ||
			    (login_data->vp == 1 &&
			     vnic->login_data.vlan != login_data->vlan))) {
			vnic_dbg_fip(discover->name,
				     "fip_discover_rx_packet host"
				     " admined vlan refused\n");
			mac_vlan_refused = 1;
		}
	}

	/* process a login packet for the specific vnic */
	synd = (int)login_data->syndrome;
	if (synd || mac_vlan_refused) {
		char *vnic_name = vnic->hadmined ?
			  (char *)vnic->interface_name : (char *)vnic->name;
		/* print syndrome as long as backlog limit is not exceeded */
		if (vnic->synd_backlog++ >= vnic_synd_backlog)
			return;

		vnic_warn(discover->name, "%s login failed "
			  "(mac "MAC_6_PRINT_FMT" vlan %d) "
			  "backlog %d/%d\n",
			  vnic_name,
			  MAC_6_PRINT_ARG(vnic->mac_cache),
			  (vnic->vlan_used ? vnic->vlan : -1),
			  vnic->synd_backlog, vnic_synd_backlog);

		if (mac_vlan_refused)
			vnic_warn(vnic->name, "MAC/VLAN refused\n");

		fip_print_syndrome(vnic, synd);

		if (synd == FIP_SYNDROM_UNRECOGNISED_HOST) {
			vnic_info("%s %s sending ucast solicit to Gateway\n",
				  discover->name, vnic_name);
			if(fip_solicit_send(gw->discover,
                                    FIP_DISCOVER_UCAST,
                                    gw->info.gw_qpn,
                                    gw->info.gw_lid,
                                    vnic_gw_ctrl_sl(gw),
                                    gw->info.gw_prot_new))
				vnic_warn(discover->name, "%s Failed to send ucast solicit\n", vnic_name);
		}
	} else {
		vnic->all_vlan_gw = !!((!vnic->hadmined && vnic->gw->info.all_vlan_gw) ||
				       (vnic->hadmined && vnic->login_data.all_vlan_gw));
		fip_vnic_login_ack_recv(vnic, login_data);
	}
}

/*
 * This function handles a single received packet that are expected to be
 * GW advertisements or login ACK packets. The function first parses the
 * packet and decides what is the packet type and then processes the packet
 * according to its type. This functions runs in task context.
 */
int fip_discover_rx_packet_bh(struct fip_discover *discover, struct fip_content *fc)
{
	struct fip_gw_data *advertise_data = NULL;
	struct fip_login_data *login_data = NULL;
	int rc;
	int ret = 0;

	switch (fc->fh->subcode) {
	case FIP_GW_ADV_SUB_OPCODE:
		advertise_data = kzalloc(sizeof *advertise_data, GFP_KERNEL);
		if (!advertise_data) {
			vnic_warn(discover->name,
				  "Failed to allocate %Zu bytes",
				  sizeof *advertise_data);
			return -ENOMEM;
		}

		rc = fip_advertise_parse_bh(discover, fc, advertise_data);
		if (!rc)
			ret = fip_discover_rx_advertise_bh(discover,
							   advertise_data);
		kfree(advertise_data);
		break;
   
	case FIP_GW_LOGIN_SUB_OPCODE:
		login_data = kzalloc(sizeof *login_data, GFP_KERNEL);
		if (!login_data) {
			vnic_warn(discover->name,
				  "Failed to allocate %Zu bytes",
				  sizeof *login_data);
			return -ENOMEM;
		}

		rc = fip_login_parse(discover, fc, login_data);
		if (!rc)
			handle_login_packet(discover, login_data);

		kfree(login_data);
		break;
	default:
		break;
	}

	return ret;
}

/*
 * This function is a callback called upon successful join to a
 * multicast group. The function checks if we have joined + attached
 * to all required mcast groups and if so moves the discovery FSM to solicit.
 */
static void fip_discover_mcast_connect_cb(struct vnic_mcast *mcaste, void *ctx)
{
	struct fip_discover *discover = mcaste->priv_data;

	if (mcaste->cur_attached && mcaste->req_attach) {
		vnic_dbg_parse(discover->name, "attached mask = 0x%lx, req mask = 0x%lx\n",
			       *mcaste->cur_attached, *mcaste->req_attach);
		if ((*mcaste->cur_attached & *mcaste->req_attach) !=
		    *mcaste->req_attach) {
			return;
		}
	}

	discover->discover_mcast_attached_jiffies = jiffies;
	set_bit(MCAST_ATTACHED, &discover->discover_mcast_state);
	/* in the case of a reconnect don't change state or send a solicit
	 * packet
	 */
	if (discover->state < FIP_DISCOVER_SOLICIT) {
		vnic_dbg_fip(discover->name, "fip_multicast_connected moved"
			     " state to solicit\n");
		spin_lock_irq(&discover->lock);
		if (discover->flush == FIP_NO_FLUSH) {
			/* delay sending solicit packet by 0-100 mSec */
			int rand_delay = jiffies % 100; /*get_random_int()*/
			discover->state = FIP_DISCOVER_SOLICIT;
			cancel_delayed_work(&discover->fsm_task);
			/* This is really (rand_delay / 1000) * HZ*/
			/* calls fip_discover_fsm() */
			queue_delayed_work(fip_wq, &discover->fsm_task,
					   (rand_delay * HZ) / 1000);
		}
		spin_unlock_irq(&discover->lock);
	}
	vnic_dbg_fip(discover->name, "discover_mcast_connect_cb done\n");
}

/*
 * This function is a callback called upon a mcast deattach event.
 * This event can be triggered due to discovery teardown or due to an async
 * event. Currently this code does not participate in the discovery's FSM.
*/
void fip_discover_mcast_deattach_cb(struct vnic_mcast *mcast, void *ctx)
{
//	struct vnic_mcast *mcast_other = ctx;
	struct fip_discover *discover = mcast->priv_data;

	discover->discover_mcast_detached_jiffies = jiffies;
	clear_bit(MCAST_ATTACHED, &discover->discover_mcast_state);

	vnic_dbg_fip(NULL, "fip_discover_mcast_deattach_cb\n");
}

/*
 * Try to connect to the relevant mcast groups. If one of the mcast failed
 * The function should be recalled to try and complete the join process
 * (for the mcast groups that the join process was not performed).
 * Note: A successful return of vnic_mcast_join means that the mcast join
 * started, not that the join completed. completion of the connection process
 * is asyncronous and uses a supplyed callback.
 */
static int fip_discover_mcast_connect(struct fip_discover *discover)
{
	struct vnic_mcast *mcaste_disc, *mcaste_sol, *mcaste;
	int rc;

	mcaste_disc = vnic_mcast_alloc(discover->port, &discover->req_attach, &discover->cur_attached);
	if (IS_ERR(mcaste_disc))
		return -EINVAL;

	mcaste_sol = vnic_mcast_alloc(discover->port, &discover->req_attach, &discover->cur_attached);
	if (IS_ERR(mcaste_sol)) {
		vnic_mcast_dealloc(mcaste_disc);
		return -EINVAL;
	}

	set_bit(FIP_MCAST_DISCOVER, &discover->req_attach);
	set_bit(FIP_MCAST_SOLICIT, &discover->req_attach);

	mcaste = mcaste_disc;
	mcaste->priv_data = discover;
	mcaste->attach_bit_nr = FIP_MCAST_DISCOVER;
	memcpy(mcaste->mac, ETH_BCAST_MAC, ETH_ALEN);
	memcpy(&mcaste->gid, fip_discover_mgid, GID_LEN);
	if (discover->pkey != 0xffff)
		*(u16 *)&mcaste->gid.raw[6] = htons(discover->pkey | 0x8000);
	memcpy(&mcaste->port_gid, &mcaste->gid, GID_LEN);
	mcaste->backoff = msecs_to_jiffies(VNIC_MCAST_BACKOFF_MSEC);
	mcaste->backoff_factor = VNIC_MCAST_BACKOF_FAC;
	mcaste->retry = VNIC_MCAST_ULIMIT_RETRY;
	mcaste->attach_cb = fip_discover_mcast_connect_cb;
	mcaste->detach_cb = fip_discover_mcast_deattach_cb;
	mcaste->attach_cb_ctx = mcaste_sol;
	mcaste->detach_cb_ctx = mcaste_sol;
	mcaste->pkey = discover->pkey;
	mcaste->qkey = VNIC_FIP_QKEY;
	mcaste->qp = discover->qp;
	mcaste->blocking = 0;
	mcaste->join_state = 1;
	rc = vnic_mcast_add(&discover->mcast_tree, mcaste);
	ASSERT(!rc);
	rc = vnic_mcast_attach(&discover->mcast_tree, mcaste); /* MCAST_RECEIVE_ONLY */
	ASSERT(!rc);

	mcaste = mcaste_sol;
	mcaste->priv_data = discover;
	mcaste->attach_bit_nr = FIP_MCAST_SOLICIT;
	memcpy(mcaste->mac, ETH_BCAST_MAC, ETH_ALEN);
	memcpy(&mcaste->gid, fip_solicit_mgid, GID_LEN);
	if (discover->pkey != 0xffff)
		*(u16 *)&mcaste->gid.raw[6] = htons(discover->pkey | 0x8000);
	memcpy(&mcaste->port_gid, &mcaste->gid, GID_LEN);
	mcaste->backoff = msecs_to_jiffies(VNIC_MCAST_BACKOFF_MSEC);
	mcaste->backoff_factor = VNIC_MCAST_BACKOF_FAC;
	mcaste->retry = VNIC_MCAST_ULIMIT_RETRY;
	mcaste->attach_cb = fip_discover_mcast_connect_cb;
	mcaste->detach_cb = fip_discover_mcast_deattach_cb;
	mcaste->attach_cb_ctx = mcaste_disc;
	mcaste->detach_cb_ctx = mcaste_disc;
	mcaste->pkey = discover->pkey;
	mcaste->qkey = VNIC_FIP_QKEY;
	mcaste->qp = discover->qp;
	mcaste->blocking = 0;
	mcaste->join_state = 1;
	mcaste->sender_only = 1;
	rc = vnic_mcast_add(&discover->mcast_tree, mcaste);
	ASSERT(!rc);
	rc = vnic_mcast_attach(&discover->mcast_tree, mcaste); /* MCAST_SEND_ONLY */
	ASSERT(!rc);

	return 0;
}

int fip_discover_mcast_reattach(struct fip_discover *discover,
				struct vnic_port *port)
{
	int flush;

	spin_lock_irq(&discover->lock);
	flush = discover->flush;
	spin_unlock_irq(&discover->lock);

	if (flush == FIP_NO_FLUSH &&
	    discover->state > FIP_DISCOVER_INIT) {
		vnic_tree_mcast_detach(&discover->mcast_tree);
		vnic_tree_mcast_attach(&discover->mcast_tree);
	}
	return 0;
}

static void fip_discover_ctrl_path_query_complete(
					int status,
					struct ib_sa_path_rec *pathrec,
					void *context)
{
	struct fip_gw_data *gw = context;
	vnic_dbg_fip_p0(gw->discover->name, "fip ctrl path query complete status=%d\n", status);
	if (!status) {
		vnic_dbg_fip_p0(gw->discover->name, "fip ctrl path query success srcgid:"VNIC_GUID_FMT" dgid:"VNIC_GUID_FMT"\n",
						VNIC_GUID_RAW_ARG(pathrec->sgid.raw+8),
						VNIC_GUID_RAW_ARG(pathrec->dgid.raw+8));
		gw->ctrl_prec = *pathrec;
		fip_discover_gw_fsm_move(gw, FIP_GW_SEND_SOLICIT);
	} else {
		vnic_dbg_fip_p0(gw->discover->name, "fip ctrl path query FAILED ret=%d\n", status);
		gw->query_id = -1; /* this will cause a retry */
	}
	complete(&gw->query_comp);
}

static void fip_discover_data_path_query_complete(
						int status,
						struct ib_sa_path_rec *pathrec,
						void *context)
{
	struct fip_gw_data *gw = context;
	vnic_dbg_fip_p0(gw->discover->name, "fip data path query complete status=%d\n", status);
	if (!status) {
		struct ib_sa_path_rec old_pathrec;
		struct fip_vnic_data *vnic;
		vnic_dbg_fip_p0(gw->discover->name, "fip data path query success srcgid:"VNIC_GUID_FMT" dgid:"VNIC_GUID_FMT"\n",
						VNIC_GUID_RAW_ARG(pathrec->sgid.raw+8),
						VNIC_GUID_RAW_ARG(pathrec->dgid.raw+8));
		old_pathrec = gw->data_prec;
		gw->data_prec = *pathrec;
		if (old_pathrec.sl != gw->data_prec.sl) {
			/* in case of SL change close the vnic to relogin with the new SL */
			vnic_info("[%s] %s %s Data SL changed from %d to %d\n",
					  gw->info.vol_info.system_name,
					  gw->discover->port->name,
					  gw->info.vol_info.gw_port_name,
					  old_pathrec.sl, gw->data_prec.sl);
			 list_for_each_entry(vnic, &gw->vnic_list, gw_vnics) {
                if (vnic->flush != FIP_FULL_FLUSH && vnic->state >= FIP_VNIC_LOGIN)
					fip_vnic_close(vnic, FIP_PARTIAL_FLUSH);
			}
		}
		fip_discover_gw_fsm_move(gw, FIP_GW_CONNECTED);
	} else {
		vnic_dbg_fip_p0(gw->discover->name, "fip data path query FAILED ret=%d\n", status);
		gw->query_id = -1; /* this will cause a retry */
	}
	complete(&gw->query_comp);
}

static int fip_discover_path_query(struct fip_gw_data *gw, int is_data_sl)
{
	ib_sa_comp_mask comp_mask;
	struct ib_sa_path_rec p_rec;
	void(*callback)(int status, struct ib_sa_path_rec *resp, void *context);

	vnic_dbg_fip_p0(gw->discover->name, "fip path query %d of GW lid:%d sl=%d GID:"VNIC_GUID_FMT" SID=%llx data_path=%d!\n",
				 gw->query_path_cnt,
				 gw->info.gw_lid,
				 gw->info.gw_sl,
				 VNIC_GUID_RAW_ARG(gw->info.gw_guid),
				 is_data_sl ? EOIB_SERVICE_ID : EOIB_CTRL_SERVICE_ID,
				 is_data_sl);

	comp_mask =      IB_SA_PATH_REC_SERVICE_ID  |
					 IB_SA_PATH_REC_DGID         |
					 IB_SA_PATH_REC_SGID         |
					 IB_SA_PATH_REC_REVERSIBLE  |
					 IB_SA_PATH_REC_PKEY;

	callback = is_data_sl ? fip_discover_data_path_query_complete : fip_discover_ctrl_path_query_complete;
	memset(&p_rec, 0, sizeof(p_rec));

	p_rec.service_id = is_data_sl ? cpu_to_be64(EOIB_SERVICE_ID) : cpu_to_be64(EOIB_CTRL_SERVICE_ID);
	p_rec.sgid = gw->discover->port->gid;
	/* copy the subnet prefix from source gid */
	memcpy(p_rec.dgid.raw, p_rec.sgid.raw, 8);
	/* copy gw dgid */
	memcpy(p_rec.dgid.raw+8, gw->info.gw_guid,8);
	p_rec.pkey = cpu_to_be16(gw->discover->pkey);
	p_rec.reversible = cpu_to_be32(1);

	if (gw->query_id >= 0 && !IS_ERR(gw->pquery) && gw->pquery) {
		ib_sa_cancel_query(gw->query_id, gw->pquery);
		return -1; /* retry later */
	}

	init_completion(&gw->query_comp);
	gw->query_path_cnt++;
	gw->query_id = -1;
	gw->pquery = ERR_PTR(-ENODATA);

	gw->query_id =
		ib_sa_path_rec_get(&vnic_sa_client,
						   gw->discover->port->dev->ca,
						   gw->discover->port->num,
						   &p_rec,
						   comp_mask,
						   2000 /*TOUT*/,
						   GFP_KERNEL,
						   callback,
						   gw,
						   &gw->pquery);
	if (gw->query_id < 0) {
		complete(&gw->query_comp);
		vnic_dbg_fip_p0(gw->discover->name, "ib_sa_path_rec_get failed, error %d\n", gw->query_id);
		gw->pquery = ERR_PTR(-ENODATA);
	}
	return gw->query_id;
}

void fip_discover_gw_fsm_move(struct fip_gw_data *gw, enum fip_gw_state state)
{
	cancel_delayed_work(&gw->gw_task);
	if (gw->pquery && !IS_ERR(gw->pquery) && gw->query_id >= 0)
		ib_sa_cancel_query(gw->query_id, gw->pquery);

	gw->state = state;
	gw->query_id = -1;
	gw->query_path_cnt = 0;
	queue_delayed_work(fip_wq, &gw->gw_task, 0);
}


static void fip_discover_gw_fsm(struct work_struct *work)
{
	struct fip_gw_data *curr_gw =
		container_of(work, struct fip_gw_data, gw_task.work);
	unsigned long next_wakeup = curr_gw->info.gw_adv_period;
	unsigned long rand = jiffies % 100 + 1;
	int ret;

	if (curr_gw->flush != FIP_NO_FLUSH)
		return;

	if (test_bit(MCAST_ATTACHED,
		     &curr_gw->discover->discover_mcast_state)) {
		if (time_after(jiffies, curr_gw->keep_alive_jiffies + next_wakeup)) {
			if (time_after(jiffies,
				       curr_gw->discover->discover_mcast_attached_jiffies
				        + next_wakeup)) {
				fip_close_gw(curr_gw, FIP_PARTIAL_FLUSH);
				return;
			}
		}
	} else {
		/* close gw if 1 minute has elapsed since mcast detach */
		if (time_after(jiffies,
			       curr_gw->discover->discover_mcast_detached_jiffies
				+ 60*HZ)) {
			fip_close_gw(curr_gw, FIP_PARTIAL_FLUSH);
			return;
		}
	}

	switch (curr_gw->state) {
	case FIP_GW_HOST_ADMIN:
		break;
	case FIP_GW_CTRL_PATH_QUERY:
		if (curr_gw->query_path_cnt && curr_gw->query_id >= 0) {
			/* PATH query is running */
			next_wakeup = msecs_to_jiffies(100);
			break;
		}
		ret = fip_discover_path_query(curr_gw, 0/*ctrl SL*/);
		if (ret < 0)
			vnic_dbg_fip_p0(curr_gw->discover->name, "Query ctrl path Failed : retry num %d ...\n", curr_gw->query_path_cnt);
		next_wakeup = msecs_to_jiffies(100);
		break;

	case FIP_GW_SEND_SOLICIT:
		curr_gw->query_path_cnt = 0;
		curr_gw->query_id = -1;
		curr_gw->pquery = ERR_PTR(-ENODATA);
		vnic_dbg_fip(curr_gw->discover->name, "DISCOVER_LOGIN FIP_GW_SEND_SOLICIT\n");
		vnic_dbg_parse(curr_gw->discover->name, "new protocol %d\n", curr_gw->info.gw_prot_new);
		ret = fip_solicit_send(curr_gw->discover, FIP_DISCOVER_UCAST,
							   curr_gw->info.gw_qpn,
							   curr_gw->info.gw_lid,
							   vnic_gw_ctrl_sl(curr_gw),
							   curr_gw->info.gw_prot_new);
		if (ret)
			next_wakeup = (100 + rand * HZ) / 200;
		else
			next_wakeup = (100 + rand * HZ) / 25;
		break;

	case FIP_GW_DATA_PATH_QUERY:
		if (curr_gw->query_path_cnt && curr_gw->query_id >= 0) {
			/* PATH query is running */
			next_wakeup = msecs_to_jiffies(100);
			break;
		}
		ret = fip_discover_path_query(curr_gw, 1/*data SL*/);
		if (ret < 0)
			vnic_dbg_fip_p0(curr_gw->discover->name, "Query data path Failed : retry num %d ...\n", curr_gw->query_path_cnt);
		next_wakeup = msecs_to_jiffies(100);
		break;

	case FIP_GW_CONNECTED:
		vnic_dbg_fip(curr_gw->discover->name, "DISCOVER_LOGIN: GW_CONNECTED!!!\n");
		/* test vnic status */
		fip_gw_create_vnics(curr_gw);
		break;
	default:
		ASSERT(0);
		break;
	}

	/* go to sleep until time out. We expect that we will be awaken by
	 * RX packets and never get to wake up due to timeout
	 */
	cancel_delayed_work(&curr_gw->gw_task);
	queue_delayed_work(fip_wq, &curr_gw->gw_task, next_wakeup);
}

static int is_new_solicit_prot(struct fip_discover *discover)
{
	vnic_dbg_parse(discover->name, "new gw %d, old gw %d\n",
		       discover->new_prot_gws, discover->old_prot_gws);

	if (!discover->old_prot_gws) {
		if (!discover->new_prot_gws) {
			/* mcast solicit sent before any
			 * advertise packets arrive. Use old format.
			 */
			return 0;
		} else
			return 1;
	}
	return 0;
}

/*
 * This is the discover finite state machine that runs the
 * advertise and solicit packet exchange of the discovery
 * proccess.
 * It is assumed that this function is only called from work queue
 * task context (for locking)
 */
static void fip_discover_fsm(struct work_struct *work)
{
	struct fip_discover *discover =
		container_of(work, struct fip_discover, fsm_task.work);
	struct vnic_port *port = discover->port;
	int recall_time = -1, flush = discover->flush;

	/* we got a flush request and we have not performed it yet */
	if ((flush != FIP_NO_FLUSH) &&
	     discover->state != FIP_DISCOVER_OFF) {
		vnic_dbg_fip(discover->name, "discover_fsm switching to OFF\n");

		recall_time = DELAYED_WORK_CLEANUP_JIFFS * 2;


		if (discover->state != FIP_DISCOVER_CLEAR) {
			fip_free_gw_list(discover, flush);
			discover->state = FIP_DISCOVER_CLEAR;
		}

		/* if we open GWs we will test again later */
		if (!fip_free_gw_done(discover, flush)) {
			vnic_dbg_fip(discover->name, "fip_free_gw_list not done, recalling \n");
			goto recall_fsm;
		}

		if (delayed_work_pending(&discover->cleanup_task))
			goto recall_fsm;

		vnic_dbg_fip(discover->name, "fip_free_gw_list done \n");
		vnic_dbg_mark();
		vnic_mcast_del_all(&discover->mcast_tree);
		vnic_dbg_mark();
		discover->state = FIP_DISCOVER_OFF;

		/* signal the unload to continue */
		complete(&discover->flush_complete);
		return;
	}

	if (discover->state == FIP_DISCOVER_OFF)
		return;

	if (!port->attr.lid) {
		recall_time = 1 * HZ;
		goto recall_fsm;
	}

	switch (discover->state) {
        int new_prot;

	case FIP_DISCOVER_INIT:
		vnic_dbg_fip(discover->name, "FIP_DISCOVER_INIT\n");
		/* in init try and join the discover multicast group
		 * This is a preliminary request for all other progress
		 * will eventually call fip_discover_mcast_connect_cb()
		 */
		if (fip_discover_mcast_connect(discover)) {
			vnic_warn(discover->name, "fip_discover_mcast_connect() "
				  "failed\n");
			recall_time = 1 * HZ;
		}
		break;

	case FIP_DISCOVER_SOLICIT:
		new_prot = is_new_solicit_prot(discover);
		vnic_dbg_fip(discover->name, "DISCOVER_SOLICIT\n");

		/* send multicast solicit of type fip, if send is
		 * successfull move to login state and await advertise
		 * packets. It TX fail then retry
		 */
		fip_solicit_send(discover, FIP_DISCOVER_MCAST, 0, 0, 0, new_prot);
		recall_time = FIP_RESOLICIT_TIME * HZ;

		break;

	case FIP_DISCOVER_OFF:
	default:
		ASSERT(0);
		break;

	}

recall_fsm:
	if (recall_time >= 0)
		queue_delayed_work(fip_wq, &discover->fsm_task, recall_time);

	return;
}

