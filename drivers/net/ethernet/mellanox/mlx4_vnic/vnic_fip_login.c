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

#ifndef work_pending /* back-port */
#define work_pending(_work) test_bit(0, &(_work)->pending)
#endif

enum {
	VNIC_LOGIN_REG_NETDEV_PENDING,
	VNIC_LOGIN_REG_NETDEV_DONE,
	VNIC_LOGIN_DESTROY_PENDING,
	VNIC_LOGIN_DESTROY_DONE,
	VNIC_LOGIN_DESTROY_FULL
};

static int fip_vnic_rings_create(struct vnic_port *port,
				 struct fip_vnic_data *vnic);
static void fip_vnic_rings_destroy(struct fip_vnic_data *vnic);
static void fip_vnic_recv(struct fip_vnic_data *vnic);

#ifdef _BP_HR_TIMER
int fip_vnic_keepalive(struct hrtimer * timer);
#else
enum hrtimer_restart fip_vnic_keepalive(struct hrtimer * timer);
#endif
int fip_vnic_keepalive_send(struct fip_vnic_data *vnic, int source);


#define QUEUE_VNIC_DWORK(vnic, task, time)			\
do {								\
	unsigned long flags;					\
	spin_lock_irqsave(&vnic->lock, flags);			\
	if (likely(vnic->flush == FIP_NO_FLUSH))		\
		queue_delayed_work(fip_wq, task, time);  \
	spin_unlock_irqrestore(&vnic->lock, flags);		\
} while(0)

#define REQUEUE_VNIC_DWORK(vnic, task, time)			\
do {								\
	cancel_delayed_work(task);				\
	QUEUE_VNIC_DWORK(vnic, task, time);			\
} while(0);


/*
 * Look for a vnic in the GW vnic list. The search key used is either the vnic_id
 * that is unique, or the mac+vlan pair. A match on either key will result in the
 * return of the vnic. both keys are nesesary because host assigned delete
 * flow might not have access to the vnic_id. The search disregards vnics that
 * are undergoing full flush (they will be removed soon).
*/
struct fip_vnic_data *fip_vnic_find_in_list(struct fip_gw_data *gw, u16 vnic_id,
					    u8 *mac, u16 vlan, u8 vlan_used)
{
	struct fip_vnic_data *vnic;
	int use_mac = mac ? 1 : 0;
	int vlan_match;

	ASSERT(gw);

	if (list_empty(&gw->vnic_list))
		return NULL;

	/* do not use MAC 0:..:0 for vnic matches */
	if (use_mac)
		use_mac = !IS_ZERO_MAC(mac);

	list_for_each_entry(vnic, &gw->vnic_list, gw_vnics) {
		if (vnic->flush == FIP_FULL_FLUSH)
			continue;

		if (vnic->vnic_id == vnic_id)
			return vnic;

		if (vlan_used != vnic->login_data.vp)
			continue;

		vlan_match = !vlan_used ||
			(vlan_used && (vlan == vnic->login_data.vlan));

		if ((use_mac && !memcmp(vnic->login_data.mac, mac, ETH_ALEN)) &&
		    vlan_match)
			return vnic;
	}
	return NULL;
}

/*
 * This function handles completions of both TX and RX
 * packets of vnics. RX packets are unmapped lightly parsed moved to a list
 * and passed to thread processing. TX packets are unmapped and freed.
 * Note: this function is called from interrupt context
 */
static void fip_vnic_comp(struct ib_cq *cq, void *vnic_ptr)
{
	struct fip_vnic_data *vnic = vnic_ptr;

	/* handle completions. On RX packets this will call vnic_recv
	 * from thread context to continue processing */
	if (fip_comp(vnic->port, vnic->cq, &vnic->rx_ring,
		     &vnic->tx_ring, vnic->name))
		fip_vnic_recv(vnic);

	fip_vnic_keepalive_send(vnic, 0);
}

/*
 * read the state of the gw eport. This can be done from any context and therefore
 * requires protection.
*/
int fip_vnic_get_eport_state(struct fip_vnic_data *vnic)
{
	int i;

	if (no_bxm)
		return 1;

	if (vnic->gw->info.gw_type == GW_TYPE_LAG) {
		for (i = 0; i < MAX_LAG_MEMBERS; i++) {
			if (!(vnic->lm.used_bitmask & 1 << i))
				continue;

			if (vnic->lm.memb[i].eport_state)
				return 1;
		}
		return 0;
	} else {
		return atomic_read(&vnic->eport_state);
	}
}

/*
 * get GW info funcs.
*/
int fip_vnic_get_bx_name(struct fip_vnic_data *vnic, char *buff)
{
	struct fip_gw_data *gw = vnic->gw;
	struct fip_gw_volatile_info tmp_info;
	int rc;

	if (!gw)
		return -EINVAL;

	mutex_lock(&gw->mlock);
	memcpy(&tmp_info, &gw->info.vol_info, sizeof(tmp_info));
	mutex_unlock(&gw->mlock);

	rc = sprintf(buff, "%s", tmp_info.system_name);

	return rc < 0 ? rc : 0;
}

int fip_vnic_get_bx_guid(struct fip_vnic_data *vnic, char *buff)
{
	struct fip_gw_data *gw = vnic->gw;
	struct fip_gw_volatile_info tmp_info;
	void *rc;

	memset(buff, 0, sizeof *buff);

	if (!gw)
		return -EINVAL;

	mutex_lock(&gw->mlock);
	memcpy(&tmp_info, &gw->info.vol_info, sizeof(tmp_info));
	mutex_unlock(&gw->mlock);

	rc = memcpy(buff, tmp_info.system_guid, GUID_LEN);

	return rc ? 0 : -EINVAL;
}

int fip_vnic_get_all_vlan_mode(struct fip_vnic_data *vnic, char *buff)
{
	struct fip_gw_data *gw = vnic->gw;
	int rc;

	if (!gw)
		return -EINVAL;

	rc = sprintf(buff, "%s", gw->info.all_vlan_gw ? "yes" : "no");

	return rc < 0 ? rc : 0;
}

int fip_vnic_get_eport_name(struct fip_vnic_data *vnic, char *buff)
{

	struct fip_gw_data *gw = vnic->gw;
	struct fip_gw_volatile_info tmp_info;
	int rc;

	if (!gw)
		return -EINVAL;

	mutex_lock(&gw->mlock);
	memcpy(&tmp_info, &gw->info.vol_info, sizeof(tmp_info));
	mutex_unlock(&gw->mlock);

	rc = sprintf(buff, "%s", tmp_info.gw_port_name);

	return rc < 0 ? rc : 0;
}

u8 fip_vnic_get_bx_sl(struct fip_vnic_data *vnic)
{
	return vnic->gw->info.gw_sl;
}

/*
 * get GW info funcs.
*/
int fip_vnic_get_gw_type(struct fip_vnic_data *vnic)
{
	struct fip_gw_data *gw = vnic->gw;
	int lag = 0;

	if (!gw)
		return -EINVAL;

	lag = gw->info.gw_type == GW_TYPE_LAG;

	return lag;
}

/*
 * get GW info funcs.
*/
int fip_vnic_get_lag_eports(struct fip_vnic_data *vnic, char *buf)
{
	struct fip_gw_data *gw = vnic->gw;
	int i;
	struct lag_member *member;
	char *p = buf;

	if (!gw)
		return -EINVAL;

	if (gw->info.gw_type != GW_TYPE_LAG)
		return -EINVAL;

	p += _sprintf(p, buf, "LAG_MEMBER_INFORMATION:\n");
	for (i=0; i<MAX_LAG_MEMBERS; i++) {
		if (!(vnic->lm.used_bitmask & 1 << i))
			continue;

		member = &vnic->lm.memb[i];
		p += _sprintf(p, buf, "  %.2d ID=%.3X LID=%4X QPN=%8X STATE=%s\n",
			      i, member->gw_port_id, member->lid, member->qpn,
			      member->eport_state ? "UP" : "DOWN");
	}

	return p - buf;
}

/*
 * process an incoming login ack packet. The packet was already parsed and
 * its data was placed in *data. The function creates RX and TX rings for the
 * vnic and starts the multicast join procedure.
 * This function should not be called for packets other then login ack packets.
 */
void fip_vnic_login_ack_recv(struct fip_vnic_data *vnic,
			     struct fip_login_data *data)
{
	/* we allow login acks only in wait for ack in other states
	 * we ignore them */
	if (vnic->state != FIP_VNIC_WAIT_4_ACK) {
		vnic_dbg_fip_v(vnic->name,
			       "vnic_login_ack_recv in state other"
			       " then FIP_VNIC_WAIT_4_ACK state %d\n",
			       vnic->state);
		return;
	}

	/* For LAG vnics, process login ack member data */
	if (vnic->gw->info.gw_type == GW_TYPE_LAG)
		handle_member_update(vnic, &data->lagm);

	memcpy(&vnic->login_data, data, sizeof(vnic->login_data));

	vnic->state = FIP_VNIC_RINGS_INIT;

	/* calls fip_vnic_fsm() */
	cancel_delayed_work(&vnic->vnic_task);
	fip_vnic_fsm(&vnic->vnic_task.work);
	// REQUEUE_VNIC_DWORK(vnic, &vnic->vnic_task, 0);
	return;
}

/*
 * This is a helper function we use in order to move the login create
 * to another context so we don't block the fip thread for too long.
 * The call stack triggered by this function calls register_netdev that
 * might block for some time when netdev are removed in parallel. This
 * stalls the fip_wq which causes KA not to be sent. 
*/
void fip_vnic_login_create(struct work_struct *work)
{
	struct fip_vnic_data *vnic =
		container_of(work, struct fip_vnic_data, vnic_login_create_task);
	char *name = NULL;
	int rc;

	if (vnic->hadmined)
		name = vnic->interface_name;

	rc = vnic_login_register_netdev(vnic, vnic->mac_cache, name);

	spin_lock_irq(&vnic->lock);
	clear_bit(VNIC_LOGIN_REG_NETDEV_PENDING, &vnic->login_status);
	if (!rc)
		set_bit(VNIC_LOGIN_REG_NETDEV_DONE, &vnic->login_status);
	spin_unlock_irq(&vnic->lock);
}

/*
 * Test if the create request posted earlier terminated or not.
 * If yes and successfully returns 0, if still pending returns
 * -EAGAIN , and if failed returns -EINVAL. if retry is set
 * it will requeue a create attempt and try again. In this case 
 * the function will return -EAGAIN. 
*/
static int fip_vnic_test_login(struct fip_vnic_data *vnic, int retry)
{
	int ret = 0;

	spin_lock_irq(&vnic->lock);

	if (!test_bit(VNIC_LOGIN_REG_NETDEV_DONE, &vnic->login_status)) {
		/* queue retry login create request */
		if (retry) {
			if (!test_and_set_bit(VNIC_LOGIN_REG_NETDEV_PENDING,
					      &vnic->login_status)) {
				memcpy(vnic->mac_cache, vnic->login_data.mac, ETH_ALEN);
				vnic->vlan_used = vnic->login_data.vp;
				vnic->vlan = vnic->login_data.vlan;
				vnic->all_vlan_gw = vnic->login_data.all_vlan_gw;

				/* calls fip_vnic_login_create() */
				if (vnic->flush == FIP_NO_FLUSH)
					queue_work(login_wq, &vnic->vnic_login_create_task);
			}
			ret = -EAGAIN;
		} else {
			if (test_bit(VNIC_LOGIN_REG_NETDEV_PENDING,
				     &vnic->login_status))
                                ret = -EAGAIN;
			else
				ret = -EINVAL;
		}
	} 
	spin_unlock_irq(&vnic->lock);

	return ret;
}


/*
 * This function should be called when the building of a vhub context
 * table is done and the vnic state should transition to CONNECTED.
 */
int fip_vnic_tbl_done(struct fip_vnic_data *vnic)
{
	vnic->vhub_table.state = VHUB_TBL_UP2DATE;
	vnic->vhub_table.tusn = vnic->vhub_table.main_list.tusn;

	if (vnic->state <= FIP_VNIC_VHUB_DONE)
		vnic->state = FIP_VNIC_VHUB_DONE;
	else 
		vnic->state = FIP_VNIC_VHUB_WRITE;

	cancel_delayed_work(&vnic->vnic_task);
	fip_vnic_fsm(&vnic->vnic_task.work);
	return 0;
}

/*
 * This function runs in interrupt context
 * It does sanity checking of the packet, moves it to a list and passes
 * handleing to a thread.
 */
static void fip_vnic_recv(struct fip_vnic_data *vnic)
{
	struct fip_ring *rx_ring = &vnic->rx_ring;
	int ret, length;
	u32 vhub_id;
	void *mem;
	int queue_packet = 0;
	int one_or_more_queued = 0;
	int index;
	int err;

	while (rx_ring->head != rx_ring->tail) {
		struct fip_content *fc;

		queue_packet = 0;
		index = rx_ring->tail & (vnic->rx_ring.size - 1);

		if (rx_ring->ring[index].entry_posted == 0)
			goto repost;

		mem = rx_ring->ring[index].mem;
		length = rx_ring->ring[index].length;


		fc = kzalloc(sizeof *fc, GFP_ATOMIC);
		if (!fc) {
			vnic_warn(vnic->name, "kzalloc failed\n");
			goto repost;
		}

		err = fip_packet_parse(vnic->port, mem + IB_GRH_BYTES, length - IB_GRH_BYTES, fc);
		if (err) {
			vnic_warn(vnic->name, "packet parse failed\n");
			kfree(fc);
			goto repost;
		}

		switch (fc->fh->subcode) {
		case FIP_GW_UPDATE_SUB_OPCODE:
			if (fc->fvu) {
				vhub_id = be32_to_cpu(fc->fvu->state_vhub_id) & 0xffffff;
				if (vnic->login_data.vhub_id == vhub_id)
					queue_packet = 1;
			}

			break;
		case FIP_GW_TABLE_SUB_OPCODE:
			if (vnic->state >= FIP_VNIC_VHUB_INIT &&
			    vnic->vhub_table.state == VHUB_TBL_INIT) {
				/* handle vhub context table packets */
				if (fc->fvt) {
					vhub_id = be32_to_cpu(fc->fvt->vp_vhub_id) & 0xffffff;
					if (vnic->login_data.vhub_id == vhub_id)
						queue_packet = 1;
				}
			}
			break;
		default:
			vnic_dbg_fip_v(vnic->name,
				       "received unexpected format packet\n");
			break;
		}

		if (queue_packet && (likely(vnic->flush == FIP_NO_FLUSH))) {
			struct fip_rcv_pkt *rcv;
			struct fip_ring_entry me;

			/* record packet time for heart beat */
			vnic->keep_alive_jiffs = jiffies;
			length -= IB_GRH_BYTES;
			rcv = kzalloc(sizeof *rcv, GFP_ATOMIC);
			if (!rcv) {
				vnic_warn(vnic->name, "failed kmalloc\n");
				kfree(fc);
				goto repost;
			}

			/* replace it with new entry, and queue old one */
			err = alloc_map_fip_buffer(vnic->port->dev->ca, &me,
						   FIP_UD_BUF_SIZE(vnic->port->max_mtu_enum),
						   GFP_ATOMIC);
			if (err) {
				vnic_warn(vnic->name, "alloc_map_fip_buffer failed\n");
				kfree(fc);
				kfree(rcv);
				goto repost;
			}

			/* unmap old entry */
			ib_dma_unmap_single(vnic->port->dev->ca,
					    rx_ring->ring[index].bus_addr,
					    FIP_UD_BUF_SIZE(vnic->port->max_mtu_enum),
					    DMA_FROM_DEVICE);

			rx_ring->ring[index] = me;
			rcv->fc = fc;
			rcv->length = length;
			rcv->mem = mem;
			spin_lock(&vnic->vnic_rcv_list.lock);
			list_add_tail(&rcv->list, &vnic->vnic_rcv_list.list);
			spin_unlock(&vnic->vnic_rcv_list.lock);
			one_or_more_queued++;
		} else
			kfree(fc);
repost:
		ret = fip_post_receive(vnic->port, vnic->qp,
				       FIP_UD_BUF_SIZE(vnic->port->max_mtu_enum),
				       index, rx_ring->ring + index, vnic->name);
		if (ret)
			vnic_warn(vnic->name, "fip_post_receive ret %d\n", ret);

		rx_ring->tail++;
	}

	if (one_or_more_queued && (likely(vnic->flush == FIP_NO_FLUSH))) {
		/* calls fip_vnic_recv_bh() */
		queue_work(fip_wq, &vnic->vnic_pkt_rcv_task_bh);
	}

	return;
}

void fip_vnic_recv_list_flush(struct fip_vnic_data *vnic)
{
	struct list_head vnic_recv_local;
	struct fip_rcv_pkt *rcv, *rcv1;
	unsigned long flags;

	INIT_LIST_HEAD(&vnic_recv_local);

	spin_lock_irqsave(&vnic->vnic_rcv_list.lock, flags);
	list_replace_init(&vnic->vnic_rcv_list.list, &vnic_recv_local);
	spin_unlock_irqrestore(&vnic->vnic_rcv_list.lock, flags);

	list_for_each_entry_safe(rcv, rcv1, &vnic_recv_local, list) {
		list_del(&rcv->list);
		kfree(rcv);
	}
	return;
}

void lag_ctx_clear(struct fip_vnic_data *vnic)
{
	memset(&vnic->lm, 0, sizeof (vnic->lm));
}

/*
 * Handle the GW eport member info for a LAG GW. The function compares the
 * member information to previous membership information that is stored in the
 * vnic. The data path info is updated only after the login ack info was
 * updated to prevent race conditions. 
 * The vnic contains a local cache of the member info. The cache is updated
 * in all cases other then if the write to the data path failed. If the write
 * failed we will not update the cache and rely on periodic updates packets
 * for the retry.
 * There are 4 possible flows per member entry:
 * 1. the entry is cached in the vnic but not in the packet - remove from vnic
 * 2. the entry is not cached in the vnic but is in the packet - add to vnic,
 * 3. entry is in vnic and in packet but different params - modifiy vnic
 * 4. entry is in vnic and in packet and with similar params - do nothing
*/
int handle_member_update(struct fip_vnic_data *vnic, struct lag_members *lm)
{
	int i, j;
	char packet_used[MAX_LAG_MEMBERS];
	char vnic_used[MAX_LAG_MEMBERS];
	struct lag_member *vnic_mem, *pkt_mem;
	int last_bit = 0;
	#define EMPTY_ENTRY (char)0xff
	/* we only update data path  with new info after certain stage */
	int write_through = !!(vnic->state >= FIP_VNIC_VHUB_WRITE);
	int skip;
	struct lag_properties lag_prop;
	struct vnic_login *login = vnic->login;

	memset(packet_used, EMPTY_ENTRY, sizeof(packet_used));
	memset(vnic_used, EMPTY_ENTRY, sizeof(vnic_used));

        /* if LAG is not enabled, or it's a child vNic, abort */
	if (!vnic->gw->info.ext_lag.valid || vnic->parent_used)
		return -EINVAL;

	mutex_lock(&vnic->gw->mlock);
	lag_prop.ca = vnic->gw->info.ext_lag.ca;
	lag_prop.ca_thresh = vnic->gw->info.ext_lag.ca_thresh;
	lag_prop.hash_mask = vnic->gw->info.ext_lag.hash;
	lag_prop.weights_policy = vnic->gw->info.ext_lag.weights_policy;
	mutex_unlock(&vnic->gw->mlock);
	if (write_through)
		vnic_member_prop(login, &lag_prop);

	/* go over all known members, for each one search for a match in the
	 * packet member struct */
	for (i=0; i<MAX_LAG_MEMBERS; i++) {
		if (!(vnic->lm.used_bitmask & 1 << i))
			continue;

		vnic_mem = &vnic->lm.memb[i];
		for (j=0; j<lm->num; j++) {

			pkt_mem = &lm->memb[j];
			/* find match for member in vnic data structure */
			if (packet_used[j] == EMPTY_ENTRY &&
			    !memcmp(vnic_mem->guid, pkt_mem->guid, GUID_LEN) &&
			    vnic_mem->gw_port_id == pkt_mem->gw_port_id) {
				/* found a match, check for change in parameters */
				if (vnic->login) {
					/* check for change in member parameters */
					if (vnic_mem->lid != pkt_mem->lid ||
					    vnic_mem->qpn != pkt_mem->qpn ||
					    vnic_mem->eport_state != pkt_mem->eport_state ||
					    vnic_mem->sl != pkt_mem->sl ||
					    vnic_mem->link_utilization != pkt_mem->link_utilization) {

						vnic_dbg_lag_v(vnic->name, "handle_member_update entry %d modifying lid %d qpn %d state %d\n",
							     i, lm->memb[j].lid, lm->memb[j].qpn, lm->memb[j].eport_state);
						/* update data path if required and store update info localy */
						if (!write_through ||
						    (write_through && !vnic_member_modify(login, i, &lm->memb[j])))
							*vnic_mem = lm->memb[j];
					}
				}
				packet_used[j] = i;
				vnic_used[i] = j;
				break;
			}
		}
		/* if member was removed in last packet remove it */
		if (vnic_used[i] == EMPTY_ENTRY) {
			if (!write_through ||
			    (write_through && !vnic_member_remove(login, i))) {
				vnic_dbg_lag_v(vnic->name, "handle_member_update entry %d removing lid %d qpn %d state %d\n",
					     i, lm->memb[j].lid, lm->memb[j].qpn, lm->memb[j].eport_state);
				vnic->lm.used_bitmask &= ~(1 << i);
			}
		}
	}

	/* go over packet and look for any new members */
	for (j=0; j<lm->num; j++) {
		/* if entry was matched up already */
		if (packet_used[j]!= EMPTY_ENTRY)
			continue;

		skip = 0;
		/* verify that the same GW_ID is not in use by another port */
		for (i=0; i<MAX_LAG_MEMBERS; i++) {
			if (!(vnic->lm.used_bitmask & 1 << i))
				continue;
			if (vnic->lm.memb[i].gw_port_id == lm->memb[j].gw_port_id)
				skip = 1;
		}
		if (skip)
			continue;

		/* look for an empty member id and add the member to it */
		for (i=last_bit; i<MAX_LAG_MEMBERS; i++) {
			if (vnic->lm.used_bitmask & 1 << i)
				continue;

			vnic_dbg_lag_v(vnic->name, "handle_member_update entry %d adding lid %d qpn %d state %d\n",
				     i, lm->memb[j].lid, lm->memb[j].qpn, lm->memb[j].eport_state);
			if (!write_through ||
			    (write_through && !vnic_member_add(login, i, &lm->memb[j]))) {
				vnic->lm.used_bitmask |= (1 << i);
				vnic->lm.memb[i] = lm->memb[j];
			}

			break;
		}
		last_bit = i;
	}

	return 0;
}

/* Write the initial member table to the datapath. If we fail we will
 * delete the entry from the local cache and rely on periodic updates
 * packets for the retry*/
int fip_vnic_write_members(struct fip_vnic_data *vnic)
{
	int i;
	struct lag_properties lag_prop;
	struct vnic_login *login = vnic->login;

        /* if LAG is not enabled, or it's a child vNic, abort */
	if (!vnic->gw->info.ext_lag.valid || vnic->parent_used)
		return -EINVAL;

	lag_prop.ca = vnic->gw->info.ext_lag.ca;
	lag_prop.ca_thresh = vnic->gw->info.ext_lag.ca_thresh;
	lag_prop.hash_mask = vnic->gw->info.ext_lag.hash;
	lag_prop.weights_policy = vnic->gw->info.ext_lag.weights_policy;
	vnic_member_prop(login, &lag_prop);

	/* go over all members, for each une used write it to the data path */
	for (i=0; i<MAX_LAG_MEMBERS; i++) {
		if (!(vnic->lm.used_bitmask & 1 << i))
			continue;

		/* if update failed, delete local entry we will use the
		 * the update packet flow for retries.
		 */
		if (vnic_member_add(login, i, &vnic->lm.memb[i]))
			vnic->lm.used_bitmask &= ~(1 << i);
	}

	return 0;
}

/* runs in the context of vnic->vnic_pkt_rcv_task_bh */
void fip_vnic_recv_bh(struct work_struct *work)
{
	struct fip_vnic_data *vnic =
		container_of(work, struct fip_vnic_data, vnic_pkt_rcv_task_bh);
	int length;
	u32 vhub_id, tusn;
	int eport_state;
	struct vnic_table_entry *vhub_entries;
	struct list_head vnic_recv_local;
	struct fip_rcv_pkt *rcv, *rcv1;
	unsigned long flags;
	int i, __eport_state;
	
	INIT_LIST_HEAD(&vnic_recv_local);

	spin_lock_irqsave(&vnic->vnic_rcv_list.lock, flags);
	list_replace_init(&vnic->vnic_rcv_list.list, &vnic_recv_local);
	spin_unlock_irqrestore(&vnic->vnic_rcv_list.lock, flags);

	/* We Are not interested in packets prior to FIP_VNIC_VHUB_INIT */
	if (vnic->state < FIP_VNIC_VHUB_INIT ||
	    vnic->flush != FIP_NO_FLUSH) {
		list_for_each_entry_safe(rcv, rcv1, &vnic_recv_local, list) {
			kfree(rcv->fc);
			kfree(rcv->mem);
			list_del(&rcv->list);
			kfree(rcv);
		}
	} else {
		int err;

		list_for_each_entry_safe(rcv, rcv1, &vnic_recv_local, list) {
			length = rcv->length;

			switch (rcv->fc->fh->subcode) {
			case FIP_GW_UPDATE_SUB_OPCODE:
				/* validate vhub id before processing packet */
				vhub_id = be32_to_cpu(rcv->fc->fvu->state_vhub_id) & 0xffffff;
				if(unlikely(vnic->login_data.vhub_id != vhub_id))
					break;

				eport_state = be32_to_cpu(rcv->fc->fvu->state_vhub_id) >> 27 & 3;
				__eport_state = (eport_state == 0) ? EPORT_STATE_DOWN : EPORT_STATE_UP;
				atomic_set(&vnic->eport_state, __eport_state);

				/* handle vhub context update packets */
				if (rcv->fc->fed.num) {
					err = extract_vhub_extended(rcv->fc->fed.fed[0], vnic);
					if (err)
						vnic_warn(vnic->name, "extract_vhub_extended() failed\n");
				}
				if (rcv->fc->cte.num) {
					vhub_entries = kmalloc(rcv->fc->cte.num * sizeof *vhub_entries, GFP_KERNEL);
					if (!vhub_entries) {
						vnic_warn(vnic->port->name, "failed to allocate memory for update CTEs\n");
						goto free_entry;
					}

					tusn = be32_to_cpu(rcv->fc->fvu->tusn);
					for (i = 0; i < rcv->fc->cte.num; ++i) {
						vhub_entries[i].lid = be16_to_cpu(rcv->fc->cte.cte[i].lid);
						vhub_entries[i].qpn = be32_to_cpu(rcv->fc->cte.cte[i].qpn) & 0xffffff;
						vhub_entries[i].sl = rcv->fc->cte.cte[i].sl & 0xf;
						vhub_entries[i].rss = rcv->fc->cte.cte[i].v_rss_type & FIP_CONTEXT_RSS_FLAG ? 1 : 0;
						vhub_entries[i].valid = rcv->fc->cte.cte[i].v_rss_type & FIP_CONTEXT_V_FLAG ? 1 : 0;
						memcpy(vhub_entries[i].mac, rcv->fc->cte.cte[i].mac, sizeof(vhub_entries[i].mac));
						vhub_handle_update(vnic, vhub_id, tusn - rcv->fc->cte.num + i + 1, &vhub_entries[i]);
					}
					kfree(vhub_entries);
				}

				/* update vnic carrier only when vnic is ready:
				 * not closing (non zero flush), and per-registered
				 */
				if (!vnic->flush && vnic->login &&
				    test_bit(VNIC_STATE_LOGIN_CREATE_1, &vnic->login_state)) {
						vnic_carrier_update(vnic->login);
				}
				break;
			case FIP_GW_TABLE_SUB_OPCODE:
				/* handle vhub context table packets */
				tusn = be32_to_cpu(rcv->fc->fvt->tusn);
				vhub_id = be32_to_cpu(rcv->fc->fvt->vp_vhub_id) & 0xffffff;
				vhub_handle_tbl(vnic, rcv->fc, vhub_id, tusn);
				break;

			default:
				break;
			}
free_entry:
			list_del(&rcv->list);
			kfree(rcv->fc);
			kfree(rcv->mem);
			kfree(rcv);
		}
	}
	return;
}

/*
 * Mark the vnic for deletion and trigger a delayed call to the cleanup
 * function. In the past the vnic was moved to another list but this
 * might cause vnic duplication if new vnics are added to the GW. Even
 * if the vnic is being flushed we need to know it is there.
 *
 * Note: This deletion method insures that all pending vnic work requests
 * are cleared without dependency of the calling context.
 */
void fip_vnic_close(struct fip_vnic_data *vnic, enum fip_flush flush)
{
	int tmp_flush;

	/* net admin -> full flush */
	tmp_flush = vnic->hadmined ? flush : FIP_FULL_FLUSH;

	/* child vNic -> full flush */
	tmp_flush = (!vnic->parent_used) ? tmp_flush : FIP_FULL_FLUSH;

	/* no need for partial cleanup in host admin idle */
	if (tmp_flush == FIP_PARTIAL_FLUSH &&
	    vnic->state < FIP_VNIC_HADMIN_IDLE)
		return;

	/* close already in process, disregard */
	spin_lock_irq(&vnic->lock);
	if (vnic->flush >= tmp_flush){
		spin_unlock_irq(&vnic->lock);
		return;
	}
	if (vnic->flush == FIP_NO_FLUSH && vnic->state > FIP_VNIC_WAIT_4_ACK)
		fip_update_send(vnic, 0, 1 /* logout */);

	vnic->flush = tmp_flush;
	cancel_delayed_work(&vnic->vnic_gw_alive_task);
	cancel_delayed_work(&vnic->vnic_task);
	spin_unlock_irq(&vnic->lock);
	/* after this point we should have no work that is not already pending
	 * for execution, and no new work will be added
	 */

	if (vnic->hadmined && tmp_flush == FIP_FULL_FLUSH)
		vnic_delete_hadmin_dentry(vnic);
	else if (!vnic->hadmined)
		/* vnic_count is relevant for net admin only */
		vnic->gw->vnic_count--;

	vnic_dbg_mark();

	/* calls fip_purge_vnics() */
	queue_delayed_work(fip_wq, &vnic->gw->vnic_cleanup_task,
			   DELAYED_WORK_CLEANUP_JIFFS);
}

/*
 * This is a helper function we use in order to move the login destroy
 * to another context so we don't block the fip thread for too long.
*/
void fip_vnic_login_destroy(struct work_struct *work)
{
	struct fip_vnic_data *vnic =
		container_of(work, struct fip_vnic_data,
			     vnic_login_destroy_task);
	int flush = vnic->flush;

	vnic_login_destroy_wq_stopped(vnic, flush);

	/* we don't want to use a lock here so we will verify that the
	 * flush level did not change between the request and now */
	if (flush == FIP_FULL_FLUSH)
		set_bit(VNIC_LOGIN_DESTROY_FULL, &vnic->login_status);

	set_bit(VNIC_LOGIN_DESTROY_DONE, &vnic->login_status);
}

/*
 * Free vnic resources. This includes closing the data vnic (data QPs etc)
 * and the discovery resources. If the vnic can be totaly destroyed (no
 * pending work) the vnic will be removed from the GW and it's memory
 * freed. If not the vnic will not be freed and the function will return an
 * error. The caller needs to recall this unction to complete the operation.
 * Note: Do not call this function to remove a vnic, use fip_vnic_close.
*/
int fip_vnic_destroy(struct fip_vnic_data *vnic)
{
	int pending;

	vnic_dbg_func(vnic->name);
	vnic_dbg_fip_p0(vnic->name, "fip_vnic_destroy called flow=%d state=%d mac" MAC_6_PRINT_FMT "\n",
		     vnic->flush, vnic->state, MAC_6_PRINT_ARG(vnic->login_data.mac));

	pending = work_pending(&vnic->vnic_pkt_rcv_task_bh) ||
		delayed_work_pending(&vnic->vnic_gw_alive_task) ||
		delayed_work_pending(&vnic->vnic_task);

	/* verify no pending packets before we start tearing down the rings */
	if (pending || fip_vnic_test_login(vnic, 0) == -EAGAIN)
		goto retry_later;

	if (!test_and_set_bit(VNIC_LOGIN_DESTROY_PENDING,
			      &vnic->login_status)) {
		vnic_login_destroy_stop_wq(vnic, vnic->flush);
		/* calls fip_vnic_login_destroy() */
		queue_work(login_wq, &vnic->vnic_login_destroy_task);
	}

	if (!test_bit(VNIC_LOGIN_DESTROY_DONE, &vnic->login_status))
		goto retry_later;

	clear_bit(VNIC_LOGIN_DESTROY_DONE, &vnic->login_status);
	clear_bit(VNIC_LOGIN_DESTROY_PENDING, &vnic->login_status);

	/* We need to test if when we queued the destroy request it was
	 * a partial flush but this has changed to a full flush.
	 * if so we need to try again */
	if (vnic->flush == FIP_FULL_FLUSH &&
	    !test_bit(VNIC_LOGIN_DESTROY_FULL, &vnic->login_status))
		goto retry_later;

	hrtimer_cancel(&vnic->keepalive_timer);

	if (vnic->state >= FIP_VNIC_VHUB_INIT) {
		lag_ctx_clear(vnic);
		vhub_ctx_free(vnic);
	}

	/* disconnect from mcast groups */
	if (vnic->state >= FIP_VNIC_MCAST_INIT) {
		vnic_mcast_del_all(&vnic->mcast_tree);
		fip_vnic_rings_destroy(vnic);
	}

	if (vnic->state > FIP_VNIC_LOGIN)
		ib_destroy_ah(vnic->ah);

	if (vnic->flush == FIP_PARTIAL_FLUSH) {
		if (vnic->hadmined) /* we close Host admin vnics so they won't do any login from fip_vnic_fsm */
			vnic->state = FIP_VNIC_CLOSED;
		else
			vnic->state = FIP_VNIC_HADMIN_IDLE;

		vnic->flush = FIP_NO_FLUSH;
		vnic->last_send_jiffs = 0;

		vnic_dbg_fip_v(vnic->name, "fip_vnic_remove partial done vnic->retry_count=%d\n", vnic->retry_count);
		if (!VNIC_MAX_RETRIES || ++vnic->retry_count < VNIC_MAX_RETRIES)
			QUEUE_VNIC_DWORK(vnic, &vnic->vnic_task, FIP_LOGIN_TIMEOUT * HZ);

	} else {
		list_del(&vnic->gw_vnics);
		vnic_dbg_fip_v(vnic->name, "fip_vnic_remove full done\n");
		kfree(vnic);
	}

	return 0;

retry_later:
	return -EBUSY;
}

int fip_vnic_keepalive_send(struct fip_vnic_data *vnic, int source_timer)
{
	int update;
	unsigned long flags;
	int ret = 0;

	if (vnic->flush != FIP_NO_FLUSH)
		return ret;

	if (vnic->last_send_jiffs > 1 && jiffies - vnic->last_send_jiffs > vnic->gw->info.vnic_ka_period * 3 / 2)
		vnic_dbg_fip_p0(vnic->name, "Delaying in sending KA should be %ld actual time=%ld source=%d\n",
			vnic->gw->info.vnic_ka_period, jiffies - vnic->last_send_jiffs, source_timer);

	spin_lock_irqsave(&vnic->ka_lock, flags);
	if (source_timer ||
	    (vnic->last_send_jiffs && jiffies - vnic->last_send_jiffs >
	     vnic->gw->info.vnic_ka_period * 6 / 5)) {

		/* we need to have mcast attached before we ask for a table */
		if (vnic->state >= FIP_VNIC_VHUB_INIT &&
		    vnic->vhub_table.state == VHUB_TBL_INIT)
			update = 1;
		else
			update = 0;

		/* send vnic keep alive to GW */
		ret = fip_update_send(vnic, update, 0 /*not logout */);
		if (!ret)
			vnic->last_send_jiffs = jiffies;
	}
	spin_unlock_irqrestore(&vnic->ka_lock, flags);

	return ret;

}

//void fip_vnic_keepalive(unsigned long data)
#ifdef _BP_HR_TIMER
int fip_vnic_keepalive(struct hrtimer * timer)
#else
enum hrtimer_restart fip_vnic_keepalive(struct hrtimer *timer)
#endif
{
//	struct fip_vnic_data *vnic = (struct fip_vnic_data *)data;
	struct fip_vnic_data *vnic = (struct fip_vnic_data *)
					container_of(timer, struct fip_vnic_data, keepalive_timer);
	unsigned long flags;
	ktime_t ktime;   
	enum hrtimer_restart ret = HRTIMER_NORESTART;
	int flush;

	spin_lock_irqsave(&vnic->lock, flags);
	flush = vnic->flush;
	spin_unlock_irqrestore(&vnic->lock, flags);

	if (flush != FIP_NO_FLUSH)
		return ret;

	fip_vnic_keepalive_send(vnic, 1);

	/*mod_timer(&vnic->keepalive, jiffies + time);*/
	ret = HRTIMER_RESTART;
	ktime = ktime_set(0, vnic->gw->info.vnic_ka_period * (1000000000 / HZ));
	hrtimer_forward(&vnic->keepalive_timer, vnic->keepalive_timer.base->get_time(), ktime);


	return ret;

}

void fip_vnic_gw_alive(struct work_struct *work)
{
	struct fip_vnic_data *vnic =
		container_of(work, struct fip_vnic_data,
			     vnic_gw_alive_task.work);
	long time_to_timeout;

	if (vnic->flush != FIP_NO_FLUSH)
		return;

	if (!test_bit(MCAST_ATTACHED, &vnic->vnic_mcaste_state)) {
		if (time_after(jiffies, vnic->detached_ka_jiffs + 60*HZ)) {
			vnic_dbg_fip_p0(vnic->name, "No GW keep alive timeout when mcast un attached "
				     "QPN 0x%06x, LID 0x%04x\n", vnic->qp->qp_num,
				     vnic->port->attr.lid);
			fip_vnic_close(vnic, FIP_PARTIAL_FLUSH);
			return;
		} else {
			vnic_dbg_fip_p0(vnic->name, "Got ka poll when bcast not "
				     "attached QPN 0x%06x, LID 0x%04x, ka=%u\n",
				     vnic->qp->qp_num, vnic->port->attr.lid,
				     jiffies_to_msecs(jiffies - vnic->detached_ka_jiffs));
			time_to_timeout = vnic->gw->info.gw_period;
               }
	} else {
		long jiffs_from_last;
		jiffs_from_last = (jiffies - vnic->keep_alive_jiffs);
		time_to_timeout = vnic->gw->info.gw_period - jiffs_from_last;
	}

	/* Todo, change receive of update to rearm work timer so an expiration
	 * indicates a truie time out */
	if (time_to_timeout <= 0) {
		vnic_dbg_fip_p0(vnic->name, "GW keep alives timed out for "
			  "QPN 0x%06x, LID 0x%04x timeout=%ld\n", vnic->qp->qp_num,
			  vnic->port->attr.lid, time_to_timeout);
		fip_vnic_close(vnic, FIP_PARTIAL_FLUSH);
	} else
		QUEUE_VNIC_DWORK(vnic, &vnic->vnic_gw_alive_task,
				 time_to_timeout + 1);
}

struct fip_vnic_data *fip_vnic_alloc(struct vnic_port *port,
				     struct fip_gw_data *gw,
				     int hadmin, u16 vnic_id)
{
	struct fip_vnic_data *vnic;

	vnic = kzalloc(sizeof(struct fip_vnic_data), GFP_KERNEL);
	if (!vnic) {
		vnic_err(port->name, "failed to alloc vnic\n");
		return NULL;
	}

	vnic->state = hadmin ? FIP_VNIC_HADMIN_IDLE : FIP_VNIC_LOGIN;
	vnic->vnic_id = vnic_id;
	vnic->gw = gw;
	vnic->gw_info = gw->info.vol_info;
	vnic->port = port;
	vnic->hadmined = hadmin;
	vnic->flush = FIP_NO_FLUSH;

	sprintf(vnic->name, "vnic-%d", vnic_id); /* will be overwritten */

	spin_lock_init(&vnic->lock);
	spin_lock_init(&vnic->ka_lock);
	INIT_DELAYED_WORK(&vnic->vnic_task, fip_vnic_fsm);
	INIT_DELAYED_WORK(&vnic->vnic_gw_alive_task, fip_vnic_gw_alive);
	INIT_WORK(&vnic->vnic_login_destroy_task, fip_vnic_login_destroy);
	INIT_WORK(&vnic->vnic_login_create_task, fip_vnic_login_create);


#ifdef _BP_HR_TIMER
	hrtimer_init(&vnic->keepalive_timer, CLOCK_MONOTONIC, HRTIMER_REL);
#else
	hrtimer_init(&vnic->keepalive_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL );
#endif
	vnic->keepalive_timer.function = fip_vnic_keepalive;

	vnic_mcast_root_init(&vnic->mcast_tree);
	atomic_set(&vnic->eport_state,EPORT_STATE_DOWN);

	return vnic;
}

int fip_vnic_hadmin_init(struct vnic_port *port, struct fip_vnic_data *vnic)
{
	int rc;

	vnic_dbg_func(port->name);

	rc = vnic_login_pre_create_1(port, vnic);
	if (rc) {
		vnic_warn(port->name, "vnic_login_pre_create_1 failed, rc %d\n", rc);
		goto pre_create_failed;
	}

	strncpy(vnic->login_data.vnic_name, vnic->interface_name,
		sizeof(vnic->interface_name));

	/* queue login create request */
	fip_vnic_test_login(vnic, 1);

	return 0;

pre_create_failed:
	return -ENODEV;
}

void fip_vnic_create_gw_param(struct fip_vnic_send_info *gw_address, u32 gw_qpn,
			      u32 qkey, u16 gw_lid, u8 gw_sl)
{
	gw_address->gw_qpn = gw_qpn;
	gw_address->qkey = qkey;
	gw_address->gw_lid = gw_lid;
	gw_address->gw_sl = gw_sl;
}

void fip_vnic_set_gw_param(struct fip_vnic_data *vnic, struct fip_vnic_send_info *gw_address)
{
	memcpy(&vnic->gw_address, gw_address, sizeof(vnic->gw_address));
}

int fip_hadmin_vnic_refresh(struct fip_vnic_data *vnic, struct fip_vnic_send_info *gw_address)
{
	vnic_dbg_fip(vnic->name, "fip_vnic_to_login host admin flow flush=%d"
		     " state=%d\n", vnic->flush, vnic->state);
	if (likely(vnic->flush == FIP_NO_FLUSH) &&
	    vnic->state <= FIP_VNIC_HADMIN_IDLE &&
	    (!VNIC_MAX_RETRIES || vnic->retry_count < VNIC_MAX_RETRIES)) {
		fip_vnic_set_gw_param(vnic, gw_address);
		cancel_delayed_work(&vnic->vnic_task);
		vnic->state = FIP_VNIC_LOGIN;
		fip_vnic_fsm(&vnic->vnic_task.work);
	}
	return 0;
}

/*
 * Call the data vnic precreate 1 + 2 in order to alloc and init the data vnic.
 * This function updates qp numbers that the data vnic will use. These qp numbers
 * are needed for the login.
 * This function does not cleanup on failures. It assumes that the caller will call
 * the login destoy.
*/
static int fip_vnic_login_init(struct vnic_port *port, struct fip_vnic_data *vnic)
{
	int qps_num;
	int rc;

	struct ib_ah_attr ah_attr = {
		.dlid = vnic->gw_address.gw_lid,
		.port_num = port->num,
		.sl = vnic_gw_ctrl_sl(vnic->gw) & 0xf,
	};

	vnic_dbg_func(vnic->name);

	/* If the driver wants to enable RSS (vnic_rss == 1) then the
	 * number of QPs is what the GW advertises: 1 << n_rss_qpn
         */
	qps_num = (port->rx_rings_num > 1) ? (1 << vnic->gw->info.n_rss_qpn) : 1;
	qps_num = (qps_num == 0) ? 1 : qps_num;

	/* However, we don't support any qps_num, if the GW asks for more than
	 * VNIC_MAX_NUM_CPUS QPs, then we're not going to enable RSS
	 * -- qps_num == 1 means RSS is disabled, otherwise it's enabled
	 */
	qps_num = qps_num <= VNIC_MAX_NUM_CPUS ? qps_num : 1;

	/* set in vnic, so it can be reported back to the BXM */
	vnic->qps_num = qps_num;

	/* in host admin vnic->login should be non NULL */
	if (!vnic->hadmined) {
		rc = vnic_login_pre_create_1(port, vnic);
		if (rc) {
			vnic_warn(vnic->name,
				  "vnic_login_pre_create_1 failed, "
				  "rc %d\n", rc);
			goto failed;
		}
	}

	/* in host admin vnic->login should be non NULL */
	rc = vnic_login_pre_create_2(vnic, qps_num,
				     vnic->gw->info.gw_type == GW_TYPE_LAG);
	if (rc) {
		vnic_warn(port->name, "vnic_login_pre_create_2 failed\n");
		goto failed;
	}

	/* if parent_used, you must already have the base QPN */
	ASSERT(!vnic->parent_used || vnic->qp_base_num);

	vnic->ah = ib_create_ah(port->pd, &ah_attr);
	if (IS_ERR(vnic->ah)) {
		vnic_warn(vnic->name, "fip_vnic_login_init failed to create ah\n");
		vnic->ah = NULL;
		goto failed;
	}

	vhub_ctx_init(vnic);

	return 0;

failed:
	return -ENODEV;
}

/*
 * create a CQ and QP for the new vNic. Create RX and TX rings for this
 * QP. Move QP to RTS and connect it to the CQ.
*/
static int fip_vnic_rings_create(struct vnic_port *port,
				 struct fip_vnic_data *vnic)
{
	struct ib_qp_init_attr qp_init_attr;
	int ret;

	vnic->rx_ring.size = FIP_LOGIN_RX_SIZE;
	vnic->tx_ring.size = FIP_LOGIN_TX_SIZE;

	INIT_WORK(&vnic->vnic_pkt_rcv_task_bh, fip_vnic_recv_bh);
	spin_lock_init(&vnic->vnic_rcv_list.lock);
	INIT_LIST_HEAD(&vnic->vnic_rcv_list.list);

	if (ib_find_pkey(port->dev->ca, port->num, vnic->login_data.pkey,
			 &vnic->login_data.pkey_index)) {
		vnic_warn(vnic->name,
			     "fip_vnic_rings_create PKey 0x%04x not found."
			     " Check configuration in SM/BX\n", vnic->login_data.pkey);
		goto out_w_err;
	}

	vnic->pkey = vnic->login_data.pkey;
	vnic->pkey_index = vnic->login_data.pkey_index;

	vnic_dbg_fip_v(vnic->name, "fip_vnic_rings_create pkey id %d "
		       "for pkey 0x%x\n", (int)vnic->pkey_index,
		       (int)vnic->pkey);

	vnic->cq = ib_create_cq(port->dev->ca, fip_vnic_comp, NULL, vnic,
				vnic->rx_ring.size + vnic->tx_ring.size, 0);
	if (IS_ERR(vnic->cq)) {
		vnic_dbg_fip(vnic->name, "failed to create receive CQ\n");
		goto out_w_err;
	}

	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.cap.max_send_wr = vnic->tx_ring.size;
	qp_init_attr.cap.max_recv_wr = vnic->rx_ring.size;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;
	qp_init_attr.sq_sig_type = IB_SIGNAL_ALL_WR;
	qp_init_attr.qp_type = IB_QPT_UD;
	qp_init_attr.send_cq = vnic->cq;
	qp_init_attr.recv_cq = vnic->cq;

	vnic->qp = ib_create_qp(port->pd, &qp_init_attr);
	if (IS_ERR(vnic->qp)) {
		vnic_dbg_fip(vnic->name, "failed to create QP\n");
		goto error_free_cq;
	}

	vnic_dbg_fip_v(vnic->name, "fip_vnic_rings_create QPN %d,"
		       " LID %d\n", (int)vnic->qp->qp_num, (int)port->attr.lid);

	/* move QP from reset to RTS */
	if (fip_init_qp(vnic->port, vnic->qp, vnic->pkey_index, vnic->name)) {
		vnic_dbg_fip(vnic->name, "fip_init_qp returned with error\n");
		goto error_free_qp;
	}

	ret = fip_init_tx(vnic->tx_ring.size, &vnic->tx_ring, vnic->name);
	if (ret) {
		vnic_dbg_fip(vnic->name, "fip_init_tx failed ret %d\n", ret);
		goto error_free_qp;
	}

	ret = fip_init_rx(port, vnic->rx_ring.size, vnic->qp,
			  &vnic->rx_ring, vnic->name);
	if (ret) {
		vnic_dbg_fip(vnic->name, "fip_init_rx returned %d\n", ret);
		goto error_release_rings;
	}

	/* enable recieving CQ completions */
	if (ib_req_notify_cq(vnic->cq, IB_CQ_NEXT_COMP))
		goto error_release_rings;
	vnic_dbg_fip_v(vnic->name, "fip_vnic_rings_create done OK\n");

	return 0;

error_release_rings:
	fip_flush_rings(port, vnic->cq, vnic->qp, &vnic->rx_ring,
			&vnic->tx_ring, vnic->name);
	fip_free_rings(port, &vnic->rx_ring, &vnic->tx_ring, vnic->name);
error_free_qp:
	ib_destroy_qp(vnic->qp);
error_free_cq:
	ib_destroy_cq(vnic->cq);
out_w_err:
	vnic->qp = NULL;
	vnic->cq = NULL;
	vnic->rx_ring.size = 0;
	vnic->tx_ring.size = 0;
	return -ENODEV;
}

static void fip_vnic_rings_destroy(struct fip_vnic_data *vnic)
{
	fip_flush_rings(vnic->port, vnic->cq, vnic->qp, &vnic->rx_ring,
			&vnic->tx_ring, vnic->name);
	fip_free_rings(vnic->port, &vnic->rx_ring, &vnic->tx_ring, vnic->name);
	fip_vnic_recv_list_flush(vnic);
	ib_destroy_qp(vnic->qp);
	ib_destroy_cq(vnic->cq);
	vnic->qp = NULL;
	vnic->cq = NULL;
}

/*
 * This function is a callback called upon successful join to a
 * multicast group. The function checks if we have joined + attached
 * to all required mcast groups and if so moves the discovery FSM to solicit.
*/
void fip_vnic_mcast_cnct_cb(struct vnic_mcast *mcast, void *ctx)
{
	struct fip_vnic_data *vnic = mcast->priv_data;

	vnic_dbg_fip(vnic->name, "fip_vnic_mcast_cnct_cb\n");
	vnic_dbg_parse(vnic->name, "attached mask = 0x%lx, req mask = 0x%lx\n",
		       *mcast->cur_attached, *mcast->req_attach);

	if ((*mcast->cur_attached & *mcast->req_attach) != *mcast->req_attach)
		return;

	vnic->keep_alive_jiffs = jiffies;
	set_bit(MCAST_ATTACHED, &vnic->vnic_mcaste_state);
	/* in case of a new mcast connection switch to VHUB_INIT, for a
	 * reconnection stay in the current state */
	if (vnic->state < FIP_VNIC_VHUB_INIT) {
		vnic_dbg_fip(vnic->name,
			"fip_vnic_mcast_cnct_cb done joining mcasts\n");
		vnic->state = FIP_VNIC_VHUB_INIT;
		cancel_delayed_work(&vnic->vnic_task);
		REQUEUE_VNIC_DWORK(vnic, &vnic->vnic_task, 0);
	}
}

/*
 * This function is a callback called upon a mcast deattach event.
 * This event can be triggered due to vnic request or due to an async
 * event. Currently this code does not participate in the vnic's FSM.
*/
void fip_vnic_mcast_deattach_cb(struct vnic_mcast *mcast, void *ctx)
{
	struct fip_vnic_data *vnic = mcast->priv_data;

	vnic->detached_ka_jiffs = jiffies;
	clear_bit(MCAST_ATTACHED, &vnic->vnic_mcaste_state);

	vnic_dbg_fip(vnic->name, "fip_vnic_mcast_deattach_cb\n");
}

/*
 * Try to connect to the relevant mcast groups. If one of the mcast failed
 * The function should be recalled to try and complete the join process
 * (for the mcast groups that the join process was not performed).
 * Note: A successful return of vnic_mcast_join means that the mcast join
 * started, not that the join completed. completion of the connection process
 * is asyncronous and uses a supplyed callback.
 */
int fip_vnic_mcast_cnct(struct fip_vnic_data *vnic)
{
	struct vnic_port *port = vnic->port;
	union vhub_mgid mgid;
	struct vnic_mcast *mcaste, *mcaste_upd, *mcaste_tbl;
	struct vnic_mcast *uninitialized_var(mcaste_ka);
	int rc;

	vnic_dbg_fip(port->name, "fip_vnic_mcast_cnct called\n");

	mcaste_upd = vnic_mcast_alloc(port, &vnic->req_attach, &vnic->cur_attached);
	if (IS_ERR(mcaste_upd))
		return -EINVAL;

	mcaste_tbl = vnic_mcast_alloc(port, &vnic->req_attach, &vnic->cur_attached);
	if (IS_ERR(mcaste_tbl)) {
		rc = -EINVAL;
		goto free_upd;
	}

	set_bit(FIP_MCAST_VHUB_UPDATE, &vnic->req_attach);
	set_bit(FIP_MCAST_TABLE, &vnic->req_attach);

	vnic_dbg_fip(port->name, "gw type is %d\n", vnic->gw->info.gw_type);
	if (vnic->gw->info.gw_type == GW_TYPE_LAG) {
		mcaste_ka = vnic_mcast_alloc(port, &vnic->req_attach, &vnic->cur_attached);
		if (IS_ERR(mcaste_ka)) {
			rc = -EINVAL;
			goto free_tbl;
		}
		set_bit(FIP_MCAST_VHUB_KA, &vnic->req_attach);
	}

	mcaste = mcaste_upd;
	mcaste->priv_data = vnic;
	mcaste->attach_bit_nr = FIP_MCAST_VHUB_UPDATE;
	memset(mcaste->mac, 0, ETH_ALEN);
	vhub_mgid_create(vnic->login_data.mgid_prefix,
			 mcaste->mac,
			 vnic->login_data.n_mac_mcgid,
			 vnic->login_data.vhub_id, VHUB_MGID_UPDATE,
			 0, &mgid);
	mcaste->gid = mgid.ib_gid;
	mcaste->port_gid = mcaste->gid;
	mcaste->backoff = msecs_to_jiffies(VNIC_MCAST_BACKOFF_MSEC);
	mcaste->backoff_factor = VNIC_MCAST_BACKOF_FAC;
	mcaste->retry = VNIC_MCAST_ULIMIT_RETRY;
	mcaste->attach_cb = fip_vnic_mcast_cnct_cb;
	mcaste->detach_cb = fip_vnic_mcast_deattach_cb;
	mcaste->attach_cb_ctx = NULL;
	mcaste->detach_cb_ctx = NULL;
	mcaste->blocking = 0;
	mcaste->qkey = VNIC_FIP_QKEY;
	mcaste->pkey = vnic->pkey;
	mcaste->qp = vnic->qp;
	mcaste->create = vnic_mcast_create;
	mcaste->blocking = 0;
	mcaste->join_state = 1;
	rc = vnic_mcast_add(&vnic->mcast_tree, mcaste);
	ASSERT(!rc);
	rc = vnic_mcast_attach(&vnic->mcast_tree, mcaste);	/* MCAST_RECEIVE_ONLY */
	ASSERT(!rc);

	mcaste = mcaste_tbl;
	mcaste->priv_data = vnic;
	mcaste->attach_bit_nr = FIP_MCAST_TABLE;
	memset(mcaste->mac, 0, ETH_ALEN);
	vhub_mgid_create(vnic->login_data.mgid_prefix,
			 mcaste->mac,
			 vnic->login_data.n_mac_mcgid,
			 vnic->login_data.vhub_id, VHUB_MGID_TABLE,
			 0, &mgid);
	mcaste->gid = mgid.ib_gid;
	mcaste->port_gid = mcaste->gid;
	mcaste->backoff = msecs_to_jiffies(VNIC_MCAST_BACKOFF_MSEC);
	mcaste->backoff_factor = VNIC_MCAST_BACKOF_FAC;
	mcaste->retry = VNIC_MCAST_ULIMIT_RETRY;
	mcaste->attach_cb = fip_vnic_mcast_cnct_cb;
	mcaste->detach_cb = fip_vnic_mcast_deattach_cb;
	mcaste->attach_cb_ctx = NULL;
	mcaste->detach_cb_ctx = NULL;
	mcaste->blocking = 0;
	mcaste->qkey = VNIC_FIP_QKEY;
	mcaste->pkey = vnic->pkey;
	mcaste->qp = vnic->qp;
	mcaste->create = vnic_mcast_create;
	mcaste->blocking = 0;
	mcaste->join_state = 1;
	rc = vnic_mcast_add(&vnic->mcast_tree, mcaste);
	ASSERT(!rc);
	rc = vnic_mcast_attach(&vnic->mcast_tree, mcaste);	/* MCAST_RECEIVE_ONLY */
	ASSERT(!rc);

	if (vnic->gw->info.gw_type != GW_TYPE_LAG)
		return 0;

	mcaste = mcaste_ka;
	mcaste->priv_data = vnic;
	mcaste->attach_bit_nr = FIP_MCAST_VHUB_KA;
	memset(mcaste->mac, 0, ETH_ALEN);
	vhub_mgid_create(vnic->login_data.mgid_prefix,
			 mcaste->mac,
			 vnic->login_data.n_mac_mcgid,
			 vnic->login_data.vhub_id, VHUB_MGID_KA,
			 0, &mgid);
	mcaste->gid = mgid.ib_gid;
	mcaste->port_gid = mcaste->gid;
	mcaste->backoff = msecs_to_jiffies(VNIC_MCAST_BACKOFF_MSEC);
	mcaste->backoff_factor = 1;
	mcaste->retry = VNIC_MCAST_MAX_RETRY;
	mcaste->attach_cb = fip_vnic_mcast_cnct_cb;
	mcaste->detach_cb = fip_vnic_mcast_deattach_cb;
	mcaste->attach_cb_ctx = NULL;
	mcaste->detach_cb_ctx = NULL;
	mcaste->blocking = 0;
	mcaste->qkey = VNIC_FIP_QKEY;
	mcaste->pkey = vnic->pkey;
	mcaste->qp = vnic->qp;
	mcaste->create = vnic_mcast_create;
	mcaste->blocking = 0;
	mcaste->join_state = 1;
	mcaste->sender_only = 1;
	vnic->ka_mcast_gid = mcaste->gid;
	rc = vnic_mcast_add(&vnic->mcast_tree, mcaste);
	ASSERT(!rc);
	rc = vnic_mcast_attach(&vnic->mcast_tree, mcaste);
	ASSERT(!rc);

        return 0;

free_tbl:
	vnic_mcast_dealloc(mcaste_tbl);

free_upd:
	vnic_mcast_dealloc(mcaste_upd);

	return rc;
}

/*
 * This function is the driving engine of the vnic logic. It manages the
 * vnics state machines.
 * Some of the states in the state machine could have been removed because
 * they contain "actions" and not states. Still it is easier to maintaine
 * the code this way and it gives an easy mechanism for exception handling
 * and retries.
 * Only call this function from fip_wq context.
*/
void fip_vnic_fsm(struct work_struct *work)
{
	struct fip_vnic_data *vnic =
		container_of(work, struct fip_vnic_data, vnic_task.work);
	struct vnic_port *port = vnic->port;
	int rc, recall_time = 0;
	const long int msec_in_sec = 1000;
	struct fip_vnic_send_info gw_address;
	ktime_t ktime;

	vnic_dbg_fip(port->name, "fip_vnic_fsm called vnic %d\n",
		     vnic->vnic_id);

	if (vnic->flush != FIP_NO_FLUSH)
		return;

	switch (vnic->state) {
	case FIP_VNIC_CLOSED:
		break;
	case FIP_VNIC_HADMIN_IDLE:
		if (vnic->gw->state < FIP_GW_CONNECTED)
			break;
		fip_vnic_create_gw_param(&gw_address, vnic->gw->info.gw_qpn, VNIC_FIP_QKEY,
					  vnic->gw->info.gw_lid, vnic_gw_ctrl_sl(vnic->gw));
		fip_vnic_set_gw_param(vnic, &gw_address);
		/* fall through */

	case FIP_VNIC_LOGIN:
		vnic_dbg_fip(port->name, "FIP_VNIC_LOGIN vnic %d\n",
			     vnic->vnic_id);
		/* get data QP numbers needed for login request packet. If we fail
		 * we will close the vnic entirely */
		rc = fip_vnic_login_init(vnic->port, vnic);
		if (rc) {
			fip_vnic_close(vnic, FIP_PARTIAL_FLUSH);
			vnic_warn(vnic->name, "fip_vnic_login_init failed, "
				 "closing vnic rc %d\n", rc);
			break;
		}
		vnic->state = FIP_VNIC_WAIT_4_ACK;
		/* fall through */

	case FIP_VNIC_WAIT_4_ACK:
		vnic_dbg_fip(port->name, "FIP_VNIC_WAIT_4_ACK vnic %d\n",
			     vnic->vnic_id);
		/* resend login request every timeout */
		vnic_dbg_fip(port->name, "fip_login_send vnic %d\n",vnic->vnic_id);
		rc = fip_login_send(vnic);
		if (!rc)
			recall_time = FIP_LOGIN_TIMEOUT * msec_in_sec;
		else
			recall_time = 1 * msec_in_sec;

		goto queue_vnic_work;

	case FIP_VNIC_RINGS_INIT:
		/* create QP and rings */
		rc = fip_vnic_rings_create(vnic->port, vnic);
		if (rc) {
			fip_vnic_close(vnic, FIP_PARTIAL_FLUSH);
			vnic_warn(vnic->name, "fip_vnic_rings_create failed, "
				  "closing vnic rc=%d\n", rc);
			break;
		}

		vnic->last_send_jiffs = 1; /* use a non zero value to start transmition */
		{
                       /* start vnic UCAST KA packets, This will also cause bxm to send us the
                         * neighbor table */
			if (vnic->gw->info.gw_type != GW_TYPE_LAG) {
				ktime = ktime_set(0, 0);
#ifdef _BP_HR_TIMER
				hrtimer_start(&vnic->keepalive_timer, ktime, HRTIMER_REL );
#else
				hrtimer_start(&vnic->keepalive_timer, ktime, HRTIMER_MODE_REL );
#endif
			}
		}

		vnic->state = FIP_VNIC_MCAST_INIT;
		/* fall through */

	case FIP_VNIC_MCAST_INIT:
		rc = fip_vnic_mcast_cnct(vnic);
		if (rc) {
			vnic_warn(vnic->name,
				     "fip_vnic_mcast_cnct failed, rc %d\n", rc);
			/* try again later */
			recall_time = 1 * msec_in_sec;
			goto queue_vnic_work;
		}
		vnic->state = FIP_VNIC_MCAST_INIT_DONE;
		/* fall through */

	case FIP_VNIC_MCAST_INIT_DONE:
		/* wait for mcast attach CB before continueing */
		break;

	case FIP_VNIC_VHUB_INIT:

		/* previous KA if sent did not request a table because MCASTs were not
		 * available. Send extra KA packet that should trigger table request in
		 * order to hasten things up */
		fip_vnic_keepalive_send(vnic, 1);

		if (vnic->gw->info.gw_type == GW_TYPE_LAG) {
			/* start vnic MCAST KA packets, This will also cause bxm to send us the
			  * neighbor table */
			ktime = ktime_set(0, 0);
#ifdef _BP_HR_TIMER
			hrtimer_start(&vnic->keepalive_timer, ktime, HRTIMER_REL );
#else
			hrtimer_start(&vnic->keepalive_timer, ktime, HRTIMER_MODE_REL );
#endif
		}

		/* start tracking GW keep alives, calls  fip_vnic_gw_alive() */
		QUEUE_VNIC_DWORK(vnic, &vnic->vnic_gw_alive_task,
				 vnic->gw->info.gw_period);

		vnic->state = FIP_VNIC_VHUB_INIT_DONE;
		/* fall through */

	case FIP_VNIC_VHUB_INIT_DONE:
		/* we are waiting to receive a full vhub table. The KA will handle
		 * retries if we do not get the table we are expecting */

		/* queue login create request */
		if (fip_vnic_test_login(vnic, 1)) {
			recall_time = 1 * msec_in_sec;
			goto queue_vnic_work;
		}

		break;

	case FIP_VNIC_VHUB_DONE:
		if (fip_vnic_test_login(vnic, 1)) {
			recall_time = 1 * msec_in_sec;
			goto queue_vnic_work;
		}

                if (vnic_login_complete_ack(vnic, &vnic->login_data, &vnic->shared_vnic)) {
			vnic_warn(vnic->name,
				     "vnic_login_complete_ack failed\n");
			recall_time = 1 * msec_in_sec;
			goto queue_vnic_work;
		}

		/* for LAG write member info */
		fip_vnic_write_members(vnic);

		vnic->state = FIP_VNIC_VHUB_WRITE;
		/* fall through */

	case FIP_VNIC_VHUB_WRITE:
		/* write the vhub table to login */
		fip_vnic_write_tbl(vnic);
		vnic->state = FIP_VNIC_CONNECTED;
		/* fall through */

	case FIP_VNIC_CONNECTED:
		vnic->retry_count = 0;
		break;
	default:
		ASSERT(0);
		break;
	}

	vnic_dbg_fip(port->name, "state %d gw_lid %d gw_qpn %d\n",
		     vnic->state, vnic->gw_address.gw_lid, vnic->gw_address.gw_qpn);
	return;

queue_vnic_work:
	QUEUE_VNIC_DWORK(vnic, &vnic->vnic_task, recall_time * HZ / msec_in_sec);
}
