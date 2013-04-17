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

#include <linux/uts.h>
#include "vnic.h"
#include "vnic_fip.h"
#include "vnic_fip_discover.h"
#include "vnic_fip_pkt.h"

const struct eoib_host_update base_update_pkt = {
	.fip.subcode = FIP_HOST_ALIVE_SUB_OPCODE,
	.fip.type.type = FIP_FIP_HDR_TYPE,
	.fip.type.length = FIP_FIP_HDR_LENGTH,
	.fip.vendor_id = FIP_VENDOR_MELLANOX,

	.type_1.type = FIP_HOST_UPDATE_TYPE,
	.type_1.length = FIP_HOST_UPDATE_LENGTH,
	.vendor_id = FIP_VENDOR_MELLANOX,
};

const struct eoib_host_update base_logout_pkt = {
	.fip.subcode = FIP_HOST_LOGOUT_SUB_OPCODE,
	.fip.type.type = FIP_FIP_HDR_TYPE,
	.fip.type.length = FIP_FIP_HDR_LENGTH,
	.fip.vendor_id = FIP_VENDOR_MELLANOX,

	.type_1.type = FIP_LOGOUT_TYPE_1,
	.type_1.length = FIP_LOGOUT_LENGTH_1,
	.vendor_id = FIP_VENDOR_MELLANOX,
};

static int extract_adv_extended(struct fip_ext_desc_tlv *fed,
				struct fip_gw_data_info *info)
{
        struct fip_ext_type_cap *extended_cap;
        struct fip_ext_type_boot *extended_boot;
	struct fip_ext_type_power_cycle_id *extended_pc_id;
	struct fip_ext_type_lag_props *extended_lag = NULL;
	struct fip_extended_type *ext_hdr;
	int length_to_go, ext_length;
	
	vnic_dbg_parse("", "extracting extended descriptor\n");

	length_to_go = (((int)fed->ft.length) << 2) - sizeof(*fed);
	ext_hdr = (struct fip_extended_type *)(fed + 1);

	while (length_to_go > 0) {
		ext_length = ((int)ext_hdr->len) << 2;

		vnic_dbg_parse(NULL, "Advertise parse, sub-tlv "
			       "type  %d length %d address=%p\n",
			       ext_hdr->ext_type, ext_length, ext_hdr);

		if (ext_length < sizeof(*ext_hdr) ||
		    ext_length > length_to_go) {
			vnic_dbg_parse(NULL, "Extended length error. "
				       "Length=%d\n", ext_length);
			return -EINVAL;
		}

		if (ext_hdr->ext_type == ADV_EXT_TYPE(CAP) &&
		    ext_length == sizeof(*extended_cap)) {		/* capabilities*/
			/* do nothing */
		} else if (ext_hdr->ext_type == ADV_EXT_TYPE(LAG) &&	/* LAG */
			   ext_length == sizeof(*extended_lag)) {
			extended_lag = (struct fip_ext_type_lag_props *)ext_hdr;
			info->gw_type = extended_lag->gw_type;
			info->ext_lag.hash =  be16_to_cpu(extended_lag->lag_hash);
			info->ext_lag.weights_policy = extended_lag->weight_policy_flags >> 4;
			info->ext_lag.member_ka = (extended_lag->weight_policy_flags & 0x8) >> 3;
			info->ext_lag.ca = !!(extended_lag->weight_policy_flags &
						FIP_EXT_LAG_W_POLICY_HOST);
			info->ext_lag.ca_thresh = extended_lag->ca_threshold;
			info->ext_lag.ucast = !!(extended_lag->weight_policy_flags &
						 FIP_EXT_LAG_W_POLICY_UCAST);
			info->ext_lag.valid = 1;
		} else if (ext_hdr->ext_type == ADV_EXT_TYPE(BOOT) &&
			   ext_length == sizeof(*extended_boot)) {	/* boot */
			extended_boot = (struct fip_ext_type_boot *)ext_hdr;
			info->ext_boot.boot_prio = extended_boot->boot_prio;
			info->ext_boot.timeout = extended_boot->discovery_timeout;
			info->ext_boot.valid = 1;
		} else if (ext_hdr->ext_type == ADV_EXT_TYPE(PC_ID) && 
			   ext_length == sizeof(*extended_pc_id)) { /* Power Cycle ID */
			extended_pc_id = (struct fip_ext_type_power_cycle_id *)ext_hdr;
			info->ext_pc_id.power_cycle_id =
				be64_to_cpu(extended_pc_id->power_cycle_id);
			info->ext_pc_id.valid = 1;
		} else if (ext_hdr->mandatory & 0x01) {
			vnic_dbg_parse(NULL, "Advertise parse, unknown"
				       " mandatory extended type %d length %d\n",
				       ext_hdr->ext_type, ext_length);
			return -EINVAL;
		} else
			vnic_dbg_parse(NULL, "Advertise parse, unknown "
				       "non-mandatory extended. Skipping, type"
				       " %d length %d\n",
				       ext_hdr->ext_type, ext_length);

		ext_hdr = (struct fip_extended_type *)((char *)ext_hdr + ext_length);
		length_to_go -= ext_length;
	}

	return 0;
}

int fip_advertise_parse_bh(struct fip_discover *discover, struct fip_content *fc,
			   struct fip_gw_data *data)
{
	long ka_time;
	int err = 0;

	/* make sure we have at least a single address descriptor */
	if (fc->fa.num < 1 || !fc->fgwi || !fc->fgid || !fc->fka)
		return -EINVAL;

	data->info.flags = be16_to_cpu(fc->fh->flags) & FIP_FIP_ADVRTS_FLAG ? FIP_GW_AVAILABLE : 0;

	data->info.flags |=
	    (be16_to_cpu(fc->fh->flags) & FIP_FIP_SOLICITED_FLAG) ? 0 :
	    FIP_RCV_MULTICAST;

	data->info.flags |= FIP_IS_FIP;
	data->info.flags |= (fc->fh->flags & FIP_ADVERTISE_HOST_VLANS) ?
	    FIP_HADMINED_VLAN : 0;

	data->info.gw_qpn = be32_to_cpu(fc->fa.fa[0]->gwtype_qpn) & 0xffffff;
	data->info.gw_lid = be16_to_cpu(fc->fa.fa[0]->lid);
	data->info.gw_port_id = be16_to_cpu(fc->fa.fa[0]->sl_gwportid) &
		FIP_ADVERTISE_GW_PORT_ID_MASK;
	data->info.gw_sl = be16_to_cpu(fc->fa.fa[0]->sl_gwportid) >> FIP_ADVERTISE_SL_SHIFT; /*ignore this value.*/
	memcpy(data->info.gw_guid, fc->fa.fa[0]->guid, sizeof(data->info.gw_guid));
	data->info.gw_num_vnics = be16_to_cpu(fc->fgwi->n_rss_qpn_vnics) &
		FIP_ADVERTISE_NUM_VNICS_MASK;

	data->info.n_rss_qpn = be16_to_cpu(fc->fgwi->n_rss_qpn_vnics) >>
		FIP_ADVERTISE_N_RSS_SHIFT;
	data->info.hadmined_en = (fc->fgwi->h_nmac_mgid & FIP_ADVERTISE_HOST_EN_MASK);
	data->info.all_vlan_gw = !!(fc->fgwi->h_nmac_mgid & FIP_ADVERTISE_ALL_VLAN_GW_MASK);

	TERMINATED_MEMCPY(data->info.gw_vendor_id, fc->fgwi->vendor_id);
	memcpy(data->info.vol_info.system_guid, fc->fgid->sys_guid,
	       sizeof(data->info.vol_info.system_guid));
	TERMINATED_MEMCPY(data->info.vol_info.system_name,
			  fc->fgid->sys_name);
	TERMINATED_MEMCPY(data->info.vol_info.gw_port_name, fc->fgid->gw_port_name);

	ka_time	= be32_to_cpu(fc->fka->adv_period);
	ka_time = ka_time ? ka_time : FKA_ADV_PERIOD;
	/* do not let KA go under 2 secs */
	ka_time = (ka_time < 2000) ? 2000 : ka_time;
	data->info.gw_adv_period = FIP_TIMEOUT_FACTOR(msecs_to_jiffies(ka_time));

	ka_time	= be32_to_cpu(fc->fka->ka_period);
	ka_time = ka_time ? ka_time : FKA_ADV_PERIOD;
	data->info.gw_period = FIP_TIMEOUT_FACTOR(msecs_to_jiffies(ka_time));

	ka_time	= be32_to_cpu(fc->fka->vnic_ka_period);
	ka_time = ka_time ? ka_time : FKA_ADV_PERIOD;
	data->info.vnic_ka_period = msecs_to_jiffies(ka_time);

	data->info.gw_type = GW_TYPE_SINGLE_EPORT;
	if (fc->fed.num > 0) {
		if (fc->fed.num == 1) {
			/* new version bxm mode */
			data->info.gw_prot_new = 1;
			err = extract_adv_extended(fc->fed.fed[0], &data->info);
			if (err)
				vnic_dbg_parse(discover->name, "invalid extended descripotr\n");
		} else {
			vnic_dbg_parse(discover->name, "too many extended descripotrs\n");
			return -EINVAL;
		}
	}

	return err;
}

static int send_generic_mcast_pkt(struct vnic_port *port,
				  struct fip_ring *tx_ring,
				  void *mem, int pkt_size,
				  struct ib_qp *qp,
				  int pkey_index,
				  struct vnic_mcast *mcast)
{
	int index, rc;
	unsigned long flags;
	unsigned long tail;

	/*
	 * we are only allowed to update the head at task level so no need to
	 * perform any locks here
	 */
	spin_lock_irqsave(&tx_ring->ring_lock, flags);
	index = tx_ring->head & (tx_ring->size - 1);
	vnic_dbg_fip(port->name, "mcast packet\n");

	spin_lock(&tx_ring->head_tail_lock);
	tail = tx_ring->tail;
	spin_unlock(&tx_ring->head_tail_lock);

	/* ring full try again */
	if (tx_ring->head - tail >=  tx_ring->size) {
		vnic_warn(port->name, "send_generic_mcast_pkt ring full: QPN 0x%x: tail=%ld head=%ld diff=%ld\n",
			  qp->qp_num, tx_ring->tail, tx_ring->head, tx_ring->head - tx_ring->tail);
		rc = -EAGAIN;
		goto err;
	}

	rc = _map_generic_pkt(port, &tx_ring->ring[index], mem, pkt_size);
	if (rc)
		goto err;

	rc = fip_mcast_send(port, qp, index,
			    tx_ring->ring[index].bus_addr,
			    pkt_size, pkey_index, mcast);

	if (rc) {
		vnic_warn(port->name,
			  "send_generic_mcast_pkt: fip_mcast_send ret %d\n",
			  rc);
		rc = -ENODEV;
		goto error_unmap_dma;
	}

	tx_ring->head++;

	spin_unlock_irqrestore(&tx_ring->ring_lock, flags);
	return 0;

error_unmap_dma:
	ib_dma_unmap_single(port->dev->ca,
			    tx_ring->ring[index].bus_addr,
			    pkt_size, DMA_TO_DEVICE);

err:
	spin_unlock_irqrestore(&tx_ring->ring_lock, flags);
	return rc;
}

static void *alloc_solicit_pkt(int new_prot, char *node_desc)
{
	void *ptr;
	struct fip_solicit_new *nptr;
	struct fip_solicit_legacy *optr;
	int size = new_prot ? sizeof *nptr : sizeof *optr;

	ptr = kzalloc(size, GFP_KERNEL);
	if (!ptr)
		return ERR_PTR(-ENOMEM);
	optr = ptr;
	optr->version.version = 1;
	optr->fh.opcode = cpu_to_be16(EOIB_FIP_OPCODE);
	optr->fh.subcode = FIP_HOST_SOL_SUB_OPCODE;
	optr->fh.list_length = cpu_to_be16(size - offsetof(typeof(*optr), fvend)) / 4;
	optr->fvend.ft.type = FIP_TYPE(VENDOR_ID);
	optr->fvend.ft.length = sizeof optr->fvend / 4; 
	strncpy(optr->fvend.vendor_id, "mellanox", sizeof optr->fvend.vendor_id);
	optr->addr.ft.type = FIP_TYPE(ADDRESS);
	optr->addr.ft.length = sizeof optr->addr / 4;
	strncpy(optr->addr.vendor_id, "mellanox", sizeof optr->addr.vendor_id);
	if (new_prot) {
		nptr = ptr;
		nptr->ext.ft.type = 254;
		nptr->ext.ft.length = sizeof nptr->ext / 4;
		strncpy(nptr->ext.vendor_id, "mellanox", sizeof nptr->ext.vendor_id);
		nptr->ext_cap.et.ext_type = 40;
		nptr->ext_cap.et.len = sizeof nptr->ext_cap / 4;
		nptr->ext_cap.et.mandatory = 1;
		nptr->ext_hostname.et.ext_type = 39;
		nptr->ext_hostname.et.len = sizeof nptr->ext_hostname / 4;
		strncpy(nptr->ext_hostname.hostname, node_desc, sizeof nptr->ext_hostname.hostname);
	}

	return ptr;
}

int fip_solicit_send(struct fip_discover *discover,
		     enum fip_packet_type multicast,
		     u32 dqpn, u16 dlid, u8 sl, int new_prot)
{
	int rc = 0;
	unsigned long flags, flags1;
	struct fip_solicit_legacy *optr;
	int size = new_prot ? sizeof(struct fip_solicit_new) : sizeof *optr;

	ASSERT(discover);

	/* alloc packet to be sent */
	optr = alloc_solicit_pkt(new_prot, discover->port->dev->ca->node_desc);
	if (IS_ERR(optr))
		return PTR_ERR(optr);

	/* we set bit 24 to signify that we're a new host */
	optr->addr.gwtype_qpn = cpu_to_be32(discover->qp->qp_num | 0x1000000);
	optr->addr.lid = cpu_to_be16(discover->port->attr.lid);
	/* send the SL to the GW*/
	optr->addr.sl_gwportid = cpu_to_be16(sl << FIP_ADVERTISE_SL_SHIFT);

	memcpy(optr->addr.guid, &discover->port->gid.global.interface_id, sizeof(optr->addr.guid));
	vnic_dbg_fip(discover->name, "fip_solicit_send creating multicast %d"
		     " solicit packet\n", multicast);

	fip_dbg_dump_raw_pkt(0, optr, size, 1, "sending solicit packet");

	if (multicast) {
		struct vnic_mcast *mcaste;
		union ib_gid gid;

		memcpy(&gid, fip_solicit_mgid, GID_LEN);
		spin_lock_irqsave(&discover->mcast_tree.mcast_rb_lock, flags);
		mcaste = vnic_mcast_search(&discover->mcast_tree, &gid);
		/* it is possible for the MCAST entry or AH to be missing in
		 * transient states (after events). This is a valid condition
		 * but we can't send packet
		 */
		if (!IS_ERR(mcaste) && mcaste->ah) {
			spin_lock_irqsave(&mcaste->lock, flags1);
			rc = send_generic_mcast_pkt(discover->port, &discover->tx_ring,
					    optr, size, discover->qp,
					    discover->pkey_index,
					    mcaste);
			spin_unlock_irqrestore(&mcaste->lock, flags1);
		} else
			kfree(optr);

		spin_unlock_irqrestore(&discover->mcast_tree.mcast_rb_lock, flags);
	} else {
		rc = send_generic_ucast_pkt(discover->port, NULL, &discover->tx_ring,
					    optr, size, discover->qp,
					    discover->pkey_index,
					    dqpn, dlid, VNIC_FIP_QKEY, sl);
	}
	if (rc)
		goto error_free_mem;

	return 0;

error_free_mem:
	vnic_warn(discover->name, "discover_send error ret %d\n", rc);
	kfree(optr);
	return -ENOMEM;
}

static void *alloc_login_pkt(struct fip_vnic_data *vnic)
{
	struct eoib_login *ptr;
	int size = sizeof *ptr;

	ptr = kzalloc(size, GFP_KERNEL);
	if (!ptr)
		return ERR_PTR(-ENOMEM);

	ptr->eoib_ver.version = 1;
	ptr->fh.opcode = cpu_to_be16(EOIB_FIP_OPCODE);
	ptr->fh.subcode = FIP_HOST_LOGIN_SUB_OPCODE;
	ptr->fh.list_length = cpu_to_be16(size - offsetof(typeof(*ptr), fvend) / 4);
	ptr->fvend.ft.type = FIP_TYPE(VENDOR_ID);
	ptr->fvend.ft.length = sizeof ptr->fvend / 4; 
	strncpy(ptr->fvend.vendor_id, "mellanox", sizeof ptr->fvend.vendor_id);
	ptr->fa.ft.type = FIP_TYPE(ADDRESS);
	ptr->fa.ft.length = sizeof ptr->fa / 4;
	strncpy(ptr->fa.vendor_id, "mellanox", sizeof ptr->fa.vendor_id);
	ptr->fa.gwtype_qpn = cpu_to_be32(vnic->qp_base_num);
	ptr->fa.sl_gwportid = cpu_to_be16(vnic->gw->info.gw_port_id);
	/* sl will be taken from the data path record query */
	ptr->fa.sl_gwportid |= cpu_to_be16(vnic->gw->data_prec.sl << FIP_ADVERTISE_SL_SHIFT);
	ptr->fa.lid = cpu_to_be16(vnic->port->attr.lid);
	memcpy(ptr->fa.guid, &vnic->port->gid.global.interface_id, sizeof ptr->fa.guid);
	ptr->fl.ft.type = FIP_TYPE(LOGIN);
	ptr->fl.ft.length = sizeof ptr->fl / 4;
	strncpy(ptr->fl.vendor_id, "mellanox", sizeof ptr->fl.vendor_id);
	ptr->fl.vnic_id = cpu_to_be16(vnic->vnic_id);

	if (vnic->hadmined) {
		int mac_valid = !IS_ZERO_MAC(vnic->login_data.mac);
		u16 flags = (mac_valid ? FIP_LOGIN_M_FLAG : 0) |
			    FIP_LOGIN_H_FLAG |
			    (vnic->login_data.vp ? FIP_LOGIN_VP_FLAG  | FIP_LOGIN_V_FLAG : 0);
		ptr->fl.flags_vlan = cpu_to_be16(vnic->login_data.vlan | flags );
		memcpy(ptr->fl.mac, vnic->login_data.mac, sizeof ptr->fl.mac);
		memcpy(ptr->fl.vnic_name, vnic->login_data.vnic_name, sizeof ptr->fl.vnic_name);

		// TODO remove this when BXM handles 0 addresses
		if (!mac_valid)
			ptr->fl.mac[ETH_ALEN-1] = 1;
	}

	/* all_vlan mode must be enforced between the host and GW side.
	   For host admin vnic with VLAN we let the host choose the work mode.
	   If the GW isn't working in that same mode, the login will fail
	   and the host will enter a login-retry loop
	   For net admin vnic or host admin without a vlan, we work in the mode
	   published by the GW */
	if (vnic->gw->info.all_vlan_gw &&
	    (!vnic->hadmined ||
	     (vnic->hadmined && !vnic->login_data.vp)))
		ptr->fl.vfields |= cpu_to_be16(FIP_LOGIN_ALL_VLAN_GW_FLAG);

	ptr->fl.syndrom_ctrl_qpn = cpu_to_be32(vnic->gw->discover->qp->qp_num);
	ptr->fl.vfields |= cpu_to_be16((vnic->qps_num > 1) << 12);

	/* for child vNics, allow implicit logout */
	if (vnic->parent_used) {
		ptr->fl.vfields |= cpu_to_be16(1 << 14);
		ptr->fl.vfields |= cpu_to_be16(1 << 13);
	}

	return ptr;
}

/*
 * Send a unicast login packet. This function supports both host and
 * network admined logins. function returns 0 on success and
 * error code on failure
*/
int fip_login_send(struct fip_vnic_data *vnic)
{
	int ret;
	struct eoib_login *ptr;

	ASSERT(vnic);
	ASSERT(vnic->port);

	/* don't send packet because GW does not support this */
	if (vnic->hadmined && !vnic->gw->hadmin_gw)
		return 0;

	/* alloc packet to be sent */
	ptr = alloc_login_pkt(vnic);
        if (IS_ERR(ptr))
		return PTR_ERR(ptr);

	fip_dbg_dump_raw_pkt(0, ptr, sizeof *ptr, 1, "sending login packet");

	ret = send_generic_ucast_pkt(vnic->port, NULL/*ah : create a new ah inside*/,
				     &vnic->gw->discover->tx_ring,
				     ptr, sizeof *ptr, vnic->gw->discover->qp,
				     vnic->gw->discover->pkey_index,
				     vnic->gw_address.gw_qpn,
				     vnic->gw_address.gw_lid,
				     vnic->gw_address.qkey,
				     vnic_gw_ctrl_sl(vnic->gw));
	if (ret) {
		vnic_warn(vnic->port->name,
			  "fip_login_send: fip_ucast_send ret %d\n", ret);
		goto error_free_mem;
	}

	return 0;

error_free_mem:
	kfree(ptr);
	return -ENOMEM;
}

/*
 * This function creates and sends a few types of packets (all ucast):
 *   vHub context request - new=1, logout=0
 *   vHub context update / vnic keep alive - new=0, logout=0
 *   vnic logout - new=0, logout=1
*/
int fip_update_send(struct fip_vnic_data *vnic, int request_new, int logout)
{
	struct eoib_host_update *pkt;
	struct ib_qp *send_qp;
	struct fip_ring *tx_ring;
	int pkey_index;
	int ret = 0;

	ASSERT(vnic);
	ASSERT(vnic->port);

	/* alloc packet to be sent */
	pkt = kmalloc(sizeof *pkt, GFP_ATOMIC);
	if (!pkt) {
		vnic_warn(vnic->port->name, "fip_update_send malloc failed\n");
		return -EAGAIN;
	}

	/* copy keep alive packet template */
	if (logout)
		memcpy(pkt, &base_logout_pkt, sizeof(struct eoib_host_update));
	else
		memcpy(pkt, &base_update_pkt, sizeof(struct eoib_host_update));

	pkt->fip.opcode = cpu_to_be16(EOIB_FIP_OPCODE);
	pkt->fip.list_length =
	    cpu_to_be16((sizeof(struct eoib_host_update) >> 2) - 3);
	pkt->vnic_id = cpu_to_be16(vnic->vnic_id);
	memcpy(pkt->mac, vnic->login_data.mac, sizeof(pkt->mac));
	memcpy(pkt->vnic_name, vnic->login_data.vnic_name,
	       sizeof(pkt->vnic_name));
	memcpy(pkt->port_guid, &vnic->port->gid.global.interface_id,
	       sizeof(pkt->port_guid));

	pkt->vhub_id.vhub_id = cpu_to_be32(vnic->login_data.vhub_id);

	if (!logout) {
		pkt->tusn = cpu_to_be32(vnic->vhub_table.main_list.tusn);
		send_qp = vnic->qp;
		tx_ring = &vnic->tx_ring;
		pkey_index = vnic->pkey_index;

		if (vnic->login_data.vp)
			pkt->vhub_id.flags.flags |= FIP_HOST_VP_FLAG;

		if (request_new)
			pkt->vhub_id.flags.flags |= FIP_HOST_R_FLAG;
		else
			pkt->vhub_id.flags.flags |= FIP_HOST_U_FLAG;
	} else {
		send_qp = vnic->gw->discover->qp;
		tx_ring = &vnic->gw->discover->tx_ring;
		pkey_index = vnic->gw->discover->pkey_index;
	}

	if (vnic->gw->info.gw_type == GW_TYPE_LAG && 
	    !vnic->gw->info.ext_lag.ucast && !logout) {
		struct vnic_mcast *mcaste;
		unsigned long flags;

		spin_lock_irqsave(&vnic->mcast_tree.mcast_rb_lock, flags);
		mcaste = vnic_mcast_search(&vnic->mcast_tree, &vnic->ka_mcast_gid);
		if (!IS_ERR(mcaste)) {
			if (mcaste->ah) {
				ret = send_generic_mcast_pkt(vnic->port, &vnic->tx_ring,
							     pkt, sizeof *pkt, vnic->qp,
							     vnic->pkey_index, mcaste);
                                vnic_dbg_parse(vnic->name, "sent multicast keep alive\n");
			}
			else {
				vnic_dbg_parse(vnic->name, "mcaste %p: ah is null\n", mcaste);
				kfree(pkt);
			}
		} else {
			vnic_dbg_parse(vnic->name, "ka mcast not found\n");
			ret = -ENOMEM;
		}
		spin_unlock_irqrestore(&vnic->mcast_tree.mcast_rb_lock, flags);

	} else
		/* For LAG gateway the ah is not up to date and therefore
		   should not be used */
		ret = send_generic_ucast_pkt(vnic->port, NULL/*ah : create a new ah inside*/,
					     tx_ring, pkt, sizeof *pkt,
					     send_qp,
					     pkey_index,
					     vnic->gw_address.gw_qpn,
					     vnic->gw_address.gw_lid,
					     vnic->gw_address.qkey,
					     vnic_gw_ctrl_sl(vnic->gw));
	if (ret) {
		vnic_warn(vnic->port->name,
			  "fip_update_send: ret %d\n", ret);
		goto error_free_mem;
	}

	return 0;

error_free_mem:
	kfree(pkt);
	return -ENOMEM;
}

static void dump_lag_member(struct lag_member *m)
{
	vnic_dbg_lag("", "QPN 0x%x, SL %d, gw_portid 0x%x, LID 0x%x, guid " GUID_FORMAT
		       ", eport_state %s, weight %d, link_utilization %d\n",
		       m->qpn, m->sl, m->gw_port_id, m->lid, GUID_ARG(m->guid),
		       eport_state_str(m->eport_state), m->weight, m->link_utilization);
}

static inline int handle_lag_member(struct fip_vnic_data *vnic,
			     struct fip_ext_type_lag_members *ext_lag_membs,
			     int ext_length)
{
	struct lag_members lag_members;

	extract_memb_extended(ext_lag_membs, ext_length, &lag_members, vnic->name);

	/* propogate change in member state as needed */
	return handle_member_update(vnic, &lag_members);
}

int extract_vhub_extended(struct fip_ext_desc_tlv *fed,
			  struct fip_vnic_data *vnic)
{
	struct fip_ext_type_ctrl_iport *ext_ctrl_iport;
	struct fip_ext_type_lag_members *ext_lag_memb;
	struct fip_extended_type *ext_hdr;
	struct fip_vnic_send_info *gw_addr;
	int length_to_go, ext_length;

	if (fed->ft.type != 254)
		return -EINVAL;

	length_to_go = ((int)(fed->ft.length) << 2) - sizeof(*fed);
	ext_hdr = (struct fip_extended_type *)(fed + 1);

	while (length_to_go > 0) {
		ext_length = ((int)ext_hdr->len) << 2;

		vnic_dbg_parse(vnic->name, "Table Update parse, sub-tlv "
			       "type  %d length %d address=%p\n",
			       ext_hdr->ext_type, ext_length, ext_hdr);

		if (ext_length < sizeof(*ext_hdr) ||
		    ext_length > length_to_go) {
			vnic_dbg_parse(vnic->name, "Extended length error."
				       " Length=%d\n", ext_length);
			return -EINVAL;
		}

		switch (ext_hdr->ext_type) {
		case ADV_EXT_TYPE(MEMBER):
			ext_lag_memb = (struct fip_ext_type_lag_members *)ext_hdr;

			if (handle_lag_member(vnic, ext_lag_memb, ext_length))
				vnic_dbg_parse(vnic->name, "handle_lag_member() failed");
			break;
		case ADV_EXT_TYPE(CTRL_IPORT):
			if (ext_length != sizeof(*ext_ctrl_iport)) {
				vnic_dbg_parse(vnic->name, "Extended length %d is"
					       " different than expected\n", 
					       ext_length);
				return -EINVAL;
			}

			gw_addr = &vnic->gw_address;
			ext_ctrl_iport 	= (struct fip_ext_type_ctrl_iport *)ext_hdr;
			gw_addr->gw_qpn = be32_to_cpu(ext_ctrl_iport->gwtype_qpn);
			gw_addr->gw_lid = be16_to_cpu(ext_ctrl_iport->lid);
			gw_addr->gw_sl 	= be16_to_cpu(ext_ctrl_iport->sl_gwportid) >> FIP_ADVERTISE_SL_SHIFT;
			break;
		default:
			if (ext_hdr->mandatory & 0x01) {
				vnic_dbg_parse(vnic->name, "Unknown mandatory extended type %d length %d\n",
					       ext_hdr->ext_type, ext_length);
				return -EINVAL;
			} else {
				vnic_dbg_parse(vnic->name, "Unknown non-mandatory extended. Skipping, type %d length %d\n",
					       ext_hdr->ext_type, ext_length);
				ext_hdr = (struct fip_extended_type *)((char *)ext_hdr + ext_length);
				length_to_go -= ext_length;
					continue;
				}
			}
	
		ext_hdr = (struct fip_extended_type *)((char *)ext_hdr + ext_length);
		length_to_go -= ext_length;
	}

	return 0;
}

static int extract_login_extended(struct fip_ext_desc_tlv *fed,
				  struct lag_members *lagm,
				  char *name)
{
	struct fip_ext_type_lag_members *ext_lag_membs;
	struct fip_extended_type *ext_hdr;
	int length_to_go, ext_length;

	if (fed->ft.type != 254)
		return -EINVAL;

	length_to_go = ((int)(fed->ft.length) << 2) - sizeof(*fed);
	ext_hdr = (struct fip_extended_type *)(fed + 1);

	while (length_to_go > 0) {
		ext_length = ((int)ext_hdr->len) << 2;

		vnic_dbg_parse(name, "Table Update parse, sub-tlv "
			       "type  %d length %d address=%p\n",
			       ext_hdr->ext_type, ext_length, ext_hdr);

		if (ext_length < sizeof(*ext_hdr) ||
		    ext_length > length_to_go) {
			vnic_dbg_parse(name, "Extended length error."
				       " Length=%d\n", ext_length);
			return -EINVAL;
		}

		switch (ext_hdr->ext_type) {
		case ADV_EXT_TYPE(MEMBER):
			ext_lag_membs = (struct fip_ext_type_lag_members *)ext_hdr;

			extract_memb_extended(ext_lag_membs, ext_length, lagm, name);
			
			break;
		default:
			if (ext_hdr->mandatory & 0x01) {
				vnic_dbg_parse(name, "Unknown mandatory extended type %d length %d\n",
					       ext_hdr->ext_type, ext_length);
				return -EINVAL;
			} else {
				vnic_dbg_parse(name, "Unknown non-mandatory extended. Skipping, type %d length %d\n",
					       ext_hdr->ext_type, ext_length);
				ext_hdr = (struct fip_extended_type *)((char *)ext_hdr + ext_length);
				length_to_go -= ext_length;
					continue;
			}
		}
		ext_hdr = (struct fip_extended_type *)((char *)ext_hdr + ext_length);
		length_to_go -= ext_length;
	}

	return 0;
}

void extract_memb_extended(struct fip_ext_type_lag_members *ext_lag_membs,
			   int ext_length,			  
			   struct lag_members *lagm,
			   char *name)
{	
	struct lag_member *m;
	struct fip_ext_type_lag_member *lm;
	int nmemb = 0;
	int i;	

	nmemb = (ext_length - sizeof ext_lag_membs->et) / sizeof *lm;
	if (nmemb > MAX_LAG_MEMBERS) {
		vnic_dbg_parse(name, "recieved %d members but max supported is %d. "
			       "Using only %d\n", nmemb, MAX_LAG_MEMBERS,
			       MAX_LAG_MEMBERS);
		nmemb = MAX_LAG_MEMBERS;
	}

	m = lagm->memb;
	lm = ext_lag_membs->lagm;

	for (i = 0; i < nmemb; ++i, ++lm, ++m) {
		m->qpn = be32_to_cpu(lm->qpn) & 0xffffff;
		m->sl = be16_to_cpu(lm->sl_gw_portid) >> 12;
		m->gw_port_id = be16_to_cpu(lm->sl_gw_portid) & 0xfff;
		m->lid = be16_to_cpu(lm->lid);
		memcpy(m->guid, lm->guid, sizeof m->guid);
		m->eport_state = lm->eport_state >> 6;
		m->weight = lm->weight;
		m->link_utilization = lm->link_utilization;
		dump_lag_member(m);
	}
	lagm->num = nmemb;

	vnic_dbg_parse(name, "Table Update extended parse finished OK. Num members=%d\n",
		       lagm->num);
	return;
}

/*
 * parse a packet that is suspected of being an login ack packet. The packet
 * returns 0 for a valid login ack packet and an error code otherwise. The
 * packets "interesting" details are returned in data.
 */
int fip_login_parse(struct fip_discover *discover, struct fip_content *fc,
		    struct fip_login_data *data)
{
	u32 vfields;
	int err = 0;

	data->syndrome = be32_to_cpu(fc->fl->syndrom_ctrl_qpn) >> 24;
	data->vnic_id = be16_to_cpu(fc->fl->vnic_id);
	data->lid = be16_to_cpu(fc->fa.fa[0]->lid);
	data->port_id = be16_to_cpu(fc->fa.fa[0]->sl_gwportid) & 0xfff;
	data->sl = be16_to_cpu(fc->fa.fa[0]->sl_gwportid) >> FIP_ADVERTISE_SL_SHIFT;
	data->qpn = be32_to_cpu(fc->fa.fa[0]->gwtype_qpn) & 0xffffff;
	memcpy(data->guid, fc->fa.fa[0]->guid, sizeof(data->guid));

	if (be16_to_cpu(fc->fl->flags_vlan) & FIP_LOGIN_VP_FLAG) {
		data->vp = 1;
		data->vlan = be16_to_cpu(fc->fl->flags_vlan) & 0xfff;
	}
	data->all_vlan_gw = !!(be16_to_cpu(fc->fl->vfields) & FIP_LOGIN_ALL_VLAN_GW_FLAG);

	data->vhub_id = CREATE_VHUB_ID(cpu_to_be16(data->vlan), data->port_id);

	data->ctl_qpn = be32_to_cpu(fc->fl->syndrom_ctrl_qpn) & FIP_LOGIN_CTRL_QPN_MASK;
	vfields = be16_to_cpu(fc->fl->vfields);
	data->n_mac_mcgid = vfields & FIP_LOGIN_DMAC_MGID_MASK;
	data->n_rss_mgid = vfields >> 8 & 0xf;
	/* data->rss = pkt->rss & FIP_LOGIN_RSS_MASK; it's redundant in login ack */
	data->pkey = be16_to_cpu(fc->fp->pkey);
	data->mtu = be16_to_cpu(fc->fl->mtu);

	memcpy(data->mac, fc->fl->mac, sizeof(data->mac));
	memcpy(data->mgid_prefix, fc->fl->eth_gid_prefix, sizeof(data->mgid_prefix));
	memcpy(data->vnic_name, fc->fl->vnic_name, sizeof(data->vnic_name));
	memcpy(data->vendor_id, fc->fl->vendor_id, sizeof(data->vendor_id));

	if (fc->fed.num)
		err = extract_login_extended(fc->fed.fed[0], &data->lagm, discover->name);

	return err;
}

/*
 * Check if a received packet is a FIP packet, And if so return its subtype.
 * The FIP type is also returned in fip_type and can be either EOIB_FIP_OPCODE
 * or FCOIB_FIP_OPCODE. If the packet is not a FIP packet -EINVAL is returned.
*/
int fip_pkt_parse(char *buffer, int length, int *fip_type)
{
	struct fip_fip_header *fip_header;
	u16 fip_opcode;

	fip_header = (struct fip_fip_header *)
	    (buffer + IB_GRH_BYTES + sizeof(struct fip_eoib_ver));

	fip_opcode = be16_to_cpu(fip_header->opcode);

	if (fip_opcode != EOIB_FIP_OPCODE) {
		*fip_type = 0;
		return -EINVAL;
	}

	*fip_type = fip_opcode;

	return fip_header->subcode;
}

/*
 * Already know that this is a FIP packet, return its subtype.
*/
int fip_pkt_get_subtype_bh(char *buffer)
{
	struct fip_fip_header *fip_header;

	fip_header = (struct fip_fip_header *)
	    (buffer + sizeof(struct fip_eoib_ver));

	return fip_header->subcode;
}

