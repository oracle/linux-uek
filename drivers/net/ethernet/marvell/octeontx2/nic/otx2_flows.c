// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Physcial Function ethernet driver
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "otx2_common.h"

/* helper macros to support mcam flows */
#define OTX2_MAX_NTUPLE_FLOWS	32
#define OTX2_MAX_UNICAST_FLOWS	8
#define OTX2_MAX_VLAN_FLOWS	1
#define OTX2_MCAM_COUNT		(OTX2_MAX_NTUPLE_FLOWS + \
				 OTX2_MAX_UNICAST_FLOWS + \
				 OTX2_MAX_VLAN_FLOWS)

struct otx2_flow {
	struct ethtool_rx_flow_spec flow_spec;
	struct list_head list;
	u32 location;
	u16 entry;
	bool is_vf;
	int vf;
};

int otx2_mcam_flow_init(struct otx2_nic *pf)
{
	pf->flow_cfg = devm_kzalloc(pf->dev, sizeof(struct otx2_flow_config),
				    GFP_KERNEL);
	if (!pf->flow_cfg)
		return -ENOMEM;

	INIT_LIST_HEAD(&pf->flow_cfg->flow_list);

	pf->flow_cfg->ntuple_max_flows = OTX2_MAX_NTUPLE_FLOWS;

	pf->flags |= (OTX2_FLAG_NTUPLE_SUPPORT |
		      OTX2_FLAG_UCAST_FLTR_SUPPORT |
		      OTX2_FLAG_RX_VLAN_SUPPORT |
		      OTX2_FLAG_VF_VLAN_SUPPORT);

	pf->mac_table = devm_kzalloc(pf->dev, sizeof(struct otx2_mac_table)
					* OTX2_MAX_UNICAST_FLOWS, GFP_KERNEL);

	if (!pf->mac_table)
		return -ENOMEM;

	/* register work queue for ndo callbacks */
	pf->otx2_ndo_wq = create_singlethread_workqueue("otx2_ndo_work_queue");
	if (!pf->otx2_ndo_wq)
		return -ENOMEM;
	INIT_WORK(&pf->otx2_rx_mode_work, otx2_do_set_rx_mode);
	return 0;
}

void otx2_mcam_flow_del(struct otx2_nic *pf)
{
	otx2_destroy_mcam_flows(pf);
	if (pf->otx2_ndo_wq) {
		flush_workqueue(pf->otx2_ndo_wq);
		destroy_workqueue(pf->otx2_ndo_wq);
	}
}

int otx2_alloc_mcam_entries(struct otx2_nic *pfvf)
{
	struct otx2_flow_config *flow_cfg = pfvf->flow_cfg;
	netdev_features_t wanted = NETIF_F_HW_VLAN_STAG_RX |
				   NETIF_F_HW_VLAN_CTAG_RX;
	struct npc_mcam_alloc_entry_req *req;
	struct npc_mcam_alloc_entry_rsp *rsp;
	int vf_vlan_max_flows;
	int i;

	otx2_mbox_lock(&pfvf->mbox);
	if (pfvf->flags & OTX2_FLAG_MCAM_ENTRIES_ALLOC) {
		otx2_mbox_unlock(&pfvf->mbox);
		return 0;
	}

	req = otx2_mbox_alloc_msg_npc_mcam_alloc_entry(&pfvf->mbox);
	if (!req) {
		otx2_mbox_unlock(&pfvf->mbox);
		return -ENOMEM;
	}

	vf_vlan_max_flows = pfvf->total_vfs * OTX2_PER_VF_VLAN_FLOWS;
	req->contig = false;
	req->count = OTX2_MCAM_COUNT + vf_vlan_max_flows;

	/* Send message to AF */
	if (otx2_sync_mbox_msg(&pfvf->mbox)) {
		otx2_mbox_unlock(&pfvf->mbox);
		return -EINVAL;
	}

	rsp = (struct npc_mcam_alloc_entry_rsp *)otx2_mbox_get_rsp
	       (&pfvf->mbox.mbox, 0, &req->hdr);

	if (rsp->count != req->count) {
		netdev_info(pfvf->netdev, "number of rules truncated to %d\n",
			    rsp->count);
		netdev_info(pfvf->netdev,
			    "Disabling RX VLAN offload due to non-availability of MCAM space\n");
		/* support only ntuples here */
		flow_cfg->ntuple_max_flows = rsp->count;
		flow_cfg->ntuple_offset = 0;
		pfvf->netdev->priv_flags &= ~IFF_UNICAST_FLT;
		pfvf->flags &= ~OTX2_FLAG_UCAST_FLTR_SUPPORT;
		pfvf->flags &= ~OTX2_FLAG_RX_VLAN_SUPPORT;
		pfvf->flags &= ~OTX2_FLAG_VF_VLAN_SUPPORT;
		pfvf->netdev->features &= ~wanted;
		pfvf->netdev->hw_features &= ~wanted;
	} else {
		flow_cfg->vf_vlan_offset = 0;
		flow_cfg->ntuple_offset = flow_cfg->vf_vlan_offset +
						vf_vlan_max_flows;
		flow_cfg->unicast_offset = flow_cfg->ntuple_offset +
						OTX2_MAX_NTUPLE_FLOWS;
		flow_cfg->rx_vlan_offset = flow_cfg->unicast_offset +
						OTX2_MAX_UNICAST_FLOWS;
	}

	for (i = 0; i < rsp->count; i++)
		flow_cfg->entry[i] = rsp->entry_list[i];

	pfvf->flags |= OTX2_FLAG_MCAM_ENTRIES_ALLOC;
	otx2_mbox_unlock(&pfvf->mbox);

	return 0;
}

/*  On success adds mcam entry
 *  On failure enable promisous mode
 */
static int otx2_do_add_macfilter(struct otx2_nic *pf, const u8 *mac)
{
	struct otx2_flow_config *flow_cfg = pf->flow_cfg;
	struct npc_install_flow_req *req;
	int err, i;

	if (!(pf->flags & OTX2_FLAG_MCAM_ENTRIES_ALLOC)) {
		err = otx2_alloc_mcam_entries(pf);
		if (err)
			return err;
	}

	if (!(pf->flags & OTX2_FLAG_UCAST_FLTR_SUPPORT))
		return -ENOMEM;

	/* dont have free mcam entries or uc list is greater than alloted */
	if (netdev_uc_count(pf->netdev) > OTX2_MAX_UNICAST_FLOWS)
		return -ENOMEM;

	otx2_mbox_lock(&pf->mbox);
	req = otx2_mbox_alloc_msg_npc_install_flow(&pf->mbox);
	if (!req) {
		otx2_mbox_unlock(&pf->mbox);
		return -ENOMEM;
	}

	/* unicast offset starts with 32 0..31 for ntuple */
	for (i = 0; i <  OTX2_MAX_UNICAST_FLOWS; i++) {
		if (pf->mac_table[i].inuse)
			continue;
		ether_addr_copy(pf->mac_table[i].addr, mac);
		pf->mac_table[i].inuse = true;
		pf->mac_table[i].mcam_entry =
			flow_cfg->entry[i + flow_cfg->unicast_offset];
		req->entry =  pf->mac_table[i].mcam_entry;
		break;
	}

	ether_addr_copy(req->packet.dmac, mac);
	u64_to_ether_addr(0xffffffffffffull, req->mask.dmac);
	req->features = BIT_ULL(NPC_DMAC);
	req->channel = pf->hw.rx_chan_base;
	req->intf = NIX_INTF_RX;
	req->op = NIX_RX_ACTION_DEFAULT;
	req->set_cntr = 1;

	err = otx2_sync_mbox_msg(&pf->mbox);
	otx2_mbox_unlock(&pf->mbox);

	return err;
}

int otx2_add_macfilter(struct net_device *netdev, const u8 *mac)
{
	struct otx2_nic *pf = netdev_priv(netdev);
	int err;

	err = otx2_do_add_macfilter(pf, mac);
	if (err) {
		netdev->flags |= IFF_PROMISC;
		return err;
	}
	return 0;
}

static bool otx2_get_mcamentry_for_mac(struct otx2_nic *pf, const u8 *mac,
				       int *mcam_entry)
{
	int i;

	for (i = 0; i < OTX2_MAX_UNICAST_FLOWS; i++) {
		if (!pf->mac_table[i].inuse)
			continue;

		if (ether_addr_equal(pf->mac_table[i].addr, mac)) {
			*mcam_entry = pf->mac_table[i].mcam_entry;
			pf->mac_table[i].inuse = false;
			return true;
		}
	}
	return false;
}

int otx2_del_macfilter(struct net_device *netdev, const u8 *mac)
{
	struct otx2_nic *pf = netdev_priv(netdev);
	struct npc_delete_flow_req *req;
	int err, mcam_entry;

	/* check does mcam entry exists for given mac */
	if (!otx2_get_mcamentry_for_mac(pf, mac, &mcam_entry))
		return 0;

	otx2_mbox_lock(&pf->mbox);
	req = otx2_mbox_alloc_msg_npc_delete_flow(&pf->mbox);
	if (!req) {
		otx2_mbox_unlock(&pf->mbox);
		return -ENOMEM;
	}
	req->entry = mcam_entry;
	/* Send message to AF */
	err = otx2_sync_mbox_msg(&pf->mbox);
	otx2_mbox_unlock(&pf->mbox);

	return err;
}

static struct otx2_flow *otx2_find_flow(struct otx2_nic *pfvf, u32 location)
{
	struct otx2_flow *iter;

	list_for_each_entry(iter, &pfvf->flow_cfg->flow_list, list) {
		if (iter->location == location)
			return iter;
	}

	return NULL;
}

static void otx2_add_flow_to_list(struct otx2_nic *pfvf, struct otx2_flow *flow)
{
	struct list_head *head = &pfvf->flow_cfg->flow_list;
	struct otx2_flow *iter;

	list_for_each_entry(iter, &pfvf->flow_cfg->flow_list, list) {
		if (iter->location > flow->location)
			break;
		head = &iter->list;
	}

	list_add(&flow->list, head);
}

int otx2_get_flow(struct otx2_nic *pfvf, struct ethtool_rxnfc *nfc,
		  u32 location)
{
	struct otx2_flow *iter;

	if (location >= pfvf->flow_cfg->ntuple_max_flows)
		return -EINVAL;

	list_for_each_entry(iter, &pfvf->flow_cfg->flow_list, list) {
		if (iter->location == location) {
			nfc->fs = iter->flow_spec;
			return 0;
		}
	}

	return -ENOENT;
}

int otx2_get_all_flows(struct otx2_nic *pfvf, struct ethtool_rxnfc *nfc,
		       u32 *rule_locs)
{
	u32 location = 0;
	int idx = 0;
	int err = 0;

	nfc->data = pfvf->flow_cfg->ntuple_max_flows;
	while ((!err || err == -ENOENT) && idx < nfc->rule_cnt) {
		err = otx2_get_flow(pfvf, nfc, location);
		if (!err)
			rule_locs[idx++] = location;
		location++;
	}

	return err;
}

static int otx2_add_flow_msg(struct otx2_nic *pfvf, struct otx2_flow *flow)
{
	u64 ring_cookie = flow->flow_spec.ring_cookie;
	struct npc_install_flow_req *req;
	int err, vf = 0;

	otx2_mbox_lock(&pfvf->mbox);
	req = otx2_mbox_alloc_msg_npc_install_flow(&pfvf->mbox);
	if (!req) {
		otx2_mbox_unlock(&pfvf->mbox);
		return -ENOMEM;
	}

	err = otx2_prepare_flow_request(&flow->flow_spec, req, pfvf);
	if (err) {
		/* free the allocated msg above */
		otx2_mbox_reset(&pfvf->mbox.mbox, 0);
		otx2_mbox_unlock(&pfvf->mbox);
		return err;
	}

	req->entry = flow->entry;
	req->intf = NIX_INTF_RX;
	req->set_cntr = 1;
	req->channel = pfvf->hw.rx_chan_base;
	if (ring_cookie == RX_CLS_FLOW_DISC) {
		req->op = NIX_RX_ACTIONOP_DROP;
	} else {
		/* change to unicast only if action of default entry is not
		 * requested by user
		 */
		if (req->op != NIX_RX_ACTION_DEFAULT)
			req->op = NIX_RX_ACTIONOP_UCAST;
		req->index = ethtool_get_flow_spec_ring(ring_cookie);
		vf = ethtool_get_flow_spec_ring_vf(ring_cookie);
		if (vf > pci_num_vf(pfvf->pdev)) {
			otx2_mbox_unlock(&pfvf->mbox);
			return -EINVAL;
		}
	}

	/* ethtool ring_cookie has (VF + 1) for VF */
	if (vf) {
		req->vf = vf;
		flow->is_vf = true;
		flow->vf = vf;
	}

	/* Send message to AF */
	err = otx2_sync_mbox_msg(&pfvf->mbox);
	otx2_mbox_unlock(&pfvf->mbox);
	return err;
}

int otx2_add_flow(struct otx2_nic *pfvf, struct ethtool_rx_flow_spec *fsp)
{
	struct otx2_flow_config *flow_cfg = pfvf->flow_cfg;
	u32 ring = ethtool_get_flow_spec_ring(fsp->ring_cookie);
	struct otx2_flow *flow;
	bool new = false;
	int err;

	if (ring >= pfvf->hw.rx_queues && fsp->ring_cookie != RX_CLS_FLOW_DISC)
		return -EINVAL;

	if (!(pfvf->flags & OTX2_FLAG_MCAM_ENTRIES_ALLOC)) {
		err = otx2_alloc_mcam_entries(pfvf);
		if (err)
			return err;
	}

	if (fsp->location >= flow_cfg->ntuple_max_flows)
		return -EINVAL;

	flow = otx2_find_flow(pfvf, fsp->location);
	if (!flow) {
		flow = kzalloc(sizeof(*flow), GFP_ATOMIC);
		if (!flow)
			return -ENOMEM;
		flow->location = fsp->location;
		flow->entry = flow_cfg->entry[flow_cfg->ntuple_offset +
						flow->location];
		new = true;
	}
	/* struct copy */
	flow->flow_spec = *fsp;

	err = otx2_add_flow_msg(pfvf, flow);
	if (err) {
		if (new)
			kfree(flow);
		return err;
	}

	/* add the new flow installed to list */
	if (new) {
		otx2_add_flow_to_list(pfvf, flow);
		flow_cfg->nr_flows++;
	}

	return 0;
}

static int otx2_remove_flow_msg(struct otx2_nic *pfvf, u16 entry, bool all)
{
	struct npc_delete_flow_req *req;
	int err;

	otx2_mbox_lock(&pfvf->mbox);
	req = otx2_mbox_alloc_msg_npc_delete_flow(&pfvf->mbox);
	if (!req) {
		otx2_mbox_unlock(&pfvf->mbox);
		return -ENOMEM;
	}

	req->entry = entry;
	if (all)
		req->all = 1;

	/* Send message to AF */
	err = otx2_sync_mbox_msg(&pfvf->mbox);
	otx2_mbox_unlock(&pfvf->mbox);
	return err;
}

int otx2_remove_flow(struct otx2_nic *pfvf, u32 location)
{
	struct otx2_flow_config *flow_cfg = pfvf->flow_cfg;
	struct otx2_flow *flow;
	int err;

	if (location >= flow_cfg->ntuple_max_flows)
		return -EINVAL;

	flow = otx2_find_flow(pfvf, location);
	if (!flow)
		return -ENOENT;

	err = otx2_remove_flow_msg(pfvf, flow->entry, false);
	if (err)
		return err;

	list_del(&flow->list);
	kfree(flow);
	flow_cfg->nr_flows--;

	return 0;
}

int otx2_destroy_ntuple_flows(struct otx2_nic *pfvf)
{
	struct otx2_flow_config *flow_cfg = pfvf->flow_cfg;
	struct npc_delete_flow_req *req;
	struct otx2_flow *iter, *tmp;
	int err;

	if (!(pfvf->flags & OTX2_FLAG_MCAM_ENTRIES_ALLOC))
		return 0;

	otx2_mbox_lock(&pfvf->mbox);
	req = otx2_mbox_alloc_msg_npc_delete_flow(&pfvf->mbox);
	if (!req) {
		otx2_mbox_unlock(&pfvf->mbox);
		return -ENOMEM;
	}

	req->start = flow_cfg->entry[flow_cfg->ntuple_offset];
	req->end   = flow_cfg->entry[flow_cfg->ntuple_offset +
				      flow_cfg->ntuple_max_flows - 1];
	err = otx2_sync_mbox_msg(&pfvf->mbox);
	otx2_mbox_unlock(&pfvf->mbox);

	list_for_each_entry_safe(iter, tmp, &flow_cfg->flow_list, list) {
		list_del(&iter->list);
		kfree(iter);
		flow_cfg->nr_flows--;
	}
	return err;
}

int otx2_destroy_mcam_flows(struct otx2_nic *pfvf)
{
	struct otx2_flow_config *flow_cfg = pfvf->flow_cfg;
	struct npc_mcam_free_entry_req *req;
	struct otx2_flow *iter, *tmp;
	int err;

	if (!(pfvf->flags & OTX2_FLAG_MCAM_ENTRIES_ALLOC))
		return 0;

	/* remove all flows */
	err = otx2_remove_flow_msg(pfvf, 0, true);
	if (err)
		return err;

	list_for_each_entry_safe(iter, tmp, &flow_cfg->flow_list, list) {
		list_del(&iter->list);
		kfree(iter);
		flow_cfg->nr_flows--;
	}

	otx2_mbox_lock(&pfvf->mbox);
	req = otx2_mbox_alloc_msg_npc_mcam_free_entry(&pfvf->mbox);
	if (!req) {
		otx2_mbox_unlock(&pfvf->mbox);
		return -ENOMEM;
	}

	req->all = 1;
	/* Send message to AF to free MCAM entries */
	err = otx2_sync_mbox_msg(&pfvf->mbox);
	if (err) {
		otx2_mbox_unlock(&pfvf->mbox);
		return err;
	}

	pfvf->flags &= ~OTX2_FLAG_MCAM_ENTRIES_ALLOC;
	otx2_mbox_unlock(&pfvf->mbox);

	return 0;
}

int otx2_install_rxvlan_offload_flow(struct otx2_nic *pfvf)
{
	struct otx2_flow_config *flow_cfg = pfvf->flow_cfg;
	struct npc_install_flow_req *req;
	int err;

	if (!(pfvf->flags & OTX2_FLAG_MCAM_ENTRIES_ALLOC))
		return -ENOMEM;

	otx2_mbox_lock(&pfvf->mbox);
	req = otx2_mbox_alloc_msg_npc_install_flow(&pfvf->mbox);
	if (!req) {
		otx2_mbox_unlock(&pfvf->mbox);
		return -ENOMEM;
	}

	req->entry = flow_cfg->entry[flow_cfg->rx_vlan_offset];
	req->intf = NIX_INTF_RX;
	ether_addr_copy(req->packet.dmac, pfvf->netdev->dev_addr);
	u64_to_ether_addr(0xffffffffffffull, req->mask.dmac);
	req->channel = pfvf->hw.rx_chan_base;
	req->op = NIX_RX_ACTION_DEFAULT;
	req->features = BIT_ULL(NPC_OUTER_VID) | BIT_ULL(NPC_DMAC);
	req->vtag0_valid = true;
	req->vtag0_type = NIX_AF_LFX_RX_VTAG_TYPE0;

	/* Send message to AF */
	err = otx2_sync_mbox_msg(&pfvf->mbox);
	otx2_mbox_unlock(&pfvf->mbox);
	return err;
}

static int otx2_delete_rxvlan_offload_flow(struct otx2_nic *pfvf)
{
	struct otx2_flow_config *flow_cfg = pfvf->flow_cfg;
	struct npc_delete_flow_req *req;
	int err;

	otx2_mbox_lock(&pfvf->mbox);
	req = otx2_mbox_alloc_msg_npc_delete_flow(&pfvf->mbox);
	if (!req) {
		otx2_mbox_unlock(&pfvf->mbox);
		return -ENOMEM;
	}

	req->entry = flow_cfg->entry[flow_cfg->rx_vlan_offset];
	/* Send message to AF */
	err = otx2_sync_mbox_msg(&pfvf->mbox);
	otx2_mbox_unlock(&pfvf->mbox);
	return err;
}

int otx2_enable_rxvlan(struct otx2_nic *pf, bool enable)
{
	struct nix_vtag_config *req;
	struct mbox_msghdr *rsp_hdr;
	int err;

	/* Dont have enough mcam entries */
	if (!(pf->flags & OTX2_FLAG_RX_VLAN_SUPPORT))
		return -ENOMEM;

	/* FDSA & RXVLAN are mutually exclusive */
	if (pf->ethtool_flags & OTX2_PRIV_FLAG_FDSA_HDR)
		enable = false;

	if (enable) {
		err = otx2_install_rxvlan_offload_flow(pf);
		if (err)
			return err;
	} else {
		err = otx2_delete_rxvlan_offload_flow(pf);
		if (err)
			return err;
	}

	otx2_mbox_lock(&pf->mbox);
	req = otx2_mbox_alloc_msg_nix_vtag_cfg(&pf->mbox);
	if (!req) {
		otx2_mbox_unlock(&pf->mbox);
		return -ENOMEM;
	}

	/* config strip, capture and size */
	req->vtag_size = VTAGSIZE_T4;
	req->cfg_type = 1; /* rx vlan cfg */
	req->rx.vtag_type = NIX_AF_LFX_RX_VTAG_TYPE0;
	req->rx.strip_vtag = enable;
	req->rx.capture_vtag = enable;

	err = otx2_sync_mbox_msg(&pf->mbox);
	if (err) {
		otx2_mbox_unlock(&pf->mbox);
		return err;
	}

	rsp_hdr = otx2_mbox_get_rsp(&pf->mbox.mbox, 0, &req->hdr);
	if (IS_ERR(rsp_hdr)) {
		otx2_mbox_unlock(&pf->mbox);
		return PTR_ERR(rsp_hdr);
	}

	otx2_mbox_unlock(&pf->mbox);
	return rsp_hdr->rc;
}
