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

static int vnic_ucast_send(struct vnic_login *login, struct sk_buff *skb,
			    struct neighbour *neighbour, int tx_res_index);
/* Push VLAN & EoIB headers and calculate RSS hash value
 * We do the RSS hash here because we already check IP|TCP|UDP
 * in this function for EoIB fields, so we make use of that
 * and do RSS too.
 */
static struct eoibhdr eoib_h_draft = {
	.encap_data = ((VNIC_EOIB_HDR_VER << 4) | (VNIC_EOIB_HDR_SIG << 6)),
	.seg_off = 0,
	.seg_id = 0
};

void vnic_learn_mac(struct net_device *dev, u8 *mac, int remove)
{
	struct vnic_login *login = vnic_netdev_priv(dev);

	vnic_dbg_func(login->name);

	/* skip invalid address */
	if (unlikely(!is_valid_ether_addr(mac)))
		return;

	/* skip parent vNic address (original dev_addr) */
	if (!(memcmp(login->dev_addr, mac, ETH_ALEN)))
		return;

	vnic_dbg_mac(login->name, "learn mac "MAC_6_PRINT_FMT"\n",
		     MAC_6_PRINT_ARG(mac));

	/* update child vNic list, ignore returned code */
	read_lock_bh(&login->mac_rwlock);
	vnic_child_update(login, mac, remove);
	read_unlock_bh(&login->mac_rwlock);
}

u32 vnic_hash(struct net_device *dev, struct sk_buff *skb)
{
	struct tcphdr *tr_h = tcp_hdr(skb);
	struct iphdr *ip_h = ip_hdr(skb);
	struct ipv6hdr *ip_h6 = (struct ipv6hdr *)ip_h;
	u32 hash = 0, addrlen, i;

	/* All mcast traffic is sent and received on 1st queue
	 * because only the 1st QP is attached to the MGIDs
	 * TODO: consider distributing tx/rx mcast traffic as well
	 */
	if (is_multicast_ether_addr(skb_mac_header(skb)))
		goto out;

	switch (ntohs(skb->protocol)) {
	case ETH_P_IP:
		/* In IPv4, access TCP/UDP header only when IP packet is not
		 * fragmented: flags == DF == 0x02.
		 */
		if (ntohs(ip_h->frag_off) >> 13 == 0x2 &&
		    (ip_h->protocol == IPPROTO_TCP ||
		     ip_h->protocol == IPPROTO_UDP)) {
			hash ^= (u32)ntohl(ip_h->saddr);
			hash ^= (u32)ntohl(ip_h->daddr);
			hash ^= (u32)ntohs(tr_h->source);
			hash ^= (u32)ntohs(tr_h->dest);
		}
		break;
	case ETH_P_IPV6:
		/* In IPv6, access TCP/UDP header only when IP packet is not
		 * fragmented: main header nexthdr field points to TCP/UDP
		 */
		if (ip_h6->nexthdr == IPPROTO_TCP ||
		    ip_h6->nexthdr == IPPROTO_UDP) {
			addrlen = ARRAY_LEN(ip_h6->saddr.in6_u.u6_addr32);
			for (i = 0; i < addrlen; ++i) {
				hash ^= (u32)ntohl(ip_h6->saddr.in6_u.u6_addr32[i]);
				hash ^= (u32)ntohl(ip_h6->daddr.in6_u.u6_addr32[i]);
			}
			tr_h = (struct tcphdr *)((void *)ip_h6 + sizeof *ip_h6);
			hash ^= (u32)ntohs(tr_h->source);
			hash ^= (u32)ntohs(tr_h->dest);
		}
	}
out:
	VNIC_SKB_SET_HASH(skb, hash);
	return hash;
}

u8 vnic_lag_hash(struct sk_buff *skb, u16 hash_mask, u16 vid)
{
	struct tcphdr *tr_h = tcp_hdr(skb);
	struct iphdr *ip_h = ip_hdr(skb);
	struct ipv6hdr *ip_h6 = (struct ipv6hdr *)ip_h;
	u32 hash = 0, addrlen, i;
	struct ethhdr *eth = (struct ethhdr *)skb_mac_header(skb);
	u32 hash_dmac, hash_smac, hash_prot, hash_vid;
	u32 hash_sip = 0, hash_dip = 0, hash_sp = 0, hash_dp = 0;
	u8 res_hash;
	u8 *tmp;

	hash_dmac = *(u32 *)(&eth->h_dest[ETH_ALEN - sizeof hash_smac]);
	hash_smac = *(u32 *)(&eth->h_source[ETH_ALEN - sizeof hash_smac]);
	hash_prot = (u32)ntohs(skb->protocol);
	hash_vid  = (u32)vid;

	if (hash_mask & GW_LAG_LAYER_2_3) {
		switch (hash_prot) {
		case ETH_P_IP:
			/* In IPv4, access TCP/UDP header only when IP packet is not
			 * fragmented: flags == DF == 0x02.
			 */
			if (ntohs(ip_h->frag_off) >> 13 == 0x2 &&
			    (ip_h->protocol == IPPROTO_TCP ||
			     ip_h->protocol == IPPROTO_UDP)) {
				hash_sip = (u32)(ip_h->saddr);
				hash_dip = (u32)(ip_h->daddr);
				hash_sp  = (u32)(tr_h->source);
				hash_dp  = (u32)(tr_h->dest);
			}
			break;
		case ETH_P_IPV6:
			/* In IPv6, access TCP/UDP header only when IP packet is not
			 * fragmented: main header nexthdr field points to TCP/UDP
			 */
			if (ip_h6->nexthdr == IPPROTO_TCP ||
			    ip_h6->nexthdr == IPPROTO_UDP) {
				addrlen = ARRAY_LEN(ip_h6->saddr.in6_u.u6_addr32);
				for (i = 0; i < addrlen; ++i) {
					hash_sip ^= (u32)(ip_h6->saddr.in6_u.u6_addr32[i]);
					hash_dip ^= (u32)(ip_h6->daddr.in6_u.u6_addr32[i]);
				}
				tr_h = (struct tcphdr *)((void *)ip_h6 + sizeof *ip_h6);
				hash_sp = (u32)(tr_h->source);
				hash_dp = (u32)(tr_h->dest);
			}
		}
	}

	hash ^= (hash_mask & GW_LAG_HASH_DMAC) ? hash_dmac : 0;
	hash ^= (hash_mask & GW_LAG_HASH_SMAC) ? hash_smac : 0;
	hash ^= (hash_mask & GW_LAG_HASH_TPID) ? hash_prot : 0;
	hash ^= (hash_mask & GW_LAG_HASH_VID)  ? hash_vid  : 0;
	hash ^= (hash_mask & GW_LAG_HASH_SIP)  ? hash_sip  : 0;
	hash ^= (hash_mask & GW_LAG_HASH_DIP)  ? hash_dip  : 0;
	hash ^= (hash_mask & GW_LAG_HASH_SPORT)  ? hash_sp  : 0;
	hash ^= (hash_mask & GW_LAG_HASH_DPORT)  ? hash_dp  : 0;

	tmp  = (u8 *)&hash;
	res_hash = tmp[0] ^ tmp[1] ^ tmp[2] ^ tmp[3];

	return res_hash;
}

static inline int vnic_header_encap(struct sk_buff *skb)
{
	struct vnic_login *login = vnic_netdev_priv(skb->dev);
	struct eoibhdr *eoib_h;
	struct iphdr *ip_h = ip_hdr(skb);
	struct ipv6hdr *ip_h6 = (struct ipv6hdr *)ip_h;

	/* push VLAN header
	 * TODO: when VID iz zero, push header only when prio exists, i.e.:
	 * if (VNIC_VLAN_ENABLED(login) && (login->vid || login->user_prio))
	 */
	if (VNIC_VLAN_ENABLED(login) && login->vid) {
		struct vlan_ethhdr *veth =
			(struct vlan_ethhdr *)skb_push(skb, VLAN_HLEN);
		ASSERT(veth);
		vnic_dbg_data_v(login->name, "push vlan tag with ID %u\n",
				be16_to_cpu(login->vid));
		memmove(skb->data, skb->data + VLAN_HLEN, 2 * ETH_ALEN);
		veth->h_vlan_proto = htons(ETH_P_8021Q);
		veth->h_vlan_TCI = login->vid;
	}

	/* push EoIB header */
	if (vnic_encap_headroom)
		skb_push(skb, VNIC_ENCAP_LEN);

	/* reset MAC header here, it can be changed for the following reasons:
	 * - vnic_encap_headroom is set, thus EoIB header is pushed
	 * - VLAN is enabled, thus VLAN header is pushed
	 * - some kernels (e.g., 2.6.18-194.el5) call dev_hard_start_xmit()
	 *   without setting the mac header pointer
	 */
	skb_set_mac_header(skb, VNIC_SKB_GET_ENCAP_OFFSET);

	/* enforce source mac*/
	if (vnic_src_mac_enforce)
		memcpy(skb_mac_header(skb) + ETH_ALEN,
		       login->dev->dev_addr, ETH_ALEN);

	/* set EoIB header VER/SIG, others set to zero */
	eoib_h = VNIC_SKB_GET_ENCAP(skb);
	*eoib_h = eoib_h_draft;

	/* set EoIB header IP_CHK */
	switch (ntohs(skb->protocol)) {
	case ETH_P_IP:
		VNIC_EOIB_HDR_SET_IP_CHK_OK(eoib_h);
		if (ip_h->protocol == IPPROTO_TCP)
			VNIC_EOIB_HDR_SET_TCP_CHK_OK(eoib_h);
		else if (ip_h->protocol == IPPROTO_UDP)
			VNIC_EOIB_HDR_SET_UDP_CHK_OK(eoib_h);
		break;
	case ETH_P_IPV6:
		VNIC_EOIB_HDR_SET_IP_CHK_OK(eoib_h);
		if (ip_h6->nexthdr == IPPROTO_TCP)
			VNIC_EOIB_HDR_SET_TCP_CHK_OK(eoib_h);
		else if (ip_h6->nexthdr == IPPROTO_UDP)
			VNIC_EOIB_HDR_SET_UDP_CHK_OK(eoib_h);
	}

#ifdef _BP_NETDEV_NO_TMQ
	/* if TSS is enabled, use the hash value calculated by
	 * vnic_select_queue() otherwise call vnic_hash()
	 */
	vnic_hash(skb->dev, skb);
#endif

	return 0;
}

static void vnic_neigh_path_query_complete(int status,
										   struct ib_sa_path_rec *pathrec,
										   void *context)
{
	struct vnic_neigh *neigh = context;
	struct ib_ah *old_ah, *new_ah;
	struct net_device *dev = neigh->login->dev;
	struct sk_buff_head skqueue;
	struct vnic_login *login = neigh->login;

	if (status) {
		vnic_dbg_data(neigh->login->name, "neigh %d "MAC_6_PRINT_FMT" path query complete FAILED\n",
						neigh->lid, MAC_6_PRINT_ARG(neigh->mac));
		goto drop_pkts;
	} else {
		struct ib_ah_attr av;
		struct sk_buff *skb;
		vnic_dbg_data(login->name, "neigh %d "MAC_6_PRINT_FMT" path query complete sucess SL=%d\n",
						neigh->lid, MAC_6_PRINT_ARG(neigh->mac), pathrec->sl);
		if(ib_init_ah_from_path(login->port->dev->ca, login->port->num, pathrec, &av)){
			vnic_warn(login->name, "ib_init_ah_from_path %d "MAC_6_PRINT_FMT" failed!\n",
						neigh->lid, MAC_6_PRINT_ARG(neigh->mac));
			goto drop_pkts;
		}

		old_ah = neigh->ah;
		new_ah = ib_create_ah(login->port->pd, &av);
		if (IS_ERR(new_ah) || !new_ah) {
			vnic_warn(login->name, "ib_create_ah %d "MAC_6_PRINT_FMT" failed!\n",
						neigh->lid, MAC_6_PRINT_ARG(neigh->mac));

			goto drop_pkts;
		}

		neigh->sl = pathrec->sl;
		skb_queue_head_init(&skqueue);
		netif_tx_lock_bh(login->dev);
		neigh->ah = new_ah;
		neigh->valid = 1;
		neigh->query_id = -1;
		while ((skb = __skb_dequeue(&neigh->pkt_queue)))
			__skb_queue_tail(&skqueue, skb);
		netif_tx_unlock_bh(login->dev);

		/* retransmit all pending packets */
		while ((skb = __skb_dequeue(&skqueue))) {
			/* reset skb headers */
			/* TODO ALL VLAN ?? */
			if (VNIC_VLAN_ENABLED(login) && login->vid)
				skb_pull(skb, VLAN_HLEN);
			if (vnic_encap_headroom)
				skb_pull(skb, VNIC_ENCAP_LEN);

			skb->dev = dev;
			dev_queue_xmit(skb);
		}

		if (old_ah && !IS_ERR(old_ah))
			ib_destroy_ah(old_ah);
	}
	complete(&neigh->query_comp);
	return;

drop_pkts:
	netif_tx_lock_bh(dev);
	neigh->query_id = -1; /* this will cause a retry */
	while (!skb_queue_empty(&neigh->pkt_queue))
	{
		struct sk_buff *skb = skb_dequeue(&neigh->pkt_queue);
		int tx_res_index;
		struct vnic_tx_res *tx_res;
		skb->dev = dev;
		tx_res_index = VNIC_TXQ_GET_HASH(skb, login->real_tx_rings_num);
		ASSERT(tx_res_index <= login->tx_rings_num);
		tx_res = &login->tx_res[tx_res_index];
		VNIC_STATS_DO_INC(tx_res->stats.tx_dropped);
		dev_kfree_skb_any(skb);
	}
	netif_tx_unlock_bh(dev);
	complete(&neigh->query_comp);
}

int vnic_neighe_path_query(struct vnic_neigh *neighe)
{
	ib_sa_comp_mask comp_mask;
	struct ib_sa_path_rec p_rec;
	u16 slid = neighe->login->port->attr.lid;
	vnic_dbg_data(neighe->login->vnic_name,"neighe SL Query slid %d dlid %d dmac:"MAC_6_PRINT_FMT"\n",
				  slid, neighe->lid, MAC_6_PRINT_ARG(neighe->mac));

	comp_mask =        IB_SA_PATH_REC_SERVICE_ID  |
					   IB_SA_PATH_REC_DLID        |
					   IB_SA_PATH_REC_SLID        |
					   IB_SA_PATH_REC_PKEY;

	if (IS_NEIGH_QUERY_RUNNING(neighe))
		ib_sa_cancel_query(neighe->query_id, neighe->pquery);

	init_completion(&neighe->query_comp);
	neighe->query_id = -1;
	neighe->pquery = NULL;

	p_rec.dlid = cpu_to_be16(neighe->lid);
	p_rec.slid = cpu_to_be16(slid);
	p_rec.service_id = cpu_to_be64(EOIB_SERVICE_ID);
	p_rec.pkey = cpu_to_be16(neighe->login->pkey);

	neighe->query_id = ib_sa_path_rec_get(&vnic_sa_client,
                                          neighe->login->port->dev->ca,
                                          neighe->login->port->num,
                                          &p_rec,
                                          comp_mask,
                                          1000/*TOUT*/,
                                          GFP_ATOMIC,
                                          vnic_neigh_path_query_complete,
                                          neighe,
                                          &neighe->pquery);
	if (neighe->query_id < 0) {
		vnic_dbg_data(neighe->login->vnic_name, "FAILED neigh SL Query slid %d dlid %d dmac:"MAC_6_PRINT_FMT"\n",
			  slid, neighe->lid, MAC_6_PRINT_ARG(neighe->mac));
		complete(&neighe->query_comp);
	}
	return neighe->query_id;
}

static int vnic_ucast_send(struct vnic_login *login, struct sk_buff *skb,
			    struct neighbour *neighbour, int tx_res_index)
{
	struct vnic_neigh *neighe;
	int hash;

	neighe = vnic_neighe_search(login, skb_mac_header(skb));
	if (IS_ERR(neighe)) {
		vnic_dbg_data(login->name, "no dst_neigh and no vnic_neigh - "
			      "gw unicast packet\n");

		/* for egress unicast traffic of a shared vnic,
		 * replace src mac by shared mac
		 */
		if (login->shared_vnic)
			memcpy(skb_mac_header(skb) + ETH_ALEN,
			       login->shared_mac, ETH_ALEN);

		if (!login->is_lag)
			neighe = login->gw_neigh;
		else {
			if (unlikely(!login->lag_member_active_count))
				return -ENOENT;

			/* use hash value precomputed and mapping to find LAG GW to send to */
			hash = vnic_lag_hash(skb, login->lag_prop.hash_mask, login->vid);
			hash = hash % LAG_MAP_TABLE_SIZE;
			neighe = &login->lag_gw_neigh[login->lag_gw_map[hash]].neigh;
		}

		/* update GW statistics */
		VNIC_STATS_ADD(login->port_stats.gw_tx_bytes, skb->len);
		VNIC_STATS_INC(login->port_stats.gw_tx_packets);
	} else {
		vnic_dbg_data(login->name,
			      "no dst_neigh but vnic_neigh exists - "
			      "local unicast packet\n");
	}

	/* TODO: in VNIC_NEIGH_GET_DQPN use neigh qps_num instead of login */
	vnic_dbg_data(login->name, "vnic_send to (base qpn 0x%06x) dqpn 0x%06x"
		      " dlid 0x%08x %s\n", neighe->qpn,
		      VNIC_NEIGH_GET_DQPN(skb, neighe), neighe->lid,
		      neighe == login->gw_neigh ? "[GW]" : "");

	if (unlikely(vnic_sa_query && !neighe->valid)) {
		/* query neigh ah*/
		vnic_dbg_data(login->name, "AH is not %s, running path query: LID=%d mac="MAC_6_PRINT_FMT"\n",
				  !IS_ERR(neighe->ah) && neighe->ah ? "valid":"found",
				  neighe->lid, MAC_6_PRINT_ARG(neighe->mac));

		if (!IS_NEIGH_QUERY_RUNNING(neighe))
			vnic_neighe_path_query(neighe);

		if (IS_ERR(neighe->ah) || !neighe->ah)
		{   /* AH is not ready yet, Queue pkt */
			if (skb_queue_len(&neighe->pkt_queue) > VNIC_SKB_QUEUE_LEN || !IS_NEIGH_QUERY_RUNNING(neighe))
				return 1; /* Drop in case queue is full or no query is currently runnig*/
			__skb_queue_tail(&neighe->pkt_queue, skb);
			return 0;
		}
		/* if ah is initialized send anyway */
	}
	vnic_send(login, skb, neighe->ah, VNIC_NEIGH_GET_DQPN(skb, neighe), tx_res_index);
	return 0;
}

void vnic_mcast_send(struct vnic_login *login, struct sk_buff *skb, int tx_res_index)
{
	struct vnic_mcast *mcaste;
	union vhub_mgid mgid;
	struct ethhdr *eth;
	struct vnic_tx_res *tx_res = &login->tx_res[tx_res_index];
	struct ib_ah_attr *av = &tx_res->mcast_av;
	struct ib_ah *ah;
	u16 gw_id;
	int hash;

	eth = (struct ethhdr *)skb_mac_header(skb);

	/* for LAG GW, perform hashing on mcast address */
	if (login->is_lag && login->lag_member_active_count) {
		hash = vnic_lag_hash(skb, login->lag_prop.hash_mask, login->vid);
		hash = hash % LAG_MAP_TABLE_SIZE;
		gw_id = login->lag_gw_neigh[login->lag_gw_map[hash]].gw_id;
	}
	else
		gw_id = login->gw_port_id;

	/* retrieve the mlid */
	vhub_mgid_create(login->mgid_prefix, ETH_ZERO_MAC, login->n_mac_mcgid,
			 CREATE_VHUB_ID(login->vid, gw_id),
			 VHUB_MGID_DATA, 0, &mgid);

	spin_lock(&login->mcast_tree.mcast_rb_lock);
	mcaste = vnic_mcast_search(&login->mcast_tree, &mgid.ib_gid);
	if (unlikely(IS_ERR(mcaste) || !mcaste->ah)) {
		vnic_dbg_data(login->name, "couldn't find mcaste for "
			      MAC_6_PRINT_FMT"\n",
			      MAC_6_PRINT_ARG(eth->h_dest));
		spin_unlock(&login->mcast_tree.mcast_rb_lock);
		goto drop;
	}

	spin_lock(&mcaste->lock);
	vhub_mgid_create(login->mgid_prefix, eth->h_dest, login->n_mac_mcgid,
			 CREATE_VHUB_ID(login->vid, gw_id),
			 vnic_mgid_data_type, 0, &mgid);
	vnic_dbg_mcast_v(login->name, "sending to ETH "MAC_6_PRINT_FMT"-> "
			 "GID "VNIC_GID_FMT" (mask %d bit)\n",
			 MAC_6_PRINT_ARG(eth->h_dest),
			 VNIC_GID_ARG(mgid.ib_gid),
			 login->n_mac_mcgid);

	av->dlid = be16_to_cpu(mcaste->port_mcaste->rec.mlid);
	av->static_rate = mcaste->port_mcaste->rec.rate;
	av->sl = mcaste->port_mcaste->rec.sl;
	memcpy(&av->grh.dgid, mgid.ib_gid.raw, GID_LEN);

	ah = ib_create_ah(login->port->pd, av);
	spin_unlock(&mcaste->lock);
	spin_unlock(&login->mcast_tree.mcast_rb_lock);

	if (!ah || IS_ERR(ah))
		goto drop;

	vnic_send(login, skb, ah, IB_MULTICAST_QPN, tx_res_index);
	ib_destroy_ah(ah);
	/* used as a counter for multicast TX packets (not RX) */
	VNIC_STATS_DO_INC(tx_res->stats.multicast);

	return;

drop:
	VNIC_STATS_DO_INC(tx_res->stats.tx_dropped);
	dev_kfree_skb_any(skb);
}

int vnic_tx(struct sk_buff *skb, struct net_device *dev)
{
	struct vnic_login *login = vnic_netdev_priv(dev);
	int tx_res_index = 0, headroom = dev->hard_header_len - ETH_HLEN;
	struct vnic_tx_res *tx_res = &login->tx_res[tx_res_index];

	ASSERT(dev);
	ASSERT(skb);
#ifdef VNIC_PROFILLNG
	login->prof_arr[login->prof_arr_it].cnt++;
	/* copy only fields for reporting, data buffer is invalid */
	login->prof_arr[login->prof_arr_it].skb = *skb;
	login->prof_arr[login->prof_arr_it].skb.data = NULL;
	login->prof_arr[login->prof_arr_it].tstamp = current_kernel_time();
	login->prof_arr[login->prof_arr_it].jiffies = jiffies;
	login->prof_arr[login->prof_arr_it].nr_frags = skb_shinfo(skb)->nr_frags;
	login->prof_arr_it = (login->prof_arr_it + 1) % VNIC_PROFILLNG_SKB_MAX;

#endif

	/* drop zero length skbs */
	if (unlikely(!skb->len))
		goto drop;

	/* sometimes, vnic_tx is called before carrier is up FM #100882 */
	if (unlikely(!test_bit(VNIC_STATE_NETDEV_CARRIER_ON, &login->netdev_state)))
		goto drop;

	/* check headroom and reallocate skb if needed:
	 * If VLAN used: need VLAN_HLEN (4) Bytes
	 * If vnic_encap_headroom set: need VNIC_ENCAP_LEN (4) Bytes
	 * when vnic_encap_headroom is clear, we do not encap EoIB header
	 * into the headroom, but rather use additional SG entry to hold it
	 */

	if (unlikely(skb_headroom(skb) < headroom)) {
		struct sk_buff *skb_new;

		skb_new = skb_realloc_headroom(skb, headroom);
		if (!skb_new)
			goto drop;

		dev_kfree_skb(skb);
		skb = skb_new;
		VNIC_STATS_INC(login->port_stats.realloc_packets);
	}
	/* don't use dev->header_ops, use vnic_header_encap() inline
	 * function instead, because when raw socket is used or BR_CTL mode
	 * then header_ops are not called as expected, and we'll end up sending
	 * the packet without EoIB header
	 */
	if (unlikely(vnic_header_encap(skb)))
		goto drop;

	/* in promiscuous mode, learn the source mac */
	if (is_ucast_promisc(login) && vnic_learn_mac_enabled)
		vnic_learn_mac(dev, skb_mac_header(skb) + ETH_ALEN, 0);

	/* get TX resource for this SKB, keep it after vnic_header_encap()
	 * so if we don't have kernel multiple queue support we use the
	 * RSS hash result for TSS
	 */
	tx_res_index = VNIC_TXQ_GET_HASH(skb, login->real_tx_rings_num);
	ASSERT(tx_res_index <= login->tx_rings_num);
	tx_res = &login->tx_res[tx_res_index];


	/* send ucast/mcast packet */
	vnic_dbg_skb("TX", skb, (unsigned long)(vnic_encap_headroom ? 0 : -1),
		     (unsigned long)(vnic_encap_headroom ? VNIC_ENCAP_LEN : 0));
#if 0 /* neighbour caching disabled */
	if (likely(skb->dst && skb->dst->neighbour)) {
		if (is_multicast_ether_addr(skb_mac_header(skb))) {
			vnic_dbg_data(login->name,
				      "dst_neigh exists but no vnic_neigh - "
				      "multicast packet\n");
			vnic_mcast_send(login, skb, tx_res_index);
		} else {
			vnic_dbg_data(login->name,
				      "dst_neigh exists but no vnic_neigh - "
				      "unicast packet\n");
			vnic_ucast_send(login, skb, skb->dst->neighbour, tx_res_index);
		}
	} else 
#endif
	{
		if (is_multicast_ether_addr(skb_mac_header(skb))) {
			vnic_dbg_data(login->name,
				      "no dst_neigh - multicast packet\n");
			vnic_mcast_send(login, skb, tx_res_index);
		} else {
			vnic_dbg_data(login->name,
				      "no dst_neigh - unicast packet\n");
			if (unlikely(vnic_ucast_send(login, skb, NULL, tx_res_index)))
				goto drop;
		}
	}

	return NETDEV_TX_OK;

drop:
	dev_kfree_skb(skb);
	return NETDEV_TX_OK;
}
