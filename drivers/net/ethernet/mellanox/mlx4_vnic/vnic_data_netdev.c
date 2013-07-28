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

extern struct net_device_stats *mlx4_vnic_stats_func_container(struct net_device *n);

static int mlx4_vnic_vlan_rx_add_vid(struct net_device *dev, unsigned short vid)
{
	struct vnic_login *login = vnic_netdev_priv(dev);

	vnic_dbg_data(login->name, "add VLAN:%d was called\n", vid);
	return 0;
}

static int mlx4_vnic_vlan_rx_kill_vid(struct net_device *dev, unsigned short vid)
{
	struct vnic_login *login = vnic_netdev_priv(dev);

	vnic_dbg_data(login->name, "Kill VID:%d was called\n", vid);
	return 0;
}

void vnic_carrier_update(struct vnic_login *login)
{
	int attached, eport_up, eport_enforce, carrier_ok;

	ASSERT(login);
	attached = test_bit(VNIC_STATE_LOGIN_BCAST_ATTACH, &login->fip_vnic->login_state);
	eport_up = fip_vnic_get_eport_state(login->fip_vnic);
	eport_enforce = vnic_eport_state_enforce;
	carrier_ok = netif_carrier_ok(login->dev);

	/* bring carrier up */
	if (!carrier_ok && attached && (!eport_enforce || eport_up)) {
		set_bit(VNIC_STATE_NETDEV_CARRIER_ON, &login->netdev_state);
		netif_carrier_on(login->dev);
		vnic_info("%s link is up\n", login->dev->name);
		return;
	}

	/* bring carrier down */
	if (carrier_ok && (!attached || (!eport_up && eport_enforce))) {
		clear_bit(VNIC_STATE_NETDEV_CARRIER_ON, &login->netdev_state);
		netif_carrier_off(login->dev);
		vnic_info("%s link is down\n", login->dev->name);
		return;
	}

}

void __bcast_attach_cb(struct vnic_mcast *mcaste, void *login_ptr)
{
	struct vnic_login *login = login_ptr;

	/* When SA is local, mcast join works even when port is down */
	if (login->port->attr.state != IB_PORT_ACTIVE)
		return;
	set_bit(VNIC_STATE_LOGIN_BCAST_ATTACH, &login->fip_vnic->login_state);
	vnic_carrier_update(login);
}

void __bcast_detach_cb(struct vnic_mcast *mcaste, void *login_ptr)
{
	struct vnic_login *login = login_ptr;

	clear_bit(VNIC_STATE_LOGIN_BCAST_ATTACH, &login->fip_vnic->login_state);
	vnic_carrier_update(login);
}

/* this function cannot sleep, avoid any mutex() in consequent calls */
static int vnic_set_mac(struct net_device *dev, void *_mac)
{
	struct vnic_login *login = vnic_netdev_priv(dev);
	struct sockaddr *saddr = _mac;
	u8 *mac = (u8 *)(saddr->sa_data);
	int rc = 0;

	vnic_dbg_func(login->name);

	vnic_dbg_mac(login->name, "mac "MAC_6_PRINT_FMT" => "MAC_6_PRINT_FMT"\n",
		     MAC_6_PRINT_ARG((u8 *)(dev->dev_addr)),
		     MAC_6_PRINT_ARG(mac));

	/* must support child vNics for mac modification */
	if (!vnic_child_max)
		return -ENOSYS;

	/* skip if invalid address */
	if (unlikely(!is_valid_ether_addr(mac)))
		return -EINVAL;

	/* skip if same mac was already set */
	if (!(memcmp((u8 *)(dev->dev_addr), mac, ETH_ALEN)))
		return 0;

	/* already in bh, calls vnic_child_update that queues a job,
	 * so read_lock is enough
	 */
	read_lock(&login->mac_rwlock);

	/* if mac same as original, delete child, set mac and return */
	if (!(memcmp(mac, login->dev_addr, ETH_ALEN)))
		goto out;

	/* else, this is a new child vNic,
	 * add new child vNic
	 * NOTE: pay attention that the GC should not destroy a child vNic that
	 * is being used as mac-change even if it was created by different
	 * source.
	 */
	rc = vnic_child_update(login, mac, 0);
	if (rc && rc != -EEXIST)
		goto err;

out:
	memcpy(dev->dev_addr, mac, ETH_ALEN);
	vnic_child_update(login, (u8 *)(dev->dev_addr), 1);
	vnic_dbg_mac(login->name, "mac changed successfully to "
		     MAC_6_PRINT_FMT"\n", MAC_6_PRINT_ARG(mac));

err:
	read_unlock(&login->mac_rwlock);
	return rc;
}

static void vnic_set_multicast_list(struct net_device *dev)
{
	struct vnic_login *login = vnic_netdev_priv(dev);

	vnic_dbg_func(login->name);

	/* test promisc flag changes */
	if (is_ucast_promisc(login) && !login->promisc) {
		/* promisc is being set */
		if (!vnic_child_max) {
			/* must support child vNics for promisc mode */
			vnic_info("%s promisc mode cannot be set "
				  "(vnic_child_max %u)\n",
				  dev->name, vnic_child_max);
		 } else if (vnic_src_mac_enforce) {
			/* cannot support promisc if source mac is enforced
			 * because sender should be able to use any smac
			 */
			vnic_info("%s promisc mode cannot be set "
				  "(vnic_src_mac_enforce %u)\n",
				  dev->name, vnic_src_mac_enforce);
		 } else {
			 login->promisc = 1;
			 vnic_dbg_mac(dev->name,
				      "entered promiscuous mode: confirmed\n");
		 }
	} else if (!is_ucast_promisc(login) && login->promisc) {
		/* promisc is being cleared */
		login->promisc = 0;
		write_lock(&login->mac_rwlock);
		vnic_child_flush(login, 0);
		write_unlock(&login->mac_rwlock);
		vnic_dbg_mac(dev->name,
			     "left promiscuous mode: confirmed\n");
	}

	/* test mcast changes */
	if (!no_bxm && !login->queue_stopped) {
		dev_hold(dev);
		if (!queue_delayed_work(login_wq, &login->mcast_task, HZ / 100))
			dev_put(dev);
	}
}

static void vnic_auto_moder(struct vnic_login *login)
{
	unsigned long period =
		(unsigned long)(jiffies - login->last_moder_jiffies);
	unsigned long packets;
	unsigned long rate;
	unsigned long avg_pkt_size;
	unsigned long rx_packets;
	unsigned long rx_bytes;
	unsigned long tx_packets;
	unsigned long tx_pkt_diff;
	unsigned long rx_pkt_diff;
	int moder_time;

	period = (unsigned long)(jiffies - login->last_moder_jiffies);
#if 0
	vnic_dbg_moder_v(login->name, "adaptive_rx_coal %d, period %d, "
			 "sample_interval %d, state %d\n",
			 login->adaptive_rx_coal, period,
			 login->sample_interval, login->port->attr.state);
#endif

	if (!login->adaptive_rx_coal || period < login->sample_interval * HZ)
		return;

	/* TODO: when NAPI is disabled, the RX completion will be called from
	 * IRQ context (and not BH context) and thus spin_lock_bh should be
	 * replaced with spin_lock_irq
	 */
	spin_lock_bh(&login->stats_lock);
	rx_packets = login->stats.rx_packets;
	rx_bytes = login->stats.rx_bytes;
	tx_packets = login->stats.tx_packets;
	spin_unlock_bh(&login->stats_lock);

	if (!login->last_moder_jiffies || !period)
		goto out_set;

	tx_pkt_diff = ((unsigned long)(tx_packets -
				       login->last_moder_tx_packets));
	rx_pkt_diff = ((unsigned long)(rx_packets - login->last_moder_packets));
	packets = max(tx_pkt_diff, rx_pkt_diff);
	rate = packets * HZ / period;
	avg_pkt_size = packets ? ((unsigned long)(rx_bytes -
						  login->last_moder_bytes)) /
	    packets : 0;

	if (rate > VNIC_RX_RATE_THRESH && avg_pkt_size > VNIC_AVG_PKT_SMALL) {
		/* If tx and rx packet rates are not balanced, assume that
		 * traffic is mainly BW bound and apply maximum moderation.
		 * Otherwise, moderate according to packet rate */
		if (2 * tx_pkt_diff > 3 * rx_pkt_diff ||
		    2 * rx_pkt_diff > 3 * tx_pkt_diff) {
			moder_time = login->rx_usecs_high;
		} else {
			if (rate < login->pkt_rate_low)
				moder_time = login->rx_usecs_low;
			else if (rate > login->pkt_rate_high)
				moder_time = login->rx_usecs_high;
			else
				moder_time = (rate - login->pkt_rate_low) *
					(login->rx_usecs_high - login->rx_usecs_low) /
					(login->pkt_rate_high - login->pkt_rate_low) +
					login->rx_usecs_low;
		}
	} else {
		moder_time = login->rx_usecs_low;
	}

	if (moder_time != login->last_moder_time) {
		vnic_dbg_moder(login->name, "tx rate:%lu rx_rate:%lu\n",
			       tx_pkt_diff * HZ / period,
			       rx_pkt_diff * HZ / period);
		vnic_dbg_moder(login->name,
			       "Rx moder_time changed from:%lu to %d period:%lu"
			       " [jiff] packets:%lu avg_pkt_size:%lu rate:%lu"
			       " [p/s])\n", login->last_moder_time, moder_time,
			      period, packets, avg_pkt_size, rate);
		login->last_moder_time = moder_time;
		vnic_ib_set_moder(login,
				  login->last_moder_time, login->rx_frames,
				  login->tx_usecs, login->tx_frames);
	}

out_set:
	login->last_moder_packets = rx_packets;
	login->last_moder_tx_packets = tx_packets;
	login->last_moder_bytes = rx_bytes;
	login->last_moder_jiffies = jiffies;
}

void vnic_dump_stats(struct vnic_login *login)
{
	unsigned long *stats, *login_stats = (unsigned long *)(&login->stats);
	int i, j, len = sizeof(struct net_device_stats) / sizeof(unsigned long);
	struct net_device_stats stats_tmp;

	spin_lock_bh(&login->stats_lock);
	/* tx stats are distributed between tx_res entries */
	stats_tmp = login->stats;
	memset(&login->stats, 0, sizeof(struct net_device_stats));
	for (i = 0; i < login->tx_rings_num; ++i) {
		stats = (unsigned long *)(&login->tx_res[i].stats);
		for (j = 0; j < len; ++j)
			login_stats[j] += stats[j];
	}

	/* rx stats are in login->stats */
	login->stats.rx_bytes = stats_tmp.rx_bytes;
	login->stats.rx_packets = stats_tmp.rx_packets;
	login->stats.rx_errors = stats_tmp.rx_errors;
	login->stats.rx_dropped = stats_tmp.rx_dropped;
        spin_unlock_bh(&login->stats_lock);
}

static void vnic_do_get_stats(struct work_struct *work)
{
	struct vnic_login *login =
		container_of(work, struct vnic_login, stats_task.work);

	mutex_lock(&login->moder_lock);
	vnic_dump_stats(login);

	if (login->queue_stopped)
		goto out;

	if (!(test_bit(VNIC_STATE_NETDEV_OPEN, &login->netdev_state)))
		goto resched;

	if (login->port->attr.state == IB_PORT_ACTIVE)
		vnic_auto_moder(login);

resched:
	/* calls vnic_do_get_stats() */
	if (!login->queue_stopped)
		queue_delayed_work(login_wq, &login->stats_task, VNIC_STATS_DELAY);
out:
	mutex_unlock(&login->moder_lock);
}

static void vnic_mcast_reattach(struct work_struct *work)
{
	struct vnic_mcast *mcaste, *mcaste_t;
	struct rb_node *n;
	unsigned long flags;
	union vhub_mgid mgid;
	LIST_HEAD(local_list);
	int i;
	struct vnic_gw_info *lag_member;
	struct vnic_login *login;
	struct net_device *dev;
#ifndef _BP_NO_MC_LIST
	struct dev_mc_list *mclist;
#else
	struct netdev_hw_addr *ha;
#endif

	login = container_of(work, struct vnic_login, mcast_task.work);
	dev = login->dev;

	vnic_dbg_mcast(login->name, "set_multicast_list was notified\n");
	if (login->queue_stopped) {
		dev_put(dev);
		return;
	}

	/* detach all mcast (except default and bcast mcasts) */
	spin_lock_irqsave(&login->mcast_tree.mcast_rb_lock, flags);
	if (!list_empty(&login->mcast_tree.reattach_list)) {
		/* an event is being processed */
		spin_unlock_irqrestore(&login->mcast_tree.mcast_rb_lock, flags);
		goto retry;
	}
		
	for (n = rb_first(&login->mcast_tree.mcast_tree); n; n = rb_next(n)) {
		mcaste = rb_entry(n, struct vnic_mcast, rb_node);
		if (IS_ZERO_MAC(mcaste->mac))
			continue;
		if (IS_BCAST_MAC(mcaste->mac))
			continue;		
		list_add_tail(&mcaste->list, &local_list);
	}

	list_for_each_entry(mcaste, &local_list, list) {
		vnic_mcast_del(&login->mcast_tree, mcaste);
		mcaste->attach_task_cnt = 0;
	}

	spin_unlock_irqrestore(&login->mcast_tree.mcast_rb_lock, flags);

	vnic_dbg_mcast(login->name, "local_list is %s empty n_mac_mcgid %u\n",
		       (list_empty(&local_list) ? "" : "not"),
		       login->n_mac_mcgid);

	list_for_each_entry_safe(mcaste, mcaste_t, &local_list, list) {
		list_del(&mcaste->list);
		vnic_mcast_detach(&login->mcast_tree, mcaste);
		vnic_mcast_dealloc(mcaste);
	}

	/* attach all mcasts in mc_list */
	vhub_mgid_create(login->mgid_prefix, ETH_ZERO_MAC, login->n_mac_mcgid,
			 CREATE_VHUB_ID(login->vid, login->gw_port_id),
			 VHUB_MGID_DATA, 0, &mgid);

	spin_lock_irqsave(&login->mcast_tree.mcast_rb_lock, flags);
	mcaste_t = vnic_mcast_search(&login->mcast_tree, &mgid.ib_gid);
	if (IS_ERR(mcaste_t) || !test_bit(VNIC_STATE_LOGIN_BCAST_ATTACH, &login->fip_vnic->login_state)) {
		vnic_dbg_data(login->name, "default mgid not ready\n");
		spin_unlock_irqrestore(&login->mcast_tree.mcast_rb_lock, flags);
		dev_put(dev);
		return;
	}
	spin_unlock_irqrestore(&login->mcast_tree.mcast_rb_lock, flags);

	/* hold the tx lock so set_multicast_list() won't change mc_list */
	netif_tx_lock_bh(dev);
#ifndef _BP_NO_MC_LIST
	for (mclist = login->dev->mc_list; mclist; mclist = mclist->next) {
		u8* mmac = mclist->dmi_addr;
#else
	netdev_for_each_mc_addr(ha, login->dev) {
		u8* mmac = ha->addr;
#endif
		/* do not add the default MGIDS because they are always used */
		if (IS_ZERO_MAC(mmac))
			continue;
		if (IS_BCAST_MAC(mmac))
			continue;

		/* attach to the legacy GW / LAG gw id MGID */
		if (_vnic_mcast_attach_mgid(login, mmac, mcaste_t, login,
					    login->gw_port_id))
			goto attach_failed;

		if (!login->is_lag)
			continue;

		for (i=0; i<MAX_LAG_MEMBERS; i++) {
			lag_member = &login->lag_gw_neigh[i];
			/* member id is already in use */
			if (lag_member->info & GW_MEMBER_INFO_CREATED)
				/* attach to the legacy GW / LAG gw id MGID */
				if (_vnic_mcast_attach_mgid(login, mmac,
							    mcaste_t,
							    lag_member,
							    lag_member->gw_id))
					goto attach_failed;
		}
	}
	netif_tx_unlock_bh(dev);
	dev_put(dev);
	return;

attach_failed:
	netif_tx_unlock_bh(dev);
	vnic_mcast_del_all(&login->mcast_tree);

retry:
	if (!login->queue_stopped) {
		if (!queue_delayed_work(login_wq, &login->mcast_task, HZ / 100))
			dev_put(dev);
	} else
		dev_put(dev);
}

static int vnic_change_mtu(struct net_device *dev, int new_mtu)
{
	struct vnic_login *login = vnic_netdev_priv(dev);

	if (new_mtu > login->max_mtu) {
		vnic_warn(login->name, "failed: new_mtu %d > %d\n", new_mtu,
			  login->max_mtu);
		return -EINVAL;
	}

	vnic_dbg_data(login->name, "mtu %d -> %d\n", dev->mtu, new_mtu);
	dev->mtu = new_mtu;

	return 0;
}

static void vnic_set_default_moder(struct vnic_login *login)
{

	login->rx_frames = VNIC_RX_COAL_TARGET / login->dev->mtu + 1;
	login->rx_usecs = VNIC_RX_COAL_TIME;
	login->tx_frames = VNIC_TX_COAL_PKTS;
	login->tx_usecs = VNIC_TX_COAL_TIME;
	login->pkt_rate_low = VNIC_RX_RATE_LOW;
	login->rx_usecs_low = VNIC_RX_COAL_TIME_LOW;
	login->pkt_rate_high = VNIC_RX_RATE_HIGH;
	login->rx_usecs_high = VNIC_RX_COAL_TIME_HIGH;
	login->sample_interval = VNIC_SAMPLE_INTERVAL;
	login->adaptive_rx_coal = 1;
	login->last_moder_time = VNIC_AUTO_CONF;
	login->last_moder_jiffies = 0;
	login->last_moder_packets = 0;
	login->last_moder_tx_packets = 0;
	login->last_moder_bytes = 0;

	vnic_dbg_data(login->name, "default coalescing params for mtu:%d to "
		      "rx_frames:%d rx_usecs:%d "
		      "tx_frames:%d tx_usecs:%d\n",
		      login->dev->mtu,
		      login->rx_frames, login->rx_usecs,
		      login->tx_frames, login->tx_usecs);
}

#ifndef _BP_NAPI_POLL
int vnic_napi_alloc(struct vnic_login *login, int rx_res_index)
{

	struct napi_struct *napi = &login->rx_res[rx_res_index].napi;

	netif_napi_add(login->dev, napi, vnic_poll_cq_rx, vnic_napi_weight);

	return 0;
}

void vnic_napi_enable(struct vnic_login *login, int rx_res_index)
{

	struct napi_struct *napi = &login->rx_res[rx_res_index].napi;
	napi_enable(napi);
}

static void vnic_napi_disable(struct vnic_login *login, int rx_res_index)
{
	struct napi_struct *napi = &login->rx_res[rx_res_index].napi;

	if (!napi->poll)
		return;

	napi_disable(napi);
}

static void vnic_napi_dealloc(struct vnic_login *login, int rx_res_index)
{
#ifndef _BP_NAPI_NO_DEL
	struct napi_struct *napi = &login->rx_res[rx_res_index].napi;

	netif_napi_del(napi);
#else
	return;
#endif
}

#else
int vnic_napi_alloc(struct vnic_login *login, int rx_res_index)
{
	struct vnic_rx_res *rx_res = &login->rx_res[rx_res_index];
	char name[IFNAMSIZ];

	snprintf(name, IFNAMSIZ, "%s-N%d", login->name, rx_res_index);
	rx_res->poll_dev =
		alloc_netdev(0, name, ether_setup);
	if (!rx_res->poll_dev)
		return -ENOMEM;

	rx_res->poll_dev = rx_res->poll_dev;
	rx_res->poll_dev->priv = rx_res;
	rx_res->poll_dev->weight = vnic_napi_weight;
	rx_res->poll_dev->poll = vnic_poll_cq_rx;

	return 0;
}

void vnic_napi_enable(struct vnic_login *login, int rx_res_index)
{
	struct vnic_rx_res *rx_res = &login->rx_res[rx_res_index];

	ASSERT(rx_res->poll_dev);
	set_bit(__LINK_STATE_START, &rx_res->poll_dev->state);
}

static void vnic_napi_disable(struct vnic_login *login, int rx_res_index)
{
	struct vnic_rx_res *rx_res = &login->rx_res[rx_res_index];
	struct net_device *poll_dev = rx_res->poll_dev;

	if (!poll_dev)
		return;

	while (test_bit(__LINK_STATE_RX_SCHED, &poll_dev->state))
		msleep(VNIC_NAPI_SCHED_TIMEOUT);
}

static void vnic_napi_dealloc(struct vnic_login *login, int rx_res_index)
{
	struct vnic_rx_res *rx_res = &login->rx_res[rx_res_index];
	struct net_device *poll_dev = rx_res->poll_dev;

	if (!poll_dev)
		return;

	free_netdev(poll_dev);
	rx_res->poll_dev = NULL;
}
#endif

static int _vnic_open(struct net_device *dev)
{
	struct vnic_login *login = vnic_netdev_priv(dev);
	int i;

	/* Todo add locks here */
	if (!(test_bit(VNIC_STATE_LOGIN_CREATE_2, &login->fip_vnic->login_state))) {
		set_bit(VNIC_STATE_NETDEV_OPEN_REQ, &login->netdev_state);
		return 0;
	}

	if (test_and_set_bit(VNIC_STATE_NETDEV_OPEN, &login->netdev_state))
		return 0;

	clear_bit(VNIC_STATE_NETDEV_OPEN_REQ, &login->netdev_state);

	/* ARM RX handlers */
	for (i = 0; i < login->rx_rings_num; ++i) {
		login->rx_res[i].stopped = 0;
		if (ib_req_notify_cq(login->rx_res[i].cq, IB_CQ_NEXT_COMP)) {
			vnic_err(login->name, "ib_req_notify_cq failed\n");
			goto err;
		}
	}

	/* ARM TX handlers */
	for (i = 0; i < login->tx_rings_num; ++i) {
		login->tx_res[i].stopped = 0;
		spin_lock_init(&login->tx_res[i].lock);
		if (!vnic_tx_polling &&
		    ib_req_notify_cq(login->tx_res[i].cq, IB_CQ_NEXT_COMP)) {
			vnic_err(login->name, "ib_req_notify_cq failed\n");
			goto err;
		}
	}

	/* enable napi*/
	for (i = 0; i < login->napi_num; ++i)
		vnic_napi_enable(login, i);

	/* move QP to RTS, post recv skb */
	if (vnic_ib_open(dev))
		goto err_napi;

	/* dummy call */
	if (vnic_ib_up(dev))
		goto err_ib_stop;

	/* configure */
	vnic_set_default_moder(login);
	if (vnic_ib_set_moder(login, login->last_moder_time, login->rx_frames,
			      login->tx_usecs, login->tx_frames))
		vnic_warn(login->name, "vnic_ib_set_moder failed!\n");

	/* start interface TX queue */
	VNIC_TXQ_START_ALL(login);

	/* report and return */
	vnic_info("%s is opened\n", dev->name);

	return 0;

err_ib_stop:
	vnic_ib_stop(dev);
err_napi:
	/* disable napi*/
	for (i = 0; i < login->napi_num; ++i)
		vnic_napi_disable(login, i);
err:
	clear_bit(VNIC_STATE_NETDEV_OPEN, &login->netdev_state);
	return -EINVAL;
}

static int vnic_open(struct net_device *dev)
{
	struct vnic_login *login = vnic_netdev_priv(dev);
	int ret;

	vnic_dbg_func(login->name);

	mutex_lock(&login->state_lock);
	ret = _vnic_open(dev);
	mutex_unlock(&login->state_lock);
	return ret;
}

static int _vnic_stop(struct net_device *dev)
{
	struct vnic_login *login = vnic_netdev_priv(dev);
	int i, _watchdog_timeo = dev->watchdog_timeo;

	/* check if already stopped */
	if (!(test_and_clear_bit(VNIC_STATE_NETDEV_OPEN, &login->netdev_state)))
		return 0;

	/* Set trans_start to jiffies and watchdog_timeo to max
	 * to avoid spurious transmit timeouts in the interval between
	 * tx queue stopped and carrier down.
	 */
	dev->trans_start = jiffies;
	dev->watchdog_timeo = 0x7fffffff;

	VNIC_TXQ_STOP_ALL(login);

	/* disable rx handlers */
	for (i = 0; i < login->rx_rings_num; ++i)
		login->rx_res[i].stopped = 1;

	/* disable tx handlers */
	for (i = 0; i < login->tx_rings_num; ++i)
		login->tx_res[i].stopped = 1;

	/* disable napi managers */
	for (i = 0; i < login->napi_num; ++i)
		vnic_napi_disable(login, i);

	vnic_ib_down(dev);
	vnic_ib_stop(dev);

	/* restore watchdog_timeo */
	dev->watchdog_timeo = _watchdog_timeo;

	vnic_info("%s is stopped\n", dev->name);

	return 0;
}

static int vnic_stop(struct net_device *dev)
{
	struct vnic_login *login = vnic_netdev_priv(dev);
	int ret;

	vnic_dbg_func(login->name);

	mutex_lock(&login->state_lock);
	ret = _vnic_stop(dev);
	mutex_unlock(&login->state_lock);

	return ret;
}

int vnic_restart(struct net_device *dev)
{
	struct vnic_login *login = vnic_netdev_priv(dev);
	int rc = 0;

	if (login->queue_stopped || !test_bit(VNIC_STATE_NETDEV_OPEN, &login->netdev_state))
		return rc;

	set_bit(VNIC_STATE_NETDEV_NO_TX_ENABLE, &login->netdev_state);
	netif_tx_disable(login->dev);

	mutex_lock(&login->state_lock);
	_vnic_stop(login->dev);

	clear_bit(VNIC_STATE_NETDEV_NO_TX_ENABLE, &login->netdev_state);
	set_bit(VNIC_STATE_NETDEV_OPEN_REQ, &login->netdev_state);

	rc = _vnic_open(login->dev);
	mutex_unlock(&login->state_lock);

	return rc;
}

static void vnic_restart_task(struct work_struct *work)
{
	struct vnic_login *login =
		container_of(work, struct vnic_login, restart_task.work);

	vnic_restart(login->dev);
}

struct net_device_stats *vnic_get_stats(struct net_device *dev)
{
	struct vnic_login *login = vnic_netdev_priv(dev);

	if (dev->reg_state != NETREG_REGISTERED)
		return &dev->stats;

	spin_lock_bh(&login->stats_lock);
	if (test_bit(VNIC_STATE_LOGIN_PRECREATE_2, &login->fip_vnic->login_state))
		memcpy(&dev->stats, &login->stats, sizeof(login->stats));
	spin_unlock_bh(&login->stats_lock);

	return &dev->stats;
}

static void vnic_tx_timeout(struct net_device *dev)
{
	struct vnic_login *login = vnic_netdev_priv(dev);

	vnic_warn(login->name, "TX timeout called on port: %d, "
		  "latency: %d msec,  stopped: %d, carrier_ok: %d,"
		  "queue_stopped: %d, watchdog_timeo: %d msec\n",
		  login->port->num,
		  jiffies_to_msecs(jiffies - dev->trans_start),
		  netif_queue_stopped(dev), netif_carrier_ok(dev),
		  login->queue_stopped,
		  jiffies_to_msecs(dev->watchdog_timeo));

	if (netif_carrier_ok(dev)) {
		VNIC_STATS_DO_INC(login->port_stats.tx_timeout);
		if (!login->queue_stopped) {
			vnic_warn(login->name, "TX timeout, queueing rings restart\n");
			queue_delayed_work(login_wq, &login->restart_task, HZ / 100);
		}
	}
}

#ifndef _BP_NETDEV_NO_TMQ
u16 vnic_select_queue(struct net_device *dev, struct sk_buff *skb)
{
	/* Notes:
	 * - In kernel 2.6.32 the skb->mac_header 0x1a is not set when
	 * select_queue() is called
	 * - In OVM Server 3.0, DomU tx skb network and transport
	 * headers are not set
	 */
	skb_reset_mac_header(skb);
	skb_set_network_header(skb, ETH_HLEN);
        skb_set_transport_header(skb,
                                 ETH_HLEN +
                                 (skb->protocol == htons(ETH_P_IPV6) ?
                                  sizeof(struct ipv6hdr) : ip_hdrlen(skb)));

	return vnic_hash(dev, skb) % dev->real_num_tx_queues;
}

#endif

#ifndef _BP_NO_NDO_OPS
static struct net_device_ops vnic_netdev_ops = {
	.ndo_open = vnic_open,
	.ndo_stop = vnic_stop,
	.ndo_start_xmit = vnic_tx,
	.ndo_get_stats = vnic_get_stats,
	.ndo_set_rx_mode = vnic_set_multicast_list,
	.ndo_change_mtu = vnic_change_mtu,
	.ndo_tx_timeout = vnic_tx_timeout,
	.ndo_set_mac_address = vnic_set_mac,
	.ndo_vlan_rx_add_vid = mlx4_vnic_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = mlx4_vnic_vlan_rx_kill_vid,
#ifndef _BP_NETDEV_NO_TMQ
	.ndo_select_queue = vnic_select_queue,
#endif
};
#endif

static void vnic_setup(struct net_device *dev)
{
	ether_setup(dev);

	dev->hard_header_len += VNIC_SKB_GET_ENCAP_OFFSET;
	dev->watchdog_timeo = VNIC_WATCHDOG_TIMEOUT;

#ifndef _BP_NO_NDO_OPS
	if (!vnic_change_mac)
		vnic_netdev_ops.ndo_set_mac_address = NULL;

	dev->netdev_ops = &vnic_netdev_ops;
#else
	dev->open = vnic_open;
	dev->stop = vnic_stop;
	dev->hard_start_xmit = vnic_tx;
	dev->get_stats = mlx4_vnic_stats_func_container;
	dev->set_multicast_list = vnic_set_multicast_list;
	dev->change_mtu = vnic_change_mtu;
	dev->tx_timeout = vnic_tx_timeout;
	dev->set_mac_address = vnic_set_mac;
	dev->vlan_rx_add_vid = mlx4_vnic_vlan_rx_add_vid;
	dev->vlan_rx_kill_vid = mlx4_vnic_vlan_rx_kill_vid;

	if (!vnic_change_mac)
		dev->set_mac_address = NULL;

#ifndef _BP_NETDEV_NO_TMQ
	dev->select_queue = vnic_select_queue;
#endif
#endif // _BP_NO_NDO_OPS
}

static int vnic_get_frag_header(struct skb_frag_struct *frags, void **mac_hdr,
				void **ip_hdr, void **tcpudp_hdr,
				u64 *hdr_flags, void *priv)
{
	struct iphdr *iph;
	*mac_hdr = page_address(frags->page.p) + frags->page_offset;
	*ip_hdr = iph = (struct iphdr *)(*mac_hdr + ETH_HLEN);
	*tcpudp_hdr = (struct tcphdr *)(iph + (iph->ihl << 2));
	*hdr_flags = LRO_IPV4 | LRO_TCP;

	return 0;
}

static int vnic_get_skb_header(struct sk_buff *skb, void **iphdr,
			       void **tcphdr, u64 *hdr_flags, void *priv)
{
	struct iphdr *iph;
	struct tcphdr *tcph;

	if (unlikely(skb->protocol != htons(ETH_P_IP)))
		return -1;

	if (unlikely(skb->ip_summed != CHECKSUM_UNNECESSARY))
		return -1;

	iph = (struct iphdr *)(skb->data + ETH_HLEN);
	if (iph->protocol != IPPROTO_TCP)
		return -1;

	tcph = (struct tcphdr *)(iph + (iph->ihl << 2));

	if (ntohs(iph->tot_len) < (iph->ihl * 4 + tcph->doff * 4))
		return -1;

	*hdr_flags = LRO_IPV4 | LRO_TCP;
	*iphdr = iph;
	*tcphdr = tcph;

	return 0;
}

static int vnic_lro_enable(struct vnic_login *login, int rx_res_index)
{
	struct net_lro_mgr *lro = &login->rx_res[rx_res_index].lro;

	lro->dev = login->dev;
	lro->features = login->napi_num ? LRO_F_NAPI : 0;
	lro->frag_align_pad = NET_IP_ALIGN;
	lro->ip_summed = CHECKSUM_UNNECESSARY;
	lro->ip_summed_aggr = CHECKSUM_UNNECESSARY;
	lro->max_desc = login->lro_num;
	lro->max_aggr = VNIC_MAX_LRO_AGGR;
	lro->lro_arr = login->rx_res[rx_res_index].lro_desc;

	if (lro->max_aggr > MAX_SKB_FRAGS)
		lro->max_aggr = MAX_SKB_FRAGS;

	if (!vnic_rx_linear)
		lro->get_frag_header = vnic_get_frag_header;
	else
		lro->get_skb_header = vnic_get_skb_header;

	return 0;
}

static void vnic_lro_disable(struct vnic_login *login, int rx_res_index)
{
	/* nop */
	return;
}

struct net_device *vnic_alloc_netdev(struct vnic_port *port)
{
	struct vnic_login_info *info;
	struct vnic_login *login;
	struct net_device *dev;
	static int vnic_cnt = 0;
	int i;

	dev = VNIC_TXQ_ALLOC_NETDEV(sizeof *info, "eth%d", vnic_setup, port->tx_rings_num);
	if (!dev) {
		vnic_err(port->name, "VNIC_TXQ_ALLOC_NETDEV failed "
			 "(size %Zu, tx_rings_num %d)\n",
			 sizeof *info, port->tx_rings_num);
		goto err;
	}

	/* this is a *very* large beast... */
	login = vmalloc(sizeof *login);
	if (!login) {
		vnic_err(port->name, "failed to allocate login struct (%Zu)\n",
			 sizeof *login);
		goto free_netdev;
	}

	/* init fields */
	memset(login, 0, sizeof *login);
	info = netdev_priv(dev);
	info->login = login;
	login->dev = dev;
	login->port = port;
	login->max_mtu = VNIC_BUF_SIZE(login->port) - IB_GRH_BYTES -
			 VNIC_ENCAP_LEN - ETH_HLEN - VLAN_HLEN;
	login->cnt = ++vnic_cnt;
	/* name will be overwritten later */
	sprintf(login->name, "%s-%d", "vnic", login->cnt);
	sprintf(login->desc, "%s-P%d",
		login->port->dev->ca->node_desc, port->num);

	login->neigh_wq = create_singlethread_workqueue(login->name);
	if (!login->neigh_wq) {
		vnic_err(NULL, "create_singlethread_workqueue failed for %s\n",
				 login->name);
		goto free_login;
	}

	login->rx_csum = 1;
	login->rx_rings_num = port->rx_rings_num;
	login->tx_rings_num = port->tx_rings_num;
#ifdef _BP_NETDEV_NO_TMQ
	/* if the kernel doesn't support Multiple TX queues,
	 * then use only one TX queue */
	login->tx_rings_num = 1;
#endif
	vnic_dbg_mark();
	spin_lock_init(&login->lock);
	spin_lock_init(&login->stats_lock);
	rwlock_init(&login->mac_rwlock);
	atomic_set(&login->vnic_child_cnt, 0);
	vnic_mcast_root_init(&login->mcast_tree);
	mutex_init(&login->moder_lock);
	mutex_init(&login->state_lock);
	SET_NETDEV_DEV(login->dev, login->port->dev->ca->dma_device);
	INIT_DELAYED_WORK(&login->stats_task, vnic_do_get_stats);
	INIT_DELAYED_WORK(&login->mcast_task, vnic_mcast_reattach);
	INIT_DELAYED_WORK(&login->restart_task, vnic_restart_task);

	vnic_set_ethtool_ops(dev);
	/* init ethtool */
	dev->hw_features = NETIF_F_SG | NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM;
	dev->hw_features |= NETIF_F_RXCSUM | NETIF_F_RXHASH;
	dev->hw_features |= NETIF_F_TSO | NETIF_F_TSO6;
	dev->features |= dev->hw_features;

	/* init NAPI (must be before LRO init) */
	login->napi_num = login->rx_rings_num;
	for (i = 0; i < login->napi_num; ++i) {
		if (vnic_napi_alloc(login, i)) {
			vnic_err(login->name, "NAPI alloc %d failed\n", i);
			goto free_napi;
		}
	}

#if defined(NETIF_F_GRO) && !defined(_BP_NO_GRO)
	login->dev->features |= NETIF_F_GRO;
#elif defined(NETIF_F_LRO)
	login->lro_num = vnic_lro_num;
	login->lro_mng_num = vnic_lro_num ? login->rx_rings_num : 0;
	login->dev->features |= vnic_lro_num ? NETIF_F_LRO : 0;
#endif
	for (i = 0; i < login->lro_mng_num; ++i) {
		if (vnic_lro_enable(login, i)) {
			vnic_err(login->name, "vnic_lro_enable %d failed\n", i);
			goto free_lro;
		}
	}

	return dev;

free_lro:
	for (--i; i >= 0; --i)
		vnic_lro_disable(login, i);

	i = login->napi_num;
free_napi:
	for (--i; i >= 0; --i)
		vnic_napi_dealloc(login, i);
free_login:
	vfree(login);
free_netdev:
	free_netdev(dev);
err:
	return ERR_PTR(-ENODEV);
}

void vnic_free_netdev(struct vnic_login *login)
{
	int i;

	vnic_dbg_func(login->name);

	for (i = 0; i < login->lro_mng_num; ++i)
		vnic_lro_disable(login, i);
	for (i = 0; i < login->napi_num; ++i)
		vnic_napi_dealloc(login, i);
	flush_workqueue(login->neigh_wq);
	destroy_workqueue(login->neigh_wq);
	free_netdev(login->dev);
	vfree(login);
}
