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

void vnic_login_refresh_mcasts(struct vnic_port *port)
{
	struct vnic_login *login;

	vnic_dbg_mark();
	mutex_lock(&port->mlock);
	list_for_each_entry(login, &port->login_list, list)
		vnic_tree_mcast_detach(&login->mcast_tree);
	list_for_each_entry(login, &port->login_list, list)
	{
			if (vnic_sa_query) {
				/* take the tx lock to make sure no delete function is called at the time */
				netif_tx_lock_bh(login->dev);
				vnic_neigh_invalidate(login);
				netif_tx_unlock_bh(login->dev);
			}

			vnic_tree_mcast_attach(&login->mcast_tree);
	}
	mutex_unlock(&port->mlock);
}

int vnic_login_pre_create_1(struct vnic_port *port,
			    struct fip_vnic_data *vnic)
{
	struct vnic_login *login;
	struct net_device *dev;

	/* set login to zero first (for parent_used case) */
	vnic->login = NULL;

	/* if parent_used, skip */
	if (vnic->parent_used) {
		vnic_dbg_mac(vnic->name, "function skipped\n");
		return 0;
	} else {
		vnic_dbg_func(vnic->name);
	}

	/* create netdev per login, vlan configuration is done from outside */
	dev = vnic_alloc_netdev(port);
	if (IS_ERR(dev)) {
		vnic_err(port->name, "vnic_alloc_netdev failed\n");
		goto err;
	}

	login = vnic_netdev_priv(dev);
	login->fip_vnic = vnic;
	vnic->login = login;
	login->vlan_used = vnic->vlan_used;
	login->dev->hard_header_len += (vnic->vlan_used && vnic->hadmined)? VLAN_HLEN: 0;
	vnic_dbg_fip(vnic->name,"creating vnic, hadmin=%d vlan_used=%d hard_header_len += %d\n",
				 vnic->hadmined, vnic->vlan_used, (vnic->vlan_used && vnic->hadmined)? VLAN_HLEN: 0);
	set_bit(VNIC_STATE_LOGIN_PRECREATE_1, &vnic->login_state);

	return 0;

err:
	return -ENODEV;
}

int vnic_login_pre_create_2(struct fip_vnic_data *vnic, int qps_num, int is_lag)
{
	struct vnic_login *login = vnic->login;
	int i, j;

	if (vnic->parent_used) {
		vnic_dbg_mac(vnic->name, "function skipped\n");
		return 0;
	} else {
		ASSERT(login);
		vnic_dbg_func(login->name);
	}

	login->qps_num = qps_num;
	login->qkey = VNIC_DATA_QKEY;
	login->is_lag = is_lag;
	VNIC_TXQ_SET_ACTIVE(login, min(login->tx_rings_num, login->qps_num));

	/* prepare padding for runt packets */
	login->pad_va = kzalloc(VNIC_EOIB_ZLEN_MAX, GFP_KERNEL);
	if (!login->pad_va)
		return -ENOMEM;

	login->pad_dma = ib_dma_map_single(login->port->dev->ca, login->pad_va,
					   VNIC_EOIB_ZLEN_MAX, DMA_TO_DEVICE);
	if (ib_dma_mapping_error(login->port->dev->ca, login->pad_dma))
		goto err;

	/* create TX resources */
	for (i = 0; i < login->tx_rings_num; ++i) {
		if (vnic_create_tx_res(login, i)) {
			vnic_err(login->name, "vnic_create_tx_res failed,"
				 " index %d\n", i);
			goto free_tx_res;
		}
	}

	/* create RX resources */
	for (j = 0; j < login->rx_rings_num; ++j) {
		if (vnic_create_rx_res(login, j)) {
			vnic_err(login->name, "vnic_create_rx_res failed,"
				 " index %d\n", j);
			goto free_rx_res;
		}
	}

	/* create QPs */
	if (vnic_create_qp_range(login)) {
		vnic_err(login->name, "vnic_create_qp_range failed\n");
		goto free_rx_res;
	}

	/* first QP is the base QP */
	login->qp_base_num = login->qp_res[0].qp->qp_num;
	vnic->qp_base_num = login->qp_base_num;

	/* update state */
	set_bit(VNIC_STATE_LOGIN_PRECREATE_2, &vnic->login_state);

	login->queue_stopped = 0;

	/* calls vnic_do_get_stats() */
	queue_delayed_work(login_wq, &login->stats_task, VNIC_STATS_DELAY);

	return 0;

free_rx_res:
	for (--j; j >= 0; --j)
		vnic_destroy_rx_res(login, j);

	i = login->tx_rings_num;
free_tx_res:
	for (--i; i >= 0; --i)
		vnic_destroy_tx_res(login, i);
/*free_pad:*/
	ib_dma_unmap_single(login->port->dev->ca, login->pad_dma,
			    VNIC_EOIB_ZLEN_MAX, DMA_TO_DEVICE);
err:
	kfree(login->pad_va);
	return -ENODEV;
}

int vnic_login_register_netdev(struct fip_vnic_data *vnic,
			       const char *mac,
			       const char *name)
{
	struct vnic_login *login = vnic->login;

	if (vnic->parent_used) {
		vnic_dbg_mac(vnic->name, "function skipped\n");
		vnic_info("%s created (parent %s mac "MAC_6_PRINT_FMT")\n",
			  name, vnic->parent_name,
			  MAC_6_PRINT_ARG(vnic->mac_cache));
		return 0;
	} else {
		ASSERT(login);
		vnic_dbg_func(login->name);
	}

	/* set netdev name and mac */
	if (name)
		strncpy(login->dev->name, name, IFNAMSIZ);
	if (mac) {
		memcpy(login->dev->dev_addr, mac, ETH_ALEN);
		/* save original mac */
		memcpy(login->dev_addr, mac, ETH_ALEN);
	}

	/* set device features according to all_vlan mode */
	login->dev->features |= NETIF_F_HIGHDMA;

	//ronni - fixme. add comment here
        if (!vnic->all_vlan_gw) {
                login->dev->features |= NETIF_F_VLAN_CHALLENGED;
                login->dev->features &= ~NETIF_F_HW_VLAN_FILTER;
        } else
                login->dev->features |= NETIF_F_HW_VLAN_FILTER;

	/* register netdev */
	if (register_netdev(login->dev)) {
		vnic_err(login->name, "register_netdev failed name=%s mac="
			 MAC_6_PRINT_FMT" login->dev=%p\n",
			 name ? name : "net_admin",
			 MAC_6_PRINT_ARG(login->dev->dev_addr), login->dev);
		goto err;
	}

	/* encode the port number in dev_id:
	 * This allows us to associate the net device
	 * with the underlying device's port.
	 */
	login->dev->dev_id = login->port->num - 1;

	if (vnic_create_dentry(login)) {
		vnic_err(login->name, "vnic_create_dentry failed\n");
		goto err;
	}
	
	/* print info only after register_netdev so dev->name is valid */
	sprintf(login->name, "%s", login->dev->name);
	vnic_info("%s created (%s port %d)\n",
		  login->dev->name,
		  login->port->dev->ca->name, login->port->num);

	/* disable tx queues and carrier. They will be started
	 * after create 2 is called the mcast is attached ...
	 */
	netif_tx_disable(login->dev);
	netif_carrier_off(login->dev);

	mutex_lock(&login->port->mlock);
	vnic_dbg_mac(login->name, "added to login_list\n");
	list_add_tail(&login->list, &login->port->login_list);
	mutex_unlock(&login->port->mlock);

	set_bit(VNIC_STATE_LOGIN_CREATE_1, &vnic->login_state);

	return 0;

err:
	return -EINVAL;
}

int vnic_login_complete_ack(struct fip_vnic_data *vnic,
			    struct fip_login_data *login_data,
			    struct fip_shared_vnic_data *shared_vnic)
{
	struct vnic_mcast *mcaste, *mcaste_bcast, *mcast_shared = NULL;
	struct vnic_login *login = vnic->login;
	int rc;
	int first_time_vlan = 0;

	if (vnic->parent_used) {
		vnic_dbg_mac(vnic->name, "function skipped\n");
		return 0;
	} else {
		ASSERT(login);
		vnic_dbg_func(login->name);
	}

	/*
	* TODO, check if you need them all, check overlap with gw_neigh
	* check how pkey is passed from FIP
	*/
	login->pkey = login_data->pkey;
	login->pkey_index = login_data->pkey_index;
	login->n_mac_mcgid = login_data->n_mac_mcgid;
	login->gw_port_id = login_data->port_id;

	/*GW should send the data SL from the login packet*/
	login->sl = login_data->sl;

	login->vnic_id = login_data->vnic_id;

	memcpy(login->mgid_prefix, login_data->mgid_prefix, VNIC_MGID_PREFIX_LEN);
	memcpy(login->vnic_name, login_data->vnic_name, sizeof(login_data->vnic_name));
	memcpy(login->vendor_id, login_data->vendor_id, sizeof(login_data->vendor_id));

	VNIC_STR_STRIP(login->vnic_name);
	VNIC_STR_STRIP(login->vendor_id);	/* set ZLEN (varies per VLAN support) */

	/* set VLAN */
	login->zlen = ETH_ZLEN + (vnic_encap_headroom? VNIC_ENCAP_LEN: 0);
	first_time_vlan = !login->vlan_used; /* always false for hadmin vnics with vlans */
	login->vlan_used = login_data->vp;
	login->all_vlan_gw = login_data->all_vlan_gw;
	if ((VNIC_VLAN_ENABLED(login))) {
		login->vid = cpu_to_be16(login_data->vlan);
		if (first_time_vlan) {
			vnic_dbg_fip(login->dev->name,"Updating hard_header_len %d+%d=%d\n",
						 login->dev->hard_header_len, VLAN_HLEN,
						 login->dev->hard_header_len + VLAN_HLEN);
			login->dev->hard_header_len += VLAN_HLEN;
		}
		login->zlen = ETH_ZLEN + VLAN_HLEN + (vnic_encap_headroom? VNIC_ENCAP_LEN: 0);
	}

	/* create gw_neigh (no RSS when sending to the GW)
	 * user zero mac to describe GW L2 address
	 */
	login->gw_neigh = 
		vnic_neighe_alloc(login, NULL, login_data->lid,
				  login_data->qpn, 0);
	if (IS_ERR(login->gw_neigh)) {
		vnic_err(login->name, "failed to alloc gw neigh\n");
		goto err;
	}

	/* alloc mcast entries here to simplify the error flow */
	mcaste = vnic_mcast_alloc(login->port, NULL, NULL);
	if (IS_ERR(mcaste))
		goto err_free_gw_ah;
	mcaste_bcast = vnic_mcast_alloc(login->port, NULL, NULL);
	if (IS_ERR(mcaste_bcast)) {
		vnic_mcast_dealloc(mcaste);
		goto err_free_gw_ah;
	}
	/* used by shared vnic mcast group */
	if (shared_vnic && shared_vnic->enabled) {
		mcast_shared = vnic_mcast_alloc(login->port, NULL, NULL);
		if (IS_ERR(mcast_shared)) {
			vnic_mcast_dealloc(mcaste);
			vnic_mcast_dealloc(mcaste_bcast);
			goto err_free_gw_ah;
		}
	}

	/* attach to default mgid */
	__vnic_mcaste_fill(login, mcaste, login->gw_port_id, ETH_ZERO_MAC, 0, vnic_mcast_create);
	mcaste->backoff_factor = VNIC_MCAST_BACKOF_FAC;
	mcaste->retry = VNIC_MCAST_ULIMIT_RETRY;
	mcaste->attach_cb = __bcast_attach_cb;
	mcaste->detach_cb = __bcast_detach_cb;
	mcaste->attach_cb_ctx = login;
	mcaste->detach_cb_ctx = login;
	rc = vnic_mcast_add(&login->mcast_tree, mcaste);
	ASSERT(!rc);
	rc = vnic_mcast_attach(&login->mcast_tree, mcaste);
	ASSERT(!rc);

	/* attach to bcast mgid (use default mlid) */
	if (login->n_mac_mcgid || vnic_mgid_data_type) {
		__vnic_mcaste_fill(login, mcaste_bcast, login->gw_port_id, ETH_BCAST_MAC, 0, 0);
		mcaste_bcast->backoff_factor = VNIC_MCAST_BACKOF_FAC;
		mcaste_bcast->retry = VNIC_MCAST_ULIMIT_RETRY;
		/* The port gid is overun by the default gid as part of the mgid over
		 * same mlid hack */
		memcpy(&mcaste_bcast->port_gid, &mcaste->port_gid, GID_LEN);
		rc = vnic_mcast_add(&login->mcast_tree, mcaste_bcast);
		ASSERT(!rc);
		rc = vnic_mcast_attach(&login->mcast_tree, mcaste_bcast);
		ASSERT(!rc);
	} else {
		vnic_mcast_dealloc(mcaste_bcast);
	}

	login->shared_vnic = 0;
	/* attach to bcast mgid (use default mlid) */
	if (shared_vnic && shared_vnic->enabled) {
		u8 rss_hash = shared_vnic->ip[0] ^  shared_vnic->ip[1] ^
			shared_vnic->ip[2] ^ shared_vnic->ip[3];

		login->shared_vnic = 1;
		__vnic_mcaste_fill(login, mcast_shared, login->gw_port_id, shared_vnic->emac, 0, 0);
		mcast_shared->backoff_factor = VNIC_MCAST_BACKOF_FAC;
		mcast_shared->retry = VNIC_MCAST_ULIMIT_RETRY;
		memcpy(&mcast_shared->port_gid, &mcaste->port_gid, GID_LEN);
		mcast_shared->gid.raw[12]= rss_hash;

		vnic_dbg_mcast(login->name, "vnic %s attaching shared vnic 1 "
			       "MGID "VNIC_GID_FMT"\n", login->name,
			       VNIC_GID_RAW_ARG(mcast_shared->gid.raw));
		mcaste = mcast_shared;
		memcpy(mcaste->mac, ETH_BCAST_MAC, ETH_ALEN);
		rc = vnic_mcast_add(&login->mcast_tree, mcaste);
		ASSERT(!rc);
		rc = vnic_mcast_attach(&login->mcast_tree, mcaste);
		ASSERT(!rc);
	}

	/* set state */
	set_bit(VNIC_STATE_LOGIN_CREATE_2, &vnic->login_state);

	/* call vnic_open() if open was called when we were not ready to handle it */
	if (test_bit(VNIC_STATE_NETDEV_OPEN_REQ, &login->netdev_state))
#ifndef _BP_NO_NDO_OPS
		login->dev->netdev_ops->ndo_open(login->dev);
#else
		login->dev->open(login->dev);
#endif

	return 0;

err_free_gw_ah:
	vnic_neighe_dealloc(login->gw_neigh);
err:
	return -EINVAL;
}

/*
 * When destroying login, call to stop login wq tasks. do not call from
 * login_wq context.
*/
void vnic_login_destroy_stop_wq(struct fip_vnic_data *vnic, enum fip_flush flush)
{
	struct vnic_login *login = vnic->login;

	if (vnic->parent_used) {
		vnic_dbg_mac(vnic->name, "function skipped\n");
		return;
	} else {
		ASSERT(login);
		vnic_dbg_func(login->name);
	}

	if (test_bit(VNIC_STATE_LOGIN_PRECREATE_1, &vnic->login_state)) {
		/* cancel vnic_auto_moder() */
		vnic_dbg_mark();
		mutex_lock(&login->moder_lock);
		login->queue_stopped = 1;
		mutex_unlock(&login->moder_lock);
#ifndef _BP_WORK_SYNC
		cancel_delayed_work_sync(&login->stats_task);
		if (cancel_delayed_work_sync(&login->mcast_task))
			dev_put(login->dev);
		cancel_delayed_work_sync(&login->restart_task);
#else
		cancel_delayed_work(&login->stats_task);
		if (cancel_delayed_work(&login->mcast_task))
			dev_put(login->dev);
		cancel_delayed_work(&login->restart_task);
		flush_workqueue(login_wq);
#endif
	}
}

/*
 * When destroy login data struct. Assumes all login wq tasks are stopped.
 * Can be called from any context, might block for a few secs.
*/
void vnic_login_destroy_wq_stopped(struct fip_vnic_data *vnic, enum fip_flush flush)
{
	struct vnic_login *login = vnic->login;
	unsigned long flags;
	int i;

	if (vnic->parent_used) {
		vnic_dbg_mac(vnic->name, "function skipped\n");
		vnic_info("%s destroyed (parent %s mac "MAC_6_PRINT_FMT")\n",
			  vnic->interface_name, vnic->parent_name,
			  MAC_6_PRINT_ARG(vnic->mac_cache));
		/* Note: vNics can be logged out by BXM (bypass sysfs calls)
		 * so we need to cleanup the parent here as well
		 * if we reach this function from sysfs calls,
		 * then vnic_parent_update will have no effect here (ok)
		 */
		vnic_parent_update(vnic->port, vnic->name, vnic->vnic_id,
				   vnic->mac_cache, NULL, vnic->parent_name, 1);
		return;
	} else {
		ASSERT(login);
		vnic_dbg_func(login->name);
	}

	/* the cleanup procedure depends on our state, our vnic type 
	 * (host/network admin), and the cleanup level required. In network admined
	 * vnics there is a single create state and only one cleanup level (full).
	 * for host admined there are two create states (init, regular) and two
	 * cleanup level. The flow depends on the reason for the cleanup. */
	vnic_dbg_data(login->name, "vnic_login_destroy flush=%d\n", flush);

	/* we need to change state to prevent from completion to re-open the TX
	 * queue once we close it. Before calling stop() function, need to make
	 * sure that all on-going hard_start_xmit() calls are done.
	 */

	if (test_bit(VNIC_STATE_LOGIN_CREATE_1, &vnic->login_state)) {
		set_bit(VNIC_STATE_NETDEV_NO_TX_ENABLE, &login->netdev_state);
		netif_tx_disable(login->dev);
		vnic_dbg_mark();
	}

	if (test_and_clear_bit(VNIC_STATE_LOGIN_CREATE_2, &vnic->login_state)) {
		if (test_bit(VNIC_STATE_NETDEV_OPEN, &login->netdev_state)) {
			/* calls vnic_stop() */
#ifndef _BP_NO_NDO_OPS
			login->dev->netdev_ops->ndo_stop(login->dev);
#else
			login->dev->stop(login->dev);
#endif
			set_bit(VNIC_STATE_NETDEV_OPEN_REQ, &login->netdev_state);
			vnic_dbg_mark();
		}
		vnic_mcast_del_all(&login->mcast_tree);
		vnic_member_remove_all(login);
		vnic_neighe_dealloc(login->gw_neigh);
		vnic_dbg_mark();
	}
	if (test_bit(VNIC_STATE_LOGIN_CREATE_1, &vnic->login_state))
		clear_bit(VNIC_STATE_NETDEV_NO_TX_ENABLE, &login->netdev_state);

	if (flush == FIP_FULL_FLUSH &&
	    test_and_clear_bit(VNIC_STATE_LOGIN_CREATE_1, &vnic->login_state)) {
		mutex_lock(&login->port->mlock);
		vnic_dbg_mac(login->name, "delete from login_list\n");
		list_del(&login->list);
		mutex_unlock(&login->port->mlock);

		/* print info if register_netdev was called before so
		 * dev->name is valid
		 */
		vnic_info("%s destroyed (%s port %d)\n", login->dev->name,
			  login->port->dev->ca->name, login->port->num);

		/* use irq save so caller function supports any context */
		write_lock_irqsave(&login->mac_rwlock, flags);
		vnic_child_flush(login, 1);
		write_unlock_irqrestore(&login->mac_rwlock, flags);

		vnic_delete_dentry(login);
		unregister_netdev(login->dev);
		vnic_dbg_mark();
	}

	vnic_dbg_mark();
	/* login_ctx was in pre created state [always true] */
	spin_lock_bh(&login->stats_lock);
	if (test_and_clear_bit(VNIC_STATE_LOGIN_PRECREATE_2, &vnic->login_state)) {
		spin_unlock_bh(&login->stats_lock);
		vnic_dbg_mark();
		/* take port->mlock in case of refresh event is being called vnic_refresh_mcasts */
		mutex_lock(&login->port->mlock);
		/* tx queues are already stopped here */
		vnic_neigh_del_all(login);
		vnic_mcast_del_all(&login->mcast_tree);
		for (i = 0; i < login->qps_num; ++i)
			vnic_destroy_qp(login, i);
		mutex_unlock(&login->port->mlock);

		for (i = 0; i < login->rx_rings_num; ++i)
			vnic_destroy_rx_res(login, i);
		for (i = 0; i < login->tx_rings_num; ++i)
			vnic_destroy_tx_res(login, i);
		ib_dma_unmap_single(login->port->dev->ca, login->pad_dma,
				    VNIC_EOIB_ZLEN_MAX, DMA_TO_DEVICE);
		kfree(login->pad_va);
	} else
		spin_unlock_bh(&login->stats_lock);

	if (flush == FIP_FULL_FLUSH &&
	    test_and_clear_bit(VNIC_STATE_LOGIN_PRECREATE_1, &vnic->login_state)) {
		vnic_free_netdev(login);
	}
}

int vnic_vhube_add(struct fip_vnic_data *vnic, struct vnic_table_entry *vhube)
{
	struct vnic_neigh *neighe;
	struct vnic_login *login = vnic->login;
	int rc;

	if (vnic->parent_used) {
		vnic_dbg_mac(vnic->name, "function skipped\n");
		return 0;
	} else {
		ASSERT(login);
		vnic_dbg_func(login->name);
	}

	vnic_dbg_data(login->name, "adding vhube lid 0x%02x qpn 0x%x, mac "
		      MAC_6_PRINT_FMT"\n", vhube->lid, vhube->qpn,
		      MAC_6_PRINT_ARG(vhube->mac));

	neighe = vnic_neighe_alloc(login, vhube->mac, vhube->lid,
				   vhube->qpn, vhube->rss);
	if (IS_ERR(neighe))
		return (int)PTR_ERR(neighe);

	vnic_dbg_mark();
	/* when adding new neighe, make sure that TX queues are not running. */
	netif_tx_lock_bh(login->dev);
	rc = vnic_neighe_add(login, neighe);
	netif_tx_unlock_bh(login->dev);
	if (rc) {
		vnic_neighe_dealloc(neighe);
		return rc;
	}

	return 0;
}

void vnic_vhube_flush(struct fip_vnic_data *vnic)
{
	struct vnic_login *login = vnic->login;

	if (vnic->parent_used) {
		vnic_dbg_mac(vnic->name, "function skipped\n");
		return;
	} else {
		ASSERT(login);
		vnic_dbg_func(login->name);
	}

	/* when adding new neighe, make sure that TX queues are not running. */
	vnic_dbg_mark();
	netif_tx_lock_bh(login->dev);
	vnic_neigh_del_all(login);
	netif_tx_unlock_bh(login->dev);

	return;
}

void vnic_vhube_del(struct fip_vnic_data *vnic, u8* mac)
{
	struct vnic_neigh *neighe;
	struct vnic_login *login = vnic->login;

	if (vnic->parent_used) {
		vnic_dbg_mac(vnic->name, "function skipped\n");
		return;
	} else {
		ASSERT(login);
		vnic_dbg_func(login->name);
	}

	vnic_dbg_mark();
	/* when adding new neighe, make sure that TX queues are not running. */
	netif_tx_lock_bh(login->dev);
	neighe = vnic_neighe_search(login, mac);
	if (IS_ERR(neighe)) {
		vnic_warn(login->name, "couldn't find "MAC_6_PRINT_FMT"\n",
			  MAC_6_PRINT_ARG(mac));
	} else {
		vnic_neighe_del(login, neighe);
		vnic_neighe_dealloc(neighe);
	}
	netif_tx_unlock_bh(login->dev);
	return;
}

struct fip_login_data login_data;
struct fip_vnic_data vnic;
struct vnic_login *__vnic_login_create(struct vnic_port *port, int index)
{
	struct vnic_login *login;
	int rc, no_bxm_n_rss = 0x4;
	int qps_num = (port->rx_rings_num > 1) ? (1 << no_bxm_n_rss) : 1;

	/* pre create vnic */
	rc = vnic_login_pre_create_1(port, &vnic);
	if (rc) {
		vnic_err(port->name, "vnic_login_pre_create_1 failed"
			 " for %s port %d index %d\n",
			 port->dev->ca->name, port->num, index);
		goto err;
	}

	login = vnic.login;

	rc = vnic_login_pre_create_2(&vnic, qps_num, 0);
	if (rc) {
		vnic_err(port->name, "vnic_login_pre_create_2 failed"
			 " for %s port %d index %d\n",
			 port->dev->ca->name, port->num, index);
		goto create_fail;
	}

	/* create vnic */
	memset(&login_data, 0, sizeof(struct fip_login_data));
	sprintf(login_data.vendor_id, "%s", NOT_AVAILABLE_STRING);
	sprintf(login_data.vnic_name, "%s", NOT_AVAILABLE_STRING);
	memcpy(login_data.mgid_prefix, NO_BXM_MGID_PREFIX, VNIC_MGID_PREFIX_LEN);
	login_data.qpn = 0xa00000;
	login_data.lid = 1;
	login_data.pkey = 0xffff;
	login_data.mtu = 1500;

	/* random_ether_addr(mac); */
	memcpy(login_data.mac, port->gid.raw + 10, ETH_ALEN);
	login_data.mac[0] += index * 0x10;
	/* mcast bit must be zero */
	login_data.mac[0] &= 0xfe;
	vnic_dbg_mark();
	if (vnic_login_register_netdev(&vnic, login_data.mac, NULL)) {
		vnic_err(login->name, "vnic_login_register_netdev failed\n");
		goto create_fail;
	}
	if (vnic_login_complete_ack(&vnic, &login_data, NULL)) {
		vnic_err(login->name, "vnic_login_complete_ack failed\n");
		goto create_fail;
	}

	return login;

create_fail:
	vnic_login_destroy(login->fip_vnic, FIP_FULL_FLUSH);
err:
	return ERR_PTR(-ENODEV);
}

int vnic_port_data_init(struct vnic_port *port)
{
	int i, no_bxm_vnic_per_port = 1;

	vnic_dbg_mark();
	mutex_lock(&port->start_stop_lock);
	for (i = 0; i < no_bxm_vnic_per_port; ++i) {
		__vnic_login_create(port, i);
	}
	mutex_unlock(&port->start_stop_lock);

	return 0;
	/*TODO - JPM: handle vnic_login_create failure */
}

void vnic_port_data_cleanup(struct vnic_port *port)
{
	struct vnic_login *login, *login_t;

	vnic_dbg_mark();
	/* vnic_login_destroy() acquires the port->mlock, cannot hold it here */
	list_for_each_entry_safe(login, login_t,
				 &port->login_list, list) {
		vnic_dbg_data(login->name, "login %s\n", login->name);
		vnic_login_destroy(login->fip_vnic, FIP_FULL_FLUSH);
	}
}

/* ALI TODO: check if need to replace login ptr with vnic */
void debug_dump_members(struct vnic_login *login, struct vnic_gw_info *member)
{
	int i;

	vnic_warn(login->name, "Error members_debug_dump "
		  "member id=%d gw id = %d active_count=%d\n",
		  member->member_id, member->gw_id,
		  login->lag_member_active_count);

	/* go over map and count how many entries are mapped to each member*/
	for (i=0; i<MAX_LAG_MEMBERS; i++) {
		vnic_warn(login->name, "%d member %d used %x gw_id %d\n",
			  i, login->lag_gw_neigh[i].member_id,
			  login->lag_gw_neigh[i].info,
			  login->lag_gw_neigh[i].gw_id);
	}
}

static void vnic_build_map_histogram(struct vnic_login *login, int member_id, int *hist)
{
	int i;

	memset(hist, 0, sizeof(int) * MAX_LAG_MEMBERS);

	/* go over map and count how many entries are mapped to each member*/
	for (i=0; i<LAG_MAP_TABLE_SIZE; i++) {
		ASSERT(login->lag_gw_map[i] >= 0 && login->lag_gw_map[i] < MAX_LAG_MEMBERS);
		hist[login->lag_gw_map[i]]++;
	}
}

static void _vnic_remove_member_from_map(struct vnic_login *login, int member_id)
{
	int user_count[MAX_LAG_MEMBERS] = {0};
	int i, j;
	int continue_flag;
	int thresh;

	login->lag_member_active_count--;
	if (login->lag_member_active_count > 0) {
		/* go over map and count how many entries are mapped to each member*/
		vnic_build_map_histogram(login, member_id, user_count);
	
		thresh = 2; //it might be possible to find a better lower boundary

		for (i=0; i<LAG_MAP_TABLE_SIZE; i++) {
			/* entries that use the removed member must be remapped */
			if (login->lag_gw_map[i] != member_id)
				continue;

			continue_flag = 1;
			while (continue_flag) {
				for (j = 0; j < MAX_LAG_MEMBERS; j++) {
					if (j == member_id)
						continue;

					/* Only use members that are connected, and are short of members */
					if (login->lag_gw_neigh[j].info & GW_MEMBER_INFO_MAPPED &&
					    user_count[j] < thresh) {
						login->lag_gw_map[i] = j;
						user_count[j]++;
						continue_flag = 0;
						break;
					}
				}
				if (j == MAX_LAG_MEMBERS)
					thresh++;
			}
		}
	}
}

static void _vnic_add_member_to_map(struct vnic_login *login, int member_id)
{
	int i;
	int expected;
	int user_count[MAX_LAG_MEMBERS] = {0};
	int continue_flag;
	int thresh;

	/* this is the first active port use it for all maps */
	if (!login->lag_member_active_count) {
		for (i=0; i<LAG_MAP_TABLE_SIZE; i++)
			login->lag_gw_map[i] = member_id;
		login->lag_member_active_count++;
	} else {
		/* go over map and count how many entries are mapped to each member
		 * we will use count to reasign ports from the most heavily used members */
		vnic_build_map_histogram(login, member_id, user_count);

		/* when adding new member, make sure that TX queues are not running. */
		login->lag_member_active_count++;
		expected = LAG_MAP_TABLE_SIZE / login->lag_member_active_count;
		thresh = LAG_MAP_TABLE_SIZE % login->lag_member_active_count;
		continue_flag = 1;
		while (continue_flag) {
			for (i = 0; i < LAG_MAP_TABLE_SIZE; i++) {
				if (user_count[login->lag_gw_map[i]] > expected + thresh) {
					user_count[login->lag_gw_map[i]]--;
					login->lag_gw_map[i] = member_id;
					user_count[login->lag_gw_map[i]]++;
					if (user_count[member_id] >= expected) {
						continue_flag = 0;
						break;
					}
				}
 			}
			thresh--;
		}
	}
}

void __bcast_member_attach_cb(struct vnic_mcast *mcaste, void *gw_ptr)
{
	struct vnic_gw_info *member = gw_ptr;

	/* When SA is local, mcast join works even when port is down */
	if (member->neigh.login->port->attr.state != IB_PORT_ACTIVE)
		return;

	vnic_dbg_lag(member->neigh.login->name, "__bcast_member_attach_cb for member id %d and "
		     "gw_id=%d\n", member->member_id, member->gw_id);

	netif_tx_lock_bh(member->neigh.login->dev);
	member->info |= GW_MEMBER_INFO_MCAST;

	if (member->info & GW_MEMBER_INFO_EPORT_UP &&
	    !(member->info & GW_MEMBER_INFO_MAPPED)) {
		_vnic_add_member_to_map(member->neigh.login, member->member_id);
		member->info |= GW_MEMBER_INFO_MAPPED;
	}
	netif_tx_unlock_bh(member->neigh.login->dev);
}

void __bcast_member_detach_cb(struct vnic_mcast *mcaste, void *gw_ptr)
{
	struct vnic_gw_info *member = gw_ptr;

	vnic_dbg_lag(member->neigh.login->name, "__bcast_member_detach_cb for member id %d and "
		     "gw_id=%d\n", member->member_id, member->gw_id);

	netif_tx_lock_bh(member->neigh.login->dev);
	if (member->info & GW_MEMBER_INFO_MAPPED)
		_vnic_remove_member_from_map(member->neigh.login, member->member_id);

	member->info &= ~(GW_MEMBER_INFO_MAPPED | GW_MEMBER_INFO_MCAST);
	netif_tx_unlock_bh(member->neigh.login->dev);
}

/*
 * create MGIDs and join the default MCAST addresses. The mcaste are added to the
 * list contained within member struct. If more MGIDs are used by the vnic when
 * a member is added we will join those too using the members GW_ID.
*/
static int _vnic_add_member_mgid(struct vnic_login *login, struct vnic_gw_info *member)
{
	struct vnic_mcast *mcaste, *mcaste_bcast;
	int rc;
#ifndef _BP_NO_MC_LIST
	struct dev_mc_list *mclist;
#else
	struct netdev_hw_addr *ha;
#endif

	mcaste = vnic_mcast_alloc(login->port, NULL, NULL);
	if (IS_ERR(mcaste))
		return (-ENOMEM);

	/* attach to default mgid */
	__vnic_mcaste_fill(login, mcaste, member->gw_id, ETH_ZERO_MAC, 0, vnic_mcast_create);
	mcaste->attach_cb = __bcast_member_attach_cb;
	mcaste->detach_cb = __bcast_member_detach_cb;
	mcaste->attach_cb_ctx = member;
	mcaste->detach_cb_ctx = member;
	mcaste->priv_data = member;
	rc = vnic_mcast_add(&login->mcast_tree, mcaste);
	if (rc) {
		debug_dump_members(login, member);
		ASSERT(!rc);
	}

	rc = vnic_mcast_attach(&login->mcast_tree, mcaste);
	if (rc) {
		debug_dump_members(login, member);
		ASSERT(!rc);
	}

	if (login->n_mac_mcgid) {
		mcaste_bcast = vnic_mcast_alloc(login->port, NULL, NULL);
		if (IS_ERR(mcaste_bcast))
			goto  free_mcasts;

		__vnic_mcaste_fill(login, mcaste_bcast, member->gw_id, ETH_BCAST_MAC, 0, 0);
		/* The port gid is overun by the default gid as part of the mgid over
		 * same mlid hack */
		memcpy(&mcaste_bcast->port_gid, &mcaste->port_gid, GID_LEN);
		mcaste_bcast->priv_data = member;
		rc = vnic_mcast_add(&login->mcast_tree, mcaste_bcast);
		ASSERT(!rc);
		rc = vnic_mcast_attach(&login->mcast_tree, mcaste_bcast);
		ASSERT(!rc);
	}


	/* hold the tx lock so set_multicast_list() won't change mc_list */
	netif_tx_lock_bh(login->dev);
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

		vnic_dbg_lag(login->name, "_vnic_add_member_mgid for "
			  MAC_6_PRINT_FMT" and member gw_id=%d\n",
			  MAC_6_PRINT_ARG(mcaste->mac), member->gw_id);

		if (_vnic_mcast_attach_mgid(login, mmac, mcaste, member,
					    member->gw_id))
			goto attach_failed;
	}
	netif_tx_unlock_bh(login->dev);

	return 0;

attach_failed:
	netif_tx_unlock_bh(login->dev);
free_mcasts:
	vnic_mcast_del_user(&login->mcast_tree, member);
	return -ENOMEM;
}

int vnic_member_add(struct vnic_login *login, int member_id, struct lag_member *member)
{
	struct vnic_gw_info *member_e;
	int ret;

	if (member_id >= MAX_LAG_MEMBERS || member_id < 0)
		return -1;

	vnic_dbg_lag(login->name,"vnic_member_add id:%d gw_id:%d lid:%x qpn:%x sl:%d\n",
			  member_id, member_e->gw_id, member->lid, member->qpn, member->sl);
	/* member id is already in use */
	if (login->lag_gw_neigh[member_id].info & GW_MEMBER_INFO_CREATED)
		return -1;

	member_e = &login->lag_gw_neigh[member_id];

	/* create new entry */
	member_e->member_id = member_id;
	member_e->neigh.lid = member->lid;
	member_e->neigh.qpn = member->qpn;
	member_e->gw_id = member->gw_port_id;
	member_e->neigh.login = login;
	INIT_DELAYED_WORK(&member_e->neigh.destroy_task, vnic_neighe_dealloc_task);
	skb_queue_head_init(&member_e->neigh.pkt_queue);
	init_completion(&member_e->neigh.query_comp);
	complete(&member_e->neigh.query_comp); /* mark as complete since no query is running */
	member_e->neigh.valid = 0;
	member_e->neigh.pquery = ERR_PTR(-ENODATA);
	member_e->neigh.query_id = -1;
	member_e->neigh.ah = ERR_PTR(-ENODATA); /* ah query will be done via datapath */
	if (!vnic_sa_query) {
		member_e->neigh.ah = vnic_ah_alloc(login, member->lid);
		if (IS_ERR(member_e->neigh.ah))
			return -ENOMEM;
	}
	/* need to add multicast code */
	ret = _vnic_add_member_mgid(login, member_e);
	if (ret)
		goto free_ah;

	netif_tx_lock_bh(login->dev);
	member_e->info = GW_MEMBER_INFO_CREATED;
	if (member->eport_state)
		member_e->info |= GW_MEMBER_INFO_EPORT_UP;
	login->lag_member_count++;
	netif_tx_unlock_bh(login->dev);

	return 0;
free_ah:
	if (!IS_ERR(member_e->neigh.ah))
		ib_destroy_ah(member_e->neigh.ah);
	return ret;
}

void vnic_member_remove_all(struct vnic_login *login)
{
	int i;

	if (!login->is_lag)
		return;

	for (i=0; i<MAX_LAG_MEMBERS; i++)
		vnic_member_remove(login, i);
}

int vnic_member_remove(struct vnic_login *login, int member_id)
{
	struct vnic_gw_info *member_e;

	vnic_dbg_lag(login->name, "vnic_member_remove for id %d\n", member_id);

	if (member_id >= MAX_LAG_MEMBERS || member_id < 0)
		return -1;

	member_e = &login->lag_gw_neigh[member_id];

	vnic_dbg_lag(login->name,"vnic_member_remove id:%d gw_id:%d lid:%x qpn:%x sl:%d\n",
			  member_id, member_e->gw_id, member_e->neigh.lid, member_e->neigh.qpn, member_e->neigh.sl);

	/* member id is not in use */
	if (!(member_e->info & GW_MEMBER_INFO_CREATED))
		return -1;

	if (member_e->neigh.query_id >=0 && member_e->neigh.pquery && !IS_ERR(member_e->neigh.pquery))
		ib_sa_cancel_query(member_e->neigh.query_id, member_e->neigh.pquery);

	netif_tx_lock_bh(login->dev);
	if (member_e->info & GW_MEMBER_INFO_MAPPED)
		_vnic_remove_member_from_map(login, member_e->member_id);
	member_e->info &= ~(GW_MEMBER_INFO_MAPPED);
	member_e->neigh.valid = 0;
	netif_tx_unlock_bh(login->dev);

	/* wait for completion after the entry was removed from login data path */
	wait_for_completion(&member_e->neigh.query_comp);

	/* modification of map will be done through mcast CB if needed */
	vnic_mcast_del_user(&login->mcast_tree, member_e);

	if(member_e->neigh.ah && !IS_ERR(member_e->neigh.ah))
		ib_destroy_ah(member_e->neigh.ah);
	member_e->neigh.ah = ERR_PTR(-ENODATA);
	member_e->info = 0;
	login->lag_member_count--;

	return 0;
}

void vnic_member_prop(struct vnic_login *login, struct lag_properties *prop)
{
	if (login->lag_prop.hash_mask != prop->hash_mask) {
		netif_tx_lock_bh(login->dev);
		memcpy(&login->lag_prop, prop,
		       sizeof(login->lag_prop));
		netif_tx_unlock_bh(login->dev);
	}
}

/*
 * modify a specific LAG eport member parameters. The parameters might not be
 * "interesting" and might not effect data traffic. They might require creating
 * a new ah, or might even result in a modification of the transmit hash mapping
 * function.
*/
int vnic_member_modify(struct vnic_login *login, int member_id, struct lag_member *member)
{
	struct vnic_gw_info *member_e;

	if (member_id >= MAX_LAG_MEMBERS || member_id < 0)
		return -1;

	member_e = &login->lag_gw_neigh[member_id];

	vnic_dbg_lag(login->name,"vnic_member_modify id:%d gw_id:%d lid:%x qpn:%x sl:%d\n",
		   member_id, member_e->gw_id, member_e->neigh.lid, member_e->neigh.qpn, member_e->neigh.sl);

	/* member id is not in use */
	if (! member_e->info & GW_MEMBER_INFO_CREATED)
		return -1;

	/* change in LID requires new ah */
	/* TODO Test this */
	if (member_e->neigh.lid != member->lid) {
		/* take tx lock to make sure ah is not being used */
		if (vnic_sa_query) {
			/* Cancel SA query in case */
			if (member_e->neigh.query_id >=0 && member_e->neigh.pquery && !IS_ERR(member_e->neigh.pquery))
				ib_sa_cancel_query(member_e->neigh.query_id, member_e->neigh.pquery);
			netif_tx_lock_bh(login->dev);
			member_e->neigh.lid = member->lid;
			member_e->neigh.valid = 0;
			if ((member_e->neigh.ah && !IS_ERR(member_e->neigh.ah)))
			{
				/* lid is not the same : destroy AH */
				ib_destroy_ah(member_e->neigh.ah);
				member_e->neigh.ah = ERR_PTR(-ENODATA);
			}
			netif_tx_unlock_bh(login->dev);
		} else {
			struct ib_ah *ah, *ah1;
			ah = member_e->neigh.ah;
			ah1 = vnic_ah_alloc(login, member->lid);
			if (IS_ERR(ah1))
				  return -ENOMEM;
			netif_tx_lock_bh(login->dev);
			member_e->neigh.lid = member->lid;
			member_e->neigh.ah = ah1;
			netif_tx_unlock_bh(login->dev);
			ib_destroy_ah(ah);
		}
	}

	if (member_e->neigh.qpn != member->qpn)
		member_e->neigh.qpn = member->qpn;

	netif_tx_lock_bh(login->dev);
	/* link changed from up to down */
	if (member_e->info & GW_MEMBER_INFO_MAPPED && !member->eport_state) {
		_vnic_remove_member_from_map(login, member_id);
		member_e->info &= ~(GW_MEMBER_INFO_MAPPED | GW_MEMBER_INFO_EPORT_UP);
	} 

	/* link changed from down to up and mcast are connected */
	if (!(member_e->info & GW_MEMBER_INFO_MAPPED) &&
	    member->eport_state) {
		if (member_e->info & GW_MEMBER_INFO_MCAST) {
			_vnic_add_member_to_map(login, member_id);
			member_e->info |= (GW_MEMBER_INFO_MAPPED | GW_MEMBER_INFO_EPORT_UP);
		} else
			member_e->info |= GW_MEMBER_INFO_EPORT_UP;
	}
	netif_tx_unlock_bh(login->dev);

	return 0;
}

