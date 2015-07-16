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

/* globals */
struct workqueue_struct *port_wq;
struct workqueue_struct *login_wq;

/* functions */
static void vnic_port_event(struct ib_event_handler *handler,
			    struct ib_event *record)
{
	struct vnic_port *port =
		container_of(handler, struct vnic_port, event_handler);

	if (record->element.port_num != port->num)
		return;

	vnic_info("Received event 0x%x (device %s port %d)\n",
		  record->event, record->device->name,
		  record->element.port_num);

	switch (record->event) {
	case IB_EVENT_SM_CHANGE:
	case IB_EVENT_CLIENT_REREGISTER:
		/* calls vnic_port_event_task_light() */
		queue_delayed_work(fip_wq, &port->event_task_light, msecs_to_jiffies(VNIC_SM_HEADSTART));
		break;
	case IB_EVENT_PORT_ERR:
	case IB_EVENT_PORT_ACTIVE:
		/* calls vnic_port_event_task() */
		queue_delayed_work(fip_wq, &port->event_task, msecs_to_jiffies(VNIC_SM_HEADSTART));
		break;
	case IB_EVENT_PKEY_CHANGE:
	case IB_EVENT_LID_CHANGE:
		/* calls port_fip_discover_restart() */
		if (no_bxm)
			queue_delayed_work(fip_wq, &port->event_task, 0);
		else
			queue_delayed_work(port_wq, &port->discover_restart_task, msecs_to_jiffies(VNIC_SM_HEADSTART));
		break;
	case IB_EVENT_SRQ_ERR:
	case IB_EVENT_SRQ_LIMIT_REACHED:
	case IB_EVENT_QP_LAST_WQE_REACHED:
	case IB_EVENT_DEVICE_FATAL:
	default:
		vnic_warn(port->name, "event 0x%x unhandled\n", record->event);
		break;
	}

}

static inline u8 vnic_mcast_rate_enum(struct vnic_port *port, int rate)
{
	u8 ret;

	switch (rate) {
	case 10:
		ret = IB_RATE_10_GBPS;
		break;
	case 20:
		ret = IB_RATE_20_GBPS;
		break;
	case 40:
		ret = IB_RATE_40_GBPS;
		break;
	case 80:
		ret = IB_RATE_80_GBPS;
		break;
	default:
		ret = IB_RATE_10_GBPS;
	}
	return ret;
}

int vnic_port_query(struct vnic_port *port)
{
	if (ib_query_gid(port->dev->ca, port->num, 0, &port->gid)) {
		vnic_err(port->name, "ib_query_gid failed\n");
		return -EINVAL;
	}

	if (ib_query_port(port->dev->ca, port->num, &port->attr)) {
		vnic_err(port->name, "ib_query_port failed\n");
		return -EINVAL;
	}

	port->max_mtu_enum = ib_mtu_enum_to_int(port->attr.max_mtu);
	port->rate = ((int)port->attr.active_speed *
		      ib_width_enum_to_int(port->attr.active_width) * 25) / 10;
	port->rate_enum = vnic_mcast_rate_enum(port, port->rate);

	if (ib_query_pkey(port->dev->ca, port->num, port->pkey_index,
			  &port->pkey)) {
		vnic_err(port->name, "ib_query_pkey failed for index %d\n",
			 port->pkey_index);
		return -EINVAL;
	}
	port->pkey |= 0x8000;

	return 0;
}

void vnic_port_event_task(struct work_struct *work)
{
	struct vnic_port *port =
		container_of(work, struct vnic_port, event_task.work);
	struct fip_discover *discover;

	/* refresh port attr, TODO: check what else need to be refreshed */
	vnic_dbg_mark();
	mutex_lock(&port->mlock);
	if (vnic_port_query(port))
		vnic_warn(port->name, "vnic_port_query failed\n");
	mutex_unlock(&port->mlock);

	/* refresh login mcasts */
	vnic_login_refresh_mcasts(port);

	list_for_each_entry(discover, &port->fip.discover_list, discover_list) {
		/* refresh FIP mcasts */
		if ((!no_bxm) && (discover->state != FIP_DISCOVER_OFF))
			fip_refresh_mcasts(discover);
	}
}

void vnic_port_event_task_light(struct work_struct *work)
{
	struct vnic_port *port =
		container_of(work, struct vnic_port, event_task_light.work);
	unsigned long flags,mc_flags;
	struct fip_discover *discover;
	struct rb_node *node;
	struct vnic_port_mcast *mcaste;
	struct mcast_root *mcast_tree = &port->mcast_tree;
	struct vnic_login *login;
	vnic_dbg_mark();
	mutex_lock(&port->mlock);

	if (vnic_port_query(port))
		vnic_warn(port->name, "vnic_port_query failed\n");

	spin_lock_irqsave(&mcast_tree->mcast_rb_lock, flags);
	for (node = rb_first(&mcast_tree->mcast_tree); node; node = rb_next(node)){
			mcaste = rb_entry(node, struct vnic_port_mcast , rb_node);
			clear_bit(MCAST_JOINED, &mcaste->state);
			set_bit(MCAST_JOIN_RUNNING, &mcaste->state);
			vnic_dbg_mcast(mcaste->port->name,"Rejoin GID="VNIC_GID_FMT"\n",VNIC_GID_ARG(mcaste->gid));
			spin_lock_irqsave(&mcaste->lock, mc_flags);
			queue_delayed_work(mcast_wq, &mcaste->join_task, 0);
			spin_unlock_irqrestore(&mcaste->lock, mc_flags);
	}

	spin_unlock_irqrestore(&mcast_tree->mcast_rb_lock, flags);

	vnic_dbg_mark();
	if (vnic_sa_query)
		list_for_each_entry(login, &port->login_list, list)
		{
				/* take the tx lock to make sure no delete function is called at the time */
				netif_tx_lock_bh(login->dev);
				vnic_neigh_invalidate(login);
				netif_tx_unlock_bh(login->dev);
		}

	mutex_unlock(&port->mlock);

	list_for_each_entry(discover, &port->fip.discover_list, discover_list) {
		if ((!no_bxm) && (discover->state != FIP_DISCOVER_OFF))
			fip_refresh_mcasts(discover);
	}
}

struct vnic_port *vnic_port_alloc(struct vnic_ib_dev *vnic_dev, u8 num)
{
	struct vnic_port *port;
	int def_rings_num;
	int max_num_cpus;

	port = kzalloc(sizeof *port, GFP_KERNEL);
	if (!port)
		return ERR_PTR(-ENOMEM);

	/* pre-init fields */
	port->num = num;
	port->dev = vnic_dev;

	max_num_cpus = min((int)num_online_cpus(), VNIC_MAX_NUM_CPUS);
	def_rings_num = min(vnic_dev->ca->num_comp_vectors, max_num_cpus);
	port->rx_rings_num = vnic_rx_rings_num ? vnic_rx_rings_num : def_rings_num;
	port->tx_rings_num = vnic_tx_rings_num ? vnic_tx_rings_num : def_rings_num;

	sprintf(port->name, "%s:%d", port->dev->ca->name, port->num);
	INIT_LIST_HEAD(&port->login_list);
	INIT_LIST_HEAD(&port->fip.discover_list);
	INIT_DELAYED_WORK(&port->event_task, vnic_port_event_task);
	INIT_DELAYED_WORK(&port->event_task_light, vnic_port_event_task_light);
	INIT_DELAYED_WORK(&port->discover_restart_task, port_fip_discover_restart);
	INIT_IB_EVENT_HANDLER(&port->event_handler, vnic_dev->ca,
			      vnic_port_event);
	mutex_init(&port->mlock);
	mutex_init(&port->start_stop_lock);
	vnic_mcast_root_init(&port->mcast_tree);
	atomic_set(&port->vnic_child_ids, 0);

	port->pkey_index = 0;	/* used by fip qps, TBD */

	if (ib_register_event_handler(&port->event_handler)) {
		vnic_err(port->name, "ib_register_event_handler failed\n");
		goto err;
	}

	vnic_dbg_mark();
	mutex_lock(&port->mlock);
	if (vnic_port_query(port)) {
		vnic_err(port->name, "vnic_port_query failed\n");
		mutex_unlock(&port->mlock);
		if (ib_unregister_event_handler(&port->event_handler))
			vnic_err(port->name, "ib_unregister_event_handler failed!\n");
		goto err;
	}
	mutex_unlock(&port->mlock);

	return port;
err:
	kfree(port);
	return ERR_PTR(-EINVAL);
}

int vnic_port_init(struct vnic_port *port)
{
	return vnic_port_ib_init(port);
}

void vnic_port_cleanup(struct vnic_port *port)
{
	/* should be empty list */
	vnic_port_ib_cleanup(port);
	return;
}

static void vnic_ib_dev_add_one(struct ib_device *device);
static void vnic_ib_dev_remove_one(struct ib_device *device);
static struct ib_client vnic_init_client = {
	.name = DRV_NAME,
	.add = vnic_ib_dev_add_one,
	.remove = vnic_ib_dev_remove_one,
};

static void vnic_ib_dev_add_one(struct ib_device *device)
{
	struct vnic_port *ib_port;
	struct vnic_ib_dev *ib_dev;
	int s, e, p, rc;

	vnic_dbg(NULL, "ib_dev %s\n", device->name);

	if (memcmp(device->name, "mlx4", 4))
		return;

	if (rdma_node_get_transport(device->node_type) != RDMA_TRANSPORT_IB)
		return;

	s = 1;
	e = device->phys_port_cnt;

	/* alloc ib device */
	ib_dev = kzalloc(sizeof *ib_dev, GFP_KERNEL);
	if (!ib_dev)
		return;

	/* init ib dev */
	mutex_init(&ib_dev->mlock);
	ib_dev->ca = device;
	mutex_lock(&ib_dev->mlock);
	/* TODO: remove mdev once all mlx4 caps are standard */
	ib_dev->mdev = to_mdev(device);
	ASSERT(ib_dev->ca);
	sprintf(ib_dev->name, "%s", device->name);
	if (ib_query_device(device, &ib_dev->attr)) {
		vnic_err(ib_dev->name, "ib_query_device failed on %s\n",
			 device->name);
		goto abort;
	}

	VNIC_FW_STR(ib_dev->attr.fw_ver, ib_dev->fw_ver_str);
	INIT_LIST_HEAD(&ib_dev->port_list);
	vnic_dbg_mark();
	for (p = s; p <= e; ++p) {
		/* skip non IB link layers */
                if (rdma_port_get_link_layer(device, p) != IB_LINK_LAYER_INFINIBAND)
                        continue;

		/* alloc IB port */
		ib_port = vnic_port_alloc(ib_dev, p);
		if (IS_ERR(ib_port)) {
			vnic_err(ib_dev->name,
				 "vnic_port_alloc failed %d from %d\n", p, e);
			continue;
		}
		/* init IB port */
		rc = vnic_port_init(ib_port);
		if (rc) {
			vnic_err(ib_port->name,
				 "vnic_port_init failed, rc %d\n", rc);
			if (ib_unregister_event_handler(&ib_port->event_handler))
				vnic_err(ib_port->name,
					 "ib_unregister_event_handler failed!\n");
			kfree(ib_port);
			continue;
		}
		if (no_bxm) {
			rc = vnic_port_data_init(ib_port);
			if (rc)
				 vnic_err(ib_port->name,
					  "vnic_port_data_init failed, rc %d\n", rc);
		} else {
			rc = vnic_port_fip_init(ib_port);
			if (rc)
				vnic_err(ib_port->name,
					 "vnic_port_fip_init failed, rc %d\n", rc);
			else {
				rc = port_fs_init(ib_port);
				if (rc)
					vnic_warn(ib_port->name, "port_fs_init sysfs:"
						  "entry creation failed, %d\n", rc);
			}
		}
		if (rc) {
			if (ib_unregister_event_handler(&ib_port->event_handler))
				vnic_err(ib_port->name,
					 "ib_unregister_event_handler failed!\n");
			vnic_port_cleanup(ib_port);
			kfree(ib_port);
			continue;

		}
		vnic_dbg_mark();
		mutex_lock(&ib_port->start_stop_lock);
		list_add_tail(&ib_port->list, &ib_dev->port_list);
		mutex_unlock(&ib_port->start_stop_lock);
	}

	/* set device ctx */
	ib_set_client_data(device, &vnic_init_client, ib_dev);
	mutex_unlock(&ib_dev->mlock);
	return;

abort:
	mutex_unlock(&ib_dev->mlock);
	kfree(ib_dev);
}

static void vnic_ib_dev_remove_one(struct ib_device *device)
{
	struct vnic_port *port, *port_t;
	struct vnic_ib_dev *ib_dev =
		ib_get_client_data(device, &vnic_init_client);

	vnic_dbg(NULL, "ib_dev %s\n", device->name);

	if (!ib_dev)
		return;

	vnic_dbg_mark();
	mutex_lock(&ib_dev->mlock);
	list_for_each_entry_safe(port, port_t, &ib_dev->port_list, list) {
		vnic_dbg(port->name, "port %d\n", port->num);
		if (ib_unregister_event_handler(&port->event_handler))
			vnic_err(port->name, "ib_unregister_event_handler failed!\n");
		/* make sure we don't have any more pending events */
#ifndef _BP_WORK_SYNC
		cancel_delayed_work_sync(&port->event_task_light);
		cancel_delayed_work_sync(&port->event_task);
		cancel_delayed_work_sync(&port->discover_restart_task);
#else
		cancel_delayed_work(&port->event_task_light);
		cancel_delayed_work(&port->event_task);
		cancel_delayed_work(&port->discover_restart_task);
		flush_workqueue(port_wq);
		flush_workqueue(fip_wq);
#endif
		/* remove sysfs entries related to FIP
		 *  we want to do this outside the lock
		 */
		port_fs_exit(port);

		/* cleanup any pending vnics */
		vnic_dbg_mark();
		mutex_lock(&port->start_stop_lock);
		list_del(&port->list);
		if (no_bxm)
			vnic_port_data_cleanup(port);
		else {
			vnic_port_fip_cleanup(port, 0);
		}
		mutex_unlock(&port->start_stop_lock);
		vnic_port_cleanup(port);
		kfree(port);
	}
	mutex_unlock(&ib_dev->mlock);

	kfree(ib_dev);
}

int vnic_ports_init(void)
{
	int rc;

	/* create global wq */
	port_wq = create_singlethread_workqueue("port_wq");
	if (!port_wq) {
		vnic_err(NULL, "create_singlethread_workqueue failed for %s\n",
			 "port_wq");
		return -EINVAL;
	}

	login_wq = create_singlethread_workqueue("login_wq");
	if (!login_wq) {
		vnic_err(NULL, "create_singlethread_workqueue failed for %s\n",
			 "login_wq");
		goto free_wq0;
	}

	fip_wq = create_singlethread_workqueue("fip");
	if (!fip_wq) {
		vnic_err(NULL, "create_singlethread_workqueue failed for %s\n",
			 "fip");
		goto free_wq1;
	}

	/* calls vnic_ib_dev_add_one() */
	rc = ib_register_client(&vnic_init_client);
	if (rc) {
		vnic_err(NULL, "ib_register_client failed %d\n", rc);
		goto free_wq2;
	}

	return 0;

free_wq2:
	destroy_workqueue(fip_wq);
free_wq1:
	destroy_workqueue(login_wq);
free_wq0:
	destroy_workqueue(port_wq);

	return -EINVAL;
}

void vnic_ports_cleanup(void)
{
	vnic_dbg(NULL, "calling ib_unregister_client\n");
	/* calls vnic_ib_dev_remove_one() */
	ib_unregister_client(&vnic_init_client);
	vnic_dbg(NULL, "calling destroy_workqueue\n");
	destroy_workqueue(fip_wq);
	destroy_workqueue(login_wq);
	destroy_workqueue(port_wq);
	vnic_dbg(NULL, "vnic_data_cleanup done\n");
}
