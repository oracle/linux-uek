/*
 * Copyright (c) 2016, Mellanox Technologies. All rights reserved.
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

#include <linux/mlx5/driver.h>
#include <linux/mlx5/vport.h>
#include "mlx5_core.h"
#include "eswitch.h"

#ifdef MLX_USE_LAG_COMPAT
#define MLX_IMPL_LAG_EVENTS
#include <net/bonding.h>

#include <linux/device.h>
#include <net/rtnetlink.h>
#include <net/sock.h>
#include "en.h"
#endif

#if defined(MLX_USE_LAG_COMPAT) || defined(HAVE_LAG_TX_TYPE)
#define MLX_LAG_SUPPORTED
#endif

#ifdef MLX_LAG_SUPPORTED

enum {
	MLX5_LAG_FLAG_BONDED = 1 << 0,
};

struct lag_func {
	struct mlx5_core_dev *dev;
	struct net_device    *netdev;
};

/* Used for collection of netdev event info. */
struct lag_tracker {
	enum   netdev_lag_tx_type           tx_type;
	struct netdev_lag_lower_state_info  netdev_state[MLX5_MAX_PORTS];
	bool is_bonded;
};

/* LAG data of a ConnectX card.
 * It serves both its phys functions.
 */
struct mlx5_lag {
	u8                        flags;
	u8                        v2p_map[MLX5_MAX_PORTS];
	struct lag_func           pf[MLX5_MAX_PORTS];
	struct lag_tracker        tracker;
	struct delayed_work       bond_work;
	struct notifier_block     nb;
};

/* General purpose, use for short periods of time.
 * Beware of lock dependencies (preferably, no locks should be acquired
 * under it).
 */
static DEFINE_MUTEX(lag_mutex);
#endif

#ifdef MLX_USE_LAG_COMPAT
#undef  register_netdevice_notifier
#undef  unregister_netdevice_notifier
#define register_netdevice_notifier  		mlx5_lag_compat_register_netdev_notifier
#define unregister_netdevice_notifier		mlx5_lag_compat_unregister_netdev_notifier
#undef register_netdevice_notifier_rh
#undef unregister_netdevice_notifier_rh
#define register_netdevice_notifier_rh          mlx5_lag_compat_register_netdev_notifier
#define unregister_netdevice_notifier_rh        mlx5_lag_compat_unregister_netdev_notifier

#undef  netdev_notifier_info_to_dev
#define netdev_notifier_info_to_dev		netdev_notifier_info_to_dev_v2

#define MLX5_LAG_COMPAT_MAX_LAGDEVS		0x8

static int mlx5_lag_netdev_event(struct notifier_block *this,
				 unsigned long event, void *ptr);

static struct mlx5_lag *mlx5_lag_compat_ldevs[MLX5_LAG_COMPAT_MAX_LAGDEVS] = {};
static int mlx5_lag_compat_reg_ldevs = 0;

static void mlx5_lag_compat_netdev_event(unsigned long event, void *ptr)
{
	struct mlx5_lag *ldev;
	int i;

	for (i = 0; i < MLX5_LAG_COMPAT_MAX_LAGDEVS; ++i) {
		ldev = mlx5_lag_compat_ldevs[i];
		if (!ldev)
			continue;
		mlx5_lag_netdev_event(&ldev->nb, event, ptr);
	}
}

static int mlx5_lag_compat_register_netdev_notifier(struct notifier_block *nb)
{
	struct mlx5_lag *ldev = container_of(nb, struct mlx5_lag, nb);
	int err = 0, i;

	if (!mlx5_lag_compat_reg_ldevs)
		mlx_lag_compat_events_open(mlx5_lag_compat_netdev_event);

	rtnl_lock();
	for (i = 0; i < MLX5_LAG_COMPAT_MAX_LAGDEVS; ++i) {
		if (mlx5_lag_compat_ldevs[i])
			continue;

		mlx5_lag_compat_ldevs[i] = ldev;
		break;
	}

	if (i == MLX5_LAG_COMPAT_MAX_LAGDEVS) {
		err = -EINVAL;
		goto unlock;
	}

	++mlx5_lag_compat_reg_ldevs;

unlock:
	rtnl_unlock();
	return err;
}

static void mlx5_lag_compat_unregister_netdev_notifier(struct notifier_block *nb)
{
	struct mlx5_lag *ldev = container_of(nb, struct mlx5_lag, nb);
	int i;

	rtnl_lock();
	for (i = 0; i < MLX5_LAG_COMPAT_MAX_LAGDEVS; ++i) {
		if (mlx5_lag_compat_ldevs[i] != ldev)
			continue;

		mlx5_lag_compat_ldevs[i] = NULL;
		break;
	}

	--mlx5_lag_compat_reg_ldevs;
	rtnl_unlock();

	if (!mlx5_lag_compat_reg_ldevs)
		mlx_lag_compat_events_close();
}
#endif

#ifdef MLX_LAG_SUPPORTED

static int mlx5_cmd_create_lag(struct mlx5_core_dev *dev, u8 remap_port1,
			       u8 remap_port2)
{
	u32   in[MLX5_ST_SZ_DW(create_lag_in)]   = {0};
	u32   out[MLX5_ST_SZ_DW(create_lag_out)] = {0};
	void *lag_ctx = MLX5_ADDR_OF(create_lag_in, in, ctx);

	MLX5_SET(create_lag_in, in, opcode, MLX5_CMD_OP_CREATE_LAG);

	MLX5_SET(lagc, lag_ctx, tx_remap_affinity_1, remap_port1);
	MLX5_SET(lagc, lag_ctx, tx_remap_affinity_2, remap_port2);

	return mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
}

static int mlx5_cmd_modify_lag(struct mlx5_core_dev *dev, u8 remap_port1,
			       u8 remap_port2)
{
	u32   in[MLX5_ST_SZ_DW(modify_lag_in)]   = {0};
	u32   out[MLX5_ST_SZ_DW(modify_lag_out)] = {0};
	void *lag_ctx = MLX5_ADDR_OF(modify_lag_in, in, ctx);

	MLX5_SET(modify_lag_in, in, opcode, MLX5_CMD_OP_MODIFY_LAG);
	MLX5_SET(modify_lag_in, in, field_select, 0x1);

	MLX5_SET(lagc, lag_ctx, tx_remap_affinity_1, remap_port1);
	MLX5_SET(lagc, lag_ctx, tx_remap_affinity_2, remap_port2);

	return mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
}

static int mlx5_cmd_destroy_lag(struct mlx5_core_dev *dev)
{
	u32  in[MLX5_ST_SZ_DW(destroy_lag_in)]  = {0};
	u32 out[MLX5_ST_SZ_DW(destroy_lag_out)] = {0};

	MLX5_SET(destroy_lag_in, in, opcode, MLX5_CMD_OP_DESTROY_LAG);

	return mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
}
#endif /* #ifdef MLX_LAG_SUPPORTED */

int mlx5_cmd_create_vport_lag(struct mlx5_core_dev *dev)
{
#ifndef MLX_LAG_SUPPORTED
	return -EOPNOTSUPP;
#else
	u32  in[MLX5_ST_SZ_DW(create_vport_lag_in)]  = {0};
	u32 out[MLX5_ST_SZ_DW(create_vport_lag_out)] = {0};

	MLX5_SET(create_vport_lag_in, in, opcode, MLX5_CMD_OP_CREATE_VPORT_LAG);

	return mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
#endif /* #ifndef MLX_LAG_SUPPORTED */
}
EXPORT_SYMBOL(mlx5_cmd_create_vport_lag);

int mlx5_cmd_destroy_vport_lag(struct mlx5_core_dev *dev)
{
#ifndef MLX_LAG_SUPPORTED
	return -EOPNOTSUPP;
#else
	u32  in[MLX5_ST_SZ_DW(destroy_vport_lag_in)]  = {0};
	u32 out[MLX5_ST_SZ_DW(destroy_vport_lag_out)] = {0};

	MLX5_SET(destroy_vport_lag_in, in, opcode, MLX5_CMD_OP_DESTROY_VPORT_LAG);

	return mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
#endif /* #ifndef MLX_LAG_SUPPORTED */
}
EXPORT_SYMBOL(mlx5_cmd_destroy_vport_lag);

static int mlx5_cmd_query_cong_counter(struct mlx5_core_dev *dev,
				       bool reset, void *out, int out_size)
{
	u32 in[MLX5_ST_SZ_DW(query_cong_statistics_in)] = { };

	MLX5_SET(query_cong_statistics_in, in, opcode,
		 MLX5_CMD_OP_QUERY_CONG_STATISTICS);
	MLX5_SET(query_cong_statistics_in, in, clear, reset);
	return mlx5_cmd_exec(dev, in, sizeof(in), out, out_size);
}

#ifdef MLX_LAG_SUPPORTED
static struct mlx5_lag *mlx5_lag_dev_get(struct mlx5_core_dev *dev)
{
	return dev->priv.lag;
}

static int mlx5_lag_dev_get_netdev_idx(struct mlx5_lag *ldev,
				       struct net_device *ndev)
{
	int i;

	for (i = 0; i < MLX5_MAX_PORTS; i++)
		if (ldev->pf[i].netdev == ndev)
			return i;

	return -1;
}

static bool mlx5_lag_is_bonded(struct mlx5_lag *ldev)
{
	return !!(ldev->flags & MLX5_LAG_FLAG_BONDED);
}

static void mlx5_infer_tx_affinity_mapping(struct lag_tracker *tracker,
					   u8 *port1, u8 *port2)
{
	*port1 = 1;
	*port2 = 2;
	if (!tracker->netdev_state[0].tx_enabled ||
	    !tracker->netdev_state[0].link_up) {
		*port1 = 2;
		return;
	}

	if (!tracker->netdev_state[1].tx_enabled ||
	    !tracker->netdev_state[1].link_up)
		*port2 = 1;
}

static void mlx5_modify_lag(struct mlx5_lag *ldev,
			    struct lag_tracker *tracker)
{
	struct mlx5_core_dev *dev0 = ldev->pf[0].dev;
	u8 v2p_port1, v2p_port2;
	int err;

	mlx5_infer_tx_affinity_mapping(tracker, &v2p_port1,
				       &v2p_port2);

	if (v2p_port1 != ldev->v2p_map[0] ||
	    v2p_port2 != ldev->v2p_map[1]) {
		ldev->v2p_map[0] = v2p_port1;
		ldev->v2p_map[1] = v2p_port2;

		mlx5_core_info(dev0, "modify lag map port 1:%d port 2:%d",
			       ldev->v2p_map[0], ldev->v2p_map[1]);

		err = mlx5_cmd_modify_lag(dev0, v2p_port1, v2p_port2);
		if (err)
			mlx5_core_err(dev0,
				      "Failed to modify LAG (%d)\n",
				      err);
	}
}

static int mlx5_create_lag(struct mlx5_lag *ldev,
			   struct lag_tracker *tracker)
{
	struct mlx5_core_dev *dev0 = ldev->pf[0].dev;
	int err;

	mlx5_infer_tx_affinity_mapping(tracker, &ldev->v2p_map[0],
				       &ldev->v2p_map[1]);

	mlx5_core_info(dev0, "lag map port 1:%d port 2:%d",
		       ldev->v2p_map[0], ldev->v2p_map[1]);

	err = mlx5_cmd_create_lag(dev0, ldev->v2p_map[0], ldev->v2p_map[1]);
	if (err)
		mlx5_core_err(dev0,
			      "Failed to create LAG (%d)\n",
			      err);
	return err;
}

static void mlx5_activate_lag(struct mlx5_lag *ldev,
			      struct lag_tracker *tracker)
{
	ldev->flags |= MLX5_LAG_FLAG_BONDED;
	mlx5_create_lag(ldev, tracker);
}

static void mlx5_deactivate_lag(struct mlx5_lag *ldev)
{
	struct mlx5_core_dev *dev0 = ldev->pf[0].dev;
	int err;

	ldev->flags &= ~MLX5_LAG_FLAG_BONDED;

	err = mlx5_cmd_destroy_lag(dev0);
	if (err)
		mlx5_core_err(dev0,
			      "Failed to destroy LAG (%d)\n",
			      err);
}

static bool lag_allowed(struct mlx5_lag *ldev)
{
	return (!ldev->pf[0].dev->priv.lag_disabled &&
		!ldev->pf[1].dev->priv.lag_disabled);
}

static bool mlx5_lag_check_prereq(struct mlx5_lag *ldev)
{
	if (ldev->pf[0].dev &&
	    ldev->pf[1].dev &&
	    lag_allowed(ldev) &&
	    mlx5_sriov_lag_prereq(ldev->pf[0].dev, ldev->pf[1].dev))
		return true;
	else
		return false;
}

static void mlx5_do_bond(struct mlx5_lag *ldev)
{
	struct mlx5_core_dev *dev0 = ldev->pf[0].dev;
	struct mlx5_core_dev *dev1 = ldev->pf[1].dev;
	bool do_bond, sriov_enabled;
	struct lag_tracker tracker;
	int i;

	if (!dev0 || !dev1)
		return;

	sriov_enabled = mlx5_sriov_is_enabled(dev0) || mlx5_sriov_is_enabled(dev1);

	mutex_lock(&lag_mutex);
	tracker = ldev->tracker;
	mutex_unlock(&lag_mutex);

	do_bond = tracker.is_bonded && mlx5_lag_check_prereq(ldev);

	if (do_bond && !mlx5_lag_is_bonded(ldev)) {
		if (!sriov_enabled)
			for (i = 0; i < MLX5_MAX_PORTS; i++)
				mlx5_remove_dev_by_protocol(ldev->pf[i].dev,
							    MLX5_INTERFACE_PROTOCOL_IB);

		mlx5_activate_lag(ldev, &tracker);

		if (!sriov_enabled) {
			mlx5_add_dev_by_protocol(dev0, MLX5_INTERFACE_PROTOCOL_IB);
			mlx5_nic_vport_enable_roce(dev1);
		}
	} else if (do_bond && mlx5_lag_is_bonded(ldev)) {
		mlx5_modify_lag(ldev, &tracker);
	} else if (!do_bond && mlx5_lag_is_bonded(ldev)) {
		if (!sriov_enabled) {
			mlx5_remove_dev_by_protocol(dev0, MLX5_INTERFACE_PROTOCOL_IB);
			mlx5_nic_vport_disable_roce(dev1);
		}

		mlx5_deactivate_lag(ldev);

		if (!sriov_enabled)
			for (i = 0; i < MLX5_MAX_PORTS; i++)
				if (ldev->pf[i].dev)
					mlx5_add_dev_by_protocol(ldev->pf[i].dev,
								 MLX5_INTERFACE_PROTOCOL_IB);
	}
}

static void mlx5_queue_bond_work(struct mlx5_lag *ldev, unsigned long delay)
{
	schedule_delayed_work(&ldev->bond_work, delay);
}

static void mlx5_do_bond_work(struct work_struct *work)
{
	struct delayed_work *delayed_work = to_delayed_work(work);
	struct mlx5_lag *ldev = container_of(delayed_work, struct mlx5_lag,
					     bond_work);
	int status;

	status = mlx5_dev_list_trylock();
	if (!status) {
		/* 1 sec delay. */
		mlx5_queue_bond_work(ldev, HZ);
		return;
	}

	mlx5_do_bond(ldev);
	mlx5_dev_list_unlock();
}

static int mlx5_handle_changeupper_event(struct mlx5_lag *ldev,
					 struct lag_tracker *tracker,
					 struct net_device *ndev,
					 struct netdev_notifier_changeupper_info *info)
{
	struct net_device *upper = info->upper_dev, *ndev_tmp;
	struct netdev_lag_upper_info *lag_upper_info = NULL;
	bool is_bonded;
	int bond_status = 0;
	int num_slaves = 0;
	int idx;

	if (!netif_is_lag_master(upper))
		return 0;

	if (info->linking)
		lag_upper_info = info->upper_info;

	/* The event may still be of interest if the slave does not belong to
	 * us, but is enslaved to a master which has one or more of our netdevs
	 * as slaves (e.g., if a new slave is added to a master that bonds two
	 * of our netdevs, we should unbond).
	 */
#ifdef for_each_netdev_in_bond_rcu
	rcu_read_lock();
	for_each_netdev_in_bond_rcu(upper, ndev_tmp) {
#else
	for_each_netdev_in_bond(upper, ndev_tmp) {
#endif
		idx = mlx5_lag_dev_get_netdev_idx(ldev, ndev_tmp);
		if (idx > -1)
			bond_status |= (1 << idx);

		num_slaves++;
	}
#ifdef for_each_netdev_in_bond_rcu
	rcu_read_unlock();
#endif

	/* None of this lagdev's netdevs are slaves of this master. */
	if (!(bond_status & 0x3))
		return 0;

	if (lag_upper_info)
		tracker->tx_type = lag_upper_info->tx_type;

	/* Determine bonding status:
	 * A device is considered bonded if both its physical ports are slaves
	 * of the same lag master, and only them.
	 * Lag mode must be activebackup or hash.
	 */
	is_bonded = (num_slaves == MLX5_MAX_PORTS) &&
		    (bond_status == 0x3) &&
		    ((tracker->tx_type == NETDEV_LAG_TX_TYPE_ACTIVEBACKUP) ||
		     (tracker->tx_type == NETDEV_LAG_TX_TYPE_HASH));

	if (tracker->is_bonded != is_bonded) {
		tracker->is_bonded = is_bonded;
		return 1;
	}

	return 0;
}

static int mlx5_handle_changelowerstate_event(struct mlx5_lag *ldev,
					      struct lag_tracker *tracker,
					      struct net_device *ndev,
					      struct netdev_notifier_changelowerstate_info *info)
{
	struct netdev_lag_lower_state_info *lag_lower_info;
	int idx;

	if (!netif_is_lag_port(ndev))
		return 0;

	idx = mlx5_lag_dev_get_netdev_idx(ldev, ndev);
	if (idx == -1)
		return 0;

	/* This information is used to determine virtual to physical
	 * port mapping.
	 */
	lag_lower_info = info->lower_state_info;
	if (!lag_lower_info)
		return 0;

	tracker->netdev_state[idx] = *lag_lower_info;

	return 1;
}

static int mlx5_lag_netdev_event(struct notifier_block *this,
				 unsigned long event, void *ptr)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(ptr);
	struct lag_tracker tracker;
	struct mlx5_lag *ldev;
	int changed = 0;

	if (!net_eq(dev_net(ndev), &init_net))
		return NOTIFY_DONE;

	if ((event != NETDEV_CHANGEUPPER) && (event != NETDEV_CHANGELOWERSTATE))
		return NOTIFY_DONE;

	ldev    = container_of(this, struct mlx5_lag, nb);
	tracker = ldev->tracker;

	switch (event) {
	case NETDEV_CHANGEUPPER:
		changed = mlx5_handle_changeupper_event(ldev, &tracker, ndev,
							ptr);
		break;
	case NETDEV_CHANGELOWERSTATE:
		changed = mlx5_handle_changelowerstate_event(ldev, &tracker,
							     ndev, ptr);
		break;
	}

	mutex_lock(&lag_mutex);
	ldev->tracker = tracker;
	mutex_unlock(&lag_mutex);

	if (changed)
		mlx5_queue_bond_work(ldev, 0);

	return NOTIFY_DONE;
}

static struct mlx5_lag *mlx5_lag_dev_alloc(void)
{
	struct mlx5_lag *ldev;

	ldev = kzalloc(sizeof(*ldev), GFP_KERNEL);
	if (!ldev)
		return NULL;

	INIT_DELAYED_WORK(&ldev->bond_work, mlx5_do_bond_work);

	return ldev;
}

static void mlx5_lag_dev_free(struct mlx5_lag *ldev)
{
	kfree(ldev);
}

static void mlx5_lag_dev_add_pf(struct mlx5_lag *ldev,
				struct mlx5_core_dev *dev,
				struct net_device *netdev)
{
	unsigned int fn = PCI_FUNC(dev->pdev->devfn);

	if (fn >= MLX5_MAX_PORTS)
		return;

	mutex_lock(&lag_mutex);
	ldev->pf[fn].dev    = dev;
	ldev->pf[fn].netdev = netdev;
	ldev->tracker.netdev_state[fn].link_up = 0;
	ldev->tracker.netdev_state[fn].tx_enabled = 0;

	dev->priv.lag = ldev;
	mutex_unlock(&lag_mutex);
}

static void mlx5_lag_dev_remove_pf(struct mlx5_lag *ldev,
				   struct mlx5_core_dev *dev)
{
	int i;

	for (i = 0; i < MLX5_MAX_PORTS; i++)
		if (ldev->pf[i].dev == dev)
			break;

	if (i == MLX5_MAX_PORTS)
		return;

	mutex_lock(&lag_mutex);
	memset(&ldev->pf[i], 0, sizeof(*ldev->pf));

	dev->priv.lag = NULL;
	mutex_unlock(&lag_mutex);
}

static ssize_t mlx5_lag_show_enabled(struct device *device,
				     struct device_attribute *attr,
				     char *buf)
{
	struct pci_dev *pdev = container_of(device, struct pci_dev, dev);
	struct mlx5_core_dev *dev  = pci_get_drvdata(pdev);

	return sprintf(buf, "%d\n", !dev->priv.lag_disabled);
}

static ssize_t mlx5_lag_set_enabled(struct device *device,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	struct pci_dev *pdev = container_of(device, struct pci_dev, dev);
	struct mlx5_core_dev *dev  = pci_get_drvdata(pdev);
	int ret = -EINVAL;
	u32 val;

	ret = kstrtou32(buf, 0, &val);
	if (ret)
		return ret;

	if (val == 1)
		dev->priv.lag_disabled = 0;
	else if (val == 0)
		dev->priv.lag_disabled = 1;
	else
		return -EINVAL;

	mlx5_lag_update(dev);

	return ret ? ret : count;
}

static DEVICE_ATTR(roce_lag_enable, 0644, mlx5_lag_show_enabled, mlx5_lag_set_enabled);
static struct device_attribute *mlx5_lag_dev_attrs = &dev_attr_roce_lag_enable;
#endif /* #ifdef MLX_LAG_SUPPORTED */

/* Must be called with intf_mutex held */
void mlx5_lag_add(struct mlx5_core_dev *dev, struct net_device *netdev)
{
#ifdef MLX_LAG_SUPPORTED
	struct mlx5_lag *ldev = NULL;
	struct mlx5_core_dev *tmp_dev;

	if (!MLX5_CAP_GEN(dev, vport_group_manager) ||
	    !MLX5_CAP_GEN(dev, lag_master) ||
	    (MLX5_CAP_GEN(dev, num_lag_ports) != MLX5_MAX_PORTS))
		return;

	if (device_create_file(&dev->pdev->dev, mlx5_lag_dev_attrs)) {
		mlx5_core_err(dev, "Failed to create RoCE LAG sysfs\n");
		return;
	}

	tmp_dev = mlx5_get_next_phys_dev(dev);
	if (tmp_dev)
		ldev = tmp_dev->priv.lag;

	if (!ldev) {
		ldev = mlx5_lag_dev_alloc();
		if (!ldev) {
			mlx5_core_err(dev, "Failed to alloc lag dev\n");
			goto remove_file;
		}
	}

	mlx5_lag_dev_add_pf(ldev, dev, netdev);

	if (!ldev->nb.notifier_call) {
		ldev->nb.notifier_call = mlx5_lag_netdev_event;
		if (register_netdevice_notifier(&ldev->nb)) {
			ldev->nb.notifier_call = NULL;
			mlx5_core_err(dev, "Failed to register LAG netdev notifier\n");
		}
	}

	return;

remove_file:
	device_remove_file(&dev->pdev->dev, mlx5_lag_dev_attrs);
#endif /* #ifdef MLX_LAG_SUPPORTED */
}

/* Must be called with intf_mutex held */
void mlx5_lag_remove(struct mlx5_core_dev *dev)
{
#ifdef MLX_LAG_SUPPORTED
	struct mlx5_lag *ldev;
	int i;

	ldev = mlx5_lag_dev_get(dev);
	if (!ldev)
		return;

	device_remove_file(&dev->pdev->dev, mlx5_lag_dev_attrs);

	if (mlx5_lag_is_bonded(ldev))
		mlx5_deactivate_lag(ldev);

	mlx5_lag_dev_remove_pf(ldev, dev);

	for (i = 0; i < MLX5_MAX_PORTS; i++)
		if (ldev->pf[i].dev)
			break;

	if (i == MLX5_MAX_PORTS) {
		if (ldev->nb.notifier_call)
			unregister_netdevice_notifier(&ldev->nb);
		cancel_delayed_work_sync(&ldev->bond_work);
		mlx5_lag_dev_free(ldev);
	}
#endif /* #ifdef MLX_LAG_SUPPORTED */
}

bool mlx5_lag_is_active(struct mlx5_core_dev *dev)
{
#ifndef MLX_LAG_SUPPORTED
	return false;
#else
	struct mlx5_lag *ldev;
	bool res;

	mutex_lock(&lag_mutex);
	ldev = mlx5_lag_dev_get(dev);
	res  = ldev && mlx5_lag_is_bonded(ldev);
	mutex_unlock(&lag_mutex);

	return res;
#endif
}
EXPORT_SYMBOL(mlx5_lag_is_active);

void mlx5_lag_update(struct mlx5_core_dev *dev)
{
#ifdef MLX_LAG_SUPPORTED
	struct mlx5_lag *ldev;

	mlx5_dev_list_lock();
	ldev = mlx5_lag_dev_get(dev);
	if (!ldev)
		goto unlock;

	mlx5_do_bond(ldev);

unlock:
	mlx5_dev_list_unlock();
#endif /* #ifdef MLX_LAG_SUPPORTED */
}


struct net_device *mlx5_lag_get_roce_netdev(struct mlx5_core_dev *dev)
{
#ifndef MLX_LAG_SUPPORTED
	return NULL;
#else
	struct net_device *ndev = NULL;
	struct mlx5_lag *ldev;

	mutex_lock(&lag_mutex);
	ldev = mlx5_lag_dev_get(dev);

	if (!(ldev && mlx5_lag_is_bonded(ldev)))
		goto unlock;

	if (ldev->tracker.tx_type == NETDEV_LAG_TX_TYPE_ACTIVEBACKUP) {
		ndev = ldev->tracker.netdev_state[0].tx_enabled ?
		       ldev->pf[0].netdev : ldev->pf[1].netdev;
	} else {
		ndev = ldev->pf[0].netdev;
	}
	if (ndev)
		dev_hold(ndev);

unlock:
	mutex_unlock(&lag_mutex);

	return ndev;
#endif /* #ifndef MLX_LAG_SUPPORTED */
}
EXPORT_SYMBOL(mlx5_lag_get_roce_netdev);

bool mlx5_lag_intf_add(struct mlx5_interface *intf, struct mlx5_priv *priv)
{
#ifndef MLX_LAG_SUPPORTED
	return false;
#else
	struct mlx5_core_dev *dev = container_of(priv, struct mlx5_core_dev,
						 priv);
	struct mlx5_lag *ldev;

	if (intf->protocol != MLX5_INTERFACE_PROTOCOL_IB)
		return true;

	ldev = mlx5_lag_dev_get(dev);
	if (!ldev || !mlx5_lag_is_bonded(ldev) || ldev->pf[0].dev == dev)
		return true;

	/* If bonded, we do not add an IB device for PF1. */
	return false;
#endif /* #ifndef MLX_LAG_SUPPORTED */
}

int mlx5_lag_query_cong_counters(struct mlx5_core_dev *dev,
				 u64 *values,
				 int num_counters,
				 size_t *offsets)
{
	int outlen = MLX5_ST_SZ_BYTES(query_cong_statistics_out);
	struct mlx5_core_dev *mdev[MLX5_MAX_PORTS];
#ifdef MLX_LAG_SUPPORTED
	struct mlx5_lag *ldev;
#endif
	int num_ports;
	int ret, i, j;
	void *out;

	out = kvzalloc(outlen, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	memset(values, 0, sizeof(*values) * num_counters);

#ifdef MLX_LAG_SUPPORTED
	mutex_lock(&lag_mutex);
	ldev = mlx5_lag_dev_get(dev);
	if (ldev && mlx5_lag_is_bonded(ldev)) {
		num_ports = MLX5_MAX_PORTS;
		mdev[0] = ldev->pf[0].dev;
		mdev[1] = ldev->pf[1].dev;
	} else {
		num_ports = 1;
		mdev[0] = dev;
	}
#else
	num_ports = 1;
	mdev[0] = dev;
#endif

	for (i = 0; i < num_ports; ++i) {
		ret = mlx5_cmd_query_cong_counter(mdev[i], false, out, outlen);
		if (ret)
			goto unlock;

		for (j = 0; j < num_counters; ++j)
			values[j] += be64_to_cpup((__be64 *)(out + offsets[j]));
	}

unlock:
#ifdef MLX_LAG_SUPPORTED
	mutex_unlock(&lag_mutex);
#endif
	kvfree(out);
	return ret;
}
EXPORT_SYMBOL(mlx5_lag_query_cong_counters);

static int mlx5_cmd_modify_cong_params(struct mlx5_core_dev *dev,
				       void *in, int in_size)
{
	u32 out[MLX5_ST_SZ_DW(modify_cong_params_out)] = { };

	return mlx5_cmd_exec(dev, in, in_size, out, sizeof(out));
}

int mlx5_lag_modify_cong_params(struct mlx5_core_dev *dev,
				void *in, int in_size)
{
	struct mlx5_core_dev *mdev[MLX5_MAX_PORTS];
#ifdef MLX_LAG_SUPPORTED
	struct mlx5_lag *ldev;
#endif
	int num_ports;
	int ret;
	int i;

#ifdef MLX_LAG_SUPPORTED
	mutex_lock(&lag_mutex);
	ldev = mlx5_lag_dev_get(dev);
	if (ldev && mlx5_lag_is_bonded(ldev)) {
		num_ports = MLX5_MAX_PORTS;
		mdev[0] = ldev->pf[0].dev;
		mdev[1] = ldev->pf[1].dev;
	} else {
		num_ports = 1;
		mdev[0] = dev;
	}
#else
	num_ports = 1;
	mdev[0] = dev;
#endif

	for (i = 0; i < num_ports; i++) {
		ret = mlx5_cmd_modify_cong_params(mdev[i], in, in_size);
		if (ret)
			goto unlock;
	}

unlock:
#ifdef MLX_LAG_SUPPORTED
	mutex_unlock(&lag_mutex);
#endif
	return ret;
}
EXPORT_SYMBOL(mlx5_lag_modify_cong_params);

struct mlx5_core_dev *mlx5_lag_get_peer_mdev(struct mlx5_core_dev *dev)
{
#ifndef MLX_LAG_SUPPORTED
	return NULL;
#else
	struct mlx5_core_dev *peer_dev = NULL;
	struct mlx5_lag *ldev;

	mutex_lock(&lag_mutex);
	ldev = mlx5_lag_dev_get(dev);
	if (!ldev)
		goto unlock;

	peer_dev = ldev->pf[0].dev == dev ? ldev->pf[1].dev : ldev->pf[0].dev;

unlock:
	mutex_unlock(&lag_mutex);
	return peer_dev;
#endif
}

struct net_device *mlx5_lag_get_peer_netdev(struct mlx5_core_dev *dev)
{
#ifndef MLX_LAG_SUPPORTED
	return NULL;
#else
	struct net_device *peer_ndev = NULL;
	struct mlx5_lag *ldev;

	mutex_lock(&lag_mutex);
	ldev = mlx5_lag_dev_get(dev);
	if (!ldev)
		goto unlock;

	peer_ndev = ldev->pf[0].dev == dev ? ldev->pf[1].netdev : ldev->pf[0].netdev;

unlock:
	mutex_unlock(&lag_mutex);
	return peer_ndev;
#endif
}
