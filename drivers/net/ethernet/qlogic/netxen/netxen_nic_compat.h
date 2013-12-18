#ifndef _NETXEN_NIC_COMPAT_H
#define _NETXEN_NIC_COMPAT_H

#include <linux/netdevice.h>
#include <linux/version.h>
#include <linux/if_vlan.h>

static inline bool netif_is_bond_master(struct net_device *dev) {
	return dev->flags & IFF_MASTER && dev->priv_flags & IFF_BONDING;
}

#define netdev_master_upper_dev_get_rcu(dev)	(dev->master)
#define for_each_netdev_in_bond_rcu(bond, slave)       \
	for_each_netdev_rcu(&init_net, slave)           \
		if (slave->master == bond)

#define for_each_netdev_rcu(net, d)		\
	list_for_each_entry_rcu(d, &(net)->dev_base_head, dev_list)

#ifndef NAPI_POLL_WEIGHT
#define NAPI_POLL_WEIGHT 64
#endif

#endif
