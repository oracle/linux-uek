/*
 * Copyright (c) 2012 Mellanox Technologies. All rights reserved
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * openfabric.org BSD license below:
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

#include "eth_ipoib.h"
#include <net/ip.h>
#include <linux/if_link.h>

#define EMAC_IP_GC_TIME (10 * HZ)

#define GEN_ARP_REQ_ISSUE_TIME (HZ/2)

#define MIG_OUT_MAX_ARP_RETRIES 5

#define GRAT_ARP_MAX_RETRIES 3

#define LIVE_MIG_PACKET 1

#define PARENT_MAC_MASK 0xe7

/* forward declaration */
static rx_handler_result_t eipoib_handle_frame(struct sk_buff **pskb);
static int eipoib_device_event(struct notifier_block *unused,
			       unsigned long event, void *ptr);
static void free_all_ip_ent_in_emac_rec(struct guest_emac_info *emac_info);

static const char * const version =
	DRV_DESCRIPTION ": v" DRV_VERSION " (" DRV_RELDATE ")\n";

LIST_HEAD(parent_dev_list);

/* name space sys/fs functions */
int eipoib_net_id __read_mostly;

static int __net_init eipoib_net_init(struct net *net)
{
	int rc;
	struct eipoib_net *eipoib_n = net_generic(net, eipoib_net_id);

	eipoib_n->net = net;
	rc = mod_create_sysfs(eipoib_n);

	return rc;
}

static void __net_exit eipoib_net_exit(struct net *net)
{
	struct eipoib_net *eipoib_n = net_generic(net, eipoib_net_id);

	mod_destroy_sysfs(eipoib_n);
}

static struct pernet_operations eipoib_net_ops = {
	.init = eipoib_net_init,
	.exit = eipoib_net_exit,
	.id   = &eipoib_net_id,
	.size = sizeof(struct eipoib_net),
};

/* set mac fields emac=<qpn><lid> */
static inline
void build_neigh_mac(u8 *_mac, u32 _qpn, u16 _lid)
{
	/* _qpn: 3B _lid: 2B */
	*((__be32 *)(_mac)) = cpu_to_be32(_qpn);
	*(u8 *)(_mac) = 0x2; /* set LG bit */
	*(__be16 *)(_mac + sizeof(_qpn)) = cpu_to_be16(_lid);
}

static inline
struct slave *get_slave_by_dev(struct parent *parent,
			       struct net_device *slave_dev)
{
	struct slave *slave, *slave_tmp;
	int found = 0;

	parent_for_each_slave(parent, slave_tmp) {
		if (slave_tmp->dev == slave_dev) {
			found = 1;
			slave = slave_tmp;
			break;
		}
	}

	return found ? slave : NULL;
}

static inline
struct slave *get_slave_by_mac_and_vlan(struct parent *parent, u8 *mac,
					u16 vlan)
{
	struct slave *slave, *slave_tmp;
	int found = 0;

	parent_for_each_slave(parent, slave_tmp) {
		if ((!memcmp(slave_tmp->emac, mac, ETH_ALEN)) &&
		    (slave_tmp->vlan == vlan)) {
			found = 1;
			slave = slave_tmp;
			break;
		}
	}

	return found ? slave : NULL;
}


static inline
struct guest_emac_info *get_mac_ip_info_by_mac_and_vlan(struct parent *parent,
							u8 *mac, u16 vlan)
{
	struct guest_emac_info *emac_info;
	int found = 0;

	list_for_each_entry(emac_info, &parent->emac_ip_list, list) {
		if ((!memcmp(emac_info->emac, mac, ETH_ALEN)) &&
		    vlan == emac_info->vlan) {
			found = 1;
			break;
		}
	}

	return found ? emac_info : NULL;
}

/*
 * searches for the relevant guest_emac_info in the parent.
 * if found it, check if it contains the required ip
 * if no such guest_emac_info object or no ip return 0,
 * otherwise return 1 and if exist set the guest_emac_info obj.
 */
static inline
int is_mac_info_contain_new_ip(struct parent *parent, u8 *mac, __be32 ip,
			  struct guest_emac_info *emac_info, u16 vlan)
{
	struct ip_member *ipm;
	int found = 0;

	emac_info = get_mac_ip_info_by_mac_and_vlan(parent, mac, vlan);

	if (!emac_info)
		return 0;

	list_for_each_entry(ipm, &emac_info->ip_list, list) {
		if (ipm->ip == ip) {
			found = 1;
			break;
		}
	}

	return found;
}

static inline int netdev_set_parent_master(struct net_device *slave,
					   struct net_device *master)
{
	int err;

	ASSERT_RTNL();

	err = netdev_set_master(slave, master);
	if (err)
		return err;
	if (master) {
			slave->priv_flags |= IFF_EIPOIB_VIF;
			/* deny bonding from enslaving it. */;
			slave->flags |= IFF_SLAVE;
	} else {
		slave->priv_flags &= ~(IFF_EIPOIB_VIF);
		slave->flags &= ~(IFF_SLAVE);
	}

	return 0;
}

static inline int is_driver_owner(struct net_device *dev, char *name)
{
	struct ethtool_drvinfo drvinfo;

	if (dev->ethtool_ops && dev->ethtool_ops->get_drvinfo) {
		memset(&drvinfo, 0, sizeof(drvinfo));
		dev->ethtool_ops->get_drvinfo(dev, &drvinfo);
		if (!strstr(drvinfo.driver, name))
			return 0;
	} else
		return 0;

	return 1;
}

static inline int is_parent(struct net_device *dev)
{
	return (dev->priv_flags & IFF_EIPOIB_PIF) &&
		is_driver_owner(dev, DRV_NAME);
}

static inline int is_parent_mac(struct net_device *dev, u8 *mac)
{
	return is_parent(dev) && !memcmp(mac, dev->dev_addr, dev->addr_len);
}

static inline int __is_slave(struct net_device *dev)
{
	return dev->master && is_parent(dev->master);
}

static inline int is_slave(struct net_device *dev)
{
	return (dev->priv_flags & IFF_EIPOIB_VIF) &&
		is_driver_owner(dev, SDRV_NAME) && __is_slave(dev);
}

/*
 * ------------------------------- Link status ------------------
 * set parent carrier:
 * link is up if at least one slave has link up
 * otherwise, bring link down
 * return 1 if parent carrier changed, zero otherwise
 */
static int parent_set_carrier(struct parent *parent)
{
	struct slave *slave;

	if (parent->slave_cnt == 0)
		goto down;

	/* bring parent link up if one slave (at least) is up */
	parent_for_each_slave(parent, slave) {
		if (netif_carrier_ok(slave->dev)) {
			if (!netif_carrier_ok(parent->dev)) {
				netif_carrier_on(parent->dev);
				return 1;
			}
			return 0;
		}
	}

down:
	if (netif_carrier_ok(parent->dev)) {
		pr_info("bring down carrier\n");
		netif_carrier_off(parent->dev);
		return 1;
	}
	return 0;
}

static int parent_set_mtu(struct parent *parent)
{
	struct slave *slave, *f_slave;
	unsigned int mtu;

	if (parent->slave_cnt == 0)
		return 0;

	/* find min mtu */
	f_slave = list_first_entry(&parent->slave_list, struct slave, list);
	mtu = f_slave->dev->mtu;

	parent_for_each_slave(parent, slave)
		mtu = min(slave->dev->mtu, mtu);

	if (parent->dev->mtu != mtu) {
		dev_set_mtu(parent->dev, mtu);
		return 1;
	}

	return 0;
}

/*
 * The function returns the features that are not depend
 * on the slaves's features.
 * Only features that were at the parent netdev before.
 */
static u64 parent_self_features(struct net_device *parent_dev)
{
	u64 parent_orig_features = 0;

	/* basic independent features*/
	if (parent_dev->features & NETIF_F_GRO)
		parent_orig_features |= NETIF_F_GRO;

	return parent_orig_features;
}


/*--------------------------- slave list handling ------
 *
 * This function attaches the slave to the end of list.
 * pay attention, the caller should held paren->lock
 */
static void parent_attach_slave(struct parent *parent,
				struct slave *new_slave)
{
	list_add_tail(&new_slave->list, &parent->slave_list);
	parent->slave_cnt++;
}

static void parent_detach_slave(struct parent *parent, struct slave *slave)
{
	list_del(&slave->list);
	parent->slave_cnt--;
}

static netdev_features_t parent_fix_features(struct net_device *dev,
					     netdev_features_t features)
{
	struct slave *slave;
	struct parent *parent = netdev_priv(dev);
	netdev_features_t mask;
	u64 parent_orig_features = parent_self_features(parent->dev);

	read_lock(&parent->lock);

	mask = features;
	features &= ~NETIF_F_ONE_FOR_ALL;
	features |= NETIF_F_ALL_FOR_ALL;

	parent_for_each_slave(parent, slave)
		features = netdev_increment_features(features,
						     slave->dev->features,
						     mask);

	features &= ~NETIF_F_VLAN_CHALLENGED;

	/* return back the original independent features */
	features |= parent_orig_features;

	read_unlock(&parent->lock);
	return features;
}

static int parent_compute_features(struct parent *parent)
{
	struct net_device *parent_dev = parent->dev;
	u64 hw_features, features, parent_orig_features = 0;
	struct slave *slave;

	if (list_empty(&parent->slave_list))
		goto done;

	/* take basic features that do not depends on slaves */
	parent_orig_features = parent_self_features(parent_dev);

	/* starts with the max set of features mask */
	hw_features = features = ~0LL;

	/* gets the common features from all slaves */
	parent_for_each_slave(parent, slave) {
		features &= slave->dev->features;
		hw_features &= slave->dev->hw_features;
	}

	features = features | PARENT_VLAN_FEATURES;
	hw_features = hw_features | PARENT_VLAN_FEATURES;

	hw_features &= ~NETIF_F_VLAN_CHALLENGED;
	features &= hw_features;
	features |= parent_orig_features;

	parent_dev->hw_features = hw_features;
	parent_dev->features = features;
	parent_dev->vlan_features = parent_dev->features & ~PARENT_VLAN_FEATURES;
done:
	pr_info("%s: %s: Features: 0x%llx\n",
		__func__, parent_dev->name, parent_dev->features);

	return 0;
}

static inline u16 slave_get_pkey(struct net_device *dev)
{
	u16 pkey = (dev->broadcast[8] << 8) + dev->broadcast[9];

	return pkey;
}

static void parent_setup_by_slave(struct net_device *parent_dev,
				  struct net_device *slave_dev)
{
	struct parent *parent = netdev_priv(parent_dev);
	const struct net_device_ops *slave_ops = slave_dev->netdev_ops;

	parent_dev->mtu = slave_dev->mtu;
	parent_dev->hard_header_len = slave_dev->hard_header_len;

	if (slave_ops->ndo_neigh_setup)
		slave_ops->ndo_neigh_setup(slave_dev, &parent->nparms);

}

/* enslave device <slave> to parent device <master> */
int parent_enslave(struct net_device *parent_dev, struct net_device *slave_dev)
{
	struct parent *parent = netdev_priv(parent_dev);
	struct slave *new_slave = NULL;
	int old_features = parent_dev->features;
	int res = 0;

	/* slave must be claimed by ipoib */
	if (!is_driver_owner(slave_dev, SDRV_NAME))
		return -EOPNOTSUPP;

	/* parent must be initialized by parent_open() before enslaving */
	if (!(parent_dev->flags & IFF_UP)) {
		pr_warn("%s parent is not up in "
			"parent_enslave\n",
			parent_dev->name);
		return -EPERM;
	}

	/* already enslaved */
	if ((slave_dev->flags & IFF_SLAVE) ||
		(slave_dev->priv_flags & IFF_EIPOIB_VIF)) {
		pr_err("%s was already enslaved!!!\n", slave_dev->name);
		return -EBUSY;
	}

	/* mark it as ipoib clone vif */
	slave_dev->priv_flags |= IFF_EIPOIB_VIF;

	/* set parent netdev attributes */
	if (parent->slave_cnt == 0)
		parent_setup_by_slave(parent_dev, slave_dev);
	else {
		/* check netdev attr match */
		if (slave_dev->hard_header_len != parent_dev->hard_header_len) {
			pr_err("%s slave %s has different HDR len %d != %d\n",
			       parent_dev->name, slave_dev->name,
			       slave_dev->hard_header_len,
			       parent_dev->hard_header_len);
			res = -EINVAL;
			goto err_undo_flags;
		}

		if (slave_dev->type != ARPHRD_INFINIBAND ||
		    slave_dev->addr_len != INFINIBAND_ALEN) {
			pr_err("%s slave type/addr_len is invalid (%d/%d)\n",
			       parent_dev->name, slave_dev->type,
			       slave_dev->addr_len);
			res = -EINVAL;
			goto err_undo_flags;
		}
	}
	/*
	 * verfiy that this (slave) device belongs to the relevant PIF
	 * abort if the name of the slave is not as the regular way in ipoib
	 */
	if (!strstr(slave_dev->name, parent->ipoib_main_interface)) {
		pr_err("%s slave name (%s) doesn't contain parent name (%s) ",
		       parent_dev->name, slave_dev->name,
		       parent->ipoib_main_interface);
		res = -EINVAL;
		goto err_undo_flags;
	}

	new_slave = kzalloc(sizeof(struct slave), GFP_KERNEL);
	if (!new_slave) {
		res = -ENOMEM;
		goto err_undo_flags;
	}

	INIT_LIST_HEAD(&new_slave->neigh_list);

	/* save slave's vlan */
	new_slave->pkey = slave_get_pkey(slave_dev);

	res = netdev_set_parent_master(slave_dev, parent_dev);
	if (res) {
		pr_err("%s %d calling netdev_set_master\n",
		       slave_dev->name, res);
		goto err_free;
	}

	res = dev_open(slave_dev);
	if (res) {
		pr_info("open failed %s\n",
			slave_dev->name);
		goto err_unset_master;
	}

	new_slave->dev = slave_dev;

	write_lock(&parent->lock);

	parent_attach_slave(parent, new_slave);

	parent_compute_features(parent);

	write_unlock(&parent->lock);

	read_lock(&parent->lock);

	parent_set_carrier(parent);

	read_unlock(&parent->lock);

	res = create_slave_symlinks(parent_dev, slave_dev);
	if (res)
		goto err_close;

	/* register handler */
	res = netdev_rx_handler_register(slave_dev, eipoib_handle_frame,
					 new_slave);
	if (res) {
		pr_warn("%s %d calling netdev_rx_handler_register\n",
			parent_dev->name, res);
		goto err_close;
	}

	pr_info("%s: enslaving %s\n", parent_dev->name, slave_dev->name);

	/* enslave is successful */
	return 0;

/* Undo stages on error */
err_close:
	dev_close(slave_dev);

err_unset_master:
	netdev_set_parent_master(slave_dev, NULL);

err_free:
	kfree(new_slave);

err_undo_flags:
	parent_dev->features = old_features;

	return res;
}

static void slave_free(struct parent *parent, struct slave *slave)
{
	struct neigh *neigh, *neigh_tmp;

	list_for_each_entry_safe(neigh, neigh_tmp, &slave->neigh_list, list) {
		list_del(&neigh->list);
		kfree(neigh);
	}

	netdev_rx_handler_unregister(slave->dev);

	kfree(slave);
}

int parent_release_slave(struct net_device *parent_dev,
			 struct net_device *slave_dev)
{
	struct parent *parent = netdev_priv(parent_dev);
	struct slave *slave;
	struct guest_emac_info *emac_info;

	/* slave is not a slave or master is not master of this slave */
	if (!(slave_dev->flags & IFF_SLAVE) ||
	    (slave_dev->master != parent_dev)) {
		pr_err("%s cannot release %s.\n",
		       parent_dev->name, slave_dev->name);
		return -EINVAL;
	}

	write_lock(&parent->lock);

	slave = get_slave_by_dev(parent, slave_dev);
	if (!slave) {
		/* not a slave of this parent */
		pr_warn("%s not enslaved %s\n",
			parent_dev->name, slave_dev->name);
		write_unlock(&parent->lock);
		return -EINVAL;
	}

	pr_info("%s: releasing interface %s\n", parent_dev->name,
		slave_dev->name);

	/* for live migration, mark its mac_ip record as invalid */
	write_lock(&parent->emac_info_lock);
	emac_info = get_mac_ip_info_by_mac_and_vlan(parent, slave->emac, slave->vlan);
	if (!emac_info)
		pr_warn("%s %s didn't find emac: %pM\n",
			parent_dev->name, slave_dev->name, slave->emac);
	else {
		emac_info->rec_state = MIGRATED_OUT;
		emac_info->num_of_retries = MIG_OUT_MAX_ARP_RETRIES;
		/* start GC work */
		pr_info("%s: sending clean task for slave mac: %pM\n",
			__func__, slave->emac);
		queue_delayed_work(parent->wq, &parent->arp_gen_work, 0);
	}
	write_unlock(&parent->emac_info_lock);

	/* release the slave from its parent */
	parent_detach_slave(parent, slave);

	parent_compute_features(parent);

	if (parent->slave_cnt == 0)
		parent_set_carrier(parent);

	write_unlock(&parent->lock);

	/* must do this from outside any spinlocks */
	destroy_slave_symlinks(parent_dev, slave_dev);

	netdev_set_parent_master(slave_dev, NULL);

	dev_close(slave_dev);

	slave_free(parent, slave);

	return 0;  /* deletion OK */
}

static int parent_release_all(struct net_device *parent_dev)
{
	struct parent *parent = netdev_priv(parent_dev);
	struct slave *slave, *slave_tmp;
	struct net_device *slave_dev;
	struct neigh *neigh_cmd, *neigh_cmd_tmp;
	struct guest_emac_info *emac_info, *emac_info_tmp;
	struct slave;

	write_lock(&parent->lock);

	netif_carrier_off(parent_dev);

	if (parent->slave_cnt == 0)
		goto out;

	list_for_each_entry_safe(slave, slave_tmp, &parent->slave_list, list) {
		slave_dev = slave->dev;

		/* remove slave from parent's slave-list */
		parent_detach_slave(parent, slave);

		parent_compute_features(parent);

		write_unlock(&parent->lock);

		destroy_slave_symlinks(parent_dev, slave_dev);

		netdev_set_parent_master(slave_dev, NULL);

		dev_close(slave_dev);

		slave_free(parent, slave);

		write_lock(&parent->lock);
	}

	list_for_each_entry_safe(neigh_cmd, neigh_cmd_tmp,
				 &parent->neigh_add_list, list) {
		list_del(&neigh_cmd->list);
			kfree(neigh_cmd);
		}

	write_lock(&parent->emac_info_lock);
	list_for_each_entry_safe(emac_info, emac_info_tmp,
				 &parent->emac_ip_list, list) {
		free_all_ip_ent_in_emac_rec(emac_info);
		list_del(&emac_info->list);
		kfree(emac_info);
	}
	write_unlock(&parent->emac_info_lock);

	pr_info("%s: released all slaves\n", parent_dev->name);

out:
	write_unlock(&parent->lock);

	return 0;
}

/* -------------------------- Device entry points --------------------------- */
static struct rtnl_link_stats64 *parent_get_stats(struct net_device *parent_dev,
						  struct rtnl_link_stats64 *stats)
{
	struct parent *parent = netdev_priv(parent_dev);
	struct slave *slave;
	struct rtnl_link_stats64 temp;

	memset(stats, 0, sizeof(*stats));

	read_lock(&parent->lock);

	parent_for_each_slave(parent, slave) {
		const struct rtnl_link_stats64 *sstats =
			dev_get_stats(slave->dev, &temp);

		stats->rx_packets += sstats->rx_packets;
		stats->rx_bytes += sstats->rx_bytes;
		stats->rx_errors += sstats->rx_errors;
		stats->rx_dropped += sstats->rx_dropped;

		stats->tx_packets += sstats->tx_packets;
		stats->tx_bytes += sstats->tx_bytes;
		stats->tx_errors += sstats->tx_errors;
		stats->tx_dropped += sstats->tx_dropped;

		stats->multicast += sstats->multicast;
		stats->collisions += sstats->collisions;

		stats->rx_length_errors += sstats->rx_length_errors;
		stats->rx_over_errors += sstats->rx_over_errors;
		stats->rx_crc_errors += sstats->rx_crc_errors;
		stats->rx_frame_errors += sstats->rx_frame_errors;
		stats->rx_fifo_errors += sstats->rx_fifo_errors;
		stats->rx_missed_errors += sstats->rx_missed_errors;

		stats->tx_aborted_errors += sstats->tx_aborted_errors;
		stats->tx_carrier_errors += sstats->tx_carrier_errors;
		stats->tx_fifo_errors += sstats->tx_fifo_errors;
		stats->tx_heartbeat_errors += sstats->tx_heartbeat_errors;
		stats->tx_window_errors += sstats->tx_window_errors;
	}

	read_unlock(&parent->lock);

	return stats;
}

/* ---------------------------- Main funcs ---------------------------------- */
static struct neigh *neigh_cmd_find_by_mac(struct slave *slave, u8 *mac)
{
	struct net_device *dev = slave->dev;
	struct net_device *parent_dev = dev->master;
	struct parent *parent = netdev_priv(parent_dev);
	struct neigh *neigh;
	int found = 0;

	list_for_each_entry(neigh, &parent->neigh_add_list, list) {
		if (!memcmp(neigh->emac, mac, ETH_ALEN)) {
			found = 1;
			break;
		}
	}

	return found ? neigh : NULL;
}

static struct neigh *neigh_find_by_mac(struct slave *slave, u8 *mac)
{
	struct neigh *neigh;
	int found = 0;

	list_for_each_entry(neigh, &slave->neigh_list, list) {
		if (!memcmp(neigh->emac, mac, ETH_ALEN)) {
			found = 1;
			break;
		}
	}

	return found ? neigh : NULL;
}

static int neigh_learn(struct slave *slave, struct sk_buff *skb, u8 *remac)
{
	struct net_device *dev = slave->dev;
	struct net_device *parent_dev = dev->master;
	struct parent *parent = netdev_priv(parent_dev);
	struct neigh *neigh_cmd;
	u8 *rimac;
	int rc;

	/* linearize to easy on reading the arp payload */
	rc = skb_linearize(skb);
	if (rc) {
		pr_err("%s: skb_linearize failed rc %d\n", dev->name, rc);
		goto out;
	} else
		rimac = skb->data + sizeof(struct arphdr);

	/* check if entry is being processed or already exists */
	if (neigh_find_by_mac(slave, remac))
		goto out;

	if (neigh_cmd_find_by_mac(slave, remac))
		goto out;

	neigh_cmd = parent_get_neigh_cmd('+', slave->dev->name, remac, rimac);
	if (!neigh_cmd) {
		pr_err("%s cannot build neigh cmd\n", slave->dev->name);
		rc = -ENOMEM;
		goto out;
	}

	list_add_tail(&neigh_cmd->list, &parent->neigh_add_list);

	/* calls neigh_learn_task() */
	queue_delayed_work(parent->wq, &parent->neigh_learn_work, 0);

out:
	return rc;
}

static void neigh_learn_task(struct work_struct *work)
{
	struct parent *parent = container_of(work, struct parent,
					     neigh_learn_work.work);
	struct neigh *neigh_cmd, *neigh_cmd_tmp;

	write_lock(&parent->lock);

	if (parent->kill_timers)
		goto out;

	list_for_each_entry_safe(neigh_cmd, neigh_cmd_tmp,
				 &parent->neigh_add_list, list) {
		__parent_store_neighs(&parent->dev->dev, NULL,
				      neigh_cmd->cmd, PAGE_SIZE);
		list_del(&neigh_cmd->list);
		kfree(neigh_cmd);
	}

out:
	write_unlock(&parent->lock);
	return;
}

static void parent_work_cancel_all(struct parent *parent)
{
	write_lock(&parent->lock);
	parent->kill_timers = 1;
	write_unlock(&parent->lock);

	if (delayed_work_pending(&parent->neigh_learn_work))
		cancel_delayed_work(&parent->neigh_learn_work);

	if (delayed_work_pending(&parent->arp_gen_work))
		cancel_delayed_work(&parent->arp_gen_work);
}

static struct parent *get_parent_by_pif_name(char *pif_name)
{
	struct parent *parent, *nxt;

	list_for_each_entry_safe(parent, nxt, &parent_dev_list, parent_list) {
		if (!strcmp(parent->ipoib_main_interface, pif_name))
			return parent;
	}
	return NULL;
}

static void free_emac_info_rec(struct guest_emac_info *emac_info)
{
	free_all_ip_ent_in_emac_rec(emac_info);
	list_del(&emac_info->list);
	kfree(emac_info);
}

void free_ip_ent_in_emac_rec(struct parent *parent, u8 *emac, u16 vlan,
			     __be32 ip)
{
	struct guest_emac_info *emac_info;
	struct ip_member *ipm, *tmp_ipm;

	write_lock(&parent->emac_info_lock);
	emac_info = get_mac_ip_info_by_mac_and_vlan(parent, emac, vlan);

	if (!emac_info) {
		write_unlock(&parent->emac_info_lock);
		return;
	}

	list_for_each_entry_safe(ipm, tmp_ipm, &emac_info->ip_list, list) {
		if (ipm->ip == ip) {
			list_del(&ipm->list);
			kfree(ipm);
		}
	}
	/* if no more records, delete that entry.*/
	if (list_empty(&emac_info->ip_list))
		free_emac_info_rec(emac_info);

	write_unlock(&parent->emac_info_lock);

}

static void free_all_ip_ent_in_emac_rec(struct guest_emac_info *emac_info)
{
	struct ip_member *ipm, *tmp_ipm;
	list_for_each_entry_safe(ipm, tmp_ipm, &emac_info->ip_list, list) {
		list_del(&ipm->list);
		kfree(ipm);
	}
}

/* assume: the lock parent->emac_info_lock is held.*/
static void update_emac_info_ip_list(struct guest_emac_info *emac_info,
				     enum eipoib_served_ip_state state)
{
	struct ip_member *ipm;

	list_for_each_entry(ipm, &emac_info->ip_list, list) {
		ipm->state = state;
	}
}

/* assume: the lock parent->emac_info_lock is held.*/
static int gen_grat_arp_req(struct parent *parent, u8 *emac,
			    u16 vlan)
{
	struct guest_emac_info *emac_info;
	struct ip_member *ipm;
	struct slave *slave;
	struct sk_buff *nskb;
	int ret = 0;
	u8 t_addr[ETH_ALEN] = {0};

	slave = get_slave_by_mac_and_vlan(parent, emac, vlan);
	if (unlikely(!slave)) {
		pr_warn("%s: Failed to find parent slave !!! %pM\n",
			__func__, emac);
		return -ENODEV;
	}

	emac_info = get_mac_ip_info_by_mac_and_vlan(parent, emac, vlan);

	if (!emac_info)
		return 0;

	/* go over all ip's attached to that mac */
	list_for_each_entry(ipm, &emac_info->ip_list, list) {
		if (ipm->state == IP_NEW) {
			/* create and send arp request to that ip.*/
			pr_info("%s: dev: %s Sending gratuitous arp, for %pI4\n",
				__func__, slave->dev->name, &(ipm->ip));
			/* create gratuitous ARP on behalf of the guest */
			nskb = arp_create(ARPOP_REQUEST,
					  ETH_P_ARP,
					  ipm->ip,
					  slave->dev,
					  ipm->ip,
					  NULL,
					  slave->dev->dev_addr,
					  t_addr);
			if (likely(nskb)) {
				arp_xmit(nskb);
			} else {
				pr_err("%s: %s failed creating skb\n",
				       __func__, slave->dev->name);
				ret = -ENOMEM;
			}
		}
	}
	return ret;
}

static int migrate_out_gen_arp_req(struct parent *parent, u8 *emac,
				   u16 vlan)
{
	struct guest_emac_info *emac_info;
	struct ip_member *ipm;
	struct slave *slave;
	struct sk_buff *nskb;
	int ret = 0;

	slave = get_slave_by_mac_and_vlan(parent, parent->dev->dev_addr, vlan);
	if (unlikely(!slave)) {
		pr_info("%s: Failed to find parent slave !!! %pM\n",
			__func__, parent->dev->dev_addr);
		return -ENODEV;
	}

	emac_info = get_mac_ip_info_by_mac_and_vlan(parent, emac, vlan);

	if (!emac_info)
		return 0;

	/* go over all ip's attached to that mac */
	list_for_each_entry(ipm, &emac_info->ip_list, list) {
		/* create and send arp request to that ip.*/
		pr_info("%s: Sending arp For migrate_out event, to %pI4 "
			"from 0.0.0.0\n", parent->dev->name, &(ipm->ip));

		nskb = arp_create(ARPOP_REQUEST,
				  ETH_P_ARP,
				  ipm->ip,
				  slave->dev,
				  0,
				  slave->dev->broadcast,
				  slave->dev->broadcast,
				  slave->dev->broadcast);
		if (nskb) {
			arp_xmit(nskb);
		}
		else {
			pr_err("%s: %s failed creating skb\n",
			       __func__, slave->dev->name);
			ret = -ENOMEM;
		}
	}
	return ret;
}

static void arp_gen_work_task(struct work_struct *work)
{
	struct parent *parent = container_of(work, struct parent,
					     arp_gen_work.work);
	struct guest_emac_info *emac_info, *next_emac_info;
	int is_reschedule = 0;
	int ret;

	write_lock(&parent->lock);
	if (parent->kill_timers)
		goto out;

	write_lock(&parent->emac_info_lock);
	list_for_each_entry_safe(emac_info, next_emac_info, &parent->emac_ip_list, list) {
		if (emac_info->rec_state == MIGRATED_OUT) {
			if (emac_info->num_of_retries > 0) {
				ret = migrate_out_gen_arp_req(parent, emac_info->emac,
							      emac_info->vlan);
				if (ret)
					pr_err("%s: migrate_out_gen_arp failed: %d\n",
					       __func__, ret);

				emac_info->num_of_retries =
					emac_info->num_of_retries - 1;
				is_reschedule = 1;
			} else {
				/* Delete it. */
				free_emac_info_rec(emac_info);
			}
		} else if (emac_info->rec_state == NEW) {
			if (emac_info->num_of_retries > 0) {
				/* generate gart arp for it */
				ret = gen_grat_arp_req(parent, emac_info->emac,
						       emac_info->vlan);
				if (ret)
					pr_err("%s: gen_gart_arp_req failed: %d\n",
					       __func__, ret);
				emac_info->num_of_retries =
					emac_info->num_of_retries - 1;
				is_reschedule = 1;
			} else {
				emac_info->rec_state = VALID;
				/*mark all ips at that record as updated.*/
				update_emac_info_ip_list(emac_info, IP_VALID);
			}
		}
	}
	/* issue arp request till the device removed that entry from list */
	if (is_reschedule)
		queue_delayed_work(parent->wq, &parent->arp_gen_work,
				   GEN_ARP_REQ_ISSUE_TIME);

	write_unlock(&parent->emac_info_lock);
out:
	write_unlock(&parent->lock);
	return;
}

inline int add_emac_ip_info(struct net_device *parent_dev, __be32 ip,
			    u8 *mac, u16 vlan, gfp_t mem_flag)
{
	struct parent *parent = netdev_priv(parent_dev);
	struct slave *slave;
	struct guest_emac_info *emac_info = NULL;
	struct ip_member *ipm;
	int ret;
	int is_just_alloc_emac_info = 0;

	/* check if exists such slave at all */
	slave = get_slave_by_mac_and_vlan(parent, mac, vlan);
	if (unlikely(!slave)) {
		pr_warn("%s: No slave (mac: %pM vlan: %d)\n",
			__func__, mac, vlan);
		return -ENXIO;
	}

	read_lock(&parent->emac_info_lock);
	ret = is_mac_info_contain_new_ip(parent, mac, ip, emac_info, vlan);
	if (ret) {
		read_unlock(&parent->emac_info_lock);
		return 0;
	}

	emac_info = get_mac_ip_info_by_mac_and_vlan(parent, mac, vlan);
	read_unlock(&parent->emac_info_lock);

	/* new ip add it to the emc_ip obj */
	if (!emac_info) {
		emac_info = kzalloc(sizeof(*emac_info), mem_flag);
		if (!emac_info) {
			pr_err("%s: Failed allocating emac_info\n",
			       parent_dev->name);
			return -ENOMEM;
		}
		strcpy(emac_info->ifname, slave->dev->name);
		memcpy(emac_info->emac, mac, ETH_ALEN);
		INIT_LIST_HEAD(&emac_info->ip_list);
		emac_info->vlan = vlan;
		is_just_alloc_emac_info = 1;
		pr_info("%s: slave:%s new emac_info for mac: %pM, vlan: %d, ip: %pI4\n",
			__func__, slave->dev->name, mac, vlan, &ip);
	}

	ipm = kzalloc(sizeof(*ipm), mem_flag);
	if (!ipm) {
		pr_err(" %s Failed allocating emac_info (ipm)\n",
		       parent_dev->name);
		if (is_just_alloc_emac_info)
			kfree(emac_info);
		return -ENOMEM;
	}

	ipm->ip = ip;
	ipm->state = IP_NEW;

	write_lock(&parent->emac_info_lock);

	list_add_tail(&ipm->list, &emac_info->ip_list);
	/* force gart-arp announce */
	emac_info->rec_state = NEW;
	emac_info->num_of_retries = GRAT_ARP_MAX_RETRIES;

	if (is_just_alloc_emac_info)
		list_add_tail(&emac_info->list, &parent->emac_ip_list);

	write_unlock(&parent->emac_info_lock);

	/* send gart arp to the world.*/
	queue_delayed_work(parent->wq, &parent->arp_gen_work, 0);

	return 0;
}

/* build ipoib arp/rarp request/reply packet */
static struct sk_buff *get_slave_skb_arp(struct slave *slave,
					 struct sk_buff *skb,
					 u8 *rimac, int *ret)
{
	struct sk_buff *nskb;
	struct arphdr *arphdr = (struct arphdr *)
				(skb->data + sizeof(struct ethhdr));
	struct eth_arp_data *arp_data = (struct eth_arp_data *)
					(skb->data + sizeof(struct ethhdr) +
					 sizeof(struct arphdr));
	u8 t_addr[ETH_ALEN] = {0};
	int err = 0;
	/* mark regular packet handling */
	*ret = 0;

	/*
	 * live-migration support: keeps the new mac/ip address:
	 * In that way each driver knows which mac/vlan - IP's where on the
	 * guests above, whenever migrate_out event comes it will send
	 * arp request for all these IP's.
	 */
	if (skb->protocol == htons(ETH_P_ARP))
		err = add_emac_ip_info(slave->dev->master, arp_data->arp_sip,
				       arp_data->arp_sha, slave->vlan, GFP_ATOMIC);
	if (err)
		pr_warn("%s: Failed creating: emac_ip_info for ip: %pI4",
			__func__, &arp_data->arp_sip);
	/*
	 * live migration support:
	 * 1.checck if we are in live migration process
	 * 2.check if the arp response is for the parent
	 * 3.ignore local-administrated bit, which was set to make sure
	 *   that the bridge will not drop it.
	 */
	arp_data->arp_dha[0] = arp_data->arp_dha[0] & 0xFD;
	if (htons(ARPOP_REPLY) == (arphdr->ar_op) &&
	    !memcmp(arp_data->arp_dha, slave->dev->master->dev_addr, ETH_ALEN)) {
		/*
		 * when the source is the parent interface, assumes
		 * that we are in the middle of live migration process,
		 * so, we will send gratuitous arp.
		 */
		pr_info("%s: Arp packet for parent: %s",
			__func__, slave->dev->master->name);
		/* create gratuitous ARP on behalf of the guest */
		nskb = arp_create(ARPOP_REQUEST,
				  be16_to_cpu(skb->protocol),
				  arp_data->arp_sip,
				  slave->dev,
				  arp_data->arp_sip,
				  NULL,
				  slave->dev->dev_addr,
				  t_addr);
		if (unlikely(!nskb))
			pr_err("%s: %s live migration: failed creating skb\n",
			       __func__, slave->dev->name);
	} else {
		nskb = arp_create(be16_to_cpu(arphdr->ar_op),
				  be16_to_cpu(skb->protocol),
				  arp_data->arp_dip,
				  slave->dev,
				  arp_data->arp_sip,
				  rimac,
				  slave->dev->dev_addr,
				  NULL);
	}

	return nskb;
}

/*
 * build ipoib arp request packet according to ip header.
 * uses for live-migration, or missing neigh for new vif.
 */
static void get_slave_skb_arp_by_ip(struct slave *slave,
				    struct sk_buff *skb)
{
	struct sk_buff *nskb = NULL;
	struct iphdr *iph = ip_hdr(skb);
	struct ethhdr *ethh = (struct ethhdr *)(skb->data);

	pr_info("Sending arp on behalf of slave %s, from %pI4"
		" to %pI4" , slave->dev->name, &(iph->saddr),
		&(iph->daddr));

	nskb = arp_create(ARPOP_REQUEST,
			  ETH_P_ARP,
			  iph->daddr,
			  slave->dev,
			  iph->saddr,
			  slave->dev->broadcast,
			  slave->dev->dev_addr,
			  NULL);
	if (nskb)
		arp_xmit(nskb);
	else
		pr_err("%s: %s failed creating skb\n",
		       __func__, slave->dev->name);

	/* add new source IP as served via the driver. */
	if (add_emac_ip_info(slave->dev->master, iph->saddr, ethh->h_source,
			     slave->vlan, GFP_ATOMIC))
		pr_warn("%s: Failed creating: emac_ip_info for ip: %pI4 mac: %pM",
			__func__, &iph->saddr, ethh->h_source);

}

/* build ipoib ipv4/ipv6 packet */
static struct sk_buff *get_slave_skb_ip(struct slave *slave,
					struct sk_buff *skb)
{

	skb_pull(skb, ETH_HLEN);
	skb_reset_network_header(skb);

	return skb;
}

/*
 * get_slave_skb -- called in TX flow
 * get skb that can be sent thru slave xmit func,
 * if skb was adjusted (cloned, pulled, etc..) successfully
 * the old skb (if any) is freed here.
 */
static struct sk_buff *get_slave_skb(struct slave *slave, struct sk_buff *skb)
{
	struct net_device *dev = slave->dev;
	struct net_device *parent_dev = dev->master;
	struct parent *parent = netdev_priv(parent_dev);
	struct sk_buff *nskb = NULL;
	struct ethhdr *ethh = (struct ethhdr *)(skb->data);
	struct neigh *neigh = NULL;
	u8 rimac[INFINIBAND_ALEN];
	int ret = 0;

	/* set neigh mac */
	if (is_multicast_ether_addr(ethh->h_dest)) {
		memcpy(rimac, dev->broadcast, INFINIBAND_ALEN);
	} else {
		neigh = neigh_find_by_mac(slave, ethh->h_dest);
		if (neigh) {
			memcpy(rimac, neigh->imac, INFINIBAND_ALEN);
		} else {
			++parent->port_stats.tx_neigh_miss;
			/*
			 * assume VIF migration, tries to get the neigh by
			 * issue arp request on behalf of the vif.
			 */
			if (skb->protocol == htons(ETH_P_IP)) {
				pr_info("Missed neigh for slave: %s,"
					"issue ARP request\n",
					slave->dev->name);
				get_slave_skb_arp_by_ip(slave, skb);
				goto out_arp_sent_instead;
			}
		}
	}

	if (skb->protocol == htons(ETH_P_ARP) ||
	    skb->protocol == htons(ETH_P_RARP)) {
		nskb = get_slave_skb_arp(slave, skb, rimac, &ret);
		if (!nskb && LIVE_MIG_PACKET == ret) {
			pr_info("%s: live migration packets\n", __func__);
			goto err;
		}
	} else {
		if (!neigh)
			goto err;
		/* pull ethernet header here */
		nskb = get_slave_skb_ip(slave, skb);
	}

	/* if new skb could not be adjusted/allocated, abort */
	if (!nskb) {
		pr_err("%s get_slave_skb_ip/arp failed 0x%x\n",
		       dev->name, skb->protocol);
		goto err;
	}

	if (neigh && nskb == skb) { /* ucast & non-arp/rarp */
		/* dev_hard_header only for ucast, for arp done already.*/
		if (dev_hard_header(nskb, dev, ntohs(skb->protocol), rimac,
				    dev->dev_addr, nskb->len) < 0) {
			pr_warn("%s: dev_hard_header failed\n",
				dev->name);
			goto err;
		}
	}

	/*
	 * new skb is ready to be sent, clean old skb if we hold a clone
	 * (old skb is not shared, already checked that.)
	 */
	if ((nskb != skb))
		dev_kfree_skb(skb);

	nskb->dev = slave->dev;
	return nskb;

out_arp_sent_instead:/* whenever sent arp instead of ip packet */
err:
	/* got error after nskb was adjusted/allocated */
	if (nskb && (nskb != skb))
		dev_kfree_skb(nskb);

	return NULL;
}

static struct sk_buff *get_parent_skb_arp(struct slave *slave,
					  struct sk_buff *skb,
					  u8 *remac)
{
	struct net_device *dev = slave->dev->master;
	struct sk_buff *nskb;
	struct arphdr *arphdr = (struct arphdr *)(skb->data);
	struct ipoib_arp_data *arp_data = (struct ipoib_arp_data *)
					(skb->data + sizeof(struct arphdr));
	u8 *target_hw = slave->emac;
	u8 *dst_hw = slave->emac;
	u8 local_eth_addr[ETH_ALEN];

	/* live migration: gets arp with broadcast src and dst */
	if (!memcmp(arp_data->arp_sha, slave->dev->broadcast, INFINIBAND_ALEN) &&
	    !memcmp(arp_data->arp_dha, slave->dev->broadcast, INFINIBAND_ALEN)) {
		pr_info("%s: ARP with bcast src and dest send from src_hw: %pM\n",
			__func__, slave->dev->master->dev_addr);
		/* replace the src with the parent src: */
		memcpy(local_eth_addr, slave->dev->master->dev_addr, ETH_ALEN);
		/*
		 * set local administrated bit,
		 * that way the bridge will not throws it
		 */
		local_eth_addr[0] = local_eth_addr[0] | 0x2;
		memcpy(remac, local_eth_addr, ETH_ALEN);
		target_hw = NULL;
		dst_hw = NULL;
	}

	nskb = arp_create(be16_to_cpu(arphdr->ar_op),
			  be16_to_cpu(skb->protocol),
			  arp_data->arp_dip,
			  dev,
			  arp_data->arp_sip,
			  dst_hw,
			  remac,
			  target_hw);

	/* prepare place for the headers. */
	if (nskb)
		skb_reserve(nskb, ETH_HLEN);

	return nskb;
}

static struct sk_buff *get_parent_skb_ip(struct slave *slave,
					 struct sk_buff *skb)
{
	/* nop */
	return skb;
}

/* get_parent_skb -- called in RX flow */
static struct sk_buff *get_parent_skb(struct slave *slave,
				      struct sk_buff *skb, u8 *remac)
{
	struct net_device *dev = slave->dev->master;
	struct sk_buff *nskb = NULL;
	struct ethhdr *ethh;

	if (skb->protocol == htons(ETH_P_ARP) ||
	    skb->protocol == htons(ETH_P_RARP))
		nskb = get_parent_skb_arp(slave, skb, remac);
	else
		nskb = get_parent_skb_ip(slave, skb);

	/* if new skb could not be adjusted/allocated, abort */
	if (!nskb)
		goto err;

	/* at this point, we can free old skb if it was cloned */
	if (nskb && (nskb != skb))
		dev_kfree_skb(skb);

	skb = nskb;

	/* build ethernet header */
	ethh = (struct ethhdr *)skb_push(skb, ETH_HLEN);
	ethh->h_proto = skb->protocol;
	memcpy(ethh->h_source, remac, ETH_ALEN);
	memcpy(ethh->h_dest, slave->emac, ETH_ALEN);

	/* zero padding whenever is needed (arp for example).to ETH_ZLEN size */
	if (unlikely((skb->len < ETH_ZLEN))) {
		if ((skb->tail + (ETH_ZLEN - skb->len) > skb->end) ||
		    skb_is_nonlinear(skb))
			/* nothing */;
		else
			memset(skb_put(skb, ETH_ZLEN - skb->len), 0,
			       ETH_ZLEN - skb->len);
	}

	/* set new skb fields */
	skb->pkt_type = PACKET_HOST;
	/*
	 * use master dev, to allow netpoll_receive_skb()
	 * in netif_receive_skb()
	 */
	skb->dev = dev;

	/* pull the Ethernet header and update other fields */
	skb->protocol = eth_type_trans(skb, skb->dev);

	return skb;

err:
	/* got error after nskb was adjusted/allocated */
	if (nskb && (nskb != skb))
		dev_kfree_skb(nskb);

	return NULL;
}

static int parent_rx(struct sk_buff *skb, struct slave *slave)
{
	struct net_device *slave_dev = skb->dev;
	struct net_device *parent_dev = slave_dev->master;
	struct parent *parent = netdev_priv(parent_dev);
	struct eipoib_cb_data *data = IPOIB_HANDLER_CB(skb);
	struct napi_struct *napi =  data->rx.napi;
	struct sk_buff *nskb;
	int rc = 0;
	u8 remac[ETH_ALEN];
	int vlan_tag;

	build_neigh_mac(remac, data->rx.sqpn, data->rx.slid);

	read_lock(&parent->lock);

	if (unlikely(skb_headroom(skb) < ETH_HLEN)) {
		pr_warn("%s: small headroom %d < %d\n",
			skb->dev->name, skb_headroom(skb), ETH_HLEN);
		++parent->port_stats.rx_skb_errors;
		goto drop;
	}

	/* learn neighs based on ARP snooping */
	if (unlikely(ntohs(skb->protocol) == ETH_P_ARP)) {
		read_unlock(&parent->lock);
		write_lock(&parent->lock);
		neigh_learn(slave, skb, remac);
		write_unlock(&parent->lock);
		read_lock(&parent->lock);
	}

	nskb = get_parent_skb(slave, skb, remac);
	if (unlikely(!nskb)) {
		++parent->port_stats.rx_skb_errors;
		pr_warn("%s: failed to create parent_skb\n",
			skb->dev->name);
		goto drop;
	} else
		skb = nskb;

	vlan_tag = slave->vlan & 0xfff;
	if (vlan_tag) {
		skb = __vlan_hwaccel_put_tag(skb, vlan_tag);
		if (!skb) {
			pr_err("%s failed to insert VLAN tag\n",
			       skb->dev->name);
			goto drop;
		}
		++parent->port_stats.rx_vlan;
	}

	if (napi)
		rc = napi_gro_receive(napi, skb);
	else
		rc = netif_receive_skb(skb);

	read_unlock(&parent->lock);

	return rc;

drop:
	dev_kfree_skb_any(skb);
	read_unlock(&parent->lock);

	return NET_RX_DROP;
}

static rx_handler_result_t eipoib_handle_frame(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct slave *slave;

	slave = eipoib_slave_get_rcu(skb->dev);

	parent_rx(skb, slave);

	return RX_HANDLER_CONSUMED;
}

static netdev_tx_t parent_tx(struct sk_buff *skb, struct net_device *dev)
{
	struct parent *parent = netdev_priv(dev);
	struct slave *slave = NULL;
	struct ethhdr *ethh = (struct ethhdr *)(skb->data);
	struct sk_buff *nskb;
	int rc;
	u16 vlan;
	u8 mac_no_admin_bit[ETH_ALEN];

	read_lock(&parent->lock);

	if (unlikely(!IS_E_IPOIB_PROTO(ethh->h_proto))) {
		++parent->port_stats.tx_proto_errors;
		goto drop;
	}
	/* assume: only orphan skb's */
	if (unlikely(skb_shared(skb))) {
		++parent->port_stats.tx_shared;
		goto drop;
	}

	/* obtain VLAN information if present */
	if (vlan_tx_tag_present(skb)) {
		vlan = vlan_tx_tag_get(skb) & 0xfff;
		++parent->port_stats.tx_vlan;
	} else {
		vlan = VLAN_N_VID;
	}

	/*
	 * for live migration: mask the admin bit if exists.
	 * only in ARP packets that came from parent's VIF interface.
	 */
	if (unlikely((htons(ETH_P_ARP) == ethh->h_proto) &&
	    !memcmp(parent->dev->dev_addr + 1, ethh->h_source + 1, ETH_ALEN - 1))) {
		/* parent's VIF: */
		memcpy(mac_no_admin_bit, ethh->h_source, ETH_ALEN);
		mac_no_admin_bit[0] = mac_no_admin_bit[0] & 0xFD;
		/* get slave, and queue packet */
		slave = get_slave_by_mac_and_vlan(parent, mac_no_admin_bit, vlan);
	}
	/* get slave, and queue packet */
	if (!slave)
		slave = get_slave_by_mac_and_vlan(parent, ethh->h_source, vlan);
	if (unlikely(!slave)) {
		pr_info("vif: %pM with vlan: %d miss for parent: %s\n",
			ethh->h_source, vlan, parent->ipoib_main_interface);
		++parent->port_stats.tx_vif_miss;
		goto drop;
	}

	nskb = get_slave_skb(slave, skb);
	if (unlikely(!nskb)) {
		++parent->port_stats.tx_skb_errors;
		goto drop;
	} else
		skb = nskb;

	/*
	 * VST mode: removes the vlan tag in the tx (will add it in the rx)
	 * the slave is from IPoIB and it is NETIF_F_VLAN_CHALLENGED,
	 * so must remove the vlan tag.
	 */
	if (vlan != VLAN_N_VID)
		skb->vlan_tci = 0;

	/* arp packets: */
	if (skb->protocol == htons(ETH_P_ARP) ||
	    skb->protocol == htons(ETH_P_RARP)) {
		arp_xmit(skb);
		goto out;
	}

	/* ip packets */
	skb_record_rx_queue(skb, skb_get_queue_mapping(skb));

	rc = dev_queue_xmit(skb);
	if (unlikely(rc)) {
		pr_err("slave tx method failed %d\n", rc);
		++parent->port_stats.tx_slave_err;
		dev_kfree_skb(skb);
	}

	goto out;

drop:
	++parent->port_stats.tx_parent_dropped;
	dev_kfree_skb(skb);

out:
	read_unlock(&parent->lock);
	return NETDEV_TX_OK;
}

static int parent_open(struct net_device *parent_dev)
{
	struct parent *parent = netdev_priv(parent_dev);

	parent->kill_timers = 0;
	INIT_DELAYED_WORK(&parent->neigh_learn_work, neigh_learn_task);
	INIT_DELAYED_WORK(&parent->arp_gen_work, arp_gen_work_task);
	return 0;
}

static int parent_close(struct net_device *parent_dev)
{
	struct parent *parent = netdev_priv(parent_dev);

	write_lock(&parent->lock);
	parent->kill_timers = 1;
	write_unlock(&parent->lock);

	cancel_delayed_work_sync(&parent->neigh_learn_work);
	cancel_delayed_work_sync(&parent->arp_gen_work);

	return 0;
}


static void parent_deinit(struct net_device *parent_dev)
{
	struct parent *parent = netdev_priv(parent_dev);

	list_del(&parent->parent_list);

	parent_work_cancel_all(parent);
}

static void parent_uninit(struct net_device *parent_dev)
{
	struct parent *parent = netdev_priv(parent_dev);

	parent_deinit(parent_dev);
	parent_destroy_sysfs_entry(parent);

	if (parent->wq)
		destroy_workqueue(parent->wq);
}

static struct lock_class_key parent_netdev_xmit_lock_key;
static struct lock_class_key parent_netdev_addr_lock_key;

static void parent_set_lockdep_class_one(struct net_device *dev,
					 struct netdev_queue *txq,
					 void *_unused)
{
	lockdep_set_class(&txq->_xmit_lock,
			  &parent_netdev_xmit_lock_key);
}

static void parent_set_lockdep_class(struct net_device *dev)
{
	lockdep_set_class(&dev->addr_list_lock,
			  &parent_netdev_addr_lock_key);
	netdev_for_each_tx_queue(dev, parent_set_lockdep_class_one, NULL);
}

static int parent_init(struct net_device *parent_dev)
{
	struct parent *parent = netdev_priv(parent_dev);

	parent->wq = create_singlethread_workqueue(parent_dev->name);
	if (!parent->wq)
		return -ENOMEM;

	parent_set_lockdep_class(parent_dev);

	list_add_tail(&parent->parent_list, &parent_dev_list);

	return 0;
}

static u16 parent_select_q(struct net_device *dev, struct sk_buff *skb)
{
	return skb_tx_hash(dev, skb);
}

int parent_add_vif_param(struct net_device *parent_dev,
			 struct net_device *new_vif_dev,
			 u16 vlan, u8 *mac)
{
	struct parent *parent = netdev_priv(parent_dev);
	struct slave *new_slave, *slave_tmp;
	int ret = 0;

	if (!is_valid_ether_addr(mac)) {
		pr_err("Invalid mac input for slave:%pM \n", mac);
		return -EINVAL;
	}

	write_lock(&parent->lock);

	new_slave = get_slave_by_dev(parent, new_vif_dev);
	if (!new_slave) {
		pr_err("%s: ERROR no slave:%s.!!!! \n",
		       __func__, new_vif_dev->name);
		ret = -EINVAL;
		goto out;
	}

	if (!is_zero_ether_addr(new_slave->emac)) {
		pr_err("slave %s mac already set to %pM\n",
		       new_slave->dev->name, new_slave->emac);
		ret = -EINVAL;
		goto out;
	}

	/* check another slave has this mac/vlan */
	parent_for_each_slave(parent, slave_tmp) {
		if (!memcmp(slave_tmp->emac, mac, ETH_ALEN) &&
		    slave_tmp->vlan == new_slave->vlan) {
			pr_err("cannot update %s, slave %s already has"
			       " vlan 0x%x mac %pM\n",
			       parent->dev->name, new_slave->dev->name,
			       slave_tmp->vlan,
			       mac);
			ret = -EINVAL;
			goto out;
		}
	}

	/* ready to go */
	pr_info("slave %s mac is set to %pM, vlan set to: %d\n",
		new_slave->dev->name, mac, vlan);

	memcpy(new_slave->emac, mac, ETH_ALEN);

	new_slave->vlan = vlan;

out:
	write_unlock(&parent->lock);

	return ret;
}

static const struct net_device_ops parent_netdev_ops = {
	.ndo_init		= parent_init,
	.ndo_uninit		= parent_uninit,
	.ndo_open		= parent_open,
	.ndo_stop		= parent_close,
	.ndo_start_xmit		= parent_tx,
	.ndo_select_queue	= parent_select_q,
	/* parnt mtu is min(slaves_mtus) */
	.ndo_change_mtu		= NULL,
	.ndo_fix_features	= parent_fix_features,
	/*
	 * initial mac address is randomized, can be changed
	 * thru this func later
	 */
	.ndo_set_mac_address = eth_mac_addr,
	.ndo_get_stats64 = parent_get_stats,
	.ndo_add_slave = parent_enslave,
	.ndo_del_slave = parent_release_slave,
};

static void parent_setup(struct net_device *parent_dev)
{
	struct parent *parent = netdev_priv(parent_dev);

	/* initialize rwlocks */
	rwlock_init(&parent->lock);
	rwlock_init(&parent->emac_info_lock);
	/* Initialize pointers */
	parent->dev = parent_dev;
	INIT_LIST_HEAD(&parent->neigh_add_list);
	INIT_LIST_HEAD(&parent->slave_list);
	INIT_LIST_HEAD(&parent->emac_ip_list);
	/* Initialize the device entry points */
	ether_setup(parent_dev);
	/* parent_dev->hard_header_len is adjusted later */
	parent_dev->netdev_ops = &parent_netdev_ops;
	parent_set_ethtool_ops(parent_dev);

	/* Initialize the device options */
	parent_dev->tx_queue_len = 0;
	/* mark the parent intf as pif (master of other vifs.) */
	parent_dev->priv_flags = IFF_EIPOIB_PIF;

	parent_dev->hw_features = NETIF_F_SG | NETIF_F_IP_CSUM |
		NETIF_F_RXCSUM | NETIF_F_GRO | NETIF_F_TSO;

	parent_dev->features = parent_dev->hw_features;
	parent_dev->vlan_features = parent_dev->hw_features;

	parent_dev->features |= PARENT_VLAN_FEATURES;
}

/*
 * Create a new parent based on the specified name and parent parameters.
 * Caller must NOT hold rtnl_lock; we need to release it here before we
 * set up our sysfs entries.
 */
static struct parent *parent_create(struct net_device *ibd)
{
	struct net_device *parent_dev;
	u32 num_queues;
	int rc;
	union ib_gid gid;
	struct parent *parent = NULL;
	int i, j;

	memcpy(&gid, ibd->dev_addr + 4, sizeof(union ib_gid));
	num_queues = num_online_cpus();
	num_queues = roundup_pow_of_two(num_queues);

	parent_dev = alloc_netdev_mq(sizeof(struct parent), "",
				     parent_setup, num_queues);
	if (!parent_dev) {
		pr_err("%s failed to alloc netdev!\n", ibd->name);
		rc = -ENOMEM;
		goto out_rtnl;
	}

	rc = dev_alloc_name(parent_dev, "eth%d");
	if (rc < 0)
		goto out_netdev;

	/* eIPoIB interface mac format. */
	for (i = 0, j = 0; i < 8; i++) {
		if ((PARENT_MAC_MASK >> i) & 0x1) {
			if (j < 6) /* only 6 bytes eth address */
				parent_dev->dev_addr[j] =
					gid.raw[GUID_LEN + i];
			j++;
		}
	}

	/* assuming that the ibd->dev.parent was alreadey been set. */
	SET_NETDEV_DEV(parent_dev, ibd->dev.parent);

	rc = register_netdevice(parent_dev);
	if (rc < 0)
		goto out_parent;

	dev_net_set(parent_dev, &init_net);

	rc = parent_create_sysfs_entry(netdev_priv(parent_dev));
	if (rc < 0)
		goto out_unreg;

	parent = netdev_priv(parent_dev);
	memcpy(parent->gid.raw, gid.raw, GID_LEN);
	strncpy(parent->ipoib_main_interface, ibd->name, IFNAMSIZ);
	parent_dev->dev_id = ibd->dev_id;

	return parent;

out_unreg:
	unregister_netdevice(parent_dev);
out_parent:
	parent_deinit(parent_dev);
out_netdev:
	free_netdev(parent_dev);
out_rtnl:
	return ERR_PTR(rc);
}


static void parent_free(struct parent *parent)
{
	struct net_device *parent_dev = parent->dev;

	parent_work_cancel_all(parent);

	parent_release_all(parent_dev);

	unregister_netdevice(parent_dev);
}

static void parent_free_all(void)
{
	struct parent *parent, *nxt;

	list_for_each_entry_safe(parent, nxt, &parent_dev_list, parent_list)
		parent_free(parent);
}

/* netdev events handlers */
static inline int is_ipoib_pif_intf(struct net_device *dev)
{
	if (ARPHRD_INFINIBAND == dev->type && dev->priv_flags & IFF_EIPOIB_PIF)
		return 1;
	return 0;
}

static int parent_event_changename(struct parent *parent)
{
	parent_destroy_sysfs_entry(parent);

	parent_create_sysfs_entry(parent);

	return NOTIFY_DONE;
}

static int parent_master_netdev_event(unsigned long event,
				      struct net_device *parent_dev)
{
	struct parent *event_parent = netdev_priv(parent_dev);

	switch (event) {
	case NETDEV_CHANGENAME:
		pr_info("%s: got NETDEV_CHANGENAME event", parent_dev->name);
		return parent_event_changename(event_parent);
	default:
		break;
	}

	return NOTIFY_DONE;
}

static int parent_slave_netdev_event(unsigned long event,
				     struct net_device *slave_dev)
{
	struct net_device *parent_dev = slave_dev->master;
	struct parent *parent = netdev_priv(parent_dev);

	if (!parent_dev) {
		pr_err("slave:%s has no parent.\n", slave_dev->name);
		return NOTIFY_DONE;
	}

	switch (event) {
	case NETDEV_UNREGISTER:
		parent_release_slave(parent_dev, slave_dev);
		break;
	case NETDEV_CHANGE:
	case NETDEV_UP:
	case NETDEV_DOWN:
		parent_set_carrier(parent);
		break;
	case NETDEV_CHANGEMTU:
		parent_set_mtu(parent);
		break;
	case NETDEV_CHANGENAME:
		break;
	case NETDEV_FEAT_CHANGE:
		parent_compute_features(parent);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

static int eipoib_netdev_event(struct notifier_block *this,
			       unsigned long event, void *ptr)
{
	struct net_device *event_dev = (struct net_device *)ptr;

	if (dev_net(event_dev) != &init_net)
		return NOTIFY_DONE;

	if (is_parent(event_dev))
		return parent_master_netdev_event(event, event_dev);

	if (is_slave(event_dev))
		return parent_slave_netdev_event(event, event_dev);
	/*
	 * general network device triggers event, check if it is new
	 * ib interface that we want to enslave.
	 */
	return eipoib_device_event(this, event, ptr);
}

static struct notifier_block parent_netdev_notifier = {
	.notifier_call = eipoib_netdev_event,
};

static int eipoib_device_event(struct notifier_block *unused,
			       unsigned long event, void *ptr)
{
	struct net_device *dev = ptr;
	struct parent *parent;

	if (!is_ipoib_pif_intf(dev))
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_REGISTER:
		parent = parent_create(dev);
		if (IS_ERR(parent)) {
			pr_warn("failed to create parent for %s\n",
				dev->name);
			break;
		}
		break;
	case NETDEV_UNREGISTER:
		parent = get_parent_by_pif_name(dev->name);
		if (parent)
			parent_free(parent);
		break;
	default:
		break;
	}

	return NOTIFY_DONE;
}

static int __init mod_init(void)
{
	int rc;

	pr_info(DRV_NAME": %s", version);

	rc = register_pernet_subsys(&eipoib_net_ops);
	if (rc)
		goto out;

	rc = register_netdevice_notifier(&parent_netdev_notifier);
	if (rc) {
		pr_err("%s failed to register_netdevice_notifier, rc: 0x%x\n",
		       __func__, rc);
		goto unreg_subsys;
	}

	goto out;

unreg_subsys:
	unregister_pernet_subsys(&eipoib_net_ops);
out:
	return rc;

}

static void __exit mod_exit(void)
{
	unregister_netdevice_notifier(&parent_netdev_notifier);

	unregister_pernet_subsys(&eipoib_net_ops);

	rtnl_lock();
	parent_free_all();
	rtnl_unlock();
}

module_init(mod_init);
module_exit(mod_exit);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION);
MODULE_DESCRIPTION(DRV_DESCRIPTION ", v" DRV_VERSION);
MODULE_AUTHOR("Ali Ayoub && Erez Shitrit");
