// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU switch driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <net/switchdev.h>
#include <net/netevent.h>
#include <net/arp.h>
#include <net/route.h>
#include <linux/inetdevice.h>

#include "../otx2_reg.h"
#include "../otx2_common.h"
#include "../otx2_struct.h"
#include "../cn10k.h"
#include "sw_nb.h"
#include "sw_fdb.h"
#include "sw_fib.h"

static const char *sw_nb_cmd2str[OTX2_CMD_MAX] = {
	[OTX2_DEV_UP]  = "OTX2_DEV_UP",
	[OTX2_DEV_DOWN] = "OTX2_DEV_DOWN",
	[OTX2_DEV_CHANGE] = "OTX2_DEV_CHANGE",
	[OTX2_NEIGH_UPDATE] = "OTX2_NEIGH_UPDATE",
	[OTX2_FIB_ENTRY_REPLACE] = "OTX2_FIB_ENTRY_REPLACE",
	[OTX2_FIB_ENTRY_ADD] = "OTX2_FIB_ENTRY_ADD",
	[OTX2_FIB_ENTRY_DEL] = "OTX2_FIB_ENTRY_DEL",
	[OTX2_FIB_ENTRY_APPEND] = "OTX2_FIB_ENTRY_APPEND",
};

const char *sw_nb_get_cmd2str(int cmd)
{
	return sw_nb_cmd2str[cmd];
}
EXPORT_SYMBOL(sw_nb_get_cmd2str);

static bool sw_nb_is_cavium_dev(struct net_device *netdev)
{
	struct pci_dev *pdev;
	struct device *dev;

	dev = netdev->dev.parent;
	if (!dev)
		return false;

	pdev = container_of(dev, struct pci_dev, dev);
	if (pdev->vendor != PCI_VENDOR_ID_CAVIUM)
		return false;

	return true;
}

static int sw_nb_check_slaves(struct net_device *dev,
			      struct netdev_nested_priv *priv)
{
	if (!priv->flags)
		return 0;

	priv->flags &= sw_nb_is_cavium_dev(dev);
	return 0;
}

static bool sw_nb_is_valid_dev(struct net_device *netdev)
{
	struct netdev_nested_priv priv = { true, NULL};

	if (netif_is_bridge_master(netdev)) {
		netdev_walk_all_lower_dev(netdev, sw_nb_check_slaves, &priv);
		return priv.flags;
	}

	return sw_nb_is_cavium_dev(netdev);
}

static int sw_nb_fdb_event(struct notifier_block *unused,
			   unsigned long event, void *ptr)
{
	struct net_device *dev = switchdev_notifier_info_to_dev(ptr);
	struct switchdev_notifier_fdb_info *fdb_info = ptr;
	int rc;

	if (!sw_nb_is_valid_dev(dev))
		return NOTIFY_DONE;

	switch (event) {
	case SWITCHDEV_FDB_ADD_TO_DEVICE:
		if (fdb_info->is_local)
			break;
		rc = sw_fdb_add_to_list(dev, (u8 *)fdb_info->addr, true);
		break;

	case SWITCHDEV_FDB_DEL_TO_DEVICE:
		if (fdb_info->is_local)
			break;
		rc = sw_fdb_add_to_list(dev, (u8 *)fdb_info->addr, false);
		break;

	default:
		return NOTIFY_DONE;
	}

	return NOTIFY_DONE;
}

static struct notifier_block sw_nb_fdb = {
	.notifier_call = sw_nb_fdb_event,
};

static void __maybe_unused
sw_nb_fib_event_dump(unsigned long event, void *ptr)
{
	struct fib_entry_notifier_info *fen_info = ptr;
	struct fib_nh *fib_nh;
	struct fib_info *fi;
	int i;

	pr_info("%s:%d FIB event=%lu dst=%#x dstlen=%u type=%u\n",
		__func__, __LINE__,
		event, fen_info->dst, fen_info->dst_len,
		fen_info->type);

	fi = fen_info->fi;
	if (!fi)
		return;

	fib_nh = fi->fib_nh;
	for (i = 0; i < fi->fib_nhs; i++, fib_nh++)
		pr_info("%s:%d dev=%s saddr=%#x gw=%#x\n",
			__func__, __LINE__,
			fib_nh->fib_nh_dev->name,
			fib_nh->nh_saddr, fib_nh->fib_nh_gw4);
}

#define SWITCH_NB_FIB_EVENT_DUMP(...) \
	sw_nb_fib_event_dump(__VA_ARGS__)

static int sw_nb_fib_event_to_otx2_event(int event)
{
	switch (event) {
	case FIB_EVENT_ENTRY_REPLACE:
		return OTX2_FIB_ENTRY_REPLACE;
	case FIB_EVENT_ENTRY_ADD:
		return OTX2_FIB_ENTRY_ADD;
	case FIB_EVENT_ENTRY_DEL:
		return OTX2_FIB_ENTRY_DEL;
	default:
		break;
	}

	pr_err("Wrong FIB event %d\n", event);
	return -1;
}

static int sw_nb_fib_event(struct notifier_block *nb,
			   unsigned long event, void *ptr)
{
	struct fib_entry_notifier_info *fen_info = ptr;
	struct fib_entry *entries, *iter;
	struct net_device *dev, *pf_dev = NULL;
	struct fib_notifier_info *info = ptr;
	struct netdev_hw_addr *dev_addr;
	struct net_device *lower;
	struct list_head *lh;
	struct neighbour *neigh;
	struct fib_nh *fib_nh;
	struct fib_info *fi;
	struct otx2_nic *pf;
	u32 *haddr;
	int hcnt = 0;
	int cnt, i;

	if (info->family != AF_INET)
		return NOTIFY_DONE;

	switch (event) {
	case FIB_EVENT_ENTRY_REPLACE:
	case FIB_EVENT_ENTRY_ADD:
	case FIB_EVENT_ENTRY_DEL:
		break;
	default:
		pr_err("%s:%d Won't process FIB event %lu\n",
		       __func__, __LINE__, event);
		return NOTIFY_DONE;
	}

	/* Process only UNICAST routes add or del */
	if (fen_info->type != RTN_UNICAST)
		return NOTIFY_DONE;

	fi = fen_info->fi;
	if (!fi)
		return NOTIFY_DONE;

	if (fi->fib_nh_is_v6) {
		pr_debug("%s:%d Received v6 notification\n", __func__, __LINE__);
		return NOTIFY_DONE;
	}

	entries = kcalloc(fi->fib_nhs, sizeof(*entries), GFP_ATOMIC);
	if (!entries) {
		pr_debug("%s:%d Err to alloc memory for fib nodes\n", __func__, __LINE__);
		return NOTIFY_DONE;
	}

	haddr = kcalloc(fi->fib_nhs, sizeof(u32), GFP_ATOMIC);

	iter = entries;
	fib_nh = fi->fib_nh;
	for (i = 0; i < fi->fib_nhs; i++, fib_nh++) {
		dev = fib_nh->fib_nh_dev;

		if (!dev)
			continue;

		if (dev->type != ARPHRD_ETHER)
			continue;

		if (!sw_nb_is_valid_dev(dev))
			continue;

		iter->cmd = sw_nb_fib_event_to_otx2_event(event);
		iter->dst = fen_info->dst;
		iter->dst_len = fen_info->dst_len;
		iter->gw = htonl(fib_nh->fib_nh_gw4);

		pr_debug("%s:%d FIB route Rule cmd=%lld dst=%#x dst_len=%d gw=%#x\n",
			 __func__, __LINE__,
			 iter->cmd, iter->dst, iter->dst_len, iter->gw);

		pf_dev = dev;
		if (netif_is_bridge_master(dev))  {
			iter->bridge = 1;
			netdev_for_each_lower_dev(dev, lower, lh) {
				pf_dev = lower;
				break;
			}
		}

		pf = netdev_priv(pf_dev);
		iter->port_id = pf->pcifunc;

		if (!fib_nh->fib_nh_gw4) {
			if (iter->dst || iter->dst_len)
				iter++;

			continue;
		}
		iter->gw_valid = 1;

		if (fib_nh->nh_saddr)
			haddr[hcnt++] = fib_nh->nh_saddr;

		rcu_read_lock();
		neigh = ip_neigh_gw4(fib_nh->fib_nh_dev, fib_nh->fib_nh_gw4);
		if (!neigh) {
			rcu_read_unlock();
			iter++;
			continue;
		}

		if (is_valid_ether_addr(neigh->ha)) {
			iter->mac_valid = 1;
			ether_addr_copy(iter->mac, neigh->ha);
		}

		iter++;
		rcu_read_unlock();
	}

	cnt = iter - entries;
	if (!cnt)
		return NOTIFY_DONE;

	sw_fib_add_to_list(pf_dev, entries, cnt);

	if (!hcnt)
		return NOTIFY_DONE;

	entries = kcalloc(hcnt, sizeof(*entries), GFP_ATOMIC);
	if (!entries) {
		pr_debug("%s:%d Err to alloc memory for fib nodes\n",
			 __func__, __LINE__);
		return NOTIFY_DONE;
	}
	iter = entries;

	for (i = 0; i < hcnt; i++, iter++) {
		iter->cmd = sw_nb_fib_event_to_otx2_event(event);
		iter->dst = htonl(haddr[i]);
		iter->dst_len = 32;
		iter->mac_valid = 1;
		iter->host = 1;
		iter->port_id = pf->pcifunc;

		for_each_dev_addr(pf_dev, dev_addr) {
			ether_addr_copy(iter->mac, dev_addr->addr);
			break;
		}

		pr_debug("%s:%d FIB host  Rule cmd=%lld dst=%#x dst_len=%d gw=%#x %s\n",
			 __func__, __LINE__,
			 iter->cmd, iter->dst, iter->dst_len, iter->gw, dev->name);
	}

	sw_fib_add_to_list(pf_dev, entries, hcnt);
	kfree(haddr);
	return NOTIFY_DONE;
}

static struct notifier_block sw_nb_fib = {
	.notifier_call = sw_nb_fib_event,
};

static int sw_nb_net_event(struct notifier_block *nb,
			   unsigned long event, void *ptr)
{
	struct net_device *lower, *pf_dev;
	struct neighbour *n = ptr;
	struct fib_entry *entry;
	struct list_head *iter;
	struct otx2_nic *pf;

	switch (event) {
	case NETEVENT_NEIGH_UPDATE:
		if (n->tbl->family != AF_INET)
			break;

		if (n->tbl != &arp_tbl)
			break;

		if (!sw_nb_is_valid_dev(n->dev))
			break;

		entry = kcalloc(1, sizeof(*entry), GFP_ATOMIC);
		entry->cmd = OTX2_NEIGH_UPDATE;
		entry->dst = htonl(*(u32 *)n->primary_key);
		entry->dst_len = n->tbl->key_len * 8;
		entry->mac_valid = 1;
		entry->nud_state = n->nud_state;
		ether_addr_copy(entry->mac, n->ha);

		pf_dev = n->dev;
		if (netif_is_bridge_master(n->dev))  {
			entry->bridge = 1;
			netdev_for_each_lower_dev(n->dev, lower, iter) {
				pf_dev = lower;
				break;
			}
		}

		pf = netdev_priv(pf_dev);
		entry->port_id = pf->pcifunc;
		sw_fib_add_to_list(pf_dev, entry, 1);
		break;
	}

	return NOTIFY_DONE;
}

static struct notifier_block sw_nb_netevent = {
	.notifier_call = sw_nb_net_event,

};

static int sw_nb_inetaddr_event_to_otx2_event(int event)
{
	switch (event) {
	case NETDEV_CHANGE:
		return OTX2_DEV_CHANGE;
	case NETDEV_UP:
		return OTX2_DEV_UP;
	case NETDEV_DOWN:
		return OTX2_DEV_DOWN;
	default:
		break;
	}
	pr_err("%s:%d Wrong interaddr event %d\n", __func__, __LINE__,  event);
	return -1;
}

static int sw_nb_inetaddr_event(struct notifier_block *nb,
				unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct net_device *dev = ifa->ifa_dev->dev;
	struct net_device *lower, *pf_dev;
	struct netdev_hw_addr *dev_addr;
	struct fib_entry *entry;
	struct in_device *idev;
	struct list_head *iter;
	struct otx2_nic *pf;

	if (event != NETDEV_CHANGE &&
	    event != NETDEV_UP &&
	    event != NETDEV_DOWN) {
		return NOTIFY_DONE;
	}

	if (!sw_nb_is_valid_dev(dev))
		return NOTIFY_DONE;

	idev = __in_dev_get_rtnl(dev);
	if (!idev || !idev->ifa_list)
		return NOTIFY_DONE;

	entry = kcalloc(1, sizeof(*entry), GFP_ATOMIC);
	entry->cmd = sw_nb_inetaddr_event_to_otx2_event(event);
	entry->dst = htonl(ifa->ifa_address);
	entry->dst_len = 32;
	entry->mac_valid = 1;
	entry->host = 1;

	pf_dev = dev;
	if (netif_is_bridge_master(dev))  {
		entry->bridge = 1;
		netdev_for_each_lower_dev(dev, lower, iter) {
			pf_dev = lower;
			break;
		}
	}

	pf = netdev_priv(pf_dev);
	entry->port_id = pf->pcifunc;

	for_each_dev_addr(dev, dev_addr) {
		ether_addr_copy(entry->mac, dev_addr->addr);
		break;
	}

	pr_debug("%s:%d pushing inetaddr event from HOST interface address %#x, %pM, %s\n",
		 __func__, __LINE__,  entry->dst, entry->mac, dev->name);

	sw_fib_add_to_list(pf_dev, entry, 1);
	return NOTIFY_DONE;
}

struct notifier_block sw_nb_inetaddr = {
	.notifier_call = sw_nb_inetaddr_event,
};

static int sw_nb_netdev_event(struct notifier_block *unused,
			      unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	struct netdev_hw_addr *dev_addr;
	struct net_device *pf_dev;
	struct in_ifaddr *ifa;
	struct fib_entry *entry;
	struct in_device *idev;
	struct otx2_nic *pf;
	struct list_head *iter;
	struct net_device *lower;

	if (event != NETDEV_CHANGE &&
	    event != NETDEV_UP &&
	    event != NETDEV_DOWN) {
		return NOTIFY_DONE;
	}

	if (!sw_nb_is_valid_dev(dev))
		return NOTIFY_DONE;

	idev = __in_dev_get_rtnl(dev);
	if (!idev || !idev->ifa_list)
		return NOTIFY_DONE;

	ifa = rtnl_dereference(idev->ifa_list);

	entry = kcalloc(1, sizeof(*entry), GFP_KERNEL);
	entry->cmd = sw_nb_inetaddr_event_to_otx2_event(event);
	entry->dst = htonl(ifa->ifa_address);
	entry->dst_len = 32;
	entry->mac_valid = 1;
	entry->host = 1;

	pf_dev = dev;
	if (netif_is_bridge_master(dev))  {
		entry->bridge = 1;
		netdev_for_each_lower_dev(dev, lower, iter) {
			pf_dev = lower;
			break;
		}
	}

	pf = netdev_priv(pf_dev);
	entry->port_id = pf->pcifunc;

	for_each_dev_addr(dev, dev_addr) {
		ether_addr_copy(entry->mac, dev_addr->addr);
		break;
	}

	sw_fib_add_to_list(pf_dev, entry, 1);

	pr_debug("%s:%d pushing netdev event from HOST interface address %#x, %pM, dev=%s\n",
		 __func__, __LINE__,  entry->dst, entry->mac, dev->name);

	return NOTIFY_DONE;
}

static struct notifier_block sw_nb_netdev = {
	.notifier_call = sw_nb_netdev_event,
};

int sw_nb_unregister(void)
{
	int err;

	sw_fdb_deinit();

	err = unregister_switchdev_notifier(&sw_nb_fdb);

	if (err)
		pr_debug("Failed to unregister switchdev nb\n");

	err = unregister_fib_notifier(&init_net, &sw_nb_fib);
	if (err)
		pr_debug("Failed to unregister fib nb\n");

	err = unregister_netevent_notifier(&sw_nb_netevent);
	if (err)
		pr_debug("Failed to unregister netevent\n");

	err = unregister_inetaddr_notifier(&sw_nb_inetaddr);
	if (err)
		pr_debug("Failed to unregister addr event\n");

	err = unregister_netdevice_notifier(&sw_nb_netdev);
	if (err)
		pr_debug("Failed to unregister netdev notifer\n");
	return 0;
}
EXPORT_SYMBOL(sw_nb_unregister);

int sw_nb_register(void)
{
	int err;

	sw_fdb_init();
	sw_fib_init();

	err = register_switchdev_notifier(&sw_nb_fdb);
	if (err) {
		pr_debug("Failed to register switchdev nb\n");
		return err;
	}

	err = register_fib_notifier(&init_net, &sw_nb_fib, NULL, NULL);
	if (err) {
		pr_debug("Failed to register fb notifier block");
		goto err1;
	}

	err = register_netevent_notifier(&sw_nb_netevent);
	if (err) {
		pr_debug("Failed to register netevent\n");
		goto err2;
	}

	err = register_inetaddr_notifier(&sw_nb_inetaddr);
	if (err) {
		pr_debug("Failed to register addr event\n");
		goto err3;
	}

	err = register_netdevice_notifier(&sw_nb_netdev);
	if (err) {
		pr_debug("Failed to register netdevice nb\n");
		goto err4;
	}

	return 0;

err4:
	unregister_inetaddr_notifier(&sw_nb_inetaddr);

err3:
	unregister_netevent_notifier(&sw_nb_netevent);

err2:
	unregister_fib_notifier(&init_net, &sw_nb_fib);

err1:
	unregister_switchdev_notifier(&sw_nb_fdb);
	return err;
}
EXPORT_SYMBOL(sw_nb_register);
