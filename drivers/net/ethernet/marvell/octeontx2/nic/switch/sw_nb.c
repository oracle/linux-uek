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

#include "../otx2_reg.h"
#include "../otx2_common.h"
#include "../otx2_struct.h"
#include "../cn10k.h"
#include "sw_fdb.h"

static bool sw_nb_is_valid_dev(struct net_device *netdev)
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

int sw_nb_unregister(void)
{
	int err;

	sw_fdb_deinit();

	err = unregister_switchdev_notifier(&sw_nb_fdb);
	if (err)
		pr_err("Failed to unregister switchdev nb\n");

	return 0;
}
EXPORT_SYMBOL(sw_nb_unregister);

int sw_nb_register(void)
{
	int err;

	err = register_switchdev_notifier(&sw_nb_fdb);
	if (err) {
		pr_err("Failed to register switchdev nb\n");
		return err;
	}

	sw_fdb_init();
	return 0;
}
EXPORT_SYMBOL(sw_nb_register);
