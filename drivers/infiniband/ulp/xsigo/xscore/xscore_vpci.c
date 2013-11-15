/*
 * Copyright (c) 2006-2012 Xsigo Systems Inc.  All rights reserved.
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
 *
 */

#include <linux/version.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/sysfs.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>

#include "xs_compat.h"
#include "xscore.h"

int xscore_vpci_enable = 1;
module_param(xscore_vpci_enable, int, 0644);

#define PCI_VENDOR_ID_XSIGO		0x199d
#define PCI_DEVICE_ID_XSIGO_VNIC	0x8209

static struct pci_bus *vbus;
static struct pci_sysdata *sysdata;

static DEFINE_PCI_DEVICE_TABLE(xs_vpci_dev_table) = {
	{PCI_DEVICE(PCI_VENDOR_ID_XSIGO, PCI_DEVICE_ID_XSIGO_VNIC)},
	{0}
};

MODULE_DEVICE_TABLE(pci, xs_vpci_dev_table);

int xs_vpci_read(struct pci_bus *bus, unsigned int devfn, int where,
		 int size, u32 *val)
{
	switch (where) {
	case PCI_VENDOR_ID:
		*val = PCI_VENDOR_ID_XSIGO | PCI_DEVICE_ID_XSIGO_VNIC << 16;
		/* our id */
		break;
	case PCI_COMMAND:
		*val = 0;
		break;
	case PCI_HEADER_TYPE:
		*val = PCI_HEADER_TYPE_NORMAL;
		break;
	case PCI_STATUS:
		*val = 0;
		break;
	case PCI_CLASS_REVISION:
		*val = (2 << 24) | (0 << 16) | 1;
		/* network class, ethernet controller, revision 1 */
		break;
	case PCI_INTERRUPT_PIN:
		*val = 0;
		break;
	case PCI_SUBSYSTEM_VENDOR_ID:
		*val = 0;
		break;
	case PCI_SUBSYSTEM_ID:
		*val = 0;
		break;
	default:
		*val = 0;
		/* sensible default */
	}
	return 0;
}

int xs_vpci_write(struct pci_bus *bus, unsigned int devfn, int where,
		  int size, u32 val)
{
	switch (where) {
	case PCI_BASE_ADDRESS_0:
	case PCI_BASE_ADDRESS_1:
	case PCI_BASE_ADDRESS_2:
	case PCI_BASE_ADDRESS_3:
	case PCI_BASE_ADDRESS_4:
	case PCI_BASE_ADDRESS_5:
		break;
	}
	return 0;
}

struct pci_ops xs_vpci_ops = {
	.read = xs_vpci_read,
	.write = xs_vpci_write
};

struct pci_dev *xs_vpci_prep_vnic(struct net_device *netdev, char *vnic_name,
				  int devn)
{
	struct pci_dev *pcidev = NULL;
	/* netdev->ifindex always comes as zero
	* for rhel5 versions before registration
	*/

	if (!boot_flag || vbus == NULL)
		return NULL;

	pcidev = pci_scan_single_device(vbus, devn);

	if (pcidev == NULL)
		return NULL;
	else
		pci_dev_get(pcidev);

	pci_bus_add_devices(vbus);
	SET_NETDEV_DEV(netdev, &pcidev->dev);
	return pcidev;
}
EXPORT_SYMBOL(xs_vpci_prep_vnic);

void *xs_vpci_add_vnic(char *vnic_name, int devn)
{
	struct pci_dev *pcidev;
	struct net_device *netdev;
	int ret;

	if (vbus == NULL)
		return NULL;
	pcidev = pci_scan_single_device(vbus, devn);
	if (pcidev == NULL)
		return NULL;
	else
		pci_dev_get(pcidev);
	/*
	 * Better to use compat layer, but for now since this is citrix specific
	 * will use LINUX version magic
	 */
	netdev = dev_get_by_name(&init_net, vnic_name);
	if (netdev == NULL) {
		pci_dev_put(pcidev);
		return NULL;
	}
	if (pci_bus_add_device(pcidev) != 0) {
		dev_put(netdev);
		pci_dev_put(pcidev);
		return NULL;
	}

	ret = sysfs_create_link(&netdev->dev.kobj, &pcidev->dev.kobj, "device");
	if (ret) {
		pci_stop_and_remove_bus_device(pcidev);
		dev_put(netdev);
		pci_dev_put(pcidev);
		pcidev = NULL;
	}
	return pcidev;
}
EXPORT_SYMBOL(xs_vpci_add_vnic);

void xs_vpci_remove_vnic(struct net_device *netdev, void *hndl)
{
	struct pci_dev *pcidev = hndl;

	if (vbus == NULL)
		return;
	if (!boot_flag) {
		sysfs_remove_link(&netdev->dev.kobj, "device");
		dev_put(netdev);
	}
	pci_stop_and_remove_bus_device(pcidev);
	pci_dev_put(pcidev);
}
EXPORT_SYMBOL(xs_vpci_remove_vnic);

void xs_vpci_vdev_remove(struct pci_dev *dev)
{
}

static struct pci_driver xs_vpci_vdev_driver = {
	.name = "Xsigo-Virtual-NIC",
	.id_table = xs_vpci_dev_table,
	.remove = xs_vpci_vdev_remove
};

int xs_vpci_bus_init(void)
{
	int i = 100;

	if (!xscore_vpci_enable)
		return 0;

	sysdata = kzalloc(sizeof(void *), GFP_KERNEL);
	while (i > 0) {
		vbus = pci_scan_bus_parented(NULL, i, &xs_vpci_ops, sysdata);
		if (vbus != NULL)
			break;
		memset(sysdata, 0, sizeof(void *));
		i--;
	}
	if (vbus == NULL) {
		kfree(sysdata);
		return -EINVAL;
	}
	if (pci_register_driver(&xs_vpci_vdev_driver) < 0) {
		pci_remove_bus(vbus);
		vbus = NULL;
		return -EINVAL;
	}
	return 0;
}

void xs_vpci_bus_remove(void)
{
	if (vbus) {
		pci_unregister_driver(&xs_vpci_vdev_driver);
		device_unregister(vbus->bridge);
		pci_remove_bus(vbus);
		kfree(sysdata);
		vbus = NULL;
	}
}
