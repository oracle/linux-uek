/*
 * Copyright (C) Marvell International Ltd. and its affiliates
 *
 * This software file (the "File") is owned and distributed by Marvell
 * International Ltd. and/or its affiliates ("Marvell") under the following
 * alternative licensing terms.  Once you have made an election to distribute
 * the file under one of the following license alternatives, please (i) delete
 * this introductory statement regarding license alternatives, (ii) delete the
 * two license alternatives that you have not elected to use and (iii) preserve
 * the Marvell copyright notice above.
 *
 *******************************************************************************
 * Marvell GPL License Option

 * If you received this File from Marvell, you may opt to use, redistribute
 * and/or modify this File in accordance with the terms and conditions of the
 * General Public License Version 2, June 1991 (the "GPL License"), a copy of
 * which is available along with the File in the license.txt file or by writing
 * to the Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 or on the worldwide web at http://www.gnu.org/licenses/gpl.txt.
 *
 * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE ARE
 * EXPRESSLY DISCLAIMED.  The GPL License provides additional details about this
 * warranty disclaimer.
*/

/*
 * mvpci.c
 *
 * DESCRIPTION:
 *	A simple PCI driver that merely exposes interface to CPSS to enable and
 *	disable PCI devices.
 *	Usage:
 *		enable:
 *			echo -n "pci-vendor-id pci-device-id" >
 *				/sys/bus/pci/drivers/mvpci/new_id
 *		disable:
 *			echo -n "pci-vendor-id pci-device-id" >
 *				/sys/bus/pci/drivers/mvpci/remove_id
 *
 */

#define MV_DRV_NAME "mvpci"

#include <linux/pci.h>

static int mvpcidrv_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int rc;

	dev_info(&pdev->dev, "Probing to PCI device\n");

	rc = pci_enable_device(pdev);
	if (rc) {
		dev_err(&pdev->dev, "Fail to enable PCI device, aborting.\n");
		rc = -ENOMEM;
	}

	return rc;
}

static void mvpcidrv_remove(struct pci_dev *pdev)
{
	dev_info(&pdev->dev, "Unprobing from PCI device\n");

	pci_disable_device(pdev);
}

static struct pci_driver mvpcidrv_pci_driver = {
	.name		= MV_DRV_NAME,
	.probe		= mvpcidrv_probe,
	.remove		= mvpcidrv_remove,
	.driver.pm	= NULL,
};

void mvpci_exit(void)
{
	pci_unregister_driver(&mvpcidrv_pci_driver);
}

int mvpci_init(void)
{
	int rc;

	rc = pci_register_driver(&mvpcidrv_pci_driver);
	if (rc) {
		pr_err("%s: Fail to register PCI driver\n", MV_DRV_NAME);
		return rc;
	}

	return 0;
}
