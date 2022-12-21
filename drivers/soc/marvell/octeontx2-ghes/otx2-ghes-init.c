// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 ghes init driver
 *
 * Copyright (C) 2022 Marvell.
 */

#include <linux/pci.h>

#define PCI_DEVICE_ID_OCTEONTX2_LMC	(0xa022)
#define PCI_DEVICE_ID_OCTEONTX2_MCC	(0xa070)
#define PCI_DEVICE_ID_OCTEONTX2_MDC	(0xa073)

static const struct pci_device_id otx2_pci_tbl[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX2_LMC) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX2_MCC) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX2_MDC) },
	{ 0, },
};

static void __init otx2_enable_msix(struct pci_dev *pdev)
{
	u16 ctrl;

	if ((pdev->msi_enabled) || (pdev->msix_enabled)) {
		dev_err(&pdev->dev, "MSI(%d) or MSIX(%d) already enabled\n",
			pdev->msi_enabled, pdev->msix_enabled);
		return;
	}

	pdev->msix_cap = pci_find_capability(pdev, PCI_CAP_ID_MSIX);
	if (pdev->msix_cap) {
		pci_read_config_word(pdev, pdev->msix_cap + PCI_MSIX_FLAGS, &ctrl);
		ctrl |= PCI_MSIX_FLAGS_ENABLE;
		pci_write_config_word(pdev, pdev->msix_cap + PCI_MSIX_FLAGS, ctrl);

		pr_info("Set MSI-X Enable for PCI dev %04d:%02d.%d\n",
			pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
	} else
		dev_err(&pdev->dev, "PCI dev %04d:%02d.%d missing MSIX capabilities\n",
			pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
}

static int __init otx2_msix_init(void)
{
	const struct pci_device_id *pdevid;
	struct pci_dev *pdev;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(otx2_pci_tbl); i++) {
		pdevid = &otx2_pci_tbl[i];
		pdev = NULL;
		while ((pdev = pci_get_device(pdevid->vendor, pdevid->device, pdev)))
			otx2_enable_msix(pdev);
	}

	return 0;
}

device_initcall(otx2_msix_init);
