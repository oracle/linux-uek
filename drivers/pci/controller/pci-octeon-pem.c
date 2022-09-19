// SPDX-License-Identifier: GPL-2.0
/* Octeon PEM driver
 *
 * Copyright (C) 2021 Marvell.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/sysfs.h>
#include <linux/of.h>
#include <linux/of_device.h>

#define DRV_NAME	"octeon-pem"
#define DRV_VERSION	"1.0"

#define PCI_DEVID_OCTEON_PEM	0xA06C

#define DTX_PEM_BASE(x)		(0x87E0FE9C0000 + 0x2000 * (x))
#define DTX_PEM_SIZE		0x1000
#define DTX_PEM_SEL(x)		(0x0 + 0x8 * (x))
#define DTX_PEM_ENA(x)		(0x20 + 0x8 * (x))
#define DTX_PEM_DAT(x)		(0x40 + 0x8 * (x))

#define ID_SHIFT		36
#define DOMAIN_OFFSET		0x3
#define ON_OFFSET		0xE0
#define RST_INT_OFFSET		0x300
#define RST_INT_ENA_W1C_OFFSET	0x310
#define RST_INT_ENA_W1S_OFFSET	0x318
#define RST_INT_LINKDOWN	BIT(1)

struct pem_ctlr {
	int			index;
	char			irq_name[32];
	void __iomem		*base;
	void __iomem		*dtx_base;
	struct pci_dev		*pdev;
	struct work_struct	recover_rc_work;
};

static void pem_recover_rc_link(struct work_struct *ws)
{
	struct pem_ctlr *pem = container_of(ws, struct pem_ctlr,
					    recover_rc_work);
	struct pci_dev *pem_dev = pem->pdev;
	struct pci_dev *root_port;
	struct pci_bus *bus;
	int rc_domain, timeout = 100;
	u64 pem_reg, dtx_reg;

	rc_domain = pem->index + DOMAIN_OFFSET;

	root_port = pci_get_domain_bus_and_slot(rc_domain, 0, 0);
	if (!root_port) {
		dev_err(&pem_dev->dev, "failed to get root port\n");
		return;
	}

	/* Due to hardware issue, sometimes link-down event may not go
	 * through cleanly and put LTSSM in to un-desired state inside PEM.
	 * Toggling PEMON(bit 0) in PEM_ON register should reset
	 * PEM state and setup correctly.
	 */
	dtx_reg = 0x000500;
	writeq(dtx_reg, pem->dtx_base + DTX_PEM_SEL(0));
	dtx_reg = 0xfffffffff;
	writeq(dtx_reg, pem->dtx_base + DTX_PEM_ENA(0));

	dtx_reg = readq(pem->dtx_base + DTX_PEM_DAT(0));

	writeq(0x0, pem->dtx_base + DTX_PEM_SEL(0));
	writeq(0x0, pem->dtx_base + DTX_PEM_ENA(0));

	pem_reg = readq(pem->base + ON_OFFSET);

	dtx_reg &= BIT_ULL(13);
	pem_reg &= (BIT_ULL(1) | BIT_ULL(0));

	if (!dtx_reg && (pem_reg & 0x3)) {
		pem_reg = readq(pem->base + ON_OFFSET);
		pem_reg &= ~(BIT_ULL(0));
		writeq(pem_reg, pem->base + ON_OFFSET);

		udelay(10);

		pem_reg = readq(pem->base + ON_OFFSET);
		pem_reg |= BIT_ULL(0);
		writeq(pem_reg, pem->base + ON_OFFSET);

		while (timeout--) {
			/* Check for PEM_OOR to be set */
			pem_reg = readq(pem->base + ON_OFFSET);
			if (pem_reg & BIT(1))
				break;
			udelay(1000);
		}
		if (!timeout) {
			dev_warn(&pem_dev->dev,
				 "PEM failed to get out of reset\n");
			return;
		}
	}

	pci_lock_rescan_remove();

	/* Clean-up device and RC bridge */
	pci_stop_and_remove_bus_device(root_port);

	/*
	 * Hardware resets and initializes config space of RC bridge
	 * on every link down event with auto-mode in use.
	 * Re-scan will setup RC bridge cleanly in kernel
	 * after removal and to be ready for next link-up event.
	 */
	bus = NULL;
	while ((bus = pci_find_next_bus(bus)) != NULL)
		if (bus->domain_nr == rc_domain)
			pci_rescan_bus(bus);
	pci_unlock_rescan_remove();
	pci_dev_put(root_port);

	/* Ack interrupt */
	writeq(RST_INT_LINKDOWN, pem->base + RST_INT_OFFSET);
	/* Enable RST_INT[LINKDOWN] interrupt */
	writeq(RST_INT_LINKDOWN, pem->base + RST_INT_ENA_W1S_OFFSET);
}

irqreturn_t pem_irq_handler(int irq, void *dev_id)
{
	struct pem_ctlr *pem = (struct pem_ctlr *)dev_id;

	/* Disable RST_INT[LINKDOWN] interrupt */
	writeq(RST_INT_LINKDOWN, pem->base + RST_INT_ENA_W1C_OFFSET);
	schedule_work(&pem->recover_rc_work);

	return IRQ_HANDLED;
}

static int pem_register_interrupts(struct pci_dev *pdev)
{
	struct pem_ctlr *pem = pci_get_drvdata(pdev);
	int nvec, err;

	nvec = pci_msix_vec_count(pdev);
	/* Some earlier silicon versions do not support RST vector
	 * so check on table size before registering otherwise
	 * return with info message.
	 */
	if (nvec != 10) {
		dev_info(&pdev->dev,
			 "No RST MSI-X vector support on silicon\n");
		return 0;
	}
	err = pci_alloc_irq_vectors(pdev, nvec, nvec, PCI_IRQ_MSIX);
	if (err < 0) {
		dev_err(&pdev->dev, "pci_alloc_irq_vectors() failed %d\n",
			nvec);
		return -ENOSPC;
	}

	snprintf(pem->irq_name, 32, "PEM%d RST_INT", pem->index);

	/* register interrupt for RST_INT */
	return devm_request_irq(&pdev->dev, pci_irq_vector(pdev, 9),
				pem_irq_handler, 0,
				pem->irq_name, pem);
}

static int pem_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct pem_ctlr *pem;
	int err;
	resource_size_t addr, size;

	pem = devm_kzalloc(dev, sizeof(struct pem_ctlr), GFP_KERNEL);
	if (pem == NULL)
		return -ENOMEM;

	pem->pdev = pdev;
	pci_set_drvdata(pdev, pem);

	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		goto enable_failed;
	}

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed 0x%x\n", err);
		goto region_failed;
	}

	pci_set_master(pdev);

	/* CSR Space mapping */
	pem->base = pcim_iomap(pdev, 0, pci_resource_len(pdev, 0));
	if (!pem->base) {
		dev_err(&pdev->dev, "Unable to map BAR0\n");
		err = -ENODEV;
		goto bar0_map_failed;
	}
	pem->index = ((u64)pci_resource_start(pdev, 0) >> ID_SHIFT) & 0xf;

	/* DTX register space mapping */
	addr = DTX_PEM_BASE(pem->index);
	size = DTX_PEM_SIZE;
	pem->dtx_base = ioremap(addr, size);
	if (IS_ERR(pem->dtx_base)) {
		dev_err(&pdev->dev, "Unable to map DTX region\n");
		err = -ENODEV;
		goto bar0_map_failed;
	}

	err = pem_register_interrupts(pdev);
	if (err < 0) {
		dev_err(dev, "Register interrupt failed\n");
		goto irq_failed;
	}

	INIT_WORK(&pem->recover_rc_work, pem_recover_rc_link);

	/* Enable RST_INT[LINKDOWN] interrupt */
	writeq(RST_INT_LINKDOWN, pem->base + RST_INT_ENA_W1S_OFFSET);

	dev_info(&pdev->dev, "PEM%d probed\n", pem->index);
	return 0;

irq_failed:
bar0_map_failed:
	pci_release_regions(pdev);
region_failed:
enable_failed:
	pci_set_drvdata(pdev, NULL);
	return err;
}

static void pem_remove(struct pci_dev *pdev)
{
	pci_release_regions(pdev);
}

/* Supported devices */
static const struct pci_device_id pem_id_table[] = {
	{PCI_VDEVICE(CAVIUM, PCI_DEVID_OCTEON_PEM)},
	{0} /* end of table */
};

static struct pci_driver pem_driver = {
	.name = DRV_NAME,
	.id_table = pem_id_table,
	.probe = pem_probe,
	.remove = pem_remove,
};

module_pci_driver(pem_driver);

MODULE_AUTHOR("Marvell Inc.");
MODULE_DESCRIPTION("Marvell Octeon PEM Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, pem_id_table);
