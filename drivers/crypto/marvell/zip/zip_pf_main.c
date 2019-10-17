// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX and OcteonTX2 ZIP Physical Function driver
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/of.h>
#include <linux/delay.h>

#include "zip_pf.h"
#include "zip.h"

static const struct pci_device_id zip_pf_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX_ZIP_PF) },
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_OCTEONTX2_ZIP_PF) },
	{ 0, }
};

/*
 * Following are the stub functions for OcteonTX Resource Manager.
 * zip_pf_create_domain()
 * zip_pf_reset_domain()
 * zip_pf_destroy_domain()
 * zip_pf_receive_message()
 *
 * The driver does not support ODP ZIP VFs.
 */

static u64 zip_pf_create_domain(u32 id, u16 domain_id, u32 num_vfs,
				void *master, void *master_data,
				struct kobject *kobj)
{
	unsigned long zip_mask = 0;
	int i;

	for (i = 0; i < num_vfs; i++)
		set_bit(i, &zip_mask);

	return zip_mask;
}

static int zip_pf_destroy_domain(u32 id, u16 domain_id,
				  struct kobject *kobj)
{
	return 0;
}

static int zip_pf_reset_domain(u32 id, u16 domain_id)
{
	return 0;
}

static int zip_pf_receive_message(u32 id, u16 domain_id,
				  struct mbox_hdr *hdr, union mbox_data *req,
				  union mbox_data *resp, void *mdata)
{
	return 0;
}

struct zippf_com_s zippf_com = {
	.create_domain = zip_pf_create_domain,
	.destroy_domain = zip_pf_destroy_domain,
	.reset_domain = zip_pf_reset_domain,
	.receive_message = zip_pf_receive_message
};
EXPORT_SYMBOL(zippf_com);

static irqreturn_t zip_pf_ecce_intr_handler(int irq, void *zip_pf)
{
	struct zip_pf_device *pf = zip_pf;

	/* Clear triggered interrupts */
	zip_pf_reg_write(pf, ZIP_PF_ECCE_INT, ~0ull);

	return IRQ_HANDLED;
}

static irqreturn_t zip_pf_fife_intr_handler(int irq, void *zip_pf)
{
	struct zip_pf_device *pf = zip_pf;

	/* Clear triggered interrupts */
	zip_pf_reg_write(pf, ZIP_PF_FIFE_INT, ~0ull);

	return IRQ_HANDLED;
}

static irqreturn_t zip_pf_mbox_intr_handler(int irq, void *zip_pf)
{
	struct zip_pf_device *pf = zip_pf;

	/* Clear triggered interrupts */
	zip_pf_reg_write(pf, ZIP_PF_MBOX_INT, ~0ull);

	return IRQ_HANDLED;
}

static void otx_zip_pf_intr_disable(struct zip_pf_device *pf)
{
	zip_pf_reg_write(pf, ZIP_PF_ECCE_ENA_W1C, ~0ull);
	zip_pf_reg_write(pf, ZIP_PF_FIFE_ENA_W1C, ~0ull);
	zip_pf_reg_write(pf, ZIP_PF_MBOX_ENA_W1C, ~0ull);
}

static void otx2_zip_pf_intr_disable(struct zip_pf_device *pf)
{
	zip_pf_reg_write(pf, ZIP_PF_MBOX_ENA_W1C, ~0ull);
}

static void zip_pf_intr_disable(struct zip_pf_device *pf)
{
	if (pf->dev_id == PCI_DEVICE_ID_OCTEONTX_ZIP_PF)
		otx_zip_pf_intr_disable(pf);
	else
		otx2_zip_pf_intr_disable(pf);
}

static int otx_zip_pf_intr_init(struct zip_pf_device *pf)
{
	struct device *dev = &pf->pdev->dev;
	int ret, i;

	/* Clear all interrupts */
	zip_pf_reg_write(pf, ZIP_PF_ECCE_INT, ~0ull);
	zip_pf_reg_write(pf, ZIP_PF_FIFE_INT, ~0ull);
	zip_pf_reg_write(pf, ZIP_PF_MBOX_INT, ~0ull);

	/* Disable all interrupts */
	zip_pf_reg_write(pf, ZIP_PF_ECCE_ENA_W1C, ~0ull);
	zip_pf_reg_write(pf, ZIP_PF_FIFE_ENA_W1C, ~0ull);
	zip_pf_reg_write(pf, ZIP_PF_MBOX_ENA_W1C, ~0ull);

	pf->msix_entries = devm_kzalloc(dev, ZIP_PF_OCTEONTX_MSIX_COUNT
			* sizeof(struct msix_entry), GFP_KERNEL);
	if (!pf->msix_entries)
		return -ENOMEM;

	for (i = 0; i < ZIP_PF_OCTEONTX_MSIX_COUNT; i++)
		pf->msix_entries[i].entry = i;

	ret = pci_enable_msix_exact(pf->pdev, pf->msix_entries,
			ZIP_PF_OCTEONTX_MSIX_COUNT);
	if (ret) {
		dev_err(dev, "Failed to enable MSI-X\n");
		return ret;
	}

	/* Register ECCE interrupt handler */
	ret = devm_request_irq(dev, pf->msix_entries[0].vector,
			  zip_pf_ecce_intr_handler, 0, "zip_pf ecce", pf);
	if (ret) {
		dev_err(dev, "Failed to register ECCE interrupt handler\n");
		return ret;
	}

	/* Register FIFE interrupt handler */
	ret = devm_request_irq(dev, pf->msix_entries[1].vector,
			  zip_pf_fife_intr_handler, 0, "zip_pf fife", pf);
	if (ret) {
		dev_err(dev, "Failed to register FIFE interrupt handler\n");
		return ret;
	}

	/* Register MBOX interrupt handler */
	ret = devm_request_irq(dev, pf->msix_entries[2].vector,
			  zip_pf_mbox_intr_handler, 0, "zip_pf mbox", pf);
	if (ret) {
		dev_err(dev, "Failed to register MBOX interrupt handler\n");
		return ret;
	}

	/* Enable all interrupts */
	zip_pf_reg_write(pf, ZIP_PF_ECCE_ENA_W1S, ~0ull);
	zip_pf_reg_write(pf, ZIP_PF_FIFE_ENA_W1S, ~0ull);
	zip_pf_reg_write(pf, ZIP_PF_MBOX_ENA_W1S, ~0ull);

	return 0;
}

static int otx2_zip_pf_intr_init(struct zip_pf_device *pf)
{
	struct device *dev = &pf->pdev->dev;
	int ret;

	/* Clear interrupt */
	zip_pf_reg_write(pf, ZIP_PF_MBOX_INT, ~0ull);

	/* Disable interrupt */
	zip_pf_reg_write(pf, ZIP_PF_MBOX_ENA_W1C, ~0ull);

	pf->msix_entries = devm_kzalloc(dev, ZIP_PF_OCTEONTX2_MSIX_COUNT
			* sizeof(struct msix_entry), GFP_KERNEL);
	if (!pf->msix_entries)
		return -ENOMEM;

	pf->msix_entries[0].entry = 0;

	ret = pci_enable_msix_exact(pf->pdev, pf->msix_entries,
			ZIP_PF_OCTEONTX2_MSIX_COUNT);
	if (ret) {
		dev_err(dev, "Failed to enable MSI-X\n");
		return ret;
	}

	/* Register MBOX interrupt handler */
	ret = devm_request_irq(dev, pf->msix_entries[0].vector,
			  zip_pf_mbox_intr_handler, 0, "zip_pf mbox", pf);
	if (ret) {
		dev_err(dev, "Failed to register MBOX interrupt handler\n");
		return ret;
	}

	/* Enable all interrupts */
	zip_pf_reg_write(pf, ZIP_PF_MBOX_ENA_W1S, ~0ull);

	return 0;
}

static int zip_pf_intr_init(struct zip_pf_device *pf)
{
	if (pf->dev_id == PCI_DEVICE_ID_OCTEONTX_ZIP_PF)
		return otx_zip_pf_intr_init(pf);
	else
		return otx2_zip_pf_intr_init(pf);
}

static int zip_pf_sriov_init(struct zip_pf_device *pf, int num_vf)
{
	struct device *dev = &pf->pdev->dev;
	struct pci_dev *pdev = pf->pdev;
	int err;

	pf->total_vf = pci_sriov_get_totalvfs(pdev);

	err = pci_enable_sriov(pdev, num_vf);
	if (err) {
		dev_err(dev, "Failed to enable SRIOV\n");
		pf->num_vf = 0;
		return err;
	}

	pf->num_vf = pci_num_vf(pdev);
	dev_info(dev, "SRIOV enabled, %d VFs available\n", pf->num_vf);

	return 0;
}

static int zip_pf_init(struct zip_pf_device *pf)
{
	union zip_quex_sbuf_ctl sbuf_ctl;
	union zip_quex_map map;
	union zip_cmd_ctl cmd_ctl;
	int q;

	/* Reset ZIP subsystem */
	cmd_ctl.u = zip_pf_reg_read(pf, ZIP_PF_CMD_CTL);
	cmd_ctl.s.reset = 1;
	zip_pf_reg_write(pf, ZIP_PF_CMD_CTL, cmd_ctl.u & 0xFF);

	udelay(5);

	for (q = 0; q < ZIP_MAX_VFS; q++) {
		sbuf_ctl.u = 0ull;
		sbuf_ctl.s.size = ZIP_CMD_QBUF_SIZE / sizeof(u64);
		sbuf_ctl.s.inst_be = 0;
		sbuf_ctl.s.stream_id = q + 1;
		sbuf_ctl.s.inst_free = 0;
		zip_pf_reg_write(pf, ZIP_PF_QUEX_SBUF_CTL(q), sbuf_ctl.u);

		/*
		 * Queue-to-ZIP core mapping
		 * If a queue is not mapped to a particular core, it is
		 * equivalent to the ZIP core being disabled.
		 */
		map.u = 0ull;
		map.s.zce = 0x3F;
		zip_pf_reg_write(pf, ZIP_PF_QUEX_MAP(q), map.u);
	}

	return 0;
}

static int zip_pf_probe(struct pci_dev *pdev,
			const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct zip_pf_device *pf = NULL;
	int err;

	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device: %d\n", err);
		return err;
	}

	err = pcim_iomap_regions_request_all(pdev, 0x1, DRV_NAME);
	if (err) {
		dev_err(dev, "Failed to reserve PCI resources: 0x%x\n", err);
		return err;
	}

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Failed to set DMA mask: %d\n", err);
		return err;
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Failed to set consistent DMA mask: %d\n", err);
		return err;
	}

	pf = devm_kzalloc(dev, sizeof(*pf), GFP_KERNEL);
	if (!pf)
		return -ENOMEM;

	pci_set_drvdata(pdev, pf);
	pf->pdev = pdev;
	pf->dev_id = ent->device;

	pf->reg_base = pcim_iomap_table(pdev)[0];
	if (!pf->reg_base) {
		dev_err(dev, "Failed to map PCI resource\n");
		err = -ENOMEM;
		goto unset_drvdata;
	}

	zip_pf_init(pf);

	err = zip_pf_intr_init(pf);
	if (err)
		goto unset_drvdata;

	err = zip_pf_sriov_init(pf, ZIP_MAX_VFS);
	if (err)
		goto disable_interrupts;

	return 0;

disable_interrupts:
	zip_pf_intr_disable(pf);

unset_drvdata:
	pci_set_drvdata(pdev, NULL);

	return err;
}

static void zip_pf_remove(struct pci_dev *pdev)
{
	struct zip_pf_device *pf = pci_get_drvdata(pdev);

	if (!pf)
		return;

	if (pci_vfs_assigned(pdev))
		dev_err(&pdev->dev, "VFs are assigned. Removing PF\n");

	pci_disable_sriov(pdev);
	zip_pf_intr_disable(pf);
	pci_set_drvdata(pdev, NULL);
}

static struct pci_driver zip_pf_driver = {
	.name     = DRV_NAME,
	.id_table = zip_pf_id_table,
	.probe    = zip_pf_probe,
	.remove   = zip_pf_remove,
};

module_pci_driver(zip_pf_driver);

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION("Marvell OcteonTX ZIP Physical Function Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, zip_pf_id_table);
