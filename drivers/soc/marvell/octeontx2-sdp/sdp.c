// SPDX-License-Identifier: GPL-2.0
/* OcteonTX2 SDP driver
 *
 * Copyright (C) 2023 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/sysfs.h>
#include <linux/of.h>
#include <linux/of_device.h>

#include "rvu.h"
#include "rvu_reg.h"
#include "rvu_struct.h"
#include "sdp.h"

#define DRV_NAME	"octeontx2-sdp"
#define DRV_VERSION	"1.1"

#define PCI_DEVID_OCTEONTX2_SDP_PF	0xA0F6
/* PCI BARs */
#define PCI_AF_REG_BAR_NUM	0
#define PCI_CFG_REG_BAR_NUM	2
#define MBOX_BAR_NUM		4

#define SDP_PPAIR_THOLD 0x400

static spinlock_t sdp_lst_lock;
LIST_HEAD(sdp_dev_lst_head);

static void
sdp_write64(struct sdp_dev *rvu, u64 b, u64 s, u64 o, u64 v)
{
	writeq(v, rvu->bar2 + ((b << 20) | (s << 12) | o));
}

static u64 sdp_read64(struct sdp_dev *rvu, u64 b, u64 s, u64 o)
{
	return readq(rvu->bar2 + ((b << 20) | (s << 12) | o));
}

static int sdp_check_pf_usable(struct sdp_dev *sdp)
{
	u64 rev;

	rev = sdp_read64(sdp, BLKADDR_RVUM, 0,
			RVU_PF_BLOCK_ADDRX_DISC(BLKADDR_RVUM));
	rev = (rev >> 12) & 0xFF;
	/* Check if AF has setup revision for RVUM block,
	 * otherwise this driver probe should be deferred
	 * until AF driver comes up.
	 */
	if (!rev) {
		dev_warn(&sdp->pdev->dev,
			 "AF is not initialized, deferring probe\n");
		return -EPROBE_DEFER;
	}
	return 0;
}

static int sdp_alloc_irqs(struct pci_dev *pdev)
{
	struct sdp_dev *sdp;
	int err;

	sdp = pci_get_drvdata(pdev);

	/* Get number of MSIX vector count and allocate vectors first */
	sdp->msix_count = pci_msix_vec_count(pdev);

	err = pci_alloc_irq_vectors(pdev, sdp->msix_count, sdp->msix_count,
				    PCI_IRQ_MSIX);

	if (err < 0) {
		dev_err(&pdev->dev, "pci_alloc_irq_vectors() failed %d\n", err);
		return err;
	}

	sdp->irq_names = kmalloc_array(sdp->msix_count, NAME_SIZE, GFP_KERNEL);
	if (!sdp->irq_names) {
		err = -ENOMEM;
		goto err_irq_names;
	}

	sdp->irq_allocated = kcalloc(sdp->msix_count, sizeof(bool), GFP_KERNEL);
	if (!sdp->irq_allocated) {
		err = -ENOMEM;
		goto err_irq_allocated;
	}

	return 0;

err_irq_allocated:
	kfree(sdp->irq_names);
	sdp->irq_names = NULL;
err_irq_names:
	pci_free_irq_vectors(pdev);
	sdp->msix_count = 0;

	return err;
}

static void sdp_free_irqs(struct pci_dev *pdev)
{
	struct sdp_dev *sdp;
	int irq;

	sdp = pci_get_drvdata(pdev);
	for (irq = 0; irq < sdp->msix_count; irq++) {
		if (sdp->irq_allocated[irq])
			free_irq(pci_irq_vector(sdp->pdev, irq), sdp);
	}

	pci_free_irq_vectors(pdev);

	kfree(sdp->irq_names);
	kfree(sdp->irq_allocated);
}

static int __sriov_disable(struct pci_dev *pdev)
{
	struct sdp_dev *sdp;

	sdp = pci_get_drvdata(pdev);
	if (pci_vfs_assigned(pdev)) {
		dev_err(&pdev->dev, "Disabing VFs while VFs are assigned\n");
		dev_err(&pdev->dev, "VFs will not be freed\n");
		return -EPERM;
	}

	pci_disable_sriov(pdev);

	kfree(sdp->vf_info);
	sdp->vf_info = NULL;

	return 0;
}

static int __sriov_enable(struct pci_dev *pdev, int num_vfs)
{
	int curr_vfs, vf = 0;
	struct sdp_dev *sdp;
	int err;

	curr_vfs = pci_num_vf(pdev);
	if (!curr_vfs && !num_vfs)
		return -EINVAL;

	if (curr_vfs) {
		dev_err(
		    &pdev->dev,
		    "Virtual Functions are already enabled on this device\n");
		return -EINVAL;
	}
	if (num_vfs > SDP_MAX_VFS)
		num_vfs = SDP_MAX_VFS;

	sdp = pci_get_drvdata(pdev);

	sdp->vf_info = kcalloc(num_vfs, sizeof(struct rvu_vf), GFP_KERNEL);
	if (sdp->vf_info == NULL)
		return -ENOMEM;

	sdp->num_vfs = num_vfs;

	err = pci_enable_sriov(pdev, num_vfs);
	if (err)
		dev_err(&pdev->dev, "Failed to enable to SRIOV VFs: %d\n", err);

	return num_vfs;
}

static int sdp_sriov_configure(struct pci_dev *pdev, int num_vfs)
{
	if (num_vfs == 0)
		return __sriov_disable(pdev);
	else
		return __sriov_enable(pdev, num_vfs);
}


static int sdp_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	uint64_t inst, regval;
	struct sdp_dev *sdp;
	struct device *dev;
	int err;

	dev = &pdev->dev;
	sdp = devm_kzalloc(dev, sizeof(struct sdp_dev), GFP_KERNEL);
	if (sdp == NULL)
		return -ENOMEM;

	sdp->pdev = pdev;
	pci_set_drvdata(pdev, sdp);

	mutex_init(&sdp->lock);

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		goto enable_failed;
	}

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed 0x%x\n", err);
		goto map_failed;
	}

	if (pci_sriov_get_totalvfs(pdev) <= 0) {
		err = -ENODEV;
		goto set_mask_failed;
	}

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to set DMA mask\n");
		goto set_mask_failed;
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to set DMA mask\n");
		goto set_mask_failed;
	}

	pci_set_master(pdev);

	/* CSR Space mapping */
	sdp->bar2 = pcim_iomap(pdev, PCI_CFG_REG_BAR_NUM,
			       pci_resource_len(pdev, PCI_CFG_REG_BAR_NUM));
	if (!sdp->bar2) {
		dev_err(&pdev->dev, "Unable to map BAR2\n");
		err = -ENODEV;
		goto set_mask_failed;
	}

	err = sdp_check_pf_usable(sdp);
	if (err)
		goto pf_unusable;

	/* Map SDP register area */
	/* right now only 2 SDP blocks are supported */
	inst = list_empty(&sdp_dev_lst_head) ? 0 : 1;
	sdp->sdp_base = ioremap(SDP_BASE(inst), SDP_REG_SIZE);
	if (!sdp->sdp_base) {
		dev_err(&pdev->dev, "Unable to map SDP CSR space\n");
		err = -ENODEV;
		goto pf_unusable;
	}
	/* Map PF-AF mailbox memory */
	sdp->af_mbx_base = ioremap_wc(pci_resource_start(pdev, MBOX_BAR_NUM),
				     pci_resource_len(pdev, MBOX_BAR_NUM));
	if (!sdp->af_mbx_base) {
		dev_err(&pdev->dev, "Unable to map BAR4\n");
		err = -ENODEV;
		goto pf_unusable;
	}

	if (sdp_alloc_irqs(pdev)) {
		dev_err(&pdev->dev,
			"Unable to allocate MSIX Interrupt vectors\n");
		err = -ENODEV;
		goto alloc_irqs_failed;
	}

	regval = readq(sdp->sdp_base + SDPX_GBL_CONTROL);
	regval |= (1 << 2); /* BPFLR_D disable clearing BP in FLR */
	writeq(regval, sdp->sdp_base + SDPX_GBL_CONTROL);

	sdp_sriov_configure(sdp->pdev, sdp->info.max_vfs);

	spin_lock(&sdp_lst_lock);
	list_add(&sdp->list, &sdp_dev_lst_head);
	spin_unlock(&sdp_lst_lock);

	return 0;

alloc_irqs_failed:
	iounmap(sdp->af_mbx_base);
pf_unusable:
	pcim_iounmap(pdev, sdp->bar2);
set_mask_failed:
	pci_release_regions(pdev);
map_failed:
	pci_disable_device(pdev);
enable_failed:
	pci_set_drvdata(pdev, NULL);
	devm_kfree(dev, sdp);
	return err;
}

static void sdp_remove(struct pci_dev *pdev)
{
	struct sdp_dev *sdp = pci_get_drvdata(pdev);


	spin_lock(&sdp_lst_lock);
	list_del(&sdp->list);
	spin_unlock(&sdp_lst_lock);

	if (sdp->num_vfs)
		__sriov_disable(pdev);

	sdp_free_irqs(pdev);

	if (sdp->af_mbx_base)
		iounmap(sdp->af_mbx_base);
	if (sdp->bar2)
		pcim_iounmap(pdev, sdp->bar2);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	devm_kfree(&pdev->dev, sdp);
}

static const struct pci_device_id rvu_sdp_id_table[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_OCTEONTX2_SDP_PF)},
	{0} /* end of table */
};

static struct pci_driver sdp_driver = {
	.name = DRV_NAME,
	.id_table = rvu_sdp_id_table,
	.probe = sdp_probe,
	.remove = sdp_remove,
	.sriov_configure = sdp_sriov_configure,
};

static int __init otx2_sdp_init_module(void)
{
	pr_info("%s\n", DRV_NAME);

	spin_lock_init(&sdp_lst_lock);
	return pci_register_driver(&sdp_driver);
}

static void __exit otx2_sdp_exit_module(void)
{
	pci_unregister_driver(&sdp_driver);
}

module_init(otx2_sdp_init_module);
module_exit(otx2_sdp_exit_module);
MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION("Marvell OcteonTX2 SDP PF Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, rvu_sdp_id_table);
