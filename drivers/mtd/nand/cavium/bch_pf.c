/*
 * Copyright (C) 2018 Cavium, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License
 * as published by the Free Software Foundation.
 */

#include <linux/device.h>
#include <linux/firmware.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/printk.h>
#include <linux/version.h>

#include "bch_pf.h"

#define DRV_NAME	"thunder-bch"
#define DRV_VERSION	"1.0"

static bool no_vf; /* no auto-config of VFs, allow their use in guest kernel */
module_param(no_vf, bool, 0444);

DEFINE_MUTEX(octeontx_bch_devices_lock);
LIST_HEAD(octeontx_bch_devices);

static unsigned int num_vfs = BCH_NR_VF;

static void bch_enable_interrupts(struct bch_device *bch)
{
	writeq(~0ull, bch->reg_base + BCH_ERR_INT_ENA_W1S);
}

static int do_bch_init(struct bch_device *bch)
{
	int ret = 0;

	bch_enable_interrupts(bch);

	return ret;
}

static irqreturn_t bch_intr_handler(int irq, void *bch_irq)
{
	struct bch_device *bch = (struct bch_device *)bch_irq;
	u64 ack = readq(bch->reg_base + BCH_ERR_INT);

	writeq(ack, bch->reg_base + BCH_ERR_INT);
	return IRQ_HANDLED;
}

static void bch_reset(struct bch_device *bch)
{
	writeq(1, bch->reg_base + BCH_CTL);
	mdelay(2);
}

static void bch_disable(struct bch_device *bch)
{
	writeq(~0ull, bch->reg_base + BCH_ERR_INT_ENA_W1C);
	writeq(~0ull, bch->reg_base + BCH_ERR_INT);
	bch_reset(bch);
}

static u32 bch_check_bist_status(struct bch_device *bch)
{
	return readq(bch->reg_base + BCH_BIST_RESULT);
}

static int bch_device_init(struct bch_device *bch)
{
	u64 bist;
	u16 sdevid;
	int rc;
	struct device *dev = &bch->pdev->dev;

	/* Reset the PF when probed first */
	bch_reset(bch);

	pci_read_config_word(bch->pdev, PCI_SUBSYSTEM_ID, &sdevid);

	/*Check BIST status*/
	bist = (u64)bch_check_bist_status(bch);
	if (bist) {
		dev_err(dev, "BCH BIST failed with code 0x%llx", bist);
		return -ENODEV;
	}

	/* Get max VQs/VFs supported by the device */
	bch->max_vfs = pci_sriov_get_totalvfs(bch->pdev);
	if (num_vfs > bch->max_vfs) {
		dev_warn(dev, "Num of VFs to enable %d is greater than max available. Enabling %d VFs.\n",
			 num_vfs, bch->max_vfs);
		num_vfs = bch->max_vfs;
	}
	/* Get number of VQs/VFs to be enabled */
	bch->vfs_enabled = num_vfs;

	/*TODO: Get CLK frequency*/
	/*Reset device parameters*/
	rc = do_bch_init(bch);

	return rc;
}

static int bch_register_interrupts(struct bch_device *bch)
{
	int ret;
	struct device *dev = &bch->pdev->dev;
	u32 num_vec = BCH_MSIX_VECTORS;

	/* Enable MSI-X */
	ret = pci_alloc_irq_vectors(bch->pdev, num_vec, num_vec, PCI_IRQ_MSIX);
	if (ret < 0) {
		dev_err(&bch->pdev->dev, "Request for #%d msix vectors failed\n",
					num_vec);
		return ret;
	}

	/* Register error interrupt handlers */
	ret = request_irq(pci_irq_vector(bch->pdev, 0),
			bch_intr_handler, 0, "BCH", bch);
	if (ret)
		goto fail;

	/* Enable error interrupt */
	bch_enable_interrupts(bch);
	return 0;

fail:
	dev_err(dev, "Request irq failed\n");
	pci_disable_msix(bch->pdev);
	return ret;
}

static void bch_unregister_interrupts(struct bch_device *bch)
{
	free_irq(pci_irq_vector(bch->pdev, 0), bch);
	pci_disable_msix(bch->pdev);
}


static int bch_sriov_configure(struct pci_dev *pdev, int numvfs)
{
	struct bch_device *bch = pci_get_drvdata(pdev);
	int tmp, ret = -EBUSY, disable = 0;

	mutex_lock(&octeontx_bch_devices_lock);
	if (bch->vfs_in_use)
		goto exit;

	ret = 0;
	tmp = bch->vfs_enabled;
	if (bch->flags & BCH_FLAG_SRIOV_ENABLED)
		disable = 1;

	if (disable) {
		pci_disable_sriov(pdev);
		bch->flags &= ~BCH_FLAG_SRIOV_ENABLED;
		bch->vfs_enabled = 0;
	}

	if (numvfs > 0) {
		bch->vfs_enabled = numvfs;
		ret = pci_enable_sriov(pdev, numvfs);
		if (ret == 0) {
			bch->flags |= BCH_FLAG_SRIOV_ENABLED;
			ret = numvfs;
		} else {
			bch->vfs_enabled = tmp;
		}
	}

	dev_notice(&bch->pdev->dev, "VFs enabled: %d\n", ret);
exit:
	mutex_unlock(&octeontx_bch_devices_lock);
	return ret;
}

static void *token = (void *)(-EPROBE_DEFER);

static int bch_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct bch_device *bch;
	int err;

	/* unsafe on CN81XX pass 1.0/1.1 */
	if (MIDR_IS_CPU_MODEL_RANGE(read_cpuid_id(),
			MIDR_OCTEON_T81, 0x00, 0x01))
		return -ENODEV;

	bch = devm_kzalloc(dev, sizeof(*bch), GFP_KERNEL);
	if (!bch)
		return -ENOMEM;

	pci_set_drvdata(pdev, bch);
	bch->pdev = pdev;
	err = pci_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		pci_set_drvdata(pdev, NULL);
		return err;
	}

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed 0x%x\n", err);
		goto bch_err_disable_device;
	}

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to get usable DMA configuration\n");
		goto bch_err_release_regions;
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to get 48-bit DMA for consistent allocations\n");
		goto bch_err_release_regions;
	}

	/* MAP PF's configuration registers */
	bch->reg_base = pcim_iomap(pdev, 0, 0);
	if (!bch->reg_base) {
		dev_err(dev, "Cannot map config register space, aborting\n");
		err = -ENOMEM;
		goto bch_err_release_regions;
	}

	bch_device_init(bch);

	/* Register interrupts */
	err = bch_register_interrupts(bch);
	if (err)
		goto bch_err_release_regions;

	INIT_LIST_HEAD(&bch->list);
	mutex_lock(&octeontx_bch_devices_lock);
	list_add(&bch->list, &octeontx_bch_devices);
	token = (void *)pdev;
	mutex_unlock(&octeontx_bch_devices_lock);

	if (!no_vf)
		bch_sriov_configure(pdev, num_vfs);

	return 0;

bch_err_release_regions:
	pci_release_regions(pdev);
bch_err_disable_device:
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	return err;
}

static void bch_remove(struct pci_dev *pdev)
{
	struct bch_device *bch = pci_get_drvdata(pdev);
	struct bch_device *curr;

	if (!bch)
		return;

	mutex_lock(&octeontx_bch_devices_lock);
	token = ERR_PTR(-EPROBE_DEFER);
	bch_disable(bch);
	list_for_each_entry(curr, &octeontx_bch_devices, list) {
		if (curr == bch) {
			list_del(&bch->list);
			break;
		}
	}
	mutex_unlock(&octeontx_bch_devices_lock);

	pci_disable_sriov(pdev);
	bch_unregister_interrupts(bch);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}


/* get/put async wrt probe, from cavium_nand or copy client */
void *cavm_bch_getp(void)
{
	try_module_get(THIS_MODULE);
	return token;
}
EXPORT_SYMBOL(cavm_bch_getp);

void cavm_bch_putp(void *token)
{
	if (token)
		module_put(THIS_MODULE);
}
EXPORT_SYMBOL(cavm_bch_putp);

/* Supported devices */
static const struct pci_device_id bch_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, BCH_PCI_PF_DEVICE_ID) },
	{ 0, }  /* end of table */
};

static struct pci_driver bch_pci_driver = {
	.name = DRV_NAME,
	.id_table = bch_id_table,
	.probe = bch_probe,
	.remove = bch_remove,
	.sriov_configure = bch_sriov_configure
};

module_pci_driver(bch_pci_driver);

MODULE_AUTHOR("Cavium Inc");
MODULE_DESCRIPTION("Cavium Thunder BCH Physical Function Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, bch_id_table);
