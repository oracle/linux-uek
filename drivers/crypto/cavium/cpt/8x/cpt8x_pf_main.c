// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "cpt8x_pf.h"

#define DRV_NAME	"octeontx-cpt"
#define DRV_VERSION	"1.0"

DEFINE_MUTEX(octeontx_cpt_devices_lock);
LIST_HEAD(octeontx_cpt_devices);

static void cpt_disable_mbox_interrupts(struct cpt_device *cpt)
{
	/* Clear mbox(0) interupts for all vfs */
	writeq(~0ull, cpt->reg_base + CPT_PF_MBOX_ENA_W1CX(0));
}

static void cpt_enable_mbox_interrupts(struct cpt_device *cpt)
{
	/* Set mbox(0) interupts for all vfs */
	writeq(~0ull, cpt->reg_base + CPT_PF_MBOX_ENA_W1SX(0));
}

static irqreturn_t cpt_mbx0_intr_handler(int irq, void *cpt_irq)
{
	struct cpt_device *cpt = (struct cpt_device *)cpt_irq;

	cpt_mbox_intr_handler(cpt, 0);

	return IRQ_HANDLED;
}

static void cpt_reset(struct cpt_device *cpt)
{
	writeq(1, cpt->reg_base + CPT_PF_RESET);
}

static void cpt_find_max_enabled_cores(struct cpt_device *cpt)
{
	union cptx_pf_constants pf_cnsts = {0};

	pf_cnsts.u = readq(cpt->reg_base + CPT_PF_CONSTANTS);
	cpt->eng_grps.avail.max_se_cnt = pf_cnsts.s.se;
	cpt->eng_grps.avail.max_ie_cnt = 0;
	cpt->eng_grps.avail.max_ae_cnt = pf_cnsts.s.ae;
}

static u32 cpt_check_bist_status(struct cpt_device *cpt)
{
	union cptx_pf_bist_status bist_sts = {0};

	bist_sts.u = readq(cpt->reg_base + CPT_PF_BIST_STATUS);
	return bist_sts.u;
}

static u64 cpt_check_exe_bist_status(struct cpt_device *cpt)
{
	union cptx_pf_exe_bist_status bist_sts = {0};

	bist_sts.u = readq(cpt->reg_base + CPT_PF_EXE_BIST_STATUS);
	return bist_sts.u;
}

static int cpt_device_init(struct cpt_device *cpt)
{
	u64 bist;
	u16 sdevid;
	struct device *dev = &cpt->pdev->dev;

	/* Reset the PF when probed first */
	cpt_reset(cpt);
	mdelay(100);

	pci_read_config_word(cpt->pdev, PCI_SUBSYSTEM_ID, &sdevid);

	/*Check BIST status*/
	bist = (u64)cpt_check_bist_status(cpt);
	if (bist) {
		dev_err(dev, "RAM BIST failed with code 0x%llx", bist);
		return -ENODEV;
	}

	bist = cpt_check_exe_bist_status(cpt);
	if (bist) {
		dev_err(dev, "Engine BIST failed with code 0x%llx", bist);
		return -ENODEV;
	}

	/*Get max enabled cores */
	cpt_find_max_enabled_cores(cpt);

	if (sdevid == CPT_81XX_PCI_PF_SUBSYS_ID) {
		cpt->pf_type = CPT_81XX;
	} else if ((sdevid == CPT_83XX_PCI_PF_SUBSYS_ID) &&
		   (cpt->eng_grps.avail.max_se_cnt == 0)) {
		cpt->pf_type = CPT_AE_83XX;
	} else if ((sdevid == CPT_83XX_PCI_PF_SUBSYS_ID) &&
		   (cpt->eng_grps.avail.max_ae_cnt == 0)) {
		cpt->pf_type = CPT_SE_83XX;
	}

	/* Get max VQs/VFs supported by the device */
	cpt->max_vfs = pci_sriov_get_totalvfs(cpt->pdev);

	/*TODO: Get CLK frequency*/
	/*Disable all cores*/
	cpt8x_disable_all_cores(cpt);
	/* PF is ready */
	cpt->flags |= CPT_FLAG_DEVICE_READY;

	return 0;
}

static int cpt_register_interrupts(struct cpt_device *cpt)
{
	int ret;
	struct device *dev = &cpt->pdev->dev;
	u32 num_vec = 0;
	u32 mbox_int_idx = ((cpt->pf_type == CPT_81XX) ?
			    CPT_81XX_PF_MBOX_INT :
			    CPT_83XX_PF_MBOX_INT);

	/* Enable MSI-X */
	num_vec = ((cpt->pf_type == CPT_81XX) ? CPT_81XX_PF_MSIX_VECTORS :
			CPT_83XX_PF_MSIX_VECTORS);
	ret = pci_alloc_irq_vectors(cpt->pdev, num_vec, num_vec, PCI_IRQ_MSIX);
	if (ret < 0) {
		dev_err(&cpt->pdev->dev, "Request for #%d msix vectors failed\n",
					num_vec);
		return ret;
	}

	/* Register mailbox interrupt handlers */
	ret = request_irq(pci_irq_vector(cpt->pdev,
				CPT_PF_INT_VEC_E_MBOXX(mbox_int_idx, 0)),
				cpt_mbx0_intr_handler, 0, "CPT Mbox0", cpt);
	if (ret)
		goto fail;

	/* Enable mailbox interrupt */
	cpt_enable_mbox_interrupts(cpt);
	return 0;

fail:
	dev_err(dev, "Request irq failed\n");
	pci_disable_msix(cpt->pdev);
	return ret;
}

static void cpt_unregister_interrupts(struct cpt_device *cpt)
{
	u32 mbox_int_idx = ((cpt->pf_type == CPT_81XX) ?
			    CPT_81XX_PF_MBOX_INT :
			    CPT_83XX_PF_MBOX_INT);

	cpt_disable_mbox_interrupts(cpt);
	free_irq(pci_irq_vector(cpt->pdev,
				CPT_PF_INT_VEC_E_MBOXX(mbox_int_idx, 0)), cpt);
	pci_disable_msix(cpt->pdev);
}


static int cpt_sriov_configure(struct pci_dev *pdev, int numvfs)
{
	struct cpt_device *cpt = pci_get_drvdata(pdev);
	int ret = -EBUSY, disable = 0;

	mutex_lock(&octeontx_cpt_devices_lock);
	if (cpt->vfs_in_use)
		goto exit;

	ret = 0;
	if (cpt->flags & CPT_FLAG_SRIOV_ENABLED)
		disable = 1;

	if (disable) {
		pci_disable_sriov(pdev);
		cpt_set_eng_grps_is_rdonly(&cpt->eng_grps, false);
		cpt->flags &= ~CPT_FLAG_SRIOV_ENABLED;
		cpt->vfs_enabled = 0;
	}

	if (numvfs > 0) {
		ret = cpt_try_create_default_eng_grps(cpt->pdev,
						      &cpt->eng_grps);
		if (ret)
			goto exit;

		cpt->vfs_enabled = numvfs;
		ret = pci_enable_sriov(pdev, numvfs);
		if (ret) {
			cpt->vfs_enabled = 0;
			goto exit;
		}

		cpt_set_eng_grps_is_rdonly(&cpt->eng_grps, true);
		cpt->flags |= CPT_FLAG_SRIOV_ENABLED;
		ret = numvfs;
	}

	dev_notice(&cpt->pdev->dev, "VFs enabled: %d\n", ret);
exit:
	mutex_unlock(&octeontx_cpt_devices_lock);
	return ret;
}

static int cpt_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct cpt_device *cpt;
	int err;

	cpt = devm_kzalloc(dev, sizeof(*cpt), GFP_KERNEL);
	if (!cpt)
		return -ENOMEM;

	pci_set_drvdata(pdev, cpt);
	cpt->pdev = pdev;

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		pci_set_drvdata(pdev, NULL);
		return err;
	}

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed 0x%x\n", err);
		goto cpt_err_disable_device;
	}

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to get usable DMA configuration\n");
		goto cpt_err_release_regions;
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to get 48-bit DMA for consistent allocations\n");
		goto cpt_err_release_regions;
	}

	/* MAP PF's configuration registers */
	cpt->reg_base = pcim_iomap(pdev, PCI_CPT_PF_8X_CFG_BAR, 0);
	if (!cpt->reg_base) {
		dev_err(dev, "Cannot map config register space, aborting\n");
		err = -ENOMEM;
		goto cpt_err_release_regions;
	}

	/* CPT device HW initialization */
	cpt_device_init(cpt);

	/* Register interrupts */
	err = cpt_register_interrupts(cpt);
	if (err)
		goto cpt_err_release_regions;

	/* Initialize engine groups */
	err = cpt_init_eng_grps(pdev, &cpt->eng_grps, cpt8x_get_ucode_ops(),
				cpt->pf_type);
	if (err)
		goto cpt_err_unregister_interrupts;

	INIT_LIST_HEAD(&cpt->list);
	mutex_lock(&octeontx_cpt_devices_lock);
	list_add(&cpt->list, &octeontx_cpt_devices);
	mutex_unlock(&octeontx_cpt_devices_lock);

	return 0;

cpt_err_unregister_interrupts:
	cpt_unregister_interrupts(cpt);
cpt_err_release_regions:
	pci_release_regions(pdev);
cpt_err_disable_device:
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	return err;
}

static void cpt_remove(struct pci_dev *pdev)
{
	struct cpt_device *cpt = pci_get_drvdata(pdev);
	struct cpt_device *curr;

	if (!cpt)
		return;

	mutex_lock(&octeontx_cpt_devices_lock);
	list_for_each_entry(curr, &octeontx_cpt_devices, list) {
		if (curr == cpt) {
			list_del(&cpt->list);
			break;
		}
	}
	mutex_unlock(&octeontx_cpt_devices_lock);

	/* Disable VFs */
	pci_disable_sriov(pdev);
	/* Cleanup engine groups */
	cpt_cleanup_eng_grps(pdev, &cpt->eng_grps);
	/* Disable CPT PF interrupts */
	cpt_unregister_interrupts(cpt);
	/* Disengage SE and AE cores from all groups*/
	cpt8x_disable_all_cores(cpt);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

/* Supported devices */
static const struct pci_device_id cpt_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, CPT_PCI_PF_8X_DEVICE_ID) },
	{ 0, }  /* end of table */
};

static struct pci_driver cpt_pci_driver = {
	.name = DRV_NAME,
	.id_table = cpt_id_table,
	.probe = cpt_probe,
	.remove = cpt_remove,
	.sriov_configure = cpt_sriov_configure
};

module_pci_driver(cpt_pci_driver);

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION("Marvell OcteonTX CPT Physical Function Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, cpt_id_table);
