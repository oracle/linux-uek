// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "cpt9x_mbox_common.h"
#include "cpt9x_passthrough.h"
#include "otx2_reg.h"
#include "rvu_reg.h"

#define DRV_NAME	"octeontx2-cptvf"
#define DRV_VERSION	"1.0"

static unsigned int cpt_block_num;
module_param(cpt_block_num, uint, 0644);
MODULE_PARM_DESC(cpt_block_num, "cpt block number (0=CPT0 1=CPT1, default 0)");

static void cptvf_enable_pfvf_mbox_intrs(struct cptvf_dev *cptvf)
{
	/* Clear interrupt if any */
	cpt_write64(cptvf->reg_base, BLKADDR_RVUM, 0, RVU_VF_INT, 0x1ULL);

	/* Enable PF-VF interrupt */
	cpt_write64(cptvf->reg_base, BLKADDR_RVUM, 0, RVU_VF_INT_ENA_W1S,
		    0x1ULL);
}

static void cptvf_disable_pfvf_mbox_intrs(struct cptvf_dev *cptvf)
{
	/* Disable PF-VF interrupt */
	cpt_write64(cptvf->reg_base, BLKADDR_RVUM, 0, RVU_VF_INT_ENA_W1C,
		    0x1ULL);

	/* Clear interrupt if any */
	cpt_write64(cptvf->reg_base, BLKADDR_RVUM, 0, RVU_VF_INT, 0x1ULL);
}

static int cptvf_register_interrupts(struct cptvf_dev *cptvf)
{
	u32 num_vec;
	int ret;

	num_vec = pci_msix_vec_count(cptvf->pdev);
	if (num_vec <= 0)
		return -EINVAL;

	/* Enable MSI-X */
	ret = pci_alloc_irq_vectors(cptvf->pdev, num_vec, num_vec,
				    PCI_IRQ_MSIX);
	if (ret < 0) {
		dev_err(&cptvf->pdev->dev,
			"Request for %d msix vectors failed\n", num_vec);
		return ret;
	}

	/* Register VF-PF mailbox interrupt handler */
	ret = request_irq(pci_irq_vector(cptvf->pdev,
			  CPT_9X_VF_INT_VEC_E_MBOX), cptvf_pfvf_mbox_intr,
			  0, "CPTPFVF Mbox", cptvf);
	if (ret)
		goto err;
	return 0;
err:
	dev_err(&cptvf->pdev->dev, "Failed to register interrupts\n");
	pci_free_irq_vectors(cptvf->pdev);
	return ret;
}

static void cptvf_unregister_interrupts(struct cptvf_dev *cptvf)
{
	free_irq(pci_irq_vector(cptvf->pdev, CPT_9X_VF_INT_VEC_E_MBOX), cptvf);
	pci_free_irq_vectors(cptvf->pdev);
}

static int cptvf_pfvf_mbox_init(struct cptvf_dev *cptvf)
{
	int err;

	cptvf->pfvf_mbox_wq = alloc_workqueue("cpt_pfvf_mailbox",
					      WQ_UNBOUND | WQ_HIGHPRI |
					      WQ_MEM_RECLAIM, 1);
	if (!cptvf->pfvf_mbox_wq)
		return -ENOMEM;

	err = otx2_mbox_init(&cptvf->pfvf_mbox, cptvf->pfvf_mbox_base,
			     cptvf->pdev, cptvf->reg_base, MBOX_DIR_VFPF, 1);
	if (err)
		goto error;

	INIT_WORK(&cptvf->pfvf_mbox_work, cptvf_pfvf_mbox_handler);
	return 0;
error:
	flush_workqueue(cptvf->pfvf_mbox_wq);
	destroy_workqueue(cptvf->pfvf_mbox_wq);
	return err;
}

static void cptvf_pfvf_mbox_destroy(struct cptvf_dev *cptvf)
{
	flush_workqueue(cptvf->pfvf_mbox_wq);
	destroy_workqueue(cptvf->pfvf_mbox_wq);
	otx2_mbox_destroy(&cptvf->pfvf_mbox);
}

static ssize_t cptvf_passthrough_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct pci_dev *pdev;
	int ret;

	pdev = container_of(dev, struct pci_dev, dev);
	ret = run_passthrough_test(pdev, buf, count);
	if (ret != -EINPROGRESS)
		dev_err(dev, "Passthrough test failed %d\n", ret);

	return strlen(buf);
}

static DEVICE_ATTR(passthrough_test, 0220, NULL, cptvf_passthrough_store);

static struct attribute *octtx_attrs[] = {
	&dev_attr_passthrough_test.attr,
	NULL
};

static const struct attribute_group octtx_attr_group = {
	.attrs = octtx_attrs,
};

static int cptvf_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct cptvf_dev *cptvf;
	int err;

	cptvf = devm_kzalloc(dev, sizeof(*cptvf), GFP_KERNEL);
	if (!cptvf)
		return -ENOMEM;

	pci_set_drvdata(pdev, cptvf);
	cptvf->pdev = pdev;

	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		goto cpt_err_set_drvdata;
	}

	pci_set_master(pdev);

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed 0x%x\n", err);
		goto cpt_err_set_drvdata;
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

	/* Map VF's configuration registers */
	cptvf->reg_base = pcim_iomap(pdev, PCI_PF_REG_BAR_NUM, 0);
	if (!cptvf->reg_base) {
		dev_err(dev, "Unable to map BAR2\n");
		err = -ENOMEM;
		goto cpt_err_release_regions;
	}

	/* Map PF-VF mailbox memory */
	cptvf->pfvf_mbox_base = ioremap_wc(pci_resource_start(cptvf->pdev,
					   PCI_MBOX_BAR_NUM),
					   pci_resource_len(cptvf->pdev,
					   PCI_MBOX_BAR_NUM));
	if (!cptvf->pfvf_mbox_base) {
		dev_err(&pdev->dev, "Unable to map BAR4\n");
		err = -ENODEV;
		goto cpt_err_release_regions;
	}

	/* Initialize PF-VF mailbox */
	err = cptvf_pfvf_mbox_init(cptvf);
	if (err)
		goto cpt_err_iounmap;

	/* Register interrupts */
	err = cptvf_register_interrupts(cptvf);
	if (err)
		goto cpt_err_destroy_pfvf_mbox;

	/* Enable PF-VF mailbox interrupts */
	cptvf_enable_pfvf_mbox_intrs(cptvf);

	/* Send ready message */
	err = cpt_send_ready_msg(cptvf->pdev);
	if (err)
		goto cpt_err_unregister_interrupts;

	/* Get engine group number for symmetric crypto */
	cptvf->lfs.kcrypto_eng_grp_num = INVALID_CRYPTO_ENG_GRP;
	err = cptvf_send_eng_grp_num_msg(cptvf, SE_TYPES);
	if (err)
		goto cpt_err_unregister_interrupts;
	if (cptvf->lfs.kcrypto_eng_grp_num == INVALID_CRYPTO_ENG_GRP) {
		dev_err(dev, "Engine group for kernel crypto not available");
		err = -ENOENT;
		goto cpt_err_unregister_interrupts;
	}

	/* Get available CPT LF resources count */
	err = cpt_get_rsrc_cnt(cptvf->pdev);
	if (err)
		goto cpt_err_unregister_interrupts;

	/* Create sysfs entries */
	err = sysfs_create_group(&dev->kobj, &octtx_attr_group);
	if (err)
		goto cpt_err_remove_sysfs;

	cptvf->blkaddr = (cpt_block_num == 0) ? BLKADDR_CPT0 : BLKADDR_CPT1;
	/* Initialize CPT LFs */
	err = cptlf_init(pdev, cptvf->reg_base, &cptvf->lfs,
			 cptvf->limits.cpt);
	if (err)
		goto cpt_err_unregister_interrupts;

	return 0;

cpt_err_remove_sysfs:
	sysfs_remove_group(&pdev->dev.kobj, &octtx_attr_group);
cpt_err_unregister_interrupts:
	cptvf_disable_pfvf_mbox_intrs(cptvf);
	cptvf_unregister_interrupts(cptvf);
cpt_err_destroy_pfvf_mbox:
	cptvf_pfvf_mbox_destroy(cptvf);
cpt_err_iounmap:
	iounmap(cptvf->pfvf_mbox_base);
cpt_err_release_regions:
	pci_release_regions(pdev);
cpt_err_set_drvdata:
	pci_set_drvdata(pdev, NULL);

	return err;
}

static void cptvf_remove(struct pci_dev *pdev)
{
	struct cptvf_dev *cptvf = pci_get_drvdata(pdev);

	if (!cptvf) {
		dev_err(&pdev->dev, "Invalid CPT VF device.\n");
		return;
	}

	/* Remove sysfs entries */
	sysfs_remove_group(&pdev->dev.kobj, &octtx_attr_group);
	/* Shutdown CPT LFs */
	if (cptlf_shutdown(pdev, &cptvf->lfs))
		dev_err(&pdev->dev, "CPT LFs shutdown failed.\n");
	/* Disable PF-VF mailbox interrupt */
	cptvf_disable_pfvf_mbox_intrs(cptvf);
	/* Unregister interrupts */
	cptvf_unregister_interrupts(cptvf);
	/* Destroy PF-VF mbox */
	cptvf_pfvf_mbox_destroy(cptvf);
	/* Unmap PF-VF mailbox memory */
	iounmap(cptvf->pfvf_mbox_base);

	pci_release_regions(pdev);
	pci_set_drvdata(pdev, NULL);
}

/* Supported devices */
static const struct pci_device_id cptvf_id_table[] = {
	{PCI_VDEVICE(CAVIUM, CPT_PCI_VF_9X_DEVICE_ID), 0},
	{ 0, }  /* end of table */
};

static struct pci_driver cptvf_pci_driver = {
	.name = DRV_NAME,
	.id_table = cptvf_id_table,
	.probe = cptvf_probe,
	.remove = cptvf_remove,
};

module_pci_driver(cptvf_pci_driver);

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION("Marvell OcteonTX2 CPT Virtual Function Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, cptvf_id_table);
