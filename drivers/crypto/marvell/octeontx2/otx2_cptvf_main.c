// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "otx2_cpt_mbox_common.h"
#include "rvu_reg.h"

#define OTX2_CPT_DRV_NAME "octeontx2-cptvf"
#define OTX2_CPT_DRV_VERSION "1.0"

static void cptvf_enable_pfvf_mbox_intrs(struct otx2_cptvf_dev *cptvf)
{
	/* Clear interrupt if any */
	otx2_cpt_write64(cptvf->reg_base, BLKADDR_RVUM, 0, OTX2_RVU_VF_INT,
			 0x1ULL);

	/* Enable PF-VF interrupt */
	otx2_cpt_write64(cptvf->reg_base, BLKADDR_RVUM, 0,
			 OTX2_RVU_VF_INT_ENA_W1S, 0x1ULL);
}

static void cptvf_disable_pfvf_mbox_intrs(struct otx2_cptvf_dev *cptvf)
{
	/* Disable PF-VF interrupt */
	otx2_cpt_write64(cptvf->reg_base, BLKADDR_RVUM, 0,
			 OTX2_RVU_VF_INT_ENA_W1C, 0x1ULL);

	/* Clear interrupt if any */
	otx2_cpt_write64(cptvf->reg_base, BLKADDR_RVUM, 0, OTX2_RVU_VF_INT,
			 0x1ULL);
}

static int cptvf_register_interrupts(struct otx2_cptvf_dev *cptvf)
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
			  OTX2_CPT_VF_INT_VEC_E_MBOX),
			  otx2_cptvf_pfvf_mbox_intr,
			  0, "CPTPFVF Mbox", cptvf);
	if (ret)
		goto free_irq;
	return 0;
free_irq:
	dev_err(&cptvf->pdev->dev, "Failed to register interrupts\n");
	pci_free_irq_vectors(cptvf->pdev);
	return ret;
}

static void cptvf_unregister_interrupts(struct otx2_cptvf_dev *cptvf)
{
	free_irq(pci_irq_vector(cptvf->pdev, OTX2_CPT_VF_INT_VEC_E_MBOX),
		 cptvf);
	pci_free_irq_vectors(cptvf->pdev);
}

static int cptvf_pfvf_mbox_init(struct otx2_cptvf_dev *cptvf)
{
	int ret;

	cptvf->pfvf_mbox_wq = alloc_workqueue("cpt_pfvf_mailbox",
					      WQ_UNBOUND | WQ_HIGHPRI |
					      WQ_MEM_RECLAIM, 1);
	if (!cptvf->pfvf_mbox_wq)
		return -ENOMEM;

	ret = otx2_mbox_init(&cptvf->pfvf_mbox, cptvf->pfvf_mbox_base,
			     cptvf->pdev, cptvf->reg_base, MBOX_DIR_VFPF, 1);
	if (ret)
		goto free_wqe;

	INIT_WORK(&cptvf->pfvf_mbox_work, otx2_cptvf_pfvf_mbox_handler);
	return 0;
free_wqe:
	flush_workqueue(cptvf->pfvf_mbox_wq);
	destroy_workqueue(cptvf->pfvf_mbox_wq);
	return ret;
}

static void cptvf_pfvf_mbox_destroy(struct otx2_cptvf_dev *cptvf)
{
	flush_workqueue(cptvf->pfvf_mbox_wq);
	destroy_workqueue(cptvf->pfvf_mbox_wq);
	otx2_mbox_destroy(&cptvf->pfvf_mbox);
}

static int otx2_cptvf_probe(struct pci_dev *pdev,
			    const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct otx2_cptvf_dev *cptvf;
	int ret, kcrypto_lfs;

	cptvf = kzalloc(sizeof(*cptvf), GFP_KERNEL);
	if (!cptvf)
		return -ENOMEM;

	pci_set_drvdata(pdev, cptvf);
	cptvf->pdev = pdev;

	ret = pci_enable_device(pdev);
	if (ret) {
		dev_err(dev, "Failed to enable PCI device\n");
		goto clear_drvdata;
	}

	pci_set_master(pdev);

	ret = pci_request_regions(pdev, OTX2_CPT_DRV_NAME);
	if (ret) {
		dev_err(dev, "PCI request regions failed 0x%x\n", ret);
		goto disable_device;
	}

	ret = pci_set_dma_mask(pdev, DMA_BIT_MASK(48));
	if (ret) {
		dev_err(dev, "Unable to get usable DMA configuration\n");
		goto release_regions;
	}

	ret = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(48));
	if (ret) {
		dev_err(dev, "Unable to get 48-bit DMA for consistent allocations\n");
		goto release_regions;
	}

	/* Map VF's configuration registers */
	cptvf->reg_base = pci_iomap(pdev, PCI_PF_REG_BAR_NUM, 0);
	if (!cptvf->reg_base) {
		dev_err(dev, "Unable to map BAR2\n");
		ret = -ENOMEM;
		goto release_regions;
	}

	/* Map PF-VF mailbox memory */
	cptvf->pfvf_mbox_base = ioremap_wc(pci_resource_start(cptvf->pdev,
					   PCI_MBOX_BAR_NUM),
					   pci_resource_len(cptvf->pdev,
					   PCI_MBOX_BAR_NUM));
	if (!cptvf->pfvf_mbox_base) {
		dev_err(&pdev->dev, "Unable to map BAR4\n");
		ret = -ENODEV;
		goto pci_unmap;
	}

	/* Initialize PF-VF mailbox */
	ret = cptvf_pfvf_mbox_init(cptvf);
	if (ret)
		goto iounmap_pfvf;

	/* Register interrupts */
	ret = cptvf_register_interrupts(cptvf);
	if (ret)
		goto destroy_pfvf_mbox;

	/* Enable PF-VF mailbox interrupts */
	cptvf_enable_pfvf_mbox_intrs(cptvf);

	/* Send ready message */
	ret = otx2_cpt_send_ready_msg(cptvf->pdev);
	if (ret)
		goto unregister_interrupts;

	/* Get engine group number for symmetric crypto */
	cptvf->lfs.kcrypto_eng_grp_num = OTX2_CPT_INVALID_CRYPTO_ENG_GRP;
	ret = otx2_cptvf_send_eng_grp_num_msg(cptvf, OTX2_CPT_SE_TYPES);
	if (ret)
		goto unregister_interrupts;

	if (cptvf->lfs.kcrypto_eng_grp_num == OTX2_CPT_INVALID_CRYPTO_ENG_GRP) {
		dev_err(dev, "Engine group for kernel crypto not available\n");
		ret = -ENOENT;
		goto unregister_interrupts;
	}
	ret = otx2_cptvf_send_kcrypto_limits_msg(cptvf);
	if (ret)
		goto unregister_interrupts;

	kcrypto_lfs = cptvf->lfs.kcrypto_limits ? cptvf->lfs.kcrypto_limits :
		      num_online_cpus();
	/* Initialize CPT LFs */
	ret = otx2_cptvf_lf_init(pdev, cptvf->reg_base, &cptvf->lfs,
				 kcrypto_lfs);
	if (ret)
		goto unregister_interrupts;

	return 0;

unregister_interrupts:
	cptvf_disable_pfvf_mbox_intrs(cptvf);
	cptvf_unregister_interrupts(cptvf);
destroy_pfvf_mbox:
	cptvf_pfvf_mbox_destroy(cptvf);
iounmap_pfvf:
	iounmap(cptvf->pfvf_mbox_base);
pci_unmap:
	pci_iounmap(pdev, cptvf->reg_base);
release_regions:
	pci_release_regions(pdev);
disable_device:
	pci_disable_device(pdev);
clear_drvdata:
	pci_set_drvdata(pdev, NULL);
	kfree(cptvf);

	return ret;
}

static void otx2_cptvf_remove(struct pci_dev *pdev)
{
	struct otx2_cptvf_dev *cptvf = pci_get_drvdata(pdev);

	if (!cptvf) {
		dev_err(&pdev->dev, "Invalid CPT VF device.\n");
		return;
	}

	/* Shutdown CPT LFs */
	if (otx2_cptvf_lf_shutdown(pdev, &cptvf->lfs))
		dev_err(&pdev->dev, "CPT LFs shutdown failed.\n");
	/* Disable PF-VF mailbox interrupt */
	cptvf_disable_pfvf_mbox_intrs(cptvf);
	/* Unregister interrupts */
	cptvf_unregister_interrupts(cptvf);
	/* Destroy PF-VF mbox */
	cptvf_pfvf_mbox_destroy(cptvf);
	/* Unmap PF-VF mailbox memory */
	iounmap(cptvf->pfvf_mbox_base);
	pci_iounmap(pdev, cptvf->reg_base);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	kfree(cptvf);
}

/* Supported devices */
static const struct pci_device_id otx2_cptvf_id_table[] = {
	{PCI_VDEVICE(CAVIUM, OTX2_CPT_PCI_VF_DEVICE_ID), 0},
	{ 0, }  /* end of table */
};

static struct pci_driver otx2_cptvf_pci_driver = {
	.name = OTX2_CPT_DRV_NAME,
	.id_table = otx2_cptvf_id_table,
	.probe = otx2_cptvf_probe,
	.remove = otx2_cptvf_remove,
};

module_pci_driver(otx2_cptvf_pci_driver);

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION("Marvell OcteonTX2 CPT Virtual Function Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(OTX2_CPT_DRV_VERSION);
MODULE_DEVICE_TABLE(pci, otx2_cptvf_id_table);
