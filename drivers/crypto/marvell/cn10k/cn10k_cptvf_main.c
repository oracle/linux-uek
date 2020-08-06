// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020 Marvell. */

#include "cn10k_cpt_mbox_common.h"
#include "rvu_reg.h"

#define CN10K_CPTVF_DRV_NAME    "cn10k-cptvf"
#define CN10K_CPTVF_DRV_STRING  "Marvell OcteonTX3 CPT Virtual Function Driver"
#define CN10K_CPTVF_DRV_VERSION "1.0"

static void cptvf_enable_pfvf_mbox_intrs(struct cn10k_cptvf_dev *cptvf)
{
	/* Clear interrupt if any */
	cn10k_cpt_write64(cptvf->reg_base, BLKADDR_RVUM, 0, CN10K_RVU_VF_INT,
			  0x1ULL);

	/* Enable PF-VF interrupt */
	cn10k_cpt_write64(cptvf->reg_base, BLKADDR_RVUM, 0,
			  CN10K_RVU_VF_INT_ENA_W1S, 0x1ULL);
}

static void cptvf_disable_pfvf_mbox_intrs(struct cn10k_cptvf_dev *cptvf)
{
	/* Disable PF-VF interrupt */
	cn10k_cpt_write64(cptvf->reg_base, BLKADDR_RVUM, 0,
			  CN10K_RVU_VF_INT_ENA_W1C, 0x1ULL);

	/* Clear interrupt if any */
	cn10k_cpt_write64(cptvf->reg_base, BLKADDR_RVUM, 0, CN10K_RVU_VF_INT,
			  0x1ULL);
}

static int cptvf_register_interrupts(struct cn10k_cptvf_dev *cptvf)
{
	int ret, irq;
	u32 num_vec;

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
	irq = pci_irq_vector(cptvf->pdev, CN10K_CPT_VF_INT_VEC_E_MBOX);
	/* Register VF-PF mailbox interrupt handler */
	ret = devm_request_irq(&cptvf->pdev->dev, irq,
			       cn10k_cptvf_pfvf_mbox_intr, 0,
			       "CPTPFVF Mbox", cptvf);
	return ret;
}

static int cptvf_pfvf_mbox_init(struct cn10k_cptvf_dev *cptvf)
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

	ret = cn10k_cpt_mbox_bbuf_init(cptvf, cptvf->pdev);
	if (ret)
		goto destroy_mbox;

	INIT_WORK(&cptvf->pfvf_mbox_work, cn10k_cptvf_pfvf_mbox_handler);
	return 0;

destroy_mbox:
	otx2_mbox_destroy(&cptvf->pfvf_mbox);
free_wqe:
	destroy_workqueue(cptvf->pfvf_mbox_wq);
	return ret;
}

static void cptvf_pfvf_mbox_destroy(struct cn10k_cptvf_dev *cptvf)
{
	destroy_workqueue(cptvf->pfvf_mbox_wq);
	otx2_mbox_destroy(&cptvf->pfvf_mbox);
}

static int cn10k_cptvf_probe(struct pci_dev *pdev,
			     const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	resource_size_t offset, size;
	struct cn10k_cptvf_dev *cptvf;
	int ret, kcrypto_lfs;

	cptvf = devm_kzalloc(dev, sizeof(*cptvf), GFP_KERNEL);
	if (!cptvf)
		return -ENOMEM;

	pci_set_drvdata(pdev, cptvf);
	cptvf->pdev = pdev;

	ret = pcim_enable_device(pdev);
	if (ret) {
		dev_err(dev, "Failed to enable PCI device\n");
		goto clear_drvdata;
	}
	pci_set_master(pdev);

	ret = pci_set_dma_mask(pdev, DMA_BIT_MASK(48));
	if (ret) {
		dev_err(dev, "Unable to get usable DMA configuration\n");
		goto clear_drvdata;
	}

	ret = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(48));
	if (ret) {
		dev_err(dev, "Unable to get 48-bit DMA for consistent allocations\n");
		goto clear_drvdata;
	}

	/* Map VF's configuration registers */
	ret = pcim_iomap_regions_request_all(pdev, 1 << PCI_PF_REG_BAR_NUM,
					     CN10K_CPTVF_DRV_NAME);
	if (ret) {
		dev_err(dev, "Couldn't get PCI resources 0x%x\n", ret);
		goto clear_drvdata;
	}
	cptvf->reg_base = pcim_iomap_table(pdev)[PCI_PF_REG_BAR_NUM];
	/*
	 * VF accesses PF-VF DRAM mailboxes via BAR2 indirect access.
	 * VF uses base address 0xC0000
	 */
	cptvf->pfvf_mbox_base = cptvf->reg_base + 0xC0000;

	offset = pci_resource_start(pdev, PCI_MBOX_BAR_NUM);
	size = pci_resource_len(pdev, PCI_MBOX_BAR_NUM);
	/* Map VF LMILINE region */
	cptvf->lfs.lmtline_base = devm_ioremap_wc(dev, offset, size);
	if (!cptvf->lfs.lmtline_base) {
		dev_err(&pdev->dev, "Unable to map BAR4\n");
		ret = -ENODEV;
		goto clear_drvdata;
	}
	/* Initialize PF-VF mailbox */
	ret = cptvf_pfvf_mbox_init(cptvf);
	if (ret)
		goto clear_drvdata;

	/* Register interrupts */
	ret = cptvf_register_interrupts(cptvf);
	if (ret)
		goto destroy_pfvf_mbox;

	/* Enable PF-VF mailbox interrupts */
	cptvf_enable_pfvf_mbox_intrs(cptvf);

	/* Send ready message */
	ret = cn10k_cpt_send_ready_msg(cptvf->pdev);
	if (ret)
		goto unregister_interrupts;

	/* Get engine group number for symmetric crypto */
	cptvf->lfs.kcrypto_eng_grp_num = CN10K_CPT_INVALID_CRYPTO_ENG_GRP;
	ret = cn10k_cptvf_send_eng_grp_num_msg(cptvf, CN10K_CPT_SE_TYPES);
	if (ret)
		goto unregister_interrupts;

	if (cptvf->lfs.kcrypto_eng_grp_num ==
	    CN10K_CPT_INVALID_CRYPTO_ENG_GRP) {
		dev_err(dev, "Engine group for kernel crypto not available\n");
		ret = -ENOENT;
		goto unregister_interrupts;
	}
	ret = cn10k_cptvf_send_kcrypto_limits_msg(cptvf);
	if (ret)
		goto unregister_interrupts;

	kcrypto_lfs = cptvf->lfs.kcrypto_limits ? cptvf->lfs.kcrypto_limits :
		      num_online_cpus();
	/* Initialize CPT LFs */
	ret = cn10k_cptvf_lf_init(pdev, cptvf->reg_base, &cptvf->lfs,
				  kcrypto_lfs);
	if (ret)
		goto unregister_interrupts;

	return 0;

unregister_interrupts:
	cptvf_disable_pfvf_mbox_intrs(cptvf);
destroy_pfvf_mbox:
	cptvf_pfvf_mbox_destroy(cptvf);
clear_drvdata:
	pci_set_drvdata(pdev, NULL);

	return ret;
}

static void cn10k_cptvf_remove(struct pci_dev *pdev)
{
	struct cn10k_cptvf_dev *cptvf = pci_get_drvdata(pdev);

	if (!cptvf) {
		dev_err(&pdev->dev, "Invalid CPT VF device.\n");
		return;
	}

	/* Shutdown CPT LFs */
	if (cn10k_cptvf_lf_shutdown(pdev, &cptvf->lfs))
		dev_err(&pdev->dev, "CPT LFs shutdown failed.\n");
	/* Disable PF-VF mailbox interrupt */
	cptvf_disable_pfvf_mbox_intrs(cptvf);
	/* Destroy PF-VF mbox */
	cptvf_pfvf_mbox_destroy(cptvf);
	pci_set_drvdata(pdev, NULL);
}

/* Supported devices */
static const struct pci_device_id cn10k_cptvf_id_table[] = {
	{ PCI_DEVICE_SUB(PCI_VENDOR_ID_CAVIUM, CN10K_CPT_PCI_VF_DEVICE_ID,
			 PCI_VENDOR_ID_CAVIUM,
			 CN10K_CPT_PCI_SUBSYS_DEVID) },
	{ 0, }  /* end of table */
};

static struct pci_driver cn10k_cptvf_pci_driver = {
	.name = CN10K_CPTVF_DRV_NAME,
	.id_table = cn10k_cptvf_id_table,
	.probe = cn10k_cptvf_probe,
	.remove = cn10k_cptvf_remove,
};

module_pci_driver(cn10k_cptvf_pci_driver);

MODULE_AUTHOR("Marvell");
MODULE_DESCRIPTION(CN10K_CPTVF_DRV_STRING);
MODULE_LICENSE("GPL v2");
MODULE_VERSION(CN10K_CPTVF_DRV_VERSION);
MODULE_DEVICE_TABLE(pci, cn10k_cptvf_id_table);
