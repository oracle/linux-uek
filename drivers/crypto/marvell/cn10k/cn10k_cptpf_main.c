// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020 Marvell. */

#include <linux/firmware.h>
#include "cn10k_cpt_mbox_common.h"
#include "rvu_reg.h"

#define CN10K_CPT_DRV_NAME    "cn10k-cpt"
#define CN10K_CPT_DRV_STRING  "Marvell OcteonTX3 CPT Physical Function Driver"
#define CN10K_CPT_DRV_VERSION "1.0"

static void cptpf_enable_vf_flr_intrs(struct cn10k_cptpf_dev *cptpf)
{
	/* Clear interrupt if any */
	cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
			  RVU_PF_VFFLR_INTX(0), ~0x0ULL);
	cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
			  RVU_PF_VFFLR_INTX(1), ~0x0ULL);

	/* Enable VF FLR interrupts */
	cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
			  RVU_PF_VFFLR_INT_ENA_W1SX(0), ~0x0ULL);
	cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
			  RVU_PF_VFFLR_INT_ENA_W1SX(1), ~0x0ULL);
}

static void cptpf_disable_vf_flr_intrs(struct cn10k_cptpf_dev *cptpf)
{
	/* Disable VF FLR interrupts */
	cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
			  RVU_PF_VFFLR_INT_ENA_W1CX(0), ~0x0ULL);
	cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
			  RVU_PF_VFFLR_INT_ENA_W1CX(1), ~0x0ULL);

	/* Clear interrupt if any */
	cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
			  RVU_PF_VFFLR_INTX(0), ~0x0ULL);
	cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
			  RVU_PF_VFFLR_INTX(1), ~0x0ULL);
}

static void cptpf_enable_afpf_mbox_intrs(struct cn10k_cptpf_dev *cptpf)
{
	/* Clear interrupt if any */
	cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_INT, 0x1ULL);

	/* Enable AF-PF interrupt */
	cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_INT_ENA_W1S,
			  0x1ULL);
}

static void cptpf_disable_afpf_mbox_intrs(struct cn10k_cptpf_dev *cptpf)
{
	/* Disable AF-PF interrupt */
	cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_INT_ENA_W1C,
			  0x1ULL);

	/* Clear interrupt if any */
	cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_INT, 0x1ULL);
}

static void cptpf_enable_vfpf_mbox_intrs(struct cn10k_cptpf_dev *cptpf,
					 int numvfs)
{
	int ena_bits;

	/* Clear any pending interrupts */
	cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
			  RVU_PF_VFPF_MBOX_INTX(0), ~0x0ULL);
	cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
			  RVU_PF_VFPF_MBOX_INTX(1), ~0x0ULL);

	/* Enable VF interrupts for VFs from 0 to 63 */
	ena_bits = ((numvfs - 1) % 64);
	cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
			  RVU_PF_VFPF_MBOX_INT_ENA_W1SX(0),
			  GENMASK_ULL(ena_bits, 0));

	if (numvfs > 64) {
		/* Enable VF interrupts for VFs from 64 to 127 */
		ena_bits = numvfs - 64 - 1;
		cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
				  RVU_PF_VFPF_MBOX_INT_ENA_W1SX(1),
				  GENMASK_ULL(ena_bits, 0));
	}
}

static void cptpf_disable_vfpf_mbox_intrs(struct cn10k_cptpf_dev *cptpf)
{
	/* Disable VF-PF interrupts */
	cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
			  RVU_PF_VFPF_MBOX_INT_ENA_W1CX(0), ~0x0ULL);
	cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
			  RVU_PF_VFPF_MBOX_INT_ENA_W1CX(1), ~0x0ULL);

	/* Clear any pending interrupts */
	cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
			  RVU_PF_VFPF_MBOX_INTX(0), ~0x0ULL);
	cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
			  RVU_PF_VFPF_MBOX_INTX(1), ~0x0ULL);
}

static void cptpf_flr_wq_handler(struct work_struct *work)
{
	struct cptpf_flr_work *flrwork;
	struct cn10k_cptpf_dev *pf;
	struct mbox_msghdr *req;
	struct otx2_mbox *mbox;
	int vf, reg = 0;

	flrwork = container_of(work, struct cptpf_flr_work, work);
	pf = flrwork->pf;
	mbox = &pf->afpf_mbox;

	vf = flrwork - pf->flr_wrk;

	req = otx2_mbox_alloc_msg_rsp(mbox, 0, sizeof(*req),
				      sizeof(struct msg_rsp));
	if (!req)
		return;

	req->sig = OTX2_MBOX_REQ_SIG;
	req->id = MBOX_MSG_VF_FLR;
	req->pcifunc &= RVU_PFVF_FUNC_MASK;
	req->pcifunc |= (vf + 1) & RVU_PFVF_FUNC_MASK;

	cn10k_cpt_send_mbox_msg(pf->pdev);

	if (vf >= 64) {
		reg = 1;
		vf = vf - 64;
	}
	/* clear transcation pending bit */
	cn10k_cpt_write64(pf->reg_base, BLKADDR_RVUM, 0,
			  RVU_PF_VFTRPENDX(reg), BIT_ULL(vf));
	cn10k_cpt_write64(pf->reg_base, BLKADDR_RVUM, 0,
			  RVU_PF_VFFLR_INT_ENA_W1SX(reg), BIT_ULL(vf));
}

static irqreturn_t cptpf_vf_flr_intr(int __always_unused irq, void *arg)
{
	int reg, dev, vf, start_vf, num_reg = 1;
	struct cn10k_cptpf_dev *cptpf = arg;
	u64 intr;

	if (cptpf->max_vfs > 64)
		num_reg = 2;

	for (reg = 0; reg < num_reg; reg++) {
		intr = cn10k_cpt_read64(cptpf->reg_base, BLKADDR_RVUM, 0,
					RVU_PF_VFFLR_INTX(reg));
		if (!intr)
			continue;
		start_vf = 64 * reg;
		for (vf = 0; vf < 64; vf++) {
			if (!(intr & BIT_ULL(vf)))
				continue;
			dev = vf + start_vf;
			queue_work(cptpf->flr_wq, &cptpf->flr_wrk[dev].work);
			/* Clear interrupt */
			cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
					  RVU_PF_VFFLR_INTX(reg), BIT_ULL(vf));
			/* Disable the interrupt */
			cn10k_cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
					  RVU_PF_VFFLR_INT_ENA_W1CX(reg),
					  BIT_ULL(vf));
		}
	}
	return IRQ_HANDLED;
}

static int cptpf_register_interrupts(struct cn10k_cptpf_dev *cptpf)
{
	struct pci_dev *pdev = cptpf->pdev;
	struct device *dev = &pdev->dev;
	int ret, irq;
	u32 num_vec;

	num_vec = CN10K_CPT_PF_MSIX_VECTORS;

	/* Enable MSI-X */
	ret = pci_alloc_irq_vectors(pdev, num_vec, num_vec, PCI_IRQ_MSIX);
	if (ret < 0) {
		dev_err(dev, "Request for %d msix vectors failed\n", num_vec);
		return ret;
	}
	irq = pci_irq_vector(pdev, RVU_PF_INT_VEC_VFFLR0);
	/* Register VF FLR interrupt handler */
	ret = devm_request_irq(dev, irq, cptpf_vf_flr_intr, 0, "CPTPF FLR0",
			       cptpf);
	if (ret)
		return ret;

	irq = pci_irq_vector(pdev, RVU_PF_INT_VEC_VFFLR1);
	ret = devm_request_irq(dev, irq, cptpf_vf_flr_intr, 0,
			       "CPTPF FLR1", cptpf);
	if (ret)
		return ret;

	irq = pci_irq_vector(pdev, RVU_PF_INT_VEC_AFPF_MBOX);
	/* Register AF-PF mailbox interrupt handler */
	ret = devm_request_irq(dev, irq, cn10k_cptpf_afpf_mbox_intr, 0,
			       "CPTAFPF Mbox", cptpf);
	if (ret)
		return ret;

	irq = pci_irq_vector(pdev, RVU_PF_INT_VEC_VFPF_MBOX0);
	/* Register VF-PF mailbox interrupt handler */
	ret = devm_request_irq(dev, irq, cn10k_cptpf_vfpf_mbox_intr, 0,
			       "CPTVFPF Mbox0", cptpf);
	if (ret)
		return ret;

	irq = pci_irq_vector(pdev, RVU_PF_INT_VEC_VFPF_MBOX1);
	ret = devm_request_irq(dev, irq, cn10k_cptpf_vfpf_mbox_intr, 0,
			       "CPTVFPF Mbox1", cptpf);

	return ret;
}

static void cptpf_flr_wq_destroy(struct cn10k_cptpf_dev *pf)
{
	if (!pf->flr_wq)
		return;
	destroy_workqueue(pf->flr_wq);
	pf->flr_wq = NULL;
	devm_kfree(&pf->pdev->dev, pf->flr_wrk);
}

static int cptpf_flr_wq_init(struct cn10k_cptpf_dev *cptpf)
{
	int num_vfs = cptpf->max_vfs;
	int vf;

	cptpf->flr_wq = alloc_workqueue("cptpf_flr_wq",
					WQ_UNBOUND | WQ_HIGHPRI, 1);
	if (!cptpf->flr_wq)
		return -ENOMEM;

	cptpf->flr_wrk = devm_kcalloc(&cptpf->pdev->dev, num_vfs,
				      sizeof(struct cptpf_flr_work),
				      GFP_KERNEL);
	if (!cptpf->flr_wrk)
		goto destroy_wq;

	for (vf = 0; vf < num_vfs; vf++) {
		cptpf->flr_wrk[vf].pf = cptpf;
		INIT_WORK(&cptpf->flr_wrk[vf].work, cptpf_flr_wq_handler);
	}

	return 0;

destroy_wq:
	destroy_workqueue(cptpf->flr_wq);
	return -ENOMEM;
}

static int cptpf_afpf_mbox_init(struct cn10k_cptpf_dev *cptpf)
{
	int err;

	cptpf->afpf_mbox_wq = alloc_workqueue("cpt_afpf_mailbox",
					      WQ_UNBOUND | WQ_HIGHPRI |
					      WQ_MEM_RECLAIM, 1);
	if (!cptpf->afpf_mbox_wq)
		return -ENOMEM;

	err = otx2_mbox_init(&cptpf->afpf_mbox, cptpf->afpf_mbox_base,
			     cptpf->pdev, cptpf->reg_base, MBOX_DIR_PFAF, 1);
	if (err)
		goto error;

	INIT_WORK(&cptpf->afpf_mbox_work, cn10k_cptpf_afpf_mbox_handler);
	return 0;
error:
	destroy_workqueue(cptpf->afpf_mbox_wq);
	return err;
}

static int cptpf_vfpf_mbox_init(struct cn10k_cptpf_dev *cptpf, int numvfs)
{
	int err, i;

	cptpf->vfpf_mbox_wq = alloc_workqueue("cpt_vfpf_mailbox",
					      WQ_UNBOUND | WQ_HIGHPRI |
					      WQ_MEM_RECLAIM, 1);
	if (!cptpf->vfpf_mbox_wq)
		return -ENOMEM;

	err = otx2_mbox_init(&cptpf->vfpf_mbox, cptpf->vfpf_mbox_base,
			     cptpf->pdev, cptpf->reg_base, MBOX_DIR_PFVF,
			     numvfs);
	if (err)
		goto error;

	for (i = 0; i < numvfs; i++) {
		cptpf->vf[i].vf_id = i;
		cptpf->vf[i].cptpf = cptpf;
		cptpf->vf[i].intr_idx = i % 64;
		INIT_WORK(&cptpf->vf[i].vfpf_mbox_work,
			  cn10k_cptpf_vfpf_mbox_handler);
	}
	return 0;
error:
	destroy_workqueue(cptpf->vfpf_mbox_wq);
	return err;
}

static void cptpf_afpf_mbox_destroy(struct cn10k_cptpf_dev *cptpf)
{
	destroy_workqueue(cptpf->afpf_mbox_wq);
	otx2_mbox_destroy(&cptpf->afpf_mbox);
}

static void cptpf_vfpf_mbox_destroy(struct cn10k_cptpf_dev *cptpf)
{
	destroy_workqueue(cptpf->vfpf_mbox_wq);
	otx2_mbox_destroy(&cptpf->vfpf_mbox);
}

static int cptpf_device_reset(struct cn10k_cptpf_dev *cptpf)
{
	int timeout = 10, ret;
	u64 reg = 0;

	ret = cn10k_cpt_write_af_reg(cptpf->pdev, CPT_AF_BLK_RST, 0x1);
	if (ret)
		return ret;

	do {
		ret = cn10k_cpt_read_af_reg(cptpf->pdev, CPT_AF_BLK_RST,
					    &reg);
		if (ret)
			return ret;

		if (!((reg >> 63) & 0x1))
			break;

		usleep_range(10000, 20000);
		if (timeout-- < 0)
			return -EBUSY;
	} while (1);

	return ret;
}

static int cptpf_device_init(struct cn10k_cptpf_dev *cptpf)
{
	union cn10k_cptx_af_constants1 af_cnsts1 = {0};
	int ret = 0;

	/* Reset the CPT PF device */
	ret = cptpf_device_reset(cptpf);
	if (ret)
		return ret;

	/* Get number of SE, IE and AE engines */
	ret = cn10k_cpt_read_af_reg(cptpf->pdev, CPT_AF_CONSTANTS1,
				    &af_cnsts1.u);
	if (ret)
		return ret;

	cptpf->eng_grps.avail.max_se_cnt = af_cnsts1.s.se;
	cptpf->eng_grps.avail.max_ie_cnt = af_cnsts1.s.ie;
	cptpf->eng_grps.avail.max_ae_cnt = af_cnsts1.s.ae;

	/* Disable all cores */
	ret = cn10k_cpt_disable_all_cores(cptpf);

	return ret;
}

static ssize_t sso_pf_func_ovrd_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct cn10k_cptpf_dev *cptpf = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", cptpf->sso_pf_func_ovrd);
}

static ssize_t sso_pf_func_ovrd_store(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf, size_t count)
{
	struct cn10k_cptpf_dev *cptpf = dev_get_drvdata(dev);
	u8 sso_pf_func_ovrd;

	if (kstrtou8(buf, 0, &sso_pf_func_ovrd))
		return -EINVAL;

	cptpf->sso_pf_func_ovrd = sso_pf_func_ovrd;

	return count;
}

static ssize_t kvf_limits_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct cn10k_cptpf_dev *cptpf = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", cptpf->kvf_limits);
}

static ssize_t kvf_limits_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct cn10k_cptpf_dev *cptpf = dev_get_drvdata(dev);
	int lfs_num;

	if (kstrtoint(buf, 0, &lfs_num)) {
		dev_err(dev, "lfs count %d must be in range [1 - %d]\n",
			lfs_num, num_online_cpus());
		return -EINVAL;
	}
	if (lfs_num < 1 || lfs_num > num_online_cpus()) {
		dev_err(dev, "lfs count %d must be in range [1 - %d]\n",
			lfs_num, num_online_cpus());
		return -EINVAL;
	}
	cptpf->kvf_limits = lfs_num;

	return count;
}

static DEVICE_ATTR_RW(kvf_limits);
static DEVICE_ATTR_RW(sso_pf_func_ovrd);

static struct attribute *cptpf_attrs[] = {
	&dev_attr_kvf_limits.attr,
	&dev_attr_sso_pf_func_ovrd.attr,
	NULL
};

static const struct attribute_group cptpf_sysfs_group = {
	.attrs = cptpf_attrs,
};

static int cpt_is_pf_usable(struct cn10k_cptpf_dev *cptpf)
{
	u64 rev;

	rev = cn10k_cpt_read64(cptpf->reg_base, BLKADDR_RVUM, 0,
			       RVU_PF_BLOCK_ADDRX_DISC(BLKADDR_RVUM));
	rev = (rev >> 12) & 0xFF;
	/*
	 * Check if AF has setup revision for RVUM block, otherwise
	 * driver probe should be deferred until AF driver comes up
	 */
	if (!rev) {
		dev_warn(&cptpf->pdev->dev,
			 "AF is not initialized, deferring probe\n");
		return -EPROBE_DEFER;
	}
	return 0;
}

static int cn10k_cptpf_sriov_configure(struct pci_dev *pdev, int numvfs)
{
	struct cn10k_cptpf_dev *cptpf = pci_get_drvdata(pdev);
	int ret = 0;

	if (numvfs > cptpf->max_vfs)
		numvfs = cptpf->max_vfs;

	if (numvfs > 0) {
		/* Get CPT HW capabilities using LOAD_FVC operation. */
		ret = cn10k_cpt_discover_eng_capabilities(cptpf);
		if (ret)
			return ret;
		ret = cn10k_cpt_try_create_default_eng_grps(cptpf->pdev,
							    &cptpf->eng_grps);
		if (ret)
			return ret;

		cptpf->enabled_vfs = numvfs;

		ret = pci_enable_sriov(pdev, numvfs);
		if (ret)
			goto reset_numvfs;

		cn10k_cpt_set_eng_grps_is_rdonly(&cptpf->eng_grps, true);
		try_module_get(THIS_MODULE);
		ret = numvfs;
	} else {
		pci_disable_sriov(pdev);
		cn10k_cpt_set_eng_grps_is_rdonly(&cptpf->eng_grps, false);
		module_put(THIS_MODULE);
		cptpf->enabled_vfs = 0;
	}

	dev_notice(&cptpf->pdev->dev, "VFs enabled: %d\n", ret);
	return ret;
reset_numvfs:
	cptpf->enabled_vfs = 0;
	return ret;
}

static int cn10k_cptpf_probe(struct pci_dev *pdev,
			     const struct pci_device_id *ent)
{
	u64 vfpf_mbox_base, pf_lmtline_base;
	struct device *dev = &pdev->dev;
	resource_size_t offset, size;
	struct cn10k_cptpf_dev *cptpf;
	int err;

	cptpf = devm_kzalloc(dev, sizeof(*cptpf), GFP_KERNEL);
	if (!cptpf)
		return -ENOMEM;

	pci_set_drvdata(pdev, cptpf);
	cptpf->pdev = pdev;
	cptpf->max_vfs = pci_sriov_get_totalvfs(pdev);

	err = pcim_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		goto clear_drvdata;
	}

	pci_set_master(pdev);

	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to get usable DMA configuration\n");
		goto clear_drvdata;
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to get 48-bit DMA for consistent allocations\n");
		goto clear_drvdata;
	}

	/* Map PF's configuration registers */
	err = pcim_iomap_regions_request_all(pdev, 1 << PCI_PF_REG_BAR_NUM,
					     CN10K_CPT_DRV_NAME);
	if (err) {
		dev_err(dev, "Couldn't get PCI resources 0x%x\n", err);
		goto clear_drvdata;
	}

	cptpf->reg_base = pcim_iomap_table(pdev)[PCI_PF_REG_BAR_NUM];

	/* Check if AF driver is up, otherwise defer probe */
	err = cpt_is_pf_usable(cptpf);
	if (err)
		goto clear_drvdata;

	offset = pci_resource_start(pdev, PCI_MBOX_BAR_NUM);
	size = pci_resource_len(pdev, PCI_MBOX_BAR_NUM);
	/* Map AF-PF mailbox memory */
	cptpf->afpf_mbox_base = devm_ioremap_wc(dev, offset, MBOX_SIZE);
	if (!cptpf->afpf_mbox_base) {
		dev_err(&pdev->dev, "Unable to map BAR4\n");
		err = -ENODEV;
		goto clear_drvdata;
	}

	/* Map VF-PF mailbox memory */
	vfpf_mbox_base = readq(cptpf->reg_base + RVU_PF_VF_MBOX_ADDR);
	if (!vfpf_mbox_base) {
		dev_err(&pdev->dev, "VF-PF mailbox address not configured\n");
		err = -ENOMEM;
		goto clear_drvdata;
	}
	cptpf->vfpf_mbox_base = devm_ioremap_wc(dev, vfpf_mbox_base,
						MBOX_SIZE * cptpf->max_vfs);
	if (!cptpf->vfpf_mbox_base) {
		dev_err(&pdev->dev,
			"Mapping of VF-PF mailbox address failed\n");
		err = -ENOMEM;
		goto clear_drvdata;
	}

	pf_lmtline_base = readq(cptpf->reg_base + RVU_PF_LMTLINE_ADDR);
	if (!pf_lmtline_base) {
		dev_err(&pdev->dev, "PF LMTLINE address not configured\n");
		err = -ENOMEM;
		goto clear_drvdata;
	}
	size -= ((1 + cptpf->max_vfs) * MBOX_SIZE);
	cptpf->pf_lmtline_base = devm_ioremap_wc(dev, pf_lmtline_base,
						 size);
	if (!cptpf->pf_lmtline_base) {
		dev_err(&pdev->dev,
			"Mapping of PF LMTLINE address failed\n");
		err = -ENOMEM;
		goto clear_drvdata;
	}
	/* Initialize AF-PF mailbox */
	err = cptpf_afpf_mbox_init(cptpf);
	if (err)
		goto clear_drvdata;

	/* Initialize VF-PF mailbox */
	err = cptpf_vfpf_mbox_init(cptpf, cptpf->max_vfs);
	if (err)
		goto destroy_afpf_mbox;

	err = cptpf_flr_wq_init(cptpf);
	if (err)
		goto destroy_vfpf_mbox;

	/* Register interrupts */
	err = cptpf_register_interrupts(cptpf);
	if (err)
		goto destroy_flr;

	/* Enable VF FLR interrupts */
	cptpf_enable_vf_flr_intrs(cptpf);

	/* Enable AF-PF mailbox interrupts */
	cptpf_enable_afpf_mbox_intrs(cptpf);

	/* Enable VF-PF mailbox interrupts */
	cptpf_enable_vfpf_mbox_intrs(cptpf, cptpf->max_vfs);

	/* Initialize CPT PF device */
	err = cptpf_device_init(cptpf);
	if (err)
		goto unregister_interrupts;

	err = cn10k_cpt_send_ready_msg(cptpf->pdev);
	if (err)
		goto unregister_interrupts;

	/* Initialize engine groups */
	err = cn10k_cpt_init_eng_grps(pdev, &cptpf->eng_grps);
	if (err)
		goto unregister_interrupts;

	err = sysfs_create_group(&dev->kobj, &cptpf_sysfs_group);
	if (err)
		goto cleanup_eng_grps;
	return 0;

cleanup_eng_grps:
	cn10k_cpt_cleanup_eng_grps(pdev, &cptpf->eng_grps);
unregister_interrupts:
	cptpf_disable_vfpf_mbox_intrs(cptpf);
	cptpf_disable_afpf_mbox_intrs(cptpf);
	cptpf_disable_vf_flr_intrs(cptpf);
destroy_flr:
	cptpf_flr_wq_destroy(cptpf);
destroy_vfpf_mbox:
	cptpf_vfpf_mbox_destroy(cptpf);
destroy_afpf_mbox:
	cptpf_afpf_mbox_destroy(cptpf);
clear_drvdata:
	pci_set_drvdata(pdev, NULL);
	return err;
}

static void cn10k_cptpf_remove(struct pci_dev *pdev)
{
	struct cn10k_cptpf_dev *cptpf = pci_get_drvdata(pdev);

	if (!cptpf)
		return;

	/* Disable SRIOV */
	pci_disable_sriov(pdev);
	/*
	 * Delete sysfs entry created for kernel VF limits
	 * and sso_pf_func_ovrd bit.
	 */
	sysfs_remove_group(&pdev->dev.kobj, &cptpf_sysfs_group);
	/* Cleanup engine groups */
	cn10k_cpt_cleanup_eng_grps(pdev, &cptpf->eng_grps);
	/* Disable VF-PF interrupts */
	cptpf_disable_vfpf_mbox_intrs(cptpf);
	/* Disable AF-PF mailbox interrupt */
	cptpf_disable_afpf_mbox_intrs(cptpf);
	/* Disable VF FLR interrupts */
	cptpf_disable_vf_flr_intrs(cptpf);
	/* Unregister CPT interrupts */
	/* Destroy AF-PF mbox */
	cptpf_afpf_mbox_destroy(cptpf);
	/* Destroy VF-PF mbox */
	cptpf_vfpf_mbox_destroy(cptpf);
	pci_set_drvdata(pdev, NULL);
}

/* Supported devices */
static const struct pci_device_id cn10k_cpt_id_table[] = {
	{ PCI_DEVICE_SUB(PCI_VENDOR_ID_CAVIUM, CN10K_CPT_PCI_PF_DEVICE_ID,
			 PCI_VENDOR_ID_CAVIUM,
			 CN10K_CPT_PCI_SUBSYS_DEVID) },
	{ 0, }  /* end of table */
};

static struct pci_driver cn10k_cpt_pci_driver = {
	.name = CN10K_CPT_DRV_NAME,
	.id_table = cn10k_cpt_id_table,
	.probe = cn10k_cptpf_probe,
	.remove = cn10k_cptpf_remove,
	.sriov_configure = cn10k_cptpf_sriov_configure
};

module_pci_driver(cn10k_cpt_pci_driver);

MODULE_AUTHOR("Marvell");
MODULE_DESCRIPTION(CN10K_CPT_DRV_STRING);
MODULE_LICENSE("GPL v2");
MODULE_VERSION(CN10K_CPT_DRV_VERSION);
MODULE_DEVICE_TABLE(pci, cn10k_cpt_id_table);
