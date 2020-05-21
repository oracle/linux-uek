// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/firmware.h>
#include "rvu_reg.h"
#include "cpt9x_mbox_common.h"

#define DRV_NAME	"octeontx2-cpt"
#define DRV_VERSION	"1.0"

static void cptpf_enable_vf_flr_intrs(struct cptpf_dev *cptpf)
{
	/* Clear interrupt if any */
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(0),
		    ~0x0ULL);
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(1),
		    ~0x0ULL);

	/* Enable VF FLR interrupts */
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
		    RVU_PF_VFFLR_INT_ENA_W1SX(0), ~0x0ULL);
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
		    RVU_PF_VFFLR_INT_ENA_W1SX(1), ~0x0ULL);
}

static void cptpf_disable_vf_flr_intrs(struct cptpf_dev *cptpf)
{
	/* Disable VF FLR interrupts */
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
		    RVU_PF_VFFLR_INT_ENA_W1CX(0), ~0x0ULL);
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
		    RVU_PF_VFFLR_INT_ENA_W1CX(1), ~0x0ULL);

	/* Clear interrupt if any */
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(0),
		    ~0x0ULL);
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(1),
		    ~0x0ULL);
}

static void cptpf_enable_afpf_mbox_intrs(struct cptpf_dev *cptpf)
{
	/* Clear interrupt if any */
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_INT, 0x1ULL);

	/* Enable AF-PF interrupt */
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_INT_ENA_W1S,
		    0x1ULL);
}

static void cptpf_disable_afpf_mbox_intrs(struct cptpf_dev *cptpf)
{
	/* Disable AF-PF interrupt */
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_INT_ENA_W1C,
		    0x1ULL);

	/* Clear interrupt if any */
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_INT, 0x1ULL);
}

static void cptpf_enable_vfpf_mbox_intrs(struct cptpf_dev *cptpf, int numvfs)
{
	int ena_bits;

	/* Clear any pending interrupts */
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_VFPF_MBOX_INTX(0),
		      ~0x0ULL);
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_VFPF_MBOX_INTX(1),
		      ~0x0ULL);

	/* Enable VF interrupts for VFs from 0 to 63 */
	ena_bits = ((numvfs - 1) % 64);
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
		    RVU_PF_VFPF_MBOX_INT_ENA_W1SX(0),
		    GENMASK_ULL(ena_bits, 0));

	if (numvfs > 64) {
		/* Enable VF interrupts for VFs from 64 to 127 */
		ena_bits = numvfs - 64 - 1;
		cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
			    RVU_PF_VFPF_MBOX_INT_ENA_W1SX(1),
			    GENMASK_ULL(ena_bits, 0));
	}
}

static void cptpf_disable_vfpf_mbox_intrs(struct cptpf_dev *cptpf)
{
	/* Disable VF-PF interrupts */
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
		    RVU_PF_VFPF_MBOX_INT_ENA_W1CX(0),
		    ~0x0ULL);
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0,
		    RVU_PF_VFPF_MBOX_INT_ENA_W1CX(1),
		    ~0x0ULL);

	/* Clear any pending interrupts */
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_VFPF_MBOX_INTX(0),
		      ~0x0ULL);
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_VFPF_MBOX_INTX(1),
		      ~0x0ULL);
}

static irqreturn_t cptpf_vf_flr_intr(int irq, void *arg)
{
	struct cptpf_dev *cptpf = (struct cptpf_dev *) arg;

	/* Clear transaction pending register */
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_VFTRPENDX(0),
		    ~0x0ULL);
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_VFTRPENDX(1),
		    ~0x0ULL);

	/* Clear interrupt if any */
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(0),
		    ~0x0ULL);
	cpt_write64(cptpf->reg_base, BLKADDR_RVUM, 0, RVU_PF_VFFLR_INTX(1),
		    ~0x0ULL);

	return IRQ_HANDLED;
}

static void cptpf_unregister_interrupts(struct cptpf_dev *cptpf)
{
	int i;

	for (i = 0; i < CPT_96XX_PF_MSIX_VECTORS; i++) {
		if (cptpf->irq_registered[i])
			free_irq(pci_irq_vector(cptpf->pdev, i), cptpf);
		cptpf->irq_registered[i] = false;
	}

	pci_free_irq_vectors(cptpf->pdev);
}

static int cptpf_register_interrupts(struct cptpf_dev *cptpf)
{
	u32 num_vec;
	int ret;

	num_vec = CPT_96XX_PF_MSIX_VECTORS;

	/* Enable MSI-X */
	ret = pci_alloc_irq_vectors(cptpf->pdev, num_vec, num_vec,
				    PCI_IRQ_MSIX);
	if (ret < 0) {
		dev_err(&cptpf->pdev->dev,
			"Request for %d msix vectors failed\n", num_vec);
		return ret;
	}

	/* Register VF FLR interrupt handler */
	ret = request_irq(pci_irq_vector(cptpf->pdev,
			  RVU_PF_INT_VEC_VFFLR0), cptpf_vf_flr_intr, 0,
			  "CPTPF FLR0", cptpf);
	if (ret)
		goto err;
	cptpf->irq_registered[RVU_PF_INT_VEC_VFFLR0] = true;

	ret = request_irq(pci_irq_vector(cptpf->pdev,
			  RVU_PF_INT_VEC_VFFLR1), cptpf_vf_flr_intr, 0,
			  "CPTPF FLR1", cptpf);
	if (ret)
		goto err;
	cptpf->irq_registered[RVU_PF_INT_VEC_VFFLR1] = true;

	/* Register AF-PF mailbox interrupt handler */
	ret = request_irq(pci_irq_vector(cptpf->pdev,
			  RVU_PF_INT_VEC_AFPF_MBOX), cptpf_afpf_mbox_intr, 0,
			  "CPTAFPF Mbox", cptpf);
	if (ret)
		goto err;
	cptpf->irq_registered[RVU_PF_INT_VEC_AFPF_MBOX] = true;

	/* Register VF-PF mailbox interrupt handler */
	ret = request_irq(pci_irq_vector(cptpf->pdev,
			  RVU_PF_INT_VEC_VFPF_MBOX0), cptpf_vfpf_mbox_intr, 0,
			  "CPTVFPF Mbox0", cptpf);
	if (ret)
		goto err;
	cptpf->irq_registered[RVU_PF_INT_VEC_VFPF_MBOX0] = true;

	ret = request_irq(pci_irq_vector(cptpf->pdev,
			  RVU_PF_INT_VEC_VFPF_MBOX1), cptpf_vfpf_mbox_intr, 0,
			  "CPTVFPF Mbox1", cptpf);
	if (ret)
		goto err;
	cptpf->irq_registered[RVU_PF_INT_VEC_VFPF_MBOX1] = true;

	return 0;
err:
	dev_err(&cptpf->pdev->dev, "Failed to register interrupts\n");
	cptpf_unregister_interrupts(cptpf);
	return ret;
}

static int cptpf_afpf_mbox_init(struct cptpf_dev *cptpf)
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

	INIT_WORK(&cptpf->afpf_mbox_work, cptpf_afpf_mbox_handler);
	return 0;
error:
	destroy_workqueue(cptpf->afpf_mbox_wq);
	return err;
}

static int cptpf_vfpf_mbox_init(struct cptpf_dev *cptpf, int numvfs)
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
			  cptpf_vfpf_mbox_handler);
	}
	return 0;
error:
	flush_workqueue(cptpf->vfpf_mbox_wq);
	destroy_workqueue(cptpf->vfpf_mbox_wq);
	return err;
}

static void cptpf_afpf_mbox_destroy(struct cptpf_dev *cptpf)
{
	flush_workqueue(cptpf->afpf_mbox_wq);
	destroy_workqueue(cptpf->afpf_mbox_wq);
	otx2_mbox_destroy(&cptpf->afpf_mbox);
}

static void cptpf_vfpf_mbox_destroy(struct cptpf_dev *cptpf)
{
	flush_workqueue(cptpf->vfpf_mbox_wq);
	destroy_workqueue(cptpf->vfpf_mbox_wq);
	otx2_mbox_destroy(&cptpf->vfpf_mbox);
}

static int cptx_device_reset(struct cptpf_dev *cptpf)
{
	int timeout = 10;
	int ret = 0;
	u64 reg;

	ret = cpt_write_af_reg(cptpf->pdev, CPT_AF_BLK_RST, 0x1);
	if (ret)
		goto error;

	do {
		ret = cpt_read_af_reg(cptpf->pdev, CPT_AF_BLK_RST, &reg);
		if (ret)
			goto error;

		if (!((reg >> 63) & 0x1))
			break;

		usleep_range(10000, 20000);
		if (timeout-- < 0)
			return -EBUSY;
	} while (1);
error:
	return ret;
}

static int cptpf_device_reset(struct cptpf_dev *cptpf)
{
	int ret = 0;

	if (cptpf->cpt1_implemented) {
		cptpf->blkaddr = BLKADDR_CPT1;
		ret = cptx_device_reset(cptpf);
		if (ret)
			return ret;
	}
	cptpf->blkaddr = BLKADDR_CPT0;
	ret = cptx_device_reset(cptpf);

	return ret;
}

static void cpt_check_block_implemented(struct cptpf_dev *cptpf)
{
	u64 cfg;

	cfg = cpt_read64(cptpf->reg_base, BLKADDR_RVUM, 0,
			 RVU_PF_BLOCK_ADDRX_DISC(BLKADDR_CPT1));
	if (cfg & BIT_ULL(11))
		cptpf->cpt1_implemented = true;
}

static int cptpf_device_init(struct cptpf_dev *cptpf)
{
	union cptx_af_constants1 af_cnsts1 = {0};
	int ret = 0;

	/* check if 'implemented' bit is set for block BLKADDR_CPT1 */
	cpt_check_block_implemented(cptpf);
	/* Reset the CPT PF device */
	ret = cptpf_device_reset(cptpf);
	if (ret)
		goto error;

	/* Get number of SE, IE and AE engines */
	ret = cpt_read_af_reg(cptpf->pdev, CPT_AF_CONSTANTS1, &af_cnsts1.u);
	if (ret)
		goto error;

	cptpf->eng_grps.avail.max_se_cnt = af_cnsts1.s.se;
	cptpf->eng_grps.avail.max_ie_cnt = af_cnsts1.s.ie;
	cptpf->eng_grps.avail.max_ae_cnt = af_cnsts1.s.ae;

	/* Disable all cores */
	ret = cpt9x_disable_all_cores(cptpf);
	if (ret)
		goto error;
error:
	return ret;
}

static void cpt_destroy_sysfs_vf_limits(struct cptpf_dev *cptpf)
{
	struct cptvf_info *vf_info;
	int i;

	cpt_quotas_free(cptpf->vf_limits.cpt);
	cptpf->vf_limits.cpt = NULL;

	for (i = 0; i < cptpf->enabled_vfs; i++) {
		vf_info = &cptpf->vf[i];
		if (!vf_info->limits_kobj)
			continue;

		kobject_del(vf_info->limits_kobj);
		vf_info->limits_kobj = NULL;
		pci_dev_put(vf_info->vf_dev);
		vf_info->vf_dev = NULL;
	}
}

static int cpt_alloc_vf_limits(struct cptpf_dev *cptpf)
{
	int avail_lfs, lfs_per_vf, kvf_lfs;
	int i, ret, online_cpus;

	mutex_init(&cptpf->vf_limits.lock);

	/* Create limit structures for CPT resource types */
	cptpf->vf_limits.cpt = cpt_quotas_alloc(cptpf->enabled_vfs,
						cptpf->limits.cpt,
						cptpf->limits.cpt, 0,
						&cptpf->vf_limits.lock, NULL);
	if (cptpf->vf_limits.cpt == NULL) {
		dev_err(&cptpf->pdev->dev,
			"Failed to allocate cpt limits structures");
			return -ENOMEM;

	}

	avail_lfs = cptpf->vf_limits.cpt->max_sum;
	if (cptpf->kvf_limits) {
		avail_lfs -= cptpf->kvf_limits;
		kvf_lfs = cptpf->kvf_limits;
	} else {
		online_cpus = num_online_cpus();
		if (avail_lfs < online_cpus) {
			dev_err(&cptpf->pdev->dev,
				"CPT LFs %d < required for kernel crypto %d",
				avail_lfs, online_cpus);
			ret = -ENOENT;
			goto error;
		}
		avail_lfs -= online_cpus;
		kvf_lfs = online_cpus;
	}

	lfs_per_vf = cptpf->enabled_vfs == 1 ?
		     1 : avail_lfs / (cptpf->enabled_vfs - 1);
	if (lfs_per_vf <= 0) {
		dev_err(&cptpf->pdev->dev,
			"Not enough CPT LFs %d for %d VFs",
			avail_lfs, cptpf->enabled_vfs);
		ret = -ENOENT;
		goto error;
	}

	cptpf->vf_limits.cpt->a[0].val = kvf_lfs;
	for (i = 1; i < cptpf->enabled_vfs; i++)
		cptpf->vf_limits.cpt->a[i].val = lfs_per_vf;
	return 0;
error:
	cpt_quotas_free(cptpf->vf_limits.cpt);
	return ret;
}

static int cpt_create_sysfs_vf_limits(struct cptpf_dev *cptpf)
{
	struct pci_dev *pdev = NULL;
	struct cptvf_info *vf_info;
	int ret, i = 0;

	/* loop through all the VFs and create sysfs entries for them */
	while ((pdev = pci_get_device(cptpf->pdev->vendor,
				      CPT_PCI_VF_9X_DEVICE_ID, pdev))) {
		if (!pdev->is_virtfn || (pdev->physfn != cptpf->pdev))
			continue;

		vf_info = &cptpf->vf[i];
		vf_info->vf_dev = pci_dev_get(pdev);
		vf_info->limits_kobj = kobject_create_and_add("limits",
							      &pdev->dev.kobj);
		if (vf_info->limits_kobj == NULL) {
			ret = -ENOMEM;
			goto error;
		}

		if (cpt_quota_sysfs_create("cpt", vf_info->limits_kobj,
				&pdev->dev, &cptpf->vf_limits.cpt->a[i],
				NULL) != 0) {
			dev_err(&cptpf->pdev->dev,
				"Failed to create cpt limits sysfs for %s.",
				pci_name(pdev));
			ret = -EFAULT;
			goto error;
		}
		i++;
	}

	return 0;
error:
	cpt_destroy_sysfs_vf_limits(cptpf);
	return ret;
}

static ssize_t sso_pf_func_ovrd_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct cptpf_dev *cptpf = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", cptpf->sso_pf_func_ovrd);
}

static ssize_t sso_pf_func_ovrd_store(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf, size_t count)
{
	struct cptpf_dev *cptpf = dev_get_drvdata(dev);
	u8 sso_pf_func_ovrd;

	if (kstrtou8(buf, 0, &sso_pf_func_ovrd))
		return -EINVAL;

	cptpf->sso_pf_func_ovrd = sso_pf_func_ovrd;

	return count;
}


static ssize_t kvf_limits_show(struct device *dev,
			       struct device_attribute *attr, char *buf)
{
	struct cptpf_dev *cptpf = dev_get_drvdata(dev);

	return sprintf(buf, "%d\n", cptpf->kvf_limits);
}

static ssize_t kvf_limits_store(struct device *dev,
				struct device_attribute *attr,
				const char *buf, size_t count)
{
	struct cptpf_dev *cptpf = dev_get_drvdata(dev);
	int lfs_num;

	if (kstrtoint(buf, 0, &lfs_num)) {
		dev_err(dev, "lfs count %d must be in range [1 - %d]", lfs_num,
			num_online_cpus());
		return -EINVAL;
	}
	if (lfs_num < 1 || lfs_num > num_online_cpus()) {
		dev_err(dev, "lfs count %d must be in range [1 - %d]", lfs_num,
			num_online_cpus());
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

static int cpt_is_pf_usable(struct cptpf_dev *cptpf)
{
	u64 rev;

	rev = cpt_read64(cptpf->reg_base, BLKADDR_RVUM, 0,
			 RVU_PF_BLOCK_ADDRX_DISC(BLKADDR_RVUM));
	rev = (rev >> 12) & 0xFF;
	/* Check if AF has setup revision for RVUM block, otherwise
	 * driver probe should be deferred until AF driver comes up
	 */
	if (!rev) {
		dev_warn(&cptpf->pdev->dev,
			 "AF is not initialized, deferring probe");
		return -EPROBE_DEFER;
	}

	return 0;
}

static int cptpf_sriov_configure(struct pci_dev *pdev, int numvfs)
{
	struct cptpf_dev *cptpf = pci_get_drvdata(pdev);
	int ret = 0;

	if (numvfs > cptpf->max_vfs)
		numvfs = cptpf->max_vfs;

	if (numvfs > 0) {
		/* Get CPT HW capabilities using LOAD_FVC operation. */
		ret = cpt9x_discover_eng_capabilities(cptpf);
		if (ret)
			goto error;
		ret = cpt_try_create_default_eng_grps(cptpf->pdev,
						      &cptpf->eng_grps);
		if (ret)
			goto error;

		cptpf->enabled_vfs = numvfs;
		ret = cpt_alloc_vf_limits(cptpf);
		if (ret)
			goto error;

		ret = pci_enable_sriov(pdev, numvfs);
		if (ret)
			goto error;

		ret = cpt_create_sysfs_vf_limits(cptpf);
		if (ret)
			goto error;

		cpt_set_eng_grps_is_rdonly(&cptpf->eng_grps, true);
		try_module_get(THIS_MODULE);
		ret = numvfs;
	} else {
		pci_disable_sriov(pdev);
		cpt_destroy_sysfs_vf_limits(cptpf);
		cpt_set_eng_grps_is_rdonly(&cptpf->eng_grps, false);
		module_put(THIS_MODULE);
		cptpf->enabled_vfs = 0;
	}

	dev_notice(&cptpf->pdev->dev, "VFs enabled: %d\n", ret);
	return ret;
error:
	cptpf->enabled_vfs = 0;
	return ret;
}

static int cptpf_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct cptpf_dev *cptpf;
	u64 vfpf_mbox_base;
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

	/* Map PF's configuration registers */
	cptpf->reg_base = pcim_iomap(pdev, PCI_PF_REG_BAR_NUM, 0);
	if (!cptpf->reg_base) {
		dev_err(&pdev->dev, "Unable to map BAR2\n");
		err = -ENODEV;
		goto cpt_err_release_regions;
	}

	/* Check if AF driver is up, otherwise defer probe */
	err = cpt_is_pf_usable(cptpf);
	if (err)
		goto cpt_err_release_regions;

	/* Map AF-PF mailbox memory */
	cptpf->afpf_mbox_base = ioremap_wc(pci_resource_start(cptpf->pdev,
					   PCI_MBOX_BAR_NUM),
					   pci_resource_len(cptpf->pdev,
					   PCI_MBOX_BAR_NUM));
	if (!cptpf->afpf_mbox_base) {
		dev_err(&pdev->dev, "Unable to map BAR4\n");
		err = -ENODEV;
		goto cpt_err_release_regions;
	}

	/* Map VF-PF mailbox memory */
	vfpf_mbox_base = readq((void __iomem *) ((u64)cptpf->reg_base +
			       RVU_PF_VF_BAR4_ADDR));
	if (!vfpf_mbox_base) {
		dev_err(&pdev->dev, "VF-PF mailbox address not configured\n");
		err = -ENOMEM;
		goto cpt_err_iounmap_afpf;
	}
	cptpf->vfpf_mbox_base = ioremap_wc(vfpf_mbox_base,
					   MBOX_SIZE * cptpf->max_vfs);
	if (!cptpf->vfpf_mbox_base) {
		dev_err(&pdev->dev,
			"Mapping of VF-PF mailbox address failed\n");
		err = -ENOMEM;
		goto cpt_err_iounmap_afpf;
	}

	/* Initialize AF-PF mailbox */
	err = cptpf_afpf_mbox_init(cptpf);
	if (err)
		goto cpt_err_iounmap_vfpf;

	/* Initialize VF-PF mailbox */
	err = cptpf_vfpf_mbox_init(cptpf, cptpf->max_vfs);
	if (err)
		goto cpt_err_destroy_afpf_mbox;

	/* Register interrupts */
	err = cptpf_register_interrupts(cptpf);
	if (err)
		goto cpt_err_destroy_vfpf_mbox;

	/* Enable VF FLR interrupts */
	cptpf_enable_vf_flr_intrs(cptpf);

	/* Enable AF-PF mailbox interrupts */
	cptpf_enable_afpf_mbox_intrs(cptpf);

	/* Enable VF-PF mailbox interrupts */
	cptpf_enable_vfpf_mbox_intrs(cptpf, cptpf->max_vfs);

	/* Initialize CPT PF device */
	err = cptpf_device_init(cptpf);
	if (err)
		goto cpt_err_unregister_interrupts;

	/* Send ready message */
	err = cpt_send_ready_msg(cptpf->pdev);
	if (err)
		goto cpt_err_unregister_interrupts;

	/* Get available resources count */
	err = cpt_get_rsrc_cnt(cptpf->pdev);
	if (err)
		goto cpt_err_unregister_interrupts;

	/* Initialize engine groups */
	err = cpt_init_eng_grps(pdev, &cptpf->eng_grps, cpt9x_get_ucode_ops(),
				CPT_96XX);
	if (err)
		goto cpt_err_unregister_interrupts;

	err = sysfs_create_group(&dev->kobj, &cptpf_sysfs_group);
	if (err)
		goto cpt_err_cleanup_eng_grps;
	return 0;

cpt_err_cleanup_eng_grps:
	cpt_cleanup_eng_grps(pdev, &cptpf->eng_grps);
cpt_err_unregister_interrupts:
	cptpf_disable_vfpf_mbox_intrs(cptpf);
	cptpf_disable_afpf_mbox_intrs(cptpf);
	cptpf_disable_vf_flr_intrs(cptpf);
	cptpf_unregister_interrupts(cptpf);
cpt_err_destroy_vfpf_mbox:
	cptpf_vfpf_mbox_destroy(cptpf);
cpt_err_destroy_afpf_mbox:
	cptpf_afpf_mbox_destroy(cptpf);
cpt_err_iounmap_vfpf:
	iounmap(cptpf->vfpf_mbox_base);
cpt_err_iounmap_afpf:
	iounmap(cptpf->afpf_mbox_base);
cpt_err_release_regions:
	pci_release_regions(pdev);
cpt_err_set_drvdata:
	pci_set_drvdata(pdev, NULL);
	return err;
}

static void cptpf_remove(struct pci_dev *pdev)
{
	struct cptpf_dev *cptpf = pci_get_drvdata(pdev);

	if (!cptpf)
		return;

	/* Disable SRIOV */
	pci_disable_sriov(pdev);
	/* Delete sysfs entry created for kernel VF limits
	 * and sso_pf_func_ovrd bit.
	 */
	sysfs_remove_group(&pdev->dev.kobj, &cptpf_sysfs_group);
	/* Cleanup engine groups */
	cpt_cleanup_eng_grps(pdev, &cptpf->eng_grps);
	/* Disable VF-PF interrupts */
	cptpf_disable_vfpf_mbox_intrs(cptpf);
	/* Disable AF-PF mailbox interrupt */
	cptpf_disable_afpf_mbox_intrs(cptpf);
	/* Disable VF FLR interrupts */
	cptpf_disable_vf_flr_intrs(cptpf);
	/* Unregister CPT interrupts */
	cptpf_unregister_interrupts(cptpf);
	/* Destroy AF-PF mbox */
	cptpf_afpf_mbox_destroy(cptpf);
	/* Destroy VF-PF mbox */
	cptpf_vfpf_mbox_destroy(cptpf);
	/* Unmap VF-PF mailbox memory */
	iounmap(cptpf->vfpf_mbox_base);
	/* Unmap AF-PF mailbox memory */
	iounmap(cptpf->afpf_mbox_base);
	pci_release_regions(pdev);
	pci_set_drvdata(pdev, NULL);
}

/* Supported devices */
static const struct pci_device_id cpt_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, CPT_PCI_PF_9X_DEVICE_ID) },
	{ 0, }  /* end of table */
};

static struct pci_driver cpt_pci_driver = {
	.name = DRV_NAME,
	.id_table = cpt_id_table,
	.probe = cptpf_probe,
	.remove = cptpf_remove,
	.sriov_configure = cptpf_sriov_configure
};

module_pci_driver(cpt_pci_driver);

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION("Marvell OcteonTX2 CPT Physical Function Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, cpt_id_table);
