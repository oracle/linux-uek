// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 DPI PF driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/module.h>
#include <linux/pci.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/sysfs.h>

#include "dpi.h"

#define DPI_DRV_NAME	"octeontx2-dpi"
#define DPI_DRV_STRING      "Marvell OcteonTX2 DPI-DMA Driver"
#define DPI_DRV_VERSION	"1.0"

/* Supported devices */
static const struct pci_device_id dpi_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_OCTEONTX2_DPI_PF) },
	{ 0, }  /* end of table */
};

static int mps = 128;
module_param(mps, int, 0644);
MODULE_PARM_DESC(mps, "Maximum payload size, Supported sizes are 128, 256, 512 and 1024 bytes");

static int mrrs = 128;
module_param(mrrs, int, 0644);
MODULE_PARM_DESC(mrrs, "Maximum read request size, Supported sizes are 128, 256, 512 and 1024 bytes");

MODULE_DEVICE_TABLE(pci, dpi_id_table);
MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION(DPI_DRV_STRING);
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DPI_DRV_VERSION);

static void dpi_reg_write(struct dpipf *dpi, u64 offset, u64 val)
{
	writeq(val, dpi->reg_base + offset);
}

static u64 dpi_reg_read(struct dpipf *dpi, u64 offset)
{
	return readq(dpi->reg_base + offset);
}

static int dpi_dma_engine_get_num(void)
{
	return DPI_MAX_ENGINES;
}

static int dpi_queue_init(struct dpipf *dpi, struct dpipf_vf *dpivf, u8 vf)
{
	int engine = 0;
	int queue = vf;
	u64 reg = 0ULL;
	u32 aura = dpivf->vf_config.aura;
	u16 buf_size = dpivf->vf_config.csize;
	u16 sso_pf_func = dpivf->vf_config.sso_pf_func;
	u16 npa_pf_func = dpivf->vf_config.npa_pf_func;

	dpi_reg_write(dpi, DPI_DMAX_IBUFF_CSIZE(queue),
		      DPI_DMA_IBUFF_CSIZE_CSIZE((u64)(buf_size / 8)));

	/* IDs are already configured while crating the domains.
	 * No need to configure here.
	 */
	for (engine = 0; engine < dpi_dma_engine_get_num(); engine++) {
		/* Dont configure the queus for PKT engines */
		if (engine >= 4)
			break;

		reg = 0;
		reg = dpi_reg_read(dpi, DPI_DMA_ENGX_EN(engine));
		reg |= DPI_DMA_ENG_EN_QEN(0x1 << queue);
		dpi_reg_write(dpi, DPI_DMA_ENGX_EN(engine), reg);
	}

	reg = dpi_reg_read(dpi, DPI_DMAX_IDS2(queue));
	reg |= DPI_DMA_IDS2_INST_AURA(aura);
	dpi_reg_write(dpi, DPI_DMAX_IDS2(queue), reg);

	reg = dpi_reg_read(dpi, DPI_DMAX_IDS(queue));
	reg |= DPI_DMA_IDS_DMA_NPA_PF_FUNC(npa_pf_func);
	reg |= DPI_DMA_IDS_DMA_SSO_PF_FUNC(sso_pf_func);
	reg |= DPI_DMA_IDS_DMA_STRM(vf + 1);
	reg |= DPI_DMA_IDS_INST_STRM(vf + 1);
	dpi_reg_write(dpi, DPI_DMAX_IDS(queue), reg);

	return 0;
}

static int dpi_queue_fini(struct dpipf *dpi, struct dpipf_vf *dpivf, u8 vf)
{
	u64 reg = 0ULL;
	int engine = 0;
	int queue = vf;
	u16 buf_size = dpivf->vf_config.csize;

	for (engine = 0; engine < dpi_dma_engine_get_num(); engine++) {
		/* Dont configure the queus for PKT engines */
		if (engine >= 4)
			break;

		reg = 0;
		reg = dpi_reg_read(dpi, DPI_DMA_ENGX_EN(engine));
		reg &= DPI_DMA_ENG_EN_QEN((~(1 << queue)));
		dpi_reg_write(dpi, DPI_DMA_ENGX_EN(engine), reg);
	}

	dpi_reg_write(dpi, DPI_DMAX_QRST(queue), 0x1ULL);
	/* TBD: below code required ? */
	dpi_reg_write(dpi, DPI_DMAX_IBUFF_CSIZE(queue),
		      DPI_DMA_IBUFF_CSIZE_CSIZE((u64)(buf_size)));

	/* Reset IDS and IDS2 registers */
	dpi_reg_write(dpi, DPI_DMAX_IDS2(queue), 0ULL);
	dpi_reg_write(dpi, DPI_DMAX_IDS(queue), 0ULL);

	return 0;
}

/**
 * Global initialization of DPI
 *
 * @dpi: DPI device context structure
 * @return Zero on success, negative on failure
 */
static int dpi_init(struct dpipf *dpi)
{
	int engine = 0, port = 0;
	u8 mrrs_val, mps_val;
	u64 reg = 0ULL;

	for (engine = 0; engine < dpi_dma_engine_get_num(); engine++) {
		if (engine == 4 || engine == 5)
			reg = DPI_ENG_BUF_BLKS(8);
		else
			reg = DPI_ENG_BUF_BLKS(4);

		dpi_reg_write(dpi, DPI_ENGX_BUF(engine), reg);

		/* Here qmap for the engines are set to 0.
		 * No dpi queues are mapped to engines.
		 * When a VF is initialised corresponding bit
		 * in the qmap will be set for all engines.
		 */
		dpi_reg_write(dpi, DPI_DMA_ENGX_EN(engine), 0x0ULL);
	}

	reg = 0ULL;
	reg =  (DPI_DMA_CONTROL_ZBWCSEN | DPI_DMA_CONTROL_PKT_EN |
		DPI_DMA_CONTROL_LDWB | DPI_DMA_CONTROL_O_MODE |
		DPI_DMA_CONTROL_DMA_ENB(0xfULL));

	dpi_reg_write(dpi, DPI_DMA_CONTROL, reg);
	dpi_reg_write(dpi, DPI_CTL, DPI_CTL_EN);

	/* Configure MPS and MRRS for DPI */
	if (mrrs < DPI_EBUS_MRRS_MIN || mrrs > DPI_EBUS_MRRS_MAX ||
			!is_power_of_2(mrrs)) {
		dev_info(&dpi->pdev->dev,
			"Invalid MRRS size:%d, Using default size(128 bytes)\n"
			, mrrs);
		mrrs = 128;
	}
	mrrs_val = fls(mrrs) - 8;

	if (mps < DPI_EBUS_MPS_MIN || mps > DPI_EBUS_MPS_MAX
			|| !is_power_of_2(mps)) {
		dev_info(&dpi->pdev->dev,
			"Invalid MPS size:%d, Using default size(128 bytes)\n"
			, mps);
		mps = 128;
	}
	mps_val = fls(mps) - 8;

	for (port = 0; port < DPI_EBUS_MAX_PORTS; port++) {
		reg = dpi_reg_read(dpi, DPI_EBUS_PORTX_CFG(port));
		reg &= ~(DPI_EBUS_PORTX_CFG_MRRS(0x7) |
			 DPI_EBUS_PORTX_CFG_MPS(0x7));
		reg |= (DPI_EBUS_PORTX_CFG_MPS(mps_val) |
			DPI_EBUS_PORTX_CFG_MRRS(mrrs_val));
		dpi_reg_write(dpi, DPI_EBUS_PORTX_CFG(port), reg);
	}
	return 0;
}

static int dpi_fini(struct dpipf *dpi)
{
	int engine = 0, port;
	u64 reg = 0ULL;

	for (engine = 0; engine < dpi_dma_engine_get_num(); engine++) {

		dpi_reg_write(dpi, DPI_ENGX_BUF(engine), reg);
		dpi_reg_write(dpi, DPI_DMA_ENGX_EN(engine), 0x0ULL);
	}

	reg = 0ULL;
	dpi_reg_write(dpi, DPI_DMA_CONTROL, reg);
	dpi_reg_write(dpi, DPI_CTL, ~DPI_CTL_EN);

	for (port = 0; port < DPI_EBUS_MAX_PORTS; port++) {
		reg = dpi_reg_read(dpi, DPI_EBUS_PORTX_CFG(port));
		reg &= ~DPI_EBUS_PORTX_CFG_MRRS(0x7);
		reg &= ~DPI_EBUS_PORTX_CFG_MPS(0x7);
		dpi_reg_write(dpi, DPI_EBUS_PORTX_CFG(port), reg);
	}
	return 0;
}

static int dpi_queue_reset(struct dpipf *dpi, u16 queue)
{
	/* TODO: add support */
	return 0;
}

static irqreturn_t dpi_pf_intr_handler (int irq, void *dpi_irq)
{
	u64 reg_val = 0;
	int i = 0;
	struct dpipf *dpi = (struct dpipf *)dpi_irq;

	dev_err(&dpi->pdev->dev, "intr received: %d\n", irq);

	/* extract MSIX vector number from irq number. */
	while (irq != pci_irq_vector(dpi->pdev, i)) {
		i++;
		if (i > dpi->num_vec)
			break;
	}
	if (i < DPI_REQQX_INT_IDX) {
		reg_val = dpi_reg_read(dpi, DPI_DMA_CCX_INT(i));
		dev_err(&dpi->pdev->dev, "DPI_CC%d_INT raised: 0x%016llx\n",
			i, reg_val);
		dpi_reg_write(dpi, DPI_DMA_CCX_INT(i), 0x1ULL);
	} else if (i < DPI_SDP_FLR_RING_LINTX_IDX) {
		reg_val = dpi_reg_read(
			dpi, DPI_REQQX_INT(i - DPI_REQQX_INT_IDX));
		dev_err(&dpi->pdev->dev,
			"DPI_REQQ_INT raised for q:%d: 0x%016llx\n",
			(i - 0x40), reg_val);

		dpi_reg_write(
			dpi, DPI_REQQX_INT(i - DPI_REQQX_INT_IDX), reg_val);

		if (reg_val & (0x71ULL))
			dpi_queue_reset(dpi, (i - DPI_REQQX_INT_IDX));
	} else if (i < DPI_SDP_IRE_LINTX_IDX) {
		/* TODO: handle interrupt */
		dev_err(&dpi->pdev->dev, "DPI_SDP_FLR_RING_LINTX raised\n");

	} else if (i < DPI_SDP_ORE_LINTX_IDX) {
		/* TODO: handle interrupt */
		dev_err(&dpi->pdev->dev, "DPI_SDP_IRE_LINTX raised\n");

	} else if (i < DPI_SDP_ORD_LINTX_IDX) {
		/* TODO: handle interrupt */
		dev_err(&dpi->pdev->dev, "DPI_SDP_ORE_LINTX raised\n");

	} else if (i < DPI_EPFX_PP_VF_LINTX_IDX) {
		/* TODO: handle interrupt */
		dev_err(&dpi->pdev->dev, "DPI_SDP_ORD_LINTX raised\n");

	} else if (i < DPI_EPFX_DMA_VF_LINTX_IDX) {
		/* TODO: handle interrupt */
		dev_err(&dpi->pdev->dev, "DPI_EPFX_PP_VF_LINTX raised\n");

	} else if (i < DPI_EPFX_MISC_LINTX_IDX) {
		/* TODO: handle interrupt */
		dev_err(&dpi->pdev->dev, "DPI_EPFX_DMA_VF_LINTX raised\n");

	} else if (i < DPI_PF_RAS_IDX) {
		/* TODO: handle interrupt */
		dev_err(&dpi->pdev->dev, "DPI_EPFX_MISC_LINTX raised\n");

	} else if (i == DPI_PF_RAS_IDX) {
		reg_val = dpi_reg_read(dpi, DPI_PF_RAS);
		dev_err(&dpi->pdev->dev, "DPI_PF_RAS raised: 0x%016llx\n",
			reg_val);
		dpi_reg_write(dpi, DPI_PF_RAS, reg_val);
	}
	return IRQ_HANDLED;
}

static int dpi_irq_init(struct dpipf *dpi)
{
	int i, irq = 0;
	int ret = 0;

	/* Clear All Interrupts */
	dpi_reg_write(dpi, DPI_PF_RAS, DPI_PF_RAS_INT);

	/* Clear All Enables */
	dpi_reg_write(dpi, DPI_PF_RAS_ENA_W1C, DPI_PF_RAS_INT);

	for (i = 0; i < DPI_MAX_REQQ_INT; i++) {
		dpi_reg_write(dpi, DPI_REQQX_INT(i), DPI_REQQ_INT);
		dpi_reg_write(dpi, DPI_REQQX_INT_ENA_W1C(i), DPI_REQQ_INT);
	}

	for (i = 0; i < DPI_MAX_CC_INT; i++) {
		dpi_reg_write(dpi, DPI_DMA_CCX_INT(i), DPI_DMA_CC_INT);
		dpi_reg_write(dpi, DPI_DMA_CCX_INT_ENA_W1C(i), DPI_DMA_CC_INT);
	}

	dpi->num_vec = pci_msix_vec_count(dpi->pdev);
	/* Enable MSI-X */
	ret = pci_alloc_irq_vectors(dpi->pdev, dpi->num_vec,
				    dpi->num_vec, PCI_IRQ_MSIX);
	if (ret < 0) {
		dev_err(&dpi->pdev->dev,
			"DPIPF: Request for %d msix vectors failed, ret %d\n",
			dpi->num_vec, ret);
		goto alloc_fail;
	}

	for (irq = 0; irq < dpi->num_vec; irq++) {
		ret = request_irq(pci_irq_vector(dpi->pdev, irq),
				  dpi_pf_intr_handler, 0, "DPIPF", dpi);
		if (ret) {
			dev_err(&dpi->pdev->dev,
				"DPIPF: IRQ(%d) registration failed for DPIPF\n",
				irq);
			goto fail;
		}
	}

#define ENABLE_DPI_INTERRUPTS 0
#if ENABLE_DPI_INTERRUPTS
	/*Enable All Interrupts */
	for (i = 0; i < DPI_MAX_REQQ_INT; i++)
		dpi_reg_write(dpi, DPI_REQQX_INT_ENA_W1S(i), DPI_REQQ_INT);

	dpi_reg_write(dpi, DPI_PF_RAS_ENA_W1S, DPI_PF_RAS_INT);
#endif
	return 0;
fail:
	if (irq) {
		for (i = 0; i <= irq; i++)
			free_irq(pci_irq_vector(dpi->pdev, i), dpi);
	}
	pci_free_irq_vectors(dpi->pdev);
alloc_fail:
	dpi->num_vec = 0;
	return ret;
}

static void dpi_irq_free(struct dpipf *dpi)
{
	int i = 0;

	/* Clear All Enables */
	dpi_reg_write(dpi, DPI_PF_RAS_ENA_W1C, DPI_PF_RAS_INT);

	for (i = 0; i < DPI_MAX_REQQ_INT; i++) {
		dpi_reg_write(dpi, DPI_REQQX_INT(i), DPI_REQQ_INT);
		dpi_reg_write(dpi, DPI_REQQX_INT_ENA_W1C(i), DPI_REQQ_INT);
	}

	for (i = 0; i < DPI_MAX_CC_INT; i++) {
		dpi_reg_write(dpi, DPI_DMA_CCX_INT(i), DPI_DMA_CC_INT);
		dpi_reg_write(dpi, DPI_DMA_CCX_INT_ENA_W1C(i), DPI_DMA_CC_INT);
	}

	for (i = 0; i < dpi->num_vec; i++)
		free_irq(pci_irq_vector(dpi->pdev, i), dpi);

	pci_free_irq_vectors(dpi->pdev);
	dpi->num_vec = 0;
}

static int dpi_sriov_configure(struct pci_dev *pdev, int numvfs)
{
	struct dpipf *dpi = pci_get_drvdata(pdev);
	int ret = 0;

	if (numvfs == 0) {
		pci_disable_sriov(pdev);
		dpi->total_vfs = 0;
	} else {
		ret = pci_enable_sriov(pdev, numvfs);
		if (ret == 0) {
			dpi->total_vfs = numvfs;
			ret = numvfs;
		}
	}

	return ret;
}

static ssize_t dpi_show_config(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct pci_dev *pdev = container_of(dev, struct pci_dev, dev);
	struct dpipf *dpi = pci_get_drvdata(pdev);
	int vf_idx;

	for (vf_idx = 0; vf_idx < DPI_MAX_VFS; vf_idx++) {
		struct dpipf_vf *dpivf = &dpi->vf[vf_idx];

		if (!dpivf->setup_done)
			continue;
		sprintf(buf + strlen(buf),
			"VF:%d command buffer size:%d aura:%d",
			vf_idx, dpivf->vf_config.csize, dpivf->vf_config.aura);
		sprintf(buf + strlen(buf),
			"sso_pf_func:%x npa_pf_func:%x\n",
			dpivf->vf_config.sso_pf_func,
			dpivf->vf_config.npa_pf_func);
	}
	return strlen(buf);
}

static ssize_t dpi_write_config(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct pci_dev *pdev = container_of(dev, struct pci_dev, dev);
	union dpi_mbox_message_t mbox_msg = {.u[0] = 0ULL, .u[1] = 0ULL};
	struct dpipf *dpi = pci_get_drvdata(pdev);
	struct dpipf_vf *dpivf;

	memcpy(&mbox_msg, buf, count);
	if (mbox_msg.s.vfid > DPI_MAX_VFS) {
		dev_err(dev, "Invalid vfid:%d\n", mbox_msg.s.vfid);
		return -1;
	}
	dpivf = &dpi->vf[mbox_msg.s.vfid];

	switch (mbox_msg.s.cmd) {
	case DPI_QUEUE_OPEN:
		dpivf->vf_config.aura = mbox_msg.s.aura;
		dpivf->vf_config.csize = mbox_msg.s.csize;
		dpivf->vf_config.sso_pf_func = mbox_msg.s.sso_pf_func;
		dpivf->vf_config.npa_pf_func = mbox_msg.s.npa_pf_func;
		dpi_queue_init(dpi, dpivf, mbox_msg.s.vfid);
		dpivf->setup_done = true;
		break;
	case DPI_QUEUE_CLOSE:
		dpivf->vf_config.aura = 0;
		dpivf->vf_config.csize = 0;
		dpivf->vf_config.sso_pf_func = 0;
		dpivf->vf_config.npa_pf_func = 0;
		dpi_queue_fini(dpi, dpivf, mbox_msg.s.vfid);
		dpivf->setup_done = false;
		break;
	default:
		return -1;
	}

	return sizeof(mbox_msg);
}

static DEVICE_ATTR(dpi_device_config, 0660,
		   dpi_show_config, dpi_write_config);

static int dpi_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct dpipf *dpi;
	int err;

	dpi = devm_kzalloc(dev, sizeof(*dpi), GFP_KERNEL);
	if (!dpi)
		return -ENOMEM;
	dpi->pdev = pdev;

	pci_set_drvdata(pdev, dpi);

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		pci_set_drvdata(pdev, NULL);
		return err;
	}

	err = pci_request_regions(pdev, DPI_DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed 0x%x\n", err);
		goto err_disable_device;
	}

	/* MAP configuration registers */
	dpi->reg_base = pcim_iomap(pdev, PCI_DPI_PF_CFG_BAR, 0);
	if (!dpi->reg_base) {
		dev_err(dev, "DPI: Cannot map CSR memory space, aborting\n");
		err = -ENOMEM;
		goto err_release_regions;
	}

	/* Initialize global PF registers */
	err = dpi_init(dpi);
	if (err) {
		dev_err(dev, "DPI: Failed to initialize dpi\n");
		goto err_release_regions;
	}

	/* Register interrupts */
	err = dpi_irq_init(dpi);
	if (err) {
		dev_err(dev, "DPI: Failed to initialize irq vectors\n");
		goto err_dpi_fini;
	}

	err = device_create_file(dev, &dev_attr_dpi_device_config);
	if (err) {
		dev_err(dev, "DPI: Failed to create sysfs entry for driver\n");
		goto err_free_irq;
	}

	return 0;

err_free_irq:
	dpi_irq_free(dpi);
err_dpi_fini:
	dpi_fini(dpi);
err_release_regions:
	pci_release_regions(pdev);
err_disable_device:
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	devm_kfree(dev, dpi);
	return err;
}

static void dpi_remove(struct pci_dev *pdev)
{
	struct device *dev = &pdev->dev;
	struct dpipf *dpi = pci_get_drvdata(pdev);

	device_remove_file(dev, &dev_attr_dpi_device_config);
	dpi_irq_free(dpi);
	dpi_fini(dpi);
	dpi_sriov_configure(pdev, 0);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	devm_kfree(dev, dpi);
}

static struct pci_driver dpi_driver = {
	.name = DPI_DRV_NAME,
	.id_table = dpi_id_table,
	.probe = dpi_probe,
	.remove = dpi_remove,
	.sriov_configure = dpi_sriov_configure,
};

static int __init dpi_init_module(void)
{
	pr_info("%s: %s\n", DPI_DRV_NAME, DPI_DRV_STRING);

	return pci_register_driver(&dpi_driver);
}

static void __exit dpi_cleanup_module(void)
{
	pci_unregister_driver(&dpi_driver);
}

module_init(dpi_init_module);
module_exit(dpi_cleanup_module);
