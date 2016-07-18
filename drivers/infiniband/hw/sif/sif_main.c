/*
 * Copyright (c) 2010, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_main.c: main entry points and initialization
 */

#include <linux/version.h>
#include <linux/module.h>
#ifdef CONFIG_X86
#include <asm/mtrr.h>
#endif
#include <linux/pci.h>
#include <linux/aer.h>
#include "sif_dev.h"
#include "sif_fwa.h"
#include "sif_mmu.h"
#include "sif_mr.h"
#include "sif_hwi.h"
#include "sif_r3.h"
#include "sif_vf.h"
#include "sif_pt.h"
#include "sif_ireg.h"
#include "sif_debug.h"
#include "psif_hw_csr.h"
#include "version.h"
#include <xen/xen.h>
#include <linux/crash_dump.h>
#include "versioninfo.h"


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Oracle SIF Infiniband HCA driver");
MODULE_VERSION(TITAN_RELEASE);
MODULE_AUTHOR("Knut Omang");

/* The device(s) we support */

static const struct pci_device_id pci_table[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_SUN, PCI_DEVICE_ID_PSIF_PF)},
	{PCI_DEVICE(PCI_VENDOR_ID_SUN, PCI_DEVICE_ID_PSIF_VF)},
	{PCI_DEVICE(PCI_VENDOR_ID_SUN, PCI_DEVICE_ID_SN1_PF)},
	{PCI_DEVICE(PCI_VENDOR_ID_SUN, PCI_DEVICE_ID_SN1_VF)},
	{0,}
};

MODULE_DEVICE_TABLE(pci, pci_table);

/* module entry points */
static int __init sif_init(void);
static void __exit sif_exit(void);

/* device entry points */
static int sif_probe(struct pci_dev *pdev,
			       const struct pci_device_id *id);
static void sif_remove(struct pci_dev *dev);


static struct pci_driver sif_driver = {
	.name = "sif",
	.id_table = pci_table,
	.probe =	sif_probe,
	.remove =	sif_remove,
	.sriov_configure = sif_vf_enable,
};

/* Driver parameters: */

ulong sif_debug_mask = 0x1;

module_param_named(debug_mask, sif_debug_mask, ulong, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug_mask, "Selective enabling of debugging output to the system log");

#ifdef SIF_TRACE_MASK
ulong sif_trace_mask = 0x0;
module_param_named(trace_mask, sif_trace_mask, ulong, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(trace_mask, "Selective enabling of debugging output to the ftrace buffer");
#endif

ulong sif_feature_mask = 0;
module_param_named(feature_mask, sif_feature_mask, ulong, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(feature_mask, "Selective enabling of sif driver features");

ulong sif_vendor_flags = 0;
module_param_named(vendor_flags, sif_vendor_flags, ulong, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(vendor_flags, "Selective enabling of sif driver vendor specific mode flags");

uint sif_max_pqp_wr = SIF_SW_MAX_SQE;
module_param_named(max_pqp_wr, sif_max_pqp_wr, uint, S_IRUGO);
MODULE_PARM_DESC(max_pqp_wr, "Maximum number of outstanding privileged QP requests supported");

uint sif_ki_spqp_size = 1;
module_param_named(ki_spqp_size, sif_ki_spqp_size, uint, S_IRUGO);
MODULE_PARM_DESC(ki_spqp_size, "Number of privileged QPs for key invalidate stencils to set up");

/* pqp_size ==  cq_eq_max */
uint sif_cq_eq_max = 46;
module_param_named(cq_eq_max, sif_cq_eq_max, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(cq_eq_max, "Upper limit on no. of EQs to distribute completion events among");

uint sif_cb_max = 100;
module_param_named(cb_max, sif_cb_max, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(cb_max, "Upper limit on no. of CBs.");

uint sif_fmr_cache_flush_threshold = 512;
module_param_named(fmr_cache_flush_threshold, sif_fmr_cache_flush_threshold, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(fmr_cache_flush_threshold, "PF limit for when to use fast-path full MMU flush for FMR unmap");


/* In principle, SIF can allow any max inline size but at the cost of more memory
 * allocated per QP. This variable sets the upper limit for any QP by defining
 * the max extent of the sq entries, which means that the real max size is slightly
 * less, depending on the max number of sges requested:
 */
uint sif_max_inline = 0x400;
module_param_named(max_inline, sif_max_inline, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(max_inline, "Max configurable inline data per QP");

uint sif_vf_en = 1;
module_param_named(vf_en, sif_vf_en, uint, S_IRUGO);
MODULE_PARM_DESC(vf_en, "If set to 0, refuse to load VF drivers");

ulong sif_eps_log_size = 0;
module_param_named(eps_log_size, sif_eps_log_size, ulong, S_IRUGO);
MODULE_PARM_DESC(eps_log_size, "Enable log redirection - value is size of log buffer to allocate");

ushort sif_eps_log_level = EPS_LOG_INFO;
module_param_named(eps_log_level, sif_eps_log_level, ushort, S_IRUGO);
MODULE_PARM_DESC(eps_log_level, "Level of logging to set for EPS redirect at load");

static int sif_bar_init(struct pci_dev *pdev);
static void sif_bar_deinit(struct pci_dev *pdev);


static int sif_set_check_max_payload(struct sif_dev *sdev)
{
	struct pci_dev *parent;
	u16 devctl, devcap, pdevctl, pdevcap;
	int pcie_cap, pcie_parent_cap, min_cap_mps, err;

	u8 payload_sz, payload_sz_cap;
	u8 parent_payload_sz, parent_payload_sz_cap;

	pcie_cap = pci_find_capability(sdev->pdev, PCI_CAP_ID_EXP);

	/* read PSIF max payload size capability and setting */
	err = pci_read_config_word(sdev->pdev, pcie_cap + PCI_EXP_DEVCTL, &devctl);
	if (err)
		return err;

	payload_sz = (devctl & PCI_EXP_DEVCTL_PAYLOAD) >> 5;

	err = pci_read_config_word(sdev->pdev, pcie_cap + PCI_EXP_DEVCAP, &devcap);
	if (err)
		return err;

	payload_sz_cap = (devcap & PCI_EXP_DEVCAP_PAYLOAD);

	if (sif_feature(max_supported_payload)) {
		parent = pci_upstream_bridge(sdev->pdev);
		if (!parent) {
			sif_log(sdev, SIF_INFO,
				"No parent bridge device, cannot determine atomic capabilities!");
			return PSIF_PCIE_ATOMIC_OP_NONE;
		}

		pcie_parent_cap = pci_find_capability(parent, PCI_CAP_ID_EXP);
		if (!pcie_parent_cap) {
			sif_log(sdev, SIF_INFO,
				"Unable to find any PCIe capability in parent device - assuming payload size is ok");
			return 0;
		}

		/* read root complex (port) max payload size */
		err = pci_read_config_word(parent, pcie_parent_cap + PCI_EXP_DEVCTL, &pdevctl);
		if (err)
			return err;

		err = pci_read_config_word(parent, pcie_parent_cap + PCI_EXP_DEVCAP, &pdevcap);
		if (err)
			return err;

		parent_payload_sz = (pdevctl & PCI_EXP_DEVCTL_PAYLOAD) >> 5;
		parent_payload_sz_cap = (pdevcap & PCI_EXP_DEVCAP_PAYLOAD);

		min_cap_mps = min(parent_payload_sz_cap, payload_sz_cap);

		/* adjusting the RC max payload size to the supported max payload size */
		if (parent_payload_sz != min_cap_mps) {
			sif_log(sdev, SIF_INFO,
				"Adjusting RC max payload sz to %d\n", 128 << parent_payload_sz_cap);
			err = pci_write_config_word(parent,
					pcie_parent_cap + PCI_EXP_DEVCTL,
					(pdevctl & ~PCI_EXP_DEVCTL_PAYLOAD) + (min_cap_mps << 5));
		}

		/* Adjusting the max payload size to the supported max payload size */
		if (payload_sz != min_cap_mps) {
			sif_log(sdev, SIF_INFO,
				"Adjusting max payload sz to %d\n", 128 << parent_payload_sz_cap);
			err = pci_write_config_word(sdev->pdev,
					pcie_cap + PCI_EXP_DEVCTL,
					(devctl & ~PCI_EXP_DEVCTL_PAYLOAD) + (min_cap_mps << 5));
		}

		if (min_cap_mps == 0) {
			sif_log(sdev, SIF_INFO,
				"PCI express max payload size is set to 128 which triggers a rev1 bug");
		}
	}
	return err;
}

/* Entry of new instance */
static int sif_probe(struct pci_dev *pdev,
			       const struct pci_device_id *id)
{
	int err = 0;

	/* TBD: Zeroed memory from ib_alloc_device? */
	struct sif_dev *sdev =
	    (struct sif_dev *)ib_alloc_device(sizeof(struct sif_dev));
	struct sif_eps *es;

	if (!sdev) {
		err = -ENOMEM;
		goto pfail_ib_alloc;
	}

	sdev->pdev = pdev;
	sdev->dfs = NULL;
	sdev->fw_vfs = -1; /* #of VFS enabled in firmware not known yet */
	sdev->ib_dev.dma_device = &pdev->dev;
	sdev->limited_mode = sif_feature(force_limited_mode) ? true : false;

	strlcpy(sdev->ib_dev.name, "sif%d", IB_DEVICE_NAME_MAX);

	pci_set_drvdata(pdev, sdev);
	sif_log(sdev, SIF_INFO,
		"%s found, device id 0x%x, subsystem id 0x%x, rev.%d",
		get_product_str(sdev), PSIF_DEVICE(sdev),
		PSIF_SUBSYSTEM(sdev), PSIF_REVISION(sdev));


	sdev->wq = create_singlethread_workqueue(sdev->ib_dev.name);
	if (!sdev->wq) {
		sif_log(sdev, SIF_INFO, "Failed to allocate kernel work queue");
		err = -ENOMEM;
		goto wq_fail;
	}
	sdev->misc_wq = create_singlethread_workqueue("sif_misc_wq");
	if (!sdev->misc_wq) {
		sif_log(sdev, SIF_INFO, "Failed to allocate sif misc work queue");
		err = -ENOMEM;
		goto wq_fail;
	}

	err = sif_set_check_max_payload(sdev);
	if (err)
		goto wq_fail;

	/* Ask PCI drivers to enable the device and set up BARs etc */
	err = pci_enable_device_mem(pdev);
	if (err)
		goto pfail_enable;

	/* Check if 64 bits DMA is supported */
	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(64));
	if (!err) {
		sif_log(sdev, SIF_INIT, "64 bit DMA supported");
		pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));
	} else {
		err = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
		if (!err) {
			sif_log(sdev, SIF_INIT, "32 bit DMA supported");
			pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
		} else {
			sif_log(sdev, SIF_INIT, "No DMA support!?");
			goto pfail_dma;
		}
	}

	pci_enable_pcie_error_reporting(pdev);

	/* Set up BAR access */
	err = sif_bar_init(pdev);
	if (err)
		goto pfail_bar;

	 /* This must be done before events reception - see Orabug: 23540257 */
	if (PSIF_REVISION(sdev) <= 3)
		sif_r3_pre_init(sdev);

	if (xen_pv_domain() || is_kdump_kernel()) {
		/* The Xen PV domain may return huge pages that are misaligned
		 * in DMA space, see Orabug: 21690736.
		 * Also we have to turn off the inline sge optimization, as it assumes
		 * that (guest) physical and DMA addresses are equal, which is not
		 * the case for the PV domain - see Orabug: 23012335.
		 * Also use the same sizes for the kdump environment
		 * - see Orabug: 23729807
		 */
		sif_log(sdev, SIF_INFO, "xen pv domain: Restricting resource allocation..");
		sif_feature_mask |= SIFF_no_huge_pages | SIFF_disable_inline_first_sge;
		sif_qp_size = min(sif_qp_size, 0x800U);
		sif_mr_size = min(sif_mr_size, 0x800U);
		sif_ah_size = min(sif_ah_size, 0x800U);
		sif_cq_size = min(sif_cq_size, 0x1000U);
		sif_rq_size = min(sif_rq_size, 0x800U);
		sif_max_pqp_wr = min(sif_max_pqp_wr, 0x1000U);
	}

	/* Timeout scaling factor:
	 * This value is used as a factor to calculate sensible
	 * timeout values throughout the driver:
	 */
	sdev->min_resp_ticks = SIF_HW_TIMEOUT;
	/* Type UMEM means no override - initialize */
	sdev->mt_override = SIFMT_UMEM;

	err = sif_dfs_register(sdev);
	if (err)
		goto pfail_dfs;

	/* PSIF initialization */
	err = sif_hw_init(sdev);
	if (err)
		goto pfail_psif_base;

	err = sif_fwa_register(sdev);
	if (err)
		goto fwa_reg_failed;

	/* Reserve key 0 as an invalid key for sanity checking
	 * See #3323 for details
	 */
	sdev->dma_inv_mr = sif_alloc_invalid_mr(sdev->pd);
	if (IS_ERR(sdev->dma_inv_mr)) {
		err = PTR_ERR(sdev->dma_inv_mr);
		goto pfail_dma_inv_mr;
	}

	/* Create a DMA MR (mapping the whole address space)
	 * for use with the local_dma_lkey
	 */
	sdev->dma_mr = create_dma_mr(sdev->pd,
				IB_ACCESS_LOCAL_WRITE |
				IB_ACCESS_REMOTE_READ |
				IB_ACCESS_REMOTE_WRITE);

	if (IS_ERR(sdev->dma_mr)) {
		err = PTR_ERR(sdev->dma_mr);
		goto pfail_dma_mr;
	}

	if (PSIF_REVISION(sdev) <= 3) {
		err = sif_r3_init(sdev);
		if (err)
			goto pfail_r3_init;
	}

	es = &sdev->es[sdev->mbox_epsc];

	err = sif_eq_request_irq_all(es);
	if (err)
		goto pfail_ibreg;

	/* Successful device init */

	err = sif_register_ib_device(sdev);
	if (err)
		goto pfail_ibreg;

	/* Now that an IB device name exists, create a symlink in debugfs */
	sif_dfs_link_to_ibdev(sdev);


	sif_log(sdev, SIF_INFO, "Enabled %s (hardware v%d.%d - firmware v%d.%d (api v%d.%d))",
		sdev->ib_dev.name,
		es->ver.psif_major, es->ver.psif_minor,
		es->ver.fw_major, es->ver.fw_minor,
		es->ver.epsc_major, es->ver.epsc_minor);
	return 0;
pfail_ibreg:
	sif_r3_deinit(sdev);
pfail_r3_init:
	sif_dealloc_mr(sdev, sdev->dma_mr);
pfail_dma_mr:
	sif_dealloc_mr(sdev, sdev->dma_inv_mr);
pfail_dma_inv_mr:
	sif_fwa_unregister(sdev);
fwa_reg_failed:
	sif_hw_deinit(sdev);
pfail_psif_base:
	sif_dfs_unregister(sdev);
pfail_dfs:
	sif_bar_deinit(pdev);
pfail_bar:
	pci_disable_pcie_error_reporting(pdev);
pfail_dma:
	pci_disable_device(pdev);
pfail_enable:
	destroy_workqueue(sdev->wq);
wq_fail:
	ib_dealloc_device(&sdev->ib_dev);
pfail_ib_alloc:
	sif_log0(SIF_INIT, "sif_probe failed with status %d\n", err);
	return err;
}

/* Exit of instance */
static void sif_remove(struct pci_dev *dev)
{
	struct sif_dev *sdev = pci_get_drvdata(dev);

	sif_log(sdev, SIF_INIT, "Enter: sif_remove");

	sif_vf_disable(sdev);

	sif_unregister_ib_device(sdev);
	sif_r3_deinit(sdev);
	sif_dealloc_mr(sdev, sdev->dma_mr);
	sif_dealloc_mr(sdev, sdev->dma_inv_mr);
	sif_fwa_unregister(sdev);
	sif_hw_deinit(sdev);
	sif_dfs_unregister(sdev);
	sif_bar_deinit(dev);
	pci_clear_master(dev);
	pci_disable_device(dev);
	flush_workqueue(sdev->wq);
	flush_workqueue(sdev->misc_wq);
	destroy_workqueue(sdev->wq);
	destroy_workqueue(sdev->misc_wq);
	sif_log(sdev, SIF_INFO, "removed device %s", sdev->ib_dev.name);
	ib_dealloc_device(&sdev->ib_dev);
}

static int sif_bar_init(struct pci_dev *pdev)
{
	struct sif_dev *sdev = pci_get_drvdata(pdev);
	int err;
	phys_addr_t start;
	size_t length;

	/* Request access to the device space in BAR0 for this driver */
	err = pci_request_region(pdev, SIF_CBU_BAR, "sif_cb");
	if (err) {
		sif_log(sdev, SIF_INIT, "Failed to request cb region");
		goto pfail_bar0;
	}

	/* Then map all of it to allow access */
	start = pci_resource_start(pdev, SIF_CBU_BAR);

	/* This should not happen - kernel or BIOS bug?
	 * TBD: Check this from the CPU ID? (M bit?)
	 */
	if (start > (1ULL << 52)) {
		sif_log(sdev, SIF_INIT,
			"pci_resource_start returned a physical address beyond CPU max phys.addr (%llx)",
			start);
		err = -ENOMEM;
		goto pfail_ioremap0;
	}

	length = pci_resource_len(pdev, SIF_CBU_BAR);

	sdev->cbu_mtrr = -1; /* Avoid attempt to free mtrr 0 */

	/*
	 * Need iomap_wc() in order to get write-combining to work,
	 * even when using explicit write-combining instructions.
	 */
	sdev->cb_base = ioremap_wc(start, length);
	if (!sdev->cb_base) {
		sif_log(sdev, SIF_INIT,
			"ioremap_wc - failed to map cb BAR (start %llx len %lx)",
			start, length);
		err = -ENOMEM;
		goto pfail_ioremap0;
	}
	sdev->cb_sz = length;

	sif_log(sdev, SIF_INIT, "BAR%d (cb) mapped at kva %p start %llx len %lx",
		SIF_CBU_BAR, sdev->cb_base, start, length);

	err = pci_request_region(pdev, SIF_MSIX_BAR, "sif_msix");
	if (err) {
		sif_log(sdev, SIF_INIT, "Failed to request msix region");
		goto pfail_bar2;
	}

	start = pci_resource_start(pdev, SIF_MSIX_BAR);
	length = pci_resource_len(pdev, SIF_MSIX_BAR);
	sdev->msi_base = ioremap_nocache(start, length);
	if (!sdev->msi_base) {
		sif_log(sdev, SIF_INIT,
			"ioremap_nocache - failed to map msix BAR%d (start %llx len %lx)",
			SIF_MSIX_BAR, start, length);
		err = -ENOMEM;
		goto pfail_ioremap2;
	}
	sdev->msi_sz = length;
	sif_log(sdev, SIF_INIT, "BAR%d (msix) mapped at kva %p start %llx len %lx",
		SIF_MSIX_BAR, sdev->msi_base, start, length);

	err = pci_request_region(pdev, SIF_EPS_BAR, "sif_csr");
	if (err) {
		sif_log(sdev, SIF_INIT, "Failed to request eps region");
		goto pfail_bar4;
	}

	start = pci_resource_start(pdev, SIF_EPS_BAR);
	length = pci_resource_len(pdev, SIF_EPS_BAR);
	sdev->eps_base = ioremap_nocache(start, length);
	if (!sdev->eps_base) {
		sif_log(sdev, SIF_INIT, "Failed to map eps BAR%d (start %llx len %lx)",
			SIF_EPS_BAR, start, length);
		err = -ENOMEM;
		goto pfail_ioremap4;
	}
	sdev->eps = (struct __iomem psif_pcie_mbox *)sdev->eps_base;
	sdev->eps_sz = length;

	sif_log(sdev, SIF_INIT, "BAR%d (eps) mapped at kva %p start %llx len %lx",
		SIF_EPS_BAR, sdev->eps, start, length);
	return 0;

pfail_ioremap4:
	pci_release_region(pdev, SIF_EPS_BAR);
pfail_bar4:
	iounmap(sdev->msi_base);
pfail_ioremap2:
	pci_release_region(pdev, SIF_CBU_BAR);
pfail_bar2:
	iounmap(sdev->cb_base);
pfail_ioremap0:
	pci_release_region(pdev, SIF_MSIX_BAR);
pfail_bar0:
	return err;
}

static void sif_bar_deinit(struct pci_dev *pdev)
{
	struct sif_dev *sdev = pci_get_drvdata(pdev);

	iounmap(sdev->eps);
	pci_release_region(pdev, 4);
	iounmap(sdev->msi_base);
	pci_release_region(pdev, 2);
	iounmap(sdev->cb_base);
	pci_release_region(pdev, 0);
}



/* Statically register this driver with the kernel */

static int __init sif_init(void)
{
	int stat = 0;

	sif_log0(SIF_INFO, "SIF - driver for Oracle's Infiniband HCAs");
	sif_log0(SIF_INIT, "sif debug mask 0x%lx", sif_debug_mask);
	if (sif_feature_mask) {
		u64 undef = sif_feature_mask & ~SIFF_all_features;

		if (undef) {
			sif_log0(SIF_INFO,
				"***** Invalid feature mask - undefined bits %llx - get rid of legacy bits!",
				undef);
			return -EINVAL;
		}
		sif_log0(SIF_INFO, "sif feature mask 0x%lx", sif_feature_mask);
	}

	stat = sif_pt_init();
	if (stat)
		goto pt_init_failed;

	stat = sif_fwa_init();
	if (stat)
		goto fwa_init_failed;

	return pci_register_driver(&sif_driver);

fwa_init_failed:
	sif_pt_exit();
pt_init_failed:
	return stat;
}

static void __exit sif_exit(void)
{
	sif_fwa_exit();
	pci_unregister_driver(&sif_driver);
	sif_pt_exit();
	sif_log0(SIF_INIT, "done unregistering");
}

module_init(sif_init);
module_exit(sif_exit);
