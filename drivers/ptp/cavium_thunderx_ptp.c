/**********************************************************************
* Author: Cavium, Inc.
*
* Contact: support@cavium.com
*          Please include "LiquidIO" in the subject.
*
* Copyright (c) 2003-2015 Cavium, Inc.
*
* This file is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License, Version 2, as
* published by the Free Software Foundation.
*
* This file is distributed in the hope that it will be useful, but
* AS-IS and WITHOUT ANY WARRANTY; without even the implied warranty
* of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE, TITLE, or
* NONINFRINGEMENT.  See the GNU General Public License for more
* details.
*
* This file may also be available under a different license from Cavium.
* Contact Cavium, Inc. for more information
**********************************************************************/

#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "cavium_ptp.h"

#define NSEC_PER_SEC     1000000000L
#define DRV_NAME         "Cavium Thunder PTP Driver"
#define DRV_VERSION      "1.0"

/* PCI device IDs */
#define PCI_DEVICE_ID_THUNDER_PTP	0xA00C

struct thunder_ptp_clock *thunder_ptp_clock;
EXPORT_SYMBOL(thunder_ptp_clock);

/*
 * Register access functions
 */

/* The Cavium PTP can *only* be found in SoCs containing the ThunderX ARM64 CPU
 * implementation.  All accesses to the device registers on this platform are
 * implicitly strongly ordered with respect to memory accesses. So
 * writeq_relaxed() and readq_relaxed() are safe to use with no memory barriers
 * in this driver.  The readq()/writeq() functions add explicit ordering
 * operation which in this case are redundant, and only add overhead.
 */

static u64 thunder_ptp_reg_read(struct cavium_ptp_clock_info *info,
				    u64 offset)
{
	struct thunder_ptp_clock *thunder_ptp_clock =
		container_of(info, struct thunder_ptp_clock, cavium_ptp_info);
	void __iomem *addr = thunder_ptp_clock->reg_base + offset;

	return readq_relaxed(addr);
}

static void thunder_ptp_reg_write(struct cavium_ptp_clock_info *info,
				      u64 offset, u64 val)
{
	struct thunder_ptp_clock *thunder_ptp_clock =
		container_of(info, struct thunder_ptp_clock, cavium_ptp_info);
	void __iomem *addr = thunder_ptp_clock->reg_base + offset;

	writeq_relaxed(val, addr);
}

static void thunder_ptp_adjtime(struct cavium_ptp_clock_info *info,
				   s64 delta)
{
	struct thunder_ptp_clock *thunder_ptp_clock =
		container_of(info, struct thunder_ptp_clock, cavium_ptp_info);

	thunder_ptp_clock->ptp_adjust = delta;
}

s64 thunder_get_adjtime(void)
{
	if (!thunder_ptp_clock)
		return 0;

	return thunder_ptp_clock->ptp_adjust;
}
EXPORT_SYMBOL(thunder_get_adjtime);

#define PCI_DEVICE_ID_CAVIUM_RST 0xA00E
#define DEFAULT_SCLK_MUL	 16
#define RST_BOOT		 0x1600

/* Get SCLK multiplier from RST block */
static u64 thunder_get_sclk_mul(void)
{
	struct pci_dev *rstdev;
	void __iomem *rst_base = NULL;
	u64 sclk_mul = DEFAULT_SCLK_MUL;

	rstdev = pci_get_device(PCI_VENDOR_ID_CAVIUM,
				PCI_DEVICE_ID_CAVIUM_RST, NULL);
	if (!rstdev)
		return sclk_mul;

	rst_base = ioremap(pci_resource_start(rstdev, 0),
			   pci_resource_len(rstdev, 0));
	if (rst_base) {
		sclk_mul = readq_relaxed(rst_base + RST_BOOT);
		sclk_mul = (sclk_mul >> 33) & 0x3F;
		iounmap(rst_base);
	}

	return sclk_mul;
}

/* module operations */

static int thunder_ptp_probe(struct pci_dev *pdev,
				 const struct pci_device_id *ent)
{
	int err;
	struct device *dev = &pdev->dev;

	thunder_ptp_clock = devm_kzalloc(dev, sizeof(*thunder_ptp_clock),
					 GFP_KERNEL);
	if (!thunder_ptp_clock)
		return -ENOMEM;
	thunder_ptp_clock->pdev = pdev;
	pci_set_drvdata(pdev, thunder_ptp_clock);

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		pci_set_drvdata(pdev, NULL);
		return err;
	}

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed 0x%x\n", err);
		goto err_disable_device;
	}

	/* MAP configuration registers */
	thunder_ptp_clock->reg_base = ioremap(pci_resource_start(pdev, 0),
					    pci_resource_len(pdev, 0));
	if (!thunder_ptp_clock->reg_base) {
		dev_err(dev, "BGX: Cannot map CSR memory space, aborting\n");
		err = -ENOMEM;
		goto err_release_regions;
	}

	/* register the cavium_ptp_clock */
	thunder_ptp_clock->cavium_ptp_info = (struct cavium_ptp_clock_info) {
		/* Below we need to give the SCLK which is:
		 * PLL_REF_CLK (= 50 MHz) × [PNR_MUL]
		 */
		.clock_rate = thunder_get_sclk_mul() * 50000000ull,
		.name = "ThunderX PTP",
		.reg_read = thunder_ptp_reg_read,
		.reg_write = thunder_ptp_reg_write,
		.adjtime_clbck = thunder_ptp_adjtime,
	};
	thunder_ptp_clock->cavium_ptp_clock = cavium_ptp_register(
		&thunder_ptp_clock->cavium_ptp_info, dev);
	if (IS_ERR(thunder_ptp_clock->cavium_ptp_clock))
		goto err_release_regions;

	return 0;

err_release_regions:
	pci_release_regions(pdev);
err_disable_device:
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);

	devm_kfree(dev, thunder_ptp_clock);
	return err;
}

static void thunder_ptp_remove(struct pci_dev *pdev)
{
	struct thunder_ptp_clock *thunder_ptp_clock = pci_get_drvdata(pdev);

	cavium_ptp_remove(thunder_ptp_clock->cavium_ptp_clock);
	iounmap(thunder_ptp_clock->reg_base);
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

/* Supported devices */
static const struct pci_device_id thunder_ptp_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVICE_ID_THUNDER_PTP) },
	{ 0, }  /* end of table */
};

static struct pci_driver thunder_ptp_driver = {
	.name = DRV_NAME,
	.id_table = thunder_ptp_id_table,
	.probe = thunder_ptp_probe,
	.remove = thunder_ptp_remove,
};

static int __init thunder_ptp_init_module(void)
{
	pr_info("%s, ver %s\n", DRV_NAME, DRV_VERSION);

	return pci_register_driver(&thunder_ptp_driver);
}

static void __exit thunder_ptp_cleanup_module(void)
{
	pci_unregister_driver(&thunder_ptp_driver);
}

module_init(thunder_ptp_init_module);
module_exit(thunder_ptp_cleanup_module);

MODULE_AUTHOR("Cavium Networks, <support@cavium.com>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION(DRV_NAME);
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, thunder_ptp_id_table);
