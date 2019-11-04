// SPDX-License-Identifier: GPL-2.0
/* Marvell PTP driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "ptp.h"

#define DRV_NAME	"Marvell PTP Driver"

#define PCI_DEVID_OCTEONTX2_PTP		0xA00C
#define PCI_SUBSYS_DEVID_OCTX2_98xx_PTP	0xB100
#define PCI_SUBSYS_DEVID_OCTX2_96XX_PTP	0xB200
#define PCI_SUBSYS_DEVID_OCTX2_95XX_PTP	0xB300
#define PCI_DEVID_OCTEONTX2_RST		0xA085

#define PCI_PTP_BAR_NO	0
#define PCI_RST_BAR_NO	0

#define PTP_CLOCK_CFG		0xF00ULL
#define  PTP_CLOCK_CFG_PTP_EN		BIT(0)
#define PTP_CLOCK_LO		0xF08ULL
#define PTP_CLOCK_HI		0xF10ULL
#define PTP_CLOCK_COMP		0xF18ULL

#define RST_BOOT	0x1600ULL
#define CLOCK_BASE_RATE	50000000ULL

static u64 get_clock_rate(void)
{
	u64 ret = CLOCK_BASE_RATE * 16;
	struct pci_dev *pdev;
	void __iomem *base;

	pdev = pci_get_device(PCI_VENDOR_ID_CAVIUM,
			      PCI_DEVID_OCTEONTX2_RST, NULL);
	if (!pdev)
		goto error;

	base = pci_ioremap_bar(pdev, PCI_RST_BAR_NO);
	if (!base)
		goto error_put_pdev;

	ret = CLOCK_BASE_RATE * ((readq(base + RST_BOOT) >> 33) & 0x3f);

	iounmap(base);

error_put_pdev:
	pci_dev_put(pdev);

error:
	return ret;
}

struct ptp *ptp_get(void)
{
	struct pci_dev *pdev;
	struct ptp *ptp;

	pdev = pci_get_device(PCI_VENDOR_ID_CAVIUM,
			      PCI_DEVID_OCTEONTX2_PTP, NULL);
	if (!pdev)
		return ERR_PTR(-ENODEV);

	ptp = pci_get_drvdata(pdev);
	if (!ptp)
		ptp = ERR_PTR(-EPROBE_DEFER);
	if (IS_ERR(ptp))
		pci_dev_put(pdev);

	return ptp;
}

void ptp_put(struct ptp *ptp)
{
	if (!ptp)
		return;

	pci_dev_put(ptp->pdev);
}

int ptp_adjfine(struct ptp *ptp, long scaled_ppm)
{
	bool neg_adj = false;
	u64 comp;
	u64 adj;
	s64 ppb;

	if (scaled_ppm < 0) {
		neg_adj = true;
		scaled_ppm = -scaled_ppm;
	}

	/* The hardware adds the clock compensation value to the PTP clock
	 * on every coprocessor clock cycle. Typical convention is that it
	 * represent number of nanosecond betwen each cycle. In this
	 * convention compensation value is in 64 bit fixed-point
	 * representation where upper 32 bits are number of nanoseconds
	 * and lower is fractions of nanosecond.
	 * The scaled_ppm represent the ratio in "parts per bilion" by which the
	 * compensation value should be corrected.
	 * To calculate new compenstation value we use 64bit fixed point
	 * arithmetic on following formula
	 * comp = tbase + tbase * scaled_ppm / (1M * 2^16)
	 * where tbase is the basic compensation value calculated initialy
	 * in cavium_ptp_init() -> tbase = 1/Hz. Then we use endian
	 * independent structure definition to write data to PTP register.
	 */
	comp = ((u64)1000000000ull << 32) / ptp->clock_rate;
	/* convert scaled_ppm to ppb */
	ppb = 1 + scaled_ppm;
	ppb *= 125;
	ppb >>= 13;
	adj = comp * ppb;
	adj = div_u64(adj, 1000000000ull);
	comp = neg_adj ? comp - adj : comp + adj;

	writeq(comp, ptp->reg_base + PTP_CLOCK_COMP);

	return 0;
}

static inline u64 get_tsc(bool is_pmu)
{
#if defined(CONFIG_ARM64)
	return is_pmu ? read_sysreg(pmccntr_el0) : read_sysreg(cntvct_el0);
#else
	return 0;
#endif
}

int ptp_get_clock(struct ptp *ptp, bool is_pmu, u64 *clk, u64 *tsc)
{
	u64 end, start;
	u8 retries = 0;

	do {
		start = get_tsc(0);
		*tsc = get_tsc(is_pmu);
		*clk = readq(ptp->reg_base + PTP_CLOCK_HI);
		end = get_tsc(0);
		retries++;
	} while (((end - start) > 50) && retries < 5);

	return 0;
}

static int ptp_probe(struct pci_dev *pdev,
		     const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct ptp *ptp;
	u64 clock_comp;
	u64 clock_cfg;
	int err;

	ptp = devm_kzalloc(dev, sizeof(*ptp), GFP_KERNEL);
	if (!ptp) {
		err = -ENOMEM;
		goto error;
	}

	ptp->pdev = pdev;

	err = pcim_enable_device(pdev);
	if (err)
		goto error_free;

	err = pcim_iomap_regions(pdev, 1 << PCI_PTP_BAR_NO, pci_name(pdev));
	if (err)
		goto error_free;

	ptp->reg_base = pcim_iomap_table(pdev)[PCI_PTP_BAR_NO];

	ptp->clock_rate = get_clock_rate();

	clock_cfg = readq(ptp->reg_base + PTP_CLOCK_CFG);
	clock_cfg |= PTP_CLOCK_CFG_PTP_EN;
	writeq(clock_cfg, ptp->reg_base + PTP_CLOCK_CFG);

	clock_comp = ((u64)1000000000ull << 32) / ptp->clock_rate;
	writeq(clock_comp, ptp->reg_base + PTP_CLOCK_COMP);

	pci_set_drvdata(pdev, ptp);

	return 0;

error_free:
	devm_kfree(dev, ptp);

error:
	/* For `ptp_get()` we need to differentiate between the case
	 * when the core has not tried to probe this device and the case when
	 * the probe failed.  In the later case we pretend that the
	 * initialization was successful and keep the error in
	 * `dev->driver_data`.
	 */
	pci_set_drvdata(pdev, ERR_PTR(err));
	return 0;
}

static void ptp_remove(struct pci_dev *pdev)
{
	struct ptp *ptp = pci_get_drvdata(pdev);
	u64 clock_cfg;

	if (IS_ERR_OR_NULL(ptp))
		return;

	clock_cfg = readq(ptp->reg_base + PTP_CLOCK_CFG);
	clock_cfg &= ~PTP_CLOCK_CFG_PTP_EN;
	writeq(clock_cfg, ptp->reg_base + PTP_CLOCK_CFG);
}

static const struct pci_device_id ptp_id_table[] = {
	{ PCI_DEVICE_SUB(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_OCTEONTX2_PTP,
			 PCI_VENDOR_ID_CAVIUM,
			 PCI_SUBSYS_DEVID_OCTX2_98xx_PTP) },
	{ PCI_DEVICE_SUB(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_OCTEONTX2_PTP,
			 PCI_VENDOR_ID_CAVIUM,
			 PCI_SUBSYS_DEVID_OCTX2_96XX_PTP) },
	{ PCI_DEVICE_SUB(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_OCTEONTX2_PTP,
			 PCI_VENDOR_ID_CAVIUM,
			 PCI_SUBSYS_DEVID_OCTX2_95XX_PTP) },
	{ 0, }
};

struct pci_driver ptp_driver = {
	.name = DRV_NAME,
	.id_table = ptp_id_table,
	.probe = ptp_probe,
	.remove = ptp_remove,
};
