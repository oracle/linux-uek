/*
 * Copyright (C) 2020 Pensando Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/bitops.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/mmc/host.h>
#include <linux/mmc/mmc.h>
#include <linux/of.h>
#include "sdhci-pltfm.h"
#include "sdhci-cadence.h"

// delay regs address
#define SDIO_REG_HRS4		0x10
#define SDIO_REG_HRS6		0x18
#define SDIO_REG_HRS44		0xb0
#define REG_DELAY_HS		0x00
#define REG_DELAY_DEFAULT	0x01
#define REG_DELAY_UHSI_SDR12	0x02
#define REG_DELAY_UHSI_SDR25	0x03
#define REG_DELAY_UHSI_SDR50	0x04
#define REG_DELAY_UHSI_DDR50	0x05

static u32 elba_read_l(struct sdhci_host *host, int reg)
{
	struct sdhci_cdns_priv *priv = sdhci_cdns_priv(host);

	writel(0x0, priv->ctl_addr + 0x44);
	return readl(host->ioaddr + reg);
}

static u16 elba_read_w(struct sdhci_host *host, int reg)
{
	struct sdhci_cdns_priv *priv = sdhci_cdns_priv(host);
	u16 res;

	writel(0x0, priv->ctl_addr + 0x44);
	res = readw(host->ioaddr + reg);

	if (unlikely(reg == SDHCI_HOST_VERSION)) {
		/* claim to be spec 3.00 to avoid "Unknown version" warning */
		res = (res & SDHCI_VENDOR_VER_MASK) | SDHCI_SPEC_300;
	}

	return res;
}

static u8 elba_read_b(struct sdhci_host *host, int reg)
{
	struct sdhci_cdns_priv *priv = sdhci_cdns_priv(host);

	writel(0x0, priv->ctl_addr + 0x44);
	return readb(host->ioaddr + reg);
}

static void elba_write_l(struct sdhci_host *host, u32 val, int reg)
{
	struct sdhci_cdns_priv *priv = sdhci_cdns_priv(host);

	writel(0x78, priv->ctl_addr + 0x44);
	writel(val, host->ioaddr + reg);
}

static void elba_write_w(struct sdhci_host *host, u16 val, int reg)
{
	struct sdhci_cdns_priv *priv = sdhci_cdns_priv(host);
	u32 m = (reg & 0x3);
	u32 msk = (0x3 << (m));

	writel(msk << 3, priv->ctl_addr + 0x44);
	writew(val, host->ioaddr + reg);
	writel(0x78, priv->ctl_addr + 0x44);
}

static void elba_write_b(struct sdhci_host *host, u8 val, int reg)
{
	struct sdhci_cdns_priv *priv = sdhci_cdns_priv(host);
	u32 m = (reg & 0x3);
	u32 msk = (0x1 << (m));

	writel(msk << 3, priv->ctl_addr + 0x44);
	writeb(val, host->ioaddr + reg);
	writel(0x78, priv->ctl_addr + 0x44);
}

static const struct sdhci_ops sdhci_elba_ops = {
	.read_l = elba_read_l,
	.read_w = elba_read_w,
	.read_b = elba_read_b,
	.write_l = elba_write_l,
	.write_w = elba_write_w,
	.write_b = elba_write_b,
	.set_clock = sdhci_set_clock,
	.get_timeout_clock = sdhci_cdns_get_timeout_clock,
	.set_bus_width = sdhci_set_bus_width,
	.reset = sdhci_reset,
	.set_uhs_signaling = sdhci_cdns_set_uhs_signaling,
};

static void sd4_set_dlyvr(struct sdhci_host *host,
			  unsigned char addr, unsigned char data)
{
	unsigned long dlyrv_reg;

	dlyrv_reg = ((unsigned long)data << 8);
	dlyrv_reg |= addr;

	// set data and address
	writel(dlyrv_reg, host->ioaddr + SDIO_REG_HRS4);
	dlyrv_reg |= (1uL << 24uL);
	// send write request
	writel(dlyrv_reg, host->ioaddr + SDIO_REG_HRS4);
	dlyrv_reg &= ~(1uL << 24);
	// clear write request
	writel(dlyrv_reg, host->ioaddr + SDIO_REG_HRS4);
}

static void phy_config(struct sdhci_host *host)
{
	sd4_set_dlyvr(host, REG_DELAY_DEFAULT, 0x04);
	sd4_set_dlyvr(host, REG_DELAY_HS, 0x04);
	sd4_set_dlyvr(host, REG_DELAY_UHSI_SDR50, 0x06);
	sd4_set_dlyvr(host, REG_DELAY_UHSI_DDR50, 0x16);
}

static int elba_drv_init(struct platform_device *pdev)
{
	struct sdhci_host *host = platform_get_drvdata(pdev);
	struct sdhci_cdns_priv *priv = sdhci_cdns_priv(host);
	struct resource *iomem;
	void __iomem *ioaddr;

	host->mmc->caps |= (MMC_CAP_1_8V_DDR | MMC_CAP_8_BIT_DATA);
	iomem = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!iomem)
		return -ENOMEM;
	ioaddr = devm_ioremap_resource(&pdev->dev, iomem);
	if (IS_ERR(ioaddr))
		return PTR_ERR(ioaddr);
	priv->ctl_addr = ioaddr;
	writel(0x78, priv->ctl_addr + 0x44);
	phy_config(host);
	return 0;
}

const struct sdhci_cdns_drv_data sdhci_elba_drv_data = {
	.init = elba_drv_init,
	.pltfm_data = {
		.ops = &sdhci_elba_ops,
		.quirks = SDHCI_QUIRK_BROKEN_TIMEOUT_VAL,
	},
	.no_retune = 1,
};
