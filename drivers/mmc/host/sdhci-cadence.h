/*
 * Copyright (C) 2016 Socionext Inc.
 *   Author: Masahiro Yamada <yamada.masahiro@socionext.com>
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

#ifndef _SDHCI_CADENCE_H_
#define _SDHCI_CADENCE_H_

struct sdhci_cdns_phy_param {
	u8 addr;
	u8 data;
};

struct sdhci_cdns_priv {
	void __iomem *hrs_addr;
#ifdef CONFIG_MMC_SDHCI_CADENCE_ELBA
	void __iomem *ctl_addr;	/* write control */
	spinlock_t wrlock;	/* write lock */
#endif
	bool enhanced_strobe;
	void (*priv_write_l)(struct sdhci_cdns_priv *priv,
                u32 val, void __iomem *reg); /* for cadence-elba.c */
	struct reset_control *rst_hw;
	unsigned int nr_phy_params;
	struct sdhci_cdns_phy_param phy_params[0];
};

struct sdhci_cdns_phy_cfg {
	const char *property;
	u8 addr;
};

struct sdhci_cdns_drv_data {
	int (*init)(struct platform_device *pdev);
	const struct sdhci_pltfm_data pltfm_data;
};

static inline void *sdhci_cdns_priv(struct sdhci_host *host)
{
	struct sdhci_pltfm_host *pltfm_host = sdhci_priv(host);

	return sdhci_pltfm_priv(pltfm_host);
}

/*
 * The Pensando Elba SoC explicitly controls byte-lane enables on writes,
 * which includes writes to the HRS registers.
 * sdhci_cdns_priv_writel() is used in the common sdhci-cadence.c code
 * to write HRS registers, and this function dispatches to the specific
 * code.
 */
static inline void sdhci_cdns_priv_writel(struct sdhci_cdns_priv *priv,
		u32 val, void __iomem *reg)
{
	if (unlikely(priv->priv_write_l))
		priv->priv_write_l(priv, val, reg);
	else
		writel(val, reg);
}

#ifdef CONFIG_MMC_SDHCI_CADENCE_ELBA
extern const struct sdhci_cdns_drv_data sdhci_elba_drv_data;
#endif

unsigned int sdhci_cdns_get_timeout_clock(struct sdhci_host *host);
void sdhci_cdns_set_uhs_signaling(struct sdhci_host *host, unsigned int timing);

#endif
