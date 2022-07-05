// SPDX-License-Identifier: GPL-2.0
/* Marvell MCS driver
 *
 * Copyright (C) 2022 Marvell.
 *
 */

#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "mcs.h"
#include "mcs_reg.h"

#define DRV_NAME	"Marvell MCS Driver"

#define PCI_CFG_REG_BAR_NUM	0

static const struct pci_device_id mcs_id_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_CAVIUM, PCI_DEVID_CN10K_MCS) },
	{ 0, }  /* end of table */
};

static LIST_HEAD(mcs_list);

int mcs_get_blkcnt(void)
{
	struct mcs *mcs;
	int idmax = -ENODEV;

	/* Check MCS block is present in hardware */
	if (!pci_dev_present(mcs_id_table))
		return 0;

	list_for_each_entry(mcs, &mcs_list, mcs_list)
		if (mcs->mcs_id > idmax)
			idmax = mcs->mcs_id;

	if (idmax < 0)
		return 0;

	return idmax + 1;
}

static void *alloc_mem(struct mcs *mcs, int n)
{
	return devm_kcalloc(mcs->dev, n, sizeof(u16), GFP_KERNEL);
}

static int mcs_alloc_struct_mem(struct mcs *mcs, struct mcs_rsrc_map *res)
{
	struct hwinfo *hw = mcs->hw;
	int err;

	res->flowid2pf_map = alloc_mem(mcs, hw->tcam_entries);
	if (!res->flowid2pf_map)
		return -ENOMEM;

	res->secy2pf_map = alloc_mem(mcs, hw->secy_entries);
	if (!res->secy2pf_map)
		return -ENOMEM;

	res->sc2pf_map = alloc_mem(mcs, hw->sc_entries);
	if (!res->sc2pf_map)
		return -ENOMEM;

	res->sa2pf_map = alloc_mem(mcs, hw->sa_entries);
	if (!res->sa2pf_map)
		return -ENOMEM;

	res->flowid2secy_map = alloc_mem(mcs, hw->tcam_entries);
	if (!res->flowid2secy_map)
		return -ENOMEM;

	res->flow_ids.max = hw->tcam_entries - MCS_RSRC_RSVD_CNT;
	err = rvu_alloc_bitmap(&res->flow_ids);
	if (err)
		return err;

	res->secy.max = hw->secy_entries - MCS_RSRC_RSVD_CNT;
	err = rvu_alloc_bitmap(&res->secy);
	if (err)
		return err;

	res->sc.max = hw->sc_entries;
	err = rvu_alloc_bitmap(&res->sc);
	if (err)
		return err;

	res->sa.max = hw->sa_entries;
	err = rvu_alloc_bitmap(&res->sa);
	if (err)
		return err;

	return 0;
}

struct mcs *mcs_get_pdata(int mcs_id)
{
	struct mcs *mcs_dev;

	list_for_each_entry(mcs_dev, &mcs_list, mcs_list) {
		if (mcs_dev->mcs_id == mcs_id)
			return mcs_dev;
	}
	return NULL;
}

int mcs_set_lmac_channels(u16 base)
{
	struct mcs *mcs;
	int lmac;
	u64 cfg;

	/* Programming channels needed only for CN10K-B which as only 1 mcs block */
	mcs = mcs_get_pdata(0);
	if (!mcs)
		return -ENODEV;
	for (lmac = 0; lmac < mcs->hw->lmac_cnt; lmac++) {
		cfg = mcs_reg_read(mcs, MCSX_LINK_LMACX_CFG(lmac));
		cfg &= ~(MCSX_LINK_LMAC_BASE_MASK | MCSX_LINK_LMAC_RANGE_MASK);
		cfg |=	FIELD_PREP(MCSX_LINK_LMAC_RANGE_MASK, ilog2(16));
		cfg |=	FIELD_PREP(MCSX_LINK_LMAC_BASE_MASK, base);
		mcs_reg_write(mcs, MCSX_LINK_LMACX_CFG(lmac), cfg);
		base += 16;
	}
	return 0;
}

static int mcs_x2p_calibration(struct mcs *mcs)
{
	unsigned long timeout = jiffies + usecs_to_jiffies(20000);
	int i, err = 0;
	u64 val;

	/* set X2P calibration */
	val = mcs_reg_read(mcs, MCSX_MIL_GLOBAL);
	val |= BIT_ULL(5);
	mcs_reg_write(mcs, MCSX_MIL_GLOBAL, val);

	/* Wait for calibration to complete */
	while (!(mcs_reg_read(mcs, MCSX_MIL_RX_GBL_STATUS) & BIT_ULL(0))) {
		if (time_before(jiffies, timeout)) {
			usleep_range(80, 100);
			continue;
		} else {
			err = -EBUSY;
			dev_err(mcs->dev, "MCS X2P calibration failed..ignoring\n");
			return err;
		}
	}

	val = mcs_reg_read(mcs, MCSX_MIL_RX_GBL_STATUS);
	for (i = 0; i < mcs->hw->mcs_x2p_intf; i++) {
		if (val & BIT_ULL(1 + i))
			continue;
		err = -EBUSY;
		dev_err(mcs->dev, "MCS:%d didn't respond to X2P calibration\n", i);
	}
	/* Clear X2P calibrate */
	mcs_reg_write(mcs, MCSX_MIL_GLOBAL, mcs_reg_read(mcs, MCSX_MIL_GLOBAL) & ~BIT_ULL(5));

	return err;
}

static void mcs_global_cfg(struct mcs *mcs)
{
	u64 val;

	/* Disable external bypass */
	val = mcs_reg_read(mcs, MCSX_MIL_GLOBAL);
	val &= ~BIT_ULL(6);
	mcs_reg_write(mcs, MCSX_MIL_GLOBAL, val);

	/* Set MCS to perform standard IEEE802.1AE macsec processing */
	mcs_reg_write(mcs, MCSX_IP_MODE, BIT_ULL(3));
}

static void mcs_set_hw_capabilities(struct mcs *mcs)
{
	struct hwinfo *hw = mcs->hw;

	hw->tcam_entries = 128;		/* TCAM entries */
	hw->secy_entries  = 128;	/* SecY entries */
	hw->sc_entries = 128;		/* SC CAM entries */
	hw->sa_entries = 256;		/* SA entries */
	hw->lmac_cnt = 20;		/* lmacs/ports per mcs block */
	hw->mcs_x2p_intf = 5;		/* x2p clabration intf */
	hw->mcs_blks = 1;		/* MCS blocks */
}

static int mcs_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct device *dev = &pdev->dev;
	struct mcs *mcs;
	int err = 0;

	mcs = devm_kzalloc(dev, sizeof(*mcs), GFP_KERNEL);
	if (!mcs)
		return -ENOMEM;

	mcs->hw = devm_kzalloc(dev, sizeof(struct hwinfo), GFP_KERNEL);
	if (!mcs->hw)
		return -ENOMEM;

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		pci_set_drvdata(pdev, NULL);
		return err;
	}

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed 0x%x\n", err);
		goto exit;
	}

	mcs->reg_base = pcim_iomap(pdev, PCI_CFG_REG_BAR_NUM, 0);
	if (!mcs->reg_base) {
		dev_err(dev, "mcs: Cannot map CSR memory space, aborting\n");
		err = -ENOMEM;
		goto exit;
	}

	pci_set_drvdata(pdev, mcs);
	mcs->pdev = pdev;
	mcs->dev = &pdev->dev;

	/* Set hardware capabilities */
	mcs_set_hw_capabilities(mcs);

	mcs_global_cfg(mcs);

	/* Performe X2P clibration */
	err = mcs_x2p_calibration(mcs);
	if (err)
		goto exit;

	mcs->mcs_id = (pci_resource_start(pdev, PCI_CFG_REG_BAR_NUM) >> 24)
			& MCS_ID_MASK;

	/* Set mcs tx side resources */
	err = mcs_alloc_struct_mem(mcs, &mcs->tx);
	if (err)
		goto exit;

	/* Set mcs rx side resources */
	err = mcs_alloc_struct_mem(mcs, &mcs->rx);
	if (err)
		goto exit;

	list_add(&mcs->mcs_list, &mcs_list);
	return 0;
exit:
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	return err;
}

static void mcs_remove(struct pci_dev *pdev)
{
	struct mcs *mcs = pci_get_drvdata(pdev);
	u64 val;

	/* Set MCS to external bypass */
	val = mcs_reg_read(mcs, MCSX_MIL_GLOBAL);
	val |= BIT_ULL(6);
	mcs_reg_write(mcs, MCSX_MIL_GLOBAL, val);

	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

struct pci_driver mcs_driver = {
	.name = DRV_NAME,
	.id_table = mcs_id_table,
	.probe = mcs_probe,
	.remove = mcs_remove,
};
