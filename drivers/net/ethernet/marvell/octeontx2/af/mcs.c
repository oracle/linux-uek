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

void mcs_pn_table_write(struct mcs *mcs, u8 pn_id, u64 next_pn, u8 dir)
{
	u64 reg;

	if (dir == MCS_RX)
		reg = MCSX_CPM_RX_SLAVE_SA_PN_TABLE_MEMX(pn_id);
	else
		reg = MCSX_CPM_TX_SLAVE_SA_PN_TABLE_MEMX(pn_id);
	mcs_reg_write(mcs, reg, next_pn);
}

void mcs_tx_sa_mem_map_write(struct mcs *mcs, struct mcs_tx_sc_sa_map *map)
{
	u64 reg, val;

	val = (map->sa_index0 & 0xFF) |
	      (map->sa_index1 & 0xFF) << 9 |
	      (map->rekey_ena & 0x1) << 18 |
	      (map->sa_index0_vld & 0x1) << 19 |
	      (map->sa_index1_vld & 0x1) << 20 |
	      (map->tx_sa_active & 0x1) << 21 |
	      map->sectag_sci << 22;
	reg = MCSX_CPM_TX_SLAVE_SA_MAP_MEM_0X(map->sc_id);
	mcs_reg_write(mcs, reg, val);

	val = map->sectag_sci >> 42;
	reg = MCSX_CPM_TX_SLAVE_SA_MAP_MEM_1X(map->sc_id);
	mcs_reg_write(mcs, reg, val);
}

void mcs_rx_sa_mem_map_write(struct mcs *mcs, struct mcs_rx_sc_sa_map *map)
{
	u64 val, reg;

	val = (map->sa_index & 0xFF) | map->sa_in_use << 9;

	reg = MCSX_CPM_RX_SLAVE_SA_MAP_MEMX(map->sc_id + map->an);
	mcs_reg_write(mcs, reg, val);
}

void mcs_sa_plcy_write(struct mcs *mcs, u64 *plcy, int sa_id, int dir)
{
	int reg_id;
	u64 reg;

	if (dir == MCS_RX) {
		for (reg_id = 0; reg_id < 8; reg_id++) {
			reg =  MCSX_CPM_RX_SLAVE_SA_PLCY_MEMX(reg_id, sa_id);
			mcs_reg_write(mcs, reg, plcy[reg_id]);
		}
	} else {
		for (reg_id = 0; reg_id < 9; reg_id++) {
			reg =  MCSX_CPM_TX_SLAVE_SA_PLCY_MEMX(reg_id, sa_id);
			mcs_reg_write(mcs, reg, plcy[reg_id]);
		}
	}
}

void mcs_ena_dis_sc_cam_entry(struct mcs *mcs, int sc_id, int ena)
{
	u64 reg, val;

	reg = MCSX_CPM_RX_SLAVE_SC_CAM_ENA(0);
	if (sc_id > 63)
		reg = MCSX_CPM_RX_SLAVE_SC_CAM_ENA(1);

	if (ena)
		val = mcs_reg_read(mcs, reg) | BIT_ULL(sc_id);
	else
		val = mcs_reg_read(mcs, reg) & ~BIT_ULL(sc_id);

	mcs_reg_write(mcs, reg, val);
}

void mcs_rx_sc_cam_write(struct mcs *mcs, u64 sci, u64 secy, int sc_id)
{
	mcs_reg_write(mcs, MCSX_CPM_RX_SLAVE_SC_CAMX(0, sc_id), sci);
	mcs_reg_write(mcs, MCSX_CPM_RX_SLAVE_SC_CAMX(1, sc_id), secy);
	/* Enable SC CAM */
	mcs_ena_dis_sc_cam_entry(mcs, sc_id, true);
}

void mcs_secy_plcy_write(struct mcs *mcs, u64 plcy, int secy_id, int dir)
{
	u64 reg;

	if (dir == MCS_RX)
		reg = MCSX_CPM_RX_SLAVE_SECY_PLCY_MEM_0X(secy_id);
	else
		reg = MCSX_CPM_TX_SLAVE_SECY_PLCY_MEMX(secy_id);

	mcs_reg_write(mcs, reg, plcy);

	if (dir == MCS_RX)
		mcs_reg_write(mcs, MCSX_CPM_RX_SLAVE_SECY_PLCY_MEM_1X(secy_id), 0x0ull);
}

void mcs_flowid_secy_map(struct mcs *mcs, struct secy_mem_map *map, int dir)
{
	u64 reg, val;

	val = (map->secy & 0x7F) | (map->ctrl_pkt & 0x1) << 8;
	if (dir == MCS_RX) {
		reg = MCSX_CPM_RX_SLAVE_SECY_MAP_MEMX(map->flow_id);
	} else {
		val |= (map->sc & 0x7F) << 9;
		reg = MCSX_CPM_TX_SLAVE_SECY_MAP_MEM_0X(map->flow_id);
	}

	mcs_reg_write(mcs, reg, val);
}

void mcs_ena_dis_flowid_entry(struct mcs *mcs, int flow_id, int dir, int ena)
{
	u64 reg, val;

	if (dir == MCS_RX) {
		reg = MCSX_CPM_RX_SLAVE_FLOWID_TCAM_ENA_0;
		if (flow_id > 63)
			reg = MCSX_CPM_RX_SLAVE_FLOWID_TCAM_ENA_1;
	} else {
		reg = MCSX_CPM_TX_SLAVE_FLOWID_TCAM_ENA_0;
		if (flow_id > 63)
			reg = MCSX_CPM_TX_SLAVE_FLOWID_TCAM_ENA_1;
	}

	/* Enable/Disable the tcam entry */
	if (ena)
		val = mcs_reg_read(mcs, reg) | BIT_ULL(flow_id);
	else
		val = mcs_reg_read(mcs, reg) & ~BIT_ULL(flow_id);

	mcs_reg_write(mcs, reg, val);
}

void mcs_flowid_entry_write(struct mcs *mcs, u64 *data, u64 *mask, int flow_id, int dir)
{
	int reg_id;
	u64 reg;

	if (dir == MCS_RX) {
		for (reg_id = 0; reg_id < 4; reg_id++) {
			reg = MCSX_CPM_RX_SLAVE_FLOWID_TCAM_DATAX(reg_id, flow_id);
			mcs_reg_write(mcs, reg, data[reg_id]);
			reg = MCSX_CPM_RX_SLAVE_FLOWID_TCAM_MASKX(reg_id, flow_id);
			mcs_reg_write(mcs, reg, mask[reg_id]);
		}
	} else {
		for (reg_id = 0; reg_id < 4; reg_id++) {
			reg = MCSX_CPM_TX_SLAVE_FLOWID_TCAM_DATAX(reg_id, flow_id);
			mcs_reg_write(mcs, reg, data[reg_id]);
			reg = MCSX_CPM_TX_SLAVE_FLOWID_TCAM_MASKX(reg_id, flow_id);
			mcs_reg_write(mcs, reg, mask[reg_id]);
		}
	}
}

void mcs_clear_secy_plcy(struct mcs *mcs, int secy_id, int dir)
{
	struct mcs_rsrc_map *map;
	int flow_id;

	if (dir == MCS_RX)
		map = &mcs->rx;
	else
		map = &mcs->tx;

	/* Clear secy memory to zero */
	mcs_secy_plcy_write(mcs, 0, secy_id, dir);

	/* Disable the tcam entry using this secy */
	for (flow_id = 0; flow_id < map->flow_ids.max; flow_id++) {
		if (map->flowid2secy_map[flow_id] != secy_id)
			continue;
		mcs_ena_dis_flowid_entry(mcs, flow_id, dir, false);
	}
}

int mcs_free_rsrc(struct rsrc_bmap *rsrc, u16 *pf_map, int rsrc_id, u16 pcifunc)
{
	/* Check if the rsrc_id is mapped to PF/VF */
	if (pf_map[rsrc_id] != pcifunc)
		return -EINVAL;

	rvu_free_rsrc(rsrc, rsrc_id);
	pf_map[rsrc_id] = 0;
	return 0;
}

/* Free all the cam resources mapped to pf */
int mcs_free_all_rsrc(struct mcs *mcs, int dir, u16 pcifunc)
{
	struct mcs_rsrc_map *map;
	int id;

	if (dir == MCS_RX)
		map = &mcs->rx;
	else
		map = &mcs->tx;

	/* free tcam entries */
	for (id = 0; id < map->flow_ids.max; id++) {
		if (map->flowid2pf_map[id] != pcifunc)
			continue;
		mcs_free_rsrc(&map->flow_ids, map->flowid2pf_map,
			      id, pcifunc);
		mcs_ena_dis_flowid_entry(mcs, id, dir, false);
	}

	/* free secy entries */
	for (id = 0; id < map->secy.max; id++) {
		if (map->secy2pf_map[id] != pcifunc)
			continue;
		mcs_free_rsrc(&map->secy, map->secy2pf_map,
			      id, pcifunc);
		mcs_clear_secy_plcy(mcs, id, dir);
	}

	/* free sc entries */
	for (id = 0; id < map->secy.max; id++) {
		if (map->sc2pf_map[id] != pcifunc)
			continue;
		mcs_free_rsrc(&map->sc, map->sc2pf_map, id, pcifunc);

		/* Disable SC CAM only on RX side */
		if (dir == MCS_RX)
			mcs_ena_dis_sc_cam_entry(mcs, id, false);
	}

	/* free sa entries */
	for (id = 0; id < map->sa.max; id++) {
		if (map->sa2pf_map[id] != pcifunc)
			continue;
		mcs_free_rsrc(&map->sa, map->sa2pf_map, id, pcifunc);
	}
	return 0;
}

int mcs_alloc_rsrc(struct rsrc_bmap *rsrc, u16 *pf_map, u16 pcifunc)
{
	int rsrc_id;

	rsrc_id = rvu_alloc_rsrc(rsrc);
	if (rsrc_id < 0)
		return -ENOMEM;
	pf_map[rsrc_id] = pcifunc;
	return rsrc_id;
}

int mcs_alloc_all_rsrc(struct mcs *mcs, u8 *flow_id, u8 *secy_id,
		       u8 *sc_id, u8 *sa_id, u16 pcifunc, int dir)
{
	struct mcs_rsrc_map *map;
	int id;

	if (dir == MCS_RX)
		map = &mcs->rx;
	else
		map = &mcs->tx;

	id = mcs_alloc_rsrc(&map->flow_ids, map->flowid2pf_map, pcifunc);
	if (id < 0)
		return -ENOMEM;
	*flow_id = id;

	id = mcs_alloc_rsrc(&map->secy, map->secy2pf_map, pcifunc);
	if (id < 0)
		return -ENOMEM;
	*secy_id = id;

	id = mcs_alloc_rsrc(&map->sc, map->sc2pf_map, pcifunc);
	if (id < 0)
		return -ENOMEM;
	*sc_id = id;

	id =  mcs_alloc_rsrc(&map->sa, map->sa2pf_map, pcifunc);
	if (id < 0)
		return -ENOMEM;
	*sa_id = id;
	return 0;
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
