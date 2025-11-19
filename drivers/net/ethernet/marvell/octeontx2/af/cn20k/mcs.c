// SPDX-License-Identifier: GPL-2.0
/* Marvell cn20k MCS driver
 *
 * Copyright (C) 2025 Marvell.
 */

#include "mcs.h"
#include "mcs_reg.h"

#define SECY_MASK	0x7F
#define SC_MASK		0x7F
#define SA_MASK		0xFF
#define MCSX_EXTERNAL_BYPASS	0x800e8UL

static void cn20k_mcs_set_hw_capabilities(struct mcs *mcs)
{
	struct hwinfo *hw = mcs->hw;

	hw->tcam_entries = 128;		/* TCAM entries */
	hw->secy_entries  = 128;	/* SecY entries */
	hw->sc_entries = 128;		/* SC CAM entries */
	hw->sa_entries = 256;		/* SA entries */
	hw->lmac_cnt = 20;		/* lmacs/ports per mcs block */
	hw->mcs_x2p_intf = 1;		/* x2p clabration intf */
	hw->mcs_blks = 1;		/* MCS blocks */
}

static void cn20k_mcs_parser_cfg(struct mcs *mcs)
{
	/* Default configuration is enough for parsing basic  IEEE 802.1AE-2006
	 * frames
	 */
}

static void cn20k_mcs_set_external_bypass(struct mcs *mcs, bool state)
{
	mcs_reg_write(mcs, MCSX_EXTERNAL_BYPASS, state);
}

static void cn20k_mcs_flowid_secy_map(struct mcs *mcs,
				      struct secy_mem_map *map, int dir)
{
	u64 reg, val;

	val = (map->secy & SECY_MASK) | (map->ctrl_pkt & 0x1) << 7;
	if (dir == MCS_RX) {
		reg = MCSX_CPM_RX_SLAVE_SECY_MAP_MEMX(map->flow_id);
	} else {
		val |= (map->sc & SC_MASK) << 8;
		reg = MCSX_CPM_TX_SLAVE_SECY_MAP_MEM_0X(map->flow_id);
	}

	mcs_reg_write(mcs, reg, val);
}

static void cn20k_mcs_tx_sa_mem_map_write(struct mcs *mcs,
					  struct mcs_tx_sc_sa_map *map)
{
	u64 reg, val;

	val = (map->sa_index0 & 0x7F) | (map->sa_index1 & 0x7F) << 7;

	reg = MCSX_CPM_TX_SLAVE_SA_MAP_MEM_0X(map->sc_id);
	mcs_reg_write(mcs, reg, val);

	reg = MCSX_CPM_TX_SLAVE_AUTO_REKEY_ENABLE_0;
	val = mcs_reg_read(mcs, reg);

	if (map->rekey_ena)
		val |= BIT_ULL(map->sc_id);
	else
		val &= ~BIT_ULL(map->sc_id);

	mcs_reg_write(mcs, reg, val);

	mcs_reg_write(mcs, MCSX_CPM_TX_SLAVE_SA_INDEX0_VLDX(map->sc_id),
		      map->sa_index0_vld);
	mcs_reg_write(mcs, MCSX_CPM_TX_SLAVE_SA_INDEX1_VLDX(map->sc_id),
		      map->sa_index1_vld);
	mcs_reg_write(mcs, MCSX_CPM_TX_SLAVE_TX_SA_ACTIVEX(map->sc_id),
		      map->tx_sa_active);
}

static void cn20k_mcs_rx_sa_mem_map_write(struct mcs *mcs,
					  struct mcs_rx_sc_sa_map *map)
{
	u64 val, reg;

	val = (map->sa_index & SA_MASK) | (map->sa_in_use << 8);

	reg = MCSX_CPM_RX_SLAVE_SA_MAP_MEMX((4 * map->sc_id) + map->an);
	mcs_reg_write(mcs, reg, val);
}

static struct mcs_ops cn20k_mcs_ops   = {
	.mcs_set_hw_capabilities	= cn20k_mcs_set_hw_capabilities,
	.mcs_parser_cfg			= cn20k_mcs_parser_cfg,
	.mcs_set_external_bypass	= cn20k_mcs_set_external_bypass,
	.mcs_tx_sa_mem_map_write	= cn20k_mcs_tx_sa_mem_map_write,
	.mcs_rx_sa_mem_map_write	= cn20k_mcs_rx_sa_mem_map_write,
	.mcs_flowid_secy_map		= cn20k_mcs_flowid_secy_map,
	.mcs_bbe_intr_handler		= NULL,
	.mcs_pab_intr_handler		= NULL,
};

struct mcs_ops *cn20ka_get_mac_ops(void)
{
	return &cn20k_mcs_ops;
}
