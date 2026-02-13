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

#define MCS_PN_THR		GENMASK_ULL(31, 0)
#define MCS_XPN_THR_0		GENMASK_ULL(63, 32)
#define MCS_XPN_THR_1		GENMASK_ULL(31, 0)

void cn20k_mcs_pn_threshold_set(struct mcs *mcs, struct mcs_set_pn_threshold *pn)
{
	u64 reg0, reg1, val;

	if (pn->dir == MCS_RX) {
		reg0 = MCSX_CPM_RX_SLAVE_PNX_THR_MEM0(pn->pn_id);
		reg1 = MCSX_CPM_RX_SLAVE_PNX_THR_MEM1(pn->pn_id);
		mcs_reg_write(mcs, MCSX_CPM_RX_SLAVE_SAX_PN_THR_MAP_MEM(pn->pn_id),
			      pn->pn_id);
	} else {
		reg0 = MCSX_CPM_TX_SLAVE_PNX_THR_MEM0(pn->pn_id);
		reg1 = MCSX_CPM_TX_SLAVE_PNX_THR_MEM1(pn->pn_id);
	}

	if (!pn->xpn) {
		val = FIELD_PREP(MCS_PN_THR, pn->threshold);
		mcs_reg_write(mcs, reg0, val);
		return;
	}

	/* setting XPN */
	val = FIELD_PREP(MCS_XPN_THR_0, pn->threshold);
	mcs_reg_write(mcs, reg0, val);
	val = FIELD_PREP(MCS_XPN_THR_1, (pn->threshold >> 32));
	mcs_reg_write(mcs, reg1, val);
}

void cn20k_mcs_get_port_cfg(struct mcs *mcs, struct mcs_port_cfg_get_req *req,
			    struct mcs_port_cfg_get_rsp *rsp)
{
	u64 reg = 0;

	reg = MCSX_PEX_TX_SLAVE_PORT_CFGX(req->port_id);
	rsp->cstm_tag_rel_mode_sel = mcs_reg_read(mcs, reg) >> 2;
	rsp->port_id = req->port_id;
	rsp->mcs_id = req->mcs_id;
}

void cn20k_mcs_set_port_cfg(struct mcs *mcs, struct mcs_port_cfg_set_req *req)
{
	u64 val;

	val = (req->cstm_tag_rel_mode_sel & 0x3) << 2;
	mcs_reg_write(mcs, MCSX_PEX_RX_SLAVE_PORT_CFGX(req->port_id), val);
	mcs_reg_write(mcs, MCSX_PEX_TX_SLAVE_PORT_CFGX(req->port_id), val);
}

static void cn20k_mcs_parser_cfg(struct mcs *mcs)
{
	u64 reg, val;

	/* VLAN CTag */
	val = BIT_ULL(0) | (0x8100ull & 0xFFFF) << 1 | BIT_ULL(17) |
	      BIT_ULL(24) | (0x4 & 0xF) << 20;
	/* RX */
	reg = MCSX_PEX_RX_SLAVE_VLAN_CFGX(0);
	mcs_reg_write(mcs, reg, val);

	/* TX */
	reg = MCSX_PEX_TX_SLAVE_VLAN_CFGX(0);
	mcs_reg_write(mcs, reg, val);

	/* VLAN STag */
	val = BIT_ULL(0) | (0x88a8ull & 0xFFFF) << 1 | BIT_ULL(18) |
	      BIT_ULL(24) | (0x4 & 0xF) << 20;
	/* RX */
	reg = MCSX_PEX_RX_SLAVE_VLAN_CFGX(1);
	mcs_reg_write(mcs, reg, val);

	/* TX */
	reg = MCSX_PEX_TX_SLAVE_VLAN_CFGX(1);
	mcs_reg_write(mcs, reg, val);
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
		val |= map->flow_id  << 16;
		reg = MCSX_CPM_TX_SLAVE_SECY_MAP_MEM_0X(map->flow_id);
	}

	mcs_reg_write(mcs, reg, val);
}

static void cn20k_mcs_tx_sa_mem_map_write(struct mcs *mcs,
					  struct mcs_tx_sc_sa_map *map)
{
	u64 reg, val;

	val = (map->sa_index0 & 0xFF) |
	      (map->sa_index1 & 0xFF) << 8 |
	      (map->rekey_ena & 0x1) << 16 |
	      (map->sa_index0_vld & 0x1) << 17 |
	      (map->sa_index1_vld & 0x1) << 18 |
	      (map->tx_sa_active & 0x1) << 19 |
	      map->sectag_sci << 20;
	reg = MCSX_CPM_TX_SLAVE_SA_MAP_MEM_0X(map->sc_id);
	mcs_reg_write(mcs, reg, val);

	val = map->sectag_sci >> 44;
	reg = MCSX_CPM_TX_SLAVE_SA_MAP_MEM_1X(map->sc_id);
	mcs_reg_write(mcs, reg, val);

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
