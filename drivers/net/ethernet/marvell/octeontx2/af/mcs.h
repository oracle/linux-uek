/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell CN10K MCS driver
 *
 * Copyright (C) 2022 Marvell.
 *
 */

#ifndef MCS_H
#define MCS_H

#include <linux/bits.h>
#include "rvu.h"

#define PCI_DEVID_CN10K_MCS		0xA096

#define MCSX_LINK_LMAC_RANGE_MASK	GENMASK_ULL(19, 16)
#define MCSX_LINK_LMAC_BASE_MASK	GENMASK_ULL(11, 0)

#define MCS_ID_MASK			0x7

/* Reserved resources for default bypass entry */
#define MCS_RSRC_RSVD_CNT		1

struct sc_mem_map {
	u64 sci;
	u8 secy_id;
	u8 sc_id;
};

struct secy_mem_map {
	u8 flow_id;
	u8 secy;
	u8 ctrl_pkt;
	u8 sc;
	u64 sci;
};

struct mcs_rsrc_map {
	u16 *flowid2pf_map;
	u16 *secy2pf_map;
	u16 *sc2pf_map;
	u16 *sa2pf_map;
	u16 *flowid2secy_map;	/* bitmap flowid mapped to secy*/
	struct rsrc_bmap	flow_ids;
	struct rsrc_bmap	secy;
	struct rsrc_bmap	sc;
	struct rsrc_bmap	sa;
};

struct hwinfo {
	u8 tcam_entries;
	u8 secy_entries;
	u8 sc_entries;
	u16 sa_entries;
	u8 mcs_x2p_intf;
	u8 lmac_cnt;
	u8 mcs_blks;
};

struct mcs {
	void __iomem		*reg_base;
	struct pci_dev		*pdev;
	struct device		*dev;
	struct hwinfo		*hw;
	struct mcs_rsrc_map	tx;
	struct mcs_rsrc_map	rx;
	u8			mcs_id;
	struct list_head	mcs_list;
};

extern struct pci_driver mcs_driver;

static inline void mcs_reg_write(struct mcs *mcs, u64 offset, u64 val)
{
	writeq(val, mcs->reg_base + offset);
}

static inline u64 mcs_reg_read(struct mcs *mcs, u64 offset)
{
	return readq(mcs->reg_base + offset);
}

/* MCS APIs */
struct mcs *mcs_get_pdata(int mcs_id);
int mcs_get_blkcnt(void);
int mcs_set_lmac_channels(u16 base);

int mcs_alloc_rsrc(struct rsrc_bmap *rsrc, u16 *pf_map, u16 pcifunc);
int mcs_free_rsrc(struct rsrc_bmap *rsrc, u16 *pf_map, int rsrc_id, u16 pcifunc);
int mcs_alloc_all_rsrc(struct mcs *mcs, u8 *flowid, u8 *secy_id,
		       u8 *sc_id, u8 *sa_id, u16 pcifunc, int dir);
int mcs_free_all_rsrc(struct mcs *mcs, int dir, u16 pcifunc);
void mcs_clear_secy_plcy(struct mcs *mcs, int secy_id, int dir);
void mcs_ena_dis_flowid_entry(struct mcs *mcs, int id, int dir, int ena);
void mcs_ena_dis_sc_cam_entry(struct mcs *mcs, int id, int ena);
void mcs_flowid_entry_write(struct mcs *mcs, u64 *data, u64 *mask, int id, int dir);
void mcs_secy_plcy_write(struct mcs *mcs, u64 plcy, int id, int dir);
void mcs_rx_sc_cam_write(struct mcs *mcs, u64 sci, u64 secy, int sc_id);
void mcs_sa_plcy_write(struct mcs *mcs, u64 *plcy, int sa, int dir);
void mcs_map_sc_to_sa(struct mcs *mcs, u64 *sa_map, int sc, int dir);
void mcs_pn_table_write(struct mcs *mcs, u8 pn_id, u64 next_pn, u8 dir);
void mcs_tx_sa_mem_map_write(struct mcs *mcs, struct mcs_tx_sc_sa_map *map);
void mcs_flowid_secy_map(struct mcs *mcs, struct secy_mem_map *map, int dir);
void mcs_rx_sa_mem_map_write(struct mcs *mcs, struct mcs_rx_sc_sa_map *map);
#endif /* MCS_H */
