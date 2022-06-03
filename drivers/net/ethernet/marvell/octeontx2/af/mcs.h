/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell CN10K MCS driver
 *
 * Copyright (C) 2022 Marvell.
 *
 */

#ifndef MCS_H
#define MCS_H

#include <linux/bits.h>

#define PCI_DEVID_CN10K_MCS		0xA096

#define MCSX_LINK_LMAC_RANGE_MASK	GENMASK_ULL(19, 16)
#define MCSX_LINK_LMAC_BASE_MASK	GENMASK_ULL(11, 0)

#define MCS_ID_MASK			0x7

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

#endif /* MCS_H */
