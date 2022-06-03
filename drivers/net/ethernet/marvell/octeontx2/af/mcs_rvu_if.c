// SPDX-License-Identifier: GPL-2.0
/* Marvell CN10K MCS driver
 *
 * Copyright (C) 2022 Marvell.
 *
 */

#include <linux/types.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "mcs.h"
#include "rvu.h"

int rvu_mcs_init(struct rvu *rvu)
{
	struct rvu_hwinfo *hw = rvu->hw;

	rvu->mcs_blk_cnt = mcs_get_blkcnt();

	if (!rvu->mcs_blk_cnt)
		return 0;

	return mcs_set_lmac_channels(hw->cgx_chan_base);
}
