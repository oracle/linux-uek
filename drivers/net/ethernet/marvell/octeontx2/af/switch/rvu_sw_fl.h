/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#ifndef RVU_SW_FL_H
#define RVU_SW_FL_H

int rvu_sw_fl_stats_sync2db(struct rvu *rvu, unsigned long cookie[128],
			    u8 disabled[128],
			    u16 mcam_idx[128][2], int cnt);

#endif
