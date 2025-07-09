/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#ifndef RVU_SW_L2_H
#define RVU_SW_L2_H

int rvu_sw_l2_init_offl_wq(struct rvu *rvu, u16 pcifunc, bool fw_up);
int rvu_sw_l2_fdb_list_entry_add(struct rvu *rvu, u16 pcifunc, u8 *mac);
#endif
