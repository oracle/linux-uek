/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2024 Marvell.
 *
 */

#ifndef RVUM_H
#define RVUM_H

#include "../rvu.h"

void rvu_cn20k_set_pfvf_cnt(struct rvu *rvu);
void rvu_cn20k_check_block_implemented(struct rvu *rvu);
void rvu_cn20k_set_af_ready_bit(struct rvu *rvu, bool set);
void rvu_cn20k_set_blk_bit(struct rvu *rvu, struct rvu_block *block,
			   int devnum, bool is_pf, bool attach);
int rvu_cn20k_get_blk_addr(struct rvu *rvu, int blktype, int devnum,
			   bool is_pf);
#endif /* RVUM_H */
