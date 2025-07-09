/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#ifndef RVU_SWITCH_H
#define RVU_SWITCH_H

/* RVU Switch */
void rvu_switch_enable(struct rvu *rvu);
void rvu_switch_disable(struct rvu *rvu);
void rvu_switch_update_rules(struct rvu *rvu, u16 pcifunc, bool ena);
void rvu_switch_enable_lbk_link(struct rvu *rvu, u16 pcifunc, bool ena);

#endif
