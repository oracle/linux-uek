/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2019 Marvell.
 *
 */

#ifndef RVU_FIXES_H
#define RVU_FIXES_H

#define RVU_SMQVF_PCIFUNC	17

struct rvu;

void otx2smqvf_xmit(void);
void rvu_smqvf_xmit(struct rvu *rvu);

#endif /* RVU_FIXES_H */
