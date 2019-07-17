/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2019 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef RVU_FIXES_H
#define RVU_FIXES_H

#define RVU_SMQVF_PCIFUNC	17

struct rvu;

void otx2smqvf_xmit(void);
void rvu_smqvf_xmit(struct rvu *rvu);

#endif /* RVU_FIXES_H */
