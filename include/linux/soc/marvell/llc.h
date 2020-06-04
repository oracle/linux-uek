/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTx2 LLC driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __MARVELL_LLC_H__
#define __MARVELL_LLC_H__

int octeontx2_llc_unlock(phys_addr_t addr, int size);
int octeontx2_llc_lock(phys_addr_t addr, int size);

#endif
