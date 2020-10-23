/* SPDX-License-Identifier: GPL-2.0 */
/*  Marvell OcteonTx2 RPM driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef RPM_H
#define RPM_H

/* PCI device IDs */
#define PCI_DEVID_CN10K_RPM		0xA060

/* Registers */
#define RPMX_CMRX_SW_INT                0x180
#define RPMX_CMRX_SW_INT_W1S            0x188
#define RPMX_CMRX_SW_INT_ENA_W1S        0x198

#define RPM_LMAC_FWI			0xa

/* Function Declarations */
int rpm_get_nr_lmacs(void *cgxd);
#endif /* RPM_H */
