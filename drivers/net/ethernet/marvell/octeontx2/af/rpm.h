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

#include <linux/bits.h>

/* PCI device IDs */
#define PCI_DEVID_CN10K_RPM		0xA060

/* Registers */
#define RPMX_CMRX_SW_INT                0x180
#define RPMX_CMRX_SW_INT_W1S            0x188
#define RPMX_CMRX_SW_INT_ENA_W1S        0x198
#define RPMX_CMRX_LINK_CFG		0x1070
#define RPMX_MTI_PCS100X_CONTROL1       0x20000
#define RPMX_MTI_LPCSX_CONTROL1         0x30000
#define RPMX_MTI_PCS_LBK                BIT_ULL(14)

#define RPMX_CMRX_LINK_RANGE_MASK	GENMASK_ULL(19, 16)
#define RPMX_CMRX_LINK_BASE_MASK	GENMASK_ULL(11, 0)

#define RPM_LMAC_FWI			0xa

/* Function Declarations */
int rpm_get_nr_lmacs(void *cgxd);
u8 rpm_get_lmac_type(void *cgx, int lmac_id);
int rpm_lmac_internal_loopback(void *cgx, int lmac_id, bool enable);
#endif /* RPM_H */
