/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell MCS driver
 *
 * Copyright (C) 2022 Marvell.
 *
 */

#ifndef MCS_REG_H
#define MCS_REG_H

#include <linux/bits.h>

/* Registers */
#define MCSX_IP_MODE		0x900c8ull
#define MCSX_MIL_GLOBAL		0x80000ull
#define MCSX_MIL_RX_GBL_STATUS	0x800c8ull
#define MCSX_LINK_LMACX_CFG(a)	(0x90000ull + (a) * 0x800ull)
#endif
