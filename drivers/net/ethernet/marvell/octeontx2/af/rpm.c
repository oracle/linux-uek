// SPDX-License-Identifier: GPL-2.0
/*  Marvell OcteonTx2 RPM driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 *
 */

#include "cgx.h"
#include "lmac_common.h"

void rpm_write(struct cgx *rpm, u64 lmac, u64 offset, u64 val)
{
	cgx_write(rpm, lmac, offset, val);
}

u64 rpm_read(struct cgx *rpm, u64 lmac, u64 offset)
{
	return	cgx_read(rpm, lmac, offset);
}

int rpm_get_nr_lmacs(void *rpmd)
{
	struct cgx *rpm = rpmd;

	return hweight8(rpm_read(rpm, 0, CGXX_CMRX_RX_LMACS) & 0xFULL);
}
