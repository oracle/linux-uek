// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "ptp.h"
#include "mbox.h"
#include "rvu.h"

int rvu_mbox_handler_ptp_op(struct rvu *rvu, struct ptp_req *req,
			    struct ptp_rsp *rsp)
{
	int err = 0;

	if (!rvu->ptp)
		return -ENODEV;

	switch (req->op) {
	case PTP_OP_ADJFINE:
		err = ptp_adjfine(rvu->ptp, req->scaled_ppm);
		break;
	case PTP_OP_GET_CLOCK:
		err = ptp_get_clock(rvu->ptp, req->is_pmu, &rsp->clk,
				    &rsp->tsc);
		break;
	default:
		err = -EINVAL;
		break;
	}

	return err;
}
