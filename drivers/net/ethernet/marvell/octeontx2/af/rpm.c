// SPDX-License-Identifier: GPL-2.0
/*  Marvell OcteonTx2 RPM driver
 *
 * Copyright (C) 2020 Marvell.
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

u8 rpm_get_lmac_type(void *rpmd, int lmac_id)
{
	struct cgx *rpm = rpmd;
	u64 req = 0, resp;
	int err;

	req = FIELD_SET(CMDREG_ID, CGX_CMD_GET_LINK_STS, req);
	err = cgx_fwi_cmd_generic(req, &resp, rpm, 0);
	if (!err)
		return FIELD_GET(RESP_LINKSTAT_LMAC_TYPE, resp);
	return err;
}

int rpm_lmac_internal_loopback(void *rpmd, int lmac_id, bool enable)
{
	struct cgx *rpm = rpmd;
	u8 lmac_type;
	u64 cfg;

	if (!rpm || lmac_id >= rpm->lmac_count)
		return -ENODEV;
	lmac_type = rpm->mac_ops->get_lmac_type(rpm, lmac_id);
	if (lmac_type == LMAC_MODE_100G_R) {
		cfg = rpm_read(rpm, lmac_id, RPMX_MTI_PCS100X_CONTROL1);

		if (enable)
			cfg |= RPMX_MTI_PCS_LBK;
		else
			cfg &= ~RPMX_MTI_PCS_LBK;
		rpm_write(rpm, lmac_id, RPMX_MTI_PCS100X_CONTROL1, cfg);
	} else {
		cfg = rpm_read(rpm, lmac_id, RPMX_MTI_LPCSX_CONTROL1);
		if (enable)
			cfg |= RPMX_MTI_PCS_LBK;
		else
			cfg &= ~RPMX_MTI_PCS_LBK;
		rpm_write(rpm, lmac_id, RPMX_MTI_LPCSX_CONTROL1, cfg);
	}

	return 0;
}
