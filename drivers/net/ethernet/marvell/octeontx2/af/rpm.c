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

	if (!is_lmac_valid(rpm, lmac_id))
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
		cfg = rpm_read(rpm, 0, RPMX_MTI_LPCSX_CONTROL(lmac_id));
		if (enable)
			cfg |= RPMX_MTI_PCS_LBK;
		else
			cfg &= ~RPMX_MTI_PCS_LBK;
		rpm_write(rpm, 0, RPMX_MTI_LPCSX_CONTROL(lmac_id), cfg);
	}

	return 0;
}

int rpm_get_rx_stats(void *rpmd, int lmac_id, int idx, u64 *rx_stat)
{
	struct cgx *rpm = rpmd;
	u64 val_lo, val_hi;

	if (!is_lmac_valid(rpm, lmac_id))
		return -ENODEV;

	mutex_lock(&rpm->lock);

	/* Update idx to point per lmac Rx statistics page */
	idx += lmac_id * rpm->mac_ops->rx_stats_cnt;

	/* Read lower 32 bits of counter */
	val_lo = rpm_read(rpm, 0, RPMX_MTI_STAT_RX_STAT_PAGES_COUNTERX +
			  (idx * 8));

	/* upon read of lower 32 bits, higher 32 bits are written
	 * to RPMX_MTI_STAT_DATA_HI_CDC
	 */
	val_hi = rpm_read(rpm, 0, RPMX_MTI_STAT_DATA_HI_CDC);

	*rx_stat = (val_hi << 32 | val_lo);

	mutex_unlock(&rpm->lock);
	return 0;
}

int rpm_get_tx_stats(void *rpmd, int lmac_id, int idx, u64 *tx_stat)
{
	struct cgx *rpm = rpmd;
	u64 val_lo, val_hi;

	if (!is_lmac_valid(rpm, lmac_id))
		return -ENODEV;

	mutex_lock(&rpm->lock);

	/* Update idx to point per lmac Tx statistics page */
	idx += lmac_id * rpm->mac_ops->tx_stats_cnt;

	val_lo = rpm_read(rpm, 0, RPMX_MTI_STAT_TX_STAT_PAGES_COUNTERX +
			    (idx * 8));
	val_hi = rpm_read(rpm, 0, RPMX_MTI_STAT_DATA_HI_CDC);

	*tx_stat = (val_hi << 32 | val_lo);

	mutex_unlock(&rpm->lock);
	return 0;
}
