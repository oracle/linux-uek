// SPDX-License-Identifier: GPL-2.0
/* Marvell BPHY RFOE PTP PHC support.
 *
 * Copyright (C) 2020 Marvell.
 */

#include "otx2_rfoe.h"

static int otx2_rfoe_ptp_adjtime(struct ptp_clock_info *ptp_info, s64 delta)
{
	return -EOPNOTSUPP;
}

static int otx2_rfoe_ptp_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	return -EOPNOTSUPP;
}

static int otx2_rfoe_ptp_gettime(struct ptp_clock_info *ptp_info,
				 struct timespec64 *ts)
{
	struct otx2_rfoe_ndev_priv *priv = container_of(ptp_info,
						struct otx2_rfoe_ndev_priv,
						ptp_clock_info);
	u64 nsec;

	mutex_lock(&priv->ptp_lock);
	nsec = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_HI);
	otx2_rfoe_calc_ptp_ts(priv, &nsec);
	mutex_unlock(&priv->ptp_lock);

	*ts = ns_to_timespec64(nsec);

	return 0;
}

static int otx2_rfoe_ptp_settime(struct ptp_clock_info *ptp_info,
				 const struct timespec64 *ts)
{
	return -EOPNOTSUPP;
}

static int otx2_rfoe_ptp_enable(struct ptp_clock_info *ptp_info,
				struct ptp_clock_request *rq, int on)
{
	return -EOPNOTSUPP;
}

static const struct ptp_clock_info otx2_rfoe_ptp_clock_info = {
	.owner          = THIS_MODULE,
	.max_adj        = 1000000000ull,
	.n_ext_ts       = 0,
	.n_pins         = 0,
	.pps            = 0,
	.adjfine	= otx2_rfoe_ptp_adjfine,
	.adjtime        = otx2_rfoe_ptp_adjtime,
	.gettime64      = otx2_rfoe_ptp_gettime,
	.settime64      = otx2_rfoe_ptp_settime,
	.enable         = otx2_rfoe_ptp_enable,
};

int otx2_rfoe_ptp_init(struct otx2_rfoe_ndev_priv *priv)
{
	int err;

	priv->ptp_clock_info = otx2_rfoe_ptp_clock_info;
	snprintf(priv->ptp_clock_info.name, 16, "%s", priv->netdev->name);
	priv->ptp_clock = ptp_clock_register(&priv->ptp_clock_info,
					     &priv->pdev->dev);
	if (IS_ERR_OR_NULL(priv->ptp_clock)) {
		priv->ptp_clock = NULL;
		err = PTR_ERR(priv->ptp_clock);
		return err;
	}

	mutex_init(&priv->ptp_lock);

	return 0;
}

void otx2_rfoe_ptp_destroy(struct otx2_rfoe_ndev_priv *priv)
{
	ptp_clock_unregister(priv->ptp_clock);
	priv->ptp_clock = NULL;
}
