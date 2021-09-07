// SPDX-License-Identifier: GPL-2.0
/* Marvell CNF10K BPHY RFOE Netdev Driver
 *
 * Copyright (C) 2021 Marvell.
 */

#include "cnf10k_rfoe.h"

static int cnf10k_rfoe_ptp_adjtime(struct ptp_clock_info *ptp_info, s64 delta)
{
	return -EOPNOTSUPP;
}

static int cnf10k_rfoe_ptp_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	return -EOPNOTSUPP;
}

static int cnf10k_rfoe_ptp_gettime(struct ptp_clock_info *ptp_info,
				   struct timespec64 *ts)
{
	struct cnf10k_rfoe_ndev_priv *priv = container_of(ptp_info,
						struct cnf10k_rfoe_ndev_priv,
						ptp_clock_info);
	u64 nsec;

	nsec = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_HI);
	*ts = ns_to_timespec64(nsec);

	return 0;
}

static int cnf10k_rfoe_ptp_settime(struct ptp_clock_info *ptp_info,
				   const struct timespec64 *ts)
{
	return -EOPNOTSUPP;
}

static int cnf10k_rfoe_ptp_enable(struct ptp_clock_info *ptp_info,
				  struct ptp_clock_request *rq, int on)
{
	return -EOPNOTSUPP;
}

static const struct ptp_clock_info cnf10k_rfoe_ptp_clock_info = {
	.owner          = THIS_MODULE,
	.max_adj        = 1000000000ull,
	.n_ext_ts       = 0,
	.n_pins         = 0,
	.pps            = 0,
	.adjfine	= cnf10k_rfoe_ptp_adjfine,
	.adjtime        = cnf10k_rfoe_ptp_adjtime,
	.gettime64      = cnf10k_rfoe_ptp_gettime,
	.settime64      = cnf10k_rfoe_ptp_settime,
	.enable         = cnf10k_rfoe_ptp_enable,
};

int cnf10k_rfoe_ptp_init(struct cnf10k_rfoe_ndev_priv  *priv)
{
	int err;

	priv->ptp_clock_info = cnf10k_rfoe_ptp_clock_info;
	snprintf(priv->ptp_clock_info.name, 16, "%s", priv->netdev->name);
	priv->ptp_clock = ptp_clock_register(&priv->ptp_clock_info,
					     &priv->pdev->dev);
	if (IS_ERR_OR_NULL(priv->ptp_clock)) {
		priv->ptp_clock = NULL;
		err = PTR_ERR(priv->ptp_clock);
		return err;
	}

	return 0;
}

void cnf10k_rfoe_ptp_destroy(struct cnf10k_rfoe_ndev_priv *priv)
{
	ptp_clock_unregister(priv->ptp_clock);
	priv->ptp_clock = NULL;
}
