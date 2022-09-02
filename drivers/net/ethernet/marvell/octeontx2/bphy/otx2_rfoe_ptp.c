// SPDX-License-Identifier: GPL-2.0
/* Marvell BPHY RFOE PTP PHC support.
 *
 * Copyright (C) 2020 Marvell.
 */

#include "otx2_rfoe.h"

#define EXT_PTP_CLK_RATE		(125 * 1000000) /* Ext PTP clk rate */

static int otx2_rfoe_ptp_adjtime(struct ptp_clock_info *ptp_info, s64 delta)
{
	struct otx2_rfoe_ndev_priv *priv = container_of(ptp_info,
							struct
							otx2_rfoe_ndev_priv,
							ptp_clock_info);
	u64 offset;

	mutex_lock(&priv->ptp_lock);
	timecounter_adjtime(&priv->time_counter, delta);
	/* Adjust the offset that is shared with the host PHC driver
	 * whenever it is adjusted.  This offset is initialized
	 * when the timecounter is initialized, and updated here where an
	 * operation that adjusts the absolute value of the timecounter is
	 * performed.
	 */
	offset = readq(priv->ptp_reg_base + MIO_PTP_CKOUT_THRESH_HI);
	writeq(offset + delta, priv->ptp_reg_base + MIO_PTP_CKOUT_THRESH_HI);
	mutex_unlock(&priv->ptp_lock);

	return 0;
}

static int otx2_rfoe_ptp_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	struct otx2_rfoe_ndev_priv *priv = container_of(ptp,
							struct
							otx2_rfoe_ndev_priv,
							ptp_clock_info);
	bool neg_adj = false;
	u64 comp, adj;
	s64 ppb;

	if (scaled_ppm < 0) {
		neg_adj = true;
		scaled_ppm = -scaled_ppm;
	}

	/* The hardware adds the clock compensation value to the PTP clock
	 * on every coprocessor clock cycle. Typical convention is that it
	 * represent number of nanosecond betwen each cycle. In this
	 * convention compensation value is in 64 bit fixed-point
	 * representation where upper 32 bits are number of nanoseconds
	 * and lower is fractions of nanosecond.
	 * The scaled_ppm represent the ratio in "parts per million" by which
	 * the compensation value should be corrected.
	 * To calculate new compenstation value we use 64bit fixed point
	 * arithmetic on following formula
	 * comp = tbase + tbase * scaled_ppm / (1M * 2^16)
	 * where tbase is the basic compensation value calculated
	 * initialy in the probe function.
	 */
	/* convert scaled_ppm to ppb */
	ppb = 1 + scaled_ppm;
	ppb *= 125;
	ppb >>= 13;

	comp = ((u64)1000000000ull << 32) / priv->ptp_ext_clk_rate;
	adj = comp * ppb;
	adj = div_u64(adj, 1000000000ull);
	comp = neg_adj ? comp - adj : comp + adj;

	writeq(comp, priv->ptp_reg_base + MIO_PTP_CLOCK_COMP);

	return 0;
}

static u64 otx2_rfoe_ptp_cc_read(const struct cyclecounter *cc)
{
	struct otx2_rfoe_ndev_priv *priv = container_of(cc, struct
							otx2_rfoe_ndev_priv,
							cycle_counter);

	return readq(priv->ptp_reg_base + MIO_PTP_CLOCK_HI);
}

static int otx2_rfoe_ptp_gettime(struct ptp_clock_info *ptp_info,
				 struct timespec64 *ts)
{
	struct otx2_rfoe_ndev_priv *priv = container_of(ptp_info,
							struct
							otx2_rfoe_ndev_priv,
							ptp_clock_info);
	u64 nsec;

	mutex_lock(&priv->ptp_lock);
	if (priv->pdev->subsystem_device == PCI_SUBSYS_DEVID_OCTX2_95XXN &&
	    priv->ptp_cfg->use_ptp_alg) {
		nsec = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_HI);
		otx2_rfoe_calc_ptp_ts(priv, &nsec);
	} else {
		nsec = timecounter_read(&priv->time_counter);
	}
	mutex_unlock(&priv->ptp_lock);

	*ts = ns_to_timespec64(nsec);

	return 0;
}

static int otx2_rfoe_ptp_settime(struct ptp_clock_info *ptp_info,
				 const struct timespec64 *ts)
{
	struct otx2_rfoe_ndev_priv *priv = container_of(ptp_info,
							struct
							otx2_rfoe_ndev_priv,
							ptp_clock_info);
	u64 nsec;

	nsec = timespec64_to_ns(ts);

	mutex_lock(&priv->ptp_lock);
	timecounter_init(&priv->time_counter, &priv->cycle_counter, nsec);
	/* We need to share an offset in ns from the PTP hardware counter
	 * and the UTC time so that the host PHC driver using the Octeon
	 * PTP counter can get the same real time as this PTP clock
	 * represents.  This is a combination of the timecounter fields
	 * nsec and cycle_last, and we can use timecounter_cyc2time() to
	 * generate this offset.
	 * We get the time in ns of the counter value of 0.  The host will
	 * then read the cycle counter, and add this value to the counter
	 * to obtain the real time as maintained by this timecounter.
	 */
	nsec = timecounter_cyc2time(&priv->time_counter, 0);
	writeq(nsec, priv->ptp_reg_base + MIO_PTP_CKOUT_THRESH_HI);
	mutex_unlock(&priv->ptp_lock);

	return 0;
}

static int otx2_rfoe_ptp_verify_pin(struct ptp_clock_info *ptp,
				    unsigned int pin,
				    enum ptp_pin_function func,
				    unsigned int chan)
{
	switch (func) {
	case PTP_PF_NONE:
	case PTP_PF_EXTTS:
		break;
	case PTP_PF_PEROUT:
	case PTP_PF_PHYSYNC:
		return -1;
	}
	return 0;
}

static void otx2_rfoe_ptp_extts_check(struct work_struct *work)
{
	struct otx2_rfoe_ndev_priv *priv = container_of(work, struct
							otx2_rfoe_ndev_priv,
							extts_work.work);
	struct ptp_clock_event event;
	u64 tstmp, new_thresh;

	mutex_lock(&priv->ptp_lock);
	tstmp = readq(priv->ptp_reg_base + MIO_PTP_TIMESTAMP);
	mutex_unlock(&priv->ptp_lock);

	if (tstmp != priv->last_extts) {
		event.type = PTP_CLOCK_EXTTS;
		event.index = 0;
		event.timestamp = timecounter_cyc2time(&priv->time_counter, tstmp);
		ptp_clock_event(priv->ptp_clock, &event);
		priv->last_extts = tstmp;

		new_thresh = tstmp % 500000000;
		if (priv->thresh != new_thresh) {
			mutex_lock(&priv->ptp_lock);
			writeq(new_thresh,
			       priv->ptp_reg_base + MIO_PTP_PPS_THRESH_HI);
			mutex_unlock(&priv->ptp_lock);
			priv->thresh = new_thresh;
		}
	}
	schedule_delayed_work(&priv->extts_work, msecs_to_jiffies(200));
}

static int otx2_rfoe_ptp_enable(struct ptp_clock_info *ptp_info,
				struct ptp_clock_request *rq, int on)
{
	struct otx2_rfoe_ndev_priv *priv = container_of(ptp_info,
							struct
							otx2_rfoe_ndev_priv,
							ptp_clock_info);
	int pin = -1;

	switch (rq->type) {
	case PTP_CLK_REQ_EXTTS:
		pin = ptp_find_pin(priv->ptp_clock, PTP_PF_EXTTS,
				   rq->extts.index);
		if (pin < 0)
			return -EBUSY;
		if (on)
			schedule_delayed_work(&priv->extts_work,
					      msecs_to_jiffies(200));
		else
			cancel_delayed_work_sync(&priv->extts_work);
		return 0;
	default:
		break;
	}
	return -EOPNOTSUPP;
}

static const struct ptp_clock_info otx2_rfoe_ptp_clock_info = {
	.owner          = THIS_MODULE,
	.name		= "RFOE PTP",
	.max_adj        = 1000000000ull,
	.n_ext_ts       = 1,
	.n_pins         = 1,
	.pps            = 0,
	.adjfine	= otx2_rfoe_ptp_adjfine,
	.adjtime        = otx2_rfoe_ptp_adjtime,
	.gettime64      = otx2_rfoe_ptp_gettime,
	.settime64      = otx2_rfoe_ptp_settime,
	.enable         = otx2_rfoe_ptp_enable,
	.verify		= otx2_rfoe_ptp_verify_pin,
};

int otx2_rfoe_ptp_init(struct otx2_rfoe_ndev_priv *priv)
{
	struct cyclecounter *cc;
	int err;
	u64 tmp;

	cc = &priv->cycle_counter;
	cc->read = otx2_rfoe_ptp_cc_read;
	cc->mask = CYCLECOUNTER_MASK(64);
	cc->mult = 1;
	cc->shift = 0;

	timecounter_init(&priv->time_counter, &priv->cycle_counter,
			 ktime_to_ns(ktime_get_real()));
	snprintf(priv->extts_config.name, sizeof(priv->extts_config.name),
		 "RFOE TSTAMP");
	priv->extts_config.index = 0;
	priv->extts_config.func = PTP_PF_NONE;
	priv->ptp_clock_info = otx2_rfoe_ptp_clock_info;
	priv->ptp_ext_clk_rate = EXT_PTP_CLK_RATE;
	if (priv->pdev->subsystem_device == PCI_SUBSYS_DEVID_OCTX2_95XXN)
		priv->ptp_ext_clk_rate = 950000000UL;
	snprintf(priv->ptp_clock_info.name, 16, "%s", priv->netdev->name);
	priv->ptp_clock_info.pin_config = &priv->extts_config;
	INIT_DELAYED_WORK(&priv->extts_work, otx2_rfoe_ptp_extts_check);
	priv->ptp_clock = ptp_clock_register(&priv->ptp_clock_info,
					     &priv->pdev->dev);
	if (IS_ERR_OR_NULL(priv->ptp_clock)) {
		priv->ptp_clock = NULL;
		err = PTR_ERR(priv->ptp_clock);
		return err;
	}
	/* Enable PTP CKOUT, as we use the MIO_PTP_CKOUT_THRESH_HI register
	 * to share the offset to be added to MIO_PTP_CLOCK_HI to get UTC
	 * time in nanoseconds.  The MIO_PTP_CKOUT_THRESH_HI is updated
	 * whenever any changes are made to the offset through the
	 * _settime() or _adjtime() functions.
	 *
	 */
	tmp = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_CFG);
	writeq(tmp | PTP_CLOCK_CFG_CKOUT_EN,
	       priv->ptp_reg_base + MIO_PTP_CLOCK_CFG);
	tmp = timecounter_cyc2time(&priv->time_counter, 0);
	writeq(tmp, priv->ptp_reg_base + MIO_PTP_CKOUT_THRESH_HI);


	mutex_init(&priv->ptp_lock);

	return 0;
}

void otx2_rfoe_ptp_destroy(struct otx2_rfoe_ndev_priv *priv)
{
	ptp_clock_unregister(priv->ptp_clock);
	priv->ptp_clock = NULL;
}
