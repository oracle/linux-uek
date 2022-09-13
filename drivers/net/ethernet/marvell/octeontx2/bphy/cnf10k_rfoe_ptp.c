// SPDX-License-Identifier: GPL-2.0
/* Marvell CNF10K BPHY RFOE Netdev Driver
 *
 * Copyright (C) 2021 Marvell.
 */

#include "cnf10k_rfoe.h"

#define EXT_PTP_CLK_RATE		(1000 * 1000000) /* Ext PTP clk rate */

static int cnf10k_rfoe_ptp_adjtime(struct ptp_clock_info *ptp_info, s64 delta)
{
	struct cnf10k_rfoe_ndev_priv *priv = container_of(ptp_info,
							  struct
							  cnf10k_rfoe_ndev_priv,
							  ptp_clock_info);

	mutex_lock(&priv->ptp_lock);
	timecounter_adjtime(&priv->time_counter, delta);
	mutex_unlock(&priv->ptp_lock);

	return 0;
}

static u64 ptp_calc_adjusted_comp(u64 ptp_clock_freq)
{
	u64 comp, adj = 0, cycles_per_sec, ns_drift = 0;
	u32 ptp_clock_nsec, cycle_time;
	int cycle;

	/* Errata:
	 * Issue #1: At the time of 1 sec rollover of the nano-second counter,
	 * the nano-second counter is set to 0. However, it should be set to
	 * (existing counter_value - 10^9).
	 *
	 * Issue #2: The nano-second counter rolls over at 0x3B9A_C9FF.
	 * It should roll over at 0x3B9A_CA00.
	 */

	/* calculate ptp_clock_comp value */
	comp = ((u64)1000000000ULL << 32) / ptp_clock_freq;
	/* use CYCLE_MULT to avoid accuracy loss due to integer arithmetic */
	cycle_time = NSEC_PER_SEC * CYCLE_MULT / ptp_clock_freq;
	/* cycles per sec */
	cycles_per_sec = ptp_clock_freq;

	/* check whether ptp nanosecond counter rolls over early */
	cycle = cycles_per_sec - 1;
	ptp_clock_nsec = (cycle * comp) >> 32;
	while (ptp_clock_nsec < NSEC_PER_SEC) {
		if (ptp_clock_nsec == 0x3B9AC9FF)
			goto calc_adj_comp;
		cycle++;
		ptp_clock_nsec = (cycle * comp) >> 32;
	}
	/* compute nanoseconds lost per second when nsec counter rolls over */
	ns_drift = ptp_clock_nsec - NSEC_PER_SEC;
	/* calculate ptp_clock_comp adjustment */
	if (ns_drift > 0) {
		adj = comp * ns_drift;
		adj = adj / 1000000000ULL;
	}
	/* speed up the ptp clock to account for nanoseconds lost */
	comp += adj;
	return comp;

calc_adj_comp:
	/* slow down the ptp clock to not rollover early */
	adj = comp * cycle_time;
	adj = adj / 1000000000ULL;
	adj = adj / CYCLE_MULT;
	comp -= adj;

	return comp;
}

static int cnf10k_rfoe_ptp_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	struct cnf10k_rfoe_ndev_priv *priv = container_of(ptp,
							  struct
							  cnf10k_rfoe_ndev_priv,
							  ptp_clock_info);
	bool neg_adj = false;
	u32 freq, freq_adj;
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


	if (priv->pdev->subsystem_device == PCI_SUBSYS_DEVID_CNF10K_B) {
		comp = ((u64)1000000000ull << 32) / priv->ptp_ext_clk_rate;
		adj = comp * ppb;
		adj = div_u64(adj, 1000000000ull);
		comp = neg_adj ? comp - adj : comp + adj;
	} else {
		/* calculate the new frequency based on ppb */
		freq_adj = (priv->ptp_ext_clk_rate * ppb) / 1000000000ULL;
		freq = neg_adj ? priv->ptp_ext_clk_rate + freq_adj :
				 priv->ptp_ext_clk_rate - freq_adj;
		comp = ptp_calc_adjusted_comp(freq);
	}

	writeq(comp, priv->ptp_reg_base + MIO_PTP_CLOCK_COMP);

	return 0;
}

u64 cnf10k_rfoe_read_ptp_clock(struct cnf10k_rfoe_ndev_priv *priv)
{
	u64 tstamp, sec, sec1,  nsec;

	if (priv->pdev->subsystem_device == PCI_SUBSYS_DEVID_CNF10K_B) {
		tstamp = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_HI);
	} else {
		sec = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_SEC) & 0xFFFFFFFFUL;
		nsec = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_HI);
		sec1 = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_SEC) & 0xFFFFFFFFUL;
		/* check nsec rollover */
		if (sec1 > sec) {
			nsec = readq(priv->ptp_reg_base + MIO_PTP_CLOCK_HI);
			sec = sec1;
		}
		tstamp = sec * NSEC_PER_SEC + nsec;
	}

	return tstamp;
}
EXPORT_SYMBOL_GPL(cnf10k_rfoe_read_ptp_clock);

static u64 cnf10k_rfoe_ptp_cc_read(const struct cyclecounter *cc)
{
	struct cnf10k_rfoe_ndev_priv *priv = container_of(cc,
							  struct cnf10k_rfoe_ndev_priv,
							  cycle_counter);
	return cnf10k_rfoe_read_ptp_clock(priv);
}

static int cnf10k_rfoe_ptp_gettime(struct ptp_clock_info *ptp_info,
				   struct timespec64 *ts)
{
	struct cnf10k_rfoe_ndev_priv *priv = container_of(ptp_info,
							  struct
							  cnf10k_rfoe_ndev_priv,
							  ptp_clock_info);
	u64 nsec;

	mutex_lock(&priv->ptp_lock);
	if (priv->pdev->subsystem_device == PCI_SUBSYS_DEVID_CNF10K_B &&
	    priv->ptp_cfg->use_ptp_alg) {
		nsec = cnf10k_rfoe_read_ptp_clock(priv);
		cnf10k_rfoe_calc_ptp_ts(priv, &nsec);
	} else {
		nsec = timecounter_read(&priv->time_counter);
	}
	mutex_unlock(&priv->ptp_lock);

	*ts = ns_to_timespec64(nsec);

	return 0;
}

static int cnf10k_rfoe_ptp_settime(struct ptp_clock_info *ptp_info,
				   const struct timespec64 *ts)
{
	struct cnf10k_rfoe_ndev_priv *priv = container_of(ptp_info,
							  struct
							  cnf10k_rfoe_ndev_priv,
							  ptp_clock_info);
	u64 nsec;

	nsec = timespec64_to_ns(ts);

	mutex_lock(&priv->ptp_lock);
	timecounter_init(&priv->time_counter, &priv->cycle_counter, nsec);
	mutex_unlock(&priv->ptp_lock);

	return 0;
}

static int cnf10k_rfoe_ptp_verify_pin(struct ptp_clock_info *ptp,
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

static void cnf10k_rfoe_ptp_extts_check(struct work_struct *work)
{
	struct cnf10k_rfoe_ndev_priv *priv = container_of(work, struct
							  cnf10k_rfoe_ndev_priv,
							  extts_work.work);
	struct ptp_clock_event event;
	u64 tstmp, new_thresh;

	mutex_lock(&priv->ptp_lock);
	tstmp = readq(priv->ptp_reg_base + MIO_PTP_TIMESTAMP);
	mutex_unlock(&priv->ptp_lock);
	tstmp = cnf10k_ptp_convert_timestamp(tstmp);

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

static int cnf10k_rfoe_ptp_enable(struct ptp_clock_info *ptp_info,
				  struct ptp_clock_request *rq, int on)
{
	struct cnf10k_rfoe_ndev_priv *priv = container_of(ptp_info,
							  struct
							  cnf10k_rfoe_ndev_priv,
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

static const struct ptp_clock_info cnf10k_rfoe_ptp_clock_info = {
	.owner          = THIS_MODULE,
	.name		= "CNF10K RFOE PTP",
	.max_adj        = 1000000000ull,
	.n_ext_ts       = 1,
	.n_pins         = 1,
	.pps            = 0,
	.adjfine	= cnf10k_rfoe_ptp_adjfine,
	.adjtime        = cnf10k_rfoe_ptp_adjtime,
	.gettime64      = cnf10k_rfoe_ptp_gettime,
	.settime64      = cnf10k_rfoe_ptp_settime,
	.enable         = cnf10k_rfoe_ptp_enable,
	.verify		= cnf10k_rfoe_ptp_verify_pin,
};

int cnf10k_rfoe_ptp_init(struct cnf10k_rfoe_ndev_priv  *priv)
{
	struct cyclecounter *cc;
	int err;

	cc = &priv->cycle_counter;
	cc->read = cnf10k_rfoe_ptp_cc_read;
	cc->mask = CYCLECOUNTER_MASK(64);
	cc->mult = 1;
	cc->shift = 0;

	timecounter_init(&priv->time_counter, &priv->cycle_counter,
			 ktime_to_ns(ktime_get_real()));

	snprintf(priv->extts_config.name, sizeof(priv->extts_config.name),
		 "CNF10K RFOE TSTAMP");
	priv->extts_config.index = 0;
	priv->extts_config.func = PTP_PF_NONE;
	priv->ptp_ext_clk_rate = EXT_PTP_CLK_RATE;

	priv->ptp_clock_info = cnf10k_rfoe_ptp_clock_info;
	snprintf(priv->ptp_clock_info.name, 16, "%s", priv->netdev->name);
	priv->ptp_clock_info.pin_config = &priv->extts_config;
	INIT_DELAYED_WORK(&priv->extts_work, cnf10k_rfoe_ptp_extts_check);
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

void cnf10k_rfoe_ptp_destroy(struct cnf10k_rfoe_ndev_priv *priv)
{
	ptp_clock_unregister(priv->ptp_clock);
	priv->ptp_clock = NULL;
}

int cnf10k_rfoe_ptp_tstamp2time(struct cnf10k_rfoe_ndev_priv *priv, u64 tstamp,
				u64 *tsns)
{
	if (!priv->ptp_clock)
		return -ENODEV;

	*tsns = timecounter_cyc2time(&priv->time_counter, tstamp);

	return 0;
}
EXPORT_SYMBOL_GPL(cnf10k_rfoe_ptp_tstamp2time);
