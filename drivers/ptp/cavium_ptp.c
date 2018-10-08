/**********************************************************************
* Author: Cavium, Inc.
*
* Contact: support@cavium.com
*          Please include "LiquidIO" in the subject.
*
* Copyright (c) 2003-2015 Cavium, Inc.
*
* This file is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License, Version 2, as
* published by the Free Software Foundation.
*
* This file is distributed in the hope that it will be useful, but
* AS-IS and WITHOUT ANY WARRANTY; without even the implied warranty
* of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE, TITLE, or
* NONINFRINGEMENT.  See the GNU General Public License for more
* details.
*
* This file may also be available under a different license from Cavium.
* Contact Cavium, Inc. for more information
**********************************************************************/

#include <linux/device.h>
#include <linux/module.h>

#include "cavium_ptp_regs.h"
#include "cavium_ptp.h"

#define DRV_NAME         "Cavium generic PTP Driver"
#define DRV_VERSION      "1.0"

/*
 * Interrupt service routine
 */

/* static irqreturn_t isr(int irq, void *priv) */

/*
 * PTP clock operations
 */

/**
 * \brief Adjust ptp frequency
 * @param ptp PTP clock info
 * @param ppb how much to adjust by, in parts-per-billion
 */
static int cavium_ptp_adjfreq(struct ptp_clock_info *ptp_info, s32 ppb)
{
	struct cavium_ptp_clock *cavium_ptp_clock =
		container_of(ptp_info, struct cavium_ptp_clock, ptp_info);
	struct cavium_ptp_clock_info *cavium_ptp_info =
		cavium_ptp_clock->cavium_ptp_info;
	union ptp_clock_comp clock_comp;
	u64 comp;
	u64 adj;
	unsigned long flags;
	int neg_adj = 0;

	if (ppb < 0) {
		neg_adj = 1;
		ppb = -ppb;
	}

	/* The hardware adds the clock compensation value to the PTP clock on
	 * every coprocessor clock cycle. Typical convention is that it
	 * represent number of nanosecond betwen each cycle. In this convention
	 * Compensation value is in 64 bit fixed-point representation where
	 * upper 32 bits are number of nanoseconds and lower is fractions of
	 * nanosecond.
	 * The ppb represent the ratio in "parts per bilion" by which the
	 * compensation value should be corrected.
	 * To calculate new compenstation value we use 64bit fixed point
	 * arithmetic on following formula comp = tbase + tbase*ppb/1G where
	 * tbase is the basic compensation value calculated initialy in
	 * cavium_ptp_init() -> tbase = 1/Hz. Then we use endian independent
	 * structure definition to write data to PTP register */
	comp = ((u64)1000000000ull << 32) / cavium_ptp_clock->clock_rate;
	adj = comp * ppb;
	adj = div_u64(adj, 1000000000ull);
	comp = neg_adj ? comp - adj : comp + adj;
	clock_comp.s.nanosec = comp >> 32;
	clock_comp.s.frnanosec = comp & 0xFFFFFFFF;

	spin_lock_irqsave(&cavium_ptp_clock->spin_lock, flags);
	cavium_ptp_info->reg_write(cavium_ptp_info,
				   PTP_CLOCK_COMP, clock_comp.u64);
	spin_unlock_irqrestore(&cavium_ptp_clock->spin_lock, flags);

	return 0;
}

/**
 * \brief Adjust ptp time
 * @param ptp PTP clock info
 * @param delta how much to adjust by, in nanosecs
 */
static int cavium_ptp_adjtime(struct ptp_clock_info *ptp_info, s64 delta)
{
	struct cavium_ptp_clock *cavium_ptp_clock =
		container_of(ptp_info, struct cavium_ptp_clock, ptp_info);
	struct cavium_ptp_clock_info *cavium_ptp_info =
		cavium_ptp_clock->cavium_ptp_info;
	unsigned long flags;

	spin_lock_irqsave(&cavium_ptp_clock->spin_lock, flags);
	cavium_ptp_clock->ptp_adjust += delta;
	spin_unlock_irqrestore(&cavium_ptp_clock->spin_lock, flags);

	/* notify child module about the time adjust */
	if (cavium_ptp_info->adjtime_clbck)
		cavium_ptp_info->adjtime_clbck(cavium_ptp_info,
					       cavium_ptp_clock->ptp_adjust);

	/* Sync, for network driver to get latest value */
	smp_mb();

	return 0;
}

/**
 * \brief Get hardware clock time, including any adjustment
 * @param ptp PTP clock info
 * @param ts timespec
 */
static int cavium_ptp_gettime(struct ptp_clock_info *ptp_info,
				  struct timespec64 *ts)
{
	struct cavium_ptp_clock *cavium_ptp_clock =
		container_of(ptp_info, struct cavium_ptp_clock, ptp_info);
	struct cavium_ptp_clock_info *cavium_ptp_info =
		cavium_ptp_clock->cavium_ptp_info;
	union ptp_clock_hi clock;
	unsigned long flags;
	u32 remainder;

	spin_lock_irqsave(&cavium_ptp_clock->spin_lock, flags);
	clock.u64 = cavium_ptp_info->reg_read(cavium_ptp_info, PTP_CLOCK_HI);
	/* adjust also need spinlock */
	clock.u64 += cavium_ptp_clock->ptp_adjust;
	spin_unlock_irqrestore(&cavium_ptp_clock->spin_lock, flags);

	ts->tv_sec = div_u64_rem(clock.s.nanosec, 1000000000ULL, &remainder);
	ts->tv_nsec = remainder;

	return 0;
}

/**
 * \brief Set hardware clock time. Reset adjustment
 * @param ptp PTP clock info
 * @param ts timespec
 */
static int cavium_ptp_settime(struct ptp_clock_info *ptp_info,
				  const struct timespec64 *ts)
{
	struct cavium_ptp_clock *cavium_ptp_clock =
		container_of(ptp_info, struct cavium_ptp_clock, ptp_info);
	struct cavium_ptp_clock_info *cavium_ptp_info =
		cavium_ptp_clock->cavium_ptp_info;
	union ptp_clock_hi clock;
	unsigned long flags;

	clock.s.nanosec = timespec_to_ns(ts);

	spin_lock_irqsave(&cavium_ptp_clock->spin_lock, flags);
	cavium_ptp_info->reg_write(cavium_ptp_info, PTP_CLOCK_HI, clock.u64);
	cavium_ptp_clock->ptp_adjust = 0; /* adjust also need spinlock */
	spin_unlock_irqrestore(&cavium_ptp_clock->spin_lock, flags);

	return 0;
}

/**
 * \brief Check if PTP is enabled
 * @param ptp PTP clock info
 * @param rq request
 * @param on is it on
 */
static int cavium_ptp_enable(struct ptp_clock_info *ptp_info,
				 struct ptp_clock_request *rq, int on)
{
	return -EOPNOTSUPP;
}



struct cavium_ptp_clock*
cavium_ptp_register(struct cavium_ptp_clock_info *cavium_ptp_info,
			struct device *dev)
{
	struct cavium_ptp_clock *cavium_ptp_clock = NULL;
	union ptp_clock_cfg clock_cfg;
	union ptp_clock_comp clock_comp;
	u64 val;

	cavium_ptp_clock = devm_kzalloc(dev, sizeof(*cavium_ptp_clock),
					GFP_KERNEL);
	if (!cavium_ptp_clock)
		return NULL;

	/* initialize genetic Cavium PTP structure */
	cavium_ptp_clock->cavium_ptp_info = cavium_ptp_info;
	spin_lock_init(&cavium_ptp_clock->spin_lock);
	cavium_ptp_clock->ptp_adjust = 0;
	cavium_ptp_clock->clock_rate = cavium_ptp_info->clock_rate;
	cavium_ptp_clock->ptp_info = (struct ptp_clock_info) {
		.owner		= THIS_MODULE,
		.max_adj	= 1000000000ull,
		.n_ext_ts	= 0,
		.n_pins		= 0,
		.pps		= 0,
		.adjfreq	= cavium_ptp_adjfreq,
		.adjtime	= cavium_ptp_adjtime,
		.gettime64	= cavium_ptp_gettime,
		.settime64	= cavium_ptp_settime,
		.enable		= cavium_ptp_enable,
	};
	snprintf(cavium_ptp_clock->ptp_info.name, 16, "%s",
		 cavium_ptp_info->name);

	/* enable PTP HW module */
	clock_cfg.u64 = cavium_ptp_info->reg_read(
		cavium_ptp_info, PTP_CLOCK_CFG);
	clock_cfg.s.ptp_en = 1;
	cavium_ptp_info->reg_write(cavium_ptp_info, PTP_CLOCK_CFG,
				   clock_cfg.u64);

	/* The hardware adds the clock compensation value to the PTP clock on
	 * every coprocessor clock cycle. Typical convention is tha it represent
	 * number of nanosecond betwen each cycle. In this convention
	 * Compensation value is in 64 bit fixed-point representation where
	 * upper 32 bits are number of nanoseconds and lower is fractions of
	 * nanosecond. To calculate it we use 64bit fixed point arithmetic on
	 * following formula comp = t = 1/Hz. Then we use endian independent
	 * structire definition to write data to PTP register */
	val = ((u64)1000000000ull << 32) / cavium_ptp_clock->clock_rate;
	clock_comp.s.nanosec = val >> 32;
	clock_comp.s.frnanosec = val & 0xFFFFFFFF;
	cavium_ptp_info->reg_write(cavium_ptp_info, PTP_CLOCK_COMP,
				   clock_comp.u64);

	/* register PTP clock in kernel */
	cavium_ptp_clock->ptp_clock =
		ptp_clock_register(&cavium_ptp_clock->ptp_info, dev);
	if (IS_ERR(cavium_ptp_clock->ptp_clock))
		goto err_stop_cavium_ptp;

	return cavium_ptp_clock;

err_stop_cavium_ptp:
	/* stop PTP HW module */
	clock_cfg.u64 = cavium_ptp_info->reg_read(
		cavium_ptp_info, PTP_CLOCK_CFG);
	clock_cfg.s.ptp_en = 0;
	cavium_ptp_info->reg_write(cavium_ptp_info, PTP_CLOCK_CFG,
				   clock_cfg.u64);

	devm_kfree(dev, cavium_ptp_clock);
	return NULL;
}
EXPORT_SYMBOL(cavium_ptp_register);

void cavium_ptp_remove(struct cavium_ptp_clock *cavium_ptp_clock)
{
	union ptp_clock_cfg clock_cfg;
	struct cavium_ptp_clock_info *cavium_ptp_info =
		cavium_ptp_clock->cavium_ptp_info;

	/* stop PTP HW module */
	clock_cfg.u64 = cavium_ptp_info->reg_read(
		cavium_ptp_info, PTP_CLOCK_CFG);
	clock_cfg.s.ptp_en = 0;
	cavium_ptp_info->reg_write(cavium_ptp_info, PTP_CLOCK_CFG,
				   clock_cfg.u64);

	ptp_clock_unregister(cavium_ptp_clock->ptp_clock);
}
EXPORT_SYMBOL(cavium_ptp_remove);

static int __init cavium_ptp_init_module(void)
{
	pr_info("%s, ver %s\n", DRV_NAME, DRV_VERSION);

	return 0;
}

static void __exit cavium_ptp_cleanup_module(void)
{
}

module_init(cavium_ptp_init_module);
module_exit(cavium_ptp_cleanup_module);

MODULE_AUTHOR("Cavium Networks, <support@cavium.com>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION(DRV_NAME);
MODULE_VERSION(DRV_VERSION);
