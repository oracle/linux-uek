/* SPDX-License-Identifier: GPL-2.0 */
/* Marvell PTP driver
 *
 * Copyright (C) 2020 Marvell.
 *
 */

#ifndef PTP_H
#define PTP_H

#include <linux/timecounter.h>
#include <linux/time64.h>
#include <linux/spinlock.h>

#define PPS_HALF_CYCLE_NS	500000000
#define PPS_FULL_CYCLE_NS	1000000000
struct ptp {
	struct pci_dev *pdev;
	void __iomem *reg_base;
	u64 (*read_ptp_tstmp)(struct ptp *ptp);
	spinlock_t ptp_lock; /* lock */
	struct hrtimer hrtimer;
	u64 thresh_delta;
	u32 clock_rate;
};

struct ptp *ptp_get(void);
void ptp_put(struct ptp *ptp);
void ptp_start(struct ptp *ptp, u64 sclk, u32 ext_clk_freq, u32 extts);

extern struct pci_driver ptp_driver;

#endif
