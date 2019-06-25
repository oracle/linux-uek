/* SPDX-License-Identifier: GPL-2.0
 * Marvell PTP driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef PTP_H
#define PTP_H

#include <linux/timecounter.h>
#include <linux/time64.h>
#include <linux/spinlock.h>

struct ptp {
	struct pci_dev *pdev;
	void __iomem *reg_base;
	u32 clock_rate;
};

struct ptp *ptp_get(void);
void ptp_put(struct ptp *ptp);

int ptp_adjfine(struct ptp *ptp, long scaled_ppm);
int ptp_get_clock(struct ptp *ptp, bool is_pmu, u64 *clki, u64 *tsc);

extern struct pci_driver ptp_driver;

#endif
