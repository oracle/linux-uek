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

#ifndef __CAVIUM_PTP_H__
#define __CAVIUM_PTP_H__

#include <linux/ptp_clock_kernel.h>

struct cavium_ptp_clock_info {
	u32 clock_rate;
	const char *name;
	u64 (*reg_read)(struct cavium_ptp_clock_info *info, u64 offset);
	void (*reg_write)(struct cavium_ptp_clock_info *info, u64 offset,
			  u64 val);
	void (*adjtime_clbck)(struct cavium_ptp_clock_info *info, s64 delta);
};

struct cavium_ptp_clock {
	/* PTP clock information */
	spinlock_t spin_lock;
	struct ptp_clock *ptp_clock;
	struct ptp_clock_info ptp_info;
	s64 ptp_adjust;
	u32 clock_rate;

	/* descendant data */
	struct cavium_ptp_clock_info *cavium_ptp_info;
};

struct thunder_ptp_clock {
	void __iomem *reg_base;
	struct pci_dev *pdev;
	struct cavium_ptp_clock *cavium_ptp_clock;
	struct cavium_ptp_clock_info cavium_ptp_info;
	s64 ptp_adjust;
};

extern struct thunder_ptp_clock *thunder_ptp_clock;
s64 thunder_get_adjtime(void);

extern struct cavium_ptp_clock *cavium_ptp_register(
	struct cavium_ptp_clock_info *info, struct device *dev);
extern void cavium_ptp_remove(struct cavium_ptp_clock *cavium_ptp_clock);

#endif /* __CAVIUM_PTP_H__ */
