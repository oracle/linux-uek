/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Multi-function driver for the IDT ClockMatrix(TM) and 82p33xxx families of
 * timing and synchronization devices.
 *
 * Copyright (C) 2019 Integrated Device Technology, Inc., a Renesas Company.
 */

#ifndef __RSMU_MFD_PRIVATE_H
#define __RSMU_MFD_PRIVATE_H

#include <linux/mfd/rsmu.h>

/* Maximum number of mfd devices */
#define RSMU_MAX_MFD_DEV		4

struct rsmu_dev {
	struct device *dev;
	void *client;
	struct regmap *regmap;
	struct mutex lock;
	enum rsmu_type type;
	u8 index;
	u16 page;
};

enum rsmu_mfd_type {
	RSMU_MFD_PTP		= 0,
	RSMU_MFD_CDEV		= 1,
	RSMU_MFD_NUM		= 2,
};
#endif /*  __LINUX_MFD_RSMU_H */
