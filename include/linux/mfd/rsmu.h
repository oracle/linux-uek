/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Multi-function driver for the IDT ClockMatrix(TM) and 82p33xxx families of
 * timing and synchronization devices.
 *
 * Copyright (C) 2019 Integrated Device Technology, Inc., a Renesas Company.
 */

#ifndef __LINUX_MFD_RSMU_H
#define __LINUX_MFD_RSMU_H

/* We only support Clockmatrix and Sabre now */
enum rsmu_type {
	RSMU_CM		= 0,
	RSMU_SABRE	= 1,
	RSMU_NONE	= 2,
};

/**
 *
 * struct rsmu_pdata - platform data structure for MFD cell devices.
 *
 * @lock: Mutex used by cell devices to make sure a series of requests
 * are not interrupted.
 *
 * @type: RSMU device type.
 *
 * @index: Device index.
 */
struct rsmu_pdata {
	enum rsmu_type type;
	struct mutex *lock;
	u8 index;
};

/**
 * NOTE: the functions below are not intended for use outside
 * of the IDT synchronization management unit drivers
 */
extern int rsmu_write(struct device *dev, u16 reg, u8 *buf, u16 size);
extern int rsmu_read(struct device *dev, u16 reg, u8 *buf, u16 size);
#endif /*  __LINUX_MFD_RSMU_H */
