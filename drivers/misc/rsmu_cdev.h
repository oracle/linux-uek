/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * This driver is developed for the IDT ClockMatrix(TM) of
 * timing and synchronization devices.
 *
 * Copyright (C) 2019 Integrated Device Technology, Inc., a Renesas Company.
 */
#ifndef __LINUX_RSMU_CDEV_H
#define __LINUX_RSMU_CDEV_H

#include <linux/cdev.h>

struct rsmu_ops;

/**
 * struct rsmu_cdev - Driver data for RSMU character device
 * @dev: pointer to platform device
 * @mfd: pointer to MFD device
 * @rsmu_cdev: character device handle
 * @lock: mutex to protect operations from being interrupted
 * @type: rsmu device type
 * @ops: rsmu device methods
 * @index: rsmu device index
 */
struct rsmu_cdev {
	struct device *dev;
	struct device *mfd;
	struct cdev rsmu_cdev;
	struct mutex *lock;
	enum rsmu_type type;
	struct rsmu_ops *ops;
	u8 index;
};

extern struct rsmu_ops cm_ops;
extern struct rsmu_ops sabre_ops;

struct rsmu_ops {
	enum rsmu_type type;
	int (*set_combomode)(struct rsmu_cdev *rsmu, u8 dpll, u8 mode);
	int (*get_dpll_state)(struct rsmu_cdev *rsmu, u8 dpll, u8 *state);
	int (*get_dpll_ffo)(struct rsmu_cdev *rsmu, u8 dpll,
			    struct rsmu_get_ffo *ffo);
};

/**
 * Enumerated type listing DPLL combination modes
 */
enum rsmu_dpll_combomode {
	E_COMBOMODE_CURRENT = 0,
	E_COMBOMODE_FASTAVG,
	E_COMBOMODE_SLOWAVG,
	E_COMBOMODE_HOLDOVER,
	E_COMBOMODE_MAX
};

/**
 * An id used to identify the respective child class states.
 */
enum rsmu_class_state {
	E_SRVLOINITIALSTATE = 0,
	E_SRVLOUNQUALIFIEDSTATE = 1,
	E_SRVLOLOCKACQSTATE = 2,
	E_SRVLOFREQUENCYLOCKEDSTATE = 3,
	E_SRVLOTIMELOCKEDSTATE = 4,
	E_SRVLOHOLDOVERINSPECSTATE = 5,
	E_SRVLOHOLDOVEROUTOFSPECSTATE = 6,
	E_SRVLOFREERUNSTATE = 7,
	E_SRVNUMBERLOSTATES = 8,
	E_SRVLOSTATEINVALID = 9,
};
#endif
