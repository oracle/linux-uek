/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _CPT9X_QUOTA_H_
#define _CPT9X_QUOTA_H_

#include <linux/kobject.h>
#include <linux/mutex.h>

struct quotas;

struct quota {
	struct kobj_attribute	sysfs;
	/* Device to scope logs to */
	struct device		*dev;
	/* Kobject of the sysfs file */
	struct kobject		*parent;
	/* Pointer to base structure */
	struct quotas		*base;
	/* Argument passed to the quota_ops when this quota is modified */
	void			*ops_arg;
	/* Value of the quota */
	int			val;
};

struct quota_ops {
	/**
	 * Called before sysfs store(). store() will proceed if returns 0.
	 * It is called with struct quotas::lock taken.
	 */
	int (*pre_store)(void *arg, struct quota *quota, int new_val);
	/** called after sysfs store(). */
	void (*post_store)(void *arg, struct quota *quota, int old_val);
};

struct quotas {
	struct quota_ops ops;
	struct mutex *lock;	/* lock taken for each sysfs operation */
	u32 cnt;		/* number of elements in arr */
	u32 max;		/* maximum value for a single quota */
	u64 max_sum;		/* maximum sum of all quotas */
	struct quota a[0];	/* array of quota assignments */
};

/**
 * Allocate and setup quotas structure.
 *
 * @p cnt number of quotas to allocate
 * @p max maximum value of a single quota
 * @p max_sum maximum sum of all quotas
 * @p init_val initial value set to all quotas
 * @p ops callbacks for sysfs manipulation notifications
 */
struct quotas *cpt_quotas_alloc(u32 cnt, u32 max, u64 max_sum,
				int init_val, struct mutex *lock,
				struct quota_ops *ops);
/**
 * Frees quota array and any sysfs entries associated with it.
 */
void cpt_quotas_free(struct quotas *quotas);

/**
 * Create a sysfs entry controling given quota entry.
 *
 * File created under parent will read the current value of the quota and
 * write will take quotas lock and check if new value does not exceed
 * configured maximum values.
 *
 * @return 0 if succeeded, negative error code otherwise.
 */
int cpt_quota_sysfs_create(const char *name, struct kobject *parent,
			   struct device *log_dev, struct quota *quota,
			   void *ops_arg);
/**
 * Remove sysfs entry for a given quota if it was created.
 */
int cpt_quota_sysfs_destroy(struct quota *quota);

#endif /* _CPT9X_QUOTA_H_ */
