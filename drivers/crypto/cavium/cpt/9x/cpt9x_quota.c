// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/pci.h>
#include <linux/sysfs.h>
#include "cpt9x_quota.h"

static u64 quotas_get_sum(struct quotas *quotas)
{
	u64 lf_sum = 0;
	int i;

	for (i = 0; i < quotas->cnt; i++)
		lf_sum += quotas->a[i].val;

	return lf_sum;
}

static ssize_t quota_show(struct kobject *kobj, struct kobj_attribute *attr,
			  char *buf)
{
	struct quota *quota;
	int val;

	quota = container_of(attr, struct quota, sysfs);

	if (quota->base->lock)
		mutex_lock(quota->base->lock);
	val = quota->val;
	if (quota->base->lock)
		mutex_unlock(quota->base->lock);

	return snprintf(buf, PAGE_SIZE, "%d\n", val);
}

static ssize_t quota_store(struct kobject *kobj, struct kobj_attribute *attr,
			   const char *buf, size_t count)
{
	struct quota *quota;
	struct quotas *base;
	struct device *dev;
	int old_val, new_val, res = 0;
	u64 lf_sum;

	quota = container_of(attr, struct quota, sysfs);
	dev = quota->dev;
	base = quota->base;

	if (kstrtoint(buf, 0, &new_val)) {
		dev_err(dev, "Invalid %s quota: %s", attr->attr.name, buf);
		return -EIO;
	}
	if (new_val <= 0) {
		dev_err(dev, "Invalid %s quota: %d <= 0", attr->attr.name,
			new_val);
		return -EIO;
	}

	if (new_val > base->max) {
		dev_err(dev, "Invalid %s quota %d > max allowed %d",
			attr->attr.name, new_val, base->max);
		return -EIO;
	}

	if (base->lock)
		mutex_lock(base->lock);
	old_val = quota->val;

	if (base->ops.pre_store)
		res = base->ops.pre_store(quota->ops_arg, quota, new_val);

	if (res != 0) {
		res = -EIO;
		goto unlock;
	}

	lf_sum = quotas_get_sum(quota->base);
	if (lf_sum + new_val - quota->val > base->max_sum) {
		dev_err(dev,
			"Not enough %s resources, requested %d, avail %lld",
			attr->attr.name, new_val,
			base->max_sum - lf_sum + quota->val);
		res = -EIO;
		goto unlock;
	}
	quota->val = new_val;

	if (base->ops.post_store)
		base->ops.post_store(quota->ops_arg, quota, old_val);

	res = count;

unlock:
	if (base->lock)
		mutex_unlock(base->lock);
	return res;
}

struct quotas *cpt_quotas_alloc(u32 cnt, u32 max, u64 max_sum, int init_val,
				struct mutex *lock, struct quota_ops *ops)
{
	struct quotas *quotas;
	u64 i;

	if (cnt == 0)
		return NULL;

	quotas = kzalloc(sizeof(struct quotas) + cnt * sizeof(struct quota),
			 GFP_KERNEL);
	if (quotas == NULL)
		return NULL;

	for (i = 0; i < cnt; i++) {
		quotas->a[i].base = quotas;
		quotas->a[i].val = init_val;
	}

	quotas->cnt = cnt;
	quotas->max = max;
	quotas->max_sum = max_sum;
	if (ops) {
		quotas->ops.pre_store = ops->pre_store;
		quotas->ops.post_store = ops->post_store;
	}
	quotas->lock = lock;

	return quotas;
}

void cpt_quotas_free(struct quotas *quotas)
{
	u64 i;

	if (quotas == NULL)
		return;
	WARN_ON(quotas->cnt == 0);

	for (i = 0; i < quotas->cnt; i++)
		cpt_quota_sysfs_destroy(&quotas->a[i]);

	kfree(quotas);
}

int cpt_quota_sysfs_create(const char *name, struct kobject *parent,
			   struct device *log_dev, struct quota *quota,
			   void *ops_arg)
{
	int err;

	if (name == NULL || quota == NULL || log_dev == NULL)
		return -EINVAL;

	quota->sysfs.show = quota_show;
	quota->sysfs.store = quota_store;
	quota->sysfs.attr.name = name;
	quota->sysfs.attr.mode = 0664;
	quota->parent = parent;
	quota->dev = log_dev;
	quota->ops_arg = ops_arg;

	sysfs_attr_init(&quota->sysfs.attr);
	err = sysfs_create_file(quota->parent, &quota->sysfs.attr);
	if (err) {
		dev_err(quota->dev,
			"Failed to create '%s' quota sysfs for '%s'\n",
			name, kobject_name(quota->parent));
		return -EFAULT;
	}

	return 0;
}

int cpt_quota_sysfs_destroy(struct quota *quota)
{
	if (quota == NULL)
		return -EINVAL;
	if (quota->sysfs.attr.mode != 0) {
		sysfs_remove_file(quota->parent, &quota->sysfs.attr);
		quota->sysfs.attr.mode = 0;
	}
	return 0;
}
