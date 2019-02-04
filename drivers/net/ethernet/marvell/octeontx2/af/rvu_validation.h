// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef RVU_VALIDATION_H
#define RVU_VALIDATION_H

struct rvu;
struct rvu_quotas;

struct rvu_quota {
	struct kobj_attribute	sysfs;
	/* Device to scope logs to */
	struct device		*dev;
	/* Kobject of the sysfs file */
	struct kobject		*parent;
	/* Pointer to base structure */
	struct rvu_quotas	*base;
	/* Argument passed to the quota_ops when this quota is modified */
	void			*ops_arg;
	/* Value of the quota */
	int			val;
};

struct rvu_quota_ops {
	/*
	 * Called before sysfs store(). store() will proceed if returns 0.
	 * It is called with struct rvu_quotas::lock taken.
	 */
	int (*pre_store)(void *arg, struct rvu_quota *quota, int new_val);
	/** called after sysfs store(). */
	void (*post_store)(void *arg, struct rvu_quota *quota, int old_val);
};

struct rvu_quotas {
	struct rvu_quota_ops	ops;
	struct mutex		*lock; /* lock taken for each sysfs operation */
	u32			cnt; /* number of elements in arr */
	u32			max; /* maximum value for a single quota */
	u64			max_sum; /* maximum sum of all quotas */
	struct rvu_quota	a[0]; /* array of quota assignments */
};

struct rvu_limits {
	struct rvu_quotas	*sso;
	struct rvu_quotas	*ssow;
	struct rvu_quotas	*tim;
	struct rvu_quotas	*cpt;
	struct rvu_quotas	*npa;
	struct rvu_quotas	*nix;
	struct rvu_quotas	*smq;
	struct rvu_quotas	*tl4;
	struct rvu_quotas	*tl3;
	struct rvu_quotas	*tl2;
};

int rvu_policy_init(struct rvu *rvu);
void rvu_policy_destroy(struct rvu *rvu);
int rvu_check_rsrc_policy(struct rvu *rvu,
			  struct rsrc_attach *req, u16 pcifunc);
int rvu_check_txsch_policy(struct rvu *rvu, struct nix_txsch_alloc_req *req,
			   u16 pcifunc);

int rvu_mbox_handler_free_rsrc_cnt(struct rvu *rvu, struct msg_req *req,
				   struct free_rsrcs_rsp *rsp);
#endif /* RVU_VALIDATION_H */
