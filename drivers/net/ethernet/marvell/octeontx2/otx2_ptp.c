// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 PTP support for ethernet driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/ptp_clock_kernel.h>

#include "otx2_common.h"
#include "otx2_ptp.h"

struct otx2_ptp {
	struct kref refcount;
	struct ptp_clock_info ptp_info;
	struct ptp_clock *ptp_clock;
	struct otx2_nic *nic;

	/* Serialize access to cycle_counter, time_counter and reg_base */
	spinlock_t spin_lock;
	struct cyclecounter cycle_counter;
	struct timecounter time_counter;
};

static struct otx2_ptp *ptp_ptr;
static DEFINE_MUTEX(ptp_mutex);

static int otx2_ptp_adjfine(struct ptp_clock_info *ptp_info, long scaled_ppm)
{
	struct otx2_ptp *ptp = container_of(ptp_info, struct otx2_ptp,
					    ptp_info);
	struct ptp_req *req;
	int err;

	if (!ptp->nic)
		return -ENODEV;

	req = otx2_mbox_alloc_msg_ptp_op(&ptp->nic->mbox);
	if (!req)
		return -ENOMEM;

	req->op = PTP_OP_ADJFINE;
	req->scaled_ppm = scaled_ppm;

	err = otx2_sync_mbox_msg_busy_poll(&ptp->nic->mbox);
	if (err)
		return err;

	return 0;
}

static u64 ptp_cc_read(const struct cyclecounter *cc)
{
	struct otx2_ptp *ptp = container_of(cc, struct otx2_ptp, cycle_counter);
	struct ptp_req *req;
	struct ptp_rsp *rsp;
	int err;

	if (!ptp->nic)
		return 0;

	req = otx2_mbox_alloc_msg_ptp_op(&ptp->nic->mbox);
	if (!req)
		return 0;

	req->op = PTP_OP_GET_CLOCK;

	err = otx2_sync_mbox_msg_busy_poll(&ptp->nic->mbox);
	if (err)
		return 0;

	rsp = (struct ptp_rsp *)otx2_mbox_get_rsp(&ptp->nic->mbox.mbox, 0,
						  &req->hdr);
	if (IS_ERR(rsp))
		return 0;

	return rsp->clk;
}

static int otx2_ptp_adjtime(struct ptp_clock_info *ptp_info, s64 delta)
{
	struct otx2_ptp *ptp = container_of(ptp_info, struct otx2_ptp,
					    ptp_info);

	spin_lock(&ptp->spin_lock);
	timecounter_adjtime(&ptp->time_counter, delta);
	spin_unlock(&ptp->spin_lock);

	return 0;
}

static int otx2_ptp_gettime(struct ptp_clock_info *ptp_info,
			    struct timespec64 *ts)
{
	struct otx2_ptp *ptp = container_of(ptp_info, struct otx2_ptp,
					    ptp_info);
	u64 nsec;

	spin_lock(&ptp->spin_lock);
	nsec = timecounter_read(&ptp->time_counter);
	spin_unlock(&ptp->spin_lock);

	*ts = ns_to_timespec64(nsec);

	return 0;
}

static int otx2_ptp_settime(struct ptp_clock_info *ptp_info,
			    const struct timespec64 *ts)
{
	struct otx2_ptp *ptp = container_of(ptp_info, struct otx2_ptp,
					    ptp_info);
	u64 nsec;

	nsec = timespec64_to_ns(ts);

	spin_lock(&ptp->spin_lock);
	timecounter_init(&ptp->time_counter, &ptp->cycle_counter, nsec);
	spin_unlock(&ptp->spin_lock);

	return 0;
}

static int otx2_ptp_enable(struct ptp_clock_info *ptp_info,
			   struct ptp_clock_request *rq, int on)
{
	return -EOPNOTSUPP;
}

int otx2_ptp_init(struct otx2_nic *pfvf)
{
	struct cyclecounter *cc;
	struct ptp_req *req;
	int err;

	/* check if PTP block is available */
	req = otx2_mbox_alloc_msg_ptp_op(&pfvf->mbox);
	if (!req)
		return -ENOMEM;

	req->op = PTP_OP_GET_CLOCK;

	err = otx2_sync_mbox_msg(&pfvf->mbox);
	if (err)
		return err;

	mutex_lock(&ptp_mutex);

	if (ptp_ptr) {
		kref_get(&ptp_ptr->refcount);
		pfvf->ptp = ptp_ptr;
		mutex_unlock(&ptp_mutex);
		return 0;
	}

	ptp_ptr = kzalloc(sizeof(*ptp_ptr), GFP_KERNEL);
	if (!ptp_ptr) {
		err = -ENOMEM;
		goto error;
	}

	ptp_ptr->nic = pfvf;

	spin_lock_init(&ptp_ptr->spin_lock);

	cc = &ptp_ptr->cycle_counter;
	cc->read = ptp_cc_read;
	cc->mask = CYCLECOUNTER_MASK(64);
	cc->mult = 1;
	cc->shift = 0;

	timecounter_init(&ptp_ptr->time_counter, &ptp_ptr->cycle_counter,
			 ktime_to_ns(ktime_get_real()));

	kref_init(&ptp_ptr->refcount);

	ptp_ptr->ptp_info = (struct ptp_clock_info) {
		.owner          = THIS_MODULE,
		.name           = "OcteonTX2 PTP",
		.max_adj        = 1000000000ull,
		.n_ext_ts       = 0,
		.n_pins         = 0,
		.pps            = 0,
		.adjfine        = otx2_ptp_adjfine,
		.adjtime        = otx2_ptp_adjtime,
		.gettime64      = otx2_ptp_gettime,
		.settime64      = otx2_ptp_settime,
		.enable         = otx2_ptp_enable,
	};

	ptp_ptr->ptp_clock = ptp_clock_register(&ptp_ptr->ptp_info, pfvf->dev);
	if (IS_ERR(ptp_ptr->ptp_clock)) {
		err = PTR_ERR(ptp_ptr->ptp_clock);
		kfree(ptp_ptr);
		goto error;
	}

	pfvf->ptp = ptp_ptr;

error:
	mutex_unlock(&ptp_mutex);
	return err;
}

static void otx2_ptp_release(struct kref *kref)
{
	struct otx2_ptp *ptp = container_of(kref, struct otx2_ptp,
					    refcount);
	ptp_clock_unregister(ptp->ptp_clock);
	kfree(ptp);
}

void otx2_ptp_destroy(struct otx2_nic *pfvf)
{
	if (!pfvf->ptp)
		return;

	mutex_lock(&ptp_mutex);

	if (kref_put(&pfvf->ptp->refcount, otx2_ptp_release)) {
		ptp_ptr = NULL;
	} else if (ptp_ptr->nic == pfvf) {
		dev_err(pfvf->dev, "orphaned ptp instance; incorrect order of nic destruction");
		ptp_ptr->nic = NULL;
	}
	pfvf->ptp = NULL;

	mutex_unlock(&ptp_mutex);
}

int otx2_ptp_clock_index(struct otx2_nic *pfvf)
{
	if (!pfvf->ptp)
		return -ENODEV;

	return ptp_clock_index(pfvf->ptp->ptp_clock);
}

int otx2_ptp_tstamp2time(struct otx2_nic *pfvf, u64 tstamp, u64 *tsns)
{
	if (!pfvf->ptp)
		return -ENODEV;

	*tsns = timecounter_cyc2time(&pfvf->ptp->time_counter, tstamp);

	return 0;
}
