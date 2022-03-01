// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Ethernet driver
 *
 * Copyright (C) 2020 Marvell.
 *
 */

#include <linux/module.h>
#include "otx2_common.h"
#include "otx2_ptp.h"

#define PCI_SUBSYS_DEVID_CN10K_A_PTP		0xB900
#define PCI_SUBSYS_DEVID_CNF10K_A_PTP		0xBA00

static bool has_cn10k_ptp_pps_errata(struct otx2_ptp *ptp)
{
	struct pci_dev *pdev = ptp->nic->pdev;

	if (pdev->subsystem_device == PCI_SUBSYS_DEVID_CN10K_A_PTP ||
	    pdev->subsystem_device == PCI_SUBSYS_DEVID_CNF10K_A_PTP)
		return true;
	return false;
}

static int otx2_ptp_adjfine(struct ptp_clock_info *ptp_info, long scaled_ppm)
{
	struct otx2_ptp *ptp = container_of(ptp_info, struct otx2_ptp,
					    ptp_info);
	struct ptp_req *req;

	if (!ptp->nic)
		return -ENODEV;

	req = otx2_mbox_alloc_msg_ptp_op(&ptp->nic->mbox);
	if (!req)
		return -ENOMEM;

	req->op = PTP_OP_ADJFINE;
	req->scaled_ppm = scaled_ppm;

	return otx2_sync_mbox_msg(&ptp->nic->mbox);
}

static int ptp_set_thresh(struct otx2_ptp *ptp, u64 thresh)
{
	struct ptp_req *req;

	if (!ptp->nic)
		return -ENODEV;

	req = otx2_mbox_alloc_msg_ptp_op(&ptp->nic->mbox);
	if (!req)
		return -ENOMEM;

	req->op = PTP_OP_SET_THRESH;
	req->thresh = thresh;

	return otx2_sync_mbox_msg(&ptp->nic->mbox);
}

static u64 ptp_tstmp_read(struct otx2_ptp *ptp)
{
	struct ptp_req *req;
	struct ptp_rsp *rsp;
	int err;

	if (!ptp->nic)
		return 0;

	req = otx2_mbox_alloc_msg_ptp_op(&ptp->nic->mbox);
	if (!req)
		return 0;

	req->op = PTP_OP_GET_TSTMP;

	err = otx2_sync_mbox_msg(&ptp->nic->mbox);
	if (err)
		return 0;

	rsp = (struct ptp_rsp *)otx2_mbox_get_rsp(&ptp->nic->mbox.mbox, 0,
						  &req->hdr);
	if (IS_ERR(rsp))
		return 0;

	return rsp->clk;
}

static void otx2_get_ptpclock(struct otx2_nic *pfvf, u64 *tstamp)
{
	struct ptp_req *req;
	struct ptp_rsp *rsp;

	mutex_lock(&pfvf->mbox.lock);

	req = otx2_mbox_alloc_msg_ptp_op(&pfvf->mbox);
	if (!req) {
		mutex_unlock(&pfvf->mbox.lock);
		return;
	}

	req->op = PTP_OP_GET_CLOCK;

	if (!otx2_sync_mbox_msg(&pfvf->mbox)) {
		rsp = (struct ptp_rsp *)otx2_mbox_get_rsp(&pfvf->mbox.mbox, 0,
							  &req->hdr);
		*tstamp = rsp->clk;
	}

	mutex_unlock(&pfvf->mbox.lock);
}

static int otx2_ptp_adjtime(struct ptp_clock_info *ptp_info, s64 delta)
{
	struct otx2_ptp *ptp = container_of(ptp_info, struct otx2_ptp,
					    ptp_info);
	struct otx2_nic *pfvf = ptp->nic;
	struct ptp_req *req;
	int err;

	mutex_lock(&pfvf->mbox.lock);
	req = otx2_mbox_alloc_msg_ptp_op(&pfvf->mbox);
	if (!req) {
		mutex_unlock(&pfvf->mbox.lock);
		return -ENOMEM;
	}
	req->op = PTP_OP_ADJ_CLOCK;
	req->delta = delta;
	err = otx2_sync_mbox_msg(&pfvf->mbox);
	mutex_unlock(&pfvf->mbox.lock);
	return err;

}

static int otx2_ptp_gettime(struct ptp_clock_info *ptp_info,
			    struct timespec64 *ts)
{
	struct otx2_ptp *ptp = container_of(ptp_info, struct otx2_ptp,
					    ptp_info);
	struct otx2_nic *pfvf = ptp->nic;
	u64 tstamp;

	otx2_get_ptpclock(pfvf, &tstamp);
	*ts = ns_to_timespec64(tstamp);

	return 0;
}

static int otx2_ptp_settime(struct ptp_clock_info *ptp_info,
			    const struct timespec64 *ts)
{
	struct otx2_ptp *ptp = container_of(ptp_info, struct otx2_ptp,
					    ptp_info);
	struct otx2_nic *pfvf = ptp->nic;
	struct ptp_req *req;
	int err;

	mutex_lock(&pfvf->mbox.lock);
	req = otx2_mbox_alloc_msg_ptp_op(&pfvf->mbox);
	if (!req) {
		mutex_unlock(&pfvf->mbox.lock);
		return -ENOMEM;
	}

	req->op = PTP_OP_SET_CLOCK;
	req->nsec = timespec64_to_ns(ts);
	err = otx2_sync_mbox_msg(&pfvf->mbox);
	mutex_unlock(&pfvf->mbox.lock);
	return err;
}

static int otx2_ptp_verify_pin(struct ptp_clock_info *ptp, unsigned int pin,
			       enum ptp_pin_function func, unsigned int chan)
{
	switch (func) {
	case PTP_PF_NONE:
	case PTP_PF_EXTTS:
		break;
	case PTP_PF_PEROUT:
	case PTP_PF_PHYSYNC:
		return -1;
	}
	return 0;
}

static void otx2_ptp_extts_check(struct work_struct *work)
{
	struct otx2_ptp *ptp = container_of(work, struct otx2_ptp,
					    extts_work.work);
	struct ptp_clock_event event;
	u64 tstmp, new_thresh;

	mutex_lock(&ptp->nic->mbox.lock);
	tstmp = ptp_tstmp_read(ptp);
	mutex_unlock(&ptp->nic->mbox.lock);

	if (tstmp != ptp->last_extts) {
		event.type = PTP_CLOCK_EXTTS;
		event.index = 0;
		event.timestamp = ptp->convert_tx_ptp_tstmp(tstmp);
		ptp_clock_event(ptp->ptp_clock, &event);
		ptp->last_extts = tstmp;

		if (has_cn10k_ptp_pps_errata(ptp))
			new_thresh = tstmp;
		else
			new_thresh = tstmp % PPS_HALF_CYCLE_NS;

		if (ptp->thresh != new_thresh) {
			mutex_lock(&ptp->nic->mbox.lock);
			ptp_set_thresh(ptp, new_thresh);
			mutex_unlock(&ptp->nic->mbox.lock);
			ptp->thresh = new_thresh;
		}
	}
	schedule_delayed_work(&ptp->extts_work, msecs_to_jiffies(200));
}

static void otx2_sync_tstamp(struct work_struct *work)
{
	struct otx2_ptp *ptp = container_of(work, struct otx2_ptp,
					    synctstamp_work.work);

	otx2_get_ptpclock(ptp->nic, &ptp->tstamp);
	schedule_delayed_work(&ptp->synctstamp_work, msecs_to_jiffies(500));
}

static int otx2_ptp_enable(struct ptp_clock_info *ptp_info,
			   struct ptp_clock_request *rq, int on)
{
	struct otx2_ptp *ptp = container_of(ptp_info, struct otx2_ptp,
					    ptp_info);
	int pin = -1;

	if (!ptp->nic)
		return -ENODEV;

	switch (rq->type) {
	case PTP_CLK_REQ_EXTTS:
		pin = ptp_find_pin(ptp->ptp_clock, PTP_PF_EXTTS,
				   rq->extts.index);
		if (pin < 0)
			return -EBUSY;
		if (on)
			schedule_delayed_work(&ptp->extts_work, msecs_to_jiffies(200));
		else
			cancel_delayed_work_sync(&ptp->extts_work);
		return 0;
	default:
		break;
	}
	return -EOPNOTSUPP;
}

int otx2_ptp_init(struct otx2_nic *pfvf)
{
	struct otx2_ptp *ptp_ptr;
	struct ptp_req *req;
	int err;

	if (is_otx2_lbkvf(pfvf->pdev)) {
		pfvf->ptp = NULL;
		return 0;
	}

	mutex_lock(&pfvf->mbox.lock);
	/* check if PTP block is available */
	req = otx2_mbox_alloc_msg_ptp_op(&pfvf->mbox);
	if (!req) {
		mutex_unlock(&pfvf->mbox.lock);
		return -ENOMEM;
	}

	req->op = PTP_OP_GET_CLOCK;

	err = otx2_sync_mbox_msg(&pfvf->mbox);
	if (err) {
		mutex_unlock(&pfvf->mbox.lock);
		return err;
	}
	mutex_unlock(&pfvf->mbox.lock);

	ptp_ptr = kzalloc(sizeof(*ptp_ptr), GFP_KERNEL);
	if (!ptp_ptr) {
		err = -ENOMEM;
		goto error;
	}

	ptp_ptr->nic = pfvf;

	snprintf(ptp_ptr->extts_config.name, sizeof(ptp_ptr->extts_config.name), "TSTAMP");
	ptp_ptr->extts_config.index = 0;
	ptp_ptr->extts_config.func = PTP_PF_NONE;

	ptp_ptr->ptp_info = (struct ptp_clock_info) {
		.owner          = THIS_MODULE,
		.name           = "OcteonTX2 PTP",
		.max_adj        = 1000000000ull,
		.n_ext_ts       = 1,
		.n_pins         = 1,
		.pps            = 0,
		.pin_config     = &ptp_ptr->extts_config,
		.adjfine        = otx2_ptp_adjfine,
		.adjtime        = otx2_ptp_adjtime,
		.gettime64      = otx2_ptp_gettime,
		.settime64      = otx2_ptp_settime,
		.enable         = otx2_ptp_enable,
		.verify         = otx2_ptp_verify_pin,
	};

	INIT_DELAYED_WORK(&ptp_ptr->extts_work, otx2_ptp_extts_check);

	ptp_ptr->ptp_clock = ptp_clock_register(&ptp_ptr->ptp_info, pfvf->dev);
	if (IS_ERR_OR_NULL(ptp_ptr->ptp_clock)) {
		err = ptp_ptr->ptp_clock ?
		      PTR_ERR(ptp_ptr->ptp_clock) : -ENODEV;
		kfree(ptp_ptr);
		goto error;
	}

	if (is_dev_otx2(pfvf->pdev)) {
		ptp_ptr->convert_rx_ptp_tstmp = &otx2_ptp_convert_rx_timestamp;
		ptp_ptr->convert_tx_ptp_tstmp = &otx2_ptp_convert_tx_timestamp;
	} else {
		ptp_ptr->convert_rx_ptp_tstmp = &cn10k_ptp_convert_timestamp;
		ptp_ptr->convert_tx_ptp_tstmp = &cn10k_ptp_convert_timestamp;
	}

	INIT_DELAYED_WORK(&ptp_ptr->synctstamp_work, otx2_sync_tstamp);

	pfvf->ptp = ptp_ptr;

error:
	return err;
}
EXPORT_SYMBOL_GPL(otx2_ptp_init);

void otx2_ptp_destroy(struct otx2_nic *pfvf)
{
	struct otx2_ptp *ptp = pfvf->ptp;

	if (!ptp)
		return;

	cancel_delayed_work(&pfvf->ptp->synctstamp_work);

	ptp_clock_unregister(ptp->ptp_clock);
	kfree(ptp);
	pfvf->ptp = NULL;
}
EXPORT_SYMBOL_GPL(otx2_ptp_destroy);

int otx2_ptp_clock_index(struct otx2_nic *pfvf)
{
	if (!pfvf->ptp)
		return -ENODEV;

	return ptp_clock_index(pfvf->ptp->ptp_clock);
}
EXPORT_SYMBOL_GPL(otx2_ptp_clock_index);

MODULE_AUTHOR("Sunil Goutham <sgoutham@marvell.com>");
MODULE_DESCRIPTION("Marvell RVU NIC PTP Driver");
MODULE_LICENSE("GPL v2");
