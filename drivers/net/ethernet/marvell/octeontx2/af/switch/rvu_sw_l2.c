// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#include <linux/bitfield.h>
#include "rvu.h"
#include "rvu_sw.h"
#include "rvu_sw_l2.h"

#define M(_name, _id, _fn_name, _req_type, _rsp_type)			\
static struct _req_type __maybe_unused					\
*otx2_mbox_alloc_msg_ ## _fn_name(struct rvu *rvu, int devid)		\
{									\
	struct _req_type *req;						\
									\
	req = (struct _req_type *)otx2_mbox_alloc_msg_rsp(		\
		&rvu->afpf_wq_info.mbox_up, devid, sizeof(struct _req_type), \
		sizeof(struct _rsp_type));				\
	if (!req)							\
		return NULL;						\
	req->hdr.sig = OTX2_MBOX_REQ_SIG;				\
	req->hdr.id = _id;						\
	return req;							\
}
MBOX_UP_AF2SWDEV_MESSAGES
MBOX_UP_AF2PF_FDB_REFRESH_MESSAGES
#undef M

struct l2_entry {
	struct list_head list;
	u64 flags;
	u32 port_id;
	u8  mac[ETH_ALEN];
};

static DEFINE_MUTEX(l2_offl_list_lock);
static LIST_HEAD(l2_offl_lh);

static DEFINE_MUTEX(fdb_refresh_list_lock);
static LIST_HEAD(fdb_refresh_lh);

struct rvu_sw_l2_work {
	struct rvu *rvu;
	struct work_struct work;
};

static struct rvu_sw_l2_work l2_offl_work;
struct workqueue_struct *rvu_sw_l2_offl_wq;

static struct rvu_sw_l2_work fdb_refresh_work;
struct workqueue_struct *fdb_refresh_wq;

static void rvu_sw_l2_offl_cancel_add_if_del_reqs_exist(u8 *mac)
{
	struct l2_entry *entry, *tmp;

	mutex_lock(&l2_offl_list_lock);
	list_for_each_entry_safe(entry, tmp, &l2_offl_lh, list) {
		if (!ether_addr_equal(mac, entry->mac))
			continue;

		if (!(entry->flags & FDB_DEL))
			continue;

		list_del_init(&entry->list);
		kfree(entry);
		break;
	}
	mutex_unlock(&l2_offl_list_lock);
}

static int rvu_sw_l2_offl_rule_push(struct rvu *rvu, struct l2_entry *l2_entry)
{
	struct af2swdev_notify_req *req;
	int swdev_pf;

	swdev_pf = rvu_get_pf(rvu->pdev, rvu->rswitch.pcifunc);

	mutex_lock(&rvu->mbox_lock);
	req = otx2_mbox_alloc_msg_af2swdev_notify(rvu, swdev_pf);
	if (!req) {
		mutex_unlock(&rvu->mbox_lock);
		return -ENOMEM;
	}

	ether_addr_copy(req->mac, l2_entry->mac);
	req->flags = l2_entry->flags;
	req->port_id = l2_entry->port_id;

	otx2_mbox_wait_for_zero(&rvu->afpf_wq_info.mbox_up, swdev_pf);
	otx2_mbox_msg_send_up(&rvu->afpf_wq_info.mbox_up, swdev_pf);

	mutex_unlock(&rvu->mbox_lock);
	return 0;
}

static int rvu_sw_l2_fdb_refresh(struct rvu *rvu, u16 pcifunc, u8 *mac)
{
	struct af2pf_fdb_refresh_req *req;
	int pf, vidx;

	pf = rvu_get_pf(rvu->pdev, pcifunc);

	mutex_lock(&rvu->mbox_lock);

	if (pf) {
		req = otx2_mbox_alloc_msg_af2pf_fdb_refresh(rvu, pf);
		if (!req) {
			mutex_unlock(&rvu->mbox_lock);
			return -ENOMEM;
		}

		req->hdr.pcifunc = pcifunc;
		ether_addr_copy(req->mac, mac);
		req->pcifunc = pcifunc;

		otx2_mbox_wait_for_zero(&rvu->afpf_wq_info.mbox_up, pf);
		otx2_mbox_msg_send_up(&rvu->afpf_wq_info.mbox_up, pf);
	} else {
		vidx = pcifunc - 1;

		req = (struct af2pf_fdb_refresh_req *)
			otx2_mbox_alloc_msg_rsp(&rvu->afvf_wq_info.mbox_up, vidx,
						sizeof(*req), sizeof(struct msg_rsp));
		if (!req) {
			mutex_unlock(&rvu->mbox_lock);
			return -ENOMEM;
		}
		req->hdr.sig = OTX2_MBOX_REQ_SIG;
		req->hdr.id = MBOX_MSG_AF2PF_FDB_REFRESH;

		req->hdr.pcifunc = pcifunc;
		ether_addr_copy(req->mac, mac);
		req->pcifunc = pcifunc;

		otx2_mbox_wait_for_zero(&rvu->afvf_wq_info.mbox_up, vidx);
		otx2_mbox_msg_send_up(&rvu->afvf_wq_info.mbox_up, vidx);
	}

	mutex_unlock(&rvu->mbox_lock);

	return 0;
}

static void rvu_sw_l2_fdb_refresh_wq_handler(struct work_struct *work)
{
	struct rvu_sw_l2_work *fdb_work;
	struct l2_entry *l2_entry;

	fdb_work = container_of(work, struct rvu_sw_l2_work, work);

	while (1) {
		mutex_lock(&fdb_refresh_list_lock);
		l2_entry = list_first_entry_or_null(&fdb_refresh_lh,
						    struct l2_entry, list);
		if (!l2_entry) {
			mutex_unlock(&fdb_refresh_list_lock);
			return;
		}

		list_del_init(&l2_entry->list);
		mutex_unlock(&fdb_refresh_list_lock);

		rvu_sw_l2_fdb_refresh(fdb_work->rvu, l2_entry->port_id, l2_entry->mac);
		kfree(l2_entry);
	}
}

static void rvu_sw_l2_offl_rule_wq_handler(struct work_struct *work)
{
	struct rvu_sw_l2_work *offl_work;
	struct l2_entry *l2_entry;
	int budget = 16;
	bool add_fdb;

	offl_work = container_of(work, struct rvu_sw_l2_work, work);

	while (budget--) {
		mutex_lock(&l2_offl_list_lock);
		l2_entry = list_first_entry_or_null(&l2_offl_lh, struct l2_entry, list);
		if (!l2_entry) {
			mutex_unlock(&l2_offl_list_lock);
			return;
		}

		list_del_init(&l2_entry->list);
		mutex_unlock(&l2_offl_list_lock);

		add_fdb = !!(l2_entry->flags & FDB_ADD);

		if (add_fdb)
			rvu_sw_l2_offl_cancel_add_if_del_reqs_exist(l2_entry->mac);

		rvu_sw_l2_offl_rule_push(offl_work->rvu, l2_entry);
		kfree(l2_entry);
	}

	if (!list_empty(&l2_offl_lh))
		queue_work(rvu_sw_l2_offl_wq, &l2_offl_work.work);
}

int rvu_sw_l2_init_offl_wq(struct rvu *rvu, u16 pcifunc, bool fw_up)
{
	struct rvu_switch *rswitch;

	rswitch = &rvu->rswitch;

	if (fw_up) {
		rswitch->flags |= RVU_SWITCH_FLAG_FW_READY;
		rswitch->pcifunc = pcifunc;

		l2_offl_work.rvu = rvu;
		INIT_WORK(&l2_offl_work.work, rvu_sw_l2_offl_rule_wq_handler);
		rvu_sw_l2_offl_wq = alloc_workqueue("swdev_rvu_sw_l2_offl_wq", 0, 0);
		if (!rvu_sw_l2_offl_wq) {
			dev_err(rvu->dev, "L2 offl workqueue allocation failed\n");
			return -ENOMEM;
		}

		fdb_refresh_work.rvu = rvu;
		INIT_WORK(&fdb_refresh_work.work, rvu_sw_l2_fdb_refresh_wq_handler);
		fdb_refresh_wq = alloc_workqueue("swdev_fdb_refresg_wq", 0, 0);
		if (!rvu_sw_l2_offl_wq) {
			dev_err(rvu->dev, "L2 offl workqueue allocation failed\n");
			return -ENOMEM;
		}

		return 0;
	}

	rswitch->flags &= ~RVU_SWITCH_FLAG_FW_READY;
	rswitch->pcifunc = -1;
	flush_work(&l2_offl_work.work);
	return 0;
}

int rvu_sw_l2_fdb_list_entry_add(struct rvu *rvu, u16 pcifunc, u8 *mac)
{
	struct l2_entry *l2_entry;

	l2_entry = kcalloc(1, sizeof(*l2_entry), GFP_KERNEL);
	if (!l2_entry)
		return -ENOMEM;

	l2_entry->port_id = pcifunc;
	ether_addr_copy(l2_entry->mac, mac);

	mutex_lock(&fdb_refresh_list_lock);
	list_add_tail(&l2_entry->list, &fdb_refresh_lh);
	mutex_unlock(&fdb_refresh_list_lock);

	queue_work(fdb_refresh_wq, &fdb_refresh_work.work);
	return 0;
}

int rvu_mbox_handler_fdb_notify(struct rvu *rvu,
				struct fdb_notify_req *req,
				struct msg_rsp *rsp)
{
	struct l2_entry *l2_entry;

	if (!(rvu->rswitch.flags & RVU_SWITCH_FLAG_FW_READY))
		return 0;

	l2_entry = kcalloc(1, sizeof(*l2_entry), GFP_KERNEL);
	if (!l2_entry)
		return -ENOMEM;

	l2_entry->port_id = rvu_sw_port_id(rvu, req->hdr.pcifunc);
	ether_addr_copy(l2_entry->mac, req->mac);
	l2_entry->flags = req->flags;

	mutex_lock(&l2_offl_list_lock);
	list_add_tail(&l2_entry->list, &l2_offl_lh);
	mutex_unlock(&l2_offl_list_lock);

	queue_work(rvu_sw_l2_offl_wq, &l2_offl_work.work);

	return 0;
}
