// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#include <linux/bitfield.h>
#include "rvu.h"
#include "rvu_sw.h"
#include "rvu_sw_fl.h"

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
#undef M

static struct workqueue_struct *sw_fl_offl_wq;

struct fl_entry {
	struct list_head list;
	struct rvu *rvu;
	u32 port_id;
	unsigned long cookie;
	struct fl_tuple tuple;
	u64 flags;
	u64 features;
};

static DEFINE_MUTEX(fl_offl_llock);
static LIST_HEAD(fl_offl_lh);
static bool fl_offl_work_running;

static struct workqueue_struct *sw_fl_offl_wq;
static void sw_fl_offl_work_handler(struct work_struct *work);
static DECLARE_DELAYED_WORK(fl_offl_work, sw_fl_offl_work_handler);

struct sw_fl_stats_node {
	struct list_head list;
	unsigned long cookie;
	u16 mcam_idx[2];
	u64 opkts, npkts;
	bool uni_di;
};

static LIST_HEAD(sw_fl_stats_lh);
static DEFINE_MUTEX(sw_fl_stats_lock);

static int
rvu_sw_fl_stats_sync2db_one_entry(unsigned long cookie, u8 disabled,
				  u16 mcam_idx[2], bool uni_di, u64 pkts)
{
	struct sw_fl_stats_node *snode, *tmp;

	mutex_lock(&sw_fl_stats_lock);
	list_for_each_entry_safe(snode, tmp, &sw_fl_stats_lh, list) {
		if (snode->cookie != cookie)
			continue;

		if (disabled) {
			list_del_init(&snode->list);
			mutex_unlock(&sw_fl_stats_lock);
			kfree(snode);
			return 0;
		}

		if (snode->uni_di != uni_di) {
			snode->uni_di = uni_di;
			snode->mcam_idx[1] = mcam_idx[1];
		}

		if (snode->opkts == pkts) {
			mutex_unlock(&sw_fl_stats_lock);
			return 0;
		}

		snode->npkts = pkts;
		mutex_unlock(&sw_fl_stats_lock);
		return 0;
	}
	mutex_unlock(&sw_fl_stats_lock);

	snode = kcalloc(1, sizeof(*snode), GFP_KERNEL);
	if (!snode)
		return -ENOMEM;

	snode->cookie = cookie;
	snode->mcam_idx[0] = mcam_idx[0];
	if (!uni_di)
		snode->mcam_idx[1] = mcam_idx[1];

	snode->npkts = pkts;
	snode->uni_di = uni_di;
	INIT_LIST_HEAD(&snode->list);

	mutex_lock(&sw_fl_stats_lock);
	list_add_tail(&snode->list, &sw_fl_stats_lh);
	mutex_unlock(&sw_fl_stats_lock);

	return 0;
}

int rvu_sw_fl_stats_sync2db(struct rvu *rvu, struct fl_info *fl, int cnt)
{
	struct npc_mcam_get_mul_stats_req *req = NULL;
	struct npc_mcam_get_mul_stats_rsp *rsp = NULL;
	int tot = 0;
	u16 i2idx_map[256];
	int rc = 0;
	u64 pkts;
	int idx;

	for (int i = 0; i < cnt; i++) {
		tot++;
		if (fl[i].uni_di)
			continue;

		tot++;
	}

	req = kcalloc(1, sizeof(*req), GFP_KERNEL);
	if (!req) {
		rc = -ENOMEM;
		goto fail;
	}

	rsp = kcalloc(1, sizeof(*rsp), GFP_KERNEL);
	if (!rsp) {
		rc = -ENOMEM;
		goto fail;
	}

	req->cnt = tot;
	idx = 0;
	for (int i = 0; i < tot; idx++) {
		i2idx_map[i] = idx;
		req->entry[i++] = fl[idx].mcam_idx[0];
		if (fl[idx].uni_di)
			continue;

		i2idx_map[i] = idx;
		req->entry[i++] = fl[idx].mcam_idx[1];
	}

	if (rvu_mbox_handler_npc_mcam_mul_stats(rvu, req, rsp)) {
		dev_err(rvu->dev, "Error to get multiple stats\n");
		rc = -EFAULT;
		goto fail;
	}

	for (int i = 0; i < tot;) {
		idx = i2idx_map[i];
		pkts =  rsp->stat[i++];

		if (!fl[idx].uni_di)
			pkts += rsp->stat[i++];

		rc |= rvu_sw_fl_stats_sync2db_one_entry(fl[idx].cookie, fl[idx].dis,
							fl[idx].mcam_idx,
							fl[idx].uni_di, pkts);
	}

fail:
	kfree(req);
	kfree(rsp);
	return rc;
}

static void sw_fl_offl_dump(struct fl_entry *fl_entry)
{
	struct fl_tuple *tuple = &fl_entry->tuple;

	pr_debug("%pI4 to %pI4\n", &tuple->ip4src, &tuple->ip4dst);
}

static int rvu_sw_fl_offl_rule_push(struct fl_entry *fl_entry)
{
	struct af2swdev_notify_req *req;
	struct rvu *rvu;
	int swdev_pf;

	rvu = fl_entry->rvu;
	swdev_pf = rvu_get_pf(rvu->pdev, rvu->rswitch.pcifunc);

	mutex_lock(&rvu->mbox_lock);
	req = otx2_mbox_alloc_msg_af2swdev_notify(rvu, swdev_pf);
	if (!req) {
		mutex_unlock(&rvu->mbox_lock);
		return -ENOMEM;
	}

	req->tuple = fl_entry->tuple;
	req->flags = fl_entry->flags;
	req->cookie = fl_entry->cookie;
	req->features = fl_entry->features;

	sw_fl_offl_dump(fl_entry);

	otx2_mbox_wait_for_zero(&rvu->afpf_wq_info.mbox_up, swdev_pf);
	otx2_mbox_msg_send_up(&rvu->afpf_wq_info.mbox_up, swdev_pf);

	mutex_unlock(&rvu->mbox_lock);
	return 0;
}

static void sw_fl_offl_work_handler(struct work_struct *work)
{
	struct fl_entry *fl_entry;

	mutex_lock(&fl_offl_llock);
	fl_entry = list_first_entry_or_null(&fl_offl_lh, struct fl_entry, list);
	if (!fl_entry) {
		mutex_unlock(&fl_offl_llock);
		return;
	}

	list_del_init(&fl_entry->list);
	mutex_unlock(&fl_offl_llock);

	rvu_sw_fl_offl_rule_push(fl_entry);
	kfree(fl_entry);

	mutex_lock(&fl_offl_llock);
	if (!list_empty(&fl_offl_lh))
		queue_delayed_work(sw_fl_offl_wq, &fl_offl_work, msecs_to_jiffies(10));
	mutex_unlock(&fl_offl_llock);
}

int rvu_mbox_handler_fl_get_stats(struct rvu *rvu,
				  struct fl_get_stats_req *req,
				  struct fl_get_stats_rsp *rsp)
{
	struct sw_fl_stats_node *snode, *tmp;

	mutex_lock(&sw_fl_stats_lock);
	list_for_each_entry_safe(snode, tmp, &sw_fl_stats_lh, list) {
		if (snode->cookie != req->cookie)
			continue;

		rsp->pkts_diff = snode->npkts - snode->opkts;
		snode->opkts = snode->npkts;
		break;
	}
	mutex_unlock(&sw_fl_stats_lock);
	return 0;
}

int rvu_mbox_handler_fl_notify(struct rvu *rvu,
			       struct fl_notify_req *req,
			       struct msg_rsp *rsp)
{
	struct fl_entry *fl_entry;

	if (!(rvu->rswitch.flags & RVU_SWITCH_FLAG_FW_READY))
		return 0;

	fl_entry = kcalloc(1, sizeof(*fl_entry), GFP_KERNEL);
	if (!fl_entry)
		return -ENOMEM;

	fl_entry->port_id = rvu_sw_port_id(rvu, req->hdr.pcifunc);
	fl_entry->rvu = rvu;
	INIT_LIST_HEAD(&fl_entry->list);
	fl_entry->tuple = req->tuple;
	fl_entry->cookie = req->cookie;
	fl_entry->flags = req->flags;
	fl_entry->features = req->features;

	mutex_lock(&fl_offl_llock);
	list_add_tail(&fl_entry->list, &fl_offl_lh);
	mutex_unlock(&fl_offl_llock);

	if (!fl_offl_work_running) {
		sw_fl_offl_wq = alloc_workqueue("sw_af_fl_wq", 0, 0);
		fl_offl_work_running = true;
	}
	queue_delayed_work(sw_fl_offl_wq, &fl_offl_work, msecs_to_jiffies(10));

	return 0;
}
