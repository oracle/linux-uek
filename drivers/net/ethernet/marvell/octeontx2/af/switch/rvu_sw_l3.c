// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Admin Function driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#include <linux/bitfield.h>
#include "rvu.h"
#include "rvu_sw.h"

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

static struct workqueue_struct *sw_l3_offl_wq;

struct l3_entry {
	struct list_head list;
	struct rvu *rvu;
	u32 port_id;
	int cnt;
	struct fib_entry entry[];
};

static DEFINE_MUTEX(l3_offl_llock);
static LIST_HEAD(l3_offl_lh);
static bool l3_offl_work_running;

static struct workqueue_struct *sw_l3_offl_wq;
static void sw_l3_offl_work_handler(struct work_struct *work);
static DECLARE_DELAYED_WORK(l3_offl_work, sw_l3_offl_work_handler);

static void sw_l3_offl_dump(struct l3_entry *l3_entry)
{
	struct fib_entry *entry = l3_entry->entry;
	int i;

	for (i = 0; i < l3_entry->cnt; i++) {
		pr_debug("%s:%d cmd=%llu port_id=%#x  dst=%#x dst_len=%d gw=%#x\n",
			 __func__, __LINE__,  entry->cmd, entry->port_id, entry->dst,
			 entry->dst_len, entry->gw);
	}
}

static int rvu_sw_l3_offl_rule_push(struct list_head *lh)
{
	struct af2swdev_notify_req *req;
	struct fib_entry *entry, *dst;
	struct l3_entry *l3_entry;
	struct rvu *rvu;
	int swdev_pf;
	int sz, cnt;
	int tot_cnt = 0;

	l3_entry = list_first_entry_or_null(lh, struct l3_entry, list);
	if (!l3_entry)
		return 0;

	rvu = l3_entry->rvu;
	swdev_pf = rvu_get_pf(rvu->pdev, rvu->rswitch.pcifunc);

	mutex_lock(&rvu->mbox_lock);
	req = otx2_mbox_alloc_msg_af2swdev_notify(rvu, swdev_pf);
	if (!req) {
		mutex_unlock(&rvu->mbox_lock);
		return -ENOMEM;
	}

	dst = &req->entry[0];
	while ((l3_entry =
		list_first_entry_or_null(lh,
					 struct l3_entry, list)) != NULL) {
		entry = l3_entry->entry;
		cnt = l3_entry->cnt;
		sz = sizeof(*entry) * cnt;

		memcpy(dst, entry, sz);
		tot_cnt += cnt;
		dst += cnt;

		sw_l3_offl_dump(l3_entry);

		list_del_init(&l3_entry->list);
		kfree(l3_entry);
	}
	req->flags = FIB_CMD;
	req->cnt = tot_cnt;

	otx2_mbox_wait_for_zero(&rvu->afpf_wq_info.mbox_up, swdev_pf);
	otx2_mbox_msg_send_up(&rvu->afpf_wq_info.mbox_up, swdev_pf);

	mutex_unlock(&rvu->mbox_lock);
	return 0;
}

static atomic64_t req_cnt;
static atomic64_t ack_cnt;
static atomic64_t req_processed;
static LIST_HEAD(l3_local_lh);

static void sw_l3_offl_work_handler(struct work_struct *work)
{
	struct l3_entry *l3_entry;
	struct list_head l3lh;
	u64 req, ack, proc;

	INIT_LIST_HEAD(&l3lh);

	mutex_lock(&l3_offl_llock);
	while (1) {
		l3_entry = list_first_entry_or_null(&l3_offl_lh, struct l3_entry, list);

		if (!l3_entry)
			break;

		atomic64_inc(&req_cnt);
		list_del_init(&l3_entry->list);
		list_add_tail(&l3_entry->list, &l3_local_lh);
	}
	mutex_unlock(&l3_offl_llock);

	req = atomic64_read(&req_cnt);
	ack = atomic64_read(&ack_cnt);

	if (req > ack) {
		atomic64_set(&ack_cnt, req);
		queue_delayed_work(sw_l3_offl_wq, &l3_offl_work,
				   msecs_to_jiffies(100));
		return;
	}

	proc = atomic64_read(&req_processed);
	if (req == proc) {
		queue_delayed_work(sw_l3_offl_wq, &l3_offl_work,
				   msecs_to_jiffies(1000));
		return;
	}

	atomic64_set(&req_processed, req);

	mutex_lock(&l3_offl_llock);
	list_splice_init(&l3_local_lh, &l3lh);
	mutex_unlock(&l3_offl_llock);

	rvu_sw_l3_offl_rule_push(&l3lh);

	queue_delayed_work(sw_l3_offl_wq, &l3_offl_work, msecs_to_jiffies(100));
}

int rvu_mbox_handler_fib_notify(struct rvu *rvu,
				struct fib_notify_req *req,
				struct msg_rsp *rsp)
{
	struct l3_entry *l3_entry;
	int sz;

	if (!(rvu->rswitch.flags & RVU_SWITCH_FLAG_FW_READY))
		return 0;

	sz = req->cnt * sizeof(struct fib_entry);

	l3_entry = kcalloc(1, sizeof(*l3_entry) + sz, GFP_KERNEL);
	if (!l3_entry)
		return -ENOMEM;

	l3_entry->port_id = rvu_sw_port_id(rvu, req->hdr.pcifunc);
	l3_entry->rvu = rvu;
	l3_entry->cnt = req->cnt;
	INIT_LIST_HEAD(&l3_entry->list);
	memcpy(l3_entry->entry, req->entry, sz);

	mutex_lock(&l3_offl_llock);
	list_add_tail(&l3_entry->list, &l3_offl_lh);
	mutex_unlock(&l3_offl_llock);

	if (!l3_offl_work_running) {
		sw_l3_offl_wq = alloc_workqueue("sw_af_fib_wq", 0, 0);
		l3_offl_work_running = true;
		queue_delayed_work(sw_l3_offl_wq, &l3_offl_work,
				   msecs_to_jiffies(1000));
	}

	return 0;
}
