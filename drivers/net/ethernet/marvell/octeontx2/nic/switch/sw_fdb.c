// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU switch driver
 *
 * Copyright (C) 2025 Marvell.
 *
 */
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <net/switchdev.h>
#include <net/netevent.h>
#include <net/arp.h>

#include "../otx2_reg.h"
#include "../otx2_common.h"
#include "../otx2_struct.h"
#include "../cn10k.h"

#if !IS_ENABLED(CONFIG_OCTEONTX_SWITCH)

int otx2_mbox_up_handler_af2pf_fdb_refresh(struct otx2_nic *pf,
					   struct af2pf_fdb_refresh_req *req,
					   struct msg_rsp *rsp)
{
	return 0;
}
EXPORT_SYMBOL(otx2_mbox_up_handler_af2pf_fdb_refresh);

#else

static DEFINE_SPINLOCK(sw_fdb_llock);
static LIST_HEAD(sw_fdb_lh);

struct sw_fdb_list_entry {
	struct list_head list;
	u64 flags;
	struct otx2_nic *pf;
	u8  mac[ETH_ALEN];
	bool add_fdb;
};

static struct workqueue_struct *sw_fdb_wq;
static struct work_struct sw_fdb_work;

static int sw_fdb_add_or_del(struct otx2_nic *pf,
			     const unsigned char *addr,
			     bool add_fdb)
{
	struct fdb_notify_req *req;
	int rc;

	mutex_lock(&pf->mbox.lock);
	req = otx2_mbox_alloc_msg_fdb_notify(&pf->mbox);
	if (!req) {
		rc = -ENOMEM;
		goto out;
	}

	ether_addr_copy(req->mac, addr);
	req->flags = add_fdb ? FDB_ADD : FDB_DEL;

	rc = otx2_sync_mbox_msg(&pf->mbox);
out:
	mutex_unlock(&pf->mbox.lock);
	return rc;
}

void sw_fdb_wq_handler(struct work_struct *work)
{
	struct sw_fdb_list_entry *entry;
	LIST_HEAD(tlist);

	spin_lock(&sw_fdb_llock);
	list_splice_init(&sw_fdb_lh, &tlist);
	spin_unlock(&sw_fdb_llock);

	while ((entry =
		list_first_entry_or_null(&tlist,
					 struct sw_fdb_list_entry,
					 list)) != NULL) {
		list_del_init(&entry->list);
		sw_fdb_add_or_del(entry->pf, entry->mac, entry->add_fdb);
		kfree(entry);
	}

	spin_lock(&sw_fdb_llock);
	if (!list_empty(&sw_fdb_lh))
		queue_work(sw_fdb_wq, &sw_fdb_work);
	spin_unlock(&sw_fdb_llock);

}

int sw_fdb_add_to_list(struct net_device *dev, u8 *mac, bool add_fdb)
{
	struct otx2_nic *pf = netdev_priv(dev);
	struct sw_fdb_list_entry *entry;

	entry = kcalloc(1, sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return -ENOMEM;

	ether_addr_copy(entry->mac, mac);
	entry->add_fdb = add_fdb;
	entry->pf = pf;

	spin_lock(&sw_fdb_llock);
	list_add_tail(&entry->list, &sw_fdb_lh);
	queue_work(sw_fdb_wq, &sw_fdb_work);
	spin_unlock(&sw_fdb_llock);

	return 0;
}

int sw_fdb_init(void)
{
	INIT_WORK(&sw_fdb_work, sw_fdb_wq_handler);
	sw_fdb_wq = alloc_workqueue("sw_fdb_wq", 0, 0);
	if (!sw_fdb_wq)
		return -ENOMEM;

	return 0;
}

void sw_fdb_deinit(void)
{
	flush_workqueue(sw_fdb_wq);
	destroy_workqueue(sw_fdb_wq);
}

int otx2_mbox_up_handler_af2pf_fdb_refresh(struct otx2_nic *pf,
					   struct af2pf_fdb_refresh_req *req,
					   struct msg_rsp *rsp)
{
	struct switchdev_notifier_fdb_info item = {0};

	item.addr = req->mac;
	item.info.dev = pf->netdev;
	call_switchdev_notifiers(SWITCHDEV_FDB_ADD_TO_BRIDGE,
				 item.info.dev, &item.info, NULL);

	return 0;
}
EXPORT_SYMBOL(otx2_mbox_up_handler_af2pf_fdb_refresh);

#endif
