/*
 * Copyright (c) 2009 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "vnic.h"

struct workqueue_struct *mcast_wq;
struct ib_sa_client vnic_sa_client;

//static void vnic_mcast_detach_task(struct work_struct *work);
static void vnic_mcast_attach_task(struct work_struct *work);
static void vnic_port_mcast_leave_task(struct work_struct *work);
static void vnic_port_mcast_join_task(struct work_struct *work);

static void vnic_port_mcast_release(struct vnic_port_mcast *mcaste);
static struct vnic_port_mcast *vnic_port_mcast_update(struct vnic_mcast
						      *_mcaste);

/*
 * A helper function to prevent code duplication. Fills vnic_mcast struct with
 * common values.
 *
 * in: mcaste - mcaste to fill
 * in: gw_id - to be used in creation MGID address
 * in: mac - to be used in creation MGID address
 * in: create - value of create field in mcaste
 */
void __vnic_mcaste_fill(struct vnic_login *login, struct vnic_mcast *mcaste,
			u16 gw_id, const u8 *mac, u8 rss_hash, int create)
{
	union vhub_mgid mgid;

	memcpy(mcaste->mac, mac, ETH_ALEN);
	vhub_mgid_create(login->mgid_prefix, mcaste->mac,
			 login->n_mac_mcgid,
			 CREATE_VHUB_ID(login->vid, gw_id),
			 VHUB_MGID_DATA, rss_hash, &mgid);
	memcpy(&mcaste->gid, mgid.ib_gid.raw, GID_LEN);
	memcpy(&mcaste->port_gid, &mcaste->gid, GID_LEN);
	mcaste->backoff = msecs_to_jiffies(VNIC_MCAST_BACKOFF_MSEC);
	mcaste->backoff_factor = 1;
	mcaste->retry = VNIC_MCAST_MAX_RETRY;
	mcaste->blocking = 0;
	mcaste->qkey = login->qkey;
	mcaste->pkey = login->pkey;
	mcaste->create = create;
	mcaste->qp = login->qp_res[0].qp; /* mcast/bcast is only on first QP */
	mcaste->join_state = 1;
}

/*
 * A helper function to prevent code duplication. Receives a multicast mac
 * and a gw_id and attaches it (join + attach). The function also receives
 * a default_mcaste (used for the MGID over default MLID hack and a user list.
 * Returns 0 on success and non 0 on failure.
 *
 * in: mmac - to be used in creation MGID address
 * in: default_mcaste - mcaste entry of the default MGID. Can be NULL
 * in: user_list - A user list to hang the new mcaste on. Can be NULL
 * in: gw_id - to be used in creation MGID address
 */
int _vnic_mcast_attach_mgid(struct vnic_login *login,
			   char *mmac,
			   struct vnic_mcast *default_mcaste,
			   void *private_data,
			   u16 gw_id)
{
	struct vnic_mcast *mcaste;
	int rc = 0;
	int rss_hash;

	mcaste = vnic_mcast_alloc(login->port, NULL, NULL);
	if (IS_ERR(mcaste)) {
		vnic_warn(login->name, "vnic_mcast_alloc for "MAC_6_PRINT_FMT" failed\n",
			  MAC_6_PRINT_ARG(mmac));
		vnic_dbg_mark();
		return -ENOMEM;
	}
	memcpy(mcaste->mac, mmac, ETH_ALEN);

	/* if mcast mac has mcast IP in it:*/
	rss_hash = 0;
	if ((mcaste->mac[0] & 0xf0) == 0xe0 &&
	     mcaste->mac[4] == 0x00 &&
	     mcaste->mac[5] == 0x00) {
		/* calculate mcas rss_hash on IP octets */
		rss_hash = mcaste->mac[0] ^ mcaste->mac[1] ^
			   mcaste->mac[2] ^ mcaste->mac[3];
		/* and build the corresponding mcast MAC using the IEEE
		 * multicast OUI 01:00:5e
		 */
		mcaste->mac[5] = mcaste->mac[3];
		mcaste->mac[4] = mcaste->mac[2];
		mcaste->mac[3] = mcaste->mac[1] & 0x7f;
		mcaste->mac[2] = 0x5e;
		mcaste->mac[1] = 0x00;
		mcaste->mac[0] = 0x01;
	}

	__vnic_mcaste_fill(login, mcaste, gw_id, mcaste->mac, rss_hash, 0);
	mcaste->priv_data = private_data;

	if (default_mcaste)
		memcpy(&mcaste->port_gid, &default_mcaste->gid, GID_LEN);

	rc = vnic_mcast_add(&login->mcast_tree, mcaste); /* add holds mcast_rb_lock */
	if (!rc) {
		rc = vnic_mcast_attach(&login->mcast_tree, mcaste);
		ASSERT(!rc);
	} else if (rc == -EEXIST){
		/* MGID may be already in the tree when n_mac_mcgid > 0 (ok)*/
		vnic_dbg_mcast(login->name, "vnic_mcast_add for "
			       MAC_6_PRINT_FMT" already exist, rc %d\n",
			       MAC_6_PRINT_ARG(mcaste->mac), rc);
		vnic_mcast_dealloc(mcaste);
		rc = 0;
	} else {
		vnic_warn(login->name, "vnic_mcast_add for "
			  MAC_6_PRINT_FMT" failed, rc %d\n",
			  MAC_6_PRINT_ARG(mcaste->mac), rc);
		vnic_mcast_dealloc(mcaste);
	}
	return rc;
}

struct vnic_mcast *vnic_mcast_alloc(struct vnic_port *port,
				    unsigned long *req_attach,
				    unsigned long *cur_attached)
{
	struct vnic_mcast *mcaste;

	mcaste = kzalloc(sizeof *mcaste, GFP_ATOMIC);
	if (!mcaste)
		return ERR_PTR(-ENOMEM);
	/* set mcaste fields */
	init_completion(&mcaste->attach_complete);
	INIT_DELAYED_WORK(&mcaste->attach_task, vnic_mcast_attach_task);
	spin_lock_init(&mcaste->lock);
	mcaste->port = port;
	mcaste->req_attach = req_attach;
	mcaste->cur_attached = cur_attached;

	return mcaste;
}

void vnic_mcast_dealloc(struct vnic_mcast *mcaste)
{
	struct vnic_port *port;

	ASSERT(mcaste);
	port = mcaste->port;
	vnic_dbg_mcast_vv(port->name, "dealloc vnic_mcast: MAC "MAC_6_PRINT_FMT
			 " GID "VNIC_GID_FMT"\n",
			 MAC_6_PRINT_ARG(mcaste->mac),
			 VNIC_GID_ARG(mcaste->gid));
	kfree(mcaste);
}

/*
 * This function grabs the mcast_tree->mcast_rb_lock
*/
int vnic_mcast_add(struct mcast_root *mcast_tree, struct vnic_mcast *mcaste)
{
	struct rb_node **n = &mcast_tree->mcast_tree.rb_node, *pn = NULL;
	struct vnic_mcast *mcaste_t;
	unsigned long flags;
	int rc;

	spin_lock_irqsave(&mcast_tree->mcast_rb_lock, flags);
	while (*n) {
		pn = *n;
		mcaste_t = rb_entry(pn, struct vnic_mcast, rb_node);
		rc = memcmp(mcaste->gid.raw, mcaste_t->gid.raw, GID_LEN);
		if (rc < 0)
			n = &pn->rb_left;
		else if (rc > 0)
			n = &pn->rb_right;
		else {
			rc = -EEXIST;
			goto out;
		}
	}

	rb_link_node(&mcaste->rb_node, pn, n);
	rb_insert_color(&mcaste->rb_node, &mcast_tree->mcast_tree);

	rc = 0;

out:
	vnic_dbg_mcast_v(mcaste->port->name,
			 "added (rc %d) vnic_mcast: MAC "MAC_6_PRINT_FMT
			 " GID "VNIC_GID_FMT"\n", rc,
			 MAC_6_PRINT_ARG(mcaste->mac),
			 VNIC_GID_ARG(mcaste->gid));

	spin_unlock_irqrestore(&mcast_tree->mcast_rb_lock, flags);
	return rc;
}

/*
 * The caller must hold the mcast_tree->mcast_rb_lock lock before calling
 */
void vnic_mcast_del(struct mcast_root *mcast_tree, struct vnic_mcast *mcaste)
{
	rb_erase(&mcaste->rb_node, &mcast_tree->mcast_tree);
}

/*
 * The caller must hold the mcast_tree->mcast_rb_lock lock before calling
*/
struct vnic_mcast *vnic_mcast_search(struct mcast_root *mcast_tree,
				     union ib_gid *gid)
{
	struct rb_node *n = mcast_tree->mcast_tree.rb_node;
	struct vnic_mcast *mcaste_t;
	int rc;

	while (n) {
		mcaste_t = rb_entry(n, struct vnic_mcast, rb_node);
		rc = memcmp(gid->raw, mcaste_t->gid.raw, GID_LEN);
		if (rc < 0)
			n = n->rb_left;
		else if (rc > 0)
			n = n->rb_right;
		else {
			vnic_dbg_mcast_v(mcaste_t->port->name,
					 "found: MAC "MAC_6_PRINT_FMT" GID "
					 VNIC_GID_FMT"\n",
					 MAC_6_PRINT_ARG(mcaste_t->mac),
					 VNIC_GID_ARG(mcaste_t->gid));
			goto out;
		}
	}
	mcaste_t = ERR_PTR(-ENODATA);

out:
	return mcaste_t;
}

static void vnic_mcast_detach_ll(struct vnic_mcast *mcaste, struct mcast_root *mcast_tree)
{
	struct vnic_port *port = mcaste->port;
	struct ib_ah *tmp_ih;
	unsigned long flags;
	int rc;

	vnic_dbg_mcast_v(port->name,
			 "mcaste->attached %d for mac "MAC_6_PRINT_FMT"\n",
			 test_bit(MCAST_ATTACHED, &mcaste->state),
			 MAC_6_PRINT_ARG(mcaste->mac));

	spin_lock_irqsave(&mcaste->lock, flags);
	if (!test_and_clear_bit(MCAST_ATTACHED, &mcaste->state)) {
		spin_unlock_irqrestore(&mcaste->lock, flags);
		return;
	}

	tmp_ih = mcaste->ah;
	mcaste->ah = NULL;
	spin_unlock_irqrestore(&mcaste->lock, flags);

	/* callback */
	if (mcaste->detach_cb) {
		vnic_dbg_mcast(port->name, "calling detach_cb\n");
		mcaste->detach_cb(mcaste, mcaste->detach_cb_ctx);
	}

	if (!mcaste->sender_only)
		rc = ib_detach_mcast(mcaste->qp, &mcaste->gid, port->attr.lid);
	else
		rc = 0;

	ASSERT(tmp_ih);
	if (ib_destroy_ah(tmp_ih))
		vnic_warn(port->name,
			  "ib_destroy_ah failed (rc %d) for mcaste mac "
			  MAC_6_PRINT_FMT"\n", rc,
			  MAC_6_PRINT_ARG(mcaste->mac));
	vnic_dbg_mcast(port->name, "GID "VNIC_GID_FMT" detached!\n",
		       VNIC_GID_ARG(mcaste->gid));
}

int vnic_mcast_detach(struct mcast_root *mcast_tree, struct vnic_mcast *mcaste)
{
	struct vnic_port *port = mcaste->port;
	unsigned long flags;

	/* must be a task, to make sure no attach task is pending */
	vnic_dbg_mcast_v(port->name, "queue delayed task (%lu) "
			 "vnic_mcast_detach_task\n", mcaste->backoff);

	/* cancel any pending/queued tasks. We can not use sync
	 * under the spinlock because it might hang. we need the
	 * spinlock here to ensure the requeueing is atomic
	 */
	vnic_dbg_mcast_v(port->name, "cancel attach_task\n");
	spin_lock_irqsave(&mcaste->lock, flags);
	clear_bit(MCAST_ATTACH_RUNNING, &mcaste->state);
	spin_unlock_irqrestore(&mcaste->lock, flags);
#ifndef _BP_WORK_SYNC
	cancel_delayed_work_sync(&mcaste->attach_task);
#else
	cancel_delayed_work(&mcaste->attach_task);
	flush_workqueue(mcast_wq);
#endif
	vnic_mcast_detach_ll(mcaste, mcast_tree);

	if (mcaste->port_mcaste)
		vnic_port_mcast_release(mcaste->port_mcaste);

	return 0;
}

static void vnic_mcast_attach_task(struct work_struct *work)
{
	struct ib_ah_attr av;
	struct vnic_mcast *mcaste =
	    container_of(work, struct vnic_mcast, attach_task.work);
	struct vnic_port *port = mcaste->port;
	unsigned long flags;
	int rc;
	u16 mlid;

	if ((++mcaste->attach_task_cnt > mcaste->retry && mcaste->retry) ||
		!test_bit(MCAST_ATTACH_RUNNING, &mcaste->state)) {
		vnic_dbg_mcast_v(port->name,
				 "attach_task stopped, tried %ld times\n",
				 mcaste->retry);
		goto out;
	}

	/* update backoff time */
	mcaste->backoff = min(mcaste->backoff * mcaste->backoff_factor,
			      msecs_to_jiffies(VNIC_MCAST_BACKOFF_MAX_MSEC));

	if (!test_bit(MCAST_JOINED, &mcaste->port_mcaste->state)) {
		vnic_dbg_mcast_v(port->name, "joined %d, retry %ld from %ld\n",
				 test_bit(MCAST_JOINED, &mcaste->port_mcaste->state),
				 mcaste->attach_task_cnt, mcaste->retry);
		goto retry;
	}

	/* attach QP */
	ASSERT(mcaste);
	ASSERT(mcaste->port_mcaste);
	ASSERT(mcaste->port_mcaste->sa_mcast);
	mlid = be16_to_cpu(mcaste->port_mcaste->rec.mlid);
	vnic_dbg_mcast(port->name, "QPN 0x%06x attaching MGID "VNIC_GID_FMT
		       " LID 0x%04x\n", mcaste->qp->qp_num,
		       VNIC_GID_ARG(mcaste->gid), mlid);
	if (!mcaste->sender_only)
		rc = ib_attach_mcast(mcaste->qp, &mcaste->gid, mlid);
	else
		rc = 0;

	if (rc) {
		int attach_count = atomic_read(&mcaste->port_mcaste->ref_cnt);

		vnic_err(port->name, "failed to attach (rc %d) to multicast "
			 "group, MGID "VNIC_GID_FMT"\n",
			 rc, VNIC_GID_ARG(mcaste->gid));

		if (port->dev->attr.max_mcast_qp_attach <= attach_count) {
			vnic_err(port->name, "Attach failed. Too many vnics are on the same"
				 " vhub on this port. vnics count=%d, max=%d\n", 
				 attach_count,
				 port->dev->attr.max_mcast_qp_attach);
		}

		goto retry;
	} else {
		/* create mcast ah */
		memset(&av, 0, sizeof(av));
		av.dlid = be16_to_cpu(mcaste->port_mcaste->rec.mlid);
		av.port_num = mcaste->port->num;
		av.ah_flags = IB_AH_GRH;
		av.static_rate = mcaste->port_mcaste->rec.rate;
		av.sl = mcaste->port_mcaste->rec.sl;
		memcpy(&av.grh.dgid, mcaste->gid.raw, GID_LEN);
		spin_lock_irqsave(&mcaste->lock, flags);
		mcaste->ah = ib_create_ah(port->pd, &av);
		if (IS_ERR(mcaste->ah)) {
			mcaste->ah = NULL;
			vnic_err(port->name,
				 "vnic_ib_create_ah failed (rc %d)\n",
				 (int)PTR_ERR(mcaste->ah));
			spin_unlock_irqrestore(&mcaste->lock, flags);
			/* for such a failure, no need to retry */
			goto out;
		}
		vnic_dbg_mcast(mcaste->port->name, "created mcast ah for %p\n", mcaste);

		/* callback */
		set_bit(MCAST_ATTACHED, &mcaste->state);
		spin_unlock_irqrestore(&mcaste->lock, flags);

		if (mcaste->cur_attached)
			set_bit(mcaste->attach_bit_nr, mcaste->cur_attached);
		vnic_dbg_mcast(mcaste->port->name,
			       "attached GID "VNIC_GID_FMT"\n",
			       VNIC_GID_ARG(mcaste->gid));
		if (mcaste->attach_cb) {
			vnic_dbg_mcast(mcaste->port->name,
				       "calling attach_cb\n");
			mcaste->attach_cb(mcaste, mcaste->attach_cb_ctx);
		}
	}

out:
	mcaste->attach_task_cnt = 0; /* for next time */
	mcaste->backoff = mcaste->backoff_init;
	clear_bit(MCAST_ATTACH_RUNNING, &mcaste->state);
	complete(&mcaste->attach_complete);
	return;

retry:
	spin_lock_irqsave(&mcaste->lock, flags);
	if (test_bit(MCAST_ATTACH_RUNNING, &mcaste->state)) {
		/* calls vnic_mcast_attach_task() */
		queue_delayed_work(mcast_wq, &mcaste->attach_task, mcaste->backoff);
	}
	spin_unlock_irqrestore(&mcaste->lock, flags);
}

int vnic_mcast_attach(struct mcast_root *mcast_tree, struct vnic_mcast *mcaste)
{
	struct vnic_port_mcast *pmcaste;
	struct vnic_port *port = mcaste->port;
	int rc = 0;
	ASSERT(mcaste);

	mcaste->backoff_init = mcaste->backoff;

	pmcaste = vnic_port_mcast_update(mcaste);
	if (IS_ERR(pmcaste)) {
		vnic_err(port->name, "vnic_port_mcast_update failed GID "
			 VNIC_GID_FMT"\n", VNIC_GID_ARG(mcaste->gid));
		rc = PTR_ERR(pmcaste);
		goto out;
	}

	mcaste->port_mcaste = pmcaste;

	set_bit(MCAST_ATTACH_RUNNING, &mcaste->state);

	/* must be a task, to sample the joined flag */
	vnic_dbg_mcast_v(port->name, "queue delayed task (%lu) "
			 "vnic_mcast_join_task\n", mcaste->backoff);
	init_completion(&mcaste->attach_complete);
	/* calls vnic_mcast_attach_task() */
	queue_delayed_work(mcast_wq, &mcaste->attach_task, 0);
	if (mcaste->blocking) {
		wait_for_completion(&mcaste->attach_complete);
		if (test_bit(MCAST_ATTACHED, &mcaste->state))
			goto out;
		vnic_mcast_detach(mcast_tree, mcaste);
		rc = 1;
	}

out:
	return rc;
}

#if 0
static int vnic_mcast_attach_all(struct mcast_root *mcast_tree)
{
	int fails = 0;
	struct vnic_mcast *mcaste;
	struct rb_node *n;

	n = rb_first(&mcast_tree->mcast_tree);
	while (n) {
		mcaste = rb_entry(n, struct vnic_mcast, rb_node);
		n = rb_next(n);
		/* async call */
		if (vnic_mcast_attach(mcast_tree, mcaste))
			fails++;
	}

	return fails;
}
#endif

int vnic_mcast_del_all(struct mcast_root *mcast_tree)
{
	struct rb_node *n;
	struct vnic_mcast *mcaste, *mcaste_t;
	unsigned long flags;
	int fails = 0;
	LIST_HEAD(local_list);

	spin_lock_irqsave(&mcast_tree->mcast_rb_lock, flags);
	n = rb_first(&mcast_tree->mcast_tree);
	while (n) {
		mcaste = rb_entry(n, struct vnic_mcast, rb_node);
		vnic_mcast_del(mcast_tree, mcaste);
		list_add_tail(&mcaste->list, &local_list);
		n = rb_first(&mcast_tree->mcast_tree);
	}
	spin_unlock_irqrestore(&mcast_tree->mcast_rb_lock, flags);

	list_for_each_entry_safe(mcaste, mcaste_t, &local_list, list) {
		list_del(&mcaste->list);
		vnic_mcast_detach(mcast_tree, mcaste);
		vnic_mcast_dealloc(mcaste);
	}

	return fails;
}

int vnic_mcast_del_user(struct mcast_root *mcast_tree, void *owner)
{
	struct rb_node *n;
	struct vnic_mcast *mcaste, *mcaste_t;
	unsigned long flags;
	int fails = 0;
	LIST_HEAD(local_list);

	spin_lock_irqsave(&mcast_tree->mcast_rb_lock, flags);
	n = rb_first(&mcast_tree->mcast_tree);
	while (n) {
		mcaste = rb_entry(n, struct vnic_mcast, rb_node);
		n = rb_next(&mcaste->rb_node);
		if (mcaste->priv_data == owner) {
			list_add_tail(&mcaste->list, &local_list);
			vnic_mcast_del(mcast_tree, mcaste);
		}
	}
	spin_unlock_irqrestore(&mcast_tree->mcast_rb_lock, flags);

	list_for_each_entry_safe(mcaste, mcaste_t, &local_list, list) {
		list_del(&mcaste->list);
		vnic_mcast_detach(mcast_tree, mcaste);
		vnic_mcast_dealloc(mcaste);
	}

	return fails;
}

/* PORT MCAST FUNCTIONS */
static struct vnic_port_mcast *vnic_port_mcast_alloc(struct vnic_port *port,
						     union ib_gid *gid)
{
	struct vnic_port_mcast *mcaste;

	mcaste = kzalloc(sizeof *mcaste, GFP_ATOMIC);
	if (!mcaste)
		return ERR_PTR(-ENOMEM);

	mcaste->gid = *gid;
	mcaste->port = port;
	init_completion(&mcaste->leave_complete);
	atomic_set(&mcaste->ref_cnt, 1);
	INIT_DELAYED_WORK(&mcaste->join_task, vnic_port_mcast_join_task);
	INIT_WORK(&mcaste->leave_task, vnic_port_mcast_leave_task);
	mcaste->sa_mcast = ERR_PTR(-EINVAL);
	memset(&mcaste->rec,0,sizeof(mcaste->rec));
	vnic_dbg_mcast_v(mcaste->port->name, "allocated port_mcast GID "
			 VNIC_GID_FMT"\n", VNIC_GID_ARG(mcaste->gid));
	spin_lock_init(&mcaste->lock);
	set_bit(MCAST_JOIN_RUNNING, &mcaste->state);

	return mcaste;
}

static void vnic_port_mcast_dealloc(struct vnic_port_mcast *mcaste)
{
	ASSERT(mcaste);
	vnic_dbg_mcast_v(NULL, "dealloc port_mcast GID "
			 VNIC_GID_FMT"\n", VNIC_GID_ARG(mcaste->gid));
	kfree(mcaste);
}

/*
 * This function accesses the port mcast tree. Please make sure
 * to call it only while holding the port mcast_rb_lock
*/
static int vnic_port_mcast_add(struct vnic_port_mcast *mcaste)
{
	struct rb_node **n = &mcaste->port->mcast_tree.mcast_tree.rb_node;
	struct rb_node *pn = NULL;
	struct vnic_port_mcast *mcaste_t;
	int rc;

	while (*n) {
		pn = *n;
		mcaste_t = rb_entry(pn, struct vnic_port_mcast, rb_node);
		rc = memcmp(mcaste->gid.raw, mcaste_t->gid.raw, GID_LEN);
		if (rc < 0)
			n = &pn->rb_left;
		else if (rc > 0)
			n = &pn->rb_right;
		else {
			rc = -EEXIST;
			goto out;
		}
	}

	rb_link_node(&mcaste->rb_node, pn, n);
	rb_insert_color(&mcaste->rb_node, &mcaste->port->mcast_tree.mcast_tree);
	rc = 0;

out:
	vnic_dbg_mcast_v(mcaste->port->name, "added (rc %d) port_mcast GID "
			 VNIC_GID_FMT"\n", rc, VNIC_GID_ARG(mcaste->gid));
	return rc;
}

/*
 * This function accesses the port mcast tree. Please make sure
 * to call it only while holding the port mcast_rb_lock
*/
static void vnic_port_mcast_del(struct vnic_port_mcast *mcaste)
{
	ASSERT(mcaste);
	vnic_dbg_mcast_v(mcaste->port->name, "del port_mcast GID "
			 VNIC_GID_FMT"\n", VNIC_GID_ARG(mcaste->gid));
	rb_erase(&mcaste->rb_node, &mcaste->port->mcast_tree.mcast_tree);
}

/*
 * This function accesses the port mcast tree. Please make sure
 * to call it only while holding the port mcast_rb_lock
*/
struct vnic_port_mcast *vnic_port_mcast_search(struct vnic_port *port,
					       union ib_gid *gid)
{
	struct rb_node *n = port->mcast_tree.mcast_tree.rb_node;
	struct vnic_port_mcast *mcaste_t;
	int rc;

	while (n) {
		mcaste_t = rb_entry(n, struct vnic_port_mcast, rb_node);
		rc = memcmp(gid->raw, mcaste_t->gid.raw, GID_LEN);
		if (rc < 0)
			n = n->rb_left;
		else if (rc > 0)
			n = n->rb_right;
		else {
			vnic_dbg_mcast_v(mcaste_t->port->name,
					 "found: GID "VNIC_GID_FMT"\n",
					 VNIC_GID_ARG(mcaste_t->gid));
			goto out;
		}
	}
	mcaste_t = ERR_PTR(-ENODATA);

out:
	return mcaste_t;
}
/*
static void vnic_port_mcast_leave_task(struct work_struct *work)
{
	struct vnic_port_mcast *mcaste =
		container_of(work, struct vnic_port_mcast, leave_task.work);

	vnic_dbg_mcast_v(mcaste->port->name, "leave GID "VNIC_GID_FMT"\n",
			 VNIC_GID_ARG(mcaste->gid));

	if (!IS_ERR(mcaste->sa_mcast) && test_bit(MCAST_JOINED, &mcaste->port_mcaste->state))
		vnic_dbg_mcast(mcaste->port->name,
			       "mcast left: GID "VNIC_GID_FMT"\n",
			       VNIC_GID_ARG(mcaste->gid));
	if (!IS_ERR(mcaste->sa_mcast))
		ib_sa_free_multicast(mcaste->sa_mcast);
	mcaste->sa_mcast = ERR_PTR(-EINVAL);
	clear_bit(MCAST_JOINED, &mcaste->port_mcaste->state);
}
*/

static int vnic_port_mcast_leave(struct vnic_port_mcast *mcaste,
				 unsigned long backoff)
{
	unsigned long flags;

	ASSERT(mcaste);
	vnic_dbg_mcast(NULL, "queue delayed task (%lu) "
		       "vnic_mcast_leave_task\n", backoff);

	/* cancel any pending/queued tasks. We can not use sync
	 * under the spinlock because it might hang. we need the
	 * spinlock here to ensure the requeueing is atomic
	 */
	spin_lock_irqsave(&mcaste->lock, flags);
	clear_bit(MCAST_JOIN_RUNNING, &mcaste->state);
	spin_unlock_irqrestore(&mcaste->lock, flags);
#ifndef _BP_WORK_SYNC
	cancel_delayed_work_sync(&mcaste->join_task);
#else
	cancel_delayed_work(&mcaste->join_task);
	if (delayed_work_pending(&mcaste->join_task)) {
		return -EBUSY;
	}
#endif

	if (test_and_clear_bit(MCAST_JOIN_STARTED, &mcaste->state)
	    && !IS_ERR(mcaste->sa_mcast)) {
		ib_sa_free_multicast(mcaste->sa_mcast);
		mcaste->sa_mcast = ERR_PTR(-EINVAL);
	}

	return 0;
}

static int vnic_port_mcast_join_comp(int status, struct ib_sa_multicast *sa_mcast)
{
	struct vnic_port_mcast *mcaste = sa_mcast->context;
	unsigned long flags;

	vnic_dbg_mcast(mcaste->port->name, "join completion for GID "
		       VNIC_GID_FMT" (status %d)\n",
		       VNIC_GID_ARG(mcaste->gid), status);

	if (status == -ENETRESET)
		return 0;

	if (status)
		goto retry;

	/* same as mcaste->rec = mcaste->sa_mcast->rec; */
	mcaste->rec = sa_mcast->rec;

	set_bit(MCAST_JOINED, &mcaste->state);
	vnic_dbg_mcast(mcaste->port->name, "joined GID "VNIC_GID_FMT"\n",
		       VNIC_GID_ARG(mcaste->gid));
#if 0
	vnic_dbg_mcast_v(mcaste->port->name, "mcast record dump:\n");
	vnic_dbg_mcast_v(mcaste->port->name, "mgid      "VNIC_GID_FMT"\n",
			 VNIC_GID_ARG(rec->mgid));
	vnic_dbg_mcast_v(mcaste->port->name, "port_gid  "VNIC_GID_FMT"\n",
			 VNIC_GID_ARG(rec->port_gid));
	vnic_dbg_mcast_v(mcaste->port->name, "pkey       0x%x\n", rec->pkey);
	vnic_dbg_mcast_v(mcaste->port->name, "qkey       0x%x\n", rec->qkey);
	vnic_dbg_mcast_v(mcaste->port->name, "mtu_slct   0x%x\n",
			 rec->mtu_selector);
	vnic_dbg_mcast_v(mcaste->port->name, "mtu        0x%x\n", rec->mtu);
	vnic_dbg_mcast_v(mcaste->port->name, "rate_slct  0x%x\n",
			 rec->rate_selector);
	vnic_dbg_mcast_v(mcaste->port->name, "rate       0x%x\n", rec->rate);
	vnic_dbg_mcast_v(mcaste->port->name, "sl         0x%x\n", rec->sl);
	vnic_dbg_mcast_v(mcaste->port->name, "flow_label 0x%x\n",
			 rec->flow_label);
	vnic_dbg_mcast_v(mcaste->port->name, "hop_limit  0x%x\n",
			 rec->hop_limit);
#endif

	goto out;
retry:
	/* calls vnic_port_mcast_join_task() */
	spin_lock_irqsave(&mcaste->lock, flags);
	if (test_bit(MCAST_JOIN_RUNNING, &mcaste->state))
		queue_delayed_work(mcast_wq, &mcaste->join_task, mcaste->backoff);
	spin_unlock_irqrestore(&mcaste->lock, flags);

out:
	/* rc is always zero so we handle ib_sa_free_multicast ourselves */
	return 0;
}

static void vnic_port_mcast_join_task(struct work_struct *work)
{
	struct vnic_port_mcast *mcaste =
	    container_of(work, struct vnic_port_mcast, join_task.work);
	struct ib_sa_mcmember_rec rec = {
		.join_state = mcaste->join_state
	};
	int rc;
	ib_sa_comp_mask comp_mask;
	unsigned long flags;

	if (++mcaste->join_task_cnt > mcaste->retry && mcaste->retry) {
		vnic_dbg_mcast(mcaste->port->name,
			       "join_task stopped, tried %ld times\n",
			       mcaste->retry);
		goto out;
	}

	/* update backoff time */
	mcaste->backoff = min(mcaste->backoff * mcaste->backoff_factor,
			      msecs_to_jiffies(VNIC_MCAST_BACKOFF_MAX_MSEC));

	rec.mgid.global = mcaste->gid.global;
	rec.port_gid.global = mcaste->port->gid.global;
	rec.pkey = cpu_to_be16(mcaste->pkey);

	comp_mask =
	    IB_SA_MCMEMBER_REC_MGID |
	    IB_SA_MCMEMBER_REC_PORT_GID |
	    /*IB_SA_MCMEMBER_REC_PKEY | */
	    IB_SA_MCMEMBER_REC_JOIN_STATE;

	if (mcaste->create) {
		comp_mask |=
		    IB_SA_MCMEMBER_REC_QKEY |
		    IB_SA_MCMEMBER_REC_MTU_SELECTOR |
		    IB_SA_MCMEMBER_REC_MTU |
		    IB_SA_MCMEMBER_REC_TRAFFIC_CLASS |
		    IB_SA_MCMEMBER_REC_RATE_SELECTOR |
		    IB_SA_MCMEMBER_REC_RATE |
		    IB_SA_MCMEMBER_REC_SL |
		    IB_SA_MCMEMBER_REC_FLOW_LABEL |
		    IB_SA_MCMEMBER_REC_HOP_LIMIT |
		    IB_SA_MCMEMBER_REC_PKEY;

		rec.qkey = cpu_to_be32(mcaste->qkey);
		rec.mtu_selector = IB_SA_EQ;
		rec.rate_selector = IB_SA_EQ;
		/* when no_bxm is set, use min values to let everybody in */
		rec.mtu = no_bxm ? IB_MTU_2048 : mcaste->port->attr.max_mtu;
		rec.rate = no_bxm ? IB_RATE_10_GBPS : mcaste->port->rate_enum;
		rec.sl = 0;
		rec.flow_label = 0;
		rec.hop_limit = 0;
	}

	vnic_dbg_mcast(mcaste->port->name, "joining MGID "VNIC_GID_FMT
		       " create %d, comp_mask %lu\n",
		       VNIC_GID_ARG(mcaste->gid), mcaste->create, (unsigned long)comp_mask);

	if (!IS_ERR(mcaste->sa_mcast))
		ib_sa_free_multicast(mcaste->sa_mcast);

	mcaste->sa_mcast =
	    ib_sa_join_multicast(&vnic_sa_client, mcaste->port->dev->ca,
				 mcaste->port->num, &rec, comp_mask,
				 GFP_KERNEL, vnic_port_mcast_join_comp, mcaste);
	set_bit(MCAST_JOIN_STARTED, &mcaste->state);

	if (IS_ERR(mcaste->sa_mcast)) {
		rc = PTR_ERR(mcaste->sa_mcast);
		vnic_warn(mcaste->port->name,
			  "ib_sa_join_multicast failed, status %d\n", rc);
		/* calls vnic_port_mcast_join_task() */
		spin_lock_irqsave(&mcaste->lock, flags);
		if (test_bit(MCAST_JOIN_RUNNING, &mcaste->state))
			queue_delayed_work(mcast_wq, &mcaste->join_task, mcaste->backoff);
		spin_unlock_irqrestore(&mcaste->lock, flags);
	}

	return;

out:
	mcaste->join_task_cnt = 0; /* for next time */
	mcaste->backoff = mcaste->backoff_init;
	return;
}

static int vnic_port_mcast_join(struct vnic_port_mcast *mcaste)
{
	unsigned long flags;

	ASSERT(mcaste);
	vnic_dbg_mcast_v(mcaste->port->name, "queue delayed task (%lu) "
			 "vnic_port_mcast_join_task\n", mcaste->backoff);

	/* calls vnic_port_mcast_join_task() */
	spin_lock_irqsave(&mcaste->lock, flags);
	if (test_bit(MCAST_JOIN_RUNNING, &mcaste->state))
		queue_delayed_work(mcast_wq, &mcaste->join_task, 0);
	spin_unlock_irqrestore(&mcaste->lock, flags);

	return 0;
}

#if 0
static int vnic_port_mcast_join_all(struct vnic_port *port)
{
	int fails = 0;
	struct vnic_port_mcast *mcaste;
	struct rb_node *n;

	n = rb_first(&port->mcast_tree.mcast_tree);
	while (n) {
		mcaste = rb_entry(n, struct vnic_port_mcast, rb_node);
		n = rb_next(n);
		if (vnic_port_mcast_join(mcaste))
			fails++;
	}

	return fails;
}
#endif

static void vnic_port_mcast_leave_task(struct work_struct *work)
{
	struct vnic_port_mcast *mcaste =
	    container_of(work, struct vnic_port_mcast, leave_task);

#ifndef _BP_WORK_SYNC
	vnic_port_mcast_leave(mcaste, 0);
#else
	if (vnic_port_mcast_leave(mcaste, 0)) {
		queue_work(mcast_wq, &mcaste->leave_task);
		return;
	}
#endif
	vnic_port_mcast_dealloc(mcaste);
}

static void vnic_port_mcast_release(struct vnic_port_mcast *mcaste)
{
	unsigned long flags;

	struct vnic_port *port = mcaste->port;

	vnic_dbg_mcast(port->name, "update mcaste->ref_cnt %d -> %d\n",
		       atomic_read(&mcaste->ref_cnt),
		       atomic_read(&mcaste->ref_cnt) - 1);

	spin_lock_irqsave(&port->mcast_tree.mcast_rb_lock, flags);
	if (atomic_dec_and_test(&mcaste->ref_cnt)) {
		vnic_port_mcast_del(mcaste);
		spin_unlock_irqrestore(&port->mcast_tree.mcast_rb_lock, flags);

		/* we are not going to wait for the leave to terminate.
		 *  We will just go on.
		 *  calls vnic_port_mcast_leave_task()
		 */
		queue_work(mcast_wq, &mcaste->leave_task);
	} else
		spin_unlock_irqrestore(&port->mcast_tree.mcast_rb_lock, flags);
}

static struct vnic_port_mcast *vnic_port_mcast_update(struct vnic_mcast *_mcaste)
{
	union ib_gid *gid = &_mcaste->port_gid;
	u32 qkey = _mcaste->qkey;
	u16 pkey = _mcaste->pkey;
	struct vnic_port *port = _mcaste->port;
	struct vnic_port_mcast *mcaste;
	unsigned long flags;

	spin_lock_irqsave(&port->mcast_tree.mcast_rb_lock, flags);
	mcaste = vnic_port_mcast_search(port, gid);
	/* entry found */
	if (PTR_ERR(mcaste) != -ENODATA) {
		ASSERT(!IS_ERR(mcaste));
		atomic_inc(&mcaste->ref_cnt);
		spin_unlock_irqrestore(&port->mcast_tree.mcast_rb_lock, flags);
		vnic_dbg_mcast(mcaste->port->name,
			       "found, add GID "VNIC_GID_FMT" \n",
			       VNIC_GID_ARG(*gid));
		vnic_dbg_mcast(mcaste->port->name,
			       "update mcaste->ref_cnt %d -> %d\n",
			       atomic_read(&mcaste->ref_cnt),
			       atomic_read(&mcaste->ref_cnt) + 1);
	} else { /* not found, add it */
		mcaste = vnic_port_mcast_alloc(port, gid);
		if (IS_ERR(mcaste)) {
			spin_unlock_irqrestore(&port->mcast_tree.mcast_rb_lock, flags);
			return mcaste;
		}
		vnic_dbg_mcast(mcaste->port->name,
			       "not found, add GID "VNIC_GID_FMT" \n",
			       VNIC_GID_ARG(*gid));
		vnic_dbg_mcast(mcaste->port->name,
			       "update mcaste->ref_cnt %d -> %d\n",
			       atomic_read(&mcaste->ref_cnt),
			       atomic_read(&mcaste->ref_cnt) + 1);
		mcaste->qkey = qkey;
		mcaste->pkey = pkey;
		mcaste->backoff_init = _mcaste->backoff_init;
		mcaste->backoff = _mcaste->backoff;
		mcaste->backoff_factor = _mcaste->backoff_factor;
		mcaste->retry = _mcaste->retry;
		mcaste->create = _mcaste->create;
		mcaste->join_state = _mcaste->join_state;
		vnic_port_mcast_add(mcaste);
		spin_unlock_irqrestore(&port->mcast_tree.mcast_rb_lock, flags);

		vnic_port_mcast_join(mcaste);
		vnic_dbg_mcast(mcaste->port->name, "added\n");
	}

	return mcaste;
}

#if 0
void vnic_port_mcast_del_all(struct vnic_port *port)
{

	struct rb_node *n;
	struct vnic_port_mcast *mcaste, *mcaste_t;
	LIST_HEAD(local_list);

	ASSERT(port);

	n = rb_first(&port->mcast_tree.mcast_tree);
	while (n) {
		mcaste = rb_entry(n, struct vnic_port_mcast, rb_node);
		list_add_tail(&mcaste->list, &local_list);
		n = rb_next(&mcaste->rb_node);
	}

	list_for_each_entry_safe(mcaste, mcaste_t, &local_list, list) {
		list_del(&mcaste->list);
		vnic_warn(port->name, "shouldn't find gid "VNIC_GID_FMT"\n",
			  VNIC_GID_ARG(mcaste->gid));
		vnic_port_mcast_release(mcaste);
	}

	return;
}
#endif

void vnic_tree_mcast_detach(struct mcast_root *mcast_tree)
{
	struct vnic_mcast *mcaste, *mcaste_t;
	struct rb_node *n;
	unsigned long flags;
	INIT_LIST_HEAD(&mcast_tree->reattach_list);

	spin_lock_irqsave(&mcast_tree->mcast_rb_lock, flags);
	n = rb_first(&mcast_tree->mcast_tree);
	while (n) {
		mcaste = rb_entry(n, struct vnic_mcast, rb_node);
		list_add_tail(&mcaste->list, &mcast_tree->reattach_list);
		n = rb_next(&mcaste->rb_node);
		vnic_mcast_del(mcast_tree, mcaste);
		mcaste->attach_task_cnt = 0;
	}
	spin_unlock_irqrestore(&mcast_tree->mcast_rb_lock, flags);

	list_for_each_entry_safe(mcaste, mcaste_t, &mcast_tree->reattach_list, list) {
		vnic_mcast_detach(mcast_tree, mcaste);
	}

	return;
}

void vnic_tree_mcast_attach(struct mcast_root *mcast_tree)
{
	struct vnic_mcast *mcaste, *mcaste_t;
	int rc;

	/* The add function grabs the mcast_rb_lock no need to take it */
	list_for_each_entry_safe(mcaste, mcaste_t, &mcast_tree->reattach_list, list) {
		rc = vnic_mcast_add(mcast_tree, mcaste);
		ASSERT(!rc);
		rc = vnic_mcast_attach(mcast_tree, mcaste);
		ASSERT(!rc);
		list_del(&mcaste->list);
	}

	return;
}

int vnic_mcast_init()
{
	ib_sa_register_client(&vnic_sa_client);

	mcast_wq = create_singlethread_workqueue("mcast_wq");
	if (!mcast_wq)
		return -ENOMEM;

	return 0;
}

void vnic_mcast_cleanup()
{
	ASSERT(mcast_wq);
	vnic_dbg_mark();
	flush_workqueue(mcast_wq);
	vnic_dbg_mark();
	destroy_workqueue(mcast_wq);
	vnic_dbg_mark();
	ib_sa_unregister_client(&vnic_sa_client);

	return;
}
