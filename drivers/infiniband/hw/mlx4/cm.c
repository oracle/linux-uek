/*
 * Copyright (c) 2007 Cisco Systems, Inc. All rights reserved.
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

#include <rdma/ib_mad.h>

#include <linux/mlx4/cmd.h>
#include <linux/rbtree.h>
#include <linux/idr.h>

#include "mlx4_ib.h"

#ifndef DEBUG
#define TRACE(format, arg...) mlx4_ib_dbg(format, ## arg)
#else
#define TRACE(format, arg...) \
	do {					\
		printk("%30s:%d - " format, __func__, __LINE__, ## arg);	\
	} while (0)
#endif
#define CM_CLEANUP_CACHE_TIMEOUT  ( 5 * HZ )

#define ID_SCHED_DELETE		1
#define	ID_CANCEL_DELETE	2

struct id_map_entry {
	struct rb_node node;

	u32 sl_cm_id;
	u32 pv_cm_id;
	int slave_id;
	int scheduled_delete;
	struct mlx4_ib_dev *dev;

	struct list_head list;
	struct delayed_work timeout;
};

struct cm_generic_msg {
	struct ib_mad_hdr hdr;

	__be32 local_comm_id;
	__be32 remote_comm_id;
};

struct cm_req_msg {
	unsigned char unused[0x60];
	union ib_gid primary_path_sgid;
};

#define CM_REQ_ATTR_ID		cpu_to_be16(0x0010)
#define CM_MRA_ATTR_ID		cpu_to_be16(0x0011)
#define CM_REJ_ATTR_ID		cpu_to_be16(0x0012)
#define CM_REP_ATTR_ID		cpu_to_be16(0x0013)
#define CM_RTU_ATTR_ID		cpu_to_be16(0x0014)
#define CM_DREQ_ATTR_ID		cpu_to_be16(0x0015)
#define CM_DREP_ATTR_ID		cpu_to_be16(0x0016)
#define CM_SIDR_REQ_ATTR_ID	cpu_to_be16(0x0017)
#define CM_SIDR_REP_ATTR_ID	cpu_to_be16(0x0018)
#define CM_LAP_ATTR_ID		cpu_to_be16(0x0019)
#define CM_APR_ATTR_ID		cpu_to_be16(0x001A)

#define CODE2STR(__code) { __code, #__code }
static const char *attr2str(int code)
{
	int i;
	struct {
		int code;
		const char *str;
	} code2str[] = {
		CODE2STR(CM_REQ_ATTR_ID),
		CODE2STR(CM_MRA_ATTR_ID),
		CODE2STR(CM_REJ_ATTR_ID),
		CODE2STR(CM_REP_ATTR_ID),
		CODE2STR(CM_RTU_ATTR_ID),
		CODE2STR(CM_DREQ_ATTR_ID),
		CODE2STR(CM_DREP_ATTR_ID),
		CODE2STR(CM_SIDR_REQ_ATTR_ID),
		CODE2STR(CM_SIDR_REP_ATTR_ID),
		CODE2STR(CM_LAP_ATTR_ID),
		CODE2STR(CM_APR_ATTR_ID),
	};

	for (i = 0; i < ARRAY_SIZE(code2str); i++) {
		if (code2str[i].code == code)
			return code2str[i].str;
	}

	return "Unknown";
}

static void set_local_comm_id(struct ib_mad *mad, u32 cm_id)
{
	struct cm_generic_msg *msg = (struct cm_generic_msg *)mad;
	msg->local_comm_id = cpu_to_be32(cm_id);
}

static u32 get_local_comm_id(struct ib_mad *mad)
{
	struct cm_generic_msg *msg = (struct cm_generic_msg *)mad;

	return be32_to_cpu(msg->local_comm_id);
}

static void set_remote_comm_id(struct ib_mad *mad, u32 cm_id)
{
	struct cm_generic_msg *msg = (struct cm_generic_msg *)mad;
	msg->remote_comm_id = cpu_to_be32(cm_id);
	//TRACE("Replacing cm_id\n");
}

static u32 get_remote_comm_id(struct ib_mad *mad)
{
	struct cm_generic_msg *msg = (struct cm_generic_msg *)mad;

	return be32_to_cpu(msg->remote_comm_id);
}

static union ib_gid gid_from_req_msg(struct ib_device *ibdev, struct ib_mad *mad)
{
	struct cm_req_msg *msg = (struct cm_req_msg *)mad;

	return msg->primary_path_sgid;
}

/* Lock should be taken before called */
static struct id_map_entry *
id_map_find_by_sl_id(struct ib_device *ibdev, u32 slave_id, u32 sl_cm_id)
{
	struct rb_root *sl_id_map = &to_mdev(ibdev)->sriov.sl_id_map;
	struct rb_node *node = sl_id_map->rb_node;

	//TRACE("looking id for {slave: %d, sl_cm_id: 0x%x}\n",
//			slave_id, sl_cm_id);
	while (node)
	{
		struct id_map_entry *id_map_entry =
			rb_entry(node, struct id_map_entry, node);

		if (id_map_entry->sl_cm_id > sl_cm_id)
			node = node->rb_left;
		else if (id_map_entry->sl_cm_id < sl_cm_id)
			node = node->rb_right;
		else if (id_map_entry->slave_id > slave_id)
			node = node->rb_left;
		else if (id_map_entry->slave_id < slave_id)
			node = node->rb_right;
		else {
			//TRACE("Found id\n");
			return id_map_entry;
		}
	}
	//TRACE("Couldn't find id\n");
	return NULL;
}

static void id_map_ent_timeout(struct work_struct *work)
{
	struct delayed_work *delay = to_delayed_work(work);
	struct id_map_entry *ent = container_of(delay, struct id_map_entry, timeout);
	struct id_map_entry *db_ent, *found_ent;
	struct mlx4_ib_dev *dev = ent->dev;
	struct mlx4_ib_sriov *sriov = &dev->sriov;
	struct rb_root *sl_id_map = &sriov->sl_id_map;
	int pv_id = (int) ent->pv_cm_id;
	unsigned long flags;

	spin_lock_irqsave(&sriov->id_map_lock, flags);
	db_ent = (struct id_map_entry *)idr_find(&sriov->pv_id_table, pv_id);
	if (db_ent) {
		TRACE("timeout cleanup: id[pv_cm_id: 0x%x] = "
		      "{slave_id: %d, sl_cm_id: 0x%x}\n",
		      pv_id, ent->slave_id, ent->sl_cm_id);
	} else {
		TRACE("timeout cleanup: No entry for pv_cm_id 0x%x\n", pv_id);
		goto out;
	}
	found_ent = id_map_find_by_sl_id(&dev->ib_dev, ent->slave_id, ent->sl_cm_id);
	if (found_ent && found_ent == ent)
		rb_erase(&found_ent->node, sl_id_map);
	idr_remove(&sriov->pv_id_table, pv_id);

out:
	list_del(&ent->list);
	spin_unlock_irqrestore(&sriov->id_map_lock, flags);
	TRACE("Freeing ent [pv_cm_id: 0x%x]\n", pv_id);
	kfree(ent);
}

static void id_map_find_del(struct ib_device *ibdev, int pv_cm_id)
{
	struct mlx4_ib_sriov *sriov = &to_mdev(ibdev)->sriov;
	struct rb_root *sl_id_map = &sriov->sl_id_map;
	struct id_map_entry *ent, *found_ent;

	spin_lock(&sriov->id_map_lock);
	ent = (struct id_map_entry *)idr_find(&sriov->pv_id_table, pv_cm_id);
	if (ent) {
		TRACE("id[pv_cm_id: 0x%x] = {slave_id: %d, sl_cm_id: 0x%x}\n",
			pv_cm_id, ent->slave_id, ent->sl_cm_id);
	} else {
		TRACE("No entry for pv_cm_id 0x%x\n", pv_cm_id);
		goto out;
	}
	found_ent = id_map_find_by_sl_id(ibdev, ent->slave_id, ent->sl_cm_id);
	if (found_ent && found_ent == ent)
	    rb_erase(&found_ent->node, sl_id_map);
	idr_remove(&sriov->pv_id_table, pv_cm_id);
out:
	spin_unlock(&sriov->id_map_lock);
}

static void sl_id_map_add(struct ib_device *ibdev, struct id_map_entry *new)
{
	struct rb_root *sl_id_map = &to_mdev(ibdev)->sriov.sl_id_map;
	struct rb_node **link = &sl_id_map->rb_node, *parent = NULL;
	struct id_map_entry *ent;
	int slave_id = new->slave_id;
	int sl_cm_id = new->sl_cm_id;

	//TRACE("Storing slave_id: %d, sl_cm_id: 0x%x\n", slave_id, sl_cm_id);
	ent = id_map_find_by_sl_id(ibdev, slave_id, sl_cm_id);
	if (ent) {
		mlx4_ib_dbg("overriding existing sl_id_map entry (cm_id = %x)",
				sl_cm_id);

		rb_replace_node(&ent->node, &new->node, sl_id_map);
		//id_map_entry_free(ibdev, ent);

		return;
	}

	/* Go to the bottom of the tree */
	while (*link)
	{
		struct id_map_entry *ent;

		parent = *link;
		ent = rb_entry(parent, struct id_map_entry, node);

		if (ent->sl_cm_id > sl_cm_id || (ent->sl_cm_id == sl_cm_id && ent->slave_id > slave_id))
			link = &(*link)->rb_left;
		else
			link = &(*link)->rb_right;
	}

	rb_link_node(&new->node, parent, link);
	rb_insert_color(&new->node, sl_id_map);
}

/* try to reschedule the delayed work
 * if not scheduled before, schedule it; otherwise, try to cancel it first and
 * reschedule on the cuccess of cancellation.
 *
 * sriov->going_down_lock & sriov->id_map_lock are required by caller
 *
 * returns 1 when (re)scheduled successfully; 0 otherwise
 */
static int __try_reschedule(struct id_map_entry *ent)
{
	if (!ent->scheduled_delete) {
		ent->scheduled_delete = 1;
		schedule_delayed_work(&ent->timeout, CM_CLEANUP_CACHE_TIMEOUT);
		return 1;
	}

	/* try to cancel delayed work */
	if (cancel_delayed_work(&ent->timeout)) {
		/* work was successfully cancelled, work not running,
		 * it's safe to queue another one */
		schedule_delayed_work(&ent->timeout, CM_CLEANUP_CACHE_TIMEOUT);
		return 1;
	}

	/* the timeout() work maybe running, don't queue another one */
	return 0;
}

static void schedule_delayed(struct ib_device *ibdev, struct id_map_entry *id)
{
	struct mlx4_ib_sriov *sriov = &to_mdev(ibdev)->sriov;
	unsigned long flags;

	spin_lock(&sriov->id_map_lock);
	spin_lock_irqsave(&sriov->going_down_lock, flags);
	/*make sure that there is no schedule inside the scheduled work.*/
	if (!sriov->is_going_down)
		__try_reschedule(id);
	spin_unlock_irqrestore(&sriov->going_down_lock, flags);
	spin_unlock(&sriov->id_map_lock);
}

static struct id_map_entry *
id_map_alloc(struct ib_device *ibdev, int slave_id, u32 sl_cm_id)
{
	int ret, id;
	static int next_id;
	struct id_map_entry *ent;
	struct mlx4_ib_sriov *sriov = &to_mdev(ibdev)->sriov;

	//TRACE("Allocating new id\n");
	ent = kmalloc(sizeof(struct id_map_entry), GFP_KERNEL);
	if (!ent) {
		mlx4_ib_warn(ibdev, "Couldn't allocate id cache entry - out of memory\n");
		return ERR_PTR(-ENOMEM);
	}

	ent->sl_cm_id = sl_cm_id;
	ent->slave_id = slave_id;
	ent->scheduled_delete = 0;
	ent->dev = to_mdev(ibdev);
	INIT_DELAYED_WORK(&ent->timeout, id_map_ent_timeout);

	do {
		spin_lock(&to_mdev(ibdev)->sriov.id_map_lock);
		ret = idr_get_new_above(&sriov->pv_id_table, ent,
					next_id, &id);
		if (!ret) {
			next_id = ((unsigned) id + 1) & MAX_ID_MASK;
			ent->pv_cm_id = (u32)id;
			TRACE("allocated pv_cm_id: 0x%x sl_cm_id: 0x%x\n",
					id, sl_cm_id);
			sl_id_map_add(ibdev, ent);
		} else {
			TRACE("Error allocating idr %d\n", ret);
		}

		spin_unlock(&sriov->id_map_lock);
	} while ( (ret == -EAGAIN) && idr_pre_get(&sriov->pv_id_table, GFP_KERNEL) );
	/*the function idr_get_new_above can return -ENOSPC, so don't insert in that case.*/
	if (!ret) {
		spin_lock(&sriov->id_map_lock);
		list_add_tail(&ent->list, &sriov->cm_list);
		spin_unlock(&sriov->id_map_lock);
		schedule_delayed(ibdev, ent);
		return ent;
	}
	/*error flow*/
	kfree(ent);
	mlx4_ib_warn(ibdev, "No more space in the idr (err:0x%x)\n", ret);
	return ERR_PTR(-ENOMEM);
}

static struct id_map_entry *
id_map_get(struct ib_device *ibdev, int *pv_cm_id, int sl_cm_id, int slave_id,
		 int sched_or_cancel)
{
        struct id_map_entry *ent;
	struct mlx4_ib_sriov *sriov = &to_mdev(ibdev)->sriov;

	spin_lock(&sriov->id_map_lock);
	if (*pv_cm_id == -1) {
		ent = id_map_find_by_sl_id(ibdev, sl_cm_id, slave_id);
		if (ent)
			*pv_cm_id = (int) ent->pv_cm_id;
	} else {
		ent = (struct id_map_entry *)idr_find(&sriov->pv_id_table, *pv_cm_id);
		if (ent) {
			TRACE("id[pv_cm_id: 0x%x] = {slave_id: %d, sl_cm_id: 0x%x}\n",
				*pv_cm_id, ent->slave_id, ent->sl_cm_id);
		} else {
			TRACE("No entry for pv_cm_id 0x%x\n", *pv_cm_id);
		}
	}
	if (ent && sched_or_cancel) {
		if (sched_or_cancel == ID_SCHED_DELETE) {
			if (!__try_reschedule(ent))
				ent = NULL;
		}
		if (sched_or_cancel == ID_CANCEL_DELETE) {
			if (cancel_delayed_work(&ent->timeout))
				ent->scheduled_delete = 0;
			else
				ent = NULL;
		}
	}
	spin_unlock(&sriov->id_map_lock);

	return ent;
}

int mlx4_ib_multiplex_cm_handler(struct ib_device *ibdev, int port, int slave_id,
		struct ib_mad *mad)
{
	struct id_map_entry *id;
	u32 sl_cm_id;
	int pv_cm_id = -1;

	TRACE("CM packet to send. type: %s\n",
			attr2str(mad->mad_hdr.attr_id));

	sl_cm_id = get_local_comm_id(mad);

	if (mad->mad_hdr.attr_id == CM_REQ_ATTR_ID ||
			mad->mad_hdr.attr_id == CM_REP_ATTR_ID) {
		id = id_map_get(ibdev, &pv_cm_id, slave_id, sl_cm_id,
				 ID_SCHED_DELETE);
		if (id)
			goto cont;
		id = id_map_alloc(ibdev, slave_id, sl_cm_id);
		if (IS_ERR(id)) {
			mlx4_ib_warn(ibdev, "%s: id{slave: %d, sl_cm_id: 0x%x} Failed to id_map_alloc\n",
				__func__, slave_id, sl_cm_id);
			return PTR_ERR(id);
		}
	} else if (mad->mad_hdr.attr_id == CM_REJ_ATTR_ID) {
		id = id_map_get(ibdev, &pv_cm_id, slave_id, sl_cm_id,
				 ID_SCHED_DELETE);
		return 0;
	} else {
		id = id_map_get(ibdev, &pv_cm_id, slave_id, sl_cm_id, 0);
	}

	if (!id) {
		mlx4_ib_dbg("id{slave: %d, sl_cm_id: 0x%x} is NULL!\n",
				slave_id, sl_cm_id);
		return -EINVAL;
	}

cont:
	set_local_comm_id(mad, id->pv_cm_id);

	if (mad->mad_hdr.attr_id == CM_DREQ_ATTR_ID) {
		//TRACE("Starting cm cleanup timeout\n");
		schedule_delayed(ibdev, id);
	} else if (mad->mad_hdr.attr_id == CM_DREP_ATTR_ID)
		id_map_find_del(ibdev, pv_cm_id);

	return 0;
}

int mlx4_ib_demux_cm_handler(struct ib_device *ibdev, int port, int *slave,
							     struct ib_mad *mad)
{
	u32 pv_cm_id;
	int gid_idx;
	int sched_or_cancel = 0;
	struct id_map_entry *id;

	TRACE("A CM packet arrived. type: %s\n",
			attr2str(mad->mad_hdr.attr_id));

	if (mad->mad_hdr.attr_id == CM_REQ_ATTR_ID) {
		union ib_gid gid;

		gid = gid_from_req_msg(ibdev, mad);
		gid_idx = mlx4_ib_find_real_gid(ibdev, port, gid.global.interface_id);
		//TRACE("Slave by gid is: %d\n", *slave);
		if (gid_idx < 0) {
			mlx4_ib_warn(ibdev, "failed matching gid index by gid (0x%llx)\n",
					gid.global.interface_id);
			return -ENOENT;
		}
		*slave = mlx4_gid_idx_to_slave(to_mdev(ibdev)->dev, gid_idx);
		return 0;
	}

	pv_cm_id = get_remote_comm_id(mad);
	//TRACE("pv_cm_id = 0x%x\n", pv_cm_id);
	if ((mad->mad_hdr.attr_id == CM_REP_ATTR_ID) ||
		(mad->mad_hdr.attr_id == CM_RTU_ATTR_ID)) {
		sched_or_cancel = ID_CANCEL_DELETE;
	}
	id = id_map_get(ibdev, (int *)&pv_cm_id, -1, -1, sched_or_cancel);

	if (!id) {
		mlx4_ib_dbg("Couldn't find an entry for pv_cm_id 0x%x\n", pv_cm_id);
		return -ENOENT;
	}

	*slave = id->slave_id;
	set_remote_comm_id(mad, id->sl_cm_id);
	TRACE("id[0x%x] = {slave: %d, sl_cm_id: 0x%x}\n",
			pv_cm_id, id->slave_id, id->sl_cm_id);

	if (mad->mad_hdr.attr_id == CM_DREQ_ATTR_ID ||
		mad->mad_hdr.attr_id == CM_REJ_ATTR_ID) {
		//TRACE("Starting cm cleanup timeout\n");
		schedule_delayed(ibdev, id);
	} else if (mad->mad_hdr.attr_id == CM_DREP_ATTR_ID) {
		id_map_find_del(ibdev, (int) pv_cm_id);
	}

	return 0;
}

void mlx4_ib_cm_paravirt_init(struct mlx4_ib_dev *dev)
{
	TRACE("%s\n", __func__);
	spin_lock_init(&dev->sriov.id_map_lock);
	INIT_LIST_HEAD(&dev->sriov.cm_list);
	dev->sriov.sl_id_map = RB_ROOT;
	idr_init(&dev->sriov.pv_id_table);
	idr_pre_get(&dev->sriov.pv_id_table, GFP_KERNEL);
}

/* slave = -1 ==> all slaves */
/* TBD -- call paravirt clean for single slave.  Need for slave RESET event */
void mlx4_ib_cm_paravirt_clean(struct mlx4_ib_dev *dev, int slave)
{
	struct mlx4_ib_sriov *sriov = &dev->sriov;
	struct rb_root *sl_id_map = &sriov->sl_id_map;
	struct list_head lh;
	struct rb_node *nd;
	int no_flush = 1;
	struct id_map_entry *map, *tmp_map;
	TRACE("%s\n", __func__);
	/* cancel all delayed work queue entries */
	INIT_LIST_HEAD(&lh);
	spin_lock(&sriov->id_map_lock);
	list_for_each_entry_safe(map, tmp_map, &dev->sriov.cm_list, list) {
		if (slave < 0 || slave == map->slave_id) {
			if (map->scheduled_delete)
				no_flush &= !!cancel_delayed_work(&map->timeout);
		}
	}

	spin_unlock(&sriov->id_map_lock);

	if (!no_flush)
		flush_scheduled_work(); /* make sure all timers were flushed */

	/* now, remove all leftover entries from databases*/
	spin_lock(&sriov->id_map_lock);
	if (slave < 0) {
		while (rb_first(sl_id_map)) {
			struct id_map_entry *ent =
				rb_entry(rb_first(sl_id_map),
					 struct id_map_entry, node);

			rb_erase(&ent->node, sl_id_map);
			idr_remove(&sriov->pv_id_table, (int) ent->pv_cm_id);
		}
		list_splice_init(&dev->sriov.cm_list, &lh);
	} else {
		/* first, move nodes belonging to slave to db remove list */
		nd = rb_first(sl_id_map);
		while (nd) {
			struct id_map_entry *ent =
				rb_entry(nd, struct id_map_entry, node);
			nd = rb_next(nd);
			if (ent->slave_id == slave)
				list_move_tail(&ent->list, &lh);
		}
		/* remove those nodes from databases */
		list_for_each_entry_safe(map, tmp_map, &lh, list) {
			rb_erase(&map->node, sl_id_map);
			idr_remove(&sriov->pv_id_table, (int) map->pv_cm_id);
		}

		/* add remaining nodes from cm_list */
		list_for_each_entry_safe(map, tmp_map, &dev->sriov.cm_list, list) {
			if (slave == map->slave_id)
				list_move_tail(&map->list, &lh);
		}
	}

	spin_unlock(&sriov->id_map_lock);

	/* free any map entries left behind due to cancel_delayed_work above */
	list_for_each_entry_safe(map, tmp_map, &lh, list) {
		list_del(&map->list);
		kfree(map);
	}
}

