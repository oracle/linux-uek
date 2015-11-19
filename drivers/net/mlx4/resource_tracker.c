/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005, 2006, 2007, 2008 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2005, 2006, 2007 Cisco Systems, Inc.  All rights reserved.
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

#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <asm/io.h>
#include <linux/mlx4/cmd.h>
#include <linux/mlx4/qp.h>

#include "mlx4.h"
#include "fw.h"
#include "fmr_master.h"
#include "fmr_slave.h"

/* For Debug uses */
static const char *ResourceType(enum mlx4_resource rt)
{
	switch (rt) {
	case RES_QP: return "RES_QP";
	case RES_CQ: return "RES_CQ";
	case RES_SRQ: return "RES_SRQ";
	case RES_MPT: return "RES_MPT";
	case RES_MTT: return "RES_MTT";
	case RES_MAC: return  "RES_MAC";
	case RES_EQ: return "RES_EQ";
	case RES_COUNTER: return "RES_COUNTER";
	case RES_XRCDN: return "RES_XRCDN";
	default: return "Unknown resource type !!!";
	};
}

int mlx4_init_resource_tracker(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int i;
	int t;

	priv->mfunc.master.res_tracker.slave_list =
		kzalloc(dev->num_slaves * sizeof (struct slave_list), GFP_KERNEL);
	if (!priv->mfunc.master.res_tracker.slave_list)
		return -ENOMEM;

	for (i = 0 ; i < dev->num_slaves; i++) {
		for (t = 0; t < MLX4_NUM_OF_RESOURCE_TYPE; ++t)
			INIT_LIST_HEAD(&priv->mfunc.master.res_tracker.slave_list[i].res_list[t]);
		mutex_init(&priv->mfunc.master.res_tracker.slave_list[i].mutex);
	}

	mlx4_dbg(dev, "Started init_resource_tracker: %ld slaves \n", dev->num_slaves);
	for (i = 0 ; i < MLX4_NUM_OF_RESOURCE_TYPE; i++)
		INIT_RADIX_TREE(&priv->mfunc.master.res_tracker.res_tree[i],
				GFP_ATOMIC|__GFP_NOWARN);

	spin_lock_init(&priv->mfunc.master.res_tracker.lock);
	return 0 ;
}

void mlx4_free_resource_tracker(struct mlx4_dev *dev)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	int i;

	if (priv->mfunc.master.res_tracker.slave_list) {
		for (i = 0 ; i < dev->num_slaves; i++)
			mlx4_delete_all_resources_for_slave(dev, i);

		kfree(priv->mfunc.master.res_tracker.slave_list);
	}
}

static void update_pkey_index(struct mlx4_dev *dev, int slave,
			      struct mlx4_cmd_mailbox *inbox)
{
	u8 sched = *(u8 *)(inbox->buf + 64);
	u8 orig_index = *(u8 *)(inbox->buf + 35);
	u8 new_index;
	struct mlx4_priv *priv = mlx4_priv(dev);
	int port;

	port = (sched >> 6 & 1) + 1;

	new_index = priv->virt2phys_pkey[slave][port - 1][orig_index];
	*(u8 *)(inbox->buf + 35) = new_index;

	mlx4_dbg(dev, "port = %d, orig pkey index = %d, "
		 "new pkey index = %d\n", port, orig_index, new_index);
}

static void update_ud_gid(struct mlx4_qp_context *qp_ctx, u8 slave)
{
	u32 ts = (be32_to_cpu(qp_ctx->flags) >> 16) & 0xff;

        if (MLX4_QP_ST_UD == ts)
		qp_ctx->pri_path.mgid_index = 0x80 | slave;

	mlx4_sdbg("slave %d, new gid index: 0x%x ",
		slave, qp_ctx->pri_path.mgid_index);
}

static int mpt_mask(struct mlx4_dev *dev)
{
	return dev->caps.num_mpts - 1;
}

static void *find_res(struct mlx4_dev *dev, int res_id,
		      enum mlx4_resource type)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	return radix_tree_lookup(&priv->mfunc.master.res_tracker.res_tree[type],
				 res_id);
}

static int get_res(struct mlx4_dev *dev, int slave, int res_id, enum mlx4_resource type,
		   void *res)
{
        struct res_common *r;
	int err = 0;

	spin_lock_irq(mlx4_tlock(dev));
	r = find_res(dev, res_id, type);
	if (!r) {
		err = -ENONET;
		goto exit;
	}

	if (r->state == RES_ANY_BUSY) {
		err = -EBUSY;
		goto exit;
	}

	if (r->owner != slave) {
		err = -EPERM;
		goto exit;
	}

	r->from_state = r->state;
	r->state = RES_ANY_BUSY;
	mlx4_sdbg("res %s id 0x%x to busy\n", ResourceType(type), r->res_id);

	if (res)
		*((struct res_common **)res) = r;

exit:
	spin_unlock_irq(mlx4_tlock(dev));
	return err;
}

#if 0
static void __put_res(struct mlx4_dev *dev, int slave, void *_r)
{
	struct res_common *r = _r;
	spin_lock_irq(mlx4_tlock(dev));
	mlx4_sdbg("move back id 0x%x from %d to %d\n",
		  r->res_id, r->state, r->from_state);
	r->state = r->from_state;
	spin_unlock_irq(mlx4_tlock(dev));
}
#endif

int mlx4_get_slave_from_resource_id(struct mlx4_dev *dev,
				    enum mlx4_resource type,
				    int res_id, int *slave)
{

	struct res_common *r;
	int err = -ENOENT;
	int id = res_id;
	unsigned long flags;

	if (type == RES_QP)
		id &= 0x7fffff;
	spin_lock_irqsave(mlx4_tlock(dev), flags);

	r = find_res(dev, id, type);
	if (r) {
		*slave = r->owner;
		err = 0;
	}
	spin_unlock_irqrestore(mlx4_tlock(dev), flags);

	return err;
}

static void put_res(struct mlx4_dev *dev, int slave, int res_id, enum mlx4_resource type)
{
        struct res_common *r;

	spin_lock_irq(mlx4_tlock(dev));
	r = find_res(dev, res_id, type);
	SASSERT(r);
	mlx4_sdbg("move back %s id 0x%x from %d to %d\n",
		  ResourceType(type), r->res_id, r->state, r->from_state);
	r->state = r->from_state;
	spin_unlock_irq(mlx4_tlock(dev));
}

static struct res_common *alloc_qp_tr(int id)
{
	struct res_qp *ret;

	ret = kzalloc(sizeof *ret, GFP_KERNEL);
	if (!ret)
		return NULL;

	ret->com.res_id = id;
	ret->com.state = RES_QP_RESERVED;
	INIT_LIST_HEAD(&ret->mcg_list);
	spin_lock_init(&ret->mcg_spl);

	return &ret->com;
}

static struct res_common *alloc_mtt_tr(int id, int order)
{
	struct res_mtt *ret;

	ret = kzalloc(sizeof *ret, GFP_KERNEL);
	if (!ret)
		return NULL;

	ret->com.res_id = id;
	ret->order = order;
	ret->com.state = RES_MTT_RESERVED;
	atomic_set(&ret->ref_count, 0);

	return &ret->com;
}

static struct res_common *alloc_mpt_tr(int id, int key,
				       enum mlx4_mr_flags flags)
{
	struct res_mpt *ret;

	ret = kzalloc(sizeof *ret, GFP_KERNEL);
	if (!ret)
		return NULL;

	ret->com.res_id = id;
	ret->com.state = RES_MPT_RESERVED;
	ret->key = key;
	ret->flags = flags;

	return &ret->com;
}

static struct res_common *alloc_eq_tr(int id)
{
	struct res_eq *ret;

	ret = kzalloc(sizeof *ret, GFP_KERNEL);
	if (!ret)
		return NULL;

	ret->com.res_id = id;
	ret->com.state = RES_EQ_RESERVED;

	return &ret->com;
}

static struct res_common *alloc_cq_tr(int id)
{
	struct res_cq *ret;

	ret = kzalloc(sizeof *ret, GFP_KERNEL);
	if (!ret)
		return NULL;

	ret->com.res_id = id;
	ret->com.state = RES_CQ_ALLOCATED;
	atomic_set(&ret->ref_count, 0);

	return &ret->com;
}

static struct res_common *alloc_srq_tr(int id)
{
	struct res_srq *ret;

	ret = kzalloc(sizeof *ret, GFP_KERNEL);
	if (!ret)
		return NULL;

	ret->com.res_id = id;
	ret->com.state = RES_SRQ_ALLOCATED;
	atomic_set(&ret->ref_count, 0);

	return &ret->com;
}

static struct res_common *alloc_counter_tr(int id)
{
	struct res_counter *ret;

	ret = kzalloc(sizeof *ret, GFP_KERNEL);
	if (!ret)
		return NULL;

	ret->com.res_id = id;
	ret->com.state = RES_COUNTER_ALLOCATED;

	return &ret->com;
}

static struct res_common *alloc_xrcdn_tr(int id)
{
	struct res_xrcdn *ret;

	ret = kzalloc(sizeof *ret, GFP_KERNEL);
	if (!ret)
		return NULL;

	ret->com.res_id = id;
	ret->com.state = RES_XRCDN_ALLOCATED;

	return &ret->com;
}

static struct res_common *alloc_tr(int id, enum mlx4_resource type, int slave,
				   int extra, int extra2)
{
	struct res_common *ret;

	switch (type) {
	case RES_QP:
		ret = alloc_qp_tr(id);
		break;
	case RES_MPT:
		ret = alloc_mpt_tr(id, extra, extra2);
		break;
	case RES_MTT:
		ret = alloc_mtt_tr(id, extra);
		break;
	case RES_EQ:
		ret = alloc_eq_tr(id);
		break;
	case RES_CQ:
		ret = alloc_cq_tr(id);
		break;
	case RES_SRQ:
		ret = alloc_srq_tr(id);
		break;
	case RES_MAC:
		printk(KERN_ERR "implementation missing\n");
		return NULL;
	case RES_COUNTER:
		ret = alloc_counter_tr(id);
		break;
	case RES_XRCDN:
		ret = alloc_xrcdn_tr(id);
		break;

	default:
		return NULL;
	}
	if (ret)
		ret->owner = slave;

	return ret;
}

static int add_res_range(struct mlx4_dev *dev, int slave, int base, int count,
			 enum mlx4_resource type, int extra, int extra2)
{
	int i;
	int err;
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct res_common **res_arr;
	struct mlx4_resource_tracker *tracker = &priv->mfunc.master.res_tracker;
	struct radix_tree_root *root = &tracker->res_tree[type];

	res_arr = kzalloc(count * sizeof *res_arr, GFP_KERNEL);
	if (!res_arr)
		return -ENOMEM;

	for (i = 0; i < count; ++i) {
		res_arr[i] = alloc_tr(base + i, type, slave, extra, extra2);
		if (!res_arr[i]) {
			for (--i; i >= 0; --i)
				kfree(res_arr[i]);

			kfree(res_arr);
			return -ENOMEM;
		}
	}

	spin_lock_irq(mlx4_tlock(dev));
	for (i = 0; i < count; ++i) {
		if (find_res(dev, base + i, type)) {
			err = -EEXIST;
			goto undo;
		}
		err = radix_tree_insert(root, base + i, res_arr[i]);
		if (err)
			goto undo;
		list_add_tail(&res_arr[i]->list, &tracker->slave_list[slave].res_list[type]);
	}
	spin_unlock_irq(mlx4_tlock(dev));
	kfree(res_arr);

	return 0;

undo:
	for (--i; i >= base; --i)
		radix_tree_delete(&tracker->res_tree[type], i);

	spin_unlock_irq(mlx4_tlock(dev));

	for (i = 0; i < count; ++i)
		kfree(res_arr[i]);

	kfree(res_arr);

	return err;
}

static int remove_qp_ok(struct res_qp *res)
{
	if (res->com.state == RES_QP_BUSY)
		return -EBUSY;
	else if (res->com.state != RES_QP_RESERVED)
		return -EPERM;

	return 0;
}

static int remove_mtt_ok(struct res_mtt *res, int order)
{
	if (res->com.state == RES_MTT_BUSY || atomic_read(&res->ref_count)) {
		printk(KERN_DEBUG "%s-%d: state %s, ref_count %d\n", __func__, __LINE__,
			  mtt_states_str(res->com.state), atomic_read(&res->ref_count));
		return -EBUSY;
	} else if (res->com.state != RES_MTT_ALLOCATED &&
		   res->com.state != RES_MTT_RESERVED)
		return -EPERM;
	else if (res->order != order)
		return -EINVAL;

	return 0;
}

static int remove_mpt_ok(struct res_mpt *res)
{
	if (res->com.state == RES_MPT_BUSY)
		return -EBUSY;
	else if (res->com.state != RES_MPT_RESERVED)
		return -EPERM;

	return 0;
}

static int remove_eq_ok(struct res_eq *res)
{
	if (res->com.state == RES_MPT_BUSY)
		return -EBUSY;
	else if (res->com.state != RES_MPT_RESERVED)
		return -EPERM;

	return 0;
}

static int remove_counter_ok(struct res_counter *res)
{
	if (res->com.state == RES_COUNTER_BUSY)
		return -EBUSY;
	else if (res->com.state != RES_COUNTER_ALLOCATED)
		return -EPERM;

	return 0;
}

static int remove_xrcdn_ok(struct res_xrcdn *res)
{
	if (res->com.state == RES_XRCDN_BUSY)
		return -EBUSY;
	else if (res->com.state != RES_XRCDN_ALLOCATED)
		return -EPERM;

	return 0;
}

static int remove_cq_ok(struct res_cq *res)
{
	if (res->com.state == RES_CQ_BUSY)
		return -EBUSY;
	else if (res->com.state != RES_CQ_ALLOCATED)
		return -EPERM;

	return 0;
}

static int remove_srq_ok(struct res_srq *res)
{
	if (res->com.state == RES_SRQ_BUSY)
		return -EBUSY;
	else if (res->com.state != RES_SRQ_ALLOCATED)
		return -EPERM;

	return 0;
}

static int remove_ok(struct res_common *res, enum mlx4_resource type, int extra)
{
	switch (type) {
	case RES_QP:
		return remove_qp_ok((struct res_qp *)res);
	case RES_CQ:
		return remove_cq_ok((struct res_cq *)res);
	case RES_SRQ:
		return remove_srq_ok((struct res_srq *)res);
	case RES_MPT:
		return remove_mpt_ok((struct res_mpt *)res);
	case RES_MTT:
		return remove_mtt_ok((struct res_mtt *)res, extra);
	case RES_MAC:
		return -ENOSYS;
	case RES_EQ:
		return remove_eq_ok((struct res_eq *)res);
	case RES_COUNTER:
		return remove_counter_ok((struct res_counter *)res);
	case RES_XRCDN:
		return remove_xrcdn_ok((struct res_xrcdn *)res);
	default:
		return -EINVAL;
	}
}

static int rem_res_range(struct mlx4_dev *dev, int slave, int base, int count,
			 enum mlx4_resource type, int extra)
{
	int i;
	int err;
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_resource_tracker *tracker = &priv->mfunc.master.res_tracker;
	struct res_common *r;

	spin_lock_irq(mlx4_tlock(dev));
	for (i = base; i < base + count; ++i) {
		r = radix_tree_lookup(&tracker->res_tree[type], i);
		if (!r) {
			err = -ENOENT;
			goto out;
		}
		if (r->owner != slave) {
			err = -EPERM;
			goto out;
		}
		if ((err = remove_ok(r, type, extra)))
			goto out;
	}

	for (i = base; i < base + count; ++i) {
		r = radix_tree_lookup(&tracker->res_tree[type], i);
		radix_tree_delete(&tracker->res_tree[type], i);
		list_del(&r->list);
		kfree(r);
	}
	err = 0;

out:
	spin_unlock_irq(mlx4_tlock(dev));

	return err;
}

static int qp_res_start_move_to(struct mlx4_dev *dev, int slave, int qpn,
				enum res_qp_states state, struct res_qp **qp, int alloc)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_resource_tracker *tracker = &priv->mfunc.master.res_tracker;
	struct res_qp *r;
	int err = 0;

	spin_lock_irq(mlx4_tlock(dev));
	r = radix_tree_lookup(&tracker->res_tree[RES_QP], qpn);
	if (!r)
		err = -ENOENT;
	else if (r->com.owner != slave)
		err = -EPERM;
	else {
		switch (state) {
		case RES_QP_BUSY:
			mlx4_sdbg("failed RES_QP, 0x%x\n", r->com.res_id);
			err = -EBUSY;
			break;

		case RES_QP_RESERVED:
			if (r->com.state == RES_QP_MAPPED && !alloc)
				break;

			mlx4_sdbg("failed RES_QP, 0x%x\n", r->com.res_id);
			err = -EINVAL;
			break;

		case RES_QP_MAPPED:
			if ((r->com.state == RES_QP_RESERVED && alloc) ||
			    r->com.state == RES_QP_HW)
				break;
			else {
				mlx4_sdbg("failed RES_QP, 0x%x\n", r->com.res_id);
				err = -EINVAL;
			}

			break;

		case RES_QP_HW:
			if (r->com.state != RES_QP_MAPPED) {
				mlx4_sdbg("failed RES_QP, 0x%x\n", r->com.res_id);
				err = -EINVAL;
			}
			break;
		default:
			mlx4_sdbg("failed RES_QP, 0x%x\n", r->com.res_id);
			err = -EINVAL;
		}

		if (!err) {
			r->com.from_state = r->com.state;
			r->com.to_state = state;
			r->com.state = RES_QP_BUSY;
			mlx4_sdbg("move to %s from %s qpn 0x%x\n", qp_states_str(state),
				  qp_states_str(r->com.from_state), r->com.res_id);
			if (qp)
				*qp = (struct res_qp *)r;
		}
	}

	spin_unlock_irq(mlx4_tlock(dev));

	return err;
}

static int mtt_res_start_move_to(struct mlx4_dev *dev, int slave, int index,
				 enum res_mtt_states state) {
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_resource_tracker *tracker =
			&priv->mfunc.master.res_tracker;
	struct res_mtt *r;
	int err = 0;

	spin_lock_irq(mlx4_tlock(dev));
	r = radix_tree_lookup(&tracker->res_tree[RES_MTT], index);
	if (!r)
		err = -ENOENT;
	else if (r->com.owner != slave)
		err = -EPERM;
	else {
		switch (state) {
		case RES_MTT_BUSY:
			err = -EINVAL;
			break;

		case RES_MTT_RESERVED:
			if (r->com.state != RES_MTT_ALLOCATED)
				err = -EINVAL;
			break;

		case RES_MTT_ALLOCATED:
			if (r->com.state != RES_MTT_RESERVED)
				err = -EINVAL;
			break;

		default:
			 err = -EINVAL;
		}
	}

	if (!err) {
		r->com.from_state = r->com.state;
		r->com.to_state = state;
		r->com.state = RES_MTT_BUSY;
	}

	spin_unlock_irq(mlx4_tlock(dev));

	return err;
}

static int mr_res_start_move_to(struct mlx4_dev *dev, int slave, int index,
				enum res_mpt_states state, struct res_mpt **mpt)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_resource_tracker *tracker = &priv->mfunc.master.res_tracker;
	struct res_mpt *r;
	int err = 0;

	spin_lock_irq(mlx4_tlock(dev));
	r = radix_tree_lookup(&tracker->res_tree[RES_MPT], index);
	if (!r)
		err = -ENOENT;
	else if (r->com.owner != slave)
		err = -EPERM;
	else {
		switch (state) {
		case RES_MPT_BUSY:
			err = -EINVAL;
			break;

		case RES_MPT_RESERVED:
			if (r->com.state != RES_MPT_MAPPED)
				err = -EINVAL;
			break;

		case RES_MPT_MAPPED:
			if (r->com.state != RES_MPT_RESERVED && r->com.state != RES_MPT_HW)
				err = -EINVAL;
			break;

		case RES_MPT_HW:
			if (r->com.state != RES_MPT_MAPPED)
				err = -EINVAL;
			break;
		default:
			err = -EINVAL;
		}

		if (!err) {
			r->com.from_state = r->com.state;
			r->com.to_state = state;
			r->com.state = RES_MPT_BUSY;
			if (mpt)
				*mpt = (struct res_mpt *)r;
		}
	}

	spin_unlock_irq(mlx4_tlock(dev));

	return err;
}

static int eq_res_start_move_to(struct mlx4_dev *dev, int slave, int index,
				enum res_eq_states state, struct res_eq **eq)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_resource_tracker *tracker = &priv->mfunc.master.res_tracker;
	struct res_eq *r;
	int err = 0;

	spin_lock_irq(mlx4_tlock(dev));
	r = radix_tree_lookup(&tracker->res_tree[RES_EQ], index);
	if (!r)
		err = -ENOENT;
	else if (r->com.owner != slave) {
		mlx4_sdbg("EQ res_id 0x%x belongs to slave %d\n", r->com.res_id, r->com.owner);
		err = -EPERM;
	} else {
		switch (state) {
		case RES_EQ_BUSY:
			err = -EINVAL;
			break;

		case RES_EQ_RESERVED:
			if (r->com.state != RES_EQ_HW)
				err = -EINVAL;
			break;

		case RES_EQ_HW:
			if (r->com.state != RES_EQ_RESERVED)
				err = -EINVAL;
			break;

		default:
			err = -EINVAL;
		}

		if (!err) {
			r->com.from_state = r->com.state;
			r->com.to_state = state;
			r->com.state = RES_EQ_BUSY;
			if (eq)
				*eq = r;
		}
	}

	spin_unlock_irq(mlx4_tlock(dev));

	return err;
}

static int cq_res_start_move_to(struct mlx4_dev *dev, int slave, int cqn,
				enum res_cq_states state, struct res_cq **cq)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_resource_tracker *tracker = &priv->mfunc.master.res_tracker;
	struct res_cq *r;
	int err;

	spin_lock_irq(mlx4_tlock(dev));
	r = radix_tree_lookup(&tracker->res_tree[RES_CQ], cqn);
	if (!r)
		err = -ENOENT;
	else if (r->com.owner != slave)
		err = -EPERM;
	else {
		switch (state) {
		case RES_CQ_BUSY:
			mlx4_sdbg("CQ 0x%x, ref count %d\n", r->com.res_id, atomic_read(&r->ref_count));
			err = -EBUSY;
			break;

		case RES_CQ_ALLOCATED:
			if (r->com.state != RES_CQ_HW)
				err = -EINVAL;
			else if (atomic_read(&r->ref_count)) {
				mlx4_sdbg("CQ 0x%x, ref count %d\n", r->com.res_id, atomic_read(&r->ref_count));
					  err = -EBUSY;
			}
			else
				err = 0;
			break;

		case RES_CQ_HW:
			if (r->com.state != RES_CQ_ALLOCATED)
				err = -EINVAL;
			else
				err = 0;
			break;

		default:
			err = -EINVAL;
		}

		if (!err) {
			r->com.from_state = r->com.state;
			r->com.to_state = state;
			r->com.state = RES_CQ_BUSY;
			if (cq)
				*cq = r;
		}
	}

	spin_unlock_irq(mlx4_tlock(dev));

	return err;
}

static int srq_res_start_move_to(struct mlx4_dev *dev, int slave, int index,
				 enum res_cq_states state, struct res_srq **srq)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_resource_tracker *tracker = &priv->mfunc.master.res_tracker;
	struct res_srq *r;
	int err = 0;

	spin_lock_irq(mlx4_tlock(dev));
	r = radix_tree_lookup(&tracker->res_tree[RES_SRQ], index);
	if (!r)
		err = -ENOENT;
	else if (r->com.owner != slave)
		err = -EPERM;
	else {
		switch (state) {
		case RES_SRQ_BUSY:
			err = -EINVAL;
			break;

		case RES_SRQ_ALLOCATED:
			if (r->com.state != RES_SRQ_HW)
				err = -EINVAL;
			else if (atomic_read(&r->ref_count))
				err = -EBUSY;
			break;

		case RES_SRQ_HW:
			if (r->com.state != RES_SRQ_ALLOCATED)
				err = -EINVAL;
			break;

		default:
			err = -EINVAL;
		}

		if (!err) {
			r->com.from_state = r->com.state;
			r->com.to_state = state;
			r->com.state = RES_SRQ_BUSY;
			if (srq)
				*srq = r;
		}
	}

	spin_unlock_irq(mlx4_tlock(dev));

	return err;
}

static void res_abort_move(struct mlx4_dev *dev, int slave,
			   enum mlx4_resource type, int id)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_resource_tracker *tracker = &priv->mfunc.master.res_tracker;
	struct res_common *r;

	spin_lock_irq(mlx4_tlock(dev));
	r = radix_tree_lookup(&tracker->res_tree[type], id);
	SASSERT(r && (r->owner == slave));
	r->state = r->from_state;
	spin_unlock_irq(mlx4_tlock(dev));
}

static void res_end_move(struct mlx4_dev *dev, int slave,
			 enum mlx4_resource type, int id)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_resource_tracker *tracker = &priv->mfunc.master.res_tracker;
	struct res_common *r;

	spin_lock_irq(mlx4_tlock(dev));
	r = radix_tree_lookup(&tracker->res_tree[type], id);
	SASSERT(r && (r->owner == slave));
	if (!(r && (r->owner == slave)))
		mlx4_sdbg("r %p, resource %s, owner %d, id 0x%x\n", r, ResourceType(type), r->owner, id);
	r->state = r->to_state;
	mlx4_sdbg("%s, id 0x%x, completed move from %d to %d\n",
		  ResourceType(type), r->res_id, r->from_state, r->to_state);
	spin_unlock_irq(mlx4_tlock(dev));
}

static int valid_reserved(struct mlx4_dev *dev, int slave, int qpn)
{
	return mlx4_is_qp_reserved(dev, qpn) && (dev->caps.sqp_demux || mlx4_is_guest_proxy(dev, slave, qpn));
}

static int fw_reserved(struct mlx4_dev *dev, int qpn)
{
	return qpn < dev->caps.reserved_qps_cnt[MLX4_QP_REGION_FW];
}

static int qp_alloc_res(struct mlx4_dev *dev, int slave, int op, int cmd,
			u64 in_param, u64 *out_param)
{
	int err;
	int count;
	int align;
	int base;
	int qpn;

	switch (op) {
	case RES_OP_RESERVE:
		mlx4_sdbg("\n");
		count = get_param_l(&in_param);
		align = get_param_h(&in_param);
		err = __mlx4_qp_reserve_range(dev, count, align, &base);
		if (err) {
			mlx4_sdbg("failed allocating : count %d, align %d\n", count, align);
			return err;
		}

		err = add_res_range(dev, slave, base, count, RES_QP, 0, 0);
		if (err) {
			mlx4_sdbg("failed adding resource range: base 0x%x, count %d\n", base, count);
			__mlx4_qp_release_range(dev, base, count);
			return err;
		}
		set_param_l(out_param, base);
		mlx4_sdbg("success adding: count %d, base 0x%x\n", count, base);
		break;
	case RES_OP_MAP_ICM:
		mlx4_sdbg("\n");
		qpn = get_param_l(&in_param) & 0x7fffff;

		mlx4_sdbg("qpn 0x%x, orig 0x%x, valid_reserved %d\n", qpn, get_param_l(&in_param), valid_reserved(dev, slave, qpn));
		if (valid_reserved(dev, slave, qpn)) {
			err = add_res_range(dev, slave, qpn, 1, RES_QP, 0, 0);
			if (err)
				return err;
		}

		err = qp_res_start_move_to(dev, slave, qpn, RES_QP_MAPPED, NULL, 1);
		if (err) {
			mlx4_sdbg("failed moving qpn 0x%x to %s. err %d\n",
				  qpn, qp_states_str(RES_QP_MAPPED), err);
			SASSERT(!valid_reserved(dev, slave, qpn));
			return err;
		}

		if (!fw_reserved(dev, qpn)) {
			err = __mlx4_qp_alloc_icm(dev, qpn, GFP_KERNEL);
			if (err) {
				res_abort_move(dev, slave, RES_QP, qpn);
				return err;
			}
		}

		res_end_move(dev, slave, RES_QP, qpn);
		break;

	default:
		err = -EINVAL;
		break;
	}
	return err;
}

static int mtt_alloc_res(struct mlx4_dev *dev, int slave, int op, int cmd,
			 u64 in_param, u64 *out_param)
{
	int err = -EINVAL;
	int base;
	int order;

	if (op != RES_OP_RESERVE_AND_MAP && op != RES_OP_RESERVE) {
		mlx4_sdbg("invalid opcode %d\n", op);
		return err;
	}

	order = get_param_l(&in_param);
	base = (op == RES_OP_RESERVE) ?
	       __mlx4_reserve_mtt_range(dev, order) :
	       __mlx4_alloc_mtt_range(dev, order, MLX4_MR_FLAG_NONE);

	if (base == 0xFFFFFFFF) {
		mlx4_sdbg("failed allocating order %d segments\n", order);
		return -ENOMEM;
	}

	err = add_res_range(dev, slave, base, 1, RES_MTT, order, 0);
	if (err) {
		mlx4_sdbg("mtt_alloc_res add res range failed\n");
		goto err_mtt_free;
	}

	if (op == RES_OP_RESERVE_AND_MAP) {
		err = mtt_res_start_move_to(dev, slave, base,
					    RES_MTT_ALLOCATED);
		if (err)
			goto err_rem_res;

		res_end_move(dev, slave, RES_MTT, base);
	}

	set_param_l(out_param, base);
	mlx4_sdbg("alloc mtt: base 0x%x, order %d, reserve only %d\n", base,
		  order, op == RES_OP_RESERVE);

	return 0;

err_rem_res:
	err = rem_res_range(dev, slave, base, 1, RES_MTT, order);
err_mtt_free:
	__mlx4_free_mtt_range(dev, base, order, MLX4_MR_FLAG_NONE);
	return err;
}

static int verify_fmr_index(struct mlx4_dev *dev, int index, int slave)
{
	int size = dev->caps.fmr_num_mpts;
	int base = dev->caps.fmr_dmpt_base_idx + slave * size;


	if (index < base || index >= base + size)
		return -EINVAL;

	return	0;
}

static int mpt_alloc_res(struct mlx4_dev *dev, int slave, int op, int cmd,
			 u64 in_param, u64 *out_param)
{
	int err = -EINVAL;
	int index;
	int id;
	struct res_mpt *mpt;
	enum mlx4_mr_flags flags;
	int fmr_flow;

	switch (op) {
	case RES_OP_RESERVE:
		mlx4_sdbg("\n");
		flags = get_param_h(&in_param);
		fmr_flow = mlx4_fmr_flow(dev, flags);
		if (fmr_flow) {
			index = get_param_l(&in_param);
			mlx4_sdbg("reserve fmr mpt index 0x%x\n", index);
			if (verify_fmr_index(dev, index, slave)) {
				mlx4_sdbg("verify_fmr_index failed, 0x%x\n",
					  index);
				index = -1;
			}
		} else
			index = __mlx4_mr_reserve(dev);
		if (index == -1) {
			mlx4_sdbg("failed reserving a MR index, 0x%x\n", index);
			break;
		}
		id = index & mpt_mask(dev);
		mlx4_sdbg("alloc mpt index 0x%x, id 0x%x, fmr_flow %d\n",
			  index, id, fmr_flow);

		err = add_res_range(dev, slave, id, 1, RES_MPT, index, flags);
		if (err) {
			mlx4_sdbg("failed adding MPT to tracker: id 0x%x\n", id);
			if (!fmr_flow)
				__mlx4_mr_release(dev, index);
			break;
		}
		set_param_l(out_param, index);
		mlx4_sdbg("allocated mpt index 0x%x, flags %d\n", index, flags);
		break;
	case RES_OP_MAP_ICM:
		index = get_param_l(&in_param);
		id = index & mpt_mask(dev);
		mlx4_sdbg("mpt map index 0x%x, id 0x%x\n", index, id);

		err = mr_res_start_move_to(dev, slave, id, RES_MPT_MAPPED, &mpt);
		if (err) {
			mlx4_sdbg("failed moving MPT id 0x%x to RES_MPT_MAPPED. err %d\n",
				  id, err);
			return err;
		}

		fmr_flow = mlx4_fmr_flow(dev, mpt->flags);
		mlx4_sdbg("mpt map index %d, fmr flow %d\n", index, id);
		if (!fmr_flow) {
			err = __mlx4_mr_alloc_icm(dev, mpt->key,
						  MLX4_MR_FLAG_NONE);
			if (err) {
				res_abort_move(dev, slave, RES_MPT, id);
				return err;
			}
		}

		res_end_move(dev, slave, RES_MPT, id);
		break;
	}
	return err;
}

static int cq_alloc_res(struct mlx4_dev *dev, int slave, int op, int cmd,
			u64 in_param, u64 *out_param)
{
	int cqn;
	int err;

	switch (op) {
	case RES_OP_RESERVE_AND_MAP:
		err = __mlx4_cq_alloc_icm(dev, &cqn);
		if (err)
			break;

		err = add_res_range(dev, slave, cqn, 1, RES_CQ, 0, 0);
		SASSERT(!err && err != -ENOMEM);
		if (err) {
			__mlx4_cq_free_icm(dev, cqn);
			break;
		}

		set_param_l(out_param, cqn);
		break;

	default:
		err = -EINVAL;
	}

	return err;
}

static int srq_alloc_res(struct mlx4_dev *dev, int slave, int op, int cmd,
			 u64 in_param, u64 *out_param)
{
	int srqn;
	int err;

	mlx4_sdbg("\n");
	switch (op) {
	case RES_OP_RESERVE_AND_MAP:
		mlx4_sdbg("\n");
		err = __mlx4_srq_alloc_icm(dev, &srqn);
		if (err)
			break;

		mlx4_sdbg("srqn 0x%x\n", srqn);
		err = add_res_range(dev, slave, srqn, 1, RES_SRQ, 0, 0);
		SASSERT(!err || (err == -ENOMEM));
		if (err) {
			__mlx4_srq_free_icm(dev, srqn);
			mlx4_sdbg("srqn 0x%x\n", srqn);
			break;
		}

		mlx4_sdbg("srqn 0x%x allocated number and ICM mapped\n", srqn);
		set_param_l(out_param, srqn);
		break;

	default:
		err = -EINVAL;
	}

	return err;
}

static int counter_alloc_res(struct mlx4_dev *dev, int slave, int op, int cmd,
			     u64 in_param, u64 *out_param)
{
	int index;
	int err;

	if (op != RES_OP_RESERVE)
		return -EINVAL;

	err = __mlx4_counter_alloc(dev, &index);
	if (err)
		return err;

	err = add_res_range(dev, slave, index, 1, RES_COUNTER, 0, 0);
	if (err)
		__mlx4_counter_free(dev, index);
	else
		set_param_l(out_param, index);

	mlx4_sdbg("counter index %d, err %d\n", index, err);
	return err;
}

static int xrcdn_alloc_res(struct mlx4_dev *dev, int slave, int op, int cmd,
			   u64 in_param, u64 *out_param)
{
	int xrcdn;
	int err;

	if (op != RES_OP_RESERVE)
		return -EINVAL;

	err = __mlx4_xrcd_alloc(dev, &xrcdn);
	if (err)
		return err;

	err = add_res_range(dev, slave, xrcdn, 1, RES_XRCDN, 0, 0);
	if (err)
		__mlx4_xrcd_free(dev, xrcdn);
	else
		set_param_l(out_param, xrcdn);

	return err;
}

int mlx4_ALLOC_RES_wrapper(struct mlx4_dev *dev, int slave,
			   struct mlx4_vhcr *vhcr,
			   struct mlx4_cmd_mailbox *inbox,
			   struct mlx4_cmd_mailbox *outbox,
			   struct mlx4_cmd_info *cmd)
{
	int err;
	int alop = vhcr->op_modifier;

	switch (vhcr->in_modifier) {
	case RES_QP:
		err = qp_alloc_res(dev, slave, vhcr->op_modifier, alop,
				   vhcr->in_param, &vhcr->out_param);
		break;

	case RES_MTT:
		err = mtt_alloc_res(dev, slave, vhcr->op_modifier, alop,
				    vhcr->in_param, &vhcr->out_param);
		break;

	case RES_MPT:
		err = mpt_alloc_res(dev, slave, vhcr->op_modifier, alop,
				    vhcr->in_param, &vhcr->out_param);
		break;

	case RES_CQ:
		err = cq_alloc_res(dev, slave, vhcr->op_modifier, alop,
				   vhcr->in_param, &vhcr->out_param);
		break;

	case RES_SRQ:
		err = srq_alloc_res(dev, slave, vhcr->op_modifier, alop,
				    vhcr->in_param, &vhcr->out_param);
		break;

	case RES_COUNTER:
		err = counter_alloc_res(dev, slave, vhcr->op_modifier, alop,
					vhcr->in_param, &vhcr->out_param);
		break;

	case RES_XRCDN:
		err = xrcdn_alloc_res(dev, slave, vhcr->op_modifier, alop,
				      vhcr->in_param, &vhcr->out_param);
		break;

	default:
		err = -EINVAL;
		break;
	}

	if (err)
		mlx4_sdbg("resoruce %s, op %d\n",
			  ResourceType(vhcr->in_modifier), alop);

	return err;
}

static int qp_free_res(struct mlx4_dev *dev, int slave, int op, int cmd,
		       u64 in_param)
{
	int err;
	int count;
	int base;
	int qpn;

	switch (op) {
	case RES_OP_RESERVE:
		mlx4_sdbg("\n");
		base = get_param_l(&in_param) & 0x7fffff;
		count = get_param_h(&in_param);
		err = rem_res_range(dev, slave, base, count, RES_QP, 0);
		if (err) {
			mlx4_sdbg("failed removing resource range, base 0x%x, count %d\n",
				  base, count);
			break;
		}
		__mlx4_qp_release_range(dev, base, count);
		mlx4_sdbg("success removing: base 0x%x, count %d\n", base, count);
		break;
	case RES_OP_MAP_ICM:
		mlx4_sdbg("\n");
		qpn = get_param_l(&in_param) & 0x7fffff;
		err = qp_res_start_move_to(dev, slave, qpn, RES_QP_RESERVED, NULL, 0);
		if (err) {
			mlx4_sdbg("failed moving qpn 0x%x to %s. err %d\n",
				  qpn, qp_states_str(RES_QP_RESERVED), err);
			return err;
		}

		if (!fw_reserved(dev, qpn))
			__mlx4_qp_free_icm(dev, qpn);

		res_end_move(dev, slave, RES_QP, qpn);

                if (valid_reserved(dev, slave, qpn)) {
			err = rem_res_range(dev, slave, qpn, 1, RES_QP, 0);
			SASSERT(!err);
		}
		break;
	default:
		err = -EINVAL;
		break;
	}
	return err;
}

static int mtt_free_res(struct mlx4_dev *dev, int slave, int op, int cmd,
			u64 in_param, u64 *out_param)
{
	int err = -EINVAL;
	int base;
	int order;

	mlx4_sdbg("\n");
	if (op != RES_OP_RESERVE_AND_MAP && op != RES_OP_RESERVE) {
		mlx4_sdbg("invalid opcode %d\n", op);
		return err;
	}

	mlx4_sdbg("\n");
	base = get_param_l(&in_param);
	order = get_param_h(&in_param);
	err = rem_res_range(dev, slave, base, 1, RES_MTT, order);
	if (err)
		return err;

	if (op == RES_OP_RESERVE_AND_MAP)
		__mlx4_free_mtt_range(dev, base, order, MLX4_MR_FLAG_NONE);
	else /* op == RES_OP_RESERVE */
		__mlx4_free_mtt_reserved_range(dev, base, order);

	if (!err)
		mlx4_sdbg("base 0x%x, order %d\n", base, order);
	else
		mlx4_sdbg("base 0x%x, order %d, err %d\n", base, order, err);

	return err;
}

static int mpt_free_res(struct mlx4_dev *dev, int slave, int op, int cmd,
			u64 in_param)
{
	int err = -EINVAL;
	u32 index;
	int id;
	struct res_mpt *mpt;
	enum mlx4_mr_flags flags;
	int fmr_flow;

	switch (op) {
	case RES_OP_RESERVE:
		index = get_param_l(&in_param);
		flags = get_param_h(&in_param);
		fmr_flow = mlx4_fmr_flow(dev, flags);
		if (fmr_flow) {
			mlx4_sdbg("free fmr mpt index 0x%x\n", index);
			if (verify_fmr_index(dev, index, slave)) {
				mlx4_sdbg("verify_fmr_index failed, 0x%x\n",
					  index);
				index = -1;
			}
		}
		id = index & mpt_mask(dev);
		mlx4_sdbg("free mpt index 0x%x, id 0x%x, fmr_flow %d\n",
			  index, id, fmr_flow);
		err = get_res(dev, slave, id, RES_MPT, &mpt);
		if (err) {
			mlx4_sdbg("id 0x%x, err %d\n", id, err);
			break;
		}
		index = mpt->key;
		put_res(dev, slave, id, RES_MPT);

		err = rem_res_range(dev, slave, id, 1, RES_MPT, 0);
		if (err) {
			mlx4_sdbg("failed removing RES_MPT at id 0x%x, err %d\n", id, err);
			break;
		}
		if (!fmr_flow)
			__mlx4_mr_release(dev, index);
		break;
	case RES_OP_MAP_ICM:
			index = get_param_l(&in_param);
			mlx4_sdbg("index 0x%x\n", index);
			id = index & mpt_mask(dev);
			err = mr_res_start_move_to(dev, slave, id, RES_MPT_RESERVED, &mpt);
			if (err) {
				mlx4_sdbg("failed moving mr 0x%x to RES_MPT_RESERVED. err %d\n",
					  id, err);
				return err;
			}
			fmr_flow = mlx4_fmr_flow(dev, mpt->flags);
			if (!fmr_flow)
				__mlx4_mr_free_icm(dev, mpt->key,
						   MLX4_MR_FLAG_NONE);
			res_end_move(dev, slave, RES_MPT, id);
			return err;
		break;
	default:
		err = -EINVAL;
		break;
	}
	return err;
}

static int cq_free_res(struct mlx4_dev *dev, int slave, int op, int cmd,
		       u64 in_param, u64 *out_param)
{
	int cqn;
	int err;

	switch (op) {
	case RES_OP_RESERVE_AND_MAP:
		mlx4_sdbg("\n");
		cqn = get_param_l(&in_param);
		err = rem_res_range(dev, slave, cqn, 1, RES_CQ, 0);
		if (err)
			break;

		__mlx4_cq_free_icm(dev, cqn);
		break;

	default:
		err = -EINVAL;
		break;
	}

	return err;
}

static int srq_free_res(struct mlx4_dev *dev, int slave, int op, int cmd,
			u64 in_param, u64 *out_param)
{
	int srqn;
	int err;

	mlx4_sdbg("\n");
	switch (op) {
	case RES_OP_RESERVE_AND_MAP:
		mlx4_sdbg("\n");
		srqn = get_param_l(&in_param);
		err = rem_res_range(dev, slave, srqn, 1, RES_SRQ, 0);
		if (err)
			break;

		__mlx4_srq_free_icm(dev, srqn);
		break;

	default:
		err = -EINVAL;
		break;
	}

	return err;
}

static int counter_free_res(struct mlx4_dev *dev, int slave, int op, int cmd,
			    u64 in_param, u64 *out_param)
{
	int index;
	int err;

	if (op != RES_OP_RESERVE) {
		mlx4_sdbg("invalid op %d\n", op);
		return -EINVAL;
	}

	index = get_param_l(&in_param);
	err = rem_res_range(dev, slave, index, 1, RES_COUNTER, 0);
	if (err) {
		mlx4_sdbg("failed freeing index %d, err %d\n", index, err);
		return err;
	}

	mlx4_sdbg("counter index %d\n", index);
	__mlx4_counter_free(dev, index);

	return err;
}

static int xrcdn_free_res(struct mlx4_dev *dev, int slave, int op, int cmd,
			  u64 in_param, u64 *out_param)
{
	int xrcdn;
	int err;

	if (op != RES_OP_RESERVE) {
		mlx4_sdbg("invalid op %d\n", op);
		return -EINVAL;
	}

	xrcdn = get_param_l(&in_param);
	err = rem_res_range(dev, slave, xrcdn, 1, RES_XRCDN, 0);
	if (err) {
		mlx4_sdbg("failed freeing xrcdn %d, err %d\n", xrcdn, err);
		return err;
	}

	__mlx4_xrcd_free(dev, xrcdn);

	return err;
}

int mlx4_FREE_RES_wrapper(struct mlx4_dev *dev, int slave,
			  struct mlx4_vhcr *vhcr,
			  struct mlx4_cmd_mailbox *inbox,
			  struct mlx4_cmd_mailbox *outbox,
			  struct mlx4_cmd_info *cmd)
{
	int err = -EINVAL;
	int alop = vhcr->op_modifier;

	switch (vhcr->in_modifier) {
	case RES_QP:
		err = qp_free_res(dev, slave, vhcr->op_modifier, alop,
				  vhcr->in_param);
		break;

	case RES_MTT:
		err = mtt_free_res(dev, slave, vhcr->op_modifier, alop,
				   vhcr->in_param, &vhcr->out_param);
		break;

	case RES_MPT:
		err = mpt_free_res(dev, slave, vhcr->op_modifier, alop,
				   vhcr->in_param);
		break;

	case RES_CQ:
		err = cq_free_res(dev, slave, vhcr->op_modifier, alop,
				  vhcr->in_param, &vhcr->out_param);
		break;

	case RES_SRQ:
		err = srq_free_res(dev, slave, vhcr->op_modifier, alop,
				   vhcr->in_param, &vhcr->out_param);
		break;

	case RES_COUNTER:
		err = counter_free_res(dev, slave, vhcr->op_modifier, alop,
				       vhcr->in_param, &vhcr->out_param);
		break;

	case RES_XRCDN:
		err = xrcdn_free_res(dev, slave, vhcr->op_modifier, alop,
				     vhcr->in_param, &vhcr->out_param);

	default:
		break;
	}
	return err;
}

/* ugly but other choices are uglier */
static int mr_phys_mpt(struct mlx4_mpt_entry *mpt)
{
	return (be32_to_cpu(mpt->flags) >> 9) & 1;
}

static int mr_get_mtt_seg(struct mlx4_mpt_entry *mpt)
{
	return (int)be64_to_cpu(mpt->mtt_seg) & 0xfffffff8;
}

static int mr_get_mtt_size(struct mlx4_mpt_entry *mpt)
{
	return be32_to_cpu(mpt->mtt_sz);
}

static int mr_get_pdn(struct mlx4_mpt_entry *mpt)
{
	return be32_to_cpu(mpt->pd_flags) & 0xffffff;
}

static int qp_get_mtt_seg(struct mlx4_qp_context *qpc)
{
	SASSERT(!qpc->mtt_base_addr_h);
	return be32_to_cpu(qpc->mtt_base_addr_l) & 0xfffffff8;
}

static int srq_get_mtt_seg(struct mlx4_srq_context *srqc)
{
	SASSERT(!srqc->mtt_base_addr_h);
	return be32_to_cpu(srqc->mtt_base_addr_l) & 0xfffffff8;
}

static int qp_get_mtt_size(struct mlx4_qp_context *qpc)
{
	int page_shift = (qpc->log_page_size & 0x3f) + 12;
	int log_sq_size = (qpc->sq_size_stride >> 3) & 0xf;
	int log_sq_sride = qpc->sq_size_stride & 7;
	int log_rq_size = (qpc->rq_size_stride >> 3) & 0xf;
	int log_rq_stride = qpc->rq_size_stride & 7;
	int srq = (be32_to_cpu(qpc->srqn) >> 24) & 1;
	int rss = (be32_to_cpu(qpc->flags) >> 13) & 1;
	int xrc = (be32_to_cpu(qpc->local_qpn) >> 23) & 1;
	int sq_size;
	int rq_size;
	int total_pages;
	int total_mem;
	int page_offset = (be32_to_cpu(qpc->params2) >> 6 ) & 0x3f;

	sq_size = 1 << (log_sq_size + log_sq_sride + 4);
	rq_size = (srq | rss | xrc) ? 0 : (1 << (log_rq_size + log_rq_stride + 4));
	total_mem = sq_size + rq_size;
	total_pages = roundup_pow_of_two((total_mem + (page_offset << 6)) >> page_shift);

	return total_pages;
}

static int qp_get_pdn(struct mlx4_qp_context *qpc)
{
	return be32_to_cpu(qpc->pd) & 0xffffff;
}

static int pdn2slave(int pdn)
{
	return (pdn >> NOT_MASKED_PD_BITS) - 1;
}

static int check_mtt_range(struct mlx4_dev *dev, int slave, int start,
			   int size, struct res_mtt *mtt)
{
	int res_start = mtt->com.res_id * dev->caps.mtts_per_seg;
	int res_size = (1 << mtt->order) * dev->caps.mtts_per_seg;

	if (start < res_start || start + size > res_start + res_size) {
		SASSERT(slave == mtt->com.owner);
		return -EPERM;
	}

	return 0;
}

int mlx4_SW2HW_MPT_wrapper(struct mlx4_dev *dev, int slave,
			   struct mlx4_vhcr *vhcr,
			   struct mlx4_cmd_mailbox *inbox,
			   struct mlx4_cmd_mailbox *outbox,
			   struct mlx4_cmd_info *cmd)
{
	int err;
	int index = vhcr->in_modifier;
	struct res_mtt *mtt;
	struct res_mpt *mpt;
	int mtt_base = (mr_get_mtt_seg(inbox->buf) / dev->caps.mtt_entry_sz) * dev->caps.mtts_per_seg;
	int phys;
	int id;
	int fmr_flow;

	id = index & mpt_mask(dev);
	err = mr_res_start_move_to(dev, slave, id, RES_MPT_HW, &mpt);
	if (err) {
		mlx4_sdbg("failed moving MPT id 0x%x to RES_MPT_HW. err %d\n",
			  id, err);
		return err;
	}

	fmr_flow = mlx4_fmr_flow(dev, mpt->flags);


	phys = mr_phys_mpt(inbox->buf);
	if (!(phys || fmr_flow)) {
		err = get_res(dev, slave, mtt_base / dev->caps.mtts_per_seg, RES_MTT, &mtt);
		if (err) {
			mlx4_sdbg("mlx4_SW2HW_MPT_wrapper failed\n");
			goto ex_abort;
		}

		err = check_mtt_range(dev, slave, mtt_base, mr_get_mtt_size(inbox->buf), mtt);
		if (err)
			goto ex_put;

		mpt->mtt = mtt;
	}

	if (pdn2slave(mr_get_pdn(inbox->buf)) != slave) {
		err = -EPERM;
		goto ex_put;
	}

	err = mlx4_DMA_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
	if (err)
		goto ex_put;

	if (!(phys || fmr_flow)) {
		atomic_inc(&mtt->ref_count);
		mlx4_sdbg("base 0x%x, count %d\n", mtt->com.res_id, atomic_read(&mtt->ref_count));
		put_res(dev, slave, mtt->com.res_id, RES_MTT);
	}

	res_end_move(dev, slave, RES_MPT, id);
	mlx4_sdbg("id 0x%x, phys %d\n", id, phys);

	return 0;

ex_put:
	if (!(phys || fmr_flow))
		put_res(dev, slave, mtt->com.res_id, RES_MTT);
ex_abort:
	res_abort_move(dev, slave, RES_MPT, id);

	return err;
}

int mlx4_HW2SW_MPT_wrapper(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
			   struct mlx4_cmd_mailbox *inbox,
			   struct mlx4_cmd_mailbox *outbox,
			   struct mlx4_cmd_info *cmd)
{
	int err;
	int index = vhcr->in_modifier;
	struct res_mpt *mpt;
	int id;

	id = index & mpt_mask(dev);
	err = mr_res_start_move_to(dev, slave, id, RES_MPT_MAPPED, &mpt);
	if (err) {
		mlx4_sdbg("failed moving MPT id 0x%x to RES_MPT_MAPPED. err %d\n",
			  id, err);
		return err;
	}

	err = mlx4_DMA_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
	if (err) {
		mlx4_sdbg("id 0x%x, err %d\n", id, err);
		goto ex_abort;
	}

	if (mpt->mtt) {
		atomic_dec(&mpt->mtt->ref_count);
		mlx4_sdbg("base 0x%x, count %d\n", mpt->mtt->com.res_id, atomic_read(&mpt->mtt->ref_count));
	}

	res_end_move(dev, slave, RES_MPT, id);
	mlx4_sdbg("id 0x%x, phys %d\n", id, !!mpt->mtt);

	return 0;

ex_abort:
	res_abort_move(dev, slave, RES_MPT, id);

	return err;
}

int mlx4_QUERY_MPT_wrapper(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
			   struct mlx4_cmd_mailbox *inbox,
			   struct mlx4_cmd_mailbox *outbox,
			   struct mlx4_cmd_info *cmd)
{
	int err;
	int index = vhcr->in_modifier;
	struct res_mpt *mpt;
	int id;

	id = index & mpt_mask(dev);
	err = get_res(dev, slave, id, RES_MPT, &mpt);
	if (err)
		return err;

	if (mpt->com.from_state != RES_MPT_HW) {
		err = -EBUSY;
		goto out;
	}

	err = mlx4_DMA_wrapper(dev, slave, vhcr, inbox, outbox, cmd);

out:
	put_res(dev, slave, id, RES_MPT);
	return err;
}

static int qp_get_rcqn(struct mlx4_qp_context *qpc)
{
	return be32_to_cpu(qpc->cqn_recv) & 0xffffff;
}

static int qp_get_scqn(struct mlx4_qp_context *qpc)
{
	return be32_to_cpu(qpc->cqn_send) & 0xffffff;
}

static u32 qp_get_srqn(struct mlx4_qp_context *qpc)
{
	return be32_to_cpu(qpc->srqn) & 0x1ffffff;
}

static int srq_get_cqn(struct mlx4_srq_context *srqc)
{
	return be32_to_cpu(srqc->pg_offset_cqn) & 0xffffff;
}

static void adjust_proxy_tun_qkey(struct mlx4_dev *dev, struct mlx4_vhcr *vhcr,
				  struct mlx4_qp_context *context)
{
	u32 qpn = vhcr->in_modifier & 0xffffff;
	u32 qkey = 0;

	if (mlx4_get_parav_qkey(dev, qpn, &qkey))
		return;

	/* adjust qkey in qp context */
	context->qkey = cpu_to_be32(qkey);
}


int mlx4_RST2INIT_QP_wrapper(struct mlx4_dev *dev, int slave, struct mlx4_vhcr *vhcr,
			     struct mlx4_cmd_mailbox *inbox,
			     struct mlx4_cmd_mailbox *outbox,
			     struct mlx4_cmd_info *cmd)
{
	int err;
	int qpn = vhcr->in_modifier & 0x7fffff;
	struct res_mtt *mtt;
	struct res_qp *qp;
	struct mlx4_qp_context *qpc = inbox->buf + 8;
	int mtt_base = (qp_get_mtt_seg(qpc) / dev->caps.mtt_entry_sz) * dev->caps.mtts_per_seg;
	int mtt_size = qp_get_mtt_size(qpc);
	struct res_cq *rcq;
	struct res_cq *scq;
	int rcqn = qp_get_rcqn(qpc);
	int scqn = qp_get_scqn(qpc);
	u32 srqn = qp_get_srqn(qpc) & 0xffffff;
	int use_srq = (qp_get_srqn(qpc) >> 24) & 1;
	struct res_srq *srq;
	int local_qpn = be32_to_cpu(qpc->local_qpn) & 0xffffff;

	err = qp_res_start_move_to(dev, slave, qpn, RES_QP_HW, &qp, 0);
	if (err) {
		mlx4_sdbg("failed moving QP qpn 0x%x to RES_QP_HW. err %d\n",
			  qpn, err);
		return err;
	}
	qp->local_qpn = local_qpn;

	err = get_res(dev, slave, mtt_base / dev->caps.mtts_per_seg, RES_MTT, &mtt);
	if (err) {
		mlx4_sdbg("base 0x%x, size %d\n", mtt_base, mtt_size);
		goto ex_abort;
	}

	err = check_mtt_range(dev, slave, mtt_base, mtt_size, mtt);
	if (err) {
		mlx4_sdbg("mtt_base 0x%x, mtt_size %d\n", mtt_base, mtt_size);
		goto ex_put_mtt;
	}

	if (pdn2slave(qp_get_pdn(qpc)) != slave) {
		mlx4_sdbg("slave pdn 0x%x\n", pdn2slave(qp_get_pdn(qpc)));
		err = -EPERM;
		goto ex_put_mtt;
	}

	err = get_res(dev, slave, rcqn, RES_CQ, &rcq);
	if (err) {
		mlx4_sdbg("cqn 0x%x\n", rcqn);
		goto ex_put_mtt;
	}

	if (scqn != rcqn) {
		err = get_res(dev, slave, scqn, RES_CQ, &scq);
		if (err) {
			mlx4_sdbg("cqn 0x%x\n", scqn);
			goto ex_put_rcq;
		}
	} else
		scq = rcq;

	mlx4_sdbg("qpn 0x%x, srqn 0x%x\n", qpn, srqn);
	if (use_srq) {
		err = get_res(dev, slave, srqn, RES_SRQ, &srq);
		if (err) {
			mlx4_sdbg("srqn 0x%x, err %d\n", srqn, err);
			goto ex_put_scq;
		}
		mlx4_sdbg("srqn 0x%x\n", srqn);
	}

	adjust_proxy_tun_qkey(dev, vhcr, qpc);
	update_pkey_index(dev, slave, inbox);
	err = mlx4_DMA_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
	if (err) {
		mlx4_sdbg("qpn 0x%x, err %d\n", qpn, err);
		goto ex_put_srq;
	}
	mlx4_sdbg("qpn 0x%x, successfully move to INIT\n", qpn);

	atomic_inc(&mtt->ref_count);
	mlx4_sdbg("base 0x%x, count %d\n", mtt->com.res_id, atomic_read(&mtt->ref_count));
	qp->mtt = mtt;

	atomic_inc(&rcq->ref_count);
        mlx4_sdbg("CQ 0x%x, ref count %d\n", rcq->com.res_id, atomic_read(&rcq->ref_count));
	qp->rcq = rcq;
	atomic_inc(&scq->ref_count);
        mlx4_sdbg("CQ 0x%x, ref count %d\n", scq->com.res_id, atomic_read(&scq->ref_count));
	qp->scq = scq;

	if (scqn != rcqn)
		put_res(dev, slave, scqn, RES_CQ);

	if (use_srq) {
		atomic_inc(&srq->ref_count);
		put_res(dev, slave, srqn, RES_SRQ);
		qp->srq = srq;
	}
	put_res(dev, slave, rcqn, RES_CQ);
	put_res(dev, slave, mtt_base  / dev->caps.mtts_per_seg, RES_MTT);
	res_end_move(dev, slave, RES_QP, qpn);

	return 0;

ex_put_srq:
	if (use_srq)
		put_res(dev, slave, srqn, RES_SRQ);
ex_put_scq:
	if (scqn != rcqn)
		put_res(dev, slave, scqn, RES_CQ);
ex_put_rcq:
	put_res(dev, slave, rcqn, RES_CQ);
ex_put_mtt:
	put_res(dev, slave, mtt_base / dev->caps.mtts_per_seg, RES_MTT);
ex_abort:
	res_abort_move(dev, slave, RES_QP, qpn);

	return err;
}

static int eq_get_mtt_seg(struct mlx4_eq_context *eqc)
{
	SASSERT(!eqc->mtt_base_addr_h);
	return (be32_to_cpu(eqc->mtt_base_addr_l) & 0xfffffff8);
}

static int eq_get_mtt_size(struct mlx4_eq_context *eqc)
{
	int log_eq_size = eqc->log_eq_size & 0x1f;
	int page_shift = (eqc->log_page_size & 0x3f) + 12;

	if (log_eq_size + 5 < page_shift)
		return 1;

	return 1 << (log_eq_size + 5 - page_shift);
}

static int cq_get_mtt_seg(struct mlx4_cq_context *cqc)
{
	return be32_to_cpu(cqc->mtt_base_addr_l) & 0xfffffff8;
}

static int cq_get_mtt_size(struct mlx4_cq_context *cqc)
{
	int log_cq_size = (be32_to_cpu(cqc->logsize_usrpage) >> 24) & 0x1f;
	int page_shift = (cqc->log_page_size & 0x3f) + 12;

	if (log_cq_size + 5 < page_shift)
		return 1;

	return 1 << (log_cq_size + 5 - page_shift);
}

int mlx4_SW2HW_EQ_wrapper(struct mlx4_dev *dev, int slave,
			  struct mlx4_vhcr *vhcr,
			  struct mlx4_cmd_mailbox *inbox,
			  struct mlx4_cmd_mailbox *outbox,
			  struct mlx4_cmd_info *cmd)
{
	int err;
	int eqn = vhcr->in_modifier;
	int res_id = (slave << 8) | eqn;
	struct mlx4_eq_context *eqc = inbox->buf;
	int mtt_base = (eq_get_mtt_seg(eqc) / dev->caps.mtt_entry_sz) * dev->caps.mtts_per_seg;
	int mtt_size = eq_get_mtt_size(eqc);
	struct res_eq *eq;
	struct res_mtt *mtt;

	err = add_res_range(dev, slave, res_id, 1, RES_EQ, 0, 0);
	if (err) {
		mlx4_sdbg("failed adding EQ to tracker: eqn 0x%x\n", eqn);
		return err;
	}

	mlx4_sdbg("sccuess adding EQ 0x%x (id 0x%x) tracker. err %d\n",
		  eqn, res_id, err);

	err = eq_res_start_move_to(dev, slave, res_id, RES_EQ_HW, &eq);
	if (err) {
		mlx4_sdbg("failed moving EQ 0x%x (id 0x%x) to RES_EQ_HW. err %d\n",
			  eqn, res_id, err);
		goto out_add;
	}

	err = get_res(dev, slave, mtt_base / dev->caps.mtts_per_seg, RES_MTT, &mtt);
	if (err) {
		mlx4_sdbg("mtt_base 0x%x\n", mtt_base / dev->caps.mtts_per_seg);
		goto out_move;
	}

	err = check_mtt_range(dev, slave, mtt_base, mtt_size, mtt);
	if (err) {
		mlx4_sdbg("mtt_base 0x%x, mtt_size %d\n", mtt_base, mtt_size);
		goto out_put;
	}

	err = mlx4_DMA_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
	if (err) {
		mlx4_sdbg("failed moving EQ 0x%x to RES_EQ_HW. err %d\n",
			  eqn, err);
		goto out_put;
	}

	atomic_inc(&mtt->ref_count);
	mlx4_sdbg("base 0x%x, count %d\n", mtt->com.res_id, atomic_read(&mtt->ref_count));
	eq->mtt = mtt;
	put_res(dev, slave, mtt->com.res_id, RES_MTT);
	res_end_move(dev, slave, RES_EQ, res_id);
	return 0;

out_put:
	put_res(dev, slave, mtt->com.res_id, RES_MTT);
out_move:
	res_abort_move(dev, slave, RES_EQ, res_id);
out_add:
	rem_res_range(dev, slave, res_id, 1, RES_EQ, 0);
	return err;
}

static int get_containing_mtt(struct mlx4_dev *dev, int slave, int start, int len, struct res_mtt **res)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_resource_tracker *tracker = &priv->mfunc.master.res_tracker;
	struct res_mtt *mtt;
	int err = -EINVAL;

	spin_lock_irq(mlx4_tlock(dev));
	list_for_each_entry(mtt, &tracker->slave_list[slave].res_list[RES_MTT], com.list) {
		if (!check_mtt_range(dev, slave, start, len, mtt)) {
			mlx4_sdbg("owner %d, start 0x%x, order %d\n", mtt->com.owner, mtt->com.res_id, mtt->order);
			*res = mtt;
			SASSERT(mtt->com.state != RES_MTT_BUSY);
			mtt->com.from_state = mtt->com.state;
			mtt->com.state = RES_MTT_BUSY;
			err = 0;
			break;
		}
	}
	spin_unlock_irq(mlx4_tlock(dev));

	return err;
}

int mlx4_WRITE_MTT_wrapper(struct mlx4_dev *dev, int slave,
			   struct mlx4_vhcr *vhcr,
			   struct mlx4_cmd_mailbox *inbox,
			   struct mlx4_cmd_mailbox *outbox,
			   struct mlx4_cmd_info *cmd)
{
	struct mlx4_mtt mtt;
	u64 *page_list = inbox->buf;
	int i;
	struct res_mtt *rmtt = NULL;
	int start = be64_to_cpu(page_list[0]);
	int npages = vhcr->in_modifier;
	int err;

        err = get_containing_mtt(dev, slave, start, npages, &rmtt);
	if (err) {
		mlx4_sdbg("start 0x%x, npages %d\n", start, npages);
		return err;
	}

	/* Call the SW implementation of write_mtt:
	 * - Prepare a dummy mtt struct
	 * - Translate inbox contents to simple addresses in host endianess */
	mtt.first_seg = 0;  // TBD this is broken but I don't handle it since we don't really use it
	mtt.order = 0;
	mtt.page_shift = 0;
	for (i = 0; i < npages; ++i)
		page_list[i + 2] = be64_to_cpu(page_list[i + 2]) & ~1ULL;
	err = __mlx4_write_mtt(dev, &mtt, be64_to_cpu(page_list[0]), npages,
                               page_list + 2);

	mlx4_sdbg("err %d\n", err);
	SASSERT(rmtt);
	put_res(dev, slave, rmtt->com.res_id, RES_MTT);

	return err;
}

int mlx4_HW2SW_EQ_wrapper(struct mlx4_dev *dev, int slave,
			  struct mlx4_vhcr *vhcr,
			  struct mlx4_cmd_mailbox *inbox,
			  struct mlx4_cmd_mailbox *outbox,
			  struct mlx4_cmd_info *cmd)
{
	int eqn = vhcr->in_modifier;
	int res_id = eqn | (slave << 8);
	struct res_eq *eq;
	int err;

	err = eq_res_start_move_to(dev, slave, res_id, RES_EQ_RESERVED, &eq);
	if (err) {
		mlx4_sdbg("failed moving EQ eqn 0x%x to RES_EQ_RESERVED. err %d\n",
			  eqn, err);
		return err;
	}

	err = get_res(dev, slave, eq->mtt->com.res_id, RES_MTT, NULL);
	if (err)
		goto ex_abort;

	err = mlx4_DMA_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
	if (err)
		goto ex_put;

	atomic_dec(&eq->mtt->ref_count);
	mlx4_sdbg("base 0x%x, count %d\n", eq->mtt->com.res_id, atomic_read(&eq->mtt->ref_count));

	put_res(dev, slave, eq->mtt->com.res_id, RES_MTT);
	res_end_move(dev, slave, RES_EQ, res_id);
	rem_res_range(dev, slave, res_id, 1, RES_EQ, 0);

	return 0;

ex_put:
	put_res(dev, slave, eq->mtt->com.res_id, RES_MTT);
ex_abort:
	res_abort_move(dev, slave, RES_EQ, res_id);

	return err;
}

int mlx4_GEN_EQE(struct mlx4_dev *dev, int slave, struct mlx4_eqe *eqe)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_slave_event_eq_info *event_eq;
	struct mlx4_cmd_mailbox *mailbox;
	u32 in_modifier = 0;
	int err;
	int res_id;
	struct res_eq *req;

	if (!priv->mfunc.master.slave_state)
		return -EINVAL;

	event_eq = &priv->mfunc.master.slave_state[slave].event_eq;

	if (!event_eq->use_int)
		return 0;

	/* Create the event only if the slave is registered */
	if ((event_eq->event_type & (1 << eqe->type)) == 0)
		return 0;

	mutex_lock(&priv->mfunc.master.gen_eqe_mutex[slave]);
	res_id = (slave << 8) | event_eq->eqn;
	err = get_res(dev, slave, res_id, RES_EQ, &req);
	if (err)
		goto unlock;

	if (req->com.from_state != RES_EQ_HW) {
		err = -EINVAL;
		goto put;
	}

	mailbox = mlx4_alloc_cmd_mailbox(dev);
	if (IS_ERR(mailbox)) {
		err = PTR_ERR(mailbox);
		goto put;
	}

	if (eqe->type == MLX4_EVENT_TYPE_CMD) {
		++event_eq->token;
		eqe->event.cmd.token = cpu_to_be16(event_eq->token);
	}

	memcpy(mailbox->buf, (u8 *) eqe, 28);

	in_modifier = (slave & 0xff) | ((event_eq->eqn & 0xff) << 16);

	err = mlx4_cmd(dev, mailbox->dma, in_modifier, 0,
		       MLX4_CMD_GEN_EQE, MLX4_CMD_TIME_CLASS_B, 1);

	put_res(dev, slave, res_id, RES_EQ);
	mutex_unlock(&priv->mfunc.master.gen_eqe_mutex[slave]);
	mlx4_free_cmd_mailbox(dev, mailbox);
	return err;

put:
	mlx4_sdbg("\n");
	put_res(dev, slave, res_id, RES_EQ);

unlock:
	mlx4_sdbg("\n");
	mutex_unlock(&priv->mfunc.master.gen_eqe_mutex[slave]);
	return err;
}

int mlx4_QUERY_EQ_wrapper(struct mlx4_dev *dev, int slave,
			  struct mlx4_vhcr *vhcr,
			  struct mlx4_cmd_mailbox *inbox,
			  struct mlx4_cmd_mailbox *outbox,
			  struct mlx4_cmd_info *cmd)
{
	int eqn = vhcr->in_modifier;
	int res_id = eqn | (slave << 8);
	struct res_eq *eq;
	int err;

	err = get_res(dev, slave, res_id, RES_EQ, &eq);
	if (err)
		return err;

	if (eq->com.from_state != RES_EQ_HW) {
		err = -EINVAL;
		goto ex_put;
	}

	err = mlx4_DMA_wrapper(dev, slave, vhcr, inbox, outbox, cmd);

ex_put:
	put_res(dev, slave, res_id, RES_EQ);
	return err;
}

int mlx4_SW2HW_CQ_wrapper(struct mlx4_dev *dev, int slave,
			  struct mlx4_vhcr *vhcr,
			  struct mlx4_cmd_mailbox *inbox,
			  struct mlx4_cmd_mailbox *outbox,
			  struct mlx4_cmd_info *cmd)
{
	int err;
	int cqn = vhcr->in_modifier;
	struct mlx4_cq_context *cqc = inbox->buf;
	int mtt_base = (cq_get_mtt_seg(cqc) / dev->caps.mtt_entry_sz) * dev->caps.mtts_per_seg;
	struct res_cq *cq;
	struct res_mtt *mtt;

	err = cq_res_start_move_to(dev, slave, cqn, RES_CQ_HW, &cq);
	if (err) {
		mlx4_sdbg("failed moving CQ 0x%x to RES_CQ_HW. err %d\n",
			  cqn, err);
		return err;
	}

	err = get_res(dev, slave, mtt_base / dev->caps.mtts_per_seg, RES_MTT, &mtt);
	if (err) {
		mlx4_sdbg("\n");
		goto out_move;
	}

	err = check_mtt_range(dev, slave, mtt_base, cq_get_mtt_size(cqc), mtt);
	if (err) {
		mlx4_sdbg("CQ mtt base 0x%x, CQ mtt size %d, mtt.base 0x%x, mtt.size %d\n",
			  mtt_base, cq_get_mtt_size(cqc),
			  mtt->com.res_id * dev->caps.mtts_per_seg, (1 << mtt->order) * dev->caps.mtts_per_seg);
		goto out_put;
	}

	err = mlx4_DMA_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
	if (err) {
		mlx4_sdbg("failed moving CQ 0x%x to RES_CQ_HW. err %d\n",
			  cqn, err);
		goto out_put;
	}

	atomic_inc(&mtt->ref_count);
	mlx4_sdbg("cqn 0x%x, mtt_base 0x%x, count %d\n", cqn, mtt->com.res_id, atomic_read(&mtt->ref_count));
	cq->mtt = mtt;
	put_res(dev, slave, mtt->com.res_id, RES_MTT);
        res_end_move(dev, slave, RES_CQ, cqn);
	return 0;

out_put:
	put_res(dev, slave, mtt->com.res_id, RES_MTT);
out_move:
	res_abort_move(dev, slave, RES_CQ, cqn);
	return err;
}

int mlx4_HW2SW_CQ_wrapper(struct mlx4_dev *dev, int slave,
			  struct mlx4_vhcr *vhcr,
			  struct mlx4_cmd_mailbox *inbox,
			  struct mlx4_cmd_mailbox *outbox,
			  struct mlx4_cmd_info *cmd)
{
	int err;
	int cqn = vhcr->in_modifier;
	struct res_cq *cq;

	err = cq_res_start_move_to(dev, slave, cqn, RES_CQ_ALLOCATED, &cq);
	if (err) {
		mlx4_sdbg("failed moving CQ 0x%x to RES_CQ_ALLOCATED. err %d\n",
			  cqn, err);
		return err;
	}

	err = mlx4_DMA_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
	if (err) {
		mlx4_sdbg("failed moving CQ 0x%x to RES_CQ_ALLOCATED. err %d\n",
			  cqn, err);
		goto out_move;
	}

	atomic_dec(&cq->mtt->ref_count);
	mlx4_sdbg("base 0x%x, count %d\n", cq->mtt->com.res_id, atomic_read(&cq->mtt->ref_count));
        mlx4_sdbg("CQ 0x%x, ref count %d\n", cq->com.res_id, atomic_read(&cq->ref_count));
        res_end_move(dev, slave, RES_CQ, cqn);
	return 0;

out_move:
	res_abort_move(dev, slave, RES_CQ, cqn);
	return err;
}

int mlx4_QUERY_CQ_wrapper(struct mlx4_dev *dev, int slave,
			  struct mlx4_vhcr *vhcr,
			  struct mlx4_cmd_mailbox *inbox,
			  struct mlx4_cmd_mailbox *outbox,
			  struct mlx4_cmd_info *cmd)
{
	int cqn = vhcr->in_modifier;
	struct res_cq *cq;
	int err;

	err = get_res(dev, slave, cqn, RES_CQ, &cq);
	if (err)
		return err;

	if (cq->com.from_state != RES_CQ_HW)
		goto ex_put;

	err = mlx4_DMA_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
	if (err)
		mlx4_sdbg("query_cq failed cqn 0x%x. err %d\n",
			  cqn, err);

ex_put:
	put_res(dev, slave, cqn, RES_CQ);

	return err;
}

static int handle_resize(struct mlx4_dev *dev, int slave,
			 struct mlx4_vhcr *vhcr,
			 struct mlx4_cmd_mailbox *inbox,
			 struct mlx4_cmd_mailbox *outbox,
			 struct mlx4_cmd_info *cmd,
			 struct res_cq *cq)
{
	int cqn = vhcr->in_modifier;
	int err;
	struct res_mtt *orig_mtt;
	struct res_mtt *mtt;
	struct mlx4_cq_context *cqc = inbox->buf;
	int mtt_base = (cq_get_mtt_seg(cqc) / dev->caps.mtt_entry_sz) * dev->caps.mtts_per_seg;

	err = get_res(dev, slave, cq->mtt->com.res_id, RES_MTT, &orig_mtt);
	SASSERT(!err);
	if (err)
		return err;

	SASSERT(orig_mtt == cq->mtt);
	if (orig_mtt != cq->mtt) {
		err = -EINVAL;
		goto ex_put;
	}

	err = get_res(dev, slave, mtt_base / dev->caps.mtts_per_seg, RES_MTT, &mtt);
	if (err) {
		mlx4_sdbg("cqn 0x%x, mtt_base 0x%x\n",
			  cqn, mtt_base / dev->caps.mtts_per_seg);
		goto ex_put;
	}

	err = check_mtt_range(dev, slave, mtt_base, cq_get_mtt_size(cqc), mtt);
	if (err) {
		mlx4_sdbg("CQ mtt base 0x%x, CQ mtt size %d, mtt.base 0x%x, mtt.size %d\n",
			  mtt_base, cq_get_mtt_size(cqc), mtt->com.res_id * dev->caps.mtts_per_seg,
			  (1 << mtt->order) * dev->caps.mtts_per_seg);
		goto ex_put1;
	}

	err = mlx4_DMA_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
	if (err) {
		mlx4_sdbg("modify cq failed cqn 0x%x. err %d\n",
			  cqn, err);
		goto ex_put1;
	}

	atomic_dec(&orig_mtt->ref_count);
	put_res(dev, slave, orig_mtt->com.res_id, RES_MTT);
	atomic_inc(&mtt->ref_count);
	cq->mtt = mtt;
	put_res(dev, slave, mtt->com.res_id, RES_MTT);
	return 0;

ex_put1:
	put_res(dev, slave, mtt->com.res_id, RES_MTT);
ex_put:
	put_res(dev, slave, orig_mtt->com.res_id, RES_MTT);

	return err;

}

int mlx4_MODIFY_CQ_wrapper(struct mlx4_dev *dev, int slave,
			   struct mlx4_vhcr *vhcr,
			   struct mlx4_cmd_mailbox *inbox,
			   struct mlx4_cmd_mailbox *outbox,
			   struct mlx4_cmd_info *cmd)
{
	int cqn = vhcr->in_modifier;
	struct res_cq *cq;
	int err;

	err = get_res(dev, slave, cqn, RES_CQ, &cq);
	if (err)
		return err;

	if (cq->com.from_state != RES_CQ_HW)
		goto ex_put;

	if (vhcr->op_modifier == 0) {
		mlx4_sdbg("resize cqn 0x%x\n", cqn);
		err = handle_resize(dev, slave, vhcr, inbox, outbox, cmd, cq);
		mlx4_sdbg("resize cqn 0x%x failed\n", cqn);
		goto ex_put;
	}

	mlx4_sdbg("modify cqn 0x%x, opmod %d\n", cqn, vhcr->op_modifier);
	err = mlx4_DMA_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
	if (err)
		mlx4_sdbg("modify cq failed cqn 0x%x. err %d\n",
			  cqn, err);

ex_put:
	put_res(dev, slave, cqn, RES_CQ);

	return err;
}

static int srq_get_pdn(struct mlx4_srq_context *srqc)
{
	return be32_to_cpu(srqc->pd) & 0xffffff;
}

static int srq_get_mtt_size(struct mlx4_srq_context *srqc)
{
	int log_srq_size = (be32_to_cpu(srqc->state_logsize_srqn) >> 24) & 0xf;
	int log_rq_stride = srqc->logstride & 7;
/*
	TBD how to use in calcualtions?
	int page_offset = be32_to_cpu(srqc->pg_offset_cqn) >> 26;
*/
	int page_shift = (srqc->log_page_size & 0x3f) + 12;

/*
	SASSERT(!page_offset);
*/

	if (log_srq_size + log_rq_stride + 4 < page_shift)
		return 1;

	return 1 << (log_srq_size + log_rq_stride + 4 - page_shift);

}

int mlx4_SW2HW_SRQ_wrapper(struct mlx4_dev *dev, int slave,
			   struct mlx4_vhcr *vhcr,
			   struct mlx4_cmd_mailbox *inbox,
			   struct mlx4_cmd_mailbox *outbox,
			   struct mlx4_cmd_info *cmd)
{
	int err;
	int srqn = vhcr->in_modifier;
	struct res_mtt *mtt;
	struct res_srq *srq;
	struct mlx4_srq_context *srqc = inbox->buf;
	int mtt_base = (srq_get_mtt_seg(srqc) / dev->caps.mtt_entry_sz) * dev->caps.mtts_per_seg;
	struct res_cq *cq;
	int cqn = srq_get_cqn(srqc);

	mlx4_sdbg("srqn 0x%x\n", srqn);
	if (srqn != (be32_to_cpu(srqc->state_logsize_srqn) & 0xffffff)) {
		mlx4_sdbg("\n");
		return -EINVAL;
	}

	mlx4_sdbg("srqn 0x%x\n", srqn);
	err = srq_res_start_move_to(dev, slave, srqn, RES_SRQ_HW, &srq);
	if (err) {
		mlx4_sdbg("failed moving SRQ 0x%x to RES_SRQ_HW. err %d\n",
			  srqn, err);
		return err;
	}

	mlx4_sdbg("srqn 0x%x\n", srqn);
	err = get_res(dev, slave, mtt_base / dev->caps.mtts_per_seg, RES_MTT, &mtt);
	if (err) {
		mlx4_sdbg("mtt_base 0x%x\n", mtt_base / dev->caps.mtts_per_seg);
		goto ex_abort;
	}

	err = check_mtt_range(dev, slave, mtt_base, srq_get_mtt_size(srqc), mtt);
	if (err) {
		mlx4_sdbg("\n");
		goto ex_put_mtt;
	}

	if (pdn2slave(srq_get_pdn(srqc)) != slave) {
		mlx4_sdbg("\n");
		err = -EPERM;
		goto ex_put_mtt;
	}

	if (cqn) {
		mlx4_sdbg("srqn 0x%x used for xrc, cqn 0x%x\n", srqn, cqn);
		err = get_res(dev, slave, cqn, RES_CQ, &cq);
		if (err) {
			mlx4_sdbg("cqn 0x%x\n", cqn);
			goto ex_put_mtt;
		}
	}

	err = mlx4_DMA_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
	if (err) {
		mlx4_sdbg("err %d\n", err);
		goto ex_put_cq;
	}

	atomic_inc(&mtt->ref_count);
	mlx4_sdbg("base 0x%x, count %d\n", mtt->com.res_id, atomic_read(&mtt->ref_count));
	srq->mtt = mtt;

        if (cqn) {
		atomic_inc(&cq->ref_count);
		mlx4_sdbg("CQ 0x%x, ref count %d\n", cq->com.res_id, atomic_read(&cq->ref_count));
		srq->cq = cq;
		put_res(dev, slave, cq->com.res_id, RES_CQ);
	}

	put_res(dev, slave, mtt->com.res_id, RES_MTT);
	res_end_move(dev, slave, RES_SRQ, srqn);
	mlx4_sdbg("srqn 0x%x\n", srqn);

	return 0;

ex_put_cq:
	if (cqn)
		put_res(dev, slave, cqn, RES_CQ);
ex_put_mtt:
	put_res(dev, slave, mtt->com.res_id, RES_MTT);
ex_abort:
	res_abort_move(dev, slave, RES_SRQ, srqn);

	return err;
}

int mlx4_HW2SW_SRQ_wrapper(struct mlx4_dev *dev, int slave,
			   struct mlx4_vhcr *vhcr,
			   struct mlx4_cmd_mailbox *inbox,
			   struct mlx4_cmd_mailbox *outbox,
			   struct mlx4_cmd_info *cmd)
{
	int err;
	int srqn = vhcr->in_modifier;
	struct res_srq *srq;

	mlx4_sdbg("srqn 0x%x\n", srqn);
	err = srq_res_start_move_to(dev, slave, srqn, RES_SRQ_ALLOCATED, &srq);
	if (err) {
		mlx4_sdbg("failed moving SRQ 0x%x to RES_SRQ_ALLOCATED. err %d\n",
			  srqn, err);
		return err;
	}

	mlx4_sdbg("srqn 0x%x\n", srqn);
	err = mlx4_DMA_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
	if (err) {
		mlx4_sdbg("\n");
		goto ex_abort;
	}


	mlx4_sdbg("srqn 0x%x\n", srqn);
	atomic_dec(&srq->mtt->ref_count);
	mlx4_sdbg("base 0x%x, count %d\n", srq->mtt->com.res_id, atomic_read(&srq->mtt->ref_count));
	if (srq->cq) {
		atomic_dec(&srq->cq->ref_count);
		mlx4_sdbg("CQ 0x%x, ref count %d\n", srq->cq->com.res_id, atomic_read(&srq->cq->ref_count));
	}

	mlx4_sdbg("srqn 0x%x\n", srqn);
	res_end_move(dev, slave, RES_SRQ, srqn);

	return 0;

ex_abort:
	res_abort_move(dev, slave, RES_SRQ, srqn);

	return err;
}

int mlx4_QUERY_SRQ_wrapper(struct mlx4_dev *dev, int slave,
			   struct mlx4_vhcr *vhcr,
			   struct mlx4_cmd_mailbox *inbox,
			   struct mlx4_cmd_mailbox *outbox,
			   struct mlx4_cmd_info *cmd)
{
	int err;
	int srqn = vhcr->in_modifier;
	struct res_srq *srq;

	err = get_res(dev, slave, srqn, RES_SRQ, &srq);
	if (err) {
		mlx4_sdbg("fail srqn 0x%x\n", srqn);
		return err;
	}

	if (srq->com.from_state != RES_SRQ_HW) {
		mlx4_sdbg("fail srqn 0x%x\n", srqn);
		err = -EBUSY;
		goto out;
	}

	err = mlx4_DMA_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
	if (err)
		mlx4_sdbg("fail srqn 0x%x\n", srqn);

out:
	put_res(dev, slave, srqn, RES_SRQ);
	return err;
}

int mlx4_ARM_SRQ_wrapper(struct mlx4_dev *dev, int slave,
			 struct mlx4_vhcr *vhcr,
			 struct mlx4_cmd_mailbox *inbox,
			 struct mlx4_cmd_mailbox *outbox,
			 struct mlx4_cmd_info *cmd)
{
	int err;
	int srqn = vhcr->in_modifier;
	struct res_srq *srq;

	err = get_res(dev, slave, srqn, RES_SRQ, &srq);
	if (err) {
		mlx4_sdbg("srqn 0x%x\n", srqn);
		return err;
	}

	if (srq->com.from_state != RES_SRQ_HW) {
		mlx4_sdbg("srqn 0x%x\n", srqn);
		err = -EBUSY;
		goto out;
	}

	err = mlx4_DMA_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
	if (err)
		mlx4_sdbg("srqn 0x%x\n", srqn);

out:
	put_res(dev, slave, srqn, RES_SRQ);
	return err;
}

static int gen_qp_wrapper(struct mlx4_dev *dev, int slave,
			  struct mlx4_vhcr *vhcr,
			  struct mlx4_cmd_mailbox *inbox,
                          struct mlx4_cmd_mailbox *outbox,
			  struct mlx4_cmd_info *cmd)
{
	int err;
	int qpn = vhcr->in_modifier & 0x7fffff;
	struct res_qp *qp;

	mlx4_sdbg("qpn 0x%x, command 0x%x\n", qpn, vhcr->op);
	err = get_res(dev, slave, qpn, RES_QP, &qp);
	if (err) {
		mlx4_sdbg("qpn 0x%x, command 0x%x, err %d\n", qpn, vhcr->op, err);
		return err;
	}

	if (qp->com.from_state != RES_QP_HW) {
		err = -EBUSY;
		mlx4_sdbg("qpn 0x%x inmod 0x%x, command 0x%x, err %d, state %s\n",
			  qpn, vhcr->in_modifier, vhcr->op, err, qp_states_str(qp->com.from_state));
		goto out;
	}

	err = mlx4_DMA_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
	if (err)
		mlx4_sdbg("qpn 0x%x, err %d\n", qpn, err);

	mlx4_sdbg("qpn 0x%x, command 0x%x\n", qpn, vhcr->op);
out:
	put_res(dev, slave, qpn, RES_QP);
	return err;
}

int mlx4_INIT2RTR_QP_wrapper(struct mlx4_dev *dev, int slave,
			     struct mlx4_vhcr *vhcr,
			     struct mlx4_cmd_mailbox *inbox,
			     struct mlx4_cmd_mailbox *outbox,
			     struct mlx4_cmd_info *cmd)
{
	struct mlx4_qp_context *qpc = inbox->buf + 8;

	update_pkey_index(dev, slave, inbox);
	update_ud_gid(qpc, (u8)slave);
	adjust_proxy_tun_qkey(dev, vhcr, qpc);

	return gen_qp_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
}

int mlx4_RTR2RTS_QP_wrapper(struct mlx4_dev *dev, int slave,
			    struct mlx4_vhcr *vhcr,
			    struct mlx4_cmd_mailbox *inbox,
			    struct mlx4_cmd_mailbox *outbox,
			    struct mlx4_cmd_info *cmd)
{
	struct mlx4_qp_context *context = inbox->buf + 8;
	u8 vep_num = mlx4_priv(dev)->mfunc.master.slave_state[slave].vep_num;
	u8 port = ((context->pri_path.sched_queue >> 6) & 1) + 1;

	if (mlx4_priv(dev)->vep_mode[port])
		context->pri_path.sched_queue = (context->pri_path.sched_queue & 0xc3 ) |
						(vep_num << 3);

	update_pkey_index(dev, slave, inbox);
	adjust_proxy_tun_qkey(dev, vhcr, context);
	return gen_qp_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
}

int mlx4_RTS2RTS_QP_wrapper(struct mlx4_dev *dev, int slave,
			    struct mlx4_vhcr *vhcr,
			    struct mlx4_cmd_mailbox *inbox,
			    struct mlx4_cmd_mailbox *outbox,
			    struct mlx4_cmd_info *cmd)
{
	struct mlx4_qp_context *context = inbox->buf + 8;
	update_pkey_index(dev, slave, inbox);
	adjust_proxy_tun_qkey(dev, vhcr, context);
	return gen_qp_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
}


int mlx4_SQERR2RTS_QP_wrapper(struct mlx4_dev *dev, int slave,
			      struct mlx4_vhcr *vhcr,
			      struct mlx4_cmd_mailbox *inbox,
			      struct mlx4_cmd_mailbox *outbox,
			      struct mlx4_cmd_info *cmd)
{
	struct mlx4_qp_context *context = inbox->buf + 8;
	adjust_proxy_tun_qkey(dev, vhcr, context);
	return gen_qp_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
}

int mlx4_2ERR_QP_wrapper(struct mlx4_dev *dev, int slave,
			 struct mlx4_vhcr *vhcr,
			 struct mlx4_cmd_mailbox *inbox,
			 struct mlx4_cmd_mailbox *outbox,
			 struct mlx4_cmd_info *cmd)
{
	return gen_qp_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
}

int mlx4_RTS2SQD_QP_wrapper(struct mlx4_dev *dev, int slave,
			    struct mlx4_vhcr *vhcr,
			    struct mlx4_cmd_mailbox *inbox,
			    struct mlx4_cmd_mailbox *outbox,
			    struct mlx4_cmd_info *cmd)
{
	return gen_qp_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
}

int mlx4_SQD2SQD_QP_wrapper(struct mlx4_dev *dev, int slave,
			    struct mlx4_vhcr *vhcr,
			    struct mlx4_cmd_mailbox *inbox,
			    struct mlx4_cmd_mailbox *outbox,
			    struct mlx4_cmd_info *cmd)
{
	struct mlx4_qp_context *context = inbox->buf + 8;
	adjust_proxy_tun_qkey(dev, vhcr, context);
	update_pkey_index(dev, slave, inbox);
	return gen_qp_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
}

int mlx4_SQD2RTS_QP_wrapper(struct mlx4_dev *dev, int slave,
			    struct mlx4_vhcr *vhcr,
			    struct mlx4_cmd_mailbox *inbox,
			    struct mlx4_cmd_mailbox *outbox,
			    struct mlx4_cmd_info *cmd)
{
	struct mlx4_qp_context *context = inbox->buf + 8;
	adjust_proxy_tun_qkey(dev, vhcr, context);
	update_pkey_index(dev, slave, inbox);
	return gen_qp_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
}

int mlx4_2RST_QP_wrapper(struct mlx4_dev *dev, int slave,
			 struct mlx4_vhcr *vhcr,
			 struct mlx4_cmd_mailbox *inbox,
			 struct mlx4_cmd_mailbox *outbox,
			 struct mlx4_cmd_info *cmd)
{
	int err;
	int qpn = vhcr->in_modifier & 0x7fffff;
	struct res_qp *qp;

	mlx4_sdbg("qpn 0x%x\n", qpn);
	err = qp_res_start_move_to(dev, slave, qpn, RES_QP_MAPPED, &qp, 0);
	if (err) {
		mlx4_sdbg("failed moving QP 0x%x to RES_QP_MAPPED. err %d, cur_state %s\n",
			  qpn, err, qp_states_str(qp->com.from_state));
		return err;
	}

	mlx4_sdbg("qpn 0x%x\n", qpn);
	err = mlx4_DMA_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
	if (err)
		goto ex_abort;

	mlx4_sdbg("qpn 0x%x\n", qpn);
	atomic_dec(&qp->mtt->ref_count);
	mlx4_sdbg("base 0x%x, count %d\n", qp->mtt->com.res_id, atomic_read(&qp->mtt->ref_count));
	atomic_dec(&qp->rcq->ref_count);
	mlx4_sdbg("CQ 0x%x, ref count %d\n", qp->rcq->com.res_id, atomic_read(&qp->rcq->ref_count));
	atomic_dec(&qp->scq->ref_count);
	mlx4_sdbg("CQ 0x%x, ref count %d\n", qp->scq->com.res_id, atomic_read(&qp->scq->ref_count));
	if (qp->srq) {
		atomic_dec(&qp->srq->ref_count);
		mlx4_sdbg("srqn 0x%x\n", qp->srq->com.res_id);
	}
	res_end_move(dev, slave, RES_QP, qpn);

	mlx4_sdbg("qpn 0x%x\n", qpn);
	return 0;

ex_abort:
	res_abort_move(dev, slave, RES_QP, qpn);

	return err;
}

int mlx4_QUERY_QP_wrapper(struct mlx4_dev *dev, int slave,
			  struct mlx4_vhcr *vhcr,
			  struct mlx4_cmd_mailbox *inbox,
                          struct mlx4_cmd_mailbox *outbox,
			  struct mlx4_cmd_info *cmd)
{
	return gen_qp_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
}

int mlx4_INIT2INIT_QP_wrapper(struct mlx4_dev *dev, int slave,
			      struct mlx4_vhcr *vhcr,
			      struct mlx4_cmd_mailbox *inbox,
			      struct mlx4_cmd_mailbox *outbox,
			      struct mlx4_cmd_info *cmd)
{
	struct mlx4_qp_context *context = inbox->buf + 8;
	adjust_proxy_tun_qkey(dev, vhcr, context);
	update_pkey_index(dev, slave, inbox);
	return gen_qp_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
}

int mlx4_SUSPEND_QP_wrapper(struct mlx4_dev *dev, int slave,
			    struct mlx4_vhcr *vhcr,
			    struct mlx4_cmd_mailbox *inbox,
			    struct mlx4_cmd_mailbox *outbox,
			    struct mlx4_cmd_info *cmd)
{
	return gen_qp_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
}

int mlx4_UNSUSPEND_QP_wrapper(struct mlx4_dev *dev, int slave,
			      struct mlx4_vhcr *vhcr,
			      struct mlx4_cmd_mailbox *inbox,
			      struct mlx4_cmd_mailbox *outbox,
			      struct mlx4_cmd_info *cmd)
{
	return gen_qp_wrapper(dev, slave, vhcr, inbox, outbox, cmd);
}

static struct res_gid *find_gid(struct mlx4_dev *dev, int slave, struct res_qp *rqp, u8 *gid)
{
	struct res_gid *res;

	list_for_each_entry(res, &rqp->mcg_list, list) {
		if (!memcmp(res->gid, gid, 16))
			return res;
	}
	return NULL;
}

static int add_mcg_res(struct mlx4_dev *dev, int slave, struct res_qp *rqp,
		       u8 *gid, enum mlx4_protocol prot)
{
	struct res_gid *res;
	int err;

	res = kzalloc(sizeof *res, GFP_KERNEL);
	if (!res)
		return -ENOMEM;

	spin_lock_irq(&rqp->mcg_spl);
	if (find_gid(dev,slave,rqp,gid)) {
		kfree(res);
		err = -EEXIST;
	} else {
		memcpy(res->gid, gid, 16);
		res->prot = prot;
		list_add_tail(&res->list, &rqp->mcg_list);
		err = 0;
	}
	spin_unlock_irq(&rqp->mcg_spl);

	return err;
}

static int rem_mcg_res(struct mlx4_dev *dev, int slave, struct res_qp *rqp, u8 *gid,
		       enum mlx4_protocol prot)
{
	struct res_gid *res;
	int err;

	spin_lock_irq(&rqp->mcg_spl);
	res = find_gid(dev, slave, rqp, gid);
	if (!res || res->prot != prot)
		err = -EINVAL;
	else {
		list_del(&res->list);
		kfree(res);
		err = 0;
	}
	spin_unlock_irq(&rqp->mcg_spl);

	return err;
}

int mlx4_MCAST_wrapper(struct mlx4_dev *dev, int slave,
		       struct mlx4_vhcr *vhcr,
		       struct mlx4_cmd_mailbox *inbox,
		       struct mlx4_cmd_mailbox *outbox,
		       struct mlx4_cmd_info *cmd)
{
	struct mlx4_qp qp; /* dummy for calling attach/detach */
	u8 *gid = inbox->buf;
	enum mlx4_protocol prot = (vhcr->in_modifier >> 28) & 0x7;
	u8 pf_num = mlx4_priv(dev)->mfunc.master.slave_state[slave].pf_num;
	int err;
	int qpn = vhcr->in_modifier & 0x7fffff;
	struct res_qp *rqp;
	int attach = vhcr->op_modifier;
	int block_loopback = vhcr->in_modifier >> 31;

	err = get_res(dev, slave, qpn, RES_QP, &rqp);
	if (err) {
		mlx4_sdbg("qpn 0x%x, attach %d, block_loopback %d\n",
			  qpn, attach, block_loopback);
		return err;
	}

	if (prot == MLX4_PROT_ETH)
		gid[7] |= (pf_num << 4 | MLX4_MC_STEER << 1);

	qp.qpn = qpn;
	if (attach) {
		err = add_mcg_res(dev, slave, rqp, gid, prot);
		if (err) {
			mlx4_sdbg("\n");
			goto ex_put;
		}

		err = mlx4_qp_attach_common(dev, &qp, gid,
					    block_loopback, prot, MLX4_MC_STEER);
		if (err) {
			mlx4_sdbg("\n");
			goto ex_rem;
		}
	} else {
		err = rem_mcg_res(dev, slave, rqp, gid, prot);
		if (err) {
			mlx4_sdbg("\n");
			goto ex_put;
		}
		err = mlx4_qp_detach_common(dev, &qp, gid, prot, MLX4_MC_STEER);
		SASSERT(!err || err == -ENOMEM);
		if (err)
			mlx4_sdbg("qpn 0x%x, err %d\n", rqp->local_qpn, err);
	}

	put_res(dev, slave, qpn, RES_QP);
	return 0;

ex_rem:
	if (rem_mcg_res(dev, slave, rqp, gid, prot))
		SASSERT(0);
ex_put:
	put_res(dev, slave, qpn, RES_QP);

	return err;
}

enum {
	BUSY_MAX_RETRIES = 10
};

int mlx4_QUERY_IF_STAT_wrapper(struct mlx4_dev *dev, int slave,
			       struct mlx4_vhcr *vhcr,
                               struct mlx4_cmd_mailbox *inbox,
			       struct mlx4_cmd_mailbox *outbox,
			       struct mlx4_cmd_info *cmd)
{
	int err;
	int index = vhcr->in_modifier & 0xffff;

	err = get_res(dev, slave, index, RES_COUNTER, NULL);
	if (err)
		return err;

	err = mlx4_DMA_wrapper(dev, slave, vhcr, inbox, outbox, cmd);

	put_res(dev, slave, index, RES_COUNTER);
	return err;
}

static void dettach_qp(struct mlx4_dev *dev, int slave, struct res_qp *rqp)
{
	struct res_gid *rgid;
	struct res_gid *tmp;
	int err;
	struct mlx4_qp qp; /* dummy for calling attach/detach */

	list_for_each_entry_safe(rgid, tmp, &rqp->mcg_list, list) {
		qp.qpn = rqp->local_qpn;
		err = mlx4_qp_detach_common(dev, &qp, rgid->gid, rgid->prot, MLX4_MC_STEER);
		SASSERT(!err);
		list_del(&rgid->list);
		kfree(rgid);
	}
}

static int _move_all_busy(struct mlx4_dev *dev, int slave,
			  enum mlx4_resource type, int print)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_resource_tracker *tracker = &priv->mfunc.master.res_tracker;
	struct list_head *rlist = &tracker->slave_list[slave].res_list[type];
	struct res_common *r;
	struct res_common *tmp;
	int busy;

	busy = 0;
	spin_lock_irq(mlx4_tlock(dev));
	list_for_each_entry_safe(r, tmp, rlist, list) {
		SASSERT(r->owner == slave);
		if (r->owner == slave) {
			if (!r->removing) {
				if (r->state == RES_ANY_BUSY) {
					if (print)
						mlx4_sdbg("%s id 0x%x is busy\n", ResourceType(type), r->res_id);
					++busy;
				} else {
					r->from_state = r->state;
					r->state = RES_ANY_BUSY;
					r->removing = 1;
					mlx4_sdbg("%s id 0x%x was grabbed\n", ResourceType(type), r->res_id);
				}
			}
		}
	}
	spin_unlock_irq(mlx4_tlock(dev));

	return busy;
}

static int move_all_busy(struct mlx4_dev *dev, int slave, enum mlx4_resource type)
{
	unsigned long begin;
	int busy;

	begin = jiffies;
	do {
		busy = _move_all_busy(dev, slave, type, 0);
		if (time_after(jiffies, begin + 5 * HZ))
			break;
		if (busy)
			cond_resched();
	} while (busy);

	if (busy)
		busy = _move_all_busy(dev, slave, type, 1);

	return busy;
}
static void rem_slave_qps(struct mlx4_dev *dev, int slave)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_resource_tracker *tracker = &priv->mfunc.master.res_tracker;
	struct list_head *qp_list = &tracker->slave_list[slave].res_list[RES_QP];
	struct res_qp *qp;
	struct res_qp *tmp;
	int err;
	int state;
	u64 in_param;
	int qpn;

	err = move_all_busy(dev, slave, RES_QP);
	SASSERT(!err);

	spin_lock_irq(mlx4_tlock(dev));
	list_for_each_entry_safe(qp, tmp, qp_list, com.list) {
		spin_unlock_irq(mlx4_tlock(dev));
		if (qp->com.owner == slave) {
			qpn = qp->com.res_id;
			mlx4_sdbg("qpn 0x%x\n", qpn);
			dettach_qp(dev, slave, qp);

			mlx4_sdbg("qpn 0x%x\n", qpn);
			state = qp->com.from_state;
			while (state != 0) {
				switch (state) {
				case RES_QP_RESERVED:
					spin_lock_irq(mlx4_tlock(dev));
					radix_tree_delete(&tracker->res_tree[RES_QP], qp->com.res_id);
					list_del(&qp->com.list);
					spin_unlock_irq(mlx4_tlock(dev));
					kfree(qp);
					state = 0;
					mlx4_sdbg("qpn 0x%x deleted\n", qpn);
					break;
				case RES_QP_MAPPED:
					if (!valid_reserved(dev, slave, qpn))
						__mlx4_qp_free_icm(dev, qpn);
					state = RES_QP_RESERVED;
					mlx4_sdbg("qpn 0x%x moved to %s\n", qpn, qp_states_str(state));
					break;
				case RES_QP_HW:
					in_param = slave;
					err = mlx4_cmd(dev, in_param, qp->local_qpn, 2,
						       MLX4_CMD_2RST_QP, MLX4_CMD_TIME_CLASS_A, 1);
					SASSERT(!err);
					atomic_dec(&qp->rcq->ref_count);
					mlx4_sdbg("CQ 0x%x, ref count %d\n", qp->rcq->com.res_id, atomic_read(&qp->rcq->ref_count));
					atomic_dec(&qp->scq->ref_count);
					mlx4_sdbg("CQ 0x%x, ref count %d\n", qp->scq->com.res_id, atomic_read(&qp->scq->ref_count));
					atomic_dec(&qp->mtt->ref_count);
					if (qp->srq) {
						atomic_dec(&qp->srq->ref_count);
						mlx4_sdbg("srqn 0x%x\n", qp->srq->com.res_id);
					}
					state = RES_QP_MAPPED;
					mlx4_sdbg("qpn 0x%x moved to %s\n", qpn, qp_states_str(state));
					break;
				default:
					SASSERT(0);
					state = 0;
				}
			}
		}
		spin_lock_irq(mlx4_tlock(dev));
	}
	spin_unlock_irq(mlx4_tlock(dev));
}

static void rem_slave_srqs(struct mlx4_dev *dev, int slave)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_resource_tracker *tracker = &priv->mfunc.master.res_tracker;
	struct list_head *srq_list = &tracker->slave_list[slave].res_list[RES_SRQ];
	struct res_srq *srq;
	struct res_srq *tmp;
	int err;
	int state;
	u64 in_param;
	LIST_HEAD(tlist);
	int srqn;

	mlx4_sdbg("\n");
	err = move_all_busy(dev, slave, RES_SRQ);
	SASSERT(!err);

	spin_lock_irq(mlx4_tlock(dev));
	list_for_each_entry_safe(srq, tmp, srq_list, com.list) {
		spin_unlock_irq(mlx4_tlock(dev));
		if (srq->com.owner == slave) {
			srqn = srq->com.res_id;
			mlx4_sdbg("srqn 0x%x\n", srqn);
			state = srq->com.from_state;
			while (state != 0) {
				switch (state) {
				case RES_SRQ_ALLOCATED:
					__mlx4_srq_free_icm(dev, srqn);
					spin_lock_irq(mlx4_tlock(dev));
					radix_tree_delete(&tracker->res_tree[RES_SRQ], srqn);
					list_del(&srq->com.list);
					spin_unlock_irq(mlx4_tlock(dev));
					kfree(srq);
					state = 0;
					break;

				case RES_SRQ_HW:
					SASSERT(!atomic_read(&srq->ref_count));
					in_param = slave;
					err = mlx4_cmd(dev, in_param, srqn, 1,
						       MLX4_CMD_HW2SW_SRQ, MLX4_CMD_TIME_CLASS_A, 1);
					SASSERT(!err);

					atomic_dec(&srq->mtt->ref_count);
					if (srq->cq) {
						atomic_dec(&srq->cq->ref_count);
						mlx4_sdbg("CQ 0x%x, ref count %d\n", srq->cq->com.res_id, atomic_read(&srq->cq->ref_count));
					}

					state = RES_SRQ_ALLOCATED;
					break;

				default:
					SASSERT(0);
					state = 0;
				}
			}
		}
		spin_lock_irq(mlx4_tlock(dev));
	}
	spin_unlock_irq(mlx4_tlock(dev));
}

static void rem_slave_cqs(struct mlx4_dev *dev, int slave)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_resource_tracker *tracker = &priv->mfunc.master.res_tracker;
	struct list_head *cq_list = &tracker->slave_list[slave].res_list[RES_CQ];
	struct res_cq *cq;
	struct res_cq *tmp;
	int err;
	int state;
	u64 in_param;
	LIST_HEAD(tlist);
	int cqn;

	mlx4_sdbg("\n");
	err = move_all_busy(dev, slave, RES_CQ);
	SASSERT(!err);

	spin_lock_irq(mlx4_tlock(dev));
	list_for_each_entry_safe(cq, tmp, cq_list, com.list) {
		spin_unlock_irq(mlx4_tlock(dev));
		if (cq->com.owner == slave) {
			cqn = cq->com.res_id;
			mlx4_sdbg("cqn 0x%x, ref_count %d\n", cqn, atomic_read(&cq->ref_count));
			SASSERT(!atomic_read(&cq->ref_count));

			mlx4_sdbg("cqn 0x%x\n", cqn);
			state = cq->com.from_state;
			while (state != 0) {
				switch (state) {
				case RES_CQ_ALLOCATED:
					__mlx4_cq_free_icm(dev, cqn);
					spin_lock_irq(mlx4_tlock(dev));
					radix_tree_delete(&tracker->res_tree[RES_CQ], cqn);
					list_del(&cq->com.list);
					spin_unlock_irq(mlx4_tlock(dev));
					kfree(cq);
					state = 0;
					break;

				case RES_CQ_HW:
					in_param = slave;
					err = mlx4_cmd(dev, in_param, cqn, 1,
						       MLX4_CMD_HW2SW_CQ, MLX4_CMD_TIME_CLASS_A, 1);
					SASSERT(!err);

					atomic_dec(&cq->mtt->ref_count);
					state = RES_CQ_ALLOCATED;
					break;

				default:
					SASSERT(0);
					state = 0;
				}
			}
		}
		spin_lock_irq(mlx4_tlock(dev));
	}
	spin_unlock_irq(mlx4_tlock(dev));
}

static void rem_slave_mrs(struct mlx4_dev *dev, int slave)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_resource_tracker *tracker = &priv->mfunc.master.res_tracker;
	struct list_head *mpt_list = &tracker->slave_list[slave].res_list[RES_MPT];
	struct res_mpt *mpt;
	struct res_mpt *tmp;
	int err;
	int state;
	u64 in_param;
	LIST_HEAD(tlist);
	int mptn;
	int fmr_flow;

	mlx4_sdbg("\n");
	err = move_all_busy(dev, slave, RES_MPT);
	SASSERT(!err);

	spin_lock_irq(mlx4_tlock(dev));
	list_for_each_entry_safe(mpt, tmp, mpt_list, com.list) {
		spin_unlock_irq(mlx4_tlock(dev));
		if (mpt->com.owner == slave) {
			mptn = mpt->com.res_id;
			fmr_flow = mlx4_fmr_flow(dev, mpt->flags);
			mlx4_sdbg("mptn 0x%x\n", mptn);
			state = mpt->com.from_state;
			while (state != 0) {
				switch (state) {
				case RES_MPT_RESERVED:
					if (!fmr_flow)
						__mlx4_mr_release(dev,
								  mpt->key);
					spin_lock_irq(mlx4_tlock(dev));
					radix_tree_delete(&tracker->res_tree[RES_MPT], mptn);
					list_del(&mpt->com.list);
					spin_unlock_irq(mlx4_tlock(dev));
					kfree(mpt);
					state = 0;
					break;

				case RES_MPT_MAPPED:
					if (!fmr_flow)
						__mlx4_mr_free_icm(dev,
								   mpt->key,
								   MLX4_MR_FLAG_NONE);
					state = RES_MPT_RESERVED;
					break;

				case RES_MPT_HW:
					in_param = slave;
					err = mlx4_cmd(dev, in_param, mptn, 0,
						       MLX4_CMD_HW2SW_MPT, MLX4_CMD_TIME_CLASS_A, 1);
					SASSERT(!err);

					if (mpt->mtt)
						atomic_dec(&mpt->mtt->ref_count);
					state = RES_MPT_MAPPED;
					break;
				default:
					SASSERT(0);
					state = 0;
				}
			}
		}
		spin_lock_irq(mlx4_tlock(dev));
	}
	spin_unlock_irq(mlx4_tlock(dev));
}

static void rem_slave_mtts(struct mlx4_dev *dev, int slave)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_resource_tracker *tracker = &priv->mfunc.master.res_tracker;
	struct list_head *mtt_list = &tracker->slave_list[slave].res_list[RES_MTT];
	struct res_mtt *mtt;
	struct res_mtt *tmp;
	int state;
	LIST_HEAD(tlist);
	int base;
	int err;

	mlx4_sdbg("\n");
	err = move_all_busy(dev, slave, RES_MTT);
	SASSERT(!err);

	spin_lock_irq(mlx4_tlock(dev));
	list_for_each_entry_safe(mtt, tmp, mtt_list, com.list) {
		spin_unlock_irq(mlx4_tlock(dev));
		if (mtt->com.owner == slave) {
			base = mtt->com.res_id;
			mlx4_sdbg("base 0x%x, ref_count %d\n", base, atomic_read(&mtt->ref_count));
			SASSERT(!atomic_read(&mtt->ref_count));

			state = mtt->com.from_state;
			while (state != 0) {
				switch (state) {
				case RES_MTT_ALLOCATED:
					__mlx4_free_mtt_range(dev, base,
						mtt->order, MLX4_MR_FLAG_NONE);
					spin_lock_irq(mlx4_tlock(dev));
					radix_tree_delete(&tracker->res_tree[RES_MTT], base);
					list_del(&mtt->com.list);
					spin_unlock_irq(mlx4_tlock(dev));
					kfree(mtt);
					state = 0;
					break;
				case RES_MTT_RESERVED:
					__mlx4_free_mtt_reserved_range(
							dev, base, mtt->order);
					spin_lock_irq(mlx4_tlock(dev));
					radix_tree_delete(
						&tracker->res_tree[RES_MTT],
						base);
					list_del(&mtt->com.list);
					spin_unlock_irq(mlx4_tlock(dev));
					kfree(mtt);
					state = 0;
					break;
				default:
					SASSERT(0);
					state = 0;
				}
			}
		}
		spin_lock_irq(mlx4_tlock(dev));
	}
	spin_unlock_irq(mlx4_tlock(dev));
}

static void rem_slave_eqs(struct mlx4_dev *dev, int slave)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_resource_tracker *tracker = &priv->mfunc.master.res_tracker;
	struct list_head *eq_list = &tracker->slave_list[slave].res_list[RES_EQ];
	struct res_eq *eq;
	struct res_eq *tmp;
	int err;
	int state;
	LIST_HEAD(tlist);
	int eqn;
	struct mlx4_cmd_mailbox *mailbox;

	mlx4_sdbg("\n");
	err = move_all_busy(dev, slave, RES_EQ);
	SASSERT(!err);

	spin_lock_irq(mlx4_tlock(dev));
	list_for_each_entry_safe(eq, tmp, eq_list, com.list) {
		spin_unlock_irq(mlx4_tlock(dev));
		if (eq->com.owner == slave) {
			eqn = eq->com.res_id;
			mlx4_sdbg("eqn 0x%x\n", eqn);
			state = eq->com.from_state;
			while (state != 0) {
				switch (state) {
				case RES_EQ_RESERVED:
					spin_lock_irq(mlx4_tlock(dev));
					radix_tree_delete(&tracker->res_tree[RES_EQ], eqn);
					list_del(&eq->com.list);
					spin_unlock_irq(mlx4_tlock(dev));
					kfree(eq);
					state = 0;
					break;

				case RES_EQ_HW:
					mailbox = mlx4_alloc_cmd_mailbox(dev);
					if (IS_ERR(mailbox)) {
						mlx4_sdbg("\n");
						cond_resched();
						continue;
					}
					err = mlx4_cmd_box(dev, slave, 0, eqn & 0xff, 0,
							   MLX4_CMD_HW2SW_EQ, MLX4_CMD_TIME_CLASS_A, 1);
					SASSERT(!err);
					mlx4_free_cmd_mailbox(dev, mailbox);
					atomic_dec(&eq->mtt->ref_count);
					state = RES_EQ_RESERVED;
					break;

				default:
					SASSERT(0);
					state = 0;
				}
			}
		}
		spin_lock_irq(mlx4_tlock(dev));
	}
	spin_unlock_irq(mlx4_tlock(dev));
}

static void rem_slave_counters(struct mlx4_dev *dev, int slave)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_resource_tracker *tracker = &priv->mfunc.master.res_tracker;
	struct list_head *counter_list = &tracker->slave_list[slave].res_list[RES_COUNTER];
	struct res_counter *counter;
	struct res_counter *tmp;
	int err;
	int index;

	err = move_all_busy(dev, slave, RES_COUNTER);
	SASSERT(!err);

	spin_lock_irq(mlx4_tlock(dev));
	list_for_each_entry_safe(counter, tmp, counter_list, com.list) {
		if (counter->com.owner == slave) {
			index = counter->com.res_id;
			radix_tree_delete(&tracker->res_tree[RES_COUNTER], index);
			list_del(&counter->com.list);
			kfree(counter);
			__mlx4_counter_free(dev, index);
			mlx4_sdbg("deleted counter index %d\n", index);
		}
	}
	spin_unlock_irq(mlx4_tlock(dev));
}

static void rem_slave_xrcdns(struct mlx4_dev *dev, int slave)
{
	struct mlx4_priv *priv = mlx4_priv(dev);
	struct mlx4_resource_tracker *tracker = &priv->mfunc.master.res_tracker;
	struct list_head *xrcdn_list = &tracker->slave_list[slave].res_list[RES_XRCDN];
	struct res_xrcdn *xrcd;
	struct res_xrcdn *tmp;
	int err;
	int xrcdn;

	err = move_all_busy(dev, slave, RES_XRCDN);
	SASSERT(!err);

	spin_lock_irq(mlx4_tlock(dev));
	list_for_each_entry_safe(xrcd, tmp, xrcdn_list, com.list) {
		if (xrcd->com.owner == slave) {
			xrcdn = xrcd->com.res_id;
			radix_tree_delete(&tracker->res_tree[RES_XRCDN], xrcdn);
			list_del(&xrcd->com.list);
			kfree(xrcd);
			__mlx4_xrcd_free(dev, xrcdn);
			mlx4_sdbg("deleted xrcdn %d\n", xrcdn);
		}
	}
	spin_unlock_irq(mlx4_tlock(dev));
}

void mlx4_delete_all_resources_for_slave(struct mlx4_dev *dev, int slave)
{
	struct mlx4_priv *priv = mlx4_priv(dev);

	mlx4_sdbg("\n");
        mutex_lock(&priv->mfunc.master.res_tracker.slave_list[slave].mutex);
	/*VLAN*/
	/* MAC */
//	mlx4_sdbg("\n");
//	mlx4_delete_specific_res_type_for_slave(dev, slave, RES_MAC);

	mlx4_sdbg("\n");
	mlx4_fmr_master_delete_slave(dev, slave);
	mlx4_sdbg("\n");
	rem_slave_qps(dev, slave);
	mlx4_sdbg("\n");
	rem_slave_srqs(dev, slave);
	mlx4_sdbg("\n");
	rem_slave_cqs(dev, slave);
	mlx4_sdbg("\n");
	rem_slave_mrs(dev, slave);
	mlx4_sdbg("\n");
	rem_slave_eqs(dev, slave);
	mlx4_sdbg("\n");
	rem_slave_mtts(dev, slave);
	mlx4_sdbg("\n");
	rem_slave_counters(dev, slave);
	mlx4_sdbg("\n");
	rem_slave_xrcdns(dev, slave);
	mlx4_sdbg("\n");
	mutex_unlock(&priv->mfunc.master.res_tracker.slave_list[slave].mutex);
}

