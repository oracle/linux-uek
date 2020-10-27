/*
 * Copyright (c) 2006, 2020 Oracle and/or its affiliates.
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
 *
 */
#include <linux/kernel.h>
#include <linux/rculist.h>

#include <trace/events/rds.h>

#include "rds.h"
#include "ib.h"
#include "xlist.h"
#include "rds_single_path.h"

struct workqueue_struct *rds_ib_fmr_wq;

enum rds_ib_fr_state {
	MR_IS_INVALID,		/* mr ready to be used */
	MR_IS_VALID,		/* mr in use, marked before posting reg. wr */
	MR_IS_STALE,		/* mr is possibly corrupt, marked if failure */
};

#define RDS_MR_INV_WR_ID ((u64)0xefefefefefefefefULL)

/*
 * This is stored as mr->r_trans_private.
 */
struct rds_ib_mr {
	struct rds_ib_device	*device;
	struct rds_ib_mr_pool	*pool;
	struct rds_ib_connection *ic;

	struct ib_fmr		*fmr;
	struct ib_mr		*mr;
	enum rds_ib_fr_state	fr_state;
	struct completion	wr_comp;

	struct xlist_head	xlist;

	unsigned int		remap_count;

	struct scatterlist	*sg;
	unsigned int		sg_len;
	int			sg_dma_len;

	struct rds_sock		*rs;

	/* For busy_list and clean_list */
	struct list_head	pool_list;
	u64			free_time;
};

/*
 * Our own little FMR pool
 */
struct rds_ib_mr_pool {
	unsigned int		pool_type;
	struct mutex		flush_lock;		/* serialize fmr invalidate */
	struct delayed_work	flush_worker;		/* flush worker */

	atomic_t		item_count;		/* total # of MRs */
	atomic_t		dirty_count;		/* # dirty of MRs */

	struct xlist_head	drop_list;		/* MRs that have reached their max_maps limit */
	struct xlist_head	free_list;		/* unused MRs */
	struct list_head	clean_list;		/* cached MRs */
	/* "clean_list" concurrency */
	spinlock_t		clean_lock;

	wait_queue_head_t	flush_wait;

	atomic_t		free_pinned;		/* memory pinned by free MRs */
	unsigned long		max_items;
	atomic_t		max_items_soft;
	unsigned long		max_free_pinned;
	unsigned                unmap_fmr_cpu;
	struct ib_fmr_attr	fmr_attr;
	bool			use_fastreg;

	spinlock_t		busy_lock; /* protect ops on 'busy_list' */
	/* All in use MRs allocated from this pool are listed here. This list
	 * helps freeing up in use MRs when a ib_device got removed while it's
	 * resources are still in use in RDS layer. Protected by busy_lock.
	 */
	struct list_head	busy_list;

	/* Work queue for garbage collecting rds_ib_mr. */
	struct workqueue_struct *frwr_clean_wq;
	struct delayed_work	frwr_clean_worker;
	bool			condemned;
};

static int rds_ib_flush_mr_pool(struct rds_ib_mr_pool *pool, int free_all, struct rds_ib_mr **);
static void rds_ib_teardown_mr(struct rds_ib_mr *ibmr);
static void rds_ib_mr_pool_flush_worker(struct work_struct *work);

static int rds_ib_map_fastreg_mr(struct rds_ib_device *rds_ibdev,
				 struct rds_ib_mr *ibmr,
				 struct scatterlist *sg, unsigned int sg_len);

static void rds_frwr_clean_worker(struct work_struct *work);
static void rds_frwr_clean(struct rds_ib_mr_pool *pool, bool all);

struct rds_ib_device *rds_ib_get_device(const struct in6_addr *ipaddr)
{
	struct rds_ib_device *rds_ibdev;
	struct rds_ib_ipaddr *i_ipaddr;

	rcu_read_lock();
	list_for_each_entry_rcu(rds_ibdev, &rds_ib_devices, list) {
		list_for_each_entry_rcu(i_ipaddr, &rds_ibdev->ipaddr_list, list) {
			if (ipv6_addr_equal(&i_ipaddr->ipaddr, ipaddr)) {
				atomic_inc(&rds_ibdev->rid_refcount);
				rcu_read_unlock();
				return rds_ibdev;
			}
		}
	}
	rcu_read_unlock();

	return NULL;
}

/* kref deallocation function of the struct rds_rdma_dev_sock.
 */
void rds_rrds_free(struct kref *kref)
{
	struct rds_rdma_dev_sock *rrds;

	rrds = container_of(kref, struct rds_rdma_dev_sock, rrds_kref);
	rds_ib_dev_put(rrds->rrds_rds_ibdev);
	kfree(rrds);
}

/* Worker function of the rrds_free_work of a struct rds_rdma_dev_sock.  It
 * releases all the MRs used by a socket.
 */
static void rds_rdma_free_dev_rs_worker(struct work_struct *work)
{
	struct rds_rdma_dev_sock *rrds;
	struct rds_sock *rs;
	bool rs_released;

	rrds = container_of(work, struct rds_rdma_dev_sock, rrds_free_work);
	rs = rrds->rrds_rs;

	/* Set rrds_dev_released so that the rds_sock knows that we are
	 * executing.
	 */
	mutex_lock(&rs->rs_trans_lock);
	rs_released = rrds->rrds_rs_released;
	rrds->rrds_dev_released = true;
	mutex_unlock(&rs->rs_trans_lock);

	/* Release all the ibmrs if we are the only or first to be called.
	 * After that, set rs_trans_private to NULL so that the rds_sock
	 * will not find this rrds.
	 *
	 * If rs_released is set, rds_rdma_sock_release() will release all
	 * ibmrs.  So just let the rds_sock know that we are done.
	 */
	if (!rs_released) {
		rds_rdma_drop_keys(rs);

		mutex_lock(&rs->rs_trans_lock);
		rs->rs_trans_private = NULL;

		/* The rds_sock may find rrds before rs_trans_private is unset.
		 * So we cannot simply free this rrds.
		 */
		kref_put(&rrds->rrds_kref, rds_rrds_free);
		mutex_unlock(&rs->rs_trans_lock);
	}

	complete(&rrds->rrds_work_done);
}

/* Given an IP address, find the RDMA device associated with that address
 * and assign it to the given socket.
 *
 * @addr: find the device associated with this address.
 * @rs: the RDS socket to be assigned to the found device.
 *
 * After a device is found and assigned to the socket, the socket holds a
 * reference on that device.
 */
struct rds_ib_device *rds_rdma_rs_get_device(const struct in6_addr *addr,
					     struct rds_sock *rs)
{
	struct rds_ib_device *tmp_rid, *found_rid = NULL;
	struct rds_ib_ipaddr *ib_ipaddr;
	struct rds_rdma_dev_sock *rrds;
	unsigned long flags;

	mutex_lock(&rs->rs_trans_lock);

	rrds = (struct rds_rdma_dev_sock *)rs->rs_trans_private;
	if (rrds && !rrds->rrds_dev_released) {
		mutex_unlock(&rs->rs_trans_lock);
		return rrds->rrds_rds_ibdev;
	}

	rrds = kzalloc(sizeof(*rrds), GFP_KERNEL);
	if (!rrds) {
		mutex_unlock(&rs->rs_trans_lock);
		return NULL;
	}
	rrds->rrds_rs = rs;
	INIT_LIST_HEAD(&rrds->rrds_list);
	init_completion(&rrds->rrds_work_done);
	INIT_WORK(&rrds->rrds_free_work, rds_rdma_free_dev_rs_worker);
	kref_init(&rrds->rrds_kref);

	rcu_read_lock();

	list_for_each_entry_rcu(tmp_rid, &rds_ib_devices, list) {
		list_for_each_entry_rcu(ib_ipaddr, &tmp_rid->ipaddr_list,
					list) {
			if (ipv6_addr_equal(&ib_ipaddr->ipaddr, addr)) {
				found_rid = tmp_rid;
				goto addr_out;
			}
		}
	}

addr_out:
	if (!found_rid) {
		rcu_read_unlock();
		mutex_unlock(&rs->rs_trans_lock);
		kfree(rrds);
		return NULL;
	}

	/* Each rds_rdma_dev_sock holds a reference on the device. */
	rrds->rrds_rds_ibdev = found_rid;
	atomic_inc(&found_rid->rid_refcount);
	rs->rs_trans_private = rrds;

	spin_lock_irqsave(&found_rid->rid_rs_list_lock, flags);
	list_add_tail(&rrds->rrds_list, &found_rid->rid_rs_list);
	spin_unlock_irqrestore(&found_rid->rid_rs_list_lock, flags);

	rcu_read_unlock();
	mutex_unlock(&rs->rs_trans_lock);

	return found_rid;
}

static int rds_ib_add_ipaddr(struct rds_ib_device *rds_ibdev,
			     struct in6_addr *ipaddr)
{
	struct rds_ib_ipaddr *i_ipaddr;

	i_ipaddr = kmalloc(sizeof *i_ipaddr, GFP_KERNEL);
	if (!i_ipaddr)
		return -ENOMEM;

	i_ipaddr->ipaddr = *ipaddr;

	spin_lock_irq(&rds_ibdev->spinlock);
	list_add_tail_rcu(&i_ipaddr->list, &rds_ibdev->ipaddr_list);
	spin_unlock_irq(&rds_ibdev->spinlock);

	return 0;
}

static void rds_ib_remove_ipaddr(struct rds_ib_device *rds_ibdev,
				 struct in6_addr *ipaddr)
{
	struct rds_ib_ipaddr *i_ipaddr;
	struct rds_ib_ipaddr *to_free = NULL;

	spin_lock_irq(&rds_ibdev->spinlock);
	list_for_each_entry_rcu(i_ipaddr, &rds_ibdev->ipaddr_list, list) {
		if (ipv6_addr_equal(&i_ipaddr->ipaddr, ipaddr)) {
			list_del_rcu(&i_ipaddr->list);
			to_free = i_ipaddr;
			break;
		}
	}
	spin_unlock_irq(&rds_ibdev->spinlock);

	if (to_free)
		kfree_rcu(to_free, rcu_head);
}

int rds_ib_update_ipaddr(struct rds_ib_device *rds_ibdev,
			 struct in6_addr *ipaddr)
{
	struct rds_ib_device *rds_ibdev_old;

	rds_ibdev_old = rds_ib_get_device(ipaddr);
	if (!rds_ibdev_old)
		return rds_ib_add_ipaddr(rds_ibdev, ipaddr);

	if (rds_ibdev_old != rds_ibdev) {
		rds_ib_remove_ipaddr(rds_ibdev_old, ipaddr);
		rds_ib_dev_put(rds_ibdev_old);
		return rds_ib_add_ipaddr(rds_ibdev, ipaddr);
	}
	rds_ib_dev_put(rds_ibdev_old);

	return 0;
}

int rds_ib_add_conn(struct rds_ib_device *rds_ibdev,
		    struct rds_connection *conn)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	unsigned long flags;

	/* conn was previously on the nodev_conns_list */
	spin_lock_irqsave(&ib_nodev_conns_lock, flags);
	spin_lock(&rds_ibdev->spinlock);

	/* Note that old requests may still be processing while the module or
	 * device is going away or the connection is being destroyed.
	 */
	if (rds_ibdev->rid_mod_unload || rds_ibdev->rid_dev_rem ||
	    conn->c_destroy_in_prog) {
		spin_unlock(&rds_ibdev->spinlock);
		spin_unlock_irqrestore(&ib_nodev_conns_lock, flags);
		return -ENOMEM;
	}

	BUG_ON(list_empty(&ib_nodev_conns));
	BUG_ON(list_empty(&ic->ib_node));
	list_del_init(&ic->ib_node);

	ic->rds_ibdev = rds_ibdev;
	list_add_tail(&ic->ib_node, &rds_ibdev->conn_list);
	spin_unlock(&rds_ibdev->spinlock);

	spin_unlock_irqrestore(&ib_nodev_conns_lock, flags);

	atomic_inc(&rds_ibdev->rid_refcount);

	return 0;
}

void rds_ib_remove_conn(struct rds_ib_device *rds_ibdev, struct rds_connection *conn)
{
	struct rds_ib_connection *ic = conn->c_transport_data;
	unsigned long flags;

	/* place conn on nodev_conns_list */
	spin_lock_irqsave(&ib_nodev_conns_lock, flags);

	spin_lock(&rds_ibdev->spinlock);
	if (!list_empty(&ic->ib_node))
		list_del_init(&ic->ib_node);
	ic->rds_ibdev = NULL;
	spin_unlock(&rds_ibdev->spinlock);

	list_add_tail(&ic->ib_node, &ib_nodev_conns);

	spin_unlock_irqrestore(&ib_nodev_conns_lock, flags);

	rds_ib_dev_put(rds_ibdev);
}

/* Destroy all RDS/RDMA connections not associated with a device. */
void rds_ib_destroy_nodev_conns(void)
{
	struct rds_ib_connection *ic;
	unsigned long flags;

	/* Avoid calling conn_destroy with irqs off.  Note that while the
	 * loop is running, conns can be queued to the nodev list until
	 * rds_conn_destroy() is called on them.
	 */
	spin_lock_irqsave(&ib_nodev_conns_lock, flags);
	while (!list_empty(&ib_nodev_conns)) {
		ic = list_first_entry(&ib_nodev_conns, struct rds_ib_connection,
				      ib_node);
		list_del_init(&ic->ib_node);
		spin_unlock_irqrestore(&ib_nodev_conns_lock, flags);
		rds_conn_destroy(ic->conn, 1);
		spin_lock_irqsave(&ib_nodev_conns_lock, flags);
	}
	spin_unlock_irqrestore(&ib_nodev_conns_lock, flags);
}

static unsigned int get_unmap_fmr_cpu(struct rds_ib_device *rds_ibdev,
				      int pool_type)
{
	int index;
	int ib_node = rdsibdev_to_node(rds_ibdev);

	/* always returns a CPU core that is closer to
	 * IB device first if possible. As for now, the
	 * first two cpu cores are returned. For numa
	 * or non-numa system, cpumask_local_spread
	 * will take care of it.
	 */
	index = pool_type == RDS_IB_MR_8K_POOL ? 0 : 1;
	return cpumask_local_spread(index, ib_node);
}

static void rds_ib_queue_delayed_work_on(struct rds_ib_device *rds_ibdev,
					 int cpu,
					 struct workqueue_struct *wq,
					 struct delayed_work *dwork,
					 unsigned long delay,
					 char *reason)
{
	trace_rds_ib_queue_work(rds_ibdev, wq, &dwork->work, delay, reason);
	queue_delayed_work_on(cpu, wq, dwork, delay);
}

static void rds_ib_queue_cancel_work(struct rds_ib_device *rds_ibdev,
				     struct delayed_work *dwork,
				     char *reason)
{
	trace_rds_ib_queue_cancel_work(rds_ibdev, NULL, &dwork->work, 0,
				       reason);
	cancel_delayed_work_sync(dwork);
}

struct rds_ib_mr_pool *rds_ib_create_mr_pool(struct rds_ib_device *rds_ibdev,
						int pool_type)
{
	struct rds_ib_mr_pool *pool;
	unsigned int unmap_cpu;

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		return ERR_PTR(-ENOMEM);

	spin_lock_init(&pool->busy_lock);
	INIT_LIST_HEAD(&pool->busy_list);

	pool->pool_type = pool_type;
	INIT_XLIST_HEAD(&pool->free_list);
	INIT_XLIST_HEAD(&pool->drop_list);
	INIT_LIST_HEAD(&pool->clean_list);
	spin_lock_init(&pool->clean_lock);
	mutex_init(&pool->flush_lock);
	init_waitqueue_head(&pool->flush_wait);
	INIT_DELAYED_WORK(&pool->flush_worker, rds_ib_mr_pool_flush_worker);

	if (pool_type == RDS_IB_MR_1M_POOL) {
		pool->fmr_attr.max_pages = RDS_FMR_1M_MSG_SIZE + 1;
		pool->max_items = rds_ibdev->max_1m_fmrs;
		pool->unmap_fmr_cpu = get_unmap_fmr_cpu(rds_ibdev, pool_type);
	} else /* pool_type == RDS_IB_MR_8K_POOL */ {
		pool->fmr_attr.max_pages = RDS_FMR_8K_MSG_SIZE + 1;
		pool->max_items = rds_ibdev->max_8k_fmrs;
		pool->unmap_fmr_cpu = get_unmap_fmr_cpu(rds_ibdev, pool_type);
	}
	pool->max_free_pinned =
		pool->max_items * pool->fmr_attr.max_pages / 4;
	pool->fmr_attr.max_maps = rds_ibdev->fmr_max_remaps;
	pool->fmr_attr.page_shift = PAGE_SHIFT;
	atomic_set(&pool->max_items_soft, pool->max_items);

	if (rds_ibdev->use_fastreg) {
		INIT_DELAYED_WORK(&pool->frwr_clean_worker,
				  rds_frwr_clean_worker);
		pool->frwr_clean_wq = create_workqueue("rds_frmr_clean_wq");
		if (!pool->frwr_clean_wq) {
			kfree(pool);
			return ERR_PTR(-ENOMEM);
		}
		unmap_cpu = rds_ib_sysctl_disable_unmap_fmr_cpu ?
			WORK_CPU_UNBOUND : pool->unmap_fmr_cpu;
		rds_ib_queue_delayed_work_on(rds_ibdev, unmap_cpu,
					     pool->frwr_clean_wq,
					     &pool->frwr_clean_worker,
					     msecs_to_jiffies(rds_frwr_wake_intrvl),
					     "frwr clean");

		/* Should set this only when everything is set up.  Otherwise,
		 * if failure happens, the clean up routine will do the
		 * wrong thing.
		 */
		pool->use_fastreg = true;
	}

	return pool;
}

void rds_ib_get_mr_info(struct rds_ib_device *rds_ibdev, struct rds_info_rdma_connection *iinfo)
{
	struct rds_ib_mr_pool *pool_1m = rds_ibdev->mr_1m_pool;

	iinfo->rdma_mr_max = pool_1m->max_items;
	iinfo->rdma_mr_size = pool_1m->fmr_attr.max_pages;
}

#if IS_ENABLED(CONFIG_IPV6)
void rds6_ib_get_mr_info(struct rds_ib_device *rds_ibdev,
			 struct rds6_info_rdma_connection *iinfo6)
{
	struct rds_ib_mr_pool *pool_1m = rds_ibdev->mr_1m_pool;

	iinfo6->rdma_mr_max = pool_1m->max_items;
	iinfo6->rdma_mr_size = pool_1m->fmr_attr.max_pages;
}
#endif

void rds_ib_destroy_mr_pool(struct rds_ib_mr_pool *pool)
{
	struct rds_ib_mr *ibmr;
	LIST_HEAD(drp_list);

	pool->condemned = true;

	/* move MRs in in-use list to drop or free list */
	spin_lock_bh(&pool->busy_lock);
	list_splice_init(&pool->busy_list, &drp_list);
	spin_unlock_bh(&pool->busy_lock);

	/* rds_rdma_drop_keys may drops more than one MRs in one iteration */
	while (!list_empty(&drp_list)) {
		ibmr = list_first_entry(&drp_list, struct rds_ib_mr, pool_list);
		list_del_init(&ibmr->pool_list);
		if (ibmr->rs)
			rds_rdma_drop_keys(ibmr->rs);
	}

	if (pool->use_fastreg) {
		/* No need to call rds_frwr_clean() as rds_ib_flush_mr_pool()
		 * with free_all set to 1 calls rds_frwr_clean().
		 */
		rds_ib_queue_cancel_work(NULL,
					 &pool->frwr_clean_worker,
					"cancel frwr worker, destroy MR pool");
		destroy_workqueue(pool->frwr_clean_wq);
	}
	rds_ib_queue_cancel_work(NULL, &pool->flush_worker,
				 "cancel flush worker, destroy MR pool");
	rds_ib_flush_mr_pool(pool, 1, NULL);

	WARN_ON(atomic_read(&pool->item_count));
	WARN_ON(atomic_read(&pool->free_pinned));
	kfree(pool);
}

static inline struct rds_ib_mr *rds_ib_reuse_fmr(struct rds_ib_mr_pool *pool)
{
	struct rds_ib_mr *ibmr = NULL;
	unsigned long flags;

	spin_lock_irqsave(&pool->clean_lock, flags);
	if (!list_empty(&pool->clean_list))
		ibmr = list_last_entry(&pool->clean_list, struct rds_ib_mr,
				       pool_list);
	if (ibmr)
		list_del_rcu(&ibmr->pool_list);
	spin_unlock_irqrestore(&pool->clean_lock, flags);

	if (ibmr) {
		spin_lock_bh(&pool->busy_lock);
		list_add(&ibmr->pool_list, &pool->busy_list);
		spin_unlock_bh(&pool->busy_lock);
	}
	return ibmr;
}

static int rds_ib_init_fastreg_mr(struct rds_ib_device *rds_ibdev,
				  struct rds_ib_mr_pool *pool,
				  struct rds_ib_mr *ibmr)
{
	struct ib_mr *mr = NULL;
	int err;

	mr = ib_alloc_mr(rds_ibdev->pd, IB_MR_TYPE_MEM_REG, pool->fmr_attr.max_pages);
	if (IS_ERR(mr)) {
		err = PTR_ERR(mr);
		pr_warn("RDS/IB: ib_alloc_fast_reg_mr failed (err=%d)\n", err);
		return err;
	}

	ibmr->mr = mr;
	return 0;
}

static int rds_ib_init_fmr(struct rds_ib_device *rds_ibdev,
			   struct rds_ib_mr_pool *pool,
			   struct rds_ib_mr *ibmr)
{
	int err;

	ibmr->fmr = ib_alloc_fmr(rds_ibdev->pd,
			(IB_ACCESS_LOCAL_WRITE |
			 IB_ACCESS_REMOTE_READ |
			 IB_ACCESS_REMOTE_WRITE |
			 IB_ACCESS_REMOTE_ATOMIC),
			&pool->fmr_attr);
	if (IS_ERR(ibmr->fmr)) {
		err = PTR_ERR(ibmr->fmr);
		ibmr->fmr = NULL;
		return err;
	}

	return 0;
}

static struct rds_ib_mr *rds_ib_alloc_ibmr(struct rds_ib_device *rds_ibdev,
					   int npages)
{
	struct rds_ib_mr_pool *pool;
	struct rds_ib_mr *ibmr = NULL;
	unsigned int unmap_fmr_cpu = 0;
	int err = 0, iter = 0;

	if (npages <= RDS_FMR_8K_MSG_SIZE)
		pool = rds_ibdev->mr_8k_pool;
	else
		pool = rds_ibdev->mr_1m_pool;

	unmap_fmr_cpu = rds_ib_sysctl_disable_unmap_fmr_cpu ?
		WORK_CPU_UNBOUND : pool->unmap_fmr_cpu;
	if (atomic_read(&pool->dirty_count) >=
		atomic_read(&pool->max_items_soft) / 10)
		rds_ib_queue_delayed_work_on(rds_ibdev, unmap_fmr_cpu,
					     rds_ib_fmr_wq, &pool->flush_worker,
					     10, "dirty count too high");

	while (1) {
		ibmr = rds_ib_reuse_fmr(pool);
		if (ibmr)
			return ibmr;

		/* No clean MRs - now we have the choice of either
		 * allocating a fresh MR up to the limit imposed by the
		 * driver, or flush any dirty unused MRs.
		 * We try to avoid stalling in the send path if possible,
		 * so we allocate as long as we're allowed to.
		 *
		 * We're fussy with enforcing the FMR limit, though. If the driver
		 * tells us we can't use more than N fmrs, we shouldn't start
		 * arguing with it */
		if (atomic_inc_return(&pool->item_count) <=
					atomic_read(&pool->max_items_soft))
			break;

		atomic_dec(&pool->item_count);

		/* FRWR MR goes directly to the clean list.  If the limit is
		 * already reached, return an error.
		 */
		if (++iter > 2 || rds_ibdev->use_fastreg) {
			if (pool->pool_type == RDS_IB_MR_8K_POOL)
				rds_ib_stats_inc(s_ib_rdma_mr_8k_pool_depleted);
			else
				rds_ib_stats_inc(s_ib_rdma_mr_1m_pool_depleted);
			return ERR_PTR(-EAGAIN);
		}

		/* We do have some empty MRs. Flush them out. */
		if (pool->pool_type == RDS_IB_MR_8K_POOL)
			rds_ib_stats_inc(s_ib_rdma_mr_8k_pool_wait);
		else
			rds_ib_stats_inc(s_ib_rdma_mr_1m_pool_wait);
		rds_ib_flush_mr_pool(pool, 0, &ibmr);
		if (ibmr)
			return ibmr;
	}

	ibmr = kzalloc(sizeof(*ibmr), GFP_KERNEL);
	if (!ibmr) {
		err = -ENOMEM;
		goto out_no_cigar;
	}

	if (rds_ibdev->use_fastreg)
		err = rds_ib_init_fastreg_mr(rds_ibdev, pool, ibmr);
	else
		err = rds_ib_init_fmr(rds_ibdev, pool, ibmr);

	if (err) {
		int total_pool_size;
		int prev_8k_max;
		int prev_1m_max;

		if (err != -ENOMEM)
			goto out_no_cigar;

		/* Re-balance the pool sizes to reflect the memory resources
		 * available to the VM.
		 */
		total_pool_size =
			atomic_read(&rds_ibdev->mr_8k_pool->item_count)
				* (RDS_FMR_8K_MSG_SIZE + 1) +
			atomic_read(&rds_ibdev->mr_1m_pool->item_count)
				* RDS_FMR_1M_MSG_SIZE;

		if (!total_pool_size)
			goto out_no_cigar;

		prev_8k_max = atomic_read(
				&rds_ibdev->mr_8k_pool->max_items_soft);
		prev_1m_max = atomic_read(
				&rds_ibdev->mr_1m_pool->max_items_soft);
		atomic_set(&rds_ibdev->mr_8k_pool->max_items_soft,
			   (total_pool_size / 4) / (RDS_FMR_8K_MSG_SIZE + 1));
		atomic_set(&rds_ibdev->mr_1m_pool->max_items_soft,
			   (total_pool_size * 3 / 4) / RDS_FMR_1M_MSG_SIZE);
		printk(KERN_ERR "RDS/IB: Adjusted 8K FMR pool (%d->%d)\n",
		       prev_8k_max,
		       atomic_read(&rds_ibdev->mr_8k_pool->max_items_soft));
		printk(KERN_ERR "RDS/IB: Adjusted 1M FMR pool (%d->%d)\n",
		       prev_1m_max,
		       atomic_read(&rds_ibdev->mr_1m_pool->max_items_soft));
		if (pool == rds_ibdev->mr_1m_pool) {
			rds_ib_flush_mr_pool(rds_ibdev->mr_1m_pool, 0, NULL);
			rds_ib_flush_mr_pool(rds_ibdev->mr_8k_pool, 1, NULL);
		} else {
			rds_ib_flush_mr_pool(rds_ibdev->mr_1m_pool, 1, NULL);
			rds_ib_flush_mr_pool(rds_ibdev->mr_8k_pool, 0, NULL);
		}
		err = -EAGAIN;
		goto out_no_cigar;
	}

	INIT_LIST_HEAD(&ibmr->pool_list);
	spin_lock_bh(&pool->busy_lock);
	list_add(&ibmr->pool_list, &pool->busy_list);
	spin_unlock_bh(&pool->busy_lock);

	init_completion(&ibmr->wr_comp);
	ibmr->fr_state = MR_IS_INVALID; /* not needed bcas of kzalloc */

	ibmr->pool = pool;
	if (pool->pool_type == RDS_IB_MR_8K_POOL)
		rds_ib_stats_inc(s_ib_rdma_mr_8k_alloc);
	else
		rds_ib_stats_inc(s_ib_rdma_mr_1m_alloc);

	atomic_add_unless(&pool->max_items_soft, 1, pool->max_items);

	return ibmr;

out_no_cigar:
	if (ibmr)
		kfree(ibmr);
	atomic_dec(&pool->item_count);
	return ERR_PTR(err);
}

static int rds_ib_map_fmr(struct rds_ib_device *rds_ibdev, struct rds_ib_mr *ibmr,
	       struct scatterlist *sg, unsigned int nents)
{
	struct ib_device *dev = rds_ibdev->dev;
	struct scatterlist *scat = sg;
	u64 io_addr = 0;
	u64 *dma_pages;
	u32 len;
	int page_cnt, sg_dma_len;
	int i, j;
	int ret;

	sg_dma_len = ib_dma_map_sg(dev, sg, nents,
				 DMA_BIDIRECTIONAL);
	if (unlikely(!sg_dma_len)) {
		printk(KERN_WARNING "RDS/IB: dma_map_sg failed!\n");
		return -EBUSY;
	}

	len = 0;
	page_cnt = 0;

	for (i = 0; i < sg_dma_len; ++i) {
		unsigned int dma_len = sg_dma_len(&scat[i]);
		u64 dma_addr = sg_dma_address(&scat[i]);

		if (dma_addr & ~PAGE_MASK) {
			if (i > 0)
				return -EINVAL;
			else
				++page_cnt;
		}
		if ((dma_addr + dma_len) & ~PAGE_MASK) {
			if (i < sg_dma_len - 1)
				return -EINVAL;
			else
				++page_cnt;
		}

		len += dma_len;
	}

	page_cnt += len >> PAGE_SHIFT;
	if (page_cnt > ibmr->pool->fmr_attr.max_pages)
		return -EINVAL;

	dma_pages = kmalloc(sizeof(u64) * page_cnt, GFP_ATOMIC);
	if (!dma_pages)
		return -ENOMEM;

	page_cnt = 0;
	for (i = 0; i < sg_dma_len; ++i) {
		unsigned int dma_len = sg_dma_len(&scat[i]);
		u64 dma_addr = sg_dma_address(&scat[i]);

		for (j = 0; j < dma_len; j += PAGE_SIZE)
			dma_pages[page_cnt++] =
				(dma_addr & PAGE_MASK) + j;
	}

	ret = ib_map_phys_fmr(ibmr->fmr,
				   dma_pages, page_cnt, io_addr);
	if (ret)
		goto out;

	/* Success - we successfully remapped the MR, so we can
	 * safely tear down the old mapping. */
	rds_ib_teardown_mr(ibmr);

	ibmr->sg = scat;
	ibmr->sg_len = nents;
	ibmr->sg_dma_len = sg_dma_len;
	ibmr->remap_count++;

	if (ibmr->pool->pool_type == RDS_IB_MR_8K_POOL)
		rds_ib_stats_inc(s_ib_rdma_mr_8k_used);
	else
		rds_ib_stats_inc(s_ib_rdma_mr_1m_used);
	ret = 0;

out:
	kfree(dma_pages);

	return ret;
}

void rds_ib_sync_mr(void *trans_private, int direction)
{
	struct rds_ib_mr *ibmr = trans_private;
	struct rds_ib_device *rds_ibdev = ibmr->device;

	switch (direction) {
	case DMA_FROM_DEVICE:
		ib_dma_sync_sg_for_cpu(rds_ibdev->dev, ibmr->sg,
			ibmr->sg_dma_len, DMA_BIDIRECTIONAL);
		break;
	case DMA_TO_DEVICE:
		ib_dma_sync_sg_for_device(rds_ibdev->dev, ibmr->sg,
			ibmr->sg_dma_len, DMA_BIDIRECTIONAL);
		break;
	}
}

static void __rds_ib_teardown_mr(struct rds_ib_mr *ibmr)
{
	struct rds_ib_device *rds_ibdev = ibmr->device;

	if (ibmr->sg_dma_len) {
		ib_dma_unmap_sg(rds_ibdev->dev,
				ibmr->sg, ibmr->sg_len,
				DMA_BIDIRECTIONAL);
		ibmr->sg_dma_len = 0;
	}

	/* Release the s/g list */
	if (ibmr->sg_len) {
		unsigned int i;

		for (i = 0; i < ibmr->sg_len; ++i) {
			struct page *page = sg_page(&ibmr->sg[i]);

			/* FIXME we need a way to tell a r/w MR
			 * from a r/o MR */
			WARN_ON_ONCE(!page->mapping && irqs_disabled());
			set_page_dirty(page);
			put_page(page);
		}
		kfree(ibmr->sg);

		ibmr->sg = NULL;
		ibmr->sg_len = 0;
	}
}

static void rds_ib_teardown_mr(struct rds_ib_mr *ibmr)
{
	unsigned int pinned = ibmr->sg_len;

	__rds_ib_teardown_mr(ibmr);
	if (pinned) {
		struct rds_ib_mr_pool *pool = ibmr->pool;

		atomic_sub(pinned, &pool->free_pinned);
	}
}

static inline unsigned int rds_ib_flush_goal(struct rds_ib_mr_pool *pool, int free_all)
{
	unsigned int item_count;

	item_count = atomic_read(&pool->item_count);
	if (free_all)
		return item_count;

	return 0;
}

/*
 * given an xlist of mrs, put them all into the list_head for more processing
 */
static int xlist_append_to_list(struct xlist_head *xlist,
				struct list_head *list)
{
	struct rds_ib_mr *ibmr;
	struct xlist_head splice;
	struct xlist_head *cur;
	struct xlist_head *next;
	int count = 0;

	splice.next = NULL;
	xlist_splice(xlist, &splice);
	cur = splice.next;
	while (cur) {
		next = cur->next;
		ibmr = list_entry(cur, struct rds_ib_mr, xlist);
		list_add_tail(&ibmr->pool_list, list);
		cur = next;
		count++;
	}
	return count;
}

/*
 * Flush our pool of MRs.
 * At a minimum, all currently unused MRs are unmapped.
 * If the number of MRs allocated exceeds the limit, we also try
 * to free as many MRs as needed to get back to this limit.
 */
static int rds_ib_flush_mr_pool(struct rds_ib_mr_pool *pool,
				int free_all, struct rds_ib_mr **ibmr_ret)
{
	struct rds_ib_mr *ibmr, *next;
	LIST_HEAD(unmap_list);
	LIST_HEAD(fmr_list);
	unsigned long unpinned = 0;
	unsigned int nfreed = 0, dirty_to_clean = 0, free_goal;
	unsigned long flags;
	int ret = 0;

	if (pool->pool_type == RDS_IB_MR_8K_POOL)
		rds_ib_stats_inc(s_ib_rdma_mr_8k_pool_flush);
	else
		rds_ib_stats_inc(s_ib_rdma_mr_1m_pool_flush);

	/* For FRWR, MRs are cleaned periodically.  Only if all MRs need
	 * to be flushed, there is no need to do anything here.
	 */
	if (pool->use_fastreg) {
		if (free_all)
			rds_frwr_clean(pool, true);
		return ret;
	}

	if (ibmr_ret) {
		DEFINE_WAIT(wait);
		while (!mutex_trylock(&pool->flush_lock)) {
			ibmr = rds_ib_reuse_fmr(pool);
			if (ibmr) {
				*ibmr_ret = ibmr;
				finish_wait(&pool->flush_wait, &wait);
				goto out_nolock;
			}

			prepare_to_wait(&pool->flush_wait, &wait,
					TASK_UNINTERRUPTIBLE);
			if (list_empty(&pool->clean_list))
				schedule();

			ibmr = rds_ib_reuse_fmr(pool);
			if (ibmr) {
				*ibmr_ret = ibmr;
				finish_wait(&pool->flush_wait, &wait);
				goto out_nolock;
			}
		}
		finish_wait(&pool->flush_wait, &wait);
	} else
		mutex_lock(&pool->flush_lock);

	if (ibmr_ret) {
		ibmr = rds_ib_reuse_fmr(pool);
		if (ibmr) {
			*ibmr_ret = ibmr;
			goto out;
		}
	}

	/* Get the list of all MRs to be dropped. Ordering matters -
	 * we want to put drop_list ahead of free_list.
	 */
	dirty_to_clean = xlist_append_to_list(&pool->drop_list, &unmap_list);
	dirty_to_clean += xlist_append_to_list(&pool->free_list, &unmap_list);
	if (free_all) {
		spin_lock_irqsave(&pool->clean_lock, flags);
		list_splice_init(&pool->clean_list, &unmap_list);
		spin_unlock_irqrestore(&pool->clean_lock, flags);
	}

	free_goal = rds_ib_flush_goal(pool, free_all);

	if (list_empty(&unmap_list))
		goto out;

	if (!pool->use_fastreg) {
		/* String all ib_mrs onto one list and hand them to
		 * ib_unmap_fmr
		 */
		list_for_each_entry(ibmr, &unmap_list, pool_list)
			list_add(&ibmr->fmr->list, &fmr_list);

		ret = ib_unmap_fmr(&fmr_list);
		if (ret)
			pr_warn("RDS/IB: ib_unmap_fmr failed (err=%d)\n", ret);
	}

	/* Now we can destroy the DMA mapping and unpin any pages */
	list_for_each_entry_safe(ibmr, next, &unmap_list, pool_list) {
		/* Teardown only FMRs here, teardown fastreg MRs later after
		 * invalidating. However, increment 'unpinned' for both, since
		 * it is used to trigger flush.
		 */
		unpinned += ibmr->sg_len;
		if (!pool->use_fastreg)
			__rds_ib_teardown_mr(ibmr);

		if (nfreed < free_goal ||
		    (!pool->use_fastreg &&
		     ibmr->remap_count >= pool->fmr_attr.max_maps) ||
		    (pool->use_fastreg && ibmr->fr_state == MR_IS_STALE)) {
			if (ibmr->pool->pool_type == RDS_IB_MR_8K_POOL)
				rds_ib_stats_inc(s_ib_rdma_mr_8k_free);
			else
				rds_ib_stats_inc(s_ib_rdma_mr_1m_free);
			list_del(&ibmr->pool_list);
			if (pool->use_fastreg) {
				__rds_ib_teardown_mr(ibmr);
				if (ibmr->mr)
					ib_dereg_mr(ibmr->mr);
			} else {
				ib_dealloc_fmr(ibmr->fmr);
			}
			kfree(ibmr);
			nfreed++;
		}
	}

	if (!list_empty(&unmap_list)) {
		spin_lock_irqsave(&pool->clean_lock, flags);
		list_splice(&unmap_list, &pool->clean_list);
		if (ibmr_ret) {
			ibmr = list_first_entry(&pool->clean_list,
						struct rds_ib_mr,
						pool_list);
			list_del_init(&ibmr->pool_list);
		}
		spin_unlock_irqrestore(&pool->clean_lock, flags);

		/* add ibmr to busy_list before handing over */
		if (ibmr_ret) {
			spin_lock_bh(&pool->busy_lock);
			list_add(&ibmr->pool_list, &pool->busy_list);
			spin_unlock_bh(&pool->busy_lock);

			*ibmr_ret = ibmr;
		}
	}

	atomic_sub(unpinned, &pool->free_pinned);
	atomic_sub(dirty_to_clean, &pool->dirty_count);
	atomic_sub(nfreed, &pool->item_count);

out:
	mutex_unlock(&pool->flush_lock);
	if (waitqueue_active(&pool->flush_wait))
		wake_up(&pool->flush_wait);
out_nolock:
	return ret;
}

int rds_ib_fmr_init(void)
{
	rds_ib_fmr_wq = create_workqueue("rds_fmr_flushd");
	if (!rds_ib_fmr_wq) {
		pr_err("%s: failed to create rds_ib_fmr_wq\n", __func__);
		return -ENOMEM;
	}
	return 0;
}

/*
 * By the time this is called all the IB devices should have been torn down and
 * had their pools freed.  As each pool is freed its work struct is waited on,
 * so the pool flushing work queue should be idle by the time we get here.
 */
void rds_ib_fmr_exit(void)
{
	destroy_workqueue(rds_ib_fmr_wq);
}

static void rds_ib_mr_pool_flush_worker(struct work_struct *work)
{
	struct rds_ib_mr_pool *pool = container_of(work, struct rds_ib_mr_pool, flush_worker.work);

	trace_rds_ib_queue_worker(NULL, rds_ib_fmr_wq, work, 0,
				  "MR pool flush worker");
	rds_ib_flush_mr_pool(pool, 0, NULL);
}

static int rds_ib_fastreg_inv(struct rds_ib_mr *ibmr)
{
	struct ib_send_wr s_wr;
	const struct ib_send_wr *failed_wr;
	atomic_t *n_wrs = &ibmr->device->fastreg_wrs;
	int ret = 0;

	down_read(&ibmr->device->fastreg_lock);

	if (ibmr->fr_state != MR_IS_VALID)
		goto out;

	while (atomic_sub_return(1, n_wrs) <= 0) {
		atomic_add(1, n_wrs);
		/* Depending on how many times schedule() is called,
		 * we could replace it with wait_event() in future.
		 */
		schedule();
	}

	ibmr->fr_state = MR_IS_INVALID;

	memset(&s_wr, 0, sizeof(s_wr));
	s_wr.wr_id = (u64)ibmr;
	s_wr.opcode = IB_WR_LOCAL_INV;
	s_wr.ex.invalidate_rkey = ibmr->mr->rkey;
	s_wr.send_flags = IB_SEND_SIGNALED;

	failed_wr = &s_wr;
	ret = ib_post_send(ibmr->device->fastreg_qp, &s_wr, &failed_wr);
	WARN_ON(failed_wr != &s_wr);
	if (ret) {
		atomic_add(1, n_wrs);
		ibmr->fr_state = MR_IS_STALE;
		pr_warn_ratelimited("RDS/IB: %s:%d ib_post_send returned %d\n",
				    __func__, __LINE__, ret);
		goto out;
	}

	wait_for_completion(&ibmr->wr_comp);
	atomic_add(1, n_wrs);

 out:
	up_read(&ibmr->device->fastreg_lock);
	return ret;
}

/* FRWR rds_ib_mr GC function.  If an rds_ib_mr is freed more than
 * rds_frwr_ibmr_gc_time eariler, it will be cleaned.  If clean_all
 * is true, all rds_ib_mr will be cleaned regardless of their freed
 * time.
 */
static void rds_frwr_clean(struct rds_ib_mr_pool *pool, bool clean_all)
{
	struct rds_ib_mr *ibmr, *tmp_ibmr;
	LIST_HEAD(free_list);
	unsigned long flags;
	u64 now, gc_time;
	u32 cnt = 0;

	gc_time = msecs_to_jiffies(rds_frwr_ibmr_gc_time);
	now = get_jiffies_64();

	if (clean_all) {
		spin_lock_irqsave(&pool->clean_lock, flags);
		list_splice_init(&pool->clean_list, &free_list);
		spin_unlock_irqrestore(&pool->clean_lock, flags);
	} else {
		rcu_read_lock();
		ibmr = list_first_or_null_rcu(&pool->clean_list,
					      struct rds_ib_mr, pool_list);
		/* The first one is the oldest.  So if the first one is not
		 * old enough, there is nothing to be cleaned.
		 */
		if (!ibmr || (now - ibmr->free_time < gc_time)) {
			rcu_read_unlock();
			return;
		}
		spin_lock_irqsave(&pool->clean_lock, flags);
		list_for_each_entry_rcu(ibmr, &pool->clean_list, pool_list) {
			if (now - ibmr->free_time < gc_time) {
				list_cut_position(&free_list, &pool->clean_list,
						  &ibmr->pool_list);
				break;
			} else if (list_is_last(&ibmr->pool_list,
						&pool->clean_list)) {
				/* The whole list is old. */
				list_splice_init(&pool->clean_list, &free_list);
				break;
			}
		}
		spin_unlock_irqrestore(&pool->clean_lock, flags);
		rcu_read_unlock();
	}

	if (list_empty(&free_list))
		return;

	list_for_each_entry_safe(ibmr, tmp_ibmr, &free_list, pool_list) {
		int ret;

		cnt++;
		ret = rds_ib_fastreg_inv(ibmr);
		__rds_ib_teardown_mr(ibmr);
		if (ibmr->mr)
			ib_dereg_mr(ibmr->mr);
		kfree(ibmr);
	}
	atomic_sub(cnt, &pool->item_count);
}

static void rds_frwr_clean_worker(struct work_struct *work)
{
	struct rds_ib_mr_pool *pool;
	unsigned int unmap_cpu;
	u32 fuzz;

	trace_rds_ib_queue_worker(NULL, rds_ib_fmr_wq, work, 0,
				  "frwr clean worker");
	pool = container_of(work, struct rds_ib_mr_pool,
			    frwr_clean_worker.work);
	/* The pool is being destroyed, just return. */
	if (pool->condemned)
		return;

	rds_frwr_clean(pool, false);
	unmap_cpu = rds_ib_sysctl_disable_unmap_fmr_cpu ?
		WORK_CPU_UNBOUND : pool->unmap_fmr_cpu;

	/* Restart the timer.  Add some fuzz (quarter of the interval) to
	 * avoid GC workers of different pools of the same device waking
	 * up at the same time.
	 */
	get_random_bytes(&fuzz, sizeof(fuzz));
	fuzz %= rds_frwr_wake_intrvl >> 2;
	rds_ib_queue_delayed_work_on(NULL, unmap_cpu, pool->frwr_clean_wq,
				     &pool->frwr_clean_worker,
				     msecs_to_jiffies(rds_frwr_wake_intrvl + fuzz),
				     "frwr clean worker");
}

static inline void __rds_frwr_free_mr(struct rds_ib_mr_pool *pool,
				      struct rds_ib_mr *ibmr,
				      int invalidate)
{
	unsigned long flags;

	if (invalidate) {
		int ret;

		ret = rds_ib_fastreg_inv(ibmr);
		if (ret)
			pr_warn_ratelimited("RDS: %s fail (err=%d)\n",
					    __func__, ret);
	}

	/* FWRW MR goes directly to the clean list for immediate
	 * reuse.
	 *
	 * If it is stale, destroy it here as it should be an
	 * uncommon case.  Otherwise, add it to the tail of clean
	 * list.  The FRWR clean list is LIFO.
	 */
	if (ibmr->fr_state == MR_IS_STALE) {
		__rds_ib_teardown_mr(ibmr);
		if (ibmr->mr)
			ib_dereg_mr(ibmr->mr);
		kfree(ibmr);
		atomic_dec(&pool->item_count);
	} else {
		ibmr->free_time = get_jiffies_64();
		spin_lock_irqsave(&pool->clean_lock, flags);
		list_add_tail_rcu(&ibmr->pool_list, &pool->clean_list);
		spin_unlock_irqrestore(&pool->clean_lock, flags);
	}
}

void rds_ib_free_mr(void *trans_private, int invalidate)
{
	struct rds_ib_mr *ibmr = trans_private;
	struct rds_ib_device *rds_ibdev = ibmr->device;
	struct rds_ib_mr_pool *pool = ibmr->pool;
	unsigned int unmap_fmr_cpu = rds_ib_sysctl_disable_unmap_fmr_cpu ?
				     WORK_CPU_UNBOUND : pool->unmap_fmr_cpu;

	rdsdebug("RDS/IB: free_mr nents %u\n", ibmr->sg_len);

	ibmr->rs = NULL;

	/* remove from pool->busy_list or a tmp list(destroy path) */
	spin_lock_bh(&pool->busy_lock);
	list_del_init(&ibmr->pool_list);
	spin_unlock_bh(&pool->busy_lock);

	if (rds_ibdev->use_fastreg) {
		__rds_frwr_free_mr(pool, ibmr, invalidate);
		return;
	}

	/* Return it to the pool's free list */
	if (ibmr->remap_count >= pool->fmr_attr.max_maps)
		xlist_add(&ibmr->xlist, &ibmr->xlist,
			  &pool->drop_list);
	else
		xlist_add(&ibmr->xlist, &ibmr->xlist,
			  &pool->free_list);
	atomic_add(ibmr->sg_len, &pool->free_pinned);
	atomic_inc(&pool->dirty_count);

	/* If we've pinned too many pages, request a flush.  This is not
	 * applicable to FRWR.
	 */
	if (atomic_read(&pool->free_pinned) >= pool->max_free_pinned ||
	    atomic_read(&pool->dirty_count) >=
	    atomic_read(&pool->max_items_soft) / 5)
		rds_ib_queue_delayed_work_on(rds_ibdev, unmap_fmr_cpu,
					     rds_ib_fmr_wq,
					     &pool->flush_worker, 10,
					     "flush frwr");

	if (invalidate) {
		if (likely(!in_interrupt())) {
			rds_ib_flush_mr_pool(pool, 0, NULL);
		} else {
			/* We get here if the user created a MR marked
			 * as use_once and invalidate at the same time. */
			rds_ib_queue_delayed_work_on(rds_ibdev, unmap_fmr_cpu,
						     rds_ib_fmr_wq,
						     &pool->flush_worker, 10,
						     "flush frwr");
		}
	}
}

void rds_ib_flush_mrs(void)
{
	struct rds_ib_device *rds_ibdev;

	down_read(&rds_ib_devices_lock);
	list_for_each_entry(rds_ibdev, &rds_ib_devices, list) {
		if (rds_ibdev->mr_8k_pool)
			rds_ib_flush_mr_pool(rds_ibdev->mr_8k_pool, 1, NULL);

		if (rds_ibdev->mr_1m_pool)
			rds_ib_flush_mr_pool(rds_ibdev->mr_1m_pool, 1, NULL);
	}
	up_read(&rds_ib_devices_lock);
}

void *rds_ib_get_mr(struct scatterlist *sg, unsigned long nents,
		    struct rds_sock *rs, u32 *key_ret,
		    struct rds_connection *conn)
{
	struct rds_ib_device *rds_ibdev;
	struct rds_ib_mr *ibmr = NULL;
	struct rds_ib_connection *ic = NULL;
	int ret;

	/* If this lookup is successful, this socket is associated with this
	 * device even if subsequent ops fail as a socket cannot change its
	 * bound address.  This association is broken if the device is removed
	 * or the socket is closed.
	 */
	rds_ibdev = rds_rdma_rs_get_device(&rs->rs_bound_addr, rs);
	if (!rds_ibdev) {
		ret = -ENODEV;
		goto out;
	}

	if (conn)
		ic = conn->c_transport_data;

	if (!rds_ibdev->mr_8k_pool || !rds_ibdev->mr_1m_pool) {
		ret = -ENODEV;
		goto out;
	}

	ibmr = rds_ib_alloc_ibmr(rds_ibdev, nents);
	if (IS_ERR(ibmr))
		return ibmr;

	ibmr->ic = ic;

	if (rds_ibdev->use_fastreg) {
		ret = rds_ib_map_fastreg_mr(rds_ibdev, ibmr, sg, nents);
		if (ret == 0)
			*key_ret = ibmr->mr->rkey;
	} else {
		ret = rds_ib_map_fmr(rds_ibdev, ibmr, sg, nents);
		if (ret == 0)
			*key_ret = ibmr->fmr->rkey;
		else
			pr_warn("RDS/IB: map_fmr failed (errno=%d)\n", ret);
	}

	ibmr->rs = rs;
	ibmr->device = rds_ibdev;

 out:
	if (ret) {
		if (ibmr)
			rds_ib_free_mr(ibmr, 0);
		ibmr = ERR_PTR(ret);
	}

	return ibmr;
}

/* Fastreg related functions */

static int rds_ib_map_scatterlist(struct rds_ib_device *rds_ibdev,
				  struct rds_ib_mr *ibmr,
				  struct scatterlist *sg, unsigned int sg_len)
{
	struct ib_device *dev = rds_ibdev->dev;
	int ret, off = 0;
	int sg_dma_len;

	sg_dma_len = ib_dma_map_sg(dev, sg, sg_len, DMA_BIDIRECTIONAL);
	if (unlikely(!sg_dma_len)) {
		pr_warn("RDS/IB: dma_map_sg failed!\n");
		return -EBUSY;
	}

	ret = ib_map_mr_sg_zbva(ibmr->mr, sg, sg_len, &off, PAGE_SIZE);
	if (unlikely(ret != sg_len)) {
		ibmr->fr_state = MR_IS_STALE;
		ret = ret < 0 ? ret : -EINVAL;
		goto out_unmap;
	}

	return sg_dma_len;

out_unmap:
	if (sg_dma_len)
		ib_dma_unmap_sg(rds_ibdev->dev, sg, sg_len, DMA_BIDIRECTIONAL);
	return ret;
}

static int rds_ib_rdma_build_fastreg(struct rds_ib_device *rds_ibdev,
				     struct rds_ib_mr *ibmr)
{
	struct ib_reg_wr reg_wr;
	struct ib_send_wr inv_wr, *first_wr = NULL;
	const struct ib_send_wr *failed_wr;
	struct ib_qp *qp;
	atomic_t *n_wrs;
	int ret = 0;

	if (ibmr->fr_state == MR_IS_STALE) {
		WARN_ON(true);
		return -EAGAIN;
	}

	if (ibmr->ic) {
		n_wrs = &ibmr->ic->i_fastreg_wrs;
		qp = ibmr->ic->i_cm_id->qp;
	} else {
		down_read(&rds_ibdev->fastreg_lock);
		n_wrs = &rds_ibdev->fastreg_wrs;
		qp = rds_ibdev->fastreg_qp;
	}

	while (atomic_sub_return(2, n_wrs) <= 0) {
		atomic_add(2, n_wrs);
		/* Depending on how many times schedule() is called,
		 * we could replace it with wait_event() in future.
		 */
		schedule();
	}

	if (ibmr->fr_state == MR_IS_VALID) {
		memset(&inv_wr, 0, sizeof(inv_wr));
		inv_wr.wr_id = RDS_MR_INV_WR_ID;
		inv_wr.opcode = IB_WR_LOCAL_INV;
		inv_wr.ex.invalidate_rkey = ibmr->mr->rkey;
		first_wr = &inv_wr;
	} else
		ibmr->fr_state = MR_IS_VALID;

	ib_update_fast_reg_key(ibmr->mr, ibmr->remap_count++);

	memset(&reg_wr, 0, sizeof(reg_wr));
	reg_wr.wr.wr_id		= (u64)ibmr;
	reg_wr.wr.opcode	= IB_WR_REG_MR;
	reg_wr.mr		= ibmr->mr;
	reg_wr.key		= ibmr->mr->rkey;
	reg_wr.access		= IB_ACCESS_LOCAL_WRITE |
				  IB_ACCESS_REMOTE_READ |
				  IB_ACCESS_REMOTE_WRITE;
	reg_wr.wr.send_flags	= IB_SEND_SIGNALED;

	if (!first_wr)
		first_wr = &reg_wr.wr;
	else
		first_wr->next = &reg_wr.wr;

	ret = ib_post_send(qp, first_wr, &failed_wr);
	if (ret) {
		atomic_add(2, n_wrs);
		ibmr->fr_state = MR_IS_STALE;
		pr_warn_ratelimited("RDS/IB: %s:%d ib_post_send returned %d\n",
				    __func__, __LINE__, ret);
		goto out;
	}

	wait_for_completion(&ibmr->wr_comp);
	atomic_add(2, n_wrs);
	if (ibmr->fr_state == MR_IS_STALE) {
		/* Registration request failed */
		ret = -EAGAIN;
	}

out:
	if (!ibmr->ic)
		up_read(&rds_ibdev->fastreg_lock);
	return ret;
}

static int rds_ib_map_fastreg_mr(struct rds_ib_device *rds_ibdev,
				 struct rds_ib_mr *ibmr,
				 struct scatterlist *sg, unsigned int sg_len)
{
	int ret = 0;
	int sg_dma_len = 0;

	ret = rds_ib_map_scatterlist(rds_ibdev, ibmr, sg, sg_len);
	if (ret < 0)
		goto out;
	sg_dma_len = ret;

	ret = rds_ib_rdma_build_fastreg(rds_ibdev, ibmr);
	if (ret)
		goto out;

	/* Teardown previous values here since we
	 * finished invalidating the previous key
	 */
	__rds_ib_teardown_mr(ibmr);

	ibmr->sg = sg;
	ibmr->sg_len = sg_len;
	ibmr->sg_dma_len = sg_dma_len;

	if (ibmr->pool->pool_type == RDS_IB_MR_8K_POOL)
		rds_ib_stats_inc(s_ib_rdma_mr_8k_used);
	else
		rds_ib_stats_inc(s_ib_rdma_mr_1m_used);

	return ret;

out:
	if (sg_dma_len)
		ib_dma_unmap_sg(rds_ibdev->dev, sg, sg_len, DMA_BIDIRECTIONAL);
	return ret;
}

void rds_ib_fcq_handler(struct rds_ib_device *rds_ibdev, struct ib_wc *wc)
{
	struct rds_ib_mr *ibmr;

	if (wc->wr_id == RDS_MR_INV_WR_ID)
		return;
	ibmr = (struct rds_ib_mr *)wc->wr_id;

	WARN_ON(ibmr->fr_state == MR_IS_STALE);

	if (wc->status != IB_WC_SUCCESS) {
		pr_warn("RDS: IB: MR completion on fastreg qp status %u vendor_err %u\n",
			wc->status, wc->vendor_err);
		ibmr->fr_state = MR_IS_STALE;
		queue_work(rds_ibdev->rid_dev_wq, &rds_ibdev->fastreg_reset_w);
	}

	complete(&ibmr->wr_comp);
}

void rds_ib_mr_cqe_handler(struct rds_ib_connection *ic, struct ib_wc *wc)
{
	struct rds_ib_mr *ibmr;

	if (wc->wr_id == RDS_MR_INV_WR_ID)
		return;
	ibmr = (struct rds_ib_mr *)wc->wr_id;

	WARN_ON(ibmr->fr_state == MR_IS_STALE);

	if (wc->status != IB_WC_SUCCESS) {
		if (rds_conn_up(ic->conn)) {
			pr_warn("RDS: IB: MR completion <%pI6c,%pI6c,%d> status %u "
				"vendor_err %u, disconnecting and reconnecting\n",
				&ic->conn->c_laddr, &ic->conn->c_faddr,
				ic->conn->c_tos, wc->status, wc->vendor_err);
		}
		ibmr->fr_state = MR_IS_STALE;
	}

	complete(&ibmr->wr_comp);
}
