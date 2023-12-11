/*
 * Copyright (c) 2006, 2024 Oracle and/or its affiliates.
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
#include <linux/cpu.h>
#include <linux/if_arp.h>
#include <linux/sockios.h>
#include <net/addrconf.h>
#include <net/inet_common.h>
#include <linux/debugfs.h>
#include <linux/uek.h>
#include <linux/kernel.h>

#include "trace.h"

#include "ib.h"
#include "rds_single_path.h"

static struct dentry *debugfs_basedir;

unsigned int rds_ib_mr_1m_pool_size = RDS_MR_1M_POOL_SIZE;
unsigned int rds_ib_mr_8k_pool_size = RDS_MR_8K_POOL_SIZE;
unsigned int rds_ib_retry_count = RDS_IB_DEFAULT_RETRY_COUNT;
unsigned int rds_ib_rnr_retry_count = RDS_IB_DEFAULT_RNR_RETRY_COUNT;
unsigned int rds_ib_cache_gc_interval = RDS_IB_DEFAULT_CACHE_GC_INTERVAL;
const u64 fw_ver_16_32_1010 = (((u64)16 << 32) | ((u64)32 << 16) | (u64)1010);

module_param(rds_ib_mr_1m_pool_size, int, 0444);
MODULE_PARM_DESC(rds_ib_mr_1m_pool_size, " Max number of 1m MRs per HCA");
module_param(rds_ib_mr_8k_pool_size, int, 0444);
MODULE_PARM_DESC(rds_ib_mr_8k_pool_size, " Max number of 8k MRs per HCA");
module_param(rds_ib_retry_count, int, 0444);
MODULE_PARM_DESC(rds_ib_retry_count, " Number of hw retries before reporting an error");
module_param(rds_ib_rnr_retry_count, int, 0444);
MODULE_PARM_DESC(rds_ib_rnr_retry_count, " QP rnr retry count");
module_param(rds_ib_cache_gc_interval, int, 0444);
MODULE_PARM_DESC(rds_ib_cache_gc_interval, " Cache cleanup interval in seconds");

/*
 * we have a clumsy combination of RCU and a rwsem protecting this list
 * because it is used both in the get_mr fast path and while blocking in
 * the MR flushing path.
 */
DECLARE_RWSEM(rds_ib_devices_lock);
struct list_head rds_ib_devices;
atomic_t rds_ib_devices_to_free = ATOMIC_INIT(0);

/* NOTE: if also grabbing ibdev lock, grab this first */
DEFINE_SPINLOCK(ib_nodev_conns_lock);
LIST_HEAD(ib_nodev_conns);

struct workqueue_struct *rds_aux_wq;
struct workqueue_struct *rds_evt_wq;

static struct ib_mr *rds_ib_get_dma_mr(struct ib_pd *pd, int mr_access_flags)
{
	struct ib_mr *mr;
	int err;

	err = ib_check_mr_access(pd->device, mr_access_flags);
	if (err)
		return ERR_PTR(err);

	mr = (*pd->device->ops.get_dma_mr)(pd, mr_access_flags);

	if (!IS_ERR(mr)) {
		mr->device      = pd->device;
		mr->pd          = pd;
		mr->uobject     = NULL;
		mr->need_inval  = false;
		atomic_inc(&pd->usecnt);
	}

	return mr;
}

static void rds_ib_cache_gc_worker(struct work_struct *work);

static int ib_rds_cache_hit_show(struct seq_file *m, void *v)
{
	struct rds_ib_device *rds_ibdev = m->private;
	struct rds_ib_refill_cache *cache;
	struct rds_ib_cache_head *head;
	unsigned long long miss, hit;
	u32 cnt;
	int i;
	int cpu;
	u64 sum_get_stats[(RDS_FRAG_CACHE_ENTRIES + 1)];
	u64 sum_hit_stats[(RDS_FRAG_CACHE_ENTRIES + 1)];
	u32 sum_cnt_stats[(RDS_FRAG_CACHE_ENTRIES + 1)];
	char heading[(RDS_FRAG_CACHE_ENTRIES + 1)][40];

	sprintf(heading[0], "------------- Inc -------------");
	for (i = 1; i <= RDS_FRAG_CACHE_ENTRIES; i++)
		sprintf(heading[i], "------------- Frag-%d -------------", i - 1);

	seq_printf(m, "%11s", " ");
	for (i = 0; i <= RDS_FRAG_CACHE_ENTRIES; i++) {
		seq_printf(m, "%41s ", heading[i]);

		sum_get_stats[i] = 0;
		sum_hit_stats[i] = 0;
		sum_cnt_stats[i] = 0;
	}
	seq_puts(m, "\n");

	seq_printf(m, "%11s", "cpu");
	for (i = 0; i <= RDS_FRAG_CACHE_ENTRIES; i++)
		seq_printf(m, "%15s %15s %4s %5s", "Get", "Hit", "%", "Count");

	seq_puts(m, "\n");

	for_each_possible_cpu(cpu) {
		u64 s = 0;

		for (i = 0; i <= RDS_FRAG_CACHE_ENTRIES; i++) {
			if (i == 0)
				cache = &rds_ibdev->i_cache_incs;
			else
				cache = rds_ibdev->i_cache_frags + i - 1;
			head = per_cpu_ptr(cache->percpu, cpu);
			s += atomic64_read(&head->miss_count);
			s += atomic64_read(&head->hit_count);
			s += atomic_read(&head->count);
		}
		if (!s)
			continue;

		seq_printf(m, "%3d        ", cpu);
		for (i = 0; i <= RDS_FRAG_CACHE_ENTRIES; i++) {
			if (i == 0)
				cache = &rds_ibdev->i_cache_incs;
			else
				cache = rds_ibdev->i_cache_frags + i - 1;
			head = per_cpu_ptr(cache->percpu, cpu);
			miss = atomic64_read(&head->miss_count);
			hit = atomic64_read(&head->hit_count);
			cnt = atomic_read(&head->count);
			seq_printf(m, "%15llu %15llu %4llu %5u",
				   (hit + miss),
				   hit,
				   (hit + miss) ? hit * 100 / (hit + miss) : 0, cnt);
			sum_get_stats[i] += (hit + miss);
			sum_hit_stats[i] += hit;
			sum_cnt_stats[i] += cnt;
		}
		seq_puts(m, "\n");
	}
	seq_puts(m, "sum        ");

	for (i = 0; i <= RDS_FRAG_CACHE_ENTRIES; i++) {
		seq_printf(m, "%15llu %15llu %4llu %5u",
			   sum_get_stats[i],
			   sum_hit_stats[i],
			   sum_get_stats[i] ? sum_hit_stats[i] * 100 / sum_get_stats[i] : 0,
			   sum_cnt_stats[i]);
	}
	seq_puts(m, "\n");

	seq_puts(m, "ready      ");
	for (i = 0; i <= RDS_FRAG_CACHE_ENTRIES; i++) {
		if (i == 0)
			cache = &rds_ibdev->i_cache_incs;
		else
			cache = rds_ibdev->i_cache_frags + i - 1;
		miss = atomic64_read(&cache->miss_count);
		hit = atomic64_read(&cache->hit_count);
		cnt = atomic_read(&cache->count);
		seq_printf(m, "%15s %15llu %4llu %5u",
			   "",
			   hit,
			   (hit + miss) ? hit  * 100 / (hit + miss) : 0, cnt);
	}
	seq_puts(m, "\n");

	seq_puts(m, "miss       ");

	for (i = 0; i <= RDS_FRAG_CACHE_ENTRIES; i++) {
		if (i == 0)
			cache = &rds_ibdev->i_cache_incs;
		else
			cache = rds_ibdev->i_cache_frags + i - 1;
		miss = atomic64_read(&cache->miss_count);
		seq_printf(m, "%15llu %15s %4s %5s",
			   miss, " ", " ", " ");
	}
	seq_puts(m, "\n");

	return 0;
}

static int ib_rds_cache_hit_open(struct inode *inode, struct file *filep)
{
	return single_open(filep, ib_rds_cache_hit_show, inode->i_private);
}

static const struct file_operations ib_rds_cache_hit_fops = {
	.open           = ib_rds_cache_hit_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = single_release,
};

static int ib_rds_create_debugfs_cache_hit(struct rds_ib_device *rds_ibdev)
{
	struct dentry *ent;

	rds_ibdev->debugfs_dir = debugfs_create_dir(rds_ibdev->dev->name, debugfs_basedir);
	if (!rds_ibdev->debugfs_dir)
		goto out;

	ent = debugfs_create_file("hit_stats", 0400, rds_ibdev->debugfs_dir,
				  rds_ibdev, &ib_rds_cache_hit_fops);
	if (!ent)
		goto fail;

	return 0;
fail:
	debugfs_remove_recursive(rds_ibdev->debugfs_dir);
	rds_ibdev->debugfs_dir = NULL;
out:
	return -ENOMEM;
}

static void ib_rds_remove_debugfs_cache_hit(struct rds_ib_device *rds_ibdev)
{
	debugfs_remove_recursive(rds_ibdev->debugfs_dir);
}

static int rds_ib_alloc_cache(struct rds_ib_refill_cache *cache)
{
	struct rds_ib_cache_head *head;
	int cpu;

	cache->percpu = alloc_percpu_gfp(struct rds_ib_cache_head, GFP_KERNEL);
	if (!cache->percpu)
		return -ENOMEM;

	for_each_possible_cpu(cpu) {
		head = per_cpu_ptr(cache->percpu, cpu);
		lfstack_init(&head->stack);
		atomic_set(&head->count, 0);
		atomic64_set(&head->hit_count, 0);
		atomic64_set(&head->miss_count, 0);
		atomic64_set(&head->gc_count, 0);
	}
	lfstack_init(&cache->ready);
	atomic_set(&cache->count, 0);
	atomic64_set(&cache->hit_count, 0);
	atomic64_set(&cache->miss_count, 0);
	set_bit_mb(RDS_IB_CACHE_INITIALIZED, &cache->initialized);
	return 0;
}

static void rds_ib_free_cache(struct rds_ib_refill_cache *cache)
{
	struct rds_ib_cache_head *head;
	int cpu;
	clear_bit_mb(RDS_IB_CACHE_INITIALIZED, &cache->initialized);
	for_each_possible_cpu(cpu) {
		head = per_cpu_ptr(cache->percpu, cpu);
		lfstack_free(&head->stack);
		atomic_set(&head->count, 0);
		atomic64_set(&head->hit_count, 0);
		atomic64_set(&head->miss_count, 0);
	}
	lfstack_free(&cache->ready);
	free_percpu(cache->percpu);
	cache->percpu = NULL;
	atomic_set(&cache->count, 0);
	atomic64_set(&cache->hit_count, 0);
	atomic64_set(&cache->miss_count, 0);
	atomic64_set(&head->gc_count, 0);
}

static int rds_ib_alloc_caches(struct rds_ib_device *rds_ibdev)
{
	int i, j;
	int ret;

	ret = rds_ib_alloc_cache(&rds_ibdev->i_cache_incs);
	if (ret)
		goto out;

	for (i = 0; i < RDS_FRAG_CACHE_ENTRIES; i++) {
		ret = rds_ib_alloc_cache(rds_ibdev->i_cache_frags + i);
		if (ret) {
			rds_ib_free_cache(&rds_ibdev->i_cache_incs);
			for (j = 0; j < i; j++)
				rds_ib_free_cache(rds_ibdev->i_cache_frags + j);
			goto out;
		}
	}
	INIT_DELAYED_WORK(&rds_ibdev->i_cache_gc_work, rds_ib_cache_gc_worker);
	rds_ibdev->i_cache_gc_cpu = 0;
	rds_queue_delayed_work(NULL, rds_aux_wq, &rds_ibdev->i_cache_gc_work,
			       msecs_to_jiffies(rds_ib_cache_gc_interval * 1000),
			       "Cache_Garbage_Collection");
out:
	return ret;
}

void rds_ib_free_one_frag(struct rds_page_frag *frag, size_t cache_sz)
{
	int cache_frag_pages = ceil(cache_sz, PAGE_SIZE);

	frag->f_cache_entry.next = NULL;
	WARN_ON(!list_empty(&frag->f_item));
	rds_ib_recv_free_frag(frag, cache_frag_pages);
	atomic_sub(cache_frag_pages, &rds_ib_allocation);
	kmem_cache_free(rds_ib_frag_slab, frag);
	rds_ib_stats_dec(s_ib_rx_total_frags);
	rds_ib_stats_inc(s_ib_recv_nmb_removed_from_cache);
	rds_ib_stats_add(s_ib_recv_removed_from_cache, cache_sz);
}

static void rds_ib_free_frag_cache_one(struct rds_ib_refill_cache *cache, size_t cache_sz, int cpu)
{
	struct lfstack_el *cache_item;
	struct rds_page_frag *frag;
	struct rds_ib_cache_head *head = per_cpu_ptr(cache->percpu, cpu);
	int cnt = 0;

	trace_rds_ib_free_cache_one(head, cpu, "frag(s)");
	cache_item = lfstack_pop_all(&head->stack);
	while (cache_item) {
		frag = container_of(cache_item, struct rds_page_frag, f_cache_entry);
		cache_item = lfstack_next(cache_item);
		rds_ib_free_one_frag(frag, cache_sz);
		cnt++;
	}
	atomic_sub(cnt, &head->count);
}

static void rds_ib_free_frag_cache(struct rds_ib_refill_cache *cache, size_t cache_sz)
{
	int cpu;
	struct rds_ib_cache_head *head;
	struct lfstack_el *cache_item;
	struct rds_page_frag *frag;

	clear_bit_mb(RDS_IB_CACHE_INITIALIZED, &cache->initialized);
	for_each_possible_cpu(cpu) {
		rds_ib_free_frag_cache_one(cache, cache_sz, cpu);
		head = per_cpu_ptr(cache->percpu, cpu);
		lfstack_free(&head->stack);
		atomic_set(&head->count, 0);
	}
	while ((cache_item = lfstack_pop(&cache->ready))) {
		frag = container_of(cache_item, struct rds_page_frag, f_cache_entry);
		rds_ib_free_one_frag(frag, cache_sz);
	}
	lfstack_free(&cache->ready);
	free_percpu(cache->percpu);
}

void rds_ib_free_one_inc(struct rds_ib_incoming *inc)
{
	inc->ii_cache_entry.next = 0;
	WARN_ON(!list_empty(&inc->ii_frags));
	kmem_cache_free(rds_ib_incoming_slab, inc);
}

static void rds_ib_free_inc_cache_one(struct rds_ib_refill_cache *cache, int cpu)
{
	struct lfstack_el *cache_item;
	struct rds_ib_incoming *inc;
	struct rds_ib_cache_head *head = per_cpu_ptr(cache->percpu, cpu);
	int cnt = 0;

	trace_rds_ib_free_cache_one(head, cpu, "inc(s)");
	cache_item = lfstack_pop_all(&head->stack);

	while (cache_item) {
		inc = container_of(cache_item, struct rds_ib_incoming, ii_cache_entry);
		cache_item = lfstack_next(cache_item);
		rds_ib_free_one_inc(inc);
		cnt++;
	}
	atomic_sub(cnt, &head->count);
}

static void rds_ib_free_inc_cache(struct rds_ib_refill_cache *cache)
{
	struct rds_ib_cache_head *head;
	int cpu;
	struct lfstack_el *cache_item;
	struct rds_ib_incoming *inc;

	clear_bit_mb(RDS_IB_CACHE_INITIALIZED, &cache->initialized);
	for_each_possible_cpu(cpu) {
		rds_ib_free_inc_cache_one(cache, cpu);
		head = per_cpu_ptr(cache->percpu, cpu);
		lfstack_free(&head->stack);
		atomic_set(&head->count, 0);
	}
	while ((cache_item = lfstack_pop(&cache->ready))) {
		inc = container_of(cache_item, struct rds_ib_incoming, ii_cache_entry);
		rds_ib_free_one_inc(inc);
	}
	lfstack_free(&cache->ready);
	free_percpu(cache->percpu);
}

static void rds_ib_free_caches(struct rds_ib_device *rds_ibdev)
{
	int i;

	if (!test_bit(RDS_IB_CACHE_INITIALIZED, &rds_ibdev->i_cache_incs.initialized))
		return;

	cancel_delayed_work_sync(&rds_ibdev->i_cache_gc_work);
	rds_ib_free_inc_cache(&rds_ibdev->i_cache_incs);
	for (i = 0; i < RDS_FRAG_CACHE_ENTRIES; i++)
		rds_ib_free_frag_cache(rds_ibdev->i_cache_frags + i, PAGE_SIZE << i);
}

static bool rds_ib_cache_need_gc(struct rds_ib_refill_cache *cache, int cpu)
{
	struct rds_ib_cache_head *head;
	u64 nmbr;
	bool ret;

	head = per_cpu_ptr(cache->percpu, cpu);
	nmbr = atomic64_read(&head->miss_count) + atomic64_read(&head->hit_count);

	ret = (atomic64_read(&head->gc_count) == nmbr && atomic_read(&head->count) > 0);
	atomic64_set(&head->gc_count, nmbr);
	return ret;
}

static void rds_ib_cache_gc_worker(struct work_struct *work)
{
	int i, j;
	int nmbr_to_check = num_possible_cpus() / 2;
	struct rds_ib_refill_cache *cache;
	struct lfstack_el *cache_item;
	struct rds_ib_incoming *inc;
	struct rds_page_frag *frag;
	int cnt = 0;
	struct rds_ib_device *rds_ibdev = container_of(work,
						       struct rds_ib_device,
						       i_cache_gc_work.work);

	for (j = 0; j < nmbr_to_check; j++) {
		if (rds_ib_cache_need_gc(&rds_ibdev->i_cache_incs, rds_ibdev->i_cache_gc_cpu))
			rds_ib_free_inc_cache_one(&rds_ibdev->i_cache_incs, rds_ibdev->i_cache_gc_cpu);

		for (i = 0; i < RDS_FRAG_CACHE_ENTRIES; i++)
			if (rds_ib_cache_need_gc(rds_ibdev->i_cache_frags + i, rds_ibdev->i_cache_gc_cpu))
				rds_ib_free_frag_cache_one(rds_ibdev->i_cache_frags + i,
							   PAGE_SIZE << i,
							   rds_ibdev->i_cache_gc_cpu);

		if (++rds_ibdev->i_cache_gc_cpu >= num_possible_cpus())
			rds_ibdev->i_cache_gc_cpu = 0;

		/* resched for waiters in non-preempt kernel */
		cond_resched();
	}
	cache = &rds_ibdev->i_cache_incs;
	cache_item = lfstack_pop_all(&cache->ready);
	while (cache_item) {
		inc = container_of(cache_item, struct rds_ib_incoming, ii_cache_entry);
		cache_item = lfstack_next(cache_item);
		rds_ib_free_one_inc(inc);
		cnt++;
	}
	atomic_sub(cnt, &cache->count);
	for (i = 0; i < RDS_FRAG_CACHE_ENTRIES; i++) {
		cache = rds_ibdev->i_cache_frags + i;
		cache_item = lfstack_pop_all(&cache->ready);
		cnt = 0;
		while (cache_item) {
			frag = container_of(cache_item, struct rds_page_frag, f_cache_entry);
			cache_item = lfstack_next(cache_item);
			rds_ib_free_one_frag(frag, PAGE_SIZE << i);
			cnt++;
		}
		atomic_sub(cnt, &cache->count);
		/* resched for waiters in non-preempt kernel */
		cond_resched();
	}

	rds_queue_delayed_work(NULL, rds_aux_wq, &rds_ibdev->i_cache_gc_work,
			       msecs_to_jiffies(rds_ib_cache_gc_interval * 1000),
			       "Cache_Garbage_Collection");
}

/* Reference counter for struct rds_ib_device on the module */
static atomic_t rds_rdma_mod_ref = ATOMIC_INIT(0);
DECLARE_WAIT_QUEUE_HEAD(rds_rdma_zero_dev);

/* Work struct for storing the work to detroy an RDS/RDMA connection. */
struct __rds_destroy_wk {
	struct rds_connection   *rdw_conn;
	struct work_struct      rdw_free_work;
};

/* Worker function to destroy an RDS/RDMA connection. */
static void __rds_conn_destroy(struct work_struct *work)
{
	struct __rds_destroy_wk *free_wk;

	free_wk = container_of(work, struct __rds_destroy_wk, rdw_free_work);
	rds_conn_destroy(free_wk->rdw_conn, 1);
	kfree(free_wk);
}

void rds_ib_nodev_connect(void)
{
	struct rds_ib_connection *ic;
	unsigned long flags;

	spin_lock_irqsave(&ib_nodev_conns_lock, flags);
	list_for_each_entry(ic, &ib_nodev_conns, ib_node)
		rds_conn_connect_if_down(ic->conn);
	spin_unlock_irqrestore(&ib_nodev_conns_lock, flags);
}

static void __rds_ib_dev_shutdown(struct rds_ib_device *rds_ibdev)
{
	struct rds_ib_connection *ic, *tmp_ic;
	struct __rds_destroy_wk *free_wk;
	LIST_HEAD(tmp_list);
	unsigned long flags;

	spin_lock_irqsave(&rds_ibdev->spinlock, flags);

	trace_rds_ib_shutdown_device(rds_ibdev->dev, rds_ibdev, NULL, NULL,
				     "shutdown IB device", 0);

	/* If the rds_rdma module is being unloaded, destroy the conns.
	 * Otherwise, drop them and they will be moved to the ib_nodev_conns
	 * list and wait for a new device for re-connection.
	 */
	if (rds_ibdev->rid_mod_unload) {
		/* At this point, there shall not be any new conn added to this
		 * dev's conn_list.  Move the list to a temporary list for
		 * deletion as deletion must not be done holding the spinlock.
		 */
		list_splice(&rds_ibdev->conn_list, &tmp_list);
		INIT_LIST_HEAD(&rds_ibdev->conn_list);
		spin_unlock_irqrestore(&rds_ibdev->spinlock, flags);

		/* Spread out the work to destroy all the connections. */
		list_for_each_entry_safe(ic, tmp_ic, &tmp_list, ib_node) {
			list_del_init(&ic->ib_node);

			free_wk = kmalloc(sizeof(*free_wk), GFP_KERNEL);
			if (!free_wk) {
				rds_conn_destroy(ic->conn, 1);
			} else {
				free_wk->rdw_conn = ic->conn;
				INIT_WORK(&free_wk->rdw_free_work,
					  __rds_conn_destroy);
				queue_work(rds_ibdev->rid_dev_wq,
					   &free_wk->rdw_free_work);
			}
		}
	} else {
		/* Drop all rds_ib_connections associated with this device.
		 * Note that there can be some rds_ib_connections which were
		 * associated with this device but had been dropped prior to
		 * this.  And they still have resources associated with this
		 * device because of the delayed free mechanism.  Those
		 * resources will either be freed by the delayed work; or when
		 * those rds_ib_connections try to restart and a new device
		 * is available, the resources will be freed when
		 * rds_ib_setup_qp() is called as the new device will not
		 * match with the old device.  The struct rds_ib_device will
		 * be freed when all the associated resources are freed (the
		 * reference count dropped to 0).
		 */
		list_for_each_entry(ic, &rds_ibdev->conn_list, ib_node)
			rds_conn_drop(ic->conn, DR_RDMA_DEV_REM, 0);
		spin_unlock_irqrestore(&rds_ibdev->spinlock, flags);
	}
}

/* Struct to hold device shut down work. */
struct __rds_dev_shutdown_wk {
	struct rds_ib_device	*rdsw_ibdev;
	struct work_struct	rdsw_work;
};

/* Device shut down worker function. */
static void __rds_dev_shutdown_worker(struct work_struct *work)
{
	struct __rds_dev_shutdown_wk *wk;

	wk = container_of(work, struct __rds_dev_shutdown_wk, rdsw_work);
	__rds_ib_dev_shutdown(wk->rdsw_ibdev);
	rds_ib_dev_put(wk->rdsw_ibdev);
	kfree(wk);
}

/* Shut down a device.
 *
 * @rds_ibdev: pointer to the device to be shut down.
 */
static void rds_ib_dev_shutdown(struct rds_ib_device *rds_ibdev)
{
	struct __rds_dev_shutdown_wk *wk;

	wk = kmalloc(sizeof(*wk), GFP_KERNEL);
	if (!wk) {
		__rds_ib_dev_shutdown(rds_ibdev);
		return;
	}

	wk->rdsw_ibdev = rds_ibdev;
	/* Get a reference on the rds_ibdev so that it won't go away util
	 * the worker is done is the device.
	 */
	atomic_inc(&rds_ibdev->rid_refcount);
	INIT_WORK(&wk->rdsw_work, __rds_dev_shutdown_worker);
	queue_work(rds_aux_wq, &wk->rdsw_work);
}

/* Worker function to de-allocate resources associated with a struct
 * rds_ib_device.  The work is queued when all references to the struct
 * are removed.
 */
static void rds_ib_dev_free(struct work_struct *work)
{
	struct rds_ib_ipaddr *i_ipaddr, *i_next;
	struct rds_ib_device *rds_ibdev = container_of(work,
					struct rds_ib_device, rid_free_work);
	bool last_to_free;
	int allocated;

	if (rds_ibdev->srq) {
		rds_ib_srq_exit(rds_ibdev);
		kfree(rds_ibdev->srq);
	}
	rds_ib_free_caches(rds_ibdev);

	if (rds_ibdev->mr_8k_pool)
		rds_ib_destroy_mr_pool(rds_ibdev->mr_8k_pool);
	if (rds_ibdev->mr_1m_pool)
		rds_ib_destroy_mr_pool(rds_ibdev->mr_1m_pool);
	trace_rds_ib_queue_cancel_work(rds_ibdev, NULL,
				       &rds_ibdev->fastreg_reset_w, 0,
				       "dev free, cancel reset work");
	cancel_work_sync(&rds_ibdev->fastreg_reset_w);
	down_write(&rds_ibdev->fastreg_lock);
	rds_ib_destroy_fastreg(rds_ibdev);
	up_write(&rds_ibdev->fastreg_lock);
	if (rds_ibdev->mr)
		ib_dereg_mr(rds_ibdev->mr);
	if (rds_ibdev->rid_dev_wq)
		destroy_workqueue(rds_ibdev->rid_dev_wq);
	if (rds_ibdev->pd)
		ib_dealloc_pd(rds_ibdev->pd);

	list_for_each_entry_safe(i_ipaddr, i_next, &rds_ibdev->ipaddr_list,
				 list) {
		list_del(&i_ipaddr->list);
		kfree(i_ipaddr);
	}
	last_to_free = atomic_dec_and_test(&rds_ib_devices_to_free);
	allocated = atomic_read(&rds_ib_allocation);
	if (system_state <= SYSTEM_RUNNING && WARN_ON(last_to_free && allocated)) {
		pr_info("%s rds_ib_allocations %d\n", __func__, allocated);
		rds_stats_print(__func__);
		rds_ib_stats_print(__func__);
	}
	if (rds_ibdev->vector_load)
		kfree(rds_ibdev->vector_load);

	/* Wake up the thread waiting in rds_ib_remove_one(). */
	if (rds_ibdev->rid_dev_rem_complete)
		complete(rds_ibdev->rid_dev_rem_complete);
	WARN_ON(!list_empty(&rds_ibdev->conn_list));
	kfree(rds_ibdev);

	/* If this is the last reference, wake up the thread doing the device
	 * removal.
	 */
	if (!atomic_dec_return(&rds_rdma_mod_ref))
		wake_up(&rds_rdma_zero_dev);
}

void rds_ib_dev_put(struct rds_ib_device *rds_ibdev)
{
	WARN_ON(atomic_read(&rds_ibdev->rid_refcount) <= 0);
	if (atomic_dec_and_test(&rds_ibdev->rid_refcount)) {
		trace_rds_ib_queue_work(rds_ibdev, rds_wq,
					&rds_ibdev->rid_free_work, 0,
					"free rds_ibdev");
		queue_work(rds_wq, &rds_ibdev->rid_free_work);
	}
}

/*
 * New connections use this to find the device to associate with the
 * connection.  It's not in the fast path so we're not concerned about the
 * performance of the IB call.  (As of this writing, it uses an interrupt
 * blocking spinlock to serialize walking a per-device list of all registered
 * clients.)
 *
 * RCU is used to handle incoming connections racing with device teardown.
 * Rather than use a lock to serialize removal from the client_data and
 * getting a new reference, we use an RCU grace period.  The destruction
 * path removes the device from client_data and then waits for all RCU
 * readers to finish.
 *
 * A new connection can get NULL from this if its arriving on a
 * device that is in the process of being removed.
 */
struct rds_ib_device *rds_ib_get_client_data(struct ib_device *device)
{
	struct rds_ib_device *rds_ibdev;

	rcu_read_lock();
	rds_ibdev = ib_get_client_data(device, &rds_ib_client);
	if (rds_ibdev)
		atomic_inc(&rds_ibdev->rid_refcount);
	rcu_read_unlock();
	return rds_ibdev;
}

/*
 * RDS/RDMA socket release function.  Called when a socket is being closed.
 */
static void rds_rdma_sock_release(struct rds_sock *rs)
{
	struct rds_ib_device *rds_ibdev;
	struct rds_rdma_dev_sock *rrds;
	bool unlinked = false;
	unsigned long flags;
	bool dev_released;

	mutex_lock(&rs->rs_trans_lock);
	rrds = (struct rds_rdma_dev_sock *)rs->rs_trans_private;
	if (!rrds) {
		mutex_unlock(&rs->rs_trans_lock);
		return;
	}
	dev_released = rrds->rrds_dev_released;
	rrds->rrds_rs_released = true;

	/* Get a reference in case rds_rdma_free_dev_rs_worker() is
	 * executing.
	 */
	kref_get(&rrds->rrds_kref);
	mutex_unlock(&rs->rs_trans_lock);

	rds_ibdev = rrds->rrds_rds_ibdev;
	spin_lock_irqsave(&rds_ibdev->rid_rs_list_lock, flags);
	/* The device may have dissociated with this sock.  Hence the
	 * rds_rdma_free_dev_rs_worker() function is executing (if
	 * (dev_released) or will be executed.
	 */
	if (list_empty(&rrds->rrds_list)) {
		unlinked = true;
	} else {
		list_del_init(&rrds->rrds_list);
		/* If we are the one to unlink this rrds, it means that
		 * rds_rdma_free_dev_rs_worker() will never execute for this
		 * rrds, release the reference obtained above.
		 */
		kref_put(&rrds->rrds_kref, rds_rrds_free);
	}
	spin_unlock_irqrestore(&rds_ibdev->rid_rs_list_lock, flags);

	/* We are the only one running, just release all ibmrs and free
	 * the rrds.
	 */
	if (!unlinked) {
		rds_rdma_drop_keys(rs);
		kref_put(&rrds->rrds_kref, rds_rrds_free);
		return;
	}

	/* The device is going away.  There are two cases;
	 *
	 * 1. rds_rdma_free_dev_rs_worker() has not yet run when this function
	 *    starts.  Release all the ibmrs as rds_rdma_free_dev_rs_worker()
	 *    will not do it.  Then wait for rds_rdma_free_dev_rs_worker() to
	 *    notify us that it is done.
	 *
	 * 2. rds_rdma_free_dev_rs_worker() has run when this function starts.
	 *    rds_rdma_free_dev_rs_worker() will release all ibmrs.  So just
	 *    wait for the notification.
	 */
	if (!dev_released) {
		rds_rdma_drop_keys(rs);
		kref_put(&rrds->rrds_kref, rds_rrds_free);
	}

	/* Need to wait for rds_rdma_free_dev_rs_worker() to finish
	 * before freeing the rrds.
	 */
	wait_for_completion(&rrds->rrds_work_done);
	kref_put(&rrds->rrds_kref, rds_rrds_free);
}

/* Go through all the sockets associated with a struct rds_ib_device and
 * notify them that the device is going away.
 */
static void rds_rdma_dev_rs_drop(struct rds_ib_device *rds_ibdev)
{
	struct rds_rdma_dev_sock *rrds, *tmp_rrds;
	unsigned long flags;

	spin_lock_irqsave(&rds_ibdev->rid_rs_list_lock, flags);
	list_for_each_entry_safe(rrds, tmp_rrds, &rds_ibdev->rid_rs_list,
				 rrds_list) {
		/* Re-initialize rrds_list so that rds_rdma_sock_release()
		 * knows that this rrds has been dissociated.
		 */
		list_del_init(&rrds->rrds_list);
		queue_work(rds_ibdev->rid_dev_wq, &rrds->rrds_free_work);
	}
	spin_unlock_irqrestore(&rds_ibdev->rid_rs_list_lock, flags);
}

/*
 * The IB stack is letting us know that a device is going away.  This can
 * happen if the underlying HCA driver is removed or if PCI hotplug is removing
 * the pci function, for example.
 *
 * This can be called at any time and can be racing with any other RDS path.
 */
void rds_ib_remove_one(struct ib_device *device, void *client_data)
{
	DECLARE_COMPLETION_ONSTACK(rem_complete);
	struct rds_ib_device *rds_ibdev;

	rds_ibdev = (struct rds_ib_device *)client_data;
	/* The device is already removed. */
	if (!rds_ibdev) {
		trace_rds_ib_remove_device_err(device, NULL, NULL, NULL,
					       "rds_ibdev is NULL", 0);
		return;
	}
	trace_rds_ib_remove_device(device, rds_ibdev, NULL, NULL,
				   "removing IB device", 0);

	rds_ibdev->rid_dev_rem = true;

	ib_rds_remove_debugfs_cache_hit(rds_ibdev);

	/* Remove all the linkages to this device so that it can't be found. */
	down_write(&rds_ib_devices_lock);
	list_del_rcu(&rds_ibdev->list);
	up_write(&rds_ib_devices_lock);

	/* Stop connection attempts from getting a reference to this device.
	 * Only need to do this if it is not done already.
	 */
	if (!rds_ibdev->rid_mod_unload)
		ib_set_client_data(device, &rds_ib_client, NULL);

	rds_ibdev->rid_dev_rem_complete = &rem_complete;

	/*
	 * This synchronize rcu is waiting for readers of both the ib
	 * client data and the devices list to finish before we close all
	 * the connections associated with this device.  And go through the
	 * rds_sock list to tell all associated rds_sock to release their
	 * ibmrs.
	 */
	synchronize_rcu();

	rds_ib_dev_shutdown(rds_ibdev);
	rds_rdma_dev_rs_drop(rds_ibdev);

	/* Drop our reference and wait for the last guy to wake us up.  Note
	 * this we may be the last guy.
	 */
	rds_ib_dev_put(rds_ibdev);
	wait_for_completion(&rem_complete);
}

struct ib_client rds_ib_client = {
	.name   = "rds_ib",
	.add    = rds_ib_add_one,
	.remove = rds_ib_remove_one
};

/* Remove IB connection information.  This function only reports IPv4
 * connections for backward compatibility.
 */
static int rds_ib_conn_info_visitor(struct rds_connection *conn,
				    void *buffer)
{
	struct rds_info_rdma_connection *iinfo = buffer;
	struct rds_ib_connection *ic = conn->c_transport_data;
	u64 now = jiffies;

	memset(iinfo, 0, sizeof(*iinfo));

	/* We will only ever look at IB transports */
	if (conn->c_trans != &rds_ib_transport)
		return 0;
	if (conn->c_isv6)
		return 0;

	iinfo->src_addr = conn->c_laddr.s6_addr32[3];
	iinfo->dst_addr = conn->c_faddr.s6_addr32[3];

	memset(&iinfo->src_gid, 0, sizeof(iinfo->src_gid));
	memset(&iinfo->dst_gid, 0, sizeof(iinfo->dst_gid));

	iinfo->qp_num = -1;
	iinfo->dst_qp_num = -1;

	if (ic) {
		iinfo->tos = conn->c_tos;
		iinfo->sl = ic->i_sl;
		iinfo->frag = ic->i_frag_sz;
	}

	if (rds_conn_state(conn) == RDS_CONN_UP) {
		struct rds_ib_device *rds_ibdev;

		rdma_read_gids(ic->i_cm_id, (union ib_gid *)&iinfo->src_gid,
			       (union ib_gid *)&iinfo->dst_gid);

		rds_ibdev = ic->rds_ibdev;
		iinfo->max_send_wr = ic->i_send_ring.w_nr;
		iinfo->max_recv_wr = ic->i_recv_ring.w_nr;
		iinfo->max_send_sge = rds_ibdev->max_sge;
		iinfo->qp_num = ic->i_qp_num;
		iinfo->dst_qp_num = ic->i_dst_qp_num;
		iinfo->recv_alloc_ctr = (uint32_t)atomic64_read(&ic->i_recv_ring.w_alloc_ctr);
		iinfo->recv_free_ctr = (uint32_t)atomic64_read(&ic->i_recv_ring.w_free_ctr);
		iinfo->flow_ctl_post_credit =
			IB_GET_POST_CREDITS(atomic_read(&ic->i_credits));
		iinfo->flow_ctl_send_credit =
			IB_GET_SEND_CREDITS(atomic_read(&ic->i_credits));
		rds_ib_get_mr_info(rds_ibdev, iinfo);
		iinfo->cache_allocs = atomic_read(&ic->i_cache_allocs);
		iinfo->send_alloc_ctr = (uint32_t)atomic64_read(&ic->i_send_ring.w_alloc_ctr);
		iinfo->send_free_ctr = (uint32_t)atomic64_read(&ic->i_send_ring.w_free_ctr);
		iinfo->send_bytes =
			(uint64_t)atomic64_read(&conn->c_send_bytes);
		iinfo->recv_bytes =
			(uint64_t)atomic64_read(&conn->c_recv_bytes);
		iinfo->r_read_bytes =
			(uint64_t)atomic64_read(&ic->i_r_read_bytes);
		iinfo->r_write_bytes =
			(uint64_t)atomic64_read(&ic->i_r_write_bytes);
		iinfo->tx_poll_ts = jiffies_to_msecs(now - ic->i_tx_poll_ts);
		iinfo->rx_poll_ts = jiffies_to_msecs(now - ic->i_rx_poll_ts);
		iinfo->tx_poll_cnt =
			(uint64_t)atomic64_read(&ic->i_tx_poll_cnt);
		iinfo->rx_poll_cnt =
			(uint64_t)atomic64_read(&ic->i_rx_poll_cnt);
		iinfo->scq_vector = ic->i_scq_vector;
		iinfo->rcq_vector = ic->i_rcq_vector;
	}
	return 1;
}

#if IS_ENABLED(CONFIG_IPV6)
/* IPv6 version of rds_ib_conn_info_visitor(). */
static int rds6_ib_conn_info_visitor(struct rds_connection *conn,
				     void *buffer)
{
	struct rds6_info_rdma_connection *iinfo6 = buffer;
	struct rds_ib_connection *ic = conn->c_transport_data;
	u64 now = jiffies;

	memset(iinfo6, 0, sizeof(*iinfo6));

	/* We will only ever look at IB transports */
	if (conn->c_trans != &rds_ib_transport)
		return 0;

	iinfo6->src_addr = conn->c_laddr;
	iinfo6->dst_addr = conn->c_faddr;

	memset(&iinfo6->src_gid, 0, sizeof(iinfo6->src_gid));
	memset(&iinfo6->dst_gid, 0, sizeof(iinfo6->dst_gid));

	iinfo6->qp_num = -1;
	iinfo6->dst_qp_num = -1;

	if (ic) {
		iinfo6->tos = conn->c_tos;
		iinfo6->sl = ic->i_sl;
		iinfo6->frag = ic->i_frag_sz;
	}

	if (rds_conn_state(conn) == RDS_CONN_UP) {
		struct rds_ib_device *rds_ibdev;

		rdma_read_gids(ic->i_cm_id, (union ib_gid *)&iinfo6->src_gid,
			       (union ib_gid *)&iinfo6->dst_gid);

		rds_ibdev = ic->rds_ibdev;
		iinfo6->max_send_wr = ic->i_send_ring.w_nr;
		iinfo6->max_recv_wr = ic->i_recv_ring.w_nr;
		iinfo6->max_send_sge = rds_ibdev->max_sge;
		iinfo6->qp_num = ic->i_qp_num;
		iinfo6->dst_qp_num = ic->i_dst_qp_num;
		iinfo6->recv_alloc_ctr = (uint32_t)atomic64_read(&ic->i_recv_ring.w_alloc_ctr);
		iinfo6->recv_free_ctr = (uint32_t)atomic64_read(&ic->i_recv_ring.w_free_ctr);
		iinfo6->flow_ctl_post_credit =
			IB_GET_POST_CREDITS(atomic_read(&ic->i_credits));
		iinfo6->flow_ctl_send_credit =
			IB_GET_SEND_CREDITS(atomic_read(&ic->i_credits));
		rds6_ib_get_mr_info(rds_ibdev, iinfo6);
		iinfo6->cache_allocs = atomic_read(&ic->i_cache_allocs);
		iinfo6->send_alloc_ctr = (uint32_t)atomic64_read(&ic->i_send_ring.w_alloc_ctr);
		iinfo6->send_free_ctr =	(uint32_t)atomic64_read(&ic->i_send_ring.w_free_ctr);
		iinfo6->send_bytes =
			(uint64_t)atomic64_read(&conn->c_send_bytes);
		iinfo6->recv_bytes =
			(uint64_t)atomic64_read(&conn->c_recv_bytes);
		iinfo6->r_read_bytes =
			(uint64_t)atomic64_read(&ic->i_r_read_bytes);
		iinfo6->r_write_bytes =
			(uint64_t)atomic64_read(&ic->i_r_write_bytes);
		iinfo6->tx_poll_ts = jiffies_to_msecs(now - ic->i_tx_poll_ts);
		iinfo6->rx_poll_ts = jiffies_to_msecs(now - ic->i_rx_poll_ts);
		iinfo6->tx_poll_cnt =
			(uint64_t)atomic64_read(&ic->i_tx_poll_cnt);
		iinfo6->rx_poll_cnt =
			(uint64_t)atomic64_read(&ic->i_rx_poll_cnt);
		iinfo6->scq_vector = ic->i_scq_vector;
		iinfo6->rcq_vector = ic->i_rcq_vector;
	}
	return 1;
}
#endif

static void rds_ib_ic_info(struct socket *sock, unsigned int len,
			   struct rds_info_iterator *iter,
			   struct rds_info_lengths *lens)
{
	u64 buffer[(sizeof(struct rds_info_rdma_connection) + 7) / 8];

	rds_for_each_conn_info(sock, len, iter, lens,
			       rds_ib_conn_info_visitor, buffer,
			       sizeof(struct rds_info_rdma_connection));
}

#if IS_ENABLED(CONFIG_IPV6)
/* IPv6 version of rds_ib_ic_info(). */
static void rds6_ib_ic_info(struct socket *sock, unsigned int len,
			    struct rds_info_iterator *iter,
			    struct rds_info_lengths *lens)
{
	u64 buffer[(sizeof(struct rds6_info_rdma_connection) + 7) / 8];

	rds_for_each_conn_info(sock, len, iter, lens,
			       rds6_ib_conn_info_visitor, buffer,
			       sizeof(struct rds6_info_rdma_connection));
}
#endif

/*
 * Early RDS/IB was built to only bind to an address if there is an IPoIB
 * device with that address set.
 *
 * If it were me, I'd advocate for something more flexible.  Sending and
 * receiving should be device-agnostic.  Transports would try and maintain
 * connections between peers who have messages queued.  Userspace would be
 * allowed to influence which paths have priority.  We could call userspace
 * asserting this policy "routing".
 */
static int rds_ib_laddr_check_cm(struct net *net, const struct in6_addr *addr,
				 __u32 scope_id)
{
	int ret;
	struct rdma_cm_id *cm_id;
#if IS_ENABLED(CONFIG_IPV6)
	struct sockaddr_in6 sin6;
#endif
	struct sockaddr_in sin;
	struct sockaddr *sa;
	bool isv4;

	isv4 = ipv6_addr_v4mapped(addr);
	/* Link-local addresses don't play well with IB */
	if (isv4 && ipv4_is_linklocal_169(addr->s6_addr32[3])) {
		pr_info_once("\n");
		pr_info_once("****************************************************\n");
		pr_info_once("** WARNING WARNING WARNING WARNING WARNING        **\n");
		pr_info_once("**                                                **\n");
		pr_info_once("** RDS/IB: Link local address %pI6c NOT SUPPORTED  **\n",
			     addr);
		pr_info_once("**                                                **\n");
		pr_info_once("** HAIP IP addresses should not be used on ORACLE **\n");
		pr_info_once("** engineered systems                             **\n");
		pr_info_once("**                                                **\n");
		pr_info_once("** If you see this message, Please refer to       **\n");
		pr_info_once("** cluster_interconnects in MOS note #1274318.1   **\n");
		pr_info_once("****************************************************\n");
	}

	/* Create a CMA ID and try to bind it. This catches both
	 * IB and iWARP capable NICs.
	 */
	cm_id = rdma_create_id(net, rds_rdma_cm_event_handler,
			       NULL, RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(cm_id))
		return -EADDRNOTAVAIL;

	if (isv4) {
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = addr->s6_addr32[3];
		sa = (struct sockaddr *)&sin;
	} else {
#if IS_ENABLED(CONFIG_IPV6)
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_addr = *addr;
		sin6.sin6_scope_id = scope_id;
		sa = (struct sockaddr *)&sin6;

		/* XXX Do a special IPv6 link local address check here.  The
		 * reason is that rdma_bind_addr() always succeeds with IPv6
		 * link local address regardless if it is configured or not in
		 * a system.
		 */
		if (ipv6_addr_type(addr) & IPV6_ADDR_LINKLOCAL) {
			struct net_device *dev;

			if (scope_id == 0) {
				ret = -EADDRNOTAVAIL;
				goto out;
			}

			/* Use init_net for now as RDS is not network
			 * name space aware.
			 */
			dev = dev_get_by_index(&init_net, scope_id);
			if (!dev) {
				ret = -EADDRNOTAVAIL;
				goto out;
			}
			if (!ipv6_chk_addr(&init_net, addr, dev, 1)) {
				dev_put(dev);
				ret = -EADDRNOTAVAIL;
				goto out;
			}
			dev_put(dev);
		}
#else
		ret = -EADDRNOTAVAIL;
		goto out;
#endif
	}

	/* rdma_bind_addr will only succeed for IB & iWARP devices */
	ret = rdma_bind_addr(cm_id, sa);
	/* due to this, we will claim to support iWARP devices unless we
	   check node_type. */
	if (ret || !cm_id->device || cm_id->device->node_type != RDMA_NODE_IB_CA)
		ret = -EADDRNOTAVAIL;

	rdsdebug("addr %pI6c%%%u ret %d node type %d\n",
		 addr, scope_id, ret,
		 cm_id->device ? cm_id->device->node_type : -1);

out:
	rdma_destroy_id(cm_id);

	return ret;
}

static int rds_ib_laddr_check(struct net *net, const struct in6_addr *addr,
			      __u32 scope_id)
{
	struct rds_ib_device *rds_ibdev;

	/* RDS/IB is only supported in the initial network namespace */
	if (!net_eq(net, &init_net))
		return -EPROTOTYPE;

	rds_ibdev = rds_ib_get_device(addr);
	if (rds_ibdev) {
		rds_ib_dev_put(rds_ibdev);

		return 0;
	}

	return rds_ib_laddr_check_cm(net, addr, scope_id);
}

/* Device removal worker function.  It just calls rds_ib_remove_one().  The
 * reason to have this is to hang out the removal work to a workqueue so
 * that different threads can work on different devices.
 */
static void rds_dev_removal_worker(struct work_struct *work)
{
	struct rds_ib_device *rds_ibdev;

	rds_ibdev = container_of(work, struct rds_ib_device, rid_dev_rem_work);
	rds_ib_remove_one(rds_ibdev->dev, rds_ibdev);
}

int rds_ib_add_one(struct ib_device *device)
{
	int error = 0;
	struct rds_ib_device *rds_ibdev;
	struct ib_device_attr *dev_attr;
	struct ib_udata uhw;
	char *reason = NULL;

	/* Only handle IB (no iWARP) devices */
	if (device->node_type != RDMA_NODE_IB_CA)
		return -EOPNOTSUPP;

	if (!(device->attrs.device_cap_flags & IB_DEVICE_MEM_MGT_EXTENSIONS)) {
		pr_info("RDS/IB: IB_DEVICE_MEM_MGT_EXTENSIONS NOT enabled for ib_device: %s\n",
			device->name);
		return -EOPNOTSUPP;
	}

	trace_rds_ib_add_device(device, NULL, NULL, NULL,
				"adding IB device", 0);

	dev_attr = kmalloc(sizeof(*dev_attr), GFP_KERNEL);
	if (!dev_attr) {
		error = -ENOMEM;
		reason = "could not allocate dev_attr";
		goto trace_err;
	}

	memset(&uhw, 0, sizeof(uhw));
	if ((*device->ops.query_device)(device, dev_attr, &uhw)) {
		error = -ENOSYS;
		reason = "query device failed";
		goto free_attr;
	}

	rds_ibdev = kzalloc_node(sizeof(*rds_ibdev), GFP_KERNEL,
				 ibdev_to_node(device));
	if (!rds_ibdev) {
		error = -ENOMEM;
		reason = "could not allocate rds_ibdev";
		goto free_attr;
	}

	INIT_LIST_HEAD(&rds_ibdev->ipaddr_list);
	INIT_LIST_HEAD(&rds_ibdev->conn_list);

	spin_lock_init(&rds_ibdev->spinlock);
	atomic_set(&rds_ibdev->rid_refcount, 1);

	/* rds_rdma_mod_ref must be incremented here, as any error condition
	 * activating the work queue calling rds_ib_dev_free() will decrement
	 * it.
	 */
	atomic_inc(&rds_rdma_mod_ref);

	INIT_WORK(&rds_ibdev->rid_free_work, rds_ib_dev_free);
	INIT_WORK(&rds_ibdev->rid_dev_rem_work, rds_dev_removal_worker);

	rds_ibdev->max_wrs = dev_attr->max_qp_wr;
	rds_ibdev->max_sge = min(dev_attr->max_send_sge, dev_attr->max_recv_sge);
	if (rds_ibdev->max_sge > RDS_IB_MAX_SGE)
		rds_ibdev->max_sge = RDS_IB_MAX_SGE;

	WARN_ON(rds_ibdev->max_sge < 2);

	rds_ibdev->max_1m_mrs = dev_attr->max_mr ?
		min_t(unsigned int, dev_attr->max_mr,
		      rds_ib_mr_1m_pool_size) :
		      rds_ib_mr_1m_pool_size;

	rds_ibdev->max_8k_mrs = dev_attr->max_mr ?
		min_t(unsigned int, dev_attr->max_mr,
		      rds_ib_mr_8k_pool_size) :
		      rds_ib_mr_8k_pool_size;

	rds_ibdev->max_initiator_depth = dev_attr->max_qp_init_rd_atom;
	rds_ibdev->max_responder_resources = dev_attr->max_qp_rd_atom;

	atomic_inc(&rds_ib_devices_to_free);

	rds_ibdev->dev = device;

	/* RNR Retry Timer check with firmware version */
	if (rds_ibdev->dev->attrs.vendor_id == 0x02c9 && /* IEEE OUI - Mellanox vendor ID */
	    (rds_ibdev->dev->attrs.vendor_part_id == 0x1017 ||  /* ConnectX-5, PCIe 3.0 */
	     rds_ibdev->dev->attrs.vendor_part_id == 0x1018 ||  /* ConnectX-5 VF */
	     rds_ibdev->dev->attrs.vendor_part_id == 0x1019 ||  /* ConnectX-5 Ex */
	     rds_ibdev->dev->attrs.vendor_part_id == 0x101a) && /* ConnectX-5 Ex VF */
	    rds_ibdev->dev->attrs.fw_ver < fw_ver_16_32_1010)
		rds_ibdev->i_work_arounds |= RDS_IB_DEV_WA_INCORRECT_RNR_TIMER;

	rds_ibdev->pd = ib_alloc_pd(device, 0);
	if (IS_ERR(rds_ibdev->pd)) {
		error = PTR_ERR(rds_ibdev->pd);
		rds_ibdev->pd = NULL;
		reason = "ib_alloc_pd failed";
		goto put_dev;
	}

	rds_ibdev->rid_dev_wq = alloc_workqueue("rds_%s_wq", WQ_UNBOUND, 0,
						device->name);
	if (!rds_ibdev->rid_dev_wq) {
		error = -ENOMEM;
		reason = "no wq";
		goto put_dev;
	}

	rds_ibdev->vector_load = kzalloc(sizeof(int) * RDS_IB_NMBR_TOS_ROWS *
					 device->num_comp_vectors, GFP_KERNEL);
	if (!rds_ibdev->vector_load) {
		pr_err("RDS/IB: failed to allocate vector memory\n");
		error = -ENOMEM;
		reason = "failed to allocate vector memory";
		goto put_dev;
	}
	mutex_init(&rds_ibdev->vector_load_lock);

	rds_ibdev->mr = rds_ib_get_dma_mr(rds_ibdev->pd, IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(rds_ibdev->mr)) {
		error = PTR_ERR(rds_ibdev->mr);
		rds_ibdev->mr = NULL;
		reason = "rds_ib_get_dma_mr failed";
		goto put_dev;
	}

	INIT_WORK(&rds_ibdev->fastreg_reset_w, rds_ib_reset_fastreg);
	init_rwsem(&rds_ibdev->fastreg_lock);
	atomic_set(&rds_ibdev->fastreg_wrs, RDS_IB_DEFAULT_FREG_WR);
	error = rds_ib_setup_fastreg(rds_ibdev);
	if (error) {
		pr_err("RDS/IB: Failed to setup fastreg resources\n");
		reason = "rds_ib_setup_fastreg failed";
		goto put_dev;
	}

	pr_info("RDS/IB: FRWR will be used for ib_device: %s\n", device->name);

	rds_ibdev->mr_1m_pool =
		rds_ib_create_mr_pool(rds_ibdev, RDS_IB_MR_1M_POOL);
	if (IS_ERR(rds_ibdev->mr_1m_pool)) {
		error = PTR_ERR(rds_ibdev->mr_1m_pool);
		rds_ibdev->mr_1m_pool = NULL;
		reason = "rds_ib_create_mr_pool (1m) failed";
		goto put_dev;
	}

	rds_ibdev->mr_8k_pool =
		rds_ib_create_mr_pool(rds_ibdev, RDS_IB_MR_8K_POOL);
	if (IS_ERR(rds_ibdev->mr_8k_pool)) {
		error = PTR_ERR(rds_ibdev->mr_8k_pool);
		rds_ibdev->mr_8k_pool = NULL;
		reason = "reds_ib_create_mr_pool (8k) failed";
		goto put_dev;
	}

	if (rds_ib_srq_init(rds_ibdev)) {
		error = -EIO;
		reason = "rds_ib_srq_init failed";
		goto put_dev;
	}

	error = rds_ib_alloc_caches(rds_ibdev);
	if (error) {
		reason = "rds_ib_alloc_caches failed";
		goto put_dev;
	}

	INIT_LIST_HEAD(&rds_ibdev->rid_rs_list);
	spin_lock_init(&rds_ibdev->rid_rs_list_lock);

	down_write(&rds_ib_devices_lock);
	list_add_tail_rcu(&rds_ibdev->list, &rds_ib_devices);
	up_write(&rds_ib_devices_lock);

	ib_set_client_data(device, &rds_ib_client, rds_ibdev);

	/* Check if those connections not associated with a device can
	 * make use of this newly added one.
	 */
	rds_ib_nodev_connect();

	ib_rds_create_debugfs_cache_hit(rds_ibdev);

	/* Tuning for BM machines */
	if (!uek_runs_in_kvm())
		rds_ib_sysctl_ring_mid_permille = 750;

	goto free_attr;

put_dev:
	rds_ib_dev_put(rds_ibdev);
free_attr:
	kfree(dev_attr);
trace_err:
	if (reason)
		trace_rds_ib_add_device_err(device, NULL, NULL, NULL,
					    reason, error);

	return error;
}

static void rds_ib_unregister_client(void)
{
	/* This triggers the upcall to remove all the RDMA devices. */
	ib_unregister_client(&rds_ib_client);
}

int rds_ib_init(void)
{
	int ret;

	INIT_LIST_HEAD(&rds_ib_devices);

	debugfs_basedir = debugfs_create_dir("rds_cache", NULL);
	if (!debugfs_basedir)
		pr_err("RDS/IB: can't create debugfs_basedir\n");

	/* Initialise the RDS IB fragment size */
	rds_ib_init_frag(RDS_PROTOCOL_VERSION);

	ret = rds_ib_sysctl_init();
	if (ret)
		goto out;

	ret = rds_ib_recv_init();
	if (ret)
		goto out_sysctl;

	rds_aux_wq = alloc_workqueue("%s", 0, 0, "krdsd_aux");
	if (!rds_aux_wq) {
		pr_err("%s: failed to create aux workqueue\n", __func__);
		goto out_recv;
	}

	rds_evt_wq = alloc_workqueue("krdsd_evt", 0, 0);
	if (!rds_evt_wq) {
		pr_err("RDS/IB: failed to create evt workqueue\n");
		goto out_aux_wq;
	}

	ret = rds_trans_register(&rds_ib_transport);
	if (ret)
		goto out_evt_wq;

	rds_info_register_func(RDS_INFO_IB_CONNECTIONS, rds_ib_ic_info);
#if IS_ENABLED(CONFIG_IPV6)
	rds_info_register_func(RDS6_INFO_IB_CONNECTIONS, rds6_ib_ic_info);
#endif

	/* Register with RDMA framework at last.  Once registered, upcall
	 * can be made so everything should be set up first.
	 */
	ret = ib_register_client(&rds_ib_client);
	if (ret) {
		pr_err("%s: ib_register_client() failed\n", __func__);
		goto out_trans;
	}

	goto out;

out_trans:
        rds_trans_unregister(&rds_ib_transport);
out_evt_wq:
	destroy_workqueue(rds_evt_wq);
out_aux_wq:
	destroy_workqueue(rds_aux_wq);
out_recv:
	rds_ib_recv_exit();
out_sysctl:
	rds_ib_sysctl_exit();
out:
	return ret;
}

void rds_ib_exit(void)
{
	struct rds_ib_device *rds_ibdev;

	/* After unregistering the module, no new connection will be made
	 * using this transport.
	 */
	rds_trans_unregister(&rds_ib_transport);

	rds_info_deregister_func(RDS_INFO_IB_CONNECTIONS, rds_ib_ic_info);
#if IS_ENABLED(CONFIG_IPV6)
	rds_info_deregister_func(RDS6_INFO_IB_CONNECTIONS, rds6_ib_ic_info);
#endif
	down_read(&rds_ib_devices_lock);
	list_for_each_entry(rds_ibdev, &rds_ib_devices, list) {
		rds_ibdev->rid_mod_unload = true;

		/* Stop connection attempts from getting a reference to this
		 * device.  And doing this also removes the race if the
		 * device is also being removed and the remove upcall is done
		 * at the same time.
		 */
		ib_set_client_data(rds_ibdev->dev, &rds_ib_client, NULL);

		/* The worker function just calls rds_ib_remove_one().  When
		 * rds_ib_remove_one() tries to remove this device from the
		 * rds_ib_devices list, it will block if this loop has not
		 * finished.  But that should be OK.
		 */
		queue_work(rds_aux_wq, &rds_ibdev->rid_dev_rem_work);
	}
	up_read(&rds_ib_devices_lock);

	/* Now wait for all the device free work to finish before freeing all
	 * other resource.
	 */
	flush_workqueue(rds_wq);
	wait_event(rds_rdma_zero_dev, !atomic_read(&rds_rdma_mod_ref));

	/* Calling ib_unregister_client() triggers the upcall to
	 * rds_ib_remove_one() to remove all RDMA devices sequentially.
	 * But since all devices should be freed at this point, so the
	 * client_data passed to rds_ib_remove_one() should be NULL.  Hence
	 * it will return immediately.
	 */
	rds_ib_unregister_client();

	/* Now kill all RDS/RDMA connection without an associated device. */
	rds_ib_destroy_nodev_conns();

	/* There should not be any RDS/RDMA connections. */
	WARN_ON(atomic_read(&rds_ib_transport.t_conn_count));

	rds_ib_sysctl_exit();
	rds_ib_recv_exit();

	destroy_workqueue(rds_evt_wq);
	destroy_workqueue(rds_aux_wq);
	debugfs_remove_recursive(debugfs_basedir);
}

struct rds_transport rds_ib_transport = {
	.laddr_check		= rds_ib_laddr_check,
	.xmit_path_complete	= rds_ib_xmit_path_complete,
	.xmit			= rds_ib_xmit,
	.xmit_rdma		= rds_ib_xmit_rdma,
	.xmit_atomic		= rds_ib_xmit_atomic,
	.recv_path		= rds_ib_recv_path,
	.recv_need_bufs         = rds_ib_recv_need_bufs,
	.conn_alloc		= rds_ib_conn_alloc,
	.conn_free		= rds_ib_conn_free,
	.conn_preferred_cpu	= rds_ib_conn_preferred_cpu,
	.conn_has_alt_conn	= rds_ib_conn_has_alt_conn,
	.conn_path_reset	= rds_ib_conn_path_reset,
	.conn_path_connect	= rds_ib_conn_path_connect,
	.conn_path_shutdown_prepare	= rds_ib_conn_path_shutdown_prepare,
	.conn_path_shutdown_check_wait	= rds_ib_conn_path_shutdown_check_wait,
	.conn_path_shutdown_tidy_up	= rds_ib_conn_path_shutdown_tidy_up,
	.conn_path_shutdown_final	= rds_ib_conn_path_shutdown_final,
	.conn_path_shutdown	= rds_ib_conn_path_shutdown,
	.inc_copy_to_user	= rds_ib_inc_copy_to_user,
	.inc_free		= rds_ib_inc_free,
	.cm_initiate_connect	= rds_ib_cm_initiate_connect,
	.cm_handle_connect	= rds_ib_cm_handle_connect,
	.cm_connect_complete	= rds_ib_cm_connect_complete,
	.conn_ha_changed	= rds_ib_conn_ha_changed,
	.stats_info_copy	= rds_ib_stats_info_copy,
	.get_mr			= rds_ib_get_mr,
	.sync_mr		= rds_ib_sync_mr,
	.free_mr		= rds_ib_free_mr,
	.flush_mrs		= rds_ib_flush_mrs,
	.sock_release		= rds_rdma_sock_release,
	.process_send_cmsg	= rds_rdma_process_send_cmsg,

	.t_owner		= THIS_MODULE,
	.t_name			= "infiniband",
	.t_type			= RDS_TRANS_IB,
	.t_conn_count		= ATOMIC_INIT(0),
};

MODULE_LICENSE("GPL");
