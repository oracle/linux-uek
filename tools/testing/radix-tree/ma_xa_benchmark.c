// SPDX-License-Identifier: GPL-2.0+
/*
 * ma_rdx_time.c: userspace time test of maple tree and radix tree.
 * Copyright (c) 2019 Liam R. Howlett <Liam.Howlett@Oracle.com>
 */

#define CONFIG_DEBUG_MAPLE_TREE
#define XA_DEBUG
#include "test.h"
#include <time.h>
#include <sys/resource.h>

#define module_init(x)
#define module_exit(x)
#define MODULE_AUTHOR(x)
#define MODULE_LICENSE(x)
#define dump_stack()	assert(0)

#include <linux/maple_tree.h>
#include <linux/xarray.h>

extern unsigned long kmem_cache_get_alloc(struct kmem_cache *);
extern struct kmem_cache *radix_tree_node_cachep;
unsigned long xa_get_alloc_size(void)
{
	return kmem_cache_get_alloc(radix_tree_node_cachep);
}

extern unsigned long mt_get_alloc_size(void);

int __weak main(void)
{
	clock_t start, end;
	double xa_t = 0, mt_t;
	unsigned long xa_m = 0, mt_m;
	void *entry = &main;
	unsigned long i, max = 200000;
	struct rusage sru, eru;

	/*  xarray first */
	radix_tree_init();
	DEFINE_XARRAY(xa);

	getrusage(RUSAGE_SELF, &sru);
	for (i = 0; i <= max; i++) {
		xa_store(&xa, i, entry, GFP_KERNEL);
	}
	getrusage(RUSAGE_SELF, &eru);

	start = sru.ru_utime.tv_usec + sru.ru_utime.tv_sec * 1000000;
	end = eru.ru_utime.tv_usec + eru.ru_utime.tv_sec * 1000000;
	for (i = 0; i <= max; i++) {
		BUG_ON(entry != xa_load(&xa, i));
	}
	rcu_barrier();
	xa_t = ((double) (end - start)) / 1000000;
	xa_m = xa_get_alloc_size();
	printk("xa %lu inserts: %fs using %luK in %d allocations\n",
		max, xa_t, xa_m/1024, nr_allocated);


	xa_destroy(&xa);
	radix_tree_cpu_dead(1);
	rcu_barrier();
	BUG_ON(nr_allocated);

	/* Maple Tree tests*/
	maple_tree_init();
	DEFINE_MTREE(mt);
	getrusage(RUSAGE_SELF, &sru);
	for (i = 0; i <= max; i++) {
		mtree_insert(&mt, i, entry, GFP_KERNEL);
	}

	getrusage(RUSAGE_SELF, &eru);
	start = sru.ru_utime.tv_usec + sru.ru_utime.tv_sec * 1000000;
	end = eru.ru_utime.tv_usec + eru.ru_utime.tv_sec * 1000000;
	for (i = 0; i <= max; i++) {
		BUG_ON(entry != mtree_load(&mt, i));
	}

	rcu_barrier();
	mt_t = ((double) (end - start))/1000000;
	mt_m = mt_get_alloc_size();
	printk("mt %lu inserts: %fs using %luK in %d allocations\n",
		max, mt_t, mt_m/1024, nr_allocated);
	mtree_destroy(&mt);
	rcu_barrier();
	printk(" Delta : %f seconds (%f%% of xa time) %ldK\n",
		mt_t - xa_t, mt_t/xa_t * 100,
		(signed long)(mt_m - xa_m)/1024);
	rcu_barrier();
	BUG_ON(nr_allocated);
	return 0;
}
