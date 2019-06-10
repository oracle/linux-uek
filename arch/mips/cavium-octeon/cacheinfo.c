/*
 * Processor cache information made available to userspace via sysfs;
 * intended to be compatible with x86 intel_cacheinfo implementation.
 *
 * This is derived from the PowerPC implementation.
 *
 * Copyright 2012 Cavium, Inc.
 * Author: Aaron Williams
 *
 * This program is free software; you can reistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 */

#include <linux/cpu.h>
#include <linux/cpumask.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/notifier.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/module.h>

/*
 * per-cpu object for tracking:
 * - a "cache" kobject for the top-level directory
 * - a list of "index" objects representing the cpu's local cache hierarchy
 */
struct cache_dir {
	/* bare (not embedded) kobject for cache directory */
	struct kobject *kobj;
	struct cache_index_dir *index; /* list of index objects */
};

/*
 * "index" object: each cpu's cache directory has an index
 * subdirectory corresponding to a cache object associated with the
 * cpu.  This object's lifetime is managed via the embedded kobject.
 */
struct cache_index_dir {
	struct kobject kobj;
	struct cache_index_dir *next; /* next index in parent directory */
	struct cache *cache;
};

/*
 * Template for determining which OF properties to query for a given
 * cache type
 */
struct cache_type_info {
	const char *name;
	const char *size_prop;

	/*
	 * Allow for both [di]-cache-line-size and
	 * [di]-cache-block-size properties.  According to the PowerPC
	 * Processor binding, -line-size should be provided if it
	 * differs from the cache block size (that which is operated
	 * on by cache instructions), so we look for -line-size first.
	 * See cache_get_line_size().
	 */

	const char *line_size_props[2];
	const char *nr_sets_prop;
};


/* These are used to index the cache_type_info array. */
#define CACHE_TYPE_UNIFIED     0
#define CACHE_TYPE_INSTRUCTION 1
#define CACHE_TYPE_DATA        2

static const struct cache_type_info cache_type_info[] = {
	{
		/*
		 * PowerPC Processor binding says the [di]-cache-*
		 * must be equal on unified caches, so just use
		 * d-cache properties.
		 */
		.name            = "Unified",
		.size_prop       = "d-cache-size",
		.line_size_props = { "d-cache-line-size",
				     "d-cache-block-size", },
		.nr_sets_prop    = "d-cache-sets",
	},
	{
		.name            = "Instruction",
		.size_prop       = "i-cache-size",
		.line_size_props = { "i-cache-line-size",
				     "i-cache-block-size", },
		.nr_sets_prop    = "i-cache-sets",
	},
	{
		.name            = "Data",
		.size_prop       = "d-cache-size",
		.line_size_props = { "d-cache-line-size",
				     "d-cache-block-size", },
		.nr_sets_prop    = "d-cache-sets",
	},
};

/*
 * Cache object: each instance of this corresponds to a distinct cache
 * in the system.  There are separate objects for Harvard caches: one
 * each for instruction and data, and each refers to the same OF node.
 * The refcount of the OF node is elevated for the lifetime of the
 * cache object.  A cache object is released when its shared_cpu_map
 * is cleared (see cache_cpu_clear).
 *
 * A cache object is on two lists: an unsorted global list
 * (cache_list) of cache objects; and a singly-linked list
 * representing the local cache hierarchy, which is ordered by level
 * (e.g. L1d -> L1i -> L2 -> L3).
 */
struct cache {
	const struct cache_desc *cache_desc;
	struct cpumask shared_cpu_map; /* online CPUs using this cache */
	int type;                      /* split cache disambiguation */
	int level;                     /* level not explicit in device tree */
	unsigned int cpu_id;            /* CPU ID of cache */
	struct list_head list;         /* global list of cache objects */
	struct cache *next_local;      /* next cache of >= level */
};

static DEFINE_PER_CPU(struct cache_dir *, cache_dir_pcpu);

/*
 * traversal/modification of this list occurs only at cpu hotplug
 * time; access is serialized by cpu hotplug locking
 */
static LIST_HEAD(cache_list);

static struct cache_index_dir *kobj_to_cache_index_dir(struct kobject *k)
{
	return container_of(k, struct cache_index_dir, kobj);
}

static const char *cache_type_string(const struct cache *cache)
{
	return cache_type_info[cache->type].name;
}

/*
 * NOTE: This does not just return cache->cache_desc but obtains it
 * from the cpu_data data structure.
 */
static struct cache_desc *get_cache_desc(const struct cache *cache)
{
	if (WARN_ON(cache->cpu_id >= num_possible_cpus()))
		return NULL;

	if (cache->level == 2)
		return &cpu_data[cache->cpu_id].scache;
	else if (cache->level == 1) {
		if (cache->type == CACHE_TYPE_INSTRUCTION)
			return &cpu_data[cache->cpu_id].icache;
		else if (cache->type == CACHE_TYPE_DATA)
			return &cpu_data[cache->cpu_id].dcache;
	}
	pr_err("Error: Cannot get cache descriptor!  Invalid cache type %d, level %d for cpuid %d\n",
	       cache->cpu_id, cache->level, cache->type);
	return NULL;
}

static void cache_init(struct cache *cache, unsigned int cpu_id,
				 int level, int type)
{
	cache->type = type;
	cache->level = level;
	cache->cpu_id = cpu_id;
	cache->cache_desc = get_cache_desc(cache);

	INIT_LIST_HEAD(&cache->list);
	list_add(&cache->list, &cache_list);
}

/* Allocates and initializes a new cache structure */
static struct cache *new_cache(int type, int level,
			       unsigned int cpu_id)
{
	struct cache *cache;

	cache = kzalloc(sizeof(*cache), GFP_KERNEL);
	if (cache)
		cache_init(cache, cpu_id, level, type);

	return cache;
}

static void release_cache_debugcheck(struct cache *cache)
{
	struct cache *iter;

	list_for_each_entry(iter, &cache_list, list)
		WARN_ONCE(iter->next_local == cache,
			  "cache for %s refers to cache for %s\n",
			  cache_type_string(iter),
			  cache_type_string(cache));
}

static void release_cache(struct cache *cache)
{
	if (!cache)
		return;

	pr_debug("freeing L%d %s cache\n", cache->level,
		 cache_type_string(cache));

	release_cache_debugcheck(cache);
	list_del(&cache->list);
	kfree(cache);
}

static void cache_cpu_set(struct cache *cache, int cpu)
{
	struct cache *next = cache;

	while (next) {
		if (next->level == 1) {
			WARN_ONCE(cpumask_test_cpu(cpu, &next->shared_cpu_map),
				 "CPU %i already accounted in %s\n",
				 cpu, cache_type_string(next));
			cpumask_set_cpu(cpu, &next->shared_cpu_map);
		} /* level 2 is handled separately */
		next = next->next_local;
	}
}

static int cache_size(const struct cache *cache, unsigned int *ret)
{
	const struct cache_desc *cd = cache->cache_desc;

	if (!cd)
		return -1;

	*ret = cd->ways * cd->waysize;

	return 0;
}

static int cache_size_kb(const struct cache *cache, unsigned int *ret)
{
	unsigned int size;

	if (cache_size(cache, &size))
		return -ENODEV;

	*ret = size / 1024;
	return 0;
}

/* not cache_line_size() because that's a macro in include/linux/cache.h */
static int cache_get_line_size(const struct cache *cache, unsigned int *ret)
{
	*ret = cache->cache_desc->linesz;

	return 0;
}

static int cache_nr_sets(const struct cache *cache, unsigned int *ret)
{
	*ret = cache->cache_desc->sets;

	return 0;
}

static int cache_associativity(const struct cache *cache, unsigned int *ret)
{
	unsigned int line_size;
	unsigned int nr_sets;
	unsigned int size;

	if (cache_nr_sets(cache, &nr_sets))
		goto err;

	/*
	 * If the cache is fully associative, there is no need to
	 * check the other properties.
	 */
	if (nr_sets == 1) {
		*ret = 0;
		return 0;
	}

	if (cache_get_line_size(cache, &line_size))
		goto err;
	if (cache_size(cache, &size))
		goto err;

	if (!(nr_sets > 0 && size > 0 && line_size > 0))
		goto err;

	*ret = (size / nr_sets) / line_size;
	return 0;
err:
	return -ENODEV;
}

static struct cache *cache_find_first_sibling(struct cache *cache)
{
	struct cache *iter;

	if (cache->type == CACHE_TYPE_UNIFIED)
		return cache;

	list_for_each_entry(iter, &cache_list, list)
	if (iter->cpu_id == cache->cpu_id && iter->next_local == cache)
		return iter;

	return cache;
}

static struct cache *cache_lookup_by_cpuid(unsigned int cpu_id)
{
	struct cache *cache = NULL;
	struct cache *iter;

	list_for_each_entry(iter, &cache_list, list) {
		if (iter->cpu_id != cpu_id)
			continue;
		cache = cache_find_first_sibling(iter);
		break;
	}

	return cache;
}

static void link_cache_lists(struct cache *smaller,
				       struct cache *bigger)
{
	while (smaller->next_local) {
		if (smaller->next_local == bigger)
			return; /* already linked */
		smaller = smaller->next_local;
	}

	smaller->next_local = bigger;
}

static struct cache *cache_chain_instantiate(unsigned int cpu_id)
{
	struct cache *l2_cache = NULL, *l1i_cache = NULL, *l1d_cache = NULL;
	unsigned int l1i_size = 0, l1d_size = 0;

	pr_debug("creating cache object(s) for CPU %i\n", cpu_id);


	l2_cache = new_cache(CACHE_TYPE_UNIFIED, 2, cpu_id);
	if (!l2_cache)
		return NULL;

	l1i_cache = new_cache(CACHE_TYPE_INSTRUCTION, 1, cpu_id);
	if (!l1i_cache)
		goto err;

	l1d_cache = new_cache(CACHE_TYPE_DATA, 1, cpu_id);
	if (!l1d_cache)
		goto err;

	if (cache_size(l1i_cache, &l1i_size))
		goto err;
	if (cache_size(l1d_cache, &l1d_size))
		goto err;

	if (l1i_size > l1d_size) {
		link_cache_lists(l1d_cache, l1i_cache);
		link_cache_lists(l1i_cache, l2_cache);
		cache_cpu_set(l1d_cache, cpu_id);
		return l1d_cache;
	}
	link_cache_lists(l1i_cache, l1d_cache);
	link_cache_lists(l1d_cache, l2_cache);
	cache_cpu_set(l1i_cache, cpu_id);
	return l1i_cache;
err:
	if (l2_cache)
		release_cache(l2_cache);
	if (l1i_cache)
		release_cache(l1i_cache);
	if (l1d_cache)
		release_cache(l1d_cache);

	return NULL;
}

static struct cache_dir *cacheinfo_create_cache_dir(unsigned int cpu_id)
{
	struct cache_dir *cache_dir;
	struct device *dev;
	struct kobject *kobj = NULL;

	dev = get_cpu_device(cpu_id);
	WARN_ONCE(!dev, "no sysdev for CPU %i\n", cpu_id);
	if (!dev)
		goto err;

	kobj = kobject_create_and_add("cache", &dev->kobj);
	if (!kobj)
		goto err;

	cache_dir = kzalloc(sizeof(*cache_dir), GFP_KERNEL);
	if (!cache_dir)
		goto err;

	cache_dir->kobj = kobj;

	WARN_ON_ONCE(per_cpu(cache_dir_pcpu, cpu_id) != NULL);

	per_cpu(cache_dir_pcpu, cpu_id) = cache_dir;

	return cache_dir;
err:
	kobject_put(kobj);
	return NULL;
}

static void cache_index_release(struct kobject *kobj)
{
	struct cache_index_dir *index;

	index = kobj_to_cache_index_dir(kobj);

	pr_debug("freeing index directory for L%d %s cache\n",
		 index->cache->level, cache_type_string(index->cache));

	kfree(index);
}

static ssize_t cache_index_show(struct kobject *k, struct attribute *attr,
				char *buf)
{
	struct kobj_attribute *kobj_attr;

	kobj_attr = container_of(attr, struct kobj_attribute, attr);

	return kobj_attr->show(k, kobj_attr, buf);
}

static struct cache *index_kobj_to_cache(struct kobject *k)
{
	struct cache_index_dir *index;

	index = kobj_to_cache_index_dir(k);

	return index->cache;
}

static ssize_t size_show(struct kobject *k, struct kobj_attribute *attr,
			 char *buf)
{
	unsigned int size_kb;
	struct cache *cache;

	cache = index_kobj_to_cache(k);

	if (cache_size_kb(cache, &size_kb))
		return -ENODEV;

	return sprintf(buf, "%uK\n", size_kb);
}

static struct kobj_attribute cache_size_attr =
	__ATTR(size, 0444, size_show, NULL);


static ssize_t line_size_show(struct kobject *k, struct kobj_attribute *attr,
			      char *buf)
{
	unsigned int line_size;
	struct cache *cache;

	cache = index_kobj_to_cache(k);

	if (cache_get_line_size(cache, &line_size))
		return -ENODEV;

	return sprintf(buf, "%u\n", line_size);
}

static struct kobj_attribute cache_line_size_attr =
	__ATTR(coherency_line_size, 0444, line_size_show, NULL);

static ssize_t nr_sets_show(struct kobject *k, struct kobj_attribute *attr,
			    char *buf)
{
	unsigned int nr_sets;
	struct cache *cache;

	cache = index_kobj_to_cache(k);

	if (cache_nr_sets(cache, &nr_sets))
		return -ENODEV;

	return sprintf(buf, "%u\n", nr_sets);
}

static struct kobj_attribute cache_nr_sets_attr =
	__ATTR(number_of_sets, 0444, nr_sets_show, NULL);

static ssize_t associativity_show(struct kobject *k, struct kobj_attribute *attr, char *buf)
{
	unsigned int associativity;
	struct cache *cache;

	cache = index_kobj_to_cache(k);

	if (cache_associativity(cache, &associativity))
		return -ENODEV;

	return sprintf(buf, "%u\n", associativity);
}

static struct kobj_attribute cache_assoc_attr =
	__ATTR(ways_of_associativity, 0444, associativity_show, NULL);

static ssize_t type_show(struct kobject *k, struct kobj_attribute *attr,
			 char *buf)
{
	struct cache *cache;

	cache = index_kobj_to_cache(k);

	return sprintf(buf, "%s\n", cache_type_string(cache));
}

static struct kobj_attribute cache_type_attr =
	__ATTR(type, 0444, type_show, NULL);

static ssize_t level_show(struct kobject *k, struct kobj_attribute *attr,
			  char *buf)
{
	struct cache_index_dir *index;
	struct cache *cache;

	index = kobj_to_cache_index_dir(k);
	cache = index->cache;

	return sprintf(buf, "%d\n", cache->level);
}

static struct kobj_attribute cache_level_attr =
	__ATTR(level, 0444, level_show, NULL);

static ssize_t shared_cpu_map_show(struct kobject *k,
				   struct kobj_attribute *attr, char *buf)
{
	struct cache_index_dir *index;
	struct cache *cache;
	int len;
	int n = 0;

	index = kobj_to_cache_index_dir(k);
	cache = index->cache;
	len = PAGE_SIZE - 2;

	if (len > 1) {
		n = scnprintf(buf, len, "%*pb\n",
			      cpumask_pr_args(&cache->shared_cpu_map));
		buf[n++] = '\n';
		buf[n] = '\0';
	}
	return n;
}

static struct kobj_attribute cache_shared_cpu_map_attr =
	__ATTR(shared_cpu_map, 0444, shared_cpu_map_show, NULL);

/*
 * Attributes which should always be created -- the kobject/sysfs core
 * does this automatically via kobj_type->default_attrs.  This is the
 * minimum data required to uniquely identify a cache.
 */
static struct attribute *cache_index_default_attrs[] = {
	&cache_type_attr.attr,
	&cache_level_attr.attr,
	&cache_shared_cpu_map_attr.attr,
	NULL,
};

/*
 * Attributes which should be created if the cache device node has the
 * right properties -- see cacheinfo_create_index_opt_attrs
 */
static struct kobj_attribute *cache_index_opt_attrs[] = {
	&cache_size_attr,
	&cache_line_size_attr,
	&cache_nr_sets_attr,
	&cache_assoc_attr,
};

static const struct sysfs_ops cache_index_ops = {
	.show = cache_index_show,
};

static struct kobj_type cache_index_type = {
	.release = cache_index_release,
	.sysfs_ops = &cache_index_ops,
	.default_attrs = cache_index_default_attrs,
};

static void cacheinfo_create_index_opt_attrs(struct cache_index_dir *dir)
{
	const char *cache_type;
	struct cache *cache;
	char *buf;
	int i;

	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buf)
		return;

	cache = dir->cache;
	cache_type = cache_type_string(cache);

	/*
	 * We don't want to create an attribute that can't provide a
	 * meaningful value.  Check the return value of each optional
	 * attribute's ->show method before registering the attribute.
	 */
	for (i = 0; i < ARRAY_SIZE(cache_index_opt_attrs); i++) {
		struct kobj_attribute *attr;
		ssize_t rc;

		attr = cache_index_opt_attrs[i];

		rc = attr->show(&dir->kobj, attr, buf);
		if (rc <= 0) {
			pr_debug("not creating %s attribute for %s (rc = %zd)\n",
				 attr->attr.name,
				 cache_type, rc);
			continue;
		}
		if (sysfs_create_file(&dir->kobj, &attr->attr))
			pr_debug("could not create %s attribute for %s\n",
				 attr->attr.name, cache_type);
	}

	kfree(buf);
}

static void cacheinfo_create_index_dir(struct cache *cache, int index,
						 struct cache_dir *cache_dir)
{
	struct cache_index_dir *index_dir;
	int rc;

	index_dir = kzalloc(sizeof(*index_dir), GFP_KERNEL);
	if (!index_dir)
		goto err;

	index_dir->cache = cache;

	rc = kobject_init_and_add(&index_dir->kobj, &cache_index_type,
				  cache_dir->kobj, "index%d", index);
	if (rc)
		goto err;

	index_dir->next = cache_dir->index;
	cache_dir->index = index_dir;

	cacheinfo_create_index_opt_attrs(index_dir);

	return;
err:
	kfree(index_dir);
}

static void cacheinfo_sysfs_populate(unsigned int cpu_id,
				     struct cache *cache_list)
{
	struct cache_dir *cache_dir;
	struct cache *cache;
	int index = 0;

	cache_dir = cacheinfo_create_cache_dir(cpu_id);
	if (!cache_dir)
		return;

	cache = cache_list;
	while (cache) {
		cacheinfo_create_index_dir(cache, index, cache_dir);
		index++;
		cache = cache->next_local;
	}
}

int cacheinfo_cpu_online(unsigned int cpu_id)
{
	struct cache *cache;
	struct cache *iter;

	cache = cache_chain_instantiate(cpu_id);
	if (!cache)
		return 0;

	/* Add all CPUs to the L2 cache for now */
	list_for_each_entry(iter, &cache_list, list) {
		if (iter->level == 2)
			cpumask_copy(&iter->shared_cpu_map, cpu_possible_mask);
	}

	cacheinfo_sysfs_populate(cpu_id, cache);

	return 0;
}

static void remove_index_dirs(struct cache_dir *cache_dir)
{
	struct cache_index_dir *index;

	index = cache_dir->index;

	while (index) {
		struct cache_index_dir *next;

		next = index->next;
		kobject_put(&index->kobj);
		index = next;
	}
}

static void remove_cache_dir(struct cache_dir *cache_dir)
{
	remove_index_dirs(cache_dir);

	kobject_put(cache_dir->kobj);

	kfree(cache_dir);
}

static void cache_cpu_clear(struct cache *cache, int cpu)
{
	while (cache) {
		struct cache *next = cache->next_local;

		if (cache->cpu_id == cpu) {
			if (cache->level == 1) {
				WARN_ONCE(!cpumask_test_cpu(cpu,
							    &cache->shared_cpu_map),
					  "CPU %i level %d not accounted in %s\n",
					  cpu, cache->level,
					  cache_type_string(cache));

				cpumask_clear_cpu(cpu, &cache->shared_cpu_map);

				/*
				 * Release the cache object if all the cpus
				 * using it are offline
				 */
				if (cpumask_empty(&cache->shared_cpu_map))
					release_cache(cache);
			} else
				release_cache(cache);
		}
		cache = next;
	}
}

int cacheinfo_cpu_offline(unsigned int cpu_id)
{
	struct cache_dir *cache_dir;
	struct cache *cache;

	/*
	 * Prevent userspace from seeing inconsistent state - remove
	 * the sysfs hierarchy first
	 */
	cache_dir = per_cpu(cache_dir_pcpu, cpu_id);

	/* careful, sysfs population may have failed */
	if (cache_dir)
		remove_cache_dir(cache_dir);

	per_cpu(cache_dir_pcpu, cpu_id) = NULL;

	/*
	 * clear the CPU's bit in its cache chain, possibly freeing
	 * cache objects
	 */
	cache = cache_lookup_by_cpuid(cpu_id);
	if (cache)
		cache_cpu_clear(cache, cpu_id);

	return 0;
}

static int __init octeon_cacheinfo_init(void)
{
	return cpuhp_setup_state(CPUHP_ONLINE,
					 "mips/cavium:cacheinfo",
					 cacheinfo_cpu_online, cacheinfo_cpu_offline);
}

static void __init octeon_cacheinfo_cleanup(void)
{
	cpuhp_remove_state(CPUHP_ONLINE);
}

module_init(octeon_cacheinfo_init);
module_exit(octeon_cacheinfo_cleanup);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Cavium Inc. <support@cavium.com>");
MODULE_DESCRIPTION("Cavium Inc. OCTEON Cache Info driver");

