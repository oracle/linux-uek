// SPDX-License-Identifier: GPL-2.0-only
/*
 * MIPS cacheinfo support
 */
#include <linux/cacheinfo.h>

#ifdef CONFIG_CAVIUM_OCTEON_SOC
/*
 * This matches what arch/mips/cavium-octeon/cacheinfo.c
 * would do to populate shared_cpu_map. Without this
 * /sys/devices/system/cpu/cpu0/cache/index0/shared_cpu_map
 * will be missing and things that want or need it, like
 * lscpu, won't function.
 *
 * arch/mips/cavium-octeon/cacheinfo.c didn't run because
 * it was incompatible with the current architecture.
 */
static inline void populate_shared_cpu_map(uint cpu, struct cacheinfo *leaf)
{
	if (leaf->level == 1)
		cpumask_set_cpu(cpu, &leaf->shared_cpu_map);
	if (leaf->level == 2)
		cpumask_copy(&leaf->shared_cpu_map,
			cpu_possible_mask);
}
#else
static inline void populate_shared_cpu_map(uint cpu, struct cacheinfo *leaf)
{}
#endif

/* Populates leaf and increments to next leaf */
#define populate_cache(cache, leaf, c_level, c_type)		\
do {								\
	leaf->type = c_type;					\
	leaf->level = c_level;					\
	leaf->coherency_line_size = c->cache.linesz;		\
	leaf->number_of_sets = c->cache.sets;			\
	leaf->ways_of_associativity = c->cache.ways;		\
	leaf->size = c->cache.linesz * c->cache.sets *		\
		c->cache.ways;					\
	populate_shared_cpu_map(cpu, leaf);			\
	leaf++;							\
} while (0)

int init_cache_level(unsigned int cpu)
{
	struct cpuinfo_mips *c = &current_cpu_data;
	struct cpu_cacheinfo *this_cpu_ci = get_cpu_cacheinfo(cpu);
	int levels = 0, leaves = 0;

	/*
	 * If Dcache is not set, we assume the cache structures
	 * are not properly initialized.
	 */
	if (c->dcache.waysize)
		levels += 1;
	else
		return -ENOENT;


	leaves += (c->icache.waysize) ? 2 : 1;

	if (c->vcache.waysize) {
		levels++;
		leaves++;
	}

	if (c->scache.waysize) {
		levels++;
		leaves++;
	}

	if (c->tcache.waysize) {
		levels++;
		leaves++;
	}

	this_cpu_ci->num_levels = levels;
	this_cpu_ci->num_leaves = leaves;
	return 0;
}

static void fill_cpumask_siblings(int cpu, cpumask_t *cpu_map)
{
	int cpu1;

	for_each_possible_cpu(cpu1)
		if (cpus_are_siblings(cpu, cpu1))
			cpumask_set_cpu(cpu1, cpu_map);
}

static void fill_cpumask_cluster(int cpu, cpumask_t *cpu_map)
{
	int cpu1;
	int cluster = cpu_cluster(&cpu_data[cpu]);

	for_each_possible_cpu(cpu1)
		if (cpu_cluster(&cpu_data[cpu1]) == cluster)
			cpumask_set_cpu(cpu1, cpu_map);
}

int populate_cache_leaves(unsigned int cpu)
{
	struct cpuinfo_mips *c = &current_cpu_data;
	struct cpu_cacheinfo *this_cpu_ci = get_cpu_cacheinfo(cpu);
	struct cacheinfo *this_leaf = this_cpu_ci->info_list;
	int level = 1;

	if (c->icache.waysize) {
		/* I/D caches are per core */
		fill_cpumask_siblings(cpu, &this_leaf->shared_cpu_map);
		populate_cache(dcache, this_leaf, level, CACHE_TYPE_DATA);
		fill_cpumask_siblings(cpu, &this_leaf->shared_cpu_map);
		populate_cache(icache, this_leaf, level, CACHE_TYPE_INST);
		level++;
	} else {
		populate_cache(dcache, this_leaf, level, CACHE_TYPE_UNIFIED);
		level++;
	}

	if (c->vcache.waysize) {
		/* Vcache is per core as well */
		fill_cpumask_siblings(cpu, &this_leaf->shared_cpu_map);
		populate_cache(vcache, this_leaf, level, CACHE_TYPE_UNIFIED);
		level++;
	}

	if (c->scache.waysize) {
		/* Scache is per cluster */
		fill_cpumask_cluster(cpu, &this_leaf->shared_cpu_map);
		populate_cache(scache, this_leaf, level, CACHE_TYPE_UNIFIED);
		level++;
	}

	if (c->tcache.waysize)
		populate_cache(tcache, this_leaf, level, CACHE_TYPE_UNIFIED);

	this_cpu_ci->cpu_map_populated = true;

	return 0;
}
