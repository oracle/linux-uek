/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2014 Cavium, Inc.
 */

#include <linux/init.h>
#include <linux/topology.h>
#include <linux/mm.h>
#include <linux/nodemask.h>
#include <linux/bootmem.h>
#include <linux/swap.h>
#include <linux/of.h>

#include <asm/sections.h>

#include <asm/pgalloc.h>
#include <asm/octeon/octeon.h>
#include <asm/octeon/cvmx-coremask.h>


void octeon_setup_numa(void)
{
	int id;
	int node;
	struct cpumask *mask;
	const int coreid = cvmx_get_core_num();
	struct cvmx_sysinfo *sysinfo = cvmx_sysinfo_get();

	for (id = 0; id < CONFIG_MIPS_NR_CPU_NR_MAP; id++) {
		if (cvmx_coremask_is_core_set(&sysinfo->core_mask, id)) {
			node = (id >> 7) & 7;
			node_set_online(node);
			node_set_state(node, N_POSSIBLE);
		}
	}
	node = (coreid >> 7) & 7;
	mask = cpumask_of_node(node);
	/* The boot CPU will be CPU 0 */
	cpumask_set_cpu(0, mask);
}

void octeon_numa_cpu_online(void)
{
	int node;
	struct cpumask *mask;
	const int coreid = cvmx_get_core_num();

	node = (coreid >> 7) & 7;
	mask = cpumask_of_node(node);
	cpumask_set_cpu(smp_processor_id(), mask);
}

void __init paging_init(void)
{
	unsigned long max_zone_pfns[MAX_NR_ZONES] = {0,};
	unsigned node;

	pagetable_init();

#ifdef CONFIG_ZONE_DMA
	max_zone_pfns[ZONE_DMA] = MAX_DMA_PFN;
#endif
#ifdef CONFIG_ZONE_DMA32
	max_zone_pfns[ZONE_DMA32] = MAX_DMA32_PFN;
#endif
	for_each_online_node(node) {
		unsigned long start_pfn, end_pfn;

		get_pfn_range_for_nid(node, &start_pfn, &end_pfn);

		if (end_pfn > max_low_pfn)
			max_low_pfn = end_pfn;
	}
	max_zone_pfns[ZONE_NORMAL] = max_low_pfn;

	free_area_init_nodes(max_zone_pfns);
}

void setup_zero_pages(void);

void __init mem_init(void)
{
	unsigned long codesize, datasize, initsize, tmp;

	totalram_pages += free_all_bootmem();
	setup_zero_pages();	/* This comes from node 0 */

	codesize =  (unsigned long) &_etext - (unsigned long) &_text;
	datasize =  (unsigned long) &_edata - (unsigned long) &_etext;
	initsize =  (unsigned long) &__init_end - (unsigned long) &__init_begin;

	tmp = nr_free_pages();
	pr_info("Memory: %luk/%luk available (%ldk kernel code, %ldk reserved, %ldk data, %ldk init)\n",
	       tmp << (PAGE_SHIFT-10),
	       totalram_pages << (PAGE_SHIFT-10),
	       codesize >> 10,
	       (totalram_pages - tmp) << (PAGE_SHIFT-10),
	       datasize >> 10,
	       initsize >> 10);
}

int of_node_to_nid(struct device_node *np)
{
	int ret = 0;
	struct device_node *node;

	if (!np)
		return 0;

	node = of_node_get(np);
	do {
		if (strcmp("soc", node->name) == 0) {
			int rc;
			u32 msbits = 0;

			rc = of_property_read_u32_index(node, "ranges",	2, &msbits);
			if (rc == -EINVAL)
				WARN_ONCE(true, "Missing ranges property<%s>\n", node->full_name);
			ret = (msbits >> 4) & 1;
			break;
		}
		node = of_get_next_parent(node);
	} while (node);

	of_node_put(node);
	return ret;
}
EXPORT_SYMBOL(of_node_to_nid);
