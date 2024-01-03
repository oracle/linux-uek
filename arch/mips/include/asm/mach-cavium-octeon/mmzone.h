#ifndef _ASM_MACH_CAVIUM_OCTEON_MMZONE_H
#define _ASM_MACH_CAVIUM_OCTEON_MMZONE_H

struct node_data {
#ifdef CONFIG_NUMA
	struct pglist_data pglist;
	struct cpumask cpumask_on_node;
#endif
	unsigned long startmempfn;
	unsigned long startpfn;
	unsigned long endpfn;
};

extern struct node_data __node_data[];

#ifdef CONFIG_NUMA
#define NODE_DATA(n)		(&__node_data[(n)].pglist)
#endif

#endif /* _ASM_MACH_CAVIUM_OCTEON_MMZONE_H */
