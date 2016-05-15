/* cpumap.c: used for optimizing CPU assignment
 *
 * Copyright (C) 2009 Hong H. Pham <hong.pham@windriver.com>
 */

#include <linux/export.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/cpumask.h>
#include <linux/spinlock.h>
#include <asm/cpudata.h>
#include "cpumap.h"


enum {
	CPUINFO_LVL_ROOT = 0,
	CPUINFO_LVL_NODE,
	CPUINFO_LVL_CORE,
	CPUINFO_LVL_PROC,
	CPUINFO_LVL_MAX,
};

enum {
	ROVER_NO_OP              = 0,
	/* Increment rover every time level is visited */
	ROVER_INC_ON_VISIT       = 1 << 0,
	/* Increment parent's rover every time rover wraps around */
	ROVER_INC_PARENT_ON_LOOP = 1 << 1,
};

struct cpuinfo_node {
	int id;
	int level;
	int num_cpus;    /* Number of CPUs in this hierarchy */
	int parent_index;
	int child_start; /* Array index of the first child node */
	int child_end;   /* Array index of the last child node */
	int rover;       /* Child node iterator */
};

struct cpuinfo_level {
	int start_index; /* Index of first node of a level in a cpuinfo tree */
	int end_index;   /* Index of last node of a level in a cpuinfo tree */
	int num_nodes;   /* Number of nodes in a level in a cpuinfo tree */
};

struct cpuinfo_tree {
	int total_nodes;

	/* Offsets into nodes[] for each level of the tree */
	struct cpuinfo_level level[CPUINFO_LVL_MAX];
	struct cpuinfo_node  nodes[0];
};


static struct cpuinfo_tree *cpuinfo_tree;

int dbgcit;	/* cpuinfo tree debug */

#define	citdbg(fmt, args...)					\
	do {							\
		if (dbgcit)					\
			pr_info("%s " fmt, __func__, ##args);	\
	} while (0)

static u16 cpu_distribution_map[NR_CPUS];
static DEFINE_SPINLOCK(cpu_map_lock);


/* Niagara optimized cpuinfo tree traversal. */
static const int niagara_iterate_method[] = {
	[CPUINFO_LVL_ROOT] = ROVER_NO_OP,

	/* Strands (or virtual CPUs) within a core may not run concurrently
	 * on the Niagara, as instruction pipeline(s) are shared.  Distribute
	 * work to strands in different cores first for better concurrency.
	 * Go to next NUMA node when all cores are used.
	 */
	[CPUINFO_LVL_NODE] = ROVER_INC_ON_VISIT|ROVER_INC_PARENT_ON_LOOP,

	/* Strands are grouped together by proc_id in cpuinfo_sparc, i.e.
	 * a proc_id represents an instruction pipeline.  Distribute work to
	 * strands in different proc_id groups if the core has multiple
	 * instruction pipelines (e.g. the Niagara 2/2+ has two).
	 */
	[CPUINFO_LVL_CORE] = ROVER_INC_ON_VISIT,

	/* Pick the next strand in the proc_id group. */
	[CPUINFO_LVL_PROC] = ROVER_INC_ON_VISIT,
};

/* Generic cpuinfo tree traversal.  Distribute work round robin across NUMA
 * nodes.
 */
static const int generic_iterate_method[] = {
	[CPUINFO_LVL_ROOT] = ROVER_INC_ON_VISIT,
	[CPUINFO_LVL_NODE] = ROVER_NO_OP,
	[CPUINFO_LVL_CORE] = ROVER_INC_PARENT_ON_LOOP,
	[CPUINFO_LVL_PROC] = ROVER_INC_ON_VISIT|ROVER_INC_PARENT_ON_LOOP,
};


/*
 * The cpuinfo tree is rebuilt during a cpu hotplug operation, either
 * directly through cpu_map_rebuild() or indirectly through map_to_cpu(),
 * the latter case happening if the number of online cpus is different
 * than the number of cpus in the tree.
 *
 * There were three paths to tree rebuild originally as depicted below,
 * one during cpu hot-add, one during cpu hot-remove, and during irq enable.
 * In addition, __cpu_up() now directly calls cpu_map_rebuild() during
 * hot-add processing.
 *
 * The tree can be accessed however when enabling interrupts.  This is not
 * an issue for hot-remove since cpu_map_rebuild() is called with all cpus
 * paused and interrupts disabled during a stop_machine() call.  This may
 * be an issue however for hot-add since __cpu_up() and fixup_irqs() are
 * called with other cpus running and interrupts enabled.
 *
 * There is no issue however if simple_map_to_cpu() is used.
 *
 *	+irq_enable()
 *	|
 *	| +dr_cpu_configure()
 *	| |
 *	| +->fixup_irqs()
 *	|   |
 *	|   +->irq_set_affinity()
 *	|   |
 *	+---+->irq_choose_cpu()
 *	       |
 *	       +->map_to_cpu()
 *		  |
 *		  +------------>_map_to_cpu()
 *				|
 *	   +--------------------+->_cpu_map_rebuild()
 *	   |			   |
 *	   |			   +->build_cpuinfo_tree()
 *	+--+->cpu_map_rebuild()
 *	|  |
 *	|  +__cpu_disable()
 *	|
 *	+__cpu_up()
 *
 *
 * set_proc_ids() iteraters through all "exec-unit" nodes and calls
 * mark_proc_ids() to assign the same proc_id to all cpus pointing to
 * the "exec-unit" unit.  This means that if a core has multiple
 * pipelines shared by all strands in the core, each strand would be
 * assigned a proc_id twice, the second overwriting the first and thus
 * hiding one of the pipelines.  On a T5 where each core has two pipelines
 * the number of reported pipelines is fact half of what they should be.
 * The increment_rover() algorithm subsequently doesn't work on all platforms.
 *
 *
 * iterate_cpu() and increment_rover() assume that all cpus between
 * start_index and end_index of a CPUINFO_LVL_PROC are always present.
 * This means that if a cpu in the middle of that range has been offlined
 * iterate_cpu() can actually return and offline cpu as the target for
 * interrupt redistribution which leads to subsequent system hangs.
 * To deal with problem, iterate_cpu() was called multiple times until
 * an online cpu was returned.
 *
 * The following code in map_to_cpu() can lead to an infinite loop in
 * case of the cpuinfo_tree because if _map_to_cpu() causes the tree
 * to be rebuilt, it can return the same offline cpu as before leading
 * to the infinite loop:
 *
 *	while (unlikely(!cpu_online(mapped_cpu)))
 *		mapped_cpu = _map_to_cpu(index);
 *
 *
 * enumerate_cpuinfo_nodes() assumes that node ids at each level of the tree
 * are monotonically increasing which is not necessarily the case for
 * ldoms, e.g. lower cpu ids can have higher core ids. If this assumption
 * is broken, the number of calculated nodes can be less that the number
 * of actual nodes required to represent the cpu topology. This can lead to
 * data corruption when the tree is iterated.  Testing showed illegal index
 * values in iterate_cpu() and subsequent panics and hangs.
 * Using bitmaps for nodes, core, and procs fixed the illegal index problem
 * and significanly reduced the number of the panics.  However, one of those
 * panics still happens, with less frequency but consistenly, sometime during
 * or after when sched domains are rebuilt as part of hotplug processing.
 * No panic happens when the cpuinfo_tree method is bypassed and the default
 * simple_map_to_cpu() method is used.
 *
 *
 * Furthermore, no documentation exists to show actual measured benefits
 * of the cpuinfo tree.  For all those reasons, ldoms defaults to
 * simple_map_to_cpu().
 */
#ifdef	CONFIG_SUN_LDOMS
/*
 * Default to simple_map_to_cpu() for LDoms.
 */
static inline struct cpuinfo_tree *build_cpuinfo_tree(void)
{
	return NULL;
}
#else
static int cpuinfo_id(int cpu, int level)
{
	int id;

	switch (level) {
	case CPUINFO_LVL_ROOT:
		id = 0;
		break;
	case CPUINFO_LVL_NODE:
		id = cpu_to_node(cpu);
		break;
	case CPUINFO_LVL_CORE:
		id = cpu_data(cpu).core_id;
		break;
	case CPUINFO_LVL_PROC:
		id = cpu_data(cpu).proc_id;
		break;
	default:
		id = -EINVAL;
	}
	return id;
}

/*
 * Enumerate the CPU information in __cpu_data to determine the start index,
 * end index, and number of nodes for each level in the cpuinfo tree.  The
 * total number of cpuinfo nodes required to build the tree is returned.
 */
static int enumerate_cpuinfo_nodes(struct cpuinfo_level *tree_level)
{
	int prev_id[CPUINFO_LVL_MAX];
	int i, n, num_nodes;
#ifdef	DBGCIT
	int c, m;
	cpumask_t node_mask, core_mask, proc_mask;

	cpumask_clear(&node_mask);
	cpumask_clear(&core_mask);
	cpumask_clear(&proc_mask);
#endif

	for (i = CPUINFO_LVL_ROOT; i < CPUINFO_LVL_MAX; i++) {
		struct cpuinfo_level *lv = &tree_level[i];

		prev_id[i] = -1;
		lv->start_index = lv->end_index = lv->num_nodes = 0;
	}

	num_nodes = 1; /* Include the root node */

	for (i = 0; i < num_possible_cpus(); i++) {
		if (!cpu_online(i))
			continue;

		n = cpuinfo_id(i, CPUINFO_LVL_NODE);
#ifdef	DBGCIT
		m = n;
		if (!cpumask_test_cpu(n, &node_mask)) {
			cpumask_set_cpu(n, &node_mask);
#else
		if (n > prev_id[CPUINFO_LVL_NODE]) {
#endif
			tree_level[CPUINFO_LVL_NODE].num_nodes++;
			prev_id[CPUINFO_LVL_NODE] = n;
			num_nodes++;
		}
		n = cpuinfo_id(i, CPUINFO_LVL_CORE);
#ifdef	DBGCIT
		c = n;
		if (!cpumask_test_cpu(n, &core_mask)) {
			cpumask_set_cpu(n, &core_mask);
#else
		if (n > prev_id[CPUINFO_LVL_CORE]) {
#endif
			tree_level[CPUINFO_LVL_CORE].num_nodes++;
			prev_id[CPUINFO_LVL_CORE] = n;
			num_nodes++;
		}
		n = cpuinfo_id(i, CPUINFO_LVL_PROC);
#ifdef	DBGCIT
		if (!cpumask_test_cpu(n, &proc_mask)) {
			cpumask_set_cpu(n, &proc_mask);
#else
		if (n > prev_id[CPUINFO_LVL_PROC]) {
#endif
			tree_level[CPUINFO_LVL_PROC].num_nodes++;
			prev_id[CPUINFO_LVL_PROC] = n;
			num_nodes++;
		}
		citdbg("cpu=%d pid=%d cid=%d nid=%d\n", i, n, c, m);
	}

	tree_level[CPUINFO_LVL_ROOT].num_nodes = 1;

	n = tree_level[CPUINFO_LVL_NODE].num_nodes;
	tree_level[CPUINFO_LVL_NODE].start_index = 1;
	tree_level[CPUINFO_LVL_NODE].end_index   = n;

	n++;
	tree_level[CPUINFO_LVL_CORE].start_index = n;
	n += tree_level[CPUINFO_LVL_CORE].num_nodes;
	tree_level[CPUINFO_LVL_CORE].end_index   = n - 1;

	tree_level[CPUINFO_LVL_PROC].start_index = n;
	n += tree_level[CPUINFO_LVL_PROC].num_nodes;
	tree_level[CPUINFO_LVL_PROC].end_index   = n - 1;

	for (i = CPUINFO_LVL_ROOT; i < CPUINFO_LVL_MAX; i++)
		citdbg("level=%d nodes=%d start=%d end=%d\n",
		       i, tree_level[i].num_nodes, tree_level[i].start_index,
		       tree_level[i].end_index);

	return num_nodes;
}

/* Build a tree representation of the CPU hierarchy using the per CPU
 * information in __cpu_data.  Entries in __cpu_data[0..NR_CPUS] are
 * assumed to be sorted in ascending order based on node, core_id, and
 * proc_id (in order of significance).
 */
static struct cpuinfo_tree *build_cpuinfo_tree(void)
{
	struct cpuinfo_tree *new_tree;
	struct cpuinfo_node *node;
	struct cpuinfo_level tmp_level[CPUINFO_LVL_MAX];
	int num_cpus[CPUINFO_LVL_MAX];
	int level_rover[CPUINFO_LVL_MAX];
	int prev_id[CPUINFO_LVL_MAX];
	int n, id, cpu, prev_cpu, last_cpu, level;

	n = enumerate_cpuinfo_nodes(tmp_level);

	new_tree = kzalloc(sizeof(struct cpuinfo_tree) +
	                   (sizeof(struct cpuinfo_node) * n), GFP_ATOMIC);
	citdbg("num_nodes=%d new_tree=%p\n", n, new_tree);
	if (!new_tree)
		return NULL;

	new_tree->total_nodes = n;
	memcpy(&new_tree->level, tmp_level, sizeof(tmp_level));

	prev_cpu = cpu = cpumask_first(cpu_online_mask);

	/* Initialize all levels in the tree with the first CPU */
	for (level = CPUINFO_LVL_PROC; level >= CPUINFO_LVL_ROOT; level--) {
		n = new_tree->level[level].start_index;

		level_rover[level] = n;
		node = &new_tree->nodes[n];

		id = cpuinfo_id(cpu, level);
		if (unlikely(id < 0)) {
			kfree(new_tree);
			return NULL;
		}
		node->id = id;
		node->level = level;
		node->num_cpus = 1;

		node->parent_index = (level > CPUINFO_LVL_ROOT)
		    ? new_tree->level[level - 1].start_index : -1;

		node->child_start = node->child_end = node->rover =
		    (level == CPUINFO_LVL_PROC)
		    ? cpu : new_tree->level[level + 1].start_index;

		prev_id[level] = node->id;
		num_cpus[level] = 1;
	}

	for (last_cpu = (num_possible_cpus() - 1); last_cpu >= 0; last_cpu--) {
		if (cpu_online(last_cpu))
			break;
	}

	while (++cpu <= last_cpu) {
		if (!cpu_online(cpu))
			continue;

		for (level = CPUINFO_LVL_PROC; level >= CPUINFO_LVL_ROOT;
		     level--) {
			id = cpuinfo_id(cpu, level);
			if (unlikely(id < 0)) {
				kfree(new_tree);
				return NULL;
			}

			if ((id != prev_id[level]) || (cpu == last_cpu)) {
				prev_id[level] = id;
				node = &new_tree->nodes[level_rover[level]];
				node->num_cpus = num_cpus[level];
				num_cpus[level] = 1;

				if (cpu == last_cpu)
					node->num_cpus++;

				/* Connect tree node to parent */
				if (level == CPUINFO_LVL_ROOT)
					node->parent_index = -1;
				else
					node->parent_index =
					    level_rover[level - 1];

				if (level == CPUINFO_LVL_PROC) {
					node->child_end =
					    (cpu == last_cpu) ? cpu : prev_cpu;
				} else {
					node->child_end =
					    level_rover[level + 1] - 1;
				}
				citdbg("l=%d r=%d s=%d e=%d p=%d\n",
					level, level_rover[level],
					node->child_start, node->child_end,
					node->parent_index);

				/* Initialize the next node in the same level */
				n = ++level_rover[level];
				if (n <= new_tree->level[level].end_index) {
					node = &new_tree->nodes[n];
					node->id = id;
					node->level = level;

					/* Connect node to child */
					node->child_start = node->child_end =
					node->rover =
					    (level == CPUINFO_LVL_PROC)
					    ? cpu : level_rover[level + 1];
				}
			} else
				num_cpus[level]++;
		}
		prev_cpu = cpu;
	}

	return new_tree;
}
#endif

static void increment_rover(struct cpuinfo_tree *t, int node_index,
                            int root_index, const int *rover_inc_table)
{
	struct cpuinfo_node *node = &t->nodes[node_index];
	int top_level, level;

	top_level = t->nodes[root_index].level;
	for (level = node->level; level >= top_level; level--) {
		node->rover++;
		if (node->rover <= node->child_end)
			return;

		node->rover = node->child_start;
		/* If parent's rover does not need to be adjusted, stop here. */
		if ((level == top_level) ||
		    !(rover_inc_table[level] & ROVER_INC_PARENT_ON_LOOP))
			return;

		node = &t->nodes[node->parent_index];
	}
}

static int iterate_cpu(struct cpuinfo_tree *t, unsigned int root_index)
{
	const int *rover_inc_table;
	int level, new_index, index = root_index;

	switch (sun4v_chip_type) {
	case SUN4V_CHIP_NIAGARA1:
	case SUN4V_CHIP_NIAGARA2:
	case SUN4V_CHIP_NIAGARA3:
	case SUN4V_CHIP_NIAGARA4:
	case SUN4V_CHIP_NIAGARA5:
	case SUN4V_CHIP_SPARC_M6:
	case SUN4V_CHIP_SPARC_M7:
	case SUN4V_CHIP_SPARC64X:
		rover_inc_table = niagara_iterate_method;
		break;
	default:
		rover_inc_table = generic_iterate_method;
	}

	for (level = t->nodes[root_index].level; level < CPUINFO_LVL_MAX;
	     level++) {
		new_index = t->nodes[index].rover;
		if (new_index < 0 || (new_index >= t->total_nodes &&
		    level != CPUINFO_LVL_PROC))
			citdbg("index=%d new_index=%d total=%d level=%d\n",
				 index, new_index, t->total_nodes, level);
		if (rover_inc_table[level] & ROVER_INC_ON_VISIT)
			increment_rover(t, index, root_index, rover_inc_table);

		index = new_index;
	}
	return index;
}

static void _cpu_map_rebuild(void)
{
	int i;

	if (cpuinfo_tree) {
		kfree(cpuinfo_tree);
		cpuinfo_tree = NULL;
	}

	cpuinfo_tree = build_cpuinfo_tree();
	if (!cpuinfo_tree)
		return;

	/* Build CPU distribution map that spans all online CPUs.  No need
	 * to check if the CPU is online, as that is done when the cpuinfo
	 * tree is being built.
	 */
	for (i = 0; i < cpuinfo_tree->nodes[0].num_cpus; i++) {
#ifdef	DBGCIT
		int cpu;
		int j = 0;

		do {
			cpu = iterate_cpu(cpuinfo_tree, 0);
			if (cpu_online(cpu))
				break;
		} while (++j < num_possible_cpus());

		if (j)
			citdbg("offline=%d\n", j);
		BUG_ON(!cpu_online(cpu));
		cpu_distribution_map[i] = cpu;
#else
		cpu_distribution_map[i] = iterate_cpu(cpuinfo_tree, 0);
#endif
	}
}

/* Fallback if the cpuinfo tree could not be built.  CPU mapping is linear
 * round robin.
 */
static int simple_map_to_cpu(unsigned int index)
{
	int i, end, cpu_rover;

	cpu_rover = 0;
	end = index % num_online_cpus();
	for (i = 0; i < num_possible_cpus(); i++) {
		if (cpu_online(cpu_rover)) {
			if (cpu_rover >= end)
				return cpu_rover;

			cpu_rover++;
		}
	}

	/* Impossible, since num_online_cpus() <= num_possible_cpus() */
	return cpumask_first(cpu_online_mask);
}

static int _map_to_cpu(unsigned int index)
{
	struct cpuinfo_node *root_node;

	if (unlikely(!cpuinfo_tree)) {
		_cpu_map_rebuild();
		if (!cpuinfo_tree)
			return simple_map_to_cpu(index);
	}

	root_node = &cpuinfo_tree->nodes[0];
#ifdef CONFIG_HOTPLUG_CPU
	if (unlikely(root_node->num_cpus != num_online_cpus())) {
		citdbg("cpus=%d online=%d\n",
		       root_node->num_cpus, num_online_cpus());
		_cpu_map_rebuild();
		if (!cpuinfo_tree)
			return simple_map_to_cpu(index);

#ifdef	DBGCIT
		/* update root_node if cpuinfo_tree has changed */
		root_node = &cpuinfo_tree->nodes[0];
#endif
	}
#endif
	return cpu_distribution_map[index % root_node->num_cpus];
}

int map_to_cpu(unsigned int index)
{
	int mapped_cpu;
	unsigned long flag;

	spin_lock_irqsave(&cpu_map_lock, flag);
	mapped_cpu = _map_to_cpu(index);

#ifdef CONFIG_HOTPLUG_CPU
#ifdef	DBGCIT
	BUG_ON(!cpu_online(cpu));
#else
	while (unlikely(!cpu_online(mapped_cpu)))
		mapped_cpu = _map_to_cpu(index);
#endif
#endif
	spin_unlock_irqrestore(&cpu_map_lock, flag);
	return mapped_cpu;
}
EXPORT_SYMBOL(map_to_cpu);

void cpu_map_rebuild(void)
{
	unsigned long flag;

	spin_lock_irqsave(&cpu_map_lock, flag);
	_cpu_map_rebuild();
	spin_unlock_irqrestore(&cpu_map_lock, flag);
}
