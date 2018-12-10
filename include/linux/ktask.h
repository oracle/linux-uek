/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * ktask.h - framework to parallelize CPU-intensive kernel work
 *
 * For more information, see Documentation/core-api/ktask.rst.
 *
 * Author: Daniel Jordan <daniel.m.jordan@oracle.com>
 *
 * Copyright (c) 2019, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _LINUX_KTASK_H
#define _LINUX_KTASK_H

#include <linux/list.h>
#include <linux/lockdep.h>
#include <linux/mm.h>
#include <linux/topology.h>
#include <linux/types.h>

#define	KTASK_RETURN_SUCCESS	0

/**
 * struct ktask_node - Holds per-NUMA-node information about a task.
 *
 * @kn_start: An object that describes the start of the task on this NUMA node.
 * @kn_task_size: size of this node's work (units are task-specific)
 * @kn_nid: NUMA node id to run threads on
 */
struct ktask_node {
	void			*kn_start;
	size_t			kn_task_size;
	int			kn_nid;

	/* Private fields below - do not touch these. */
	void			*kn_position;
	size_t			kn_remaining_size;
	struct list_head	kn_failed_works;
};

/**
 * typedef ktask_thread_func
 *
 * Called on each chunk of work that a ktask thread does.  A thread may call
 * this multiple times during one task.
 *
 * @start: An object that describes the start of the chunk.
 * @end: An object that describes the end of the chunk.
 * @arg: The thread function argument (provided with struct ktask_ctl).
 *
 * RETURNS:
 * KTASK_RETURN_SUCCESS or a client-specific nonzero error code.
 */
typedef int (*ktask_thread_func)(void *start, void *end, void *arg);

/**
 * typedef ktask_undo_func
 *
 * The same as ktask_thread_func, with the exception that it must always
 * succeed, so it doesn't return anything.
 */
typedef void (*ktask_undo_func)(void *start, void *end, void *arg);

/**
 * typedef ktask_iter_func
 *
 * An iterator function that advances the position by @size units.  ktask will
 * not advance the iterator beyond the end of the task, and it is an error for
 * the iterator to return a position beyond a task's end.
 *
 * @position: An object that describes the current position in the task.
 * @size: The amount to advance in the task (in task-specific units).
 *
 * RETURNS:
 * An object representing the new position.
 */
typedef void *(*ktask_iter_func)(void *position, size_t size);

/**
 * ktask_iter_range
 *
 * An iterator function for a contiguous range such as an array or address
 * range.  This is the default iterator; clients may override with
 * ktask_ctl_set_iter_func.
 *
 * @position: An object that describes the current position in the task.
 *            Interpreted as an unsigned long.
 * @size: The amount to advance in the task (in task-specific units).
 *
 * RETURNS:
 * (position + size)
 */
void *ktask_iter_range(void *position, size_t size);

/**
 * struct ktask_ctl - Client-provided per-task control information.
 *
 * @kc_thread_func: A thread function that completes one chunk of the task per
 *                  call.
 * @kc_undo_func: A function that undoes one chunk of the task per call.
 *                If non-NULL and error(s) occur during the task, this is
 *                called on all successfully completed chunks of work.  The
 *                chunk(s) in which failure occurs should be handled in
 *                kc_thread_func.
 * @kc_func_arg: An argument to be passed to the thread and undo functions.
 * @kc_min_chunk_size: The minimum chunk size in task-specific units.  This
 *                     allows the client to communicate the minimum amount of
 *                     work that's appropriate for one worker thread to do at
 *                     once.
 * @kc_flags:     Control the job, such as whether to busywait or sleep.
 * @kc_iter_func: An iterator function to advance the iterator by some number
 *                   of task-specific units.
 * @kc_max_threads: max threads to use for the task, actual number may be less
 *                  depending on CPU count, task size, and minimum chunk size.
 */
struct ktask_ctl {
	/* Required arguments set with DEFINE_KTASK_CTL. */
	ktask_thread_func	kc_thread_func;
	ktask_undo_func		kc_undo_func;
	void			*kc_func_arg;
	size_t			kc_min_chunk_size;
	int			kc_flags;

	/* Optional, can set with ktask_ctl_set_*.  Defaults on the right. */
	ktask_iter_func		kc_iter_func;    /* ktask_iter_range */
	size_t			kc_max_threads;  /* 0 (uses internal limit) */
};

#define KTASK_CTL_INITIALIZER(thread_func, func_arg, min_chunk_size, flags)  \
	{								     \
		.kc_thread_func = (ktask_thread_func)(thread_func),	     \
		.kc_undo_func = NULL,					     \
		.kc_func_arg = (func_arg),				     \
		.kc_min_chunk_size = (min_chunk_size),			     \
		.kc_flags = (flags),					     \
		.kc_iter_func = (ktask_iter_range),			     \
		.kc_max_threads = 0,					     \
	}

/*
 * KTASK_CTL_INITIALIZER casts 'thread_func' to be of type ktask_thread_func so
 * clients can write cleaner thread functions by relieving them of the need to
 * cast the three void * arguments.  Clients can just use the actual argument
 * types instead.
 */
#define DEFINE_KTASK_CTL(ctl_name, thread_func, func_arg, min_chunk, flags)    \
	struct ktask_ctl ctl_name =					       \
		KTASK_CTL_INITIALIZER(thread_func, func_arg, min_chunk, flags) \

/**
 * ktask_ctl_set_iter_func - Set a task-specific iterator
 *
 * Overrides the default iterator, ktask_iter_range.
 *
 * Casts the type of the iterator function so its arguments can be
 * client-specific (see the comment above DEFINE_KTASK_CTL).
 *
 * @ctl:  A control structure containing information about the task.
 * @iter_func:  Walks a given number of units forward in the task, returning
 *              an iterator corresponding to the new position.
 */
#define ktask_ctl_set_iter_func(ctl, iter_func)				\
	((ctl)->kc_iter_func = (ktask_iter_func)(iter_func))

/**
 * ktask_ctl_set_undo_func - Designate an undo function to unwind from error
 *
 * @ctl:  A control structure containing information about the task.
 * @undo_func:  Undoes a piece of the task.
 */
#define ktask_ctl_set_undo_func(ctl, undo_func)				\
	((ctl)->kc_undo_func = (ktask_undo_func)(undo_func))

/**
 * ktask_ctl_set_max_threads - Set a task-specific maximum number of threads
 *
 * This overrides the default maximum, which is KTASK_DEFAULT_MAX_THREADS.
 *
 * @ctl:  A control structure containing information about the task.
 * @max_threads:  The maximum number of threads to be started for this task.
 *                The actual number of threads may be less than this.
 */
static inline void ktask_ctl_set_max_threads(struct ktask_ctl *ctl,
					     size_t max_threads)
{
	ctl->kc_max_threads = max_threads;
}

enum {
	KTASK_ATOMIC = 1,
};

/*
 * The minimum chunk sizes for tasks that operate on ranges of memory.  For
 * now, say 128M.
 */
#define	KTASK_MEM_CHUNK		(1ul << 27)
#define	KTASK_PTE_MINCHUNK	(KTASK_MEM_CHUNK / PAGE_SIZE)
#define	KTASK_PMD_MINCHUNK	(KTASK_MEM_CHUNK / PMD_SIZE)

#ifdef CONFIG_KTASK

/**
 * ktask_run - Runs one task.
 *
 * Starts threads to complete one task with the given thread function.  Waits
 * for the task to finish before returning.
 *
 * On a NUMA system, threads run on the current node.  This is designed to
 * mirror other parts of the kernel that favor locality, such as the default
 * memory policy of allocating pages from the same node as the calling thread.
 * ktask_run_numa may be used to get more control over where threads run.
 *
 * @start: An object that describes the start of the task.  The client thread
 *         function interprets the object however it sees fit (e.g. an array
 *         index, a simple pointer, or a pointer to a more complicated
 *         representation of job position).
 * @task_size:  The size of the task (units are task-specific).
 * @ctl:  A control structure containing information about the task, including
 *        the client thread function.
 *
 * RETURNS:
 * KTASK_RETURN_SUCCESS or a client-specific nonzero error code.
 */
#define ktask_run(start, task_size, ctl)				       \
({									       \
	struct ktask_node __node;					       \
									       \
	__node.kn_start = (start);					       \
	__node.kn_task_size = (task_size);				       \
	__node.kn_nid = numa_node_id();					       \
									       \
	ktask_run_numa(&__node, 1, (ctl));				       \
})

/**
 * ktask_run_numa - Runs one task while accounting for NUMA locality.
 *
 * Starts threads on the requested nodes to complete one task with the given
 * thread function.  The client is responsible for organizing the work along
 * NUMA boundaries in the 'nodes' array.  Waits for the task to finish before
 * returning.
 *
 * In the special case of NUMA_NO_NODE, threads are allowed to run on any node.
 * This is distinct from ktask_run, which runs threads on the current node.
 *
 * @nodes: An array of nodes.
 * @nr_nodes:  Length of the 'nodes' array.
 * @ctl:  Control structure containing information about the task.
 *
 * RETURNS:
 * KTASK_RETURN_SUCCESS or a client-specific nonzero error code.
 */
#ifdef CONFIG_LOCKDEP
#define ktask_run_numa(nodes, nr_nodes, ctl)				       \
({									       \
	static struct lock_class_key __key;				       \
	const char *__map_name = "ktask master waiting";		       \
									       \
	__ktask_run_numa((nodes), (nr_nodes), (ctl), &__key, __map_name);      \
})
#else
#define ktask_run_numa(nodes, nr_nodes, ctl)				       \
	__ktask_run_numa((nodes), (nr_nodes), (ctl), NULL, NULL);
#endif

void ktask_init(void);
int __ktask_run_numa(struct ktask_node *nodes, size_t nr_nodes,
		     struct ktask_ctl *ctl, struct lock_class_key *key,
		     const char *map_name);

#else  /* CONFIG_KTASK */

static inline int ktask_run(void *start, size_t task_size,
			    struct ktask_ctl *ctl)
{
	return ctl->kc_thread_func(start, ctl->kc_iter_func(start, task_size),
				   ctl->kc_func_arg);
}

static inline int ktask_run_numa(struct ktask_node *nodes, size_t nr_nodes,
				 struct ktask_ctl *ctl)
{
	size_t i;
	int err = KTASK_RETURN_SUCCESS;

	for (i = 0; i < nr_nodes; ++i) {
		void *start = nodes[i].kn_start;
		void *end = ctl->kc_iter_func(start, nodes[i].kn_task_size);

		err = ctl->kc_thread_func(start, end, ctl->kc_func_arg);
		if (err != KTASK_RETURN_SUCCESS)
			break;
	}

	return err;
}

static inline void ktask_init(void) { }

#endif /* CONFIG_KTASK */
#endif /* _LINUX_KTASK_H */
