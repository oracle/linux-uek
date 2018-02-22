/*
 * FILE:	dtrace_task.c
 * DESCRIPTION:	DTrace - per-task data
 *
 * Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/dtrace_task_impl.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>

struct kmem_cache	*dtrace_task_cachep;

/*
 * Fasttrap hooks that needs to be called when a fasttrap meta provider
 * is loaded and registered with the framework.
 */
void (*dtrace_helpers_cleanup)(struct task_struct *);
EXPORT_SYMBOL(dtrace_helpers_cleanup);
void (*dtrace_fasttrap_probes_cleanup)(struct task_struct *);
EXPORT_SYMBOL(dtrace_fasttrap_probes_cleanup);
void (*dtrace_helpers_fork)(struct task_struct *, struct task_struct *);
EXPORT_SYMBOL(dtrace_helpers_fork);

/*
 * Reset per-task sate to default values. Modifies only part of
 * the state that does not persist across process forks.
 */
static void dtrace_task_reinit(dtrace_task_t *dtsk)
{
	dtsk->dt_predcache = 0;
	dtsk->dt_stop = 0;
	dtsk->dt_sig = 0;

	dtsk->dt_helpers = NULL;
	dtsk->dt_probes = 0;
	dtsk->dt_tp_count = 0;
}

/*
 * Allocate new per-task structure and initialize it with default
 * values.
 */
static dtrace_task_t *dtrace_task_alloc(void)
{
	dtrace_task_t *dtsk;

	/* Try to allocate new task. */
	dtsk = kmem_cache_alloc(dtrace_task_cachep, GFP_KERNEL);
	if (dtsk == NULL)
		return NULL;

	/* Initialize new task. */
	dtrace_task_reinit(dtsk);

	dtsk->dt_vtime = ktime_set(0, 0);
	dtsk->dt_start = ktime_set(0, 0);
	dtsk->dt_psinfo = NULL;
	dtsk->dt_ustack = NULL;

	return dtsk;
}

/*
 * Cleans all attached resources to the per-task structure so it is ready to be
 * reused or freed.
 */
static void dtrace_task_cleanup(struct task_struct *tsk)
{
	dtrace_psinfo_t *psinfo;

	/* Nothing to remove. */
	if (tsk->dt_task == NULL)
		return;

	/* Handle fasttrap provider cleanups. */
	if (tsk->dt_task->dt_helpers != NULL && dtrace_helpers_cleanup != NULL)
		(*dtrace_helpers_cleanup)(tsk);

	if (tsk->dt_task->dt_probes && dtrace_fasttrap_probes_cleanup != NULL)
		(*dtrace_fasttrap_probes_cleanup)(tsk);

	/* Release psinfo if any. */
	psinfo = tsk->dt_task->dt_psinfo;
	if (psinfo != NULL) {
		tsk->dt_task->dt_psinfo = NULL;
		dtrace_psinfo_put(psinfo);
	}
}

/*
 * Kernel hooks for per-task events.
 */

/*
 * Called when a new task has been created.
 *
 * It tries to allocate new per-task data strcture and initialize
 * it with default values.
 */
void dtrace_task_init(struct task_struct *tsk)
{
	struct mm_struct	*mm = NULL;

	/* Initialize new task structure */
	tsk->dt_task = dtrace_task_alloc();
	if (tsk->dt_task == NULL)
		return;

	/* Try to setup initial userspace stack. */
	mm = get_task_mm(tsk);
	if (mm) {
		tsk->dt_task->dt_ustack = (void *)mm->start_stack;
		mmput(mm);
	}
}

/*
 * Called when a task has been duplicated.
 *
 * When a task is duplicated this is called early to provide new instance
 * of per-task data. This hook is called very early after a dup has been
 * performed. The new task shares almost everything with its parent and
 * locking performed must be aligned with locking of the kernel.
 *
 * DTrace resets new task to its default values.
 */
void dtrace_task_dup(struct task_struct *src, struct task_struct *dst)
{
	dtrace_psinfo_t	*psinfo;
	dtrace_task_t	*dtsk;

	/* Nothing to clone. */
	if (src->dt_task == NULL)
		return;

	/* Allocate and reinitialize new task. */
	dtsk = dtrace_task_alloc();
	if (dtsk == NULL) {
		dst->dt_task = NULL;
		return;
	}
	dtrace_task_reinit(dtsk);

	/* Share psinfo if it is available. */
	psinfo = src->dt_task->dt_psinfo;
	if (psinfo != NULL) {
		dtrace_psinfo_get(psinfo);
		dtsk->dt_psinfo = psinfo;
	}

	/* Copy remaining attributes of the source task. */
	dtsk->dt_ustack = src->dt_task->dt_ustack;
	dst->dt_task = dtsk;
}

/*
 * Called when a process has been copied.
 *
 * If the original task has helpers attached fork them too.
 */
void dtrace_task_copy(struct task_struct *tsk, struct task_struct *child)
{
	if (tsk->dt_task == NULL)
		return;

	if (child->dt_task == NULL)
		return;

	/* Handle helpers for this task. */
	if (likely(dtrace_helpers_fork == NULL))
		return;

	if (tsk->dt_task->dt_helpers != NULL)
		(*dtrace_helpers_fork)(tsk, child);
}

/*
 * Called when a task has performed exec.
 *
 * If DTrace's per-task structure is already allocated it is reused for
 * the new task. If it is not present an allocation attempt is made.
 */
void dtrace_task_exec(struct task_struct *tsk)
{
	struct mm_struct *mm = NULL;

	/* Try to reuse existing dtrace task. */
	if (tsk->dt_task != NULL) {
		dtrace_task_cleanup(tsk);
		dtrace_task_reinit(tsk->dt_task);

		/* Try to set up initial userspace stack. */
		mm = get_task_mm(tsk);
		if (mm) {
			tsk->dt_task->dt_ustack = (void *)mm->start_stack;
			mmput(mm);
		}
	} else {
		dtrace_task_init(tsk);

		/* No luck, we won't be able to trace this task. */
		if (tsk->dt_task == NULL)
			return;
	}

	/* Finalize init of the per-task structure. */
	dtrace_psinfo_alloc(tsk);
}

/*
 * Called when a task is about to be released.
 *
 * The DTrace's per-task data are disconnected and freed.
 */
void dtrace_task_free(struct task_struct *tsk)
{
	dtrace_task_t *dtsk = tsk->dt_task;

	/* Nothing to do. */
	if (dtsk == NULL)
		return;

	/* Release the per-task data. */
	dtrace_task_cleanup(tsk);
	tsk->dt_task = NULL;
	kmem_cache_free(dtrace_task_cachep, dtsk);
}

/*
 * Initialize DTrace's task subsystem.
 */
void __init dtrace_task_os_init(void)
{
	/* Will panic if not initialized so no need to check for errors. */
	dtrace_task_cachep = kmem_cache_create("dtrace_task_cache",
				sizeof(dtrace_task_t), 0,
				SLAB_HWCACHE_ALIGN | SLAB_PANIC,
				NULL);
}

