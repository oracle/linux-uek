/*
 * FILE:	dtrace_psinfo.c
 * DESCRIPTION:	DTrace - DTrace psinfo implementation
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

#include <linux/binfmts.h>
#include <linux/dtrace_psinfo.h>
#include <linux/dtrace_task_impl.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

struct kmem_cache	*dtrace_psinfo_cachep;

/*
 * Free the psinfo_t structure.
 */
void dtrace_psinfo_free(dtrace_psinfo_t *psinfo)
{
	kfree(psinfo->dtps_argv);
	kfree(psinfo->dtps_envp);
	kmem_cache_free(dtrace_psinfo_cachep, psinfo);
}

/*
 * Allocate a new dtrace_psinfo_t structure.
 */
void dtrace_psinfo_alloc(struct task_struct *tsk)
{
	dtrace_psinfo_t		*psinfo;
	struct mm_struct	*mm = NULL;

	if (unlikely(tsk->dt_task == NULL))
		return;

	if (likely(tsk->dt_task->dt_psinfo != NULL)) {
		dtrace_psinfo_t *tmp = tsk->dt_task->dt_psinfo;
		tsk->dt_task->dt_psinfo = NULL;

		dtrace_psinfo_put(tmp);
	}

	psinfo = kmem_cache_alloc(dtrace_psinfo_cachep, GFP_KERNEL);
	if (psinfo == NULL)
		goto fail;

	mm = get_task_mm(tsk);
	if (mm) {
		size_t	len = mm->arg_end - mm->arg_start;
		int	i = 0;
		char	*p;

		/*
		 * Construct the psargs string.
		 */
		if (len > 0) {
			if (len >= PR_PSARGS_SZ)
				len = PR_PSARGS_SZ - 1;

			i = access_process_vm(tsk, mm->arg_start,
					      psinfo->dtps_psargs, len, 0);

			if (i > 0) {
				if (i < len)
					len = i;

				for (i = 0, --len; i < len; i++) {
					if (psinfo->dtps_psargs[i] == '\0')
						psinfo->dtps_psargs[i] = ' ';
				}
			}
		}

		if (i < 0)
			i = 0;

		while (i < PR_PSARGS_SZ)
			psinfo->dtps_psargs[i++] = 0;

		/*
		 * Determine the number of arguments.
		 */
		psinfo->dtps_argc = 0;
		for (p = (char *)mm->arg_start; p < (char *)mm->arg_end;
		     psinfo->dtps_argc++) {
			size_t	l = strnlen_user(p, MAX_ARG_STRLEN);

			if (!l)
				break;

			p += l + 1;
		}

		/*
		 * Limit the number of stored argument pointers.
		 */
		len = psinfo->dtps_argc;
		if (len >= PR_ARGV_SZ)
			len = PR_ARGV_SZ - 1;

		psinfo->dtps_argv = kmalloc((len + 1) * sizeof(char *),
					 GFP_KERNEL);
		if (psinfo->dtps_argv == NULL)
			goto fail;

		/*
		 * Now populate the array of argument strings.
		 */
		for (i = 0, p = (char *)mm->arg_start; i < len; i++) {
			psinfo->dtps_argv[i] = p;
			p += strnlen_user(p, MAX_ARG_STRLEN) + 1;
		}
		psinfo->dtps_argv[len] = NULL;

		/*
		 * Determine the number of environment variables.
		 */
		psinfo->dtps_envc = 0;
		for (p = (char *)mm->env_start; p < (char *)mm->env_end;
		     psinfo->dtps_envc++) {
			size_t	l = strnlen_user(p, MAX_ARG_STRLEN);

			if (!l)
				break;

			p += l + 1;
		}

		/*
		 * Limit the number of stored environment pointers.
		 */
		len = psinfo->dtps_envc;
		if (len >= PR_ENVP_SZ)
			len = PR_ENVP_SZ - 1;

		psinfo->dtps_envp = kmalloc((len + 1) * sizeof(char *),
					 GFP_KERNEL);
		if (psinfo->dtps_envp == NULL)
			goto fail;

		/*
		 * Now populate the array of environment variable strings.
		 */
		for (i = 0, p = (char *)mm->env_start; i < len; i++) {
			psinfo->dtps_envp[i] = p;
			p += strnlen_user(p, MAX_ARG_STRLEN) + 1;
		}
		psinfo->dtps_envp[len] = NULL;

		mmput(mm);
	} else {
		size_t	len = min(TASK_COMM_LEN, PR_PSARGS_SZ);
		int	i;

		/*
		 * We end up here for tasks that do not have managed memory at
		 * all, which generally means that this is a kernel thread.
		 * If it is not, this is still safe because we know that tasks
		 * always have the comm member populated with something (even
		 * if it would be an empty string).
		 */
		memcpy(psinfo->dtps_psargs, tsk->comm, len);
		for (i = len; i < PR_PSARGS_SZ; i++)
			psinfo->dtps_psargs[i] = 0;

		psinfo->dtps_argc = 0;
		psinfo->dtps_argv = kmalloc(sizeof(char *), GFP_KERNEL);
		psinfo->dtps_argv[0] = NULL;
		psinfo->dtps_envc = 0;
		psinfo->dtps_envp = kmalloc(sizeof(char *), GFP_KERNEL);
		psinfo->dtps_envp[0] = NULL;
	}

	atomic_set(&psinfo->dtps_usage, 1);
	tsk->dt_task->dt_psinfo = psinfo;		/* new one */

	return;

fail:
	if (mm)
		mmput(mm);

	if (psinfo)
		dtrace_psinfo_free(psinfo);
}

/*
 * Initialize DTrace's psinf subsystem.
 */
void __init dtrace_psinfo_os_init(void)
{
	dtrace_psinfo_cachep = kmem_cache_create("dtrace_psinfo_cache",
				sizeof(dtrace_psinfo_t), 0,
				SLAB_HWCACHE_ALIGN | SLAB_PANIC,
				NULL);

}
