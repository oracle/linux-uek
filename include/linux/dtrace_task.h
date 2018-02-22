/*
 * Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _LINUX_DTRACE_TASK_H_
#define _LINUX_DTRACE_TASK_H_

#ifdef CONFIG_DTRACE

#include <linux/sched.h>

/*
 * Opaque handle for per-task data.
 */
typedef struct dtrace_task dtrace_task_t;

/*
 * DTrace's kernel API for per-task data manipulation.
 */

extern void dtrace_task_init(struct task_struct *);
extern void dtrace_task_exec(struct task_struct *);
extern void dtrace_task_copy(struct task_struct *, struct task_struct *);
extern void dtrace_task_free(struct task_struct *);
extern void dtrace_task_dup(struct task_struct *, struct task_struct *);

#else /* CONFIG_DTRACE */

#define	dtrace_task_init(ignore)
#define	dtrace_task_exec(ignore)
#define	dtrace_task_copy(ignore1, ignore2)
#define	dtrace_task_free(ignore)
#define	dtrace_task_dup(ignore1, ignore2)

#endif /* CONFIG_DTRACE */

#endif /* _LINUX_DTRACE_TASK_H_ */
