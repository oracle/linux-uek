/*
 * Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
 */
#ifndef	_LINUX_DTRACE_TASK_IMPL_H_
#define _LINUX_DTRACE_TASK_IMPL_H_

#ifdef CONFIG_DTRACE

#include <linux/dtrace_task.h>
#include <linux/dtrace_psinfo.h>

struct dtrace_task {
	uint32_t	dt_predcache;
	ktime_t		dt_vtime;
	ktime_t		dt_start;
	uint8_t		dt_stop;
	uint8_t		dt_sig;
	dtrace_psinfo_t	*dt_psinfo;
	void		*dt_helpers;
	uint32_t	dt_probes;
	uint64_t	dt_tp_count;
	void		*dt_ustack;
};

#endif /* CONFIG_DTRACE */
#endif /* _LINUX_DTRACE_TASK_IMPL_H_ */

