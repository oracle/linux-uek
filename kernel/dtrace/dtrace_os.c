/*
 * FILE:	dtrace_os.c
 * DESCRIPTION:	Dynamic Tracing: OS support functions - part of kernel core
 *
 * Copyright (C) 2010 Oracle Corporation
 */

#include <linux/hrtimer.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <asm/unistd.h>

#include "cyclic.h"
#include "systrace.h"

/*
 * Return a high resolution timer value that is guaranteed to always increase.
 */
ktime_t dtrace_gethrtime(void)
{
	struct timespec ts;

	getrawmonotonic(&ts);
	return timespec_to_ktime(ts);
}
EXPORT_SYMBOL(dtrace_gethrtime);

/*
 * Return the current wall-clock time, in nanoseconds since the epoch.
 */
ktime_t dtrace_getwalltime(void)
{
	struct timespec ts;

	getnstimeofday(&ts);
	return timespec_to_ktime(ts);
}
EXPORT_SYMBOL(dtrace_getwalltime);

/*
 * Very basic implementation of cyclics, merely enough to support dtrace.
 */
typedef union cyclic	cyclic_t;
union cyclic {
	struct {
		cyc_time_t	when;
		cyc_handler_t	hdlr;
		struct hrtimer	timr;
	} cyc;
	cyclic_t		*nxt;
};

static cyclic_t		*cyc_arr = NULL;
static cyclic_t		*cyc_flst = NULL;
static unsigned long	cyc_size = 0;

#define CHUNKSIZE	12

DEFINE_MUTEX(cyclic_lock);

/*
 * Find a free cyclic slot.  Returns NULL in out-of-memory conditions.
 */
static cyclic_t *cyc_alloc(void)
{
	cyclic_t	*np;

	mutex_lock(&cyclic_lock);

	if (cyc_flst == NULL) {
		unsigned long	nsize = cyc_size + CHUNKSIZE;
		unsigned long	idx = nsize;
		cyclic_t	*narr;

		if (!(narr = (cyclic_t *)vmalloc(nsize * sizeof(cyclic_t)))) {
			mutex_unlock(&cyclic_lock);
			return NULL;
		}

		memcpy(narr, cyc_arr, cyc_size * sizeof(cyclic_t));
		vfree(cyc_arr);
		cyc_arr = narr;

		idx = nsize;
		cyc_flst = &cyc_arr[cyc_size];
		cyc_arr[--idx].nxt = NULL;
		while (idx-- > cyc_size)
			cyc_arr[idx].nxt = &cyc_arr[idx + 1];

		cyc_size = nsize;
	}

	np = cyc_flst;
	cyc_flst = cyc_flst->nxt;

	mutex_unlock(&cyclic_lock);

	np->cyc.hdlr.cyh_func = NULL;
	return np;
}

static enum hrtimer_restart cyclic_fire_fn(struct hrtimer *timr)
{
	cyclic_t	*cyc = container_of(timr, cyclic_t, cyc.timr);

	if (cyc->cyc.hdlr.cyh_func)
		cyc->cyc.hdlr.cyh_func(cyc->cyc.hdlr.cyh_arg);

	hrtimer_forward_now(&cyc->cyc.timr, cyc->cyc.when.cyt_interval);

	return HRTIMER_RESTART;
}

/*
 * Add a new cyclic to the system.
 */
cyclic_id_t cyclic_add(cyc_handler_t *hdlr, cyc_time_t *when)
{
	cyclic_t	*cyc;

	if (hdlr == NULL || when == NULL)
		return CYCLIC_NONE;

	if ((cyc = cyc_alloc()) == NULL)
		return CYCLIC_NONE;

	cyc->cyc.when = *when;
	cyc->cyc.hdlr = *hdlr;

	hrtimer_init(&cyc->cyc.timr, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	cyc->cyc.timr.function = cyclic_fire_fn;

	if (cyc->cyc.when.cyt_when.tv64 == 0)
		hrtimer_start(&cyc->cyc.timr, cyc->cyc.when.cyt_interval,
			      HRTIMER_MODE_REL_PINNED);
	else
		hrtimer_start(&cyc->cyc.timr, cyc->cyc.when.cyt_when,
			      HRTIMER_MODE_ABS_PINNED);

	return (cyclic_id_t)cyc;
}
EXPORT_SYMBOL(cyclic_add);

/*
 * Remove a specific cyclic from the system.
 */
void cyclic_remove(cyclic_id_t id)
{
	cyclic_t	*cyc = (cyclic_t *)id;

	hrtimer_cancel(&cyc->cyc.timr);

	mutex_lock(&cyclic_lock);

	cyc->nxt = cyc_flst;
	cyc_flst = cyc;

	mutex_unlock(&cyclic_lock);
}
EXPORT_SYMBOL(cyclic_remove);

void (*systrace_probe)(dtrace_id_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t,
		       uintptr_t, uintptr_t);

void systrace_stub(dtrace_id_t id, uintptr_t arg0, uintptr_t arg1,
		   uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
		   uintptr_t arg5)
{
}

asmlinkage long systrace_syscall(uintptr_t, uintptr_t,
				 uintptr_t, uintptr_t,
				 uintptr_t, uintptr_t);

static systrace_info_t	systrace_info = {
					    &systrace_probe,
					    systrace_stub,
					    systrace_syscall,
					    {
/*
 * Need to remove the define for _ASM_X86_UNISTD_64_H in order for unistd_64
 * to be included here because it was already included indirectly.
 */
#undef __SYSCALL
#define __SYSCALL(nr, sym)			[nr] { __stringify(sym), },
#undef _ASM_X86_UNISTD_64_H
#include <asm/unistd_64.h>
					    }
					};


asmlinkage long systrace_syscall(uintptr_t arg0, uintptr_t arg1,
				 uintptr_t arg2, uintptr_t arg3,
				 uintptr_t arg4, uintptr_t arg5)
{
	long			rc = 0;
	unsigned long		sysnum;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;

	asm volatile("movq %%rax,%0" : "=m"(sysnum));

	sc = &systrace_info.sysent[sysnum];

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, arg0, arg1, arg2, arg3, arg4, arg5);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	if (sc->stsy_underlying != NULL)
		rc = (*sc->stsy_underlying)(arg0, arg1, arg2, arg3, arg4,
					    arg5);

	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, arg0, arg1, arg2, arg3, arg4, arg5);

	return rc;
}

systrace_info_t *dtrace_syscalls_init() {
	int			i;
	extern sys_call_ptr_t	sys_call_table[NR_syscalls];

	systrace_info.probep = &systrace_probe;
	systrace_info.stub = systrace_stub;
	systrace_info.syscall = systrace_syscall;

	for (i = 0; i < NR_syscalls; i++) {
		systrace_info.sysent[i].stsy_tblent = &sys_call_table[i];
		systrace_info.sysent[i].stsy_underlying =
					(dt_sys_call_t)sys_call_table[i];
	}

	return &systrace_info;
}
EXPORT_SYMBOL(dtrace_syscalls_init);
