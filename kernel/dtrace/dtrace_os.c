/*
 * FILE:	dtrace_os.c
 * DESCRIPTION:	Dynamic Tracing: OS support functions - part of kernel core
 *
 * Copyright (C) 2010 Oracle Corporation
 */

#include <linux/hrtimer.h>
#include <linux/module.h>
#include <linux/vmalloc.h>

#include "cyclic.h"

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

printk(KERN_INFO "cyc_alloc: flst [O] %p\n", cyc_flst);
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
printk(KERN_INFO "cyc_alloc: flst [N] %p, size [N] %lu\n", cyc_flst, nsize);
		cyc_arr[--idx].nxt = NULL;
printk(KERN_INFO "cyc_alloc: cyc_arr[%lu] NULL\n", idx);
		while (idx-- > cyc_size)
{
			cyc_arr[idx].nxt = &cyc_arr[idx + 1];
printk(KERN_INFO "cyc_alloc: cyc_arr[%lu] %p\n", idx, cyc_arr[idx].nxt);
}

		cyc_size = nsize;
	}

	np = cyc_flst;
	cyc_flst = cyc_flst->nxt;
printk(KERN_INFO "cyc_alloc: cyc %p, flst [N] %p\n", np, cyc_flst);

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
printk(KERN_INFO "cyclic_fire_fn: Cyclic %p, hrtimer %p\n", cyc, timr);
printk(KERN_INFO "cyclic_fire_fn:   Next expiry in %lld ns (interval %lld)\n", hrtimer_expires_remaining(&cyc->cyc.timr).tv64, cyc->cyc.when.cyt_interval.tv64);

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
printk(KERN_INFO "cyclic_add: Adding %p, hrtimer %p\n", cyc, &cyc->cyc.timr);

	if (cyc->cyc.when.cyt_when.tv64 == 0)
{
printk(KERN_INFO "cyclic_add:   Starting at relative %lld\n", cyc->cyc.when.cyt_interval.tv64);
		hrtimer_start(&cyc->cyc.timr, cyc->cyc.when.cyt_interval,
			      HRTIMER_MODE_REL_PINNED);
}
	else
{
printk(KERN_INFO "cyclic_add:   Starting at absolute %lld\n", cyc->cyc.when.cyt_when.tv64);
		hrtimer_start(&cyc->cyc.timr, cyc->cyc.when.cyt_when,
			      HRTIMER_MODE_ABS_PINNED);
}

	return (cyclic_id_t)cyc;
}
EXPORT_SYMBOL(cyclic_add);

/*
 * Remove a specific cyclic from the system.
 */
void cyclic_remove(cyclic_id_t id)
{
	cyclic_t	*cyc = (cyclic_t *)id;

printk(KERN_INFO "cyclic_add: Removing %p, hrtimer %p\n", cyc, &cyc->cyc.timr);
	hrtimer_cancel(&cyc->cyc.timr);

	mutex_lock(&cyclic_lock);

	cyc->nxt = cyc_flst;
	cyc_flst = cyc;

	mutex_unlock(&cyclic_lock);
}
EXPORT_SYMBOL(cyclic_remove);
