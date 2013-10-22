/*
 * FILE:	cyclic.c
 * DESCRIPTION:	Minimal cyclic implementation
 *
 * Copyright (C) 2010, 2011, 2012, 2013 Oracle Corporation
 */

#include <linux/cyclic.h>
#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/slab.h>

typedef union cyclic	cyclic_t;
union cyclic {
	struct {
		cyc_time_t		when;
		cyc_handler_t		hdlr;
		uint32_t		pend;
		struct hrtimer		timr;
		struct tasklet_struct	task;
	} cyc;
	cyclic_t		*nxt;
};

static void cyclic_fire(uintptr_t arg)
{
	cyclic_t	*cyc = (cyclic_t *)arg;
	uint32_t	cpnd, npnd;

	do {
		/*
		 * We know that the 'pend' counter for the cyclic is non-zero.
		 * So, we can start with calling the handler at least once.
		 */
		(*cyc->cyc.hdlr.cyh_func)(cyc->cyc.hdlr.cyh_arg);

again:
		/*
		 * The 'pend' counter may be modified by cyclic_expire() while
		 * we go through this loop.  We use an atomic compare-and-set
		 * instruction to determine whether it got changed.  If so, we
		 * retrieve the updated 'pend' value and try this again.
		 *
		 * Note that when the cyclic is being removed, the hrtimer will
		 * be cancelled first, which ensures that 'pend' will no longer
		 * be incremented.  When that happens, this loop will simply
		 * run through the remaining pending calls, and terminate.
		 */
		cpnd = cyc->cyc.pend;
		npnd = cpnd - 1;
		if (cmpxchg(&cyc->cyc.pend, cpnd, npnd) != cpnd)
			goto again;
	} while (npnd > 0);
}

/*
 * Timer expiration handler for cyclic hrtimers.  Cyclic worker functions must
 * be able to perform a variety of tasks (including calling functions that
 * could sleep), and therefore they cannot be called from interrupt context.
 *
 * We schedule a tasklet to do the actual work.
 *
 * But... under heavy load it is possible that the hrtimer will expire again
 * before the tasklet had a chance to run.  That would lead to missed events
 * which isn't quite acceptable.  Therefore, we use a counter to record how
 * many times the timer has expired vs how many times the handler has been
 * called.  The counter is incremented by this function upon hrtimer expiration
 * and decremented by the tasklet.  Note that the tasklet is responsible for
 * calling the handler multiple times if the counter indicates that multiple
 * invocation are pending.
 *
 * This function is called as hrtimer handler, and therefore runs in interrupt
 * context, which by definition will ensure that manipulation of the 'pend'
 * counter in the cyclic can be done without locking, and changes will appear
 * atomic to the tasklet.
 *
 * Moral of the story: the handler may not get called at the absolute times as
 * requested, but it will be called the correct number of times.
 */
static enum hrtimer_restart cyclic_expire(struct hrtimer *timr)
{
	cyclic_t		*cyc = container_of(timr, cyclic_t, cyc.timr);

	/*
	 * Increment the 'pend' counter, in case the tasklet is already set to
	 * run.  If the counter was 0 upon entry, we need to schedule the
	 * tasklet.  If the increment wraps the counter back to 0, we admit
	 * defeat, and reset it to its max value.
	 */
	if (cyc->cyc.pend++ == 0)
		tasklet_hi_schedule(&cyc->cyc.task);
	else if (cyc->cyc.pend == 0)
		cyc->cyc.pend = UINT_MAX;

	/*
	 * Prepare the timer for the next expiration.
	 */
	hrtimer_forward_now(timr, cyc->cyc.when.cyt_interval);

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

	cyc = kmalloc(sizeof(cyclic_t), GFP_KERNEL);
	if (cyc == NULL)
		return CYCLIC_NONE;

	cyc->cyc.when = *when;
	cyc->cyc.hdlr = *hdlr;
	cyc->cyc.pend = 0;
	hrtimer_init(&cyc->cyc.timr, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	cyc->cyc.timr.function = cyclic_expire;
	tasklet_init(&cyc->cyc.task, cyclic_fire, (uintptr_t)cyc);

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
 * Add a new omnipresent cyclic to the system.
 */
cyclic_id_t cyclic_add_omni(cyc_omni_handler_t *omni)
{
	if (omni == NULL)
		return CYCLIC_NONE;

	return CYCLIC_NONE;
}
EXPORT_SYMBOL(cyclic_add_omni);

/*
 * Remove a specific cyclic from the system.
 */
void cyclic_remove(cyclic_id_t id)
{
	cyclic_t	*cyc = (cyclic_t *)id;

	/*
	 * We know that hrtimer_cancel() will wait for the timer callback to
	 * finish if it is being executed at the time of making this call.  It
	 * is therefore guaranteed that 'pend' will no longer get incremented.
	 *
	 * The call to tasklet_kill() will wait for the tasklet handler to
	 * finish also, and since the handler always brings 'pend' down to zero
	 * prior to returning, it is guaranteed that (1) all pending handler
	 * calls will be made before cyclic_remove() returns, and that (2) the
	 * amount of work to be done before returning is finite.
	 */
	hrtimer_cancel(&cyc->cyc.timr);
	tasklet_kill(&cyc->cyc.task);

	kfree(cyc);
}
EXPORT_SYMBOL(cyclic_remove);
