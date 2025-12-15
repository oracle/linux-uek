/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_RSEQ_ENTRY_H
#define _LINUX_RSEQ_ENTRY_H

/* Must be outside the CONFIG_RSEQ guard to resolve the stubs */
#ifdef CONFIG_RSEQ_STATS
#include <linux/percpu.h>

struct rseq_stats {
	unsigned long	s_granted;
	unsigned long	s_expired;
	unsigned long	s_revoked;
	unsigned long	s_yielded;
	unsigned long	s_aborted;
};

DECLARE_PER_CPU(struct rseq_stats, rseq_stats);

/*
 * Slow path has interrupts and preemption enabled, but the fast path
 * runs with interrupts disabled so there is no point in having the
 * preemption checks implied in __this_cpu_inc() for every operation.
 */
#ifdef RSEQ_BUILD_SLOW_PATH
#define rseq_stat_inc(which)	this_cpu_inc((which))
#else
#define rseq_stat_inc(which)	raw_cpu_inc((which))
#endif

#else /* CONFIG_RSEQ_STATS */
#define rseq_stat_inc(x)	do { } while (0)
#endif /* !CONFIG_RSEQ_STATS */

DECLARE_STATIC_KEY_MAYBE(CONFIG_RSEQ_DEBUG_DEFAULT_ENABLE, rseq_debug_enabled);

#ifdef CONFIG_RSEQ
#include <linux/jump_label.h>

#ifdef CONFIG_RSEQ_SLICE_EXTENSION
DECLARE_STATIC_KEY_TRUE(rseq_slice_extension_key);

static __always_inline bool rseq_slice_extension_enabled(void)
{
	return static_branch_likely(&rseq_slice_extension_key);
}

extern unsigned int rseq_slice_ext_nsecs;
bool __rseq_arm_slice_extension_timer(void);

static __always_inline bool rseq_arm_slice_extension_timer(void)
{
	if (!rseq_slice_extension_enabled())
		return false;

	if (likely(!current->rseq_slice.state.granted))
		return false;

	return __rseq_arm_slice_extension_timer();
}

static __always_inline void rseq_slice_clear_grant(struct task_struct *t)
{
	if (IS_ENABLED(CONFIG_RSEQ_STATS) && t->rseq_slice.state.granted)
		rseq_stat_inc(rseq_stats.s_revoked);
	t->rseq_slice.state.granted = false;
}

static __always_inline bool rseq_grant_slice_extension(bool work_pending)
{
	struct task_struct *curr = current;
	struct rseq_slice_ctrl usr_ctrl;
	union rseq_slice_state state;
	struct rseq __user *rseq;

	if (!rseq_slice_extension_enabled())
		return false;

	/* If not enabled or not a return from interrupt, nothing to do. */
	state = curr->rseq_slice.state;
	state.enabled &= curr->rseq_slice.user_irq;
	if (likely(!state.state))
		return false;

	rseq = curr->rseq;
	if (!user_write_access_begin(rseq, sizeof(*rseq)))
		goto efault_sig;
	/*
	 * Quick check conditions where a grant is not possible or
	 * needs to be revoked.
	 *
	 *  1) Any TIF bit which needs to do extra work aside of
	 *     rescheduling prevents a grant.
	 *
	 *  2) A previous rescheduling request resulted in a slice
	 *     extension grant.
	 */
	if (unlikely(work_pending || state.granted)) {
		/* Clear user control unconditionally. No point for checking */
		unsafe_put_user(0U, &rseq->slice_ctrl.all, efault);
		rseq_slice_clear_grant(curr);
		user_write_access_end();
		return false;
	}

	unsafe_get_user(usr_ctrl.all, &rseq->slice_ctrl.all, efault);
	if (likely(!(usr_ctrl.request))) {
		user_write_access_end();
		return false;
	}

	/* Grant the slice extension */
	usr_ctrl.request = 0;
	usr_ctrl.granted = 1;
	unsafe_put_user(usr_ctrl.all, &rseq->slice_ctrl.all, efault);

	user_write_access_end();
	rseq_stat_inc(rseq_stats.s_granted);

	curr->rseq_slice.state.granted = true;
	/* Store expiry time for arming the timer on the way out */
	curr->rseq_slice_expires = data_race(rseq_slice_ext_nsecs) + ktime_get_mono_fast_ns();
	/*
	 * This is racy against a remote CPU setting TIF_NEED_RESCHED in
	 * several ways:
	 *
	 * 1)
	 *	CPU0			CPU1
	 *	clear_tsk()
	 *				set_tsk()
	 *	clear_preempt()
	 *				Raise scheduler IPI on CPU0
	 *	--> IPI
	 *	    fold_need_resched() -> Folds correctly
	 * 2)
	 *	CPU0			CPU1
	 *				set_tsk()
	 *	clear_tsk()
	 *	clear_preempt()
	 *				Raise scheduler IPI on CPU0
	 *	--> IPI
	 *	    fold_need_resched() <- NOOP as TIF_NEED_RESCHED is false
	 *
	 * #1 is not any different from a regular remote reschedule as it
	 *    sets the previously not set bit and then raises the IPI which
	 *    folds it into the preempt counter
	 *
	 * #2 is obviously incorrect from a scheduler POV, but it's not
	 *    differently incorrect than the code below clearing the
	 *    reschedule request with the safety net of the timer.
	 *
	 * The important part is that the clearing is protected against the
	 * scheduler IPI and also against any other interrupt which might
	 * end up waking up a task and setting the bits in the middle of
	 * the operation:
	 *
	 *	clear_tsk()
	 *	---> Interrupt
	 *		wakeup_on_this_cpu()
	 *		set_tsk()
	 *		set_preempt()
	 *	clear_preempt()
	 *
	 * which would be inconsistent state.
	 */
	local_irq_disable();
	clear_tsk_need_resched(curr);
	clear_preempt_need_resched();
	local_irq_enable();
	return true;

efault:
	user_write_access_end();
efault_sig:
	force_sig(SIGSEGV);
	return false;
}

#else /* CONFIG_RSEQ_SLICE_EXTENSION */
static inline bool rseq_slice_extension_enabled(void) { return false; }
static inline bool rseq_arm_slice_extension_timer(void) { return false; }
static inline void rseq_slice_clear_grant(struct task_struct *t) { }
static inline bool rseq_grant_slice_extension(bool work_pending) { return false; }
#endif /* !CONFIG_RSEQ_SLICE_EXTENSION */

static __always_inline void rseq_note_user_irq_entry(void)
{
	if (IS_ENABLED(CONFIG_GENERIC_ENTRY))
		current->rseq_slice.user_irq = true;
}

static __always_inline void rseq_irqentry_exit_to_user_mode(void)
{
	if (current->rseq_slice.user_irq)
		current->rseq_slice.user_irq = false;
}

static __always_inline bool rseq_exit_to_user_mode_restart(void)
{
	if (current->rseq_slice.user_irq)
		current->rseq_slice.user_irq = false;
	return rseq_arm_slice_extension_timer();
}
#else /* CONFIG_RSEQ */
static inline void rseq_note_user_irq_entry(void) { }
static inline bool rseq_exit_to_user_mode_restart(void) { return false; }
static inline bool rseq_grant_slice_extension(bool work_pending) { return false; }
#endif /* !CONFIG_RSEQ */

#endif /* _LINUX_RSEQ_ENTRY_H */
