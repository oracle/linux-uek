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
#else /* CONFIG_RSEQ_SLICE_EXTENSION */
static inline bool rseq_slice_extension_enabled(void) { return false; }
#endif /* !CONFIG_RSEQ_SLICE_EXTENSION */
#endif /* !CONFIG_RSEQ */

#endif /* _LINUX_RSEQ_ENTRY_H */
