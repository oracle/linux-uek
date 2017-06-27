#ifndef _SPARC64_BACKOFF_H
#define _SPARC64_BACKOFF_H

/* The macros in this file implement an exponential backoff facility
 * for atomic operations.
 *
 * When multiple threads compete on an atomic operation, it is
 * possible for one thread to be continually denied a successful
 * completion of the compare-and-swap instruction.  Heavily
 * threaded cpu implementations like Niagara can compound this
 * problem even further.
 *
 * When an atomic operation fails and needs to be retried, we spin a
 * certain number of times.  At each subsequent failure of the same
 * operation we double the spin count, realizing an exponential
 * backoff.
 *
 * When we spin, we try to use an operation that will cause the
 * current cpu strand to block, and therefore make the core fully
 * available to any other other runnable strands.  There are two
 * options, based upon cpu capabilities.
 *
 * On all cpus prior to SPARC-T4 we do three dummy reads of the
 * condition code register.  Each read blocks the strand for something
 * between 40 and 50 cpu cycles.
 *
 * For SPARC-T4 and later we have a special "pause" instruction
 * available.  NOTE: pause is currently not used due to performance degradation
 * in M7/M8 platforms.
 *
 */

#define BACKOFF_LIMIT	(4 * 1024)

#ifdef CONFIG_SMP

#define BACKOFF_SETUP(reg)	\
	mov	1, reg

#define BACKOFF_LABEL(spin_label, continue_label) \
	spin_label

#define BACKOFF_SPIN(reg, tmp, label)  \
   mov   reg, tmp; \
88:   brnz,pt  tmp, 88b; \
    sub  tmp, 1, tmp; \
   set   BACKOFF_LIMIT, tmp; \
   cmp   reg, tmp; \
   bg,pn %xcc, label; \
    nop; \
   ba,pt %xcc, label; \
    sllx reg, 1, reg;

#else

#define BACKOFF_SETUP(reg)

#define BACKOFF_LABEL(spin_label, continue_label) \
	continue_label

#define BACKOFF_SPIN(reg, tmp, label)

#endif

#endif /* _SPARC64_BACKOFF_H */
