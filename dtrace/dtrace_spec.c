/*
 * FILE:	dtrace_spec.c
 * DESCRIPTION:	Dynamic Tracing: speculation functions
 *
 * Copyright (C) 2010 Oracle Corporation
 */

#include <linux/smp.h>
#include <asm/cmpxchg.h>

#include "dtrace.h"

/*
 * Given consumer state, this routine finds a speculation in the INACTIVE
 * state and transitions it into the ACTIVE state.  If there is no speculation
 * in the INACTIVE state, 0 is returned.  In this case, no error counter is
 * incremented -- it is up to the caller to take appropriate action.
 */
int dtrace_speculation(dtrace_state_t *state)
{
	int				i = 0;
	dtrace_speculation_state_t	curr;
	uint32_t			*stat =
					    &state->dts_speculations_unavail,
					count;

	while (i < state->dts_nspeculations) {
		dtrace_speculation_t	*spec = &state->dts_speculations[i];

		curr = spec->dtsp_state;

		if (curr != DTRACESPEC_INACTIVE) {
			if (curr == DTRACESPEC_COMMITTINGMANY ||
			    curr == DTRACESPEC_COMMITTING ||
			    curr == DTRACESPEC_DISCARDING)
				stat = &state->dts_speculations_busy;

			i++;
			continue;
		}

		if (cmpxchg((uint32_t *)&spec->dtsp_state, curr,
			    DTRACESPEC_ACTIVE) == curr)
			return i + 1;
	}

	/*
	 * We couldn't find a speculation.  If we found as much as a single
	 * busy speculation buffer, we'll attribute this failure as "busy"
	 * instead of "unavail".
	 */
	do {
		count = *stat;
	} while (cmpxchg(stat, count, count + 1) != count);

	return 0;
}

/*
 * This routine commits an active speculation.  If the specified speculation
 * is not in a valid state to perform a commit(), this routine will silently do
 * nothing.  The state of the specified speculation is transitioned according
 * to the state transition diagram outlined in <sys/dtrace_impl.h>
 */
void dtrace_speculation_commit(dtrace_state_t *state, processorid_t cpu,
			       dtrace_specid_t which)
{
	dtrace_speculation_t		*spec;
	dtrace_buffer_t			*src, *dest;
	uintptr_t			daddr, saddr, dlimit;
	dtrace_speculation_state_t	curr, new = 0;
	intptr_t			offs;

	if (which == 0)
		return;

printk(KERN_INFO "spec-commit: CPU#%d, which %d\n", cpu, which);
	if (which > state->dts_nspeculations) {
		cpu_core[cpu].cpuc_dtrace_flags |= CPU_DTRACE_ILLOP;
		return;
	}

	spec = &state->dts_speculations[which - 1];
	src = &spec->dtsp_buffer[cpu];
	dest = &state->dts_buffer[cpu];

	do {
printk(KERN_INFO "spec-commit: a) CPU#%d, which %d, spec-state %d\n", cpu, which, spec->dtsp_state);
		curr = spec->dtsp_state;

		if (curr == DTRACESPEC_COMMITTINGMANY)
			break;

		switch (curr) {
		case DTRACESPEC_INACTIVE:
		case DTRACESPEC_DISCARDING:
			return;

		case DTRACESPEC_COMMITTING:
			/*
			 * This is only possible if we are (a) commit()'ing
			 * without having done a prior speculate() on this CPU
			 * and (b) racing with another commit() on a different
			 * CPU.  There's nothing to do -- we just assert that
			 * our offset is 0.
			 */
			ASSERT(src->dtb_offset == 0);
			return;

		case DTRACESPEC_ACTIVE:
			new = DTRACESPEC_COMMITTING;
			break;

		case DTRACESPEC_ACTIVEONE:
			/*
			 * This speculation is active on one CPU.  If our
			 * buffer offset is non-zero, we know that the one CPU
			 * must be us.  Otherwise, we are committing on a
			 * different CPU from the speculate(), and we must
			 * rely on being asynchronously cleaned.
			 */
			if (src->dtb_offset != 0) {
				new = DTRACESPEC_COMMITTING;
				break;
			}
			/*FALLTHROUGH*/

		case DTRACESPEC_ACTIVEMANY:
			new = DTRACESPEC_COMMITTINGMANY;
			break;

		default:
			ASSERT(0);
		}
printk(KERN_INFO "spec-commit: a) CPU#%d, which %d, spec-state %d -> %d\n", cpu, which, curr, new);
	} while (cmpxchg((uint32_t *)&spec->dtsp_state, curr, new) !=
		 curr);

	/*
	 * We have set the state to indicate that we are committing this
	 * speculation.  Now reserve the necessary space in the destination
	 * buffer.
	 */
	offs = dtrace_buffer_reserve(dest, src->dtb_offset, sizeof (uint64_t),
				     state, NULL);
	if (offs < 0) {
		dtrace_buffer_drop(dest);
		goto out;
	}

	/*
	 * We have the space; copy the buffer across.  (Note that this is a
	 * highly subobtimal bcopy(); in the unlikely event that this becomes
	 * a serious performance issue, a high-performance DTrace-specific
	 * bcopy() should obviously be invented.)
	 */
	daddr = (uintptr_t)dest->dtb_tomax + offs;
	dlimit = daddr + src->dtb_offset;
	saddr = (uintptr_t)src->dtb_tomax;

	/*
	 * First, the aligned portion.
	 */
	while (dlimit - daddr >= sizeof (uint64_t)) {
		*((uint64_t *)daddr) = *((uint64_t *)saddr);
		*((uint64_t *)daddr) = *((uint64_t *)saddr);

		daddr += sizeof (uint64_t);
		saddr += sizeof (uint64_t);
	}

	/*
	 * Now any left-over bit...
	 */
	while (dlimit - daddr)
		*((uint8_t *)daddr++) = *((uint8_t *)saddr++);

	/*
	 * Finally, commit the reserved space in the destination buffer.
	 */
	dest->dtb_offset = offs + src->dtb_offset;

out:
	/*
	 * If we're lucky enough to be the only active CPU on this speculation
	 * buffer, we can just set the state back to DTRACESPEC_INACTIVE.
	 */
	if (curr == DTRACESPEC_ACTIVE ||
	    (curr == DTRACESPEC_ACTIVEONE && new == DTRACESPEC_COMMITTING)) {
		/*
		 * Will cause unused warning if DEBUG is not defined.
		 */
		uint32_t	rval =
				cmpxchg((uint32_t *)&spec->dtsp_state,
					DTRACESPEC_COMMITTING,
					DTRACESPEC_INACTIVE);

		ASSERT(rval == DTRACESPEC_COMMITTING);
		rval = 0; /* Avoid warning about unused variable if !DEBUG */
	}

	src->dtb_offset = 0;
	src->dtb_xamot_drops += src->dtb_drops;
	src->dtb_drops = 0;
}

/*
 * This routine discards an active speculation.  If the specified speculation
 * is not in a valid state to perform a discard(), this routine will silently
 * do nothing.  The state of the specified speculation is transitioned
 * according to the state transition diagram outlined in <sys/dtrace_impl.h>
 */
void dtrace_speculation_discard(dtrace_state_t *state, processorid_t cpu,
				dtrace_specid_t which)
{
	dtrace_speculation_t		*spec;
	dtrace_speculation_state_t	curr, new = 0;
	dtrace_buffer_t			*buf;

	if (which == 0)
		return;

	if (which > state->dts_nspeculations) {
		cpu_core[cpu].cpuc_dtrace_flags |= CPU_DTRACE_ILLOP;
		return;
	}

	spec = &state->dts_speculations[which - 1];
	buf = &spec->dtsp_buffer[cpu];

	do {
		curr = spec->dtsp_state;

		switch (curr) {
		case DTRACESPEC_INACTIVE:
		case DTRACESPEC_COMMITTINGMANY:
		case DTRACESPEC_COMMITTING:
		case DTRACESPEC_DISCARDING:
			return;

		case DTRACESPEC_ACTIVE:
		case DTRACESPEC_ACTIVEMANY:
			new = DTRACESPEC_DISCARDING;
			break;

		case DTRACESPEC_ACTIVEONE:
			if (buf->dtb_offset != 0)
				new = DTRACESPEC_INACTIVE;
			else
				new = DTRACESPEC_DISCARDING;

			break;

		default:
			ASSERT(0);
		}
	} while (cmpxchg((uint32_t *)&spec->dtsp_state, curr, new) != curr);

	buf->dtb_offset = 0;
	buf->dtb_drops = 0;
}

/*
 * Note:  not called from probe context.  This function is called
 * asynchronously from cross call context to clean any speculations that are
 * in the COMMITTINGMANY or DISCARDING states.  These speculations may not be
 * transitioned back to the INACTIVE state until all CPUs have cleaned the
 * speculation.
 */
void dtrace_speculation_clean_here(dtrace_state_t *state)
{
	dtrace_icookie_t	cookie;
	processorid_t		cpu = smp_processor_id();
	dtrace_buffer_t		*dest = &state->dts_buffer[cpu];
	dtrace_specid_t		i;

	local_irq_save(cookie);

	if (dest->dtb_tomax == NULL) {
		local_irq_restore(cookie);
		return;
	}

	for (i = 0; i < state->dts_nspeculations; i++) {
		dtrace_speculation_t	*spec = &state->dts_speculations[i];
		dtrace_buffer_t		*src = &spec->dtsp_buffer[cpu];

		if (src->dtb_tomax == NULL)
			continue;

		if (spec->dtsp_state == DTRACESPEC_DISCARDING) {
			src->dtb_offset = 0;
			continue;
		}

		if (spec->dtsp_state != DTRACESPEC_COMMITTINGMANY)
			continue;

		if (src->dtb_offset == 0)
			continue;

		dtrace_speculation_commit(state, cpu, i + 1);
	}

	local_irq_restore(cookie);
}

void dtrace_speculation_clean(dtrace_state_t *state)
{
	int		work = 0, rv;
	dtrace_specid_t	i;

	for (i = 0; i < state->dts_nspeculations; i++) {
		dtrace_speculation_t	*spec = &state->dts_speculations[i];

		ASSERT(!spec->dtsp_cleaning);

		if (spec->dtsp_state != DTRACESPEC_DISCARDING &&
		    spec->dtsp_state != DTRACESPEC_COMMITTINGMANY)
			continue;

		work++;
		spec->dtsp_cleaning = 1;
	}

	if (!work)
		return;

	dtrace_xcall(DTRACE_CPUALL,
		     (dtrace_xcall_t)dtrace_speculation_clean_here, state);

	/*
	 * We now know that all CPUs have committed or discarded their
	 * speculation buffers, as appropriate.  We can now set the state
	 * to inactive.
	 */
	for (i = 0; i < state->dts_nspeculations; i++) {
		dtrace_speculation_t		*spec =
						&state->dts_speculations[i];
		dtrace_speculation_state_t	curr, new;

		if (!spec->dtsp_cleaning)
			continue;

		curr= spec->dtsp_state;
		ASSERT(curr == DTRACESPEC_DISCARDING ||
		       curr == DTRACESPEC_COMMITTINGMANY);

		new = DTRACESPEC_INACTIVE;

		rv = cmpxchg((uint32_t *)&spec->dtsp_state, curr, new);
		ASSERT(rv == curr);
		spec->dtsp_cleaning = 0;
	}
}

/*
 * Called as part of a speculate() to get the speculative buffer associated
 * with a given speculation.  Returns NULL if the specified speculation is not
 * in an ACTIVE state.  If the speculation is in the ACTIVEONE state -- and
 * the active CPU is not the specified CPU -- the speculation will be
 * atomically transitioned into the ACTIVEMANY state.
 */
dtrace_buffer_t *dtrace_speculation_buffer(dtrace_state_t *state,
					   processorid_t cpuid,
					   dtrace_specid_t which)
{
	dtrace_speculation_t		*spec;
	dtrace_speculation_state_t	curr, new = 0;
	dtrace_buffer_t			*buf;

	if (which == 0)
		return NULL;

	if (which > state->dts_nspeculations) {
		cpu_core[cpuid].cpuc_dtrace_flags |= CPU_DTRACE_ILLOP;
		return NULL;
	}

	spec = &state->dts_speculations[which - 1];
	buf = &spec->dtsp_buffer[cpuid];

	do {
		curr = spec->dtsp_state;

		switch (curr) {
		case DTRACESPEC_INACTIVE:
		case DTRACESPEC_COMMITTINGMANY:
		case DTRACESPEC_DISCARDING:
			return NULL;

		case DTRACESPEC_COMMITTING:
			ASSERT(buf->dtb_offset == 0);
			return NULL;

		case DTRACESPEC_ACTIVEONE:
			/*
			 * This speculation is currently active on one CPU.
			 * Check the offset in the buffer; if it's non-zero,
			 * that CPU must be us (and we leave the state alone).
			 * If it's zero, assume that we're starting on a new
			 * CPU -- and change the state to indicate that the
			 * speculation is active on more than one CPU.
			 */
			if (buf->dtb_offset != 0)
				return buf;

			new = DTRACESPEC_ACTIVEMANY;
			break;

		case DTRACESPEC_ACTIVEMANY:
			return buf;

		case DTRACESPEC_ACTIVE:
			new = DTRACESPEC_ACTIVEONE;
			break;

		default:
			ASSERT(0);
		}
	} while (cmpxchg((uint32_t *)&spec->dtsp_state, curr, new) != curr);

	ASSERT(new == DTRACESPEC_ACTIVEONE || new == DTRACESPEC_ACTIVEMANY);

	return buf;
}
