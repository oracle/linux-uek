/*
 * FILE:	dtrace_buffer.c
 * DESCRIPTION:	Dynamic Tracing: buffer functions
 *
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2010, 2011 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <linux/vmalloc.h>

#include "dtrace.h"

dtrace_optval_t		dtrace_nonroot_maxsize = (16 * 1024 * 1024);

/*
 * Note:  called from cross call context.  This function switches the two
 * buffers on a given CPU.  The atomicity of this operation is assured by
 * disabling interrupts while the actual switch takes place; the disabling of
 * interrupts serializes the execution with any execution of dtrace_probe() on
 * the same CPU.
 */
void dtrace_buffer_switch(dtrace_buffer_t *buf)
{
	caddr_t			tomax = buf->dtb_tomax;
	caddr_t			xamot = buf->dtb_xamot;
	dtrace_icookie_t	cookie;

	ASSERT(!(buf->dtb_flags & DTRACEBUF_NOSWITCH));
	ASSERT(!(buf->dtb_flags & DTRACEBUF_RING));

	local_irq_save(cookie);

	buf->dtb_tomax = xamot;
	buf->dtb_xamot = tomax;
	buf->dtb_xamot_drops = buf->dtb_drops;
	buf->dtb_xamot_offset = buf->dtb_offset;
	buf->dtb_xamot_errors = buf->dtb_errors;
	buf->dtb_xamot_flags = buf->dtb_flags;
	buf->dtb_offset = 0;
	buf->dtb_drops = 0;
	buf->dtb_errors = 0;
	buf->dtb_flags &= ~(DTRACEBUF_ERROR | DTRACEBUF_DROPPED);

	local_irq_restore(cookie);
}

/*
 * Note:  called from cross call context.  This function activates a buffer
 * on a CPU.  As with dtrace_buffer_switch(), the atomicity of the operation
 * is guaranteed by the disabling of interrupts.
 */
void dtrace_buffer_activate(dtrace_state_t *state)
{
	dtrace_buffer_t		*buf;
	dtrace_icookie_t	cookie;

	local_irq_save(cookie);

	buf = &state->dts_buffer[smp_processor_id()];

	if (buf->dtb_tomax != NULL) {
		/*
		 * We might like to assert that the buffer is marked inactive,
		 * but this isn't necessarily true:  the buffer for the CPU
		 * that processes the BEGIN probe has its buffer activated
		 * manually.  In this case, we take the (harmless) action
		 * re-clearing the bit INACTIVE bit.
		 */
		 buf->dtb_flags &= ~DTRACEBUF_INACTIVE;
	}

	local_irq_restore(cookie);
}

int dtrace_buffer_alloc(dtrace_buffer_t *bufs, size_t size, int flags,
			processorid_t cpuid)
{
	processorid_t	cpu;
	dtrace_buffer_t	*buf;

	ASSERT(MUTEX_HELD(&dtrace_lock));
	ASSERT(MUTEX_HELD(&cpu_lock));

#ifdef FIXME
	if (size > dtrace_nonroot_maxsize &&
	    !PRIV_POLICY_CHOICE(current_cred(), PRIV_ALL, FALSE))
		return -EFBIG;
#endif

	for_each_online_cpu(cpu) {
		if (cpuid != DTRACE_CPUALL && cpuid != cpu)
			continue;

		buf = &bufs[cpu];

		/*
		 * If there is already a buffer allocated for this CPU, it
		 * is only possible that this is a DR event.  In this case,
		 * the buffer size must match our specified size.
		 */
		if (buf->dtb_tomax != NULL) {
			ASSERT(buf->dtb_size == size);
			continue;
		}

		ASSERT(buf->dtb_xamot == NULL);

		if ((buf->dtb_tomax = dtrace_vzalloc_try(size)) == NULL)
			goto err;

		buf->dtb_size = size;
		buf->dtb_flags = flags;
		buf->dtb_offset = 0;
		buf->dtb_drops = 0;

		if (flags & DTRACEBUF_NOSWITCH)
			continue;

		if ((buf->dtb_xamot = dtrace_vzalloc_try(size)) == NULL)
			goto err;
	}

	return 0;

err:
	for_each_online_cpu(cpu) {
		if (cpuid != DTRACE_CPUALL && cpuid != cpu)
			continue;

		buf = &bufs[cpu];

		if (buf->dtb_xamot != NULL) {
			ASSERT(buf->dtb_tomax != NULL);
			ASSERT(buf->dtb_size == size);
			vfree(buf->dtb_xamot);
		}

		if (buf->dtb_tomax != NULL) {
			ASSERT(buf->dtb_size == size);
			vfree(buf->dtb_tomax);
		}

		buf->dtb_tomax = NULL;
		buf->dtb_xamot = NULL;
		buf->dtb_size = 0;
	}

	return -ENOMEM;
}
void dtrace_buffer_drop(dtrace_buffer_t *buf)
{
	buf->dtb_drops++;
}

intptr_t dtrace_buffer_reserve(dtrace_buffer_t *buf, size_t needed,
			       size_t align, dtrace_state_t *state,
			       dtrace_mstate_t *mstate)
{
	intptr_t	offs = buf->dtb_offset, soffs;
	intptr_t	woffs;
	caddr_t		tomax;
	size_t		total;

	if (buf->dtb_flags & DTRACEBUF_INACTIVE)
		return -1;

	if ((tomax = buf->dtb_tomax) == NULL) {
		dtrace_buffer_drop(buf);
		return -1;
	}

	if (!(buf->dtb_flags & (DTRACEBUF_RING | DTRACEBUF_FILL))) {
		while (offs & (align - 1)) {
			/*
			 * Assert that our alignment is off by a number which
			 * is itself sizeof (uint32_t) aligned.
			 */
			ASSERT(!((align - (offs & (align - 1))) &
				(sizeof (uint32_t) - 1)));
			DTRACE_STORE(uint32_t, tomax, offs, DTRACE_EPIDNONE);
			offs += sizeof (uint32_t);
		}

		if ((soffs = offs + needed) > buf->dtb_size) {
			dtrace_buffer_drop(buf);
			return -1;
		}

		if (mstate == NULL)
			return (offs);

		mstate->dtms_scratch_base = (uintptr_t)tomax + soffs;
		mstate->dtms_scratch_size = buf->dtb_size - soffs;
		mstate->dtms_scratch_ptr = mstate->dtms_scratch_base;

		return offs;
	}

	if (buf->dtb_flags & DTRACEBUF_FILL) {
		if (state->dts_activity != DTRACE_ACTIVITY_COOLDOWN &&
		    (buf->dtb_flags & DTRACEBUF_FULL))
			return -1;

		goto out;
	}

	total = needed + (offs & (align - 1));

	/*
	 * For a ring buffer, life is quite a bit more complicated.  Before
	 * we can store any padding, we need to adjust our wrapping offset.
	 * (If we've never before wrapped or we're not about to, no adjustment
	 * is required.)
	 */
	if ((buf->dtb_flags & DTRACEBUF_WRAPPED) ||
	    offs + total > buf->dtb_size) {
		woffs = buf->dtb_xamot_offset;

		if (offs + total > buf->dtb_size) {
			/*
			 * We can't fit in the end of the buffer.  First, a
			 * sanity check that we can fit in the buffer at all.
			 */
			if (total > buf->dtb_size) {
				dtrace_buffer_drop(buf);
				return -1;
			}

			/*
			 * We're going to be storing at the top of the buffer,
			 * so now we need to deal with the wrapped offset.  We
			 * only reset our wrapped offset to 0 if it is
			 * currently greater than the current offset.  If it
			 * is less than the current offset, it is because a
			 * previous allocation induced a wrap -- but the
			 * allocation didn't subsequently take the space due
			 * to an error or false predicate evaluation.  In this
			 * case, we'll just leave the wrapped offset alone: if
			 * the wrapped offset hasn't been advanced far enough
			 * for this allocation, it will be adjusted in the
			 * lower loop.
			 */
			if (buf->dtb_flags & DTRACEBUF_WRAPPED) {
				if (woffs >= offs)
					woffs = 0;
			} else
				woffs = 0;

			/*
			 * Now we know that we're going to be storing to the
			 * top of the buffer and that there is room for us
			 * there.  We need to clear the buffer from the current
			 * offset to the end (there may be old gunk there).
			 */
			while (offs < buf->dtb_size)
				tomax[offs++] = 0;

			/*
			 * We need to set our offset to zero.  And because we
			 * are wrapping, we need to set the bit indicating as
			 * much.  We can also adjust our needed space back
			 * down to the space required by the ECB -- we know
			 * that the top of the buffer is aligned.
			 */
			offs = 0;
			total = needed;
			buf->dtb_flags |= DTRACEBUF_WRAPPED;
		} else {
			/*
			 * There is room for us in the buffer, so we simply
			 * need to check the wrapped offset.
			 */
			if (woffs < offs) {
				/*
				 * The wrapped offset is less than the offset.
				 * This can happen if we allocated buffer space
				 * that induced a wrap, but then we didn't
				 * subsequently take the space due to an error
				 * or false predicate evaluation.  This is
				 * okay; we know that _this_ allocation isn't
				 * going to induce a wrap.  We still can't
				 * reset the wrapped offset to be zero,
				 * however: the space may have been trashed in
				 * the previous failed probe attempt.  But at
				 * least the wrapped offset doesn't need to
				 * be adjusted at all...
				 */
				goto out;
			}
		}

		while (offs + total > woffs) {
			dtrace_epid_t	epid = *(uint32_t *)(tomax + woffs);
			size_t		size;

			if (epid == DTRACE_EPIDNONE)
				size = sizeof (uint32_t);
			else {
				ASSERT(epid <= state->dts_necbs);
				ASSERT(state->dts_ecbs[epid - 1] != NULL);

				size = state->dts_ecbs[epid - 1]->dte_size;
			}

			ASSERT(woffs + size <= buf->dtb_size);
			ASSERT(size != 0);

			if (woffs + size == buf->dtb_size) {
				/*
				 * We've reached the end of the buffer; we want
				 * to set the wrapped offset to 0 and break
				 * out.  However, if the offs is 0, then we're
				 * in a strange edge-condition:  the amount of
				 * space that we want to reserve plus the size
				 * of the record that we're overwriting is
				 * space but subsequently don't consume it (due
				 * to a failed predicate or error) the wrapped
				 * offset will be 0 -- yet the EPID at offset 0
				 * will not be committed.  This situation is
				 * relatively easy to deal with:  if we're in
				 * this case, the buffer is indistinguishable
				 * from one that hasn't wrapped; we need only
				 * finish the job by clearing the wrapped bit,
				 * explicitly setting the offset to be 0, and
				 * zero'ing out the old data in the buffer.
				 */
				if (offs == 0) {
					buf->dtb_flags &= ~DTRACEBUF_WRAPPED;
					buf->dtb_offset = 0;
					woffs = total;

					while (woffs < buf->dtb_size)
						tomax[woffs++] = 0;
				}

				woffs = 0;
				break;
			}

			woffs += size;
		}

		/*
		 * We have a wrapped offset.  It may be that the wrapped offset
		 * has become zero -- that's okay.
		 */
		buf->dtb_xamot_offset = woffs;
	}

out:
	/*
	 * Now we can plow the buffer with any necessary padding.
	 */
	while (offs & (align - 1)) {
		/*
		 * Assert that our alignment is off by a number which
		 * is itself sizeof (uint32_t) aligned.
		 */
		ASSERT(!((align - (offs & (align - 1))) &
			(sizeof (uint32_t) - 1)));
		DTRACE_STORE(uint32_t, tomax, offs, DTRACE_EPIDNONE);
		offs += sizeof (uint32_t);
	}

	if (buf->dtb_flags & DTRACEBUF_FILL) {
		if (offs + needed > buf->dtb_size - state->dts_reserve) {
			buf->dtb_flags |= DTRACEBUF_FULL;
			return -1;
		}
	}

	if (mstate == NULL)
		return offs;

	/*
	 * For ring buffers and fill buffers, the scratch space is always
	 * the inactive buffer.
	 */
	mstate->dtms_scratch_base = (uintptr_t)buf->dtb_xamot;
	mstate->dtms_scratch_size = buf->dtb_size;
	mstate->dtms_scratch_ptr = mstate->dtms_scratch_base;

	return offs;
}

void dtrace_buffer_polish(dtrace_buffer_t *buf)
{
	ASSERT(buf->dtb_flags & DTRACEBUF_RING);
	ASSERT(MUTEX_HELD(&dtrace_lock));

	if (!(buf->dtb_flags & DTRACEBUF_WRAPPED))
		return;

	/*
	 * We need to polish the ring buffer.  There are three cases:
	 *
	 * - The first (and presumably most common) is that there is no gap
	 *   between the buffer offset and the wrapped offset.  In this case,
	 *   there is nothing in the buffer that isn't valid data; we can
	 *   mark the buffer as polished and return.
	 *
	 * - The second (less common than the first but still more common
	 *   than the third) is that there is a gap between the buffer offset
	 *   and the wrapped offset, and the wrapped offset is larger than the
	 *   buffer offset.  This can happen because of an alignment issue, or
	 *   can happen because of a call to dtrace_buffer_reserve() that
	 *   didn't subsequently consume the buffer space.  In this case,
	 *   we need to zero the data from the buffer offset to the wrapped
	 *   offset.
	 *
	 * - The third (and least common) is that there is a gap between the
	 *   buffer offset and the wrapped offset, but the wrapped offset is
	 *   _less_ than the buffer offset.  This can only happen because a
	 *   call to dtrace_buffer_reserve() induced a wrap, but the space
	 *   was not subsequently consumed.  In this case, we need to zero the
	 *   space from the offset to the end of the buffer _and_ from the
	 *   top of the buffer to the wrapped offset.
	 */
	if (buf->dtb_offset < buf->dtb_xamot_offset)
		memset(buf->dtb_tomax + buf->dtb_offset, 0,
		       buf->dtb_xamot_offset - buf->dtb_offset);

	if (buf->dtb_offset > buf->dtb_xamot_offset) {
		memset(buf->dtb_tomax + buf->dtb_offset, 0,
		       buf->dtb_size - buf->dtb_offset);
		memset(buf->dtb_tomax, 0, buf->dtb_xamot_offset);
	}
}

void dtrace_buffer_free(dtrace_buffer_t *bufs)
{
	int	cpu;

	for_each_online_cpu(cpu) {
		dtrace_buffer_t	*buf = &bufs[cpu];

		if (buf->dtb_tomax == NULL) {
			ASSERT(buf->dtb_xamot == NULL);
			ASSERT(buf->dtb_size == 0);

			continue;
		}

		if (buf->dtb_xamot != NULL) {
			ASSERT(!(buf->dtb_flags & DTRACEBUF_NOSWITCH));

			vfree(buf->dtb_xamot);
			buf->dtb_xamot = NULL;
		}

		vfree(buf->dtb_tomax);
		buf->dtb_size = 0;
		buf->dtb_tomax = NULL;
	}
}
