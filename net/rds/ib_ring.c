/*
 * Copyright (c) 2006, 2023, Oracle and/or its affiliates.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
#include <linux/atomic.h>
#include <linux/kernel.h>

#include "rds.h"
#include "ib.h"

/*
 * Locking for IB rings.
 * We assume that allocation is always protected by a mutex
 * in the caller (this is a valid assumption for the current
 * implementation).
 *
 * Freeing always happens in an interrupt, and hence only
 * races with allocations, but not with other free()s.
 *
 * The interaction between allocation and freeing is that the alloc
 * code has to determine the number of free entries.  To this end, we
 * maintain two free-running counters; an allocation counter and a
 * free counter.
 *
 * The number of used entries is always (alloc_ctr - free_ctr) % NR.
 *
 * When the caller finds an allocation fails, it should set an "alloc
 * fail" bit and retry the allocation. The "alloc fail" bit
 * essentially tells the CQ completion handlers to wake it up after
 * freeing some more entries.
 */

/*
 * This only happens on shutdown.
 */
DECLARE_WAIT_QUEUE_HEAD(rds_ib_ring_empty_wait);

void rds_ib_ring_init(struct rds_ib_work_ring *ring, u32 nr)
{
	memset(ring, 0, sizeof(*ring));
	ring->w_nr = nr;
	rdsdebug("ring %p nr %u\n", ring, ring->w_nr);
}

static inline u32 __rds_ib_ring_used(struct rds_ib_work_ring *ring)
{
	return (u64)atomic64_read(&ring->w_alloc_ctr) - (u64)atomic64_read(&ring->w_free_ctr);
}

void rds_ib_ring_resize(struct rds_ib_work_ring *ring, u32 nr)
{
	/* We only ever get called from the connection setup code,
	 * prior to creating the QP. */
	BUG_ON(__rds_ib_ring_used(ring));
	ring->w_nr = nr;
}

static int __rds_ib_ring_empty(struct rds_ib_work_ring *ring)
{
	return __rds_ib_ring_used(ring) == 0;
}

u32 rds_ib_ring_alloc(struct rds_ib_work_ring *ring, u32 val, u32 *pos)
{
	u32 ret = 0, avail;

	avail = ring->w_nr - __rds_ib_ring_used(ring);

	if (val && avail) {
		u64 new_ctr;

		ret = min(val, avail);
		new_ctr = (u64)atomic64_add_return(ret, &ring->w_alloc_ctr);
		*pos = (new_ctr - ret) % ring->w_nr;
	}

	return ret;
}

void rds_ib_ring_free(struct rds_ib_work_ring *ring, u32 val)
{
	smp_mb__before_atomic();
	atomic64_add(val, &ring->w_free_ctr);
	smp_mb__after_atomic();

}

void rds_ib_ring_unalloc(struct rds_ib_work_ring *ring, u32 val)
{
	smp_mb__before_atomic();
	atomic64_sub(val, &ring->w_alloc_ctr);
	smp_mb__after_atomic();
}

int rds_ib_ring_empty(struct rds_ib_work_ring *ring)
{
	return __rds_ib_ring_empty(ring);
}

int rds_ib_ring_low(struct rds_ib_work_ring *ring)
{
	return __rds_ib_ring_used(ring) <= ring->w_nr * rds_ib_sysctl_ring_low_permille / 1000;
}

int rds_ib_ring_mid(struct rds_ib_work_ring *ring)
{
	return __rds_ib_ring_used(ring) <= ring->w_nr * rds_ib_sysctl_ring_mid_permille / 1000;
}

/*
 * returns the oldest alloced ring entry.  This will be the next one
 * freed.  This can't be called if there are none allocated.
 */
u32 rds_ib_ring_oldest(struct rds_ib_work_ring *ring)
{
	return (u64)atomic64_read(&ring->w_free_ctr) % ring->w_nr;
}

/*
 * returns the number of completed work requests.
 */

u32 rds_ib_ring_completed(struct rds_ib_work_ring *ring, u32 wr_id, u32 oldest)
{
	u32 ret;

	if (oldest <= (unsigned long long)wr_id)
		ret = (unsigned long long)wr_id - oldest + 1;
	else
		ret = ring->w_nr - oldest + (unsigned long long)wr_id + 1;

	rdsdebug("ring %p ret %u wr_id %u oldest %u\n", ring, ret,
		 wr_id, oldest);
	return ret;
}
