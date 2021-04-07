// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 Google, Inc.
 *
 * Author:
 *	Sami Tolvanen <samitolvanen@google.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#define pr_fmt(fmt)	"pgo: " fmt

#include <linux/bitops.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include "pgo.h"

/*
 * This lock guards both profile count updating and serialization of the
 * profiling data. Keeping both of these activities separate via locking
 * ensures that we don't try to serialize data that's only partially updated.
 */
static DEFINE_SPINLOCK(pgo_lock);
static int current_node;

unsigned long prf_lock(void)
{
	unsigned long flags;

	spin_lock_irqsave(&pgo_lock, flags);

	return flags;
}

void prf_unlock(unsigned long flags)
{
	spin_unlock_irqrestore(&pgo_lock, flags);
}

/*
 * Return a newly allocated profiling value node which contains the tracked
 * value by the value profiler.
 * Note: caller *must* hold pgo_lock.
 */
static struct llvm_prf_value_node *allocate_node(struct llvm_prf_data *p,
						 u32 index, u64 value)
{
	if (&__llvm_prf_vnds_start[current_node + 1] >= __llvm_prf_vnds_end)
		return NULL; /* Out of nodes */

	current_node++;

	/* Make sure the node is entirely within the section */
	if (&__llvm_prf_vnds_start[current_node] >= __llvm_prf_vnds_end ||
	    &__llvm_prf_vnds_start[current_node + 1] > __llvm_prf_vnds_end)
		return NULL;

	return &__llvm_prf_vnds_start[current_node];
}

/*
 * Counts the number of times a target value is seen.
 *
 * Records the target value for the index if not seen before. Otherwise,
 * increments the counter associated w/ the target value.
 */
void __llvm_profile_instrument_target(u64 target_value, void *data, u32 index)
{
	struct llvm_prf_data *p = (struct llvm_prf_data *)data;
	struct llvm_prf_value_node **counters;
	struct llvm_prf_value_node *curr;
	struct llvm_prf_value_node *min = NULL;
	struct llvm_prf_value_node *prev = NULL;
	u64 min_count = U64_MAX;
	u8 values = 0;
	unsigned long flags;

	if (!p || !p->values)
		return;

	counters = (struct llvm_prf_value_node **)p->values;
	curr = counters[index];

	while (curr) {
		if (target_value == curr->value) {
			curr->count++;
			return;
		}

		if (curr->count < min_count) {
			min_count = curr->count;
			min = curr;
		}

		prev = curr;
		curr = curr->next;
		values++;
	}

	if (values >= LLVM_INSTR_PROF_MAX_NUM_VAL_PER_SITE) {
		if (!min->count || !(--min->count)) {
			curr = min;
			curr->value = target_value;
			curr->count++;
		}
		return;
	}

	/* Lock when updating the value node structure. */
	flags = prf_lock();

	curr = allocate_node(p, index, target_value);
	if (!curr)
		goto out;

	curr->value = target_value;
	curr->count++;

	if (!counters[index])
		counters[index] = curr;
	else if (prev && !prev->next)
		prev->next = curr;

out:
	prf_unlock(flags);
}
EXPORT_SYMBOL(__llvm_profile_instrument_target);

/* Counts the number of times a range of targets values are seen. */
void __llvm_profile_instrument_range(u64 target_value, void *data,
				     u32 index, s64 precise_start,
				     s64 precise_last, s64 large_value)
{
	if (large_value != S64_MIN && (s64)target_value >= large_value)
		target_value = large_value;
	else if ((s64)target_value < precise_start ||
		 (s64)target_value > precise_last)
		target_value = precise_last + 1;

	__llvm_profile_instrument_target(target_value, data, index);
}
EXPORT_SYMBOL(__llvm_profile_instrument_range);

static u64 inst_prof_get_range_rep_value(u64 value)
{
	if (value <= 8)
		/* The first ranges are individually tracked, use it as is. */
		return value;
	else if (value >= 513)
		/* The last range is mapped to its lowest value. */
		return 513;
	else if (hweight64(value) == 1)
		/* If it's a power of two, use it as is. */
		return value;

	/* Otherwise, take to the previous power of two + 1. */
	return ((u64)1 << (64 - __builtin_clzll(value) - 1)) + 1;
}

/*
 * The target values are partitioned into multiple ranges. The range spec is
 * defined in compiler-rt/include/profile/InstrProfData.inc.
 */
void __llvm_profile_instrument_memop(u64 target_value, void *data,
				     u32 counter_index)
{
	u64 rep_value;

	/* Map the target value to the representative value of its range. */
	rep_value = inst_prof_get_range_rep_value(target_value);
	__llvm_profile_instrument_target(rep_value, data, counter_index);
}
EXPORT_SYMBOL(__llvm_profile_instrument_memop);
