/*
 * FILE:	dtrace_probe_ctx.c
 * DESCRIPTION:	DTrace - probe context safe functions
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/dtrace_cpu.h>

#include "dtrace.h"

void dtrace_panic(const char *fmt, ...)
{
	va_list		alist;

	va_start(alist, fmt);
	vprintk(fmt, alist);
	va_end(alist);

	BUG();
}
EXPORT_SYMBOL(dtrace_panic);

int dtrace_assfail(const char *a, const char *f, int l)
{
	dtrace_panic(KERN_EMERG "assertion failed: %s, file: %s, line: %d",
		     a, f, l);

	/*
	 * FIXME: We can do better than this.  The OpenSolaris DTrace source
	 * states that this cannot be optimized away.
	 */
	return a[(uintptr_t)f];
}
EXPORT_SYMBOL(dtrace_assfail);

#define DT_MASK_LO	0x00000000FFFFFFFFULL

static void dtrace_add_128(uint64_t *addend1, uint64_t *addend2, uint64_t *sum)
{
	uint64_t	result[2];

	result[0] = addend1[0] + addend2[0];
	result[1] = addend1[1] + addend2[1] +
		    (result[0] < addend1[0] || result[0] < addend2[0] ? 1 : 0);

	sum[0] = result[0];
	sum[1] = result[1];
}

static void dtrace_shift_128(uint64_t *a, int b)
{
	uint64_t	mask;

	if (b == 0)
		return;

	if (b < 0) {
		b = -b;

		if (b >= 64) {
			a[0] = a[1] >> (b - 64);
			a[1] = 0;
		} else {
			a[0] >>= b;
			mask = 1LL << (64 - b);
			mask -= 1;
			a[0] |= ((a[1] & mask) << (64 - b));
			a[1] >>= b;
		}
	} else {
		if (b >= 64) {
			a[1] = a[0] << (b - 64);
			a[0] = 0;
		} else {
			a[1] <<= b;
			mask = a[0] >> (64 - b);
			a[1] |= mask;
			a[0] <<= b;
		}
	}
}

static void dtrace_multiply_128(uint64_t factor1, uint64_t factor2,
				uint64_t *product)
{
	uint64_t	hi1, hi2, lo1, lo2;
	uint64_t	tmp[2];

	hi1 = factor1 >> 32;
	hi2 = factor2 >> 32;

	lo1 = factor1 & DT_MASK_LO;
	lo2 = factor2 & DT_MASK_LO;

	product[0] = lo1 * lo2;
	product[1] = hi1 * hi2;

	tmp[0] = hi1 * lo2;
	tmp[1] = 0;
	dtrace_shift_128(tmp, 32);
	dtrace_add_128(product, tmp, product);

	tmp[0] = hi2 * lo1;
	tmp[1] = 0;
	dtrace_shift_128(tmp, 32);
	dtrace_add_128(product, tmp, product);
}

void dtrace_aggregate_min(uint64_t *oval, uint64_t nval, uint64_t arg)
{
	if ((int64_t)nval < (int64_t)*oval)
		*oval = nval;
}

void dtrace_aggregate_max(uint64_t *oval, uint64_t nval, uint64_t arg)
{
	if ((int64_t)nval > (int64_t)*oval)
		*oval = nval;
}

void dtrace_aggregate_quantize(uint64_t *quanta, uint64_t nval, uint64_t incr)
{
	int	i, zero = DTRACE_QUANTIZE_ZEROBUCKET;
	int64_t	val = (int64_t)nval;

	if (val < 0) {
		for (i = 0; i < zero; i++) {
			if (val <= DTRACE_QUANTIZE_BUCKETVAL(i)) {
				quanta[i] += incr;

				return;
			}
		}
	} else {
		for (i = zero + 1; i < DTRACE_QUANTIZE_NBUCKETS; i++) {
			if (val < DTRACE_QUANTIZE_BUCKETVAL(i)) {
				quanta[i - 1] += incr;

				return;
			}
		}

		quanta[DTRACE_QUANTIZE_NBUCKETS - 1] += incr;

		return;
	}

	ASSERT(0);
}

void dtrace_aggregate_lquantize(uint64_t *lquanta, uint64_t nval,
				uint64_t incr)
{
	uint64_t	arg = *lquanta++;
	int32_t		base = DTRACE_LQUANTIZE_BASE(arg);
	uint16_t	step = DTRACE_LQUANTIZE_STEP(arg);
	uint16_t	levels = DTRACE_LQUANTIZE_LEVELS(arg);
	int32_t		val = (int32_t)nval, level;

	ASSERT(step != 0);
	ASSERT(levels != 0);

	if (val < base) {
		lquanta[0] += incr;

		return;
	}

	level = (val - base) / step;

	if (level < levels) {
		lquanta[level + 1] += incr;

		return;
	}

	lquanta[levels + 1] += incr;
}

void dtrace_aggregate_avg(uint64_t *data, uint64_t nval, uint64_t arg)
{
	data[0]++;
	data[1] += nval;
}

void dtrace_aggregate_stddev(uint64_t *data, uint64_t nval, uint64_t arg)
{
	int64_t		snval = (int64_t)nval;
	uint64_t	tmp[2];

	data[0]++;
	data[1] += nval;

	if (snval < 0)
		snval = -snval;

	dtrace_multiply_128((uint64_t)snval, (uint64_t)snval, tmp);
	dtrace_add_128(data + 2, tmp, data + 2);
}

void dtrace_aggregate_count(uint64_t *oval, uint64_t nval, uint64_t arg)
{
	*oval = *oval + 1;
}

void dtrace_aggregate_sum(uint64_t *oval, uint64_t nval, uint64_t arg)
{
	*oval += nval;
}

/*
 * DTrace Aggregation Buffers
 *
 * Aggregation buffers use much of the same mechanism as described above
 * ("DTrace Buffers").  However, because an aggregation is fundamentally a
 * hash, there exists dynamic metadata associated with an aggregation buffer
 * that is not associated with other kinds of buffers.  This aggregation
 * metadata is _only_ relevant for the in-kernel implementation of
 * aggregations; it is not actually relevant to user-level consumers.  To do
 * this, we allocate dynamic aggregation data (hash keys and hash buckets)
 * starting below the _limit_ of the buffer, and we allocate data from the
 * _base_ of the buffer.  When the aggregation buffer is copied out, _only_ the
 * data is copied out; the metadata is simply discarded.  Schematically,
 * aggregation buffers look like:
 *
 *      base of data buffer --->  +-------+------+-----------+-------+
 *                                | aggid | key  | value     | aggid |
 *                                +-------+------+-----------+-------+
 *                                | key                              |
 *                                +-------+-------+-----+------------+
 *                                | value | aggid | key | value      |
 *                                +-------+------++-----+------+-----+
 *                                | aggid | key  | value       |     |
 *                                +-------+------+-------------+     |
 *                                |                ||                |
 *                                |                ||                |
 *                                |                \/                |
 *                                :                                  :
 *                                .                                  .
 *                                .                                  .
 *                                .                                  .
 *                                :                                  :
 *                                |                /\                |
 *                                |                ||   +------------+
 *                                |                ||   |            |
 *                                +---------------------+            |
 *                                | hash keys                        |
 *                                | (dtrace_aggkey structures)       |
 *                                |                                  |
 *                                +----------------------------------+
 *                                | hash buckets                     |
 *                                | (dtrace_aggbuffer structure)     |
 *                                |                                  |
 *     limit of data buffer --->  +----------------------------------+
 *
 * As implied above, just as we assure that ECBs always store a constant
 * amount of data, we assure that a given aggregation -- identified by its
 * aggregation ID -- always stores data of a constant quantity and type.
 * As with EPIDs, this allows the aggregation ID to serve as the metadata for a
 * given record.
 *
 * Note that the size of the dtrace_aggkey structure must be sizeof (uintptr_t)
 * aligned.  (If this the structure changes such that this becomes false, an
 * assertion will fail in dtrace_aggregate().)
 */
#define DTRACE_AGGHASHSIZE_SLEW		17

typedef struct dtrace_aggkey {
	uint32_t dtak_hashval;			/* hash value */
	uint32_t dtak_action:4;			/* action -- 4 bits */
	uint32_t dtak_size:28;			/* size -- 28 bits */
	caddr_t dtak_data;			/* data pointer */
	struct dtrace_aggkey *dtak_next;	/* next in hash chain */
} dtrace_aggkey_t;

typedef struct dtrace_aggbuffer {
	uintptr_t dtagb_hashsize;		/* number of buckets */
	uintptr_t dtagb_free;			/* free list of keys */
	dtrace_aggkey_t **dtagb_hash;		/* hash table */
} dtrace_aggbuffer_t;

#define DTRACEACT_ISSTRING(act)						      \
	((act)->dta_kind == DTRACEACT_DIFEXPR &&			      \
	 (act)->dta_difo->dtdo_rtype.dtdt_kind == DIF_TYPE_STRING)

/*
 * Aggregate given the tuple in the principal data buffer, and the aggregating
 * action denoted by the specified dtrace_aggregation_t.  The aggregation
 * buffer is specified as the buf parameter.  This routine does not return
 * failure; if there is no space in the aggregation buffer, the data will be
 * dropped, and a corresponding counter incremented.
 */
void dtrace_aggregate(dtrace_aggregation_t *agg, dtrace_buffer_t *dbuf,
		      intptr_t offset, dtrace_buffer_t *buf, uint64_t expr,
		      uint64_t arg)
{
	dtrace_recdesc_t	*rec = &agg->dtag_action.dta_rec;
	uint32_t		i, ndx, size, fsize;
	uint32_t		align = sizeof (uint64_t) - 1;
	dtrace_aggbuffer_t	*agb;
	dtrace_aggkey_t		*key;
	uint32_t		hashval = 0, limit, isstr;
	caddr_t			tomax, data, kdata;
	dtrace_actkind_t	action;
	dtrace_action_t		*act;
	uintptr_t		offs;

	if (buf == NULL)
		return;

	if (!agg->dtag_hasarg)
		/*
		 * Currently, only quantize() and lquantize() take additional
		 * arguments, and they have the same semantics:  an increment
		 * value that defaults to 1 when not present.  If additional
		 * aggregating actions take arguments, the setting of the
		 * default argument value will presumably have to become more
		 * sophisticated...
		 */
		arg = 1;

	action = agg->dtag_action.dta_kind - DTRACEACT_AGGREGATION;
	size = rec->dtrd_offset - agg->dtag_base;
	fsize = size + rec->dtrd_size;

	ASSERT(dbuf->dtb_tomax != NULL);
	data = dbuf->dtb_tomax + offset + agg->dtag_base;

	if ((tomax = buf->dtb_tomax) == NULL) {
		dtrace_buffer_drop(buf);
		return;
	}

	/*
	 * The metastructure is always at the bottom of the buffer.
	 */
	agb = (dtrace_aggbuffer_t *)(tomax + buf->dtb_size -
					     sizeof (dtrace_aggbuffer_t));

	if (buf->dtb_offset == 0) {
		/*
		 * We just kludge up approximately 1/8th of the size to be
		 * buckets.  If this guess ends up being routinely
		 * off-the-mark, we may need to dynamically readjust this
		 * based on past performance.
		 */
		uintptr_t	hashsize = (buf->dtb_size >> 3) /
					   sizeof (uintptr_t);

		if ((uintptr_t)agb - hashsize * sizeof (dtrace_aggkey_t *) <
		    (uintptr_t)tomax || hashsize == 0) {
			/*
			 * We've been given a ludicrously small buffer;
			 * increment our drop count and leave.
			 */
			dtrace_buffer_drop(buf);
			return;
		}

		/*
		 * And now, a pathetic attempt to try to get a an odd (or
		 * perchance, a prime) hash size for better hash distribution.
		 */
		if (hashsize > (DTRACE_AGGHASHSIZE_SLEW << 3))
			hashsize -= DTRACE_AGGHASHSIZE_SLEW;

		agb->dtagb_hashsize = hashsize;
		agb->dtagb_hash = (dtrace_aggkey_t **)((uintptr_t)agb -
		agb->dtagb_hashsize * sizeof (dtrace_aggkey_t *));
		agb->dtagb_free = (uintptr_t)agb->dtagb_hash;

		for (i = 0; i < agb->dtagb_hashsize; i++)
			agb->dtagb_hash[i] = NULL;
	}

	ASSERT(agg->dtag_first != NULL);
	ASSERT(agg->dtag_first->dta_intuple);

	/*
	 * Calculate the hash value based on the key.  Note that we _don't_
	 * include the aggid in the hashing (but we will store it as part of
	 * the key).  The hashing algorithm is Bob Jenkins' "One-at-a-time"
	 * algorithm: a simple, quick algorithm that has no known funnels, and
	 * gets good distribution in practice.  The efficacy of the hashing
	 * algorithm (and a comparison with other algorithms) may be found by
	 * running the ::dtrace_aggstat MDB dcmd.
	 */
	for (act = agg->dtag_first; act->dta_intuple; act = act->dta_next) {
		i = act->dta_rec.dtrd_offset - agg->dtag_base;
		limit = i + act->dta_rec.dtrd_size;
		ASSERT(limit <= size);
		isstr = DTRACEACT_ISSTRING(act);

		for (; i < limit; i++) {
			hashval += data[i];
			hashval += (hashval << 10);
			hashval ^= (hashval >> 6);

			if (isstr && data[i] == '\0')
				break;
		}
	}

	hashval += (hashval << 3);
	hashval ^= (hashval >> 11);
	hashval += (hashval << 15);

	/*
	 * Yes, the divide here is expensive -- but it's generally the least
	 * of the performance issues given the amount of data that we iterate
	 * over to compute hash values, compare data, etc.
	 */
	ndx = hashval % agb->dtagb_hashsize;

	for (key = agb->dtagb_hash[ndx]; key != NULL; key = key->dtak_next) {
		ASSERT((caddr_t)key >= tomax);
		ASSERT((caddr_t)key < tomax + buf->dtb_size);

		if (hashval != key->dtak_hashval || key->dtak_size != size)
			continue;

		kdata = key->dtak_data;
		ASSERT(kdata >= tomax && kdata < tomax + buf->dtb_size);

		for (act = agg->dtag_first; act->dta_intuple;
		     act = act->dta_next) {
			i = act->dta_rec.dtrd_offset - agg->dtag_base;
			limit = i + act->dta_rec.dtrd_size;
			ASSERT(limit <= size);
			isstr = DTRACEACT_ISSTRING(act);

			for (; i < limit; i++) {
				if (kdata[i] != data[i])
					goto next;

				if (isstr && data[i] == '\0')
					break;
			}
		}

		if (action != key->dtak_action) {
			/*
			 * We are aggregating on the same value in the same
			 * aggregation with two different aggregating actions.
			 * (This should have been picked up in the compiler,
			 * so we may be dealing with errant or devious DIF.)
			 * This is an error condition; we indicate as much,
			 * and return.
			 */
			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);
			return;
		}

		/*
		 * This is a hit:  we need to apply the aggregator to
		 * the value at this key.
		 */
		dt_dbg_agg("    Aggregate [accum]: Buf %p, offs %d, act %d, "
			   "%lld (%lld, %lld)\n",
			   buf, size,
			   agg->dtag_action.dta_kind - DTRACEACT_AGGREGATION,
			   *(uint64_t *)(kdata + size), expr, arg);
		agg->dtag_aggregate((uint64_t *)(kdata + size), expr, arg);
		return;
next:
		continue;
	}

	/*
	 * We didn't find it.  We need to allocate some zero-filled space,
	 * link it into the hash table appropriately, and apply the aggregator
	 * to the (zero-filled) value.
	 */
	offs = buf->dtb_offset;
	while (offs & (align - 1))
		offs += sizeof (uint32_t);

	/*
	 * If we don't have enough room to both allocate a new key _and_
	 * its associated data, increment the drop count and return.
	 */
	if ((uintptr_t)tomax + offs + fsize >
	    agb->dtagb_free - sizeof (dtrace_aggkey_t)) {
		dtrace_buffer_drop(buf);
		return;
	}

	ASSERT(!(sizeof (dtrace_aggkey_t) & (sizeof (uintptr_t) - 1)));
	key = (dtrace_aggkey_t *)(agb->dtagb_free - sizeof (dtrace_aggkey_t));
	agb->dtagb_free -= sizeof (dtrace_aggkey_t);

	key->dtak_data = kdata = tomax + offs;
	buf->dtb_offset = offs + fsize;

	/*
	 * Now copy the data across.
	 */
	*((dtrace_aggid_t *)kdata) = agg->dtag_id;

	for (i = sizeof (dtrace_aggid_t); i < size; i++)
		kdata[i] = data[i];

	/*
	 * Because strings are not zeroed out by default, we need to iterate
	 * looking for actions that store strings, and we need to explicitly
	 * pad these strings out with zeroes.
	 */
	for (act = agg->dtag_first; act->dta_intuple; act = act->dta_next) {
		int	nul;

		if (!DTRACEACT_ISSTRING(act))
			continue;

		i = act->dta_rec.dtrd_offset - agg->dtag_base;
		limit = i + act->dta_rec.dtrd_size;
		ASSERT(limit <= size);

		for (nul = 0; i < limit; i++) {
			if (nul) {
				kdata[i] = '\0';
				continue;
			}

			if (data[i] != '\0')
				continue;

			nul = 1;
		}
	}

	for (i = size; i < fsize; i++)
		kdata[i] = 0;

	key->dtak_hashval = hashval;
	key->dtak_size = size;
	key->dtak_action = action;
	key->dtak_next = agb->dtagb_hash[ndx];
	agb->dtagb_hash[ndx] = key;

	/*
	 * Finally, apply the aggregator.
	 */
	*((uint64_t *)(key->dtak_data + size)) = agg->dtag_initial;
	dt_dbg_agg("    Aggregate [initial]: Buf %p, offs %d, act %d, "
	           "%lld (%lld, %lld)\n",
	           buf, size,
	           agg->dtag_action.dta_kind - DTRACEACT_AGGREGATION,
	           *(uint64_t *)(key->dtak_data + size), expr, arg);
	agg->dtag_aggregate((uint64_t *)(key->dtak_data + size), expr, arg);
}
