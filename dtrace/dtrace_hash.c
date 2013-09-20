/*
 * FILE:	dtrace_hash.c
 * DESCRIPTION:	Dynamic Tracing: probe hashing functions
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

#include <linux/slab.h>

#include "dtrace.h"

#define DTRACE_HASHSTR(hash, probe)	\
	dtrace_hash_str(*((char **)((uintptr_t)(probe) + (hash)->dth_stroffs)))
#define DTRACE_HASHEQ(hash, lhs, rhs)	\
	(strcmp(*((char **)((uintptr_t)(lhs) + (hash)->dth_stroffs)), \
		*((char **)((uintptr_t)(rhs) + (hash)->dth_stroffs))) == 0)

static uint_t dtrace_hash_str(char *p)
{
	uint_t	g;
	uint_t	hval = 0;

	while (*p) {
		hval = (hval << 4) + *p++;
		if ((g = (hval & 0xf0000000)) != 0)
			hval ^= g >> 24;

		hval &= ~g;
	}

	return hval;
}

dtrace_hash_t *dtrace_hash_create(uintptr_t stroffs, uintptr_t nextoffs,
				  uintptr_t prevoffs)
{
	dtrace_hash_t	*hash = kzalloc(sizeof(dtrace_hash_t), GFP_KERNEL);

	if (hash == NULL)
		return NULL;

	hash->dth_stroffs = stroffs;
	hash->dth_nextoffs = nextoffs;
	hash->dth_prevoffs = prevoffs;

	hash->dth_size = 1;
	hash->dth_mask = hash->dth_size - 1;

	hash->dth_tab = vzalloc(hash->dth_size *
				sizeof(dtrace_hashbucket_t *));

	if (hash->dth_tab == NULL) {
		kfree(hash);
		return NULL;
	}

	return hash;
}

void dtrace_hash_destroy(dtrace_hash_t *hash)
{
#ifdef DEBUG
	int	i;

	for (i = 0; i < hash->dth_size; i++)
		ASSERT(hash->dth_tab[i] == NULL);
#endif

	vfree(hash->dth_tab);
	kfree(hash);
}

static int dtrace_hash_resize(dtrace_hash_t *hash)
{
	int			size = hash->dth_size, i, ndx;
	int			new_size = hash->dth_size << 1;
	int			new_mask = new_size - 1;
	dtrace_hashbucket_t	**new_tab, *bucket, *next;

	ASSERT((new_size & new_mask) == 0);

	new_tab = vzalloc(new_size * sizeof(void *));
	if (new_tab == NULL)
		return -ENOMEM;

	for (i = 0; i < size; i++) {
		for (bucket = hash->dth_tab[i]; bucket != NULL;
		     bucket = next) {
			dtrace_probe_t *probe = bucket->dthb_chain;

			ASSERT(probe != NULL);
			ndx = DTRACE_HASHSTR(hash, probe) & new_mask;

			next = bucket->dthb_next;
			bucket->dthb_next = new_tab[ndx];
			new_tab[ndx] = bucket;
		}
	}

	vfree(hash->dth_tab);
	hash->dth_tab = new_tab;
	hash->dth_size = new_size;
	hash->dth_mask = new_mask;

	return 0;
}

int dtrace_hash_add(dtrace_hash_t *hash, dtrace_probe_t *new)
{
	int			hashval = DTRACE_HASHSTR(hash, new);
	int			ndx = hashval & hash->dth_mask;
	dtrace_hashbucket_t	*bucket = hash->dth_tab[ndx];
	dtrace_probe_t		**nextp, **prevp;

	for (; bucket != NULL; bucket = bucket->dthb_next) {
		if (DTRACE_HASHEQ(hash, bucket->dthb_chain, new))
			goto add;
	}

	if ((hash->dth_nbuckets >> 1) > hash->dth_size) {
		int	err = 0;

		if ((err = dtrace_hash_resize(hash)) != 0)
			return err;

		dtrace_hash_add(hash, new);
		return 0;
	}

	bucket = kzalloc(sizeof(dtrace_hashbucket_t), GFP_KERNEL);
	if (bucket == NULL)
		return -ENOMEM;

	bucket->dthb_next = hash->dth_tab[ndx];
	hash->dth_tab[ndx] = bucket;
	hash->dth_nbuckets++;

add:
	nextp = DTRACE_HASHNEXT(hash, new);

	ASSERT(*nextp == NULL && *(DTRACE_HASHPREV(hash, new)) == NULL);

	*nextp = bucket->dthb_chain;

	if (bucket->dthb_chain != NULL) {
		prevp = DTRACE_HASHPREV(hash, bucket->dthb_chain);

		ASSERT(*prevp == NULL);

		*prevp = new;
	}

	bucket->dthb_chain = new;
	bucket->dthb_len++;

	return 0;
}

dtrace_probe_t *dtrace_hash_lookup(dtrace_hash_t *hash,
				   dtrace_probe_t *template)
{
	int			hashval = DTRACE_HASHSTR(hash, template);
	int			ndx = hashval & hash->dth_mask;
	dtrace_hashbucket_t	*bucket = hash->dth_tab[ndx];

	for (; bucket != NULL; bucket = bucket->dthb_next) {
		if (DTRACE_HASHEQ(hash, bucket->dthb_chain, template))
			return bucket->dthb_chain;
	}

	return NULL;
}

/*
 * FIXME:
 * It would be more accurate to calculate a lookup cost based on the number
 * of buckets in the hash table slot, the length of the chain, and the length
 * of the string being looked up.
 * The hash tables can also be optimized by storing the hashval in each element
 * rather than always performing string comparisons.
 */
int dtrace_hash_collisions(dtrace_hash_t *hash, dtrace_probe_t *template)
{
	int			hashval = DTRACE_HASHSTR(hash, template);
	int			ndx = hashval & hash->dth_mask;
	dtrace_hashbucket_t	*bucket = hash->dth_tab[ndx];

	for (; bucket != NULL; bucket = bucket->dthb_next) {
		if (DTRACE_HASHEQ(hash, bucket->dthb_chain, template))
			return bucket->dthb_len;
	}

	return 0;
}

void dtrace_hash_remove(dtrace_hash_t *hash, dtrace_probe_t *probe)
{
	int			ndx = DTRACE_HASHSTR(hash, probe) &
				      hash->dth_mask;
	dtrace_hashbucket_t	*bucket = hash->dth_tab[ndx];
	dtrace_probe_t		**prevp = DTRACE_HASHPREV(hash, probe);
	dtrace_probe_t		**nextp = DTRACE_HASHNEXT(hash, probe);

	for (; bucket != NULL; bucket = bucket->dthb_next) {
		if (DTRACE_HASHEQ(hash, bucket->dthb_chain, probe))
			break;
	}

	ASSERT(bucket != NULL);

	if (*prevp == NULL) {
		if (*nextp == NULL) {
			/*
			 * This is the last probe in the bucket; we can remove
			 * the bucket.
			 */
			dtrace_hashbucket_t	*b = hash->dth_tab[ndx];

			ASSERT(bucket->dthb_chain == probe);
			ASSERT(b != NULL);

			if (b == bucket)
				hash->dth_tab[ndx] = bucket->dthb_next;
			else {
				while (b->dthb_next != bucket)
					b = b->dthb_next;

				b->dthb_next = bucket->dthb_next;
			}

			ASSERT(hash->dth_nbuckets > 0);

			hash->dth_nbuckets--;
			kfree(bucket);

			return;
		}

		bucket->dthb_chain = *nextp;
	} else
		*(DTRACE_HASHNEXT(hash, *prevp)) = *nextp;

	if (*nextp != NULL)
		*(DTRACE_HASHPREV(hash, *nextp)) = *prevp;
}
