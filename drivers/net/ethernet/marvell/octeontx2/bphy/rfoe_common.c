// SPDX-License-Identifier: GPL-2.0
/* Marvell CNF10K BPHY RFOE Netdev Driver
 *
 * Copyright (C) 2024 Marvell.
 */

#include "rfoe_common.h"

#define MAX_PSM_QUEUES 12

struct psm_queue_lock {
	/*  PSM queue lock  */
	spinlock_t	lock;
	u8		psm_queue_id;
	bool		valid;
};

static struct psm_queue_lock psm_queue_locks[MAX_PSM_QUEUES];

static struct psm_queue_lock *get_psm_queue_lock(u8 psm_queue_id)
{
	int index;
	struct psm_queue_lock *lock;

	for (index = 0; index < MAX_PSM_QUEUES; index++) {
		lock = &psm_queue_locks[index];
		if (psm_queue_id == lock->psm_queue_id &&
		    lock->valid) {
			return lock;
		}
	}

	return NULL;
}

spinlock_t *rfoe_common_get_psm_queue_lock(u8 psm_queue_id)
{
	int index;
	struct psm_queue_lock *lock;

	lock = get_psm_queue_lock(psm_queue_id);

	if (lock)
		return &lock->lock;

	for (index = 0; index < MAX_PSM_QUEUES; index++) {
		lock = &psm_queue_locks[index];

		if (!lock->valid) {
			spin_lock_init(&lock->lock);
			lock->psm_queue_id = psm_queue_id;
			lock->valid = true;
			return &lock->lock;
		}
	}

	return NULL;
}
