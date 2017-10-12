/*
 * Queued read/write locks
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
 *
 * (C) Copyright 2013-2014 Hewlett-Packard Development Company, L.P.
 *
 * Authors: Waiman Long <waiman.long@hp.com>
 */
#include <linux/smp.h>
#include <linux/bug.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/hardirq.h>
#include <linux/sdt.h>
#include <linux/spinlock.h>
#include <asm/qrwlock.h>

/*
 * This internal data structure is used for optimizing access to some of
 * the subfields within the atomic_t cnts.
 */
struct __qrwlock {
	union {
		atomic_t cnts;
		struct {
#ifdef __LITTLE_ENDIAN
			u8 wlocked;	/* Locked for write? */
			u8 __lstate[3];
#else
			u8 __lstate[3];
			u8 wlocked;	/* Locked for write? */
#endif
		};
	};
	arch_spinlock_t	lock;
};

/**
 * queued_read_lock_slowpath - acquire read lock of a queue rwlock
 * @lock: Pointer to queue rwlock structure
 */
void queued_read_lock_slowpath(struct qrwlock *lock)
{
	u64 spinstart = 0, spinend, spintime;

	/*
	 * Readers come here when they cannot get the lock without waiting
	 */
	if (DTRACE_LOCKSTAT_ENABLED(rw__spin))
		spinstart = dtrace_gethrtime_ns();
	if (unlikely(in_interrupt())) {
		/*
		 * Readers in interrupt context will get the lock immediately
		 * if the writer is just waiting (not holding the lock yet),
		 * so spin with ACQUIRE semantics until the lock is available
		 * without waiting in the queue.
		 */
		atomic_cond_read_acquire(&lock->cnts, !(VAL & _QW_LOCKED));
		goto done;
	}
	atomic_sub(_QR_BIAS, &lock->cnts);

	/*
	 * Put the reader into the wait queue
	 */
	arch_spin_lock(&lock->wait_lock);
	atomic_add(_QR_BIAS, &lock->cnts);

	/*
	 * The ACQUIRE semantics of the following spinning code ensure
	 * that accesses can't leak upwards out of our subsequent critical
	 * section in the case that the lock is currently held for write.
	 */
	atomic_cond_read_acquire(&lock->cnts, !(VAL & _QW_LOCKED));

	/*
	 * Signal the next one in queue to become queue head
	 */
	arch_spin_unlock(&lock->wait_lock);
done:
	if (DTRACE_LOCKSTAT_ENABLED(rw__spin) && spinstart) {
		spinend = dtrace_gethrtime_ns();
		spintime = spinend > spinstart ? spinend - spinstart : 0;
		DTRACE_LOCKSTAT(rw__spin, rwlock_t *, lock, uint64_t, spintime,
				int, DTRACE_LOCKSTAT_RW_READER);
	}
}
EXPORT_SYMBOL(queued_read_lock_slowpath);

/**
 * queued_write_lock_slowpath - acquire write lock of a queue rwlock
 * @lock : Pointer to queue rwlock structure
 */
void queued_write_lock_slowpath(struct qrwlock *lock)
{
	u64 spinstart = 0, spinend, spintime;

	/* Put the writer into the wait queue */
	if (DTRACE_LOCKSTAT_ENABLED(rw__spin))
		spinstart = dtrace_gethrtime_ns();
	arch_spin_lock(&lock->wait_lock);

	/* Try to acquire the lock directly if no reader is present */
	if (!atomic_read(&lock->cnts) &&
	    (atomic_cmpxchg_acquire(&lock->cnts, 0, _QW_LOCKED) == 0))
		goto unlock;

	/* Set the waiting flag to notify readers that a writer is pending */
	atomic_add(_QW_WAITING, &lock->cnts);

	/* When no more readers or writers, set the locked flag */
	do {
		atomic_cond_read_acquire(&lock->cnts, VAL == _QW_WAITING);
	} while (atomic_cmpxchg_relaxed(&lock->cnts, _QW_WAITING,
					_QW_LOCKED) != _QW_WAITING);
unlock:
	arch_spin_unlock(&lock->wait_lock);
	if (DTRACE_LOCKSTAT_ENABLED(rw__spin) && spinstart) {
		spinend = dtrace_gethrtime_ns();
		spintime = spinend > spinstart ? spinend - spinstart : 0;
		DTRACE_LOCKSTAT(rw__spin, rwlock_t *, lock, uint64_t, spintime,
				int, DTRACE_LOCKSTAT_RW_WRITER);
	}
}
EXPORT_SYMBOL(queued_write_lock_slowpath);
