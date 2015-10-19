/*
 * Copyright 2006 Andi Kleen, SUSE Labs.
 * Subject to the GNU Public License, v.2
 *
 * Fast user context implementation of clock_gettime, gettimeofday, and time.
 *
 * The code should have no internal unresolved relocations.
 * Check with readelf after changing.
 * Also alternative() doesn't work.
 */

/* Disable profiling for userspace code: */
#define DISABLE_BRANCH_PROFILING

#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/string.h>
#include <asm/vvar.h>
#include <asm/timex.h>
#include <asm/unistd.h>
#include <asm/io.h>

#define TICK_PRIV_BIT	(1UL << 63)

#define SYSCALL_STRING							\
	"ta	0x6d;"							\
	"bcc,pt	%%xcc, 1f;"						\
	"sub	%%g0, %%o0, %%o0;"					\
	"1:"

#define SYSCALL_CLOBBERS						\
	"f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",			\
	"f8", "f9", "f10", "f11", "f12", "f13", "f14", "f15",		\
	"f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23",		\
	"f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31",		\
	"f32", "f34", "f36", "f38", "f40", "f42", "f44", "f46",		\
	"f48", "f50", "f52", "f54", "f56", "f58", "f60", "f62",		\
	"cc", "memory"

/*
 * Compute the vvar page's address in the process address space, and return it
 * as a pointer to the vvar_data.
 */
notrace static inline struct vvar_data *
get_vvar_data(void)
{
	unsigned long ret;

	/*
	 * This horrible hack avoids taking the address of anything and thus
	 * generating a reference to a GOT that we don't have.
	 */
	ret = (unsigned long) current_text_addr();
	ret &= ~(PAGE_SIZE - 1);
	ret -= PAGE_SIZE;

	return (struct vvar_data *) ret;
}

notrace static long
vdso_fallback_gettime(long clock, struct timespec *ts)
{
	register long num __asm__("g1") = __NR_clock_gettime;
	register long o0 __asm__("o0") = clock;
	register long o1 __asm__("o1") = (long) ts;

	__asm__ __volatile__(SYSCALL_STRING : "=r" (o0) : "r" (num),
			     "0" (o0), "r" (o1) : SYSCALL_CLOBBERS);
	return o0;
}

notrace static __always_inline long
vdso_fallback_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	register long num __asm__("g1") = __NR_gettimeofday;
	register long o0 __asm__("o0") = (long) tv;
	register long o1 __asm__("o1") = (long) tz;

	__asm__ __volatile__(SYSCALL_STRING : "=r" (o0) : "r" (num),
			     "0" (o0), "r" (o1) : SYSCALL_CLOBBERS);
	return o0;
}

notrace static __always_inline long
vread_stick(void)
{
	long ret;

	__asm__ __volatile__("rd	%%asr24, %0"
			     : "=r" (ret));

	return ret & ~TICK_PRIV_BIT;
}

notrace static unsigned long long
vread_tick(void)
{
	unsigned long ret;

	__asm__ __volatile__("rd	%%tick, %0\n\t"
			     "mov	%0, %0"
			     : "=r" (ret));

	return ret & ~TICK_PRIV_BIT;
}

notrace static inline u64
vgetsns(struct vsyscall_gtod_data *gtod)
{
	long v;
	cycles_t cycles;

	switch (gtod->vclock_mode) {
	case VCLOCK_TICK:
		cycles = vread_tick();
		break;
	case VCLOCK_STICK:
		cycles = vread_stick();
		break;
	default:
		return 0;
	}
	v = (cycles - gtod->clock.cycle_last) & gtod->clock.mask;
	return v * gtod->clock.mult;
}

notrace static noinline int
do_realtime(struct vsyscall_gtod_data *gtod, struct timespec *ts)
{
	unsigned long seq;
	u64 ns;

	ts->tv_nsec = 0;
	do {
		seq = read_seqcount_begin(&gtod->seq);
		ts->tv_sec = gtod->wall_time_sec;
		ns = gtod->wall_time_snsec;
		ns += vgetsns(gtod);
		ns >>= gtod->clock.shift;
	} while (unlikely(read_seqcount_retry(&gtod->seq, seq)));

	timespec_add_ns(ts, ns);

	return 0;
}

notrace static noinline int
do_monotonic(struct vsyscall_gtod_data *gtod, struct timespec *ts)
{
	unsigned long seq;
	u64 ns;

	ts->tv_nsec = 0;
	do {
		seq = read_seqcount_begin(&gtod->seq);
		ts->tv_sec = gtod->monotonic_time_sec;
		ns = gtod->monotonic_time_snsec;
		ns += vgetsns(gtod);
		ns >>= gtod->clock.shift;
	} while (unlikely(read_seqcount_retry(&gtod->seq, seq)));

	timespec_add_ns(ts, ns);

	return 0;
}

notrace static noinline int
do_realtime_coarse(struct vsyscall_gtod_data *gtod, struct timespec *ts)
{
	unsigned long seq;
	do {
		seq = read_seqcount_begin(&gtod->seq);
		ts->tv_sec = gtod->wall_time_coarse.tv_sec;
		ts->tv_nsec = gtod->wall_time_coarse.tv_nsec;
	} while (unlikely(read_seqcount_retry(&gtod->seq, seq)));
	return 0;
}

notrace static noinline int
do_monotonic_coarse(struct vsyscall_gtod_data *gtod, struct timespec *ts)
{
	unsigned long seq;
	do {
		seq = read_seqcount_begin(&gtod->seq);
		ts->tv_sec = gtod->monotonic_time_coarse.tv_sec;
		ts->tv_nsec = gtod->monotonic_time_coarse.tv_nsec;
	} while (unlikely(read_seqcount_retry(&gtod->seq, seq)));

	return 0;
}

notrace int
__vdso_clock_gettime(clockid_t clock, struct timespec *ts)
{
	struct vvar_data *vvd = get_vvar_data();
	struct vsyscall_gtod_data *gtod = &vvd->gtod;

	switch (clock) {
	case CLOCK_REALTIME:
		if (unlikely(gtod->vclock_mode == VCLOCK_NONE))
			break;
		return do_realtime(gtod, ts);
	case CLOCK_MONOTONIC:
		if (unlikely(gtod->vclock_mode == VCLOCK_NONE))
			break;
		return do_monotonic(gtod, ts);
	case CLOCK_REALTIME_COARSE:
		return do_realtime_coarse(gtod, ts);
	case CLOCK_MONOTONIC_COARSE:
		return do_monotonic_coarse(gtod, ts);
	}
	/*
	 * Unknown clock ID ? Fall back to the syscall.
	 */
	return vdso_fallback_gettime(clock, ts);
}
int
clock_gettime(clockid_t, struct timespec *)
	__attribute__((weak, alias("__vdso_clock_gettime")));

notrace int
__vdso_gettimeofday(struct timeval *tv, struct timezone *tz)
{
	struct vvar_data *vvd = get_vvar_data();
	struct vsyscall_gtod_data *gtod = &vvd->gtod;

	if (likely(gtod->vclock_mode != VCLOCK_NONE)) {
		if (likely(tv != NULL)) {
			union tstv_t {
				struct timespec ts;
				struct timeval tv;
			} *tstv = (union tstv_t *) tv;
			do_realtime(gtod, &tstv->ts);
			/*
			 * Assign before dividing to ensure that the division is
			 * done in the type of tv_usec, not tv_nsec.
			 *
			 * There cannot be > 1 billion usec in a second:
			 * do_realtime() has already distributed such overflow
			 * into tv_sec.  So we can assign it to an int safely.
			 */
			tstv->tv.tv_usec = tstv->ts.tv_nsec;
			tstv->tv.tv_usec /= 1000;
		}
		if (unlikely(tz != NULL)) {
			/* Avoid memcpy. Some old compilers fail to inline it */
			tz->tz_minuteswest = gtod->sys_tz.tz_minuteswest;
			tz->tz_dsttime = gtod->sys_tz.tz_dsttime;
		}
		return 0;
	}
	return vdso_fallback_gettimeofday(tv, tz);
}
int
gettimeofday(struct timeval *, struct timezone *)
	__attribute__((weak, alias("__vdso_gettimeofday")));
