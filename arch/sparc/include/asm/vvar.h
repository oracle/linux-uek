#ifndef _ASM_SPARC_VVAR_DATA_H
#define _ASM_SPARC_VVAR_DATA_H

#include <linux/clocksource.h>

struct vsyscall_gtod_data {
	seqcount_t	seq;

	int vclock_mode;
	struct { /* extract of a clocksource struct */
		cycle_t	cycle_last;
		cycle_t	mask;
		u32	mult;
		u32	shift;
	} clock;
	/* open coded 'struct timespec' */
	time_t		wall_time_sec;
	u64		wall_time_snsec;
	u64		monotonic_time_snsec;
	time_t		monotonic_time_sec;

	struct timezone sys_tz;
	struct timespec wall_time_coarse;
	struct timespec monotonic_time_coarse;
};

struct vvar_data {
	struct vsyscall_gtod_data gtod;
};

extern struct vvar_data *vvar_data;

#endif /* _ASM_SPARC_VVAR_DATA_H */
