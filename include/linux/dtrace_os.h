/* Copyright (C) 2011 Oracle Corporation */

#ifndef _DTRACE_OS_H_
#define _DTRACE_OS_H_

#include <asm/unistd.h>

typedef uint32_t dtrace_id_t;

#define DTRACE_IDNONE 0

typedef void (*sys_call_ptr_t)(void);
typedef long (*dt_sys_call_t)(uintptr_t, uintptr_t, uintptr_t, uintptr_t,
			      uintptr_t, uintptr_t);

typedef struct dtrace_syscalls {
	const char	*name;
	dtrace_id_t	stsy_entry;
	dtrace_id_t	stsy_return;
	dt_sys_call_t	stsy_underlying;
	sys_call_ptr_t	*stsy_tblent;
} dtrace_syscalls_t;

typedef void (*dtrace_systrace_probe_t)(dtrace_id_t, uintptr_t, uintptr_t,
					uintptr_t, uintptr_t, uintptr_t,
					uintptr_t);

typedef struct systrace_info {
	dtrace_systrace_probe_t	*probep;
	dtrace_systrace_probe_t	stub;
	dt_sys_call_t		syscall;
	dtrace_syscalls_t	sysent[NR_syscalls];
} systrace_info_t;

extern systrace_info_t *dtrace_syscalls_init(void);

#define STACKTRACE_KERNEL	0x01
#define STACKTRACE_USER		0x02
#define STACKTRACE_SKIP		0x10

typedef struct stacktrace_state {
	uint64_t	*pcs;
	uint64_t	*fps;
	int		limit;
	int		depth;
	int		flags;
} stacktrace_state_t;

extern void dtrace_stacktrace(stacktrace_state_t *);

#endif /* _DTRACE_OS_H_ */
