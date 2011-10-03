/* Copyright (C) 2011 Oracle Corporation */

#ifndef _SYSTRACE_OS_H_
#define _SYSTRACE_OS_H_

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

#endif /* _SYSTRACE_OS_H_ */
