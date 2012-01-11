/* Copyright (C) 2011 Oracle Corporation */

#ifndef _DTRACE_OS_H_
#define _DTRACE_OS_H_

#include <asm/unistd.h>

typedef uint32_t dtrace_id_t;

#define DTRACE_IDNONE 0

#define SCE_CLONE		0
#define SCE_FORK		1
#define SCE_VFORK		2
#define SCE_SIGALTSTACK		3
#define SCE_IOPL		4
#define SCE_EXECVE		5
#define SCE_RT_SIGRETURN	6
#define SCE_nr_stubs		7

extern void dtrace_enable(void);
extern void dtrace_disable(void);

extern void dtrace_invop_add(int (*func)(struct pt_regs *));
extern void dtrace_invop_remove(int (*func)(struct pt_regs *));

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
	dt_sys_call_t		stubs[SCE_nr_stubs];
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
