/*
 * Copyright (c) 2011, 2017, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _LINUX_DTRACE_SYSCALL_H_
#define _LINUX_DTRACE_SYSCALL_H_

#include <linux/types.h>
#include <linux/types.h>
#include <linux/dtrace_os.h>
#include <asm/syscall.h>

#define DTRACE_SYSCALL_STUB(t, n)      SCE_##t,
enum dtrace_sce_id {
        SCE_NONE = 0,
#include <asm/dtrace_syscall.h>
	SCE_nr_stubs
};
#undef DTRACE_SYSCALL_STUB

#define DTRACE_SYSCALL_STUB(t, n) \
	asmlinkage long dtrace_stub_##n(uintptr_t, uintptr_t, uintptr_t, \
					uintptr_t, uintptr_t, uintptr_t);
#include <asm/dtrace_syscall.h>
#undef DTRACE_SYSCALL_STUB

typedef asmlinkage long (*dt_sys_call_t)(uintptr_t, uintptr_t, uintptr_t,
					 uintptr_t, uintptr_t, uintptr_t);

typedef struct dtrace_syscalls {
	const char	*name;
	dtrace_id_t	stsy_entry;
	dtrace_id_t	stsy_return;
	dt_sys_call_t	stsy_underlying;
	dt_sys_call_t	*stsy_tblent;
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

#endif /* _LINUX_DTRACE_SYSCALL_H_ */
