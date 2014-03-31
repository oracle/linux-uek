/* Copyright (C) 2011, 2012, 2013 Oracle, Inc. */

#ifndef _LINUX_DTRACE_OS_H_
#define _LINUX_DTRACE_OS_H_

typedef uint32_t dtrace_id_t;

#ifndef HEADERS_CHECK

#ifdef CONFIG_DTRACE

#include <linux/uprobes.h>
#include <asm/asm-offsets.h>
#include <linux/dtrace_cpu.h>

#define DTRACE_IDNONE 0

#define SCE_CLONE		0
#define SCE_FORK		1
#define SCE_VFORK		2
#define SCE_SIGALTSTACK		3
#define SCE_IOPL		4
#define SCE_EXECVE		5
#define SCE_RT_SIGRETURN	6
#define SCE_nr_stubs		7

extern struct module	*dtrace_kmod;

extern void dtrace_os_init(void);
extern void dtrace_os_exit(void);

extern void dtrace_enable(void);
extern void dtrace_disable(void);

extern ktime_t dtrace_gethrtime(void);
extern ktime_t dtrace_getwalltime(void);

typedef enum dtrace_vtime_state {
	DTRACE_VTIME_INACTIVE = 0,
	DTRACE_VTIME_ACTIVE
} dtrace_vtime_state_t;

extern dtrace_vtime_state_t dtrace_vtime_active;

extern void dtrace_vtime_enable(void);
extern void dtrace_vtime_disable(void);
extern void dtrace_vtime_switch(struct task_struct *, struct task_struct *);

extern int dtrace_invop_add(uint8_t (*func)(struct pt_regs *));
extern void dtrace_invop_remove(uint8_t (*func)(struct pt_regs *));

extern void dtrace_invop_enable(uint8_t *);
extern void dtrace_invop_disable(uint8_t *, uint8_t);

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
extern int dtrace_handle_no_pf(struct pt_regs *);

/*
 * This is only safe to call if we know this is a userspace fault
 * or that the call happens after early boot.
 */
static inline int dtrace_no_pf(struct pt_regs *regs)
{
	if (unlikely(DTRACE_CPUFLAG_ISSET(CPU_DTRACE_NOPF)))
		return dtrace_handle_no_pf(regs);
	return 0;
}

extern struct task_struct *register_pid_provider(pid_t);
extern void unregister_pid_provider(pid_t);
extern void dtrace_task_reinit(struct task_struct *);
extern void dtrace_task_init(struct task_struct *);
extern void dtrace_task_fork(struct task_struct *, struct task_struct *);
extern void dtrace_task_cleanup(struct task_struct *);

typedef struct fasttrap_machtp {
	struct inode		*fmtp_ino;
	loff_t			fmtp_off;
	struct uprobe_consumer	fmtp_cns;
} fasttrap_machtp_t;

extern void (*dtrace_helpers_cleanup)(struct task_struct *);
extern void (*dtrace_fasttrap_probes_cleanup)(struct task_struct *);
extern void (*dtrace_helpers_fork)(struct task_struct *,
				   struct task_struct *);
extern int (*dtrace_tracepoint_hit)(fasttrap_machtp_t *, struct pt_regs *);

extern int dtrace_tracepoint_enable(pid_t, uintptr_t, fasttrap_machtp_t *);
extern int dtrace_tracepoint_disable(pid_t, fasttrap_machtp_t *);

#else

/*
 * See arch/x86/mm/fault.c.
 */

#define dtrace_no_pf(ignore) 0

#endif /* CONFIG_DTRACE */

#endif /* !HEADERS_CHECK */

#endif /* _LINUX_DTRACE_OS_H_ */
