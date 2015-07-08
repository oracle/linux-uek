/* Copyright (C) 2011-2014 Oracle, Inc. */

#ifndef _LINUX_DTRACE_OS_H_
#define _LINUX_DTRACE_OS_H_

typedef uint32_t dtrace_id_t;

#ifndef HEADERS_CHECK

#ifdef CONFIG_DTRACE

#include <linux/ktime.h>
#include <linux/notifier.h>
#if defined(CONFIG_DT_FASTTRAP) || defined(CONFIG_DT_FASTTRAP_MODULE)
#include <linux/uprobes.h>
#endif
#include <asm/dtrace_util.h>
#include <asm/unistd.h>
#include <asm/asm-offsets.h>
#include <linux/dtrace_cpu.h>

#define DTRACE_IDNONE 0

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

extern void dtrace_skip_instruction(struct pt_regs *);

extern int dtrace_die_notifier(struct notifier_block *, unsigned long, void *);

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
extern void dtrace_handle_badaddr(struct pt_regs *);

/*
 * This is only safe to call if we know this is a userspace fault
 * or that the call happens after early boot.
 */
static inline int dtrace_no_pf(struct pt_regs *regs)
{
	if (unlikely(DTRACE_CPUFLAG_ISSET(CPU_DTRACE_NOFAULT))) {
		dtrace_handle_badaddr(regs);
		return 1;
	}

	return 0;
}

extern void dtrace_task_reinit(struct task_struct *);
extern void dtrace_task_init(struct task_struct *);
extern void dtrace_task_fork(struct task_struct *, struct task_struct *);
extern void dtrace_task_cleanup(struct task_struct *);

extern void (*dtrace_helpers_cleanup)(struct task_struct *);
extern void (*dtrace_fasttrap_probes_cleanup)(struct task_struct *);
extern void (*dtrace_helpers_fork)(struct task_struct *,
				   struct task_struct *);

#if defined(CONFIG_DT_FASTTRAP) || defined(CONFIG_DT_FASTTRAP_MODULE)
typedef struct fasttrap_machtp {
	struct inode		*fmtp_ino;
	loff_t			fmtp_off;
	struct uprobe_consumer	fmtp_cns;
} fasttrap_machtp_t;

extern int (*dtrace_tracepoint_hit)(fasttrap_machtp_t *, struct pt_regs *);

extern struct task_struct *register_pid_provider(pid_t);
extern void unregister_pid_provider(pid_t);

extern int dtrace_tracepoint_enable(pid_t, uintptr_t, fasttrap_machtp_t *);
extern int dtrace_tracepoint_disable(pid_t, fasttrap_machtp_t *);
#endif /* CONFIG_DT_FASTTRAP || CONFIG_DT_FASTTRAP_MODULE */

#else

/*
 * See arch/x86/mm/fault.c.
 */

#define dtrace_no_pf(ignore) 0

#endif /* CONFIG_DTRACE */

#endif /* !HEADERS_CHECK */

#endif /* _LINUX_DTRACE_OS_H_ */
