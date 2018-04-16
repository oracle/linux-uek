/*
 * Copyright (c) 2011, 2018, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _LINUX_DTRACE_OS_H_
#define _LINUX_DTRACE_OS_H_

#ifndef HEADERS_CHECK

#ifdef CONFIG_DTRACE

#include <linux/ktime.h>
#include <linux/mm.h>
#include <linux/notifier.h>
#include <linux/timekeeper_internal.h>
#if defined(CONFIG_DT_FASTTRAP) || defined(CONFIG_DT_FASTTRAP_MODULE)
#include <linux/uprobes.h>
#endif
#include <asm/unistd.h>
#include <linux/dtrace_cpu.h>
#include <linux/dtrace_task.h>
#include <linux/dtrace_psinfo.h>

extern struct module	*dtrace_kmod;

extern void __init dtrace_os_init(void);
extern void __init dtrace_psinfo_os_init(void);
extern void __init dtrace_task_os_init(void);

extern void *dtrace_alloc_text(struct module *, unsigned long);
extern void dtrace_free_text(void *);

extern void dtrace_mod_pdata_alloc(struct module *);
extern void dtrace_mod_pdata_free(struct module *);
extern int dtrace_destroy_prov(struct module *);

extern int dtrace_enable(void);
extern void dtrace_disable(void);

extern ktime_t dtrace_gethrtime(void);
extern ktime_t dtrace_getwalltime(void);

typedef enum dtrace_vtime_state {
	DTRACE_VTIME_INACTIVE = 0,
	DTRACE_VTIME_ACTIVE
} dtrace_vtime_state_t;

extern dtrace_vtime_state_t dtrace_vtime_active;

typedef void for_each_module_fn(void *, struct module *);
extern void dtrace_for_each_module(for_each_module_fn *fn, void *arg);

extern void dtrace_update_time(struct timekeeper *);
extern ktime_t dtrace_get_walltime(void);

extern void dtrace_vtime_enable(void);
extern void dtrace_vtime_disable(void);
extern void dtrace_vtime_switch(struct task_struct *, struct task_struct *);

#include <asm/dtrace_util.h>

extern int dtrace_instr_size(const asm_instr_t *);
extern void dtrace_skip_instruction(struct pt_regs *);

extern int dtrace_die_notifier(struct notifier_block *, unsigned long, void *);

#define STACKTRACE_KERNEL	0x01
#define STACKTRACE_USER		0x02
#define STACKTRACE_TYPE		0x0f

typedef struct stacktrace_state {
	uint64_t	*pcs;
	uint64_t	*fps;
	int		limit;
	int		depth;
	int		flags;
} stacktrace_state_t;

extern void dtrace_stacktrace(stacktrace_state_t *);
extern void dtrace_user_stacktrace(stacktrace_state_t *);
extern void dtrace_handle_badaddr(struct pt_regs *);
extern void dtrace_mod_pdata_init(dtrace_module_t *pdata);
extern void dtrace_mod_pdata_cleanup(dtrace_module_t *pdata);

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

extern void (*dtrace_helpers_cleanup)(struct task_struct *);
extern void (*dtrace_fasttrap_probes_cleanup)(struct task_struct *);
extern void (*dtrace_helpers_fork)(struct task_struct *, struct task_struct *);

#if defined(CONFIG_DT_FASTTRAP) || defined(CONFIG_DT_FASTTRAP_MODULE)
typedef struct fasttrap_machtp {
	struct inode		*fmtp_ino;
	loff_t			fmtp_off;
	struct uprobe_consumer	fmtp_cns;
} fasttrap_machtp_t;

extern int (*dtrace_tracepoint_hit)(fasttrap_machtp_t *, struct pt_regs *, int);

extern struct task_struct *register_pid_provider(pid_t);
extern void unregister_pid_provider(pid_t);

extern int dtrace_copy_code(pid_t, uint8_t *, uintptr_t, size_t);
extern int dtrace_tracepoint_enable(pid_t, uintptr_t, int, fasttrap_machtp_t *);
extern int dtrace_tracepoint_disable(pid_t, fasttrap_machtp_t *);
#endif /* CONFIG_DT_FASTTRAP || CONFIG_DT_FASTTRAP_MODULE */

#else

/*
 * See arch/x86/mm/fault.c.
 */

#define dtrace_no_pf(ignore) 0

/*
 * See kernel/timekeeper.c
 */
#define	dtrace_update_time(ignore)

/*
 * See kernel/dtrace/dtrace_os.c
 */
#define dtrace_mod_pdata_alloc(ignore)
#define dtrace_mod_pdata_free(ignore)
#define dtrace_destroy_prov(ignore) 1

#endif /* CONFIG_DTRACE */

#endif /* !HEADERS_CHECK */

#endif /* _LINUX_DTRACE_OS_H_ */
