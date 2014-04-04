/*
 * FILE:	dtrace_os.c
 * DESCRIPTION:	Dynamic Tracing: OS support functions - part of kernel core
 *
 * Copyright (C) 2010, 2011, 2012, 2013 Oracle Corporation
 */

#include <linux/binfmts.h>
#include <linux/dtrace_cpu.h>
#include <linux/dtrace_os.h>
#include <linux/fs.h>
#include <linux/hardirq.h>
#include <linux/interrupt.h>
#include <linux/kdebug.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/kallsyms.h>
#include <linux/workqueue.h>
#include <linux/mm.h>
#include <asm/insn.h>
#include <asm/stacktrace.h>
#include <asm/syscalls.h>

#include <linux/uprobes.h>
#include <asm/ptrace.h>

/*---------------------------------------------------------------------------*\
(* OS SPECIFIC DTRACE SETUP                                                  *)
\*---------------------------------------------------------------------------*/
struct module		*dtrace_kmod = NULL;
EXPORT_SYMBOL(dtrace_kmod);

int			dtrace_ustackdepth_max = 2048;

struct kmem_cache	*psinfo_cachep;

void dtrace_os_init(void)
{
	if (dtrace_kmod != NULL) {
		pr_warning("%s: cannot be called twice\n", __func__);
		return;
	}

	dtrace_kmod = kzalloc(sizeof(struct module), GFP_KERNEL);
	if (dtrace_kmod == NULL) {
		pr_warning("%s: cannot allocate kernel pseudo-module\n",
			   __func__);
		return;
	}

	dtrace_kmod->state = MODULE_STATE_LIVE;
	strlcpy(dtrace_kmod->name, "vmlinux", MODULE_NAME_LEN);

	psinfo_cachep = kmem_cache_create("psinfo_cache",
				sizeof(dtrace_psinfo_t), 0,
				SLAB_HWCACHE_ALIGN|SLAB_PANIC|SLAB_NOTRACK,
				NULL);

	dtrace_sdt_init();
	dtrace_sdt_register(dtrace_kmod);
}
EXPORT_SYMBOL(dtrace_os_init);

void dtrace_os_exit(void)
{
	pr_warn_once("%s is being deprecated - please do not use.\n",
		     __func__);
}
EXPORT_SYMBOL(dtrace_os_exit);

/*---------------------------------------------------------------------------*\
(* TASK PSINFO SUPPORT                                                       *)
\*---------------------------------------------------------------------------*/
/*
 * Allocate a new dtrace_psinfo_t structure.
 */
void dtrace_psinfo_alloc(struct task_struct *tsk)
{
	dtrace_psinfo_t		*psinfo;
	struct mm_struct	*mm;

	if (likely(tsk->dtrace_psinfo)) {
		put_psinfo(tsk);
		tsk->dtrace_psinfo = NULL;	/* while we build one */
	}

	psinfo = kmem_cache_alloc(psinfo_cachep, GFP_KERNEL);
	if (psinfo == NULL)
		goto fail;

	mm = get_task_mm(tsk);
	if (mm) {
		size_t	len = mm->arg_end - mm->arg_start;
		int	i, envc = 0;
		char	*p;

		/*
		 * Construct the psargs string.
		 */
		if (len >= PR_PSARGS_SZ)
			len = PR_PSARGS_SZ - 1;

		i = access_process_vm(tsk, mm->arg_start, psinfo->psargs,
					len, 0);
		while (i < PR_PSARGS_SZ)
			psinfo->psargs[i++] = 0;

		for (i = 0; i < len; i++) {
			if (psinfo->psargs[i] == '\0')
				psinfo->psargs[i] = ' ';
		}

		/*
		 * Determine the number of arguments.
		 */
		psinfo->argc = 0;
		for (p = (char *)mm->arg_start; p < (char *)mm->arg_end;
		     psinfo->argc++) {
			size_t	l = strnlen(p, MAX_ARG_STRLEN);

			if (!l)
				break;

			p += l + 1;
		}

		/*
		 * Limit the number of stored argument pointers.
		 */
		if ((len = psinfo->argc) >= PR_ARGV_SZ)
			len = PR_ARGV_SZ - 1;

		psinfo->argv = kmalloc((len + 1) * sizeof(char *),
					 GFP_KERNEL);
		if (psinfo->argv == NULL)
			goto fail;

		/*
		 * Now populate the array of argument strings.
		 */
		for (i = 0, p = (char *)mm->arg_start; i < len; i++) {
			psinfo->argv[i] = p;
			p += strnlen(p, MAX_ARG_STRLEN) + 1;
		}
		psinfo->argv[len] = NULL;

		/*
		 * Determine the number of environment variables.
		 */
		for (p = (char *)mm->env_start; p < (char *)mm->env_end;
		     envc++) {
			size_t	l = strnlen(p, MAX_ARG_STRLEN);

			if (!l)
				break;

			p += l + 1;
		}

		/*
		 * Limit the number of stored environment pointers.
		 */
		if ((len = envc) >= PR_ENVP_SZ)
			len = PR_ENVP_SZ - 1;

		psinfo->envp = kmalloc((len + 1) * sizeof(char *),
					 GFP_KERNEL);
		if (psinfo->envp == NULL)
			goto fail;

		/*
		 * Now populate the array of environment variable strings.
		 */
		for (i = 0, p = (char *)mm->env_start; i < len; i++) {
			psinfo->envp[i] = p;
			p += strnlen(p, MAX_ARG_STRLEN) + 1;
		}
		psinfo->envp[len] = NULL;

		mmput(mm);
	} else {
		size_t	len = min(TASK_COMM_LEN, PR_PSARGS_SZ);
		int	i;

		/*
		 * We end up here for tasks that do not have managed memory at
		 * all, which generally means that this is a kernel thread.
		 * If it is not, this is still safe because we know that tasks
		 * always have the comm member populated with something (even
		 * if it would be an empty string).
		 */
		memcpy(psinfo->psargs, tsk->comm, len);
		for (i = len; i < PR_PSARGS_SZ; i++)
			psinfo->psargs[i] = 0;

		psinfo->argc = 0;
		psinfo->argv = kmalloc(sizeof(char *), GFP_KERNEL);
		psinfo->argv[0] = NULL;
		psinfo->envp = kmalloc(sizeof(char *), GFP_KERNEL);
		psinfo->envp[0] = NULL;
	}

	atomic_set(&psinfo->usage, 1);
	tsk->dtrace_psinfo = psinfo;		/* new one */

	return;

fail:
	if (mm)
		mmput(mm);

	if (psinfo) {
		if (psinfo->argv)
			kfree(psinfo->argv);
		if (psinfo->envp)
			kfree(psinfo->envp);

		kmem_cache_free(psinfo_cachep, psinfo);
	}
}

static DEFINE_SPINLOCK(psinfo_lock);
static dtrace_psinfo_t *psinfo_free_list;

/*
 * Work queue handler to clean up psinfo structures for tasks that no longer
 * exist.
 */
static void psinfo_cleaner(struct work_struct *work)
{
	unsigned long	flags;
	dtrace_psinfo_t	*psinfo;

	spin_lock_irqsave(&psinfo_lock, flags);
	psinfo = psinfo_free_list;
	psinfo_free_list = NULL;
	spin_unlock_irqrestore(&psinfo_lock, flags);

#ifdef CONFIG_DT_DEBUG
	DTRACE_PROBE8(test, uint64_t, 10, uint64_t, 20, uint64_t, 30,
			    uint64_t, 40, uint64_t, 50, uint64_t, 60,
			    uint64_t, 70, uint64_t, 80);
#endif

	while (psinfo) {
		dtrace_psinfo_t	*next = psinfo->next;

		if (psinfo->argv)
			kfree(psinfo->argv);
		if (psinfo->envp)
			kfree(psinfo->envp);

		kmem_cache_free(psinfo_cachep, psinfo);
		psinfo = next;
	}
}

static DECLARE_WORK(psinfo_cleanup, psinfo_cleaner);

/*
 * Schedule a psinfo structure for free'ing.
 */
void dtrace_psinfo_free(struct task_struct *tsk)
{
	unsigned long	flags;
	dtrace_psinfo_t	*psinfo = tsk->dtrace_psinfo;

	/*
	 * There are (very few) tasks without psinfo...
	 */
	if (unlikely(psinfo == NULL))
		return;

	tsk->dtrace_psinfo = NULL;

	spin_lock_irqsave(&psinfo_lock, flags);
	psinfo->next = psinfo_free_list;
	psinfo_free_list = psinfo;
	spin_unlock_irqrestore(&psinfo_lock, flags);

	schedule_work(&psinfo_cleanup);
}

/*---------------------------------------------------------------------------*\
(* TIME SUPPORT FUNCTIONS                                                    *)
\*---------------------------------------------------------------------------*/
dtrace_vtime_state_t	dtrace_vtime_active = 0;

/*
 * Return a high resolution timer value that is guaranteed to always increase.
 */
ktime_t dtrace_gethrtime(void)
{
	struct timespec ts;

	getrawmonotonic(&ts);
	return timespec_to_ktime(ts);
}
EXPORT_SYMBOL(dtrace_gethrtime);

/*
 * Return the current wall-clock time, in nanoseconds since the epoch.
 */
ktime_t dtrace_getwalltime(void)
{
	struct timespec ts;

	getnstimeofday(&ts);
	return timespec_to_ktime(ts);
}
EXPORT_SYMBOL(dtrace_getwalltime);

void dtrace_vtime_enable(void)
{
	dtrace_vtime_state_t	old, new;

	do {
		old = dtrace_vtime_active;
		if (old == DTRACE_VTIME_ACTIVE) {
			pr_warn_once("DTrace virtual time already enabled");
			return;
		}

		new = DTRACE_VTIME_ACTIVE;
	} while (cmpxchg(&dtrace_vtime_active, old, new) != old);
}
EXPORT_SYMBOL(dtrace_vtime_enable);

void dtrace_vtime_disable(void)
{
	int	old, new;

	do {
		old = dtrace_vtime_active;
		if (old == DTRACE_VTIME_INACTIVE) {
			pr_warn_once("DTrace virtual time already disabled");
			return;
		}

		new = DTRACE_VTIME_INACTIVE;
	} while (cmpxchg(&dtrace_vtime_active, old, new) != old);
}
EXPORT_SYMBOL(dtrace_vtime_disable);

void dtrace_vtime_switch(struct task_struct *prev, struct task_struct *next)
{
	ktime_t	now = dtrace_gethrtime();

	if (ktime_nz(prev->dtrace_start)) {
		prev->dtrace_vtime = ktime_add(prev->dtrace_vtime,
					       ktime_sub(now,
							 prev->dtrace_start));
		prev->dtrace_start = ktime_set(0, 0);
	}

	next->dtrace_start = now;
}

/*---------------------------------------------------------------------------*\
(* STACK TRACES                                                              *)
\*---------------------------------------------------------------------------*/
static int dtrace_stacktrace_stack(void *data, char *name)
{
	stacktrace_state_t	*st = (stacktrace_state_t *)data;

	/*
	 * We do not skip anything for non-user stack analysis.
	 */
	if (!(st->flags & STACKTRACE_USER))
		return 0;

	if (name != NULL && strlen(name) > 3) {
		/*
		 * Sadly, the dump stack code calls us with both <EOE> and EOI.
		 * Consistency would be much nicer.
		 */
		if ((name[0] == '<' && name[1] == 'E' && name[2] == 'O') ||
		    (name[0] == 'E' && name[2] == 'O'))
			st->flags &= ~STACKTRACE_SKIP;
	}

	return 0;
}

static void dtrace_stacktrace_address(void *data, unsigned long addr,
				       int reliable)
{
	stacktrace_state_t	*st = (stacktrace_state_t *)data;

	if (st->flags & STACKTRACE_SKIP)
		return;

	if (reliable == 2) {
		if (st->fps)
			st->fps[st->depth] = addr;
	} else {
		if (st->pcs != NULL) {
			if (st->depth < st->limit)
				st->pcs[st->depth++] = addr;
		} else
			st->depth++;
	}

	if (st->depth >= dtrace_ustackdepth_max) {
		DTRACE_CPUFLAG_SET(CPU_DTRACE_BADSTACK);
		this_cpu_core->cpuc_dtrace_illval = st->depth;

		return;
	}
}

static inline int valid_sp(struct thread_info *tinfo, void *p,
			   unsigned int size, void *end)
{
	void	*t = tinfo;

	if (end) {
		if (p < end && p >= (end - THREAD_SIZE))
			return 1;
		else
			return 0;
	}

	return p > t && p < t + THREAD_SIZE - size;
}

struct frame {
	struct frame	*fr_savfp;
	unsigned long	fr_savpc;
} __attribute__((packed));

static unsigned long dtrace_stacktrace_walk_stack(
					struct thread_info *tinfo,
					unsigned long *stack,
					unsigned long bp,
					const struct stacktrace_ops *ops,
					void *data, unsigned long *end,
					int *graph)
{
	struct frame	*fr = (struct frame *)bp;
	unsigned long	*pcp = &(fr->fr_savpc);

	while (valid_sp(tinfo, pcp, sizeof(*pcp), end)) {
		unsigned long	addr = *pcp;

		fr = fr->fr_savfp;
		ops->address(data, (unsigned long)fr, 2);
		ops->address(data, addr, 1);
		pcp = &(fr->fr_savpc);
	}

	return (unsigned long)fr;
}

static const struct stacktrace_ops	dtrace_stacktrace_ops = {
	.stack		= dtrace_stacktrace_stack,
	.address	= dtrace_stacktrace_address,
	.walk_stack	= print_context_stack
};

static const struct stacktrace_ops	dtrace_fpstacktrace_ops = {
	.stack		= dtrace_stacktrace_stack,
	.address	= dtrace_stacktrace_address,
	.walk_stack	= dtrace_stacktrace_walk_stack
};

void dtrace_stacktrace(stacktrace_state_t *st)
{
	dump_trace(NULL, NULL, NULL, 0,
		   st->fps != NULL ? &dtrace_fpstacktrace_ops
				   : &dtrace_stacktrace_ops, st);
}
EXPORT_SYMBOL(dtrace_stacktrace);

/*---------------------------------------------------------------------------*\
(* INVALID OPCODE HANDLING                                                   *)
\*---------------------------------------------------------------------------*/
typedef struct dtrace_invop_hdlr {
	uint8_t				(*dtih_func)(struct pt_regs *);
	struct dtrace_invop_hdlr	*dtih_next;
} dtrace_invop_hdlr_t;

static dtrace_invop_hdlr_t	*dtrace_invop_hdlrs;

#define INVOP_TRAP_INSTR	0xf0

static int dtrace_die_notifier(struct notifier_block *nb, unsigned long val,
			       void *args)
{
	struct die_args		*dargs = args;
	struct insn		insn;

	switch (val) {
	case DIE_PAGE_FAULT: {
		unsigned long	addr = read_cr2();

		if (!DTRACE_CPUFLAG_ISSET(CPU_DTRACE_NOFAULT))
			return NOTIFY_DONE;

		DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
		this_cpu_core->cpuc_dtrace_illval = addr;

		kernel_insn_init(&insn, (void *)dargs->regs->ip);
		insn_get_length(&insn);

		dargs->regs->ip += insn.length;

		return NOTIFY_OK | NOTIFY_STOP_MASK;
	}
	case DIE_GPF: {
		kernel_insn_init(&insn, (void *)dargs->regs->ip);
		insn_get_length(&insn);

		/*
		 * It would seem that the invalid opcode generated by the LOCK
		 * prefix (0xF0) used for SDT probe points may get delivered as
		 * a general protection failure on Xen.  We need to ignore them
		 * as general protection failures...
		 */
		if (insn.length != 5 || insn.prefixes.bytes[0] != 0xf0 ||
		    insn.opcode.bytes[0] != 0x90) {
			if (!DTRACE_CPUFLAG_ISSET(CPU_DTRACE_NOFAULT))
				return NOTIFY_DONE;

			DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);

			dargs->regs->ip += insn.length;

			return NOTIFY_OK | NOTIFY_STOP_MASK;
		}

		/*
		 * ... and instead treat them as the SDT probe point traps that
		 * they are.
		 */
		dargs->trapnr = 6;
	}
	case DIE_TRAP: {
		dtrace_invop_hdlr_t	*hdlr;
		int			rval = 0;

		if (dargs->trapnr != 6)
			return NOTIFY_DONE;

		for (hdlr = dtrace_invop_hdlrs; hdlr != NULL;
		     hdlr = hdlr->dtih_next) {
			if ((rval = hdlr->dtih_func(dargs->regs)) != 0)
				break;
		}

		if (rval != 0) {
			kernel_insn_init(&insn, (void *)dargs->regs->ip);
			insn_get_length(&insn);

			dargs->regs->ip += insn.length;

			return NOTIFY_OK | NOTIFY_STOP_MASK;
		}
	}
	default:
		return NOTIFY_DONE;
	}
}

static struct notifier_block	dtrace_die = {
	.notifier_call = dtrace_die_notifier,
};

static int	dtrace_enabled = 0;

void dtrace_enable(void)
{
	if (!dtrace_enabled) {
		register_die_notifier(&dtrace_die);
		dtrace_enabled = 1;
	}
}
EXPORT_SYMBOL(dtrace_enable);

void dtrace_disable(void)
{
	if (!dtrace_enabled)
		return;

	unregister_die_notifier(&dtrace_die);
	dtrace_enabled = 0;
}
EXPORT_SYMBOL(dtrace_disable);

int dtrace_invop_add(uint8_t (*func)(struct pt_regs *))
{
	dtrace_invop_hdlr_t	*hdlr;

	hdlr = kmalloc(sizeof(dtrace_invop_hdlr_t), GFP_KERNEL);
	if (hdlr == NULL) {
		pr_warn("Failed to add invop handler: out of memory\n");
		return -ENOMEM;
	}

	hdlr->dtih_func = func;
	hdlr->dtih_next = dtrace_invop_hdlrs;
	dtrace_invop_hdlrs = hdlr;

	return 0;
}
EXPORT_SYMBOL(dtrace_invop_add);

void dtrace_invop_remove(uint8_t (*func)(struct pt_regs *))
{
	dtrace_invop_hdlr_t	*hdlr = dtrace_invop_hdlrs, *prev = NULL;

	for (;;) {
		if (hdlr == NULL)
			return;

		if (hdlr->dtih_func == func)
			break;

		prev = hdlr;
		hdlr = hdlr->dtih_next;
	}

	if (prev == NULL) {
		dtrace_invop_hdlrs = hdlr->dtih_next;
	} else
		prev->dtih_next = hdlr->dtih_next;

	kfree(hdlr);
}
EXPORT_SYMBOL(dtrace_invop_remove);

void dtrace_invop_enable(uint8_t *addr)
{
	text_poke(addr, ((unsigned char []){INVOP_TRAP_INSTR}), 1);
}
EXPORT_SYMBOL(dtrace_invop_enable);

void dtrace_invop_disable(uint8_t *addr, uint8_t opcode)
{
	text_poke(addr, ((unsigned char []){opcode}), 1);
}
EXPORT_SYMBOL(dtrace_invop_disable);

/*---------------------------------------------------------------------------*\
(* SYSTEM CALL TRACING SUPPORT                                               *)
\*---------------------------------------------------------------------------*/
void (*systrace_probe)(dtrace_id_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t,
		       uintptr_t, uintptr_t);

void systrace_stub(dtrace_id_t id, uintptr_t arg0, uintptr_t arg1,
		   uintptr_t arg2, uintptr_t arg3, uintptr_t arg4,
		   uintptr_t arg5)
{
}

asmlinkage long systrace_syscall(uintptr_t, uintptr_t,
				 uintptr_t, uintptr_t,
				 uintptr_t, uintptr_t);
asmlinkage long dtrace_stub_clone(uintptr_t, uintptr_t,
				 uintptr_t, uintptr_t,
				 uintptr_t, uintptr_t);
asmlinkage long dtrace_stub_fork(uintptr_t, uintptr_t,
				 uintptr_t, uintptr_t,
				 uintptr_t, uintptr_t);
asmlinkage long dtrace_stub_vfork(uintptr_t, uintptr_t,
				  uintptr_t, uintptr_t,
				  uintptr_t, uintptr_t);
asmlinkage long dtrace_stub_iopl(uintptr_t, uintptr_t,
				 uintptr_t, uintptr_t,
				 uintptr_t, uintptr_t);
asmlinkage long dtrace_stub_execve(uintptr_t, uintptr_t,
				   uintptr_t, uintptr_t,
				   uintptr_t, uintptr_t);
asmlinkage long dtrace_stub_rt_sigreturn(uintptr_t, uintptr_t,
					 uintptr_t, uintptr_t,
					 uintptr_t, uintptr_t);

static systrace_info_t	systrace_info =
		{
			&systrace_probe,
			systrace_stub,
			systrace_syscall,
			{
			    [SCE_CLONE] dtrace_stub_clone,
			    [SCE_FORK] dtrace_stub_fork,
			    [SCE_VFORK] dtrace_stub_vfork,
			    [SCE_IOPL] dtrace_stub_iopl,
			    [SCE_EXECVE] dtrace_stub_execve,
			    [SCE_RT_SIGRETURN] dtrace_stub_rt_sigreturn,
			},
			{
#define __SYSCALL_64(nr, sym, compat)		[nr] { __stringify(sym), },
#define __SYSCALL_COMMON(nr, sym, compat)	__SYSCALL_64(nr, sym, compat)
#define __SYSCALL_X32(nt, sym, compat)
#include <asm/syscalls_64.h>
			}
		};


long systrace_syscall(uintptr_t arg0, uintptr_t arg1, uintptr_t arg2,
		      uintptr_t arg3, uintptr_t arg4, uintptr_t arg5)
{
	long			rc = 0;
	unsigned long		sysnum;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;

	asm volatile("movq %%rax,%0" : "=m"(sysnum));

	sc = &systrace_info.sysent[sysnum];

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, arg0, arg1, arg2, arg3, arg4, arg5);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	if (sc->stsy_underlying != NULL)
		rc = (*sc->stsy_underlying)(arg0, arg1, arg2, arg3, arg4,
					    arg5);

	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0);

	return rc;
}

systrace_info_t *dtrace_syscalls_init() {
	int			i;
	extern sys_call_ptr_t	sys_call_table[NR_syscalls];

	for (i = 0; i < NR_syscalls; i++) {
		systrace_info.sysent[i].stsy_tblent = &sys_call_table[i];
		systrace_info.sysent[i].stsy_underlying =
					(dt_sys_call_t)sys_call_table[i];
	}

	return &systrace_info;
}
EXPORT_SYMBOL(dtrace_syscalls_init);

long dtrace_clone(unsigned long clone_flags, unsigned long newsp,
		  int __user *parent_tidptr, int __user *child_tidptr,
		  int tls_val)
{
	long			rc = 0;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;

	sc = &systrace_info.sysent[__NR_clone];

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, clone_flags, newsp,
				  (uintptr_t)parent_tidptr,
				  (uintptr_t)child_tidptr, tls_val, 0);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	rc = do_fork(clone_flags, newsp, 0, parent_tidptr, child_tidptr);

	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0);

	return rc;
}

long dtrace_fork(void)
{
	long			rc = 0;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;

	sc = &systrace_info.sysent[__NR_fork];

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, 0, 0, 0, 0, 0, 0);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	rc = do_fork(SIGCHLD, 0, 0, NULL, NULL);

	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0);

	return rc;
}

long dtrace_vfork(void)
{
	long			rc = 0;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;

	sc = &systrace_info.sysent[__NR_vfork];

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, 0, 0, 0, 0, 0, 0);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	rc = do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, 0, 0, NULL, NULL);

	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0);

	return rc;
}

long dtrace_execve(const char __user *name,
		   const char __user *const __user *argv,
		   const char __user *const __user *envp)
{
	long			rc = 0;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;
	struct filename		*path;

	sc = &systrace_info.sysent[__NR_execve];

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)name, (uintptr_t)argv,
				  (uintptr_t)envp, 0, 0, 0);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	path = getname(name);
	rc = PTR_ERR(path);
	if (IS_ERR(path))
		goto out;
	rc = do_execve(path->name, argv, envp);
	putname(path);

out:
	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0);

	return rc;
}

long dtrace_iopl(unsigned int level, struct pt_regs *regs)
{
	long			rc = 0;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;
	unsigned int		old = (regs->flags >> 12) & 3;
	struct thread_struct	*t = &current->thread;

	sc = &systrace_info.sysent[__NR_iopl];

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)level, (uintptr_t)regs,
				  0, 0, 0, 0);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	if (level > 3) {
		rc = -EINVAL;
		goto out;
	}

	/* Trying to gain more privileges? */
	if (level > old) {
		if (!capable(CAP_SYS_RAWIO)) {
			rc = -EPERM;
			goto out;
		}
	}

	regs->flags = (regs->flags & ~X86_EFLAGS_IOPL) | (level << 12);
	t->iopl = level << 12;
	set_iopl_mask(t->iopl);

out:
	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0);

	return rc;
}

long dtrace_rt_sigreturn(struct pt_regs *regs)
{
	long			rc = 0;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;

	sc = &systrace_info.sysent[__NR_rt_sigreturn];

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)regs, 0, 0, 0, 0, 0);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	rc = sys_rt_sigreturn(regs);

	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0);

	return rc;
}

/*---------------------------------------------------------------------------*\
(* USER SPACE TRACING (FASTTRAP) SUPPORT                                     *)
\*---------------------------------------------------------------------------*/
struct task_struct *register_pid_provider(pid_t pid)
{
	struct task_struct	*p;

	/*
	 * Make sure the process exists, (FIXME: isn't a child created as the
	 * result of a vfork(2)), and isn't a zombie (but may be in fork).
	 */
	rcu_read_lock();
	read_lock(&tasklist_lock);
	if ((p = find_task_by_vpid(pid)) == NULL) {
		read_unlock(&tasklist_lock);
		rcu_read_unlock();
		return NULL;
	}

	get_task_struct(p);
	read_unlock(&tasklist_lock);
	rcu_read_unlock();

	if (p->state & TASK_DEAD ||
	    p->exit_state & (EXIT_ZOMBIE | EXIT_DEAD)) {
		put_task_struct(p);
		return NULL;
	}

	/*
	 * Increment dtrace_probes so that the process knows to inform us
	 * when it exits or execs. fasttrap_provider_free() decrements this
	 * when we're done with this provider.
	 */
	p->dtrace_probes++;
	put_task_struct(p);

	return p;
}
EXPORT_SYMBOL(register_pid_provider);

void unregister_pid_provider(pid_t pid)
{
	struct task_struct	*p;

	/*
	 * Decrement dtrace_probes on the process whose provider we're
	 * freeing. We don't have to worry about clobbering somone else's
	 * modifications to it because we have locked the bucket that
	 * corresponds to this process's hash chain in the provider hash
	 * table. Don't sweat it if we can't find the process.
	 */
	rcu_read_lock();
	read_lock(&tasklist_lock);
	if ((p = find_task_by_vpid(pid)) == NULL) {
		read_unlock(&tasklist_lock);
		rcu_read_unlock();
		return;
	}

	get_task_struct(p);
	read_unlock(&tasklist_lock);
	rcu_read_unlock();

	p->dtrace_probes--;
	put_task_struct(p);
}
EXPORT_SYMBOL(unregister_pid_provider);

void (*dtrace_helpers_cleanup)(struct task_struct *);
EXPORT_SYMBOL(dtrace_helpers_cleanup);
void (*dtrace_fasttrap_probes_cleanup)(struct task_struct *);
EXPORT_SYMBOL(dtrace_fasttrap_probes_cleanup);
void (*dtrace_helpers_fork)(struct task_struct *, struct task_struct *);
EXPORT_SYMBOL(dtrace_helpers_fork);
int (*dtrace_tracepoint_hit)(fasttrap_machtp_t *, struct pt_regs *);
EXPORT_SYMBOL(dtrace_tracepoint_hit);

void dtrace_task_reinit(struct task_struct *tsk)
{
	tsk->predcache = 0;
	tsk->dtrace_stop = 0;
	tsk->dtrace_sig = 0;

	tsk->dtrace_helpers = NULL;
	tsk->dtrace_probes = 0;
	tsk->dtrace_tp_count = 0;
}

void dtrace_task_init(struct task_struct *tsk)
{
	dtrace_task_reinit(tsk);

	tsk->dtrace_vtime = ktime_set(0, 0);
	tsk->dtrace_start = ktime_set(0, 0);
}

void dtrace_task_fork(struct task_struct *tsk, struct task_struct *child)
{
	if (likely(dtrace_helpers_fork == NULL))
		return;

	if (tsk->dtrace_helpers != NULL)
		(*dtrace_helpers_fork)(tsk, child);
}

void dtrace_task_cleanup(struct task_struct *tsk)
{
	if (likely(dtrace_helpers_cleanup == NULL))
		return;

	if (tsk->dtrace_helpers != NULL)
		(*dtrace_helpers_cleanup)(tsk);

	if (tsk->dtrace_probes) {
		if (dtrace_fasttrap_probes_cleanup != NULL)
			(*dtrace_fasttrap_probes_cleanup)(tsk);
	}
}

static int handler(struct uprobe_consumer *self, struct pt_regs *regs)
{
	fasttrap_machtp_t	*mtp = container_of(self, fasttrap_machtp_t,
						    fmtp_cns);
	int			rc = 0;

	read_lock(&this_cpu_core->cpu_ft_lock);
	if (dtrace_tracepoint_hit == NULL)
		pr_warn("Fasttrap probes, but no handler\n");
	else
		rc = (*dtrace_tracepoint_hit)(mtp, regs);
	read_unlock(&this_cpu_core->cpu_ft_lock);

	return rc;
}

int dtrace_tracepoint_enable(pid_t pid, uintptr_t addr,
			     fasttrap_machtp_t *mtp)
{
	struct task_struct	*p;
	struct inode		*ino;
	struct vm_area_struct	*vma;
	loff_t			off;
	int			rc = 0;

	mtp->fmtp_ino = NULL;
	mtp->fmtp_off = 0;

	p = find_task_by_vpid(pid);
	if (!p) {
		pr_warn("PID %d not found\n", pid);
		return -ESRCH;
	}

	vma = find_vma(p->mm, addr);
	if (vma == NULL || vma->vm_file == NULL)
		return -EFAULT;

	ino = vma->vm_file->f_mapping->host;
	off = ((loff_t)vma->vm_pgoff << PAGE_SHIFT) + (addr - vma->vm_start);

	mtp->fmtp_cns.handler = handler;

	rc = uprobe_register(ino, off, &mtp->fmtp_cns);

	/*
	 * If successful, increment the count of the number of
	 * tracepoints active in the victim process.
	 */
	if (rc == 0) {
		mtp->fmtp_ino = ino;
		mtp->fmtp_off = off;

		p->dtrace_tp_count++;
	}

	return rc;
}
EXPORT_SYMBOL(dtrace_tracepoint_enable);

int dtrace_tracepoint_disable(pid_t pid, fasttrap_machtp_t *mtp)
{
	struct task_struct	*p;

	if (!mtp || !mtp->fmtp_ino) {
		pr_warn("DTRACE: Tracepoint was never enabled\n");
		return -ENOENT;
	}

	if (!mtp->fmtp_cns.handler) {
		pr_warn("DTRACE: No handler for tracepoint\n");
		return -ENOENT;
	}

	uprobe_unregister(mtp->fmtp_ino, mtp->fmtp_off, &mtp->fmtp_cns);

	mtp->fmtp_ino = NULL;
	mtp->fmtp_off = 0;

	/*
	 * Decrement the count of the number of tracepoints active in
	 * the victim process (if it still exists).
	 */
	p = find_task_by_vpid(pid);
	if (p)
		p->dtrace_tp_count--;

	return 0;
}
EXPORT_SYMBOL(dtrace_tracepoint_disable);
