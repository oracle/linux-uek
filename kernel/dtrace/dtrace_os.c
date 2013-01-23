/*
 * FILE:	dtrace_os.c
 * DESCRIPTION:	Dynamic Tracing: OS support functions - part of kernel core
 *
 * Copyright (C) 2010, 2011, 2012, 2013 Oracle Corporation
 */

#include <linux/binfmts.h>
#include <linux/cyclic.h>
#include <linux/dtrace_cpu.h>
#include <linux/dtrace_os.h>
#include <linux/fs.h>
#include <linux/hardirq.h>
#include <linux/hrtimer.h>
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

/*---------------------------------------------------------------------------*\
(* OS SPECIFIC DTRACE SETUP                                                  *)
\*---------------------------------------------------------------------------*/
struct module	*dtrace_kmod = NULL;
EXPORT_SYMBOL(dtrace_kmod);

int		dtrace_ustackdepth_max = 2048;

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

	dtrace_sdt_register(dtrace_kmod);
}
EXPORT_SYMBOL(dtrace_os_init);

void dtrace_os_exit(void)
{
	if (dtrace_kmod == NULL) {
		pr_warning("%s: kernel pseudo-module not allocated\n",
			   __func__);
		return;
	}

	kfree(dtrace_kmod);
	dtrace_kmod = NULL;
}
EXPORT_SYMBOL(dtrace_os_exit);

/*---------------------------------------------------------------------------*\
(* TASK PSINFO SUPPORT                                                       *)
\*---------------------------------------------------------------------------*/
/*
 * Allocate a new dtrace_psinfo_t structure.
 */
dtrace_psinfo_t *dtrace_psinfo_alloc(struct task_struct *task)
{
	dtrace_psinfo_t		*psinfo;
	struct mm_struct	*mm;

	psinfo = kzalloc(sizeof(dtrace_psinfo_t), GFP_KERNEL);
	if (psinfo == NULL) {
		pr_warning("%s: cannot allocate DTrace psinfo structure\n",
			   __func__);
		return NULL;
	}

	mm = get_task_mm(task);
	if (mm) {
		size_t	len = mm->arg_end - mm->arg_start;
		int	i, envc = 0;
		char	*p;

		/*
		 * Construct the psargs string.
		 */
		if (len >= PR_PSARGS_SZ)
			len = PR_PSARGS_SZ - 1;

		i = access_process_vm(task, mm->arg_start, psinfo->psargs,
					len, 0);
		while (i < PR_PSARGS_SZ)
			psinfo->psargs[i++] = 0;

		mmput(mm);

		for (i = 0; i < len; i++) {
			if (psinfo->psargs[i] == '\0')
				psinfo->psargs[i] = ' ';
		}

		/*
		 * Determine the number of arguments.
		 */
		for (p = (char *)mm->arg_start; p < (char *)mm->arg_end;
		     psinfo->argc++) {
			size_t	l = strnlen(p, MAX_ARG_STRLEN);

			if (!l)
				break;

			p += l + 1;
		}

		psinfo->argv = vmalloc((psinfo->argc + 1) * sizeof(char *));

		/*
		 * Now populate the array of argument strings.
		 */
		for (i = 0, p = (char *)mm->arg_start; i < psinfo->argc; i++) {
			psinfo->argv[i] = p;
			p += strnlen(p, MAX_ARG_STRLEN) + 1;
		}
		psinfo->argv[psinfo->argc] = NULL;

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

		psinfo->envp = vmalloc((envc + 1) * sizeof(char *));

		/*
		 * Now populate the array of environment variable strings.
		 */
		for (i = 0, p = (char *)mm->env_start; i < envc; i++) {
			psinfo->envp[i] = p;
			p += strnlen(p, MAX_ARG_STRLEN) + 1;
		}
		psinfo->envp[envc] = NULL;
	}

	return psinfo;
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

	while (psinfo) {
		dtrace_psinfo_t	*next = psinfo->next;

		if (psinfo->argv)
			vfree(psinfo->argv);
		if (psinfo->envp)
			vfree(psinfo->envp);

		kfree(psinfo);
		psinfo = next;
	}
}

static DECLARE_WORK(psinfo_cleanup, psinfo_cleaner);

/*
 * Schedule a psinfo structure for free'ing.
 */
void dtrace_psinfo_free(dtrace_psinfo_t *psinfo)
{
	unsigned long	flags;

	/*
	 * For most tasks, we never populate any DTrace psinfo.
	 */
	if (!psinfo)
		return;

	spin_lock_irqsave(&psinfo_lock, flags);
	psinfo->next = psinfo_free_list;
	psinfo_free_list = psinfo;
	spin_unlock_irqrestore(&psinfo_lock, flags);

	schedule_work(&psinfo_cleanup);
}

/*---------------------------------------------------------------------------*\
(* TIME QUERIES                                                              *)
\*---------------------------------------------------------------------------*/
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

/*---------------------------------------------------------------------------*\
(* CYCLICS                                                                   *)
\*---------------------------------------------------------------------------*/
typedef union cyclic	cyclic_t;
union cyclic {
	struct {
		cyc_time_t	when;
		cyc_handler_t	hdlr;
		struct hrtimer	timr;
	} cyc;
	cyclic_t		*nxt;
};

static enum hrtimer_restart cyclic_fire_fn(struct hrtimer *timr)
{
	cyclic_t	*cyc = container_of(timr, cyclic_t, cyc.timr);

	if (cyc->cyc.hdlr.cyh_func)
		cyc->cyc.hdlr.cyh_func(cyc->cyc.hdlr.cyh_arg);

	hrtimer_forward_now(&cyc->cyc.timr, cyc->cyc.when.cyt_interval);

	return HRTIMER_RESTART;
}

/*
 * Add a new cyclic to the system.
 */
cyclic_id_t cyclic_add(cyc_handler_t *hdlr, cyc_time_t *when)
{
	cyclic_t	*cyc;

	if (hdlr == NULL || when == NULL)
		return CYCLIC_NONE;

	if ((cyc = kmalloc(sizeof(cyclic_t), GFP_KERNEL)) == NULL)
		return CYCLIC_NONE;

	cyc->cyc.when = *when;
	cyc->cyc.hdlr = *hdlr;

	hrtimer_init(&cyc->cyc.timr, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	cyc->cyc.timr.function = cyclic_fire_fn;

	if (cyc->cyc.when.cyt_when.tv64 == 0)
		hrtimer_start(&cyc->cyc.timr, cyc->cyc.when.cyt_interval,
			      HRTIMER_MODE_REL_PINNED);
	else
		hrtimer_start(&cyc->cyc.timr, cyc->cyc.when.cyt_when,
			      HRTIMER_MODE_ABS_PINNED);

	return (cyclic_id_t)cyc;
}
EXPORT_SYMBOL(cyclic_add);

/*
 * Add a new omnipresent cyclic to the system.
 */
cyclic_id_t cyclic_add_omni(cyc_omni_handler_t *omni)
{
	if (omni == NULL)
		return CYCLIC_NONE;

	return CYCLIC_NONE;
}
EXPORT_SYMBOL(cyclic_add_omni);

/*
 * Remove a specific cyclic from the system.
 */
void cyclic_remove(cyclic_id_t id)
{
	cyclic_t	*cyc = (cyclic_t *)id;

	hrtimer_cancel(&cyc->cyc.timr);

	kfree(cyc);
}
EXPORT_SYMBOL(cyclic_remove);

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

void dtrace_invop_add(uint8_t (*func)(struct pt_regs *))
{
	dtrace_invop_hdlr_t	*hdlr;

	hdlr = kmalloc(sizeof(dtrace_invop_hdlr_t), GFP_KERNEL);
	hdlr->dtih_func = func;
	hdlr->dtih_next = dtrace_invop_hdlrs;
	dtrace_invop_hdlrs = hdlr;
}
EXPORT_SYMBOL(dtrace_invop_add);

void dtrace_invop_remove(uint8_t (*func)(struct pt_regs *))
{
	dtrace_invop_hdlr_t	*hdlr = dtrace_invop_hdlrs, *prev = NULL;

	for (;;) {
		if (hdlr == NULL)
			pr_err("attempt to remove non-existant invop handler");

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
asmlinkage long dtrace_stub_sigaltstack(uintptr_t, uintptr_t,
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
			    [SCE_SIGALTSTACK] dtrace_stub_sigaltstack,
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
		  void __user *parent_tid, void __user *child_tid,
		  struct pt_regs *regs)
{
	long			rc = 0;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;

	if (!newsp)
		newsp = regs->sp;

	sc = &systrace_info.sysent[__NR_clone];

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, clone_flags, newsp,
				  (uintptr_t)parent_tid, (uintptr_t)child_tid,
				  (uintptr_t)regs, 0);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	rc = do_fork(clone_flags, newsp, regs, 0, parent_tid, child_tid);

	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0);

	return rc;
}

long dtrace_fork(struct pt_regs *regs)
{
	long			rc = 0;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;

	sc = &systrace_info.sysent[__NR_fork];

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)regs, 0, 0, 0, 0, 0);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	rc = do_fork(SIGCHLD, regs->sp, regs, 0, NULL, NULL);

	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0);

	return rc;
}

long dtrace_vfork(struct pt_regs *regs)
{
	long			rc = 0;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;

	sc = &systrace_info.sysent[__NR_vfork];

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)regs, 0, 0, 0, 0, 0);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	rc = do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, regs->sp, regs, 0,
		     NULL, NULL);

	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0);

	return rc;
}

long dtrace_execve(const char __user *name,
		   const char __user *const __user *argv,
		   const char __user *const __user *envp, struct pt_regs *regs)
{
	long			rc = 0;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;
	char			*filename;

	sc = &systrace_info.sysent[__NR_execve];

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)name, (uintptr_t)argv,
				  (uintptr_t)envp, (uintptr_t)regs, 0, 0);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	filename = getname(name);
	rc = PTR_ERR(filename);
	if (IS_ERR(filename))
		goto out;

	rc = do_execve(filename, argv, envp, regs);

	putname(filename);

out:
	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0);

	return rc;
}

long dtrace_sigaltstack(const stack_t __user *uss, stack_t __user *uoss,
			struct pt_regs *regs)
{
	long			rc = 0;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;

	sc = &systrace_info.sysent[__NR_sigaltstack];

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)uss, (uintptr_t)uoss,
				  (uintptr_t)regs, 0, 0, 0);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

        rc =  do_sigaltstack(uss, uoss, regs->sp);

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
