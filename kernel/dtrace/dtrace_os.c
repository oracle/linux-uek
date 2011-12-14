/*
 * FILE:	dtrace_os.c
 * DESCRIPTION:	Dynamic Tracing: OS support functions - part of kernel core
 *
 * Copyright (C) 2010, 2011 Oracle Corporation
 */

#include <linux/cyclic.h>
#include <linux/dtrace_cpu.h>
#include <linux/dtrace_os.h>
#include <linux/fs.h>
#include <linux/hrtimer.h>
#include <linux/kdebug.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/insn.h>
#include <asm/stacktrace.h>
#include <asm/syscalls.h>

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
	int				(*dtih_func)(struct pt_regs *);
	struct dtrace_invop_hdlr	*dtih_next;
} dtrace_invop_hdlr_t;

static dtrace_invop_hdlr_t	*dtrace_invop_hdlrs;

static int dtrace_die_notifier(struct notifier_block *nb, unsigned long val,
			       void *args)
{
	struct die_args		*dargs = args;
	dtrace_invop_hdlr_t	*hdlr;
	int			rval = 0;

	if (val == DIE_PAGE_FAULT) {
		unsigned long	addr = read_cr2();
		struct insn	insn;

		if (!DTRACE_CPUFLAG_ISSET(CPU_DTRACE_NOFAULT))
			return NOTIFY_DONE;

		DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
		this_cpu_core->cpuc_dtrace_illval = addr;

		kernel_insn_init(&insn, (void *)dargs->regs->ip);
		insn_get_length(&insn);

		dargs->regs->ip += insn.length;

		return NOTIFY_OK | NOTIFY_STOP_MASK;
	}
	if (val == DIE_GPF) {
		struct insn	insn;

		if (!DTRACE_CPUFLAG_ISSET(CPU_DTRACE_NOFAULT))
			return NOTIFY_DONE;

		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);

		kernel_insn_init(&insn, (void *)dargs->regs->ip);
		insn_get_length(&insn);

		dargs->regs->ip += insn.length;

		return NOTIFY_DONE;
	}

	if (val != DIE_TRAP || dargs->trapnr != 6)
		return NOTIFY_DONE;


	for (hdlr = dtrace_invop_hdlrs; hdlr != NULL; hdlr = hdlr->dtih_next) {
		if ((rval = hdlr->dtih_func(dargs->regs)) != 0)
			break;
	}

	if (rval != 0) {
		dargs->regs->ip++;

		return NOTIFY_OK | NOTIFY_STOP_MASK;
	}

	return NOTIFY_DONE;
}

static struct notifier_block	dtrace_die = {
	.notifier_call = dtrace_die_notifier,
};

void dtrace_invop_add(int (*func)(struct pt_regs *))
{
	dtrace_invop_hdlr_t	*hdlr;

	hdlr = kmalloc(sizeof(dtrace_invop_hdlr_t), GFP_KERNEL);
	hdlr->dtih_func = func;
	hdlr->dtih_next = dtrace_invop_hdlrs;
	dtrace_invop_hdlrs = hdlr;

	/*
	 * If this is the first DTrace invalid opcode handling, register the
	 * die notifier with the kernel notifier core.
	 */
	if (hdlr->dtih_next == NULL)
		register_die_notifier(&dtrace_die);
}
EXPORT_SYMBOL(dtrace_invop_add);

void dtrace_invop_remove(int (*func)(struct pt_regs *))
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

		/*
		 * If there are no invalid opcode handlers left, unregister
		 * from the kernel notifier core.
		 */
		if (dtrace_invop_hdlrs == NULL)
			unregister_die_notifier(&dtrace_die);
	} else
		prev->dtih_next = hdlr->dtih_next;

	kfree(hdlr);
}
EXPORT_SYMBOL(dtrace_invop_remove);

/*---------------------------------------------------------------------------*\
(* SYSTEM CALL PROBING SUPPORT                                               *)
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
/*
 * Need to remove the define for _ASM_X86_UNISTD_64_H in order for unistd_64
 * to be included here because it was already included indirectly.
 */
#undef __SYSCALL
#define __SYSCALL(nr, sym)	[nr] { __stringify(sym), },
# undef _ASM_X86_UNISTD_64_H
#include <asm/unistd.h>
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
