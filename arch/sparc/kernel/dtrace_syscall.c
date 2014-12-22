/*
 * FILE:	dtrace_syscall.c
 * DESCRIPTION:	Dynamic Tracing: system call tracing support (arch-specific)
 *
 * Copyright (C) 2010-2014 Oracle Corporation
 */

#include <linux/dtrace_cpu.h>
#include <linux/dtrace_os.h>
#include <linux/dtrace_syscall.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <asm/compat.h>

#include "systbls.h"

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

static systrace_info_t	systrace_info =
		{
			&systrace_probe,
			&systrace_stub,
			&systrace_syscall,
			{
#define DTRACE_SYSCALL_STUB(t, n) \
			    [SCE_##t] dtrace_stub_##n,
#include <asm/dtrace_syscall.h>
#undef DTRACE_SYSCALL_STUB
			},
			{
			}
		};


long systrace_syscall(uintptr_t arg0, uintptr_t arg1, uintptr_t arg2,
		      uintptr_t arg3, uintptr_t arg4, uintptr_t arg5)
{
	long			rc = 0;
	unsigned long		sysnum;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;

	sysnum = syscall_get_nr(current, current_pt_regs());
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

	/*
	 * Only initialize this stuff once...
	 */
	if (systrace_info.sysent[0].stsy_tblent != NULL)
		return &systrace_info;

	for (i = 0; i < NR_syscalls; i++) {
		char	sym[KSYM_SYMBOL_LEN];
		char	*p = sym;

		/*
		 * We (ab)use the knowledge that the perfctr system call is
		 * not implemented, and is directed to sys_nis_syscall.  We'd
		 * rather refer to that function directly, but it is not a
		 * global symbol.
		 */
		if (sys_call_table[i] == (uintptr_t)sys_ni_syscall ||
		    sys_call_table[i] == sys_call_table[__NR_perfctr])
			continue;

		lookup_symbol_name(sys_call_table[i],  sym);
		p = strchr(sym, '_');
		if (p == NULL)
			continue;
		p++;

		systrace_info.sysent[i].name = kstrdup(p, GFP_KERNEL);
		systrace_info.sysent[i].stsy_tblent =
				(dt_sys_call_t *)&sys_call_table[i];
		systrace_info.sysent[i].stsy_underlying =
				(dt_sys_call_t)(uintptr_t)sys_call_table[i];
	}

	return &systrace_info;
}
EXPORT_SYMBOL(dtrace_syscalls_init);

asmlinkage long dtrace_sys_clone(unsigned long clone_flags,
				 unsigned long newsp, struct pt_regs *regs,
				 unsigned long stack_size)
{
	int __user		*parent_tidptr, *child_tidptr;
	long			rc = 0;
	unsigned long		orig_i1 = regs->u_regs[UREG_I1];
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;

	sc = &systrace_info.sysent[__NR_clone];

#ifdef CONFIG_COMPAT
	if (test_thread_flag(TIF_32BIT)) {
		parent_tidptr = compat_ptr(regs->u_regs[UREG_I2]);
		child_tidptr = compat_ptr(regs->u_regs[UREG_I4]);
	} else
#endif
	{
		parent_tidptr = (int __user *) regs->u_regs[UREG_I2];
		child_tidptr = (int __user *) regs->u_regs[UREG_I4];
	}

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, clone_flags, newsp,
				  (uintptr_t)parent_tidptr,
				  (uintptr_t)child_tidptr, 0, 0);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	rc = do_fork(clone_flags, newsp, stack_size, parent_tidptr,
		     child_tidptr);

	if ((unsigned long)rc >= -ERESTART_RESTARTBLOCK)
		regs->u_regs[UREG_I1] = orig_i1;

	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0);

	return rc;
}

asmlinkage long dtrace_sys_execve(const char __user *name,
				  const char __user *const __user *argv,
				  const char __user *const __user *envp)
{
	long			rc = 0;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;

	sc = &systrace_info.sysent[__NR_execve];

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)name, (uintptr_t)argv,
				  (uintptr_t)envp, 0, 0, 0);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	rc = do_execve(getname(name), argv, envp);

out:
	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0);

	return rc;
}

asmlinkage long dtrace_sys_exit(int error_code)
{
	long			rc = 0;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;

	sc = &systrace_info.sysent[__NR_exit];

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, error_code, 0, 0, 0, 0, 0);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	do_exit((error_code&0xff)<<8);

	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0);

	return rc;
}

asmlinkage long dtrace_sys_exit_group(int error_code)
{
	long			rc = 0;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;

	sc = &systrace_info.sysent[__NR_exit_group];

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, error_code, 0, 0, 0, 0, 0);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	do_group_exit((error_code & 0xff) << 8);

	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0);

	return rc;
}

asmlinkage long dtrace_sys_memory_ordering(unsigned long model,
					    struct pt_regs *regs)
{
	long			rc = 0;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;

	sc = &systrace_info.sysent[__NR_memory_ordering];

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)regs, 0, 0, 0, 0, 0);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	if (model >= 3)
		rc = -EINVAL;
	else
		regs->tstate = (regs->tstate & ~TSTATE_MM) | (model << 14);

	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0);

	return rc;
}

asmlinkage long dtrace_sys_pipe(struct pt_regs *regs)
{
	int			fd[2];
	long			rc = 0;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;

	sc = &systrace_info.sysent[__NR_pipe];

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, 0, 0, 0, 0, 0, 0);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	rc = do_pipe_flags(fd, 0);
	if (rc)
		goto out;

	regs->u_regs[UREG_I1] = fd[1];
	rc = fd[0];

out:
	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0);

	return rc;
}

asmlinkage long dtrace_sys_rt_sigreturn(struct pt_regs *regs)
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

	do_rt_sigreturn(regs);

	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0);

	return rc;
}

asmlinkage long dtrace_sys_sigaltstack(const stack_t __user *uss,
				       stack_t __user *uoss, unsigned long sp)
{
	long			rc = 0;
	dtrace_id_t		id;
	dtrace_syscalls_t	*sc;

	sc = &systrace_info.sysent[__NR_sigaltstack];

	if ((id = sc->stsy_entry) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)uss, (uintptr_t)uoss, sp, 0,
				  0, 0);

	/*
	 * FIXME: Add stop functionality for DTrace.
	 */

	rc = do_sigaltstack(uss, uoss, sp);

	if ((id = sc->stsy_return) != DTRACE_IDNONE)
		(*systrace_probe)(id, (uintptr_t)rc, (uintptr_t)rc,
				  (uintptr_t)((uint64_t)rc >> 32), 0, 0, 0);

	return rc;
}
