/*
 * FILE:        dtrace_syscall_stubs.S
 * DESCRIPTION: Dynamic Tracing: Syscall tracing stubs (arch-specific)
 *
 * Copyright (C) 2010-2014 Oracle Corporation
 */

#include <linux/linkage.h>
#include <asm/head.h>
#include <asm/ptrace.h>
#include <asm/signal.h>
#include <asm/thread_info.h>

	ENTRY(dtrace_stub_execve)
	set	dtrace_sys_execve, %g1
	jmpl	%g1, %g0
	 flushw
	ENDPROC(dtrace_stub_execve)

	ENTRY(dtrace_stub_pipe)
	ba,pt	%xcc, dtrace_sys_pipe
	 add	%sp, PTREGS_OFF, %o0
	ENDPROC(dtrace_stub_pipe)

	ENTRY(dtrace_stub_memory_ordering)
	ba,pt	%xcc, dtrace_sys_memory_ordering
	 add	%sp, PTREGS_OFF, %o1
	ENDPROC(dtrace_stub_memory_ordering)

	ENTRY(dtrace_stub_sigaltstack)
	ba,pt	%xcc, dtrace_sys_sigaltstack
	 add	%i6, STACK_BIAS, %o2
	ENDPROC(dtrace_stub_sigaltstack)

	ENTRY(dtrace_stub_rt_sigreturn)
	add	%sp, PTREGS_OFF, %o0
	call	dtrace_sys_rt_sigreturn
	 add	%o7, 1f-.-4, %o7
	nop
	.align	32
1:	ldx	[%g6 + TI_FLAGS], %l5
	andcc	%l5, (_TIF_SYSCALL_TRACE|_TIF_SECCOMP|_TIF_SYSCALL_AUDIT|_TIF_SYSCALL_TRACEPOINT), %g0
	be,pt	%icc, 2f
	 nop
	call	syscall_trace_leave
	 add	%sp, PTREGS_OFF, %o0
2:	set	rtrap, %g1
	jmpl	%g1, %g0
	 nop
	ENDPROC(dtrace_stub_rt_sigreturn)

	ENTRY(dtrace_stub_vfork)
	sethi	%hi(0x4000 | 0x0100 | SIGCHLD), %o0
	or	%o0, %lo(0x4000 | 0x0100 | SIGCHLD), %o0
	ba,pt	%xcc, dtrace_stub_clone

	ENTRY(dtrace_stub_fork)
	 clr	%o1
	mov	SIGCHLD, %o0

	ENTRY(dtrace_stub_clone)
	flushw
	movrz	%o1, %fp, %o1
	mov	0, %o3
	ba,pt	%xcc, dtrace_sys_clone
	 add	%sp, PTREGS_OFF, %o2
	ENDPROC(dtrace_stub_clone)
	ENDPROC(dtrace_stub_fork)
	ENDPROC(dtrace_stub_vfork)

	ENTRY(dtrace_stub_exit_group)
	sethi	%hi(dtrace_sys_exit_group), %g7
	ba,pt	%xcc, 1f
	 or	%g7, %lo(dtrace_sys_exit_group), %g7
	ENDPROC(dtrace_stub_exit_group)

	ENTRY(dtrace_stub_exit)
	sethi	%hi(dtrace_sys_exit), %g7
	or	%g7, %lo(dtrace_sys_exit), %g7
1:	rdpr	%pstate, %g2
	wrpr	%g2, PSTATE_IE, %pstate
	rdpr	%otherwin, %g1
	rdpr	%cansave, %g3
	add	%g3, %g1, %g3
	wrpr	%g3, 0x0, %cansave
	wrpr	%g0, 0x0, %otherwin
	wrpr	%g2, 0x0, %pstate
	jmpl	%g7, %g0
	stb	%g0, [%g6 + TI_WSAVED]
	ENDPROC(dtrace_stub_exit)
