/*
 * FILE:        dtrace_stubs_x86_64.S
 * DESCRIPTION: Dynamic Tracing: Syscall tracing stubs (arch-specific)
 *
 * Copyright (C) 2010-2014 Oracle Corporation
 */

#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/cache.h>
#include <asm/errno.h>
#include <asm/dwarf2.h>
#include <asm/calling.h>
#include <asm/asm-offsets.h>
#include <asm/msr.h>
#include <asm/unistd.h>
#include <asm/thread_info.h>
#include <asm/hw_irq.h>
#include <asm/page_types.h>
#include <asm/irqflags.h>
#include <asm/paravirt.h>
#include <asm/ftrace.h>
#include <asm/percpu.h>

/* Avoid __ASSEMBLER__'ifying <linux/audit.h> just for this.  */
#include <linux/elf-em.h>
#define AUDIT_ARCH_X86_64	(EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#define __AUDIT_ARCH_64BIT 0x80000000
#define __AUDIT_ARCH_LE	   0x40000000

	.code64
	.section .entry.text, "ax"

/*
 * C code is not supposed to know about undefined top of stack. Every time
 * a C function with an pt_regs argument is called from the SYSCALL based
 * fast path FIXUP_TOP_OF_STACK is needed.
 * RESTORE_TOP_OF_STACK syncs the syscall state after any possible ptregs
 * manipulation.
 */

	/* %rsp:at FRAMEEND */
	.macro FIXUP_TOP_OF_STACK tmp offset=0
	movq PER_CPU_VAR(old_rsp),\tmp
	movq \tmp,RSP+\offset(%rsp)
	movq $__USER_DS,SS+\offset(%rsp)
	movq $__USER_CS,CS+\offset(%rsp)
	movq $-1,RCX+\offset(%rsp)
	movq R11+\offset(%rsp),\tmp  /* get eflags */
	movq \tmp,EFLAGS+\offset(%rsp)
	.endm

	.macro RESTORE_TOP_OF_STACK tmp offset=0
	movq RSP+\offset(%rsp),\tmp
	movq \tmp,PER_CPU_VAR(old_rsp)
	movq EFLAGS+\offset(%rsp),\tmp
	movq \tmp,R11+\offset(%rsp)
	.endm

/*
 * empty frame
 */
	.macro EMPTY_FRAME start=1 offset=0
	.if \start
	CFI_STARTPROC simple
	CFI_SIGNAL_FRAME
	CFI_DEF_CFA rsp,8+\offset
	.else
	CFI_DEF_CFA_OFFSET 8+\offset
	.endif
	.endm

/*
 * initial frame state for interrupts (and exceptions without error code)
 */
	.macro INTR_FRAME start=1 offset=0
	EMPTY_FRAME \start, 5*8+\offset
	/*CFI_REL_OFFSET ss, 4*8+\offset*/
	CFI_REL_OFFSET rsp, 3*8+\offset
	/*CFI_REL_OFFSET rflags, 2*8+\offset*/
	/*CFI_REL_OFFSET cs, 1*8+\offset*/
	CFI_REL_OFFSET rip, 0*8+\offset
	.endm

/*
 * initial frame state for exceptions with error code (and interrupts
 * with vector already pushed)
 */
	.macro XCPT_FRAME start=1 offset=0
	INTR_FRAME \start, 1*8+\offset
	.endm

/*
 * frame that enables passing a complete pt_regs to a C function.
 */
	.macro DEFAULT_FRAME start=1 offset=0
	XCPT_FRAME \start, ORIG_RAX+\offset
	CFI_REL_OFFSET rdi, RDI+\offset
	CFI_REL_OFFSET rsi, RSI+\offset
	CFI_REL_OFFSET rdx, RDX+\offset
	CFI_REL_OFFSET rcx, RCX+\offset
	CFI_REL_OFFSET rax, RAX+\offset
	CFI_REL_OFFSET r8, R8+\offset
	CFI_REL_OFFSET r9, R9+\offset
	CFI_REL_OFFSET r10, R10+\offset
	CFI_REL_OFFSET r11, R11+\offset
	CFI_REL_OFFSET rbx, RBX+\offset
	CFI_REL_OFFSET rbp, RBP+\offset
	CFI_REL_OFFSET r12, R12+\offset
	CFI_REL_OFFSET r13, R13+\offset
	CFI_REL_OFFSET r14, R14+\offset
	CFI_REL_OFFSET r15, R15+\offset
	.endm

	.macro FORK_LIKE func
ENTRY(dtrace_stub_\func)
	CFI_STARTPROC
	DEFAULT_FRAME 0, 8
	SAVE_EXTRA_REGS 8
	jmp dtrace_sys_\func
	CFI_ENDPROC
END(dtrace_stub_\func)
	.endm

        FORK_LIKE  clone
        FORK_LIKE  fork
        FORK_LIKE  vfork

ENTRY(dtrace_stub_execve)
	CFI_STARTPROC
	DEFAULT_FRAME 0, 8
	call dtrace_sys_execve
return_from_execve:
        testl %eax, %eax
        jz 1f
        /* exec failed, can use fast SYSRET code path in this case */
        ret
1:
        /* must use IRET code path (pt_regs->cs may have changed) */
        addq $8, %rsp
        CFI_ADJUST_CFA_OFFSET -8
        ZERO_EXTRA_REGS
        movq %rax,RAX(%rsp)
        jmp int_ret_from_sys_call
	CFI_ENDPROC
END(dtrace_stub_execve)

GLOBAL(dtrace_stub_execveat)
	CFI_STARTPROC
	DEFAULT_FRAME 0, 8
	call dtrace_sys_execveat
	jmp return_from_execve
	CFI_ENDPROC
END(dtrace_stub_execveat)

/*
 * sigreturn is special because it needs to restore all registers on return.
 * This cannot be done with SYSRET, so use the IRET return path instead.
 */
ENTRY(dtrace_stub_rt_sigreturn)
	CFI_STARTPROC
	DEFAULT_FRAME 0, 8
	SAVE_EXTRA_REGS 8
	call dtrace_sys_rt_sigreturn
	addq    $8, %rsp
	CFI_ADJUST_CFA_OFFSET -8
	RESTORE_EXTRA_REGS
	movq %rax,RAX(%rsp)
	jmp int_ret_from_sys_call
	CFI_ENDPROC
END(dtrace_stub_rt_sigreturn)
