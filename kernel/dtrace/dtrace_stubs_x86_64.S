/*
 * FILE:        dtrace_stubs_x86_64.S
 * DESCRIPTION: Dynamic Tracing: x86_64 specific stubs (based on entry_64.S)
 *
 * Copyright (C) 2010, 2011 Oracle Corporation
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

	.macro FAKE_STACK_FRAME child_rip
	/* push in order ss, rsp, eflags, cs, rip */
	xorl %eax, %eax
	pushq_cfi $__KERNEL_DS /* ss */
	/*CFI_REL_OFFSET	ss,0*/
	pushq_cfi %rax /* rsp */
	CFI_REL_OFFSET	rsp,0
	pushq_cfi $X86_EFLAGS_IF /* eflags - interrupts on */
	/*CFI_REL_OFFSET	rflags,0*/
	pushq_cfi $__KERNEL_CS /* cs */
	/*CFI_REL_OFFSET	cs,0*/
	pushq_cfi \child_rip /* rip */
	CFI_REL_OFFSET	rip,0
	pushq_cfi %rax /* orig rax */
	.endm

	.macro UNFAKE_STACK_FRAME
	addq $8*6, %rsp
	CFI_ADJUST_CFA_OFFSET	-(6*8)
	.endm

/*
 * initial frame state for interrupts (and exceptions without error code)
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
	EMPTY_FRAME \start, SS+8+\offset-RIP
	/*CFI_REL_OFFSET ss, SS+\offset-RIP*/
	CFI_REL_OFFSET rsp, RSP+\offset-RIP
	/*CFI_REL_OFFSET rflags, EFLAGS+\offset-RIP*/
	/*CFI_REL_OFFSET cs, CS+\offset-RIP*/
	CFI_REL_OFFSET rip, RIP+\offset-RIP
	.endm

/*
 * initial frame state for exceptions with error code (and interrupts
 * with vector already pushed)
 */
	.macro XCPT_FRAME start=1 offset=0
	INTR_FRAME \start, RIP+\offset-ORIG_RAX
	/*CFI_REL_OFFSET orig_rax, ORIG_RAX-ORIG_RAX*/
	.endm

/*
 * frame that enables calling into C.
 */
	.macro PARTIAL_FRAME start=1 offset=0
	XCPT_FRAME \start, ORIG_RAX+\offset-ARGOFFSET
	CFI_REL_OFFSET rdi, RDI+\offset-ARGOFFSET
	CFI_REL_OFFSET rsi, RSI+\offset-ARGOFFSET
	CFI_REL_OFFSET rdx, RDX+\offset-ARGOFFSET
	CFI_REL_OFFSET rcx, RCX+\offset-ARGOFFSET
	CFI_REL_OFFSET rax, RAX+\offset-ARGOFFSET
	CFI_REL_OFFSET r8, R8+\offset-ARGOFFSET
	CFI_REL_OFFSET r9, R9+\offset-ARGOFFSET
	CFI_REL_OFFSET r10, R10+\offset-ARGOFFSET
	CFI_REL_OFFSET r11, R11+\offset-ARGOFFSET
	.endm

/*
 * frame that enables passing a complete pt_regs to a C function.
 */
	.macro DEFAULT_FRAME start=1 offset=0
	PARTIAL_FRAME \start, R11+\offset-R15
	CFI_REL_OFFSET rbx, RBX+\offset
	CFI_REL_OFFSET rbp, RBP+\offset
	CFI_REL_OFFSET r12, R12+\offset
	CFI_REL_OFFSET r13, R13+\offset
	CFI_REL_OFFSET r14, R14+\offset
	CFI_REL_OFFSET r15, R15+\offset
	.endm

/*
 * Certain special system calls that need to save a complete full stack frame.
 */
	.macro PTREGSCALL label,func,arg
ENTRY(\label)
	PARTIAL_FRAME 1 8		/* offset 8: return address */
	subq $REST_SKIP, %rsp
	CFI_ADJUST_CFA_OFFSET REST_SKIP
	call save_rest
	DEFAULT_FRAME 0 8		/* offset 8: return address */
	leaq 8(%rsp), \arg	/* pt_regs pointer */
	call \func
	jmp ptregscall_common
	CFI_ENDPROC
END(\label)
	.endm

	.macro FORK_LIKE func
ENTRY(dtrace_stub_\func)
	CFI_STARTPROC
	popq	%r11			/* save return address */
	PARTIAL_FRAME 0
	SAVE_REST
	pushq	%r11			/* put it back on stack */
	FIXUP_TOP_OF_STACK %r11, 8
	DEFAULT_FRAME 0 8		/* offset 8: return address */
	call dtrace_\func
	RESTORE_TOP_OF_STACK %r11, 8
	ret $REST_SKIP			/* pop extended registers */
	CFI_ENDPROC
END(dtrace_stub_\func)
	.endm

        FORK_LIKE  clone
        FORK_LIKE  fork
        FORK_LIKE  vfork
	PTREGSCALL dtrace_stub_iopl, dtrace_iopl, %rsi

ENTRY(dtrace_stub_execve)
	CFI_STARTPROC
	addq $8, %rsp
	PARTIAL_FRAME 0
	SAVE_REST
	FIXUP_TOP_OF_STACK %r11
	call dtrace_execve
	RESTORE_TOP_OF_STACK %r11
	movq %rax,RAX(%rsp)
	RESTORE_REST
	jmp int_ret_from_sys_call
	CFI_ENDPROC
END(dtrace_stub_execve)

/*
 * sigreturn is special because it needs to restore all registers on return.
 * This cannot be done with SYSRET, so use the IRET return path instead.
 */
ENTRY(dtrace_stub_rt_sigreturn)
	CFI_STARTPROC
	addq $8, %rsp
	PARTIAL_FRAME 0
	SAVE_REST
	movq %rsp,%rdi
	FIXUP_TOP_OF_STACK %r11
	call dtrace_rt_sigreturn
	movq %rax,RAX(%rsp) # fixme, this could be done at the higher layer
	RESTORE_REST
	jmp int_ret_from_sys_call
	CFI_ENDPROC
END(dtrace_stub_rt_sigreturn)
