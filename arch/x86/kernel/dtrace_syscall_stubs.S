/*
 * FILE:        dtrace_stubs_x86_64.S
 * DESCRIPTION: Dynamic Tracing: Syscall tracing stubs (arch-specific)
 *
 * Copyright (C) 2010-2016 Oracle Corporation
 */

#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/cache.h>
#include <asm/errno.h>
#include "../entry/calling.h"
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
#define AUDIT_ARCH_X86_64			(EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#define __AUDIT_ARCH_64BIT 			0x80000000
#define __AUDIT_ARCH_LE	 			0x40000000

.code64
.section .entry.text, "ax"

	.macro FORK_LIKE func
ENTRY(dtrace_stub_\func)
	SAVE_EXTRA_REGS 8
	jmp	dtrace_sys_\func
END(dtrace_stub_\func)
	.endm

        FORK_LIKE  clone
        FORK_LIKE  fork
        FORK_LIKE  vfork

ENTRY(dtrace_stub_execve)
	call	dtrace_sys_execve
return_from_execve:
        testl	%eax, %eax
        jz	1f
        /* exec failed, can use fast SYSRET code path in this case */
        ret
1:
        /* must use IRET code path (pt_regs->cs may have changed) */
        addq	$8, %rsp
        ZERO_EXTRA_REGS
        movq	%rax,RAX(%rsp)
        jmp	int_ret_from_sys_call
END(dtrace_stub_execve)

GLOBAL(dtrace_stub_execveat)
	call	dtrace_sys_execveat
	jmp	return_from_execve
END(dtrace_stub_execveat)

/*
 * sigreturn is special because it needs to restore all registers on return.
 * This cannot be done with SYSRET, so use the IRET return path instead.
 */
ENTRY(dtrace_stub_rt_sigreturn)
	SAVE_EXTRA_REGS 8
	call	dtrace_sys_rt_sigreturn
	addq	$8, %rsp
	RESTORE_EXTRA_REGS
	movq	%rax,RAX(%rsp)
	jmp	int_ret_from_sys_call
END(dtrace_stub_rt_sigreturn)
