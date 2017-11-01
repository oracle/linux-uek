/*
 * FILE:        dtrace_stubs_x86_64.S
 * DESCRIPTION: Dynamic Tracing: Syscall tracing stubs (arch-specific)
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
 */
#include <linux/linkage.h>
#include <asm/asm.h>

	.code64
	.section .entry.text, "ax"

ENTRY(dtrace_stub_ptregs)
	leaq	systrace_syscall(%rip), %rax
	jmp	stub_ptregs_64
END(dtrace_stub_ptregs)
