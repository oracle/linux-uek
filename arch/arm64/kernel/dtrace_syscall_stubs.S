/*
 * FILE:        dtrace_stubs_arm64.S
 * DESCRIPTION: Dynamic Tracing: Syscall tracing stubs (arch-specific)
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
 */
#include <linux/linkage.h>

ENTRY(dtrace_stub_rt_sigreturn)
	mov	x0, sp
	b	sys_rt_sigreturn
ENDPROC(dtrace_stub_rt_sigreturn)
