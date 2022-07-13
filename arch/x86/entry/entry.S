/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Common place for both 32- and 64-bit entry routines.
 */

#include <linux/linkage.h>
#include <asm/export.h>
#include <asm/msr-index.h>

SYM_FUNC_START(entry_ibpb)
	push 	%rax
	push 	%rcx
	push 	%rdx
	movl	$MSR_IA32_PRED_CMD, %ecx
	movl	$PRED_CMD_IBPB, %eax
	xorl	%edx, %edx
	wrmsr
	pop	%rdx
	pop 	%rcx
	pop	%rax
	RET
SYM_FUNC_END(entry_ibpb)
/* For KVM */
EXPORT_SYMBOL_GPL(entry_ibpb);
