#ifndef _ASM_X86_SPEC_CTRL_H
#define _ASM_X86_SPEC_CTRL_H

#include <linux/stringify.h>
#include <asm/msr-index.h>
#include <asm/cpufeatures.h>
#include <asm/alternative-asm.h>

#ifdef __ASSEMBLY__

.macro PUSH_MSR_REGS
	pushq %rax
	pushq %rcx
	pushq %rdx
.endm

.macro POP_MSR_REGS
	popq %rdx
	popq %rcx
	popq %rax
.endm

.macro WRMSR_ASM msr_nr:req eax_val:req
	movl	\msr_nr, %ecx
	movl	$0, %edx
	movl	\eax_val, %eax
	wrmsr
.endm

.macro ENABLE_IBRS
	ALTERNATIVE "jmp .Lskip_\@", "", X86_FEATURE_SPEC_CTRL
	PUSH_MSR_REGS
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, $SPEC_CTRL_IBRS
	POP_MSR_REGS
.Lskip_\@:
.endm

.macro DISABLE_IBRS
	ALTERNATIVE "jmp .Lskip_\@", "", X86_FEATURE_SPEC_CTRL
	PUSH_MSR_REGS
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, $0
	POP_MSR_REGS
.Lskip_\@:
.endm

.macro ENABLE_IBRS_CLOBBER
	ALTERNATIVE "jmp .Lskip_\@", "", X86_FEATURE_SPEC_CTRL
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, $SPEC_CTRL_IBRS
.Lskip_\@:
.endm

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_SPEC_CTRL_H */
