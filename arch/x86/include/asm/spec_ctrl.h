#ifndef _ASM_X86_SPEC_CTRL_H
#define _ASM_X86_SPEC_CTRL_H

#include <linux/stringify.h>
#include <asm/msr-index.h>
#include <asm/cpufeature.h>
#include <asm/alternative-asm.h>

#ifdef __ASSEMBLY__

.extern use_ibrs

#define __ASM_ENABLE_IBRS			\
	pushq %rax;				\
	pushq %rcx;				\
	pushq %rdx;				\
	movl $MSR_IA32_SPEC_CTRL, %ecx;		\
	movl $0, %edx;				\
	movl $FEATURE_ENABLE_IBRS, %eax;	\
	wrmsr;					\
	popq %rdx;				\
	popq %rcx;				\
	popq %rax
#define __ASM_ENABLE_IBRS_CLOBBER		\
	movl $MSR_IA32_SPEC_CTRL, %ecx;		\
	movl $0, %edx;				\
	movl $FEATURE_ENABLE_IBRS, %eax;	\
	wrmsr;
#define __ASM_DISABLE_IBRS			\
	pushq %rax;				\
	pushq %rcx;				\
	pushq %rdx;				\
	movl $MSR_IA32_SPEC_CTRL, %ecx;		\
	movl $0, %edx;				\
	movl $0, %eax;				\
	wrmsr;					\
	popq %rdx;				\
	popq %rcx;				\
	popq %rax
#define __ASM_SET_IBPB				\
	pushq %rax;				\
	pushq %rcx;				\
	pushq %rdx;				\
	movl $MSR_IA32_PRED_CMD, %ecx;		\
	movl $0, %edx;				\
	movl $FEATURE_SET_IBPB, %eax;		\
	wrmsr;					\
	popq %rdx;				\
	popq %rcx;				\
	popq %rax
#define __ASM_DISABLE_IBRS_CLOBBER		\
	movl $MSR_IA32_SPEC_CTRL, %ecx;		\
	movl $0, %edx;				\
	movl $0, %eax;				\
	wrmsr;

.macro ENABLE_IBRS
ALTERNATIVE "", __stringify(__ASM_ENABLE_IBRS), X86_FEATURE_SPEC_CTRL
.endm

.macro ENABLE_IBRS_CLOBBER
	testl	$1, use_ibrs
	jz	11f
	__ASM_ENABLE_IBRS_CLOBBER
11:
.endm

.macro DISABLE_IBRS
ALTERNATIVE "", __stringify(__ASM_DISABLE_IBRS), X86_FEATURE_SPEC_CTRL
.endm

.macro SET_IBPB
ALTERNATIVE "", __stringify(__ASM_SET_IBPB), X86_FEATURE_SPEC_CTRL
.endm

.macro DISABLE_IBRS_CLOBBER
ALTERNATIVE "", __stringify(__ASM_DISABLE_IBRS_CLOBBER), X86_FEATURE_SPEC_CTRL
.endm

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_SPEC_CTRL_H */
