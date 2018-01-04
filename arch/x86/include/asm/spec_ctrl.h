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

#define __ASM_STUFF_RSB				\
	call	1f;				\
	pause;					\
1:	call	2f;				\
	pause;					\
2:	call	3f;				\
	pause;					\
3:	call	4f;				\
	pause;					\
4:	call	5f;				\
	pause;					\
5:	call	6f;				\
	pause;					\
6:	call	7f;				\
	pause;					\
7:	call	8f;				\
	pause;					\
8:	call	9f;				\
	pause;					\
9:	call	10f;				\
	pause;					\
10:	call	11f;				\
	pause;					\
11:	call	12f;				\
	pause;					\
12:	call	13f;				\
	pause;					\
13:	call	14f;				\
	pause;					\
14:	call	15f;				\
	pause;					\
15:	call	16f;				\
	pause;					\
16:	call	17f;				\
	pause;					\
17:	call	18f;				\
	pause;					\
18:	call	19f;				\
	pause;					\
19:	call	20f;				\
	pause;					\
20:	call	21f;				\
	pause;					\
21:	call	22f;				\
	pause;					\
22:	call	23f;				\
	pause;					\
23:	call	24f;				\
	pause;					\
24:	call	25f;				\
	pause;					\
25:	call	26f;				\
	pause;					\
26:	call	27f;				\
	pause;					\
27:	call	28f;				\
	pause;					\
28:	call	29f;				\
	pause;					\
29:	call	30f;				\
	pause;					\
30:	call	31f;				\
	pause;					\
31:	call	32f;				\
	pause;					\
32:						\
	add $(32*8), %rsp;

.macro ENABLE_IBRS
ALTERNATIVE "", __stringify(__ASM_ENABLE_IBRS), X86_FEATURE_SPEC_CTRL
.endm

.macro ENABLE_IBRS_CLOBBER
	testl	$1, use_ibrs
	jz	11f
	__ASM_ENABLE_IBRS_CLOBBER
11:
.endm

.macro ENABLE_IBRS_SAVE_AND_CLOBBER save_reg:req
	testl	$1, use_ibrs
	jz	12f

	movl	$MSR_IA32_SPEC_CTRL, %ecx
	rdmsr
	movl	%eax, \save_reg

	movl	$0, %edx
	movl	$FEATURE_ENABLE_IBRS, %eax
	wrmsr
	jmp 22f
12:
	lfence
22:
.endm

.macro RESTORE_IBRS_CLOBBER save_reg:req
	testl	$1, use_ibrs
	jz	13f

	cmpl	$FEATURE_ENABLE_IBRS, \save_reg
	je	13f

	movl	$MSR_IA32_SPEC_CTRL, %ecx
	movl	$0, %edx
	movl	\save_reg, %eax
	wrmsr
	jmp 23f
13:
	lfence
23:
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

.macro STUFF_RSB
ALTERNATIVE __stringify(__ASM_STUFF_RSB), "", X86_FEATURE_SMEP
.endm

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_SPEC_CTRL_H */
