#ifndef _ASM_X86_SPEC_CTRL_H
#define _ASM_X86_SPEC_CTRL_H

#include <linux/stringify.h>
#include <asm/msr-index.h>
#include <asm/cpufeatures.h>
#include <asm/alternative-asm.h>

#define SPEC_CTRL_IBRS_INUSE           (1<<0)  /* OS enables IBRS usage */
#define SPEC_CTRL_IBRS_SUPPORTED       (1<<1)  /* System supports IBRS */
#define SPEC_CTRL_IBRS_ADMIN_DISABLED  (1<<2)  /* Admin disables IBRS */

#ifdef __ASSEMBLY__

.extern use_ibrs

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
	testl	$SPEC_CTRL_IBRS_INUSE, use_ibrs
	jz	.Lskip_\@
	PUSH_MSR_REGS
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, $SPEC_CTRL_FEATURE_ENABLE_IBRS
	POP_MSR_REGS
	jmp	.Ldone_\@
.Lskip_\@:
	 lfence
.Ldone_\@:
.endm

.macro DISABLE_IBRS
	testl	$1, use_ibrs
	jz	.Lskip_\@
	PUSH_MSR_REGS
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, $0
	POP_MSR_REGS
.Lskip_\@:
.endm

.macro ENABLE_IBRS_SAVE_AND_CLOBBER save_reg:req
	testl	$SPEC_CTRL_IBRS_INUSE, use_ibrs
	jz	.Lskip_\@

	movl	$MSR_IA32_SPEC_CTRL, %ecx
	rdmsr
	movl	%eax, \save_reg

	movl	$0, %edx
	movl	$SPEC_CTRL_FEATURE_ENABLE_IBRS, %eax
	wrmsr
	jmp	.Ldone_\@
.Lskip_\@:
	lfence
.Ldone_\@:
.endm

.macro RESTORE_IBRS_CLOBBER save_reg:req
	testl	$SPEC_CTRL_IBRS_INUSE, use_ibrs
	jz	.Lskip_\@

	cmpl	$SPEC_CTRL_FEATURE_ENABLE_IBRS, \save_reg
	je	.Lskip_\@

	movl	$MSR_IA32_SPEC_CTRL, %ecx
	movl	$0, %edx
	movl	\save_reg, %eax
	wrmsr
	jmp	.Ldone_\@
.Lskip_\@:
	lfence
.Ldone_\@:
.endm

.macro ENABLE_IBRS_CLOBBER
	testl	$SPEC_CTRL_IBRS_INUSE, use_ibrs
	jz	.Lskip_\@
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, $SPEC_CTRL_FEATURE_ENABLE_IBRS
	jmp	.Ldone_\@
.Lskip_\@:
	 lfence
.Ldone_\@:
.endm

.macro DISABLE_IBRS_CLOBBER
	testl	$SPEC_CTRL_IBRS_INUSE, use_ibrs
	jz	.Lskip_\@
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, $0
.Lskip_\@:
.endm

.macro STUFF_RSB_NON_SMEP
	ALTERNATIVE __stringify(__ASM_STUFF_RSB), "", X86_FEATURE_SMEP
.endm

#else
enum {
	IBRS_DISABLED,
	/* in host kernel, disabled in guest and userland */
	IBRS_ENABLED,
	/* in host kernel and host userland, disabled in guest */
	IBRS_ENABLED_USER,
	IBRS_MAX = IBRS_ENABLED_USER,
};
#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_SPEC_CTRL_H */
