/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2002 Andi Kleen, SuSE Labs */

#include <linux/export.h>
#include <linux/linkage.h>
#include <asm/cpufeatures.h>
#include <asm/alternative.h>

.section .noinstr.text, "ax"

/*
 * ISO C memset - set a memory block to a byte value. This function uses fast
 * string to get better performance than the original function. The code is
 * simpler and shorter than the original function as well.
 *
 * rdi   destination
 * rsi   value (char)
 * rdx   count (bytes)
 *
 * rax   original destination
 *
 * The FSRS alternative should be done inline (avoiding the call and
 * the disgusting return handling), but that would require some help
 * from the compiler for better calling conventions.
 *
 * The 'rep stosb' itself is small enough to replace the call, but all
 * the register moves blow up the code. And two of them are "needed"
 * only for the return value that is the same as the source input,
 * which the compiler could/should do much better anyway.
 */
SYM_FUNC_START(__memset)
	ALTERNATIVE "jmp memset_movq", "", X86_FEATURE_FSRS

	movq %rdi,%r9
	movb %sil,%al
	movq %rdx,%rcx
	rep stosb
	movq %r9,%rax
	RET
SYM_FUNC_END(__memset)
EXPORT_SYMBOL(__memset)

SYM_FUNC_ALIAS_MEMFUNC(memset, __memset)
EXPORT_SYMBOL(memset)

.macro MEMSET_MOV OP fence
SYM_FUNC_START_LOCAL(memset_\OP)
	movq %rdi,%r10

	/* expand byte value  */
	movzbl %sil,%ecx
	movabs $0x0101010101010101,%rax
	imulq  %rcx,%rax

	/* align dst */
	movl  %edi,%r9d
	andl  $7,%r9d
	jnz  .Lbad_alignment_\@
.Lafter_bad_alignment_\@:

	movq  %rdx,%rcx
	shrq  $6,%rcx
	jz	 .Lhandle_tail_\@

	.p2align 4
.Lloop_64_\@:
	decq  %rcx
	\OP  %rax,(%rdi)
	\OP  %rax,8(%rdi)
	\OP  %rax,16(%rdi)
	\OP  %rax,24(%rdi)
	\OP  %rax,32(%rdi)
	\OP  %rax,40(%rdi)
	\OP  %rax,48(%rdi)
	\OP  %rax,56(%rdi)
	leaq  64(%rdi),%rdi
	jnz    .Lloop_64_\@

	/* Handle tail in loops. The loops should be faster than hard
	   to predict jump tables. */
	.p2align 4
.Lhandle_tail_\@:
	movl	%edx,%ecx
	andl    $63&(~7),%ecx
	jz 		.Lhandle_7_\@
	shrl	$3,%ecx
	.p2align 4
.Lloop_8_\@:
	decl   %ecx
	\OP  %rax,(%rdi)
	leaq  8(%rdi),%rdi
	jnz    .Lloop_8_\@

.Lhandle_7_\@:
	andl	$7,%edx
	jz      .Lende_\@
	.p2align 4
.Lloop_1_\@:
	decl    %edx
	movb 	%al,(%rdi)
	leaq	1(%rdi),%rdi
	jnz     .Lloop_1_\@

.Lende_\@:
	.if \fence
	sfence
	.endif
	movq	%r10,%rax
	RET

.Lbad_alignment_\@:
	cmpq $7,%rdx
	jbe	.Lhandle_7_\@
	movq %rax,(%rdi)	/* unaligned store */
	movq $8,%r8
	subq %r9,%r8
	addq %r8,%rdi
	subq %r8,%rdx
	jmp .Lafter_bad_alignment_\@
.Lfinal_\@:
SYM_FUNC_END(memset_\OP)
.endm

MEMSET_MOV OP=movq fence=0
MEMSET_MOV OP=movnti fence=1
