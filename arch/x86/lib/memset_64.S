/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2002 Andi Kleen, SuSE Labs */

#include <linux/linkage.h>
#include <asm/cpufeatures.h>
#include <asm/alternative-asm.h>
#include <asm/export.h>

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
 */
SYM_FUNC_START_WEAK(memset)
ENTRY(__memset)
	/*
	 * Some CPUs support enhanced REP MOVSB/STOSB feature. It is recommended
	 * to use it when possible. If not available, use fast string instructions.
	 *
	 * Otherwise, use original memset function.
	 */
	ALTERNATIVE_2 "jmp memset_movq", "", X86_FEATURE_REP_GOOD, \
		      "jmp memset_erms", X86_FEATURE_ERMS

	movq %rdi,%r9
	movq %rdx,%rcx
	andl $7,%edx
	shrq $3,%rcx
	/* expand byte value  */
	movzbl %sil,%esi
	movabs $0x0101010101010101,%rax
	imulq %rsi,%rax
	rep stosq
	movl %edx,%ecx
	rep stosb
	movq %r9,%rax
	RET
ENDPROC(memset)
ENDPROC(__memset)
EXPORT_SYMBOL(memset)
EXPORT_SYMBOL(__memset)

/*
 * ISO C memset - set a memory block to a byte value. This function uses
 * enhanced rep stosb to override the fast string function.
 * The code is simpler and shorter than the fast string function as well.
 *
 * rdi   destination
 * rsi   value (char)
 * rdx   count (bytes)
 *
 * rax   original destination
 */
ENTRY(memset_erms)
	movq %rdi,%r9
	movb %sil,%al
	movq %rdx,%rcx
	rep stosb
	movq %r9,%rax
	RET
ENDPROC(memset_erms)

.macro MEMSET_MOV OP fence
ENTRY(memset_\OP)
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
ENDPROC(memset_\OP)
.endm

MEMSET_MOV OP=movq fence=0
MEMSET_MOV OP=movnti fence=1
