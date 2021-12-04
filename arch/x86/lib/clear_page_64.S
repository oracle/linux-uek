/* SPDX-License-Identifier: GPL-2.0-only */
#include <linux/linkage.h>
#include <asm/export.h>

/*
 * Most CPUs support enhanced REP MOVSB/STOSB instructions. It is
 * recommended to use this when possible and we do use them by default.
 * If enhanced REP MOVSB/STOSB is not available, try to use fast string.
 * Otherwise, use original.
 */

/*
 * Zero a page.
 * %rdi	- page
 */
ENTRY(clear_page_rep)
	movl $4096/8,%ecx
	xorl %eax,%eax
	rep stosq
	RET
ENDPROC(clear_page_rep)
EXPORT_SYMBOL_GPL(clear_page_rep)

ENTRY(clear_page_orig)
	xorl   %eax,%eax
	movl   $4096/64,%ecx
	.p2align 4
.Lloop:
	decl	%ecx
#define PUT(x) movq %rax,x*8(%rdi)
	movq %rax,(%rdi)
	PUT(1)
	PUT(2)
	PUT(3)
	PUT(4)
	PUT(5)
	PUT(6)
	PUT(7)
	leaq	64(%rdi),%rdi
	jnz	.Lloop
	nop
	RET
ENDPROC(clear_page_orig)
EXPORT_SYMBOL_GPL(clear_page_orig)

ENTRY(clear_page_erms)
	movl $4096,%ecx
	xorl %eax,%eax
	rep stosb
	RET
ENDPROC(clear_page_erms)
EXPORT_SYMBOL_GPL(clear_page_erms)

/*
 * Zero a page.
 * %rdi - page
 *
 * Caller needs to issue a fence at the end.
 */
ENTRY(clear_page_nt)
	xorl	%eax,%eax
	movl	$4096,%ecx

	.p2align 4
.Lstart:
        movnti  %rax, 0x00(%rdi)
        movnti  %rax, 0x08(%rdi)
        movnti  %rax, 0x10(%rdi)
        movnti  %rax, 0x18(%rdi)
        movnti  %rax, 0x20(%rdi)
        movnti  %rax, 0x28(%rdi)
        movnti  %rax, 0x30(%rdi)
        movnti  %rax, 0x38(%rdi)
        addq    $0x40, %rdi
        subl    $0x40, %ecx
        ja      .Lstart
	RET
ENDPROC(clear_page_nt)
EXPORT_SYMBOL_GPL(clear_page_nt)

/*
 * Zero a page using clzero (on AMD.)
 * %rdi - page
 *
 * Caller needs to issue a sfence at the end.
 */
ENTRY(clear_page_clzero)
	movl	$4096,%ecx
	movq	%rdi,%rax

	.p2align 4
.Liter:
	clzero
	addq    $0x40, %rax
	sub     $0x40, %ecx
	ja      .Liter
	RET
ENDPROC(clear_page_clzero)
EXPORT_SYMBOL_GPL(clear_page_clzero)
