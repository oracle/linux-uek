/*
 * Dynamic Tracing for Linux - x86 specific assembly
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/linkage.h>
#include <asm/smap.h>

#define CPU_DTRACE_BADADDR	0x0004	/* DTrace fault: bad address */

#if defined(__x86_64__)
	ENTRY(dtrace_caller)
	movq	$-1, %rax
	ret
	ENDPROC(dtrace_caller)

#elif defined(__i386__)

	ENTRY(dtrace_caller)
	movl	$-1, %eax
	ret
	ENDPROC(dtrace_caller)

#endif	/* __i386__ */

#if defined(__x86_64__)

	ENTRY(dtrace_copy)
	pushq	%rbp
	movq	%rsp, %rbp

	ASM_STAC
	xchgq	%rdi, %rsi		# make %rsi source, %rdi dest
	movq	%rdx, %rcx		# load count
	repz				# repeat for count ...
	smovb				#   move from %ds:rsi to %ed:rdi
	ASM_CLAC
	leave
	ret
	ENDPROC(dtrace_copy)

#elif defined(__i386__)

	ENTRY(dtrace_copy)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%esi
	pushl	%edi

	movl	8(%ebp), %esi		# Load source address
	movl	12(%ebp), %edi		# Load destination address
	movl	16(%ebp), %ecx		# Load count
	repz				# Repeat for count...
	smovb				#   move from %ds:si to %es:di

	popl	%edi
	popl	%esi
	movl	%ebp, %esp
	popl	%ebp
	ret
	ENDPROC(dtrace_copy)

#endif	/* __i386__ */

#if defined(__x86_64__)

	ENTRY(dtrace_copystr)
	pushq	%rbp
	movq	%rsp, %rbp

	ASM_STAC
0:
	movb	(%rdi), %al		# load from source
	movb	%al, (%rsi)		# store to destination
	addq	$1, %rdi		# increment source pointer
	addq	$1, %rsi		# increment destination pointer
	subq	$1, %rdx		# decrement remaining count
	cmpb	$0, %al
	je	2f
	testq	$0xfff, %rdx		# test if count is 4k-aligned
	jnz	1f			# if not, continue with copying
	testq	$CPU_DTRACE_BADADDR, (%rcx) # load and test dtrace flags
	jnz	2f
1:
	cmpq	$0, %rdx
	jne	0b
2:
	ASM_CLAC
	leave
	ret

	ENDPROC(dtrace_copystr)

#elif defined(__i386__)

	ENTRY(dtrace_copystr)

	pushl	%ebp			# Setup stack frame
	movl	%esp, %ebp
	pushl	%ebx			# Save registers

	movl	8(%ebp), %ebx		# Load source address
	movl	12(%ebp), %edx		# Load destination address
	movl	16(%ebp), %ecx		# Load count

0:
	movb	(%ebx), %al		# Load from source
	movb	%al, (%edx)		# Store to destination
	incl	%ebx			# Increment source pointer
	incl	%edx			# Increment destination pointer
	decl	%ecx			# Decrement remaining count
	cmpb	$0, %al
	je	2f
	testl	$0xfff, %ecx		# Check if count is 4k-aligned
	jnz	1f
	movl	20(%ebp), %eax		# load flags pointer
	testl	$CPU_DTRACE_BADADDR, (%eax) # load and test dtrace flags
	jnz	2f
1:
	cmpl	$0, %ecx
	jne	0b

2:
	popl	%ebx
	movl	%ebp, %esp
	popl	%ebp
	ret

	ENDPROC(dtrace_copystr)

#endif	/* __i386__ */

#if defined(__x86_64__)

	ENTRY(dtrace_fuword8_nocheck)
	xorq	%rax, %rax
	ASM_STAC
	movb	(%rdi), %al
	ASM_CLAC
	ret
	ENDPROC(dtrace_fuword8_nocheck)

#elif defined(__i386__)

	ENTRY(dtrace_fuword8_nocheck)
	movl	4(%esp), %ecx
	xorl	%eax, %eax
	movzbl	(%ecx), %eax
	ret
	ENDPROC(dtrace_fuword8_nocheck)

#endif	/* __i386__ */

#if defined(__x86_64__)

	ENTRY(dtrace_fuword16_nocheck)
	xorq	%rax, %rax
	ASM_STAC
	movw	(%rdi), %ax
	ASM_CLAC
	ret
	ENDPROC(dtrace_fuword16_nocheck)

#elif defined(__i386__)

	ENTRY(dtrace_fuword16_nocheck)
	movl	4(%esp), %ecx
	xorl	%eax, %eax
	movzwl	(%ecx), %eax
	ret
	ENDPROC(dtrace_fuword16_nocheck)

#endif	/* __i386__ */

#if defined(__x86_64__)

	ENTRY(dtrace_fuword32_nocheck)
	xorq	%rax, %rax
	ASM_STAC
	movl	(%rdi), %eax
	ASM_CLAC
	ret
	ENDPROC(dtrace_fuword32_nocheck)

#elif defined(__i386__)

	ENTRY(dtrace_fuword32_nocheck)
	movl	4(%esp), %ecx
	xorl	%eax, %eax
	movl	(%ecx), %eax
	ret
	ENDPROC(dtrace_fuword32_nocheck)

#endif	/* __i386__ */

#if defined(__x86_64__)

	ENTRY(dtrace_fuword64_nocheck)
	ASM_STAC
	movq	(%rdi), %rax
	ASM_CLAC
	ret
	ENDPROC(dtrace_fuword64_nocheck)

#elif defined(__i386__)

	ENTRY(dtrace_fuword64_nocheck)
	movl	4(%esp), %ecx
	xorl	%eax, %eax
	xorl	%edx, %edx
	movl	(%ecx), %eax
	movl	4(%ecx), %edx
	ret
	ENDPROC(dtrace_fuword64_nocheck)

#endif	/* __i386__ */
