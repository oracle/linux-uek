/*
 * Copyright (c) 2002-2005 Eric Biederman <ebiederm@xmission.com>
 * Copyright (c) 2011 Daniel Kiper
 * Copyright (c) 2012 Daniel Kiper, Oracle Corporation
 *
 * kexec/kdump implementation for Xen was written by Daniel Kiper.
 * Initial work on it was sponsored by Google under Google Summer
 * of Code 2011 program and Citrix. Konrad Rzeszutek Wilk from Oracle
 * was the mentor for this project.
 *
 * Some ideas are taken from:
 *   - native kexec/kdump implementation,
 *   - kexec/kdump implementation for Xen Linux Kernel Ver. 2.6.18,
 *   - PV-GRUB.
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
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <asm/page_types.h>
#include <asm/pgtable_types.h>
#include <asm/processor-flags.h>

#include <asm/xen/kexec.h>

#define PTR(x)	(x << 3)

	.text
	.code64
	.globl	xen_kexec_control_code_size, xen_relocate_kernel

xen_relocate_kernel:
	/*
	 * Must be relocatable PIC code callable as a C function.
	 *
	 * This function is called by Xen but here hypervisor is dead.
	 * We are playing on bare metal.
	 *
	 * Every machine address passed to this function through
	 * page_list (e.g. XK_MA_CONTROL_PAGE) is established
	 * by dom0 during kexec load phase.
	 *
	 * Every virtual address passed to this function through page_list
	 * (e.g. XK_VA_CONTROL_PAGE) is established by hypervisor during
	 * HYPERVISOR_kexec_op(KEXEC_CMD_kexec_load) hypercall.
	 *
	 * %rdi - indirection_page,
	 * %rsi - page_list,
	 * %rdx - start_address,
	 * %ecx - preserve_context (ignored).
	 */

	/* Zero out flags, and disable interrupts. */
	pushq	$0
	popfq

	/*
	 * Map the control page at its virtual address
	 * in transition page table.
	 */
	movq	PTR(XK_VA_CONTROL_PAGE)(%rsi), %r8

	/* Get PGD address and PGD entry index. */
	movq	PTR(XK_VA_PGD_PAGE)(%rsi), %r9
	movq	%r8, %r10
	shrq	$PGDIR_SHIFT, %r10
	andq	$(PTRS_PER_PGD - 1), %r10

	/* Fill PGD entry with PUD0 reference. */
	movq	PTR(XK_MA_PUD0_PAGE)(%rsi), %r11
	orq	$_KERNPG_TABLE, %r11
	movq	%r11, (%r9, %r10, 8)

	/* Get PUD0 address and PUD0 entry index. */
	movq	PTR(XK_VA_PUD0_PAGE)(%rsi), %r9
	movq	%r8, %r10
	shrq	$PUD_SHIFT, %r10
	andq	$(PTRS_PER_PUD - 1), %r10

	/* Fill PUD0 entry with PMD0 reference. */
	movq	PTR(XK_MA_PMD0_PAGE)(%rsi), %r11
	orq	$_KERNPG_TABLE, %r11
	movq	%r11, (%r9, %r10, 8)

	/* Get PMD0 address and PMD0 entry index. */
	movq	PTR(XK_VA_PMD0_PAGE)(%rsi), %r9
	movq	%r8, %r10
	shrq	$PMD_SHIFT, %r10
	andq	$(PTRS_PER_PMD - 1), %r10

	/* Fill PMD0 entry with PTE0 reference. */
	movq	PTR(XK_MA_PTE0_PAGE)(%rsi), %r11
	orq	$_KERNPG_TABLE, %r11
	movq	%r11, (%r9, %r10, 8)

	/* Get PTE0 address and PTE0 entry index. */
	movq	PTR(XK_VA_PTE0_PAGE)(%rsi), %r9
	movq	%r8, %r10
	shrq	$PAGE_SHIFT, %r10
	andq	$(PTRS_PER_PTE - 1), %r10

	/* Fill PTE0 entry with control page reference. */
	movq	PTR(XK_MA_CONTROL_PAGE)(%rsi), %r11
	orq	$__PAGE_KERNEL_EXEC, %r11
	movq	%r11, (%r9, %r10, 8)

	/*
	 * Identity map the control page at its machine address
	 * in transition page table.
	 */
	movq	PTR(XK_MA_CONTROL_PAGE)(%rsi), %r8

	/* Get PGD address and PGD entry index. */
	movq	PTR(XK_VA_PGD_PAGE)(%rsi), %r9
	movq	%r8, %r10
	shrq	$PGDIR_SHIFT, %r10
	andq	$(PTRS_PER_PGD - 1), %r10

	/* Fill PGD entry with PUD1 reference. */
	movq	PTR(XK_MA_PUD1_PAGE)(%rsi), %r11
	orq	$_KERNPG_TABLE, %r11
	movq	%r11, (%r9, %r10, 8)

	/* Get PUD1 address and PUD1 entry index. */
	movq	PTR(XK_VA_PUD1_PAGE)(%rsi), %r9
	movq	%r8, %r10
	shrq	$PUD_SHIFT, %r10
	andq	$(PTRS_PER_PUD - 1), %r10

	/* Fill PUD1 entry with PMD1 reference. */
	movq	PTR(XK_MA_PMD1_PAGE)(%rsi), %r11
	orq	$_KERNPG_TABLE, %r11
	movq	%r11, (%r9, %r10, 8)

	/* Get PMD1 address and PMD1 entry index. */
	movq	PTR(XK_VA_PMD1_PAGE)(%rsi), %r9
	movq	%r8, %r10
	shrq	$PMD_SHIFT, %r10
	andq	$(PTRS_PER_PMD - 1), %r10

	/* Fill PMD1 entry with PTE1 reference. */
	movq	PTR(XK_MA_PTE1_PAGE)(%rsi), %r11
	orq	$_KERNPG_TABLE, %r11
	movq	%r11, (%r9, %r10, 8)

	/* Get PTE1 address and PTE1 entry index. */
	movq	PTR(XK_VA_PTE1_PAGE)(%rsi), %r9
	movq	%r8, %r10
	shrq	$PAGE_SHIFT, %r10
	andq	$(PTRS_PER_PTE - 1), %r10

	/* Fill PTE1 entry with control page reference. */
	movq	PTR(XK_MA_CONTROL_PAGE)(%rsi), %r11
	orq	$__PAGE_KERNEL_EXEC, %r11
	movq	%r11, (%r9, %r10, 8)

	/*
	 * Get machine address of control page now.
	 * This is impossible after page table switch.
	 */
	movq	PTR(XK_MA_CONTROL_PAGE)(%rsi), %r8

	/* Get machine address of identity page table now too. */
	movq	PTR(XK_MA_TABLE_PAGE)(%rsi), %r9

	/* Get machine address of transition page table now too. */
	movq	PTR(XK_MA_PGD_PAGE)(%rsi), %r10

	/* Switch to transition page table. */
	movq	%r10, %cr3

	/* Setup a new stack at the end of machine address of control page. */
	leaq	PAGE_SIZE(%r8), %rsp

	/* Store start_address on the stack. */
	pushq   %rdx

	/* Jump to identity mapped page. */
	addq	$(identity_mapped - xen_relocate_kernel), %r8
	jmpq	*%r8

identity_mapped:
	/* Switch to identity page table. */
	movq	%r9, %cr3

	/*
	 * Set %cr0 to a known state:
	 *   - disable alignment check,
	 *   - disable floating point emulation,
	 *   - no task switch,
	 *   - disable write protect,
	 *   - enable protected mode,
	 *   - enable paging.
	 */
	movq	%cr0, %rax
	andq	$~(X86_CR0_AM | X86_CR0_EM | X86_CR0_TS | X86_CR0_WP), %rax
	orl	$(X86_CR0_PE | X86_CR0_PG), %eax
	movq	%rax, %cr0

	/*
	 * Set %cr4 to a known state:
	 *   - enable physical address extension.
	 */
	movq	$X86_CR4_PAE, %rax
	movq	%rax, %cr4

	jmp	1f

1:
	/* Flush the TLB (needed?). */
	movq	%r9, %cr3

	/* Do the copies. */
	movq	%rdi, %rcx	/* Put the indirection_page in %rcx. */
	xorq	%rdi, %rdi
	xorq	%rsi, %rsi
	jmp	1f

0:
	/*
	 * Top, read another quadword from the indirection page.
	 * Indirection page is an array which contains source
	 * and destination address pairs. If all pairs could
	 * not fit in one page then at the end of given
	 * indirection page is pointer to next one.
	 * Copy is stopped when done indicator
	 * is found in indirection page.
	 */
	movq	(%rbx), %rcx
	addq	$8, %rbx

1:
	testq	$0x1, %rcx	/* Is it a destination page? */
	jz	2f

	movq	%rcx, %rdi
	andq	$PAGE_MASK, %rdi
	jmp	0b

2:
	testq	$0x2, %rcx	/* Is it an indirection page? */
	jz	2f

	movq	%rcx, %rbx
	andq	$PAGE_MASK, %rbx
	jmp	0b

2:
	testq	$0x4, %rcx	/* Is it the done indicator? */
	jz	2f
	jmp	3f

2:
	testq	$0x8, %rcx	/* Is it the source indicator? */
	jz	0b		/* Ignore it otherwise. */

	movq	%rcx, %rsi
	andq	$PAGE_MASK, %rsi
	movq	$512, %rcx

	/* Copy page. */
	rep	movsq
	jmp	0b

3:
	/*
	 * To be certain of avoiding problems with self-modifying code
	 * I need to execute a serializing instruction here.
	 * So I flush the TLB by reloading %cr3 here, it's handy,
	 * and not processor dependent.
	 */
	movq	%cr3, %rax
	movq	%rax, %cr3

	/*
	 * Set all of the registers to known values.
	 * Leave %rsp alone.
	 */
	xorq	%rax, %rax
	xorq	%rbx, %rbx
	xorq    %rcx, %rcx
	xorq    %rdx, %rdx
	xorq    %rsi, %rsi
	xorq    %rdi, %rdi
	xorq    %rbp, %rbp
	xorq	%r8, %r8
	xorq	%r9, %r9
	xorq	%r10, %r10
	xorq	%r11, %r11
	xorq	%r12, %r12
	xorq	%r13, %r13
	xorq	%r14, %r14
	xorq	%r15, %r15

	/* Jump to start_address. */
	retq

xen_kexec_control_code_size:
	.long	. - xen_relocate_kernel
