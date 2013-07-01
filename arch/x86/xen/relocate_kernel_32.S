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
 * the Free Software Foundation; either veesion 2 of the License, or
 * (at your option) any later veesion.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <asm/cache.h>
#include <asm/page_types.h>
#include <asm/pgtable_types.h>
#include <asm/processor-flags.h>

#include <asm/xen/kexec.h>

#define ARG_INDIRECTION_PAGE	0x4
#define ARG_PAGE_LIST		0x8
#define ARG_START_ADDRESS	0xc

#define PTR(x)	(x << 2)

	.text
	.align	PAGE_SIZE
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
	 * 0x4(%esp) - indirection_page,
	 * 0x8(%esp) - page_list,
	 * 0xc(%esp) - start_address,
	 * 0x10(%esp) - cpu_has_pae (ignored),
	 * 0x14(%esp) - preserve_context (ignored).
	 */

	/* Zero out flags, and disable interrupts. */
	pushl	$0
	popfl

	/* Get page_list address. */
	movl	ARG_PAGE_LIST(%esp), %esi

	/*
	 * Map the control page at its virtual address
	 * in transition page table.
	 */
	movl	PTR(XK_VA_CONTROL_PAGE)(%esi), %eax

	/* Get PGD address and PGD entry index. */
	movl	PTR(XK_VA_PGD_PAGE)(%esi), %ebx
	movl	%eax, %ecx
	shrl	$PGDIR_SHIFT, %ecx
	andl	$(PTRS_PER_PGD - 1), %ecx

	/* Fill PGD entry with PMD0 reference. */
	movl	PTR(XK_MA_PMD0_PAGE)(%esi), %edx
	orl	$_PAGE_PRESENT, %edx
	movl	%edx, (%ebx, %ecx, 8)

	/* Get PMD0 address and PMD0 entry index. */
	movl	PTR(XK_VA_PMD0_PAGE)(%esi), %ebx
	movl	%eax, %ecx
	shrl	$PMD_SHIFT, %ecx
	andl	$(PTRS_PER_PMD - 1), %ecx

	/* Fill PMD0 entry with PTE0 reference. */
	movl	PTR(XK_MA_PTE0_PAGE)(%esi), %edx
	orl	$_KERNPG_TABLE, %edx
	movl	%edx, (%ebx, %ecx, 8)

	/* Get PTE0 address and PTE0 entry index. */
	movl	PTR(XK_VA_PTE0_PAGE)(%esi), %ebx
	movl	%eax, %ecx
	shrl	$PAGE_SHIFT, %ecx
	andl	$(PTRS_PER_PTE - 1), %ecx

	/* Fill PTE0 entry with control page reference. */
	movl	PTR(XK_MA_CONTROL_PAGE)(%esi), %edx
	orl	$__PAGE_KERNEL_EXEC, %edx
	movl	%edx, (%ebx, %ecx, 8)

	/*
	 * Identity map the control page at its machine address
	 * in transition page table.
	 */
	movl	PTR(XK_MA_CONTROL_PAGE)(%esi), %eax

	/* Get PGD address and PGD entry index. */
	movl	PTR(XK_VA_PGD_PAGE)(%esi), %ebx
	movl	%eax, %ecx
	shrl	$PGDIR_SHIFT, %ecx
	andl	$(PTRS_PER_PGD - 1), %ecx

	/* Fill PGD entry with PMD1 reference. */
	movl	PTR(XK_MA_PMD1_PAGE)(%esi), %edx
	orl	$_PAGE_PRESENT, %edx
	movl	%edx, (%ebx, %ecx, 8)

	/* Get PMD1 address and PMD1 entry index. */
	movl	PTR(XK_VA_PMD1_PAGE)(%esi), %ebx
	movl	%eax, %ecx
	shrl	$PMD_SHIFT, %ecx
	andl	$(PTRS_PER_PMD - 1), %ecx

	/* Fill PMD1 entry with PTE1 reference. */
	movl	PTR(XK_MA_PTE1_PAGE)(%esi), %edx
	orl	$_KERNPG_TABLE, %edx
	movl	%edx, (%ebx, %ecx, 8)

	/* Get PTE1 address and PTE1 entry index. */
	movl	PTR(XK_VA_PTE1_PAGE)(%esi), %ebx
	movl	%eax, %ecx
	shrl	$PAGE_SHIFT, %ecx
	andl	$(PTRS_PER_PTE - 1), %ecx

	/* Fill PTE1 entry with control page reference. */
	movl	PTR(XK_MA_CONTROL_PAGE)(%esi), %edx
	orl	$__PAGE_KERNEL_EXEC, %edx
	movl	%edx, (%ebx, %ecx, 8)

	/*
	 * Get machine address of control page now.
	 * This is impossible after page table switch.
	 */
	movl	PTR(XK_MA_CONTROL_PAGE)(%esi), %ebx

	/* Get machine address of transition page table now too. */
	movl	PTR(XK_MA_PGD_PAGE)(%esi), %ecx

	/* Get start_address too. */
	movl	ARG_START_ADDRESS(%esp), %edx

	/* Get indirection_page address too. */
	movl	ARG_INDIRECTION_PAGE(%esp), %edi

	/* Switch to transition page table. */
	movl	%ecx, %cr3

	/* Load IDT. */
	lidtl	(idt_48 - xen_relocate_kernel)(%ebx)

	/* Load GDT. */
	leal	(gdt - xen_relocate_kernel)(%ebx), %eax
	movl	%eax, (gdt_48 - xen_relocate_kernel + 2)(%ebx)
	lgdtl	(gdt_48 - xen_relocate_kernel)(%ebx)

	/* Load data segment registers. */
	movl	$(gdt_ds - gdt), %eax
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %fs
	movl	%eax, %gs
	movl	%eax, %ss

	/* Setup a new stack at the end of machine address of control page. */
	leal	PAGE_SIZE(%ebx), %esp

	/* Store start_address on the stack. */
	pushl   %edx

	/* Jump to identity mapped page. */
	pushl	$0
	pushl	$(gdt_cs - gdt)
	addl	$(identity_mapped - xen_relocate_kernel), %ebx
	pushl	%ebx
	iretl

identity_mapped:
	/*
	 * Set %cr0 to a known state:
	 *   - disable alignment check,
	 *   - disable floating point emulation,
	 *   - disable paging,
	 *   - no task switch,
	 *   - disable write protect,
	 *   - enable protected mode.
	 */
	movl	%cr0, %eax
	andl	$~(X86_CR0_AM | X86_CR0_EM | X86_CR0_PG | X86_CR0_TS | X86_CR0_WP), %eax
	orl	$(X86_CR0_PE), %eax
	movl	%eax, %cr0

	/* Set %cr4 to a known state. */
	xorl	%eax, %eax
	movl	%eax, %cr4

	jmp	1f

1:
	/* Flush the TLB (needed?). */
	movl	%eax, %cr3

	/* Do the copies. */
	movl	%edi, %ecx	/* Put the indirection_page in %ecx. */
	xorl	%edi, %edi
	xorl	%esi, %esi
	jmp	1f

0:
	/*
	 * Top, read another doubleword from the indirection page.
	 * Indirection page is an array which contains source
	 * and destination address pairs. If all pairs could
	 * not fit in one page then at the end of given
	 * indirection page is pointer to next one.
	 * Copy is stopped when done indicator
	 * is found in indirection page.
	 */
	movl	(%ebx), %ecx
	addl	$4, %ebx

1:
	testl	$0x1, %ecx	/* Is it a destination page? */
	jz	2f

	movl	%ecx, %edi
	andl	$PAGE_MASK, %edi
	jmp	0b

2:
	testl	$0x2, %ecx	/* Is it an indirection page? */
	jz	2f

	movl	%ecx, %ebx
	andl	$PAGE_MASK, %ebx
	jmp	0b

2:
	testl	$0x4, %ecx	/* Is it the done indicator? */
	jz	2f
	jmp	3f

2:
	testl	$0x8, %ecx	/* Is it the source indicator? */
	jz	0b		/* Ignore it otherwise. */

	movl	%ecx, %esi
	andl	$PAGE_MASK, %esi
	movl	$1024, %ecx

	/* Copy page. */
	rep	movsl
	jmp	0b

3:
	/*
	 * To be certain of avoiding problems with self-modifying code
	 * I need to execute a serializing instruction here.
	 * So I flush the TLB by reloading %cr3 here, it's handy,
	 * and not processor dependent.
	 */
	xorl	%eax, %eax
	movl	%eax, %cr3

	/*
	 * Set all of the registers to known values.
	 * Leave %esp alone.
	 */
	xorl	%ebx, %ebx
	xorl    %ecx, %ecx
	xorl    %edx, %edx
	xorl    %esi, %esi
	xorl    %edi, %edi
	xorl    %ebp, %ebp

	/* Jump to start_address. */
	retl

	.align	L1_CACHE_BYTES

gdt:
	.quad	0x0000000000000000	/* NULL descriptor. */

gdt_cs:
	.quad	0x00cf9a000000ffff	/* 4 GiB code segment at 0x00000000. */

gdt_ds:
	.quad	0x00cf92000000ffff	/* 4 GiB data segment at 0x00000000. */
gdt_end:

gdt_48:
	.word	gdt_end - gdt - 1	/* GDT limit. */
	.long	0			/* GDT base - filled in by code above. */

idt_48:
	.word	0			/* IDT limit. */
	.long	0			/* IDT base. */

xen_kexec_control_code_size:
	.long	. - xen_relocate_kernel
