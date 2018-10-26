/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Secure Launch protected mode entry point.
 *
 * Copyright (c) 2024, Oracle and/or its affiliates.
 */
	.code32
	.text
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/msr.h>
#include <asm/apicdef.h>
#include <asm/trapnr.h>
#include <asm/processor-flags.h>
#include <asm/asm-offsets.h>
#include <asm/bootparam.h>
#include <asm/page_types.h>
#include <asm/irq_vectors.h>
#include <linux/slr_table.h>
#include <linux/slaunch.h>

/* CPUID: leaf 1, ECX, SMX feature bit */
#define X86_FEATURE_BIT_SMX	(1 << 6)

#define IDT_VECTOR_LO_BITS	0
#define IDT_VECTOR_HI_BITS	6

/*
 * See the comment in head_64.S for detailed information on what this macro
 * and others like it are used for. The comment appears right at the top of
 * the file.
 */
#define rva(X) ((X) - sl_stub_entry)

/*
 * The GETSEC op code is open coded because older versions of
 * GCC do not support the getsec mnemonic.
 */
.macro GETSEC leaf
	pushl	%ebx
	xorl	%ebx, %ebx	/* Must be zero for SMCTRL */
	movl	\leaf, %eax	/* Leaf function */
	.byte 	0x0f, 0x37	/* GETSEC opcode */
	popl	%ebx
.endm

.macro TXT_RESET error
	/*
	 * Set a sticky error value and reset. Note the movs to %eax act as
	 * TXT register barriers.
	 */
	movl	\error, (TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_ERRORCODE)
	movl	(TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_E2STS), %eax
	movl	$1, (TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_CMD_NO_SECRETS)
	movl	(TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_E2STS), %eax
	movl	$1, (TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_CMD_UNLOCK_MEM_CONFIG)
	movl	(TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_E2STS), %eax
	movl	$1, (TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_CMD_RESET)
1:
	hlt
	jmp	1b
.endm

	.code32
SYM_FUNC_START(sl_stub_entry)
	cli
	cld

	/*
	 * On entry, %ebx has the entry abs offset to sl_stub_entry. The rva()
	 * macro is used to generate relative references using %ebx as a base, as
	 * to avoid absolute relocations, which would require fixups at runtime.
	 * Only %cs and %ds segments are known good.
	 */

	/* Load GDT, set segment regs and lret to __SL32_CS */
	leal	rva(sl_gdt_desc)(%ebx), %eax
	addl	%eax, 2(%eax)
	lgdt	(%eax)

	movl	$(__SL32_DS), %eax
	movw	%ax, %ds
	movw	%ax, %es
	movw	%ax, %fs
	movw	%ax, %gs
	movw	%ax, %ss

	/*
	 * Now that %ss is known good, take the first stack for the BSP. The
	 * AP stacks are only used on Intel.
	 */
	leal	rva(sl_stacks_end)(%ebx), %esp

	leal	rva(.Lsl_cs)(%ebx), %eax
	pushl	$(__SL32_CS)
	pushl	%eax
	lret

.Lsl_cs:
	/* Save our base pointer reg and page table for MLE */
	pushl	%ebx
	pushl	%ecx

	/* See if SMX feature is supported. */
	movl	$1, %eax
	cpuid
	testl	$(X86_FEATURE_BIT_SMX), %ecx
	jz	.Ldo_unknown_cpu

	popl	%ecx
	popl	%ebx

	/* Know it is Intel */
	movl	$(SL_CPU_INTEL), rva(sl_cpu_type)(%ebx)

	/* Locate the base of the MLE using the page tables in %ecx */
	call	sl_find_mle_base

	/* Increment CPU count for BSP */
	incl	rva(sl_txt_cpu_count)(%ebx)

	/*
	 * Enable SMI with GETSEC[SMCTRL] which were disabled by SENTER.
	 * NMIs were also disabled by SENTER. Since there is no IDT for the BSP,
	 * allow the mainline kernel re-enable them in the normal course of
	 * booting.
	 */
	GETSEC	$(SMX_X86_GETSEC_SMCTRL)

	/* Clear the TXT error registers for a clean start of day */
	movl	$0, (TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_ERRORCODE)
	movl	$0xffffffff, (TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_ESTS)

	/* On Intel, the zero page address is passed in the TXT heap */
	/* Read physical base of heap into EAX */
	movl	(TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_HEAP_BASE), %eax
	/* Read the size of the BIOS data into ECX (first 8 bytes) */
	movl	(%eax), %ecx
	/* Skip over BIOS data and size of OS to MLE data section */
	leal	8(%eax, %ecx), %eax

	/* Need to verify the values in the OS-MLE struct passed in */
	call	sl_txt_verify_os_mle_struct

	/*
	 * Get the boot params address from the heap. Note %esi and %ebx MUST
	 * be preserved across calls and operations.
	 */
	movl	SL_boot_params_addr(%eax), %esi

	/* Save %ebx so the APs can find their way home */
	movl	%ebx, (SL_mle_scratch + SL_SCRATCH_AP_EBX)(%eax)

	/* Fetch the AP wake code block address from the heap */
	movl	SL_ap_wake_block(%eax), %edi
	movl	%edi, rva(sl_txt_ap_wake_block)(%ebx)

	/* Store the offset in the AP wake block to the jmp address */
	movl	$(sl_ap_jmp_offset - sl_txt_ap_wake_begin), \
		(SL_mle_scratch + SL_SCRATCH_AP_JMP_OFFSET)(%eax)

	/* Store the offset in the AP wake block to the AP stacks block */
	movl	$(sl_stacks - sl_txt_ap_wake_begin), \
		(SL_mle_scratch + SL_SCRATCH_AP_STACKS_OFFSET)(%eax)

	/* %eax still is the base of the OS-MLE block, save it */
	pushl	%eax

	/* Relocate the AP wake code to the safe block */
	call	sl_txt_reloc_ap_wake

	/*
	 * Wake up all APs that are blocked in the ACM and wait for them to
	 * halt. This should be done before restoring the MTRRs so the ACM is
	 * still properly in WB memory.
	 */
	call	sl_txt_wake_aps

	/* Restore OS-MLE in %eax */
	popl	%eax

	/*
	 * %edi is used by this routine to find the MTRRs which are in the SLRT
	 * in the Intel info.
	 */
	movl	SL_txt_info(%eax), %edi
	call	sl_txt_load_regs

	jmp	.Lcpu_setup_done

.Ldo_unknown_cpu:
	/* Non-Intel CPUs are not yet supported */
	ud2

.Lcpu_setup_done:
	/*
	 * Don't enable MCE at this point. The kernel will enable
	 * it on the BSP later when it is ready.
	 */

	/* Done, jump to normal 32b pm entry */
	jmp	startup_32
SYM_FUNC_END(sl_stub_entry)

SYM_FUNC_START(sl_find_mle_base)
	/* %ecx has PDPT, get first PD */
	movl	(%ecx), %eax
	andl	$(PAGE_MASK), %eax
	/* Get first PT from first PDE */
	movl	(%eax), %eax
	andl	$(PAGE_MASK), %eax
	/* Get MLE base from first PTE */
	movl	(%eax), %eax
	andl	$(PAGE_MASK), %eax

	movl	%eax, rva(sl_mle_start)(%ebx)
	ret
SYM_FUNC_END(sl_find_mle_base)

SYM_FUNC_START(sl_check_buffer_mle_overlap)
	/* %ecx: buffer begin %edx: buffer end */
	/* %ebx: MLE begin %edi: MLE end */
	/* %eax: region may be inside MLE */

	cmpl	%edi, %ecx
	jb	.Lnext_check
	cmpl	%edi, %edx
	jbe	.Lnext_check
	jmp	.Lvalid /* Buffer above MLE */

.Lnext_check:
	cmpl	%ebx, %edx
	ja	.Linside_check
	cmpl	%ebx, %ecx
	jae	.Linside_check
	jmp	.Lvalid /* Buffer below MLE */

.Linside_check:
	cmpl	$0, %eax
	jz	.Linvalid
	cmpl	%ebx, %ecx
	jb	.Linvalid
	cmpl	%edi, %edx
	ja	.Linvalid
	jmp	.Lvalid /* Buffer in MLE */

.Linvalid:
	TXT_RESET $(SL_ERROR_MLE_BUFFER_OVERLAP)

.Lvalid:
	ret
SYM_FUNC_END(sl_check_buffer_mle_overlap)

SYM_FUNC_START(sl_txt_verify_os_mle_struct)
	pushl	%ebx
	/*
	 * %eax points to the base of the OS-MLE struct. Need to also
	 * read some values from the OS-SINIT struct too.
	 */
	movl	-8(%eax), %ecx
	/* Skip over OS to MLE data section and size of OS-SINIT structure */
	leal	(%eax, %ecx), %edx

	/* Load MLE image base absolute offset */
	movl	rva(sl_mle_start)(%ebx), %ebx

	/* Verify the value of the low PMR base. It should always be 0. */
	movl	SL_vtd_pmr_lo_base(%edx), %esi
	cmpl	$0, %esi
	jz	.Lvalid_pmr_base
	TXT_RESET $(SL_ERROR_LO_PMR_BASE)

.Lvalid_pmr_base:
	/* Grab some values from OS-SINIT structure */
	movl	SL_mle_size(%edx), %edi
	addl	%ebx, %edi
	jc	.Loverflow_detected
	movl	SL_vtd_pmr_lo_size(%edx), %esi

	/* Check the AP wake block */
	movl	SL_ap_wake_block(%eax), %ecx
	movl	SL_ap_wake_block_size(%eax), %edx
	addl	%ecx, %edx
	jc	.Loverflow_detected
	pushl	%eax
	xorl	%eax, %eax
	call	sl_check_buffer_mle_overlap
	popl	%eax
	cmpl	%esi, %edx
	ja	.Lbuffer_beyond_pmr

	/*
	 * Check the boot params. Note during a UEFI boot, the boot
	 * params will be inside the MLE image. Test for this case
	 * in the overlap case.
	 */
	movl	SL_boot_params_addr(%eax), %ecx
	movl	$(PAGE_SIZE), %edx
	addl	%ecx, %edx
	jc	.Loverflow_detected
	pushl	%eax
	movl	$1, %eax
	call	sl_check_buffer_mle_overlap
	popl	%eax
	cmpl	%esi, %edx
	ja	.Lbuffer_beyond_pmr

	/* Check that the AP wake block is big enough */
	cmpl	$(sl_txt_ap_wake_end - sl_txt_ap_wake_begin), \
		SL_ap_wake_block_size(%eax)
	jae	.Lwake_block_ok
	TXT_RESET $(SL_ERROR_WAKE_BLOCK_TOO_SMALL)

.Lwake_block_ok:
	popl	%ebx
	ret

.Loverflow_detected:
	TXT_RESET $(SL_ERROR_INTEGER_OVERFLOW)

.Lbuffer_beyond_pmr:
	TXT_RESET $(SL_ERROR_BUFFER_BEYOND_PMR)
SYM_FUNC_END(sl_txt_verify_os_mle_struct)

SYM_FUNC_START(sl_txt_ap_entry)
	cli
	cld
	/*
	 * The %cs and %ds segments are known good after waking the AP.
	 * First order of business is to find where we are and
	 * save it in %ebx.
	 */

	/* Read physical base of heap into EAX */
	movl	(TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_HEAP_BASE), %eax
	/* Read the size of the BIOS data into ECX (first 8 bytes) */
	movl	(%eax), %ecx
	/* Skip over BIOS data and size of OS to MLE data section */
	leal	8(%eax, %ecx), %eax

	/* Saved %ebx from the BSP and stash OS-MLE pointer */
	movl	(SL_mle_scratch + SL_SCRATCH_AP_EBX)(%eax), %ebx

	/* Save TXT info ptr in %edi for call to sl_txt_load_regs */
	movl	SL_txt_info(%eax), %edi

	/* Lock and get our stack index */
	movl	$1, %ecx
.Lspin:
	xorl	%eax, %eax
	lock cmpxchgl	%ecx, rva(sl_txt_spin_lock)(%ebx)
	pause
	jnz	.Lspin

	/* Increment the stack index and use the next value inside lock */
	incl	rva(sl_txt_stack_index)(%ebx)
	movl	rva(sl_txt_stack_index)(%ebx), %eax

	/* Unlock */
	movl	$0, rva(sl_txt_spin_lock)(%ebx)

	/* Location of the relocated AP wake block */
	movl	rva(sl_txt_ap_wake_block)(%ebx), %ecx

	/* Load reloc GDT, set segment regs and lret to __SL32_CS */
	lgdt	(sl_ap_gdt_desc - sl_txt_ap_wake_begin)(%ecx)

	movl	$(__SL32_DS), %edx
	movw	%dx, %ds
	movw	%dx, %es
	movw	%dx, %fs
	movw	%dx, %gs
	movw	%dx, %ss

	/* Load our reloc AP stack */
	movl	$(TXT_BOOT_STACK_SIZE), %edx
	mull	%edx
	leal	(sl_stacks_end - sl_txt_ap_wake_begin)(%ecx), %esp
	subl	%eax, %esp

	/* Switch to AP code segment */
	leal	rva(.Lsl_ap_cs)(%ebx), %eax
	pushl	$(__SL32_CS)
	pushl	%eax
	lret

.Lsl_ap_cs:
	/* Load the relocated AP IDT */
	lidt	(sl_ap_idt_desc - sl_txt_ap_wake_begin)(%ecx)

	/* Fixup MTRRs and misc enable MSR on APs too */
	call	sl_txt_load_regs

	/* Enable SMI with GETSEC[SMCTRL] */
	GETSEC $(SMX_X86_GETSEC_SMCTRL)

	/* IRET-to-self can be used to enable NMIs which SENTER disabled */
	leal	rva(.Lnmi_enabled_ap)(%ebx), %eax
	pushfl
	pushl	$(__SL32_CS)
	pushl	%eax
	iret

.Lnmi_enabled_ap:
	/* Put APs in X2APIC mode like the BSP */
	movl	$(MSR_IA32_APICBASE), %ecx
	rdmsr
	orl	$(XAPIC_ENABLE | X2APIC_ENABLE), %eax
	wrmsr

	/*
	 * Basically done, increment the CPU count and jump off to the AP
	 * wake block to wait.
	 */
	lock incl	rva(sl_txt_cpu_count)(%ebx)

	movl	rva(sl_txt_ap_wake_block)(%ebx), %eax
	jmp	*%eax
SYM_FUNC_END(sl_txt_ap_entry)

SYM_FUNC_START(sl_txt_reloc_ap_wake)
	/* Save boot params register */
	pushl	%esi

	movl	rva(sl_txt_ap_wake_block)(%ebx), %edi

	/* Fixup AP IDT and GDT descriptor before relocating */
	leal	rva(sl_ap_idt_desc)(%ebx), %eax
	addl	%edi, 2(%eax)
	leal	rva(sl_ap_gdt_desc)(%ebx), %eax
	addl	%edi, 2(%eax)

	/*
	 * Copy the AP wake code and AP GDT/IDT to the protected wake block
	 * provided by the loader. Destination already in %edi.
	 */
	movl	$(sl_txt_ap_wake_end - sl_txt_ap_wake_begin), %ecx
	leal	rva(sl_txt_ap_wake_begin)(%ebx), %esi
	rep movsb

	/* Setup the IDT for the APs to use in the relocation block */
	movl	rva(sl_txt_ap_wake_block)(%ebx), %ecx
	addl	$(sl_ap_idt - sl_txt_ap_wake_begin), %ecx
	xorl	%edx, %edx

	/* Form the default reset vector relocation address */
	movl	rva(sl_txt_ap_wake_block)(%ebx), %esi
	addl	$(sl_txt_int_reset - sl_txt_ap_wake_begin), %esi

1:
	cmpw	$(NR_VECTORS), %dx
	jz	.Lap_idt_done

	cmpw	$(X86_TRAP_NMI), %dx
	jz	2f

	/* Load all other fixed vectors with reset handler */
	movl	%esi, %eax
	movw	%ax, (IDT_VECTOR_LO_BITS)(%ecx)
	shrl	$16, %eax
	movw	%ax, (IDT_VECTOR_HI_BITS)(%ecx)
	jmp	3f

2:
	/* Load single wake NMI IPI vector at the relocation address */
	movl	rva(sl_txt_ap_wake_block)(%ebx), %eax
	addl	$(sl_txt_int_nmi - sl_txt_ap_wake_begin), %eax
	movw	%ax, (IDT_VECTOR_LO_BITS)(%ecx)
	shrl	$16, %eax
	movw	%ax, (IDT_VECTOR_HI_BITS)(%ecx)

3:
	incw	%dx
	addl	$8, %ecx
	jmp	1b

.Lap_idt_done:
	popl	%esi
	ret
SYM_FUNC_END(sl_txt_reloc_ap_wake)

SYM_FUNC_START(sl_txt_load_regs)
	/* Save base pointer register */
	pushl	%ebx

	/*
	 * On Intel, the original variable MTRRs and Misc Enable MSR are
	 * restored on the BSP at early boot. Each AP will also restore
	 * its MTRRs and Misc Enable MSR.
	 */
	pushl	%edi
	addl	$(SL_saved_bsp_mtrrs), %edi
	movl	(%edi), %ebx
	pushl	%ebx /* default_mem_type lo */
	addl	$4, %edi
	movl	(%edi), %ebx
	pushl	%ebx /* default_mem_type hi */
	addl	$4, %edi
	movl	(%edi), %ebx /* mtrr_vcnt lo, don't care about hi part */
	addl	$8, %edi /* now at MTRR pair array */
	/* Write the variable MTRRs */
	movl	$(MSR_MTRRphysBase0), %ecx
1:
	cmpl	$0, %ebx
	jz	2f

	movl	(%edi), %eax /* MTRRphysBaseX lo */
	addl	$4, %edi
	movl	(%edi), %edx /* MTRRphysBaseX hi */
	wrmsr
	addl	$4, %edi
	incl	%ecx
	movl	(%edi), %eax /* MTRRphysMaskX lo */
	addl	$4, %edi
	movl	(%edi), %edx /* MTRRphysMaskX hi */
	wrmsr
	addl	$4, %edi
	incl	%ecx

	decl	%ebx
	jmp	1b
2:
	/* Write the default MTRR register */
	popl	%edx
	popl	%eax
	movl	$(MSR_MTRRdefType), %ecx
	wrmsr

	/* Return to beginning and write the misc enable msr */
	popl	%edi
	addl	$(SL_saved_misc_enable_msr), %edi
	movl	(%edi), %eax /* saved_misc_enable_msr lo */
	addl	$4, %edi
	movl	(%edi), %edx /* saved_misc_enable_msr hi */
	movl	$(MSR_IA32_MISC_ENABLE), %ecx
	wrmsr

	popl	%ebx
	ret
SYM_FUNC_END(sl_txt_load_regs)

SYM_FUNC_START(sl_txt_wake_aps)
	/* Save boot params register */
	pushl	%esi

	/* First setup the MLE join structure and load it into TXT reg */
	leal	rva(sl_gdt)(%ebx), %eax
	leal	rva(sl_txt_ap_entry)(%ebx), %ecx
	leal	rva(sl_smx_rlp_mle_join)(%ebx), %edx
	movl	%eax, SL_rlp_gdt_base(%edx)
	movl	%ecx, SL_rlp_entry_point(%edx)
	movl	%edx, (TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_MLE_JOIN)

	/* Another TXT heap walk to find various values needed to wake APs */
	movl	(TXT_PRIV_CONFIG_REGS_BASE + TXT_CR_HEAP_BASE), %eax
	/* At BIOS data size, find the number of logical processors */
	movl	(SL_num_logical_procs + 8)(%eax), %edx
	/* Skip over BIOS data */
	movl	(%eax), %ecx
	addl	%ecx, %eax
	/* Skip over OS to MLE */
	movl	(%eax), %ecx
	addl	%ecx, %eax
	/* At OS-SNIT size, get capabilities to know how to wake up the APs */
	movl	(SL_capabilities + 8)(%eax), %esi
	/* Skip over OS to SNIT */
	movl	(%eax), %ecx
	addl	%ecx, %eax
	/* At SINIT-MLE size, get the AP wake MONITOR address */
	movl	(SL_rlp_wakeup_addr + 8)(%eax), %edi

	/* Determine how to wake up the APs */
	testl	$(1 << TXT_SINIT_MLE_CAP_WAKE_MONITOR), %esi
	jz	.Lwake_getsec

	/* Wake using MWAIT MONITOR */
	movl	$1, (%edi)
	jmp	.Laps_awake

.Lwake_getsec:
	/* Wake using GETSEC(WAKEUP) */
	GETSEC	$(SMX_X86_GETSEC_WAKEUP)

.Laps_awake:
	/*
	 * All of the APs are woken up and rendesvous in the relocated wake
	 * block starting at sl_txt_ap_wake_begin. Wait for all of them to
	 * halt.
	 */
	pause
	cmpl	rva(sl_txt_cpu_count)(%ebx), %edx
	jne	.Laps_awake

	popl	%esi
	ret
SYM_FUNC_END(sl_txt_wake_aps)

/* This is the beginning of the relocated AP wake code block */
	.global sl_txt_ap_wake_begin
sl_txt_ap_wake_begin:

	/* Get the LAPIC ID for each AP and stash it on the stack */
	movl	$(MSR_IA32_X2APIC_APICID), %ecx
	rdmsr
	pushl	%eax

	/*
	 * Get a pointer to the monitor location on this APs stack to test below
	 * after mwait returns. Currently %esp points to just past the pushed APIC
	 * ID value.
	 */
	movl	%esp, %eax
	subl	$(TXT_BOOT_STACK_SIZE - 4), %eax
	movl	$0, (%eax)

	/* Clear ecx/edx so no invalid extensions or hints are passed to monitor */
	xorl	%ecx, %ecx
	xorl	%edx, %edx

	/*
	 * Arm the monitor and wait for it to be poked by he SMP bringup code. The mwait
	 * instruction can return for a number of reasons. Test to see if it returned
	 * because the monitor was written to.
	 */
	monitor

1:
	mfence
	mwait
	movl	(%eax), %edx
	testl	%edx, %edx
	jz	1b

	/*
	 * This is the long absolute jump to the 32b Secure Launch protected mode stub
	 * code in sl_trampoline_start32() in the rmpiggy. The jump address will be
	 * fixed in the SMP boot code when the first AP is brought up. This whole area
	 * is provided and protected in the memory map by the prelaunch code.
	 */
	.byte	0xea
sl_ap_jmp_offset:
	.long	0x00000000
	.word	__SL32_CS

SYM_FUNC_START(sl_txt_int_nmi)
	/* NMI context, just IRET */
	iret
SYM_FUNC_END(sl_txt_int_nmi)

SYM_FUNC_START(sl_txt_int_reset)
	TXT_RESET $(SL_ERROR_INV_AP_INTERRUPT)
SYM_FUNC_END(sl_txt_int_reset)

	.balign 8
SYM_DATA_START_LOCAL(sl_ap_idt_desc)
	.word	sl_ap_idt_end - sl_ap_idt - 1		/* Limit */
	.long	sl_ap_idt - sl_txt_ap_wake_begin	/* Base */
SYM_DATA_END_LABEL(sl_ap_idt_desc, SYM_L_LOCAL, sl_ap_idt_desc_end)

	.balign 8
SYM_DATA_START_LOCAL(sl_ap_idt)
	.rept	NR_VECTORS
	.word	0x0000		/* Offset 15 to 0 */
	.word	__SL32_CS	/* Segment selector */
	.word	0x8e00		/* Present, DPL=0, 32b Vector, Interrupt */
	.word	0x0000		/* Offset 31 to 16 */
	.endr
SYM_DATA_END_LABEL(sl_ap_idt, SYM_L_LOCAL, sl_ap_idt_end)

	.balign 8
SYM_DATA_START_LOCAL(sl_ap_gdt_desc)
	.word	sl_ap_gdt_end - sl_ap_gdt - 1
	.long	sl_ap_gdt - sl_txt_ap_wake_begin
SYM_DATA_END_LABEL(sl_ap_gdt_desc, SYM_L_LOCAL, sl_ap_gdt_desc_end)

	.balign	8
SYM_DATA_START_LOCAL(sl_ap_gdt)
	.quad	0x0000000000000000	/* NULL */
	.quad	0x00cf9a000000ffff	/* __SL32_CS */
	.quad	0x00cf92000000ffff	/* __SL32_DS */
SYM_DATA_END_LABEL(sl_ap_gdt, SYM_L_LOCAL, sl_ap_gdt_end)

	/* Small stacks for BSP and APs to work with */
	.balign 64
SYM_DATA_START_LOCAL(sl_stacks)
	.fill (TXT_MAX_CPUS * TXT_BOOT_STACK_SIZE), 1, 0
SYM_DATA_END_LABEL(sl_stacks, SYM_L_LOCAL, sl_stacks_end)

/* This is the end of the relocated AP wake code block */
	.global sl_txt_ap_wake_end
sl_txt_ap_wake_end:

	.data
	.balign 8
SYM_DATA_START_LOCAL(sl_gdt_desc)
	.word	sl_gdt_end - sl_gdt - 1
	.long	sl_gdt - sl_gdt_desc
SYM_DATA_END_LABEL(sl_gdt_desc, SYM_L_LOCAL, sl_gdt_desc_end)

	.balign	8
SYM_DATA_START_LOCAL(sl_gdt)
	.quad	0x0000000000000000	/* NULL */
	.quad	0x00cf9a000000ffff	/* __SL32_CS */
	.quad	0x00cf92000000ffff	/* __SL32_DS */
SYM_DATA_END_LABEL(sl_gdt, SYM_L_LOCAL, sl_gdt_end)

	.balign 8
SYM_DATA_START_LOCAL(sl_smx_rlp_mle_join)
	.long	sl_gdt_end - sl_gdt - 1	/* GDT limit */
	.long	0x00000000		/* GDT base */
	.long	__SL32_CS	/* Seg Sel - CS (DS, ES, SS = seg_sel+8) */
	.long	0x00000000	/* Entry point physical address */
SYM_DATA_END(sl_smx_rlp_mle_join)

SYM_DATA(sl_cpu_type, .long 0x00000000)

SYM_DATA(sl_mle_start, .long 0x00000000)

SYM_DATA_LOCAL(sl_txt_spin_lock, .long 0x00000000)

SYM_DATA_LOCAL(sl_txt_stack_index, .long 0x00000000)

SYM_DATA_LOCAL(sl_txt_cpu_count, .long 0x00000000)

SYM_DATA_LOCAL(sl_txt_ap_wake_block, .long 0x00000000)
