#ifndef _ASM_X86_SPEC_CTRL_H
#define _ASM_X86_SPEC_CTRL_H

#include <linux/stringify.h>
#include <asm/msr-index.h>
#include <asm/cpufeatures.h>
#include <asm/alternative-asm.h>

/*
 * IBRS Flags.
 *
 * Note that we use dedicated bits to specify if basic IBRS is
 * in use (SPEC_CTRL_BASIC_IBRS_INUSE) or enhanced IBRS is in use
 * (SPEC_CTRL_ENHCD_IBRS_INUSE), instead of combining multiple
 * bits (e.g. SPEC_CTRL_BASIC_IBRS_INUSE | SPEC_CTRL_ENHCD_IBRS_SUPPORTED).
 * This is to optimize testing when checking if basic or enhanced
 * IBRS is in use, in particular for assembly code.
 */
#define SPEC_CTRL_BASIC_IBRS_INUSE	(1<<0)  /* OS enables basic IBRS usage */
#define SPEC_CTRL_IBRS_SUPPORTED	(1<<1)  /* System supports IBRS (basic or enhanced) */
#define SPEC_CTRL_IBRS_ADMIN_DISABLED	(1<<2)  /* Admin disables IBRS (basic and enhanced) */
#define SPEC_CTRL_ENHCD_IBRS_SUPPORTED	(1<<4)  /* System supports enhanced IBRS */
#define SPEC_CTRL_ENHCD_IBRS_INUSE	(1<<5)  /* OS enables enhanced IBRS usage */

#ifdef __ASSEMBLY__

.extern use_ibrs
.extern x86_spec_ctrl_priv

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
	testl	$SPEC_CTRL_BASIC_IBRS_INUSE, use_ibrs
	jz	.Lskip_\@
	PUSH_MSR_REGS
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, x86_spec_ctrl_priv
	POP_MSR_REGS
	jmp	.Ldone_\@
.Lskip_\@:
	 lfence
.Ldone_\@:
.endm

.macro DISABLE_IBRS
	testl	$SPEC_CTRL_BASIC_IBRS_INUSE, use_ibrs
	jz	.Lskip_\@
	PUSH_MSR_REGS
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, x86_spec_ctrl_base
	POP_MSR_REGS
.Lskip_\@:
.endm

.macro ENABLE_IBRS_SAVE_AND_CLOBBER save_reg:req
	testl	$SPEC_CTRL_BASIC_IBRS_INUSE, use_ibrs
	jz	.Lskip_\@

	movl	$MSR_IA32_SPEC_CTRL, %ecx
	rdmsr
	movl	%eax, \save_reg

	movl	$0, %edx
	movl	x86_spec_ctrl_priv, %eax
	wrmsr
	jmp	.Ldone_\@
.Lskip_\@:
	movl	x86_spec_ctrl_priv, \save_reg
	lfence
.Ldone_\@:
.endm

.macro RESTORE_IBRS_CLOBBER save_reg:req
	testl	$SPEC_CTRL_BASIC_IBRS_INUSE, use_ibrs
	jz	.Lskip_\@

	cmp	\save_reg, x86_spec_ctrl_priv
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
	testl	$SPEC_CTRL_BASIC_IBRS_INUSE, use_ibrs
	jz	.Lskip_\@
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, x86_spec_ctrl_priv
	jmp	.Ldone_\@
.Lskip_\@:
	 lfence
.Ldone_\@:
.endm

#else /* __ASSEMBLY__ */

#include <linux/cpu.h>

/* Defined in bugs.c */
extern u64 x86_spec_ctrl_priv;
extern u64 x86_spec_ctrl_base;

/*
 * Indicate usage of IBRS to control execution speculation.
 *
 * IBRS usage is defined globally with the use_ibrs variable.
 * During the boot, the boot cpu will set the initial value of use_ibrs.
 */
extern unsigned int use_ibrs;
DECLARE_STATIC_KEY_FALSE(ibrs_firmware_enabled_key);
extern struct mutex spec_ctrl_mutex;

DECLARE_STATIC_KEY_FALSE(retpoline_enabled_key);
DECLARE_STATIC_KEY_FALSE(rsb_stuff_key);
DECLARE_STATIC_KEY_FALSE(rsb_overwrite_key);

static inline void rsb_overwrite_enable(void)
{
	static_branch_enable(&rsb_stuff_key);
	static_branch_enable(&rsb_overwrite_key);
}

static inline void rsb_overwrite_disable(void)
{
	if (static_key_enabled(&rsb_overwrite_key)) {
		static_branch_disable(&rsb_stuff_key);
		static_branch_disable(&rsb_overwrite_key);
	}
}

static inline void rsb_stuff_enable(void)
{
	static_branch_enable(&rsb_stuff_key);
}

static inline void rsb_stuff_disable(void)
{
	static_branch_disable(&rsb_stuff_key);
}

#define ibrs_supported		(use_ibrs & SPEC_CTRL_IBRS_SUPPORTED)
#define ibrs_disabled		(use_ibrs & SPEC_CTRL_IBRS_ADMIN_DISABLED)
#define eibrs_supported		(use_ibrs & SPEC_CTRL_ENHCD_IBRS_SUPPORTED)

static inline void set_ibrs_inuse(void)
{
	if (!ibrs_supported || ibrs_disabled)
		return;

	use_ibrs &= ~(SPEC_CTRL_BASIC_IBRS_INUSE | SPEC_CTRL_ENHCD_IBRS_INUSE);

	if (eibrs_supported)
		/* Enhanced IBRS is available */
		use_ibrs |= SPEC_CTRL_ENHCD_IBRS_INUSE;
	else
		/* Basic IBRS is available */
		use_ibrs |= SPEC_CTRL_BASIC_IBRS_INUSE;

	/* When entering kernel */
	x86_spec_ctrl_priv |= SPEC_CTRL_IBRS;
}

static inline void clear_ibrs_inuse(void)
{
	use_ibrs &= ~(SPEC_CTRL_BASIC_IBRS_INUSE | SPEC_CTRL_ENHCD_IBRS_INUSE);
	/*
	 * This is stricly not needed as the use_ibrs guards against the
	 * the use of the MSR so these values wouldn't be touched.
	 */
	x86_spec_ctrl_priv &= ~(SPEC_CTRL_IBRS);
}

static inline int check_basic_ibrs_inuse(void)
{
	if (use_ibrs & SPEC_CTRL_BASIC_IBRS_INUSE)
		return 1;

	/* rmb to prevent wrong speculation for security */
	rmb();
	return 0;
}

static inline int check_enhanced_ibrs_inuse(void)
{
	if (use_ibrs & SPEC_CTRL_ENHCD_IBRS_INUSE)
		return 1;

	/* rmb to prevent wrong speculation for security */
	rmb();
	return 0;
}

static inline int check_ibrs_inuse(void)
{
	if (use_ibrs & (SPEC_CTRL_BASIC_IBRS_INUSE |
			SPEC_CTRL_ENHCD_IBRS_INUSE))
		return 1;

	/* rmb to prevent wrong speculation for security */
	rmb();
	return 0;
}

static inline void set_ibrs_supported(void)
{
	use_ibrs |= SPEC_CTRL_IBRS_SUPPORTED;
}

static inline void set_ibrs_disabled(void)
{
	use_ibrs |= SPEC_CTRL_IBRS_ADMIN_DISABLED;
	if (check_ibrs_inuse())
		clear_ibrs_inuse();
}

static inline void set_ibrs_enhanced(void)
{
	use_ibrs |= SPEC_CTRL_ENHCD_IBRS_SUPPORTED;
}

static inline bool ibrs_firmware_enabled(void)
{
	return static_key_enabled(&ibrs_firmware_enabled_key);
}

static inline void ibrs_firmware_enable(void)
{
	if (ibrs_supported)
		static_branch_enable(&ibrs_firmware_enabled_key);
}

static inline void ibrs_firmware_disable(void)
{
	static_branch_disable(&ibrs_firmware_enabled_key);
}

static inline void clear_ibrs_disabled(void)
{
	use_ibrs &= ~SPEC_CTRL_IBRS_ADMIN_DISABLED;
	set_ibrs_inuse();
}

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_SPEC_CTRL_H */
