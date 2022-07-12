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

#include <linux/frame.h>

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

/*
 * IBRS kernel mitigation for Spectre_v2.
 *
 * Assumes full context is established (PUSH_REGS, CR3 and GS.) Clobbers flags
 * register. Saves and restores (AX, CX, DX). Must be called before the first
 * RET instruction (NOTE! UNTRAIN_RET includes a RET instruction)
 */
.macro ENABLE_IBRS
	testl	$SPEC_CTRL_BASIC_IBRS_INUSE, PER_CPU_VAR(cpu_ibrs)
	jz	.Lskip_\@
	PUSH_MSR_REGS
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, PER_CPU_VAR(x86_spec_ctrl_priv_cpu)
	POP_MSR_REGS
	jmp	.Ldone_\@
.Lskip_\@:
	 lfence
.Ldone_\@:
.endm

/*
 * Similar to ENABLE_IBRS, requires KERNEL GS,CR3 and clobbers rflags.
 * Saves and restores (AX, CX, DX). Must be called after the last RET.
 */
.macro DISABLE_IBRS
	testl	$SPEC_CTRL_BASIC_IBRS_INUSE, PER_CPU_VAR(cpu_ibrs)
	jz	.Lskip_\@
	PUSH_MSR_REGS
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, PER_CPU_VAR(x86_spec_ctrl_restore)
	POP_MSR_REGS
.Lskip_\@:
.endm

.macro ENABLE_IBRS_SAVE_AND_CLOBBER save_reg:req
	testl	$SPEC_CTRL_BASIC_IBRS_INUSE, PER_CPU_VAR(cpu_ibrs)
	jz	.Lskip_\@

	movl	$MSR_IA32_SPEC_CTRL, %ecx
	rdmsr
	movl	%eax, \save_reg

	movl	$0, %edx
	movl	PER_CPU_VAR(x86_spec_ctrl_priv_cpu), %eax
	wrmsr
	jmp	.Ldone_\@
.Lskip_\@:
	movl	PER_CPU_VAR(x86_spec_ctrl_priv_cpu), \save_reg
	lfence
.Ldone_\@:
.endm

.macro RESTORE_IBRS_CLOBBER save_reg:req
	testl	$SPEC_CTRL_BASIC_IBRS_INUSE, PER_CPU_VAR(cpu_ibrs)
	jz	.Lskip_\@

	cmp	\save_reg, PER_CPU_VAR(x86_spec_ctrl_priv_cpu)
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
	testl	$SPEC_CTRL_BASIC_IBRS_INUSE, PER_CPU_VAR(cpu_ibrs)
	jz	.Lskip_\@
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, PER_CPU_VAR(x86_spec_ctrl_priv_cpu)
	jmp	.Ldone_\@
.Lskip_\@:
	 lfence
.Ldone_\@:
.endm

/*
 * Define stuff and overwrite RSB stuffing macro.
 * Similar to __FILL_RETURN_BUFFER without the need of an extra register.
 *
 * This macro will either:
 * - do nothing, if rsb_stuff_key is disabled
 * - do stuffing of 16 RSB entries, if rsb_stuff_key is enabled,
 *   similar to using RSB_FILL_LOOPS with __FILL_RETURN_BUFFER.
 * - do RSB overwrite, clearing 32 RSB entries, if both
 *   rsb_stuff_key and rsb_overwrite_key are enabled,
 *   similar to using RSB_CLEAR_LOOPS with __FILL_RETURN_BUFFER.
 */
.macro STUFF_RSB
	STATIC_JUMP_IF_TRUE .Lstuff_rsb_\@, rsb_stuff_key, def=0
	jmp	.Ldone_call_\@
.Lstuff_rsb_\@:
	ANNOTATE_INTRA_FUNCTION_CALL
	call	1f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
1:	call	2f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
2:	call	3f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
3:	call	4f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
4:	call	5f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
5:	call	6f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
6:	call	7f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
7:	call	8f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
8:	call	9f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
9:	call	10f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
10:	call	11f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
11:	call	12f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
12:	call	13f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
13:	call	14f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
14:	call	15f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
15:	call	16f;	pause
16:	STATIC_JUMP_IF_TRUE .Loverwrite_rsb_\@, rsb_overwrite_key, def=0
	jmp	.Lset_stack_half_\@
.Loverwrite_rsb_\@:
	ANNOTATE_INTRA_FUNCTION_CALL
	call	17f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
17:	call	18f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
18:	call	19f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
19:	call	20f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
20:	call	21f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
21:	call	22f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
22:	call	23f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
23:	call	24f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
24:	call	25f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
25:	call	26f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
26:	call	27f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
27:	call	28f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
28:	call	29f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
29:	call	30f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
30:	call	31f;	pause
	ANNOTATE_INTRA_FUNCTION_CALL
31:	call	32f;	pause
32:	add $(16*8), %rsp
.Lset_stack_half_\@:
	add $(16*8), %rsp
.Ldone_call_\@:
.endm

#else /* __ASSEMBLY__ */

#include <linux/cpu.h>

/* Defined in bugs.c */
extern u64 x86_spec_ctrl_priv;
DECLARE_PER_CPU(u64, x86_spec_ctrl_priv_cpu);
DECLARE_PER_CPU(u64, x86_spec_ctrl_restore);
extern u64 x86_spec_ctrl_base;

/*
 * Indicate usage of IBRS to control execution speculation.
 *
 * IBRS usage is defined globally with the use_ibrs variable, and
 * per-cpu with the per-cpu variable cpu_ibrs. During the boot,
 * the boot cpu will set the initial value of use_ibrs and the
 * per-cpu value of all online cpus which support IBRS. If, after
 * that, a cpu comes online or has its microcode updated, it will
 * set its own per-cpu value based on the value of use_ibrs and
 * the IBRS capability of the cpu.
 */
extern unsigned int use_ibrs;
DECLARE_PER_CPU(unsigned int, cpu_ibrs);
DECLARE_STATIC_KEY_FALSE(ibrs_firmware_enabled_key);
extern u32 sysctl_ibrs_enabled;
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

static inline void spec_ctrl_flush_all_cpus(u32 msr_nr, u64 val)
{
	int cpu;
	get_online_cpus();
	for_each_online_cpu(cpu)
		wrmsrl_on_cpu(cpu, msr_nr, val);
	put_online_cpus();
}

static inline void update_cpu_spec_ctrl(int cpu)
{
	per_cpu(x86_spec_ctrl_priv_cpu, cpu) = x86_spec_ctrl_priv;
	per_cpu(x86_spec_ctrl_restore, cpu) = x86_spec_ctrl_base;
}

static inline void update_cpu_spec_ctrl_all(void)
{
	int cpu_index;

	for_each_online_cpu(cpu_index)
		update_cpu_spec_ctrl(cpu_index);
}

static inline void update_cpu_ibrs(struct cpuinfo_x86 *cpu)
{
	struct cpuinfo_x86 *cpu_info;

	/*
	 * IBRS can be set at boot time while cpu capabilities
	 * haven't been copied from boot_cpu_data yet.
	 */
	cpu_info = (cpu->initialized) ? cpu : &boot_cpu_data;
	per_cpu(cpu_ibrs, cpu->cpu_index) =
	    cpu_has(cpu_info, X86_FEATURE_SPEC_CTRL) ? use_ibrs : 0;
}

static inline void update_cpu_ibrs_all(void)
{
	int cpu_index;

	for_each_online_cpu(cpu_index)
		update_cpu_ibrs(&cpu_data(cpu_index));
}

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

	/* Propagate the change to each cpu */
	update_cpu_ibrs_all();
	/* Update what sysfs shows */
	sysctl_ibrs_enabled = true;
	/* When entering kernel */
	x86_spec_ctrl_priv |= SPEC_CTRL_IBRS;
	/* Update per-cpu spec_ctrl */
	update_cpu_spec_ctrl_all();
}

static inline void clear_ibrs_inuse(void)
{
	use_ibrs &= ~(SPEC_CTRL_BASIC_IBRS_INUSE | SPEC_CTRL_ENHCD_IBRS_INUSE);
	update_cpu_ibrs_all();
	/* Update what sysfs shows. */
	sysctl_ibrs_enabled = false;
	/*
	 * This is stricly not needed as the use_ibrs guards against the
	 * the use of the MSR so these values wouldn't be touched.
	 */
	x86_spec_ctrl_priv &= ~(SPEC_CTRL_IBRS);
	update_cpu_spec_ctrl_all();
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

static inline int cpu_ibrs_inuse_any(void)
{
	return (this_cpu_read(cpu_ibrs) &
	    (SPEC_CTRL_BASIC_IBRS_INUSE | SPEC_CTRL_ENHCD_IBRS_INUSE)) ? 1 : 0;
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

/* indicate usage of IBPB to control execution speculation */
DECLARE_STATIC_KEY_FALSE(switch_mm_always_ibpb);
DECLARE_STATIC_KEY_FALSE(switch_mm_cond_ibpb);

static inline u32 ibpb_enabled(void)
{
	if (static_key_enabled(&switch_mm_always_ibpb))
		return 1;
	if (static_key_enabled(&switch_mm_cond_ibpb))
		return 2;
	return 0;
}

static inline void ibpb_always_enable(void)
{
	static_branch_enable(&switch_mm_always_ibpb);
}

static inline void ibpb_cond_enable(void)
{
	static_branch_enable(&switch_mm_cond_ibpb);
}

static inline void ibpb_disable(void)
{
	static_branch_disable(&switch_mm_always_ibpb);
	static_branch_disable(&switch_mm_cond_ibpb);
}

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_SPEC_CTRL_H */
