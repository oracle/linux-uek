#ifndef _ASM_X86_SPEC_CTRL_H
#define _ASM_X86_SPEC_CTRL_H

#include <linux/stringify.h>
#include <asm/msr-index.h>
#include <asm/cpufeatures.h>
#include <asm/alternative-asm.h>

#define SPEC_CTRL_IBRS_INUSE           (1<<0)  /* OS enables IBRS usage */
#define SPEC_CTRL_IBRS_SUPPORTED       (1<<1)  /* System supports IBRS */
#define SPEC_CTRL_IBRS_ADMIN_DISABLED  (1<<2)  /* Admin disables IBRS */
#define SPEC_CTRL_IBRS_FIRMWARE        (1<<3)  /* IBRS to be used on firmware paths */

#ifdef __ASSEMBLY__

.extern use_ibrs
.extern x86_spec_ctrl_priv
.extern x86_spec_ctrl_base

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
	testl	$SPEC_CTRL_IBRS_INUSE, PER_CPU_VAR(cpu_ibrs)
	jz	.Lskip_\@
	PUSH_MSR_REGS
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, PER_CPU_VAR(x86_spec_ctrl_priv_cpu)
	POP_MSR_REGS
	jmp	.Ldone_\@
.Lskip_\@:
	 lfence
.Ldone_\@:
.endm

.macro DISABLE_IBRS
	testl	$SPEC_CTRL_IBRS_INUSE, PER_CPU_VAR(cpu_ibrs)
	jz	.Lskip_\@
	PUSH_MSR_REGS
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, x86_spec_ctrl_base
	POP_MSR_REGS
.Lskip_\@:
.endm

.macro ENABLE_IBRS_SAVE_AND_CLOBBER save_reg:req
	testl	$SPEC_CTRL_IBRS_INUSE, PER_CPU_VAR(cpu_ibrs)
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
	testl	$SPEC_CTRL_IBRS_INUSE, PER_CPU_VAR(cpu_ibrs)
	jz	.Lskip_\@

	testl	$SPEC_CTRL_FEATURE_ENABLE_IBRS, \save_reg
	jnz	.Lskip_\@

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
	testl	$SPEC_CTRL_IBRS_INUSE, PER_CPU_VAR(cpu_ibrs)
	jz	.Lskip_\@
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, PER_CPU_VAR(x86_spec_ctrl_priv_cpu)
	jmp	.Ldone_\@
.Lskip_\@:
	 lfence
.Ldone_\@:
.endm

.macro DISABLE_IBRS_CLOBBER
	testl	$SPEC_CTRL_IBRS_INUSE, PER_CPU_VAR(cpu_ibrs)
	jz	.Lskip_\@
	WRMSR_ASM $MSR_IA32_SPEC_CTRL, x86_spec_ctrl_base
.Lskip_\@:
.endm

.macro STUFF_RSB_NON_SMEP
	ALTERNATIVE __stringify(__ASM_STUFF_RSB), "", X86_FEATURE_STUFF_RSB
.endm

#else

/* Defined in bugs.c */
extern u64 x86_spec_ctrl_priv;
DECLARE_PER_CPU(u64, x86_spec_ctrl_priv_cpu);
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
extern u32 sysctl_ibrs_enabled;
extern struct mutex spec_ctrl_mutex;

#define ibrs_firmware		(use_ibrs & SPEC_CTRL_IBRS_FIRMWARE)
#define ibrs_supported		(use_ibrs & SPEC_CTRL_IBRS_SUPPORTED)
#define ibrs_disabled		(use_ibrs & SPEC_CTRL_IBRS_ADMIN_DISABLED)

#define ibrs_inuse		(cpu_ibrs_inuse())

static inline void update_cpu_spec_ctrl(int cpu)
{
	per_cpu(x86_spec_ctrl_priv_cpu, cpu) = x86_spec_ctrl_priv;
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
	if (ibrs_supported && !ibrs_disabled) {
		use_ibrs |= SPEC_CTRL_IBRS_INUSE;
		update_cpu_ibrs_all();
		/* Update what sysfs shows. */
		sysctl_ibrs_enabled = true;
		/* When entering kernel */
		x86_spec_ctrl_priv |= SPEC_CTRL_FEATURE_ENABLE_IBRS;
		/* Update per-cpu spec_ctrl */
		update_cpu_spec_ctrl_all();
	}
}

static inline void clear_ibrs_inuse(void)
{
	use_ibrs &= ~SPEC_CTRL_IBRS_INUSE;
	update_cpu_ibrs_all();
	/* Update what sysfs shows. */
	sysctl_ibrs_enabled = false;
	/*
	 * This is stricly not needed as the use_ibrs guards against the
	 * the use of the MSR so these values wouldn't be touched.
	 */
	x86_spec_ctrl_priv &= ~(SPEC_CTRL_FEATURE_ENABLE_IBRS);
	update_cpu_spec_ctrl_all();
}

static inline int check_ibrs_inuse(void)
{
	if (use_ibrs & SPEC_CTRL_IBRS_INUSE)
		return 1;

	/* rmb to prevent wrong speculation for security */
	rmb();
	return 0;
}

static inline int cpu_ibrs_inuse(void)
{
	return (this_cpu_read(cpu_ibrs) & SPEC_CTRL_IBRS_INUSE) ? 1 : 0;
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

static inline void set_ibrs_firmware(void)
{
	if (ibrs_supported)
		use_ibrs |= SPEC_CTRL_IBRS_FIRMWARE;
}

static inline void disable_ibrs_firmware(void)
{
	use_ibrs &= ~SPEC_CTRL_IBRS_FIRMWARE;
}

static inline void clear_ibrs_disabled(void)
{
	use_ibrs &= ~SPEC_CTRL_IBRS_ADMIN_DISABLED;
	set_ibrs_inuse();
}

/* indicate usage of IBPB to control execution speculation */
extern unsigned int use_ibpb;
extern u32 sysctl_ibpb_enabled;

#define SPEC_CTRL_IBPB_INUSE		(1<<0)	/* OS enables IBPB usage */
#define SPEC_CTRL_IBPB_SUPPORTED	(1<<1)	/* System supports IBPB */
#define SPEC_CTRL_IBPB_ADMIN_DISABLED	(1<<2)	/* Admin disables IBPB */

#define ibpb_supported		(use_ibpb & SPEC_CTRL_IBPB_SUPPORTED)
#define ibpb_disabled		(use_ibpb & SPEC_CTRL_IBPB_ADMIN_DISABLED)

#define ibpb_inuse		(check_ibpb_inuse())

static inline void set_ibpb_inuse(void)
{
	if (ibpb_supported && !ibpb_disabled) {
		use_ibpb |= SPEC_CTRL_IBPB_INUSE;
		sysctl_ibpb_enabled = true;
	}
}

static inline void clear_ibpb_inuse(void)
{
	use_ibpb &= ~SPEC_CTRL_IBPB_INUSE;
	sysctl_ibpb_enabled = false;
}

static inline int check_ibpb_inuse(void)
{
	if (use_ibpb & SPEC_CTRL_IBPB_INUSE)
		return 1;

	/* rmb to prevent wrong speculation for security */
	rmb();
	return 0;
}

static inline void set_ibpb_supported(void)
{
	use_ibpb |= SPEC_CTRL_IBPB_SUPPORTED;
	if (!ibpb_disabled)
		set_ibpb_inuse();
}

static inline void set_ibpb_disabled(void)
{
	use_ibpb |= SPEC_CTRL_IBPB_ADMIN_DISABLED;
	if (check_ibpb_inuse())
		clear_ibpb_inuse();
}

static inline void clear_ibpb_disabled(void)
{
	use_ibpb &= ~SPEC_CTRL_IBPB_ADMIN_DISABLED;
	set_ibpb_inuse();
}

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_SPEC_CTRL_H */
