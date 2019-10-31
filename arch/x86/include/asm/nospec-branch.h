/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_X86_NOSPEC_BRANCH_H_
#define _ASM_X86_NOSPEC_BRANCH_H_

#include <linux/jump_label.h>

#include <asm/alternative.h>
#include <asm/alternative-asm.h>
#include <asm/cpufeature.h>

/*
 * Fill the CPU return stack buffer.
 *
 * Each entry in the RSB, if used for a speculative 'ret', contains an
 * infinite 'pause; lfence; jmp' loop to capture speculative execution.
 *
 * This is required in various cases for retpoline and IBRS-based
 * mitigations for the Spectre variant 2 vulnerability. Sometimes to
 * eliminate potentially bogus entries from the RSB, and sometimes
 * purely to ensure that it doesn't get empty, which on some CPUs would
 * allow predictions from other (unwanted!) sources to be used.
 *
 * We define a CPP macro such that it can be used from both .S files and
 * inline assembly. It's possible to do a .macro and then include that
 * from C via asm(".include <asm/nospec-branch.h>") but let's not go there.
 */

#define RSB_CLEAR_LOOPS		32	/* To forcibly overwrite all entries */
#define RSB_FILL_LOOPS		16	/* To avoid underflow */

/*
 * Google experimented with loop-unrolling and this turned out to be
 * the optimal version — two calls, each with their own speculation
 * trap should their return address end up getting used, in a loop.
 */
#define __FILL_RETURN_BUFFER(reg, nr, sp)	\
	mov	$(nr/2), reg;			\
771:						\
	call	772f;				\
773:	/* speculation trap */			\
	pause;					\
	lfence;					\
	jmp	773b;				\
772:						\
	call	774f;				\
775:	/* speculation trap */			\
	pause;					\
	lfence;					\
	jmp	775b;				\
774:						\
	dec	reg;				\
	jnz	771b;				\
	add	$(BITS_PER_LONG/8) * nr, sp;

#ifdef __ASSEMBLY__

.extern retpoline_enabled_key

/*
 * These are the bare retpoline primitives for indirect jmp and call.
 * Do not use these directly; they only exist to make the ALTERNATIVE
 * invocation below less ugly.
 */
.macro RETPOLINE_JMP reg:req
	call	.Ldo_rop_\@
.Lspec_trap_\@:
	pause
	lfence
	jmp	.Lspec_trap_\@
.Ldo_rop_\@:
	mov	\reg, (%_ASM_SP)
	ret
.endm

/*
 * This is a wrapper around RETPOLINE_JMP so the called function in reg
 * returns to the instruction after the macro.
 */
.macro RETPOLINE_CALL reg:req
	jmp	.Ldo_call_\@
.Ldo_retpoline_jmp_\@:
	RETPOLINE_JMP \reg
.Ldo_call_\@:
	call	.Ldo_retpoline_jmp_\@
.endm

/*
 * JMP_NOSPEC and CALL_NOSPEC macros can be used instead of a simple
 * indirect jmp/call which may be susceptible to the Spectre variant 2
 * attack.
 */
.macro JMP_NOSPEC reg:req
#ifdef CONFIG_RETPOLINE
	STATIC_JUMP_IF_TRUE .Lretpoline_jmp_\@, retpoline_enabled_key, def=0
	jmp	*\reg
.Lretpoline_jmp_\@:
	ALTERNATIVE __stringify(RETPOLINE_JMP \reg), \
		__stringify(lfence; jmp *\reg), X86_FEATURE_RETPOLINE_AMD
#else
	jmp	*\reg
#endif
.endm

.macro CALL_NOSPEC reg:req
#ifdef CONFIG_RETPOLINE
	STATIC_JUMP_IF_TRUE .Lretpoline_call_\@, retpoline_enabled_key, def=0
	call	*\reg
	jmp	.Ldone_call_\@
.Lretpoline_call_\@:
	ALTERNATIVE __stringify(RETPOLINE_CALL \reg), \
		__stringify(lfence; call *\reg), X86_FEATURE_RETPOLINE_AMD
.Ldone_call_\@:
#else
	call	*\reg
#endif
.endm

 /*
  * A simpler FILL_RETURN_BUFFER macro. Don't make people use the CPP
  * monstrosity above, manually.
  */
.macro FILL_RETURN_BUFFER reg:req nr:req ftr:req
#ifdef CONFIG_RETPOLINE
	ALTERNATIVE "jmp .Lskip_rsb_\@",				\
		__stringify(__FILL_RETURN_BUFFER(\reg,\nr,%_ASM_SP))	\
		\ftr
.Lskip_rsb_\@:
#endif
.endm


/**
 * MDS_CLEAR_CPU_BUFFERS - Mitigation for MDS vulnerability
 *
 * This uses the otherwise unused and obsolete VERW instruction in
 * combination with microcode which triggers a CPU buffer flush when the
 * instruction is executed.
 */
.extern mds_user_clear

.macro MDS_CLEAR_CPU_BUFFERS
	STATIC_JUMP_IF_TRUE	.Lmdsverwcall_\@, mds_user_clear, def=0
	jmp	.Lmdsverwdone_\@
.Lmdsverwcall_\@:
	sub	$8, %rsp
	mov	%ds, (%rsp)
	verw	(%rsp)
	add	$8, %rsp
.Lmdsverwdone_\@:
.endm

.macro SPEC_RETURN_TO_USER
	DISABLE_IBRS
	MDS_CLEAR_CPU_BUFFERS
.endm

#else /* __ASSEMBLY__ */

#ifdef CONFIG_RETPOLINE
#ifdef CONFIG_X86_64

/*
 * Inline asm uses the %V modifier which is only in newer GCC
 * which is ensured when CONFIG_RETPOLINE is defined.
 */
# define CALL_NOSPEC						\
	"901: .byte " __stringify(STATIC_KEY_INIT_NOP) "\n"	\
	".pushsection __jump_table, \"aw\"\n"			\
	_ASM_ALIGN "\n"						\
	_ASM_PTR "901b, 902f, retpoline_enabled_key\n"		\
	".popsection\n"						\
	"	call *%[thunk_target];\n"			\
	"	jmp   903f;\n"					\
	"       .align 16\n"					\
	"902:	call __x86_indirect_thunk_%V[thunk_target];\n"	\
	"903:"

# define THUNK_TARGET(addr) [thunk_target] "r" (addr)

#else /* CONFIG_X86_32 */
/*
 * For i386 we use the original ret-equivalent retpoline, because
 * otherwise we'll run out of registers. We don't care about CET
 * here, anyway.
 */
# define CALL_NOSPEC						\
	"910: .byte " __stringify(STATIC_KEY_INIT_NOP) "\n"	\
	".pushsection __jump_table, \"aw\"\n"			\
	_ASM_ALIGN "\n"						\
	_ASM_PTR "910b, 904f, retpoline_enabled_key\n"		\
	".popsection\n"						\
	"	call *%[thunk_target];\n"			\
	"	jmp   905f;\n"					\
	"       .align 16\n"					\
	"901:	call   903f;\n"					\
	"902:	pause;\n"					\
	"    	lfence;\n"					\
	"       jmp    902b;\n"					\
	"       .align 16\n"					\
	"903:	addl   $4, %%esp;\n"				\
	"       pushl  %[thunk_target];\n"			\
	"       ret;\n"						\
	"       .align 16\n"					\
	"904:	call   901b;\n"					\
	"905:"

# define THUNK_TARGET(addr) [thunk_target] "rm" (addr)
#endif
#else /* No retpoline for C / inline asm */
# define CALL_NOSPEC "call *%[thunk_target]\n"
# define THUNK_TARGET(addr) [thunk_target] "rm" (addr)
#endif

/* The Spectre V2 mitigation variants */
enum spectre_v2_mitigation {
	SPECTRE_V2_NONE,
	SPECTRE_V2_RETPOLINE_GENERIC,
	SPECTRE_V2_RETPOLINE_AMD,
	SPECTRE_V2_IBRS,
	SPECTRE_V2_IBRS_ENHANCED,
};

enum spec_ctrl_set_context {
	SPEC_CTRL_INITIAL,	/* boottime and CPU hotplug */
	SPEC_CTRL_IDLE_ENTER,
	SPEC_CTRL_IDLE_EXIT,
};

extern void x86_spec_ctrl_set(enum spec_ctrl_set_context);

/* The Intel SPEC CTRL MSR base value cache */
extern u64 x86_spec_ctrl_base;

/* The Speculative Store Bypass disable variants */
enum ssb_mitigation {
	SPEC_STORE_BYPASS_NONE,
	SPEC_STORE_BYPASS_DISABLE,
	SPEC_STORE_BYPASS_PRCTL,
	SPEC_STORE_BYPASS_SECCOMP,
	SPEC_STORE_BYPASS_USERSPACE,
};

extern char __indirect_thunk_start[];
extern char __indirect_thunk_end[];

/* Speculation control prctl */
int arch_prctl_spec_ctrl_get(struct task_struct *task, unsigned long which);
int arch_prctl_spec_ctrl_set(struct task_struct *task, unsigned long which, unsigned long ctrl);
/* Speculation control for seccomp enforced mitigation */
void arch_seccomp_spec_mitigate(struct task_struct *task);

/*
 * On VMEXIT we must ensure that no RSB predictions learned in the guest
 * can be followed in the host, by overwriting the RSB completely. Both
 * retpoline and IBRS mitigations for Spectre v2 need this; only on future
 * CPUs with IBRS_ALL *might* it be avoided.
 */
static inline void vmexit_fill_RSB(void)
{
#ifdef CONFIG_RETPOLINE
	unsigned long loops;

	asm volatile (ALTERNATIVE("jmp 910f",
				  __stringify(__FILL_RETURN_BUFFER(%0, RSB_CLEAR_LOOPS, %1)),
				  X86_FEATURE_VMEXIT_RSB_FULL)
		      "910:"
		      : "=r" (loops), ASM_CALL_CONSTRAINT
		      : : "memory" );
#endif
} 

DECLARE_STATIC_KEY_FALSE(mds_user_clear);
DECLARE_STATIC_KEY_FALSE(mds_idle_clear);

#include <asm/segment.h>

/**
 * mds_clear_cpu_buffers - Mitigation for MDS and TAA vulnerability
 *
 * This uses the otherwise unused and obsolete VERW instruction in
 * combination with microcode which triggers a CPU buffer flush when the
 * instruction is executed.
 */
static inline void mds_clear_cpu_buffers(void)
{
	static const u16 ds = __KERNEL_DS;

	/*
	 * Has to be the memory-operand variant because only that
	 * guarantees the CPU buffer flush functionality according to
	 * documentation. The register-operand variant does not.
	 * Works with any segment selector, but a valid writable
	 * data segment is the fastest variant.
	 *
	 * "cc" clobber is required because VERW modifies ZF.
	 */
	asm volatile("verw %[ds]" : : [ds] "m" (ds) : "cc");
}

/**
 * mds_user_clear_cpu_buffers - Mitigation for MDS and TAA vulnerability
 *
 * Clear CPU buffers if the corresponding static key is enabled
 */
static inline void mds_user_clear_cpu_buffers(void)
{
	if (static_branch_likely(&mds_user_clear))
		mds_clear_cpu_buffers();
}

/**
 * mds_idle_clear_cpu_buffers - Mitigation for MDS vulnerability
 *
 * Clear CPU buffers if the corresponding static key is enabled
 */
static inline void mds_idle_clear_cpu_buffers(void)
{
	if (static_branch_likely(&mds_idle_clear))
		mds_clear_cpu_buffers();
}

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_NOSPEC_BRANCH_H_ */
