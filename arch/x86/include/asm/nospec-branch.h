/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_X86_NOSPEC_BRANCH_H_
#define _ASM_X86_NOSPEC_BRANCH_H_

#include <linux/static_key.h>
#include <linux/frame.h>

#include <asm/alternative.h>
#include <asm/alternative-asm.h>
#include <asm/cpufeatures.h>
#include <asm/msr-index.h>
#include <asm/msr.h>
#include <asm/nospec-annotate.h>
#include <asm/unwind_hints.h>

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
#ifdef CONFIG_X86_64
#define __FILL_RETURN_BUFFER(reg, nr, sp)	\
	mov	$(nr/2), reg;			\
771:						\
	ANNOTATE_INTRA_FUNCTION_CALL;		\
	call	772f;				\
773:	/* speculation trap */			\
	UNWIND_HINT_EMPTY_ASM;			\
	pause;					\
	lfence;					\
	jmp	773b;				\
772:						\
	ANNOTATE_INTRA_FUNCTION_CALL;		\
	call	774f;				\
775:	/* speculation trap */			\
	UNWIND_HINT_EMPTY_ASM;			\
	pause;					\
	lfence;					\
	jmp	775b;				\
774:						\
	add	$(BITS_PER_LONG/8) * 2, sp;	\
	dec	reg;				\
	jnz	771b;				\
	/* barrier for jnz misprediction */	\
	lfence;
#else
/*
 * i386 doesn't unconditionally have LFENCE, as such it can't
 * do a loop.
 */
#define __FILL_RETURN_BUFFER(reg, nr, sp)	\
	.rept nr;				\
	call	772f;				\
	int3;					\
772:;						\
	.endr;					\
	add	$(BITS_PER_LONG/8) * nr, sp;
#endif

#ifdef __ASSEMBLY__

.extern retpoline_enabled_key

/*
 * (ab)use RETPOLINE_SAFE on RET to annotate away 'bare' RET instructions
 * vs RETBleed validation.
 */
#define ANNOTATE_UNRET_SAFE ANNOTATE_RETPOLINE_SAFE

/*
 * Abuse ANNOTATE_RETPOLINE_SAFE on a NOP to indicate UNRET_END, should
 * eventually turn into it's own annotation.
 */
.macro ANNOTATE_UNRET_END
#if (defined(CONFIG_CPU_UNRET_ENTRY) || defined(CONFIG_CPU_SRSO))
	ANNOTATE_RETPOLINE_SAFE
	nop
#endif
.endm

/*
 * JMP_NOSPEC and CALL_NOSPEC macros can be used instead of a simple
 * indirect jmp/call which may be susceptible to the Spectre variant 2
 * attack.
 */
.macro JMP_NOSPEC reg:req
#ifdef CONFIG_RETPOLINE
	STATIC_JUMP_IF_TRUE .Lretpoline_jmp_\@, retpoline_enabled_key, def=0
	ANNOTATE_RETPOLINE_SAFE
	jmp	*%\reg
.Lretpoline_jmp_\@:
	ALTERNATIVE_2 __stringify(jmp __x86_retpoline_\reg),							\
		__stringify(lfence; ANNOTATE_RETPOLINE_SAFE; jmp *%\reg; int3), X86_FEATURE_RETPOLINE_LFENCE,	\
		__stringify(ANNOTATE_RETPOLINE_SAFE; jmp *%\reg), ALT_NOT(X86_FEATURE_RETPOLINE)
#else
	jmp	*%\reg
#endif
.endm

.macro CALL_NOSPEC reg:req
#ifdef CONFIG_RETPOLINE
	STATIC_JUMP_IF_TRUE .Lretpoline_call_\@, retpoline_enabled_key, def=0
	ANNOTATE_RETPOLINE_SAFE
	call	*%\reg
	jmp	.Ldone_call_\@
.Lretpoline_call_\@:
	ALTERNATIVE_2 __stringify(ANNOTATE_RETPOLINE_SAFE; call *%\reg),	\
		__stringify(call __x86_retpoline_\reg), X86_FEATURE_RETPOLINE,	\
		__stringify(lfence; ANNOTATE_RETPOLINE_SAFE; call *%\reg), X86_FEATURE_RETPOLINE_LFENCE
.Ldone_call_\@:
#else
	call	*%\reg
#endif
.endm

.macro ISSUE_UNBALANCED_RET_GUARD
	ANNOTATE_INTRA_FUNCTION_CALL
	call .Lunbalanced_ret_guard_\@
	int3
.Lunbalanced_ret_guard_\@:
	add $(BITS_PER_LONG/8), %_ASM_SP
	lfence
.endm

 /*
  * A simpler FILL_RETURN_BUFFER macro. Don't make people use the CPP
  * monstrosity above, manually.
  */
.macro FILL_RETURN_BUFFER reg:req nr:req ftr:req ftr2
.ifb \ftr2
	ALTERNATIVE "jmp .Lskip_rsb_\@", "", \ftr
.else
	ALTERNATIVE_2 "jmp .Lskip_rsb_\@", "", \ftr, "jmp .Lunbalanced_\@", \ftr2
.endif
	__FILL_RETURN_BUFFER(\reg,\nr,%_ASM_SP)
.Lunbalanced_\@:
	ISSUE_UNBALANCED_RET_GUARD
.Lskip_rsb_\@:
.endm

#ifdef CONFIG_CPU_UNRET_ENTRY
#define CALL_UNTRAIN_RET	"call entry_untrain_ret"
#else
#define CALL_UNTRAIN_RET	""
#endif

/*
 * Mitigate RETBleed for AMD/Hygon Zen uarch. Requires KERNEL CR3 because the
 * return thunk isn't mapped into the userspace tables (then again, AMD
 * typically has NO_MELTDOWN).
 *
 * While retbleed_untrain_ret() doesn't clobber anything but requires stack,
 * entry_ibpb() will clobber AX, CX, DX.
 *
 * As such, this must be placed after every *SWITCH_TO_KERNEL_CR3 at a point
 * where we have a stack but before any RET instruction.
 */
.macro UNTRAIN_RET
#if defined(CONFIG_CPU_UNRET_ENTRY) || defined(CONFIG_CPU_IBPB_ENTRY) || \
	defined(CONFIG_CPU_SRSO)
	ANNOTATE_UNRET_END
	ALTERNATIVE_2 "",						\
		      CALL_UNTRAIN_RET, X86_FEATURE_UNRET,		\
		      "call entry_ibpb", X86_FEATURE_ENTRY_IBPB
#endif
.endm

#ifdef CONFIG_X86_64
.macro CLEAR_BRANCH_HISTORY
	ALTERNATIVE "", "call clear_bhb_loop", X86_FEATURE_CLEAR_BHB_LOOP
.endm

.macro CLEAR_BRANCH_HISTORY_VMEXIT
	ALTERNATIVE "", "call clear_bhb_loop", X86_FEATURE_CLEAR_BHB_LOOP_ON_VMEXIT
.endm
#else
#define CLEAR_BRANCH_HISTORY
#define CLEAR_BRANCH_HISTORY_VMEXIT
#endif

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
	".long 901b - ., 902f - .\n"				\
	_ASM_PTR "retpoline_enabled_key - .\n"			\
	".popsection\n"						\
	ANNOTATE_RETPOLINE_SAFE					\
	"	call *%[thunk_target]\n"			\
	"	jmp  903f\n"					\
	"	.align 16\n"					\
	"902:"							\
	ALTERNATIVE_2(						\
	ANNOTATE_RETPOLINE_SAFE					\
	"call *%[thunk_target]\n",				\
	"call __x86_retpoline_%V[thunk_target];\n",		\
	X86_FEATURE_RETPOLINE,					\
	"lfence;\n"						\
	ANNOTATE_RETPOLINE_SAFE					\
	"call *%[thunk_target]\n",				\
	X86_FEATURE_RETPOLINE_LFENCE)				\
	"903:"
# define THUNK_TARGET(addr) [thunk_target] "r" (addr)

#else /* CONFIG_X86_32 */
/*
 * For i386 we use the original ret-equivalent retpoline, because
 * otherwise we'll run out of registers. We don't care about CET
 * here, anyway.
 */
# define CALL_NOSPEC						\
	ALTERNATIVE(						\
	"910: .byte " __stringify(STATIC_KEY_INIT_NOP) "\n"	\
	".pushsection __jump_table, \"aw\"\n"			\
	_ASM_ALIGN "\n"						\
	_ASM_PTR "910b, 904f, retpoline_enabled_key\n"		\
	".popsection\n"						\
	ANNOTATE_RETPOLINE_SAFE					\
	"	call *%[thunk_target];\n"			\
	"	jmp   905f;\n"					\
	"       .align 16\n"					\
	"901:	call   903f;\n"					\
	"902:	pause;\n"					\
	"    	lfence;\n"					\
	"       jmp    902b;\n"					\
	"       .align 16\n"					\
	"903:	lea    4(%%esp), %%esp;\n"			\
	"       pushl  %[thunk_target];\n"			\
	"       ret;\n"						\
	"       .align 16\n"					\
	"904:	call   901b;\n"					\
	"905:",							\
	"lfence;\n"						\
	ANNOTATE_RETPOLINE_SAFE					\
	"call *%[thunk_target]\n",				\
	X86_FEATURE_RETPOLINE_LFENCE)

# define THUNK_TARGET(addr) [thunk_target] "rm" (addr)
#endif
#else /* No retpoline for C / inline asm */
# define CALL_NOSPEC "call *%[thunk_target]\n"
# define THUNK_TARGET(addr) [thunk_target] "rm" (addr)
#endif

/* The Spectre V2 mitigation variants */
enum spectre_v2_mitigation {
	SPECTRE_V2_NONE,
	SPECTRE_V2_RETPOLINE,
	SPECTRE_V2_LFENCE,
	SPECTRE_V2_IBRS,
	SPECTRE_V2_EIBRS,
	SPECTRE_V2_EIBRS_RETPOLINE,
	SPECTRE_V2_EIBRS_LFENCE,
};

/* The indirect branch speculation control variants */
enum spectre_v2_user_mitigation {
	SPECTRE_V2_USER_NONE,
	SPECTRE_V2_USER_STRICT,
	SPECTRE_V2_USER_STRICT_PREFERRED,
	SPECTRE_V2_USER_PRCTL,
	SPECTRE_V2_USER_SECCOMP,
};

/* The Speculative Store Bypass disable variants */
enum ssb_mitigation {
	SPEC_STORE_BYPASS_NONE,
	SPEC_STORE_BYPASS_DISABLE,
	SPEC_STORE_BYPASS_PRCTL,
	SPEC_STORE_BYPASS_SECCOMP,
	SPEC_STORE_BYPASS_USERSPACE,
};

enum spec_ctrl_set_context {
	SPEC_CTRL_INITIAL,	/* boottime and CPU hotplug */
	SPEC_CTRL_IDLE_ENTER,
	SPEC_CTRL_IDLE_EXIT,
};

extern void x86_spec_ctrl_set(enum spec_ctrl_set_context);
extern u64 spec_ctrl_current(void);

extern char __indirect_thunk_start[];
extern char __indirect_thunk_end[];

#ifdef CONFIG_RETHUNK
extern void __x86_return_thunk(void);
#else
static inline void __x86_return_thunk(void) {}
#endif

extern void retbleed_return_thunk(void);
extern void srso_return_thunk(void);
extern void srso_alias_return_thunk(void);

extern void retbleed_untrain_ret(void);
extern void srso_untrain_ret(void);
extern void srso_alias_untrain_ret(void);

extern void entry_untrain_ret(void);
extern void entry_ibpb(void);

#ifdef CONFIG_X86_64
extern void clear_bhb_loop(void);
#endif

DECLARE_STATIC_KEY_FALSE(switch_mm_always_ibpb);
DECLARE_STATIC_KEY_FALSE(switch_mm_cond_ibpb);

extern u64 x86_pred_cmd;

static inline void indirect_branch_prediction_barrier(void)
{
	if (static_branch_likely(&switch_mm_always_ibpb) || static_branch_likely(&switch_mm_cond_ibpb))
		wrmsrl(MSR_IA32_PRED_CMD, x86_pred_cmd);
}

/* The Intel SPEC CTRL MSR base value cache */
extern u64 x86_spec_ctrl_base;
extern void update_spec_ctrl_cond(u64 val);

/*
 * With retpoline, we must use IBRS to restrict branch prediction
 * before calling into firmware.
 *
 * (Implemented as CPP macros due to header hell.)
 */
DECLARE_STATIC_KEY_FALSE(ibrs_firmware_enabled_key);

#define firmware_restrict_branch_speculation_start()			\
do {									\
	preempt_disable();						\
	if (static_branch_likely(&ibrs_firmware_enabled_key))		\
		wrmsrl(MSR_IA32_SPEC_CTRL,				\
		       spec_ctrl_current() | SPEC_CTRL_IBRS);		\
									\
	if (static_cpu_has(X86_FEATURE_USE_IBPB_FW))			\
		wrmsrl(MSR_IA32_PRED_CMD, PRED_CMD_IBPB);		\
} while (0)

#define firmware_restrict_branch_speculation_end()			\
do {									\
	if (static_branch_likely(&ibrs_firmware_enabled_key))		\
		wrmsrl(MSR_IA32_SPEC_CTRL, spec_ctrl_current());	\
	preempt_enable();						\
} while (0)

DECLARE_STATIC_KEY_FALSE(switch_to_cond_stibp);
DECLARE_STATIC_KEY_FALSE(switch_mm_cond_ibpb);
DECLARE_STATIC_KEY_FALSE(switch_mm_always_ibpb);

DECLARE_STATIC_KEY_FALSE(mds_user_clear);
DECLARE_STATIC_KEY_FALSE(mds_idle_clear);

DECLARE_STATIC_KEY_FALSE(mmio_stale_data_clear);

#include <asm/segment.h>

/**
 * mds_clear_cpu_buffers - Mitigation for MDS and TAA vulnerability
 *
 * This uses the otherwise unused and obsolete VERW instruction in
 * combination with microcode which triggers a CPU buffer flush when the
 * instruction is executed.
 */
static __always_inline void mds_clear_cpu_buffers(void)
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
static __always_inline void mds_user_clear_cpu_buffers(void)
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
