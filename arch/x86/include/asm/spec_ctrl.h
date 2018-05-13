#ifndef _ASM_X86_SPEC_CTRL_H
#define _ASM_X86_SPEC_CTRL_H

#include <linux/stringify.h>
#include <asm/msr-index.h>
#include <asm/cpufeature.h>
#include <asm/alternative-asm.h>

#define SPEC_CTRL_IBRS_INUSE           (1<<0)  /* OS enables IBRS usage */
#define SPEC_CTRL_IBRS_SUPPORTED       (1<<1)  /* System supports IBRS */
#define SPEC_CTRL_IBRS_ADMIN_DISABLED  (1<<2)  /* Admin disables IBRS */
#define SPEC_CTRL_IBRS_FIRMWARE        (1<<3)  /* IBRS to be used on firmware paths */

#ifdef __ASSEMBLY__

.extern use_ibrs
.extern use_ibpb
.extern x86_spec_ctrl_priv
.extern x86_spec_ctrl_base

#define __ASM_ENABLE_IBRS			\
	pushq %rax;				\
	pushq %rcx;				\
	pushq %rdx;				\
	movl $MSR_IA32_SPEC_CTRL, %ecx;		\
	movl $0, %edx;				\
	movl x86_spec_ctrl_priv, %eax;		\
	wrmsr;					\
	popq %rdx;				\
	popq %rcx;				\
	popq %rax
#define __ASM_ENABLE_IBRS_CLOBBER		\
	movl $MSR_IA32_SPEC_CTRL, %ecx;		\
	movl $0, %edx;				\
	movl x86_spec_ctrl_priv, %eax;		\
	wrmsr;
#define __ASM_DISABLE_IBRS			\
	pushq %rax;				\
	pushq %rcx;				\
	pushq %rdx;				\
	movl $MSR_IA32_SPEC_CTRL, %ecx;		\
	movl $0, %edx;				\
	movl x86_spec_ctrl_base, %eax;		\
	wrmsr;					\
	popq %rdx;				\
	popq %rcx;				\
	popq %rax
#define __ASM_SET_IBPB				\
	pushq %rax;				\
	pushq %rcx;				\
	pushq %rdx;				\
	movl $MSR_IA32_PRED_CMD, %ecx;		\
	movl $0, %edx;				\
	movl $FEATURE_SET_IBPB, %eax;		\
	wrmsr;					\
	popq %rdx;				\
	popq %rcx;				\
	popq %rax
#define __ASM_DISABLE_IBRS_CLOBBER		\
	movl $MSR_IA32_SPEC_CTRL, %ecx;		\
	movl $0, %edx;				\
	movl x86_spec_ctrl_base, %eax;		\
	wrmsr;

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

.macro ENABLE_IBRS
	testl	$SPEC_CTRL_IBRS_INUSE, use_ibrs
	jz	7f
	__ASM_ENABLE_IBRS
	jmp	20f
7:
	lfence
20:
.endm

.macro ENABLE_IBRS_CLOBBER
	testl	$SPEC_CTRL_IBRS_INUSE, use_ibrs
	jz	11f
	__ASM_ENABLE_IBRS_CLOBBER
	jmp	21f
11:
	lfence
21:
.endm

.macro ENABLE_IBRS_SAVE_AND_CLOBBER save_reg:req
	testl	$SPEC_CTRL_IBRS_INUSE, use_ibrs
	jz	12f

	movl	$MSR_IA32_SPEC_CTRL, %ecx
	rdmsr
	movl	%eax, \save_reg

	movl	$0, %edx
	movl	$SPEC_CTRL_FEATURE_ENABLE_IBRS, %eax
	wrmsr
	jmp 22f
12:
	movl $SPEC_CTRL_FEATURE_ENABLE_IBRS, \save_reg
	lfence
22:
.endm

.macro RESTORE_IBRS_CLOBBER save_reg:req
	testl	$SPEC_CTRL_IBRS_INUSE, use_ibrs
	jz	13f

	testl	$SPEC_CTRL_FEATURE_ENABLE_IBRS, \save_reg
	jnz	13f

	movl	$MSR_IA32_SPEC_CTRL, %ecx
	movl	$0, %edx
	movl	\save_reg, %eax
	wrmsr
	jmp 23f
13:
	lfence
23:
.endm

.macro DISABLE_IBRS
	testl	$SPEC_CTRL_IBRS_INUSE, use_ibrs
	jz	9f
	__ASM_DISABLE_IBRS
9:
.endm

.macro SET_IBPB
ALTERNATIVE "", __stringify(__ASM_SET_IBPB), X86_FEATURE_IBRS
.endm

.macro DISABLE_IBRS_CLOBBER
ALTERNATIVE "", __stringify(__ASM_DISABLE_IBRS_CLOBBER), X86_FEATURE_IBRS
.endm

.macro STUFF_RSB
ALTERNATIVE __stringify(__ASM_STUFF_RSB), "", X86_FEATURE_STUFF_RSB
.endm

#else

/* Defined in bugs_64.c */
extern u64 x86_spec_ctrl_priv;
extern u64 x86_spec_ctrl_base;

/* indicate usage of IBRS to control execution speculation */
extern int use_ibrs;
extern u32 sysctl_ibrs_enabled;
extern struct mutex spec_ctrl_mutex;

extern void unprotected_firmware_begin(void);
extern void unprotected_firmware_end(void);

#define ibrs_firmware		(use_ibrs & SPEC_CTRL_IBRS_FIRMWARE)
#define ibrs_supported		(use_ibrs & SPEC_CTRL_IBRS_SUPPORTED)
#define ibrs_disabled		(use_ibrs & SPEC_CTRL_IBRS_ADMIN_DISABLED)

#define ibrs_inuse		(check_ibrs_inuse())

static inline bool set_ibrs_inuse(void)
{
	if (ibrs_supported && !ibrs_disabled) {
		use_ibrs |= SPEC_CTRL_IBRS_INUSE;
		/* Update what sysfs shows. */
		sysctl_ibrs_enabled = true;
		/* When entering kernel */
		x86_spec_ctrl_priv |= SPEC_CTRL_FEATURE_ENABLE_IBRS;
		return true;
	} else {
		return false;
	}
}

static inline void clear_ibrs_inuse(void)
{
	use_ibrs &= ~SPEC_CTRL_IBRS_INUSE;
	/* Update what sysfs shows. */
	sysctl_ibrs_enabled = false;
	/*
        * This is stricly not needed as the use_ibrs guards against the
        * the use of the MSR so these values wouldn't be touched.
        */
       x86_spec_ctrl_priv &= ~(SPEC_CTRL_FEATURE_ENABLE_IBRS);

}

static inline int check_ibrs_inuse(void)
{
	if (use_ibrs & SPEC_CTRL_IBRS_INUSE) {
		return 1;
	} else {
		/* rmb to prevent wrong speculation for security */
		rmb();
	}
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

static inline void clear_ibrs_disabled(void)
{
	use_ibrs &= ~SPEC_CTRL_IBRS_ADMIN_DISABLED;
	(void)set_ibrs_inuse();
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

/* indicate usage of IBPB to control execution speculation */
extern int use_ibpb;
extern u32 sysctl_ibpb_enabled;

#define SPEC_CTRL_IBPB_INUSE		(1<<0)	/* OS enables IBPB usage */
#define SPEC_CTRL_IBPB_SUPPORTED	(1<<1)	/* System supports IBPB */
#define SPEC_CTRL_IBPB_ADMIN_DISABLED	(1<<2)	/* Admin disables IBPB */

#define ibpb_supported		(use_ibpb & SPEC_CTRL_IBPB_SUPPORTED)
#define ibpb_disabled		(use_ibpb & SPEC_CTRL_IBPB_ADMIN_DISABLED)

#define ibpb_inuse		(check_ibpb_inuse())

static inline bool set_ibpb_inuse(void)
{
	if (ibpb_supported && !ibpb_disabled) {
		use_ibpb |= SPEC_CTRL_IBPB_INUSE;
		sysctl_ibpb_enabled = true;
		return true;
	} else {
		return false;
	}
}

static inline void clear_ibpb_inuse(void)
{
	use_ibpb &= ~SPEC_CTRL_IBPB_INUSE;
	sysctl_ibpb_enabled = false;
}

static inline int check_ibpb_inuse(void)
{
	if (use_ibpb & SPEC_CTRL_IBPB_INUSE) {
		return 1;
	} else {
		/* rmb to prevent wrong speculation for security */
		rmb();
	}
	return 0;
}

static inline void set_ibpb_supported(void)
{
	use_ibpb |= SPEC_CTRL_IBPB_SUPPORTED;
	if (!ibpb_disabled)
		(void)set_ibpb_inuse();
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
	(void)set_ibpb_inuse();
}

/*
 * Allow/disallow falling back to another Spectre v2 mitigation
 * when disabling retpoline.
 */

extern int retpoline_fallback;
extern u32 sysctl_retpoline_fallback;

/* Flags for retpoline_fallback: */
#define SPEC_CTRL_USE_RETPOLINE_FALLBACK (1<<0)	/* pick new mitigation */
						/* when disabling retpoline */

#define allow_retpoline_fallback (retpoline_fallback &			\
				  SPEC_CTRL_USE_RETPOLINE_FALLBACK)

static inline void set_retpoline_fallback(void)
{
	retpoline_fallback |= SPEC_CTRL_USE_RETPOLINE_FALLBACK;

	/* Update what sysfs shows. */
	sysctl_retpoline_fallback = 1;
}

static inline void clear_retpoline_fallback(void)
{
	retpoline_fallback &= ~SPEC_CTRL_USE_RETPOLINE_FALLBACK;

	/* Update what sysfs shows. */
	sysctl_retpoline_fallback = 0;
}

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_SPEC_CTRL_H */
