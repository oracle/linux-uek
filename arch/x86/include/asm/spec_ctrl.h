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

#ifndef __ASSEMBLY__

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
extern struct mutex spec_ctrl_mutex;

DECLARE_STATIC_KEY_FALSE(retpoline_enabled_key);

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

static inline void clear_ibrs_disabled(void)
{
	use_ibrs &= ~SPEC_CTRL_IBRS_ADMIN_DISABLED;
	set_ibrs_inuse();
}

#endif /* __ASSEMBLY__ */
#endif /* _ASM_X86_SPEC_CTRL_H */
