/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_X86_SPEC_CTRL_H
#define _ASM_X86_SPEC_CTRL_H

#include <asm/msr-index.h>
#include <asm/cpufeature.h>

#define SPEC_CTRL_IBRS_INUSE           (1<<0)  /* OS enables IBRS usage */
#define SPEC_CTRL_IBRS_SUPPORTED       (1<<1)  /* System supports IBRS */
#define SPEC_CTRL_IBRS_ADMIN_DISABLED  (1<<2)  /* Admin disables IBRS */

#ifdef __ASSEMBLY__
.extern dynamic_ibrs
#else

#include <asm/microcode.h>

extern unsigned int dynamic_ibrs;
extern u32 sysctl_ibrs_enabled;

extern struct mutex spec_ctrl_mutex;

#define ibrs_supported		(dynamic_ibrs & SPEC_CTRL_IBRS_SUPPORTED)
#define ibrs_disabled		(dynamic_ibrs & SPEC_CTRL_IBRS_ADMIN_DISABLED)

#define ibrs_inuse		(check_ibrs_inuse())

static inline void set_ibrs_inuse(void)
{
	if (ibrs_supported)
		dynamic_ibrs |= SPEC_CTRL_IBRS_INUSE;
}

static inline void clear_ibrs_inuse(void)
{
	dynamic_ibrs &= ~SPEC_CTRL_IBRS_INUSE;
}

static inline int check_ibrs_inuse(void)
{
	if (dynamic_ibrs & SPEC_CTRL_IBRS_INUSE)
		return 1;
	else
		/* rmb to prevent wrong speculation for security */
		rmb();
	return 0;
}

static inline void set_ibrs_supported(void)
{
	dynamic_ibrs |= SPEC_CTRL_IBRS_SUPPORTED;
	if (!ibrs_disabled)
		set_ibrs_inuse();
}

static inline void set_ibrs_disabled(void)
{
	dynamic_ibrs |= SPEC_CTRL_IBRS_ADMIN_DISABLED;

	if (check_ibrs_inuse())
		clear_ibrs_inuse();

	sysctl_ibrs_enabled = ibrs_inuse ? 1 : 0;
}

static inline void clear_ibrs_disabled(void)
{
	dynamic_ibrs &= ~SPEC_CTRL_IBRS_ADMIN_DISABLED;

	set_ibrs_inuse();

	sysctl_ibrs_enabled = ibrs_inuse ? 1 : 0;
}


#define SPEC_CTRL_IBPB_INUSE           (1<<0)  /* OS enables IBPB usage */
#define SPEC_CTRL_IBPB_SUPPORTED       (1<<1)  /* System supports IBPB */
#define SPEC_CTRL_IBPB_ADMIN_DISABLED  (1<<2)  /* Admin disables IBPB */

extern unsigned int dynamic_ibpb;
extern u32 sysctl_ibpb_enabled;

#define ibpb_supported		(dynamic_ibpb & SPEC_CTRL_IBPB_SUPPORTED)
#define ibpb_disabled		(dynamic_ibpb & SPEC_CTRL_IBPB_ADMIN_DISABLED)

#define ibpb_inuse		(check_ibpb_inuse())

static inline void set_ibpb_inuse(void)
{
	if (ibpb_supported)
		dynamic_ibpb |= SPEC_CTRL_IBPB_INUSE;
}

static inline void clear_ibpb_inuse(void)
{
	dynamic_ibpb &= ~SPEC_CTRL_IBPB_INUSE;
}

static inline int check_ibpb_inuse(void)
{
	if (dynamic_ibpb & SPEC_CTRL_IBPB_INUSE)
		return 1;
	else
		/* rmb to prevent wrong speculation for security */
		rmb();
	return 0;
}

static inline void set_ibpb_supported(void)
{
	dynamic_ibpb |= SPEC_CTRL_IBPB_SUPPORTED;
	if (!ibpb_disabled)
		set_ibpb_inuse();
}

static inline void set_ibpb_disabled(void)
{
	dynamic_ibpb |= SPEC_CTRL_IBPB_ADMIN_DISABLED;
	if (check_ibpb_inuse())
		clear_ibpb_inuse();

	sysctl_ibpb_enabled = ibpb_inuse ? 1 : 0;
}

static inline void clear_ibpb_disabled(void)
{
	dynamic_ibpb &= ~SPEC_CTRL_IBPB_ADMIN_DISABLED;
	set_ibpb_inuse();

	sysctl_ibpb_enabled = ibpb_inuse ? 1 : 0;
}

void unprotected_firmware_begin(void);
void unprotected_firmware_end(void);

static inline void __disable_indirect_speculation(void)
{
	wrmsrl(MSR_IA32_SPEC_CTRL, SPEC_CTRL_FEATURE_ENABLE_IBRS);
}

static inline void __enable_indirect_speculation(void)
{
	wrmsrl(MSR_IA32_SPEC_CTRL, SPEC_CTRL_FEATURE_DISABLE_IBRS);
}

/*
 * Interrupts must be disabled to begin unprotected speculation.
 * Otherwise interrupts could come in and start running in unprotected mode.
 */
static inline void unprotected_speculation_begin(void)
{
	WARN_ONCE(!irqs_disabled(),
	    KERN_INFO "unprotected_speculation_begin() called with IRQs enabled!");

	if (dynamic_ibrs)
		__enable_indirect_speculation();
}

static inline void unprotected_speculation_end(void)
{
	if (dynamic_ibrs) {
		__disable_indirect_speculation();
	} else {
		/*
		 * rmb prevent unwanted speculation when we
		 * are setting IBRS
		 */
		rmb();
	}
}
#endif /* __ASSEMBLY */
#endif /* _ASM_X86_SPEC_CTRL_H */
