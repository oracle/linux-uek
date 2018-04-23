/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_X86_SPEC_CTRL_H
#define _ASM_X86_SPEC_CTRL_H

#include <asm/msr-index.h>
#include <asm/cpufeature.h>

#define	SPEC_CTRL_IBRS_INUSE		(1<<0)  /* OS enables IBRS usage */

#ifndef	__ASSEMBLY__

void scan_spec_ctrl_feature(struct cpuinfo_x86 *c);
bool ibrs_inuse(void);
bool ibpb_inuse(void);
void set_ibrs_disabled(void);
void set_ibpb_disabled(void);

void unprotected_firmware_begin(void);
void unprotected_firmware_end(void);

extern unsigned int dynamic_ibrs;
extern u32 sysctl_ibrs_enabled;
extern unsigned int dynamic_ibpb;
extern u32 sysctl_ibpb_enabled;

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

#endif

#endif /* _ASM_X86_SPEC_CTRL_H */
