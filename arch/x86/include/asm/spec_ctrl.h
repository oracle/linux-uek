/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_X86_SPEC_CTRL_H
#define _ASM_X86_SPEC_CTRL_H

#include <asm/msr-index.h>
#include <asm/cpufeature.h>
#include <asm/microcode.h>

void scan_spec_ctrl_feature(struct cpuinfo_x86 *c);
bool ibrs_inuse(void);
bool ibpb_inuse(void);

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
#endif /* _ASM_X86_SPEC_CTRL_H */
