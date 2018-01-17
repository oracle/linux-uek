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

#endif /* _ASM_X86_SPEC_CTRL_H */
