/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_ARM64_NOSPEC_BRANCH_H_
#define _ASM_ARM64_NOSPEC_BRANCH_H_

#ifdef __ASSEMBLY__

.macro retpoline
	str	x30, [sp, #-16]!
	bl	101f
100: //speculation trap
	wfe
	b	100b
101: //do ROP
	adr	x30, 102f
	ret
102: //non-spec code
	ldr	x30, [sp], #16
.endm

.macro br_nospec reg
#ifdef CONFIG_RETPOLINE
	b	__aarch64_indirect_thunk_\reg
#else
	br	\reg
#endif
.endm

.macro blr_nospec reg
#ifdef CONFIG_RETPOLINE
	bl	__aarch64_indirect_thunk_\reg
#else
	blr	\reg
#endif
.endm

/*
 * In case of "blr lr" we need to inline the retpoline
 * as we cannot do a bl to the indirect_thunk, because
 * it would destroy the contents of our link register.
 */
.macro blr_nospec_lr
#ifdef CONFIG_RETPOLINE
	retpoline
#endif
	blr	lr
.endm

#else /* __ASSEMBLY__ */

extern char __indirect_thunk_start[];
extern char __indirect_thunk_end[];

#endif /* __ASSEMBLY__ */

#endif /* _ASM_ARM64_NOSPEC_BRANCH_H_ */
