/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _ASM_X86_NOSPEC_ANNOTATE_H_
#define _ASM_X86_NOSPEC_ANNOTATE_H_

#include <asm/asm.h>

#ifdef __ASSEMBLY__

/*
 * This should be used immediately before a retpoline alternative.  It tells
 * objtool where the retpolines are so that it can make sense of the control
 * flow by just reading the original instruction(s) and ignoring the
 * alternatives.
 */
#define ANNOTATE_NOSPEC_ALTERNATIVE \
	ANNOTATE_IGNORE_ALTERNATIVE

/*
 * This should be used immediately before an indirect jump/call. It tells
 * objtool the subsequent indirect jump/call is vouched safe for retpoline
 * builds.
 */
.macro ANNOTATE_RETPOLINE_SAFE
	.Lannotate_\@:
	.pushsection .discard.retpoline_safe
	_ASM_PTR .Lannotate_\@
	.popsection
.endm

#else /* __ASSEMBLY__ */

#define ANNOTATE_NOSPEC_ALTERNATIVE				\
	"999:\n\t"						\
	".pushsection .discard.nospec\n\t"			\
	".long 999b - .\n\t"					\
	".popsection\n\t"

#define ANNOTATE_RETPOLINE_SAFE					\
	"999:\n\t"						\
	".pushsection .discard.retpoline_safe\n\t"		\
	_ASM_PTR " 999b\n\t"					\
	".popsection\n\t"

#endif /* __ASSEMBLY__ */

#endif /* _ASM_X86_NOSPEC_ANNOTATE_H_ */
