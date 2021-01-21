/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_FRAME_H
#define _LINUX_FRAME_H

#ifdef CONFIG_STACK_VALIDATION

#ifndef __ASSEMBLY__
/*
 * This macro marks the given function's stack frame as "non-standard", which
 * tells objtool to ignore the function when doing stack metadata validation.
 * It should only be used in special cases where you're 100% sure it won't
 * affect the reliability of frame pointers and kernel stack traces.
 *
 * For more information, see tools/objtool/Documentation/stack-validation.txt.
 */
#define STACK_FRAME_NON_STANDARD(func) \
	static void __used __section(.discard.func_stack_frame_non_standard) \
		*__func_stack_frame_non_standard_##func = func

#else /* __ASSEMBLY__ */

/*
 * This macro indicates that the following intra-function call is valid.
 * Any non-annotated intra-function call will cause objtool to issue a warning.
 */
#define ANNOTATE_INTRA_FUNCTION_CALL				\
	999:							\
	.pushsection .discard.intra_function_calls;		\
	.long 999b;						\
	.popsection;

.macro STACK_FRAME_NON_STANDARD func:req
	.pushsection .discard.func_stack_frame_non_standard, "aw"
		.long \func - .
	.popsection
.endm

#endif /* __ASSEMBLY__ */

#else /* !CONFIG_STACK_VALIDATION */

#ifndef __ASSEMBLY__

#define STACK_FRAME_NON_STANDARD(func)
#else
#define ANNOTATE_INTRA_FUNCTION_CALL
.macro STACK_FRAME_NON_STANDARD func:req
.endm
#endif

#endif /* CONFIG_STACK_VALIDATION */

#endif /* _LINUX_FRAME_H */
