/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_JUMP_LABEL_H
#define _ASM_X86_JUMP_LABEL_H

#define HAVE_JUMP_LABEL_BATCH

#include <asm/asm.h>
#include <asm/nops.h>

#ifndef __ASSEMBLY__

#include <linux/stringify.h>
#include <linux/types.h>

#define JUMP_TABLE_ENTRY				\
	".pushsection __jump_table,  \"aw\" \n\t"	\
	_ASM_ALIGN "\n\t"				\
	".long 1b - . \n\t"				\
	".long %l[l_yes] - . \n\t"			\
	_ASM_PTR "%c0 + %c1 - .\n\t"			\
	".popsection \n\t"

#ifdef CONFIG_STACK_VALIDATION

static __always_inline bool arch_static_branch(struct static_key *key, bool branch)
{
	asm_volatile_goto("1:"
		"jmp %l[l_yes] # objtool NOPs this \n\t"
		JUMP_TABLE_ENTRY
		: :  "i" (key), "i" (2 | branch) : : l_yes);

	return false;
l_yes:
	return true;
}

#else

static __always_inline bool arch_static_branch(struct static_key * const key, const bool branch)
{
	asm_volatile_goto("1:"
		".byte " __stringify(BYTES_NOP5) "\n\t"
		JUMP_TABLE_ENTRY
		: :  "i" (key), "i" (branch) : : l_yes);

	return false;
l_yes:
	return true;
}

#endif /* STACK_VALIDATION */

static __always_inline bool arch_static_branch_jump(struct static_key * const key, const bool branch)
{
	asm_volatile_goto("1:"
		"jmp %l[l_yes]\n\t"
		JUMP_TABLE_ENTRY
		: :  "i" (key), "i" (branch) : : l_yes);

	return false;
l_yes:
	return true;
}

extern int arch_jump_entry_size(struct jump_entry *entry);

#else	/* __ASSEMBLY__ */

.macro STATIC_JUMP_IF_TRUE target, key, def
.Lstatic_jump_\@:
	.if \def
	/* Equivalent to "jmp.d32 \target" */
	.byte		0xe9
	.long		\target - .Lstatic_jump_after_\@
.Lstatic_jump_after_\@:
	.else
	.byte		BYTES_NOP5
	.endif
	.pushsection __jump_table, "aw"
	_ASM_ALIGN
	.long		.Lstatic_jump_\@ - ., \target - .
	_ASM_PTR	\key - .
	.popsection
.endm

.macro STATIC_JUMP_IF_FALSE target, key, def
.Lstatic_jump_\@:
	.if \def
	.byte		BYTES_NOP5
	.else
	/* Equivalent to "jmp.d32 \target" */
	.byte		0xe9
	.long		\target - .Lstatic_jump_after_\@
.Lstatic_jump_after_\@:
	.endif
	.pushsection __jump_table, "aw"
	_ASM_ALIGN
	.long		.Lstatic_jump_\@ - ., \target - .
	_ASM_PTR	\key + 1 - .
	.popsection
.endm

#endif	/* __ASSEMBLY__ */

#endif
