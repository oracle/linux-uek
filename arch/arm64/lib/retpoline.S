/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/stringify.h>
#include <linux/linkage.h>
#include <asm/assembler.h>
#include <asm/nospec-branch.h>
#include <asm-generic/export.h>

.macro THUNK reg
	.section .text.__aarch64.indirect_thunk

ENTRY(__aarch64_indirect_thunk_\reg)
	retpoline
	br	\reg
ENDPROC(__aarch64_indirect_thunk_\reg)
.endm

#define _ASM_NOKPROBE(entry)					\
	.pushsection "_kprobe_blacklist","aw" ;			\
	.quad entry;						\
	.popsection

#define __EXPORT_THUNK(sym) _ASM_NOKPROBE(sym); EXPORT_SYMBOL(sym)
#define EXPORT_THUNK(reg) __EXPORT_THUNK(__aarch64_indirect_thunk_ ## reg)
#define GENERATE_THUNK(reg) THUNK reg ; EXPORT_THUNK(reg)

GENERATE_THUNK(x0)
GENERATE_THUNK(x1)
GENERATE_THUNK(x2)
GENERATE_THUNK(x3)
GENERATE_THUNK(x4)
GENERATE_THUNK(x5)
GENERATE_THUNK(x6)
GENERATE_THUNK(x7)
GENERATE_THUNK(x8)
GENERATE_THUNK(x9)
GENERATE_THUNK(x10)
GENERATE_THUNK(x11)
GENERATE_THUNK(x12)
GENERATE_THUNK(x13)
GENERATE_THUNK(x14)
GENERATE_THUNK(x15)
GENERATE_THUNK(x16)
GENERATE_THUNK(x17)
GENERATE_THUNK(x18)
GENERATE_THUNK(x19)
GENERATE_THUNK(x20)
GENERATE_THUNK(x21)
GENERATE_THUNK(x22)
GENERATE_THUNK(x23)
GENERATE_THUNK(x24)
GENERATE_THUNK(x25)
GENERATE_THUNK(x26)
GENERATE_THUNK(x27)
GENERATE_THUNK(x28)
GENERATE_THUNK(x29)
GENERATE_THUNK(x30)
