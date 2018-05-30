/*
 * FILE:        dtrace_sdt.c
 * DESCRIPTION: Dynamic Tracing: SDT registration code (arch-specific)
 *
 * Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
 */

#include <linux/module.h>
#include <asm/debug-monitors.h>
#include <asm/insn.h>
#include <asm/dtrace_arch.h>
#include <asm/dtrace_sdt_arch.h>

void __init_or_module dtrace_sdt_nop_multi(asm_instr_t **addrs,
					   int *is_enabled, int cnt)
{
	int		i;

	for (i = 0; i < cnt; i++) {
		if (likely(!is_enabled[i]))
			aarch64_insn_patch_text_nosync(addrs[i], NOP_INSTR);
		else
			aarch64_insn_patch_text_nosync(addrs[i], MOV_INSTR);
	}
}

asm_instr_t dtrace_sdt_peek(asm_instr_t *addr)
{
	asm_instr_t	opcode;

	aarch64_insn_read(addr, &opcode);

	return opcode;
}
EXPORT_SYMBOL(dtrace_sdt_peek);

void dtrace_sdt_poke(asm_instr_t *addr, asm_instr_t opcode)
{
	aarch64_insn_patch_text_nosync(addr, opcode);
}
EXPORT_SYMBOL(dtrace_sdt_poke);

void dtrace_sdt_start(void *arg)
{
	register_break_hook((struct break_hook *)arg);
}
EXPORT_SYMBOL(dtrace_sdt_start);

void dtrace_sdt_stop(void *arg)
{
	unregister_break_hook((struct break_hook *)arg);
}
EXPORT_SYMBOL(dtrace_sdt_stop);
