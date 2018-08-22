/*
 * FILE:        dtrace_sdt.c
 * DESCRIPTION: Dynamic Tracing: SDT registration code (arch-specific)
 *
 * Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
 */

#include <linux/module.h>
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
