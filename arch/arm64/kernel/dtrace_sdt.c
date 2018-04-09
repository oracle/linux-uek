/*
 * FILE:        dtrace_sdt.c
 * DESCRIPTION: Dynamic Tracing: SDT registration code (arch-specific)
 *
 * Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
 */

#include <linux/module.h>
#include <asm/cacheflush.h>
#include <asm/dtrace_arch.h>
#include <asm/dtrace_sdt_arch.h>

void __init_or_module dtrace_sdt_nop_multi(asm_instr_t **addrs,
					   int * __always_unused is_enabled,
					   int cnt)
{
	int		i;
	asm_instr_t	*addr;

	for (i = 0; i < cnt; i++) {
		addr = addrs[i];
		*addr = NOP_INSTR;
		flush_icache_range((uintptr_t)addr, (uintptr_t)(addr + 1));
	}
}
