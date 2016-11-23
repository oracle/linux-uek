/*
 * FILE:        dtrace_sdt.c
 * DESCRIPTION: Dynamic Tracing: SDT registration code (arch-specific)
 *
 * Copyright (C) 2010-2014 Oracle Corporation
 */

#include <linux/kernel.h>
#include <linux/memory.h>
#include <linux/module.h>
#include <linux/dtrace_os.h>
#include <linux/sdt.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/cacheflush.h>
#include <asm/dtrace_arch.h>

void __init_or_module dtrace_sdt_nop_multi(asm_instr_t **addrs,
					   int * __always_unused is_enabled,
					   int cnt)
{
	int		i;
	asm_instr_t	*addr;

	for (i = 0; i < cnt; i++) {
		addr = addrs[i];
		*addr = 0x01000000;
		flushi(addr);
	}
}

/*
 * Perform architecture dependent initialization for SDT.  On sparc64, we need
 * not do anything.
 */
void dtrace_sdt_init_arch(void)
{
}
