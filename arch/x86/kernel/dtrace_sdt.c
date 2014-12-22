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
#include <asm/nmi.h>
#include <asm/nops.h>
#include <asm/dtrace_sdt.h>

#define	SDT_NOP_SIZE	5

uint8_t			nops[SDT_NOP_SIZE];

/* This code is based on apply_alternatives and text_poke_early.  It needs to
 * run before SMP is initialized in order to avoid SMP problems with patching
 * code that might be accessed on another CPU.
 */
void __init_or_module dtrace_sdt_nop_multi(sdt_instr_t **addrs, int cnt)
{
	int			i;
	sdt_instr_t		*addr;
	unsigned long		flags;

	stop_nmi();
	local_irq_save(flags);

	for (i = 0; i < cnt; i++) {
		addr = addrs[i];
		memcpy(addr, nops, sizeof(nops));
	}

	sync_core();
	local_irq_restore(flags);
	restart_nmi();
}

void dtrace_sdt_init_arch(void)
{
	/*
	 * A little unusual, but potentially necessary.  While we could use a
	 * single NOP sequence of length SDT_NOP_SIZE, we need to consider the
	 * fact that when a SDT probe point is enabled, a single invalid opcode
	 * is written on the first byte of this NOP sequence.  By using a
	 * sequence of a 1-byte NOP, followed by a (SDT_NOP_SIZE - 1) byte NOP
	 * sequence, we play it pretty safe.
	 */
	add_nops(nops, 1);
	add_nops(nops + 1, SDT_NOP_SIZE - 1);
}
