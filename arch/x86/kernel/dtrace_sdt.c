/*
 * FILE:        dtrace_sdt.c
 * DESCRIPTION: Dynamic Tracing: SDT registration code (arch-specific)
 *
 * Copyright (C) 2010-2016 Oracle Corporation
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
#include <asm/dtrace_arch.h>
#include <asm/text-patching.h>

static uint8_t nops[ASM_CALL_SIZE];
static uint8_t movs[ASM_CALL_SIZE];

#define DT_OP_REX_RAX           0x48
#define DT_OP_XOR_EAX_0         0x33
#define DT_OP_XOR_EAX_1         0xc0

/* This code is based on apply_alternatives and text_poke_early.  It needs to
 * run before SMP is initialized in order to avoid SMP problems with patching
 * code that might be accessed on another CPU.
 */
void __init_or_module dtrace_sdt_nop_multi(asm_instr_t **addrs,
					   int *is_enabled, int cnt)
{
	int			i;
	asm_instr_t		*addr;
	unsigned long		flags;

	stop_nmi();
	local_irq_save(flags);

	for (i = 0; i < cnt; i++) {
		addr = addrs[i];
		if (likely(!is_enabled[i]))
			memcpy(addr, nops, sizeof(nops));
		else
			memcpy(addr, movs, sizeof(movs));
	}

	sync_core();
	local_irq_restore(flags);
	restart_nmi();
}

void dtrace_sdt_init_arch(void)
{
	/*
	 * A little unusual, but potentially necessary.  While we could use a
	 * single NOP sequence of length ASM_CALL_SIZE, we need to consider the
	 * fact that when a SDT probe point is enabled, a single invalid opcode
	 * is written on the first byte of this NOP sequence.  By using a
	 * sequence of a 1-byte NOP, followed by a (ASM_CALL_SIZE - 1) byte NOP
	 * sequence, we play it pretty safe.
	 */
	add_nops(nops, 1);
	add_nops(nops + 1, ASM_CALL_SIZE - 1);

	/*
	 * Is-enabled probe points contain an "xor %rax, %rax" when disabled.
	 */
	movs[0] = DT_OP_REX_RAX;
	movs[1] = DT_OP_XOR_EAX_0;
	movs[2] = DT_OP_XOR_EAX_1;
	add_nops(movs + 3, ASM_CALL_SIZE - 3);
}
