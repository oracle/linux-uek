/*
 * FILE:        dtrace_fbt.c
 * DESCRIPTION: Dynamic Tracing: FBT registration code (arch-specific)
 *
 * Copyright (c) 2010, 2018, Oracle and/or its affiliates. All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/dtrace_os.h>
#include <linux/dtrace_fbt.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <asm/insn.h>
#include <asm/sections.h>

#define FBT_REG_FP	0x1d		/* fp is regiater 29 */
#define FBT_REG_LR	0x1e		/* lr is regiater 30 */
#define FBT_REG_SP	0x1f		/* sp is register 31 */
#define FBT_MOV_FP_SP	0x910003fd	/* "mov x29, sp" */

#define BL_SENTRY(tp, nm)	extern tp nm;
#define BL_DENTRY(tp, nm)
#include "fbt_blacklist.h"
#undef BL_DENTRY
#undef BL_SENTRY

static void
dtrace_fbt_populate_bl(void)
{
#define	BL_SENTRY(tp, nm)	dtrace_fbt_bl_add((unsigned long)&nm, __stringify(nm));
#define BL_DENTRY(tp, nm)	dtrace_fbt_bl_add(0, __stringify(nm));
#include "fbt_blacklist.h"
#undef BL_SENTRY
#undef BL_DENTRY
}

void dtrace_fbt_init(fbt_add_probe_fn fbt_add_probe, struct module *mp,
		     void *arg)
{
	loff_t			pos;
	struct kallsym_iter	sym;
	asm_instr_t		*paddr = NULL;
	dt_fbt_bl_entry_t	*blent = NULL;

	/*
	 * Look up any unresolved symbols in the blacklist, and sort the list
	 * by ascending address.
	 */
	dtrace_fbt_populate_bl();

	blent = dtrace_fbt_bl_first();

	pos = 0;
	kallsyms_iter_reset(&sym, 0);
	while (kallsyms_iter_update(&sym, pos++)) {
		asm_instr_t	*addr, *end;
		asm_instr_t	instr;

		/*
		 * There is no point considering non-function symbols for FBT,
		 * or symbols that have a zero size.  We could consider weak
		 * symbols but that gets quite complicated and there is no
		 * demands for that (so far).
		 */
		if (sym.type != 'T' && sym.type != 't')
			continue;
		if (!sym.size)
			continue;

		/*
		 * The symbol must be at a properly aligned text address.
		 */
		if (!IS_ALIGNED(sym.value, sizeof(asm_instr_t)))
			continue;

		/*
		 * Handle only symbols that belong to the module we have been
		 * asked for.
		 */
		if (mp == dtrace_kmod && !core_kernel_text(sym.value))
			continue;

		/*
		 * Ensure we have not been given .init symbol from kallsyms
		 * interface. This could lead to memory corruption once DTrace
		 * tries to enable probe in already freed memory.
		 */
		if (mp != dtrace_kmod && !within_module_core(sym.value, mp))
			continue;

		/*
		 * See if the symbol is on the FBT's blacklist.  Since both
		 * iterators are workng in sort order by ascending address we
		 * can use concurrent traversal.
		 */
		while (blent != NULL &&
		       dtrace_fbt_bl_entry_addr(blent) < sym.value) {
			blent = dtrace_fbt_bl_next(blent);
		}
		if (dtrace_fbt_bl_entry_addr(blent) == sym.value)
			continue;

		/*
		 * No FBT tracing for DTrace functions, and functions that are
		 * crucial to probe processing.
		 * Also weed out symbols that are not relevant here.
		 */
		if (strncmp(sym.name, "dtrace_", 7) == 0)
			continue;
		if (strncmp(sym.name, "insn_", 5) == 0)
			continue;
		if (strncmp(sym.name, "inat_", 5) == 0)
			continue;
		if (strncmp(sym.name, "_GLOBAL_", 8) == 0)
			continue;
		if (strncmp(sym.name, "do_", 3) == 0)
			continue;
		if (strncmp(sym.name, "xen_", 4) == 0)
			continue;

		addr = (asm_instr_t *)sym.value;
		end = (asm_instr_t *)(sym.value + sym.size);

		/*
		 * FIXME:
		 * When there are multiple symbols for the same address, we
		 * should link them together as probes associated with the
		 * same function.  When a probe for that function is triggered
		 * all associated probes should fire.
		 *
		 * For now, we ignore duplicates.
		 */
		if (addr == paddr)
			continue;
		paddr = addr;

		instr = le32_to_cpu(*addr);

		/*
		 * We can only instrument functions that begin with a proper
		 * frame set-up sequence:
		 *	stp     x29, x30, [sp,#-80]!
		 *	mov     x29, sp
		 * So, a STP instruction storing the FP (x29) and LR (x30)
		 * registers as a pair in a location relative to the SP
		 * register value.  And then a MOV instruction that sets the
		 * FP (x29) register to the current SP value (effectively
		 * establishing the new stack frame).
		 *
		 * We will place our breakpoint on the MOV instruction.
		 */
		if (!aarch64_insn_is_stp_pre(instr) ||
		    aarch64_insn_decode_register(
			    AARCH64_INSN_REGTYPE_RN, instr) != FBT_REG_SP ||
		    aarch64_insn_decode_register(
			    AARCH64_INSN_REGTYPE_RT, instr) != FBT_REG_FP ||
		    aarch64_insn_decode_register(
			    AARCH64_INSN_REGTYPE_RT2, instr) != FBT_REG_LR)
			continue;

		addr++;
		instr = le32_to_cpu(*addr);

		if (instr == FBT_MOV_FP_SP) {
			fbt_add_probe(mp, sym.name, FBT_ENTRY, instr, addr, 0,
				      NULL, arg);
		}
	}
}
EXPORT_SYMBOL(dtrace_fbt_init);
