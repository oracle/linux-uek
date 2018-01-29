/*
 * FILE:        dtrace_fbt.c
 * DESCRIPTION: Dynamic Tracing: FBT registration code (arch-specific)
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
 */

#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/dtrace_os.h>
#include <linux/dtrace_fbt.h>
#include <linux/sort.h>
#include <asm/insn.h>
#include <asm/sections.h>

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
		 * The symbol must be at a properly aligned address.
		 */
		if (!IS_ALIGNED(sym.value, 4))
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
		if (strncmp(sym.name, "_GLOBAL_", 8) == 0)
			continue;
		if (strncmp(sym.name, "do_", 3) == 0)
			continue;

		addr = (asm_instr_t *)sym.value;
		end = (asm_instr_t *)(sym.value + sym.size);

		/*
		 * FIXME:
		 * Add code here to determine which functions we can put FBT
		 * probes on.
		 */
	}
}
EXPORT_SYMBOL(dtrace_fbt_init);
