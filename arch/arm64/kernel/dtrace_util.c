/*
 * FILE:	dtrace_util.c
 * DESCRIPTION:	Dynamic Tracing: Architecture utility functions
 *
 * Copyright (c) 2010, 2017, Oracle and/or its affiliates. All rights reserved.
 */

#include <linux/dtrace_cpu.h>
#include <linux/dtrace_os.h>
#include <linux/notifier.h>
#include <linux/ptrace.h>
#include <linux/kdebug.h>

void dtrace_skip_instruction(struct pt_regs *regs)
{
	instruction_pointer_set(regs, instruction_pointer(regs) + 4);
}

void dtrace_handle_badaddr(struct pt_regs *regs)
{
	unsigned long	addr = current->thread.fault_address;

	DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
	this_cpu_core->cpuc_dtrace_illval = addr;

	dtrace_skip_instruction(regs);
}

int dtrace_die_notifier(struct notifier_block *nb, unsigned long val,
			void *args)
{
	struct die_args		*dargs = args;

	switch (val) {
	case DIE_PAGE_FAULT: {
		if (!DTRACE_CPUFLAG_ISSET(CPU_DTRACE_NOFAULT))
			return NOTIFY_DONE;

		DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
		this_cpu_core->cpuc_dtrace_illval = dargs->err;

		dtrace_skip_instruction(dargs->regs);

		return NOTIFY_OK | NOTIFY_STOP_MASK;
	}
	case DIE_OOPS: {
		pr_info("DTrace: last probe %u\n",
		       this_cpu_core->cpuc_current_probe);
		return NOTIFY_DONE;
	}
	default:
		return NOTIFY_DONE;
	}
}

int dtrace_user_addr_is_exec(uintptr_t addr)
{
	/*
	 * FIXME:
	 * Placeholder
	 */
	return 0;
}
EXPORT_SYMBOL(dtrace_user_addr_is_exec);

void dtrace_user_stacktrace(stacktrace_state_t *st)
{
	struct pt_regs		*regs = current_pt_regs();
	uint64_t		*pcs = st->pcs;
	int			limit = st->limit;

	if (!user_mode(regs))
		goto out;

	st->depth = 1;
	if (pcs)
		*pcs++ = (uint64_t)instruction_pointer(regs);
	limit--;

out:
	if (pcs) {
		while (limit--)
			*pcs++ = 0;
	}
}

void dtrace_mod_pdata_init(dtrace_module_t *pdata)
{
}

void dtrace_mod_pdata_cleanup(dtrace_module_t *pdata)
{
}
