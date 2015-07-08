/*
 * FILE:	dtrace_util.c
 * DESCRIPTION:	Dynamic Tracing: Architecture utility functions
 *
 * Copyright (C) 2010-2014 Oracle Corporation
 */

#include <linux/dtrace_cpu.h>
#include <linux/kdebug.h>
#include <linux/notifier.h>
#include <linux/slab.h>
#include <asm/ptrace.h>

void dtrace_skip_instruction(struct pt_regs *regs)
{
	regs->tpc = regs->tnpc;
	regs->tnpc += 4;
}

void dtrace_handle_badaddr(struct pt_regs *regs) {
	unsigned long	addr = current_thread_info()->fault_address;

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

		dtrace_handle_badaddr(dargs->regs);

		return NOTIFY_OK | NOTIFY_STOP_MASK;
	}
	case DIE_GPF: {
		if (!DTRACE_CPUFLAG_ISSET(CPU_DTRACE_NOFAULT))
			return NOTIFY_DONE;

		DTRACE_CPUFLAG_SET(CPU_DTRACE_ILLOP);

		dtrace_skip_instruction(dargs->regs);

		return NOTIFY_OK | NOTIFY_STOP_MASK;
	}
	case DIE_TRAP: {
		if (dargs->trapnr != 0x34)
			return NOTIFY_DONE;

		if (!DTRACE_CPUFLAG_ISSET(CPU_DTRACE_NOFAULT))
			return NOTIFY_DONE;

		dtrace_handle_badaddr(dargs->regs);

		return NOTIFY_OK | NOTIFY_STOP_MASK;
	}
	default:
		return NOTIFY_DONE;
	}
}
