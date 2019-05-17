// SPDX-License-Identifier: GPL-2.0
/* Marvell GTI Watchdog driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/kernel.h>
#include <linux/arm-smccc.h>
#include <linux/cpu.h>
#include <linux/nmi.h>
#include <linux/module.h>
#include <linux/irq.h>
#include <linux/sched/debug.h>

#include "gti.h"

#define GTI_CWD_WDOG_POKE(a) (0x50000ll + 8ll * ((a) & 0x3f))

/* Kernel exception simulation wrapper for the NMI callback */
void nmi_kernel_callback_other_cpus(void *unused)
{
	struct pt_regs *regs = get_irq_regs();

	pr_emerg("Watchdog CPU:%d\n", raw_smp_processor_id());

	if (regs)
		show_regs(regs);
	else
		dump_stack();
}

void nmi_kernel_callback(struct pt_regs *regs)
{
	int c;

	pr_emerg("Watchdog CPU:%d Hard LOCKUP\n", raw_smp_processor_id());

	if (regs)
		show_regs(regs);
	else
		dump_stack();

	for_each_online_cpu(c) {
		if (c == raw_smp_processor_id())
			continue;
		/*
		 * We are making a synchronous call to other cores and
		 * waiting for those cores to dump their state/context,
		 * if one of the cores is hanged or unable to respond
		 * to interrupts, we can wait here forever, currently
		 * depending on our NMI timer to trigger a system-wide
		 * warm reset to break out of such deadlocks.
		 */
		smp_call_function_single(c,
			 nmi_kernel_callback_other_cpus, NULL, 1);
	}

	/*
	 * FIXME: Add a new SMC interface to clear a per-core watchdog.
	 * Also, importantly add support for recovery here and return to the
	 * interrupted state via el3.
	 */
	for (;;) {
		/* Poke the Watchdog */
		if (g_gti_devmem) {
			writeq(0, g_gti_devmem +
				GTI_CWD_WDOG_POKE(raw_smp_processor_id()));
		}
	}
}
