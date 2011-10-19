/******************************************************************************
 * acpi.h
 * acpi file for domain 0 kernel
 *
 * Copyright (c) 2011 Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>
 * Copyright (c) 2011 Yu Ke <ke.yu@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#ifndef _XEN_ACPI_H
#define _XEN_ACPI_H

#include <linux/types.h>
#include <acpi/acpi_drivers.h>
#include <acpi/processor.h>

/*
 * Following are interfaces for xen acpi processor control
 */
#if defined(CONFIG_ACPI_PROCESSOR_XEN) || \
defined(CONFIG_ACPI_PROCESSOR_XEN_MODULE)
/* Events notified to xen */
#define PROCESSOR_PM_INIT	1
#define PROCESSOR_PM_CHANGE	2
#define PROCESSOR_HOTPLUG	3

/* Objects for the PM events */
#define PM_TYPE_IDLE		0
#define PM_TYPE_PERF		1
#define PM_TYPE_THR		2
#define PM_TYPE_MAX		3

#define XEN_MAX_ACPI_ID 255

/* Processor hotplug events */
#define HOTPLUG_TYPE_ADD	0
#define HOTPLUG_TYPE_REMOVE	1

extern int (*__acpi_processor_register_driver)(void);
extern void (*__acpi_processor_unregister_driver)(void);
#endif

#ifndef CONFIG_CPU_FREQ
static inline int xen_acpi_processor_get_performance(struct acpi_processor *pr)
{
	printk(KERN_WARNING
		"Warning: xen_acpi_processor_get_performance not supported\n"
		"Consider compiling CPUfreq support into your kernel.\n");
	return 0;
}
#endif

#if defined(CONFIG_ACPI_PROCESSOR_XEN) || \
defined(CONFIG_ACPI_PROCESSOR_XEN_MODULE)

struct processor_cntl_xen_ops {
	/* Transfer processor PM events to xen */
int (*pm_ops[PM_TYPE_MAX])(struct acpi_processor *pr, int event);
	/* Notify physical processor status to xen */
	int (*hotplug)(struct acpi_processor *pr, int type);
};

extern int processor_cntl_xen_notify(struct acpi_processor *pr,
			int event, int type);
extern int processor_cntl_xen_power_cache(int cpu, int cx,
		struct acpi_power_register *reg);
#else

static inline int processor_cntl_xen_notify(struct acpi_processor *pr,
			int event, int type)
{
	return 0;
}
static inline int processor_cntl_xen_power_cache(int cpu, int cx,
		struct acpi_power_register *reg)
{
	return 0;
}
#endif /* CONFIG_ACPI_PROCESSOR_XEN */

#endif	/* _XEN_ACPI_H */
