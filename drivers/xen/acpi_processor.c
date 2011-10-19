/*
 *  acpi_processor.c - interface to notify Xen on acpi processor object
 *                     info parsing
 *
 *  Copyright (C) 2008, Intel corporation
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or (at
 *  your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful, but
 *  WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  General Public License for more details.
 *
 */

#include <linux/acpi.h>
#include <linux/cpufreq.h>
#include <acpi/processor.h>
#include <xen/acpi.h>

#include <asm/xen/hypercall.h>
#include <asm/xen/hypervisor.h>

static struct processor_cntl_xen_ops xen_ops;
int processor_cntl_xen_notify(struct acpi_processor *pr, int event, int type)
{
	int ret = -EINVAL;

	switch (event) {
	case PROCESSOR_PM_INIT:
	case PROCESSOR_PM_CHANGE:
		if ((type >= PM_TYPE_MAX) ||
			!xen_ops.pm_ops[type])
			break;

		ret = xen_ops.pm_ops[type](pr, event);
		break;
	default:
		printk(KERN_ERR "Unsupport processor events %d.\n", event);
		break;
	}

	return ret;
}
EXPORT_SYMBOL(processor_cntl_xen_notify);

MODULE_LICENSE("GPL");
