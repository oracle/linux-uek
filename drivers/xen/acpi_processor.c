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

#include <xen/interface/platform.h>
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

static inline void xen_convert_pct_reg(struct xen_pct_register *xpct,
	struct acpi_pct_register *apct)
{
	xpct->descriptor = apct->descriptor;
	xpct->length     = apct->length;
	xpct->space_id   = apct->space_id;
	xpct->bit_width  = apct->bit_width;
	xpct->bit_offset = apct->bit_offset;
	xpct->reserved   = apct->reserved;
	xpct->address    = apct->address;
}

static inline void xen_convert_pss_states(struct xen_processor_px *xpss,
	struct acpi_processor_px *apss, int state_count)
{
	int i;
	for (i = 0; i < state_count; i++) {
		xpss->core_frequency     = apss->core_frequency;
		xpss->power              = apss->power;
		xpss->transition_latency = apss->transition_latency;
		xpss->bus_master_latency = apss->bus_master_latency;
		xpss->control            = apss->control;
		xpss->status             = apss->status;
		xpss++;
		apss++;
	}
}

static inline void xen_convert_psd_pack(struct xen_psd_package *xpsd,
	struct acpi_psd_package *apsd)
{
	xpsd->num_entries    = apsd->num_entries;
	xpsd->revision       = apsd->revision;
	xpsd->domain         = apsd->domain;
	xpsd->coord_type     = apsd->coord_type;
	xpsd->num_processors = apsd->num_processors;
}

static int xen_cx_notifier(struct acpi_processor *pr, int action)
{
	int ret, count = 0, i;
	struct xen_platform_op op = {
		.cmd			= XENPF_set_processor_pminfo,
		.interface_version	= XENPF_INTERFACE_VERSION,
		.u.set_pminfo.id	= pr->acpi_id,
		.u.set_pminfo.type	= XEN_PM_CX,
	};
	struct xen_processor_cx *data, *buf;
	struct acpi_processor_cx *cx;
	struct acpi_power_register *reg;

	if (action == PROCESSOR_PM_CHANGE)
		return -EINVAL;

	/* Convert to Xen defined structure and hypercall */
	buf = kzalloc(pr->power.count * sizeof(struct xen_processor_cx)\
		, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	data = buf;
	for (i = 1; i <= pr->power.count; i++) {
		cx = &pr->power.states[i];
		reg = &cx->reg;
		/* Skip invalid cstate entry */
		if (!cx->valid)
			continue;

		data->type = cx->type;
		data->latency = cx->latency;
		data->power = cx->power;
		data->reg.space_id = reg->space_id;
		data->reg.bit_width = reg->bit_width;
		data->reg.bit_offset = reg->bit_offset;
		data->reg.access_size = reg->access_size;
		data->reg.address = reg->address;

		/* Get dependency relationships, _CSD is not supported yet */
		data->dpcnt = 0;
		set_xen_guest_handle(data->dp, NULL);

		data++;
		count++;
	}

	if (!count) {
		printk(KERN_ERR "No available Cx info for cpu %d\n",
				pr->acpi_id);
		kfree(buf);
		return -EINVAL;
	}

	op.u.set_pminfo.power.count = count;
	op.u.set_pminfo.power.flags.bm_control = pr->flags.bm_control;
	op.u.set_pminfo.power.flags.bm_check = pr->flags.bm_check;
	op.u.set_pminfo.power.flags.has_cst = pr->flags.has_cst;
	op.u.set_pminfo.power.flags.power_setup_done =
		pr->flags.power_setup_done;

	set_xen_guest_handle(op.u.set_pminfo.power.states, buf);
	ret = HYPERVISOR_dom0_op(&op);
	kfree(buf);
	return ret;
}

static int xen_px_notifier(struct acpi_processor *pr, int action)
{
	int ret = -EINVAL;
	struct xen_platform_op op = {
		.cmd			= XENPF_set_processor_pminfo,
		.interface_version	= XENPF_INTERFACE_VERSION,
		.u.set_pminfo.id	= pr->acpi_id,
		.u.set_pminfo.type	= XEN_PM_PX,
	};
	struct xen_processor_performance *perf;
	struct xen_processor_px *states = NULL;
	struct acpi_processor_performance *px;
	struct acpi_psd_package *pdomain;

	if (!pr)
		return -EINVAL;

	perf = &op.u.set_pminfo.perf;
	px = pr->performance;

	switch (action) {
	case PROCESSOR_PM_CHANGE:
		/* ppc dynamic handle */
		perf->flags = XEN_PX_PPC;
		perf->platform_limit = pr->performance_platform_limit;

		ret = HYPERVISOR_dom0_op(&op);
		break;

	case PROCESSOR_PM_INIT:
		/* px normal init */
		perf->flags = XEN_PX_PPC |
			      XEN_PX_PCT |
			      XEN_PX_PSS |
			      XEN_PX_PSD;

		/* ppc */
		perf->platform_limit = pr->performance_platform_limit;

		/* pct */
		xen_convert_pct_reg(&perf->control_register,
				&px->control_register);
		xen_convert_pct_reg(&perf->status_register,
				&px->status_register);

		/* pss */
		perf->state_count = px->state_count;
		states = kzalloc(px->state_count*\
			sizeof(struct xen_processor_px), GFP_KERNEL);
		if (!states)
			return -ENOMEM;
		xen_convert_pss_states(states, px->states, px->state_count);
		set_xen_guest_handle(perf->states, states);

		/* psd */
		pdomain = &px->domain_info;
		/* Some sanity check */
		if ((pdomain->revision != ACPI_PSD_REV0_REVISION) ||
			(pdomain->num_entries != ACPI_PSD_REV0_ENTRIES) ||
			((pdomain->coord_type != DOMAIN_COORD_TYPE_SW_ALL) &&
			(pdomain->coord_type != DOMAIN_COORD_TYPE_SW_ANY) &&
			(pdomain->coord_type != DOMAIN_COORD_TYPE_HW_ALL))) {
			ret = -EINVAL;
			kfree(states);
			break;
		}

		xen_convert_psd_pack(&perf->domain_info, pdomain);
		if (pdomain->coord_type == DOMAIN_COORD_TYPE_SW_ALL)
			perf->shared_type = CPUFREQ_SHARED_TYPE_ALL;
		else if (pdomain->coord_type == DOMAIN_COORD_TYPE_SW_ANY)
			perf->shared_type = CPUFREQ_SHARED_TYPE_ANY;
		else if (pdomain->coord_type == DOMAIN_COORD_TYPE_HW_ALL)
			perf->shared_type = CPUFREQ_SHARED_TYPE_HW;
		else {
			ret = -EINVAL;
			kfree(states);
			break;
		}

		ret = HYPERVISOR_dom0_op(&op);
		kfree(states);
		break;

	default:
		break;
	}

	return ret;
}

static int __init xen_acpi_processor_extcntl_init(void)
{
	unsigned int pmbits;

	/* Only xen dom0 is allowed to handle ACPI processor info */
	if (!xen_initial_domain())
		return 0;

	pmbits = (xen_start_info->flags & SIF_PM_MASK) >> 8;

	if (pmbits & XEN_PROCESSOR_PM_CX)
		xen_ops.pm_ops[PM_TYPE_IDLE] = xen_cx_notifier;
	if (pmbits & XEN_PROCESSOR_PM_PX)
		xen_ops.pm_ops[PM_TYPE_PERF] = xen_px_notifier;

	return 0;
}

subsys_initcall(xen_acpi_processor_extcntl_init);
MODULE_LICENSE("GPL");
