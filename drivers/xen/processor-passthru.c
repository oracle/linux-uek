/*
 * Copyright 2012 by Oracle Inc
 * Author: Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>
 *
 * This code borrows ideas from https://lkml.org/lkml/2011/11/30/249
 * so many thanks go to Kevin Tian <kevin.tian@intel.com>
 * and Yu Ke <ke.yu@intel.com>.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 */

#include <linux/cpumask.h>
#include <linux/cpufreq.h>
#include <linux/freezer.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <acpi/acpi_bus.h>
#include <acpi/acpi_drivers.h>
#include <acpi/processor.h>

#include <xen/interface/platform.h>
#include <asm/xen/hypercall.h>

#define DRV_NAME "xen-processor-thru"
MODULE_AUTHOR("Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>");
MODULE_DESCRIPTION("ACPI Power Management driver to pass Cx and Pxx data to Xen hypervisor");
MODULE_LICENSE("GPL");


static int no_hypercall;
MODULE_PARM_DESC(off, "Inhibit the hypercall.");
module_param_named(off, no_hypercall, int, 0400);

/*
 * Mutex to protect the acpi_ids_done.
 */
static DEFINE_MUTEX(acpi_ids_mutex);
/*
 * Don't think convert this to cpumask_var_t or use cpumask_bit - as those
 * shrink to nr_cpu_bits (which is dependent on possible_cpu), which can be
 * less than what we want to put in.
 */
#define NR_ACPI_CPUS	NR_CPUS
#define MAX_ACPI_BITS	(BITS_TO_LONGS(NR_ACPI_CPUS))
static unsigned long *acpi_ids_done;
/*
 * Again, don't convert to cpumask - as we are reading the raw ACPI CPU ids
 * which can go beyond what we presently see.
 */
static unsigned long *acpi_id_present;


#define POLL_TIMER	msecs_to_jiffies(5000 /* 5 sec */)
static struct task_struct *xen_processor_thread;

static int xen_push_cxx_to_hypervisor(struct acpi_processor *_pr)
{
	struct xen_platform_op op = {
		.cmd			= XENPF_set_processor_pminfo,
		.interface_version	= XENPF_INTERFACE_VERSION,
		.u.set_pminfo.id	= _pr->acpi_id,
		.u.set_pminfo.type	= XEN_PM_CX,
	};
	struct xen_processor_cx *xen_cx, *xen_cx_states = NULL;
	struct acpi_processor_cx *cx;
	int i, ok, ret = 0;

	xen_cx_states = kcalloc(_pr->power.count,
				sizeof(struct xen_processor_cx), GFP_KERNEL);
	if (!xen_cx_states)
		return -ENOMEM;

	for (ok = 0, i = 1; i <= _pr->power.count; i++) {
		cx = &_pr->power.states[i];
		if (!cx->valid)
			continue;

		xen_cx = &(xen_cx_states[ok++]);

		xen_cx->reg.space_id = ACPI_ADR_SPACE_SYSTEM_IO;
		if (cx->entry_method == ACPI_CSTATE_SYSTEMIO) {
			xen_cx->reg.bit_width = 8;
			xen_cx->reg.bit_offset = 0;
			xen_cx->reg.access_size = 1;
		} else {
			xen_cx->reg.space_id = ACPI_ADR_SPACE_FIXED_HARDWARE;
			if (cx->entry_method == ACPI_CSTATE_FFH) {
				/* NATIVE_CSTATE_BEYOND_HALT */
				xen_cx->reg.bit_offset = 2;
				xen_cx->reg.bit_width = 1; /* VENDOR_INTEL */
			}
			xen_cx->reg.access_size = 0;
		}
		xen_cx->reg.address = cx->address;

		xen_cx->type = cx->type;
		xen_cx->latency = cx->latency;
		xen_cx->power = cx->power;

		xen_cx->dpcnt = 0;
		set_xen_guest_handle(xen_cx->dp, NULL);
#ifdef DEBUG
		pr_debug(DRV_NAME ": CX: ID:%d [C%d:%s] entry:%d\n", _pr->acpi_id,
			 cx->type, cx->desc, cx->entry_method);
#endif
	}
	if (!ok) {
		pr_err(DRV_NAME ": No available Cx info for cpu %d\n", _pr->acpi_id);
		kfree(xen_cx_states);
		return -EINVAL;
	}
	op.u.set_pminfo.power.count = ok;
	op.u.set_pminfo.power.flags.bm_control = _pr->flags.bm_control;
	op.u.set_pminfo.power.flags.bm_check = _pr->flags.bm_check;
	op.u.set_pminfo.power.flags.has_cst = _pr->flags.has_cst;
	op.u.set_pminfo.power.flags.power_setup_done =
		_pr->flags.power_setup_done;

	set_xen_guest_handle(op.u.set_pminfo.power.states, xen_cx_states);

	if (!no_hypercall)
		ret = HYPERVISOR_dom0_op(&op);

	if (ret)
		pr_err(DRV_NAME "(CX): Hypervisor returned (%d) for ACPI ID: %d\n",
		       ret, _pr->acpi_id);

	kfree(xen_cx_states);

	return ret;
}
static struct xen_processor_px *xen_copy_pss_data(struct acpi_processor *_pr,
						  struct xen_processor_performance *xen_perf)
{
	struct xen_processor_px *xen_states = NULL;
	int i;

	BUILD_BUG_ON(sizeof(struct xen_processor_px) !=
		     sizeof(struct acpi_processor_px));

	xen_states = kcalloc(_pr->performance->state_count,
			     sizeof(struct xen_processor_px), GFP_KERNEL);
	if (!xen_states)
		return ERR_PTR(-ENOMEM);

	xen_perf->state_count = _pr->performance->state_count;
	for (i = 0; i < _pr->performance->state_count; i++) {
		/* Fortunatly for us, they are both the same size */
		memcpy(&(xen_states[i]), &(_pr->performance->states[i]),
		       sizeof(struct acpi_processor_px));
	}
	return xen_states;
}
static int xen_copy_psd_data(struct acpi_processor *_pr,
			     struct xen_processor_performance *xen_perf)
{
	BUILD_BUG_ON(sizeof(struct xen_psd_package) !=
		     sizeof(struct acpi_psd_package));

	if (_pr->performance->shared_type != CPUFREQ_SHARED_TYPE_NONE) {
		xen_perf->shared_type = _pr->performance->shared_type;

		memcpy(&(xen_perf->domain_info), &(_pr->performance->domain_info),
		       sizeof(struct acpi_psd_package));
	} else {
		if ((&cpu_data(0))->x86_vendor != X86_VENDOR_AMD)
			return -EINVAL;

		/* On AMD, the powernow-k8 is loaded before acpi_cpufreq
		 * meaning that acpi_processor_preregister_performance never
		 * gets called which would parse the _PSD. The only relevant
		 * information from _PSD we need is whether it is HW_ALL or any
		 * other type. AMD K8 >= are SW_ALL or SW_ANY, AMD K7<= HW_ANY.
		 * This driver checks at the start whether it is K8 so it
		 * if we get here it can only be K8.
		 */
		xen_perf->shared_type = CPUFREQ_SHARED_TYPE_ANY;
		xen_perf->domain_info.coord_type = DOMAIN_COORD_TYPE_SW_ANY;
		xen_perf->domain_info.num_processors = num_online_cpus();
	}
	return 0;
}
static int xen_copy_pct_data(struct acpi_pct_register *pct,
			     struct xen_pct_register *_pct)
{
	/* It would be nice if you could just do 'memcpy(pct, _pct') but
	 * sadly the Xen structure did not have the proper padding
	 * so the descriptor field takes two (_pct) bytes instead of one (pct).
	 */
	_pct->descriptor = pct->descriptor;
	_pct->length = pct->length;
	_pct->space_id = pct->space_id;
	_pct->bit_width = pct->bit_width;
	_pct->bit_offset = pct->bit_offset;
	_pct->reserved = pct->reserved;
	_pct->address = pct->address;
	return 0;
}
static int xen_push_pxx_to_hypervisor(struct acpi_processor *_pr)
{
	int ret = 0;
	struct xen_platform_op op = {
		.cmd			= XENPF_set_processor_pminfo,
		.interface_version	= XENPF_INTERFACE_VERSION,
		.u.set_pminfo.id	= _pr->acpi_id,
		.u.set_pminfo.type	= XEN_PM_PX,
	};
	struct xen_processor_performance *xen_perf;
	struct xen_processor_px *xen_states = NULL;

	xen_perf = &op.u.set_pminfo.perf;

	xen_perf->platform_limit = _pr->performance_platform_limit;
	xen_perf->flags |= XEN_PX_PPC;
	xen_copy_pct_data(&(_pr->performance->control_register),
			  &xen_perf->control_register);
	xen_copy_pct_data(&(_pr->performance->status_register),
			  &xen_perf->status_register);
	xen_perf->flags |= XEN_PX_PCT;
	xen_states = xen_copy_pss_data(_pr, xen_perf);
	if (!IS_ERR_OR_NULL(xen_states)) {
		set_xen_guest_handle(xen_perf->states, xen_states);
		xen_perf->flags |= XEN_PX_PSS;
	}
	if (!xen_copy_psd_data(_pr, xen_perf))
		xen_perf->flags |= XEN_PX_PSD;

	if (!no_hypercall)
		ret = HYPERVISOR_dom0_op(&op);

	if (ret)
		pr_err(DRV_NAME "(_PXX): Hypervisor returned (%d) for ACPI ID %d\n",
		       ret, _pr->acpi_id);

	if (!IS_ERR_OR_NULL(xen_states))
		kfree(xen_states);

	return ret;
}
/*
 * We read out the struct acpi_processor, and serialize access
 * so that there is only one caller. This is so that we won't
 * race with the CPU hotplug code (xen_cpu_soft_notify).
 */
static int xen_process_data(struct acpi_processor *_pr)
{
	int err = 0;

	mutex_lock(&acpi_ids_mutex);
	if (__test_and_set_bit(_pr->acpi_id, acpi_ids_done)) {
		mutex_unlock(&acpi_ids_mutex);
		return -EBUSY;
	}
	if (_pr->flags.power)
		err = xen_push_cxx_to_hypervisor(_pr);

	if (_pr->performance && _pr->performance->states)
		err |= xen_push_pxx_to_hypervisor(_pr);

	mutex_unlock(&acpi_ids_mutex);
	return err;
}
static acpi_status
xen_read_acpi_id(acpi_handle handle, u32 lvl, void *context, void **rv)
{
	u32 acpi_id;
	acpi_status status;
	acpi_object_type acpi_type;
	unsigned long long tmp;
	union acpi_object object = { 0 };
	struct acpi_buffer buffer = { sizeof(union acpi_object), &object };

	status = acpi_get_type(handle, &acpi_type);
	if (ACPI_FAILURE(status))
		return AE_OK;

	switch (acpi_type) {
	case ACPI_TYPE_PROCESSOR:
		status = acpi_evaluate_object(handle, NULL, NULL, &buffer);
		if (ACPI_FAILURE(status))
			return AE_OK;
		acpi_id = object.processor.proc_id;
		break;
	case ACPI_TYPE_DEVICE:
		status = acpi_evaluate_integer(handle, "_UID", NULL, &tmp);
		if (ACPI_FAILURE(status))
			return AE_OK;
		acpi_id = tmp;
		break;
	default:
		return AE_OK;
	}
	if (acpi_id > NR_ACPI_CPUS) {
		WARN_ONCE(1, "There are %d ACPI processors, but kernel can only do %d!\n",
		     acpi_id, NR_ACPI_CPUS);
		return AE_OK;
	}
	__set_bit(acpi_id, acpi_id_present);

	return AE_OK;
}
static unsigned int xen_acpi_ids_more(void)
{
	unsigned int n = 0;

	acpi_walk_namespace(ACPI_TYPE_PROCESSOR, ACPI_ROOT_OBJECT,
			    ACPI_UINT32_MAX,
			    xen_read_acpi_id, NULL, NULL, NULL);
	acpi_get_devices("ACPI0007", xen_read_acpi_id, NULL, NULL);

	mutex_lock(&acpi_ids_mutex);
	if (!bitmap_equal(acpi_id_present, acpi_ids_done, MAX_ACPI_BITS))
		n = bitmap_weight(acpi_id_present, MAX_ACPI_BITS);
	mutex_unlock(&acpi_ids_mutex);

	return n;
}

static int xen_processor_check(void)
{
	struct cpufreq_policy *policy;
	struct acpi_processor *pr_backup = NULL;
	int cpu, err = 0;

	cpu = get_cpu();
	put_cpu();
	policy = cpufreq_cpu_get(cpu);
	if (!policy)
		return -EBUSY;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		struct acpi_processor *_pr;

		_pr = per_cpu(processors, cpu /* APIC ID */);
		if (!_pr)
			continue;

		if (!pr_backup) {
			pr_backup = kzalloc(sizeof(struct acpi_processor), GFP_KERNEL);
			memcpy(pr_backup, _pr, sizeof(struct acpi_processor));
		}
		(void)xen_process_data(_pr);
	}
	put_online_cpus();

	cpufreq_cpu_put(policy);

	/* All online CPUs have been processed at this stage. Now verify
	 * whether in fact "online CPUs" == physical CPUs.
	 */
	acpi_id_present = kcalloc(MAX_ACPI_BITS, sizeof(unsigned long), GFP_KERNEL);
	if (!acpi_id_present) {
		err = -ENOMEM;
		goto err_out;
	}
	memset(acpi_id_present, 0, MAX_ACPI_BITS * sizeof(unsigned long));

	if (xen_acpi_ids_more() && pr_backup) {
		for_each_set_bit(cpu, acpi_id_present, MAX_ACPI_BITS) {
			pr_backup->acpi_id = cpu;
			/* We will get -EBUSY if it has been programmed already. */
			(void)xen_process_data(pr_backup);
		}
	}
	kfree(acpi_id_present);
	acpi_id_present = NULL;
err_out:
	kfree(pr_backup);
	pr_backup = NULL;
	return err;
}
/*
 * The purpose of this timer/thread is to wait for the ACPI processor
 * and CPUfreq drivers to load up and parse the Pxx and Cxx information
 * before we attempt to read it.
 */
static int xen_processor_thread_func(void *dummy)
{
	int err = 0;
	unsigned long t = POLL_TIMER;

	set_freezable();
	for (;;) {
		long timeout = schedule_timeout_interruptible(t);

		if (timeout == -ERESTARTSYS || kthread_should_stop())
			break;
		try_to_freeze();
		if (xen_processor_check() != -EBUSY)
			t = MAX_SCHEDULE_TIMEOUT;
	}
	return 0;
}

static int xen_cpu_soft_notify(struct notifier_block *nfb,
			       unsigned long action, void *hcpu)
{
	unsigned int cpu = (unsigned long)hcpu;
	struct acpi_processor *_pr = per_cpu(processors, cpu);

	if (action == CPU_ONLINE && _pr)
		(void)xen_process_data(_pr);

	return NOTIFY_OK;
}

static struct notifier_block xen_cpu_notifier = {
	.notifier_call = xen_cpu_soft_notify,
	.priority = -1, /* Be the last one */
};

static int __init check_prereq(void)
{
	struct cpuinfo_x86 *c = &cpu_data(0);

	if (!xen_initial_domain())
		return -ENODEV;

	if (!acpi_gbl_FADT.smi_command)
		return -ENODEV;

	if (c->x86_vendor == X86_VENDOR_INTEL) {
		if (!cpu_has(c, X86_FEATURE_EST))
			return -ENODEV;

		return 0;
	}
	if (c->x86_vendor == X86_VENDOR_AMD) {
		u32 hi = 0, lo = 0;
		/* Copied from powernow-k8.h, can't include ../cpufreq/powernow
		 * as we get compile warnings for the static functions.
		 */
#define MSR_PSTATE_CUR_LIMIT    0xc0010061 /* pstate current limit MSR */
		rdmsr(MSR_PSTATE_CUR_LIMIT, lo, hi);

		/* If the MSR cannot provide the data, the powernow-k8
		 * won't process the data properly either.
		 */
		if (hi || lo)
			return 0;
	}
	return -ENODEV;
}

static int __init xen_processor_passthru_init(void)
{
	int rc = check_prereq();

	if (rc)
		return rc;

	acpi_ids_done = kcalloc(MAX_ACPI_BITS, sizeof(unsigned long), GFP_KERNEL);
	if (!acpi_ids_done)
		return -ENOMEM;
	memset(acpi_ids_done, 0, MAX_ACPI_BITS * sizeof(unsigned long));
	xen_processor_thread = kthread_run(xen_processor_thread_func, NULL, DRV_NAME);
	if (IS_ERR(xen_processor_thread)) {
		pr_err(DRV_NAME ": Failed to create thread. Aborting.\n");
		return -ENOMEM;
	}
	register_hotcpu_notifier(&xen_cpu_notifier);
	return 0;
}
static void __exit xen_processor_passthru_exit(void)
{
	unregister_hotcpu_notifier(&xen_cpu_notifier);
	if (xen_processor_thread)
		kthread_stop(xen_processor_thread);
	kfree(acpi_ids_done);
}
late_initcall(xen_processor_passthru_init);
module_exit(xen_processor_passthru_exit);
