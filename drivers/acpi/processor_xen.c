/*
 * processor_xen.c - ACPI Processor Driver for xen
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
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

#include <acpi/acpi_drivers.h>
#include <acpi/processor.h>
#include <xen/acpi.h>

#define PREFIX "ACPI: "

#define ACPI_PROCESSOR_CLASS            "processor"
#define ACPI_PROCESSOR_NOTIFY_PERFORMANCE 0x80
#define ACPI_PROCESSOR_NOTIFY_POWER	0x81
#define ACPI_PROCESSOR_NOTIFY_THROTTLING	0x82

#define _COMPONENT              ACPI_PROCESSOR_COMPONENT
ACPI_MODULE_NAME("processor_xen");

#if defined(CONFIG_ACPI_PROCESSOR_XEN) || \
defined(CONFIG_ACPI_PROCESSOR_XEN_MODULE)
static const struct acpi_device_id processor_device_ids[] = {
	{ACPI_PROCESSOR_OBJECT_HID, 0},
	{"ACPI0007", 0},
	{"", 0},
};

static int xen_acpi_processor_add(struct acpi_device *device);
static void xen_acpi_processor_notify(struct acpi_device *device, u32 event);

struct acpi_driver xen_acpi_processor_driver = {
	.name = "processor",
	.class = ACPI_PROCESSOR_CLASS,
	.ids = processor_device_ids,
	.ops = {
		.add = xen_acpi_processor_add,
		.remove = acpi_processor_remove,
		.suspend = acpi_processor_suspend,
		.resume = acpi_processor_resume,
		.notify = xen_acpi_processor_notify,
		},
};

#ifdef CONFIG_CPU_FREQ
/*
 * Existing ACPI module does parse performance states at some point,
 * when acpi-cpufreq driver is loaded which however is something
 * we'd like to disable to avoid confliction with xen PM
 * logic. So we have to collect raw performance information here
 * when ACPI processor object is found and started.
 */
static int xen_acpi_processor_get_performance(struct acpi_processor *pr)
{
	int ret;
	struct acpi_processor_performance *perf;
	struct acpi_psd_package *pdomain;

	if (pr->performance)
		return -EBUSY;

	perf = kzalloc(sizeof(struct acpi_processor_performance), GFP_KERNEL);
	if (!perf)
		return -ENOMEM;

	pr->performance = perf;
	/* Get basic performance state information */
	ret = acpi_processor_get_performance_info(pr);
	if (ret < 0)
		goto err_out;

	/* invoke raw psd parse interface directly, as it's useless to
	 * construct a shared map around dom0's vcpu ID.
	 */
	pdomain = &pr->performance->domain_info;
	pdomain->num_processors = 0;
	ret = acpi_processor_get_psd(pr);
	if (ret < 0) {
		/*
		 * _PSD is optional - assume no coordination if absent (or
		 * broken), matching native kernels' behavior.
		 */
		pdomain->num_entries = ACPI_PSD_REV0_ENTRIES;
		pdomain->revision = ACPI_PSD_REV0_REVISION;
		pdomain->domain = pr->acpi_id;
		pdomain->coord_type = DOMAIN_COORD_TYPE_SW_ALL;
		pdomain->num_processors = 1;
	}

	processor_cntl_xen_notify(pr, PROCESSOR_PM_INIT, PM_TYPE_PERF);

	/* Last step is to notify BIOS that xen exists */
	acpi_processor_notify_smm(THIS_MODULE);

	return 0;
err_out:
	pr->performance = NULL;
	kfree(perf);
	return ret;
}
#endif /* CONFIG_CPU_FREQ */

static int __cpuinit xen_acpi_processor_add(struct acpi_device *device)
{
	struct acpi_processor *pr = NULL;
	int result = 0;

	result = acpi_processor_add(device);
	if (result < 0)
		return result;

	pr = acpi_driver_data(device);
	if (!pr)
		return -EINVAL;

	if (pr->id == -1) {
		int device_declaration;
		int apic_id = -1;

		if (!strcmp(acpi_device_hid(device), ACPI_PROCESSOR_OBJECT_HID))
			device_declaration = 0;
		else
			device_declaration = 1;

		apic_id = acpi_get_cpuid(pr->handle,
			device_declaration, pr->acpi_id);
		if (apic_id == -1) {
			/* Processor is not present in MADT table */
			return 0;
		}

		/*
		 * It's possible to have pr->id as '-1' even when it's actually
		 * present in MADT table, e.g. due to limiting dom0 max vcpus
		 * less than physical present number. In such case we still want
		 * to parse ACPI processor object information, so mimic the
		 * pr->id to CPU-0. This should be safe because we only care
		 * about raw ACPI information, which only relies on pr->acpi_id.
		 * For other information relying on pr->id and gathered through
		 * SMP function call, it's safe to let them run on CPU-0 since
		 * underlying Xen will collect them. Only a valid pr->id can
		 * make later invocations forward progress.
		 */
		pr->id = 0;
	}

	if (likely(!pr->flags.power_setup_done)) {
		/* reset idle boot option which we don't care */
		boot_option_idle_override = IDLE_NO_OVERRIDE;
		acpi_processor_power_init(pr, device);
		/* set to IDLE_HALT for trapping into Xen */
		boot_option_idle_override = IDLE_HALT;

		if (pr->flags.power)
			processor_cntl_xen_notify(pr,
					PROCESSOR_PM_INIT, PM_TYPE_IDLE);
	}

#ifdef CONFIG_CPU_FREQ
	if (likely(!pr->performance))
		xen_acpi_processor_get_performance(pr);
#endif

	return 0;
}

static void xen_acpi_processor_notify(struct acpi_device *device, u32 event)
{
	struct acpi_processor *pr = acpi_driver_data(device);

	if (!pr)
		return;

	acpi_processor_notify(device, event);

	switch (event) {
	case ACPI_PROCESSOR_NOTIFY_PERFORMANCE:
#ifdef CONFIG_CPU_FREQ
		processor_cntl_xen_notify(pr,
				PROCESSOR_PM_CHANGE, PM_TYPE_PERF);
#endif
		break;
	case ACPI_PROCESSOR_NOTIFY_POWER:
		processor_cntl_xen_notify(pr,
				PROCESSOR_PM_CHANGE, PM_TYPE_IDLE);
		break;
	default:
		break;
	}

	return;
}

/* init and exit */

/* we don't install acpi cpuidle driver because dom0 itself is running
 * as a guest which has no knowledge whether underlying is actually idle
 */
int xen_acpi_processor_init(void)
{
	int result = 0;

	result = acpi_bus_register_driver(&xen_acpi_processor_driver);
	if (result < 0)
		return result;
		/* mark ready for handling ppc */
	ignore_ppc = 0;

	return 0;
}

void xen_acpi_processor_exit(void)
{
	ignore_ppc = -1;

	acpi_bus_unregister_driver(&xen_acpi_processor_driver);
}
#endif

#if defined(CONFIG_ACPI_PROCESSOR_XEN) || \
defined(CONFIG_ACPI_PROCESSOR_XEN_MODULE)
void xen_processor_driver_register(void)
{
	if (xen_initial_domain()) {
		__acpi_processor_register_driver = xen_acpi_processor_init;
		__acpi_processor_unregister_driver = xen_acpi_processor_exit;
	}
}
#else
void xen_processor_driver_register(void)
{
}
#endif
