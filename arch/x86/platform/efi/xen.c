/*
 * Xen EFI (Extensible Firmware Interface) support functions
 * Based on related efforts in SLE and SUSE trees
 *
 * Copyright (C) 1999 VA Linux Systems
 * Copyright (C) 1999 Walt Drummond <drummond@valinux.com>
 * Copyright (C) 1999-2002 Hewlett-Packard Co.
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 *	Stephane Eranian <eranian@hpl.hp.com>
 * Copyright (C) 2005-2008 Intel Co.
 *	Fenghua Yu <fenghua.yu@intel.com>
 *	Bibo Mao <bibo.mao@intel.com>
 *	Chandramouli Narayanan <mouli@linux.intel.com>
 *	Huang Ying <ying.huang@intel.com>
 * Copyright (C) 2011 Novell Co.
 *	Jan Beulic <JBeulich@suse.com>
 * Copyright (C) 2011-2012 Oracle Co.
 *	Liang Tang <liang.tang@oracle.com>
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/efi.h>
#include <linux/export.h>
#include <linux/platform_device.h>
#include <linux/spinlock.h>
#include <linux/time.h>

#include <asm/setup.h>
#include <asm/efi.h>
#include <asm/time.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>
#include <asm/x86_init.h>

#include <xen/interface/platform.h>
#include <asm/xen/hypercall.h>

#define PFX		"EFI: "

#define call (op.u.efi_runtime_call)
#define DECLARE_CALL(what) \
	struct xen_platform_op op; \
	op.cmd = XENPF_efi_runtime_call; \
	call.function = XEN_EFI_##what; \
	call.misc = 0

static void register_xen_efi_function(void);

static efi_status_t xen_efi_get_time(efi_time_t *tm, efi_time_cap_t *tc)
{
	int err;
	DECLARE_CALL(get_time);

	err = HYPERVISOR_dom0_op(&op);
	if (err)
		return EFI_UNSUPPORTED;

	if (tm) {
		BUILD_BUG_ON(sizeof(*tm) != sizeof(call.u.get_time.time));
		memcpy(tm, &call.u.get_time.time, sizeof(*tm));
	}

	if (tc) {
		tc->resolution = call.u.get_time.resolution;
		tc->accuracy = call.u.get_time.accuracy;
		tc->sets_to_zero = !!(call.misc &
				      XEN_EFI_GET_TIME_SET_CLEARS_NS);
	}

	return call.status;
}

static efi_status_t xen_efi_set_time(efi_time_t *tm)
{
	DECLARE_CALL(set_time);

	BUILD_BUG_ON(sizeof(*tm) != sizeof(call.u.set_time));
	memcpy(&call.u.set_time, tm, sizeof(*tm));

	return HYPERVISOR_dom0_op(&op) ? EFI_UNSUPPORTED : call.status;
}

static efi_status_t xen_efi_get_wakeup_time(efi_bool_t *enabled,
					    efi_bool_t *pending,
					    efi_time_t *tm)
{
	int err;
	DECLARE_CALL(get_wakeup_time);

	err = HYPERVISOR_dom0_op(&op);
	if (err)
		return EFI_UNSUPPORTED;

	if (tm) {
		BUILD_BUG_ON(sizeof(*tm) != sizeof(call.u.get_wakeup_time));
		memcpy(tm, &call.u.get_wakeup_time, sizeof(*tm));
	}

	if (enabled)
		*enabled = !!(call.misc & XEN_EFI_GET_WAKEUP_TIME_ENABLED);

	if (pending)
		*pending = !!(call.misc & XEN_EFI_GET_WAKEUP_TIME_PENDING);

	return call.status;
}

static efi_status_t xen_efi_set_wakeup_time(efi_bool_t enabled, efi_time_t *tm)
{
	DECLARE_CALL(set_wakeup_time);

	BUILD_BUG_ON(sizeof(*tm) != sizeof(call.u.set_wakeup_time));
	if (enabled)
		call.misc = XEN_EFI_SET_WAKEUP_TIME_ENABLE;
	if (tm)
		memcpy(&call.u.set_wakeup_time, tm, sizeof(*tm));
	else
		call.misc |= XEN_EFI_SET_WAKEUP_TIME_ENABLE_ONLY;

	return HYPERVISOR_dom0_op(&op) ? EFI_UNSUPPORTED : call.status;
}

static efi_status_t xen_efi_get_variable(efi_char16_t *name,
					 efi_guid_t *vendor,
					 u32 *attr,
					 unsigned long *data_size,
					 void *data)
{
	int err;
	DECLARE_CALL(get_variable);

	set_xen_guest_handle(call.u.get_variable.name, name);
	BUILD_BUG_ON(sizeof(*vendor) !=
		     sizeof(call.u.get_variable.vendor_guid));
	memcpy(&call.u.get_variable.vendor_guid, vendor, sizeof(*vendor));
	call.u.get_variable.size = *data_size;
	set_xen_guest_handle(call.u.get_variable.data, data);
	err = HYPERVISOR_dom0_op(&op);
	if (err)
		return EFI_UNSUPPORTED;

	*data_size = call.u.get_variable.size;
	*attr = call.misc; /* misc in struction is U32 variable*/

	return call.status;
}

static efi_status_t xen_efi_get_next_variable(unsigned long *name_size,
					      efi_char16_t *name,
					      efi_guid_t *vendor)
{
	int err;
	DECLARE_CALL(get_next_variable_name);
	if (efi.runtime_version < EFI_2_00_SYSTEM_TABLE_REVISION)
		return EFI_UNSUPPORTED;
	call.u.get_next_variable_name.size = *name_size;
	set_xen_guest_handle(call.u.get_next_variable_name.name, name);
	BUILD_BUG_ON(sizeof(*vendor) !=
		     sizeof(call.u.get_next_variable_name.vendor_guid));
	memcpy(&call.u.get_next_variable_name.vendor_guid, vendor,
	       sizeof(*vendor));
	err = HYPERVISOR_dom0_op(&op);
	if (err)
		return EFI_UNSUPPORTED;

	*name_size = call.u.get_next_variable_name.size;
	memcpy(vendor, &call.u.get_next_variable_name.vendor_guid,
	       sizeof(*vendor));

	return call.status;
}

static efi_status_t xen_efi_set_variable(efi_char16_t *name,
					 efi_guid_t *vendor,
					 u32 attr,
					 unsigned long data_size,
					 void *data)
{
	DECLARE_CALL(set_variable);

	set_xen_guest_handle(call.u.set_variable.name, name);
	call.misc = attr;
	BUILD_BUG_ON(sizeof(*vendor) !=
		     sizeof(call.u.set_variable.vendor_guid));
	memcpy(&call.u.set_variable.vendor_guid, vendor, sizeof(*vendor));
	call.u.set_variable.size = data_size;
	set_xen_guest_handle(call.u.set_variable.data, data);

	return HYPERVISOR_dom0_op(&op) ? EFI_UNSUPPORTED : call.status;
}

static efi_status_t xen_efi_query_variable_info(u32 attr,
						u64 *storage_space,
						u64 *remaining_space,
						u64 *max_variable_size)
{
	int err;
	DECLARE_CALL(query_variable_info);

	if (efi.runtime_version < EFI_2_00_SYSTEM_TABLE_REVISION)
		return EFI_UNSUPPORTED;

	err = HYPERVISOR_dom0_op(&op);
	if (err)
		return EFI_UNSUPPORTED;

	*storage_space = call.u.query_variable_info.max_store_size;
	*remaining_space = call.u.query_variable_info.remain_store_size;
	*max_variable_size = call.u.query_variable_info.max_size;

	return call.status;
}

static efi_status_t xen_efi_get_next_high_mono_count(u32 *count)
{
	int err;
	DECLARE_CALL(get_next_high_monotonic_count);

	err = HYPERVISOR_dom0_op(&op);
	if (err)
		return EFI_UNSUPPORTED;

	*count = call.misc;

	return call.status;
}

static efi_status_t xen_efi_update_capsule(efi_capsule_header_t **capsules,
					   unsigned long count,
					   unsigned long sg_list)
{
	DECLARE_CALL(update_capsule);

	if (efi.runtime_version < EFI_2_00_SYSTEM_TABLE_REVISION)
		return EFI_UNSUPPORTED;

	set_xen_guest_handle(call.u.update_capsule.capsule_header_array,
			     capsules);
	call.u.update_capsule.capsule_count = count;
	call.u.update_capsule.sg_list = sg_list;

	return HYPERVISOR_dom0_op(&op) ? EFI_UNSUPPORTED : call.status;
}

static efi_status_t xen_efi_query_capsule_caps(efi_capsule_header_t **capsules,
					       unsigned long count,
					       u64 *max_size,
					       int *reset_type)
{
	int err;
	DECLARE_CALL(query_capsule_capabilities);

	if (efi.runtime_version < EFI_2_00_SYSTEM_TABLE_REVISION)
		return EFI_UNSUPPORTED;

	set_xen_guest_handle(call.u.query_capsule_capabilities.
		capsule_header_array, capsules);
	call.u.query_capsule_capabilities.capsule_count = count;

	err = HYPERVISOR_dom0_op(&op);
	if (err)
		return EFI_UNSUPPORTED;

	*max_size = call.u.query_capsule_capabilities.max_capsule_size;
	*reset_type = call.u.query_capsule_capabilities.reset_type;

	return call.status;
}

#undef DECLARE_CALL
#undef call

static const struct efi __initconst efi_xen = {
	.mps                      = EFI_INVALID_TABLE_ADDR,
	.acpi                     = EFI_INVALID_TABLE_ADDR,
	.acpi20                   = EFI_INVALID_TABLE_ADDR,
	.smbios                   = EFI_INVALID_TABLE_ADDR,
	.sal_systab               = EFI_INVALID_TABLE_ADDR,
	.boot_info                = EFI_INVALID_TABLE_ADDR,
	.hcdp                     = EFI_INVALID_TABLE_ADDR,
	.uga                      = EFI_INVALID_TABLE_ADDR,
	.uv_systab                = EFI_INVALID_TABLE_ADDR,
	.get_time                 = xen_efi_get_time,
	.set_time                 = xen_efi_set_time,
	.get_wakeup_time          = xen_efi_get_wakeup_time,
	.set_wakeup_time          = xen_efi_set_wakeup_time,
	.get_variable             = xen_efi_get_variable,
	.get_next_variable        = xen_efi_get_next_variable,
	.set_variable             = xen_efi_set_variable,
	.get_next_high_mono_count = xen_efi_get_next_high_mono_count,
	.query_variable_info      = xen_efi_query_variable_info,
	.update_capsule           = xen_efi_update_capsule,
	.query_capsule_caps       = xen_efi_query_capsule_caps,
};

void xen_efi_probe(void)
{
	static struct xen_platform_op __initdata op = {
		.cmd = XENPF_firmware_info,
		.u.firmware_info = {
			.type = XEN_FW_EFI_INFO,
			.index = XEN_FW_EFI_CONFIG_TABLE
		}
	};

	if (HYPERVISOR_dom0_op(&op) == 0) {
		/*efi_enabled = 1;*/
		set_bit(EFI_BOOT, &x86_efi_facility);
		/* this should be set based on whether the EFI loader
		 * signature contains "EL64" (see arch/x86/kernel/setup.c).
		 * Looks like a new hypercall will be needed for this */
		set_bit(EFI_64BIT, &x86_efi_facility);

		register_xen_efi_function();
	}
}


static void __init efi_init_xen(void)
{
	efi_char16_t c16[100];
	char vendor[ARRAY_SIZE(c16)] = "unknown";
	int ret, i;
	struct xen_platform_op op;
	union xenpf_efi_info *info = &op.u.firmware_info.u.efi_info;

	efi = efi_xen;
	op.cmd = XENPF_firmware_info;
	op.u.firmware_info.type = XEN_FW_EFI_INFO;

	/*
	 * Show what we know for posterity
	 */
	op.u.firmware_info.index = XEN_FW_EFI_VENDOR;
	info->vendor.bufsz = sizeof(c16);
	set_xen_guest_handle(info->vendor.name, c16);
	ret = HYPERVISOR_dom0_op(&op);
	if (!ret) {
		for (i = 0; i < sizeof(vendor) - 1 && c16[i]; ++i)
			vendor[i] = c16[i];
		vendor[i] = '\0';
	} else
		pr_err("Could not get the firmware vendor!\n");

	op.u.firmware_info.index = XEN_FW_EFI_VERSION;
	ret = HYPERVISOR_dom0_op(&op);
	if (!ret)
		pr_info("EFI-xen v%u.%.02u by %s\n",
		       info->version >> 16,
		       info->version & 0xffff, vendor);
	else
		pr_err("Could not get EFI revision!\n");

	op.u.firmware_info.index = XEN_FW_EFI_RT_VERSION;
	ret = HYPERVISOR_dom0_op(&op);
	if (!ret)
		efi.runtime_version = info->version;
	else
		pr_warn(PFX "Could not get runtime services revision.\n");
	set_bit(EFI_RUNTIME_SERVICES, &x86_efi_facility);

	/*
	 * Let's see what config tables the firmware passed to us.
	 */
	op.u.firmware_info.index = XEN_FW_EFI_CONFIG_TABLE;
	if (HYPERVISOR_dom0_op(&op))
		BUG();

	if (efi_config_init(info->cfg.addr, info->cfg.nent, &efi))
		panic("Could not init EFI Configuration Tables!\n");
	set_bit(EFI_CONFIG_TABLES, &x86_efi_facility);

	/* the EFI memory info is digested by the hypervisor and
	 * supplied to dom0 via E820 entries */
	set_bit(EFI_MEMMAP, &x86_efi_facility);

	set_bit(EFI_SYSTEM_TABLES, &x86_efi_facility); /* not checked */

	/* NOTE: efi.c only does this for CONFIG_X86_32 */
	x86_platform.get_wallclock = efi_get_time;
	x86_platform.set_wallclock = efi_set_rtc_mmss;
}

/*
 * Convenience functions to obtain memory types and attributes
 */
static u32 efi_mem_type_xen(unsigned long phys_addr)
{
	struct xen_platform_op op;
	union xenpf_efi_info *info = &op.u.firmware_info.u.efi_info;

	op.cmd = XENPF_firmware_info;
	op.u.firmware_info.type = XEN_FW_EFI_INFO;
	op.u.firmware_info.index = XEN_FW_EFI_MEM_INFO;
	info->mem.addr = phys_addr;
	info->mem.size = 0;
	return HYPERVISOR_dom0_op(&op) ? 0 : info->mem.type;
}

static u64 efi_mem_attributes_xen(unsigned long phys_addr)
{
	struct xen_platform_op op;
	union xenpf_efi_info *info = &op.u.firmware_info.u.efi_info;

	op.cmd = XENPF_firmware_info;
	op.u.firmware_info.type = XEN_FW_EFI_INFO;
	op.u.firmware_info.index = XEN_FW_EFI_MEM_INFO;
	info->mem.addr = phys_addr;
	info->mem.size = 0;
	return HYPERVISOR_dom0_op(&op) ? 0 : info->mem.attr;
}

static const struct __initconst efi_init_funcs xen_efi_funcs = {
	.init		        = efi_init_xen,
	.late_init		= NULL,
	.reserve_boot_services  = NULL,
	.free_boot_services     = NULL,
	.enter_virtual_mode     = NULL,
	.mem_type	        = efi_mem_type_xen,
	.mem_attributes	        = efi_mem_attributes_xen,
	.x86_reserve_range	= NULL
};

static void register_xen_efi_function(void)
{
	efi_init_function_register(&xen_efi_funcs);
}
