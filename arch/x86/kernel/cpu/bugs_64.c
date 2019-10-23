/*
 *  Copyright (C) 1994  Linus Torvalds
 *  Copyright (C) 2000  SuSE
 */

#include <linux/kernel.h>
#include <linux/init.h>
#ifdef CONFIG_SYSFS
#include <linux/device.h>
#endif
#include <linux/cpu.h>
#include <linux/prctl.h>
#include <asm/alternative.h>
#include <asm/nospec-branch.h>
#include <asm/cmdline.h>
#include <asm/bugs.h>
#include <asm/processor.h>
#include <asm/mtrr.h>
#include <asm/cacheflush.h>
#include <asm/spec_ctrl.h>
#include <asm/spec-ctrl.h>
#include <asm/cmdline.h>
#include <asm/intel-family.h>
#include <asm/hypervisor.h>
#include <asm/e820.h>
#include <asm/vmx.h>
#include <xen/xen.h>

#include "cpu.h"

/*
 * use_ibrs flags:
 * SPEC_CTRL_BASIC_IBRS_INUSE		basic ibrs is currently in use
 * SPEC_CTRL_IBRS_SUPPORTED		system supports basic ibrs
 * SPEC_CTRL_IBRS_ADMIN_DISABLED	admin disables ibrs (basic and enhanced)
 * SPEC_CTRL_IBRS_FIRMWARE		ibrs to be used on firmware paths
 * SPEC_CTRL_ENHCD_IBRS_SUPPORTED	system supports enhanced ibrs
 * SPEC_CTRL_ENHCD_IBRS_INUSE		Enhanced ibrs is currently in use
 */
int use_ibrs;
EXPORT_SYMBOL(use_ibrs);

DEFINE_PER_CPU(unsigned int, cpu_ibrs) = 0;
EXPORT_PER_CPU_SYMBOL(cpu_ibrs);

/*
 * use_ibpb flags:
 * SPEC_CTRL_IBPB_INUSE			indicate if ibpb is currently in use
 * SPEC_CTRL_IBPB_SUPPORTED		indicate if system supports ibpb
 * SPEC_CTRL_IBPB_ADMIN_DISABLED	indicate if admin disables ibpb
 */
int use_ibpb;
EXPORT_SYMBOL(use_ibpb);

/* mutex to serialize IBRS & IBPB control changes */
DEFINE_MUTEX(spec_ctrl_mutex);
EXPORT_SYMBOL(spec_ctrl_mutex);

bool use_ibrs_on_skylake = true;
EXPORT_SYMBOL(use_ibrs_on_skylake);

bool use_ibrs_with_ssbd = true;

bool microcode_had_ibrs = false;

/*
 * retpoline_fallback flags:
 * SPEC_CTRL_USE_RETPOLINE_FALLBACK	pick retpoline fallback mitigation
 */
int retpoline_fallback = SPEC_CTRL_USE_RETPOLINE_FALLBACK;
EXPORT_SYMBOL(retpoline_fallback);


/*
 * Retpoline variables.
 */
static enum spectre_v2_mitigation retpoline_mode = SPECTRE_V2_NONE;
DEFINE_STATIC_KEY_FALSE(retpoline_enabled_key);
EXPORT_SYMBOL(retpoline_enabled_key);

/*
 * RSB stuffing dynamic keys to activate the STUFF_RSB macro,
 * and indicate if this macro should overwrite the RSB.
 */
DEFINE_STATIC_KEY_FALSE(rsb_stuff_key);
EXPORT_SYMBOL(rsb_stuff_key);
DEFINE_STATIC_KEY_FALSE(rsb_overwrite_key);
EXPORT_SYMBOL(rsb_overwrite_key);

static bool is_skylake_era(void);
static void disable_ibrs_and_friends(bool);
static void activate_spectre_v2_mitigation(enum spectre_v2_mitigation);

int __init spectre_v2_heuristics_setup(char *p)
{
	ssize_t len;

	while (*p) {
		/* Disable all heuristics. */
		if (!strncmp(p, "off", 3)) {
			use_ibrs_on_skylake = false;
			use_ibrs_with_ssbd = false;
			clear_retpoline_fallback();
			break;
		}
		len = strlen("skylake");
		if (!strncmp(p, "skylake", len)) {
			p += len;
			if (*p == '=')
				++p;
			if (*p == '\0')
				break;
			if (!strncmp(p, "off", 3))
				use_ibrs_on_skylake = false;
		}
		len = strlen("retpoline_fallback");
		if (!strncmp(p, "retpoline_fallback", len)) {
			p += len;
			if (*p == '=')
				++p;
			if (*p == '\0')
				break;
			if (!strncmp(p, "off", 3))
				clear_retpoline_fallback();
		}
		len = strlen("ssbd");
		if (!strncmp(p, "ssbd", len)) {
			p += len;
			if (*p == '=')
				++p;
			if (*p == '\0')
				break;
			if (!strncmp(p, "off", 3))
				use_ibrs_with_ssbd = false;
		}

		p = strpbrk(p, ",");
		if (!p)
			break;
		p++; /* skip ',' */
	}
	return 1;
}
__setup("spectre_v2_heuristics=", spectre_v2_heuristics_setup);

static void __init spectre_v1_select_mitigation(void);
static void __init spectre_v2_select_mitigation(void);
static enum ssb_mitigation __init ssb_select_mitigation(void);
static void __init ssb_init(void);
static void __init l1tf_select_mitigation(void);
static void __init mds_select_mitigation(void);
static void __init taa_select_mitigation(void);

static enum ssb_mitigation ssb_mode = SPEC_STORE_BYPASS_NONE;

/*
 * Our boot-time value of the SPEC_CTRL MSR. We read it once so that any
 * writes to SPEC_CTRL contain whatever reserved bits have been set.
 */
u64 x86_spec_ctrl_base;
EXPORT_SYMBOL_GPL(x86_spec_ctrl_base);

/*
 * The vendor and possibly platform specific bits which can be modified in
 * x86_spec_ctrl_base.
 */
static u64 x86_spec_ctrl_mask = SPEC_CTRL_IBRS;

/*
 * Our knob on entering the kernel to enable and disable IBRS.
 * Inherits value from x86_spec_ctrl_base.
 */
u64 x86_spec_ctrl_priv;
EXPORT_SYMBOL_GPL(x86_spec_ctrl_priv);
DEFINE_PER_CPU(u64, x86_spec_ctrl_priv_cpu) = 0;
EXPORT_PER_CPU_SYMBOL(x86_spec_ctrl_priv_cpu);
DEFINE_PER_CPU(u64, x86_spec_ctrl_restore) = 0;
EXPORT_PER_CPU_SYMBOL(x86_spec_ctrl_restore);

/*
 * AMD specific MSR info for Speculative Store Bypass control.
 * x86_amd_ls_cfg_ssbd_mask is initialized in identify_boot_cpu().
 */
u64 x86_amd_ls_cfg_base;
u64 x86_amd_ls_cfg_ssbd_mask;

/* Control MDS CPU buffer clear before returning to user space */
DEFINE_STATIC_KEY_FALSE(mds_user_clear);
EXPORT_SYMBOL_GPL(mds_user_clear);

/* Control MDS CPU buffer clear before idling (halt, mwait) */
DEFINE_STATIC_KEY_FALSE(mds_idle_clear);
EXPORT_SYMBOL_GPL(mds_idle_clear);

static enum spectre_v2_mitigation spectre_v2_enabled = SPECTRE_V2_NONE;

static inline bool spectre_v2_eibrs_enabled(void)
{
	return spectre_v2_enabled == SPECTRE_V2_IBRS_ENHANCED;
}

void __init check_bugs(void)
{
	identify_boot_cpu();

	/*
	 * identify_boot_cpu() initialized SMT support information, let the
	 * core code know.
	 */
	cpu_smt_check_topology_early();

#if !defined(CONFIG_SMP)
	printk(KERN_INFO "CPU: ");
	print_cpu_info(&boot_cpu_data);
#endif
	/*
	 * Read the SPEC_CTRL MSR to account for reserved bits which may
	 * have unknown values. AMD64_LS_CFG MSR is cached in the early AMD
	 * init code as it is not enumerated and depends on the family.
	 */
       if (boot_cpu_has(X86_FEATURE_IBRS)) {
		rdmsrl(MSR_IA32_SPEC_CTRL, x86_spec_ctrl_base);
		if (x86_spec_ctrl_base & (SPEC_CTRL_IBRS | SPEC_CTRL_SSBD)) {
			pr_warn("SPEC CTRL MSR (0x%16llx) has IBRS and/or "
				"SSBD set during boot, clearing it.", x86_spec_ctrl_base);
			x86_spec_ctrl_base &= ~(SPEC_CTRL_IBRS | SPEC_CTRL_SSBD);
		}
		x86_spec_ctrl_priv = x86_spec_ctrl_base;
		update_cpu_spec_ctrl_all();
		microcode_had_ibrs = true;
	}

	/* Allow STIBP in MSR_SPEC_CTRL if supported */
	if (boot_cpu_has(X86_FEATURE_STIBP))
		x86_spec_ctrl_mask |= SPEC_CTRL_STIBP;

	/* Select the proper CPU mitigations before patching alternatives: */
	ssb_mode = ssb_select_mitigation();
	spectre_v1_select_mitigation();
	spectre_v2_select_mitigation();

	/* Relies on the result of spectre_v2_select_mitigation. */
	ssb_init();
	l1tf_select_mitigation();
	mds_select_mitigation();
	taa_select_mitigation();

	alternative_instructions();

	/*
	 * Make sure the first 2MB area is not mapped by huge pages
	 * There are typically fixed size MTRRs in there and overlapping
	 * MTRRs into large pages causes slow downs.
	 *
	 * Right now we don't do that with gbpages because there seems
	 * very little benefit for that case.
	 */
	if (!direct_gbpages)
		set_memory_4k((unsigned long)__va(0), 1);
}

/* Check for Skylake-like CPUs (for RSB handling) */
static bool is_skylake_era(void)
{
	if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL &&
	    boot_cpu_data.x86 == 6) {
		switch (boot_cpu_data.x86_model) {
		case INTEL_FAM6_SKYLAKE_MOBILE:
		case INTEL_FAM6_SKYLAKE_DESKTOP:
		case INTEL_FAM6_SKYLAKE_X:
		case INTEL_FAM6_KABYLAKE_MOBILE:
		case INTEL_FAM6_KABYLAKE_DESKTOP:
			return true;
		}
	}
	return false;
}

#undef pr_fmt
#define pr_fmt(fmt)     "Spectre V1 : " fmt

enum spectre_v1_mitigation {
	SPECTRE_V1_MITIGATION_NONE,
	SPECTRE_V1_MITIGATION_AUTO,
};

static enum spectre_v1_mitigation spectre_v1_mitigation __read_mostly =
	SPECTRE_V1_MITIGATION_AUTO;

static const char * const spectre_v1_strings[] = {
	[SPECTRE_V1_MITIGATION_NONE] = "Vulnerable: __user pointer sanitization and usercopy barriers only; no swapgs barriers",
	[SPECTRE_V1_MITIGATION_AUTO] = "Mitigation: usercopy/swapgs barriers and __user pointer sanitization",
};

/*
 * Does SMAP provide full mitigation against speculative kernel access to
 * userspace?
 */
static bool smap_works_speculatively(void)
{
	if (!boot_cpu_has(X86_FEATURE_SMAP))
		return false;

	/*
	 * On CPUs which are vulnerable to Meltdown, SMAP does not
	 * prevent speculative access to user data in the L1 cache.
	 * Consider SMAP to be non-functional as a mitigation on these
	 * CPUs.
	 */
	if (boot_cpu_has(X86_BUG_CPU_MELTDOWN))
		return false;

	return true;
}

static void __init spectre_v1_select_mitigation(void)
{
	spectre_v1_mitigation = SPECTRE_V1_MITIGATION_AUTO;

	if (!boot_cpu_has_bug(X86_BUG_SPECTRE_V1) || cpu_mitigations_off() ||
	    cmdline_find_option_bool (boot_command_line, "nospectre_v1")) {
		spectre_v1_mitigation = SPECTRE_V1_MITIGATION_NONE;
	}

	if (spectre_v1_mitigation == SPECTRE_V1_MITIGATION_AUTO) {
		/*
		 * With Spectre v1, a user can speculatively control either
		 * path of a conditional swapgs with a user-controlled GS
		 * value.  The mitigation is to add lfences to both code paths.
		 *
		 * If FSGSBASE is enabled, the user can put a kernel address in
		 * GS, in which case SMAP provides no protection.
		 *
		 * [ NOTE: Don't check for X86_FEATURE_FSGSBASE until the
		 *	   FSGSBASE enablement patches have been merged. ]
		 *
		 * If FSGSBASE is disabled, the user can only put a user space
		 * address in GS.  That makes an attack harder, but still
		 * possible if there's no SMAP protection.
		 */
		if (!smap_works_speculatively()) {
			/*
			 * Mitigation can be provided from SWAPGS itself or
			 * PTI as the CR3 write in the Meltdown mitigation
			 * is serializing.
			 *
			 * If neither is there, mitigate with an LFENCE to
			 * stop speculation through swapgs.
			 */
			if (boot_cpu_has_bug(X86_BUG_SWAPGS) &&
			    !boot_cpu_has(X86_FEATURE_PTI))
				setup_force_cpu_cap(X86_FEATURE_FENCE_SWAPGS_USER);

			/*
			 * Enable lfences in the kernel entry (non-swapgs)
			 * paths, to prevent user entry from speculatively
			 * skipping swapgs.
			 */
			setup_force_cpu_cap(X86_FEATURE_FENCE_SWAPGS_KERNEL);
		}
	}

	pr_info("%s\n", spectre_v1_strings[spectre_v1_mitigation]);
}

/* The kernel command line selection */
enum spectre_v2_mitigation_cmd {
	SPECTRE_V2_CMD_NONE,
	SPECTRE_V2_CMD_AUTO,
	SPECTRE_V2_CMD_FORCE,
	SPECTRE_V2_CMD_RETPOLINE,
	SPECTRE_V2_CMD_RETPOLINE_GENERIC,
	SPECTRE_V2_CMD_RETPOLINE_AMD,
	SPECTRE_V2_CMD_IBRS,
};

static const char *spectre_v2_strings[] = {
	[SPECTRE_V2_NONE]			= "Vulnerable",
	[SPECTRE_V2_RETPOLINE_GENERIC]		= "Mitigation: Full generic retpoline",
	[SPECTRE_V2_RETPOLINE_AMD]		= "Mitigation: Full AMD retpoline",
	[SPECTRE_V2_IBRS]			= "Mitigation: Basic IBRS",
	[SPECTRE_V2_IBRS_ENHANCED]		= "Mitigation: Enhanced IBRS",
};

#undef pr_fmt
#define pr_fmt(fmt)     "Spectre V2 : " fmt

void x86_spec_ctrl_set(enum spec_ctrl_set_context context)
{
	u64 host;

	if (context != SPEC_CTRL_INITIAL &&
	    this_cpu_read(x86_spec_ctrl_priv_cpu) == x86_spec_ctrl_base)
		return;

	switch (context) {
	case SPEC_CTRL_INITIAL:
		/*
		 * Initial write of the MSR on this CPU.  Done to turn on SSBD
		 * if it is always enabled in privileged mode
		 * (spec_store_bypass_disable=on). If enhanced IBRS is in use,
		 * its bit has been set by an earlier write to the MSR on all
		 * the cpus, and it must be preserved by this MSR write.
		 * Otherwise use only the base bits (x86_spec_ctrl_base) to
		 * avoid basic IBRS needlessly being enabled before userspace
		 * is running.
		 */
		host = x86_spec_ctrl_base | (spectre_v2_eibrs_enabled() ?
			SPEC_CTRL_FEATURE_ENABLE_IBRS : 0);
		break;
	case SPEC_CTRL_IDLE_ENTER:
		/*
		 * If IBRS/SSBD are in use, disable them to avoid performance impact
		 * during idle.
		 */
		host = x86_spec_ctrl_base & ~SPEC_CTRL_SSBD;
		break;
	case SPEC_CTRL_IDLE_EXIT:
		host = this_cpu_read(x86_spec_ctrl_priv_cpu);
		break;
	default:
		WARN_ONCE(1, "unknown spec_ctrl_set_context %#x\n", context);
		return;
	}

	/*
	 * Note that when MSR_IA32_SPEC_CTRL is not available both
	 * per_cpu(x86_spec_ctrl_priv_cpu ) and x86_spec_ctrl_base
	 * are zero. Therefore we don't need to explicitly check for
	 * MSR presence.
	 * And for SPEC_CTRL_INITIAL we are only called when we know
	 * the MSR exists.
	 */
	wrmsrl(MSR_IA32_SPEC_CTRL, host);
}
EXPORT_SYMBOL_GPL(x86_spec_ctrl_set);

void
x86_virt_spec_ctrl(u64 guest_spec_ctrl, u64 guest_virt_spec_ctrl, bool setguest)
{
	u64 msrval, guestval, hostval = x86_spec_ctrl_base;
	struct thread_info *ti = current_thread_info();

	if (ibrs_supported) {
		/*
		 * Restrict guest_spec_ctrl to supported values. Clear the
		 * modifiable bits in the host base value and or the
		 * modifiable bits from the guest value.
		 */
		if (cpu_ibrs_inuse_any())
			/*
			 * Except on IBRS we don't want to use host base value
			 * but rather the privilege value which has IBRS set.
			 */
			hostval = this_cpu_read(x86_spec_ctrl_priv_cpu);

		guestval = hostval & ~x86_spec_ctrl_mask;
		guestval |= guest_spec_ctrl & x86_spec_ctrl_mask;

		/* SSBD controlled in MSR_SPEC_CTRL */
		if (static_cpu_has(X86_FEATURE_SSBD))
			hostval |= ssbd_tif_to_spec_ctrl(ti->flags);

		if (hostval != guestval || check_basic_ibrs_inuse()) {
			msrval = setguest ? guestval : hostval;
			wrmsrl(MSR_IA32_SPEC_CTRL, msrval);
		}
	}

	/*
	 * If SSBD is not handled in MSR_SPEC_CTRL on AMD, update
	 * MSR_AMD64_L2_CFG or MSR_VIRT_SPEC_CTRL if supported.
	 */
	if (!static_cpu_has(X86_FEATURE_AMD_SSBD) &&
	    !static_cpu_has(X86_FEATURE_VIRT_SSBD))
		return;

	/*
	 * If the host has SSBD mitigation enabled, force it in the host's
	 * virtual MSR value. If its not permanently enabled, evaluate
	 * current's TIF_SSBD thread flag.
	 */
	if (static_cpu_has(X86_FEATURE_SPEC_STORE_BYPASS_DISABLE))
		hostval = SPEC_CTRL_SSBD;
	else
		hostval = ssbd_tif_to_spec_ctrl(ti->flags);

	/* Sanitize the guest value */
	guestval = guest_virt_spec_ctrl & SPEC_CTRL_SSBD;

	if (hostval != guestval) {
		unsigned long tif;

		tif = setguest ? ssbd_spec_ctrl_to_tif(guestval) :
				 ssbd_spec_ctrl_to_tif(hostval);

		speculative_store_bypass_update(tif);
	}
}
EXPORT_SYMBOL_GPL(x86_virt_spec_ctrl);

static void x86_amd_ssbd_enable(void)
{
	u64 msrval = x86_amd_ls_cfg_base | x86_amd_ls_cfg_ssbd_mask;

	if (boot_cpu_has(X86_FEATURE_VIRT_SSBD))
		wrmsrl(MSR_AMD64_VIRT_SPEC_CTRL, SPEC_CTRL_SSBD);
	else if (boot_cpu_has(X86_FEATURE_AMD_SSBD))
		wrmsrl(MSR_AMD64_LS_CFG, msrval);
}

/*
 * Attempt to fall back to another Spectre v2 mitigation (IBRS and IBPB).
 * Failing that, we keep retpoline enabled but the system will be
 * reported as vulnerable.
 */
void find_retpoline_alternative(void)
{
	if (!retpoline_enabled())
		return;

	if (allow_retpoline_fallback) {
		if (!cpu_ibrs_inuse_any()) {
			/* try to enable ibrs */
			if (ibrs_supported) {
				change_spectre_v2_mitigation(SPECTRE_V2_ENABLE_IBRS);
				pr_notice("Spectre v2 mitigation set to IBRS.\n");
				if (!ibpb_inuse && set_ibpb_inuse()) {
					pr_notice("Spectre v2 mitigation IBPB enabled.\n");
				}
			} else {
				pr_err("Could not enable IBRS.\n");
				pr_err("No Spectre v2 mitigation to fall back to.\n");
				refresh_set_spectre_v2_enabled();
			}
		}
	} else {
		pr_err("Cannot choose another Spectre v2 mitigation because retpoline_fallback is off.\n");
		refresh_set_spectre_v2_enabled();
	}
}

bool retpoline_enabled(void)
{
	return static_key_enabled(&retpoline_enabled_key);
}

void retpoline_enable(void)
{
	static_branch_enable(&retpoline_enabled_key);
	if (is_skylake_era()) {
		/*
		 * With retpoline, Skylake era CPUs should also fill RSB on any
		 * condition that might empty the RSB.
		 */
		rsb_stuff_enable();
	}
}

void retpoline_disable(void)
{
	if (is_skylake_era() && !static_key_enabled(&rsb_overwrite_key))
		rsb_stuff_disable();
	static_branch_disable(&retpoline_enabled_key);
}

static void retpoline_init(void)
{
	/*
	 * Set the retpoline capability to advertise that that retpoline
	 * is available, however the retpoline feature is enabled via
	 * the retpoline_enabled_key static key.
	 */
	setup_force_cpu_cap(X86_FEATURE_RETPOLINE);

	if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD) {
		if (boot_cpu_has(X86_FEATURE_LFENCE_RDTSC)) {
			setup_force_cpu_cap(X86_FEATURE_RETPOLINE_AMD);
			retpoline_mode = SPECTRE_V2_RETPOLINE_AMD;
			return;
		}
		pr_err("Spectre mitigation: LFENCE not serializing, setting up generic retpoline\n");
	}

	retpoline_mode = SPECTRE_V2_RETPOLINE_GENERIC;
}

static void __init retpoline_activate(enum spectre_v2_mitigation mode)
{
	retpoline_enable();
	/* IBRS is unnecessary with retpoline mitigation. */
	disable_ibrs_and_friends(false);
}

static void spec_ctrl_flush_all_cpus(u32 msr_nr, u64 val)
{
	int cpu;

	get_online_cpus();
	for_each_online_cpu(cpu)
		wrmsrl_on_cpu(cpu, msr_nr, val);
	put_online_cpus();
}

void change_spectre_v2_mitigation(enum spectre_v2_mitigation_action action)
{
	bool ibrs_requested, ibrs_fw_requested, retpoline_requested;
	bool ibrs_used, ibrs_fw_used, retpoline_used;
	int changes = 0;

	mutex_lock(&spec_ctrl_mutex);

	/*
	 * Define the current state.
	 *
	 * IBRS firmware is enabled if either basic IBRS or retpoline is
	 * enabled. If both IBRS and retpoline are disabled, then IBRS firmware
	 * is disabled too.
	 */

	ibrs_used = !ibrs_disabled;
	retpoline_used = !!retpoline_enabled();
	ibrs_fw_used = ((ibrs_used && !eibrs_supported) || retpoline_used);

	/*
	 * Define the requested state.
	 *
	 * Enabling IBRS will disable retpoline, and respectively enabling
	 * retpoline will disable IBRS. On the other hand, disabling a
	 * mitigation won't impact other mitigations.
	 *
	 */

	ibrs_requested = ibrs_used;
	retpoline_requested = retpoline_used;
	ibrs_fw_requested = ibrs_fw_used;

	switch (action) {

	case SPECTRE_V2_ENABLE_IBRS:
		ibrs_requested = true;
		ibrs_fw_requested = !eibrs_supported;
		retpoline_requested = false;
		break;

	case SPECTRE_V2_DISABLE_IBRS:
		ibrs_requested = false;
		ibrs_fw_requested = retpoline_used;
		retpoline_requested = retpoline_used;
		break;

	case SPECTRE_V2_ENABLE_RETPOLINE:
		ibrs_requested = false;
		ibrs_fw_requested = true;
		retpoline_requested = true;
		break;

	case SPECTRE_V2_DISABLE_RETPOLINE:
		ibrs_requested = ibrs_used;
		ibrs_fw_requested = ibrs_used && !eibrs_supported;
		retpoline_requested = false;
		break;
	}

	/* Switch to the requested mitigation state. */

	if (ibrs_requested != ibrs_used) {
		if (ibrs_requested) {
			clear_ibrs_disabled();
			/* If enhanced IBRS is available, turn it on now */
			if (eibrs_supported)
				spec_ctrl_flush_all_cpus(MSR_IA32_SPEC_CTRL,
					x86_spec_ctrl_priv);
			if (!boot_cpu_has(X86_FEATURE_SMEP)) {
				/* IBRS without SMEP needs RSB overwrite */
				rsb_overwrite_enable();
			}
		} else {
			set_ibrs_disabled();
			if (use_ibrs & SPEC_CTRL_IBRS_SUPPORTED) {
				rsb_overwrite_disable();
				spec_ctrl_flush_all_cpus(MSR_IA32_SPEC_CTRL,
							 x86_spec_ctrl_base);
			}
		}
		changes++;
	}

	if (retpoline_requested != retpoline_used) {
		if (retpoline_requested)
			retpoline_enable();
		else
			retpoline_disable();
		changes++;
	}

	if (ibrs_fw_requested != ibrs_fw_used) {
		if (ibrs_fw_requested)
			set_ibrs_firmware();
		else
			disable_ibrs_firmware();
		changes++;
	}

	if (changes > 0)
		refresh_set_spectre_v2_enabled();

	mutex_unlock(&spec_ctrl_mutex);
}

void refresh_set_spectre_v2_enabled(void)
{
	if (retpoline_enabled()) {
		/*
		 * If retpoline is enabled and a non-retpoline module has been
		 * loaded since the last reboot (tainting the kernel), then
		 * the retpoline mitigation is still active but a warning is
		 * shown in sysfs to indicate that the system is potentially
		 * vulnerable.
		 */
		spectre_v2_enabled = retpoline_mode;
	} else if (check_ibrs_inuse()) {
		spectre_v2_enabled = (check_basic_ibrs_inuse() ?
			SPECTRE_V2_IBRS : SPECTRE_V2_IBRS_ENHANCED);
	} else {
		spectre_v2_enabled = SPECTRE_V2_NONE;
	}
}

static void __init spec2_print_if_insecure(const char *reason)
{
	if (boot_cpu_has_bug(X86_BUG_SPECTRE_V2))
		pr_info("%s\n", reason);
}

static void __init spec2_print_if_secure(const char *reason)
{
	if (!boot_cpu_has_bug(X86_BUG_SPECTRE_V2))
		pr_info("%s\n", reason);
}

static inline bool match_option(const char *arg, int arglen, const char *opt)
{
	int len = strlen(opt);

	return len == arglen && !strncmp(arg, opt, len);
}

static enum spectre_v2_mitigation_cmd __init spectre_v2_parse_cmdline(void)
{
	char arg[20];
	int ret;

	if (cmdline_find_option_bool(boot_command_line, "noibrs")) {
		set_ibrs_disabled();
	}

	if (cmdline_find_option_bool(boot_command_line, "noibpb")) {
		set_ibpb_disabled();
	}

	ret = cmdline_find_option(boot_command_line, "spectre_v2", arg,
				  sizeof(arg));
	if (ret > 0)  {
		if (match_option(arg, ret, "off")) {
			goto disable;
		} else if (match_option(arg, ret, "on")) {
			spec2_print_if_secure("force enabled on command line.");
			return SPECTRE_V2_CMD_FORCE;
		} else if (match_option(arg, ret, "retpoline")) {
			spec2_print_if_insecure("retpoline selected on command line.");
			return SPECTRE_V2_CMD_RETPOLINE;
		} else if (match_option(arg, ret, "retpoline,amd")) {
			if (boot_cpu_data.x86_vendor != X86_VENDOR_AMD) {
				pr_err("retpoline,amd selected but CPU is not AMD. Switching to AUTO select\n");
				return SPECTRE_V2_CMD_AUTO;
			}
			spec2_print_if_insecure("AMD retpoline selected on command line.");
			return SPECTRE_V2_CMD_RETPOLINE_AMD;
		} else if (match_option(arg, ret, "retpoline,generic")) {
			spec2_print_if_insecure("generic retpoline selected on command line.");
			return SPECTRE_V2_CMD_RETPOLINE_GENERIC;
		} else if (match_option(arg, ret, "auto")) {
			return SPECTRE_V2_CMD_AUTO;
		} else if (match_option(arg, ret, "ibrs")) {
			return SPECTRE_V2_CMD_IBRS;
		}
	}

	if (!cmdline_find_option_bool(boot_command_line, "nospectre_v2") &&
	    !cpu_mitigations_off())
		return SPECTRE_V2_CMD_AUTO;
disable:
	spec2_print_if_insecure("disabled on command line.");
	return SPECTRE_V2_CMD_NONE;
}

static void ibrs_select(enum spectre_v2_mitigation *mode)
{
	/* Turn it on (if possible) */
	set_ibrs_inuse();
	if (!check_ibrs_inuse()) {
		pr_info("IBRS could not be enabled.\n");
		return;
	}
	/* Determine the specific IBRS variant in use */
	*mode = (check_basic_ibrs_inuse() ?
		SPECTRE_V2_IBRS : SPECTRE_V2_IBRS_ENHANCED);

	if (boot_cpu_has(X86_FEATURE_SMEP))
		return;

	/* IBRS without SMEP needs RSB overwrite */
	rsb_overwrite_enable();

	if (*mode == SPECTRE_V2_IBRS_ENHANCED)
		pr_warn("Enhanced IBRS might not provide full mitigation against Spectre v2 if SMEP is not available.\n");
}

static void __init select_ibrs_variant(enum spectre_v2_mitigation *mode)
{
	/* Attempt to start IBRS */
	ibrs_select(mode);

	if (*mode != SPECTRE_V2_NONE)
		/* Mode has been set to one of the IBRS variants */
		return;

	/* Could not enable IBRS, use retpoline mitigation if possible */
	if (IS_ENABLED(CONFIG_RETPOLINE)) {
		*mode = retpoline_mode;
		return;
	}

	pr_err("Spectre mitigation: IBRS could not be enabled; "
			"no mitigation available!");
}

static void disable_ibrs_and_friends(bool disable_ibpb)
{
	set_ibrs_disabled();
	if (use_ibrs & SPEC_CTRL_IBRS_SUPPORTED) {
		rsb_overwrite_disable();
		/* Disable IBRS on all cpus */
		spec_ctrl_flush_all_cpus(MSR_IA32_SPEC_CTRL,
			x86_spec_ctrl_base & ~SPEC_CTRL_FEATURE_ENABLE_IBRS);
	}

	/*
	 * We need to use IBPB with retpoline if it is available.
	 * Also IBRS for firmware paths.
	 */
	if (disable_ibpb) {
		set_ibpb_disabled();
		disable_ibrs_firmware();
	} else {
		set_ibrs_firmware();
	}
}

static bool retpoline_mode_selected(enum spectre_v2_mitigation mode)
{
	switch (mode) {
	case SPECTRE_V2_RETPOLINE_GENERIC:
	case SPECTRE_V2_RETPOLINE_AMD:
		return true;
	default:
		return false;
	}
	return false;
}

/*
 * Based on the cmd parsed from the kernel arguments and the capabilities of
 * the system, determine which spectre v2 mitigation will be employed and
 * return it.
 */
static enum spectre_v2_mitigation
select_auto_mitigation_mode(enum spectre_v2_mitigation_cmd cmd)
{
	enum spectre_v2_mitigation auto_mode = SPECTRE_V2_NONE;

	if (!boot_cpu_has_bug(X86_BUG_SPECTRE_V2) &&
		cmd == SPECTRE_V2_CMD_AUTO) {
		/* CPU is not affected, nothing to do */
		disable_ibrs_and_friends(true);
		return auto_mode;
	}

	pr_info("Options: %s%s%s\n",
		ibrs_supported ? (eibrs_supported ? "IBRS(enhanced) " : "IBRS(basic) ") : "",
		check_ibpb_inuse() ? "IBPB " : "",
		IS_ENABLED(CONFIG_RETPOLINE) ? "retpoline" : "");

	/*
	 * On AMD, if we have retpoline then favor it over IBRS.
	 * AMD plans to have a CPUID Function(8000_0008, EBX[18]=1)
	 * that indicates the processor prefers using IBRS over software
	 * mitigations such as retpoline. When that is available, this check
	 * should be adjusted accordingly.
	 */
	if ((IS_ENABLED(CONFIG_RETPOLINE)) &&
		(retpoline_mode == SPECTRE_V2_RETPOLINE_AMD)) {
		return retpoline_mode;
	}

	/*
	 * The default mitigation preference is:
	 * IBRS(enhanced) --> retpoline --> IBRS(basic)
	 * Except for Skylake cpus where we prefer basic IBRS over retpoline.
	 */
	if (eibrs_supported && !ibrs_disabled) {
		/*
		 * Enhanced IBRS supports an 'always on' model in which IBRS is
		 * enabled once and never disabled. Calling ibrs_select() now to
		 * set the correct mode and update the ibrs state variables.
		 */
		ibrs_select(&auto_mode);
		BUG_ON(auto_mode != SPECTRE_V2_IBRS_ENHANCED);
		return auto_mode;

	} else if (IS_ENABLED(CONFIG_RETPOLINE)) {
		/* On Skylake, basic IBRS is preferred over retpoline */
		if (ibrs_supported && !ibrs_disabled) {
			if (is_skylake_era() && use_ibrs_on_skylake) {
				/* Start the engine! */
				ibrs_select(&auto_mode);
				BUG_ON(auto_mode != SPECTRE_V2_IBRS);
				return auto_mode;
			}
		}
		/* retpoline mode has been initialized by retpoline_init() */
		return retpoline_mode;
	} else {
		/* If retpoline is not available, basic IBRS will do */
		ibrs_select(&auto_mode);
		if (auto_mode == SPECTRE_V2_IBRS)
			return auto_mode;

		pr_err("Spectre mitigation: IBRS could not be enabled; no mitigation available!");
		return SPECTRE_V2_NONE;
	}
}

/*
 * Activate the selected spectre v2 mitigation
 */
static void activate_spectre_v2_mitigation(enum spectre_v2_mitigation mode)
{
	spectre_v2_enabled = mode;
	pr_info("%s\n", spectre_v2_strings[spectre_v2_enabled]);

	if (spectre_v2_enabled == SPECTRE_V2_NONE)
		return;

	/* Activate the selected mitigation if necessary. */
	if (retpoline_mode_selected(spectre_v2_enabled)) {
		retpoline_activate(spectre_v2_enabled);
		if (is_skylake_era()) {
			/*
			 * Indicate that Skylake+ CPUs also enable RSB stuffing
			 * from the above call to retpoline_activate().
			 */
			pr_info("Spectre v2 mitigation: Filling RSB on underflow conditions\n");
		}
	} else if (spectre_v2_eibrs_enabled()) {
		/* If enhanced IBRS mode is selected, enable it in all cpus */
		spec_ctrl_flush_all_cpus(MSR_IA32_SPEC_CTRL,
			x86_spec_ctrl_base | SPEC_CTRL_FEATURE_ENABLE_IBRS);
	}

	/*
	 * Overwrite the RSB after a VM exit to ensure that guest behavior
	 * cannot control it. Only enhanced IBRS with SMEP can avoid this.
	 */
	if (!spectre_v2_eibrs_enabled() || !boot_cpu_has(X86_FEATURE_SMEP))
		setup_force_cpu_cap(X86_FEATURE_VMEXIT_RSB_FULL);

	/*
	 * If spectre v2 protection has been enabled, unconditionally fill
	 * RSB during a context switch; this protects against two independent
	 * issues:
	 *
	 *	- RSB underflow (and switch to BTB) on Skylake+
	 *	- SpectreRSB variant of spectre v2 on X86_BUG_SPECTRE_V2 CPUs
	 */
	setup_force_cpu_cap(X86_FEATURE_RSB_CTXSW);
	pr_info("Spectre v2 mitigation: Filling RSB on context switch\n");

	/* Initialize Indirect Branch Prediction Barrier if supported */
	if (boot_cpu_has(X86_FEATURE_IBPB) && ibpb_inuse)
		pr_info("Spectre v2 mitigation: Enabling Indirect Branch Prediction Barrier\n");

	/*
	 * Retpoline means the kernel is safe because it has no indirect
	 * branches. Enhanced IBRS protects firmware too, so, enable restricted
	 * speculation around firmware calls only when Enhanced IBRS isn't
	 * supported.
	 */
	if ((ibrs_firmware) && !spectre_v2_eibrs_enabled())
		pr_info("Enabling Restricted Speculation for firmware calls\n");
}

static void __init spectre_v2_select_mitigation(void)
{
	enum spectre_v2_mitigation_cmd cmd = spectre_v2_parse_cmdline();
	enum spectre_v2_mitigation mode = SPECTRE_V2_NONE;

	if (IS_ENABLED(CONFIG_RETPOLINE))
		retpoline_init();

	switch (cmd) {
	case SPECTRE_V2_CMD_NONE:
		disable_ibrs_and_friends(true);
		return;

	case SPECTRE_V2_CMD_FORCE:
	case SPECTRE_V2_CMD_AUTO:
		mode = select_auto_mitigation_mode(cmd);
		break;

	case SPECTRE_V2_CMD_RETPOLINE:
	case SPECTRE_V2_CMD_RETPOLINE_AMD:
	case SPECTRE_V2_CMD_RETPOLINE_GENERIC:
		/*
		 * These options are sanitized by spectre_v2_parse_cmdline().
		 * If they were received here, it means CONFIG_RETPOLINE is
		 * enabled, so there is no need to check again.
		 */
		mode = retpoline_mode;
		break;

	case SPECTRE_V2_CMD_IBRS:
		/*
		 * Determine which IBRS variant can be enabled. If IBRS is not
		 * available, select_ibrs_variant() will select retpoline as
		 * fallback.
		 */
		select_ibrs_variant(&mode);
		break;
	}

	activate_spectre_v2_mitigation(mode);
}

#undef pr_fmt

#define pr_fmt(fmt)	"Speculative Store Bypass: " fmt

/* The kernel command line selection */
enum ssb_mitigation_cmd {
	SPEC_STORE_BYPASS_CMD_NONE,
	SPEC_STORE_BYPASS_CMD_AUTO,
	SPEC_STORE_BYPASS_CMD_ON,
	SPEC_STORE_BYPASS_CMD_PRCTL,
	SPEC_STORE_BYPASS_CMD_SECCOMP,
	SPEC_STORE_BYPASS_CMD_USERSPACE /* Deprecated */
};

static const char *ssb_strings[] = {
	[SPEC_STORE_BYPASS_NONE]	= "Vulnerable",
	[SPEC_STORE_BYPASS_DISABLE]	= "Mitigation: Speculative Store Bypass disabled",
	[SPEC_STORE_BYPASS_PRCTL]	= "Mitigation: Speculative Store Bypass disabled via prctl",
	[SPEC_STORE_BYPASS_SECCOMP]	= "Mitigation: Speculative Store Bypass disabled via prctl and seccomp",
};

static const struct {
	const char *option;
	enum ssb_mitigation_cmd cmd;
} ssb_mitigation_options[] = {
	{ "auto",	SPEC_STORE_BYPASS_CMD_AUTO },    /* Platform decides */
	{ "on",		SPEC_STORE_BYPASS_CMD_ON },      /* Disable Speculative Store Bypass */
	{ "off",	SPEC_STORE_BYPASS_CMD_NONE },    /* Don't touch Speculative Store Bypass */
	{ "prctl",	SPEC_STORE_BYPASS_CMD_PRCTL },   /* Disable Speculative Store Bypass via prctl */
	{ "seccomp",	SPEC_STORE_BYPASS_CMD_SECCOMP }, /* Disable Speculative Store Bypass via prctl and seccomp */
	{ "userspace",	SPEC_STORE_BYPASS_CMD_USERSPACE }, /* Disable Speculative Store Bypass for userspace (deprecated) */
};

static enum ssb_mitigation_cmd __init ssb_parse_cmdline(void)
{
	enum ssb_mitigation_cmd cmd = SPEC_STORE_BYPASS_CMD_AUTO;
	char arg[20];
	int ret, i;

	if (cmdline_find_option_bool(boot_command_line, "nospec_store_bypass_disable") ||
	    cpu_mitigations_off()) {
		return SPEC_STORE_BYPASS_CMD_NONE;
	} else {
		ret = cmdline_find_option(boot_command_line, "spec_store_bypass_disable",
					  arg, sizeof(arg));
		if (ret < 0)
			return SPEC_STORE_BYPASS_CMD_AUTO;

		for (i = 0; i < ARRAY_SIZE(ssb_mitigation_options); i++) {
			if (!match_option(arg, ret, ssb_mitigation_options[i].option))
				continue;

			cmd = ssb_mitigation_options[i].cmd;
			break;
		}

		if (i >= ARRAY_SIZE(ssb_mitigation_options)) {
			pr_err("unknown option (%s). Switching to AUTO select\n", arg);
			return SPEC_STORE_BYPASS_CMD_AUTO;
		}
	}

	return cmd;
}

static enum ssb_mitigation __init ssb_select_mitigation(void)
{
	enum ssb_mitigation mode = SPEC_STORE_BYPASS_NONE;
	enum ssb_mitigation_cmd cmd;

	if (!boot_cpu_has(X86_FEATURE_SSBD))
		return mode;

	cmd = ssb_parse_cmdline();
	if (!boot_cpu_has_bug(X86_BUG_SPEC_STORE_BYPASS) &&
	    (cmd == SPEC_STORE_BYPASS_CMD_NONE ||
	     cmd == SPEC_STORE_BYPASS_CMD_AUTO))
		return mode;

	switch (cmd) {
	case SPEC_STORE_BYPASS_CMD_AUTO:
	case SPEC_STORE_BYPASS_CMD_SECCOMP:
		/*
		 * Choose prctl+seccomp as the default mode if seccomp is
		 * enabled.
		 */
		if (IS_ENABLED(CONFIG_SECCOMP))
			mode = SPEC_STORE_BYPASS_SECCOMP;
		else
			mode = SPEC_STORE_BYPASS_PRCTL;
		break;
	case SPEC_STORE_BYPASS_CMD_ON:
		mode = SPEC_STORE_BYPASS_DISABLE;
		break;
	case SPEC_STORE_BYPASS_CMD_PRCTL:
		mode = SPEC_STORE_BYPASS_PRCTL;
		break;
	case SPEC_STORE_BYPASS_CMD_USERSPACE:
		pr_warn("spec_store_bypass_disable=userspace is deprecated. "
			"Disabling Speculative Store Bypass\n");
		if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
			mode = SPEC_STORE_BYPASS_DISABLE;
		break;
	case SPEC_STORE_BYPASS_CMD_NONE:
		break;
	}

       return mode;
}

static void __init ssb_init(void)
{
	/*
	 * We have three CPU feature flags that are in play here:
	 *  - X86_BUG_SPEC_STORE_BYPASS - CPU is susceptible.
	 *  - X86_FEATURE_SSBD - CPU is able to turn off speculative store bypass
	 *  - X86_FEATURE_SPEC_STORE_BYPASS_DISABLE - engage the mitigation
	 */

	/*
	 * If SSBD is controlled by the SPEC_CTRL MSR, then set the proper
	 * bit in the mask to allow guests to use the mitigation even in the
	 * case where the host does not.
	 */
	if (boot_cpu_has(X86_FEATURE_SSBD) ||
	    boot_cpu_has(X86_FEATURE_AMD_SSBD)) {
		x86_spec_ctrl_mask |= SPEC_CTRL_SSBD;
	}

	if (ssb_mode == SPEC_STORE_BYPASS_DISABLE)
		setup_force_cpu_cap(X86_FEATURE_SPEC_STORE_BYPASS_DISABLE);

	if (ssb_mode == SPEC_STORE_BYPASS_DISABLE) {
		/*
		 * Intel uses the SPEC CTRL MSR Bit(2) for this, while AMD uses
		 * a completely different MSR and bit dependent on family.
		 */
		switch (boot_cpu_data.x86_vendor) {
		case X86_VENDOR_INTEL:
			x86_spec_ctrl_base |= SPEC_CTRL_SSBD;
			x86_spec_ctrl_priv |= SPEC_CTRL_SSBD;

			x86_spec_ctrl_set(SPEC_CTRL_INITIAL);

			update_cpu_spec_ctrl_all();
			break;
		case X86_VENDOR_AMD:
			if (ssb_mode == SPEC_STORE_BYPASS_DISABLE)
				x86_amd_ssbd_enable();
			break;
		}
	}
	if (boot_cpu_has_bug(X86_BUG_SPEC_STORE_BYPASS))
		pr_info("%s\n", ssb_strings[ssb_mode]);
}

#undef pr_fmt
#define pr_fmt(fmt)	"Speculation prctl: " fmt

static int ssb_prctl_set(struct task_struct *task, unsigned long ctrl)
{
	bool update;

	if (ssb_mode != SPEC_STORE_BYPASS_PRCTL &&
	    ssb_mode != SPEC_STORE_BYPASS_SECCOMP)
		return -ENXIO;

	switch (ctrl) {
	case PR_SPEC_ENABLE:
		/* If speculation is force disabled, enable is not allowed */
		if (task_spec_ssb_force_disable(task))
			return -EPERM;
		task_clear_spec_ssb_disable(task);
		update = test_and_clear_tsk_thread_flag(task, TIF_SSBD);
		break;
	case PR_SPEC_DISABLE:
		task_set_spec_ssb_disable(task);
		update = !test_and_set_tsk_thread_flag(task, TIF_SSBD);
		break;
	case PR_SPEC_FORCE_DISABLE:
		task_set_spec_ssb_disable(task);
		task_set_spec_ssb_force_disable(task);
		update = !test_and_set_tsk_thread_flag(task, TIF_SSBD);
		break;
	default:
		return -ERANGE;
	}
	/*
	 * If being set on non-current task, delay setting the CPU
	 * mitigation until it is next scheduled.
	 */
	if (task == current && update)
		speculative_store_bypass_update_current();

	return 0;
}

int arch_prctl_spec_ctrl_set(struct task_struct *task, unsigned long which,
			     unsigned long ctrl)
{
	switch (which) {
	case PR_SPEC_STORE_BYPASS:
		return ssb_prctl_set(task, ctrl);
	default:
		return -ENODEV;
	}
}

#ifdef CONFIG_SECCOMP
void arch_seccomp_spec_mitigate(struct task_struct *task)
{
	if (ssb_mode == SPEC_STORE_BYPASS_SECCOMP)
		ssb_prctl_set(task, PR_SPEC_FORCE_DISABLE);
}
#endif

static int ssb_prctl_get(struct task_struct *task)
{
	switch (ssb_mode) {
	case SPEC_STORE_BYPASS_DISABLE:
		return PR_SPEC_DISABLE;
	case SPEC_STORE_BYPASS_SECCOMP:
	case SPEC_STORE_BYPASS_PRCTL:
		if (task_spec_ssb_force_disable(task))
			return PR_SPEC_PRCTL | PR_SPEC_FORCE_DISABLE;
		if (task_spec_ssb_disable(task))
			return PR_SPEC_PRCTL | PR_SPEC_DISABLE;
		return PR_SPEC_PRCTL | PR_SPEC_ENABLE;
	default:
		if (boot_cpu_has_bug(X86_BUG_SPEC_STORE_BYPASS))
			return PR_SPEC_ENABLE;
		return PR_SPEC_NOT_AFFECTED;
	}
}

int arch_prctl_spec_ctrl_get(struct task_struct *task, unsigned long which)
{
	switch (which) {
	case PR_SPEC_STORE_BYPASS:
		return ssb_prctl_get(task);
	default:
		return -ENODEV;
	}
}

void x86_spec_ctrl_setup_ap(void)
{
	if (boot_cpu_has(X86_FEATURE_IBRS))
		x86_spec_ctrl_set(SPEC_CTRL_INITIAL);

	if (ssb_mode == SPEC_STORE_BYPASS_DISABLE)
		x86_amd_ssbd_enable();
}

#undef pr_fmt
#define pr_fmt(fmt)	"L1TF: " fmt

/* Default mitigation for L1TF-affected CPUs */
enum l1tf_mitigations l1tf_mitigation __read_mostly = L1TF_MITIGATION_FLUSH;
#if IS_ENABLED(CONFIG_KVM_INTEL)
EXPORT_SYMBOL_GPL(l1tf_mitigation);
#endif
enum vmx_l1d_flush_state l1tf_vmx_mitigation = VMENTER_L1D_FLUSH_AUTO;
EXPORT_SYMBOL_GPL(l1tf_vmx_mitigation);

static void __init parse_l1tf_cmdline(void)
{
	char arg[12];
	int ret;

	ret = cmdline_find_option(boot_command_line, "l1tf", arg,
				  sizeof(arg));
	if (ret <= 0)
		return;

	if (match_option(arg, ret, "off"))
		l1tf_mitigation = L1TF_MITIGATION_OFF;
	else if (match_option(arg, ret, "flush,nowarn"))
		l1tf_mitigation = L1TF_MITIGATION_FLUSH_NOWARN;
	else if (match_option(arg, ret, "flush"))
		l1tf_mitigation = L1TF_MITIGATION_FLUSH;
	else if (match_option(arg, ret, "flush,nosmt"))
		l1tf_mitigation = L1TF_MITIGATION_FLUSH_NOSMT;
	else if (match_option(arg, ret, "full"))
		l1tf_mitigation = L1TF_MITIGATION_FULL;
	else if (match_option(arg, ret, "full,force"))
		l1tf_mitigation = L1TF_MITIGATION_FULL_FORCE;
	else
		pr_warn("l1tf: unknown option %s\n", arg);
}

/*
 * These CPUs all support 44bits physical address space internally in the
 * cache but CPUID can report a smaller number of physical address bits.
 *
 * The L1TF mitigation uses the top most address bit for the inversion of
 * non present PTEs. When the installed memory reaches into the top most
 * address bit due to memory holes, which has been observed on machines
 * which report 36bits physical address bits and have 32G RAM installed,
 * then the mitigation range check in l1tf_select_mitigation() triggers.
 * This is a false positive because the mitigation is still possible due to
 * the fact that the cache uses 44bit internally. Use the cache bits
 * instead of the reported physical bits and adjust them on the affected
 * machines to 44bit if the reported bits are less than 44.
 */
static void override_cache_bits(struct cpuinfo_x86 *c)
{
	if (c->x86 != 6)
		return;

	switch (c->x86_model) {
	case INTEL_FAM6_NEHALEM:
	case INTEL_FAM6_WESTMERE:
	case INTEL_FAM6_SANDYBRIDGE:
	case INTEL_FAM6_IVYBRIDGE:
	case INTEL_FAM6_HASWELL_CORE:
	case INTEL_FAM6_HASWELL_ULT:
	case INTEL_FAM6_HASWELL_GT3E:
	case INTEL_FAM6_BROADWELL_CORE:
	case INTEL_FAM6_BROADWELL_GT3E:
	case INTEL_FAM6_SKYLAKE_MOBILE:
	case INTEL_FAM6_SKYLAKE_DESKTOP:
	case INTEL_FAM6_KABYLAKE_MOBILE:
	case INTEL_FAM6_KABYLAKE_DESKTOP:
		if (c->x86_cache_bits < 44)
			c->x86_cache_bits = 44;
		break;
	}
}

static void __init l1tf_select_mitigation(void)
{
	u64 half_pa;

	if (!boot_cpu_has_bug(X86_BUG_L1TF))
		return;

	if (cpu_mitigations_off())
		l1tf_mitigation = L1TF_MITIGATION_OFF;
	else if (cpu_mitigations_auto_nosmt())
		l1tf_mitigation = L1TF_MITIGATION_FLUSH_NOSMT;

	parse_l1tf_cmdline();

	override_cache_bits(&boot_cpu_data);

	switch (l1tf_mitigation) {
	case L1TF_MITIGATION_OFF:
	case L1TF_MITIGATION_FLUSH_NOWARN:
	case L1TF_MITIGATION_FLUSH:
		break;
	case L1TF_MITIGATION_FLUSH_NOSMT:
	case L1TF_MITIGATION_FULL:
		cpu_smt_disable(false);
		break;
	case L1TF_MITIGATION_FULL_FORCE:
		cpu_smt_disable(true);
		break;
	}

#if CONFIG_PGTABLE_LEVELS == 2
	pr_warn("Kernel not compiled for PAE. No mitigation for L1TF\n");
	return;
#endif

	half_pa = (u64)l1tf_pfn_limit() << PAGE_SHIFT;
	if (e820_any_mapped(half_pa, ULLONG_MAX - half_pa, E820_RAM)) {
		pr_warn("System has more than MAX_PA/2 memory. L1TF mitigation not effective.\n");
		pr_info("You may make it effective by booting the kernel with mem=%llu parameter.\n",
				half_pa);
		pr_info("However, doing so will make a part of your RAM unusable.\n");
		pr_info("Reading https://www.kernel.org/doc/html/latest/admin-guide/l1tf.html might help you decide.\n");
		return;
	}

	setup_force_cpu_cap(X86_FEATURE_L1TF_PTEINV);
}
/* Default mitigation for MDS-affected CPUs */
static enum mds_mitigations mds_mitigation __read_mostly = MDS_MITIGATION_FULL;
static bool mds_nosmt = false;

static const char * const mds_strings[] = {
	[MDS_MITIGATION_OFF]    = "Vulnerable",
	[MDS_MITIGATION_FULL]   = "Mitigation: Clear CPU buffers",
	[MDS_MITIGATION_IDLE]   = "Mitigation: Clear CPU buffers during idle only",
	[MDS_MITIGATION_VMWERV] = "Vulnerable: Clear CPU buffers attempted, no microcode",
};

#undef pr_fmt
#define pr_fmt(fmt)	"MDS: " fmt

bool mds_user_clear_enabled(void)
{
        return static_key_enabled(&mds_user_clear);
}

void mds_user_clear_enable(void)
{
	static_branch_enable(&mds_user_clear);

	mds_mitigation = MDS_MITIGATION_FULL;
	if (!boot_cpu_has(X86_FEATURE_MD_CLEAR))
		mds_mitigation = MDS_MITIGATION_VMWERV;

}

void mds_user_clear_disable(void)
{
	static_branch_disable(&mds_user_clear);

	if (static_key_enabled(&mds_idle_clear))
		mds_mitigation = MDS_MITIGATION_IDLE;
	else
		mds_mitigation = MDS_MITIGATION_OFF;

}

bool mds_idle_clear_enabled(void)
{
        return static_key_enabled(&mds_idle_clear);
}

void mds_idle_clear_enable(void)
{
	static_branch_enable(&mds_idle_clear);

	if (!static_key_enabled(&mds_user_clear)) {
		mds_mitigation = MDS_MITIGATION_IDLE;
	}
}

void mds_idle_clear_disable(void)
{
	static_branch_disable(&mds_idle_clear);

	if (!static_key_enabled(&mds_user_clear))
		mds_mitigation = MDS_MITIGATION_OFF;
}

static void update_mds_branch_idle(void)
{
	/*
	 * Enable the idle clearing on CPUs which are affected only by
	 * MDBDS and not any other MDS variant. The other variants cannot
	 * be mitigated when SMT is enabled, so unless explicitly requested
	 * clearing the buffers on idle would be a window dressing exercise.
	 */
	if (!boot_cpu_has(X86_BUG_MSBDS_ONLY) &&
	    !boot_cpu_has_bug(X86_BUG_TAA) &&
	     mds_mitigation != MDS_MITIGATION_IDLE)
		return;

	if (cpu_smt_control == CPU_SMT_ENABLED)
		static_branch_enable(&mds_idle_clear);
	else
		static_branch_disable(&mds_idle_clear);
}

#define MDS_MSG_SMT "MDS CPU bug present and SMT on, data leak possible. See https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/mds.html for more details.\n"

static void mds_select_mitigation(void)
{
	char arg[12];
	int ret;

	if (!boot_cpu_has_bug(X86_BUG_MDS) || cpu_mitigations_off()) {
		mds_mitigation = MDS_MITIGATION_OFF;
		return;
	}

	if (!boot_cpu_has(X86_FEATURE_MD_CLEAR)) {
		mds_mitigation = MDS_MITIGATION_VMWERV;
		return;
	}

        ret = cmdline_find_option(boot_command_line, "mds", arg,
                                  sizeof(arg));
        if (ret > 0) {
	        if (match_option(arg, ret, "off"))
			mds_mitigation = MDS_MITIGATION_OFF;
		else if (match_option(arg, ret, "idle"))
			mds_mitigation = MDS_MITIGATION_IDLE;
		else if (match_option(arg, ret, "full,nosmt"))
			mds_nosmt = true;
	        else if (!match_option(arg, ret, "full"))
			pr_warn("mds: unknown option %s\n", arg);
	}

	if (mds_mitigation == MDS_MITIGATION_FULL) {

		static_branch_enable(&mds_user_clear);
		
		if (!boot_cpu_has(X86_BUG_MSBDS_ONLY) &&
		   (mds_nosmt || cpu_mitigations_auto_nosmt()))
			cpu_smt_disable(false);

		if (cpu_smt_control == CPU_SMT_ENABLED &&
		    !boot_cpu_has(X86_BUG_MSBDS_ONLY))
			pr_warn_once(MDS_MSG_SMT);

		update_mds_branch_idle();
	} else if (mds_mitigation == MDS_MITIGATION_IDLE)
		update_mds_branch_idle();
	pr_info("%s\n", mds_strings[mds_mitigation]);
}

bool itlb_multihit_kvm_mitigation;
EXPORT_SYMBOL_GPL(itlb_multihit_kvm_mitigation);

#undef pr_fmt
#define pr_fmt(fmt)	"TAA: " fmt

/* Default mitigation for TAA-affected CPUs */
static enum taa_mitigations taa_mitigation __read_mostly = TAA_MITIGATION_VERW;
static bool taa_nosmt;

static const char * const taa_strings[] = {
	[TAA_MITIGATION_OFF]		= "Vulnerable",
	[TAA_MITIGATION_UCODE_NEEDED]	= "Vulnerable: Clear CPU buffers attempted, no microcode",
	[TAA_MITIGATION_VERW]		= "Mitigation: Clear CPU buffers",
	[TAA_MITIGATION_IDLE]		= "Mitigation: Clear CPU buffers during idle only",
	[TAA_MITIGATION_TSX_DISABLED]	= "Mitigation: TSX disabled",
};

static void taa_select_mitigation(void)
{
	u64 ia32_cap;
	char arg[12];
	int ret;

	if (!boot_cpu_has_bug(X86_BUG_TAA)) {
		taa_mitigation = TAA_MITIGATION_OFF;
		return;
	}

	if (!boot_cpu_has(X86_FEATURE_RTM)) {
		taa_mitigation = TAA_MITIGATION_TSX_DISABLED;
		goto out;
	}

	/* All mitigations turned off from cmdline (mitigations=off) */
	if (cpu_mitigations_off()) {
		taa_mitigation = TAA_MITIGATION_OFF;
		return;
	}

       ret = cmdline_find_option(boot_command_line, "tsx", arg,
                                 sizeof(arg));

        if (ret > 0) {
	        if (match_option(arg, ret, "off"))
			taa_mitigation = TAA_MITIGATION_OFF;
		else if (match_option(arg, ret, "full"))
			taa_mitigation = TAA_MITIGATION_VERW;
		else if (match_option(arg, ret, "idle")) 
			taa_mitigation = TAA_MITIGATION_IDLE;
		else if (match_option(arg, ret, "full,nosmt")) {
			taa_mitigation = TAA_MITIGATION_VERW;
			taa_nosmt = true;
	        } else
			pr_warn("tsx: unknown option %s\n", arg);
	}

	/* TAA mitigation is turned off from cmdline (tsx_async_abort=off) */
	if (taa_mitigation == TAA_MITIGATION_OFF) {
		goto out;
	}

	ia32_cap = x86_read_arch_cap_msr(&cpu_data(smp_processor_id()));

	if (boot_cpu_has(X86_FEATURE_MD_CLEAR))
		if ( !(ia32_cap & ARCH_CAP_MDS_NO)) {
			switch (mds_mitigation) {
			case MDS_MITIGATION_FULL:
				taa_mitigation = TAA_MITIGATION_VERW;
				break;
			case MDS_MITIGATION_IDLE:
				taa_mitigation = TAA_MITIGATION_IDLE;
				break;
			case MDS_MITIGATION_OFF:
				taa_mitigation = TAA_MITIGATION_OFF;
				goto out;
			}; 
		}
	else
		taa_mitigation = TAA_MITIGATION_UCODE_NEEDED;

	/*
	 * VERW doesn't clear the CPU buffers when MD_CLEAR=1 and MDS_NO=1.
	 * A microcode update fixes this behavior to clear CPU buffers.
	 * Microcode update also adds support for MSR_IA32_TSX_CTRL which
	 * is enumerated by ARCH_CAP_TSX_CTRL_MSR bit.
	 *
	 * On MDS_NO=1 CPUs if ARCH_CAP_TSX_CTRL_MSR is not set, microcode
	 * update is required.
	 */
	if ((ia32_cap & ARCH_CAP_MDS_NO) &&
	   !(ia32_cap & ARCH_CAP_TSX_CTRL_MSR))
		taa_mitigation = TAA_MITIGATION_UCODE_NEEDED;

	/*
	 * TSX is enabled, select alternate mitigation for TAA which is
	 * same as MDS. 
	 *
	 * For guests that can't determine whether the correct microcode is
	 * present on host, enable the mitigation for UCODE_NEEDED as well.
	 * MDS would have already done that.
	 */

	if (taa_mitigation == TAA_MITIGATION_IDLE) 
		static_branch_enable(&mds_idle_clear);
	else
		static_branch_enable(&mds_user_clear);

	if (taa_nosmt || cpu_mitigations_auto_nosmt())
		cpu_smt_disable(false);

out:
	pr_info("%s\n", taa_strings[taa_mitigation]);
}

#define TAA_MSG_SMT "TAA CPU bug present and SMT on, data leak possible. See https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/tsx_async_abort.html for more details.\n"

#undef pr_fmt
#define pr_fmt(fmt) fmt

#ifdef CONFIG_SYSFS

#define L1TF_DEFAULT_MSG "Mitigation: PTE Inversion"

#if IS_ENABLED(CONFIG_KVM_INTEL)
static const char *l1tf_vmx_states[] = {
	[VMENTER_L1D_FLUSH_AUTO]		= "auto",
	[VMENTER_L1D_FLUSH_NEVER]		= "vulnerable",
	[VMENTER_L1D_FLUSH_COND]		= "conditional cache flushes",
	[VMENTER_L1D_FLUSH_ALWAYS]		= "cache flushes",
	[VMENTER_L1D_FLUSH_EPT_DISABLED]	= "EPT disabled",
	[VMENTER_L1D_FLUSH_NOT_REQUIRED]	= "flush not necessary"
};

static ssize_t l1tf_show_state(char *buf)
{
	if (l1tf_vmx_mitigation == VMENTER_L1D_FLUSH_AUTO)
		return sprintf(buf, "%s\n", L1TF_DEFAULT_MSG);

	if (l1tf_vmx_mitigation == VMENTER_L1D_FLUSH_EPT_DISABLED ||
	    (l1tf_vmx_mitigation == VMENTER_L1D_FLUSH_NEVER &&
	     cpu_smt_control == CPU_SMT_ENABLED))
		return sprintf(buf, "%s; VMX: %s\n", L1TF_DEFAULT_MSG,
			       l1tf_vmx_states[l1tf_vmx_mitigation]);

	return sprintf(buf, "%s; VMX: %s, SMT %s\n", L1TF_DEFAULT_MSG,
		       l1tf_vmx_states[l1tf_vmx_mitigation],
		       cpu_smt_control == CPU_SMT_ENABLED ? "vulnerable" : "disabled");
}

static ssize_t itlb_multihit_show_state(char *buf)
{
	if (itlb_multihit_kvm_mitigation)
		return sprintf(buf, "KVM: Mitigation: Split huge pages\n");
	else
		return sprintf(buf, "KVM: Vulnerable\n");
}


static ssize_t mds_show_state(char *buf)
{
	if (cpu_has_hypervisor) {
		return sprintf(buf, "%s; SMT Host state unknown\n",
			       mds_strings[mds_mitigation]);
	}

	if (boot_cpu_has(X86_BUG_MSBDS_ONLY)) {
		return sprintf(buf, "%s; SMT %s\n", mds_strings[mds_mitigation],
			       (mds_mitigation == MDS_MITIGATION_OFF ? "vulnerable" :
			        (cpu_smt_control == CPU_SMT_ENABLED ? "mitigated" : "disabled")));
	}

	return sprintf(buf, "%s; SMT %s\n", mds_strings[mds_mitigation],
		(cpu_smt_control == CPU_SMT_ENABLED) ? "vulnerable" : "disabled");
}

static ssize_t tsx_async_abort_show_state(char *buf)
{
	if ((taa_mitigation == TAA_MITIGATION_TSX_DISABLED) ||
	    (taa_mitigation == TAA_MITIGATION_OFF))
			return sprintf(buf, "%s\n", taa_strings[taa_mitigation]);

	if (boot_cpu_has(X86_FEATURE_HYPERVISOR)) {
		return sprintf(buf, "%s; SMT Host state unknown\n",
			       taa_strings[taa_mitigation]);
	}

	return sprintf(buf, "%s; SMT %s\n", taa_strings[taa_mitigation],
		       (cpu_smt_control == CPU_SMT_ENABLED) ? "vulnerable" : "disabled");
}

#else

static ssize_t l1tf_show_state(char *buf)
{
	return sprintf(buf, "%s\n", L1TF_DEFAULT_MSG);
}

static ssize_t itlb_multihit_show_state(char *buf)
{
	return sprintf(buf, "Processor vulnerable\n");
}

#endif


/*
 * This function replicates at runtime what check_bugs would do at init time.
 * As we will be using default mitigations everywhere, essentially we have
 * dropped the logic of parsing boot_command_line which either was not
 * possible.
 */
void microcode_late_select_mitigation(void)
{
	enum spectre_v2_mitigation mode;
	bool microcode_added_ssbd  = false;
	/*
	 * In late loading we will use default mitigation which is
	 * secomp or prctl. We will do this ONLY if these bits were
	 * not present at init time and were added by microcode late
	 * loading.
	 */
	if (cpu_has(&cpu_data(smp_processor_id()), X86_FEATURE_SSBD) &&
	    !static_cpu_has(X86_FEATURE_SSBD)) {
		setup_force_cpu_cap(X86_FEATURE_SSBD);
		microcode_added_ssbd = true;
	}
	if (cpu_has(&cpu_data(smp_processor_id()), X86_FEATURE_AMD_SSBD) &&
	    !static_cpu_has(X86_FEATURE_AMD_SSBD)) {
		setup_force_cpu_cap(X86_FEATURE_AMD_SSBD);
		microcode_added_ssbd = true;
	}

	if (boot_cpu_has_bug(X86_BUG_SPEC_STORE_BYPASS)) {
		if (microcode_added_ssbd) {
			if (IS_ENABLED(CONFIG_SECCOMP))
				ssb_mode = SPEC_STORE_BYPASS_SECCOMP;
			else
				ssb_mode = SPEC_STORE_BYPASS_PRCTL;
			x86_spec_ctrl_mask |= SPEC_CTRL_SSBD;
		}
#undef pr_fmt
#define pr_fmt(fmt)	"Speculative Store Bypass late loading: " fmt
		pr_info("%s\n", ssb_strings[ssb_mode]);

	} else {
		ssb_mode = SPEC_STORE_BYPASS_NONE;
	}

	/*
	 * Select SpectreV2 mitigation and enable it. First we clear the
	 * ibrs_disabled flag in order to be able to pick it up for Skylake.
	 * Also we re-check SpectreV2 if we did not support IBRS at boot time.
	 * If so we do not do anything to not break command line user preference.
	 */
	if (!microcode_had_ibrs) {
		clear_ibrs_disabled();
		mode = select_auto_mitigation_mode(SPECTRE_V2_CMD_AUTO);
		activate_spectre_v2_mitigation(mode);

		/*
		 * Mark microcode_had_ibrs so at the second
		 * update we won't trigger this check again.
		 */
		if (boot_cpu_has(X86_FEATURE_IBRS))
			microcode_had_ibrs = true;
	}

#undef pr_fmt
#define pr_fmt(fmt)	"MDS late loading: " fmt
	/*
	 * If the CPU does not have the X86_BUG_MDS bug means that the microcode
	 * solved this issue and we just turn off mds_mitigation.
	 * If the CPU has X86_BUG_MDS bug, we check to see if the microcode has
	 * added X86_FEATURE_MD_CLEAR.
	 */
	if (boot_cpu_has_bug(X86_BUG_MDS)) {
		/*
		 * If mds_mitigation is off, it means that the user selected
		 * this using cmdline option and we do not do anything.
		 */
		if (mds_mitigation == MDS_MITIGATION_OFF)
			goto out_bug_mds;

		/*
		 * If mds_mitigation is idle, it means that the user selected
		 * this using cmdline option and we just update_mds_branch_idle.
		 */
		if (mds_mitigation == MDS_MITIGATION_IDLE) {
			update_mds_branch_idle();
			goto out_bug_mds;
		}

		/*
		 * If we have MDS_MITIGATION_VMWERV, jump back to
		 * MDS_MITIGATION_FULL and re-assess.
		 */
		if (mds_mitigation == MDS_MITIGATION_VMWERV)
			mds_mitigation = MDS_MITIGATION_FULL;

		if (cpu_has(&cpu_data(smp_processor_id()), X86_FEATURE_MD_CLEAR) &&
		    !static_cpu_has(X86_FEATURE_MD_CLEAR)) {
			setup_force_cpu_cap(X86_FEATURE_MD_CLEAR);
		}

		if (!boot_cpu_has(X86_FEATURE_MD_CLEAR))
			mds_mitigation = MDS_MITIGATION_VMWERV;

		static_branch_enable(&mds_user_clear);

		update_mds_branch_idle();

out_bug_mds:
		pr_info("%s\n", mds_strings[mds_mitigation]);
	} else if (mds_mitigation != MDS_MITIGATION_OFF) {
		mds_mitigation = MDS_MITIGATION_OFF;
		static_branch_disable(&mds_user_clear);
		static_branch_disable(&mds_idle_clear);

		pr_info("Not affected\n");
	}
}

static ssize_t cpu_show_common(struct device *dev, struct device_attribute *attr,
			      char *buf, unsigned int bug)
{
	if (!boot_cpu_has_bug(bug))
		return sprintf(buf, "Not affected\n");

	switch (bug) {
	case X86_BUG_CPU_MELTDOWN:
		if (boot_cpu_has(X86_FEATURE_PTI))
			return sprintf(buf, "Mitigation: PTI\n");

		if (xen_pv_domain())
			return sprintf(buf, "Unknown (XEN PV detected, hypervisor mitigation required)\n");

		break;

	case X86_BUG_SPECTRE_V1:
		/* At the moment, a single hard-wired mitigation */
		return sprintf(buf, "%s\n", spectre_v1_strings[spectre_v1_mitigation]);

	case X86_BUG_SPECTRE_V2:
		return sprintf(buf, "%s%s%s%s\n",
		    spectre_v2_strings[spectre_v2_enabled],
		    (test_taint(TAINT_NO_RETPOLINE) &&
		    retpoline_mode_selected(spectre_v2_enabled) ?
		    " (non-retpoline module(s) has been loaded)" : ""),
		    ibrs_firmware ? ", IBRS_FW" : "",
		    ibpb_inuse ? ", IBPB" : "");

	case X86_BUG_SPEC_STORE_BYPASS:
		return sprintf(buf, "%s\n", ssb_strings[ssb_mode]);

	case X86_BUG_L1TF:
		if (boot_cpu_has(X86_FEATURE_L1TF_PTEINV))
			return l1tf_show_state(buf);
		break;

	case X86_BUG_MDS:
		return mds_show_state(buf);
		break;

	case X86_BUG_ITLB_MULTIHIT:
		return itlb_multihit_show_state(buf);

	case X86_BUG_TAA:
		return tsx_async_abort_show_state(buf);

	default:
		break;
	}

	return sprintf(buf, "Vulnerable\n");
}

ssize_t cpu_show_meltdown(struct device *dev,
			  struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_CPU_MELTDOWN);
}

ssize_t cpu_show_spectre_v1(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_SPECTRE_V1);

}

ssize_t cpu_show_spectre_v2(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_SPECTRE_V2);
}

ssize_t cpu_show_spec_store_bypass(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_SPEC_STORE_BYPASS);
}

ssize_t cpu_show_l1tf(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_L1TF);
}

ssize_t cpu_show_mds(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_MDS);
}

ssize_t cpu_show_tsx_async_abort(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_TAA);
}

ssize_t cpu_show_itlb_multihit(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_ITLB_MULTIHIT);
}
#endif
