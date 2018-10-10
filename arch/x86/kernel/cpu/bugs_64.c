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

/*
 * use_ibrs flags:
 * SPEC_CTRL_IBRS_INUSE			indicate if ibrs is currently in use
 * SPEC_CTRL_IBRS_SUPPORTED		indicate if system supports ibrs
 * SPEC_CTRL_IBRS_ADMIN_DISABLED	indicate if admin disables ibrs
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

/*
 * retpoline_fallback flags:
 * SPEC_CTRL_USE_RETPOLINE_FALLBACK	pick retpoline fallback mitigation
 */
int retpoline_fallback = SPEC_CTRL_USE_RETPOLINE_FALLBACK;
EXPORT_SYMBOL(retpoline_fallback);


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

static void __init spectre_v2_select_mitigation(void);
static void __init ssb_select_mitigation(void);
static bool ssbd_ibrs_selected(void);
static void __init l1tf_select_mitigation(void);

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

/*
 * AMD specific MSR info for Speculative Store Bypass control.
 * x86_amd_ls_cfg_ssbd_mask is initialized in identify_boot_cpu().
 */
u64 x86_amd_ls_cfg_base;
u64 x86_amd_ls_cfg_ssbd_mask;

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
		if (x86_spec_ctrl_base & SPEC_CTRL_IBRS) {
			pr_warn("SPEC CTRL MSR (0x%16llx) has IBRS set during boot, clearing it.", x86_spec_ctrl_base);
			x86_spec_ctrl_base &= ~(SPEC_CTRL_IBRS);
		}
		x86_spec_ctrl_priv = x86_spec_ctrl_base;
		update_cpu_spec_ctrl_all();
	}

	/* Allow STIBP in MSR_SPEC_CTRL if supported */
	if (boot_cpu_has(X86_FEATURE_STIBP))
		x86_spec_ctrl_mask |= SPEC_CTRL_STIBP;

	/* Select the proper spectre mitigation before patching alternatives */
	spectre_v2_select_mitigation();

	/*
	 * Select proper mitigation for any exposure to the Speculative Store
	 * Bypass vulnerability.
	 */
	ssb_select_mitigation();

	l1tf_select_mitigation();

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
static bool __init is_skylake_era(void)
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
	[SPECTRE_V2_RETPOLINE_MINIMAL]		= "Vulnerable: Minimal generic ASM retpoline",
	[SPECTRE_V2_RETPOLINE_MINIMAL_AMD]	= "Vulnerable: Minimal AMD ASM retpoline",
	[SPECTRE_V2_RETPOLINE_GENERIC]		= "Mitigation: Full generic retpoline",
	[SPECTRE_V2_RETPOLINE_AMD]		= "Mitigation: Full AMD retpoline",
	[SPECTRE_V2_IBRS]			= "Mitigation: IBRS",

};

#undef pr_fmt
#define pr_fmt(fmt)     "Spectre V2 : " fmt

static enum spectre_v2_mitigation spectre_v2_enabled = SPECTRE_V2_NONE;

void x86_spec_ctrl_set(u64 val)
{
	u64 host;

	if (val & ~x86_spec_ctrl_mask)
		WARN_ONCE(1, "SPEC_CTRL MSR value 0x%16llx is unknown.\n", val);
	else {
		/*
		 * Only two states are allowed - with IBRS or without.
		 */
		if (ssbd_ibrs_selected()) {
			if (val & SPEC_CTRL_IBRS)
				host = this_cpu_read(x86_spec_ctrl_priv_cpu);
			else
				host = val & ~(SPEC_CTRL_SSBD);
		} else {
			if (ibrs_inuse && (val & SPEC_CTRL_IBRS))
				host = this_cpu_read(x86_spec_ctrl_priv_cpu);
			else
				host = x86_spec_ctrl_base;
			host |= val;
		}
		wrmsrl(MSR_IA32_SPEC_CTRL, host);
	}
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
		if (ibrs_inuse)
			/*
			 * Except on IBRS we don't want to use host base value
			 * but rather the privilege value which has IBRS set.
			 */
			hostval = this_cpu_read(x86_spec_ctrl_priv);

		guestval = hostval & ~x86_spec_ctrl_mask;
		guestval |= guest_spec_ctrl & x86_spec_ctrl_mask;

		if (ibrs_inuse) {
			/* You may wonder why we don't just jump to the
			 * 'if (hostval ! guestval)' conditional to save an MSR.
			 * (by say the guest MSR value is IBRS and hostval being
			 * that too) - the reason is that on some platforms the
			 * SPEC_CTRL MSR is like a reset button, not latched.
			 */
			msrval = setguest ? guestval : hostval;
			wrmsrl(MSR_IA32_SPEC_CTRL, msrval);
			return;
		}

		/* SSBD controlled in MSR_SPEC_CTRL */
		if (static_cpu_has(X86_FEATURE_SSBD))
			hostval |= ssbd_tif_to_spec_ctrl(ti->flags);

		if (hostval != guestval) {
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
 * Disable retpoline and attempt to fall back to another Spectre v2 mitigation.
 * If possible, fall back to IBRS and IBPB.
 * Failing that, indicate that we have no Spectre v2 mitigation.
 *
 * Checks that spec_ctrl_mutex is held.
 */
void disable_retpoline(void)
{
	BUG_ON(!mutex_is_locked(&spec_ctrl_mutex));

	if (!retpoline_only_enabled())
		return;

	if (allow_retpoline_fallback) {
		if (!ibrs_inuse) {
			/* try to enable ibrs */
			if (set_ibrs_inuse()) {
				pr_err("Spectre v2 mitigation set to IBRS and retpoline.\n");
				if (!ibpb_inuse && set_ibpb_inuse()) {
					pr_err("Spectre v2 mitigation IBPB enabled.\n");
				}
			} else {
				pr_err("Could not enable IBRS.\n");
				pr_err("No Spectre v2 mitigation to fall back to.\n");
				spectre_v2_enabled = SPECTRE_V2_NONE;
			}
		}
	} else {
		pr_err("Cannot choose another Spectre v2 mitigation because retpoline_fallback is off.\n");
		spectre_v2_enabled = SPECTRE_V2_NONE;
	}

	if (spectre_v2_enabled == SPECTRE_V2_NONE)
		pr_err("system may be vulnerable to spectre\n");
}

static bool retpoline_enabled(void)
{
	switch (spectre_v2_enabled) {
	case SPECTRE_V2_RETPOLINE_MINIMAL:
	case SPECTRE_V2_RETPOLINE_MINIMAL_AMD:
	case SPECTRE_V2_RETPOLINE_GENERIC:
	case SPECTRE_V2_RETPOLINE_AMD:
		return true;
	default:
		break;
	}

	return false;
}

bool retpoline_only_enabled(void)
{
	return (retpoline_enabled() && !ibrs_inuse);
}

int refresh_set_spectre_v2_enabled(void)
{
	if (retpoline_enabled())
		return false;

	if (check_ibrs_inuse())
		spectre_v2_enabled = SPECTRE_V2_IBRS;
	else {
		spectre_v2_enabled = SPECTRE_V2_NONE;
	}

	return true;
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

static inline bool retp_compiler(void)
{
	return __is_defined(RETPOLINE);
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

	if (!cmdline_find_option_bool(boot_command_line, "nospectre_v2"))
		return SPECTRE_V2_CMD_AUTO;
disable:
	spec2_print_if_insecure("disabled on command line.");
	return SPECTRE_V2_CMD_NONE;
}

static void __init ibrs_select(enum spectre_v2_mitigation *mode)
{
	/* Turn it on (if possible) */
	if (set_ibrs_inuse()) {
		*mode = SPECTRE_V2_IBRS;
		if (!boot_cpu_has(X86_FEATURE_SMEP))
			setup_force_cpu_cap(X86_FEATURE_STUFF_RSB);
	} else
		pr_info("IBRS could not be enabled.\n");
}

static void __init disable_ibrs_and_friends(bool disable)
{
	if (use_ibrs & SPEC_CTRL_IBRS_SUPPORTED) {
		unsigned int cpu;

		get_online_cpus();
		for_each_online_cpu(cpu)
			wrmsrl_on_cpu(cpu, MSR_IA32_SPEC_CTRL,
				      x86_spec_ctrl_base & ~SPEC_CTRL_FEATURE_ENABLE_IBRS);

		put_online_cpus();
	}

	if (disable) {
		set_ibrs_disabled();
		set_ibpb_disabled();
		disable_ibrs_firmware();
	} else {
		/*
		 * Clear in-use instead of disabling so that IBRS can be
		 * set back in use later by disable_retpoline().
		 */
		clear_ibrs_inuse();
		/*
		 * We need to use IBPB with retpoline if it is available.
		 * Also IBRS for firmware paths.
		 */
		set_ibrs_firmware();
	}
}

static bool __init retpoline_selected(enum spectre_v2_mitigation_cmd cmd)
{
	switch (cmd) {
	case SPECTRE_V2_CMD_RETPOLINE_AMD:
	case SPECTRE_V2_CMD_RETPOLINE_GENERIC:
	case SPECTRE_V2_CMD_RETPOLINE:
		return true;
	default:
		return false;
		break;
	}
	return false;
}

static void __init spectre_v2_select_mitigation(void)
{
	enum spectre_v2_mitigation_cmd cmd = spectre_v2_parse_cmdline();
	enum spectre_v2_mitigation mode = SPECTRE_V2_NONE;

	/*
	 * If the CPU is not affected and the command line mode is NONE or AUTO
	 * then nothing to do.
	 */
	if (!boot_cpu_has_bug(X86_BUG_SPECTRE_V2) &&
	    (cmd == SPECTRE_V2_CMD_NONE || cmd == SPECTRE_V2_CMD_AUTO)) {
		disable_ibrs_and_friends(true);
		return;
	}

	switch (cmd) {
	case SPECTRE_V2_CMD_NONE:
		disable_ibrs_and_friends(true);
		return;

	case SPECTRE_V2_CMD_FORCE:
		/* FALLTRHU */
	case SPECTRE_V2_CMD_AUTO:
		goto retpoline_auto;

	case SPECTRE_V2_CMD_RETPOLINE_AMD:
		if (IS_ENABLED(CONFIG_RETPOLINE))
			goto retpoline_amd;
		break;
	case SPECTRE_V2_CMD_RETPOLINE_GENERIC:
		if (IS_ENABLED(CONFIG_RETPOLINE))
			goto retpoline_generic;
		break;
	case SPECTRE_V2_CMD_RETPOLINE:
		if (IS_ENABLED(CONFIG_RETPOLINE))
			goto retpoline_auto;
		break;
	case SPECTRE_V2_CMD_IBRS:
		ibrs_select(&mode);
		if (mode == SPECTRE_V2_NONE)
			goto retpoline_auto;

		goto display;
		break; /* Not needed but compilers may complain otherwise. */
	}
	pr_err("kernel not compiled with retpoline; retpoline mitigation not available");
	goto out;

retpoline_auto:
	if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD) {
	retpoline_amd:
		if (!boot_cpu_has(X86_FEATURE_LFENCE_RDTSC)) {
			pr_err("LFENCE not serializing. Switching to generic retpoline\n");
			goto retpoline_generic;
		}
		mode = retp_compiler() ? SPECTRE_V2_RETPOLINE_AMD :
					 SPECTRE_V2_RETPOLINE_MINIMAL_AMD;
		/* On AMD we do not need IBRS, so lets use the ASM mitigation. */
		setup_force_cpu_cap(X86_FEATURE_RETPOLINE_AMD);
		setup_force_cpu_cap(X86_FEATURE_RETPOLINE);
	} else {
	retpoline_generic:
		mode = retp_compiler() ? SPECTRE_V2_RETPOLINE_GENERIC :
					 SPECTRE_V2_RETPOLINE_MINIMAL;

		pr_info("Options: %s%s%s\n",
			ibrs_supported ? "IBRS " : "",
			check_ibpb_inuse() ? "IBPB " : "",
			retp_compiler() ? "retpoline" : "");

		/* IBRS available. Lets see if we are compiled with retpoline. */
		if (ibrs_supported) {
			/*
			 * If we are on Skylake, use IBRS (if available). But if we
			 * are forced to use retpoline on Skylake then use that.
			 */
			if (!retp_compiler() /* prefer IBRS over minimal ASM */ ||
			    (retp_compiler() && !retpoline_selected(cmd) &&
			     ((is_skylake_era() && use_ibrs_on_skylake) ||
			      (ssbd_ibrs_selected() && use_ibrs_with_ssbd)))) {

				/* Start the engine! */
				ibrs_select(&mode);
				if (mode == SPECTRE_V2_IBRS)
					goto display;
				/* But if we can't, then just use retpoline */
			}
		}
		setup_force_cpu_cap(X86_FEATURE_RETPOLINE);
	}
display:
	spectre_v2_enabled = mode;
	pr_info("%s\n", spectre_v2_strings[mode]);

out:
	/*
	 * If neither SMEP or KPTI are available, there is a risk of
	 * hitting userspace addresses in the RSB after a context switch
	 * from a shallow call stack to a deeper one. To prevent this fill
	 * the entire RSB, even when using IBRS.
	 *
	 * Skylake era CPUs have a separate issue with *underflow* of the
	 * RSB, when they will predict 'ret' targets from the generic BTB.
	 * The proper mitigation for this is IBRS. If IBRS is not supported
	 * or deactivated in favour of retpolines the RSB fill on context
	 * switch is required.
	 */
	if (((mode != SPECTRE_V2_IBRS) && (mode != SPECTRE_V2_IBRS_LFENCE)) &&
	    ((!boot_cpu_has(X86_FEATURE_PTI) &&
	     !boot_cpu_has(X86_FEATURE_SMEP)) || is_skylake_era())) {
		setup_force_cpu_cap(X86_FEATURE_RSB_CTXSW);
		pr_info("Filling RSB on context switch\n");
	}

	/* IBRS is unnecessary with retpoline mitigation. */
	if (mode == SPECTRE_V2_RETPOLINE_GENERIC ||
	    mode == SPECTRE_V2_RETPOLINE_AMD) {
		disable_ibrs_and_friends(false /* set not-in-use */);
	}
	/* Future CPUs with IBRS_ALL might be able to avoid this. */
	setup_force_cpu_cap(X86_FEATURE_VMEXIT_RSB_FULL);

	/* Initialize Indirect Branch Prediction Barrier if supported */
	if (boot_cpu_has(X86_FEATURE_IBPB) && ibpb_inuse)
		pr_info("Enabling Indirect Branch Prediction Barrier\n");

	if (ibrs_firmware)
		pr_info("Enabling Restricted Speculation for firmware calls\n");
}

#undef pr_fmt

#define pr_fmt(fmt)	"Speculative Store Bypass: " fmt

static enum ssb_mitigation ssb_mode = SPEC_STORE_BYPASS_NONE;

bool ssbd_ibrs_selected(void)
{
	return (ssb_mode == SPEC_STORE_BYPASS_USERSPACE);
}

/* The kernel command line selection */
enum ssb_mitigation_cmd {
	SPEC_STORE_BYPASS_CMD_NONE,
	SPEC_STORE_BYPASS_CMD_AUTO,
	SPEC_STORE_BYPASS_CMD_ON,
	SPEC_STORE_BYPASS_CMD_PRCTL,
	SPEC_STORE_BYPASS_CMD_SECCOMP,
	SPEC_STORE_BYPASS_CMD_USERSPACE,
};

static const char *ssb_strings[] = {
	[SPEC_STORE_BYPASS_NONE]	= "Vulnerable",
	[SPEC_STORE_BYPASS_DISABLE]	= "Mitigation: Speculative Store Bypass disabled",
	[SPEC_STORE_BYPASS_PRCTL]	= "Mitigation: Speculative Store Bypass disabled via prctl",
	[SPEC_STORE_BYPASS_SECCOMP]	= "Mitigation: Speculative Store Bypass disabled via prctl and seccomp",
	[SPEC_STORE_BYPASS_USERSPACE]	= "Mitigation: Speculative Store Bypass disabled for userspace"
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
	{ "userspace",	SPEC_STORE_BYPASS_CMD_USERSPACE }, /* Disable Speculative Store Bypass for userspace */
};

static enum ssb_mitigation_cmd __init ssb_parse_cmdline(void)
{
	enum ssb_mitigation_cmd cmd = SPEC_STORE_BYPASS_CMD_AUTO;
	char arg[20];
	int ret, i;

	if (cmdline_find_option_bool(boot_command_line, "nospec_store_bypass_disable")) {
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

static enum ssb_mitigation __init __ssb_select_mitigation(void)
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
		if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
			mode = SPEC_STORE_BYPASS_USERSPACE;
		break;
	case SPEC_STORE_BYPASS_CMD_NONE:
		break;
	}

	/*
	 * We have three CPU feature flags that are in play here:
	 *  - X86_BUG_SPEC_STORE_BYPASS - CPU is susceptible.
	 *  - X86_FEATURE_SSBD - CPU is able to turn off speculative store bypass
	 *  - X86_FEATURE_SPEC_STORE_BYPASS_DISABLE - engage the mitigation
	 */
	if (mode != SPEC_STORE_BYPASS_DISABLE)
		setup_force_cpu_cap(X86_FEATURE_SPEC_STORE_BYPASS_DISABLE);

	if (mode == SPEC_STORE_BYPASS_DISABLE ||
	    mode == SPEC_STORE_BYPASS_USERSPACE) {
		/*
		 * Intel uses the SPEC CTRL MSR Bit(2) for this, while AMD uses
		 * a completely different MSR and bit dependent on family.
		 */
		switch (boot_cpu_data.x86_vendor) {
		case X86_VENDOR_INTEL:
			x86_spec_ctrl_base |= SPEC_CTRL_SSBD;
			x86_spec_ctrl_mask |= SPEC_CTRL_SSBD;

			if (mode == SPEC_STORE_BYPASS_DISABLE) {
				x86_spec_ctrl_set(SPEC_CTRL_SSBD);
				if (spectre_v2_enabled == SPECTRE_V2_IBRS) {
					x86_spec_ctrl_priv |= SPEC_CTRL_SSBD;
				}
			}
			else
				x86_spec_ctrl_priv &= ~(SPEC_CTRL_SSBD);

			update_cpu_spec_ctrl_all();
			break;
		case X86_VENDOR_AMD:
			if (mode == SPEC_STORE_BYPASS_DISABLE)
				x86_amd_ssbd_enable();
			break;
		}
	}
	return mode;
}

static void ssb_select_mitigation(void)
{
	ssb_mode = __ssb_select_mitigation();

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
	case SPEC_STORE_BYPASS_USERSPACE:
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
	if (boot_cpu_has(X86_FEATURE_IBRS) && ssb_mode != SPEC_STORE_BYPASS_USERSPACE)
		x86_spec_ctrl_set(x86_spec_ctrl_base & x86_spec_ctrl_mask);

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

#undef pr_fmt

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
#else
static ssize_t l1tf_show_state(char *buf)
{
	return sprintf(buf, "%s\n", L1TF_DEFAULT_MSG);
}
#endif

static ssize_t cpu_show_common(struct device *dev, struct device_attribute *attr,
			      char *buf, unsigned int bug)
{
	if (!boot_cpu_has_bug(bug))
		return sprintf(buf, "Not affected\n");

	switch (bug) {
	case X86_BUG_CPU_MELTDOWN:
		if (boot_cpu_has(X86_FEATURE_PTI))
			return sprintf(buf, "Mitigation: PTI\n");

		if (x86_hyper == &x86_hyper_xen)
			return sprintf(buf, "Unknown (XEN PV detected, hypervisor mitigation required)\n");

		break;

	case X86_BUG_SPECTRE_V1:
		/* At the moment, a single hard-wired mitigation */
		return sprintf(buf, "Mitigation: lfence\n");

	case X86_BUG_SPECTRE_V2:
		return sprintf(buf, "%s%s%s%s\n", spectre_v2_strings[spectre_v2_enabled],
			       (check_ibrs_inuse() && retpoline_enabled()) ? ", IBRS" : "",
			       ibrs_firmware ? ", IBRS_FW" : "",
			       ibpb_inuse ? ", IBPB" : "");

	case X86_BUG_SPEC_STORE_BYPASS:
		return sprintf(buf, "%s\n", ssb_strings[ssb_mode]);

	case X86_BUG_L1TF:
		if (boot_cpu_has(X86_FEATURE_L1TF_PTEINV))
			return l1tf_show_state(buf);
		break;

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
#endif
