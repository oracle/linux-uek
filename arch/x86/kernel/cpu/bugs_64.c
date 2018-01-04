/*
 *  Copyright (C) 1994  Linus Torvalds
 *  Copyright (C) 2000  SuSE
 */

#include <linux/kernel.h>
#include <linux/init.h>
#ifdef CONFIG_SYSFS
#include <linux/device.h>
#endif
#include <asm/alternative.h>
#include <asm/nospec-branch.h>
#include <asm/cmdline.h>
#include <asm/bugs.h>
#include <asm/processor.h>
#include <asm/mtrr.h>
#include <asm/cacheflush.h>
#include <asm/spec_ctrl.h>
#include <asm/cmdline.h>
#include <asm/intel-family.h>

/*
 * use IBRS
 * bit 0 = indicate if ibrs is currently in use
 * bit 1 = indicate if system supports ibrs
 * bit 2 = indicate if admin disables ibrs
 */
int use_ibrs;
EXPORT_SYMBOL(use_ibrs);

/*
 * use IBRS
 * bit 0 = indicate if ibpb is currently in use
 * bit 1 = indicate if system supports ibpb
 * bit 2 = indicate if admin disables ibpb
 */
int use_ibpb;
EXPORT_SYMBOL(use_ibpb);

/* mutex to serialize IBRS & IBPB control changes */
DEFINE_MUTEX(spec_ctrl_mutex);
EXPORT_SYMBOL(spec_ctrl_mutex);

static void __init spectre_v2_select_mitigation(void);

void __init check_bugs(void)
{
	identify_boot_cpu();
#if !defined(CONFIG_SMP)
	printk(KERN_INFO "CPU: ");
	print_cpu_info(&boot_cpu_data);
#endif

	/* Select the proper spectre mitigation before patching alternatives */
	spectre_v2_select_mitigation();

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
	[SPECTRE_V2_IBRS_LFENCE]		= "Mitigation: lfence",

};

#undef pr_fmt
#define pr_fmt(fmt)     "Spectre V2 mitigation: " fmt

static enum spectre_v2_mitigation spectre_v2_enabled = SPECTRE_V2_NONE;

/* A module has been loaded. Disable reporting that we're good. */
void disable_retpoline(void)
{
	spectre_v2_enabled = SPECTRE_V2_NONE;
	pr_err("system may be vulnerable to spectre\n");
}

bool retpoline_enabled(void)
{
	return spectre_v2_enabled != SPECTRE_V2_NONE;
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

	if (cmdline_find_option_bool(boot_command_line, "nolfence")) {
		set_lfence_disabled();
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

static enum spectre_v2_mitigation __init ibrs_select(void)
{
	enum spectre_v2_mitigation mode = SPECTRE_V2_NONE;

	/* If it is ON, OK, lets use it.*/
	if (check_ibrs_inuse())
		mode = SPECTRE_V2_IBRS;
	else {
		/*
		 * If that didn't work (say no microcode or noibrs), we end up using
		 * lfence on system calls/exceptions/parameters.
		 */
		if (lfence_inuse)
			mode = SPECTRE_V2_IBRS_LFENCE;
	}

	if (mode == SPECTRE_V2_NONE)
		/* Well, fallback on automatic discovery. */
		pr_info("IBRS and lfence could not be enabled.\n");
	else {
		/* OK, some form of IBRS is enabled, lets see if we need to STUFF_RSB */
		if (!boot_cpu_has(X86_FEATURE_SMEP))
			setup_force_cpu_cap(X86_FEATURE_STUFF_RSB);
	}
	return mode;
}

static void __init disable_ibrs_and_friends(void)
{
	set_ibrs_disabled();
	set_ibpb_disabled();
	set_lfence_disabled();
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
		disable_ibrs_and_friends();
		return;
	}

	switch (cmd) {
	case SPECTRE_V2_CMD_NONE:
		disable_ibrs_and_friends();
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
		mode = ibrs_select();
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

		/* IBRS available. Lets see if we are compiled with retpoline. */
		if (check_ibrs_inuse() && !retp_compiler()) {
			mode = SPECTRE_V2_IBRS;
			/* OK, some form of IBRS is enabled, lets see if we need to STUFF_RSB */
			if (!boot_cpu_has(X86_FEATURE_SMEP))
				setup_force_cpu_cap(X86_FEATURE_STUFF_RSB);
			goto display;
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
	if ((!boot_cpu_has(X86_FEATURE_PTI) &&
	     !boot_cpu_has(X86_FEATURE_SMEP)) || is_skylake_era()) {
		setup_force_cpu_cap(X86_FEATURE_RSB_CTXSW);
		pr_info("Filling RSB on context switch\n");
	}

	/* IBRS is unnecessary with retpoline mitigation. */
	if (mode == SPECTRE_V2_RETPOLINE_GENERIC ||
	    mode == SPECTRE_V2_RETPOLINE_AMD) {
		disable_ibrs_and_friends();
	}
}

#undef pr_fmt

#ifdef CONFIG_SYSFS
ssize_t cpu_show_meltdown(struct device *dev,
			  struct device_attribute *attr, char *buf)
{
	if (!boot_cpu_has_bug(X86_BUG_CPU_MELTDOWN))
		return sprintf(buf, "Not affected\n");
	if (boot_cpu_has(X86_FEATURE_PTI))
		return sprintf(buf, "Mitigation: PTI\n");
	return sprintf(buf, "Vulnerable\n");
}

ssize_t cpu_show_spectre_v1(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	if (!boot_cpu_has_bug(X86_BUG_SPECTRE_V1))
		return sprintf(buf, "Not affected\n");
	/* At the moment, a single hard-wired mitigation */
	return sprintf(buf, "Mitigation: lfence\n");
}

ssize_t cpu_show_spectre_v2(struct device *dev,
			    struct device_attribute *attr, char *buf)
{
	if (!boot_cpu_has_bug(X86_BUG_SPECTRE_V2))
		return sprintf(buf, "Not affected\n");

	return sprintf(buf, "%s%s%s\n", spectre_v2_strings[spectre_v2_enabled],
					ibrs_inuse ? "" /* As spectre_v2_strings has it. */ :
						lfence_inuse ? " lfence " : "",
					ibpb_inuse ? ", IBPB" : "");
}
#endif
