// SPDX-License-Identifier: GPL-2.0
/*
 *  Copyright (C) 1994  Linus Torvalds
 *
 *  Cyrix stuff, June 1998 by:
 *	- Rafael R. Reilova (moved everything from head.S),
 *        <rreilova@ececs.uc.edu>
 *	- Channing Corn (tests & fixes),
 *	- Andrew D. Balsa (code cleanup).
 */
#include <linux/init.h>
#include <linux/utsname.h>
#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/nospec.h>
#include <linux/prctl.h>

#include <asm/spec-ctrl.h>
#include <asm/cmdline.h>
#include <asm/bugs.h>
#include <asm/processor.h>
#include <asm/processor-flags.h>
#include <asm/fpu/internal.h>
#include <asm/msr.h>
#include <asm/paravirt.h>
#include <asm/alternative.h>
#include <asm/pgtable.h>
#include <asm/set_memory.h>
#include <asm/intel-family.h>
#include <asm/spec_ctrl.h>

/*
 * use_ibrs flags:
 * SPEC_CTRL_IBRS_INUSE			indicate if ibrs is currently in use
 * SPEC_CTRL_IBRS_SUPPORTED		indicate if system supports ibrs
 * SPEC_CTRL_IBRS_ADMIN_DISABLED	indicate if admin disables ibrs
 */
unsigned int use_ibrs;
EXPORT_SYMBOL(use_ibrs);

/*
 * use_ibpb flags:
 * SPEC_CTRL_IBPB_INUSE			indicate if ibpb is currently in use
 * SPEC_CTRL_IBPB_SUPPORTED		indicate if system supports ibpb
 * SPEC_CTRL_IBPB_ADMIN_DISABLED	indicate if admin disables ibpb
 */
unsigned int use_ibpb;
EXPORT_SYMBOL(use_ibpb);

/* mutex to serialize IBRS & IBPB control changes */
DEFINE_MUTEX(spec_ctrl_mutex);
EXPORT_SYMBOL(spec_ctrl_mutex);

bool use_ibrs_on_skylake = true;
EXPORT_SYMBOL(use_ibrs_on_skylake);


int __init spectre_v2_heuristics_setup(char *p)
{
	ssize_t len;

	while (*p) {
		/* Disable all heuristics. */
		if (!strncmp(p, "off", 3)) {
			use_ibrs_on_skylake = false;
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

/*
 * Our boot-time value of the SPEC_CTRL MSR. We read it once so that any
 * writes to SPEC_CTRL contain whatever reserved bits have been set.
 */
u64 __ro_after_init x86_spec_ctrl_base;
EXPORT_SYMBOL_GPL(x86_spec_ctrl_base);

/*
 * Our knob on entering the kernel to enable and disable IBRS.
 * Inherits value from x86_spec_ctrl_base.
 */
u64 x86_spec_ctrl_priv;
EXPORT_SYMBOL_GPL(x86_spec_ctrl_priv);

/*
 * The vendor and possibly platform specific bits which can be modified in
 * x86_spec_ctrl_base.
 */
static u64 __ro_after_init x86_spec_ctrl_mask = ~SPEC_CTRL_IBRS;

/*
 * AMD specific MSR info for Speculative Store Bypass control.
 * x86_amd_ls_cfg_rds_mask is initialized in identify_boot_cpu().
 */
u64 __ro_after_init x86_amd_ls_cfg_base;
u64 __ro_after_init x86_amd_ls_cfg_rds_mask;

void __init check_bugs(void)
{
	identify_boot_cpu();

	if (!IS_ENABLED(CONFIG_SMP)) {
		pr_info("CPU: ");
		print_cpu_info(&boot_cpu_data);
	}

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
	}
	/* Select the proper spectre mitigation before patching alternatives */
	spectre_v2_select_mitigation();

	/*
	 * Select proper mitigation for any exposure to the Speculative Store
	 * Bypass vulnerability.
	 */
	ssb_select_mitigation();

#ifdef CONFIG_X86_32
	/*
	 * Check whether we are able to run this kernel safely on SMP.
	 *
	 * - i386 is no longer supported.
	 * - In order to run on anything without a TSC, we need to be
	 *   compiled for a i486.
	 */
	if (boot_cpu_data.x86 < 4)
		panic("Kernel requires i486+ for 'invlpg' and other features");

	init_utsname()->machine[1] =
		'0' + (boot_cpu_data.x86 > 6 ? 6 : boot_cpu_data.x86);
	alternative_instructions();

	fpu__init_check_bugs();
#else /* CONFIG_X86_64 */
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
#endif
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

	if (val & x86_spec_ctrl_mask)
		WARN_ONCE(1, "SPEC_CTRL MSR value 0x%16llx is unknown.\n", val);
	else {
		/*
		 * Only two states are allowed - with IBRS or without.
		 */
		if (check_ibrs_inuse()) {
			if (val & SPEC_CTRL_IBRS)
				host = x86_spec_ctrl_priv;
			else
				host = val;
		} else
			host = x86_spec_ctrl_base | val;

		wrmsrl(MSR_IA32_SPEC_CTRL, host);
	}
}
EXPORT_SYMBOL_GPL(x86_spec_ctrl_set);

u64 x86_spec_ctrl_get_default(void)
{
	u64 msrval = x86_spec_ctrl_base;

	if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
		msrval |= rds_tif_to_spec_ctrl(current_thread_info()->flags);
	return msrval;
}
EXPORT_SYMBOL_GPL(x86_spec_ctrl_get_default);

void x86_spec_ctrl_set_guest(u64 guest_spec_ctrl)
{
	u64 host = x86_spec_ctrl_base;

	if (!ibrs_supported)
		return;

	if (ibrs_inuse) {
		wrmsrl(MSR_IA32_SPEC_CTRL, guest_spec_ctrl);
		return;
	}

	if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
		host |= rds_tif_to_spec_ctrl(current_thread_info()->flags);

	if (host != guest_spec_ctrl)
		wrmsrl(MSR_IA32_SPEC_CTRL, guest_spec_ctrl);
}
EXPORT_SYMBOL_GPL(x86_spec_ctrl_set_guest);

void x86_spec_ctrl_restore_host(u64 guest_spec_ctrl)
{
	u64 host = x86_spec_ctrl_base;

	if (!ibrs_supported)
		return;

	if (ibrs_inuse) {
		wrmsrl(MSR_IA32_SPEC_CTRL, x86_spec_ctrl_priv);
		return;
	}

	if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL)
		host |= rds_tif_to_spec_ctrl(current_thread_info()->flags);

	if (host != guest_spec_ctrl)
		wrmsrl(MSR_IA32_SPEC_CTRL, host);
}
EXPORT_SYMBOL_GPL(x86_spec_ctrl_restore_host);

static void x86_amd_rds_enable(void)
{
	u64 msrval = x86_amd_ls_cfg_base | x86_amd_ls_cfg_rds_mask;

	if (boot_cpu_has(X86_FEATURE_AMD_RDS))
		wrmsrl(MSR_AMD64_LS_CFG, msrval);
}

#ifdef RETPOLINE
static bool spectre_v2_bad_module;

bool retpoline_module_ok(bool has_retpoline)
{
	if (spectre_v2_enabled == SPECTRE_V2_NONE || has_retpoline)
		return true;

	pr_err("System may be vulnerable to spectre v2\n");
	spectre_v2_bad_module = true;
	return false;
}

static inline const char *spectre_v2_module_string(void)
{
	return spectre_v2_bad_module ? " - vulnerable module loaded" : "";
}
#else
static inline const char *spectre_v2_module_string(void) { return ""; }
#endif

bool retpoline_enabled(void)
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

int refresh_set_spectre_v2_enabled(void)
{
	if (retpoline_enabled())
		return false;

	if (check_ibrs_inuse())
		spectre_v2_enabled = SPECTRE_V2_IBRS;
	else
		spectre_v2_enabled = SPECTRE_V2_NONE;

	return true;
}

static void __init spec2_print_if_insecure(const char *reason)
{
	if (boot_cpu_has_bug(X86_BUG_SPECTRE_V2))
		pr_info("%s selected on command line.\n", reason);
}

static void __init spec2_print_if_secure(const char *reason)
{
	if (!boot_cpu_has_bug(X86_BUG_SPECTRE_V2))
		pr_info("%s selected on command line.\n", reason);
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

static const struct {
	const char *option;
	enum spectre_v2_mitigation_cmd cmd;
	bool secure;
} mitigation_options[] = {
	{ "off",               SPECTRE_V2_CMD_NONE,              false },
	{ "on",                SPECTRE_V2_CMD_FORCE,             true },
	{ "retpoline",         SPECTRE_V2_CMD_RETPOLINE,         false },
	{ "retpoline,amd",     SPECTRE_V2_CMD_RETPOLINE_AMD,     false },
	{ "retpoline,generic", SPECTRE_V2_CMD_RETPOLINE_GENERIC, false },
	{ "auto",              SPECTRE_V2_CMD_AUTO,              false },
	{ "ibrs",              SPECTRE_V2_CMD_IBRS,              false },
};

static enum spectre_v2_mitigation_cmd __init spectre_v2_parse_cmdline(void)
{
	char arg[20];
	int ret, i;
	enum spectre_v2_mitigation_cmd cmd = SPECTRE_V2_CMD_AUTO;

	if (cmdline_find_option_bool(boot_command_line, "noibrs"))
		set_ibrs_disabled();

	if (cmdline_find_option_bool(boot_command_line, "noibpb"))
		set_ibpb_disabled();

	if (cmdline_find_option_bool(boot_command_line, "nospectre_v2"))
		goto disable;
	else {
		ret = cmdline_find_option(boot_command_line, "spectre_v2", arg, sizeof(arg));
		if (ret < 0)
			return SPECTRE_V2_CMD_AUTO;

		for (i = 0; i < ARRAY_SIZE(mitigation_options); i++) {
			if (!match_option(arg, ret, mitigation_options[i].option))
				continue;
			cmd = mitigation_options[i].cmd;
			break;
		}

		if (i >= ARRAY_SIZE(mitigation_options)) {
			pr_err("unknown option (%s). Switching to AUTO select\n", arg);
			return SPECTRE_V2_CMD_AUTO;
		}
	}

	if ((cmd == SPECTRE_V2_CMD_RETPOLINE ||
	     cmd == SPECTRE_V2_CMD_RETPOLINE_AMD ||
	     cmd == SPECTRE_V2_CMD_RETPOLINE_GENERIC) &&
	    !IS_ENABLED(CONFIG_RETPOLINE)) {
		pr_err("%s selected but not compiled in. Switching to AUTO select\n", mitigation_options[i].option);
		return SPECTRE_V2_CMD_AUTO;
	}

	if (cmd == SPECTRE_V2_CMD_RETPOLINE_AMD &&
	    boot_cpu_data.x86_vendor != X86_VENDOR_AMD) {
		pr_err("retpoline,amd selected but CPU is not AMD. Switching to AUTO select\n");
		return SPECTRE_V2_CMD_AUTO;
	}

	if (mitigation_options[i].secure)
		spec2_print_if_secure(mitigation_options[i].option);
	else
		spec2_print_if_insecure(mitigation_options[i].option);

	if (cmd == SPECTRE_V2_CMD_NONE)
		goto disable;

	return cmd;

disable:
	return SPECTRE_V2_CMD_NONE;
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

static enum spectre_v2_mitigation __init ibrs_select(void)
{
	enum spectre_v2_mitigation mode = SPECTRE_V2_NONE;

	/* Turn it on (if possible) */
	set_ibrs_inuse();

	/* If it is ON, OK, lets use it.*/
	if (check_ibrs_inuse())
		mode = SPECTRE_V2_IBRS;

	if (mode == SPECTRE_V2_NONE)
		/* Well, fallback on automatic discovery. */
		pr_info("IBRS could not be enabled.\n");
	else {
		/*
		 * OK, some form of IBRS is enabled, lets see if we need
		 * to STUFF_RSB
		 */
		if (!boot_cpu_has(X86_FEATURE_SMEP))
			setup_force_cpu_cap(X86_FEATURE_STUFF_RSB);
	}
	return mode;
}

static void __init disable_ibrs_and_friends(bool disable_ibpb)
{
	set_ibrs_disabled();
	if (use_ibrs & SPEC_CTRL_IBRS_SUPPORTED) {
		unsigned int cpu;

		get_online_cpus();
		for_each_online_cpu(cpu)
			wrmsrl_on_cpu(cpu, MSR_IA32_SPEC_CTRL,
				      x86_spec_ctrl_base & ~SPEC_CTRL_FEATURE_ENABLE_IBRS);

		put_online_cpus();
	}
	/*
	 * We need to use IBPB with retpoline if it is available.
	 * And also IBRS for firmware paths.
	 */
	if (disable_ibpb) {
		set_ibpb_disabled();
		disable_ibrs_firmware();
	} else
		set_ibrs_firmware();
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
	case SPECTRE_V2_CMD_AUTO:
		if (IS_ENABLED(CONFIG_RETPOLINE))
			goto retpoline_auto;
		break;
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
	pr_err("Spectre mitigation: kernel not compiled with retpoline; no mitigation available!");
	return;

retpoline_auto:
	if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD) {
	retpoline_amd:
		if (!boot_cpu_has(X86_FEATURE_LFENCE_RDTSC)) {
			pr_err("Spectre mitigation: LFENCE not serializing, switching to generic retpoline\n");
			goto retpoline_generic;
		}
		mode = retp_compiler() ? SPECTRE_V2_RETPOLINE_AMD :
					 SPECTRE_V2_RETPOLINE_MINIMAL_AMD;
		/* On AMD we don't need IBRS, so lets use the ASM mitigation. */
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

		/* IBRS available. Check if we are compiled with retpoline. */
		if (ibrs_supported) {
			/*
			 * If we are on Skylake, use IBRS (if available).
			 * But if we are forced to use retpoline on Skylake
			 * then use that.
			 */
			if (!retp_compiler() /* prefer IBRS over minimal ASM */ ||
			    (retp_compiler() && !retpoline_selected(cmd) &&
			     is_skylake_era() && use_ibrs_on_skylake)) {
				/* Start the engine! */
				mode = ibrs_select();
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

	/* IBRS is unnecessary with retpoline mitigation. */
	if (mode == SPECTRE_V2_RETPOLINE_GENERIC ||
	    mode == SPECTRE_V2_RETPOLINE_AMD)
		disable_ibrs_and_friends(false /* Do use IPBP if possible */);

	/* Future CPUs with IBRS_ALL might be able to avoid this. */
	setup_force_cpu_cap(X86_FEATURE_VMEXIT_RSB_FULL);

	/*
	 * If neither SMEP nor PTI are available, there is a risk of
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
	if ((mode != SPECTRE_V2_IBRS) &&
	    ((!boot_cpu_has(X86_FEATURE_PTI) &&
	     !boot_cpu_has(X86_FEATURE_SMEP)) || is_skylake_era())) {
		setup_force_cpu_cap(X86_FEATURE_RSB_CTXSW);
		pr_info("Spectre v2 mitigation: Filling RSB on context switch\n");
	}

	/* Initialize Indirect Branch Prediction Barrier if supported */
	if (boot_cpu_has(X86_FEATURE_IBPB)) {
		setup_force_cpu_cap(X86_FEATURE_USE_IBPB);
		pr_info("Spectre v2 mitigation: Enabling Indirect Branch Prediction Barrier\n");
	}

	/*
	 * Retpoline means the kernel is safe because it has no indirect
	 * branches. But firmware isn't, so use IBRS to protect that.
	 */
	if (ibrs_firmware) {
		setup_force_cpu_cap(X86_FEATURE_USE_IBRS_FW);
		pr_info("Enabling Restricted Speculation for firmware calls\n");
	}
}

#undef pr_fmt
#define pr_fmt(fmt)	"Speculative Store Bypass: " fmt

static enum ssb_mitigation ssb_mode = SPEC_STORE_BYPASS_NONE;

/* The kernel command line selection */
enum ssb_mitigation_cmd {
	SPEC_STORE_BYPASS_CMD_NONE,
	SPEC_STORE_BYPASS_CMD_AUTO,
	SPEC_STORE_BYPASS_CMD_ON,
	SPEC_STORE_BYPASS_CMD_PRCTL,
};

static const char *ssb_strings[] = {
	[SPEC_STORE_BYPASS_NONE]	= "Vulnerable",
	[SPEC_STORE_BYPASS_DISABLE]	= "Mitigation: Speculative Store Bypass disabled",
	[SPEC_STORE_BYPASS_PRCTL]	= "Mitigation: Speculative Store Bypass disabled via prctl"
};

static const struct {
	const char *option;
	enum ssb_mitigation_cmd cmd;
} ssb_mitigation_options[] = {
	{ "auto",	SPEC_STORE_BYPASS_CMD_AUTO },  /* Platform decides */
	{ "on",		SPEC_STORE_BYPASS_CMD_ON },    /* Disable Speculative Store Bypass */
	{ "off",	SPEC_STORE_BYPASS_CMD_NONE },  /* Don't touch Speculative Store Bypass */
	{ "prctl",	SPEC_STORE_BYPASS_CMD_PRCTL }, /* Disable Speculative Store Bypass via prctl */
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

static enum ssb_mitigation_cmd __init __ssb_select_mitigation(void)
{
	enum ssb_mitigation mode = SPEC_STORE_BYPASS_NONE;
	enum ssb_mitigation_cmd cmd;

	if (!boot_cpu_has(X86_FEATURE_RDS))
		return mode;

	cmd = ssb_parse_cmdline();
	if (!boot_cpu_has_bug(X86_BUG_SPEC_STORE_BYPASS) &&
	    (cmd == SPEC_STORE_BYPASS_CMD_NONE ||
	     cmd == SPEC_STORE_BYPASS_CMD_AUTO))
		return mode;

	switch (cmd) {
	case SPEC_STORE_BYPASS_CMD_AUTO:
		/* Choose prctl as the default mode */
		mode = SPEC_STORE_BYPASS_PRCTL;
		break;
	case SPEC_STORE_BYPASS_CMD_ON:
		mode = SPEC_STORE_BYPASS_DISABLE;
		break;
	case SPEC_STORE_BYPASS_CMD_PRCTL:
		mode = SPEC_STORE_BYPASS_PRCTL;
		break;
	case SPEC_STORE_BYPASS_CMD_NONE:
		break;
	}

	/*
	 * We have three CPU feature flags that are in play here:
	 *  - X86_BUG_SPEC_STORE_BYPASS - CPU is susceptible.
	 *  - X86_FEATURE_RDS - CPU is able to turn off speculative store bypass
	 *  - X86_FEATURE_SPEC_STORE_BYPASS_DISABLE - engage the mitigation
	 */
	if (mode == SPEC_STORE_BYPASS_DISABLE) {
		setup_force_cpu_cap(X86_FEATURE_SPEC_STORE_BYPASS_DISABLE);
		/*
		 * Intel uses the SPEC CTRL MSR Bit(2) for this, while AMD uses
		 * a completely different MSR and bit dependent on family.
		 */
		switch (boot_cpu_data.x86_vendor) {
		case X86_VENDOR_INTEL:
			x86_spec_ctrl_base |= SPEC_CTRL_RDS;
			x86_spec_ctrl_mask &= ~SPEC_CTRL_RDS;
			x86_spec_ctrl_set(SPEC_CTRL_RDS);
			break;
		case X86_VENDOR_AMD:
			x86_amd_rds_enable();
			break;
		}
	}

	return mode;
}

static void ssb_select_mitigation()
{
	ssb_mode = __ssb_select_mitigation();

	if (boot_cpu_has_bug(X86_BUG_SPEC_STORE_BYPASS))
		pr_info("%s\n", ssb_strings[ssb_mode]);
}

#undef pr_fmt

static int ssb_prctl_set(unsigned long ctrl)
{
	bool rds = !!test_tsk_thread_flag(current, TIF_RDS);

	if (ssb_mode != SPEC_STORE_BYPASS_PRCTL)
		return -ENXIO;

	if (ctrl == PR_SPEC_ENABLE)
		clear_tsk_thread_flag(current, TIF_RDS);
	else
		set_tsk_thread_flag(current, TIF_RDS);

	if (rds != !!test_tsk_thread_flag(current, TIF_RDS))
		speculative_store_bypass_update();

	return 0;
}

static int ssb_prctl_get(void)
{
	switch (ssb_mode) {
	case SPEC_STORE_BYPASS_DISABLE:
		return PR_SPEC_DISABLE;
	case SPEC_STORE_BYPASS_PRCTL:
		if (test_tsk_thread_flag(current, TIF_RDS))
			return PR_SPEC_PRCTL | PR_SPEC_DISABLE;
		return PR_SPEC_PRCTL | PR_SPEC_ENABLE;
	default:
		if (boot_cpu_has_bug(X86_BUG_SPEC_STORE_BYPASS))
			return PR_SPEC_ENABLE;
		return PR_SPEC_NOT_AFFECTED;
	}
}

int arch_prctl_spec_ctrl_set(unsigned long which, unsigned long ctrl)
{
	if (ctrl != PR_SPEC_ENABLE && ctrl != PR_SPEC_DISABLE)
		return -ERANGE;

	switch (which) {
	case PR_SPEC_STORE_BYPASS:
		return ssb_prctl_set(ctrl);
	default:
		return -ENODEV;
	}
}

int arch_prctl_spec_ctrl_get(unsigned long which)
{
	switch (which) {
	case PR_SPEC_STORE_BYPASS:
		return ssb_prctl_get();
	default:
		return -ENODEV;
	}
}

void x86_spec_ctrl_setup_ap(void)
{
	if (boot_cpu_has(X86_FEATURE_IBRS))
		x86_spec_ctrl_set(x86_spec_ctrl_base & ~x86_spec_ctrl_mask);

	if (ssb_mode == SPEC_STORE_BYPASS_DISABLE)
		x86_amd_rds_enable();
}

#ifdef CONFIG_SYSFS

ssize_t cpu_show_common(struct device *dev, struct device_attribute *attr,
			char *buf, unsigned int bug)
{
	if (!boot_cpu_has_bug(bug))
		return sprintf(buf, "Not affected\n");

	switch (bug) {
	case X86_BUG_CPU_MELTDOWN:
		if (boot_cpu_has(X86_FEATURE_PTI))
			return sprintf(buf, "Mitigation: PTI\n");

		break;

	case X86_BUG_SPECTRE_V1:
		return sprintf(buf, "Mitigation: __user pointer sanitization\n");

	case X86_BUG_SPECTRE_V2:
		return sprintf(buf, "%s%s%s%s%s\n", spectre_v2_strings[spectre_v2_enabled],
			       ibrs_inuse && (spectre_v2_enabled != SPECTRE_V2_IBRS) ? ", IBRS" : "",
			       ibpb_inuse ? ", IBPB" : "",
			       ibrs_firmware ? ", IBRS_FW" : "",
			       spectre_v2_module_string());

	case X86_BUG_SPEC_STORE_BYPASS:
		return sprintf(buf, "%s\n", ssb_strings[ssb_mode]);

	default:
		break;
	}

	return sprintf(buf, "Vulnerable\n");
}

ssize_t cpu_show_meltdown(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_CPU_MELTDOWN);
}

ssize_t cpu_show_spectre_v1(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_SPECTRE_V1);
}

ssize_t cpu_show_spectre_v2(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_SPECTRE_V2);
}

ssize_t cpu_show_spec_store_bypass(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_SPEC_STORE_BYPASS);
}
#endif
