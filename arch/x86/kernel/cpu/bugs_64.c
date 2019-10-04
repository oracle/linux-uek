/*
 *  Copyright (C) 1994  Linus Torvalds
 *  Copyright (C) 2000  SuSE
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <asm/alternative.h>
#include <asm/bugs.h>
#include <asm/processor.h>
#include <asm/mtrr.h>
#include <asm/cacheflush.h>
#include <linux/device.h>
#include <asm/spec_ctrl.h>
#include <asm/cmdline.h>
#include <asm/e820.h>

#include "cpu.h"

static void __init spectre_v1_select_mitigation(void);
static void __init spectre_v2_parse_cmdline(void);
static void __init l1tf_select_mitigation(void);
static void mds_select_mitigation(void);
static void taa_select_mitigation(void);

void __init check_bugs(void)
{
	identify_boot_cpu();
#if !defined(CONFIG_SMP)
	printk(KERN_INFO "CPU: ");
	print_cpu_info(&boot_cpu_data);
#endif
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

	spectre_v2_parse_cmdline();
	spectre_v1_select_mitigation();
	l1tf_select_mitigation();
	mds_select_mitigation();
	taa_select_mitigation();

	alternative_instructions();
}

static inline bool match_option(const char *arg, int arglen, const char *opt)
{
	int len = strlen(opt);

	return len == arglen && !strncmp(arg, opt, len);
}

static void spectre_v2_usage_error(const char *str)
{
	pr_warn("%s arguments for option spectre_v2. "
	    "Usage spectre_v2={on|off|auto}\n", str);
}

static void __init spectre_v2_parse_cmdline(void)
{
	char arg[20];
	int ret;

	if (cmdline_find_option_bool(boot_command_line, "noibrs")) {
		set_ibrs_disabled();
	}

	if (cmdline_find_option_bool(boot_command_line, "noibpb")) {
		set_ibpb_disabled();
	}

	if (cmdline_find_option_bool(boot_command_line, "nospectre_v2"))
		goto disable;

	ret = cmdline_find_option(boot_command_line, "spectre_v2", arg,
	    sizeof(arg));

	if (ret > 0) {

		if (match_option(arg, ret, "off"))
			goto disable;

		if (match_option(arg, ret, "on") ||
		    match_option(arg, ret, "auto")) {
			if (!boot_cpu_has(X86_FEATURE_IBRS))
				pr_warn("Spectre_v2 mitigation unsupported\n");
		} else {
			spectre_v2_usage_error("Invalid");
		}
	}

	return;

disable:
	set_ibrs_disabled();
	set_ibpb_disabled();
}

#undef pr_fmt
#define pr_fmt(fmt)	"L1TF: " fmt
static void __init l1tf_select_mitigation(void)
{
	u64 half_pa;

	if (!boot_cpu_has(X86_BUG_L1TF))
		return;

#if PAGETABLE_LEVELS == 2
	pr_warn("Kernel not compiled for PAE. No mitigation for L1TF\n");
	return;
#endif

	/*
	 * This is extremely unlikely to happen because almost all
	 * systems have far more MAX_PA/2 than RAM can be fit into
	 * DIMM slots.
	 */
	half_pa = (u64)l1tf_pfn_limit() << PAGE_SHIFT;
	if (e820_any_mapped(half_pa, ULLONG_MAX - half_pa, E820_RAM)) {
		pr_warn("System has more than MAX_PA/2 memory. L1TF mitigation not effective.\n");
		return;
	}

	setup_force_cpu_cap(X86_FEATURE_L1TF_PTEINV);
}
#undef pr_fmt
#define pr_fmt(fmt)	"MDS: " fmt

/* Default mitigation for MDS-affected CPUs */
static enum mds_mitigations mds_mitigation __read_mostly = MDS_MITIGATION_FULL;

static const char * const mds_strings[] = {
	[MDS_MITIGATION_OFF]	= "Vulnerable",
	[MDS_MITIGATION_FULL]	= "Mitigation: Clear CPU buffers",
	[MDS_MITIGATION_VMWERV] = "Vulnerable: Clear CPU buffers attempted, no microcode",
};

static void mds_select_mitigation(void)
{
	u64 ia32_cap = 0;

	if (boot_cpu_has(X86_FEATURE_ARCH_CAPABILITIES))
		rdmsrl(MSR_IA32_ARCH_CAPABILITIES, ia32_cap);

	if (cpu_matches(NO_MDS) || (ia32_cap & ARCH_CAP_MDS_NO)) {
		mds_mitigation = MDS_MITIGATION_OFF;
		return;
	}

	if (mds_mitigation == MDS_MITIGATION_FULL) {
		if (!boot_cpu_has(X86_FEATURE_MD_CLEAR))
			mds_mitigation = MDS_MITIGATION_VMWERV;
	}
	pr_info("%s\n", mds_strings[mds_mitigation]);
}

#undef pr_fmt
#define pr_fmt(fmt)	"TAA: " fmt

/* Default mitigation for TAA-affected CPUs */
static enum taa_mitigations taa_mitigation = TAA_MITIGATION_VERW;

static const char * const taa_strings[] = {
	[TAA_MITIGATION_OFF]		= "Vulnerable",
	[TAA_MITIGATION_UCODE_NEEDED]	= "Vulnerable: Clear CPU buffers attempted, no microcode",
	[TAA_MITIGATION_VERW]		= "Mitigation: Clear CPU buffers",
	[TAA_MITIGATION_TSX_DISABLED]	= "Mitigation: TSX disabled",
};

static void taa_select_mitigation(void)
{
	char arg[12] = {};
	u64 ia32_cap;
	int ret;

	if (!boot_cpu_has(X86_BUG_TAA)) {
		taa_mitigation = TAA_MITIGATION_OFF;
		return;
	}

	/* TSX previously disabled by tsx=off */
	if (!boot_cpu_has(X86_FEATURE_RTM)) {
		taa_mitigation = TAA_MITIGATION_TSX_DISABLED;
		goto out;
	}

	ret = cmdline_find_option(boot_command_line, "tsx_async_abort", arg,
				  sizeof(arg));

	if (ret > 0) {
		if (match_option(arg, ret, "off"))
			taa_mitigation = TAA_MITIGATION_OFF;
		else if (match_option(arg, ret, "full"))
			taa_mitigation = TAA_MITIGATION_VERW;
		else
			pr_warn("tsx_async_abort: unknown option %s\n", arg);
	}

	/* TAA mitigation is turned off from cmdline (tsx_async_abort=off) */
	if (taa_mitigation == TAA_MITIGATION_OFF)
		goto out;

	if (boot_cpu_has(X86_FEATURE_MD_CLEAR))
		taa_mitigation = TAA_MITIGATION_VERW;
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
	ia32_cap = x86_read_arch_cap_msr();
	if ((ia32_cap & ARCH_CAP_MDS_NO) &&
	   !(ia32_cap & ARCH_CAP_TSX_CTRL_MSR))
		taa_mitigation = TAA_MITIGATION_UCODE_NEEDED;

	/*
	 * TSX is enabled, select alternate mitigation for TAA which is
	 * same as MDS. The MDS mitigation is always on, so do nothing.
	 */

out:
	pr_info("%s\n", taa_strings[taa_mitigation]);
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
	if (!boot_cpu_has(X86_BUG_SPECTRE_V1)) {
		spectre_v1_mitigation = SPECTRE_V1_MITIGATION_NONE;
		return;
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
			if (boot_cpu_has(X86_BUG_SWAPGS) &&
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

static int __init nospectre_v1_cmdline(char *str)
{
	spectre_v1_mitigation = SPECTRE_V1_MITIGATION_NONE;
	return 0;
}
early_param("nospectre_v1", nospectre_v1_cmdline);

#undef pr_fmt

#ifdef CONFIG_SYSFS
static ssize_t mds_show_state(char *buf)
{
	if (cpu_has_hypervisor) {
		return sprintf(buf, "%s; SMT Host state unknown\n",
			       mds_strings[mds_mitigation]);
	}

	if (cpu_matches(MSBDS_ONLY)) {
		return sprintf(buf, "%s; SMT %s\n", mds_strings[mds_mitigation],
			       (cpumask_weight(cpu_sibling_mask(0)) > 1) ?
			       "mitigated" : "disabled");
	}

	return sprintf(buf, "%s; SMT %s\n", mds_strings[mds_mitigation],
		       (cpumask_weight(cpu_sibling_mask(0)) > 1) ?
		       "vulnerable" : "disabled");
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
		       (cpumask_weight(cpu_sibling_mask(0)) > 1) ?
		       "vulnerable" : "disabled");
}

ssize_t cpu_show_common(struct device *dev, struct device_attribute *attr,
			char *buf, unsigned int bug)
{
	if (!boot_cpu_has(bug))
		return sprintf(buf, "Not affected\n");

	switch (bug) {
	case X86_BUG_CPU_MELTDOWN:
		if (boot_cpu_has(X86_FEATURE_PTI))
			return sprintf(buf, "Mitigation: PTI\n");

		break;

	case X86_BUG_SPECTRE_V1:
		return sprintf(buf, "%s\n", spectre_v1_strings[spectre_v1_mitigation]);

	case X86_BUG_SPECTRE_V2:
		if (ibrs_inuse || ibpb_inuse)
			return sprintf(buf, "Mitigation: %s%s\n",
				       ibrs_inuse ? "IBRS " : "",
				       ibpb_inuse ? "IBPB" : "");
		break;

	case X86_BUG_L1TF:
		if (boot_cpu_has(X86_FEATURE_L1TF_PTEINV))
			return sprintf(buf, "Mitigation: Page Table Inversion\n");
		break;

	case X86_BUG_TAA:
		return tsx_async_abort_show_state(buf);

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

ssize_t cpu_show_spectre_v2(struct device *dev,
                           struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_SPECTRE_V2);
}

ssize_t cpu_show_l1tf(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_L1TF);
}

ssize_t cpu_show_mds(struct device *dev, struct device_attribute *attr, char *buf)
{
	return mds_show_state(buf);
}

ssize_t cpu_show_tsx_async_abort(struct device *dev, struct device_attribute *attr, char *buf)
{
	return cpu_show_common(dev, attr, buf, X86_BUG_TAA);
}
#endif
