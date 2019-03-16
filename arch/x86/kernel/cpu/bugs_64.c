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

static void __init spectre_v2_parse_cmdline(void);
static void __init l1tf_select_mitigation(void);
static void mds_select_mitigation(void);

void __init check_bugs(void)
{
	identify_boot_cpu();
#if !defined(CONFIG_SMP)
	printk(KERN_INFO "CPU: ");
	print_cpu_info(&boot_cpu_data);
#endif
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

	spectre_v2_parse_cmdline();

	l1tf_select_mitigation();

	mds_select_mitigation();
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

/* Default mitigation for L1TF-affected CPUs */
static enum mds_mitigations mds_mitigation __read_mostly = MDS_MITIGATION_FULL;

static const char * const mds_strings[] = {
	[MDS_MITIGATION_OFF]	= "Vulnerable",
	[MDS_MITIGATION_FULL]	= "Mitigation: Clear CPU buffers"
};

static void mds_select_mitigation(void)
{
	u64 ia32_cap = 0;

	/*
	 * Reset MDS mitigation to default value as new microcode may have
	 * been loaded and we need to re-determine the current status.
	 */
	mds_mitigation = MDS_MITIGATION_FULL;

	if (cpu_has(&cpu_data(0), X86_FEATURE_ARCH_CAPABILITIES))
		rdmsrl(MSR_IA32_ARCH_CAPABILITIES, ia32_cap);

	if (cpu0_matches(NO_MDS) || (ia32_cap & ARCH_CAP_MDS_NO)) {
		mds_mitigation = MDS_MITIGATION_OFF;
		return;
	}

	if (mds_mitigation == MDS_MITIGATION_FULL) {
		if (!cpu_has(&cpu_data(0), X86_FEATURE_MD_CLEAR))
			mds_mitigation = MDS_MITIGATION_OFF;
	}
	pr_info("%s\n", mds_strings[mds_mitigation]);
}

#undef pr_fmt

#ifdef CONFIG_SYSFS
static ssize_t mds_show_state(char *buf)
{
	/* Select mitigation again in case new microcode has been loaded. */
	mds_select_mitigation();

	if (cpu_has_hypervisor) {
		return sprintf(buf, "%s; SMT Host state unknown\n",
			       mds_strings[mds_mitigation]);
	}

	if (cpu0_matches(MSBDS_ONLY)) {
		return sprintf(buf, "%s; SMT %s\n", mds_strings[mds_mitigation],
			       (cpumask_weight(cpu_sibling_mask(0)) > 1) ?
			       "mitigated" : "disabled");
	}

	return sprintf(buf, "%s; SMT %s\n", mds_strings[mds_mitigation],
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
		return sprintf(buf, "Mitigation: lfence\n");

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
#endif
