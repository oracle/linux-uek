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
#ifdef CONFIG_SYSFS
#include <linux/device.h>
#endif
#include <asm/spec_ctrl.h>
#include <asm/cmdline.h>

static void __init spectre_v2_parse_cmdline(void);

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

#ifdef CONFIG_SYSFS
ssize_t cpu_show_meltdown(struct device *dev,
                         struct device_attribute *attr, char *buf)
{
	if (!boot_cpu_has(X86_BUG_CPU_MELTDOWN))
		return sprintf(buf, "Not affected\n");
	if (boot_cpu_has(X86_FEATURE_PTI))
		return sprintf(buf, "Mitigation: PTI\n");
	return sprintf(buf, "Vulnerable\n");
}

ssize_t cpu_show_spectre_v1(struct device *dev,
                           struct device_attribute *attr, char *buf)
{
	if (!boot_cpu_has(X86_BUG_SPECTRE_V1))
		return sprintf(buf, "Not affected\n");
	/* At the moment, a single hard-wired mitigation */
	return sprintf(buf, "Mitigation: lfence\n");
}

ssize_t cpu_show_spectre_v2(struct device *dev,
                           struct device_attribute *attr, char *buf)
{
	if (!boot_cpu_has(X86_BUG_SPECTRE_V2))
		return sprintf(buf, "Not affected\n");
	if (ibrs_inuse() || ibpb_inuse())
		return sprintf(buf, "Mitigation: %s%s\n",
				ibrs_inuse() ? "IBRS " : "",
				ibpb_inuse() ? "IBPB" : "");

	return sprintf(buf, "Vulnerable\n");
}
#endif
