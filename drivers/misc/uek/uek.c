// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 */

#include <linux/dmi.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/isolation.h>
#include <linux/slab.h>

#define UEK_MISC_VER  "0.1"

MODULE_AUTHOR("Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>");
MODULE_DESCRIPTION("uek");
MODULE_LICENSE("GPL");
MODULE_VERSION(UEK_MISC_VER);

DEFINE_STATIC_KEY_FALSE(on_exadata);
EXPORT_SYMBOL_GPL(on_exadata);

#ifdef	CONFIG_HUGETLB_PAGE_OPTIMIZE_VMEMMAP
extern void __init hugetlb_enable_vmemmap(void);
#endif

/* Override to disable optimizations on Exadata systems. */
static bool exadata_disable;

static int __init uek_params(char *str)
{
	if (!str)
		return 0;

	if (strncmp(str, "exadata", 7) == 0) {
		static_branch_enable(&on_exadata);
		return 1;
	} else if ((strncmp(str, "noexadata", 9) == 0)) {
		exadata_disable = true;
		return 1;
	}

	return 1;
}
__setup("uek=", uek_params);

int exadata_check_allowed(struct task_struct *p, const struct cpumask *new_mask)
{
	/* Both isolcpus and uek=exadata MUST be set. */
	if (!static_key_enabled(&housekeeping_overridden))
		return 0;

	if (!static_key_enabled(&on_exadata))
		return 0;

	/* Kernel threads are OK. */
	if (p->flags & PF_KTHREAD)
		return 0;

	/*
	 * User-space tasks cannot be on CPUs on the isolcpus=.
	 *
	 * N.B. The housekeeping_cpumask is the inverse of isolcpus=
	 */
	if (cpumask_intersects(new_mask, housekeeping_cpumask(HK_FLAG_DOMAIN)))
		return 0;

	return -EINVAL;
};
EXPORT_SYMBOL_GPL(exadata_check_allowed);

static int detect_exadata_dmi(char **reason)
{
	static const char * const oemstrs[] = {"SUNW-PRMS-1", "00010000"};
	static const struct dmi_system_id oracle_mbs[] = {
		{
			.matches = {
				DMI_MATCH(DMI_SYS_VENDOR, "Oracle Corporation"),
			},
		},
		{
			.matches = {
				DMI_MATCH(DMI_CHASSIS_ASSET_TAG, "OracleCloud.com"),
			},
		},
		{}
	};

	unsigned int i, ok = 0;

	/* Not Oracle system? .. Bye. */
	if (!dmi_check_system(oracle_mbs))
		goto err;

	/* Check for Type 11 and make sure it has the right markings. */
	for (i = 0; i < ARRAY_SIZE(oemstrs); i++)
		if (dmi_find_device(DMI_DEV_TYPE_OEM_STRING, oemstrs[i], NULL))
			ok++;

	if (ok == 2) {
		*reason = "via DMI";
		return 0;
	}

err:
	return -ENODEV;
}

static int detect_exadata_bootline(char **reason)
{
	if (static_key_enabled(&on_exadata)) {
		*reason = "via command line";
		return 0;
	}
	return -ENODEV;
}

static int __init uek_misc_init(void)
{
	int ret;
	char *reason = NULL;

	/* Boot time override engaged */
	if (exadata_disable)
		return -ENODEV;

	ret = detect_exadata_bootline(&reason);
	if (!ret)
		goto enable;

	ret = detect_exadata_dmi(&reason);
	if (ret)
		return ret;

enable:
	/* Go-Go Exadata goodness! */
	static_branch_enable(&on_exadata);

#ifdef	CONFIG_HUGETLB_PAGE_OPTIMIZE_VMEMMAP
	hugetlb_enable_vmemmap();
#endif
	pr_info("Detected Exadata (%s)", reason);

	return 0;
}

core_initcall(uek_misc_init);
