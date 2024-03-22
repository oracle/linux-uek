// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 */

#include <linux/dmi.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kvm_para.h>
#ifdef CONFIG_ARM64
#include <asm/virt.h>
#endif

#define UEK_MISC_VER  "0.2"

MODULE_AUTHOR("Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>");
MODULE_DESCRIPTION("uek");
MODULE_LICENSE("GPL");
MODULE_VERSION(UEK_MISC_VER);

DEFINE_STATIC_KEY_FALSE(on_exadata);
DEFINE_STATIC_KEY_FALSE(cls_enabled);
EXPORT_SYMBOL_GPL(on_exadata);
EXPORT_SYMBOL_GPL(cls_enabled);

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
	} else if (strncmp(str, "cls", 3) == 0) {
		static_branch_enable(&cls_enabled);
		return 1;
	}

	return 1;
}
__setup("uek=", uek_params);

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

static int uek_misc_init(void)
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

	pr_info("Detected Exadata (%s)", reason);

	return 0;
}

core_initcall(uek_misc_init);

bool uek_runs_in_kvm(void)
{
	/*
	 * ARM64 returns false for kvm_para_available(), but on ARM64
	 * we can utilize is_hyp_mode_available() instead.
	 */
#ifdef CONFIG_ARM64
	return !is_hyp_mode_available();
#else
	return kvm_para_available();
#endif
}
EXPORT_SYMBOL_GPL(uek_runs_in_kvm);
