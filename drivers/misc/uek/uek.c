// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, Oracle and/or its affiliates.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/dmi.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/kvm_para.h>
#include <linux/utsname.h>
#ifdef CONFIG_ARM64
#include <asm/virt.h>
#endif

#define UEK_MISC_VER  "0.3"

MODULE_AUTHOR("Konrad Rzeszutek Wilk <konrad.wilk@oracle.com>");
MODULE_DESCRIPTION("uek");
MODULE_LICENSE("GPL");
MODULE_VERSION(UEK_MISC_VER);

DEFINE_STATIC_KEY_FALSE(on_exadata);
DEFINE_STATIC_KEY_FALSE(cls_enabled);
DEFINE_STATIC_KEY_FALSE(on_oci);

EXPORT_SYMBOL_GPL(on_exadata);
EXPORT_SYMBOL_GPL(cls_enabled);
EXPORT_SYMBOL_GPL(on_oci);

/*
 * The Oracle Server UEFI BIOS Specification lists requirements imposed by PRMS
 * (Platform Resource Management Specification) for SMBIOS structures.
 * PRMS-003 requires an OEM Strings (Type 11) structure with a string of the
 * form "SUNW-PRMS-1".
 */
#define PRMS_003_ID		"SUNW-PRMS-1"

/*
 * In Type 11 structures (OEM Strings), and specifically Type 11 String 4, BIOS
 * must provide system profile identification by setting String 4 to "00010000"
 * for Exadata systems, and "00000000" for general purpose systems (GPS).
 */
#define EXADATA_STR4_ID		"00010000"
#define GPS_STR4_ID		"00000000"

enum orcl_platform_type {
	ORCL_EXADATA,
	ORCL_OCI,
	ORCL_NOID,
};

/* Override to disable optimizations on Exadata systems. */
static bool exadata_disable;

/* Disables oci specific behavior */
static bool oci_disable;

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
	} else if (strncmp(str, "oci", 3) == 0) {
		static_branch_enable(&on_oci);
		return 1;
	} else if (strncmp(str, "nooci", 5) == 0) {
		oci_disable = true;
		return 1;
	}

	return 1;
}
__setup("uek=", uek_params);

static inline bool dmi_oem_string_present(const char *id_str)
{
	return !!dmi_find_device(DMI_DEV_TYPE_OEM_STRING, id_str, NULL);
}

/*
 * Attempt to identify the running platform based on DMI structures.
 */
static enum orcl_platform_type detect_platform_dmi(void)
{
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

	/* Attempt to identify an Oracle platform signature */
	if (!dmi_check_system(oracle_mbs))
		return ORCL_NOID;

	/*
	 * Query OEM Strings structures (Type 11) for identifying data.
	 *
	 * A requirement is that platforms implementing all or part of the
	 * PRMS specification must contain an OEM Strings (Type 11) structure
	 * with a string of the form "SUNW-PRMS-1" (PRMS-003).
	 *
	 * Additionally, PRMS requirements state that Exadata systems set
	 * String 4 to "00010000", while other systems have "00000000".
	 * Use this to uniquely identify Exadata platforms.
	 */

	/* Validate that "SUNW-PRMS-1" is present */
	if (!dmi_oem_string_present(PRMS_003_ID)) {
		pr_debug("SMBIOS data could be missing or incomplete");
		return ORCL_NOID;
	}

	/* Search for specific system profiles encoded in OEM Strings struct */
	if (dmi_oem_string_present(EXADATA_STR4_ID)) {
		/* Exadata signature detected*/
		return ORCL_EXADATA;
	} else if (dmi_oem_string_present(GPS_STR4_ID)) {
		/*
		 * Categorize Oracle platforms with general purpose signature
		 * as being an OCI platform.
		 * Refine further if a unique identifier is later assigned to
		 * OCI system profile.
		 */
		return ORCL_OCI;
	} else {
		/*
		 * No known system profile detected on OEM Strings structure
		 */
		pr_debug("Unable to identify system profile from OEM Strings");
		return ORCL_NOID;
	}
}

static enum orcl_platform_type detect_bootline_options(void)
{
	if (static_key_enabled(&on_exadata)) {
		return ORCL_EXADATA;
	}
	if (static_key_enabled(&on_oci)) {
		return ORCL_OCI;
	}
	return ORCL_NOID;
}

static inline void enable_exadata(char **reason)
{
	static_branch_enable(&on_exadata);
	pr_info("Detected Exadata (%s)", *reason);
}

static inline void enable_oci(char **reason)
{
	static_branch_enable(&on_oci);
	pr_info("Detected OCI (%s)", *reason);
}

static int uek_misc_init(void)
{
	enum orcl_platform_type plat_detected = ORCL_NOID;
	char *reason = NULL;

	/* Boot time override options */
	if (exadata_disable && oci_disable)
		return -ENODEV;

	plat_detected = detect_bootline_options();

	if (plat_detected != ORCL_NOID) {
		reason = "via command line";
	} else {
		/*
		 * If a platform option was not specified in the kernel
		 * commandline via 'uek=*' parameter, fallback to try to
		 * determine the platform using DMI info.
		 */
		plat_detected = detect_platform_dmi();
		reason = "via DMI";
	}

	switch (plat_detected) {
	case ORCL_EXADATA:
		if (exadata_disable)
			return -ENODEV;
		/* Go-Go Exadata goodness! */
		enable_exadata(&reason);
		return 0;
	case ORCL_OCI:
		if (oci_disable)
			return -ENODEV;
		enable_oci(&reason);
		return 0;
	case ORCL_NOID:
	default:
		pr_debug("Unable to identify platform");
		return -ENODEV;
	}

	/* Unreachable */
	return -ENODEV;
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

bool uek_on_ol8_or_ol9(void) {

	if (strstr(utsname()->release, "el8uek"))
		return true;
	if (strstr(utsname()->release, "el9uek"))
		return true;
	return false;

}
EXPORT_SYMBOL_GPL(uek_on_ol8_or_ol9);
