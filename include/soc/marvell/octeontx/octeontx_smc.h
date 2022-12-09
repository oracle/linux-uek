/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (C) 2021 Marvell
 *
 */

#ifndef _SOC_MRVL_OCTEONTX_SMC_H
#define _SOC_MRVL_OCTEONTX_SMC_H

#include <linux/errno.h>
#include <linux/arm-smccc.h>
#include <asm/cputype.h>
#include <linux/of.h>
#include <linux/sys_soc.h>

/* Data and defines for SMC call */
#define OCTEONTX_ARM_SMC_SVC_UID			0xc200ff01

/* This is expected OCTEONTX response for SVC UID command */
/** Check software version and compatibility of ATF
 *
 * The call verifies ATF instance running on the system.
 *
 * @return
 *	0 (T9x) and 2 (cn10k) on success
 *	error code on failure
 *
 */
static inline int octeontx_soc_check_smc(void)
{
#define CPU_MODEL_CN10KX_PART	0xd49

	const int octeontx_svc_uuid[] = {
		0x6ff498cf,
		0x5a4e9cfa,
		0x2f2a3aa4,
		0x5945b105,
	};

	struct arm_smccc_res res;

	/* Is it OCTEONTX on the other side of SMC monitor? */
	arm_smccc_smc(OCTEONTX_ARM_SMC_SVC_UID, 0, 0, 0, 0, 0, 0, 0, &res);
	if (res.a0 != octeontx_svc_uuid[0] || res.a1 != octeontx_svc_uuid[1] ||
	    res.a2 != octeontx_svc_uuid[2] || res.a3 != octeontx_svc_uuid[3])
		return -EPERM;

	if (MIDR_PARTNUM(read_cpuid_id()) == CPU_MODEL_CN10KX_PART)
		return 2;

	return 0;
}

static inline bool is_soc_cn9x(void)
{
	u32 partnum;

	partnum = MIDR_PARTNUM(read_cpuid_id());

	if ((partnum & 0xbf) || (partnum & 0xaf))
		return true;
	return false;
}

static inline bool is_soc_cn10kx(void)
{
	if (MIDR_PARTNUM(read_cpuid_id()) == CPU_MODEL_CN10KX_PART)
		return 1;
	return 0;
}

static inline bool is_soc_cnf10kb(void)
{
	static const struct soc_device_attribute cnf10kb_socinfo[] = {
		{.soc_id = "jep106:0369:00bc", },
		{},
	};
	const struct soc_device_attribute *attr;

	attr = soc_device_match(cnf10kb_socinfo);

	if (attr)
		return true;

	return false;
}

static inline bool is_soc_cn10ka_ax(void)
{
	static const struct soc_device_attribute cn10ka_socinfo[] = {
		{.soc_id = "jep106:0369:00b9", .revision = "0x00000000", },
		{.soc_id = "jep106:0369:00b9", .revision = "0x00000001", },
		{},
	};
	const struct soc_device_attribute *attr;

	attr = soc_device_match(cn10ka_socinfo);

	if (attr)
		return true;

	return false;
}

static inline bool is_soc_cnf10ka_ax(void)
{
	static const struct soc_device_attribute cnf10ka_socinfo[] = {
		{.soc_id = "jep106:0369:00ba", .revision = "0x00000000", },
		{.soc_id = "jep106:0369:00ba", .revision = "0x00000001", },
		{},
	};
	const struct soc_device_attribute *attr;

	attr = soc_device_match(cnf10ka_socinfo);

	if (attr)
		return true;

	return false;
}

#endif /* _SOC_MRVL_OCTEONTX_SMC_H */
