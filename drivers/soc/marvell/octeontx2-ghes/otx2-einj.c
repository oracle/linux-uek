// SPDX-License-Identifier: GPL-2.0
/*
 * OcteonTX2 memory controller ECC injection
 * Copyright Marvell Technologies. (C) 2019-2020. All rights reserved.
 */

#include <linux/module.h>
#include <linux/pci.h>

/*
 * All DRAM/cache controller hardware is handled by ATF on these platforms
 * and not visible to Non-Secure OS kernel.
 * The EDAC functions are passed to ATF by OCTEONTX_EDAC SMC, which performs
 * injection and reporting, and copies log stream back to kernel for reporting
 * detail in syslog.
 *
 * This is minimal SMC stub approach, minimally providing hooks for usermode
 * error-injection tools, to exercise either the legacy EDAC code of pre-4.18,
 * or the standard SDEI/GHES RAS handling possible in newer kernels.
 * It knows nothing of either, just asks ATF to corrupt memory.
 * This allows LMC/etc details to be hidden from EL2, all RAS/EDAC
 * work going to ATF/EL3 for security.
 *
 * For further details, see:
 *  ATF's docs/plat/marvell/marvell_ras.txt
 *  include/plat/marvell/octeontx/otx2/plat_ras.h
 */

#define OCTEONTX_EDAC                   0xc2000c0b
/* x1 is one of the following ... */
#define OCTEONTX_EDAC_VER	0	/* report version */
#define OCTEONTX_EDAC_INJECT	3	/* x2=addr x3=flags _F_xxx below */
#define OCTEONTX_EDAC_MDC_CONST	4	/* read CAVM_MDC_CONST */
#define OCTEONTX_EDAC_MDC_RW	5	/* read/write MDC */
#define OCTEONTX_EDAC_MDC_ROM	6	/* read MDC_RAS_ROM x2=addr */

#define OCTEONTX_EDAC_F_BITMASK	0x007 /* single bit to corrupt */
#define OCTEONTX_EDAC_F_MULTI	0x008 /* corrupt multiple bits */
#define OCTEONTX_EDAC_F_CLEVEL	0x070 /* cache level to corrupt (L0 == DRAM) */
#define OCTEONTX_EDAC_F_ICACHE	0x080 /* Icache, not Dcache */
#define OCTEONTX_EDAC_F_REREAD	0x100 /* read-back in EL3 */
#define OCTEONTX_EDAC_F_PHYS	0x200 /* target is EL3-physical, not EL012 */

#include <linux/arm-smccc.h>

/*
 * Module parameters are used here instead of debugfs because debugfs requires
 * a kernel configuration option to be enabled, which potentially requires
 * a configuration change and kernel rebuild.
 * The use of error injection via this module is meant to be available at all
 * times (when the module is loaded) and should not require a special kernel.
 */
static u64 smc_params[7];
static u64 smc_result;
static int smc_argc;

/* an easily recognized value for logs */
static const u64 test_val = 0x5555555555555555;

/* target address for please-corrupt-EL1/EL2 I-cache/DRAM */
static u64 ecc_test_target_fn(void)
{
	return test_val;
}

static int otx2_edac_smc(void)
{
	/* target address for please-corrupt-EL1/EL2 D-cache/DRAM: */
	u64 ecc_test_target_data = test_val;
	struct arm_smccc_res res;
	bool test_read = false;
	bool test_call = false;
	u64 *a = smc_params;

	/*
	 * Replace magic ECC-injection addresses:
	 * special ECC-injection addresses 0-3/4-7 are substituted by
	 * EL0-3 code as instr/data targets at that execution level.
	 * Any 0/4 addresses will have already been substituted
	 * by EL0 test harness, here we substitute EL1/EL2 targets.
	 * While 3/7 are replaced by ATF with its own test objects,
	 * we remind it to reread in its own context.
	 */
	if (a[0] == OCTEONTX_EDAC_INJECT) {
		a[2] &= ~OCTEONTX_EDAC_F_REREAD;
		switch (a[1]) {
		case 1 ... 2:	/* EL0..EL2 D-space target */
			a[1] = (u64)&ecc_test_target_data;
			test_read = true;
			break;	/* EL0..EL2 I-space target */
		case 5 ... 6:
			a[1] = (u64)ecc_test_target_fn;
			test_call = true;
			break;
		case 3: /* EL3 targets */
		case 7:
			a[2] |= OCTEONTX_EDAC_F_REREAD;
			break;
		}
	}

	arm_smccc_smc(OCTEONTX_EDAC, a[0], a[1], a[2], /* x1-x3 */
		a[3], a[4], a[5], a[6], &res); /* x4-x7, result */
	trace_printk("%s: OCTEONTX_EDAC(%llx, %llx, %llx, %llx) -> e?%ld\n",
		__func__, a[0], a[1], a[2], a[3], res.a0);

	if (test_read && ecc_test_target_data != test_val)
		trace_printk("%s test_read mismatch\n", __func__);
	if (test_call && ecc_test_target_fn() != test_val)
		trace_printk("%s test_call mismatch\n", __func__);

	return res.a0;
}

static int smc_params_set(const char *_str, const struct kernel_param *kp)
{
	/* as with param_array_set(), temporarily overwrites string */
	char *str = (char *)_str;
	int rc;

	trace_printk("%s: (%s)\n", __func__, str);

	if (!str)
		return -EINVAL;

	smc_result = -EBUSY;

	for (smc_argc = 0; smc_argc < 7 && *str; smc_argc++) {
		int len = strcspn(str, ",");
		char *nxt = len ? str + len + 1 : "";

		if (len)
			str[len] = '\0';
		rc = kstrtoull(str, 0, &smc_params[smc_argc]);

		trace_printk("%s: (%s/%s) smc_params[%d]=%llx e?%d\n",
			__func__, str, nxt, smc_argc,
			smc_params[smc_argc], rc);
		if (len)
			str[len] = ',';
		str = nxt;
		trace_printk("%s: smc_params[%d]=%llx\n",
			__func__, smc_argc, smc_params[smc_argc]);
	}

	smc_result = otx2_edac_smc();
	trace_printk("%s: result: %llx\n", __func__, smc_result);
	return 0;
}

static int smc_params_get(char *buffer, const struct kernel_param *kp)
{
	return sprintf(buffer, "%lld\n", smc_result);
}

static const struct kernel_param_ops smc_params_ops = {
	.set = smc_params_set,
	.get = smc_params_get,
};

module_param_cb(smc_params, &smc_params_ops, smc_params, 0644);
MODULE_PARM_DESC(smc_params, "call/return  values for OCTEONTX_EDAC SMC");

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Marvell Semiconductor");
MODULE_DESCRIPTION("OcteonTX2 ECC injector stub");
