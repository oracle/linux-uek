// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021, Pensando Systems Inc.
 */

#include <linux/device.h>
#include <linux/string.h>
#include <linux/arm-smccc.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "penfw.h"

#define PENFW_CALL_FID			    0xC2000002

extern void *penfwdata;
extern struct device *penfw_dev;
extern phys_addr_t penfwdata_phys;
void penfw_smc_get_chip_cert(struct penfw_call_args *args);
void penfw_smc_attest_get_time(struct penfw_call_args *args);

static const char *_opcode_to_str(uint8_t opcode)
{
	switch (opcode) {
	case PENFW_OP_GET_API_VER:
		return "PENFW_OP_GET_API_VER";
	case PENFW_OP_GET_PENTRUST_STA:
		return "PENFW_OP_GET_PENTRUST_STA";
	case PENFW_OP_SET_PENTRUST_UPG:
		return "PENFW_OP_SET_PENTRUST_UPG";
	case PENFW_OP_GET_BL1_STA:
		return "PENFW_OP_GET_BL1_STA";
	case PENFW_OP_SET_BL1_UPG:
		return "PENFW_OP_SET_BL1_UPG";
	case PENFW_OP_GET_BL1_AR_NVCNTR:
		return "PENFW_OP_GET_BL1_AR_NVCNTR";
	case PENFW_OP_COMMIT_BL1_AR_NVCNTR:
		return "PENFW_OP_COMMIT_BL1_AR_NVCNTR";
	case PENFW_OP_GET_BL31_SW_VER:
		return "PENFW_OP_GET_BL31_SW_VER";
	case PENFW_OP_GET_BOOT_LCS:
		return "PENFW_OP_GET_BOOT_LCS";
	case PENFW_OP_GET_NEXT_LCS:
		return "PENFW_OP_GET_NEXT_LCS";
	case PENFW_OP_COMMIT_LCS_PROD:
		return "PENFW_OP_COMMIT_LCS_PROD";
	case PENFW_OP_GET_PENTRUST_VERSION:
		return "PENFW_OP_GET_PENTRUST_VERSION";
	case PENFW_OP_GET_SERIAL_NUMBER:
		return "PENFW_OP_GET_SERIAL_NUMBER";
	case PENFW_OP_GET_RANDOM:
		return "PENFW_OP_GET_RANDOM";
	case PENFW_OP_GET_CHIP_CERT:
		return "PENFW_OP_GET_CHIP_CERT";
	case PENFW_OP_ATTEST_GET_TIME:
		return "PENFW_OP_ATTEST_GET_TIME";
	case PENFW_OP_GET_MMA_CLK:
		return "PENFW_OP_GET_MMA_CLK";
	case PENFW_OP_SET_ETH_PLL_CLK:
		return "PENFW_OP_SET_ETH_PLL_CLK";
	case PENFW_OP_ATOMIC_INC_AXI_LIMITER:
		return "PENFW_OP_ATOMIC_INC_AXI_LIMITER";
	case PENFW_OP_GET_SECURE_INTERRUPTS:
		return "PENFW_OP_GET_SECURE_INTERRUPTS";
	default:
		return "PENFW_OP_UNKNOWN";
	}
}

/*
 * a1 = smc op (PENFW_OP_GET_CHIP_CERT)
 * a2 = user buffer pointer to save the cert
 * a3 = length of the user buf to get the chip cert
 */
void penfw_smc_get_chip_cert(struct penfw_call_args *args)
{
	struct arm_smccc_res res = {0};
	uint8_t *chip_cert = NULL;
	phys_addr_t cert_phys = 0;
	uint32_t cert_len = 0;
	uint32_t user_cert_len = args->a3;
	void __user *user_cert = (void __user *)args->a2;

	if ((user_cert_len != 0) && (user_cert_len > PAGE_SIZE)) {
		args->a0 = -1;
		return;
	}

	chip_cert = (uint8_t *)penfwdata;
	cert_phys = penfwdata_phys;

	if (user_cert_len)
		cert_len = PAGE_SIZE;

	arm_smccc_smc(PENFW_CALL_FID, PENFW_OP_GET_CHIP_CERT, cert_phys,
					cert_len, 0, 0, 0, 0, &res);

	if (res.a1 > PAGE_SIZE) {
		args->a0 = -1;
		return;
	}

	if (user_cert_len) {
		if (res.a1 > user_cert_len) {
			args->a0 = -1;
			return;
		}
		if (copy_to_user(user_cert, chip_cert, res.a1)) {
			args->a0 = -1;
			return;
		}
	}

	/* zero-out chip-cert after copying to userspace */
	memset(penfwdata, 0, PAGE_SIZE);

	args->a0 = res.a0;
	args->a1 = res.a1;
	args->a2 = res.a2;
}

/*
 * a1 = smc op (PENFW_OP_ATTEST_GET_TIME)
 * a2 = pointer to user provided nonce.
 * a3 = length of nonce (must be 12 bytes)
 * a4 = pointer to user buffer for attestation data.
 * a5 = length of user attestation buffer
 */
void penfw_smc_attest_get_time(struct penfw_call_args *args)
{
	struct penfw_time_attestation *attp;
	struct arm_smccc_res res = {0};
	void __user *user_ta = (void  __user *)args->a4;
	uint8_t *nonce;
	phys_addr_t nonce_phys = 0, att_phys;

	nonce = (uint8_t *)penfwdata;
	nonce_phys = penfwdata_phys;

	attp = (struct penfw_time_attestation *)(penfwdata + PENFW_NONCE_LEN);
	att_phys = penfwdata_phys + PENFW_NONCE_LEN;

	if (args->a3 != PENFW_NONCE_LEN) {
		args->a0 = -1;
		return;
	}

	if (args->a5 < sizeof(struct penfw_time_attestation)) {
		args->a0 = -1;
		return;
	}

	if (copy_from_user(nonce, (void *)args->a2, PENFW_NONCE_LEN)) {
		args->a0 = -1;
		return;
	}

	arm_smccc_smc(PENFW_CALL_FID, PENFW_OP_ATTEST_GET_TIME,
		(uint64_t)nonce_phys, PENFW_NONCE_LEN,
		(uint64_t)att_phys, sizeof(*attp), 0, 0, &res);

	if (res.a0 == 0) {
		if (copy_to_user(user_ta, attp, sizeof(*attp))) {
			args->a0 = -5;
			return;
		}
	}

	args->a0 = res.a0;
	args->a1 = res.a1;
	args->a2 = res.a2;
	args->a3 = res.a3;

	/* zero out nonce and attestation data after copying to userspace */
	memset(penfwdata, 0, PAGE_SIZE);
}

/*
 * a1 = smc op (PENFW_OP_GET_SECURE_INTERRUPTS)
 * a2 = pointer to user provided interrupt structure.
 */
void penfw_smc_get_secure_intrs(struct penfw_call_args *args)
{
	uint32_t len = 0;
	struct arm_smccc_res res = {0};
	struct penfw_secure_intrs u_intrs;
	struct penfw_secure_intrs *intrs = penfwdata;
	struct penfw_intrreg *intr_regs_phys;
	struct penfw_intrreg *intr_regs = (struct penfw_intrreg *)((uint8_t *)penfwdata + sizeof(struct penfw_secure_intrs));
	void __user *user_intrs_addr = (void  __user *)args->a2;

	// copied struct from user space
	if (copy_from_user(&u_intrs, user_intrs_addr, sizeof(struct penfw_secure_intrs))) {
		args->a0 = -1;
		return;
	}

	intrs->num_intr_regs = u_intrs.num_intr_regs;
	// now copy the array of interrupts
	len = sizeof(struct penfw_intrreg) * u_intrs.num_intr_regs;
	if (len > PAGE_SIZE) {
		args->a0 = -1;
		return;
	}
	if (copy_from_user(intr_regs, u_intrs.intr_regs, len)) {
		args->a0 = -1;
		return;
	}

	intr_regs_phys = (struct penfw_intrreg *)(penfwdata_phys + sizeof(struct penfw_secure_intrs));
	intrs->intr_regs = intr_regs_phys;

	arm_smccc_smc(PENFW_CALL_FID, PENFW_OP_GET_SECURE_INTERRUPTS,
			(uint64_t)penfwdata_phys, 0, 0, 0, 0, 0, &res);

	if (res.a0 == 0) {
		if (copy_to_user(u_intrs.intr_regs, intr_regs, len)) {
			args->a0 = -5;
			return;
		}
	}

	args->a0 = res.a0;
	args->a1 = res.a1;
	args->a2 = res.a2;
	args->a3 = res.a3;

	/* zero out interrupts data after copying to userspace */
	memset(penfwdata, 0, PAGE_SIZE);
}

void penfw_smc(struct penfw_call_args *args)
{
	struct arm_smccc_res res = {0};

	dev_dbg(penfw_dev, "penfw: smc call for fn: %s\n",
		 _opcode_to_str(args->a1));

	switch (args->a1) {
	case PENFW_OP_GET_API_VER:
	case PENFW_OP_GET_PENTRUST_STA:
	case PENFW_OP_SET_PENTRUST_UPG:
	case PENFW_OP_GET_BL1_STA:
	case PENFW_OP_SET_BL1_UPG:
	case PENFW_OP_GET_BL1_AR_NVCNTR:
	case PENFW_OP_COMMIT_BL1_AR_NVCNTR:
	case PENFW_OP_GET_BL31_SW_VER:
	case PENFW_OP_GET_BOOT_LCS:
	case PENFW_OP_GET_NEXT_LCS:
	case PENFW_OP_COMMIT_LCS_PROD:
	case PENFW_OP_GET_PENTRUST_VERSION:
	case PENFW_OP_GET_SERIAL_NUMBER:
	case PENFW_OP_GET_RANDOM:
	case PENFW_OP_GET_MMA_CLK:
	case PENFW_OP_SET_ETH_PLL_CLK:
		arm_smccc_smc(PENFW_CALL_FID, args->a1, args->a2, args->a3, 0, 0,
						0, 0, &res);
		// copy return vals
		args->a0 = res.a0;
		args->a1 = res.a1;
		args->a2 = res.a2;
		args->a3 = res.a3;
		break;
	case PENFW_OP_GET_CHIP_CERT:
		penfw_smc_get_chip_cert(args);
		break;
	case PENFW_OP_ATTEST_GET_TIME:
		penfw_smc_attest_get_time(args);
		break;
	case PENFW_OP_GET_SECURE_INTERRUPTS:
		penfw_smc_get_secure_intrs(args);
		break;
	case PENFW_OP_ATOMIC_INC_AXI_LIMITER:
		// deprecated, do nothing
		break;
	default:
		break;
	}

	dev_dbg(penfw_dev, "penfw: smc return a0: 0x%llx a1: 0x%llx "\
		 "a2: 0x%llx a3: 0x%llx\n", args->a0, args->a1,
		 args->a2, args->a3);
}

long penfw_svc_smc(penfw_svc_args_t *args)
{
	struct arm_smccc_res res = { 0 };
	void *cfg = NULL;
	void *cfg_out = NULL;
	phys_addr_t cfg_phys = 0;
	phys_addr_t cfg_phys_out = 0;
	long ret = 0;

	if (args->length_in != 0) {
		cfg = (void *)__get_free_pages((GFP_KERNEL | GFP_ATOMIC | __GFP_ZERO),
						get_order(args->length_in));
		if (cfg == NULL) {
			dev_err(penfw_dev, "penfw svc memory allocation failed\n");
			ret = -ENOMEM;
			goto err;
		}
		cfg_phys = virt_to_phys(cfg);
		if (copy_from_user(cfg, (void __user *)args->value,
					args->length_in)) {
			dev_err(penfw_dev, "Unable to copy argument %llx "
				"from user for smc cmd(%llx/%llx)\n", args->value,
				args->func_id, args->sub_func_id);
			ret = -EFAULT;
			goto err;
		}
	}
	if (args->length_out != 0) {
		cfg_out = (void *)__get_free_pages((GFP_KERNEL | GFP_ATOMIC | __GFP_ZERO),
						get_order(args->length_out));
		if (cfg_out == NULL) {
			dev_err(penfw_dev,
				"penfw svc out memory allocation failed\n");
			ret = -ENOMEM;
			goto err;
		}
		cfg_phys_out = virt_to_phys(cfg_out);
	}
	arm_smccc_smc(args->func_id, args->sub_func_id, cfg_phys,
			cfg_phys_out, 0, 0, 0, 0, &res);
	// copy back to user only if SMC operation is successful
	if ((res.a0 == 0) && args->length_out) {
		if (res.a1 <= args->length_out) {
			if (copy_to_user((void __user *)args->value, cfg_out,
						res.a1)) {
				dev_err(penfw_dev, "copy to user failed\n");
				ret = -EFAULT;
				goto err;
			}
		} else {
			dev_err(penfw_dev,
				"penfw svc out memory allocation not enough\n");
			ret = -EINVAL;
			goto err;
		}
		args->length_out = res.a1;
	}
	args->status = res.a0;

err:
	if (cfg_out) {
		free_pages((unsigned long)cfg_out, get_order(args->length_out));
	}
	if (cfg) {
		free_pages((unsigned long)cfg, get_order(args->length_in));
	}

	return ret;
}
