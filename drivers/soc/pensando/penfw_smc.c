// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021, Pensando Systems Inc.
 */

#include <linux/device.h>
#include <linux/dma-map-ops.h>
#include <linux/string.h>
#include <linux/arm-smccc.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/sizes.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#include "penfw.h"

#define PENFW_CALL_FID			    0xC2000002
#define PENFW_DICE_CALL_FID		    0xC2000009

/* Max combined sign_ctx + aux_data + data length for DICE SIGN_DATA */
#define PENFW_DICE_SIGN_MAX_IN_LEN	    SZ_64K

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
static void penfw_smc_get_chip_cert(struct penfw_call_args *args)
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
static void penfw_smc_attest_get_time(struct penfw_call_args *args)
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
static void penfw_smc_get_secure_intrs(struct penfw_call_args *args)
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

	if (u_intrs.num_intr_regs >
		(PAGE_SIZE - sizeof(*intrs)) / sizeof(struct penfw_intrreg)) {
		args->a0 = -1;
		return;
	}
	intrs->num_intr_regs = u_intrs.num_intr_regs;
	len = sizeof(struct penfw_intrreg) * u_intrs.num_intr_regs;
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

	pr_debug("penfw: smc call for fn: %s\n",
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
	default:
		break;
	}

	pr_debug("penfw: smc return a0: 0x%llx a1: 0x%llx a2: 0x%llx a3: 0x%llx\n",
		 args->a0, args->a1, args->a2, args->a3);
}

long penfw_svc_smc(struct penfw_svc_args *args)
{
	struct arm_smccc_res res = { 0 };
	void *cfg = NULL;
	void *cfg_out = NULL;
	phys_addr_t cfg_phys = 0;
	phys_addr_t cfg_phys_out = 0;
	long ret = 0;
	size_t length_in = args->length_in;
	size_t length_out = args->length_out;

	if (length_in != 0) {
		cfg = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
						get_order(length_in));
		if (cfg == NULL) {
			dev_err(penfw_dev, "penfw svc memory allocation failed\n");
			ret = -ENOMEM;
			goto err;
		}
		cfg_phys = virt_to_phys(cfg);
		if (copy_from_user(cfg, (void __user *)args->value,
				   length_in)) {
			dev_err(penfw_dev, "Unable to copy argument %llx from user for smc cmd(%llx/%llx)\n",
				args->value, args->func_id, args->sub_func_id);
			ret = -EFAULT;
			goto err;
		}
	}
	if (length_out != 0) {
		cfg_out = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO,
						get_order(length_out));
		if (cfg_out == NULL) {
			dev_err(penfw_dev,
				"penfw svc out memory allocation failed\n");
			ret = -ENOMEM;
			goto err;
		}
		cfg_phys_out = virt_to_phys(cfg_out);
	}
	arm_smccc_smc(args->func_id, args->sub_func_id, cfg_phys,
		      cfg_phys_out, length_in, length_out, 0, 0, &res);
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
	if (cfg_out)
		free_pages((unsigned long)cfg_out, get_order(length_out));
	if (cfg)
		free_pages((unsigned long)cfg, get_order(length_in));

	return ret;
}

/*
 * DICE GET_CERTIFICATE handler
 *
 * Copies pen_dice_cert_req from userspace, allocates a kernel buffer for
 * the certificate data, patches the cert_buff pointer to a physical address,
 * places the request struct in penfwdata, and calls ATF.
 * ATF returns: x0 = status, x1 = remaining_len, x2 = out_buff_len.
 */
static long penfw_smc_dice_get_cert(struct penfw_dice_args *args)
{
	struct arm_smccc_res res = {0};
	struct pen_dice_cert_req req;
	void __user *user_req = (void __user *)args->req;
	void __user *user_cert;
	void *cert_kern = NULL;
	phys_addr_t cert_phys;
	struct pen_dice_cert_req *smc_req;
	long ret = 0;

	if (copy_from_user(&req, user_req, sizeof(req)))
		return -EFAULT;

	user_cert = (void __user *)req.cert_buff;

	if (req.chunk_size == 0 || req.chunk_size > PAGE_SIZE)
		return -EINVAL;

	/* Allocate kernel buffer for cert data (no __GFP_ZERO — DMA will fill it) */
	cert_kern = (void *)__get_free_pages(GFP_KERNEL | GFP_DMA32,
					     get_order(req.chunk_size));
	if (!cert_kern)
		return -ENOMEM;
	cert_phys = virt_to_phys(cert_kern);

	/* Build ATF request struct in penfwdata with physical address */
	smc_req = (struct pen_dice_cert_req *)penfwdata;
	smc_req->chunk_size = req.chunk_size;
	smc_req->offset = req.offset;
	smc_req->cert_buff = cert_phys;

	/* Clean+invalidate cert buffer before DMA to flush any dirty cache lines */
	arch_sync_dma_for_device(cert_phys, req.chunk_size, DMA_FROM_DEVICE);

	arm_smccc_smc(PENFW_DICE_CALL_FID, PENFW_DICE_GET_CERTIFICATE,
		      (uint64_t)penfwdata_phys, 0, 0, 0, 0, 0, &res);

	/* Invalidate cache after eSec DMA so CPU sees fresh data */
	arch_sync_dma_for_cpu(cert_phys, req.chunk_size, DMA_FROM_DEVICE);

	args->rc = res.a0;
	args->out1 = res.a1;  /* remaining_len */
	args->out2 = res.a2;  /* out_buff_len */

	/* Copy cert data back to userspace if successful */
	if (res.a0 == 0 && res.a2 > 0) {
		if (res.a2 > req.chunk_size)
			ret = -EIO;
		else if (copy_to_user(user_cert, cert_kern, res.a2))
			ret = -EFAULT;
	}

	free_pages((unsigned long)cert_kern, get_order(req.chunk_size));
	memset(penfwdata, 0, PAGE_SIZE);

	return ret;
}

/*
 * DICE SIGN_DATA handler
 *
 * Copies pen_dice_sign_data_req from userspace, allocates kernel buffers
 * for all embedded data pointers, patches them to physical addresses,
 * places the request struct in penfwdata, and calls ATF.
 */
static long penfw_smc_dice_sign_data(struct penfw_dice_args *args)
{
	struct arm_smccc_res res = {0};
	struct pen_dice_sign_data_req req;
	void __user *user_req = (void __user *)args->req;
	void __user *user_sign_ctx, *user_aux_data, *user_in_data, *user_sig;
	size_t total_in, total_out;
	void *buf_in = NULL, *buf_out = NULL;
	phys_addr_t buf_in_phys, buf_out_phys;
	uint32_t off;
	struct pen_dice_sign_data_req *smc_req;
	long ret = 0;

	if (copy_from_user(&req, user_req, sizeof(req)))
		return -EFAULT;

	user_sign_ctx = (void __user *)req.sign_ctx;
	user_aux_data = (void __user *)req.aux_data;
	user_in_data = (void __user *)req.in_data;
	user_sig = (void __user *)req.signature;

	/* Calculate total input buffer size needed (64-bit, cannot overflow) */
	total_in = (size_t)req.sign_ctx_len + req.aux_data_len + req.data_len;
	total_out = req.out_len_max;

	if (total_in == 0 || total_in > PENFW_DICE_SIGN_MAX_IN_LEN ||
	    total_out == 0 || total_out > PAGE_SIZE)
		return -EINVAL;

	/* Allocate kernel buffer for input data */
	buf_in = (void *)__get_free_pages(GFP_KERNEL | GFP_DMA32 | __GFP_ZERO,
					  get_order(total_in));
	if (!buf_in)
		return -ENOMEM;
	buf_in_phys = virt_to_phys(buf_in);

	/*
	 * Allocate kernel buffer for output (signature). Zero it, since all
	 * out_len_max bytes are copied to userspace but eSec may write fewer.
	 */
	buf_out = (void *)__get_free_pages(GFP_KERNEL | GFP_DMA32 | __GFP_ZERO,
					   get_order(total_out));
	if (!buf_out) {
		ret = -ENOMEM;
		goto out;
	}
	buf_out_phys = virt_to_phys(buf_out);

	/* Copy input data from userspace into contiguous kernel buffer */
	off = 0;
	if (copy_from_user(buf_in + off, user_sign_ctx, req.sign_ctx_len)) {
		ret = -EFAULT;
		goto out;
	}
	off += req.sign_ctx_len;

	if (req.aux_data_len > 0) {
		if (copy_from_user(buf_in + off, user_aux_data,
				   req.aux_data_len)) {
			ret = -EFAULT;
			goto out;
		}
	}
	off += req.aux_data_len;

	if (copy_from_user(buf_in + off, user_in_data, req.data_len)) {
		ret = -EFAULT;
		goto out;
	}

	/* Build ATF request struct in penfwdata with physical addresses */
	smc_req = (struct pen_dice_sign_data_req *)penfwdata;
	smc_req->sign_ctx = buf_in_phys;
	smc_req->sign_ctx_len = req.sign_ctx_len;
	smc_req->aux_data = req.aux_data_len ?
		(buf_in_phys + req.sign_ctx_len) : 0;
	smc_req->aux_data_len = req.aux_data_len;
	smc_req->in_data = buf_in_phys + req.sign_ctx_len +
			   req.aux_data_len;
	smc_req->data_len = req.data_len;
	smc_req->signature = buf_out_phys;
	smc_req->out_len_max = req.out_len_max;

	/* Clean input data to PoC so eSec DMA reads what userspace provided */
	arch_sync_dma_for_device(buf_in_phys, total_in, DMA_TO_DEVICE);

	/* Clean+invalidate signature buffer before DMA */
	arch_sync_dma_for_device(buf_out_phys, total_out, DMA_FROM_DEVICE);

	arm_smccc_smc(PENFW_DICE_CALL_FID, PENFW_DICE_SIGN_DATA,
		      (uint64_t)penfwdata_phys, 0, 0, 0, 0, 0, &res);

	/* Invalidate cache after eSec DMA so CPU sees fresh data */
	arch_sync_dma_for_cpu(buf_out_phys, total_out, DMA_FROM_DEVICE);

	args->rc = res.a0;

	/* Copy signature back to userspace if successful */
	if (res.a0 == 0) {
		if (copy_to_user(user_sig, buf_out, req.out_len_max))
			ret = -EFAULT;
	}

out:
	if (buf_out)
		free_pages((unsigned long)buf_out, get_order(total_out));
	if (buf_in)
		free_pages((unsigned long)buf_in, get_order(total_in));
	memset(penfwdata, 0, PAGE_SIZE);

	return ret;
}

/*
 * DICE GET_MEASUREMENT handler
 *
 * Copies pen_dice_get_meas_req from userspace, allocates a kernel buffer
 * for measurement data, patches meas_buf to physical address, places
 * the request struct in penfwdata, and calls ATF.
 * ATF returns: x0 = status, x1 = algo.
 */
static long penfw_smc_dice_get_meas(struct penfw_dice_args *args)
{
	struct arm_smccc_res res = {0};
	struct pen_dice_get_meas_req req;
	void __user *user_req = (void __user *)args->req;
	void __user *user_meas;
	void *meas_kern = NULL;
	phys_addr_t meas_phys;
	struct pen_dice_get_meas_req *smc_req;
	long ret = 0;

	if (copy_from_user(&req, user_req, sizeof(req)))
		return -EFAULT;

	user_meas = (void __user *)req.meas_buf;

	if (req.meas_buf_len == 0 || req.meas_buf_len > PAGE_SIZE)
		return -EINVAL;

	/* Allocate kernel buffer for measurement data */
	meas_kern = (void *)__get_free_pages(GFP_KERNEL | GFP_DMA32 | __GFP_ZERO,
					     get_order(req.meas_buf_len));
	if (!meas_kern)
		return -ENOMEM;
	meas_phys = virt_to_phys(meas_kern);

	/* Build ATF request struct in penfwdata with physical address */
	smc_req = (struct pen_dice_get_meas_req *)penfwdata;
	smc_req->meas_id = req.meas_id;
	smc_req->meas_buf_len = req.meas_buf_len;
	smc_req->meas_buf = meas_phys;

	arm_smccc_smc(PENFW_DICE_CALL_FID, PENFW_DICE_GET_MEASUREMENT,
		      (uint64_t)penfwdata_phys, 0, 0, 0, 0, 0, &res);

	args->rc = res.a0;
	args->out1 = res.a1;  /* algo */

	/* Copy measurement data back to userspace if successful */
	if (res.a0 == 0) {
		if (copy_to_user(user_meas, meas_kern, req.meas_buf_len))
			ret = -EFAULT;
	}

	free_pages((unsigned long)meas_kern, get_order(req.meas_buf_len));
	memset(penfwdata, 0, PAGE_SIZE);

	return ret;
}

/*
 * DICE SET_MEASUREMENT handler
 *
 * Copies pen_dice_set_meas_req from userspace, copies digest data into
 * kernel buffer, patches meas_buf to physical address, places the
 * request struct in penfwdata, and calls ATF.
 */
static long penfw_smc_dice_set_meas(struct penfw_dice_args *args)
{
	struct arm_smccc_res res = {0};
	struct pen_dice_set_meas_req req;
	void __user *user_req = (void __user *)args->req;
	void *meas_kern = NULL;
	phys_addr_t meas_phys;
	struct pen_dice_set_meas_req *smc_req;

	if (copy_from_user(&req, user_req, sizeof(req)))
		return -EFAULT;

	if (req.meas_buf_len == 0 || req.meas_buf_len > PAGE_SIZE)
		return -EINVAL;

	/* Allocate kernel buffer for digest data */
	meas_kern = (void *)__get_free_pages(GFP_KERNEL | GFP_DMA32 | __GFP_ZERO,
					     get_order(req.meas_buf_len));
	if (!meas_kern)
		return -ENOMEM;
	meas_phys = virt_to_phys(meas_kern);

	/* Copy digest from userspace */
	if (copy_from_user(meas_kern, (void __user *)req.meas_buf,
			   req.meas_buf_len)) {
		free_pages((unsigned long)meas_kern,
			   get_order(req.meas_buf_len));
		return -EFAULT;
	}

	/* Build ATF request struct in penfwdata with physical address */
	smc_req = (struct pen_dice_set_meas_req *)penfwdata;
	smc_req->meas_id = req.meas_id;
	smc_req->algo = req.algo;
	smc_req->meas_buf_len = req.meas_buf_len;
	smc_req->meas_buf = meas_phys;

	arm_smccc_smc(PENFW_DICE_CALL_FID, PENFW_DICE_SET_MEASUREMENT,
		      (uint64_t)penfwdata_phys, 0, 0, 0, 0, 0, &res);

	args->rc = res.a0;

	free_pages((unsigned long)meas_kern, get_order(req.meas_buf_len));
	memset(penfwdata, 0, PAGE_SIZE);

	return 0;
}

/*
 * Returns 0 or a negative errno for failures detected in the kernel.
 * The ATF status of the SMC itself is returned in args->rc.
 */
long penfw_dice_smc(struct penfw_dice_args *args)
{
	long ret;

	pr_debug("penfw: dice smc call for func: %u\n", args->func);

	switch (args->func) {
	case PENFW_DICE_GET_CERTIFICATE:
		ret = penfw_smc_dice_get_cert(args);
		break;
	case PENFW_DICE_SIGN_DATA:
		ret = penfw_smc_dice_sign_data(args);
		break;
	case PENFW_DICE_GET_MEASUREMENT:
		ret = penfw_smc_dice_get_meas(args);
		break;
	case PENFW_DICE_SET_MEASUREMENT:
		ret = penfw_smc_dice_set_meas(args);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	pr_debug("penfw: dice smc return ret: %ld rc: %lld out1: 0x%llx out2: 0x%llx\n",
		 ret, args->rc, args->out1, args->out2);

	return ret;
}
