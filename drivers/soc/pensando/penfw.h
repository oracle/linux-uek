/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021, Pensando Systems Inc.
 */

#ifndef __PENFW_H__
#define __PENFW_H__

enum penfw_opcodes {
	PENFW_OP_GET_API_VER = 0,
	PENFW_OP_GET_PENTRUST_STA,
	PENFW_OP_SET_PENTRUST_UPG,
	PENFW_OP_GET_BL1_STA,
	PENFW_OP_SET_BL1_UPG,
	PENFW_OP_GET_BL1_AR_NVCNTR,
	PENFW_OP_COMMIT_BL1_AR_NVCNTR,
	PENFW_OP_GET_BL31_SW_VER,
	PENFW_OP_GET_BOOT_LCS,
	PENFW_OP_GET_NEXT_LCS,
	PENFW_OP_COMMIT_LCS_PROD,
	PENFW_OP_GET_PENTRUST_VERSION,
	PENFW_OP_GET_SERIAL_NUMBER,
	PENFW_OP_GET_RANDOM,
	PENFW_OP_GET_CHIP_CERT,
	PENFW_OP_ATTEST_GET_TIME,
	PENFW_OPCODE_MAX,
};

struct penfw_call_args {
	int64_t a0;
	uint64_t a1;
	uint64_t a2;
	uint64_t a3;
	uint64_t a4;
	uint64_t a5;
};

#define PENFW_NONCE_LEN 12
#define PENFW_EC_SIG_SZ 96

struct penfw_time_attestation {
	struct {
		uint32_t magic;
		uint8_t nonce[PENFW_NONCE_LEN];
		uint64_t time;
	} data;
	struct {
		uint8_t	r[PENFW_EC_SIG_SZ / 2];
		uint8_t	s[PENFW_EC_SIG_SZ / 2];
	} signature;
};


#define PENFW_IOCTL_NUM  0xcd
#define PENFW_FWCALL     _IOWR(PENFW_IOCTL_NUM, 1, struct penfw_call_args)

void penfw_smc(struct penfw_call_args *args);

#endif /* __PENFW_H__ */
