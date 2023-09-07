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
	PENFW_OPCODE_MAX,
};

struct penfw_call_args {
	int64_t a0;
	uint64_t a1;
	uint64_t a2;
	uint64_t a3;
};

#define PENFW_IOCTL_NUM  0xcd
#define PENFW_FWCALL     _IOWR(PENFW_IOCTL_NUM, 1, struct penfw_call_args)

void penfw_smc(struct penfw_call_args *args);

#endif /* __PENFW_H__ */
