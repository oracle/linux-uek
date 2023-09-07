/*
 * Copyright (c) 2021, Pensando Systems Inc.
 */

#include <linux/string.h>
#include <linux/arm-smccc.h>
#include <linux/printk.h>
#include <linux/types.h>

#include "penfw.h"

#define PENFW_CALL_FID			    0xC2000002

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
	default:
		return "PENFW_OP_UNKNOWN";
	}
}

void penfw_smc(struct penfw_call_args *args)
{
	struct arm_smccc_res res = {0};

	pr_debug("penfw: smc call for fn: %s\n",
		_opcode_to_str(args->a1));

	arm_smccc_smc(PENFW_CALL_FID, args->a1, args->a2, args->a3, 0, 0,
		      0, 0, &res);

	// copy return vals
	args->a0 = res.a0;
	args->a1 = res.a1;
	args->a2 = res.a2;
	args->a3 = res.a3;

	pr_debug("penfw: smc return a0: 0x%llx a1: 0x%llx "
		"a2: 0x%llx a3: 0x%llx\n", args->a0, args->a1,
					   args->a2, args->a3);
}
