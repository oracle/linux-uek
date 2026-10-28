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
	// TODO: add support for sub-ops 16-23 and 25-36.
	// Values should match SDK pal_fw.h and ATF sub-FIDs, these are common to Elba and Salina
	PENFW_OP_GET_SECURE_INTERRUPTS = 24,
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

struct penfw_intrreg {
	// input
	uint64_t addr;
	// output
	uint32_t value;
	uint32_t valid;
};

struct penfw_secure_intrs {
	uint32_t num_intr_regs;
	struct penfw_intrreg *intr_regs;
};

/*
 * penfw_svc_args - UAPI structure for PENFW_SVC ioctl
 *
 * This struct uses explicit padding (reserved1/reserved2) to ensure
 * all fields are naturally aligned. The __attribute__((packed)) prevents
 * any compiler from adding additional implicit padding, guaranteeing
 * the layout is consistent across all toolchains and architectures.
 */
struct penfw_svc_args {
	__u64 func_id;
	__u64 sub_func_id;
	__u16 length_in;
	__u16 reserved1[3];	// explicit padding for natural alignment
	__u64 value;		// pointer to input/output data
	__u16 length_out;
	__u16 reserved2[3];	// explicit padding for natural alignment
	__s64 status;		// status of the smc operation
} __attribute__((packed));

/* Build-time layout verification */
static_assert(sizeof(struct penfw_svc_args) == 48);
static_assert(offsetof(struct penfw_svc_args, value) == 24);
static_assert(offsetof(struct penfw_svc_args, status) == 40);

#define PENFW_IOCTL_NUM  0xcd
#define PENFW_FWCALL     _IOWR(PENFW_IOCTL_NUM, 1, struct penfw_call_args)
#define PENFW_SVC        _IOWR(PENFW_IOCTL_NUM, 2, struct penfw_svc_args)

void penfw_smc(struct penfw_call_args *args);
long penfw_svc_smc(struct penfw_svc_args *args);

extern struct device *penfw_dev;
extern void *penfwdata;
extern phys_addr_t penfwdata_phys;

#endif /* __PENFW_H__ */
