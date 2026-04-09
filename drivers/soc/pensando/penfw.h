/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2021, Pensando Systems Inc.
 */

#ifndef __PENFW_H__
#define __PENFW_H__

#define	PENFW_OP_GET_API_VER				0
#define	PENFW_OP_GET_PENTRUST_STA			1
#define	PENFW_OP_SET_PENTRUST_UPG			2
#define	PENFW_OP_GET_BL1_STA				3
#define	PENFW_OP_SET_BL1_UPG				4
#define	PENFW_OP_GET_BL1_AR_NVCNTR			5
#define	PENFW_OP_COMMIT_BL1_AR_NVCNTR		6
#define	PENFW_OP_GET_BL31_SW_VER			7
#define	PENFW_OP_GET_BOOT_LCS				8
#define	PENFW_OP_GET_NEXT_LCS				9

#define	PENFW_OP_COMMIT_LCS_PROD			10
#define	PENFW_OP_GET_PENTRUST_VERSION		11
#define	PENFW_OP_GET_SERIAL_NUMBER			12
#define	PENFW_OP_GET_RANDOM					13
#define	PENFW_OP_GET_CHIP_CERT				14
#define	PENFW_OP_ATTEST_GET_TIME			15
#define	PENFW_OP_GET_PENTRUST_AR_NVCNTR		16
#define	PENFW_OP_COMMIT_PENTRUST_AR_NVCNTR	17
#define	PENFW_OP_GET_HMAC					18
#define	PENFW_OP_GET_SM_LOG					19

#define	PENFW_OP_BSM_SET_RUNNING			20
#define	PENFW_OP_GET_MMA_CLK				21
#define	PENFW_OP_SET_ETH_PLL_CLK			22
#define	PENFW_OP_ATOMIC_INC_AXI_LIMITER		23
#define	PENFW_OP_GET_SECURE_INTERRUPTS		24
#define	PENFW_OP_GET_CERT_CHAIN				25
#define	PENFW_OP_SET_MEAS					26
#define	PENFW_OP_ATTEST_MEAS				27
#define	PENFW_OP_SET_PCIE_PLL_CLK			28
#define	PENFW_OP_ENABLE_SERDES_IROM			29

#define	PENFW_OP_GET_BSM_STATE				30
#define	PENFW_OP_GET_RESET_CAUSE			31
#define	PENFW_OP_SET_RESET_CAUSE			32
#define	PENFW_OP_SET_BSM_STATE				33
#define	PENFW_OP_PCIEPORT_DOWNLOAD_FW		34

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

typedef struct penfw_svc_args_s {
	uint64_t func_id;
	uint64_t sub_func_id;
	uint16_t length_in;
	uint64_t value;		// pointer to input/output data
	uint16_t length_out;
	uint64_t status;	// status of the smc operation
} penfw_svc_args_t;

#define PENFW_IOCTL_NUM  0xcd
#define PENFW_FWCALL     _IOWR(PENFW_IOCTL_NUM, 1, struct penfw_call_args)
#define PENFW_SVC        _IOWR(PENFW_IOCTL_NUM, 2, penfw_svc_args_t)

void penfw_smc(struct penfw_call_args *args);
long penfw_svc_smc(penfw_svc_args_t *args);

#define PENFW_CERT_CHAIN_MAX_LEN  4096

struct penfw_get_cert_chain_req {
	uint32_t chunk_size;
	uint32_t offset;
	uint64_t cert_buff;	/* physical address of chunk data area */
};

struct penfw_attest_meas_req {
	uint8_t  nonce[PENFW_NONCE_LEN];
	uint8_t *meas_buf;
	uint32_t meas_buflen;
	uint8_t *sig;
	uint32_t siglen;
};

#define PENFW_MEAS_DIGEST_LEN	64

struct penfw_meas {
	uint32_t meas_id;
	uint32_t hash_fct;
	uint8_t  meas_value[PENFW_MEAS_DIGEST_LEN];
};

struct penfw_meas_resp_hdr {
	uint32_t magic_number;
	uint32_t version;
	uint8_t  nonce[PENFW_NONCE_LEN];
	uint32_t resp_len;
};

struct penfw_meas_resp {
	struct penfw_meas_resp_hdr hdr;
	uint32_t sig_algo;
	uint32_t sig_len;
	uint32_t meas_count;
	struct penfw_meas meas[0];
};

#endif /* __PENFW_H__ */
