/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2020 Apertus Solutions, LLC
 *
 * Author(s):
 *      Daniel P. Smith <dpsmith@apertussolutions.com>
 *
 * The definitions in this header are extracted from the Trusted Computing
 * Group's "TPM Main Specification", Parts 1-3.
 *
 */

#ifndef _TPM1_H
#define _TPM1_H

#include "tpm.h"

/* Section 2.2.3 */
#define TPM_AUTH_DATA_USAGE u8
#define TPM_PAYLOAD_TYPE u8
#define TPM_VERSION_BYTE u8
#define TPM_TAG u16
#define TPM_PROTOCOL_ID u16
#define TPM_STARTUP_TYPE u16
#define TPM_ENC_SCHEME u16
#define TPM_SIG_SCHEME u16
#define TPM_MIGRATE_SCHEME u16
#define TPM_PHYSICAL_PRESENCE u16
#define TPM_ENTITY_TYPE u16
#define TPM_KEY_USAGE u16
#define TPM_EK_TYPE u16
#define TPM_STRUCTURE_TAG u16
#define TPM_PLATFORM_SPECIFIC u16
#define TPM_COMMAND_CODE u32
#define TPM_CAPABILITY_AREA u32
#define TPM_KEY_FLAGS u32
#define TPM_ALGORITHM_ID u32
#define TPM_MODIFIER_INDICATOR u32
#define TPM_ACTUAL_COUNT u32
#define TPM_TRANSPORT_ATTRIBUTES u32
#define TPM_AUTHHANDLE u32
#define TPM_DIRINDEX u32
#define TPM_KEY_HANDLE u32
#define TPM_PCRINDEX u32
#define TPM_RESULT u32
#define TPM_RESOURCE_TYPE u32
#define TPM_KEY_CONTROL u32
#define TPM_NV_INDEX u32 The
#define TPM_FAMILY_ID u32
#define TPM_FAMILY_VERIFICATION u32
#define TPM_STARTUP_EFFECTS u32
#define TPM_SYM_MODE u32
#define TPM_FAMILY_FLAGS u32
#define TPM_DELEGATE_INDEX u32
#define TPM_CMK_DELEGATE u32
#define TPM_COUNT_ID u32
#define TPM_REDIT_COMMAND u32
#define TPM_TRANSHANDLE u32
#define TPM_HANDLE u32
#define TPM_FAMILY_OPERATION u32

/* Section 6 */
#define TPM_TAG_RQU_COMMAND		0x00C1
#define TPM_TAG_RQU_AUTH1_COMMAND	0x00C2
#define TPM_TAG_RQU_AUTH2_COMMAND	0x00C3
#define TPM_TAG_RSP_COMMAND		0x00C4
#define TPM_TAG_RSP_AUTH1_COMMAND	0x00C5
#define TPM_TAG_RSP_AUTH2_COMMAND	0x00C6

/* Section 16 */
#define TPM_SUCCESS 0x0

/* Section 17 */
#define TPM_ORD_EXTEND			0x00000014

#define SHA1_DIGEST_SIZE 20

/* Section 5.4 */
struct tpm_sha1_digest {
	u8 digest[SHA1_DIGEST_SIZE];
};
struct tpm_digest {
	TPM_PCRINDEX pcr;
	union {
		struct tpm_sha1_digest sha1;
	} digest;
};

#define TPM_DIGEST		struct tpm_sha1_digest
#define TPM_CHOSENID_HASH	TPM_DIGEST
#define TPM_COMPOSITE_HASH	TPM_DIGEST
#define TPM_DIRVALUE		TPM_DIGEST
#define TPM_HMAC		TPM_DIGEST
#define TPM_PCRVALUE		TPM_DIGEST
#define TPM_AUDITDIGEST		TPM_DIGEST
#define TPM_DAA_TPM_SEED	TPM_DIGEST
#define TPM_DAA_CONTEXT_SEED	TPM_DIGEST

struct tpm_extend_cmd {
	TPM_PCRINDEX pcr_num;
	TPM_DIGEST digest;
};

struct tpm_extend_resp {
	TPM_COMMAND_CODE ordinal;
	TPM_PCRVALUE digest;
};

/* TPM Commands */
int tpm1_pcr_extend(struct tpm *t, struct tpm_digest *d);

#endif
