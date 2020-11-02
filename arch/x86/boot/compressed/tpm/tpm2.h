/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2020 Apertus Solutions, LLC
 *
 * Author(s):
 *      Daniel P. Smith <dpsmith@apertussolutions.com>
 *
 * The definitions in this header are extracted and/or dervied from the
 * Trusted Computing Group's TPM 2.0 Library Specification Parts 1&2.
 *
 */

#ifndef _TPM2_H
#define _TPM2_H

#include "tpm_common.h"
#include "tpm2_constants.h"


/* Table 192  Definition of TPM2B_TEMPLATE Structure:
 *   Using this as the base structure similar to the spec
 */
struct tpm2b {
	u16 size;
	u8 buffer[0];
};

// Table 32  Definition of TPMA_SESSION Bits <  IN/OUT>
struct tpma_session {
	u8 continue_session  : 1;
	u8 audit_exclusive   : 1;
	u8 audit_reset       : 1;
	u8 reserved3_4       : 2;
	u8 decrypt           : 1;
	u8 encrypt           : 1;
	u8 audit             : 1;
};


// Table 72  Definition of TPMT_HA Structure <  IN/OUT>
struct tpmt_ha {
	u16 alg;	/* TPMI_ALG_HASH	*/
	u8 digest[0];	/* TPMU_HA		*/
};

// Table 100  Definition of TPML_DIGEST_VALUES Structure
struct tpml_digest_values {
	u32 count;
	struct tpmt_ha digests[0];
};


// Table 124  Definition of TPMS_AUTH_COMMAND Structure <  IN>
struct tpms_auth_cmd {
	u32 *handle;
	struct tpm2b *nonce;
	struct tpma_session *attributes;
	struct tpm2b *hmac;
};

// Table 125  Definition of TPMS_AUTH_RESPONSE Structure <  OUT>
struct tpms_auth_resp {
	struct tpm2b *nonce;
	struct tpma_session *attributes;
	struct tpm2b *hmac;
};

struct tpm2_cmd {
	struct tpm_header *header;
	u32 *handles;			/* TPM Handles array	*/
	u32 *auth_size;			/* Size of Auth Area	*/
	u8 *auth;			/* Authorization Area	*/
	u8 *params;			/* Parameters		*/
	u8 *raw;			/* internal raw buffer	*/
};

struct tpm2_resp {
	struct tpm_header *header;
	u32 *handles;		/* TPM Handles array	*/
	u32 *param_size;	/* Size of Parameters	*/
	struct tpm2b *params;	/* Parameters		*/
	u8 *auth;		/* Authorization Area	*/
	u8 *raw;		/* internal raw buffer	*/
};

int tpm2_extend_pcr(struct tpm *t, u32 pcr,
		struct tpml_digest_values *digests);

#endif
