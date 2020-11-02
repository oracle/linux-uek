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

#ifndef _TPM2_AUTH_H
#define _TPM2_AUTH_H

#include "tpm2.h"

u32 tpm2_null_auth_size(void);
u8 *tpm2_null_auth(struct tpmbuff *b);

#endif
