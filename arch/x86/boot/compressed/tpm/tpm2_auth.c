// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Apertus Solutions, LLC
 *
 * Author(s):
 *      Daniel P. Smith <dpsmith@apertussolutions.com>
 *
 */

#include <linux/types.h>
#include <linux/const.h>
#include <linux/string.h>
#include <asm/byteorder.h>
#include "tpm.h"
#include "tpmbuff.h"
#include "tpm2.h"
#include "tpm2_constants.h"

#define NULL_AUTH_SIZE 9

u32 tpm2_null_auth_size(void)
{
	return NULL_AUTH_SIZE;
}

u8 *tpm2_null_auth(struct tpmbuff *b)
{
	u32 *handle;
	u8 *auth = (u8 *)tpmb_put(b, NULL_AUTH_SIZE);

	if (!auth)
		return NULL;

	memset(auth, 0, NULL_AUTH_SIZE);

	/*
	 * The handle, the first element, is the
	 * only non-zero value in a NULL auth
	 */
	handle = (u32 *)auth;
	*handle = cpu_to_be32(TPM_RS_PW);

	return auth;
}
