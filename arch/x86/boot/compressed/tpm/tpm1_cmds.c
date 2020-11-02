// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020 Apertus Solutions, LLC
 *
 * Author(s):
 *      Daniel P. Smith <dpsmith@apertussolutions.com>
 *
 * The code in this file is based on the article "Writing a TPM Device Driver"
 * published on http://ptgmedia.pearsoncmg.com.
 *
 */

#include <linux/string.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <asm/byteorder.h>
#include "tpm.h"
#include "tpmbuff.h"
#include "tis.h"
#include "tpm_common.h"
#include "tpm1.h"

int tpm1_pcr_extend(struct tpm *t, struct tpm_digest *d)
{
	int ret = 0;
	struct tpmbuff *b = t->buff;
	struct tpm_header *hdr;
	struct tpm_extend_cmd *cmd;
	size_t size;

	if (b == NULL) {
		ret = -EINVAL;
		goto out;
	}

	/* ensure buffer is free for use */
	tpmb_free(b);

	hdr = (struct tpm_header *)tpmb_reserve(b);
	if (!hdr) {
		ret = -ENOMEM;
		goto out;
	}


	hdr->tag = cpu_to_be16(TPM_TAG_RQU_COMMAND);
	hdr->code = cpu_to_be32(TPM_ORD_EXTEND);

	cmd = (struct tpm_extend_cmd *)
		tpmb_put(b, sizeof(struct tpm_extend_cmd));
	if (cmd == NULL) {
		ret = -ENOMEM;
		goto free;
	}

	cmd->pcr_num = cpu_to_be32(d->pcr);
	memcpy(&(cmd->digest), &(d->digest), sizeof(TPM_DIGEST));

	hdr->size = cpu_to_be32(tpmb_size(b));

	if (be32_to_cpu(hdr->size) != t->ops.send(b)) {
		ret = -EAGAIN;
		goto free;
	}

	/* Reset buffer for receive */
	tpmb_trim(b, tpmb_size(b));

	hdr = (struct tpm_header *)b->head;
	tpmb_put(b, sizeof(struct tpm_header));

	/*
	 * The extend receive operation returns a struct tpm_extend_resp
	 * but the current implementation ignores the returned PCR value.
	 */

	/* recv() will increase the buffer size */
	size = t->ops.recv(t->family, b);
	if (tpmb_size(b) != size) {
		ret = -EAGAIN;
		goto free;
	}

	/*
	 * On return, the code field is used for the return code out. Though
	 * the commands specifications section 16.1 implies there is an
	 * ordinal field, the return size and values point to this being
	 * incorrect.
	 *
	 * Also tis_recv() converts the header back to CPU endianness.
	 */
	if (hdr->code != TPM_SUCCESS)
		ret = -EAGAIN;

free:
	tpmb_free(b);
out:
	return ret;
}
