/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2020 Apertus Solutions, LLC
 *
 * Author(s):
 *      Daniel P. Smith <dpsmith@apertussolutions.com>
 *
 */

#ifndef _TPMBUFF_H
#define _TPMBUFF_H

/* mirroring Linux SKB */
struct tpmbuff {
	size_t truesize;
	size_t len;

	u8 locked;

	u8 *head;
	u8 *data;
	u8 *tail;
	u8 *end;
};

u8 *tpmb_reserve(struct tpmbuff *b);
void tpmb_free(struct tpmbuff *b);
u8 *tpmb_put(struct tpmbuff *b, size_t size);
size_t tpmb_trim(struct tpmbuff *b, size_t size);
size_t tpmb_size(struct tpmbuff *b);
struct tpmbuff *alloc_tpmbuff(enum tpm_hw_intf i, u8 locality);
void free_tpmbuff(struct tpmbuff *b, enum tpm_hw_intf i);

#endif
