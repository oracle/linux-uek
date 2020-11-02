/*
 *  Copyright (C) 2020 Apertus Solutions, LLC
 *
 *  Author: Daniel P. Smith <dpsmith@apertussolutions.com>
 *
 * This source code is licensed under the GNU General Public License,
 * Version 2.  See the file COPYING for more details.
 */

#ifndef SHA512_H
#define SHA512_H

#include <linux/types.h>
#include <crypto/sha.h>

extern int sha512_init(struct sha512_state *sctx);
extern int sha512_update(struct sha512_state *sctx, const u8 *input,
			 unsigned int length);
extern int sha512_final(struct sha512_state *sctx, u8 *hash);

#endif /* SHA512_H */
