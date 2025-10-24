/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _FIPS_H
#define _FIPS_H

#include <linux/init.h>

#include <crypto/sha2.h> /* SHA256_DIGEST_SIZE */

#ifdef CONFIG_CRYPTO_FIPS
/*
 * fips_enabled = FIPS mode was requested on the command line
 * fips_operational = FIPS module has run self-tests etc. and is operational
 */
extern int fips_enabled;
extern int fips_operational;

extern struct atomic_notifier_head fips_fail_notif_chain;

void fips_fail_notify(void);

/* FIPS-certified module blob and digest */
extern const u8 __initconst _binary_fips140_ko_start[];
extern const u8 __initconst _binary_fips140_ko_end[];
extern const u8 __initconst _binary_fips140_hmac_start[SHA256_DIGEST_SIZE];

#define _binary_fips140_ko_size (_binary_fips140_ko_end - _binary_fips140_ko_start)

#else
#define fips_enabled 0

static inline void fips_fail_notify(void) {}

#endif

#endif
