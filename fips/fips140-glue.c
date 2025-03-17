// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FIPS 140-3 and FIPS 200 support.
 *
 * Copyright (c) 2008 Neil Horman <nhorman@tuxdriver.com>
 * Copyright (c) 2025, Oracle and/or its affiliates.
 */

#include <generated/utsrelease.h>

#include <linux/export.h>
#include <linux/fips.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/sysctl.h>

#include <crypto/api.h>
#include <crypto/hash.h>

#include "crypto/internal.h"

#define FIPS_MODULE_NAME CONFIG_CRYPTO_FIPS_NAME
#ifdef CONFIG_CRYPTO_FIPS_CUSTOM_VERSION
#define FIPS_MODULE_VERSION CONFIG_CRYPTO_FIPS_VERSION
#else
#define FIPS_MODULE_VERSION UTS_RELEASE
#endif

static char fips_name[] = FIPS_MODULE_NAME;
static char fips_version[] = FIPS_MODULE_VERSION;

/*
 * FIPS 140-2 prefers the use of HMAC with a public key over a plain hash.
 */
static const u8 fips140_integ_hmac_key[] = CONFIG_CRYPTO_FIPS140_HMAC_KEY;

int fips_operational = 0;

static int verify_integrity(void)
{
	int err;

	struct crypto_shash *tfm = NULL;
	SHASH_DESC_ON_STACK(desc, dontcare);
	u8 digest[SHA256_DIGEST_SIZE];

	/*
	 * Verify integrity
	 */

	tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tfm))
		panic("FIPS 140: failed to allocate hmac tfm (%ld)\n", PTR_ERR(tfm));

	desc->tfm = tfm;
	pr_info("FIPS 140: using '%s' for integrity check\n",
		crypto_shash_driver_name(tfm));

	err = crypto_shash_setkey(tfm, fips140_integ_hmac_key, strlen(fips140_integ_hmac_key));
	if (err)
		panic("FIPS 140: crypto_shash_setkey() failed: %d\n", err);

	err = crypto_shash_init(desc);
	if (err)
		panic("FIPS 140: crypto_shash_init() failed: %d\n", err);

	/* Compute HMAC over the module's source memory */
	//err = crypto_shash_update(desc, THIS_MODULE->source_ptr, THIS_MODULE->source_len);
	err = crypto_shash_update(desc, _binary_fips140_ko_start, _binary_fips140_ko_end - _binary_fips140_ko_start);
	if (err)
		panic("FIPS 140: crypto_shash_update() failed: %d\n", err);

	err = crypto_shash_final(desc, digest);
	if (err)
		panic("FIPS 140: crypto_shash_final() failed: %d\n", err);

	/* Zeroizing this is important; see the comment below. */
	shash_desc_zero(desc);

	if (err)
		panic("FIPS 140: failed to calculate hmac shash (%d)\n", err);

	pr_info("FIPS 140: expected digest: %*phN\n", (int)sizeof(digest), _binary_fips140_hmac_start);
	pr_info("FIPS 140: computed digest: %*phN\n", (int)sizeof(digest), digest);

	if (memcmp(digest, _binary_fips140_hmac_start, sizeof(digest)))
		panic("FIPS 140: failed integrity check\n");

	/*
	 * FIPS 140-3 requires that all "temporary value(s) generated during the
	 * integrity test" be zeroized (ref: FIPS 140-3 IG 9.7.B).  There is no
	 * technical reason to do this given that these values are public
	 * information, but this is the requirement so we follow it.
	 */
	crypto_free_shash(tfm);
	memzero_explicit(digest, sizeof(digest));

	return 0;
}

/* This technically is never supposed to change. */
static int fips_standalone = 1;

static struct ctl_table crypto_sysctl_table[] = {
	{
		.procname	= "fips_enabled",
		/*
		 * Note: we use fips_operational instead of fips_enabled,
		 * since fips_enabled is more like "FIPS was requested",
		 * and is nonzero before self testing and integrity testing
		 * has finished. However, the difference is theoretical
		 * since this file will not even be created until the
		 * testing has completed.
		 */
		.data		= &fips_operational,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "fips_name",
		.data		= &fips_name,
		.maxlen		= 64,
		.mode		= 0444,
		.proc_handler	= proc_dostring,
	},
	{
		.procname	= "fips_version",
		.data		= &fips_version,
		.maxlen		= 64,
		.mode		= 0444,
		.proc_handler	= proc_dostring,
	},
	/*
	 * Helper file for dracut that always returns "1" to indicate
	 * that no userspace help is needed to get the FIPS module
	 * operational.
	 */
	{
		.procname	= "fips_standalone",
		.data		= &fips_standalone,
		.maxlen		= sizeof(fips_standalone),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
};

static struct ctl_table_header *crypto_sysctls;

static int __init check_nonfips_alg_list(void)
{
	extern struct list_head nonfips_crypto_alg_list;

	struct crypto_alg *q;
	int err = 0;

	list_for_each_entry(q, &nonfips_crypto_alg_list, cra_list) {
		pr_err("FIPS 140: found registered non-FIPS algorithm %s (%s)\n", q->cra_name, q->cra_driver_name);
		err = 1;
	}

	return err;
}

static int __init run_initcalls(void)
{
	extern unsigned long __fips_initcalls_start[];
	extern unsigned long __fips_initcalls_end[];

	for (unsigned long *initcall = __fips_initcalls_start;
		initcall != __fips_initcalls_end; ++initcall)
	{
		int ret;
		initcall_t fn;

		fn = (initcall_t) *initcall;
		pr_info("FIPS 140: calling %pS\n", fn);

		ret = fn();
		if (!ret || ret == -ENODEV)
			continue;

		panic("FIPS 140: initcall %pS failed: %d\n", fn, ret);
	}

	return 0;
}

static int __init fips140_init(void)
{
	pr_info("FIPS 140: %s version %s\n", fips_name, fips_version);

	if (check_nonfips_alg_list())
		panic("FIPS 140: found registered non-FIPS algorithms\n");

	run_initcalls();

	if (verify_integrity())
		panic("FIPS 140: integrity check failed\n");

	crypto_sysctls = register_sysctl("crypto", crypto_sysctl_table);
	if (!crypto_sysctls)
		panic("FIPS 140: failed to register sysctls");

	fips_operational = 1;

	pr_info("FIPS 140: operational\n");
	return 0;
}
module_init(fips140_init);

MODULE_DESCRIPTION("UEK8 FIPS Cryptographic Module");
MODULE_LICENSE("GPL");
