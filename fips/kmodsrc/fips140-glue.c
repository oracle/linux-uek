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

#define FIPS_MODULE_NAME "UEK 8 FIPS 140-3 module"

#ifdef CONFIG_CRYPTO_FIPS_CUSTOM_VERSION
#define FIPS_MODULE_VERSION CONFIG_CRYPTO_FIPS_VERSION
#else
#define FIPS_MODULE_VERSION UTS_RELEASE
#endif

static char fips_name[] = FIPS_MODULE_NAME;
static char fips_version[] = FIPS_MODULE_VERSION;

struct ar_file_header {
	char path[16];
	char unused[12];
	char uid[6];
	char gid[6];
	char mode[8];
	char size[10];
	char magic[2];
};

static char *read_path(const char *string_table, const struct ar_file_header *fh)
{
	char path_str[sizeof(fh->path) + 1];
	const char *start;
	const char *end;

	memcpy(path_str, fh->path, sizeof(fh->path));
	path_str[sizeof(fh->path)] = '\0';

	/* The 'ar' header has a space-padded value */
	for (int i = 0; i < sizeof(fh->path); ++i) {
		if (path_str[i] == ' ')
			path_str[i] = '\0';
	}

	/* Is this a pointer into the string table? */
	if (path_str[0] == '/') {
		unsigned long index;

		if (kstrtoul(path_str + 1, 10, &index))
			return NULL;

		// TODO: sanity check the index/end?
		start = string_table + index;
		end = strchr(start, '\n');
		if (!end)
			return NULL;
	} else {
		start = path_str;
		end = start + strlen(start);
	}

	if (start == end)
		return NULL;

	/* Skip trailing '/' */
	if (end[-1] != '/')
		return NULL;
	--end;

	return kstrndup(start, end - start, GFP_KERNEL);
}

static size_t read_size(const struct ar_file_header *fh)
{
	int err;
	char size_str[sizeof(fh->size) + 1];
	unsigned long size;

	memcpy(size_str, fh->size, sizeof(fh->size));
	size_str[sizeof(fh->size)] = '\0';

	/* The 'ar' header has a space-padded value */
	for (int i = 0; i < sizeof(fh->size); ++i) {
		if (size_str[i] == ' ')
			size_str[i] = '\0';
	}

	err = kstrtoul(size_str, 10, &size);
	if (err)
		panic("FIPS 140 initialization failed: invalid file size: <%s>\n", size_str);

	return size;
}

/* 'ar' archive of kernel modules to load */
extern const u8 _binary_fips140_archive_a_start[];
extern const u8 _binary_fips140_archive_a_end[];

static int load_archive(void)
{
	const void *ptr;
	const void *end;
	const char *string_table = NULL;

	ptr = _binary_fips140_archive_a_start;
	end = _binary_fips140_archive_a_end;

	/* Read global header (just a magic string) */
	if (end - ptr < 8 || memcmp(ptr, "!<arch>\n", 8))
		panic("FIPS 140 initialization failed: missing or corrupt global header\n");

	ptr += 8;

	/* Iterate over file headers and load kernel modules */
	while (ptr < end) {
		struct ar_file_header fh;
		const char *path;
		size_t size;
		int err;

		if (end - ptr < sizeof(fh))
			panic("FIPS 140 initialization failed: missing or currupt file header\n");

		/*
		 * Copy the file header as it may have incorrect alignment
		 * to dereference directly.
		 */
		memcpy(&fh, ptr, sizeof(fh));
		ptr += sizeof(fh);

		size = read_size(&fh);

		/* Skip string table */
		if (!strncmp(fh.path, "// ", 3)) {
			string_table = ptr;
			goto next;
		}

		path = read_path(string_table, &fh);
		pr_info("FIPS 140: loading %s\n", path);
		kfree(path);

		err = load_module_mem(ptr, size);
		if (err)
			panic("FIPS 140: module initialization failed: %d\n", err);

	next:
		ptr = ptr + ((size + 1) & ~1);
	}

	return 0;
}

static int run_tests(void)
{
	/*
	 * The following code was copied from crypto/algapi.c's
	 * crypto_start_tests() and modified so that it actually
	 * waits for all the tests to pass before proceeding.
	 */
	for (;;) {
		int all_complete = 1;
		struct crypto_larval *larval = NULL;
		struct crypto_alg *q;

		down_write(&crypto_alg_sem);

		list_for_each_entry(q, &crypto_alg_list, cra_list) {
			struct crypto_larval *l;

			if (!crypto_is_larval(q))
				continue;

			l = (void *)q;

			if (!crypto_is_test_larval(l))
				continue;

			if (!l->test_started) {
				l->test_started = true;
				larval = l;
				crypto_schedule_test(larval);
			}

			if (!try_wait_for_completion(&l->completion)) {
				all_complete = 0;

				pr_debug("fips140: waiting for %s/%s (module: %s)\n",
					l->alg.cra_name,
					l->alg.cra_driver_name,
					l->alg.cra_module ? l->alg.cra_module->name : "(none)");
			}
		}

		up_write(&crypto_alg_sem);

		if (all_complete)
			break;
	}

	return 0;
}

/*
 * FIPS 140-2 prefers the use of HMAC with a public key over a plain hash.
 */
static const u8 fips140_integ_hmac_key[] = FIPS140_INTEG_HMAC_KEY;

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
		.proc_handler	= proc_dointvec
	},
	{
		.procname	= "fips_name",
		.data		= &fips_name,
		.maxlen		= 64,
		.mode		= 0444,
		.proc_handler	= proc_dostring
	},
	{
		.procname	= "fips_version",
		.data		= &fips_version,
		.maxlen		= 64,
		.mode		= 0444,
		.proc_handler	= proc_dostring
	},
};

static struct ctl_table_header *crypto_sysctls;

DECLARE_CRYPTO_API0(fips140_init, int);

int CRYPTO_API(fips140_init)(void)
{
	if (load_archive())
		panic("FIPS 140: failed to load kernel modules\n");

	if (run_tests())
		panic("FIPS 140: failed to run algorithm self tests\n");

	if (verify_integrity())
		panic("FIPS 140: integrity check failed\n");

	crypto_sysctls = register_sysctl("crypto", crypto_sysctl_table);
	if (!crypto_sysctls)
		panic("FIPS 140: failed to register sysctls");

	fips_operational = 1;

	crypto_init_proc();

	pr_info("FIPS 140: operational\n");
	return 0;
}
DEFINE_CRYPTO_API(fips140_init);

MODULE_DESCRIPTION("UEK8 FIPS Cryptographic Module");
MODULE_LICENSE("GPL");
