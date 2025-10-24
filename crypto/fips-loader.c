// SPDX-License-Identifier: GPL-2.0-only
/*
 * FIPS 140-3 module loader.
 *
 * Copyright 2021 Google LLC
 * Copyright (c) 2025, Oracle and/or its affiliates.
 */

#include <linux/fips.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/panic.h>
#include <linux/printk.h>
#include <linux/string.h>

#include <crypto/api.h>
#include <crypto/hash.h>

int fips_enabled;
EXPORT_SYMBOL_GPL(fips_enabled);

ATOMIC_NOTIFIER_HEAD(fips_fail_notif_chain);
EXPORT_SYMBOL_GPL(fips_fail_notif_chain);

void fips_fail_notify(void)
{
	if (fips_enabled)
		atomic_notifier_call_chain(&fips_fail_notif_chain, 0, NULL);
}
EXPORT_SYMBOL_GPL(fips_fail_notify);

/* defined in crypto/fips140-{module,digest}.o -OR- vmlinux.lds */
EXPORT_SYMBOL_GPL(_binary_fips140_ko_start);
EXPORT_SYMBOL_GPL(_binary_fips140_ko_end);
EXPORT_SYMBOL_GPL(_binary_fips140_hmac_start);

/* Process kernel command-line parameter at boot time. fips=0 or fips=1 */
static int fips_enable(char *str)
{
	fips_enabled = !!simple_strtol(str, NULL, 0);
	if (!fips_enabled)
		pr_info("FIPS 140-3 module: disabled\n");

	return 1;
}

__setup("fips=", fips_enable);

static struct ctl_table crypto_sysctl_table[] = {
	{
		.procname	= "fips_enabled",
		.data		= &fips_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0444,
		.proc_handler	= proc_dointvec,
	},
};

static int __init fips_loader_init(void)
{
	void *ko_mem;
	int err;
	struct ctl_table_header *crypto_sysctls;

	if (!fips_enabled) {
		/* Add crypto sysctl for nonfips mode */
		crypto_sysctls = register_sysctl("crypto", crypto_sysctl_table);
		if (!crypto_sysctls)
			pr_err("fips 140: failed to register sysctl for nonfips mode");

		return 0;
	}

	/*
	 * Duplicate the memory as the kernel module loader will
	 * modify it and mess up the integrity check.
	 */
	ko_mem = kvmemdup(_binary_fips140_ko_start, _binary_fips140_ko_size, GFP_KERNEL);
	if (!ko_mem) {
		err = -ENOMEM;
		goto out;
	}

	err = load_module_mem(ko_mem, _binary_fips140_ko_size);
	if (err)
		goto out;

	kvfree(ko_mem);

out:
	if (err)
		panic("FIPS 140-3 module: loading error\n");
	return err;
}
arch_initcall_sync(fips_loader_init);
