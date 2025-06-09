// SPDX-License-Identifier: GPL-2.0-only
/*
 * Landlock LSM - Security framework setup
 *
 * Copyright © 2016-2020 Mickaël Salaün <mic@digikod.net>
 * Copyright © 2018-2020 ANSSI
 */

#include <linux/bits.h>
#include <linux/init.h>
#include <linux/lsm_hooks.h>

#include "common.h"
#include "cred.h"
#include "errata.h"
#include "fs.h"
#include "ptrace.h"
#include "setup.h"

bool landlock_initialized __lsm_ro_after_init = false;

struct lsm_blob_sizes landlock_blob_sizes __lsm_ro_after_init = {
	.lbs_cred = sizeof(struct landlock_cred_security),
	.lbs_inode = sizeof(struct landlock_inode_security),
	.lbs_superblock = sizeof(struct landlock_superblock_security),
};

int landlock_errata __ro_after_init;

static void __init compute_errata(void)
{
	size_t i;

#ifndef __has_include
	/*
	 * This is a safeguard to make sure the compiler implements
	 * __has_include (see errata.h).
	 */
	WARN_ON_ONCE(1);
	return;
#endif

	for (i = 0; landlock_errata_init[i].number; i++) {
		const int prev_errata = landlock_errata;

		if (WARN_ON_ONCE(landlock_errata_init[i].abi >
				 landlock_abi_version))
			continue;

		landlock_errata |= BIT(landlock_errata_init[i].number - 1);
		WARN_ON_ONCE(prev_errata == landlock_errata);
	}
}

static int __init landlock_init(void)
{
	compute_errata();
	landlock_add_cred_hooks();
	landlock_add_ptrace_hooks();
	landlock_add_fs_hooks();
	landlock_initialized = true;
	pr_info("Up and running.\n");
	return 0;
}

DEFINE_LSM(LANDLOCK_NAME) = {
	.name = LANDLOCK_NAME,
	.init = landlock_init,
	.blobs = &landlock_blob_sizes,
};
