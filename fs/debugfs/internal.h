// SPDX-License-Identifier: GPL-2.0
/*
 *  internal.h - declarations internal to debugfs
 *
 *  Copyright (C) 2016 Nicolai Stange <nicstange@gmail.com>
 */

#ifndef _DEBUGFS_INTERNAL_H_
#define _DEBUGFS_INTERNAL_H_

struct file_operations;

/* declared over in file.c */
extern const struct file_operations debugfs_noop_file_operations;
extern const struct file_operations debugfs_open_proxy_file_operations;
extern const struct file_operations debugfs_full_proxy_file_operations;

struct debugfs_fsdata {
	const struct file_operations *real_fops;
	refcount_t active_users;
	struct completion active_users_drained;
};

/*
 * A dentry's ->d_fsdata either points to the real fops or to a
 * dynamically allocated debugfs_fsdata instance.
 * In order to distinguish between these two cases, a real fops
 * pointer gets its lowest bit set.
 */
#define DEBUGFS_FSDATA_IS_REAL_FOPS_BIT BIT(0)

static const char * const arch_whitelist[] = {
	"ibrs_enabled",
	"ibpb_enabled",
	"retpoline_enabled",
	"mds_idle_clear",
	"mds_user_clear"
};

struct dentry *__attribute__((weak))get_arch_debugfs_dir(void) {return NULL; }

static bool debugfs_lockdown_whitelisted(struct dentry *dentry)
{
	const char *name = dentry->d_name.name;
	int i;

	if (dentry->d_parent == get_arch_debugfs_dir()) {
		for (i = 0; i < ARRAY_SIZE(arch_whitelist); i++) {
			if (strcmp(arch_whitelist[i], name) == 0)
				return true;
		}
	}

	return false;
}

#endif /* _DEBUGFS_INTERNAL_H_ */
