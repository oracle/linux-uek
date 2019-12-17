/*
 *  internal.h - declarations internal to debugfs
 *
 *  Copyright (C) 2016 Nicolai Stange <nicstange@gmail.com>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License version
 *	2 as published by the Free Software Foundation.
 *
 */

#ifndef _DEBUGFS_INTERNAL_H_
#define _DEBUGFS_INTERNAL_H_

struct file_operations;

/* declared over in file.c */
extern const struct file_operations debugfs_noop_file_operations;
extern const struct file_operations debugfs_open_proxy_file_operations;
extern const struct file_operations debugfs_full_proxy_file_operations;

static const char * const arch_whitelist[] = {
	"ibrs_enabled",
	"ibpb_enabled",
	"retpoline_enabled",
	"mds_idle_clear",
	"mds_user_clear"
};

struct dentry *__attribute__((weak))get_arch_debugfs_dir(void) {return NULL; }

static bool debugfs_lockdown_whitelisted(const struct dentry *dentry)
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
