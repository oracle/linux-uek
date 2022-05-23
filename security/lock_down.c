/* Lock down the kernel
 *
 * Copyright (C) 2016 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <linux/security.h>
#include <linux/efi.h>
#include <linux/export.h>

static bool kernel_locked_down;
static bool lockdown_confidentiality;

static const char * const lockdown_reasons[] = { "none",
						 "integrity",
						 "confidentiality" };

enum lockdown_reason {
	LOCKDOWN_NONE,
	LOCKDOWN_INTEGRITY,
	LOCKDOWN_CONFIDENTIALITY
};

/*
 * Put the kernel into lock-down mode.
 */
static void lock_kernel_down(const char *where)
{
	if (!kernel_locked_down) {
		kernel_locked_down = true;
		pr_notice("Kernel is locked down from %s; see man kernel_lockdown.7\n",
			  where);
	}
}

static int __init lockdown_param(char *level)
{
	if (level) {
		if (strcmp(level, "none") == 0)
			return 0;
		else if (strcmp(level, "confidentiality") == 0)
			lockdown_confidentiality = true;
		else if (strcmp(level, "integrity") == 0)
			lockdown_confidentiality = false;
	}
	lock_kernel_down("command line");
	return 0;
}

early_param("lockdown", lockdown_param);

/*
 * Lock the kernel down from very early in the arch setup.  This must happen
 * prior to things like ACPI being initialised.
 */
void __init init_lockdown(void)
{
#ifdef CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT
	if (efi_enabled(EFI_SECURE_BOOT))
		lock_kernel_down("EFI secure boot");
#endif
}

/**
 * kernel_is_locked_down - Find out if the kernel is locked down
 * @what: Tag to use in notice generated if lockdown is in effect
 */
bool __kernel_is_locked_down(const char *what, bool first)
{
	if (what && kernel_locked_down) {
		/* If we are in integrity mode we allow certain callsites */
		if (!lockdown_confidentiality) {
			if ((strcmp(what, "BPF") == 0) ||
			    (strcmp(what, "debugfs") == 0) ||
			    (strcmp(what, "Use of kprobes") == 0) ||
			    (strcmp(what, "perf") == 0) ||
			    (strcmp(what, "/proc/kcore") == 0) ||
			    (strcmp(what, "DTRACE") == 0) ||
			    (strcmp(what, "use of kgdb/kdb to read kernel RAM") == 0)) {
				return false;
			}
		}
		if (first) {
			pr_notice("Lockdown: %s is restricted; see man kernel_lockdown.7\n",
			  what);
		}
	}
	return kernel_locked_down;
}
EXPORT_SYMBOL(__kernel_is_locked_down);

/**
 * kernel_is_confidentiality_mode - Find out if the kernel is locked down
 * and in confidentiality mode.
 */
bool __kernel_is_confidentiality_mode(void)
{
	return (kernel_locked_down && lockdown_confidentiality);
}
EXPORT_SYMBOL(__kernel_is_confidentiality_mode);

static enum lockdown_reason __get_lockdown_level(void)
{
	enum lockdown_reason lockdown_level = LOCKDOWN_NONE;

	if (kernel_locked_down) {
		lockdown_level = __kernel_is_confidentiality_mode() ?
				 LOCKDOWN_CONFIDENTIALITY :
				 LOCKDOWN_INTEGRITY;
	}
	return lockdown_level;
}

static ssize_t lockdown_read(struct file *filp, char __user *buf, size_t count,
			     loff_t *ppos)
{
	enum lockdown_reason lockdown_level = __get_lockdown_level();
	int i, offset = 0;
	char temp[80];

	for (i = 0; i < ARRAY_SIZE(lockdown_reasons); i++) {
		const char *label = lockdown_reasons[i];

		if (lockdown_level == i)
			offset += sprintf(temp+offset, "[%s] ", label);
		else
			offset += sprintf(temp+offset, "%s ", label);
	}

	/* Convert the last space to a newline if needed. */
	if (offset > 0)
		temp[offset-1] = '\n';

	return simple_read_from_buffer(buf, count, ppos, temp, strlen(temp));
}

static ssize_t lockdown_write(struct file *file, const char __user *buf,
			      size_t n, loff_t *ppos)
{
	enum lockdown_reason lockdown_level = __get_lockdown_level();
	char *state;
	int i, len, err = -EINVAL;

	state = memdup_user_nul(buf, n);
	if (IS_ERR(state))
		return PTR_ERR(state);

	len = strlen(state);
	if (len && state[len-1] == '\n') {
		state[len-1] = '\0';
		len--;
	}

	for (i = 0; i < ARRAY_SIZE(lockdown_reasons); i++) {
		const char *label = lockdown_reasons[i];

		if (label && !strcmp(state, label)) {
			if (i < lockdown_level) {
				err = -EPERM;
				break;
			}
			lockdown_confidentiality = i ==
						   LOCKDOWN_CONFIDENTIALITY;
			lock_kernel_down("securityfs");
			err = 0;
		}
	}

	kfree(state);
	return err ? err : n;
}

static const struct file_operations lockdown_ops = {
	.read  = lockdown_read,
	.write = lockdown_write,
};

static int __init lockdown_secfs_init(void)
{
	struct dentry *dentry;

	dentry = securityfs_create_file("lockdown", 0644, NULL, NULL,
					&lockdown_ops);
	return PTR_ERR_OR_ZERO(dentry);
}

core_initcall(lockdown_secfs_init);
