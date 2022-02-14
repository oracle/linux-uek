// SPDX-License-Identifier: GPL-2.0
/*
 * Pensando reboot control via sysfs
 *
 * Copyright (c) 2020-2021, Pensando Systems Inc.
 */

#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/module.h>
#include <linux/init.h>

/*
 * This module provides userspace control of reboot behavior
 * after a panic.  Naples25 SWM and OCP cards will use this
 * to enable immediate reboot after panic handling.
 */
static int panic_reboot;	/* default=0, no reboot */

bool cap_panic_reboot(void)
{
	if (panic_reboot)
		return true;
	return false;
}

struct kobject *reboot_kobj;

static ssize_t panic_reboot_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", panic_reboot);
}

static ssize_t panic_reboot_store(struct kobject *kobj,
		struct kobj_attribute *attr, const char *buf, size_t count)
{
	int ret;

	ret = kstrtoint(buf, 10, &panic_reboot);
	if (ret < 0)
		return ret;
	return count;
}

static struct kobj_attribute panic_reboot_attribute =
	__ATTR(panic_reboot, 0664, panic_reboot_show, panic_reboot_store);

static struct attribute *attrs[] = {
	&panic_reboot_attribute.attr,
	NULL,
};

/* Put all attributes in the kobject directory */
static struct attribute_group attr_group = {
	.attrs = attrs,
};

static int __init capri_reboot_init(void)
{
	int ret;

	reboot_kobj = kobject_create_and_add("reboot", kernel_kobj);
	if (!reboot_kobj)
		return -ENOMEM;

	ret = sysfs_create_group(reboot_kobj, &attr_group);
	if (ret)
		kobject_put(reboot_kobj);
	return ret;
}

static void __exit capri_reboot_exit(void)
{
	kobject_put(reboot_kobj);
}

module_init(capri_reboot_init);
module_exit(capri_reboot_exit);
