// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2021, Pensando Systems Inc.
 */

#include <linux/export.h>
#include <linux/kobject.h>

static struct kobject *pensando_fw_kobj;

/*
 * Creates a new pensando sysfs node if it does not exists. The kobj is
 * returned after incrementing the refcnt, so a module should use kobject_put()
 * when it is done using this koject.
 */
struct kobject *pensando_fw_kobj_get(void)
{
	if (!pensando_fw_kobj) {
		pensando_fw_kobj = kobject_create_and_add("pensando", firmware_kobj);
		if (!pensando_fw_kobj)
			return NULL;
	}
	return kobject_get(pensando_fw_kobj);
}
EXPORT_SYMBOL_GPL(pensando_fw_kobj_get);
