/*****************************************************************************
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
*
* Copyright 2009, 2011 Oracle America, Inc. All rights reserved.
*
* This program is free software; you can redistribute it and/or modify it under
* the terms of the GNU General Public License version 2 only, as published by
* the Free Software Foundation.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
* FOR A PARTICULAR PURPOSE.  See the GNU General Public License version 2 for
* more details (a copy is included in the LICENSE file that accompanied this
* code).
*
* You should have received a copy of the GNU General Public License version 2
* along with this program; If not,
* see http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*
* Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 or
* visit www.oracle.com if you need additional information or have any
* questions.
*
******************************************************************************/

#include "hxge.h"
#include <linux/sysfs.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
#define DEV_TYPE  class_device
#define to_net_dev(class) container_of(class, struct net_device, class_dev)
static ssize_t errinject_show(struct class_device *, char *);
static ssize_t errinject_store(struct class_device *, const char *, size_t);
static CLASS_DEVICE_ATTR(errinject, S_IWUSR | S_IRUGO, errinject_show, errinject_store);
#else
#define DEV_TYPE device
static ssize_t errinject_show(struct device *, struct device_attribute *, 
				char *);
static ssize_t errinject_store(struct device *, struct device_attribute *, 
				const char *, size_t);
DEVICE_ATTR(errinject, S_IWUSR | S_IRUGO, errinject_show, errinject_store);
#endif


static ssize_t errinject_show (struct DEV_TYPE *dev, 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
				struct device_attribute *attr,
#endif
				char *buf)
{
	struct hxge_adapter *hxgep = netdev_priv(to_net_dev(dev));
	
	return (sprintf(buf, "%#lx\n", hxgep->err_flags));
}

static ssize_t errinject_store (struct DEV_TYPE *dev,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
				struct device_attribute *attr,
#endif
				const char *buf,
				size_t len)
{
	unsigned long val;
	char *endp;
	struct hxge_adapter *hxgep = netdev_priv(to_net_dev(dev));

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	val = simple_strtoul(buf, &endp, 16);
	if (endp == buf)
		return -EINVAL;

	HXGE_ERR(hxgep, "val is 0x%lx, len = %d", val, (int)len);
	spin_lock(&hxgep->lock);
	hxgep->err_flags = val;
	spin_unlock(&hxgep->lock);
	HXGE_ERR(hxgep, "Setting err_flags to 0x%lx", hxgep->err_flags);
	return len;
	
}


int hxge_create_sysfs(struct net_device *netdev)
{
	struct DEV_TYPE *dev;
	int ret;

	printk(KERN_DEBUG "Creating errinject device file.. \n");
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	dev = &netdev->class_dev;
	ret = class_device_create_file(dev, &class_device_attr_errinject);
#else
	dev = &netdev->dev;
	ret = device_create_file(dev, &dev_attr_errinject);
#endif
	return ret;
}

void hxge_remove_sysfs(struct net_device *netdev)
{
	struct DEV_TYPE *dev;

	printk(KERN_DEBUG "Removing errinject device.. \n");
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
	dev = &netdev->class_dev;
	class_device_remove_file(dev, &class_device_attr_errinject);
#else
	dev = &netdev->dev;
	device_remove_file(dev, &dev_attr_errinject);
#endif
}
