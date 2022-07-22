/*
 * Copyright (c) 2021 Oracle and/or its affiliates.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/sysfs.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <rdma/rdma_cm.h>

static struct kobject *rdmaip_notify_kobj;

static ssize_t
handle_rdma_notify_addr_change(struct kobject *kobj, struct kobj_attribute *attr,
			       const char *buf, size_t count)
{
	const char *cp, *cp_limit, *cp_end;
	union {
		struct sockaddr_in  inet4;
#if IS_ENABLED(CONFIG_IPV6)
		struct sockaddr_in6 inet6;
#endif
		struct sockaddr     any;
	} addr;
	int error;

	cp = buf;
	cp_limit = buf + count;
	while (cp < cp_limit && isspace(*cp))
		cp++;

	while (cp_limit > cp && isspace(cp_limit[-1]))
		cp_limit--;

	memset(&addr, 0, sizeof(addr));
	addr.any.sa_family = AF_INET;
	error = !in4_pton(cp, cp_limit - cp, (void *)&addr.inet4.sin_addr,
			  -1, &cp_end) ||
		cp_end != cp_limit;

#if IS_ENABLED(CONFIG_IPV6)
	if (error) {
		memset(&addr, 0, sizeof(addr));
		addr.any.sa_family = AF_INET6;
		error = !in6_pton(cp, cp_limit - cp, (void *)&addr.inet6.sin6_addr,
				  -1, &cp_end) ||
			cp_end != cp_limit;
	}
#endif /* IS_ENABLED(CONFIG_IPV6) */

	if (error)
		return -EINVAL;

	error = rdma_notify_addr_change(&addr.any);

	return error ? error : count;
}

static ssize_t
handle_netdev_notify_peers(struct kobject *kobj, struct kobj_attribute *attr,
			   const char *buf, size_t count)
{
	const char *cp, *cp_limit;
	char ifname[IFNAMSIZ];
	struct net_device *ndev;

	cp = buf;
	cp_limit = buf + count;
	while (cp < cp_limit && isspace(*cp))
		cp++;

	while (cp_limit > cp && isspace(cp_limit[-1]))
		cp_limit--;

	if (cp_limit - cp >= IFNAMSIZ)
		return -ENAMETOOLONG;

	memcpy(ifname, cp, cp_limit - cp);
	ifname[cp_limit - cp] = 0;

	ndev = dev_get_by_name(&init_net, ifname);
	if (!ndev)
		return -ENODEV;

	netdev_notify_peers(ndev);
	dev_put(ndev);

	return count;
}

static struct kobj_attribute rdma_notify_addr_change_attribute =
	__ATTR(rdma_notify_addr_change, 0200, NULL, handle_rdma_notify_addr_change);

static struct kobj_attribute netdev_notify_peers_attribute =
	__ATTR(netdev_notify_peers, 0200, NULL, handle_netdev_notify_peers);

static struct attribute *rdmaip_notify_attrs[] = {
	&rdma_notify_addr_change_attribute.attr,
	&netdev_notify_peers_attribute.attr,
	NULL,
};

static struct attribute_group rdmaip_notify_attr_group = {
	.attrs = rdmaip_notify_attrs,
};

static int __init
rdmaip_notify_init(void)
{
	int error;

	rdmaip_notify_kobj = kobject_create_and_add("rdmaip_notify", kernel_kobj);
	if (!rdmaip_notify_kobj)
		return -ENOMEM;

	error = sysfs_create_group(rdmaip_notify_kobj, &rdmaip_notify_attr_group);
	if (error) {
		kobject_put(rdmaip_notify_kobj);
		return error;
	}

	return 0;
}

static void __exit
rdmaip_notify_exit(void)
{
	kobject_put(rdmaip_notify_kobj);
}

module_init(rdmaip_notify_init);
module_exit(rdmaip_notify_exit);

MODULE_LICENSE("GPL");
MODULE_VERSION("2020-03-18.0");
