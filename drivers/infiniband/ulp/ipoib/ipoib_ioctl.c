/*
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
 */

#include <net/arp.h>
#include <linux/jhash.h>

#include "ipoib.h"

int ipoib_do_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	struct ipoib_ioctl_req *rq = (struct ipoib_ioctl_req *)ifr;
	struct ipoib_ioctl_req_data req_data;
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	int rc = 0;
	struct ib_cm_acl_elem *list;
	ssize_t list_count, i;
	u64 guid, subnet_prefix;
	u32 ip;
	char uuid[UUID_SZ];
	struct ib_cm_acl *acl;
	char *buf;

	if (cmd < IPOIBSTATUSGET || cmd > IPOIBACLDEL) {
		ipoib_dbg(priv, "invalid ioctl opcode 0x%x\n", cmd);
		return -EOPNOTSUPP;
	}

	rc = copy_from_user(&req_data, rq->req_data,
			    sizeof(struct ipoib_ioctl_req_data));
	if (rc != 0) {
		ipoib_warn(priv, "ioctl fail to copy request data\n");
		return -EINVAL;
	}

	switch (cmd) {
	case IPOIBSTATUSGET:
		req_data.acl_enabled = priv->acl.enabled;
		break;
	case IPOIBSTATUSSET:
		priv->acl.enabled = req_data.acl_enabled;
		break;
	case IPOIBACLINSTSZ:
		req_data.sz = priv->instances_acls.list_count;
		break;
	case IPOIBACLINSTGET:
		buf = kmalloc(req_data.sz, GFP_KERNEL);
		print_acl_instances_to_buf(buf, req_data.sz, priv);
		rc = copy_to_user(req_data.instances_names, buf, req_data.sz);
		kfree(buf);
		if (rc) {
			ipoib_warn(priv,
				   "ioctl fail to copy instances names to userspace\n");
			return -EINVAL;
		}
		break;
	case IPOIBACLINSTADD:
		rc = ipoib_create_instance_acl(req_data.instance_name, dev);
		if (rc != 0)
			return -EINVAL;
		break;
	case IPOIBACLINSTDEL:
		rc = ipoib_delete_instance_acl(req_data.instance_name, dev);
		if (rc != 0)
			return -EINVAL;
		break;
	case IPOIBACLSZ:
		if (!strcmp(req_data.instance_name, DRIVER_ACL_NAME))
			acl = &priv->acl;
		else
			acl = ipoib_get_instance_acl(req_data.instance_name,
						     dev);
		if (!acl)
			return -EINVAL;

		ib_cm_acl_scan(acl, &list, &list_count);
		kfree(list);
		req_data.sz = list_count;
		break;
	case IPOIBACLGET:
		if (!strcmp(req_data.instance_name, DRIVER_ACL_NAME))
			acl = &priv->acl;
		else
			acl = ipoib_get_instance_acl(req_data.instance_name,
						     dev);
		if (!acl)
			return -EINVAL;

		ib_cm_acl_scan(acl, &list, &list_count);
		for (i = req_data.from_idx; (i < list_count) &&
		     (i < req_data.sz) ; i++) {
			rc = copy_to_user(&req_data.subnet_prefixes[i -
					  req_data.from_idx],
					  &(list[i].subnet_prefix),
					  sizeof(u64));
			rc |= copy_to_user(&req_data.guids[i -
					   req_data.from_idx], &(list[i].guid),
					   sizeof(u64));
			rc |= copy_to_user(&req_data.ips[i -
					   req_data.from_idx], &(list[i].ip),
					   sizeof(u32));
			rc |= copy_to_user((req_data.uuids + i * UUID_SZ),
					   list[i].uuid, UUID_SZ);
			if (rc) {
				ipoib_warn(priv,
					   "ioctl fail to copy index %ld to userspace\n",
					   i);
				kfree(list);
				return -EINVAL;
			}
		}
		kfree(list);
		req_data.sz = i - req_data.from_idx;
		break;
	case IPOIBACLADD:
		acl = ipoib_get_instance_acl(req_data.instance_name, dev);
		if (!acl)
			return -EINVAL;

		for (i = 0; i < req_data.sz; i++) {
			rc = copy_from_user(&subnet_prefix,
					    &req_data.subnet_prefixes[i],
					    sizeof(u64));
			rc |= copy_from_user(&guid, &req_data.guids[i],
					     sizeof(u64));
			rc |= copy_from_user(&ip, &req_data.ips[i],
					     sizeof(u32));
			rc |= copy_from_user(&uuid,
					     (req_data.uuids + i * UUID_SZ),
					     UUID_SZ);
			if (rc) {
				ipoib_warn(priv,
					   "ioctl fail to copy index %ld from userspace\n",
					   i);
				return -EINVAL;
			}
			rc = ib_cm_acl_insert(acl, subnet_prefix, guid, ip,
					      uuid);
			rc |= ib_cm_acl_insert(&priv->acl, subnet_prefix, guid,
					       ip, uuid);
			if (rc) {
				ipoib_warn(priv,
					   "ioctl fail to insert index %ld to ACL\n",
					   i);
				return -EINVAL;
			}
		}
		break;
	case IPOIBACLDEL:
		acl = ipoib_get_instance_acl(req_data.instance_name, dev);
		if (!acl)
			return -EINVAL;

		for (i = 0; i < req_data.sz; i++) {
			rc = copy_from_user(&subnet_prefix,
					    &req_data.subnet_prefixes[i],
					    sizeof(u64));
			rc |= copy_from_user(&guid, &req_data.guids[i],
					     sizeof(u64));
			if (rc) {
				ipoib_warn(priv,
					   "ioctl fail to copy index %ld from userspace\n",
					   i);
				return -EINVAL;
			}
			ib_cm_acl_delete(acl, subnet_prefix, guid);
			ib_cm_acl_delete(&priv->acl, subnet_prefix, guid);
		}
		break;
	}

	rc = copy_to_user(rq->req_data, &req_data,
			  sizeof(struct ipoib_ioctl_req_data));
	if (rc != 0) {
		ipoib_warn(priv, "ioctl fail to copy back request data\n");
		return -EINVAL;
	}

	return rc;
}
