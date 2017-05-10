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

#include <linux/module.h>
#include <linux/jhash.h>
#include "ipoib.h"

int extract_guid_and_subnet(const char *buf, char *name, u64 *subnet_prefix,
			    u64 *guid)
{
	u64 gid[8];
	int i, shift;

	memset(&gid, 0, sizeof(gid));

	if (name) {
		if (sscanf(buf,
			   "%s %4llx:%4llx:%4llx:%4llx:%4llx:%4llx:%4llx:%4llx",
			   name, &gid[0], &gid[1], &gid[2], &gid[3], &gid[4],
			   &gid[5], &gid[6], &gid[7]) != 9)
			return -EINVAL;
	} else
		if (sscanf(buf,
			   "%4llx:%4llx:%4llx:%4llx:%4llx:%4llx:%4llx:%4llx",
			   &gid[0], &gid[1], &gid[2], &gid[3], &gid[4], &gid[5],
			   &gid[6], &gid[7]) != 8)
			return -EINVAL;

	*guid = 0;
	*subnet_prefix = 0;
	for (i = 0; i < 4; i++) {
		shift = ((3 - i) * 16);
		*subnet_prefix |= gid[i] << shift;
		*guid |= gid[i + 4] << shift;
	}

	return 0;
}

int extract_guid_subnet_and_ip(const char *buf, char *name, u64 *subnet_prefix,
			       u64 *guid, u32 *src_ip, char *uuid)
{
	u64 gid[8];
	u32 ip[4];
	int rc, i, shift;

	memset(&gid, 0, sizeof(gid));
	memset(&ip, 0, sizeof(ip));
	memset(uuid, 0, UUID_SZ);

	rc = sscanf(buf,
		"%s %4llx:%4llx:%4llx:%4llx:%4llx:%4llx:%4llx:%4llx %s %d.%d.%d.%d",
		name, &gid[0], &gid[1], &gid[2], &gid[3], &gid[4], &gid[5],
		&gid[6], &gid[7], uuid, &ip[0], &ip[1],  &ip[2],  &ip[3]);
	if (rc != 14)
		return -EINVAL;

	*guid = 0;
	*subnet_prefix = 0;
	for (i = 0; i < 4; i++) {
		shift = ((3 - i) * 16);
		*subnet_prefix |= gid[i] << shift;
		*guid |= gid[i + 4] << shift;
	}

	*src_ip = 0;
	for (i = 0; i < 4; i++) {
		shift = ((3 - i) * 8);
		*src_ip |= ip[i] << shift;
	}

	return 0;
}

static ssize_t show_acl_enabled(struct device *d,
				struct device_attribute *attr, char *buf)
{
	struct ipoib_dev_priv *priv = netdev_priv(to_net_dev(d));

	if (priv->acl.enabled)
		return sprintf(buf, "1\n");
	else
		return sprintf(buf, "0\n");
}

static ssize_t set_acl_enabled(struct device *d, struct device_attribute *attr,
			       const char *buf, size_t count)
{
	struct ipoib_dev_priv *priv = netdev_priv(to_net_dev(d));

	priv->acl.enabled = strcmp(buf, "0\n");
	return count;
}

static DEVICE_ATTR(acl_enabled, S_IWUSR | S_IRUGO, show_acl_enabled,
		   set_acl_enabled);

static ssize_t add_acl(struct device *d, struct device_attribute *attr,
		       const char *buf, size_t count)
{
	struct ipoib_dev_priv *priv = netdev_priv(to_net_dev(d));
	int rc;
	u64 guid, subnet_prefix;
	u32 ip;
	char uuid[UUID_SZ];
	struct ib_cm_acl *instance_acl;
	char name[INSTANCE_ACL_ID_SZ];

	rc = extract_guid_subnet_and_ip(buf, name, &subnet_prefix, &guid, &ip,
					uuid);
	if (rc != 0)
		return rc;

	instance_acl = ipoib_get_instance_acl(name, to_net_dev(d));
	if (!instance_acl)
		return -EINVAL;

	rc = ib_cm_acl_insert(instance_acl, subnet_prefix, guid, ip, uuid);
	rc |= ib_cm_acl_insert(&priv->acl, subnet_prefix, guid, ip, uuid);
	if (rc != 0)
		return rc;

	return count;
}

static DEVICE_ATTR(add_acl, S_IWUSR, NULL, add_acl);

static ssize_t delete_acl(struct device *d, struct device_attribute *attr,
			  const char *buf, size_t count)
{
	struct ipoib_dev_priv *priv = netdev_priv(to_net_dev(d));
	u64 guid, subnet_prefix;
	int rc;
	struct ib_cm_acl *instance_acl;
	char name[INSTANCE_ACL_ID_SZ];

	rc = extract_guid_and_subnet(buf, name, &subnet_prefix, &guid);
	if (rc != 0)
		return rc;

	instance_acl = ipoib_get_instance_acl(name, to_net_dev(d));
	if (!instance_acl)
		return -EINVAL;

	ib_cm_acl_delete(instance_acl, subnet_prefix, guid);
	ib_cm_acl_delete(&priv->acl, subnet_prefix, guid);

	return count;
}

static DEVICE_ATTR(delete_acl, S_IWUSR, NULL, delete_acl);

void print_acl_to_buf(char *buf, const char *name, struct ib_cm_acl *acl)
{
	struct ib_cm_acl_elem *list;
	ssize_t list_count, i;
	u8 *subnet_prefix, *guid;
	u8 *ip;

	ib_cm_acl_scan(acl, &list, &list_count);
	for (i = 0; i < list_count; i++) {
		subnet_prefix = (u8 *)&(list[i].subnet_prefix);
		guid = (u8 *)&(list[i].guid);
		ip = (u8 *)&(list[i].ip);
		sprintf(buf,
			"%s%s\t%d\t%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\t%s\t%d.%d.%d.%d\n",
			buf, name, list[i].ref_count, subnet_prefix[7],
			subnet_prefix[6], subnet_prefix[5], subnet_prefix[4],
			subnet_prefix[3], subnet_prefix[2], subnet_prefix[1],
			subnet_prefix[0], guid[7], guid[6], guid[5], guid[4],
			guid[3], guid[2], guid[1], guid[0], list[i].uuid,
			ip[3], ip[2], ip[1], ip[0]);
	}
	kfree(list);
}

static ssize_t show_acl(struct device *d,
			struct device_attribute *attr, char *buf)
{
	struct ipoib_dev_priv *priv = netdev_priv(to_net_dev(d));
	struct ipoib_instance_acl *results[ACL_BATCH_SZ];
	unsigned int count, i;
	unsigned long idx = 0;

	strcpy(buf, "");

	print_acl_to_buf(buf, DRIVER_ACL_NAME, &priv->acl);

	count = 0;
	do {
		count = radix_tree_gang_lookup(&priv->instances_acls.instances,
					      (void **)results, idx,
					      ACL_BATCH_SZ);
		for (i = 0; i < count; i++)
			print_acl_to_buf(buf, results[i]->name,
					 &results[i]->acl);
		if (count)
			idx = jhash(results[i - 1]->name,
				    strlen(results[i - 1]->name), 0) + 1;
	} while (count);

	return strlen(buf);
}

static DEVICE_ATTR(acl, S_IRUGO, show_acl, NULL);

void print_acl_instances_to_buf(char *buf, size_t sz,
				struct ipoib_dev_priv *priv)
{
	struct ipoib_instance_acl *results[ACL_BATCH_SZ];
	unsigned int count, i;
	unsigned long idx = 0;

	if (sz == 0)
		return;

	strcpy(buf, "");

	count = 0;
	do {
		count = radix_tree_gang_lookup(&priv->instances_acls.instances,
					      (void **)results, idx,
					      ACL_BATCH_SZ);
		for (i = 0; i < count; i++) {
			if (sz &&
			    (strlen(buf) + strlen(results[i]->name) + 1) > sz)
				return;
			sprintf(buf, "%s%s\n", buf, results[i]->name);
		}

		if (count)
			idx = jhash(results[i - 1]->name,
				    strlen(results[i - 1]->name), 0) + 1;
	} while (count);
}

static ssize_t show_acl_instances(struct device *d,
				  struct device_attribute *attr, char *buf)
{
	struct ipoib_dev_priv *priv = netdev_priv(to_net_dev(d));

	/* Assumption here is that buf has enoght place to hold entire list */
	print_acl_instances_to_buf(buf, priv->instances_acls.list_count *
				   INSTANCE_ACL_ID_SZ + 1, priv);

	return strlen(buf);
}

static DEVICE_ATTR(acl_instances, S_IRUGO, show_acl_instances, NULL);

static ssize_t add_acl_instance(struct device *d, struct device_attribute *attr,
				const char *buf, size_t count)
{
	char name[INSTANCE_ACL_ID_SZ];
	char *crlf_pos = strchr(buf, '\n');

	strncpy(name, buf, INSTANCE_ACL_ID_SZ);
	if (crlf_pos)
		name[crlf_pos - buf] = 0;
	ipoib_create_instance_acl(name, to_net_dev(d));

	return count;
}

static DEVICE_ATTR(add_acl_instance, S_IWUSR, NULL, add_acl_instance);

static ssize_t delete_acl_instance(struct device *d,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	char name[INSTANCE_ACL_ID_SZ];
	char *crlf_pos = strchr(buf, '\n');

	strncpy(name, buf, INSTANCE_ACL_ID_SZ);
	if (crlf_pos)
		name[crlf_pos - buf] = 0;
	ipoib_delete_instance_acl(name, to_net_dev(d));

	return count;
}

static DEVICE_ATTR(delete_acl_instance, S_IWUSR, NULL, delete_acl_instance);

int ipoib_create_acl_sysfs(struct net_device *dev)
{
	int rc = 0;

	if (!ipoib_debug_level)
		dev_attr_acl_enabled.attr.mode = 0444;

	rc = device_create_file(&dev->dev, &dev_attr_acl_enabled);
	if (rc)
		return rc;

	if (!ipoib_debug_level)
		return 0;

	rc = device_create_file(&dev->dev, &dev_attr_add_acl);
	if (rc)
		return rc;
	rc = device_create_file(&dev->dev, &dev_attr_delete_acl);
	if (rc)
		return rc;
	rc = device_create_file(&dev->dev, &dev_attr_acl);
	if (rc)
		return rc;
	rc = device_create_file(&dev->dev, &dev_attr_add_acl_instance);
	if (rc)
		return rc;
	rc = device_create_file(&dev->dev, &dev_attr_delete_acl_instance);
	if (rc)
		return rc;
	rc = device_create_file(&dev->dev, &dev_attr_acl_instances);
	if (rc)
		return rc;

	return 0;
}

void delete_instance_acls(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ipoib_instance_acl *results[ACL_BATCH_SZ];
	unsigned int count, i;
	unsigned long idx = 0;

	count = 0;
	do {
		count = radix_tree_gang_lookup(&priv->instances_acls.instances,
					      (void **)results, idx,
					      ACL_BATCH_SZ);
		for (i = 0; i < count; i++) {
			ipoib_dbg(priv, "Clean instance ACL %s\n",
				  results[i]->name);
			ipoib_delete_instance_acl(results[i]->name, dev);
		}
		if (count)
			idx = jhash(results[i - 1]->name,
				    strlen(results[i - 1]->name), 0) + 1;
	} while (count);
}

int ipoib_create_instance_acl(const char *name, struct net_device *dev)
{
	u32 inst_name_hash;
	struct ipoib_instance_acl *instance_acl;
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	int rc = 0;

	if (strlen(name) > INSTANCE_ACL_ID_SZ)
		return -EINVAL;

	inst_name_hash = jhash(name, strlen(name), 0);
	mutex_lock(&priv->instances_acls.lock);
	if (radix_tree_lookup(&priv->instances_acls.instances, inst_name_hash))
		goto err_exist;

	instance_acl = (struct ipoib_instance_acl *)
		       kmalloc(sizeof(struct ipoib_instance_acl), GFP_KERNEL);
	if (!instance_acl)
		goto err_nomem;

	strcpy(instance_acl->name, name);
	ib_cm_acl_init(&instance_acl->acl);

	rc = radix_tree_insert(&priv->instances_acls.instances, inst_name_hash,
			       instance_acl);
	if (rc != 0)
		goto err_radix;

	priv->instances_acls.list_count++;

	__module_get(THIS_MODULE);

	goto out;

err_exist:
	ipoib_err(priv, "Instance ACL %s already exist\n", name);
	rc = -EEXIST;
	goto out;

err_nomem:
	ipoib_err(priv, "No memory to create Instance ACL %s\n", name);
	rc = -ENOMEM;
	goto out;

err_radix:
	ipoib_err(priv, "Error %d while trying to add %s\n", rc, name);
	kfree(instance_acl);

out:
	mutex_unlock(&priv->instances_acls.lock);
	return rc;
}

int ipoib_delete_instance_acl(const char *name, struct net_device *dev)
{
	u32 inst_name_hash;
	struct ipoib_instance_acl *instance_acl;
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	struct ib_cm_acl_elem *list;
	ssize_t list_count, i;
	int rc = 0;

	inst_name_hash = jhash(name, strlen(name), 0);
	mutex_lock(&priv->instances_acls.lock);
	instance_acl = (struct ipoib_instance_acl *)
		       radix_tree_delete(&priv->instances_acls.instances,
					 inst_name_hash);
	if (!instance_acl)
		goto err_notexist;

	/* Decrease reference count in main ACL */
	ib_cm_acl_scan(&instance_acl->acl, &list, &list_count);
	for (i = 0; i < list_count; i++) {
		/* Clean all referrence */
		do
			ib_cm_acl_delete(&priv->acl, list[i].subnet_prefix,
					 list[i].guid);
		while (ib_cm_acl_delete(&(instance_acl->acl),
		       list[i].subnet_prefix, list[i].guid));
	}
	kfree(list);

	ib_cm_acl_clean(&(instance_acl->acl));

	kfree(instance_acl);

	priv->instances_acls.list_count--;

	module_put(THIS_MODULE);

	goto out;

err_notexist:
	ipoib_err(priv, "Instance ACL %s is not exist\n", name);
	rc = -EINVAL;
	goto out;

out:
	mutex_unlock(&priv->instances_acls.lock);
	return rc;
}

struct ib_cm_acl *ipoib_get_instance_acl(const char *name,
					 struct net_device *dev)
{
	u32 inst_name_hash;
	struct ipoib_instance_acl *instance_acl;
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	inst_name_hash = jhash(name, strlen(name), 0);
	mutex_lock(&priv->instances_acls.lock);
	instance_acl = (struct ipoib_instance_acl *)
		       radix_tree_lookup(&priv->instances_acls.instances,
					 inst_name_hash);
	mutex_unlock(&priv->instances_acls.lock);
	if (!instance_acl) {
		ipoib_err(priv, "Instance ACL %s is not exist\n", name);
		return 0;
	}

	return &(instance_acl->acl);
}

void ipoib_init_acl(struct net_device *dev)
{
	struct ib_cm_dpp dpp;
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	INIT_RADIX_TREE(&priv->instances_acls.instances, GFP_KERNEL);
	priv->instances_acls.list_count = 0;
	mutex_init(&priv->instances_acls.lock);

	ipoib_dbg(priv, "Initializing ACL for device %s\n", dev->name);
	ib_cm_acl_init(&priv->acl);
	ib_cm_dpp_init(&dpp, priv->ca, priv->port, priv->pkey);
	ib_cm_register_acl(&priv->acl, &dpp);
}

void ipoib_clean_acl(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	delete_instance_acls(dev);

	ipoib_dbg(priv, "Clean ACL for device %s\n", dev->name);
	ib_cm_unregister_acl(&priv->acl);
	ib_cm_acl_clean(&priv->acl);
}
