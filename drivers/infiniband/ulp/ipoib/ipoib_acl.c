/*
 * Copyright(c) 2018 Oracle
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
 */

#include <linux/module.h>
#include <linux/jhash.h>
#include "ipoib.h"

static ssize_t show_acl_enabled(struct device *d,
				struct device_attribute *attr, char *buf)
{
	struct ipoib_dev_priv *priv = ipoib_priv(to_net_dev(d));

	return sprintf(buf, "%d\n", priv->acl.enabled ? 1 : 0);
}

static ssize_t set_acl_enabled(struct device *d, struct device_attribute *attr,
			       const char *buf, size_t count)
{
	struct ipoib_dev_priv *priv = ipoib_priv(to_net_dev(d));

	priv->acl.enabled = !!strcmp(buf, "0\n");
	return count;
}

static DEVICE_ATTR(acl_enabled, S_IWUSR | S_IRUGO, show_acl_enabled,
		   set_acl_enabled);

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
			strcat(buf, results[i]->name);
		}

		if (count)
			idx = jhash(results[i - 1]->name,
				    strlen(results[i - 1]->name), 0) + 1;
	} while (count);
}

int ipoib_create_acl_sysfs(struct net_device *dev)
{
	if (!ipoib_debug_level)
		dev_attr_acl_enabled.attr.mode = 0444;

	return device_create_file(&dev->dev, &dev_attr_acl_enabled);
}

void delete_instance_acls(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = ipoib_priv(dev);
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
	struct ipoib_dev_priv *priv = ipoib_priv(dev);
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
	if (rc)
		goto err_radix;

	priv->instances_acls.list_count++;

	__module_get(THIS_MODULE);

	goto out;

err_exist:
	ipoib_err(priv, "Instance ACL %s already exists\n", name);
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
	struct ipoib_dev_priv *priv = ipoib_priv(dev);
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
		/* Clean all references */
		do {
			ib_cm_acl_delete(&priv->acl, list[i].subnet_prefix,
					 list[i].guid);
		} while (ib_cm_acl_delete(&(instance_acl->acl),
					  list[i].subnet_prefix, list[i].guid));
	}
	kfree(list);

	ib_cm_acl_clean(&(instance_acl->acl));

	kfree(instance_acl);

	priv->instances_acls.list_count--;

	module_put(THIS_MODULE);

	goto out;

err_notexist:
	ipoib_err(priv, "Instance ACL %s does not exist\n", name);
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
	struct ipoib_dev_priv *priv = ipoib_priv(dev);

	inst_name_hash = jhash(name, strlen(name), 0);
	mutex_lock(&priv->instances_acls.lock);
	instance_acl = (struct ipoib_instance_acl *)
		       radix_tree_lookup(&priv->instances_acls.instances,
					 inst_name_hash);
	mutex_unlock(&priv->instances_acls.lock);
	if (!instance_acl) {
		ipoib_err(priv, "Instance ACL %s does not exist\n", name);
		return 0;
	}

	return &(instance_acl->acl);
}

void ipoib_init_acl(struct net_device *dev)
{
	struct ib_cm_dpp dpp;
	struct ipoib_dev_priv *priv = ipoib_priv(dev);

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
	struct ipoib_dev_priv *priv = ipoib_priv(dev);

	delete_instance_acls(dev);

	ipoib_dbg(priv, "Clean ACL for device %s\n", dev->name);
	ib_cm_unregister_acl(&priv->acl);
	ib_cm_acl_clean(&priv->acl);
}
