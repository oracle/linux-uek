/*
 * Copyright (c) 2004 Topspin Communications.  All rights reserved.
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

#include <linux/init.h>
#include <linux/seq_file.h>

#include <asm/uaccess.h>

#include "ipoib.h"

static ssize_t show_parent(struct device *d, struct device_attribute *attr,
			   char *buf)
{
	struct net_device *dev = to_net_dev(d);
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	return sprintf(buf, "%s\n", priv->parent->name);
}
static DEVICE_ATTR(parent, S_IRUGO, show_parent, NULL);

int __ipoib_vlan_add(struct ipoib_dev_priv *ppriv, struct ipoib_dev_priv *priv,
		     u16 pkey, int type)
{
	int result;

	priv->max_ib_mtu = ppriv->max_ib_mtu;
	/* MTU will be reset when mcast join happens */
	priv->dev->mtu   = IPOIB_UD_MTU(priv->max_ib_mtu);
	priv->mcast_mtu  = priv->admin_mtu = priv->dev->mtu;
	set_bit(IPOIB_FLAG_SUBINTERFACE, &priv->flags);

	result = ipoib_set_dev_features(priv, ppriv->ca);
	if (result)
		goto err;

	priv->pkey = pkey;

	memcpy(priv->dev->dev_addr, ppriv->dev->dev_addr, INFINIBAND_ALEN);
	priv->dev->broadcast[8] = pkey >> 8;
	priv->dev->broadcast[9] = pkey & 0xff;

	result = ipoib_dev_init(priv->dev, ppriv->ca, ppriv->port);
	if (result < 0) {
		ipoib_warn(ppriv, "failed to initialize subinterface: "
			   "device %s, port %d",
			   ppriv->ca->name, ppriv->port);
		goto err;
	}

	result = register_netdevice(priv->dev);
	if (result) {
		ipoib_warn(priv, "failed to initialize; error %i", result);
		goto register_failed;
	}

	priv->parent = ppriv->dev;

	ipoib_create_debug_files(priv->dev);

	/* RTNL childs don't need proprietary sysfs entries */
	if (type == IPOIB_LEGACY_CHILD) {
		if (ipoib_cm_add_mode_attr(priv->dev))
			goto sysfs_failed;
		if (ipoib_add_pkey_attr(priv->dev))
			goto sysfs_failed;
		if (ipoib_add_umcast_attr(priv->dev))
			goto sysfs_failed;
		if (device_create_file(&priv->dev->dev, &dev_attr_parent))
			goto sysfs_failed;
		if (ipoib_add_channels_attr(priv->dev))
			goto sysfs_failed;
	}

	priv->child_type  = type;
	priv->dev->iflink = ppriv->dev->ifindex;
	list_add_tail(&priv->list, &ppriv->child_intfs);

	return 0;

sysfs_failed:
	result = -ENOMEM;
	ipoib_delete_debug_files(priv->dev);
	unregister_netdevice(priv->dev);

register_failed:
	ipoib_dev_cleanup(priv->dev);

err:
	return result;
}

static int ipoib_vlan_add_common(struct net_device *pdev,
				 unsigned short pkey,
				 unsigned char child_index,
				 char *child_name_buf)
{
	struct ipoib_dev_priv *ppriv, *priv;
	char intf_name[IFNAMSIZ];
	int result;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;
	
	priv = NULL;
	ppriv = netdev_priv(pdev);

	if (!rtnl_trylock()) {
		ipoib_warn(ppriv, "%s: RTNL_LOCK is held, try later\n", __func__);
		return -EPERM;
	}

	down_write(&ppriv->vlan_rwsem);

	if (child_name_buf == NULL) {
		/*
		 * If child name is not provided, we generate one using
		 * name of parent, pkey and child index.
		 *
		 * First ensure this isn't a duplicate. We check all of the
		 * child interfaces to make sure the Pkey AND the child index
		 * don't match.
		 * (Note: another "named child" with default child index 0 can
		 * already exist with same pkey so we allow that! A duplicate
		 * name with child_index 0 will be detected by failure of
		 * register_netdevice() with EEXIST -
		 * same as for "named child" where interface name is
		 * explicitly provided and not generated here!)
		 */
		if (child_index != 0) {
			list_for_each_entry(priv, &ppriv->child_intfs, list) {
				if (priv->pkey == pkey &&
				    priv->child_index == child_index) {
					result = -ENOTUNIQ;
					priv = NULL;
					goto out;
				}
			}
		}

		/*
		 * for the case of non-legacy and same pkey childs we wanted
		 * to use a notation of ibN.pkey:index and ibN:index but this
		 * is problematic with tools like ifconfig who treat devices
		 * with ":" in their names as aliases which are restriced,
		 * e.t w.r.t counters, etc
		 */
		if (ppriv->pkey != pkey && child_index == 0) /* legacy child */
			snprintf(intf_name, sizeof intf_name, "%s.%04x",
				 ppriv->dev->name, pkey);
		else if (ppriv->pkey != pkey && child_index != 0)
			/* non-legacy child */
			snprintf(intf_name, sizeof intf_name, "%s.%04x.%d",
				 ppriv->dev->name, pkey, child_index);
		else if (ppriv->pkey == pkey && child_index != 0)
			/* same pkey child */
			snprintf(intf_name, sizeof intf_name, "%s.%d",
				 ppriv->dev->name, child_index);
		else  {
			ipoib_warn(ppriv, "wrong pkey/child_index "
				   "pairing %04x %d\n", pkey, child_index);
			result = -EINVAL;
			goto out;
		}
	} else {
		/*
		 * Note: Duplicate intf_name will be detected later in the code
		 * by register_netdevice() below returning EEXIST!
		 */
		strncpy(intf_name, child_name_buf, IFNAMSIZ);
	}

	priv = ipoib_intf_alloc(intf_name, ppriv);
	if (!priv) {
		result = -ENOMEM;
		goto out;
	}

	/*
	 * keep the child_index inside the priv, in order to find it when it
	 * needs to be deleted.
	 */
	priv->child_index = child_index;

	result = __ipoib_vlan_add(ppriv, priv, pkey, IPOIB_LEGACY_CHILD);

out:
	up_write(&ppriv->vlan_rwsem);

	rtnl_unlock();

	if (result && priv)
		free_netdev(priv->dev);


	return result;
}

int ipoib_vlan_add(struct net_device *pdev, unsigned short pkey,
		unsigned char child_index)
{
	return ipoib_vlan_add_common(pdev, pkey, child_index, NULL);
}

int ipoib_named_vlan_add(struct net_device *pdev, unsigned short pkey,
			 char *child_name_buf)
{
	return ipoib_vlan_add_common(pdev, pkey, 0, child_name_buf);
}


static int ipoib_vlan_delete_common(struct net_device *pdev,
				    unsigned short pkey,
				    unsigned char child_index,
				    char *child_name_buf)
{
	struct ipoib_dev_priv *ppriv, *priv, *tpriv;
	struct net_device *dev = NULL;
	char gen_intf_name[IFNAMSIZ];

	gen_intf_name[0] = '\0'; /* initialize - paranoia! */

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	ppriv = netdev_priv(pdev);

	if (!rtnl_trylock()) {
		ipoib_warn(ppriv, "%s: RTNL_LOCK is held, try later\n", __func__);
		return -EPERM;
	}

	down_write(&ppriv->vlan_rwsem);
	if (child_name_buf == NULL) {
		/*
		 * If child name is not provided, we generate the
		 * expected one using name of parent, pkey and child index
		 * and use it in addition to pkey value and child index
		 * (other children with same pkey may exist which have been
		 * created by create_named_child()).
		 *
		 * Note: see comment in ipoib_vlan_add_common() about
		 * the notation ibN.pkey.index etc.
		 */
		if (ppriv->pkey != pkey && child_index == 0) /* legacy child */
			snprintf(gen_intf_name, sizeof gen_intf_name,
				 "%s.%04x", ppriv->dev->name, pkey);
		else if (ppriv->pkey != pkey && child_index != 0)
			/* non-legacy child */
			snprintf(gen_intf_name,
				 sizeof gen_intf_name, "%s.%04x.%d",
				 ppriv->dev->name, pkey, child_index);
		else if (ppriv->pkey == pkey && child_index != 0)
			/* same pkey child */
			snprintf(gen_intf_name,
				 sizeof gen_intf_name, "%s.%d",
				 ppriv->dev->name, child_index);
		else  {
			ipoib_warn(ppriv, "wrong pkey/child_index "
				   "pairing %04x %d\n", pkey, child_index);
			up_write(&ppriv->vlan_rwsem);
			rtnl_unlock();
			return -EINVAL;
		}
	}

	list_for_each_entry_safe(priv, tpriv, &ppriv->child_intfs, list) {
		/* user named child (match by name) OR */
		if ((child_name_buf && priv->dev &&
		     !strcmp(child_name_buf, priv->dev->name)) ||
		    /*
		     * OR classic (dev.hexpkey generated name) child
		     * (match by pkey and child-index and expected name))
		     */
			/* found child to delete */
		    (!child_name_buf && priv->pkey == pkey &&
		     priv->child_type == IPOIB_LEGACY_CHILD &&
		     priv->child_index == child_index &&
		     priv->dev && !strcmp(gen_intf_name, priv->dev->name))) {
			list_del(&priv->list);
			dev = priv->dev;
			break;
		}
	}
	up_write(&ppriv->vlan_rwsem);

	if (dev) {
		ipoib_dbg(ppriv, "delete child vlan %s\n", dev->name);
		unregister_netdevice(dev);
	}
	rtnl_unlock();

	if (dev) {
		free_netdev(dev);
		return 0;
	}

	return -ENODEV;
}

int ipoib_vlan_delete(struct net_device *pdev, unsigned short pkey,
		unsigned char child_index)
{

	return ipoib_vlan_delete_common(pdev, pkey, child_index, NULL);
}

int ipoib_named_vlan_delete(struct net_device *pdev, char *child_name_buf)
{
	return ipoib_vlan_delete_common(pdev, 0, 0, child_name_buf);
}
