/*
 * Copyright (c) 2012 Mellanox Technologies. All rights reserved
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * openfabric.org BSD license below:
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/in.h>
#include <linux/sysfs.h>
#include <linux/ctype.h>
#include <linux/inet.h>
#include <linux/rtnetlink.h>
#include <linux/etherdevice.h>
#include <net/net_namespace.h>

#include "eth_ipoib.h"

#define to_dev(obj)	container_of(obj, struct device, kobj)
#define to_parent(cd)	((struct parent *)(netdev_priv(to_net_dev(cd))))
#define MOD_NA_STRING		"N/A"

#define _sprintf(p, buf, format, arg...)				\
((PAGE_SIZE - (int)(p - buf)) <= 0 ? 0 :				\
	scnprintf(p, PAGE_SIZE - (int)(p - buf), format, ## arg))\

#define _end_of_line(_p, _buf)					\
do { if (_p - _buf) /* eat the leftover space */			\
		buf[_p - _buf - 1] = '\n';				\
} while (0)

/* helper functions */
static int get_emac(u8 *mac, char *s)
{
	if (sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   mac + 0, mac + 1, mac + 2, mac + 3, mac + 4,
		   mac + 5) != 6)
		return -1;

	return 0;
}

/* show/store functions per module (CLASS_ATTR) */
static ssize_t show_parents(struct class *cls, struct class_attribute *attr,
			    char *buf)
{
	char *p = buf;
	struct parent *parent;

	rtnl_lock(); /* because of parent_dev_list */

	list_for_each_entry(parent, &parent_dev_list, parent_list) {
		p += _sprintf(p, buf, "%s over IB port: %s\n",
			      parent->dev->name,
			      parent->ipoib_main_interface);
	}
	_end_of_line(p, buf);

	rtnl_unlock();
	return (ssize_t)(p - buf);
}

/* show/store functions per parent (DEVICE_ATTR) */
static ssize_t parent_show_neighs(struct device *d,
				  struct device_attribute *attr, char *buf)
{
	struct slave *slave;
	struct parent *parent = to_parent(d);
	char *p = buf;
	int i;

	read_lock_bh(&parent->lock);
	rcu_read_lock_bh();

	parent_for_each_slave_rcu(parent, slave) {
		for (i = 0; i < NEIGH_HASH_SIZE; i++) {
			struct neigh *neigh;
			struct hlist_node *n;
			hlist_for_each_entry_rcu(neigh, n, &slave->hash[i], hlist)
				p += _sprintf(p, buf, "SLAVE=%-10s EMAC=%pM IMAC=%pM:%pM:%pM:%.2x:%.2x\n",
					      slave->dev->name,
					      neigh->emac,
					      neigh->imac, neigh->imac + 6, neigh->imac + 12,
					      neigh->imac[18], neigh->imac[19]);
		}
	}
	rcu_read_unlock_bh();
	read_unlock_bh(&parent->lock);

	_end_of_line(p, buf);

	return (ssize_t)(p - buf);
}

struct neigh *parent_get_neigh_cmd(char op,
				   char *ifname, u8 *remac, u8 *rimac)
{
	struct neigh *neigh_cmd;

	neigh_cmd = kzalloc(sizeof *neigh_cmd, GFP_ATOMIC);
	if (!neigh_cmd) {
		pr_err("%s cannot allocate neigh struct\n", ifname);
		goto out;
	}

	/*
	 * populate emac field so it can be used easily
	 * in neigh_cmd_find_by_mac()
	 */
	memcpy(neigh_cmd->emac, remac, ETH_ALEN);
	memcpy(neigh_cmd->imac, rimac, INFINIBAND_ALEN);

	/* prepare the command as a string */
	sprintf(neigh_cmd->cmd, "%c%s %pM %pM:%pM:%pM:%.2x:%.2x",
		op, ifname, remac, rimac, rimac + 6, rimac + 12, rimac[18], rimac[19]);
out:
	return neigh_cmd;
}

static DEVICE_ATTR(neighs, S_IRUGO, parent_show_neighs,
		   NULL);

static ssize_t parent_show_vifs(struct device *d,
				struct device_attribute *attr, char *buf)
{
	struct slave *slave;
	struct parent *parent = to_parent(d);
	char *p = buf;

	read_lock_bh(&parent->lock);
	rcu_read_lock_bh();

	parent_for_each_slave_rcu(parent, slave) {
		if (is_zero_ether_addr(slave->emac)) {
			p += _sprintf(p, buf, "SLAVE=%-10s MAC=%-17s "
				      "VLAN=%s\n", slave->dev->name,
				      MOD_NA_STRING, MOD_NA_STRING);
		} else if (slave->vlan == VLAN_N_VID) {
			p += _sprintf(p, buf, "SLAVE=%-10s MAC=%pM VLAN=%s\n",
				      slave->dev->name,
				      slave->emac,
				      MOD_NA_STRING);
		} else {
			p += _sprintf(p, buf, "SLAVE=%-10s MAC=%pM VLAN=%d\n",
				      slave->dev->name,
				      slave->emac,
				      slave->vlan);
		}
	}
	rcu_read_unlock_bh();
	read_unlock_bh(&parent->lock);

	_end_of_line(p, buf);

	return (ssize_t)(p - buf);
}

static ssize_t parent_store_vifs(struct device *d,
				 struct device_attribute *attr,
				 const char *buffer, size_t count)
{
	char command[IFNAMSIZ + 1] = { 0, };
	char mac_str[ETH_ALEN * 3] = { 0, };
	char *ifname;
	u8 mac[ETH_ALEN];
	u16 vlan = VLAN_N_VID;
	int found = 0, ret = count;
	struct slave *slave = NULL, *slave_tmp;
	struct parent *parent = to_parent(d);

	sscanf(buffer, "%s %s %hd", command, mac_str, &vlan);

	/* check ifname */
	ifname = command + 1;
	if ((strlen(command) <= 1) || !dev_valid_name(ifname) ||
	    (command[0] != '+' && command[0] != '-'))
		goto err_no_cmd;

	rcu_read_lock_bh();
	/* check if ifname exist */
	parent_for_each_slave_rcu(parent, slave_tmp) {
		if (!strcmp(slave_tmp->dev->name, ifname)) {
			found = 1;
			slave = slave_tmp;
		}
	}

	if (!found) {
		pr_err("%s could not find slave\n", ifname);
		ret = -EINVAL;
		goto out_free_lock;
	}

	/* process command */
	if (command[0] == '+') {
		if (get_emac(mac, mac_str)) {
			pr_err("%s invalid mac input\n", ifname);
			ret = -EINVAL;
			goto out_free_lock;
		}
		found = parent_add_vif_param(parent->dev, slave->dev, vlan, mac);
		if (found)
			ret = -EINVAL;
	}

out_free_lock:
	rcu_read_unlock_bh();
	return ret;
err_no_cmd:
	pr_err("%s USAGE: (-|+)ifname [mac]\n", DRV_NAME);
	return -EPERM;

}

static DEVICE_ATTR(vifs, S_IRUGO | S_IWUSR, parent_show_vifs,
		   parent_store_vifs);

static ssize_t parent_show_slaves(struct device *d,
				  struct device_attribute *attr, char *buf)
{
	struct slave *slave;
	struct parent *parent = to_parent(d);
	char *p = buf;

	read_lock_bh(&parent->lock);
	rcu_read_lock_bh();

	parent_for_each_slave_rcu(parent, slave)
		p += _sprintf(p, buf, "%s\n", slave->dev->name);

	rcu_read_unlock_bh();
	read_unlock_bh(&parent->lock);

	_end_of_line(p, buf);

	return (ssize_t)(p - buf);
}

static ssize_t parent_store_slaves(struct device *d,
				   struct device_attribute *attr,
				   const char *buffer, size_t count)
{
	char command[IFNAMSIZ + 1] = { 0, };
	char *ifname;
	int res, ret = count;
	struct slave *slave;
	struct net_device *dev = NULL;
	struct parent *parent = to_parent(d);

	/* Quick sanity check -- is the parent interface up? */
	if (!(parent->dev->flags & IFF_UP)) {
		pr_warn("%s: doing slave updates when "
			"interface is down.\n", dev->name);
	}

	if (!rtnl_trylock()) {/* because __dev_get_by_name */
		pr_warn("%s: %s not available right now\n",
			parent->dev->name, __func__);
		return restart_syscall();
	}

	sscanf(buffer, "%16s", command);

	ifname = command + 1;
	if ((strlen(command) <= 1) || !dev_valid_name(ifname))
		goto err_no_cmd;

	if (command[0] == '+') {
		/* Got a slave name in ifname. Is it already in the list? */
		dev = __dev_get_by_name(&init_net, ifname);
		if (!dev) {
			pr_warn("%s: Interface %s does not exist!\n",
				parent->dev->name, ifname);
			ret = -EINVAL;
			goto out;
		}

		rcu_read_lock_bh();
		parent_for_each_slave_rcu(parent, slave) {
			if (slave->dev == dev) {
				pr_err("%s ERR- Interface %s is already enslaved!\n",
				       parent->dev->name, dev->name);
				ret = -EPERM;
			}
		}
		rcu_read_unlock_bh();

		if (ret < 0)
			goto out;

		pr_info("%s: adding slave %s\n",
			parent->dev->name, ifname);

		res = parent_enslave(parent->dev, dev);
		if (res)
			ret = res;

		goto out;
	}

	if (command[0] == '-') {
		dev = NULL;

		rcu_read_lock_bh();
		parent_for_each_slave_rcu(parent, slave)
			if (strnicmp(slave->dev->name, ifname, IFNAMSIZ) == 0) {
				dev = slave->dev;
				break;
			}
		rcu_read_unlock_bh();

		if (dev) {
			pr_info("%s: removing slave %s\n",
				parent->dev->name, dev->name);
			res = parent_release_slave(parent->dev, dev);
			if (res) {
				ret = res;
				goto out;
			}
		} else {
			pr_warn("%s: unable to remove non-existent "
				"slave for parent %s.\n",
				ifname, parent->dev->name);
			ret = -ENODEV;
		}
		goto out;
	}

err_no_cmd:
	pr_err("%s USAGE: (-|+)ifname\n", DRV_NAME);
	ret = -EPERM;

out:
	rtnl_unlock();
	return ret;
}

static DEVICE_ATTR(slaves, S_IRUGO | S_IWUSR, parent_show_slaves,
		   parent_store_slaves);


static ssize_t parent_show_served(struct device *d,
				  struct device_attribute *attr, char *buf)
{
	struct parent *parent = to_parent(d);
	char *p = buf;
	struct guest_emac_info *emac_info;
	struct ip_member *ipm;

	read_lock_bh(&parent->lock);
	read_lock_bh(&parent->emac_info_lock);

	list_for_each_entry(emac_info, &parent->emac_ip_list, list) {
		if (VALID == emac_info->rec_state || NEW == emac_info->rec_state) {
			list_for_each_entry(ipm, &emac_info->ip_list, list) {
				if (emac_info->vlan == VLAN_N_VID) {
					p += _sprintf(p, buf, "SLAVE=%s MAC=%pM IP=%pI4 VLAN=%s\n",
						      emac_info->ifname, emac_info->emac, &ipm->ip,
						      MOD_NA_STRING);
				} else {
					p += _sprintf(p, buf, "SLAVE=%s MAC=%pM IP=%pI4 VLAN=%d\n",
						      emac_info->ifname, emac_info->emac, &ipm->ip,
						      emac_info->vlan);
				}
			}
		}
	}

	read_unlock_bh(&parent->emac_info_lock);
	read_unlock_bh(&parent->lock);

	 _end_of_line(p, buf);

	 return (ssize_t)(p - buf);

}

#define IP_ADDR_LEN 48/* in bytes: x.y.z.w*/

static ssize_t parent_store_served(struct device *d,
				   struct device_attribute *attr,
				   const char *buffer, size_t count)
{
	char command[512] = { 0, };
	char *mac_str;
	char ip_str[IP_ADDR_LEN] = { 0, };
	u8 mac[ETH_ALEN];
	u16 vlan = VLAN_N_VID;
	__be32 ip;
	int ret = count, ret2 = 0;
	struct parent *parent = to_parent(d);

	/* format: +52:54:00:ca:0b:0f 11.134.45.1 7 */
	sscanf(buffer, "%s %s %hd", command, ip_str, &vlan);

	mac_str = command + 1;
	if ((strlen(command) <= 1) || /*!dev_valid_name(ifname) ||*/
	    (command[0] != '+' && command[0] != '-'))
		goto err_no_cmd;
	/* process command */
	if (command[0] == '+') {
		if (get_emac(mac, mac_str)) {
			pr_err("%s invalid mac input\n", parent->dev->name);
			return -EINVAL;
		}

		ip = in_aton(ip_str);
		/*
		 * takes parent->lock, before calling add_emac_ip_info.
		 * because add_emac_ip_info can reschedule work, make sure
		 * the driver is not at the middle of getting down.
		 */
		pr_info("Adding new served ip: %pI4, mac: %pM, vlan:%d.\n",
			&ip, mac, vlan);
		read_lock_bh(&parent->lock);
		ret2 = add_emac_ip_info(parent->dev, ip, mac, vlan, GFP_ATOMIC);
		read_unlock_bh(&parent->lock);
		if (ret2)
			return -EINVAL;

		return ret;
	}

	if (command[0] == '-') {

		if (get_emac(mac, mac_str)) {
			pr_err("invalid mac input: %s\n", mac_str);
			return -EINVAL;
		}

		ip = in_aton(ip_str);

		pr_info("Delete served ip: %pI4, mac: %pM, vlan:%d.\n",
			&ip, mac, vlan);

		free_ip_ent_in_emac_rec(parent, mac, vlan, ip);
		return ret;

	}

err_no_cmd:
	pr_err("%s USAGE: (-|+)ifname [mac]\n", DRV_NAME);
	ret = -EPERM;

	return ret;

}

static DEVICE_ATTR(served, S_IRUGO | S_IWUSR, parent_show_served,
		   parent_store_served);


/* sysfs create/destroy functions */
static struct attribute *per_parent_attrs[] = {
	&dev_attr_slaves.attr, /* DEVICE_ATTR(slaves..) */
	&dev_attr_vifs.attr,
	&dev_attr_neighs.attr,
	&dev_attr_served.attr,
	NULL,
};

/* name spcase  support */
static const void *eipoib_namespace(struct class *cls,
				    const struct class_attribute *attr)
{
	const struct eipoib_net *eipoib_n =
		container_of(attr,
			     struct eipoib_net, class_attr_eipoib_interfaces);
	return eipoib_n->net;
}

static struct attribute_group parent_group = {
	/* per parent sysfs files under: /sys/class/net/<IF>/eth/.. */
	.name = "eth",
	.attrs = per_parent_attrs
};

int create_slave_symlinks(struct net_device *master,
			  struct net_device *slave)
{
	char linkname[IFNAMSIZ+7];
	int ret = 0;

	ret = sysfs_create_link(&(slave->dev.kobj), &(master->dev.kobj),
				"eth_parent");
	if (ret)
		return ret;

	sprintf(linkname, "slave_%s", slave->name);
	ret = sysfs_create_link(&(master->dev.kobj), &(slave->dev.kobj),
				linkname);
	return ret;

}

void destroy_slave_symlinks(struct net_device *master,
			    struct net_device *slave)
{
	char linkname[IFNAMSIZ+7];

	sysfs_remove_link(&(slave->dev.kobj), "eth_parent");
	sprintf(linkname, "slave_%s", slave->name);
	sysfs_remove_link(&(master->dev.kobj), linkname);
}

static struct class_attribute class_attr_eth_ipoib_interfaces = {
	.attr = {
		.name = "eth_ipoib_interfaces",
		.mode = S_IWUSR | S_IRUGO,
	},
	.show = show_parents,
	.namespace = eipoib_namespace,
};

/* per module sysfs file under: /sys/class/net/eth_ipoib_interfaces */
int mod_create_sysfs(struct eipoib_net *eipoib_n)
{
	int rc;
	/* defined in CLASS_ATTR(eth_ipoib_interfaces..) */
	eipoib_n->class_attr_eipoib_interfaces =
		class_attr_eth_ipoib_interfaces;

	sysfs_attr_init(&eipoib_n->class_attr_eipoib_interfaces.attr);

	rc = netdev_class_create_file(&eipoib_n->class_attr_eipoib_interfaces);
	if (rc)
		pr_err("%s failed to create sysfs (rc %d)\n",
		       eipoib_n->class_attr_eipoib_interfaces.attr.name, rc);

	return rc;
}

void mod_destroy_sysfs(struct eipoib_net *eipoib_n)
{
	netdev_class_remove_file(&eipoib_n->class_attr_eipoib_interfaces);
}

int parent_create_sysfs_entry(struct parent *parent)
{
	struct net_device *dev = parent->dev;
	int rc;

	rc = sysfs_create_group(&(dev->dev.kobj), &parent_group);
	if (rc)
		pr_info("failed to create sysfs group\n");

	return rc;
}

void parent_destroy_sysfs_entry(struct parent *parent)
{
	struct net_device *dev = parent->dev;

	sysfs_remove_group(&(dev->dev.kobj), &parent_group);
}
