/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Mellanox Technologies Ltd.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
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

/*#include "core_priv.h"*/
#include "mlx4_ib.h"
#include "alias_GUID.h"
#include <linux/slab.h>
#include <linux/string.h>

#include <rdma/ib_mad.h>
/*The function returns the administartively value of that GUID.
meaning, the value that was setted by the administrator.
Values:
	0 - let the opensm to assign.
	0xff - delete this entry.
	other - assigned by administrator.
*/
static ssize_t show_admin_alias_guid(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	int record_num;/*0-15*/
	int guid_index_in_rec; /*0 - 7*/
	struct mlx4_ib_iov_sysfs_attr *mlx4_ib_iov_dentry =
		container_of(attr, struct mlx4_ib_iov_sysfs_attr, dentry);
	struct mlx4_ib_iov_port *port = mlx4_ib_iov_dentry->ctx;
	struct mlx4_ib_dev *mdev = port->dev;

	record_num = mlx4_ib_iov_dentry->entry_num / 8 ;
	guid_index_in_rec = mlx4_ib_iov_dentry->entry_num % 8 ;

	return sprintf(buf, "%llx\n",
		       be64_to_cpu(mdev->sriov.alias_guid.ports_guid[port->num - 1].
				   all_rec_per_port[record_num].all_recs[guid_index_in_rec]));
}

/*The function stors the (new)administartively value of that GUID.
Values:
	0 - let the opensm to assign.
	0xff - delete this entry.
	other - assigned by administrator.
*/
static ssize_t store_admin_alias_guid(struct device *dev,
				      struct device_attribute *attr,
				      const char *buf, size_t count)
{
	int record_num;/*0-15*/
	int guid_index_in_rec; /*0 - 7*/
	struct mlx4_ib_iov_sysfs_attr *mlx4_ib_iov_dentry =
		container_of(attr, struct mlx4_ib_iov_sysfs_attr, dentry);
	struct mlx4_ib_iov_port *port = mlx4_ib_iov_dentry->ctx;
	struct mlx4_ib_dev *mdev = port->dev;
	u64 sysadmin_ag_val;

	record_num = mlx4_ib_iov_dentry->entry_num / 8;
	guid_index_in_rec = mlx4_ib_iov_dentry->entry_num % 8;
	if (0 == record_num && 0 == guid_index_in_rec) {
		printk(KERN_ERR  "GUID 0 block 0 is RO\n");
		return count;
	}

	sscanf(buf,"%llx", &sysadmin_ag_val);
	mdev->sriov.alias_guid.ports_guid[port->num - 1].all_rec_per_port[record_num].
		all_recs[guid_index_in_rec] = cpu_to_be64(sysadmin_ag_val);

	/*change the state to be be pending for update*/
	mdev->sriov.alias_guid.ports_guid[port->num - 1].all_rec_per_port[record_num].status
		 = MLX4_GUID_INFO_STATUS_IDLE ;

	mdev->sriov.alias_guid.ports_guid[port->num - 1].all_rec_per_port[record_num].method
	= MLX4_GUID_INFO_RECORD_SET;

	/*set the method, is it set or delete*/
	switch (sysadmin_ag_val) {
	case MLX4_GUID_FOR_DELETE_VAL:
		mdev->sriov.alias_guid.ports_guid[port->num - 1].all_rec_per_port[record_num].method 
			= MLX4_GUID_INFO_RECORD_DELETE;
		mdev->sriov.alias_guid.ports_guid[port->num - 1].all_rec_per_port[record_num].ownership
			= MLX4_GUID_SYSADMIN_ASSIGN;
		mdev->sriov.alias_guid.ports_guid[port->num - 1].all_rec_per_port[record_num].guid_indexes = 0;
		break;
	/*if the sysadmin asks for the SM to re-assign:*/
	case MLX4_NOT_SET_GUID:
		mdev->sriov.alias_guid.ports_guid[port->num - 1].all_rec_per_port[record_num].ownership
			= MLX4_GUID_DRIVER_ASSIGN;
		break;
	/*The sysadmin asks for specific value.*/
	default:
		mdev->sriov.alias_guid.ports_guid[port->num - 1].all_rec_per_port[record_num].ownership
			= MLX4_GUID_SYSADMIN_ASSIGN;
		break;
	}

	/*set the record index*/

	mdev->sriov.alias_guid.ports_guid[port->num - 1].all_rec_per_port[record_num].guid_indexes
		|= get_alias_guid_comp_mask_from_index(guid_index_in_rec);

	init_alias_guid_work(mdev, port->num - 1);

	return count;
}

static ssize_t show_port_gid(struct device *dev,
			     struct device_attribute *attr,
			     char *buf)
{
	struct mlx4_ib_iov_sysfs_attr *mlx4_ib_iov_dentry =
		container_of(attr, struct mlx4_ib_iov_sysfs_attr, dentry);
	struct mlx4_ib_iov_port *port = mlx4_ib_iov_dentry->ctx;
	struct mlx4_ib_dev *mdev = port->dev;
	union ib_gid gid;
	ssize_t ret;

	ret = mlx4_ib_get_indexed_gid(&mdev->ib_dev,
				       port->num,
				       mlx4_ib_iov_dentry->entry_num,
				       &gid);
	if (ret)
		return ret;
	ret = sprintf(buf, "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
                                     be16_to_cpu(((__be16 *) gid.raw)[0]),
                                     be16_to_cpu(((__be16 *) gid.raw)[1]),
                                     be16_to_cpu(((__be16 *) gid.raw)[2]),
                                     be16_to_cpu(((__be16 *) gid.raw)[3]),
                                     be16_to_cpu(((__be16 *) gid.raw)[4]),
                                     be16_to_cpu(((__be16 *) gid.raw)[5]),
                                     be16_to_cpu(((__be16 *) gid.raw)[6]),
                                     be16_to_cpu(((__be16 *) gid.raw)[7]));
	return ret;
}

static ssize_t show_phys_port_pkey(struct device *dev,
				   struct device_attribute *attr,
				   char *buf)
{
	struct mlx4_ib_iov_sysfs_attr *mlx4_ib_iov_dentry =
		container_of(attr, struct mlx4_ib_iov_sysfs_attr, dentry);
	struct mlx4_ib_iov_port *port = mlx4_ib_iov_dentry->ctx;
	struct mlx4_ib_dev *mdev = port->dev;
	u16 pkey;
	ssize_t ret;

	ret = mlx4_ib_query_pkey(&mdev->ib_dev, port->num,
				 mlx4_ib_iov_dentry->entry_num, &pkey);
	if (ret)
		return ret;

	return sprintf(buf, "0x%04x\n", pkey);
}

#define DENTRY_REMOVE(_dentry)						\
do {									\
	sysfs_remove_file((_dentry)->kobj, &(_dentry)->dentry.attr);	\
} while (0);

static int create_sysfs_entry(void *_ctx, struct mlx4_ib_iov_sysfs_attr *_dentry,
			       char *_name, struct kobject *_kobj,
			      ssize_t (*show)(struct device *dev,
					      struct device_attribute *attr,
					      char *buf),
			      ssize_t (*store)(struct device *dev,
					       struct device_attribute *attr,
					       const char *buf, size_t count)
			      )
{
	int ret = 0;
	struct mlx4_ib_iov_sysfs_attr *vdentry = _dentry;

	vdentry->ctx = _ctx;
	vdentry->dentry.show = show;
	vdentry->dentry.store = store;
	vdentry->dentry.attr.name = vdentry->name;
	vdentry->dentry.attr.mode = 0;
	vdentry->kobj = _kobj;
	snprintf(vdentry->name, 15, "%s", _name);

	if (vdentry->dentry.store)
		vdentry->dentry.attr.mode |= S_IWUGO;

	if (vdentry->dentry.show)
		vdentry->dentry.attr.mode |= S_IRUGO;

	ret = sysfs_create_file(vdentry->kobj, &vdentry->dentry.attr);
	if (ret) {
		printk(KERN_ERR  "failed to create %s\n", vdentry->dentry.attr.name);
		vdentry->ctx = NULL;
		return ret;
	}

	return ret;
}

int add_sysfs_port_mcg_attr(struct mlx4_ib_dev *device, int port_num,
		struct attribute *attr)
{
	struct mlx4_ib_iov_port *port = &device->iov_ports[port_num - 1];
	int ret;

	ret = sysfs_create_file(port->mcgs_parent, attr);
	if (ret)
		printk(KERN_ERR  "failed to create %s\n", attr->name);

	return ret;
}

void del_sysfs_port_mcg_attr(struct mlx4_ib_dev *device, int port_num,
		struct attribute *attr)
{
	struct mlx4_ib_iov_port *port = &device->iov_ports[port_num - 1];

	sysfs_remove_file(port->mcgs_parent, attr);
}

static int add_port_entries(struct mlx4_ib_dev *device, int port_num)
{
	int i;
	char buff[10];
	struct mlx4_ib_iov_port *port = NULL;
	int ret = 0 ;
	struct ib_port_attr attr;
	/*get the table size.*/
	ret = mlx4_ib_query_port(&device->ib_dev, port_num, &attr);
	if (ret)
		goto err;

	port = &device->iov_ports[port_num - 1];
	port->dev = device;
	port->num = port_num;
/*	iov -
		port num -
			--admin_guids
			--(operational)gids
			--mcg_table
*/
	port->dentr_ar = kzalloc(sizeof (struct mlx4_ib_iov_sysfs_attr_ar),
				 GFP_KERNEL);
	if (!port->dentr_ar) {
		printk(KERN_ERR "add_port_entries: could not allocate dentry array\n");
		ret = -ENOMEM;
		goto err;
	}
	sprintf(buff, "%d", port_num);
	port->cur_port = kobject_create_and_add(buff,
				 kobject_get(device->ports_parent));
	if (!port->cur_port) {
		ret = -ENOMEM;
		goto kobj_create_err;
	}
	/*setting the admin GUID*/
	port->admin_alias_parent = kobject_create_and_add("admin_guids",
						  kobject_get(port->cur_port));
	if (!port->admin_alias_parent) {
		ret = -ENOMEM;
		goto err_admin_guids1;
	}

	for (i = 0 ; i < attr.gid_tbl_len; i++) {
		sprintf(buff, "%d",i);
		port->dentr_ar->dentries[i].entry_num = i;
		ret = create_sysfs_entry(port, &port->dentr_ar->dentries[i],
					  buff, port->admin_alias_parent,
					  show_admin_alias_guid, store_admin_alias_guid);
		if (ret)
			goto err_admin_guids2;
	}

	/*setting the operational GUID*/
	port->gids_parent = kobject_create_and_add("gids",
						  kobject_get(port->cur_port));
	if (!port->gids_parent) {
		ret = -ENOMEM;
		goto err_gids1;
	}

	for (i = 0 ; i < attr.gid_tbl_len; i++) {
		sprintf(buff, "%d",i);
		port->dentr_ar->dentries[attr.gid_tbl_len + i].entry_num = i;
		ret = create_sysfs_entry(port,
					  &port->dentr_ar->dentries[attr.gid_tbl_len + i],
					  buff,
					  port->gids_parent, show_port_gid, NULL);
		if (ret)
			goto err_gids2;
	}

	/* physical port pkey table */
	port->pkeys_parent = kobject_create_and_add("pkeys",
						  kobject_get(port->cur_port));
	if (!port->pkeys_parent) {
		ret = -ENOMEM;
		goto err_pkeys1;
	}

	for (i = 0 ; i < attr.pkey_tbl_len; i++) {
		sprintf(buff, "%d",i);
		port->dentr_ar->dentries[2 * attr.gid_tbl_len + i].entry_num = i;
		ret = create_sysfs_entry(port,
					 &port->dentr_ar->dentries[2 * attr.gid_tbl_len + i],
					 buff, port->pkeys_parent,
					 show_phys_port_pkey, NULL);
		if (ret)
			goto err_pkeys2;
	}

	/* MCGs table */
	port->mcgs_parent = kobject_create_and_add("mcgs",
						  kobject_get(port->cur_port));
	if (!port->mcgs_parent) {
		ret = -ENOMEM;
		goto err_mcgs1;
	}

	return 0 ;

err_mcgs1:
err_pkeys2:
	kobject_put(port->pkeys_parent);

err_pkeys1:
err_gids2:
	kobject_put(port->gids_parent);

err_gids1:

err_admin_guids2:
	kobject_put(port->admin_alias_parent);

err_admin_guids1:
	kobject_put(port->cur_port);

kobj_create_err:
	kfree(port->dentr_ar);

err:
	printk(KERN_ERR "add_port_entries FAILED: for port:%d, error: %d\n",
	       port_num, ret);
	return ret;
}

static void get_name(struct mlx4_ib_dev *dev, char *name, int i, int max)
{
	char base_name[9];

	/*pci_name format is: bus:dev:func -> xxxx:yy:zz.n*/
	strlcpy(name, pci_name(dev->dev->pdev), max);
	strncpy(base_name, name,8); /*till xxxx:yy:*/
	base_name[8] ='\0';
	/*with no ARI only 3 last bits are used so when the fn it higher than 8
	 need to add it to the dev num, so till 8 wil be count in the last number*/
	sprintf(name, "%s%.2d.%d", base_name,(i/8), (i%8));
}

struct mlx4_port {
	struct kobject         kobj;
	struct mlx4_ib_dev    *dev;
	struct attribute_group pkey_group;
	struct attribute_group gid_group;
	u8                     port_num;
	int		       slave;
};


static void mlx4_port_release(struct kobject *kobj)
{
	struct mlx4_port *p = container_of(kobj, struct mlx4_port, kobj);
	struct attribute *a;
	int i;

	for (i = 0; (a = p->pkey_group.attrs[i]); ++i)
		kfree(a);

	kfree(p->pkey_group.attrs);

	for (i = 0; (a = p->gid_group.attrs[i]); ++i)
		kfree(a);

	kfree(p->gid_group.attrs);

	kfree(p);
}

struct port_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mlx4_port *, struct port_attribute *, char *buf);
	ssize_t (*store)(struct mlx4_port *, struct port_attribute *,
			 const char *buf, size_t count);
};

static ssize_t port_attr_show(struct kobject *kobj,
			      struct attribute *attr, char *buf)
{
	struct port_attribute *port_attr =
		container_of(attr, struct port_attribute, attr);
	struct mlx4_port *p = container_of(kobj, struct mlx4_port, kobj);

	if (!port_attr->show)
		return -EIO;

	return port_attr->show(p, port_attr, buf);
}

static ssize_t port_attr_store(struct kobject *kobj,
			       struct attribute *attr,
			       const char *buf, size_t size)
{
	struct port_attribute *port_attr =
		container_of(attr, struct port_attribute, attr);
	struct mlx4_port *p = container_of(kobj, struct mlx4_port, kobj);

	if (!port_attr->store)
		return -EIO;

	return port_attr->store(p, port_attr, buf, size);
}

static struct sysfs_ops port_sysfs_ops = {
	.show = port_attr_show,
	.store = port_attr_store,
};

static struct kobj_type port_type = {
	.release       = mlx4_port_release,
	.sysfs_ops     = &port_sysfs_ops,
};

struct port_table_attribute {
	struct port_attribute	attr;
	char			name[8];
	int			index;
};

static ssize_t show_port_pkey(struct mlx4_port *p, struct port_attribute *attr,
			      char *buf)
{
	struct port_table_attribute *tab_attr =
		container_of(attr, struct port_table_attribute, attr);
	ssize_t ret = -ENODEV;

	if (p->dev->pkeys.virt2phys_pkey[p->slave][p->port_num - 1][tab_attr->index] >=
	    (p->dev->dev->caps.pkey_table_len[p->port_num]))
		ret = sprintf(buf, "none\n");
	else
		ret = sprintf(buf, "%d\n",
			      p->dev->pkeys.virt2phys_pkey[p->slave]
			      [p->port_num - 1][tab_attr->index]);
		      

	return ret;
}

static ssize_t store_port_pkey(struct mlx4_port *p, struct port_attribute *attr,
			       const char *buf, size_t count)
{
	struct port_table_attribute *tab_attr =
		container_of(attr, struct port_table_attribute, attr);
	int idx;
	int err;

	/* do not allow remapping Dom0 virtual pkey table */
	if (p->slave == p->dev->dev->caps.function)
		return -EINVAL;

	if (!strncasecmp(buf, "no", 2))
		idx = p->dev->dev->caps.pkey_table_max_len[p->port_num] - 1;
	else if (sscanf(buf, "%i", &idx) != 1 ||
		 idx >= p->dev->dev->caps.pkey_table_len[p->port_num] ||
		 idx < 0)
		return -EINVAL;

	p->dev->pkeys.virt2phys_pkey[p->slave][p->port_num - 1][tab_attr->index] = idx;
	mlx4_sync_pkey_table(p->dev->dev, p->slave, p->port_num, tab_attr->index, idx);
	err = mlx4_gen_pkey_eqe(p->dev->dev, p->slave, p->port_num);
	if (err) {
		printk("mlx4_gen_pkey_eqe failed for slave %d, port %d, index %d\n",
		       p->slave, p->port_num, idx);
		return err;
	}

	return count;
}

static ssize_t show_port_gid_idx(struct mlx4_port *p, struct port_attribute *attr,
				 char *buf)
{
	struct port_table_attribute *tab_attr =
		container_of(attr, struct port_table_attribute, attr);

	return sprintf(buf, "%d\n", ACT_GID_INDEX(p->dev->dev, tab_attr->index, p->slave));
}


static struct attribute **
alloc_group_attrs(ssize_t (*show)(struct mlx4_port *,
				  struct port_attribute *, char *buf),
		  ssize_t (*store)(struct mlx4_port *, struct port_attribute *,
				   const char *buf, size_t count),
		  int len)
{
	struct attribute **tab_attr;
	struct port_table_attribute *element;
	int i;

	tab_attr = kcalloc(1 + len, sizeof(struct attribute *), GFP_KERNEL);
	if (!tab_attr)
		return NULL;

	for (i = 0; i < len; i++) {
		element = kzalloc(sizeof(struct port_table_attribute),
				  GFP_KERNEL);
		if (!element)
			goto err;

		if (snprintf(element->name, sizeof(element->name),
			     "%d", i) >= sizeof(element->name)) {
			kfree(element);
			goto err;
		}

		element->attr.attr.name  = element->name;
		if (store) {
			element->attr.attr.mode  = S_IWUSR | S_IRUGO;
			element->attr.store	 = store;
		} else
			element->attr.attr.mode  = S_IRUGO;

		element->attr.show       = show;
		element->index		 = i;

		tab_attr[i] = &element->attr.attr;
	}

	return tab_attr;

err:
	while (--i >= 0)
		kfree(tab_attr[i]);
	kfree(tab_attr);
	return NULL;
}

static int add_port(struct mlx4_ib_dev *dev, int port_num, int slave)
{
	struct mlx4_port *p;
	int i;
	int ret;

	p = kzalloc(sizeof *p, GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	p->dev = dev;
	p->port_num = port_num;
	p->slave = slave;

	ret = kobject_init_and_add(&p->kobj, &port_type,
				   kobject_get(dev->dev_ports_parent[slave]),
				   "%d", port_num);
	if (ret)
		goto err_alloc;

	p->pkey_group.name  = "pkey_idx";
	p->pkey_group.attrs = alloc_group_attrs(show_port_pkey, store_port_pkey,
						dev->dev->caps.pkey_table_len[port_num]);
	if (!p->pkey_group.attrs)
		goto err_put;

	ret = sysfs_create_group(&p->kobj, &p->pkey_group);
	if (ret)
		goto err_free_pkey;

	p->gid_group.name  = "gid_idx";
	p->gid_group.attrs = alloc_group_attrs(show_port_gid_idx, NULL, dev->dev->gids_per_func);
	if (!p->gid_group.attrs)
		goto err_free_pkey;

	ret = sysfs_create_group(&p->kobj, &p->gid_group);
	if (ret)
		goto err_free_gid;

	list_add_tail(&p->kobj.entry, &dev->pkeys.pkey_port_list[slave]);
	return 0;

err_free_gid:
	for (i = 0; i < dev->dev->gids_per_func; ++i)
		kfree(p->gid_group.attrs[i]);

	kfree(p->gid_group.attrs);

err_free_pkey:
	for (i = 0; i < dev->dev->caps.pkey_table_len[port_num]; ++i)
		kfree(p->pkey_group.attrs[i]);

	kfree(p->pkey_group.attrs);

err_put:
	kobject_put(dev->dev_ports_parent[slave]);

err_alloc:
	kfree(p);

	return ret;
}

static int register_one_pkey_tree(struct mlx4_ib_dev *device, int slave)
{
	char name[32];
	int err;
	int port;

	get_name(device, name, slave, sizeof name);

	device->pkeys.device_parent[slave] = kobject_create_and_add(name,
						kobject_get(device->iov_parent));
	if (!device->pkeys.device_parent[slave]) {
		err = -ENOMEM;
		goto fail_dev;
	}

	INIT_LIST_HEAD(&device->pkeys.pkey_port_list[slave]);

	device->dev_ports_parent[slave] = kobject_create_and_add("ports",
					kobject_get(device->pkeys.device_parent[slave]));
	if (!device->dev_ports_parent[slave]) {
		err = -ENOMEM;
		goto err_ports;
	}

	for (port = 1; port <= device->dev->caps.num_ports; ++port) {
		err = add_port(device, port, slave);
		if (err)
			goto err_add;
	}

	return 0;

err_add:
	{
		struct kobject *p, *t;
		struct mlx4_port *port;

		list_for_each_entry_safe(p, t, &device->pkeys.pkey_port_list[slave], entry) {
			list_del(&p->entry);
			port = container_of(p, struct mlx4_port, kobj);
			sysfs_remove_group(p, &port->pkey_group);
			sysfs_remove_group(p, &port->gid_group);
			kobject_put(p);
		}
	}
	kobject_put(device->dev_ports_parent[slave]);
err_ports:
	kobject_put(device->pkeys.device_parent[slave]);

fail_dev:
	return err;
}

static int register_pkey_tree(struct mlx4_ib_dev *device)
{
	int i;

	if (!device->dev->caps.sqp_demux)
		return 0;

	for (i = 0; i <= device->dev->sr_iov; ++i)
		register_one_pkey_tree(device, i);

	return 0;
}

static void unregister_pkey_tree(struct mlx4_ib_dev *device)
{
	int slave;
	struct kobject *p, *t;
	struct mlx4_port *port;

	if (!device->dev->caps.sqp_demux)
		return;

	for (slave = device->dev->sr_iov; slave >= 0; --slave) {
		list_for_each_entry_safe(p, t, &device->pkeys.pkey_port_list[slave], entry) {
			list_del(&p->entry);
			port = container_of(p, struct mlx4_port, kobj);
			sysfs_remove_group(p, &port->pkey_group);
			sysfs_remove_group(p, &port->gid_group);
			kobject_put(p);
			kobject_put(device->dev_ports_parent[slave]);
		}
		kobject_put(device->dev_ports_parent[slave]);
		kobject_put(device->pkeys.device_parent[slave]);
		kobject_put(device->pkeys.device_parent[slave]);
		kobject_put(device->iov_parent);
	}
}

int mlx4_ib_device_register_sysfs(struct mlx4_ib_dev *device)
{

	int i;
	int ret = 0;

	if (!device->dev->caps.sqp_demux)
		return 0;

	device->iov_parent = kobject_create_and_add("iov",
					kobject_get(device->ib_dev.ports_parent->parent));
	if (!device->iov_parent) {
		ret = -ENOMEM;
		goto err;
	}
	device->ports_parent = kobject_create_and_add("ports",
					kobject_get(device->iov_parent));
	if (!device->iov_parent) {
		ret = -ENOMEM;
		goto err_port;
	}
	for (i = 1; i <= device->ib_dev.phys_port_cnt; ++i) {
		ret = add_port_entries(device, i);
		if (ret)
			goto err_port;
	}

	ret = register_pkey_tree(device);
	if (ret)
		goto err_pkey;

	return ret;


err_pkey:

err_port:
	kobject_put(device->ib_dev.ports_parent->parent);
err:
	printk(KERN_ERR "mlx4_ib_device_register_sysfs Error\n");
	return ret;

}
void unregister_alias_guid_tree(struct mlx4_ib_dev *device)
{
	struct mlx4_ib_iov_port *p;
	int i;

	if (!device->dev->caps.sqp_demux)
		return;

	for (i = 0; i < MLX4_MAX_PORTS; i++) {
		p = &device->iov_ports[i];
		kobject_put(p->admin_alias_parent);
		kobject_put(p->gids_parent);
		kobject_put(p->pkeys_parent);
		kobject_put(p->mcgs_parent);
		kobject_put(p->cur_port);
		kobject_put(p->cur_port);
		kobject_put(p->cur_port);
		kobject_put(p->cur_port);
		kobject_put(p->cur_port);
		kobject_put(p->dev->ports_parent);
		kfree(p->dentr_ar);
	}
}

void mlx4_ib_device_unregister_sysfs(struct mlx4_ib_dev *device)
{
	unregister_alias_guid_tree(device);
	unregister_pkey_tree(device);
	kobject_put(device->ports_parent);
	kobject_put(device->iov_parent);
	kobject_put(device->iov_parent);
	kobject_put(device->ib_dev.ports_parent->parent);
}
