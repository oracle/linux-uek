/*
 * Copyright (c) 2009 Mellanox Technologies. All rights reserved.
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

#include "vnic.h"
#include "vnic_data.h"
#include "vnic_fip_discover.h"

static void vnic_mace_dealloc(struct vnic_mac *mace)
{
	ASSERT(mace);
	kfree(mace);
}

static struct vnic_mac *vnic_mace_alloc(const u8 *mac, u16 vnic_id)
{
	struct vnic_mac *mace;

	mace = kzalloc(sizeof *mace, GFP_ATOMIC);
	if (!mace)
		return ERR_PTR(-ENOMEM);

	/* set mac entry fields */
	memcpy(mace->mac, mac, ETH_ALEN);
	mace->created = jiffies;
	mace->last_tx = jiffies;
	mace->vnic_id = vnic_id;

	return mace;
}

static void vnic_mace_del(struct vnic_login *login, struct vnic_mac *mace)
{
	ASSERT(mace);
	rb_erase(&mace->rb_node, &login->mac_tree);
}

static int vnic_mace_add(struct vnic_login *login, struct vnic_mac *mace)
{
	struct rb_node **n = &login->mac_tree.rb_node, *pn = NULL;
	struct vnic_mac *mace_t;
	int rc;

	while (*n) {
		pn = *n;
		mace_t = rb_entry(pn, struct vnic_mac, rb_node);
		rc = memcmp(mace->mac, mace_t->mac, ETH_ALEN);
		if (rc < 0)
			n = &pn->rb_left;
		else if (rc > 0)
			n = &pn->rb_right;
		else {
			rc = -EEXIST;
			goto out;
		}
	}

	rb_link_node(&mace->rb_node, pn, n);
	rb_insert_color(&mace->rb_node, &login->mac_tree);
	rc = 0;

out:
	return rc;
}

/* vnic_mace_search --
 * Return entry pointer if found, or ERR_PTR(-ENODATA) if not found.
 */
static struct vnic_mac *vnic_mace_search(struct vnic_login *login, u8 *mac)
{
	struct rb_node *n = login->mac_tree.rb_node;
	struct vnic_mac *mace_t;
	int rc;

	ASSERT(login);
	ASSERT(mac);

	while (n) {
		mace_t = rb_entry(n, struct vnic_mac, rb_node);
		ASSERT(mace_t);
		rc = memcmp(mac, mace_t->mac, ETH_ALEN);
		if (rc < 0)
			n = n->rb_left;
		else if (rc > 0)
			n = n->rb_right;
		else
			goto out;
	}

	mace_t = ERR_PTR(-ENODATA);

out:
	return mace_t;
}

/* vnic_mace_update --
 * Remove: -ENODATA if not found, if removed, update ref_cnt, return 0
 * Add:    -ENOMEM if no mem, -EEXIST if already exists,
 *         if added, update ref_cnt, return 0
 * NOTE: ref counters must be updated here, as this function is
 *       shared among multiple entry points
 */
int vnic_mace_update(struct vnic_login *login, u8 *mac, u16 vnic_id, int remove)
{
	struct vnic_mac *mace;
	int rc;

	mace = vnic_mace_search(login, mac);
	if (remove) {
		if (IS_ERR(mace))
			return -ENODATA;
		vnic_mace_del(login, mace);
		vnic_mace_dealloc(mace);
		/* update ref cnt */
		ASSERT(atomic_read(&login->vnic_child_cnt));
		atomic_dec(&login->vnic_child_cnt);
	} else {
		if (PTR_ERR(mace) != -ENODATA)
			return -EEXIST;

		/* test ref cnt */
		if (atomic_read(&login->vnic_child_cnt) + 1 > vnic_child_max) {
			vnic_warn(login->name, "too many child vNics, max %d\n",
				  vnic_child_max);
			return -EUSERS; /* too many users */
		}

		mace = vnic_mace_alloc(mac, vnic_id);
		if (!mace)
			return -ENOMEM;

		rc = vnic_mace_add(login, mace);
		if (rc) {
			vnic_mace_dealloc(mace);
			return rc;
		}
		/* update ref cnt */
		atomic_inc(&login->vnic_child_cnt);
		vnic_dbg_mac(login->name,
			     "updated mac "MAC_6_PRINT_FMT" remove %d\n",
			     MAC_6_PRINT_ARG(mac), remove);
	}

	return 0;
}

/* this function can be called from fast data-path 
 * need to make sure that login instance is protected here
 * likely/unlikely below were added to match the hard_start_xmit fast data flow
 * + caller must hold login->mac_rwlock (read_lock is enough because we only
 *   queue the job here)
 * + it queues a job to create a child
 */
int vnic_child_update(struct vnic_login *login, u8 *mac, int remove)
{
	struct vnic_mac *mace;
	char *cmd_str;
	struct fip_hadmin_cmd *cmd_hadmin;
	int count, rc = -EINVAL;
	u16 vnic_id = 0;

	vnic_dbg_func(login->name);

	mace = vnic_mace_search(login, mac);

	/* if asked to add, and data already exists, abort */
	if (likely(!remove && !IS_ERR(mace))) {
		mace->last_tx = jiffies;
		return -EEXIST;
	}

	if (!remove) {
		/* test if there is too many child vNics same check exist in
		 * vnic_mace_update(), but we have it here as well to let
		 * vnic_set_mac return friendly rc
		 */
		if (atomic_read(&login->vnic_child_cnt) + 1 > vnic_child_max) {
			vnic_warn(login->name, "too many child vNics, "
				  "max %d\n", vnic_child_max);
			return -EUSERS; /* too many users */
		}

		/* update last_tx */
		ASSERT(mace);
		/* generate new vnic_id only when new child is being added */
		vnic_id = atomic_inc_return(&login->port->vnic_child_ids);
		/* set bit 14 so we avoid conflict with normal host/net admin */
		vnic_id %= (1 << (VNIC_ID_LEN - 2));
		vnic_id |= (1 << (VNIC_ID_LEN - 2));

		/* TODO: update hadmin user-script and manual to make hadmin
		 * vnic_id interval >= 16K (1<<14 == 16384) so bit 14 is clear
		 * for parent host admin.
		 * to avoid atomic counter wrap around, move to bitmap array
		 */ 
	} else {
		/* if asked to remove, and data not found, abort */
		if (IS_ERR(mace))
			return -ENODATA;

		ASSERT(mace);
		vnic_id = mace->vnic_id;
	}

	/* allocate cmd structs, too big to be local vars
	 * use GFP_ATOMIC because this func can be called from data path
	 */
	cmd_str = kmalloc(sizeof *cmd_str * PAGE_SIZE, GFP_ATOMIC);
	if (!cmd_str)
		return -ENOMEM;

	cmd_hadmin = kmalloc(sizeof *cmd_hadmin, GFP_ATOMIC);
	if (!cmd_hadmin) {
		kfree(cmd_str);
		return -ENOMEM;
	}

	/* inherit command from parent, change:
	 * name, parent, mac, vnic_id and source
	 * Note: cannot use parent login->fip_vnic->cmd here
	 * in order to support net-admin-vnics
	 */
	vnic_login_cmd_init(cmd_hadmin);

	/* child vNic name scheme:
	 * eth<parent-cnt>.c<child-vnic-id>
	 * Note: avoid sysfs files conflict (that's why parent unique cnt must
	 * be included in the name here)
	 */
	snprintf(cmd_hadmin->c_name, MAX_INPUT_LEN, "%s%u.c%u",
		 "eth", login->cnt, vnic_id);
	snprintf(cmd_hadmin->c_mac, MAX_INPUT_LEN, MAC_6_PRINT_FMT,
		 MAC_6_PRINT_ARG(mac));
	snprintf(cmd_hadmin->c_vnic_id, MAX_INPUT_LEN, "%u",
		 vnic_id);
	snprintf(cmd_hadmin->c_eport, MAX_INPUT_LEN, "%s",
		 login->fip_vnic->gw_info.gw_port_name);
	snprintf(cmd_hadmin->c_parent, MAX_INPUT_LEN, "%s",
		 login->dev->name);
	snprintf(cmd_hadmin->c_bxname, MAX_INPUT_LEN, "%s",
		 login->fip_vnic->gw_info.system_name);
	snprintf(cmd_hadmin->c_bxguid, MAX_INPUT_LEN, VNIC_GUID_FMT,
		 VNIC_GUID_RAW_ARG(login->fip_vnic->gw_info.system_guid));

	/* all hadmin vNics must use same BX format (guid vs. name) */
	if (login->fip_vnic->hadmined) {
		snprintf(cmd_hadmin->c_bxname, MAX_INPUT_LEN, "%s",
			 login->fip_vnic->cmd.c_bxname);
		snprintf(cmd_hadmin->c_bxguid, MAX_INPUT_LEN, "%s",
			 login->fip_vnic->cmd.c_bxguid);
	}

	/* VLAN is optional, set it only when used by parent */
	if (login->vlan_used)
		snprintf(cmd_hadmin->c_vid, MAX_INPUT_LEN, "%d",
			 login->fip_vnic->vlan);

	/* ready to set the command */
	count = vnic_login_cmd_set(cmd_str, cmd_hadmin);
	if (!count)
		goto out;

	/* queue job (similar to sysfs write function,
	 * will eventually call fip_discover_hadmin_update_parent() ->
	 * vnic_mace_update()
	 */
	count = fip_hadmin_sysfs_update(login->port, cmd_str, count, remove);
	if (count <= 0 && count != -EEXIST)
		goto out;

	/* at this point, job queued, return success */
	rc = 0;

out:
	kfree(cmd_str);
	kfree(cmd_hadmin);
	return rc;
}

void vnic_child_flush(struct vnic_login *login, int all)
{
	struct rb_node *n;
	struct vnic_mac *mace, *mace_t;
	LIST_HEAD(local_list);

	vnic_dbg_func(login->name);

	n = rb_first(&login->mac_tree);
	while (n) {
		mace = rb_entry(n, struct vnic_mac, rb_node);
		list_add_tail(&mace->list, &local_list);
		n = rb_next(n);
	}

	list_for_each_entry_safe(mace, mace_t, &local_list, list) {
		list_del(&mace->list);
		/* if not-flush-all, and mac is dev_addr mac, skip this entry */
		if (!all && !memcmp(login->dev->dev_addr, mace->mac, ETH_ALEN))
			continue;
		vnic_child_update(login, mace->mac, 1);
		vnic_mace_del(login, mace);
		vnic_mace_dealloc(mace);
	}


}

/* find parent vNic
 * add the child vnic to its mac_tree
 * sync child qp_base_num with parent
 * for child removal, it's ok not to find the parent, or the child mac entry
 */
int vnic_parent_update(struct vnic_port *port, char *name, u16 vnic_id,
		       u8 *mac, u32 *qp_base_num_ptr, char *parent_name,
		       int remove)
{
	struct vnic_login *login;
	int rc = -ENODATA;

	vnic_dbg_func(name);

	mutex_lock(&port->mlock);
	list_for_each_entry(login, &port->login_list, list) {
		vnic_dbg_mac(name, "checking parent %s for child %s (expect %s)\n",
			     login->dev->name, name, parent_name);
		/* check if parent vnic has valid QPN and not being destroyed */
		if ((!strcmp(login->dev->name, parent_name) &&
		    test_bit(VNIC_STATE_LOGIN_PRECREATE_2, &login->fip_vnic->login_state) &&
		    !login->fip_vnic->flush) || (!strcmp(login->dev->name, parent_name) && remove)) {
			/* sync qp_base_num with parent */
			if (qp_base_num_ptr)
				*qp_base_num_ptr = login->qp_base_num;

			/* update mac_tree and mace vnic_id */
			vnic_dbg_mac(name, "update child %s remove=%d\n", name, remove);
			write_lock_bh(&login->mac_rwlock);
			rc = vnic_mace_update(login, mac, vnic_id, remove);
			vnic_child_update(login, mac, remove);
			write_unlock_bh(&login->mac_rwlock);
			break;
		}
	}

	mutex_unlock(&port->mlock);

	/* for vNic removal, ignore rc */
	return remove ? 0 : rc;
}
