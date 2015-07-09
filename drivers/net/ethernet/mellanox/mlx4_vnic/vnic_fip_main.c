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
#include "vnic_fip.h"
#include "vnic_fip_discover.h"

struct workqueue_struct *fip_wq;

void fip_refresh_mcasts(struct fip_discover *discover)
{
	struct fip_gw_data *gw;
	struct fip_vnic_data *vnic;

	fip_discover_mcast_reattach(discover, discover->port);

	down_read(&discover->l_rwsem);
	list_for_each_entry(gw, &discover->gw_list, list)
		list_for_each_entry(vnic, &gw->vnic_list, gw_vnics) {
			if (vnic->flush != FIP_FULL_FLUSH && vnic->state > FIP_VNIC_MCAST_INIT)
				vnic_tree_mcast_detach(&vnic->mcast_tree);
		}

	list_for_each_entry(gw, &discover->gw_list, list) {
            list_for_each_entry(vnic, &gw->vnic_list, gw_vnics)  {
                if (vnic->flush != FIP_FULL_FLUSH && vnic->state > FIP_VNIC_MCAST_INIT)
					vnic_tree_mcast_attach(&vnic->mcast_tree);
			}
            /* restart path query */
            if (vnic_sa_query && gw->state >= FIP_GW_CTRL_PATH_QUERY && gw->flush == FIP_NO_FLUSH)
				fip_discover_gw_fsm_move(gw, FIP_GW_CTRL_PATH_QUERY);
    }
	up_read(&discover->l_rwsem);

}

void port_fip_discover_restart(struct work_struct *work)
{
	struct vnic_port *port =
	    container_of(work, struct vnic_port, discover_restart_task.work);
	struct fip_discover *discover;
	struct vnic_login *login;

	vnic_dbg_mark();
	mutex_lock(&port->start_stop_lock);
	vnic_dbg_mark();
	mutex_lock(&port->mlock);
	if (vnic_port_query(port))
		vnic_warn(port->name, "vnic_port_query failed\n");

	/* bring vnics links down */
	list_for_each_entry(login, &port->login_list, list)
		vnic_mcast_del_all(&login->mcast_tree);

	mutex_unlock(&port->mlock);
	list_for_each_entry(discover, &port->fip.discover_list, discover_list) {
		if (fip_discover_cleanup(port, discover, 0)) {
			vnic_dbg(port->name, "fip_discover_cleanup flushed\n");
			goto out;
		}
	}

	list_for_each_entry(discover, &port->fip.discover_list, discover_list) {
		if (fip_discover_init(port, discover, discover->pkey, 0)) {
			vnic_warn(port->name, "failed to alloc discover resources\n");
		}
	}
out:
	mutex_unlock(&port->start_stop_lock);
	return;
}

void vnic_port_fip_cleanup(struct vnic_port *port, int lock)
{
	struct fip_discover *discover, *tmp_discover;

	if (lock)
		mutex_lock(&port->start_stop_lock);

	list_for_each_entry_safe(discover, tmp_discover, &port->fip.discover_list, discover_list) {
		vnic_dbg_fip_p0(port->name, "Discovery cleanup of PKEY=0x%x\n", discover->pkey);

		list_del(&discover->discover_list);
		vnic_info("Removed fip discovery %s port %d pkey 0x%x\n",
			  port->dev->ca->name, port->num, discover->pkey);
		fip_discover_cleanup(port, discover, 1);
		kfree(discover);
	}

	if (lock)
		mutex_unlock(&port->start_stop_lock);
}


int vnic_port_fip_init(struct vnic_port *port)
{
	int rc;
	struct fip_discover *discover;
	int i;

	if (no_bxm)
		return 0;

	vnic_discovery_pkeys_count = vnic_discovery_pkeys_count > MAX_NUM_PKEYS_DISCOVERY ?
		MAX_NUM_PKEYS_DISCOVERY : vnic_discovery_pkeys_count;

	if (vnic_discovery_pkeys_count == 0 ||
	    (vnic_discovery_pkeys_count == MAX_NUM_PKEYS_DISCOVERY &&
	     vnic_discovery_pkeys[0] == 0)) {
		vnic_discovery_pkeys[0] = 0xffff;
		vnic_discovery_pkeys_count = 1;
		vnic_dbg_fip_p0(port->name, "Creating default PKEY for Discovery\n");
	}

	mutex_lock(&port->start_stop_lock);

	for (i = 0; i < vnic_discovery_pkeys_count; i++) {
		vnic_discovery_pkeys[i] &= 0xffff;
		vnic_discovery_pkeys[i] |= 0x8000;

		vnic_dbg_fip_p0(port->name, "Init Discovery=%d on PKEY=0x%x\n", i, vnic_discovery_pkeys[i]);

		discover = kzalloc(sizeof(struct fip_discover), GFP_KERNEL);
		if (!discover) {
			vnic_warn(port->name, "discover alloc failed\n");
			rc = -ENOMEM;
			goto fail;
		}

		INIT_LIST_HEAD(&discover->discover_list);

		vnic_info("Added fip discovery %s port %d PKEY 0x%x\n",
			  port->dev->ca->name, port->num,
			  vnic_discovery_pkeys[i]);

		list_add_tail(&discover->discover_list, &port->fip.discover_list);
		rc = fip_discover_init(port, discover, vnic_discovery_pkeys[i], 1);
		if (rc) {
			vnic_warn(port->name, "fip_discover_init pkey=0x%x "
				  "failed\n", discover->pkey);
			list_del(&discover->discover_list);
			kfree(discover);
			goto fail;
		}
	}
	mutex_unlock(&port->start_stop_lock);
	return 0;

fail:
	mutex_unlock(&port->start_stop_lock);
	vnic_port_fip_cleanup(port, 1);
	return rc;
}

