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

#include <linux/err.h>
#include <linux/seq_file.h>
#include <linux/debugfs.h>
#include <linux/version.h>

#include "vnic.h"
#include "vnic_data.h"
#include "vnic_fip_discover.h"

#define ALL_VLAN_GW_VID "all"

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0))
#define __MODULE_KOBJ_TYPE struct module_kobject
#else
#define __MODULE_KOBJ_TYPE struct module
#endif

char *login_dentry_name(char *buf, struct vnic_login *login, char *str)
{
	snprintf(buf, VNIC_SYSFS_FLEN, "%s%d-%s", "vnic",
		 login->cnt, str);
	return buf;
}

char *port_dentry_name(char *buf, struct vnic_port *port, char *str)
{
	snprintf(buf, VNIC_SYSFS_FLEN, "%s_%s_%d",
		 str, port->dev->name, port->num);
	return buf;
}

char *vnic_dentry_name(char *buf, struct fip_vnic_data *vnic, char *str)
{
	snprintf(buf, VNIC_SYSFS_FLEN, "%s-%s-%s", "vnic",
		 vnic->interface_name, str);
	return buf;
}

#ifndef _BP_NO_ATT_OWNER
#define DENTRY_OWNER(_vdentry)						\
	(_vdentry)->dentry.attr.owner = THIS_MODULE;			\
	(_vdentry)->kobj = &vdentry->dentry.attr.owner->mkobj.kobj;
#else
#define DENTRY_OWNER(_vdentry)						\
	(_vdentry)->kobj = &(THIS_MODULE)->mkobj.kobj;
#endif

#define DENTRY_REMOVE(_dentry)						\
do {									\
	vnic_dbg_sysfs((_dentry)->name, "deleted\n");			\
	sysfs_remove_file((_dentry)->kobj, &(_dentry)->dentry.attr);	\
	(_dentry)->ctx = NULL;						\
} while (0);

#define DENTRY_CREATE(_ctx, _dentry, _name, _show, _store)		\
do {									\
	struct vnic_sysfs_attr *vdentry = _dentry;			\
	vdentry->ctx = _ctx;						\
	vdentry->dentry.show = _show;					\
	vdentry->dentry.store = _store;					\
	vdentry->dentry.attr.name = vdentry->name;			\
	vdentry->dentry.attr.mode = 0;					\
	DENTRY_OWNER(vdentry);						\
	snprintf(vdentry->name, VNIC_SYSFS_FLEN, "%s", _name);		\
	if (vdentry->dentry.store)					\
		vdentry->dentry.attr.mode |= S_IWUSR;			\
	if (vdentry->dentry.show)					\
		vdentry->dentry.attr.mode |= S_IRUGO;			\
	vnic_dbg_sysfs(_ctx->name, "creating %s\n",			\
		vdentry->name);						\
	if (strlen(_name) > VNIC_SYSFS_FLEN) {				\
		vnic_err(_ctx->name, "name too long %d > %d\n",		\
			 (int)strlen(_name), VNIC_SYSFS_FLEN);		\
		vdentry->ctx = NULL;					\
		break;							\
	}								\
	if (sysfs_create_file(vdentry->kobj, &vdentry->dentry.attr)) {	\
		vnic_err(_ctx->name, "failed to create %s\n",		\
			 vdentry->dentry.attr.name);			\
		vdentry->ctx = NULL;					\
		break;							\
	}								\
	vnic_dbg_sysfs(_ctx->name, "created %s\n", vdentry->name);	\
} while (0);

/* helper functions */
static const char *port_phys_state_str(enum ib_port_state pstate)
{
	switch (pstate) {
	case 0:
		return "no_state_change";
	case 1:
		return "sleep";
	case 2:
		return "polling";
	case 3:
		return "disabled";
	case 4:
		return "port_configuration_training";
	case 5:
		return "up";
	case 6:
		return "error_recovery";
	case 7:
		return "phy_test";
	default:
		return "invalid_state";
	}
}
static const char *port_state_str(enum ib_port_state pstate)
{
	switch (pstate) {
	case IB_PORT_DOWN:
		return "down";
	case IB_PORT_INIT:
		return "initializing";
	case IB_PORT_ARMED:
		return "armed";
	case IB_PORT_ACTIVE:
		return "active";
	case IB_PORT_NOP:
		return "nop";
	case IB_PORT_ACTIVE_DEFER:
		return "defer";
	default:
		return "invalid_state";
	}
}

/* store/show functions */
static ssize_t vnic_neigh_show(struct module_attribute *attr,
			       __MODULE_KOBJ_TYPE *mod, char *buf)
{
	char *p = buf;
	struct vnic_sysfs_attr *vnic_dentry =
		container_of(attr, struct vnic_sysfs_attr, dentry);
	struct vnic_login *login = vnic_dentry->ctx;
	struct vnic_neigh *neighe;
	struct vnic_mcast *mcaste;
	struct rb_node *n;
	unsigned long flags;

	/* check if GW entry is ready */
	if (!login->gw_neigh)
		goto out;
	ASSERT(login->gw_neigh);

	/* print GW entry */
	neighe = login->gw_neigh;
	p += _sprintf(p, buf, "G:MAC["MAC_6_PRINT_FMT"] VID[0x%04x] "
		     "VID_USED[%d] QPN[0x%06x] LID[0x%04x] RSS[%d] SL[%d] VALID[%d]\n",
		     MAC_6_PRINT_ARG(neighe->mac),
		     be16_to_cpu(login->vid), login->vlan_used, neighe->qpn,
		     neighe->lid, neighe->rss, neighe->sl, neighe->valid);

	/* print neigh tree entries */
	n = rb_first(&login->neigh_tree);
	while (n) {
		neighe = rb_entry(n, struct vnic_neigh, rb_node);
		p += _sprintf(p, buf, "U:MAC["MAC_6_PRINT_FMT"] VID[0x%04x] "
			     "VID_USED[%d] QPN[0x%06x] LID[0x%04x] RSS[%d] SL[%d] VALID[%d]\n",
			     MAC_6_PRINT_ARG(neighe->mac),
			     be16_to_cpu(login->vid), login->vlan_used,
			     neighe->qpn, neighe->lid, neighe->rss, neighe->sl, neighe->valid);
		n = rb_next(n);
	}

	/* print mcast tree entries */
	spin_lock_irqsave(&login->mcast_tree.mcast_rb_lock, flags);
	n = rb_first(&login->mcast_tree.mcast_tree);
	while (n) {
		u16 lid = 0xFFFF;
		mcaste = rb_entry(n, struct vnic_mcast, rb_node);
		n = rb_next(n);
		if (test_bit(MCAST_ATTACHED, &mcaste->state))
			lid = mcaste->port_mcaste->rec.mlid;
		p += _sprintf(p, buf, "M:MAC["MAC_6_PRINT_FMT"] VID[0x%04x] "
			     "VID_USED[%d] QPN[0x%06x] LID[0x%04x] RSS[%d] SL[%d]\n",
			     MAC_6_PRINT_ARG(mcaste->mac),
			     0, login->vlan_used, IB_MULTICAST_QPN, lid, 0, mcaste->port_mcaste->sa_mcast->rec.sl);
	}
	spin_unlock_irqrestore(&login->mcast_tree.mcast_rb_lock, flags);

out:
	return (ssize_t)(p - buf);
}

/* store/show functions */
static ssize_t vnic_member_show(struct module_attribute *attr,
			       __MODULE_KOBJ_TYPE *mod, char *buf)
{
	char *p = buf;
	struct vnic_sysfs_attr *vnic_dentry =
		container_of(attr, struct vnic_sysfs_attr, dentry);
	struct vnic_login *login = vnic_dentry->ctx;
	int i;

	if (!login->is_lag)
		goto out;

	netif_tx_lock_bh(login->dev);
	p += _sprintf(p, buf, "GW member count=%d active count=%d hash bitmask=0x%X\n",
		     login->lag_member_count, login->lag_member_active_count, login->lag_prop.hash_mask);

	p += _sprintf(p, buf, "GW hash mapping table:\n");

	for (i=0; i<LAG_MAP_TABLE_SIZE; i+=8) {
		p += _sprintf(p, buf, "%3d %3d %3d %3d %3d %3d %3d %3d\n",
		       login->lag_gw_map[i], login->lag_gw_map[i+1], login->lag_gw_map[i+2], login->lag_gw_map[i+3],
		       login->lag_gw_map[i+4], login->lag_gw_map[i+5], login->lag_gw_map[i+6], login->lag_gw_map[i+7]);
	}

	p += _sprintf(p, buf, "\nGW member state info:   (0x1-created, 0x2-eport up, 0x4-mcast join complete, 0x8-member in use)\n");

	for (i=0; i<MAX_LAG_MEMBERS; i++) {
		p += _sprintf(p, buf, "%.2d GW id=%.3d State=0x%.3x LID=%.3d QPN=0x%.6x SL[%d] VALID[%d]\n", i,
			      login->lag_gw_neigh[i].gw_id,
			      login->lag_gw_neigh[i].info,
			      login->lag_gw_neigh[i].neigh.lid,
			      login->lag_gw_neigh[i].neigh.qpn,
			      login->lag_gw_neigh[i].neigh.sl,
			      login->lag_gw_neigh[i].neigh.valid);
	}
	netif_tx_unlock_bh(login->dev);

out:
	return (ssize_t)(p - buf);
}

static ssize_t vnic_login_show(struct module_attribute *attr,
			     __MODULE_KOBJ_TYPE *mod, char *buf)
{
	char *p = buf, tmp_line[VNIC_SYSFS_LLEN];
	struct vnic_sysfs_attr *vnic_dentry =
	    container_of(attr, struct vnic_sysfs_attr, dentry);
	struct vnic_login *login = vnic_dentry->ctx;
	struct fip_vnic_data *vnic_fip = login->fip_vnic;
	int rc, eport_connected = test_bit(VNIC_STATE_LOGIN_CREATE_2, &vnic_fip->login_state);
	u16 pkey_used = 0;
	int lag_gw;
	int ret;

	ASSERT(login->dev);
	ASSERT(login->port->dev->ca);

	/* NETDEV attributes */
	p += _sprintf(p, buf, "NETDEV_NAME   %s\n", login->dev->name);
	p += _sprintf(p, buf, "NETDEV_LINK   %s\n",
		     netif_carrier_ok(login->dev) ? "up" : "down");
	p += _sprintf(p, buf, "NETDEV_OPEN   %s\n",
		     (login->dev->flags & IFF_UP) ? "yes" : "no");
	p += _sprintf(p, buf, "NETDEV_QSTOP  %s\n",
		     netif_queue_stopped(login->dev) ? "yes" : "no");
	p += _sprintf(p, buf, "NETDEV_MTU    %d/%d\n",
		      (int)login->dev->mtu,
		      (int)login->max_mtu);

	/* IOA attributes */
	p += _sprintf(p, buf, "IOA_PORT      %s:%d\n",
		      login->port->dev->ca->name,
		      login->port->num);
	p += _sprintf(p, buf, "IOA_NAME      %s\n",
		      login->desc);
	p += _sprintf(p, buf, "IOA_LID       0x%04x\n", login->port->attr.lid);
	p += _sprintf(p, buf, "IOA_GUID      "VNIC_GUID_FMT"\n",
		     VNIC_GUID_RAW_ARG(login->port->gid.raw + 8));
	p += _sprintf(p, buf, "IOA_LOG_LINK  %s\n",
		     port_phys_state_str(login->port->attr.phys_state));
	p += _sprintf(p, buf, "IOA_PHY_LINK  %s\n",
		     port_state_str(login->port->attr.state));
	p += _sprintf(p, buf, "IOA_MTU       %d\n", login->port->max_mtu_enum);


	/* EPORT and BX attributes */
	if (no_bxm) {
		p += _sprintf(p, buf, "EPORT_STATE   %s\n", "bridgeless");
	} else if (vnic_fip) {
		p += _sprintf(p, buf, "EPORT_STATE   %s\n",
			      !eport_connected ? "disconnected" :
			      (fip_vnic_get_eport_state(vnic_fip) ?
			       "up" : "down"));
		p += _sprintf(p, buf, "EPORT_NAME    %s\n",
			      fip_vnic_get_eport_name(vnic_fip, tmp_line) ?
			      NOT_AVAILABLE_STRING : tmp_line);
		p += _sprintf(p, buf, "EPORT_QPN     0x%06x\n",
			      login->gw_neigh ? login->gw_neigh->qpn : 0);
		p += _sprintf(p, buf, "EPORT_LID     0x%04x\n",
			      login->gw_neigh ? login->gw_neigh->lid : 0);
		p += _sprintf(p, buf, "EPORT_ID      %u\n", login->gw_port_id);

		p += _sprintf(p, buf, "BX_NAME       %s\n",
			      fip_vnic_get_bx_name(vnic_fip, tmp_line) ?
			      NOT_AVAILABLE_STRING : tmp_line);
		fip_vnic_get_bx_guid(vnic_fip, tmp_line);
		if (*((u64 *)tmp_line) == 0)
			p += _sprintf(p, buf, "BX_GUID       %s\n", NOT_AVAILABLE_STRING);
		else
			p += _sprintf(p, buf, "BX_GUID       "VNIC_GUID_FMT"\n",
				      VNIC_GUID_RAW_ARG(tmp_line));

		lag_gw = fip_vnic_get_gw_type(vnic_fip);
		if (lag_gw) {
			p += _sprintf(p, buf, "GW_TYPE       LAG\n");
			ret = fip_vnic_get_lag_eports(vnic_fip, p);
			p += (ret > 0) ? ret : 0;
		} else
			p += _sprintf(p, buf, "GW_TYPE       LEGACY\n");

		rc = fip_vnic_get_all_vlan_mode(vnic_fip, tmp_line);
		p += _sprintf(p, buf, "ALL_VLAN      %s\n",
			      rc < 0 ? NOT_AVAILABLE_STRING : tmp_line);

	} else {
		p += _sprintf(p, buf, "EPORT_STATE %s\n", "error");
	}

	/* misc attributes*/
	p += _sprintf(p, buf, "SW_RSS        %s\n",
		      !eport_connected ? NOT_AVAILABLE_STRING :
		      ((login->qps_num > 1) ? "yes" : "no"));
	p += _sprintf(p, buf, "SW_RSS_SIZE   %u\n", login->qps_num);
	p += _sprintf(p, buf, "RX_RINGS_NUM  %d\n", login->rx_rings_num);
	p += _sprintf(p, buf, "RX_RINGS_LIN  %s\n",
		      login->port->rx_ring[0]->log_rx_info ? "no" : "yes");
	p += _sprintf(p, buf, "TX_RINGS_NUM  %d\n", login->tx_rings_num);
	p += _sprintf(p, buf, "TX_RINGS_ACT  %d\n",
		      VNIC_TXQ_GET_ACTIVE(login));
	p += _sprintf(p, buf, "NDO_TSS       %s\n",
		      (login->ndo_tx_rings_num > 1) ? "yes" : "no");
	p += _sprintf(p, buf, "NDO_TSS_SIZE  %u\n", login->ndo_tx_rings_num);
	p += _sprintf(p, buf, "MCAST_PROMISC %s\n",
		      !eport_connected ? NOT_AVAILABLE_STRING :
		      (is_mcast_promisc(login) ? "yes" : "no"));
	p += _sprintf(p, buf, "UCAST_PROMISC %s\n",
		      (is_ucast_promisc(login) ? "yes" : "no"));
	p += _sprintf(p, buf, "MCAST_MASK    %d\n", login->n_mac_mcgid);
	p += _sprintf(p, buf, "CHILD_VNICS   %d/%d\n",
		      atomic_read(&login->vnic_child_cnt),
		      vnic_child_max);
	p += _sprintf(p, buf, "PKEY          0x%04x\n", login->pkey);
	p += _sprintf(p, buf, "PKEY_INDEX    0x%04x\n", login->pkey_index);
	rc = ib_query_pkey(login->port->dev->ca, login->port->num,
			   login->pkey_index, &pkey_used);
	p += _sprintf(p, buf, "PKEY_MEMBER   %s\n",
		      (rc || !eport_connected) ? NOT_AVAILABLE_STRING :
		      ((pkey_used & 0x8000) ? "full" : "partial"));
	p += _sprintf(p, buf, "SL_DATA       %u\n", login->sl);
	p += _sprintf(p, buf, "SL_CONTROL    %u\n",
		      vnic_fip ? fip_vnic_get_bx_sl(vnic_fip) : 0);
#if defined(NETIF_F_GRO) && !defined(_BP_NO_GRO)
	p += _sprintf(p, buf, "GRO           %s\n",
		      login->dev->features & NETIF_F_GRO ? "yes" : "no");
#elif defined(NETIF_F_LRO)
	p += _sprintf(p, buf, "LRO           %s\n",
		      login->dev->features & NETIF_F_LRO ? "yes" : "no");
	p += _sprintf(p, buf, "LRO_NUM       %d\n", login->lro_num);
#endif
	p += _sprintf(p, buf, "NAPI          %s\n",
		      login->napi_num ? "yes" : "no");
	p += _sprintf(p, buf, "NAPI_WEIGHT   %u\n",
		      login->napi_num ? vnic_napi_weight : 0);
	p += _sprintf(p, buf, "QPN           0x%x\n",
		      login->qp_base_num);
	p += _sprintf(p, buf, "MAC           "MAC_6_PRINT_FMT"\n",
		     MAC_6_PRINT_ARG(login->dev_addr));
	p += _sprintf(p, buf, "VNIC_ID       %d\n",
		      vnic_fip ? vnic_fip->vnic_id : 0);
	p += _sprintf(p, buf, "ADMIN_MODE    %s\n",
		      !vnic_fip ? NOT_AVAILABLE_STRING :
		      (vnic_fip->hadmined ? "host" : "network"));

	if (vnic_fip && vnic_fip->vlan_used)
		p += _sprintf(p, buf, "VLAN          0x%03x\n", vnic_fip->vlan);
	else
		p += _sprintf(p, buf, "VLAN          %s\n", NOT_AVAILABLE_STRING);

	if (vnic_fip && vnic_fip->shared_vnic.enabled) {
		p += _sprintf(p, buf, "SHARED_MAC    "MAC_6_PRINT_FMT"\n",
			      MAC_6_PRINT_ARG(vnic_fip->shared_vnic.emac));
		p += _sprintf(p, buf, "SHARED_IP     "IP_4_PRINT_FMT"\n",
			      IP_4_PRINT_ARG(vnic_fip->shared_vnic.ip));
	} else {
		p += _sprintf(p, buf, "SHARED_MAC    %s\n", NOT_AVAILABLE_STRING);
		p += _sprintf(p, buf, "SHARED_IP     %s\n", NOT_AVAILABLE_STRING);
	}
	p += _sprintf(p, buf, "GW KA(msec)   %d\n",
		      jiffies_to_msecs(vnic_fip->gw->info.gw_period));
	p += _sprintf(p, buf, "Last KA(msec) %d\n",
		      jiffies_to_msecs(jiffies - vnic_fip->keep_alive_jiffs));
	return (ssize_t)(p - buf);
}

static ssize_t vnic_qps_show(struct module_attribute *attr,
			     __MODULE_KOBJ_TYPE *mod, char *buf)
{
	char *p = buf;
	struct vnic_sysfs_attr *vnic_dentry =
	    container_of(attr, struct vnic_sysfs_attr, dentry);
	struct vnic_login *login = vnic_dentry->ctx;
	struct ib_qp *qp;
	struct ib_qp_attr query_attr;
	struct ib_qp_init_attr query_init_attr;
	int i, mask = -1;

	for (i = 0; i < login->qps_num; ++i) {
		qp = login->qp_res[i].qp;
		if (ib_query_qp(qp, &query_attr, mask, &query_init_attr))
			continue;
		p += _sprintf(p, buf, "QP_INDEX         %d\n", i);
		p += _sprintf(p, buf, "QP_NUM           0x%06x\n", qp->qp_num);
		p += _sprintf(p, buf, "QP_QKEY          0x%08x\n", query_attr.qkey);
		p += _sprintf(p, buf, "QP_STATE         0x%02x\n", query_attr.qp_state);
		p += _sprintf(p, buf, "QP_RX_RING       %d\n", i % login->rx_rings_num);
		p += _sprintf(p, buf, "QP_PTR           %p\n", qp);
		p += _sprintf(p, buf, "QP_RX_SRQ_PTR    %p\n", qp->srq);
		p += _sprintf(p, buf, "QP_RX_CQ_PTR     %p\n", qp->recv_cq);
		p += _sprintf(p, buf, "QP_TX_CQ_PTR     %p\n", qp->send_cq);
		p += _sprintf(p, buf, "\n");
	}

	return (ssize_t)(p - buf);
}
static char* vnic_state_2str(enum fip_vnic_state state)
{
	switch(state) {
	case FIP_VNIC_CLOSED: return "CLOSED";
	case FIP_VNIC_CONNECTED: return "CONNECTED";
	case FIP_VNIC_HADMIN_IDLE: return "HADMIN_IDLE";
	case FIP_VNIC_LOGIN: return "LOGIN";
	case FIP_VNIC_MCAST_INIT: return "MCAST_INIT";
	case FIP_VNIC_MCAST_INIT_DONE: return "MCAST_INIT_DONE";
	case FIP_VNIC_RINGS_INIT: return "RINGS_INIT";
	case FIP_VNIC_VHUB_DONE: return "VHUB_DONE";
	case FIP_VNIC_VHUB_INIT: return "VHUB_INIT";
	case FIP_VNIC_VHUB_INIT_DONE: return "VHUB_INIT_DONE";
	case FIP_VNIC_VHUB_WRITE: return "VHUB_WRITE";
	case FIP_VNIC_WAIT_4_ACK: return "WAIT_4_ACK";
	}
	return "UNKNOWN";


}

int port_vnics_sysfs_show(struct vnic_port *port, char *buf)
{
	struct fip_gw_data *gw;
	char *p = buf;
	struct fip_discover *discover;
	struct fip_vnic_data *vnic;

	mutex_lock(&port->start_stop_lock);
	list_for_each_entry(discover, &port->fip.discover_list, discover_list) {

		down_read(&discover->l_rwsem);

		list_for_each_entry(gw, &discover->gw_list, list) {
			list_for_each_entry(vnic, &gw->vnic_list, gw_vnics) {
				p += _sprintf(p, buf, "%-15s\t%-10s\t%10s:%d  %-10s\t%.7d\t%-10s\t%s\n",
							  gw->info.vol_info.system_name,
							  gw->info.vol_info.gw_port_name,
							  gw->discover->port->dev->ca->name,
							  gw->discover->port->num,
							  vnic->name,
							  vnic->vnic_id,
							  vnic->hadmined?"HOSTADMIN":"NETADMIN",
							  vnic_state_2str(vnic->state));
			}
		}

		up_read(&discover->l_rwsem);
	}

	mutex_unlock(&port->start_stop_lock);
	return (p - buf);
}


#ifdef VNIC_PROFILLNG
static ssize_t vnic_dentry_prof_skb_show(struct module_attribute *attr,
				     __MODULE_KOBJ_TYPE *mod, char *buf)
{
	char *p = buf;
	struct vnic_sysfs_attr *vnic_dentry =
	       container_of(attr, struct vnic_sysfs_attr, dentry);
	struct vnic_login *login = vnic_dentry->ctx;
	struct sk_buff *skb;
	int i;

	for (i = 0; i < VNIC_PROFILLNG_SKB_MAX; ++i) {
		if (!login->prof_arr[i].cnt)
			continue;
		skb = &login->prof_arr[i].skb;
		p += _sprintf(p, buf, "==============\n");
		p += _sprintf(p, buf, "SKB[%d] CNT %d\n", i, login->prof_arr[i].cnt);
		p += _sprintf(p, buf, "len         %d\n", skb->len);
		p += _sprintf(p, buf, "data_len    %d\n", skb->data_len);
		p += _sprintf(p, buf, "head_len    %d\n", skb_headlen(skb));
		p += _sprintf(p, buf, "gso         %d\n", skb_is_gso(skb));
		p += _sprintf(p, buf, "nr_frags    %d\n", login->prof_arr[i].nr_frags);
		p += _sprintf(p, buf, "jiffies     %lu\n", login->prof_arr[i].jiffies);
		p += _sprintf(p, buf, "msecs       %u\n",
			      jiffies_to_msecs(login->prof_arr[i].jiffies));
		p += _sprintf(p, buf, "msecs_diff  %u\n",
			      jiffies_to_msecs(login->prof_arr[i].jiffies) -
			      jiffies_to_msecs(login->prof_arr[i ? i -1 : 0].jiffies));
	}

	return (ssize_t)(p - buf);
}

#endif

static int get_guid(u8 *guid, char *s)
{
	if (sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   guid + 0, guid + 1, guid + 2, guid + 3, guid + 4,
		   guid + 5, guid + 6, guid + 7) != 8)
		return -1;

	return 0;
}

static int get_mac(u8 *mac, char *s)
{
	if (sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   mac + 0, mac + 1, mac + 2, mac + 3, mac + 4,
		   mac + 5) != 6)
		return -1;

	return 0;
}

static int get_ipv4(short unsigned int *ip, char *s)
{
	if (sscanf(s, "%hu.%hu.%hu.%hu", ip + 0, ip + 1, ip + 2, ip + 3) != 4)
		return -1;

	return 0;
}

static int get_parent(struct vnic_port *port, char *parent)
{
	struct net_device *parent_netdev;

	/* check parent syntax */
	if (!dev_valid_name(parent))
		return -EINVAL;

	parent_netdev = dev_get_by_name(&init_net, parent);
	if (parent_netdev)
		dev_put(parent_netdev);

	return parent_netdev ? 0 : -ENODATA;
}

static struct fip_hadmin_cache *get_hadmin_entry(void)
{
	struct fip_hadmin_cache *hadmin_entry;

	hadmin_entry = kzalloc(sizeof *hadmin_entry, GFP_ATOMIC);
	if (!hadmin_entry)
		return NULL;

	hadmin_entry->vnic_id = NOT_AVAILABLE_NUM;
	hadmin_entry->gw_port_id = NOT_AVAILABLE_NUM;

	return hadmin_entry;
}

void vnic_login_cmd_init(struct fip_hadmin_cmd *cmd)
{
	char *buf = (char *)cmd;
	u8 i;

	for (i = 0; i < MAX_INPUT_ARG; ++i)
		sprintf(buf + (i * MAX_INPUT_LEN),  NOT_AVAILABLE_STRING);
}

int vnic_login_cmd_set(char *buf, struct fip_hadmin_cmd *cmd)
{
	int count;

	if (cmd) {
		count = sprintf(buf, "name=%s mac=%s vnic_id=%s vid=%s "
				"bxname=%s bxguid=%s eport=%s ipv4=%s ipv6=%s "
				"emac=%s pkey=%s parent=%s\n",
				cmd->c_name, cmd->c_mac, cmd->c_vnic_id,
				cmd->c_vid, cmd->c_bxname, cmd->c_bxguid,
				cmd->c_eport, cmd->c_ipv4, cmd->c_ipv6,
				cmd->c_emac, cmd->c_pkey, cmd->c_parent);
		vnic_dbg_sysfs((char *)(cmd->c_name), "cmd: %s", buf);
	} else /* print the cmd syntax */
		count = sprintf(buf, "name=%%s mac=%%s vnic_id=%%s vid=%%s "
				"bxname=%%s bxguid=%%s eport=%%s ipv4=%%s "
				"ipv6=%%s emac=%%s pkey=%%s parent=%%s\n");

	return count;
}

/* create/destroy child vNic; syntax example:
 * +00:11:22:33:44:55
 */
static ssize_t vnic_child_write(struct module_attribute *attr,
				__MODULE_KOBJ_TYPE *mod,
				const char *buf, size_t count)
{
	struct vnic_sysfs_attr *vnic_dentry =
	    container_of(attr, struct vnic_sysfs_attr, dentry);
	struct vnic_login *login = vnic_dentry->ctx;
	char action = buf[0];
	char *buf_mac = (char *)buf + 1;
	int remove = -1;
	u8 mac[ETH_ALEN];

	if (action == '-')
		remove = 1;
	if (action == '+')
		remove = 0;

	if (remove < 0 || get_mac(mac, buf_mac) || !is_valid_ether_addr(mac))
		return -EINVAL;

	vnic_learn_mac(login->dev, mac, remove);
	return count;
}

int fip_hadmin_sysfs_update(struct vnic_port *port,
			    const char *buf, int count, int remove)
{
	struct fip_discover *discover;
	struct fip_hadmin_cache *hadmin_entry, *hadmin_it;
	struct fip_hadmin_cmd *cmd;
	char *name = NULL;
	int rc, num;
	u16 pkey;

	hadmin_entry = get_hadmin_entry();
	if (!hadmin_entry) {
		rc = -ENOMEM;
		vnic_dbg_sysfs(port->name, "get_hadmin_entry failed\n");
		goto err;
	}

	cmd = &hadmin_entry->cmd;
	rc = sscanf(buf, "name=%s mac=%s vnic_id=%s vid=%s bxname=%s bxguid=%s "
		    "eport=%s ipv4=%s ipv6=%s emac=%s pkey=%s parent=%s",
		    cmd->c_name, cmd->c_mac, cmd->c_vnic_id, cmd->c_vid,
		    cmd->c_bxname, cmd->c_bxguid, cmd->c_eport, cmd->c_ipv4,
		    cmd->c_ipv6, cmd->c_emac, cmd->c_pkey, cmd->c_parent);
	if (rc != MAX_INPUT_ARG) {
		vnic_dbg_sysfs(port->name, "sscanf failed, rc %d\n", rc);
		rc = -EINVAL;
		goto err;
	} else
		name = (char *)(cmd->c_name);

	/* get parent name */
	if (!dev_valid_name(cmd->c_parent))
		hadmin_entry->parent_used = 0;
	else if (remove || !get_parent(port, cmd->c_parent)) {
		vnic_dbg_sysfs(name, "parent set %s\n", cmd->c_parent);
		strncpy(hadmin_entry->parent_name, cmd->c_parent,
		        sizeof(hadmin_entry->parent_name));
		hadmin_entry->parent_used = 1;
	} else {
		vnic_warn(name, "invalid parent name %s\n", cmd->c_parent);
		rc = -EINVAL;
		goto err;
	}

	/* get vNic ID dec (must) */
	if (sscanf(cmd->c_vnic_id, "%d", &num) != 1) {
		/* abort on failure */
		vnic_warn(name, "invalid vNic ID %s\n", cmd->c_vnic_id);
		rc = -EINVAL;
		goto err;
	}
	hadmin_entry->vnic_id = (u16)num;

	/* get vNic MAC (must) */
	if (get_mac(hadmin_entry->mac, cmd->c_mac)) {
		vnic_warn(name, "invalid vNic MAC %s\n", cmd->c_vnic_id);
		rc = -EINVAL;
		goto err;
	}

	/* get interface name (must) */
	if ((!dev_valid_name(cmd->c_name) && !hadmin_entry->parent_used) ||
	    ((strlen(cmd->c_name) > VNIC_NAME_LEN) && hadmin_entry->parent_used)) {
		vnic_warn(name, "invalid vNic name %s\n", cmd->c_name);
		rc = -EINVAL;
		goto err;
	}

	strncpy(hadmin_entry->interface_name, cmd->c_name,
		sizeof(hadmin_entry->interface_name));

	/* get BX GUID, if fails, get BX NAME */
	if (get_guid(hadmin_entry->system_guid, cmd->c_bxguid)) {
		strncpy(hadmin_entry->system_name, cmd->c_bxname,
			sizeof(hadmin_entry->system_name));
		vnic_dbg_sysfs(name, "use BX NAME %s\n", cmd->c_bxname);
	}

	/* get shared emac/ip */
	if (!get_ipv4((short unsigned int *)hadmin_entry->shared_vnic_ip,
		      cmd->c_ipv4)) {
		/* TODO, add IPv6 support for shared vNic */
		get_mac(hadmin_entry->shared_vnic_mac, cmd->c_emac);
		vnic_dbg_sysfs(name, "use shared ip/mac\n");
	}

#ifndef VLAN_GROUP_ARRAY_LEN
#define VLAN_GROUP_ARRAY_LEN VLAN_N_VID
#endif

	/* get VLAN field (dec) */
	if ((sscanf(cmd->c_vid, "%d", &num) == 1) &&
	    num < VLAN_GROUP_ARRAY_LEN && num >= 0) {
		/* set other fields on success, skip on failure */
		vnic_dbg_sysfs(name, "vlan set 0x%x\n", hadmin_entry->vlan);
		hadmin_entry->vlan_used = 1;
		hadmin_entry->vlan = (u16)num;
	} else if (!strcmp(cmd->c_vid, ALL_VLAN_GW_VID)) {
		/* Dont set 'vlan_used'. the code counts on it being NULL for
		 * host admin vnics in all_vlan mode, when Vlans are used */
		hadmin_entry->vlan = 0;
		hadmin_entry->all_vlan_gw = 1;
	}

	/* get eport name */
	if (!strlen(cmd->c_eport)) {
		vnic_warn(name, "invalid eport name %s\n", cmd->c_eport);
		rc = -EINVAL;
		goto err;
	}
	strncpy(hadmin_entry->eport_name, cmd->c_eport,
		sizeof(hadmin_entry->eport_name));

	/* set remove/add flag */
	vnic_dbg_sysfs(name, "%s hadmin vNic\n", remove ? "remove" : "add");
	hadmin_entry->remove = remove;

	/* set pkey (hex) */
	if ((sscanf(cmd->c_pkey, "%x", &num) != 1) || !num)
		pkey = 0xffff; /* default */
	else
		pkey = (u16)num | 0x8000;
	vnic_dbg_sysfs(name, "pkey 0x%x\n", pkey);

	/* cannot sleep in this functions for child vnics flow
	 * (avoid schedule while atomic oops)
	 * TODO: check if holding start_stop_lock is needed here
	 */
	//mutex_lock(&port->start_stop_lock);

	list_for_each_entry(discover, &port->fip.discover_list, discover_list) {
		if (discover->pkey == pkey) {
			spin_lock_irq(&discover->lock);

			if (discover->flush != FIP_NO_FLUSH) {
				rc = -EBUSY;
				spin_unlock_irq(&discover->lock);
				goto skip;
			}

			/* check that this mac/vlan is not in the cache list
			 * (saves redundant queue_delayed_work call during
			 * vnic_learn_mac bursts)
			 */
			list_for_each_entry_reverse(hadmin_it, &discover->hadmin_cache, next) {
				if (!memcmp(hadmin_entry->mac, hadmin_it->mac, ETH_ALEN) &&
				    hadmin_entry->vlan == hadmin_it->vlan &&
				    hadmin_entry->remove == hadmin_it->remove) {
					rc = -EEXIST;
					spin_unlock_irq(&discover->lock);
					goto skip;
				}
			}
			list_add_tail(&hadmin_entry->next, &discover->hadmin_cache);
			/* calls fip_discover_hadmin_update() */
			queue_delayed_work(fip_wq, &discover->hadmin_update_task, HZ/10);
			spin_unlock_irq(&discover->lock);
			goto updated_discover;
		}
	}

	//mutex_unlock(&port->start_stop_lock);
	vnic_dbg_sysfs(name, "Requested PKEY=0x%x is not configured\n", pkey);
	goto skip;

err:
	vnic_dbg_sysfs(name, "Invalid host admin request format string. Request rejected\n");
skip:
	kfree(hadmin_entry);
	return rc;

updated_discover:
	//mutex_unlock(&port->start_stop_lock);
	return count;
}

static ssize_t vnic_login_cmd(struct module_attribute *attr,
			      __MODULE_KOBJ_TYPE *mod, char *buf)
{
	char *p = buf;
	struct vnic_sysfs_attr *vnic_dentry =
		container_of(attr, struct vnic_sysfs_attr, dentry);
	struct fip_vnic_data *vnic_fip = vnic_dentry->ctx;
	struct fip_hadmin_cmd *cmd;

	if (!vnic_fip || !vnic_fip->hadmined)
		goto out;

	cmd = &vnic_fip->cmd;
	p += _sprintf(p, buf, "name=%s mac=%s vnic_id=%s vid=%s bxname=%s bxguid=%s "
		      "eport=%s ipv4=%s ipv6=%s emac=%s pkey=%s parent=%s ",
		      cmd->c_name, cmd->c_mac, cmd->c_vnic_id, cmd->c_vid,
		      cmd->c_bxname, cmd->c_bxguid, cmd->c_eport, cmd->c_ipv4,
		      cmd->c_ipv6, cmd->c_emac, cmd->c_pkey, cmd->c_parent);
	p += _sprintf(p, buf, "ib_port=%s", vnic_fip->port->name);
	p += _sprintf(p, buf, "\n");

out:
	return (ssize_t)(p - buf);
}

int vnic_create_hadmin_dentry(struct fip_vnic_data *vnic)
{
	char name[VNIC_SYSFS_FLEN];

	DENTRY_CREATE(vnic, &vnic->dentry,
		      vnic_dentry_name(name, vnic, "cmd"),
		      vnic_login_cmd, NULL);
	return 0;
}

void vnic_delete_hadmin_dentry(struct fip_vnic_data *vnic)
{
	if (vnic->dentry.ctx)
		DENTRY_REMOVE(&vnic->dentry);
}

int vnic_create_dentry(struct vnic_login *login)
{
	int i = 0;
	char name[VNIC_SYSFS_FLEN];

	DENTRY_CREATE(login, &login->dentries[i++],
		      login_dentry_name(name, login, "info"),
		      vnic_login_show, NULL);
	DENTRY_CREATE(login, &login->dentries[i++],
		      login_dentry_name(name, login, "child"),
		      NULL, vnic_child_write);
	DENTRY_CREATE(login, &login->dentries[i++],
		      login_dentry_name(name, login, "neigh"),
		      vnic_neigh_show, NULL);
	DENTRY_CREATE(login, &login->dentries[i++],
		      login_dentry_name(name, login, "qps"),
		      vnic_qps_show, NULL);
	DENTRY_CREATE(login, &login->dentries[i++],
		      login_dentry_name(name, login, "member"),
		      vnic_member_show, NULL);

#ifdef VNIC_PROFILLNG
	DENTRY_CREATE(login, &login->dentries[i++],
		      login_dentry_name(name, login, "prof_skb"),
		      vnic_dentry_prof_skb_show, NULL);
#endif
	return 0;
}

void vnic_delete_dentry(struct vnic_login *login)
{
	int i;

	for (i = 0; i < VNIC_MAX_DENTRIES; ++i) {
		if (login->dentries[i].ctx)
			DENTRY_REMOVE(&login->dentries[i]);
	}
}

static ssize_t port_gw_fs_show(struct module_attribute *attr,
			       __MODULE_KOBJ_TYPE *mod, char *buf)
{
	struct vnic_sysfs_attr *vnic_dentry =
		container_of(attr, struct vnic_sysfs_attr, dentry);
	struct vnic_port *port = vnic_dentry->ctx;

	return fip_gw_sysfs_show(port, buf);
}


static ssize_t port_vnics_fs_show(struct module_attribute *attr,
			       __MODULE_KOBJ_TYPE *mod, char *buf)
{
	struct vnic_sysfs_attr *vnic_dentry =
		container_of(attr, struct vnic_sysfs_attr, dentry);
	struct vnic_port *port = vnic_dentry->ctx;
	return port_vnics_sysfs_show(port, buf);
}

static ssize_t port_hadmin_syntax(struct module_attribute *attr,
				  __MODULE_KOBJ_TYPE *mod, char *buf)
{
	/* print cmd syntax only (for usage) */
	return vnic_login_cmd_set(buf, NULL);
}

static ssize_t port_hadmin_add_write(struct module_attribute *attr,
				     __MODULE_KOBJ_TYPE *mod,
				     const char *buf, size_t count)
{
	struct vnic_sysfs_attr *vnic_dentry =
		container_of(attr, struct vnic_sysfs_attr, dentry);
	struct vnic_port *port = vnic_dentry->ctx;

	return fip_hadmin_sysfs_update(port, buf, count, 0);
}

static ssize_t port_hadmin_del_write(struct module_attribute *attr,
				     __MODULE_KOBJ_TYPE *mod,
				     const char *buf, size_t count)
{
	struct vnic_sysfs_attr *vnic_dentry =
		container_of(attr, struct vnic_sysfs_attr, dentry);
	struct vnic_port *port = vnic_dentry->ctx;

	return fip_hadmin_sysfs_update(port, buf, count, 1);
}

int port_fs_init(struct vnic_port *port)
{
	int i = 0;
	char name[VNIC_SYSFS_FLEN];

	DENTRY_CREATE(port, &port->dentries[i++],
		      port_dentry_name(name, port, "host_add"),
		      port_hadmin_syntax, port_hadmin_add_write);

	DENTRY_CREATE(port, &port->dentries[i++],
		      port_dentry_name(name, port, "host_del"),
		      port_hadmin_syntax, port_hadmin_del_write);

	DENTRY_CREATE(port, &port->dentries[i++],
		      port_dentry_name(name, port, "gws"),
		      port_gw_fs_show, NULL);

	DENTRY_CREATE(port, &port->dentries[i++],
		      port_dentry_name(name, port, "vnics"),
		      port_vnics_fs_show, NULL);
	return 0;
}

void port_fs_exit(struct vnic_port *port)
{
	int i;

	for (i = 0; i < VNIC_MAX_DENTRIES; ++i) {
		if (port->dentries[i].ctx)
			DENTRY_REMOVE(&port->dentries[i]);
	}
}

