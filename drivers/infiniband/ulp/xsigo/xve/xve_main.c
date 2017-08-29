/*
 * Copyright (c) 2011 Xsigo Systems.  All rights reserved.
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

#include "xve.h"
#include "xve_compat.h"

#ifndef XSIGO_LOCAL_VERSION
#define DRIVER_VERSION "0.31"
#else
#define DRIVER_VERSION XSIGO_LOCAL_VERSION
#endif

static int xve_xsmp_service_id = -1;
struct mutex xve_mutex;
static spinlock_t xve_lock;
u32 xve_counters[XVE_MAX_GLOB_COUNTERS];

MODULE_AUTHOR("Oracle corp (OVN-linux-drivers@oracle.com)");
MODULE_DESCRIPTION("OVN Virtual Ethernet driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRIVER_VERSION);

int xve_sendq_size __read_mostly = XVE_TX_RING_SIZE;
int xve_recvq_size __read_mostly = XVE_RX_RING_SIZE;
module_param_named(send_queue_size, xve_sendq_size, int, 0444);
MODULE_PARM_DESC(send_queue_size, "Number of descriptors in send queue");
module_param_named(recv_queue_size, xve_recvq_size, int, 0444);
MODULE_PARM_DESC(recv_queue_size, "Number of recv queue descriptors");

int xve_max_send_cqe __read_mostly = MAX_SEND_CQE;
module_param_named(max_send_cqe, xve_max_send_cqe, int, 0444);
MODULE_PARM_DESC(max_send_cqe, "Threshold for polling send completion queue");

static int napi_weight = 128;
module_param(napi_weight, int, 0644);

static int xve_no_tx_checksum_offload;
module_param(xve_no_tx_checksum_offload, int, 0644);

int lro;
module_param(lro, bool, 0444);
MODULE_PARM_DESC(lro, "Enable LRO (Large Receive Offload)");

static int lro_max_aggr = XVE_LRO_MAX_AGGR;
module_param(lro_max_aggr, int, 0644);
MODULE_PARM_DESC(lro_max_aggr,
		 "LRO: Max packets to be aggregated (default = 64)");

static int xve_hbeat_enable;
module_param(xve_hbeat_enable, int, 0644);
MODULE_PARM_DESC(xve_hbeat_enable, "Enable/Disable heartbeat");

static int xve_aging_timeout = 5 * 60;
module_param(xve_aging_timeout, int, 0644);
MODULE_PARM_DESC(xve_aging_timeout, "Aging timeout in seconds");

static int xve_flood_rc = 1;
module_param(xve_flood_rc, int, 0644);
MODULE_PARM_DESC(xve_flood_rc, "Enable/Disable flood mode for RC");

int xve_debug_level;
module_param_named(xve_debug_level, xve_debug_level, int, 0644);
MODULE_PARM_DESC(xve_debug_level, "Enable debug tracing ");

int xve_cm_single_qp;
module_param_named(xve_cm_single_qp, xve_cm_single_qp, int, 0644);

int xve_mc_sendonly_timeout;
module_param_named(mc_sendonly_timeout, xve_mc_sendonly_timeout, int, 0644);
MODULE_PARM_DESC(mc_sendonly_timeout, "Enable debug tracing if > 0");

int xve_do_arp = 1;
module_param_named(do_arp, xve_do_arp, int, 0644);
MODULE_PARM_DESC(do_arp, "Enable/Disable ARP for NIC MTU less than IB-MTU");

int xve_ignore_hbeat_loss;
module_param_named(ignore_hb_loss, xve_ignore_hbeat_loss, int, 0644);
MODULE_PARM_DESC(ignore_hb_loss, "Ignore heart beat loss on edr based vNICs with uplink");

int xve_enable_offload = 1;
module_param_named(enable_offload, xve_enable_offload, int, 0444);
MODULE_PARM_DESC(enable_offload, "Enable stateless offload");
unsigned long xve_tca_subnet;
module_param(xve_tca_subnet, ulong, 0444);
MODULE_PARM_DESC(xve_tca_subnet, "tca subnet prefix");

unsigned long xve_tca_guid;
module_param(xve_tca_guid, ulong, 0444);
MODULE_PARM_DESC(xve_tca_guid, "TCA GUID");

unsigned int xve_tca_data_qp;
module_param(xve_tca_data_qp, uint, 0444);
MODULE_PARM_DESC(xve_tca_data_qp, "tca data qp number");

unsigned int xve_tca_pkey;
module_param(xve_tca_pkey, uint, 0444);
MODULE_PARM_DESC(xve_tca_pkey, "tca pkey");

unsigned int xve_tca_qkey;
module_param(xve_tca_qkey, uint, 0444);
MODULE_PARM_DESC(xve_tca_qkey, "tca qkey");

unsigned int xve_ud_mode;
module_param(xve_ud_mode, uint, 0444);
MODULE_PARM_DESC(xve_ud_mode, "Always use UD mode irrespective of xsmp.vnet_mode value");

unsigned int xve_eoib_mode = 1;
module_param(xve_eoib_mode, uint, 0444);
MODULE_PARM_DESC(xve_eoib_mode, "Always use UD mode irrespective of xsmp.vnet_mode value");

static int xve_age_path = 1;
module_param(xve_age_path, int, 0644);
MODULE_PARM_DESC(xve_age_path, "Age path enable/disable if no fwt entries");

static void xve_send_msg_to_xsigod(xsmp_cookie_t xsmp_hndl, void *data,
				   int len);
struct xve_path_iter {
	struct net_device *dev;
	struct xve_path path;
};

static const u8 bcast_mgid[] = {
	0xff, 0x12, 0x40, 0x1c, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
};

static u8 ipv6_dmac_addr[] = {
	0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00
};

struct workqueue_struct *xve_workqueue;
struct workqueue_struct *xve_taskqueue;

struct ib_sa_client xve_sa_client;

struct list_head xve_dev_list;

static inline int xve_esx_preregister_setup(struct net_device *netdev)
{
	xg_preregister_pseudo_device(netdev);
	return 0;
}

static inline int xve_esx_postregister_setup(struct net_device *netdev)
{
	return 0;
}

static inline void vmk_notify_uplink(struct net_device *netdev)
{

}

int xve_open(struct net_device *netdev)
{
	struct xve_dev_priv *priv = netdev_priv(netdev);
	unsigned long flags = 0;

	xve_info(priv, "Bringing interface up");
	priv->counters[XVE_OPEN_COUNTER]++;

	spin_lock_irqsave(&priv->lock, flags);
	if (test_bit(XVE_VNIC_READY_PENDING, &priv->state)) {
		spin_unlock_irqrestore(&priv->lock, flags);
		return -EAGAIN;
	}
	set_bit(XVE_FLAG_ADMIN_UP, &priv->flags);
	set_bit(XVE_OPER_UP, &priv->state);
	set_bit(XVE_OS_ADMIN_UP, &priv->state);
	if (xve_is_uplink(priv))
		set_bit(XVE_GW_STATE_UP, &priv->state);
	priv->port_speed = xve_calc_speed(priv);
	spin_unlock_irqrestore(&priv->lock, flags);

	if (xve_pkey_dev_delay_open(netdev))
		return 0;

	if (xve_ib_dev_open(netdev))
		goto err_disable;

	if (xve_ib_dev_up(netdev))
		goto err_stop;

	queue_age_work(priv, 0);

	return 0;

err_stop:
	xve_ib_dev_stop(netdev, 1);

err_disable:
	clear_bit(XVE_FLAG_ADMIN_UP, &priv->flags);

	return -EINVAL;
}

static int xve_stop(struct net_device *netdev)
{
	struct xve_dev_priv *priv = netdev_priv(netdev);
	unsigned long flags = 0;

	xve_info(priv, "Stopping interface");

	spin_lock_irqsave(&priv->lock, flags);
	clear_bit(XVE_FLAG_ADMIN_UP, &priv->flags);
	clear_bit(XVE_OPER_UP, &priv->state);
	clear_bit(XVE_OS_ADMIN_UP, &priv->state);
	handle_carrier_state(priv, 0);
	spin_unlock_irqrestore(&priv->lock, flags);

	xve_ib_dev_down(netdev, 0);
	xve_ib_dev_stop(netdev, 0);
	xve_xsmp_send_oper_state(priv, priv->resource_id,
			 XSMP_XVE_OPER_DOWN);

	xve_debug(DEBUG_IBDEV_INFO, priv,
			"%s Stopped interface %s\n", __func__,
			priv->xve_name);
	return 0;
}

int xve_modify_mtu(struct net_device *netdev, int new_mtu)
{
	struct xve_dev_priv *priv = netdev_priv(netdev);

	xve_info(priv, "changing mtu from %d to %d",
			priv->admin_mtu, new_mtu);
	if (new_mtu == netdev->mtu)
		return 0;

	/* dev->mtu > 2K ==> connected mode */
	if (xve_cm_admin_enabled(netdev)) {
		if (new_mtu > xve_cm_max_mtu(netdev))
			return -EINVAL;

		netdev->mtu = new_mtu;
		return 0;
	}

	if (!priv->is_jumbo && (new_mtu > XVE_UD_MTU(priv->max_ib_mtu)))
		return -EINVAL;

	priv->admin_mtu = netdev->mtu = new_mtu;
	if (!priv->is_jumbo)
		netdev->mtu = min(priv->mcast_mtu, priv->admin_mtu);
	xve_queue_work(priv, XVE_WQ_START_FLUSHLIGHT);
	(void)xve_xsmp_handle_oper_req(priv->xsmp_hndl, priv->resource_id);

	return 0;
}

static int xve_change_mtu(struct net_device *netdev, int new_mtu)
{
	return xve_modify_mtu(netdev, new_mtu);
}

static int xve_set_mac_address(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EINVAL;
	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	return 0;
}

static struct net_device_stats *xve_get_stats(struct net_device *netdev)
{
	struct xve_dev_priv *priv = netdev_priv(netdev);

	priv->counters[XVE_GETSTATS_COUNTER]++;
	return &priv->netdev->stats;
}

static int xve_ioctl(struct net_device *netdev, struct ifreq *ifr, int cmd)
{
	struct mii_ioctl_data *data = if_mii(ifr);
	int ret = 0;
	struct xve_dev_priv *priv;

	if (!netdev && !netif_running(netdev))
		return -EAGAIN;

	priv = netdev_priv(netdev);
	priv->counters[XVE_IOCTL_COUNTER]++;

	switch (cmd) {
	case SIOCGMIIPHY:
		data->phy_id = 5;
		break;
	case SIOCGMIIREG:
		/*
		 * Mainly used by mii monitor
		 */
		switch (data->reg_num) {
		case 0:
			data->val_out = 0x2100;
			break;
		case 1:
			data->val_out = 0xfe00 |
			    (netif_carrier_ok(netdev) << 2);
			break;
		default:
			break;
		}
		break;
	default:
		ret = -EOPNOTSUPP;
		break;
	}
	return ret;
}

inline void xve_get_path(struct xve_path *path)
{
	atomic_inc(&path->users);
}

inline void xve_put_path(struct xve_path *path)
{
	atomic_dec_if_positive(&path->users);
}

inline void xve_free_path(struct xve_path *path)
{
	struct xve_dev_priv *priv;
	struct net_device *netdev;
	struct sk_buff *skb;
	unsigned long flags = 0;

	netdev = path->dev;
	priv = netdev_priv(netdev);
	xve_debug(DEBUG_FLUSH_INFO, priv, "%s Freeing the path %p",
		  __func__, path);
	while ((skb = __skb_dequeue(&path->queue)))
		dev_kfree_skb_irq(skb);

	while ((skb = __skb_dequeue(&path->uplink_queue)))
		dev_kfree_skb_irq(skb);

	netif_tx_lock_bh(netdev);
	if (xve_cmtx_get(path))
		xve_cm_destroy_tx_deferred(xve_cmtx_get(path));
	netif_tx_unlock_bh(netdev);

	spin_lock_irqsave(&priv->lock, flags);
	xve_flush_l2_entries(netdev, path);
	if (path->ah)
		xve_put_ah(path->ah);
	spin_unlock_irqrestore(&priv->lock, flags);

	kfree(path);
}

struct xve_path *__path_find(struct net_device *netdev, void *gid)
{
	struct xve_dev_priv *priv = netdev_priv(netdev);
	struct rb_node *n = priv->path_tree.rb_node;
	struct xve_path *path;
	int ret;

	while (n) {
		path = rb_entry(n, struct xve_path, rb_node);

		ret = memcmp(gid, path->pathrec.dgid.raw, sizeof(union ib_gid));

		if (ret < 0)
			n = n->rb_left;
		else if (ret > 0)
			n = n->rb_right;
		else
			return path;
	}

	return NULL;
}

static int __path_add(struct net_device *netdev, struct xve_path *path)
{
	struct xve_dev_priv *priv = netdev_priv(netdev);
	struct rb_node **n = &priv->path_tree.rb_node;
	struct rb_node *pn = NULL;
	struct xve_path *tpath;
	int ret;

	while (*n) {
		pn = *n;
		tpath = rb_entry(pn, struct xve_path, rb_node);

		ret = memcmp(path->pathrec.dgid.raw, tpath->pathrec.dgid.raw,
			     sizeof(union ib_gid));
		if (ret < 0)
			n = &pn->rb_left;
		else if (ret > 0)
			n = &pn->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&path->rb_node, pn, n);
	rb_insert_color(&path->rb_node, &priv->path_tree);

	list_add_tail(&path->list, &priv->path_list);
	xve_get_path(path);

	return 0;
}

void xve_flush_l2_entries(struct net_device *netdev, struct xve_path *path)
{
	struct xve_dev_priv *priv = netdev_priv(netdev);
	struct xve_fwt_entry *fwt_entry, *tn;

	list_for_each_entry_safe(fwt_entry, tn, &path->fwt_list, list)
		xve_fwt_entry_destroy(priv, fwt_entry);

}

/*
 * Called with priv->lock held
 */
static void xve_flood_all_paths(struct net_device *dev, struct sk_buff *skb)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_path *path;
	struct sk_buff *nskb;
	int ret = 0;

	list_for_each_entry(path, &priv->path_list, list) {
		if (xve_cmtx_get(path) && xve_cm_up(path)) {
			nskb = skb_clone(skb, GFP_ATOMIC);
			if (nskb) {
				ret = xve_cm_send(dev, nskb,
						xve_cmtx_get(path));
				if (ret == NETDEV_TX_BUSY)
					xve_warn(priv,
						"send queue full so dropping packet %s\n",
							priv->xve_name);
			}
		}
	}
}

void xve_mark_paths_invalid(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_path *path, *tp;

	spin_lock_irq(&priv->lock);

	list_for_each_entry_safe(path, tp, &priv->path_list, list) {
		xve_debug(DEBUG_IBDEV_INFO, priv,
			  "%s mark path LID 0x%04x GID %pI6 invalid\n",
			  __func__, be16_to_cpu(path->pathrec.dlid),
			  path->pathrec.dgid.raw);
		path->valid = 0;
	}

	spin_unlock_irq(&priv->lock);
}


void xve_flush_single_path_by_gid(struct net_device *dev, union ib_gid *gid,
		struct xve_fwt_entry *fwt_entry)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	unsigned long flags = 0;
	struct xve_path *path;
	uint8_t path_ret = 0;

	netif_tx_lock_bh(dev);
	spin_lock_irqsave(&priv->lock, flags);

	path = __path_find(dev, gid->raw);
	if (!path) {
		char *mgid_token = gid->raw;
		char tmp_buf[64];

		print_mgid_buf(tmp_buf, mgid_token);
		xve_debug(DEBUG_FLUSH_INFO, priv, "%s Path not found MGID %s",
				__func__, tmp_buf);
		path_ret = 1;
	}


	if (fwt_entry != NULL) {
		xve_remove_fwt_entry(priv, fwt_entry);
		xve_debug(DEBUG_FLUSH_INFO, priv, "%s Fwt removed %p",
				__func__, fwt_entry);
		/*
		 * There is more than one FWT entry in this path,
		 * destroy just this FWT entry.
		 */
		if ((path && !list_empty(&path->fwt_list)) || !xve_age_path) {
			xve_info(priv, "path%p has more entries FWT%p",
					path, fwt_entry);
			path_ret = 1;
		}
	}

	if (path_ret)
		goto unlock;

	xve_debug(DEBUG_FLUSH_INFO, priv, "%s Flushing the path %p",
		  __func__, path);
	/* This path is not used in subsequent path_look ups's */
	rb_erase(&path->rb_node, &priv->path_tree);
	if (path->query)
		ib_sa_cancel_query(path->query_id, path->query);

	spin_unlock_irqrestore(&priv->lock, flags);
	netif_tx_unlock_bh(dev);

	wait_for_completion(&path->done);
	list_del(&path->list);

	/* Make sure path is not in use */
	if (atomic_dec_if_positive(&path->users) <= 0)
		xve_free_path(path);
	else {
		/* Wait for path->users to become zero */
		unsigned long begin = jiffies;

		while (atomic_read(&path->users)) {
			if (time_after(jiffies, begin + 5 * HZ)) {
				xve_warn(priv, "%p Waited to free path %pI6",
						path, path->pathrec.dgid.raw);
				goto timeout;
			}
			msleep(20);
		}
		if (atomic_read(&path->users) == 0)
			xve_free_path(path);

	}
	xve_debug(DEBUG_FLUSH_INFO, priv, "%s Flushed the path %p",
		  __func__, path);
timeout:
	return;

unlock:
	spin_unlock_irqrestore(&priv->lock, flags);
	netif_tx_unlock_bh(dev);
	return;

}

static void path_rec_completion(int status,
				struct ib_sa_path_rec *pathrec, void *path_ptr)
{
	struct xve_path *path = path_ptr;
	struct net_device *dev = path->dev;
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_ah *ah = NULL;
	struct xve_ah *old_ah = NULL;
	struct sk_buff_head skqueue, uplink_skqueue;
	struct sk_buff *skb;
	unsigned long flags;
	int ret;

	if (!status) {
		priv->counters[XVE_PATHREC_RESP_COUNTER]++;
		xve_test("XVE: %s PathRec LID 0x%04x for GID %pI6\n",
			 __func__, be16_to_cpu(pathrec->dlid),
			 pathrec->dgid.raw);
	} else {
		priv->counters[XVE_PATHREC_RESP_ERR_COUNTER]++;
		xve_test("XVE: %s PathRec status %d for GID %pI6\n",
			 __func__, status, path->pathrec.dgid.raw);
	}

	skb_queue_head_init(&skqueue);
	skb_queue_head_init(&uplink_skqueue);

	if (!status) {
		struct ib_ah_attr av;

		if (!ib_init_ah_from_path(priv->ca, priv->port, pathrec, &av)) {
			av.ah_flags = IB_AH_GRH;
			av.grh.dgid = path->pathrec.dgid;
			ah = xve_create_ah(dev, priv->pd, &av);
		}
	}

	spin_lock_irqsave(&priv->lock, flags);

	if (ah) {
		path->pathrec = *pathrec;
		old_ah = path->ah;
		path->ah = ah;

		xve_test
		    ("XVE: %screated address handle %p for LID 0x%04x, SL %d\n",
		     __func__, ah, be16_to_cpu(pathrec->dlid), pathrec->sl);
		if (xve_cm_enabled(dev)) {
			if (!xve_cmtx_get(path))
				xve_cm_create_tx(dev, path);
		}

		while ((skb = __skb_dequeue(&path->queue)))
			__skb_queue_tail(&skqueue, skb);
		while ((skb = __skb_dequeue(&path->uplink_queue)))
			__skb_queue_tail(&uplink_skqueue, skb);
		path->valid = 1;
	}

	path->query = NULL;
	complete(&path->done);

	if (old_ah)
		xve_put_ah(old_ah);
	spin_unlock_irqrestore(&priv->lock, flags);


	while ((skb = __skb_dequeue(&skqueue))) {
		if (xve_is_edr(priv)) {
			skb_pull(skb, sizeof(struct xve_eoib_hdr));
			skb_reset_mac_header(skb);
		}
		if (dev_queue_xmit(skb)) {
			xve_warn(priv,
				"dev_queue_xmit failed to requeue pkt for %s\n",
				priv->xve_name);
		} else {
			xve_test("%s Succefully completed path for %s\n",
				 __func__, priv->xve_name);
		}
	}
	while ((skb = __skb_dequeue(&uplink_skqueue))) {
		skb->dev = dev;
		xve_get_ah_refcnt(path->ah);
		priv->counters[XVE_PATHREC_GW_COUNTER]++;
		/* Send G/W packet */
		netif_tx_lock_bh(dev);
		spin_lock_irqsave(&priv->lock, flags);

		ret = xve_send(dev, skb, path->ah, priv->gw.t_data_qp, 2);
		if (ret == NETDEV_TX_BUSY) {
			xve_warn(priv, "send queue full full, dropping packet for %s\n",
					priv->xve_name);
		}

		spin_unlock_irqrestore(&priv->lock, flags);
		netif_tx_unlock_bh(dev);

	}
}

static struct xve_path *path_rec_create(struct net_device *dev, void *gid)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_path *path;

	if (!priv->broadcast)
		return NULL;

	path = kzalloc(sizeof(*path), GFP_ATOMIC);
	if (!path)
		return NULL;

	path->dev = dev;

	skb_queue_head_init(&path->queue);
	skb_queue_head_init(&path->uplink_queue);

	INIT_LIST_HEAD(&path->fwt_list);

	memcpy(path->pathrec.dgid.raw, gid, sizeof(union ib_gid));
	path->pathrec.sgid = priv->local_gid;
	path->pathrec.pkey = cpu_to_be16(priv->pkey);
	path->pathrec.numb_path = 1;
	path->pathrec.traffic_class = priv->broadcast->mcmember.traffic_class;

	return path;
}

static int path_rec_start(struct net_device *dev, struct xve_path *path)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	ib_sa_comp_mask comp_mask =
	    IB_SA_PATH_REC_MTU_SELECTOR | IB_SA_PATH_REC_MTU;
	struct ib_sa_path_rec p_rec;

	p_rec = path->pathrec;
	p_rec.mtu_selector = IB_SA_GT;

	switch (roundup_pow_of_two(dev->mtu + VLAN_ETH_HLEN)) {
	case 512:
		p_rec.mtu = IB_MTU_256;
		break;
	case 1024:
		p_rec.mtu = IB_MTU_512;
		break;
	case 2048:
		p_rec.mtu = IB_MTU_1024;
		break;
	default:
		/* Wildcard everything */
		comp_mask = 0;
		p_rec.mtu = 0;
		p_rec.mtu_selector = 0;
	}

	xve_dbg_mcast(priv, "%s Start path record lookup for %pI6 MTU > %d\n",
		      __func__, p_rec.dgid.raw,
		      comp_mask ? ib_mtu_enum_to_int(p_rec.mtu) : 0);

	init_completion(&path->done);

	path->query_id =
	    ib_sa_path_rec_get(&xve_sa_client, priv->ca, priv->port,
			       &p_rec, comp_mask |
			       IB_SA_PATH_REC_DGID |
			       IB_SA_PATH_REC_SGID |
			       IB_SA_PATH_REC_NUMB_PATH |
			       IB_SA_PATH_REC_TRAFFIC_CLASS |
			       IB_SA_PATH_REC_PKEY,
			       1000, GFP_ATOMIC,
			       path_rec_completion, path, &path->query);
	if (path->query_id < 0) {
		xve_warn(priv, "ib_sa_path_rec_get failed: %d for %s\n",
			 path->query_id, priv->xve_name);
		path->query = NULL;
		complete_all(&path->done);
		return path->query_id;
	}
	priv->counters[XVE_PATHREC_QUERY_COUNTER]++;
	return 0;
}

inline struct xve_path*
xve_fwt_get_path(struct xve_fwt_entry *fwt)
{
	if (!fwt->path)
		return NULL;

	xve_get_path(fwt->path);
	return fwt->path;
}

struct xve_path*
xve_find_path_by_gid(struct xve_dev_priv *priv,
		union ib_gid *gid)
{
	struct xve_path *path;

	path = __path_find(priv->netdev, gid->raw);
	if (!path) {
		xve_debug(DEBUG_TABLE_INFO, priv, "%s Unable to find path\n",
			  __func__);
		path = path_rec_create(priv->netdev, gid->raw);
		if (!path)
			return NULL;
		__path_add(priv->netdev, path);
	}
	xve_get_path(path);

	return path;
}

static struct xve_path*
xve_path_lookup(struct net_device *dev,
			struct xve_fwt_entry *fwt_entry)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_fwt_s *xve_fwt = &priv->xve_fwt;
	struct xve_path *path;
	unsigned long flags = 0;

	xve_debug(DEBUG_TABLE_INFO, priv, "%s Adding  FWT to list %p",
		  __func__, fwt_entry);
	path = xve_find_path_by_gid(priv, &fwt_entry->dgid);
	if (!path)
		return NULL;

	if (!path->ah) {
		if (!path->query && path_rec_start(dev, path)) {
			/*
			 * Forwarding entry not yet added to the path fwt_list
			 * just free that path
			 */
			kfree(path);
			return NULL;
		}
	}

	spin_lock_irqsave(&xve_fwt->lock, flags);
	fwt_entry->path = path;
	list_add_tail(&fwt_entry->list, &path->fwt_list);
	spin_unlock_irqrestore(&xve_fwt->lock, flags);

	return path;
}

struct xve_path *
xve_get_gw_path(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_path	*path;

	if (!priv->gw.t_data_qp)
		return NULL;

	path = xve_find_path_by_gid(priv, &priv->gw.t_gid);

	if (!path->ah && !path->query)
		path_rec_start(priv->netdev, path);

	return path;
}

int xve_gw_send(struct net_device *dev, struct sk_buff *skb)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_gw_info *gwp = &priv->gw;
	struct xve_path	*path;
	int ret = NETDEV_TX_OK;

	path = xve_get_gw_path(dev);
	if (!path) {
		dev_kfree_skb_any(skb);
		return NETDEV_TX_BUSY;
	}

	if (path->ah) {
		xve_dbg_data(priv, "Sending unicast copy to gw ah:%p dqpn:%u\n",
				path->ah, gwp->t_data_qp);
		xve_get_ah_refcnt(path->ah);
		/* Sending Packet to GATEWAY */
		ret = xve_send(dev, skb, path->ah, priv->gw.t_data_qp, 1);
	} else if (skb_queue_len(&path->uplink_queue) <
			XVE_MAX_PATH_REC_QUEUE) {
		xve_dbg_data(priv, "gw ah not found - queue len: %u\n",
				skb_queue_len(&path->uplink_queue));
		priv->counters[XVE_TX_QUEUE_PKT]++;
		__skb_queue_tail(&path->uplink_queue, skb);
	} else {
		xve_dbg_data(priv,
			"No path found to gw - droping the unicast packet\n");
		dev_kfree_skb_any(skb);
		INC_TX_DROP_STATS(priv, dev);
		goto out;
	}
	priv->counters[XVE_GW_MCAST_TX]++;

out:
	xve_put_path(path);
	return ret;
}

int xve_add_eoib_header(struct xve_dev_priv *priv, struct sk_buff *skb)
{
	struct xve_eoib_hdr *eoibp;
	int len = sizeof(*eoibp);

	if (skb_headroom(skb) < len) {
		struct sk_buff *skb_new;

		skb_new = skb_realloc_headroom(skb, len);
		if (!skb_new)
			return -1;

		dev_kfree_skb_any(skb);
		skb = skb_new;
	}
	eoibp = (struct xve_eoib_hdr *) skb_push(skb, len);

	skb_set_mac_header(skb, len);
	eoibp->magic = cpu_to_be16(XVE_EOIB_MAGIC);
	eoibp->tss_mask_sz = 0;
	return 0;
}

static int xve_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct sk_buff *bcast_skb = NULL;
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_fwt_entry *fwt_entry = NULL;
	struct xve_path *path = NULL;
	unsigned long flags = 0;
	int ret = NETDEV_TX_OK, len = 0;
	u8 skb_need_tofree = 0, inc_drop_cnt = 0, queued_pkt = 0;
	u16 vlan_tag = 0;

	spin_lock_irqsave(&priv->lock, flags);
	if (!test_bit(XVE_OPER_UP, &priv->state)) {
		ret = NETDEV_TX_BUSY;
		priv->counters[XVE_TX_DROP_OPER_DOWN_COUNT]++;
		goto unlock;
	}

	if (skb->len < XVE_MIN_PACKET_LEN) {
		priv->counters[XVE_SHORT_PKT_COUNTER]++;
		if (skb_padto(skb, XVE_MIN_PACKET_LEN)) {
			inc_drop_cnt = 1;
			priv->counters[XVE_TX_SKB_ALLOC_ERROR_COUNTER]++;
			ret = NETDEV_TX_OK;
			goto unlock;
		}
		skb->len = XVE_MIN_PACKET_LEN;
	}

	skb_reset_mac_header(skb);
	if (xg_vlan_tx_tag_present(skb))
		vlan_get_tag(skb, &vlan_tag);

	if (xve_is_edr(priv) &&
			xve_add_eoib_header(priv, skb)) {
		skb_need_tofree = inc_drop_cnt = 1;
		priv->counters[XVE_TX_DROP_OPER_DOWN_COUNT]++;
		goto unlock;
	}
	len = skb->len;

	fwt_entry = xve_fwt_lookup(priv, eth_hdr(skb)->h_dest,
			vlan_tag, 0);
	if (!fwt_entry) {
		if (is_broadcast_ether_addr(eth_hdr(skb)->h_dest)) {
			ret = xve_mcast_send(dev,
					(void *)priv->bcast_mgid.raw, skb, 1);
			priv->counters[XVE_TX_BCAST_PKT]++;
			goto stats;
		} else if (is_multicast_ether_addr(eth_hdr(skb)->h_dest)) {
			/* For Now Send Multicast Packet to G/W also */
			ret = xve_mcast_send(dev,
					(void *)priv->bcast_mgid.raw, skb, 1);
			priv->counters[XVE_TX_MCAST_PKT]++;
			goto stats;
		} else {
			/*
			 * Since this is a unicast packet and we do not have
			 * an L2 table entry
			 * We need to do the following
			 * If packet is less than IB MTU,flood it
			 * If more than IB MTU, we need to send to to all ports
			 * We still generate ARP and NDP for IPv4 and IPv6
			 * respectively
			 */

			/*
			 * Do not ARP if if user does not want to for less
			 * than IB-MTU
			 */
			if (!xve_is_edr(priv) && (xve_do_arp
			    || (priv->netdev->mtu >
				XVE_UD_MTU(priv->max_ib_mtu))))

				bcast_skb = xve_generate_query(priv, skb);
				if (bcast_skb != NULL)
					ret = xve_mcast_send(dev,
						       (void *)priv->bcast_mgid.
						       raw, bcast_skb, 1);
			/*
			 * Now send the original packet also to over broadcast
			 * Later add counters for flood mode
			 */
			if (xve_is_edr(priv) ||
					len < XVE_UD_MTU(priv->max_ib_mtu)) {
				ret = xve_mcast_send(dev,
				       (void *)priv->bcast_mgid.raw, skb, 1);
				priv->counters[XVE_TX_MCAST_FLOOD_UD]++;
			} else {
				if (xve_flood_rc) {
					xve_flood_all_paths(dev, skb);
					priv->counters[XVE_TX_MCAST_FLOOD_RC]++;
					/*
					 * Free the original skb
					 */
					skb_need_tofree = 1;
				} else {
					skb_need_tofree = 1;
					goto unlock;
				}
			}
			goto stats;
		}
	}

	path = xve_fwt_get_path(fwt_entry);
	if (!path) {
		priv->counters[XVE_PATH_NOT_FOUND]++;
		xve_debug(DEBUG_SEND_INFO, priv,
			  "%s Unable to find neigbour doing a path lookup\n",
			  __func__);
		path = xve_path_lookup(dev, fwt_entry);
		if (!path) {
			skb_need_tofree = inc_drop_cnt = 1;
			goto free_fwt_ctx;
		}
	} else {
		if (!path->ah) {
			priv->counters[XVE_AH_NOT_FOUND]++;
			xve_debug(DEBUG_SEND_INFO, priv,
				  "%s Path present %p no ah\n", __func__,
				  fwt_entry->path);
			if (!path->query && path_rec_start(dev, path)) {
				skb_need_tofree = inc_drop_cnt = 1;
				goto free_fwt_ctx;
			}
		}
	}

	if (xve_cmtx_get(path)) {
		if (xve_cm_up(path)) {
			ret = xve_cm_send(dev, skb, xve_cmtx_get(path));
			update_cm_tx_rate(xve_cmtx_get(path), len);
			priv->counters[XVE_TX_RC_COUNTER]++;
			goto stats;
		}
	} else if (path->ah) {
		xve_debug(DEBUG_SEND_INFO, priv, "%s path ah is %p\n",
			  __func__, path->ah);
		xve_get_ah_refcnt(path->ah);
		ret = xve_send(dev, skb, path->ah, fwt_entry->dqpn, 3);
		priv->counters[XVE_TX_UD_COUNTER]++;
		goto stats;
	}

	if (skb_queue_len(&path->queue) < XVE_MAX_PATH_REC_QUEUE) {
		priv->counters[XVE_TX_QUEUE_PKT]++;
		__skb_queue_tail(&path->queue, skb);
		queued_pkt = 1;
	} else {
		xve_debug(DEBUG_SEND_INFO, priv,
			  "%s Dropping packets path %p fwt_entry %p\n",
			  __func__, path, fwt_entry);
		skb_need_tofree = inc_drop_cnt = 1;
		goto free_fwt_ctx;
	}
stats:
	INC_TX_PKT_STATS(priv, dev);
	INC_TX_BYTE_STATS(priv, dev, len);
free_fwt_ctx:
	if (path)
		xve_put_path(path);
	xve_fwt_put_ctx(&priv->xve_fwt, fwt_entry);
unlock:
	if (inc_drop_cnt)
		INC_TX_DROP_STATS(priv, dev);

	if (!queued_pkt)
		dev->trans_start = jiffies;
	if (skb_need_tofree)
		dev_kfree_skb_any(skb);

	spin_unlock_irqrestore(&priv->lock, flags);

	if (unlikely(priv->tx_outstanding > SENDQ_LOW_WMARK)) {
		priv->counters[XVE_TX_WMARK_REACH_COUNTER]++;
		mod_timer(&priv->poll_timer, jiffies);

	}

	return ret;
}

static void xve_timeout(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);

	xve_warn(priv, "transmit timeout: latency %d msecs\n",
		 jiffies_to_msecs(jiffies - dev->trans_start));
	xve_warn(priv, "queue stopped %d, tx_head %u, tx_tail %u\n",
		 netif_queue_stopped(dev), priv->tx_head, priv->tx_tail);
	priv->counters[XVE_WDOG_TIMEOUT_COUNTER]++;
}

static void xve_set_mcast_list(struct net_device *dev)
{
}

int xve_dev_init(struct net_device *dev, struct ib_device *ca, int port)
{
	struct xve_dev_priv *priv = netdev_priv(dev);

	/* Allocate RX/TX "rings" to hold queued skbs */
	priv->rx_ring = kcalloc(priv->xve_recvq_size, sizeof(*priv->rx_ring),
				GFP_KERNEL);
	if (!priv->rx_ring) {
		DRV_PRINT("%s:failed to allocate RX ring (%d entries)\n",
			ca->name, priv->xve_recvq_size);
		goto out;
	}

	priv->tx_ring = vmalloc(priv->xve_sendq_size * sizeof(*priv->tx_ring));
	if (!priv->tx_ring) {
		DRV_PRINT("%s:failed to allocate TX ring (%d entries)\n",
			ca->name, priv->xve_sendq_size);
		goto out_rx_ring_cleanup;
	}
	memset(priv->tx_ring, 0, priv->xve_sendq_size * sizeof(*priv->tx_ring));

	/* priv->tx_head, tx_tail & tx_outstanding are already 0 */

	if (xve_ib_dev_init(dev, ca, port) != 0) {
		pr_err("%s Failed for %s\n", __func__, priv->xve_name);
		goto out_tx_ring_cleanup;
	}

	return 0;

out_tx_ring_cleanup:
	vfree(priv->tx_ring);

out_rx_ring_cleanup:
	kfree(priv->rx_ring);

out:
	return -ENOMEM;
}

void xve_dev_cleanup(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);

	xve_remove_proc_entry(priv);
	xve_ib_dev_cleanup(dev);

	kfree(priv->rx_ring);
	vfree(priv->tx_ring);

	priv->rx_ring = NULL;
	priv->tx_ring = NULL;

	xve_fwt_cleanup(priv);
}

static int get_skb_hdr(struct sk_buff *skb, void **iphdr,
		       void **tcph, u64 *hdr_flags, void *priv)
{
	unsigned int ip_len;
	struct iphdr *iph;

	if (unlikely(skb->protocol != htons(ETH_P_IP)))
		return -1;

	/* Check for non-TCP packet */
	skb_reset_network_header(skb);
	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return -1;

	ip_len = ip_hdrlen(skb);
	skb_set_transport_header(skb, ip_len);
	*tcph = tcp_hdr(skb);

	/* check if IP header and TCP header are complete */
	if (ntohs(iph->tot_len) < ip_len + tcp_hdrlen(skb))
		return -1;

	*hdr_flags = LRO_IPV4 | LRO_TCP;
	*iphdr = iph;

	return 0;
}

static void xve_lro_setup(struct xve_dev_priv *priv)
{
	priv->lro.lro_mgr.max_aggr = lro_max_aggr;
	priv->lro.lro_mgr.max_desc = XVE_MAX_LRO_DESCRIPTORS;
	priv->lro.lro_mgr.lro_arr = priv->lro.lro_desc;
	priv->lro.lro_mgr.get_skb_header = get_skb_hdr;
	priv->lro.lro_mgr.features = LRO_F_NAPI;
	priv->lro.lro_mgr.dev = priv->netdev;
	priv->lro.lro_mgr.ip_summed_aggr = CHECKSUM_UNNECESSARY;
}

static struct net_device_ops xve_netdev_ops = {
	.ndo_open = xve_open,
	.ndo_stop = xve_stop,
	.ndo_change_mtu = xve_change_mtu,
	.ndo_set_mac_address = xve_set_mac_address,
	.ndo_start_xmit = xve_start_xmit,
	.ndo_tx_timeout = xve_timeout,
	.ndo_set_rx_mode = xve_set_mcast_list,
	.ndo_do_ioctl = xve_ioctl,
	.ndo_get_stats = xve_get_stats,
};

static void xve_set_oper_down(struct xve_dev_priv *priv)
{
	if (test_and_clear_bit(XVE_OPER_UP, &priv->state)) {
		handle_carrier_state(priv, 0);
		clear_bit(XVE_OPER_REP_SENT, &priv->state);
		clear_bit(XVE_PORT_LINK_UP, &priv->state);
		clear_bit(XVE_OPER_UP, &priv->state);
		xve_xsmp_send_oper_state(priv, priv->resource_id,
					 XSMP_XVE_OPER_DOWN);
	}
}

static void xve_io_disconnect(struct xve_dev_priv *priv)
{
	unsigned long flags;

	spin_lock_irqsave(&priv->lock, flags);
	if (test_bit(XVE_OPER_UP, &priv->state)) {
		xve_set_oper_down(priv);
		spin_unlock_irqrestore(&priv->lock, flags);
		if (test_bit(XVE_OS_ADMIN_UP, &priv->state))
			napi_synchronize(&priv->napi);
		xve_info(priv, "%s Flushing mcast", __func__);
		xve_queue_work(priv, XVE_WQ_START_FLUSHNORMAL);
	} else {
		spin_unlock_irqrestore(&priv->lock, flags);
	}
}

void handle_carrier_state(struct xve_dev_priv *priv, char state)
{
	if (state) {
		priv->jiffies = jiffies;
		netif_carrier_on(priv->netdev);
		if (netif_queue_stopped(priv->netdev)) {
			netif_wake_queue(priv->netdev);
			priv->counters[XVE_TX_WAKE_UP_COUNTER]++;
		}
		/* careful we are holding lock (priv->lock)inside this */
		xve_data_recv_handler(priv);
	} else {
		netif_carrier_off(priv->netdev);
		netif_stop_queue(priv->netdev);
		priv->counters[XVE_TX_QUEUE_STOP_COUNTER]++;
	}
}

struct sk_buff *xve_generate_query(struct xve_dev_priv *priv,
				   struct sk_buff *skb)
{
	struct vlan_ethhdr *veth = (struct vlan_ethhdr *)(skb->data);

	if ((xg_vlan_tx_tag_present(skb)
	     && veth->h_vlan_encapsulated_proto == htons(ETH_P_IP))
	    || skb->protocol == htons(ETH_P_IP))
		return xve_create_arp(priv, skb);
	if ((xg_vlan_tx_tag_present(skb)
	     && veth->h_vlan_encapsulated_proto == htons(ETH_P_IPV6))
	    || skb->protocol == htons(ETH_P_IPV6))
		return xve_create_ndp(priv, skb);

	return NULL;
}

struct sk_buff *xve_create_arp(struct xve_dev_priv *priv,
			       struct sk_buff *skb_pkt)
{
	struct sk_buff *skb;
	struct arphdr *arp;
	struct iphdr *iphdr;
	unsigned char *arp_ptr, *eth_ptr;
	struct net_device *netdev = priv->netdev;

	skb = alloc_skb(XVE_MIN_PACKET_LEN, GFP_ATOMIC);
	if (skb == NULL)
		return NULL;

	eth_ptr = (unsigned char *)skb_put(skb, XVE_MIN_PACKET_LEN);
	/*
	 * Broadcast packet
	 */
	memset(eth_ptr, 0xFF, ETH_ALEN);
	eth_ptr += ETH_ALEN;
	/*
	 * Copy the source MAC
	 */
	memcpy(eth_ptr, skb_pkt->data + ETH_ALEN, ETH_ALEN);

	eth_ptr += ETH_ALEN;

	if (xg_vlan_tx_tag_present(skb_pkt)) {
		u16 vlan_tci = 0;
		struct vlan_ethhdr *veth;

		vlan_get_tag(skb_pkt, &vlan_tci);
		veth = (struct vlan_ethhdr *)(skb->data);
		veth->h_vlan_proto = htons(ETH_P_8021Q);
		/* now, the TCI */
		veth->h_vlan_TCI = htons(vlan_tci);
		eth_ptr += VLAN_HLEN;
		priv->counters[XVE_TX_MCAST_ARP_VLAN_QUERY]++;
	}

	*eth_ptr++ = (ETH_P_ARP >> 8) & 0xff;
	*eth_ptr++ = ETH_P_ARP & 0xff;

	arp = (struct arphdr *)eth_ptr;
	arp->ar_hrd = htons(netdev->type);
	arp->ar_pro = htons(ETH_P_IP);
	arp->ar_hln = netdev->addr_len;
	arp->ar_pln = 4;
	arp->ar_op = htons(ARPOP_REQUEST);

	iphdr = (struct iphdr *)ip_hdr(skb_pkt);
	arp_ptr = (unsigned char *)(arp + 1);

	ether_addr_copy(arp_ptr, skb_pkt->data + ETH_ALEN);
	arp_ptr += netdev->addr_len;
	memcpy(arp_ptr, &iphdr->saddr, 4);
	arp_ptr += 4;
	ether_addr_copy(arp_ptr, skb_pkt->data);
	arp_ptr += netdev->addr_len;
	memcpy(arp_ptr, &iphdr->daddr, 4);

	skb_reset_network_header(skb);
	skb->dev = netdev;
	skb->protocol = htons(ETH_P_ARP);
	priv->counters[XVE_TX_MCAST_ARP_QUERY]++;
	return skb;
}

/**
 * Function:	xve_create_ndp()
 * Param:	priv - private structure
 *		skb_pkt - skb buff from stack
 * Description: generates NDP packet (ARP) packet for ipv6
 *		This funciton generates Neighbor Solicitation
 *		packet to discover the link layer address of
 *		an on-link ipv6 node or to confirm the previously
 *		determined link layer address.
 *
 *	The NDP packet constructed follows the packet format as:
 *	Ethernet Header
 *-----------------------------
 *			- destination mac		6 bytes
 *			- source mac			6 bytes
 *			- type ipv6 (0x86dd)		2 bytes
 *	IPV6 Header
 *-----------------------------
 *			- Version			4 bits
 *			- traffic class			4 bits
 *			- flow label			3 bytes
 *			- payload length		3 bytes
 *			- next header			1 byte
 *			- hop limit			1 byte
 *			- source ip addr		16 bytes
 *			- destination ip addr		16 bytes
 *	ICMPv6 Header
 *----------------------------
 *			- type				1 byte
 *			- code				1 byte
 *			- checksum			2 bytes
 *			- reserved			4 bytes
 *			- target ip addr		16 bytes
 *	ICMPv6 Optional Header
 *----------------------------
 *			- type				1 byte
 *			- length			1 byte
 *			- source mac addr		6 bytes
 *-------------------------------------------------------------
 * TOTAL						86 bytes
 **/

struct sk_buff *xve_create_ndp(struct xve_dev_priv *priv,
			       struct sk_buff *skb_pkt)
{
	struct sk_buff *skb;
	struct net_device *netdev = priv->netdev;
	struct ipv6hdr *ipv6_hdr, *ipv6_hdr_tmp;
	struct icmp6_ndp *icmp_ndp_hdr;
	unsigned char *hdr_ptr;
	unsigned char source_addr[16];
	unsigned char dest_addr[16];
	int count;		/* keep tack of skb_pkt->data */

	count = 0;
	skb = alloc_skb(XVE_IPV6_MIN_PACK_LEN, GFP_ATOMIC);
	if (skb == NULL)
		return NULL;

	/* get the ipv6hdr from skb_pkt */
	if (xg_vlan_tx_tag_present(skb_pkt))
		ipv6_hdr_tmp =
		    (struct ipv6hdr *)(skb_pkt->data + ETH_HDR_LEN + VLAN_HLEN);
	else
		ipv6_hdr_tmp = (struct ipv6hdr *)(skb_pkt->data + ETH_HDR_LEN);

	/* get local copy of source and destination ip address */
	memcpy(source_addr, ipv6_hdr_tmp->saddr.s6_addr, IPV6_ADDR_LEN);
	memcpy(dest_addr, ipv6_hdr_tmp->daddr.s6_addr, IPV6_ADDR_LEN);

	/* initialise the memory allocated */
	memset(skb->data, 0, XVE_IPV6_MIN_PACK_LEN);
	/* create space for data in skb buffer */
	hdr_ptr = (unsigned char *)skb_put(skb, XVE_IPV6_MIN_PACK_LEN);

	/* construct destination mac address (multicast address) */
	hdr_ptr[0] = PREFIX_MULTI_ADDR;
	hdr_ptr[1] = PREFIX_MULTI_ADDR;
	/* get the last 4 bytes from ipv6 destination ip address */
	memcpy(hdr_ptr + 2, &(dest_addr[IPV6_ADDR_LEN - 4]), ETH_ALEN - 2);

	hdr_ptr += ETH_ALEN;
	count += ETH_ALEN;

	/* copy the source MAC */
	memcpy(hdr_ptr, skb_pkt->data + ETH_ALEN, ETH_ALEN);
	hdr_ptr += ETH_ALEN;
	count += ETH_ALEN;

	if (xg_vlan_tx_tag_present(skb_pkt)) {
		u16 vlan_tci = 0;
		struct vlan_ethhdr *veth;

		vlan_get_tag(skb_pkt, &vlan_tci);
		veth = (struct vlan_ethhdr *)(skb->data);
		veth->h_vlan_proto = htons(ETH_P_8021Q);
		/* now, the TCI */
		veth->h_vlan_TCI = htons(vlan_tci);
		hdr_ptr += VLAN_HLEN;
		priv->counters[XVE_TX_MCAST_NDP_VLAN_QUERY]++;
	}

	*hdr_ptr++ = (ETH_P_IPV6 >> 8) & 0xff;
	count++;
	*hdr_ptr++ = ETH_P_IPV6 & 0xff;
	count++;

	/* get the header pointer to populate with ipv6 header */
	ipv6_hdr = (struct ipv6hdr *)hdr_ptr;

	/* construct ipv6 header */
	ipv6_hdr->priority = ipv6_hdr_tmp->priority;
	ipv6_hdr->version = ipv6_hdr_tmp->version;
	memcpy(ipv6_hdr->flow_lbl, ipv6_hdr_tmp->flow_lbl, 3);
	ipv6_hdr->payload_len = PAYLOAD_LEN;
	ipv6_hdr->nexthdr = NEXTHDR_ICMP;
	ipv6_hdr->hop_limit = ipv6_hdr_tmp->hop_limit;
	/* get the ipv6 source ip address */
	memcpy(ipv6_hdr->saddr.s6_addr, source_addr, IPV6_ADDR_LEN);
	/* construct the multicast dest. ip addr. Solicited Node address */
	memcpy(&(ipv6_dmac_addr[13]), &(dest_addr[13]), 3);
	/* get the ipv6 destination ip address */
	memcpy(ipv6_hdr->daddr.s6_addr, ipv6_dmac_addr, IPV6_ADDR_LEN);

	/* update the header pointer */
	hdr_ptr += IPV6_HDR_LEN;
	/* get the header pointer to populate with icmp header */
	icmp_ndp_hdr = (struct icmp6_ndp *)hdr_ptr;

	/* initialize with ICMP-NDP type */
	icmp_ndp_hdr->icmp6_type = ICMP_NDP_TYPE;

	/* initialize with ICMP-NDP code */
	icmp_ndp_hdr->icmp6_code = ICMP_CODE;

	/* get the destination addr from ipv6 header for
	 * ICMP-NDP destination addr */
	memcpy(&(icmp_ndp_hdr->icmp6_daddr), dest_addr, IPV6_ADDR_LEN);

	/* update icmp header with the optional header */
	icmp_ndp_hdr->icmp6_option_type = ICMP_OPTION_TYPE;
	icmp_ndp_hdr->icmp6_option_len = ICMP_OPTION_LEN;
	/* get the source mac address */
	memcpy(&(icmp_ndp_hdr->icmp6_option_saddr), skb_pkt->data + ETH_ALEN,
	       ETH_ALEN);

	/* calculate the checksum and update the ICMP-NDP header */
	icmp_ndp_hdr->icmp6_cksum =
	    csum_ipv6_magic((struct in6_addr *)ipv6_hdr->saddr.s6_addr,
			    (struct in6_addr *)ipv6_hdr->daddr.s6_addr,
			    PAYLOAD_LEN, IPPROTO_ICMPV6,
			    csum_partial(icmp_ndp_hdr, PAYLOAD_LEN, 0));

	skb_reset_network_header(skb);
	skb->dev = netdev;
	skb->protocol = htons(ETH_P_IPV6);
	priv->counters[XVE_TX_MCAST_NDP_QUERY]++;
	return skb;
}

int xve_send_hbeat(struct xve_dev_priv *priv)
{
	struct sk_buff *skb;
	struct arphdr *arp;
	unsigned char *arp_ptr, *eth_ptr;
	int ret;

	if (!xve_hbeat_enable)
		return 0;
	skb = alloc_skb(XVE_MIN_PACKET_LEN, GFP_ATOMIC);
	if (skb == NULL) {
		priv->counters[XVE_HBEAT_ERR_COUNTER]++;
		return -ENOMEM;
	}
	priv->counters[XVE_DATA_HBEAT_COUNTER]++;

	eth_ptr = (unsigned char *)skb_put(skb, XVE_MIN_PACKET_LEN);
	ether_addr_copy(eth_ptr, priv->netdev->dev_addr);
	eth_ptr += ETH_ALEN;
	ether_addr_copy(eth_ptr, priv->netdev->dev_addr);
	eth_ptr += ETH_ALEN;
	*eth_ptr++ = (ETH_P_RARP >> 8) & 0xff;
	*eth_ptr++ = ETH_P_RARP & 0xff;

	arp = (struct arphdr *)eth_ptr;
	arp->ar_hrd = htons(priv->netdev->type);
	arp->ar_hln = priv->netdev->addr_len;
	arp->ar_pln = 4;
	arp->ar_op = htons(ARPOP_RREPLY);

	arp_ptr = (unsigned char *)(arp + 1);

	ether_addr_copy(arp_ptr, priv->netdev->dev_addr);
	arp_ptr += priv->netdev->addr_len;
	arp_ptr += 4;
	ether_addr_copy(arp_ptr, priv->netdev->dev_addr);

	skb_reset_network_header(skb);
	skb->dev = priv->netdev;
	skb->protocol = htons(ETH_P_RARP);

	ret = xve_start_xmit(skb, priv->netdev);
	return 0;
}

static int xve_xsmp_send_msg(xsmp_cookie_t xsmp_hndl, void *data, int length)
{
	struct xsmp_message_header *m_header = data;
	int ret;

	m_header->length = cpu_to_be16(m_header->length);
	ret = xcpm_send_message(xsmp_hndl, xve_xsmp_service_id, data, length);
	if (ret)
		xcpm_free_msg(data);
	return ret;
}

static int xve_xsmp_send_notification(struct xve_dev_priv *priv, u64 vid,
				      int notifycmd)
{
	xsmp_cookie_t *xsmp_hndl = priv->xsmp_hndl;
	int length = sizeof(struct xsmp_message_header) +
	    sizeof(struct xve_xsmp_msg);
	void *msg;
	struct xsmp_message_header *header;
	struct xve_xsmp_msg *xsmp_msg;

	msg = xcpm_alloc_msg(length);
	if (!msg)
		return -ENOMEM;

	memset(msg, 0, length);

	header = (struct xsmp_message_header *)msg;
	xsmp_msg = (struct xve_xsmp_msg *)(msg + sizeof(*header));

	if (notifycmd == XSMP_XVE_OPER_UP) {
		xve_debug(DEBUG_INSTALL_INFO, priv,
			"XVE: %s sending updated mtu for %s[mtu %d]\n",
			__func__, priv->xve_name, priv->admin_mtu);
		xsmp_msg->vn_mtu = cpu_to_be16(priv->admin_mtu);
		xsmp_msg->net_id = cpu_to_be32(priv->net_id);
		if (test_bit(XVE_HBEAT_LOST, &priv->state))
			xsmp_msg->install_flag = XVE_NOTIFY_HBEAT_LOST;
		else
			xsmp_msg->install_flag = 0;
	}

	header->type = XSMP_MESSAGE_TYPE_XVE;
	header->length = length;

	xsmp_msg->type = notifycmd;
	xsmp_msg->length = cpu_to_be16(sizeof(*xsmp_msg));
	xsmp_msg->resource_id = cpu_to_be64(vid);

	return xve_xsmp_send_msg(xsmp_hndl, msg, length);
}

static void handle_action_flags(struct xve_dev_priv *priv)
{
	if (test_bit(XVE_TRIGGER_NAPI_SCHED, &priv->state)) {
		xve_data_recv_handler(priv);
		clear_bit(XVE_TRIGGER_NAPI_SCHED, &priv->state);
	}
}

static int xve_state_machine(struct xve_dev_priv *priv)
{

	priv->counters[XVE_STATE_MACHINE]++;

	if (!test_bit(XVE_OS_ADMIN_UP, &priv->state) ||
	    !test_bit(XVE_CHASSIS_ADMIN_UP, &priv->state) ||
	    test_bit(XVE_IBLINK_DOWN, &priv->state) ||
	    test_bit(XVE_DELETING, &priv->state)) {
		priv->counters[XVE_STATE_MACHINE_DOWN]++;
		xve_io_disconnect(priv);
		if (test_bit(XVE_SEND_ADMIN_STATE, &priv->state)) {
			clear_bit(XVE_SEND_ADMIN_STATE, &priv->state);
			xve_xsmp_send_notification(priv,
						   priv->resource_id,
						   XSMP_XVE_UPDATE);
		}
		priv->sm_delay = 2000;
		goto out;
	}

	if (test_bit(XVE_OPER_UP, &priv->state) &&
	    test_bit(XVE_OS_ADMIN_UP, &priv->state) &&
	    !test_bit(XVE_DELETING, &priv->state)) {
		/* Heart beat loss */
		if (xve_is_uplink(priv) &&
			!xve_ignore_hbeat_loss &&
			time_after(jiffies, (unsigned long)priv->last_hbeat +
				XVE_HBEAT_LOSS_THRES*priv->hb_interval)) {
			unsigned long flags = 0;

			xve_info(priv, "Heart Beat Loss: %lu:%lu\n",
				jiffies, (unsigned long)priv->last_hbeat +
				3*priv->hb_interval*HZ);

			spin_lock_irqsave(&priv->lock, flags);
			/* Disjoin from multicast Group */
			set_bit(XVE_HBEAT_LOST, &priv->state);
			spin_unlock_irqrestore(&priv->lock, flags);
			/* Send updated state */
			(void)xve_xsmp_handle_oper_req(priv->xsmp_hndl,
							priv->resource_id);
			xve_queue_work(priv, XVE_WQ_START_FLUSHNORMAL);
		}
		priv->counters[XVE_STATE_MACHINE_UP]++;
		if (!test_bit(XVE_OPER_REP_SENT, &priv->state))
			(void)xve_xsmp_handle_oper_req(priv->xsmp_hndl,
						       priv->resource_id);

		/*Bring ib up (start mcast ) */
		if (!test_bit(XVE_FLAG_OPER_UP, &priv->flags))
			xve_ib_dev_up(priv->netdev);

		/* Clear Out standing IB Event */
		if (test_and_clear_bit(XVE_FLAG_IB_EVENT, &priv->flags)) {
			xve_debug(DEBUG_MCAST_INFO, priv,
				  "%s Clear  Pending IB  work [xve %s]\n",
				  __func__, priv->xve_name);
			xve_queue_work(priv, XVE_WQ_START_MCASTRESTART);
		}

		handle_action_flags(priv);

		if (priv->send_hbeat_flag) {
			if (xve_is_ovn(priv))
				xve_send_hbeat(priv);
		}
		priv->send_hbeat_flag = 1;
	}

out:
	return 0;
}

void queue_age_work(struct xve_dev_priv *priv, int msecs)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&priv->lock, flags);
	if (!test_bit(XVE_DELETING, &priv->state) &&
	    test_bit(XVE_OS_ADMIN_UP, &priv->state))
		xve_queue_dwork(priv, XVE_WQ_START_FWT_AGING,
				msecs_to_jiffies(msecs));
	spin_unlock_irqrestore(&priv->lock, flags);
}

void queue_sm_work(struct xve_dev_priv *priv, int msecs)
{
	int del = 0;
	unsigned long flags = 0;

	spin_lock_irqsave(&priv->lock, flags);
	if (!test_bit(XVE_DELETING, &priv->state))
		queue_delayed_work(xve_workqueue, &priv->sm_work,
				   msecs_to_jiffies(msecs));
	else
		del = 1;
	spin_unlock_irqrestore(&priv->lock, flags);

	if (del)
		xve_remove_one(priv);
}

void xve_start_aging_work(struct work_struct *work)
{
	struct xve_dev_priv *priv =
	    xve_get_wqctx(work, XVE_WQ_FINISH_FWT_AGING, 1);

	mutex_lock(&priv->mutex);
	xve_aging_task_machine(priv);
	mutex_unlock(&priv->mutex);

	if (priv->aging_delay != 0)
		queue_age_work(priv, 30 * HZ);
	xve_put_ctx(priv);
}

void xve_state_machine_work(struct work_struct *work)
{
	struct xve_dev_priv *priv =
	    container_of(work, struct xve_dev_priv, sm_work.work);

	mutex_lock(&priv->mutex);
	xve_state_machine(priv);
	mutex_unlock(&priv->mutex);

	queue_sm_work(priv, priv->sm_delay);
}

static void xve_setup(struct net_device *netdev)
{
	struct xve_dev_priv *priv = netdev_priv(netdev);

	ether_setup(netdev);
	priv->netdev = netdev;
}

static void xve_set_netdev(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);

	spin_lock_init(&priv->lock);
	mutex_init(&priv->mutex);

	INIT_LIST_HEAD(&priv->path_list);
	INIT_LIST_HEAD(&priv->dead_ahs);
	INIT_LIST_HEAD(&priv->multicast_list);
	INIT_DELAYED_WORK(&priv->sm_work, xve_state_machine_work);
	INIT_DELAYED_WORK(&priv->mcast_leave_task, xve_mcast_leave_task);
	INIT_DELAYED_WORK(&priv->mcast_join_task, xve_mcast_join_task);
	INIT_DELAYED_WORK(&priv->stale_task, xve_cm_stale_task);
}

void
xve_set_ovn_features(struct xve_dev_priv *priv)
{
	priv->netdev->features |=
	    NETIF_F_HIGHDMA | NETIF_F_GRO;

	if (!xve_no_tx_checksum_offload) {
		priv->netdev->features |= NETIF_F_IP_CSUM;
		set_bit(XVE_FLAG_CSUM, &priv->flags);
	}

	if (priv->lro_mode && lro) {
		priv->netdev->features |= NETIF_F_LRO;
		xve_lro_setup(priv);
	} else
		priv->lro_mode = 0;
}

void
xve_set_edr_features(struct xve_dev_priv *priv)
{
	priv->netdev->hw_features =
		NETIF_F_HIGHDMA | NETIF_F_SG | NETIF_F_GRO;

	xve_info(priv, "%s HCA capability flags[%x]",
			__func__, priv->hca_caps);
	if (xve_enable_offload & (priv->is_eoib && priv->is_titan)) {
		if (priv->hca_caps & IB_DEVICE_UD_IP_CSUM) {
			set_bit(XVE_FLAG_CSUM, &priv->flags);
			priv->netdev->hw_features |=
				NETIF_F_IP_CSUM | NETIF_F_RXCSUM;
		}

		if (priv->hca_caps & IB_DEVICE_UD_TSO)
			priv->netdev->hw_features |= NETIF_F_TSO;
	}
	priv->netdev->features |= priv->netdev->hw_features;

	/* Reserve extra space for EoIB header */
	priv->netdev->hard_header_len += sizeof(struct xve_eoib_hdr);
}

int xve_set_dev_features(struct xve_dev_priv *priv, struct ib_device *hca)
{
	struct ib_device_attr device_attr;
	int result = -ENOMEM;

	priv->netdev->watchdog_timeo = 1000 * HZ;
	priv->netdev->tx_queue_len = priv->xve_sendq_size * 2;

	priv->lro_mode = 1;
	if (priv->vnet_mode == XVE_VNET_MODE_RC) {
		strcpy(priv->mode, "connected(RC)");
		set_bit(XVE_FLAG_ADMIN_CM, &priv->flags);
		priv->cm_supported = 1;
	} else {/* UD */
		strcpy(priv->mode, "datagram(UD)");

		/* MTU will be reset when mcast join happens */
		if (!priv->is_jumbo &&
			(priv->netdev->mtu > XVE_UD_MTU(priv->max_ib_mtu)))
			priv->netdev->mtu = XVE_UD_MTU(priv->max_ib_mtu);
		priv->lro_mode = 0;
	}
	xve_info(priv, "%s Mode:%d MTU:%d", __func__,
			priv->vnet_mode, priv->netdev->mtu);

	priv->mcast_mtu = priv->admin_mtu = priv->netdev->mtu;
	xg_setup_pseudo_device(priv->netdev, hca);

	SET_NETDEV_OPS(priv->netdev, &xve_netdev_ops);
	xve_set_ethtool_ops(priv->netdev);
	netif_napi_add(priv->netdev, &priv->napi, xve_poll, napi_weight);
	if (xve_esx_preregister_setup(priv->netdev))
		return -EINVAL;

	xve_set_netdev(priv->netdev);

	result = ib_query_device(hca, &device_attr);
	if (result) {
		pr_warn("%s: ib_query_device failed (ret = %d)\n",
				hca->name, result);
		return result;
	}

	priv->dev_attr = device_attr;
	priv->hca_caps = device_attr.device_cap_flags;

	xve_lro_setup(priv);
	if (xve_is_ovn(priv))
		xve_set_ovn_features(priv);
	else
		xve_set_edr_features(priv);

	return 0;
}

static int xve_xsmp_send_nack(xsmp_cookie_t xsmp_hndl, void *data, int length,
			      u8 code)
{
	void *msg;
	struct xsmp_message_header *m_header;
	int total_len = length + sizeof(struct xsmp_message_header);
	struct xve_xsmp_msg *xsmsgp = (struct xve_xsmp_msg *)data;

	msg = xcpm_alloc_msg(total_len);
	if (!msg)
		return -ENOMEM;
	m_header = (struct xsmp_message_header *)msg;
	m_header->type = XSMP_MESSAGE_TYPE_XVE;
	m_header->length = total_len;

	xsmsgp->code = XSMP_XVE_NACK | code;
	memcpy(msg + sizeof(*m_header), data, length);
	return xve_xsmp_send_msg(xsmp_hndl, msg, total_len);
}

void xve_remove_one(struct xve_dev_priv *priv)
{

	int count = 0;

	xve_info(priv, "%s Removing xve interface", __func__);
	ib_unregister_event_handler(&priv->event_handler);
	cancel_delayed_work_sync(&priv->stale_task);
	rtnl_lock();
	dev_change_flags(priv->netdev, priv->netdev->flags & ~IFF_UP);
	rtnl_unlock();
	vmk_notify_uplink(priv->netdev);
	unregister_netdev(priv->netdev);
	xve_info(priv, "%s Unregistered xve interface ", __func__);
	/* Wait for reference count to go zero  */
	while (atomic_read(&priv->ref_cnt) && xve_continue_unload()) {
		count++;
		if (count > 20) {
			xve_info(priv, "Waiting for refcnt to become zero %d",
					atomic_read(&priv->ref_cnt));
			count = 0;
		}
		msleep(1000);
	}
	xve_dev_cleanup(priv->netdev);
	if (!test_bit(XVE_SHUTDOWN, &priv->state)) {
		/* Ideally need to figure out why userspace ACK isn't working */
		xve_xsmp_send_notification(priv,
					   priv->resource_id, XSMP_XVE_DELETE);
	}
	mutex_lock(&xve_mutex);
	list_del(&priv->list);
	mutex_unlock(&xve_mutex);
	free_netdev(priv->netdev);

	pr_info("XVE:%s Removed xve interface %s\n", __func__, priv->xve_name);

}

static int xcpm_check_vnic_from_same_pvi(xsmp_cookie_t xsmp_hndl,
					 struct xve_xsmp_msg *xmsgp)
{
	struct xve_dev_priv *priv;
	struct xsmp_session_info xsmp_info;
	union ib_gid local_gid;
	struct ib_device *hca;
	u8 port;
	char gid_buf[64];

	if ((xcpm_get_xsmp_session_info(xsmp_hndl, &xsmp_info) != 0)) {
		pr_info("XVE:%s Session Not present", __func__);
		return -EINVAL;
	}

	hca = xsmp_info.ib_device;
	port = xscore_port_num(xsmp_info.port);
	(void)ib_query_gid(hca, port, 0, &local_gid);

	mutex_lock(&xve_mutex);
	list_for_each_entry(priv, &xve_dev_list, list) {
		if (xmsgp->net_id == cpu_to_be32(priv->net_id) &&
		    memcmp(priv->local_gid.raw, local_gid.raw,
			   sizeof(local_gid)) == 0) {
			mutex_unlock(&xve_mutex);
			print_mgid_buf(gid_buf, local_gid.raw);
			pr_info("XVE: %s,%s Multiple VNIC on same pvi",
				xmsgp->xve_name, priv->xve_name);
			pr_info("%d on same port %s NOT allowed\n",
				priv->net_id, gid_buf + 8);
			return -EEXIST;
		}
	}
	mutex_unlock(&xve_mutex);
	return 0;
}

static int xve_check_for_hca(xsmp_cookie_t xsmp_hndl, u8 *is_titan)
{
	struct ib_device *hca;
	struct xsmp_session_info xsmp_info;

	if ((xcpm_get_xsmp_session_info(xsmp_hndl, &xsmp_info) != 0)) {
		pr_info("XVE:%s Session Not present", __func__);
		return -EINVAL;
	}

	hca = xsmp_info.ib_device;
	if (strncmp(hca->name, "sif", 3) == 0)
		*is_titan = (u8)1;

	if (!((strncmp(hca->name, "mlx4", 4) != 0) ||
			(strncmp(hca->name, "sif0", 4) != 0)))
		return -EINVAL;
	return 0;
}

struct xve_dev_priv *xve_get_xve_by_vid(u64 resource_id)
{
	struct xve_dev_priv *priv;

	mutex_lock(&xve_mutex);
	list_for_each_entry(priv, &xve_dev_list, list) {
		if (priv->resource_id == resource_id) {
			mutex_unlock(&xve_mutex);
			return priv;
		}
	}
	mutex_unlock(&xve_mutex);

	return NULL;
}

struct xve_dev_priv *xve_get_xve_by_name(char *xve_name)
{
	struct xve_dev_priv *priv;

	mutex_lock(&xve_mutex);
	list_for_each_entry(priv, &xve_dev_list, list) {
		if (strcmp(priv->xve_name, xve_name) == 0) {
			mutex_unlock(&xve_mutex);
			return priv;
		}
	}
	mutex_unlock(&xve_mutex);

	return NULL;
}

int xve_xsmp_send_oper_state(struct xve_dev_priv *priv, u64 vid, int state)
{
	int ret;
	char *str = state == XSMP_XVE_OPER_UP ? "UP" : "DOWN";

	xve_debug(DEBUG_INSTALL_INFO, priv,
		"XVE: %s Sending OPER state [%d:%s]  to %s\n",
		__func__, state, str, priv->xve_name);
	if (state == XSMP_XVE_OPER_UP) {
		set_bit(XVE_OPER_REP_SENT, &priv->state);
		set_bit(XVE_PORT_LINK_UP, &priv->state);
	} else {
		clear_bit(XVE_OPER_REP_SENT, &priv->state);
		clear_bit(XVE_PORT_LINK_UP, &priv->state);
	}

	ret = xve_xsmp_send_notification(priv, vid, state);
	XSMP_INFO("XVE: %s:Oper %s notification  for ", __func__, str);
	XSMP_INFO("resource_id: 0x%Lx state %d\n", vid, state);

	return ret;
}

void xve_set_oper_up_state(struct xve_dev_priv *priv)
{
	unsigned long flags = 0;

	spin_lock_irqsave(&priv->lock, flags);
	set_bit(XVE_OPER_UP, &priv->state);
	spin_unlock_irqrestore(&priv->lock, flags);
}

static int handle_admin_state_change(struct xve_dev_priv *priv,
				     struct xve_xsmp_msg *xmsgp)
{
	if (xmsgp->admin_state) {
		XSMP_INFO("%s: VNIC %s Admin state up message\n", __func__,
			  priv->xve_name);
		if (!test_bit(XVE_CHASSIS_ADMIN_UP, &priv->state)) {
			priv->counters[XVE_ADMIN_UP_COUNTER]++;
			set_bit(XVE_CHASSIS_ADMIN_UP, &priv->state);
			set_bit(XVE_SEND_ADMIN_STATE, &priv->state);
			/*
			 * We wont have notification from XT as in
			 * VNIC so set OPER_UP Here
			 */
			xve_set_oper_up_state(priv);
		}
	} else {		/* Admin Down */
		XSMP_INFO("%s: VNIC %s Admin state down message\n",
			  __func__, priv->xve_name);
		if (test_bit(XVE_CHASSIS_ADMIN_UP, &priv->state)) {
			priv->counters[XVE_ADMIN_DOWN_COUNTER]++;
			netif_carrier_off(priv->netdev);
			clear_bit(XVE_CHASSIS_ADMIN_UP, &priv->state);
			set_bit(XVE_SEND_ADMIN_STATE, &priv->state);
		}
	}
	return 0;
}

void xve_xsmp_handle_oper_req(xsmp_cookie_t xsmp_hndl, u64 resource_id)
{
	struct xve_dev_priv *priv;
	unsigned long flags = 0;

	priv = xve_get_xve_by_vid(resource_id);
	if (!priv)
		return;
	spin_lock_irqsave(&priv->lock, flags);

	priv->counters[XVE_OPER_REQ_COUNTER]++;
	xve_xsmp_send_oper_state(priv, resource_id,
				 test_bit(XVE_OPER_UP,
					  &priv->state) ? XSMP_XVE_OPER_UP :
				 XSMP_XVE_OPER_DOWN);

	spin_unlock_irqrestore(&priv->lock, flags);

}

static int xve_xsmp_send_ack(struct xve_dev_priv *priv,
			     struct xve_xsmp_msg *xmsgp)
{
	void *msg;
	struct xsmp_message_header *m_header;
	int total_len = sizeof(*xmsgp) + sizeof(*m_header);
	xsmp_cookie_t xsmp_hndl = priv->xsmp_hndl;

	msg = xcpm_alloc_msg(total_len);
	if (!msg)
		return -ENOMEM;
	m_header = (struct xsmp_message_header *)msg;
	m_header->type = XSMP_MESSAGE_TYPE_XVE;
	m_header->length = total_len;

	xmsgp->code = 0;
	xmsgp->vn_mtu = cpu_to_be16(priv->admin_mtu);
	xmsgp->net_id = cpu_to_be32(priv->net_id);
	if (priv->vnic_type != XSMP_XCM_OVN) {
		xmsgp->hca_subnet_prefix =
			cpu_to_be64(priv->local_gid.global.subnet_prefix);
		xmsgp->hca_ctrl_qp = 0;
		xmsgp->hca_data_qp = cpu_to_be32(priv->qp->qp_num);
		xmsgp->hca_qkey = cpu_to_be32(priv->qkey);
		xmsgp->hca_pkey = cpu_to_be16(priv->pkey);
		if (!priv->is_eoib) {
			xmsgp->tca_subnet_prefix =
				cpu_to_be64(priv->gw.t_gid.
					global.subnet_prefix);
			xmsgp->tca_guid =
				cpu_to_be64(priv->gw.t_gid.global.interface_id);
			xmsgp->tca_ctrl_qp = cpu_to_be32(priv->gw.t_ctrl_qp);
			xmsgp->tca_data_qp = cpu_to_be32(priv->gw.t_data_qp);
			xmsgp->tca_pkey = cpu_to_be16(priv->gw.t_pkey);
			xmsgp->tca_qkey = cpu_to_be16(priv->gw.t_qkey);
		}
	}
	xve_debug(DEBUG_INSTALL_INFO, priv,
		"XVE: %s ACK back with admin mtu ",  __func__);
	xve_debug(DEBUG_INSTALL_INFO, priv,
		"%d for %s", xmsgp->vn_mtu, priv->xve_name);
	xve_debug(DEBUG_INSTALL_INFO, priv,
		"[netid %d ]\n", xmsgp->net_id);

	memcpy(msg + sizeof(*m_header), xmsgp, sizeof(*xmsgp));

	return xve_xsmp_send_msg(xsmp_hndl, msg, total_len);
}

static void
xve_update_gw_info(struct xve_dev_priv *priv, struct xve_xsmp_msg *xmsgp)
{
	struct xve_gw_info *gwp = &priv->gw;

	gwp->t_gid.global.subnet_prefix =
		xve_tca_subnet ? cpu_to_be64(xve_tca_subnet) :
		xmsgp->tca_subnet_prefix;

	gwp->t_gid.global.interface_id =
		xve_tca_guid ? cpu_to_be64(xve_tca_guid) :
		xmsgp->tca_guid;
	gwp->t_ctrl_qp = be32_to_cpu(xmsgp->tca_ctrl_qp);
	gwp->t_data_qp = xve_tca_data_qp ? (xve_tca_data_qp)
		: be32_to_cpu(xmsgp->tca_data_qp);
	gwp->t_pkey = xve_tca_pkey ? (xve_tca_pkey)
		: be16_to_cpu(xmsgp->tca_pkey);
	gwp->t_qkey = xve_tca_qkey ? (xve_tca_qkey)
		: be16_to_cpu(xmsgp->tca_qkey);
	xve_dbg_ctrl(priv, "GW INFO gid:%pI6, lid: %hu\n",
			&gwp->t_gid.raw, be32_to_cpu(xmsgp->tca_lid));
	xve_dbg_ctrl(priv, "qpn: %u, pkey: 0x%x, qkey: 0x%x\n",
			gwp->t_data_qp, gwp->t_pkey,
			gwp->t_qkey);
}

/*
 * Handle install message
 */

static int xve_xsmp_install(xsmp_cookie_t xsmp_hndl, struct xve_xsmp_msg *xmsgp,
			    void *data, int len)
{
	struct net_device *netdev;
	struct xve_dev_priv *priv;
	char xve_name[XVE_MAX_NAME_SIZE];
	int ret = 0;
	int update_state = 0;
	int result = -ENOMEM;
	struct ib_device *hca;
	u8 port;
	__be16 pkey_be;
	__be32 net_id_be;
	u8 ecode = 0;
	u8 is_titan = 0, is_jumbo = 0;

	if (xve_check_for_hca(xsmp_hndl, &is_titan) != 0) {
		pr_info("Warning !!!!! Unsupported HCA card for xve ");
		pr_info("interface - %s XSF feature is only ", xmsgp->xve_name);
		pr_info("supported on Connect-X and PSIF HCA cards !!!!!!!");
		ret = -EEXIST;
		goto dup_error;
	}

	if ((be16_to_cpu(xmsgp->vn_mtu) > XVE_UD_MTU(4096))
			&& (xmsgp->vnet_mode & XVE_VNET_MODE_UD)) {
		if (is_titan)
			is_jumbo = 1;
		else {
			pr_info("Warning !!!!! Jumbo is supported on Titan Cards Only");
			pr_info("MTU%d %s\n", be16_to_cpu(xmsgp->vn_mtu),
				xmsgp->xve_name);
			ret = -EINVAL;
			ecode = XVE_NACK_IB_MTU_MISMATCH;
			goto dup_error;
		}
	}

	priv = xve_get_xve_by_vid(be64_to_cpu(xmsgp->resource_id));
	if (priv) {
		/*
		 * Duplicate VID, send ACK, send oper state update
		 */
		xve_debug(DEBUG_INSTALL_INFO, priv,
		     "%s: Duplicate XVE install message name: %s, VID=0x%llx\n",
		     __func__, xmsgp->xve_name,
		     be64_to_cpu(xmsgp->resource_id));
		ret = -EEXIST;
		update_state = 1;
		priv->xsmp_hndl = xsmp_hndl;
		priv->counters[XVE_DUP_VID_COUNTER]++;
		goto send_ack;
	}

	if (xcpm_check_duplicate_names
	    (xsmp_hndl, xmsgp->xve_name, XSMP_MESSAGE_TYPE_VNIC) != 0) {
		pr_info("%s Duplicate name %s\n", __func__, xmsgp->xve_name);
		ret = -EEXIST;
		/* send VID to xmsgp*/
		priv = xve_get_xve_by_name(xmsgp->xve_name);
		if (priv)
			xmsgp->tca_subnet_prefix =
				cpu_to_be64(priv->resource_id);
		ecode = XVE_NACK_DUP_NAME;
		goto dup_error;
	}

	if (xcpm_check_vnic_from_same_pvi(xsmp_hndl, xmsgp) != 0) {
		ret = -EEXIST;
		goto dup_error;
	}

	strncpy(xve_name, xmsgp->xve_name, sizeof(xve_name) - 1);

	priv = xve_get_xve_by_name(xve_name);
	if (priv) {
		XSMP_ERROR("%s: Duplicate name: %s, VID=0x%llx\n",
			   __func__, xmsgp->xve_name,
			   be64_to_cpu(xmsgp->resource_id));
		ret = -EEXIST;
		/* send VID to xmsgp*/
		ecode = XVE_NACK_DUP_NAME;
		xmsgp->tca_subnet_prefix = cpu_to_be64(priv->resource_id);
		goto dup_error;
	}

	netdev =
		alloc_netdev(sizeof(*priv), xve_name, NET_NAME_UNKNOWN,
				&xve_setup);
	if (netdev == NULL) {
		XSMP_ERROR("%s: alloc_netdev error name: %s, VID=0x%llx\n",
				__func__, xmsgp->xve_name,
				be64_to_cpu(xmsgp->resource_id));
		ret = -ENOMEM;
		ecode = XVE_NACK_ALLOCATION_ERROR;
		goto dup_error;
	}
	priv = netdev_priv(netdev);

	xcpm_get_xsmp_session_info(xsmp_hndl, &priv->xsmp_info);
	hca = priv->xsmp_info.ib_device;
	port = xscore_port_num(priv->xsmp_info.port);
	/* Parse PVI parameters */
	priv->vnet_mode = xve_ud_mode ? XVE_VNET_MODE_UD :
		(xmsgp->vnet_mode);
	priv->net_id = be32_to_cpu(xmsgp->net_id);
	priv->netdev->mtu = be16_to_cpu(xmsgp->vn_mtu);
	priv->resource_id = be64_to_cpu(xmsgp->resource_id);
	priv->mp_flag = be16_to_cpu(xmsgp->mp_flag);
	priv->install_flag = be32_to_cpu(xmsgp->install_flag);
	priv->xsmp_hndl = xsmp_hndl;
	priv->sm_delay = 1000;
	priv->aging_delay = xve_aging_timeout * HZ;
	strcpy(priv->xve_name, xmsgp->xve_name);
	strcpy(priv->proc_name, priv->xve_name);
	net_id_be = cpu_to_be32(priv->net_id);
	/* Parse Uvnic properties */
	/* For legacy PVI's XSMP will not have vnic_type field so
	   value is zero */
	priv->vnic_type = xmsgp->vnic_type;
	priv->is_eoib = xve_eoib_mode ? (xmsgp->eoib_enable) : 0;
	priv->is_titan = (is_titan) ? 1 : 0;
	priv->is_jumbo = (is_jumbo) ? 1 : 0;

	pr_info("Install VNIC:%s rID:%llx pDS:%p NetId:%d",
			  xmsgp->xve_name, be64_to_cpu(xmsgp->resource_id),
			  priv, priv->net_id);
	/* Make Send and Recv Queue parmaters Per Vnic */
	if (!(priv->vnet_mode & XVE_VNET_MODE_UD)) {
		priv->xve_sendq_size = xve_sendq_size;
		priv->xve_recvq_size = xve_recvq_size;
		priv->xve_max_send_cqe = xve_max_send_cqe;
	} else {
		/* For UD mode set higher values */
		priv->xve_sendq_size = 8192;
		priv->xve_recvq_size = 8192;
		priv->xve_max_send_cqe = 512;
	}

	if (priv->vnic_type == XSMP_XCM_UPLINK) {
		priv->gw.t_gid.global.subnet_prefix =
			xve_tca_subnet ? cpu_to_be64(xve_tca_subnet) :
			be64_to_cpu(xmsgp->tca_subnet_prefix);

		priv->gw.t_gid.global.interface_id =
			xve_tca_guid ? cpu_to_be64(xve_tca_guid) :
			be64_to_cpu(xmsgp->tca_guid);
		priv->gw.t_ctrl_qp = be32_to_cpu(xmsgp->tca_ctrl_qp);
		priv->gw.t_data_qp = xve_tca_data_qp ? xve_tca_data_qp :
			be32_to_cpu(xmsgp->tca_data_qp);
		priv->gw.t_pkey = xve_tca_pkey ? xve_tca_pkey :
			be16_to_cpu(xmsgp->tca_pkey);
		xve_dbg_ctrl(priv,
			"GW prefix:%llx guid:%llx, lid: %hu sl: %hu TDQP%x TCQP:%x\n",
				priv->gw.t_gid.global.subnet_prefix,
				priv->gw.t_gid.global.interface_id,
				be16_to_cpu(xmsgp->tca_lid),
				be16_to_cpu(xmsgp->service_level),
				priv->gw.t_data_qp, priv->gw.t_ctrl_qp);
	}
	/* Pkey */
	priv->pkey = xve_tca_pkey ? xve_tca_pkey :
		be16_to_cpu(xmsgp->tca_pkey);
	if (priv->pkey == 0)
		priv->pkey |= 0x8000;
	/* Qkey For EDR vnic's*/
	if (priv->is_eoib) {
		priv->gw.t_qkey = xve_tca_qkey ? xve_tca_qkey :
				be32_to_cpu(xmsgp->global_qpkey);
		priv->port_qkey = (port == 1 || priv->is_titan != 1) ?
				priv->gw.t_qkey : priv->gw.t_qkey + 1;
	} else
		priv->gw.t_qkey = xve_tca_qkey ? xve_tca_qkey :
			be16_to_cpu(xmsgp->tca_qkey);

	/* Always set chassis ADMIN up by default */
	set_bit(XVE_CHASSIS_ADMIN_UP, &priv->state);

	if (!ib_query_port(hca, port, &priv->port_attr))
		priv->max_ib_mtu = ib_mtu_enum_to_int(priv->port_attr.max_mtu);
	else {
		pr_warn("%s: ib_query_port %d failed\n",
		       hca->name, port);
		goto device_init_failed;
	}


	memcpy(priv->bcast_mgid.raw, bcast_mgid, sizeof(union ib_gid));
	if (xve_is_edr(priv)) {
		result = ib_find_pkey(hca, port, priv->pkey, &priv->pkey_index);
		if (result != 0)
			pr_warn("%s : ib_find_pkey %d failed %d in %s\n",
					hca->name, port, result, __func__);
		/* EDR MGID format: FF15:101C:P:0:0:0:0:N
		 * Where, P is the P_Key, N is the NetID. */
		pkey_be = cpu_to_be16(priv->pkey);
		priv->bcast_mgid.raw[0] = 0xFF;
		priv->bcast_mgid.raw[1] = 0x15;
		priv->bcast_mgid.raw[2] = 0x10;
		priv->bcast_mgid.raw[3] = 0x1C;
		memcpy(&priv->bcast_mgid.raw[4], &pkey_be, 2);
		memcpy(&priv->bcast_mgid.raw[12], &net_id_be,
				sizeof(net_id_be));
	} else {
		memcpy(&priv->bcast_mgid.raw[4], &net_id_be, sizeof(net_id_be));
		result = ib_query_pkey(hca, port, 0, &priv->pkey);
		if (result) {
			pr_warn("%s: ib_query_pkey port %d failed (ret = %d)\n",
					hca->name, port, result);
			goto device_init_failed;
		}
		/*
		 * Set the full membership bit, so that we join the right
		 * broadcast group, etc.
		 */
		priv->pkey |= 0x8000;
	}


	if (xve_set_dev_features(priv, hca))
		goto device_init_failed;

	result = ib_query_gid(hca, port, 0, &priv->local_gid);

	if (result) {
		pr_warn("%s: ib_query_gid port %d failed (ret = %d)\n",
			hca->name, port, result);
		goto device_init_failed;
	} else {
		u64 m;

		m = xmsgp->mac_high;
		m = m << 32 | xmsgp->mac_low;
		m = be64_to_cpu(m);
		memcpy(priv->netdev->dev_addr, (u8 *) (&m) + 2, ETH_ALEN);
		priv->mac = m << 32 | xmsgp->mac_low;
	}

	result = xve_dev_init(priv->netdev, hca, port);
	if (result != 0) {
		pr_warn
		    ("%s: failed to initialize port %d net_id %d (ret = %d)\n",
		     hca->name, port, priv->net_id, result);
		goto device_init_failed;
	}

	INIT_IB_EVENT_HANDLER(&priv->event_handler, priv->ca, xve_event);
	result = ib_register_event_handler(&priv->event_handler);
	if (result < 0) {
		pr_warn("%s: ib_register_event_handler failed for ", hca->name);
		pr_warn("port %d net_id %d (ret = %d)\n",
			port, priv->net_id, result);
		goto event_failed;
	}

	xve_fwt_init(&priv->xve_fwt);

	if (xve_add_proc_entry(priv)) {
		pr_err("XVE; %s procfs error name: %s, VID=0x%llx\n",
		       __func__, priv->xve_name,
		       be64_to_cpu(xmsgp->resource_id));
		goto proc_error;
	}

	result = register_netdev(priv->netdev);
	if (result) {
		pr_warn("%s: couldn't register xve %d net_id %d; error %d\n",
			hca->name, port, priv->net_id, result);
		goto register_failed;
	}

	handle_carrier_state(priv, 0);
	if (xve_esx_postregister_setup(priv->netdev)) {
		ecode = XVE_NACK_ALLOCATION_ERROR;
		goto sysfs_failed;
	}

	mutex_lock(&xve_mutex);
	list_add_tail(&priv->list, &xve_dev_list);
	mutex_unlock(&xve_mutex);

	if (xve_is_ovn(priv))
		xve_send_msg_to_xsigod(xsmp_hndl, data, len);
	else
		set_bit(XVE_VNIC_READY_PENDING, &priv->state);

	queue_sm_work(priv, 0);

	pr_info("%s Install Success: vnet_mode:%d type:%d eoib[%s] HPort:%d\n",
			priv->xve_name, priv->vnet_mode, priv->vnic_type,
			priv->is_eoib ? "Yes" : "no", port);
	pr_info("VNIC:%s MTU[%d:%d:%d] MGID:%pI6 pkey:%d\n", priv->xve_name,
			priv->netdev->mtu, priv->port_attr.max_mtu,
			priv->port_attr.active_mtu,
			&priv->bcast_mgid.raw, priv->pkey);

send_ack:
	ret = xve_xsmp_send_ack(priv, xmsgp);
	if (ret) {
		xve_info(priv, "%s: xve_xsmp_send_ack error name VID=0x%llx",
			   __func__, be64_to_cpu(xmsgp->resource_id));
	}
	if (update_state && priv->vnic_type == XSMP_XCM_OVN) {
		xve_info(priv, "Sending Oper state to  chassis for  id %llx\n",
		     priv->resource_id);
		(void)xve_xsmp_handle_oper_req(priv->xsmp_hndl,
					       priv->resource_id);
	}

	return 0;

sysfs_failed:
	unregister_netdev(priv->netdev);
register_failed:
proc_error:
	ib_unregister_event_handler(&priv->event_handler);
event_failed:
	xve_dev_cleanup(priv->netdev);
device_init_failed:
	free_netdev(priv->netdev);
dup_error:
	(void)xve_xsmp_send_nack(xsmp_hndl, xmsgp, sizeof(*xmsgp), ecode);
	return ret;

}

static void xve_send_msg_to_xsigod(xsmp_cookie_t xsmp_hndl, void *data, int len)
{
	void *tmsg;

	tmsg = xcpm_alloc_msg(len);
	if (!tmsg)
		return;
	memcpy(tmsg, data, len);
	if (xcpm_send_msg_xsigod(xsmp_hndl, tmsg, len))
		xcpm_free_msg(tmsg);
}

static void xve_handle_ip_req(xsmp_cookie_t xsmp_hndl, u8 *data, int len)
{
	struct xve_xsmp_vlanip_msg *msgp =
	    (struct xve_xsmp_vlanip_msg *)(data +
					   sizeof(struct xsmp_message_header));
	struct xve_dev_priv *priv;

	priv = xve_get_xve_by_vid(be64_to_cpu(msgp->resource_id));
	if (!priv) {
		xve_counters[XVE_VNIC_DEL_NOVID_COUNTER]++;
		return;
	}
	XSMP_INFO("%s:XSMP message type VLAN IP for %s\n", __func__,
		  priv->xve_name);
	strcpy(msgp->ifname, priv->xve_name);
	msgp->mp_flag = cpu_to_be16(priv->mp_flag);

	/*
	 * Punt this message to userspace
	 */
	xve_send_msg_to_xsigod(xsmp_hndl, data, len);
}

static void xve_xsmp_send_stats(xsmp_cookie_t xsmp_hndl, u8 *data, int length)
{
	struct xve_dev_priv *priv;
	struct xve_xsmp_stats_msg *msgp =
	    (struct xve_xsmp_stats_msg *)(data +
					  sizeof(struct xsmp_message_header));

	void *msg;
	struct xsmp_message_header *m_header;

	priv = xve_get_xve_by_vid(be64_to_cpu(msgp->resource_id));
	if (!priv) {
		xve_test("XVE: %s priv not found for %llx\n",
			 __func__, be64_to_cpu(msgp->resource_id));
		return;
	}

	msg = xcpm_alloc_msg(length);
	if (!msg)
		return;
	m_header = (struct xsmp_message_header *)msg;
	m_header->type = XSMP_MESSAGE_TYPE_XVE;
	m_header->length = length;

	/* Clear stats */
	if (msgp->bitmask == 0)
		memset(&priv->stats, 0, sizeof(struct net_device_stats));
	msgp->rx_packets = priv->stats.rx_packets;
	msgp->rx_bytes = priv->stats.rx_bytes;
	msgp->rx_errors = priv->stats.rx_errors;
	msgp->rx_drops = priv->stats.rx_dropped;

	msgp->tx_packets = priv->stats.tx_packets;
	msgp->tx_bytes = priv->stats.tx_bytes;
	msgp->tx_errors = priv->stats.tx_errors;
	msgp->tx_drops = priv->stats.tx_dropped;

	memcpy(msg + sizeof(*m_header), msgp, sizeof(*msgp));
	xve_xsmp_send_msg(priv->xsmp_hndl, msg, length);

}

static int xve_xsmp_update(xsmp_cookie_t xsmp_hndl, struct xve_xsmp_msg *xmsgp)
{
	u32 bitmask = be32_to_cpu(xmsgp->bitmask);
	struct xve_dev_priv *priv;
	int ret = 0;
	int send_ack = 0;

	priv = xve_get_xve_by_vid(be64_to_cpu(xmsgp->resource_id));
	if (!priv) {
		XSMP_ERROR("%s: request for invalid vid: 0x%llx\n",
			   __func__, be64_to_cpu(xmsgp->resource_id));
		return -EINVAL;
	}

	XSMP_INFO("%s: VNIC: %s bit mask: 0x%x\n", __func__, priv->xve_name,
		  bitmask);

	mutex_lock(&priv->mutex);

	if (bitmask & XVE_UPDATE_ADMIN_STATE)
		/*
		 * Ack will be sent once QP's are brought down
		 */
		ret = handle_admin_state_change(priv, xmsgp);
	if (bitmask & XVE_UPDATE_MTU)
		xve_modify_mtu(priv->netdev, be16_to_cpu(xmsgp->vn_mtu));

	if (bitmask & XVE_UPDATE_XT_STATE_DOWN &&
			xve_is_uplink(priv)) {
		clear_bit(XVE_GW_STATE_UP, &priv->state);
		if (netif_carrier_ok(priv->netdev))
			handle_carrier_state(priv, 0);
	}
	if (bitmask & XVE_UPDATE_XT_CHANGE && xve_is_uplink(priv)) {
		xve_update_gw_info(priv, xmsgp);
		if (!netif_carrier_ok(priv->netdev))
			handle_carrier_state(priv, 1);
		send_ack = 1;
	}

	if (send_ack) {
		ret = xve_xsmp_send_ack(priv, xmsgp);
		if (ret) {
			xve_info(priv, "%s: error name VID=0x%llx",
				 __func__, be64_to_cpu(xmsgp->resource_id));
		}
	}
	mutex_unlock(&priv->mutex);

	return ret;
}

static int
xve_xsmp_vnic_ready(xsmp_cookie_t xsmp_hndl, struct xve_xsmp_msg *xmsgp,
	void *data, int len)
{
	struct xve_dev_priv *priv;
	unsigned long flags;
	int ret;

	priv = xve_get_xve_by_vid(be64_to_cpu(xmsgp->resource_id));
	if (!priv) {
		XSMP_INFO("XVE: %s priv not found for %s\n",
			  __func__, xmsgp->xve_name);
		return -1;
	}
	xve_debug(DEBUG_INSTALL_INFO, priv,
			"XVE VNIC_READY: vnic_type: %u, subnet_prefix: %llx\n",
			priv->vnic_type, priv->gw.t_gid.global.subnet_prefix);
	xve_debug(DEBUG_INSTALL_INFO, priv,
			"TCA ctrl_qp: %u, data_qp: %u, pkey: %x, qkey: %x\n",
			priv->gw.t_ctrl_qp, priv->gw.t_data_qp,
			priv->gw.t_pkey, priv->gw.t_qkey);

	xve_send_msg_to_xsigod(xsmp_hndl, data, len);
	spin_lock_irqsave(&priv->lock, flags);
	clear_bit(XVE_VNIC_READY_PENDING, &priv->state);
	spin_unlock_irqrestore(&priv->lock, flags);

	ret = xve_xsmp_send_ack(priv, xmsgp);
	if (ret) {
		xve_info(priv, "%s: xve_xsmp_send_ack error name VID=0x%llx",
			   __func__, be64_to_cpu(xmsgp->resource_id));
	}

	(void) xve_xsmp_handle_oper_req(priv->xsmp_hndl,
	    priv->resource_id);

	return 0;
}

/*
 * We set the DELETING bit and let sm_work thread handle delete
 */
static void xve_handle_del_message(xsmp_cookie_t xsmp_hndl,
				   struct xve_xsmp_msg *xmsgp)
{
	struct xve_dev_priv *priv;
	unsigned long flags;

	priv = xve_get_xve_by_vid(be64_to_cpu(xmsgp->resource_id));
	if (!priv) {
		XSMP_INFO("XVE: %s priv not found for %s\n",
			  __func__, xmsgp->xve_name);
		return;
	}
	xve_info(priv, "Start Deleting interface");
	spin_lock_irqsave(&priv->lock, flags);
	set_bit(XVE_DELETING, &priv->state);
	/*Set OperState to down*/
	clear_bit(XVE_OPER_UP, &priv->state);
	spin_unlock_irqrestore(&priv->lock, flags);

}

static void handle_xve_xsmp_messages(xsmp_cookie_t xsmp_hndl, u8 *data,
				     int length)
{
	int hlen;
	struct xsmp_message_header *header = (struct xsmp_message_header *)data;
	struct xve_xsmp_msg *xmsgp =
	    (struct xve_xsmp_msg *)(data + sizeof(*header));

	if (length < sizeof(*header))
		return;
	hlen = be16_to_cpu(header->length);
	if (hlen > length)
		return;
	if (header->type != XSMP_MESSAGE_TYPE_XVE)
		return;
	XSMP_INFO("%s: XSMP message type: %d\n", __func__, xmsgp->type);

	switch (xmsgp->type) {
	case XSMP_XVE_VLANIP:
		xve_handle_ip_req(xsmp_hndl, data, length);
		break;
	case XSMP_XVE_INFO_REQUEST:
		break;
	case XSMP_XVE_INSTALL:
		xve_counters[XVE_VNIC_INSTALL_COUNTER]++;
		xve_xsmp_install(xsmp_hndl, xmsgp, data, length);
		break;
	case XSMP_VNIC_READY:
		xve_xsmp_vnic_ready(xsmp_hndl, xmsgp, data, length);
		break;
	case XSMP_XVE_DELETE:
		xve_counters[XVE_VNIC_DEL_COUNTER]++;
		xve_handle_del_message(xsmp_hndl, xmsgp);
		break;
	case XSMP_XVE_UPDATE:
		xve_counters[XVE_VNIC_UPDATE_COUNTER]++;
		xve_xsmp_update(xsmp_hndl, xmsgp);
		break;
	case XSMP_XVE_OPER_REQ:
		xve_counters[XVE_VNIC_OPER_REQ_COUNTER]++;
		(void)xve_xsmp_handle_oper_req(xsmp_hndl,
					       be64_to_cpu(xmsgp->resource_id));
		break;
	case XSMP_XVE_STATS:
		xve_counters[XVE_VNIC_STATS_COUNTER]++;
		(void)xve_xsmp_send_stats(xsmp_hndl, data, length);
		break;
	default:
		break;
	}
}

static void handle_xve_xsmp_messages_work(struct work_struct *work)
{
	struct xve_work *xwork = container_of(work, struct xve_work,
					      work);

	(void)handle_xve_xsmp_messages(xwork->xsmp_hndl, xwork->msg,
				       xwork->len);
	kfree(xwork->msg);
	kfree(xwork);
}

/*
 * Called from thread context
 */
static void xve_receive_handler(xsmp_cookie_t xsmp_hndl, u8 *msg, int length)
{
	struct xve_work *work;
	unsigned long flags = 0;

	work = kmalloc(sizeof(*work), GFP_KERNEL);
	if (!work) {
		kfree(msg);
		return;
	}
	INIT_WORK(&work->work, handle_xve_xsmp_messages_work);
	work->xsmp_hndl = xsmp_hndl;
	work->msg = msg;
	work->len = length;

	spin_lock_irqsave(&xve_lock, flags);
	queue_work(xve_workqueue, &work->work);
	spin_unlock_irqrestore(&xve_lock, flags);

}

/*
 * Needs to be called with mutex lock held
 */
static void xve_wait_for_removal(xsmp_cookie_t xsmp_hndl)
{
	int is_pres;
	struct xve_dev_priv *priv;

	while (1) {
		is_pres = 0;
		list_for_each_entry(priv, &xve_dev_list, list) {
			if (xsmp_sessions_match(&priv->xsmp_info, xsmp_hndl))
				is_pres = 1;
		}
		if (is_pres) {
			mutex_unlock(&xve_mutex);
			msleep(100);
			mutex_lock(&xve_mutex);
		} else
			break;
	}
}

static void xve_xsmp_event_handler(xsmp_cookie_t xsmp_hndl, int event)
{
	struct xve_dev_priv *priv;
	unsigned long flags;

	mutex_lock(&xve_mutex);

	switch (event) {
	case XSCORE_PORT_UP:
	case XSCORE_PORT_DOWN:
		list_for_each_entry(priv, &xve_dev_list, list) {
			if (xsmp_sessions_match(&priv->xsmp_info, xsmp_hndl)) {
				if (event == XSCORE_PORT_DOWN) {
					set_bit(XVE_IBLINK_DOWN, &priv->state);
					priv->counters
					    [XVE_IBLINK_DOWN_COUNTER]++;
				} else {
					clear_bit(XVE_IBLINK_DOWN,
						  &priv->state);
					xve_set_oper_up_state(priv);
					priv->counters[XVE_IBLINK_UP_COUNTER]++;
				}
			}
		}
		break;
	case XSCORE_DEVICE_REMOVAL:
		xve_counters[XVE_DEVICE_REMOVAL_COUNTER]++;
		list_for_each_entry(priv, &xve_dev_list, list) {
			if (xsmp_sessions_match(&priv->xsmp_info, xsmp_hndl)) {
				spin_lock_irqsave(&priv->lock, flags);
				set_bit(XVE_DELETING, &priv->state);
				/*Set OperState to down*/
				clear_bit(XVE_OPER_UP, &priv->state);
				spin_unlock_irqrestore(&priv->lock, flags);
			}
		}
		/*
		 * Now wait for all the vnics to be deleted
		 */
		xve_wait_for_removal(xsmp_hndl);
		break;
	case XSCORE_CONN_CONNECTED:
		list_for_each_entry(priv, &xve_dev_list, list) {
			if (xsmp_sessions_match(&priv->xsmp_info, xsmp_hndl))
				priv->xsmp_hndl = xsmp_hndl;
		}
		break;
	default:
		break;
	}

	mutex_unlock(&xve_mutex);
}

static int xve_xsmp_callout_handler(char *name)
{
	struct xve_dev_priv *priv;
	int ret = 0;

	mutex_lock(&xve_mutex);
	list_for_each_entry(priv, &xve_dev_list, list) {
		/* CHECK for duplicate name */
		if (strcmp(priv->xve_name, name) == 0) {
			ret = -EINVAL;
			break;
		}
	}
	mutex_unlock(&xve_mutex);
	return ret;
}

int xve_xsmp_init(void)
{
	struct xsmp_service_reg_info service_info = {
		.receive_handler = xve_receive_handler,
		.event_handler = xve_xsmp_event_handler,
		.callout_handler = xve_xsmp_callout_handler,
		.ctrl_message_type = XSMP_MESSAGE_TYPE_XVE,
		.resource_flag_index = RESOURCE_FLAG_INDEX_XVE
	};

	xve_xsmp_service_id = xcpm_register_service(&service_info);
	if (xve_xsmp_service_id < 0)
		return xve_xsmp_service_id;
	return 0;
}

void xve_xsmp_exit(void)
{
	(void)xcpm_unregister_service(xve_xsmp_service_id);
	xve_xsmp_service_id = -1;
}

static int __init xve_init_module(void)
{
	int ret;

	INIT_LIST_HEAD(&xve_dev_list);
	spin_lock_init(&xve_lock);

	mutex_init(&xve_mutex);

	xve_recvq_size = roundup_pow_of_two(xve_recvq_size);
	xve_recvq_size = min(xve_recvq_size, XVE_MAX_QUEUE_SIZE);
	xve_recvq_size = max(xve_recvq_size, XVE_MIN_QUEUE_SIZE);

	xve_sendq_size = roundup_pow_of_two(xve_sendq_size);
	xve_sendq_size = min(xve_sendq_size, XVE_MAX_QUEUE_SIZE);
	xve_sendq_size = max(xve_sendq_size, max(2 * xve_max_send_cqe,
						 XVE_MIN_QUEUE_SIZE));
	/*
	 * When copying small received packets, we only copy from the
	 * linear data part of the SKB, so we rely on this condition.
	 */
	BUILD_BUG_ON(XVE_CM_COPYBREAK > XVE_CM_HEAD_SIZE);

	ret = xve_create_procfs_root_entries();
	if (ret)
		return ret;

	ret = xve_tables_init();
	if (ret)
		goto err_fs;

	/*
	 * We create our own workqueue mainly because we want to be
	 * able to flush it when devices are being removed.  We can't
	 * use schedule_work()/flush_scheduled_work() because both
	 * unregister_netdev() and linkwatch_event take the rtnl lock,
	 * so flush_scheduled_work() can deadlock during device
	 * removal.
	 */
	xve_workqueue = create_singlethread_workqueue("xve");
	if (!xve_workqueue) {
		ret = -ENOMEM;
		goto err_tables;
	}

	xve_taskqueue = create_singlethread_workqueue("xve_taskq");
	if (!xve_taskqueue) {
		ret = -ENOMEM;
		goto err_tables;
	}

	xve_xsmp_init();
	/*
	 * Now register with IB framework
	 */
	ib_sa_register_client(&xve_sa_client);
	return 0;

err_tables:
	xve_tables_exit();

err_fs:
	xve_remove_procfs_root_entries();
	return ret;
}

static void __exit xve_cleanup_module(void)
{
	struct xve_dev_priv *priv;
	unsigned long flags = 0;

	pr_info("XVE: %s Remove module\n", __func__);
	xve_xsmp_exit();

	mutex_lock(&xve_mutex);

	list_for_each_entry(priv, &xve_dev_list, list) {
		spin_lock_irqsave(&priv->lock, flags);
		set_bit(XVE_DELETING, &priv->state);
		/*Set OperState to down*/
		clear_bit(XVE_OPER_UP, &priv->state);
		set_bit(XVE_SHUTDOWN, &priv->state);
		spin_unlock_irqrestore(&priv->lock, flags);
	}

	while (!list_empty(&xve_dev_list)) {
		mutex_unlock(&xve_mutex);
		msleep(100);
		mutex_lock(&xve_mutex);
	}
	mutex_unlock(&xve_mutex);
	ib_sa_unregister_client(&xve_sa_client);
	xve_tables_exit();
	mutex_lock(&xve_mutex);
	flush_workqueue(xve_workqueue);
	destroy_workqueue(xve_workqueue);
	flush_workqueue(xve_taskqueue);
	destroy_workqueue(xve_taskqueue);
	mutex_unlock(&xve_mutex);

	xve_remove_procfs_root_entries();
	mutex_destroy(&xve_mutex);
	pr_info("XVE: %s module remove success\n", __func__);
}

module_init(xve_init_module);
module_exit(xve_cleanup_module);
