/*
 * Copyright (c) 2011-2012 Xsigo Systems. All rights reserved
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

#include <linux/skbuff.h>
#include <linux/delay.h>
#include <linux/completion.h>

#include "xve.h"
#include "xve_compat.h"

static int rate_selector = IB_SA_EQ;
module_param(rate_selector, int, 0444);
MODULE_PARM_DESC(rate_selector, "Multicast rate selector");

static int mcast_rate = IB_RATE_10_GBPS;
module_param(mcast_rate, int, 0444);
MODULE_PARM_DESC(mcast_rate, "Multicast rate during join/create");

static DEFINE_MUTEX(mcast_mutex);

struct xve_mcast_iter {
	struct net_device *dev;
	union ib_gid mgid;
	unsigned long created;
	unsigned int queuelen;
	unsigned int complete;
	unsigned int send_only;
};

static void xve_mcast_free(struct xve_mcast *mcast)
{
	struct net_device *dev = mcast->netdev;
	int tx_dropped = 0;

	xve_dbg_mcast(netdev_priv(dev), "deleting multicast group %pI6\n",
		      mcast->mcmember.mgid.raw);

	if (mcast->ah)
		xve_put_ah(mcast->ah);

	while (!skb_queue_empty(&mcast->pkt_queue)) {
		++tx_dropped;
		dev_kfree_skb_any(skb_dequeue(&mcast->pkt_queue));
	}

	netif_tx_lock_bh(dev);
	dev->stats.tx_dropped += tx_dropped;
	((struct xve_dev_priv *)netdev_priv(dev))->stats.tx_dropped +=
	    tx_dropped;
	netif_tx_unlock_bh(dev);

	kfree(mcast);
}

static struct xve_mcast *xve_mcast_alloc(struct net_device *dev, int can_sleep)
{
	struct xve_mcast *mcast;

	mcast = kzalloc(sizeof(*mcast), can_sleep ? GFP_KERNEL : GFP_ATOMIC);
	if (!mcast)
		return NULL;

	mcast->netdev = dev;
	mcast->created = jiffies;
	mcast->used = jiffies;
	mcast->backoff = 1;

	INIT_LIST_HEAD(&mcast->list);
	skb_queue_head_init(&mcast->pkt_queue);

	return mcast;
}

static struct xve_mcast *__xve_mcast_find(struct net_device *dev, void *mgid)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct rb_node *n = priv->multicast_tree.rb_node;

	while (n) {
		struct xve_mcast *mcast;
		int ret;

		mcast = rb_entry(n, struct xve_mcast, rb_node);

		ret = memcmp(mgid, mcast->mcmember.mgid.raw,
			     sizeof(union ib_gid));
		if (ret < 0)
			n = n->rb_left;
		else if (ret > 0)
			n = n->rb_right;
		else
			return mcast;
	}

	return NULL;
}

static int __xve_mcast_add(struct net_device *dev, struct xve_mcast *mcast)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct rb_node **n = &priv->multicast_tree.rb_node, *pn = NULL;

	while (*n) {
		struct xve_mcast *tmcast;
		int ret;

		pn = *n;
		tmcast = rb_entry(pn, struct xve_mcast, rb_node);

		ret =
		    memcmp(mcast->mcmember.mgid.raw, tmcast->mcmember.mgid.raw,
			   sizeof(union ib_gid));
		if (ret < 0)
			n = &pn->rb_left;
		else if (ret > 0)
			n = &pn->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&mcast->rb_node, pn, n);
	rb_insert_color(&mcast->rb_node, &priv->multicast_tree);

	return 0;
}

static int xve_mcast_join_finish(struct xve_mcast *mcast,
				 struct ib_sa_mcmember_rec *mcmember)
{
	struct net_device *dev = mcast->netdev;
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_ah *ah;
	int ret;
	int set_qkey = 0;

	mcast->mcmember = *mcmember;

	/* Set the cached Q_Key before we attach if it's the broadcast group */
	if (!memcmp(mcast->mcmember.mgid.raw, priv->bcast_mgid.raw,
		    sizeof(union ib_gid))) {
		spin_lock_irq(&priv->lock);
		if (!priv->broadcast) {
			spin_unlock_irq(&priv->lock);
			return -EAGAIN;
		}
		priv->qkey = be32_to_cpu(priv->broadcast->mcmember.qkey);
		spin_unlock_irq(&priv->lock);
		priv->tx_wr.wr.ud.remote_qkey = priv->qkey;
		set_qkey = 1;
	}

	if (!test_bit(XVE_MCAST_FLAG_SENDONLY, &mcast->flags)) {
		if (test_and_set_bit(XVE_MCAST_FLAG_ATTACHED, &mcast->flags)) {
			xve_warn(priv,
				 "multicast group %pI6 already attached\n",
				 mcast->mcmember.mgid.raw);

			return 0;
		}

		ret = xve_mcast_attach(dev, be16_to_cpu(mcast->mcmember.mlid),
				       &mcast->mcmember.mgid, set_qkey);
		if (ret < 0) {
			xve_warn(priv,
				 "couldn't attach QP to multicast group %pI6\n",
				 mcast->mcmember.mgid.raw);

			clear_bit(XVE_MCAST_FLAG_ATTACHED, &mcast->flags);
			return ret;
		}
	}

	{
		struct ib_ah_attr av = {
			.dlid = be16_to_cpu(mcast->mcmember.mlid),
			.port_num = priv->port,
			.sl = mcast->mcmember.sl,
			.ah_flags = IB_AH_GRH,
			.static_rate = mcast->mcmember.rate,
			.grh = {
				.flow_label =
				be32_to_cpu(mcast->mcmember.flow_label),
				.hop_limit = mcast->mcmember.hop_limit,
				.sgid_index = 0,
				.traffic_class = mcast->mcmember.traffic_class}
		};
		av.grh.dgid = mcast->mcmember.mgid;

		ah = xve_create_ah(dev, priv->pd, &av);
		if (!ah) {
			xve_warn(priv, "ib_address_create failed\n");
		} else {
			spin_lock_irq(&priv->lock);
			mcast->ah = ah;
			spin_unlock_irq(&priv->lock);

			xve_dbg_mcast(priv,
				      "MGID %pI6 AV %p, LID 0x%04x, SL %d\n",
				      mcast->mcmember.mgid.raw, mcast->ah->ah,
				      be16_to_cpu(mcast->mcmember.mlid),
				      mcast->mcmember.sl);
		}
	}

	/* actually send any queued packets */
	netif_tx_lock_bh(dev);
	while (!skb_queue_empty(&mcast->pkt_queue)) {
		struct sk_buff *skb = skb_dequeue(&mcast->pkt_queue);
		netif_tx_unlock_bh(dev);
		skb->dev = dev;
		if (dev_queue_xmit(skb))
			xve_warn(priv,
				 "dev_queue_xmit failed to requeue packet\n");
		netif_tx_lock_bh(dev);
	}
	netif_tx_unlock_bh(dev);

	return 0;
}

static int xve_mcast_sendonly_join_complete(int status,
					    struct ib_sa_multicast *multicast)
{
	struct xve_mcast *mcast = multicast->context;
	struct net_device *dev = mcast->netdev;

	/* We trap for port events ourselves. */
	if (status == -ENETRESET)
		return 0;

	if (!status)
		status = xve_mcast_join_finish(mcast, &multicast->rec);

	if (status) {
		if (mcast->logcount++ < 20)
			xve_dbg_mcast(netdev_priv(dev),
				      "%s multicast join failed for %pI6, status %d\n",
				      __func__, mcast->mcmember.mgid.raw,
				      status);

		/* Flush out any queued packets */
		netif_tx_lock_bh(dev);
		while (!skb_queue_empty(&mcast->pkt_queue)) {
			INC_TX_DROP_STATS(((struct xve_dev_priv *)
					   netdev_priv(dev)), dev);
			dev_kfree_skb_any(skb_dequeue(&mcast->pkt_queue));
		}
		netif_tx_unlock_bh(dev);
		/* Clear the busy flag so we try again */
		status = test_and_clear_bit(XVE_MCAST_FLAG_BUSY, &mcast->flags);
	}
	return status;
}

static int xve_mcast_sendonly_join(struct xve_mcast *mcast)
{
	struct net_device *dev = mcast->netdev;
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct ib_sa_mcmember_rec rec = {
		.join_state = 1
	};
	ib_sa_comp_mask comp_mask;
	int ret = 0;

	if (!test_bit(XVE_FLAG_OPER_UP, &priv->flags)) {
		xve_dbg_mcast(priv,
			      "device shutting down, no multicast joins\n");
		return -ENODEV;
	}

	if (test_and_set_bit(XVE_MCAST_FLAG_BUSY, &mcast->flags)) {
		xve_dbg_mcast(priv, "multicast entry busy, skipping\n");
		return -EBUSY;
	}

	rec.mgid = mcast->mcmember.mgid;
	rec.port_gid = priv->local_gid;
	rec.pkey = cpu_to_be16(priv->pkey);

	comp_mask =
	    IB_SA_MCMEMBER_REC_MGID |
	    IB_SA_MCMEMBER_REC_PORT_GID |
	    IB_SA_MCMEMBER_REC_PKEY | IB_SA_MCMEMBER_REC_JOIN_STATE;

	if (priv->broadcast) {
		comp_mask |=
		    IB_SA_MCMEMBER_REC_QKEY |
		    IB_SA_MCMEMBER_REC_MTU_SELECTOR |
		    IB_SA_MCMEMBER_REC_MTU |
		    IB_SA_MCMEMBER_REC_TRAFFIC_CLASS |
		    IB_SA_MCMEMBER_REC_RATE_SELECTOR |
		    IB_SA_MCMEMBER_REC_RATE |
		    IB_SA_MCMEMBER_REC_SL |
		    IB_SA_MCMEMBER_REC_FLOW_LABEL |
		    IB_SA_MCMEMBER_REC_HOP_LIMIT;

		rec.qkey = priv->broadcast->mcmember.qkey;
		rec.mtu_selector = IB_SA_EQ;
		rec.mtu = priv->broadcast->mcmember.mtu;
		rec.traffic_class = priv->broadcast->mcmember.traffic_class;
		rec.rate_selector = IB_SA_EQ;
		rec.rate = priv->broadcast->mcmember.rate;
		rec.sl = priv->broadcast->mcmember.sl;
		rec.flow_label = priv->broadcast->mcmember.flow_label;
		rec.hop_limit = priv->broadcast->mcmember.hop_limit;
	}
	xve_dbg_mcast(priv, "%s Joining send only join mtu %d\n", __func__,
		      rec.mtu);

	mcast->mc = ib_sa_join_multicast(&xve_sa_client, priv->ca,
					 priv->port, &rec,
					 comp_mask,
					 GFP_ATOMIC,
					 xve_mcast_sendonly_join_complete,
					 mcast);
	if (IS_ERR(mcast->mc)) {
		ret = PTR_ERR(mcast->mc);
		clear_bit(XVE_MCAST_FLAG_BUSY, &mcast->flags);
		xve_warn(priv, "ib_sa_join_multicast failed (ret = %d)\n", ret);
	} else {
		xve_dbg_mcast(priv,
			      "no multicast record for %pI6, starting join\n",
			      mcast->mcmember.mgid.raw);
	}

	return ret;
}

static int xve_mcast_join_complete(int status,
				   struct ib_sa_multicast *multicast)
{
	struct xve_mcast *mcast = multicast->context;
	struct net_device *dev = mcast->netdev;
	struct xve_dev_priv *priv = netdev_priv(dev);

	xve_dbg_mcast(priv, "join completion for %pI6 (status %d)\n",
		      mcast->mcmember.mgid.raw, status);

	/* We trap for port events ourselves. */
	if (status == -ENETRESET)
		return 0;

	if (!status)
		status = xve_mcast_join_finish(mcast, &multicast->rec);

	if (!status) {
		mcast->backoff = 1;
		mutex_lock(&mcast_mutex);
		if (test_bit(XVE_MCAST_RUN, &priv->flags))
			xve_queue_complete_work(priv, XVE_WQ_START_MCASTJOIN,
						0);
		mutex_unlock(&mcast_mutex);

		/*
		 * Defer carrier on work to workqueue to avoid a
		 * deadlock on rtnl_lock here.
		 */
		if (mcast == priv->broadcast)
			xve_queue_work(priv, XVE_WQ_START_MCASTON);

		return 0;
	}

	if (mcast->logcount++ < 20) {
		if (status == -ETIMEDOUT || status == -EAGAIN) {
			xve_dbg_mcast(priv,
				      "%s multicast join failed for %pI6, status %d\n",
				      __func__, mcast->mcmember.mgid.raw,
				      status);
		} else {
			xve_warn(priv,
				 "%s multicast join failed for %pI6, status %d\n",
				 __func__, mcast->mcmember.mgid.raw,
				 status);
		}
	}

	mcast->backoff *= 2;
	if (mcast->backoff > XVE_MAX_BACKOFF_SECONDS)
		mcast->backoff = XVE_MAX_BACKOFF_SECONDS;

	/* Clear the busy flag so we try again */
	status = test_and_clear_bit(XVE_MCAST_FLAG_BUSY, &mcast->flags);

	mutex_lock(&mcast_mutex);
	spin_lock_irq(&priv->lock);
	if (test_bit(XVE_MCAST_RUN, &priv->flags))
		xve_queue_complete_work(priv, XVE_WQ_START_MCASTJOIN,
					mcast->backoff * HZ);
	spin_unlock_irq(&priv->lock);
	mutex_unlock(&mcast_mutex);

	return status;
}

static void xve_mcast_join(struct net_device *dev, struct xve_mcast *mcast,
			   int create)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct ib_sa_mcmember_rec rec = {
		.join_state = 1
	};
	ib_sa_comp_mask comp_mask;
	int ret = 0;

	rec.mgid = mcast->mcmember.mgid;
	rec.port_gid = priv->local_gid;
	rec.pkey = cpu_to_be16(priv->pkey);

	comp_mask =
	    IB_SA_MCMEMBER_REC_MGID |
	    IB_SA_MCMEMBER_REC_PORT_GID |
	    IB_SA_MCMEMBER_REC_PKEY | IB_SA_MCMEMBER_REC_JOIN_STATE;

	if (create) {
		comp_mask |=
		    IB_SA_MCMEMBER_REC_QKEY |
		    IB_SA_MCMEMBER_REC_TRAFFIC_CLASS |
		    IB_SA_MCMEMBER_REC_SL |
		    IB_SA_MCMEMBER_REC_FLOW_LABEL |
		    IB_SA_MCMEMBER_REC_RATE_SELECTOR |
		    IB_SA_MCMEMBER_REC_RATE | IB_SA_MCMEMBER_REC_HOP_LIMIT;

		rec.qkey = 0x0;
		rec.traffic_class = 0x0;
		rec.sl = 0x0;
		rec.flow_label = 0x0;
		rec.hop_limit = 0x0;
		/*
		 * Create with 10Gbps speed (equals)
		 */
		rec.rate_selector = rate_selector;
		rec.rate = mcast_rate;
	}

	xve_dbg_mcast(priv, "joining MGID %pI6 pkey %d qkey %d\n",
		      mcast->mcmember.mgid.raw, rec.pkey, rec.qkey);
	set_bit(XVE_MCAST_FLAG_BUSY, &mcast->flags);
	mcast->mc = ib_sa_join_multicast(&xve_sa_client, priv->ca, priv->port,
					 &rec, comp_mask, GFP_KERNEL,
					 xve_mcast_join_complete, mcast);
	if (IS_ERR(mcast->mc)) {
		clear_bit(XVE_MCAST_FLAG_BUSY, &mcast->flags);
		ret = PTR_ERR(mcast->mc);
		xve_warn(priv, "ib_sa_join_multicast failed, status %d\n", ret);

		mcast->backoff *= 2;
		if (mcast->backoff > XVE_MAX_BACKOFF_SECONDS)
			mcast->backoff = XVE_MAX_BACKOFF_SECONDS;

		mutex_lock(&mcast_mutex);
		if (test_bit(XVE_MCAST_RUN, &priv->flags))
			xve_queue_complete_work(priv, XVE_WQ_START_MCASTJOIN,
						mcast->backoff * HZ);
		mutex_unlock(&mcast_mutex);
	}
}

void xve_mcast_join_task(struct work_struct *work)
{
	struct xve_dev_priv *priv =
	    xve_get_wqctx(work, XVE_WQ_FINISH_MCASTJOIN, 2);
	struct net_device *dev = priv->netdev;
	struct ib_port_attr attr;

	if (!test_bit(XVE_MCAST_RUN, &priv->flags))
		return;

	if (!ib_query_port(priv->ca, priv->port, &attr))
		priv->local_lid = attr.lid;
	else
		xve_warn(priv, "ib_query_port failed\n");

	priv->counters[XVE_MCAST_JOIN_TASK]++;

	if (!priv->broadcast) {
		struct xve_mcast *broadcast;

		if (!test_bit(XVE_FLAG_ADMIN_UP, &priv->flags))
			return;

		broadcast = xve_mcast_alloc(dev, 1);
		if (!broadcast) {
			xve_warn(priv, "failed to allocate broadcast group\n");
			mutex_lock(&mcast_mutex);
			if (test_bit(XVE_MCAST_RUN, &priv->flags))
				xve_queue_complete_work(priv,
							XVE_WQ_START_MCASTJOIN,
							HZ);
			mutex_unlock(&mcast_mutex);
			return;
		}

		spin_lock_irq(&priv->lock);
		memcpy(broadcast->mcmember.mgid.raw, priv->bcast_mgid.raw,
		       sizeof(union ib_gid));
		priv->broadcast = broadcast;
		__xve_mcast_add(dev, priv->broadcast);
		spin_unlock_irq(&priv->lock);
	}

	if (priv->broadcast &&
	    !test_bit(XVE_MCAST_FLAG_ATTACHED, &priv->broadcast->flags)) {
		if (priv->broadcast &&
		    !test_bit(XVE_MCAST_FLAG_BUSY, &priv->broadcast->flags))
			xve_mcast_join(dev, priv->broadcast, 1);
		return;
	}

	while (1) {
		struct xve_mcast *mcast = NULL;

		spin_lock_irq(&priv->lock);
		list_for_each_entry(mcast, &priv->multicast_list, list) {
			if (!test_bit(XVE_MCAST_FLAG_SENDONLY, &mcast->flags)
			    && !test_bit(XVE_MCAST_FLAG_BUSY, &mcast->flags)
			    && !test_bit(XVE_MCAST_FLAG_ATTACHED,
					 &mcast->flags)) {
				/* Found the next unjoined group */
				break;
			}
		}
		spin_unlock_irq(&priv->lock);

		if (&mcast->list == &priv->multicast_list) {
			/* All done */
			break;
		}

		xve_mcast_join(dev, mcast, 1);
		return;
	}

	spin_lock_irq(&priv->lock);
	if (priv->broadcast)
		priv->mcast_mtu =
		    XVE_UD_MTU(ib_mtu_enum_to_int
			       (priv->broadcast->mcmember.mtu));
	else
		priv->mcast_mtu = priv->admin_mtu;
	spin_unlock_irq(&priv->lock);

	if (!xve_cm_admin_enabled(dev)) {
		printk
		    ("XVE: %s xve %s dev mtu %d, admin_mtu %d, mcast_mtu %d\n",
		     __func__, priv->xve_name, priv->netdev->mtu,
		     priv->admin_mtu, priv->mcast_mtu);
		xve_dev_set_mtu(dev, min(priv->mcast_mtu, priv->admin_mtu));
	}

	xve_dbg_mcast(priv, "successfully joined all multicast groups\n");
	clear_bit(XVE_MCAST_RUN, &priv->flags);
}

int xve_mcast_start_thread(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);

	/* Dont start mcast if it the interface is not up */
	if (!test_bit(XVE_FLAG_ADMIN_UP, &priv->flags)
	    || !test_bit(XVE_CHASSIS_ADMIN_UP, &priv->state))
		return -ENOTCONN;

	xve_dbg_mcast(priv, "%s Starting  mcast thread for  state[%ld ]\n",
		      __func__, priv->flags);

	mutex_lock(&mcast_mutex);
	if (!test_and_set_bit(XVE_MCAST_RUN, &priv->flags))
		xve_queue_complete_work(priv, XVE_WQ_START_MCASTJOIN, 0);

	if (!test_and_set_bit(XVE_MCAST_RUN_GC, &priv->flags))
		xve_queue_complete_work(priv, XVE_WQ_START_MCASTLEAVE, 0);

	mutex_unlock(&mcast_mutex);

	return 0;
}

int xve_mcast_stop_thread(struct net_device *dev, int flush)
{
	struct xve_dev_priv *priv = netdev_priv(dev);

	xve_dbg_mcast(priv, "stopping multicast thread\n");

	mutex_lock(&mcast_mutex);
	clear_bit(XVE_MCAST_RUN, &priv->flags);
	clear_bit(XVE_MCAST_RUN_GC, &priv->flags);
	cancel_delayed_work(&priv->mcast_join_task);
	cancel_delayed_work(&priv->mcast_leave_task);
	mutex_unlock(&mcast_mutex);

	return 0;
}

static int xve_mcast_leave(struct net_device *dev, struct xve_mcast *mcast)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	int ret = 0;

	if (test_and_clear_bit(XVE_MCAST_FLAG_BUSY, &mcast->flags))
		ib_sa_free_multicast(mcast->mc);

	if (test_and_clear_bit(XVE_MCAST_FLAG_ATTACHED, &mcast->flags)) {
		xve_dbg_mcast(priv, "leaving MGID %pI6\n",
			      mcast->mcmember.mgid.raw);

		/* Remove ourselves from the multicast group */
		if (priv->qp) {
			if (!test_bit(XVE_FLAG_DONT_DETACH_MCAST, &priv->flags))
				ret =
				    ib_detach_mcast(priv->qp,
						    &mcast->mcmember.mgid,
						    be16_to_cpu(mcast->mcmember.
								mlid));
		}
		if (ret)
			xve_warn(priv, "ib_detach_mcast failed (result = %d)\n",
				 ret);
	}

	return 0;
}

void xve_mcast_send(struct net_device *dev, void *mgid, struct sk_buff *skb)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct xve_mcast *mcast;

	if (!test_bit(XVE_FLAG_OPER_UP, &priv->flags) ||
	    !priv->broadcast ||
	    !test_bit(XVE_MCAST_FLAG_ATTACHED, &priv->broadcast->flags)) {
		INC_TX_DROP_STATS(priv, dev);
		dev_kfree_skb_any(skb);
		return;
	}

	mcast = __xve_mcast_find(dev, mgid);
	if (!mcast) {
		/* Let's create a new send only group now */
		xve_dbg_mcast(priv,
			      "setting up send only multicast group for %pI6\n",
			      mgid);

		mcast = xve_mcast_alloc(dev, 0);
		if (!mcast) {
			xve_warn(priv, "unable to allocate memory for ");
			xve_warn(priv, "multicast structure\n");
			INC_TX_DROP_STATS(priv, dev);
			dev_kfree_skb_any(skb);
			goto out;
		}

		set_bit(XVE_MCAST_FLAG_SENDONLY, &mcast->flags);
		memcpy(mcast->mcmember.mgid.raw, mgid, sizeof(union ib_gid));
		__xve_mcast_add(dev, mcast);
		list_add_tail(&mcast->list, &priv->multicast_list);
	}

	if (!mcast->ah) {
		if (skb_queue_len(&mcast->pkt_queue) < XVE_MAX_MCAST_QUEUE)
			skb_queue_tail(&mcast->pkt_queue, skb);
		else {
			INC_TX_DROP_STATS(priv, dev);
			dev_kfree_skb_any(skb);
		}

		if (test_bit(XVE_MCAST_FLAG_BUSY, &mcast->flags)) {
			xve_dbg_mcast(priv, "no address vector, ");
			xve_dbg_mcast(priv, "but mcast join already started\n");
		}
		if (test_bit(XVE_MCAST_FLAG_SENDONLY, &mcast->flags))
			xve_mcast_sendonly_join(mcast);
		/*
		 * If lookup completes between here and out:, don't
		 * want to send packet twice.
		 */
		mcast = NULL;
	}

out:
	if (mcast && mcast->ah) {
		xve_test("%s about to send mcast %02x%02x%02x%02x%02x%02x"
			, __func__, skb->data[0],
			skb->data[1], skb->data[2], skb->data[3], skb->data[4],
			skb->data[5]);
		xve_test("ah=%p proto=%02x%02x for %s\n",
			mcast->ah->ah, skb->data[12],
			skb->data[13], dev->name);
		xve_send(dev, skb, mcast->ah, IB_MULTICAST_QPN);
	}

}

void xve_mcast_carrier_on_task(struct work_struct *work)
{
	struct xve_dev_priv *priv =
	    xve_get_wqctx(work, XVE_WQ_FINISH_MCASTON, 0);
	struct ib_port_attr attr;

	if (ib_query_port(priv->ca, priv->port, &attr) ||
	    attr.state != IB_PORT_ACTIVE) {
		priv->counters[XVE_IB_PORT_NOT_ACTIVE]++;
		xve_dbg_mcast(priv,
			      "%s Keeping carrier off until IB port is active\n",
			      __func__);
		return;
	}

	priv->counters[XVE_MCAST_CARRIER_TASK]++;
	/*
	 * Take rtnl_lock to avoid racing with xve_stop() and
	 * turning the carrier back on while a device is being
	 * removed.
	 */
	rtnl_lock();
	if (!netif_carrier_ok(priv->netdev) && priv->broadcast &&
	    (test_bit(XVE_MCAST_FLAG_ATTACHED, &priv->broadcast->flags))) {
		xve_dbg_mcast(priv, "XVE: %s Sending netif carrier on to %s\n",
			      __func__, priv->xve_name);
		handle_carrier_state(priv, 1);
	}
	rtnl_unlock();
}

void xve_mcast_dev_flush(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	LIST_HEAD(remove_list);
	struct xve_mcast *mcast, *tmcast;
	unsigned long flags;

	xve_dbg_mcast(priv, "flushing multicast list\n");

	spin_lock_irqsave(&priv->lock, flags);
	list_for_each_entry_safe(mcast, tmcast, &priv->multicast_list, list) {
		list_del(&mcast->list);
		rb_erase(&mcast->rb_node, &priv->multicast_tree);
		list_add_tail(&mcast->list, &remove_list);
		mcast->used = jiffies;
	}

	if (priv->broadcast) {
		rb_erase(&priv->broadcast->rb_node, &priv->multicast_tree);
		list_add_tail(&priv->broadcast->list, &remove_list);
		priv->broadcast = NULL;
	}
	spin_unlock_irqrestore(&priv->lock, flags);

	list_for_each_entry_safe(mcast, tmcast, &remove_list, list) {
		mcast->used = jiffies;
		xve_mcast_leave(dev, mcast);
		xve_mcast_free(mcast);
	}

}

void xve_mcast_restart_task(struct work_struct *work)
{
	struct xve_dev_priv *priv =
	    xve_get_wqctx(work, XVE_WQ_FINISH_MCASTRESTART, 0);
	struct net_device *dev = priv->netdev;

	xve_dbg_mcast(priv, "%s Restarting  mcast thread for  state[%ld ]\n",
		      __func__, priv->flags);
	xve_mcast_stop_thread(dev, 0);
	xve_mcast_start_thread(dev);
}

void xve_mcast_leave_task(struct work_struct *work)
{
	struct xve_dev_priv *priv =
	    xve_get_wqctx(work, XVE_WQ_FINISH_MCASTLEAVE, 2);
	struct net_device *dev = priv->netdev;
	struct xve_mcast *mcast, *tmcast;
	LIST_HEAD(remove_list);

	if (!test_bit(XVE_MCAST_RUN_GC, &priv->flags))
		return;

	priv->counters[XVE_MCAST_LEAVE_TASK]++;

	if (xve_mc_sendonly_timeout > 0) {
		list_for_each_entry_safe(mcast, tmcast, &priv->multicast_list,
					 list) {
			if (test_bit(XVE_MCAST_FLAG_SENDONLY, &mcast->flags)
			    && time_before(mcast->used,
					   jiffies -
					   xve_mc_sendonly_timeout * HZ)) {
				rb_erase(&mcast->rb_node,
					 &priv->multicast_tree);
				list_move_tail(&mcast->list, &remove_list);
			}
		}

		list_for_each_entry_safe(mcast, tmcast, &remove_list, list) {
			xve_mcast_leave(dev, mcast);
			xve_mcast_free(mcast);
		}
	}

	xve_queue_complete_work(priv, XVE_WQ_START_MCASTLEAVE, 60 * HZ);

}
