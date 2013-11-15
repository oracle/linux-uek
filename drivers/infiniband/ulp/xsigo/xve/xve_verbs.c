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

#include "xve.h"
#include "xve_compat.h"

int xve_mcast_attach(struct net_device *dev, u16 mlid, union ib_gid *mgid,
		     int set_qkey)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct ib_qp_attr *qp_attr = NULL;
	int ret;
	u16 pkey_index;

	if (ib_find_pkey(priv->ca, priv->port, priv->pkey, &pkey_index)) {
		clear_bit(XVE_PKEY_ASSIGNED, &priv->flags);
		ret = -ENXIO;
		goto out;
	}
	set_bit(XVE_PKEY_ASSIGNED, &priv->flags);

	if (set_qkey) {
		ret = -ENOMEM;
		qp_attr = kmalloc(sizeof(*qp_attr), GFP_KERNEL);
		if (!qp_attr)
			goto out;

		/* set correct QKey for QP */
		qp_attr->qkey = priv->qkey;
		ret = ib_modify_qp(priv->qp, qp_attr, IB_QP_QKEY);
		if (ret) {
			xve_warn(priv, "failed to modify QP, ret = %d\n", ret);
			goto out;
		}
	}

	/* attach QP to multicast group */
	ret = ib_attach_mcast(priv->qp, mgid, mlid);
	if (ret)
		xve_warn(priv,
			 "failed to attach to multicast group, ret = %d\n",
			 ret);

out:
	kfree(qp_attr);
	return ret;
}

int xve_init_qp(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	int ret;
	struct ib_qp_attr qp_attr;
	int attr_mask;

	if (!test_bit(XVE_PKEY_ASSIGNED, &priv->flags))
		return -1;

	qp_attr.qp_state = IB_QPS_INIT;
	qp_attr.qkey = 0;
	qp_attr.port_num = priv->port;
	qp_attr.pkey_index = priv->pkey_index;
	attr_mask = IB_QP_QKEY | IB_QP_PORT | IB_QP_PKEY_INDEX | IB_QP_STATE;
	ret = ib_modify_qp(priv->qp, &qp_attr, attr_mask);
	if (ret) {
		xve_warn(priv, "failed to modify QP to init, ret = %d\n", ret);
		goto out_fail;
	}

	qp_attr.qp_state = IB_QPS_RTR;
	/* Can't set this in a INIT->RTR transition */
	attr_mask &= ~IB_QP_PORT;
	ret = ib_modify_qp(priv->qp, &qp_attr, attr_mask);
	if (ret) {
		xve_warn(priv, "failed to modify QP to RTR, ret = %d\n", ret);
		goto out_fail;
	}

	qp_attr.qp_state = IB_QPS_RTS;
	qp_attr.sq_psn = 0;
	attr_mask |= IB_QP_SQ_PSN;
	attr_mask &= ~IB_QP_PKEY_INDEX;
	ret = ib_modify_qp(priv->qp, &qp_attr, attr_mask);
	if (ret) {
		xve_warn(priv, "failed to modify QP to RTS, ret = %d\n", ret);
		goto out_fail;
	}

	return 0;

out_fail:
	qp_attr.qp_state = IB_QPS_RESET;
	if (ib_modify_qp(priv->qp, &qp_attr, IB_QP_STATE))
		xve_warn(priv, "Failed to modify QP to RESET state\n");

	return ret;
}

int xve_transport_dev_init(struct net_device *dev, struct ib_device *ca)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	struct ib_qp_init_attr init_attr = {
		.cap = {
			.max_send_wr = xve_sendq_size,
			.max_recv_wr = xve_recvq_size,
			.max_send_sge = 1,
			.max_recv_sge = XVE_UD_RX_SG},
		.sq_sig_type = IB_SIGNAL_ALL_WR,
		.qp_type = IB_QPT_UD
	};

	int ret, size;
	int i;
	struct ethtool_coalesce *coal;

	priv->pd = ib_alloc_pd(priv->ca);
	if (IS_ERR(priv->pd)) {
		pr_warn("%s: failed to allocate PD for %s\n",
		       ca->name, priv->xve_name);
		return -ENODEV;
	}

	priv->mr = ib_get_dma_mr(priv->pd, IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(priv->mr)) {
		pr_warn("%s: ib_get_dma_mr failed\n", ca->name);
		goto out_free_pd;
	}

	size = xve_recvq_size + 1;
	ret = xve_cm_dev_init(dev);
	if (ret != 0) {
		pr_err("%s Failed for %s [ret %d ]\n", __func__,
		       priv->xve_name, ret);
		goto out_free_mr;
	}
	size += xve_sendq_size;
	size += xve_recvq_size + 1;	/* 1 extra for rx_drain_qp */

	priv->recv_cq =
	    ib_create_cq(priv->ca, xve_ib_completion, NULL, dev, size, 0);
	if (IS_ERR(priv->recv_cq)) {
		pr_warn("%s: failed to create receive CQ for %s\n",
		       ca->name, priv->xve_name);
		goto out_free_mr;
	}

	priv->send_cq = ib_create_cq(priv->ca, xve_send_comp_handler, NULL,
				     dev, xve_sendq_size, 0);
	if (IS_ERR(priv->send_cq)) {
		pr_warn("%s: failed to create send CQ for %s\n",
		       ca->name, priv->xve_name);
		goto out_free_recv_cq;
	}

	if (ib_req_notify_cq(priv->recv_cq, IB_CQ_NEXT_COMP))
		goto out_free_send_cq;

	coal = kzalloc(sizeof(*coal), GFP_KERNEL);
	if (coal) {
		coal->rx_coalesce_usecs = 10;
		coal->tx_coalesce_usecs = 10;
		coal->rx_max_coalesced_frames = 16;
		coal->tx_max_coalesced_frames = 16;
		dev->ethtool_ops->set_coalesce(dev, coal);
		kfree(coal);
	}

	init_attr.send_cq = priv->send_cq;
	init_attr.recv_cq = priv->recv_cq;

	if (priv->hca_caps & IB_DEVICE_BLOCK_MULTICAST_LOOPBACK)
		init_attr.create_flags |= IB_QP_CREATE_BLOCK_MULTICAST_LOOPBACK;

	if (dev->features & NETIF_F_SG)
		init_attr.cap.max_send_sge = MAX_SKB_FRAGS + 1;

	priv->qp = ib_create_qp(priv->pd, &init_attr);
	if (IS_ERR(priv->qp)) {
		pr_warn("%s: failed to create QP\n", ca->name);
		goto out_free_send_cq;
	}

	for (i = 0; i < MAX_SKB_FRAGS + 1; ++i)
		priv->tx_sge[i].lkey = priv->mr->lkey;

	priv->tx_wr.opcode = IB_WR_SEND;
	priv->tx_wr.sg_list = priv->tx_sge;
	priv->tx_wr.send_flags = IB_SEND_SIGNALED;

	priv->rx_sge[0].lkey = priv->mr->lkey;
	if (xve_ud_need_sg(priv->max_ib_mtu)) {
		priv->rx_sge[0].length = XVE_UD_HEAD_SIZE;
		priv->rx_sge[1].length = PAGE_SIZE;
		priv->rx_sge[1].lkey = priv->mr->lkey;
		priv->rx_wr.num_sge = XVE_UD_RX_SG;
	} else {
		priv->rx_sge[0].length = XVE_UD_BUF_SIZE(priv->max_ib_mtu);
		priv->rx_wr.num_sge = 1;
	}
	priv->rx_wr.next = NULL;
	priv->rx_wr.sg_list = priv->rx_sge;

	return 0;

out_free_send_cq:
	ib_destroy_cq(priv->send_cq);

out_free_recv_cq:
	ib_destroy_cq(priv->recv_cq);

out_free_mr:
	ib_dereg_mr(priv->mr);
	xve_cm_dev_cleanup(dev);

out_free_pd:
	ib_dealloc_pd(priv->pd);
	return -ENODEV;
}

void xve_transport_dev_cleanup(struct net_device *dev)
{
	struct xve_dev_priv *priv = netdev_priv(dev);
	int ret = 0;

	if (priv->qp) {
		if (ib_destroy_qp(priv->qp))
			xve_warn(priv, "ib_qp_destroy failed\n");
		priv->qp = NULL;
		clear_bit(XVE_PKEY_ASSIGNED, &priv->flags);
	}
	ret = ib_destroy_cq(priv->send_cq);
	if (ret)
		xve_warn(priv, "%s ib_destroy_cq (sendq) failed ret=%d\n",
			 __func__, ret);

	ret = ib_destroy_cq(priv->recv_cq);
	if (ret)
		xve_warn(priv, "%s ib_destroy_cq failed ret=%d\n",
			 __func__, ret);

	xve_cm_dev_cleanup(dev);

	ret = ib_dereg_mr(priv->mr);
	if (ret)
		xve_warn(priv, "%s ib_dereg_mr failed ret=%d\n", __func__,
			 ret);

	ret = ib_dealloc_pd(priv->pd);
	if (ret)
		xve_warn(priv, "%s ib_dealloc_pd failed ret=%d\n",
			 __func__, ret);
}

void xve_event(struct ib_event_handler *handler, struct ib_event *record)
{
	struct xve_dev_priv *priv =
	    container_of(handler, struct xve_dev_priv, event_handler);

	if (record->element.port_num != priv->port)
		return;

	xve_debug(DEBUG_MCAST_INFO, priv, "Event %d on device %s port %d\n",
		  record->event, record->device->name,
		  record->element.port_num);

	switch (record->event) {
	case IB_EVENT_SM_CHANGE:
			priv->counters[XVE_SM_CHANGE_COUNTER]++;
			xve_queue_work(priv, XVE_WQ_START_FLUSHLIGHT);
			break;
	case IB_EVENT_CLIENT_REREGISTER:
			priv->counters[XVE_CLIENT_REREGISTER_COUNTER]++;
			set_bit(XVE_FLAG_DONT_DETACH_MCAST, &priv->flags);
			xve_queue_work(priv, XVE_WQ_START_FLUSHLIGHT);
			break;
	case IB_EVENT_PORT_ERR:
			priv->counters[XVE_EVENT_PORT_ERR_COUNTER]++;
			xve_queue_work(priv, XVE_WQ_START_FLUSHNORMAL);
			break;
	case IB_EVENT_PORT_ACTIVE:
			priv->counters[XVE_EVENT_PORT_ACTIVE_COUNTER]++;
			xve_queue_work(priv, XVE_WQ_START_FLUSHNORMAL);
			break;
	case IB_EVENT_LID_CHANGE:
			priv->counters[XVE_EVENT_LID_CHANGE_COUNTER]++;
			xve_queue_work(priv, XVE_WQ_START_FLUSHNORMAL);
			break;
	case IB_EVENT_PKEY_CHANGE:
			priv->counters[XVE_EVENT_PKEY_CHANGE_COUNTER]++;
			xve_queue_work(priv, XVE_WQ_START_FLUSHHEAVY);
			break;
	default:
			priv->counters[XVE_INVALID_EVENT_COUNTER]++;
			break;
	}
}
