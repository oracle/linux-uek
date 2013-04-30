/*
 * Copyright (c) 2007 Mellanox Technologies. All rights reserved.
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

#include <linux/kernel.h>
#include <linux/ethtool.h>
#include <linux/netdevice.h>

#include "ipoib.h"

static void ipoib_get_drvinfo(struct net_device *netdev,
			      struct ethtool_drvinfo *drvinfo)
{
	strncpy(drvinfo->driver, "ipoib", sizeof(drvinfo->driver) - 1);
}

static u32 ipoib_get_rx_csum(struct net_device *dev)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	return test_bit(IPOIB_FLAG_CSUM, &priv->flags) &&
		!test_bit(IPOIB_FLAG_ADMIN_CM, &priv->flags);
}

static int ipoib_set_tso(struct net_device *dev, u32 data)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	if (data) {
		if (!test_bit(IPOIB_FLAG_ADMIN_CM, &priv->flags) &&
		    (dev->features & NETIF_F_SG) &&
		    (priv->hca_caps & IB_DEVICE_UD_TSO)) {
			dev->features |= NETIF_F_TSO;
		} else {
			ipoib_warn(priv, "can't set TSO on\n");
			return -EOPNOTSUPP;
		}
	} else
		dev->features &= ~NETIF_F_TSO;

	return 0;
}

static int ipoib_get_coalesce(struct net_device *dev,
			      struct ethtool_coalesce *coal)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	coal->rx_coalesce_usecs = priv->ethtool.rx_coalesce_usecs;
	coal->rx_max_coalesced_frames = priv->ethtool.rx_max_coalesced_frames;
	coal->pkt_rate_low = priv->ethtool.pkt_rate_low;
	coal->rx_coalesce_usecs_low = priv->ethtool.rx_coalesce_usecs_low;
	coal->rx_coalesce_usecs_high = priv->ethtool.rx_coalesce_usecs_high;
	coal->pkt_rate_high = priv->ethtool.pkt_rate_high;
	coal->rate_sample_interval = priv->ethtool.rate_sample_interval;
	coal->use_adaptive_rx_coalesce = priv->ethtool.use_adaptive_rx_coalesce;
/*	coal->rx_coalesce_usecs = priv->ethtool.coalesce_usecs;
	coal->rx_max_coalesced_frames = priv->ethtool.max_coalesced_frames;
*/
	return 0;
}

enum ipoib_auto_moder_operation {
        NONE,
        MOVING_TO_ON,
        MOVING_TO_OFF
};

static int ipoib_set_coalesce(struct net_device *dev,
                              struct ethtool_coalesce *coal)
{
        struct ipoib_dev_priv *priv = netdev_priv(dev);
        int ret;
        enum ipoib_auto_moder_operation moder_operation = NONE;

        /*
         * These values are saved in the private data and returned
         * when ipoib_get_coalesce() is called
         */
        if (coal->rx_coalesce_usecs       > 0xffff ||
            coal->rx_max_coalesced_frames > 0xffff)
                return -EINVAL;
        priv->ethtool.rx_max_coalesced_frames =
                (coal->rx_max_coalesced_frames ==
                           IPOIB_AUTO_CONF) ?
                                IPOIB_RX_COAL_TARGET :
                                coal->rx_max_coalesced_frames;
        priv->ethtool.rx_coalesce_usecs = (coal->rx_coalesce_usecs ==
                          IPOIB_AUTO_CONF) ?
                                IPOIB_RX_COAL_TIME :
                                coal->rx_coalesce_usecs;

        ret = ib_modify_cq(priv->recv_cq, coal->rx_max_coalesced_frames,
                           coal->rx_coalesce_usecs);
        if (ret && ret != -ENOSYS) {
                ipoib_warn(priv, "failed modifying CQ (%d)\n", ret);
                return ret;
        }

        priv->ethtool.pkt_rate_low = coal->pkt_rate_low;
        priv->ethtool.rx_coalesce_usecs_low = coal->rx_coalesce_usecs_low;
        priv->ethtool.rx_coalesce_usecs_high = coal->rx_coalesce_usecs_high;
        priv->ethtool.pkt_rate_high = coal->pkt_rate_high;
        priv->ethtool.rate_sample_interval = coal->rate_sample_interval;

        if (priv->ethtool.use_adaptive_rx_coalesce &&
            !coal->use_adaptive_rx_coalesce) {
                /* switch from adaptive-mode to non-adaptive mode:
                cancell the adaptive moderation task. */
                clear_bit(IPOIB_FLAG_AUTO_MODER, &priv->flags);
                cancel_delayed_work(&priv->adaptive_moder_task);
                moder_operation = MOVING_TO_OFF;
        } else if ((!priv->ethtool.use_adaptive_rx_coalesce &&
                    coal->use_adaptive_rx_coalesce)) {
                /* switch from non-adaptive-mode to adaptive mode,
                 starts it now */
                set_bit(IPOIB_FLAG_AUTO_MODER, &priv->flags);
                moder_operation = MOVING_TO_ON;
		priv->ethtool.use_adaptive_rx_coalesce = 1;
                queue_delayed_work(ipoib_auto_moder_workqueue,
                                   &priv->adaptive_moder_task, 0);
        }

        if (MOVING_TO_OFF == moder_operation)
                flush_workqueue(ipoib_auto_moder_workqueue);
        else if (MOVING_TO_ON == moder_operation) {
                /* move to initial values */
                ret = ib_modify_cq(priv->recv_cq,
				   priv->ethtool.rx_max_coalesced_frames,
				   priv->ethtool.rx_coalesce_usecs);
                if (ret && ret != -ENOSYS) {
                        ipoib_warn(priv, "failed modifying CQ (%d)"
                                         "(when moving to auto-moderation)\n",
                                   ret);
                        return ret;
                }
        }
        priv->ethtool.use_adaptive_rx_coalesce = coal->use_adaptive_rx_coalesce;

        return 0;
}

static const char ipoib_stats_keys[][ETH_GSTRING_LEN] = {
	"LRO aggregated", "LRO flushed",
	"LRO avg aggr", "LRO no desc"
};

static void ipoib_get_strings(struct net_device *netdev, u32 stringset, u8 *data)
{
	switch (stringset) {
	case ETH_SS_STATS:
		memcpy(data, *ipoib_stats_keys,	sizeof(ipoib_stats_keys));
		break;
	}
}

static int ipoib_get_sset_count(struct net_device *dev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return ARRAY_SIZE(ipoib_stats_keys);
	default:
		return -EOPNOTSUPP;
	}
}

static void ipoib_get_ethtool_stats(struct net_device *dev,
				struct ethtool_stats *stats, uint64_t *data)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);
	int index = 0;

	/* Get LRO statistics */
	data[index++] = priv->lro.lro_mgr.stats.aggregated;
	data[index++] = priv->lro.lro_mgr.stats.flushed;
	if (priv->lro.lro_mgr.stats.flushed)
		data[index++] = priv->lro.lro_mgr.stats.aggregated /
				priv->lro.lro_mgr.stats.flushed;
	else
		data[index++] = 0;
	data[index++] = priv->lro.lro_mgr.stats.no_desc;
}

static void ipoib_get_ringparam(struct net_device *dev,
				  struct ethtool_ringparam *param)
{

	memset(param, 0, sizeof(*param));
	param->rx_max_pending = IPOIB_MAX_QUEUE_SIZE;
	param->tx_max_pending = IPOIB_MAX_QUEUE_SIZE;
	param->rx_pending = ipoib_recvq_size;
	param->tx_pending = ipoib_sendq_size;
}
int ipoib_set_flags(struct net_device *dev, u32 data)
{
	struct ipoib_dev_priv *priv = netdev_priv(dev);

	ethtool_op_set_flags(dev, data, ETH_FLAG_LRO);
	/*no support in LRO with 4k mtu.*/
	if (ipoib_ud_need_sg(priv->max_ib_mtu) && (data & NETIF_F_LRO)) {

		priv->dev->features  &= ~NETIF_F_LRO;
		return -EOPNOTSUPP;
	}

	return 0;
}

static const struct ethtool_ops ipoib_ethtool_ops = {
	.get_drvinfo		= ipoib_get_drvinfo,
	.get_rx_csum		= ipoib_get_rx_csum,
	.get_tso		= ethtool_op_get_tso,
	.set_tso		= ipoib_set_tso,
	.get_coalesce		= ipoib_get_coalesce,
	.set_coalesce		= ipoib_set_coalesce,
	.get_flags		= ethtool_op_get_flags,
	.set_flags		= ipoib_set_flags,
	.get_strings		= ipoib_get_strings,
	.get_sset_count		= ipoib_get_sset_count,
	.get_ethtool_stats	= ipoib_get_ethtool_stats,
	.get_ringparam 		= ipoib_get_ringparam,
};

void ipoib_set_ethtool_ops(struct net_device *dev)
{
	SET_ETHTOOL_OPS(dev, &ipoib_ethtool_ops);
}
