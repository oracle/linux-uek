// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 BPHY RFOE/CPRI Ethernet Driver
 *
 * Copyright (C) 2020 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "otx2_rfoe.h"

static const char ethtool_stat_strings[][ETH_GSTRING_LEN] = {
	"oth_rx_packets",
	"ptp_rx_packets",
	"ecpri_rx_packets",
	"rx_bytes",
	"oth_rx_dropped",
	"ptp_rx_dropped",
	"ecpri_rx_dropped",
	"oth_tx_packets",
	"ptp_tx_packets",
	"ecpri_tx_packets",
	"tx_bytes",
	"oth_tx_dropped",
	"ptp_tx_dropped",
	"ecpri_tx_dropped",
};

static void otx2_rfoe_get_strings(struct net_device *netdev, u32 sset, u8 *data)
{
	switch (sset) {
	case ETH_SS_STATS:
		memcpy(data, *ethtool_stat_strings,
		       sizeof(ethtool_stat_strings));
		break;
	}
}

static int otx2_rfoe_get_sset_count(struct net_device *netdev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return ARRAY_SIZE(ethtool_stat_strings);
	default:
		return -EOPNOTSUPP;
	}
}

static void otx2_rfoe_get_ethtool_stats(struct net_device *netdev,
					struct ethtool_stats *stats,
					u64 *data)
{
	struct otx2_rfoe_ndev_priv *priv = netdev_priv(netdev);

	spin_lock(&priv->stats.lock);
	memcpy(data, &priv->stats,
	       ARRAY_SIZE(ethtool_stat_strings) * sizeof(u64));
	spin_unlock(&priv->stats.lock);
}

static void otx2_rfoe_get_drvinfo(struct net_device *netdev,
				  struct ethtool_drvinfo *p)
{
	struct otx2_rfoe_ndev_priv *priv = netdev_priv(netdev);

	snprintf(p->driver, sizeof(p->driver), "otx2_rfoe {rfoe%d lmac%d}",
		 priv->rfoe_num, priv->lmac_id);
	strlcpy(p->bus_info, "platform", sizeof(p->bus_info));
}

static int otx2_rfoe_get_ts_info(struct net_device *netdev,
				 struct ethtool_ts_info *info)
{
	info->so_timestamping = SOF_TIMESTAMPING_TX_SOFTWARE |
				SOF_TIMESTAMPING_RX_SOFTWARE |
				SOF_TIMESTAMPING_SOFTWARE |
				SOF_TIMESTAMPING_TX_HARDWARE |
				SOF_TIMESTAMPING_RX_HARDWARE |
				SOF_TIMESTAMPING_RAW_HARDWARE;

	info->phc_index = -1;

	info->tx_types = (1 << HWTSTAMP_TX_OFF) | (1 << HWTSTAMP_TX_ON);

	info->rx_filters = (1 << HWTSTAMP_FILTER_NONE) |
			   (1 << HWTSTAMP_FILTER_ALL);

	return 0;
}

static u32 otx2_rfoe_get_msglevel(struct net_device *netdev)
{
	struct otx2_rfoe_ndev_priv *priv = netdev_priv(netdev);

	return priv->msg_enable;
}

static void otx2_rfoe_set_msglevel(struct net_device *netdev, u32 level)
{
	struct otx2_rfoe_ndev_priv *priv = netdev_priv(netdev);

	priv->msg_enable = level;
}

static const struct ethtool_ops otx2_rfoe_ethtool_ops = {
	.get_drvinfo		= otx2_rfoe_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_ts_info		= otx2_rfoe_get_ts_info,
	.get_strings		= otx2_rfoe_get_strings,
	.get_sset_count		= otx2_rfoe_get_sset_count,
	.get_ethtool_stats	= otx2_rfoe_get_ethtool_stats,
	.get_msglevel		= otx2_rfoe_get_msglevel,
	.set_msglevel		= otx2_rfoe_set_msglevel,
};

void otx2_rfoe_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &otx2_rfoe_ethtool_ops;
}
