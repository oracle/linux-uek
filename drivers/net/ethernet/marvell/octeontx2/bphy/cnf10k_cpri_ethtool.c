// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 BPHY RFOE/CPRI Ethernet Driver
 *
 * Copyright (C) 2022 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/netdevice.h>
#include <linux/ethtool.h>
#include <linux/net_tstamp.h>

#include "cnf10k_cpri.h"

static const char ethtool_stat_strings[][ETH_GSTRING_LEN] = {
	"rx_frames",
	"rx_octets",
	"rx_err",
	"bad_crc",
	"oversize",
	"undersize",
	"rx_fifo_overrun",
	"rx_dropped",
	"malformed",
	"rx_bad_octets",
	"tx_frames",
	"tx_octets",
	"tx_dropped",
};

static void cnf10k_cpri_get_strings(struct net_device *netdev, u32 sset, u8 *data)
{
	switch (sset) {
	case ETH_SS_STATS:
		memcpy(data, *ethtool_stat_strings,
		       sizeof(ethtool_stat_strings));
		break;
	}
}

static int cnf10k_cpri_get_sset_count(struct net_device *netdev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return ARRAY_SIZE(ethtool_stat_strings);
	default:
		return -EOPNOTSUPP;
	}
}

static void cnf10k_cpri_get_ethtool_stats(struct net_device *netdev,
					  struct ethtool_stats *stats,
					  u64 *data)
{
	struct cnf10k_cpri_ndev_priv *priv = netdev_priv(netdev);

	cnf10k_cpri_update_stats(priv);

	spin_lock(&priv->stats.lock);
	memcpy(data, &priv->stats,
	       ARRAY_SIZE(ethtool_stat_strings) * sizeof(u64));
	spin_unlock(&priv->stats.lock);
}

static void cnf10k_cpri_get_drvinfo(struct net_device *netdev,
				    struct ethtool_drvinfo *p)
{
	struct cnf10k_cpri_ndev_priv *priv = netdev_priv(netdev);

	snprintf(p->driver, sizeof(p->driver), "otx2_cpri {cpri%d lmac%d}",
		 priv->cpri_num, priv->lmac_id);
	strlcpy(p->bus_info, "platform", sizeof(p->bus_info));
}

static u32 cnf10k_cpri_get_msglevel(struct net_device *netdev)
{
	struct cnf10k_cpri_ndev_priv *priv = netdev_priv(netdev);

	return priv->msg_enable;
}

static void cnf10k_cpri_set_msglevel(struct net_device *netdev, u32 level)
{
	struct cnf10k_cpri_ndev_priv *priv = netdev_priv(netdev);

	priv->msg_enable = level;
}

static const struct ethtool_ops cnf10k_cpri_ethtool_ops = {
	.get_drvinfo		= cnf10k_cpri_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_strings		= cnf10k_cpri_get_strings,
	.get_sset_count		= cnf10k_cpri_get_sset_count,
	.get_ethtool_stats	= cnf10k_cpri_get_ethtool_stats,
	.get_msglevel		= cnf10k_cpri_get_msglevel,
	.set_msglevel		= cnf10k_cpri_set_msglevel,
};

void cnf10k_cpri_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &cnf10k_cpri_ethtool_ops;
}
