// SPDX-License-Identifier: GPL-2.0
/* Marvell CNF10K BPHY RFOE Netdev Driver
 *
 * Copyright (C) 2021 Marvell.
 */

#include "cnf10k_rfoe.h"
#include "cnf10k_bphy_hw.h"

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
	"ptp_tx_hwtstamp_failures",
	"EthIfInFrames",
	"EthIfInOctets",
	"EthIfOutFrames",
	"EthIfOutOctets",
	"EthIfInUnknownVlan",
};

static void cnf10k_rfoe_get_strings(struct net_device *netdev, u32 sset,
				    u8 *data)
{
	switch (sset) {
	case ETH_SS_STATS:
		memcpy(data, *ethtool_stat_strings,
		       sizeof(ethtool_stat_strings));
		break;
	}
}

static int cnf10k_rfoe_get_sset_count(struct net_device *netdev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return ARRAY_SIZE(ethtool_stat_strings);
	default:
		return -EOPNOTSUPP;
	}
}

static void cnf10k_rfoe_update_lmac_stats(struct cnf10k_rfoe_ndev_priv *priv)
{
	struct otx2_rfoe_stats *stats = &priv->stats;

	stats->EthIfInFrames = readq(priv->rfoe_reg_base +
				     CNF10K_RFOEX_RX_RPM_PKT_STAT(priv->rfoe_num,
								  priv->lmac_id));
	stats->EthIfInOctets = readq(priv->rfoe_reg_base +
				     CNF10K_RFOEX_RX_RPM_OCTS_STAT(priv->rfoe_num,
								   priv->lmac_id));
	stats->EthIfOutFrames = readq(priv->rfoe_reg_base +
				      CNF10K_RFOEX_TX_PKT_STAT(priv->rfoe_num,
							       priv->lmac_id));
	stats->EthIfOutOctets = readq(priv->rfoe_reg_base +
				      CNF10K_RFOEX_TX_OCTS_STAT(priv->rfoe_num,
								priv->lmac_id));
	stats->EthIfInUnknownVlan =
				readq(priv->rfoe_reg_base +
				      CNF10K_RFOEX_RX_VLAN_DROP_STAT(priv->rfoe_num,
								     priv->lmac_id));
}

static void cnf10k_rfoe_get_ethtool_stats(struct net_device *netdev,
					  struct ethtool_stats *stats,
					  u64 *data)
{
	struct cnf10k_rfoe_ndev_priv *priv = netdev_priv(netdev);

	cnf10k_rfoe_update_lmac_stats(priv);
	spin_lock(&priv->stats.lock);
	memcpy(data, &priv->stats,
	       ARRAY_SIZE(ethtool_stat_strings) * sizeof(u64));
	spin_unlock(&priv->stats.lock);
}

static void cnf10k_rfoe_get_drvinfo(struct net_device *netdev,
				    struct ethtool_drvinfo *p)
{
	struct cnf10k_rfoe_ndev_priv *priv = netdev_priv(netdev);

	snprintf(p->driver, sizeof(p->driver), "cnf10k_rfoe {rfoe%d lmac%d}",
		 priv->rfoe_num, priv->lmac_id);
	strlcpy(p->bus_info, "platform", sizeof(p->bus_info));
}

static int cnf10k_rfoe_get_ts_info(struct net_device *netdev,
				   struct ethtool_ts_info *info)
{
	struct cnf10k_rfoe_ndev_priv *priv = netdev_priv(netdev);

	info->so_timestamping = SOF_TIMESTAMPING_TX_SOFTWARE |
				SOF_TIMESTAMPING_RX_SOFTWARE |
				SOF_TIMESTAMPING_SOFTWARE |
				SOF_TIMESTAMPING_TX_HARDWARE |
				SOF_TIMESTAMPING_RX_HARDWARE |
				SOF_TIMESTAMPING_RAW_HARDWARE;

	info->phc_index =  ptp_clock_index(priv->ptp_clock);

	info->tx_types = BIT(HWTSTAMP_TX_OFF) | BIT(HWTSTAMP_TX_ON) |
			 BIT(HWTSTAMP_TX_ONESTEP_SYNC);

	info->rx_filters = BIT(HWTSTAMP_FILTER_NONE) |
			   BIT(HWTSTAMP_FILTER_ALL);

	return 0;
}

static u32 cnf10k_rfoe_get_msglevel(struct net_device *netdev)
{
	struct cnf10k_rfoe_ndev_priv *priv = netdev_priv(netdev);

	return priv->msg_enable;
}

static void cnf10k_rfoe_set_msglevel(struct net_device *netdev, u32 level)
{
	struct cnf10k_rfoe_ndev_priv *priv = netdev_priv(netdev);

	priv->msg_enable = level;
}

static const struct ethtool_ops cnf10k_rfoe_ethtool_ops = {
	.get_drvinfo		= cnf10k_rfoe_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_ts_info		= cnf10k_rfoe_get_ts_info,
	.get_strings		= cnf10k_rfoe_get_strings,
	.get_sset_count		= cnf10k_rfoe_get_sset_count,
	.get_ethtool_stats	= cnf10k_rfoe_get_ethtool_stats,
	.get_msglevel		= cnf10k_rfoe_get_msglevel,
	.set_msglevel		= cnf10k_rfoe_set_msglevel,
};

void cnf10k_rfoe_set_ethtool_ops(struct net_device *netdev)
{
	netdev->ethtool_ops = &cnf10k_rfoe_ethtool_ops;
}
