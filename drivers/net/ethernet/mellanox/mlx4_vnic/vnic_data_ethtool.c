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

#include <linux/kernel.h>
#include <linux/netdevice.h>

#include "vnic.h"
#include "vnic_data.h"

static struct ethtool_ops vnic_ethtool_ops;

static const char vnic_strings[][ETH_GSTRING_LEN] = {
	/* public statistics */
	"rx_packets", "tx_packets", "rx_bytes",
	"tx_bytes", "rx_errors", "tx_errors",
	"rx_dropped", "tx_dropped", "multicast",
	"collisions", "rx_length_errors", "rx_over_errors",
	"rx_crc_errors", "rx_frame_errors", "rx_fifo_errors",
	"rx_missed_errors", "tx_aborted_errors", "tx_carrier_errors",
	"tx_fifo_errors", "tx_heartbeat_errors", "tx_window_errors",
#define VNIC_PUB_STATS_LEN	21

	/* private statistics */
	"gro_held", "gro_merged", "gro_normal", "gro_drop",
	"lro_aggregated", "lro_flushed", "lro_no_desc",
	"tso_packets", "queue_stopped", "wake_queue",
	"tx_timeout", "rx_chksum_good", "rx_chksum_none",
	"tx_chksum_offload", "sig_ver_err", "vlan_err",
	"shared_packets", "runt_packets", "realloc_packets",
	"gw_tx_packets", "gw_tx_bytes",
#define VNIC_PORT_STATS_LEN	21

	/* packet statistics rx_prio_X (TODO) */
#define VNIC_PKT_STATS_LEN	0
};

#define VNIC_STATS_LEN (sizeof(vnic_strings) / ETH_GSTRING_LEN)

static void vnic_get_drvinfo(struct net_device *dev,
			     struct ethtool_drvinfo *drvinfo)
{
	struct vnic_login *login = vnic_netdev_priv(dev);

	*drvinfo = login->drvinfo;
}

static u32 vnic_get_msglevel(struct net_device *dev)
{
	return vnic_msglvl;
}

static void vnic_set_msglevel(struct net_device *dev, u32 mlevel)
{
	vnic_msglvl = mlevel;
}

static int vnic_get_coalesce(struct net_device *dev,
			     struct ethtool_coalesce *coal)
{
	struct vnic_login *login = vnic_netdev_priv(dev);

	vnic_dbg_ethtool(login->name, "get coalescing params for mtu:%d "
			 "rx_frames:%d rx_usecs:%d, "
			 "tx_frames:%d tx_usecs:%d, "
			 "adaptive_rx_coal:%d, "
			 "adaptive_tx_coal:%d\n",
			 login->dev->mtu,
			 login->rx_frames, login->rx_usecs,
			 login->tx_frames, login->tx_usecs,
			 login->adaptive_rx_coal, 0);

	coal->tx_coalesce_usecs = login->tx_usecs;
	coal->tx_max_coalesced_frames = login->tx_frames;
	coal->rx_coalesce_usecs = login->rx_usecs;
	coal->rx_max_coalesced_frames = login->rx_frames;

	coal->pkt_rate_low = login->pkt_rate_low;
	coal->rx_coalesce_usecs_low = login->rx_usecs_low;
	coal->pkt_rate_high = login->pkt_rate_high;
	coal->rx_coalesce_usecs_high = login->rx_usecs_high;
	coal->rate_sample_interval = login->sample_interval;
	coal->use_adaptive_rx_coalesce = login->adaptive_rx_coal;

	return 0;
}

static int vnic_set_coalesce(struct net_device *dev,
			     struct ethtool_coalesce *coal)
{
	struct vnic_login *login = vnic_netdev_priv(dev);

	login->rx_frames = (coal->rx_max_coalesced_frames ==
			    VNIC_AUTO_CONF) ?
	    VNIC_RX_COAL_TARGET /
	    login->dev->mtu + 1 : coal->rx_max_coalesced_frames;
	login->rx_usecs = (coal->rx_coalesce_usecs ==
			   VNIC_AUTO_CONF) ?
	    VNIC_RX_COAL_TIME : coal->rx_coalesce_usecs;
	login->tx_frames = coal->tx_max_coalesced_frames;
	login->tx_usecs = coal->tx_coalesce_usecs;

	/* Set adaptive coalescing params */
	login->pkt_rate_low = coal->pkt_rate_low;
	login->rx_usecs_low = coal->rx_coalesce_usecs_low;
	login->pkt_rate_high = coal->pkt_rate_high;
	login->rx_usecs_high = coal->rx_coalesce_usecs_high;
	login->sample_interval = coal->rate_sample_interval;
	login->adaptive_rx_coal = coal->use_adaptive_rx_coalesce;
	login->last_moder_time = VNIC_AUTO_CONF;

	if (login->adaptive_rx_coal)
		return 0;

	vnic_ib_set_moder(login,
			  login->rx_usecs, login->rx_frames,
			  login->tx_usecs, login->tx_frames);

	return 0;
}

static int vnic_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	cmd->autoneg = AUTONEG_DISABLE;
	cmd->supported = SUPPORTED_10000baseT_Full;
	cmd->advertising = SUPPORTED_10000baseT_Full;
	if (netif_carrier_ok(dev)) {
		cmd->speed = SPEED_10000;
		cmd->duplex = DUPLEX_FULL;
	} else {
		cmd->speed = -1;
		cmd->duplex = -1;
	}
	return 0;
}

static int vnic_set_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	if ((cmd->autoneg == AUTONEG_ENABLE) ||
	    (cmd->speed != SPEED_10000) || (cmd->duplex != DUPLEX_FULL))
		return -EINVAL;

	/* Nothing to change */
	return 0;
}

static void vnic_get_strings(struct net_device *dev,
			     uint32_t stringset, uint8_t *data)
{
	struct vnic_login *login = vnic_netdev_priv(dev);
	int index = 0, stats_off = 0, i;

	if (stringset != ETH_SS_STATS)
		return;

	/* Add main counters */
	for (i = 0; i < VNIC_PUB_STATS_LEN; i++)
		strcpy(data + (index++) * ETH_GSTRING_LEN,
		       vnic_strings[i + stats_off]);
	stats_off += VNIC_PUB_STATS_LEN;

	for (i = 0; i < VNIC_PORT_STATS_LEN; i++)
		strcpy(data + (index++) * ETH_GSTRING_LEN,
		       vnic_strings[i + stats_off]);
	stats_off += VNIC_PORT_STATS_LEN;

	for (i = 0; i < VNIC_PKT_STATS_LEN; i++)
		strcpy(data + (index++) * ETH_GSTRING_LEN,
		       vnic_strings[i + stats_off]);
	stats_off += VNIC_PKT_STATS_LEN;

	for (i = 0; i < login->tx_rings_num; i++) {
		sprintf(data + (index++) * ETH_GSTRING_LEN,
			"tx%d_packets", i);
		sprintf(data + (index++) * ETH_GSTRING_LEN,
			"tx%d_bytes", i);
	}
	for (i = 0; i < login->rx_rings_num; i++) {
		sprintf(data + (index++) * ETH_GSTRING_LEN,
			"rx%d_packets", i);
		sprintf(data + (index++) * ETH_GSTRING_LEN,
			"rx%d_bytes", i);
	}
}

static void vnic_get_ethtool_stats(struct net_device *dev,
				   struct ethtool_stats *stats, uint64_t *data)
{
	struct vnic_login *login = vnic_netdev_priv(dev);
	int index = 0, i;

	spin_lock_bh(&login->stats_lock);

	for (i = 0; i < VNIC_PUB_STATS_LEN; i++)
		data[index++] = ((unsigned long *) &login->stats)[i];
	for (i = 0; i < VNIC_PORT_STATS_LEN; i++)
		data[index++] = ((unsigned long *) &login->port_stats)[i];
	for (i = 0; i < VNIC_PKT_STATS_LEN; i++)
		data[index++] = 0;
	for (i = 0; i < login->tx_rings_num; i++) {
		data[index++] = login->tx_res[i].stats.tx_packets;
		data[index++] = login->tx_res[i].stats.tx_bytes;
	}
	for (i = 0; i < login->rx_rings_num; i++) {
		data[index++] = login->port->rx_ring[i]->stats.rx_packets;
		data[index++] = login->port->rx_ring[i]->stats.rx_bytes;
	}
	spin_unlock_bh(&login->stats_lock);
}

#ifndef _BP_ETHTOOL_NO_SSETC
static int vnic_get_sset_count(struct net_device *dev, int sset)
{
	struct vnic_login *login = vnic_netdev_priv(dev);

	switch (sset) {
	case ETH_SS_STATS:
		return VNIC_STATS_LEN + /* static stats + stats per ring */
		       (login->tx_rings_num + login->rx_rings_num) * 2;
	default:
		return -EOPNOTSUPP;
	}
}

#else
static int vnic_get_stats_count(struct net_device *dev)
{
	struct vnic_login *login = vnic_netdev_priv(dev);

	return VNIC_STATS_LEN +
	       (login->tx_rings_num + login->rx_rings_num) * 2;
}
#endif

static void vnic_get_wol(struct net_device *dev, struct ethtool_wolinfo *wol)
{
	wol->supported = wol->wolopts = 0;

	return;
}

void vnic_get_ringparam(struct net_device *dev, struct ethtool_ringparam *param)
{
	memset(param, 0, sizeof *param);
	param->rx_max_pending = VNIC_MAX_RX_SIZE;
	param->tx_max_pending = VNIC_MAX_TX_SIZE;
	param->rx_pending = vnic_rx_rings_len;
	param->tx_pending = vnic_tx_rings_len;
}

void vnic_set_ethtool_ops(struct net_device *dev)
{
	struct vnic_login *login = vnic_netdev_priv(dev);
	struct mlx4_ib_dev *mlx4_ibdev = login->port->dev->mdev;

	ASSERT(login);
	ASSERT(login->port->dev->ca);
	ASSERT(login->port->dev->ca->dma_device);

	SET_ETHTOOL_OPS(dev, &vnic_ethtool_ops);
	strncpy(login->drvinfo.driver, DRV_NAME, VNIC_ETHTOOL_LINE_MAX);
	strncpy(login->drvinfo.version, DRV_VER, VNIC_ETHTOOL_LINE_MAX);
	login->drvinfo.n_stats = 0;
	login->drvinfo.regdump_len = 0;
	login->drvinfo.eedump_len = 0;

	sprintf(login->drvinfo.bus_info, "%s [%s:%d]",
		pci_name(to_pci_dev(login->port->dev->ca->dma_device)),
		login->port->dev->ca->name, login->port->num);
	sprintf(login->drvinfo.fw_version, "%s [%.*s]",
		login->port->dev->fw_ver_str, MLX4_BOARD_ID_LEN,
		mlx4_ibdev->dev->board_id);
	vnic_dbg_ethtool(login->name, "bus %s, port %d, fw_ver %s\n",
			 login->drvinfo.bus_info, login->port->num,
			 login->drvinfo.fw_version);

	return;
}

static struct ethtool_ops vnic_ethtool_ops = {
	.get_link = ethtool_op_get_link,
	.get_drvinfo = vnic_get_drvinfo,
	.get_msglevel = vnic_get_msglevel,
	.set_msglevel = vnic_set_msglevel,
	.get_coalesce = vnic_get_coalesce,
	.set_coalesce = vnic_set_coalesce,
	.get_strings = vnic_get_strings,
	.get_ethtool_stats = vnic_get_ethtool_stats,
#ifndef _BP_ETHTOOL_NO_SSETC
	.get_sset_count = vnic_get_sset_count,
#else
	.get_stats_count = vnic_get_stats_count,
#endif
	.get_settings = vnic_get_settings,
	.set_settings = vnic_set_settings,
	.get_wol = vnic_get_wol,
	.get_ringparam = vnic_get_ringparam,
	.set_ringparam = NULL,
};

