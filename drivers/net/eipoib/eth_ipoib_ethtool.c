/*
 * Copyright (c) 2012 Mellanox Technologies. All rights reserved
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * openfabric.org BSD license below:
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

#include "eth_ipoib.h"

static void parent_ethtool_get_drvinfo(struct net_device *parent_dev,
				       struct ethtool_drvinfo *drvinfo)
{
	struct parent *parent = netdev_priv(parent_dev);

	strncpy(drvinfo->driver, DRV_NAME, 32);

	strncpy(drvinfo->version, DRV_VERSION, 32);

	strncpy(drvinfo->bus_info, parent->ipoib_main_interface,
		ETHTOOL_BUSINFO_LEN);

	/* indicates ABI version */
	snprintf(drvinfo->fw_version, 32, "%d", EIPOIB_ABI_VER);
}

static const char parent_strings[][ETH_GSTRING_LEN] = {
	/* private statistics */
	"tx_parent_dropped",
	"tx_vif_miss",
	"tx_neigh_miss",
	"tx_vlan",
	"tx_shared",
	"tx_proto_errors",
	"tx_skb_errors",
	"tx_slave_err",

	"rx_parent_dropped",
	"rx_vif_miss",
	"rx_neigh_miss",
	"rx_vlan",
	"rx_shared",
	"rx_proto_errors",
	"rx_skb_errors",
	"rx_slave_err",
};

#define PORT_STATS_LEN (sizeof(parent_strings) / ETH_GSTRING_LEN)

static void parent_get_strings(struct net_device *parent_dev,
			       uint32_t stringset, uint8_t *data)
{
	if (stringset != ETH_SS_STATS)
		return;
	memcpy(data, parent_strings, sizeof(parent_strings));
}

static void parent_get_ethtool_stats(struct net_device *parent_dev,
				     struct ethtool_stats *stats,
				     uint64_t *data)
{
	struct parent *parent = netdev_priv(parent_dev);

	read_lock_bh(&parent->lock);
	memcpy(data, &parent->port_stats, sizeof(parent->port_stats));
	read_unlock_bh(&parent->lock);
}

static int parent_get_sset_count(struct net_device *parent_dev, int sset)
{
	switch (sset) {
	case ETH_SS_STATS:
		return PORT_STATS_LEN;
	default:
		return -EOPNOTSUPP;
	}
}

static const struct ethtool_ops parent_ethtool_ops = {
	.get_drvinfo		= parent_ethtool_get_drvinfo,
	.get_strings		= parent_get_strings,
	.get_ethtool_stats	= parent_get_ethtool_stats,
	.get_sset_count		= parent_get_sset_count,
	.get_link		= ethtool_op_get_link,
};

void parent_set_ethtool_ops(struct net_device *dev)
{
	SET_ETHTOOL_OPS(dev, &parent_ethtool_ops);
}
