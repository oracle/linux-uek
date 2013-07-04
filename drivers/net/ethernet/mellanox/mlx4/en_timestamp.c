/*
 * Copyright (c) 2012 Mellanox Technologies. All rights reserved.
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
 *
 */

#include <linux/mlx4/device.h>

#include "mlx4_en.h"

#define CORE_CLOCK_MASK 0xffffffffffffULL

int mlx4_en_timestamp_config(struct net_device *dev, int tx_type, int rx_filter)
{
	struct mlx4_en_priv *priv = netdev_priv(dev);
	struct mlx4_en_dev *mdev = priv->mdev;
	int port_up = 0;
	int n_stats, err = 0;
	u64 *data = NULL;

	err = mlx4_en_pre_config(priv);
	if (err)
		return err;

	mutex_lock(&mdev->state_lock);
	if (priv->port_up) {
		port_up = 1;
		mlx4_en_stop_port(dev);
	}

	/* Cache port statistics */
	n_stats = mlx4_en_get_sset_count(dev, ETH_SS_STATS);
	if (n_stats > 0) {
		data = kmalloc(n_stats * sizeof(u64), GFP_KERNEL);
		if (data)
			mlx4_en_get_ethtool_stats(dev, NULL, data);
	}

	mlx4_en_free_resources(priv);

	en_err(priv, "Changing Time Stamp configuration\n");

	priv->hwtstamp_config.tx_type = tx_type;
	priv->hwtstamp_config.rx_filter = rx_filter;

	if (rx_filter != HWTSTAMP_FILTER_NONE)
		dev->features &= ~NETIF_F_HW_VLAN_RX;
	else
		dev->features |= NETIF_F_HW_VLAN_RX;

	if (tx_type != HWTSTAMP_TX_OFF)
		dev->features &= ~NETIF_F_HW_VLAN_TX;
	else
		dev->features |= NETIF_F_HW_VLAN_TX;

	err = mlx4_en_alloc_resources(priv);
	if (err) {
		en_err(priv, "Failed reallocating port resources\n");
		goto out;
	}

	/* Restore port statistics */
	if (n_stats > 0 && data)
		mlx4_en_restore_ethtool_stats(priv, data);

	if (port_up) {
		err = mlx4_en_start_port(dev);
		if (err)
			en_err(priv, "Failed starting port\n");
	}

out:
	kfree(data);
	mutex_unlock(&mdev->state_lock);
	return err;
}

/*
 * mlx4_en_read_clock - read raw cycle counter (to be used by time counter)
 */
cycle_t mlx4_en_read_clock(const struct cyclecounter *tc)
{
	struct mlx4_en_dev *mdev =
		container_of(tc, struct mlx4_en_dev, cycles);
	struct mlx4_dev *dev = mdev->dev;

	return mlx4_read_clock(dev) & CORE_CLOCK_MASK;
}

u64 mlx4_en_get_cqe_ts(struct mlx4_cqe *cqe)
{
	u64 hi, lo;
	struct mlx4_ts_cqe *ts_cqe = (struct mlx4_ts_cqe *)cqe;

	lo = (u64)be16_to_cpu(ts_cqe->timestamp_lo);
	hi = ((u64)be32_to_cpu(ts_cqe->timestamp_hi) + !lo) << 16;

	return hi | lo;
}

void mlx4_en_fill_hwtstamps(struct mlx4_en_dev *mdev,
			    struct skb_shared_hwtstamps *hwts,
			    u64 timestamp)
{
	u64 nsec;

	nsec = timecounter_cyc2time(&mdev->clock, timestamp);

	/*
	 * force a timecompare_update here (even if less than a second
	 * has passed) in order to prevent the case when ptpd or other
	 * software jumps the clock offset. othwerise there is a small
	 * window when the timestamp would be based on previous skew
	 * and invalid results would be pushed to the network stack.
	 */
	timecompare_update(&mdev->compare, 0);
	memset(hwts, 0, sizeof(struct skb_shared_hwtstamps));
	hwts->hwtstamp = ns_to_ktime(nsec);
	hwts->syststamp = timecompare_transform(&mdev->compare, nsec);
}

void mlx4_en_init_timestamp(struct mlx4_en_dev *mdev)
{
	struct mlx4_dev *dev = mdev->dev;
	u64 temp_mult;

	memset(&mdev->cycles, 0, sizeof(mdev->cycles));
	mdev->cycles.read = mlx4_en_read_clock;
	mdev->cycles.mask = CLOCKSOURCE_MASK(48);

	/*
	 * we have hca_core_clock in MHz, so to translate cycles to nsecs
	 * we need to divide cycles by freq and multiply by 1000;
	 * in order to get precise result we shift left the value,
	 * since we don't have floating point there;
	 * at the end shift result back
	 */
	temp_mult = div_u64(((1ull * 1000) << 29), dev->caps.hca_core_clock);
	mdev->cycles.mult = (u32)temp_mult;
	mdev->cycles.shift = 29;

	timecounter_init(&mdev->clock, &mdev->cycles,
			 ktime_to_ns(ktime_get_real()));

	memset(&mdev->compare, 0, sizeof(mdev->compare));
	mdev->compare.source = &mdev->clock;
	mdev->compare.target = ktime_get_real;
	mdev->compare.num_samples = 10;
	timecompare_update(&mdev->compare, 0);
}

