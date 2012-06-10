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
 */

#include "mlx4_en.h"
#include <linux/debugfs.h>
#include <linux/slab.h>

#define MAX_DIR_NAME 7

static struct dentry *mlx4_en_root;
void mlx4_en_create_debug_files(struct mlx4_en_priv *priv)
{
	int i;
	char name_final[MAX_DIR_NAME];
	struct dentry *queue_root;
	struct dentry *rx_root;
	struct dentry *tx_root;
	struct dentry *rx_ring_root;
	struct dentry *tx_ring_root;

	priv->dev_root = NULL;
	if (!mlx4_en_root)
		return;
	priv->dev_root = debugfs_create_dir(priv->dev->name, mlx4_en_root);
	if (!priv->dev_root)
		goto error;
	queue_root = debugfs_create_dir("queues", priv->dev_root);
	if (!queue_root)
		goto error;
	rx_root = debugfs_create_dir("rx", queue_root);
	if (!rx_root)
		goto error;
	tx_root = debugfs_create_dir("tx", queue_root);
	if (!tx_root)
		goto error;
	if (!debugfs_create_x32("indir_qp", 0444,
				rx_root, (u32 *) &priv->rss_map.indir_qp.qpn))
		goto error;
	if (!debugfs_create_x32("qpn_base_rx", 0444,
				rx_root, (u32 *) &priv->rss_map.base_qpn))
		goto error;

	for (i = 0; i < priv->rx_ring_num; i++) {
		sprintf(name_final, "rx-%d", i);
		rx_ring_root = debugfs_create_dir(name_final, rx_root);
		if (!rx_ring_root)
			goto error;
		if (!debugfs_create_u16("cqn_rx", 0444,
					rx_ring_root, &priv->rx_ring[i]->cqn))
			goto error;
		if (!debugfs_create_x32("qpn_rx", 0444,
					rx_ring_root,
					(u32 *) &priv->rx_ring[i]->qpn))
			goto error;
		if (!debugfs_create_u32("eq_rx", 0444,
					rx_ring_root,
					(u32 *) &priv->rx_cq[i]->mcq.eqn))
			goto error;
		if (!debugfs_create_u16("irq_rx", 0444,
				       rx_ring_root, &priv->rx_cq[i]->mcq.irq))
			goto error;
	}


	for (i = 0; i < priv->tx_ring_num; i++) {
		sprintf(name_final, "tx-%d", i);
		tx_ring_root = debugfs_create_dir(name_final, tx_root);
		if (!tx_ring_root)
			goto error;
		if (!debugfs_create_u16("cqn_tx", 0444,
					tx_ring_root, &priv->tx_ring[i]->cqn))
			goto error;
		if (!debugfs_create_x32("qpn_tx", 0444,
					tx_ring_root,
					(u32 *) &priv->tx_ring[i]->qpn))
			goto error;
		if (!debugfs_create_u32("eq_tx", 0444,
					tx_ring_root,
					(u32 *) &priv->tx_cq[i]->mcq.eqn))
			goto error;
		if (!debugfs_create_u16("irq_tx", 0444,
				       tx_ring_root, &priv->tx_cq[i]->mcq.irq))
			goto error;
	}

	return;

error:
	mlx4_warn(priv->mdev, "Fail to create debugfs for %s\n",
		  priv->dev->name);
	if (priv->dev_root)
		debugfs_remove_recursive(priv->dev_root);
	return;
}

void mlx4_en_delete_debug_files(struct mlx4_en_priv *priv)
{
	if (priv->dev_root)
		debugfs_remove_recursive(priv->dev_root);
}

int mlx4_en_register_debugfs(void)
{
	mlx4_en_root = debugfs_create_dir("mlx4_en", NULL);
	return mlx4_en_root ? 0 : -ENOMEM;
}

void mlx4_en_unregister_debugfs(void)
{
	if (mlx4_en_root)
		debugfs_remove_recursive(mlx4_en_root);
}
