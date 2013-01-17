/*
 * Copyright (c) 2010 Mellanox Technologies. All rights reserved.
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
 
#include <linux/mlx4/device.h>
#include <linux/mlx4/cmd.h>
#include "mlx4.h"

static void invalidate_p2v_table(int len, u8 inval, u8 *table)
{
	int i;

	for (i = 0; i < len; ++i)
		table[i] = inval;
}


void mlx4_sync_pkey_table(struct mlx4_dev *dev, int slave, int port, int i, int val)
{
	struct mlx4_priv *priv = container_of(dev, struct mlx4_priv, dev);

	if (!dev->caps.sqp_demux)
		return;

	priv->virt2phys_pkey[slave][port - 1][i] = val;
}
EXPORT_SYMBOL(mlx4_sync_pkey_table);

int mlx4_PKEY_TABLE_wrapper(struct mlx4_dev *dev, int slave,
			    struct mlx4_vhcr *vhcr,
			    struct mlx4_cmd_mailbox *inbox,
			    struct mlx4_cmd_mailbox *outbox,
			    struct mlx4_cmd_info *cmd)
{
	u8 *p2v = outbox->buf;
	u8 port = vhcr->in_modifier;
	u8 virt, phys;
	struct mlx4_priv *priv = container_of(dev, struct mlx4_priv, dev);

	mlx4_dbg(dev, "got update request for slave %d, port %d\n", slave, port);
	invalidate_p2v_table(dev->caps.pkey_table_len[port],
			     dev->caps.pkey_table_max_len[port] - 1,
			     p2v);

	for (virt = 0; virt < dev->caps.pkey_table_len[port]; ++virt) {
		phys = priv->virt2phys_pkey[slave][port - 1][virt];
		p2v[phys] = virt;
		mlx4_dbg(dev, "phys %d = virt %d\n", phys, virt);
	}

	return 0;
}

