/*
 * Copyright (c) 2012, Mellanox Technologies inc.  All rights reserved.
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

#ifndef __MLX5_CORE_H__
#define __MLX5_CORE_H__

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>

extern int mlx5_core_debug_mask;

#define mlx5_core_dbg(dev, format, arg...)				       \
do {									       \
	if (debug_mask & mlx5_core_debug_mask)				       \
		pr_debug("%s:%s:%d:(pid %d): " format, (dev)->priv.name,       \
			 __func__, __LINE__, current->pid, ##arg);	       \
} while (0)

#define mlx5_core_dbg_mask(dev, mask, format, arg...)			       \
do {									       \
	if ((mask) & mlx5_core_debug_mask)				       \
		pr_debug("%s:%s:%d:(pid %d): " format, (dev)->priv.name,       \
			 __func__, __LINE__, current->pid, ##arg);	       \
} while (0)

#define mlx5_core_err(dev, format, arg...) \
pr_err("%s:%s:%d:(pid %d): " format, (dev)->priv.name, __func__, __LINE__,     \
	current->pid, ##arg)

#define mlx5_core_warn(dev, format, arg...) \
pr_warn("%s:%s:%d:(pid %d): " format, (dev)->priv.name, __func__, __LINE__,    \
	current->pid, ##arg)

#define MLX5_MOD_DBG_MASK(mod_id)\
static const u32 debug_mask = 1 << (mod_id)

enum {
	MLX5_MOD_MAIN,
	MLX5_MOD_CMDIF,
	MLX5_MOD_EQ,
	MLX5_MOD_QP,
	MLX5_MOD_PGALLOC,
	MLX5_MOD_FW,
	MLX5_MOD_UAR,
	MLX5_MOD_ALLOC,
	MLX5_MOD_DEBUG,
	MLX5_MOD_HEALTH,
	MLX5_MOD_MAD,
	MLX5_MOD_MCG,
	MLX5_MOD_MR,
	MLX5_MOD_PD,
	MLX5_MOD_PORT,
	MLX5_MOD_SRQ,
	MLX5_MOD_CQ,
	MLX5_MOD_CMD_DATA, /* print command payload only */
	MLX5_CMD_DATA_TIME,
};


int mlx5_cmd_query_hca_cap(struct mlx5_core_dev *dev,
			   struct mlx5_caps *caps);
int mlx5_cmd_query_adapter(struct mlx5_core_dev *dev);
int mlx5_cmd_init_hca(struct mlx5_core_dev *dev);
int mlx5_cmd_teardown_hca(struct mlx5_core_dev *dev);

#endif /* __MLX5_CORE_H__ */
