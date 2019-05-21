/*
 * Copyright (c) 2013-2017, Mellanox Technologies. All rights reserved.
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

#ifndef __ICMD_H
#define __ICMD_H

enum {
	ICMD_OP_QUERY_CAPABILITIES	= 0x8400,
	ICMD_OP_ACCESS_REGISTER		= 0x9001,
};

enum {
	MLX5_ACCEES_REG_METHOD_QUERY	= 1,
	MLX5_ACCESS_REG_METHOD_WR	= 2,
};

struct icmd_acc_reg_in {
	u16	reg_id;
	int	method;
	u16	dw_len;
	u32	data[];
};

struct icmd_acc_reg_out {
	u16	dw_len;
	u32	data[];
};

int mlx5_icmd_init(struct mlx5_core_dev *dev);
void mlx5_icmd_cleanup(struct mlx5_core_dev *dev);
int mlx5_icmd_exec(struct mlx5_icmd *icmd, u16 opcode, void *inbox,
		   int in_dw_sz, void *outbox, int out_dw_sz);
int mlx5_core_icmd_query_cap(struct mlx5_core_dev *dev, u16 cap_group, u64 *out);
int mlx5_core_icmd_access_reg(struct mlx5_core_dev *dev,
			      struct icmd_acc_reg_in *in,
			      struct icmd_acc_reg_out *out);

#endif /* __ICMD_H */
