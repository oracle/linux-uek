/*
 * Copyright (c) 2016, Mellanox Technologies. All rights reserved.
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

#include <linux/mlx5/driver.h>

int mlx5_core_set_dc_cnak_trace(struct mlx5_core_dev *dev, int enable_val,
				u64 addr)
{
	u32 in[MLX5_ST_SZ_DW(set_dc_cnak_trace_in)] = {0};
	u32 out[MLX5_ST_SZ_DW(set_dc_cnak_trace_out)] = {0};
	__be64 be_addr;
	void *pas;

	MLX5_SET(set_dc_cnak_trace_in, in, opcode,
		 MLX5_CMD_OP_SET_DC_CNAK_TRACE);
	MLX5_SET(set_dc_cnak_trace_in, in, enable, enable_val);
	pas = MLX5_ADDR_OF(set_dc_cnak_trace_in, in, pas);
	be_addr = cpu_to_be64(addr);
	memcpy(MLX5_ADDR_OF(cmd_pas, pas, pa_h), &be_addr, sizeof(be_addr));

	return mlx5_cmd_exec(dev, &in, sizeof(in), &out, sizeof(out));
}
EXPORT_SYMBOL_GPL(mlx5_core_set_dc_cnak_trace);
