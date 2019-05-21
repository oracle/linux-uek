/*
 * Copyright (c) 2017, Mellanox Technologies. All rights reserved.
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

#ifdef CONFIG_CXL_LIB
#include <linux/mlx5/device.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/mlx5_ifc.h>
#include <misc/cxllib.h>
#include <linux/mlx5/capi.h>
#include "mlx5_core.h"

int mlx5_core_create_pec(struct mlx5_core_dev *dev,
			 struct cxllib_pe_attributes *attr, u32 *pasid)
{
	u8 in[MLX5_ST_SZ_BYTES(create_capi_pec_in)] = {0};
	u8 out[MLX5_ST_SZ_BYTES(create_capi_pec_out)] = {0};
	void *ctx = MLX5_ADDR_OF(create_capi_pec_in, in, capi_pec_context);
	int err;

	MLX5_SET(create_capi_pec_in, in, opcode, MLX5_CMD_OP_CREATE_CAPI_PEC);
	MLX5_SET64(capi_pec_context, ctx, state_register, attr->sr);
	MLX5_SET(capi_pec_context, ctx, thread_id, attr->tid);
	MLX5_SET(capi_pec_context, ctx, process_id, attr->pid);
	MLX5_SET(capi_pec_context, ctx, local_partition_id, attr->lpid);

	err = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
	if (!err)
		*pasid = MLX5_GET(create_capi_pec_out, out, pasid);

	return err;
}
EXPORT_SYMBOL(mlx5_core_create_pec);

int mlx5_core_destroy_pec(struct mlx5_core_dev *dev, u32 pasid)
{
	u8 in[MLX5_ST_SZ_BYTES(destroy_capi_pec_in)] = {0};
	u8 out[MLX5_ST_SZ_BYTES(destroy_capi_pec_out)] = {0};

	MLX5_SET(destroy_capi_pec_in, in, opcode, MLX5_CMD_OP_DESTROY_CAPI_PEC);
	MLX5_SET(destroy_capi_pec_in, in, pasid, pasid);
	return mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
}
EXPORT_SYMBOL(mlx5_core_destroy_pec);
#endif
