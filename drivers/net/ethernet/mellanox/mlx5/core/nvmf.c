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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/nvmf.h>
#include <linux/mlx5/cmd.h>
#include "mlx5_core.h"

static int get_pas_size(struct mlx5_be_ctrl_attr  *in)
{
	/*
	 * Currently we support only contig sq/cq aligned to 64B.
	 * In the future we might add number sq/cq physical addresses
	 * and set the size accordingly
	 */
	return 2 * MLX5_PAS_ALIGN;
}

static inline void set_nvmf_pas(struct mlx5_be_ctrl_attr *in,
				void *start,
				int align)
{
	dma_addr_t dma_addr_be;

	/* set cq PAS */
	dma_addr_be = cpu_to_be64(in->cq_pas);
	memcpy(start, &dma_addr_be, sizeof(u64));

	/* set sq PAS */
	dma_addr_be = cpu_to_be64(in->sq_pas);
	memcpy(start + align, &dma_addr_be, sizeof(u64));
}

int mlx5_core_create_nvmf_backend_ctrl(struct mlx5_core_dev *dev,
				       struct mlx5_core_srq *srq,
				       struct mlx5_core_nvmf_be_ctrl *ctrl,
				       struct mlx5_be_ctrl_attr *attr_in)
{
	u32 out[MLX5_ST_SZ_DW(create_nvmf_be_ctrl_out)] = {0};
	void *in;
	void *pas_addr;
	int pas_size;
	int inlen;
	int err;

	pas_size  = get_pas_size(attr_in);
	inlen	  = MLX5_ST_SZ_BYTES(create_nvmf_be_ctrl_in) + pas_size;
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	pas_addr = MLX5_ADDR_OF(create_nvmf_be_ctrl_in, in,
				nvmf_be_ctrl_entry.pas);
	set_nvmf_pas(attr_in, pas_addr, MLX5_PAS_ALIGN);

	MLX5_SET(create_nvmf_be_ctrl_in, in,
		 opcode,
		 MLX5_CMD_OP_CREATE_NVMF_BACKEND_CTRL);
	MLX5_SET(create_nvmf_be_ctrl_in, in,
		 xrqn,
		 srq->srqn);
	MLX5_SET(create_nvmf_be_ctrl_in, in,
		 nvmf_be_ctrl_entry.cq_page_offset,
		 attr_in->cq_page_offset);
	MLX5_SET(create_nvmf_be_ctrl_in, in,
		 nvmf_be_ctrl_entry.sq_page_offset,
		 attr_in->sq_page_offset);
	MLX5_SET(create_nvmf_be_ctrl_in, in,
		 nvmf_be_ctrl_entry.cq_log_page_size,
		 attr_in->cq_log_page_size);
	MLX5_SET(create_nvmf_be_ctrl_in, in,
		 nvmf_be_ctrl_entry.sq_log_page_size,
		 attr_in->sq_log_page_size);
	MLX5_SET(create_nvmf_be_ctrl_in, in,
		 nvmf_be_ctrl_entry.initial_cqh_db_value,
		 attr_in->initial_cqh_db_value);
	MLX5_SET(create_nvmf_be_ctrl_in, in,
		 nvmf_be_ctrl_entry.initial_sqt_db_value,
		 attr_in->initial_sqt_db_value);
	MLX5_SET(create_nvmf_be_ctrl_in, in,
		 nvmf_be_ctrl_entry.log_cmd_timeout_us,
		 attr_in->log_cmd_timeout_us);
	MLX5_SET64(create_nvmf_be_ctrl_in, in,
		   nvmf_be_ctrl_entry.cqh_dbr_addr,
		   attr_in->cqh_dbr_addr);
	MLX5_SET64(create_nvmf_be_ctrl_in, in,
		   nvmf_be_ctrl_entry.sqt_dbr_addr,
		   attr_in->sqt_dbr_addr);

	err = mlx5_cmd_exec(dev, in, inlen, out, sizeof(out));
	kvfree(in);
	if (err)
		return err;

	ctrl->id = MLX5_GET(create_nvmf_be_ctrl_out, out,
			    backend_controller_id);
	spin_lock(&srq->lock);
	list_add_tail(&ctrl->entry, &srq->ctrl_list);
	spin_unlock(&srq->lock);

	spin_lock_init(&ctrl->lock);
	INIT_LIST_HEAD(&ctrl->ns_list);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_core_create_nvmf_backend_ctrl);

int mlx5_core_destroy_nvmf_backend_ctrl(struct mlx5_core_dev *dev,
					struct mlx5_core_srq *srq,
					struct mlx5_core_nvmf_be_ctrl *ctrl)
{
	u32 in[MLX5_ST_SZ_DW(destroy_nvmf_be_ctrl_in)]   = {0};
	u32 out[MLX5_ST_SZ_DW(destroy_nvmf_be_ctrl_out)] = {0};

	spin_lock(&srq->lock);
	list_del(&ctrl->entry);
	spin_unlock(&srq->lock);

	MLX5_SET(destroy_nvmf_be_ctrl_in, in, opcode,
		 MLX5_CMD_OP_DESTROY_NVMF_BACKEND_CTRL);
	MLX5_SET(destroy_nvmf_be_ctrl_in, in, xrqn, srq->srqn);
	MLX5_SET(destroy_nvmf_be_ctrl_in, in, backend_controller_id, ctrl->id);

	return mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
}
EXPORT_SYMBOL_GPL(mlx5_core_destroy_nvmf_backend_ctrl);

int mlx5_core_attach_nvmf_ns(struct mlx5_core_dev *dev,
			     struct mlx5_core_srq *srq,
			     struct mlx5_core_nvmf_be_ctrl *ctrl,
			     struct mlx5_core_nvmf_ns *ns,
			     struct mlx5_ns_attr *attr_in)

{
	u32 in[MLX5_ST_SZ_DW(attach_nvmf_namespace_in)]   = {0};
	u32 out[MLX5_ST_SZ_DW(attach_nvmf_namespace_out)] = {0};
	int err;

	MLX5_SET(attach_nvmf_namespace_in, in,
		 opcode,
		 MLX5_CMD_OP_ATTACH_NVMF_NAMESPACE);
	MLX5_SET(attach_nvmf_namespace_in, in,
		 xrqn,
		 srq->srqn);
	MLX5_SET(attach_nvmf_namespace_in, in,
		 frontend_namespace,
		 attr_in->frontend_namespace);
	MLX5_SET(attach_nvmf_namespace_in, in,
		 backend_namespace,
		 attr_in->backend_namespace);
	MLX5_SET(attach_nvmf_namespace_in, in,
		 lba_data_size,
		 attr_in->lba_data_size);
	MLX5_SET(attach_nvmf_namespace_in, in,
		 backend_controller_id,
		 attr_in->backend_ctrl_id);

	err = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
	if (err)
		return err;

	ns->frontend_nsid = attr_in->frontend_namespace;
	ns->backend_nsid = attr_in->backend_namespace;

	spin_lock(&ctrl->lock);
	list_add_tail(&ns->entry, &ctrl->ns_list);
	spin_unlock(&ctrl->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_core_attach_nvmf_ns);

int mlx5_core_detach_nvmf_ns(struct mlx5_core_dev *dev,
			     struct mlx5_core_srq *srq,
			     struct mlx5_core_nvmf_be_ctrl *ctrl,
			     struct mlx5_core_nvmf_ns *ns)
{
	u32 in[MLX5_ST_SZ_DW(detach_nvmf_namespace_in)]   = {0};
	u32 out[MLX5_ST_SZ_DW(detach_nvmf_namespace_out)] = {0};
	int err;

	MLX5_SET(detach_nvmf_namespace_in, in,
		 opcode,
		 MLX5_CMD_OP_DETACH_NVMF_NAMESPACE);
	MLX5_SET(detach_nvmf_namespace_in, in,
		 xrqn,
		 srq->srqn);
	MLX5_SET(detach_nvmf_namespace_in, in,
		 frontend_namespace,
		 ns->frontend_nsid);

	err = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
	if (err)
		return err;

	spin_lock(&ctrl->lock);
	list_del(&ns->entry);
	spin_unlock(&ctrl->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_core_detach_nvmf_ns);

int mlx5_core_query_nvmf_ns(struct mlx5_core_dev *dev,
			    struct mlx5_core_srq *srq,
			    struct mlx5_core_nvmf_ns *ns)
{
	u32 in[MLX5_ST_SZ_DW(query_nvmf_namespace_in)]   = {0};
	u32 out[MLX5_ST_SZ_DW(query_nvmf_namespace_out)] = {0};
	int err;

	MLX5_SET(query_nvmf_namespace_in, in,
		 opcode,
		 MLX5_CMD_OP_QUERY_NVMF_NAMESPACE_CONTEXT);
	MLX5_SET(query_nvmf_namespace_in, in,
		 xrqn,
		 srq->srqn);
	MLX5_SET(query_nvmf_namespace_in, in,
		 frontend_namespace,
		 ns->frontend_nsid);

	err = mlx5_cmd_exec(dev, in, sizeof(in), out, sizeof(out));
	if (err)
		return err;

	ns->counters.num_read_cmd = MLX5_GET(query_nvmf_namespace_out, out,
					     ns_ctx.num_read_cmd_low);
	ns->counters.num_read_blocks = MLX5_GET(query_nvmf_namespace_out, out,
						ns_ctx.num_read_blocks_low);
	ns->counters.num_write_cmd = MLX5_GET(query_nvmf_namespace_out, out,
					      ns_ctx.num_write_cmd_low);
	ns->counters.num_write_blocks = MLX5_GET(query_nvmf_namespace_out, out,
						 ns_ctx.num_write_blocks_low);
	ns->counters.num_write_inline_cmd = MLX5_GET(query_nvmf_namespace_out, out,
						     ns_ctx.num_write_inline_cmd_low);
	ns->counters.num_flush_cmd = MLX5_GET(query_nvmf_namespace_out, out,
					      ns_ctx.num_flush_cmd_low);
	ns->counters.num_error_cmd = MLX5_GET(query_nvmf_namespace_out, out,
					      ns_ctx.num_error_cmd_low);
	ns->counters.num_backend_error_cmd = MLX5_GET(query_nvmf_namespace_out, out,
						      ns_ctx.num_backend_error_cmd_low);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_core_query_nvmf_ns);

