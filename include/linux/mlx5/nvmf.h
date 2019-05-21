/*
 * Copyright (c) 2013-2015, Mellanox Technologies. All rights reserved.
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

#ifndef MLX5_NVMF_H
#define MLX5_NVMF_H

#include <linux/mlx5/driver.h>

struct mlx5_be_ctrl_attr {
	u32	cq_page_offset;
	u32	sq_page_offset;
	u8	cq_log_page_size;
	u8	sq_log_page_size;
	u16	initial_cqh_db_value;
	u16	initial_sqt_db_value;
	u8	log_cmd_timeout_us;
	u64	cqh_dbr_addr;
	u64	sqt_dbr_addr;
	u64	cq_pas;
	u64	sq_pas;
};

struct mlx5_ns_attr {
	u32	frontend_namespace;
	u32	backend_namespace;
	u16	lba_data_size;
	u16	backend_ctrl_id;
};

struct mlx5_core_nvmf_be_ctrl {
	int			id;
	void (*event)(struct mlx5_core_nvmf_be_ctrl *, int, int);
	spinlock_t		lock;
	struct list_head	ns_list;
	struct list_head	entry;
};

struct mlx5_core_nvmf_ns_counters {
	u64 num_read_cmd;
	u64 num_read_blocks;
	u64 num_write_cmd;
	u64 num_write_blocks;
	u64 num_write_inline_cmd;
	u64 num_flush_cmd;
	u64 num_error_cmd;
	u64 num_backend_error_cmd;
};

struct mlx5_core_nvmf_ns {
	u32 frontend_nsid;
	u32 backend_nsid;
	struct list_head entry;
	struct mlx5_core_nvmf_ns_counters counters;
};

int mlx5_core_create_nvmf_backend_ctrl(struct mlx5_core_dev *dev,
				       struct mlx5_core_srq *srq,
				       struct mlx5_core_nvmf_be_ctrl *ctrl,
				       struct mlx5_be_ctrl_attr *in);

int mlx5_core_destroy_nvmf_backend_ctrl(struct mlx5_core_dev *dev,
					struct mlx5_core_srq *srq,
					struct mlx5_core_nvmf_be_ctrl *ctrl);

int mlx5_core_attach_nvmf_ns(struct mlx5_core_dev *dev,
			     struct mlx5_core_srq *srq,
			     struct mlx5_core_nvmf_be_ctrl *ctrl,
			     struct mlx5_core_nvmf_ns *ns,
			     struct mlx5_ns_attr *attr_in);

int mlx5_core_detach_nvmf_ns(struct mlx5_core_dev *dev,
			     struct mlx5_core_srq *srq,
			     struct mlx5_core_nvmf_be_ctrl *ctrl,
			     struct mlx5_core_nvmf_ns *ns);

int mlx5_core_query_nvmf_ns(struct mlx5_core_dev *dev,
			    struct mlx5_core_srq *srq,
			    struct mlx5_core_nvmf_ns *ns);

#endif /* MLX5_NVMF_H */
