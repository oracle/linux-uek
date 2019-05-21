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

#ifndef MLX5_SRQ_H
#define MLX5_SRQ_H

#include <linux/mlx5/driver.h>

enum {
	MLX5_SRQ_FLAG_ERR    = (1 << 0),
	MLX5_SRQ_FLAG_WQ_SIG = (1 << 1),
	MLX5_SRQ_FLAG_RNDV   = (1 << 2),
	MLX5_SRQ_FLAG_SET_DC_OP = 1 << 3,
	MLX5_SRQ_FLAG_STRIDING_RECV_WQ = (1 << 4),
};

enum mlx5_nvmf_offload_type {
	MLX5_NVMF_WRITE_OFFLOAD			= 1,
	MLX5_NVMF_READ_OFFLOAD			= 2,
	MLX5_NVMF_READ_WRITE_OFFLOAD		= 3,
	MLX5_NVMF_READ_WRITE_FLUSH_OFFLOAD	= 4,
};

struct mlx5_nvmf_attr {
	enum mlx5_nvmf_offload_type	type;
	u8				log_max_namespace;
	u32				cmd_unknown_namespace_cnt;
	u32				ioccsz;
	u8				icdoff;
	u8				log_max_io_size;
	u8				nvme_memory_log_page_size;
	u8				staging_buffer_log_page_size;
	u16				staging_buffer_number_of_pages;
	u8				staging_buffer_page_offset;
	u32				nvme_queue_size;
	u64				*staging_buffer_pas;
};

struct mlx5_dc_offload_params {
	u16				pkey_index;
	enum ib_mtu			path_mtu;
	u8				sl;
	u8				max_rd_atomic;
	u8				min_rnr_timer;
	u8				timeout;
	u8				retry_cnt;
	u8				rnr_retry;
	u64				dct_key;
	u32				ooo_caps;
};

struct mlx5_striding_recv_wq {
	u8 log_wqe_num_of_strides;
	u8 log_wqe_stride_size;
};

struct mlx5_srq_attr {
	u32 type;
	u32 flags;
	u32 log_size;
	u32 wqe_shift;
	u32 log_page_size;
	u32 wqe_cnt;
	u32 srqn;
	u32 xrcd;
	u32 page_offset;
	u32 cqn;
	u32 pd;
	u32 lwm;
	u32 user_index;
	u64 db_record;
	__be64 *pas;
	u32 tm_log_list_size;
	u32 tm_next_tag;
	u32 tm_hw_phase_cnt;
	u32 tm_sw_phase_cnt;
	struct mlx5_nvmf_attr nvmf;
	struct mlx5_dc_offload_params dc_op;
	struct mlx5_striding_recv_wq	striding_recv_wq;
	u16 uid;
};

struct mlx5_core_dev;

void mlx5_init_srq_table(struct mlx5_core_dev *dev);
void mlx5_cleanup_srq_table(struct mlx5_core_dev *dev);

#endif /* MLX5_SRQ_H */
