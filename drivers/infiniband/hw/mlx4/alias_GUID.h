/*
 * Copyright (c) 2007 Cisco Systems, Inc. All rights reserved.
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
 /***********************************************************/
/*This file support the handling of the Alias GUID feature. */
/***********************************************************/
#ifndef MLX4_ALIAS_GUID_H
#define MLX4_ALIAS_GUID_H

#include <rdma/ib_mad.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_sa.h>

#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <rdma/ib_user_verbs.h>
#include "mlx4_ib.h"

#define MLX4_PORT_DOWN_WAIT_TIME 	(HZ * 10)
#define MLX4_GUID_FOR_DELETE_VAL 	cpu_to_be64(~0ULL)

enum mlx4_guid_alias_rec_method {
	MLX4_GUID_INFO_RECORD_SET	= IB_MGMT_METHOD_SET,
	MLX4_GUID_INFO_RECORD_DELETE 	= IB_SA_METHOD_DELETE,
};

/*work completion status */
enum guid_alias_status {
	MLX4_PORT_NOT_CONFIGURED	= 1971,
};

/*structures*/

struct mlx4_alias_guid_work_context {
	u8 port;
	struct mlx4_ib_dev     *dev ;
	struct ib_sa_query     *sa_query;
	struct completion	done;
	int			query_id;
	struct list_head	list;
	int			block_num;
	u8 method;
};

struct mlx4_next_alias_guid_work {
	u8 port;
	u8 block_num;
	struct mlx4_sriov_alias_guid_info_rec_det rec_det;
};

/*Functions*/

/*init work for port, send the (port_num - 1) for port number*/
int init_alias_guid_work(struct mlx4_ib_dev *dev, int port);

void clear_alias_guid_work(struct mlx4_ib_dev *dev);

int init_alias_guid_service(struct mlx4_ib_dev *dev);

/*When ever you want all the record to be assign*/
void invalidate_all_guid_record(struct mlx4_ib_dev *dev, int port);

/*sysfs function:*/
int mlx4_ib_device_register_sysfs(struct mlx4_ib_dev *device) ;

void mlx4_ib_device_unregister_sysfs(struct mlx4_ib_dev *device);

int mlx4_ib_get_indexed_gid(struct ib_device *ibdev, u8 port, int index,
			       union ib_gid *gid);

ib_sa_comp_mask get_alias_guid_comp_mask_from_index(int index);

int notify_slaves_on_guid_change(struct mlx4_ib_dev *dev, int block_num,
				  u8 port_num, u8* p_data);

void update_cache_on_guid_change(struct mlx4_ib_dev *dev, int block_num, u8 port_num, u8* p_data);

__be64 get_cached_alias_guid(struct mlx4_ib_dev *dev, int port, int index);

enum mlx4_guid_alias_rec_status get_record_status(struct mlx4_ib_dev *dev,
						  int port, int index);
#endif /*MLX4_ALIAS_GUID_H*/
