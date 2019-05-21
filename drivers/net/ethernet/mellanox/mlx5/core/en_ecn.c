/*
 * Copyright (c) 2015, Mellanox Technologies. All rights reserved.
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
#include <linux/device.h>
#include <linux/netdevice.h>
#include "en.h"
#include "en_ecn.h"

ssize_t mlx5e_show_ecn_enable(struct kobject *kobj,
			      struct kobj_attribute *attr,
			      char *buf)
{
	struct mlx5e_ecn_enable_ctx *enable_attr = container_of(attr,
						struct mlx5e_ecn_enable_ctx ,
						enable);
	int is_enable;
	int err;

	err = mlx5_query_port_cong_status(enable_attr->mdev,
					  enable_attr->cong_protocol,
					  enable_attr->priority, &is_enable);
	if (!err)
		return sprintf(buf, "%d\n", is_enable);
	return 0;
}

ssize_t mlx5e_store_ecn_enable(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       const char *buf, size_t count)
{
	struct mlx5e_ecn_enable_ctx  *enable_attr = container_of(attr,
						struct mlx5e_ecn_enable_ctx ,
						enable);
	int is_qcn_enable;
	int enable;
	int err;

	err = sscanf(buf, "%d", &enable);

	if (enable) {
		err = mlx5_query_port_cong_status(enable_attr->mdev,
						  enable_attr->cong_protocol,
						  enable_attr->priority,
						  &is_qcn_enable);

		if ((!err) & (is_qcn_enable))
			return -EPERM;
	}

	err = mlx5_modify_port_cong_status(enable_attr->mdev,
					   enable_attr->cong_protocol,
					   enable_attr->priority, enable);
	if (err)
		return err;
	return count;
}

ssize_t mlx5e_show_clamp_tgt_rate(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  char *buf)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						clamp_tgt_rate);
	u32 out[MLX5_ST_SZ_DW(query_cong_params_out)];
	void *congestion_parameters;
	u8 clamp_tgt_rate = -1;
	int err;

	err = mlx5_query_port_cong_params(rp_attr->mdev,
					  MLX5E_CON_PROTOCOL_R_ROCE_RP,
					  out, sizeof(out));
	if (!err) {
		congestion_parameters = MLX5_ADDR_OF(query_cong_params_out,
						     out,
						     congestion_parameters);
		clamp_tgt_rate = MLX5_GET(cong_control_r_roce_ecn_rp,
					  congestion_parameters,
					  clamp_tgt_rate);
		return sprintf(buf, "%d\n", clamp_tgt_rate);
	}
	return err;
}

ssize_t mlx5e_store_clamp_tgt_rate(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						clamp_tgt_rate);
	u32 in[MLX5_ST_SZ_DW(modify_cong_params_in)];
	void *congestion_parameters;
	int clamp_tgt_rate;
	void *field_select;
	int err;

	err = sscanf(buf, "%d", &clamp_tgt_rate);

	memset(in, 0, sizeof(in));
	MLX5_SET(modify_cong_params_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_PARAMS);
	MLX5_SET(modify_cong_params_in, in, cong_protocol,
		 MLX5E_CON_PROTOCOL_R_ROCE_RP);
	field_select = MLX5_ADDR_OF(modify_cong_params_in, in, field_select);
	MLX5_SET(field_select_r_roce_rp, field_select, field_select_r_roce_rp,
		 1 << MLX5E_RP_CLAMP_TGT_RATE);
	congestion_parameters = MLX5_ADDR_OF(modify_cong_params_in, in,
					     congestion_parameters);
	MLX5_SET(cong_control_r_roce_ecn_rp, congestion_parameters,
		 clamp_tgt_rate, clamp_tgt_rate);

	err = mlx5_modify_port_cong_params(rp_attr->mdev, in, sizeof(in));

	if (err)
		return err;
	return count;
}

ssize_t mlx5e_show_clamp_tgt_rate_ati(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      char *buf)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						clamp_tgt_rate_ati);
	u32 out[MLX5_ST_SZ_DW(query_cong_params_out)];
	void *congestion_parameters;
	u32 clamp_tgt_rate_ati = -1;
	int err;

	err = mlx5_query_port_cong_params(rp_attr->mdev,
					  MLX5E_CON_PROTOCOL_R_ROCE_RP,
					  out, sizeof(out));
	if (!err) {
		congestion_parameters = MLX5_ADDR_OF(query_cong_params_out,
						     out,
						     congestion_parameters);
		clamp_tgt_rate_ati = MLX5_GET(cong_control_r_roce_ecn_rp,
					      congestion_parameters,
					      clamp_tgt_rate_after_time_inc);
		return sprintf(buf, "%d\n", clamp_tgt_rate_ati);
	}
	return err;
}

ssize_t mlx5e_store_clamp_tgt_rate_ati(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buf, size_t count)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						clamp_tgt_rate_ati);
	u32 in[MLX5_ST_SZ_DW(modify_cong_params_in)];
	void *congestion_parameters;
	int clamp_tgt_rate_ati;
	void *field_select;
	int err;

	err = sscanf(buf, "%d", &clamp_tgt_rate_ati);

	memset(in, 0, sizeof(in));
	MLX5_SET(modify_cong_params_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_PARAMS);
	MLX5_SET(modify_cong_params_in, in, cong_protocol,
		 MLX5E_CON_PROTOCOL_R_ROCE_RP);
	field_select = MLX5_ADDR_OF(modify_cong_params_in, in, field_select);
	MLX5_SET(field_select_r_roce_rp, field_select, field_select_r_roce_rp,
		 1 << MLX5E_RP_CLAMP_TGT_RATE_AFTER_TIME_INC);
	congestion_parameters = MLX5_ADDR_OF(modify_cong_params_in, in,
					     congestion_parameters);
	MLX5_SET(cong_control_r_roce_ecn_rp, congestion_parameters,
		 clamp_tgt_rate_after_time_inc, clamp_tgt_rate_ati);

	err = mlx5_modify_port_cong_params(rp_attr->mdev, in, sizeof(in));

	if (err)
		return err;
	return count;
}

ssize_t mlx5e_show_rpg_time_reset(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  char *buf)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rpg_time_reset);
	u32 out[MLX5_ST_SZ_DW(query_cong_params_out)];
	void *congestion_parameters;
	u32 rpg_time_reset = -1;
	int err;

	err = mlx5_query_port_cong_params(rp_attr->mdev,
					  MLX5E_CON_PROTOCOL_R_ROCE_RP,
					  out, sizeof(out));
	if (!err) {
		congestion_parameters = MLX5_ADDR_OF(query_cong_params_out,
						     out,
						     congestion_parameters);
		rpg_time_reset = MLX5_GET(cong_control_r_roce_ecn_rp,
					  congestion_parameters,
					  rpg_time_reset);
		return sprintf(buf, "%d\n", rpg_time_reset);
	}
	return err;
}

ssize_t mlx5e_store_rpg_time_reset(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rpg_time_reset);
	u32 in[MLX5_ST_SZ_DW(modify_cong_params_in)];
	void *congestion_parameters;
	int rpg_time_reset;
	void *field_select;
	int err;

	err = sscanf(buf, "%d", &rpg_time_reset);

	memset(in, 0, sizeof(in));
	MLX5_SET(modify_cong_params_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_PARAMS);
	MLX5_SET(modify_cong_params_in, in, cong_protocol,
		 MLX5E_CON_PROTOCOL_R_ROCE_RP);
	field_select = MLX5_ADDR_OF(modify_cong_params_in, in, field_select);
	MLX5_SET(field_select_r_roce_rp, field_select, field_select_r_roce_rp,
		 1 << MLX5E_RP_RPG_TIME_RESET);
	congestion_parameters = MLX5_ADDR_OF(modify_cong_params_in, in,
					     congestion_parameters);
	MLX5_SET(cong_control_r_roce_ecn_rp, congestion_parameters,
		 rpg_time_reset, rpg_time_reset);

	err = mlx5_modify_port_cong_params(rp_attr->mdev, in, sizeof(in));

	if (err)
		return err;
	return count;
}

ssize_t mlx5e_show_rpg_byte_reset(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  char *buf)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rpg_byte_reset);
	u32 out[MLX5_ST_SZ_DW(query_cong_params_out)];
	void *congestion_parameters;
	u32 rpg_byte_reset = -1;
	int err;

	err = mlx5_query_port_cong_params(rp_attr->mdev,
					  MLX5E_CON_PROTOCOL_R_ROCE_RP,
					  out, sizeof(out));
	if (!err) {
		congestion_parameters = MLX5_ADDR_OF(query_cong_params_out,
						     out,
						     congestion_parameters);
		rpg_byte_reset = MLX5_GET(cong_control_r_roce_ecn_rp,
					  congestion_parameters,
					  rpg_byte_reset);
		return sprintf(buf, "%d\n", rpg_byte_reset);
	}
	return err;
}

ssize_t mlx5e_store_rpg_byte_reset(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rpg_byte_reset);
	u32 in[MLX5_ST_SZ_DW(modify_cong_params_in)];
	void *congestion_parameters;
	int rpg_byte_reset;
	void *field_select;
	int err;

	err = sscanf(buf, "%d", &rpg_byte_reset);

	memset(in, 0, sizeof(in));
	MLX5_SET(modify_cong_params_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_PARAMS);
	MLX5_SET(modify_cong_params_in, in, cong_protocol,
		 MLX5E_CON_PROTOCOL_R_ROCE_RP);
	field_select = MLX5_ADDR_OF(modify_cong_params_in, in, field_select);
	MLX5_SET(field_select_r_roce_rp, field_select, field_select_r_roce_rp,
		 1 << MLX5E_RP_RPG_BYTE_RESET);
	congestion_parameters = MLX5_ADDR_OF(modify_cong_params_in, in,
					     congestion_parameters);
	MLX5_SET(cong_control_r_roce_ecn_rp, congestion_parameters,
		 rpg_byte_reset, rpg_byte_reset);

	err = mlx5_modify_port_cong_params(rp_attr->mdev, in, sizeof(in));

	if (err)
		return err;
	return count;
}

ssize_t mlx5e_show_rpg_threshold(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 char *buf)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rpg_threshold);
	u32 out[MLX5_ST_SZ_DW(query_cong_params_out)];
	void *congestion_parameters;
	u32 rpg_threshold = -1;
	int err;

	err = mlx5_query_port_cong_params(rp_attr->mdev,
					  MLX5E_CON_PROTOCOL_R_ROCE_RP,
					  out, sizeof(out));
	if (!err) {
		congestion_parameters = MLX5_ADDR_OF(query_cong_params_out,
						     out,
						     congestion_parameters);
		rpg_threshold = MLX5_GET(cong_control_r_roce_ecn_rp,
					 congestion_parameters, rpg_threshold);
		return sprintf(buf, "%d\n", rpg_threshold);
	}
	return err;
}

ssize_t mlx5e_store_rpg_threshold(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rpg_threshold);
	u32 in[MLX5_ST_SZ_DW(modify_cong_params_in)];
	void *congestion_parameters;
	int rpg_threshold;
	void *field_select;
	int err;

	err = sscanf(buf, "%d", &rpg_threshold);

	memset(in, 0, sizeof(in));
	MLX5_SET(modify_cong_params_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_PARAMS);
	MLX5_SET(modify_cong_params_in, in, cong_protocol,
		 MLX5E_CON_PROTOCOL_R_ROCE_RP);
	field_select = MLX5_ADDR_OF(modify_cong_params_in, in, field_select);
	MLX5_SET(field_select_r_roce_rp, field_select, field_select_r_roce_rp,
		 1 << MLX5E_RP_RPG_THRESHOLD);
	congestion_parameters = MLX5_ADDR_OF(modify_cong_params_in, in,
					     congestion_parameters);
	MLX5_SET(cong_control_r_roce_ecn_rp, congestion_parameters,
		 rpg_threshold, rpg_threshold);

	err = mlx5_modify_port_cong_params(rp_attr->mdev, in, sizeof(in));

	if (err)
		return err;
	return count;
}

ssize_t mlx5e_show_rpg_max_rate(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rpg_max_rate);
	u32 out[MLX5_ST_SZ_DW(query_cong_params_out)];
	void *congestion_parameters;
	u32 rpg_max_rate = -1;
	int err;

	err = mlx5_query_port_cong_params(rp_attr->mdev,
					  MLX5E_CON_PROTOCOL_R_ROCE_RP,
					  out, sizeof(out));
	if (!err) {
		congestion_parameters = MLX5_ADDR_OF(query_cong_params_out,
						     out,
						     congestion_parameters);
		rpg_max_rate = MLX5_GET(cong_control_r_roce_ecn_rp,
					congestion_parameters, rpg_max_rate);
		return sprintf(buf, "%d\n", rpg_max_rate);
	}
	return err;
}

ssize_t mlx5e_store_rpg_max_rate(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buf, size_t count)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rpg_max_rate);
	u32 in[MLX5_ST_SZ_DW(modify_cong_params_in)];
	void *congestion_parameters;
	int rpg_max_rate;
	void *field_select;
	int err;

	err = sscanf(buf, "%d", &rpg_max_rate);

	memset(in, 0, sizeof(in));
	MLX5_SET(modify_cong_params_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_PARAMS);
	MLX5_SET(modify_cong_params_in, in, cong_protocol,
		 MLX5E_CON_PROTOCOL_R_ROCE_RP);
	field_select = MLX5_ADDR_OF(modify_cong_params_in, in, field_select);
	MLX5_SET(field_select_r_roce_rp, field_select, field_select_r_roce_rp,
		 1 << MLX5E_RP_RPG_MAX_RATE);
	congestion_parameters = MLX5_ADDR_OF(modify_cong_params_in, in,
					     congestion_parameters);
	MLX5_SET(cong_control_r_roce_ecn_rp, congestion_parameters,
		 rpg_max_rate, rpg_max_rate);

	err = mlx5_modify_port_cong_params(rp_attr->mdev, in, sizeof(in));

	if (err)
		return err;
	return count;
}

ssize_t mlx5e_show_rpg_ai_rate(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       char *buf)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rpg_ai_rate);
	u32 out[MLX5_ST_SZ_DW(query_cong_params_out)];
	void *congestion_parameters;
	u32 rpg_ai_rate = -1;
	int err;

	err = mlx5_query_port_cong_params(rp_attr->mdev,
					  MLX5E_CON_PROTOCOL_R_ROCE_RP,
					  out, sizeof(out));
	if (!err) {
		congestion_parameters = MLX5_ADDR_OF(query_cong_params_out,
						     out,
						     congestion_parameters);
		rpg_ai_rate = MLX5_GET(cong_control_r_roce_ecn_rp,
				       congestion_parameters, rpg_ai_rate);
		return sprintf(buf, "%d\n", rpg_ai_rate);
	}
	return err;
}

ssize_t mlx5e_store_rpg_ai_rate(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rpg_ai_rate);
	u32 in[MLX5_ST_SZ_DW(modify_cong_params_in)];
	void *congestion_parameters;
	int rpg_ai_rate;
	void *field_select;
	int err;

	err = sscanf(buf, "%d", &rpg_ai_rate);

	memset(in, 0, sizeof(in));
	MLX5_SET(modify_cong_params_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_PARAMS);
	MLX5_SET(modify_cong_params_in, in, cong_protocol,
		 MLX5E_CON_PROTOCOL_R_ROCE_RP);
	field_select = MLX5_ADDR_OF(modify_cong_params_in, in, field_select);
	MLX5_SET(field_select_r_roce_rp, field_select, field_select_r_roce_rp,
		 1 << MLX5E_RP_RPG_AI_RATE);
	congestion_parameters = MLX5_ADDR_OF(modify_cong_params_in, in,
					     congestion_parameters);
	MLX5_SET(cong_control_r_roce_ecn_rp, congestion_parameters,
		 rpg_ai_rate, rpg_ai_rate);

	err = mlx5_modify_port_cong_params(rp_attr->mdev, in, sizeof(in));

	if (err)
		return err;
	return count;
}

ssize_t mlx5e_show_rpg_hai_rate(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rpg_hai_rate);
	u32 out[MLX5_ST_SZ_DW(query_cong_params_out)];
	void *congestion_parameters;
	u32 rpg_hai_rate = -1;
	int err;

	err = mlx5_query_port_cong_params(rp_attr->mdev,
					  MLX5E_CON_PROTOCOL_R_ROCE_RP,
					  out, sizeof(out));
	if (!err) {
		congestion_parameters = MLX5_ADDR_OF(query_cong_params_out,
						     out,
						     congestion_parameters);
		rpg_hai_rate = MLX5_GET(cong_control_r_roce_ecn_rp,
					congestion_parameters, rpg_hai_rate);
		return sprintf(buf, "%d\n", rpg_hai_rate);
	}
	return err;
}

ssize_t mlx5e_store_rpg_hai_rate(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buf, size_t count)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rpg_hai_rate);
	u32 in[MLX5_ST_SZ_DW(modify_cong_params_in)];
	void *congestion_parameters;
	int rpg_hai_rate;
	void *field_select;
	int err;

	err = sscanf(buf, "%d", &rpg_hai_rate);

	memset(in, 0, sizeof(in));
	MLX5_SET(modify_cong_params_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_PARAMS);
	MLX5_SET(modify_cong_params_in, in, cong_protocol,
		 MLX5E_CON_PROTOCOL_R_ROCE_RP);
	field_select = MLX5_ADDR_OF(modify_cong_params_in, in, field_select);
	MLX5_SET(field_select_r_roce_rp, field_select, field_select_r_roce_rp,
		 1 << MLX5E_RP_RPG_HAI_RATE);
	congestion_parameters = MLX5_ADDR_OF(modify_cong_params_in, in,
					     congestion_parameters);
	MLX5_SET(cong_control_r_roce_ecn_rp, congestion_parameters,
		 rpg_hai_rate, rpg_hai_rate);

	err = mlx5_modify_port_cong_params(rp_attr->mdev, in, sizeof(in));

	if (err)
		return err;
	return count;
}

ssize_t mlx5e_show_rpg_gd(struct kobject *kobj,
			  struct kobj_attribute *attr,
			  char *buf)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rpg_gd);
	u32 out[MLX5_ST_SZ_DW(query_cong_params_out)];
	void *congestion_parameters;
	u32 rpg_gd = -1;
	int err;

	err = mlx5_query_port_cong_params(rp_attr->mdev,
					  MLX5E_CON_PROTOCOL_R_ROCE_RP,
					  out, sizeof(out));
	if (!err) {
		congestion_parameters = MLX5_ADDR_OF(query_cong_params_out,
					out, congestion_parameters);
		rpg_gd = MLX5_GET(cong_control_r_roce_ecn_rp,
				  congestion_parameters, rpg_gd);
		return sprintf(buf, "%d\n", rpg_gd);
	}
	return err;
}

ssize_t mlx5e_store_rpg_gd(struct kobject *kobj,
			   struct kobj_attribute *attr,
			   const char *buf, size_t count)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rpg_gd);
	u32 in[MLX5_ST_SZ_DW(modify_cong_params_in)];
	void *congestion_parameters;
	int rpg_gd;
	void *field_select;
	int err;

	err = sscanf(buf, "%d", &rpg_gd);

	printk("rpg_gd value: %d\n", rpg_gd);

	memset(in, 0, sizeof(in));
	MLX5_SET(modify_cong_params_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_PARAMS);
	MLX5_SET(modify_cong_params_in, in, cong_protocol,
		 MLX5E_CON_PROTOCOL_R_ROCE_RP);
	field_select = MLX5_ADDR_OF(modify_cong_params_in, in, field_select);
	MLX5_SET(field_select_r_roce_rp, field_select, field_select_r_roce_rp,
		 1 << MLX5E_RP_RPG_GD); //TODO???

	congestion_parameters = MLX5_ADDR_OF(modify_cong_params_in, in,
					     congestion_parameters);
	MLX5_SET(cong_control_r_roce_ecn_rp, congestion_parameters,
		 rpg_gd, rpg_gd);

	err = mlx5_modify_port_cong_params(rp_attr->mdev, in, sizeof(in));

	if (err)
		return err;

	return count;
}

ssize_t mlx5e_show_rpg_min_dec_fac(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   char *buf)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rpg_min_dec_fac);
	u32 out[MLX5_ST_SZ_DW(query_cong_params_out)];
	void *congestion_parameters;
	u32 rpg_min_dec_fac = -1;
	int err;

	err = mlx5_query_port_cong_params(rp_attr->mdev,
					  MLX5E_CON_PROTOCOL_R_ROCE_RP,
					  out, sizeof(out));
	if (!err) {
		congestion_parameters = MLX5_ADDR_OF(query_cong_params_out,
						     out,
						     congestion_parameters);
		rpg_min_dec_fac = MLX5_GET(cong_control_r_roce_ecn_rp,
					   congestion_parameters,
					   rpg_min_dec_fac);
		return sprintf(buf, "%d\n", rpg_min_dec_fac);
	}
	return err;
}

ssize_t mlx5e_store_rpg_min_dec_fac(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rpg_min_dec_fac);
	u32 in[MLX5_ST_SZ_DW(modify_cong_params_in)];
	void *congestion_parameters;
	int rpg_min_dec_fac;
	void *field_select;
	int err;

	err = sscanf(buf, "%d", &rpg_min_dec_fac);

	memset(in, 0, sizeof(in));
	MLX5_SET(modify_cong_params_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_PARAMS);
	MLX5_SET(modify_cong_params_in, in, cong_protocol,
		 MLX5E_CON_PROTOCOL_R_ROCE_RP);
	field_select = MLX5_ADDR_OF(modify_cong_params_in, in, field_select);
	MLX5_SET(field_select_r_roce_rp, field_select, field_select_r_roce_rp,
		 1 << MLX5E_RP_MIN_DEC_FAC);
	congestion_parameters = MLX5_ADDR_OF(modify_cong_params_in, in,
					     congestion_parameters);
	MLX5_SET(cong_control_r_roce_ecn_rp, congestion_parameters,
		 rpg_min_dec_fac, rpg_min_dec_fac);

	err = mlx5_modify_port_cong_params(rp_attr->mdev, in, sizeof(in));

	if (err)
		return err;
	return count;
}

ssize_t mlx5e_show_rpg_min_rate(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rpg_min_rate);
	u32 out[MLX5_ST_SZ_DW(query_cong_params_out)];
	void *congestion_parameters;
	u32 rpg_min_rate = -1;
	int err;

	err = mlx5_query_port_cong_params(rp_attr->mdev,
					  MLX5E_CON_PROTOCOL_R_ROCE_RP,
					  out, sizeof(out));
	if (!err) {
		congestion_parameters = MLX5_ADDR_OF(query_cong_params_out,
						     out,
						     congestion_parameters);
		rpg_min_rate = MLX5_GET(cong_control_r_roce_ecn_rp,
					congestion_parameters, rpg_min_rate);
		return sprintf(buf, "%d\n", rpg_min_rate);
	}
	return err;
}

ssize_t mlx5e_store_rpg_min_rate(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buf, size_t count)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rpg_min_rate);
	u32 in[MLX5_ST_SZ_DW(modify_cong_params_in)];
	void *congestion_parameters;
	int rpg_min_rate;
	void *field_select;
	int err;

	err = sscanf(buf, "%d", &rpg_min_rate);

	memset(in, 0, sizeof(in));
	MLX5_SET(modify_cong_params_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_PARAMS);
	MLX5_SET(modify_cong_params_in, in, cong_protocol,
		 MLX5E_CON_PROTOCOL_R_ROCE_RP);
	field_select = MLX5_ADDR_OF(modify_cong_params_in, in, field_select);
	MLX5_SET(field_select_r_roce_rp, field_select, field_select_r_roce_rp,
		 1 << MLX5E_RP_RPG_MIN_RATE);
	congestion_parameters = MLX5_ADDR_OF(modify_cong_params_in, in,
					     congestion_parameters);
	MLX5_SET(cong_control_r_roce_ecn_rp, congestion_parameters,
		 rpg_min_rate, rpg_min_rate);

	err = mlx5_modify_port_cong_params(rp_attr->mdev, in, sizeof(in));

	if (err)
		return err;
	return count;
}

ssize_t mlx5e_show_rate2set_fcnp(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 char *buf)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rate2set_fcnp);
	u32 out[MLX5_ST_SZ_DW(query_cong_params_out)];
	void *congestion_parameters;
	u32 rate_to_set_on_first_cnp = -1;
	int err;

	err = mlx5_query_port_cong_params(rp_attr->mdev,
					  MLX5E_CON_PROTOCOL_R_ROCE_RP,
					  out, sizeof(out));
	if (!err) {
		congestion_parameters = MLX5_ADDR_OF(query_cong_params_out,
						     out,
						     congestion_parameters);
		rate_to_set_on_first_cnp = MLX5_GET(cong_control_r_roce_ecn_rp,
						    congestion_parameters,
						    rate_to_set_on_first_cnp);
		return sprintf(buf, "%d\n", rate_to_set_on_first_cnp);
	}
	return err;
}

ssize_t mlx5e_store_rate2set_fcnp(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rate2set_fcnp);
	u32 in[MLX5_ST_SZ_DW(modify_cong_params_in)];
	void *congestion_parameters;
	int rate_to_set_on_first_cnp;
	void *field_select;
	int err;

	err = sscanf(buf, "%d", &rate_to_set_on_first_cnp);

	memset(in, 0, sizeof(in));
	MLX5_SET(modify_cong_params_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_PARAMS);
	MLX5_SET(modify_cong_params_in, in, cong_protocol,
		 MLX5E_CON_PROTOCOL_R_ROCE_RP);
	field_select = MLX5_ADDR_OF(modify_cong_params_in, in, field_select);
	MLX5_SET(field_select_r_roce_rp, field_select, field_select_r_roce_rp,
		 1 << MLX5E_RP_RATE_TO_SET_ON_FIRST_CNP);
	congestion_parameters = MLX5_ADDR_OF(modify_cong_params_in, in,
					     congestion_parameters);
	MLX5_SET(cong_control_r_roce_ecn_rp, congestion_parameters,
		 rate_to_set_on_first_cnp, rate_to_set_on_first_cnp);

	err = mlx5_modify_port_cong_params(rp_attr->mdev, in, sizeof(in));

	if (err)
		return err;
	return count;
}

ssize_t mlx5e_show_dce_tcp_g(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     char *buf)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						dce_tcp_g);
	u32 out[MLX5_ST_SZ_DW(query_cong_params_out)];
	void *congestion_parameters;
	u32 dce_tcp_g = -1;
	int err;

	err = mlx5_query_port_cong_params(rp_attr->mdev,
					  MLX5E_CON_PROTOCOL_R_ROCE_RP,
					  out, sizeof(out));
	if (!err) {
		congestion_parameters = MLX5_ADDR_OF(query_cong_params_out,
						     out,
						     congestion_parameters);
		dce_tcp_g = MLX5_GET(cong_control_r_roce_ecn_rp,
				     congestion_parameters, dce_tcp_g);
		return sprintf(buf, "%d\n", dce_tcp_g);
	}
	return err;
}

ssize_t mlx5e_store_dce_tcp_g(struct kobject *kobj,
			      struct kobj_attribute *attr,
			      const char *buf, size_t count)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						dce_tcp_g);
	u32 in[MLX5_ST_SZ_DW(modify_cong_params_in)];
	void *congestion_parameters;
	int dce_tcp_g;
	void *field_select;
	int err;

	err = sscanf(buf, "%d", &dce_tcp_g);

	memset(in, 0, sizeof(in));
	MLX5_SET(modify_cong_params_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_PARAMS);
	MLX5_SET(modify_cong_params_in, in, cong_protocol,
		 MLX5E_CON_PROTOCOL_R_ROCE_RP);
	field_select = MLX5_ADDR_OF(modify_cong_params_in, in, field_select);
	MLX5_SET(field_select_r_roce_rp, field_select, field_select_r_roce_rp,
		 1 << MLX5E_RP_DCE_TCP_G);
	congestion_parameters = MLX5_ADDR_OF(modify_cong_params_in, in,
					     congestion_parameters);
	MLX5_SET(cong_control_r_roce_ecn_rp, congestion_parameters,
		 dce_tcp_g, dce_tcp_g);

	err = mlx5_modify_port_cong_params(rp_attr->mdev, in, sizeof(in));

	if (err)
		return err;
	return count;
}

ssize_t mlx5e_show_dce_tcp_rtt(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       char *buf)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						dce_tcp_rtt);
	u32 out[MLX5_ST_SZ_DW(query_cong_params_out)];
	void *congestion_parameters;
	u32 dce_tcp_rtt = -1;
	int err;

	err = mlx5_query_port_cong_params(rp_attr->mdev,
					  MLX5E_CON_PROTOCOL_R_ROCE_RP,
					  out, sizeof(out));
	if (!err) {
		congestion_parameters = MLX5_ADDR_OF(query_cong_params_out,
						     out,
						     congestion_parameters);
		dce_tcp_rtt = MLX5_GET(cong_control_r_roce_ecn_rp,
				       congestion_parameters, dce_tcp_rtt);
		return sprintf(buf, "%d\n", dce_tcp_rtt);
	}
	return err;
}

ssize_t mlx5e_store_dce_tcp_rtt(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						dce_tcp_rtt);
	u32 in[MLX5_ST_SZ_DW(modify_cong_params_in)];
	void *congestion_parameters;
	int dce_tcp_rtt;
	void *field_select;
	int err;

	err = sscanf(buf, "%d", &dce_tcp_rtt);

	memset(in, 0, sizeof(in));
	MLX5_SET(modify_cong_params_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_PARAMS);
	MLX5_SET(modify_cong_params_in, in, cong_protocol,
		 MLX5E_CON_PROTOCOL_R_ROCE_RP);
	field_select = MLX5_ADDR_OF(modify_cong_params_in, in, field_select);
	MLX5_SET(field_select_r_roce_rp, field_select, field_select_r_roce_rp,
		 1 << MLX5E_RP_DCE_TCP_RTT);
	congestion_parameters = MLX5_ADDR_OF(modify_cong_params_in, in,
					     congestion_parameters);
	MLX5_SET(cong_control_r_roce_ecn_rp, congestion_parameters,
		 dce_tcp_rtt, dce_tcp_rtt);

	err = mlx5_modify_port_cong_params(rp_attr->mdev, in, sizeof(in));
	if (err)
		return err;
	return count;
}

ssize_t mlx5e_show_rreduce_mperiod(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   char *buf)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rreduce_mperiod);
	u32 out[MLX5_ST_SZ_DW(query_cong_params_out)];
	void *congestion_parameters;
	u32 rate_reduce_mperiod = -1;
	int err;

	err = mlx5_query_port_cong_params(rp_attr->mdev,
					  MLX5E_CON_PROTOCOL_R_ROCE_RP,
					  out, sizeof(out));
	if (!err) {
		congestion_parameters = MLX5_ADDR_OF(query_cong_params_out,
						     out,
						     congestion_parameters);
		rate_reduce_mperiod = MLX5_GET(cong_control_r_roce_ecn_rp,
					       congestion_parameters,
					       rate_reduce_monitor_period);
		return sprintf(buf, "%d\n", rate_reduce_mperiod);
	}
	return err;
}

ssize_t mlx5e_store_rreduce_mperiod(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						rreduce_mperiod);
	u32 in[MLX5_ST_SZ_DW(modify_cong_params_in)];
	void *congestion_parameters;
	int rate_reduce_monitor_period;
	void *field_select;
	int err;

	err = sscanf(buf, "%d", &rate_reduce_monitor_period);

	memset(in, 0, sizeof(in));
	MLX5_SET(modify_cong_params_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_PARAMS);
	MLX5_SET(modify_cong_params_in, in, cong_protocol,
		 MLX5E_CON_PROTOCOL_R_ROCE_RP);
	field_select = MLX5_ADDR_OF(modify_cong_params_in, in, field_select);
	MLX5_SET(field_select_r_roce_rp, field_select, field_select_r_roce_rp,
		 1 << MLX5E_RP_RATE_REDUCE_MONITOR_PERIOD);
	congestion_parameters = MLX5_ADDR_OF(modify_cong_params_in, in,
					     congestion_parameters);
	MLX5_SET(cong_control_r_roce_ecn_rp, congestion_parameters,
		 rate_reduce_monitor_period, rate_reduce_monitor_period);

	err = mlx5_modify_port_cong_params(rp_attr->mdev, in, sizeof(in));
	if (err)
		return err;
	return count;
}

ssize_t mlx5e_show_initial_alpha_value(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       char *buf)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						initial_alpha_value);
	u32 out[MLX5_ST_SZ_DW(query_cong_params_out)];
	void *congestion_parameters;
	u32 initial_alpha_value = -1;
	int err;

	err = mlx5_query_port_cong_params(rp_attr->mdev,
					  MLX5E_CON_PROTOCOL_R_ROCE_RP,
					  out, sizeof(out));
	if (!err) {
		congestion_parameters = MLX5_ADDR_OF(query_cong_params_out,
						     out,
						     congestion_parameters);
		initial_alpha_value = MLX5_GET(cong_control_r_roce_ecn_rp,
					       congestion_parameters,
					       initial_alpha_value);
		return sprintf(buf, "%d\n", initial_alpha_value);
	}
	return err;
}

ssize_t mlx5e_store_initial_alpha_value(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	struct mlx5e_ecn_rp_attributes *rp_attr = container_of(attr,
						struct mlx5e_ecn_rp_attributes,
						initial_alpha_value);
	u32 in[MLX5_ST_SZ_DW(modify_cong_params_in)];
	void *congestion_parameters;
	int initial_alpha_value;
	void *field_select;
	int err;

	err = sscanf(buf, "%d", &initial_alpha_value);

	memset(in, 0, sizeof(in));
	MLX5_SET(modify_cong_params_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_PARAMS);
	MLX5_SET(modify_cong_params_in, in, cong_protocol,
		 MLX5E_CON_PROTOCOL_R_ROCE_RP);
	field_select = MLX5_ADDR_OF(modify_cong_params_in, in, field_select);
	MLX5_SET(field_select_r_roce_rp, field_select, field_select_r_roce_rp,
		 1 << MLX5E_RP_INITIAL_ALPHA_VALUE);
	congestion_parameters = MLX5_ADDR_OF(modify_cong_params_in, in,
					     congestion_parameters);
	MLX5_SET(cong_control_r_roce_ecn_rp, congestion_parameters,
		 initial_alpha_value, initial_alpha_value);

	err = mlx5_modify_port_cong_params(rp_attr->mdev, in, sizeof(in));

	if (err)
		return err;
	return count;
}

ssize_t mlx5e_show_min_time_between_cnps(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 char *buf)
{
	struct mlx5e_ecn_np_attributes *np_attr = container_of(attr,
						struct mlx5e_ecn_np_attributes,
						min_time_between_cnps);
	u32 out[MLX5_ST_SZ_DW(query_cong_params_out)];
	void *congestion_parameters;
	u32 min_time_between_cnps = -1;
	int err;

	err = mlx5_query_port_cong_params(np_attr->mdev,
					  MLX5E_CON_PROTOCOL_R_ROCE_NP,
					  out, sizeof(out));
	if (!err) {
		congestion_parameters = MLX5_ADDR_OF(query_cong_params_out,
						     out,
						     congestion_parameters);
		min_time_between_cnps = MLX5_GET(cong_control_r_roce_ecn_np,
						 congestion_parameters,
						 min_time_between_cnps);
		return sprintf(buf, "%d\n", min_time_between_cnps);
	}
	return err;
}

ssize_t mlx5e_store_min_time_between_cnps(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  const char *buf, size_t count)
{
	struct mlx5e_ecn_np_attributes *np_attr = container_of(attr,
						struct mlx5e_ecn_np_attributes,
						min_time_between_cnps);
	u32 in[MLX5_ST_SZ_DW(modify_cong_params_in)];
	void *congestion_parameters;
	int min_time_between_cnps;
	void *field_select;
	int err;

	err = sscanf(buf, "%d", &min_time_between_cnps);

	memset(in, 0, sizeof(in));
	MLX5_SET(modify_cong_params_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_PARAMS);
	MLX5_SET(modify_cong_params_in, in, cong_protocol,
		 MLX5E_CON_PROTOCOL_R_ROCE_NP);
	field_select = MLX5_ADDR_OF(modify_cong_params_in, in, field_select);
	MLX5_SET(field_select_r_roce_np, field_select, field_select_r_roce_np,
		 1 << MLX5E_NP_MIN_TIME_BETWEEN_CNPS);
	congestion_parameters = MLX5_ADDR_OF(modify_cong_params_in, in,
					     congestion_parameters);
	MLX5_SET(cong_control_r_roce_ecn_np, congestion_parameters,
		 min_time_between_cnps, min_time_between_cnps);

	err = mlx5_modify_port_cong_params(np_attr->mdev, in, sizeof(in));

	if (err)
		return err;
	return count;
}

ssize_t mlx5e_show_cnp_dscp(struct kobject *kobj,
			    struct kobj_attribute *attr,
			    char *buf)
{
	struct mlx5e_ecn_np_attributes *np_attr = container_of(attr,
						struct mlx5e_ecn_np_attributes,
						cnp_dscp);
	u32 out[MLX5_ST_SZ_DW(query_cong_params_out)];
	void *congestion_parameters;
	u32 cnp_dscp = -1;
	int err;

	err = mlx5_query_port_cong_params(np_attr->mdev,
					  MLX5E_CON_PROTOCOL_R_ROCE_NP,
					  out, sizeof(out));
	if (!err) {
		congestion_parameters = MLX5_ADDR_OF(query_cong_params_out,
						     out,
						     congestion_parameters);
		cnp_dscp = MLX5_GET(cong_control_r_roce_ecn_np,
				    congestion_parameters, cnp_dscp);
		return sprintf(buf, "%d\n", cnp_dscp);
	}
	return err;
}

ssize_t mlx5e_store_cnp_dscp(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count)
{
	struct mlx5e_ecn_np_attributes *np_attr = container_of(attr,
						struct mlx5e_ecn_np_attributes,
						cnp_dscp);
	u32 in[MLX5_ST_SZ_DW(modify_cong_params_in)];
	void *congestion_parameters;
	void *field_select;
	int cnp_dscp;
	int err;

	err = sscanf(buf, "%d", &cnp_dscp);

	memset(in, 0, sizeof(in));
	MLX5_SET(modify_cong_params_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_PARAMS);
	MLX5_SET(modify_cong_params_in, in, cong_protocol,
		 MLX5E_CON_PROTOCOL_R_ROCE_NP);
	field_select = MLX5_ADDR_OF(modify_cong_params_in, in, field_select);
	MLX5_SET(field_select_r_roce_np, field_select, field_select_r_roce_np,
		 1 << MLX5E_NP_CNP_DSCP);
	congestion_parameters = MLX5_ADDR_OF(modify_cong_params_in, in,
					     congestion_parameters);
	MLX5_SET(cong_control_r_roce_ecn_np, congestion_parameters,
		 cnp_dscp, cnp_dscp);

	err = mlx5_modify_port_cong_params(np_attr->mdev, in, sizeof(in));

	if (err)
		return err;
	return count;
}

ssize_t mlx5e_show_cnp_802p_prio(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 char *buf)
{
	struct mlx5e_ecn_np_attributes *np_attr = container_of(attr,
						struct mlx5e_ecn_np_attributes,
						cnp_802p_prio);
	u32 out[MLX5_ST_SZ_DW(query_cong_params_out)];
	void *congestion_parameters;
	u32 cnp_802p_prio = -1;
	int err;

	err = mlx5_query_port_cong_params(np_attr->mdev,
					  MLX5E_CON_PROTOCOL_R_ROCE_NP,
					  out, sizeof(out));
	if (!err) {
		congestion_parameters = MLX5_ADDR_OF(query_cong_params_out,
						     out,
						     congestion_parameters);
		cnp_802p_prio = MLX5_GET(cong_control_r_roce_ecn_np,
					 congestion_parameters,
					 cnp_802p_prio);
		return sprintf(buf, "%d\n", cnp_802p_prio);
	}
	return err;
}

ssize_t mlx5e_store_cnp_802p_prio(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count)
{
	struct mlx5e_ecn_np_attributes *np_attr = container_of(attr,
						struct mlx5e_ecn_np_attributes,
						cnp_802p_prio);
	u32 in[MLX5_ST_SZ_DW(modify_cong_params_in)];
	void *congestion_parameters;
	int cnp_802p_prio;
	void *field_select;
	int err;

	err = sscanf(buf, "%d", &cnp_802p_prio);

	memset(in, 0, sizeof(in));
	MLX5_SET(modify_cong_params_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_PARAMS);
	MLX5_SET(modify_cong_params_in, in, cong_protocol,
		 MLX5E_CON_PROTOCOL_R_ROCE_NP);
	field_select = MLX5_ADDR_OF(modify_cong_params_in, in, field_select);
	MLX5_SET(field_select_r_roce_np, field_select, field_select_r_roce_np,
		 1 << MLX5E_NP_CNP_802P_PRIO);
	congestion_parameters = MLX5_ADDR_OF(modify_cong_params_in, in,
					     congestion_parameters);
	MLX5_SET(cong_control_r_roce_ecn_np, congestion_parameters,
		 cnp_802p_prio, cnp_802p_prio);

	err = mlx5_modify_port_cong_params(np_attr->mdev, in, sizeof(in));

	if (err)
		return err;
	return count;
}
