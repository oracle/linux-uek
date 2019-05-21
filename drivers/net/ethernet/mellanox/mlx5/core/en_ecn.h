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

#ifndef __MLX5_EN_ECN_H__
#define __MLX5_EN_ECN_H__

#define MLX5E_RP_CLAMP_TGT_RATE			1
#define MLX5E_RP_CLAMP_TGT_RATE_AFTER_TIME_INC	2
#define MLX5E_RP_RPG_TIME_RESET			3
#define MLX5E_RP_RPG_BYTE_RESET			4
#define MLX5E_RP_RPG_THRESHOLD			5
#define MLX5E_RP_RPG_MAX_RATE			6
#define MLX5E_RP_RPG_AI_RATE			7
#define MLX5E_RP_RPG_HAI_RATE			8
#define MLX5E_RP_MIN_DEC_FAC			9
#define MLX5E_RP_RPG_MIN_RATE			10
#define MLX5E_RP_RATE_TO_SET_ON_FIRST_CNP	11
#define MLX5E_RP_DCE_TCP_G			12
#define MLX5E_RP_DCE_TCP_RTT			13
#define MLX5E_RP_RATE_REDUCE_MONITOR_PERIOD	14
#define MLX5E_RP_INITIAL_ALPHA_VALUE		15
#define MLX5E_RP_RPG_GD				16
#define MLX5E_NP_MIN_TIME_BETWEEN_CNPS		2
#define MLX5E_NP_CNP_DSCP			3
#define MLX5E_NP_CNP_802P_PRIO			4

ssize_t mlx5e_show_ecn_enable(struct kobject *kobj,
			      struct kobj_attribute *attr,
			      char *buf);
ssize_t mlx5e_store_ecn_enable(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       const char *buf, size_t count);
ssize_t mlx5e_show_clamp_tgt_rate(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  char *buf);
ssize_t mlx5e_store_clamp_tgt_rate(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count);
ssize_t mlx5e_show_clamp_tgt_rate_ati(struct kobject *kobj,
				      struct kobj_attribute *attr,
				      char *buf);
ssize_t mlx5e_store_clamp_tgt_rate_ati(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       const char *buf, size_t count);
ssize_t mlx5e_show_rpg_time_reset(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  char *buf);
ssize_t mlx5e_store_rpg_time_reset(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count);
ssize_t mlx5e_show_rpg_byte_reset(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  char *buf);
ssize_t mlx5e_store_rpg_byte_reset(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count);
ssize_t mlx5e_show_rpg_threshold(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 char *buf);
ssize_t mlx5e_store_rpg_threshold(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count);
ssize_t mlx5e_show_rpg_max_rate(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf);
ssize_t mlx5e_store_rpg_max_rate(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buf, size_t count);
ssize_t mlx5e_show_rpg_ai_rate(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       char *buf);
ssize_t mlx5e_store_rpg_ai_rate(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count);
ssize_t mlx5e_show_rpg_hai_rate(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf);
ssize_t mlx5e_store_rpg_hai_rate(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buf, size_t count);
ssize_t mlx5e_show_rpg_gd(struct kobject *kobj,
			  struct kobj_attribute *attr,
			  char *buf);
ssize_t mlx5e_store_rpg_gd(struct kobject *kobj,
			   struct kobj_attribute *attr,
			   const char *buf, size_t count);
ssize_t mlx5e_show_rpg_min_dec_fac(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   char *buf);
ssize_t mlx5e_store_rpg_min_dec_fac(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count);
ssize_t mlx5e_show_rpg_min_rate(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf);
ssize_t mlx5e_store_rpg_min_rate(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 const char *buf, size_t count);
ssize_t mlx5e_show_rate2set_fcnp(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 char *buf);
ssize_t mlx5e_store_rate2set_fcnp(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count);
ssize_t mlx5e_show_dce_tcp_g(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     char *buf);
ssize_t mlx5e_store_dce_tcp_g(struct kobject *kobj,
			      struct kobj_attribute *attr,
			      const char *buf, size_t count);
ssize_t mlx5e_show_dce_tcp_rtt(struct kobject *kobj,
			       struct kobj_attribute *attr,
			       char *buf);
ssize_t mlx5e_store_dce_tcp_rtt(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count);
ssize_t mlx5e_show_rreduce_mperiod(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   char *buf);
ssize_t mlx5e_store_rreduce_mperiod(struct kobject *kobj,
				    struct kobj_attribute *attr,
				    const char *buf, size_t count);
ssize_t mlx5e_show_initial_alpha_value(struct kobject *kobj,
				       struct kobj_attribute *attr,
				       char *buf);
ssize_t mlx5e_store_initial_alpha_value(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count);
ssize_t mlx5e_show_min_time_between_cnps(struct kobject *kobj,
					 struct kobj_attribute *attr,
					 char *buf);
ssize_t mlx5e_store_min_time_between_cnps(struct kobject *kobj,
					  struct kobj_attribute *attr,
					  const char *buf, size_t count);
ssize_t mlx5e_show_cnp_dscp(struct kobject *kobj,
			    struct kobj_attribute *attr,
			    char *buf);
ssize_t mlx5e_store_cnp_dscp(struct kobject *kobj,
			     struct kobj_attribute *attr,
			     const char *buf, size_t count);
ssize_t mlx5e_show_cnp_802p_prio(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 char *buf);
ssize_t mlx5e_store_cnp_802p_prio(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  const char *buf, size_t count);
#endif /* __MLX5_ECN_H__ */
