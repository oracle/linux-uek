/* SPDX-License-Identifier: (GPL-2.0+ OR BSD-3-Clause) */
/*
 * Copyright (c) 2018 Mellanox Technologies. All rights reserved.
 */

#ifndef _MLX5_ESWITCH_
#define _MLX5_ESWITCH_

#include <linux/mlx5/driver.h>

enum {
	SRIOV_NONE,
	SRIOV_LEGACY,
	SRIOV_OFFLOADS
};

struct mlx5_eswitch_rep {
	int		       (*load)(struct mlx5_eswitch *esw,
				       struct mlx5_eswitch_rep *rep);
	void		       (*unload)(struct mlx5_eswitch *esw,
					 struct mlx5_eswitch_rep *rep);
	u16		       vport;
	u8		       hw_id[ETH_ALEN];
	struct net_device      *netdev;

	struct mlx5_flow_handle *vport_rx_rule;
	struct list_head       vport_sqs_list;
	u16		       vlan;
	u32		       vlan_refcount;
	bool		       valid;
};

void mlx5_eswitch_register_vport_rep(struct mlx5_eswitch *esw,
				     int vport_index,
				     struct mlx5_eswitch_rep *rep);
void mlx5_eswitch_unregister_vport_rep(struct mlx5_eswitch *esw,
				       int vport_index);
u8 mlx5_eswitch_mode(struct mlx5_eswitch *esw);
struct mlx5_flow_handle *
mlx5_eswitch_add_send_to_vport_rule(struct mlx5_eswitch *esw,
				    int vport, u32 sqn);
#ifdef CONFIG_MLX5_ESWITCH
bool mlx5_eswitch_vport_match_metadata_enabled(const struct mlx5_eswitch *esw);
u32 mlx5_eswitch_get_vport_metadata_for_match(const struct mlx5_eswitch *esw,
					      u16 vport_num);
#else  /* CONFIG_MLX5_ESWITCH */
static inline bool
mlx5_eswitch_vport_match_metadata_enabled(const struct mlx5_eswitch *esw)
{
	return false;
};

static inline u32
mlx5_eswitch_get_vport_metadata_for_match(const struct mlx5_eswitch *esw,
					  u16 vport_num)
{
	return 0;
};
#endif /* CONFIG_MLX5_ESWITCH */
#endif
