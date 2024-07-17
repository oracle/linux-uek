// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/* Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. */

#include "reporter_vnic.h"
#include "devlink.h"

#define VNIC_ENV_GET64(vnic_env_stats, c) \
	MLX5_GET64(query_vnic_env_out, (vnic_env_stats)->query_vnic_env_out, \
		 vport_env.c)

struct mlx5_vnic_diag_stats {
	__be64 query_vnic_env_out[MLX5_ST_SZ_QW(query_vnic_env_out)];
};

int mlx5_reporter_vnic_diagnose_counters(struct mlx5_core_dev *dev,
					 struct devlink_fmsg *fmsg,
					 u16 vport_num, bool other_vport)
{
	u32 in[MLX5_ST_SZ_DW(query_vnic_env_in)] = {};
	struct mlx5_vnic_diag_stats vnic;
	int err;

	MLX5_SET(query_vnic_env_in, in, opcode, MLX5_CMD_OP_QUERY_VNIC_ENV);
	MLX5_SET(query_vnic_env_in, in, vport_number, vport_num);
	MLX5_SET(query_vnic_env_in, in, other_vport, !!other_vport);

	err = mlx5_cmd_exec_inout(dev, query_vnic_env, in, &vnic.query_vnic_env_out);
	if (err)
		return err;

	err = devlink_fmsg_pair_nest_start(fmsg, "vNIC env counters");
	if (err)
		return err;

	err = devlink_fmsg_obj_nest_start(fmsg);
	if (err)
		return err;

	err = devlink_fmsg_u64_pair_put(fmsg, "total_error_queues",
					VNIC_ENV_GET64(&vnic, total_error_queues));
	if (err)
		return err;

	err = devlink_fmsg_u64_pair_put(fmsg, "send_queue_priority_update_flow",
					VNIC_ENV_GET64(&vnic, send_queue_priority_update_flow));
	if (err)
		return err;

	err = devlink_fmsg_u64_pair_put(fmsg, "comp_eq_overrun",
					VNIC_ENV_GET64(&vnic, comp_eq_overrun));
	if (err)
		return err;

	err = devlink_fmsg_u64_pair_put(fmsg, "async_eq_overrun",
					VNIC_ENV_GET64(&vnic, async_eq_overrun));
	if (err)
		return err;

	err = devlink_fmsg_u64_pair_put(fmsg, "cq_overrun",
					VNIC_ENV_GET64(&vnic, cq_overrun));
	if (err)
		return err;

	err = devlink_fmsg_u64_pair_put(fmsg, "invalid_command",
					VNIC_ENV_GET64(&vnic, invalid_command));
	if (err)
		return err;

	err = devlink_fmsg_u64_pair_put(fmsg, "quota_exceeded_command",
					VNIC_ENV_GET64(&vnic, quota_exceeded_command));
	if (err)
		return err;

	err = devlink_fmsg_u64_pair_put(fmsg, "nic_receive_steering_discard",
					VNIC_ENV_GET64(&vnic, nic_receive_steering_discard));
	if (err)
		return err;

	err = devlink_fmsg_obj_nest_end(fmsg);
	if (err)
		return err;

	err = devlink_fmsg_pair_nest_end(fmsg);
	if (err)
		return err;

	return 0;
}

static int mlx5_reporter_vnic_diagnose(struct devlink_health_reporter *reporter,
				       struct devlink_fmsg *fmsg,
				       struct netlink_ext_ack *extack)
{
	struct mlx5_core_dev *dev = devlink_health_reporter_priv(reporter);

	return mlx5_reporter_vnic_diagnose_counters(dev, fmsg, 0, false);
}

static const struct devlink_health_reporter_ops mlx5_reporter_vnic_ops = {
	.name = "vnic",
	.diagnose = mlx5_reporter_vnic_diagnose,
};

void mlx5_reporter_vnic_create(struct mlx5_core_dev *dev)
{
	struct mlx5_core_health *health = &dev->priv.health;
	struct devlink *devlink = priv_to_devlink(dev);

	health->vnic_reporter =
		devlink_health_reporter_create(devlink,
					       &mlx5_reporter_vnic_ops,
					       0, dev);
	if (IS_ERR(health->vnic_reporter))
		mlx5_core_warn(dev,
			       "Failed to create vnic reporter, err = %ld\n",
			       PTR_ERR(health->vnic_reporter));
}

void mlx5_reporter_vnic_destroy(struct mlx5_core_dev *dev)
{
	struct mlx5_core_health *health = &dev->priv.health;

	if (!IS_ERR_OR_NULL(health->vnic_reporter))
		devlink_health_reporter_destroy(health->vnic_reporter);
}
