// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/*
 * Copyright (c) 2024, NVIDIA CORPORATION & AFFILIATES
 */
#include <linux/fwctl.h>
#include <linux/auxiliary_bus.h>
#include <linux/mlx5/device.h>
#include <linux/mlx5/driver.h>
#include <uapi/fwctl/mlx5.h>

#define mlx5ctl_err(mcdev, format, ...) \
	dev_err(&mcdev->fwctl.dev, format, ##__VA_ARGS__)

#define mlx5ctl_dbg(mcdev, format, ...)                             \
	dev_dbg(&mcdev->fwctl.dev, "PID %u: " format, current->pid, \
		##__VA_ARGS__)

struct mlx5ctl_uctx {
	struct fwctl_uctx uctx;
	u32 uctx_caps;
	u32 uctx_uid;
};

struct mlx5ctl_dev {
	struct fwctl_device fwctl;
	struct mlx5_core_dev *mdev;
};
DEFINE_FREE(mlx5ctl, struct mlx5ctl_dev *, if (_T) fwctl_put(&_T->fwctl));

struct mlx5_ifc_mbox_in_hdr_bits {
	u8 opcode[0x10];
	u8 uid[0x10];

	u8 reserved_at_20[0x10];
	u8 op_mod[0x10];

	u8 reserved_at_40[0x40];
};

struct mlx5_ifc_mbox_out_hdr_bits {
	u8 status[0x8];
	u8 reserved_at_8[0x18];

	u8 syndrome[0x20];

	u8 reserved_at_40[0x40];
};

enum {
	MLX5_UCTX_OBJECT_CAP_TOOLS_RESOURCES = 0x4,
};

enum {
	MLX5_CMD_OP_QUERY_DIAGNOSTIC_PARAMS = 0x819,
	MLX5_CMD_OP_SET_DIAGNOSTIC_PARAMS = 0x820,
	MLX5_CMD_OP_QUERY_DIAGNOSTIC_COUNTERS = 0x821,
	MLX5_CMD_OP_POSTPONE_CONNECTED_QP_TIMEOUT = 0xb2e,
};

static int mlx5ctl_alloc_uid(struct mlx5ctl_dev *mcdev, u32 cap)
{
	u32 out[MLX5_ST_SZ_DW(create_uctx_out)] = {};
	u32 in[MLX5_ST_SZ_DW(create_uctx_in)] = {};
	void *uctx;
	int ret;
	u16 uid;

	uctx = MLX5_ADDR_OF(create_uctx_in, in, uctx);

	mlx5ctl_dbg(mcdev, "%s: caps 0x%x\n", __func__, cap);
	MLX5_SET(create_uctx_in, in, opcode, MLX5_CMD_OP_CREATE_UCTX);
	MLX5_SET(uctx, uctx, cap, cap);

	ret = mlx5_cmd_exec(mcdev->mdev, in, sizeof(in), out, sizeof(out));
	if (ret)
		return ret;

	uid = MLX5_GET(create_uctx_out, out, uid);
	mlx5ctl_dbg(mcdev, "allocated uid %u with caps 0x%x\n", uid, cap);
	return uid;
}

static void mlx5ctl_release_uid(struct mlx5ctl_dev *mcdev, u16 uid)
{
	u32 in[MLX5_ST_SZ_DW(destroy_uctx_in)] = {};
	struct mlx5_core_dev *mdev = mcdev->mdev;
	int ret;

	MLX5_SET(destroy_uctx_in, in, opcode, MLX5_CMD_OP_DESTROY_UCTX);
	MLX5_SET(destroy_uctx_in, in, uid, uid);

	ret = mlx5_cmd_exec_in(mdev, destroy_uctx, in);
	mlx5ctl_dbg(mcdev, "released uid %u %pe\n", uid, ERR_PTR(ret));
}

static int mlx5ctl_open_uctx(struct fwctl_uctx *uctx)
{
	struct mlx5ctl_uctx *mfd =
		container_of(uctx, struct mlx5ctl_uctx, uctx);
	struct mlx5ctl_dev *mcdev =
		container_of(uctx->fwctl, struct mlx5ctl_dev, fwctl);
	int uid;

	/*
	 * New FW supports the TOOLS_RESOURCES uid security label
	 * which allows commands to manipulate the global device state.
	 * Otherwise only basic existing RDMA devx privilege are allowed.
	 */
	if (MLX5_CAP_GEN(mcdev->mdev, uctx_cap) &
	    MLX5_UCTX_OBJECT_CAP_TOOLS_RESOURCES)
		mfd->uctx_caps |= MLX5_UCTX_OBJECT_CAP_TOOLS_RESOURCES;

	if (MLX5_CAP_GEN(mcdev->mdev, uctx_cap) &
	    MLX5_UCTX_CAP_INTERNAL_DEV_RES)
		mfd->uctx_caps |= MLX5_UCTX_CAP_INTERNAL_DEV_RES;

	uid = mlx5ctl_alloc_uid(mcdev, mfd->uctx_caps);
	if (uid < 0)
		return uid;

	mfd->uctx_uid = uid;
	return 0;
}

static void mlx5ctl_close_uctx(struct fwctl_uctx *uctx)
{
	struct mlx5ctl_dev *mcdev =
		container_of(uctx->fwctl, struct mlx5ctl_dev, fwctl);
	struct mlx5ctl_uctx *mfd =
		container_of(uctx, struct mlx5ctl_uctx, uctx);

	mlx5ctl_release_uid(mcdev, mfd->uctx_uid);
}

static void *mlx5ctl_info(struct fwctl_uctx *uctx, size_t *length)
{
	struct mlx5ctl_uctx *mfd =
		container_of(uctx, struct mlx5ctl_uctx, uctx);
	struct fwctl_info_mlx5 *info;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return ERR_PTR(-ENOMEM);

	info->uid = mfd->uctx_uid;
	info->uctx_caps = mfd->uctx_caps;
	*length = sizeof(*info);
	return info;
}

static bool mlx5ctl_validate_rpc(const void *in, enum fwctl_rpc_scope scope)
{
	u16 opcode = MLX5_GET(mbox_in_hdr, in, opcode);

	/*
	 * Currently the driver can't keep track of commands that allocate
	 * objects in the FW, these commands are safe from a security
	 * perspective but nothing will free the memory when the FD is closed.
	 * For now permit only query commands. Also the caps for the scope have
	 * not been defined yet, filter commands manually for now.
	 */
	switch (opcode) {
	case MLX5_CMD_OP_POSTPONE_CONNECTED_QP_TIMEOUT:
	case MLX5_CMD_OP_QUERY_ADAPTER:
	case MLX5_CMD_OP_QUERY_ESW_FUNCTIONS:
	case MLX5_CMD_OP_QUERY_HCA_CAP:
	case MLX5_CMD_OP_QUERY_HCA_VPORT_CONTEXT:
	case MLX5_CMD_OP_QUERY_ROCE_ADDRESS:
		return scope <= FWCTL_RPC_CONFIGURATION;

	case MLX5_CMD_OP_QUERY_CONG_PARAMS:
	case MLX5_CMD_OP_QUERY_CONG_STATISTICS:
	case MLX5_CMD_OP_QUERY_CONG_STATUS:
	case MLX5_CMD_OP_QUERY_CQ:
	case MLX5_CMD_OP_QUERY_DCT:
	case MLX5_CMD_OP_QUERY_DIAGNOSTIC_COUNTERS:
	case MLX5_CMD_OP_QUERY_DIAGNOSTIC_PARAMS:
	case MLX5_CMD_OP_QUERY_EQ:
	case MLX5_CMD_OP_QUERY_ESW_VPORT_CONTEXT:
	case MLX5_CMD_OP_QUERY_FLOW_COUNTER:
	case MLX5_CMD_OP_QUERY_FLOW_GROUP:
	case MLX5_CMD_OP_QUERY_FLOW_TABLE_ENTRY:
	case MLX5_CMD_OP_QUERY_FLOW_TABLE:
	case MLX5_CMD_OP_QUERY_GENERAL_OBJECT:
	case MLX5_CMD_OP_QUERY_ISSI:
	case MLX5_CMD_OP_QUERY_L2_TABLE_ENTRY:
	case MLX5_CMD_OP_QUERY_LAG:
	case MLX5_CMD_OP_QUERY_MAD_DEMUX:
	case MLX5_CMD_OP_QUERY_MKEY:
	case MLX5_CMD_OP_QUERY_MODIFY_HEADER_CONTEXT:
	case MLX5_CMD_OP_QUERY_PACKET_REFORMAT_CONTEXT:
	case MLX5_CMD_OP_QUERY_PAGES:
	case MLX5_CMD_OP_QUERY_Q_COUNTER:
	case MLX5_CMD_OP_QUERY_QP:
	case MLX5_CMD_OP_QUERY_RMP:
	case MLX5_CMD_OP_QUERY_RQ:
	case MLX5_CMD_OP_QUERY_RQT:
	case MLX5_CMD_OP_QUERY_SCHEDULING_ELEMENT:
	case MLX5_CMD_OP_QUERY_SPECIAL_CONTEXTS:
	case MLX5_CMD_OP_QUERY_SQ:
	case MLX5_CMD_OP_QUERY_SRQ:
	case MLX5_CMD_OP_QUERY_TIR:
	case MLX5_CMD_OP_QUERY_TIS:
	case MLX5_CMD_OP_QUERY_VHCA_MIGRATION_STATE:
	case MLX5_CMD_OP_QUERY_VNIC_ENV:
	case MLX5_CMD_OP_QUERY_VPORT_COUNTER:
	case MLX5_CMD_OP_QUERY_VPORT_STATE:
	case MLX5_CMD_OP_QUERY_WOL_ROL:
	case MLX5_CMD_OP_QUERY_XRC_SRQ:
	case MLX5_CMD_OP_QUERY_XRQ_DC_PARAMS_ENTRY:
	case MLX5_CMD_OP_QUERY_XRQ_ERROR_PARAMS:
	case MLX5_CMD_OP_QUERY_XRQ:
		return scope <= FWCTL_RPC_DEBUG_READ_ONLY;

	case MLX5_CMD_OP_SET_DIAGNOSTIC_PARAMS:
		return scope <= FWCTL_RPC_DEBUG_WRITE;

	case MLX5_CMD_OP_ACCESS_REG:
		return scope <= FWCTL_RPC_DEBUG_WRITE_FULL;
	default:
		return false;
	}
}

static void *mlx5ctl_fw_rpc(struct fwctl_uctx *uctx, enum fwctl_rpc_scope scope,
			    void *rpc_in, size_t in_len, size_t *out_len)
{
	struct mlx5ctl_dev *mcdev =
		container_of(uctx->fwctl, struct mlx5ctl_dev, fwctl);
	struct mlx5ctl_uctx *mfd =
		container_of(uctx, struct mlx5ctl_uctx, uctx);
	void *rpc_alloc __free(kvfree) = NULL;
	void *rpc_out;
	int ret;

	if (in_len < MLX5_ST_SZ_BYTES(mbox_in_hdr) ||
	    *out_len < MLX5_ST_SZ_BYTES(mbox_out_hdr))
		return ERR_PTR(-EMSGSIZE);

	/* FIXME: Requires device support for more scopes */
	if (scope != FWCTL_RPC_CONFIGURATION &&
	    scope != FWCTL_RPC_DEBUG_READ_ONLY)
		return ERR_PTR(-EOPNOTSUPP);

	mlx5ctl_dbg(mcdev, "[UID %d] cmdif: opcode 0x%x inlen %zu outlen %zu\n",
		    mfd->uctx_uid, MLX5_GET(mbox_in_hdr, rpc_in, opcode),
		    in_len, *out_len);

	if (!mlx5ctl_validate_rpc(rpc_in, scope))
		return ERR_PTR(-EBADMSG);

	/*
	 * mlx5_cmd_do() copies the input message to its own buffer before
	 * executing it, so we can reuse the allocation for the output.
	 */
	if (*out_len <= in_len) {
		rpc_out = rpc_in;
	} else {
		rpc_out = rpc_alloc = kvzalloc(*out_len, GFP_KERNEL);
		if (!rpc_alloc)
			return ERR_PTR(-ENOMEM);
	}

	/* Enforce the user context for the command */
	MLX5_SET(mbox_in_hdr, rpc_in, uid, mfd->uctx_uid);
	ret = mlx5_cmd_do(mcdev->mdev, rpc_in, in_len, rpc_out, *out_len);

	mlx5ctl_dbg(mcdev,
		    "[UID %d] cmdif: opcode 0x%x status 0x%x retval %pe\n",
		    mfd->uctx_uid, MLX5_GET(mbox_in_hdr, rpc_in, opcode),
		    MLX5_GET(mbox_out_hdr, rpc_out, status), ERR_PTR(ret));

	/*
	 * -EREMOTEIO means execution succeeded and the out is valid,
	 * but an error code was returned inside out. Everything else
	 * means the RPC did not make it to the device.
	 */
	if (ret && ret != -EREMOTEIO)
		return ERR_PTR(ret);
	if (rpc_out == rpc_in)
		return rpc_in;
	return_ptr(rpc_alloc);
}

static const struct fwctl_ops mlx5ctl_ops = {
	.device_type = FWCTL_DEVICE_TYPE_MLX5,
	.uctx_size = sizeof(struct mlx5ctl_uctx),
	.open_uctx = mlx5ctl_open_uctx,
	.close_uctx = mlx5ctl_close_uctx,
	.info = mlx5ctl_info,
	.fw_rpc = mlx5ctl_fw_rpc,
};

static int mlx5ctl_probe(struct auxiliary_device *adev,
			 const struct auxiliary_device_id *id)

{
	struct mlx5_adev *madev = container_of(adev, struct mlx5_adev, adev);
	struct mlx5_core_dev *mdev = madev->mdev;
	struct mlx5ctl_dev *mcdev __free(mlx5ctl) = fwctl_alloc_device(
		&mdev->pdev->dev, &mlx5ctl_ops, struct mlx5ctl_dev, fwctl);
	int ret;

	if (!mcdev)
		return -ENOMEM;

	mcdev->mdev = mdev;

	ret = fwctl_register(&mcdev->fwctl);
	if (ret)
		return ret;
	auxiliary_set_drvdata(adev, no_free_ptr(mcdev));
	return 0;
}

static void mlx5ctl_remove(struct auxiliary_device *adev)
{
	struct mlx5ctl_dev *mcdev __free(mlx5ctl) = auxiliary_get_drvdata(adev);

	fwctl_unregister(&mcdev->fwctl);
}

static const struct auxiliary_device_id mlx5ctl_id_table[] = {
	{.name = MLX5_ADEV_NAME ".fwctl",},
	{},
};
MODULE_DEVICE_TABLE(auxiliary, mlx5ctl_id_table);

static struct auxiliary_driver mlx5ctl_driver = {
	.name = "mlx5_fwctl",
	.probe = mlx5ctl_probe,
	.remove = mlx5ctl_remove,
	.id_table = mlx5ctl_id_table,
};

module_auxiliary_driver(mlx5ctl_driver);

MODULE_IMPORT_NS(FWCTL);
MODULE_DESCRIPTION("mlx5 ConnectX fwctl driver");
MODULE_AUTHOR("Saeed Mahameed <saeedm@nvidia.com>");
MODULE_LICENSE("Dual BSD/GPL");
