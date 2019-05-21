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

#include <linux/module.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/port.h>
#include <linux/mlx5/cmd.h>
#include "mlx5_core.h"

int mlx5_core_access_reg(struct mlx5_core_dev *dev, void *data_in,
			 int size_in, void *data_out, int size_out,
			 u16 reg_id, int arg, int write)
{
	int outlen = MLX5_ST_SZ_BYTES(access_register_out) + size_out;
	int inlen = MLX5_ST_SZ_BYTES(access_register_in) + size_in;
	int err = -ENOMEM;
	u32 *out = NULL;
	u32 *in = NULL;
	void *data;

	in = kvzalloc(inlen, GFP_KERNEL);
	out = kvzalloc(outlen, GFP_KERNEL);
	if (!in || !out)
		goto out;

	data = MLX5_ADDR_OF(access_register_in, in, register_data);
	memcpy(data, data_in, size_in);

	MLX5_SET(access_register_in, in, opcode, MLX5_CMD_OP_ACCESS_REG);
	MLX5_SET(access_register_in, in, op_mod, !write);
	MLX5_SET(access_register_in, in, argument, arg);
	MLX5_SET(access_register_in, in, register_id, reg_id);

	err = mlx5_cmd_exec(dev, in, inlen, out, outlen);
	if (err)
		goto out;

	data = MLX5_ADDR_OF(access_register_out, out, register_data);
	memcpy(data_out, data, size_out);

out:
	kvfree(out);
	kvfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_access_reg);

int mlx5_query_pcam_reg(struct mlx5_core_dev *dev, u32 *pcam, u8 feature_group,
			u8 access_reg_group)
{
	u32 in[MLX5_ST_SZ_DW(pcam_reg)] = {0};
	int sz = MLX5_ST_SZ_BYTES(pcam_reg);

	MLX5_SET(pcam_reg, in, feature_group, feature_group);
	MLX5_SET(pcam_reg, in, access_reg_group, access_reg_group);

	return mlx5_core_access_reg(dev, in, sz, pcam, sz, MLX5_REG_PCAM, 0, 0);
}

int mlx5_query_mcam_reg(struct mlx5_core_dev *dev, u32 *mcam, u8 feature_group,
			u8 access_reg_group)
{
	u32 in[MLX5_ST_SZ_DW(mcam_reg)] = {0};
	int sz = MLX5_ST_SZ_BYTES(mcam_reg);

	MLX5_SET(mcam_reg, in, feature_group, feature_group);
	MLX5_SET(mcam_reg, in, access_reg_group, access_reg_group);

	return mlx5_core_access_reg(dev, in, sz, mcam, sz, MLX5_REG_MCAM, 0, 0);
}

int mlx5_query_qcam_reg(struct mlx5_core_dev *mdev, u32 *qcam,
			u8 feature_group, u8 access_reg_group)
{
	u32 in[MLX5_ST_SZ_DW(qcam_reg)] = {};
	int sz = MLX5_ST_SZ_BYTES(qcam_reg);

	MLX5_SET(qcam_reg, in, feature_group, feature_group);
	MLX5_SET(qcam_reg, in, access_reg_group, access_reg_group);

	return mlx5_core_access_reg(mdev, in, sz, qcam, sz, MLX5_REG_QCAM, 0, 0);
}

struct mlx5_reg_pcap {
	u8			rsvd0;
	u8			port_num;
	u8			rsvd1[2];
	__be32			caps_127_96;
	__be32			caps_95_64;
	__be32			caps_63_32;
	__be32			caps_31_0;
};

int mlx5_set_port_caps(struct mlx5_core_dev *dev, u8 port_num, u32 caps)
{
	struct mlx5_reg_pcap in;
	struct mlx5_reg_pcap out;

	memset(&in, 0, sizeof(in));
	in.caps_127_96 = cpu_to_be32(caps);
	in.port_num = port_num;

	return mlx5_core_access_reg(dev, &in, sizeof(in), &out,
				    sizeof(out), MLX5_REG_PCAP, 0, 1);
}
EXPORT_SYMBOL_GPL(mlx5_set_port_caps);

int mlx5_query_port_ptys(struct mlx5_core_dev *dev, u32 *ptys,
			 int ptys_size, int proto_mask, u8 local_port)
{
	u32 in[MLX5_ST_SZ_DW(ptys_reg)] = {0};

	MLX5_SET(ptys_reg, in, local_port, local_port);
	MLX5_SET(ptys_reg, in, proto_mask, proto_mask);
	return mlx5_core_access_reg(dev, in, sizeof(in), ptys,
				    ptys_size, MLX5_REG_PTYS, 0, 0);
}
EXPORT_SYMBOL_GPL(mlx5_query_port_ptys);

int mlx5_set_port_beacon(struct mlx5_core_dev *dev, u16 beacon_duration)
{
	u32 in[MLX5_ST_SZ_DW(mlcr_reg)]  = {0};
	u32 out[MLX5_ST_SZ_DW(mlcr_reg)];

	MLX5_SET(mlcr_reg, in, local_port, 1);
	MLX5_SET(mlcr_reg, in, beacon_duration, beacon_duration);
	return mlx5_core_access_reg(dev, in, sizeof(in), out,
				    sizeof(out), MLX5_REG_MLCR, 0, 1);
}

int mlx5_query_port_proto_cap(struct mlx5_core_dev *dev,
			      u32 *proto_cap, int proto_mask)
{
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	int err;

	err = mlx5_query_port_ptys(dev, out, sizeof(out), proto_mask, 1);
	if (err)
		return err;

	if (proto_mask == MLX5_PTYS_EN)
		*proto_cap = MLX5_GET(ptys_reg, out, eth_proto_capability);
	else
		*proto_cap = MLX5_GET(ptys_reg, out, ib_proto_capability);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_proto_cap);

int mlx5_query_port_proto_admin(struct mlx5_core_dev *dev,
				u32 *proto_admin, int proto_mask)
{
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	int err;

	err = mlx5_query_port_ptys(dev, out, sizeof(out), proto_mask, 1);
	if (err)
		return err;

	if (proto_mask == MLX5_PTYS_EN)
		*proto_admin = MLX5_GET(ptys_reg, out, eth_proto_admin);
	else
		*proto_admin = MLX5_GET(ptys_reg, out, ib_proto_admin);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_proto_admin);

int mlx5_query_port_link_width_oper(struct mlx5_core_dev *dev,
				    u8 *link_width_oper, u8 local_port)
{
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	int err;

	err = mlx5_query_port_ptys(dev, out, sizeof(out), MLX5_PTYS_IB, local_port);
	if (err)
		return err;

	*link_width_oper = MLX5_GET(ptys_reg, out, ib_link_width_oper);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_link_width_oper);

int mlx5_query_port_eth_proto_oper(struct mlx5_core_dev *dev,
				   u32 *proto_oper, u8 local_port)
{
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	int err;

	err = mlx5_query_port_ptys(dev, out, sizeof(out), MLX5_PTYS_EN,
				   local_port);
	if (err)
		return err;

	*proto_oper = MLX5_GET(ptys_reg, out, eth_proto_oper);

	return 0;
}
EXPORT_SYMBOL(mlx5_query_port_eth_proto_oper);

int mlx5_query_port_ib_proto_oper(struct mlx5_core_dev *dev,
				  u8 *proto_oper, u8 local_port)
{
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	int err;

	err = mlx5_query_port_ptys(dev, out, sizeof(out), MLX5_PTYS_IB,
				   local_port);
	if (err)
		return err;

	*proto_oper = MLX5_GET(ptys_reg, out, ib_proto_oper);

	return 0;
}
EXPORT_SYMBOL(mlx5_query_port_ib_proto_oper);

int mlx5_set_port_ptys(struct mlx5_core_dev *dev, bool an_disable,
		       u32 proto_admin, int proto_mask)
{
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];
	u32 in[MLX5_ST_SZ_DW(ptys_reg)];
	u8 an_disable_admin;
	u8 an_disable_cap;
	u8 an_status;

	mlx5_query_port_autoneg(dev, proto_mask, &an_status,
				&an_disable_cap, &an_disable_admin);
	if (!an_disable_cap && an_disable)
		return -EPERM;

	memset(in, 0, sizeof(in));

	MLX5_SET(ptys_reg, in, local_port, 1);
	MLX5_SET(ptys_reg, in, an_disable_admin, an_disable);
	MLX5_SET(ptys_reg, in, proto_mask, proto_mask);
	if (proto_mask == MLX5_PTYS_EN)
		MLX5_SET(ptys_reg, in, eth_proto_admin, proto_admin);
	else
		MLX5_SET(ptys_reg, in, ib_proto_admin, proto_admin);

	return mlx5_core_access_reg(dev, in, sizeof(in), out,
				    sizeof(out), MLX5_REG_PTYS, 0, 1);
}
EXPORT_SYMBOL_GPL(mlx5_set_port_ptys);

/* This function should be used after setting a port register only */
void mlx5_toggle_port_link(struct mlx5_core_dev *dev)
{
	enum mlx5_port_status ps;

	mlx5_query_port_admin_status(dev, &ps);
	mlx5_set_port_admin_status(dev, MLX5_PORT_DOWN);
	if (ps == MLX5_PORT_UP)
		mlx5_set_port_admin_status(dev, MLX5_PORT_UP);
}
EXPORT_SYMBOL_GPL(mlx5_toggle_port_link);

int mlx5_set_port_admin_status(struct mlx5_core_dev *dev,
			       enum mlx5_port_status status)
{
	u32 in[MLX5_ST_SZ_DW(paos_reg)] = {0};
	u32 out[MLX5_ST_SZ_DW(paos_reg)];

	MLX5_SET(paos_reg, in, local_port, 1);
	MLX5_SET(paos_reg, in, admin_status, status);
	MLX5_SET(paos_reg, in, ase, 1);
	return mlx5_core_access_reg(dev, in, sizeof(in), out,
				    sizeof(out), MLX5_REG_PAOS, 0, 1);
}
EXPORT_SYMBOL_GPL(mlx5_set_port_admin_status);

int mlx5_query_port_admin_status(struct mlx5_core_dev *dev,
				 enum mlx5_port_status *status)
{
	u32 in[MLX5_ST_SZ_DW(paos_reg)] = {0};
	u32 out[MLX5_ST_SZ_DW(paos_reg)];
	int err;

	MLX5_SET(paos_reg, in, local_port, 1);
	err = mlx5_core_access_reg(dev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_PAOS, 0, 0);
	if (err)
		return err;
	*status = MLX5_GET(paos_reg, out, admin_status);
	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_admin_status);

static void mlx5_query_port_mtu(struct mlx5_core_dev *dev, u16 *admin_mtu,
				u16 *max_mtu, u16 *oper_mtu, u8 port)
{
	u32 in[MLX5_ST_SZ_DW(pmtu_reg)] = {0};
	u32 out[MLX5_ST_SZ_DW(pmtu_reg)];

	MLX5_SET(pmtu_reg, in, local_port, port);
	mlx5_core_access_reg(dev, in, sizeof(in), out,
			     sizeof(out), MLX5_REG_PMTU, 0, 0);

	if (max_mtu)
		*max_mtu  = MLX5_GET(pmtu_reg, out, max_mtu);
	if (oper_mtu)
		*oper_mtu = MLX5_GET(pmtu_reg, out, oper_mtu);
	if (admin_mtu)
		*admin_mtu = MLX5_GET(pmtu_reg, out, admin_mtu);
}

int mlx5_set_port_mtu(struct mlx5_core_dev *dev, u16 mtu, u8 port)
{
	u32 in[MLX5_ST_SZ_DW(pmtu_reg)] = {0};
	u32 out[MLX5_ST_SZ_DW(pmtu_reg)];

	MLX5_SET(pmtu_reg, in, admin_mtu, mtu);
	MLX5_SET(pmtu_reg, in, local_port, port);
	return mlx5_core_access_reg(dev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_PMTU, 0, 1);
}
EXPORT_SYMBOL_GPL(mlx5_set_port_mtu);

void mlx5_query_port_max_mtu(struct mlx5_core_dev *dev, u16 *max_mtu,
			     u8 port)
{
	mlx5_query_port_mtu(dev, NULL, max_mtu, NULL, port);
}
EXPORT_SYMBOL_GPL(mlx5_query_port_max_mtu);

void mlx5_query_port_oper_mtu(struct mlx5_core_dev *dev, u16 *oper_mtu,
			      u8 port)
{
	mlx5_query_port_mtu(dev, NULL, NULL, oper_mtu, port);
}
EXPORT_SYMBOL_GPL(mlx5_query_port_oper_mtu);

int mlx5_query_module_num(struct mlx5_core_dev *dev, int *module_num)
{
	u32 in[MLX5_ST_SZ_DW(pmlp_reg)] = {0};
	u32 out[MLX5_ST_SZ_DW(pmlp_reg)];
	int module_mapping;
	int err;

	MLX5_SET(pmlp_reg, in, local_port, 1);
	err = mlx5_core_access_reg(dev, in, sizeof(in), out, sizeof(out),
				   MLX5_REG_PMLP, 0, 0);
	if (err)
		return err;

	module_mapping = MLX5_GET(pmlp_reg, out, lane0_module_mapping);
	*module_num = module_mapping & MLX5_EEPROM_IDENTIFIER_BYTE_MASK;

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_query_module_num);

int mlx5_query_module_eeprom(struct mlx5_core_dev *dev,
			     u16 offset, u16 size, u8 *data)
{
	u32 out[MLX5_ST_SZ_DW(mcia_reg)];
	u32 in[MLX5_ST_SZ_DW(mcia_reg)];
	int module_num;
	u16 i2c_addr;
	int status;
	int err;
	void *ptr = MLX5_ADDR_OF(mcia_reg, out, dword_0);

	err = mlx5_query_module_num(dev, &module_num);
	if (err)
		return err;

	memset(in, 0, sizeof(in));
	size = min_t(int, size, MLX5_EEPROM_MAX_BYTES);

	if (offset < MLX5_EEPROM_PAGE_LENGTH &&
	    offset + size > MLX5_EEPROM_PAGE_LENGTH)
		/* Cross pages read, read until offset 256 in low page */
		size -= offset + size - MLX5_EEPROM_PAGE_LENGTH;

	i2c_addr = MLX5_I2C_ADDR_LOW;
	if (offset >= MLX5_EEPROM_PAGE_LENGTH) {
		i2c_addr = MLX5_I2C_ADDR_HIGH;
		offset -= MLX5_EEPROM_PAGE_LENGTH;
	}

	MLX5_SET(mcia_reg, in, l, 0);
	MLX5_SET(mcia_reg, in, module, module_num);
	MLX5_SET(mcia_reg, in, i2c_device_address, i2c_addr);
	MLX5_SET(mcia_reg, in, page_number, 0);
	MLX5_SET(mcia_reg, in, device_address, offset);
	MLX5_SET(mcia_reg, in, size, size);

	err = mlx5_core_access_reg(dev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_MCIA, 0, 0);
	if (err)
		return err;

	status = MLX5_GET(mcia_reg, out, status);
	if (status) {
		mlx5_core_err(dev, "query_mcia_reg failed: status: 0x%x\n",
			      status);
		return -EIO;
	}

	memcpy(data, ptr, size);

	return size;
}
EXPORT_SYMBOL_GPL(mlx5_query_module_eeprom);

static int mlx5_query_port_pvlc(struct mlx5_core_dev *dev, u32 *pvlc,
				int pvlc_size,  u8 local_port)
{
	u32 in[MLX5_ST_SZ_DW(pvlc_reg)] = {0};

	MLX5_SET(pvlc_reg, in, local_port, local_port);
	return mlx5_core_access_reg(dev, in, sizeof(in), pvlc,
				    pvlc_size, MLX5_REG_PVLC, 0, 0);
}

int mlx5_query_port_vl_hw_cap(struct mlx5_core_dev *dev,
			      u8 *vl_hw_cap, u8 local_port)
{
	u32 out[MLX5_ST_SZ_DW(pvlc_reg)];
	int err;

	err = mlx5_query_port_pvlc(dev, out, sizeof(out), local_port);
	if (err)
		return err;

	*vl_hw_cap = MLX5_GET(pvlc_reg, out, vl_hw_cap);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_vl_hw_cap);

int mlx5_core_query_ib_ppcnt(struct mlx5_core_dev *dev,
			     u8 port_num, void *out, size_t sz)
{
	u32 *in;
	int err;

	in  = kvzalloc(sz, GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		return err;
	}

	MLX5_SET(ppcnt_reg, in, local_port, port_num);

	MLX5_SET(ppcnt_reg, in, grp, MLX5_INFINIBAND_PORT_COUNTERS_GROUP);
	err = mlx5_core_access_reg(dev, in, sz, out,
				   sz, MLX5_REG_PPCNT, 0, 0);

	kvfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_query_ib_ppcnt);

static int mlx5_query_pfcc_reg(struct mlx5_core_dev *dev, u32 *out,
			       u32 out_size)
{
	u32 in[MLX5_ST_SZ_DW(pfcc_reg)] = {0};

	MLX5_SET(pfcc_reg, in, local_port, 1);

	return mlx5_core_access_reg(dev, in, sizeof(in), out,
				    out_size, MLX5_REG_PFCC, 0, 0);
}

int mlx5_set_port_pause(struct mlx5_core_dev *dev, u32 rx_pause, u32 tx_pause)
{
	u32 in[MLX5_ST_SZ_DW(pfcc_reg)] = {0};
	u32 out[MLX5_ST_SZ_DW(pfcc_reg)];

	MLX5_SET(pfcc_reg, in, local_port, 1);
	MLX5_SET(pfcc_reg, in, pptx, tx_pause);
	MLX5_SET(pfcc_reg, in, pprx, rx_pause);

	return mlx5_core_access_reg(dev, in, sizeof(in), out,
				    sizeof(out), MLX5_REG_PFCC, 0, 1);
}
EXPORT_SYMBOL_GPL(mlx5_set_port_pause);

int mlx5_query_port_pause(struct mlx5_core_dev *dev,
			  u32 *rx_pause, u32 *tx_pause)
{
	u32 out[MLX5_ST_SZ_DW(pfcc_reg)];
	int err;

	err = mlx5_query_pfcc_reg(dev, out, sizeof(out));
	if (err)
		return err;

	if (rx_pause)
		*rx_pause = MLX5_GET(pfcc_reg, out, pprx);

	if (tx_pause)
		*tx_pause = MLX5_GET(pfcc_reg, out, pptx);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_pause);

int mlx5_set_port_pfc_prevention(struct mlx5_core_dev *dev,
				 u16 pfc_preven_critical, u16 pfc_preven_minor)
{
	u32 in[MLX5_ST_SZ_DW(pfcc_reg)] = {0};
	u32 out[MLX5_ST_SZ_DW(pfcc_reg)];

	MLX5_SET(pfcc_reg, in, local_port, 1);
	MLX5_SET(pfcc_reg, in, pptx_mask_n, 1);
	MLX5_SET(pfcc_reg, in, pprx_mask_n, 1);
	MLX5_SET(pfcc_reg, in, ppan_mask_n, 1);
	MLX5_SET(pfcc_reg, in, critical_stall_mask, 1);
	MLX5_SET(pfcc_reg, in, minor_stall_mask, 1);
	MLX5_SET(pfcc_reg, in, device_stall_critical_watermark, pfc_preven_critical);
	MLX5_SET(pfcc_reg, in, device_stall_minor_watermark, pfc_preven_minor);

	return mlx5_core_access_reg(dev, in, sizeof(in), out,
				    sizeof(out), MLX5_REG_PFCC, 0, 1);
}

int mlx5_query_port_pfc_prevention(struct mlx5_core_dev *dev,
				   u16 *pfc_preven_critical)
{
	u32 out[MLX5_ST_SZ_DW(pfcc_reg)];
	int err;

	err = mlx5_query_pfcc_reg(dev, out, sizeof(out));
	if (err)
		return err;

	if (pfc_preven_critical)
		*pfc_preven_critical = MLX5_GET(pfcc_reg, out,
						device_stall_critical_watermark);

	return 0;
}

int mlx5_set_port_stall_watermark(struct mlx5_core_dev *dev,
				  u16 stall_critical_watermark,
				  u16 stall_minor_watermark)
{
	u32 in[MLX5_ST_SZ_DW(pfcc_reg)] = {0};
	u32 out[MLX5_ST_SZ_DW(pfcc_reg)];

	MLX5_SET(pfcc_reg, in, local_port, 1);
	MLX5_SET(pfcc_reg, in, pptx_mask_n, 1);
	MLX5_SET(pfcc_reg, in, pprx_mask_n, 1);
	MLX5_SET(pfcc_reg, in, ppan_mask_n, 1);
	MLX5_SET(pfcc_reg, in, critical_stall_mask, 1);
	MLX5_SET(pfcc_reg, in, minor_stall_mask, 1);
	MLX5_SET(pfcc_reg, in, device_stall_critical_watermark,
		 stall_critical_watermark);
	MLX5_SET(pfcc_reg, in, device_stall_minor_watermark, stall_minor_watermark);

	return mlx5_core_access_reg(dev, in, sizeof(in), out,
				    sizeof(out), MLX5_REG_PFCC, 0, 1);
}

int mlx5_query_port_stall_watermark(struct mlx5_core_dev *dev,
				    u16 *stall_critical_watermark,
				    u16 *stall_minor_watermark)
{
	u32 out[MLX5_ST_SZ_DW(pfcc_reg)];
	int err;

	err = mlx5_query_pfcc_reg(dev, out, sizeof(out));
	if (err)
		return err;

	if (stall_critical_watermark)
		*stall_critical_watermark = MLX5_GET(pfcc_reg, out,
						     device_stall_critical_watermark);

	if (stall_minor_watermark)
		*stall_minor_watermark = MLX5_GET(pfcc_reg, out,
						  device_stall_minor_watermark);

	return 0;
}

int mlx5_set_port_pfc(struct mlx5_core_dev *dev, u8 pfc_en_tx, u8 pfc_en_rx)
{
	u32 in[MLX5_ST_SZ_DW(pfcc_reg)] = {0};
	u32 out[MLX5_ST_SZ_DW(pfcc_reg)];

	MLX5_SET(pfcc_reg, in, local_port, 1);
	MLX5_SET(pfcc_reg, in, pfctx, pfc_en_tx);
	MLX5_SET(pfcc_reg, in, pfcrx, pfc_en_rx);
	MLX5_SET_TO_ONES(pfcc_reg, in, prio_mask_tx);
	MLX5_SET_TO_ONES(pfcc_reg, in, prio_mask_rx);

	return mlx5_core_access_reg(dev, in, sizeof(in), out,
				    sizeof(out), MLX5_REG_PFCC, 0, 1);
}
EXPORT_SYMBOL_GPL(mlx5_set_port_pfc);

int mlx5_query_port_pfc(struct mlx5_core_dev *dev, u8 *pfc_en_tx, u8 *pfc_en_rx)
{
	u32 out[MLX5_ST_SZ_DW(pfcc_reg)];
	int err;

	err = mlx5_query_pfcc_reg(dev, out, sizeof(out));
	if (err)
		return err;

	if (pfc_en_tx)
		*pfc_en_tx = MLX5_GET(pfcc_reg, out, pfctx);

	if (pfc_en_rx)
		*pfc_en_rx = MLX5_GET(pfcc_reg, out, pfcrx);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_pfc);

void mlx5_query_port_autoneg(struct mlx5_core_dev *dev, int proto_mask,
			     u8 *an_status,
			     u8 *an_disable_cap, u8 *an_disable_admin)
{
	u32 out[MLX5_ST_SZ_DW(ptys_reg)];

	*an_status = 0;
	*an_disable_cap = 0;
	*an_disable_admin = 0;

	if (mlx5_query_port_ptys(dev, out, sizeof(out), proto_mask, 1))
		return;

	*an_status = MLX5_GET(ptys_reg, out, an_status);
	*an_disable_cap = MLX5_GET(ptys_reg, out, an_disable_cap);
	*an_disable_admin = MLX5_GET(ptys_reg, out, an_disable_admin);
}
EXPORT_SYMBOL_GPL(mlx5_query_port_autoneg);

int mlx5_max_tc(struct mlx5_core_dev *mdev)
{
	u8 num_tc = MLX5_CAP_GEN(mdev, max_tc) ? : 8;

	return num_tc - 1;
}

int mlx5_query_port_dcbx_param(struct mlx5_core_dev *mdev, u32 *out)
{
	u32 in[MLX5_ST_SZ_DW(dcbx_param)] = {0};

	MLX5_SET(dcbx_param, in, port_number, 1);

	return  mlx5_core_access_reg(mdev, in, sizeof(in), out,
				    sizeof(in), MLX5_REG_DCBX_PARAM, 0, 0);
}

int mlx5_set_port_dcbx_param(struct mlx5_core_dev *mdev, u32 *in)
{
	u32 out[MLX5_ST_SZ_DW(dcbx_param)];

	MLX5_SET(dcbx_param, in, port_number, 1);

	return mlx5_core_access_reg(mdev, in, sizeof(out), out,
				    sizeof(out), MLX5_REG_DCBX_PARAM, 0, 1);
}

int mlx5_set_port_prio_tc(struct mlx5_core_dev *mdev, u8 *prio_tc)
{
	u32 in[MLX5_ST_SZ_DW(qtct_reg)] = {0};
	u32 out[MLX5_ST_SZ_DW(qtct_reg)];
	int err;
	int i;

	for (i = 0; i < 8; i++) {
		if (prio_tc[i] > mlx5_max_tc(mdev))
			return -EINVAL;

		MLX5_SET(qtct_reg, in, prio, i);
		MLX5_SET(qtct_reg, in, tclass, prio_tc[i]);

		err = mlx5_core_access_reg(mdev, in, sizeof(in), out,
					   sizeof(out), MLX5_REG_QTCT, 0, 1);
		if (err)
			return err;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_set_port_prio_tc);

int mlx5_query_port_prio_tc(struct mlx5_core_dev *mdev,
			    u8 prio, u8 *tc)
{
	u32 in[MLX5_ST_SZ_DW(qtct_reg)];
	u32 out[MLX5_ST_SZ_DW(qtct_reg)];
	int err;

	memset(in, 0, sizeof(in));
	memset(out, 0, sizeof(out));

	MLX5_SET(qtct_reg, in, port_number, 1);
	MLX5_SET(qtct_reg, in, prio, prio);

	err = mlx5_core_access_reg(mdev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_QTCT, 0, 0);
	if (!err)
		*tc = MLX5_GET(qtct_reg, out, tclass);

	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_prio_tc);

static int mlx5_set_port_qetcr_reg(struct mlx5_core_dev *mdev, u32 *in,
				   int inlen)
{
	u32 out[MLX5_ST_SZ_DW(qetc_reg)];

	if (!MLX5_CAP_GEN(mdev, ets))
		return -EOPNOTSUPP;

	return mlx5_core_access_reg(mdev, in, inlen, out, sizeof(out),
				    MLX5_REG_QETCR, 0, 1);
}

static int mlx5_query_port_qetcr_reg(struct mlx5_core_dev *mdev, u32 *out,
				     int outlen)
{
	u32 in[MLX5_ST_SZ_DW(qetc_reg)];

	if (!MLX5_CAP_GEN(mdev, ets))
		return -EOPNOTSUPP;

	memset(in, 0, sizeof(in));
	return mlx5_core_access_reg(mdev, in, sizeof(in), out, outlen,
				    MLX5_REG_QETCR, 0, 0);
}

int mlx5_set_port_tc_group(struct mlx5_core_dev *mdev, u8 *tc_group)
{
	u32 in[MLX5_ST_SZ_DW(qetc_reg)] = {0};
	int i;

	for (i = 0; i <= mlx5_max_tc(mdev); i++) {
		MLX5_SET(qetc_reg, in, tc_configuration[i].g, 1);
		MLX5_SET(qetc_reg, in, tc_configuration[i].group, tc_group[i]);
	}

	return mlx5_set_port_qetcr_reg(mdev, in, sizeof(in));
}
EXPORT_SYMBOL_GPL(mlx5_set_port_tc_group);

int mlx5_query_port_tc_group(struct mlx5_core_dev *mdev,
			     u8 tc, u8 *tc_group)
{
	u32 out[MLX5_ST_SZ_DW(qetc_reg)];
	void *ets_tcn_conf;
	int err;

	err = mlx5_query_port_qetcr_reg(mdev, out, sizeof(out));
	if (err)
		return err;

	ets_tcn_conf = MLX5_ADDR_OF(qetc_reg, out,
				    tc_configuration[tc]);

	*tc_group = MLX5_GET(ets_tcn_config_reg, ets_tcn_conf,
			     group);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_tc_group);

int mlx5_set_port_tc_bw_alloc(struct mlx5_core_dev *mdev, u8 *tc_bw)
{
	u32 in[MLX5_ST_SZ_DW(qetc_reg)] = {0};
	int i;

	for (i = 0; i <= mlx5_max_tc(mdev); i++) {
		MLX5_SET(qetc_reg, in, tc_configuration[i].b, 1);
		MLX5_SET(qetc_reg, in, tc_configuration[i].bw_allocation, tc_bw[i]);
	}

	return mlx5_set_port_qetcr_reg(mdev, in, sizeof(in));
}
EXPORT_SYMBOL_GPL(mlx5_set_port_tc_bw_alloc);

int mlx5_query_port_tc_bw_alloc(struct mlx5_core_dev *mdev,
				u8 tc, u8 *bw_pct)
{
	u32 out[MLX5_ST_SZ_DW(qetc_reg)];
	void *ets_tcn_conf;
	int err;

	err = mlx5_query_port_qetcr_reg(mdev, out, sizeof(out));
	if (err)
		return err;

	ets_tcn_conf = MLX5_ADDR_OF(qetc_reg, out,
				    tc_configuration[tc]);

	*bw_pct = MLX5_GET(ets_tcn_config_reg, ets_tcn_conf,
			   bw_allocation);

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_tc_bw_alloc);

int mlx5_modify_port_ets_rate_limit(struct mlx5_core_dev *mdev,
				    u8 *max_bw_value,
				    u8 *max_bw_units)
{
	u32 in[MLX5_ST_SZ_DW(qetc_reg)] = {0};
	void *ets_tcn_conf;
	int i;

	MLX5_SET(qetc_reg, in, port_number, 1);

	for (i = 0; i <= mlx5_max_tc(mdev); i++) {
		ets_tcn_conf = MLX5_ADDR_OF(qetc_reg, in, tc_configuration[i]);

		MLX5_SET(ets_tcn_config_reg, ets_tcn_conf, r, 1);
		MLX5_SET(ets_tcn_config_reg, ets_tcn_conf, max_bw_units,
			 max_bw_units[i]);
		MLX5_SET(ets_tcn_config_reg, ets_tcn_conf, max_bw_value,
			 max_bw_value[i]);
	}

	return mlx5_set_port_qetcr_reg(mdev, in, sizeof(in));
}
EXPORT_SYMBOL_GPL(mlx5_modify_port_ets_rate_limit);

int mlx5_query_port_ets_rate_limit(struct mlx5_core_dev *mdev,
				   u8 *max_bw_value,
				   u8 *max_bw_units)
{
	u32 out[MLX5_ST_SZ_DW(qetc_reg)];
	void *ets_tcn_conf;
	int err;
	int i;

	err = mlx5_query_port_qetcr_reg(mdev, out, sizeof(out));
	if (err)
		return err;

	for (i = 0; i <= mlx5_max_tc(mdev); i++) {
		ets_tcn_conf = MLX5_ADDR_OF(qetc_reg, out, tc_configuration[i]);

		max_bw_value[i] = MLX5_GET(ets_tcn_config_reg, ets_tcn_conf,
					   max_bw_value);
		max_bw_units[i] = MLX5_GET(ets_tcn_config_reg, ets_tcn_conf,
					   max_bw_units);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_ets_rate_limit);

int mlx5_set_port_wol(struct mlx5_core_dev *mdev, u8 wol_mode)
{
	u32 in[MLX5_ST_SZ_DW(set_wol_rol_in)]   = {0};
	u32 out[MLX5_ST_SZ_DW(set_wol_rol_out)] = {0};

	MLX5_SET(set_wol_rol_in, in, opcode, MLX5_CMD_OP_SET_WOL_ROL);
	MLX5_SET(set_wol_rol_in, in, wol_mode_valid, 1);
	MLX5_SET(set_wol_rol_in, in, wol_mode, wol_mode);
	return mlx5_cmd_exec(mdev, in, sizeof(in), out, sizeof(out));
}
EXPORT_SYMBOL_GPL(mlx5_set_port_wol);

int mlx5_query_port_wol(struct mlx5_core_dev *mdev, u8 *wol_mode)
{
	u32 in[MLX5_ST_SZ_DW(query_wol_rol_in)]   = {0};
	u32 out[MLX5_ST_SZ_DW(query_wol_rol_out)] = {0};
	int err;

	MLX5_SET(query_wol_rol_in, in, opcode, MLX5_CMD_OP_QUERY_WOL_ROL);
	err = mlx5_cmd_exec(mdev, in, sizeof(in), out, sizeof(out));
	if (!err)
		*wol_mode = MLX5_GET(query_wol_rol_out, out, wol_mode);

	return err;
}
EXPORT_SYMBOL_GPL(mlx5_query_port_wol);

static int mlx5_query_pddr(struct mlx5_core_dev *mdev,
			   int page_select, u32 *out, int outlen)
{
	u32 in[MLX5_ST_SZ_DW(pddr_reg)] = {0};

	if (!MLX5_CAP_PCAM_REG(mdev, pddr))
		return -EOPNOTSUPP;

	MLX5_SET(pddr_reg, in, local_port, 1);
	MLX5_SET(pddr_reg, in, page_select, page_select);

	return mlx5_core_access_reg(mdev, in, sizeof(in), out, outlen, MLX5_REG_PDDR, 0, 0);
}

int mlx5_query_pddr_troubleshooting_info(struct mlx5_core_dev *mdev,
					 u16 *monitor_opcode,
					 u8 *status_message)
{
	int outlen = MLX5_ST_SZ_BYTES(pddr_reg);
	u32 out[MLX5_ST_SZ_DW(pddr_reg)] = {0};
	int err;

	err = mlx5_query_pddr(mdev, MLX5_PDDR_TROUBLESHOOTING_INFO_PAGE,
			      out, outlen);
	if (err)
		return err;

	if (monitor_opcode)
		*monitor_opcode = MLX5_GET(pddr_reg, out,
					   page_data.troubleshooting_info_page.status_opcode.monitor_opcodes);

	if (status_message)
		strncpy(status_message,
			MLX5_ADDR_OF(pddr_reg, out, page_data.troubleshooting_info_page.status_message),
			MLX5_FLD_SZ_BYTES(troubleshooting_info_page_layout, status_message));

	return 0;
}

int mlx5_query_port_cong_status(struct mlx5_core_dev *mdev, int protocol,
				int priority, int *is_enable)
{
	u32 in[MLX5_ST_SZ_DW(query_cong_status_in)];
	u32 out[MLX5_ST_SZ_DW(query_cong_status_out)];
	int err;

	memset(in, 0, sizeof(in));
	memset(out, 0, sizeof(out));

	MLX5_SET(query_cong_status_in, in, opcode,
		 MLX5_CMD_OP_QUERY_CONG_STATUS);
	MLX5_SET(query_cong_status_in, in, cong_protocol, protocol);
	MLX5_SET(query_cong_status_in, in, priority, priority);

	err = mlx5_cmd_exec(mdev, in, sizeof(in), out, sizeof(out));
	if (!err)
		*is_enable = MLX5_GET(query_cong_status_out, out, enable);
	return err;
}

int mlx5_modify_port_cong_status(struct mlx5_core_dev *mdev, int protocol,
				 int priority, int enable)
{
	u32 in[MLX5_ST_SZ_DW(modify_cong_status_in)];
	u32 out[MLX5_ST_SZ_DW(modify_cong_status_out)];

	memset(in, 0, sizeof(in));
	memset(out, 0, sizeof(out));

	MLX5_SET(modify_cong_status_in, in, opcode,
		 MLX5_CMD_OP_MODIFY_CONG_STATUS);
	MLX5_SET(modify_cong_status_in, in, cong_protocol, protocol);
	MLX5_SET(modify_cong_status_in, in, priority, priority);
	MLX5_SET(modify_cong_status_in, in, enable, enable);

	return mlx5_cmd_exec(mdev, in, sizeof(in), out, sizeof(out));
}

int mlx5_query_port_cong_params(struct mlx5_core_dev *mdev, int protocol,
				void *out, int out_size)
{
	u32 in[MLX5_ST_SZ_DW(query_cong_params_in)];

	memset(in, 0, sizeof(in));

	MLX5_SET(query_cong_params_in, in, opcode,
		 MLX5_CMD_OP_QUERY_CONG_PARAMS);
	MLX5_SET(query_cong_params_in, in, cong_protocol, protocol);

	return mlx5_cmd_exec(mdev, in, sizeof(in), out, out_size);
}

int mlx5_modify_port_cong_params(struct mlx5_core_dev *mdev,
				 void *in, int in_size)
{
	u32 out[MLX5_ST_SZ_DW(modify_cong_params_out)];

	memset(out, 0, sizeof(out));

	return mlx5_cmd_exec(mdev, in, in_size, out, sizeof(out));
}

static int mlx5_query_ports_check(struct mlx5_core_dev *mdev, u32 *out,
				  int outlen)
{
	u32 in[MLX5_ST_SZ_DW(pcmr_reg)] = {0};

	MLX5_SET(pcmr_reg, in, local_port, 1);
	return mlx5_core_access_reg(mdev, in, sizeof(in), out,
				    outlen, MLX5_REG_PCMR, 0, 0);
}

static int mlx5_set_ports_check(struct mlx5_core_dev *mdev, u32 *in, int inlen)
{
	u32 out[MLX5_ST_SZ_DW(pcmr_reg)];

	return mlx5_core_access_reg(mdev, in, inlen, out,
				    sizeof(out), MLX5_REG_PCMR, 0, 1);
}

int mlx5_set_port_fcs(struct mlx5_core_dev *mdev, u8 enable)
{
	u32 in[MLX5_ST_SZ_DW(pcmr_reg)] = {0};

	MLX5_SET(pcmr_reg, in, local_port, 1);
	MLX5_SET(pcmr_reg, in, fcs_chk, enable);
	return mlx5_set_ports_check(mdev, in, sizeof(in));
}

void mlx5_query_port_fcs(struct mlx5_core_dev *mdev, bool *supported,
			 bool *enabled)
{
	u32 out[MLX5_ST_SZ_DW(pcmr_reg)];
	/* Default values for FW which do not support MLX5_REG_PCMR */
	*supported = false;
	*enabled = true;

	if (!MLX5_CAP_GEN(mdev, ports_check))
		return;

	if (mlx5_query_ports_check(mdev, out, sizeof(out)))
		return;

	*supported = !!(MLX5_GET(pcmr_reg, out, fcs_cap));
	*enabled = !!(MLX5_GET(pcmr_reg, out, fcs_chk));
}

const char *mlx5_pme_status_to_string(enum port_module_event_status_type status)
{
	switch (status) {
	case MLX5_MODULE_STATUS_PLUGGED:
		return "Cable plugged";
	case MLX5_MODULE_STATUS_UNPLUGGED:
		return "Cable unplugged";
	case MLX5_MODULE_STATUS_ERROR:
		return "Cable error";
	case MLX5_MODULE_STATUS_DISABLED:
		return "Cable disabled";
	default:
		return "Unknown status";
	}
}

const char *mlx5_pme_error_to_string(enum port_module_event_error_type error)
{
	switch (error) {
	case MLX5_MODULE_EVENT_ERROR_POWER_BUDGET_EXCEEDED:
		return "Power budget exceeded";
	case MLX5_MODULE_EVENT_ERROR_LONG_RANGE_FOR_NON_MLNX_CABLE_MODULE:
		return "Long Range for non MLNX cable";
	case MLX5_MODULE_EVENT_ERROR_BUS_STUCK:
		return "Bus stuck (I2C or data shorted)";
	case MLX5_MODULE_EVENT_ERROR_NO_EEPROM_RETRY_TIMEOUT:
		return "No EEPROM/retry timeout";
	case MLX5_MODULE_EVENT_ERROR_ENFORCE_PART_NUMBER_LIST:
		return "Enforce part number list";
	case MLX5_MODULE_EVENT_ERROR_UNKNOWN_IDENTIFIER:
		return "Unknown identifier";
	case MLX5_MODULE_EVENT_ERROR_HIGH_TEMPERATURE:
		return "High Temperature";
	case MLX5_MODULE_EVENT_ERROR_BAD_CABLE:
		return "Bad or shorted cable/module";
	case MLX5_MODULE_EVENT_ERROR_PCIE_POWER_SLOT_EXCEEDED:
		return "One or more network ports have been powered down due to insufficient/unadvertised power on the PCIe slot. Please refer to the card's user manual for power specifications or contact Mellanox support";
	default:
		return "Unknown error";
	}
}

void mlx5_port_module_event(struct mlx5_core_dev *dev, struct mlx5_eqe *eqe)
{
	enum port_module_event_status_type module_status;
	enum port_module_event_error_type error_type;
	struct mlx5_eqe_port_module *module_event_eqe;
	struct mlx5_priv *priv = &dev->priv;
	const char *status_str, *error_str;
	u8 module_num;

	module_event_eqe = &eqe->data.port_module;
	module_num = module_event_eqe->module;
	module_status = module_event_eqe->module_status &
			PORT_MODULE_EVENT_MODULE_STATUS_MASK;
	error_type = module_event_eqe->error_type &
		     PORT_MODULE_EVENT_ERROR_TYPE_MASK;

	if (module_status < MLX5_MODULE_STATUS_NUM)
		priv->pme_stats.status_counters[module_status]++;
	status_str = mlx5_pme_status_to_string(module_status);

	if (module_status == MLX5_MODULE_STATUS_ERROR) {
		if (error_type < MLX5_MODULE_EVENT_ERROR_NUM)
			priv->pme_stats.error_counters[error_type]++;
		error_str = mlx5_pme_error_to_string(error_type);
	}

	if (!printk_ratelimit())
		return;

	if (module_status == MLX5_MODULE_STATUS_ERROR)
		mlx5_core_err(dev,
			      "Port module event[error]: module %u, %s, %s\n",
			      module_num, status_str, error_str);
	else
		mlx5_core_info(dev,
			       "Port module event: module %u, %s\n",
			       module_num, status_str);
}

int mlx5_query_mtpps(struct mlx5_core_dev *mdev, u32 *mtpps, u32 mtpps_size)
{
	u32 in[MLX5_ST_SZ_DW(mtpps_reg)] = {0};

	return mlx5_core_access_reg(mdev, in, sizeof(in), mtpps,
				    mtpps_size, MLX5_REG_MTPPS, 0, 0);
}

int mlx5_set_mtpps(struct mlx5_core_dev *mdev, u32 *mtpps, u32 mtpps_size)
{
	u32 out[MLX5_ST_SZ_DW(mtpps_reg)] = {0};

	return mlx5_core_access_reg(mdev, mtpps, mtpps_size, out,
				    sizeof(out), MLX5_REG_MTPPS, 0, 1);
}

int mlx5_query_mtppse(struct mlx5_core_dev *mdev, u8 pin, u8 *arm, u8 *mode)
{
	u32 out[MLX5_ST_SZ_DW(mtppse_reg)] = {0};
	u32 in[MLX5_ST_SZ_DW(mtppse_reg)] = {0};
	int err = 0;

	MLX5_SET(mtppse_reg, in, pin, pin);

	err = mlx5_core_access_reg(mdev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_MTPPSE, 0, 0);
	if (err)
		return err;

	*arm = MLX5_GET(mtppse_reg, in, event_arm);
	*mode = MLX5_GET(mtppse_reg, in, event_generation_mode);

	return err;
}

int mlx5_set_mtppse(struct mlx5_core_dev *mdev, u8 pin, u8 arm, u8 mode)
{
	u32 out[MLX5_ST_SZ_DW(mtppse_reg)] = {0};
	u32 in[MLX5_ST_SZ_DW(mtppse_reg)] = {0};

	MLX5_SET(mtppse_reg, in, pin, pin);
	MLX5_SET(mtppse_reg, in, event_arm, arm);
	MLX5_SET(mtppse_reg, in, event_generation_mode, mode);

	return mlx5_core_access_reg(mdev, in, sizeof(in), out,
				    sizeof(out), MLX5_REG_MTPPSE, 0, 1);
}

int mlx5_set_trust_state(struct mlx5_core_dev *mdev, u8 trust_state)
{
	u32 out[MLX5_ST_SZ_DW(qpts_reg)] = {};
	u32 in[MLX5_ST_SZ_DW(qpts_reg)] = {};
	int err;

	MLX5_SET(qpts_reg, in, local_port, 1);
	MLX5_SET(qpts_reg, in, trust_state, trust_state);

	err = mlx5_core_access_reg(mdev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_QPTS, 0, 1);
	return err;
}

int mlx5_query_trust_state(struct mlx5_core_dev *mdev, u8 *trust_state)
{
	u32 out[MLX5_ST_SZ_DW(qpts_reg)] = {};
	u32 in[MLX5_ST_SZ_DW(qpts_reg)] = {};
	int err;

	MLX5_SET(qpts_reg, in, local_port, 1);

	err = mlx5_core_access_reg(mdev, in, sizeof(in), out,
				   sizeof(out), MLX5_REG_QPTS, 0, 0);
	if (!err)
		*trust_state = MLX5_GET(qpts_reg, out, trust_state);

	return err;
}

int mlx5_set_dscp2prio(struct mlx5_core_dev *mdev, u8 dscp, u8 prio)
{
	int sz = MLX5_ST_SZ_BYTES(qpdpm_reg);
	void *qpdpm_dscp;
	void *out;
	void *in;
	int err;

	in = kzalloc(sz, GFP_KERNEL);
	out = kzalloc(sz, GFP_KERNEL);
	if (!in || !out) {
		err = -ENOMEM;
		goto out;
	}

	MLX5_SET(qpdpm_reg, in, local_port, 1);
	err = mlx5_core_access_reg(mdev, in, sz, out, sz, MLX5_REG_QPDPM, 0, 0);
	if (err)
		goto out;

	memcpy(in, out, sz);
	MLX5_SET(qpdpm_reg, in, local_port, 1);

	/* Update the corresponding dscp entry */
	qpdpm_dscp = MLX5_ADDR_OF(qpdpm_reg, in, dscp[dscp]);
	MLX5_SET16(qpdpm_dscp_reg, qpdpm_dscp, prio, prio);
	MLX5_SET16(qpdpm_dscp_reg, qpdpm_dscp, e, 1);
	err = mlx5_core_access_reg(mdev, in, sz, out, sz, MLX5_REG_QPDPM, 0, 1);

out:
	kfree(in);
	kfree(out);
	return err;
}

/* dscp2prio[i]: priority that dscp i mapped to */
#define MLX5E_SUPPORTED_DSCP 64
int mlx5_query_dscp2prio(struct mlx5_core_dev *mdev, u8 *dscp2prio)
{
	int sz = MLX5_ST_SZ_BYTES(qpdpm_reg);
	void *qpdpm_dscp;
	void *out;
	void *in;
	int err;
	int i;

	in = kzalloc(sz, GFP_KERNEL);
	out = kzalloc(sz, GFP_KERNEL);
	if (!in || !out) {
		err = -ENOMEM;
		goto out;
	}

	MLX5_SET(qpdpm_reg, in, local_port, 1);
	err = mlx5_core_access_reg(mdev, in, sz, out, sz, MLX5_REG_QPDPM, 0, 0);
	if (err)
		goto out;

	for (i = 0; i < (MLX5E_SUPPORTED_DSCP); i++) {
		qpdpm_dscp = MLX5_ADDR_OF(qpdpm_reg, out, dscp[i]);
		dscp2prio[i] = MLX5_GET16(qpdpm_dscp_reg, qpdpm_dscp, prio);
	}

out:
	kfree(in);
	kfree(out);
	return err;
}

static int is_valid_vf(struct mlx5_core_dev *dev, int vf)
{
	struct pci_dev *pdev = dev->pdev;

	if (vf == 1)
		return 1;

	if (mlx5_core_is_pf(dev))
		return (vf <= pci_num_vf(pdev)) && (vf >= 1);

	return 0;
}

int mlx5_core_query_gids(struct mlx5_core_dev *dev, u8 other_vport,
			 u8 port_num, u16  vf_num, u16 gid_index,
			 union ib_gid *gid)
{
	int in_sz = MLX5_ST_SZ_BYTES(query_hca_vport_gid_in);
	int out_sz = MLX5_ST_SZ_BYTES(query_hca_vport_gid_out);
	int is_group_manager;
	void *out = NULL;
	void *in = NULL;
	union ib_gid *tmp;
	int tbsz;
	int nout;
	int err;

	vf_num += 1;
	if (!is_valid_vf(dev, vf_num)) {
		mlx5_core_warn(dev, "invalid vf number %d", vf_num);
		return -EINVAL;
	}

	is_group_manager = MLX5_CAP_GEN(dev, vport_group_manager);
	tbsz = mlx5_get_gid_table_len(MLX5_CAP_GEN(dev, gid_table_size));
	mlx5_core_dbg(dev, "vf_num %d, index %d, gid_table_size %d\n",
		      vf_num, gid_index, tbsz);

	if (gid_index > tbsz && gid_index != 0xffff)
		return -EINVAL;

	if (gid_index == 0xffff)
		nout = tbsz;
	else
		nout = 1;

	out_sz += nout * sizeof(*gid);

	in = kzalloc(in_sz, GFP_KERNEL);
	out = kzalloc(out_sz, GFP_KERNEL);
	if (!in || !out) {
		err = -ENOMEM;
		goto out;
	}

	MLX5_SET(query_hca_vport_gid_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_VPORT_GID);
	if (other_vport) {
		if (is_group_manager) {
			MLX5_SET(query_hca_vport_gid_in, in, vport_number, vf_num);
			MLX5_SET(query_hca_vport_gid_in, in, other_vport, 1);
		} else {
			err = -EPERM;
			goto out;
		}
	}
	MLX5_SET(query_hca_vport_gid_in, in, gid_index, gid_index);

	if (MLX5_CAP_GEN(dev, num_ports) == 2)
		MLX5_SET(query_hca_vport_gid_in, in, port_num, port_num);

	err = mlx5_cmd_exec(dev, in, in_sz, out, out_sz);
	if (err)
		goto out;

	tmp = out + MLX5_ST_SZ_BYTES(query_hca_vport_gid_out);
	gid->global.subnet_prefix = tmp->global.subnet_prefix;
	gid->global.interface_id = tmp->global.interface_id;

out:
	kfree(in);
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_query_gids);

int mlx5_core_query_pkeys(struct mlx5_core_dev *dev, u8 other_vport,
			  u8 port_num, u16 vf_num, u16 pkey_index,
			  u16 *pkey)
{
	int in_sz = MLX5_ST_SZ_BYTES(query_hca_vport_pkey_in);
	int out_sz = MLX5_ST_SZ_BYTES(query_hca_vport_pkey_out);
	int is_group_manager;
	void *out = NULL;
	void *in = NULL;
	void *pkarr;
	int nout;
	int tbsz;
	int err;
	int i;

	is_group_manager = MLX5_CAP_GEN(dev, vport_group_manager);
	mlx5_core_dbg(dev, "vf_num %d\n", vf_num);

	vf_num += 1;
	if (!is_valid_vf(dev, vf_num)) {
		mlx5_core_warn(dev, "invalid vf number %d", vf_num);
		return -EINVAL;
	}

	tbsz = mlx5_to_sw_pkey_sz(MLX5_CAP_GEN(dev, pkey_table_size));
	if (pkey_index > tbsz && pkey_index != 0xffff)
		return -EINVAL;

	if (pkey_index == 0xffff)
		nout = tbsz;
	else
		nout = 1;

	out_sz += nout * MLX5_ST_SZ_BYTES(pkey);

	in = kzalloc(in_sz, GFP_KERNEL);
	out = kzalloc(out_sz, GFP_KERNEL);
	if (!in || !out) {
		err = -ENOMEM;
		goto out;
	}

	MLX5_SET(query_hca_vport_pkey_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_VPORT_PKEY);
	if (other_vport) {
		if (is_group_manager) {
			MLX5_SET(query_hca_vport_pkey_in, in, vport_number, vf_num);
			MLX5_SET(query_hca_vport_pkey_in, in, other_vport, 1);
		} else {
			err = -EPERM;
			goto out;
		}
	}
	MLX5_SET(query_hca_vport_pkey_in, in, pkey_index, pkey_index);

	if (MLX5_CAP_GEN(dev, num_ports) == 2)
		MLX5_SET(query_hca_vport_pkey_in, in, port_num, port_num);

	err = mlx5_cmd_exec(dev, in, in_sz, out, out_sz);
	if (err)
		goto out;

	pkarr = out + MLX5_ST_SZ_BYTES(query_hca_vport_pkey_out);
	for (i = 0; i < nout; i++, pkey++, pkarr += MLX5_ST_SZ_BYTES(pkey))
		*pkey = MLX5_GET_PR(pkey, pkarr, pkey);

out:
	kfree(in);
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_query_pkeys);

int mlx5_core_query_hca_vport_context(struct mlx5_core_dev *dev,
				      u8 other_vport, u8 port_num,
				      u16 vf_num,
				      struct mlx5_hca_vport_context *rep)
{
	int out_sz = MLX5_ST_SZ_BYTES(query_hca_vport_context_out);
	u32 in[MLX5_ST_SZ_DW(query_hca_vport_context_in)];
	int is_group_manager;
	void *out;
	void *ctx;
	int err;

	mlx5_core_dbg(dev, "vf_num %d\n", vf_num);
	is_group_manager = MLX5_CAP_GEN(dev, vport_group_manager);
	vf_num += 1;
	if (!is_valid_vf(dev, vf_num)) {
		mlx5_core_warn(dev, "invalid vf number %d", vf_num);
		return -EINVAL;
	}

	memset(in, 0, sizeof(in));
	out = kzalloc(out_sz, GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	MLX5_SET(query_hca_vport_context_in, in, opcode, MLX5_CMD_OP_QUERY_HCA_VPORT_CONTEXT);

	if (other_vport) {
		if (is_group_manager) {
			MLX5_SET(query_hca_vport_context_in, in, other_vport, 1);
			MLX5_SET(query_hca_vport_context_in, in, vport_number, vf_num);
		} else {
			err = -EPERM;
			goto ex;
		}
	}

	if (MLX5_CAP_GEN(dev, num_ports) == 2)
		MLX5_SET(query_hca_vport_context_in, in, port_num, port_num);

	err = mlx5_cmd_exec(dev, in, sizeof(in), out,  out_sz);
	if (err)
		goto ex;

	ctx = MLX5_ADDR_OF(query_hca_vport_context_out, out, hca_vport_context);
	rep->field_select = MLX5_GET_PR(hca_vport_context, ctx, field_select);
	rep->sm_virt_aware = MLX5_GET_PR(hca_vport_context, ctx, sm_virt_aware);
	rep->has_smi = MLX5_GET_PR(hca_vport_context, ctx, has_smi);
	rep->has_raw = MLX5_GET_PR(hca_vport_context, ctx, has_raw);
	rep->policy = MLX5_GET_PR(hca_vport_context, ctx, vport_state_policy);
	rep->phys_state = MLX5_GET_PR(hca_vport_context, ctx,
				      port_physical_state);
	rep->vport_state = MLX5_GET_PR(hca_vport_context, ctx, vport_state);
	rep->port_physical_state = MLX5_GET_PR(hca_vport_context, ctx,
					       port_physical_state);
	rep->port_guid = MLX5_GET64_PR(hca_vport_context, ctx, port_guid);
	rep->node_guid = MLX5_GET64_PR(hca_vport_context, ctx, node_guid);
	rep->cap_mask1 = MLX5_GET_PR(hca_vport_context, ctx, cap_mask1);
	rep->cap_mask1_perm = MLX5_GET_PR(hca_vport_context, ctx,
					  cap_mask1_field_select);
	rep->cap_mask2 = MLX5_GET_PR(hca_vport_context, ctx, cap_mask2);
	rep->cap_mask2_perm = MLX5_GET_PR(hca_vport_context, ctx,
					  cap_mask2_field_select);
	rep->lid = MLX5_GET_PR(hca_vport_context, ctx, lid);
	rep->init_type_reply = MLX5_GET_PR(hca_vport_context, ctx,
					   init_type_reply);
	rep->lmc = MLX5_GET_PR(hca_vport_context, ctx, lmc);
	rep->subnet_timeout = MLX5_GET_PR(hca_vport_context, ctx,
					  subnet_timeout);
	rep->sm_lid = MLX5_GET_PR(hca_vport_context, ctx, sm_lid);
	rep->sm_sl = MLX5_GET_PR(hca_vport_context, ctx, sm_sl);
	rep->qkey_violation_counter = MLX5_GET_PR(hca_vport_context, ctx,
						  qkey_violation_counter);
	rep->pkey_violation_counter = MLX5_GET_PR(hca_vport_context, ctx,
						  pkey_violation_counter);
	rep->grh_required = MLX5_GET_PR(hca_vport_context, ctx, grh_required);
	rep->sys_image_guid = MLX5_GET64_PR(hca_vport_context, ctx,
					    system_image_guid);

ex:
	kfree(out);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_query_hca_vport_context);
