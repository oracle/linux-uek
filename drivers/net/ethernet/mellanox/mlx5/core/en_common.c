/*
 * Copyright (c) 2016, Mellanox Technologies. All rights reserved.
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

#include "en.h"

/* mlx5e global resources should be placed in this file.
 * Global resources are common to all the netdevices crated on the same nic.
 */

int mlx5e_create_tir(struct mlx5_core_dev *mdev,
		     struct mlx5e_tir *tir, u32 *in, int inlen)
{
	u32 out[MLX5_ST_SZ_DW(create_tir_out)] = {0};
	int err;

	err = mlx5_core_create_tir(mdev, in, inlen,
				   out, MLX5_ST_SZ_BYTES(create_tir_out));
	if (err)
		return err;

	tir->tirn = MLX5_GET(create_tir_out, out, tirn);
	list_add(&tir->list, &mdev->mlx5e_res.td.tirs_list);

	return 0;
}

void mlx5e_destroy_tir(struct mlx5_core_dev *mdev,
		       struct mlx5e_tir *tir)
{
	mlx5_core_destroy_tir(mdev, tir->tirn);
	list_del(&tir->list);
}

static int mlx5e_create_mkey(struct mlx5_core_dev *mdev, u32 pdn,
			     struct mlx5_core_mkey *mkey)
{
	int inlen = MLX5_ST_SZ_BYTES(create_mkey_in);
	void *mkc;
	u32 *in;
	int err;

	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	mkc = MLX5_ADDR_OF(create_mkey_in, in, memory_key_mkey_entry);
	MLX5_SET(mkc, mkc, access_mode_1_0, MLX5_MKC_ACCESS_MODE_PA);
	MLX5_SET(mkc, mkc, lw, 1);
	MLX5_SET(mkc, mkc, lr, 1);

	MLX5_SET(mkc, mkc, pd, pdn);
	MLX5_SET(mkc, mkc, length64, 1);
	MLX5_SET(mkc, mkc, qpn, 0xffffff);

	err = mlx5_core_create_mkey(mdev, mkey, in, inlen);

	kvfree(in);
	return err;
}

int mlx5e_create_mdev_resources(struct mlx5_core_dev *mdev)
{
	struct mlx5e_resources *res = &mdev->mlx5e_res;
	int err;

	err = mlx5_core_alloc_pd(mdev, &res->pdn);
	if (err) {
		mlx5_core_err(mdev, "alloc pd failed, %d\n", err);
		return err;
	}

	err = mlx5_core_alloc_transport_domain(mdev, &res->td.tdn);
	if (err) {
		mlx5_core_err(mdev, "alloc td failed, %d\n", err);
		goto err_dealloc_pd;
	}

	err = mlx5e_create_mkey(mdev, res->pdn, &res->mkey);
	if (err) {
		mlx5_core_err(mdev, "create mkey failed, %d\n", err);
		goto err_dealloc_transport_domain;
	}

	err = mlx5_alloc_bfreg(mdev, &res->bfreg, false, false);
	if (err) {
		mlx5_core_err(mdev, "alloc bfreg failed, %d\n", err);
		goto err_destroy_mkey;
	}

	INIT_LIST_HEAD(&mdev->mlx5e_res.td.tirs_list);

	return 0;

err_destroy_mkey:
	mlx5_core_destroy_mkey(mdev, &res->mkey);
err_dealloc_transport_domain:
	mlx5_core_dealloc_transport_domain(mdev, res->td.tdn);
err_dealloc_pd:
	mlx5_core_dealloc_pd(mdev, res->pdn);
	return err;
}

void mlx5e_destroy_mdev_resources(struct mlx5_core_dev *mdev)
{
	struct mlx5e_resources *res = &mdev->mlx5e_res;

	mlx5_free_bfreg(mdev, &res->bfreg);
	mlx5_core_destroy_mkey(mdev, &res->mkey);
	mlx5_core_dealloc_transport_domain(mdev, res->td.tdn);
	mlx5_core_dealloc_pd(mdev, res->pdn);
	memset(res, 0, sizeof(*res));
}

int mlx5e_refresh_tirs(struct mlx5e_priv *priv, bool enable_uc_lb)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5e_tir *tir;
	int err  = -ENOMEM;
	u32 tirn = 0;
	int inlen;
	void *in;

	inlen = MLX5_ST_SZ_BYTES(modify_tir_in);
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		goto out;

	if (enable_uc_lb)
		MLX5_SET(modify_tir_in, in, ctx.self_lb_block,
			 MLX5_TIRC_SELF_LB_BLOCK_BLOCK_UNICAST);

	MLX5_SET(modify_tir_in, in, bitmask.self_lb_en, 1);

	list_for_each_entry(tir, &mdev->mlx5e_res.td.tirs_list, list) {
		tirn = tir->tirn;
		err = mlx5_core_modify_tir(mdev, tirn, in, inlen);
		if (err)
			goto out;
	}

out:
	kvfree(in);
	if (err)
		netdev_err(priv->netdev, "refresh tir(0x%x) failed, %d\n", tirn, err);

	return err;
}

u8 mlx5e_params_calculate_tx_min_inline(struct mlx5_core_dev *mdev)
{
	u8 min_inline_mode;

	mlx5_query_min_inline(mdev, &min_inline_mode);
	if (min_inline_mode == MLX5_INLINE_MODE_NONE &&
	    !MLX5_CAP_ETH(mdev, wqe_vlan_insert))
		min_inline_mode = MLX5_INLINE_MODE_L2;

	return min_inline_mode;
}

/* speed in units of 1Mb */
static const u32 mlx5e_link_speed[MLX5E_LINK_MODES_NUMBER] = {
	[MLX5E_1000BASE_CX_SGMII] = 1000,
	[MLX5E_1000BASE_KX]       = 1000,
	[MLX5E_10GBASE_CX4]       = 10000,
	[MLX5E_10GBASE_KX4]       = 10000,
	[MLX5E_10GBASE_KR]        = 10000,
	[MLX5E_20GBASE_KR2]       = 20000,
	[MLX5E_40GBASE_CR4]       = 40000,
	[MLX5E_40GBASE_KR4]       = 40000,
	[MLX5E_56GBASE_R4]        = 56000,
	[MLX5E_10GBASE_CR]        = 10000,
	[MLX5E_10GBASE_SR]        = 10000,
	[MLX5E_10GBASE_ER]        = 10000,
	[MLX5E_40GBASE_SR4]       = 40000,
	[MLX5E_40GBASE_LR4]       = 40000,
	[MLX5E_50GBASE_SR2]       = 50000,
	[MLX5E_100GBASE_CR4]      = 100000,
	[MLX5E_100GBASE_SR4]      = 100000,
	[MLX5E_100GBASE_KR4]      = 100000,
	[MLX5E_100GBASE_LR4]      = 100000,
	[MLX5E_100BASE_TX]        = 100,
	[MLX5E_1000BASE_T]        = 1000,
	[MLX5E_10GBASE_T]         = 10000,
	[MLX5E_25GBASE_CR]        = 25000,
	[MLX5E_25GBASE_KR]        = 25000,
	[MLX5E_25GBASE_SR]        = 25000,
	[MLX5E_50GBASE_CR2]       = 50000,
	[MLX5E_50GBASE_KR2]       = 50000,
};

u32 mlx5e_ptys_to_speed(u32 eth_proto_oper)
{
	unsigned long temp = (unsigned long)eth_proto_oper;
	u32 speed = 0;
	int i;

	i = find_first_bit(&temp, MLX5E_LINK_MODES_NUMBER);

	if (i < MLX5E_LINK_MODES_NUMBER)
		speed = mlx5e_link_speed[i];

	return speed;
}

int mlx5e_get_port_speed(struct mlx5e_priv *priv, u32 *speed)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	u32 out[MLX5_ST_SZ_DW(ptys_reg)] = {};
	u32 eth_proto_oper;
	int err;

	err = mlx5_query_port_ptys(mdev, out, sizeof(out), MLX5_PTYS_EN, 1);
	if (err)
		return err;

	eth_proto_oper = MLX5_GET(ptys_reg, out, eth_proto_oper);
	*speed = mlx5e_ptys_to_speed(eth_proto_oper);
	if (!(*speed)) {
		mlx5_core_warn(mdev, "cannot get port speed\n");
		err = -EINVAL;
	}

	return err;
}

#ifdef HAVE_GET_SET_LINK_KSETTINGS
int mlx5e_get_max_linkspeed(struct mlx5_core_dev *mdev, u32 *speed)
{
	u32 max_speed = 0;
	u32 proto_cap;
	int err;
	int i;

	err = mlx5_query_port_proto_cap(mdev, &proto_cap, MLX5_PTYS_EN);
	if (err)
		return err;

	for (i = 0; i < MLX5E_LINK_MODES_NUMBER; ++i)
		if (proto_cap & MLX5E_PROT_MASK(i))
			max_speed = max(max_speed, mlx5e_link_speed[i]);

	*speed = max_speed;
	return 0;
}
#endif

