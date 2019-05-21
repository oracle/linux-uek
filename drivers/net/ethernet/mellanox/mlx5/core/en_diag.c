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

#define MLX5_DRV_VER_SZ 64
#define MLX5_DEV_NAME_SZ 64

#define DIAG_BLK_SZ(data_size) (sizeof(struct mlx5_diag_blk) + data_size)
#define DIAG_GET_NEXT_BLK(dump_hdr) \
	((struct mlx5_diag_blk *)(dump_hdr->dump + dump_hdr->total_length))

#ifdef HAVE_GET_SET_DUMP
static int mlx5e_diag_fill_device_name(struct mlx5e_priv *priv, void *buff)
{
	struct mlx5_core_dev *mdev = priv->mdev;
	size_t pci_name_sz = strlen(pci_name(mdev->pdev));

	memset(buff, 0, MLX5_DEV_NAME_SZ);
	strncpy(buff, pci_name(mdev->pdev), MLX5_DEV_NAME_SZ);
	if (pci_name_sz >= MLX5_DEV_NAME_SZ - 2)
		goto out;

	/* there is at least 2 bytes left */
	buff += pci_name_sz;
	strncpy(buff, ":", 1);
	buff += 1;

	strncpy(buff, priv->netdev->name, MLX5_DEV_NAME_SZ - pci_name_sz - 1);
out:
	return MLX5_DEV_NAME_SZ;
}

static int mlx5e_diag_fill_driver_version(void *buff)
{
	memset(buff, 0, MLX5_DRV_VER_SZ);
	strlcpy(buff, DRIVER_VERSION, MLX5_DRV_VER_SZ);
	return MLX5_DRV_VER_SZ;
}

static int dump_rq_info(struct mlx5e_rq *rq, void *buffer)
{
	struct mlx5_diag_wq *rqd = (struct mlx5_diag_wq *)buffer;

	rqd->wq_type = MLX5_DIAG_RQ;
	rqd->wqn = rq->rqn;
	rqd->ci = 0;
	rqd->pi = rq->wqe.wq.cur_sz;
	rqd->wqe_stride = rq->wqe.wq.fbc.log_stride;
	rqd->size = rq->wqe.wq.fbc.sz_m1 + 1;
	rqd->wqe_num = ((rq->wqe.wq.fbc.sz_m1 + 1) << rq->wqe.wq.fbc.log_stride);
	rqd->group_id = rq->channel->ix;

	return sizeof(*rqd);
}

static int dump_sq_info(struct mlx5e_txqsq *sq, void *buffer)
{
	struct mlx5_diag_wq *sqd = (struct mlx5_diag_wq *)buffer;

	sqd->wq_type = MLX5_DIAG_SQ;
	sqd->wqn = sq->sqn;
	sqd->ci = sq->cc;
	sqd->pi = sq->pc;
	sqd->wqe_stride = sq->wq.fbc.log_stride;
	sqd->size = sq->wq.fbc.sz_m1 + 1;
	sqd->wqe_num = ((sq->wq.fbc.sz_m1 + 1) << sq->wq.fbc.log_stride);
	sqd->group_id = sq->channel->ix;

	return sizeof(*sqd);
}

static int dump_cq_info(struct mlx5e_cq *cq, void *buffer)
{
	struct mlx5_diag_wq *cqd = (struct mlx5_diag_wq *)buffer;
	struct mlx5_cqwq *wq = &cq->wq;

	cqd->wq_type = MLX5_DIAG_CQ;
	cqd->wqn = cq->mcq.cqn;
	cqd->ci = wq->cc & wq->fbc.sz_m1;
	cqd->pi = 0;
	cqd->wqe_stride = wq->fbc.log_stride;
	cqd->size = wq->fbc.sz_m1 + 1;
	cqd->wqe_num = cqd->size;
	cqd->group_id = cq->channel->ix;

	return sizeof(*cqd);
}

static int dump_eq_info(struct mlx5_eq *eq, void *buffer)
{
	struct mlx5_diag_eq *eqd = (struct mlx5_diag_eq *)buffer;

	eqd->type = MLX5_DIAG_EQ;
	eqd->ci = eq->cons_index;
	eqd->size = eq->size;
	eqd->irqn = eq->irqn;
	eqd->eqn = eq->eqn;
	eqd->nent = eq->nent;
	eqd->mask = 0;
	eqd->index = eq->index;
	eqd->group_id = eq->index;

	return sizeof(*eqd);
}

static void dump_channel_info(struct mlx5e_channel *c,
			      struct mlx5_diag_dump *dump_hdr)
{
	struct mlx5_diag_blk *dump_blk;
	struct mlx5_eq eqc;
	int i;

	for (i = 0; i < c->num_tc; i++) {
		/* Dump SQ */
		dump_blk = DIAG_GET_NEXT_BLK(dump_hdr);
		dump_blk->type = MLX5_DIAG_SQ;
		dump_blk->length = dump_sq_info(&c->sq[i], &dump_blk->data);
		dump_hdr->total_length += DIAG_BLK_SZ(dump_blk->length);
		dump_hdr->num_blocks++;

		/* Dump SQ CQ */
		dump_blk = DIAG_GET_NEXT_BLK(dump_hdr);
		dump_blk->type = MLX5_DIAG_CQ;
		dump_blk->length = dump_cq_info(&c->sq[i].cq, &dump_blk->data);
		dump_hdr->total_length += DIAG_BLK_SZ(dump_blk->length);
		dump_hdr->num_blocks++;
	}

	/* Dump RQ */
	dump_blk = DIAG_GET_NEXT_BLK(dump_hdr);
	dump_blk->type = MLX5_DIAG_RQ;
	dump_blk->length = dump_rq_info(&c->rq, &dump_blk->data);
	dump_hdr->total_length += DIAG_BLK_SZ(dump_blk->length);
	dump_hdr->num_blocks++;

	/* Dump RQ CQ */
	dump_blk = DIAG_GET_NEXT_BLK(dump_hdr);
	dump_blk->type = MLX5_DIAG_CQ;
	dump_blk->length = dump_cq_info(&c->rq.cq, &dump_blk->data);
	dump_hdr->total_length += DIAG_BLK_SZ(dump_blk->length);
	dump_hdr->num_blocks++;

	/* Dump EQ */
	mlx5_vector2eq(c->priv->mdev, c->ix, &eqc);
	dump_blk = DIAG_GET_NEXT_BLK(dump_hdr);
	dump_blk->type = MLX5_DIAG_EQ;
	dump_blk->length = dump_eq_info(&eqc, &dump_blk->data);
	dump_hdr->total_length += DIAG_BLK_SZ(dump_blk->length);
	dump_hdr->num_blocks++;
}

static void dump_channels_info(struct mlx5e_priv *priv,
			       struct mlx5_diag_dump *dump_hdr)
{
	u32 nch = priv->channels.num;
	int i;

	for (i = 0; i < nch; i++)
		dump_channel_info(priv->channels.c[i], dump_hdr);
}

int mlx5e_set_dump(struct net_device *netdev, struct ethtool_dump *dump)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);

	priv->channels.params.dump.flag = dump->flag;
	return 0;
}

int mlx5e_get_dump_flag(struct net_device *netdev, struct ethtool_dump *dump)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	__u32 extra_len = 0;

	dump->version = MLX5_DIAG_DUMP_VERSION;
	dump->flag = priv->channels.params.dump.flag;

	if (dump->flag & MLX5_DIAG_FLAG_MST) {
		u32 mst_size = mlx5_mst_capture(priv->mdev);

		if (mst_size <= 0) {
			dump->flag &= ~MLX5_DIAG_FLAG_MST;
			netdev_warn(priv->netdev,
				    "Failed to get mst dump, err (%d)\n",
				    mst_size);
			mst_size = 0;
		}
		priv->channels.params.dump.mst_size = mst_size;
		extra_len += mst_size ? DIAG_BLK_SZ(mst_size) : 0;
	}

	mutex_lock(&priv->state_lock);
	if (dump->flag & MLX5_DIAG_FLAG_CHANNELS &&
	    test_bit(MLX5E_STATE_OPENED, &priv->state)) {
		u32 nch = priv->channels.num;
		u32 ntc = priv->channels.params.num_tc;

		extra_len +=
			nch * ntc * DIAG_BLK_SZ(sizeof(struct mlx5_diag_wq)) + /* SQs     */
			nch * ntc * DIAG_BLK_SZ(sizeof(struct mlx5_diag_wq)) + /* SQs CQs */
			nch * DIAG_BLK_SZ(sizeof(struct mlx5_diag_wq)) +       /* RQs     */
			nch * DIAG_BLK_SZ(sizeof(struct mlx5_diag_wq)) +       /* RQs CQs */
			nch * DIAG_BLK_SZ(sizeof(struct mlx5_diag_eq));        /* EQs     */
	}
	mutex_unlock(&priv->state_lock);

	dump->len = sizeof(struct mlx5_diag_dump) +
		    DIAG_BLK_SZ(MLX5_DRV_VER_SZ)  +
		    DIAG_BLK_SZ(MLX5_DEV_NAME_SZ) +
		    extra_len;
	return 0;
}

int mlx5e_get_dump_data(struct net_device *netdev, struct ethtool_dump *dump,
			void *buffer)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5_diag_dump *dump_hdr = buffer;
	struct mlx5_diag_blk *dump_blk;
	struct mlx5_mcion_reg mcion = {};
	int module_num;
	int err;

	err = mlx5_query_module_num(priv->mdev, &module_num);

	if (err)
		return err;

	mcion.module = module_num;
	dump_hdr->version = MLX5_DIAG_DUMP_VERSION;
	dump_hdr->flag = 0;
	dump_hdr->num_blocks = 0;
	dump_hdr->total_length = 0;
	mlx5_icmd_access_register(priv->mdev,
				  MLX5_ICMD_MCION,
				  MLX5_ICMD_QUERY,
				  &mcion,
				  sizeof(mcion) / 4);
	dump_hdr->module_no = mcion.module;
	dump_hdr->module_status = mcion.module_status;

	/* Dump driver version */
	dump_blk = DIAG_GET_NEXT_BLK(dump_hdr);
	dump_blk->type = MLX5_DIAG_DRV_VERSION;
	dump_blk->length = mlx5e_diag_fill_driver_version(&dump_blk->data);
	dump_hdr->total_length += DIAG_BLK_SZ(dump_blk->length);
	dump_hdr->num_blocks++;

	/* Dump device name */
	dump_blk = DIAG_GET_NEXT_BLK(dump_hdr);
	dump_blk->type = MLX5_DIAG_DEVICE_NAME;
	dump_blk->length = mlx5e_diag_fill_device_name(priv, &dump_blk->data);
	dump_hdr->total_length += DIAG_BLK_SZ(dump_blk->length);
	dump_hdr->num_blocks++;

	/* Dump channels info */
	mutex_lock(&priv->state_lock);
	if (priv->channels.params.dump.flag & MLX5_DIAG_FLAG_CHANNELS &&
	    test_bit(MLX5E_STATE_OPENED, &priv->state))
		dump_channels_info(priv, dump_hdr);
	mutex_unlock(&priv->state_lock);

	if (priv->channels.params.dump.flag & MLX5_DIAG_FLAG_MST) {
		/* Dump mst buffer */
		dump_blk = DIAG_GET_NEXT_BLK(dump_hdr);
		dump_blk->type = MLX5_DIAG_MST;
		dump_blk->length = mlx5_mst_dump(priv->mdev, &dump_blk->data,
						 priv->channels.params.dump.mst_size);
		dump_hdr->total_length += DIAG_BLK_SZ(dump_blk->length);
		dump_hdr->num_blocks++;
		dump_hdr->flag |= MLX5_DIAG_FLAG_MST;
	}

	return 0;
}
#endif
