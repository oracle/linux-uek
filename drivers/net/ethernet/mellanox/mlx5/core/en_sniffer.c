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

#include <linux/mlx5/fs.h>
#include <linux/mlx5/compat/compat-4.10.h>
#include "en.h"

enum sniffer_types {
	SNIFFER_TX,
	SNIFFER_RX,
	SNIFFER_LEFTOVERS,
	SNIFFER_NUM_TYPES,
};

struct mlx5_sniffer_rule_info {
	struct mlx5_flow_rule	*rule;
	struct mlx5_flow_table  *ft;
	enum sniffer_types      type;
};

struct sniffer_work {
	struct work_struct             work;
	struct mlx5_sniffer_rule_info  rule_info;
	struct mlx5e_sniffer           *sniffer;
	struct notifier_block          *nb;
};

struct sniffer_evt_ctx {
	struct mlx5e_sniffer    *sniffer;
	struct notifier_block   nb;
};

struct sniffer_rule {
	struct mlx5_flow_handle   *handle;
	struct list_head        list;
};

enum {
	SNIFFER_ROCE_V1_RULE,
	SNIFFER_ROCE_V2_IPV4_RULE,
	SNIFFER_ROCE_V2_IPV6_RULE,
	SNIFFER_ROCE_NUM_RULES
};

struct mlx5e_sniffer {
	struct mlx5e_priv	*priv;
	struct workqueue_struct *sniffer_wq;
	struct mlx5_flow_table  *rx_ft;
	struct mlx5_flow_table  *tx_ft;
	struct sniffer_evt_ctx  bypass_ctx;
	struct sniffer_evt_ctx  roce_ctx;
	struct sniffer_evt_ctx  leftovers_ctx;
	struct list_head        rules;
	struct list_head        leftover_rules;
	struct mlx5e_tir        tir[SNIFFER_NUM_TYPES];
	struct mlx5_flow_handle	*roce_rules[SNIFFER_ROCE_NUM_RULES];
};

static bool sniffer_rule_in_leftovers(struct mlx5e_sniffer *sniffer,
				      struct mlx5_flow_rule *rule)
{
	struct sniffer_rule *sniffer_flow;

	list_for_each_entry(sniffer_flow, &sniffer->leftover_rules, list) {
		if (sniffer_flow->handle->rule[0] == rule)
			return true;
	}
	return false;
}

static int mlx5e_sniffer_create_tx_rule(struct mlx5e_sniffer *sniffer)
{
	struct mlx5e_priv *priv = sniffer->priv;
	struct sniffer_rule *sniffer_flow;
	struct mlx5_flow_act flow_act = {0};
	struct mlx5_flow_destination dest;
	struct mlx5_flow_spec *spec;
	int err = 0;

	/* Create no filter rule */
	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec)
		return -ENOMEM;

	sniffer_flow = kzalloc(sizeof(*sniffer_flow), GFP_KERNEL);
	if (!sniffer_flow) {
		err = -ENOMEM;
		netdev_err(priv->netdev, "failed to alloc sniifer_flow");
		goto out;
	}

	dest.tir_num = sniffer->tir[SNIFFER_TX].tirn;
	dest.type = MLX5_FLOW_DESTINATION_TYPE_TIR;
	flow_act.flow_tag = MLX5_FS_OFFLOAD_FLOW_TAG;
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	sniffer_flow->handle = mlx5_add_flow_rules(sniffer->tx_ft, spec, &flow_act,
						 &dest, 1);
	if (IS_ERR(sniffer_flow->handle)) {
		err = PTR_ERR(sniffer_flow->handle);
		kfree(sniffer_flow);
		goto out;
	}
	list_add(&sniffer_flow->list, &sniffer->rules);
out:
	kvfree(spec);
	return err;
}

static void sniffer_del_roce_rules(struct mlx5e_sniffer *sniffer)
{
	int i;

	for (i = 0; i < SNIFFER_ROCE_NUM_RULES; i++) {
		if (!IS_ERR_OR_NULL(sniffer->roce_rules[i])) {
			mlx5_del_flow_rules(sniffer->roce_rules[i]);
			sniffer->roce_rules[i] = NULL;
		}
	}
}

#define ROCEV1_ETHERTYPE   0x8915
static int sniffer_create_roce_rules(struct mlx5e_sniffer *sniffer)
{
	struct mlx5_flow_destination dest;
	struct mlx5_flow_act flow_act = {0};
	struct mlx5_flow_spec *spec;
	u32 *mc;
	u32 *mv;
	int err = 0;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec)
		return -ENOMEM;

	mc = spec->match_criteria;
	mv = spec->match_value;
	spec->match_criteria_enable = MLX5_MATCH_OUTER_HEADERS;

	dest.tir_num = sniffer->tir[SNIFFER_RX].tirn;
	dest.type = MLX5_FLOW_DESTINATION_TYPE_TIR;

	MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.ethertype);
	MLX5_SET(fte_match_param, mv, outer_headers.ethertype, ROCEV1_ETHERTYPE);
	flow_act.flow_tag = MLX5_FS_OFFLOAD_FLOW_TAG;
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	sniffer->roce_rules[SNIFFER_ROCE_V1_RULE]
		= mlx5_add_flow_rules(sniffer->rx_ft, spec, &flow_act,
				      &dest, 1);
	if (IS_ERR(sniffer->roce_rules[SNIFFER_ROCE_V1_RULE])) {
		err = PTR_ERR(sniffer->roce_rules[SNIFFER_ROCE_V1_RULE]);
		sniffer->roce_rules[SNIFFER_ROCE_V1_RULE] = NULL;
		goto create_roce_rules_out;
	}

	MLX5_SET(fte_match_param, mv, outer_headers.ethertype, ETH_P_IP);
	MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.ip_protocol);
	MLX5_SET(fte_match_param, mv, outer_headers.ip_protocol, IPPROTO_UDP);
	MLX5_SET_TO_ONES(fte_match_param, mc, outer_headers.udp_dport);
	MLX5_SET(fte_match_param, mv, outer_headers.udp_dport,
		 ROCE_V2_UDP_DPORT);
	sniffer->roce_rules[SNIFFER_ROCE_V2_IPV4_RULE]
		= mlx5_add_flow_rules(sniffer->rx_ft, spec, &flow_act,
				      &dest, 1);
	if (IS_ERR(sniffer->roce_rules[SNIFFER_ROCE_V2_IPV4_RULE])) {
		err = PTR_ERR(sniffer->roce_rules[SNIFFER_ROCE_V2_IPV4_RULE]);
		sniffer->roce_rules[SNIFFER_ROCE_V2_IPV4_RULE] = NULL;
		goto create_roce_rules_out;
	}

	MLX5_SET(fte_match_param, mv, outer_headers.ethertype, ETH_P_IPV6);
	sniffer->roce_rules[SNIFFER_ROCE_V2_IPV6_RULE]
		= mlx5_add_flow_rules(sniffer->rx_ft, spec, &flow_act,
				      &dest, 1);
	if (IS_ERR(sniffer->roce_rules[SNIFFER_ROCE_V2_IPV6_RULE])) {
		err = PTR_ERR(sniffer->roce_rules[SNIFFER_ROCE_V2_IPV6_RULE]);
		sniffer->roce_rules[SNIFFER_ROCE_V2_IPV6_RULE] = NULL;
		goto create_roce_rules_out;
	}

create_roce_rules_out:
	kfree(spec);
	if (err)
		sniffer_del_roce_rules(sniffer);
	return err;
}

static void sniffer_del_rule_handler(struct work_struct *_work)
{
	struct mlx5_sniffer_rule_info *rule_info;
	struct sniffer_rule *sniffer_rule;
	struct sniffer_work *work;

	work = container_of(_work, struct sniffer_work, work);
	rule_info = &work->rule_info;
	sniffer_rule = (struct sniffer_rule *)
		mlx5_get_rule_private_data(rule_info->rule, work->nb);

	if (!sniffer_rule)
		goto out;

	mlx5_del_flow_rules(sniffer_rule->handle);
	list_del(&sniffer_rule->list);
	kfree(sniffer_rule);

out:
	mlx5_release_rule_private_data(rule_info->rule, work->nb);
	mlx5_put_flow_rule(work->rule_info.rule);
	kfree(work);
}

static int sniffer_add_flow_rule(struct mlx5e_sniffer *sniffer,
				 struct sniffer_rule *sniffer_flow,
				 struct mlx5_sniffer_rule_info *rule_info)
{
	struct mlx5_flow_destination  dest;
	struct mlx5_flow_act flow_act = {0};
	struct mlx5_flow_spec *spec;
	struct mlx5_flow_table *ft;
	int err = 0;

	spec = kvzalloc(sizeof(*spec), GFP_KERNEL);
	if (!spec)
		return -ENOMEM;

	mlx5_get_rule_flow_spec(spec, rule_info->rule);
	dest.tir_num = sniffer->tir[rule_info->type].tirn;
	dest.type = MLX5_FLOW_DESTINATION_TYPE_TIR;
	ft = (rule_info->type == SNIFFER_LEFTOVERS) ? rule_info->ft :
		sniffer->rx_ft;
	flow_act.flow_tag = MLX5_FS_OFFLOAD_FLOW_TAG;
	flow_act.action = MLX5_FLOW_CONTEXT_ACTION_FWD_DEST;
	sniffer_flow->handle = mlx5_add_flow_rules(ft, spec, &flow_act,
						 &dest, 1);
	if (IS_ERR(sniffer_flow->handle)) {
		err = PTR_ERR(sniffer_flow->handle);
		sniffer_flow->handle = NULL;
	}

	kfree(spec);
	return err;
}

static void sniffer_add_rule_handler(struct work_struct *work)
{
	struct mlx5_sniffer_rule_info *rule_info;
	struct sniffer_rule *sniffer_flow;
	struct sniffer_work *sniffer_work;
	struct mlx5e_sniffer *sniffer;
	struct notifier_block *nb;
	struct mlx5e_priv *priv;
	int err;

	sniffer_work = container_of(work, struct sniffer_work, work);
	rule_info = &sniffer_work->rule_info;
	sniffer = sniffer_work->sniffer;
	nb = sniffer_work->nb;
	priv = sniffer->priv;

	if (sniffer_rule_in_leftovers(sniffer,
				      rule_info->rule))
		goto out;

	sniffer_flow = kzalloc(sizeof(*sniffer_flow), GFP_KERNEL);
	if (!sniffer_flow)
		goto out;

	err = sniffer_add_flow_rule(sniffer, sniffer_flow, rule_info);
	if (err) {
		netdev_err(priv->netdev, "%s: Failed to add sniffer rule, err=%d\n",
			   __func__, err);
		kfree(sniffer_flow);
		goto out;
	}

	err = mlx5_set_rule_private_data(rule_info->rule, nb, sniffer_flow);
	if (err) {
		netdev_err(priv->netdev, "%s: mlx5_set_rule_private_data failed\n",
			   __func__);
		mlx5_del_flow_rules(sniffer_flow->handle);
	}
	if (rule_info->type == SNIFFER_LEFTOVERS)
		list_add(&sniffer_flow->list, &sniffer->leftover_rules);
	else
		list_add(&sniffer_flow->list, &sniffer->rules);

out:
	mlx5_put_flow_rule(rule_info->rule);
	kfree(sniffer_work);
}

static int sniffer_flow_rule_event_fn(struct notifier_block *nb,
				      unsigned long event, void *data)
{
	struct mlx5_event_data *event_data;
	struct sniffer_evt_ctx *event_ctx;
	struct mlx5e_sniffer *sniffer;
	struct sniffer_work *work;
	enum sniffer_types type;

	event_ctx = container_of(nb, struct sniffer_evt_ctx, nb);
	sniffer = event_ctx->sniffer;

	event_data = (struct mlx5_event_data *)data;
	type = (event_ctx == &sniffer->leftovers_ctx) ? SNIFFER_LEFTOVERS :
		SNIFFER_RX;

	if ((type == SNIFFER_LEFTOVERS) && (event == MLX5_RULE_EVENT_DEL) &&
	    sniffer_rule_in_leftovers(sniffer, event_data->rule)) {
		return 0;
	}

	work = kzalloc(sizeof(*work), GFP_KERNEL);
	if (!work)
		return -ENOMEM;

	work->rule_info.rule = event_data->rule;
	work->rule_info.ft = event_data->ft;
	work->rule_info.type = type;
	work->sniffer = sniffer;
	work->nb = nb;

	mlx5_get_flow_rule(event_data->rule);

	if (event == MLX5_RULE_EVENT_ADD)
		INIT_WORK(&work->work, sniffer_add_rule_handler);
	else
		INIT_WORK(&work->work, sniffer_del_rule_handler);

	queue_work(sniffer->sniffer_wq, &work->work);

	return 0;
}

static struct sniffer_evt_ctx *sniffer_get_event_ctx(struct mlx5e_sniffer *sniffer,
						     enum mlx5_flow_namespace_type type)
{
	switch (type) {
	case MLX5_FLOW_NAMESPACE_BYPASS:
		return &sniffer->bypass_ctx;
	case MLX5_FLOW_NAMESPACE_LEFTOVERS:
		return &sniffer->leftovers_ctx;
	default:
		return NULL;
	}
}

static void sniffer_destroy_tirs(struct mlx5e_sniffer *sniffer)
{
	struct mlx5e_priv *priv = sniffer->priv;
	int i;

	for (i = 0; i < SNIFFER_NUM_TYPES; i++)
		mlx5e_destroy_tir(priv->mdev, &sniffer->tir[i]);
}

static void sniffer_cleanup_resources(struct mlx5e_sniffer *sniffer)
{
	struct sniffer_rule *sniffer_flow;
	struct sniffer_rule *tmp;

	if (sniffer->sniffer_wq)
		destroy_workqueue(sniffer->sniffer_wq);

	list_for_each_entry_safe(sniffer_flow, tmp, &sniffer->rules, list) {
		mlx5_del_flow_rules(sniffer_flow->handle);
		list_del(&sniffer_flow->list);
		kfree(sniffer_flow);
	}

	list_for_each_entry_safe(sniffer_flow, tmp, &sniffer->leftover_rules, list) {
		mlx5_del_flow_rules(sniffer_flow->handle);
		list_del(&sniffer_flow->list);
		kfree(sniffer_flow);
	}
	sniffer_del_roce_rules(sniffer);

	if (sniffer->rx_ft)
		mlx5_destroy_flow_table(sniffer->rx_ft);

	if (sniffer->tx_ft)
		mlx5_destroy_flow_table(sniffer->tx_ft);

	sniffer_destroy_tirs(sniffer);
}

static void sniffer_unregister_ns_rules_handlers(struct mlx5e_sniffer *sniffer,
						 enum mlx5_flow_namespace_type ns_type)
{
	struct mlx5e_priv *priv = sniffer->priv;
	struct sniffer_evt_ctx *evt_ctx;
	struct mlx5_flow_namespace *ns;

	ns = mlx5_get_flow_namespace(priv->mdev, ns_type);
	if (!ns)
		return;

	evt_ctx = sniffer_get_event_ctx(sniffer, ns_type);
	mlx5_unregister_rule_notifier(ns, &evt_ctx->nb);
}

static void sniffer_unregister_rules_handlers(struct mlx5e_sniffer *sniffer)
{
	sniffer_unregister_ns_rules_handlers(sniffer,
					     MLX5_FLOW_NAMESPACE_BYPASS);
	sniffer_unregister_ns_rules_handlers(sniffer,
					     MLX5_FLOW_NAMESPACE_LEFTOVERS);
}

int mlx5e_sniffer_stop(struct mlx5e_priv *priv)
{
	struct mlx5e_sniffer *sniffer = priv->fs.sniffer;

	if (!sniffer)
		return 0;

	sniffer_unregister_rules_handlers(sniffer);
	sniffer_cleanup_resources(sniffer);
	kfree(sniffer);

	return 0;
}

static int sniffer_register_ns_rules_handlers(struct mlx5e_sniffer *sniffer,
					      enum mlx5_flow_namespace_type ns_type)
{
	struct mlx5e_priv *priv = sniffer->priv;
	struct sniffer_evt_ctx *evt_ctx;
	struct mlx5_flow_namespace *ns;
	int err;

	ns = mlx5_get_flow_namespace(priv->mdev, ns_type);
	if (!ns)
		return -ENOENT;

	evt_ctx = sniffer_get_event_ctx(sniffer, ns_type);
	if (!evt_ctx)
		return -ENOENT;

	evt_ctx->nb.notifier_call = sniffer_flow_rule_event_fn;
	evt_ctx->sniffer  = sniffer;
	err = mlx5_register_rule_notifier(ns, &evt_ctx->nb);
	if (err) {
		netdev_err(priv->netdev,
			   "%s: mlx5_register_rule_notifier failed\n", __func__);
		return err;
	}

	return 0;
}

static int sniffer_register_rules_handlers(struct mlx5e_sniffer *sniffer)
{
	struct mlx5e_priv *priv = sniffer->priv;
	int err;

	err = sniffer_register_ns_rules_handlers(sniffer,
						 MLX5_FLOW_NAMESPACE_BYPASS);
	if (err)
		netdev_err(priv->netdev,
			   "%s: Failed to register for bypass namesapce\n",
			   __func__);

	err = sniffer_register_ns_rules_handlers(sniffer,
						 MLX5_FLOW_NAMESPACE_LEFTOVERS);
	if (err)
		netdev_err(priv->netdev,
			   "%s: Failed to register for leftovers namesapce\n",
			   __func__);

	return err;
}

static int sniffer_create_tirs(struct mlx5e_sniffer *sniffer)
{
	struct mlx5e_priv *priv = sniffer->priv;
	struct mlx5e_tir *tir;
	void *tirc;
	int inlen;
	u32 rqtn;
	int err;
	u32 *in;
	int tt;

	inlen = MLX5_ST_SZ_BYTES(create_tir_in);
	in = kvzalloc(inlen, GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	for (tt = 0; tt < SNIFFER_NUM_TYPES; tt++) {
		memset(in, 0, inlen);
		tir = &sniffer->tir[tt];
		tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);
		rqtn = priv->direct_tir[tt % priv->channels.params.num_channels].rqt.rqtn;
		mlx5e_build_direct_tir_ctx(priv, rqtn, tirc);
		err = mlx5e_create_tir(priv->mdev, tir, in, inlen);
		if (err)
			goto err_destroy_ch_tirs;
	}

	kvfree(in);

	return 0;

err_destroy_ch_tirs:
	for (tt--; tt >= 0; tt--)
		mlx5e_destroy_tir(priv->mdev, &sniffer->tir[tt]);
	kvfree(in);

	return err;
}

#define FS_MAX_ENTRIES 32000UL
#define FS_MAX_TYPES 10

#define SNIFFER_RX_MAX_FTES min_t(u32, (MLX5_BY_PASS_NUM_REGULAR_PRIOS *\
					FS_MAX_ENTRIES), BIT(20))
#define SNIFFER_RX_MAX_NUM_GROUPS (MLX5_BY_PASS_NUM_REGULAR_PRIOS *\
				   FS_MAX_TYPES)

#define SNIFFER_TX_MAX_FTES 1
#define SNIFFER_TX_MAX_NUM_GROUPS 1

static int sniffer_init_resources(struct mlx5e_sniffer *sniffer)
{
	struct mlx5e_priv *priv = sniffer->priv;
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_flow_namespace *p_sniffer_rx_ns;
	struct mlx5_flow_namespace *p_sniffer_tx_ns;
	int table_size;
	int err;

	INIT_LIST_HEAD(&sniffer->rules);
	INIT_LIST_HEAD(&sniffer->leftover_rules);

	p_sniffer_rx_ns =
		mlx5_get_flow_namespace(mdev, MLX5_FLOW_NAMESPACE_SNIFFER_RX);
	if (!p_sniffer_rx_ns)
		return -ENOENT;

	p_sniffer_tx_ns =
		mlx5_get_flow_namespace(mdev, MLX5_FLOW_NAMESPACE_SNIFFER_TX);
	if (!p_sniffer_tx_ns)
		return -ENOENT;

	err = sniffer_create_tirs(sniffer);
	if (err) {
		netdev_err(priv->netdev, "%s: Create tirs failed, err=%d\n",
			   __func__, err);
		return err;
	}

	sniffer->sniffer_wq = create_singlethread_workqueue("mlx5e_sniffer");
	if (!sniffer->sniffer_wq)
		goto error;

	/* Create "medium" size flow table */
	table_size = min_t(u32,
			   BIT(MLX5_CAP_FLOWTABLE_SNIFFER_RX(mdev,
							     log_max_ft_size)),
			   SNIFFER_RX_MAX_FTES);
	sniffer->rx_ft =
		mlx5_create_auto_grouped_flow_table(p_sniffer_rx_ns, 0,
						    table_size,
						    SNIFFER_RX_MAX_NUM_GROUPS,
						    0, 0);
	if (IS_ERR(sniffer->rx_ft)) {
		err = PTR_ERR(sniffer->rx_ft);
		sniffer->rx_ft = NULL;
		goto error;
	}

	sniffer->tx_ft =
		mlx5_create_auto_grouped_flow_table(p_sniffer_tx_ns, 0,
						    SNIFFER_TX_MAX_FTES,
						    SNIFFER_TX_MAX_NUM_GROUPS,
						    0, 0);
	if (IS_ERR(sniffer->tx_ft)) {
		err = PTR_ERR(sniffer->tx_ft);
		sniffer->tx_ft = NULL;
		goto error;
	}

	err = mlx5e_sniffer_create_tx_rule(sniffer);
	if (err)
		goto error;

	err = sniffer_create_roce_rules(sniffer);
	if (err)
		goto error;

	return 0;
error:
	sniffer_cleanup_resources(sniffer);
	return err;
}

int mlx5e_sniffer_start(struct mlx5e_priv *priv)
{
	struct mlx5e_sniffer *sniffer;
	int err;

	if (!test_bit(MLX5E_STATE_OPENED, &priv->state)) {
		netdev_err(priv->netdev, "Device is already closed\n");
		return -EPERM;
	}

	sniffer = kzalloc(sizeof(*sniffer), GFP_KERNEL);
	if (!sniffer)
		return -ENOMEM;

	sniffer->priv = priv;
	err = sniffer_init_resources(sniffer);
	if (err) {
		netdev_err(priv->netdev, "%s: Failed to init sniffer resources\n",
			   __func__);
		goto err_out;
	}

	err = sniffer_register_rules_handlers(sniffer);
	if (err) {
		netdev_err(priv->netdev, "%s: Failed to register rules handlers\n",
			   __func__);
		goto err_cleanup_resources;
	}
	priv->fs.sniffer = sniffer;
	return 0;

err_cleanup_resources:
	sniffer_cleanup_resources(sniffer);
err_out:
	kfree(sniffer);
	return err;
}
