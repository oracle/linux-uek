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
#include <linux/dcbnl.h>
#include "en.h"
#include "en_ecn.h"
#include "eswitch.h"
#ifdef HAVE_IEEE_DCBNL_ETS
#ifdef CONFIG_MLX5_CORE_EN_DCB
#include "en/port_buffer.h"
#endif
#endif

#define MLX5E_SKPRIOS_NUM   16
#define MLX5E_GBPS_TO_KBPS 1000000
#define MLX5E_100MBPS_TO_KBPS 100000
#define set_kobj_mode(mdev) mlx5_core_is_pf(mdev) ? S_IWUSR | S_IRUGO : S_IRUGO

#if defined(HAVE_NETDEV_GET_NUM_TC) && defined(HAVE_NETDEV_SET_NUM_TC)
static ssize_t mlx5e_show_tc_num(struct device *device,
				 struct device_attribute *attr,
				 char *buf)
{
	struct mlx5e_priv *priv = netdev_priv(to_net_dev(device));
	struct net_device *netdev = priv->netdev;
	int len = 0;

	len += sprintf(buf + len,  "%d\n", netdev_get_num_tc(netdev));

	return len;
}

static ssize_t mlx5e_store_tc_num(struct device *device,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct mlx5e_priv *priv = netdev_priv(to_net_dev(device));
	struct net_device *netdev = priv->netdev;
#if defined(HAVE_NDO_SETUP_TC_TAKES_TC_SETUP_TYPE) || defined(HAVE_NDO_SETUP_TC_RH_EXTENDED)
	struct tc_mqprio_qopt mqprio = { 0 };
#endif
	int tc_num;
	int err = 0;

	err = sscanf(buf, "%d", &tc_num);

	if (err != 1)
		return -EINVAL;

	rtnl_lock();
#if defined(HAVE_NDO_SETUP_TC_TAKES_TC_SETUP_TYPE) || defined(HAVE_NDO_SETUP_TC_RH_EXTENDED)
	mqprio.num_tc = tc_num;
	mlx5e_setup_tc_mqprio(netdev, &mqprio);
#else
	mlx5e_setup_tc(netdev, tc_num);
#endif
	rtnl_unlock();
	return count;
}
#endif

static  ssize_t mlx5e_show_maxrate(struct device *device,
				   struct device_attribute *attr,
				   char *buf)
{
	struct mlx5e_priv *priv = netdev_priv(to_net_dev(device));
	u8 max_bw_value[MLX5E_MAX_NUM_TC];
	u8 max_bw_unit[MLX5E_MAX_NUM_TC];
	int len = 0;
	int ret;
	int i;

	ret = mlx5_query_port_ets_rate_limit(priv->mdev,max_bw_value,
					     max_bw_unit);
	if (ret) {
		netdev_err(priv->netdev, "Failed to query port ets rate limit, ret = %d\n", ret);
		return ret;
	}

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		u64 maxrate = 0;
		if (max_bw_unit[i] == MLX5_100_MBPS_UNIT)
			maxrate = max_bw_value[i] * MLX5E_100MBPS_TO_KBPS;
		else if (max_bw_unit[i] == MLX5_GBPS_UNIT)
			maxrate = max_bw_value[i] * MLX5E_GBPS_TO_KBPS;
		len += sprintf(buf + len, "%lld ", maxrate);
	}
	len += sprintf(buf + len, "\n");

	return len;
}

static ssize_t mlx5e_store_maxrate(struct device *device,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	 __u64 upper_limit_mbps = roundup(255 * MLX5E_100MBPS_TO_KBPS,
						MLX5E_GBPS_TO_KBPS);
	struct mlx5e_priv *priv = netdev_priv(to_net_dev(device));
	u8 max_bw_value[MLX5E_MAX_NUM_TC];
	u8 max_bw_unit[MLX5E_MAX_NUM_TC];
	u64 tc_maxrate[IEEE_8021QAZ_MAX_TCS];
	int i = 0;
	char delimiter;
	int ret;

	do {
		int len;
		u64 input_maxrate;

		if (i >= MLX5E_MAX_NUM_TC)
			goto bad_elem_count;

		len = strcspn(buf, " ");

		/* nul-terminate and parse */
		delimiter = buf[len];
		((char *)buf)[len] = '\0';

		if (sscanf(buf, "%lld", &input_maxrate) != 1
			   || input_maxrate < 0) {
			netdev_err(priv->netdev, "bad maxrate value: '%s'\n",
				   buf);
			goto out;
		}
		tc_maxrate[i] = input_maxrate;

		buf += len + 1;
		i++;
	} while (delimiter == ' ');

	if (i != MLX5E_MAX_NUM_TC)
		goto bad_elem_count;

	for (i = 0; i < IEEE_8021QAZ_MAX_TCS; i++) {
		if (!tc_maxrate[i]) {
			max_bw_unit[i]  = MLX5_BW_NO_LIMIT;
			continue;
		}
		if (tc_maxrate[i] < upper_limit_mbps) {
			max_bw_value[i] = div_u64(tc_maxrate[i],
						MLX5E_100MBPS_TO_KBPS);
			max_bw_value[i] = max_bw_value[i] ? max_bw_value[i] : 1;
			max_bw_unit[i]  = MLX5_100_MBPS_UNIT;
		} else {
			max_bw_value[i] = div_u64(tc_maxrate[i],
						MLX5E_GBPS_TO_KBPS);
			max_bw_unit[i]  = MLX5_GBPS_UNIT;
		}
	}

	ret = mlx5_modify_port_ets_rate_limit(priv->mdev,
					      max_bw_value, max_bw_unit);
	if (ret) {
		netdev_err(priv->netdev, "Failed to modify port ets rate limit, err = %d\n"
				, ret);
		return ret;
	}
	return count;

bad_elem_count:
	netdev_err(priv->netdev, "bad number of elemets in maxrate array\n");
out:
	return -EINVAL;
}

static DEVICE_ATTR(maxrate, S_IRUGO | S_IWUSR,
		   mlx5e_show_maxrate, mlx5e_store_maxrate);
#if defined(HAVE_NETDEV_GET_NUM_TC) && defined(HAVE_NETDEV_SET_NUM_TC)
static DEVICE_ATTR(tc_num, S_IRUGO | S_IWUSR,
		   mlx5e_show_tc_num, mlx5e_store_tc_num);
#endif

static ssize_t mlx5e_show_lro_timeout(struct device *device,
				      struct device_attribute *attr,
				      char *buf)
{
	struct mlx5e_priv *priv = netdev_priv(to_net_dev(device));
	int len = 0;
	int i;

	rtnl_lock();
	len += sprintf(buf + len, "Actual timeout: %d\n",
		       priv->channels.params.lro_timeout);

	len += sprintf(buf + len, "Supported timeout:");

	for (i = 0; i < MLX5E_LRO_TIMEOUT_ARR_SIZE; i++)
		len += sprintf(buf + len,  " %d",
		       MLX5_CAP_ETH(priv->mdev,
				    lro_timer_supported_periods[i]));

	len += sprintf(buf + len, "\n");

	rtnl_unlock();

	return len;
}

static ssize_t mlx5e_store_lro_timeout(struct device *device,
				       struct device_attribute *attr,
				       const char *buf, size_t count)
{
	struct mlx5e_priv *priv = netdev_priv(to_net_dev(device));
	struct net_device *netdev = priv->netdev;
	u32 lro_timeout;
	int err = 0;

	err = sscanf(buf, "%d", &lro_timeout);

	if (err != 1)
		goto bad_input;

	rtnl_lock();
	if (lro_timeout > MLX5_CAP_ETH(priv->mdev,
				       lro_timer_supported_periods
				       [MLX5E_LRO_TIMEOUT_ARR_SIZE - 1]))
		goto bad_input_unlock;

	lro_timeout = mlx5e_choose_lro_timeout(priv->mdev, lro_timeout);

	mutex_lock(&priv->state_lock);

	if (priv->channels.params.lro_timeout == lro_timeout) {
		err = 0;
		goto unlock;
	}

	priv->channels.params.lro_timeout = lro_timeout;
	err = mlx5e_modify_tirs_lro(priv);

unlock:
	mutex_unlock(&priv->state_lock);
	rtnl_unlock();

	if (err)
		return err;

	return count;

bad_input_unlock:
	rtnl_unlock();
bad_input:
	netdev_err(netdev, "Bad Input\n");
	return -EINVAL;
}

static DEVICE_ATTR(lro_timeout, S_IRUGO | S_IWUSR,
		  mlx5e_show_lro_timeout, mlx5e_store_lro_timeout);

#ifdef ETH_SS_RSS_HASH_FUNCS
#define MLX5E_HFUNC_TOP ETH_RSS_HASH_TOP
#define MLX5E_HFUNC_XOR ETH_RSS_HASH_XOR
#else
#define MLX5E_HFUNC_TOP 1
#define MLX5E_HFUNC_XOR 2
#endif

static ssize_t mlx5e_show_hfunc(struct device *device,
				struct device_attribute *attr,
				char *buf)
{
	struct mlx5e_priv *priv = netdev_priv(to_net_dev(device));
	int len = 0;

	rtnl_lock();

	len += sprintf(buf + len, "Operational hfunc: %s\n",
		       priv->channels.params.rss_hfunc == MLX5E_HFUNC_XOR ?
		       "xor" : "toeplitz");

	len += sprintf(buf + len, "Supported hfuncs: xor toeplitz\n");

	rtnl_unlock();

	return len;
}

static ssize_t mlx5e_store_hfunc(struct device *device,
				 struct device_attribute *attr,
				 const char *buf, size_t count)
{
	struct mlx5e_priv *priv = netdev_priv(to_net_dev(device));
	u32 in[MLX5_ST_SZ_DW(modify_tir_in)] = {0};
	struct net_device *netdev = priv->netdev;
	char hfunc[ETH_GSTRING_LEN];
	u8 ethtool_hfunc;
	int err;

	err = sscanf(buf, "%31s", hfunc);

	if (err != 1)
		goto bad_input;

	if (!strcmp(hfunc, "xor"))
		ethtool_hfunc = MLX5E_HFUNC_XOR;
	else if (!strcmp(hfunc, "toeplitz"))
		ethtool_hfunc = MLX5E_HFUNC_TOP;
	else
		goto bad_input;

	rtnl_lock();
	mutex_lock(&priv->state_lock);

	if (priv->channels.params.rss_hfunc == ethtool_hfunc)
		goto unlock;

	priv->channels.params.rss_hfunc = ethtool_hfunc;
	mlx5e_sysfs_modify_tirs_hash(priv, in, sizeof(in));

unlock:
	mutex_unlock(&priv->state_lock);
	rtnl_unlock();

	return count;

bad_input:
	netdev_err(netdev, "Bad Input\n");
	return -EINVAL;
}

static DEVICE_ATTR(hfunc, S_IRUGO | S_IWUSR,
		  mlx5e_show_hfunc, mlx5e_store_hfunc);

static ssize_t mlx5e_show_link_down_reason(struct device *device,
					    struct device_attribute *attr,
					    char *buf)
{
	u8 status_message[MLX5_FLD_SZ_BYTES(troubleshooting_info_page_layout,
					    status_message)];
	struct mlx5e_priv *priv = netdev_priv(to_net_dev(device));
	u16 monitor_opcode;
	int len = 0;
	int err;

	err = mlx5_query_pddr_troubleshooting_info(priv->mdev, &monitor_opcode,
						   status_message);
	if (err)
		return err;

	len += sprintf(buf + len, "monitor_opcode: %#x\n", monitor_opcode);
	len += sprintf(buf + len, "status_message: %s\n", status_message);

	return len;
}

static DEVICE_ATTR(link_down_reason, S_IRUGO,
		   mlx5e_show_link_down_reason, NULL);
#define MLX5E_PFC_PREVEN_CRITICAL_AUTO_MSEC	100
#define MLX5E_PFC_PREVEN_MINOR_AUTO_MSEC	85
#define MLX5E_PFC_PREVEN_CRITICAL_DEFAULT_MSEC	8000
#define MLX5E_PFC_PREVEN_MINOR_DEFAULT_MSEC	6800

static ssize_t mlx5e_get_pfc_prevention_mode(struct device *device,
					     struct device_attribute *attr,
					     char *buf)
{
	struct mlx5e_priv *priv = netdev_priv(to_net_dev(device));
	struct mlx5_core_dev *mdev = priv->mdev;
	u16 pfc_prevention_critical;
	char *str_critical;
	int len = 0;
	int err;

	if (!MLX5_CAP_PCAM_FEATURE(mdev, pfcc_mask))
		return -EOPNOTSUPP;

	err = mlx5_query_port_pfc_prevention(mdev, &pfc_prevention_critical);
	if (err)
		return err;

	str_critical = (pfc_prevention_critical ==
			MLX5E_PFC_PREVEN_CRITICAL_DEFAULT_MSEC) ?
			"default" : "auto";
	len += sprintf(buf, "%s\n", str_critical);

	return len;
}

static ssize_t mlx5e_set_pfc_prevention_mode(struct device *device,
					     struct device_attribute *attr,
					     const char *buf, size_t count)
{
	struct mlx5e_priv *priv = netdev_priv(to_net_dev(device));
	struct net_device *netdev = priv->netdev;
	struct mlx5_core_dev *mdev = priv->mdev;
	char pfc_stall_prevention[ETH_GSTRING_LEN];
	u16 pfc_prevention_critical;
	u16 pfc_prevention_minor;
	int err;

	if (!MLX5_CAP_PCAM_FEATURE(mdev, pfcc_mask))
		return -EOPNOTSUPP;

	err = sscanf(buf, "%31s", pfc_stall_prevention);

	if (!strcmp(pfc_stall_prevention, "default")) {
		pfc_prevention_critical = MLX5E_PFC_PREVEN_CRITICAL_DEFAULT_MSEC;
		pfc_prevention_minor = MLX5E_PFC_PREVEN_MINOR_DEFAULT_MSEC;
	} else if (!strcmp(pfc_stall_prevention, "auto")) {
		pfc_prevention_critical = MLX5E_PFC_PREVEN_CRITICAL_AUTO_MSEC;
		pfc_prevention_minor = MLX5E_PFC_PREVEN_MINOR_AUTO_MSEC;
	} else {
		goto bad_input;
	}

	rtnl_lock();

	err = mlx5_set_port_pfc_prevention(mdev, pfc_prevention_critical,
					   pfc_prevention_minor);

	rtnl_unlock();
	if (err)
		return err;

	return count;

bad_input:
	netdev_err(netdev, "Bad Input\n");
	return -EINVAL;
}

static DEVICE_ATTR(pfc_stall_prevention, S_IRUGO | S_IWUSR,
		   mlx5e_get_pfc_prevention_mode, mlx5e_set_pfc_prevention_mode);

static const char *mlx5e_get_cong_protocol(int protocol)
{
	switch (protocol) {
	case MLX5E_CON_PROTOCOL_802_1_RP:
		return "802.1.qau_rp";
	case MLX5E_CON_PROTOCOL_R_ROCE_RP:
		return "roce_rp";
	case MLX5E_CON_PROTOCOL_R_ROCE_NP:
		return "roce_np";
	}
	return "";
}

static void mlx5e_fill_rp_attributes(struct kobject *kobj,
				     struct mlx5_core_dev *mdev,
				     struct mlx5e_ecn_rp_attributes *rp_attr)
{
	int err;

	rp_attr->mdev = mdev;

	sysfs_attr_init(&rp_attr->clamp_tgt_rate.attr);
	rp_attr->clamp_tgt_rate.attr.name = "clamp_tgt_rate";
	rp_attr->clamp_tgt_rate.attr.mode = set_kobj_mode(mdev);
	rp_attr->clamp_tgt_rate.show = mlx5e_show_clamp_tgt_rate;
	rp_attr->clamp_tgt_rate.store = mlx5e_store_clamp_tgt_rate;
	err = sysfs_create_file(kobj, &rp_attr->clamp_tgt_rate.attr);

	sysfs_attr_init(&rp_attr->clamp_tgt_rate_ati.attr);
	rp_attr->clamp_tgt_rate_ati.attr.name = "clamp_tgt_rate_after_time_inc";
	rp_attr->clamp_tgt_rate_ati.attr.mode = set_kobj_mode(mdev);
	rp_attr->clamp_tgt_rate_ati.show = mlx5e_show_clamp_tgt_rate_ati;
	rp_attr->clamp_tgt_rate_ati.store = mlx5e_store_clamp_tgt_rate_ati;
	err = sysfs_create_file(kobj, &rp_attr->clamp_tgt_rate_ati.attr);

	sysfs_attr_init(&rp_attr->rpg_time_reset.attr);
	rp_attr->rpg_time_reset.attr.name = "rpg_time_reset";
	rp_attr->rpg_time_reset.attr.mode = set_kobj_mode(mdev);
	rp_attr->rpg_time_reset.show = mlx5e_show_rpg_time_reset;
	rp_attr->rpg_time_reset.store = mlx5e_store_rpg_time_reset;
	err = sysfs_create_file(kobj, &rp_attr->rpg_time_reset.attr);

	sysfs_attr_init(&rp_attr->rpg_byte_reset.attr);
	rp_attr->rpg_byte_reset.attr.name = "rpg_byte_reset";
	rp_attr->rpg_byte_reset.attr.mode = set_kobj_mode(mdev);
	rp_attr->rpg_byte_reset.show = mlx5e_show_rpg_byte_reset;
	rp_attr->rpg_byte_reset.store = mlx5e_store_rpg_byte_reset;
	err = sysfs_create_file(kobj, &rp_attr->rpg_byte_reset.attr);

	sysfs_attr_init(&rp_attr->rpg_threshold.attr);
	rp_attr->rpg_threshold.attr.name = "rpg_threshold";
	rp_attr->rpg_threshold.attr.mode = set_kobj_mode(mdev);
	rp_attr->rpg_threshold.show = mlx5e_show_rpg_threshold;
	rp_attr->rpg_threshold.store = mlx5e_store_rpg_threshold;
	err = sysfs_create_file(kobj, &rp_attr->rpg_threshold.attr);

	sysfs_attr_init(&rp_attr->rpg_max_rate.attr);
	rp_attr->rpg_max_rate.attr.name = "rpg_max_rate";
	rp_attr->rpg_max_rate.attr.mode = set_kobj_mode(mdev);
	rp_attr->rpg_max_rate.show = mlx5e_show_rpg_max_rate;
	rp_attr->rpg_max_rate.store = mlx5e_store_rpg_max_rate;
	err = sysfs_create_file(kobj, &rp_attr->rpg_max_rate.attr);

	sysfs_attr_init(&rp_attr->rpg_ai_rate.attr);
	rp_attr->rpg_ai_rate.attr.name = "rpg_ai_rate";
	rp_attr->rpg_ai_rate.attr.mode = set_kobj_mode(mdev);
	rp_attr->rpg_ai_rate.show = mlx5e_show_rpg_ai_rate;
	rp_attr->rpg_ai_rate.store = mlx5e_store_rpg_ai_rate;
	err = sysfs_create_file(kobj, &rp_attr->rpg_ai_rate.attr);

	sysfs_attr_init(&rp_attr->rpg_hai_rate.attr);
	rp_attr->rpg_hai_rate.attr.name = "rpg_hai_rate";
	rp_attr->rpg_hai_rate.attr.mode = set_kobj_mode(mdev);
	rp_attr->rpg_hai_rate.show = mlx5e_show_rpg_hai_rate;
	rp_attr->rpg_hai_rate.store = mlx5e_store_rpg_hai_rate;
	err = sysfs_create_file(kobj, &rp_attr->rpg_hai_rate.attr);

	sysfs_attr_init(&rp_attr->rpg_gd.attr);
	rp_attr->rpg_gd.attr.name = "rpg_gd";
	rp_attr->rpg_gd.attr.mode = set_kobj_mode(mdev);
	rp_attr->rpg_gd.show = mlx5e_show_rpg_gd;
	rp_attr->rpg_gd.store = mlx5e_store_rpg_gd;

	err = sysfs_create_file(kobj, &rp_attr->rpg_gd.attr);

	sysfs_attr_init(&rp_attr->rpg_min_dec_fac.attr);
	rp_attr->rpg_min_dec_fac.attr.name = "rpg_min_dec_fac";
	rp_attr->rpg_min_dec_fac.attr.mode = set_kobj_mode(mdev);
	rp_attr->rpg_min_dec_fac.show = mlx5e_show_rpg_min_dec_fac;
	rp_attr->rpg_min_dec_fac.store = mlx5e_store_rpg_min_dec_fac;
	err = sysfs_create_file(kobj, &rp_attr->rpg_min_dec_fac.attr);

	sysfs_attr_init(&rp_attr->rpg_min_rate.attr);
	rp_attr->rpg_min_rate.attr.name = "rpg_min_rate";
	rp_attr->rpg_min_rate.attr.mode = set_kobj_mode(mdev);
	rp_attr->rpg_min_rate.show = mlx5e_show_rpg_min_rate;
	rp_attr->rpg_min_rate.store = mlx5e_store_rpg_min_rate;
	err = sysfs_create_file(kobj, &rp_attr->rpg_min_rate.attr);

	sysfs_attr_init(&rp_attr->rate2set_fcnp.attr);
	rp_attr->rate2set_fcnp.attr.name = "rate_to_set_on_first_cnp";
	rp_attr->rate2set_fcnp.attr.mode = set_kobj_mode(mdev);
	rp_attr->rate2set_fcnp.show = mlx5e_show_rate2set_fcnp;
	rp_attr->rate2set_fcnp.store = mlx5e_store_rate2set_fcnp;
	err = sysfs_create_file(kobj, &rp_attr->rate2set_fcnp.attr);

	sysfs_attr_init(&rp_attr->dce_tcp_g.attr);
	rp_attr->dce_tcp_g.attr.name = "dce_tcp_g";
	rp_attr->dce_tcp_g.attr.mode = set_kobj_mode(mdev);
	rp_attr->dce_tcp_g.show = mlx5e_show_dce_tcp_g;
	rp_attr->dce_tcp_g.store = mlx5e_store_dce_tcp_g;
	err = sysfs_create_file(kobj, &rp_attr->dce_tcp_g.attr);

	sysfs_attr_init(&rp_attr->dce_tcp_rtt.attr);
	rp_attr->dce_tcp_rtt.attr.name = "dce_tcp_rtt";
	rp_attr->dce_tcp_rtt.attr.mode = set_kobj_mode(mdev);
	rp_attr->dce_tcp_rtt.show = mlx5e_show_dce_tcp_rtt;
	rp_attr->dce_tcp_rtt.store = mlx5e_store_dce_tcp_rtt;
	err = sysfs_create_file(kobj, &rp_attr->dce_tcp_rtt.attr);

	sysfs_attr_init(&rp_attr->rreduce_mperiod.attr);
	rp_attr->rreduce_mperiod.attr.name = "rate_reduce_monitor_period";
	rp_attr->rreduce_mperiod.attr.mode = set_kobj_mode(mdev);
	rp_attr->rreduce_mperiod.show = mlx5e_show_rreduce_mperiod;
	rp_attr->rreduce_mperiod.store = mlx5e_store_rreduce_mperiod;
	err = sysfs_create_file(kobj, &rp_attr->rreduce_mperiod.attr);

	sysfs_attr_init(&rp_attr->initial_alpha_value.attr);
	rp_attr->initial_alpha_value.attr.name = "initial_alpha_value";
	rp_attr->initial_alpha_value.attr.mode = set_kobj_mode(mdev);
	rp_attr->initial_alpha_value.show = mlx5e_show_initial_alpha_value;
	rp_attr->initial_alpha_value.store = mlx5e_store_initial_alpha_value;
	err = sysfs_create_file(kobj, &rp_attr->initial_alpha_value.attr);
}

static void mlx5e_remove_rp_attributes(struct kobject *kobj,
				       struct mlx5e_ecn_rp_attributes *rp_attr)
{
	sysfs_remove_file(kobj, &rp_attr->clamp_tgt_rate.attr);
	sysfs_remove_file(kobj, &rp_attr->clamp_tgt_rate_ati.attr);
	sysfs_remove_file(kobj, &rp_attr->rpg_time_reset.attr);
	sysfs_remove_file(kobj, &rp_attr->rpg_byte_reset.attr);
	sysfs_remove_file(kobj, &rp_attr->rpg_threshold.attr);
	sysfs_remove_file(kobj, &rp_attr->rpg_max_rate.attr);
	sysfs_remove_file(kobj, &rp_attr->rpg_ai_rate.attr);
	sysfs_remove_file(kobj, &rp_attr->rpg_hai_rate.attr);
	sysfs_remove_file(kobj, &rp_attr->rpg_gd.attr);
	sysfs_remove_file(kobj, &rp_attr->rpg_min_dec_fac.attr);
	sysfs_remove_file(kobj, &rp_attr->rpg_min_rate.attr);
	sysfs_remove_file(kobj, &rp_attr->rate2set_fcnp.attr);
	sysfs_remove_file(kobj, &rp_attr->dce_tcp_g.attr);
	sysfs_remove_file(kobj, &rp_attr->dce_tcp_rtt.attr);
	sysfs_remove_file(kobj, &rp_attr->rreduce_mperiod.attr);
	sysfs_remove_file(kobj, &rp_attr->initial_alpha_value.attr);
}

static void mlx5e_fill_np_attributes(struct kobject *kobj,
				     struct mlx5_core_dev *mdev,
				     struct mlx5e_ecn_np_attributes *np_attr)
{
	int err;

	np_attr->mdev = mdev;

	sysfs_attr_init(&np_attr->min_time_between_cnps.attr);
	np_attr->min_time_between_cnps.attr.name = "min_time_between_cnps";
	np_attr->min_time_between_cnps.attr.mode = set_kobj_mode(mdev);
	np_attr->min_time_between_cnps.show  = mlx5e_show_min_time_between_cnps;
	np_attr->min_time_between_cnps.store =
					  mlx5e_store_min_time_between_cnps;
	err = sysfs_create_file(kobj, &np_attr->min_time_between_cnps.attr);

	sysfs_attr_init(&np_attr->cnp_dscp.attr);
	np_attr->cnp_dscp.attr.name = "cnp_dscp";
	np_attr->cnp_dscp.attr.mode = set_kobj_mode(mdev);
	np_attr->cnp_dscp.show  = mlx5e_show_cnp_dscp;
	np_attr->cnp_dscp.store = mlx5e_store_cnp_dscp;
	err = sysfs_create_file(kobj, &np_attr->cnp_dscp.attr);

	sysfs_attr_init(&np_attr->cnp_802p_prio.attr);
	np_attr->cnp_802p_prio.attr.name = "cnp_802p_prio";
	np_attr->cnp_802p_prio.attr.mode = set_kobj_mode(mdev);
	np_attr->cnp_802p_prio.show  = mlx5e_show_cnp_802p_prio;
	np_attr->cnp_802p_prio.store = mlx5e_store_cnp_802p_prio;
	err = sysfs_create_file(kobj, &np_attr->cnp_802p_prio.attr);
}

static void mlx5e_remove_np_attributes(struct kobject *kobj,
				       struct mlx5e_ecn_np_attributes *np_attr)
{
	sysfs_remove_file(kobj, &np_attr->min_time_between_cnps.attr);
	sysfs_remove_file(kobj, &np_attr->cnp_dscp.attr);
	sysfs_remove_file(kobj, &np_attr->cnp_802p_prio.attr);
}

static void mlx5e_fill_attributes(struct mlx5e_priv *priv,
				  int proto)
{
	const char *priority_arr[8] = {"0", "1", "2", "3", "4", "5", "6", "7"};
	struct mlx5e_ecn_ctx *ecn_ctx = &priv->ecn_ctx[proto];
	struct mlx5e_ecn_enable_ctx *ecn_enable_ctx;
	int i, err;

	ecn_ctx->ecn_enable_kobj = kobject_create_and_add("enable",
				   ecn_ctx->ecn_proto_kobj);

	for (i = 0; i < 8; i++) {
		ecn_enable_ctx = &priv->ecn_enable_ctx[proto][i];
		ecn_enable_ctx->priority = i;
		ecn_enable_ctx->cong_protocol = proto;
		ecn_enable_ctx->mdev = priv->mdev;
		sysfs_attr_init(&ecn_enable_ctx->enable.attr);
		ecn_enable_ctx->enable.attr.name = priority_arr[i];
		ecn_enable_ctx->enable.attr.mode = set_kobj_mode(priv->mdev);
		ecn_enable_ctx->enable.show  = mlx5e_show_ecn_enable;
		ecn_enable_ctx->enable.store = mlx5e_store_ecn_enable;
		err = sysfs_create_file(ecn_ctx->ecn_enable_kobj,
					&ecn_enable_ctx->enable.attr);
	}

	switch (proto) {
	case MLX5E_CON_PROTOCOL_802_1_RP:
		return;
	case MLX5E_CON_PROTOCOL_R_ROCE_RP:
		return mlx5e_fill_rp_attributes(ecn_ctx->ecn_proto_kobj,
						priv->mdev,
						&ecn_ctx->ecn_attr.rp_attr);
	case MLX5E_CON_PROTOCOL_R_ROCE_NP:
		return mlx5e_fill_np_attributes(ecn_ctx->ecn_proto_kobj,
						priv->mdev,
						&ecn_ctx->ecn_attr.np_attr);
	}
}

#ifdef CONFIG_MLX5_ESWITCH
static ssize_t mlx5e_show_vf_roce(struct device *device,
				  struct device_attribute *attr,
				  char *buf)
{
	struct mlx5e_priv *priv = netdev_priv(to_net_dev(device));
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_eswitch *esw = mdev->priv.eswitch;
	int len = 0;
	bool mode;
	int err = 0;
	int i;

	for (i = 1; i < esw->total_vports; i++) {
		err = mlx5_eswitch_vport_get_other_hca_cap_roce(esw, i, &mode);
		if (err)
			break;
		len += sprintf(buf + len, "vf_num %d: %d\n", i - 1, mode);
	}

	if (err)
		return 0;

	return len;
}

static ssize_t mlx5e_store_vf_roce(struct device *device,
				   struct device_attribute *attr,
				   const char *buf, size_t count)
{
	struct mlx5e_priv *priv = netdev_priv(to_net_dev(device));
	struct mlx5_core_dev *mdev = priv->mdev;
	struct mlx5_eswitch *esw = mdev->priv.eswitch;
	int vf_num, err;
	int mode;

	err = sscanf(buf, "%d %d", &vf_num, &mode);
	if (err != 2)
		return -EINVAL;

	err = mlx5_eswitch_vport_modify_other_hca_cap_roce(esw, vf_num + 1, (bool)mode);
	if (err)
		return err;

	return count;
}
#endif

static void mlx5e_remove_attributes(struct mlx5e_priv *priv,
				    int proto)
{
	struct mlx5e_ecn_ctx *ecn_ctx = &priv->ecn_ctx[proto];
	struct mlx5e_ecn_enable_ctx *ecn_enable_ctx;
	int i;

	for (i = 0; i < 8; i++) {
		ecn_enable_ctx = &priv->ecn_enable_ctx[proto][i];
		sysfs_remove_file(priv->ecn_ctx[proto].ecn_enable_kobj,
				  &ecn_enable_ctx->enable.attr);
	}

	kobject_put(priv->ecn_ctx[proto].ecn_enable_kobj);

	switch (proto) {
	case MLX5E_CON_PROTOCOL_802_1_RP:
		return;
	case MLX5E_CON_PROTOCOL_R_ROCE_RP:
		mlx5e_remove_rp_attributes(priv->ecn_ctx[proto].ecn_proto_kobj,
					   &ecn_ctx->ecn_attr.rp_attr);
		break;
	case MLX5E_CON_PROTOCOL_R_ROCE_NP:
		mlx5e_remove_np_attributes(priv->ecn_ctx[proto].ecn_proto_kobj,
					   &ecn_ctx->ecn_attr.np_attr);
		break;
	}
}

#ifdef HAVE_IEEE_DCBNL_ETS
#ifdef CONFIG_MLX5_CORE_EN_DCB
static ssize_t mlx5e_show_prio2buffer(struct device *device,
				      struct device_attribute *attr,
				      char *buf)
{
	struct net_device *dev = to_net_dev(device);
	struct mlx5e_priv *priv = netdev_priv(dev);
	u8 prio2buffer[MLX5E_MAX_PRIORITY];
	int len = 0;
	int err;
	int i;

	err = mlx5e_port_query_priority2buffer(priv->mdev, prio2buffer);
	if (err)
		return err;

	len += sprintf(buf + len, "Priority\tBuffer\n");
	for (i = 0; i < MLX5E_MAX_PRIORITY; i++)
		len += sprintf(buf + len, "%d\t\t%d\n",
			       i, prio2buffer[i]);

	return len;
}

static ssize_t mlx5e_store_prio2buffer(struct device *device,
				       struct device_attribute *attr,
				       const char *buf, size_t count)
{
	struct net_device *dev = to_net_dev(device);
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;
	u8 old_prio2buffer[MLX5E_MAX_PRIORITY];
	u8 prio2buffer[MLX5E_MAX_PRIORITY];
	unsigned int temp;
	char *options;
	char *p;
	u32 changed = 0;
	int i = 0;
	int err;

	options = kstrdup(buf, GFP_KERNEL);
	while ((p = strsep(&options, ",")) != NULL && i < MLX5E_MAX_PRIORITY) {
		if (sscanf(p, "%u", &temp) != 1)
			continue;
		if (temp > 7)
			return -EINVAL;
		prio2buffer[i] = temp;
		i++;
	}

	if (i != MLX5E_MAX_PRIORITY)
		return -EINVAL;

	err = mlx5e_port_query_priority2buffer(mdev, old_prio2buffer);
	if (err)
		return err;

	for (i = 0; i < MLX5E_MAX_PRIORITY; i++) {
		if (prio2buffer[i] != old_prio2buffer[i]) {
			changed = MLX5E_PORT_BUFFER_PRIO2BUFFER;
			break;
		}
	}

	err = mlx5e_port_manual_buffer_config(priv, changed, dev->mtu, NULL, NULL, prio2buffer);
	if (err)
		return err;

	return count;
}

static ssize_t mlx5e_show_buffer_size(struct device *device,
				      struct device_attribute *attr,
				      char *buf)
{
	struct net_device *dev = to_net_dev(device);
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5e_port_buffer port_buffer;
	int len = 0;
	int err;
	int i;

	err = mlx5e_port_query_buffer(priv, &port_buffer);
	if (err)
		return err;

	len += sprintf(buf + len, "Port buffer size = %d\n", port_buffer.port_buffer_size);
	len += sprintf(buf + len, "Spare buffer size = %d\n", port_buffer.spare_buffer_size);
	len += sprintf(buf + len, "Buffer\tSize\txoff_threshold\txon_threshold\n");
	for (i = 0; i < MLX5E_MAX_BUFFER; i++)
		len += sprintf(buf + len, "%d\t%d\t%d\t\t%d\n", i,
			       port_buffer.buffer[i].size,
			       port_buffer.buffer[i].xoff,
			       port_buffer.buffer[i].xon);

	return len;
}

static ssize_t mlx5e_store_buffer_size(struct device *device,
				       struct device_attribute *attr,
				       const char *buf, size_t count)
{
	struct net_device *dev = to_net_dev(device);
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5e_port_buffer port_buffer;
	u32 buffer_size[MLX5E_MAX_BUFFER];
	unsigned int temp;
	char *options;
	char *p;
	u32 changed = 0;
	int i = 0;
	int err;

	options = kstrdup(buf, GFP_KERNEL);
	while ((p = strsep(&options, ",")) != NULL && i < MLX5E_MAX_BUFFER) {
		if (sscanf(p, "%u", &temp) != 1)
			continue;
		buffer_size[i] = temp;
		i++;
	}

	if (i != MLX5E_MAX_BUFFER)
		return -EINVAL;

	err = mlx5e_port_query_buffer(priv, &port_buffer);
	if (err)
		return err;

	for (i = 0; i < MLX5E_MAX_BUFFER; i++) {
		if (port_buffer.buffer[i].size != buffer_size[i]) {
			changed = MLX5E_PORT_BUFFER_SIZE;
			break;
		}
	}

	err = mlx5e_port_manual_buffer_config(priv, changed, dev->mtu, NULL, buffer_size, NULL);
	if (err)
		return err;

	return count;
}
#endif
#endif

#ifdef HAVE_IEEE_DCBNL_ETS
#ifdef CONFIG_MLX5_CORE_EN_DCB
static DEVICE_ATTR(buffer_size, S_IRUGO | S_IWUSR,
		   mlx5e_show_buffer_size,
		   mlx5e_store_buffer_size);

static DEVICE_ATTR(prio2buffer, S_IRUGO | S_IWUSR,
		   mlx5e_show_prio2buffer,
		   mlx5e_store_prio2buffer);
#endif
#endif

#ifdef CONFIG_MLX5_ESWITCH
static DEVICE_ATTR(vf_roce, S_IRUGO | S_IWUSR,
		   mlx5e_show_vf_roce,
		   mlx5e_store_vf_roce);
#endif

static ssize_t mlx5e_show_force_local_lb(struct device *device,
					 struct device_attribute *attr,
					 char *buf)
{
	struct net_device *dev = to_net_dev(device);
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;
	bool force_disable_lb = mdev->local_lb.user_force_disable;
	int len = 0;

	len += sprintf(buf, "Force local loopback disable is %s\n", force_disable_lb ? "ON" : "OFF");

	return len;
}

static ssize_t mlx5e_store_force_local_lb(struct device *device,
					  struct device_attribute *attr,
					  const char *buf, size_t count)
{
	struct net_device *dev = to_net_dev(device);
	struct mlx5e_priv *priv = netdev_priv(dev);
	struct mlx5_core_dev *mdev = priv->mdev;
	bool disable;
	int err;
#ifndef HAVE_KSTRTOBOOL
	int udata;

	err = sscanf(buf, "%d", &udata);
	if (err != 1)
		return -EINVAL;

	if (udata >> 1)
		return -EINVAL;

	disable = udata ? true : false;
#else
	err = kstrtobool(buf, &disable);
	if (err)
		return -EINVAL;
#endif

	if (mdev->local_lb.user_force_disable != disable) {
		mdev->local_lb.user_force_disable = disable;
		mlx5_nic_vport_update_local_lb(mdev,
					       mdev->local_lb.driver_state);
	}

	return count;
}

static DEVICE_ATTR(force_local_lb_disable, S_IRUGO | S_IWUSR,
		   mlx5e_show_force_local_lb,
		   mlx5e_store_force_local_lb);

static struct attribute *mlx5e_settings_attrs[] = {
	&dev_attr_hfunc.attr,
	&dev_attr_pfc_stall_prevention.attr,
	NULL,
};

static struct attribute_group settings_group = {
	.name = "settings",
	.attrs = mlx5e_settings_attrs,
};

static struct attribute *mlx5e_debug_group_attrs[] = {
	&dev_attr_lro_timeout.attr,
	&dev_attr_link_down_reason.attr,
	NULL,
};

static struct attribute *mlx5e_qos_attrs[] = {
#if defined(HAVE_NETDEV_GET_NUM_TC) && defined(HAVE_NETDEV_SET_NUM_TC)
	&dev_attr_tc_num.attr,
#endif
	&dev_attr_maxrate.attr,
	NULL,
};

static struct attribute_group qos_group = {
	.name = "qos",
	.attrs = mlx5e_qos_attrs,
};

static struct attribute_group debug_group = {
	.name = "debug",
	.attrs = mlx5e_debug_group_attrs,
};

#define PHY_STAT_ENTRY(name, cnt)					\
static ssize_t name##_show(struct device *d,				\
			   struct device_attribute *attr, char *buf)	\
{									\
	struct net_device *dev = to_net_dev(d);				\
	struct mlx5e_priv *priv = netdev_priv(dev);			\
	struct mlx5e_pport_stats *pstats = &priv->stats.pport;		\
									\
	return sprintf(buf, "%llu\n",					\
			PPORT_802_3_GET(pstats, cnt));			\
}									\
static DEVICE_ATTR(name, S_IRUGO, name##_show, NULL)

PHY_STAT_ENTRY(rx_packets, a_frames_received_ok);
PHY_STAT_ENTRY(tx_packets, a_frames_transmitted_ok);
PHY_STAT_ENTRY(rx_bytes, a_octets_received_ok);
PHY_STAT_ENTRY(tx_bytes, a_octets_transmitted_ok);

static struct attribute *mlx5e_phy_stat_attrs[] = {
	&dev_attr_rx_packets.attr,
	&dev_attr_tx_packets.attr,
	&dev_attr_rx_bytes.attr,
	&dev_attr_tx_bytes.attr,
	NULL,
};

static struct attribute_group phy_stat_group = {
	.name = "phy_stats",
	.attrs = mlx5e_phy_stat_attrs,
};

static int update_qos_sysfs(struct net_device *dev,
			    struct mlx5_core_dev *mdev)
{
	int err = 0;

#ifdef HAVE_IEEE_DCBNL_ETS
#ifdef CONFIG_MLX5_CORE_EN_DCB
	if (MLX5_BUFFER_SUPPORTED(mdev)) {
		err = sysfs_add_file_to_group(&dev->dev.kobj,
					      &dev_attr_prio2buffer.attr,
					      "qos");
		err = sysfs_add_file_to_group(&dev->dev.kobj,
					      &dev_attr_buffer_size.attr,
					      "qos");
	}
#endif
#endif

	return err;
}

static int update_settings_sysfs(struct net_device *dev,
				 struct mlx5_core_dev *mdev)
{
	int err = 0;

#ifdef CONFIG_MLX5_ESWITCH
	if (MLX5_CAP_GEN(mdev, vport_group_manager) &&
	    MLX5_CAP_GEN(mdev, port_type) == MLX5_CAP_PORT_TYPE_ETH) {
		err = sysfs_add_file_to_group(&dev->dev.kobj,
					      &dev_attr_vf_roce.attr,
					      "settings");
	}
#endif

	if (MLX5_CAP_GEN(mdev, disable_local_lb_mc) ||
	    MLX5_CAP_GEN(mdev, disable_local_lb_uc)) {
		err = sysfs_add_file_to_group(&dev->dev.kobj,
					      &dev_attr_force_local_lb_disable.attr,
					      "settings");
	}

	return err;
}

int mlx5e_sysfs_create(struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int err = 0;
	int i;

	priv->ecn_root_kobj = kobject_create_and_add("ecn", &dev->dev.kobj);

	for (i = 1; i < MLX5E_CONG_PROTOCOL_NUM; i++) {
		priv->ecn_ctx[i].ecn_proto_kobj = kobject_create_and_add(
					     mlx5e_get_cong_protocol(i),
					     priv->ecn_root_kobj);
		mlx5e_fill_attributes(priv, i);
	}

	err = sysfs_create_group(&dev->dev.kobj, &settings_group);
	if (err)
		goto remove_attributes;

	err = update_settings_sysfs(dev, priv->mdev);
	if (err)
		goto remove_settings_group;

	err = sysfs_create_group(&dev->dev.kobj, &qos_group);
	if (err)
		goto remove_settings_group;

	err = update_qos_sysfs(dev, priv->mdev);
	if (err)
		goto remove_qos_group;

	err = sysfs_create_group(&dev->dev.kobj, &debug_group);

	if (err)
		goto remove_qos_group;

	err = sysfs_create_group(&dev->dev.kobj, &phy_stat_group);

	if (err)
		goto remove_debug_group;

	mlx5_eswitch_compat_sysfs_init(dev);

	return 0;

remove_debug_group:
	sysfs_remove_group(&dev->dev.kobj, &phy_stat_group);
remove_qos_group:
	sysfs_remove_group(&dev->dev.kobj, &qos_group);
remove_settings_group:
	sysfs_remove_group(&dev->dev.kobj, &settings_group);
remove_attributes:
	for (i = 1; i < MLX5E_CONG_PROTOCOL_NUM; i++) {
		mlx5e_remove_attributes(priv, i);
		kobject_put(priv->ecn_ctx[i].ecn_proto_kobj);
	}

	kobject_put(priv->ecn_root_kobj);

	return err;
}

void mlx5e_sysfs_remove(struct net_device *dev)
{
	struct mlx5e_priv *priv = netdev_priv(dev);
	int i;

	mlx5_eswitch_compat_sysfs_cleanup(dev);

	sysfs_remove_group(&dev->dev.kobj, &qos_group);
	sysfs_remove_group(&dev->dev.kobj, &debug_group);
	sysfs_remove_group(&dev->dev.kobj, &settings_group);
	sysfs_remove_group(&dev->dev.kobj, &phy_stat_group);

	for (i = 1; i < MLX5E_CONG_PROTOCOL_NUM; i++) {
		mlx5e_remove_attributes(priv, i);
		kobject_put(priv->ecn_ctx[i].ecn_proto_kobj);
	}

	kobject_put(priv->ecn_root_kobj);
}
