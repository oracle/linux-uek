// SPDX-License-Identifier: GPL-2.0 or BSD-3-Clause
/*
 *  Copyright (C) 2023 NVIDIA Corporation & Affiliates.
 *
 *  Nvidia Bluefield power and thermal debugfs driver
 *  This driver provides a debugfs interface for systems management
 *  software to monitor power and thermal actions.
 */

#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/arm-smccc.h>

/* SMC IDs */
#define MLNX_PTM_GET_VR0_POWER		0x82000101
#define MLNX_PTM_GET_VR1_POWER		0x82000102
#define MLNX_PTM_GET_THROTTLE_STATE	0x82000103
#define MLNX_PTM_GET_DDR_THLD		0x82000104
#define MLNX_PTM_GET_STATUS_REG		0x82000105
#define MLNX_PTM_GET_PTHROTTLE          0x82000106
#define MLNX_PTM_GET_TTHROTTLE          0x82000107
#define MLNX_PTM_GET_MAX_TEMP           0x82000108
#define MLNX_PTM_GET_PWR_EVT_CNT	0x82000109
#define MLNX_PTM_GET_TEMP_EVT_CNT	0x8200010A
#define MLNX_PTM_GET_POWER_ENVELOPE     0x8200010B
#define MLNX_PTM_GET_ATX_PWR_STATE      0x8200010C
#define MLNX_PTM_GET_CUR_PPROFILE       0x8200010D

#define MLNX_POWER_ERROR		300

struct dentry *monitors;

static int smc_call1(unsigned int smc_op, int smc_arg)
{
	struct arm_smccc_res res;

	arm_smccc_smc(smc_op, smc_arg, 0, 0, 0, 0, 0, 0, &res);

	return res.a0;
}

#define smc_call0(smc_op) smc_call1(smc_op, 0)

static int throttling_state_show(void *data, u64 *val)
{
	*val = smc_call0(MLNX_PTM_GET_THROTTLE_STATE);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(throttling_state_fops,
			throttling_state_show, NULL, "%llu\n");

static int pthrottling_state_show(void *data, u64 *val)
{
	*val = smc_call0(MLNX_PTM_GET_PTHROTTLE);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(pthrottling_state_fops,
			pthrottling_state_show, NULL, "%llu\n");

static int tthrottling_state_show(void *data, u64 *val)
{
	*val = smc_call0(MLNX_PTM_GET_TTHROTTLE);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(tthrottling_state_fops,
			tthrottling_state_show, NULL, "%llu\n");

static int core_temp_show(void *data, u64 *val)
{
	*val = smc_call0(MLNX_PTM_GET_MAX_TEMP);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(core_temp_fops,
			core_temp_show, NULL, "%lld\n");

static int pwr_evt_counter_show(void *data, u64 *val)
{
	*val = smc_call0(MLNX_PTM_GET_PWR_EVT_CNT);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(pwr_evt_counter_fops,
			pwr_evt_counter_show, NULL, "%llu\n");

static int temp_evt_counter_show(void *data, u64 *val)
{
	*val = smc_call0(MLNX_PTM_GET_TEMP_EVT_CNT);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(temp_evt_counter_fops,
			temp_evt_counter_show, NULL, "%llu\n");

static int vr0_power_show(void *data, u64 *val)
{
	*val = smc_call0(MLNX_PTM_GET_VR0_POWER);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(vr0_power_fops, vr0_power_show, NULL, "%llu\n");

static int vr1_power_show(void *data, u64 *val)
{
	*val = smc_call0(MLNX_PTM_GET_VR1_POWER);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(vr1_power_fops, vr1_power_show, NULL, "%llu\n");

static int total_power_show(void *data, u64 *val)
{
	u64 v0, v1;

	v0 = smc_call0(MLNX_PTM_GET_VR0_POWER);
	if (v0 > MLNX_POWER_ERROR)
		v0 = 0;
	v1 = smc_call0(MLNX_PTM_GET_VR1_POWER);
	if (v1 > MLNX_POWER_ERROR)
		v1 = 0;
	*val = (v0 + v1);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(total_power_fops, total_power_show, NULL, "%llu\n");

static int ddr_thld_show(void *data, u64 *val)
{
	*val = smc_call0(MLNX_PTM_GET_DDR_THLD);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(ddr_thld_fops, ddr_thld_show, NULL, "%llu\n");

static int error_status_show(void *data, u64 *val)
{
	*val = smc_call0(MLNX_PTM_GET_STATUS_REG);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(error_status_fops,
			error_status_show, NULL, "%llu\n");

static int power_envelope_show(void *data, u64 *val)
{
	*val = smc_call0(MLNX_PTM_GET_POWER_ENVELOPE);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(power_envelope_fops,
			power_envelope_show, NULL, "%llu\n");

static int atx_status_show(void *data, u64 *val)
{
	*val = smc_call0(MLNX_PTM_GET_ATX_PWR_STATE);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(atx_status_fops,
			atx_status_show, NULL, "%lld\n");

static int current_pprofile_show(void *data, u64 *val)
{
	*val = smc_call0(MLNX_PTM_GET_CUR_PPROFILE);

	return 0;
}
DEFINE_SIMPLE_ATTRIBUTE(current_pprofile_fops,
			current_pprofile_show, NULL, "%llu\n");


static int __init mlxbf_ptm_init(void)
{
	struct dentry *ptm_root, *status;

	ptm_root = debugfs_lookup("mlxbf-ptm", NULL);
	if (!ptm_root)
		ptm_root = debugfs_create_dir("mlxbf-ptm", NULL);

	monitors = debugfs_create_dir("monitors", ptm_root);
	status = debugfs_create_dir("status", monitors);

	debugfs_create_file("vr0_power", 0444, status, NULL,
			    &vr0_power_fops);
	debugfs_create_file("vr1_power", 0444, status, NULL,
			    &vr1_power_fops);
	debugfs_create_file("total_power", 0444, status, NULL,
			    &total_power_fops);
	debugfs_create_file("ddr_temp", 0444, status,
			    NULL, &ddr_thld_fops);
	debugfs_create_file("core_temp", 0444, status,
			    NULL, &core_temp_fops);
	debugfs_create_file("power_throttling_event_count", 0444, status,
			    NULL, &pwr_evt_counter_fops);
	debugfs_create_file("thermal_throttling_event_count", 0444, status,
			    NULL, &temp_evt_counter_fops);
	debugfs_create_file("throttling_state", 0444, status,
			    NULL, &throttling_state_fops);
	debugfs_create_file("power_throttling_state", 0444, status,
			    NULL, &pthrottling_state_fops);
	debugfs_create_file("thermal_throttling_state", 0444, status,
			    NULL, &tthrottling_state_fops);
	debugfs_create_file("error_state", 0444, status,
			    NULL, &error_status_fops);
	debugfs_create_file("power_envelope", 0444, status,
			    NULL, &power_envelope_fops);
	debugfs_create_file("atx_power_available", 0444, status,
			    NULL, &atx_status_fops);
	debugfs_create_file("active_power_profile", 0444, status,
			    NULL, &current_pprofile_fops);

	return 0;
}

static void __exit mlxbf_ptm_exit(void)
{
	debugfs_remove_recursive(monitors);
}

module_init(mlxbf_ptm_init);
module_exit(mlxbf_ptm_exit);

MODULE_AUTHOR("Jitendra Lanka <jlanka@nvidia.com>");
MODULE_DESCRIPTION("Nvidia Bluefield power and thermal debugfs driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION("1.0");
