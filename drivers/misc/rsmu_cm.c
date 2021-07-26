// SPDX-License-Identifier: GPL-2.0+
/*
 * This driver is developed for the IDT ClockMatrix(TM) of
 * timing and synchronization devices.
 *
 * Copyright (C) 2019 Integrated Device Technology, Inc., a Renesas Company.
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/mfd/idt8a340_reg.h>
#include <linux/mfd/rsmu.h>
#include <uapi/linux/rsmu.h>
#include <asm/unaligned.h>

#include "rsmu_cdev.h"

static int rsmu_cm_set_combomode(struct rsmu_cdev *rsmu, u8 dpll, u8 mode)
{
	u16 dpll_ctrl_n;
	u8 cfg;
	int err;

	switch (dpll) {
	case 0:
		dpll_ctrl_n = DPLL_CTRL_0;
		break;
	case 1:
		dpll_ctrl_n = DPLL_CTRL_1;
		break;
	case 2:
		dpll_ctrl_n = DPLL_CTRL_2;
		break;
	case 3:
		dpll_ctrl_n = DPLL_CTRL_3;
		break;
	case 4:
		dpll_ctrl_n = DPLL_CTRL_4;
		break;
	case 5:
		dpll_ctrl_n = DPLL_CTRL_5;
		break;
	case 6:
		dpll_ctrl_n = DPLL_CTRL_6;
		break;
	case 7:
		dpll_ctrl_n = DPLL_CTRL_7;
		break;
	default:
		return -EINVAL;
	}

	if (mode >= E_COMBOMODE_MAX)
		return -EINVAL;

	err = rsmu_read(rsmu->mfd, dpll_ctrl_n + DPLL_CTRL_COMBO_MASTER_CFG,
			&cfg, sizeof(cfg));
	if (err)
		return err;

	/* Only need to enable/disable COMBO_MODE_HOLD. */
	if (mode)
		cfg |= COMBO_MASTER_HOLD;
	else
		cfg &= ~COMBO_MASTER_HOLD;

	return rsmu_write(rsmu->mfd, dpll_ctrl_n + DPLL_CTRL_COMBO_MASTER_CFG,
			  &cfg, sizeof(cfg));
}

static int rsmu_cm_get_dpll_state(struct rsmu_cdev *rsmu, u8 dpll, u8 *state)
{
	u8 cfg;
	int err;

	/* 8 is sys dpll */
	if (dpll > 8)
		return -EINVAL;

	err = rsmu_read(rsmu->mfd,
			  STATUS + DPLL0_STATUS + dpll,
			  &cfg, sizeof(cfg));
	if (err)
		return err;

	switch (cfg & DPLL_STATE_MASK) {
	case DPLL_STATE_FREERUN:
		*state = E_SRVLOUNQUALIFIEDSTATE;
		break;
	case DPLL_STATE_LOCKACQ:
	case DPLL_STATE_LOCKREC:
		*state = E_SRVLOLOCKACQSTATE;
		break;
	case DPLL_STATE_LOCKED:
		*state = E_SRVLOTIMELOCKEDSTATE;
		break;
	case DPLL_STATE_HOLDOVER:
		*state = E_SRVLOHOLDOVERINSPECSTATE;
		break;
	default:
		*state = E_SRVLOSTATEINVALID;
		break;
	}

	return 0;
}

static int rsmu_cm_get_dpll_ffo(struct rsmu_cdev *rsmu, u8 dpll,
				struct rsmu_get_ffo *ffo)
{
	u8 buf[8] = {0};
	s64 fcw = 0;
	u16 dpll_filter_status;
	int err;

	switch (dpll) {
	case 0:
		dpll_filter_status = DPLL0_FILTER_STATUS;
		break;
	case 1:
		dpll_filter_status = DPLL1_FILTER_STATUS;
		break;
	case 2:
		dpll_filter_status = DPLL2_FILTER_STATUS;
		break;
	case 3:
		dpll_filter_status = DPLL3_FILTER_STATUS;
		break;
	case 4:
		dpll_filter_status = DPLL4_FILTER_STATUS;
		break;
	case 5:
		dpll_filter_status = DPLL5_FILTER_STATUS;
		break;
	case 6:
		dpll_filter_status = DPLL6_FILTER_STATUS;
		break;
	case 7:
		dpll_filter_status = DPLL7_FILTER_STATUS;
		break;
	case 8:
		dpll_filter_status = DPLLSYS_FILTER_STATUS;
		break;
	default:
		return -EINVAL;
	}

	err = rsmu_read(rsmu->mfd, STATUS + dpll_filter_status, buf, 6);
	if (err)
		return err;

	/* Convert to frequency control word */
	fcw = sign_extend64(get_unaligned_le64(buf), 47);

	/* FCW unit is 2 ^ -53 = 1.1102230246251565404236316680908e-16 */
	ffo->ffo = fcw * 111;

	return 0;
}

struct rsmu_ops cm_ops = {
	.type = RSMU_CM,
	.set_combomode = rsmu_cm_set_combomode,
	.get_dpll_state = rsmu_cm_get_dpll_state,
	.get_dpll_ffo = rsmu_cm_get_dpll_ffo,
};
