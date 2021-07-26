// SPDX-License-Identifier: GPL-2.0+
/*
 * This driver is developed for the IDT 82P33XXX series of
 * timing and synchronization devices.
 *
 * Copyright (C) 2019 Integrated Device Technology, Inc., a Renesas Company.
 */
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/device.h>
#include <linux/mfd/idt82p33_reg.h>
#include <linux/mfd/rsmu.h>
#include <uapi/linux/rsmu.h>
#include <asm/unaligned.h>

#include "rsmu_cdev.h"

static int rsmu_sabre_set_combomode(struct rsmu_cdev *rsmu, u8 dpll, u8 mode)
{
	u16 dpll_ctrl_n;
	u8 cfg;
	int err;

	switch (dpll) {
	case 0:
		dpll_ctrl_n = DPLL1_OPERATING_MODE_CNFG;
		break;
	case 1:
		dpll_ctrl_n = DPLL2_OPERATING_MODE_CNFG;
		break;
	default:
		return -EINVAL;
	}

	if (mode >= E_COMBOMODE_MAX)
		return -EINVAL;

	err = rsmu_read(rsmu->mfd, dpll_ctrl_n, &cfg, sizeof(cfg));
	if (err)
		return err;

	cfg &= ~(COMBO_MODE_MASK << COMBO_MODE_SHIFT);
	cfg |= mode << COMBO_MODE_SHIFT;

	return rsmu_write(rsmu->mfd, dpll_ctrl_n, &cfg, sizeof(cfg));
}

static int rsmu_sabre_get_dpll_state(struct rsmu_cdev *rsmu, u8 dpll, u8 *state)
{
	u16 dpll_sts_n;
	u8 cfg;
	int err;

	switch (dpll) {
	case 0:
		dpll_sts_n = DPLL1_OPERATING_STS;
		break;
	case 1:
		dpll_sts_n = DPLL2_OPERATING_STS;
		break;
	default:
		return -EINVAL;
	}

	err = rsmu_read(rsmu->mfd, dpll_sts_n, &cfg, sizeof(cfg));
	if (err)
		return err;

	switch (cfg & OPERATING_STS_MASK) {
	case DPLL_STATE_FREERUN:
		*state = E_SRVLOUNQUALIFIEDSTATE;
		break;
	case DPLL_STATE_PRELOCKED2:
	case DPLL_STATE_PRELOCKED:
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

static int rsmu_sabre_get_dpll_ffo(struct rsmu_cdev *rsmu, u8 dpll,
				   struct rsmu_get_ffo *ffo)
{
	u8 buf[8] = {0};
	s64 fcw = 0;
	u16 dpll_freq_n;
	int err;

	switch (dpll) {
	case 0:
		dpll_freq_n = DPLL1_CURRENT_FREQ_STS;
		break;
	case 1:
		dpll_freq_n = DPLL2_CURRENT_FREQ_STS;
		break;
	default:
		return -EINVAL;
	}

	err = rsmu_read(rsmu->mfd, dpll_freq_n, buf, 5);
	if (err)
		return err;

	/* Convert to frequency control word */
	fcw = sign_extend64(get_unaligned_le64(buf), 39);

	/* FCW unit is 77760 / ( 1638400 * 2^48) = 1.68615121864946 * 10^-16 */
	ffo->ffo = div_s64(fcw * 168615, 1000);

	return 0;
}

struct rsmu_ops sabre_ops = {
	.type = RSMU_SABRE,
	.set_combomode = rsmu_sabre_set_combomode,
	.get_dpll_state = rsmu_sabre_get_dpll_state,
	.get_dpll_ffo = rsmu_sabre_get_dpll_ffo,
};
