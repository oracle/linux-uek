// SPDX-License-Identifier: GPL-2.0
/* Marvell MCS Device Devlink
 *
 * Copyright (C) 2025 Marvell.
 *
 */

#include <linux/bitfield.h>

#include "mcs.h"
#include "mcs_reg.h"

#define DRV_NAME	"Marvell MCS Driver"

static int mcs_dl_mcs_bypass_set(struct devlink *devlink, u32 id,
				 struct devlink_param_gset_ctx *ctx,
				 struct netlink_ext_ack *extack)
{
	struct mcs_devlink *mcs_dl = devlink_priv(devlink);
	struct mcs *mcs = mcs_dl->mcs;
	bool state = ctx->val.vbool;
	int devtype;
	u64 val;

	devtype = mcs->hw->mcs_devtype;
	if (devtype == CN20KA_MCS || devtype == CNF20KA_MCS) {
		mcs_reg_write(mcs, MCSX_EXTERNAL_BYPASS, state);
		mcs->bypass = state;
		return 0;
	}

	val = mcs_reg_read(mcs, MCSX_MIL_GLOBAL);
	if (state)
		val |= BIT_ULL(6);
	else
		val &= ~BIT_ULL(6);
	mcs_reg_write(mcs, MCSX_MIL_GLOBAL, val);
	mcs->bypass = state;
	return 0;
}

static int mcs_dl_mcs_bypass_get(struct devlink *devlink, u32 id,
				 struct devlink_param_gset_ctx *ctx)
{
	struct mcs_devlink *mcs_dl = devlink_priv(devlink);
	struct mcs *mcs = mcs_dl->mcs;

	ctx->val.vbool = mcs->bypass;

	return 0;
}

enum mcs_dl_param_id {
	MCS_DEVLINK_PARAM_ID_BASE = DEVLINK_PARAM_GENERIC_ID_MAX,
	MCS_DEVLINK_PARAM_ID_MCS_BYPASS,
};

static const struct devlink_param mcs_dl_params[] = {
	DEVLINK_PARAM_DRIVER(MCS_DEVLINK_PARAM_ID_MCS_BYPASS,
			     "mcs_bypass", DEVLINK_PARAM_TYPE_BOOL,
			      BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			      mcs_dl_mcs_bypass_get,
			      mcs_dl_mcs_bypass_set,
			      NULL),
};

static const struct devlink_ops mcs_devlink_ops = {
};

int mcs_register_dl(struct mcs *mcs)
{
	struct mcs_devlink *mcs_dl;
	struct devlink *dl;
	int err;

	dl = devlink_alloc(&mcs_devlink_ops,
			   sizeof(struct mcs_devlink), mcs->dev);
	if (!dl) {
		dev_warn(mcs->dev, "devlink_alloc failed\n");
		return -ENOMEM;
	}

	mcs_dl = devlink_priv(dl);
	mcs_dl->dl = dl;
	mcs_dl->mcs = mcs;
	mcs->dl = mcs_dl;

	err = devlink_params_register(dl, mcs_dl_params,
				      ARRAY_SIZE(mcs_dl_params));
	if (err) {
		dev_err(mcs->dev,
			"devlink params register failed with error %d", err);
		goto err_dl;
	}

	devlink_register(dl);
	return 0;

err_dl:
	devlink_free(dl);
	return err;
}
EXPORT_SYMBOL(mcs_register_dl);

void mcs_unregister_dl(struct mcs *mcs)
{
	struct mcs_devlink *mcs_dl = mcs->dl;
	struct devlink *dl = mcs_dl->dl;

	devlink_unregister(dl);
	devlink_params_unregister(dl, mcs_dl_params,
				  ARRAY_SIZE(mcs_dl_params));
	devlink_free(dl);
}
EXPORT_SYMBOL(mcs_unregister_dl);
