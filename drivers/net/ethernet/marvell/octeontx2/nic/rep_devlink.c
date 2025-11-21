// SPDX-License-Identifier: GPL-2.0
/* Marvell RVU Representor Devlink
 *
 * Copyright (C) 2025 Marvell.
 */

#include "otx2_common.h"

static int rvu_rep_devlink_eswitch_mode_get(struct devlink *devlink, u16 *mode)
{
	struct otx2_devlink *otx2_dl = devlink_priv(devlink);
	struct otx2_nic *pfvf = otx2_dl->pfvf;

	if (!otx2_rep_dev(pfvf->pdev))
		return -EOPNOTSUPP;

	*mode = pfvf->esw_mode;

	return 0;
}

static int rvu_rep_devlink_eswitch_mode_set(struct devlink *devlink, u16 mode,
					     struct netlink_ext_ack *extack)
{
	struct otx2_devlink *otx2_dl = devlink_priv(devlink);
	struct otx2_nic *pfvf = otx2_dl->pfvf;
	int ret = 0;

	if (!otx2_rep_dev(pfvf->pdev))
		return -EOPNOTSUPP;

	if (pfvf->esw_mode == mode)
		return 0;

	switch (mode) {
	case DEVLINK_ESWITCH_MODE_LEGACY:
		devl_unlock(devlink);
		rvu_rep_destroy(pfvf);
		devl_lock(devlink);
		break;
	case DEVLINK_ESWITCH_MODE_SWITCHDEV:
		ret = rvu_rep_create(pfvf, extack);
		break;
	default:
		return -EINVAL;
	}

	if (!ret)
		pfvf->esw_mode = mode;

	return ret;
}

static const struct devlink_ops rep_devlink_ops = {
	.eswitch_mode_get = rvu_rep_devlink_eswitch_mode_get,
	.eswitch_mode_set = rvu_rep_devlink_eswitch_mode_set,
};

int rvu_rep_register_dl(struct otx2_nic *pfvf)
{
	struct otx2_devlink *otx2_dl;
	struct devlink *dl;

	dl = devlink_alloc(&rep_devlink_ops,
			   sizeof(struct otx2_devlink), pfvf->dev);
	if (!dl) {
		dev_warn(pfvf->dev, "devlink_alloc failed\n");
		return -ENOMEM;
	}

	otx2_dl = devlink_priv(dl);
	otx2_dl->dl = dl;
	otx2_dl->pfvf = pfvf;
	pfvf->dl = otx2_dl;

	devlink_register(dl);
	return 0;
}
EXPORT_SYMBOL(rvu_rep_register_dl);

void rvu_rep_unregister_dl(struct otx2_nic *pfvf)
{
	struct otx2_devlink *otx2_dl = pfvf->dl;
	struct devlink *dl = otx2_dl->dl;

	devlink_unregister(dl);
	devlink_free(dl);
}
EXPORT_SYMBOL(rvu_rep_unregister_dl);
