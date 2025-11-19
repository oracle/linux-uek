// SPDX-License-Identifier: GPL-2.0
/* Copyright(c) 2017 - 2022 Pensando Systems, Inc */

#include <linux/module.h>
#include <linux/netdevice.h>

#include "ionic.h"
#include "ionic_bus.h"
#include "ionic_lif.h"
#include "ionic_devlink.h"
#include "ionic_aux.h"

#ifdef IONIC_DEVLINK
#ifdef HAVE_DEVLINK_UPDATE_PARAMS
static int ionic_dl_flash_update(struct devlink *dl,
				 struct devlink_flash_update_params *params,
				 struct netlink_ext_ack *extack)
{
	struct ionic *ionic = devlink_priv(dl);

#ifdef HAVE_DEVLINK_PREFETCH_FW
	return ionic_firmware_update(ionic->lif, params->fw);
#else
	return ionic_firmware_fetch_and_update(ionic->lif, params->file_name);
#endif
}
#else
static int ionic_dl_flash_update(struct devlink *dl,
				 const char *fwname,
				 const char *component,
				 struct netlink_ext_ack *extack)
{
	struct ionic *ionic = devlink_priv(dl);

	if (component)
		return -EOPNOTSUPP;

	return ionic_firmware_fetch_and_update(ionic->lif, fwname);
}
#endif /* HAVE_DEVLINK_UPDATE_PARAMS */

static int ionic_dl_info_get(struct devlink *dl, struct devlink_info_req *req,
			     struct netlink_ext_ack *extack)
{
	struct ionic *ionic = devlink_priv(dl);
	struct ionic_dev *idev = &ionic->idev;
	char buf[16];
	int err = 0;
	u32 val;

	if (!idev->dev_cmd_regs)
		return -ENXIO;

	err = devlink_info_driver_name_put(req, IONIC_DRV_NAME);
	if (err)
		return err;

	err = devlink_info_version_running_put(req,
					       DEVLINK_INFO_VERSION_GENERIC_FW,
					       idev->dev_info.fw_version);
	if (err)
		return err;

	val = ioread32(&idev->dev_info_regs->fw_heartbeat);
	snprintf(buf, sizeof(buf), "0x%x", val);
	err = devlink_info_version_running_put(req, "fw.heartbeat", buf);
	if (err)
		return err;

	val = ioread8(&idev->dev_info_regs->fw_status);
	snprintf(buf, sizeof(buf), "0x%x", val);
	err = devlink_info_version_running_put(req, "fw.status", buf);
	if (err)
		return err;

	snprintf(buf, sizeof(buf), "0x%x", idev->dev_info.asic_type);
	err = devlink_info_version_fixed_put(req,
					     DEVLINK_INFO_VERSION_GENERIC_ASIC_ID,
					     buf);
	if (err)
		return err;

	snprintf(buf, sizeof(buf), "0x%x", idev->dev_info.asic_rev);
	err = devlink_info_version_fixed_put(req,
					     DEVLINK_INFO_VERSION_GENERIC_ASIC_REV,
					     buf);
	if (err)
		return err;

	err = devlink_info_serial_number_put(req, idev->dev_info.serial_num);

	return err;
}

static const struct devlink_ops ionic_dl_ops = {
	.info_get	= ionic_dl_info_get,
	.flash_update	= ionic_dl_flash_update,
};

enum ionic_devlink_param_id {
	IONIC_DEVLINK_PARAM_ID_BASE = DEVLINK_PARAM_GENERIC_ID_MAX,
#ifndef IONIC_HAVE_DEVLINK_GENERIC_RDMA_ID
	IONIC_DEVLINK_PARAM_ID_ENABLE_RDMA,
#endif
};

static bool is_aux_enabled(struct ionic *ionic)
{
#ifdef CONFIG_AUXILIARY_BUS
	return ionic->lif->ionic_adev ? true : false;
#else
	return false;
#endif
}

static int ionic_devlink_enable_rdma_get(struct devlink *dl, u32 id,
					 struct devlink_param_gset_ctx *ctx,
					 struct netlink_ext_ack *extack)
{
	ctx->val.vbool = is_aux_enabled(devlink_priv(dl));
	return 0;
}

#ifdef IONIC_HAVE_DEVLINK_EXT_ACK_PARAM
static int ionic_devlink_enable_rdma_set(struct devlink *dl, u32 id,
					 struct devlink_param_gset_ctx *ctx,
					 struct netlink_ext_ack *extack)
#else
static int ionic_devlink_enable_rdma_set(struct devlink *dl, u32 id,
					 struct devlink_param_gset_ctx *ctx)
#endif
{
	struct ionic *ionic = devlink_priv(dl);
	int err = 0;

	if (ctx->val.vbool == is_aux_enabled(ionic))
		return err;

	if (ctx->val.vbool)
		err = ionic_auxbus_register(ionic->lif);
	else
		ionic_auxbus_unregister(ionic->lif);

	return err;
}

static int ionic_devlink_enable_rdma_validate(struct devlink *dl, u32 id,
					      union devlink_param_value val,
					      struct netlink_ext_ack *extack)
{
	struct ionic *ionic = devlink_priv(dl);
	bool new_state = val.vbool;

	if (new_state && !ionic->nrdma_eqs_per_lif)
		return -EOPNOTSUPP;
	return 0;
}

static const struct devlink_param ionic_dl_rdma_params[] = {
#ifdef IONIC_HAVE_DEVLINK_GENERIC_RDMA_ID
	DEVLINK_PARAM_GENERIC(ENABLE_RDMA, BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			      ionic_devlink_enable_rdma_get, ionic_devlink_enable_rdma_set,
			      ionic_devlink_enable_rdma_validate),
#else
	DEVLINK_PARAM_DRIVER(IONIC_DEVLINK_PARAM_ID_ENABLE_RDMA,
			     "enable_rdma", DEVLINK_PARAM_TYPE_BOOL,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     ionic_devlink_enable_rdma_get, ionic_devlink_enable_rdma_set,
			     ionic_devlink_enable_rdma_validate),
#endif
};

static int ionic_dl_rdma_params_register(struct devlink *dl)
{
	int err;

	if (!IS_ENABLED(CONFIG_AUXILIARY_BUS))
		return 0;

	err = devlink_params_register(dl, ionic_dl_rdma_params, ARRAY_SIZE(ionic_dl_rdma_params));
	if (err)
		return err;

#ifdef IONIC_HAVE_DEVLINK_PARAMS_PUBLISH
	devlink_params_publish(dl);
#endif
	return 0;
}

static void ionic_devlink_rdma_params_unregister(struct devlink *dl)
{
	if (!IS_ENABLED(CONFIG_AUXILIARY_BUS))
		return;

	devlink_params_unregister(dl, ionic_dl_rdma_params, ARRAY_SIZE(ionic_dl_rdma_params));
}

struct ionic *ionic_devlink_alloc(struct device *dev)
{
	struct devlink *dl;

	dl = devlink_alloc(&ionic_dl_ops, sizeof(struct ionic), dev);
	if (!dl)
		return NULL;

	return devlink_priv(dl);
}

void ionic_devlink_free(struct ionic *ionic)
{
	struct devlink *dl = priv_to_devlink(ionic);

	devlink_free(dl);
}

int ionic_devlink_register(struct ionic *ionic)
{
	struct devlink *dl = priv_to_devlink(ionic);
	int err;

#ifdef IONIC_HAVE_VOID_DEVLINK_REGISTER
	err = ionic_dl_rdma_params_register(dl);
	if (err) {
		dev_err(ionic->dev, "ionic_dl_rdma_params_register failed: %d\n", err);
		return err;
	}

	err = devlink_port_register(dl, &ionic->dl_port, 0);
	if (err) {
		dev_err(ionic->dev, "devlink_port_register failed: %d\n", err);
		ionic_devlink_rdma_params_unregister(dl);
		return err;
	}

	SET_NETDEV_DEVLINK_PORT(ionic->lif->netdev, &ionic->dl_port);
	devlink_register(dl);

	return 0;
#else
	err = devlink_register(dl, ionic->dev);
	if (err) {
		dev_warn(ionic->dev, "devlink_register failed: %d\n", err);
		return err;
	}

	err = devlink_port_register(dl, &ionic->dl_port, 0);
	if (err) {
		dev_err(ionic->dev, "devlink_port_register failed: %d\n", err);
		goto err_unreg_devlink;
	}

	devlink_port_type_eth_set(&ionic->dl_port, ionic->lif->netdev);

	err = ionic_dl_rdma_params_register(dl);
	if (err) {
		dev_err(ionic->dev, "ionic_dl_rdma_params_register failed: %d\n", err);
		goto err_unreg_all;
	}

	return 0;

err_unreg_all:
	devlink_port_type_clear(&ionic->dl_port);
	devlink_port_unregister(&ionic->dl_port);
err_unreg_devlink:
	devlink_unregister(dl);

	return err;
#endif
}

void ionic_devlink_unregister(struct ionic *ionic)
{
	struct devlink *dl = priv_to_devlink(ionic);

#ifdef IONIC_HAVE_VOID_DEVLINK_REGISTER
	devlink_unregister(dl);
	devlink_port_unregister(&ionic->dl_port);
	ionic_devlink_rdma_params_unregister(dl);
#else
	ionic_devlink_rdma_params_unregister(dl);
	devlink_port_unregister(&ionic->dl_port);
	devlink_unregister(dl);
#endif
}
#endif /* IONIC_DEVLINK */
