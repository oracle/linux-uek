// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2021 Marvell. */

#include "otx2_cpt_devlink.h"

static int otx2_cpt_dl_egrp_create(struct devlink *dl, u32 id,
				   struct devlink_param_gset_ctx *ctx)
{
	struct otx2_cpt_devlink *cpt_dl = devlink_priv(dl);
	struct otx2_cptpf_dev *cptpf = cpt_dl->cptpf;

	return otx2_cpt_dl_custom_egrp_create(cptpf, ctx);
}

static int otx2_cpt_dl_egrp_delete(struct devlink *dl, u32 id,
				   struct devlink_param_gset_ctx *ctx)
{
	struct otx2_cpt_devlink *cpt_dl = devlink_priv(dl);
	struct otx2_cptpf_dev *cptpf = cpt_dl->cptpf;

	return otx2_cpt_dl_custom_egrp_delete(cptpf, ctx);
}

static int otx2_cpt_dl_uc_info(struct devlink *dl, u32 id,
			       struct devlink_param_gset_ctx *ctx)
{
	struct otx2_cpt_devlink *cpt_dl = devlink_priv(dl);
	struct otx2_cptpf_dev *cptpf = cpt_dl->cptpf;

	otx2_cpt_print_uc_dbg_info(cptpf);

	return 0;
}

enum otx2_cpt_dl_param_id {
	OTX2_CPT_DEVLINK_PARAM_ID_BASE = DEVLINK_PARAM_GENERIC_ID_MAX,
	OTX2_CPT_DEVLINK_PARAM_ID_EGRP_CREATE,
	OTX2_CPT_DEVLINK_PARAM_ID_EGRP_DELETE,
};

static const struct devlink_param otx2_cpt_dl_params[] = {
	DEVLINK_PARAM_DRIVER(OTX2_CPT_DEVLINK_PARAM_ID_EGRP_CREATE,
			     "egrp_create", DEVLINK_PARAM_TYPE_STRING,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     otx2_cpt_dl_uc_info, otx2_cpt_dl_egrp_create,
			     NULL),
	DEVLINK_PARAM_DRIVER(OTX2_CPT_DEVLINK_PARAM_ID_EGRP_DELETE,
			     "egrp_delete", DEVLINK_PARAM_TYPE_STRING,
			     BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			     otx2_cpt_dl_uc_info, otx2_cpt_dl_egrp_delete,
			     NULL),
};

static int otx2_cpt_dl_info_firmware_version_put(struct devlink_info_req *req,
						 struct otx2_cpt_eng_grp_info grp[],
						 const char *ver_name, int eng_type)
{
	struct otx2_cpt_engs_rsvd *eng;
	int i;

	for (i = 0; i < OTX2_CPT_MAX_ENGINE_GROUPS; i++) {
		eng = find_engines_by_type(&grp[i], eng_type);
		if (eng)
			return devlink_info_version_running_put(req, ver_name,
								eng->ucode->ver_str);
	}

	return 0;
}

static int otx2_cpt_devlink_info_get(struct devlink *dl,
				     struct devlink_info_req *req,
				     struct netlink_ext_ack *extack)
{
	struct otx2_cpt_devlink *cpt_dl = devlink_priv(dl);
	struct otx2_cptpf_dev *cptpf = cpt_dl->cptpf;
	int err;

	err = devlink_info_driver_name_put(req, "rvu_cptpf");
	if (err)
		return err;

	err = otx2_cpt_dl_info_firmware_version_put(req, cptpf->eng_grps.grp,
						    "fw.ae", OTX2_CPT_AE_TYPES);
	if (err)
		return err;

	err = otx2_cpt_dl_info_firmware_version_put(req, cptpf->eng_grps.grp,
						    "fw.se", OTX2_CPT_SE_TYPES);
	if (err)
		return err;

	return otx2_cpt_dl_info_firmware_version_put(req, cptpf->eng_grps.grp,
						    "fw.ie", OTX2_CPT_IE_TYPES);
}

static const struct devlink_ops otx2_cpt_devlink_ops = {
	.info_get = otx2_cpt_devlink_info_get,
};

int otx2_cpt_register_dl(struct otx2_cptpf_dev *cptpf)
{
	struct device *dev = &cptpf->pdev->dev;
	struct otx2_cpt_devlink *cpt_dl;
	struct devlink *dl;
	int err;

	dl = devlink_alloc(&otx2_cpt_devlink_ops,
			   sizeof(struct otx2_cpt_devlink));
	if (!dl) {
		dev_warn(dev, "devlink_alloc failed\n");
		return -ENOMEM;
	}

	err = devlink_register(dl, dev);
	if (err) {
		dev_err(dev, "devlink register failed with error %d\n", err);
		goto dl_free;
	}
	cpt_dl = devlink_priv(dl);
	cpt_dl->dl = dl;
	cpt_dl->cptpf = cptpf;
	cptpf->dl = dl;

	err = devlink_params_register(dl, otx2_cpt_dl_params,
				      ARRAY_SIZE(otx2_cpt_dl_params));
	if (err) {
		dev_err(dev,
			"devlink params register failed with error %d", err);
		goto dl_unreg;
	}
	devlink_params_publish(dl);

	return 0;

dl_unreg:
	devlink_unregister(dl);
dl_free:
	devlink_free(dl);
	return err;
}

void otx2_cpt_unregister_dl(struct otx2_cptpf_dev *cptpf)
{
	struct devlink *dl = cptpf->dl;

	if (!dl)
		return;

	devlink_params_unregister(dl, otx2_cpt_dl_params,
				  ARRAY_SIZE(otx2_cpt_dl_params));
	devlink_unregister(dl);
	devlink_free(dl);
}
