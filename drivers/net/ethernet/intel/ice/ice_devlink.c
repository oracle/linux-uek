// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2020, Intel Corporation. */

#include "ice.h"
#include "ice_lib.h"
#include "ice_devlink.h"
#include "ice_eswitch.h"
#include "ice_fw_update.h"

static int ice_active_port_option = -1;

/* context for devlink info version reporting */
struct ice_info_ctx {
	char buf[128];
	struct ice_orom_info pending_orom;
	struct ice_nvm_info pending_nvm;
	struct ice_netlist_info pending_netlist;
	struct ice_hw_dev_caps dev_caps;
};

/* The following functions are used to format specific strings for various
 * devlink info versions. The ctx parameter is used to provide the storage
 * buffer, as well as any ancillary information calculated when the info
 * request was made.
 *
 * If a version does not exist, for example when attempting to get the
 * inactive version of flash when there is no pending update, the function
 * should leave the buffer in the ctx structure empty.
 */

static void ice_info_get_dsn(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	u8 dsn[8];

	/* Copy the DSN into an array in Big Endian format */
	put_unaligned_be64(pci_get_dsn(pf->pdev), dsn);

	snprintf(ctx->buf, sizeof(ctx->buf), "%8phD", dsn);
}

static void ice_info_pba(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_hw *hw = &pf->hw;
	int status;

	status = ice_read_pba_string(hw, (u8 *)ctx->buf, sizeof(ctx->buf));
	if (status)
		/* We failed to locate the PBA, so just skip this entry */
		dev_dbg(ice_pf_to_dev(pf), "Failed to read Product Board Assembly string, status %d\n",
			status);
}

static void ice_info_fw_mgmt(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_hw *hw = &pf->hw;

	snprintf(ctx->buf, sizeof(ctx->buf), "%u.%u.%u",
		 hw->fw_maj_ver, hw->fw_min_ver, hw->fw_patch);
}

static void ice_info_fw_api(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_hw *hw = &pf->hw;

	snprintf(ctx->buf, sizeof(ctx->buf), "%u.%u.%u", hw->api_maj_ver,
		 hw->api_min_ver, hw->api_patch);
}

static void ice_info_fw_build(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_hw *hw = &pf->hw;

	snprintf(ctx->buf, sizeof(ctx->buf), "0x%08x", hw->fw_build);
}

static void ice_info_orom_ver(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_orom_info *orom = &pf->hw.flash.orom;

	snprintf(ctx->buf, sizeof(ctx->buf), "%u.%u.%u",
		 orom->major, orom->build, orom->patch);
}

static void
ice_info_pending_orom_ver(struct ice_pf __always_unused *pf,
			  struct ice_info_ctx *ctx)
{
	struct ice_orom_info *orom = &ctx->pending_orom;

	if (ctx->dev_caps.common_cap.nvm_update_pending_orom)
		snprintf(ctx->buf, sizeof(ctx->buf), "%u.%u.%u",
			 orom->major, orom->build, orom->patch);
}

static void ice_info_nvm_ver(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_nvm_info *nvm = &pf->hw.flash.nvm;

	snprintf(ctx->buf, sizeof(ctx->buf), "%x.%02x", nvm->major, nvm->minor);
}

static void
ice_info_pending_nvm_ver(struct ice_pf __always_unused *pf,
			 struct ice_info_ctx *ctx)
{
	struct ice_nvm_info *nvm = &ctx->pending_nvm;

	if (ctx->dev_caps.common_cap.nvm_update_pending_nvm)
		snprintf(ctx->buf, sizeof(ctx->buf), "%x.%02x",
			 nvm->major, nvm->minor);
}

static void ice_info_eetrack(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_nvm_info *nvm = &pf->hw.flash.nvm;

	snprintf(ctx->buf, sizeof(ctx->buf), "0x%08x", nvm->eetrack);
}

static void
ice_info_pending_eetrack(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_nvm_info *nvm = &ctx->pending_nvm;

	if (ctx->dev_caps.common_cap.nvm_update_pending_nvm)
		snprintf(ctx->buf, sizeof(ctx->buf), "0x%08x", nvm->eetrack);
}

static void ice_info_ddp_pkg_name(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_hw *hw = &pf->hw;

	snprintf(ctx->buf, sizeof(ctx->buf), "%s", hw->active_pkg_name);
}

static void
ice_info_ddp_pkg_version(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_pkg_ver *pkg = &pf->hw.active_pkg_ver;

	snprintf(ctx->buf, sizeof(ctx->buf), "%u.%u.%u.%u",
		 pkg->major, pkg->minor, pkg->update, pkg->draft);
}

static void
ice_info_ddp_pkg_bundle_id(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	snprintf(ctx->buf, sizeof(ctx->buf), "0x%08x", pf->hw.active_track_id);
}

static void ice_info_netlist_ver(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_netlist_info *netlist = &pf->hw.flash.netlist;

	/* The netlist version fields are BCD formatted */
	snprintf(ctx->buf, sizeof(ctx->buf), "%x.%x.%x-%x.%x.%x",
		 netlist->major, netlist->minor,
		 netlist->type >> 16, netlist->type & 0xFFFF,
		 netlist->rev, netlist->cust_ver);
}

static void ice_info_netlist_build(struct ice_pf *pf, struct ice_info_ctx *ctx)
{
	struct ice_netlist_info *netlist = &pf->hw.flash.netlist;

	snprintf(ctx->buf, sizeof(ctx->buf), "0x%08x", netlist->hash);
}

static void
ice_info_pending_netlist_ver(struct ice_pf __always_unused *pf,
			     struct ice_info_ctx *ctx)
{
	struct ice_netlist_info *netlist = &ctx->pending_netlist;

	/* The netlist version fields are BCD formatted */
	if (ctx->dev_caps.common_cap.nvm_update_pending_netlist)
		snprintf(ctx->buf, sizeof(ctx->buf), "%x.%x.%x-%x.%x.%x",
			 netlist->major, netlist->minor,
			 netlist->type >> 16, netlist->type & 0xFFFF,
			 netlist->rev, netlist->cust_ver);
}

static void
ice_info_pending_netlist_build(struct ice_pf __always_unused *pf,
			       struct ice_info_ctx *ctx)
{
	struct ice_netlist_info *netlist = &ctx->pending_netlist;

	if (ctx->dev_caps.common_cap.nvm_update_pending_netlist)
		snprintf(ctx->buf, sizeof(ctx->buf), "0x%08x", netlist->hash);
}

#define fixed(key, getter) { ICE_VERSION_FIXED, key, getter, NULL }
#define running(key, getter) { ICE_VERSION_RUNNING, key, getter, NULL }
#define stored(key, getter, fallback) { ICE_VERSION_STORED, key, getter, fallback }

/* The combined() macro inserts both the running entry as well as a stored
 * entry. The running entry will always report the version from the active
 * handler. The stored entry will first try the pending handler, and fallback
 * to the active handler if the pending function does not report a version.
 * The pending handler should check the status of a pending update for the
 * relevant flash component. It should only fill in the buffer in the case
 * where a valid pending version is available. This ensures that the related
 * stored and running versions remain in sync, and that stored versions are
 * correctly reported as expected.
 */
#define combined(key, active, pending) \
	running(key, active), \
	stored(key, pending, active)

enum ice_version_type {
	ICE_VERSION_FIXED,
	ICE_VERSION_RUNNING,
	ICE_VERSION_STORED,
};

static const struct ice_devlink_version {
	enum ice_version_type type;
	const char *key;
	void (*getter)(struct ice_pf *pf, struct ice_info_ctx *ctx);
	void (*fallback)(struct ice_pf *pf, struct ice_info_ctx *ctx);
} ice_devlink_versions[] = {
	fixed(DEVLINK_INFO_VERSION_GENERIC_BOARD_ID, ice_info_pba),
	running(DEVLINK_INFO_VERSION_GENERIC_FW_MGMT, ice_info_fw_mgmt),
	running("fw.mgmt.api", ice_info_fw_api),
	running("fw.mgmt.build", ice_info_fw_build),
	combined(DEVLINK_INFO_VERSION_GENERIC_FW_UNDI, ice_info_orom_ver, ice_info_pending_orom_ver),
	combined("fw.psid.api", ice_info_nvm_ver, ice_info_pending_nvm_ver),
	combined(DEVLINK_INFO_VERSION_GENERIC_FW_BUNDLE_ID, ice_info_eetrack, ice_info_pending_eetrack),
	running("fw.app.name", ice_info_ddp_pkg_name),
	running(DEVLINK_INFO_VERSION_GENERIC_FW_APP, ice_info_ddp_pkg_version),
	running("fw.app.bundle_id", ice_info_ddp_pkg_bundle_id),
	combined("fw.netlist", ice_info_netlist_ver, ice_info_pending_netlist_ver),
	combined("fw.netlist.build", ice_info_netlist_build, ice_info_pending_netlist_build),
};

/**
 * ice_devlink_info_get - .info_get devlink handler
 * @devlink: devlink instance structure
 * @req: the devlink info request
 * @extack: extended netdev ack structure
 *
 * Callback for the devlink .info_get operation. Reports information about the
 * device.
 *
 * Return: zero on success or an error code on failure.
 */
static int ice_devlink_info_get(struct devlink *devlink,
				struct devlink_info_req *req,
				struct netlink_ext_ack *extack)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	struct ice_info_ctx *ctx;
	size_t i;
	int err;

	err = ice_wait_for_reset(pf, 10 * HZ);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Device is busy resetting");
		return err;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	/* discover capabilities first */
	err = ice_discover_dev_caps(hw, &ctx->dev_caps);
	if (err) {
		dev_dbg(dev, "Failed to discover device capabilities, status %d aq_err %s\n",
			err, ice_aq_str(hw->adminq.sq_last_status));
		NL_SET_ERR_MSG_MOD(extack, "Unable to discover device capabilities");
		goto out_free_ctx;
	}

	if (ctx->dev_caps.common_cap.nvm_update_pending_orom) {
		err = ice_get_inactive_orom_ver(hw, &ctx->pending_orom);
		if (err) {
			dev_dbg(dev, "Unable to read inactive Option ROM version data, status %d aq_err %s\n",
				err, ice_aq_str(hw->adminq.sq_last_status));

			/* disable display of pending Option ROM */
			ctx->dev_caps.common_cap.nvm_update_pending_orom = false;
		}
	}

	if (ctx->dev_caps.common_cap.nvm_update_pending_nvm) {
		err = ice_get_inactive_nvm_ver(hw, &ctx->pending_nvm);
		if (err) {
			dev_dbg(dev, "Unable to read inactive NVM version data, status %d aq_err %s\n",
				err, ice_aq_str(hw->adminq.sq_last_status));

			/* disable display of pending Option ROM */
			ctx->dev_caps.common_cap.nvm_update_pending_nvm = false;
		}
	}

	if (ctx->dev_caps.common_cap.nvm_update_pending_netlist) {
		err = ice_get_inactive_netlist_ver(hw, &ctx->pending_netlist);
		if (err) {
			dev_dbg(dev, "Unable to read inactive Netlist version data, status %d aq_err %s\n",
				err, ice_aq_str(hw->adminq.sq_last_status));

			/* disable display of pending Option ROM */
			ctx->dev_caps.common_cap.nvm_update_pending_netlist = false;
		}
	}

	ice_info_get_dsn(pf, ctx);

	err = devlink_info_serial_number_put(req, ctx->buf);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Unable to set serial number");
		goto out_free_ctx;
	}

	for (i = 0; i < ARRAY_SIZE(ice_devlink_versions); i++) {
		enum ice_version_type type = ice_devlink_versions[i].type;
		const char *key = ice_devlink_versions[i].key;

		memset(ctx->buf, 0, sizeof(ctx->buf));

		ice_devlink_versions[i].getter(pf, ctx);

		/* If the default getter doesn't report a version, use the
		 * fallback function. This is primarily useful in the case of
		 * "stored" versions that want to report the same value as the
		 * running version in the normal case of no pending update.
		 */
		if (ctx->buf[0] == '\0' && ice_devlink_versions[i].fallback)
			ice_devlink_versions[i].fallback(pf, ctx);

		/* Do not report missing versions */
		if (ctx->buf[0] == '\0')
			continue;

		switch (type) {
		case ICE_VERSION_FIXED:
			err = devlink_info_version_fixed_put(req, key, ctx->buf);
			if (err) {
				NL_SET_ERR_MSG_MOD(extack, "Unable to set fixed version");
				goto out_free_ctx;
			}
			break;
		case ICE_VERSION_RUNNING:
			err = devlink_info_version_running_put(req, key, ctx->buf);
			if (err) {
				NL_SET_ERR_MSG_MOD(extack, "Unable to set running version");
				goto out_free_ctx;
			}
			break;
		case ICE_VERSION_STORED:
			err = devlink_info_version_stored_put(req, key, ctx->buf);
			if (err) {
				NL_SET_ERR_MSG_MOD(extack, "Unable to set stored version");
				goto out_free_ctx;
			}
			break;
		}
	}

out_free_ctx:
	kfree(ctx);
	return err;
}

/**
 * ice_devlink_reload_empr_start - Start EMP reset to activate new firmware
 * @devlink: pointer to the devlink instance to reload
 * @netns_change: if true, the network namespace is changing
 * @action: the action to perform. Must be DEVLINK_RELOAD_ACTION_FW_ACTIVATE
 * @limit: limits on what reload should do, such as not resetting
 * @extack: netlink extended ACK structure
 *
 * Allow user to activate new Embedded Management Processor firmware by
 * issuing device specific EMP reset. Called in response to
 * a DEVLINK_CMD_RELOAD with the DEVLINK_RELOAD_ACTION_FW_ACTIVATE.
 *
 * Note that teardown and rebuild of the driver state happens automatically as
 * part of an interrupt and watchdog task. This is because all physical
 * functions on the device must be able to reset when an EMP reset occurs from
 * any source.
 */
static int
ice_devlink_reload_empr_start(struct devlink *devlink, bool netns_change,
			      enum devlink_reload_action action,
			      enum devlink_reload_limit limit,
			      struct netlink_ext_ack *extack)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	u8 pending;
	int err;

	err = ice_get_pending_updates(pf, &pending, extack);
	if (err)
		return err;

	/* pending is a bitmask of which flash banks have a pending update,
	 * including the main NVM bank, the Option ROM bank, and the netlist
	 * bank. If any of these bits are set, then there is a pending update
	 * waiting to be activated.
	 */
	if (!pending) {
		NL_SET_ERR_MSG_MOD(extack, "No pending firmware update");
		return -ECANCELED;
	}

	if (pf->fw_emp_reset_disabled) {
		NL_SET_ERR_MSG_MOD(extack, "EMP reset is not available. To activate firmware, a reboot or power cycle is needed");
		return -ECANCELED;
	}

	dev_dbg(dev, "Issuing device EMP reset to activate firmware\n");

	err = ice_aq_nvm_update_empr(hw);
	if (err) {
		dev_err(dev, "Failed to trigger EMP device reset to reload firmware, err %d aq_err %s\n",
			err, ice_aq_str(hw->adminq.sq_last_status));
		NL_SET_ERR_MSG_MOD(extack, "Failed to trigger EMP device reset to reload firmware");
		return err;
	}

	return 0;
}

/**
 * ice_devlink_reload_empr_finish - Wait for EMP reset to finish
 * @devlink: pointer to the devlink instance reloading
 * @action: the action requested
 * @limit: limits imposed by userspace, such as not resetting
 * @actions_performed: on return, indicate what actions actually performed
 * @extack: netlink extended ACK structure
 *
 * Wait for driver to finish rebuilding after EMP reset is completed. This
 * includes time to wait for both the actual device reset as well as the time
 * for the driver's rebuild to complete.
 */
static int
ice_devlink_reload_empr_finish(struct devlink *devlink,
			       enum devlink_reload_action action,
			       enum devlink_reload_limit limit,
			       u32 *actions_performed,
			       struct netlink_ext_ack *extack)
{
	struct ice_pf *pf = devlink_priv(devlink);
	int err;

	*actions_performed = BIT(DEVLINK_RELOAD_ACTION_FW_ACTIVATE);

	err = ice_wait_for_reset(pf, 60 * HZ);
	if (err) {
		NL_SET_ERR_MSG_MOD(extack, "Device still resetting after 1 minute");
		return err;
	}

	return 0;
}

/**
 * ice_devlink_port_opt_speed_str - convert speed to a string
 * @speed: speed value
 */
static const char *ice_devlink_port_opt_speed_str(u8 speed)
{
	switch (speed & ICE_AQC_PORT_OPT_MAX_LANE_M) {
	case ICE_AQC_PORT_OPT_MAX_LANE_100M:
		return "0.1";
	case ICE_AQC_PORT_OPT_MAX_LANE_1G:
		return "1";
	case ICE_AQC_PORT_OPT_MAX_LANE_2500M:
		return "2.5";
	case ICE_AQC_PORT_OPT_MAX_LANE_5G:
		return "5";
	case ICE_AQC_PORT_OPT_MAX_LANE_10G:
		return "10";
	case ICE_AQC_PORT_OPT_MAX_LANE_25G:
		return "25";
	case ICE_AQC_PORT_OPT_MAX_LANE_50G:
		return "50";
	case ICE_AQC_PORT_OPT_MAX_LANE_100G:
		return "100";
	}

	return "-";
}

#define ICE_PORT_OPT_DESC_LEN	50
/**
 * ice_devlink_port_options_print - Print available port split options
 * @pf: the PF to print split port options
 *
 * Prints a table with available port split options and max port speeds
 */
static void ice_devlink_port_options_print(struct ice_pf *pf)
{
	u8 i, j, options_count, cnt, speed, pending_idx, active_idx;
	struct ice_aqc_get_port_options_elem *options, *opt;
	struct device *dev = ice_pf_to_dev(pf);
	bool active_valid, pending_valid;
	char desc[ICE_PORT_OPT_DESC_LEN];
	const char *str;
	int status;

	options = kcalloc(ICE_AQC_PORT_OPT_MAX * ICE_MAX_PORT_PER_PCI_DEV,
			  sizeof(*options), GFP_KERNEL);
	if (!options)
		return;

	for (i = 0; i < ICE_MAX_PORT_PER_PCI_DEV; i++) {
		opt = options + i * ICE_AQC_PORT_OPT_MAX;
		options_count = ICE_AQC_PORT_OPT_MAX;
		active_valid = 0;

		status = ice_aq_get_port_options(&pf->hw, opt, &options_count,
						 i, true, &active_idx,
						 &active_valid, &pending_idx,
						 &pending_valid);
		if (status) {
			dev_dbg(dev, "Couldn't read port option for port %d, err %d\n",
				i, status);
			goto err;
		}
	}

	dev_dbg(dev, "Available port split options and max port speeds (Gbps):\n");
	dev_dbg(dev, "Status  Split      Quad 0          Quad 1\n");
	dev_dbg(dev, "        count  L0  L1  L2  L3  L4  L5  L6  L7\n");

	for (i = 0; i < options_count; i++) {
		cnt = 0;

		if (i == ice_active_port_option)
			str = "Active";
		else if ((i == pending_idx) && pending_valid)
			str = "Pending";
		else
			str = "";

		cnt += snprintf(&desc[cnt], ICE_PORT_OPT_DESC_LEN - cnt,
				"%-8s", str);

		cnt += snprintf(&desc[cnt], ICE_PORT_OPT_DESC_LEN - cnt,
				"%-6u", options[i].pmd);

		for (j = 0; j < ICE_MAX_PORT_PER_PCI_DEV; ++j) {
			speed = options[i + j * ICE_AQC_PORT_OPT_MAX].max_lane_speed;
			str = ice_devlink_port_opt_speed_str(speed);
			cnt += snprintf(&desc[cnt], ICE_PORT_OPT_DESC_LEN - cnt,
					"%3s ", str);
		}

		dev_dbg(dev, "%s\n", desc);
	}

err:
	kfree(options);
}

/**
 * ice_devlink_aq_set_port_option - Send set port option admin queue command
 * @pf: the PF to print split port options
 * @option_idx: selected port option
 * @extack: extended netdev ack structure
 *
 * Sends set port option admin queue command with selected port option and
 * calls NVM write activate.
 */
static int
ice_devlink_aq_set_port_option(struct ice_pf *pf, u8 option_idx,
			       struct netlink_ext_ack *extack)
{
	struct device *dev = ice_pf_to_dev(pf);
	int status;

	status = ice_aq_set_port_option(&pf->hw, 0, true, option_idx);
	if (status) {
		dev_dbg(dev, "ice_aq_set_port_option, err %d aq_err %d\n",
			status, pf->hw.adminq.sq_last_status);
		NL_SET_ERR_MSG_MOD(extack, "Port split request failed");
		return -EIO;
	}

	status = ice_acquire_nvm(&pf->hw, ICE_RES_WRITE);
	if (status) {
		dev_dbg(dev, "ice_acquire_nvm failed, err %d aq_err %d\n",
			status, pf->hw.adminq.sq_last_status);
		NL_SET_ERR_MSG_MOD(extack, "Failed to acquire NVM semaphore");
		return -EIO;
	}

	status = ice_nvm_write_activate(&pf->hw, ICE_AQC_NVM_ACTIV_REQ_EMPR, NULL);
	if (status) {
		dev_dbg(dev, "ice_nvm_write_activate failed, err %d aq_err %d\n",
			status, pf->hw.adminq.sq_last_status);
		NL_SET_ERR_MSG_MOD(extack, "Port split request failed to save data");
		ice_release_nvm(&pf->hw);
		return -EIO;
	}

	ice_release_nvm(&pf->hw);

	NL_SET_ERR_MSG_MOD(extack, "Reboot required to finish port split");
	return 0;
}

/**
 * ice_devlink_port_split - .port_split devlink handler
 * @devlink: devlink instance structure
 * @port: devlink port structure
 * @count: number of ports to split to
 * @extack: extended netdev ack structure
 *
 * Callback for the devlink .port_split operation.
 *
 * Unfortunately, the devlink expression of available options is limited
 * to just a number, so search for an FW port option which supports
 * the specified number. As there could be multiple FW port options with
 * the same port split count, allow switching between them. When the same
 * port split count request is issued again, switch to the next FW port
 * option with the same port split count.
 *
 * Return: zero on success or an error code on failure.
 */
static int
ice_devlink_port_split(struct devlink *devlink, struct devlink_port *port,
		       unsigned int count, struct netlink_ext_ack *extack)
{
	struct ice_aqc_get_port_options_elem options[ICE_AQC_PORT_OPT_MAX];
	u8 i, j, active_idx, pending_idx, new_option;
	struct ice_pf *pf = devlink_priv(devlink);
	u8 option_count = ICE_AQC_PORT_OPT_MAX;
	struct device *dev = ice_pf_to_dev(pf);
	bool active_valid, pending_valid;
	int status;

	status = ice_aq_get_port_options(&pf->hw, options, &option_count,
					 0, true, &active_idx, &active_valid,
					 &pending_idx, &pending_valid);
	if (status) {
		dev_dbg(dev, "Couldn't read port split options, err = %d\n",
			status);
		NL_SET_ERR_MSG_MOD(extack, "Failed to get available port split options");
		return -EIO;
	}

	new_option = ICE_AQC_PORT_OPT_MAX;
	active_idx = pending_valid ? pending_idx : active_idx;
	for (i = 1; i <= option_count; i++) {
		/* In order to allow switching between FW port options with
		 * the same port split count, search for a new option starting
		 * from the active/pending option (with array wrap around).
		 */
		j = (active_idx + i) % option_count;

		if (count == options[j].pmd) {
			new_option = j;
			break;
		}
	}

	if (new_option == active_idx) {
		dev_dbg(dev, "request to split: count: %u is already set and there are no other options\n",
			count);
		NL_SET_ERR_MSG_MOD(extack, "Requested split count is already set");
		ice_devlink_port_options_print(pf);
		return -EINVAL;
	}

	if (new_option == ICE_AQC_PORT_OPT_MAX) {
		dev_dbg(dev, "request to split: count: %u not found\n", count);
		NL_SET_ERR_MSG_MOD(extack, "Port split requested unsupported port config");
		ice_devlink_port_options_print(pf);
		return -EINVAL;
	}

	status = ice_devlink_aq_set_port_option(pf, new_option, extack);
	if (status)
		return status;

	ice_devlink_port_options_print(pf);

	return 0;
}

/**
 * ice_devlink_port_unsplit - .port_unsplit devlink handler
 * @devlink: devlink instance structure
 * @port: devlink port structure
 * @extack: extended netdev ack structure
 *
 * Callback for the devlink .port_unsplit operation.
 * Calls ice_devlink_port_split with split count set to 1.
 * There could be no FW option available with split count 1.
 *
 * Return: zero on success or an error code on failure.
 */
static int
ice_devlink_port_unsplit(struct devlink *devlink, struct devlink_port *port,
			 struct netlink_ext_ack *extack)
{
	return ice_devlink_port_split(devlink, port, 1, extack);
}

static const struct devlink_ops ice_devlink_ops = {
	.supported_flash_update_params = DEVLINK_SUPPORT_FLASH_UPDATE_OVERWRITE_MASK,
	.reload_actions = BIT(DEVLINK_RELOAD_ACTION_FW_ACTIVATE),
	/* The ice driver currently does not support driver reinit */
	.reload_down = ice_devlink_reload_empr_start,
	.reload_up = ice_devlink_reload_empr_finish,
	.eswitch_mode_get = ice_eswitch_mode_get,
	.eswitch_mode_set = ice_eswitch_mode_set,
	.info_get = ice_devlink_info_get,
	.flash_update = ice_devlink_flash_update,
};

static int
ice_devlink_enable_roce_get(struct devlink *devlink, u32 id,
			    struct devlink_param_gset_ctx *ctx)
{
	struct ice_pf *pf = devlink_priv(devlink);

	ctx->val.vbool = pf->rdma_mode & IIDC_RDMA_PROTOCOL_ROCEV2 ? true : false;

	return 0;
}

static int
ice_devlink_enable_roce_set(struct devlink *devlink, u32 id,
			    struct devlink_param_gset_ctx *ctx)
{
	struct ice_pf *pf = devlink_priv(devlink);
	bool roce_ena = ctx->val.vbool;
	int ret;

	if (!roce_ena) {
		ice_unplug_aux_dev(pf);
		pf->rdma_mode &= ~IIDC_RDMA_PROTOCOL_ROCEV2;
		return 0;
	}

	pf->rdma_mode |= IIDC_RDMA_PROTOCOL_ROCEV2;
	ret = ice_plug_aux_dev(pf);
	if (ret)
		pf->rdma_mode &= ~IIDC_RDMA_PROTOCOL_ROCEV2;

	return ret;
}

static int
ice_devlink_enable_roce_validate(struct devlink *devlink, u32 id,
				 union devlink_param_value val,
				 struct netlink_ext_ack *extack)
{
	struct ice_pf *pf = devlink_priv(devlink);

	if (!test_bit(ICE_FLAG_RDMA_ENA, pf->flags))
		return -EOPNOTSUPP;

	if (pf->rdma_mode & IIDC_RDMA_PROTOCOL_IWARP) {
		NL_SET_ERR_MSG_MOD(extack, "iWARP is currently enabled. This device cannot enable iWARP and RoCEv2 simultaneously");
		return -EOPNOTSUPP;
	}

	return 0;
}

static int
ice_devlink_enable_iw_get(struct devlink *devlink, u32 id,
			  struct devlink_param_gset_ctx *ctx)
{
	struct ice_pf *pf = devlink_priv(devlink);

	ctx->val.vbool = pf->rdma_mode & IIDC_RDMA_PROTOCOL_IWARP;

	return 0;
}

static int
ice_devlink_enable_iw_set(struct devlink *devlink, u32 id,
			  struct devlink_param_gset_ctx *ctx)
{
	struct ice_pf *pf = devlink_priv(devlink);
	bool iw_ena = ctx->val.vbool;
	int ret;

	if (!iw_ena) {
		ice_unplug_aux_dev(pf);
		pf->rdma_mode &= ~IIDC_RDMA_PROTOCOL_IWARP;
		return 0;
	}

	pf->rdma_mode |= IIDC_RDMA_PROTOCOL_IWARP;
	ret = ice_plug_aux_dev(pf);
	if (ret)
		pf->rdma_mode &= ~IIDC_RDMA_PROTOCOL_IWARP;

	return ret;
}

static int
ice_devlink_enable_iw_validate(struct devlink *devlink, u32 id,
			       union devlink_param_value val,
			       struct netlink_ext_ack *extack)
{
	struct ice_pf *pf = devlink_priv(devlink);

	if (!test_bit(ICE_FLAG_RDMA_ENA, pf->flags))
		return -EOPNOTSUPP;

	if (pf->rdma_mode & IIDC_RDMA_PROTOCOL_ROCEV2) {
		NL_SET_ERR_MSG_MOD(extack, "RoCEv2 is currently enabled. This device cannot enable iWARP and RoCEv2 simultaneously");
		return -EOPNOTSUPP;
	}

	return 0;
}

static const struct devlink_param ice_devlink_params[] = {
	DEVLINK_PARAM_GENERIC(ENABLE_ROCE, BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			      ice_devlink_enable_roce_get,
			      ice_devlink_enable_roce_set,
			      ice_devlink_enable_roce_validate),
	DEVLINK_PARAM_GENERIC(ENABLE_IWARP, BIT(DEVLINK_PARAM_CMODE_RUNTIME),
			      ice_devlink_enable_iw_get,
			      ice_devlink_enable_iw_set,
			      ice_devlink_enable_iw_validate),

};

static void ice_devlink_free(void *devlink_ptr)
{
	devlink_free((struct devlink *)devlink_ptr);
}

/**
 * ice_allocate_pf - Allocate devlink and return PF structure pointer
 * @dev: the device to allocate for
 *
 * Allocate a devlink instance for this device and return the private area as
 * the PF structure. The devlink memory is kept track of through devres by
 * adding an action to remove it when unwinding.
 */
struct ice_pf *ice_allocate_pf(struct device *dev)
{
	struct devlink *devlink;

	devlink = devlink_alloc(&ice_devlink_ops, sizeof(struct ice_pf), dev);
	if (!devlink)
		return NULL;

	/* Add an action to teardown the devlink when unwinding the driver */
	if (devm_add_action_or_reset(dev, ice_devlink_free, devlink))
		return NULL;

	return devlink_priv(devlink);
}

/**
 * ice_devlink_register - Register devlink interface for this PF
 * @pf: the PF to register the devlink for.
 *
 * Register the devlink instance associated with this physical function.
 *
 * Return: zero on success or an error code on failure.
 */
void ice_devlink_register(struct ice_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);

	devlink_register(devlink);
}

/**
 * ice_devlink_unregister - Unregister devlink resources for this PF.
 * @pf: the PF structure to cleanup
 *
 * Releases resources used by devlink and cleans up associated memory.
 */
void ice_devlink_unregister(struct ice_pf *pf)
{
	devlink_unregister(priv_to_devlink(pf));
}

/**
 * ice_devlink_set_switch_id - Set unique switch id based on pci dsn
 * @pf: the PF to create a devlink port for
 * @ppid: struct with switch id information
 */
static void
ice_devlink_set_switch_id(struct ice_pf *pf, struct netdev_phys_item_id *ppid)
{
	struct pci_dev *pdev = pf->pdev;
	u64 id;

	id = pci_get_dsn(pdev);

	ppid->id_len = sizeof(id);
	put_unaligned_be64(id, &ppid->id);
}

int ice_devlink_register_params(struct ice_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);

	return devlink_params_register(devlink, ice_devlink_params,
				       ARRAY_SIZE(ice_devlink_params));
}

void ice_devlink_unregister_params(struct ice_pf *pf)
{
	devlink_params_unregister(priv_to_devlink(pf), ice_devlink_params,
				  ARRAY_SIZE(ice_devlink_params));
}

/**
 * ice_devlink_set_port_split_options - Set port split options
 * @pf: the PF to set port split options
 * @attrs: devlink attributes
 *
 * Sets devlink port split options based on available FW port options
 */
static void
ice_devlink_set_port_split_options(struct ice_pf *pf,
				   struct devlink_port_attrs *attrs)
{
	struct ice_aqc_get_port_options_elem options[ICE_AQC_PORT_OPT_MAX];
	u8 i, active_idx, pending_idx, option_count = ICE_AQC_PORT_OPT_MAX;
	bool active_valid, pending_valid;
	int status;

	status = ice_aq_get_port_options(&pf->hw, options, &option_count,
					 0, true, &active_idx, &active_valid,
					 &pending_idx, &pending_valid);
	if (status) {
		dev_dbg(ice_pf_to_dev(pf), "Couldn't read port split options, err = %d\n",
			status);
		return;
	}

	/* find the biggest available port split count */
	for (i = 0; i < option_count; i++)
		attrs->lanes = max_t(int, attrs->lanes, options[i].pmd);

	attrs->splittable = attrs->lanes ? 1 : 0;
	ice_active_port_option = active_idx;
}

static const struct devlink_port_ops ice_devlink_port_ops = {
	.port_split = ice_devlink_port_split,
	.port_unsplit = ice_devlink_port_unsplit,
};

/**
 * ice_devlink_create_pf_port - Create a devlink port for this PF
 * @pf: the PF to create a devlink port for
 *
 * Create and register a devlink_port for this PF.
 *
 * Return: zero on success or an error code on failure.
 */
int ice_devlink_create_pf_port(struct ice_pf *pf)
{
	struct devlink_port_attrs attrs = {};
	struct devlink_port *devlink_port;
	struct devlink *devlink;
	struct ice_vsi *vsi;
	struct device *dev;
	int err;

	dev = ice_pf_to_dev(pf);

	devlink_port = &pf->devlink_port;

	vsi = ice_get_main_vsi(pf);
	if (!vsi)
		return -EIO;

	attrs.flavour = DEVLINK_PORT_FLAVOUR_PHYSICAL;
	attrs.phys.port_number = pf->hw.bus.func;

	/* As FW supports only port split options for whole device,
	 * set port split options only for first PF.
	 */
	if (pf->hw.pf_id == 0)
		ice_devlink_set_port_split_options(pf, &attrs);

	ice_devlink_set_switch_id(pf, &attrs.switch_id);

	devlink_port_attrs_set(devlink_port, &attrs);
	devlink = priv_to_devlink(pf);

	err = devlink_port_register_with_ops(devlink, devlink_port, vsi->idx,
					     &ice_devlink_port_ops);
	if (err) {
		dev_err(dev, "Failed to create devlink port for PF %d, error %d\n",
			pf->hw.pf_id, err);
		return err;
	}

	return 0;
}

/**
 * ice_devlink_destroy_pf_port - Destroy the devlink_port for this PF
 * @pf: the PF to cleanup
 *
 * Unregisters the devlink_port structure associated with this PF.
 */
void ice_devlink_destroy_pf_port(struct ice_pf *pf)
{
	devlink_port_unregister(&pf->devlink_port);
}

/**
 * ice_devlink_create_vf_port - Create a devlink port for this VF
 * @vf: the VF to create a port for
 *
 * Create and register a devlink_port for this VF.
 *
 * Return: zero on success or an error code on failure.
 */
int ice_devlink_create_vf_port(struct ice_vf *vf)
{
	struct devlink_port_attrs attrs = {};
	struct devlink_port *devlink_port;
	struct devlink *devlink;
	struct ice_vsi *vsi;
	struct device *dev;
	struct ice_pf *pf;
	int err;

	pf = vf->pf;
	dev = ice_pf_to_dev(pf);
	devlink_port = &vf->devlink_port;

	vsi = ice_get_vf_vsi(vf);
	if (!vsi)
		return -EINVAL;

	attrs.flavour = DEVLINK_PORT_FLAVOUR_PCI_VF;
	attrs.pci_vf.pf = pf->hw.bus.func;
	attrs.pci_vf.vf = vf->vf_id;

	ice_devlink_set_switch_id(pf, &attrs.switch_id);

	devlink_port_attrs_set(devlink_port, &attrs);
	devlink = priv_to_devlink(pf);

	err = devlink_port_register(devlink, devlink_port, vsi->idx);
	if (err) {
		dev_err(dev, "Failed to create devlink port for VF %d, error %d\n",
			vf->vf_id, err);
		return err;
	}

	return 0;
}

/**
 * ice_devlink_destroy_vf_port - Destroy the devlink_port for this VF
 * @vf: the VF to cleanup
 *
 * Unregisters the devlink_port structure associated with this VF.
 */
void ice_devlink_destroy_vf_port(struct ice_vf *vf)
{
	devlink_port_unregister(&vf->devlink_port);
}

#define ICE_DEVLINK_READ_BLK_SIZE (1024 * 1024)

/**
 * ice_devlink_nvm_snapshot - Capture a snapshot of the NVM flash contents
 * @devlink: the devlink instance
 * @ops: the devlink region being snapshotted
 * @extack: extended ACK response structure
 * @data: on exit points to snapshot data buffer
 *
 * This function is called in response to the DEVLINK_CMD_REGION_TRIGGER for
 * the nvm-flash devlink region. It captures a snapshot of the full NVM flash
 * contents, including both banks of flash. This snapshot can later be viewed
 * via the devlink-region interface.
 *
 * It captures the flash using the FLASH_ONLY bit set when reading via
 * firmware, so it does not read the current Shadow RAM contents. For that,
 * use the shadow-ram region.
 *
 * @returns zero on success, and updates the data pointer. Returns a non-zero
 * error code on failure.
 */
static int ice_devlink_nvm_snapshot(struct devlink *devlink,
				    const struct devlink_region_ops *ops,
				    struct netlink_ext_ack *extack, u8 **data)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	u8 *nvm_data, *tmp, i;
	u32 nvm_size, left;
	s8 num_blks;
	int status;

	nvm_size = hw->flash.flash_size;
	nvm_data = vzalloc(nvm_size);
	if (!nvm_data)
		return -ENOMEM;


	num_blks = DIV_ROUND_UP(nvm_size, ICE_DEVLINK_READ_BLK_SIZE);
	tmp = nvm_data;
	left = nvm_size;

	/* Some systems take longer to read the NVM than others which causes the
	 * FW to reclaim the NVM lock before the entire NVM has been read. Fix
	 * this by breaking the reads of the NVM into smaller chunks that will
	 * probably not take as long. This has some overhead since we are
	 * increasing the number of AQ commands, but it should always work
	 */
	for (i = 0; i < num_blks; i++) {
		u32 read_sz = min_t(u32, ICE_DEVLINK_READ_BLK_SIZE, left);

		status = ice_acquire_nvm(hw, ICE_RES_READ);
		if (status) {
			dev_dbg(dev, "ice_acquire_nvm failed, err %d aq_err %d\n",
				status, hw->adminq.sq_last_status);
			NL_SET_ERR_MSG_MOD(extack, "Failed to acquire NVM semaphore");
			vfree(nvm_data);
			return -EIO;
		}

		status = ice_read_flat_nvm(hw, i * ICE_DEVLINK_READ_BLK_SIZE,
					   &read_sz, tmp, false);
		if (status) {
			dev_dbg(dev, "ice_read_flat_nvm failed after reading %u bytes, err %d aq_err %d\n",
				read_sz, status, hw->adminq.sq_last_status);
			NL_SET_ERR_MSG_MOD(extack, "Failed to read NVM contents");
			ice_release_nvm(hw);
			vfree(nvm_data);
			return -EIO;
		}
		ice_release_nvm(hw);

		tmp += read_sz;
		left -= read_sz;
	}

	*data = nvm_data;

	return 0;
}

/**
 * ice_devlink_sram_snapshot - Capture a snapshot of the Shadow RAM contents
 * @devlink: the devlink instance
 * @ops: the devlink region being snapshotted
 * @extack: extended ACK response structure
 * @data: on exit points to snapshot data buffer
 *
 * This function is called in response to the DEVLINK_CMD_REGION_TRIGGER for
 * the shadow-ram devlink region. It captures a snapshot of the shadow ram
 * contents. This snapshot can later be viewed via the devlink-region
 * interface.
 *
 * @returns zero on success, and updates the data pointer. Returns a non-zero
 * error code on failure.
 */
static int
ice_devlink_sram_snapshot(struct devlink *devlink,
			  const struct devlink_region_ops __always_unused *ops,
			  struct netlink_ext_ack *extack, u8 **data)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	u8 *sram_data;
	u32 sram_size;
	int err;

	sram_size = hw->flash.sr_words * 2u;
	sram_data = vzalloc(sram_size);
	if (!sram_data)
		return -ENOMEM;

	err = ice_acquire_nvm(hw, ICE_RES_READ);
	if (err) {
		dev_dbg(dev, "ice_acquire_nvm failed, err %d aq_err %d\n",
			err, hw->adminq.sq_last_status);
		NL_SET_ERR_MSG_MOD(extack, "Failed to acquire NVM semaphore");
		vfree(sram_data);
		return err;
	}

	/* Read from the Shadow RAM, rather than directly from NVM */
	err = ice_read_flat_nvm(hw, 0, &sram_size, sram_data, true);
	if (err) {
		dev_dbg(dev, "ice_read_flat_nvm failed after reading %u bytes, err %d aq_err %d\n",
			sram_size, err, hw->adminq.sq_last_status);
		NL_SET_ERR_MSG_MOD(extack,
				   "Failed to read Shadow RAM contents");
		ice_release_nvm(hw);
		vfree(sram_data);
		return err;
	}

	ice_release_nvm(hw);

	*data = sram_data;

	return 0;
}

/**
 * ice_devlink_devcaps_snapshot - Capture snapshot of device capabilities
 * @devlink: the devlink instance
 * @ops: the devlink region being snapshotted
 * @extack: extended ACK response structure
 * @data: on exit points to snapshot data buffer
 *
 * This function is called in response to the DEVLINK_CMD_REGION_TRIGGER for
 * the device-caps devlink region. It captures a snapshot of the device
 * capabilities reported by firmware.
 *
 * @returns zero on success, and updates the data pointer. Returns a non-zero
 * error code on failure.
 */
static int
ice_devlink_devcaps_snapshot(struct devlink *devlink,
			     const struct devlink_region_ops *ops,
			     struct netlink_ext_ack *extack, u8 **data)
{
	struct ice_pf *pf = devlink_priv(devlink);
	struct device *dev = ice_pf_to_dev(pf);
	struct ice_hw *hw = &pf->hw;
	void *devcaps;
	int status;

	devcaps = vzalloc(ICE_AQ_MAX_BUF_LEN);
	if (!devcaps)
		return -ENOMEM;

	status = ice_aq_list_caps(hw, devcaps, ICE_AQ_MAX_BUF_LEN, NULL,
				  ice_aqc_opc_list_dev_caps, NULL);
	if (status) {
		dev_dbg(dev, "ice_aq_list_caps: failed to read device capabilities, err %d aq_err %d\n",
			status, hw->adminq.sq_last_status);
		NL_SET_ERR_MSG_MOD(extack, "Failed to read device capabilities");
		vfree(devcaps);
		return status;
	}

	*data = (u8 *)devcaps;

	return 0;
}

static const struct devlink_region_ops ice_nvm_region_ops = {
	.name = "nvm-flash",
	.destructor = vfree,
	.snapshot = ice_devlink_nvm_snapshot,
};

static const struct devlink_region_ops ice_sram_region_ops = {
	.name = "shadow-ram",
	.destructor = vfree,
	.snapshot = ice_devlink_sram_snapshot,
};

static const struct devlink_region_ops ice_devcaps_region_ops = {
	.name = "device-caps",
	.destructor = vfree,
	.snapshot = ice_devlink_devcaps_snapshot,
};

/**
 * ice_devlink_init_regions - Initialize devlink regions
 * @pf: the PF device structure
 *
 * Create devlink regions used to enable access to dump the contents of the
 * flash memory on the device.
 */
void ice_devlink_init_regions(struct ice_pf *pf)
{
	struct devlink *devlink = priv_to_devlink(pf);
	struct device *dev = ice_pf_to_dev(pf);
	u64 nvm_size, sram_size;

	nvm_size = pf->hw.flash.flash_size;
	pf->nvm_region = devlink_region_create(devlink, &ice_nvm_region_ops, 1,
					       nvm_size);
	if (IS_ERR(pf->nvm_region)) {
		dev_err(dev, "failed to create NVM devlink region, err %ld\n",
			PTR_ERR(pf->nvm_region));
		pf->nvm_region = NULL;
	}

	sram_size = pf->hw.flash.sr_words * 2u;
	pf->sram_region = devlink_region_create(devlink, &ice_sram_region_ops,
						1, sram_size);
	if (IS_ERR(pf->sram_region)) {
		dev_err(dev, "failed to create shadow-ram devlink region, err %ld\n",
			PTR_ERR(pf->sram_region));
		pf->sram_region = NULL;
	}

	pf->devcaps_region = devlink_region_create(devlink,
						   &ice_devcaps_region_ops, 10,
						   ICE_AQ_MAX_BUF_LEN);
	if (IS_ERR(pf->devcaps_region)) {
		dev_err(dev, "failed to create device-caps devlink region, err %ld\n",
			PTR_ERR(pf->devcaps_region));
		pf->devcaps_region = NULL;
	}
}

/**
 * ice_devlink_destroy_regions - Destroy devlink regions
 * @pf: the PF device structure
 *
 * Remove previously created regions for this PF.
 */
void ice_devlink_destroy_regions(struct ice_pf *pf)
{
	if (pf->nvm_region)
		devlink_region_destroy(pf->nvm_region);

	if (pf->sram_region)
		devlink_region_destroy(pf->sram_region);

	if (pf->devcaps_region)
		devlink_region_destroy(pf->devcaps_region);
}
