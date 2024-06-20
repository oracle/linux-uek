// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2016 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2016 Jiri Pirko <jiri@mellanox.com>
 */

#include <net/genetlink.h>
#include <net/sock.h>
#include "devl_internal.h"

struct devlink_reload_combination {
	enum devlink_reload_action action;
	enum devlink_reload_limit limit;
};

static const struct devlink_reload_combination devlink_reload_invalid_combinations[] = {
	{
		/* can't reinitialize driver with no down time */
		.action = DEVLINK_RELOAD_ACTION_DRIVER_REINIT,
		.limit = DEVLINK_RELOAD_LIMIT_NO_RESET,
	},
};

static bool
devlink_reload_combination_is_invalid(enum devlink_reload_action action,
				      enum devlink_reload_limit limit)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(devlink_reload_invalid_combinations); i++)
		if (devlink_reload_invalid_combinations[i].action == action &&
		    devlink_reload_invalid_combinations[i].limit == limit)
			return true;
	return false;
}

static bool
devlink_reload_action_is_supported(struct devlink *devlink, enum devlink_reload_action action)
{
	return test_bit(action, &devlink->ops->reload_actions);
}

static bool
devlink_reload_limit_is_supported(struct devlink *devlink, enum devlink_reload_limit limit)
{
	return test_bit(limit, &devlink->ops->reload_limits);
}

static int devlink_reload_stat_put(struct sk_buff *msg,
				   enum devlink_reload_limit limit, u32 value)
{
	struct nlattr *reload_stats_entry;

	reload_stats_entry = nla_nest_start(msg, DEVLINK_ATTR_RELOAD_STATS_ENTRY);
	if (!reload_stats_entry)
		return -EMSGSIZE;

	if (nla_put_u8(msg, DEVLINK_ATTR_RELOAD_STATS_LIMIT, limit) ||
	    nla_put_u32(msg, DEVLINK_ATTR_RELOAD_STATS_VALUE, value))
		goto nla_put_failure;
	nla_nest_end(msg, reload_stats_entry);
	return 0;

nla_put_failure:
	nla_nest_cancel(msg, reload_stats_entry);
	return -EMSGSIZE;
}

static int
devlink_reload_stats_put(struct sk_buff *msg, struct devlink *devlink, bool is_remote)
{
	struct nlattr *reload_stats_attr, *act_info, *act_stats;
	int i, j, stat_idx;
	u32 value;

	if (!is_remote)
		reload_stats_attr = nla_nest_start(msg, DEVLINK_ATTR_RELOAD_STATS);
	else
		reload_stats_attr = nla_nest_start(msg, DEVLINK_ATTR_REMOTE_RELOAD_STATS);

	if (!reload_stats_attr)
		return -EMSGSIZE;

	for (i = 0; i <= DEVLINK_RELOAD_ACTION_MAX; i++) {
		if ((!is_remote &&
		     !devlink_reload_action_is_supported(devlink, i)) ||
		    i == DEVLINK_RELOAD_ACTION_UNSPEC)
			continue;
		act_info = nla_nest_start(msg, DEVLINK_ATTR_RELOAD_ACTION_INFO);
		if (!act_info)
			goto nla_put_failure;

		if (nla_put_u8(msg, DEVLINK_ATTR_RELOAD_ACTION, i))
			goto action_info_nest_cancel;
		act_stats = nla_nest_start(msg, DEVLINK_ATTR_RELOAD_ACTION_STATS);
		if (!act_stats)
			goto action_info_nest_cancel;

		for (j = 0; j <= DEVLINK_RELOAD_LIMIT_MAX; j++) {
			/* Remote stats are shown even if not locally supported.
			 * Stats of actions with unspecified limit are shown
			 * though drivers don't need to register unspecified
			 * limit.
			 */
			if ((!is_remote && j != DEVLINK_RELOAD_LIMIT_UNSPEC &&
			     !devlink_reload_limit_is_supported(devlink, j)) ||
			    devlink_reload_combination_is_invalid(i, j))
				continue;

			stat_idx = j * __DEVLINK_RELOAD_ACTION_MAX + i;
			if (!is_remote)
				value = devlink->stats.reload_stats[stat_idx];
			else
				value = devlink->stats.remote_reload_stats[stat_idx];
			if (devlink_reload_stat_put(msg, j, value))
				goto action_stats_nest_cancel;
		}
		nla_nest_end(msg, act_stats);
		nla_nest_end(msg, act_info);
	}
	nla_nest_end(msg, reload_stats_attr);
	return 0;

action_stats_nest_cancel:
	nla_nest_cancel(msg, act_stats);
action_info_nest_cancel:
	nla_nest_cancel(msg, act_info);
nla_put_failure:
	nla_nest_cancel(msg, reload_stats_attr);
	return -EMSGSIZE;
}

static int devlink_nl_fill(struct sk_buff *msg, struct devlink *devlink,
			   enum devlink_command cmd, u32 portid,
			   u32 seq, int flags)
{
	struct nlattr *dev_stats;
	void *hdr;

	hdr = genlmsg_put(msg, portid, seq, &devlink_nl_family, flags, cmd);
	if (!hdr)
		return -EMSGSIZE;

	if (devlink_nl_put_handle(msg, devlink))
		goto nla_put_failure;
	if (nla_put_u8(msg, DEVLINK_ATTR_RELOAD_FAILED, devlink->reload_failed))
		goto nla_put_failure;

	dev_stats = nla_nest_start(msg, DEVLINK_ATTR_DEV_STATS);
	if (!dev_stats)
		goto nla_put_failure;

	if (devlink_reload_stats_put(msg, devlink, false))
		goto dev_stats_nest_cancel;
	if (devlink_reload_stats_put(msg, devlink, true))
		goto dev_stats_nest_cancel;

	nla_nest_end(msg, dev_stats);
	genlmsg_end(msg, hdr);
	return 0;

dev_stats_nest_cancel:
	nla_nest_cancel(msg, dev_stats);
nla_put_failure:
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

void devlink_notify(struct devlink *devlink, enum devlink_command cmd)
{
	struct sk_buff *msg;
	int err;

	WARN_ON(cmd != DEVLINK_CMD_NEW && cmd != DEVLINK_CMD_DEL);
	WARN_ON(!xa_get_mark(&devlinks, devlink->index, DEVLINK_REGISTERED));

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return;

	err = devlink_nl_fill(msg, devlink, cmd, 0, 0, 0);
	if (err) {
		nlmsg_free(msg);
		return;
	}

	genlmsg_multicast_netns(&devlink_nl_family, devlink_net(devlink),
				msg, 0, DEVLINK_MCGRP_CONFIG, GFP_KERNEL);
}

int devlink_nl_cmd_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct devlink *devlink = info->user_ptr[0];
	struct sk_buff *msg;
	int err;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	err = devlink_nl_fill(msg, devlink, DEVLINK_CMD_NEW,
			      info->snd_portid, info->snd_seq, 0);
	if (err) {
		nlmsg_free(msg);
		return err;
	}

	return genlmsg_reply(msg, info);
}

static int
devlink_nl_cmd_get_dump_one(struct sk_buff *msg, struct devlink *devlink,
			    struct netlink_callback *cb)
{
	return devlink_nl_fill(msg, devlink, DEVLINK_CMD_NEW,
			       NETLINK_CB(cb->skb).portid,
			       cb->nlh->nlmsg_seq, NLM_F_MULTI);
}

const struct devlink_cmd devl_cmd_get = {
	.dump_one		= devlink_nl_cmd_get_dump_one,
};

static void devlink_reload_failed_set(struct devlink *devlink,
				      bool reload_failed)
{
	if (devlink->reload_failed == reload_failed)
		return;
	devlink->reload_failed = reload_failed;
	devlink_notify(devlink, DEVLINK_CMD_NEW);
}

bool devlink_is_reload_failed(const struct devlink *devlink)
{
	return devlink->reload_failed;
}
EXPORT_SYMBOL_GPL(devlink_is_reload_failed);

static void
__devlink_reload_stats_update(struct devlink *devlink, u32 *reload_stats,
			      enum devlink_reload_limit limit, u32 actions_performed)
{
	unsigned long actions = actions_performed;
	int stat_idx;
	int action;

	for_each_set_bit(action, &actions, __DEVLINK_RELOAD_ACTION_MAX) {
		stat_idx = limit * __DEVLINK_RELOAD_ACTION_MAX + action;
		reload_stats[stat_idx]++;
	}
	devlink_notify(devlink, DEVLINK_CMD_NEW);
}

static void
devlink_reload_stats_update(struct devlink *devlink, enum devlink_reload_limit limit,
			    u32 actions_performed)
{
	__devlink_reload_stats_update(devlink, devlink->stats.reload_stats, limit,
				      actions_performed);
}

/**
 *	devlink_remote_reload_actions_performed - Update devlink on reload actions
 *	  performed which are not a direct result of devlink reload call.
 *
 *	This should be called by a driver after performing reload actions in case it was not
 *	a result of devlink reload call. For example fw_activate was performed as a result
 *	of devlink reload triggered fw_activate on another host.
 *	The motivation for this function is to keep data on reload actions performed on this
 *	function whether it was done due to direct devlink reload call or not.
 *
 *	@devlink: devlink
 *	@limit: reload limit
 *	@actions_performed: bitmask of actions performed
 */
void devlink_remote_reload_actions_performed(struct devlink *devlink,
					     enum devlink_reload_limit limit,
					     u32 actions_performed)
{
	if (WARN_ON(!actions_performed ||
		    actions_performed & BIT(DEVLINK_RELOAD_ACTION_UNSPEC) ||
		    actions_performed >= BIT(__DEVLINK_RELOAD_ACTION_MAX) ||
		    limit > DEVLINK_RELOAD_LIMIT_MAX))
		return;

	__devlink_reload_stats_update(devlink, devlink->stats.remote_reload_stats, limit,
				      actions_performed);
}
EXPORT_SYMBOL_GPL(devlink_remote_reload_actions_performed);

static struct net *devlink_netns_get(struct sk_buff *skb,
				     struct genl_info *info)
{
	struct nlattr *netns_pid_attr = info->attrs[DEVLINK_ATTR_NETNS_PID];
	struct nlattr *netns_fd_attr = info->attrs[DEVLINK_ATTR_NETNS_FD];
	struct nlattr *netns_id_attr = info->attrs[DEVLINK_ATTR_NETNS_ID];
	struct net *net;

	if (!!netns_pid_attr + !!netns_fd_attr + !!netns_id_attr > 1) {
		NL_SET_ERR_MSG_MOD(info->extack, "multiple netns identifying attributes specified");
		return ERR_PTR(-EINVAL);
	}

	if (netns_pid_attr) {
		net = get_net_ns_by_pid(nla_get_u32(netns_pid_attr));
	} else if (netns_fd_attr) {
		net = get_net_ns_by_fd(nla_get_u32(netns_fd_attr));
	} else if (netns_id_attr) {
		net = get_net_ns_by_id(sock_net(skb->sk),
				       nla_get_u32(netns_id_attr));
		if (!net)
			net = ERR_PTR(-EINVAL);
	} else {
		WARN_ON(1);
		net = ERR_PTR(-EINVAL);
	}
	if (IS_ERR(net)) {
		NL_SET_ERR_MSG_MOD(info->extack, "Unknown network namespace");
		return ERR_PTR(-EINVAL);
	}
	if (!netlink_ns_capable(skb, net->user_ns, CAP_NET_ADMIN)) {
		put_net(net);
		return ERR_PTR(-EPERM);
	}
	return net;
}

static void devlink_reload_netns_change(struct devlink *devlink,
					struct net *curr_net,
					struct net *dest_net)
{
	/* Userspace needs to be notified about devlink objects
	 * removed from original and entering new network namespace.
	 * The rest of the devlink objects are re-created during
	 * reload process so the notifications are generated separatelly.
	 */
	devlink_notify_unregister(devlink);
	write_pnet(&devlink->_net, dest_net);
	devlink_notify_register(devlink);
}

int devlink_reload(struct devlink *devlink, struct net *dest_net,
		   enum devlink_reload_action action,
		   enum devlink_reload_limit limit,
		   u32 *actions_performed, struct netlink_ext_ack *extack)
{
	u32 remote_reload_stats[DEVLINK_RELOAD_STATS_ARRAY_SIZE];
	struct net *curr_net;
	int err;

	memcpy(remote_reload_stats, devlink->stats.remote_reload_stats,
	       sizeof(remote_reload_stats));

	err = devlink->ops->reload_down(devlink, !!dest_net, action, limit, extack);
	if (err)
		return err;

	curr_net = devlink_net(devlink);
	if (dest_net && !net_eq(dest_net, curr_net))
		devlink_reload_netns_change(devlink, curr_net, dest_net);

	err = devlink->ops->reload_up(devlink, action, limit, actions_performed, extack);
	devlink_reload_failed_set(devlink, !!err);
	if (err)
		return err;

	WARN_ON(!(*actions_performed & BIT(action)));
	/* Catch driver on updating the remote action within devlink reload */
	WARN_ON(memcmp(remote_reload_stats, devlink->stats.remote_reload_stats,
		       sizeof(remote_reload_stats)));
	devlink_reload_stats_update(devlink, limit, *actions_performed);
	return 0;
}

static int
devlink_nl_reload_actions_performed_snd(struct devlink *devlink, u32 actions_performed,
					enum devlink_command cmd, struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq, &devlink_nl_family, 0, cmd);
	if (!hdr)
		goto free_msg;

	if (devlink_nl_put_handle(msg, devlink))
		goto nla_put_failure;

	if (nla_put_bitfield32(msg, DEVLINK_ATTR_RELOAD_ACTIONS_PERFORMED, actions_performed,
			       actions_performed))
		goto nla_put_failure;
	genlmsg_end(msg, hdr);

	return genlmsg_reply(msg, info);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
free_msg:
	nlmsg_free(msg);
	return -EMSGSIZE;
}

int devlink_nl_cmd_reload(struct sk_buff *skb, struct genl_info *info)
{
	struct devlink *devlink = info->user_ptr[0];
	enum devlink_reload_action action;
	enum devlink_reload_limit limit;
	struct net *dest_net = NULL;
	u32 actions_performed;
	int err;

	err = devlink_resources_validate(devlink, NULL, info);
	if (err) {
		NL_SET_ERR_MSG_MOD(info->extack, "resources size validation failed");
		return err;
	}

	if (info->attrs[DEVLINK_ATTR_RELOAD_ACTION])
		action = nla_get_u8(info->attrs[DEVLINK_ATTR_RELOAD_ACTION]);
	else
		action = DEVLINK_RELOAD_ACTION_DRIVER_REINIT;

	if (!devlink_reload_action_is_supported(devlink, action)) {
		NL_SET_ERR_MSG_MOD(info->extack,
				   "Requested reload action is not supported by the driver");
		return -EOPNOTSUPP;
	}

	limit = DEVLINK_RELOAD_LIMIT_UNSPEC;
	if (info->attrs[DEVLINK_ATTR_RELOAD_LIMITS]) {
		struct nla_bitfield32 limits;
		u32 limits_selected;

		limits = nla_get_bitfield32(info->attrs[DEVLINK_ATTR_RELOAD_LIMITS]);
		limits_selected = limits.value & limits.selector;
		if (!limits_selected) {
			NL_SET_ERR_MSG_MOD(info->extack, "Invalid limit selected");
			return -EINVAL;
		}
		for (limit = 0 ; limit <= DEVLINK_RELOAD_LIMIT_MAX ; limit++)
			if (limits_selected & BIT(limit))
				break;
		/* UAPI enables multiselection, but currently it is not used */
		if (limits_selected != BIT(limit)) {
			NL_SET_ERR_MSG_MOD(info->extack,
					   "Multiselection of limit is not supported");
			return -EOPNOTSUPP;
		}
		if (!devlink_reload_limit_is_supported(devlink, limit)) {
			NL_SET_ERR_MSG_MOD(info->extack,
					   "Requested limit is not supported by the driver");
			return -EOPNOTSUPP;
		}
		if (devlink_reload_combination_is_invalid(action, limit)) {
			NL_SET_ERR_MSG_MOD(info->extack,
					   "Requested limit is invalid for this action");
			return -EINVAL;
		}
	}
	if (info->attrs[DEVLINK_ATTR_NETNS_PID] ||
	    info->attrs[DEVLINK_ATTR_NETNS_FD] ||
	    info->attrs[DEVLINK_ATTR_NETNS_ID]) {
		dest_net = devlink_netns_get(skb, info);
		if (IS_ERR(dest_net))
			return PTR_ERR(dest_net);
	}

	err = devlink_reload(devlink, dest_net, action, limit, &actions_performed, info->extack);

	if (dest_net)
		put_net(dest_net);

	if (err)
		return err;
	/* For backward compatibility generate reply only if attributes used by user */
	if (!info->attrs[DEVLINK_ATTR_RELOAD_ACTION] && !info->attrs[DEVLINK_ATTR_RELOAD_LIMITS])
		return 0;

	return devlink_nl_reload_actions_performed_snd(devlink, actions_performed,
						       DEVLINK_CMD_RELOAD, info);
}

bool devlink_reload_actions_valid(const struct devlink_ops *ops)
{
	const struct devlink_reload_combination *comb;
	int i;

	if (!devlink_reload_supported(ops)) {
		if (WARN_ON(ops->reload_actions))
			return false;
		return true;
	}

	if (WARN_ON(!ops->reload_actions ||
		    ops->reload_actions & BIT(DEVLINK_RELOAD_ACTION_UNSPEC) ||
		    ops->reload_actions >= BIT(__DEVLINK_RELOAD_ACTION_MAX)))
		return false;

	if (WARN_ON(ops->reload_limits & BIT(DEVLINK_RELOAD_LIMIT_UNSPEC) ||
		    ops->reload_limits >= BIT(__DEVLINK_RELOAD_LIMIT_MAX)))
		return false;

	for (i = 0; i < ARRAY_SIZE(devlink_reload_invalid_combinations); i++)  {
		comb = &devlink_reload_invalid_combinations[i];
		if (ops->reload_actions == BIT(comb->action) &&
		    ops->reload_limits == BIT(comb->limit))
			return false;
	}
	return true;
}

static int devlink_nl_eswitch_fill(struct sk_buff *msg, struct devlink *devlink,
				   enum devlink_command cmd, u32 portid,
				   u32 seq, int flags)
{
	const struct devlink_ops *ops = devlink->ops;
	enum devlink_eswitch_encap_mode encap_mode;
	u8 inline_mode;
	void *hdr;
	int err = 0;
	u16 mode;

	hdr = genlmsg_put(msg, portid, seq, &devlink_nl_family, flags, cmd);
	if (!hdr)
		return -EMSGSIZE;

	err = devlink_nl_put_handle(msg, devlink);
	if (err)
		goto nla_put_failure;

	if (ops->eswitch_mode_get) {
		err = ops->eswitch_mode_get(devlink, &mode);
		if (err)
			goto nla_put_failure;
		err = nla_put_u16(msg, DEVLINK_ATTR_ESWITCH_MODE, mode);
		if (err)
			goto nla_put_failure;
	}

	if (ops->eswitch_inline_mode_get) {
		err = ops->eswitch_inline_mode_get(devlink, &inline_mode);
		if (err)
			goto nla_put_failure;
		err = nla_put_u8(msg, DEVLINK_ATTR_ESWITCH_INLINE_MODE,
				 inline_mode);
		if (err)
			goto nla_put_failure;
	}

	if (ops->eswitch_encap_mode_get) {
		err = ops->eswitch_encap_mode_get(devlink, &encap_mode);
		if (err)
			goto nla_put_failure;
		err = nla_put_u8(msg, DEVLINK_ATTR_ESWITCH_ENCAP_MODE, encap_mode);
		if (err)
			goto nla_put_failure;
	}

	genlmsg_end(msg, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	return err;
}

int devlink_nl_cmd_eswitch_get_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct devlink *devlink = info->user_ptr[0];
	struct sk_buff *msg;
	int err;

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	err = devlink_nl_eswitch_fill(msg, devlink, DEVLINK_CMD_ESWITCH_GET,
				      info->snd_portid, info->snd_seq, 0);

	if (err) {
		nlmsg_free(msg);
		return err;
	}

	return genlmsg_reply(msg, info);
}

int devlink_nl_cmd_eswitch_set_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct devlink *devlink = info->user_ptr[0];
	const struct devlink_ops *ops = devlink->ops;
	enum devlink_eswitch_encap_mode encap_mode;
	u8 inline_mode;
	int err = 0;
	u16 mode;

	if (info->attrs[DEVLINK_ATTR_ESWITCH_MODE]) {
		if (!ops->eswitch_mode_set)
			return -EOPNOTSUPP;
		mode = nla_get_u16(info->attrs[DEVLINK_ATTR_ESWITCH_MODE]);
		err = devlink_rate_nodes_check(devlink, mode, info->extack);
		if (err)
			return err;
		err = ops->eswitch_mode_set(devlink, mode, info->extack);
		if (err)
			return err;
	}

	if (info->attrs[DEVLINK_ATTR_ESWITCH_INLINE_MODE]) {
		if (!ops->eswitch_inline_mode_set)
			return -EOPNOTSUPP;
		inline_mode = nla_get_u8(info->attrs[DEVLINK_ATTR_ESWITCH_INLINE_MODE]);
		err = ops->eswitch_inline_mode_set(devlink, inline_mode,
						   info->extack);
		if (err)
			return err;
	}

	if (info->attrs[DEVLINK_ATTR_ESWITCH_ENCAP_MODE]) {
		if (!ops->eswitch_encap_mode_set)
			return -EOPNOTSUPP;
		encap_mode = nla_get_u8(info->attrs[DEVLINK_ATTR_ESWITCH_ENCAP_MODE]);
		err = ops->eswitch_encap_mode_set(devlink, encap_mode,
						  info->extack);
		if (err)
			return err;
	}

	return 0;
}
