/*
 * Copyright (c) 2006-2012 Xsigo Systems Inc.  All rights reserved.
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
 *
 */

/*
 * This file implements XSMP protocol
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>

#include "xscore_priv.h"
#include "xscore.h"
#include "xs_versions.h"
#include "xsmp.h"
#include "xs_compat.h"

#define	MAX_XSMP_MSG_SIZE	1024

#define XSMP_SERVICE_ID		0x02139701

#define	QUEUE_CONN_DELAY	(1000 * 10)

struct xsmp_work {
	struct work_struct work;
	struct xsmp_ctx *xsmp_ctx;
	void *msg;
	int len;
	int status;
};

static struct list_head gxsmp_list;
static struct idr xsmp_id_table;
static spinlock_t xsmp_glob_lock;
u32 xcpm_resource_flags;
unsigned long xscore_wait_time;
/*
 * This mutex is used to protect service structure
 */
struct mutex svc_mutex;
struct mutex xsmp_mutex;

/*
 * xscore_wait_in_boot will be the one which controls vnics,vhbas wait also
 * Disable this in ESX , OVM , CITRIX ......
  */
int boot_flag = 1;
int xscore_wait_in_boot = 1;
module_param(boot_flag, int, 0444);
module_param(xscore_wait_in_boot, int, 0644);

int xscore_handle_hello_msg;
module_param(xscore_handle_hello_msg, int, 0444);

int xsigod_enable;
module_param(xsigod_enable, int, 0444);

static int xsmp_ring_size = 256;
module_param(xsmp_ring_size, int, 0644);
static int xscore_sess_wait_time = 600;
module_param(xscore_sess_wait_time, int, 0644);

#define	MAX_NUM_SVCS		XSMP_MESSAGE_TYPE_MAX

static struct xsmp_service_reg_info xcpm_services[MAX_NUM_SVCS];

static void xsmp_cleanup_session(struct xsmp_ctx *ctx);
static int xsmp_session_create(struct xscore_port *port, u64 dguid, u16 dlid);
static int xsmp_send_resource_list(struct xsmp_ctx *ctx, u32 rflags);
static int xsmp_sess_disconnect(struct xsmp_ctx *xsmp_ctx);
static void notify_ulp(struct xsmp_ctx *ctx, int evt);

static struct xsmp_ctx *xsmp_get_ctx(xsmp_cookie_t cookie)
{
	int idr = (int)(unsigned long)cookie;
	struct xsmp_ctx *ctx;
	unsigned long flags;

	spin_lock_irqsave(&xsmp_glob_lock, flags);
	ctx = idr_find(&xsmp_id_table, idr);
	if (!ctx) {
		spin_unlock_irqrestore(&xsmp_glob_lock, flags);
		return NULL;
	}
	/*
	 * Increment reference count
	 */
	atomic_inc(&ctx->ref_cnt);
	spin_unlock_irqrestore(&xsmp_glob_lock, flags);
	return ctx;
}

static void xsmp_put_ctx(struct xsmp_ctx *ctx)
{
	atomic_dec(&ctx->ref_cnt);
}

void xsmp_ulp_notify(struct xscore_port *port, int port_up)
{
	struct xsmp_ctx *xsmp_ctx;

	mutex_lock(&xsmp_mutex);
	list_for_each_entry(xsmp_ctx, &port->xsmp_list, list) {
		if (port_up)
			clear_bit(XSMP_IBLINK_DOWN, &xsmp_ctx->flags);
		else {
			set_bit(XSMP_IBLINK_DOWN, &xsmp_ctx->flags);
			clear_bit(XSMP_REG_SENT, &xsmp_ctx->flags);
			clear_bit(XSMP_REG_CONFIRM_RCVD, &xsmp_ctx->flags);
			xsmp_ctx->state = XSMP_SESSION_ERROR;
		}
		notify_ulp(xsmp_ctx,
			   port_up ? XSCORE_PORT_UP : XSCORE_PORT_DOWN);
	}
	mutex_unlock(&xsmp_mutex);
}

void xsmp_allocate_xsmp_session(struct xscore_port *port, u64 dguid, u16 dlid)
{
	struct xsmp_ctx *xsmp_ctx;
	int found = 0;

	XSMP_FUNCTION("%s dguid: 0x%llx, dlid: 0x%x\n", __func__, dguid,
		      dlid);

	/*
	 * Grab the xsmp mutex. This protects the xsmp list from 3 different
	 * threads.
	 * 1. The port workq through which xsmp session add/delete happens
	 * 2. A rmmod thread (when user issues rmmod) (module unload)
	 * 3. A ULP attaches to XSMP layer (session update list) or deattaches
	 * This happens when xsvnic/xsvhba/uadm is loaded/unloaded
	 */
	mutex_lock(&xsmp_mutex);

	list_for_each_entry(xsmp_ctx, &port->xsmp_list, list) {
		if (xsmp_ctx->dguid == dguid && port == xsmp_ctx->port) {
			/*
			 * We saw the IO director from the same port
			 * (dguid + port)
			 * Now check if we have a LID change
			 */
			if (dlid != xsmp_ctx->dlid) {
				XSMP_PRINT
				    ("IO Director %s (GUID: 0x%llx)LID changd ",
				     xsmp_ctx->chassis_name, xsmp_ctx->dguid);
				XSMP_PRINT("from 0x%x - 0x%x on port: 0x%llx\n",
				     xsmp_ctx->dlid, dlid, port->guid);
				/*
				 * The connection will get torn down and
				 * reconnect back because of hello timeout
				 */
				xsmp_ctx->dlid = dlid;
				xsmp_ctx->conn_ctx.dlid = dlid;
			}
			found++;
			break;
		}
	}
	/*
	 * Did not find an entry, now start an XSMP session
	 * Need to be called in non-irq context
	 */
	if (!found)
		xsmp_session_create(port, dguid, dlid);

	mutex_unlock(&xsmp_mutex);
}

void xsmp_cleanup_stale_xsmp_sessions(struct xscore_port *port, int force)
{
	struct xsmp_ctx *xsmp_ctx, *tmp;

	XSMP_FUNCTION("%s:\n", __func__);

	/*
	 *  Protect list from rmmod thread/port wq and ULP register/unregister
	 */
	mutex_lock(&xsmp_mutex);

	list_for_each_entry_safe(xsmp_ctx, tmp, &port->xsmp_list, list) {
		if (force || test_bit(XSMP_DELETE_BIT, &xsmp_ctx->flags)) {
			XSMP_PRINT("Deleted XSMP session %s : %s (0x%llx)\n",
				   xsmp_ctx->session_name,
				   xsmp_ctx->chassis_name, xsmp_ctx->dguid);
			/*
			 * If we are in force mode, notify ULP's that either
			 * 1. module is going away
			 * 2. or underlying hardware driver is going away
			 */
			if (force)
				notify_ulp(xsmp_ctx, XSCORE_DEVICE_REMOVAL);
			xsmp_cleanup_session(xsmp_ctx);
		}
	}

	mutex_unlock(&xsmp_mutex);
}

/*
 * Need to be called with global spin lock held
 */
static int xsmp_send_resource_list_update(void)
{
	struct xsmp_ctx *xsmp_ctx;

	mutex_lock(&xsmp_mutex);
	list_for_each_entry(xsmp_ctx, &gxsmp_list, glist) {
		xsmp_ctx->counters[XSMP_RES_LIST_COUNTER]++;
		xsmp_send_resource_list(xsmp_ctx, xcpm_resource_flags);
	}
	mutex_unlock(&xsmp_mutex);
	return 0;
}

int xcpm_register_service(struct xsmp_service_reg_info *s_info)
{
	struct xsmp_service_reg_info *sp;
	int i = s_info->ctrl_message_type;

	if (i < 1 || i >= MAX_NUM_SVCS)
		return -EINVAL;

	sp = &xcpm_services[i];
	/*
	 * Check for duplicate entries
	 */
	mutex_lock(&svc_mutex);
	if (sp->svc_state == SVC_STATE_UP) {
		mutex_unlock(&svc_mutex);
		return i;
	}
	sp->ctrl_message_type = s_info->ctrl_message_type;
	sp->resource_flag_index = s_info->resource_flag_index;
	sp->receive_handler = s_info->receive_handler;
	sp->event_handler = s_info->event_handler;
	sp->callout_handler = s_info->callout_handler;
	sp->svc_state = SVC_STATE_UP;
	/*
	 * Kick start sending resource list list to remote end
	 */
	xcpm_resource_flags |= (1 << sp->resource_flag_index);
	xsmp_send_resource_list_update();
	mutex_unlock(&svc_mutex);
	return i;
}
EXPORT_SYMBOL(xcpm_register_service);

static int xcpm_send_msg_client(struct xsmp_ctx *xsmp_ctx, int svc_id,
				void *msg, int len)
{
	int ret = -ENOTCONN;
	struct xsmp_service_reg_info *sp = &xcpm_services[svc_id];

	mutex_lock(&svc_mutex);
	if (sp->svc_state == SVC_STATE_UP && sp->receive_handler) {
		atomic_inc(&sp->ref_cnt);
		mutex_unlock(&svc_mutex);
		sp->receive_handler((xsmp_cookie_t) (unsigned long)xsmp_ctx->
				    idr, msg, len);
		ret = 0;
		atomic_dec(&sp->ref_cnt);
	} else
		mutex_unlock(&svc_mutex);
	return ret;
}

int xcpm_send_msg_xsigod(xsmp_cookie_t xsmp_hndl, void *msg, int len)
{
	struct xsmp_ctx *ctx;
	int ret;

	ctx = xsmp_get_ctx(xsmp_hndl);
	if (!ctx)
		return -EINVAL;

	if (xcpm_resource_flags & (1 << RESOURCE_FLAG_INDEX_USPACE))
		ret =
		    xcpm_send_msg_client(ctx, XSMP_MESSAGE_TYPE_USPACE, msg,
					 len);
	else {
		xscore_uadm_receive(xsmp_hndl, msg, len);
		ret = 0;
	}

	xsmp_put_ctx(ctx);
	return ret;
}
EXPORT_SYMBOL(xcpm_send_msg_xsigod);

int xcpm_unregister_service(int service_id)
{
	struct xsmp_service_reg_info *sp = &xcpm_services[service_id];

	mutex_lock(&svc_mutex);
	if (sp->svc_state == SVC_STATE_UP) {
		sp->svc_state = SVC_STATE_DOWN;
		mutex_unlock(&svc_mutex);
		while (atomic_read(&sp->ref_cnt))
			msleep(20);
		xcpm_resource_flags &= ~(1 << sp->resource_flag_index);
		/*
		 * Send updated list
		 */
		xsmp_send_resource_list_update();
	} else
		mutex_unlock(&svc_mutex);
	return 0;
}
EXPORT_SYMBOL(xcpm_unregister_service);

void *xcpm_alloc_msg(int sz)
{
	return kmalloc(sz, GFP_ATOMIC);
}
EXPORT_SYMBOL(xcpm_alloc_msg);

void xcpm_free_msg(void *msg)
{
	kfree(msg);
}
EXPORT_SYMBOL(xcpm_free_msg);

int xcpm_is_xsigod_enabled(void)
{
	return xsigod_enable;
}
EXPORT_SYMBOL(xcpm_is_xsigod_enabled);

static inline void change_header_byte_order(struct xsmp_message_header
					    *m_header)
{
	m_header->length = cpu_to_be16(m_header->length);
	m_header->seq_number = cpu_to_be32(m_header->seq_number);
	m_header->source_id.node_id_primary =
	    cpu_to_be64(m_header->source_id.node_id_primary);
	m_header->dest_id.node_id_primary =
	    cpu_to_be64(m_header->dest_id.node_id_primary);
}

static inline void change_session_byte_order(struct xsmp_session_msg *m_session)
{
	m_session->length = cpu_to_be16(m_session->length);
	m_session->resource_flags = cpu_to_be32(m_session->resource_flags);
	m_session->version = cpu_to_be32(m_session->version);
	m_session->chassis_version = cpu_to_be32(m_session->chassis_version);
	m_session->boot_flags = cpu_to_be32(m_session->boot_flags);
	m_session->fw_ver = cpu_to_be64(m_session->fw_ver);
	m_session->hw_ver = cpu_to_be32(m_session->hw_ver);
	m_session->vendor_part_id = cpu_to_be32(m_session->vendor_part_id);
}

int xcpm_get_xsmp_session_info(xsmp_cookie_t xsmp_hndl,
			       struct xsmp_session_info *ip)
{
	struct xsmp_ctx *ctx;

	ctx = xsmp_get_ctx(xsmp_hndl);
	if (!ctx)
		return -EINVAL;

	strncpy(ip->chassis_name, ctx->chassis_name,
		sizeof(ip->chassis_name) - 1);
	ip->chassis_name[sizeof(ip->chassis_name) - 1] = 0;
	strncpy(ip->session_name, ctx->session_name,
		sizeof(ip->session_name) - 1);
	ip->session_name[sizeof(ip->session_name) - 1] = 0;
	ip->version = ctx->xsigo_xsmp_version;
	ip->port = ctx->port;
	ip->ib_device = ctx->port->xs_dev->device;
	ip->dma_device = ctx->port->xs_dev->device->dma_device;
	ip->pd = ctx->port->xs_dev->pd;
	ip->mr = ctx->port->xs_dev->mr;
	ip->is_shca = ctx->port->xs_dev->is_shca;
	ip->dguid = ctx->dguid;
	xsmp_put_ctx(ctx);
	return 0;
}
EXPORT_SYMBOL(xcpm_get_xsmp_session_info);

int xcpm_check_duplicate_names(xsmp_cookie_t xsmp_hndl, char *name, u8 svc_id)
{
	int ret = 0;
	struct xsmp_service_reg_info *sp = &xcpm_services[svc_id];
	struct net_device *chk_netdev;

	if (strcmp(name, VMWARE_RESERVED_KEYS) == 0) {
		pr_err("%s %s is not supported vnic name ", __func__, name);
		pr_err("(it is a reserved keyword for esx5.0)\n");
		ret = -EINVAL;
		goto out;
	}

	chk_netdev = dev_get_by_name(&init_net, name);
	if (chk_netdev != NULL) {
		ret = -EINVAL;
		pr_info("%s !!Warning!! NIC %s is already", __func__, name);
		pr_info("present in system\n");
		dev_put(chk_netdev);
		goto out;
	}

	mutex_lock(&svc_mutex);
	if (sp->svc_state == SVC_STATE_UP && sp->callout_handler) {
		atomic_inc(&sp->ref_cnt);
		mutex_unlock(&svc_mutex);
		ret = sp->callout_handler(name);
		atomic_dec(&sp->ref_cnt);
	} else
		mutex_unlock(&svc_mutex);
out:
	return ret;
}
EXPORT_SYMBOL(xcpm_check_duplicate_names);

int xcpm_send_message(xsmp_cookie_t hndl, int svc_id, u8 *msg, int len)
{
	unsigned long flags;
	struct xsmp_ctx *ctx;
	int ret;
	struct xsmp_message_header *m_header;

	m_header = (struct xsmp_message_header *)msg;

	ctx = xsmp_get_ctx(hndl);
	if (!ctx)
		return -EINVAL;
	/*
	 * Now check state of XSMP
	 */
	spin_lock_irqsave(&ctx->lock, flags);
	if (ctx->state != XSMP_SESSION_CONNECTED) {
		ctx->counters[XSMP_SESSION_CONN_DOWN_COUNTER]++;
		spin_unlock_irqrestore(&ctx->lock, flags);
		xsmp_put_ctx(ctx);
		return -ENOTCONN;
	}
	/*
	 * Fix sequence number and GUID
	 */
	m_header->seq_number = cpu_to_be32(ctx->seq_number++);
	m_header->source_id.node_id_primary = cpu_to_be64(ctx->port->guid);
	m_header->source_id.node_id_aux = 0;
	m_header->dest_id.node_id_aux = 0;
	m_header->dest_id.node_id_primary = cpu_to_be64(ctx->dguid);
	ret =
	    xscore_post_send(&ctx->conn_ctx, m_header, len,
			     XSCORE_DEFER_PROCESS);
	ctx->counters[XSMP_TOTAL_MSG_SENT_COUNTER]++;
	switch (svc_id) {
	case XSMP_MESSAGE_TYPE_VNIC:
		ctx->counters[XSMP_VNIC_MESSAGE_SENT_COUNTER]++;
		break;
	case XSMP_MESSAGE_TYPE_VHBA:
		ctx->counters[XSMP_VHBA_MESSAGE_SENT_COUNTER]++;
		break;
	case XSMP_MESSAGE_TYPE_USPACE:
		ctx->counters[XSMP_USPACE_MESSAGE_SENT_COUNTER]++;
		break;
	case XSMP_MESSAGE_TYPE_XVE:
		ctx->counters[XSMP_XVE_MESSAGE_SENT_COUNTER]++;
		break;
	default:
		break;
	}
	if (ret) {
		if (ret == -ENOBUFS)
			ctx->counters[XSMP_SESSION_RING_FULL_COUNTER]++;
		else
			ctx->counters[XSMP_SESSION_SEND_ERROR_COUNTER]++;
	}
	spin_unlock_irqrestore(&ctx->lock, flags);
	xsmp_put_ctx(ctx);
	return ret;
}
EXPORT_SYMBOL(xcpm_send_message);

/*
 * XSMP session will be considered to "match" (i.e. are the
 * same logical communication path) if the remote (destination) GUID
 * and the session (aka server profile name) are identical.
 * GUIDs by definition should be unique and there is a requirement
 * that each server profile name on a given chassis be unique.
 */
int xsmp_sessions_match(struct xsmp_session_info *infop, xsmp_cookie_t cookie)
{
	struct xsmp_ctx *ctx;
	int rc;

	ctx = xsmp_get_ctx(cookie);
	if (!ctx)
		return 0;
	rc = ((infop->dguid == ctx->dguid)
	      && (strncmp(infop->session_name, ctx->session_name,
			  SESSION_NAME_LEN) == 0));
	xsmp_put_ctx(ctx);
	return rc;
}
EXPORT_SYMBOL(xsmp_sessions_match);

void xscore_wait_for_link_up(void)
{
	struct xscore_port *port;
	int time, delayms = 1000;
	int timeoutsecs = 90;
	struct ib_port_attr port_attr;
	int all_up;

	for (time = 0; time < timeoutsecs * 1000; time += delayms) {
		all_up = 1;
		mutex_lock(&xscore_port_mutex);
		list_for_each_entry(port, &xscore_port_list, gport_list) {
			(void)ib_query_port(port->xs_dev->device,
					    port->port_num, &port_attr);
			if (port_attr.state != IB_PORT_ACTIVE) {
				all_up = 0;
				continue;
			}
		}
		mutex_unlock(&xscore_port_mutex);
		if (all_up)
			break;
		msleep(delayms);
	}
}

void xscore_wait_for_xds_resp(void)
{
	struct xscore_port *port;
	int time, delayms = 1000;
	int timeoutsecs = 30;
	struct ib_port_attr port_attr;
	int all_ok;

	for (time = 0; time < timeoutsecs * 1000; time += delayms) {
		all_ok = 1;
		mutex_lock(&xscore_port_mutex);
		list_for_each_entry(port, &xscore_port_list, gport_list) {
			(void)ib_query_port(port->xs_dev->device,
					    port->port_num, &port_attr);
			if (port_attr.state != IB_PORT_ACTIVE)
				continue;
			/*
			 * Check if XDS bit is set
			 */
			if (!test_bit(XSCORE_SP_PRESENT, &port->flags)
			    && !test_bit(XSCORE_SP_NOT_PRESENT, &port->flags))
				all_ok = 0;
		}
		mutex_unlock(&xscore_port_mutex);
		if (all_ok)
			break;
		msleep(delayms);
	}
}

/*
 * This is used the xsigoboot driver to verify all XSMP sessions are up
 */
int xsmp_sessions_up(void)
{
	struct xsmp_ctx *xsmp_ctx;
	int n = 0;

	mutex_lock(&xsmp_mutex);
	if (list_empty(&gxsmp_list)) {
		/*
		 * If XSMP list is empty mark all sessions up
		 */
		n = 1;
		goto out;
	}
	list_for_each_entry(xsmp_ctx, &gxsmp_list, glist) {
		if (xsmp_ctx->state != XSMP_SESSION_CONNECTED) {
			n = 0;
			break;
		}
		n++;
	}
out:
	mutex_unlock(&xsmp_mutex);
	return n > 0;
}

/*
 * wait for the XSMP sessions to come up.
 */
int xscore_wait_for_sessions(u8 cal_time)
{
	unsigned long init_time;
	int time, ret = 0, delayms = 1000;
	int timeoutsecs = xscore_sess_wait_time;

	init_time = jiffies;

	if (!xscore_wait_in_boot)
		goto out;

	if (cal_time)
		pr_info("XSCORE: Waiting for XSMP Session to come up .....\n");
	else {
		mutex_lock(&xsmp_mutex);
		if (list_empty(&gxsmp_list))
			ret = 0;
		else
			ret = 1;
		mutex_unlock(&xsmp_mutex);
		return ret;
	}

	xscore_wait_for_link_up();

	xscore_wait_for_xds_resp();

	for (time = 0; time < timeoutsecs * 1000; time += delayms) {
		if (xsmp_sessions_up()) {
			XSMP_INFO("XSMP Sessions are up\n");
			ret = delayms;
			goto out;
		}
		msleep(delayms);
		XSMP_INFO("Waiting for XSMP Session to be up\n");
	}
	XSMP_INFO("XSMP Sessions are not up\n");

out:
	if (cal_time)
		xscore_wait_time = jiffies - init_time;
	return ret;
}
EXPORT_SYMBOL(xscore_wait_for_sessions);

static int send_xsmp_sess_msg(struct xsmp_ctx *ctxp, u8 type, u32 rflags)
{
	struct xsmp_session_msg *m_session;
	struct xsmp_message_header *m_header;
	unsigned long flags;
	int ret = 0;
	int len;

	m_header = kmalloc(MAX_XSMP_MSG_SIZE, GFP_ATOMIC);
	if (!m_header)
		return -ENOMEM;
	spin_lock_irqsave(&ctxp->lock, flags);
	if (ctxp->state < XSMP_SESSION_TPT_CONNECTED
	    || ctxp->state > XSMP_SESSION_CONNECTED) {
		ret = -ENOTCONN;
		goto out;
	}
	m_session = (struct xsmp_session_msg *)(m_header + 1);

	m_header->type = XSMP_MESSAGE_TYPE_SESSION;
	len = m_header->length = sizeof(*m_header) + sizeof(*m_session);

	m_header->source_id.node_id_primary = ctxp->port->guid;
	m_header->source_id.node_id_aux = 0;
	m_header->dest_id.node_id_primary = ctxp->dguid;
	m_header->dest_id.node_id_aux = 0;
	m_header->seq_number = ctxp->seq_number++;

	m_session->type = type;
	m_session->length = sizeof(*m_session);
	m_session->resource_flags = rflags | RESOURCE_OS_TYPE_LINUX;
	m_session->version = XSIGO_LINUX_DRIVER_VERSION;
	m_session->chassis_version = MINIMUM_XSIGOS_VERSION;
	m_session->boot_flags = boot_flag;
	m_session->fw_ver = ctxp->port->xs_dev->fw_ver;
	m_session->hw_ver = ctxp->port->xs_dev->hw_ver;
	m_session->vendor_part_id = ctxp->port->xs_dev->vendor_part_id;

	change_header_byte_order(m_header);
	change_session_byte_order(m_session);
	ret =
	    xscore_post_send(&ctxp->conn_ctx, m_header, len,
			     XSCORE_DEFER_PROCESS);
	ctxp->counters[XSMP_TOTAL_MSG_SENT_COUNTER]++;
	ctxp->counters[XSMP_SESSION_MESSAGE_SENT_COUNTER]++;
	if (ret) {
		if (ret == -ENOBUFS)
			ctxp->counters[XSMP_SESSION_RING_FULL_COUNTER]++;
		else
			ctxp->counters[XSMP_SESSION_SEND_ERROR_COUNTER]++;
	}
out:
	spin_unlock_irqrestore(&ctxp->lock, flags);
	if (ret)
		kfree(m_header);
	return ret;
}

static int xsmp_send_register_msg(struct xsmp_ctx *ctx, u32 rflags)
{
	return send_xsmp_sess_msg(ctx, XSMP_SESSION_REGISTER, rflags);
}

static int xsmp_send_hello_msg(struct xsmp_ctx *ctx)
{
	return send_xsmp_sess_msg(ctx, XSMP_SESSION_HELLO, 0);
}

int xsmp_send_resource_list(struct xsmp_ctx *ctx, u32 rflags)
{
	return send_xsmp_sess_msg(ctx, XSMP_SESSION_RESOURCE_LIST, rflags);
}

int xsmp_send_shutdown(struct xsmp_ctx *ctx)
{
	return send_xsmp_sess_msg(ctx, XSMP_SESSION_SHUTDOWN, 0);
}

static void handle_reg_confirm_msg(struct xsmp_ctx *ctx,
				   struct xsmp_session_msg *m_session)
{
	int hello_interval = m_session->version;
	int datapath_timeout = m_session->resource_flags;

	XSMP_INFO("Rcvd XSMP_SESSION_REG_CONFIRM from 0x%llx\n", ctx->dguid);
	set_bit(XSMP_REG_CONFIRM_RCVD, &ctx->flags);
	ctx->counters[XSMP_REG_CONF_COUNTER]++;
	ctx->state = XSMP_SESSION_CONNECTED;
	ctx->hello_timeout = msecs_to_jiffies(hello_interval * 3 * 1000);

	if (datapath_timeout != -1)
		ctx->datapath_timeout = (hello_interval * 3) * 2;
	else
		ctx->datapath_timeout = -1;

	ctx->xsigo_xsmp_version = ntohl(m_session->xsigo_xsmp_version);
	memcpy(ctx->chassis_name, m_session->chassis_name, CHASSIS_NAME_LEN);
	ctx->chassis_name[CHASSIS_NAME_LEN - 1] = '\0';
	memcpy(ctx->session_name, m_session->session_name, SESSION_NAME_LEN);
	ctx->session_name[SESSION_NAME_LEN - 1] = '\0';
	XSMP_PRINT("Established XSMP session (%s) to chassis (%s)\n",
		   ctx->session_name, ctx->chassis_name);
}

static int is_seq_number_ok(struct xsmp_ctx *ctx,
			    struct xsmp_message_header *hdr)
{
	int ok = 1;

	if (ctx->rcv_seq_number != be32_to_cpu(hdr->seq_number)) {
		XSMP_INFO("XSMP Session 0x%llx", ctx->dguid);
		XSMP_INFO("Seq number mismatch: exp: 0x%x, actual: 0x%x\n",
			  ctx->rcv_seq_number,
			  be32_to_cpu(hdr->seq_number));
		ctx->counters[XSMP_SEQ_MISMATCH_COUNTER]++;
		ok = 0;
	}
	ctx->rcv_seq_number++;
	return ok;
}

static void handle_hello_msg(struct xsmp_ctx *ctx,
			     struct xsmp_message_header *hdr)
{
	XSMP_INFO("Rcvd XSMP_SESSION_HELLO from 0x%llx\n", ctx->dguid);
	ctx->hello_jiffies = jiffies;
	if (xsmp_send_hello_msg(ctx)) {
		/*
		 * Mark connection as bad and reconnect
		 */
	} else {
		ctx->counters[XSMP_HELLO_SENT_COUNTER]++;
	}
}

static int xsmp_process_xsmp_session_type(struct xsmp_ctx *ctx, void *msg,
					  int length)
{
	struct xsmp_message_header *m_header = msg;
	struct xsmp_session_msg *m_session =
	    (struct xsmp_session_msg *)(m_header + 1);

	XSMP_FUNCTION("%s: Processing message from GUID: %llx\n",
		      __func__, ctx->dguid);

	if (length < sizeof(*m_header)) {
		kfree(msg);
		return -EINVAL;
	}
	change_header_byte_order(m_header);
	if (length > m_header->length) {
		kfree(msg);
		return -EINVAL;
	}
	change_session_byte_order(m_session);

	switch (m_session->type) {
	case XSMP_SESSION_REG_CONFIRM:
		handle_reg_confirm_msg(ctx, m_session);
		set_bit(XSMP_REG_CONFIRM_RCVD, &ctx->flags);
		break;
	case XSMP_SESSION_HELLO:
		ctx->counters[XSMP_HELLO_RCVD_COUNTER]++;
		handle_hello_msg(ctx, m_header);
		break;
	case XSMP_SESSION_REG_REJECT:
		ctx->counters[XSMP_REJ_RCVD_COUNTER]++;
		set_bit(XSMP_SHUTTINGDOWN_BIT, &ctx->flags);
		XSMP_PRINT("XSMP REJECT received session %s : %s (0x%llx)\n",
			   ctx->session_name, ctx->chassis_name, ctx->dguid);
		break;
	case XSMP_SESSION_SHUTDOWN:
		ctx->counters[XSMP_SHUTDOWN_RCVD_COUNTER]++;
		XSMP_PRINT("XSMP shutdown received session %s : %s (0x%llx)\n",
			   ctx->session_name, ctx->chassis_name, ctx->dguid);
		set_bit(XSMP_SHUTTINGDOWN_BIT, &ctx->flags);
		break;
	default:
		break;
	}
	kfree(msg);
	return 0;
}

static void xsmp_cleanup_session(struct xsmp_ctx *xsmp_ctx)
{
	unsigned long flags, flags1;
	/*
	 * Now delete the entry from the list & idr
	 */
	XSMP_FUNCTION("%s: Cleaning up 0x%llx\n", __func__,
		      xsmp_ctx->dguid);
	xcpm_xsmp_remove_proc_entry(xsmp_ctx);
	spin_lock_irqsave(&xsmp_glob_lock, flags);
	idr_remove(&xsmp_id_table, xsmp_ctx->idr);
	xsmp_ctx->idr = -1;
	spin_lock_irqsave(&xsmp_ctx->lock, flags1);
	set_bit(XSMP_SHUTTINGDOWN_BIT, &xsmp_ctx->flags);
	spin_unlock_irqrestore(&xsmp_ctx->lock, flags1);
	spin_unlock_irqrestore(&xsmp_glob_lock, flags);
	/*
	 * Now disconnect and cleanup connection
	 */
	(void)xsmp_sess_disconnect(xsmp_ctx);

	if (cancel_delayed_work(&xsmp_ctx->sm_work))
		xsmp_put_ctx(xsmp_ctx);
	/*
	 * Wait for reference count to goto zero
	 */
	while (atomic_read(&xsmp_ctx->ref_cnt))
		msleep(100);

	xscore_conn_destroy(&xsmp_ctx->conn_ctx);
	spin_lock_irqsave(&xsmp_glob_lock, flags);
	list_del(&xsmp_ctx->list);
	list_del(&xsmp_ctx->glist);
	spin_unlock_irqrestore(&xsmp_glob_lock, flags);
	kfree(xsmp_ctx);
}

static int xsmp_check_msg_type(struct xsmp_ctx *xsmp_ctx, void *msg)
{
	struct xsmp_session_msg *m_session = { 0 };
	struct xsmp_message_header *m_header =
	    (struct xsmp_message_header *)msg;
	int ret = 1;
	switch (m_header->type) {
	case XSMP_MESSAGE_TYPE_SESSION:
		m_session = (struct xsmp_session_msg *)(m_header + 1);
		if (m_session->type == XSMP_SESSION_HELLO)
			ret = 0;
		break;
	default:
		break;

	}
	return ret;
}

/*
 * Executes in workq/thread context
 * Potentially can use idr here XXX
 */
static void xsmp_process_recv_msgs(struct work_struct *work)
{
	struct xsmp_work *xwork = container_of(work, struct xsmp_work,
					       work);
	struct xsmp_message_header *m_header = xwork->msg;
	struct xsmp_ctx *xsmp_ctx = xwork->xsmp_ctx;
	int sendup = 0;

	xscore_set_wq_state(XSCORE_WQ_XSMP_PROC_MSG);
	is_seq_number_ok(xsmp_ctx, m_header);

	switch (m_header->type) {
	case XSMP_MESSAGE_TYPE_VNIC:
		xsmp_ctx->counters[XSMP_VNIC_MESSAGE_COUNTER]++;
		sendup++;
		break;
	case XSMP_MESSAGE_TYPE_VHBA:
		xsmp_ctx->counters[XSMP_VHBA_MESSAGE_COUNTER]++;
		sendup++;
		break;
	case XSMP_MESSAGE_TYPE_USPACE:
		xsmp_ctx->counters[XSMP_USPACE_MESSAGE_COUNTER]++;
		sendup++;
		break;
	case XSMP_MESSAGE_TYPE_XVE:
		xsmp_ctx->counters[XSMP_XVE_MESSAGE_COUNTER]++;
		sendup++;
		break;
	case XSMP_MESSAGE_TYPE_SESSION:
		xsmp_ctx->counters[XSMP_SESSION_MESSAGE_COUNTER]++;
		xsmp_process_xsmp_session_type(xwork->xsmp_ctx, xwork->msg,
					       xwork->len);
		break;
	default:
		kfree(xwork->msg);
		XSMP_ERROR("%s: Unknown message type: %d\n", __func__,
			   m_header->type);
		break;
	}
	if (sendup) {
		if (xcpm_send_msg_client
		    (xsmp_ctx, m_header->type, xwork->msg, xwork->len))
			kfree(xwork->msg);
	}
	kfree(xwork);
	xsmp_put_ctx(xsmp_ctx);
	xscore_clear_wq_state(XSCORE_WQ_XSMP_PROC_MSG);
}

static void queue_sm_work(struct xsmp_ctx *xsmp_ctx, int msecs)
{
	unsigned long flags;

	spin_lock_irqsave(&xsmp_ctx->lock, flags);
	if (!test_bit(XSMP_SHUTTINGDOWN_BIT, &xsmp_ctx->flags)) {
		atomic_inc(&xsmp_ctx->ref_cnt);
		queue_delayed_work(xsmp_ctx->wq, &xsmp_ctx->sm_work,
				   msecs_to_jiffies(msecs));
	} else
		set_bit(XSMP_DELETE_BIT, &xsmp_ctx->flags);
	spin_unlock_irqrestore(&xsmp_ctx->lock, flags);
}

static int xsmp_sess_disconnect(struct xsmp_ctx *xsmp_ctx)
{
	xsmp_ctx->state = XSMP_SESSION_DISCONNECTED;
	(void)xscore_conn_disconnect(&xsmp_ctx->conn_ctx, 0);
	return 0;
}

static int xsmp_sess_connect(struct xsmp_ctx *xsmp_ctx)
{
	int ret = 0;

	switch (xsmp_ctx->state) {
	case XSMP_SESSION_ERROR:
	case XSMP_SESSION_INIT:
	case XSMP_SESSION_DISCONNECTED:
		xsmp_ctx->counters[XSMP_CONN_RETRY_COUNTER]++;
		xsmp_ctx->rcv_seq_number = 1;
		xsmp_ctx->seq_number = 1;
		xsmp_ctx->jiffies = jiffies;
		xsmp_ctx->state = XSMP_SESSION_TPT_CONNECTING;
		clear_bit(XSMP_REG_SENT, &xsmp_ctx->flags);
		clear_bit(XSMP_REG_CONFIRM_RCVD, &xsmp_ctx->flags);
		XSMP_INFO("%s: Session to 0x%llx, Trying\n", __func__,
			  xsmp_ctx->dguid);
		ret = xscore_conn_connect(&xsmp_ctx->conn_ctx,
			XSCORE_SYNCHRONOUS);
		if (ret) {
			xsmp_ctx->counters[XSMP_CONN_FAILED_COUNTER]++;
			XSMP_INFO("%s: Session %s:%s to 0x%llx Failed ret %d\n",
				  __func__, xsmp_ctx->session_name,
				  xsmp_ctx->chassis_name, xsmp_ctx->dguid, ret);
			ret = -ENOTCONN;
		} else {
			XSMP_INFO("%s: Session to 0x%llx successful\n",
				  __func__, xsmp_ctx->dguid);
			xsmp_ctx->counters[XSMP_CONN_SUCCESS_COUNTER]++;
			xsmp_ctx->jiffies = jiffies;
			xsmp_ctx->hello_jiffies = jiffies;
			xsmp_ctx->state = XSMP_SESSION_CONNECTING;
			if (xsmp_send_register_msg
			    (xsmp_ctx, xcpm_resource_flags)) {
				XSMP_ERROR("REGISTER_MESSAGE failed");
				XSMP_ERROR("to GUID:0x%llx\n", xsmp_ctx->dguid);
			} else {
				set_bit(XSMP_REG_SENT, &xsmp_ctx->flags);
				xsmp_ctx->counters[XSMP_REG_SENT_COUNTER]++;
			}
		}
		break;
	default:
		XSMP_ERROR("%s:Connect called in wrong state, %d\n",
			   __func__, xsmp_ctx->state);
		break;
	}
	return ret;
}

static void xsmp_state_machine(struct xsmp_ctx *xsmp_ctx)
{
	if (xsmp_ctx->state == XSMP_SESSION_CONNECTED ||
	    xsmp_ctx->state == XSMP_SESSION_CONNECTING) {
		xsmp_ctx->sm_delay = 10000;
		/*
		 * Check hello time stamp
		 */
		if (!boot_flag
		    && (((long)jiffies - (long)xsmp_ctx->hello_jiffies) >
			(long)xsmp_ctx->hello_timeout)) {
			/*
			 * Reconnect
			 */
			XSMP_PRINT("XSMROR: trailing whitespacesis");
			XSMP_PRINT("(%s) expired..Reconnecting %s\n",
			xsmp_ctx->session_name, xsmp_ctx->chassis_name);

			xsmp_ctx->counters[XSMP_SESSION_TIMEOUT_COUNTER]++;
		} else
			return;
	}
	xsmp_ctx->sm_delay = 2000;
	(void)xsmp_sess_disconnect(xsmp_ctx);
	if (!test_bit(XSMP_IBLINK_DOWN, &xsmp_ctx->flags))
		xsmp_sess_connect(xsmp_ctx);
}

static void xsmp_state_machine_work(struct work_struct *work)
{
	struct xsmp_ctx *xsmp_ctx = container_of(work, struct xsmp_ctx,
						 sm_work.work);
	xscore_set_wq_state(XSCORE_DWQ_SM_WORK);
	if (!test_bit(XSMP_SHUTTINGDOWN_BIT, &xsmp_ctx->flags))
		xsmp_state_machine(xsmp_ctx);
	queue_sm_work(xsmp_ctx, xsmp_ctx->sm_delay);
	xsmp_put_ctx(xsmp_ctx);
	xscore_clear_wq_state(XSCORE_DWQ_SM_WORK);
}

/*
 * Called from interrupt context
 */
void xsmp_send_handler(void *client_arg, void *msg, int status, int n)
{
	struct xsmp_ctx *xsmp_ctx = client_arg;

	XSMP_INFO("%s: Status %d, GUID: 0x%llx\n", __func__, status,
		  xsmp_ctx->dguid);
	if (status) {
		XSMP_ERROR
		    ("XSMP: %s:%s Send Completion error: 0x%llx, status %d\n",
		     xsmp_ctx->session_name, xsmp_ctx->chassis_name,
		     xsmp_ctx->dguid, status);
		xsmp_ctx->state = XSMP_SESSION_ERROR;
	}
	kfree(msg);
}

/*
 * Called from interrupt context
 */
void xsmp_recv_handler(void *client_arg, void *msg, int sz, int status, int n)
{
	struct xsmp_ctx *xsmp_ctx = client_arg;
	struct xsmp_work *work;
	unsigned long flags;

	if (status) {
		/*
		 * XXX mark connection as bad and
		 * it reconnect (hello timer will kick in)
		 */
		XSMP_ERROR
		    ("XSMP: %s:%s Recv Completion error: 0x%llx, status %d\n",
		     xsmp_ctx->session_name, xsmp_ctx->chassis_name,
		     xsmp_ctx->dguid, status);
		xsmp_ctx->state = XSMP_SESSION_ERROR;
		kfree(msg);
		return;
	}
	if (xscore_handle_hello_msg && !xsmp_check_msg_type(xsmp_ctx, msg)) {
		xsmp_ctx->counters[XSMP_SESSION_MESSAGE_COUNTER]++;
		xsmp_ctx->counters[XSMP_HELLO_INTERRUPT_COUNTER]++;
		xsmp_process_xsmp_session_type(xsmp_ctx, msg, sz);
		return;
	}

	work = kmalloc(sizeof(*work), GFP_ATOMIC);
	if (!work) {
		kfree(msg);
		return;
	}
	INIT_WORK(&work->work, xsmp_process_recv_msgs);
	work->xsmp_ctx = xsmp_ctx;
	work->msg = msg;
	work->len = sz;
	work->status = status;

	spin_lock_irqsave(&xsmp_ctx->lock, flags);
	if (!test_bit(XSMP_SHUTTINGDOWN_BIT, &xsmp_ctx->flags)) {
		atomic_inc(&xsmp_ctx->ref_cnt);
		queue_work(xsmp_ctx->wq, &work->work);
	} else {
		kfree(msg);
		kfree(work);
	}
	spin_unlock_irqrestore(&xsmp_ctx->lock, flags);
}

static void notify_ulp(struct xsmp_ctx *ctx, int evt)
{
	int i;
	struct xsmp_service_reg_info *sp;

	mutex_lock(&svc_mutex);
	for (i = 1; i < MAX_NUM_SVCS; i++) {
		sp = &xcpm_services[i];
		if (sp->svc_state == SVC_STATE_UP && sp->event_handler) {
			atomic_inc(&sp->ref_cnt);
			mutex_unlock(&svc_mutex);
			sp->event_handler((xsmp_cookie_t) (unsigned long)ctx->
					  idr, evt);
			atomic_dec(&sp->ref_cnt);
			mutex_lock(&svc_mutex);
		}
	}
	mutex_unlock(&svc_mutex);
}

/*
 * Called from CM thread context, if you want delayed
 * processing, post to local thread
 */
void xsmp_event_handler(void *client_arg, int event)
{
	struct xsmp_ctx *xsmp_ctx = client_arg;

	switch (event) {
	case XSCORE_CONN_CONNECTED:
		XSMP_INFO("XSCORE_CONN_CONNECTED: GUID: 0x%llx\n",
			  xsmp_ctx->dguid);
		break;
	case XSCORE_CONN_ERR:
		xsmp_ctx->state = XSMP_SESSION_ERROR;
		XSMP_INFO("XSCORE_CONN_ERR: GUID: 0x%llx\n", xsmp_ctx->dguid);
		break;
	case XSCORE_CONN_RDISCONNECTED:
		xsmp_ctx->state = XSMP_SESSION_DISCONNECTED;
		XSMP_INFO("XSCORE_CONN_RDISCONNECTED: GUID: 0x%llx\n",
			  xsmp_ctx->dguid);
		break;
	case XSCORE_CONN_LDISCONNECTED:
		xsmp_ctx->state = XSMP_SESSION_DISCONNECTED;
		XSMP_INFO("XSCORE_CONN_LDISCONNECTED: GUID: 0x%llx\n",
			  xsmp_ctx->dguid);
		break;
	default:
		break;
	}
	notify_ulp(xsmp_ctx, event);
}

struct xsmp_private_data {
	u8 is_checksum;
	u32 reserved[6];
} __packed;

int xsmp_session_create(struct xscore_port *port, u64 dguid, u16 dlid)
{
	struct xsmp_ctx *xsmp_ctx;
	unsigned long flags;
	static int next_id = 1;
	int ret;
	struct xscore_conn_ctx *cctx;
	struct xsmp_private_data *cmp;

	XSMP_FUNCTION("%s: dguid: 0x%llx, dlid: 0x%x\n", __func__, dguid,
		      dlid);

	xsmp_ctx = kzalloc(sizeof(*xsmp_ctx), GFP_ATOMIC);
	if (!xsmp_ctx)
		return -ENOMEM;
	spin_lock_init(&xsmp_ctx->lock);

	cctx = &xsmp_ctx->conn_ctx;
	memset(cctx, 0, sizeof(*cctx));
	cctx->tx_ring_size = xsmp_ring_size;
	cctx->rx_ring_size = xsmp_ring_size;
	cctx->rx_buf_size = MAX_XSMP_MSG_SIZE;
	cctx->client_arg = xsmp_ctx;
	cctx->event_handler = xsmp_event_handler;
	cctx->send_compl_handler = xsmp_send_handler;
	cctx->recv_msg_handler = xsmp_recv_handler;
	cctx->dguid = dguid;
	cctx->dlid = dlid;
	cctx->service_id = be64_to_cpu(XSMP_SERVICE_ID);

	cmp = (struct xsmp_private_data *)cctx->priv_data;
	cctx->priv_data_len = sizeof(*cmp);
	if (port->xs_dev->is_shca && shca_csum) {
		cmp->is_checksum = 1;
		cctx->features |= XSCORE_USE_CHECKSUM;
	} else {
		cmp->is_checksum = 0;
		cctx->features &= ~XSCORE_USE_CHECKSUM;
	}

	ret = xscore_conn_init(&xsmp_ctx->conn_ctx, port);
	if (ret) {
		XSMP_ERROR("xscore_conn_init error %d\n", ret);
		kfree(xsmp_ctx);
		return ret;
	}
	xsmp_ctx->state = XSMP_SESSION_INIT;
	xsmp_ctx->dguid = dguid;
	xsmp_ctx->dlid = dlid;
	xsmp_ctx->port = port;
	xsmp_ctx->wq = port->port_wq;
	xsmp_ctx->hello_timeout = msecs_to_jiffies(60 * 1000);
	do {
		spin_lock_irqsave(&xsmp_glob_lock, flags);
		ret =
		    idr_get_new_above(&xsmp_id_table, xsmp_ctx, next_id++,
				      (__force int *)&xsmp_ctx->idr);
		spin_unlock_irqrestore(&xsmp_glob_lock, flags);
	} while ((ret == -EAGAIN)
		 && idr_pre_get(&xsmp_id_table, GFP_KERNEL));

	INIT_DELAYED_WORK(&xsmp_ctx->sm_work, xsmp_state_machine_work);
	spin_lock_irqsave(&xsmp_glob_lock, flags);
	list_add_tail(&xsmp_ctx->list, &port->xsmp_list);
	list_add_tail(&xsmp_ctx->glist, &gxsmp_list);
	spin_unlock_irqrestore(&xsmp_glob_lock, flags);
	xcpm_xsmp_add_proc_entry(xsmp_ctx);
	xsmp_ctx->sm_delay = 1000;
	queue_sm_work(xsmp_ctx, 0);
	return 0;
}

void xsmp_module_init(void)
{
	spin_lock_init(&xsmp_glob_lock);
	mutex_init(&svc_mutex);
	mutex_init(&xsmp_mutex);
	idr_init(&xsmp_id_table);
	idr_pre_get(&xsmp_id_table, GFP_KERNEL);
	INIT_LIST_HEAD(&gxsmp_list);
}

void xsmp_module_destroy(void)
{
	idr_destroy(&xsmp_id_table);
	mutex_destroy(&svc_mutex);
	mutex_destroy(&xsmp_mutex);
}
