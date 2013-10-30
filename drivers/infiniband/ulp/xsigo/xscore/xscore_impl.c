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
 * This file implements XDS/XDDS protocol as well as XSMP protocol
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/utsname.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/jiffies.h>
#include <linux/proc_fs.h>

#include "xscore_priv.h"
#include "xs_compat.h"
#include "xs_versions.h"
#include "xscore.h"

#ifndef XSIGO_LOCAL_VERSION
#define XSCORE_VERSION "Unknown"
#error "No Version"
#else
#define XSCORE_VERSION XSIGO_LOCAL_VERSION
#endif

MODULE_AUTHOR("Oracle corp (OVN-linux-drivers@oracle.com)");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("OVN core driver");
MODULE_VERSION(XSCORE_VERSION);

int xscore_debug = 0x0;
module_param(xscore_debug, int, 0644);

int xscore_force_sm_change;
module_param(xscore_force_sm_change, int, 0644);
int xscore_notify_ulps;
module_param(xscore_notify_ulps, int, 0644);

char hostname_str[XSIGO_MAX_HOSTNAME + 1];
char system_id_str[64];

static char *hostname;
module_param(hostname, charp, 0444);
static char *system_id;
module_param(system_id, charp, 0444);

char *os_version;
module_param(os_version, charp, 0444);
char *os_arch;
module_param(os_arch, charp, 0444);

#if defined(INDIVIDUAL_HEAPS)
vmk_heapid ib_basic_heapid;
#endif

struct ib_sa_client xscore_sa_client;
struct list_head xscore_port_list;
struct mutex xscore_port_mutex;

static void xscore_add_one(struct ib_device *device);
static void xscore_remove_one(struct ib_device *device);
static void xds_send_handler(struct ib_mad_agent *agent,
			     struct ib_mad_send_wc *mad_send_wc);
static void xds_recv_handler(struct ib_mad_agent *mad_agent,
			     struct ib_mad_recv_wc *mad_recv_wc);
static int xds_check_xcm_record(struct xscore_port *port,
				struct ib_xds_mad *xds_mad);
static void xscore_port_event_handler(struct work_struct *work);

static struct ib_client xscore_client = {
	.name = "xscore",
	.add = xscore_add_one,
	.remove = xscore_remove_one
};

/*
 * Initialize XDS mad agent to send and receive XDS query
 */
static int xscore_init_mad_agent(struct xscore_port *port)
{
	struct xscore_dev *xs_dev = port->xs_dev;
	struct ib_mad_reg_req mad_reg_req;

	memset(&mad_reg_req, 0, sizeof(struct ib_mad_reg_req));
	mad_reg_req.mgmt_class = XSIGO_MGMT_CLASS;
	mad_reg_req.mgmt_class_version = XSIGO_MGMT_CLASS_VERSION;
	set_bit(IB_MGMT_METHOD_GET, mad_reg_req.method_mask);

	port->mad_agent = ib_register_mad_agent(xs_dev->device,
						port->port_num, IB_QPT_GSI,
						&mad_reg_req, 0,
						xds_send_handler,
						xds_recv_handler, (void *)port);

	if (IS_ERR(port->mad_agent)) {
		IB_ERROR("Failure registering mad-handle for ");
		IB_ERROR("port %d,", port->port_num);
		IB_ERROR("GUID: 0x%llx\n", port->guid);
		return PTR_ERR(port->mad_agent);
	}
	return 0;
}

/*
 * This is the callback for service record query by the IB MAD layer
 */
static void service_rec_callback(int status, struct ib_sa_service_rec *resp,
				 void *context)
{
	struct xscore_port *port = (struct xscore_port *)context;

	if (!status && resp) {
		port->xds_lid = be16_to_cpu(resp->data16[0]);
		port->xds_guid = be64_to_cpu(resp->data64[0]);
	} else {
		XDS_INFO("service_rec_callback: failed code: %d,", status);
		XDS_INFO("port %d, GUID: 0x%llx\n", port->port_num, port->guid);
		port->counters[PORT_XDS_SA_QUERY_TOUT_COUNTER]++;
		set_bit(XSCORE_FORCE_SM_CHANGE, &port->flags);
	}
	port->sa_query_status = status;
	/*
	 * Wake up thread waiting
	 */
	XDS_INFO("service_rec_callback: success code: %d, GUID: 0x%llx\n",
		 status, port->guid);
	complete(&port->sa_query_done);
}

static void xdds_msg_handler(struct work_struct *work)
{
	struct xdds_work *xwork = container_of(work, struct xdds_work,
					       work);
	struct xdp_hdr *msghdr = (struct xdp_hdr *)xwork->msg;

	xscore_set_wq_state(XSCORE_WQ_XDDS_HANDLER);
	switch (ntohs(msghdr->type)) {

	case XDP_MSG_TYPE_DISC_SOL:

		/* Unicast from chassis (xcfm info) */
		if (ntohs(msghdr->flags) & XDP_FLAGS_RSP) {
			struct ib_xds_mad xds_mad;

			memset(&xds_mad, 0, sizeof(struct ib_xds_mad));
			memcpy(xds_mad.data,
			       xwork->msg + sizeof(struct xdp_hdr),
			       sizeof(struct xcm_list));
			/*
			 * Now call XCM list handling routine
			 */
			xds_check_xcm_record(xwork->port, &xds_mad);
		}
		break;
	default:
		XDDS_ERROR("%s: Port GUID: ", __func__);
		XDDS_ERROR("0x%llx", xwork->port->guid);
		XDDS_ERROR("Unexpected protocol type");
		XDDS_ERROR(" %d\n", ntohs(msghdr->type));
		break;
	}
	xs_ud_free(xwork->msg);
	kfree(xwork);
	xscore_clear_wq_state(XSCORE_WQ_XDDS_HANDLER);
}

static void xs_ud_callback(void *arg, void *msg, int len)
{
	struct xscore_port *port = arg;
	struct xdds_work *xwork;
	unsigned long flags;

	/*
	 * Grab spin lock and check for SHUTDOWN state
	 */
	spin_lock_irqsave(&port->lock, flags);
	if (test_bit(XSCORE_PORT_SHUTDOWN, &port->flags))
		goto out;
	xwork = kzalloc(sizeof(struct xdds_work), GFP_ATOMIC);
	if (xwork) {
		xwork->msg = (u8 *) msg;
		xwork->msg_len = len;
		xwork->port = port;
		INIT_WORK(&xwork->work, xdds_msg_handler);
		queue_work(port->port_wq, &xwork->work);
	} else
out :
		xs_ud_free(msg);
	spin_unlock_irqrestore(&port->lock, flags);
}

#define	XSCORE_SA_QUERY_TIMEOUT	(3*1000)

/*
 * This function queries SA for XDS service record. This is synchronous
 * and needs to be called  in thread/workq context
 */

int xscore_query_svc_record(struct xscore_port *port)
{
	struct xscore_dev *xs_dev = port->xs_dev;
	struct ib_sa_service_rec service_rec;
	struct ib_sa_query *query;
	struct ib_port_attr attr;
	int ret;

	memset(&service_rec, 0, sizeof(service_rec));
	strcpy(service_rec.name, "XSIGOXDS");
	init_completion(&port->sa_query_done);

	if (xscore_notify_ulps || (xscore_force_sm_change &&
				   test_and_clear_bit(XSCORE_FORCE_SM_CHANGE,
						      &port->flags))) {
		XDS_INFO("ib_sa_force_update: port %d GUID: 0x%llx\n",
			 port->port_num, port->guid);
		attr.sm_lid = port->sm_lid;
		attr.lid = port->lid;
		/* mode = 1 Notify ULPs about IB events */
		ib_sa_force_update(&xscore_sa_client,
				   xs_dev->device, &attr, port->port_num,
				   xscore_notify_ulps);
	}
	port->rec_poller_state = XDS_RECP_SAUPDATE_DONE;

	ret = ib_sa_service_rec_query(&xscore_sa_client,
				      xs_dev->device, port->port_num,
				      IB_MGMT_METHOD_GET, &service_rec,
				      IB_SA_SERVICE_REC_SERVICE_NAME,
				      XSCORE_SA_QUERY_TIMEOUT, GFP_KERNEL,
				      &service_rec_callback, port, &query);
	port->rec_poller_state = XDS_RECP_SAREC_DONE;
	if (ret) {
		XDS_INFO("ib_sa_service_rec_query: failed %d ret,", ret);
		XDS_INFO(" port: %d,", port->port_num);
		XDS_INFO(" GUID: 0x%llx\n:", port->guid);
		port->counters[PORT_XDS_SA_QUERY_ERROR_COUNTER]++;
		return ret;
	}
	port->counters[PORT_XDS_SA_QUERY_COUNTER]++;
	/*
	 * This is get out of jail in case we do not
	 * get any completion, must never happen
	 */
	if (!wait_for_completion_timeout(&port->sa_query_done,
					 msecs_to_jiffies
					 (XSCORE_SA_QUERY_TIMEOUT * 10))) {
		XDS_ERROR("%s: completion timeout, port: %d, GUID: 0x%llx\n:",
			  __func__, port->port_num, port->guid);
		return -ETIMEDOUT;
	}
	return port->sa_query_status;
}

static void create_ib_mad_header(struct xscore_port *port,
				 struct ib_xds_mad *xds_mad)
{
	struct ib_mad_hdr *mad_hdr = &xds_mad->mad_hdr;

	mad_hdr->base_version = IB_MGMT_BASE_VERSION;
	mad_hdr->mgmt_class = XSIGO_MGMT_CLASS;
	mad_hdr->class_version = XSIGO_MGMT_CLASS_VERSION;
	mad_hdr->method = IB_MGMT_METHOD_GET;
	mad_hdr->attr_id = __constant_cpu_to_be16(IB_MAD_ATTR_XCM_REQUEST);
	mad_hdr->tid = port->mad_agent->hi_tid;
	mad_hdr->tid <<= 32;
	mad_hdr->tid |= port->port_num;
	mad_hdr->tid = cpu_to_be64(mad_hdr->tid);
}

/*
 * 31 bit should be set
 * |30|......|17      |16    |15|14
 * ......    | VHBA   | VNIC |
 */
static void xds_send_cap_info(struct xds_request *request)
{
	uint32_t cap_info, i;
	cap_info = (1 << 31) & 0xffffffff;

	for (i = 0; i < RESOURCE_FLAG_INDEX_MAX; i++) {
		if (xcpm_resource_flags & (1 << i))
			cap_info = (cap_info & 0xffff0000) | (1 << (16 + i));
	}
	request->reserved = htonl(cap_info);
}

/*
 * Create a XDS query packet
 */
static void create_xds_mad_req(struct xscore_port *port,
			       struct xds_request *request)
{
	u8 h[16 + 1];
	char tmp_os_version[64];
	unsigned long system_id_ul;
	int ret;

	request->server_record.port_id = cpu_to_be64(port->guid);
	strncpy(request->hostname, hostname_str, XSIGO_MAX_HOSTNAME);
	snprintf(tmp_os_version, sizeof(tmp_os_version) - 1, "%s:xg-%s",
		 init_utsname()->release, XSCORE_VERSION);
	if (strlen(tmp_os_version) >= sizeof(request->os_version)) {
		snprintf(request->os_version, sizeof(request->os_version) - 1,
			 "%s", init_utsname()->release);
		snprintf(request->build_version,
			 sizeof(request->build_version) - 1, "xg-%s",
			 XSCORE_VERSION);
	} else {
		snprintf(request->os_version, sizeof(request->os_version) - 1,
			 "%s:xg-%s", init_utsname()->release, XSCORE_VERSION);
	}
	strcpy(request->os_arch, init_utsname()->machine);
	request->os_type = htonl(RESOURCE_OS_TYPE_LINUX);
	request->os_version[sizeof(request->os_version) - 1] = 0;
	request->os_arch[sizeof(request->os_arch) - 1] = 0;

	request->fw_version = cpu_to_be64(port->xs_dev->fw_ver);
	request->hw_version = htonl(port->xs_dev->hw_ver);
	request->driver_version = htonl(XSIGO_LINUX_DRIVER_VERSION);
	if (system_id_str[0]) {
		ret = kstrtoul(system_id_str + 16 , 16, &system_id_ul);
		request->system_id_l =
		    cpu_to_be64(system_id_ul);
		memcpy(h, system_id_str, 16);
		h[16] = 0;
		ret = kstrtoul(h, 16, &system_id_ul);
		request->system_id_h = cpu_to_be64(system_id_ul);
	}
	xds_send_cap_info(request);
}

/*
 * Send completion handler for XDS query
 */
static void xds_send_handler(struct ib_mad_agent *agent,
			     struct ib_mad_send_wc *mad_send_wc)
{
	struct ib_mad_send_buf *msg = mad_send_wc->send_buf;
	struct xscore_port *port = agent->context;

	switch (mad_send_wc->status) {
	case IB_WC_SUCCESS:
		break;
	default:
		break;
	}

	XDS_INFO("%s, Unmapping send buffer: status %d, Port GUID: 0x%llx\n",
		 __func__, mad_send_wc->status, port->guid);

	ib_destroy_ah(msg->ah);
	ib_free_send_mad(msg);
}

static int xds_check_xcm_record(struct xscore_port *port,
				struct ib_xds_mad *xds_mad)
{
	struct xcm_list list;
	int i;

	XDS_FUNCTION("%s: port 0x%llx\n", __func__, port->guid);

	/*
	 * Skip server_info structure size in response
	 */
	memcpy(&list, xds_mad->data + sizeof(struct server_info), sizeof(list));

	XDS_INFO("%s: port 0x%llx, XCM list count %d\n", __func__,
		 port->guid, list.count);

	if (list.count > MAX_XCFM_COUNT) {
		/*
		 * Print error
		 */
		XDS_ERROR("%s GUID: 0x%llx, list count range error %d\n",
			  __func__, port->guid, list.count);
		return -EINVAL;
	}
	if (list.count && list.xcm_version != XCM_REC_VERSION) {
		XDS_ERROR("%s GUID: 0x%llx, Bad XCM version %d\n",
			  __func__, port->guid, list.xcm_version);
		return -EINVAL;
	}

	for (i = 0; i < list.count; i++) {
		u64 dguid;
		u16 dlid;
		/*
		 * Go through all the XSMP sessions and verify for any duplicate
		 */
		struct xcfm_record *xcmp = &list.xcms[i];

		dguid = be64_to_cpu(xcmp->port_id);
		dlid = be16_to_cpu(xcmp->xcm_lid);
		XDS_INFO("Port GUID: 0x%llx, XCM lid: 0x%x, XCM guid: 0x%llx\n",
			 port->guid, dlid, dguid);
		xsmp_allocate_xsmp_session(port, dguid, dlid);
	}
	if (list.count) {
		port->counters[PORT_XDS_LIST_COUNT_COUNTER]++;
		set_bit(XSCORE_SP_PRESENT, &port->flags);
		clear_bit(XSCORE_SP_NOT_PRESENT, &port->flags);
	} else {
		port->counters[PORT_XDS_LIST_COUNT_ZERO_COUNTER]++;
		set_bit(XSCORE_SP_NOT_PRESENT, &port->flags);
		clear_bit(XSCORE_SP_PRESENT, &port->flags);
	}

	return 0;
}

/*
 * Receive completion handler for XDS query
 */
static void xds_recv_handler(struct ib_mad_agent *mad_agent,
			     struct ib_mad_recv_wc *mad_recv_wc)
{
	struct xscore_port *port = mad_agent->context;

	XDS_FUNCTION("%s: port 0x%llx\n", __func__, port->guid);

	port->counters[PORT_XDS_XDS_QUERY_COUNTER]++;
	port->mad_recv_wc = mad_recv_wc;
	complete(&port->xds_query_done);
}

/*
 * This routine queries XDS for XCM record. This is synchronous and needs to
 * called in thread/workq context
 */
int xscore_query_xds_xcm_rec(struct xscore_port *port)
{
	struct xscore_dev *xs_dev = port->xs_dev;
	struct ib_ah_attr ah_attr;
	struct ib_mad_recv_wc *mad_recv_wc;
	struct ib_xds_mad *xds_mad;
	struct xds_request *request;
	struct ib_port_attr port_attr;
	int ret;

	XDS_FUNCTION("%s: port 0x%llx\n", __func__, port->guid);

	port->send_buf = ib_create_send_mad(port->mad_agent, 1, 0, 0,
					    IB_MGMT_SA_HDR, IB_MGMT_SA_DATA,
					    GFP_KERNEL);
	port->rec_poller_state = XDS_RECP_CREATEMAD_DONE;
	if (IS_ERR(port->send_buf)) {
		ret = PTR_ERR(port->send_buf);
		IB_ERROR("ib_create_send_mad failed, error %d, GUID: 0x%llx\n",
			 ret, port->guid);
		return ret;
	}
	/*
	 * Create XDS MAD query packet
	 */
	xds_mad = port->send_buf->mad;
	memset(xds_mad, 0, sizeof(*xds_mad));
	request = (struct xds_request *)xds_mad->data;
	create_ib_mad_header(port, xds_mad);
	create_xds_mad_req(port, request);

	memset(&ah_attr, 0, sizeof(ah_attr));
	ah_attr.dlid = port->xds_lid;
	(void)ib_query_port(xs_dev->device, port->port_num, &port_attr);
	ah_attr.sl = port_attr.sm_sl;
	ah_attr.port_num = port->port_num;

	port->send_buf->ah = ib_create_ah(port->mad_agent->qp->pd, &ah_attr);
	if (IS_ERR(port->send_buf->ah)) {
		ib_free_send_mad(port->send_buf);
		ret = PTR_ERR(port->send_buf->ah);
		IB_ERROR("ib_create_ah failed, error %d, GUID: 0x%llx\n",
			 ret, port->guid);
		return ret;
	}
	port->rec_poller_state = XDS_RECP_CREATEAH_DONE;

	port->send_buf->retries = 2;
	port->send_buf->timeout_ms = XSCORE_SA_QUERY_TIMEOUT;

	init_completion(&port->xds_query_done);

	ret = ib_post_send_mad(port->send_buf, NULL);
	if (ret) {
		IB_ERROR("ib_post_send_mad failed, error %d, GUID: 0x%llx\n",
			 ret, port->guid);
		ib_destroy_ah(port->send_buf->ah);
		ib_free_send_mad(port->send_buf);
		port->counters[PORT_XDS_XDS_QUERY_ERROR_COUNTER]++;
		port->send_buf = 0;
		return ret;
	}
	port->rec_poller_state = XDS_RECP_SENDMAD_DONE;
	if (!wait_for_completion_timeout(&port->xds_query_done,
					 msecs_to_jiffies
					 (XSCORE_SA_QUERY_TIMEOUT * 10))) {
		XDS_ERROR("%s: completion timeout, port: %d, GUID: 0x%llx\n:",
			  __func__, port->port_num, port->guid);
		port->counters[PORT_XDS_XDS_QUERY_TOUT_COUNTER]++;
		return -ETIMEDOUT;
	}
	mad_recv_wc = port->mad_recv_wc;
	if (!mad_recv_wc || mad_recv_wc->wc->status != IB_WC_SUCCESS) {
		if (mad_recv_wc)
			ret = mad_recv_wc->wc->status;
		else
			ret = -EINVAL;
	} else
		xds_check_xcm_record(port,
				     (struct ib_xds_mad *)mad_recv_wc->recv_buf.
				     mad);
	ib_free_recv_mad(port->mad_recv_wc);
	port->rec_poller_state = XDS_RECP_FREEMAD_DONE;
	port->mad_recv_wc = 0;
	return ret;
}

static int xs_send_xds_disc_msg(struct xscore_port *port)
{
	int ret;
	struct xdds_disc_req xd_msg;

	port->counters[PORT_XDS_XDS_QUERY_COUNTER]++;

	memset(&xd_msg, 0, sizeof(struct xdds_disc_req));
	xd_msg.xhdr.type = htons(XDP_MSG_TYPE_DISC_SOL);
	xd_msg.xhdr.flags = htons(XDP_FLAGS_REQ);
	xd_msg.xhdr.len = htons(sizeof(struct xdds_disc_req));

	create_xds_mad_req(port, &xd_msg.req);
	ret = xs_ud_send_msg(port, 0, &xd_msg, sizeof(xd_msg), XS_UD_COPY_MSG);
	if (ret) {
		XDDS_ERROR("xs_ud_send_msg: port GUID %llx failed, error %d\n",
			   port->guid, ret);
		port->counters[PORT_XDS_XDS_QUERY_ERROR_COUNTER]++;
	}
	return ret;
}

static void xcm_rec_poller(struct work_struct *work)
{
	struct xscore_port *port = container_of(work, struct xscore_port,
						poll_work.work);
	unsigned long flags;
	struct ib_port_attr port_attr;
	int ret = 0;

	xscore_set_wq_state(XSCORE_DWQ_POLL_WORK);
	port->rec_poller_state = XDS_RECP_START;
	xsmp_cleanup_stale_xsmp_sessions(port, 0);

	(void)ib_query_port(port->xs_dev->device, port->port_num, &port_attr);
	port->rec_poller_state = XDS_RECP_QUERY_IB_DONE;

	if (port_attr.state != IB_PORT_ACTIVE) {
		XDS_INFO("%s: Port %d, GUID: 0x%llx, Not Active\n",
			 __func__, port->port_num, port->guid);
		port->counters[PORT_XDS_PORT_NOT_ACTIVE_COUNTER]++;
	} else {
		if (port->link_layer == IB_LINK_LAYER_INFINIBAND) {
			ret = xscore_query_svc_record(port);
			if (!ret)
				ret = xscore_query_xds_xcm_rec(port);
		} else
			(void)xs_send_xds_disc_msg(port);
	}
	if (ret)
		port->poll_interval = msecs_to_jiffies(1000 * 10);
	else
		port->poll_interval = msecs_to_jiffies(1000 * 20);
	spin_lock_irqsave(&port->lock, flags);
	if (!test_bit(XSCORE_PORT_SHUTDOWN, &port->flags))
		queue_delayed_work(port->port_wq,
				   &port->poll_work, port->poll_interval);
	spin_unlock_irqrestore(&port->lock, flags);

	port->rec_poller_state = XDS_RECP_DONE;
	port->rec_poller_time = jiffies;
	xscore_clear_wq_state(XSCORE_DWQ_POLL_WORK);

}

static void xscore_destroy_port(struct xscore_port *port)
{
	IB_FUNCTION("%s: port %d\n", __func__, port->port_num);
	if (port->link_layer == IB_LINK_LAYER_INFINIBAND) {
		ib_unregister_mad_agent(port->mad_agent);
		port->mad_agent = 0;
	} else
		xs_ud_destroy(port);
}

/*
 * Convert GUID to MAC address by stripping out bytes 3 and 4  == FF0E
 * Reset bit 7 of byte 0 as per specification
 */
static void convert_guid_to_mac(u64 guid, u64 *mac)
{
	u64 t1;
	t1 = guid & 0x0000000000FFFFFFLL;
	guid >>= 16;
	t1 |= (guid & 0x0000FFFFFF000000LL);
	*mac = t1;
	*mac ^= (1ULL << 41);
}

/*
 * Initialize Query based on port information
 */
static int xscore_init_port(struct xscore_port *port)
{
	struct xscore_dev *xs_dev = port->xs_dev;
	struct ib_port_attr port_attr;
	int ret;

	IB_FUNCTION("%s\n", __func__);

	ret = ib_query_gid(xs_dev->device, port->port_num, 0, &port->sgid);
	if (ret) {
		IB_ERROR("xscore_init_port: ib_query_gid GUID 0x%llx %d\n",
			 port->guid, ret);
		return ret;
	}
	/*
	 * Get port attributes and check the type of the port
	 */
	ret = ib_query_port(xs_dev->device, port->port_num, &port_attr);
	if (ret) {
		IB_ERROR("xscore_init_port: ib_query_port GUID: 0x%llx, %d\n",
			 port->guid, ret);
		return ret;
	}
	port->link_layer = rdma_port_link_layer(xs_dev->device, port->port_num);
	port->guid = be64_to_cpu(port->sgid.global.interface_id);
	port->lid = port_attr.lid;
	port->sm_lid = port_attr.sm_lid;

	XDS_PRINT("Port Number: %d, ", port->port_num);
	XDS_PRINT("GUID: 0x%llx, ", port->guid);
	XDS_PRINT("LID: 0x%x, ", port->lid);
	XDS_PRINT("SM LID: 0x%x, ", port->sm_lid);
	XDS_PRINT("Mode: ");
	XDS_PRINT("%s\n",
		port->link_layer == IB_LINK_LAYER_INFINIBAND ? "IB" : "ETH");

	if (port->link_layer == IB_LINK_LAYER_INFINIBAND) {
		ret = xscore_init_mad_agent(port);
	} else {
		u64 mac;

		/*
		 * Convert to MAC only if valid GUID.
		 * In case of link down, GUID is zero
		 */
		if (port->guid) {
			convert_guid_to_mac(port->guid, &mac);
			port->guid = mac;
		}
		ret = xs_ud_create(port, xs_ud_callback, port);
	}
	return ret;
}

static void xscore_remove_port(struct xscore_port *port)
{
	/*
	 * Set a state bit to tell others we are going down
	 */
	IB_FUNCTION("%s: port %d\n", __func__, port->port_num);

	flush_workqueue(port->port_wq);
	destroy_workqueue(port->port_wq);
	port->port_wq = 0;
	xscore_destroy_port(port);
	list_del(&port->port_list);
	mutex_lock(&xscore_port_mutex);
	list_del(&port->gport_list);
	mutex_unlock(&xscore_port_mutex);
	xcpm_port_remove_proc_entry(port);
	kfree(port);
}

/*
 * Initialize a port context
 */
static struct xscore_port *xscore_add_port(struct xscore_dev *device,
					   u8 port_num)
{
	struct xscore_port *port;
	char name[32];
	int ret;

	IB_FUNCTION("%s: port %d\n", __func__, port_num);

	port = kzalloc(sizeof(*port), GFP_KERNEL);
	if (!port)
		return NULL;
	port->xs_dev = device;
	port->port_num = port_num;

	INIT_LIST_HEAD(&port->xsmp_list);
	spin_lock_init(&port->lock);

	INIT_WORK(&port->ework, xscore_port_event_handler);
	INIT_DELAYED_WORK(&port->poll_work, xcm_rec_poller);
	sprintf(name, "xs_wq:%d", port_num);
	port->port_wq = create_singlethread_workqueue(name);
	if (!port->port_wq)
		goto err_ret;

	ret = xscore_init_port(port);
	if (ret) {
		XDS_ERROR("xscore_init_port failed %d\n", ret);
		goto err_ret1;
	}

	if (port->guid)
		xcpm_port_add_proc_entry(port);
	/*
	 * Now start XCM record polling
	 */
	queue_delayed_work(port->port_wq,
			   &port->poll_work, port->poll_interval);

	return port;
err_ret1:
	destroy_workqueue(port->port_wq);
err_ret:
	kfree(port);
	return NULL;
}

static void xscore_port_event_handler(struct work_struct *work)
{
	struct xscore_port *port =
	    container_of(work, struct xscore_port, ework);
	struct ib_port_attr port_attr;
	int port_up;

	xscore_set_wq_state(XSCORE_WQ_PORT_EVENTH);
	if (port->link_layer == IB_LINK_LAYER_ETHERNET &&
	    test_bit(XSCORE_PORT_LID_CHANGE, &port->flags)) {
		u64 mac;

		clear_bit(XSCORE_PORT_LID_CHANGE, &port->flags);
		ib_query_gid(port->xs_dev->device, port->port_num, 0,
			     &port->sgid);
		port->guid = be64_to_cpu(port->sgid.global.interface_id);
		convert_guid_to_mac(port->guid, &mac);
		port->guid = mac;
		xcpm_port_add_proc_entry(port);
	}

	(void)ib_query_port(port->xs_dev->device, port->port_num, &port_attr);

	/*
	 * In the case of SM lid change update with new one
	 */
	if (xscore_notify_ulps
	    && (test_and_clear_bit(XSCORE_PORT_SMLID_CHANGE, &port->flags))) {
		pr_info("%s port%d SM Update ", __func__, port->port_num);
		pr_info(" [New %x old %x]\n", port_attr.sm_lid, port->sm_lid);
		port->sm_lid = port_attr.sm_lid;
	}

	/*
	 * We have seen the ACTIVE event come up, but port is still not ACTIVE
	 * Make it active if we get ACTIVE event and port is still not active
	 */
	if (port->pevent == IB_EVENT_PORT_ACTIVE
	    || port_attr.state == IB_PORT_ACTIVE) {
		pr_info("xscore: Port: %llx UP\n", port->guid);
		port_up = 1;
		port->lid = port_attr.lid;
		port->sm_lid = port_attr.sm_lid;
	} else {
		port_up = 0;
		pr_info("xscore: Port: %llx DOWN\n", port->guid);
	}
	xsmp_ulp_notify(port, port_up);
	xscore_clear_wq_state(XSCORE_WQ_PORT_EVENTH);
}

/*
 * IB stack event handler callback
 */
static void xscore_event_handler(struct ib_event_handler *handler,
				 struct ib_event *event)
{
	struct xscore_dev *xs_dev =
	    ib_get_client_data(event->device, &xscore_client);
	struct xscore_port *port;
	int port_num = event->element.port_num;

	if (!xs_dev || xs_dev->device != event->device)
		return;

	list_for_each_entry(port, &xs_dev->port_list, port_list) {
		if (port->port_num == port_num)
			goto found;
	}
	return;

found:
	port->pevent = event->event;

	switch (event->event) {
	case IB_EVENT_PORT_ERR:
	case IB_EVENT_PORT_ACTIVE:
		queue_work(port->port_wq, &port->ework);
		break;
	case IB_EVENT_LID_CHANGE:
		/*
		 * Used by IBOE
		 */
		set_bit(XSCORE_PORT_LID_CHANGE, &port->flags);
		queue_work(port->port_wq, &port->ework);
		break;
	case IB_EVENT_PKEY_CHANGE:
		break;
	case IB_EVENT_SM_CHANGE:
		if (xscore_notify_ulps) {
			set_bit(XSCORE_PORT_SMLID_CHANGE, &port->flags);
			queue_work(port->port_wq, &port->ework);
		}
		break;
	default:
		break;
	}
}

static const u64 min_fw_version = (2ULL << 32) | (7ULL << 16) | (0ULL << 0);

static int xscore_is_mlx4_fw_down_rev(u64 fw_ver)
{

	return (fw_ver < min_fw_version);
}

/*
 * This callback gets called ror every HCA in the system
 * This gets executed for the most part in the register call context
 */
static void xscore_add_one(struct ib_device *device)
{
	struct xscore_dev *xs_dev;
	struct ib_device_attr dev_attr;
	int p;
	struct xscore_port *port;

	IB_FUNCTION("%s: device: %s\n", __func__, device->name);

	if (ib_query_device(device, &dev_attr)) {
		IB_ERROR("Query device failed for %s\n", device->name);
		return;
	}

	/* See if this is some form of a Mellanox ConnectX card */
	if (strncmp(device->name, "mlx4", sizeof("mlx4") - 1) == 0) {
		if (xscore_is_mlx4_fw_down_rev(dev_attr.fw_ver)) {
			pr_info("Firmware on device \"%s\" (%d,%d,%d) is below",
			       device->name,
			       (int)((dev_attr.fw_ver >> 32) & 0xffff),
			       (int)((dev_attr.fw_ver >> 16) & 0xffff),
			       (int)(dev_attr.fw_ver & 0xffff));
			pr_info(" min needed to support ethernet transport");
			pr_info("Minimum firmware version is %d.%d.%d\n",
			       (int)((min_fw_version >> 32) & 0xffff),
			       (int)((min_fw_version >> 16) & 0xffff),
			       (int)(min_fw_version & 0xffff));
		}
	}

	xs_dev = kzalloc(sizeof(*xs_dev), GFP_KERNEL);
	if (!xs_dev)
		return;

	INIT_LIST_HEAD(&xs_dev->port_list);
	if (strstr(device->name, "xgc"))
		xs_dev->is_shca = 1;
	xs_dev->device = device;
	xs_dev->fw_ver = dev_attr.fw_ver;
	xs_dev->hw_ver = dev_attr.hw_ver;
	xs_dev->pd = ib_alloc_pd(device);
	if (IS_ERR(xs_dev->pd))
		goto free_dev;

	xs_dev->mr = ib_get_dma_mr(xs_dev->pd,
				   IB_ACCESS_LOCAL_WRITE |
				   IB_ACCESS_REMOTE_READ |
				   IB_ACCESS_REMOTE_WRITE);
	if (IS_ERR(xs_dev->mr))
		goto err_pd;

	for (p = 1; p <= device->phys_port_cnt; ++p) {
		port = xscore_add_port(xs_dev, p);
		if (port) {
			list_add_tail(&port->port_list, &xs_dev->port_list);
			mutex_lock(&xscore_port_mutex);
			list_add_tail(&port->gport_list, &xscore_port_list);
			mutex_unlock(&xscore_port_mutex);
		}
	}

	ib_set_client_data(device, &xscore_client, xs_dev);

	INIT_IB_EVENT_HANDLER(&xs_dev->event_handler, xs_dev->device,
			      xscore_event_handler);
	(void)ib_register_event_handler(&xs_dev->event_handler);

	return;

err_pd:
	ib_dealloc_pd(xs_dev->pd);
free_dev:
	kfree(xs_dev);
}

/*
 * Remove a HCA from the system, happens during driver unload when we unregister
 * from IB stack
 */
static void xscore_remove_one(struct ib_device *device)
{
	struct xscore_dev *xs_dev;
	struct xscore_port *port;
	struct xscore_port *tmp_port;
	unsigned long flags;

	IB_FUNCTION("%s: device: %s\n", __func__, device->name);

	xs_dev = ib_get_client_data(device, &xscore_client);
	ib_unregister_event_handler(&xs_dev->event_handler);
	/*
	 * Now go through the port list and shut down everything you can
	 */
	list_for_each_entry_safe(port, tmp_port,
	&xs_dev->port_list, port_list) {
		spin_lock_irqsave(&port->lock, flags);
		set_bit(XSCORE_PORT_SHUTDOWN, &port->flags);
		spin_unlock_irqrestore(&port->lock, flags);
		cancel_delayed_work(&port->poll_work);
		flush_workqueue(port->port_wq);
		cancel_delayed_work(&port->poll_work);
		xsmp_cleanup_stale_xsmp_sessions(port, 1);
		xscore_remove_port(port);
	}
	ib_dereg_mr(xs_dev->mr);
	ib_dealloc_pd(xs_dev->pd);
	kfree(xs_dev);
}

/*
 * Driver load entry point
 */
static int __init xscore_init(void)
{
	int ret;

	if (!hostname)
		strncpy(hostname_str, init_utsname()->nodename,
			XSIGO_MAX_HOSTNAME);
	else
		strncpy(hostname_str, hostname, XSIGO_MAX_HOSTNAME);
	hostname_str[XSIGO_MAX_HOSTNAME] = 0;

	system_id_str[0] = 0;
	if (system_id)
		strncpy(system_id_str, system_id, sizeof(system_id_str) - 1);
	system_id_str[sizeof(system_id_str) - 1] = 0;

	xg_vmk_kompat_init();

	INIT_LIST_HEAD(&xscore_port_list);
	mutex_init(&xscore_port_mutex);

	ret = xscore_create_procfs_entries();
	if (ret)
		return ret;

	xs_vpci_bus_init();

	xsmp_module_init();
	/*
	 * Now register with SA
	 */
	ib_sa_register_client(&xscore_sa_client);

	/*
	 * Now register with IB framework
	 */
	ret = ib_register_client(&xscore_client);
	if (ret) {
		IB_ERROR("couldn't register IB client\n");
		goto err1;
	}
	ret = xscore_uadm_init();
	if (ret)
		goto err2;
	/* Wait for Sessions to come up */
	xscore_wait_for_sessions(1);
	return ret;
err2:
	ib_unregister_client(&xscore_client);
err1:
	ib_sa_unregister_client(&xscore_sa_client);
	xsmp_module_destroy();
	xs_vpci_bus_remove();
	xscore_remove_procfs_entries();
	return ret;
}

/*
 * Driver unload entry point
 */
static void __exit xscore_exit(void)
{
	xscore_uadm_destroy();
	ib_unregister_client(&xscore_client);
	ib_sa_unregister_client(&xscore_sa_client);
	xsmp_module_destroy();
	xs_vpci_bus_remove();
	xscore_remove_procfs_entries();
	xg_vmk_kompat_cleanup();
}

module_init(xscore_init);
module_exit(xscore_exit);
