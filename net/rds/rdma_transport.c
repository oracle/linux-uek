/*
 * Copyright (c) 2009, 2020 Oracle and/or its affiliates.
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
#include <rdma/rdma_cm.h>
#include <rdma/rdma_cm_ib.h>

#include "rdma_transport.h"
#include "ib.h"
#include "rds_single_path.h"

#include <net/sock.h>
#include <net/inet_common.h>
#include <linux/version.h>

#include "trace.h"

#define RDS_REJ_CONSUMER_DEFINED 28

struct mutex cm_id_map_lock;
DEFINE_IDR(cm_id_map);
/* Global IPv4 and IPv6 RDS RDMA listener cm_id */
static struct rdma_cm_id *rds_rdma_listen_id;
#if IS_ENABLED(CONFIG_IPV6)
static struct rdma_cm_id *rds6_rdma_listen_id;
#endif

static int rds_rdma_resolve_to_ms[] = {1000, 1000, 2000, 4000, 5000};

static char *rds_cm_event_strings[] = {
#define RDS_CM_EVENT_STRING(foo) \
		[RDMA_CM_EVENT_##foo] = __stringify(RDMA_CM_EVENT_##foo)
	RDS_CM_EVENT_STRING(ADDR_RESOLVED),
	RDS_CM_EVENT_STRING(ADDR_ERROR),
	RDS_CM_EVENT_STRING(ROUTE_RESOLVED),
	RDS_CM_EVENT_STRING(ROUTE_ERROR),
	RDS_CM_EVENT_STRING(CONNECT_REQUEST),
	RDS_CM_EVENT_STRING(CONNECT_RESPONSE),
	RDS_CM_EVENT_STRING(CONNECT_ERROR),
	RDS_CM_EVENT_STRING(UNREACHABLE),
	RDS_CM_EVENT_STRING(REJECTED),
	RDS_CM_EVENT_STRING(ESTABLISHED),
	RDS_CM_EVENT_STRING(DISCONNECTED),
	RDS_CM_EVENT_STRING(DEVICE_REMOVAL),
	RDS_CM_EVENT_STRING(MULTICAST_JOIN),
	RDS_CM_EVENT_STRING(MULTICAST_ERROR),
	RDS_CM_EVENT_STRING(ADDR_CHANGE),
	RDS_CM_EVENT_STRING(TIMEWAIT_EXIT),
#undef RDS_CM_EVENT_STRING
};

static char *rds_cm_event_str(enum rdma_cm_event_type type)
{
	return rds_str_array(rds_cm_event_strings,
			     ARRAY_SIZE(rds_cm_event_strings), type);
};

/* Check if the RDMA device is OK to be used. */
static inline bool __rds_rdma_chk_dev(struct rds_connection *conn)
{
	struct rds_ib_connection *ic;

	ic = (struct rds_ib_connection *)conn->c_transport_data;
	/* If the rds_rdma module is unloading or the device is being removed,
	 * the device is not OK.
	 */
	if (ic->rds_ibdev && (ic->rds_ibdev->rid_mod_unload ||
			      ic->rds_ibdev->rid_dev_rem))
		return false;
	else
		return true;
}

static int rds_rdma_cm_event_handler_cmn(struct rdma_cm_id *cm_id,
					 struct rdma_cm_event *event,
					 bool isv6)
{
	/* this can be null in the listening path */
	struct rds_connection *conn;
	struct rds_transport *trans = &rds_ib_transport;
	int ret = 0;
	/* ADDR_CHANGE event indicates that the local address has moved
	 * to a different device, most likely due to failover/failback.
	 * If this is a local connection (a connection to this host), we need
	 * to flush the neighbor cache entry for the peer side of the
	 * connection. In this case we do not need to flush this side of the
	 * connection. If this is not a local connection, we still flush
	 * the neighbor cache for the local side of the connection.
	 */
	bool flush_local_peer = event->event == RDMA_CM_EVENT_ADDR_CHANGE;
	char *reason = NULL;
	int *err;

	conn = rds_ib_get_conn(cm_id);
	if (!conn) {
		if (event->event == RDMA_CM_EVENT_CONNECT_REQUEST) {
			trace_rds_rdma_cm_event_handler(NULL, NULL, NULL,
							NULL,
							rds_cm_event_str(event->event),
							0);
			ret = trans->cm_handle_connect(cm_id, event, isv6, false);
			if (ret)
				reason = "handle connect failed";
		} else {
			reason = "no conn found for event";
		}

		if (reason)
			trace_rds_rdma_cm_event_handler_err(NULL, NULL, NULL,
							    NULL, reason, ret);
		return ret;
	}

	/* Prevent shutdown from tearing down the connection
	 * while we're executing. */
	mutex_lock(&conn->c_cm_lock);

	trace_rds_rdma_cm_event_handler(NULL, NULL, conn,
					conn->c_npaths > 0 ?
					conn->c_transport_data : NULL,
					rds_cm_event_str(event->event), 0);

	/* If the connection is being shut down, bail out
	 * right away. We return 0 so cm_id doesn't get
	 * destroyed prematurely.
	 *
	 * Events RDMA_CM_EVENT_ADDR_CHANGE and RDMA_CM_EVENT_DISCONNECTED
	 * need to be processed regardless of the connection state
	 * as they flush the ARP cache as well as invalidate the
	 * pending inbound connection (RDS_CONN_PATH_RESET_ALT_CONN).
	 * 
	 * Also event RDMA_CM_EVENT_CONNECT_REQUEST needs to be processed,
	 * because we want to figure out if we want to yield to that incoming connection,
	 * also regardless of what state the outbound connection is in.
	 */
	if ((rds_conn_state(conn) == RDS_CONN_DISCONNECTING ||
	     rds_conn_state(conn) == RDS_CONN_ERROR) &&
	    event->event != RDMA_CM_EVENT_ADDR_CHANGE &&
	    event->event != RDMA_CM_EVENT_DISCONNECTED &&
	    event->event != RDMA_CM_EVENT_CONNECT_REQUEST) {
		reason = "reject incoming connections during teardown";
		goto out;
	}

	/* If the device used by this conn is not OK, no need to process this
	 * event and the device removal/module clean up code will handle it.
	 */
	if (!__rds_rdma_chk_dev(conn)) {
		reason = "event ignored, device not OK";
		goto out;
	}

	switch (event->event) {
		struct rds_ib_connection *ibic;
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		if (conn->c_path)
			conn->c_path->cp_conn_start_jf = 0;
		ret = trans->cm_handle_connect(cm_id, event, isv6, true);
		if (ret)
			reason = "handle connect failed";
		break;

	case RDMA_CM_EVENT_ADDR_RESOLVED:
		rdma_set_service_type(cm_id, conn->c_tos);
		if (rds_ib_sysctl_local_ack_timeout &&
		    rdma_port_get_link_layer(cm_id->device, cm_id->port_num) == IB_LINK_LAYER_ETHERNET)
			rdma_set_ack_timeout(cm_id, rds_ib_sysctl_local_ack_timeout);

		/* XXX do we need to clean up if this fails? */
		ret = rdma_resolve_route(cm_id,
				rds_rdma_resolve_to_ms[conn->c_to_index]);
		if (ret) {
			/*
			 * The cm_id will get destroyed by addr_handler
			 * in RDMA CM when we return from here.
			 */
			reason = "resolve route failed";
			ibic = conn->c_transport_data;
			if (rds_ib_same_cm_id(ibic, cm_id))
				ibic->i_cm_id = NULL;
			rds_conn_drop(conn, DR_IB_RESOLVE_ROUTE_FAIL, ret);
		} else if (conn->c_to_index < (RDS_RDMA_RESOLVE_TO_MAX_INDEX-1))
				conn->c_to_index++;
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		/* XXX worry about racing with listen acceptance */
		conn->c_to_index = 0;

		/* Connection could have been dropped so make sure the
		 * cm_id is valid before proceeding */

		ibic = conn->c_transport_data;
		if (rds_ib_same_cm_id(ibic, cm_id)) {
			/* ibacm caches the path record without considering the tos/sl.
			 * It is considered a match if the <src,dest> matches the
			 * cache. In order to create qp with the correct sl/vl, RDS
			 * needs to update the sl manually. As for now, RDS is assuming
			 * that it is a 1:1 in tos to sl mapping.
			 */
			cm_id->route.path_rec[0].sl = TOS_TO_SL(conn->c_tos);
			cm_id->route.path_rec[0].qos_class = conn->c_tos;
			ret = trans->cm_initiate_connect(cm_id, isv6);
			if (ret)
				reason = "initiate connect failed";
		} else {
			rds_conn_drop(conn, DR_IB_RDMA_CM_ID_MISMATCH, 0);
		}
		break;

	case RDMA_CM_EVENT_ROUTE_ERROR:
		/* IP might have been moved so flush the ARP entry and retry */
		rds_ib_flush_neigh(&init_net, conn, flush_local_peer, false);

		rds_conn_drop(conn, DR_IB_ROUTE_ERR, 0);
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		trans->cm_connect_complete(conn, event);
		break;

	case RDMA_CM_EVENT_ADDR_ERROR:
		/* IP might have been moved so flush the ARP entry and retry */
		rds_ib_flush_neigh(&init_net, conn, flush_local_peer, false);

		rds_conn_drop(conn, DR_IB_ADDR_ERR, 0);
		break;

	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		/* IP might have been moved so flush the ARP entry and retry */
		rds_ib_flush_neigh(&init_net, conn, flush_local_peer, false);

		rds_conn_drop(conn, DR_IB_CONNECT_ERR, 0);
		break;

	case RDMA_CM_EVENT_REJECTED:
		/* May be due to ARP cache containing an incorrect dmac, hence flush it */
		rds_ib_flush_neigh(&init_net, conn, flush_local_peer, false);

		err = (int *)event->param.conn.private_data;

		if (event->status == RDS_REJ_CONSUMER_DEFINED && (*err) == 0) {
			/* Rejection from RDSV3.1 */
			pr_warn("Rejected: CSR_DEF err 0, calling rds_conn_drop <%pI6c,%pI6c,%d>\n",
				&conn->c_laddr,
				&conn->c_faddr, conn->c_tos);
			if (!conn->c_tos)
				conn->c_proposed_version =
					RDS_PROTOCOL_COMPAT_VERSION;
			rds_conn_drop(conn,
				      DR_IB_CONSUMER_DEFINED_REJ, *err);
			reason = "rejection from RDS";
		} else if (event->status == RDS_REJ_CONSUMER_DEFINED &&
			   (*err) == RDS_ACL_FAILURE) {
			/* Rejection due to ACL violation */
			pr_err("RDS: IB: conn %p <%pI6c,%pI6c,%d> destroyed due to ACL violation\n",
			       conn, &conn->c_laddr, &conn->c_faddr, conn->c_tos);

			reason = "ACL violation";
			rds_ib_conn_destroy_init(conn);
		} else {
			rds_conn_drop(conn, DR_IB_REJECTED_EVENT, *err);
			reason = "connection rejected";
		}
		break;

	case RDMA_CM_EVENT_ADDR_CHANGE:
		/* IP might have been moved so flush the ARP entry and retry */
		rds_ib_flush_neigh(&init_net, conn, flush_local_peer, true);

		rds_conn_drop(conn, DR_IB_ADDR_CHANGE, 0);
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		/* IP might have been moved so flush the ARP entry and retry */
		rds_ib_flush_neigh(&init_net, conn, flush_local_peer, false);

		if (!rds_conn_self_loopback_passive(conn))
			rds_conn_drop(conn, DR_IB_DISCONNECTED_EVENT, 0);
		break;

	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		rds_conn_drop(conn, DR_IB_TIMEWAIT_EXIT, 0);
		break;

	default:
		/* things like device disconnect? */
		pr_err("RDS: unknown event %u (%s)!\n", event->event,
		       rds_cm_event_str(event->event));
		reason = "unknown event";
		break;
	}

out:
	if (reason)
		trace_rds_rdma_cm_event_handler_err(NULL, NULL, conn, NULL,
						    reason, ret);
	mutex_unlock(&conn->c_cm_lock);

	return ret;
}

int rds_rdma_cm_event_handler(struct rdma_cm_id *cm_id,
			      struct rdma_cm_event *event)
{
	return rds_rdma_cm_event_handler_cmn(cm_id, event, false);
}

#if IS_ENABLED(CONFIG_IPV6)
int rds6_rdma_cm_event_handler(struct rdma_cm_id *cm_id,
			       struct rdma_cm_event *event)
{
	return rds_rdma_cm_event_handler_cmn(cm_id, event, true);
}
#endif

static int rds_rdma_listen_init_common(rdma_cm_event_handler handler,
				       struct sockaddr *sa,
				       struct rdma_cm_id **ret_cm_id)
{
	struct rds_ib_connection *dummy_ic;
	struct rdma_cm_id *cm_id;
	int ret;

	dummy_ic = kmalloc(sizeof(*dummy_ic), GFP_KERNEL);
	if (!dummy_ic)
		return -ENOMEM;

	cm_id = rds_ib_rdma_create_id(&init_net, handler, dummy_ic, NULL, RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(cm_id)) {
		ret = PTR_ERR(cm_id);
		printk(KERN_ERR "RDS/RDMA: failed to setup listener, rds_ib_rdma_create_id() returned %d\n",
		       ret);
		return ret;
	}

	/* XXX I bet this binds the cm_id to a device.  If we want to support
	 * fail-over we'll have to take this into consideration.
	 */
	ret = rdma_bind_addr(cm_id, sa);
	if (ret) {
		printk(KERN_ERR "RDS/RDMA: failed to setup listener, rdma_bind_addr() returned %d\n",
		       ret);
		goto out;
	}

	ret = rdma_listen(cm_id, 128);
	if (ret) {
		printk(KERN_ERR "RDS/RDMA: failed to setup listener, rdma_listen() returned %d\n",
		       ret);
		goto out;
	}

	rdsdebug("cm %p listening on port %u\n", cm_id,
		 sa->sa_family == PF_INET ?
		 ntohs(((struct sockaddr_in *)sa)->sin_port) :
		 ntohs(((struct sockaddr_in6 *)sa)->sin6_port));

	*ret_cm_id = cm_id;
	cm_id = NULL;
out:
	if (cm_id)
		rds_ib_rdma_destroy_id(cm_id);
	return ret;
}

/* Initialize the RDS RDMA listeners.  We create two listeners for
 * compatibility reason.  The one on RDS_PORT is used for IPv4
 * requests only.  The one on RDS_CM_PORT is used for IPv6 requests
 * only.  So only IPv6 enabled RDS module will communicate using this
 * port.
 */
static int rds_rdma_listen_init(void)
{
	int ret;
#if IS_ENABLED(CONFIG_IPV6)
	struct sockaddr_in6 sin6;
#endif
	struct sockaddr_in sin;

	sin.sin_family = PF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(RDS_PORT);
	ret = rds_rdma_listen_init_common(rds_rdma_cm_event_handler,
					  (struct sockaddr *)&sin,
					  &rds_rdma_listen_id);
	if (ret)
		return ret;

#if IS_ENABLED(CONFIG_IPV6)
	sin6.sin6_family = PF_INET6;
	sin6.sin6_addr = in6addr_any;
	sin6.sin6_port = htons(RDS_CM_PORT);
	sin6.sin6_scope_id = 0;
	sin6.sin6_flowinfo = 0;
	ret = rds_rdma_listen_init_common(rds6_rdma_cm_event_handler,
					  (struct sockaddr *)&sin6,
					  &rds6_rdma_listen_id);
	/* Keep going even when IPv6 is not enabled in the system. */
	if (ret)
		rdsdebug("Cannot set up IPv6 RDMA listener\n");
#endif
	return 0;
}

static void rds_rdma_listen_stop(void)
{
	struct rds_ib_connection *ic;
	struct rds_connection *conn;

	if (rds_rdma_listen_id) {
		conn = rds_ib_get_conn(rds_rdma_listen_id);
		ic = conn ? conn->c_transport_data : NULL;
		rdsdebug("cm %p\n", rds_rdma_listen_id);
		rds_ib_rdma_destroy_id(rds_rdma_listen_id);
		rds_rdma_listen_id = NULL;
		kfree(ic);
	}
#if IS_ENABLED(CONFIG_IPV6)
	if (rds6_rdma_listen_id) {
		conn = rds_ib_get_conn(rds6_rdma_listen_id);
		ic = conn ? conn->c_transport_data : NULL;
		rdsdebug("cm %p\n", rds6_rdma_listen_id);
		rds_ib_rdma_destroy_id(rds6_rdma_listen_id);
		rds6_rdma_listen_id = NULL;
		kfree(ic);
	}
#endif
}

#define MODULE_NAME "rds_rdma"

int __init rds_rdma_init(void)
{
	int ret;

	rds_rt_debug_tp_enable();

	mutex_init(&cm_id_map_lock);

	ret = rds_ib_init();
	if (ret)
		goto out;

	ret = rds_rdma_listen_init();
	if (ret)
		goto err_rdma_listen_init;

	goto out;

err_rdma_listen_init:
	/* We need to clean up both ib components. */
	rds_ib_exit();
out:
	/* Either nothing is done successfully or everything succeeds at
	 * this point.
	 */
	return ret;
}
module_init(rds_rdma_init);

void __exit rds_rdma_exit(void)
{
	/* Stop listening first to ensure no new connections are attempted.
	 * But there can be still connection requests waiting to be processed.
	 */
	rds_rdma_listen_stop();
	rds_ib_exit();
}
module_exit(rds_rdma_exit);

MODULE_AUTHOR("Oracle Corporation <rds-devel@oss.oracle.com>");
MODULE_DESCRIPTION("RDS: IB transport");
MODULE_LICENSE("Dual BSD/GPL");

