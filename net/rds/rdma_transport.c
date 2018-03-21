/*
 * Copyright (c) 2009, 2017 Oracle and/or its affiliates. All rights reserved.
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
#include "net/arp.h"
#include "rds_single_path.h"

#include <net/sock.h>
#include <net/inet_common.h>
#include <linux/version.h>

#define RDS_REJ_CONSUMER_DEFINED 28

/* Global IPv4 and IPv6 RDS RDMA listener cm_id */
static struct rdma_cm_id *rds_rdma_listen_id;
static struct rdma_cm_id *rds6_rdma_listen_id;

int unload_allowed __initdata;

module_param_named(module_unload_allowed, unload_allowed, int, 0);
MODULE_PARM_DESC(module_unload_allowed, "Allow this module to be unloaded or not (default 0 for NO)");

int rds_rdma_resolve_to_ms[] = {1000, 1000, 2000, 4000, 5000};

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

int rds_rdma_cm_event_handler_cmn(struct rdma_cm_id *cm_id,
				  struct rdma_cm_event *event,
				  bool isv6)
{
	/* this can be null in the listening path */
	struct rds_connection *conn = cm_id->context;
	struct rds_transport *trans = &rds_ib_transport;
	struct page *page;
	struct arpreq *r;
	struct sockaddr_in *sin;
	int ret = 0;
	int *err;

	rdsdebug("conn %p id %p handling event %u (%s)\n", conn, cm_id,
		 event->event, rds_cm_event_str(event->event));

	/* Prevent shutdown from tearing down the connection
	 * while we're executing. */
	if (conn) {
		mutex_lock(&conn->c_cm_lock);
		/* If the connection is being shut down, bail out
		 * right away. We return 0 so cm_id doesn't get
		 * destroyed prematurely */
		if (rds_conn_state(conn) == RDS_CONN_DISCONNECTING) {
			/* Reject incoming connections while we're tearing
			 * down an existing one. */
			if (event->event == RDMA_CM_EVENT_CONNECT_REQUEST)
				ret = 1;
			goto out;
		}
	}

	switch (event->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		ret = trans->cm_handle_connect(cm_id, event, isv6);
		break;

	case RDMA_CM_EVENT_ADDR_RESOLVED:
		rdma_set_service_type(cm_id, conn->c_tos);

		/* XXX do we need to clean up if this fails? */
		ret = rdma_resolve_route(cm_id,
				rds_rdma_resolve_to_ms[conn->c_to_index]);
		if (ret) {
			/*
			 * The cm_id will get destroyed by addr_handler
			 * in RDMA CM when we return from here.
			 */
			if (conn) {
				struct rds_ib_connection *ibic;

				printk(KERN_CRIT "rds dropping connection after rdma_resolve_route failure connection %pI6c->%pI6c\n",
				       &conn->c_laddr, &conn->c_faddr);
				ibic = conn->c_transport_data;
				if (ibic && ibic->i_cm_id == cm_id)
					ibic->i_cm_id = NULL;
				rds_conn_drop(conn, DR_IB_RESOLVE_ROUTE_FAIL);
			}
		} else if (conn->c_to_index < (RDS_RDMA_RESOLVE_TO_MAX_INDEX-1))
				conn->c_to_index++;
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		/* XXX worry about racing with listen acceptance */
		conn->c_to_index = 0;

		/* Connection could have been dropped so make sure the
		 * cm_id is valid before proceeding */
		if (conn) {
			struct rds_ib_connection *ibic;

			ibic = conn->c_transport_data;
			if (ibic && ibic->i_cm_id == cm_id) {
				/* ibacm caches the path record without considering the tos/sl.
				 * It is considered a match if the <src,dest> matches the
				 * cache. In order to create qp with the correct sl/vl, RDS
				 * needs to update the sl manually. As for now, RDS is assuming
				 * that it is a 1:1 in tos to sl mapping.
				 */
				cm_id->route.path_rec[0].sl = TOS_TO_SL(conn->c_tos);
				cm_id->route.path_rec[0].qos_class = conn->c_tos;
				ret = trans->cm_initiate_connect(cm_id, isv6);
			} else {
				rds_rtd(RDS_RTD_CM,
					"ROUTE_RESOLVED: calling rds_conn_drop, conn %p <%pI6c,%pI6c,%d>\n",
					conn, &conn->c_laddr,
					&conn->c_faddr, conn->c_tos);
				rds_conn_drop(conn, DR_IB_RDMA_CM_ID_MISMATCH);
			}
		}
		break;

	case RDMA_CM_EVENT_ROUTE_ERROR:
		/* IP might have been moved so flush the ARP entry and retry */
		page = alloc_page(GFP_HIGHUSER);
		if (!page) {
			printk(KERN_ERR "alloc_page failed .. NO MEM\n");
			ret = -ENOMEM;
		} else {
			if (ipv6_addr_v4mapped(&conn->c_faddr)) {
				r = (struct arpreq *)kmap(page);
				memset(r, 0, sizeof(struct arpreq));
				sin = (struct sockaddr_in *)&r->arp_pa;
				sin->sin_family = AF_INET;
				sin->sin_addr.s_addr =
				    conn->c_faddr.s6_addr32[3];
				inet_ioctl(rds_ib_inet_socket, SIOCDARP,
					   (unsigned long)r);
				kunmap(page);
				__free_page(page);
			}
		}

		if (conn) {
			rds_rtd(RDS_RTD_ERR,
				"ROUTE_ERROR: conn %p, calling rds_conn_drop <%pI6c,%pI6c,%d>\n",
				conn, &conn->c_laddr,
				&conn->c_faddr, conn->c_tos);
			rds_conn_drop(conn, DR_IB_ROUTE_ERR);
		}
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		trans->cm_connect_complete(conn, event);
		break;

	case RDMA_CM_EVENT_ADDR_ERROR:
		if (conn) {
			rds_rtd(RDS_RTD_ERR,
				"ADDR_ERROR: conn %p, calling rds_conn_drop <%pI6c,%pI6c,%d>\n",
				conn, &conn->c_laddr,
				&conn->c_faddr, conn->c_tos);
			rds_conn_drop(conn, DR_IB_ADDR_ERR);
		}
		break;

	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		if (conn) {
			rds_rtd(RDS_RTD_ERR,
				"CONN/UNREACHABLE/RMVAL ERR: conn %p, calling rds_conn_drop <%pI6c,%pI6c,%d>\n",
				conn, &conn->c_laddr,
				&conn->c_faddr, conn->c_tos);
			rds_conn_drop(conn, DR_IB_CONNECT_ERR);
		}
		break;

	case RDMA_CM_EVENT_REJECTED:
		err = (int *)event->param.conn.private_data;

		if (conn) {
			if (event->status == RDS_REJ_CONSUMER_DEFINED &&
			    (*err) == 0) {
				/* Rejection from RDSV3.1 */
				pr_warn("Rejected: CSR_DEF err 0, calling rds_conn_drop <%pI6c,%pI6c,%d>\n",
					&conn->c_laddr,
					&conn->c_faddr, conn->c_tos);
				if (!conn->c_tos)
					conn->c_proposed_version =
						RDS_PROTOCOL_COMPAT_VERSION;
				rds_conn_drop(conn,
					DR_IB_CONSUMER_DEFINED_REJ);
			} else if (event->status == RDS_REJ_CONSUMER_DEFINED &&
				   (*err) == RDS_ACL_FAILURE) {
				/* Rejection due to ACL violation */
				pr_err("RDS: IB: conn=%p, <%pI6c,%pI6c,%d> destroyed due to ACL violation\n",
				       conn, &conn->c_laddr,
				       &conn->c_faddr,
				       conn->c_tos);
				rds_ib_conn_destroy_init(conn);
			} else {
				rds_rtd(RDS_RTD_ERR,
					"Rejected: *err %d status %d calling rds_conn_drop <%pI6c,%pI6c,%d>\n",
					*err, event->status,
					&conn->c_laddr,
					&conn->c_faddr,
					conn->c_tos);
				rds_conn_drop(conn, DR_IB_REJECTED_EVENT);
			}
		}
		break;

	case RDMA_CM_EVENT_ADDR_CHANGE:
		rds_rtd(RDS_RTD_CM_EXT,
			"ADDR_CHANGE event <%pI6c,%pI6c>\n",
			&conn->c_laddr,
			&conn->c_faddr);
		if (conn) {
			rds_rtd(RDS_RTD_CM,
				"ADDR_CHANGE: calling rds_conn_drop <%pI6c,%pI6c,%d>\n",
				&conn->c_laddr, &conn->c_faddr,
				conn->c_tos);
			if (!rds_conn_self_loopback_passive(conn)) {
				queue_delayed_work(conn->c_path[0].cp_wq,
						   &conn->c_reconn_w,
						   msecs_to_jiffies(conn->c_reconnect_retry));
				rds_conn_drop(conn, DR_IB_ADDR_CHANGE);
			}
		}
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		rds_rtd(RDS_RTD_CM,
			"DISCONNECT event - dropping connection %pI6c->%pI6c tos %d\n",
			&conn->c_laddr, &conn->c_faddr,	conn->c_tos);
		rds_conn_drop(conn, DR_IB_DISCONNECTED_EVENT);
		break;

	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		if (conn) {
			printk(KERN_INFO "TIMEWAIT_EXIT event - dropping connection %pI6c->%pI6c\n",
			       &conn->c_laddr, &conn->c_faddr);
			rds_conn_drop(conn, DR_IB_TIMEWAIT_EXIT);
		} else
			printk(KERN_INFO "TIMEWAIT_EXIT event - conn=NULL\n");
		break;

	default:
		/* things like device disconnect? */
		pr_err("RDS: unknown event %u (%s)!\n", event->event,
		       rds_cm_event_str(event->event));
		break;
	}

out:
	if (conn)
		mutex_unlock(&conn->c_cm_lock);

	rdsdebug("id %p event %u (%s) handling ret %d\n", cm_id, event->event,
		 rds_cm_event_str(event->event), ret);

	return ret;
}

int rds_rdma_cm_event_handler(struct rdma_cm_id *cm_id,
			      struct rdma_cm_event *event)
{
	return rds_rdma_cm_event_handler_cmn(cm_id, event, false);
}

int rds6_rdma_cm_event_handler(struct rdma_cm_id *cm_id,
			       struct rdma_cm_event *event)
{
	return rds_rdma_cm_event_handler_cmn(cm_id, event, true);
}

static int rds_rdma_listen_init_common(rdma_cm_event_handler handler,
				       struct sockaddr *sa,
				       struct rdma_cm_id **ret_cm_id)
{
	struct rdma_cm_id *cm_id;
	int ret;

	cm_id = rdma_create_id(&init_net, handler, NULL, RDMA_PS_TCP, IB_QPT_RC);
	if (IS_ERR(cm_id)) {
		ret = PTR_ERR(cm_id);
		printk(KERN_ERR "RDS/RDMA: failed to setup listener, rdma_create_id() returned %d\n",
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
		rdma_destroy_id(cm_id);
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
	struct sockaddr_in6 sin6;
	struct sockaddr_in sin;

	sin.sin_family = PF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(RDS_PORT);
	ret = rds_rdma_listen_init_common(rds_rdma_cm_event_handler,
					  (struct sockaddr *)&sin,
					  &rds_rdma_listen_id);
	if (ret)
		return ret;

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
	return 0;
}

static void rds_rdma_listen_stop(void)
{
	if (rds_rdma_listen_id) {
		rdsdebug("cm %p\n", rds_rdma_listen_id);
		rdma_destroy_id(rds_rdma_listen_id);
		rds_rdma_listen_id = NULL;
	}
	if (rds6_rdma_listen_id) {
		rdsdebug("cm %p\n", rds6_rdma_listen_id);
		rdma_destroy_id(rds6_rdma_listen_id);
		rds6_rdma_listen_id = NULL;
	}
}

#define MODULE_NAME "rds_rdma"

int __init rds_rdma_init(void)
{
	int ret;

	ret = rds_ib_init();
	if (ret)
		goto out;

	ret = rds_rdma_listen_init();
	if (ret)
		goto err_rdma_listen_init;

	if (!unload_allowed) {
		printk(KERN_NOTICE "Module %s locked in memory until next boot\n",
		       MODULE_NAME);
		__module_get(THIS_MODULE);
	}

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
	/* stop listening first to ensure no new connections are attempted */
	rds_rdma_listen_stop();
	rds_ib_exit();
}
module_exit(rds_rdma_exit);

MODULE_AUTHOR("Oracle Corporation <rds-devel@oss.oracle.com>");
MODULE_DESCRIPTION("RDS: IB transport");
MODULE_LICENSE("Dual BSD/GPL");

