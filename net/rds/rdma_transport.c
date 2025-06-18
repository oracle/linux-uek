/*
 * Copyright (c) 2009 Oracle.  All rights reserved.
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
#include "tcp.h"

#include <net/sock.h>
#include <net/inet_common.h>
#include <linux/version.h>

#define RDS_REJ_CONSUMER_DEFINED 28

static struct rdma_cm_id *rds_listen_id;

int unload_allowed __read_mostly;

module_param_named(module_unload_allowed, unload_allowed, int, 0444);
MODULE_PARM_DESC(module_unload_allowed, "Allow this module to be unloaded or not (default 0 for NO)");

int rds_rdma_resolve_to_ms[] = {1000, 1000, 2000, 4000, 5000};

int rds_rdma_cm_event_handler(struct rdma_cm_id *cm_id,
			      struct rdma_cm_event *event)
{
	/* this can be null in the listening path */
	struct rds_connection *conn = cm_id->context;
	struct rds_transport *trans = &rds_ib_transport;
	struct page *page;
	struct arpreq *r;
	struct sockaddr_in *sin;
	int ret = 0;
	int *err;

	rdsdebug("conn %p id %p handling event %u\n", conn, cm_id,
		 event->event);

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
		ret = trans->cm_handle_connect(cm_id, event);
		break;

	case RDMA_CM_EVENT_ADDR_RESOLVED:
		rdma_set_service_type(cm_id, conn->c_tos);

#if RDMA_RDS_APM_SUPPORTED
		if (rds_ib_apm_enabled)
			rdma_set_timeout(cm_id, rds_ib_apm_timeout);
#endif

		if (conn->c_tos && conn->c_reconnect) {
			struct rds_ib_connection *base_ic =
				conn->c_base_conn->c_transport_data;

			mutex_lock(&conn->c_base_conn->c_cm_lock);
			if (rds_conn_transition(conn->c_base_conn, RDS_CONN_UP,
						RDS_CONN_UP)) {
				ret = rdma_set_ib_paths(cm_id,
					base_ic->i_cm_id->route.path_rec,
					base_ic->i_cm_id->route.num_paths);
				if (!ret) {
					struct rds_ib_connection *ic =
						conn->c_transport_data;

					cm_id->route.path_rec[0].sl =
						ic->i_sl;
					cm_id->route.path_rec[0].qos_class =
						conn->c_tos;
					ret = trans->cm_initiate_connect(cm_id);
				}
			} else {
				ret = 1;
			}
			mutex_unlock(&conn->c_base_conn->c_cm_lock);

			if (ret) {
				rds_conn_drop(conn);
				ret = 0;
			}

			break;
		}


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

				printk(KERN_CRIT "rds dropping connection after rdma_resolve_route failure"
				       "connection %pI4->%pI4\n", &conn->c_laddr, &conn->c_faddr);
				ibic = conn->c_transport_data;
				if (ibic && ibic->i_cm_id == cm_id)
					ibic->i_cm_id = NULL;
				rds_conn_drop(conn);
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
			if (ibic && ibic->i_cm_id == cm_id)
				ret = trans->cm_initiate_connect(cm_id);
			else
				rds_conn_drop(conn);
		}
		break;

#if RDMA_RDS_APM_SUPPORTED
	case RDMA_CM_EVENT_ALT_PATH_LOADED:
		rdsdebug("RDS: alt path loaded\n");
		if (conn)
			trans->check_migration(conn, event);
		break;

	case RDMA_CM_EVENT_ALT_ROUTE_RESOLVED:
		rdsdebug("RDS: alt route resolved\n");
		break;

	case RDMA_CM_EVENT_ALT_ROUTE_ERROR:
		rdsdebug("RDS: alt route resolve error\n");
		break;
#endif

	case RDMA_CM_EVENT_ROUTE_ERROR:
		/* IP might have been moved so flush the ARP entry and retry */
		page = alloc_page(GFP_HIGHUSER);
		if (!page) {
			printk(KERN_ERR "alloc_page failed .. NO MEM\n");
			ret = -ENOMEM;
		} else {
			r = (struct arpreq *)kmap(page);
			memset(r, 0, sizeof(struct arpreq));
			sin = (struct sockaddr_in *)&r->arp_pa;
			sin->sin_family = AF_INET;
			sin->sin_addr.s_addr = conn->c_faddr;
			inet_ioctl(rds_ib_inet_socket, SIOCDARP, (unsigned long) r);
			kunmap(page);
			__free_page(page);
		}

		rds_conn_drop(conn);
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		trans->cm_connect_complete(conn, event);
		break;

	case RDMA_CM_EVENT_ADDR_ERROR:
		if (conn)
			rds_conn_drop(conn);
		break;

	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		if (conn)
			rds_conn_drop(conn);
		break;

	case RDMA_CM_EVENT_REJECTED:
		err = (int *)event->param.conn.private_data;

		if (conn && event->status == RDS_REJ_CONSUMER_DEFINED &&
		    *err <= 1)
			conn->c_reconnect_racing++;

		if (conn) {
			if (event->status == RDS_REJ_CONSUMER_DEFINED &&
			    (*err) == 0) {
				/* Rejection from RDSV3.1 */
				if (!conn->c_tos) {
					conn->c_proposed_version =
						RDS_PROTOCOL_COMPAT_VERSION;
					rds_conn_drop(conn);
				} else  {
					if (conn->c_loopback)
						queue_delayed_work(rds_local_wq,
							&conn->c_reject_w,
							msecs_to_jiffies(10));
					else
						queue_delayed_work(rds_wq,
							&conn->c_reject_w,
							msecs_to_jiffies(10));
				}
			} else
				rds_conn_drop(conn);
		}
		break;

	case RDMA_CM_EVENT_ADDR_CHANGE:
		rdsdebug("ADDR_CHANGE event <%pI4,%pI4>\n",
			 &conn->c_laddr, &conn->c_faddr);
#if RDMA_RDS_APM_SUPPORTED
		if (conn && !rds_ib_apm_enabled)
			rds_conn_drop(conn);
#else
		if (conn)
			rds_conn_drop(conn);
#endif
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		rdsdebug("DISCONNECT event - dropping connection "
			"%pI4->%pI4\n", &conn->c_laddr,
			 &conn->c_faddr);
		rds_conn_drop(conn);
		break;

	default:
		/* things like device disconnect? */
		printk(KERN_ERR "RDS: unknown event %u!\n", event->event);
		break;
	}

out:
	if (conn)
		mutex_unlock(&conn->c_cm_lock);

	rdsdebug("id %p event %u handling ret %d\n", cm_id, event->event, ret);

	return ret;
}

static int rds_rdma_listen_init(void)
{
	struct sockaddr_in sin;
	struct rdma_cm_id *cm_id;
	int ret;

	cm_id = rdma_create_id(&init_net, rds_rdma_cm_event_handler, NULL, RDMA_PS_TCP,
			       IB_QPT_RC);
	if (IS_ERR(cm_id)) {
		ret = PTR_ERR(cm_id);
		printk(KERN_ERR "RDS/RDMA: failed to setup listener, "
		       "rdma_create_id() returned %d\n", ret);
		return ret;
	}

	sin.sin_family = PF_INET,
	sin.sin_addr.s_addr = (__force u32)htonl(INADDR_ANY);
	sin.sin_port = (__force u16)htons(RDS_PORT);

	/*
	 * XXX I bet this binds the cm_id to a device.  If we want to support
	 * fail-over we'll have to take this into consideration.
	 */
	ret = rdma_bind_addr(cm_id, (struct sockaddr *)&sin);
	if (ret) {
		printk(KERN_ERR "RDS/RDMA: failed to setup listener, "
		       "rdma_bind_addr() returned %d\n", ret);
		goto out;
	}

	ret = rdma_listen(cm_id, 128);
	if (ret) {
		printk(KERN_ERR "RDS/RDMA: failed to setup listener, "
		       "rdma_listen() returned %d\n", ret);
		goto out;
	}

	rdsdebug("cm %p listening on port %u\n", cm_id, RDS_PORT);

	rds_listen_id = cm_id;
	cm_id = NULL;
out:
	if (cm_id)
		rdma_destroy_id(cm_id);
	return ret;
}

static void rds_rdma_listen_stop(void)
{
	if (rds_listen_id) {
		rdsdebug("cm %p\n", rds_listen_id);
		rdma_destroy_id(rds_listen_id);
		rds_listen_id = NULL;
	}
}

#define MODULE_NAME "rds_rdma"

int rds_rdma_init(void)
{
	int ret;

	ret = rds_rdma_listen_init();
	if (ret)
		goto out;

	ret = rds_ib_init();
	if (ret)
		goto err_ib_init;

	if (!unload_allowed) {
		printk(KERN_NOTICE "Module %s locked in memory until next boot\n",
		       MODULE_NAME);
		__module_get(THIS_MODULE);
	}

	goto out;

err_ib_init:
	rds_rdma_listen_stop();
out:
	return ret;
}
module_init(rds_rdma_init);

void rds_rdma_exit(void)
{
	/* stop listening first to ensure no new connections are attempted */
	rds_rdma_listen_stop();
	/* cancel initial ib failover work if still active*/
	cancel_delayed_work_sync(&riif_dlywork);
	rds_ib_exit();
}
module_exit(rds_rdma_exit);

MODULE_AUTHOR("Oracle Corporation <rds-devel@oss.oracle.com>");
MODULE_DESCRIPTION("RDS: IB/iWARP transport");
MODULE_LICENSE("Dual BSD/GPL");

