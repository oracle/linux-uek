/*
 * Copyright (c) 2009, 2021 Oracle and/or its affiliates.
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
#include <net/netevent.h>
#include <linux/version.h>

#include "trace.h"

#define RDS_REJ_CONSUMER_DEFINED 28

struct rds_rdma_cm_event_handler_info {
	struct work_struct     work;
	struct rdma_cm_id     *cm_id;
	struct rdma_cm_event   event;
	struct rds_connection *conn;
	bool                   isv6;
	char                   private_data[];
};

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

static void rds_rdma_cm_event_handler_cmn(struct rdma_cm_id *cm_id,
					  struct rdma_cm_event *event,
					  struct rds_connection *conn,
					  bool isv6)
{
	struct rds_transport *trans = &rds_ib_transport;
	struct rds_connection *new_conn;
	struct rds_ib_connection *ic;
	int ret = 0;
	char *reason = NULL;

	if (!conn) {
		trace_rds_rdma_cm_event_handler(NULL, NULL, NULL,
						NULL,
						rds_cm_event_str(event->event),
						0);

		if (event->event == RDMA_CM_EVENT_CONNECT_REQUEST)
			ret = trans->cm_handle_connect(cm_id, event, isv6);

		if (ret) {
			trace_rds_rdma_cm_event_handler_err(NULL, NULL, NULL,
							    NULL, rds_cm_event_str(event->event), ret);

			/* make sure that ic and cm_id are disassocated
			 * before cm_id gets destroyed
			 */
			new_conn = cm_id->context;
			if (new_conn) {
				mutex_lock(&new_conn->c_cm_lock);
				ic = new_conn->c_transport_data;
				BUG_ON(!ic);
				down_write(&ic->i_cm_id_free_lock);
				ic->i_cm_id = NULL;
				cm_id->context = NULL;
				up_write(&ic->i_cm_id_free_lock);
				mutex_unlock(&new_conn->c_cm_lock);
			}

			rdma_destroy_id(cm_id);
		}

		return;
	}

	/* Prevent shutdown from tearing down the connection
	 * while we're executing. */
	mutex_lock(&conn->c_cm_lock);

	trace_rds_rdma_cm_event_handler(NULL, NULL, conn,
					conn->c_npaths > 0 ?
					conn->c_transport_data : NULL,
					rds_cm_event_str(event->event), 0);

	/* RDMA_CM_EVENT_CONNECT_REQUEST should always come in on a freshly
	 * allocated cm_id:
	 * ("cm_req_handler" unconditionally calls "ib_create_cm_id",
	 * which allocates with "kzalloc").
	 *
	 * If we ever encounter "cm_id->context != NULL" for this event,
	 * then something went very wrong.
	 *
	 * Whatever the cause, we certainly don't want to proceed
	 * by dispatching the same "cm_id" to "trans->cm_handle_connect" twice.
	 */
	BUG_ON(event->event == RDMA_CM_EVENT_CONNECT_REQUEST);

	ic = conn->c_transport_data;
	BUG_ON(!ic);

        /* If we can't acquire a read-lock on "i_cm_id_free_lock",
	 * "ic->i_cm_id" is in the process of being disassociated.
	 * Just ignore the event in that case.
	 */
        if (!down_read_trylock(&ic->i_cm_id_free_lock)) {
		mutex_unlock(&conn->c_cm_lock);
                return;
	}

	/* If the connection no longer points to this cm_id,
	 * it already has been disassociated and possibly destroyed.
	 * Just ignore the event in this case as well.
	 */
	if (ic->i_cm_id != cm_id) {
		up_read(&ic->i_cm_id_free_lock);
		mutex_unlock(&conn->c_cm_lock);
                return;
	}

	/* Even though this function no longer accesses "ic->i_cm_id" past this point
	 * and "cma.c" always blocks "rdma_destroy_id" until "event_callback" is done,
	 * we still need to hang on to the "i_cm_id_free_lock" until return,
	 * since some functions called (e.g. conn->c_transport_data) just access
	 * "ic->i_cm_id" without any checks.
	 */

	/* If the connection is being shut down, bail out right away.
	 *
	 * Events RDMA_CM_EVENT_ADDR_CHANGE and RDMA_CM_EVENT_DISCONNECTED
	 * need to be processed regardless of the connection state
	 * as they flush the ARP cache as well as invalidate the
	 * pending inbound connection (RDS_CONN_PATH_RESET_ALT_CONN).
	 */
	if ((rds_conn_state(conn) == RDS_CONN_DISCONNECTING ||
	     rds_conn_state(conn) == RDS_CONN_ERROR) &&
	    event->event != RDMA_CM_EVENT_ADDR_CHANGE &&
	    event->event != RDMA_CM_EVENT_DISCONNECTED) {
		reason = "ignoring events during teardown";
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
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		rdma_set_service_type(cm_id, conn->c_tos);
		if (rds_ib_sysctl_local_ack_timeout &&
		    rdma_port_get_link_layer(cm_id->device, cm_id->port_num) == IB_LINK_LAYER_ETHERNET)
			rdma_set_ack_timeout(cm_id, rds_ib_sysctl_local_ack_timeout);

		conn->c_to_index = 0;
		ret = rdma_resolve_route(cm_id,
				rds_rdma_resolve_to_ms[conn->c_to_index]);
		if (ret) {
			reason = "resolve route failed";
			rds_conn_drop(conn, DR_IB_RESOLVE_ROUTE_FAIL, ret);
			ret = 0;
		}
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		/* Connection could have been dropped so make sure the
		 * cm_id is valid before proceeding */

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
		break;

	case RDMA_CM_EVENT_ROUTE_ERROR:
		if (conn->c_to_index < (RDS_RDMA_RESOLVE_TO_MAX_INDEX-1))
			conn->c_to_index++;

		ret = rdma_resolve_route(cm_id,
				rds_rdma_resolve_to_ms[conn->c_to_index]);
		if (ret) {
			reason = "resolve route failed";
			rds_conn_drop(conn, DR_IB_RESOLVE_ROUTE_FAIL, ret);
			ret = 0;
		}
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		trans->cm_connect_complete(conn, event);
		break;

	case RDMA_CM_EVENT_ADDR_ERROR:
		rds_conn_drop(conn, DR_IB_ADDR_ERR, 0);
		break;

	case RDMA_CM_EVENT_CONNECT_ERROR:
	case RDMA_CM_EVENT_UNREACHABLE:
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		rds_conn_drop(conn, DR_IB_CONNECT_ERR, 0);
		break;

	case RDMA_CM_EVENT_REJECTED: {
		const int *rej_data;
		u8 rej_data_len;

		rej_data = rdma_consumer_reject_data(cm_id, event,
						     &rej_data_len);
		if (!rej_data || rej_data_len < sizeof(*rej_data))  {
			/* Rejection coming from the peer's RDMA layer.
			 * Note that rej_data_len is currently always set to
			 * IB_CM_REJ_PRIVATE_DATA_SIZE.  That may be changed
			 * in future.  So also check for that.
			 */
			pr_warn("Rejected: <%pI6c,%pI6c,%d>: %s\n",
				&conn->c_laddr, &conn->c_faddr, conn->c_tos,
				rdma_reject_msg(cm_id, event->status));
			rds_conn_drop(conn, DR_IB_REJECTED_EVENT, 0);
			reason = "rejection from RDMA";
			break;
		}

		if (*rej_data) {
			if (ntohl(*rej_data) == RDS_ACL_FAILURE) {
				pr_err("Rejected: <%pI6c,%pI6c,%d>: ACL violation\n",
				       &conn->c_laddr, &conn->c_faddr,
				       conn->c_tos);
				reason = "rejection ACL violation";
				rds_ib_conn_destroy_init(conn);
				break;
			}

			pr_err("Rejected: <%pI6c,%pI6c,%d>: error %d\n",
			       &conn->c_laddr, &conn->c_faddr, conn->c_tos,
			       ntohl(*rej_data));
			reason = "rejection with error code";
		} else {
			/* Only retry with old version if this connection
			 * has never been established.  This assumes that
			 * the peer will not suddenly be downgraded to an
			 * old version.
			 */
			if (!conn->c_version && !conn->c_tos) {
				conn->c_proposed_version =
					RDS_PROTOCOL_COMPAT_VERSION;
				pr_warn("Rejected: <%pI6c,%pI6c,%d>: retry with old protocol version\n",
					&conn->c_laddr,	&conn->c_faddr,
					conn->c_tos);
				reason = "rejection and retry with old version";
			} else {
				pr_warn("Rejected: <%pI6c,%pI6c,%d>: no error code\n",
					&conn->c_laddr,	&conn->c_faddr,
					conn->c_tos);
				reason = "rejection with no error code";
			}
		}
		rds_conn_drop(conn, DR_IB_CONSUMER_DEFINED_REJ,
			      ntohl(*rej_data));
		break;
	}

	case RDMA_CM_EVENT_ADDR_CHANGE:
		rds_conn_drop(conn, DR_IB_ADDR_CHANGE, 0);
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
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

	if (ret) {
		/* We need to take the shutdown-path here
		 * since this cm_id is already owned by a connection.
		 * There may be delayed or scheduled work pending.
		 * Or there may be resources allocated by "rds_ib_setup_qp"
		 * that are only released in the shutdown-path.
		 */

		rds_conn_drop(conn, DR_IB_SHUTDOWN_NEEDED, ret);
	}

        up_read(&ic->i_cm_id_free_lock);
	mutex_unlock(&conn->c_cm_lock);
}

static void rds_rdma_cm_event_handler_worker(struct work_struct *work)
{
	struct rds_rdma_cm_event_handler_info *info = container_of(work,
								   struct rds_rdma_cm_event_handler_info,
								   work);

	rds_rdma_cm_event_handler_cmn(info->cm_id, &info->event, info->conn, info->isv6);

	kfree(info);
}

static void rds_spawn_rdma_cm_event_handler(struct rdma_cm_id *cm_id,
					    struct rdma_cm_event *event,
					    bool isv6)
{
	struct rds_connection *conn = cm_id->context;
	struct workqueue_struct *wq;
	struct rds_rdma_cm_event_handler_info *info;

	if (event->event != RDMA_CM_EVENT_CONNECT_REQUEST)
		wq = conn ? conn->c_path->cp_wq : NULL;
	else
		wq = rds_aux_wq;

	if (!wq) {
		rds_rdma_cm_event_handler_cmn(cm_id, event, conn, isv6);
		return;
	}

	info = kmalloc(sizeof(*info) + event->param.conn.private_data_len, GFP_KERNEL);
	if (!info) {
		rds_rdma_cm_event_handler_cmn(cm_id, event, conn, isv6);
		return;
	}

	INIT_WORK(&info->work, rds_rdma_cm_event_handler_worker);

	info->cm_id = cm_id;
	memcpy(&info->event, event, sizeof(*event));
	info->conn = conn;
	info->isv6 = isv6;

	if (event->param.conn.private_data &&
	    event->param.conn.private_data_len) {
		memcpy(info->private_data,
		       event->param.conn.private_data,
		       event->param.conn.private_data_len);
		info->event.param.conn.private_data = info->private_data;
	} else {
		info->event.param.conn.private_data = NULL;
		info->event.param.conn.private_data_len = 0;
	}

	queue_work(wq, &info->work);
}

int rds_rdma_cm_event_handler(struct rdma_cm_id *cm_id,
			      struct rdma_cm_event *event)
{
	rds_spawn_rdma_cm_event_handler(cm_id, event, false);
	return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
int rds6_rdma_cm_event_handler(struct rdma_cm_id *cm_id,
			       struct rdma_cm_event *event)
{
	rds_spawn_rdma_cm_event_handler(cm_id, event, true);
	return 0;
}
#endif

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
	if (rds_rdma_listen_id) {
		rdsdebug("cm %p\n", rds_rdma_listen_id);
		rdma_destroy_id(rds_rdma_listen_id);
		rds_rdma_listen_id = NULL;
	}
#if IS_ENABLED(CONFIG_IPV6)
	if (rds6_rdma_listen_id) {
		rdsdebug("cm %p\n", rds6_rdma_listen_id);
		rdma_destroy_id(rds6_rdma_listen_id);
		rds6_rdma_listen_id = NULL;
	}
#endif
}

static int rds_rdma_nb_cb(struct notifier_block *self,
			  unsigned long event,
			  void *ctx)
{
	if (event == NETEVENT_NEIGH_UPDATE) {
		struct neighbour *neigh = ctx;
		struct in6_addr faddr;

                read_lock_bh(&neigh->lock);
		if (neigh->nud_state & NUD_VALID) {
			switch (neigh->tbl->family) {
			case AF_INET:
				ipv6_addr_set_v4mapped(*(const __be32 *)neigh->primary_key, &faddr);
				rds_conn_faddr_ha_changed(&faddr, neigh->ha, neigh->dev->addr_len);
				break;

			case AF_INET6:
				rds_conn_faddr_ha_changed((const struct in6_addr *)neigh->primary_key,
							  neigh->ha, neigh->dev->addr_len);
				break;
			}
		}
		read_unlock_bh(&neigh->lock);
	}

	return 0;
}

static struct notifier_block rds_rdma_nb = {
	.notifier_call = rds_rdma_nb_cb
};

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

	register_netevent_notifier(&rds_rdma_nb);

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
	unregister_netevent_notifier(&rds_rdma_nb);
	rds_rdma_listen_stop();
	rds_ib_exit();
}
module_exit(rds_rdma_exit);

MODULE_AUTHOR("Oracle Corporation <rds-devel@oss.oracle.com>");
MODULE_DESCRIPTION("RDS: IB transport");
MODULE_LICENSE("Dual BSD/GPL");

