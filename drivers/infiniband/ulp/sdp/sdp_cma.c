/*
 * Copyright (c) 2006 Mellanox Technologies Ltd.  All rights reserved.
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
 * $Id$
 */
#include <asm/semaphore.h>
#include <linux/device.h>
#include <linux/in.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/time.h>
#include <linux/workqueue.h>

#include <rdma/ib_verbs.h>
#include <rdma/rdma_cm.h>
#include <net/tcp_states.h>
#include "sdp_socket.h"
#include "sdp.h"

union cma_ip_addr {
        struct in6_addr ip6;
        struct {
                __u32 pad[3];
                __u32 addr;
        } ip4;
};

#define SDP_MAJV_MINV 0x22

/* TODO: too much? Can I avoid having the src/dst and port here? */
struct sdp_hh {
	struct sdp_bsdh bsdh;
	u8 majv_minv;
	u8 ipv_cap;
	u8 rsvd1;
	u8 max_adverts;
	__u32 desremrcvsz;
	__u32 localrcvsz;
	__u16 port;
	__u16 rsvd2;
	union cma_ip_addr src_addr;
	union cma_ip_addr dst_addr;
};

struct sdp_hah {
	struct sdp_bsdh bsdh;
	u8 majv_minv;
	u8 ipv_cap;
	u8 rsvd1;
	u8 ext_max_adverts;
	__u32 actrcvsz;
};

static void sdp_cq_event_handler(struct ib_event *event, void *data)
{
}

static void sdp_qp_event_handler(struct ib_event *event, void *data)
{
}

int sdp_init_qp(struct sock *sk, struct rdma_cm_id *id)
{
	struct ib_qp_init_attr qp_init_attr = {
		.event_handler = sdp_qp_event_handler,
		.cap.max_send_wr = SDP_TX_SIZE,
		.cap.max_send_sge = SDP_MAX_SEND_SKB_FRAGS + 1, /* TODO */
		.cap.max_recv_wr = SDP_RX_SIZE,
		.cap.max_recv_sge = SDP_MAX_SEND_SKB_FRAGS + 1, /* TODO */
        	.sq_sig_type = IB_SIGNAL_REQ_WR,
        	.qp_type = IB_QPT_RC,
	};
	struct ib_device *device = id->device;
	struct ib_cq *cq;
	struct ib_pd *pd;
	int rc;

	sdp_dbg(sk, "%s\n", __func__);

	sdp_sk(sk)->tx_ring = kmalloc(sizeof *sdp_sk(sk)->tx_ring * SDP_TX_SIZE,
				      GFP_KERNEL);
	if (!sdp_sk(sk)->tx_ring) {
		rc = -ENOMEM;
		sdp_warn(sk, "Unable to allocate TX Ring size %zd.\n",
			 sizeof *sdp_sk(sk)->tx_ring * SDP_TX_SIZE);
		goto err_tx;
	}

	sdp_sk(sk)->rx_ring = kmalloc(sizeof *sdp_sk(sk)->rx_ring * SDP_RX_SIZE,
				      GFP_KERNEL);
	if (!sdp_sk(sk)->rx_ring) {
		rc = -ENOMEM;
		sdp_warn(sk, "Unable to allocate RX Ring size %zd.\n",
			 sizeof *sdp_sk(sk)->rx_ring * SDP_TX_SIZE);
		goto err_rx;
	}

	pd = ib_alloc_pd(device);
	if (IS_ERR(pd)) {
		rc = PTR_ERR(pd);
		sdp_warn(sk, "Unable to allocate PD: %d.\n", rc);
		goto err_pd;
	}
	
        sdp_sk(sk)->mr = ib_get_dma_mr(pd, IB_ACCESS_LOCAL_WRITE);
        if (IS_ERR(sdp_sk(sk)->mr)) {
                rc = PTR_ERR(sdp_sk(sk)->mr);
		sdp_warn(sk, "Unable to get dma MR: %d.\n", rc);
                goto err_mr;
        }

	INIT_WORK(&sdp_sk(sk)->work, sdp_work, sdp_sk(sk));

	cq = ib_create_cq(device, sdp_completion_handler, sdp_cq_event_handler,
			  sk, SDP_TX_SIZE + SDP_RX_SIZE);

	if (IS_ERR(cq)) {
		rc = PTR_ERR(cq);
		sdp_warn(sk, "Unable to allocate CQ: %d.\n", rc);
		goto err_cq;
	}

        qp_init_attr.send_cq = qp_init_attr.recv_cq = cq;

	rc = rdma_create_qp(id, pd, &qp_init_attr);
	if (rc) {
		sdp_warn(sk, "Unable to create QP: %d.\n", rc);
		goto err_qp;
	}
	sdp_sk(sk)->cq = cq;
	sdp_sk(sk)->qp = id->qp;
	sdp_sk(sk)->dma_device = device->dma_device;

	init_waitqueue_head(&sdp_sk(sk)->wq);

	sdp_post_recvs(sdp_sk(sk));

	sdp_dbg(sk, "%s done\n", __func__);
	return 0;

err_qp:
	ib_destroy_cq(cq);
err_cq:
	ib_dereg_mr(sdp_sk(sk)->mr);
err_mr:
	ib_dealloc_pd(pd);
err_pd:
	kfree(sdp_sk(sk)->rx_ring);
err_rx:
	kfree(sdp_sk(sk)->tx_ring);
err_tx:
	return rc;
}

int sdp_connect_handler(struct sock *sk, struct rdma_cm_id *id,
		       	struct rdma_cm_event *event)
{
	struct sockaddr_in *dst_addr;
	struct sock *child;
	struct sdp_hh *h;
	int rc;

	sdp_dbg(sk, "%s %p -> %p\n", __func__, sdp_sk(sk)->id, id);

        child = sk_clone(sk, GFP_KERNEL);
        if (!child) {
                return -ENOMEM;
	}

	INIT_LIST_HEAD(&sdp_sk(child)->accept_queue);
	INIT_LIST_HEAD(&sdp_sk(child)->backlog_queue);
	INIT_WORK(&sdp_sk(child)->time_wait_work, sdp_time_wait_work, child);
	INIT_WORK(&sdp_sk(child)->destroy_work, sdp_destroy_work, child);

	dst_addr = (struct sockaddr_in *)&id->route.addr.dst_addr;
	inet_sk(child)->dport = dst_addr->sin_port;
	inet_sk(child)->daddr = dst_addr->sin_addr.s_addr;

	bh_unlock_sock(child);
	__sock_put(child);

	rc = sdp_init_qp(child, id);
	if (rc) {
		sk_common_release(child);
		return rc;
	}

	h = event->private_data;
	sdp_sk(child)->bufs = ntohs(h->bsdh.bufs);
	sdp_sk(child)->xmit_size_goal = ntohl(h->localrcvsz) -
		sizeof(struct sdp_bsdh);

	sdp_dbg(child, "%s bufs %d xmit_size_goal %d\n", __func__,
		sdp_sk(child)->bufs,
		sdp_sk(child)->xmit_size_goal);

	id->context = child;
	sdp_sk(child)->id = id;

	list_add_tail(&sdp_sk(child)->backlog_queue, &sdp_sk(sk)->backlog_queue);
	sdp_sk(child)->parent = sk;

	/* child->sk_write_space(child); */
	/* child->sk_data_ready(child, 0); */
	sk->sk_data_ready(sk, 0);

	return 0;
}

static int sdp_response_handler(struct sock *sk, struct rdma_cm_event *event)
{
	struct sdp_hah *h;
	sdp_dbg(sk, "%s\n", __func__);

	sk->sk_state = TCP_ESTABLISHED;

	/* TODO: If SOCK_KEEPOPEN set, need to reset and start
	   keepalive timer here */

	if (sock_flag(sk, SOCK_DEAD))
		return 0;

	h = event->private_data;
	sdp_sk(sk)->bufs = ntohs(h->bsdh.bufs);
	sdp_sk(sk)->xmit_size_goal = ntohl(h->actrcvsz) -
		sizeof(struct sdp_bsdh);

	sdp_dbg(sk, "%s bufs %d xmit_size_goal %d\n", __func__,
		sdp_sk(sk)->bufs,
		sdp_sk(sk)->xmit_size_goal);

	ib_req_notify_cq(sdp_sk(sk)->cq, IB_CQ_NEXT_COMP);

	sk->sk_state_change(sk);
	sk_wake_async(sk, 0, POLL_OUT);
	return 0;
}

int sdp_connected_handler(struct sock *sk, struct rdma_cm_event *event)
{
	struct sock *parent;
	sdp_dbg(sk, "%s\n", __func__);

	parent = sdp_sk(sk)->parent;
	BUG_ON(!parent);

	sk->sk_state = TCP_ESTABLISHED;

	/* TODO: If SOCK_KEEPOPEN set, need to reset and start
	   keepalive timer here */

	if (sock_flag(sk, SOCK_DEAD))
		return 0;

	lock_sock(parent);
	if (!sdp_sk(parent)->id) { /* TODO: look at SOCK_DEAD? */
		sdp_dbg(sk, "parent is going away.\n");
		goto done;
	}
#if 0
	/* TODO: backlog */
	if (sk_acceptq_is_full(parent)) {
		sdp_dbg(parent, "%s ECONNREFUSED: parent accept queue full: %d > %d\n", __func__, parent->sk_ack_backlog, parent->sk_max_ack_backlog);
		release_sock(parent);
		return -ECONNREFUSED;
	}
#endif
	sk_acceptq_added(parent);
	sdp_dbg(parent, "%s child connection established\n", __func__);
	list_del_init(&sdp_sk(sk)->backlog_queue);
	list_add_tail(&sdp_sk(sk)->accept_queue, &sdp_sk(parent)->accept_queue);

	parent->sk_state_change(parent);
	sk_wake_async(parent, 0, POLL_OUT);
done:
	release_sock(parent);

	return 0;
}

void sdp_disconnected_handler(struct sock *sk)
{
	sdp_dbg(sk, "%s\n", __func__);
}

int sdp_cma_handler(struct rdma_cm_id *id, struct rdma_cm_event *event)
{
	struct rdma_conn_param conn_param;
	struct sock *parent = NULL;
	struct sock *child = NULL;
	struct sock *sk;
	struct sdp_hah hah;
	struct sdp_hh hh;
	
	int rc = 0;

	sk = id->context;
	if (!sk) {
		sdp_dbg(NULL, "cm_id is being torn down, event %d\n",
		       	event->event);
		return event->event == RDMA_CM_EVENT_CONNECT_REQUEST ?
			-EINVAL : 0;
	}

	lock_sock(sk);
	sdp_dbg(sk, "%s event %d id %p\n", __func__, event->event, id);
	if (!sdp_sk(sk)->id) {
		sdp_dbg(sk, "socket is being torn down\n");
		rc = event->event == RDMA_CM_EVENT_CONNECT_REQUEST ?
			-EINVAL : 0;
		release_sock(sk);
		return rc;
	}

	switch (event->event) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		sdp_dbg(sk, "RDMA_CM_EVENT_ADDR_RESOLVED\n");
		rc = rdma_resolve_route(id, SDP_ROUTE_TIMEOUT);
		break;
	case RDMA_CM_EVENT_ADDR_ERROR:
		sdp_dbg(sk, "RDMA_CM_EVENT_ADDR_ERROR\n");
		rc = -ENETUNREACH;
		break;
	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		sdp_dbg(sk, "RDMA_CM_EVENT_ROUTE_RESOLVED : %p\n", id);
		rc = sdp_init_qp(sk, id);
		if (rc)
			break;
		sdp_sk(sk)->remote_credits = sdp_sk(sk)->rx_head -
			sdp_sk(sk)->rx_tail;
		memset(&hh, 0, sizeof hh);
		hh.bsdh.mid = SDP_MID_HELLO;
		hh.bsdh.bufs = htons(sdp_sk(sk)->remote_credits);
		hh.majv_minv = SDP_MAJV_MINV;
		hh.localrcvsz = hh.desremrcvsz = htonl(SDP_MAX_SEND_SKB_FRAGS *
			PAGE_SIZE + sizeof(struct sdp_bsdh));
		hh.max_adverts = 0x1;

		memset(&conn_param, 0, sizeof conn_param);
		conn_param.private_data_len = sizeof hh;
		conn_param.private_data = &hh;
		conn_param.responder_resources = 4 /* TODO */;
		conn_param.initiator_depth = 4 /* TODO */;
		conn_param.retry_count = SDP_RETRY_COUNT;
		rc = rdma_connect(id, &conn_param);
		break;
	case RDMA_CM_EVENT_ROUTE_ERROR:
		sdp_dbg(sk, "RDMA_CM_EVENT_ROUTE_ERROR : %p\n", id);
		rc = -ETIMEDOUT;
		break;
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		sdp_dbg(sk, "RDMA_CM_EVENT_CONNECT_REQUEST\n");
		rc = sdp_connect_handler(sk, id, event);
		if (rc) {
			rdma_reject(id, NULL, 0);
			break;
		}
		child = id->context;
		sdp_sk(child)->remote_credits = sdp_sk(child)->rx_head -
			sdp_sk(child)->rx_tail;
		memset(&hah, 0, sizeof hah);
		hah.bsdh.mid = SDP_MID_HELLO_ACK;
		hah.bsdh.bufs = htons(sdp_sk(child)->remote_credits);
		hah.majv_minv = SDP_MAJV_MINV;
		hah.actrcvsz = htonl(SDP_MAX_SEND_SKB_FRAGS * PAGE_SIZE +
				     sizeof(struct sdp_bsdh));
		memset(&conn_param, 0, sizeof conn_param);
		conn_param.private_data_len = sizeof hah;
		conn_param.private_data = &hah;
		conn_param.responder_resources = 4 /* TODO */;
		conn_param.initiator_depth = 4 /* TODO */;
		conn_param.retry_count = SDP_RETRY_COUNT;
		rc = rdma_accept(id, &conn_param);
		if (rc) {
			sdp_sk(child)->id = NULL;
			id->qp = NULL;
			id->context = NULL;
			parent = sdp_sk(child)->parent; /* TODO: hold ? */
		}
		break;
	case RDMA_CM_EVENT_CONNECT_RESPONSE:
		sdp_dbg(sk, "RDMA_CM_EVENT_CONNECT_RESPONSE\n");
		rc = sdp_response_handler(sk, event);
		if (rc)
			rdma_reject(id, NULL, 0);
		else
			rc = rdma_accept(id, NULL);
		break;
	case RDMA_CM_EVENT_CONNECT_ERROR:
		sdp_dbg(sk, "RDMA_CM_EVENT_CONNECT_ERROR\n");
		rc = -ETIMEDOUT;
		break;
	case RDMA_CM_EVENT_UNREACHABLE:
		sdp_dbg(sk, "RDMA_CM_EVENT_UNREACHABLE\n");
		rc = -ENETUNREACH;
		break;
	case RDMA_CM_EVENT_REJECTED:
		sdp_dbg(sk, "RDMA_CM_EVENT_REJECTED\n");
		rc = -ECONNREFUSED;
		break;
	case RDMA_CM_EVENT_ESTABLISHED:
		sdp_dbg(sk, "RDMA_CM_EVENT_ESTABLISHED\n");
		rc = sdp_connected_handler(sk, event);
		break;
	case RDMA_CM_EVENT_DISCONNECTED:
		sdp_dbg(sk, "RDMA_CM_EVENT_DISCONNECTED\n");
		rdma_disconnect(id);
		sdp_disconnected_handler(sk);
		rc = -ECONNRESET;
		break;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		sdp_warn(sk, "RDMA_CM_EVENT_DEVICE_REMOVAL\n");
		sdp_disconnected_handler(sk);
		rc = -ENETRESET;
		break;
	default:
		printk(KERN_ERR "SDP: Unexpected CMA event: %d\n",
		       event->event);
		rc = -ECONNABORTED;
		break;
	}

	sdp_dbg(sk, "%s event %d handled\n", __func__, event->event);

	if (rc && sdp_sk(sk)->id == id) {
		child = sk;
		sdp_sk(sk)->id = NULL;
		id->qp = NULL;
		id->context = NULL;
		sdp_set_error(sk, rc);
		parent = sdp_sk(sk)->parent;
	}

	release_sock(sk);

	sdp_dbg(sk, "event %d done. status %d\n", event->event, rc);

	if (parent) {
		sdp_dbg(parent, "deleting child %d done. status %d\n", event->event, rc);
		lock_sock(parent);
		if (!sdp_sk(parent)->id) { /* TODO: look at SOCK_DEAD? */
			sdp_dbg(sk, "parent is going away.\n");
			goto done;
		}
		list_del_init(&sdp_sk(child)->backlog_queue);
		if (!list_empty(&sdp_sk(child)->accept_queue)) {
			list_del_init(&sdp_sk(child)->accept_queue);
			sk_acceptq_removed(parent);
		}
done:
		release_sock(parent);
		sk_common_release(child);
	}
	return rc;
}
