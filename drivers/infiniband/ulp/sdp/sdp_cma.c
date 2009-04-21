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

#define SDP_MAJV_MINV 0x22

enum {
	SDP_HH_SIZE = 76,
	SDP_HAH_SIZE = 180,
};

static void sdp_cq_event_handler(struct ib_event *event, void *data)
{
}

static void sdp_qp_event_handler(struct ib_event *event, void *data)
{
}

static int sdp_init_qp(struct sock *sk, struct rdma_cm_id *id)
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
	struct ib_cq *rx_cq, *tx_cq;
	struct ib_mr *mr;
	struct ib_pd *pd;
	int rc;

	sdp_dbg(sk, "%s\n", __func__);

	sdp_sk(sk)->tx_ring.head = 1;
	sdp_sk(sk)->tx_ring.tail = 1;
	sdp_sk(sk)->rx_head = 1;
	sdp_sk(sk)->rx_tail = 1;

	sdp_sk(sk)->tx_ring.buffer = kmalloc(sizeof(*sdp_sk(sk)->tx_ring.buffer) *
			(SDP_TX_SIZE + 1), GFP_KERNEL);
	if (!sdp_sk(sk)->tx_ring.buffer) {
		rc = -ENOMEM;
		sdp_warn(sk, "Unable to allocate TX Ring size %zd.\n",
			 sizeof *sdp_sk(sk)->tx_ring.buffer * (SDP_TX_SIZE + 1));
		goto err_tx;
	}

	sdp_sk(sk)->rx_ring = kmalloc(sizeof *sdp_sk(sk)->rx_ring * SDP_RX_SIZE,
				      GFP_KERNEL);
	if (!sdp_sk(sk)->rx_ring) {
		rc = -ENOMEM;
		sdp_warn(sk, "Unable to allocate RX Ring size %zd.\n",
			 sizeof *sdp_sk(sk)->rx_ring * SDP_RX_SIZE);
		goto err_rx;
	}

	pd = ib_alloc_pd(device);
	if (IS_ERR(pd)) {
		rc = PTR_ERR(pd);
		sdp_warn(sk, "Unable to allocate PD: %d.\n", rc);
		goto err_pd;
	}

        mr = ib_get_dma_mr(pd, IB_ACCESS_LOCAL_WRITE);
        if (IS_ERR(mr)) {
                rc = PTR_ERR(mr);
		sdp_warn(sk, "Unable to get dma MR: %d.\n", rc);
                goto err_mr;
        }

	sdp_sk(sk)->mr = mr;
	INIT_WORK(&sdp_sk(sk)->rx_comp_work, sdp_rx_comp_work);

	rx_cq = ib_create_cq(device, sdp_rx_irq, sdp_cq_event_handler,
			  sk, SDP_RX_SIZE, 0);

	if (IS_ERR(rx_cq)) {
		rc = PTR_ERR(rx_cq);
		sdp_warn(sk, "Unable to allocate RX CQ: %d.\n", rc);
		goto err_rx_cq;
	}

	rc = ib_modify_cq(rx_cq, 10, 200);
	if (rc) {
		sdp_warn(sk, "Unable to modify RX CQ: %d.\n", rc);
		goto err_tx_cq;
	}
	sdp_warn(sk, "Initialized CQ moderation\n");
	sdp_sk(sk)->rx_cq = rx_cq;
	sdp_arm_rx_cq(sk);
	qp_init_attr.recv_cq = rx_cq;

	tx_cq = ib_create_cq(device, sdp_tx_irq, sdp_cq_event_handler,
			  sk, SDP_TX_SIZE, 0);

	if (IS_ERR(tx_cq)) {
		rc = PTR_ERR(tx_cq);
		sdp_warn(sk, "Unable to allocate TX CQ: %d.\n", rc);
		goto err_tx_cq;
	}

	init_timer(&sdp_sk(sk)->tx_ring.timer);
	sdp_sk(sk)->tx_ring.timer.function = sdp_poll_tx_cq;
	sdp_sk(sk)->tx_ring.timer.data = (unsigned long) sdp_sk(sk);
	sdp_sk(sk)->tx_ring.poll_cnt = 0;

	sdp_sk(sk)->tx_ring.cq = tx_cq;
        qp_init_attr.send_cq = tx_cq;

	rc = rdma_create_qp(id, pd, &qp_init_attr);
	if (rc) {
		sdp_warn(sk, "Unable to create QP: %d.\n", rc);
		goto err_qp;
	}
	sdp_sk(sk)->qp = id->qp;
	sdp_sk(sk)->ib_device = device;

	init_waitqueue_head(&sdp_sk(sk)->wq);

	sdp_dbg(sk, "%s done\n", __func__);
	return 0;

err_qp:
	ib_destroy_cq(tx_cq);
err_tx_cq:
	ib_destroy_cq(rx_cq);
err_rx_cq:
	ib_dereg_mr(sdp_sk(sk)->mr);
err_mr:
	ib_dealloc_pd(pd);
err_pd:
	kfree(sdp_sk(sk)->rx_ring);
	sdp_sk(sk)->rx_ring = NULL;
err_rx:
	kfree(sdp_sk(sk)->tx_ring.buffer);
	sdp_sk(sk)->tx_ring.buffer = NULL;
err_tx:
	return rc;
}

static int sdp_connect_handler(struct sock *sk, struct rdma_cm_id *id,
		       	struct rdma_cm_event *event)
{
	struct sockaddr_in *dst_addr;
	struct sock *child;
	const struct sdp_hh *h;
	int rc;

	sdp_dbg(sk, "%s %p -> %p\n", __func__, sdp_sk(sk)->id, id);

	h = event->param.conn.private_data;
	SDP_DUMP_PACKET(sk, "RX", NULL, &h->bsdh);

	if (!h->max_adverts)
		return -EINVAL;

	child = sk_clone(sk, GFP_KERNEL);
	if (!child)
		return -ENOMEM;

	sdp_init_sock(child);

	dst_addr = (struct sockaddr_in *)&id->route.addr.dst_addr;
	inet_sk(child)->dport = dst_addr->sin_port;
	inet_sk(child)->daddr = dst_addr->sin_addr.s_addr;

	bh_unlock_sock(child);
	__sock_put(child, SOCK_REF_CLONE);

	rc = sdp_init_qp(child, id);
	if (rc) {
		sdp_sk(child)->destructed_already = 1;
		sk_free(child);
		return rc;
	}

	sdp_add_sock(sdp_sk(child));

	sdp_sk(child)->max_bufs = sdp_sk(child)->tx_ring.credits = ntohs(h->bsdh.bufs);
	sdp_sk(child)->min_bufs = sdp_sk(child)->tx_ring.credits / 4;
	sdp_sk(child)->xmit_size_goal = ntohl(h->localrcvsz) -
		sizeof(struct sdp_bsdh);
	sdp_sk(child)->send_frags = PAGE_ALIGN(sdp_sk(child)->xmit_size_goal) /
		PAGE_SIZE;
        sdp_init_buffers(sdp_sk(child), rcvbuf_initial_size);
	
	sdp_dbg(child, "%s recv_frags: %d tx credits %d xmit_size_goal %d send trigger %d\n",
		__func__,
		sdp_sk(child)->recv_frags,
		sdp_sk(child)->tx_ring.credits,
		sdp_sk(child)->xmit_size_goal,
		sdp_sk(child)->min_bufs);

	id->context = child;
	sdp_sk(child)->id = id;

	list_add_tail(&sdp_sk(child)->backlog_queue, &sdp_sk(sk)->backlog_queue);
	sdp_sk(child)->parent = sk;

	sdp_exch_state(child, TCPF_LISTEN | TCPF_CLOSE, TCP_SYN_RECV);

	/* child->sk_write_space(child); */
	/* child->sk_data_ready(child, 0); */
	sk->sk_data_ready(sk, 0);

	return 0;
}

static int sdp_response_handler(struct sock *sk, struct rdma_cm_id *id,
				struct rdma_cm_event *event)
{
	const struct sdp_hah *h;
	struct sockaddr_in *dst_addr;
	sdp_dbg(sk, "%s\n", __func__);

	sdp_exch_state(sk, TCPF_SYN_SENT, TCP_ESTABLISHED);

	if (sock_flag(sk, SOCK_KEEPOPEN))
		sdp_start_keepalive_timer(sk);

	if (sock_flag(sk, SOCK_DEAD))
		return 0;

	h = event->param.conn.private_data;
	SDP_DUMP_PACKET(sk, "RX", NULL, &h->bsdh);
	sdp_sk(sk)->max_bufs = sdp_sk(sk)->tx_ring.credits = ntohs(h->bsdh.bufs);
	sdp_sk(sk)->min_bufs = sdp_sk(sk)->tx_ring.credits / 4;
	sdp_sk(sk)->xmit_size_goal = ntohl(h->actrcvsz) -
		sizeof(struct sdp_bsdh);
	sdp_sk(sk)->send_frags = MIN(PAGE_ALIGN(sdp_sk(sk)->xmit_size_goal) /
		PAGE_SIZE, SDP_MAX_SEND_SKB_FRAGS);
	sdp_sk(sk)->xmit_size_goal = MIN(sdp_sk(sk)->xmit_size_goal, 
		sdp_sk(sk)->send_frags * PAGE_SIZE);

	sdp_dbg(sk, "tx credits %d xmit_size_goal %d send_frags: %d credits update trigger %d\n",
		sdp_sk(sk)->tx_ring.credits,
		sdp_sk(sk)->xmit_size_goal,
		sdp_sk(sk)->send_frags,
		sdp_sk(sk)->min_bufs);

	sdp_sk(sk)->poll_cq = 1;
	sdp_arm_rx_cq(sk);
	sdp_poll_rx_cq(sdp_sk(sk));

	sk->sk_state_change(sk);
	sk_wake_async(sk, 0, POLL_OUT);

	dst_addr = (struct sockaddr_in *)&id->route.addr.dst_addr;
	inet_sk(sk)->dport = dst_addr->sin_port;
	inet_sk(sk)->daddr = dst_addr->sin_addr.s_addr;

	return 0;
}

static int sdp_connected_handler(struct sock *sk, struct rdma_cm_event *event)
{
	struct sock *parent;
	sdp_dbg(sk, "%s\n", __func__);

	parent = sdp_sk(sk)->parent;
	BUG_ON(!parent);

	sdp_exch_state(sk, TCPF_SYN_RECV, TCP_ESTABLISHED);

	if (sock_flag(sk, SOCK_KEEPOPEN))
		sdp_start_keepalive_timer(sk);

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

static int sdp_disconnected_handler(struct sock *sk)
{
	struct sdp_sock *ssk = sdp_sk(sk);

	sdp_dbg(sk, "%s\n", __func__);

	if (ssk->rx_cq)
		sdp_poll_rx_cq(ssk);

	if (ssk->tx_ring.cq)
		sdp_xmit_poll(ssk, 1);

	if (sk->sk_state == TCP_SYN_RECV) {
		sdp_connected_handler(sk, NULL);

		if (ssk->rcv_nxt)
			return 0;
	}

	return -ECONNRESET;
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
		hh.bsdh.len = htonl(sizeof(struct sdp_bsdh) + SDP_HH_SIZE);
		hh.max_adverts = 1;
		hh.majv_minv = SDP_MAJV_MINV;
		sdp_init_buffers(sdp_sk(sk), rcvbuf_initial_size);
		hh.localrcvsz = hh.desremrcvsz = htonl(sdp_sk(sk)->recv_frags *
						       PAGE_SIZE + SDP_HEAD_SIZE);
		hh.max_adverts = 0x1;
		inet_sk(sk)->saddr = inet_sk(sk)->rcv_saddr =
			((struct sockaddr_in *)&id->route.addr.src_addr)->sin_addr.s_addr;
		memset(&conn_param, 0, sizeof conn_param);
		conn_param.private_data_len = sizeof hh;
		conn_param.private_data = &hh;
		conn_param.responder_resources = 4 /* TODO */;
		conn_param.initiator_depth = 4 /* TODO */;
		conn_param.retry_count = SDP_RETRY_COUNT;
		SDP_DUMP_PACKET(NULL, "TX", NULL, &hh.bsdh);
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
		hah.bsdh.len = htonl(sizeof(struct sdp_bsdh) + SDP_HAH_SIZE);
		hah.majv_minv = SDP_MAJV_MINV;
		hah.ext_max_adverts = 1; /* Doesn't seem to be mandated by spec,
					    but just in case */
		hah.actrcvsz = htonl(sdp_sk(child)->recv_frags * PAGE_SIZE + SDP_HEAD_SIZE);
		memset(&conn_param, 0, sizeof conn_param);
		conn_param.private_data_len = sizeof hah;
		conn_param.private_data = &hah;
		conn_param.responder_resources = 4 /* TODO */;
		conn_param.initiator_depth = 4 /* TODO */;
		conn_param.retry_count = SDP_RETRY_COUNT;
		SDP_DUMP_PACKET(sk, "TX", NULL, &hah.bsdh);
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
		rc = sdp_response_handler(sk, id, event);
		if (rc)
			rdma_reject(id, NULL, 0);
		else
			rc = rdma_accept(id, NULL);

		if (!rc)
			rc = sdp_post_credits(sdp_sk(sk));
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
		inet_sk(sk)->saddr = inet_sk(sk)->rcv_saddr =
			((struct sockaddr_in *)&id->route.addr.src_addr)->sin_addr.s_addr;
		rc = sdp_connected_handler(sk, event);
		break;
	case RDMA_CM_EVENT_DISCONNECTED: /* This means DREQ/DREP received */
		sdp_dbg(sk, "RDMA_CM_EVENT_DISCONNECTED\n");

		if (sk->sk_state == TCP_LAST_ACK) {
			sdp_cancel_dreq_wait_timeout(sdp_sk(sk));

			sdp_exch_state(sk, TCPF_LAST_ACK, TCP_TIME_WAIT);

			sdp_dbg(sk, "%s: waiting for Infiniband tear down\n",
				__func__);
		}

		rdma_disconnect(id);

		if (sk->sk_state != TCP_TIME_WAIT) {
			if (sk->sk_state == TCP_CLOSE_WAIT) {
				sdp_dbg(sk, "IB teardown while in TCP_CLOSE_WAIT "
					    "taking reference to let close() finish the work\n");
				sock_hold(sk, SOCK_REF_CM_TW);
			}
			sdp_set_error(sk, EPIPE);
			rc = sdp_disconnected_handler(sk);
		}
		break;
	case RDMA_CM_EVENT_TIMEWAIT_EXIT:
		sdp_dbg(sk, "RDMA_CM_EVENT_TIMEWAIT_EXIT\n");
		rc = sdp_disconnected_handler(sk);
		break;
	case RDMA_CM_EVENT_DEVICE_REMOVAL:
		sdp_warn(sk, "RDMA_CM_EVENT_DEVICE_REMOVAL\n");
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
		parent = sdp_sk(sk)->parent;
		sdp_reset_sk(sk, rc);
	}

	release_sock(sk);

	sdp_dbg(sk, "event %d done. status %d\n", event->event, rc);

	if (parent) {
		sdp_dbg(parent, "deleting child %d done. status %d\n", event->event, rc);
		lock_sock(parent);
		if (!sdp_sk(parent)->id) { /* TODO: look at SOCK_DEAD? */
			sdp_dbg(sk, "parent is going away.\n");
			child = NULL;
			goto done;
		}
		if (!list_empty(&sdp_sk(child)->backlog_queue))
			list_del_init(&sdp_sk(child)->backlog_queue);
		else
			child = NULL;
done:
		release_sock(parent);
		if (child)
			sk_common_release(child);
	}
	return rc;
}
