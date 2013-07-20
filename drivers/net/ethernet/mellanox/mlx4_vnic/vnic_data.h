/*
 * Copyright (c) 2009 Mellanox Technologies. All rights reserved.
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
 */

#ifndef _VNIC_DATA_H
#define _VNIC_DATA_H

#include "vnic.h"

enum {
	VNIC_SEND_INLINE_FLAG_POS = 63,
};

#define	VNIC_SEND_INLINE_FLAG ((u64)1 << VNIC_SEND_INLINE_FLAG_POS)

/* main funcs */
int vnic_port_data_init(struct vnic_port *port);
void vnic_port_data_cleanup(struct vnic_port *port);

/* ib funcs */
struct sk_buff *vnic_alloc_rx_skb(struct vnic_rx_ring *ring, int buf_ind,
				  gfp_t gfp_flag);
int vnic_post_recv(struct vnic_rx_ring *ring, u64 wr_id);
int vnic_post_recvs(struct vnic_rx_ring *ring);
int vnic_ib_create_qp_range(struct ib_pd *pd, struct ib_qp_init_attr *init_attr,
			    struct ib_udata *udata, int nqps,
			    int align, struct ib_qp *list[]);
int vnic_ib_destroy_qp(struct ib_qp *qp);
int vnic_ib_post_send(struct ib_qp *ibqp,
		      struct ib_send_wr *wr,
		      struct ib_send_wr **bad_wr,
		      u8 ip_off, u8 ip6_off,
		      u8 tcp_off, u8 udp_off);
struct vnic_rx_ring *vnic_create_rx_ring(struct vnic_port *port, int index);
void vnic_destroy_rx_ring(struct vnic_rx_ring *ring);
int vnic_init_qp(struct vnic_login *login, int qp_index);
int vnic_create_qp(struct vnic_login *login, int qp_index);
int vnic_create_qp_range(struct vnic_login *login);
void vnic_destroy_qp(struct vnic_login *login, int qp_index);
int vnic_create_tx_res(struct vnic_login *login, int tx_res_index);
int vnic_create_rx_res(struct vnic_login *login, int rx_res_index);
void vnic_destroy_tx_res(struct vnic_login *login, int tx_res_index);
void vnic_destroy_rx_res(struct vnic_login *login, int rx_res_index);

int vnic_ib_up(struct net_device *dev);
int vnic_ib_down(struct net_device *dev);
int vnic_ib_open(struct net_device *dev);
int vnic_ib_stop(struct net_device *dev);

int vnic_ib_set_moder(struct vnic_login *login,
		      u16 rx_usecs, u16 rx_frames, u16 tx_usecs, u16 tx_frames);
int vnic_port_ib_init(struct vnic_port *port);
void vnic_port_ib_cleanup(struct vnic_port *port);
void vnic_ib_dispatch_event(struct ib_event *event);
#ifndef _BP_NAPI_POLL
int vnic_poll_cq_rx(struct napi_struct *napi, int budget);
#else
int vnic_poll_cq_rx(struct net_device *poll_dev, int *budget);
#endif
void vnic_send(struct vnic_login *login, struct sk_buff *skb,
	       struct ib_ah *ah, u32 dqpn, int tx_res_index);
void vnic_ib_free_ring(struct vnic_rx_ring *ring);
int vnic_ib_init_ring(struct vnic_rx_ring *ring);

/* netdev funcs */
struct net_device *vnic_alloc_netdev(struct vnic_port *port);
void vnic_free_netdev(struct vnic_login *login);
int vnic_restart(struct net_device *dev);
void __bcast_attach_cb(struct vnic_mcast *mcaste, void *login_ptr);
void __bcast_detach_cb(struct vnic_mcast *mcaste, void *login_ptr);

/* rx funcs */
int vnic_rx(struct vnic_login *login, struct sk_buff *skb, struct ib_wc *wc);
int vnic_unmap_and_replace_rx(struct vnic_rx_ring *ring, struct ib_device *dev,
			      struct skb_frag_struct *skb_frags_rx,
			      u64 wr_id, int length);
int vnic_rx_skb(struct vnic_login *login, struct vnic_rx_ring *ring,
		struct ib_wc *wc, int ip_summed, char *eth_hdr_va);

/* tx funcs */
int vnic_tx(struct sk_buff *skb, struct net_device *dev);

/* sysfs funcs */
int vnic_create_dentry(struct vnic_login *login);
void vnic_delete_dentry(struct vnic_login *login);

/* ethtool funcs */
void vnic_set_ethtool_ops(struct net_device *dev);

/* neigh funcs */
void vnic_neigh_del_all(struct vnic_login *login);
struct vnic_neigh *vnic_neighe_search(struct vnic_login *login, u8 *mac);
void vnic_neighe_dealloc_task(struct work_struct *work);
void vnic_neighe_dealloc(struct vnic_neigh *neighe);
struct vnic_neigh *vnic_neighe_alloc(struct vnic_login *login,
				     const u8 *mac, u16 dlid, u32 dqpn, u8 rss);
void vnic_neighe_del(struct vnic_login *login, struct vnic_neigh *neighe);
int vnic_neighe_add(struct vnic_login *login, struct vnic_neigh *neighe);
struct ib_ah *vnic_ah_alloc(struct vnic_login *login, u16 dlid);
void vnic_neigh_invalidate(struct vnic_login *login);



struct vnic_login *__vnic_login_create(struct vnic_port *port, int index);
u32 vnic_hash(struct net_device *dev, struct sk_buff *skb);
#endif /* _VNIC_DATA_H */
