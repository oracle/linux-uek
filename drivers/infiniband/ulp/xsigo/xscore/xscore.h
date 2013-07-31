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

#ifndef _XSCORE_H_
#define _XSCORE_H_

#include <linux/types.h>
#include <linux/err.h>
#include <linux/dma-mapping.h>
#include <asm/byteorder.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_cm.h>

#include <linux/version.h>

#include <rdma/ib_addr.h>

#include "xs_compat.h"

#define	XSCORE_PORT_UP		100
#define	XSCORE_PORT_DOWN	101

/* Support MAX of 4 PAGES */
#define	XSCORE_MAX_RXFRAGS	4

enum xscore_conn_state {
	XSCORE_CONN_INIT = 1,
	XSCORE_CONN_ERR,
	XSCORE_CONN_CONNECTED,
	XSCORE_CONN_LDISCONNECTED,
	XSCORE_CONN_RDISCONNECTED,
	XSCORE_DEVICE_REMOVAL,
};

struct xscore_port;
struct xscore_desc;

struct xscore_buf_info {
	unsigned long addr;
	void *cookie;
	int sz;
	int status;
	unsigned long time_stamp;
};

struct xscore_conn_ctx {
	/*
	 * These are public attributes which needs to be set
	 * These can be made a different structure and copied
	 * over here XXX
	 */

	int tx_ring_size;
	int rx_ring_size;
	int rx_buf_size;
	/* In Interrupt mode coalescing parameters */
	u32 tx_coalesce_usecs;
	u32 tx_max_coalesced_frames;
	u32 rx_coalesce_usecs;
	u32 rx_max_coalesced_frames;
	u32 features;
#define	XSCORE_NO_SEND_COMPL_INTR	0x1
#define	XSCORE_SG_SUPPORT		0x2
#define	XSCORE_RDMA_SUPPORT		0x4
#define	XSCORE_NO_RECV_COMPL_INTR	0x8
#define	XSCORE_FMR_SUPPORT		0x10
#define	XSCORE_DONT_FREE_SENDBUF	0x20
#define	XSCORE_8K_IBMTU_SUPPORT		0x40
#define	XSCORE_USE_CHECKSUM		(1 << 31)
	void (*send_compl_handler) (void *client_arg, void *, int status,
				    int n);
	void (*recv_msg_handler) (void *client_arg, void *, int sz, int status,
				  int n);
	void (*recv_compl_handler) (void *client_arg);
	void (*event_handler) (void *client_arg, int event);
	u8 *(*alloc_buf) (void *client_arg, void **cookie, int sz);
	struct page *(*alloc_page_bufs) (void *client_arg, void **cookie,
					 int *sz, int element);
#define	XSCORE_SEND_BUF		1
#define	XSCORE_RECV_BUF		2
	void (*free_buf) (void *client_arg, void *cookie, int dir);
	char priv_data[IB_CM_REQ_PRIVATE_DATA_SIZE];
	int priv_data_len;
	void *client_arg;
	u64 service_id;
	union ib_gid dgid;
	u64 dguid;
	u16 dlid;
	int max_fmr_pages;
	int fmr_pool_size;
	u8 cm_timeout;
	u8 cm_retries;
	/*
	 * These are private attributes
	 */
	spinlock_t lock;
	struct mutex mlock;
	enum xscore_conn_state state;
	int status;
	struct xscore_port *port;
	struct ib_cm_id *cm_id;
	struct ib_sa_path_rec path_rec;
	struct ib_cq *scq;
	struct ib_cq *rcq;
	struct ib_qp *qp;
	int local_qpn;
	int remote_qpn;
	struct ib_sge *tx_sge;
	struct ib_fmr_pool *fmr_pool;
	struct xscore_desc *tx_ring;
	struct xscore_desc *rx_ring;
	int next_xmit;
	struct completion done;
	int flags;
#define	XSCORE_SYNCHRONOUS	0x1

#define	XSCORE_NUM_RWC		128
#define	XSCORE_NUM_SWC		8

	struct ib_wc rwc[XSCORE_NUM_RWC];
	int total_rwc;
	int cur_rwc;
	struct ib_wc swc[XSCORE_NUM_SWC];
	int total_swc;
	int cur_swc;
};

/*
 * This bit is used to signal soft-hca to defer processing in case of
 * called in interrupt disabled context
 */
#define	XSCORE_DEFER_PROCESS	(1 << 31)

int xscore_post_send_sg(struct xscore_conn_ctx *ctx, struct sk_buff *skb,
			int oflags);
int xscore_post_send(struct xscore_conn_ctx *ctx, void *addr, int len,
		     int flags);
int xscore_enable_txintr(struct xscore_conn_ctx *ctx);
int xscore_enable_rxintr(struct xscore_conn_ctx *ctx);
int xscore_conn_connect(struct xscore_conn_ctx *ctx, int flags);
void xscore_conn_disconnect(struct xscore_conn_ctx *ctx, int flags);
int xscore_conn_init(struct xscore_conn_ctx *ctx, struct xscore_port *port);
void xscore_conn_destroy(struct xscore_conn_ctx *ctx);
struct xscore_port *xscore_get_port(unsigned long hndl);
int xscore_read_buf(struct xscore_conn_ctx *ctx, struct xscore_buf_info *bp);
int xscore_poll_send(struct xscore_conn_ctx *ctx, struct xscore_buf_info *bp);
int xscore_refill_recv(struct xscore_conn_ctx *ctx, int gfp_flags);
u8 xscore_port_num(struct xscore_port *port);
int xscore_modify_cq(struct ib_cq *cq, u16 cq_count, u16 cq_period);
int xscore_wait_for_sessions(u8 calc_time);

typedef void (*xcpm_receive_message_handler) (xsmp_cookie_t xsmp_hndl,
					      u8 *data, int length);
typedef void (*xcpm_receive_event_handler) (xsmp_cookie_t xsmp_hndl, int event);
typedef int (*xcpm_callout_event_handler) (char *name);

enum xsmp_svc_state {
	SVC_STATE_DOWN = 1,
	SVC_STATE_UP,
};

struct xsmp_service_reg_info {
	enum xsmp_svc_state svc_state;
	xcpm_receive_message_handler receive_handler;
	xcpm_receive_event_handler event_handler;
	xcpm_callout_event_handler callout_handler;
	u16 ctrl_message_type;
	u16 resource_flag_index;
	int flags;
	atomic_t ref_cnt;
};

struct xsmp_session_info {
	char chassis_name[64];
	char session_name[64];
	u32 version;
	struct xscore_port *port;
	struct ib_device *ib_device;
	struct device *dma_device;
	struct ib_pd *pd;
	struct ib_mr *mr;
	u8 is_shca;
	u64 dguid;
};

/* extern declarations */
extern u32 xcpm_resource_flags;
extern int boot_flag;
extern struct list_head xscore_port_list;
extern int shca_csum;
extern int xsigod_enable;
extern char *os_version;
extern char *os_arch;
extern char hostname_str[];
extern char system_id_str[];
extern int xscore_create_procfs_entries(void);
extern void xscore_remove_procfs_entries(void);
extern void xcpm_port_add_proc_entry(struct xscore_port *port);
extern void xcpm_port_remove_proc_entry(struct xscore_port *port);
extern void xsmp_ulp_notify(struct xscore_port *p, int e);
extern int xscore_wait_for_sessions(u8 cacl_time);

/*
 * All XCPM service message functions
 */

int xsmp_sessions_match(struct xsmp_session_info *, xsmp_cookie_t);

int xcpm_register_service(struct xsmp_service_reg_info *s_info);

int xcpm_unregister_service(int service_id);

int xcpm_send_message(xsmp_cookie_t xsmp_hndl, int service_id,
		      u8 *data, int length);

int xcpm_get_xsmp_session_info(xsmp_cookie_t xsmp_hndl,
			       struct xsmp_session_info *ip);

int xcpm_check_duplicate_names(xsmp_cookie_t xsmp_hndl, char *name, u8 svc_id);
int xcpm_send_msg_xsigod(xsmp_cookie_t xsmp_hndl, void *msg, int len);

void *xcpm_alloc_msg(int sz);

void xcpm_free_msg(void *msg);

int xcpm_is_xsigod_enabled(void);

struct pci_dev *xs_vpci_prep_vnic(struct net_device *netdev, char *vnic_name,
				  int devn);
void *xs_vpci_add_vnic(char *vnic_name, int devn);
void xs_vpci_remove_vnic(struct net_device *netdev, void *hndl);

#endif /* _XSCORE_H_ */
