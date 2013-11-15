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

#ifndef __VHBA_IB_H__
#define __VHBA_IB_H__

#include <linux/types.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_fmr_pool.h>
#include "vhba_os_def.h"

/* Control queue pair defines*/
#define VHBA_CQP_SEND_Q_SZ		64
#define VHBA_CQP_RECV_Q_SZ		64
#define VHBA_CQP_MAX_BUF_SIZE		1024
#define VHBA_CQP_MAX_CTRL_MSG_SIZE	1024

/* Data queue pair defines */
#define VHBA_DQP_SEND_Q_SZ		1400
#define VHBA_DQP_RECV_Q_SZ		1400
#define VHBA_DQP_MAX_BUF_SIZE		256
#define VHBA_DQP_MAX_CTRL_MSG_SIZE	256

/* VHBA QP States */
#define VHBA_QP_NOTCONNECTED		0
#define VHBA_QP_TRYCONNECTING		1
#define VHBA_QP_RECONNECTING		2
#define VHBA_QP_PARTIAL_CONNECT		3
#define VHBA_QP_CONNECTED		4
#define VHBA_QP_DISCONNECTED		5

#define VHBA_IB_UP			0
#define VHBA_IB_DOWN			1
#define VHBA_IB_DEAD			2

/* Queue pair type */
#define QP_TYPE_CONTROL			0
#define QP_TYPE_DATA			1

/* Data queue pair direction */
#define DATA_QP_TYPE_TX			1
#define DATA_QP_TYPE_RX			2

/* FMR defines */
#define VHBA_FMR_POOL_SIZE		256
#define VHBA_MAX_TRANSFER_SIZE		4080
#define VHBA_DEFAULT_TRANSFER_SIZE	512
#define VHBA_MAX_FMR_PAGES		(((VHBA_DEFAULT_TRANSFER_SIZE * 512)/ \
							(PAGE_SIZE)) + 2)
#define VHBA_FMR_DIRTY_MARK		32
#define VHBA_MAX_DSDS_IN_FMR		((VHBA_DEFAULT_TRANSFER_SIZE * 512)/ \
								(PAGE_SIZE))

#define TCA_SERVICE_ID 0x1001ULL

struct scsi_xg_vhba_host;
struct srb;

int vhba_init_rings(struct virtual_hba *vhba);
void process_cqp_msg(struct virtual_hba *vhba, u8 *msg, int length);
void process_dqp_msg(struct virtual_hba *vhba, u8 *msg, int length);
int vhba_xsmp_notify(xsmp_cookie_t xsmp_hndl, u64 resource_id, int notifycmd);

void vhba_control_callback(void *client_arg, int event);
void vhba_data_callback(void *client_arg, int event);

int vhba_ib_disconnect_qp(struct virtual_hba *vhba);
int vhba_ib_connect_qp(struct virtual_hba *vhba);
int vhba_conn_init(struct virtual_hba *vhba);
void vhba_unmap_buf_fmr(struct virtual_hba *vhba, struct srb *sp, int tot_dsds);
void sp_put(struct virtual_hba *vhba, struct srb *sp);
int vhba_map_buf_fmr(struct virtual_hba *vhba, u64 *phys_addr, int num_pgs,
		     u64 *mapped_fmr_iova, struct srb *sp, int index);
int vhba_send_write_index(struct virtual_hba *vhba);
int readjust_io_addr(struct srb *sp);
int vhba_alloc_fmr_pool(struct virtual_hba *vhba);
void vhba_dealloc_fmr_pool(struct virtual_hba *vhba);

#endif /* __VHBA_IB_H__ */
