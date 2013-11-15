/*
 * Copyright (c) 2006-2012 Xsigo Systems Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 * Redistribution and use in source and binary forms, with or
 * without modification, are permitted provided that the following
 * conditions are met:
 *
 *  - Redistributions of source code must retain the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer.
 *
 *  - Redistributions in binary form must reproduce the above
 *    copyright notice, this list of conditions and the following
 *    disclaimer in the documentation and/or other materials
 *    provided with the distribution.
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

#include <linux/delay.h>

#include <linux/version.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <rdma/ib_verbs.h>

#include "vhba_ib.h"
#include "vhba_defs.h"
#include "vhba_os_def.h"
#include "vhba_xsmp.h"

void vhba_connection_setup(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	int qp_status, ret;

	qp_status = atomic_read(&ha->qp_status);

	switch (qp_status) {
	case VHBA_QP_RECONNECTING:
		atomic_set(&ha->qp_status, VHBA_QP_PARTIAL_CONNECT);
		break;
	case VHBA_QP_PARTIAL_CONNECT:
		atomic_set(&ha->qp_status, VHBA_QP_CONNECTED);
		dprintk(TRC_INFO, vhba, "QP is connected\n");
		vhba->reconn_attempt = 0;
		vhba->qp_count++;
		atomic_set(&ha->ib_status, VHBA_IB_UP);
		dprintk(TRC_IB, vhba, "setting oper state up\n");
		vhba_xsmp_notify(vhba->xsmp_hndl,
				 vhba->resource_id, XSMP_VHBA_OPER_UP);
		break;
	default:
		eprintk(vhba,
			"Error - Unexpected QP state detected %d\n", qp_status);
		return;
	}			/* end switch */

	if (atomic_read(&ha->qp_status) == VHBA_QP_CONNECTED) {
		dprintk(TRC_INFO, vhba, "sending init blk\n");
		ret = vhba_send_init_blk(vhba);
		if (ret)
			eprintk(vhba, "sending init blk failed\n");
		dprintk(TRC_INFO, vhba, "sending enable vhba\n");
		ret = vhba_send_enable_vhba(vhba);
		if (ret)
			eprintk(vhba, "sending enable vhba failed\n");
	}
}

void vhba_control_callback(void *context, int event)
{
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha;

	vhba = (struct virtual_hba *)vhba_get_context_by_idr((u32)
							     (unsigned long)
							     context);
	if (!vhba) {
		eprintk(NULL, "Invalid context\n");
		return;
	}
	ha = vhba->ha;

	switch (event) {
	case XSCORE_CONN_RDISCONNECTED:
	case XSCORE_CONN_LDISCONNECTED:
		dprintk(TRC_IB, vhba, "Received Control Disconnect\n");
		ha->stats.ib_stats.cqp_remote_disconn_cnt++;
		atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);
		break;
	case XSCORE_CONN_CONNECTED:
		dprintk(TRC_IB, vhba, "Control Is Connected\n");
		ha->stats.ib_stats.cqp_up_cnt++;
		ha->control_qp_handle = XSCORE_CONN_CONNECTED;
		vhba_connection_setup(vhba);
		break;
	case XSCORE_CONN_ERR:
		ib_link_down(ha);
		ha->control_qp_handle = XSCORE_CONN_ERR;
		atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);
		break;
	default:
		break;
	}
	DEC_REF_CNT(vhba);

}

void vhba_data_callback(void *context, int event)
{
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha;

	vhba = (struct virtual_hba *)vhba_get_context_by_idr((u32)
							     (unsigned long)
							     context);
	if (!vhba) {
		eprintk(NULL, "Invalid COntext\n");
		return;
	}
	ha = vhba->ha;

	switch (event) {
	case XSCORE_CONN_RDISCONNECTED:
	case XSCORE_CONN_LDISCONNECTED:
		dprintk(TRC_IB, vhba, "Received Data Disconnect\n");
		ha->stats.ib_stats.dqp_remote_disconn_cnt++;
		atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);
		break;
	case XSCORE_CONN_CONNECTED:
		dprintk(TRC_IB, vhba, "Data Connected\n");
		ha->data_qp_handle = XSCORE_CONN_CONNECTED;
		vhba_connection_setup(vhba);
		break;
	case XSCORE_CONN_ERR:
		ib_link_down(ha);
		ha->data_qp_handle = XSCORE_CONN_ERR;
		atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);
		break;
	default:
		break;
	}
	DEC_REF_CNT(vhba);

}

int vhba_conn_init(struct virtual_hba *vhba)
{
	struct xsvhba_conn *cp = &vhba->ctrl_conn;
	struct xscore_conn_ctx *cctx = &cp->ctx;
	struct xt_cm_private_data *cmp;
	struct scsi_xg_vhba_host *ha = vhba->ha;
	int ret;

	/*
	 * Control connection
	 */
	cp->type = QP_TYPE_CONTROL;
	cctx->tx_ring_size = 8;
	cctx->rx_ring_size = 8;
	cctx->rx_buf_size = VHBA_CQP_MAX_BUF_SIZE;
	cctx->client_arg = (void *)(unsigned long)(vhba->idr);
	cctx->event_handler = vhba_control_callback;
	cctx->alloc_buf = 0;
	cctx->free_buf = 0;
	cctx->send_compl_handler = vhba_ctrl_send_comp_handler;
	cctx->recv_msg_handler = vhba_cqp_recv_comp_handler;
	cctx->dguid = ha->tca_guid;
	cctx->dlid = ha->tca_lid;
	cctx->service_id = be64_to_cpu(TCA_SERVICE_ID);
	cctx->features = XSCORE_DONT_FREE_SENDBUF;

	cmp = (struct xt_cm_private_data *)cctx->priv_data;
	cmp->vid = cpu_to_be64(vhba->resource_id);
	cmp->qp_type = cpu_to_be16(QP_TYPE_CONTROL);
	cmp->data_qp_type = 0;
	cctx->priv_data_len = sizeof(*cmp);

	ret = xscore_conn_init(cctx, vhba->xsmp_info.port);
	if (ret) {
		eprintk(vhba, "xscore_conn_init ctrl error for VID %llx %d\n",
			vhba->resource_id, ret);
		return ret;
	}

	cp = &vhba->data_conn;
	cctx = &cp->ctx;

	cp->type = QP_TYPE_DATA;
	cctx->tx_ring_size = VHBA_DQP_SEND_Q_SZ;
	cctx->rx_ring_size = VHBA_DQP_RECV_Q_SZ;
	cctx->rx_buf_size = VHBA_DQP_MAX_BUF_SIZE;
	cctx->client_arg = (void *)(unsigned long)(vhba->idr);
	cctx->event_handler = vhba_data_callback;
	cctx->alloc_buf = 0;
	cctx->free_buf = 0;
	cctx->send_compl_handler = vhba_data_send_comp_handler;
	cctx->recv_msg_handler = vhba_recv_comp_handler;
	cctx->dguid = ha->tca_guid;
	cctx->dlid = ha->tca_lid;
	cctx->service_id = be64_to_cpu(TCA_SERVICE_ID);
	cctx->features = XSCORE_RDMA_SUPPORT | XSCORE_DONT_FREE_SENDBUF;

	cmp = (struct xt_cm_private_data *)cctx->priv_data;
	cmp->vid = cpu_to_be64(vhba->resource_id);
	cmp->qp_type = cpu_to_be16(QP_TYPE_DATA);
	cmp->data_qp_type = 0;
	cctx->priv_data_len = sizeof(*cmp);

	ret = xscore_conn_init(cctx, vhba->xsmp_info.port);
	if (ret) {
		eprintk(vhba, "xscore_conn_init data error for VID %llx %d\n",
			vhba->resource_id, ret);
		xscore_conn_destroy(&vhba->ctrl_conn.ctx);
	}
	return ret;
}

int vhba_ib_connect_qp(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;

	int ret = 0;

	/* Create Control queue pair with the destination TCA */
	if ((atomic_read(&ha->qp_status) == VHBA_QP_PARTIAL_CONNECT) ||
	    (atomic_read(&ha->qp_status) == VHBA_QP_CONNECTED)) {
		dprintk(TRC_IB_ERRS, vhba, "Error - Invalid qp state: %d\n",
			atomic_read(&ha->qp_status));
		ret = 1;
		goto out;
	}

	atomic_set(&ha->qp_status, VHBA_QP_RECONNECTING);

	ret = xscore_conn_connect(&vhba->data_conn.ctx, 0);

	if (ret) {
		eprintk(vhba, "Data QP Connect failed: ret = %d\n", ret);
		ib_link_down(ha);
		atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);
		goto out;
	}

	ret = xscore_conn_connect(&vhba->ctrl_conn.ctx, 0);

	if (ret) {
		eprintk(vhba, "Control QP Connect failed: ret = %d\n", ret);
		xscore_conn_disconnect(&vhba->data_conn.ctx, 0);
		ib_link_down(ha);
		atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);
		goto out;
	}
	ret = 0;
out:
	return ret;

}

int vhba_ib_disconnect_qp(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;

	if (ha->control_qp_handle == XSCORE_CONN_CONNECTED) {
		dprintk(TRC_IB, vhba, "Disconnecting Control\n");
		xscore_conn_disconnect(&vhba->ctrl_conn.ctx, 0);
	}

	if (ha->data_qp_handle == XSCORE_CONN_CONNECTED) {
		dprintk(TRC_IB, vhba, "Disconnecting Data\n");
		xscore_conn_disconnect(&vhba->data_conn.ctx, 0);
	}

	atomic_set(&ha->qp_status, VHBA_QP_NOTCONNECTED);
	return 0;
}

int vhba_alloc_fmr_pool(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct ib_device_attr dev_attr;
	int ret;
	int page_shift = 0;
	struct ib_fmr_pool_param pool_params = {
		.max_pages_per_fmr = vhba_max_fmr_pages,
		.access = IB_ACCESS_LOCAL_WRITE |
		    IB_ACCESS_REMOTE_READ | IB_ACCESS_REMOTE_WRITE,
		.pool_size = VHBA_FMR_POOL_SIZE,
		.dirty_watermark = VHBA_FMR_DIRTY_MARK,
		.flush_function = 0,
		.flush_arg = 0,
		.cache = 1
	};

	ret = ib_query_device(vhba->xsmp_info.ib_device, &dev_attr);
	if (ret) {
		eprintk(vhba, "query_device error %d\n", ret);
		return -1;
	}

	page_shift = ffs(dev_attr.page_size_cap) - 1;
	if (page_shift < 0) {
		page_shift = PAGE_SIZE;
		dprintk(TRC_IB_ERRS, vhba,
			"ib_query_device returned a page_size of 0\n");
	}
	page_shift = max(12, page_shift);

	dprintk(TRC_IB, vhba, "Using page shift: %d\n", page_shift);

	pool_params.page_shift = page_shift;

	/*
	 * Allocate an fmr pool, assuming that the pd has been obtained
	 * before the call
	 */
	ha->fmr_pool = ib_create_fmr_pool(vhba->xsmp_info.pd, &pool_params);

	if (IS_ERR(ha->fmr_pool) || (!ha->fmr_pool)) {
		ha->fmr_pool = NULL;
		dprintk(TRC_IB_ERRS, vhba, "ib_create_fmr_pool failed\n");
		return -1;
	}
	return 0;
}

void vhba_dealloc_fmr_pool(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;

	if (ha->fmr_pool) {
		ib_destroy_fmr_pool(ha->fmr_pool);
		ha->fmr_pool = 0;
	} else {
		dprintk(TRC_IB_ERRS, vhba, "fmr pool ptr is null!\n");
	}
}

int vhba_map_buf_fmr(struct virtual_hba *vhba, u64 *phys_addr, int num_pgs,
		     u64 *mapped_fmr_iova, struct srb *sp, int index)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;

	if (!ha->fmr_pool) {
		eprintk(vhba, "Error - null fmr pool ptr\n");
		ha->stats.fmr_stats.map_fail_cnt++;
		/* Revisit: Correct return value is -1 */
		return 0;
	}
	sp->pool_fmr[index] = ib_fmr_pool_map_phys(ha->fmr_pool,
						   phys_addr, num_pgs,
						   *mapped_fmr_iova, NULL);

	if (IS_ERR(sp->pool_fmr[index])) {
		eprintk(vhba, "Error - pool fmr index map failed [%ld/%p]\n",
			IS_ERR_VALUE((unsigned long)sp->pool_fmr[index]),
			sp->pool_fmr[index]);
		ha->stats.fmr_stats.map_fail_cnt++;
		return -1;
	}
	ha->stats.fmr_stats.map_cnt++;
	return 0;
}

void vhba_unmap_buf_fmr(struct virtual_hba *vhba, struct srb *sp, int tot_dsds)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	int index;

	for (index = 0; index < tot_dsds; index++) {
		if (sp->pool_fmr[index]) {
			ib_fmr_pool_unmap(sp->pool_fmr[index]);
			sp->pool_fmr[index] = 0;
		}
	}
	ha->stats.fmr_stats.unmap_cnt++;
}

int vhba_send_init_blk(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	int ret;
	struct init_block *init_blk;

	vhba_init_rings(vhba);

	if (!ha->request_ring) {
		eprintk(vhba, "Error - null req ring ptr. Returning 1\n");
		return 1;
	}

	init_blk = &ha->init_blk;

	memset(init_blk, 0, sizeof(struct init_block));

	init_blk->type = INIT_BLOCK;
	init_blk->entry_size = sizeof(struct cmd_type_7);
	init_blk->ring_size = ha->request_q_length;
	init_blk->read_index_addr = ha->req_ring_rindex_dma;
	init_blk->read_index_rkey = vhba->xsmp_info.mr->rkey;
	init_blk->base_addr = ha->request_dma;
	init_blk->base_addr_rkey = vhba->xsmp_info.mr->rkey;

	dprintk(TRC_IB, vhba, "base (%Lx), rkey (%0x)\n",
		init_blk->base_addr, init_blk->base_addr_rkey);
	dprintk(TRC_IB, vhba, "read (%Lx), rrkey (%0x)\n",
		init_blk->read_index_addr, init_blk->read_index_rkey);
	dprintk(TRC_IB, vhba, "ring (%0x), entry (%0x)\n",
		init_blk->ring_size, init_blk->entry_size);

/* Init block index is 2048 (not overlapping with write_index 0 - 1023) */

	ret = xscore_post_send(&vhba->data_conn.ctx, (u8 *) init_blk,
			       sizeof(struct init_block), XSCORE_DEFER_PROCESS);

	if (ret) {
		eprintk(vhba, "xscore_post_send() failed\n");
		ha->stats.ib_stats.dqp_send_err_cnt++;
		ib_link_down(ha);
		atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);
		return 1;
	}
	return 0;
}

int vhba_send_write_index(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct vhba_write_index_msg *send_write_index_msg = 0;
	int ret;

	if ((ha->data_qp_handle == XSCORE_CONN_ERR) ||
	    (ha->control_qp_handle == XSCORE_CONN_ERR)) {
		dprintk(TRC_IB_ERRS, vhba, "IB handle is -1\n");
		return 1;
	}
	if ((ha->req_ring_windex < 0) ||
	    (ha->req_ring_windex >= ha->request_q_length)) {
		eprintk(vhba, "Error - invalid req_ring_windex %d\n"
			" in vhba_send_write_index\n", ha->req_ring_windex);
		return 1;
	}

	if (!ha->send_buf_ptr[ha->req_ring_windex]) {
		ha->send_buf_ptr[ha->req_ring_windex] =
			kmalloc(sizeof(struct vhba_write_index_msg),
			GFP_ATOMIC);
		if (!ha->send_buf_ptr[ha->req_ring_windex]) {
			eprintk(vhba, "Error - kmalloc failed!\n");
			return 1;
		}
	}

	send_write_index_msg = ha->send_buf_ptr[ha->req_ring_windex];
	ha->send_write_index_msg = send_write_index_msg;

	if (!send_write_index_msg) {
		eprintk(vhba, "Error - null send write index msg ptr.\n"
			"	Returning 1\n");
		return 1;
	}

	send_write_index_msg->type = WRITE_INDEX_UPDATE;
	send_write_index_msg->_reserved1 = 0x0;
	send_write_index_msg->_reserved = 0x0;
	send_write_index_msg->write_index = ha->req_ring_windex;

	ret = xscore_post_send(&vhba->data_conn.ctx,
			       (u8 *) send_write_index_msg,
			       sizeof(struct vhba_write_index_msg),
			       XSCORE_DEFER_PROCESS);
	if (ret) {
		eprintk(vhba, "Error - xsigo ib send msg failed?\n");
		send_write_index_msg = 0;
		ha->stats.ib_stats.dqp_send_err_cnt++;
		atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);
		ib_link_down(ha);
		return 1;
	}

	return 0;
}

int vhba_send_heart_beat(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct heart_beat_msg *hb_msg;
	int ret = 0;

	dprintk(TRC_FUNCS, vhba, "Entering...\n");

	if (atomic_read(&ha->qp_status) != VHBA_QP_CONNECTED)
		return 1;

	if (atomic_read(&ha->ib_status) != VHBA_IB_UP)
		return 1;

	dprintk(TRC_IB, vhba, "handle is %d\n", ha->control_qp_handle);

	hb_msg = kmalloc(sizeof(struct heart_beat_msg), GFP_ATOMIC);
	if (!hb_msg) {
		dprintk(TRC_IB_ERRS, vhba, "heart beat msg is not valid\n");
		return 1;
	}

	hb_msg->type = VHBA_HEART_BEAT;
	hb_msg->rsvd = 0;

	dprintk(TRC_IB, vhba,
		"sending hear beat msg on handle %d\n", ha->control_qp_handle);

	if (atomic_read(&ha->qp_status) == VHBA_QP_CONNECTED) {
		dprintk(TRC_IB, vhba, "cqp hdl %d hb_msg ptr %p\n",
			ha->control_qp_handle, hb_msg);
		ret = xscore_post_send(&vhba->ctrl_conn.ctx,
				       (u8 *) hb_msg,
				       sizeof(struct heart_beat_msg),
				       XSCORE_DEFER_PROCESS);
	}

	if (ret) {
		ha->stats.ib_stats.cqp_send_err_cnt++;
		dprintk(TRC_IB_ERRS, vhba, "heart beat msg failed\n");
		ib_link_down(ha);
		atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);
		kfree(hb_msg);
	}

	dprintk(TRC_FUNCS, vhba, "Returning...\n");
	return 0;
}

int vhba_send_enable_vhba(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct enable_msg *enable_msg;
	int ret = 1;

	enable_msg = kmalloc(sizeof(struct enable_msg), GFP_ATOMIC);
	if (!enable_msg) {
		dprintk(TRC_IB_ERRS, vhba, "enable_msg malloc error\n");
		return 1;
	}

	memset(enable_msg, 0, sizeof(struct enable_msg));

	enable_msg->type = ENABLE_VHBA_Q;
	enable_msg->rsvd = 0;

	dprintk(TRC_INFO, vhba, "sending enable vhba msg on Control Q Pair\n");

	if (atomic_read(&ha->qp_status) == VHBA_QP_CONNECTED) {
		ret = xscore_post_send(&vhba->ctrl_conn.ctx,
				       (u8 *) enable_msg,
				       sizeof(struct enable_msg),
				       XSCORE_DEFER_PROCESS);
	}
	if (ret) {
		ha->stats.ib_stats.cqp_send_err_cnt++;
		eprintk(vhba, "Error - xscore_post_send() failed\n");
		ib_link_down(ha);
		kfree(enable_msg);
		atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);
	}
	ha->stats.fc_stats.enable_msg_cnt++;
	return 0;
}

void vhba_data_send_comp_handler(void *client_arg, void *msg, int status, int n)
{
	u32 idr = (u32) (unsigned long)client_arg;
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha;

	vhba = vhba_get_context_by_idr(idr);
	if (!vhba) {
		eprintk(NULL, "Invalid client_arg received\n");
		return;
	}
	ha = vhba->ha;

	if (status) {
		eprintk(vhba, "Data Send Completion error: status %d\n",
			status);
		ib_link_down(ha);
		atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);
		goto out;
	}
out:
	DEC_REF_CNT(vhba);
}

void vhba_ctrl_send_comp_handler(void *client_arg, void *msg, int status, int n)
{
	u32 idr = (u32) (unsigned long)client_arg;
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha;

	vhba = vhba_get_context_by_idr(idr);
	if (!vhba) {
		eprintk(NULL, "Invalid client_arg received\n");
		return;
	}
	ha = vhba->ha;

	if (status) {
		eprintk(vhba, "Ctrl Send Completion error: status %d\n",
			status);
		ib_link_down(ha);
		atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);
		goto out;
	}
	kfree(msg);
out:
	DEC_REF_CNT(vhba);
}

void vhba_cqp_recv_comp_handler(void *client_arg, void *msg, int sz,
				int status, int n)
{
	u32 idr = (u32) (unsigned long)client_arg;
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha;

	vhba = vhba_get_context_by_idr(idr);
	if (!vhba) {
		eprintk(NULL, "Invalid client_arg received\n");
		kfree(msg);
		return;
	}
	ha = vhba->ha;

	if (status) {
		eprintk(vhba, "CQP Recv Completion error: status %d\n", status);
		ib_link_down(ha);
		atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);
		goto out;
	}
	process_cqp_msg(vhba, msg, sz);
out:
	kfree(msg);
	DEC_REF_CNT(vhba);
}

/*
 * Called from interrupt context
 */

void vhba_recv_comp_handler(void *client_arg, void *msg, int sz,
			    int status, int n)
{
	u32 idr = (u32) (unsigned long)client_arg;
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha;

	vhba = vhba_get_context_by_idr(idr);
	if (!vhba) {
		eprintk(NULL, "Invalid client_arg received\n");
		return;
	}
	ha = vhba->ha;

	if (status) {
		eprintk(vhba, "Recv Completion error: status %d\n", status);
		ib_link_down(ha);
		atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);
		kfree(msg);
		DEC_REF_CNT(vhba);
		return;
	}
	process_dqp_msg(vhba, msg, sz);

	kfree(msg);
	DEC_REF_CNT(vhba);
}
