/*
 * Copyright (c) 2006-2012 Xsigo Systems Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *	 Redistribution and use in source and binary forms, with or
 *	 without modification, are permitted provided that the following
 *	 conditions are met:
 *
 *	  - Redistributions of source code must retain the above
 *		copyright notice, this list of conditions and the following
 *		disclaimer.
 *
 *	  - Redistributions in binary form must reproduce the above
 *		copyright notice, this list of conditions and the following
 *		disclaimer in the documentation and/or other materials
 *		provided with the distribution.
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

/*
 * vhba_create.c
 */

#include <linux/version.h>
#include <linux/moduleparam.h>
#include <linux/vmalloc.h>
/* #include <linux/smp_lock.h> */
#include <linux/delay.h>
#include "vhba_xsmp.h"
#include "vhba_defs.h"
#include "vhba_ib.h"
#include "vhba_scsi_intf.h"

#include <scsi/scsi_transport_fc.h>

static u32 xg_vhba_mem_alloc(struct virtual_hba *);

int vhba_create(xsmp_cookie_t xsmp_hndl, struct vhba_xsmp_msg *msg)
{
	struct virtual_hba *vhba;
	struct Scsi_Host *host;
	struct scsi_xg_vhba_host *ha;
	struct vhba_xsmp_msg *msg1;
	uint32_t mtu;
	u32 i;
	int ret;
	int vhba_xsmp_msg_len = sizeof(struct vhba_xsmp_msg);
	enum vhba_xsmp_error_codes nack_code = VHBA_NACK_GENERAL_ERROR;

	vhba = kmalloc(sizeof(struct virtual_hba), GFP_ATOMIC);
	if (!vhba) {
		eprintk(NULL, "vhba alloc failed\n");
		vhba_xsmp_nack(xsmp_hndl, (u8 *) msg, vhba_xsmp_msg_len,
			       VHBA_NACK_ALLOC_ERROR);
		return 1;
	}

	memset(vhba, 0, sizeof(struct virtual_hba));

	atomic_set(&vhba->ref_cnt, 0);
	atomic_set(&vhba->vhba_state, VHBA_STATE_NOT_ACTIVE);

	init_waitqueue_head(&vhba->timer_wq);
	init_waitqueue_head(&vhba->delete_wq);

	ret = vhba_create_context(msg, vhba);

	if (ret == 0) {
		/*
		 * Duplicate vHBA, probably due to previous sync operation
		 */
		dprintk(TRC_XSMP_ERRS, NULL,
			"VHBA with resource_id <0x%Lx> exists, "
			"not installing\n", msg->resource_id);
		vhba->xsmp_hndl = xsmp_hndl;
		vhba_xsmp_ack(xsmp_hndl, (u8 *) msg, vhba_xsmp_msg_len);
		vhba_xsmp_notify(xsmp_hndl, msg->resource_id,
				 XSMP_VHBA_OPER_UP);
		kfree(vhba);
		return 0;
	} else if (ret == -1) {
		eprintk(NULL, "mem alloc failed\n");
		nack_code = VHBA_NACK_ALLOC_ERROR;
		goto err_ret_5;
	} else if (ret != 1) {
		eprintk(NULL, "Error: unable to create context [%s]\n",
			msg->vh_name);
		goto err_ret_5;
	}

	mtu = msg->mtu;

	if (mtu == 0)
		mtu = 256;	/* 256KB */
	if (mtu > 2040)		/* 2MB - 8KB */
		mtu = 2040;
	dprintk(TRC_XSMP, NULL, "mtu size=%d\n", mtu);

	vhba_max_dsds_in_fmr = (mtu * 1024) / PAGE_SIZE;
	vhba_max_fmr_pages = ((mtu * 1024) / PAGE_SIZE) + 2;
	vhba_max_transfer_size = (mtu * 1024) / 512;

	xg_vhba_driver_template.sg_tablesize = vhba_max_dsds_in_fmr;

	if (vhba_max_transfer_size != VHBA_DEFAULT_TRANSFER_SIZE)
		xg_vhba_driver_template.max_sectors = vhba_max_transfer_size;

	host = scsi_host_alloc(&xg_vhba_driver_template, sizeof(int));

	if (host == NULL) {
		eprintk(NULL, "scsi host alloc failed\n");
		nack_code = VHBA_NACK_ALLOC_ERROR;
		goto err_ret_5;
	}

	ha = (struct scsi_xg_vhba_host *)
	    kmalloc(sizeof(struct scsi_xg_vhba_host), GFP_ATOMIC);

	if (!ha) {
		eprintk(NULL, "Ha alloc failed\n");
		nack_code = VHBA_NACK_ALLOC_ERROR;
		goto err_ret_4;
	}
	memset(ha, 0, sizeof(struct scsi_xg_vhba_host));
	ha->host = host;
	ha->host_no = host->host_no;
	sprintf(ha->host_str, "%ld", ha->host_no);

	spin_lock_init(&ha->io_lock);

	/* Initialize proc related counters */
	ha->stats.io_stats.total_io_rsp = 0;
	ha->stats.io_stats.total_read_reqs = 0;
	ha->stats.io_stats.total_write_reqs = 0;
	ha->stats.io_stats.total_task_mgmt_reqs = 0;
	ha->stats.io_stats.total_read_mbytes = 0;
	ha->stats.io_stats.total_write_mbytes = 0;
	ha->stats.io_stats.total_copy_ios = 0;
	ha->stats.io_stats.total_copy_page_allocs = 0;
	ha->stats.io_stats.total_copy_page_frees = 0;

	for (i = 0; i < VHBA_MAX_VH_Q_COUNT; i++) {
		atomic_set(&ha->stats.io_stats.num_vh_q_reqs[i], 0);
		atomic_set(&ha->stats.io_stats.vh_q_full_cnt[i], 0);
	}

	ha->ports = MAX_BUSES;
	ha->request_q_length = REQUEST_ENTRY_CNT_24XX;
	host->can_queue = vhba_max_q_depth;
	if ((vhba_max_q_depth > 64) || (vhba_max_q_depth < 1)) {
		/*
		 * Looks like a bogus value, set it to default (16).
		 */
		host->can_queue = VHBA_MAX_VH_Q_DEPTH;
	}
	ha->data_qp_handle = 0;
	ha->control_qp_handle = 0;
	atomic_set(&ha->qp_status, VHBA_QP_NOTCONNECTED);

	for (i = 0; i < REQUEST_ENTRY_CNT_24XX; i++)
		ha->send_buf_ptr[i] = NULL;

	spin_lock_init(&ha->list_lock);
	INIT_LIST_HEAD(&ha->disc_ports);
	INIT_LIST_HEAD(&ha->defer_list);
	atomic_set(&ha->periodic_def_cnt, 0);

	dprintk(TRC_XSMP, NULL, "create_vhba: new vhba = %p\n", (void *)vhba);

	*(host->hostdata) = (int)vhba->idr;
	vhba->ha = ha;
	ha->vhba = vhba;
	ha->max_tgt_id = 0;
	ha->max_targets = 0;
	ha->tca_guid = be64_to_cpu(msg->tca_guid);
	ha->tca_lid = be16_to_cpu(msg->tca_lid);

	vhba->xsmp_hndl = xsmp_hndl;
	vhba->scanned_once = 0;
	vhba->scan_reqd = 0;
	vhba->sync_needed = 0;
	vhba->ha->sync_flag = 1;
	vhba->reconn_try_cnt = 0;

	xcpm_get_xsmp_session_info(xsmp_hndl, &vhba->xsmp_info);

	if (msg->vhba_flag & 0x1)
		dprintk(TRC_XSMP, NULL, "This is a boot vhba\n");

	if ((msg->vhba_flag & 0x1) == 0x0)
		dprintk(TRC_XSMP, NULL, "This is a regular vhba\n");

	if (xg_vhba_mem_alloc(vhba)) {
		eprintk(vhba, "failure in xg_vhba_mem_alloc\n");
		nack_code = VHBA_NACK_ALLOC_ERROR;
		goto err_ret_2;
	}

	msg1 = kmalloc(sizeof(struct vhba_xsmp_msg), GFP_ATOMIC);

	if (!msg1) {
		eprintk(vhba, "kmalloc for vhba xsmp msg failed\n");
		nack_code = VHBA_NACK_ALLOC_ERROR;
		goto err_ret_1;
	}

	memcpy(msg1, msg, sizeof(struct vhba_xsmp_msg));
	vhba->cfg = msg1;
	ha->resource_id = msg->resource_id;
	vhba->resource_id = msg->resource_id;
	dprintk(TRC_INFO, vhba, "resource id is %Lx\n", msg->resource_id);
	host->this_id = 255;
	host->cmd_per_lun = cmds_per_lun;
	host->max_cmd_len = MAX_CMDSZ;
	host->max_channel = ha->ports - 1;
	if (vhba->cfg->lunmask_enable)
		ha->max_luns = 256;
	else
		ha->max_luns = MAX_FIBRE_LUNS_MORE;
	host->max_lun = ha->max_luns;
	host->unique_id = ha->instance;
	dprintk(TRC_XSMP, vhba,
		"detect hba %ld at address = %p\n", ha->host_no, ha);

	/* Use the VMware consistent naming convention & register the
	 * device as a FC-capable transport.  This FC-transport template
	 * needs to be pre-registered, and typically during module init */
	host->transportt = vhba_transport_template;
	host->max_channel = 0;
	host->max_lun = MAX_LUNS - 1;	/*0xffff-1 */
	host->max_id = MAX_TARGETS;
	ha->flags.init_done = 1;
	ret = scsi_add_host(host, NULL);
	if (ret) {
		pr_err("scsi_add_host failed: ret = %d\n", ret);
		goto err_ret_1;
	}

	{
		u64 port_name = wwn_to_u64((u8 *) &vhba->cfg->wwn);
	/* Hard coding the node name isn't right, but doing it for now */
		u64 node_name = port_name | 0x100000000;
		fc_host_node_name(host) = node_name;
		fc_host_port_name(host) = port_name;

	}

	if (vhba_initialize(vhba, msg1)) {
		eprintk(vhba, "scsi(%ld): Failed to initialize adapter -\n"
			"Adapter flags %x.\n", ha->host_no, ha->device_flags);
		goto err_ret_0;
	}

	vhba_xsmp_ack(xsmp_hndl, (u8 *) msg, vhba_xsmp_msg_len);
	sprintf((char *)ha->vhba_name, "vhba:%p", vhba);
	vhba_add_proc_entry(vhba);
	vhba_add_target_proc_entry(vhba);
	vhba_add_context(vhba);

	/* Any VHBA context setting, data & control IB queue pairs, etc.. */
	ret = vhba_conn_init(vhba);
	if (ret) {
		eprintk(vhba, "Trouble doing Conn Init. Returning %d\n", ret);
		vhba_remove_context(vhba->resource_id);
		goto err_ret_0;
	}
	ret = vhba_ib_connect_qp(vhba);
	if (ret) {
		eprintk(vhba, "Trouble Setting up Conn. Returning %d\n", ret);
		vhba_remove_context(vhba->resource_id);
		goto err_ret_0;
	}
	atomic_inc(&vhba_count);
	return 0;

err_ret_0:
	scsi_host_put(host);
err_ret_1:
	if (vhba->cfg != NULL)
		kfree(vhba->cfg);
err_ret_2:
	kfree(ha);
err_ret_4:
err_ret_5:
	kfree(vhba);
	vhba_xsmp_nack(xsmp_hndl, (u8 *) msg, vhba_xsmp_msg_len, nack_code);
	return -1;
}

void xg_vhba_free_device(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;

	if (ha->request_ring) {
		ib_dma_free_coherent(vhba->xsmp_info.ib_device,
				     ha->request_q_length *
				     sizeof(struct cmd_type_7),
				     ha->request_ring, ha->request_dma);
		dprintk(TRC_XSMP, vhba,
			"called ib_dma_free_coherent for req ring\n");
	} else
		dprintk(TRC_XSMP_ERRS, vhba, "request ring already NULL!\n");

	if (ha->req_ring_rindex) {
		ib_dma_free_coherent(vhba->xsmp_info.ib_device,
				     sizeof(u32), ha->req_ring_rindex,
				     ha->req_ring_rindex_dma);
		dprintk(TRC_XSMP, vhba,
			"called dma_free_coherent for req ring rindex\n");
	} else
		dprintk(TRC_XSMP_ERRS, vhba, "request ring ptr already NULL\n");
}

int get_outstding_cmd_entry(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	int start_cnt = ha->current_outstanding_cmd;
	int curr_cnt = ha->current_outstanding_cmd;

	while ((curr_cnt < MAX_OUTSTANDING_COMMANDS)) {
		if (ha->outstanding_cmds[curr_cnt] == NULL) {
			ha->current_outstanding_cmd = curr_cnt;
			return curr_cnt;
		} else
			curr_cnt++;
	}

	ha->stats.ib_stats.total_outstding_q_wraps++;
	curr_cnt = 0;
	while (curr_cnt < start_cnt) {
		if (ha->outstanding_cmds[curr_cnt] == NULL) {
			ha->current_outstanding_cmd = curr_cnt;
			return curr_cnt;
		} else
			curr_cnt++;
	}

	ha->stats.ib_stats.total_req_q_fulls++;
	return -1;
}

static u32 xg_vhba_mem_alloc(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;

	ha->request_ring = ib_dma_alloc_coherent(vhba->xsmp_info.ib_device,
						 ha->request_q_length *
						 sizeof(struct cmd_type_7),
						 &ha->request_dma, GFP_KERNEL);
	if (ha->request_ring == NULL) {
		eprintk(vhba, "alloc failed for req ring\n");
		return 1;
	}

	ha->req_ring_rindex = ib_dma_alloc_coherent(vhba->xsmp_info.ib_device,
						    sizeof(u32),
						    &ha->req_ring_rindex_dma,
						    GFP_KERNEL);
	if (ha->req_ring_rindex == NULL) {
		ib_dma_free_coherent(vhba->xsmp_info.ib_device,
				     ha->request_q_length *
				     sizeof(struct cmd_type_7),
				     ha->request_ring, ha->request_dma);
		eprintk(vhba, "alloc failed for req ring rindex\n");
		return 1;
	}
	return 0;
}
