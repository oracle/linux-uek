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

#include <linux/version.h>
#include <linux/moduleparam.h>
#include <linux/vmalloc.h>
/* #include <linux/smp_lock.h> */
#include <linux/delay.h>

#include "vhba_os_def.h"
#include "vhba_xsmp.h"
#include "vhba_defs.h"
#include "vhba_ib.h"

struct timer_list stats_timer;
u32 stats_timer_on;

void vhba_stats_clear_all(struct vhba_ha_stats *pStats)
{
	if (pStats == NULL) {
		dprintk(0, -1, "NULL stats pointer passed");
		return;
	}
	memset(pStats, 0, sizeof(struct vhba_ha_stats));
}

void vhba_xsmp_stats_req(struct work_struct *work)
{
	struct xsvhba_work *xwork =
	    container_of(work, struct xsvhba_work, work);
	struct _vhba_stats *msg = (struct _vhba_stats *)xwork->msg;
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha = NULL;
	struct vhba_ha_stats *pStats = NULL;

	vhba = vhba_get_context_by_resource_id(msg->vid);

	if (vhba == NULL)
		goto out;

	ha = vhba->ha;
	pStats = &ha->stats;

	if (msg->action == 1) {
		dprintk(TRC_STATS, NULL, "received clear stats\n");
		vhba_stats_clear_all(pStats);
		DEC_REF_CNT(vhba);
		goto out;
	} else {
		dprintk(TRC_STATS, NULL,
			"received get stats action %d\n", msg->action);
		msg->totalIo = ha->stats.io_stats.total_read_reqs +
		    ha->stats.io_stats.total_write_reqs +
		    ha->stats.io_stats.total_task_mgmt_reqs;
		msg->readByteCount = ha->stats.io_stats.total_read_mbytes;
		msg->writeByteCount = ha->stats.io_stats.total_write_mbytes;
		msg->outstandingRequestCount = 0;
		msg->ioRequestCount = msg->totalIo;
		msg->readRequestCount = ha->stats.io_stats.total_read_reqs;
		msg->writeRequestCount = ha->stats.io_stats.total_write_reqs;
		msg->taskManagementRequestCount =
		    ha->stats.io_stats.total_task_mgmt_reqs;
		msg->targetCount = ha->target_count;
		msg->lunCount = ha->lun_count;

		/* this is cummulative and not per vhba */
		msg->xsmpXtDownCount = vhba_xsmp_stats.xt_state_dn_cnt;

		/* this is also cumulative */
		msg->xsmpXtOperStateRequestCount =
		    vhba_xsmp_stats.oper_req_msg_cnt;
		msg->mapFmrCount = ha->stats.fmr_stats.map_cnt;
		msg->ummapFmrCount = ha->stats.fmr_stats.unmap_cnt;
		msg->usedMapFmrCount = msg->mapFmrCount - msg->ummapFmrCount;
		msg->abortCommandCount =
		    ha->stats.scsi_stats.abort_success_cnt +
		    ha->stats.scsi_stats.abort_fail_cnt;
		msg->resetLunCommandCount = 0;
		msg->resetTargetCommandCount =
		    ha->stats.scsi_stats.dev_reset_success_cnt +
		    ha->stats.scsi_stats.dev_reset_fail_cnt;
		msg->resetBusCommandCount =
		    ha->stats.scsi_stats.bus_reset_success_cnt +
		    ha->stats.scsi_stats.bus_reset_fail_cnt;
		msg->linkDownCount = ha->stats.fc_stats.link_dn_cnt;
		msg->discInfoUpdateCount = ha->stats.fc_stats.disc_info_cnt;
		msg->targetLostCount = ha->stats.fc_stats.rscn_dn_cnt +
		    ha->stats.fc_stats.rscn_multiple_dn_cnt;
		msg->targetFoundCount = ha->stats.fc_stats.rscn_up_cnt +
		    ha->stats.fc_stats.rscn_multiple_up_cnt;
		msg->cqpDisconnectCount = ha->stats.ib_stats.cqp_dn_cnt;
		msg->dqpDisconnectCount = ha->stats.ib_stats.dqp_dn_cnt;
		msg->cqpIbSentErrorCount = ha->stats.ib_stats.cqp_send_err_cnt;
		msg->dqpIbSentErrorCount = ha->stats.ib_stats.dqp_send_err_cnt;
		msg->cqpIbReceiveErrorCount =
		    ha->stats.ib_stats.cqp_recv_err_cnt;
		msg->dqpIbReceiveErrorCount =
		    ha->stats.ib_stats.dqp_recv_err_cnt;
		msg->cqpIbRemoteDisconnectErrorCount = 0;
		msg->dqpIbRemoteDisconnectErrorCount = 0;
	}
	msg->code = 0;
	DEC_REF_CNT(vhba);
	vhba_xsmp_ack(vhba->xsmp_hndl, (u8 *) msg, sizeof(struct _vhba_stats));
out:
	kfree(xwork->msg);
	kfree(xwork);
}
