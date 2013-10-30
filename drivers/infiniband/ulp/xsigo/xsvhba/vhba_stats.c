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

void vhba_stats_clear_all(struct vhba_ha_stats *pstats)
{
	if (pstats == NULL) {
		dprintk(0, -1, "NULL stats pointer passed");
		return;
	}
	memset(pstats, 0, sizeof(struct vhba_ha_stats));
}

void vhba_xsmp_stats_req(struct work_struct *work)
{
	struct xsvhba_work *xwork =
	    container_of(work, struct xsvhba_work, work);
	struct _vhba_stats *msg = (struct _vhba_stats *)xwork->msg;
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha = NULL;
	struct vhba_ha_stats *pstats = NULL;

	vhba = vhba_get_context_by_resource_id(msg->vid);

	if (vhba == NULL)
		goto out;

	ha = vhba->ha;
	pstats = &ha->stats;

	if (msg->action == 1) {
		dprintk(TRC_STATS, NULL, "received clear stats\n");
		vhba_stats_clear_all(pstats);
		DEC_REF_CNT(vhba);
		goto out;
	} else {
		dprintk(TRC_STATS, NULL,
			"received get stats action %d\n", msg->action);
		msg->totalio = ha->stats.io_stats.total_read_reqs +
		    ha->stats.io_stats.total_write_reqs +
		    ha->stats.io_stats.total_task_mgmt_reqs;
		msg->readbytecount = ha->stats.io_stats.total_read_mbytes;
		msg->writebytecount = ha->stats.io_stats.total_write_mbytes;
		msg->outstandingrequestcount = 0;
		msg->iorequestcount = msg->totalio;
		msg->readrequestcount = ha->stats.io_stats.total_read_reqs;
		msg->writerequestcount = ha->stats.io_stats.total_write_reqs;
		msg->taskmanagementrequestcount =
		    ha->stats.io_stats.total_task_mgmt_reqs;
		msg->targetcount = ha->target_count;
		msg->luncount = ha->lun_count;

		/* this is cummulative and not per vhba */
		msg->xsmpxtdowncount = vhba_xsmp_stats.xt_state_dn_cnt;

		/* this is also cumulative */
		msg->xsmpxtoperstaterequestcount =
		    vhba_xsmp_stats.oper_req_msg_cnt;
		msg->mapfmrcount = ha->stats.fmr_stats.map_cnt;
		msg->ummapfmrcount = ha->stats.fmr_stats.unmap_cnt;
		msg->usedmapfmrcount = msg->mapfmrcount - msg->ummapfmrcount;
		msg->abortcommandcount =
		    ha->stats.scsi_stats.abort_success_cnt +
		    ha->stats.scsi_stats.abort_fail_cnt;
		msg->resetluncommandcount = 0;
		msg->resettargetcommandcount =
		    ha->stats.scsi_stats.dev_reset_success_cnt +
		    ha->stats.scsi_stats.dev_reset_fail_cnt;
		msg->resetbuscommandcount =
		    ha->stats.scsi_stats.bus_reset_success_cnt +
		    ha->stats.scsi_stats.bus_reset_fail_cnt;
		msg->linkdowncount = ha->stats.fc_stats.link_dn_cnt;
		msg->discinfoupdatecount = ha->stats.fc_stats.disc_info_cnt;
		msg->targetlostcount = ha->stats.fc_stats.rscn_dn_cnt +
		    ha->stats.fc_stats.rscn_multiple_dn_cnt;
		msg->targetfoundcount = ha->stats.fc_stats.rscn_up_cnt +
		    ha->stats.fc_stats.rscn_multiple_up_cnt;
		msg->cqpdisconnectcount = ha->stats.ib_stats.cqp_dn_cnt;
		msg->dqpdisconnectcount = ha->stats.ib_stats.dqp_dn_cnt;
		msg->cqpibsenterrorcount = ha->stats.ib_stats.cqp_send_err_cnt;
		msg->dqpibsenterrorcount = ha->stats.ib_stats.dqp_send_err_cnt;
		msg->cqpibreceiveerrorcount =
		    ha->stats.ib_stats.cqp_recv_err_cnt;
		msg->dqpibreceiverrrorcount =
		    ha->stats.ib_stats.dqp_recv_err_cnt;
		msg->cqpibremotedisconnecterrorcount = 0;
		msg->dqpibremotedisconnecterrorcount = 0;
	}
	msg->code = 0;
	DEC_REF_CNT(vhba);
	vhba_xsmp_ack(vhba->xsmp_hndl, (u8 *) msg, sizeof(struct _vhba_stats));
out:
	kfree(xwork->msg);
	kfree(xwork);
}
