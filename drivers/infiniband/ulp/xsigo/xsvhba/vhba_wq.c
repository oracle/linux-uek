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

#include <linux/fs.h>
#include "vhba_defs.h"
#include "vhba_ib.h"
#include "vhba_xsmp.h"
#include "vhba_scsi_intf.h"

#define	VHBA_WORKQUEUE			  "xsvhba_wq"
#define VHBA_MAX_DEL_TRY			3
#define VHBA_MAX_TEAR_DOWN_TRY	  3

struct delayed_work vhba_main_work;
struct workqueue_struct *vhba_workqueuep;
struct reconn_sts {
	int idr;
	int cqp_hdl;
	int dqp_hdl;
};
struct reconn_sts reconn_st[MAX_VHBAS];

void vhba_internal_processing(void)
{
	int i = 0;
	int reconn_count = 0;
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha;
	unsigned long flags;

	read_lock_irqsave(&vhba_global_lock, flags);
	list_for_each_entry(vhba, &vhba_g.list, list) {
		int got_handle = 0;
		ha = vhba->ha;

		/* Check IB is dead or not */
		ib_link_dead_poll(ha);

		if (atomic_read(&ha->qp_status) == VHBA_QP_RECONNECTING)
			vhba->qp_poll_count++;
		else
			vhba->qp_poll_count = 0;

		/*
		 * If we are stuck in VHBA_QP_RECONNECTING for 60+ seconds,
		 * let us try to force reconnect
		 */
		if (vhba->qp_poll_count >= 12) {
			reconn_st[i].idr = vhba->idr;
			goto reconnect;
		}

		/*
		 * Check if IOP lost the QP context. Send a heartbeat
		 * to revive it.
		 */

		if (atomic_read(&vhba->ha->ib_status) == VHBA_IB_UP) {
			if (vhba_check_heart_beat(vhba))
				vhba->heartbeat_count++;
			else
				vhba->heartbeat_count = 0;
		}

		if (vhba->heartbeat_count >= 12) {
			dprintk(TRC_WQ, vhba,
				"Sending hearbeat for QP context recovery\n");
			(void)vhba_send_heart_beat(vhba);
			vhba->heartbeat_count = 0;
		}

		if (atomic_read(&ha->qp_status) == VHBA_QP_TRYCONNECTING) {
			if (vhba->reconn_try_cnt < VHBA_MAX_TEAR_DOWN_TRY) {
				vhba->reconn_try_cnt++;
				continue;
			}
			vhba->reconn_attempt++;
			dprintk(TRC_WQ, vhba,
				"QP Marked for reconnect: idr=%d\n", vhba->idr);
			reconn_st[i].idr = vhba->idr;
			got_handle = 1;
			i++;
		}

		if (!got_handle)
			continue;

reconnect:
		vhba->reconn_try_cnt = 0;
		reconn_count++;
	}
	read_unlock_irqrestore(&vhba_global_lock, flags);

	for (i = 0; i < reconn_count; i++) {
		vhba = vhba_get_context_by_idr(reconn_st[i].idr);
		if (vhba == NULL) {
			dprintk(TRC_WQ, NULL, "No matching vhba for idr=%d\n",
				reconn_st[i].idr);
			continue;
		}
		ha = vhba->ha;
		vhba_xsmp_notify(vhba->xsmp_hndl,
				 vhba->resource_id, XSMP_VHBA_OPER_DOWN);
		vhba_ib_disconnect_qp(vhba);

		vhba_purge_pending_ios(vhba);

		dprintk(TRC_INFO, vhba, "Trying to reconnect QP\n");
		vhba_ib_connect_qp(vhba);
		DEC_REF_CNT(vhba);
	}
	return;
}

int vhbawq_init(void)
{
	vhba_workqueuep = create_singlethread_workqueue(VHBA_WORKQUEUE);
	if (vhba_workqueuep == NULL)
		return -1;

	return 0;
}

int vhbawq_cleanup(void)
{
	cancel_delayed_work(&vhba_main_work);
	flush_workqueue(vhba_workqueuep);
	destroy_workqueue(vhba_workqueuep);
	return 0;
}

int vhbawq_queue(void)
{
	INIT_DELAYED_WORK(&vhba_main_work, vhba_workqueue_processor);
	queue_delayed_work(vhba_workqueuep, &vhba_main_work,
			   WQ_PERIODIC_TIMER * HZ);
	return 0;
}

void vhba_workqueue_processor(struct work_struct *work)
{
	vhba_internal_processing();
	vhbawq_queue();
}

int vhba_check_heart_beat(struct virtual_hba *vhba)
{
	int tgt;
	int tgt_dead = 0;
	int ret = 0;
	struct os_tgt *tq;
	struct scsi_xg_vhba_host *ha = vhba->ha;

	for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
		tq = TGT_Q(ha, tgt);
		if (!tq)
			continue;
		if (atomic_read(&tq->fcport->state) == FCS_DEVICE_DEAD) {
			tgt_dead = 1;
			break;
		}
	}

	if ((tgt_dead == 1) ||
	    (vhba->ha->target_count == 0) ||
	    (atomic_read(&ha->link_state) == LINK_DEAD)) {
		ret = 1;
	}

	return ret;
}
