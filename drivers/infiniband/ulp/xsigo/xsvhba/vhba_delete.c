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

#include <linux/version.h>
#include <linux/moduleparam.h>
#include <linux/vmalloc.h>
/* #include <linux/smp_lock.h> */
#include <linux/delay.h>

#include "vhba_ib.h"
#include "vhba_os_def.h"
#include "vhba_xsmp.h"
#include "vhba_defs.h"
#include "vhba_scsi_intf.h"

/* Get the driver IO-Lock for use here. */

int vhba_delete(u64 resource_id)
{
	int i = 0, j = 0;
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha = NULL;

	vhba = vhba_remove_context(resource_id);

	if (vhba == NULL) {
		dprintk(TRC_XSMP_ERRS, NULL, "Non existent vhba\n");
		return -EINVAL;
	}

	ha = vhba->ha;

	/* Flush defered list */
	if (atomic_read(&ha->ib_status) == VHBA_IB_DOWN) {
		atomic_set(&ha->ib_link_down_cnt, 0);
		atomic_set(&ha->ib_status, VHBA_IB_DEAD);
	}

	dprintk(TRC_XSMP, vhba, "disconnecting qps for vhba %p\n", vhba);
	vhba_ib_disconnect_qp(vhba);
	dprintk(TRC_XSMP, vhba, "purging ios for vhba %p\n", vhba);
	vhba_purge_pending_ios(vhba);

	dprintk(TRC_XSMP, vhba, "uniniting QP connections\n");
	xscore_conn_destroy(&vhba->ctrl_conn.ctx);
	xscore_conn_destroy(&vhba->data_conn.ctx);

	atomic_set(&vhba->vhba_state, VHBA_STATE_NOT_ACTIVE);

	if (atomic_read(&vhba->ref_cnt)) {
		int err;

		dprintk(TRC_XSMP, NULL, "%s(): vhba %p has ref_cnt %d,\n"
				"waiting on...\n",
				__func__, vhba, atomic_read(&vhba->ref_cnt));

		err = wait_event_timeout(vhba->delete_wq,
				!atomic_read(&vhba->ref_cnt), 30 * HZ);
		if (err == 0) {
			eprintk(vhba, "vhba_delete: ref_cnt %d is non zero\n",
					atomic_read(&vhba->ref_cnt));
			return -EIO;
		}
	}

	dprintk(TRC_XSMP, NULL, "setting oper state dn\n");
	vhba_xsmp_notify(vhba->xsmp_hndl,
			 vhba->resource_id, XSMP_VHBA_OPER_DOWN);

	vhba_remove_proc_entry(vhba);
	vhba_remove_target_proc_entry(vhba);

	for (i = 0; i < REQUEST_ENTRY_CNT_24XX; i++) {
		if (ha->send_buf_ptr[i] != NULL) {
			kfree(ha->send_buf_ptr[i]);
			ha->send_buf_ptr[i] = NULL;
		}
	}
	xg_vhba_free_device(vhba);
	vhba_scsi_release(vhba);

	/*
	 * Free memory allocated for tgts/lun's etc.
	 */
	for (i = 0; i < MAX_FIBRE_TARGETS; i++) {
		if (TGT_Q(ha, i)) {
			dprintk(TRC_XSMP, NULL, "freeing tgt %d\n", i);
			for (j = 0; j < MAX_FIBRE_LUNS; j++) {
				if (LUN_Q(ha, i, j)) {
					dprintk(TRC_XSMP,
						NULL, "freeing lun %d\n", j);
					if (LUN_Q(ha, i, j)->fclun) {
						kfree(LUN_Q(ha, i, j)->fclun);
						LUN_Q(ha, i, j)->fclun = NULL;
					}
					kfree(LUN_Q(ha, i, j));
					LUN_Q(ha, i, j) = NULL;
				}
			}	/* end free all lun's under the tgt */
			if (TGT_Q(ha, i)->fcport) {
				kfree(TGT_Q(ha, i)->fcport);
				TGT_Q(ha, i)->fcport = NULL;
			}
			kfree(TGT_Q(ha, i));
			TGT_Q(ha, i) = NULL;
		}

	}			/* end free all tgts */

	kfree(ha);
	kfree(vhba);
	atomic_dec(&vhba_count);

	return 0;
}				/* vhba_delete() */

int vhba_scsi_release(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;

	dprintk(TRC_XSMP, vhba, "deleting scsi host for vhba %p\n", vhba);

	fc_remove_host(ha->host);

	scsi_remove_host(ha->host);

	scsi_host_put(ha->host);

	vhba_dealloc_fmr_pool(vhba);

	if (vhba->cfg != NULL) {
		kfree(vhba->cfg);
		vhba->cfg = NULL;
	}
	return 0;
}
