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
#include <linux/blkdev.h>
#include <scsi/scsi_tcq.h>

#include "vhba_defs.h"
#include "vhba_ib.h"
#include "vhba_align.h"
#include "vhba_scsi_intf.h"

#define XG_VHBA_VERSION "1.0.0"
#define VHBA_ABORT_TIMEOUT 5
#define VHBA_RESET_TIMEOUT 10

static int xg_vhba_slave_configure(struct scsi_device *device);
static int xg_vhba_eh_abort(struct scsi_cmnd *);
static int xg_vhba_eh_device_reset(struct scsi_cmnd *);
static int xg_vhba_eh_bus_reset(struct scsi_cmnd *);
static int xg_vhba_eh_host_reset(struct scsi_cmnd *);

struct info_str {
	char *buffer;
	int length;
	off_t offset;
	int pos;
};

static int xg_vhba_slave_configure(struct scsi_device *device)
{
	dprintk(TRC_FUNCS, NULL, "Entering...\n");

	scsi_change_queue_depth(device, vhba_max_q_depth);

	dprintk(TRC_FUNCS, NULL, "Returning\n");
	return 0;
}

static int xg_vhba_queuecommand_lck(struct scsi_cmnd *cmd,
				    void (*fn)(struct scsi_cmnd *))
{
	struct virtual_hba *vhba;
	struct Scsi_Host *host;
	struct scsi_xg_vhba_host *ha;
	u32 t, l;
	struct srb *sp;
	struct os_tgt *tq;
	struct os_lun *lq;
	unsigned long flags = 0;
	int index = -1;
	u32 queue_num = 0;
	u32 curr_position = 0;
	int vhba_state;
	int lun_map_byte, lun_map_bit;
	int vv, lindex = -1;
	struct srb *xg_sp;
	int found = 0;
	u32 timeout_val;

	host = cmd->device->host;
	cmd->scsi_done = fn;

	if (!host) {
		dprintk(TRC_SCSI_ERRS, NULL,
			"host ptr is null in queuecommand\n");
		return SCSI_MLQUEUE_HOST_BUSY;
	}
	vhba = vhba_get_context_by_idr((u32) *(host->hostdata));
	if (vhba == NULL) {
		cmd->result = DID_NO_CONNECT << 16;
		if (cmd->scsi_done)
			(cmd->scsi_done) (cmd);
		else
			dprintk(TRC_SCSI_ERRS, NULL, "scsi_done is null\n");
		return 0;
	}
	ha = (struct scsi_xg_vhba_host *)vhba->ha;

	vhba_state = atomic_read(&vhba->vhba_state);
	if ((vhba_state != VHBA_STATE_ACTIVE) &&
	    (vhba_state != VHBA_STATE_SCAN)) {
		dprintk(TRC_SCSI_ERRS, vhba,
			"Error - vhba not active! returning DID_NO_CONNECT\n");
		cmd->result = DID_NO_CONNECT << 16;
		(cmd->scsi_done) (cmd);
		DEC_REF_CNT(vhba);
		return 0;
	}

/* Only use this define when you are doing a obj/opt build in vmware */
#ifdef VMX86_DEVEL
	if (atomic_read(&vhba->ref_cnt) <= 0)
		panic("Refcount went negative\n");
#endif

	if ((atomic_read(&ha->ib_status) == VHBA_IB_DEAD) ||
	    (atomic_read(&ha->ib_status) == VHBA_IB_DOWN)) {
		cmd->result = DID_NO_CONNECT << 16;
		if (cmd->scsi_done) {
			(cmd->scsi_done) (cmd);
			dprintk(TRC_SCSI_ERRS, vhba,
				"returning DID_NO_CONNECT as QP is down\n");
		}
		DEC_REF_CNT(vhba);
		return 0;
	}

	t = cmd->device->id;
	l = cmd->device->lun;
	dprintk(TRC_IO, vhba, "recvd tgt %d, lun %d\n", t, l);

	if (l >= ha->max_luns) {
		ha->stats.scsi_stats.invalid_lun_cnt++;
		cmd->result = DID_NO_CONNECT << 16;
		dprintk(TRC_SCSI_ERRS, vhba, "Invalid lun %d max luns %d\n",
			l, ha->max_luns);
		goto release_return;
	}

	if (t >= ha->max_tgt_id) {
		ha->stats.scsi_stats.invalid_tgt_cnt++;
		if (ha->max_tgt_id != 0) {
			cmd->result = DID_BAD_TARGET << 16;
			dprintk(TRC_INFO, vhba,	"Invalid target %d\n ", t);
			dprintk(TRC_INFO, vhba, "targt cnt %d", ha->max_tgt_id);
		} else {
			cmd->result = DID_NO_CONNECT << 16;
		}
		goto release_return;
	}

	if (vhba_multiple_q)
		queue_num = t % VHBA_MAX_VH_Q_COUNT;
	else
		queue_num = 0;

	spin_lock_irqsave(&ha->io_lock, flags);

	if (atomic_read(&ha->stats.io_stats.num_vh_q_reqs[queue_num])
	    >= vhba_max_q_depth) {
		atomic_inc(&ha->stats.io_stats.vh_q_full_cnt[queue_num]);
		/*
		 * Queue is full. If we have a command with ABORTING
		 * status pending in the outstanding array for this target,
		 * then in all likelyhood iocard/vh is hosed. Take the recovery
		 * action and disconnect the QP.
		 */

		spin_unlock_irqrestore(&ha->io_lock, flags);
		if (vhba_recovery_action(ha, t)) {
			cmd->result = DID_NO_CONNECT << 16;
			cmd->scsi_done(cmd);
			DEC_REF_CNT(vhba);
			return 0;
		}
		ha->stats.io_stats.qcmd_busy_ret_cnt++;
		DEC_REF_CNT(vhba);
		return SCSI_MLQUEUE_HOST_BUSY;

	}

	atomic_inc(&ha->stats.io_stats.num_vh_q_reqs[queue_num]);

	lun_map_byte = l / 8;
	lun_map_bit = l % 8;
	tq = TGT_Q(ha, t);
	if (tq) {
		if (tq->init_done == 0) {
			dprintk(TRC_IO, vhba,
				"setting dma alignment to %ld for tgt %d\n",
				PAGE_SIZE, t);
			blk_queue_dma_alignment(cmd->device->request_queue,
						(PAGE_SIZE - 1));
			tq->init_done = 1;
		}
		if (!(vhba->cfg->lunmask_enable))
			goto no_lun_mask;

		if (l < MAX_FIBRE_LUNS) {
			for (vv = 0; vv < tq->fcport->lun_count; vv++) {
				if (l == tq->fcport->lun_ids[vv]) {
					lindex = vv;
					found = 1;
					break;
				}
			}
		} else
			found = 1;

		dprintk(TRC_IO, vhba,
			"l=%d, lun_ids=%d,",  l, tq->fcport->lun_ids[lindex]);
		dprintk(TRC_INFO, vhba,	"cmd=%02x\n", cmd->cmnd[0]);

		if (found == 0) {
			if (l == 0) {
				if (cmd->cmnd[0] == INQUIRY) {
					struct scatterlist *sg;
					char *buf;

					cmd->result = DID_OK << 16;
					if (scsi_sg_count(cmd)) {
						unsigned int sg_offset;

						sg = scsi_sglist(cmd);
						sg_offset = SG_OFFSET(sg);

						buf = page_address(sg_page(sg))
						    + sg_offset;

						*buf = 0x7f;
						*(buf + 2) = 0x03;
						*(buf + 3) = 0x22;
						*(buf + 4) = 0x00;
					} else if (scsi_bufflen(cmd)) {
						buf = (u8 *) scsi_sglist(cmd);
						*buf = 0x7f;
						*(buf + 2) = 0x03;
						*(buf + 3) = 0x22;
						*(buf + 4) = 0x00;
					}
					dprintk(TRC_IO, vhba, "Mask LUN 0\n");
					spin_unlock_irqrestore(&ha->io_lock,
							       flags);
					goto dec_release_return;
				}
			} else {
				ha->stats.scsi_stats.invalid_lun_cnt++;
				cmd->result = DID_NO_CONNECT << 16;
				dprintk(TRC_SCSI_ERRS, vhba, "(LUN ID) Error");
				dprintk(TRC_SCSI_ERRS, vhba, "lun %d ", l);
				dprintk(TRC_SCSI_ERRS, vhba, "not found in ");
				dprintk(TRC_SCSI_ERRS, vhba, "target queue!\n");
				spin_unlock_irqrestore(&ha->io_lock, flags);
				goto dec_release_return;
			}
		}
no_lun_mask:
		lq = LUN_Q(ha, t, l);
		if (!(lq)) {
			lq = vhba_allocate_lun(vhba, t, l);
			if (lq)
				lq->fclun = kmalloc(sizeof(struct fc_lun),
						    GFP_ATOMIC);
			if (!lq || !lq->fclun) {
				cmd->result = DID_NO_CONNECT << 16;
				spin_unlock_irqrestore(&ha->io_lock, flags);
				goto dec_release_return;
			}
			memset(lq->fclun, 0, sizeof(struct fc_lun));
			lq->fclun->lun = l;
		}

		dprintk(TRC_IO, vhba, "mapped tgt %d" " lun %d\n", t, l);
	} else {
		ha->stats.scsi_stats.invalid_tgt_cnt++;
		cmd->result = DID_NO_CONNECT << 16;
		spin_unlock_irqrestore(&ha->io_lock, flags);
		goto dec_release_return;
	}

	/* Maximum SCSI I/O retry */
	if (cmd->allowed < vhba_max_scsi_retry)
		cmd->allowed = vhba_max_scsi_retry;

	if (atomic_read(&ha->link_state) == LINK_DEAD ||
	    atomic_read(&tq->fcport->state) == FCS_DEVICE_DEAD) {
		cmd->result = DID_NO_CONNECT << 16;

		dprintk(TRC_TIMER, vhba, "Error - link/tgt dead!\n");
		dprintk(TRC_TIMER, vhba, "Link state %d device state %d\n",
			atomic_read(&ha->link_state),
			atomic_read(&tq->fcport->state));

		dprintk(TRC_TIMER, vhba, "sp(%p) cmd:(%p)", CMD_SP(cmd), cmd);
		spin_unlock_irqrestore(&ha->io_lock, flags);
		goto dec_release_return;
	}

	if (vhba->cfg->lunmask_enable) {
		/* Report lun interception */
		if ((cmd->cmnd[0] == REPORT_LUNS) &&
		    (atomic_read(&ha->link_state) == LINK_UP) &&
		    (atomic_read(&tq->fcport->state) == FCS_ONLINE)) {
			/* Just decrement the ha reference counter right away
			 * as the command is not going to be sent to the
			 * chip anyway.*/
			atomic_dec(&ha->stats.io_stats.
				   num_vh_q_reqs[queue_num]);
			xg_sp = kmalloc(sizeof(struct srb), GFP_ATOMIC);
			if (xg_sp == NULL) {
				cmd->result = DID_ERROR << 16;
				eprintk(vhba, "Error - allocate SRB failed\n");
				goto release_return;
			}
			memset(xg_sp, 0, sizeof(struct srb));
			xg_sp->cmd = cmd;
			xg_sp->ha = ha;
			CMD_SP(cmd) = (void *)xg_sp;
			xg_sp->state = 0;
			xg_sp->abort_cnt = 0;

			spin_unlock_irqrestore(&ha->io_lock, flags);

			if (vhba_report_luns_cmd(xg_sp, t, l)) {
				kfree(xg_sp);
				goto release_return;
			} else {

				cmd->result = DID_OK << 16;

				if (xg_sp->cmd) {
					if (xg_sp->cmd->scsi_done)
						(*(xg_sp->cmd)->scsi_done)
						    (xg_sp->cmd);
				}
				kfree(xg_sp);
				/*
				 * Decrement vhba ref cnt, since the cmd
				 * is not going down.
				 */
				DEC_REF_CNT(vhba);
				goto ret_success;
			}
		}
	}
	index = get_outstding_cmd_entry(vhba);
	if (index == -1) {
		spin_unlock_irqrestore(&ha->io_lock, flags);
		dprintk(TRC_SCSI_ERRS, vhba,
		"Warn - Max limit on outstanding commands reached.\n");
		dprintk(TRC_SCSI_ERRS, vhba, "returnin SCSI_MLQUEUE_HOST_BUSY");
		atomic_dec(&ha->stats.io_stats.num_vh_q_reqs[queue_num]);
		ha->stats.io_stats.qcmd_busy_ret_cnt++;
		DEC_REF_CNT(vhba);
		return SCSI_MLQUEUE_HOST_BUSY;

	}

	ha->outstanding_cmds[ha->current_outstanding_cmd] =
	    kmalloc(sizeof(struct srb), GFP_ATOMIC);
	if (ha->outstanding_cmds[ha->current_outstanding_cmd] == NULL) {
		cmd->result = DID_ERROR << 16;
		eprintk(vhba, "Error - allocate SRB failed\n");
		spin_unlock_irqrestore(&ha->io_lock, flags);
		goto dec_release_return;
	}

	sp = ha->outstanding_cmds[ha->current_outstanding_cmd];
	memset(sp, 0, sizeof(struct srb));
	sp->cmd = cmd;
	sp->ha = ha;
	CMD_SP(cmd) = (void *)sp;
	sp->state = 0;
	sp->tgt_queue = tq;
	sp->lun_queue = lq;
	sp->error_flag = 0;
	sp->abort_cnt = 0;
	sp->unaligned_sg = NULL;

	sp->queue_num = queue_num;

	if (tq->fcport->flags & FCF_TAPE_PRESENT)
		sp->flags |= SRB_TAPE;

	/* Check for processor irq affinity or few outstanding
	   I/O for processing otherwise the IRQ can pick up and submit the I/O
	 */

	curr_position = ha->current_outstanding_cmd++;
	if (ha->current_outstanding_cmd == MAX_OUTSTANDING_COMMANDS)
		ha->current_outstanding_cmd = 0;

	if ((timeout_per_command(cmd) / HZ) <= IB_CMD_TIMEOUT_DELTA)
		timeout_val = vhba_default_scsi_timeout;
	else
		timeout_val = timeout_per_command(cmd) / HZ;

	/* Prepare the IOCB, the handle, build IOCB and fire it off */
	dprintk(TRC_IO, vhba,
		"calling start scsi for sp %p t %d l %d\n", sp, t, (u32) l);

	if (vhba_start_scsi(sp, t, l, curr_position)) {
		dprintk(TRC_INFO, vhba,
			"vhba_start_scsi failed sp=%p cmd=%p\n", sp, sp->cmd);
		if (sp->timer.function != NULL) {
			del_timer(&sp->timer);
			sp->timer.function = NULL;
		}
		if (ha->outstanding_cmds[curr_position]) {
			CMD_SP(sp->cmd) = NULL;
			kfree(ha->outstanding_cmds[curr_position]);
			ha->outstanding_cmds[curr_position] = NULL;
		} else {
			/* Cmd got flushed asynchronously */
			dprintk(TRC_INFO, vhba,
			"Cmd Got flushed Asynchronously");
			dprintk(TRC_INFO, vhba, " sp=%p cmd=%p\n", sp, sp->cmd);
			DEC_REF_CNT(vhba);
			spin_unlock_irqrestore(&ha->io_lock, flags);
			return 0;
		}
		spin_unlock_irqrestore(&ha->io_lock, flags);
		cmd->result = DID_BUS_BUSY << 16;
		goto dec_release_return;
	}
	spin_unlock_irqrestore(&ha->io_lock, flags);

ret_success:
	dprintk(TRC_FUNCS, vhba, "Returning SUCCESS\n");
	return 0;

dec_release_return:
	atomic_dec(&ha->stats.io_stats.num_vh_q_reqs[queue_num]);

release_return:
	dprintk(TRC_SCSI_ERRS, vhba, "returning cmd status %d from qcmd\n",
		(int)((cmd->result) >> 16));
	(cmd->scsi_done) (cmd);

	DEC_REF_CNT(vhba);
	return 0;
}

/*
 * The queuecommand has changed from 2.6.37 where it is
 * now lock-less and the prototype has changed.
 * In order to provide backward compatibility a MACRO
 * is provided by linux which will call queuecommand
 * with host_lock held. We will use that MACRO so that the
 * behavior is the same before 2.6.37
 * Please see Documentation/scsi/scsi_mid_low_api.txt in
 * linux kernel tree and the following URL
 * for discussion on lockless queuecommand.
 * http://www.spinics.net/lists/linux-scsi/msg48200.html
 */

#if !defined(DEF_SCSI_QCMD)

#define	xg_vhba_queuecommand	xg_vhba_queuecommand_lck

#else

DEF_SCSI_QCMD(xg_vhba_queuecommand)
#endif
struct scsi_host_template xg_vhba_driver_template = {
	.module = THIS_MODULE,
	.name = "xsvhba",
	.proc_name = "xsvhba",
	.queuecommand = xg_vhba_queuecommand,
	.eh_abort_handler = xg_vhba_eh_abort,
	.eh_device_reset_handler = xg_vhba_eh_device_reset,
	.eh_bus_reset_handler = xg_vhba_eh_bus_reset,
	.eh_host_reset_handler = xg_vhba_eh_host_reset,
	.slave_configure = xg_vhba_slave_configure,
#ifdef CONFIG_SCSI_QLA2xxx_FAILOVER
	.ioctl = xg_vhba_ioctl,
#endif
	.this_id = -1,
	.cmd_per_lun = 1,
	.use_clustering = ENABLE_CLUSTERING,
/* Xsigo limit is 6 */
	.sg_tablesize = 1,
/* 512 secs * 512 bytes = VH limit (256 KB) */
	.max_sectors = VHBA_DEFAULT_TRANSFER_SIZE,
	.use_blk_tags = 1,
};

void sp_put(struct virtual_hba *vhba, struct srb *sp)
{
	if ((sp->cmd) && (sp->cmd->scsi_done))
		(*(sp->cmd)->scsi_done) (sp->cmd);
	kfree(sp);
}

static int xg_vhba_eh_abort(struct scsi_cmnd *cmd)
{
	struct virtual_hba *vhba;
	struct srb *sp, *sp1;
	unsigned int b, t, l;
	struct scsi_xg_vhba_host *ha = NULL;
	unsigned long flags = 0;
	int iocb_handle = 0;
	int i, ret = FAILED;

	vhba = vhba_get_context_by_idr((u32) *(cmd->device->host->hostdata));

	if (vhba == NULL) {
		dprintk(TRC_ERRORS, NULL,
			"Could not find vhba for this command\n");
		return FAILED;
	}
	ha = vhba->ha;

	spin_lock_irqsave(&ha->io_lock, flags);

	sp = (struct srb *)CMD_SP(cmd);

	if (sp == NULL) {
		dprintk(TRC_INFO, vhba, "cmd already done cmd=%p\n", cmd);
		ret = FAILED;
		spin_unlock_irqrestore(&ha->io_lock, flags);
		goto out;
	}

	/* Generate LU queue on bus, target, LUN */
	b = cmd->device->channel;
	t = cmd->device->id;
	l = cmd->device->lun;

	/*
	 * Print the type of command and size of the IO being aborted.
	 */
	dprintk(TRC_INFO, vhba,
		"Abort cmd called for sp=%p, cmd=%p,", sp, cmd);
	dprintk(TRC_INFO, vhba,	" opcode/len = 0x%x/0x%x\n",
		cmd->cmnd[0], scsi_bufflen(cmd));

	atomic_inc(&vhba->abort_count);

	for (i = 0; i < MAX_OUTSTANDING_COMMANDS; i++) {
		sp1 = ha->outstanding_cmds[i];
		if (sp1 == NULL)
			continue;
		if (sp1->cmd == cmd) {
			/*
			 * We found the command. sp1 must be same as sp, if
			 * not, we have a duplicate command in the list, and
			 * we should fail this abort.
			 */
			if (sp1 != sp) {
				dprintk(TRC_INFO, vhba,
					"Duplicate cmd in Outstanding array: ");
				dprintk(TRC_INFO, vhba, "sp=%p, cmd=%p,sp1=%p",
					 sp, cmd, sp1);
				spin_unlock_irqrestore(&ha->io_lock, flags);
				ret = FAILED;
				goto out;
			}
			break;
		}
	}
	/*
	 * If IOP did not respond to the first abort and it
	 * failed through this routine, it is possible that the IOP
	 * never got a chance to look at the abort and the command
	 * about to be aborted crossed paths with the abort failure.
	 * In that case, mark the second attempt to abort this command
	 * as success.
	 */
	if ((sp->state == VHBA_IO_STATE_ABORTED) ||
	    (sp->state == VHBA_IO_STATE_ABORT_NEEDED)) {
		spin_unlock_irqrestore(&ha->io_lock, flags);
		goto success;
	}

	if (i == MAX_OUTSTANDING_COMMANDS) {
		if (atomic_read(&ha->ib_status) == VHBA_IB_DEAD) {
			spin_unlock_irqrestore(&ha->io_lock, flags);
			ret = FAILED;
			goto out;
		}
		dprintk(TRC_INFO, vhba,
			"Failing Abort(): cant find sp:0x%p, ", sp);
		dprintk(TRC_INFO, vhba,	"cmd:0x%p sp->cmd:0x%p", cmd, sp->cmd);
		spin_unlock_irqrestore(&ha->io_lock, flags);
		ret = FAILED;
		goto out;
	}

	sp->state = VHBA_IO_STATE_ABORTING;
	iocb_handle = sp->iocb_handle;

	/*
	 * It may take upto 30 seconds for a target to transition from
	 * LOST to ONLINE/DEAD state. Aborts will continue to fail during
	 * that time. Allow that much time before starting recovery.
	 */

	if (((sp->abort_cnt)++ > vhba_abort_recovery_count) &&
	    (atomic_read(&ha->ib_status) == VHBA_IB_UP)) {
		/*
		 * We are stuck in ABORT loop due to IOP/agent being stuck
		 * Purge all pending IOs and disconnect/reconnect QP
		 */
		spin_unlock_irqrestore(&ha->io_lock, flags);
		dprintk(TRC_INFO, vhba,
			 "Abort failed %d times", vhba_abort_recovery_count);
		dprintk(TRC_INFO, vhba, "initiating recovery action\n");
		atomic_set(&ha->ib_status, VHBA_IB_DEAD);
		vhba_purge_pending_ios(vhba);
		/*
		 * Let the Work Queue thread disconnect the Q pair.
		 */
		atomic_set((&ha->qp_status), VHBA_QP_TRYCONNECTING);
		ret = FAILED;
		goto out;

	}

	ret = vhba_send_abort(vhba, iocb_handle, t);
	if (ret) {
		/*
		 * If  QP is disconnected, complete the abort
		 */
		if (ret == VHBA_QP_DISCONNECTED) {
			if (ha->outstanding_cmds[iocb_handle]) {
				ha->outstanding_cmds[iocb_handle] = NULL;
				atomic_dec(&ha->stats.
					   io_stats.num_vh_q_reqs[sp->
								  queue_num]);
				goto success;
			} else {
				dprintk(TRC_INFO, vhba,
				"cmd completed while we were in abort()");
				dprintk(TRC_INFO, vhba, "cmd = %p sp->cmd = %p",
					cmd, sp->cmd);
				ret = FAILED;
				spin_unlock_irqrestore(&ha->io_lock, flags);
				goto out;
			}
		}
		ha->stats.scsi_stats.abort_fail_cnt++;
		dprintk(TRC_INFO, vhba, "Error - send abort failed %d\n", ret);
		ret = FAILED;
		sp->state = VHBA_IO_STATE_ACTIVE;
		spin_unlock_irqrestore(&ha->io_lock, flags);
		goto out;
	}
	if (sp->state == VHBA_IO_STATE_ABORTING) {
		ret = FAILED;
		if (sp->timer.function != NULL) {
			del_timer(&sp->timer);
			sp->timer.function = NULL;
			sp->timer.data = (unsigned long)NULL;
		}
		sp->state = VHBA_IO_STATE_ABORT_FAILED;
		spin_unlock_irqrestore(&ha->io_lock, flags);
		goto out;
	}

success:
	ha->stats.scsi_stats.abort_success_cnt++;
	if (sp->timer.function != NULL) {
		del_timer(&sp->timer);
		sp->timer.function = NULL;
		sp->timer.data = (unsigned long)NULL;
	}
	sp->cmd->result = DID_ABORT << 16;
	/*
	 * Reacquire the iocb handle and clear the
	 * outstanding array entry.
	 */

	iocb_handle = sp->iocb_handle;
	if (ha->outstanding_cmds[iocb_handle])
		ha->outstanding_cmds[iocb_handle] = NULL;
	CMD_SP(sp->cmd) = NULL;
	spin_unlock_irqrestore(&ha->io_lock, flags);

	complete_cmd_and_callback(vhba, sp, sp->cmd);

	/*
	 * Decrement Ref count for the original command
	 */
	DEC_REF_CNT(vhba);
	ret = SUCCESS;
	dprintk(TRC_INFO, vhba,
	"Abort Success for sp=%p, cmd=%p, ", sp, cmd);
	dprintk(TRC_INFO, vhba,	"sp->cmd=%p\n", sp->cmd);
out:
	DEC_REF_CNT(vhba);
	return ret;
}

static int xg_vhba_eh_device_reset(struct scsi_cmnd *cmd)
{
	struct virtual_hba *vhba;
	unsigned int b, t, l;
	struct scsi_xg_vhba_host *ha = NULL;
	int ret = FAILED;

	vhba = vhba_get_context_by_idr((u32) *(cmd->device->host->hostdata));

	if (vhba == NULL) {
		dprintk(TRC_ERR_RECOV, vhba,
			"Could not find vhba for this command\n");
		return FAILED;
	}

	ha = (struct scsi_xg_vhba_host *)vhba->ha;

	/* Generate LU queue on bus, target, LUN */
	b = cmd->device->channel;
	t = cmd->device->id;
	l = cmd->device->lun;

	dprintk(TRC_INFO, vhba,
		"Device Reset called for cmd=%p ", cmd);
	dprintk(TRC_INFO, vhba,	"tgt=%d, lun=%d\n", t, l);

	dprintk(TRC_INFO, vhba, "TGT reset:tgt=%d\n", t);
	ret = vhba_send_tgt_reset(vhba, t);
	if (ret && ret != VHBA_QP_DISCONNECTED) {
		ha->stats.scsi_stats.dev_reset_fail_cnt++;
		dprintk(TRC_INFO, vhba, "Error - send failed\n");
		ret = FAILED;
		goto out;
	} else
		vhba_taskmgmt_flush_ios(vhba, cmd->device->id, -1, 0);

	ret = SUCCESS;
	ha->stats.scsi_stats.dev_reset_success_cnt++;
	dprintk(TRC_INFO, vhba, "Device Reset Successful!\n");
out:
	DEC_REF_CNT(vhba);
	return ret;
}

static int xg_vhba_eh_bus_reset(struct scsi_cmnd *cmd)
{
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha;

	vhba = vhba_get_context_by_idr((u32) *(cmd->device->host->hostdata));

	if (vhba == NULL) {
		eprintk(vhba, "Could not find vhba for this command\n");
		return FAILED;
	}

	dprintk(TRC_INFO, vhba, "Bus reset called\n");

	ha = (struct scsi_xg_vhba_host *)vhba->ha;

	vhba_ib_disconnect_qp(vhba);
	vhba_purge_pending_ios(vhba);

	atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);

	ha->stats.scsi_stats.bus_reset_success_cnt++;
	dprintk(TRC_INFO, vhba, "Bus Reset Successful\n");

	DEC_REF_CNT(vhba);
	return SUCCESS;
}

static int xg_vhba_eh_host_reset(struct scsi_cmnd *cmd)
{
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha;

	vhba = vhba_get_context_by_idr((u32) *(cmd->device->host->hostdata));

	if (vhba == NULL) {
		eprintk(vhba, "Could not find vhba for this command\n");
		return FAILED;
	}

	dprintk(TRC_INFO, vhba, "Host Reset Called\n");

	ha = (struct scsi_xg_vhba_host *)vhba->ha;

	vhba_ib_disconnect_qp(vhba);
	vhba_purge_pending_ios(vhba);

	atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);

	ha->stats.scsi_stats.bus_reset_success_cnt++;
	dprintk(TRC_INFO, vhba, "Host Reset Successful\n");

	DEC_REF_CNT(vhba);
	return SUCCESS;
}

void copy_mem_info(struct info_str *info, char *data, int len)
{
	dprintk(TRC_FUNCS, NULL, "Entering\n");

	if (info->pos + len > info->offset + info->length)
		len = info->offset + info->length - info->pos;

	if (info->pos + len < info->offset) {
		info->pos += len;
		return;
	}

	if (info->pos < info->offset) {
		off_t partial;

		partial = info->offset - info->pos;
		data += partial;
		info->pos += partial;
		len -= partial;
	}

	if (len > 0) {
		memcpy(info->buffer, data, len);
		info->pos += len;
		info->buffer += len;
	}
	dprintk(TRC_FUNCS, NULL, "Returning\n");
}

static int copy_info(struct info_str *info, char *fmt, ...)
{
	va_list args;
	char buf[256];
	int len;

	va_start(args, fmt);
	len = vsprintf(buf, fmt, args);
	va_end(args);

	copy_mem_info(info, buf, len);
	return len;
}

int xg_vhba_proc_info(struct Scsi_Host *shost, char *buffer, char **start,
		      off_t offset, int length, int inout)
{
	struct virtual_hba *vhba = NULL;
	struct info_str info;
	struct scsi_xg_vhba_host *ha;
	int retval;

	vhba = vhba_get_context_by_idr((u32) *(shost->hostdata));
	if (vhba == NULL)
		return 0;
	ha = vhba->ha;

	if (inout) {
		DEC_REF_CNT(vhba);
		return length;
	}

	if (start)
		*start = buffer;

	info.buffer = buffer;
	info.length = length;
	info.offset = offset;
	info.pos = 0;

	/* start building the print buffer */
	copy_info(&info, "Xsigo Virtual Host Adapter\n");
	copy_info(&info, "Driver version %s\n", XG_VHBA_VERSION);

	retval = info.pos > info.offset ? info.pos - info.offset : 0;

	dprintk(TRC_PROC, vhba,
		"Exiting proc_info: info.pos=%d,", info.pos);
	dprintk(TRC_INFO, vhba, "offset=0x%lx, length=0x%x\n", offset, length);
	DEC_REF_CNT(vhba);
	return retval;
}

int vhba_recovery_action(struct scsi_xg_vhba_host *ha, u32 t)
{
	struct os_tgt *tq;
	struct srb *sp;
	struct virtual_hba *vhba = ha->vhba;
	unsigned long flags = 0;
	int i, count = 0;
	int rval = 0;

	tq = TGT_Q(ha, t);

	spin_lock_irqsave(&ha->io_lock, flags);
	for (i = 0; i < MAX_OUTSTANDING_COMMANDS; i++) {
		if (ha->outstanding_cmds[i]) {
			sp = ha->outstanding_cmds[i];
			if ((sp->tgt_queue == tq) &&
			    (sp->state == VHBA_IO_STATE_ABORTING)) {
				count++;
			}
		}

	}
	spin_unlock_irqrestore(&ha->io_lock, flags);
	if (count == VHBA_MAX_VH_Q_DEPTH) {
		/*
		 * We found all the commands stuck in ABORTING state and the
		 * queue is full.Fflush the defer list and purge all pending IOs
		 */
		dprintk(TRC_INFO, vhba,
			"Command queue is stuck with aborts.");
		dprintk(TRC_INFO, vhba,	" Take recovery actions.\n");

		atomic_set(&ha->ib_status, VHBA_IB_DEAD);

		vhba_purge_pending_ios(vhba);

		/*
		 * Let the Work Queue thread disconnect the Q pair.
		 */

		atomic_set((&ha->qp_status), VHBA_QP_TRYCONNECTING);

		rval = 1;
	}

	return rval;
}
