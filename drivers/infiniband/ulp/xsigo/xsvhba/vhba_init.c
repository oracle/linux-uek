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

/*
 * The VHBA driver is an i/f driver for the Xsigo virtual HBA (VHBA)
 */

#include <linux/delay.h>
#include <linux/highmem.h>

#include <scsi/scsi.h>
#include <linux/interrupt.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_transport_fc.h>
#include <rdma/ib_verbs.h>

#include "vhba_ib.h"
#include "vhba_defs.h"
#include "vhba_os_def.h"
#include "vhba_xsmp.h"
#include "vhba_align.h"
#include "vhba_scsi_intf.h"

#include "xs_compat.h"

static u32 vhba_target_bind(struct virtual_hba *vhba, u32 loop_id,
			    u8 *nwwn, u8 *pwwn, u32 port_id, s32 bound_value,
			    u32 lun_count, u8 *lun_map, u16 *lun_id,
			    u8 media_type);
static u32 vhba_map_unbound_targets(struct virtual_hba *vhba);
static struct os_tgt *vhba_tgt_alloc(struct virtual_hba *vhba, u32 tgt);
static void process_status_cont_entry(struct virtual_hba *vhba,
				      struct sts_cont_entry *pkt);

#define VHBA_CMD_TIMEOUT 18

static inline void add_to_disc_ports(struct fc_port *fcport,
				     struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	unsigned long flags;

	spin_lock_irqsave(&ha->list_lock, flags);
	list_add_tail(&fcport->list, &ha->disc_ports);
	spin_unlock_irqrestore(&ha->list_lock, flags);
}

int vhba_initialize(struct virtual_hba *vhba, struct vhba_xsmp_msg *msg)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	int rval = 0;

	ha->flags.online = 0;
	ha->device_flags = 0;

	rval = vhba_alloc_fmr_pool(vhba);
	if (rval) {
		eprintk(vhba, "Trouble allocating FMR pool.\n"
			" Returning %d\n", rval);
		return -1;
	}

	/* Initialize VHBA request, IB queues, etc */
	rval = vhba_init_rings(vhba);
	if (rval) {
		eprintk(vhba, "Trouble initializing rings.\n"
			" Returning %d\n", rval);
		vhba_dealloc_fmr_pool(vhba);
	}
	return rval;
}

int vhba_init_rings(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	int i;

	for (i = 0; i < MAX_OUTSTANDING_COMMANDS; i++)
		ha->outstanding_cmds[i] = NULL;

	ha->current_outstanding_cmd = 0;

	ha->request_ring_ptr = ha->request_ring;
	*ha->req_ring_rindex = 0;
	ha->req_ring_windex = 0;
	ha->req_q_cnt = ha->request_q_length;

	return 0;
}

void complete_cmd_and_callback(struct virtual_hba *vhba, struct srb *sp,
			       struct scsi_cmnd *cp)
{
	int sg_count;
	u32 request_bufflen;
	struct scatterlist *request_buffer;

	/*
	 * Grab the outstanding command
	 * make the callback and pass the status
	 */
	if (sp && cp) {
		if (sp->cmd != NULL) {
			sg_count = scsi_sg_count(sp->cmd);
			request_buffer = scsi_sglist(sp->cmd);
			request_bufflen = scsi_bufflen(sp->cmd);

			if (sp->flags & SRB_DMA_VALID) {
				sp->flags &= ~SRB_DMA_VALID;
				/* Ummap the memory used for this I/O */
				if (sg_count) {
					ib_dma_unmap_sg(vhba->
							xsmp_info.ib_device,
							request_buffer,
							sg_count,
							sp->
							cmd->sc_data_direction);

					vhba_unmap_buf_fmr(vhba,
							   sp, sp->tot_dsds);

				} else if (request_bufflen) {
					ib_dma_unmap_single(vhba->xsmp_info.
						ib_device, sp->dma_handle,
						request_bufflen,
						sp->cmd->sc_data_direction);

					vhba_unmap_buf_fmr(vhba, sp,
							   sp->tot_dsds);
					if (sp->unaligned_sg)
						vhba_tear_bounce_buffer(sp);
				}
			}
		} else
			dprintk(TRC_ERRORS, vhba, "sp cmd null\n");
		sp_put(vhba, sp);
	}
}

int vhba_purge_pending_ios(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct srb *sp;
	struct scsi_cmnd *cp;
	int i, queue_num;
	unsigned long flags = 0;

	spin_lock_irqsave(&ha->io_lock, flags);
	for (i = 0; i < MAX_OUTSTANDING_COMMANDS; i++) {
		if (ha->outstanding_cmds[i]) {
			sp = ha->outstanding_cmds[i];
			cp = sp->cmd;
			cp->result = DID_NO_CONNECT << 16;
			/* Delete SCSI timer */
			if (sp->timer.function != NULL) {
				del_timer(&sp->timer);
				sp->timer.function = NULL;
				sp->timer.data = (unsigned long)NULL;
			}
			ha->outstanding_cmds[i] = NULL;
			CMD_SP(sp->cmd) = NULL;
			spin_unlock_irqrestore(&ha->io_lock, flags);
			complete_cmd_and_callback(vhba, sp, cp);
			DEC_REF_CNT(vhba);
			spin_lock_irqsave(&ha->io_lock, flags);
			queue_num = sp->queue_num;

			dprintk(TRC_SCSI, vhba,
				"dec q cnt for vhba %p q %d\n",
				vhba, queue_num);
			if (atomic_read
			    (&ha->stats.io_stats.num_vh_q_reqs[queue_num]) != 0)
				atomic_dec(&ha->stats.io_stats.
					   num_vh_q_reqs[queue_num]);
		}
	}
	spin_unlock_irqrestore(&ha->io_lock, flags);
	return 0;
}

void vhba_taskmgmt_flush_ios(struct virtual_hba *vhba, int tgt_id, int lun,
			     int lun_reset_flag)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct srb *sp;
	struct scsi_cmnd *cp;
	int i, queue_num;
	unsigned long flags = 0;

	spin_lock_irqsave(&ha->io_lock, flags);
	for (i = 0; i < MAX_OUTSTANDING_COMMANDS; i++) {
		if (ha->outstanding_cmds[i]) {
			sp = ha->outstanding_cmds[i];
			cp = sp->cmd;
			if ((lun_reset_flag && (cp->device->id == tgt_id) &&
			     (cp->device->lun == lun)) ||
			    ((lun_reset_flag == 0) &&
			     (cp->device->id == tgt_id))) {

				cp->result = DID_NO_CONNECT << 16;
				if (sp->timer.function != NULL) {
					del_timer(&sp->timer);
					sp->timer.function = NULL;
					sp->timer.data = (unsigned long)NULL;
				}
				ha->outstanding_cmds[i] = NULL;
				CMD_SP(sp->cmd) = NULL;
				spin_unlock_irqrestore(&ha->io_lock, flags);

				complete_cmd_and_callback(vhba, sp, cp);
				DEC_REF_CNT(vhba);

				spin_lock_irqsave(&ha->io_lock, flags);

				queue_num = sp->queue_num;

				dprintk(TRC_SCSI, vhba,
					"dec q cnt for vhba %p q %d\n",
					vhba, queue_num);
				if (atomic_read
				    (&ha->stats.io_stats.
				     num_vh_q_reqs[queue_num]) != 0)
					atomic_dec(&ha->stats.io_stats.
						   num_vh_q_reqs[queue_num]);
			}
		}
	}
	spin_unlock_irqrestore(&ha->io_lock, flags);
}

void process_status_entry(struct virtual_hba *vhba, struct sts_entry_24xx *sts)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct srb *sp;
	struct scsi_cmnd *cp;
	struct os_tgt *tq;
	unsigned long flags;
	u8 *rsp_info, *sense_data;
	u8 *cdb_ptr, *byte_ptr;
	u8 lscsi_status;
	u16 comp_status, scsi_status;
	s32 resid;
	u32 sense_len, rsp_info_len, resid_len;
	u32 queue_num;
	u32 request_bufflen;

	byte_ptr = (u8 *) sts;
	byte_ptr = byte_ptr + 8;
	sts = (struct sts_entry_24xx *)byte_ptr;
	cdb_ptr = byte_ptr;

	sts->handle &= 0x000003ff;
	comp_status = le16_to_cpu(sts->comp_status);
	scsi_status = le16_to_cpu(sts->scsi_status) & SS_MASK;

	ha->stats.io_stats.total_io_rsp++;

	dprintk(TRC_IO, vhba, "comp status %x scsi_status %x handle %x\n",
		(int)le16_to_cpu(sts->comp_status),
		(int)le16_to_cpu(sts->scsi_status),
		(int)le16_to_cpu(sts->handle));

	if (sts->handle < MAX_OUTSTANDING_COMMANDS) {

		spin_lock_irqsave(&ha->io_lock, flags);
		sp = ha->outstanding_cmds[sts->handle];

		if (sp) {
			queue_num = sp->queue_num;

			atomic_dec(&ha->stats.
				   io_stats.num_vh_q_reqs[queue_num]);

			if (sp->state == VHBA_IO_STATE_ABORTING) {
				dprintk(TRC_INFO, vhba,
					"Aborting IO: sp:0x%p, sp->cmd:0x%p\n",
					sp, sp->cmd);

				dprintk(TRC_ERR_RECOV, vhba,
					"scsi_status= 0x%x\n",
					(int)le16_to_cpu(sts->scsi_status));

				sp->state = VHBA_IO_STATE_ABORTED;
				sp->abort_cnt = 0;
				spin_unlock_irqrestore(&ha->io_lock, flags);
				return;
			}
			if (sp->state == VHBA_IO_STATE_ABORT_FAILED) {
				sp->state = VHBA_IO_STATE_ABORT_NEEDED;
				sp->abort_cnt = 0;
				spin_unlock_irqrestore(&ha->io_lock, flags);
				return;
			}

			ha->outstanding_cmds[sts->handle] = NULL;
			CMD_SP(sp->cmd) = NULL;
			spin_unlock_irqrestore(&ha->io_lock, flags);

		} else {
			spin_unlock_irqrestore(&ha->io_lock, flags);
			dprintk(TRC_SCSI_ERRS, vhba, "sp is null for hndl %d\n",
				(int)sts->handle);
		}

	} else if (sts->handle == MAX_OUTSTANDING_COMMANDS) {
		/*
		 * This indicates completion of a tsk mgmt command
		 * No corresponding sp to worry about
		 */
		dprintk(TRC_ERRORS, vhba,
			"Returning erroneously: hndl is 1024!\n");
		return;
	} else
		sp = NULL;

	if (sp == NULL) {
		dprintk(TRC_SCSI_ERRS, vhba, "sp is null. sts_handle= %u\n"
			" curr hndl = %u\n", (u32) sts->handle,
			(u32) ha->current_outstanding_cmd);
		/* Reset this adapter or I/O card, etc */
		return;
	}

	cp = sp->cmd;
	if (cp == NULL) {
		dprintk(TRC_ERRORS, vhba, "cmd already returned to OS\n"
			" hndl %u sp %p sp->state %d\n",
			(u32)sts->handle, sp, sp->state);
		return;
	}
	/*
	 * When abort is happening (sp is searched) so can't change
	 * the sp. Quietly store this response somewhere to be
	 * processed once this sp search is over
	 */
	if (sp->state == 1) {
		dprintk(TRC_ERRORS, vhba, "Command already aborted\n");
		return;
	}
	request_bufflen = scsi_bufflen(sp->cmd);

	/* Delete SCSI timer */
	if (sp->timer.function != NULL) {
		del_timer(&sp->timer);
		sp->timer.function = NULL;
		sp->timer.data = (unsigned long)NULL;
	}

	if (sts->entry_type == COMMAND_TYPE_7) {
		dprintk(TRC_ERRORS, vhba,
			"Received type 7 iocb back from QL\n");
		cp->result = DID_NO_CONNECT << 16;
		complete_cmd_and_callback(vhba, sp, cp);
		DEC_REF_CNT(vhba);
		return;
	}

	/* Decrement actthreads if used */

	lscsi_status = scsi_status & STATUS_MASK;

	CMD_ENTRY_STATUS(cp) = sts->entry_status;
	CMD_COMPL_STATUS(cp) = comp_status;
	CMD_SCSI_STATUS(cp) = scsi_status;

	sense_len = rsp_info_len = resid_len = 0;

	sense_len = le32_to_cpu(sts->sense_len);
	rsp_info_len = le32_to_cpu(sts->rsp_data_len);
	resid_len = le32_to_cpu(sts->rsp_residual_count);
	rsp_info = sts->data;
	sense_data = sts->data;
	host_to_fcp_swap(sts->data, sizeof(sts->data));

	/* Check for any FCP transport errors. */
	if (scsi_status & SS_RESPONSE_INFO_LEN_VALID) {
		sense_data += rsp_info_len;
		if (rsp_info_len > 3 && rsp_info[3]) {
			eprintk(vhba,
				"scsi(%ld:%d:%d:%d) FCP I/O protocol failure ",
				ha->host_no, cp->device->channel,
				(int)cp->device->id, (int)cp->device->lun);
			eprintk(vhba,
				" (%x/%02x%02x%02x%02x%02x%02x%02x%02x)... ",
				rsp_info_len, rsp_info[0], rsp_info[1],
				rsp_info[2], rsp_info[3], rsp_info[4],
				rsp_info[5], rsp_info[6], rsp_info[7]);
			eprintk(vhba, "retrying command\n");
			cp->result = DID_BUS_BUSY << 16;
			complete_cmd_and_callback(vhba, sp, cp);
			DEC_REF_CNT(vhba);
			return;
		}
	} else {
		rsp_info_len = 0;
	}

	/* Based on Host and scsi status generate status code for Linux */
	switch (comp_status) {
	case CS_COMPLETE:
		if (scsi_status == 0) {
			dprintk(TRC_IO, vhba, "hndl %d: sts ok\n",
				(int)sts->handle);
			cp->result = DID_OK << 16;
			break;
		}

		if (scsi_status & (SS_RESIDUAL_UNDER | SS_RESIDUAL_OVER)) {
			resid = resid_len;
			scsi_set_resid(cp, resid);
			CMD_RESID_LEN(cp) = resid;
		}

		cp->result = DID_OK << 16 | lscsi_status;
		if (lscsi_status == SS_BUSY_CONDITION)
			break;
		if (lscsi_status != SS_CHECK_CONDITION)
			break;

		/* Copy Sense Data into sense buffer. */
		memset(cp->sense_buffer, 0, SCSI_SENSE_BUFFERSIZE);

		if (!(scsi_status & SS_SENSE_LEN_VALID))
			break;

		if (sense_len >= SCSI_SENSE_BUFFERSIZE)
			sense_len = SCSI_SENSE_BUFFERSIZE;

		sp->request_sense_length = sense_len;
		sp->request_sense_ptr = cp->sense_buffer;

		if (sp->request_sense_length >
		    (sizeof(sts->data) - rsp_info_len))
			sense_len = sizeof(sts->data) - rsp_info_len;

		memcpy(cp->sense_buffer, sense_data, sense_len);
		CMD_ACTUAL_SNSLEN(cp) = sense_len;
		sp->request_sense_ptr += sense_len;
		sp->request_sense_length -= sense_len;
		if (sp->request_sense_length != 0)
			ha->status_srb = sp;

		dprintk(TRC_SCSI_ERRS, vhba, "Check condition Sense data,\n"
			"scsi(%ld:%d:%d:%d) scsi_status = %d\n",
			(long)ha->host_no, (int)cp->device->channel,
			(int)cp->device->id, (int)cp->device->lun, scsi_status);

		break;

	case CS_DATA_UNDERRUN:
		dprintk(TRC_SCSI, vhba, "UNDERRUN detected\n");

		resid = resid_len;
		if (scsi_status & SS_RESIDUAL_UNDER) {
			scsi_set_resid(cp, resid);
			CMD_RESID_LEN(cp) = resid;
		}

		/*
		 * Check to see if SCSI Status is non zero. If so report SCSI
		 * Status.
		 */
		if (lscsi_status != 0) {
			cp->result = DID_OK << 16 | lscsi_status;
			if (lscsi_status == SS_BUSY_CONDITION)
				break;
			if (lscsi_status != SS_CHECK_CONDITION)
				break;

			/* Copy Sense Data into sense buffer */
			memset(cp->sense_buffer, 0, SCSI_SENSE_BUFFERSIZE);

			if (!(scsi_status & SS_SENSE_LEN_VALID))
				break;

			if (sense_len >= SCSI_SENSE_BUFFERSIZE)
				sense_len = SCSI_SENSE_BUFFERSIZE;

			sp->request_sense_length = sense_len;
			sp->request_sense_ptr = cp->sense_buffer;

			if (sp->request_sense_length >
			    (sizeof(sts->data) - rsp_info_len))
				sense_len = sizeof(sts->data) - rsp_info_len;

			memcpy(cp->sense_buffer, sense_data, sense_len);
			CMD_ACTUAL_SNSLEN(cp) = sense_len;

			sp->request_sense_ptr += sense_len;
			sp->request_sense_length -= sense_len;
			if (sp->request_sense_length != 0)
				ha->status_srb = sp;

			dprintk(TRC_SCSI_ERRS, vhba,
				"Check condition Sense data, ");
			dprintk(TRC_SCSI_ERRS, vhba,
				"scsi(%ld:%d:%d:%d) cmd=%p pid=%ld\n",
				ha->host_no, cp->device->channel,
				(int)cp->device->id, (int)cp->device->lun, cp,
				cp->serial_number);

		} else {

			/*
			 * If RISC reports underrun and target does not report
			 * it then we must have a lost frame, so tell upper
			 * layer to retry it by reporting a bus busy.
			 */
			if (!(scsi_status & SS_RESIDUAL_UNDER)) {
				eprintk(vhba, "scsi(%ld:%d:%d:%d) Dropped\n",
					ha->host_no, cp->device->channel,
					(int)cp->device->id,
					(int)cp->device->lun);
				eprintk(vhba,
					"frame(s) detected (%x of %d bytes)..",
					resid, (u32)request_bufflen);
				eprintk(vhba, "retrying command.\n");

				cp->result = DID_BUS_BUSY << 16;

				break;
			}

			/* Handle mid-layer underflow */
			if ((unsigned)(request_bufflen - resid) <
								cp->underflow) {
				eprintk(vhba, "scsi(%ld:%d:%d:%d):Mid-layer\n",
					ha->host_no, cp->device->channel,
					(int)cp->device->id,
					(int)cp->device->lun);
				eprintk(vhba,
					"underflow detected (%x of %d bytes) ",
					resid, (u32)request_bufflen);
				eprintk(vhba, "...returning error status.\n");
				cp->result = DID_ERROR << 16;
				break;
			}

			cp->result = DID_OK << 16;
		}
		break;

	case CS_DATA_OVERRUN:

		eprintk(vhba, "scsi(%ld:%d:%d): OVERRUN status detected\n",
			ha->host_no, (int)cp->device->id, (int)cp->device->lun);
		eprintk(vhba, " 0x%x-0x%x\n", comp_status, scsi_status);
		dprintk(TRC_SCSI_ERRS, vhba, "CDB: 0x%x 0x%x 0x%x 0x%x 0x%x\n",
			cp->cmnd[0], cp->cmnd[1], cp->cmnd[2], cp->cmnd[3],
			cp->cmnd[4]);
		dprintk(TRC_SCSI_ERRS, vhba, " 0x%x\n", cp->cmnd[5]);

		dprintk(TRC_SCSI_ERRS, vhba, "PID=0x%lx req=0x%x xtra=0x%x --",
			cp->serial_number, request_bufflen, resid_len);
		dprintk(TRC_SCSI_ERRS, vhba, "\nreturning DID_ERROR status\n");
		cp->result = DID_ERROR << 16;
		break;

	case CS_PORT_LOGGED_OUT:
	case CS_PORT_CONFIG_CHG:
	case CS_PORT_BUSY:
	case CS_INCOMPLETE:
	case CS_PORT_UNAVAILABLE:
		/*
		 * If the port is in Target Down state, return all IOs for this
		 * Target with DID_NO_CONNECT ELSE Queue the IOs in the
		 * retry_queue.
		 */
		tq = TGT_Q(ha, cp->device->id);
		if (tq) {
			dprintk(TRC_INFO, vhba,
				"Port Down: Logged Out/Unavailable: ");
			dprintk(TRC_INFO, vhba,
				"port_id:0x%x, PWWN:%lx comp_status=0x%x\n",
				tq->fcport->d_id.b24, (unsigned long)
				wwn_to_u64(tq->fcport->port_name), comp_status);
		}
		cp->result = DID_BUS_BUSY << 16;
		break;

	case CS_RESET:
		dprintk(TRC_INFO, vhba,
			"CS_RESET:cp=%p, scsi_status=0x%x\n", cp, scsi_status);

		cp->result = DID_RESET << 16;
		break;

	case CS_ABORTED:
		/*
		 * hv2.19.12 - DID_ABORT does not retry the request if we
		 * aborted this request then abort otherwise it must be a
		 * reset.
		 */
		dprintk(TRC_INFO, vhba,
			"CS_ABORTED, cp=%p, scsi_status=0x%x\n", cp,
			scsi_status);

		cp->result = DID_RESET << 16;
		break;

	case CS_TIMEOUT:
		cp->result = DID_BUS_BUSY << 16;

		vhba->cs_timeout_count++;
		dprintk(TRC_INFO, vhba,
			"CS_TIMEOUT for cmd=%p, opcode/len/status 0x%x/0x%x/0x%x\n",
			cp, cp->cmnd[0], scsi_bufflen(cp), scsi_status);
		break;

	case CS_QUEUE_FULL:
		dprintk(TRC_INFO, vhba, "scsi(%ld): QUEUE FULL status\n",
			 ha->host_no);
		dprintk(TRC_INFO, vhba, " detected 0x%x-0x%x\n", comp_status,
			scsi_status);

		/* SCSI Mid-Layer handles device queue full */
		cp->result = DID_OK << 16 | lscsi_status;
		break;

	case CS_DMA:
		dprintk(TRC_INFO, vhba, "dma error\n");
		cp->result = DID_NO_CONNECT << 16;
		break;

	default:
		eprintk(vhba, "SCSI error with unknown status\n");
		eprintk(vhba, " 0x%x-0x%x\n", comp_status, scsi_status);

		cp->result = DID_ERROR << 16;
		break;
	}

	/* If no continuation stat */
	if (ha->status_srb == NULL) {
		complete_cmd_and_callback(vhba, sp, cp);
		DEC_REF_CNT(vhba);
	} else {
		struct sts_cont_entry *ptr;

		if (sts->entry_count > 1) {
			dprintk(TRC_SCSI_ERRS, vhba, "non null sts srb!\n");
			ptr = (struct sts_cont_entry *)(byte_ptr +
							sizeof(struct
							       sts_entry_24xx));
			process_status_cont_entry(vhba, ptr);
		} else {
			sp->request_sense_length = 0;
			complete_cmd_and_callback(vhba, sp, cp);
			DEC_REF_CNT(vhba);
		}
	}
}

static
void process_status_cont_entry(struct virtual_hba *vhba,
			       struct sts_cont_entry *pkt)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct srb *sp = ha->status_srb;
	struct scsi_cmnd *cp;
	u8 sense_sz;

	if (sp != NULL) {
		cp = sp->cmd;
		if (cp == NULL) {
			eprintk(vhba, "Cmd already returned back\n");
			eprintk(vhba, " to OS sp %p sp->state %d\n",
				sp, sp->state);
			ha->status_srb = NULL;
			return;
		}

		if (sp->request_sense_length != 0) {
			if (sp->request_sense_length > sizeof(pkt->data))
				sense_sz = sizeof(pkt->data);
			else
				sense_sz = sp->request_sense_length;

			host_to_fcp_swap(pkt->data, sizeof(pkt->data));

			dprintk(TRC_IO, vhba, "memcpy of %d bytes\n", sense_sz);
			memcpy(sp->request_sense_ptr, pkt->data, sense_sz);

			ha->status_srb = NULL;
		}
		complete_cmd_and_callback(vhba, sp, cp);
		DEC_REF_CNT(vhba);
	}
}

void process_dqp_msg(struct virtual_hba *vhba, u8 *msg, int length)
{
	int type;
	struct abort_entry_24xx *abt;

	type = *(u8 *) (msg + 8);

	if ((type == STATUS_TYPE) || (type == COMMAND_TYPE_7))
		process_status_entry(vhba, (struct sts_entry_24xx *)msg);
	else if (type == STATUS_CONT_TYPE)
		process_status_cont_entry(vhba, (struct sts_cont_entry *)msg);
	else if (type == ABORT_IOCB_TYPE) {
		abt = (struct abort_entry_24xx *)msg;
		if (abt->nport_handle) {
			eprintk(vhba, "Could not Abort the command indexed\n");
			eprintk(vhba, " by handle %d\n", abt->handle);
		}
	} else
		eprintk(vhba, "Unknown message from VH\n");
}

int vhba_set_tgt_offline(struct virtual_hba *vhba, struct os_tgt *tq)
{
	int tgt = tq->fcport->os_target_id;

	dprintk(TRC_TIMER, vhba, "RSCN: setting tgt %d offline\n", tgt);
	atomic_set(&tq->fcport->state, FCS_DEVICE_LOST);

	return 0;
}

int vhba_set_all_tgts_offline(struct virtual_hba *vhba)
{
	int tgt;
	struct os_tgt *tq;
	struct scsi_xg_vhba_host *ha = vhba->ha;

	for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
		tq = TGT_Q(ha, tgt);
		if (!tq)
			continue;
		vhba_set_tgt_offline(vhba, tq);
	}
	return 0;
}

int vhba_set_tgt_online(struct virtual_hba *vhba, struct os_tgt *tq)
{
	atomic_set(&tq->fcport->state, FCS_ONLINE);
	set_bit(TQF_ONLINE, &tq->flags);
	return 0;
}

static inline struct fc_rport *xg_rport_add(struct fc_port *fcport,
					    struct scsi_xg_vhba_host *ha)
{
	struct fc_rport_identifiers rport_ids;
	struct fc_rport *rport;

	rport_ids.node_name = wwn_to_u64(fcport->node_name);
	rport_ids.port_name = wwn_to_u64(fcport->port_name);
	rport_ids.port_id = fcport->d_id.b.domain << 16 |
	    fcport->d_id.b.area << 8 | fcport->d_id.b.al_pa;
	rport_ids.roles = FC_PORT_ROLE_FCP_TARGET;	/* Hardcode the role */
	fcport->rport = rport = fc_remote_port_add(ha->host, 0, &rport_ids);
	if (!rport) {
		pr_err("FC remote port add failed\n");
		return NULL;
	}
	pr_info("scsi(%ld:%d)\n",  ha->host_no, fcport->os_target_id);
	pr_info(" rport_add: PWWN:%lx NWWN:%lx PORT_ID:%x\n",
		(unsigned long)rport_ids.port_name,
		(unsigned long)rport_ids.node_name, rport_ids.port_id);
	rport->supported_classes = fcport->supported_classes;
	*((struct fc_port **) rport->dd_data) = fcport;
	fc_remote_port_rolechg(rport, rport_ids.roles);
	return rport;
}

void vhba_update_rports(struct work_struct *work)
{
	struct xsvhba_work *xwork = container_of(work, struct xsvhba_work,
						 work);
	int tgt;
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha;

	vhba = vhba_get_context_by_idr(xwork->idr);
	if (vhba == NULL) {
		dprintk(TRC_INFO, NULL,
			"Could not find vhba for updating rport\n");
		goto out;
	}
	ha = vhba->ha;

	for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
		struct os_tgt *tq;

		tq = TGT_Q(ha, tgt);
		if (tq && tq->fcport) {
			eprintk(vhba, "rport = %p, state = %d\n",
				tq->fcport->rport,
				atomic_read(&tq->fcport->state));

			if (atomic_read(&tq->fcport->state) == FCS_ONLINE) {
				/* Check if you've already reported the rport */
				if (tq->fcport->rport) {
					continue;
				} else {
					eprintk(vhba, "Updating rports\n");
					tq->fcport->rport =
					    xg_rport_add(tq->fcport, ha);
					if (!tq->fcport->rport)
						eprintk(ha->vhba,
							"Error registering ");
						eprintk(ha->vhba,
							"scsi(%ld:%d)\n",
							ha->host_no,
							tq->
							fcport->os_target_id);
				}
			} else {
				struct fc_rport *remote_port;

				if ((tq->fcport->rport) &&
				    (atomic_read(&tq->fcport->state)
				     == FCS_DEVICE_DEAD)) {
					/* Target dead remove rport from OS */
					eprintk(ha->vhba,
						"removing scsi(%ld:%d) ",
						ha->host_no,
						tq->fcport->os_target_id);
					eprintk(ha->vhba,
						"state: 0x%x\n",
						atomic_read(&tq->
							    fcport->state));
					remote_port = tq->fcport->rport;
					tq->fcport->rport = NULL;
					fc_remote_port_delete(remote_port);
				}
			}
		}
	}
	DEC_REF_CNT(vhba);
	vhba->scan_reqd = 1;
out:
	kfree(xwork);
}

void schedule_update_rports(struct scsi_xg_vhba_host *ha)
{
	struct xsvhba_work *xwork =
	    kmalloc(sizeof(struct xsvhba_work), GFP_ATOMIC);

	if (!xwork) {
		eprintk(NULL, "Error allocating work\n");
		return;
	}
	xwork->idr = ha->vhba->idr;
	INIT_WORK(&xwork->work, vhba_update_rports);
	queue_work(vhba_workqueuep, &xwork->work);
}

void vhba_handle_scan(struct work_struct *work)
{
	struct xsvhba_work *xwork = container_of(work, struct xsvhba_work,
						 work);

	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha;

	vhba = vhba_get_context_by_idr(xwork->idr);
	if (vhba == NULL) {
		dprintk(TRC_INFO, NULL, "Could not find vhba for scan\n");
		goto out;
	}
	ha = vhba->ha;

	if (atomic_read(&vhba->vhba_state) == VHBA_STATE_SCAN) {
		if (vhba->scanned_once == 0) {
			vhba->scanned_once = 1;

		} else {
			dprintk(TRC_INFO, vhba, "(target_count = %d)\n",
				ha->target_count);
			dprintk(TRC_INFO, vhba, " max_targets = %d)\n",
				ha->max_targets);
			if ((ha->target_count > 0) || (ha->max_targets > 0)) {
				u32 t_id;
				struct os_tgt *tq;
				struct scsi_device *device;

				dprintk(TRC_INFO, vhba,
					"changing to VHBA_STATE_ACTIVE ");
				dprintk(TRC_INFO, vhba,
					"since we have targets..\n");

				for (t_id = 0; t_id < ha->max_targets; t_id++) {
					tq = TGT_Q(ha, t_id);
					if (!tq)
						continue;
					if (atomic_read(&ha->link_state) !=
					    LINK_DOWN &&
					    atomic_read(&tq->fcport->state) !=
					    FCS_DEVICE_LOST) {
						device =
						    scsi_device_lookup(ha->host,
								       0, t_id,
								       0);

						if (device == NULL)
							continue;
						if (device->sdev_state ==
						    SDEV_OFFLINE) {
							device->sdev_state =
							    SDEV_RUNNING;
						}
						scsi_device_put(device);
					}
				}
			}
		}
		atomic_set(&vhba->vhba_state, VHBA_STATE_ACTIVE);
	}

	/* on the first install, it seems like you might need to register
	   this here.  TGT update messages don't come in the first time.  */
	schedule_update_rports(ha);

	DEC_REF_CNT(vhba);
out:
	kfree(xwork);
}

void vhba_handle_targets(struct virtual_hba *vhba,
			 struct vhba_tgt_status_msg tgt_status_msg, int *found)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct os_tgt *tq;
	int loop_id = (u32) be16_to_cpu(tgt_status_msg.loop_id);
	int tgt, k, lun_count;

	for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
		tq = TGT_Q(ha, tgt);
		if (tq && (memcmp(tgt_status_msg.wwpn, tq->fcport->port_name,
				  WWN_SIZE) == 0)) {
			*found = 1;
			if (atomic_read(&tq->fcport->state) != FCS_ONLINE) {
				ha->stats.fc_stats.rscn_up_cnt++;
				atomic_set(&tq->fcport->state, FCS_ONLINE);
				set_bit(TQF_ONLINE, &tq->flags);
				dprintk(TRC_INFO, vhba,
					"RSCN:Target online");
				dprintk(TRC_INFO, vhba,
					" msg received: PWWN: %llx, ",
					wwn_to_u64(tgt_status_msg.wwpn));
				dprintk(TRC_INFO, vhba,
					"port_id: 0x%x,loop_id: 0x%x\n",
					be32_to_cpu(tgt_status_msg.port_id),
					loop_id);
				dprintk(TRC_INFO, vhba,
					"RSCN: old PWWN: %llx, old port_id: ",
					wwn_to_u64(tq->fcport->port_name));
				dprintk(TRC_INFO, vhba,
					"0x%x, old loop_id: 0x%x\n",
					tq->fcport->d_id.b24,
					tq->fcport->loop_id);
				tq->fcport->loop_id = (u32)
				    be16_to_cpu(tgt_status_msg.loop_id);
				tq->fcport->d_id.b24 = tq->d_id.b24 =
				    be32_to_cpu(tgt_status_msg.port_id);
				for (k = 0; k < WWN_SIZE; k++)
					tq->port_name[k] =
					    tgt_status_msg.wwpn[k];

				lun_count = (u32)
				    be16_to_cpu(tgt_status_msg.lun_count);
				if (lun_count != tq->fcport->lun_count) {
					dprintk(TRC_INFO, vhba,
						"RSCN Target online: lun count is ");
					dprintk(TRC_INFO, vhba, "different\n");
					vhba->scan_reqd = 1;
				} else {
					for (k = 0; k < lun_count; k++) {
						if (tq->fcport->lun_ids[k] !=
						    tgt_status_msg.lun_ids[k]) {
							dprintk(TRC_INFO,
								vhba,
								"RSCN Target ");
							dprintk(TRC_INFO,
								vhba,
								"online:lun id ");
							dprintk(TRC_INFO,
								vhba,
								"different\n");
							vhba->scan_reqd = 1;
							break;
						}
					}
				}
				for (k = 0; k < MAX_FIBRE_LUNS; k++)
					tq->fcport->lun_ids[k] = -1;
				for (k = 0; k < lun_count; k++)
					tq->fcport->lun_ids[k] =
					    tgt_status_msg.lun_ids[k];

				dprintk(TRC_INFO, NULL,
					"New Lun_count= %d\n", lun_count);
				tq->fcport->lun_count = lun_count;
				memcpy(tq->fcport->port_name, tq->port_name,
				       WWN_SIZE);
				vhba_set_tgt_online(vhba, tq);
			} else {
				/*
				 * Already in up state no need to process...
				 */
				dprintk(TRC_INFO, vhba,
					"RSCN:Target online");
				dprintk(TRC_INFO, vhba,
					" msg received for already enabled");
				dprintk(TRC_INFO, vhba,
					" device PWWN: %llx, ",
					wwn_to_u64(tgt_status_msg.wwpn));
				dprintk(TRC_INFO, vhba,
					"port_id: 0x%x,loop_id: 0x%x\n",
					be32_to_cpu(tgt_status_msg.port_id),
					loop_id);
				dprintk(TRC_INFO, vhba,
					"RSCN: old PWWN: %llx, old port_id: ",
					wwn_to_u64(tq->fcport->port_name));
				dprintk(TRC_INFO, vhba,
					"0x%x, old loop_id: 0x%x\n",
					tq->fcport->d_id.b24,
					tq->fcport->loop_id);

				ha->stats.fc_stats.rscn_multiple_up_cnt++;
				tq->fcport->loop_id = (u32)
				    be16_to_cpu(tgt_status_msg.loop_id);
				tq->fcport->d_id.b24 = tq->d_id.b24 =
				    be32_to_cpu(tgt_status_msg.port_id);
				for (k = 0; k < WWN_SIZE; k++)
					tq->port_name[k] =
					    tgt_status_msg.wwpn[k];
				lun_count = (u32)
				    be16_to_cpu(tgt_status_msg.lun_count);

				if (lun_count != tq->fcport->lun_count) {
					dprintk(TRC_INFO, vhba,
						"RSCN Target already online: lun");
					dprintk(TRC_INFO, vhba,
						" count is different\n");
					vhba->scan_reqd = 1;
				} else {
					for (k = 0; k < lun_count; k++) {
						if (tq->fcport->lun_ids[k] !=
						    tgt_status_msg.lun_ids[k]) {
							dprintk(TRC_INFO,
								vhba, "RSCN ");
							dprintk(TRC_INFO,
							vhba, "Target already");
							dprintk(TRC_INFO,
							vhba, " online: lun");
							dprintk(TRC_INFO,
							vhba, " count is ");
							dprintk(TRC_INFO,
							vhba, "different\n");
							vhba->scan_reqd = 1;
							break;
						}
					}
				}
				for (k = 0; k < MAX_FIBRE_LUNS; k++)
					tq->fcport->lun_ids[k] = -1;
				for (k = 0; k < lun_count; k++) {
					tq->fcport->lun_ids[k] =
					    tgt_status_msg.lun_ids[k];
					dprintk(TRC_INFO, NULL,
						"Lun id = %d\n",
						tq->fcport->lun_ids[k]);
				}
				dprintk(TRC_INFO, NULL,
					"New Lun_count= " "%d\n", lun_count);
				tq->fcport->lun_count = lun_count;
				memcpy(tq->fcport->port_name, tq->port_name,
				       WWN_SIZE);
			}
		}
		ha->stats.fc_stats.last_up_tgt = tgt;
	}
}

void process_cqp_msg(struct virtual_hba *vhba, u8 *msg, int length)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct vhba_discovery_msg *r_msg;
	struct vhba_discovery_cont_msg *r_cont_msg;
	struct vhba_tgt_status_msg tgt_status_msg;
	struct enable_rsp *enable_rsp;
	struct os_tgt *tq;
	struct tgt_info *tgt_msg;
	struct vhba_link_status *link_status_msg = NULL;
	struct xsvhba_work *xwork;
	int type, vp;
	int i, k, found;
	int work_submitted = 0;

	u8 port_name[WWN_SIZE];
	u8 node_name[WWN_SIZE];
	u32 lun_count;
	u32 tgt;
	u32 port_id;
	u32 loop_id;
	u32 t_count;
	s32 bound_value;
	u8 lun_map[MAX_FIBRE_LUNS >> 3];
	u16 lun_id[MAX_FIBRE_LUNS];
	u8 media_type;

	xwork = kmalloc(sizeof(struct xsvhba_work), GFP_ATOMIC);
	if (!xwork) {
		eprintk(NULL, "vhba_work kmalloc failed\n");
		return;
	}

	xwork->idr = vhba->idr;

	type = *(u8 *) msg;

	if (type == DISC_INFO_UPDATE) {
		r_msg = (struct vhba_discovery_msg *)msg;
		dprintk(TRC_INFO, vhba,
			"Got disc info from IOP." " length %d\n", length);

		ha->stats.fc_stats.disc_info_cnt++;

		if (be16_to_cpu(r_msg->target_count) == 0) {
			dprintk(TRC_INFO, vhba, "zero tgts discovered!\n");
			ha->target_count = 0;
			ha->max_targets = ha->target_count;
			ha->max_cont_segs = be16_to_cpu(r_msg->cont_count);
			dprintk(TRC_CQP, vhba,
				"Number of continuation segments = %d\n",
				ha->max_cont_segs);
			kfree(xwork);
			return;
		}

		ha->target_count = be16_to_cpu(r_msg->target_count);
		t_count = (u32) ha->target_count;
		dprintk(TRC_INFO, vhba, "Target Count %d\n", t_count);

		ha->max_targets = ha->target_count;
		ha->max_tgt_id = ha->max_targets;

		ha->max_cont_segs = be16_to_cpu(r_msg->cont_count);
		k = (int)ha->max_cont_segs;
		dprintk(TRC_CQP, vhba, "Cont segs %d\n", k);

		tgt_msg = (struct tgt_info *)(r_msg->tgt_data);

		for (i = 0; i < ha->target_count; i++) {
			/*
			 * use fcport from the message
			 * also get the fclun info
			 * check for return values...
			 */
			for (k = 0; k < WWN_SIZE; k++)
				port_name[k] = tgt_msg[i].wwpn[k];

			for (k = 0; k < WWN_SIZE; k++)
				node_name[k] = tgt_msg[i].wwnn[k];

			port_id = be32_to_cpu(tgt_msg[i].port_id);
			loop_id = (u32) (be16_to_cpu(tgt_msg[i].loop_id));
			bound_value =
			    be32_to_cpu(tgt_msg[i].persistent_binding);
			if ((bound_value != -1) &&
			    (bound_value >= MAX_FIBRE_TARGETS)) {
				bound_value = -1;
			}
			lun_count = (u32) (be16_to_cpu(tgt_msg[i].lun_count));

			dprintk(TRC_INFO, vhba,
				"PWWN: %llx, NWWN: %llx, ",
				wwn_to_u64(port_name),
				 wwn_to_u64(node_name));
			dprintk(TRC_INFO, vhba,
				"port_id(%x) loop_id(%x)",
				(int) port_id, (int)loop_id);
			dprintk(TRC_INFO, vhba,
				" bound_value(%d) lun_count(%d)\n",
				(int)bound_value, (int)lun_count);

			for (k = 0; k < lun_count; k++) {
				lun_id[k] = tgt_msg[i].lun_ids[k];
				dprintk(TRC_INFO, vhba,
					"lun id = %d\n", lun_id[k]);
			}

			media_type = tgt_msg[i].media_type;

			vhba_target_bind(vhba, loop_id, node_name, port_name,
					 port_id, bound_value, lun_count,
					 lun_map, lun_id, media_type);
		}

		vhba_set_tgt_count(vhba);

		if (ha->max_cont_segs == 0) {

			/* Map all unbound fcports to the tgt map */
			vhba_map_unbound_targets(vhba);

			/* Set the loop status to LINK_UP if already not up */
			if (atomic_read(&ha->link_state) != LINK_UP)
				atomic_set(&ha->link_state, LINK_UP);

			/*
			 * Let the workqueue handle the scsi scan
			 */

			atomic_set(&vhba->vhba_state, VHBA_STATE_SCAN);
			ha->discs_ready_flag = 1;
			INIT_WORK(&xwork->work, vhba_handle_scan);
			queue_work(vhba_workqueuep, &xwork->work);
			work_submitted = 1;

		}
		vhba->scan_reqd = 1;

	} else if (type == DISC_INFO_CONT_UPDATE) {
		r_cont_msg = (struct vhba_discovery_cont_msg *)msg;
		dprintk(TRC_INFO, vhba, "Got cont disc info from IOP\n");

		if ((ha->max_cont_segs == 0) &&
		    (ha->max_cont_segs < r_cont_msg->seg_num)) {
			dprintk(TRC_CQP, vhba,
				"Max cont segs in the" " DISC_INFO msg is 0\n");
			return;
		}

		t_count = (u32) be16_to_cpu(r_cont_msg->target_count);
		dprintk(TRC_INFO, vhba, "Cont Target Count %d\n", t_count);
		k = (int)be16_to_cpu(r_cont_msg->seg_num);

		if ((ha->target_count + t_count) <= MAX_FIBRE_TARGETS) {
			ha->target_count += t_count;

			tgt_msg = (struct tgt_info *)(r_cont_msg->tgt_data);
			for (i = 0; i < t_count; i++) {
				/*
				 * use fcport from the message
				 * also get the fclun info
				 * check for return values...
				 */
				for (k = 0; k < WWN_SIZE; k++)
					port_name[k] = tgt_msg[i].wwpn[k];

				for (k = 0; k < WWN_SIZE; k++)
					node_name[k] = tgt_msg[i].wwnn[k];

				port_id = be32_to_cpu(tgt_msg[i].port_id);
				loop_id = be16_to_cpu(tgt_msg[i].loop_id);
				bound_value =
				    be32_to_cpu(tgt_msg[i].persistent_binding);
				lun_count = be16_to_cpu(tgt_msg[i].lun_count);

				dprintk(TRC_INFO, vhba,
					"PWWN: %llx, NWWN: %llx, ",
					wwn_to_u64(port_name),
					wwn_to_u64(node_name));
				dprintk(TRC_INFO, vhba,
					"port_id(%x) loop_id(%x)",
					(int)port_id, (int)loop_id);
				dprintk(TRC_INFO, vhba,
					" bound_value(%d) lun_count(%d)\n",
					(int)bound_value, (int)lun_count);

				for (k = 0; k < lun_count; k++) {
					lun_id[k] = tgt_msg[i].lun_ids[k];
					dprintk(TRC_INFO, vhba,
						"lun id = %d\n", lun_id[k]);
				}

				media_type = tgt_msg[i].media_type;

				vhba_target_bind(vhba, loop_id, node_name,
						 port_name, port_id,
						 bound_value, lun_count,
						 lun_map, lun_id, media_type);
			}
		}

		dprintk(TRC_CQP, vhba, "max disc msgs cnt is %d\n",
			ha->max_cont_segs);
		dprintk(TRC_CQP, vhba,
			"disc cont update seg num is %d %d\n",
			be16_to_cpu(r_cont_msg->seg_num), r_cont_msg->seg_num);

		/* If last segment processed then start scanning */
		if (ha->max_cont_segs == r_cont_msg->seg_num) {
			vhba_map_unbound_targets(vhba);

			ha->max_targets = ha->target_count;

			/* Set the loop status to LINK_UP if already not up */
			if (atomic_read(&ha->link_state) != LINK_UP)
				atomic_set(&ha->link_state, LINK_UP);

			dprintk(TRC_INFO, vhba,
				"max_tgt_id= %d :", ha->max_tgt_id);
			dprintk(TRC_INFO, vhba,	" max_targets= %d\n",
				ha->max_targets);

			/*
			 * Let the workqueue handle the scsi scan
			 */

			atomic_set(&vhba->vhba_state, VHBA_STATE_SCAN);
			ha->discs_ready_flag = 1;
			INIT_WORK(&xwork->work, vhba_handle_scan);
			queue_work(vhba_workqueuep, &xwork->work);
			work_submitted = 1;
		}
		vhba->scan_reqd = 1;
	} else if (type == TGT_STATUS_UPDATE) {

		memcpy(&tgt_status_msg, (struct vhba_tgt_status_msg *)msg,
		       sizeof(struct vhba_tgt_status_msg));
		dprintk(TRC_INFO, vhba, "Got tgt status update from IOP\n");

		vhba->scan_reqd = 1;

		if (tgt_status_msg.flag == TGT_DEAD) {
			loop_id =
			    (uint32_t) be16_to_cpu(tgt_status_msg.loop_id);
			for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
				tq = TGT_Q(ha, tgt);
				port_id = be32_to_cpu(tgt_status_msg.port_id);
				if (tq && (memcmp(tgt_status_msg.wwpn,
						  tq->fcport->port_name,
						  WWN_SIZE) == 0)
				    && tq->d_id.b24 == port_id) {
					atomic_set(&tq->fcport->state,
						   FCS_DEVICE_DEAD);
					ha->stats.fc_stats.rscn_dead_cnt++;
					ha->stats.fc_stats.last_dead_tgt = tgt;
					dprintk(TRC_INFO, vhba,
						"RSCN: Target dead msg ");
					dprintk(TRC_INFO, vhba,
						"received: PWWN: %llx,",
					 wwn_to_u64(tgt_status_msg.wwpn));
					dprintk(TRC_INFO, vhba,
						"port_id: 0x%x,loop_id: 0x%x\n",
						be32_to_cpu
						(tgt_status_msg.port_id),
						loop_id);
				}
			}
			vhba->scan_reqd = 1;
		} else if (tgt_status_msg.flag == TGT_LOST) {
			found = 0;
			loop_id = (u32) be16_to_cpu(tgt_status_msg.loop_id);
			for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
				tq = TGT_Q(ha, tgt);
				if (tq && (memcmp(tgt_status_msg.wwpn,
						  tq->fcport->port_name,
						  WWN_SIZE) == 0)) {
					found = 1;
					if (atomic_read(&tq->fcport->state) !=
					    FCS_DEVICE_LOST) {
						dprintk(TRC_INFO, vhba,
						"RSCN: Target Offline ");
						dprintk(TRC_INFO, vhba,
						"msg received: PWWN:%llx,",
						wwn_to_u64
						(tgt_status_msg.wwpn));
						dprintk(TRC_INFO, vhba,
						"port_id: 0x%x, ",
						be32_to_cpu
						(tgt_status_msg.port_id));
						dprintk(TRC_INFO, vhba,
						"loop_id: 0x%x\n",
						loop_id);
						ha->stats.
						    fc_stats.rscn_dn_cnt++;
						vhba_set_tgt_offline(vhba, tq);
					} else {
						dprintk(TRC_INFO, vhba,
						"RSCN: Target Offline ");
						dprintk(TRC_INFO, vhba,
						"msg received for already ");
						dprintk(TRC_INFO, vhba,
						"disabled device: PWWN:%llx,",
						wwn_to_u64
						(tgt_status_msg.wwpn));
						dprintk(TRC_INFO, vhba,
						"port_id: 0x%x, ",
						be32_to_cpu
						(tgt_status_msg.port_id));
						dprintk(TRC_INFO, vhba,
						"loop_id: 0x%x\n",
						loop_id);
						ha->stats.fc_stats.
						    rscn_multiple_dn_cnt++;
					}
					ha->stats.fc_stats.last_dn_tgt = tgt;
				}
			}
			if (!found) {
				eprintk(vhba,
					"RSCN: No target ");
				eprintk(vhba, "found for offline msg: ");
				eprintk(vhba, "port_id: 0x%x, loop_id: 0x%x\n",
					be32_to_cpu(tgt_status_msg.port_id),
					loop_id);
			}
		} else if (tgt_status_msg.flag == TGT_FOUND) {

			if (atomic_read(&ha->link_state) != LINK_UP) {
				ha->stats.fc_stats.link_up_cnt++;
				atomic_set(&ha->link_state, LINK_UP);
			}
			found = 0;
			vhba_handle_targets(vhba, tgt_status_msg, &found);
			if (!found) {
				/* Brand new target discovered. process it */
				loop_id =
				    (u32) be16_to_cpu(tgt_status_msg.loop_id);
				port_id = be32_to_cpu(tgt_status_msg.port_id);
				if (tgt_status_msg.persistent_binding != -1) {
					bound_value =
					    be32_to_cpu
					    (tgt_status_msg.persistent_binding);
					ha->stats.fc_stats.last_up_tgt =
					    bound_value;
				} else {
					bound_value = -1;
				}

				if (bound_value > MAX_TARGETS) {
					eprintk(vhba,
						"bound value exceeds limits\n");
					bound_value = -1;
				}

				dprintk(TRC_INFO, vhba,
					"RSCN: Target online msg received fr");
				dprintk(TRC_INFO, vhba,
					" new device: PWWN:%llx, ",
					 wwn_to_u64(tgt_status_msg.wwpn));
				dprintk(TRC_INFO, vhba,
					"port_id: 0x%x, loop_id: ", (u32)
					be32_to_cpu(tgt_status_msg.port_id));
				dprintk(TRC_INFO, vhba,
					"0x%x binding: %d\n",
					loop_id, (int)bound_value);
				dprintk(TRC_INFO, vhba,
					"RSCN: Curr tgt_cnt: 0x%x max_tgt_id ",
					ha->target_count);
				dprintk(TRC_INFO, vhba,
					"0x%x, max_tgts 0x%x\n",
					ha->max_tgt_id, ha->max_targets);
				for (k = 0; k < WWN_SIZE; k++)
					port_name[k] = tgt_status_msg.wwpn[k];
				for (k = 0; k < WWN_SIZE; k++)
					node_name[k] = tgt_status_msg.wwnn[k];
				lun_count =
				    (u32) (be16_to_cpu
					   (tgt_status_msg.lun_count));
				for (k = 0; k < lun_count; k++)
					lun_id[k] = tgt_status_msg.lun_ids[k];

				media_type = tgt_status_msg.media_type;

				vhba_target_bind(vhba, loop_id, node_name,
						 port_name, port_id,
						 bound_value, lun_count,
						 lun_map, lun_id, media_type);
				vhba_map_unbound_targets(vhba);
				if (bound_value == -1)
					ha->stats.fc_stats.last_up_tgt =
					    ha->max_tgt_id;
				if (vhba->scanned_once == 0) {
					/*
					 * Let the workqueue handle the
					 * scsi scan
					 */
					atomic_set(&vhba->vhba_state,
						   VHBA_STATE_SCAN);
					INIT_WORK(&xwork->work,
						  vhba_handle_scan);
					queue_work(vhba_workqueuep,
						   &xwork->work);
					work_submitted = 1;
				} else {
					/*for new device */
					vhba->scan_reqd = 1;
				}
			} else {
				vhba_set_tgt_count(vhba);
				atomic_set(&vhba->vhba_state,
					   VHBA_STATE_ACTIVE);
			}
		}

		schedule_update_rports(ha);

	} else if (type == ENABLE_RSP) {
		enable_rsp = (struct enable_rsp *)msg;
		ha->stats.fc_stats.enable_resp_cnt++;
		vp = (int)enable_rsp->vp_index;
		dprintk(TRC_INFO, vhba,
			"Got enable rsp: vp_index %d, res_id %Lx for ha\n",
			vp, enable_rsp->resource_id);

		for (i = 0; i < MAX_VHBAS; i++) {
			if (vhba->cfg && vhba->ha &&
			    (vhba->resource_id == enable_rsp->resource_id)) {
				dprintk(TRC_INFO, vhba,
					"Setting vp_index %d for ha\n", vp);
				vhba->ha->vp_index = enable_rsp->vp_index;
				break;
			}
		}
	} else if (type == PLINK_STATUS_UPDATE) {
		dprintk(TRC_CQP, vhba, "got plink status update\n");
		link_status_msg = (struct vhba_link_status *)msg;
		if (link_status_msg->phy_link_status == LINK_DOWN) {
			dprintk(TRC_INFO, vhba,
				"received link down msg from iop\n");
			ha->stats.fc_stats.link_dn_cnt++;
			if (atomic_read(&ha->link_state) == LINK_UP) {
				atomic_set(&ha->link_state, LINK_DOWN);
				vhba_set_all_tgts_offline(vhba);
			} else {
				dprintk(TRC_INFO, vhba,
					"vhba already in link down state\n");
			}
		} else if (link_status_msg->phy_link_status == LINK_DEAD) {
			atomic_set(&ha->link_state, LINK_DEAD);
			ha->stats.fc_stats.link_dead_cnt++;
			dprintk(TRC_INFO, vhba, "vhba link dead state\n");
		} else {
			ha->stats.fc_stats.link_up_cnt++;
		}

	} else {
		eprintk(vhba, "Unknown msg from IOP\n");
	}
	/* Not all the code paths submit work.  In error cases
	 * or some states, the work might need to be freed */
	if (!work_submitted)
		kfree(xwork);
}

static inline struct cont_a64_entry *vhba_prep_cont_type1_iocb(struct
							       virtual_hba
							       *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct cont_a64_entry *cont_pkt;

	if (!ha) {
		eprintk(NULL, "null ha context\n");
		return 0;
	}

	/* Adjust ring index. */
	ha->req_ring_windex++;
	if (ha->req_ring_windex == ha->request_q_length) {
		ha->req_ring_windex = 0;
		ha->request_ring_ptr = ha->request_ring;
	} else
		ha->request_ring_ptr++;

	cont_pkt = (struct cont_a64_entry *)ha->request_ring_ptr;

	/* Load packet defaults. */
	cont_pkt->entry_type = CONTINUE_A64_TYPE;

	return cont_pkt;
}

static inline void
vhba_build_scsi_iocbs(struct srb *sp, struct cmd_type_7 *cmd_pkt, u16 tot_dsds)
{
	struct scsi_xg_vhba_host *ha = sp->ha;
	struct virtual_hba *vhba = ha->vhba;
	struct scsi_cmnd *cmd;
	u16 avail_dsds;
	u32 *cur_dsd;
	u32 *rkey;
	u32 rindex;
	u32 sp_index;
	u64 *page_list = NULL;
	u64 mapped_addr;
	u32 *cur_dsd_len;
	int unaligned_io = 0;
	int ret;
	u32 request_bufflen = scsi_bufflen(sp->cmd);

	u64 fmr_page_mask = ~((u64) PAGE_SIZE - 1);

	cmd = sp->cmd;

	/* Update entry type to indicate Command Type 3 IOCB */
	cmd_pkt->entry_type = COMMAND_TYPE_7;

	/* No data transfer */
	if (request_bufflen == 0 || cmd->sc_data_direction == DMA_NONE) {
		cmd_pkt->byte_count = cpu_to_le32(0);
		sp->ha->stats.io_stats.total_task_mgmt_reqs++;
		dprintk(TRC_SCSI_ERRS, vhba, "Task Mgmt Req. Returning\n");
		return;
	}

	/* Set transfer direction */
	if (cmd->sc_data_direction == DMA_TO_DEVICE) {
		cmd_pkt->task_mgmt_flags =
		    cpu_to_le16(TMF_WRITE_DATA);
		ha->stats.io_stats.total_write_reqs++;
		ha->stats.io_stats.total_write_mbytes += cmd_pkt->byte_count;
	} else if (cmd->sc_data_direction == DMA_FROM_DEVICE) {
		cmd_pkt->task_mgmt_flags =
		    cpu_to_le16(TMF_READ_DATA);
		ha->stats.io_stats.total_read_reqs++;
		ha->stats.io_stats.total_read_mbytes += cmd_pkt->byte_count;
	}

	/* One DSD is available in the Command Type 3 IOCB */
	cmd_pkt->rkey1 = 0;
	cmd_pkt->rkey2 = 0;
	cmd_pkt->rkey3 = 0;
	cmd_pkt->rkey4 = 0;
	cmd_pkt->rkey5 = 0;

	avail_dsds = 1;
	cur_dsd = (u32 *) &(cmd_pkt->dseg_0_address);
	cur_dsd_len = (u32 *) &(cmd_pkt->dseg_0_len);
	rkey = (u32 *) &(cmd_pkt->rkey1);
	rindex = 0;
	sp_index = 0;
	sp->tot_dsds = tot_dsds;

	/* Load data segments */
	if (scsi_sg_count(cmd) != 0) {
		struct scatterlist *cur_seg;
		int mapped_len = 0;
		int remaining_length = 0;
		int first_pg_offset = 0;
		int cntr = 0;
		int t_cntr = 0;
		u64 cur_map_ptr = 0;
		int pg_list_cntr = 0;

		dprintk(TRC_IO, vhba,
			"hndl %d: Scatter Gather list used\n",
			(int)cmd_pkt->handle);

		{
			ha->stats.fmr_stats.total_fmr_ios++;

			cur_seg = scsi_sglist(cmd);
			dprintk(TRC_FMR, vhba,
				"SG tot_dsds %d. using FMR...\n", tot_dsds);

			page_list = kmalloc(sizeof(u64) *
					    ((request_bufflen /
					      PAGE_SIZE) +
					     (2 * tot_dsds)), GFP_ATOMIC);

			dprintk(TRC_FMR, vhba,
				"allocated %d address ptrs for fmr list\n",
				(int)((request_bufflen / PAGE_SIZE) +
				      (2 * tot_dsds)));
			if (!page_list) {
				eprintk(vhba, "alloc failed!\n");
				sp->error_flag = 1;
				return;
			}

			mapped_len = 0;

			for (cntr = 0; cntr < tot_dsds; cntr++) {
				if (pg_list_cntr > vhba_max_dsds_in_fmr) {
					eprintk(vhba,
					"%s: Page list ptrs ", __func__);
					eprintk(vhba, "exceeeds 65!\n");
					assert(0);
					sp->error_flag = 1;
					dprintk(TRC_FMR, vhba,
						"freeing pg_list\n");
					kfree(page_list);
					page_list = NULL;
					sp->error_flag = 1;
					return;
				}
				remaining_length =
				    ib_sg_dma_len(vhba->xsmp_info.ib_device,
						  cur_seg);
				cur_map_ptr =
				    ib_sg_dma_address(vhba->xsmp_info.ib_device,
						      cur_seg) & fmr_page_mask;
				dprintk(TRC_FMR, vhba,
				"new dsd rem len %d ", remaining_length);
				dprintk(TRC_FMR, vhba,
					"cur_map_ptr %lx\n",
					(unsigned long)cur_map_ptr);
				if (cntr == 0) {
					page_list[pg_list_cntr] =
					    ib_sg_dma_address(vhba->
							xsmp_info.ib_device,
							      cur_seg) &
					    fmr_page_mask;
					first_pg_offset =
					    (ib_sg_dma_address
					     (vhba->xsmp_info.ib_device,
					      cur_seg) -
					     page_list[pg_list_cntr]) &
					    ~fmr_page_mask;
					remaining_length =
					    ib_sg_dma_len(vhba->
							  xsmp_info.ib_device,
							  cur_seg)
					    - (PAGE_SIZE - first_pg_offset);
					dprintk(TRC_FMR, vhba,
						"offset %d rem len in ",
						first_pg_offset);
					dprintk(TRC_FMR, vhba,
					"dsd %d\n", remaining_length);
					cur_map_ptr = page_list[pg_list_cntr] +
					    PAGE_SIZE;
					pg_list_cntr++;
				} else {
					if ((cur_map_ptr & 0xfff) != 0) {
						dprintk(TRC_FMR, vhba,
							"\n%s(): Non-alligned",
							__func__);
						dprintk(TRC_FMR, vhba,
							" page address = 0x%x",
							(int)cur_map_ptr);
						panic("Non-aligned page in ");
						panic("middle element\n");
						assert(0);
						ha->stats.
					    fmr_stats.unaligned_ptr_cnt++;
						unaligned_io = 1;
					}
				}
				while (remaining_length > 0) {
					dprintk(TRC_FMR, vhba,
						"rem len %d cntr %x ",
					remaining_length, pg_list_cntr);
					dprintk(TRC_FMR, vhba,
						"cur_map_ptr %lx\n",
						(unsigned long)cur_map_ptr);
					page_list[pg_list_cntr] = cur_map_ptr;
					remaining_length =
					    remaining_length - PAGE_SIZE;
					cur_map_ptr += PAGE_SIZE;
					pg_list_cntr++;
				}

				if (unaligned_io) {
					ha->stats.fmr_stats.unaligned_io_cnt++;
					dprintk(TRC_FMR, vhba,
						"freeing pg_list\n");
					kfree(page_list);
					page_list = NULL;
					sp->error_flag = 1;
					return;
				}

				dprintk(TRC_FMR, vhba,
					"final rem len %d cntr %d cur_map_ptr ",
					remaining_length, pg_list_cntr);
				dprintk(TRC_FMR, vhba,
					"%lx\n",
					(unsigned long)cur_map_ptr);
				mapped_len +=
				    (int)ib_sg_dma_len(vhba->
						       xsmp_info.ib_device,
						       cur_seg);
				dprintk(TRC_FMR, vhba,
					"hndl %d: mapped len is %u\n",
					(int)cmd_pkt->handle, mapped_len);
				SG_NEXT(cur_seg);
			}

			for (t_cntr = 0; t_cntr < pg_list_cntr; t_cntr++)
				dprintk(TRC_FMR, vhba,
					"hndl %d: SG FMR: page_list[%d] = ",
					(int)cmd_pkt->handle, t_cntr);
				dprintk(TRC_FMR, vhba,
					"%lx\n",
					(unsigned long)page_list[t_cntr]);

			mapped_addr = page_list[0];
			dprintk(TRC_FMR, vhba,
				"calling map buf fmr len %u cmd",
				mapped_len);
			dprintk(TRC_FMR, vhba,
				" bufflen %u page_list_cntr %x mapped addr ",
				request_bufflen, pg_list_cntr);
			dprintk(TRC_FMR, vhba,
				"%lx\n",
				(unsigned long)mapped_addr);
			dprintk(TRC_FMR, vhba,
				"sp %lx sp_index %lx spfmr pool %lx\n",
				(unsigned long)sp, (unsigned long)sp_index,
				(unsigned long)sp->pool_fmr[sp_index]);
			ret = vhba_map_buf_fmr(vhba, page_list,
					       pg_list_cntr, &mapped_addr, sp,
					       sp_index);
			if (ret == -1) {
				dprintk(TRC_FMR_ERRS, vhba,
					"vhba_map_buf_fmr failed\n");
				dprintk(TRC_FMR, vhba, "freeing pg_list\n");
				kfree(page_list);
				page_list = NULL;
				sp->error_flag = 1;
				return;
			}

			dprintk(TRC_FMR, vhba,
				"hndl %d: SG FMR: mapped addr %llx + ",
				(int)cmd_pkt->handle, mapped_addr);
			dprintk(TRC_FMR, vhba,
				"offset %d\n", first_pg_offset);
			dprintk(TRC_FMR, vhba,
				"hndl %d: SG FMR: len %u  rkey 0x%x ",
				(int)cmd_pkt->handle, mapped_len,
				((struct ib_pool_fmr *)sp->pool_fmr[sp_index])->
				fmr->rkey);
			dprintk(TRC_FMR, vhba, "rindex 0x%x\n", rindex);
			mapped_addr = mapped_addr + first_pg_offset;
			*cur_dsd++ = cpu_to_le32(LSD(mapped_addr));
			*cur_dsd++ = cpu_to_le32(MSD(mapped_addr));
			*cur_dsd_len = cpu_to_le32((u32) request_bufflen);

			dprintk(TRC_FMR, NULL,
				"Original SCSI request_buflen = %d 0x%x\n",
				(u32) request_bufflen, (u32) request_bufflen);

			sp->tot_dsds = 1;
			cmd_pkt->dseg_count = cpu_to_le16(sp->tot_dsds);
			dprintk(TRC_FMR, vhba, "done with mapping\n");

			cmd_pkt->rkey1 = cpu_to_be32(((struct ib_pool_fmr *)
						      sp->
						      pool_fmr[sp_index])->fmr->
						     rkey);
		}
	} else {
		dma_addr_t req_dma;
		unsigned long offset;

		dprintk(TRC_FMR, vhba,
			"hndl %d: No Scatter Gather list used\n",
			(int)cmd_pkt->handle);
		offset = ((unsigned long)scsi_sglist(cmd) & ~PAGE_MASK);
		req_dma = ib_dma_map_single(vhba->xsmp_info.ib_device,
					    (void *)scsi_sglist(cmd),
					    request_bufflen,
					    cmd->sc_data_direction);
		sp->dma_handle = req_dma;

		if (req_dma & 0x7) {
			dprintk(TRC_ERRORS, vhba,
				"data buff address not 8 byte aligned!\n");
			sp->error_flag = 1;
			ib_dma_unmap_single(vhba->xsmp_info.ib_device,
					    sp->dma_handle, request_bufflen,
					    cmd->sc_data_direction);
			return;
		}

		{
			int i;
			int num_pages;

			req_dma = req_dma & fmr_page_mask;
			offset = sp->dma_handle - req_dma;
			sp_index = 0;

			/* Get the number of pages */
			num_pages = (unsigned long)
			    request_bufflen / PAGE_SIZE;
			if (request_bufflen % PAGE_SIZE)
				num_pages += 1;

			if ((offset + (request_bufflen % PAGE_SIZE)) >
			    PAGE_SIZE)
				num_pages += 1;

			page_list = kmalloc(sizeof(u64) *
					    num_pages, GFP_ATOMIC);
			if (!page_list) {
				eprintk(vhba, "Page alloc failed!\n");
				/*
				 * CHECK: need to possibly call
				 * ib_dma_unmap_single here to free
				 * up the dma mapping
				 */
				sp->error_flag = 1;
				return;
			}

			for (i = 0; i < num_pages; i++) {
				page_list[i] = sp->dma_handle + (PAGE_SIZE * i);
				page_list[i] &= fmr_page_mask;
			}
			mapped_addr = cmd_pkt->handle + 1;
			mapped_addr = mapped_addr << 12;
			mapped_addr = page_list[0];

			ret = vhba_map_buf_fmr(vhba, page_list, num_pages,
					       &mapped_addr, sp, sp_index);

			if (ret == -1) {
				dprintk(TRC_ERRORS, vhba,
					"vhba_map_buf_fmr failed\n");
				kfree(page_list);
				page_list = NULL;
				sp->error_flag = 1;
				return;
			}

			dprintk(TRC_FMR, vhba,
				"no sg: hndl %d: NSG FMR: req_dma %llx",
				(int)cmd_pkt->handle,
				(unsigned long long int)req_dma);
			dprintk(TRC_FMR, vhba,
				" mapped addr %llx + offset %lu\n",
				mapped_addr, offset);
			mapped_addr += offset;
			rkey[rindex] = cpu_to_be32(((struct ib_pool_fmr *)
						    sp->
						    pool_fmr[sp_index])->fmr->
						   rkey);
			*cur_dsd++ = cpu_to_le32(LSD(mapped_addr));
			*cur_dsd++ = cpu_to_le32(MSD(mapped_addr));
			*cur_dsd_len = cpu_to_le32((u32) request_bufflen);

			dprintk(TRC_FMR, NULL,
				"Original SCSI request_buflen = %d 0x%x\n",
				(u32) request_bufflen, (u32) request_bufflen);

			dprintk(TRC_FMR, vhba,
				"no sg: hndl %d: NSG FMR: mapped addr",
				(int)cmd_pkt->handle);
			dprintk(TRC_FMR, vhba,
				" 0x%llx len 0x%x rkey 0x%x rindex 0x%x\n",
				mapped_addr, request_bufflen,
			((struct ib_pool_fmr *)sp->pool_fmr[sp_index])->
				fmr->rkey, rindex);

		}
	}

	kfree(page_list);
	page_list = NULL;
}

static void sense_buffer(struct scsi_cmnd *cmd, int key, int asc, int asq)
{
	u8 *sbuff;

	sbuff = cmd->sense_buffer;
	memset(sbuff, 0, SCSI_SENSE_BUFFERSIZE);
	sbuff[0] = 0x70;	/* fixed, current */
	sbuff[2] = key;
	sbuff[7] = 0xa;		/* implies 18 byte sense buffer */
	sbuff[12] = asc;
	sbuff[13] = asq;

	dprintk(TRC_SCSI_ERRS, NULL, "[sense_key,asc,ascq]: [0x%x,0x%x,0x%x]\n",
		key, asc, asq);
}

int vhba_report_luns_cmd(struct srb *sp, u32 t, u32 l)
{
	struct scatterlist *sg;
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha;
	struct scsi_cmnd *cmd;
	struct xg_scsi_lun *lun;
	struct os_tgt *tq;
	unsigned long flags = 0;
	int ret = 0;
	int i;
	u16 lun_cnt;
	int lun_byte;
	int rsp_byte;
	int total_size;
	int copy_len;
	char *buf;
	char *data_ptr;
	u8 *cdb;
	int alloc_len;
	int req_len;
	int act_len;
	u32 request_bufflen = scsi_bufflen(sp->cmd);

	cmd = sp->cmd;
	ha = sp->ha;
	cdb = cmd->cmnd;
	vhba = ha->vhba;

	dprintk(TRC_FUNCS, vhba, "Entering...\n");

	spin_lock_irqsave(&ha->io_lock, flags);

	/* Check allocation length and select report */
	alloc_len = cdb[9] + (cdb[8] << 8) + (cdb[7] << 16) + (cdb[6] << 24);
	if ((alloc_len < 16) || (cdb[2] > 2)) {
		sense_buffer(cmd, ILLEGAL_REQUEST, INVALID_FIELD_IN_CDB, 0);
		cmd->result = (DRIVER_SENSE << 24) | SAM_STAT_CHECK_CONDITION;
		ret = 1;
		goto err;
	}

	/* Check reserved bit */
	if (cdb[1] || cdb[3] || cdb[4] || cdb[5] || cdb[10]) {
		sense_buffer(cmd, ILLEGAL_REQUEST, INVALID_FIELD_IN_CDB, 0);
		cmd->result = (DRIVER_SENSE << 24) | SAM_STAT_CHECK_CONDITION;
		ret = 1;
		goto err;
	}

	tq = TGT_Q(ha, t);
	lun_cnt = tq->fcport->lun_count;
	lun_byte = lun_cnt * sizeof(struct xg_scsi_lun);
	rsp_byte = (lun_cnt + 1) * sizeof(struct xg_scsi_lun);

	/* Calculate actual length */
	req_len = request_bufflen;
	scsi_set_resid(cmd, 0);
	if (alloc_len < req_len) {
		act_len = alloc_len;
		scsi_set_resid(cmd, req_len - alloc_len);
	} else {
		act_len = req_len;
		scsi_set_resid(cmd, alloc_len - req_len);
	}
	dprintk(TRC_SCSI, vhba, "req_len=%d, alloc_len=%d, act_len=%d, ",
		req_len, alloc_len, act_len);

	if (rsp_byte > act_len) {
		rsp_byte = act_len;
		lun_cnt = act_len / sizeof(struct xg_scsi_lun);
		if (lun_cnt > 0)
			lun_cnt--;
		else
			lun_cnt = 0;
		dprintk(TRC_SCSI, vhba,
			"Truncate response buffer, " "lun_cnt=%d\n", lun_cnt);
	}
	dprintk(TRC_SCSI, vhba, "Total number of luns active = %d\n", lun_cnt);

	lun = kmalloc(rsp_byte, GFP_ATOMIC);
	if (!lun) {
		dprintk(TRC_SCSI, vhba, "Fail to allocate memory\n");
		cmd->result = DID_ERROR << 16;
		ret = 1;
		goto err;
	}
	memset(lun, 0, rsp_byte);

	/* Create the header. */
	lun[0].scsi_lun[0] = (lun_byte >> 24) & 0xff;
	lun[0].scsi_lun[1] = (lun_byte >> 16) & 0xff;
	lun[0].scsi_lun[2] = (lun_byte >> 8) & 0xff;
	lun[0].scsi_lun[3] = (lun_byte >> 0) & 0xff;

	/* Create data */
	for (i = 1; i <= lun_cnt; i++) {
		lun[i].scsi_lun[0] = ((tq->fcport->lun_ids[i - 1] >> 8) & 0xff);
		lun[i].scsi_lun[1] = (tq->fcport->lun_ids[i - 1] & 0xff);
		lun[i].scsi_lun[2] = 0;
		lun[i].scsi_lun[3] = 0;
		lun[i].scsi_lun[4] = 0;
		lun[i].scsi_lun[5] = 0;
		lun[i].scsi_lun[6] = 0;
		lun[i].scsi_lun[7] = 0;
	}

	/* Data copy */
	if (scsi_sg_count(cmd)) {
		data_ptr = (u8 *) &(lun[0]);
		total_size = rsp_byte;
		sg = scsi_sglist(cmd);
		dprintk(TRC_SCSI, vhba, "S/G list, num_sg=%d, buf_len=%d\n",
			scsi_sg_count(cmd), request_bufflen);
		dprintk(TRC_SCSI, vhba, "total response size = 0x%x\n",
			total_size);

		while (total_size > 0) {
			unsigned int sg_offset = SG_OFFSET(sg);
			unsigned int sg_length = SG_LENGTH(sg);

			if (total_size > (sg_length - sg_offset))
				copy_len = sg_length - sg_offset;
			else
				copy_len = total_size;

			dprintk(TRC_SCSI, vhba,
				"sg_len=0x%x, sg_offset=0x%x, ",
				sg_length, sg_offset);
			dprintk(TRC_SCSI, vhba, "copy_len=0x%x\n",
				copy_len);

			buf = page_address(sg_page(sg)) + sg_offset;
			if (!buf) {
				ret = 1;
				goto err_2;
			}
			memcpy(buf, data_ptr, copy_len);

			total_size -= copy_len;
			if (total_size > 0) {
				dprintk(TRC_SCSI, vhba,
					"More data 0x%x\n", total_size);
				data_ptr += copy_len;
				SG_NEXT(sg);
			}
		}
		SG_RESET(sg);
	} else if (request_bufflen) {
		dprintk(TRC_SCSI, vhba, "Single buffer size=0x%x\n",
			request_bufflen);
		memcpy(scsi_sglist(cmd), (void *)lun, rsp_byte);
	}
	cmd->result = DID_OK << 16;
err_2:
	kfree(lun);
err:
	spin_unlock_irqrestore(&ha->io_lock, flags);

	return ret;
}

int vhba_start_scsi(struct srb *sp, u32 tgt, u32 lun, u32 handle)
{
	struct cmd_type_7 *cmd_pkt;
	struct scsi_xg_vhba_host *ha = sp->ha;
	struct virtual_hba *vhba = ha->vhba;
	struct scsi_cmnd *cmd = sp->cmd;
	struct os_tgt *tq;
	struct scatterlist *sg;
	int tot_dsds;
	int req_cnt, i;
	u16 lcl_timeout;
	u32 request_bufflen = scsi_bufflen(cmd);

	dprintk(TRC_FUNCS, NULL, "Entering...\n");

	sp->unaligned_sg = NULL;
	sp->bounce_buffer = NULL;
	if (scsi_sg_count(cmd) && (sp->cmd->sc_data_direction != DMA_NONE)) {
		if (check_sg_alignment(sp, scsi_sglist(cmd))) {
			sp->unaligned_sg = vhba_setup_bounce_buffer(sp);
			if (!sp->unaligned_sg) {
				pr_err("Error: unable to setup bounce buffr\n");
				sp->error_flag = 1;
				return 1;
			}
			ha->stats.fmr_stats.unaligned_io_cnt++;
		}
	}

	/*
	 * Enqueue srb in the outstanding commands
	 * Check if marker is needed
	 */
	tot_dsds = 0;
	sg = NULL;

	if (scsi_sg_count(cmd)) {
		sg = scsi_sglist(cmd);
		tot_dsds = ib_dma_map_sg(vhba->xsmp_info.ib_device,
					 sg, scsi_sg_count(cmd),
					 cmd->sc_data_direction);
	} else if (request_bufflen)
		tot_dsds++;

	req_cnt = 1;

	if (req_cnt > MAX_IOCBS_IN_VH) {
		eprintk(vhba,
			"Total IOCBS %d > max val %d with ",
			req_cnt, MAX_IOCBS_IN_VH);
		eprintk(vhba, "total dsds %d\n", tot_dsds);
		goto queuing_error;
	}

	if (tot_dsds > vhba_max_dsds_in_fmr) {
		eprintk(vhba, "Total DSDs %d > %d\n",
			tot_dsds, (int)vhba_max_dsds_in_fmr);
		goto queuing_error;
	}

	if (((ha->req_ring_windex + 1) % 1024) == *ha->req_ring_rindex) {
		dprintk(TRC_IO, NULL, "Queue full\n");
		goto queuing_error;
	}

	/* Make sure there is place for all IOCBS in the ring... */
	cmd_pkt = (struct cmd_type_7 *)ha->request_ring_ptr;

	memset(cmd_pkt, 0, sizeof(struct cmd_type_7));

	cmd_pkt->handle = handle;
	sp->iocb_handle = handle;
	if (vhba_multiple_q)
		cmd_pkt->handle = cmd_pkt->handle | (sp->queue_num << 16);

	sp->cmd->host_scribble =
	    (unsigned char *)(unsigned long)cmd_pkt->handle;
	ha->req_q_cnt -= req_cnt;

	tq = TGT_Q(ha, tgt);
	cmd_pkt->nport_handle = cpu_to_le16(tq->fcport->loop_id);
	dprintk(TRC_IO, vhba, "NPORT hndl is 0x%x\n", cmd_pkt->nport_handle);

	cmd_pkt->port_id[0] = tq->d_id.b.al_pa;
	dprintk(TRC_IO, vhba, "PORT ID byte 0 is 0x%x\n", cmd_pkt->port_id[0]);
	cmd_pkt->port_id[1] = tq->d_id.b.area;
	dprintk(TRC_IO, vhba, "PORT ID byte 1 is 0x%x\n", cmd_pkt->port_id[1]);
	cmd_pkt->port_id[2] = tq->d_id.b.domain;
	dprintk(TRC_IO, vhba, "PORT ID byte 2 is 0x%x\n", cmd_pkt->port_id[2]);

	cmd_pkt->dseg_count = cpu_to_le16(tot_dsds);

	cmd_pkt->lun[1] = LSB(lun);
	cmd_pkt->lun[2] = MSB(lun);
	host_to_fcp_swap(cmd_pkt->lun, sizeof(cmd_pkt->lun));

	dprintk(TRC_IO, vhba, "hndl %d: cdb buffer dump:\n",
		(int)cmd_pkt->handle);
	if (vhba_debug == TRC_IO) {
		for (i = 0; i < cmd->cmd_len; i++)
			dprintk(TRC_IO, vhba, "%x ", cmd->cmnd[i]);
		dprintk(TRC_IO, vhba, "\n");
	}

	memcpy(cmd_pkt->fcp_cdb, cmd->cmnd, cmd->cmd_len);
	host_to_fcp_swap(cmd_pkt->fcp_cdb, sizeof(cmd_pkt->fcp_cdb));

	/*
	 * timeout_per_command(cmd) is the timeout value
	 * for the cmd from SCSI and is in milliseconds
	 * so divide by 1000 to get in secs
	 */

	if ((timeout_per_command(cmd) / 1000) > 5) {
		lcl_timeout =
		    (u16) (((timeout_per_command(cmd) / 1000) * 8) / 10);
	} else if ((timeout_per_command(cmd) / 1000) >= 2)
		lcl_timeout =
		    cpu_to_le16((timeout_per_command(cmd) / 1000) - 1);
	else if ((timeout_per_command(cmd) / 1000) == 1)
		lcl_timeout = cpu_to_le16(1);
	else
		lcl_timeout = cpu_to_le16(VHBA_CMD_TIMEOUT);

	cmd_pkt->timeout = cpu_to_le16(lcl_timeout);
	dprintk(TRC_IO, vhba, "sp = %p, scsi_pkt_timeout = %d\n",
		sp, timeout_per_command(cmd));
	cmd_pkt->byte_count = cpu_to_le32((u32) request_bufflen);
	dprintk(TRC_IO, vhba, "hndl %d: byte cnt x%0x, lcl_timeout:0x%x\n",
		(int)cmd_pkt->handle, cmd_pkt->byte_count, lcl_timeout);

	vhba_build_scsi_iocbs(sp, cmd_pkt, tot_dsds);

	if (sp->error_flag) {
		if (scsi_sg_count(cmd))
			ib_dma_unmap_sg(vhba->xsmp_info.ib_device,
					sg, scsi_sg_count(cmd),
					cmd->sc_data_direction);
		return 1;
	}

	cmd_pkt->vp_index = ha->vp_index;

	if (cmd_pkt->byte_count != cpu_to_le32((u32) request_bufflen))
		dprintk(TRC_IO, vhba,
			"hndl %d: byte cnt %d != req buff ",
			(int)cmd_pkt->handle, cmd_pkt->byte_count);
		dprintk(TRC_IO, vhba, "len %d\n",
			cpu_to_le32((u32) request_bufflen));

	if (req_cnt != 1)
		dprintk(TRC_IO, vhba, "curr entry cnt is %d\n", req_cnt);
	cmd_pkt->entry_count = 1;

	sp->flags |= SRB_DMA_VALID;

	/* Adjust ring index  and send a write index update... */
	ha->req_ring_windex++;
	if (ha->req_ring_windex == REQUEST_ENTRY_CNT_24XX) {
		ha->req_ring_windex = 0;
		ha->request_ring_ptr = ha->request_ring;
	} else
		ha->request_ring_ptr++;

	if (vhba_send_write_index(vhba)) {
		dprintk(TRC_ERRORS, vhba, "send write index failed\n");
		sp->flags &= ~SRB_DMA_VALID;
		if (scsi_sg_count(sp->cmd)) {
			ib_dma_unmap_sg(vhba->xsmp_info.ib_device,
					scsi_sglist(sp->cmd),
					scsi_sg_count(sp->cmd),
					sp->cmd->sc_data_direction);
		} else if (request_bufflen) {
			ib_dma_unmap_single(vhba->xsmp_info.ib_device,
					    sp->dma_handle,
					    request_bufflen,
					    sp->cmd->sc_data_direction);
		}
		vhba_unmap_buf_fmr(vhba, sp, sp->tot_dsds);

		return 1;
	}

	return 0;

queuing_error:
	if (scsi_sg_count(cmd))
		ib_dma_unmap_sg(vhba->xsmp_info.ib_device, sg,
				scsi_sg_count(cmd), cmd->sc_data_direction);
	dprintk(TRC_SCSI_ERRS, vhba,
		"Cannot queue req as IOCB to ring (err2)\n");
	return 1;
}

int vhba_send_abort(struct virtual_hba *vhba, int abort_handle, int t)
{
	struct vhba_abort_cmd *abort_msg = NULL;
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct os_tgt *tq = NULL;
	int ret = 0;

	tq = TGT_Q(ha, t);

	if (!tq) {
		eprintk(vhba, "null tq context in vhba_send_abort\n");
		return 2;
	}

	abort_msg = kmalloc(sizeof(struct vhba_abort_cmd), GFP_ATOMIC);
	if (!abort_msg) {
		eprintk(vhba, "kmalloc failed for send xsmp abort\n");
		return 1;
	}

	abort_msg->type = ABORT_CMD;
	abort_msg->handle_to_abort = abort_handle;
	abort_msg->port_id[0] = tq->d_id.b.al_pa;
	abort_msg->port_id[1] = tq->d_id.b.area;
	abort_msg->port_id[2] = tq->d_id.b.domain;

	dprintk(TRC_INFO, vhba,
		"sending abort msg for handle %x p0 %x p1 %x p2 %x\n",
		abort_handle, abort_msg->port_id[0],
		abort_msg->port_id[1], abort_msg->port_id[2]);

	/* check qp status */
	if (atomic_read(&ha->qp_status) == VHBA_QP_CONNECTED)
		ret = xscore_post_send(&vhba->ctrl_conn.ctx,
				       (u8 *) abort_msg,
				       sizeof(struct vhba_abort_cmd),
				       XSCORE_DEFER_PROCESS);
	else {
		dprintk(TRC_INFO, vhba, "qp already in disconn state\n");
		kfree(abort_msg);
		return VHBA_QP_DISCONNECTED;
	}

	if (ret) {
		ha->stats.ib_stats.cqp_send_err_cnt++;
		eprintk(vhba, "xsigo ib send msg failed [%d]\n", ret);
		ib_link_down(ha);
		atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);
		kfree(abort_msg);
		return 1;
	}

	return 0;
}

int vhba_send_tgt_reset(struct virtual_hba *vhba, int t)
{
	struct vhba_tgt_reset_msg *reset_msg = NULL;
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct os_tgt *tq;
	int ret = 0;
	int i;

	tq = TGT_Q(ha, t);

	/*
	 * TODO: there should be a mechanism to check whether the otgt
	 * array has been fully populated. This is a simple check in the
	 * meantime.
	 */
	if (!tq) {
		pr_err("null tq context in vhba_send_tgt_reset\n");
		return 2;
	}

	reset_msg = kmalloc(sizeof(struct vhba_tgt_reset_msg), GFP_ATOMIC);
	if (!reset_msg) {
		eprintk(NULL, "kmalloc failed for send xsmp abort\n");
		return 1;
	}

	reset_msg->type = TGT_RESET;
	reset_msg->vhba_id = ha->vp_index;

	for (i = 0; i < WWN_SIZE; i++)
		reset_msg->wwpn[i] = tq->port_name[i];

	/* check qp status */
	if (atomic_read(&ha->qp_status) == VHBA_QP_CONNECTED) {
		dprintk(TRC_INFO, vhba,
			"sending tgt reset msg for vhba %p\n", vhba);
		ret = xscore_post_send(&vhba->ctrl_conn.ctx,
				       (u8 *) reset_msg,
				       sizeof(struct vhba_tgt_reset_msg),
				       XSCORE_DEFER_PROCESS);
	} else {
		dprintk(TRC_INFO, vhba, "qp already in disconn state\n");
		kfree(reset_msg);
		return VHBA_QP_DISCONNECTED;
	}

	if (ret) {
		ha->stats.ib_stats.cqp_send_err_cnt++;
		eprintk(vhba, "xsigo ib send msg failed?\n");
		ib_link_down(ha);
		atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);
		kfree(reset_msg);
		return 1;
	}

	return 0;
}

int vhba_send_lun_reset(struct virtual_hba *vhba, int t, int l)
{
	struct vhba_lun_reset_msg *reset_msg = NULL;
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct os_tgt *tq;
	struct os_lun *lq;
	int ret = 0;
	int i;

	tq = TGT_Q(ha, t);

	/*
	 * TODO: there should be a mechanism to check whether the otgt
	 * array has been fully populated. This is a simple check in the
	 * meantime.
	 */
	if (!tq) {
		pr_err("null tq context in vhba_send_lun_reset\n");
		return 2;
	}

	lq = LUN_Q(ha, t, l);
	if (!lq) {
		pr_err("null lq context in vhba_send_lun_reset\n");
		return 3;
	}

	reset_msg = kmalloc(sizeof(struct vhba_lun_reset_msg), GFP_ATOMIC);
	if (!reset_msg) {
		eprintk(NULL, "kmalloc failed for send xsmp lun reset\n");
		return 1;
	}

	reset_msg->type = LUN_RESET;
	reset_msg->vhba_id = ha->vp_index;
	reset_msg->lun = (u16) l;

	for (i = 0; i < WWN_SIZE; i++)
		reset_msg->wwpn[i] = tq->port_name[i];

	/* check qp status */
	if (atomic_read(&ha->qp_status) == VHBA_QP_CONNECTED) {
		dprintk(TRC_INFO, vhba,
			"sending lun reset msg for vhba %p\n", vhba);
		ret = xscore_post_send(&vhba->ctrl_conn.ctx,
				       (u8 *) reset_msg,
				       sizeof(struct vhba_lun_reset_msg),
				       XSCORE_DEFER_PROCESS);
	} else {
		dprintk(TRC_INFO, vhba, "qp already in disconn state\n");
		kfree(reset_msg);
		return VHBA_QP_DISCONNECTED;
	}

	if (ret) {
		ha->stats.ib_stats.cqp_send_err_cnt++;
		eprintk(vhba, "xsocre_post_send() failed?\n");
		ib_link_down(ha);
		atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);
		kfree(reset_msg);
		return 1;
	}
	return 0;
}

struct os_lun *vhba_allocate_lun(struct virtual_hba *vhba, u32 tgt, u32 lun)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct os_lun *lq;
	u32 max_lun;

	if (vhba->cfg->lunmask_enable)
		max_lun = MAX_FIBRE_LUNS;
	else
		max_lun = MAX_FIBRE_LUNS_MORE;

	/* If SCSI addressing OK, allocate LUN queue. */
	if (tgt >= MAX_TARGETS || lun >= max_lun) {
		eprintk(vhba,
			"scsi(%ld): Unable to allocate lun, invalid ",
			ha->host_no);
		eprintk(vhba, "parameters %d %d. Returning null\n",
			tgt, lun);
		return NULL;
	}

	if (TGT_Q(ha, tgt) == NULL) {
		eprintk(vhba, "Tgt %d not found in tgt_q\n", tgt);
		return NULL;
	}

	lq = LUN_Q(ha, tgt, lun);
	if (lq == NULL) {
		lq = kmalloc(sizeof(struct os_lun), GFP_ATOMIC);
		if (lq != NULL) {
			dprintk(TRC_IO, vhba,
				"scsi(%ld): Alloc Lun %d @ tgt %d\n",
				ha->host_no, lun, tgt);

			memset(lq, 0, sizeof(struct os_lun));
			LUN_Q(ha, tgt, lun) = lq;
		}
	}

	if (lq == NULL) {
		eprintk(vhba, "Unable to allocate lun\n");
		return NULL;
	}

	return lq;
}

static struct os_tgt *vhba_tgt_alloc(struct virtual_hba *vhba, u32 tgt)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct os_tgt *tq;

	/* If SCSI addressing OK, allocate TGT queue and lock. */
	if (tgt >= MAX_TARGETS) {
		eprintk(vhba,
			"scsi(%ld): Unable to allocate", ha->host_no);
		eprintk(vhba,
			" target, invalid target number %d. Returning null\n",
			tgt);
		return NULL;
	}

	tq = TGT_Q(ha, tgt);
	if (tq == NULL) {
		tq = kmalloc(sizeof(struct os_tgt), GFP_ATOMIC);
		if (tq != NULL) {
			dprintk(TRC_IO, vhba,
				"scsi(%ld): Alloc Target %d @ %p\n",
				ha->host_no, tgt, tq);
			memset(tq, 0, sizeof(struct os_tgt));
			tq->ha = ha;
			tq->init_done = 0;
			TGT_Q(ha, tgt) = tq;
			tq->state = VHBA_IO_STATE_ACTIVE;
		}
	}

	if (tq != NULL) {
		tq = TGT_Q(ha, tgt);
		if (tq)
			dprintk(TRC_IO, vhba, "tq is same as TGT_Q\n");
		else
			dprintk(TRC_IO, vhba, "tq is not same as TGT_Q\n");
	} else
		eprintk(vhba, "Unable to allocate target\n");

	return tq;
}

static u32
vhba_target_bind(struct virtual_hba *vhba, u32 loop_id, u8 *node_name,
		 u8 *port_name, u32 port_id, s32 bound_value,
		 u32 lun_count, u8 *lun_map, u16 *lun_id, u8 media_type)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct os_tgt *tq;
	struct fc_port *fcport;
	struct fc_port *fcporttemp;
	unsigned long flags;
	u32 tgt;
	int port_found;
	int k, id;

	port_found = 0;
	spin_lock_irqsave(&ha->list_lock, flags);

	list_for_each_entry_safe(fcport, fcporttemp, &ha->disc_ports, list) {
		if (memcmp(port_name, fcport->port_name, WWN_SIZE) == 0) {
			port_found = 1;
			break;
		}
	}

	spin_unlock_irqrestore(&ha->list_lock, flags);

	if (port_found) {
		/*
		 * Port must be already bound at a particular location
		 * Just set the state and flags
		 */
		dprintk(TRC_IO, NULL,
			"port already exists, so just updating info\n");
		fcport->d_id.b24 = port_id;
		fcport->loop_id = loop_id;
		fcport->lun_count = lun_count;
		if (fcport->tgt_queue) {
			fcport->tgt_queue->d_id.b24 = fcport->d_id.b24;
			set_bit(TQF_ONLINE, &fcport->tgt_queue->flags);
		}
		if (media_type == TYPE_TAPE)
			fcport->flags |= FCF_TAPE_PRESENT;
		else
			fcport->flags &= ~FCF_TAPE_PRESENT;
		atomic_set(&fcport->state, FCS_ONLINE);
		return 0;
	}

	fcport = kmalloc(sizeof(struct fc_port), GFP_ATOMIC);

	if (!fcport) {
		eprintk(vhba, "Couldn't allocate fcport\n");
		return 1;
	}
	memset(fcport, 0, sizeof(struct fc_port));
	fcport->loop_id = loop_id;
	fcport->lun_count = lun_count;
	fcport->supported_classes |= FC_COS_CLASS3;

	for (k = 0; k < lun_count; k++)
		fcport->lun_ids[k] = -1;

	for (k = 0; k < lun_count; k++) {
		if (lun_id) {
			dprintk(TRC_IO, vhba,
				"Adding lun id %d to list\n", lun_id[k]);
			fcport->lun_ids[k] = lun_id[k];
		} else {
			dprintk(TRC_IO, vhba,
				"Setting lun id %d to 0 in list\n", lun_id[k]);
			fcport->lun_ids[k] = 0;
		}
	}

	id = fcport->loop_id;
	dprintk(TRC_IO, vhba, "fcport loop id:%d\n", id);
	fcport->d_id.b24 = port_id;

	memcpy(fcport->port_name, port_name, WWN_SIZE);
	memcpy(fcport->node_name, node_name, WWN_SIZE);
	fcport->persistent_binding = bound_value;

	add_to_disc_ports(fcport, vhba);

	/*
	 * Check for persistent binding.
	 * if bound value is not -1 then check for valid place...
	 * validate bound value  <= 0 and < 256
	 */
	tgt = (u32) bound_value;
	if (bound_value != -1) {
		tq = TGT_Q(ha, tgt);
		if (tq == NULL) {
			tq = vhba_tgt_alloc(vhba, tgt);
			if (tq != NULL) {
				memcpy(tq->node_name, fcport->node_name,
				       WWN_SIZE);
				memcpy(tq->port_name, fcport->port_name,
				       WWN_SIZE);
				tq->d_id.b24 = fcport->d_id.b24;
				fcport->bound = 1;
				fcport->os_target_id = tgt;
				fcport->tgt_queue = tq;
				tq->fcport = fcport;
				if (media_type == TYPE_TAPE)
					fcport->flags |= FCF_TAPE_PRESENT;
				else
					fcport->flags &= ~FCF_TAPE_PRESENT;
				set_bit(TQF_ONLINE, &tq->flags);
				atomic_set(&fcport->state, FCS_ONLINE);
				if (ha->max_tgt_id < tgt)
					ha->max_tgt_id = tgt;
			} else {
				id = fcport->loop_id;
				fcport->bound = 0;
				eprintk(vhba,
					"Unable to allocate tgt");
				eprintk(vhba, " for fc_port %d\n", id);
				return 1;
			}
		} else {
			id = fcport->loop_id;
			eprintk(vhba,
				"Cannot bind fc_port %d at tgt %d\n",
				id, tgt);
			/* Make the port unbound which will be
			   added later to the map */
			fcport->bound = 0;
			return 1;
		}
	} else {
		/* Make the port unbound which will be added later to the map */
		fcport->bound = 0;
		if (media_type == TYPE_TAPE)
			fcport->flags |= FCF_TAPE_PRESENT;
		else
			fcport->flags &= ~FCF_TAPE_PRESENT;
	}
	return 0;
}

void vhba_set_tgt_count(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct os_tgt *tq;
	int tgt;

	ha->target_count = 0;
	ha->max_tgt_id = 0;
	for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
		tq = TGT_Q(ha, tgt);
		if (tq != NULL) {
			if (atomic_read(&tq->fcport->state) == FCS_ONLINE) {
				dprintk(TRC_INFO, vhba,
					"tgt[%d]: nport_id: 0x%x\n",
					tgt, tq->d_id.b24);
				ha->target_count++;
				if (ha->max_tgt_id < tgt)
					ha->max_tgt_id = tgt;
			}
		}
	}

	if (ha->target_count > 0)
		ha->max_tgt_id++;

	if (ha->max_tgt_id < ha->target_count)
		ha->max_tgt_id = ha->target_count;

	ha->max_targets = ha->max_tgt_id;
	dprintk(TRC_INFO, vhba,
		"RSCN: max id = %d max targets = %d tgt count = %d\n",
		ha->max_tgt_id, ha->max_targets, ha->target_count);
}

static u32 vhba_map_unbound_targets(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct os_tgt *tq;
	struct fc_port *fcport;
	struct fc_port *fcporttemp;
	u32 tgt;
	int id;
	int free_tgt_found = 0;

	list_for_each_entry_safe(fcport, fcporttemp, &ha->disc_ports, list) {
		if (fcport->bound)
			continue;
		tgt = ha->max_tgt_id;
		while (free_tgt_found == 0) {
			tq = TGT_Q(ha, tgt);
			if (tq == NULL) {
				free_tgt_found = 1;
				break;
			}
			tgt++;
			if (tgt == ha->max_tgt_id)
				break;
			if (tgt > MAX_TARGETS)
				tgt = 0;
		}
		if (free_tgt_found == 0) {
			dprintk(TRC_SCSI_ERRS, vhba, "Tgt map is full\n");
			return 1;
		}
		free_tgt_found = 0;
		tq = vhba_tgt_alloc(vhba, tgt);
		if (tq != NULL) {
			memcpy(tq->node_name, fcport->node_name, WWN_SIZE);
			memcpy(tq->port_name, fcport->port_name, WWN_SIZE);
			tq->d_id.b24 = fcport->d_id.b24;
			fcport->bound = 1;
			fcport->os_target_id = tgt;
			fcport->tgt_queue = tq;
			tq->fcport = fcport;
			set_bit(TQF_ONLINE, &tq->flags);
			atomic_set(&fcport->state, FCS_ONLINE);
		} else {
			id = fcport->loop_id;
			eprintk(vhba, "alloc failed for fc_port %x" "\n", id);
			return 1;
		}
	}
	vhba_set_tgt_count(vhba);
	return 0;
}

void vhba_mark_tgts_lost(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	struct os_tgt *tq;
	u16 tgt;

	for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
		tq = TGT_Q(ha, tgt);
		if (tq == NULL)
			continue;
		set_bit(TQF_SUSPENDED, &tq->flags);
		atomic_set(&tq->fcport->state, FCS_DEVICE_LOST);
	}
}

void ib_link_dead_poll(struct scsi_xg_vhba_host *ha)
{
	struct virtual_hba *vhba = ha->vhba;

	if (atomic_read(&ha->ib_status) != VHBA_IB_DOWN)
		return;

	if (atomic_read(&ha->ib_link_down_cnt)) {
		if (!atomic_dec_and_test(&ha->ib_link_down_cnt))
			return;
	} else
		return;

	atomic_set(&ha->ib_status, VHBA_IB_DEAD);
	dprintk(TRC_INFO, vhba, "Marking IB link dead\n");
}

void ib_link_down(struct scsi_xg_vhba_host *ha)
{
	struct virtual_hba *vhba = ha->vhba;
	struct vhba_xsmp_msg *msg;
	u32 ib_timeout;

	if (atomic_read(&ha->ib_status) != VHBA_IB_UP)
		return;

	msg = (struct vhba_xsmp_msg *)vhba->cfg;

	ib_timeout = msg->linkdowntimeout;

	if (ib_timeout > 60)
		ib_timeout = 60;
	dprintk(TRC_INFO, vhba, "IB down, timer=%d\n", ib_timeout);

	if (ib_timeout < 5) {
		atomic_set(&ha->ib_status, VHBA_IB_DEAD);
	} else {
		atomic_set(&ha->ib_status, VHBA_IB_DOWN);
		atomic_set(&ha->ib_link_down_cnt,
			   ib_timeout / WQ_PERIODIC_TIMER);
	}
}

void dump_iocb(struct cmd_type_7 *cmd_pkt)
{

	pr_alert("IOCB Data:\n");
	pr_alert("Entry Type: 0x%x\tEntry Count: 0x%x\n",
		 cmd_pkt->entry_type, cmd_pkt->entry_count);
	pr_alert("IOCB Handle : 0x%x\n", cmd_pkt->handle);
	pr_alert("N_Port Handle: 0x%x\n", cmd_pkt->nport_handle);
	pr_alert("Data Segment Count: 0x%x\tFCP_LUN: 0x%x\n",
		 cmd_pkt->dseg_count, cmd_pkt->lun[0]);
	pr_alert("Task (Operation): 0x%x\tTotal Data Byte Count: 0x%x\n",
		 cmd_pkt->task_mgmt_flags, cmd_pkt->byte_count);
	pr_alert("Target ID (Port ID): [0]: 0x%x\t[1]: 0x%x\t[2]: 0x%x\n",
		 cmd_pkt->port_id[0], cmd_pkt->port_id[1], cmd_pkt->port_id[2]);
	pr_alert("VP Index: 0x%x\tData Segment Length: 0x%x\n",
		 cmd_pkt->vp_index, cmd_pkt->dseg_0_len);
	pr_alert("Data Segment Address: 0x%x_%x\n",
		 cmd_pkt->dseg_0_address[1], cmd_pkt->dseg_0_address[0]);
	pr_alert("\n");
}

/*
 * Used by San Boot.
 * Returns 1 if atleast one Disc Is Up.
 * Returns 0 if all Discs are Not Ready
 */
int vhba_check_discs_status(void)
{
	struct virtual_hba *vhba = NULL;

	read_lock_bh(&vhba_global_lock);
	list_for_each_entry(vhba, &vhba_g.list, list) {
		if (vhba->ha->discs_ready_flag) {
			read_unlock_bh(&vhba_global_lock);
			dprintk(TRC_ERRORS, vhba,
				"vhba_check_discs_status: found 1 disc Up\n");
			return 1;
		}
	}
	read_unlock_bh(&vhba_global_lock);
	dprintk(TRC_ERRORS, vhba, "vhba_check_discs_status:No disc is Up\n");
	return 0;
}
EXPORT_SYMBOL(vhba_check_discs_status);

/*
 * Used by San Boot.
 * Returns # of VHBAs created.
 */

int check_number_of_vhbas_provisioned(void)
{
	return atomic_read(&vhba_count);
}
EXPORT_SYMBOL(check_number_of_vhbas_provisioned);
