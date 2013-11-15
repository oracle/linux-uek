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
#include <linux/delay.h>
#ifdef CONFIG_SUSE_KERNEL
#include <linux/hardirq.h>
#endif
#include "vhba_os_def.h"
#include "vhba_xsmp.h"
#include "vhba_ib.h"
#include "xsmp_session.h"
#include "vhba_defs.h"

static int vhba_swap_bytes(int direction, u8 *msg);

int vhba_xsmp_send_msg(xsmp_cookie_t xsmp_hndl, u8 *data, int length)
{
	if (vhba_swap_bytes(H_TO_N, data)) {
		eprintk(NULL,
			"Error - byte order conversion gone "
			"wrong! Returning -1\n");
		return -1;
	}

	return xcpm_send_message(xsmp_hndl, vhba_xsmp_service_id, data, length);
}

int vhba_xsmp_ack(xsmp_cookie_t xsmp_hndl, u8 *data, int length)
{
	int new_length = length + sizeof(struct xsmp_message_header);
	struct xsmp_message_header *m_header;
	u8 *msg_offset;
	int ret;
	u8 *msg = kmalloc(new_length, GFP_ATOMIC);

	if (!msg) {
		eprintk(NULL,
			"Error - alloc for vhba xsmp_send_ack"
			" failed. Returning 1\n");
		return 1;
	}
	m_header = (struct xsmp_message_header *)msg;
	msg_offset = msg + sizeof(struct xsmp_message_header);

	memset(msg, 0, sizeof(struct xsmp_message_header));

	m_header->type = XSMP_MESSAGE_TYPE_VHBA;
	m_header->length = new_length;
	m_header->seq_number = 0;

	memcpy(msg_offset, data, length);
	/* msg freed by callee */
	ret = vhba_xsmp_send_msg(xsmp_hndl, msg, new_length);

	return ret;
}

int vhba_xsmp_nack(xsmp_cookie_t xsmp_hndl,
		   u8 *data, int length, enum vhba_xsmp_error_codes nack_code)
{
	int new_length = length + sizeof(struct xsmp_message_header);
	struct xsmp_message_header *m_header;
	u8 *msg_offset;
	int ret = 0;
	u8 *msg = kmalloc(new_length, GFP_ATOMIC);

	if (!((nack_code > VHBA_NACK_INVALID)
	      && (nack_code < VHBA_NACK_CODE_MAX))) {
		eprintk(NULL,
			"Error - invalid nack code %d\n", nack_code);
	}
	if (!msg) {
		eprintk(NULL,
			"Error - alloc for vhba xsmp_send_nack"
			" failed. Returning 1\n");
		return 1;
	}
	m_header = (struct xsmp_message_header *)msg;
	msg_offset = msg + sizeof(struct xsmp_message_header);
	memset(msg, 0, sizeof(struct xsmp_message_header));

	m_header->type = XSMP_MESSAGE_TYPE_VHBA;
	m_header->length = new_length;
	m_header->seq_number = 0;

	memcpy(msg_offset, data, length);

	((struct vhba_xsmp_msg *)msg_offset)->code = nack_code | XSMP_VHBA_NACK;
	/* msg freed by callee */
	ret = vhba_xsmp_send_msg(xsmp_hndl, msg, new_length);
	return ret;
}

int vhba_xsmp_notify(xsmp_cookie_t xsmp_hndl, u64 resource_id, int notifycmd)
{
	int length = sizeof(struct xsmp_message_header) +
	    sizeof(struct vhba_xsmp_msg);
	int prio = (in_interrupt()) ? GFP_ATOMIC : GFP_KERNEL;
	int ret;
	struct xsmp_message_header *header;
	struct vhba_xsmp_msg *xsmp_msg;
	u8 *msg = kmalloc(length, prio);

	if (!msg) {
		eprintk(NULL,
			"Error - alloc for vhba xsmp_send_nack"
			" failed. Returning 1\n");
		return 1;
	}
	header = (struct xsmp_message_header *)msg;
	xsmp_msg = (struct vhba_xsmp_msg *)(msg + sizeof(*header));

	memset(msg, 0, length);
	header->type = XSMP_MESSAGE_TYPE_VHBA;
	header->length = length;

	xsmp_msg->type = notifycmd;
	xsmp_msg->length = sizeof(struct vhba_xsmp_msg);
	xsmp_msg->resource_id = resource_id;

	ret = vhba_xsmp_send_msg(xsmp_hndl, msg, length);
	if (ret) {
		eprintk(NULL, "Error sending xsmp message %d\n", ret);
		kfree(msg);
	}
	return ret;
}

static void vhba_sync_begin(struct work_struct *work)
{
	struct xsvhba_work *xwork = container_of(work, struct xsvhba_work,
						 work);

	xsmp_cookie_t xsmp_hndl = xwork->xsmp_hndl;
	struct virtual_hba *vhba;
	unsigned long flags = 0;

	read_lock_irqsave(&vhba_global_lock, flags);
	list_for_each_entry(vhba, &vhba_g.list, list) {
		if (xsmp_sessions_match(&vhba->xsmp_info, xsmp_hndl)) {
			dprintk(TRC_INFO,
				vhba, "sync begin: xsmp_hndl=%p\n", xsmp_hndl);
			vhba->xsmp_hndl = xsmp_hndl;
#if 0
			/*
			 * Because of bug on chassis sometimes VHBA's
			 * get deleted
			 */
			vhba->sync_needed = 1;
#endif
		}
	}
	read_unlock_irqrestore(&vhba_global_lock, flags);

	kfree(xwork->msg);
	kfree(xwork);
}

static void vhba_sync_end(struct work_struct *work)
{
	struct xsvhba_work *xwork = container_of(work, struct xsvhba_work,
						 work);

	xsmp_cookie_t xsmp_hndl = xwork->xsmp_hndl;
	struct virtual_hba *vhba = NULL;
	struct virtual_hba *tmp_vhba;
	unsigned long flags = 0;

	/* Delete all non-sync'ed VHBAs */
	read_lock_irqsave(&vhba_global_lock, flags);
	list_for_each_entry_safe(vhba, tmp_vhba, &vhba_g.list, list) {
		if (xsmp_sessions_match(&vhba->xsmp_info, xsmp_hndl)) {
			if (vhba->sync_needed) {
				read_unlock_irqrestore(&vhba_global_lock,
						       flags);
				dprintk(TRC_INFO, vhba,
					"Deleting vhba on xsmp_hndl=%p\n",
					xsmp_hndl);
				vhba_delete(vhba->resource_id);
				read_lock_irqsave(&vhba_global_lock, flags);
			}
		}
	}
	read_unlock_irqrestore(&vhba_global_lock, flags);
	dprintk(TRC_INFO, NULL, "xsmp_hndl=%p\n", xsmp_hndl);
	kfree(xwork->msg);
	kfree(xwork);
}

static void vhba_xsmp_handle_oper_req(struct work_struct *work)
{
	struct xsvhba_work *xwork = container_of(work, struct xsvhba_work,
						 work);

	struct vhba_xsmp_msg *msg = (struct vhba_xsmp_msg *)xwork->msg;
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha;
	int qp_state = 0;

	vhba = vhba_get_context_by_resource_id(msg->resource_id);

	if (vhba == NULL)
		goto out;
	ha = vhba->ha;

	qp_state = atomic_read(&ha->qp_status);
	if (qp_state == VHBA_QP_CONNECTED) {
		dprintk(TRC_XSMP, NULL,
			"SYNC: sending oper state up for "
			"vhba %p due to oper req. QP state = %d\n",
			vhba, qp_state);

		vhba_xsmp_notify(xwork->xsmp_hndl, msg->resource_id,
				 XSMP_VHBA_OPER_UP);
	} else {
		dprintk(TRC_XSMP, NULL,
			"SYNC: sending oper state down for "
			"vhba %p due to oper req\n", vhba);
		vhba_xsmp_notify(xwork->xsmp_hndl, msg->resource_id,
				 XSMP_VHBA_OPER_DOWN);
	}
	DEC_REF_CNT(vhba);
out:
	kfree(xwork->msg);
	kfree(xwork);
}

void vhba_xsmp_create(struct work_struct *work)
{
	struct xsvhba_work *xwork = container_of(work, struct xsvhba_work,
						 work);

	struct vhba_xsmp_msg *msg = (struct vhba_xsmp_msg *)xwork->msg;

	dprintk(TRC_XSMP, NULL, "Vhba: Type= %d Code= %d Len= %d BMask= %d\n",
		msg->type, msg->code, msg->length, msg->bit_mask);

	dprintk(TRC_XSMP, NULL, "Vhba: TCA_Lid= %d TS= %d Res_Id= %Lx\n",
		ntohs(msg->tca_lid), msg->tapesupport, msg->resource_id);

	dprintk(TRC_XSMP, NULL, "Vhba: BW= %d AS= %d QD= %d ET= %d\n",
		msg->bandwidth, msg->adminstate, msg->scsiqueuedepth,
		msg->executionthrottle);

	dprintk(TRC_INFO, NULL, "INSTALL received for vhba:vid %s:0x%Lx\n",
		msg->vh_name, msg->resource_id);
	vhba_create(xwork->xsmp_hndl, msg);

	kfree(xwork->msg);
	kfree(xwork);
}

int vhba_update(xsmp_cookie_t xsmp_hndl, struct vhba_xsmp_msg *msg)
{
	struct scsi_xg_vhba_host *ha = NULL;
	struct virtual_hba *vhba;
	int ret = 0;

	vhba = vhba_get_context_by_resource_id(msg->resource_id);

	if (vhba == NULL) {
		dprintk(TRC_XSMP_ERRS, NULL, "vhba not found\n");
		ret = -EINVAL;
		goto out;
	}

	ha = vhba->ha;

	dprintk(TRC_XSMP, vhba,
		"xg lid %x guid %llx msg lid %x "
		"guid %llx %x %llx\n",
		ntohs(vhba->cfg->tca_lid),
		be64_to_cpu(vhba->cfg->tca_guid),
		ntohs(msg->tca_lid), be64_to_cpu(msg->tca_guid), msg->tca_lid,
		msg->tca_guid);

	if (msg->bit_mask & VHBA_XT_INFO_CHANGE) {
		dprintk(TRC_XSMP, vhba, "bit mask is %ux\n", msg->bit_mask);
		dprintk(TRC_XSMP,
			vhba, "xg lid %x guid %llx msg lid %x guid %llx\n",
			ntohs(vhba->cfg->tca_lid),
			be64_to_cpu(vhba->cfg->tca_guid),
			ntohs(msg->tca_lid), be64_to_cpu(msg->tca_guid));

		/*
		 * Make this change to handle the case when
		 * the XCM sends an vhba_update message
		 * with the same TCA GUID and LID.
		 *
		 * We now ignore the message when the TCA GUID and
		 * LID are the same as ones we have stored.
		 */
		if ((vhba->cfg->tca_lid == msg->tca_lid) &&
		    (vhba->cfg->tca_guid == msg->tca_guid)) {
			dprintk(TRC_XSMP_ERRS, vhba,
				"Received identical GUID and LID\n");
			goto out1;
		}
	}

	if (msg->bit_mask & VHBA_XT_STATE_DOWN) {
		dprintk(TRC_XSMP, NULL, "XT state DOWN received.\n");
		vhba_xsmp_stats.xt_state_dn_cnt++;
		vhba_xsmp_notify(xsmp_hndl, vhba->resource_id,
				 XSMP_VHBA_OPER_DOWN);
		atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);
	} else if (msg->bit_mask & VHBA_XT_INFO_CHANGE) {
		atomic_set(&vhba->vhba_state, VHBA_STATE_BUSY);
		dprintk(TRC_XSMP, vhba,
			"Received new TCA "
			"LID and GUID. Reconnecting QPs "
			"with new IB info.\n");
		vhba_xsmp_stats.tca_lid_changed_cnt++;

		vhba->cfg->tca_lid = msg->tca_lid;
		vhba->cfg->tca_guid = msg->tca_guid;

		vhba->ctrl_conn.ctx.dguid = be64_to_cpu(msg->tca_guid);
		vhba->data_conn.ctx.dguid = be64_to_cpu(msg->tca_guid);
		vhba->ctrl_conn.ctx.dlid = be16_to_cpu(msg->tca_lid);
		vhba->data_conn.ctx.dlid = be16_to_cpu(msg->tca_lid);

		vhba_purge_pending_ios(vhba);
		atomic_set(&ha->qp_status, VHBA_QP_TRYCONNECTING);
	} else if (msg->bit_mask & VHBA_LDT_CHANGED) {
		dprintk(TRC_XSMP, vhba,
			"bit mask is %08x, Update IB timer=%d\n",
			msg->bit_mask, msg->linkdowntimeout);
		vhba->cfg->linkdowntimeout = msg->linkdowntimeout;
	}
out1:
	DEC_REF_CNT(vhba);
out:
	return ret;
}

void vhba_xsmp_modify(struct work_struct *work)
{
	struct xsvhba_work *xwork =
	    container_of(work, struct xsvhba_work, work);

	struct vhba_xsmp_msg *msg = (struct vhba_xsmp_msg *)xwork->msg;
	int vhba_xsmp_length = sizeof(struct vhba_xsmp_msg);
	int ret = 0;

	ret = vhba_update(xwork->xsmp_hndl, msg);

	if (!ret)
		vhba_xsmp_ack(xwork->xsmp_hndl, (u8 *) msg, vhba_xsmp_length);
	else
		vhba_xsmp_nack(xwork->xsmp_hndl, (u8 *) msg, vhba_xsmp_length,
			       VHBA_NACK_GENERAL_ERROR);

	kfree(xwork->msg);
	kfree(xwork);
}

static void vhba_xsmp_delete(struct work_struct *work)
{
	struct xsvhba_work *xwork =
	    container_of(work, struct xsvhba_work, work);

	struct vhba_xsmp_msg *msg = (struct vhba_xsmp_msg *)xwork->msg;
	int vhba_xsmp_length = sizeof(struct vhba_xsmp_msg);
	int ret = 0;

	dprintk(TRC_INFO, NULL, "DELETE received for vhba:vid %s:0x%Lx\n",
		msg->vh_name, msg->resource_id);
	ret = vhba_delete(msg->resource_id);
	if (ret == -EIO) {
		dprintk(TRC_XSMP, NULL,
			"delete failed. device busy, "
			"sending NACK\n");
		vhba_xsmp_nack(xwork->xsmp_hndl, (u8 *) msg, vhba_xsmp_length,
			       VHBA_NACK_DEVICE_BUSY);
	} else {
		vhba_xsmp_ack(xwork->xsmp_hndl, (u8 *) msg, vhba_xsmp_length);
		dprintk(TRC_XSMP, NULL, "sent ack\n");
	}
	kfree(xwork->msg);
	kfree(xwork);
}

static void vhba_xsmp_boot_msg(struct work_struct *work)
{
	struct xsvhba_work *xwork =
	    container_of(work, struct xsvhba_work, work);

	struct vhba_boot_info *msg = (struct vhba_boot_info *)xwork->msg;
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha = NULL;
	struct os_tgt *tq = NULL;
	int i, x = 0;
	int tgt;
	xg_tgt_wwpn boot_xwwpn;
	xg_tgt_wwpn mount_xwwpn;

	vhba = vhba_get_context_by_resource_id(msg->resource_id);

	if (vhba == NULL)
		goto out;

	ha = vhba->ha;

	ha->boot_count = msg->boot_count;
	ha->mount_count = msg->mount_count;
	ha->mount_type = msg->mount_type;

	dprintk(TRC_XSMP, vhba,
		"Boot count = %d\t "
		"Mount count = %d\tMount type = %d\n",
		ha->boot_count, ha->mount_count, ha->mount_type);

	for (i = 0; i < ha->boot_count; i++) {
		memset(&ha->sanboot[i], 0,
		       sizeof(struct host_san_vhba_list_sts));

		memcpy(ha->sanboot[i].vh_name, msg->boot_devlist[i].vh_name,
		       VHBA_NAME_LEN);
		ha->sanboot[i].wwn = msg->boot_devlist[i].wwn;
		ha->sanboot[i].lun = msg->boot_devlist[i].lun;

		for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
			tq = TGT_Q(ha, tgt);
			if (!tq)
				continue;
			else {
				for (x = 0; x < WWN_SIZE; x++)
					boot_xwwpn.wwpn_t[7 - x] =
					    tq->fcport->port_name[x];
			}
			dprintk(TRC_XSMP, NULL,
				"Boot (local target WWN)  WWN = %Lx\n",
				boot_xwwpn.wwpn_val);

			if (tq && (boot_xwwpn.wwpn_val == ha->sanboot[i].wwn)) {
				dprintk(TRC_XSMP, NULL,
					"Found a wwn match "
					"for a valid target\n");
				ha->sanboot[i].tgt_num =
				    tq->fcport->os_target_id;
			}
		}

		dprintk(TRC_XSMP, vhba, "Boot device # %d\n", i);
		dprintk(TRC_XSMP, vhba,
			"vh_name: %s\tWWPN:0x%llx\t Lun: 0x%x\n",
			ha->sanboot[i].vh_name, ha->sanboot[i].wwn,
			ha->sanboot[i].lun);
	}

	for (i = 0; i < ha->mount_count; i++) {
		memcpy(&ha->sanmount[i].vh_name,
		       &msg->mount_devlist[i].vh_name, VHBA_NAME_LEN);
		ha->sanmount[i].wwn = msg->mount_devlist[i].wwn;
		ha->sanmount[i].lun = msg->mount_devlist[i].lun;

		for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
			tq = TGT_Q(ha, tgt);
			if (!tq)
				continue;
			else {
				for (x = 0; x < WWN_SIZE; x++)
					mount_xwwpn.wwpn_t[7 - x] =
					    tq->fcport->port_name[x];
			}
			dprintk(TRC_XSMP, NULL,
				"Mount(local target WWN)  WWN = %Lx\n",
				mount_xwwpn.wwpn_val);

			if (tq &&
				(mount_xwwpn.wwpn_val == ha->sanmount[i].wwn)) {
				ha->sanmount[i].tgt_num =
				    tq->fcport->os_target_id;

				dprintk(TRC_XSMP, NULL,
					"Found a wwpn match"
					" for a valid target. "
					"Tgt id = %d (%d)\n",
					ha->sanmount[i].tgt_num,
					tq->fcport->os_target_id);
			}

		}

		dprintk(TRC_XSMP, vhba, "Mount device # %d\n", i);
		dprintk(TRC_XSMP, vhba,
			"vh_name: %s\tWWPN:0x%Lx\t "
			"Lun: 0x%x\n",
			(char *)ha->sanmount[i].vh_name,
			ha->sanmount[i].wwn, ha->sanmount[i].lun);
	}

	if (ha->mount_type == 1) {
		memcpy(ha->host_lvm_info.logical_vol_group,
		       msg->logical_vol_group, VHBA_LVM_NAME_LEN);

		memcpy(ha->host_lvm_info.logical_vol, msg->logical_vol,
		       VHBA_LVM_NAME_LEN);

		dprintk(TRC_XSMP, vhba,
			"Msg:   Logical vol group: %s\tLogical vol = %s\n",
			msg->logical_vol_group, msg->logical_vol);

	} else if (ha->mount_type == 2) {
		memcpy(ha->direct_mount_dev, msg->direct_mount_dev,
		       VHBA_LVM_NAME_LEN);

		dprintk(TRC_XSMP, NULL, "Direct mount device = %s\n",
			(char *)ha->direct_mount_dev);
	}

	memcpy(ha->mount_options, msg->mount_options, VHBA_MOUNT_OPT_LEN);

	dprintk(TRC_XSMP, NULL, "Mount options = %s\n",
		(char *)ha->mount_options);

	vhba_xsmp_ack(xwork->xsmp_hndl, (u8 *) msg,
		      sizeof(struct vhba_boot_info));

	DEC_REF_CNT(vhba);
out:
	kfree(xwork->msg);
	kfree(xwork);
}

/*   The interface function used by the XCPM to deliver messages */
static int vhba_xsmp_msg_handler(xsmp_cookie_t xsmp_hndl, u8 *data, int length)
{
	struct xsvhba_work *vhba_work;
	void *xsmp_msg;
	u8 *msg;
	int type = 0;
	int boot_type;
	int ret = 0;

	dprintk(TRC_XSMP, NULL, "New message, length <%d>\n", length);

	vhba_work = kmalloc(sizeof(struct xsvhba_work), GFP_ATOMIC);
	if (!vhba_work) {
		eprintk(NULL, "vhba_work kmalloc failed\n");
		ret = -1;
		goto out;
	}

	if (length < sizeof(struct xsmp_message_header)) {
		eprintk(NULL, "Error - Message too short. Returning -1\n");
		ret = -1;
		goto out;
	}

	if (vhba_swap_bytes(N_TO_H, data)) {
		eprintk(NULL,
			"Errors in the received message, dropping it. "
			"Returning -1\n");
		ret = -1;
		goto out;
	}

	if (*(u8 *) data != XSMP_MESSAGE_TYPE_VHBA) {
		eprintk(NULL,
			"Error - Wrong message type, not a VHBA message. "
			"Returning -1\n");
		ret = -1;
		goto out;
	}

	if (*(u16 *) (data + 2) != length)
		dprintk(TRC_XSMP, NULL,
			"Warning - lengths are not the same, "
			"header: 0x%x, actual: 0x%x\n",
			*(u16 *) (data + 2), length);

	msg = data + sizeof(struct xsmp_message_header);
	length -= sizeof(struct xsmp_message_header);

	boot_type = *msg;

	if (boot_type == XSMP_VHBA_BOOT_INFO)
		xsmp_msg = kmalloc(sizeof(struct vhba_boot_info), GFP_ATOMIC);
	else
		xsmp_msg = kmalloc(sizeof(struct vhba_xsmp_msg), GFP_ATOMIC);

	if (!xsmp_msg) {
		eprintk(NULL, "xsmp msg kmalloc failed\n");
		ret = -1;
		goto out;
	}

	if (boot_type == XSMP_VHBA_BOOT_INFO)
		memcpy(xsmp_msg, msg, sizeof(struct vhba_boot_info));
	else
		memcpy(xsmp_msg, msg, sizeof(struct vhba_xsmp_msg));

	type = *(u8 *) xsmp_msg;
	vhba_work->xsmp_hndl = xsmp_hndl;
	vhba_work->msg = xsmp_msg;
	vhba_work->len = length;
	vhba_xsmp_stats.last_msg = type;

	vhba_handle_xsmp_msg(type, vhba_work);

out:
	kfree(data);
	return ret;
}

/* The interface functions exported to the XCPM as callbacks */
void vhba_receive_handler(xsmp_cookie_t xsmp_hndl, u8 *data, int length)
{
	vhba_xsmp_msg_handler(xsmp_hndl, data, length);
}

static int vhba_swap_bytes(int direction, u8 *msg)
{
	int rem_length = 0;
	int vhba_xsmp_length = sizeof(struct vhba_xsmp_msg);
	int num_messages = 0;
	int count = 0;
	int type = 0;
	int i = 0;

	if (direction == N_TO_H && (*(u8 *) msg == XSMP_MESSAGE_TYPE_VHBA))
		rem_length = ntohs(*(u16 *) (msg + 2));
	else if (direction == H_TO_N && (*(u8 *) msg == XSMP_MESSAGE_TYPE_VHBA))
		rem_length = *(u16 *) (msg + 2);
	else {
		eprintk(NULL,
			"Error - Hdr type not of a lcl msg. "
			"Returning -1\n");
		return -1;
	}

	if (direction == H_TO_N)
		dprintk(TRC_XSMP, NULL,
			"Sending message: type <0x%x>, "
			"length <0x%x>\n", *(u16 *) (msg), *(u16 *) (msg + 2));

	if (direction == N_TO_H)
		dprintk(TRC_XSMP, NULL,
			"Message received: XSMP type <0x%x>, "
			"length <0x%x>, sequence_number <0x%x>\n",
			*(u8 *) (msg), htons(*(u16 *) (msg + 2)),
			htonl(*(u32 *) (msg + 4)));

	/* Swizzle the header first */
	msg += 2;		/* Type */
	*(u16 *) msg = htons(*(u16 *) msg);	/* Length */
	msg += 2;
	*(u32 *) msg = htonl(*(u32 *) msg);	/* Sequence number */
	msg += 4;

	/* Skip the source and destination IDs */
	msg += 24;

	rem_length -= sizeof(struct xsmp_message_header);

	dprintk(TRC_XSMP, NULL,
		"Msg payload length %d"
		" vhba_xsmp_length %d\n", rem_length, vhba_xsmp_length);

	type = *(u8 *) (msg);
	if (type == XSMP_VHBA_STATS) {
		struct _vhba_stats *pstats = (struct _vhba_stats *)msg;

		dprintk(TRC_XSMP, NULL, "received a stats message\n");
		if (direction == N_TO_H) {
			pstats->length = htons(pstats->length);
			dprintk(TRC_XSMP, NULL, "length %d\n", pstats->length);
			dprintk(TRC_XSMP, NULL,
				"vid before (%llX)\n", pstats->vid);
			pstats->vid = htonq(pstats->vid);
			dprintk(TRC_XSMP, NULL,
				"vid after (%llX)\n", pstats->vid);
		} else if (direction == H_TO_N) {
			pstats->vid = htonq(pstats->vid);
			dprintk(TRC_XSMP, NULL,
				"vid exit (%llX)\n", pstats->vid);
		}
		dprintk(TRC_XSMP, NULL, "action = %d", pstats->action);
		return 0;
	}

	if (type == XSMP_VHBA_BOOT_INFO) {
		struct vhba_boot_info *pboot = (struct vhba_boot_info *)msg;

		dprintk(TRC_XSMP, NULL, "received a boot message\n");
		if (direction == N_TO_H) {

			pboot->length = ntohs(pboot->length);
			pboot->resource_id = ntohq(pboot->resource_id);
			pboot->boot_count = ntohs(pboot->boot_count);

			for (i = 0; i < pboot->boot_count; i++) {
				pboot->boot_devlist[i].wwn =
				    ntohq(pboot->boot_devlist[i].wwn);
				dprintk(TRC_XSMP, NULL,
					"WWN = %llx (%Lx)\n",
					pboot->boot_devlist[i].wwn,
					pboot->boot_devlist[i].wwn);
				pboot->boot_devlist[i].lun =
				    ntohs(pboot->boot_devlist[i].lun);
				dprintk(TRC_XSMP, NULL, "lun  = %d\n",
					pboot->boot_devlist[i].lun);
			}

			pboot->mount_type = ntohs(pboot->mount_type);
			pboot->mount_count = ntohs(pboot->mount_count);

			for (i = 0; i < pboot->mount_count; i++) {
				dprintk(TRC_XSMP, NULL, "VHBA name = %s\n",
					(char *)(pboot->
						 mount_devlist[i].vh_name));
				pboot->mount_devlist[i].wwn =
				    ntohq(pboot->mount_devlist[i].wwn);
				dprintk(TRC_XSMP, NULL, "WWN = %llx (%Lx)\n",
					pboot->mount_devlist[i].wwn,
					pboot->mount_devlist[i].wwn);
				pboot->mount_devlist[i].lun =
				    ntohs(pboot->mount_devlist[i].lun);
				dprintk(TRC_XSMP, NULL, "lun  = %d\n",
					pboot->mount_devlist[i].lun);

			}
		} else if (direction == H_TO_N)
			dprintk(TRC_XSMP, NULL,
				"Host to network message. "
				"Doing nothing for now\n");

		return 0;
	}

	if (rem_length % vhba_xsmp_length != 0) {
		eprintk(NULL,
			"Error - Incorrect length XSMP header and payload,"
			" input_size(%d) header (%d)\n",
			rem_length, vhba_xsmp_length);
		return -1;
	}

	num_messages = rem_length / vhba_xsmp_length;

	for (count = 0; count < num_messages; count++) {
		struct vhba_xsmp_msg *payload = (struct vhba_xsmp_msg *)msg;

		if (rem_length == 0)
			return 0;

		payload->length = htons(payload->length);
		payload->bit_mask = htonl(payload->bit_mask);
		payload->resource_id = htonq(payload->resource_id);

		payload->vhba_flag = htons(payload->vhba_flag);
		payload->mtu = htonl(payload->mtu);
		payload->tapesupport = htons(payload->tapesupport);
		payload->bandwidth = htons(payload->bandwidth);
		payload->interruptdelaytimer =
		    htonl(payload->interruptdelaytimer);
		payload->executionthrottle = htonl(payload->executionthrottle);
		payload->scsiqueuedepth = htonl(payload->scsiqueuedepth);
		payload->linkdowntimeout = htonl(payload->linkdowntimeout);

		payload->adminstate = htonl(payload->adminstate);
		payload->enabletargetreset = htonl(payload->enabletargetreset);
		payload->maxlunspertarget = htonl(payload->maxlunspertarget);

		msg += vhba_xsmp_length;
	}
	return 0;
}

void vhba_handle_xsmp_msg(int type, struct xsvhba_work *vhba_work)
{

	switch (type) {
	case XSMP_VHBA_INSTALL:{
			dprintk(TRC_XSMP, NULL,
				"Received XSMP_VHBA_INSTALL msg\n");
			vhba_xsmp_stats.install_msg_cnt++;
			INIT_WORK(&vhba_work->work, vhba_xsmp_create);
			queue_work(vhba_workqueuep, &vhba_work->work);
			break;
		}

	case XSMP_VHBA_DELETE:{
			dprintk(TRC_XSMP, NULL,
				"Received XSMP_VHBA_DELETE msg\n");
			vhba_xsmp_stats.delete_msg_cnt++;
			INIT_WORK(&vhba_work->work, vhba_xsmp_delete);
			queue_work(vhba_workqueuep, &vhba_work->work);
			break;
		}

	case XSMP_VHBA_UPDATE:{
			dprintk(TRC_XSMP, NULL,
				"Received XSMP_VHBA_UPDATE msg\n");
			vhba_xsmp_stats.update_msg_cnt++;
			INIT_WORK(&vhba_work->work, vhba_xsmp_modify);
			queue_work(vhba_workqueuep, &vhba_work->work);
			break;
		}

	case XSMP_VHBA_STATS:{
			dprintk(TRC_XSMP, NULL,
				"Received XSMP_VHBA_STATS msg\n");
			INIT_WORK(&vhba_work->work, vhba_xsmp_stats_req);
			queue_work(vhba_workqueuep, &vhba_work->work);
			vhba_xsmp_stats.cfg_stats_msg_cnt++;
			break;
		}

	case XSMP_VHBA_SYNC_BEGIN:{
			dprintk(TRC_XSMP, NULL,
				"SYNC: Received XSMP_VHBA_SYNC_BEGIN msg\n");
			vhba_xsmp_stats.sync_begin_msg_cnt++;
			INIT_WORK(&vhba_work->work, vhba_sync_begin);
			queue_work(vhba_workqueuep, &vhba_work->work);
			break;
		}

	case XSMP_VHBA_SYNC_END:{
			dprintk(TRC_XSMP, NULL,
				"SYNC: Received XSMP_VHBA_SYNC_END msg\n");
			vhba_xsmp_stats.sync_end_msg_cnt++;
			INIT_WORK(&vhba_work->work, vhba_sync_end);
			queue_work(vhba_workqueuep, &vhba_work->work);
			break;
		}

	case XSMP_VHBA_OPER_REQ:{
			dprintk(TRC_XSMP, NULL,
				"SYNC: Received XSMP_VHBA_OPER_REQ\n");
			vhba_xsmp_stats.oper_req_msg_cnt++;
			INIT_WORK(&vhba_work->work, vhba_xsmp_handle_oper_req);
			queue_work(vhba_workqueuep, &vhba_work->work);
			break;
		}

	case XSMP_VHBA_BOOT_INFO:{
			dprintk(TRC_XSMP, NULL,
				"Received XSMP_VHBA_BOOT_INFO msg\n");
			vhba_xsmp_stats.boot_msg_cnt++;
			INIT_WORK(&vhba_work->work, vhba_xsmp_boot_msg);
			queue_work(vhba_workqueuep, &vhba_work->work);
			break;
		}

	default:{
			dprintk(TRC_XSMP, NULL,
				"Warning - Invalid session "
				"message. Returning -1\n");
			vhba_xsmp_stats.unknown_msg_cnt++;
			vhba_xsmp_stats.last_unknown_msg = type;
			kfree(vhba_work);
		}
	}
}

int vhba_create_context(struct vhba_xsmp_msg *msg, struct virtual_hba *vhba)
{
	u32 idr;
	int ret = 0;
	unsigned long flags = 0;
	struct virtual_hba *t_vhba;
	u64 resource_id = msg->resource_id;

	if (!idr_pre_get(&vhba_idr_table, GFP_KERNEL))
		return -1;

	write_lock_irqsave(&vhba_global_lock, flags);
	list_for_each_entry(t_vhba, &vhba_g.list, list) {
		if (t_vhba->resource_id == resource_id) {
			/*
			 * Already in the list, may have been due to sync-begin
			 * operation. Reset the sync flag and return
			 */
			dprintk(TRC_INFO, t_vhba,
				"vhba already in the list: vid 0x%Lx\n",
				t_vhba->resource_id);
			t_vhba->sync_needed = 0;
			ret = 0;
			goto out;
		}
	}
	if (idr_get_new_above(&vhba_idr_table, (void *)vhba,
			      vhba_current_idr, &idr) < 0) {
		ret = -1;
		goto out;
	}

	vhba->idr = idr;
	vhba->resource_id = resource_id;
	vhba_current_idr = idr + 1;
	ret = 1;

out:
	write_unlock_irqrestore(&vhba_global_lock, flags);
	return ret;
}

void vhba_add_context(struct virtual_hba *vhba)
{
	unsigned long flags = 0;

	atomic_inc(&vhba->ref_cnt);
	write_lock_irqsave(&vhba_global_lock, flags);
	list_add_tail(&vhba->list, &vhba_g.list);
	write_unlock_irqrestore(&vhba_global_lock, flags);
}

struct virtual_hba *vhba_remove_context(u64 resource_id)
{
	struct virtual_hba *vhba = NULL;
	unsigned long flags = 0;

	write_lock_irqsave(&vhba_global_lock, flags);
	list_for_each_entry(vhba, &vhba_g.list, list) {
		if (vhba->resource_id == resource_id)
			goto out;
	}
	write_unlock_irqrestore(&vhba_global_lock, flags);
	return NULL;
out:
	idr_remove(&vhba_idr_table, vhba->idr);
	atomic_dec(&vhba->ref_cnt);
	list_del(&vhba->list);
	write_unlock_irqrestore(&vhba_global_lock, flags);
	return vhba;
}

struct virtual_hba *vhba_get_context_by_resource_id(u64 resource_id)
{
	struct virtual_hba *vhba = NULL;
	unsigned long flags = 0;

	read_lock_irqsave(&vhba_global_lock, flags);
	list_for_each_entry(vhba, &vhba_g.list, list) {
		if (vhba->resource_id == resource_id)
			goto out;
	}
	read_unlock_irqrestore(&vhba_global_lock, flags);
	return NULL;
out:
	atomic_inc(&vhba->ref_cnt);
	read_unlock_irqrestore(&vhba_global_lock, flags);
	return vhba;
}

struct virtual_hba *vhba_get_context_by_idr(u32 idr)
{
	struct virtual_hba *vhba;
	unsigned long flags = 0;

	read_lock_irqsave(&vhba_global_lock, flags);
	vhba = idr_find(&vhba_idr_table, idr);
	if (vhba)
		atomic_inc(&vhba->ref_cnt);

	read_unlock_irqrestore(&vhba_global_lock, flags);
	return vhba;
}
