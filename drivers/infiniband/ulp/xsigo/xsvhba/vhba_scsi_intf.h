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

#ifndef __VHBA_SCSI_INTF_H__
#define __VHBA_SCSI_INTF_H__

extern int vhba_max_q_depth;
extern int vhba_max_scsi_retry;
extern int vhba_default_scsi_timeout;

int vhba_purge_pending_ios(struct virtual_hba *vhba);
void vhba_taskmgmt_flush_ios(struct virtual_hba *vhba, int tgt_id, int lun,
			     int lun_reset_flag);
int vhba_send_abort(struct virtual_hba *vhba, int abort_handle, int t);
int vhba_send_lun_reset(struct virtual_hba *vhba, int t, int l);
int vhba_send_tgt_reset(struct virtual_hba *vhba, int t);
void complete_cmd_and_callback(struct virtual_hba *vhba, struct srb *sp,
			       struct scsi_cmnd *cp);
int vhba_start_scsi(struct srb *sp, u32 t, u32 l, u32 handle);
int vhba_report_luns_cmd(struct srb *sp, u32 t, u32 l);
int vhba_ib_disconnect_qp(struct virtual_hba *vhba);
int vhba_purge_pending_ios(struct virtual_hba *vhba);
struct os_lun *vhba_allocate_lun(struct virtual_hba *vhba, u32 tgt, u32 lun);
int get_outstding_cmd_entry(struct virtual_hba *vhba);

void vhba_set_tgt_count(struct virtual_hba *vhba);
void vhba_mark_tgts_lost(struct virtual_hba *vhba);
int vhba_set_all_tgts_offline(struct virtual_hba *vhba);

int xg_vhba_start_scsi(void);
void xg_vhba_free_device(struct virtual_hba *);
extern int vhba_scsi_release(struct virtual_hba *vhba);
void dump_iocb(struct cmd_type_7 *cmd_pkt);

#endif
