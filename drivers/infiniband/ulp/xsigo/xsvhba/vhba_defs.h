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

#ifndef __VHBA_DEFS_H__
#define __VHBA_DEFS_H__

#include <linux/types.h>

#include "vhba_os_def.h"
#include "vhba_xsmp.h"

#define VHBA_VALIDATE_STATE(vhba)				\
{								\
	if (atomic_read(&vhba->ha->qp_status) != VHBA_QP_CONNECTED) {	\
		dprintk(0, vhba,				\
			"Error - QPs not connected!\n");	\
		ret_error = 1;					\
	}							\
}

extern int vhba_abort_recovery_count;
extern struct scsi_transport_template *vhba_transport_template;
extern int vhba_max_dsds_in_fmr;
extern int vhba_max_fmr_pages;
extern int hba_offset;
extern int force_sp_copy;
extern int vhba_use_fmr;
extern int boot_vhba_use_fmr;
extern struct scsi_host_template xg_vhba_driver_template;
extern int cmds_per_lun;
extern int vhba_max_transfer_size;
extern int vhba_max_scsi_retry;
extern int vhba_initialize(struct virtual_hba *vhba, struct vhba_xsmp_msg *msg);
extern int vhba_add_proc_entry(struct virtual_hba *vhba);
extern int vhba_add_target_proc_entry(struct virtual_hba *vhba);
extern int vhba_remove_target_proc_entry(struct virtual_hba *vhba);
extern void vhba_remove_proc_entry(struct virtual_hba *vhba);
extern void add_to_defer_list(struct scsi_xg_vhba_host *ha, struct srb *sp);
extern int vhba_map_buf_fmr(struct virtual_hba *vhba, u64 *phys_addr,
			    int num_pgs, u64 *mapped_fmr_iova, struct srb *sp,
			    int index);
extern void extend_timeout(struct scsi_cmnd *cmd, struct srb *sp, int timeout);
extern void ib_link_down(struct scsi_xg_vhba_host *ha);
extern void ib_link_dead_poll(struct scsi_xg_vhba_host *ha);
extern int vhba_send_heart_beat(struct virtual_hba *vhba);
extern int check_number_of_vhbas_provisioned(void);
extern int vhba_check_discs_status(void);

int vhba_create_procfs_root_entries(void);
void vhba_remove_procfs_root_entries(void);
ssize_t vhba_read(struct file *, char *, size_t, loff_t *);
ssize_t vhba_write(struct file *, const char *, size_t, loff_t *);
int vhba_open(struct inode *, struct file *);
int vhba_release(struct inode *, struct file *);
int vhba_ioctl(struct inode *, struct file *, unsigned int, unsigned long);

void vhba_internal_processing(void);

/*
 * Globals
 */
extern struct semaphore vhba_init_sem;
extern int vhba_ready;
extern struct timer_list vhba_init_timer;
extern int vhba_init_timer_on;

extern struct semaphore vhba_cmd_sem;
extern int vhba_cmd_done;
extern struct timer_list vhba_cmd_timer;
extern int vhba_cmd_timer_on;

extern int bench_target_count;
extern int vhba_multiple_q;

#define VHBA_RECONN_INTERVAL 5
#define MAX_IOCBS_IN_VH 2

extern struct proc_dir_entry *proc_root_vhba;
extern struct proc_dir_entry *proc_root_vhba_dev;
extern struct proc_dir_entry *proc_root_vhba_targ;

int vhba_print_io_stats(struct seq_file *m, struct scsi_xg_vhba_host *ha);
int vhba_print_ib_stats(struct seq_file *m, struct scsi_xg_vhba_host *ha);
int vhba_print_xsmp_stats(struct seq_file *m, struct scsi_xg_vhba_host *ha);
int vhba_print_fmr_stats(struct seq_file *m, struct scsi_xg_vhba_host *ha);
int vhba_print_fc_stats(struct seq_file *m, struct scsi_xg_vhba_host *ha);
int vhba_print_scsi_stats(struct seq_file *m, struct scsi_xg_vhba_host *ha);

extern char vhba_version_str[40];
extern int vhba_xsmp_service_id;
extern struct service_type_info service_info;
extern struct vhba_xsmp_stats vhba_xsmp_stats;

extern int init_status;
extern int dev_major;
extern int vhba_ready;
extern struct timer_list vhba_init_timer;
extern int vhba_init_timer_on;
extern struct vhba_discovery_msg disc_info;
extern struct vhba_io_cmd vhba_io_cmd_o;

void xg_vhba_free_device(struct virtual_hba *);
int vhba_send_init_blk(struct virtual_hba *);
int vhba_send_enable_vhba(struct virtual_hba *);
int vhba_send_vhba_write_index(int);
int send_abort_command(int, struct srb *sp, unsigned int t);
int send_device_reset(int, unsigned int t);
int send_link_reset(int);
int vhbawq_init(void);
int vhbawq_queue(void);
int vhbawq_cleanup(void);

#endif /* __VHBA_DEFS_H__ */
