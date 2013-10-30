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
#include <linux/proc_fs.h>
#include <linux/delay.h>

#include "vhba_os_def.h"
#include "vhba_xsmp.h"
#include "vhba_ib.h"
#include "vhba_defs.h"

#define vhba_proc_print(buf, len, fmt, args...)				\
	do {								\
		if (len < (limit - 256)) {				\
			len += snprintf((char *)(buf+len), 256, fmt,	\
					## args);			\
		} else {						\
			len += snprintf((char *)(buf+len), limit - len,	\
					fmt, ## args);			\
			eprintk(NULL, "proc buffer limit exceeded %d\n",\
					len);				\
			goto out;					\
		}							\
	} while (0)

#define vhba_proc_fn_print(buf, len, fmt, args...)			\
	do {								\
		if (len < (limit - 256)) {				\
			len += snprintf((char *)(buf+len), 256, fmt,	\
					## args);			\
		} else {						\
			len += snprintf((char *)(buf+len), limit - len,	\
					fmt, ## args);			\
			eprintk(NULL, "proc buffer limit exceeded\n");	\
			return limit;					\
		}							\
	} while (0)

int limit = PAGE_SIZE;

int force_sp_copy;

struct proc_dir_entry *proc_root_vhba;
struct proc_dir_entry *proc_root_vhba_dev;
struct proc_dir_entry *proc_root_vhba_targ;

/*
int vhba_print_io_stats(char *page, int len, struct scsi_xg_vhba_host *ha);
int vhba_print_ib_stats(char *page, int len, struct scsi_xg_vhba_host *ha);
int vhba_print_xsmp_stats(char *page, int len, struct scsi_xg_vhba_host *ha);
int vhba_print_fmr_stats(char *page, int len, struct scsi_xg_vhba_host *ha);
int vhba_print_fc_stats(char *page, int len, struct scsi_xg_vhba_host *ha);
int vhba_print_scsi_stats(char *page, int len, struct scsi_xg_vhba_host *ha);
*/

static int vhba_proc_read_device(char *page, char **start, off_t off,
				 int count, int *eof, void *data)
{
	char qp_sts_str[][64] = { "VHBA_QP_NOTCONNECTED",
		"VHBA_QP_TRYCONNECTING",
		"VHBA_QP_RECONNECTING",
		"VHBA_QP_PARTIAL_CONNECT",
		"VHBA_QP_CONNECTED",
		"ERROR"
	};

	char vhba_sts_str[][64] = {
		"VHBA_STATE_NOT_ACTIVE",
		"VHBA_STATE_ACTIVE",
		"VHBA_STATE_SCAN",
		"VHBA_STATE_BUSY",
		"ERROR"
	};

	struct virtual_hba *vhba;
	int *pint;
	char *start_page = page;
	struct scsi_xg_vhba_host *ha;
	struct vhba_xsmp_msg *cfg;
	int link_state;
	u64 wwn;
	int len = 0;
	int ret = 0;

	vhba = (struct virtual_hba *)
	    vhba_get_context_by_idr((u32) (unsigned long)data);
	if (vhba == NULL) {
		dprintk(TRC_PROC, NULL, "Error - Null vhba context!\n");
		return page - start_page;
	}
	ha = vhba->ha;
	if (atomic_read(&ha->vhba_flags) != VHBA_READY) {
		dprintk(TRC_PROC, vhba, "VHBA not in ready state to\n"
			"			display valid information!\n");
		goto out;
	}
	cfg = vhba->cfg;

	vhba_proc_print(page, len, "VHBA Information\n");
	vhba_proc_print(page, len, "----------------\n");
	vhba_proc_print(page, len,
			"Symbolic Name\t\t\t: %s\n", (char *)(cfg->vh_name));
	vhba_proc_print(page, len, "Chassis Name\t\t\t: %s\n",
			vhba->xsmp_info.chassis_name);
	vhba_proc_print(page, len, "Chassis Version\t\t\t: %x\n",
			vhba->xsmp_info.version);
	vhba_proc_print(page, len, "Server-Profile Name\t\t: %s\n",
			vhba->xsmp_info.session_name);

	if (vhba->cfg->vhba_flag & 0x1) {
		vhba_proc_print(page, len,
				"Bootable\t\t\t: Yes\n");
	} else {
		vhba_proc_print(page, len,
				"Bootable\t\t\t: No\n");
	}
	vhba_proc_print(page, len,
			"VHBA state\t\t\t: %s\n",
			vhba_sts_str[atomic_read(&vhba->vhba_state)]);
	vhba_proc_print(page, len, "Link State\t\t\t: ");
	link_state = atomic_read(&ha->link_state);
	switch (link_state) {
	case 0:
		vhba_proc_print(page, len, "LINK_DOWN\n");
		break;
	case 1:
		vhba_proc_print(page, len, "LINK_UP\n");
		break;
	case 2:
		vhba_proc_print(page, len, "LINK_DEAD\n");
		break;
	default:
		vhba_proc_print(page, len, "UNKNOWN\n");
	}
	vhba_proc_print(page, len, "IB Status\t\t\t: ");
	switch (atomic_read(&ha->ib_status)) {
	case 0:
		vhba_proc_print(page, len, "IB_UP\n");
		break;
	case 1:
		vhba_proc_print(page, len, "IB_DOWN\n");
		break;
	case 2:
		vhba_proc_print(page, len, "IB_DEAD\n");
		break;
	default:
		vhba_proc_print(page, len, "UNKNOWN\n");
	}
	vhba_proc_print(page, len,
			"Reconnect Attempts\t\t: %d\n",
			(int)vhba->reconn_attempt);
	vhba_proc_print(page, len,
			"Cumulative QP Count\t\t: %d\n", (int)vhba->qp_count);
	vhba_proc_print(page, len, "Lun masking\t\t\t: %s\n",
			vhba->cfg->lunmask_enable ? "Enabled" : "Disabled");
	vhba_proc_print(page, len,
			"Host Number\t\t\t: %u\n", (unsigned)ha->host_no);
	vhba_proc_print(page, len,
			"Target count\t\t\t: %llu\n", (u64) ha->target_count);
	wwn = (u64) (vhba->cfg)->wwn;
	vhba_proc_print(page, len, "Port WWN\t\t\t:\n"
			"%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n",
			(u8) (wwn & 0xff), (u8) ((wwn >> 8) & 0xff),
			(u8) ((wwn >> 16) & 0xff), (u8) ((wwn >> 24) & 0xff),
			(u8) ((wwn >> 32) & 0xff), (u8) ((wwn >> 40) & 0xff),
			(u8) ((wwn >> 48) & 0xff), (u8) ((wwn >> 56) & 0xff));

	vhba_proc_print(page, len, "Scan Required\t\t\t: %d\n",
			vhba->scan_reqd);
	vhba_proc_print(page, len, "SCSI Max Retry count\t\t: %d\n",
			vhba_max_scsi_retry);
	vhba_proc_print(page, len, "\n");
	len = vhba_print_xsmp_stats(page, len, ha);
	if (len == limit) {
		ret = limit;
		goto out;
	}

	vhba_proc_print(page, len, "\n");
	vhba_proc_print(page, len, "VHBA Infiniband Information\n");
	vhba_proc_print(page, len, "---------------------------\n");
	vhba_proc_print(page, len,
			"Remote IB LID\t\t\t: 0x%x\n",
			be16_to_cpu(cfg->tca_lid));
	pint = (int *)&cfg->tca_guid;
	vhba_proc_print(page, len,
			"Remote IB GUID\t\t\t: 0x%x%x\n",
			be32_to_cpu(*pint), be32_to_cpu(*(pint + 1)));
	vhba_proc_print(page, len,
			"Resource ID\t\t\t: 0x%Lx\n", cfg->resource_id);
	vhba_proc_print(page, len,
			"CQP handle/qpn\t\t\t: 0x%x/%u\n",
			ha->control_qp_handle, ha->control_qpn);
	vhba_proc_print(page, len,
			"DQP handle/qpn\t\t\t: 0x%x/%u\n",
			ha->data_qp_handle, ha->data_qpn);
	vhba_proc_print(page, len,
			"QP status\t\t\t: %s\n",
			qp_sts_str[atomic_read(&ha->qp_status)]);
	vhba_proc_print(page, len, "Driver ref count\t\t: %d\n",
			atomic_read(&vhba->ref_cnt));
	vhba_proc_print(page, len, "\n");
	len = vhba_print_ib_stats(page, len, ha);
	if (len == limit) {
		ret = limit;
		goto out;
	}
	vhba_proc_print(page, len, "\n");
	len = vhba_print_io_stats(page, len, ha);
	if (len == limit) {
		ret = limit;
		goto out;
	}
	vhba_proc_print(page, len, "\n");

	/*XXX this all needs to go into different stats proc files
	 *       The vmkernel helpers don't do multipage returns, so
	 *         each /proc entry can only be less than 4K, 3K? */
	len = vhba_print_fmr_stats(page, len, ha);
	if (len == limit) {
		ret = limit;
		goto out;
	}
	vhba_proc_print(page, len, "\n");
	len = vhba_print_fc_stats(page, len, ha);
	if (len == limit) {
		ret = limit;
		goto out;
	}
	vhba_proc_print(page, len, "\n");
	len = vhba_print_scsi_stats(page, len, ha);
	if (len == limit) {
		ret = limit;
		goto out;
	}
	vhba_proc_print(page, len, "\n");
	ret = len;

out:
	DEC_REF_CNT(vhba);
	return ret;
}

static int vhba_proc_write_device(struct file *file, const char *buffer,
				  unsigned long count, void *data)
{
	struct virtual_hba *vhba;
	int newval = 0;
	vhba = (struct virtual_hba *)
	    vhba_get_context_by_idr((u32) (unsigned long)data);
	if (vhba == NULL) {
		dprintk(TRC_PROC, NULL, "Error - Null vhba context!\n");
		return count;
	}
	sscanf(buffer, "%d", &newval);
	vhba->scan_reqd = 0;
	DEC_REF_CNT(vhba);
	return count;
}

static int vhba_proc_read_target(char *page, char **start, off_t off,
				 int count, int *eof, void *data)
{
	struct virtual_hba *vhba;
	int tgt, k;
	char *start_page = page;
	struct scsi_xg_vhba_host *ha;
	struct os_tgt *tq;
	int len = 0;

	vhba = (struct virtual_hba *)
	    vhba_get_context_by_idr((u32) (unsigned long)data);
	if (vhba == NULL) {
		dprintk(TRC_PROC, NULL, "Error - Null vhba context!\n");
		return page - start_page;
	}
	ha = vhba->ha;
	if (atomic_read(&ha->vhba_flags) != VHBA_READY) {
		dprintk(TRC_PROC, NULL,
			"VHBA not in ready state to display valid information!\n");
		goto out;
	}

	vhba_proc_print(page, len, "VHBA Target Information\n");
	vhba_proc_print(page, len, "-----------------------\n\n");
	vhba_proc_print(page, len, "Host no\t\t\t\t: %u\n",
			(unsigned)ha->host_no);

	for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
		tq = TGT_Q(ha, tgt);
		if (!tq || (atomic_read(&tq->fcport->state) != FCS_ONLINE))
			continue;
		vhba_proc_print(page, len, "Target WWPN\t\t\t: ");
		for (k = 0; k < WWN_SIZE; k++)
			vhba_proc_print(page, len, "%02x ", tq->port_name[k]);
		vhba_proc_print(page, len, "\nFC Port id\t\t\t: 0x%x\n",
				tq->d_id.b24);
		vhba_proc_print(page, len,
				"Bound\t\t\t\t: %d\n", tq->fcport->bound);
		vhba_proc_print(page, len,
				"ncmds\t\t\t\t: %d\n", atomic_read(&tq->ncmds));
		vhba_proc_print(page, len,
				"Lun Count\t\t\t: %d\n", tq->fcport->lun_count);
		vhba_proc_print(page, len,
				"N-Port Handle\t\t\t: 0x%x\n",
				tq->fcport->loop_id);
		vhba_proc_print(page, len,
				"Map Order\t\t\t: %d\n",
				tq->fcport->os_target_id);

		vhba_proc_print(page, len, "Lun id(s)\t\t\t:");
		for (k = 0; k < tq->fcport->lun_count; k++) {
			if (k != 0)
				vhba_proc_print(page, len, ",");
			vhba_proc_print(page, len, " %d",
					tq->fcport->lun_ids[k]);
		}
		vhba_proc_print(page, len, "\n\n");
		vhba_proc_print(page, len, "-------------------------\n\n");
	}
out:
	DEC_REF_CNT(vhba);
	return len;
}

static int vhba_proc_write_target(struct file *file, const char *buffer,
				  unsigned long count, void *data)
{
	/* Simply return from the function */
	return 0;
}

static int vhba_proc_read_san_info(char *page, char **start, off_t off,
				   int count, int *eof, void *data)
{
	int j;
	char *start_page = page;
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha;

	read_lock(&vhba_global_lock);
	list_for_each_entry(vhba, &vhba_g.list, list) {
		ha = vhba->ha;
		dprintk(TRC_PROC, NULL,
			"Mount count = %d\tBoot count = %d\n",
			ha->mount_count, ha->boot_count);
		for (j = 0; j < ha->boot_count; j++)
			page += sprintf(page, "sanboot%d=%s:%d:%d\n",
					j, ha->sanboot[j].vh_name,
					ha->sanboot[j].tgt_num,
					ha->sanboot[j].lun);
		page += sprintf(page, "\n\n");
		for (j = 0; j < ha->mount_count; j++)
			page += sprintf(page, "sanmount%d=%s:%d:%d\n",
					j, ha->sanmount[j].vh_name,
					ha->sanmount[j].tgt_num,
					ha->sanmount[j].lun);
		if (ha->mount_type == 1)
			page += sprintf(page, "sanmount%d=lvm:%s:%s\n",
					j, ha->host_lvm_info.logical_vol_group,
					ha->host_lvm_info.logical_vol);
		else if (ha->mount_type == 2)
			page += sprintf(page, "sanmount=%s\n",
					ha->direct_mount_dev);
		if (ha->mount_options != NULL)
			page += sprintf(page, "mount-opts:%s:%s\n",
					(char *)vhba->cfg->vh_name,
					ha->mount_options);
	}
	read_unlock(&vhba_global_lock);

	return page - start_page;
}

static int vhba_proc_write_san_info(struct file *file, const char *buffer,
				    unsigned long count, void *data)
{
	/* Simply return from the function */
	return 0;
}

static int vhba_proc_read_debug(char *page, char **start, off_t off, int count,
				int *eof, void *data)
{
	char *start_page = page;

	page +=
	    sprintf(page, "Total wait time(secs): %ld\n",
		    (vhba_wait_time / HZ));
	page += sprintf(page, "Debug bitmask: 0x%x\n", vhba_debug);
	return page - start_page;
}

static int vhba_proc_write_debug(struct file *file, const char *buffer,
				 unsigned long count, void *data)
{
	sscanf(buffer, "%x", &vhba_debug);
	return count;
}

static int vhba_proc_read_force_copy(char *page, char **start, off_t off,
				     int count, int *eof, void *data)
{
	return sprintf(page, "%d\n", force_sp_copy);
}

static int vhba_proc_write_force_copy(struct file *file, const char *buffer,
				      unsigned long count, void *data)
{
	int newval;

	sscanf(buffer, "%d", &newval);
	if (newval >= 0 && newval < 2) {	/* Sanity checks */
		force_sp_copy = newval;
		return count;
	} else
		return -EINVAL;
}

int vhba_add_proc_entry(struct virtual_hba *vhba)
{
	struct proc_dir_entry *file;
	struct scsi_xg_vhba_host *ha = vhba->ha;
	char name[35];

	sprintf(name, "%s.%Lx", (char *)vhba->cfg->vh_name, vhba->resource_id);
	file = create_proc_entry((char *)name, S_IFREG, proc_root_vhba_dev);
	if (!file) {
		eprintk(vhba, "Unable to create/proc entry\n");
		return -1;
	}

	SET_NLINK(file, 1);
	file->read_proc = vhba_proc_read_device;
	file->write_proc = vhba_proc_write_device;
	SET_OWNER(file);
	file->data = (void *)(unsigned long)vhba->idr;
	ha->vhba_proc = file;

	return 0;
}

void vhba_remove_proc_entry(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	char name[35];

	if (ha->vhba_proc) {
		sprintf(name, "%s.%Lx", (char *)vhba->cfg->vh_name,
			vhba->resource_id);
		remove_proc_entry((char *)name, proc_root_vhba_dev);
		ha->vhba_proc = 0;
	}
}

int vhba_add_target_proc_entry(struct virtual_hba *vhba)
{
	struct proc_dir_entry *file;
	struct scsi_xg_vhba_host *ha = vhba->ha;
	int ret = 0;
	char name[35];

	sprintf(name, "%s.%Lx", (char *)vhba->cfg->vh_name, vhba->resource_id);
	file = create_proc_entry((char *)name, S_IFREG, proc_root_vhba_targ);
	if (!file) {
		eprintk(vhba, "Unable to create/proc entry\n");
		ret = -1;
		goto add_target_proc_end;
	}

	SET_NLINK(file, 1);
	file->read_proc = vhba_proc_read_target;
	file->write_proc = vhba_proc_write_target;
	SET_OWNER(file);
	file->data = (void *)(unsigned long)vhba->idr;
	ha->vhba_proc_target = file;

add_target_proc_end:
	return ret;
}

int vhba_remove_target_proc_entry(struct virtual_hba *vhba)
{
	struct scsi_xg_vhba_host *ha = vhba->ha;
	char name[35];

	if (ha->vhba_proc_target) {
		sprintf(name, "%s.%Lx", (char *)vhba->cfg->vh_name,
			vhba->resource_id);
		remove_proc_entry((char *)name, proc_root_vhba_targ);
		ha->vhba_proc_target = 0;
	}
	return 0;
}

int vhba_create_procfs_root_entries(void)
{
	struct proc_dir_entry *debug_file = 0;
	struct proc_dir_entry *force_copy_file = 0;
	struct proc_dir_entry *san_info = 0;

	proc_root_vhba = proc_root_vhba_dev = NULL;

	proc_root_vhba = create_proc_entry("driver/xsvhba", S_IFDIR, PROC_ROOT);
	if (!proc_root_vhba) {
		eprintk(NULL, "Unable to create /proc/driver/xsvhba\n");
		return -1;
	} else {

		debug_file = create_proc_entry("debug", S_IFREG,
					       proc_root_vhba);
		SET_NLINK(debug_file, 1);
		debug_file->read_proc = vhba_proc_read_debug;
		debug_file->write_proc = vhba_proc_write_debug;
		SET_OWNER(debug_file);

		force_copy_file = create_proc_entry("force_copy", S_IFREG,
						    proc_root_vhba);

		SET_NLINK(force_copy_file, 1);
		force_copy_file->read_proc = vhba_proc_read_force_copy;
		force_copy_file->write_proc = vhba_proc_write_force_copy;
		SET_OWNER(force_copy_file);

		proc_root_vhba_dev = create_proc_entry("devices", S_IFDIR,
						       proc_root_vhba);
		san_info = create_proc_entry("san-info", S_IFREG,
					     proc_root_vhba);
		SET_NLINK(san_info, 1);
		san_info->read_proc = vhba_proc_read_san_info;
		san_info->write_proc = vhba_proc_write_san_info;
		SET_OWNER(san_info);

		proc_root_vhba_targ = create_proc_entry("target_info", S_IFDIR,
							proc_root_vhba);
	}

	return 0;
}

void vhba_remove_procfs_root_entries(void)
{
	dprintk(TRC_PROC, NULL, "removing target_info proc entry\n");
	if (proc_root_vhba_targ)
		remove_proc_entry("target_info", proc_root_vhba);

	dprintk(TRC_PROC, NULL, "removing devices proc entry\n");
	if (proc_root_vhba_dev)
		remove_proc_entry("devices", proc_root_vhba);

	dprintk(TRC_PROC, NULL, "removing debug proc entry\n");
	if (proc_root_vhba_dev)
		remove_proc_entry("debug", proc_root_vhba);

	dprintk(TRC_PROC, NULL, "removing san-info proc entry\n");
	if (proc_root_vhba_dev)
		remove_proc_entry("san-info", proc_root_vhba);

	dprintk(TRC_PROC, NULL, "removing force copy proc entry\n");
	if (proc_root_vhba_dev)
		remove_proc_entry("force_copy", proc_root_vhba);

	dprintk(TRC_PROC, NULL, "removing vhba proc entry\n");
	if (proc_root_vhba)
		remove_proc_entry("driver/xsvhba", PROC_ROOT);
}

int vhba_print_io_stats(char *page, int len, struct scsi_xg_vhba_host *ha)
{
	int i;

	vhba_proc_fn_print(page, len, "VHBA I/O Statistics\n");
	vhba_proc_fn_print(page, len, "-------------------\n");
	vhba_proc_fn_print(page, len,
			   "Read I/O Reqs\t\t\t: %llu\n",
			   (u64) ha->stats.io_stats.total_read_reqs);
	vhba_proc_fn_print(page, len,
			   "Write I/O Reqs\t\t\t: %llu\n",
			   (u64) ha->stats.io_stats.total_write_reqs);
	vhba_proc_fn_print(page, len,
			   "Task Mgmt Reqs\t\t\t: %llu\n",
			   (u64) ha->stats.io_stats.total_task_mgmt_reqs);
	vhba_proc_fn_print(page, len,
			   "CS_TIMEOUT Count\t\t: %llu\n",
			   (u64) ha->vhba->cs_timeout_count);
	vhba_proc_fn_print(page, len,
			   "Abort Count\t\t\t: %llu\n",
			   (u64) atomic_read(&ha->vhba->abort_count));
	vhba_proc_fn_print(page, len,
			   "Total I/O Rsps\t\t\t: %llu\n",
			   (u64) ha->stats.io_stats.total_io_rsp);
	vhba_proc_fn_print(page, len,
			   "Total copy I/Os\t\t\t: %llu\n",
			   (u64) ha->stats.io_stats.total_copy_ios);
	vhba_proc_fn_print(page, len, "Total copy page allocs\t\t: %llu\n",
			   (u64) ha->stats.io_stats.total_copy_page_allocs);
	vhba_proc_fn_print(page, len, "Total copy page frees\t\t: %llu\n",
			   (u64) ha->stats.io_stats.total_copy_page_frees);
	for (i = 0; i < VHBA_MAX_VH_Q_COUNT; i++) {
		vhba_proc_fn_print(page, len,
				   "Pending reqs for VH queue-%-2d\t: %llu\n",
				   i, (u64) atomic_read(&ha->stats.io_stats.
						     num_vh_q_reqs[i]));
	}

	vhba_proc_fn_print(page, len,
			   "Curr outstding cmd\t\t: %llu\n",
			   (u64) ha->current_outstanding_cmd);

	vhba_proc_fn_print(page, len,
			   "Bytes Read\t\t\t: %llu\n",
			   (u64) ha->stats.io_stats.total_read_mbytes);
	vhba_proc_fn_print(page, len,
			   "Bytes Written\t\t\t: %llu\n",
			   (u64) ha->stats.io_stats.total_write_mbytes);

	vhba_proc_fn_print(page, len, "Queue cmd busy return count\t: %llu\n",
			   (u64) ha->stats.io_stats.qcmd_busy_ret_cnt);

	return len;
}

int vhba_print_ib_stats(char *page, int len, struct scsi_xg_vhba_host *ha)
{
	int i;
	struct ib_cntr {
		char name[32];
		u64 *cntr;
	} ib_cntrs[] = {
		{
		"CQP down", &(ha->stats.ib_stats.cqp_dn_cnt)}, {
		"CQP up", &(ha->stats.ib_stats.cqp_up_cnt)}, {
		"CQP send error", &(ha->stats.ib_stats.cqp_send_err_cnt)}, {
		"CQP receive error", &(ha->stats.ib_stats.cqp_recv_err_cnt)},
		{
		"CQP remote disconnect",
			    &(ha->stats.ib_stats.cqp_remote_disconn_cnt)}, {
		"DQP down", &(ha->stats.ib_stats.dqp_dn_cnt)}, {
		"DQP up", &(ha->stats.ib_stats.dqp_up_cnt)}, {
		"DQP send error", &(ha->stats.ib_stats.dqp_send_err_cnt)}, {
		"DQP receive error", &(ha->stats.ib_stats.dqp_recv_err_cnt)},
		{
		"DQP remote disconnect",
			    &(ha->stats.ib_stats.dqp_remote_disconn_cnt)}, {
		"Current outstanding reqs",
			    &(ha->stats.ib_stats.curr_outstanding_reqs)}, {
		"Request queue full", &(ha->stats.ib_stats.total_req_q_fulls)},
		{
	"Outstanding queue wraps",
			    &(ha->stats.ib_stats.total_outstding_q_wraps)},};

	vhba_proc_fn_print(page, len, "VHBA IB Statistics\n");
	vhba_proc_fn_print(page, len, "------------------\n");
	for (i = 0; i < 13; i++) {
		vhba_proc_fn_print(page, len, "%-24s\t: %llu\n",
				   ib_cntrs[i].name,
				   (u64) *(ib_cntrs[i].cntr));
	}
	return len;
}

int vhba_print_xsmp_stats(char *page, int len, struct scsi_xg_vhba_host *ha)
{
	int i;
	struct xsmp_cntr {
		char name[32];
		u64 *cntr;
	} xsmp_cntrs[] = {
		{
		"install", &(vhba_xsmp_stats.install_msg_cnt)}, {
		"delete", &(vhba_xsmp_stats.delete_msg_cnt)}, {
		"update", &(vhba_xsmp_stats.update_msg_cnt)}, {
		"stats config", &(vhba_xsmp_stats.cfg_stats_msg_cnt)}, {
		"stats clear", &(vhba_xsmp_stats.clr_stats_msg_cnt)}, {
		"sync begin", &(vhba_xsmp_stats.sync_begin_msg_cnt)}, {
		"sync end", &(vhba_xsmp_stats.sync_end_msg_cnt)}, {
		"oper req", &(vhba_xsmp_stats.oper_req_msg_cnt)}, {
		"unknown xsmp", &(vhba_xsmp_stats.unknown_msg_cnt)}, {
		"xt state down", &(vhba_xsmp_stats.xt_state_dn_cnt)}, {
		"tca lid change", &(vhba_xsmp_stats.tca_lid_changed_cnt)}, {
	"abort all", &(vhba_xsmp_stats.abort_all_cnt)},};

	vhba_proc_fn_print(page, len, "VHBA XSMP Statistics\n");
	vhba_proc_fn_print(page, len, "--------------------\n");
	for (i = 0; i < 12; i++) {
		vhba_proc_fn_print(page, len, "%-20s\t\t: %llu\n",
				   xsmp_cntrs[i].name,
				   (u64) *(xsmp_cntrs[i].cntr));
	}
	vhba_proc_fn_print(page, len, "Last unknown xsmp msg\t\t: %llu\n",
			   (u64) vhba_xsmp_stats.last_unknown_msg);
	vhba_proc_fn_print(page, len, "Last known xsmp msg\t\t: %llu\n",
			   (u64) vhba_xsmp_stats.last_msg);
	return len;
}

int vhba_print_fmr_stats(char *page, int len, struct scsi_xg_vhba_host *ha)
{
	int i;
	struct fmr_cntr {
		char name[32];
		u64 *cntr;
	} fmr_cntrs[] = {
		{
		"FMR successful map", &(ha->stats.fmr_stats.map_cnt)}, {
		"FMR unmap", &(ha->stats.fmr_stats.unmap_cnt)}, {
		"FMR map fail", &(ha->stats.fmr_stats.map_fail_cnt)}, {
		"Unaligned i/o", &(ha->stats.fmr_stats.unaligned_io_cnt)}, {
		"Unaligned sg list ptr",
			    &(ha->stats.fmr_stats.unaligned_ptr_cnt)}, {
	"FMR i/o", &(ha->stats.fmr_stats.total_fmr_ios)},};

	vhba_proc_fn_print(page, len, "VHBA FMR Statistics\n");
	vhba_proc_fn_print(page, len, "-------------------\n");
	for (i = 0; i < 6; i++) {
		vhba_proc_fn_print(page, len, "%-24s\t: %llu\n",
				   fmr_cntrs[i].name,
				   (u64) *(fmr_cntrs[i].cntr));
	}
	return len;
}

int vhba_print_fc_stats(char *page, int len, struct scsi_xg_vhba_host *ha)
{
	int i;
	struct fc_cntr {
		char name[32];
		u64 *cntr;
	} fc_cntrs[] = {
		{
		"FC link down", &(ha->stats.fc_stats.link_dn_cnt)}, {
		"FC link dead", &(ha->stats.fc_stats.link_dead_cnt)}, {
		"FC link up", &(ha->stats.fc_stats.link_up_cnt)}, {
		"Target online RSCN", &(ha->stats.fc_stats.rscn_up_cnt)}, {
		"Target offline RSCN", &(ha->stats.fc_stats.rscn_dn_cnt)}, {
		"Target dead RSCN", &(ha->stats.fc_stats.rscn_dead_cnt)}, {
		"Dup RSCN for online tgt",
			    &(ha->stats.fc_stats.rscn_multiple_up_cnt)}, {
		"Dup RSCN for offline tgt",
			    &(ha->stats.fc_stats.rscn_multiple_dn_cnt)}, {
		"Last online target", &(ha->stats.fc_stats.last_up_tgt)}, {
		"Last dead target", &(ha->stats.fc_stats.last_dead_tgt)}, {
		"Last offline target", &(ha->stats.fc_stats.last_dn_tgt)}, {
		"Disc info msg received", &(ha->stats.fc_stats.disc_info_cnt)},
		{
		"Enable resp msg received",
			    &(ha->stats.fc_stats.enable_resp_cnt)}, {
	"Enable msg sent", &(ha->stats.fc_stats.enable_msg_cnt)},};

	vhba_proc_fn_print(page, len, "VHBA FC Statistics\n");
	vhba_proc_fn_print(page, len, "------------------\n");
	for (i = 0; i < 14; i++) {
		vhba_proc_fn_print(page, len, "%-24s\t: %llu\n",
				   fc_cntrs[i].name,
				   (u64) *(fc_cntrs[i].cntr));
	}
	return len;
}

int vhba_print_scsi_stats(char *page, int len, struct scsi_xg_vhba_host *ha)
{
	int i;
	struct scsi_cntr {
		char name[32];
		u64 *cntr;
	} scsi_cntrs[] = {
		{
		"Invalid target", &(ha->stats.scsi_stats.invalid_tgt_cnt)},
		{
		"Invalid lun", &(ha->stats.scsi_stats.invalid_lun_cnt)}, {
		"Successful abort", &(ha->stats.scsi_stats.abort_success_cnt)},
		{
		"Failed abort", &(ha->stats.scsi_stats.abort_fail_cnt)}, {
		"Successful device reset",
			    &(ha->stats.scsi_stats.dev_reset_success_cnt)}, {
		"Failed device reset",
			    &(ha->stats.scsi_stats.dev_reset_fail_cnt)}, {
		"Successful bus reset",
			    &(ha->stats.scsi_stats.bus_reset_success_cnt)}, {
		"Failed bus reset",
			    &(ha->stats.scsi_stats.bus_reset_fail_cnt)}, {
		"Successful host reset",
			    &(ha->stats.scsi_stats.host_reset_success_cnt)}, {
	"Failed host reset",
			    &(ha->stats.scsi_stats.host_reset_fail_cnt)},};

	vhba_proc_fn_print(page, len, "VHBA SCSI Statistics\n");
	vhba_proc_fn_print(page, len, "--------------------\n");
	for (i = 0; i < 10; i++) {
		vhba_proc_fn_print(page, len,
				   "%-24s\t: %llu\n", scsi_cntrs[i].name,
				   (u64) *(scsi_cntrs[i].cntr));
	}
	return len;
}
