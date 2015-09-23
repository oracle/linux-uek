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
#include <linux/proc_fs.h>
#include <linux/delay.h>

#include "vhba_os_def.h"
#include "vhba_xsmp.h"
#include "vhba_ib.h"
#include "vhba_defs.h"

int limit = PAGE_SIZE;

int force_sp_copy;

struct proc_dir_entry *proc_root_vhba = 0;
struct proc_dir_entry *proc_root_vhba_dev = 0;
struct proc_dir_entry *proc_root_vhba_targ = 0;

/*
int vhba_print_io_stats(struct seq_file *m, struct scsi_xg_vhba_host *ha);
int vhba_print_ib_stats(struct seq_file *m, struct scsi_xg_vhba_host *ha);
int vhba_print_xsmp_stats(struct seq_file *m,  struct scsi_xg_vhba_host *ha);
int vhba_print_fmr_stats(struct seq_file *m, struct scsi_xg_vhba_host *ha);
int vhba_print_fc_stats(struct seq_file *m, struct scsi_xg_vhba_host *ha);
int vhba_print_scsi_stats(struct seq_file *m, struct scsi_xg_vhba_host *ha);
*/

static int vhba_proc_read_debug(struct seq_file *m, void *data);
static ssize_t vhba_proc_write_debug(struct file *file,
				     const char __user *buffer, size_t count,
				     loff_t *offp);
static int vhba_proc_open_debug(struct inode *inode, struct file *file);
static int vhba_proc_read_force_copy(struct seq_file *m, void *data);
static ssize_t vhba_proc_write_force_copy(struct file *file,
					  const char __user *buffer,
					  size_t count, loff_t *offp);
static int vhba_proc_open_force_copy(struct inode *inode, struct file *file);
static int vhba_proc_read_device(struct seq_file *m, void *data);
static ssize_t vhba_proc_write_device(struct file *file,
				      const char __user *buffer, size_t count,
				      loff_t *offp);
static int vhba_proc_open_device(struct inode *inode, struct file *file);
static int vhba_proc_read_target(struct seq_file *m, void *data);
static ssize_t vhba_proc_write_target(struct file *file,
				      const char __user *buffer, size_t count,
				      loff_t *offp);
static int vhba_proc_open_target(struct inode *inode, struct file *file);
static int vhba_proc_read_san_info(struct seq_file *m, void *data);
static ssize_t vhba_proc_write_san_info(struct file *file,
					const char __user *buffer,
					size_t count, loff_t *offp);
static int vhba_proc_open_san_info(struct inode *inode, struct file *file);

static const struct file_operations vhba_debug_proc_fops = {
	.owner = THIS_MODULE,
	.open = vhba_proc_open_debug,
	.read = seq_read,
	.write = vhba_proc_write_debug,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations vhba_force_copy_proc_fops = {
	.owner = THIS_MODULE,
	.open = vhba_proc_open_force_copy,
	.read = seq_read,
	.write = vhba_proc_write_force_copy,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations vhba_device_proc_fops = {
	.owner = THIS_MODULE,
	.open = vhba_proc_open_device,
	.read = seq_read,
	.write = vhba_proc_write_device,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations vhba_target_proc_fops = {
	.owner = THIS_MODULE,
	.open = vhba_proc_open_target,
	.read = seq_read,
	.write = vhba_proc_write_target,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations vhba_san_info_proc_fops = {
	.owner = THIS_MODULE,
	.open = vhba_proc_open_san_info,
	.read = seq_read,
	.write = vhba_proc_write_san_info,
	.llseek = seq_lseek,
	.release = single_release,
};

static int vhba_proc_read_device(struct seq_file *m, void *data)
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
	struct scsi_xg_vhba_host *ha;
	struct vhba_xsmp_msg *cfg;
	int link_state;
	u64 wwn;

	vhba = (struct virtual_hba *)
	    vhba_get_context_by_idr((u32) (unsigned long)m->private);
	if (vhba == NULL) {
		dprintk(TRC_PROC, NULL, "Error - Null vhba context!\n");
		return 0;
	}
	ha = vhba->ha;
	if (atomic_read(&ha->vhba_flags) != VHBA_READY) {
		dprintk(TRC_PROC, vhba, "VHBA not in ready state to\n"
			"                       display valid information!\n");
		goto out;
	}
	cfg = vhba->cfg;

	seq_puts(m, "VHBA Information\n");
	seq_puts(m, "----------------\n");
	seq_printf(m, "Symbolic Name\t\t\t: %s\n", (char *)(cfg->vh_name));
	seq_printf(m, "Chassis Name\t\t\t: %s\n", vhba->xsmp_info.chassis_name);
	seq_printf(m, "Chassis Version\t\t\t: %x\n", vhba->xsmp_info.version);
	seq_printf(m, "Server-Profile Name\t\t: %s\n",
		   vhba->xsmp_info.session_name);

	if (vhba->cfg->vhba_flag & 0x1) {
		seq_puts(m, "Bootable\t\t\t: Yes\n");
	} else {
		seq_puts(m, "Bootable\t\t\t: No\n");
	}
	seq_printf(m,
		   "VHBA state\t\t\t: %s\n",
		   vhba_sts_str[atomic_read(&vhba->vhba_state)]);
	seq_puts(m, "Link State\t\t\t: ");
	link_state = atomic_read(&ha->link_state);
	switch (link_state) {
	case 0:
		seq_puts(m, "LINK_DOWN\n");
		break;
	case 1:
		seq_puts(m, "LINK_UP\n");
		break;
	case 2:
		seq_puts(m, "LINK_DEAD\n");
		break;
	default:
		seq_puts(m, "UNKNOWN\n");
	}
	seq_puts(m, "IB Status\t\t\t: ");
	switch (atomic_read(&ha->ib_status)) {
	case 0:
		seq_puts(m, "IB_UP\n");
		break;
	case 1:
		seq_puts(m, "IB_DOWN\n");
		break;
	case 2:
		seq_puts(m, "IB_DEAD\n");
		break;
	default:
		seq_puts(m, "UNKNOWN\n");
	}
	seq_printf(m, "Reconnect Attempts\t\t: %d\n",
		   (int)vhba->reconn_attempt);
	seq_printf(m, "Cumulative QP Count\t\t: %d\n", (int)vhba->qp_count);
	seq_printf(m, "Lun masking\t\t\t: %s\n",
		   vhba->cfg->lunmask_enable ? "Enabled" : "Disabled");
	seq_printf(m, "Host Number\t\t\t: %u\n", (unsigned)ha->host_no);
	seq_printf(m, "Target count\t\t\t: %llu\n", (u64) ha->target_count);
	wwn = (u64) (vhba->cfg)->wwn;
	seq_puts(m, "Port WWN\t\t\t:\n");
	seq_printf(m,
			"%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X\n",
			(u8) (wwn & 0xff), (u8) ((wwn >> 8) & 0xff),
			(u8) ((wwn >> 16) & 0xff), (u8) ((wwn >> 24) & 0xff),
			(u8) ((wwn >> 32) & 0xff), (u8) ((wwn >> 40) & 0xff),
			(u8) ((wwn >> 48) & 0xff), (u8) ((wwn >> 56) & 0xff));

	seq_printf(m, "Scan Required\t\t\t: %d\n", vhba->scan_reqd);
	seq_printf(m, "SCSI Max Retry count\t\t: %d\n", vhba_max_scsi_retry);
	seq_puts(m, "\n");

	vhba_print_xsmp_stats(m, ha);

	seq_puts(m, "\n");
	seq_puts(m, "VHBA Infiniband Information\n");
	seq_puts(m, "---------------------------\n");
	seq_printf(m, "Remote IB LID\t\t\t: 0x%x\n", be16_to_cpu(cfg->tca_lid));
	pint = (int *)&cfg->tca_guid;
	seq_printf(m, "Remote IB GUID\t\t\t: 0x%x%x\n",
		   be32_to_cpu(*pint), be32_to_cpu(*(pint + 1)));
	seq_printf(m, "Resource ID\t\t\t: 0x%Lx\n", cfg->resource_id);
	seq_printf(m, "CQP handle/qpn\t\t\t: 0x%x/%u\n",
		   ha->control_qp_handle, ha->control_qpn);
	seq_printf(m, "DQP handle/qpn\t\t\t: 0x%x/%u\n",
		   ha->data_qp_handle, ha->data_qpn);
	seq_printf(m, "QP status\t\t\t: %s\n",
		   qp_sts_str[atomic_read(&ha->qp_status)]);
	seq_printf(m, "Driver ref count\t\t: %d\n",
		   atomic_read(&vhba->ref_cnt));
	seq_puts(m, "\n");

	vhba_print_ib_stats(m, ha);
	seq_puts(m, "\n");

	vhba_print_io_stats(m, ha);
	seq_puts(m, "\n");

	/*XXX this all needs to go into different stats proc files
	 *       The vmkernel helpers don't do multipage returns, so
	 *         each /proc entry can only be less than 4K, 3K? */
	vhba_print_fmr_stats(m, ha);
	seq_puts(m, "\n");

	vhba_print_fc_stats(m, ha);
	seq_puts(m, "\n");

	vhba_print_scsi_stats(m, ha);
	seq_puts(m, "\n");
out:
	DEC_REF_CNT(vhba);
	return 0;
}

static ssize_t vhba_proc_write_device(struct file *file,
				      const char __user *buffer, size_t count,
				      loff_t *offp)
{
	struct virtual_hba *vhba;
	int newval = 0;
	void *data = PDE_DATA(file_inode(file));
	int ret;

	vhba = (struct virtual_hba *)
		vhba_get_context_by_idr((u32) (unsigned long)data);
	if (vhba == NULL) {
		dprintk(TRC_PROC, NULL, "Error - Null vhba context!\n");
		return count;
	}
	ret = kstrtoint(buffer, 0, &newval);
	if (ret < 0)
		return ret;
	vhba->scan_reqd = 0;
	DEC_REF_CNT(vhba);
	return count;
}

static int vhba_proc_open_device(struct inode *inode, struct file *file)
{
	return single_open(file, vhba_proc_read_device, PDE_DATA(inode));
}

static int vhba_proc_read_target(struct seq_file *m, void *data)
{
	struct virtual_hba *vhba;
	int tgt, k;
	struct scsi_xg_vhba_host *ha;
	struct os_tgt *tq;

	vhba = (struct virtual_hba *)
	    vhba_get_context_by_idr((u32) (unsigned long)m->private);

	if (vhba == NULL) {
		dprintk(TRC_PROC, NULL, "Error - Null vhba context!\n");
		goto out;
	}

	ha = vhba->ha;
	if (atomic_read(&ha->vhba_flags) != VHBA_READY) {
		dprintk(TRC_PROC, NULL,
			"VHBA not in ready state to display valid information!\n");
		goto out;
	}

	seq_puts(m, "VHBA Target Information\n");
	seq_puts(m, "-----------------------\n\n");
	seq_printf(m, "Host no\t\t\t\t: %u\n", (unsigned)ha->host_no);

	for (tgt = 0; tgt < MAX_TARGETS; tgt++) {
		tq = TGT_Q(ha, tgt);
		if (!tq || (atomic_read(&tq->fcport->state) != FCS_ONLINE))
			continue;
		seq_puts(m, "Target WWPN\t\t\t: ");
		for (k = 0; k < WWN_SIZE; k++) {
			seq_printf(m, "%02x ", tq->port_name[k]);
		}
		seq_printf(m, "\nFC Port id\t\t\t: 0x%x\n", tq->d_id.b24);
		seq_printf(m, "Bound\t\t\t\t: %d\n", tq->fcport->bound);
		seq_printf(m, "ncmds\t\t\t\t: %d\n", atomic_read(&tq->ncmds));
		seq_printf(m, "Lun Count\t\t\t: %d\n", tq->fcport->lun_count);
		seq_printf(m, "N-Port Handle\t\t\t: 0x%x\n",
			 tq->fcport->loop_id);
		seq_printf(m, "Map Order\t\t\t: %d\n",
			 tq->fcport->os_target_id);

		seq_puts(m, "Lun id(s)\t\t\t:");
		for (k = 0; k < tq->fcport->lun_count; k++) {
			if (k != 0) {
				seq_puts(m, ",");
			}
			seq_printf(m, " %d", tq->fcport->lun_ids[k]);
		}
		seq_puts(m, "\n\n");
		seq_puts(m, "-------------------------\n\n");
	}
out:
	DEC_REF_CNT(vhba);
		return 0;
}
static ssize_t vhba_proc_write_target(struct file *file,
			const char __user *buffer, size_t count,
			loff_t *offp)
{
	/* Simply return from the function */
	return 0;
}

static int vhba_proc_open_target(struct inode *inode, struct file *file)
{
	return single_open(file, vhba_proc_read_target, PDE_DATA(inode));
}

static int vhba_proc_read_san_info(struct seq_file *m, void *data)
{
	int j;
	struct virtual_hba *vhba;
	struct scsi_xg_vhba_host *ha;

	read_lock(&vhba_global_lock);
	list_for_each_entry(vhba, &vhba_g.list, list) {
		ha = vhba->ha;
		dprintk(TRC_PROC, NULL,
			"Mount count = %d\tBoot count = %d\n",
			ha->mount_count, ha->boot_count);
		for (j = 0; j < ha->boot_count; j++)
			seq_printf(m, "sanboot%d=%s:%d:%d\n",
				   j, ha->sanboot[j].vh_name,
				   ha->sanboot[j].tgt_num, ha->sanboot[j].lun);
		seq_puts(m, "\n\n");
		for (j = 0; j < ha->mount_count; j++)
			seq_printf(m, "sanmount%d=%s:%d:%d\n",
				   j, ha->sanmount[j].vh_name,
				   ha->sanmount[j].tgt_num,
				   ha->sanmount[j].lun);
		if (ha->mount_type == 1)
			seq_printf(m, "sanmount%d=lvm:%s:%s\n",
				   j, ha->host_lvm_info.logical_vol_group,
				   ha->host_lvm_info.logical_vol);
		else if (ha->mount_type == 2)
			seq_printf(m, "sanmount=%s\n", ha->direct_mount_dev);
		if (ha->mount_options != NULL)
			seq_printf(m, "mount-opts:%s:%s\n",
				   (char *)vhba->cfg->vh_name,
				   ha->mount_options);
	}
	read_unlock(&vhba_global_lock);

	return 0;
}

static ssize_t vhba_proc_write_san_info(struct file *file,
					const char __user *buffer,
					size_t count, loff_t *offp)
{
	/* Simply return from the function */
	return 0;
}

static int vhba_proc_open_san_info(struct inode *inode, struct file *file)
{
	return single_open(file, vhba_proc_read_san_info, PDE_DATA(inode));
}

static int vhba_proc_read_debug(struct seq_file *m, void *data)
{
	seq_printf(m, "Total wait time(secs): %ld\n", (vhba_wait_time / HZ));
	seq_printf(m, "Debug bitmask: 0x%x\n", vhba_debug);
	return 0;
}

static ssize_t vhba_proc_write_debug(struct file *file,
				     const char __user *buffer, size_t count,
				     loff_t *offp)
{
	int ret;
	char	*buf = (char *) __get_free_page(GFP_USER);
	if (!buf) {
		return -ENOMEM;
	}

	if (copy_from_user(buf, buffer, count - 1)) {
		goto out;
	}
	buf[count] = '\0';

	ret = kstrtoint(buf, 0, &vhba_debug);
	if (ret != 0) {
		return -EINVAL;
	}
	return count;

out:
	free_page((unsigned long)buf);
	return -EINVAL;
}

static int vhba_proc_open_debug(struct inode *inode, struct file *file)
{
	return single_open(file, vhba_proc_read_debug, PDE_DATA(inode));
}

static int vhba_proc_read_force_copy(struct seq_file *m, void *data)
{
	seq_printf(m, "%d\n", force_sp_copy);
	return 0;
}

static ssize_t vhba_proc_write_force_copy(struct file *file,
					  const char __user *buffer,
					  size_t count, loff_t *offp)
{
	int newval;
	int ret;
	char	*buf = (char *) __get_free_page(GFP_USER);
	if (!buf) {
		return -ENOMEM;
	}

	if (copy_from_user(buf, buffer, count - 1)) {
		goto out;
	}
	buf[count] = '\0';

	ret = kstrtoint(buf, 0, &newval);
	if (ret != 0) {
		return -EINVAL;
	}
	if (newval >= 0 && newval < 2) {        /* Sanity checks */
		force_sp_copy = newval;
		return count;
	} else
		return -EINVAL;

out:
	free_page((unsigned long)buf);
	return -EINVAL;
}

static int vhba_proc_open_force_copy(struct inode *inode, struct file *file)
{
	return single_open(file, vhba_proc_read_force_copy, PDE_DATA(inode));
}

int vhba_add_proc_entry(struct virtual_hba *vhba)
{
	struct proc_dir_entry *file;
	struct scsi_xg_vhba_host *ha = vhba->ha;
	char name[35];

	sprintf(name, "%s.%Lx", (char *)vhba->cfg->vh_name, vhba->resource_id);
	file = proc_create_data((char *)name, S_IFREG, proc_root_vhba_dev,
				&vhba_device_proc_fops,
				(void *)(unsigned long)vhba->idr);
	if (!file) {
		eprintk(vhba, "Unable to create/proc entry\n");
		return -1;
	}
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
	file = proc_create_data((char *)name, S_IFREG, proc_root_vhba_targ,
				&vhba_target_proc_fops,
				(void *)(unsigned long)vhba->idr);
	if (!file) {
		eprintk(vhba, "Unable to create/proc entry\n");
		ret = -1;
		goto add_target_proc_end;
	}

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

	proc_root_vhba = proc_mkdir("driver/xsvhba", NULL);
	if (!proc_root_vhba) {
		eprintk(NULL, "Unable to create /proc/driver/xsvhba\n");
		return -1;
	} else {
		debug_file = proc_create_data("debug", S_IFREG, proc_root_vhba,
				&vhba_debug_proc_fops, NULL);

		force_copy_file =
		    proc_create_data("force_copy", S_IFREG, proc_root_vhba,
			     &vhba_force_copy_proc_fops, NULL);

		san_info = proc_create_data("san-info", S_IFREG, proc_root_vhba,
					    &vhba_san_info_proc_fops, NULL);

		proc_root_vhba_dev = proc_mkdir("devices", proc_root_vhba);
		proc_root_vhba_targ = proc_mkdir("target_info", proc_root_vhba);
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
		remove_proc_entry("driver/xsvhba", NULL);
}

int vhba_print_io_stats(struct seq_file *m, struct scsi_xg_vhba_host *ha)
{
	int i;

	seq_puts(m, "VHBA I/O Statistics\n");
	seq_puts(m, "-------------------\n");
	seq_printf(m, "Read I/O Reqs\t\t\t: %llu\n",
		   (u64) ha->stats.io_stats.total_read_reqs);
	seq_printf(m, "Write I/O Reqs\t\t\t: %llu\n",
		   (u64) ha->stats.io_stats.total_write_reqs);
	seq_printf(m, "Task Mgmt Reqs\t\t\t: %llu\n",
		   (u64) ha->stats.io_stats.total_task_mgmt_reqs);
	seq_printf(m, "CS_TIMEOUT Count\t\t: %llu\n",
		   (u64) ha->vhba->cs_timeout_count);
	seq_printf(m, "Abort Count\t\t\t: %llu\n",
		   (u64) atomic_read(&ha->vhba->abort_count));
	seq_printf(m, "Total I/O Rsps\t\t\t: %llu\n",
		   (u64) ha->stats.io_stats.total_io_rsp);
	seq_printf(m, "Total copy I/Os\t\t\t: %llu\n",
		   (u64) ha->stats.io_stats.total_copy_ios);
	seq_printf(m, "Total copy page allocs\t\t: %llu\n",
		   (u64) ha->stats.io_stats.total_copy_page_allocs);
	seq_printf(m, "Total copy page frees\t\t: %llu\n",
		   (u64) ha->stats.io_stats.total_copy_page_frees);
	for (i = 0; i < VHBA_MAX_VH_Q_COUNT; i++) {
		seq_printf(m, "Pending reqs for VH queue-%-2d\t: %llu\n", i,
			   (u64) atomic_read(&ha->stats.io_stats.
					     num_vh_q_reqs[i]));
	}

	seq_printf(m, "Curr outstding cmd\t\t: %llu\n",
		   (u64) ha->current_outstanding_cmd);

	seq_printf(m, "Bytes Read\t\t\t: %llu\n",
		   (u64) ha->stats.io_stats.total_read_mbytes);
	seq_printf(m, "Bytes Written\t\t\t: %llu\n",
		   (u64) ha->stats.io_stats.total_write_mbytes);

	seq_printf(m, "Queue cmd busy return count\t: %llu\n",
		   (u64) ha->stats.io_stats.qcmd_busy_ret_cnt);

	return 0;
}

int vhba_print_ib_stats(struct seq_file *m, struct scsi_xg_vhba_host *ha)
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

	seq_puts(m, "VHBA IB Statistics\n");
	seq_puts(m, "------------------\n");
	for (i = 0; i < 13; i++) {
		seq_printf(m, "%-24s\t: %llu\n",
			   ib_cntrs[i].name, (u64) *(ib_cntrs[i].cntr));
	}
	return 0;
}

int vhba_print_xsmp_stats(struct seq_file *m, struct scsi_xg_vhba_host *ha)
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

	seq_puts(m, "VHBA XSMP Statistics\n");
	seq_puts(m, "--------------------\n");
	for (i = 0; i < 12; i++) {
		seq_printf(m, "%-20s\t\t: %llu\n",
			   xsmp_cntrs[i].name, (u64) *(xsmp_cntrs[i].cntr));
	}
	seq_printf(m, "Last unknown xsmp msg\t\t: %llu\n",
		   (u64) vhba_xsmp_stats.last_unknown_msg);
	seq_printf(m, "Last known xsmp msg\t\t: %llu\n",
		   (u64) vhba_xsmp_stats.last_msg);
	return 0;
}

int vhba_print_fmr_stats(struct seq_file *m, struct scsi_xg_vhba_host *ha)
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

	seq_puts(m, "VHBA FMR Statistics\n");
	seq_puts(m, "-------------------\n");
	for (i = 0; i < 6; i++) {
		seq_printf(m, "%-24s\t: %llu\n",
			   fmr_cntrs[i].name, (u64) *(fmr_cntrs[i].cntr));
	}
	return 0;
}

int vhba_print_fc_stats(struct seq_file *m, struct scsi_xg_vhba_host *ha)
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

	seq_puts(m, "VHBA FC Statistics\n");
	seq_puts(m, "------------------\n");
	for (i = 0; i < 14; i++) {
		seq_printf(m, "%-24s\t: %llu\n",
			   fc_cntrs[i].name, (u64) *(fc_cntrs[i].cntr));
	}
	return 0;
}

int vhba_print_scsi_stats(struct seq_file *m, struct scsi_xg_vhba_host *ha)
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

	seq_puts(m, "VHBA SCSI Statistics\n");
	seq_puts(m, "--------------------\n");
	for (i = 0; i < 10; i++) {
		seq_printf(m, "%-24s\t: %llu\n", scsi_cntrs[i].name,
			   (u64) *(scsi_cntrs[i].cntr));
	}
	return 0;
}
