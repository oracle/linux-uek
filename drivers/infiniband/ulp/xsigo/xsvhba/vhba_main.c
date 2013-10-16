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
 * vhba_main.c
 */

#include <linux/version.h>
#include <linux/moduleparam.h>
#include <linux/vmalloc.h>
/* #include <linux/smp_lock.h> */
#include <linux/proc_fs.h>
#include <linux/delay.h>
#include <linux/slab.h>

#include <scsi/scsi_transport_fc.h>
struct scsi_transport_template *vhba_transport_template;

#include "vhba_os_def.h"
#include "vhba_ib.h"
#include "vhba_defs.h"

#include "xscore.h"
#include "vhba_xsmp.h"
#include "xsmp_session.h"

#ifndef XSIGO_LOCAL_VERSION
#define DRIVER_VERSION "0.5.1"
#else
#define DRIVER_VERSION XSIGO_LOCAL_VERSION
#endif

#define DRIVER_VERSION_STRING "Xsigo Virtual HBA Driver for Linux v"	\
							DRIVER_VERSION
#define VHBA_MAJOR				0

MODULE_AUTHOR("Oracle corp (OVN-linux-drivers@oracle.com)");
MODULE_DESCRIPTION("OVN VHBA Driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRIVER_VERSION);

/***********************************
 * Module parameters: starts here  *
 ***********************************/

int cmds_per_lun = 16;
module_param(cmds_per_lun, int, S_IRWXU);

int vhba_multiple_q = 1;
module_param(vhba_multiple_q, int, S_IRWXU);

int vhba_max_transfer_size = VHBA_DEFAULT_TRANSFER_SIZE;
module_param(vhba_max_transfer_size, int, S_IRWXU);

int vhba_max_q_depth = VHBA_MAX_VH_Q_DEPTH;
module_param(vhba_max_q_depth, int, S_IRWXU);

int vhba_debug = 0x200001;
module_param(vhba_debug, int, 5);

int vhba_max_scsi_retry = VHBA_MAX_SCSI_RETRY;
module_param(vhba_max_scsi_retry, int, S_IRWXU);

int vhba_default_scsi_timeout = VHBA_DEFAULT_SCSI_TIMEOUT;
module_param(vhba_default_scsi_timeout, int, S_IRWXU);

int vhba_wait_in_boot = 1;
module_param(vhba_wait_in_boot, int, 0644);

int vhba_wait_per_vhba = 30;
module_param(vhba_wait_per_vhba, int, 0644);

int vhba_abort_recovery_count = 15;	/* 15*2 = 30 seconds */
module_param(vhba_abort_recovery_count, int, 0644);

/****************************************
 * Module parameters: Ends here		 *
 ****************************************/
unsigned long vhba_wait_time;
char vhba_version_str[40];
int vhba_xsmp_service_id;
int vhba_max_dsds_in_fmr;
int vhba_max_fmr_pages;

DEFINE_IDR(vhba_idr_table);

u32 vhba_current_idr = MAX_VHBAS;
atomic_t vhba_count;
rwlock_t vhba_global_lock;

struct virtual_hba vhba_g;
struct vhba_xsmp_stats vhba_xsmp_stats;

static const struct file_operations vhba_fops = {
read: vhba_read,
write : vhba_write,
open : vhba_open,
release : vhba_release,
/* Not in ESX 3.5 or 4.0 */
aio_read : generic_file_aio_read,
aio_write : generic_file_aio_write,
};

int vhba_wait_all_vhbas_up(void)
{
	int time, delayms = 200;
	int vhba_count = 0;

	/* Wait for 30 seconds */
	dprintk(TRC_INIT, NULL, "%s Checking VHBA's state\n", __func__);

	for (time = 0; time < vhba_wait_per_vhba * 1000; time += delayms) {
		vhba_count = check_number_of_vhbas_provisioned();
		if (vhba_count > 0) {
			dprintk(TRC_INIT, NULL, "%s Found %d vhbas\n",
				__func__, vhba_count);
			break;
		}
		msleep(delayms);
	}

	if (vhba_count <= 0) {
		dprintk(TRC_INIT, NULL, "%s Found 0 vhbas\n", __func__);

		return 0;
	}

	/* Wait for 100 seconds */
	for (time = 0; time < 500; time++) {
		if (vhba_check_discs_status()) {
			dprintk(TRC_INIT, NULL, "%s Found disc status\n",
				__func__);
			return 1;
		}
		msleep(delayms);
	}

	return 0;
}

static void vhba_wait_for_vhbas(void)
{
	unsigned long wait_time = jiffies;

	if (vhba_wait_in_boot && xscore_wait_for_sessions(0)) {
		printk(KERN_INFO "XSVHBA: Waiting for VHBA's to come up .....\n");
		if (vhba_wait_all_vhbas_up()) {
			dprintk(TRC_INIT, NULL,
				"%s VHBA's are ready with discs\n",
				__func__);
		} else {
			dprintk(TRC_INIT, NULL,
				"%s VHBA's are NOT ready with discs\n",
				__func__);
		}
	}
	vhba_wait_time = jiffies - wait_time;
}

int dev_major;

/*
 * vhba_module_init - Module initialization.
 */
static int __init vhba_module_init(void)
{
	dprintk(TRC_INIT, NULL, "%s\n", DRIVER_VERSION_STRING);
	dprintk(TRC_INIT, NULL, "Driver queue depth is %d\n", cmds_per_lun);
	dprintk(TRC_INIT, NULL, "Driver max transfer size is %dKB\n",
		vhba_max_transfer_size / 2);
	dprintk(TRC_INIT,
		NULL, "\nBuild date: " __DATE__ " @ " __TIME__ "\n\n");

	/* Probably needs to be added to the regular linux driver */
	vhba_transport_template =
	    fc_attach_transport(&vhba_transport_functions);

	vhbawq_init();
	vhbawq_queue();

	rwlock_init(&vhba_global_lock);
	INIT_LIST_HEAD(&vhba_g.list);

	/* Register with XCPM module for receving XSMP messages */
	if (vhba_register_xsmp_service()) {
		eprintk(NULL, "vhba_register_xsmp_service() failed!\n");
		goto init_failed;
	}

	if (vhba_create_procfs_root_entries()) {
		eprintk(NULL, "vhba_create_procfs_root_entries() failed!\n");
		vhba_unregister_xsmp_service();
		goto init_failed;
	}

	/* register a character interface here... */
	dev_major = register_chrdev(VHBA_MAJOR, "svhba", &vhba_fops);

	if (dev_major < 0) {
		dprintk(TRC_ERRORS,
			NULL, "char device registration failed for vhba\n");
		eprintk(NULL, "register chrdev() failed\n");
		vhba_unregister_xsmp_service();
		vhba_remove_procfs_root_entries();
		goto init_failed;
	}
	/* Wait for vhba's to come up */
	vhba_wait_for_vhbas();
	return 0;

init_failed:
	fc_release_transport(vhba_transport_template);
	return -1;
}

/*
 * vhba_module_exit - Module cleanup routine.
 */
static void __exit vhba_module_exit(void)
{
	struct virtual_hba *vhba;
	struct virtual_hba *tmp_vhba;

	vhba_unregister_xsmp_service();

	vhbawq_cleanup();

	list_for_each_entry_safe(vhba, tmp_vhba, &vhba_g.list, list) {
		if (vhba->cfg)
			wake_up_interruptible(&vhba->timer_wq);
		vhba_delete(vhba->resource_id);
	}
	vhba_remove_procfs_root_entries();

	if (dev_major >= 0)
		unregister_chrdev(dev_major, "svhba");

	fc_release_transport(vhba_transport_template);

	dprintk(0, NULL, "Xsigo Virtual HBA driver is unloaded\n");
}

ssize_t vhba_read(struct file *filp, char *buf, size_t size, loff_t *offp)
{
	return 0;
}

ssize_t vhba_write(struct file *filp, const char *buf, size_t size,
		   loff_t *offp)
{
	return 0;
}

int vhba_open(struct inode *inode, struct file *filp)
{
	int minor;

	minor = MINOR(inode->i_rdev);
	return 0;
}

int vhba_release(struct inode *inode, struct file *filp)
{
	int minor;

	minor = MINOR(inode->i_rdev);
	return 0;
}

/*
 * Called from thread context
 */
static void vhba_xsmp_event_handler(xsmp_cookie_t xsmp_hndl, int event)
{
	struct virtual_hba *vhba, *tmp_vhba;
	unsigned long flags = 0;

	switch (event) {
	case XSCORE_CONN_CONNECTED:
		read_lock_bh(&vhba_global_lock);
		list_for_each_entry(vhba, &vhba_g.list, list) {
			if (xsmp_sessions_match(&vhba->xsmp_info, xsmp_hndl))
				vhba->xsmp_hndl = xsmp_hndl;
		}
		read_unlock_bh(&vhba_global_lock);
		break;
	case XSCORE_DEVICE_REMOVAL:
		read_lock_irqsave(&vhba_global_lock, flags);
		list_for_each_entry_safe(vhba, tmp_vhba, &vhba_g.list, list) {
			if (xsmp_sessions_match(&vhba->xsmp_info, xsmp_hndl)) {
				read_unlock_irqrestore(&vhba_global_lock,
						       flags);
				(void)vhba_delete(vhba->resource_id);
				read_lock_irqsave(&vhba_global_lock, flags);
			}
		}
		read_unlock_irqrestore(&vhba_global_lock, flags);
		break;
		/* At present we don't need to worry about any other cases */
	case XSCORE_PORT_UP:
	case XSCORE_PORT_DOWN:
	default:
		break;
	}
}

int vhba_register_xsmp_service(void)
{
	struct xsmp_service_reg_info service_info = {
		.receive_handler = vhba_receive_handler,
		.event_handler = vhba_xsmp_event_handler,
		.ctrl_message_type = XSMP_MESSAGE_TYPE_VHBA,
		.resource_flag_index = RESOURCE_FLAG_INDEX_VHBA
	};

	vhba_xsmp_service_id = xcpm_register_service(&service_info);
	if (vhba_xsmp_service_id < 0) {
		eprintk(NULL, "Unable to register with XCPM\n");
		return -1;
	}
	return 0;
}

void vhba_unregister_xsmp_service(void)
{
	int ret = 0;

	ret = xcpm_unregister_service(vhba_xsmp_service_id);
	if (ret != 0) {
		eprintk(NULL, "Unable to unregister from XCPM %d\n",
			ret);
	} else {
		dprintk(TRC_INIT, NULL,
			"Completed xcpm unregister\n");
	}
}

module_init(vhba_module_init);
module_exit(vhba_module_exit);
