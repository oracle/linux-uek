/*
 * Copyright 2012 Cisco Systems, Inc.  All rights reserved.
 *
 * This program is free software; you may redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * [Insert appropriate license here when releasing outside of Cisco]
 * $Id: fnic_ioctl.c 95328 2012-02-09 01:42:58Z hiralpat $
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include "fnic_io.h"
#include "fnic.h"
#include "fnic_ioctl.h"

#define FNIC_CTL_DEV_NAME "fnic-mgmt"

int fnic_major;
extern int fnic_tracing_enabled;
extern unsigned int trace_max_pages;

/*
 * fnic driver's open routine
 */
static int fnic_ioctl_device_open(struct inode *inode,
				  struct file *file)
{
	return 0;
}
/*
 * fnic driver's release routine
 */
static int fnic_ioctl_device_release(struct inode *inode,
				  struct file *file)
{
	return 0;
}

/*
 * fnic_trace_enable_get - Routine to get the value of fnic_tracing_enabled
 *                         to verify tracing is enabled/disabled
 * Description:
 * This routine passes the value of fnic_tracing_enabled variable to user
 * buffer @ubuf
 */
static int fnic_trace_enable_get(char __user *ubuf)
{
	return copy_to_user(ubuf, &fnic_tracing_enabled, sizeof(int));
}

/*
 * fnic_trace_enable_set - Routine to enable/disable fnic tracing from
 * userworld
 *
 * Description:
 * This routine sets value of fnic_tracing_enabled to value specified by
 * userworld program @ubuf
 */
static int fnic_trace_enable_set(const char __user *ubuf)
{
	unsigned int val;

	if (copy_from_user(&val, ubuf, sizeof(int))) {
		printk(KERN_DEBUG "fnic_trace_enable_set Failed\n");
		return -EFAULT;
	}
	fnic_tracing_enabled = val;

	return 0;
}

/*
 * fnic_trace_get_data - Routine to transfer trace buffer contents from
 * kernel buffer to userworld buffer
 */
static int fnic_trace_get_data(const char __user *arg)
{
	struct fnic_trace_get buf;
	fnic_dbgfs_t fnic_dbg_ptr;
	int ret = 0;

	if (copy_from_user(&buf, arg, sizeof(struct fnic_trace_get)))
		return -EFAULT;

	fnic_dbg_ptr.buffer = vmalloc((3*(trace_max_pages * PAGE_SIZE)));
	if (!fnic_dbg_ptr.buffer) {
		printk(KERN_DEBUG "Memory allocation failed\n");
		return -ENOMEM;
	}
	memset((void *) fnic_dbg_ptr.buffer, 0,
			(3*(trace_max_pages * PAGE_SIZE)));
	buf.rcv_buf_len = fnic_get_trace_data(&fnic_dbg_ptr);

	/*
	 * Get trace buffer contents into ioctl structure
	 */
	if (copy_to_user(buf.tb_ptr, fnic_dbg_ptr.buffer,
			  buf.rcv_buf_len)) {
		ret = -EFAULT;
		goto error;
	}

	/* Copy struct buf contents to userworld buf @arg */
	if (copy_to_user((void __user *)arg, &buf,
			  sizeof(struct fnic_trace_get))) {
		ret = -EFAULT;
		goto error;
	}

error:
	vfree(fnic_dbg_ptr.buffer);
	return ret;
}

/*
 * fnic_trace_get_max_size - Routine to get max pages allocated for trace
 * buffer while module initialization
 */
static int fnic_trace_get_max_size(char __user *arg)
{
	unsigned long trace_size;
	trace_size = trace_max_pages * PAGE_SIZE;
	return copy_to_user(arg, &trace_size, sizeof(ulong));
}

/*
 * fnic_stats_get_max_size - Routine to get max size allocated for stats buffer.
 */
static int fnic_stats_get_max_size(char __user *arg)
{
	int buf_size;
	buf_size = 2 * PAGE_SIZE;
	return copy_to_user(arg, &buf_size, sizeof(int));
}

/*
 * find_fnic - Routine to find fnic structure using host number provided by user
 */
struct fnic *find_fnic(char *host_name) {
        struct Scsi_Host *host;
	struct fc_lport *lp;
	struct fnic *fnic;

	list_for_each_entry(fnic, &fnic_list, list) {
		lp = fnic->lport;
		host = lp->host;
		if (strncmp(host_name, vmklnx_get_vmhba_name(host),
				strlen(host_name)) == 0) {
			return fnic;
		}
	}
	return NULL;
}

/*
 * fnic_get_host_stats - Routine to transfer fnic_stats struct contents from
 * kernel buffer to userworld buffer
 */
static int fnic_get_host_stats(const char __user *arg)
{
	struct fnic_stats_get buf;
	struct stats_debug_info debug;
	struct fnic *fnic;
        struct fnic_stats *fnic_stats;
	int buf_size = 2 * PAGE_SIZE; 
	int ret = 0;

	if (copy_from_user(&buf, arg, sizeof(struct fnic_stats_get)))
		return -EFAULT;

	fnic = find_fnic(buf.host_name);
	if (!fnic)
		return -ENODEV;

	fnic_stats = &fnic->fnic_stats;
	debug.debug_buffer = vmalloc(buf_size);
	if (!debug.debug_buffer) {
		printk(KERN_DEBUG "Memory allocation failed\n");
		return -ENOMEM;
	}
	debug.buf_size = buf_size;
	memset((void *) debug.debug_buffer, 0, (buf_size));
	buf.rcv_buf_len = fnic_get_stats_data(&debug, fnic_stats);

	/*
	 * Get trace buffer contents into ioctl structure
	 */
	if (copy_to_user(buf.stats_ptr, debug.debug_buffer,
			  buf.rcv_buf_len)) {
		ret = -EFAULT;
		goto error;
	}

	/* Copy struct buf contents to userworld buf @arg */
	if (copy_to_user((void __user *)arg, &buf,
			  sizeof(struct fnic_stats_get))) {
		ret = -EFAULT;
		goto error;
	}

error:
	vfree(debug.debug_buffer);
	return ret;
}

static int fnic_get_hba_info(const char __user *arg)
{
        struct fnic_stats_get buf;
        struct stats_debug_info debug;
	struct Scsi_Host *host;
	struct fc_lport *lp;
	struct fnic *fnic;
	int len = 0;
        int ret = 0;

        if (copy_from_user(&buf, arg, sizeof(struct fnic_stats_get)))
                return -EFAULT;

        debug.debug_buffer = vmalloc(buf.snd_buf_len);
        if (!debug.debug_buffer) {
                printk(KERN_DEBUG "Memory allocation failed\n");
                return -ENOMEM;
        }
        debug.buf_size = buf.snd_buf_len;
        memset((void *) debug.debug_buffer, 0, (debug.buf_size));
	len = snprintf(debug.debug_buffer + len, debug.buf_size - len,
                  	"HBA\t\tDevice\t\t\n---\t\t------\t\t\n");

	list_for_each_entry(fnic, &fnic_list, list) {
		lp = fnic->lport;
		host = lp->host;
		len += snprintf(debug.debug_buffer + len, debug.buf_size - len,
			"%s\t\tfnic%d\t\t\n", vmklnx_get_vmhba_name(host), host->host_no);
	}
		
        buf.rcv_buf_len = len;

        /*
         * Get trace buffer contents into ioctl structure
         */
        if (copy_to_user(buf.stats_ptr, debug.debug_buffer,
                          buf.rcv_buf_len)) {
                ret = -EFAULT;
                goto error;
        }

        /* Copy struct buf contents to userworld buf @arg */
        if (copy_to_user((void __user *)arg, &buf,
                          sizeof(struct fnic_stats_get))) {
                ret = -EFAULT;
                goto error;
        }

error:
        vfree(debug.debug_buffer);
        return ret;
}

/*
 * fnic_reset_host_stats - Routine to reset specific host stats
 *
 * Description:
 * This routine gets host number from user and resets thats specific
 * host cumulative stats.
 */
static int fnic_reset_host_stats(const char __user *arg)
{
	struct fnic_stats_get buf;
	struct fnic *fnic;
	struct fnic_stats *stats;
	u64 *io_stats_p;
	u64 *fw_stats_p;

	if (copy_from_user(&buf, arg, sizeof(struct fnic_stats_get)))
		return -EFAULT;

	fnic = find_fnic(buf.host_name);
	if (!fnic)
		return -ENODEV;

	stats = &fnic->fnic_stats;
        io_stats_p = (u64 *)&stats->io_stats;
        fw_stats_p = (u64 *)&stats->fw_stats;

	/* Skip variable is used to avoid descrepancies to Num IOs
	 * and IO Completions stats. Skip incrementing No IO Compls
	 * for pending active IOs after reset stats
	 */
	atomic64_set(&fnic->io_cmpl_skip,
		atomic64_read(&stats->io_stats.active_ios));
	memset(&stats->abts_stats, 0, sizeof(struct abort_stats));
	memset(&stats->term_stats, 0, sizeof(struct terminate_stats));
	memset(&stats->reset_stats, 0, sizeof(struct reset_stats));
	memset(&stats->misc_stats, 0, sizeof(struct misc_stats));
	memset(&stats->vlan_stats, 0, sizeof(struct vlan_stats));
	memset(io_stats_p+1, 0, sizeof(struct io_path_stats) - sizeof(u64));
	memset(fw_stats_p+1, 0, sizeof(struct fw_stats) - sizeof(u64));

        return 0;
}

static int fnic_ioctl(struct inode *inode,
			  struct file *file,
			  unsigned int cmd,
			  unsigned long arg)
{
	int  rc = -1;
	void __user    *_arg = (void __user *) arg;

	switch (cmd) {
	case FNIC_SET_TRACE_ENABLE:
		rc = fnic_trace_enable_set(_arg);
		break;
	case FNIC_GET_TRACE_ENABLE:
		rc = fnic_trace_enable_get(_arg);
		break;
	case FNIC_GET_TRACE_BUF_SIZE:
		rc = fnic_trace_get_max_size(_arg);
		break;
	case FNIC_GET_TRACE_DATA:
		rc = fnic_trace_get_data(_arg);
		break;
	case FNIC_GET_HOST_STATS:
		rc = fnic_get_host_stats(_arg);
		break;
	case FNIC_RESET_HOST_STATS:
		rc = fnic_reset_host_stats(_arg);
		break;
	case FNIC_GET_STATS_SIZE:
		rc = fnic_stats_get_max_size(_arg);
		break;
	case FNIC_GET_HBAS_INFO:
		rc = fnic_get_hba_info(_arg);
		break;
	default:
		rc = -ENOIOCTLCMD;
		break;
	}
	return rc;
}

static struct file_operations fnic_file_ops = {
    .owner = THIS_MODULE,
    .open = fnic_ioctl_device_open,
    .release = fnic_ioctl_device_release,
    .ioctl = fnic_ioctl,
};

int fnic_reg_char_dev()
{
	return register_chrdev(0, FNIC_CTL_DEV_NAME, &fnic_file_ops);
}

void fnic_unreg_char_dev()
{
	unregister_chrdev(fnic_major, FNIC_CTL_DEV_NAME);
}

int fnic_ioctl_init()
{
	int rc = 0;

	fnic_major = fnic_reg_char_dev();
	if (fnic_major < 0) {
		printk(KERN_DEBUG "Failed to register the control device\n");
		rc = -ENODEV;
		goto err_reg_char_dev;
	}
	printk(KERN_INFO "Successfully created ioctl char device /dev/%s"
		  "using major number %d\n", FNIC_CTL_DEV_NAME, fnic_major);
	return rc;

err_reg_char_dev:
	return rc;
}

int fnic_ioctl_exit()
{
	fnic_unreg_char_dev();
	return 0;
}
