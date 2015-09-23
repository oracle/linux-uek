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

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>

#include "xscore_priv.h"
#include "xs_compat.h"
#include "xscore.h"
#include "xsmp.h"

#define	PFX	"STATS"

unsigned long xscore_wq_state;
unsigned long xscore_wq_jiffies;
unsigned long xscore_last_wq;

struct proc_dir_entry *proc_root_xscore = NULL;
struct proc_dir_entry *proc_root_xcpm = NULL;
struct proc_dir_entry *proc_root_xcpm_info = NULL;
struct proc_dir_entry *proc_root_xcpm_links = NULL;
struct proc_dir_entry *proc_root_xcpm_ports = NULL;

static char *ib_port_phys_state_str[] = {
	"0: Link Down",
	"1: Sleep",
	"2: Polling",
	"3: Disabled",
	"4: Port Configuration Training",
	"5: Link Up",
	"6: Link Error Recovery",
	"7: Phy Test",
};

static char *port_state2str[] = {
	"PORT_NOP",
	"PORT_DOWN",
	"PORT_INIT",
	"PORT_ARMED",
	"PORT_ACTIVE",
	"PORT_ACTIVE_DEFER",
};

static char *port_linkLayer2str[] = {
	"Unspecified",
	"Infiniband",
	"Ethernet",
};

static int xcpm_port_proc_open_device(struct inode *inode, struct file *file);
static int xcpm_port_proc_read_device(struct seq_file *m, void *data);
static ssize_t xcpm_port_proc_write_device(struct file *file,
					   const char __user *buffer,
					   size_t count, loff_t *offp);
static int xcpm_xsmp_proc_open_device(struct inode *inode, struct file *file);
static int xcpm_xsmp_proc_read_device(struct seq_file *m, void *data);
static ssize_t xcpm_xsmp_proc_write_device(struct file *file,
					   const char __user *buffer,
					   size_t count, loff_t *offp);
static int xscore_proc_open_debug(struct inode *inode, struct file *file);
static int xscore_proc_read_debug(struct seq_file *m, void *data);
static ssize_t xscore_proc_write_debug(struct file *file,
				       const char __user *buffer, size_t count,
				       loff_t *offp);
static int xscore_proc_open_info(struct inode *inode, struct file *file);
static int xscore_proc_read_info(struct seq_file *m, void *data);
static ssize_t xscore_proc_write_info(struct file *file,
				      const char __user *buffer, size_t count,
				      loff_t *offp);
static int xscore_proc_open_systemid(struct inode *inode, struct file *file);
static int xscore_proc_read_systemid(struct seq_file *m, void *data);
static ssize_t xscore_proc_write_systemid(struct file *file,
					  const char __user *buffer,
					  size_t count, loff_t *offp);
static const struct file_operations xcpm_port_proc_fops = {
	.owner = THIS_MODULE,
	.open = xcpm_port_proc_open_device,
	.read = seq_read,
	.write = xcpm_port_proc_write_device,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations xcpm_xsmp_proc_fops = {
	.owner = THIS_MODULE,
	.open = xcpm_xsmp_proc_open_device,
	.read = seq_read,
	.write = xcpm_xsmp_proc_write_device,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations xscore_debug_proc_fops = {
	.owner = THIS_MODULE,
	.open = xscore_proc_open_debug,
	.read = seq_read,
	.write = xscore_proc_write_debug,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations xscore_info_proc_fops = {
	.owner = THIS_MODULE,
	.open = xscore_proc_open_info,
	.read = seq_read,
	.write = xscore_proc_write_info,
	.llseek = seq_lseek,
	.release = single_release,
};

static const struct file_operations xscore_systemid_proc_fops = {
	.owner = THIS_MODULE,
	.open = xscore_proc_open_systemid,
	.read = seq_read,
	.write = xscore_proc_write_systemid,
	.llseek = seq_lseek,
	.release = single_release,
};

static void calc_time_fjiffies(unsigned long ojiffies, unsigned long *tsecs,
			       unsigned long *tmins, unsigned long *thrs)
{
	unsigned long tmp_tsecs = 0;
	*tsecs = *tmins = *thrs = 0;

	tmp_tsecs = jiffies_to_msecs(jiffies - ojiffies) / 1000;
	*thrs = tmp_tsecs / (60 * 60);
	*tmins = (tmp_tsecs / 60 - ((*thrs) * 60));
	*tsecs = tmp_tsecs - ((*tmins) * 60) - ((*thrs) * 60 * 60);
}

static ssize_t xcpm_port_proc_write_device(struct file *file,
					   const char __user *buffer,
					   size_t count, loff_t *offp)
{
	struct xscore_port *ib_port = NULL;

	file->private_data = PDE_DATA(file_inode(file));
	ib_port = (struct xscore_port *)file->private_data;

	memset(ib_port->counters, 0, sizeof(ib_port->counters));
	return count;
}

static int xcpm_port_proc_read_device(struct seq_file *m, void *data)
{
	struct xscore_port *ib_port = NULL;
	struct ib_port_attr port_attr;
	u64 fw_ver;
	unsigned long tsecs = 0, tmins = 0, thrs = 0;

	ib_port = (struct xscore_port *)m->private;

	(void)ib_query_port(ib_port->xs_dev->device, ib_port->port_num,
			    &port_attr);

	seq_printf(m, "Device name: \t\t%s\n", ib_port->xs_dev->device->name);
	fw_ver = ib_port->xs_dev->fw_ver;
	seq_printf(m, "Device FW Version: \t%d.%d.%d\n", (int)(fw_ver >> 32),
		   (int)((fw_ver >> 16) & 0xFFFF), (int)(fw_ver & 0xFFFF));
	seq_printf(m, "Port: \t\t\t%d\n", ib_port->port_num);
	seq_printf(m, "Port %s: \t\t0x%llx\n",
		   ib_port->link_layer == IB_LINK_LAYER_ETHERNET ?
		   "MAC" : "GUID", ib_port->guid);
	seq_printf(m, "Port PhysState: \t%s\n",
		   ib_port_phys_state_str[port_attr.phys_state]);
	seq_printf(m, "Port State: \t\t%s\n", port_state2str[port_attr.state]);
	if (ib_port->link_layer == IB_LINK_LAYER_INFINIBAND) {
		seq_printf(m, "Port LID: \t\t%d\n", port_attr.lid);
		seq_printf(m, "Port SM LID: \t\t%d\n", port_attr.sm_lid);
	} else {
		if (ib_port->xs_dev->is_shca == 0 && port_attr.active_mtu == 4)
			port_attr.active_mtu = 5;
	}
	calc_time_fjiffies(ib_port->rec_poller_time, &tsecs, &tmins, &thrs);
	seq_printf(m, "Last XCM poll :\t\t%lu hrs %lu mins %lu seconds\n",
		   thrs, tmins, tsecs);
	seq_printf(m, "Port XCM poll state: \t%d\n", ib_port->rec_poller_state);

	/*
	 * IB8KTBD this reports wrong mtu for 8k IB Mtu defined for softhca
	 */
	seq_printf(m, "Port MTU: \t\t%d (%d)\n", port_attr.active_mtu,
		   xg_ib_mtu_enum_to_int(port_attr.active_mtu));

	seq_printf(m, "Port Link Layer: \t%s\n",
		   port_linkLayer2str[ib_port->link_layer]);
	seq_puts(m, "\n");
	if (ib_port->link_layer == IB_LINK_LAYER_INFINIBAND) {
		seq_printf(m, "Port XDS LID: \t\t%d\n", ib_port->xds_lid);
		seq_printf(m, "Port XDS GUID: \t\t0x%llx\n", ib_port->xds_guid);
	}
	seq_puts(m, "\n");

	seq_printf(m, "Port Not Active Counter: \t%d\n",
		   ib_port->counters[PORT_XDS_PORT_NOT_ACTIVE_COUNTER]);
	seq_printf(m, "SA Query Error Counter: \t%d\n",
		   ib_port->counters[PORT_XDS_SA_QUERY_ERROR_COUNTER]);
	seq_printf(m, "SA Query Timeout Counter: \t%d\n",
		   ib_port->counters[PORT_XDS_SA_QUERY_TOUT_COUNTER]);
	seq_printf(m, "SA Query Counter: \t\t%d\n",
		   ib_port->counters[PORT_XDS_SA_QUERY_COUNTER]);
	seq_printf(m, "XDS Query Counter: \t\t%d\n",
		   ib_port->counters[PORT_XDS_XDS_QUERY_COUNTER]);
	seq_printf(m, "XDS Query Error Counter: \t%d\n",
		   ib_port->counters[PORT_XDS_XDS_QUERY_ERROR_COUNTER]);
	seq_printf(m, "XDS List Count Zero Counter: \t%d\n",
		   ib_port->counters[PORT_XDS_LIST_COUNT_ZERO_COUNTER]);
	seq_printf(m, "XDS Query Timeout Counter: \t%d\n",
		   ib_port->counters[PORT_XDS_XDS_QUERY_TOUT_COUNTER]);
	seq_printf(m, "XDS List Count Counter: \t%d\n",
		   ib_port->counters[PORT_XDS_LIST_COUNT_COUNTER]);

	return 0;
}

static int xcpm_port_proc_open_device(struct inode *inode, struct file *file)
{
	return single_open(file, xcpm_port_proc_read_device, PDE_DATA(inode));
}

void xcpm_port_add_proc_entry(struct xscore_port *port)
{
	struct proc_dir_entry *file;
	char name[32];

	if (test_and_set_bit(XSCORE_PORT_PROCFS_CREATED, &port->flags))
		return;

	sprintf(name, "%llx", port->guid);

	file = proc_create_data(name, S_IFREG, proc_root_xcpm_ports,
				&xcpm_port_proc_fops, port);
	if (!file)
		pr_err("unable to create /proc/driver/xscore/xcpm/ports/%s.\n", name);
}

void xcpm_port_remove_proc_entry(struct xscore_port *port)
{
	char name[32];

	sprintf(name, "%llx", port->guid);
	remove_proc_entry(name, proc_root_xcpm_ports);
	clear_bit(XSCORE_PORT_PROCFS_CREATED, &port->flags);
}

static ssize_t xcpm_xsmp_proc_write_device(struct file *file,
					   const char __user *buffer,
					   size_t count, loff_t *offp)
{
	struct xsmp_ctx *ctx = NULL;
	int action, ret;
	char	*buf = (char *) __get_free_page(GFP_USER);
	if (!buf) {
		return -ENOMEM;
	}

	if (copy_from_user(buf, buffer, count - 1)) {
		goto out;
	}
	buf[count] = '\0';

	file->private_data = PDE_DATA(file_inode(file));
	ctx = (struct xsmp_ctx *)file->private_data;

	ret = kstrtoint(buf, 0, &action);
	if (ret != 0) {
		return -EINVAL;
	}
	switch (action) {
	case 0:		/* Clear counters */
		memset(ctx->counters, 0, sizeof(ctx->counters));
		break;
	case 4567:
		pr_err("XSMP is shutdown by user %s : %s (0x%llx)\n",
		       ctx->session_name, ctx->chassis_name, ctx->dguid);
		set_bit(XSMP_SHUTTINGDOWN_BIT, &ctx->flags);
		break;
	default:
		break;
	}
	return count;
out:
	free_page((unsigned long)buf);
	return -EINVAL;
}

static int xcpm_xsmp_proc_read_device(struct seq_file *m, void *data)
{
	struct xsmp_ctx *xsmp_ctx = (struct xsmp_ctx *)m->private;
	char *state_str = NULL;
	unsigned long tsecs = 0, tmins = 0, thrs = 0;
	char tmp_buf[256];

	if (xsmp_ctx->state == XSMP_SESSION_CONNECTED)
		state_str = "Up";
	else
		state_str = "Down";

	seq_printf(m, "State:\t\t\t\t%s\n", state_str);
	seq_printf(m, "Hello interval (secs):\t\t%d\n",
		   xsmp_ctx->hello_timeout / (3 * HZ));
	seq_printf(m, "Session timeout (secs):\t\t%d\n",
		   xsmp_ctx->hello_timeout / HZ);
	seq_printf(m, "Datapath timeout (secs):\t%d\n",
		   xsmp_ctx->datapath_timeout);

	seq_printf(m, "CA Device Name:\t\t\t%s\n",
		   xsmp_ctx->port->xs_dev->device->name);
	seq_printf(m, "Local port:\t\t\t%d\n", (int)xsmp_ctx->port->port_num);
	seq_printf(m, "Local lid:\t\t\t%d\n", (int)xsmp_ctx->port->lid);
	seq_printf(m, "Local guid:\t\t\t0x%Lx\n", xsmp_ctx->port->guid);
	seq_printf(m, "Remote lid:\t\t\t%d\n", xsmp_ctx->dlid);
	seq_printf(m, "Remote guid:\t\t\t0x%Lx\n", xsmp_ctx->dguid);

	seq_printf(m, "Chassis's xcpm version:\t\t%x\n",
		   xsmp_ctx->xsigo_xsmp_version);
	seq_printf(m, "Chassis Name:\t\t\t%s\n", xsmp_ctx->chassis_name);
	seq_printf(m, "Server-Profile Name:\t\t%s\n", xsmp_ctx->session_name);

	seq_puts(m, "\n");
	seq_printf(m, "Port Link Layer:\t\t%s\n",
		   port_linkLayer2str[xsmp_ctx->port->link_layer]);
	seq_puts(m, "\n");

	if (xsmp_ctx->state == XSMP_SESSION_CONNECTED) {
		int lqpn, dqpn;

		lqpn = xsmp_ctx->conn_ctx.local_qpn;
		dqpn = xsmp_ctx->conn_ctx.remote_qpn;

		calc_time_fjiffies(xsmp_ctx->jiffies, &tsecs, &tmins, &thrs);
		seq_printf(m, "QP end points:\t\t(0x%x, %d) : (0x%x, %d)\n",
			   lqpn, lqpn, dqpn, dqpn);
	}

	tmp_buf[0] = 0;
	if (test_bit(XSMP_REG_SENT, &xsmp_ctx->flags))
		strcat(tmp_buf, "XSMP Reg Sent");
	else
		strcat(tmp_buf, "XSMP Reg Not Sent");
	if (test_bit(XSMP_REG_CONFIRM_RCVD, &xsmp_ctx->flags))
		strcat(tmp_buf, " + XSMP Reg Conf Rcvd");
	else
		strcat(tmp_buf, " + XSMP Reg Conf Not Rcvd");

	if (test_bit(XSMP_IBLINK_DOWN, &xsmp_ctx->flags))
		strcat(tmp_buf, " + IB Link Down");

	if (xsmp_ctx->conn_ctx.features & XSCORE_USE_CHECKSUM)
		strcat(tmp_buf, " + Checksum Mode");
	else
		strcat(tmp_buf, " + ICRC Mode");

	seq_printf(m, "%s\n\n", tmp_buf);

	seq_printf(m, "Session Uptime:\t\t\t%lu hrs %lu mins %lu seconds\n",
		   thrs, tmins, tsecs);

	calc_time_fjiffies(xsmp_ctx->hello_jiffies, &tsecs, &tmins, &thrs);
	seq_printf(m, "Last Hello received :\t\t%lu hrs %lu mins %lu seconds\n",
		   thrs, tmins, tsecs);
	seq_printf(m, "Number of session timeouts:\t%d\n",
		   xsmp_ctx->counters[XSMP_SESSION_TIMEOUT_COUNTER]);
	seq_printf(m, "Reg Sent Counter:\t\t%d\n",
		   xsmp_ctx->counters[XSMP_REG_SENT_COUNTER]);
	seq_printf(m, "Resource List Sent Counter:\t%d\n",
		   xsmp_ctx->counters[XSMP_RES_LIST_COUNTER]);
	seq_printf(m, "Reg Confirm Rcvd Counter:\t%d\n",
		   xsmp_ctx->counters[XSMP_REG_CONF_COUNTER]);
	seq_printf(m, "Rej Rcvd Counter:\t\t%d\n",
		   xsmp_ctx->counters[XSMP_REJ_RCVD_COUNTER]);
	seq_printf(m, "Shutdown Rcvd Counter:\t\t%d\n",
		   xsmp_ctx->counters[XSMP_SHUTDOWN_RCVD_COUNTER]);
	seq_printf(m, "XVE Type Rcvd Counter:\t\t%d\n",
		   xsmp_ctx->counters[XSMP_XVE_MESSAGE_COUNTER]);
	seq_printf(m, "VNIC Type Rcvd Counter:\t\t%d\n",
		   xsmp_ctx->counters[XSMP_VNIC_MESSAGE_COUNTER]);
	seq_printf(m, "VHBA Type Rcvd Counter:\t\t%d\n",
		   xsmp_ctx->counters[XSMP_VHBA_MESSAGE_COUNTER]);
	seq_printf(m, "USPACE Type Rcvd Counter:\t%d\n",
		   xsmp_ctx->counters[XSMP_USPACE_MESSAGE_COUNTER]);
	seq_printf(m, "SESSION Type Rcvd Counter:\t%d\n",
		   xsmp_ctx->counters[XSMP_SESSION_MESSAGE_COUNTER]);
	seq_printf(m, "VHBA Type Sent Counter:\t\t%d\n",
		   xsmp_ctx->counters[XSMP_VHBA_MESSAGE_SENT_COUNTER]);
	seq_printf(m, "VNIC Type Sent Counter:\t\t%d\n",
		   xsmp_ctx->counters[XSMP_VNIC_MESSAGE_SENT_COUNTER]);
	seq_printf(m, "USPACE Type Sent Counter:\t%d\n",
		   xsmp_ctx->counters[XSMP_USPACE_MESSAGE_SENT_COUNTER]);
	seq_printf(m, "SESSION Type Sent Counter:\t%d\n",
		   xsmp_ctx->counters[XSMP_SESSION_MESSAGE_SENT_COUNTER]);
	seq_printf(m, "Hello recv count:\t\t%d\n",
		   xsmp_ctx->counters[XSMP_HELLO_RCVD_COUNTER]);
	seq_printf(m, "Hello recv(INTERRUPT_MODE):\t%d\n",
		   xsmp_ctx->counters[XSMP_HELLO_INTERRUPT_COUNTER]);
	seq_printf(m, "Hello send count:\t\t%d\n",
		   xsmp_ctx->counters[XSMP_HELLO_SENT_COUNTER]);
	seq_printf(m, "Seq Number Mismatch Counter:\t%d\n",
		   xsmp_ctx->counters[XSMP_SEQ_MISMATCH_COUNTER]);
	seq_printf(m, "Ring Full Counter:\t\t%d\n",
		   xsmp_ctx->counters[XSMP_SESSION_RING_FULL_COUNTER]);
	seq_printf(m, "Send Error Counter:\t\t%d\n",
		   xsmp_ctx->counters[XSMP_SESSION_SEND_ERROR_COUNTER]);
	seq_printf(m, "Conn Down Counter:\t\t%d\n",
		   xsmp_ctx->counters[XSMP_SESSION_CONN_DOWN_COUNTER]);
	seq_printf(m, "Total XSMP msg Counter:\t\t%d\n",
		   xsmp_ctx->counters[XSMP_TOTAL_MSG_SENT_COUNTER]);
	seq_printf(m, "Session Conn Retry Counter:\t%d\n",
		   xsmp_ctx->counters[XSMP_CONN_RETRY_COUNTER]);
	seq_printf(m, "Session Conn Failed Counter:\t%d\n",
		   xsmp_ctx->counters[XSMP_CONN_FAILED_COUNTER]);
	seq_printf(m, "Session Conn Success Counter:\t%d\n",
		   xsmp_ctx->counters[XSMP_CONN_SUCCESS_COUNTER]);
	return 0;
}

static int xcpm_xsmp_proc_open_device(struct inode *inode, struct file *file)
{
	return single_open(file, xcpm_xsmp_proc_read_device, PDE_DATA(inode));
}

void xcpm_xsmp_add_proc_entry(struct xsmp_ctx *xsmp_ctx)
{
	struct proc_dir_entry *file;
	char name[32];

	sprintf(name, "%d", xsmp_ctx->idr);

	file = proc_create_data(name, S_IFREG, proc_root_xcpm_links,
				&xcpm_xsmp_proc_fops, xsmp_ctx);
	if (!file)
		pr_err("Unable to create /proc/driver/xscore/xcpm/links/%s.\n", name);
}

void xcpm_xsmp_remove_proc_entry(struct xsmp_ctx *xsmp_ctx)
{
	char name[32];

	sprintf(name, "%d", xsmp_ctx->idr);
	remove_proc_entry(name, proc_root_xcpm_links);
}

static ssize_t xscore_proc_write_systemid(struct file *file,
					  const char __user *buffer,
					  size_t count, loff_t *offp)
{
	char	*buf = (char *) __get_free_page(GFP_USER);
	if (!buf) {
		return -ENOMEM;
	}

	if (copy_from_user(buf, buffer, count - 1)) {
		goto out;
	}
	buf[count] = '\0';

	memcpy(system_id_str, buf, count);
	if (system_id_str[count - 1] == '\n')
		system_id_str[count - 1] = 0;
	else
		system_id_str[count] = 0;
	return count;
out:
	free_page((unsigned long)buf);
	return -EINVAL;
}

static int xscore_proc_read_systemid(struct seq_file *m, void *data)
{
	if (system_id_str[0])
		seq_printf(m, "system_id:\t\t\t%s\n", system_id_str);
	else
		seq_puts(m, "system_id:\t\t\t<NULL>\n");
	return 0;
}

static int xscore_proc_open_systemid(struct inode *inode, struct file *file)
{
	return single_open(file, xscore_proc_read_systemid, PDE_DATA(inode));
}

static ssize_t xscore_proc_write_info(struct file *file,
				      const char __user *buffer, size_t count,
				      loff_t *offp)
{
	int cc = count > XSIGO_MAX_HOSTNAME ? XSIGO_MAX_HOSTNAME : count;
	char	*buf = (char *) __get_free_page(GFP_USER);
	if (!buf) {
		return -ENOMEM;
	}

	if (copy_from_user(buf, buffer, cc - 1)) {
		goto out;
	}
	buf[cc] = '\0';

	memcpy(hostname_str, buf, cc);
	/*
	 * The last character is a newline, overwrite it
	 */
	if (hostname_str[cc - 1] == '\n')
		hostname_str[cc - 1] = 0;
	else
		hostname_str[cc] = 0;
	return count;
out:
	free_page((unsigned long)buf);
	return -EINVAL;
}

static int xscore_proc_read_info(struct seq_file *m, void *data)
{
	char buf[XSIGO_MAX_HOSTNAME];

	seq_printf(m, "ULP services mask:\t\t0x%x\n", xcpm_resource_flags);
	seq_printf(m, "Boot_flag:\t\t\t%d\n", boot_flag);
	if (system_id_str[0])
		seq_printf(m, "system_id:\t\t\t%s\n", system_id_str);
	else
		seq_puts(m, "system_id:\t\t\t<NULL>\n");
	snprintf(buf, XSIGO_MAX_HOSTNAME, "HostName:\t\t\t%s\n", hostname_str);
	seq_puts(m, buf);
	if (os_version)
		seq_printf(m, "OS version:\t\t\t%s\n", os_version);
	if (os_arch)
		seq_printf(m, "OS Arch:\t\t\t%s\n", os_arch);
	return 0;
}

static int xscore_proc_open_info(struct inode *inode, struct file *file)
{
	return single_open(file, xscore_proc_read_info, PDE_DATA(inode));
}

static int xscore_proc_read_debug(struct seq_file *m, void *data)
{
	unsigned long tsecs = 0, tmins = 0, thrs = 0;

	calc_time_fjiffies(xscore_wq_jiffies, &tsecs, &tmins, &thrs);

	seq_printf(m, "Total wait time(secs): %ld\n", (xscore_wait_time / HZ));
	seq_printf(m, "Debug Bit mask : 0x%x\n", xscore_debug);
	seq_printf(m, "Force sm change : 0x%x\n", xscore_force_sm_change);
	seq_printf(m, "Workqueue state : 0x%lx\n", xscore_wq_state);
	seq_printf(m, "Last WQ(%lx) trigger time :\t%lu hrs",
		xscore_last_wq, thrs);
	seq_printf(m, "Last WQ : %lu mins %lu seconds\n", tmins, tsecs);

	return 0;
}

static ssize_t xscore_proc_write_debug(struct file *file,
				       const char __user *buffer, size_t count,
				       loff_t *offp)
{
	int 	ret;
	char	*buf = (char *) __get_free_page(GFP_USER);
	if (!buf) {
		return -ENOMEM;
	}

	if (copy_from_user(buf, buffer, count - 1)) {
		goto out;
	}
	buf[count] = '\0';

	ret = kstrtoint(buf, 0, &xscore_debug);
	if (ret != 0) {
		return -EINVAL;
	}
	ret = kstrtoint(buf, 0, &xscore_force_sm_change);
	if (ret != 0) {
		return -EINVAL;
	}
	return count;
out:
	free_page((unsigned long)buf);
	return -EINVAL;
}

static int xscore_proc_open_debug(struct inode *inode, struct file *file)
{
	return single_open(file, xscore_proc_read_debug, PDE_DATA(inode));
}

int xscore_create_procfs_entries(void)
{
	int ret = 0;
	struct proc_dir_entry *file_d;

	proc_root_xscore = proc_mkdir("driver/xscore", NULL);
	if (!proc_root_xscore) {
		pr_err("Unable to create /proc/driver/xscore\n");
		return -ENOMEM;
	}
	file_d = proc_create_data("debug", S_IFREG, proc_root_xscore,
				  &xscore_debug_proc_fops, NULL);
	if (!file_d) {
		pr_err(PFX
		       "Unable to create /proc/driver/xscore/debug\n");
		ret = -ENOMEM;
		goto no_debug;
	}

	file_d = proc_create_data("info", S_IFREG, proc_root_xscore,
				  &xscore_info_proc_fops, NULL);
	if (!file_d) {
		pr_err(PFX
		       "Unable to create /proc/driver/xscore/info\n");
		ret = -ENOMEM;
		goto no_info;
	}

	file_d = proc_create_data("systemid", S_IFREG, proc_root_xscore,
				  &xscore_systemid_proc_fops, NULL);
	if (!file_d) {
		pr_err(PFX
		       "Unable to create /proc/driver/xscore/systermid\n");
		ret = -ENOMEM;
		goto no_systemid;
	}

	proc_root_xcpm = proc_mkdir("xcpm", proc_root_xscore);
	if (!proc_root_xcpm) {
		pr_err(PFX
		       "Unable to create /proc/driver/xscore/xcpm\n");
		ret = -ENOMEM;
		goto no_xcpm;
	}

	proc_root_xcpm_links = proc_mkdir("links", proc_root_xcpm);
	if (!proc_root_xcpm_links) {
		pr_err(PFX
		       "Unable to create /proc/driver/xscore/xcpm/links\n");
		ret = -ENOMEM;
		goto no_links;
	}
	proc_root_xcpm_ports = proc_mkdir("ports", proc_root_xcpm);
	if (!proc_root_xcpm_ports) {
		pr_err(PFX
		       "Unable to create /proc/driver/xscore/xcpm/ports\n");
		ret = -ENOMEM;
		goto no_ports;
	}
	return 0;

no_ports:
	remove_proc_entry("links", proc_root_xcpm);
no_links:
	remove_proc_entry("xcpm", proc_root_xscore);
no_xcpm:
	remove_proc_entry("systemid", proc_root_xscore);
no_systemid:
	remove_proc_entry("info", proc_root_xscore);
no_info:
	remove_proc_entry("debug", proc_root_xscore);
no_debug:
	remove_proc_entry("driver/xscore", NULL);
	return ret;
}

void xscore_remove_procfs_entries(void)
{
	remove_proc_entry("ports", proc_root_xcpm);
	remove_proc_entry("links", proc_root_xcpm);
	remove_proc_entry("xcpm", proc_root_xscore);
	remove_proc_entry("systemid", proc_root_xscore);
	remove_proc_entry("info", proc_root_xscore);
	remove_proc_entry("debug", proc_root_xscore);
	remove_proc_entry("driver/xscore", NULL);
}
