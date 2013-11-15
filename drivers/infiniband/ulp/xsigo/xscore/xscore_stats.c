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
#include <linux/proc_fs.h>
#include <linux/utsname.h>

#include "xscore_priv.h"
#include "xs_compat.h"
#include "xscore.h"
#include "xsmp.h"

#define	PFX	"STATS"

unsigned long xscore_wq_state;
unsigned long xscore_wq_jiffies;
unsigned long xscore_last_wq;

struct proc_dir_entry *proc_root_xscore;
struct proc_dir_entry *proc_root_xcpm;
struct proc_dir_entry *proc_root_xcpm_info;
struct proc_dir_entry *proc_root_xcpm_links;
struct proc_dir_entry *proc_root_xcpm_ports;

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

static int xcpm_port_proc_write_device(struct file *file, const char *buffer,
				       unsigned long count, void *data)
{
	struct xscore_port *ib_port = (struct xscore_port *)data;

	memset(ib_port->counters, 0, sizeof(ib_port->counters));
	return count;
}

static int xcpm_port_proc_read_device(char *page, char **start, off_t off,
				      int count, int *eof, void *data)
{
	char *start_page = page;
	struct xscore_port *ib_port = (struct xscore_port *)data;
	struct ib_port_attr port_attr;
	u64 fw_ver;
	unsigned long tsecs = 0, tmins = 0, thrs = 0;

	(void)ib_query_port(ib_port->xs_dev->device, ib_port->port_num,
			    &port_attr);

	page += sprintf(page, "Device name: \t\t%s\n",
		    ib_port->xs_dev->device->name);
	fw_ver = ib_port->xs_dev->fw_ver;
	page += sprintf(page, "Device FW Version: \t%d.%d.%d\n",
		    (int)(fw_ver >> 32), (int)((fw_ver >> 16) & 0xFFFF),
		    (int)(fw_ver & 0xFFFF));
	page += sprintf(page, "Port: \t\t\t%d\n", ib_port->port_num);
	page += sprintf(page, "Port %s: \t\t0x%llx\n",
			ib_port->link_layer == IB_LINK_LAYER_ETHERNET ?
			"MAC" : "GUID", ib_port->guid);
	page += sprintf(page, "Port PhysState: \t%s\n",
			ib_port_phys_state_str[port_attr.phys_state]);
	page += sprintf(page, "Port State: \t\t%s\n",
		    port_state2str[port_attr.state]);
	if (ib_port->link_layer == IB_LINK_LAYER_INFINIBAND) {
		page += sprintf(page, "Port LID: \t\t%d\n", port_attr.lid);
		page += sprintf(page, "Port SM LID: \t\t%d\n",
				port_attr.sm_lid);
	} else {
		if (ib_port->xs_dev->is_shca == 0 && port_attr.active_mtu == 4)
			port_attr.active_mtu = 5;
	}
	calc_time_fjiffies(ib_port->rec_poller_time, &tsecs, &tmins, &thrs);
	page += sprintf(page, "Last XCM poll :\t\t%lu hrs %lu mins %lu secs\n",
			thrs, tmins, tsecs);
	page += sprintf(page, "Port XCM poll state: \t%d\n",
		    ib_port->rec_poller_state);

	/* IB8KTBD this reports wrong mtu for 8k IB Mtu defined for softhca */
	page += sprintf(page, "Port MTU: \t\t%d (%d)\n", port_attr.active_mtu,
			xg_ib_mtu_enum_to_int(port_attr.active_mtu));

	page += sprintf(page, "Port Link Layer: \t%s\n",
			port_linkLayer2str[ib_port->link_layer]);
	page += sprintf(page, "\n");
	if (ib_port->link_layer == IB_LINK_LAYER_INFINIBAND) {
		page += sprintf(page, "Port XDS LID: \t\t%d\n",
				ib_port->xds_lid);
		page += sprintf(page, "Port XDS GUID: \t\t0x%llx\n",
				ib_port->xds_guid);
	}
	page += sprintf(page, "\n");

	page += sprintf(page, "Port Not Active Counter: \t%d\n",
			ib_port->counters[PORT_XDS_PORT_NOT_ACTIVE_COUNTER]);
	page += sprintf(page, "SA Query Error Counter: \t%d\n",
			ib_port->counters[PORT_XDS_SA_QUERY_ERROR_COUNTER]);
	page += sprintf(page, "SA Query Timeout Counter: \t%d\n",
			ib_port->counters[PORT_XDS_SA_QUERY_TOUT_COUNTER]);
	page += sprintf(page, "SA Query Counter: \t\t%d\n",
			ib_port->counters[PORT_XDS_SA_QUERY_COUNTER]);
	page += sprintf(page, "XDS Query Counter: \t\t%d\n",
			ib_port->counters[PORT_XDS_XDS_QUERY_COUNTER]);
	page += sprintf(page, "XDS Query Error Counter: \t%d\n",
			ib_port->counters[PORT_XDS_XDS_QUERY_ERROR_COUNTER]);
	page += sprintf(page, "XDS List Count Zero Counter: \t%d\n",
			ib_port->counters[PORT_XDS_LIST_COUNT_ZERO_COUNTER]);
	page += sprintf(page, "XDS Query Timeout Counter: \t%d\n",
			ib_port->counters[PORT_XDS_XDS_QUERY_TOUT_COUNTER]);
	page += sprintf(page, "XDS List Count Counter: \t%d\n",
			ib_port->counters[PORT_XDS_LIST_COUNT_COUNTER]);

	return page - start_page;
}

static int xcpm_xsmp_proc_write_device(struct file *file, const char *buffer,
				       unsigned long count, void *data)
{
	struct xsmp_ctx *ctx = (struct xsmp_ctx *)data;
	int action;

	sscanf(buffer, "%d", &action);
	switch (action) {
	case 0:		/* Clear counters */
		memset(ctx->counters, 0, sizeof(ctx->counters));
		break;
	case 4567:
		pr_info("XSMP is shutdown by user %s : %s (0x%llx)\n",
		       ctx->session_name, ctx->chassis_name, ctx->dguid);
		set_bit(XSMP_SHUTTINGDOWN_BIT, &ctx->flags);
		break;
	default:
		break;
	}
	return count;
}

static int xcpm_xsmp_proc_read_device(char *page, char **start, off_t off,
				      int count, int *eof, void *data)
{
	struct xsmp_ctx *xsmp_ctx = (struct xsmp_ctx *)data;
	char *start_page = page;
	char *state_str = NULL;
	unsigned long tsecs = 0, tmins = 0, thrs = 0;
	char tmp_buf[256];

	if (xsmp_ctx->state == XSMP_SESSION_CONNECTED)
		state_str = "Up";
	else
		state_str = "Down";

	page += sprintf(page, "State:\t\t\t\t%s\n", state_str);
	page += sprintf(page, "Hello interval (secs):\t\t%d\n",
			xsmp_ctx->hello_timeout / (3 * HZ));
	page += sprintf(page, "Session timeout (secs):\t\t%d\n",
			xsmp_ctx->hello_timeout / HZ);
	page += sprintf(page, "Datapath timeout (secs):\t%d\n",
			xsmp_ctx->datapath_timeout);

	page += sprintf(page, "CA Device Name:\t\t\t%s\n",
			xsmp_ctx->port->xs_dev->device->name);
	page += sprintf(page, "Local port:\t\t\t%d\n",
			(int)xsmp_ctx->port->port_num);
	page += sprintf(page, "Local lid:\t\t\t%d\n", (int)xsmp_ctx->port->lid);
	page += sprintf(page, "Local guid:\t\t\t0x%Lx\n", xsmp_ctx->port->guid);
	page += sprintf(page, "Remote lid:\t\t\t%d\n", xsmp_ctx->dlid);
	page += sprintf(page, "Remote guid:\t\t\t0x%Lx\n", xsmp_ctx->dguid);

	page += sprintf(page, "Chassis's xcpm version:\t\t%x\n",
			xsmp_ctx->xsigo_xsmp_version);
	page +=
	    sprintf(page, "Chassis Name:\t\t\t%s\n", xsmp_ctx->chassis_name);
	page +=
	    sprintf(page, "Server-Profile Name:\t\t%s\n",
		    xsmp_ctx->session_name);

	page += sprintf(page, "\n");
	page += sprintf(page, "Port Link Layer:\t\t%s\n",
			port_linkLayer2str[xsmp_ctx->port->link_layer]);
	page += sprintf(page, "\n");

	if (xsmp_ctx->state == XSMP_SESSION_CONNECTED) {
		int lqpn, dqpn;

		lqpn = xsmp_ctx->conn_ctx.local_qpn;
		dqpn = xsmp_ctx->conn_ctx.remote_qpn;

		calc_time_fjiffies(xsmp_ctx->jiffies, &tsecs, &tmins, &thrs);
		page +=
		    sprintf(page, "QP end points:\t\t(0x%x, %d) : (0x%x, %d)\n",
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

	page += sprintf(page, "%s\n\n", tmp_buf);

	page +=
	    sprintf(page, "Session Uptime:\t\t\t%lu hrs %lu mins %lu seconds\n",
		    thrs, tmins, tsecs);

	calc_time_fjiffies(xsmp_ctx->hello_jiffies, &tsecs, &tmins, &thrs);
	page +=
	    sprintf(page,
		    "Last Hello received :\t\t%lu hrs %lu mins %lu seconds\n",
		    thrs, tmins, tsecs);
	page +=
	    sprintf(page, "Number of session timeouts:\t%d\n",
		    xsmp_ctx->counters[XSMP_SESSION_TIMEOUT_COUNTER]);
	page +=
	    sprintf(page, "Reg Sent Counter:\t\t%d\n",
		    xsmp_ctx->counters[XSMP_REG_SENT_COUNTER]);
	page +=
	    sprintf(page, "Resource List Sent Counter:\t%d\n",
		    xsmp_ctx->counters[XSMP_RES_LIST_COUNTER]);
	page +=
	    sprintf(page, "Reg Confirm Rcvd Counter:\t%d\n",
		    xsmp_ctx->counters[XSMP_REG_CONF_COUNTER]);
	page +=
	    sprintf(page, "Rej Rcvd Counter:\t\t%d\n",
		    xsmp_ctx->counters[XSMP_REJ_RCVD_COUNTER]);
	page +=
	    sprintf(page, "Shutdown Rcvd Counter:\t\t%d\n",
		    xsmp_ctx->counters[XSMP_SHUTDOWN_RCVD_COUNTER]);
	page +=
	    sprintf(page, "XVE Type Rcvd Counter:\t\t%d\n",
		    xsmp_ctx->counters[XSMP_XVE_MESSAGE_COUNTER]);
	page +=
	    sprintf(page, "VNIC Type Rcvd Counter:\t\t%d\n",
		    xsmp_ctx->counters[XSMP_VNIC_MESSAGE_COUNTER]);
	page +=
	    sprintf(page, "VHBA Type Rcvd Counter:\t\t%d\n",
		    xsmp_ctx->counters[XSMP_VHBA_MESSAGE_COUNTER]);
	page +=
	    sprintf(page, "USPACE Type Rcvd Counter:\t%d\n",
		    xsmp_ctx->counters[XSMP_USPACE_MESSAGE_COUNTER]);
	page +=
	    sprintf(page, "SESSION Type Rcvd Counter:\t%d\n",
		    xsmp_ctx->counters[XSMP_SESSION_MESSAGE_COUNTER]);
	page +=
	    sprintf(page, "VHBA Type Sent Counter:\t\t%d\n",
		    xsmp_ctx->counters[XSMP_VHBA_MESSAGE_SENT_COUNTER]);
	page +=
	    sprintf(page, "VNIC Type Sent Counter:\t\t%d\n",
		    xsmp_ctx->counters[XSMP_VNIC_MESSAGE_SENT_COUNTER]);
	page +=
	    sprintf(page, "USPACE Type Sent Counter:\t%d\n",
		    xsmp_ctx->counters[XSMP_USPACE_MESSAGE_SENT_COUNTER]);
	page +=
	    sprintf(page, "SESSION Type Sent Counter:\t%d\n",
		    xsmp_ctx->counters[XSMP_SESSION_MESSAGE_SENT_COUNTER]);
	page +=
	    sprintf(page, "Hello recv count:\t\t%d\n",
		    xsmp_ctx->counters[XSMP_HELLO_RCVD_COUNTER]);
	page +=
	    sprintf(page, "Hello recv(INTERRUPT_MODE):\t%d\n",
		    xsmp_ctx->counters[XSMP_HELLO_INTERRUPT_COUNTER]);
	page +=
	    sprintf(page, "Hello send count:\t\t%d\n",
		    xsmp_ctx->counters[XSMP_HELLO_SENT_COUNTER]);
	page +=
	    sprintf(page, "Seq Number Mismatch Counter:\t%d\n",
		    xsmp_ctx->counters[XSMP_SEQ_MISMATCH_COUNTER]);
	page +=
	    sprintf(page, "Ring Full Counter:\t\t%d\n",
		    xsmp_ctx->counters[XSMP_SESSION_RING_FULL_COUNTER]);
	page +=
	    sprintf(page, "Send Error Counter:\t\t%d\n",
		    xsmp_ctx->counters[XSMP_SESSION_SEND_ERROR_COUNTER]);
	page +=
	    sprintf(page, "Conn Down Counter:\t\t%d\n",
		    xsmp_ctx->counters[XSMP_SESSION_CONN_DOWN_COUNTER]);
	page +=
	    sprintf(page, "Total XSMP msg Counter:\t\t%d\n",
		    xsmp_ctx->counters[XSMP_TOTAL_MSG_SENT_COUNTER]);
	page +=
	    sprintf(page, "Session Conn Retry Counter:\t%d\n",
		    xsmp_ctx->counters[XSMP_CONN_RETRY_COUNTER]);
	page +=
	    sprintf(page, "Session Conn Failed Counter:\t%d\n",
		    xsmp_ctx->counters[XSMP_CONN_FAILED_COUNTER]);
	page +=
	    sprintf(page, "Session Conn Success Counter:\t%d\n",
		    xsmp_ctx->counters[XSMP_CONN_SUCCESS_COUNTER]);
	return page - start_page;
}

void xcpm_port_add_proc_entry(struct xscore_port *port)
{
	struct proc_dir_entry *file;
	char name[32];

	if (test_and_set_bit(XSCORE_PORT_PROCFS_CREATED, &port->flags))
		return;

	sprintf(name, "%llx", port->guid);

	file = create_proc_entry(name, S_IFREG, proc_root_xcpm_ports);

	SET_NLINK(file, 1);
	file->read_proc = xcpm_port_proc_read_device;
	file->write_proc = xcpm_port_proc_write_device;
	file->data = (void *)port;
	SET_OWNER(file);
}

void xcpm_port_remove_proc_entry(struct xscore_port *port)
{
	char name[32];

	sprintf(name, "%llx", port->guid);
	remove_proc_entry(name, proc_root_xcpm_ports);
	clear_bit(XSCORE_PORT_PROCFS_CREATED, &port->flags);
}

void xcpm_xsmp_add_proc_entry(struct xsmp_ctx *xsmp_ctx)
{
	struct proc_dir_entry *file;
	char name[32];

	sprintf(name, "%d", xsmp_ctx->idr);

	file = create_proc_entry(name, S_IFREG, proc_root_xcpm_links);

	SET_NLINK(file, 1);
	file->read_proc = xcpm_xsmp_proc_read_device;
	file->write_proc = xcpm_xsmp_proc_write_device;
	file->data = (void *)xsmp_ctx;
	SET_OWNER(file);
}

void xcpm_xsmp_remove_proc_entry(struct xsmp_ctx *xsmp_ctx)
{
	char name[32];

	sprintf(name, "%d", xsmp_ctx->idr);
	remove_proc_entry(name, proc_root_xcpm_links);
}

static int xscore_proc_write_systemid(struct file *file, const char *buffer,
				      unsigned long count, void *data)
{
	memcpy(system_id_str, buffer, count);
	if (system_id_str[count - 1] == '\n')
		system_id_str[count - 1] = 0;
	else
		system_id_str[count] = 0;
	return count;
}

static int xscore_proc_read_systemid(char *page, char **start, off_t off,
				     int count, int *eof, void *data)
{
	char *start_page = page;

	if (system_id_str[0])
		page += sprintf(page, "system_id:\t\t\t%s\n", system_id_str);
	else
		page += sprintf(page, "system_id:\t\t\t<NULL>\n");
	return page - start_page;
}

static int xscore_proc_write_info(struct file *file, const char *buffer,
				  unsigned long count, void *data)
{
	int cc = count > XSIGO_MAX_HOSTNAME ? XSIGO_MAX_HOSTNAME : count;
	memcpy(hostname_str, buffer, cc);
	/*
	 * The last character is a newline, overwrite it
	 */
	if (hostname_str[cc - 1] == '\n')
		hostname_str[cc - 1] = 0;
	else
		hostname_str[cc] = 0;
	return count;
}

static int xscore_proc_read_info(char *page, char **start, off_t off, int count,
				 int *eof, void *data)
{
	char *start_page = page;

	page +=
	    sprintf(page, "ULP services mask:\t\t0x%x\n", xcpm_resource_flags);
	page += sprintf(page, "Boot_flag:\t\t\t%d\n", boot_flag);
	if (system_id_str[0])
		page += sprintf(page, "system_id:\t\t\t%s\n", system_id_str);
	else
		page += sprintf(page, "system_id:\t\t\t<NULL>\n");
	page +=
	    snprintf(page, XSIGO_MAX_HOSTNAME, "HostName:\t\t\t%s\n",
		     hostname_str);
	if (os_version)
		page += sprintf(page, "OS version:\t\t\t%s\n", os_version);
	if (os_arch)
		page += sprintf(page, "OS Arch:\t\t\t%s\n", os_arch);
	return page - start_page;
}

static int xscore_proc_read_debug(char *page, char **start, off_t off,
				  int count, int *eof, void *data)
{
	char *start_page = page;
	unsigned long tsecs = 0, tmins = 0, thrs = 0;

	calc_time_fjiffies(xscore_wq_jiffies, &tsecs, &tmins, &thrs);

	page += sprintf(page, "Total wait time(secs): %ld\n",
		    (xscore_wait_time / HZ));
	page += sprintf(page, "Debug Bit mask		: 0x%x\n",
		    xscore_debug);
	page += sprintf(page, "Force sm change		: 0x%x\n",
		    xscore_force_sm_change);
	page += sprintf(page, "Workqueue state		: 0x%lx\n",
		    xscore_wq_state);
	page += sprintf(page,
		    "Last WQ(%lx) trigger time :\t%lu hrs"
		    " %lu mins %lu seconds\n", xscore_last_wq, thrs, tmins,
		    tsecs);
	return page - start_page;
}

static int xscore_proc_write_debug(struct file *file, const char *buffer,
				   unsigned long count, void *data)
{
	sscanf(buffer, "%x", &xscore_debug);
	sscanf(buffer, "%x", &xscore_force_sm_change);
	return count;
}

int xscore_create_procfs_entries(void)
{
	int ret = 0;
	struct proc_dir_entry *file_d;

	proc_root_xscore = create_proc_entry("driver/xscore", S_IFDIR,
					     PROC_ROOT);
	if (!proc_root_xscore) {
		pr_err("Unable to create /proc/driver/xscore\n");
		return -ENOMEM;
	}
	file_d = create_proc_entry("debug", S_IFREG, proc_root_xscore);
	if (!file_d) {
		pr_err("Unable to create /proc/driver/xscore/debug\n");
		ret = -ENOMEM;
		goto no_debug;
	}

	SET_NLINK(file_d, 1);
	file_d->read_proc = xscore_proc_read_debug;
	file_d->write_proc = xscore_proc_write_debug;
	SET_OWNER(file_d);

	file_d = create_proc_entry("info", S_IFREG, proc_root_xscore);
	if (!file_d) {
		pr_err("Unable to create /proc/driver/xscore/info\n");
		ret = -ENOMEM;
		goto no_info;
	}

	SET_NLINK(file_d, 1);
	file_d->read_proc = xscore_proc_read_info;
	file_d->write_proc = xscore_proc_write_info;
	SET_OWNER(file_d);

	file_d = create_proc_entry("systemid", S_IFREG, proc_root_xscore);
	if (!file_d) {
		pr_err("Unable to create /proc/driver/xscore/systermid\n");
		ret = -ENOMEM;
		goto no_systemid;
	}

	SET_NLINK(file_d, 1);
	file_d->read_proc = xscore_proc_read_systemid;
	file_d->write_proc = xscore_proc_write_systemid;
	SET_OWNER(file_d);

	proc_root_xcpm = create_proc_entry("xcpm", S_IFDIR, proc_root_xscore);
	if (!proc_root_xcpm) {
		pr_err("Unable to create /proc/driver/xscore/xcpm\n");
		ret = -ENOMEM;
		goto no_xcpm;
	}
	proc_root_xcpm_links = create_proc_entry("links", S_IFDIR,
						 proc_root_xcpm);
	if (!proc_root_xcpm_links) {
		pr_err("Unable to create /proc/driver/xscore/xcpm/links\n");
		ret = -ENOMEM;
		goto no_links;
	}
	proc_root_xcpm_ports = create_proc_entry("ports", S_IFDIR,
						 proc_root_xcpm);
	if (!proc_root_xcpm_ports) {
		pr_err("Unable to create /proc/driver/xscore/xcpm/ports\n");
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
	remove_proc_entry("driver/xscore", PROC_ROOT);
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
	remove_proc_entry("driver/xscore", PROC_ROOT);
}
