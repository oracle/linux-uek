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

#ifndef __XSMP_SESSION_H__
#define __XSMP_SESSION_H__

#include "xsmp_common.h"

/* Session management messages */

/* Session message types */
enum xsmp_session_cmd_type {
	XSMP_SESSION_UNUSED = 0,

	/* Heartbeat between the server and XCM */
	XSMP_SESSION_HELLO,

	/*
	 * Used by the server while initiating a connection to an XCM
	 * 'resource_flags' specify which services are already active
	 */
	XSMP_SESSION_REGISTER,

	/* Positive reply from XCM in response to a register from server */
	XSMP_SESSION_REG_CONFIRM,

	/*
	 * Negative reply from XCM in response to a register from server
	 * 'reason_code' specifies the reason for the reject
	 */
	XSMP_SESSION_REG_REJECT,

	/* Session shutdown message: initiated by either server or XCM */
	XSMP_SESSION_SHUTDOWN,

	/* List of services that are active: sent by server to XCM */
	XSMP_SESSION_RESOURCE_LIST,

	/* Set of error counts sent by server to XCM */
	XSMP_SESSION_ERROR_STATS,

	/*
	 * Secondary timeout value specified by XCM
	 * after which the datapaths are aborted
	 */
	XSMP_SESSION_STALE_TIME,
};

#define CHASSIS_NAME_LEN    32
#define SESSION_NAME_LEN    32
struct xsmp_session_msg {
	union {
		struct {
			u8 type;
			u8 code;
			u16 length;
			u32 resource_flags;
			u32 version;	/* current driver version */
			u32 chassis_version;	/* chassis sw version
						* this driver can work with */
			u32 boot_flags;
			u64 fw_ver;
			u32 hw_ver;
			u32 vendor_part_id;
			u32 xsigo_xsmp_version;
			char chassis_name[CHASSIS_NAME_LEN];
			char session_name[SESSION_NAME_LEN];
		} __packed;
		u8 bytes[224];
	};
} __packed;

enum {
	RESOURCE_OS_TYPE_LINUX = 0x01000000,
	RESOURCE_OS_TYPE_VMWARE = 0x02000000,
	RESOURCE_MS_CLIENT = 0x80000000,
};

#endif /* __XSMP_SESSION_H__ */
