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

#ifndef __XSCORE_XDS_H__
#define __XSCORE_XDS_H__

#include <rdma/ib_verbs.h>
#include <rdma/ib_mad.h>

#define XCM_REC_VERSION 1
#define MAX_XCFM_COUNT	8

#define XSIGO_MGMT_CLASS	 0x0B
#define XSIGO_MGMT_CLASS_VERSION 0x02

#define IB_MAD_ATTR_XCM_REQUEST	 0xB002

#define XSIGO_MGMT_METHOD_GET	IB_MGMT_METHOD_GET
#define XSIGO_MGMT_METHOD_SET	IB_MGMT_METHOD_SET

#define XSIGO_MAX_HOSTNAME		65
#define XSIGO_MAX_OS_VERSION_LEN	32
#define XSIGO_MAX_OS_ARCH_LEN		16
#define XSIGO_MAX_BUILD_VER_LEN		16

struct xcfm_record {
	u64 port_id;
	u16 xcm_lid;		/* lid of the XCM port */
	u8 reserved[10];
} __packed;

struct xcm_list {
	u8 count;
	u8 xcm_version;
	u8 reserved[2];
	struct xcfm_record xcms[MAX_XCFM_COUNT];
};

struct server_info {
	u32 vm_id;
	u64 port_id;
} __packed;

struct xds_request {
	struct server_info server_record;
	char hostname[XSIGO_MAX_HOSTNAME];
	char os_version[XSIGO_MAX_OS_VERSION_LEN];
	char os_arch[XSIGO_MAX_OS_ARCH_LEN];
	uint32_t os_type;
	uint64_t fw_version;
	uint32_t hw_version;
	uint32_t driver_version;
	uint64_t system_id_l;
	uint64_t system_id_h;
	uint32_t reserved;	/* For sending capablilties */
	char build_version[XSIGO_MAX_BUILD_VER_LEN];
} __packed;

struct ib_xds_mad {
	struct ib_mad_hdr mad_hdr;
	u8 reserved[IB_MGMT_SA_HDR - IB_MGMT_MAD_HDR];
	u8 data[IB_MGMT_SA_DATA];
} __packed;

/* Discovery solicitation packet.
 *      Sent by server as mcast request to all chassis.  (xds_request)
 *      Sent by chassis as unicast response to server.   (xcm_rsp_msg_t)
 */
#define XDP_MSG_TYPE_DISC_SOL 0x1

#define XDP_FLAGS_REQ 0x1
#define XDP_FLAGS_RSP 0x2

struct xdp_hdr {
	uint16_t type;
	uint16_t len;
	uint16_t flags;
	uint32_t reserved1;
	uint32_t reserved2;
	uint32_t chksum;
} __packed;

struct xdds_disc_req {
	struct xdp_hdr xhdr;
	struct xds_request req;
} __packed;

struct xdp_info {
#define XDP_FABRIC_MTU_1K 0
#define XDP_FABRIC_MTU_2K 1
#define XDP_FABRIC_MTU_4K 2
	uint8_t fabric_mtu;
	uint8_t xsmp_vlan;
	uint8_t xsmp_cos;
	uint8_t resv1;
	uint32_t reserved[63];
} __packed;

struct xdds_work {
	struct work_struct work;
	u8 *msg;
	int msg_len;
	struct xscore_port *port;
};

#endif /*__XSCORE_XDS_H__ */
