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

#ifndef __XVE_XSMP_MSGS_H__
#define __XVE_XSMP_MSGS_H__

#define XVE_MAX_NAME_SIZE		16
#define XVE_MAX_PROC_NAME_SIZE          32
#define CHASSIS_MAX_NAME_SIZE           32
#define SESSION_MAX_NAME_SIZE           32
#define XVE_MAX_HOST_NAME		32
#define XVE_MP_GROUP_NAME_MAX		(XVE_MAX_NAME_SIZE + XVE_MAX_HOST_NAME)

enum xve_xsmp_cmd_type {
	XSMP_XVE_INVALID,
	XSMP_XVE_INSTALL,
	XSMP_XVE_DELETE,
	XSMP_XVE_UPDATE,
	XSMP_XVE_ADMIN_UP,
	XSMP_XVE_ADMIN_DOWN,
	XSMP_XVE_OPER_UP,
	XSMP_XVE_OPER_DOWN,
	XSMP_XVE_OPER_READY,
	XSMP_XVE_VLANIP,	/* VLAN and IP address */
	XSMP_XVE_STATS,		/* XVE driver statistics */
	XSMP_XVE_SYNC_BEGIN,
	XSMP_XVE_SYNC_END,
	XSMP_XVE_INFO_REQUEST,	/* request vnic info  */
	XSMP_XVE_OPER_FAILED,
	XSMP_XVE_OPER_REQ,
	XSMP_XVE_HA_INFO,
	XSMP_XVE_ISCSI_INFO,

	XSMP_XVE_TYPE_MAX,
};

/* XVE specific messages */

struct xve_xsmp_msg {
	union {
		struct {
			u8 type;
			u8 code;
			u16 length;
			u32 bitmask;
			u64 resource_id;
			u64 tca_guid;
			u16 tca_lid;
			u16 mac_high;
			u32 mac_low;
			u16 vn_admin_rate;
			u16 admin_state;
			u16 encap;
			u16 vn_mtu;
			u32 install_flag;
			u8 xve_name[XVE_MAX_NAME_SIZE];
			u16 service_level;	/* SL value for this vnic */
			u16 fc_active;	/* 1: enable, 0:
					* disable host rate control */
			u16 cir;	/* commited rate in mbps */
			u16 pir;	/* peak rate in mbps */
			u32 cbs;	/* committed burst size in bytes */
			u32 pbs;	/* peak burst size in bytes */
			u8 vm_index;	/* the index used by vmware
					* for persistence */
			u8 _reserved;
			u16 mp_flag;
			u8 mp_group[XVE_MP_GROUP_NAME_MAX];
			u8 la_flag;	/* linkAggregation flag */
			u8 la_policy;
			/* for virtual network */
			u32 net_id;
			u8 vnet_mode;
		} __packed;
		u8 bytes[512];
	};
} __attribute__((packed));

/* The reason code for NACKing an install  */
#define XVE_NACK_DUP_NAME	1	/* duplicate name */
#define XVE_NACK_DUP_VID	2	/* duplicate VID */
#define XVE_NACK_LIMIT_REACHED	3	/* Max number of XVEs reached */
#define XVE_NACK_ALLOCATION_ERROR	4	/* Error during instantiation */
#define XVE_NACK_CODE_MAX	5

/* The common XVE XSMP header for all messages */
struct xve_xsmp_header {
	u8 type;
	u8 code;
	u16 length;
	u32 bitmask;
	u64 resource_id;
};

/* Maximum number of dwords in an IP address (v4 or v6) */
#define MAX_IP_ADDR_DWORDS	4

/* IP address type */
enum xve_ipaddr_type {
	XVE_ADDR_TYPE_IPV4 = 1,
	XVE_ADDR_TYPE_IPV6,
};

/* Bitmask values for add/delete VLAN notifications */
#define XVE_ADD_VLAN_NOTIFY		(1 << 0)
#define XVE_DELETE_VLAN_NOTIFY	(1 << 1)

/* Denotes an instance of a VLANID and IP address pair */
struct xve_xsmp_vlanip_msg {
	union {
		struct {
			u8 type;
			u8 code;
			u16 length;
			u32 bitmask;
			u64 resource_id;
			u8 ip_type;
			u8 _reserved1;
			u16 _reserved2;
			u32 vlanid;
			u32 ipaddress[MAX_IP_ADDR_DWORDS];
			u32 netmask[MAX_IP_ADDR_DWORDS];
			/*
			 * This does not come from chassis but locally generated
			 */
			char ifname[XVE_MAX_NAME_SIZE];
			u16 mp_flag;
		} __packed;
		u8 bytes[512];
	};
};

struct xve_xsmp_stats_msg {
	union {
		struct {
			u8 type;
			u8 code;
			u16 length;
			u32 bitmask;
			u64 resource_id;
			u32 counter[16];
			/*XVE IO STATS */
			u64 stats_handle;
			u64 rx_packets;
			u64 rx_bytes;
			u64 rx_errors;
			u64 rx_drops;
			u64 rx_overruns;
			u64 tx_packets;
			u64 tx_bytes;
			u64 tx_errors;
			u64 tx_drops;
		} __packed;
		u8 bytes[512];
	};
};

struct xve_ha_info_msg {
	union {
		struct {
			u8 type;
			u8 code;
			u16 length;
			u32 reserved;
			u64 resource_id;	/* vid */
			u8 ha_state;
			u8 name[XVE_MAX_NAME_SIZE];
		} __packed;
		u8 bytes[512];
	};
} __attribute__((packed));

#define ISCSI_MOUNT_DEV_NAME_LEN    100
#define MAX_DOMAIN_NAME_LEN 64

#define SAN_MOUNT_TYPE_STATIC 1
#define SAN_MOUNT_TYPE_LVM    2
#define SAN_MOUNT_TYPE_DIRECT 3

struct xve_iscsi_info {
	uint64_t vid;
	uint8_t role;
	uint16_t vlan_id;
	uint8_t ip_type;
	uint32_t ip_addr;
	uint32_t netmask;
	uint64_t mac;
	char xve_name[XVE_MAX_NAME_SIZE];
	uint32_t gateway_ip_address;
	uint32_t dns_ip_address;
	char domain_name[MAX_DOMAIN_NAME_LEN];
	uint16_t protocol;
	uint16_t port;
	uint16_t lun;
	uint32_t target_ip_address;
	char target_iqn[ISCSI_MOUNT_DEV_NAME_LEN];	/* Target Name */
	char target_portal_group[ISCSI_MOUNT_DEV_NAME_LEN];
	char initiator_iqn[ISCSI_MOUNT_DEV_NAME_LEN];

	uint16_t mount_type;
	char mount_dev[ISCSI_MOUNT_DEV_NAME_LEN];
	char mount_options[ISCSI_MOUNT_DEV_NAME_LEN];
	char vol_group[ISCSI_MOUNT_DEV_NAME_LEN];
	char vol_group_name[ISCSI_MOUNT_DEV_NAME_LEN];
} __attribute__((packed));

struct xve_iscsi_msg {
	union {
		struct {
			uint8_t type;
			uint8_t code;
			uint16_t length;
			struct xve_iscsi_info iscsi_info;
		} __packed;
		uint8_t bytes[960];
	};
} __attribute__((packed));

/* Values for the bitmask of the install/delete/update message*/
#define XVE_UPDATE_MAC		(1 << 0)
#define XVE_UPDATE_BANDWIDTH		(1 << 1)
#define XVE_UPDATE_MTU		(1 << 2)
#define XVE_UPDATE_TCA_INFO		(1 << 3)
#define XVE_UPDATE_SL		(1 << 4)
#define XVE_UPDATE_ENCAP		(1 << 5)
#define XVE_UPDATE_ADMIN_STATE	(1 << 6)
#define XVE_UPDATE_QOS		(1 << 7)
#define XVE_UPDATE_ACL		(1 << 8)
#define XVE_UPDATE_MP_FLAG		(1 << 10)
#define XVE_XT_STATE_DOWN		(1 << 30)
#define XVE_UPDATE_XT_CHANGE		(1 << 31)

/* mp_flag */
#define MP_XVE_PRIMARY         (1 << 0)
#define MP_XVE_SECONDARY       (1 << 1)
#define MP_XVE_AUTO_SWITCH     (1 << 2)

/* ha_state */
#define XVE_HA_STATE_UNKNOWN	0
#define XVE_HA_STATE_ACTIVE	1
#define XVE_HA_STATE_STANDBY	2

/* Ack and Nack sent out in the 'code' field */
#define	XSMP_XVE_ACK		(1 << 6)
#define	XSMP_XVE_NACK		(1 << 7)

/* Bits for the promiscuous flag field */
#define XVE_MCAST		(1 << 0)

/* Defines for the install flag */
#define XVE_INSTALL_TCP_OFFL	(1 << 0)
#define XVE_INSTALL_UDP_OFFL	(1 << 1)
#define XVE_INSTALL_TSO	(1 << 3)
#define XVE_INSTALL_RX_BAT	(1 << 4)
#define XVE_8K_IBMTU		(1 << 5)
#define	XVE_INSTALL_LINK2QP	(1 << 8)

#define XSIGO_IP_FRAGMENT_BIT       (1 << 8)
#define XSIGO_IPV4_BIT              (1 << 6)
#define XSIGO_TCP_CHKSUM_GOOD_BIT   (1 << 3)
#define XSIGO_UDP_CHKSUM_GOOD_BIT   (1 << 1)

#endif /* __XVE_XSMP_MSGS_H__ */
