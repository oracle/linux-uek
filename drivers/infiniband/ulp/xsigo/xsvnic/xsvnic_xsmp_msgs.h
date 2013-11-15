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

#ifndef __XSVNIC_XSMP_MSGS_H__
#define __XSVNIC_XSMP_MSGS_H__

#define XSVNIC_MAX_NAME_SIZE		16
#define CHASSIS_MAX_NAME_SIZE           32
#define SESSION_MAX_NAME_SIZE           32
#define XSVNIC_MAX_HOST_NAME		32
#define MP_GROUP_NAME_MAX		(XSVNIC_MAX_NAME_SIZE + \
					XSVNIC_MAX_HOST_NAME)
#define XSVNIC_VNIC_NAMELENTH		15

enum xsvnic_xsmp_cmd_type {
	XSMP_XSVNIC_INVALID,
	XSMP_XSVNIC_INSTALL,
	XSMP_XSVNIC_DELETE,
	XSMP_XSVNIC_UPDATE,
	XSMP_XSVNIC_ADMIN_UP,
	XSMP_XSVNIC_ADMIN_DOWN,
	XSMP_XSVNIC_OPER_UP,
	XSMP_XSVNIC_OPER_DOWN,
	XSMP_XSVNIC_OPER_READY,
	XSMP_XSVNIC_VLANIP,	/* VLAN and IP address */
	XSMP_XSVNIC_STATS,	/* XSVNIC driver statistics */
	XSMP_XSVNIC_SYNC_BEGIN,
	XSMP_XSVNIC_SYNC_END,
	XSMP_XSVNIC_INFO_REQUEST,	/* request vnic info  */
	XSMP_XSVNIC_OPER_FAILED,
	XSMP_XSVNIC_OPER_REQ,
	XSMP_XSVNIC_HA_INFO,
	XSMP_XSVNIC_ISCSI_INFO,

	XSMP_XSVNIC_TYPE_MAX,
};

/* XSVNIC specific messages */

struct xsvnic_xsmp_msg {
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
			u8 vnic_name[XSVNIC_MAX_NAME_SIZE];
			u16 service_level;	/* SL value for this vnic */
			/* 1: enable, 0: disable host rate control */
			u16 fc_active;
			u16 cir;	/* commited rate in mbps */
			u16 pir;	/* peak rate in mbps */
			u32 cbs;	/* committed burst size in bytes */
			u32 pbs;	/* peak burst size in bytes */
			/* the index used by vmware for persistence */
			u8 vm_index;
			u8 _reserved;
			u16 mp_flag;
			u8 mp_group[MP_GROUP_NAME_MAX];
		} __attribute__((packed));
		u8 bytes[512];
	};
} __attribute__((packed));

/* The reason code for NACKing an install  */
/* vnic name exceeding 15 chars */
#define XSVNIC_NACK_INVALID		0
/* duplicate name */
#define XSVNIC_NACK_DUP_NAME		1
/* duplicate VID */
#define XSVNIC_NACK_DUP_VID		2
/* Max number of XSVNICs reached */
#define XSVNIC_NACK_LIMIT_REACHED	3
/* Error during instantiation */
#define XSVNIC_NACK_ALLOCATION_ERROR	4
#define XSVNIC_NACK_CODE_MAX		5

/* The common XSVNIC XSMP header for all messages */
struct xsvnic_xsmp_header {
	u8 type;
	u8 code;
	u16 length;
	u32 bitmask;
	u64 resource_id;
};

/* Maximum number of dwords in an IP address (v4 or v6) */
#define MAX_IP_ADDR_DWORDS	4

/* IP address type */
enum xsvnic_ipaddr_type {
	ADDR_TYPE_IPV4 = 1,
	ADDR_TYPE_IPV6,
};

/* Bitmask values for add/delete VLAN notifications */
#define XSVNIC_ADD_VLAN_NOTIFY		(1 << 0)
#define XSVNIC_DELETE_VLAN_NOTIFY	(1 << 1)

/* Denotes an instance of a VLANID and IP address pair */
struct xsvnic_xsmp_vlanip_msg {
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
			char ifname[XSVNIC_MAX_NAME_SIZE];
			u16 mp_flag;
		} __attribute__((packed));
		u8 bytes[512];
	};
};

struct xsvnic_ha_info_msg {
	union {
		struct {
			u8 type;
			u8 code;
			u16 length;
			u32 reserved;
			u64 resource_id;	/* vid */
			u8 ha_state;
			u8 name[XSVNIC_MAX_NAME_SIZE];
		}  __attribute__((packed));
		u8 bytes[512];
	};
} __attribute__((packed));

#define ISCSI_MOUNT_DEV_NAME_LEN    100
#define MAX_DOMAIN_NAME_LEN 64

#define SAN_MOUNT_TYPE_STATIC 1
#define SAN_MOUNT_TYPE_LVM    2
#define SAN_MOUNT_TYPE_DIRECT 3

struct xsvnic_iscsi_info {
	uint64_t vid;
	uint8_t role;
	uint16_t vlan_id;
	uint8_t ip_type;
	uint32_t ip_addr;
	uint32_t netmask;
	uint64_t mac;
	char vnic_name[XSVNIC_MAX_NAME_SIZE];
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

struct xsvnic_iscsi_msg {
	union {
		struct {
			uint8_t type;
			uint8_t code;
			uint16_t length;
			struct xsvnic_iscsi_info iscsi_info;
		}  __attribute__((packed));
		uint8_t bytes[960];
	};
} __attribute__((packed));

/* Values for the bitmask of the install/delete/update message*/
#define XSVNIC_UPDATE_MAC		(1 << 0)
#define XSVNIC_UPDATE_BANDWIDTH		(1 << 1)
#define XSVNIC_UPDATE_MTU		(1 << 2)
#define XSVNIC_UPDATE_TCA_INFO		(1 << 3)
#define XSVNIC_UPDATE_SL		(1 << 4)
#define XSVNIC_UPDATE_ENCAP		(1 << 5)
#define XSVNIC_UPDATE_ADMIN_STATE	(1 << 6)
#define XSVNIC_UPDATE_QOS		(1 << 7)
#define XSVNIC_UPDATE_ACL		(1 << 8)
#define XSVNIC_UPDATE_MP_FLAG		(1 << 10)
#define XSVNIC_XT_STATE_DOWN		(1 << 30)
#define XSVNIC_UPDATE_XT_CHANGE		(1 << 31)

/* mp_flag */
#define MP_XSVNIC_PRIMARY         (1 << 0)
#define MP_XSVNIC_SECONDARY       (1 << 1)
#define MP_XSVNIC_AUTO_SWITCH     (1 << 2)

/* ha_state */
#define XSVNIC_HA_STATE_UNKNOWN	0
#define XSVNIC_HA_STATE_ACTIVE	1
#define XSVNIC_HA_STATE_STANDBY	2

/* Ack and Nack sent out in the 'code' field */
#define	XSMP_XSVNIC_ACK		(1 << 6)
#define	XSMP_XSVNIC_NACK		(1 << 7)

/* Bits for the promiscuous flag field */
#define XSVNIC_MCAST		(1 << 0)

/* Defines for the install flag */
#define XSVNIC_INSTALL_TCP_OFFL	(1 << 0)
#define XSVNIC_INSTALL_UDP_OFFL	(1 << 1)
#define XSVNIC_INSTALL_TSO	(1 << 3)
#define XSVNIC_INSTALL_RX_BAT	(1 << 4)
#define XSVNIC_8K_IBMTU		(1 << 5)
#define	XSVNIC_INSTALL_LINK2QP	(1 << 8)

#define XSIGO_IP_FRAGMENT_BIT       (1 << 8)
#define XSIGO_IPV4_BIT              (1 << 6)
#define XSIGO_TCP_CHKSUM_GOOD_BIT   (1 << 3)
#define XSIGO_UDP_CHKSUM_GOOD_BIT   (1 << 1)

#endif /* __XSVNIC_XSMP_MSGS_H__ */
