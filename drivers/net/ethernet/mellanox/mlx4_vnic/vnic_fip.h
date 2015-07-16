/*
 * Copyright (c) 2009 Mellanox Technologies. All rights reserved.
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
 */

#ifndef _VNIC_FIP_H
#define _VNIC_FIP_H

#include "vnic.h"


#define FIP_TYPE(FIPT) FIP_TYPE_##FIPT
#define FIP_TYPE_IDX(FIPT) FIP_TYPE_IDX_##FIPT

#define FIP_CASE(FIPT) case FIP_TYPE(FIPT): return FIP_TYPE_IDX(FIPT)

#define FIP_CASE_STR(FIPT) case FIP_TYPE(FIPT): return # FIPT
#define FIP_SUBCODE_CASE_STR(SUBCODE) case (SUBCODE): return # SUBCODE

#define FIP_MASK(FIPT) (((u64)1) << FIP_TYPE_IDX(FIPT))

#define ADV_EXT_TYPE(FIPT) ADV_EXT_TYPE_##FIPT
#define ADV_EXT_IDX(FIPT) ADV_EXT_IDX_##FIPT

#define GUID_FORMAT "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"
#define MGID_PREFIX_FMT "%02x:%02x:%02x:%02x:%02x"
#define GUID_ARG(g) (g)[0], (g)[1], (g)[2], (g)[3], (g)[4], (g)[5], (g)[6], (g)[7]
#define MGID_PRE_ARG(g) (g)[0], (g)[1], (g)[2], (g)[3], (g)[4]

enum {
	FIP_TYPE(VENDOR_ID)	= 13,
	FIP_TYPE(ADDRESS)	= 240,
	FIP_TYPE(GW_INFORMATION)= 241,
	FIP_TYPE(LOGIN)		= 242,
	FIP_TYPE(VHUB_UPDATE)	= 243,
	FIP_TYPE(VHUB_TABLE)	= 244,
	FIP_TYPE(VNIC_IDENTITY)	= 245,
	FIP_TYPE(PARTITION)	= 246,
	FIP_TYPE(GW_IDENTIFIER)	= 248,
	FIP_TYPE(KA_PARAMS)	= 249,
	FIP_TYPE(EXT_DESC)	= 254,
};

enum {
	FIP_TYPE_IDX(VENDOR_ID),
	FIP_TYPE_IDX(ADDRESS),
	FIP_TYPE_IDX(GW_INFORMATION),
	FIP_TYPE_IDX(LOGIN),
	FIP_TYPE_IDX(VHUB_UPDATE),
	FIP_TYPE_IDX(VHUB_TABLE),
	FIP_TYPE_IDX(VNIC_IDENTITY),
	FIP_TYPE_IDX(PARTITION),
	FIP_TYPE_IDX(GW_IDENTIFIER),
	FIP_TYPE_IDX(KA_PARAMS),
	FIP_TYPE_IDX(EXT_DESC),
};

enum {
	ADV_EXT_TYPE(CAP)	 = 40,
	ADV_EXT_TYPE(BOOT)	 = 18,
	ADV_EXT_TYPE(LAG)	 = 41,
	ADV_EXT_TYPE(MEMBER)	 = 42,
	ADV_EXT_TYPE(PC_ID)	 = 43, /* Power Cycle ID */
	ADV_EXT_TYPE(CTRL_IPORT) = 240,
};

enum {
	ADV_EXT_IDX(CAP),
	ADV_EXT_IDX(BOOT),
	ADV_EXT_IDX(LAG),
	ADV_EXT_IDX(PC_ID),
	ADV_EXT_IDX(CTRL_IPORT),
};


enum {
	EPORT_STATE_DOWN = 0,
	EPORT_STATE_UP = 1,
};

enum fip_packet_type {
	FIP_DISCOVER_UCAST = 0,
	FIP_DISCOVER_MCAST = 1
};

enum {
	FIP_TABLE_HDR_MIDDLE = 0,
	FIP_TABLE_HDR_FIRST = 1,
	FIP_TABLE_HDR_LAST = 2,
	FIP_TABLE_HDR_ONLY = 3
};

enum {
	FIP_EXT_LAG_W_POLICY_HOST  = 1,
	FIP_EXT_LAG_W_POLICY_UCAST = 1 << 2
};

/* string "mellanox" */
#define FIP_VENDOR_MELLANOX { 0x6d, 0x65, 0x6c, 0x6c, 0x61, 0x6e, 0x6f, 0x78 }


#define FIP_TEST_PKT_LENGTH(port, length, type)				   \
	 if ((length) != sizeof(type) + IB_GRH_BYTES) {			   \
		 vnic_dbg_fip(port->name, "Dump packet:"		   \
			 "at %d unexpected size. length %d expected %d\n", \
			  __LINE__, (int)length,			   \
			  (int)(sizeof(type) + IB_GRH_BYTES));		   \
		 return -EINVAL;					   \
	 }

/*
 * copy string b to string a and NULL termination.
 * length a must be >= length b+1.
 */
#define TERMINATED_MEMCPY(a,b)			\
	do {					\
		ASSERT(sizeof(a)>=sizeof(b)+1);	\
		memcpy((a), (b), sizeof(b));	\
		(a)[sizeof(b)] = '\0';		\
	} while (0);


enum {
	FIP_MAX_ADDR_TLVS = 6,
	FIP_MAX_TLVS = 32,
	FIP_MAX_EXT_DESC = 32,
};

struct fip_fip_type {
	u8	type;
	u8 	length;
	u16 	reserved;
};

struct fip_header_simple {
	__be16 opcode;
	u8 reserved;
	u8 subcode;
	__be16 list_length;
	__be16 flags;
};

struct fip_vendor_id_tlv {
	struct fip_fip_type ft;
	u8	vendor_id[8];
};

struct fip_address_tlv {
	struct fip_fip_type ft;
	u8		    vendor_id[8];
	__be32		    gwtype_qpn;
	__be16		    sl_gwportid;
	__be16		    lid;
	u8		    guid[8];
};

struct fip_gw_information_tlv {
	struct fip_fip_type ft;
	u8		    vendor_id[8];
	u8		    h_nmac_mgid;
	u8		    n_rss_mgid_tss_qpn;
	__be16		    n_rss_qpn_vnics;
};

struct fip_login_tlv {
	struct fip_fip_type ft;
	u8		    vendor_id[8];
	__be16		    mtu;
	__be16		    vnic_id;
	__be16		    flags_vlan;
	u8		    mac[6];
	u8		    eth_gid_prefix[5];
	u8		    antispoofing;
	__be16		    vfields;
	__be32		    syndrom_ctrl_qpn;
	u8		    vnic_name[16];
};

struct context_table_entry {
	u8	v_rss_type;
	u8	reserved;
	u8	mac[ETH_ALEN];
	__be32	qpn;
	u8	reserved1;
	u8	sl;
	__be16	lid;
};

struct fip_vhub_update_tlv {
	struct fip_fip_type ft;
	u8		    vendor_id[8];
	__be32		    state_vhub_id;
	__be32		    tusn;
};

struct fip_vhub_table_tlv {
	struct fip_fip_type ft;
	u8		    vendor_id[8];
	__be32		    vp_vhub_id;
	__be32		    tusn;
	__be16		    hdr;
	__be16		    table_size;
};

struct fip_vnic_identity_tlv {
	struct fip_fip_type ft;
	u8		    vendor_id[8];
	__be32		    flags_vhub_id;
	__be32		    tusn;
	__be16		    vnic_id;
	u8		    mac[6];
	u8		    port_guid[8];
	u8		    vnic_name[16];
};

struct fip_partition_tlv {
	struct fip_fip_type ft;
	u8		    vendor_id[8];
	__be16		    reserved;
	__be16		    pkey;
};

struct fip_gw_identifier_tlv {
	struct fip_fip_type ft;
	u8		    vendor_id[8];
	u8		    sys_guid[8];
	u8		    sys_name[32];
	u8		    gw_port_name[8];
};

struct fip_ka_params_tlv {
	struct fip_fip_type ft;
	u8		    vendor_id[8];
	__be32		    adv_period;
	__be32		    ka_period;
	__be32		    vnic_ka_period;
};

struct fip_ext_desc_tlv {
	struct fip_fip_type ft;
	u8		    vendor_id[8];
};

struct fip_extended_type {
	u8	ext_type;
	u8	len;
	u8	reserved;
	u8	mandatory;
};

struct fip_ext_type_cap {
	struct fip_extended_type et;
	u32			 reserved[4];
};

struct fip_ext_type_boot {
	struct fip_extended_type et;
	u8			 boot_prio;
	u8			 reserved;
	__be16			 discovery_timeout;
};

struct fip_ext_type_lag_props {
	struct fip_extended_type et;
	u8			 gw_type;
	u8			 reserved;
	__be16			 lag_hash;
	u8    			 weight_policy_flags;
	u8			 ca_threshold;
	__be16			 link_down_pol_thresh;
	u32			 reserved2[2];
};

struct fip_ext_type_power_cycle_id {
	struct fip_extended_type et;
	__be64			 power_cycle_id;
	u32			 reserved;
} __attribute__((packed));

struct fip_ext_type_hostname {
	struct fip_extended_type et;
	u8			 hostname[32];
};

struct fip_ext_type_ctrl_iport {
	struct fip_extended_type et;
	u8		    vendor_id[8];
	__be32		    gwtype_qpn;
	__be16		    sl_gwportid;
	__be16		    lid;
	u8		    guid[8];
};

struct fip_ext_type_lag_member {
	__be32			 qpn;
	__be16			 sl_gw_portid;
	__be16			 lid;
	u8			 guid[8];
	u8			 eport_state;
	u8			 reserved1;
	u8			 weight;
	u8			 link_utilization;
	u32			 reserved2;
};

struct fip_ext_type_lag_members {
	struct fip_extended_type et;
	struct fip_ext_type_lag_member lagm[0];
};

struct fip_ext_group {
	struct fip_ext_desc_tlv	*fed[FIP_MAX_EXT_DESC];
	int			 num;
};

struct fip_address_group {
	struct fip_address_tlv *fa[FIP_MAX_ADDR_TLVS];
	int 			num;
};

struct fip_context_group {
	struct context_table_entry *cte;
	int			    num;
};

struct fip_content {
	struct fip_eoib_ver *eoib_ver;
	struct fip_header_simple *fh;
	struct fip_vendor_id_tlv *fvend;
	struct fip_address_group fa;
	struct fip_gw_information_tlv *fgwi;
	struct fip_login_tlv *fl;
	struct fip_vhub_update_tlv *fvu;
	struct fip_vhub_table_tlv *fvt;
	struct fip_vnic_identity_tlv *fvi;
	struct fip_partition_tlv *fp;
	struct fip_gw_identifier_tlv *fgid;
	struct fip_ka_params_tlv *fka;
        struct fip_ext_group fed;
	struct fip_context_group cte;
	u64	mask;
	u16	offsets[FIP_MAX_TLVS];
	int	num;
};

/**************************************************************************/
/*                           packet format structs                        */
/**************************************************************************/
#define VENDOR_ID_LENGTH 8

struct fip_eoib_ver {
	u8 version;
	u8 reserved[3];
};

struct fip_fip_header {
	__be16 opcode;
	u8 reserved;
	u8 subcode;
	__be16 list_length;
	__be16 flags;
	struct fip_fip_type type;
	u8 vendor_id[VNIC_VENDOR_LEN];
};

struct fip_discover_base {
	struct fip_fip_type type;
	u8 vendor_id[VNIC_VENDOR_LEN];
	u32 qpn;
	u16 sl_port_id;
	u16 lid;
	u8 guid[GUID_LEN];
};

struct eoib_adv_gw_info { /* Gabi */
	struct fip_fip_type type; 
	u8 vendor_id[VNIC_VENDOR_LEN];
	u8 system_guid[GUID_LEN];
	u8 system_name[VNIC_SYSTEM_NAME_LEN];
	u8 gw_port_name[VNIC_GW_PORT_NAME_LEN];
};

/* keep alive information */
struct eoib_adv_ka_info { /* Gabi */
	struct fip_fip_type type; 
	u8 vendor_id[VNIC_VENDOR_LEN];
	u32 gw_adv_period;
	u32 gw_period;
	u32 vnic_ka_period;
};

struct eoib_advertise {
	struct fip_eoib_ver version;
	struct fip_fip_header fip;
	struct fip_discover_base base;
	struct fip_fip_type type_1;
	u8 vendor_id[VNIC_VENDOR_LEN];
	u8 flags;
	u8 reserved;
	u16 num_net_vnics;
	struct eoib_adv_gw_info gw_info; /* Gabi */
	struct eoib_adv_ka_info ka_info; /* Gabi */
};

struct syndrom_dword {
	u8 syndrom;
	u8 reserved[3];
};

union syn_qp_ctrl {
	struct syndrom_dword syn;
	u32 ctl_qpn;
};

struct eoib_login {
	struct fip_eoib_ver		eoib_ver;
	struct fip_header_simple	fh;
	struct fip_vendor_id_tlv	fvend;
	struct fip_address_tlv		fa;
	struct fip_login_tlv		fl;
};

struct fip_solicit_legacy {
	struct fip_eoib_ver version;
	struct fip_header_simple fh;
	struct fip_vendor_id_tlv fvend;
	struct fip_address_tlv addr;
};

struct fip_solicit_new {
	struct fip_eoib_ver version;
	struct fip_header_simple fh;
	struct fip_vendor_id_tlv fvend;
	struct fip_address_tlv addr;
	struct fip_ext_desc_tlv ext;
	struct fip_ext_type_cap ext_cap;
        struct fip_ext_type_hostname ext_hostname;
};

union fip_vhub_id {
	struct {
		u8 flags;
		u8 reserved[3];
	} flags;
	u32 vhub_id;
};

struct eoib_context_table {
	struct fip_eoib_ver version;
	struct fip_fip_header fip;
	struct fip_fip_type type_1;
	u8 vendor_id[VNIC_VENDOR_LEN];
	union fip_vhub_id vhub_id;
	u32 tusn;
	u8 flags;
	u8 reserved;
	u16 table_size;
	/* here come the context entries */
};

/* this is the number of DWORDS to subtract from type_1->length
 * to get the size of the entries / 4. (size in dwords from start
 * of vendor_id field until the first context entry + 1 for checksum
 */
#define FIP_TABLE_SUB_LENGTH 6

/*
 * eoib_host_update will be used for vHub context requests,
 * keep alives and logouts
 */
struct eoib_host_update {
	struct fip_eoib_ver version;
	struct fip_fip_header fip;
	struct fip_fip_type type_1;
	u8 vendor_id[VNIC_VENDOR_LEN];
	union fip_vhub_id vhub_id;
	u32 tusn;
	u16 vnic_id;
	u8 mac[ETH_ALEN];
	u8 port_guid[GUID_LEN];
	u8 vnic_name[VNIC_NAME_LEN];
};

enum fip_packet_fields {
	EOIB_FIP_OPCODE = 0xFFF9,
	FIP_FIP_HDR_LENGTH = 3,
	FIP_FIP_HDR_TYPE = 13,

	/* keep all subcodes here */
	FIP_HOST_SOL_SUB_OPCODE = 0x1,
	FIP_GW_ADV_SUB_OPCODE = 0x2,
	FIP_HOST_LOGIN_SUB_OPCODE = 0x3,
	FIP_GW_LOGIN_SUB_OPCODE = 0x4,
	FIP_HOST_LOGOUT_SUB_OPCODE = 0x5,
	FIP_GW_UPDATE_SUB_OPCODE = 0x6,
	FIP_GW_TABLE_SUB_OPCODE = 0x7,
	FIP_HOST_ALIVE_SUB_OPCODE = 0x8,
	FIP_MAX_SUBCODES,
	/* end subcodes section */

	FIP_FIP_FCF_FLAG = 0x1,
	FIP_FIP_SOLICITED_FLAG = 0x2,
	FIP_FIP_ADVRTS_FLAG = 0x4,
	FIP_FIP_FP_FLAG = 0x80,
	FIP_FIP_SP_FLAG = 0x40,

	FIP_BASIC_LENGTH = 7,
	FIP_BASIC_TYPE = 240,

	FIP_ADVERTISE_LENGTH_1 = 4,
	FIP_ADVERTISE_TYPE_1 = 241,
	FIP_ADVERTISE_HOST_VLANS = 0x80,
	FIP_ADVERTISE_NUM_VNICS_MASK = 0x0FFF,
	FIP_ADVERTISE_N_RSS_SHIFT = 12,
	FIP_ADVERTISE_HOST_EN_MASK = 0x80,
	FIP_ADVERTISE_ALL_VLAN_GW_MASK = 0x60,
	FIP_ADVERTISE_GW_PORT_ID_MASK = 0x0FFF,
	FIP_ADVERTISE_SL_SHIFT = 12,

	FIP_ADVERTISE_GW_LENGTH = 15,
	FIP_ADVERTISE_GW_TYPE = 248,

	FIP_ADVERTISE_KA_LENGTH = 6,
	FIP_ADVERTISE_KA_TYPE = 249,

	FIP_LOGIN_LENGTH_1 = 13,
	FIP_LOGIN_TYPE_1 = 242,
	FIP_LOGIN_LENGTH_2 = 4,
	FIP_LOGIN_TYPE_2 = 246,

	FIP_LOGIN_V_FLAG = 0x8000,
	FIP_LOGIN_M_FLAG = 0x4000,
	FIP_LOGIN_VP_FLAG = 0x2000,
	FIP_LOGIN_H_FLAG = 0x1000,
	FIP_LOGIN_VLAN_MASK = 0x0FFF,
	FIP_LOGIN_DMAC_MGID_MASK = 0x3F,
	FIP_LOGIN_RSS_MGID_MASK = 0x0F,
	FIP_LOGIN_RSS_MASK = 0x10,
	FIP_LOGIN_RSS_SHIFT = 4,
	FIP_LOGIN_CTRL_QPN_MASK = 0xFFFFFF,
	FIP_LOGIN_VNIC_ID_BITS = 16,
	FIP_LOGIN_ALL_VLAN_GW_FLAG = 0x0040,

	FIP_LOGOUT_LENGTH_1 = 13,
	FIP_LOGOUT_TYPE_1 = 245,

	FIP_HOST_UPDATE_LENGTH = 13,
	FIP_HOST_UPDATE_TYPE = 245,
	FIP_HOST_VP_FLAG = 0x01,
	FIP_HOST_U_FLAG = 0x80,
	FIP_HOST_R_FLAG = 0x40,

	FIP_CONTEXT_UP_LENGTH = 9,
	FIP_CONTEXT_UP_TYPE = 243,
	FIP_CONTEXT_UP_EPORT_MASK = 0x30,
	FIP_CONTEXT_UP_EPORT_SHIFT = 4,
	FIP_CONTEXT_V_FLAG = 0x80,
	FIP_CONTEXT_RSS_FLAG = 0x40,
	FIP_CONTEXT_TYPE_MASK = 0x0F,

	FIP_CONTEXT_TBL_TYPE = 244,
	FIP_CONTEXT_TBL_SEQ_MASK = 0xC0,
	FIP_CONTEXT_TBL_SEQ_FIRST = 0x40,
	FIP_CONTEXT_TBL_SEQ_LAST = 0x80,

	FKA_ADV_PERIOD = 8000,	/* in mSecs */
	FKA_ADV_MISSES = 3
};

enum fip_login_syndroms {
	FIP_SYNDROM_SUCCESS = 0,
	FIP_SYNDROM_HADMIN_REJECT = 1,
	FIP_SYNDROM_GW_RESRC = 2,
	FIP_SYNDROM_NO_NADMIN = 3,
	FIP_SYNDROM_UNRECOGNISED_HOST = 4,
	FIP_SYNDROM_UNSUPPORTED_PARAM = 5,
	FIP_SYNDROM_GW_IS_LAG_MEMBER = 6,
	FIP_SYNDROM_DUPLICATE_ADDRESS = 7,
};

/*
 * Send a multicast or unicast solicit packet. The multicast packet is sent
 * to the discover mcast group. Unicast packets are sent to the dqpn + dlid
 * supplied. The dlid, dqpn, sl are ignored for multicast packets.
 * functionreturns 0 on success and error code on failure
*/
int fip_solicit_send(struct fip_discover *discover,
		     enum fip_packet_type multicast, u32 dqpn,
		     u16 dlid, u8 sl, int new_prot);

/*
 * Send a unicast login packet. This function supports both host and
 * network admined logins. function returns 0 on success and
 * error code on failure
*/
int fip_login_send(struct fip_vnic_data *vnic);

int fip_logout_send(struct fip_vnic_data *vnic);

/*
 * This function creates and sends a few types of packets (all ucast):
 *   vHub context request - new=1, logout=0
 *   vHub context update / vnic keep alive - new=0, logout=0
 *   vnic logout - new=0, logout=1
*/
int fip_update_send(struct fip_vnic_data *vnic, int request_new, int logout);

/*
 * Check if a received packet is a FIP packet, And if so return its subtype.
 * The FIP type is also returned in fip_type and can be either EOIB_FIP_OPCODE
 * or FCOIB_FIP_OPCODE. If the packet is not a FIP packet -EINVAL is returned.
*/
int fip_pkt_parse(char *buffer, int length, int *fip_type);

/*
 * Already know that this is a FIP packet, return its subtype.
*/
int fip_pkt_get_subtype_bh(char *buffer);

/*
 * parse a packet that is suspected of being an advertise packet. The packet
 * returns 0 for a valid advertise packet and an error code other wise. The
 * packets "interesting" details are returned in data.
*/
int fip_advertise_parse_bh(struct fip_discover *discover, struct fip_content *fc,
			   struct fip_gw_data *data);

/*
 * parse a packet that is suspected of being an login ack packet. The packet
 * returns 0 for a valid login ack packet and an error code other wise. The
 * packets "interesting" details are returned in data.
*/
int fip_login_parse(struct fip_discover *discover, struct fip_content *fc,
		    struct fip_login_data *data);

static inline int _map_generic_pkt(struct vnic_port *port,
				   struct fip_ring_entry *tx_ring_entry,
				   void *mem, int pkt_size)
{
	/* alloc packet to be sent */
	tx_ring_entry->mem = mem;

	/* map packet to bus */
	tx_ring_entry->bus_addr =
	    ib_dma_map_single(port->dev->ca,
			      tx_ring_entry->mem, pkt_size, DMA_TO_DEVICE);

	if (unlikely(ib_dma_mapping_error(port->dev->ca,
					  tx_ring_entry->bus_addr))) {
		vnic_warn(port->name,
			  "send_generic_pkt failed to map to pci\n");
		return -ENOMEM;
	}
	tx_ring_entry->length = pkt_size;

	return 0;
}

static inline int alloc_map_fip_buffer(struct ib_device *ca,
				       struct fip_ring_entry *me,
				       int size, gfp_t mask)
{
	me->mem = kmalloc(size, mask);
	if (!me->mem) {
		vnic_warn(ca->name, "failed to alloc memory (%d)\n", size);
		return -ENOMEM;
	}

	me->bus_addr = ib_dma_map_single(ca, me->mem, size, DMA_FROM_DEVICE);
	if (unlikely(ib_dma_mapping_error(ca, me->bus_addr))) {
		kfree(me->mem);
		vnic_warn(ca->name, "ib_dma_mapping_error failed\n");
		return -ENOMEM;
	}
	me->length = size;
	me->entry_posted = 0;

	return 0;
}

#define DELAYED_WORK_CLEANUP_JIFFS	2
#define FIP_MAX_PKT_PRINT_LENGTH	120
#define	FIP_OP_RECV			(1ul << 31)

static const char fip_discover_mgid[GID_LEN] = {
	0xFF, 0x12, 0xE0, 0x1B,
	0x00, 0x06, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00};
static const char fip_solicit_mgid[GID_LEN] = {
	0xFF, 0x12, 0xE0, 0x1B,
	0x00, 0x07, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00};


/* TODO - remove this: for initial debug only */
void fip_dbg_dump_raw_pkt(int level, void *buff,
			  int length, int is_tx, char *name);
enum {
	FIP_ETH_HEADER_LEN = 14,
	FIP_ENCAP_LEN = 4,
	FIP_PROTOCOL_RX_SIZE = 16,	/* must be power of 2 */
	FIP_PROTOCOL_TX_SIZE = 64,	/* must be power of 2 */
	FIP_LOGIN_RX_SIZE = 64,	/* must be power of 2 */
	FIP_LOGIN_TX_SIZE = 64,		/* must be power of 2 */

	/* timeout in seconds between LOGIN and ACK */
	FIP_LOGIN_TIMEOUT = 8,
	FIP_RESOLICIT_TIME = 8,

	IPOIB_UD_HEAD_SIZE = IB_GRH_BYTES + FIP_ENCAP_LEN,
};

struct fip_rcv_pkt {
	struct list_head list;
	struct fip_content *fc;
	int length;
	void *mem;
};

/*
 * Alloc the discover CQ, QP. Configure the QP to RTS.
 * alloc the RX + TX rings and queue work for discover
 * finite state machine code. If complete it set, it clears
 * possible previous GW / VNIC data structs on init.
 */
int fip_discover_init(struct vnic_port *port, struct fip_discover *discover,
		      u16 pkey, int complete);

/*
 * free the discover TX and RX rings, QP and CQ. If complete 
 * is set, it clears possible previous GW / VNIC data structs
 * by using a "complete" flush otherwise vnic data is preserved.
*/
int fip_discover_cleanup(struct vnic_port *port, struct fip_discover *discover, int complete);

/*
 * send a single multicast packet.
 * return 0 on success, other on failure.
*/
int fip_mcast_send(struct vnic_port *port, struct ib_qp *qp,
		   unsigned int wr_id, u64 mapping,
		   int size, u16 pkey_index, struct vnic_mcast *mcast);
/*
 * send a single unicast packet.
 * return 0 on success, other on failure.
*/
int fip_ucast_send(struct vnic_port *port, struct ib_ah *ah,
		   struct ib_qp *qp,
		   unsigned int wr_id, u64 mapping,
		   int size, u16 pkey_index, u32 dest_qpn, u16 dlid,
		   u32 qkey, u8 sl);
/*
 * qonfigure a newly allocated QP and move it
 * from reset->init->RTR->RTS
 */
int fip_init_qp(struct vnic_port *port, struct ib_qp *qp,
		u16 pkey_index, char *name);

/*
 * allocs a single rx buffer (of size size), map it to pci bus
 * and post it to the qp for receive. id parameter is used
 * to keep track of work request when completion is received.
 * kernel and bus address are returned in mem_entry.
 * returns 0 on success else failure.
 * id used to identify entry in receive queue.
 */
int fip_post_receive(struct vnic_port *port, struct ib_qp *qp, int size,
		     int _id, struct fip_ring_entry *mem_entry, char *name);

/* trigered by a core event */
void fip_qp_to_reset(struct ib_qp *qp, char *name);
void fip_flush_rings(struct vnic_port *port,
		     struct ib_cq *cq,
		     struct ib_qp *qp,
		     struct fip_ring *rx_ring,
		     struct fip_ring *tx_ring,
		     char *name);
void fip_free_rings(struct vnic_port *port,
		    struct fip_ring *rx_ring,
		    struct fip_ring *tx_ring,
		    char *name);

/*
 * This function allocates the tx buffers and initializes the head and
 * tail indexes.
 */
int fip_init_tx(int size, struct fip_ring *tx_ring, char *name);

/*
 * Configure the discover QP. This includes configuring rx+tx
 * moving the discover QP to RTS and creating the tx  and rx rings
 */
int fip_init_rx(struct vnic_port *port, int ring_size, struct ib_qp *qp,
		struct fip_ring *rx_ring, char *name);

/*
 * This is a general purpose CQ completion function that handles
 * completions on RX and TX rings. It can serve all users that are
 * using RX and TX rings.
 * RX completions are destinguished from TX comp by the MSB that is set
 * for RX and clear for TX. For RX, the memory is unmapped from the PCI,
 * The head is incremented. For TX the memory is unmapped and then freed.
 * The function returns the number of packets received.
*/
int fip_comp(struct vnic_port *port,
	     struct ib_cq *cq,
	     struct fip_ring *rx_ring,
	     struct fip_ring *tx_ring,
	     char *name);

/*
 * This function is the driving engine of the vnic logic. It manages the
 * vnics state machines.
 * Some of the states in the state machine could have been removed because
 * they contain "actions" and not states. Still it is easier to maintaine
 * the code this way and it gives an easy mechanism for exception handling
 * and retries.
 * Only call this function from fip_wq context.
*/
void fip_vnic_fsm(struct work_struct *work);

/*
 * Mark the vnic for deletion and trigger a delayed call to the cleanup
 * function. In the past the vnic was moved to another list but this
 * might cause vnic duplication if new vnics are added to the GW. Even
 * if the vnic is being flushed we need to know it is there.
 *
 * Note: This deletion method insures that all pending vnic work requests
 * are cleared without dependency of the calling context.
*/
void fip_vnic_close(struct fip_vnic_data *vnic, enum fip_flush flush);

/*
 * Free vnic resources. This includes closing the data vnic (data QPs etc)
 * and the discovery resources. If the vnic can be totaly destroyed (no
 * pending work) the vnic will be removed from the GW list and it's memory
 * freed. If not the vnic will not be freed and the function will return an
 * error. The caller needs to recall this unction to complete the operation.
*/
int fip_vnic_destroy(struct fip_vnic_data *vnic);

struct fip_vnic_data *fip_vnic_alloc(struct vnic_port *port,
				     struct fip_gw_data *gw,
				     int hadmin,
				     u16 vnic_id);

/*
 * Look for a vnic in the GW vnic list. The search key used is either the vnic_id
 * that is unique, or the mac+vlan pair. A match on either key will result in the
 * return of the vnic. both keys are nesesary because host assigned delete
 * flow might not have access to the vnic_id. The search disregards vnics that
 * are undergoing full flush (they will be removed soon).
*/
struct fip_vnic_data *fip_vnic_find_in_list(struct fip_gw_data *gw,
					    u16 vnic_id, u8 *mac,
					    u16 vlan, u8 vlan_used);

/*
 * process an incoming login ack packet. The packet was already parsed and
 * its data was placed in *data. The function creates RX and TX rings for the
 * vnic and starts the multicast join procedure.
 * This function should not be called for packets other then login ack packets.
*/
void fip_vnic_login_ack_recv(struct fip_vnic_data *vnic,
			     struct fip_login_data *data);

/*
 * This function should be called when the building of a vhub context
 * table is done and the vnic state should transition to CONNECTED.
*/
int fip_vnic_tbl_done(struct fip_vnic_data *vnic);
int fip_vnic_mcast_recnct(struct fip_vnic_data *vnic);

/*
 * Init the vnic's vHub table data structures, before using them
 */
void vhub_ctx_init(struct fip_vnic_data *vnic);
void vhub_table_free(struct vhub_elist *elist);

/*
 * Clear and free the vnic's vHub context table data structures.
 */
void vhub_ctx_free(struct fip_vnic_data *vnic);

/*
 * This function handles a vhub context table packet. The table will
 * be processed only if we do not have a up to date local coppy of
 * our own. The table update supports multi-packet tables so care
 * must be taken in building the complete table.
*/
int vhub_handle_tbl(struct fip_vnic_data *vnic, struct fip_content *fc,
		    u32 vhub_id, u32 tusn);

/*
 * This function handles a vhub context update packets. There are three flows
 * in handeling update packets. The first is before the main table is up
 * to date, the second is after the table is up to date but before it was
 * passed to the ownership of the data vnic (login struct) and the local
 * lists are freed, and the last is when the table maintanence is done
 * by the data vnic. This function handles all cases.
*/
int vhub_handle_update(struct fip_vnic_data *vnic,
		       u32 vhub_id, u32 tusn,
		       struct vnic_table_entry *data);

/*
 * This function writes the main vhub table to the data (login) vnic.
 * You should call it when the data vnic is ready for it and after the
 * table is up to date (and the update list was applied to the main list)
 */
int fip_vnic_write_tbl(struct fip_vnic_data *vnic);

/* sysfs entries for hadmin vNics*/
int vnic_create_hadmin_dentry(struct fip_vnic_data *vnic);
void vnic_delete_hadmin_dentry(struct fip_vnic_data *vnic);
void extract_memb_extended(struct fip_ext_type_lag_members *ext_lag_membs,
			   int ext_length,			  
			   struct lag_members *lagm,
			   char *name);
int handle_member_update(struct fip_vnic_data *vnic, struct lag_members *lm);
int extract_vhub_extended(struct fip_ext_desc_tlv *fed,
                          struct fip_vnic_data *vnic);
static inline int send_generic_ucast_pkt(struct vnic_port *port,
					 struct ib_ah *ah,
					 struct fip_ring *tx_ring,
					 void *mem, int pkt_size,
					 struct ib_qp *qp,
					 int pkey_index,
					 u32 dst_qpn, u16 dst_lid,
					 u32 qkey, u8 sl)
{
	int index, rc;
	unsigned long flags;
	unsigned long tail;

	/*
	 * we are only allowed to update the head at task level so no need to
	 * perform any locks here
	 */
	spin_lock_irqsave(&tx_ring->ring_lock, flags);
	index = tx_ring->head & (tx_ring->size - 1);

	vnic_dbg_fip(port->name, "send ucast packet\n");

	spin_lock(&tx_ring->head_tail_lock);
	tail = tx_ring->tail;
	spin_unlock(&tx_ring->head_tail_lock);

	/* ring full try again */
	if (tx_ring->head - tail >=  tx_ring->size) {
		vnic_warn(port->name, "send_generic_pkt ring full: QPN 0x%x: tail=%ld head=%ld diff=%ld\n",
			  qp->qp_num, tx_ring->tail, tx_ring->head, tx_ring->head - tx_ring->tail);
		rc = -EAGAIN;
		goto err;
	}


	rc = _map_generic_pkt(port, &tx_ring->ring[index], mem, pkt_size);
	if (rc)
		goto err;

	rc = fip_ucast_send(port, ah, qp, index,
			    tx_ring->ring[index].bus_addr,
			    pkt_size, pkey_index, dst_qpn, dst_lid,
			    qkey, sl);

	if (rc) {
		vnic_warn(port->name, "fip_ucast_send() failed (%d)\n", rc);
		rc = -ENODEV;
		goto error_unmap_dma;
	}

	tx_ring->head++;

	spin_unlock_irqrestore(&tx_ring->ring_lock, flags);
	return 0;

error_unmap_dma:
	ib_dma_unmap_single(port->dev->ca,
			    tx_ring->ring[index].bus_addr,
			    pkt_size, DMA_TO_DEVICE);
err:
	spin_unlock_irqrestore(&tx_ring->ring_lock, flags);
	return rc;
}

static inline const char *eport_state_str(int state)
{
	switch (state) {
	case EPORT_STATE_DOWN: return "Down";
	case EPORT_STATE_UP: return "Up";
	default:return "Invalid";
	}
}

#endif /* _VNIC_FIP_H */
