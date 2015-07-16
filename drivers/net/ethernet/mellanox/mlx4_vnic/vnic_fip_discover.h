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

#ifndef _FIP_DISCOVER_H
#define _FIP_DISCOVER_H

#include "vnic.h"
#include "vnic_fip.h"

/* TODO - rethink this */
#define FIP_UD_MTU(ib_mtu) (ib_mtu - FIP_ENCAP_LEN - FIP_ETH_HEADER_LEN)
#define FIP_UD_BUF_SIZE(ib_mtu)	(ib_mtu + IB_GRH_BYTES)

#define FIP_MAX_BACKOFF_SECONDS	16
#define FIP_MAX_VNICS_PER_GW	(1 << 9)

#define FIP_TIMEOUT_FACTOR(a) ((a)*5/2)

enum fip_gw_state {
	FIP_GW_HOST_ADMIN,
	FIP_GW_CTRL_PATH_QUERY,
	FIP_GW_SEND_SOLICIT,	/* got mcast advertise & ctrl path query. sending solicit */
	FIP_GW_DATA_PATH_QUERY,
	FIP_GW_CONNECTED	/* we are already connected. do nothing */
};


enum {
	GW_TYPE_SINGLE_EPORT = 0,
	GW_TYPE_LAG = 1,
};

struct gw_ext_boot {
	int valid;
	int boot_prio;
	int timeout;
};

struct gw_ext_lag {
	int valid;
	int hash;	/* enum gw_ext_lag_hash_policy */
	int weights_policy;
	int member_ka;
	int ca;		/* conjestion aware */
	int ca_thresh;
	int ucast;	/* gw supports unicat keep alives */
};


struct gw_ext_pc_id {
	int valid;
	u64 power_cycle_id;
};

struct fip_gw_data_info {
	struct fip_gw_volatile_info vol_info;
	long gw_adv_period;  /* timeout in jiffies */
	long gw_period;      /* timeout in jiffies */
	long vnic_ka_period; /* in jiffies */
	int flags;
	u32 gw_qpn;
	u16 gw_lid;
	u16 gw_port_id;
	u16 gw_num_vnics;
	u16 n_rss_qpn;
	u8 gw_sl; /* GW ctrl SL */
	u8 hadmined_en;
	u8 all_vlan_gw;
	u8 gw_vendor_id[VNIC_VENDOR_LEN+1];
	u8 gw_guid[GUID_LEN];
	int gw_type;
	int gw_prot_new;
	int ext_mask;
	struct gw_ext_boot   ext_boot;
	struct gw_ext_lag    ext_lag;
	struct gw_ext_pc_id  ext_pc_id;
};

struct fip_gw_data {
	enum fip_flush flush;
	int hadmin_gw;
	struct mutex mlock;
	struct fip_discover *discover;
	struct list_head list;
	unsigned long keep_alive_jiffies;
	enum fip_gw_state state;
	int vnic_count;
	struct list_head vnic_list;
	struct delayed_work gw_task;
	struct delayed_work vnic_cleanup_task;
	struct fip_gw_data_info info;
	unsigned long n_bitmask[(FIP_MAX_VNICS_PER_GW >> 3) /
			      sizeof(unsigned long)];

	struct ib_sa_path_rec ctrl_prec;
	struct ib_sa_path_rec data_prec;
	struct ib_sa_query *pquery;
	int query_path_cnt;
	int query_id;
	struct completion query_comp;
};

enum fip_gw_data_flags {
	FIP_IS_FIP = 1 << 0,	/* protocol type */
	FIP_RCV_MULTICAST = 1 << 1,	/* received mcast packet */
	FIP_GW_AVAILABLE = 1 << 2,	/* GW available bit set in pkt */
	FIP_HADMINED_VLAN = 1 << 3,	/* H bit set in advertise pkt */
};

static inline u8 vnic_gw_ctrl_sl(struct fip_gw_data *gw)
{
	return vnic_sa_query? gw->ctrl_prec.sl : gw->info.gw_sl;
}

/*
 * TODO - we can do a nicer job here. stage 2
 * allocates memory and post receives
 */
int fip_post_discovery_rcv(struct vnic_port *port,
			   int ring_size, struct ib_qp *qp,
			   struct fip_ring *rx_ring);

int fip_discover_mcast_reattach(struct fip_discover *discover,
				struct vnic_port *port);

/*
 * This function handles a single received packet that are expected to be
 * GW advertisements or login ACK packets. The function first parses the
 * packet and decides what is the packet type and then handles the packets
 * specifically according to its type. This functions runs in task context.
*/
void fip_discover_rx_packet(int *queue, struct fip_content *fc);
int fip_discover_rx_packet_bh(struct fip_discover *discover, struct fip_content *fc);

/*
 * This function is the RX packet handler entry point at the thread level
 * (unlike the completion handler that runs from interrupt context).
 * the function calls a handler function and then reallocats the ring
 * entry for the next receive.
*/
void fip_discover_process_rx(struct fip_discover *discover);
void fip_discover_process_rx_bh(struct work_struct *work);
void fip_discover_gw_fsm_move(struct fip_gw_data *gw, enum fip_gw_state state);

/* This function creates an info string from GW attributes published
 * by the GW in advertisement pkts */
int fip_get_short_gw_info(struct fip_gw_data *gw, char *buff);


int fip_packet_parse(struct vnic_port *port, void *packet, int size,
		     struct fip_content *fc);

#endif /* _FIP_DISCOVER_H */
