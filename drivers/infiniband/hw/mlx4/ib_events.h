/*
 * Copyright (c) 2007 Cisco Systems, Inc. All rights reserved.
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
 /***********************************************************/
/*This file support the handling of mlx4_ib events. */
/***********************************************************/
#ifndef MLX4_IB_EVENTS_H
#define MLX4_IB_EVENTS_H

#include "mlx4_ib.h"

#define MAX_SET_PORT_INFO_GEN_EVENTS 4



struct mlx4_ib_eqe {
	u8			reserved1;
	u8			type;
	u8			reserved2;
	u8			subtype;
	union {
		u32		raw[6];
		struct {
			u16	reserved1;
			__be16	token;
			u32	reserved2;
			u8	reserved3[3];
			u8	status;
			__be64	out_param;
		} __attribute__((packed)) cmd;
		struct {
			u32	reserved1[2];
			__be32	port;
		} __attribute__((packed)) port_change;
		struct {
			#define COMM_CHANNEL_BIT_ARRAY_SIZE	4
			u32 reserved;
			u32 bit_vec[COMM_CHANNEL_BIT_ARRAY_SIZE];
		} __attribute__((packed)) comm_channel_arm;
		struct {
			u8	reserved[3];
			u8 	vep_num;
		} __attribute__((packed)) vep_config;
		struct {
			u8	port;
			u8	reserved[3];
			__be64	mac;
		} __attribute__((packed)) mac_update;
		struct {
			u8	port;
		} __attribute__((packed)) sw_event;
		struct {
			__be32	slave_id;
		} __attribute__((packed)) flr_event;
		struct {
			u8 reserved[3];
			u8 port;
			union {
				struct {
					__be16 mstr_sm_lid;
					__be16 port_lid;
					__be32 changed_attr;
					u8 reserved[3];
					u8 mstr_sm_sl;
				} __attribute__((packed)) port_info;
				struct {
					__be32 block_ptr;
					__be32 tbl_entries_mask;
				} __attribute__((packed)) tbl_change_info;
			} params;
		} __attribute__((packed)) port_mgmt_change;
	} event;
	u8			reserved3[3];
	u8			owner;
};

struct ib_event_work {
	struct work_struct	work;
	struct mlx4_ib_dev	*ib_dev;
	struct mlx4_ib_eqe	ib_eqe;
};


void handle_lid_change_event(struct mlx4_ib_dev *dev, u8 port_num);
void handle_client_rereg_event(struct mlx4_ib_dev *dev, u8 port_num);
void handle_port_mgmt_change_event(struct work_struct *work);
#endif /* MLX4_IB_EVENTSMLX4_DEV_EVENT_PORT_MGMT_CHANGE_H */
