/*
 * Copyright (c) 2007 Mellanox Technologies. All rights reserved.
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

#ifndef _MLX4_EN_PORT_H_
#define _MLX4_EN_PORT_H_


#define VLAN_FLTR_SIZE	128
struct mlx4_set_vlan_fltr_mbox {
    __be32 entry[VLAN_FLTR_SIZE];
};

enum {
	MLX4_MCAST_CONFIG       = 0,
	MLX4_MCAST_DISABLE      = 1,
	MLX4_MCAST_ENABLE       = 2,
};

enum {
	MLX4_EN_1G_SPEED	= 0x02,
	MLX4_EN_10G_SPEED_XFI	= 0x01,
	MLX4_EN_10G_SPEED_XAUI	= 0x00,
	MLX4_EN_40G_SPEED	= 0x40,
	MLX4_EN_OTHER_SPEED	= 0x0f,
};

struct mlx4_en_query_port_context {
	u8 link_up;
#define MLX4_EN_LINK_UP_MASK	0x80
	u8 reserved;
	__be16 mtu;
	u8 reserved2;
	u8 link_speed;
#define MLX4_EN_SPEED_MASK	0x43
	u16 reserved3[5];
	__be64 mac;
	u8 transceiver;
	u8 actual_speed;
};

#endif
