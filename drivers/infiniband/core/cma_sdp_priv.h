/*
 * Copyright (c) 2005 Voltaire Inc.  All rights reserved.
 * Copyright (c) 2002-2005, Network Appliance, Inc. All rights reserved.
 * Copyright (c) 1999-2005, Mellanox Technologies, Inc. All rights reserved.
 * Copyright (c) 2005-2006 Intel Corporation.  All rights reserved.
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
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
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

#ifndef _CMA_SDP_PRIV_H
#define _CMA_SDP_PRIV_H

struct sdp_hh {
	u8 bsdh[16];
	u8 sdp_version; /* Major version: 7:4 */
	u8 ip_version;	/* IP version: 7:4 */
	u8 sdp_specific1[10];
	__be16 port;
	__be16 sdp_specific2;
	union cma_ip_addr src_addr;
	union cma_ip_addr dst_addr;
};

struct sdp_hah {
	u8 bsdh[16];
	u8 sdp_version;
};

#define SDP_MAJ_VERSION 0x2

static inline u8 sdp_get_majv(u8 sdp_version)
{
	return sdp_version >> 4;
}

static inline u8 sdp_get_ip_ver(struct sdp_hh *hh)
{
	return hh->ip_version >> 4;
}

static inline void sdp_set_ip_ver(struct sdp_hh *hh, u8 ip_ver)
{
	hh->ip_version = (ip_ver << 4) | (hh->ip_version & 0xF);
}

extern int cma_verify_rep(struct rdma_id_private *id_priv, void *data);

extern int cma_get_net_info_sdp(void *hdr, enum rdma_port_space ps,
			    u8 *ip_ver, __be16 *port,
			    union cma_ip_addr **src, union cma_ip_addr **dst);

extern void cma_set_compare_data_sdp(enum rdma_port_space ps,
				     struct sockaddr *addr,
				     struct ib_cm_compare_data *compare);

extern int cma_format_hdr_sdp(void *hdr, struct rdma_id_private *id_priv);

extern void cma_save_ip4_info_sdp(struct rdma_cm_id *id,
				  struct rdma_cm_id *listen_id,
				  struct cma_hdr *hdr);

extern void cma_save_ip6_info_sdp(struct rdma_cm_id *id,
				  struct rdma_cm_id *listen_id,
				  struct cma_hdr *hdr);

#endif /* _CMA_SDP_PRIV_H */
