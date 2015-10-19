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

#include <linux/completion.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/idr.h>
#include <linux/inetdevice.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <net/route.h>

#include <net/tcp.h>
#include <net/ipv6.h>

#include <rdma/rdma_cm.h>
#include <rdma/rdma_cm_ib.h>
#include <rdma/rdma_netlink.h>
#include <rdma/ib.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_cm.h>
#include <rdma/ib_sa.h>
#include <rdma/iw_cm.h>

#include "cma_priv.h"
#include "cma_sdp_priv.h"

int cma_verify_rep(struct rdma_id_private *id_priv, void *data)
{
	if (id_priv->id.ps == RDMA_PS_SDP &&
	    sdp_get_majv(((struct sdp_hah *) data)->sdp_version) !=
	    SDP_MAJ_VERSION)
		return -EINVAL;

	return 0;
}

int cma_get_net_info_sdp(void *hdr, enum rdma_port_space ps,
			 u8 *ip_ver, __be16 *port,
			 union cma_ip_addr **src, union cma_ip_addr **dst)
{
	switch (ps) {
	case RDMA_PS_SDP:
		if (sdp_get_majv(((struct sdp_hh *) hdr)->sdp_version) !=
		    SDP_MAJ_VERSION)
			return -EINVAL;

		*ip_ver = sdp_get_ip_ver(hdr);
		*port	= ((struct sdp_hh *) hdr)->port;
		*src	= &((struct sdp_hh *) hdr)->src_addr;
		*dst	= &((struct sdp_hh *) hdr)->dst_addr;
		break;
	default:
		if (((struct cma_hdr *) hdr)->cma_version != CMA_VERSION)
			return -EINVAL;

		*ip_ver = cma_get_ip_ver(hdr);
		*port	= ((struct cma_hdr *) hdr)->port;
		*src	= &((struct cma_hdr *) hdr)->src_addr;
		*dst	= &((struct cma_hdr *) hdr)->dst_addr;
		break;
	}

	if (*ip_ver != 4 && *ip_ver != 6)
		return -EINVAL;

	return 0;
}

void cma_set_compare_data_sdp(enum rdma_port_space ps, struct sockaddr *addr,
				 struct ib_cm_compare_data *compare)
{
	struct cma_hdr *cma_data, *cma_mask;
	struct sdp_hh *sdp_data, *sdp_mask;
	__be32 ip4_addr;
	struct in6_addr ip6_addr;

	memset(compare, 0, sizeof(*compare));
	cma_data = (void *) compare->data;
	cma_mask = (void *) compare->mask;
	sdp_data = (void *) compare->data;
	sdp_mask = (void *) compare->mask;

	switch (addr->sa_family) {
	case AF_INET:
		ip4_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
		sdp_set_ip_ver(sdp_data, 4);
		sdp_set_ip_ver(sdp_mask, 0xF);
		sdp_data->dst_addr.ip4.addr = ip4_addr;
		sdp_mask->dst_addr.ip4.addr = htonl(~0);
		break;
	case AF_INET6:
		ip6_addr = ((struct sockaddr_in6 *) addr)->sin6_addr;
		sdp_set_ip_ver(sdp_data, 6);
		sdp_set_ip_ver(sdp_mask, 0xF);
		sdp_data->dst_addr.ip6 = ip6_addr;
		memset(&sdp_mask->dst_addr.ip6, 0xFF,
			sizeof(sdp_mask->dst_addr.ip6));
		break;
	default:
		break;
	}
}

int cma_format_hdr_sdp(void *hdr, struct rdma_id_private *id_priv)
{
	struct sdp_hh *sdp_hdr;

	if (cma_family(id_priv) == AF_INET) {
		struct sockaddr_in *src4, *dst4;

		src4 = (struct sockaddr_in *) cma_src_addr(id_priv);
		dst4 = (struct sockaddr_in *) cma_dst_addr(id_priv);

		sdp_hdr = hdr;

		if (sdp_get_majv(sdp_hdr->sdp_version) != SDP_MAJ_VERSION)
			return -EINVAL;
		sdp_set_ip_ver(sdp_hdr, 4);
		sdp_hdr->src_addr.ip4.addr = src4->sin_addr.s_addr;
		sdp_hdr->dst_addr.ip4.addr = dst4->sin_addr.s_addr;
		sdp_hdr->port = src4->sin_port;
	} else {
		struct sockaddr_in6 *src6, *dst6;

		src6 = (struct sockaddr_in6 *) cma_src_addr(id_priv);
		dst6 = (struct sockaddr_in6 *) cma_dst_addr(id_priv);

		sdp_hdr = hdr;

		if (sdp_get_majv(sdp_hdr->sdp_version) != SDP_MAJ_VERSION)
			return -EINVAL;
		sdp_set_ip_ver(sdp_hdr, 6);
		sdp_hdr->src_addr.ip6 = src6->sin6_addr;
		sdp_hdr->dst_addr.ip6 = dst6->sin6_addr;
		sdp_hdr->port = src6->sin6_port;
	}

	return 0;
}

void cma_save_ip4_info_sdp(struct rdma_cm_id *id, struct rdma_cm_id *listen_id,
			   struct cma_hdr *cma_hdr)
{
	struct sockaddr_in *ip4;
	struct sdp_hh *hdr = (struct sdp_hh *)cma_hdr;

	ip4 = (struct sockaddr_in *) &id->route.addr.src_addr;
	ip4->sin_family = AF_INET;
	ip4->sin_addr.s_addr = hdr->dst_addr.ip4.addr;
	ip4->sin_port = ss_get_port(&listen_id->route.addr.src_addr);

	ip4 = (struct sockaddr_in *) &id->route.addr.dst_addr;
	ip4->sin_family = AF_INET;
	ip4->sin_addr.s_addr = hdr->src_addr.ip4.addr;
	ip4->sin_port = hdr->port;
}

void cma_save_ip6_info_sdp(struct rdma_cm_id *id, struct rdma_cm_id *listen_id,
			   struct cma_hdr *cma_hdr)
{
	struct sockaddr_in6 *ip6;
	struct sdp_hh *hdr = (struct sdp_hh *)cma_hdr;

	ip6 = (struct sockaddr_in6 *) &id->route.addr.src_addr;
	ip6->sin6_family = AF_INET6;
	ip6->sin6_addr = hdr->dst_addr.ip6;
	ip6->sin6_port = ss_get_port(&listen_id->route.addr.src_addr);

	ip6 = (struct sockaddr_in6 *) &id->route.addr.dst_addr;
	ip6->sin6_family = AF_INET6;
	ip6->sin6_addr = hdr->src_addr.ip6;
	ip6->sin6_port = hdr->port;

}
