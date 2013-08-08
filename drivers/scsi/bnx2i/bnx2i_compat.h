/* bnx2i_compat.h: Broadcom NetXtreme II iSCSI compatible header.
 *
 * Copyright (c) 2012 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * Written by: Eddie Wai (eddie.wai@broadcom.com)
 */

#ifndef _BNX2I_COMPAT_H_
#define _BNX2I_COMPAT_H_

/* Common */
#define __RHELS_DISTRO__	\
	(defined(__RHELS_DISTRO_5__) || defined(__RHELS_DISTRO_6__))

#define __DISTRO__		\
	(defined(__SLES_DISTRO__) || defined(__RHELS_DISTRO__))

#if (defined(_EP_CONNECT_IFACE_NUM_))
#define bnx2i_ep_connect(shost, dst_addr, non_blocking, iface_num) \
	bnx2i_ep_connect(shost, dst_addr, non_blocking, iface_num)

#define	bnx2i_offload_mesg(shost, transport, msg_type, buf, buflen, iface_num) \
	iscsi_offload_mesg(shost, transport, msg_type, buf, buflen, iface_num)
#else
#define bnx2i_ep_connect(shost, dst_addr, non_blocking, iface_num) \
	bnx2i_ep_connect(shost, dst_addr, non_blocking)

#define	bnx2i_offload_mesg(shost, transport, msg_type, buf, buflen, iface_num) \
	iscsi_offload_mesg(shost, transport, msg_type, buf, buflen)
#endif

/********************************* Upstream **********************************/
/* Common for all upstream kernels */
#include <scsi/iscsi_if.h>
#include <scsi/iscsi_proto.h>
#include <scsi/scsi_transport_iscsi.h>
#include <scsi/libiscsi.h>

#define FORMAT_IP(buf, fstr, src, len)		\
	do {					\
		len = sprintf(buf, fstr, src);	\
	} while (0)

#define FORMAT_IP6(buf, fstr, src, len) FORMAT_IP(buf, fstr, src, len)

#define kthread_create_on_node(io_thread, arg, node, str, cpu)	\
	kthread_create(io_thread, arg, str, cpu)

#define set_unfreezable(cur)

#endif /* _BNX2I_COMPAT_H_ */
