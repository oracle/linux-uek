/*
 * Copyright (c) 2013, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_verbs.h: IB verbs API extensions specific to PSIF
 */

#ifndef _SIF_VERBS_H
#define _SIF_VERBS_H
#include <rdma/ib_verbs.h>
#include "sif_user.h"

/*** sif verbs extensions ***/

enum sif_eoib_ctrl {
	/* Per UF controls */
	SIF_EC_UPM  = 1 <<  0,  /* Unicast promiscuous mode */
	SIF_EC_MPM  = 1 <<  1,  /* Multicast promiscuous mode */
	SIF_EC_ABC  = 1 <<  2,  /* Accept broadcast packets */
	SIF_EC_PAD  = 1 <<  3,  /* Ethernet padding */
	/* HCA wide (PF only) controls */
	SIF_EC_UOFE = 1 << 10,   /* Unicast overflow table enable */
	SIF_EC_RTP  = 1 << 11,   /* Receive tossed packets */
	SIF_EC_DVM  = 1 << 12,   /* Double VLAN mode */
	SIF_EC_VEM  = 1 << 13,   /* VLAN Enforcement mode */
	SIF_EC_NSM  = 1 << 14,   /* No strip mode */
};


/* If this bit is set in the device_modify_mask to ib_modify_device
 * the sif ib driver will assume that the provided ib_device_attr
 * is embedded in a sif_device_modify struct.
 */
enum sif_device_modify_flags {
	IB_DEVICE_MODIFY_EXTENDED = 1 << 3
};


struct sif_device_modify {
	struct ib_device_modify ib;
	/* These two masks use values from sif_eoib_ctrl */
	u32 eoib_ctrl;  /* Indicate affected bits in eoib_data */
	u32 eoib_data;  /* Values to set/unset, only bits set in eoib_ctrl affected */
	u16 uf;         /* This field is only valid from PF */
};


/* Extension bits in the qp create mask to ib_create_qp    */
/* Note that we use bits below IB_QP_CREATE_RESERVED_START */
enum sif_qp_create_flags {
	IB_QP_CREATE_EOIB            = IB_QP_CREATE_RESERVED_END     ,  /* Indicate that this is an Ethernet over IB QP */
	IB_QP_CREATE_RSS             = IB_QP_CREATE_RESERVED_END >> 1,  /* Enable receive side scaling */
	IB_QP_CREATE_HDR_SPLIT       = IB_QP_CREATE_RESERVED_END >> 2,  /* Enable header/data split for offloading */
	IB_QP_CREATE_RCV_DYNAMIC_MTU = IB_QP_CREATE_RESERVED_END >> 3,  /* Enable receive side dynamic mtu */
	IB_QP_CREATE_PROXY           = IB_QP_CREATE_RESERVED_END >> 4,  /* Enable a special EPSA proxy */
	IB_QP_NO_CSUM		     = IB_QP_CREATE_RESERVED_END >> 5,  /* No csum for qp, wqe.wr.csum = qp.magic */
	IB_QP_CREATE_SND_DYNAMIC_MTU = IB_QP_CREATE_RESERVED_END >> 6,  /* Enable receive side dynamic mtu */
};

/* Extension bits in the qp attr mask to ib_modify_qp
 * TBD: Not implemented yet
 */
enum sif_qp_attr_mask {
	IB_QP_EOIB         = 1 << 24,  /* Enable as an Ethernet over IB QP */
	IB_QP_IPOIB        = 1 << 25,  /* Enable as an IP over IB QP */
	IB_QP_RSS          = 1 << 26,  /* Enable receive side scaling */
	IB_QP_HDR_SPLIT    = 1 << 27,  /* Enable header/data split for offloading */
	IB_QP_RCV_DYN_MTU  = 1 << 28,  /* Enable receive side dynamic mtu */
	IB_QP_SND_DYN_MTU  = 1 << 29,  /* Enable send side dynamic mtu */
};


/* Set/get the 48 bit ethernet mac address for a port on a uf
 * The uf field is ignored for all ufs except uf 0 (PF)
 */
int sif_get_mac(struct ib_device *dev, u8 port, u16 uf, u64 *address);
int sif_set_mac(struct ib_device *dev, u8 port, u16 uf, u64 address);

struct sif_dev;
struct psif_epsc_csr_req;
struct psif_epsc_csr_rsp;
enum psif_mbox_type;

struct sif_verbs {
	/* Exposed internal create_cq call to allow creation of proxy CQs.
	 * Needed by EPSA users. Implemented in sif_cq.c.
	 */
	struct ib_cq * (*create_cq)(struct ib_device *ibdev, int cqe,
				int comp_vector, struct ib_ucontext *context,
				struct ib_udata *udata,
				enum sif_proxy_type proxy);
	int (*eps_wr)(struct  ib_device *ibdev, enum psif_mbox_type eps_num,
		struct psif_epsc_csr_req *req, struct psif_epsc_csr_rsp *cqe);
};

/* TBD: External rep of struct sif_dev - must be kept synchronized */
struct sif_device {
	struct ib_device ib_dev;
	struct sif_verbs sv;
};

static inline struct sif_device *to_sif_device(struct ib_device *ibdev)
{
	return container_of(ibdev, struct sif_device, ib_dev);
}

#endif
