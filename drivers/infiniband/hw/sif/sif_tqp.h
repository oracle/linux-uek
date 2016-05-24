/*
 * Copyright (c) 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Wei Lin Guay <wei.lin.guay@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_tqp.h: Implementation of EPSA tunnelling QP for SIF
 */

#ifndef __SIF_TQP_H
#define __SIF_TQP_H
#include <rdma/ib_verbs.h>
#include "sif_dev.h"
#include "sif_base.h"
#include "sif_epsc.h"
#include "sif_cq.h"

static inline enum psif_mbox_type u32_to_mbox(u32 proxy)
{
	switch (proxy) {
	case 0:
		return MBOX_EPSA0;
	case 1:
		return MBOX_EPSA1;
	case 2:
		return MBOX_EPSA2;
	case 3:
		return MBOX_EPSA3;
	default:
		break;
	}
	return (enum psif_mbox_type) -1;
}

extern int sif_epsa_tunneling_post_send(struct ib_qp *ibqp, struct ib_send_wr *wr,
					struct ib_send_wr **bad_wr);

#endif

