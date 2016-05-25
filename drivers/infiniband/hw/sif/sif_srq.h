/*
 * Copyright (c) 2011, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_srq.h: Interface to internal Shared receive queue logic for SIF
 */

#ifndef __SIF_SRQ_H
#define __SIF_SRQ_H

struct ib_srq *sif_create_srq(struct ib_pd *ibpd,
			      struct ib_srq_init_attr *srq_init_attr,
			      struct ib_udata *udata);
int sif_modify_srq(struct ib_srq *ibsrq, struct ib_srq_attr *srq_attr,
		   enum ib_srq_attr_mask srq_attr_mask, struct ib_udata *udata);
int sif_query_srq(struct ib_srq *ibsrq, struct ib_srq_attr *srq_attr);
int sif_destroy_srq(struct ib_srq *ibsrq);

int sif_post_srq_recv(struct ib_srq *ibsrq,
		      struct ib_recv_wr *recv_wr,
		      struct ib_recv_wr **bad_recv_wr);

#endif
