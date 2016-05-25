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
 * sif_ibqp.h: External interface to IB queue pair logic for sif
 */

#ifndef __SIF_IBQP_H
#define __SIF_IBQP_H

struct ib_qp *sif_create_qp(struct ib_pd *ibpd,
			    struct ib_qp_init_attr *qp_init_attr,
			    struct ib_udata *udata);
int sif_modify_qp(struct ib_qp *ibqp,
		  struct ib_qp_attr *qp_attr,
		  int qp_attr_mask, struct ib_udata *udata);

int sif_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr,
		 int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr);
int sif_destroy_qp(struct ib_qp *ibqp);

#endif
