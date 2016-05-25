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
 * sif_ibcq.h: External interface to IB completion queue logic for SIF
 */

#ifndef __SIF_IBCQ_H
#define __SIF_IBCQ_H

struct ib_cq *sif_create_cq(struct ib_device *ibdev, int cqe,
			int comp_vector, struct ib_ucontext *context,
			struct ib_udata *udata,
			enum sif_proxy_type proxy);

int sif_modify_cq(struct ib_cq *ibcq, u16 cq_count, u16 cq_period);
int sif_destroy_cq(struct ib_cq *ibcq);
int sif_resize_cq(struct ib_cq *ibcq, int cqe, struct ib_udata *udata);
int sif_poll_cq(struct ib_cq *ibcq, int num_entries, struct ib_wc *wc);
int sif_peek_cq(struct ib_cq *ibcq, int wc_cnt);

int sif_req_notify_cq(struct ib_cq *ibcq, enum ib_cq_notify_flags flags);
int sif_req_ncomp_notif(struct ib_cq *ibcq, int wc_cnt);

#endif
