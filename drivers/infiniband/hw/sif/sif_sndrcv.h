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
 * sif_sndrcv.h: Interface to IB send/receive, MAD packet recv and
 *   multicast send/recv
 */

#ifndef __SIF_SNDRCV_H
#define __SIF_SNDRCV_H

struct sif_rq;
struct sif_dev;

int sif_post_send(struct ib_qp *ibqp,
		  struct ib_send_wr *wr, struct ib_send_wr **bad_wr);
int sif_post_recv(struct ib_qp *ibqp,
		  struct ib_recv_wr *wr, struct ib_recv_wr **bad_wr);

int sif_multicast_attach(struct ib_qp *ibqp, union ib_gid *gid, u16 lid);
int sif_multicast_detach(struct ib_qp *ibqp, union ib_gid *gid, u16 lid);

int post_recv(struct sif_dev *sdev, struct sif_qp *qp, struct sif_rq *rq,
	struct ib_recv_wr *wr, struct ib_recv_wr **bad_wr);

/* Send a single wr */
int sif_post_send_single(struct ib_qp *ibqp, struct ib_send_wr *wr, bool *use_db, bool last, u16 *first_seq);

#endif
