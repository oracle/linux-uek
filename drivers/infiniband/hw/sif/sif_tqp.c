/*
 * Copyright (c) 2011, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Wei Lin Guay <wei.lin.guay@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_tqp.c: Implementation of EPSA tunneling QP for SIF
 */
#include <linux/sched.h>
#include <rdma/ib_verbs.h>
#include "sif_tqp.h"
#include "psif_hw_setget.h"
#include "sif_defs.h"

/*
 * This is a host-EPSA mailbox function that is called via ib_post_send()
 * The conditions and assumptions are:-
 * 1. qp_type == IB_QPT_EPSA_TUNNELING.
 * 2. opcode == IB_WR_SEND_WITH_IMM
 * 3. Only receive completion - no send completion will be generated.
 * 4. Only the first wr.sge will be handled.
 * 5. wr.ex.imm_data is the EPSA_N
 */
int sif_epsa_tunneling_post_send(struct ib_qp *ibqp, struct ib_send_wr *wr,
				 struct ib_send_wr **bad_wr)
{
	struct psif_epsc_csr_req req;
	struct psif_epsc_csr_rsp rsp;
	struct sif_dev *sdev = to_sdev(ibqp->device);

	/* The status of the epsa mailbox communication is logged in the received cq: */
	struct sif_cq *cq = to_scq(ibqp->recv_cq);
	struct sif_cq_sw *cq_sw = get_sif_cq_sw(sdev, cq->index);
	volatile struct psif_cq_entry *cqe;
	struct psif_cq_entry lcqe;
	u32 seqno;
	int ret;

	memset(&req, 0, sizeof(req));
	memset(&rsp, 0, sizeof(rsp));

	req.uf = 0;
	req.opcode = EPSC_A_COMMAND;
	req.u.epsa_cmd.cmd = EPSA_GENERIC_CMD;
	req.u.epsa_cmd.length = wr->sg_list[0].length;
	req.u.epsa_cmd.host_addr = wr->sg_list[0].addr;
	req.u.epsa_cmd.key = wr->sg_list[0].lkey;

	if (wr->ex.imm_data > 3) {
		sif_log(sdev, SIF_INFO, "Exit: Fail to post_send a WR");
		return -EINVAL;
	}

	sif_log(sdev, SIF_SND, "len %d host addr addr 0x%llx key 0x%x",
		req.u.epsa_cmd.length, req.u.epsa_cmd.host_addr, key);

	ret = sif_eps_wr(sdev, u32_to_mbox(wr->ex.imm_data), &req, &rsp);

	seqno = cq_sw->next_seq;
	cqe = get_cq_entry(cq, seqno);

	memset(&lcqe, 0, sizeof(lcqe));
	/* construct the required info for WC during poll_cq.
	 * As for now include the wr_id, mailbox status, qp_num, and status:
	 */
	lcqe.seq_num = seqno;
	lcqe.wc_id.rq_id = wr->wr_id;
	lcqe.vendor_err = rsp.status;
	lcqe.qp = ibqp->qp_num;
	lcqe.status = ret == 0 ? PSIF_WC_STATUS_SUCCESS : PSIF_WC_STATUS_GENERAL_ERR;

	copy_conv_to_hw(cqe, &lcqe, sizeof(*cqe));

	return ret;
}
