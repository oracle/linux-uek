// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "cpt8x_vf.h"
#include "cpt_algs.h"

static void cpt8x_send_cmds_for_speed_test(union cpt_inst_s *cptinst, u32 num,
				    void *obj) __attribute__((unused));

static void cpt8x_fill_inst(union cpt_inst_s *cptinst,
			    struct cpt_info_buffer *info,
			    struct cpt_iq_command *iq_cmd)
{
	cptinst->u[0] = 0x0;
	cptinst->s8x.doneint = true;
	cptinst->s8x.res_addr = (u64)info->comp_baddr;
	cptinst->u[2] = 0x0;
	cptinst->s8x.wq_ptr = 0;
	cptinst->s8x.ei0 = iq_cmd->cmd.u64;
	cptinst->s8x.ei1 = iq_cmd->dptr;
	cptinst->s8x.ei2 = iq_cmd->rptr;
	cptinst->s8x.ei3 = iq_cmd->cptr.u64;
}

static int cpt8x_process_ccode(struct pci_dev *pdev,
			       union cpt_res_s *cpt_status,
			       struct cpt_info_buffer *cpt_info,
			       struct cpt_request_info *req, u32 *res_code)
{
	u8 ccode = cpt_status->s8x.compcode;
	union error_code ecode;

	ecode.u = be64_to_cpu(*((u64 *) cpt_info->out_buffer));
	switch (ccode) {
	case CPT_8X_COMP_E_FAULT:
		dev_err(&pdev->dev,
			"Request failed with DMA fault\n");
		dump_sg_list(pdev, req);
	break;

	case CPT_8X_COMP_E_SWERR:
		dev_err(&pdev->dev,
			"Request failed with software error code %d\n",
			ecode.s.ccode);
		dump_sg_list(pdev, req);
	break;

	case CPT_8X_COMP_E_HWERR:
		dev_err(&pdev->dev,
			"Request failed with hardware error\n");
		dump_sg_list(pdev, req);
	break;

	case COMPLETION_CODE_INIT:
		/* check for timeout */
		if (time_after_eq(jiffies, cpt_info->time_in +
				  CPT_COMMAND_TIMEOUT * HZ))
			dev_warn(&pdev->dev, "Request timed out 0x%p", req);
		else if (cpt_info->extra_time < TIME_IN_RESET_COUNT) {
			cpt_info->time_in = jiffies;
			cpt_info->extra_time++;
		}
		return 1;
	break;

	case CPT_8X_COMP_E_GOOD:
		/* Check microcode completion code */
		if (ecode.s.ccode) {
			/* If requested hmac is truncated and ucode returns
			 * s/g write length error then we report success
			 * because ucode writes as many bytes of calculated
			 * hmac as available in gather buffer and reports
			 * s/g write length error if number of bytes in gather
			 * buffer is less than full hmac size.
			 */
			if (req->is_trunc_hmac &&
			    ecode.s.ccode == ERR_SCATTER_GATHER_WRITE_LENGTH) {
				*res_code = 0;
				break;
			}

			dev_err(&pdev->dev,
				"Request failed with software error code 0x%x\n",
				ecode.s.ccode);
			dump_sg_list(pdev, req);
			break;
		}

		/* Request has been processed with success */
		*res_code = 0;
	break;

	default:
		dev_err(&pdev->dev, "Request returned invalid status\n");
	break;
	}

	return 0;
}

/*
 * On 8X platform the parameter db_count is used as a count for ringing
 * door bell. The valid values for db_count are:
 * 0 - 1 CPT instruction will be enqueued however CPT will not be informed
 * 1 - 1 CPT instruction will be enqueued and CPT will be informed
 */
static void cpt8x_send_cmd(union cpt_inst_s *cptinst, u32 db_count, void *obj)
{
	struct cpt_vf *cptvf = (struct cpt_vf *) obj;
	struct command_qinfo *qinfo = &cptvf->cqinfo;
	struct command_queue *queue = &qinfo->queue[0];
	u8 *ent;

	/*
	 * cpt8x_send_cmd is currently called only from critical section
	 * therefore no locking is required for accessing instruction queue
	 */
	ent = &queue->qhead->head[queue->idx * qinfo->cmd_size];
	memcpy(ent, (void *) cptinst, qinfo->cmd_size);

	if (++queue->idx >= queue->qhead->size / 64) {
		struct command_chunk *curr = queue->qhead;

		if (list_is_last(&curr->nextchunk, &queue->chead))
			queue->qhead = queue->base;
		else
			queue->qhead = list_next_entry(queue->qhead, nextchunk);
		queue->idx = 0;
	}
	/* make sure all memory stores are done before ringing doorbell */
	smp_wmb();
	cptvf_write_vq_doorbell(cptvf, db_count);
}

static void cpt8x_send_cmds_in_batch(union cpt_inst_s *cptinst,
						u32 num, void *obj)
{
	struct cpt_vf *cptvf = (struct cpt_vf *) obj;
	int i;

	for (i = 0; i < num; i++)
		cpt8x_send_cmd(&cptinst[i], 0, obj);

	cptvf_write_vq_doorbell(cptvf, num);
}

static void cpt8x_send_cmds_for_speed_test(union cpt_inst_s *cptinst, u32 num,
				    void *obj)
{
	cpt8x_send_cmds_in_batch(cptinst, num, obj);
}

void cpt8x_post_process(struct cptvf_wqe *wqe)
{
	process_pending_queue(wqe->cptvf->pdev, &wqe->cptvf->ops,
			      &wqe->cptvf->pqinfo.queue[0]);
}

struct reqmgr_ops cpt8x_get_reqmgr_ops(void)
{
	struct reqmgr_ops ops;

	ops.fill_inst = cpt8x_fill_inst;
	ops.process_ccode = cpt8x_process_ccode;
	ops.send_cmd = cpt8x_send_cmd;

	return ops;
}
