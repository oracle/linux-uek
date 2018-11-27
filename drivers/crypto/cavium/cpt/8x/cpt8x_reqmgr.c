// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "cpt_reqmgr.h"
#include "cpt8x_vf.h"
#include "cpt8x_reqmgr.h"

inline void fill_cpt_inst(union cpt_inst_s *cptinst,
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

inline int process_ccode(struct pci_dev *pdev, union cpt_res_s *cpt_status,
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
		if (time_after_eq(jiffies,
				  (cpt_info->time_in +
				  (CPT_COMMAND_TIMEOUT * HZ)))) {
			dev_err(&pdev->dev, "Request timed out\n");
		} else if ((ccode == (COMPLETION_CODE_INIT)) &&
			   (cpt_info->extra_time <
			    TIME_IN_RESET_COUNT)) {
			cpt_info->time_in = jiffies;
			cpt_info->extra_time++;
			return 1;
		}
	break;

	case CPT_8X_COMP_E_GOOD:
		/* Check microcode completion code */
		if (ecode.s.ccode) {
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
inline void send_cpt_cmd(union cpt_inst_s *cptinst, u32 db_count, void *obj)
{
	struct cpt_vf *cptvf = (struct cpt_vf *) obj;
	struct command_qinfo *qinfo = &cptvf->cqinfo;
	struct command_queue *queue = &qinfo->queue[0];
	u8 *ent;

	/* lock commad queue */
	spin_lock(&queue->lock);
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
	/* unlock command queue */
	spin_unlock(&queue->lock);
}

inline void send_cpt_cmds_in_batch(union cpt_inst_s *cptinst, u32 num,
				   void *obj)
{
	struct cpt_vf *cptvf = (struct cpt_vf *) obj;
	int i;

	for (i = 0; i < num; i++)
		send_cpt_cmd(&cptinst[i], 0, obj);

	cptvf_write_vq_doorbell(cptvf, num);
}

inline void send_cpt_cmds_for_speed_test(union cpt_inst_s *cptinst, u32 num,
					 void *obj)
{
	send_cpt_cmds_in_batch(cptinst, num, obj);
}

inline int cpt_get_kcrypto_eng_grp_num(struct pci_dev *pdev)
{
	return 0;
}

inline void cptvf_post_process(struct cptvf_wqe *wqe)
{
	process_pending_queue(wqe->cptvf->pdev, &wqe->cptvf->pqinfo.queue[0]);
}

inline int cpt_do_request(struct pci_dev *pdev, struct cpt_request_info *req,
		   int cpu_num)
{
	struct cpt_vf *cptvf = pci_get_drvdata(pdev);

	if (!cpt_device_ready(cptvf)) {
		dev_err(&pdev->dev, "CPT Device is not ready");
		return -ENODEV;
	}

	if ((cptvf->vftype == SE_TYPES) && (!req->ctrl.s.se_req)) {
		dev_err(&pdev->dev, "CPTVF-%d of SE TYPE got AE request",
			cptvf->vfid);
		return -EINVAL;
	} else if ((cptvf->vftype == AE_TYPES) && (req->ctrl.s.se_req)) {
		dev_err(&pdev->dev, "CPTVF-%d of AE TYPE got SE request",
			cptvf->vfid);
		return -EINVAL;
	}

	return process_request(pdev, req, &cptvf->pqinfo.queue[0], cptvf);
}
