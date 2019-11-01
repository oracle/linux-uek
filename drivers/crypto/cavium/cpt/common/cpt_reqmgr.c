// SPDX-License-Identifier: GPL-2.0
/* Marvell CPT common code
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "cpt_common.h"
#include "cpt_reqmgr.h"

inline void process_pending_queue(struct pci_dev *pdev, struct reqmgr_ops *ops,
				  struct pending_queue *pqueue)
{
	struct pending_entry *resume_pentry = NULL;
	struct cpt_info_buffer *cpt_info = NULL;
	void (*callback)(int, void *, void *);
	struct pending_entry *pentry = NULL;
	struct cpt_request_info *req = NULL;
	union cpt_res_s *cpt_status = NULL;
	struct crypto_async_request *areq;
	u32 res_code, resume_index;

	while (1) {
		spin_lock_bh(&pqueue->lock);
		pentry = &pqueue->head[pqueue->front];

		if (WARN_ON(!pentry)) {
			spin_unlock_bh(&pqueue->lock);
			break;
		}

		res_code = -EINVAL;
		if (unlikely(!pentry->busy)) {
			spin_unlock_bh(&pqueue->lock);
			break;
		}

		if (unlikely(!pentry->callback) ||
		    unlikely(!pentry->areq)) {
			dev_err(&pdev->dev, "Callback or callback arg NULL\n");
			goto process_pentry;
		}

		cpt_info = (struct cpt_info_buffer *) pentry->post_arg;
		if (unlikely(!cpt_info)) {
			dev_err(&pdev->dev, "Pending entry post arg NULL\n");
			goto process_pentry;
		}

		req = cpt_info->req;
		if (unlikely(!req)) {
			dev_err(&pdev->dev, "Request NULL\n");
			goto process_pentry;
		}

		cpt_status = (union cpt_res_s *) pentry->completion_addr;
		if (unlikely(!cpt_status)) {
			dev_err(&pdev->dev, "Completion address NULL\n");
			goto process_pentry;
		}

		/* Process completion code */
		if (!ops->process_ccode) {
			dev_err(&pdev->dev, "Process_ccode pointer is NULL\n");
			goto process_pentry;
		}
		if (ops->process_ccode(pdev, cpt_status, cpt_info, req,
				       &res_code)) {
			spin_unlock_bh(&pqueue->lock);
			return;
		}

process_pentry:
		/*
		 * Check if we should inform sending side to resume
		 * We do it CPT_IQ_RESUME_MARGIN elements in advance before
		 * pending queue becomes empty
		 */
		resume_index = modulo_inc(pqueue->front, pqueue->qlen,
					  CPT_IQ_RESUME_MARGIN);
		resume_pentry = &pqueue->head[resume_index];
		if (resume_pentry &&
		    resume_pentry->resume_sender) {
			resume_pentry->resume_sender = false;
			callback = resume_pentry->callback;
			areq = resume_pentry->areq;

			if (callback && areq) {
				spin_unlock_bh(&pqueue->lock);

				/*
				 * EINPROGRESS is an indication for sending
				 * side that it can resume sending requests
				 */
				callback(-EINPROGRESS, areq, req);
				spin_lock_bh(&pqueue->lock);
			}
		}

		callback = pentry->callback;
		areq = pentry->areq;
		free_pentry(pentry);

		pqueue->pending_count--;
		pqueue->front = modulo_inc(pqueue->front, pqueue->qlen, 1);
		spin_unlock_bh(&pqueue->lock);
		/*
		 * Kernel crypto can reuse/free buffer(s), that's why cleanup
		 * needs to be done before callback.
		 */
		if (cpt_info)
			do_request_cleanup(pdev, cpt_info);
		/*
		 * Call callback after current pending entry has been been
		 * processed we don't do it if the callback pointer or
		 * argument pointer is invalid
		 */
		if (callback && areq)
			callback(res_code, areq, req);
	}
}
EXPORT_SYMBOL_GPL(process_pending_queue);

inline int process_request(struct pci_dev *pdev, struct reqmgr_ops *ops,
			   struct cpt_request_info *req,
			   struct pending_queue *pqueue, void *obj)
{
	struct cptvf_request *cpt_req = &req->req;
	struct cpt_info_buffer *info = NULL;
	struct pending_entry *pentry = NULL;
	union ctrl_info *ctrl = &req->ctrl;
	union cpt_res_s *result = NULL;
	struct cpt_iq_command iq_cmd;
	union cpt_inst_s cptinst;
	int retry, ret = 0;
	u8 resume_sender;
	gfp_t gfp;

	if (!ops->fill_inst ||
	    !ops->send_cmd)
		return -EFAULT;

	gfp = (req->areq->flags & CRYPTO_TFM_REQ_MAY_SLEEP) ? GFP_KERNEL :
							      GFP_ATOMIC;
	info = kzalloc(sizeof(*info), gfp);
	if (unlikely(!info)) {
		dev_err(&pdev->dev, "Memory allocation failed\n");
		return -ENOMEM;
	}

	ret = setup_sgio_list(pdev, info, req, gfp);
	if (unlikely(ret)) {
		dev_err(&pdev->dev, "Setting up SG list failed");
		goto request_cleanup;
	}
	cpt_req->dlen = info->dlen;

	/*
	 * Get buffer for union cpt_res_s response
	 * structure and its physical address
	 */
	info->completion_addr = kzalloc(sizeof(union cpt_res_s), gfp);
	if (unlikely(!info->completion_addr)) {
		dev_err(&pdev->dev, "memory allocation failed\n");
		goto request_cleanup;
	}

	result = (union cpt_res_s *) info->completion_addr;
	result->s9x.compcode = COMPLETION_CODE_INIT;
	info->comp_baddr = dma_map_single(&pdev->dev,
					  (void *) info->completion_addr,
					  sizeof(union cpt_res_s),
					  DMA_BIDIRECTIONAL);
	if (unlikely(dma_mapping_error(&pdev->dev, info->comp_baddr))) {
		dev_err(&pdev->dev, "Dma mapping failed\n");
		ret = -EFAULT;
		goto request_cleanup;
	}

	spin_lock_bh(&pqueue->lock);
	pentry = get_free_pending_entry(pqueue, pqueue->qlen);
	retry = CPT_PENTRY_TIMEOUT / CPT_PENTRY_STEP;
	while (unlikely(!pentry) && retry--) {
		spin_unlock_bh(&pqueue->lock);
		udelay(CPT_PENTRY_STEP);
		spin_lock_bh(&pqueue->lock);
		pentry = get_free_pending_entry(pqueue, pqueue->qlen);
	}

	if (unlikely(!pentry)) {
		ret = -ENOSPC;
		spin_unlock_bh(&pqueue->lock);
		goto request_cleanup;
	}

	/*
	 * Check if we are close to filling in entire pending queue,
	 * if so then tell the sender to stop/sleep by returning -EBUSY
	 * We do it only for context which can sleep (GFP_KERNEL)
	 */
	if (gfp == GFP_KERNEL &&
	    pqueue->pending_count > (pqueue->qlen - CPT_IQ_STOP_MARGIN)) {
		pentry->resume_sender = true;
	} else
		pentry->resume_sender = false;
	resume_sender = pentry->resume_sender;
	pqueue->pending_count++;

	pentry->completion_addr = info->completion_addr;
	pentry->post_arg = (void *) info;
	pentry->callback = req->callback;
	pentry->areq = req->areq;
	pentry->busy = true;
	info->pentry = pentry;
	info->time_in = jiffies;
	info->req = req;

	/* Fill in the command */
	iq_cmd.cmd.u64 = 0;
	iq_cmd.cmd.s.opcode = cpu_to_be16(cpt_req->opcode.flags);
	iq_cmd.cmd.s.param1 = cpu_to_be16(cpt_req->param1);
	iq_cmd.cmd.s.param2 = cpu_to_be16(cpt_req->param2);
	iq_cmd.cmd.s.dlen   = cpu_to_be16(cpt_req->dlen);

	/* 64-bit swap for microcode data reads, not needed for addresses*/
	iq_cmd.cmd.u64 = cpu_to_be64(iq_cmd.cmd.u64);
	iq_cmd.dptr = info->dptr_baddr;
	iq_cmd.rptr = info->rptr_baddr;
	iq_cmd.cptr.u64 = 0;
	iq_cmd.cptr.s.grp = ctrl->s.grp;

	/* Fill in the CPT_INST_S type command for HW interpretation */
	ops->fill_inst(&cptinst, info, &iq_cmd);

	/* Print debug info if enabled */
	dump_sg_list(pdev, req);
	pr_debug("Cpt_inst_s hexdump (%d bytes)\n", CPT_INST_SIZE);
	print_hex_dump_debug("", 0, 16, 1, &cptinst, CPT_INST_SIZE, false);
	pr_debug("Dptr hexdump (%d bytes)\n", cpt_req->dlen);
	print_hex_dump_debug("", 0, 16, 1, info->in_buffer,
			     cpt_req->dlen, false);

	/* Send CPT command */
	ops->send_cmd(&cptinst, 1, obj);

	/*
	 * We allocate and prepare pending queue entry in critical section
	 * together with submitting CPT instruction to CPT instruction queue
	 * to make sure that order of CPT requests is the same in both
	 * pending and instruction queues
	 */
	spin_unlock_bh(&pqueue->lock);

	ret = resume_sender ? -EBUSY : -EINPROGRESS;
	return ret;

request_cleanup:
	do_request_cleanup(pdev, info);
	return ret;
}
EXPORT_SYMBOL_GPL(process_request);

void dump_sg_list(struct pci_dev *pdev, struct cpt_request_info *req)
{
	int i;

	pr_debug("Gather list size %d\n", req->incnt);
	for (i = 0; i < req->incnt; i++) {
		pr_debug("Buffer %d size %d, vptr 0x%p, dmaptr 0x%p\n", i,
			 req->in[i].size, req->in[i].vptr,
			 (void *) req->in[i].dma_addr);
		pr_debug("Buffer hexdump (%d bytes)\n",
			 req->in[i].size);
		print_hex_dump_debug("", DUMP_PREFIX_NONE, 16, 1,
				     req->in[i].vptr, req->in[i].size, false);
	}

	pr_debug("Scatter list size %d\n", req->outcnt);
	for (i = 0; i < req->outcnt; i++) {
		pr_debug("Buffer %d size %d, vptr 0x%p, dmaptr 0x%p\n", i,
			 req->out[i].size, req->out[i].vptr,
			 (void *) req->out[i].dma_addr);
		pr_debug("Buffer hexdump (%d bytes)\n", req->out[i].size);
		print_hex_dump_debug("", DUMP_PREFIX_NONE, 16, 1,
				     req->out[i].vptr, req->out[i].size, false);
	}
}
EXPORT_SYMBOL_GPL(dump_sg_list);

