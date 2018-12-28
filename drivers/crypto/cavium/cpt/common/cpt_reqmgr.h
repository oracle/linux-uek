// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 RVU Admin Function driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CPT_REQUEST_MANAGER_H
#define __CPT_REQUEST_MANAGER_H

#include <linux/delay.h>
#include <linux/crypto.h>
#include "cpt_hw_types.h"

void send_cpt_cmd(union cpt_inst_s *cptinst, u32 val, void *obj);
void send_cpt_cmds_in_batch(union cpt_inst_s *cptinst, u32 num, void *obj);
void send_cpt_cmds_for_speed_test(union cpt_inst_s *cptinst, u32 num,
				  void *obj);
void dump_sg_list(struct pci_dev *pdev, struct cpt_request_info *req);
void fill_cpt_inst(union cpt_inst_s *cptinst, struct cpt_info_buffer *info,
		   struct cpt_iq_command *iq_cmd);
int process_ccode(struct pci_dev *pdev, union cpt_res_s *cpt_status,
		  struct cpt_info_buffer *cpt_info,
		  struct cpt_request_info *req, u32 *res_code);
static inline
struct pending_entry *get_free_pending_entry(struct pending_queue *q, int qlen)
{
	struct pending_entry *ent = NULL;

	ent = &q->head[q->rear];
	if (unlikely(ent->busy)) {
		ent = NULL;
		goto no_free_entry;
	}

	q->rear++;
	if (unlikely(q->rear == qlen))
		q->rear = 0;

no_free_entry:
	return ent;
}

static inline u32 modulo_inc(u32 index, u32 length, u32 inc)
{
	if (WARN_ON(inc > length))
		inc = length;

	index += inc;
	if (unlikely(index >= length))
		index -= length;

	return index;
}

static inline void free_pentry(struct pending_entry *pentry)
{
	pentry->completion_addr = NULL;
	pentry->post_arg = NULL;
	pentry->callback = NULL;
	pentry->areq = NULL;
	pentry->resume_sender = false;
	pentry->busy = false;
}

static inline int setup_sgio_components(struct pci_dev *pdev,
					struct buf_ptr *list,
					int buf_count, u8 *buffer)
{
	struct sglist_component *sg_ptr = NULL;
	int ret = 0, i, j;
	int components;

	if (unlikely(!list)) {
		dev_err(&pdev->dev, "Input list pointer is NULL\n");
		return -EFAULT;
	}

	for (i = 0; i < buf_count; i++) {
		if (likely(list[i].vptr)) {
			list[i].dma_addr = dma_map_single(&pdev->dev,
							  list[i].vptr,
							  list[i].size,
							  DMA_BIDIRECTIONAL);
			if (unlikely(dma_mapping_error(&pdev->dev,
						       list[i].dma_addr))) {
				dev_err(&pdev->dev, "Dma mapping failed\n");
				ret = -EIO;
				goto sg_cleanup;
			}
		}
	}

	components = buf_count / 4;
	sg_ptr = (struct sglist_component *)buffer;
	for (i = 0; i < components; i++) {
		sg_ptr->u.s.len0 = cpu_to_be16(list[i * 4 + 0].size);
		sg_ptr->u.s.len1 = cpu_to_be16(list[i * 4 + 1].size);
		sg_ptr->u.s.len2 = cpu_to_be16(list[i * 4 + 2].size);
		sg_ptr->u.s.len3 = cpu_to_be16(list[i * 4 + 3].size);
		sg_ptr->ptr0 = cpu_to_be64(list[i * 4 + 0].dma_addr);
		sg_ptr->ptr1 = cpu_to_be64(list[i * 4 + 1].dma_addr);
		sg_ptr->ptr2 = cpu_to_be64(list[i * 4 + 2].dma_addr);
		sg_ptr->ptr3 = cpu_to_be64(list[i * 4 + 3].dma_addr);
		sg_ptr++;
	}
	components = buf_count % 4;

	switch (components) {
	case 3:
		sg_ptr->u.s.len2 = cpu_to_be16(list[i * 4 + 2].size);
		sg_ptr->ptr2 = cpu_to_be64(list[i * 4 + 2].dma_addr);
		/* Fall through */
	case 2:
		sg_ptr->u.s.len1 = cpu_to_be16(list[i * 4 + 1].size);
		sg_ptr->ptr1 = cpu_to_be64(list[i * 4 + 1].dma_addr);
		/* Fall through */
	case 1:
		sg_ptr->u.s.len0 = cpu_to_be16(list[i * 4 + 0].size);
		sg_ptr->ptr0 = cpu_to_be64(list[i * 4 + 0].dma_addr);
		break;
	default:
		break;
	}

	return ret;

sg_cleanup:
	for (j = 0; j < i; j++) {
		if (list[j].dma_addr) {
			dma_unmap_single(&pdev->dev, list[i].dma_addr,
					 list[i].size, DMA_BIDIRECTIONAL);
		}

		list[j].dma_addr = 0;
	}

	return ret;
}

static inline int setup_sgio_list(struct pci_dev *pdev,
				  struct cpt_info_buffer *info,
				  struct cpt_request_info *req, gfp_t gfp)
{
	u16 g_sz_bytes = 0, s_sz_bytes = 0;
	int ret = 0;

	if (unlikely(req->incnt > MAX_SG_IN_CNT ||
		     req->outcnt > MAX_SG_OUT_CNT)) {
		dev_err(&pdev->dev, "Error too many sg components\n");
		ret = -EINVAL;
		goto  scatter_gather_clean;
	}

	/* Setup gather (input) components */
	g_sz_bytes = ((req->incnt + 3) / 4) * sizeof(struct sglist_component);
	info->gather_components = kzalloc(g_sz_bytes, gfp);
	if (unlikely(!info->gather_components)) {
		dev_err(&pdev->dev, "Memory allocation failed\n");
		ret = -ENOMEM;
		goto  scatter_gather_clean;
	}

	ret = setup_sgio_components(pdev, req->in, req->incnt,
				    info->gather_components);
	if (unlikely(ret)) {
		dev_err(&pdev->dev, "Failed to setup gather list\n");
		ret = -EFAULT;
		goto  scatter_gather_clean;
	}

	/* Setup scatter (output) components */
	s_sz_bytes = ((req->outcnt + 3) / 4) * sizeof(struct sglist_component);
	info->scatter_components = kzalloc(s_sz_bytes, gfp);
	if (unlikely(!info->scatter_components)) {
		dev_err(&pdev->dev, "Memory allocation failed\n");
		ret = -ENOMEM;
		goto  scatter_gather_clean;
	}

	ret = setup_sgio_components(pdev, req->out, req->outcnt,
				    info->scatter_components);
	if (unlikely(ret)) {
		dev_err(&pdev->dev, "Failed to setup scatter list\n");
		ret = -EFAULT;
		goto  scatter_gather_clean;
	}

	/* Create and initialize DPTR */
	info->dlen = g_sz_bytes + s_sz_bytes + SG_LIST_HDR_SIZE;
	info->in_buffer = kzalloc(info->dlen, gfp);
	if (unlikely(!info->in_buffer)) {
		dev_err(&pdev->dev, "Memory allocation failed\n");
		ret = -ENOMEM;
		goto  scatter_gather_clean;
	}

	((u16 *)info->in_buffer)[0] = req->outcnt;
	((u16 *)info->in_buffer)[1] = req->incnt;
	((u16 *)info->in_buffer)[2] = 0;
	((u16 *)info->in_buffer)[3] = 0;
	*(u64 *)info->in_buffer = cpu_to_be64p((u64 *)info->in_buffer);

	memcpy(&info->in_buffer[8], info->gather_components, g_sz_bytes);
	memcpy(&info->in_buffer[8 + g_sz_bytes], info->scatter_components,
	       s_sz_bytes);
	info->dptr_baddr = dma_map_single(&pdev->dev,
					  (void *)info->in_buffer,
					  info->dlen,
					  DMA_BIDIRECTIONAL);
	if (unlikely(dma_mapping_error(&pdev->dev, info->dptr_baddr))) {
		dev_err(&pdev->dev, "Mapping dptr failed %d\n", info->dlen);
		ret = -EIO;
		goto  scatter_gather_clean;
	}

	/* Create and initialize RPTR */
	info->out_buffer = kzalloc(COMPLETION_CODE_SIZE, gfp);
	if (unlikely(!info->out_buffer)) {
		dev_err(&pdev->dev, "Memory allocation failed\n");
		ret = -ENOMEM;
		goto scatter_gather_clean;
	}

	*((u64 *) info->out_buffer) = ~((u64) COMPLETION_CODE_INIT);
	info->rptr_baddr = dma_map_single(&pdev->dev,
					  (void *)info->out_buffer,
					  COMPLETION_CODE_SIZE,
					  DMA_BIDIRECTIONAL);
	if (unlikely(dma_mapping_error(&pdev->dev, info->rptr_baddr))) {
		dev_err(&pdev->dev, "Mapping rptr failed %d\n",
			COMPLETION_CODE_SIZE);
		ret = -EIO;
		goto  scatter_gather_clean;
	}

	return 0;

scatter_gather_clean:
	return ret;
}

static inline void do_request_cleanup(struct pci_dev *pdev,
				      struct cpt_info_buffer *info)
{
	struct cpt_request_info *req;
	int i;

	if (info->dptr_baddr)
		dma_unmap_single(&pdev->dev, info->dptr_baddr,
				 info->dlen, DMA_BIDIRECTIONAL);

	if (info->rptr_baddr)
		dma_unmap_single(&pdev->dev, info->rptr_baddr,
				 COMPLETION_CODE_SIZE, DMA_BIDIRECTIONAL);

	if (info->comp_baddr)
		dma_unmap_single(&pdev->dev, info->comp_baddr,
				 sizeof(union cpt_res_s), DMA_BIDIRECTIONAL);

	if (info->req) {
		req = info->req;
		for (i = 0; i < req->outcnt; i++) {
			if (req->out[i].dma_addr)
				dma_unmap_single(&pdev->dev,
						 req->out[i].dma_addr,
						 req->out[i].size,
						 DMA_BIDIRECTIONAL);
		}

		for (i = 0; i < req->incnt; i++) {
			if (req->in[i].dma_addr)
				dma_unmap_single(&pdev->dev,
						 req->in[i].dma_addr,
						 req->in[i].size,
						 DMA_BIDIRECTIONAL);
		}
	}

	if (info->scatter_components)
		kzfree(info->scatter_components);

	if (info->gather_components)
		kzfree(info->gather_components);

	if (info->out_buffer)
		kzfree(info->out_buffer);

	if (info->in_buffer)
		kzfree(info->in_buffer);

	if (info->completion_addr)
		kzfree((void *)info->completion_addr);

	kzfree(info);
}

static inline void process_pending_queue(struct pci_dev *pdev,
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
		if (process_ccode(pdev, cpt_status, cpt_info, req,
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
		 * Call callback after current pending entry has been been
		 * processed we don't do it if the callback pointer or
		 * argument pointer is invalid
		 */
		if (callback && areq)
			callback(res_code, areq, req);

		if (cpt_info)
			do_request_cleanup(pdev, cpt_info);
	}
}

static inline int process_request(struct pci_dev *pdev,
				  struct cpt_request_info *req,
				  struct pending_queue *pqueue,
				  void *obj)
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
	}
	else
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
	spin_unlock_bh(&pqueue->lock);

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
	fill_cpt_inst(&cptinst, info, &iq_cmd);

	/* Print debug info if enabled */
	if (cpt_is_dbg_level_en(CPT_DBG_ENC_DEC_REQS)) {
		dump_sg_list(pdev, req);
		dev_info(&pdev->dev, "Cpt_inst_s hexdump (%d bytes)\n",
			 CPT_INST_SIZE);
		print_hex_dump(KERN_INFO, "", 0, 16, 1, &cptinst,
			       CPT_INST_SIZE, false);
		dev_info(&pdev->dev, "Dptr hexdump (%d bytes)\n",
			 cpt_req->dlen);
		print_hex_dump(KERN_INFO, "", 0, 16, 1, info->in_buffer,
			       cpt_req->dlen, false);
	}

	/* Send CPT command */
	send_cpt_cmd(&cptinst, 1, obj);

	ret = resume_sender ? -EBUSY : -EINPROGRESS;
	return ret;

request_cleanup:
	do_request_cleanup(pdev, info);
	return ret;
}

#endif /* __CPT_REQUEST_MANAGER_H */
