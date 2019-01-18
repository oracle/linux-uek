/* SPDX-License-Identifier: GPL-2.0
 * Marvell CPT common code
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

struct reqmgr_ops {
	void (*send_cmd)(union cpt_inst_s *cptinst, u32 val, void *obj);
	void (*fill_inst)(union cpt_inst_s *cptinst,
			  struct cpt_info_buffer *info,
			  struct cpt_iq_command *iq_cmd);
	int (*process_ccode)(struct pci_dev *pdev, union cpt_res_s *cpt_status,
			     struct cpt_info_buffer *cpt_info,
			     struct cpt_request_info *req, u32 *res_code);
};

void process_pending_queue(struct pci_dev *pdev, struct reqmgr_ops *ops,
			   struct pending_queue *pqueue);
int process_request(struct pci_dev *pdev, struct reqmgr_ops *ops,
		    struct cpt_request_info *req,
		    struct pending_queue *pqueue, void *obj);
void dump_sg_list(struct pci_dev *pdev, struct cpt_request_info *req);

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

#endif /* __CPT_REQUEST_MANAGER_H */
