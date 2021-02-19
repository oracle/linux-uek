// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2020 Marvell. */

#include "cn10k_cptvf.h"
#include "cn10k_cptvf_algs.h"
#include "cn10k_cpt_mbox_common.h"

/* SG list header size in bytes */
#define SG_LIST_HDR_SIZE	8

/* Default timeout when waiting for free pending entry in us */
#define CPT_PENTRY_TIMEOUT	1000
#define CPT_PENTRY_STEP		50

/* Default threshold for stopping and resuming sender requests */
#define CPT_IQ_STOP_MARGIN	128
#define CPT_IQ_RESUME_MARGIN	512

/* Default command timeout in seconds */
#define CPT_COMMAND_TIMEOUT	4
#define CPT_TIME_IN_RESET_COUNT 5

static void cn10k_cpt_dump_sg_list(struct pci_dev *pdev,
				  struct cn10k_cpt_req_info *req)
{
	int i;

	pr_debug("Gather list size %d\n", req->in_cnt);
	for (i = 0; i < req->in_cnt; i++) {
		pr_debug("Buffer %d size %d, vptr 0x%p, dmaptr 0x%p\n", i,
			 req->in[i].size, req->in[i].vptr,
			 (void *) req->in[i].dma_addr);
		pr_debug("Buffer hexdump (%d bytes)\n",
			 req->in[i].size);
		print_hex_dump_debug("", DUMP_PREFIX_NONE, 16, 1,
				     req->in[i].vptr, req->in[i].size, false);
	}

	pr_debug("Scatter list size %d\n", req->out_cnt);
	for (i = 0; i < req->out_cnt; i++) {
		pr_debug("Buffer %d size %d, vptr 0x%p, dmaptr 0x%p\n", i,
			 req->out[i].size, req->out[i].vptr,
			 (void *) req->out[i].dma_addr);
		pr_debug("Buffer hexdump (%d bytes)\n", req->out[i].size);
		print_hex_dump_debug("", DUMP_PREFIX_NONE, 16, 1,
				     req->out[i].vptr, req->out[i].size, false);
	}
}

static inline struct cn10k_cpt_pending_entry *get_free_pending_entry(
					struct cn10k_cpt_pending_queue *q,
					int qlen)
{
	struct cn10k_cpt_pending_entry *ent = NULL;

	ent = &q->head[q->rear];
	if (unlikely(ent->busy))
		return NULL;

	q->rear++;
	if (unlikely(q->rear == qlen))
		q->rear = 0;

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

static inline void free_pentry(struct cn10k_cpt_pending_entry *pentry)
{
	pentry->completion_addr = NULL;
	pentry->info = NULL;
	pentry->callback = NULL;
	pentry->areq = NULL;
	pentry->resume_sender = false;
	pentry->busy = false;
}

static inline int setup_sgio_components(struct pci_dev *pdev,
					struct cn10k_cpt_buf_ptr *list,
					int buf_count, u8 *buffer)
{
	struct cn10k_cpt_sglist_component *sg_ptr = NULL;
	int ret = 0, i, j;
	int components;

	if (unlikely(!list)) {
		dev_err(&pdev->dev, "Input list pointer is NULL\n");
		return -EFAULT;
	}

	for (i = 0; i < buf_count; i++) {
		if (unlikely(!list[i].vptr))
			continue;
		list[i].dma_addr = dma_map_single(&pdev->dev, list[i].vptr,
						  list[i].size,
						  DMA_BIDIRECTIONAL);
		if (unlikely(dma_mapping_error(&pdev->dev, list[i].dma_addr))) {
			dev_err(&pdev->dev, "Dma mapping failed\n");
			ret = -EIO;
			goto sg_cleanup;
		}
	}
	components = buf_count / 4;
	sg_ptr = (struct cn10k_cpt_sglist_component *)buffer;
	for (i = 0; i < components; i++) {
		sg_ptr->len0 = cpu_to_be16(list[i * 4 + 0].size);
		sg_ptr->len1 = cpu_to_be16(list[i * 4 + 1].size);
		sg_ptr->len2 = cpu_to_be16(list[i * 4 + 2].size);
		sg_ptr->len3 = cpu_to_be16(list[i * 4 + 3].size);
		sg_ptr->ptr0 = cpu_to_be64(list[i * 4 + 0].dma_addr);
		sg_ptr->ptr1 = cpu_to_be64(list[i * 4 + 1].dma_addr);
		sg_ptr->ptr2 = cpu_to_be64(list[i * 4 + 2].dma_addr);
		sg_ptr->ptr3 = cpu_to_be64(list[i * 4 + 3].dma_addr);
		sg_ptr++;
	}
	components = buf_count % 4;

	switch (components) {
	case 3:
		sg_ptr->len2 = cpu_to_be16(list[i * 4 + 2].size);
		sg_ptr->ptr2 = cpu_to_be64(list[i * 4 + 2].dma_addr);
		fallthrough;
	case 2:
		sg_ptr->len1 = cpu_to_be16(list[i * 4 + 1].size);
		sg_ptr->ptr1 = cpu_to_be64(list[i * 4 + 1].dma_addr);
		fallthrough;
	case 1:
		sg_ptr->len0 = cpu_to_be16(list[i * 4 + 0].size);
		sg_ptr->ptr0 = cpu_to_be64(list[i * 4 + 0].dma_addr);
		break;
	default:
		break;
	}
	return ret;

sg_cleanup:
	for (j = 0; j < i; j++) {
		if (list[j].dma_addr) {
			dma_unmap_single(&pdev->dev, list[j].dma_addr,
					 list[j].size, DMA_BIDIRECTIONAL);
		}

		list[j].dma_addr = 0;
	}
	return ret;
}

static inline struct cn10k_cpt_inst_info *info_create(struct pci_dev *pdev,
					      struct cn10k_cpt_req_info *req,
					      gfp_t gfp)
{
	int align = CN10K_CPT_DMA_MINALIGN;
	struct cn10k_cpt_inst_info *info;
	u32 dlen, align_dlen, info_len;
	u16 g_sz_bytes, s_sz_bytes;
	u32 total_mem_len;

	if (unlikely(req->in_cnt > CN10K_CPT_MAX_SG_IN_CNT ||
		     req->out_cnt > CN10K_CPT_MAX_SG_OUT_CNT)) {
		dev_err(&pdev->dev, "Error too many sg components\n");
		return NULL;
	}

	g_sz_bytes = ((req->in_cnt + 3) / 4) *
		      sizeof(struct cn10k_cpt_sglist_component);
	s_sz_bytes = ((req->out_cnt + 3) / 4) *
		      sizeof(struct cn10k_cpt_sglist_component);

	dlen = g_sz_bytes + s_sz_bytes + SG_LIST_HDR_SIZE;
	align_dlen = ALIGN(dlen, align);
	info_len = ALIGN(sizeof(*info), align);
	total_mem_len = align_dlen + info_len + sizeof(union cn10k_cpt_res_s);

	info = kzalloc(total_mem_len, gfp);
	if (unlikely(!info))
		return NULL;

	info->dlen = dlen;
	info->in_buffer = (u8 *)info + info_len;

	((u16 *)info->in_buffer)[0] = req->out_cnt;
	((u16 *)info->in_buffer)[1] = req->in_cnt;
	((u16 *)info->in_buffer)[2] = 0;
	((u16 *)info->in_buffer)[3] = 0;
	cpu_to_be64s((u64 *)info->in_buffer);

	/* Setup gather (input) components */
	if (setup_sgio_components(pdev, req->in, req->in_cnt,
				  &info->in_buffer[8])) {
		dev_err(&pdev->dev, "Failed to setup gather list\n");
		goto destroy_info;
	}

	if (setup_sgio_components(pdev, req->out, req->out_cnt,
				  &info->in_buffer[8 + g_sz_bytes])) {
		dev_err(&pdev->dev, "Failed to setup scatter list\n");
		goto destroy_info;
	}

	info->dma_len = total_mem_len - info_len;
	info->dptr_baddr = dma_map_single(&pdev->dev, info->in_buffer,
					  info->dma_len, DMA_BIDIRECTIONAL);
	if (unlikely(dma_mapping_error(&pdev->dev, info->dptr_baddr))) {
		dev_err(&pdev->dev, "DMA Mapping failed for cpt req\n");
		goto destroy_info;
	}
	/*
	 * Get buffer for union cn10k_cpt_res_s response
	 * structure and its physical address
	 */
	info->completion_addr = info->in_buffer + align_dlen;
	info->comp_baddr = info->dptr_baddr + align_dlen;

	return info;
destroy_info:
	cn10k_cpt_info_destroy(pdev, info);
	return NULL;
}

static int process_request(struct pci_dev *pdev, struct cn10k_cpt_req_info *req,
			   struct cn10k_cpt_pending_queue *pqueue,
			   struct cn10k_cptlf_info *lf)
{
	struct cn10k_cptvf_request *cpt_req = &req->req;
	struct cn10k_cpt_pending_entry *pentry = NULL;
	union cn10k_cpt_ctrl_info *ctrl = &req->ctrl;
	struct cn10k_cpt_inst_info *info = NULL;
	union cn10k_cpt_res_s *result = NULL;
	struct cn10k_cpt_iq_command iq_cmd;
	union cn10k_cpt_inst_s cptinst;
	int retry, ret = 0;
	u8 resume_sender;
	gfp_t gfp;

	gfp = (req->areq->flags & CRYPTO_TFM_REQ_MAY_SLEEP) ? GFP_KERNEL :
							      GFP_ATOMIC;
	if (unlikely(!cn10k_cptlf_started(lf->lfs)))
		return -ENODEV;

	info = info_create(pdev, req, gfp);
	if (unlikely(!info)) {
		dev_err(&pdev->dev, "Setting up cpt inst info failed");
		return -ENOMEM;
	}
	cpt_req->dlen = info->dlen;

	result = info->completion_addr;
	result->s.compcode = CN10K_CPT_COMPLETION_CODE_INIT;

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
		goto destroy_info;
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
	pentry->info = info;
	pentry->callback = req->callback;
	pentry->areq = req->areq;
	pentry->busy = true;
	info->pentry = pentry;
	info->time_in = jiffies;
	info->req = req;

	/* Fill in the command */
	iq_cmd.cmd.u = 0;
	iq_cmd.cmd.s.opcode = cpu_to_be16(cpt_req->opcode.flags);
	iq_cmd.cmd.s.param1 = cpu_to_be16(cpt_req->param1);
	iq_cmd.cmd.s.param2 = cpu_to_be16(cpt_req->param2);
	iq_cmd.cmd.s.dlen   = cpu_to_be16(cpt_req->dlen);

	/* 64-bit swap for microcode data reads, not needed for addresses*/
	cpu_to_be64s(&iq_cmd.cmd.u);
	iq_cmd.dptr = info->dptr_baddr;
	iq_cmd.rptr = 0;
	iq_cmd.cptr.u = 0;
	iq_cmd.cptr.s.grp = ctrl->s.grp;

	/* Fill in the CPT_INST_S type command for HW interpretation */
	cn10k_cpt_fill_inst(&cptinst, &iq_cmd, info->comp_baddr);

	/* Print debug info if enabled */
	cn10k_cpt_dump_sg_list(pdev, req);
	pr_debug("Cpt_inst_s hexdump (%d bytes)\n", CN10K_CPT_INST_SIZE);
	print_hex_dump_debug("", 0, 16, 1, &cptinst, CN10K_CPT_INST_SIZE,
			     false);
	pr_debug("Dptr hexdump (%d bytes)\n", cpt_req->dlen);
	print_hex_dump_debug("", 0, 16, 1, info->in_buffer,
			     cpt_req->dlen, false);

	/* Send CPT command */
	cn10k_cpt_send_cmd(&cptinst, 1, lf);

	/*
	 * We allocate and prepare pending queue entry in critical section
	 * together with submitting CPT instruction to CPT instruction queue
	 * to make sure that order of CPT requests is the same in both
	 * pending and instruction queues
	 */
	spin_unlock_bh(&pqueue->lock);

	ret = resume_sender ? -EBUSY : -EINPROGRESS;
	return ret;
destroy_info:
	spin_unlock_bh(&pqueue->lock);
	cn10k_cpt_info_destroy(pdev, info);
	return ret;
}

int cn10k_cpt_get_kcrypto_eng_grp_num(struct pci_dev *pdev)
{
	struct cn10k_cptlfs_info *lfs = cn10k_cpt_get_lfs_info(pdev);

	return lfs->kcrypto_eng_grp_num;
}

int cn10k_cpt_do_request(struct pci_dev *pdev, struct cn10k_cpt_req_info *req,
			 int cpu_num)
{
	struct cn10k_cptlfs_info *lfs = cn10k_cpt_get_lfs_info(pdev);

	return process_request(pdev, req, &lfs->lf[cpu_num].pqueue,
			       &lfs->lf[cpu_num]);
}

static int cpt_process_ccode(struct pci_dev *pdev,
			     union cn10k_cpt_res_s *cpt_status,
			     struct cn10k_cpt_inst_info *info,
			     u32 *res_code)
{
	u8 uc_ccode = cpt_status->s.uc_compcode;
	u8 ccode = cpt_status->s.compcode;

	switch (ccode) {
	case CN10K_CPT_COMP_E_FAULT:
		dev_err(&pdev->dev,
			"Request failed with DMA fault\n");
		cn10k_cpt_dump_sg_list(pdev, info->req);
		break;

	case CN10K_CPT_COMP_E_HWERR:
		dev_err(&pdev->dev,
			"Request failed with hardware error\n");
		cn10k_cpt_dump_sg_list(pdev, info->req);
		break;

	case CN10K_CPT_COMP_E_INSTERR:
		dev_err(&pdev->dev,
			"Request failed with instruction error\n");
		cn10k_cpt_dump_sg_list(pdev, info->req);
		break;

	case CN10K_CPT_COMP_E_NOTDONE:
		/* check for timeout */
		if (time_after_eq(jiffies, info->time_in +
				  CPT_COMMAND_TIMEOUT * HZ))
			dev_warn(&pdev->dev,
				 "Request timed out 0x%p", info->req);
		else if (info->extra_time < CPT_TIME_IN_RESET_COUNT) {
			info->time_in = jiffies;
			info->extra_time++;
		}
		return 1;

	case CN10K_CPT_COMP_E_GOOD:
	case CN10K_CPT_COMP_E_WARN:
		/*
		 * Check microcode completion code, it is only valid
		 * when completion code is CPT_COMP_E::GOOD
		 */
		if (uc_ccode != CN10K_CPT_UCC_SUCCESS) {
			/*
			 * If requested hmac is truncated and ucode returns
			 * s/g write length error then we report success
			 * because ucode writes as many bytes of calculated
			 * hmac as available in gather buffer and reports
			 * s/g write length error if number of bytes in gather
			 * buffer is less than full hmac size.
			 */
			if (info->req->is_trunc_hmac &&
			    uc_ccode == CN10K_CPT_UCC_SG_WRITE_LENGTH) {
				*res_code = 0;
				break;
			}

			dev_err(&pdev->dev,
				"Request failed with software error code 0x%x\n",
				cpt_status->s.uc_compcode);
			cn10k_cpt_dump_sg_list(pdev, info->req);
			break;
		}
		/* Request has been processed with success */
		*res_code = 0;
		break;

	default:
		dev_err(&pdev->dev,
			"Request returned invalid status %d\n", ccode);
		break;
	}
	return 0;
}

static inline void process_pending_queue(struct pci_dev *pdev,
					 struct cn10k_cpt_pending_queue *pqueue)
{
	struct cn10k_cpt_pending_entry *resume_pentry = NULL;
	void (*callback)(int status, void *arg, void *req);
	struct cn10k_cpt_pending_entry *pentry = NULL;
	union cn10k_cpt_res_s *cpt_status = NULL;
	struct cn10k_cpt_inst_info *info = NULL;
	struct cn10k_cpt_req_info *req = NULL;
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

		if (unlikely(!pentry->callback)) {
			dev_err(&pdev->dev, "Callback NULL\n");
			goto process_pentry;
		}

		info = pentry->info;
		if (unlikely(!info)) {
			dev_err(&pdev->dev, "Pending entry post arg NULL\n");
			goto process_pentry;
		}

		req = info->req;
		if (unlikely(!req)) {
			dev_err(&pdev->dev, "Request NULL\n");
			goto process_pentry;
		}

		cpt_status = pentry->completion_addr;
		if (unlikely(!cpt_status)) {
			dev_err(&pdev->dev, "Completion address NULL\n");
			goto process_pentry;
		}

		if (cpt_process_ccode(pdev, cpt_status, info, &res_code)) {
			spin_unlock_bh(&pqueue->lock);
			return;
		}
		info->pdev = pdev;

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

			if (callback) {
				spin_unlock_bh(&pqueue->lock);

				/*
				 * EINPROGRESS is an indication for sending
				 * side that it can resume sending requests
				 */
				callback(-EINPROGRESS, areq, info);
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
		 * Call callback after current pending entry has been
		 * processed, we don't do it if the callback pointer is
		 * invalid.
		 */
		if (callback)
			callback(res_code, areq, info);
	}
}

void cn10k_cpt_post_process(struct cn10k_cptlf_wqe *wqe)
{
	process_pending_queue(wqe->lfs->pdev,
			      &wqe->lfs->lf[wqe->lf_num].pqueue);
}
