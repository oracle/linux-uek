/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2020 Marvell.
 */

#ifndef __CN10K_CPT_REQMGR_H
#define __CN10K_CPT_REQMGR_H

#include "cn10k_cpt_common.h"

/* Completion code size and initial value */
#define CN10K_CPT_COMPLETION_CODE_SIZE 8
#define CN10K_CPT_COMPLETION_CODE_INIT CN10K_CPT_COMP_E_NOTDONE
/*
 * Maximum total number of SG buffers is 100, we divide it equally
 * between input and output
 */
#define CN10K_CPT_MAX_SG_IN_CNT  50
#define CN10K_CPT_MAX_SG_OUT_CNT 50

/* DMA mode direct or SG */
#define CN10K_CPT_DMA_MODE_DIRECT 0
#define CN10K_CPT_DMA_MODE_SG     1

/* Context source CPTR or DPTR */
#define CN10K_CPT_FROM_CPTR 0
#define CN10K_CPT_FROM_DPTR 1

#define CN10K_CPT_MAX_REQ_SIZE 65535

union cn10k_cpt_opcode {
	u16 flags;
	struct {
		u8 major;
		u8 minor;
	} s;
};

struct cn10k_cptvf_request {
	u32 param1;
	u32 param2;
	u16 dlen;
	union cn10k_cpt_opcode opcode;
};

/*
 * CPT_INST_S software command definitions
 * Words EI (0-3)
 */
union cn10k_cpt_iq_cmd_word0 {
	u64 u;
	struct {
		__be16 opcode;
		__be16 param1;
		__be16 param2;
		__be16 dlen;
	} s;
};

union cn10k_cpt_iq_cmd_word3 {
	u64 u;
	struct {
#if defined(__BIG_ENDIAN_BITFIELD)
		u64 grp:3;
		u64 cptr:61;
#else
		u64 cptr:61;
		u64 grp:3;
#endif
	} s;
};

struct cn10k_cpt_iq_command {
	union cn10k_cpt_iq_cmd_word0 cmd;
	u64 dptr;
	u64 rptr;
	union cn10k_cpt_iq_cmd_word3 cptr;
};

struct cn10k_cpt_pending_entry {
	void *completion_addr;	/* Completion address */
	void *info;
	/* Kernel async request callback */
	void (*callback)(int status, void *arg1, void *arg2);
	struct crypto_async_request *areq; /* Async request callback arg */
	u8 resume_sender;	/* Notify sender to resume sending requests */
	u8 busy;		/* Entry status (free/busy) */
};

struct cn10k_cpt_pending_queue {
	struct cn10k_cpt_pending_entry *head; /* Head of the queue */
	u32 front;		/* Process work from here */
	u32 rear;		/* Append new work here */
	u32 pending_count;	/* Pending requests count */
	u32 qlen;		/* Queue length */
	spinlock_t lock;	/* Queue lock */
};

struct cn10k_cpt_buf_ptr {
	u8 *vptr;
	dma_addr_t dma_addr;
	u16 size;
};

union cn10k_cpt_ctrl_info {
	u32 flags;
	struct {
#if defined(__BIG_ENDIAN_BITFIELD)
		u32 reserved_6_31:26;
		u32 grp:3;	/* Group bits */
		u32 dma_mode:2;	/* DMA mode */
		u32 se_req:1;	/* To SE core */
#else
		u32 se_req:1;	/* To SE core */
		u32 dma_mode:2;	/* DMA mode */
		u32 grp:3;	/* Group bits */
		u32 reserved_6_31:26;
#endif
	} s;
};

struct cn10k_cpt_req_info {
	/* Kernel async request callback */
	void (*callback)(int status, void *arg1, void *arg2);
	struct crypto_async_request *areq; /* Async request callback arg */
	struct cn10k_cptvf_request req;/* Request information (core specific) */
	union cn10k_cpt_ctrl_info ctrl;/* User control information */
	struct cn10k_cpt_buf_ptr in[CN10K_CPT_MAX_SG_IN_CNT];
	struct cn10k_cpt_buf_ptr out[CN10K_CPT_MAX_SG_OUT_CNT];
	u8 *iv_out;     /* IV to send back */
	u16 rlen;	/* Output length */
	u8 in_cnt;	/* Number of input buffers */
	u8 out_cnt;	/* Number of output buffers */
	u8 req_type;	/* Type of request */
	u8 is_enc;	/* Is a request an encryption request */
	u8 is_trunc_hmac;/* Is truncated hmac used */
};

struct cn10k_cpt_inst_info {
	struct cn10k_cpt_pending_entry *pentry;
	struct cn10k_cpt_req_info *req;
	struct pci_dev *pdev;
	void *completion_addr;
	u8 *out_buffer;
	u8 *in_buffer;
	dma_addr_t dptr_baddr;
	dma_addr_t rptr_baddr;
	dma_addr_t comp_baddr;
	unsigned long time_in;
	u32 dlen;
	u32 dma_len;
	u8 extra_time;
};

struct cn10k_cpt_sglist_component {
	u16 len0;
	u16 len1;
	u16 len2;
	u16 len3;
	u64 ptr0;
	u64 ptr1;
	u64 ptr2;
	u64 ptr3;
};

static inline void cn10k_cpt_info_destroy(struct pci_dev *pdev,
					 struct cn10k_cpt_inst_info *info)
{
	struct cn10k_cpt_req_info *req;
	int i;

	if (info->dptr_baddr)
		dma_unmap_single(&pdev->dev, info->dptr_baddr,
				 info->dma_len, DMA_BIDIRECTIONAL);

	if (info->req) {
		req = info->req;
		for (i = 0; i < req->out_cnt; i++) {
			if (req->out[i].dma_addr)
				dma_unmap_single(&pdev->dev,
						 req->out[i].dma_addr,
						 req->out[i].size,
						 DMA_BIDIRECTIONAL);
		}

		for (i = 0; i < req->in_cnt; i++) {
			if (req->in[i].dma_addr)
				dma_unmap_single(&pdev->dev,
						 req->in[i].dma_addr,
						 req->in[i].size,
						 DMA_BIDIRECTIONAL);
		}
	}
	kzfree(info);
}

struct cn10k_cptlf_wqe;
int cn10k_cpt_get_kcrypto_eng_grp_num(struct pci_dev *pdev);
int cn10k_cpt_do_request(struct pci_dev *pdev, struct cn10k_cpt_req_info *req,
			int cpu_num);
void cn10k_cpt_post_process(struct cn10k_cptlf_wqe *wqe);

#endif /* __CN10K_CPT_REQMGR_H */
