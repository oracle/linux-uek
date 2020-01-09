/* SPDX-License-Identifier: GPL-2.0
 * Marvell CPT common code
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CPT_COMMON_H
#define __CPT_COMMON_H

#include <linux/pci.h>
#include <linux/types.h>
#include <linux/module.h>

/* Maximum request size in bytes */
#define CPT_MAX_REQ_SIZE	65535

/* Delay in us when waiting for a state change */
#define CSR_DELAY		30

/* Microcode version string length */
#define CPT_UCODE_VER_STR_SZ	44
#define TIME_IN_RESET_COUNT	5

/* Completion code size and initial value */
#define COMPLETION_CODE_SIZE	8
#define COMPLETION_CODE_INIT	0

/* SG list header size in bytes */
#define SG_LIST_HDR_SIZE	8

/* Maximum total number of SG buffers is 100, we divide it equally
 * between input and output
 */
#define MAX_SG_IN_CNT		50
#define MAX_SG_OUT_CNT		50

/* DMA mode direct or SG */
#define DMA_DIRECT_DIRECT	0
#define DMA_GATHER_SCATTER	1

/* Context source CPTR or DPTR */
#define FROM_CPTR		0
#define FROM_DPTR		1

/* CPT instruction queue alignment */
#define CPT_INST_Q_ALIGNMENT	128

/* Default timeout when waiting for free pending entry in us */
#define CPT_PENTRY_TIMEOUT	1000
#define CPT_PENTRY_STEP		50

/* Default threshold for stopping and resuming sender requests */
#define CPT_IQ_STOP_MARGIN	128
#define CPT_IQ_RESUME_MARGIN	512

/* Default command timeout in seconds */
#define CPT_COMMAND_TIMEOUT	4
#define CPT_TIMER_HOLD		0x03F
#define CPT_COUNT_HOLD		32

/* Minimum and maximum values for interrupt coalescing */
#define CPT_COALESC_MIN_TIME_WAIT	0x0
#define CPT_COALESC_MAX_TIME_WAIT	((1<<16)-1)
#define CPT_COALESC_MIN_NUM_WAIT	0x0
#define CPT_COALESC_MAX_NUM_WAIT	((1<<20)-1)

#define BAD_CPT_VF_TYPE		CPT_MAX_ENG_TYPES

enum cpt_pf_type {
	CPT_81XX = 1,
	CPT_AE_83XX = 2,
	CPT_SE_83XX = 3,
	CPT_96XX = 4,
	BAD_CPT_PF_TYPE,
};

enum cpt_eng_type {
	AE_TYPES = 1,
	SE_TYPES = 2,
	IE_TYPES = 3,
	CPT_MAX_ENG_TYPES,
};

union opcode_info {
	u16 flags;
	struct {
		u8 major;
		u8 minor;
	} s;
};

struct cptvf_request {
	u32 param1;
	u32 param2;
	u16 dlen;
	union opcode_info opcode;
};

struct buf_ptr {
	u8 *vptr;
	dma_addr_t dma_addr;
	u16 size;
};

union ctrl_info {
	u32 flags;
	struct {
#if defined(__BIG_ENDIAN_BITFIELD)
		u32 reserved0:26;
		u32 grp:3; /* Group bits */
		u32 dma_mode:2; /* DMA mode */
		u32 se_req:1;/* To SE core */
#else
		u32 se_req:1; /* To SE core */
		u32 dma_mode:2; /* DMA mode */
		u32 grp:3; /* Group bits */
		u32 reserved0:26;
#endif
	} s;
};

/*
 * CPT_INST_S software command definitions
 * Words EI (0-3)
 */
union iq_cmd_word0 {
	u64 u64;
	struct {
		u16 opcode;
		u16 param1;
		u16 param2;
		u16 dlen;
	} s;
};

union iq_cmd_word3 {
	u64 u64;
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

struct cpt_iq_command {
	union iq_cmd_word0 cmd;
	u64 dptr;
	u64 rptr;
	union iq_cmd_word3 cptr;
};

struct sglist_component {
	union {
		u64 len;
		struct {
			u16 len0;
			u16 len1;
			u16 len2;
			u16 len3;
		} s;
	} u;
	u64 ptr0;
	u64 ptr1;
	u64 ptr2;
	u64 ptr3;
};

struct pending_entry {
	u64 *completion_addr;	/* Completion address */
	void *post_arg;
	/* Kernel async request callback */
	void (*callback)(int, void *, void *);
	struct crypto_async_request *areq; /* Async request callback arg */
	u8 resume_sender;	/* Notify sender to resume sending requests */
	u8 busy;		/* Entry status (free/busy) */
};

struct pending_queue {
	struct pending_entry *head;	/* Head of the queue */
	u32 front;			/* Process work from here */
	u32 rear;			/* Append new work here */
	u32 pending_count;		/* Pending requests count */
	u32 qlen;			/* Queue length */
	spinlock_t lock;		/* Queue lock */
};

struct cpt_request_info {
	/* Kernel async request callback */
	void (*callback)(int, void *, void *);
	struct crypto_async_request *areq; /* Async request callback arg */
	struct cptvf_request req; /* Request information (core specific) */
	union ctrl_info ctrl; /* User control information */
	struct buf_ptr in[MAX_SG_IN_CNT];
	struct buf_ptr out[MAX_SG_OUT_CNT];
	u16 rlen; /* Output length */
	u8 incnt; /* Number of input buffers */
	u8 outcnt; /* Number of output buffers */
	u8 req_type; /* Type of request */
	u8 is_enc; /* Is a request an encryption request */
	u8 is_trunc_hmac; /* Is truncated hmac used */
};

struct cpt_info_buffer {
	struct pending_entry *pentry;
	struct cpt_request_info *req;
	u8 *scatter_components;
	u8 *gather_components;
	u64 *completion_addr;
	u8 *out_buffer;
	u8 *in_buffer;
	dma_addr_t dptr_baddr;
	dma_addr_t rptr_baddr;
	dma_addr_t comp_baddr;
	unsigned long time_in;
	u32 dlen;
	u8 extra_time;
};

#endif /* __CPT_COMMON_H */
