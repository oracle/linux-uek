/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2020 Marvell.
 */

#ifndef __CN10K_CPT_REQMGR_H
#define __CN10K_CPT_REQMGR_H

#include "cn10k_cpt_common.h"

/* Completion code size and initial value */
#define CN10K_CPT_COMPLETION_CODE_SIZE 8
#define CN10K_CPT_COMPLETION_CODE_INIT CN10K_CPT_COMP_E_NOTDONE

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
#endif /* __CN10K_CPT_REQMGR_H */
