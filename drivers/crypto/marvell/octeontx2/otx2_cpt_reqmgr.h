/* SPDX-License-Identifier: GPL-2.0
 * Marvell CPT OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __OTX2_CPT_REQMGR_H
#define __OTX2_CPT_REQMGR_H

#include "otx2_cpt_common.h"

/* Completion code size and initial value */
#define OTX2_CPT_COMPLETION_CODE_SIZE 8
#define OTX2_CPT_COMPLETION_CODE_INIT 0

union otx2_cpt_opcode_info {
	u16 flags;
	struct {
		u8 major;
		u8 minor;
	} s;
};

struct otx2_cptvf_request {
	u32 param1;
	u32 param2;
	u16 dlen;
	union otx2_cpt_opcode_info opcode;
};

/*
 * CPT_INST_S software command definitions
 * Words EI (0-3)
 */
union otx2_cpt_iq_cmd_word0 {
	u64 u64;
	struct {
		u16 opcode;
		u16 param1;
		u16 param2;
		u16 dlen;
	} s;
};

union otx2_cpt_iq_cmd_word3 {
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

struct otx2_cpt_iq_command {
	union otx2_cpt_iq_cmd_word0 cmd;
	u64 dptr;
	u64 rptr;
	union otx2_cpt_iq_cmd_word3 cptr;
};

struct otx2_cpt_pending_entry {
	u64 *completion_addr;	/* Completion address */
	void *info;
	/* Kernel async request callback */
	void (*callback)(int status, void *arg1, void *arg2);
	struct crypto_async_request *areq; /* Async request callback arg */
	u8 resume_sender;	/* Notify sender to resume sending requests */
	u8 busy;		/* Entry status (free/busy) */
};

struct otx2_cpt_pending_queue {
	struct otx2_cpt_pending_entry *head; /* Head of the queue */
	u32 front;		/* Process work from here */
	u32 rear;		/* Append new work here */
	u32 pending_count;	/* Pending requests count */
	u32 qlen;		/* Queue length */
	spinlock_t lock;	/* Queue lock */
};
#endif /* __OTX2_CPT_REQMGR_H */
