/* SPDX-License-Identifier: GPL-2.0
 * Marvell OcteonTX CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CPT8X_VF_H
#define __CPT8X_VF_H

#include <linux/list.h>
#include <linux/interrupt.h>
#include "cpt_common.h"
#include "cpt_reqmgr.h"
#include "cpt_hw_types.h"
#include "cpt8x_common.h"

/* Default command queue length */
#define CPT_CMD_QLEN (4*2046)
#define CPT_CMD_QCHUNK_SIZE 1023
#define CPT_NUM_QS_PER_VF 1

struct command_chunk {
	u8 *head;
	u8 *real_vaddr;
	dma_addr_t dma_addr;
	dma_addr_t real_dma_addr;
	u32 size; /* Chunk size, max CPT_INST_CHUNK_MAX_SIZE */
	struct list_head nextchunk;
};

struct command_queue {
	u32 idx; /* Command queue host write idx */
	u32 nchunks; /* Number of command chunks */
	struct command_chunk *qhead;	/* Command queue head, instructions
					 * are inserted here
					 */
	struct command_chunk *base;
	struct list_head chead;
};

struct command_qinfo {
	u32 cmd_size;
	u32 qchunksize; /* Command queue chunk size */
	struct command_queue queue[CPT_NUM_QS_PER_VF];
};

struct pending_qinfo {
	u32 nr_queues;	/* Number of queues supported */
	struct pending_queue queue[CPT_NUM_QS_PER_VF];
};

#define for_each_pending_queue(qinfo, q, i)	\
	for (i = 0, q = &qinfo->queue[i]; i < qinfo->nr_queues; i++, \
	q = &qinfo->queue[i])

struct cptvf_wqe {
	struct tasklet_struct twork;
	struct cpt_vf *cptvf;
};

struct cptvf_wqe_info {
	struct cptvf_wqe vq_wqe[CPT_NUM_QS_PER_VF];
};

struct cpt_vf {
	u16 flags; /* Flags to hold device status bits */
	u8 vfid; /* Device Index 0...CPT_MAX_VF_NUM */
	u8 num_vfs; /* Number of enabled VFs */
	u8 vftype; /* VF type of SE_TYPE(2) or AE_TYPE(1) */
	u8 vfgrp; /* VF group (0 - 8) */
	u8 node; /* Operating node: Bits (46:44) in BAR0 address */
	u8 priority; /* VF priority ring: 1-High proirity round
		      * robin ring;0-Low priority round robin ring;
		      */
	struct pci_dev *pdev; /* Pci device handle */
	struct reqmgr_ops ops; /* Request manager operations */
	void __iomem *reg_base; /* Register start address */
	void *wqe_info;	/* BH worker info */
	/* MSI-X */
	cpumask_var_t affinity_mask[CPT_8X_VF_MSIX_VECTORS];
	/* Command and Pending queues */
	u32 qsize;
	u32 nr_queues;
	struct command_qinfo cqinfo; /* Command queue information */
	struct pending_qinfo pqinfo; /* Pending queue information */
	/* VF-PF mailbox communication */
	bool pf_acked;
	bool pf_nacked;
};

int cptvf_send_vf_up(struct cpt_vf *cptvf);
int cptvf_send_vf_down(struct cpt_vf *cptvf);
int cptvf_send_vf_to_grp_msg(struct cpt_vf *cptvf, int group);
int cptvf_send_vf_priority_msg(struct cpt_vf *cptvf);
int cptvf_send_vq_size_msg(struct cpt_vf *cptvf);
int cptvf_check_pf_ready(struct cpt_vf *cptvf);
void cptvf_handle_mbox_intr(struct cpt_vf *cptvf);
void cptvf_write_vq_doorbell(struct cpt_vf *cptvf, u32 val);
struct algs_ops cpt8x_get_algs_ops(void);

#endif /* __CPT8X_VF_H */
