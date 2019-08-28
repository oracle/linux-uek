// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/interrupt.h>
#include <linux/module.h>
#include "cpt8x_vf.h"
#include "cpt_algs.h"
#include "cpt8x_reqmgr.h"

#define DRV_NAME	"octeontx-cptvf"
#define DRV_VERSION	"1.0"

static void vq_work_handler(unsigned long data)
{
	struct cptvf_wqe_info *cwqe_info = (struct cptvf_wqe_info *) data;

	cpt8x_post_process(&cwqe_info->vq_wqe[0]);
}

static int init_worker_threads(struct cpt_vf *cptvf)
{
	struct pci_dev *pdev = cptvf->pdev;
	struct cptvf_wqe_info *cwqe_info;
	int i;

	cwqe_info = kzalloc(sizeof(*cwqe_info), GFP_KERNEL);
	if (!cwqe_info)
		return -ENOMEM;

	if (cptvf->nr_queues) {
		dev_dbg(&pdev->dev, "Creating VQ worker threads (%d)\n",
			cptvf->nr_queues);
	}

	for (i = 0; i < cptvf->nr_queues; i++) {
		tasklet_init(&cwqe_info->vq_wqe[i].twork, vq_work_handler,
			     (u64)cwqe_info);
		cwqe_info->vq_wqe[i].cptvf = cptvf;
	}

	cptvf->wqe_info = cwqe_info;

	return 0;
}

static void cleanup_worker_threads(struct cpt_vf *cptvf)
{
	struct cptvf_wqe_info *cwqe_info;
	struct pci_dev *pdev = cptvf->pdev;
	int i;

	cwqe_info = (struct cptvf_wqe_info *)cptvf->wqe_info;
	if (!cwqe_info)
		return;

	if (cptvf->nr_queues) {
		dev_dbg(&pdev->dev, "Cleaning VQ worker threads (%u)\n",
			cptvf->nr_queues);
	}

	for (i = 0; i < cptvf->nr_queues; i++)
		tasklet_kill(&cwqe_info->vq_wqe[i].twork);

	kzfree(cwqe_info);
	cptvf->wqe_info = NULL;
}

static void free_pending_queues(struct pending_qinfo *pqinfo)
{
	int i;
	struct pending_queue *queue;

	for_each_pending_queue(pqinfo, queue, i) {
		if (!queue->head)
			continue;

		/* free single queue */
		kzfree((queue->head));
		queue->front = 0;
		queue->rear = 0;
		queue->qlen = 0;
		return;
	}

	pqinfo->nr_queues = 0;
}

static int alloc_pending_queues(struct pending_qinfo *pqinfo, u32 qlen,
				u32 nr_queues)
{
	u32 i;
	size_t size;
	int ret;
	struct pending_queue *queue = NULL;

	pqinfo->nr_queues = nr_queues;
	size = (qlen * sizeof(struct pending_entry));

	for_each_pending_queue(pqinfo, queue, i) {
		queue->head = kzalloc((size), GFP_KERNEL);
		if (!queue->head) {
			ret = -ENOMEM;
			goto pending_qfail;
		}

		queue->pending_count = 0;
		queue->front = 0;
		queue->rear = 0;
		queue->qlen = qlen;

		/* init queue spin lock */
		spin_lock_init(&queue->lock);
	}

	return 0;

pending_qfail:
	free_pending_queues(pqinfo);

	return ret;
}

static int init_pending_queues(struct cpt_vf *cptvf, u32 qlen, u32 nr_queues)
{
	struct pci_dev *pdev = cptvf->pdev;
	int ret;

	if (!nr_queues)
		return 0;

	ret = alloc_pending_queues(&cptvf->pqinfo, qlen, nr_queues);
	if (ret) {
		dev_err(&pdev->dev, "failed to setup pending queues (%u)\n",
			nr_queues);
		return ret;
	}

	return 0;
}

static void cleanup_pending_queues(struct cpt_vf *cptvf)
{
	struct pci_dev *pdev = cptvf->pdev;

	if (!cptvf->nr_queues)
		return;

	dev_dbg(&pdev->dev, "Cleaning VQ pending queue (%u)\n",
		cptvf->nr_queues);
	free_pending_queues(&cptvf->pqinfo);
}

static void free_command_queues(struct cpt_vf *cptvf,
				struct command_qinfo *cqinfo)
{
	int i;
	struct command_queue *queue = NULL;
	struct command_chunk *chunk = NULL;
	struct pci_dev *pdev = cptvf->pdev;

	/* clean up for each queue */
	for (i = 0; i < cptvf->nr_queues; i++) {
		queue = &cqinfo->queue[i];

		while (!list_empty(&cqinfo->queue[i].chead)) {
			chunk = list_first_entry(&cqinfo->queue[i].chead,
					struct command_chunk, nextchunk);

			dma_free_coherent(&pdev->dev, chunk->size,
					  chunk->real_vaddr,
					  chunk->real_dma_addr);
			chunk->real_vaddr = NULL;
			chunk->real_dma_addr = 0;
			chunk->head = NULL;
			chunk->dma_addr = 0;
			list_del(&chunk->nextchunk);
			kzfree(chunk);
		}
		queue->nchunks = 0;
		queue->idx = 0;

	}
	/* common cleanup */
	cqinfo->cmd_size = 0;
}

static int alloc_command_queues(struct cpt_vf *cptvf,
				struct command_qinfo *cqinfo, size_t cmd_size,
				u32 qlen)
{
	int i;
	size_t q_size;
	struct command_queue *queue = NULL;
	struct pci_dev *pdev = cptvf->pdev;
	int align =  CPT_INST_Q_ALIGNMENT;

	/* common init */
	cqinfo->cmd_size = cmd_size;
	/* Qsize in dwords, needed for SADDR config, 1-next chunk pointer */
	cptvf->qsize = min(qlen, cqinfo->qchunksize) *
			CPT_NEXT_CHUNK_PTR_SIZE + 1;
	/* Qsize in bytes to create space for alignment */
	q_size = qlen * cqinfo->cmd_size;

	/* per queue initialization */
	for (i = 0; i < cptvf->nr_queues; i++) {
		size_t c_size = 0;
		size_t rem_q_size = q_size;
		struct command_chunk *curr = NULL, *first = NULL, *last = NULL;
		u32 qcsize_bytes = cqinfo->qchunksize * cqinfo->cmd_size;

		queue = &cqinfo->queue[i];
		INIT_LIST_HEAD(&cqinfo->queue[i].chead);
		do {
			curr = kzalloc(sizeof(*curr), GFP_KERNEL);
			if (!curr)
				goto cmd_qfail;

			c_size = (rem_q_size > qcsize_bytes) ? qcsize_bytes :
					rem_q_size;
			curr->real_vaddr = (u8 *)dma_zalloc_coherent(&pdev->dev,
				c_size + align + CPT_NEXT_CHUNK_PTR_SIZE,
				&curr->real_dma_addr, GFP_KERNEL);
			if (!curr->real_vaddr) {
				dev_err(&pdev->dev, "Command Q (%d) chunk (%d) allocation failed\n",
					i, queue->nchunks);
				kfree(curr);
				goto cmd_qfail;
			}
			curr->head = (uint8_t *) PTR_ALIGN(curr->real_vaddr,
							   align);
			curr->dma_addr =
			    (dma_addr_t) PTR_ALIGN(curr->real_dma_addr, align);
			curr->size = c_size;

			if (queue->nchunks == 0) {
				first = curr;
				queue->base  = first;
			}
			list_add_tail(&curr->nextchunk,
				      &cqinfo->queue[i].chead);

			queue->nchunks++;
			rem_q_size -= c_size;
			if (last)
				*((u64 *)(&last->head[last->size])) =
					(u64)curr->dma_addr;

			last = curr;
		} while (rem_q_size);

		/* Make the queue circular */
		/* Tie back last chunk entry to head */
		curr = first;
		*((u64 *)(&last->head[last->size])) = (u64)curr->dma_addr;
		queue->qhead = curr;
	}
	return 0;

cmd_qfail:
	free_command_queues(cptvf, cqinfo);
	return -ENOMEM;
}

static int init_command_queues(struct cpt_vf *cptvf, u32 qlen)
{
	struct pci_dev *pdev = cptvf->pdev;
	int ret;

	/* setup command queues */
	ret = alloc_command_queues(cptvf, &cptvf->cqinfo, CPT_INST_SIZE,
				   qlen);
	if (ret) {
		dev_err(&pdev->dev, "Failed to allocate command queues (%u)\n",
			cptvf->nr_queues);
		return ret;
	}

	return ret;
}

static void cleanup_command_queues(struct cpt_vf *cptvf)
{
	struct pci_dev *pdev = cptvf->pdev;

	if (!cptvf->nr_queues)
		return;

	dev_dbg(&pdev->dev, "Cleaning VQ command queue (%u)\n",
		cptvf->nr_queues);
	free_command_queues(cptvf, &cptvf->cqinfo);
}

static void cptvf_sw_cleanup(struct cpt_vf *cptvf)
{
	cleanup_worker_threads(cptvf);
	cleanup_pending_queues(cptvf);
	cleanup_command_queues(cptvf);
}

static int cptvf_sw_init(struct cpt_vf *cptvf, u32 qlen, u32 nr_queues)
{
	struct pci_dev *pdev = cptvf->pdev;
	int ret = 0;
	u32 max_dev_queues = 0;

	max_dev_queues = CPT_NUM_QS_PER_VF;
	/* possible cpus */
	nr_queues = min_t(u32, nr_queues, max_dev_queues);
	cptvf->nr_queues = nr_queues;

	ret = init_command_queues(cptvf, qlen);
	if (ret) {
		dev_err(&pdev->dev, "Failed to setup command queues (%u)\n",
			nr_queues);
		return ret;
	}

	ret = init_pending_queues(cptvf, qlen, nr_queues);
	if (ret) {
		dev_err(&pdev->dev, "Failed to setup pending queues (%u)\n",
			nr_queues);
		goto setup_pqfail;
	}

	/* Create worker threads for BH processing */
	ret = init_worker_threads(cptvf);
	if (ret) {
		dev_err(&pdev->dev, "Failed to setup worker threads\n");
		goto init_work_fail;
	}

	return 0;

init_work_fail:
	cleanup_worker_threads(cptvf);
	cleanup_pending_queues(cptvf);

setup_pqfail:
	cleanup_command_queues(cptvf);

	return ret;
}

static void cptvf_free_irq_affinity(struct cpt_vf *cptvf, int vec)
{
	irq_set_affinity_hint(pci_irq_vector(cptvf->pdev, vec), NULL);
	free_cpumask_var(cptvf->affinity_mask[vec]);
}

static void cptvf_write_vq_ctl(struct cpt_vf *cptvf, bool val)
{
	union cptx_vqx_ctl vqx_ctl;

	vqx_ctl.u = readq(cptvf->reg_base + CPT_VQX_CTL(0));
	vqx_ctl.s.ena = val;
	writeq(vqx_ctl.u, cptvf->reg_base + CPT_VQX_CTL(0));
}

void cptvf_write_vq_doorbell(struct cpt_vf *cptvf, u32 val)
{
	union cptx_vqx_doorbell vqx_dbell;

	vqx_dbell.u = readq(cptvf->reg_base + CPT_VQX_DOORBELL(0));
	vqx_dbell.s.dbell_cnt = val * 8; /* Num of Instructions * 8 words */
	writeq(vqx_dbell.u, cptvf->reg_base + CPT_VQX_DOORBELL(0));
}

static void cptvf_write_vq_inprog(struct cpt_vf *cptvf, u8 val)
{
	union cptx_vqx_inprog vqx_inprg;

	vqx_inprg.u = readq(cptvf->reg_base + CPT_VQX_INPROG(0));
	vqx_inprg.s.inflight = val;
	writeq(vqx_inprg.u, cptvf->reg_base + CPT_VQX_INPROG(0));
}

static void cptvf_write_vq_done_numwait(struct cpt_vf *cptvf, u32 val)
{
	union cptx_vqx_done_wait vqx_dwait;

	vqx_dwait.u = readq(cptvf->reg_base + CPT_VQX_DONE_WAIT(0));
	vqx_dwait.s.num_wait = val;
	writeq(vqx_dwait.u, cptvf->reg_base + CPT_VQX_DONE_WAIT(0));
}

static u32 cptvf_read_vq_done_numwait(struct cpt_vf *cptvf)
{
	union cptx_vqx_done_wait vqx_dwait;

	vqx_dwait.u = readq(cptvf->reg_base + CPT_VQX_DONE_WAIT(0));
	return vqx_dwait.s.num_wait;
}

static void cptvf_write_vq_done_timewait(struct cpt_vf *cptvf, u16 time)
{
	union cptx_vqx_done_wait vqx_dwait;

	vqx_dwait.u = readq(cptvf->reg_base + CPT_VQX_DONE_WAIT(0));
	vqx_dwait.s.time_wait = time;
	writeq(vqx_dwait.u, cptvf->reg_base + CPT_VQX_DONE_WAIT(0));
}


static u16 cptvf_read_vq_done_timewait(struct cpt_vf *cptvf)
{
	union cptx_vqx_done_wait vqx_dwait;

	vqx_dwait.u = readq(cptvf->reg_base + CPT_VQX_DONE_WAIT(0));
	return vqx_dwait.s.time_wait;
}

static void cptvf_enable_swerr_interrupts(struct cpt_vf *cptvf)
{
	union cptx_vqx_misc_ena_w1s vqx_misc_ena;

	vqx_misc_ena.u = readq(cptvf->reg_base + CPT_VQX_MISC_ENA_W1S(0));
	/* Set mbox(0) interupts for the requested vf */
	vqx_misc_ena.s.swerr = 1;
	writeq(vqx_misc_ena.u, cptvf->reg_base + CPT_VQX_MISC_ENA_W1S(0));
}

static void cptvf_enable_mbox_interrupts(struct cpt_vf *cptvf)
{
	union cptx_vqx_misc_ena_w1s vqx_misc_ena;

	vqx_misc_ena.u = readq(cptvf->reg_base + CPT_VQX_MISC_ENA_W1S(0));
	/* Set mbox(0) interupts for the requested vf */
	vqx_misc_ena.s.mbox = 1;
	writeq(vqx_misc_ena.u, cptvf->reg_base + CPT_VQX_MISC_ENA_W1S(0));
}

static void cptvf_enable_done_interrupts(struct cpt_vf *cptvf)
{
	union cptx_vqx_done_ena_w1s vqx_done_ena;

	vqx_done_ena.u = readq(cptvf->reg_base + CPT_VQX_DONE_ENA_W1S(0));
	/* Set DONE interrupt for the requested vf */
	vqx_done_ena.s.done = 1;
	writeq(vqx_done_ena.u, cptvf->reg_base + CPT_VQX_DONE_ENA_W1S(0));
}

static void cptvf_clear_dovf_intr(struct cpt_vf *cptvf)
{
	union cptx_vqx_misc_int vqx_misc_int;

	vqx_misc_int.u = readq(cptvf->reg_base + CPT_VQX_MISC_INT(0));
	/* W1C for the VF */
	vqx_misc_int.s.dovf = 1;
	writeq(vqx_misc_int.u, cptvf->reg_base + CPT_VQX_MISC_INT(0));
}

static void cptvf_clear_irde_intr(struct cpt_vf *cptvf)
{
	union cptx_vqx_misc_int vqx_misc_int;

	vqx_misc_int.u = readq(cptvf->reg_base + CPT_VQX_MISC_INT(0));
	/* W1C for the VF */
	vqx_misc_int.s.irde = 1;
	writeq(vqx_misc_int.u, cptvf->reg_base + CPT_VQX_MISC_INT(0));
}

static void cptvf_clear_nwrp_intr(struct cpt_vf *cptvf)
{
	union cptx_vqx_misc_int vqx_misc_int;

	vqx_misc_int.u = readq(cptvf->reg_base + CPT_VQX_MISC_INT(0));
	/* W1C for the VF */
	vqx_misc_int.s.nwrp = 1;
	writeq(vqx_misc_int.u, cptvf->reg_base + CPT_VQX_MISC_INT(0));
}

static void cptvf_clear_mbox_intr(struct cpt_vf *cptvf)
{
	union cptx_vqx_misc_int vqx_misc_int;

	vqx_misc_int.u = readq(cptvf->reg_base + CPT_VQX_MISC_INT(0));
	/* W1C for the VF */
	vqx_misc_int.s.mbox = 1;
	writeq(vqx_misc_int.u, cptvf->reg_base + CPT_VQX_MISC_INT(0));
}

static void cptvf_clear_swerr_intr(struct cpt_vf *cptvf)
{
	union cptx_vqx_misc_int vqx_misc_int;

	vqx_misc_int.u = readq(cptvf->reg_base + CPT_VQX_MISC_INT(0));
	/* W1C for the VF */
	vqx_misc_int.s.swerr = 1;
	writeq(vqx_misc_int.u, cptvf->reg_base + CPT_VQX_MISC_INT(0));
}

static u64 cptvf_read_vf_misc_intr_status(struct cpt_vf *cptvf)
{
	return readq(cptvf->reg_base + CPT_VQX_MISC_INT(0));
}

static irqreturn_t cptvf_misc_intr_handler(int irq, void *cptvf_irq)
{
	struct cpt_vf *cptvf = (struct cpt_vf *)cptvf_irq;
	struct pci_dev *pdev = cptvf->pdev;
	u64 intr;

	intr = cptvf_read_vf_misc_intr_status(cptvf);
	/*Check for MISC interrupt types*/
	if (likely(intr & CPT_8X_VF_INTR_MBOX_MASK)) {
		dev_dbg(&pdev->dev, "Mailbox interrupt 0x%llx on CPT VF %d\n",
			intr, cptvf->vfid);
		cptvf_handle_mbox_intr(cptvf);
		cptvf_clear_mbox_intr(cptvf);
	} else if (unlikely(intr & CPT_8X_VF_INTR_DOVF_MASK)) {
		cptvf_clear_dovf_intr(cptvf);
		/*Clear doorbell count*/
		cptvf_write_vq_doorbell(cptvf, 0);
		dev_err(&pdev->dev, "Doorbell overflow error interrupt 0x%llx on CPT VF %d\n",
			intr, cptvf->vfid);
	} else if (unlikely(intr & CPT_8X_VF_INTR_IRDE_MASK)) {
		cptvf_clear_irde_intr(cptvf);
		dev_err(&pdev->dev, "Instruction NCB read error interrupt 0x%llx on CPT VF %d\n",
			intr, cptvf->vfid);
	} else if (unlikely(intr & CPT_8X_VF_INTR_NWRP_MASK)) {
		cptvf_clear_nwrp_intr(cptvf);
		dev_err(&pdev->dev, "NCB response write error interrupt 0x%llx on CPT VF %d\n",
			intr, cptvf->vfid);
	} else if (unlikely(intr & CPT_8X_VF_INTR_SERR_MASK)) {
		cptvf_clear_swerr_intr(cptvf);
		dev_err(&pdev->dev, "Software error interrupt 0x%llx on CPT VF %d\n",
			intr, cptvf->vfid);
	} else {
		dev_err(&pdev->dev, "Unhandled interrupt in CPT VF %d\n",
			cptvf->vfid);
	}

	return IRQ_HANDLED;
}

static inline struct cptvf_wqe *get_cptvf_vq_wqe(struct cpt_vf *cptvf,
						 int qno)
{
	struct cptvf_wqe_info *nwqe_info;

	if (unlikely(qno >= cptvf->nr_queues))
		return NULL;
	nwqe_info = (struct cptvf_wqe_info *)cptvf->wqe_info;

	return &nwqe_info->vq_wqe[qno];
}

static inline u32 cptvf_read_vq_done_count(struct cpt_vf *cptvf)
{
	union cptx_vqx_done vqx_done;

	vqx_done.u = readq(cptvf->reg_base + CPT_VQX_DONE(0));
	return vqx_done.s.done;
}

static inline void cptvf_write_vq_done_ack(struct cpt_vf *cptvf,
					   u32 ackcnt)
{
	union cptx_vqx_done_ack vqx_dack_cnt;

	vqx_dack_cnt.u = readq(cptvf->reg_base + CPT_VQX_DONE_ACK(0));
	vqx_dack_cnt.s.done_ack = ackcnt;
	writeq(vqx_dack_cnt.u, cptvf->reg_base + CPT_VQX_DONE_ACK(0));
}

static irqreturn_t cptvf_done_intr_handler(int irq, void *cptvf_irq)
{
	struct cpt_vf *cptvf = (struct cpt_vf *)cptvf_irq;
	struct pci_dev *pdev = cptvf->pdev;
	/* Read the number of completions */
	u32 intr = cptvf_read_vq_done_count(cptvf);

	if (intr) {
		struct cptvf_wqe *wqe;

		/* Acknowledge the number of
		 * scheduled completions for processing
		 */
		cptvf_write_vq_done_ack(cptvf, intr);
		wqe = get_cptvf_vq_wqe(cptvf, 0);
		if (unlikely(!wqe)) {
			dev_err(&pdev->dev, "No work to schedule for VF (%d)",
				cptvf->vfid);
			return IRQ_NONE;
		}
		tasklet_hi_schedule(&wqe->twork);
	}

	return IRQ_HANDLED;
}

static void cptvf_set_irq_affinity(struct cpt_vf *cptvf, int vec)
{
	struct pci_dev *pdev = cptvf->pdev;
	int cpu;

	if (!zalloc_cpumask_var(&cptvf->affinity_mask[vec],
				GFP_KERNEL)) {
		dev_err(&pdev->dev, "Allocation failed for affinity_mask for VF %d",
			cptvf->vfid);
		return;
	}

	cpu = cptvf->vfid % num_online_cpus();
	cpumask_set_cpu(cpumask_local_spread(cpu, cptvf->node),
			cptvf->affinity_mask[vec]);
	irq_set_affinity_hint(pci_irq_vector(pdev, vec),
			cptvf->affinity_mask[vec]);
}

static void cptvf_write_vq_saddr(struct cpt_vf *cptvf, u64 val)
{
	union cptx_vqx_saddr vqx_saddr;
	vqx_saddr.u = val;
	writeq(vqx_saddr.u, cptvf->reg_base + CPT_VQX_SADDR(0));
}

static void cptvf_device_init(struct cpt_vf *cptvf)
{
	u64 base_addr = 0;

	/* Disable the VQ */
	cptvf_write_vq_ctl(cptvf, 0);
	/* Reset the doorbell */
	cptvf_write_vq_doorbell(cptvf, 0);
	/* Clear inflight */
	cptvf_write_vq_inprog(cptvf, 0);
	/* Write VQ SADDR */
	/* TODO: for now only one queue, so hard coded */
	base_addr = (u64)(cptvf->cqinfo.queue[0].qhead->dma_addr);
	cptvf_write_vq_saddr(cptvf, base_addr);
	/* Configure timerhold / coalescence */
	cptvf_write_vq_done_timewait(cptvf, CPT_TIMER_HOLD);
	cptvf_write_vq_done_numwait(cptvf, CPT_COUNT_HOLD);
	/* Enable the VQ */
	cptvf_write_vq_ctl(cptvf, 1);
	/* Flag the VF ready */
	cptvf->flags |= CPT_FLAG_DEVICE_READY;
}

static ssize_t cptvf_type_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cpt_vf *cptvf = dev_get_drvdata(dev);
	char *msg;

	switch (cptvf->vftype) {
	case AE_TYPES:
		msg = "AE";
	break;

	case SE_TYPES:
		msg = "SE";
	break;

	default:
		msg = "Invalid";
	}

	return scnprintf(buf, PAGE_SIZE, "%s\n", msg);
}

static ssize_t cptvf_engine_group_show(struct device *dev,
				       struct device_attribute *attr,
				       char *buf)
{
	struct cpt_vf *cptvf = dev_get_drvdata(dev);

	return scnprintf(buf, PAGE_SIZE, "%d\n", cptvf->vfgrp);
}

static ssize_t cptvf_engine_group_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct cpt_vf *cptvf = dev_get_drvdata(dev);
	int val, ret;

	ret = kstrtoint(buf, 10, &val);
	if (ret)
		return ret;

	if (val < 0)
		return -EINVAL;

	if (val >= CPT_MAX_ENGINE_GROUPS) {
		dev_err(dev, "Engine group >= than max available groups %d",
			CPT_MAX_ENGINE_GROUPS);
		return -EINVAL;
	}

	ret = cptvf_send_vf_to_grp_msg(cptvf, val);
	if (ret)
		return ret;

	return count;
}

static ssize_t cptvf_coalesc_time_wait_show(struct device *dev,
					    struct device_attribute *attr,
					    char *buf)
{
	struct cpt_vf *cptvf = dev_get_drvdata(dev);

	return scnprintf(buf, PAGE_SIZE, "%d\n",
			 cptvf_read_vq_done_timewait(cptvf));
}

static ssize_t cptvf_coalesc_num_wait_show(struct device *dev,
					   struct device_attribute *attr,
					   char *buf)
{
	struct cpt_vf *cptvf = dev_get_drvdata(dev);

	return scnprintf(buf, PAGE_SIZE, "%d\n",
			 cptvf_read_vq_done_numwait(cptvf));
}

static ssize_t cptvf_coalesc_time_wait_store(struct device *dev,
					     struct device_attribute *attr,
					     const char *buf, size_t count)
{
	struct cpt_vf *cptvf = dev_get_drvdata(dev);
	long int val;
	int ret;

	ret = kstrtol(buf, 10, &val);
	if (ret != 0)
		return ret;

	if (val < CPT_COALESC_MIN_TIME_WAIT ||
	    val > CPT_COALESC_MAX_TIME_WAIT)
		return -EINVAL;

	cptvf_write_vq_done_timewait(cptvf, val);
	return count;
}

static ssize_t cptvf_coalesc_num_wait_store(struct device *dev,
					    struct device_attribute *attr,
					    const char *buf, size_t count)
{
	struct cpt_vf *cptvf = dev_get_drvdata(dev);
	long int val;
	int ret;

	ret = kstrtol(buf, 10, &val);
	if (ret != 0)
		return ret;

	if (val < CPT_COALESC_MIN_NUM_WAIT ||
	    val > CPT_COALESC_MAX_NUM_WAIT)
		return -EINVAL;

	cptvf_write_vq_done_numwait(cptvf, val);
	return count;
}

static DEVICE_ATTR(vf_type, 0444, cptvf_type_show, NULL);
static DEVICE_ATTR(vf_engine_group, 0664, cptvf_engine_group_show,
				   cptvf_engine_group_store);
static DEVICE_ATTR(vf_coalesc_time_wait, 0664,
		   cptvf_coalesc_time_wait_show, cptvf_coalesc_time_wait_store);
static DEVICE_ATTR(vf_coalesc_num_wait, 0664,
		   cptvf_coalesc_num_wait_show, cptvf_coalesc_num_wait_store);

static struct attribute *vf_attrs[] = {
	&dev_attr_vf_type.attr,
	&dev_attr_vf_engine_group.attr,
	&dev_attr_vf_coalesc_time_wait.attr,
	&dev_attr_vf_coalesc_num_wait.attr,
	NULL
};

static const struct attribute_group vf_sysfs_group = {
	.attrs = vf_attrs,
};

static int cptvf_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	struct device *dev = &pdev->dev;
	struct cpt_vf *cptvf;
	int err;

	cptvf = devm_kzalloc(dev, sizeof(*cptvf), GFP_KERNEL);
	if (!cptvf)
		return -ENOMEM;

	pci_set_drvdata(pdev, cptvf);
	cptvf->pdev = pdev;

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(dev, "Failed to enable PCI device\n");
		pci_set_drvdata(pdev, NULL);
		return err;
	}

	err = pci_request_regions(pdev, DRV_NAME);
	if (err) {
		dev_err(dev, "PCI request regions failed 0x%x\n", err);
		goto cptvf_err_disable_device;
	}

	/* Mark as VF driver */
	cptvf->flags |= CPT_FLAG_VF_DRIVER;
	err = pci_set_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to get usable DMA configuration\n");
		goto cptvf_err_release_regions;
	}

	err = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(48));
	if (err) {
		dev_err(dev, "Unable to get 48-bit DMA for consistent allocations\n");
		goto cptvf_err_release_regions;
	}

	/* MAP PF's configuration registers */
	cptvf->reg_base = pcim_iomap(pdev, PCI_CPT_VF_8X_CFG_BAR, 0);
	if (!cptvf->reg_base) {
		dev_err(dev, "Cannot map config register space, aborting\n");
		err = -ENOMEM;
		goto cptvf_err_release_regions;
	}

	cptvf->node = dev_to_node(&pdev->dev);
	err = pci_alloc_irq_vectors(pdev, CPT_8X_VF_MSIX_VECTORS,
			CPT_8X_VF_MSIX_VECTORS, PCI_IRQ_MSIX);
	if (err < 0) {
		dev_err(dev, "Request for #%d msix vectors failed\n",
			CPT_8X_VF_MSIX_VECTORS);
		goto cptvf_err_release_regions;
	}

	err = request_irq(pci_irq_vector(pdev, CPT_8X_VF_INT_VEC_E_MISC),
			  cptvf_misc_intr_handler, 0, "CPT VF misc intr",
			  cptvf);
	if (err) {
		dev_err(dev, "Request misc irq failed");
		goto cptvf_free_vectors;
	}

	/* Enable mailbox interrupt */
	cptvf_enable_mbox_interrupts(cptvf);
	cptvf_enable_swerr_interrupts(cptvf);

	/* Check ready with PF */
	/* Gets chip ID / device Id from PF if ready */
	err = cptvf_check_pf_ready(cptvf);
	if (err) {
		dev_err(dev, "PF not responding to READY msg");
		goto cptvf_free_misc_irq;
	}

	/* CPT VF software resources initialization */
	cptvf->cqinfo.qchunksize = CPT_CMD_QCHUNK_SIZE;
	err = cptvf_sw_init(cptvf, CPT_CMD_QLEN, CPT_NUM_QS_PER_VF);
	if (err) {
		dev_err(dev, "cptvf_sw_init() failed");
		goto cptvf_free_misc_irq;
	}
	/* Convey VQ LEN to PF */
	err = cptvf_send_vq_size_msg(cptvf);
	if (err) {
		dev_err(dev, "PF not responding to QLEN msg");
		goto cptvf_free_misc_irq;
	}

	/* CPT VF device initialization */
	cptvf_device_init(cptvf);
	/* Send msg to PF to assign currnet Q to required group */
	err = cptvf_send_vf_to_grp_msg(cptvf, cptvf->vfgrp);
	if (err) {
		dev_err(dev, "PF not responding to VF_GRP msg");
		goto cptvf_free_misc_irq;
	}

	cptvf->priority = 1;
	err = cptvf_send_vf_priority_msg(cptvf);
	if (err) {
		dev_err(dev, "PF not responding to VF_PRIO msg");
		goto cptvf_free_misc_irq;
	}

	err = request_irq(pci_irq_vector(pdev, CPT_8X_VF_INT_VEC_E_DONE),
			  cptvf_done_intr_handler, 0, "CPT VF done intr",
			  cptvf);
	if (err) {
		dev_err(dev, "Request done irq failed\n");
		goto cptvf_free_done_irq;
	}

	/* Enable done interrupt */
	cptvf_enable_done_interrupts(cptvf);

	/* Set irq affinity masks */
	cptvf_set_irq_affinity(cptvf, CPT_8X_VF_INT_VEC_E_MISC);
	cptvf_set_irq_affinity(cptvf, CPT_8X_VF_INT_VEC_E_DONE);

	err = cptvf_send_vf_up(cptvf);
	if (err) {
		dev_err(dev, "PF not responding to UP msg");
		goto cptvf_free_irq_affinity;
	}

	/* Set request manager ops */
	cptvf->ops = cpt8x_get_reqmgr_ops();

	/* Initialize algorithms and set ops */
	err = cvm_crypto_init(pdev, THIS_MODULE, cpt8x_get_algs_ops(),
			      cptvf->vftype == SE_TYPES ? CPT_SE_83XX :
			      CPT_AE_83XX, cptvf->vftype, 1, cptvf->num_vfs);
	if (err) {
		dev_err(dev, "Algorithm register failed\n");
		goto cptvf_free_irq_affinity;
	}

	err = sysfs_create_group(&dev->kobj, &vf_sysfs_group);
	if (err) {
		dev_err(dev, "Creating sysfs entries failed\n");
		goto cptvf_crypto_exit;
	}

	return 0;

cptvf_crypto_exit:
	cvm_crypto_exit(pdev, THIS_MODULE, cptvf->vftype);
cptvf_free_irq_affinity:
	cptvf_free_irq_affinity(cptvf, CPT_8X_VF_INT_VEC_E_DONE);
	cptvf_free_irq_affinity(cptvf, CPT_8X_VF_INT_VEC_E_MISC);
cptvf_free_done_irq:
	free_irq(pci_irq_vector(pdev, CPT_8X_VF_INT_VEC_E_DONE), cptvf);
cptvf_free_misc_irq:
	free_irq(pci_irq_vector(pdev, CPT_8X_VF_INT_VEC_E_MISC), cptvf);
cptvf_free_vectors:
	pci_free_irq_vectors(cptvf->pdev);
cptvf_err_release_regions:
	pci_release_regions(pdev);
cptvf_err_disable_device:
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);

	return err;
}

static void cptvf_remove(struct pci_dev *pdev)
{
	struct cpt_vf *cptvf = pci_get_drvdata(pdev);

	if (!cptvf) {
		dev_err(&pdev->dev, "Invalid CPT-VF device\n");
		return;
	}

	/* Convey DOWN to PF */
	if (cptvf_send_vf_down(cptvf)) {
		dev_err(&pdev->dev, "PF not responding to DOWN msg");
	} else {
		cvm_crypto_exit(pdev, THIS_MODULE, cptvf->vftype);
		cptvf_free_irq_affinity(cptvf, CPT_8X_VF_INT_VEC_E_DONE);
		cptvf_free_irq_affinity(cptvf, CPT_8X_VF_INT_VEC_E_MISC);
		free_irq(pci_irq_vector(pdev, CPT_8X_VF_INT_VEC_E_DONE), cptvf);
		free_irq(pci_irq_vector(pdev, CPT_8X_VF_INT_VEC_E_MISC), cptvf);
		pci_free_irq_vectors(cptvf->pdev);
		cptvf_sw_cleanup(cptvf);
		sysfs_remove_group(&pdev->dev.kobj, &vf_sysfs_group);
		pci_set_drvdata(pdev, NULL);
		pci_release_regions(pdev);
		pci_disable_device(pdev);
	}
}

/* Supported devices */
static const struct pci_device_id cptvf_id_table[] = {
	{PCI_VDEVICE(CAVIUM, CPT_PCI_VF_8X_DEVICE_ID), 0},
	{ 0, }  /* end of table */
};

static struct pci_driver cptvf_pci_driver = {
	.name = DRV_NAME,
	.id_table = cptvf_id_table,
	.probe = cptvf_probe,
	.remove = cptvf_remove,
};

module_pci_driver(cptvf_pci_driver);

MODULE_AUTHOR("Marvell International Ltd.");
MODULE_DESCRIPTION("Marvell OcteonTX CPT Virtual Function Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION(DRV_VERSION);
MODULE_DEVICE_TABLE(pci, cptvf_id_table);
