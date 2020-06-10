// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTX2 CPT driver
 *
 * Copyright (C) 2018 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "cpt_reqmgr.h"
#include "cpt_algs.h"
#include "cpt9x_mbox_common.h"
#include "cpt9x_common.h"
#include "cpt9x_reqmgr.h"
#include "otx2_reg.h"
#include "rvu_reg.h"

static int cptlf_get_done_time_wait(struct cptlf_info *lf)
{
	u8 blkaddr = cpt_get_blkaddr(lf->lfs->pdev);
	union cptx_vqx_done_wait done_wait;

	done_wait.u = cpt_read64(lf->lfs->reg_base, blkaddr, lf->slot,
				 CPT_LF_DONE_WAIT);
	return done_wait.s.time_wait;
}

static void cptlf_do_set_done_time_wait(struct cptlf_info *lf, int time_wait)
{
	u8 blkaddr = cpt_get_blkaddr(lf->lfs->pdev);
	union cptx_vqx_done_wait done_wait;

	done_wait.u = cpt_read64(lf->lfs->reg_base, blkaddr, lf->slot,
				 CPT_LF_DONE_WAIT);
	done_wait.s.time_wait = time_wait;
	cpt_write64(lf->lfs->reg_base, blkaddr, lf->slot, CPT_LF_DONE_WAIT,
		    done_wait.u);
}

static int cptlf_get_done_num_wait(struct cptlf_info *lf)
{
	u8 blkaddr = cpt_get_blkaddr(lf->lfs->pdev);
	union cptx_vqx_done_wait done_wait;

	done_wait.u = cpt_read64(lf->lfs->reg_base, blkaddr, lf->slot,
				 CPT_LF_DONE_WAIT);
	return done_wait.s.num_wait;
}

static void cptlf_do_set_done_num_wait(struct cptlf_info *lf, int num_wait)
{
	u8 blkaddr = cpt_get_blkaddr(lf->lfs->pdev);
	union cptx_vqx_done_wait done_wait;

	done_wait.u = cpt_read64(lf->lfs->reg_base, blkaddr, lf->slot,
				 CPT_LF_DONE_WAIT);
	done_wait.s.num_wait = num_wait;
	cpt_write64(lf->lfs->reg_base, blkaddr, lf->slot, CPT_LF_DONE_WAIT,
		    done_wait.u);
}

static void cptlf_set_done_time_wait(struct cptlfs_info *lfs, int time_wait)
{
	int slot;

	for (slot = 0; slot < lfs->lfs_num; slot++)
		cptlf_do_set_done_time_wait(&lfs->lf[slot], time_wait);
}

static void cptlf_set_done_num_wait(struct cptlfs_info *lfs, int num_wait)
{
	int slot;

	for (slot = 0; slot < lfs->lfs_num; slot++)
		cptlf_do_set_done_num_wait(&lfs->lf[slot], num_wait);
}

static int cptlf_get_inflight(struct cptlf_info *lf)
{
	u8 blkaddr = cpt_get_blkaddr(lf->lfs->pdev);
	union cptx_lf_inprog lf_inprog;

	lf_inprog.u = cpt_read64(lf->lfs->reg_base, blkaddr, lf->slot,
				 CPT_LF_INPROG);

	return lf_inprog.s.inflight;
}

static int cptlf_get_pri(struct pci_dev *pdev, struct cptlf_info *lf, int *pri)
{
	union cptx_af_lf_ctrl lf_ctrl;
	int ret = 0;

	ret = cpt_read_af_reg(pdev, CPT_AF_LFX_CTL(lf->slot), &lf_ctrl.u);
	if (ret)
		goto err;

	*pri = lf_ctrl.s.pri;
err:
	return ret;
}

static int cptlf_set_pri(struct pci_dev *pdev, struct cptlf_info *lf, int pri)
{
	union cptx_af_lf_ctrl lf_ctrl;
	int ret = 0;

	ret = cpt_read_af_reg(pdev, CPT_AF_LFX_CTL(lf->slot), &lf_ctrl.u);
	if (ret)
		goto err;

	lf_ctrl.s.pri = pri ? 1 : 0;

	ret = cpt_write_af_reg(pdev, CPT_AF_LFX_CTL(lf->slot), lf_ctrl.u);
	if (ret)
		goto err;
err:
	return ret;
}

static int cptlf_get_eng_grps_mask(struct pci_dev *pdev, struct cptlf_info *lf,
				   int *eng_grps_mask)
{
	union cptx_af_lf_ctrl lf_ctrl;
	int ret = 0;

	ret = cpt_read_af_reg(pdev, CPT_AF_LFX_CTL(lf->slot), &lf_ctrl.u);
	if (ret)
		goto err;

	*eng_grps_mask = lf_ctrl.s.grp;
err:
	return ret;
}

static int cptlf_set_eng_grps_mask(struct pci_dev *pdev, struct cptlf_info *lf,
				   int eng_grps_mask)
{
	union cptx_af_lf_ctrl lf_ctrl;
	int ret = 0;

	ret = cpt_read_af_reg(pdev, CPT_AF_LFX_CTL(lf->slot), &lf_ctrl.u);
	if (ret)
		goto err;

	lf_ctrl.s.grp = eng_grps_mask;

	ret = cpt_write_af_reg(pdev, CPT_AF_LFX_CTL(lf->slot), lf_ctrl.u);
	if (ret)
		goto err;
err:
	return ret;
}

static int cptlf_set_grp_and_pri(struct pci_dev *pdev, struct cptlfs_info *lfs,
				 int eng_grp_mask, int pri)
{
	int slot, ret = 0;

	for (slot = 0; slot < lfs->lfs_num; slot++) {
		ret = cptlf_set_pri(pdev, &lfs->lf[slot], pri);
		if (ret)
			goto err;

		ret = cptlf_set_eng_grps_mask(pdev, &lfs->lf[slot],
					      eng_grp_mask);
		if (ret)
			goto err;
	}
err:
	return ret;
}

static void cptlf_hw_init(struct cptlfs_info *lfs)
{
	/* Disable instruction queues */
	cptlf_disable_iqueues(lfs);

	/* Set instruction queues base addresses */
	cptlf_set_iqueues_base_addr(lfs);

	/* Set instruction queues sizes */
	cptlf_set_iqueues_size(lfs);

	/* Set done interrupts time wait */
	cptlf_set_done_time_wait(lfs, CPT_TIMER_HOLD);

	/* Set done interrupts num wait */
	cptlf_set_done_num_wait(lfs, CPT_COUNT_HOLD);

	/* Enable instruction queues */
	cptlf_enable_iqueues(lfs);
}

static void cptlf_hw_cleanup(struct cptlfs_info *lfs)
{
	/* Disable instruction queues */
	cptlf_disable_iqueues(lfs);
}

static void cptlf_set_misc_intrs(struct cptlfs_info *lfs, u8 enable)
{
	union cptx_lf_misc_int_ena_w1s irq_misc = { .u = 0x0 };
	u64 reg = enable ? CPT_LF_MISC_INT_ENA_W1S : CPT_LF_MISC_INT_ENA_W1C;
	u8 blkaddr = cpt_get_blkaddr(lfs->pdev);
	int slot;

	irq_misc.s.fault = 0x1;
	irq_misc.s.hwerr = 0x1;
	irq_misc.s.irde = 0x1;
	irq_misc.s.nqerr = 0x1;
	irq_misc.s.nwrp = 0x1;

	for (slot = 0; slot < lfs->lfs_num; slot++)
		cpt_write64(lfs->reg_base, blkaddr, slot, reg, irq_misc.u);
}

static void cptlf_enable_misc_intrs(struct cptlfs_info *lfs)
{
	cptlf_set_misc_intrs(lfs, true);
}

static void cptlf_disable_misc_intrs(struct cptlfs_info *lfs)
{
	cptlf_set_misc_intrs(lfs, false);
}

static void cptlf_enable_done_intr(struct cptlfs_info *lfs)
{
	u8 blkaddr = cpt_get_blkaddr(lfs->pdev);
	int slot;

	for (slot = 0; slot < lfs->lfs_num; slot++)
		cpt_write64(lfs->reg_base, blkaddr, slot,
			    CPT_LF_DONE_INT_ENA_W1S, 0x1);
}

static void cptlf_disable_done_intr(struct cptlfs_info *lfs)
{
	u8 blkaddr = cpt_get_blkaddr(lfs->pdev);
	int slot;

	for (slot = 0; slot < lfs->lfs_num; slot++)
		cpt_write64(lfs->reg_base, blkaddr, slot,
			    CPT_LF_DONE_INT_ENA_W1C, 0x1);
}

static inline int cptlf_read_done_cnt(struct cptlf_info *lf)
{
	u8 blkaddr = cpt_get_blkaddr(lf->lfs->pdev);
	union cptx_vqx_done irq_cnt;

	irq_cnt.u = cpt_read64(lf->lfs->reg_base, blkaddr, lf->slot,
			       CPT_LF_DONE);
	return irq_cnt.s.done;
}

static irqreturn_t cptlf_misc_intr_handler(int irq, void *cptlf)
{
	struct cptlf_info *lf = (struct cptlf_info *) cptlf;
	union cptx_lf_misc_int irq_misc, irq_misc_ack;
	u8 blkaddr = cpt_get_blkaddr(lf->lfs->pdev);
	struct device *dev = &lf->lfs->pdev->dev;

	irq_misc.u = cpt_read64(lf->lfs->reg_base, blkaddr, lf->slot,
				CPT_LF_MISC_INT);
	irq_misc_ack.u = 0x0;

	if (irq_misc.s.fault) {
		dev_err(dev, "Memory error detected while executing CPT_INST_S, LF %d.\n",
			lf->slot);
		irq_misc_ack.s.fault = 0x1;

	} else if (irq_misc.s.hwerr) {
		dev_err(dev, "HW error from an engine executing CPT_INST_S, LF %d.",
			lf->slot);
		irq_misc_ack.s.hwerr = 0x1;

	} else if (irq_misc.s.nwrp) {
		dev_err(dev, "SMMU fault while writing CPT_RES_S to CPT_INST_S[RES_ADDR], LF %d.\n",
			lf->slot);
		irq_misc_ack.s.nwrp = 0x1;

	} else if (irq_misc.s.irde) {
		dev_err(dev, "Memory error when accessing instruction memory queue CPT_LF_Q_BASE[ADDR].\n");
		irq_misc_ack.s.irde = 0x1;

	} else if (irq_misc.s.nqerr) {
		dev_err(dev, "Error enqueuing an instruction received at CPT_LF_NQ.\n");
		irq_misc_ack.s.nqerr = 0x1;

	} else {
		dev_err(dev, "Unhandled interrupt in CPT LF %d\n", lf->slot);
		return IRQ_NONE;
	}

	/* Acknowledge interrupts */
	cpt_write64(lf->lfs->reg_base, blkaddr, lf->slot, CPT_LF_MISC_INT,
		    irq_misc_ack.u);

	return IRQ_HANDLED;
}

static irqreturn_t cptlf_done_intr_handler(int irq, void *cptlf)
{
	struct cptlf_info *lf = (struct cptlf_info *) cptlf;
	u8 blkaddr = cpt_get_blkaddr(lf->lfs->pdev);
	union cptx_vqx_done_wait done_wait;
	int irq_cnt;

	/* Read the number of completed requests */
	irq_cnt = cptlf_read_done_cnt(lf);
	if (irq_cnt) {
		done_wait.u = cpt_read64(lf->lfs->reg_base, blkaddr,
					 lf->slot, CPT_LF_DONE_WAIT);
		/* Acknowledge the number of completed requests */
		cpt_write64(lf->lfs->reg_base, blkaddr, lf->slot,
			    CPT_LF_DONE_ACK, irq_cnt);

		cpt_write64(lf->lfs->reg_base, blkaddr, lf->slot,
			    CPT_LF_DONE_WAIT, done_wait.u);
		if (unlikely(!lf->wqe)) {
			dev_err(&lf->lfs->pdev->dev, "No work for LF %d\n",
				lf->slot);
			return IRQ_NONE;
		}

		/* Schedule processing of completed requests */
		tasklet_hi_schedule(&lf->wqe->work);
	}

	return IRQ_HANDLED;
}

static int cptlf_do_register_interrrupts(struct cptlfs_info *lfs, int lf_num,
					 int irq_offset, irq_handler_t handler)
{
	int ret = 0;

	ret = request_irq(pci_irq_vector(lfs->pdev, lfs->lf[lf_num].msix_offset
			  + irq_offset), handler, 0,
			  lfs->lf[lf_num].irq_name[irq_offset],
			  &lfs->lf[lf_num]);
	if (ret)
		goto error;

	lfs->lf[lf_num].is_irq_reg[irq_offset] = true;
error:
	return ret;
}

static int cptlf_register_interrupts(struct cptlfs_info *lfs)
{
	int irq_offs, i;
	int ret = 0;

	for (i = 0; i < lfs->lfs_num; i++) {
		irq_offs = CPT_9X_LF_INT_VEC_E_MISC;
		snprintf(lfs->lf[i].irq_name[irq_offs], 32, "CPTLF Misc%d", i);
		ret = cptlf_do_register_interrrupts(lfs, i, irq_offs,
						    cptlf_misc_intr_handler);
		if (ret)
			goto error;

		irq_offs = CPT_9X_LF_INT_VEC_E_DONE;
		snprintf(lfs->lf[i].irq_name[irq_offs], 32, "CPTLF Done%d", i);
		ret = cptlf_do_register_interrrupts(lfs, i, irq_offs,
						    cptlf_done_intr_handler);
		if (ret)
			goto error;
	}
error:
	return ret;
}

static void cptlf_unregister_interrupts(struct cptlfs_info *lfs)
{
	int i, offs;

	for (i = 0; i < lfs->lfs_num; i++)
		for (offs = 0; offs < CPT_9X_LF_MSIX_VECTORS; offs++)
			if (lfs->lf[i].is_irq_reg[offs]) {
				free_irq(pci_irq_vector(lfs->pdev,
							lfs->lf[i].msix_offset
							+ offs),
							&lfs->lf[i]);
				lfs->lf[i].is_irq_reg[offs] = false;
			}
}

static int cptlf_set_irqs_affinity(struct cptlfs_info *lfs)
{
	int slot, offs;
	int ret = 0;

	for (slot = 0; slot < lfs->lfs_num; slot++) {
		if (!zalloc_cpumask_var(&lfs->lf[slot].affinity_mask,
					GFP_KERNEL)) {
			dev_err(&lfs->pdev->dev,
				"cpumask allocation failed for LF %d", slot);
			return -ENOMEM;
		}

		cpumask_set_cpu(cpumask_local_spread(slot,
				dev_to_node(&lfs->pdev->dev)),
				lfs->lf[slot].affinity_mask);

		for (offs = 0; offs < CPT_9X_LF_MSIX_VECTORS; offs++) {
			ret = irq_set_affinity_hint(pci_irq_vector(lfs->pdev,
					lfs->lf[slot].msix_offset + offs),
					lfs->lf[slot].affinity_mask);
			if (ret)
				return ret;
		}
	}

	return ret;
}

static void cptlf_free_irqs_affinity(struct cptlfs_info *lfs)
{
	int slot, offs;

	for (slot = 0; slot < lfs->lfs_num; slot++) {
		for (offs = 0; offs < CPT_9X_LF_MSIX_VECTORS; offs++)
			irq_set_affinity_hint(pci_irq_vector(lfs->pdev,
					      lfs->lf[slot].msix_offset +
					      offs), NULL);
		free_cpumask_var(lfs->lf[slot].affinity_mask);
	}
}

static void cptlf_work_handler(unsigned long data)
{
	cpt9x_post_process((struct cptlf_wqe *) data);
}

static int init_tasklet_work(struct cptlfs_info *lfs)
{
	struct cptlf_wqe *wqe;
	int i;

	for (i = 0; i < lfs->lfs_num; i++) {
		wqe = kzalloc(sizeof(struct cptlf_wqe), GFP_KERNEL);
		if (!wqe)
			return -ENOMEM;

		tasklet_init(&wqe->work, cptlf_work_handler, (u64) wqe);
		wqe->lfs = lfs;
		wqe->lf_num = i;
		lfs->lf[i].wqe = wqe;
	}

	return 0;
}

static void cleanup_tasklet_work(struct cptlfs_info *lfs)
{
	int i;

	for (i = 0; i <  lfs->lfs_num; i++) {
		if (!lfs->lf[i].wqe)
			continue;

		tasklet_kill(&lfs->lf[i].wqe->work);
		kfree(lfs->lf[i].wqe);
		lfs->lf[i].wqe = NULL;
	}
}

static void free_pending_queues(struct cptlfs_info *lfs)
{
	int i;

	for (i = 0; i < lfs->lfs_num; i++) {
		kfree(lfs->lf[i].pqueue.head);
		lfs->lf[i].pqueue.head = NULL;
	}
}

static int alloc_pending_queues(struct cptlfs_info *lfs)
{
	int ret = 0;
	int size, i;

	if (!lfs->lfs_num)
		return -EINVAL;

	for (i = 0; i < lfs->lfs_num; i++) {
		lfs->lf[i].pqueue.qlen = CPT_INST_QLEN_MSGS;
		size = lfs->lf[i].pqueue.qlen *
		       sizeof(struct pending_entry);

		lfs->lf[i].pqueue.head = kzalloc(size, GFP_KERNEL);
		if (!lfs->lf[i].pqueue.head) {
			ret = -ENOMEM;
			goto error;
		}

		/* Initialize spin lock */
		spin_lock_init(&lfs->lf[i].pqueue.lock);
	}

	return 0;
error:
	free_pending_queues(lfs);
	return ret;
}

static int cptlf_sw_init(struct cptlfs_info *lfs)
{
	int ret = 0;

	ret = alloc_instruction_queues(lfs);
	if (ret) {
		dev_err(&lfs->pdev->dev,
			"Allocating instruction queues failed\n");
		goto error;
	}

	ret = alloc_pending_queues(lfs);
	if (ret) {
		dev_err(&lfs->pdev->dev,
			"Allocating pending queues failed\n");
		goto error;
	}

	ret = init_tasklet_work(lfs);
	if (ret) {
		dev_err(&lfs->pdev->dev,
			"Tasklet work init failed\n");
		goto error;
	}
error:
	return ret;
}

static void cptlf_sw_cleanup(struct cptlfs_info *lfs)
{
	cleanup_tasklet_work(lfs);
	free_pending_queues(lfs);
	free_instruction_queues(lfs);
}

void cpt9x_send_cmds_in_batch(union cpt_inst_s *cptinst, u32 num, void *obj)
{
	int i;

	for (i = 0; i < (num & 0xFFFFFFFE); i += 2)
		cpt9x_send_cmd(&cptinst[i], 2, obj);
	if (num & 0x1)
		cpt9x_send_cmd(&cptinst[num-1], 1, obj);
}

void cpt9x_send_cmds_for_speed_test(union cpt_inst_s *cptinst, u32 num,
				    void *obj)
{
	struct cptlf_info *lf = (struct cptlf_info *) obj;

	cptlf_do_disable_iqueue(lf);
	/* We set queue size to reset CPT_LF_Q_INST_PTR
	 * and CPT_LF_Q_GRP_PTR pointers
	 */
	cptlf_do_set_iqueue_size(lf);
	cptlf_enable_iqueue_enq(lf);

	cpt9x_send_cmds_in_batch(cptinst, num, obj);

	cptlf_enable_iqueue_exec(lf);
}

static ssize_t cptlf_coalesc_time_wait_show(struct device *dev,
					    struct device_attribute *attr,
					    char *buf)
{
	struct lf_sysfs_cfg *cfg;
	struct cptlf_info *lf;

	cfg = container_of(attr, struct lf_sysfs_cfg, coalesc_tw_attr);
	lf = container_of(cfg, struct cptlf_info, sysfs_cfg);

	return scnprintf(buf, PAGE_SIZE, "%d\n", cptlf_get_done_time_wait(lf));
}

static ssize_t cptlf_coalesc_time_wait_store(struct device *dev,
					     struct device_attribute *attr,
					     const char *buf, size_t count)
{
	struct lf_sysfs_cfg *cfg;
	struct cptlf_info *lf;
	long int val;
	int ret;

	ret = kstrtol(buf, 10, &val);
	if (ret != 0)
		return ret;

	if (val < CPT_COALESC_MIN_TIME_WAIT ||
	    val > CPT_COALESC_MAX_TIME_WAIT)
		return -EINVAL;

	cfg = container_of(attr, struct lf_sysfs_cfg, coalesc_tw_attr);
	lf = container_of(cfg, struct cptlf_info, sysfs_cfg);

	cptlf_do_set_done_time_wait(lf, val);
	return count;
}

static ssize_t cptlf_coalesc_num_wait_show(struct device *dev,
					   struct device_attribute *attr,
					   char *buf)
{
	struct lf_sysfs_cfg *cfg;
	struct cptlf_info *lf;

	cfg = container_of(attr, struct lf_sysfs_cfg, coalesc_nw_attr);
	lf = container_of(cfg, struct cptlf_info, sysfs_cfg);

	return scnprintf(buf, PAGE_SIZE, "%d\n", cptlf_get_done_num_wait(lf));
}

static ssize_t cptlf_coalesc_num_wait_store(struct device *dev,
					    struct device_attribute *attr,
					    const char *buf, size_t count)
{
	struct lf_sysfs_cfg *cfg;
	struct cptlf_info *lf;
	long int val;
	int ret;

	ret = kstrtol(buf, 10, &val);
	if (ret != 0)
		return ret;

	if (val < CPT_COALESC_MIN_NUM_WAIT ||
	    val > CPT_COALESC_MAX_NUM_WAIT)
		return -EINVAL;

	cfg = container_of(attr, struct lf_sysfs_cfg, coalesc_nw_attr);
	lf = container_of(cfg, struct cptlf_info, sysfs_cfg);

	cptlf_do_set_done_num_wait(lf, val);
	return count;
}

static ssize_t cptlf_priority_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	struct lf_sysfs_cfg *cfg;
	struct cptlf_info *lf;
	struct pci_dev *pdev;
	int pri, ret;

	cfg = container_of(attr, struct lf_sysfs_cfg, prio_attr);
	lf = container_of(cfg, struct cptlf_info, sysfs_cfg);
	pdev = container_of(dev, struct pci_dev, dev);

	ret = cptlf_get_pri(pdev, lf, &pri);
	if (ret)
		return ret;

	return scnprintf(buf, PAGE_SIZE, "%d\n", pri);
}

static ssize_t cptlf_priority_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	struct lf_sysfs_cfg *cfg;
	struct cptlf_info *lf;
	struct pci_dev *pdev;
	long int val;
	int ret;

	ret = kstrtol(buf, 10, &val);
	if (ret)
		return ret;

	if (val < QUEUE_LOW_PRIO ||
	    val > QUEUE_HI_PRIO)
		return -EINVAL;

	cfg = container_of(attr, struct lf_sysfs_cfg, prio_attr);
	lf = container_of(cfg, struct cptlf_info, sysfs_cfg);
	pdev = container_of(dev, struct pci_dev, dev);

	/* Queue's priority can be modified only if queue is quiescent */
	if (cptlf_get_inflight(lf)) {
		ret = -EPERM;
		goto err_print;
	}

	cptlf_disable_iqueue_exec(lf);

	if (cptlf_get_inflight(lf)) {
		ret = -EPERM;
		cptlf_enable_iqueue_exec(lf);
		goto err_print;
	}

	ret = cptlf_set_pri(pdev, lf, val);
	if (ret) {
		cptlf_enable_iqueue_exec(lf);
		goto err;
	}

	cptlf_enable_iqueue_exec(lf);
	return count;

err_print:
	dev_err(&pdev->dev,
		"Disable traffic before modifying queue's priority");
err:
	return ret;
}

static ssize_t cptlf_eng_grps_mask_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	struct lf_sysfs_cfg *cfg;
	struct cptlf_info *lf;
	struct pci_dev *pdev;
	int eng_grps_mask;
	int ret;

	cfg = container_of(attr, struct lf_sysfs_cfg, eng_grps_mask_attr);
	lf = container_of(cfg, struct cptlf_info, sysfs_cfg);
	pdev = container_of(dev, struct pci_dev, dev);

	ret = cptlf_get_eng_grps_mask(pdev, lf, &eng_grps_mask);
	if (ret)
		return ret;

	return scnprintf(buf, PAGE_SIZE, "0x%2.2X\n", eng_grps_mask);
}

static ssize_t cptlf_eng_grps_mask_store(struct device *dev,
					 struct device_attribute *attr,
					 const char *buf, size_t count)
{
	struct lf_sysfs_cfg *cfg;
	struct cptlf_info *lf;
	struct pci_dev *pdev;
	long int val;
	int ret;

	ret = kstrtol(buf, 16, &val);
	if (ret)
		return ret;

	if (val < 1 ||
	    val > ALL_ENG_GRPS_MASK)
		return -EINVAL;

	cfg = container_of(attr, struct lf_sysfs_cfg, eng_grps_mask_attr);
	lf = container_of(cfg, struct cptlf_info, sysfs_cfg);
	pdev = container_of(dev, struct pci_dev, dev);

	/* Queue's engine groups mask can be
	 * modified only if queue is quiescent
	 */
	if (cptlf_get_inflight(lf)) {
		ret = -EPERM;
		goto err_print;
	}

	cptlf_disable_iqueue_exec(lf);

	if (cptlf_get_inflight(lf)) {
		ret = -EPERM;
		cptlf_enable_iqueue_exec(lf);
		goto err_print;
	}

	ret = cptlf_set_eng_grps_mask(pdev, lf, val);
	if (ret) {
		cptlf_enable_iqueue_exec(lf);
		goto err;
	}

	cptlf_enable_iqueue_exec(lf);
	return count;

err_print:
	dev_err(&pdev->dev,
		"Disable traffic before modifying queue's engine groups mask");
err:
	return ret;
}

static void cptlf_delete_sysfs_cfg(struct cptlfs_info *lfs)
{
	struct lf_sysfs_cfg *cfg;
	int i;

	for (i = 0; i < lfs->lfs_num; i++) {
		cfg = &lfs->lf[i].sysfs_cfg;
		if (cfg->is_sysfs_grp_created) {
			sysfs_remove_group(&lfs->pdev->dev.kobj,
					   &cfg->attr_grp);
			cfg->is_sysfs_grp_created = false;
		}
	}
}

static int cptlf_create_sysfs_cfg(struct cptlfs_info *lfs)
{
	struct lf_sysfs_cfg *cfg;
	int i, ret = 0;

	for (i = 0; i < lfs->lfs_num; i++) {
		cfg = &lfs->lf[i].sysfs_cfg;
		snprintf(cfg->name, NAME_LENGTH, "cpt_queue%d", i);

		cfg->eng_grps_mask_attr.show = cptlf_eng_grps_mask_show;
		cfg->eng_grps_mask_attr.store = cptlf_eng_grps_mask_store;
		cfg->eng_grps_mask_attr.attr.name = "eng_grps_mask";
		cfg->eng_grps_mask_attr.attr.mode = 0664;
		sysfs_attr_init(&cfg->eng_grps_mask_attr.attr);

		cfg->coalesc_tw_attr.show = cptlf_coalesc_time_wait_show;
		cfg->coalesc_tw_attr.store = cptlf_coalesc_time_wait_store;
		cfg->coalesc_tw_attr.attr.name = "coalescence_time_wait";
		cfg->coalesc_tw_attr.attr.mode = 0664;
		sysfs_attr_init(&cfg->coalesc_tw_attr.attr);

		cfg->coalesc_nw_attr.show = cptlf_coalesc_num_wait_show;
		cfg->coalesc_nw_attr.store = cptlf_coalesc_num_wait_store;
		cfg->coalesc_nw_attr.attr.name = "coalescence_num_wait";
		cfg->coalesc_nw_attr.attr.mode = 0664;
		sysfs_attr_init(&cfg->coalesc_nw_attr.attr);

		cfg->prio_attr.show = cptlf_priority_show;
		cfg->prio_attr.store = cptlf_priority_store;
		cfg->prio_attr.attr.name = "priority";
		cfg->prio_attr.attr.mode = 0664;
		sysfs_attr_init(&cfg->prio_attr.attr);

		cfg->attrs[0] = &cfg->eng_grps_mask_attr.attr;
		cfg->attrs[1] = &cfg->coalesc_tw_attr.attr;
		cfg->attrs[2] = &cfg->coalesc_nw_attr.attr;
		cfg->attrs[3] = &cfg->prio_attr.attr;
		cfg->attrs[ATTRS_NUM - 1] = NULL;

		cfg->attr_grp.name = cfg->name;
		cfg->attr_grp.attrs = cfg->attrs;
		ret = sysfs_create_group(&lfs->pdev->dev.kobj,
					 &cfg->attr_grp);
		if (ret)
			goto err;
		cfg->is_sysfs_grp_created = true;
	}

	return 0;
err:
	cptlf_delete_sysfs_cfg(lfs);
	return ret;
}

int cptlf_init(struct pci_dev *pdev, void *reg_base,
	       struct cptlfs_info *lfs, int lfs_num)
{
	u8 blkaddr = cpt_get_blkaddr(pdev);
	int slot, ret = 0;

	lfs->reg_base = reg_base;
	lfs->lfs_num = lfs_num;
	lfs->pdev = pdev;
	lfs->ops = cpt9x_get_reqmgr_ops();
	for (slot = 0; slot < lfs->lfs_num; slot++) {
		lfs->lf[slot].lfs = lfs;
		lfs->lf[slot].slot = slot;
		lfs->lf[slot].lmtline = lfs->reg_base +
			RVU_FUNC_ADDR_S(BLKADDR_LMT, slot, LMT_LF_LMTLINEX(0));
		lfs->lf[slot].ioreg = lfs->reg_base +
			RVU_FUNC_ADDR_S(blkaddr, slot, CPT_LF_NQX(0));
	}

	/* Send request to attach LFs */
	ret = cpt_attach_rscrs_msg(pdev);
	if (ret)
		goto cpt_err;

	/* Get msix offsets for attached LFs */
	ret = cpt_msix_offset_msg(pdev);
	if (ret)
		goto cpt_err_detach;

	/* Initialize LFs software side */
	ret = cptlf_sw_init(lfs);
	if (ret)
		goto cpt_err_detach;

	/* Register LFs interrupts */
	ret = cptlf_register_interrupts(lfs);
	if (ret)
		goto cpt_err_sw_cleanup;

	/* Initialize LFs hardware side */
	cptlf_hw_init(lfs);

	/* Allow each LF to execute requests destined to any of 8 engine
	 * groups and set queue priority of each LF to high
	 */
	ret = cptlf_set_grp_and_pri(pdev, lfs, ALL_ENG_GRPS_MASK,
				    QUEUE_HI_PRIO);
	if (ret)
		goto cpt_err_unregister_interrupts;

	/* Set interrupts affinity */
	ret = cptlf_set_irqs_affinity(lfs);
	if (ret)
		goto cpt_err_unregister_interrupts;

	/* Create sysfs configuration entries */
	ret = cptlf_create_sysfs_cfg(lfs);
	if (ret)
		goto cpt_err_unregister_interrupts;

	/* Enable interrupts */
	cptlf_enable_misc_intrs(lfs);
	cptlf_enable_done_intr(lfs);

	/* Register crypto algorithms */
	ret = cvm_crypto_init(pdev, THIS_MODULE, cpt9x_get_algs_ops(),
			      CPT_96XX, SE_TYPES, lfs_num, 1);
	if (ret) {
		dev_err(&pdev->dev, "algorithms registration failed\n");
		goto cpt_err_disable_irqs;
	}

	return 0;

cpt_err_disable_irqs:
	cptlf_disable_done_intr(lfs);
	cptlf_disable_misc_intrs(lfs);
	cptlf_free_irqs_affinity(lfs);
	cptlf_hw_cleanup(lfs);
cpt_err_unregister_interrupts:
	cptlf_unregister_interrupts(lfs);
cpt_err_sw_cleanup:
	cptlf_sw_cleanup(lfs);
cpt_err_detach:
	cpt_detach_rscrs_msg(pdev);
cpt_err:
	return ret;
}

int cptlf_shutdown(struct pci_dev *pdev, struct cptlfs_info *lfs)
{
	int ret = 0;

	/* Unregister crypto algorithms */
	cvm_crypto_exit(pdev, THIS_MODULE, SE_TYPES);

	/* Disable interrupts */
	cptlf_disable_done_intr(lfs);
	cptlf_disable_misc_intrs(lfs);

	/* Remove interrupts affinity */
	cptlf_free_irqs_affinity(lfs);

	/* Remove sysfs configuration entries */
	cptlf_delete_sysfs_cfg(lfs);

	/* Cleanup LFs hardware side */
	cptlf_hw_cleanup(lfs);

	/* Unregister LFs interrupts */
	cptlf_unregister_interrupts(lfs);

	/* Cleanup LFs software side */
	cptlf_sw_cleanup(lfs);

	/* Send request to detach LFs */
	ret = cpt_detach_rscrs_msg(pdev);
	if (ret)
		goto error;
error:
	return ret;
}
