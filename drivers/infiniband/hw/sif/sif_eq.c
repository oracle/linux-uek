/*
 * Copyright (c) 2011, 2015, Oracle and/or its affiliates. All rights reserved.
 *    Author: Knut Omang <knut.omang@oracle.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * Driver for Oracle Scalable Infiniband Fabric (SIF) Host Channel Adapters
 *
 * sif_eq.c: Setup of event queues and interrupt handling
 */

#include "sif_dev.h"
#include "sif_eq.h"
#include "sif_qp.h"
#include "sif_defs.h"
#include "sif_query.h"
#include "sif_base.h"
#include "sif_dma.h"
#include "sif_elog.h"
#include "sif_hwi.h"
#include "sif_ibqp.h"
#include "psif_hw_csr.h"
#include "psif_hw_setget.h"
#include <linux/seq_file.h>

static int sif_map_irq(struct sif_eq *eq);
static int sif_request_irq(struct sif_eq *eq);

static int sif_irq_coalesce(struct sif_eq *eq);

static void sif_unmap_irq(struct sif_eq *eq);

static int sif_eq_table_init(struct sif_dev *sdev, struct sif_eps *es, u16 eq_idx);
static void sif_eq_table_deinit(struct sif_dev *sdev, struct sif_eps *es, u16 eq_idx);

static void sif_eq_deinit_tables(struct sif_dev *sdev, struct sif_eps *es);

static int dispatch_eq(struct sif_eq *eq);

static enum ib_event_type epsc2ib_event(struct psif_eq_entry *eqe);

/* Work elements for dispatching events at non-interrupt level
 */
struct event_work {
	struct work_struct ws;
	struct ib_event ibe;
	struct sif_eq *eq;
};

/* Define accessor functions - see sif_defs.h */
sif_define_entry_funcs(eq, int)

/* Set up the event queues using info about #of queues from the @cqe
 * which contains a host byte order copy of the successful response
 * to the configuration request to the EPS-C.
 * The EPS-C event queue which receives the async events is always
 * index 0
 */
int sif_eq_init(struct sif_dev *sdev, struct sif_eps *es, struct psif_epsc_csr_rsp *cqe)
{
	int ret = 0;
	int i;
	int cnt;
	struct sif_eq_base *eqb = &es->eqs;
	struct sif_eq *eq;

	cnt = es->eqs.cnt;
	sif_log(sdev, SIF_INIT, "setting up %d event queues for EPS%s", cnt,
		eps_name(sdev, es->eps_num));

	eq = (struct sif_eq *)
		kzalloc(sizeof(struct sif_eq) * cnt, GFP_KERNEL);
	if (!eq)
		return -ENOMEM;

	eqb->eq = eq;
	for (i = 0; i < cnt; i++) {
		ret = sif_eq_table_init(sdev, es, i);
		if (ret) {
			eqb->cnt = i;
			goto eqi_failed;
		}
	}

	eqb->cnt = cnt;

	if (cnt) {
		/* Request irq for the EPS interrupt queue only - all the rest
		 * of the interrupts can be enabled explicitly using sif_eq_request_irq_all
		 * when we are ready to process events of all kinds.
		 * See Orabug: 24296729
		 */
		ret = sif_request_irq(&eq[0]);
		if (ret)
			goto eqi_failed;
	}
	return 0;

eqi_failed:
	sif_eq_deinit_tables(sdev, es);
	kfree(eqb->eq);
	eqb->eq = NULL;
	return ret;
}

/* Request irq for all eqs still not requested for */
int sif_eq_request_irq_all(struct sif_eps *es)
{
	int ret;
	int i;

	for (i = 0; i < es->eqs.cnt; i++) {
		struct sif_eq *eq = &es->eqs.eq[i];
		if (!eq->requested) {
			ret = sif_request_irq(eq);
			if (ret)
				return ret;
		}
	}
	return 0;
}

static void sif_eq_deinit_tables(struct sif_dev *sdev, struct sif_eps *es)
{
	int i;

	for (i = es->eqs.cnt - 1; i >= 0; i--)
		sif_eq_table_deinit(sdev, es, i);
	es->eqs.cnt = 0;
}


void sif_eq_deinit(struct sif_dev *sdev, struct sif_eps *es)
{
	if (es->eqs.cnt > 0)
		sif_eq_deinit_tables(sdev, es);

	kfree(es->eqs.eq);
	es->eqs.eq = NULL;
}

static int sif_set_affinity_mask_hint(struct sif_dev *sdev, struct sif_eq *eq)
{
	int numa_node = dev_to_node(&sdev->pdev->dev);
	int cpu;

	if (!zalloc_cpumask_var(&eq->affinity_mask, GFP_KERNEL))
		return -ENOMEM;

	cpu = cpumask_local_spread(eq->index, numa_node);
	cpumask_set_cpu(cpu, eq->affinity_mask);
	return 0;
}


/* Bit field for #entries in hw is 5 bits wide */
#define SIF_MAX_EQ_ENTRIES (1 << 0x1f)

/* Set up of a single EQ requested by an EPS.
 * This code is quite similar to base table setup in sif_base.c - sif_table_init
 * but since we do not have the base_layout for each of these tables since
 * we do not know the number of tables in advance, we cannot use the same code.
 * We also need separat accessor functions and use a dynamically allocated array
 * of sif_eq objects with some more extra info in addition to the sif_table
 */
static int sif_eq_table_init(struct sif_dev *sdev, struct sif_eps *es, u16 eq_idx)
{
	struct sif_eq *eq = &es->eqs.eq[eq_idx];
	volatile struct psif_eq_entry *eqe;
	struct sif_table *tp = &eq->ba;
	int extent;  /* As log2 */
	int ret = 0;
	u32 min_entries, headroom;

	struct psif_epsc_csr_req req; /* local epsc wr copy */
	struct psif_epsc_csr_rsp resp;

	memset(eq, 0, sizeof(*eq));
	eq->eps = es;
	eq->index = tp->type = eq_idx; /* We *reuse* type with a different meaning here */
	eq->next_seq = 0;
	tp->sdev = sdev;
	tp->ext_sz = roundup_pow_of_two(sizeof(struct psif_eq_entry));
	tp->is_eq = true;  /* To distinguish namespace from other base tables */

	/* Event queue sizes: It is critical that these are sized for worst case.
	 * The size of event queues used for completions must be large enough to
	 * receive at least one entry from each associated completion queue.
	 * The async event queue (queue 1) must be scaled to fit every possible event.
	 * See sec.36.2.3. Event Queue Sizing, page 361 in the PSIF PRM.
	 */

	switch (eq_idx)	{
	case 0: /* Async + epsc events */
		headroom = sif_epsc_eq_headroom;
		min_entries = es->eps_num == sdev->mbox_epsc ?
			(sif_epsc_size + headroom + 2*es->eqs.min_sw_entry_cnt + 1)
			: 64;
		break;
	case 1:
		/* TSU - asynchronous events: */
		headroom = sif_tsu_eq_headroom;
		min_entries = es->eps_num == sdev->mbox_epsc ?
			7 * sif_qp_size + 2 * sif_rq_size + sif_cq_size + 9 + headroom : 64;
		break;
	default:
		/* completion notification events coming here
		 * TBD: We might want to scale the sizes of each of these queues and limit
		 * the number of CQs to handle by each of them instead:
		 */
		headroom = sif_tsu_eq_headroom;
		min_entries = es->eps_num == sdev->mbox_epsc ? sif_cq_size + headroom : 64;
		break;
	}

	eq->entries = tp->entry_cnt = roundup_pow_of_two(min_entries);
	eq->sw_index_interval = eq->entries - min_entries + headroom;
	if (!eq->sw_index_interval)
		eq->sw_index_interval = 1; /* Always update case */
	eq->sw_index_next_update = eq->sw_index_interval;

	if (eq->entries > SIF_MAX_EQ_ENTRIES) {
		sif_log(sdev, SIF_INFO,
			"requested %d entries but sif only supports %d",
			eq->entries, SIF_MAX_EQ_ENTRIES);
		return -ENFILE; /* 5 bit size_log2 field in eq descs in psif */
	}

	eq->mask = eq->entries - 1;
	eq->extent = tp->ext_sz;
	tp->table_sz = (size_t)tp->ext_sz * tp->entry_cnt;
	extent = order_base_2(tp->ext_sz);

	sif_alloc_table(tp, tp->table_sz);
	if (!tp->mem) {
		sif_log(sdev, SIF_INIT,
			"Failed to allocate 0x%lx bytes of memory for event queue table %d",
			tp->table_sz, eq_idx);
		return -ENOMEM;
	}

	ret = sif_set_affinity_mask_hint(sdev, eq);
	if (ret)
		goto err_map_ctx;

	/* No MMU translations from EPS-C in PSIF Rev 2 or SIBS rev 1 */
	if (epsc_gva_permitted(sdev) && eq_idx == 0 && tp->mem->mem_type != SIFMT_BYPASS) {
		sif_log(sdev, SIF_INFO,
			"Rev 2.0 does not support MMU translations from EPS-C");
		ret = -EINVAL;
		goto err_map_ctx;
	}

	eq->mem = tp->mem;

	/* Make sure the initial value of entry 0's seq.no is is different from a real event */
	eqe = (struct psif_eq_entry *)get_eq_entry(eq, 0);
	set_psif_eq_entry__seq_num(eqe, eq->entries);

	sif_log(sdev, SIF_INIT,
		"Event queue %d: entry cnt %d (min.req.%d), ext sz %d, extent %d, sw_index_interval %d",
		eq_idx, tp->entry_cnt, min_entries, tp->ext_sz, extent, eq->sw_index_interval);
	sif_log(sdev, SIF_INIT,	" - table sz 0x%lx %s sif_base 0x%llx",
		tp->table_sz, sif_mem_type_str(tp->mem->mem_type),
		tp->sif_base);

	spin_lock_init(&tp->lock);

	/* Set up HW descriptor */
	memset(&req, 0, sizeof(req));

	req.opcode = EPSC_SET_BASEADDR_EQ;
	req.u.base_addr.address = tp->sif_base;
	req.u.base_addr.num_entries = tp->entry_cnt;
	req.u.base_addr.extent_log2 = extent;
	req.addr = eq_idx; /* The "CSR address" for this operation is the index of the queue */

	/* Allocate mmu context with wr_access set */
	ret = sif_map_ctx(sdev, &tp->mmu_ctx, tp->mem, tp->sif_base, tp->table_sz, true);
	if (ret) {
		sif_log(sdev, SIF_INFO, "Failed to set mmu context for eq %d",
			eq_idx);
		goto err_map_ctx;
	}

	/* Allocate an irq index (but do not yet enable interrupts on it) */
	ret = sif_map_irq(eq);
	if (ret)
		goto err_map_irq;

	/* Pass the populated mmu context on to the EPS */
	req.u.base_addr.mmu_context = tp->mmu_ctx.mctx;

	req.u.base_addr.msix_index = eq->intr_vec;

	ret = sif_eps_wr_poll(sdev, es->eps_num, &req, &resp);
	if (ret)
		goto err_epsc_comm;

	/* Default interrupt channel coalescing settings */
	if (eq_idx != 0 && eps_version_ge(&sdev->es[sdev->mbox_epsc], 0, 36)) {
		ret = sif_irq_coalesce(eq);
		if (ret)
			goto err_epsc_comm;
	}

	return 0;

err_epsc_comm:
	sif_unmap_irq(eq);
err_map_irq:
	sif_unmap_ctx(sdev, &tp->mmu_ctx);
err_map_ctx:
	sif_free_table(tp);
	return ret;
}


static void sif_eq_table_deinit(struct sif_dev *sdev, struct sif_eps *es, u16 eq_idx)
{
	struct sif_eq *eq = &es->eqs.eq[eq_idx];
	struct sif_table *tp = &eq->ba;

	sif_unmap_irq(eq);

	if (tp->mem) {
		sif_unmap_ctx(sdev, &tp->mmu_ctx);
		sif_free_table(tp);
		tp->mem = NULL;
	}
}


/* Interrupt routines for MSI-X */

static irqreturn_t sif_intr(int irq, void *d)
{
	u32 nreqs;
	struct sif_eq *eq = (struct sif_eq *)d;
	struct sif_dev *sdev = eq->ba.sdev;
	nreqs = dispatch_eq(eq);
	sif_log(sdev, SIF_INTR,
		"done [irq %d (eq %d) - %d events dispatched]",
		irq, eq->index, nreqs);

	if (sif_feature(check_all_eqs_on_intr)) {
		int i;
		struct sif_eps *es = &sdev->es[sdev->mbox_epsc];

		sif_log(sdev, SIF_INTR, "feature check_all_eqs_on_intr - dispatching:");
		for (i = 0; i < es->eqs.cnt; i++)
			if (i != eq->index)
				dispatch_eq(&es->eqs.eq[i]);
		sif_log(sdev, SIF_INTR, "feature check_all_eqs_on_intr - dispatch done.");
		/* Note: this feature does not check the EPSA* interrupt queues */
	}

	return IRQ_HANDLED;
}

/* Interrupt coalescing settings for a single channel */
static int sif_irq_coalesce(struct sif_eq *eq)
{
	int ret;
	struct sif_dev *s = eq->ba.sdev;
	struct psif_epsc_csr_req req; /* local epsc wr copy */
	struct psif_epsc_csr_rsp resp;

	if (!eps_version_ge(&s->es[s->mbox_epsc], 0, 36))
		goto opcode_not_available;

	sif_log(s, SIF_INTR, "Set default coalescing settings for the interrupt channel %d\n",
		eq->index);

	memset(&req, 0, sizeof(req));

	req.opcode = EPSC_HOST_INT_CHANNEL_CTRL;
	req.uf = 0;
	req.u.int_channel.int_channel = eq->index;
#define SET_DEFAULT_HOST_INT_CTRL_SETTING(attr, _value) {		\
		int value = ((sif_feature(dis_auto_int_coalesce)) ||	\
			     (eq->index < 2)) ? 0 : _value;		\
		req.u.int_channel.attributes.attr = 1;			\
		req.u.int_channel.attr =  value;			\
		eq->irq_ch.attr = value;				\
	}
	SET_DEFAULT_HOST_INT_CTRL_SETTING(enable_adaptive, 1);
	SET_DEFAULT_HOST_INT_CTRL_SETTING(channel_rx_scale, 1);
	SET_DEFAULT_HOST_INT_CTRL_SETTING(channel_rate_low, 0);
	SET_DEFAULT_HOST_INT_CTRL_SETTING(channel_rate_high, 200000);
	SET_DEFAULT_HOST_INT_CTRL_SETTING(channel_ausec, 0);
	SET_DEFAULT_HOST_INT_CTRL_SETTING(channel_ausec_low, 0);
	SET_DEFAULT_HOST_INT_CTRL_SETTING(channel_ausec_high, 190);
	SET_DEFAULT_HOST_INT_CTRL_SETTING(channel_pusec, 0);
	SET_DEFAULT_HOST_INT_CTRL_SETTING(channel_pusec_low, 0);
	SET_DEFAULT_HOST_INT_CTRL_SETTING(channel_pusec_high, 10);

	ret = sif_epsc_wr_poll(s, &req, &resp);
	if (ret) {
		sif_log(s, SIF_INFO,
			"Failed to initialize the coalescing settings for interrupt channel %d\n",
			eq->index);
		memset(&eq->irq_ch, 0, sizeof(eq->irq_ch));
		return ret;
	}

	return 0;
opcode_not_available:
	return -1;
}

/* Set up interrupt handling for a single event queue (but do not enable interrupts) */
static int sif_map_irq(struct sif_eq *eq)
{
	int vector_num;
	struct sif_dev *s = eq->ba.sdev;
	const char *en;

	spin_lock(&s->msix_lock);
	vector_num = find_next_zero_bit(s->intr_used, s->msix_entries_sz, 0);
	if (vector_num < s->msix_entries_sz)
		set_bit(vector_num, s->intr_used);
	else
		vector_num = -1;
	spin_unlock(&s->msix_lock);

	if (vector_num == -1) {
		sif_log(s, SIF_INFO, "Failed to allocate an irq for eq %d", eq->index);
		return -ENOMEM;
	}

	en = eps_name(s, eq->eps->eps_num);

	if (eq->index)
		snprintf(eq->name, SIF_EQ_NAME_LEN, "sif%d-%d", 0, eq->index);
	else
		snprintf(eq->name, SIF_EQ_NAME_LEN, "sif%d-EPS%s", 0, en);

	sif_log(s, SIF_INFO_V, "Allocated irq %d for EPS%s, eq %d, name %s",
		s->msix_entries[vector_num].vector, en,	eq->index, eq->name);
	eq->intr_vec = vector_num;
	return 0;
}


static int sif_request_irq(struct sif_eq *eq)
{
	int irq;
	int vector_num = eq->intr_vec;
	struct sif_dev *s = eq->ba.sdev;
	int ret = 0;
	int flags = (s->intr_cnt !=  s->intr_req) ? IRQF_SHARED : 0;

	irq = s->msix_entries[vector_num].vector;
	ret = request_irq(irq, &sif_intr, flags, eq->name, eq);
	if (ret)
		return ret;

	eq->requested = true;
	ret = irq_set_affinity_hint(irq, eq->affinity_mask);
	if (ret)
		sif_log(s, SIF_INFO_V, "set affinity hint for irq %d, failed", irq);
	return ret;
}


static void sif_unmap_irq(struct sif_eq *eq)
{
	struct sif_dev *s = eq->ba.sdev;
	int irq = s->msix_entries[eq->intr_vec].vector;

	free_cpumask_var(eq->affinity_mask);
	if (eq->requested) {
		irq_set_affinity_hint(irq, NULL);
		free_irq(irq, eq);
	}
	spin_lock(&s->msix_lock);
	clear_bit(eq->intr_vec, s->intr_used);
	spin_unlock(&s->msix_lock);
	eq->intr_vec = -1;
	sif_log(s, SIF_INTR, "Freed irq %d for EPS%s", irq, eps_name(s, eq->eps->eps_num));
}


int sif_enable_msix(struct sif_dev *sdev)
{
	int err;
	int i = -1;
	int cnt = sdev->es[sdev->mbox_epsc].eqs.cnt + 4;
	int array_alloc_cnt = cnt;
	int bitmap_words = max(1, array_alloc_cnt + 63 / 64);

	sdev->msix_entries = kcalloc(array_alloc_cnt, sizeof(struct msix_entry), GFP_KERNEL);
	if (!sdev->msix_entries)
		return -ENOMEM;

	sdev->msix_entries_sz = array_alloc_cnt;
	sdev->intr_used = kcalloc(bitmap_words, sizeof(ulong), GFP_KERNEL);
	if (!sdev->intr_used) {
		err = -ENOMEM;
		goto iu_failed;
	}

	sif_log(sdev, SIF_INIT,
		"EPSC offers %ld event queues, need %ld + 4 for the EPSA's = %d vecs, array sz %d",
		sdev->es[sdev->mbox_epsc].eqs.max_cnt, sdev->es[sdev->mbox_epsc].eqs.cnt,
		cnt, array_alloc_cnt);
	spin_lock_init(&sdev->msix_lock);

	for (i = 0; i < cnt; i++)
		sdev->msix_entries[i].entry = i;

	err = pci_enable_msix_range(sdev->pdev, sdev->msix_entries, 1, cnt);
	if (err < 0) {
		sif_log(sdev, SIF_INFO,
			"Failed to allocate %d MSI-X vectors", cnt);
		goto vector_alloc_failed;
	}

	if (err < cnt)
		sif_log(sdev, SIF_INFO,
			"Unable to allocate more than %d MSI-X vectors", err);

	sdev->intr_req = cnt;
	sdev->intr_cnt = err;
	return 0;

vector_alloc_failed:
	kfree(sdev->intr_used);
iu_failed:
	kfree(sdev->msix_entries);
	return err;
}


int sif_disable_msix(struct sif_dev *sdev)
{
	pci_disable_msix(sdev->pdev);
	kfree(sdev->intr_used);
	kfree(sdev->msix_entries);
	return 0;
}


/* simple allocation of EPSC EQ channels for CQs: Just do round robin for now: */
u32 sif_get_eq_channel(struct sif_dev *sdev, struct sif_cq *cq)
{
	struct sif_eps *es = &sdev->es[sdev->mbox_epsc];
	u32 seq = atomic_inc_return(&es->eqs.eq_sel_seq);

	/* This is supposed to be a number between 0 and cnt - 2 as the EPSC EQ and the
	 * EQ for async events are not counted by hardware, so the first eilgible EQ
	 * is eq[2] which for hardware has index 0:
	 */
	u32 eqs_cnt = (u32) (es->eqs.cnt - 2);

	return seq % eqs_cnt;
}

/* check a valid EQ channel */
bool sif_check_valid_eq_channel(struct sif_dev *sdev, int comp_vector)
{
	struct sif_eps *es = &sdev->es[sdev->mbox_epsc];
	u32 eqs_cnt = (u32) (es->eqs.cnt - 2);

	return ((comp_vector >= 0) && (comp_vector <= eqs_cnt) ? true : false);
}

/* @eqe contains little endian copy of event triggering the call
 *   - called from interrupt level
 *  Returns the number of events handled
 */
static u32 handle_completion_event(struct sif_eq *eq, struct psif_eq_entry *eqe)
{
	u32 ret = 1;
	struct sif_dev *sdev = eq->ba.sdev;
	struct sif_cq *cq = safe_get_sif_cq(sdev, eqe->cqd_id);

	if (!cq) {
		sif_log(sdev, SIF_INTR, "eq %d: CQ Event seq %d: invalid or out-of-range cqd_id %d",
			eq->index, eqe->seq_num, eqe->cqd_id);
		return 0;
	}
	if (atomic_add_unless(&cq->refcnt, 1, 0)) {
		u32 ec = atomic_inc_return(&cq->event_cnt);

		sif_log(sdev, SIF_INTR, "eq %d: Processing PSIF_EVENT_COMPLETION event #%d, seq %d - cq %d",
			eq->index, ec, eqe->seq_num, eqe->cqd_id);
		if (unlikely(!cq->ibcq.comp_handler)) {
			/* This should not be possible - hw error? */
			sif_log(sdev, SIF_INFO,
				"eq %d: No handler for PSIF_EVENT_COMPLETION event seq %d on cq %d",
				eq->index, eqe->seq_num, eqe->cqd_id);
			ret = 0;
		} else
			cq->ibcq.comp_handler(&cq->ibcq, cq->ibcq.cq_context);

		if (atomic_dec_and_test(&cq->refcnt))
			complete(&cq->cleanup_ok);

	} else {
		/* TBD: We end up here also if an event was processed after the cq was destroyed
		 * but before the cq was reallocated again. We may consequently also
		 * get "spurious" events on a new CQ that was a delayed event from the previous
		 * usage but that should be ok.
		 */
		sif_log(sdev, SIF_INFO,
			"eq %d: PSIF_EVENT_COMPLETION event seq %d - cq %d for invalid cq",
			eq->index, eqe->seq_num, eqe->cqd_id);
		ret = 0;
	}
	return ret;
}


static void handle_event_work(struct work_struct *work)
{
	struct event_work *ew = container_of(work, struct event_work, ws);
	struct sif_dev *sdev = to_sdev(ew->ibe.device);

	atomic_inc(&ew->eq->work_cnt);

	if (unlikely(!sdev->registered)) {
		wait_for_completion_interruptible(&sdev->ready_for_events);
	}

	switch (ew->ibe.event) {
	case IB_EVENT_CQ_ERR: {
		struct ib_cq *cq = ew->ibe.element.cq;

		if (cq->event_handler)
			cq->event_handler(&ew->ibe, cq->cq_context);
		else
			sif_log(sdev, SIF_INFO,
				"Unhandled event of type %s received",
				ib_event2str(ew->ibe.event));
		break;
	}
	case IB_EVENT_SRQ_LIMIT_REACHED:
	case IB_EVENT_SRQ_ERR: {
		struct ib_srq *srq = ew->ibe.element.srq;

		if (ew->ibe.event == IB_EVENT_SRQ_LIMIT_REACHED)
			to_srq(srq)->srq_limit = 0;

		if (srq->event_handler)
			srq->event_handler(&ew->ibe, srq->srq_context);
		else
			sif_log(sdev, SIF_INFO,
				"Unhandled event of type %s received, srq %d",
				ib_event2str(ew->ibe.event), to_srq(srq)->index);
		break;
	}
	case IB_EVENT_QP_FATAL:
	case IB_EVENT_QP_REQ_ERR:
	case IB_EVENT_QP_ACCESS_ERR:
	case IB_EVENT_PATH_MIG_ERR:
	case IB_EVENT_QP_LAST_WQE_REACHED: {
		struct ib_qp *ibqp = ew->ibe.element.qp;
		struct sif_qp *qp = to_sqp(ibqp);
		struct sif_rq *rq = get_rq(sdev, qp);

		if (rq) {
			struct sif_rq_sw *rq_sw = get_sif_rq_sw(sdev, rq->index);

			/* WA #3850:if SRQ, generate LAST_WQE event */
			if (rq->is_srq && ibqp->event_handler) {
				struct ib_event ibe = {
					.device = &sdev->ib_dev,
					.event = IB_EVENT_QP_LAST_WQE_REACHED,
					.element.qp = &qp->ibqp
				};
				ibqp->event_handler(&ibe, ibqp->qp_context);
			} else {
				/* WA #622: if reqular RQ, flush */
				if (sif_flush_rq_wq(sdev, rq, qp, atomic_read(&rq_sw->length)))
					sif_log(sdev, SIF_INFO, "failed to flush RQ %d",
						rq->index);
			}
		}
		if (!ibqp->event_handler)
			sif_log(sdev, SIF_INFO,
				"Unhandled event of type %s received, qp %d",
				ib_event2str(ew->ibe.event), qp->qp_idx);
		/* fall through */
	}
	case IB_EVENT_PATH_MIG:
	case IB_EVENT_COMM_EST: {
		struct ib_qp *ibqp = ew->ibe.element.qp;
		struct sif_qp *qp = to_sqp(ibqp);

		/* IB spec o11-5.1.1 says suppress COMM_EST event for UD & RAW QP types.
		 * Also, avoid sending COMM_EST to MAD layer (it reports fatal error).
		 */
		if ((ew->ibe.event == IB_EVENT_COMM_EST)
			&& ((ibqp->qp_type == IB_QPT_GSI)
			|| (ibqp->qp_type == IB_QPT_UD)
			|| (ibqp->qp_type == IB_QPT_RAW_IPV6)
			|| (ibqp->qp_type == IB_QPT_RAW_ETHERTYPE)
			|| (ibqp->qp_type == IB_QPT_RAW_PACKET))) {
			if (atomic_dec_and_test(&qp->refcnt))
				complete(&qp->can_destroy);
			break;
		}

		if (ibqp->event_handler) {
			ibqp->event_handler(&ew->ibe, ibqp->qp_context);
		} else {
			sif_log(sdev, SIF_INFO,
				"Unhandled event of type %s received, qp %d",
				ib_event2str(ew->ibe.event), qp->qp_idx);
		}

		if (atomic_dec_and_test(&qp->refcnt))
			complete(&qp->can_destroy);

		break;
	}
	case IB_EVENT_LID_CHANGE:
		if (PSIF_REVISION(sdev) <= 3)
			sif_r3_recreate_flush_qp(sdev, ew->ibe.element.port_num - 1);
	case IB_EVENT_PORT_ERR:
	case IB_EVENT_CLIENT_REREGISTER:
	case IB_EVENT_PORT_ACTIVE:
	case IB_EVENT_DEVICE_FATAL:
	case IB_EVENT_PKEY_CHANGE:
	case IB_EVENT_GID_CHANGE:
	case IB_EVENT_SM_CHANGE:
		ib_dispatch_event(&ew->ibe);
		break;
	default:
		sif_log(sdev, SIF_INFO, "Unhandled event type %d", ew->ibe.event);
		break;
	}
	kfree(ew);
}

/* Generic event handler - @eqe contains little endian copy of event triggering the call
 * ib_dispatch_event dispatches directly so we have to defer the actual dispatch
 * a better priority level via sdev->wq:
 */

static u32 handle_event(struct sif_eq *eq, void *element, enum ib_event_type ev_type)
{
	struct sif_dev *sdev = eq->ba.sdev;
	struct event_work *ew = kmalloc(sizeof(struct event_work), GFP_ATOMIC);

	if (!ew) {
		/* TBD: kmem_cache_alloc or fallback static necessary? */
		sif_log(sdev, SIF_INFO, "FATAL: Failed to allocate work struct");
		return 0;
	}
	memset(&ew->ibe, 0, sizeof(struct ib_event));
	ew->ibe.device = &sdev->ib_dev;
	ew->ibe.event = ev_type;
	ew->eq = eq;

	/* Assume ibe.element is a union and that our caller has
	 * set up the right value for us (port, cq, qp or srq):
	 */
	ew->ibe.element.cq = element;
	INIT_WORK(&ew->ws, handle_event_work);

	sif_log(sdev, SIF_INTR, "Processing IB event type %s",
		ib_event2str(ew->ibe.event));
	queue_work(sdev->wq, &ew->ws);
	return 1;
}

static u32 handle_psif_event(struct sif_eq *eq, struct psif_eq_entry *eqe,
			const char *type_str)
{
	struct sif_dev *sdev = eq->ba.sdev;

	sif_log(sdev, SIF_INFO, "Received (unhandled) psif event of type %s, port flags %s",
		type_str,
		string_enum_psif_event(eqe->port_flags));
	return 1;
}

static u32 handle_epsc_event(struct sif_eq *eq, struct psif_eq_entry *eqe)
{
	struct sif_dev *sdev = eq->ba.sdev;
	struct sif_eps *es = &sdev->es[eq->eps->eps_num];
	u32 ret = 1;
	enum psif_event event_type;

	if (eqe->port_flags == PSIF_EVENT_EXTENSION)
		event_type = eqe->extension_type;
	else
		event_type = eqe->port_flags;

	switch (event_type) {
	case PSIF_EVENT_MAILBOX:
		sif_log(sdev, SIF_INTR, "epsc completion event for seq.%d eps_num %d",
			eqe->cq_sequence_number, eq->eps->eps_num);
		epsc_complete(sdev, eq->eps->eps_num, eqe->cq_sequence_number & es->mask);
		break;
	case PSIF_EVENT_LOG:
		sif_log(sdev, SIF_INTR, "epsc log event");
		sif_elog_intr(sdev, sdev->mbox_epsc);
		break;
	case PSIF_EVENT_EPSC_KEEP_ALIVE:
		sif_log(sdev, SIF_INTR, "epsc keep-alive event");
		sif_eps_send_keep_alive(sdev, eq->eps->eps_num, true);
		break;
	default:
	{
		enum ib_event_type ibe = epsc2ib_event(eqe);

		if (ibe != (enum ib_event_type)-1) {
			void *element = (void *)((u64) eqe->port + 1);

			return handle_event(eq, element, ibe);
		}
		sif_log(sdev, SIF_INFO, "Unhandled epsc event of type %s::%s (%d::%u)",
			string_enum_psif_event(eqe->port_flags),
			string_enum_psif_event(eqe->extension_type),
			eqe->port_flags, eqe->extension_type);
		if (eqe->extension_type == PSIF_EVENT_DEGRADED_MODE) {
			sdev->degraded = true;
			epsc_report_degraded(sdev, eqe->event_data);
		}
		ret = 0;
		break;
	}
	}
	return ret;
}


static u32 handle_epsa_event(struct sif_eq *eq, struct psif_eq_entry *eqe)
{
	struct sif_dev *sdev = eq->ba.sdev;

	sif_log(sdev, SIF_INFO, "Received (unhandled) epsa event of type %s",
		string_enum_psif_event(eqe->port_flags));
	return 1;
}

#define check_for_psif_event(__event__)\
		if (leqe.__event__)\
			nevents += handle_psif_event(eq, &leqe, #__event__)

/* Bug #3952 - WA for HW bug #3523 (leqe.rqd_id is not valid)
 * If QP transport is different from XRC
 * and the QP is not already destroyed
 * then retrieve the rq_idx from the QP
 * Note: For SRQ_LIM event due to modify_srq, QP points to pQP.
 */
static u32 handle_srq_event(struct sif_eq *eq, void *element, enum ib_event_type ev_type)
{
	if (element != NULL) {
		struct sif_dev *sdev = eq->ba.sdev;
		struct sif_qp *qp = to_sqp(element);
		enum psif_qp_trans type = qp->type;
		struct sif_rq *rq = (ev_type == IB_EVENT_SRQ_LIMIT_REACHED &&
				     type == PSIF_QP_TRANSPORT_MANSP1) ?
			get_sif_rq(sdev, qp->srq_idx) : get_sif_rq(sdev, qp->rq_idx);

		/* release the qp lock */
		if (atomic_dec_and_test(&qp->refcnt))
			complete(&qp->can_destroy);

		return handle_event(eq, (void *)&rq->ibsrq, ev_type);
	}
	sif_log(eq->ba.sdev, SIF_INFO, "eq %d: Discarding %s event: QP destroyed", eq->index,
		ev_type == IB_EVENT_SRQ_ERR ? "IB_EVENT_SRQ_ERR" : "IB_EVENT_SRQ_LIMIT_REACHED");
	return 1;
}


#define dump_eq_entry(level, _s, _eqe)	\
	sif_logs(level, printk("%s: ", _s); \
		write_struct_psif_eq_entry(NULL, 0, &leqe); printk("\n"))


/* Called from interrupt threads */
static int dispatch_eq(struct sif_eq *eq)
{
	volatile struct psif_eq_entry *eqe;
	struct psif_eq_entry leqe;
	struct psif_epsc_csr_req req;
	struct sif_dev *sdev = eq->ba.sdev;

	u32 seqno;
	u32 nreqs = 0;
	ulong flags;
	void *port_elem;
	void *qp_elem = NULL;

	/* Serialize event queue processing: */
	spin_lock_irqsave(&eq->ba.lock, flags);
	seqno = eq->next_seq;
	eqe = (struct psif_eq_entry *)get_eq_entry(eq, seqno);
	sif_log(sdev, SIF_INTR, "eqe at %p next seq.no %x", eqe, seqno);
	while (get_psif_eq_entry__seq_num(eqe) == seqno) {
		u32 nevents = 0;

		eq->next_seq++;

		/* Update eq_sw::index if necessary */
		if (eq->next_seq == eq->sw_index_next_update) {
			u32 old_nu = eq->sw_index_next_update;

			memset(&req, 0, sizeof(req));
			req.opcode = EPSC_EVENT_INDEX;
			req.addr = eq->index;
			req.u.single.data = eq->next_seq;
			eq->sw_index_next_update += eq->sw_index_interval;

			spin_unlock_irqrestore(&eq->ba.lock, flags);

			sif_log(eq->ba.sdev, SIF_INFO_V,
				"Updating EQ_SW_INDEX for eq %d to %x. Interval %x, lim %x, next lim %x",
				eq->index, eq->next_seq, eq->sw_index_interval, old_nu,
				eq->sw_index_next_update);

			/* We ignore the response by providing NULL for seq_num and lcqe */
			sif_post_eps_wr(eq->ba.sdev, eq->eps->eps_num, &req, NULL, NULL, false);
		} else {
			/* Avoid callbacks while interrupts off */
			spin_unlock_irqrestore(&eq->ba.lock, flags);
		}

		copy_conv_to_sw(&leqe, eqe, sizeof(leqe));

		port_elem = (void *)((u64) leqe.port + 1);

		if (likely(leqe.event_status_cmpl_notify)) {
			nevents += handle_completion_event(eq, &leqe);

			/* No other event type bits will be set on a CNE */
			goto only_cne;
		}

		dump_eq_entry(SIF_DUMP, " ", &leqe);

		/* TBD: Handle this check with a mask... */
		if (unlikely(leqe.event_status_local_work_queue_catastrophic_error ||
			     leqe.event_status_path_migration_request_error ||
			     leqe.event_status_invalid_request_local_wq_error ||
			     leqe.event_status_local_access_violation_wq_error ||
			     leqe.event_status_last_wqe_reached ||
			     leqe.event_status_communication_established ||
			     leqe.event_status_path_migrated ||
			     leqe.event_status_srq_limit_reached ||
			     leqe.event_status_srq_catastrophic_error ||
			     /* Affiliated async. error on XRC TGTQP mapped to IB_EVENT_QP_FATAL */
			     leqe.event_status_invalid_xrceth ||
			     leqe.event_status_xrc_domain_violation)) {
			struct sif_qp *sif_qp_elem = safe_get_sif_qp(sdev, leqe.qp);
			bool is_srq_event = (leqe.event_status_srq_limit_reached ||
					      leqe.event_status_srq_catastrophic_error);

			/* silently drop the event if qp is no longer there. */
			if (!sif_qp_elem) {
				sif_log(eq->ba.sdev, SIF_INFO, "QP context is NULL!");
				goto only_cne;
			}

			/* silently drop the event if it is a PQP. */
			if (unlikely(sif_qp_elem->type == PSIF_QP_TRANSPORT_MANSP1) &&
			    !leqe.event_status_srq_limit_reached) {
				sif_log(eq->ba.sdev, SIF_INFO, "Received async event on PQP!");
				goto only_cne;
			}

			if (unlikely(sif_qp_elem->type == PSIF_QP_TRANSPORT_XRC) && is_srq_event) {
				sif_log(sdev, SIF_INTR,
					"eq %d: Discarding %s event: QP transport XRC",
					eq->index, leqe.event_status_srq_catastrophic_error ?
					"IB_EVENT_SRQ_ERR" : "IB_EVENT_SRQ_LIMIT_REACHED");
				goto only_cne;
			}

			/* check whether a qp context is required */
			if (PSIF_REVISION(sdev) <= 3 || !is_srq_event) {
				/* silently drop the event if qp has been destroyed at this point. */
				if (!atomic_add_unless(&sif_qp_elem->refcnt, 1, 0)) {
					sif_log(sdev, SIF_INTR,
						"eq %d: qp %d has been destroyed for event seq %d",
						eq->index, sif_qp_elem->qp_idx, eqe->seq_num);
					goto only_cne;
				}
				qp_elem = (void *) &sif_qp_elem->ibqp;
			}
		}

		if (leqe.event_status_eps_c)
			nevents += handle_epsc_event(eq, &leqe);
		if (leqe.event_status_eps_a)
			nevents += handle_epsa_event(eq, &leqe);
		if (leqe.event_status_port_error)
			nevents += handle_event(eq, port_elem, IB_EVENT_PORT_ERR);
		if (leqe.event_status_client_registration)
			nevents += handle_event(eq, port_elem, IB_EVENT_CLIENT_REREGISTER);
		if (leqe.event_status_port_active)
			nevents += handle_event(eq, port_elem, IB_EVENT_PORT_ACTIVE);
		if (leqe.event_status_local_work_queue_catastrophic_error ||
			leqe.event_status_xrc_domain_violation ||
			leqe.event_status_invalid_xrceth) {
			nevents += handle_event(eq, qp_elem, IB_EVENT_QP_FATAL);
			dump_eq_entry(SIF_INFO, "Got Fatal error", &leqe);
		}
		if (leqe.event_status_srq_catastrophic_error)
			nevents += PSIF_REVISION(sdev) <= 3 ?
				handle_srq_event(eq, qp_elem, IB_EVENT_SRQ_ERR) :
				handle_event(eq, &get_sif_rq(sdev, leqe.rqd_id)->ibsrq, IB_EVENT_SRQ_ERR);
		if (leqe.event_status_path_migration_request_error)
			nevents += handle_event(eq, qp_elem, IB_EVENT_PATH_MIG_ERR);
		if (leqe.event_status_local_access_violation_wq_error)
			nevents += handle_event(eq, qp_elem, IB_EVENT_QP_ACCESS_ERR);
		if (leqe.event_status_invalid_request_local_wq_error)
			nevents += handle_event(eq, qp_elem, IB_EVENT_QP_REQ_ERR);
		if (leqe.event_status_last_wqe_reached)
			nevents += handle_event(eq, qp_elem,
						IB_EVENT_QP_LAST_WQE_REACHED);
		if (leqe.event_status_srq_limit_reached)
			nevents += PSIF_REVISION(sdev) <= 3 ?
				handle_srq_event(eq, qp_elem, IB_EVENT_SRQ_LIMIT_REACHED) :
				handle_event(eq, &get_sif_rq(sdev, leqe.rqd_id)->ibsrq,
					IB_EVENT_SRQ_LIMIT_REACHED);
		if (leqe.event_status_communication_established)
			nevents += handle_event(eq, qp_elem, IB_EVENT_COMM_EST);
		if (leqe.event_status_path_migrated)
			nevents += handle_event(eq, qp_elem, IB_EVENT_PATH_MIG);
		if (leqe.event_status_cq_error) {
			nevents += handle_event(eq, &get_sif_cq(sdev, leqe.cqd_id)->ibcq,
						IB_EVENT_CQ_ERR);
			dump_eq_entry(SIF_INFO, "Got cq_error", &leqe);
		}
		if (leqe.event_status_local_catastrophic_error)
			nevents += handle_event(eq, port_elem, IB_EVENT_DEVICE_FATAL);


		/* TBD: These are the ones that do not map directly to IB errors */
		check_for_psif_event(event_status_port_changed);

		if (!nevents) {
			sif_log(eq->ba.sdev, SIF_INTR, "eq %d: Warning: No events found for seq 0x%x",
				eq->index, seqno);
			dump_eq_entry(SIF_INFO, "(no event processed)", &leqe);
		} else
			sif_log(eq->ba.sdev, SIF_INTR, "Handled %d set event bits", nevents);

only_cne:
		spin_lock_irqsave(&eq->ba.lock, flags);
		seqno = eq->next_seq;
		eqe = (struct psif_eq_entry *)get_eq_entry(eq, seqno);
		nreqs++;
	}
	spin_unlock_irqrestore(&eq->ba.lock, flags);
	atomic_add(nreqs, &eq->intr_cnt);
	return nreqs;
}


static enum ib_event_type epsc2ib_event(struct psif_eq_entry *eqe)
{
	switch (eqe->port_flags) {
	case PSIF_EVENT_SGID_TABLE_CHANGED:
		return IB_EVENT_GID_CHANGE;
	case PSIF_EVENT_PKEY_TABLE_CHANGED:
		return IB_EVENT_PKEY_CHANGE;
	case PSIF_EVENT_MASTER_SM_LID_CHANGED:
	case PSIF_EVENT_MASTER_SM_SL_CHANGED:
	case PSIF_EVENT_IS_SM_DISABLED_CHANGED:
		return IB_EVENT_SM_CHANGE;
	case PSIF_EVENT_LID_TABLE_CHANGED:
		return IB_EVENT_LID_CHANGE;
	case PSIF_EVENT_SUBNET_TIMEOUT_CHANGED:
	case PSIF_EVENT_CLIENT_REREGISTER:
		return IB_EVENT_CLIENT_REREGISTER;
	case PSIF_EVENT_PORT_ACTIVE:
		return IB_EVENT_PORT_ACTIVE;
	case PSIF_EVENT_PORT_ERR:
		return IB_EVENT_PORT_ERR;
	default:
		return (enum ib_event_type)-1;
	}
}


void sif_dfs_print_eq(struct seq_file *s, struct sif_dev *sdev,
		loff_t pos)
{
	struct sif_eq *eq;

	if (unlikely(pos < 0)) {
		seq_printf(s, "#   sii = software index update interval\n"
			"#   niu = (index of) next software index update\n#\n"
			"#   ni = Number of events seen\n"
			"#   wi = Number of events handled in work queue\n"
			"# Name\tindex\tentries\textent\tn.seq\tvector#\tIRQ#\t"
			"#ni\t#wi\tsii\tniu\n");
		return;
	}

	eq = &sdev->es[sdev->mbox_epsc].eqs.eq[pos];

	seq_printf(s, "%-12s%u\t%u\t%u\t%u\t%d\t%d\t%u\t%u\t%u\t%u\n",
		eq->name, eq->index, eq->entries, eq->extent, eq->next_seq, eq->intr_vec,
		sdev->msix_entries[eq->intr_vec].vector,
		atomic_read(&eq->intr_cnt), atomic_read(&eq->work_cnt),
		eq->sw_index_interval, eq->sw_index_next_update);
}

void sif_dfs_print_irq_ch(struct seq_file *s, struct sif_dev *sdev,
			loff_t pos)
{
	struct sif_eq *eq;

	if (unlikely(pos < 0)) {
		seq_printf(s, "#   Interrupt channel coalescing settings\n#\n"
			"# echo \"channel=1;adaptive=0;rx_scale=0;rate_low=0;"
			"rate_high=0;ausec=0;ausec_low=0;ausec_high=0;pusec=0;"
			"pusec_low=0;pusec_high=0\" > irq_ch\n#\n\n"
			"# Channel  adaptive  rx_scale  rate_low  rate_high  ausec  ausec_low  ausec_high  pusec  pusec_low  pusec_high\n");
		return;
	}

	eq = &sdev->es[sdev->mbox_epsc].eqs.eq[pos];
	seq_printf(s, "%-11s%-10u%-10u%-10u%-11u%-7d%-11d%-12u%-7u%-11u%-12u\n",
		   eq->name, eq->irq_ch.enable_adaptive, eq->irq_ch.channel_rx_scale,
		   eq->irq_ch.channel_rate_low, eq->irq_ch.channel_rate_high,
		   eq->irq_ch.channel_ausec, eq->irq_ch.channel_ausec_low,
		   eq->irq_ch.channel_ausec_high, eq->irq_ch.channel_pusec,
		   eq->irq_ch.channel_pusec_low, eq->irq_ch.channel_pusec_high);
}
