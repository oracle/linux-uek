// SPDX-License-Identifier: GPL-2.0
/* Marvell CN10K DRAM Subsystem (DSS) Performance Monitor Driver
 *
 * Copyright (C) 2021 Marvell.
 */

#include <linux/init.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/perf_event.h>
#include <linux/hrtimer.h>

/* Performance Counters Operating Mode Control Registers */
#define DDRC_PERF_CNT_OP_MODE_CTRL	0x8020
#define OP_MODE_CTRL_VAL_MANUAL		0x1

/* Performance Counters Start Operation Control Registers */
#define DDRC_PERF_CNT_START_OP_CTRL	0x8028
#define START_OP_CTRL_VAL_START		0x1ULL
#define START_OP_CTRL_VAL_ACTIVE	0x2

/* Performance Counters End Operation Control Registers */
#define DDRC_PERF_CNT_END_OP_CTRL	0x8030
#define END_OP_CTRL_VAL_END		0x1ULL

/* Performance Counters End Status Registers */
#define DDRC_PERF_CNT_END_STATUS		0x8038
#define END_STATUS_VAL_END_TIMER_MODE_END	0x1

/* Performance Counters Configuration Registers */
#define DDRC_PERF_CFG_BASE		0x8040

/* 8 Generic event counter + 2 fixed event counters */
#define DDRC_PERF_NUM_GEN_COUNTERS	8
#define DDRC_PERF_NUM_FIX_COUNTERS	2
#define DDRC_PERF_READ_COUNTER_IDX	DDRC_PERF_NUM_GEN_COUNTERS
#define DDRC_PERF_WRITE_COUNTER_IDX	(DDRC_PERF_NUM_GEN_COUNTERS + 1)
#define DDRC_PERF_NUM_COUNTERS		(DDRC_PERF_NUM_GEN_COUNTERS + \
					 DDRC_PERF_NUM_FIX_COUNTERS)

/* Generic event counter registers */
#define DDRC_PERF_CFG(n)		(DDRC_PERF_CFG_BASE + 8 * (n))
#define EVENT_ENABLE			BIT_ULL(63)

/* Two dedicated event counters for DDR reads and writes */
#define EVENT_DDR_READS			101
#define EVENT_DDR_WRITES		100

/* One event counter for Memory bandwidth measurement */
#define EVENT_MBWC_READS		0
#define DDRC_PERF_READ_MBWC_IDX		0

/*
 * Programmable events IDs in programmable event counters.
 * DO NOT change these event-id numbers, they are used to
 * program event bitmap in h/w.
 */
#define EVENT_OP_IS_ZQLATCH			55
#define EVENT_OP_IS_ZQSTART			54
#define EVENT_OP_IS_TCR_MRR			53
#define EVENT_OP_IS_DQSOSC_MRR			52
#define EVENT_OP_IS_DQSOSC_MPC			51
#define EVENT_VISIBLE_WIN_LIMIT_REACHED_WR	50
#define EVENT_VISIBLE_WIN_LIMIT_REACHED_RD	49
#define EVENT_BSM_STARVATION			48
#define EVENT_BSM_ALLOC				47
#define EVENT_LPR_REQ_WITH_NOCREDIT		46
#define EVENT_HPR_REQ_WITH_NOCREDIT		45
#define EVENT_OP_IS_ZQCS			44
#define EVENT_OP_IS_ZQCL			43
#define EVENT_OP_IS_LOAD_MODE			42
#define EVENT_OP_IS_SPEC_REF			41
#define EVENT_OP_IS_CRIT_REF			40
#define EVENT_OP_IS_REFRESH			39
#define EVENT_OP_IS_ENTER_MPSM			35
#define EVENT_OP_IS_ENTER_POWERDOWN		31
#define EVENT_OP_IS_ENTER_SELFREF		27
#define EVENT_WAW_HAZARD			26
#define EVENT_RAW_HAZARD			25
#define EVENT_WAR_HAZARD			24
#define EVENT_WRITE_COMBINE			23
#define EVENT_RDWR_TRANSITIONS			22
#define EVENT_PRECHARGE_FOR_OTHER		21
#define EVENT_PRECHARGE_FOR_RDWR		20
#define EVENT_OP_IS_PRECHARGE			19
#define EVENT_OP_IS_MWR				18
#define EVENT_OP_IS_WR				17
#define EVENT_OP_IS_RD				16
#define EVENT_OP_IS_RD_ACTIVATE			15
#define EVENT_OP_IS_RD_OR_WR			14
#define EVENT_OP_IS_ACTIVATE			13
#define EVENT_WR_XACT_WHEN_CRITICAL		12
#define EVENT_LPR_XACT_WHEN_CRITICAL		11
#define EVENT_HPR_XACT_WHEN_CRITICAL		10
#define EVENT_DFI_RD_DATA_CYCLES		9
#define EVENT_DFI_WR_DATA_CYCLES		8
#define EVENT_ACT_BYPASS			7
#define EVENT_READ_BYPASS			6
#define EVENT_HIF_HI_PRI_RD			5
#define EVENT_HIF_RMW				4
#define EVENT_HIF_RD				3
#define EVENT_HIF_WR				2
#define EVENT_HIF_RD_OR_WR			1

/* Event counter value registers */
#define DDRC_PERF_CNT_VALUE_BASE		0x8080
#define DDRC_PERF_CNT_VALUE(n)	(DDRC_PERF_CNT_VALUE_BASE + 8 * (n))

/* Fixed event counter enable/disable register */
#define DDRC_PERF_CNT_FREERUN_EN	0x80C0
#define DDRC_PERF_FREERUN_WRITE_EN	0x1
#define DDRC_PERF_FREERUN_READ_EN	0x2

/* Fixed event counter control register */
#define DDRC_PERF_CNT_FREERUN_CTRL	0x80C8
#define DDRC_FREERUN_WRITE_CNT_CLR	0x1
#define DDRC_FREERUN_READ_CNT_CLR	0x2

/* Fixed event counter value register */
#define DDRC_PERF_CNT_VALUE_WR_OP	0x80D0
#define DDRC_PERF_CNT_VALUE_RD_OP	0x80D8
#define DDRC_PERF_CNT_VALUE_OVERFLOW	BIT_ULL(48)
#define DDRC_PERF_CNT_MAX_VALUE		GENMASK_ULL(48, 0)

/* Memory bandwidth related register */
#define PART_SEL			0x100
#define CUST_MBWC			0xA08
#define CUST_WINDOW			0xA0C

#define MBW_BASE			0x240000
#define OCTTX_NODE			"octeontx_brd"

bool is_probed_once;
long ddr_speed;

struct cn10k_ddr_pmu {
	struct pmu pmu;
	int id;
	void __iomem *base;
	void __iomem *mbw_base;
	unsigned int cpu;
	struct	device *dev;
	int active_events;
	struct perf_event *events[DDRC_PERF_NUM_COUNTERS];
	struct hrtimer hrtimer;
	struct hlist_node node;
};

#define to_cn10k_ddr_pmu(p)	container_of(p, struct cn10k_ddr_pmu, pmu)

static ssize_t cn10k_ddr_pmu_event_show(struct device *dev,
					struct device_attribute *attr,
					char *page)
{
	struct perf_pmu_events_attr *pmu_attr;

	pmu_attr = container_of(attr, struct perf_pmu_events_attr, attr);
	return sprintf(page, "event=0x%02llx\n", pmu_attr->id);
}

#define CN10K_DDR_PMU_EVENT_ATTR(_name, _id)				     \
	(&((struct perf_pmu_events_attr[]) {				     \
	{ .attr = __ATTR(_name, 0444, cn10k_ddr_pmu_event_show, NULL),	     \
		.id = _id, }						     \
	})[0].attr.attr)

static struct attribute *cn10k_ddr_perf_events_attrs[] = {
	/* MBWC */
	CN10K_DDR_PMU_EVENT_ATTR(ddr_mbwc_reads, EVENT_MBWC_READS),
	/* Programmable */
	CN10K_DDR_PMU_EVENT_ATTR(ddr_hif_rd_or_wr_access, EVENT_HIF_RD_OR_WR),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_hif_wr_access, EVENT_HIF_WR),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_hif_rd_access, EVENT_HIF_RD),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_hif_rmw_access, EVENT_HIF_RMW),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_hif_pri_rdaccess, EVENT_HIF_HI_PRI_RD),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_rd_bypass_access, EVENT_READ_BYPASS),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_act_bypass_access, EVENT_ACT_BYPASS),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_dfi_wr_data_access, EVENT_DFI_WR_DATA_CYCLES),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_dfi_rd_data_access, EVENT_DFI_RD_DATA_CYCLES),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_hpri_sched_rd_crit_access,
					EVENT_HPR_XACT_WHEN_CRITICAL),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_lpri_sched_rd_crit_access,
					EVENT_LPR_XACT_WHEN_CRITICAL),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_wr_trxn_crit_access,
					EVENT_WR_XACT_WHEN_CRITICAL),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_cam_active_access, EVENT_OP_IS_ACTIVATE),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_cam_rd_or_wr_access, EVENT_OP_IS_RD_OR_WR),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_cam_rd_active_access, EVENT_OP_IS_RD_ACTIVATE),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_cam_read, EVENT_OP_IS_RD),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_cam_write, EVENT_OP_IS_WR),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_cam_mwr, EVENT_OP_IS_MWR),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_precharge, EVENT_OP_IS_PRECHARGE),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_precharge_for_rdwr, EVENT_PRECHARGE_FOR_RDWR),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_precharge_for_other,
					EVENT_PRECHARGE_FOR_OTHER),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_rdwr_transitions, EVENT_RDWR_TRANSITIONS),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_write_combine, EVENT_WRITE_COMBINE),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_war_hazard, EVENT_WAR_HAZARD),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_raw_hazard, EVENT_RAW_HAZARD),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_waw_hazard, EVENT_WAW_HAZARD),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_enter_selfref, EVENT_OP_IS_ENTER_SELFREF),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_enter_powerdown, EVENT_OP_IS_ENTER_POWERDOWN),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_enter_mpsm, EVENT_OP_IS_ENTER_MPSM),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_refresh, EVENT_OP_IS_REFRESH),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_crit_ref, EVENT_OP_IS_CRIT_REF),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_spec_ref, EVENT_OP_IS_SPEC_REF),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_load_mode, EVENT_OP_IS_LOAD_MODE),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_zqcl, EVENT_OP_IS_ZQCL),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_cam_wr_access, EVENT_OP_IS_ZQCS),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_hpr_req_with_nocredit,
					EVENT_HPR_REQ_WITH_NOCREDIT),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_lpr_req_with_nocredit,
					EVENT_LPR_REQ_WITH_NOCREDIT),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_bsm_alloc, EVENT_BSM_ALLOC),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_bsm_starvation, EVENT_BSM_STARVATION),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_win_limit_reached_rd,
					EVENT_VISIBLE_WIN_LIMIT_REACHED_RD),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_win_limit_reached_wr,
					EVENT_VISIBLE_WIN_LIMIT_REACHED_WR),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_dqsosc_mpc, EVENT_OP_IS_DQSOSC_MPC),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_dqsosc_mrr, EVENT_OP_IS_DQSOSC_MRR),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_tcr_mrr, EVENT_OP_IS_TCR_MRR),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_zqstart, EVENT_OP_IS_ZQSTART),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_zqlatch, EVENT_OP_IS_ZQLATCH),
	/* Free run event counters */
	CN10K_DDR_PMU_EVENT_ATTR(ddr_ddr_reads, EVENT_DDR_READS),
	CN10K_DDR_PMU_EVENT_ATTR(ddr_ddr_writes, EVENT_DDR_WRITES),
	NULL,
};

static struct attribute_group cn10k_ddr_perf_events_attr_group = {
	.name = "events",
	.attrs = cn10k_ddr_perf_events_attrs,
};

PMU_FORMAT_ATTR(event, "config:0-8");
PMU_FORMAT_ATTR(partid, "config1:0-15");

static struct attribute *cn10k_ddr_perf_format_attrs[] = {
	&format_attr_event.attr,
	&format_attr_partid.attr,
	NULL,
};

static struct attribute_group cn10k_ddr_perf_format_attr_group = {
	.name = "format",
	.attrs = cn10k_ddr_perf_format_attrs,
};

static ssize_t cn10k_ddr_perf_cpumask_show(struct device *dev,
					   struct device_attribute *attr,
					   char *buf)
{
	struct cn10k_ddr_pmu *pmu = dev_get_drvdata(dev);

	return cpumap_print_to_pagebuf(true, buf, cpumask_of(pmu->cpu));
}

static struct device_attribute cn10k_ddr_perf_cpumask_attr =
	__ATTR(cpumask, 0444, cn10k_ddr_perf_cpumask_show, NULL);

static struct attribute *cn10k_ddr_perf_cpumask_attrs[] = {
	&cn10k_ddr_perf_cpumask_attr.attr,
	NULL,
};

static struct attribute_group cn10k_ddr_perf_cpumask_attr_group = {
	.attrs = cn10k_ddr_perf_cpumask_attrs,
};

static const struct attribute_group *cn10k_attr_groups[] = {
	&cn10k_ddr_perf_events_attr_group,
	&cn10k_ddr_perf_format_attr_group,
	&cn10k_ddr_perf_cpumask_attr_group,
	NULL,
};

/*
 * Default poll timeout is 100 sec, which is very sufficient for
 * 48 bit counter per DDR controller incremented max at 5.6 GT/s,
 * which may take many hours to overflow.
 */
static unsigned long cn10k_ddr_pmu_poll_period_sec = 100;
module_param_named(poll_period_sec, cn10k_ddr_pmu_poll_period_sec, ulong, 0644);

static ktime_t cn10k_ddr_pmu_timer_period(void)
{
	return ms_to_ktime((u64)cn10k_ddr_pmu_poll_period_sec * 1000000ULL);
}

static uint64_t ddr_perf_get_event_bitmap(int eventid)
{
	uint64_t event_bitmap = 0;

	switch (eventid) {
	case EVENT_HIF_RD_OR_WR ... EVENT_WAW_HAZARD:
	case EVENT_OP_IS_REFRESH ... EVENT_OP_IS_ZQLATCH:
		event_bitmap = (1ULL << (eventid - 1));
		break;

	case EVENT_OP_IS_ENTER_SELFREF:
	case EVENT_OP_IS_ENTER_POWERDOWN:
	case EVENT_OP_IS_ENTER_MPSM:
		event_bitmap = (0xFULL << (eventid - 1));
		break;
	default:
		pr_err("%s Invalid eventid %d\n", __func__, eventid);
		break;
	}

	return event_bitmap;
}

static int cn10k_ddr_perf_alloc_counter(struct cn10k_ddr_pmu *pmu,
					struct perf_event *event)
{
	uint8_t config = event->attr.config;
	int i;

	/* DDR Memory bandwidth counter index */
	if (config == EVENT_MBWC_READS) {
		pmu->events[DDRC_PERF_READ_MBWC_IDX] = event;
		return DDRC_PERF_READ_MBWC_IDX;
	}

	/* DDR read free-run counter index */
	if (config == EVENT_DDR_READS) {
		pmu->events[DDRC_PERF_READ_COUNTER_IDX] = event;
		return DDRC_PERF_READ_COUNTER_IDX;
	}

	/* DDR write free-run counter index */
	if (config == EVENT_DDR_WRITES) {
		pmu->events[DDRC_PERF_WRITE_COUNTER_IDX] = event;
		return DDRC_PERF_WRITE_COUNTER_IDX;
	}

	/* Allocate DDR generic counters */
	for (i = 0; i < DDRC_PERF_NUM_GEN_COUNTERS; i++) {
		if (pmu->events[i] == NULL) {
			pmu->events[i] = event;
			return i;
		}
	}

	return -ENOENT;
}

static void cn10k_ddr_perf_free_counter(struct cn10k_ddr_pmu *pmu, int counter)
{
	pmu->events[counter] = NULL;
}

static int cn10k_ddr_perf_event_init(struct perf_event *event)
{
	struct cn10k_ddr_pmu *pmu = to_cn10k_ddr_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;

	if (event->attr.type != event->pmu->type)
		return -ENOENT;

	if (is_sampling_event(event)) {
		dev_info(pmu->dev, "Sampling not supported!\n");
		return -EOPNOTSUPP;
	}

	if (event->cpu < 0) {
		dev_warn(pmu->dev, "Can't provide per-task data!\n");
		return -EOPNOTSUPP;
	}

	/*  We must NOT create groups containing mixed PMUs */
	if (event->group_leader->pmu != event->pmu &&
			!is_software_event(event->group_leader))
		return -EINVAL;

	/*
	 * Set ownership of event to one CPU, same event can not be observed
	 * on multiple cpus at same time.
	 */
	event->cpu = pmu->cpu;
	hwc->idx = -1;
	return 0;
}

static void cn10k_ddr_perf_counter_enable(struct cn10k_ddr_pmu *pmu,
					  int counter, u16 partid,
					  bool enable)
{
	uint32_t reg;
	uint64_t val;

	if (counter > DDRC_PERF_NUM_COUNTERS) {
		pr_err("Error: unsupported counter %d\n", counter);
		return;
	}

	if (counter == DDRC_PERF_READ_MBWC_IDX) {
		if (enable)
			writel(partid, pmu->mbw_base + PART_SEL);
	} else if (counter < DDRC_PERF_NUM_GEN_COUNTERS) {
		reg = DDRC_PERF_CFG(counter);
		val = readq(pmu->base + reg);

		if (enable)
			val |= EVENT_ENABLE;
		else
			val &= ~EVENT_ENABLE;

		writeq(val, pmu->base + reg);
	} else {
		val = readq(pmu->base + DDRC_PERF_CNT_FREERUN_EN);
		if (enable) {
			if (counter == DDRC_PERF_READ_COUNTER_IDX)
				val |= DDRC_PERF_FREERUN_READ_EN;
			else
				val |= DDRC_PERF_FREERUN_WRITE_EN;
		} else {
			if (counter == DDRC_PERF_READ_COUNTER_IDX)
				val &= ~DDRC_PERF_FREERUN_READ_EN;
			else
				val &= ~DDRC_PERF_FREERUN_WRITE_EN;
		}
		writeq(val, pmu->base + DDRC_PERF_CNT_FREERUN_EN);
	}
}

static uint64_t cn10_ddr_raw_to_mbs(uint32_t raw_counter, uint32_t window)
{
	/*
	 * DFI clock frequency is 1/8 of data rate, for instance
	 * 3200 MT/s has 400 MHz core clock.
	 */
	uint32_t core_clk_period = ddr_speed / 8;
	uint64_t val;

	/*
	 * CUST_MBWC stores the accounted bandwidth of a PartID in
	 * terms of cycle count, convert it into B/s format using:
	 * (32B * CUST_MBWC)/(CUST_WINDOW * core_clk_period)
	 */
	val = (raw_counter * 32) * ((core_clk_period * 1000000UL) / window);
	val /= 1000000UL;

	return val;
}

static uint64_t cn10k_ddr_perf_get_mbw(struct cn10k_ddr_pmu *pmu)
{
	uint32_t raw_cnt_val, window_val, raw_cnt_sum = 0;

	raw_cnt_val = readl(pmu->mbw_base + CUST_MBWC);
	raw_cnt_sum +=  raw_cnt_val;
	/*
	 * we don't want cumulative count (from one channel) for
	 * bandwidth counters. So, once we read this counter,
	 * we program an invalid partid so that it just reads 0's
	 * for successive run.
	 */
	writel(0x40, pmu->mbw_base + PART_SEL);
	window_val = readl(pmu->mbw_base + CUST_WINDOW);

	return cn10_ddr_raw_to_mbs(raw_cnt_val, window_val);
}

static uint64_t cn10k_ddr_perf_read_counter(struct cn10k_ddr_pmu *pmu,
					    int counter)
{
	uint64_t val;

	if (counter == DDRC_PERF_READ_MBWC_IDX)
		return cn10k_ddr_perf_get_mbw(pmu);

	if (counter == DDRC_PERF_READ_COUNTER_IDX)
		return readq(pmu->base + DDRC_PERF_CNT_VALUE_RD_OP);

	if (counter == DDRC_PERF_WRITE_COUNTER_IDX)
		return readq(pmu->base + DDRC_PERF_CNT_VALUE_WR_OP);

	val = readq(pmu->base + DDRC_PERF_CNT_VALUE(counter));
	return val;
}

static void cn10k_ddr_perf_event_update(struct perf_event *event)
{
	struct cn10k_ddr_pmu *pmu = to_cn10k_ddr_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	uint64_t prev_count, new_count, mask;

	do {
		prev_count = local64_read(&hwc->prev_count);
		new_count = cn10k_ddr_perf_read_counter(pmu, hwc->idx);
	} while (local64_xchg(&hwc->prev_count, new_count) != prev_count);

	mask = DDRC_PERF_CNT_MAX_VALUE;

	local64_add((new_count - prev_count) & mask, &event->count);
}

static void cn10k_ddr_perf_event_start(struct perf_event *event, int flags)
{
	struct cn10k_ddr_pmu *pmu = to_cn10k_ddr_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	u16 partid = event->attr.config1;
	int counter = hwc->idx;

	local64_set(&hwc->prev_count, 0);

	cn10k_ddr_perf_counter_enable(pmu, counter, partid, true);

	hwc->state = 0;
}

static int cn10k_ddr_perf_event_add(struct perf_event *event, int flags)
{
	struct cn10k_ddr_pmu *pmu = to_cn10k_ddr_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	uint8_t config = event->attr.config;
	uint32_t reg_offset;
	uint64_t val;
	int counter;

	counter = cn10k_ddr_perf_alloc_counter(pmu, event);
	if (counter < 0) {
		dev_dbg(pmu->dev, "There are not enough counters\n");
		return -EOPNOTSUPP;
	}

	pmu->active_events++;
	hwc->idx = counter;

	if (pmu->active_events == 1)
		hrtimer_start(&pmu->hrtimer, cn10k_ddr_pmu_timer_period(),
			      HRTIMER_MODE_REL_PINNED);

	if (counter == DDRC_PERF_READ_MBWC_IDX) {
		/*
		 * Memory bandwidth counters are not
		 * configurable, it just count once proper
		 * partid is programmed into partition select
		 * register.
		 */
	} else if (counter < DDRC_PERF_NUM_GEN_COUNTERS) {
		/* Generic counters, configure event id */
		reg_offset = DDRC_PERF_CFG(counter);
		val = ddr_perf_get_event_bitmap(config);
		writeq(val, pmu->base + reg_offset);
	} else {
		/* fixed event counter, clear counter value */
		if (counter == DDRC_PERF_READ_COUNTER_IDX)
			val = DDRC_FREERUN_READ_CNT_CLR;
		else
			val = DDRC_FREERUN_WRITE_CNT_CLR;

		writeq(val, pmu->base + DDRC_PERF_CNT_FREERUN_CTRL);
	}

	hwc->state |= PERF_HES_STOPPED;

	if (flags & PERF_EF_START)
		cn10k_ddr_perf_event_start(event, flags);

	return 0;
}

static void cn10k_ddr_perf_event_stop(struct perf_event *event, int flags)
{
	struct cn10k_ddr_pmu *pmu = to_cn10k_ddr_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	u16 partid = event->attr.config1;
	int counter = hwc->idx;

	cn10k_ddr_perf_counter_enable(pmu, counter, partid, false);

	if (flags & PERF_EF_UPDATE)
		cn10k_ddr_perf_event_update(event);

	hwc->state |= PERF_HES_STOPPED;
}

static void cn10k_ddr_perf_event_del(struct perf_event *event, int flags)
{
	struct cn10k_ddr_pmu *pmu = to_cn10k_ddr_pmu(event->pmu);
	struct hw_perf_event *hwc = &event->hw;
	int counter = hwc->idx;

	cn10k_ddr_perf_event_stop(event, PERF_EF_UPDATE);

	cn10k_ddr_perf_free_counter(pmu, counter);
	pmu->active_events--;
	hwc->idx = -1;

	/* Cancel timer when no events to capture */
	if (pmu->active_events == 0)
		hrtimer_cancel(&pmu->hrtimer);
}

static void cn10k_ddr_perf_pmu_enable(struct pmu *pmu)
{
	struct cn10k_ddr_pmu *ddr_pmu = to_cn10k_ddr_pmu(pmu);

	writeq(START_OP_CTRL_VAL_START, ddr_pmu->base +
	       DDRC_PERF_CNT_START_OP_CTRL);
}

static void cn10k_ddr_perf_pmu_disable(struct pmu *pmu)
{
	struct cn10k_ddr_pmu *ddr_pmu = to_cn10k_ddr_pmu(pmu);

	writeq(END_OP_CTRL_VAL_END, ddr_pmu->base +
	       DDRC_PERF_CNT_END_OP_CTRL);
}

static void cn10k_ddr_perf_event_update_all(struct cn10k_ddr_pmu *pmu)
{
	struct hw_perf_event *hwc;
	int i;

	for (i = 0; i < DDRC_PERF_NUM_GEN_COUNTERS; i++) {
		if (pmu->events[i] == NULL)
			continue;

		cn10k_ddr_perf_event_update(pmu->events[i]);
	}

	/* Reset previous count as h/w counter are reset */
	for (i = 0; i < DDRC_PERF_NUM_GEN_COUNTERS; i++) {
		if (pmu->events[i] == NULL)
			continue;

		hwc = &pmu->events[i]->hw;
		local64_set(&hwc->prev_count, 0);
	}
}

static irqreturn_t cn10k_ddr_pmu_overflow_handler(struct cn10k_ddr_pmu *pmu)
{
	struct perf_event *event;
	struct hw_perf_event *hwc;
	uint64_t prev_count, new_count;
	uint64_t value;
	int i;

	event = pmu->events[DDRC_PERF_READ_COUNTER_IDX];
	if (event) {
		hwc = &event->hw;
		prev_count = local64_read(&hwc->prev_count);
		new_count = cn10k_ddr_perf_read_counter(pmu, hwc->idx);

		/*
		 * Overflow condition is when new count less than
		 * previous count
		 */
		if (new_count < prev_count)
			cn10k_ddr_perf_event_update(event);
	}

	event = pmu->events[DDRC_PERF_WRITE_COUNTER_IDX];
	if (event) {
		hwc = &event->hw;
		prev_count = local64_read(&hwc->prev_count);
		new_count = cn10k_ddr_perf_read_counter(pmu, hwc->idx);

		/*
		 * Overflow condition is when new count less than
		 * previous count
		 */
		if (new_count < prev_count)
			cn10k_ddr_perf_event_update(event);
	}

	for (i = 0; i < DDRC_PERF_NUM_GEN_COUNTERS; i++) {
		if (pmu->events[i] == NULL)
			continue;

		value = cn10k_ddr_perf_read_counter(pmu, i);
		if (value == DDRC_PERF_CNT_MAX_VALUE) {
			pr_info("Counter-(%d) reached max value\n", i);
			cn10k_ddr_perf_event_update_all(pmu);
			cn10k_ddr_perf_pmu_disable(&pmu->pmu);
			cn10k_ddr_perf_pmu_enable(&pmu->pmu);
		}
	}

	return IRQ_HANDLED;
}

static enum hrtimer_restart cn10k_ddr_pmu_timer_handler(struct hrtimer *hrtimer)
{
	struct cn10k_ddr_pmu *pmu = container_of(hrtimer, struct cn10k_ddr_pmu,
						 hrtimer);
	unsigned long flags;

	local_irq_save(flags);
	cn10k_ddr_pmu_overflow_handler(pmu);
	local_irq_restore(flags);

	hrtimer_forward_now(hrtimer, cn10k_ddr_pmu_timer_period());
	return HRTIMER_RESTART;
}

static int cn10k_ddr_pmu_offline_cpu(unsigned int cpu, struct hlist_node *node)
{
	struct cn10k_ddr_pmu *pmu = hlist_entry_safe(node, struct cn10k_ddr_pmu,
						     node);
	unsigned int target;

	if (cpu != pmu->cpu)
		return 0;

	target = cpumask_any_but(cpu_online_mask, cpu);
	if (target >= nr_cpu_ids)
		return 0;

	perf_pmu_migrate_context(&pmu->pmu, cpu, target);
	pmu->cpu = target;
	return 0;
}

static int cn10k_ddr_get_speed(void)
{
	struct device_node *np = NULL;
	const char *speed;
	int ret;

	np = of_find_node_by_name(NULL, OCTTX_NODE);
	if (!np) {
		pr_err("No board info available!\n");
		return -ENODEV;
	}

	ret = of_property_read_string(np, "DDR-SPEED", &speed);
	if (ret) {
		pr_err("DDR-SPEED property not found\n");
		return ret;
	}

	ret = kstrtol(speed, 0, &ddr_speed);
	if (ret < 0)
		return ret;

	return 0;
}

static int cn10k_ddr_perf_probe(struct platform_device *pdev)
{
	struct cn10k_ddr_pmu *ddr_pmu;
	struct resource *res;
	void __iomem *base;
	static int index;
	char *name;
	int ret;

	ddr_pmu = devm_kzalloc(&pdev->dev, sizeof(*ddr_pmu), GFP_KERNEL);
	if (!ddr_pmu)
		return -ENOMEM;

	ddr_pmu->dev = &pdev->dev;
	platform_set_drvdata(pdev, ddr_pmu);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(base))
		return PTR_ERR(base);

	ddr_pmu->base = base;
	ddr_pmu->mbw_base = ioremap_nocache(res->start + MBW_BASE,
						resource_size(res));

	if (!is_probed_once) {
		if (cn10k_ddr_get_speed())
			pr_err("Couldn't fetch speed for %s\n",
				pdev->name);
		is_probed_once = true;
	}

	/* Setup the PMU counter to work in manual mode */
	writeq(OP_MODE_CTRL_VAL_MANUAL, ddr_pmu->base +
	       DDRC_PERF_CNT_OP_MODE_CTRL);

	ddr_pmu->pmu = (struct pmu) {
		.module	      = THIS_MODULE,
		.capabilities = PERF_PMU_CAP_NO_EXCLUDE,
		.task_ctx_nr = perf_invalid_context,
		.attr_groups = cn10k_attr_groups,
		.event_init  = cn10k_ddr_perf_event_init,
		.add	     = cn10k_ddr_perf_event_add,
		.del	     = cn10k_ddr_perf_event_del,
		.start	     = cn10k_ddr_perf_event_start,
		.stop	     = cn10k_ddr_perf_event_stop,
		.read	     = cn10k_ddr_perf_event_update,
		.pmu_enable  = cn10k_ddr_perf_pmu_enable,
		.pmu_disable = cn10k_ddr_perf_pmu_disable,
	};

	/* Choose this cpu to collect perf data */
	ddr_pmu->cpu = raw_smp_processor_id();

	name = devm_kasprintf(ddr_pmu->dev, GFP_KERNEL, "mrvl_ddr_pmu@%llx",
			      res->start);
	if (!name)
		return -ENOMEM;

	hrtimer_init(&ddr_pmu->hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	ddr_pmu->hrtimer.function = cn10k_ddr_pmu_timer_handler;

	cpuhp_state_add_instance_nocalls(
				CPUHP_AP_PERF_ARM_MARVELL_CN10K_DDR_ONLINE,
				&ddr_pmu->node);

	ret = perf_pmu_register(&ddr_pmu->pmu, name, -1);
	if (ret)
		goto error;

	ddr_pmu->id = index++;
	pr_info("CN10K DDR PMU Driver for ddrc@%llx - id-%d\n",
		res->start, ddr_pmu->id);
	return 0;
error:
	cpuhp_state_remove_instance_nocalls(
				CPUHP_AP_PERF_ARM_MARVELL_CN10K_DDR_ONLINE,
				&ddr_pmu->node);
	return ret;
}

static int cn10k_ddr_perf_remove(struct platform_device *pdev)
{
	struct cn10k_ddr_pmu *ddr_pmu = platform_get_drvdata(pdev);

	cpuhp_state_remove_instance_nocalls(
				CPUHP_AP_PERF_ARM_MARVELL_CN10K_DDR_ONLINE,
				&ddr_pmu->node);

	perf_pmu_unregister(&ddr_pmu->pmu);
	return 0;
}

static const struct of_device_id cn10k_ddr_pmu_of_match[] = {
	{ .compatible = "marvell,cn10k-ddr-pmu", },
	{ },
};
MODULE_DEVICE_TABLE(of, cn10k_ddr_pmu_of_match);

static struct platform_driver cn10k_ddr_pmu_driver = {
	.driver	= {
		.name   = "cn10k-ddr-pmu",
		.of_match_table = cn10k_ddr_pmu_of_match,
		.suppress_bind_attrs = true,
	},
	.probe		= cn10k_ddr_perf_probe,
	.remove		= cn10k_ddr_perf_remove,
};

static int __init cn10k_ddr_pmu_init(void)
{
	int ret;

	ret = cpuhp_setup_state_multi(
				CPUHP_AP_PERF_ARM_MARVELL_CN10K_DDR_ONLINE,
				"perf/marvell/cn10k/ddr:online", NULL,
				cn10k_ddr_pmu_offline_cpu);
	if (ret)
		return ret;

	ret = platform_driver_register(&cn10k_ddr_pmu_driver);
	if (ret)
		cpuhp_remove_multi_state(
				CPUHP_AP_PERF_ARM_MARVELL_CN10K_DDR_ONLINE);
	return ret;
}

static void __exit cn10k_ddr_pmu_exit(void)
{
	platform_driver_unregister(&cn10k_ddr_pmu_driver);
	cpuhp_remove_multi_state(CPUHP_AP_PERF_ARM_MARVELL_CN10K_DDR_ONLINE);
}

module_init(cn10k_ddr_pmu_init);
module_exit(cn10k_ddr_pmu_exit);

MODULE_AUTHOR("Bharat Bhushan <bbhushan2@marvell.com>");
MODULE_LICENSE("GPL v2");
