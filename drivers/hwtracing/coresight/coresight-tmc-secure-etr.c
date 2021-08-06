// SPDX-License-Identifier: GPL-2.0

#include <linux/atomic.h>
#include <linux/coresight.h>
#include <linux/dma-mapping.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "coresight-etm4x.h"
#include "coresight-priv.h"
#include "coresight-tmc.h"
#include "coresight-quirks.h"
#include "coresight-tmc-secure-etr.h"

/* SW mode sync insertion interval
 *
 * Sync insertion interval for 1M is based on assumption of
 * trace data generated at  4bits/cycle ,cycle period of 0.4 ns
 * and atleast 4 syncs per buffer wrap.
 *
 * One limitation of fixing only 4 syncs per buffer wrap is that
 * we might loose 1/4 of the initial buffer data due to lack of sync.
 * But on the other hand, we could reduce the sync insertion frequency
 * by increasing the buffer size which seems to be a good compromise.
 */
#define SYNC_TICK_NS_PER_MB 200000 /* 200us */
#define SYNCS_PER_FILL 4

/* Global mode timer management */

/**
 * struct tmc_etr_tsync_global - Global mode timer
 * @drvdata_cpumap:	cpu to tmc drvdata map
 * @timer:		global timer shared by all cores
 * @tick:		gloabl timer tick period
 * @active_count:	timer reference count
 */
static struct tmc_etr_tsync_global {
	struct tmc_drvdata *drvdata_cpumap[NR_CPUS];
	struct hrtimer	timer;
	int active_count;
	u64 tick;
} tmc_etr_tsync_global;

/* Accessor functions for tsync global */
void tmc_etr_add_cpumap(struct tmc_drvdata *drvdata)
{
	tmc_etr_tsync_global.drvdata_cpumap[drvdata->cpu] = drvdata;
}

static inline struct tmc_drvdata *cpu_to_tmcdrvdata(int cpu)
{
	return tmc_etr_tsync_global.drvdata_cpumap[cpu];
}

static inline struct hrtimer *tmc_etr_tsync_global_timer(void)
{
	return &tmc_etr_tsync_global.timer;
}

static inline void tmc_etr_tsync_global_tick(u64 tick)
{
	tmc_etr_tsync_global.tick = tick;
}

/* Refernence counting is assumed to be always called from
 * an atomic context.
 */
static inline int tmc_etr_tsync_global_addref(void)
{
	return ++tmc_etr_tsync_global.active_count;
}

static inline int tmc_etr_tsync_global_delref(void)
{
	return --tmc_etr_tsync_global.active_count;
}

/* Sync insertion API */
static void tmc_etr_insert_sync(struct tmc_drvdata *drvdata)
{
	struct coresight_device *sdev = drvdata->etm_source;
	struct etr_tsync_data *syncd = &drvdata->tsync_data;
	struct etmv4_drvdata *etm_drvdata = dev_get_drvdata(sdev->dev.parent);
	int err = 0, len;
	u64 rwp;

	/* We have three contenders for ETM control.
	 * 1. User initiated ETM control
	 * 2. Timer sync initiated ETM control
	 * 3. No stop on flush initated ETM control
	 * They all run in an atomic context and that too in
	 * the same core. Either on a core in which ETM is associated
	 * or in the primary core thereby mutually exclusive.
	 *
	 * To avoid any sync insertion while ETM is disabled by
	 * user, we rely on the device hw_state.
	 * Like for example, hrtimer being in active state even
	 * after ETM is disabled by user.
	 */
	if (etm_drvdata->hw_state != USR_START)
		return;

	rwp = tmc_read_rwp(drvdata);
	if (!syncd->prev_rwp)
		goto sync_insert;

	if (syncd->prev_rwp <= rwp) {
		len = rwp - syncd->prev_rwp;
	} else { /* Buffer wrapped */
		goto sync_insert;
	}

	/* Check if we reached buffer threshold */
	if (len < syncd->len_thold)
		goto skip_insert;

	/* Software based sync insertion procedure */
sync_insert:
	/* Disable source */
	etm4_disable_raw(sdev);

	/* Enable source */
	etm4_enable_raw(sdev);

	if (!err) {
		/* Mark the write pointer of sync insertion */
		syncd->prev_rwp = tmc_read_rwp(drvdata);
	}

skip_insert:
	return;
}

/* Timer handler APIs */

static enum hrtimer_restart tmc_etr_timer_handler_percore(struct hrtimer *t)
{
	struct tmc_drvdata *drvdata;

	drvdata = container_of(t, struct tmc_drvdata, timer);
	hrtimer_forward_now(t, ns_to_ktime(drvdata->tsync_data.tick));
	tmc_etr_insert_sync(drvdata);
	return HRTIMER_RESTART;
}

static enum hrtimer_restart tmc_etr_timer_handler_global(struct hrtimer *t)
{
	cpumask_t active_mask;
	int cpu;

	hrtimer_forward_now(t, ns_to_ktime(tmc_etr_tsync_global.tick));

	active_mask = coresight_etm_active_list();
	/* Run sync insertions for all active ETMs */
	for_each_cpu(cpu, &active_mask)
		tmc_etr_insert_sync(cpu_to_tmcdrvdata(cpu));

	return HRTIMER_RESTART;
}

/* Timer init API common for both global and per core mode */
void tmc_etr_timer_init(struct tmc_drvdata *drvdata)
{
	struct hrtimer *timer;

	timer = coresight_get_etm_sync_mode() == SYNC_MODE_SW_GLOBAL ?
		tmc_etr_tsync_global_timer() : &drvdata->timer;
	hrtimer_init(timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
}

/* Timer setup API common for both global and per core mode
 *
 * Global mode: Timer gets started only if its not active already.
 *		Number of users managed by reference counting.
 * Percore mode: Timer gets started always
 *
 * Always executed in an atomic context either in IPI handler
 * on a remote core or with irqs disabled in the local core
 */
void tmc_etr_timer_start(void *data)
{
	struct tmc_drvdata *drvdata = data;
	struct hrtimer *timer;
	bool mode_global;
	u64 tick;

	tick = drvdata->tsync_data.tick;
	mode_global = (coresight_get_etm_sync_mode() == SYNC_MODE_SW_GLOBAL);
	if (mode_global) {
		if (tmc_etr_tsync_global_addref() == 1) {
			/* Start only if we are the first user */
			tmc_etr_tsync_global_tick(tick); /* Configure tick */
		} else {
			dev_dbg(&drvdata->csdev->dev, "global timer active already\n");
			return;
		}
	}

	timer = mode_global ? tmc_etr_tsync_global_timer() : &drvdata->timer;
	timer->function = mode_global ?
		tmc_etr_timer_handler_global : tmc_etr_timer_handler_percore;
	dev_dbg(&drvdata->csdev->dev, "Starting sync timer, mode:%s period:%lld ns\n",
		mode_global ? "global" : "percore", tick);
	hrtimer_start(timer, ns_to_ktime(tick), HRTIMER_MODE_REL_PINNED);
}

/* Timer cancel API common for both global and per core mode
 *
 * Global mode: Timer gets cancelled only if there are no other users
 * Percore mode: Timer gets cancelled always
 *
 * Always executed in an atomic context either in IPI handler
 * on a remote core or with irqs disabled in the local core
 */
void tmc_etr_timer_cancel(void *data)
{
	struct tmc_drvdata *drvdata = data;
	struct hrtimer *timer;
	bool mode_global;

	mode_global = (coresight_get_etm_sync_mode() == SYNC_MODE_SW_GLOBAL);
	if (mode_global) {
		if (tmc_etr_tsync_global_delref() != 0) {
			/* Nothing to do if we are not the last user */
			return;
		}
	}

	timer = mode_global ?
		tmc_etr_tsync_global_timer() : &drvdata->timer;
	hrtimer_cancel(timer);
}

/*
 * tmc_etr_alloc_secure_buf: Allocate a contiguous DMA buffer.
 */
static int tmc_etr_alloc_secure_buf(struct tmc_drvdata *drvdata,
				  struct etr_buf *etr_buf, int node,
				  void **pages)
{
	struct etr_secure_buf *secure_buf;
	struct device *real_dev = drvdata->csdev->dev.parent;
	u64 s_hwaddr = 0;
	int err;

	/* We cannot reuse existing pages for flat buf */
	if (pages)
		return -EINVAL;

	/* Perf tries to allocate a larger size and falls back to
	 * the drvdata->size or smaller sizes if they fail.
	 * Since we have a cap on per CPU tracebuf size which is
	 * is set in drvdata->size, don't proceed with secure buffer
	 * allocation if size if larger than drvdata->size.
	 */
	if (etr_buf->size > drvdata->size)
		return -ENOMEM;

	secure_buf = kzalloc(sizeof(*secure_buf), GFP_KERNEL);
	if (!secure_buf)
		return -ENOMEM;

	secure_buf->size = etr_buf->size;
	secure_buf->dev = &drvdata->csdev->dev;

	secure_buf->vaddr = dma_alloc_coherent(real_dev, etr_buf->size,
					     &secure_buf->daddr, GFP_KERNEL);
	if (!secure_buf->vaddr) {
		kfree(secure_buf);
		return -ENOMEM;
	}

	/* Register driver allocated dma buffer for necessary
	 * mapping in the secure world
	 */
	if (tmc_register_drvbuf(drvdata, secure_buf->daddr, secure_buf->size)) {
		err = -ENOMEM;
		goto reg_err;
	}

	/* Allocate secure trace buffer */
	if (tmc_alloc_secbuf(drvdata, secure_buf->size, &s_hwaddr)) {
		err = -ENOMEM;
		goto salloc_err;
	}

	secure_buf->secure_hwaddr = s_hwaddr;

	/* Pass the secure_hwaddr to etr_buf so that
	 * the core tmc driver can use this to program
	 * registers like DBA.
	 */
	etr_buf->hwaddr = secure_buf->secure_hwaddr;
	etr_buf->mode = ETR_MODE_SECURE;
	etr_buf->private = secure_buf;

	/* Calculate parameters for sync packet insertion */
	if (drvdata->etr_quirks & CORESIGHT_QUIRK_ETM_SW_SYNC) {
		drvdata->tsync_data.len_thold = drvdata->size / (SYNCS_PER_FILL);
		drvdata->tsync_data.tick = (drvdata->size / SZ_1M) * SYNC_TICK_NS_PER_MB;
		drvdata->tsync_data.prev_rwp = 0;
		if (!drvdata->tsync_data.tick) {
			drvdata->tsync_data.tick = SYNC_TICK_NS_PER_MB;
			dev_warn(&drvdata->csdev->dev,
				"Trace bufer size not sufficient, sync insertion can fail\n");
		}
	}

	return 0;

salloc_err:
	tmc_unregister_drvbuf(drvdata, secure_buf->daddr, secure_buf->size);

reg_err:
	dma_free_coherent(real_dev, etr_buf->size, secure_buf->vaddr,
			  secure_buf->daddr);
	return err;

}

static void tmc_etr_free_secure_buf(struct etr_buf *etr_buf)
{
	struct etr_secure_buf *secure_buf = etr_buf->private;
	struct tmc_drvdata *drvdata;
	struct device *real_dev;

	if (!secure_buf)
		return;

	real_dev = secure_buf->dev->parent;
	drvdata = dev_get_drvdata(real_dev);

	dma_free_coherent(real_dev, secure_buf->size, secure_buf->vaddr,
			  secure_buf->daddr);

	tmc_unregister_drvbuf(drvdata, secure_buf->daddr, secure_buf->size);

	tmc_free_secbuf(drvdata, secure_buf->secure_hwaddr, secure_buf->size);

	kfree(secure_buf);
}

static void tmc_etr_sync_secure_buf(struct etr_buf *etr_buf, u64 rrp, u64 rwp)
{
	struct etr_secure_buf *secure_buf = etr_buf->private;
	u64 w_offset;

	/*
	 * Adjust the buffer to point to the beginning of the trace data
	 * and update the available trace data.
	 */
	w_offset = rwp - secure_buf->secure_hwaddr;

	if (etr_buf->full) {
		etr_buf->offset = w_offset;
		etr_buf->len = etr_buf->size;
	} else {
		etr_buf->offset = 0;
		etr_buf->len = w_offset;
	}

	/* Copy the secure buffer to the driver allocated buffer.
	 * This is done here so that when the core TMC driver starts
	 * to copy the data to sysfs or perf buffer, we do not
	 * generate SMC calls at different offsets everytime.
	 */
	tmc_copy_secure_buffer(secure_buf, 0x0, etr_buf->len);
}

static ssize_t tmc_etr_get_data_secure_buf(struct etr_buf *etr_buf,
					 u64 offset, size_t len, char **bufpp)
{
	struct etr_secure_buf *secure_buf = etr_buf->private;

	*bufpp = (char *)secure_buf->vaddr + offset;

	/*
	 * tmc_etr_buf_get_data already adjusts the length to handle
	 * buffer wrapping around.
	 */
	return len;
}

const struct etr_buf_operations etr_secure_buf_ops = {
	.alloc = tmc_etr_alloc_secure_buf,
	.free = tmc_etr_free_secure_buf,
	.sync = tmc_etr_sync_secure_buf,
	.get_data = tmc_etr_get_data_secure_buf,
};

/* APIs to manage ETM start/stop when ETR stop on flush is broken */

void tmc_flushstop_etm_off(void *data)
{
	struct tmc_drvdata *drvdata = data;
	struct coresight_device *sdev = drvdata->etm_source;
	struct etmv4_drvdata *etm_drvdata = dev_get_drvdata(sdev->dev.parent);

	if (etm_drvdata->hw_state == USR_START) {
		etm4_disable_raw(sdev);
		etm_drvdata->hw_state = SW_STOP;
	}
}

void tmc_flushstop_etm_on(void *data)
{
	struct tmc_drvdata *drvdata = data;
	struct coresight_device *sdev = drvdata->etm_source;
	struct etmv4_drvdata *etm_drvdata = dev_get_drvdata(sdev->dev.parent);

	if (etm_drvdata->hw_state == SW_STOP) { /* Restore the user configured state */
		etm4_enable_raw(sdev);
		etm_drvdata->hw_state = USR_START;
	}
}
