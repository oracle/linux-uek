// SPDX-License-Identifier: GPL-2.0
/* Marvell Silicon GICv3 hardware quirks
 *
 * Copyright (C) 2020 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/percpu.h>
#include <linux/io.h>
#include <linux/irqchip.h>
#include <linux/irqchip/arm-gic-v3.h>
#include <linux/irqchip/arm-gic-common.h>
#include <linux/irqchip/irq-gic-v3-fixes.h>

#include "irq-gic-common.h"

enum ipi_msg_type {
	IPI_RESCHEDULE,
	IPI_CALL_FUNC,
	IPI_CPU_STOP,
	IPI_CPU_CRASH_STOP,
	IPI_TIMER,
	IPI_IRQ_WORK,
	IPI_WAKEUP,
	NR_IPIS
};

struct gic_ipi_track {
	atomic_t tx_count;
	atomic_t rx_count;
	raw_spinlock_t lock;
};

static struct gic_ipi_track gic_ipitrack[NR_CPUS][NR_IPIS];

static inline void gic_ipi_txcount_inc(int cpu, int irq)
{
	atomic_inc(&gic_ipitrack[cpu][irq].tx_count);
}

void gic_ipi_rxcount_inc(int cpu, int irq)
{
	atomic_inc(&gic_ipitrack[cpu][irq].rx_count);
}

static inline void gic_ipi_count_reset(int cpu, int irq)
{
	atomic_set(&gic_ipitrack[cpu][irq].tx_count, 0x0);
	atomic_set(&gic_ipitrack[cpu][irq].rx_count, 0x0);
}

static inline bool is_gic_ipi_received(int dest_cpu, int irq)
{
	int retry_count = 0xf;

retry:
	if (gic_rdist_pend_reg(dest_cpu, 0x0) & (1 << irq))
		return true;

	if (gic_rdist_active_reg(dest_cpu, 0x0) & (1 << irq))
		return true;
	smp_rmb(); /* Ensure pend/active reg read happens first */

	if (atomic_read(&gic_ipitrack[dest_cpu][irq].tx_count) ==
		atomic_read(&gic_ipitrack[dest_cpu][irq].rx_count))
		return true;

	if (!retry_count)
		return false;

	retry_count--;
	goto retry;
}

void gic_write_sgi1r_retry(int dest_cpu, int irq, u64 val)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&gic_ipitrack[dest_cpu][irq].lock, flags);
	wmb(); /* Ensure lock is acquired before we generate an IPI */
retry:
	gic_write_sgi1r(val);
	isb(); /* Ensure sgi write is completed before pending/active read */
	gic_ipi_txcount_inc(dest_cpu, irq);
	if (is_gic_ipi_received(dest_cpu, irq))
		goto out;

	/* Seems we have lost an interrupt
	 * Reset and start again
	 */
	gic_ipi_count_reset(dest_cpu, irq);
	wmb(); /* Ensure the write is completed before we start again */
	goto retry;
out:
	raw_spin_unlock_irqrestore(&gic_ipitrack[dest_cpu][irq].lock, flags);
}

static bool __maybe_unused gicv3_enable_quirk_otx(void *data)
{
	int cpu, ipi;

	gic_v3_enable_ipimiss_quirk();

	/* Initialize necessary lock */
	for_each_possible_cpu(cpu)
		for (ipi = 0; ipi < NR_IPIS; ipi++)
			raw_spin_lock_init(&gic_ipitrack[cpu][ipi].lock);

	return true;
}

static const struct gic_quirk gicv3_quirks[] = {
	{
		.desc	= "GIC V3: IPI Miss",
		.iidr	= 0xb100034c,
		.mask	= 0xff000fff,
		.init	= gicv3_enable_quirk_otx,
	},
	{
		.desc	= "GIC V3: IPI Miss",
		.iidr	= 0xb200034c,
		.mask	= 0xff000fff,
		.init	= gicv3_enable_quirk_otx,
	},
	{
		.desc	= "GIC V3: IPI Miss",
		.iidr	= 0xb300034c,
		.mask	= 0xff000fff,
		.init	= gicv3_enable_quirk_otx,
	},
	{
		.desc	= "GIC V3: IPI Miss",
		.iidr	= 0xb400034c,
		.mask	= 0xff000fff,
		.init	= gicv3_enable_quirk_otx,
	},
	{
		.desc	= "GIC V3: IPI Miss",
		.iidr	= 0xb500034c,
		.mask	= 0xff000fff,
		.init	= gicv3_enable_quirk_otx,
	},
	{
		.desc	= "GIC V3: IPI Miss",
		.iidr	= 0xa100034c, /* 88xx */
		.mask	= 0xff000fff,
		.init	= gicv3_enable_quirk_otx,
	},
	{
		.desc	= "GIC V3: IPI Miss",
		.iidr	= 0xa200034c, /* 81xx */
		.mask	= 0xff000fff,
		.init	= gicv3_enable_quirk_otx,
	},
	{
		.desc	= "GIC V3: IPI Miss",
		.iidr	= 0xa300034c, /* 83xx */
		.mask	= 0xff000fff,
		.init	= gicv3_enable_quirk_otx,
	},

	{ /* NULL entry */
		0,
		0,
		0,
		0,
	}
};

void gic_v3_enable_quirks(void __iomem *base)
{
	u32 iidr = readl_relaxed(base + GICD_IIDR);

	gic_enable_quirks(iidr, gicv3_quirks, NULL);
}
