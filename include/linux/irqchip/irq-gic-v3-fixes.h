/* SPDX-License-Identifier: GPL-2.0
 * Marvell Silicon GICv3 hardware quirks
 *
 * Copyright (C) 2020 Marvell International Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __LINUX_IRQCHIP_MARVELL_GIC_V3_H
#define __LINUX_IRQCHIP_MARVELL_GIC_V3_H

#define GICV3_QUIRK_IPI_MISS	(1 << 0)

u32 gic_rdist_pend_reg(int cpu, int offset);
u32 gic_rdist_active_reg(int cpu, int offset);

void gic_ipi_rxcount_inc(int cpu, int irq);
void gic_write_sgi1r_retry(int dest_cpu, int irq, u64 val);
void gic_v3_enable_quirks(void __iomem *base);
void gic_v3_enable_ipimiss_quirk(void);

#endif

