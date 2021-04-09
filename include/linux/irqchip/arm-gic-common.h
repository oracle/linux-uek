/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * include/linux/irqchip/arm-gic-common.h
 *
 * Copyright (C) 2016 ARM Limited, All Rights Reserved.
 */
#ifndef __LINUX_IRQCHIP_ARM_GIC_COMMON_H
#define __LINUX_IRQCHIP_ARM_GIC_COMMON_H

#include <linux/irqchip/arm-vgic-info.h>

/*
 * We need a value to serve as a irq-type for LPIs. Choose one that will
 * hopefully pique the interest of the reviewer.
 */
#define GIC_IRQ_TYPE_LPI               0xa110c8ed
#define GIC_IRQ_TYPE_PARTITION         (GIC_IRQ_TYPE_LPI + 1)
#define GIC_IRQ_TYPE_GSI               (GIC_IRQ_TYPE_LPI + 2)

#define GICD_INT_DEF_PRI		0xa0
#define GICD_INT_DEF_PRI_X4		((GICD_INT_DEF_PRI << 24) |\
					(GICD_INT_DEF_PRI << 16) |\
					(GICD_INT_DEF_PRI << 8) |\
					GICD_INT_DEF_PRI)

struct irq_domain;
struct fwnode_handle;
int gicv2m_init(struct fwnode_handle *parent_handle,
		struct irq_domain *parent);

#endif /* __LINUX_IRQCHIP_ARM_GIC_COMMON_H */
