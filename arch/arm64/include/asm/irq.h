/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_IRQ_H
#define __ASM_IRQ_H

#ifndef __ASSEMBLER__

#include <asm-generic/irq.h>
#include <linux/irqchip/arm-gic-common.h>

#define ACPI_IRQCHIP_FWSPEC_ARG0	GIC_IRQ_TYPE_GSI

struct pt_regs;

int set_handle_irq(void (*handle_irq)(struct pt_regs *));
#define set_handle_irq	set_handle_irq
int set_handle_fiq(void (*handle_fiq)(struct pt_regs *));

static inline int nr_legacy_irqs(void)
{
	return 0;
}

#endif /* !__ASSEMBLER__ */
#endif
