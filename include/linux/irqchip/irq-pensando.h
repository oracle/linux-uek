/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2019-2021, Pensando Systems Inc.
 *
 * Definitions for interrupt domain controllers for Pensando Capri and Elba chip
 */

#ifndef _LINUX_IRQCHIP_IRQ_CAPRI_H_
#define _LINUX_IRQCHIP_IRQ_CAPRI_H_
/* Types of possible register blocks */
enum reg_type {
	REG_TYPE_UNKNOWN,
	REG_TYPE_CSR,
	REG_TYPE_GRP,
	REG_TYPE_CSRINTR,
};

/*
 * Common format for interrupt block control registers for a CSR block
 * @intreg:		Interrupt status on read, clear interrupt on write
 * @int_test:		Test bits, write to cause corresponding interrupt
 * @int_enable_set:	Write to set enable bits, read for current enable mask
 * @int_enable_clear:	Write to clear enable bits
 */
struct pen_ictlr_csr {
	u32	intreg;
	u32	int_test;
	u32	int_enable_set;
	u32	int_enable_clear;
};

/*
 * Common format for interrupt block control registers for a group
 * @intreg:		Interrupt status on read, clear interrupt on write
 * @int_enable_rw_reg:	Enable bits
 * @int_rw_reg:		TBD
 */
struct pen_ictlr_grp {
	u32	intreg;
	u32	int_enable_rw_reg;
	u32	int_rw_reg;
};

/*
 * Common format for interrupt block control registers for a CSR interrupt
 * block
 * @intr:		Interrupt status in low order bit, i.e. bit 0. The
 *			enable bit is bit 1.
 */
struct pen_ictlr_csrintr {
	u32	intr;
};

/*
 * Per domain information
 * @reg_type:		Type of register block
 * @domain:		Pointer to the associated &struct irq_domain
 * @dn:			Pointer to the device tree device node for this
 *			interrupt controller
 * @irq_chip:		Pointer to the struct irq_chip for this domain (which
 *			has just one)
 * @num_irqs:		Number of IRQs for this chip
 * @irq_lock:		Per-domain controller lock
 * @irq_flag:		Flag set by spin_lock_irqsave() when used on
 *			@irq_lock to be restored by spin_lock_irqrestore()
 * @num_bases:		Number of virtual addresses in @map_base
 * @map_base:		Virtual addresses of the beginning of the register
 *			block, mapped from the reg property. Allocation
 *			continues at the end to accommodate the values.
 */
struct pen_ictlr_info {
	enum reg_type		reg_type;
	struct irq_domain	*domain;
	struct device_node	*dn;
	struct irq_chip		*irq_chip;
	unsigned int		parent_irq;
	spinlock_t		irq_lock;
	unsigned long		irq_flag;
	unsigned int		num_bases;
	void __iomem		*map_base[];
};

/* Enable/disable functions that do not recurse on their parents */
void pen_irq_unmask_enable_csr_one(struct irq_data *irq_data);
void pen_irq_mask_disable_csr_one(struct irq_data *irq_data);
void pen_irq_unmask_enable_grp_one(struct irq_data *irq_data);
void pen_irq_mask_disable_grp_one(struct irq_data *d);
void pen_irq_unmask_enable_csrintr_one(struct irq_data *irq_data);
void pen_irq_mask_disable_csrintr_one(struct irq_data *irq_data);

#endif	/* _LINUX_IRQCHIP_IRQ_CAPRI_H_ */
