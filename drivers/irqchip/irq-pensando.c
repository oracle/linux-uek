// SPDX-License-Identifier: GPL-2.0
/*
 * Pensando register-based hierarchical IRQ driver
 *
 * Copyright (C) 2019-2021 Pensando, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Thanks to other irqchip developers!
 *
 * There are three types of registers in the Pensando Capri and Elba ASICs:
 * o	csr - a particular device. This has enable set, enable clear, and
 *	interrupt status registers
 * o	group - a group of devices. This has an enable register and an
 *	interrupt status register
 * o	csrintr - module level interrupts. This has a single register with the
 *	interrupt status at bit 0 and the enable at bit 1. The csrintr code
 *	supports two or more address tuples, which are all considered for
 *	interrupt enable, disable, and EOI processing.
 *
 * Items remaining to do:
 * o	Make interrupts use two cells. Right now they have 3 with an
 *	unnecessary leading GIC_SPI.
 * o	Drop enable_csr_padddr and enable_mask:
 *
 *	a.	Change reg to have what is now in enable_csr_paddr be
 *		the first element, which will be the same as the current
 *		value of enable_csr_paddr.
 *	b.	The enable mask should be the same as 1 shifted left by
 *		the second value in the interrupts property
 *
 *	Doing these, and documenting them, should make this easier to maintain.
 */

#define pr_fmt(fmt)	KBUILD_MODNAME	": " fmt

#include <asm/stacktrace.h>
#include <asm-generic/bitops/find.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/io.h>
#include <linux/irqdomain.h>
#include <linux/reboot.h>
#include <linux/bitops.h>
#include <linux/irqchip.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/spinlock.h>
#include <linux/irqchip/irq-pensando.h>
#include <dt-bindings/interrupt-controller/arm-gic.h>
#include <asm/stacktrace.h>

#ifndef CHAR_BIT
#define CHAR_BIT	8
#endif

/* Build in debugging messages in unmask_enable, eio, etc. functions */
#undef TRACE_IRQ_DOMAIN_OPS

#ifdef TRACE_IRQ_DOMAIN_OPS
#define trace_irq_domain_ops(fmt, ...) pr_err("%s: " fmt, __func__, \
	##__VA_ARGS__)
#else
#define trace_irq_domain_ops(fmt, ...) do { } while (false)
#endif

/* Maximum number of supported domains */
#define MAX_DOMAINS	25

#define MAX_N_IRQS_PER_CHIP	32

/* Parameters for interpreting an irq_fwspec parsed from the device tree */
#define IRQ_GIC_INTR_TYPE	0
#define IRQ_FWSPEC_HWIRQ	1
#define IRQ_FWSPEC_TYPE		2
#define N_INTERRUPT_CELLS	3
#define N_CHIP_TYPES		1		/* On a per-domain basis */

struct domain_info {
	unsigned int		i;
	struct irq_domain	*domain;
};

/*
 * Control access to IRQ data
 */
static unsigned long info_irq_lock(struct pen_ictlr_info *info)
{
	unsigned long flags;

	spin_lock_irqsave(&info->irq_lock, flags);
	return flags;
}

static void info_irq_unlock(struct pen_ictlr_info *info, unsigned long flags)
{
	spin_unlock_irqrestore(&info->irq_lock, flags);
}

/*
 * Interrupt functions with disjoint enable and disable registers.
 *
 * The following interrupt enable/disable functions are here for
 * debugging only and should be replaced by the corresponding
 * irq_gc* function.
 */
void pen_irq_unmask_enable_csr_one(struct irq_data *irq_data)
{
	struct irq_domain *domain;
	struct pen_ictlr_info *info;
	struct pen_ictlr_csr __iomem *data;
	irq_hw_number_t hwirq;
	u32 mask;

	hwirq = irq_data->hwirq;
	domain = irq_data->domain;
	info = domain->host_data;
	data = info->map_base[0];
	mask = BIT(hwirq);
	trace_irq_domain_ops("enable %s with %x\n", irq_data->domain->name,
		mask);
	writel(mask, &data->int_enable_set);
}
EXPORT_SYMBOL(pen_irq_unmask_enable_csr_one);

void pen_irq_unmask_enable_csr(struct irq_data *irq_data)
{
	pen_irq_unmask_enable_csr_one(irq_data);
	irq_chip_unmask_parent(irq_data);
}

void pen_irq_mask_disable_csr_one(struct irq_data *irq_data)
{
	struct irq_domain *domain;
	struct pen_ictlr_info *info;
	struct irq_chip *irq_chip;
	void *chip_data;
	struct pen_ictlr_csr __iomem *data;
	irq_hw_number_t hwirq;
	u32 mask;

	hwirq = irq_data->hwirq;
	domain = irq_data->domain;
	irq_chip = irq_data->chip;
	chip_data = irq_data->chip_data;
	info = domain->host_data;
	data = info->map_base[0];

	mask = BIT(hwirq);
	trace_irq_domain_ops("disable %s with %x\n", irq_data->domain->name,
		mask);
	writel(mask, &data->int_enable_clear);
}
EXPORT_SYMBOL(pen_irq_mask_disable_csr_one);

void pen_irq_mask_disable_csr(struct irq_data *irq_data)
{
	pen_irq_mask_disable_csr_one(irq_data);
	irq_chip_mask_parent(irq_data);
}

void pen_irq_eoi_csr(struct irq_data *irq_data)
{
	struct irq_domain *domain;
	struct pen_ictlr_info *info;
	struct pen_ictlr_csr __iomem *data;
	irq_hw_number_t hwirq;
	u32 mask;
	u32 intreg_before;

	trace_irq_domain_ops("eio %s\n", irq_data->domain->name);
	hwirq = irq_data->hwirq;
	domain = irq_data->domain;
	info = domain->host_data;
	data = info->map_base[0];

	mask = BIT(hwirq);
	intreg_before = readl(&data->intreg);
	writel(mask, &data->intreg);
	irq_chip_eoi_parent(irq_data);
}

/*
 * Interrupt functions with enable and disable in the bit of the same
 * register but a disjoint interrupt status register
 *
 * The following interrupt enable/disable functions are here for
 * debugging only and should be replaced by the corresponding
 * irq_gc* function.
 */
void pen_irq_unmask_enable_grp_one(struct irq_data *irq_data)
{
	struct irq_domain *domain;
	struct pen_ictlr_info *info;
	struct pen_ictlr_grp *data;
	irq_hw_number_t hwirq;
	unsigned long flags;
	u32 enable, mask;

	hwirq = irq_data->hwirq;
	domain = irq_data->domain;
	info = domain->host_data;
	data = info->map_base[0];

	mask = BIT(hwirq);

	flags = info_irq_lock(info);
	enable = readl(&data->intreg);
	trace_irq_domain_ops("enable %s with %x\n", irq_data->domain->name,
		enable | mask);
	writel(enable | mask, &data->int_enable_rw_reg);
	info_irq_unlock(info, flags);
}
EXPORT_SYMBOL(pen_irq_unmask_enable_grp_one);

void pen_irq_unmask_enable_grp(struct irq_data *irq_data)
{
	pen_irq_unmask_enable_grp_one(irq_data);
	irq_chip_unmask_parent(irq_data);
}

void pen_irq_mask_disable_grp_one(struct irq_data *irq_data)
{
	struct irq_domain *domain;
	struct pen_ictlr_info *info;
	struct pen_ictlr_grp *data;
	irq_hw_number_t hwirq;
	unsigned long flags;
	u32 enable, mask;

	hwirq = irq_data->hwirq;
	domain = irq_data->domain;
	info = domain->host_data;
	info = domain->host_data;
	data = info->map_base[0];

	mask = BIT(hwirq);

	flags = info_irq_lock(info);
	enable = readl(&data->int_enable_rw_reg);
	trace_irq_domain_ops("disable %s with %x\n", irq_data->domain->name,
		enable & ~mask);
	writel(enable & ~mask, &data->int_enable_rw_reg);
	info_irq_unlock(info, flags);
}
EXPORT_SYMBOL(pen_irq_mask_disable_grp_one);

void pen_irq_mask_disable_grp(struct irq_data *irq_data)
{
	pen_irq_mask_disable_grp_one(irq_data);
	irq_chip_mask_parent(irq_data);
}

void pen_irq_eoi_grp(struct irq_data *irq_data)
{
	struct irq_domain *domain;
	struct pen_ictlr_info *info;
	struct pen_ictlr_grp *data;
	irq_hw_number_t hwirq;
	unsigned long flags;
	u32 before, after;

	hwirq = irq_data->hwirq;
	domain = irq_data->domain;
	info = domain->host_data;
	data = info->map_base[0];

	flags = info_irq_lock(info);

	/* No state here, so we just invoke the parent */
	before = readl(&data->int_enable_rw_reg);
	irq_chip_eoi_parent(irq_data);
	after = readl(&data->int_enable_rw_reg);
	info_irq_unlock(info, flags);
	trace_irq_domain_ops("eio %s before %x after %x\n",
		irq_data->domain->name, before, after);
}

/*
 * Interrupt functions with enable and disable in one bit of the same
 * register as the interrupt status bit
 *
 * The following interrupt enable/disable functions are here for
 * debugging only and should be replaced by the corresponding
 * irq_gc* function.
 */
void pen_irq_unmask_enable_csrintr_one(struct irq_data *irq_data)
{
	struct irq_domain *domain;
	struct pen_ictlr_info *info;
	struct pen_ictlr_csrintr *data;
	irq_hw_number_t hwirq;
	unsigned long flags;
	u32 mask;
	u32 enable;
	unsigned int i;

	hwirq = irq_data->hwirq;
	domain = irq_data->domain;
	info = domain->host_data;
	mask = BIT(1);

	flags = info_irq_lock(info);

	for (i = 0; i < info->num_bases; i++) {
		data = info->map_base[i];
		enable = readl(&data->intr);
		trace_irq_domain_ops("enable %s (base #%u) with %x\n",
			irq_data->domain->name, i, enable | mask);
		writel(enable | mask, &data->intr);
	}

	info_irq_unlock(info, flags);
}
EXPORT_SYMBOL(pen_irq_unmask_enable_csrintr_one);

void pen_irq_unmask_enable_csrintr(struct irq_data *irq_data)
{
	pen_irq_unmask_enable_csrintr_one(irq_data);
	irq_chip_unmask_parent(irq_data);
}

void pen_irq_mask_disable_csrintr_one(struct irq_data *irq_data)
{
	struct irq_domain *domain;
	struct pen_ictlr_info *info;
	struct pen_ictlr_csrintr *data;
	irq_hw_number_t hwirq;
	unsigned long flags;
	u32 mask;
	u32 enable;
	unsigned int i;

	hwirq = irq_data->hwirq;
	domain = irq_data->domain;
	info = domain->host_data;
	mask = BIT(1);

	flags = info_irq_lock(info);

	for (i = 0; i < info->num_bases; i++) {
		data = info->map_base[i];
		enable = readl(&data->intr);
		trace_irq_domain_ops("disable %s (base #%u) with %x\n",
			irq_data->domain->name, i, enable & ~mask);
		writel(enable & ~mask, &data->intr);
	}

	info_irq_unlock(info, flags);
}
EXPORT_SYMBOL(pen_irq_mask_disable_csrintr_one);

void pen_irq_mask_disable_csrintr(struct irq_data *irq_data)
{
	pen_irq_mask_disable_csrintr_one(irq_data);
	irq_chip_mask_parent(irq_data);
}

/*
 * We don't need to do any real work here, just report debugging info
 */
void pen_irq_eoi_csrintr(struct irq_data *irq_data)
{
	struct irq_domain *domain;
	struct pen_ictlr_info *info;
	struct pen_ictlr_csrintr *data;
	irq_hw_number_t hwirq;
	unsigned long flags;
	u32 before, after;
	unsigned int i;

	hwirq = irq_data->hwirq;
	domain = irq_data->domain;
	info = domain->host_data;
	flags = info_irq_lock(info);

	/* No state here, so we just invoke the parent */
	for (i = 0; i < info->num_bases; i++) {
		data = info->map_base[i];
		before = readl(&data->intr);

		irq_chip_eoi_parent(irq_data);

		after = readl(&data->intr);
		trace_irq_domain_ops("eio %s (base #%u) before %x after %x\n",
			irq_data->domain->name, i, before, after);
	}
	info_irq_unlock(info, flags);
}

static struct irq_chip pen_irq_chip_csr = {
	.name =			"CSR",
	.irq_mask =		pen_irq_mask_disable_csr,
	.irq_unmask =		pen_irq_unmask_enable_csr,
	.irq_eoi =		pen_irq_eoi_csr,
	.irq_set_type =		irq_chip_set_type_parent,
#ifdef CONFIG_SMP
	.irq_set_affinity =	irq_chip_set_affinity_parent,
#endif
};

static struct irq_chip pen_irq_chip_grp = {
	.name =			"GRP",
	.irq_mask =		pen_irq_mask_disable_grp,
	.irq_unmask =		pen_irq_unmask_enable_grp,
#ifdef TRACE_IRQ_DOMAIN_OPS
	.irq_eoi =		pen_irq_eoi_grp,
#else
	.irq_eoi =		irq_chip_eoi_parent,
#endif
	.irq_set_type =		irq_chip_set_type_parent,
#ifdef CONFIG_SMP
	.irq_set_affinity =	irq_chip_set_affinity_parent,
#endif
};

static struct irq_chip pen_irq_chip_csrintr = {
	.name =			"CSRintr",
	.irq_mask =		pen_irq_mask_disable_csrintr,
	.irq_unmask =		pen_irq_unmask_enable_csrintr,
#ifdef TRACE_IRQ_DOMAIN_OPS
	.irq_eoi =		pen_irq_eoi_csrintr,
#else
	.irq_eoi =		irq_chip_eoi_parent,
#endif
	.irq_set_type =		irq_chip_set_type_parent,
#ifdef CONFIG_SMP
	.irq_set_affinity =	irq_chip_set_affinity_parent,
#endif
};

/*
 * Pull the hardware IRQ number from the device tree information
 * Returns the zero if successful, otherwise a negative errno value
 */
static int extract_hwirq(struct irq_fwspec *fwspec, irq_hw_number_t *hwirq)
{

	/* Verify that the value from the interrupts property is correct */
	if (fwspec->param_count != N_INTERRUPT_CELLS ||
		fwspec->param[IRQ_GIC_INTR_TYPE] != GIC_SPI) {
		pr_err("Invalid value for #interrupts property\n");
		return -EINVAL;
	}

	*hwirq = fwspec->param[IRQ_FWSPEC_HWIRQ];
	if (*hwirq >= MAX_N_IRQS_PER_CHIP) {
		pr_err("Hardware interrupt number too big (>%lu)", *hwirq);
		return -EINVAL;
	}

	return 0;
}

/*
 * This will fill in the param_count and 3 elements of param of a
 * struct irq_fwspec. It is narrowly tailored for this particular usage
 * but could fairly easily be generalized.
 *
 * Returns 0 on success, or a negative errno on failure.
 */
static int pen_get_parent_fwspec(struct irq_domain *d,
	struct irq_fwspec *fwspec)
{
	struct device_node *device;
	struct device_node *parent;
	struct pen_ictlr_info *info;
	u32 intsize;
	unsigned int i;
	int err;

	info = d->host_data;
	device = info->dn;

	/* Look for the interrupt parent. */
	parent = of_irq_find_parent(device);
	if (parent == NULL) {
		err = -EINVAL;
		goto out;
	}

	/* Get size of interrupt specifier */
	if (of_property_read_u32(parent, "#interrupt-cells", &intsize)) {
		err = -EINVAL;
		goto out;
	}

	/* This is not a general solution, fail if it's not one we can do */
	if (intsize != N_INTERRUPT_CELLS) {
		err = -EOPNOTSUPP;
		goto out;
	}

	fwspec->param_count = N_INTERRUPT_CELLS;
	for (i = 0; i < intsize; i++) {
		err = of_property_read_u32_index(device, "interrupts", i,
			&fwspec->param[i]);
		if (err != 0)
			goto out;
	}

	fwspec->param_count = intsize;

	return 0;

out:
	of_node_put(parent);
	return err;
}

/*
 * Translate from a value in the device tree interrupts property to a
 * hardware IRQ number.
 * @d:		Domain for which translation should be done
 * @fwspec:	Hardware IRQ information from the device tree for this
 *		domain
 * @out_hwirq:	Pointer to place to store the lowest supported hardware IRQ
 * @out_type:	Pointer to the type of interrupt, e.g. edge, or level triggered
 */
static int pen_irq_domain_translate(struct irq_domain *d,
	struct irq_fwspec *fwspec, irq_hw_number_t *out_hwirq,
	unsigned int *out_type)
{
	if (is_of_node(fwspec->fwnode)) {
		irq_hw_number_t hwirq;
		int rc;

		rc = extract_hwirq(fwspec, &hwirq);
		if (rc != 0)
			return rc;

		*out_hwirq = hwirq;
		*out_type = fwspec->param[IRQ_FWSPEC_TYPE] &
			IRQ_TYPE_SENSE_MASK;
		return 0;
	}

	return -EINVAL;
}

/*
 * Recursively allocate the IRQ structures for this domain, using information
 * provided in the device tree
 * @d:		Domain for which IRQ information should be added
 * @virq:	Lowest available kernel IRQ number
 * @nr_irqs:	Number of IRQs to allocate
 * @fw_data:	Hardware IRQ information for this domain
 */
static int pen_irq_domain_alloc(struct irq_domain *d, unsigned int virq,
	unsigned int nr_irqs, void *fw_data)
{
	struct irq_fwspec *fwspec = fw_data;
	struct irq_fwspec parent_fwspec;
	struct pen_ictlr_info *info;
	irq_hw_number_t hwirq;
	unsigned int i;
	int rc;

	rc = extract_hwirq(fwspec, &hwirq);
	if (rc != 0)
		return rc;

	/* Create the irq structure */
	info = d->host_data;
	for (i = 0; i < nr_irqs; i++) {
		rc = irq_domain_set_hwirq_and_chip(d, virq + i, hwirq + i,
			info->irq_chip, info);
		if (rc != 0) {
			pr_err("irq_domain_set_hwirq_and_chipd failed: %d\n",
				rc);
			return rc;
		}
	}

	/* Set up the parent information */
	rc = pen_get_parent_fwspec(d, &parent_fwspec);
	parent_fwspec.fwnode = d->parent->fwnode;

	rc = irq_domain_alloc_irqs_parent(d, virq, nr_irqs, &parent_fwspec);

	return rc;
}

static void pen_irq_domain_free(struct irq_domain *d, unsigned int virq,
				unsigned int nr_irqs)
{
	struct irq_data *data = irq_domain_get_irq_data(d, virq);

	irq_domain_reset_irq_data(data);
}

static const struct irq_domain_ops pen_irq_domain_generic_chip_ops = {
	.translate =	pen_irq_domain_translate,
	.alloc =	pen_irq_domain_alloc,
	.free =		pen_irq_domain_free,
};

/*
 * Handle mapping I/O of a device register block
 */
static int __init pen_ictlr_iomap_csr(struct device_node *dn,
				     struct pen_ictlr_info *info)
{
	if (info->num_bases != 1) {
		pr_err("%pOF: reg property needs one tuple but has %u\n",
			dn, info->num_bases);
		return -EIO;
	}

	info->map_base[0] = of_iomap(dn, 0);
	if (info->map_base[0] == NULL) {
		pr_err("unable to map registers\n");
		return -ENOMEM;
	}

	return 0;
}

/*
 * Handle mapping I/O of a group register block
 */
static int __init pen_ictlr_iomap_grp(struct device_node *dn,
				     struct pen_ictlr_info *info)
{
	if (info->num_bases != 1) {
		pr_err("%pOF: reg property needs one tuple but has %u\n",
			dn, info->num_bases);
		return -EIO;
	}

	info->map_base[0] = of_iomap(dn, 0);
	if (info->map_base[0] == NULL) {
		pr_err("unable to map registers\n");
		return -ENOMEM;
	}

	return 0;
}

/*
 * Handle mapping I/O of a device register block
 */
static int __init pen_ictlr_iomap_csrintr(struct device_node *dn,
					     struct pen_ictlr_info *info)
{
	unsigned int i;

	if (info->num_bases < 1) {
		pr_err("%pOF: reg property needs at least one tuple, has %u\n",
			dn, info->num_bases);
		return -EIO;
	}

	for (i = 0; i < info->num_bases; i++) {
		info->map_base[i] = of_iomap(dn, i);
		if (info->map_base[i] == NULL)
			break;
	}

	if (i != info->num_bases) {
		pr_err("only mapped %u of %u regions\n", i, info->num_bases);
		return -ENOMEM;
	}

	return 0;
}

static struct pen_ictlr_info *__init pen_ictlr_probe(struct device_node *dn,
	 struct device_node *parent, enum reg_type reg_type,
	 int (*of_iomap_fn)(struct device_node *, struct pen_ictlr_info *),
	 void (*set_irq_chip_info)(struct irq_chip_type *ct),
	 struct irq_chip *irq_chip)
{
	struct irq_domain *parent_domain;
	struct pen_ictlr_info *info;
	unsigned int num_bases;
	unsigned int info_size;
	int ret = 0;

	pr_info("Probe IRQ domain controller %s\n", dn->full_name);

	if (parent == NULL) {
		pr_err("%pOF has no device node parent\n", dn);
		return ERR_PTR(-ENODEV);
	}

	parent_domain = irq_find_host(parent);
	if (parent_domain == NULL) {
		pr_err("%pOF has no domain parent\n", dn);
		return ERR_PTR(-ENXIO);
	}

	/* Count the number of mapped areas */
	num_bases = 0;
	for (num_bases = 0; of_get_address(dn, num_bases, NULL, NULL) != NULL;
		num_bases++) {
	}
	if (num_bases == 0) {
		pr_err("no addresses found in reg property for %pOF\n",
			dn);
		return ERR_PTR(ENXIO);
	}

	/* Allocate a struct pen_ictlr_info and add on space for the
	 * mapped addresses at the end
	 */
	info_size = offsetof(struct pen_ictlr_info, map_base[num_bases]);
	info = kzalloc(info_size, GFP_KERNEL);
	if (info == NULL)
		return ERR_PTR(-ENOMEM);
	info->num_bases = num_bases;

	/* Set up the mapping to the register block */
	ret = of_iomap_fn(dn, info);
	if (ret != 0) {
		pr_err("Unable to map register block\n");
		goto out_free_info;
	}

	/* Create a new domain with a linear IRQ mapping */
	info->reg_type = reg_type;
	info->irq_chip = irq_chip;
	info->domain = irq_domain_add_hierarchy(parent_domain, 0,
		MAX_N_IRQS_PER_CHIP, dn, &pen_irq_domain_generic_chip_ops,
		info);
	if (info->domain == NULL) {
		pr_err("Unable to create pensando soc domain\n");
		ret = -ENOMEM;
		goto out_unmap_regs;
	}

	info->dn = dn;

	spin_lock_init(&info->irq_lock);

	return info;

out_unmap_regs:
	if (info->map_base)
		iounmap(info->map_base);

out_free_info:
	kfree(info);
	return ERR_PTR(ret);
}

static void set_irq_chip_info_csr(struct irq_chip_type *ct)
{
	ct->chip.irq_mask = pen_irq_mask_disable_csr;
	ct->chip.irq_unmask = pen_irq_unmask_enable_csr;

	ct->regs.enable = offsetof(struct pen_ictlr_csr, int_enable_set);
	ct->regs.disable = offsetof(struct pen_ictlr_csr, int_enable_set);
	ct->regs.ack = offsetof(struct pen_ictlr_csr, intreg);

	ct->chip.irq_ack = irq_gc_noop;
}

static void set_irq_chip_info_grp(struct irq_chip_type *ct)
{
	ct->chip.irq_mask = pen_irq_mask_disable_grp;
	ct->chip.irq_unmask = pen_irq_unmask_enable_grp;

	ct->regs.enable = offsetof(struct pen_ictlr_grp, int_enable_rw_reg);
	ct->regs.disable = offsetof(struct pen_ictlr_grp,
		int_enable_rw_reg);
	ct->regs.ack = offsetof(struct pen_ictlr_grp, intreg);

	ct->chip.irq_ack = irq_gc_noop;
}

static void set_irq_chip_info_csrintr(struct irq_chip_type *ct)
{
	ct->chip.irq_mask = pen_irq_mask_disable_csrintr;
	ct->chip.irq_unmask = pen_irq_unmask_enable_csrintr;

	ct->regs.enable = offsetof(struct pen_ictlr_csrintr, intr);
	ct->regs.disable = offsetof(struct pen_ictlr_csrintr, intr);
	ct->regs.ack = offsetof(struct pen_ictlr_csrintr, intr);

	ct->chip.irq_ack = irq_gc_noop;
}

static int __init pen_ictlr_probe_csr(struct device_node *dn,
	 struct device_node *parent,
	 int (*iomap_fn)(struct device_node *,
		 struct pen_ictlr_info *), struct irq_chip *irq_chip,
	const char *intc_name)
{
	struct pen_ictlr_info *info;
	int ret = 0;

	info = pen_ictlr_probe(dn, parent, REG_TYPE_CSR, iomap_fn,
		set_irq_chip_info_csr, &pen_irq_chip_csr);
	if (IS_ERR(info))
		return PTR_ERR(info);

	return ret;
}

static int __init pen_ictlr_probe_grp(struct device_node *dn,
	 struct device_node *parent,
	 int (*iomap_fn)(struct device_node *,
		 struct pen_ictlr_info *), struct irq_chip *irq_chip,
	 const char *intc_name)
{
	struct pen_ictlr_info *info;
	int ret = 0;

	info = pen_ictlr_probe(dn, parent, REG_TYPE_GRP, iomap_fn,
		set_irq_chip_info_grp, &pen_irq_chip_grp);
	if (IS_ERR(info))
		return PTR_ERR(info);

	return ret;
}

static int __init pen_ictlr_probe_csrintr(struct device_node *dn,
	 struct device_node *parent,
	 int (*iomap_fn)(struct device_node *,
		 struct pen_ictlr_info *), struct irq_chip *irq_chip,
	 const char *intc_name)
{
	struct pen_ictlr_info *info;

	info = pen_ictlr_probe(dn, parent, REG_TYPE_CSRINTR, iomap_fn,
		set_irq_chip_info_csrintr, &pen_irq_chip_csrintr);
	if (IS_ERR(info))
		return PTR_ERR(info);

	return 0;
}

/* Probe for device-level interrupts */
static int __init soc_probe_csr(struct device_node *dn,
				     struct device_node *parent)
{
	pr_info("Probe %pOF\n", dn);
	return pen_ictlr_probe_csr(dn, parent,
		pen_ictlr_iomap_csr, &pen_irq_chip_csr,
		"Pensando SOC CSR");
}

/* Probe for group-level interrupts */
static int __init soc_probe_grp(struct device_node *dn,
				     struct device_node *parent)
{
	pr_info("Probe %pOF\n", dn);
	return pen_ictlr_probe_grp(dn, parent,
		pen_ictlr_iomap_grp, &pen_irq_chip_grp,
		"Pensando SOC GRP");
}

/* Probe for module-level interrupts */
static int __init soc_probe_csrintr(struct device_node *dn,
				     struct device_node *parent)
{
	pr_info("Probe %pOF\n", dn);
	return pen_ictlr_probe_csrintr(dn, parent,
		pen_ictlr_iomap_csrintr, &pen_irq_chip_csrintr,
		"Pensando SOC CSR Intr");
}

IRQCHIP_DECLARE(soc_ictlr_csr, "pensando,soc-ictlr-csr",
	soc_probe_csr);
IRQCHIP_DECLARE(soc_ictlr_grp, "pensando,soc-ictlr-grp",
	soc_probe_grp);
IRQCHIP_DECLARE(soc_ictlr_csrintr, "pensando,soc-ictlr-csrintr",
	soc_probe_csrintr);
