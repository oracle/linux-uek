/*
 * Support of MSI, HPET and DMAR interrupts.
 *
 * Copyright (C) 1997, 1998, 1999, 2000, 2009 Ingo Molnar, Hajnalka Szabo
 *	Moved from arch/x86/kernel/apic/io_apic.c.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/pci.h>
#include <linux/dmar.h>
#include <linux/hpet.h>
#include <linux/msi.h>
#include <asm/msidef.h>
#include <asm/hpet.h>
#include <asm/hw_irq.h>
#include <asm/apic.h>
#include <asm/irq_remapping.h>

void native_compose_msi_msg(struct pci_dev *pdev,
			    unsigned int irq, unsigned int dest,
			    struct msi_msg *msg, u8 hpet_id)
{
	struct irq_cfg *cfg = irq_cfg(irq);

	msg->address_hi = MSI_ADDR_BASE_HI;

	if (x2apic_enabled())
		msg->address_hi |= MSI_ADDR_EXT_DEST_ID(dest);

	msg->address_lo =
		MSI_ADDR_BASE_LO |
		((apic->irq_dest_mode == 0) ?
			MSI_ADDR_DEST_MODE_PHYSICAL :
			MSI_ADDR_DEST_MODE_LOGICAL) |
		((apic->irq_delivery_mode != dest_LowestPrio) ?
			MSI_ADDR_REDIRECTION_CPU :
			MSI_ADDR_REDIRECTION_LOWPRI) |
		MSI_ADDR_DEST_ID(dest);

	msg->data =
		MSI_DATA_TRIGGER_EDGE |
		MSI_DATA_LEVEL_ASSERT |
		((apic->irq_delivery_mode != dest_LowestPrio) ?
			MSI_DATA_DELIVERY_FIXED :
			MSI_DATA_DELIVERY_LOWPRI) |
		MSI_DATA_VECTOR(cfg->vector);
}

static int msi_compose_msg(struct pci_dev *pdev, unsigned int irq,
			   struct msi_msg *msg, u8 hpet_id)
{
	struct irq_cfg *cfg;
	int err;
	unsigned dest;

	if (disable_apic)
		return -ENXIO;

	cfg = irq_cfg(irq);
	if(!cfg->vector) {
		err = assign_irq_vector(irq, cfg, apic->target_cpus());
		if (err)
			return err;
	}

	err = apic->cpu_mask_to_apicid_and(cfg->domain,
					   apic->target_cpus(), &dest);
	if (err)
		return err;

	x86_msi.compose_msi_msg(pdev, irq, dest, msg, hpet_id);

	return 0;
}

static int
msi_set_affinity(struct irq_data *data, const struct cpumask *mask, bool force)
{
	struct irq_cfg *cfg = irqd_cfg(data);
	struct msi_msg msg, old_msg;
	unsigned int dest;
	unsigned cpu, vector;
	int ret;

	__get_cached_msi_msg(data->msi_desc, &msg);

	/* Save it */
	memcpy(&old_msg, &msg, sizeof(msg));

	vector = cfg->vector;
	cpu = cpumask_first(cfg->domain);
	old_msg.data &= ~MSI_DATA_VECTOR_MASK;
	old_msg.data |= MSI_DATA_VECTOR(cfg->vector);
	old_msg.address_hi = MSI_ADDR_BASE_HI;
	if (x2apic_enabled())
		old_msg.address_hi |= MSI_ADDR_EXT_DEST_ID(cpu);
	old_msg.address_lo &= ~MSI_ADDR_DEST_ID_MASK;
	old_msg.address_lo |= MSI_ADDR_DEST_ID(cpu);

	ret = apic_set_affinity(data, mask, &dest);
	if (ret)
		return ret;

	msg.data &= ~MSI_DATA_VECTOR_MASK;
	msg.data |= MSI_DATA_VECTOR(cfg->vector);
	msg.address_hi = MSI_ADDR_BASE_HI;
	if (x2apic_enabled())
		msg.address_hi |= MSI_ADDR_EXT_DEST_ID(dest);
	msg.address_lo &= ~MSI_ADDR_DEST_ID_MASK;
	msg.address_lo |= MSI_ADDR_DEST_ID(dest);

	if (vector == cfg->vector || cpu == dest) {
		__pci_write_msi_msg(data->msi_desc, &msg);
		return ret;
	}
	if (WARN_ON_ONCE(cpu != smp_processor_id())) {
		__pci_write_msi_msg(data->msi_desc, &msg);
		return ret;
	}

	/*
	 * Redirect the interrupt to the new vector on the current CPU
	 * first. This might cause a spurious interrupt on this vector if
	 * the device raises an interrupt right between this update and the
	 * update to the final destination CPU.
	 *
	 * If the vector is in use then the installed device handler will
	 * denote it as spurious which is no harm as this is a rare event
	 * and interrupt handlers have to cope with spurious interrupts
	 * anyway. If the vector is unused, then it is marked so it won't
	 * trigger the 'No irq handler for vector' warning in do_IRQ().
	 *
	 * This requires to hold vector lock to prevent concurrent updates to
	 * the affected vector.
	 */
	lock_vector_lock();

	/*
	 * Mark the new target vector on the local CPU if it is currently
	 * unused. Reuse the VECTOR_RETRIGGERED state which is also used in
	 * the CPU hotplug path for a similar purpose. This cannot be
	 * undone here as the current CPU has interrupts disabled and
	 * cannot handle the interrupt before the whole set_affinity()
	 * section is done. In the CPU unplug case, the current CPU is
	 * about to vanish and will not handle any interrupts anymore. The
	 * vector is cleaned up when the CPU comes online again.
	 */
	if (IS_ERR_OR_NULL(this_cpu_read(vector_irq[cfg->vector])))
		this_cpu_write(vector_irq[cfg->vector], VECTOR_RETRIGGERED);

	/* Redirect it to the new vector on the local CPU temporarily */
	__pci_write_msi_msg(data->msi_desc, &old_msg);

	/* Now transition it to the target CPU */
	__pci_write_msi_msg(data->msi_desc, &msg);

	/*
	 * All interrupts after this point are now targeted at the new
	 * vector/CPU.
	 *
	 * Drop vector lock before testing whether the temporary assignment
	 * to the local CPU was hit by an interrupt raised in the device,
	 * because the retrigger function acquires vector lock again.
	 */
	unlock_vector_lock();
	/*
	 * Check whether the transition raced with a device interrupt and
	 * is pending in the local APICs IRR. It is safe to do this outside
	 * of vector lock as the irq_desc::lock of this interrupt is still
	 * held and interrupts are disabled: The check is not accessing the
	 * underlying vector store. It's just checking the local APIC's
	 * IRR.
	 */
	if (lapic_vector_set_in_irr(cfg->vector)) {
		printk("Retriger IRQ for cpu %d vector: %u\n", smp_processor_id(), cfg->vector);
		irq_data_get_irq_chip(data)->irq_retrigger(data);
	}

	return IRQ_SET_MASK_OK_NOCOPY;
}

/*
 * IRQ Chip for MSI PCI/PCI-X/PCI-Express Devices,
 * which implement the MSI or MSI-X Capability Structure.
 */
static struct irq_chip msi_chip = {
	.name			= "PCI-MSI",
	.irq_unmask		= pci_msi_unmask_irq,
	.irq_mask		= pci_msi_mask_irq,
	.irq_ack		= apic_ack_edge,
	.irq_set_affinity	= msi_set_affinity,
	.irq_retrigger		= apic_retrigger_irq,
	.flags			= IRQCHIP_SKIP_SET_WAKE,
};

int setup_msi_irq(struct pci_dev *dev, struct msi_desc *msidesc,
		  unsigned int irq_base, unsigned int irq_offset)
{
	struct irq_chip *chip = &msi_chip;
	struct msi_msg msg;
	unsigned int irq = irq_base + irq_offset;
	int ret;

	ret = msi_compose_msg(dev, irq, &msg, -1);
	if (ret < 0)
		return ret;

	irq_set_msi_desc_off(irq_base, irq_offset, msidesc);

	/*
	 * MSI-X message is written per-IRQ, the offset is always 0.
	 * MSI message denotes a contiguous group of IRQs, written for 0th IRQ.
	 */
	if (!irq_offset)
		pci_write_msi_msg(irq, &msg);

	setup_remapped_irq(irq, irq_cfg(irq), chip);

	irq_set_chip_and_handler_name(irq, chip, handle_edge_irq, "edge");

	dev_dbg(&dev->dev, "irq %d for MSI/MSI-X\n", irq);

	return 0;
}

int native_setup_msi_irqs(struct pci_dev *dev, int nvec, int type)
{
	struct msi_desc *msidesc;
	unsigned int irq;
	int node, ret;

	/* Multiple MSI vectors only supported with interrupt remapping */
	if (type == PCI_CAP_ID_MSI && nvec > 1)
		return 1;

	node = dev_to_node(&dev->dev);

	list_for_each_entry(msidesc, &dev->msi_list, list) {
		irq = irq_alloc_hwirq(node);
		if (!irq)
			return -ENOSPC;

		ret = setup_msi_irq(dev, msidesc, irq, 0);
		if (ret < 0) {
			irq_free_hwirq(irq);
			return ret;
		}

	}
	return 0;
}

void native_teardown_msi_irq(unsigned int irq)
{
	irq_free_hwirq(irq);
}

#ifdef CONFIG_DMAR_TABLE
static int
dmar_msi_set_affinity(struct irq_data *data, const struct cpumask *mask,
		      bool force)
{
	struct irq_cfg *cfg = irqd_cfg(data);
	unsigned int dest, irq = data->irq;
	struct msi_msg msg;
	int ret;

	ret = apic_set_affinity(data, mask, &dest);
	if (ret)
		return ret;

	dmar_msi_read(irq, &msg);

	msg.data &= ~MSI_DATA_VECTOR_MASK;
	msg.data |= MSI_DATA_VECTOR(cfg->vector);
	msg.address_lo &= ~MSI_ADDR_DEST_ID_MASK;
	msg.address_lo |= MSI_ADDR_DEST_ID(dest);
	msg.address_hi = MSI_ADDR_BASE_HI | MSI_ADDR_EXT_DEST_ID(dest);

	dmar_msi_write(irq, &msg);

	return IRQ_SET_MASK_OK_NOCOPY;
}

static struct irq_chip dmar_msi_type = {
	.name			= "DMAR_MSI",
	.irq_unmask		= dmar_msi_unmask,
	.irq_mask		= dmar_msi_mask,
	.irq_ack		= apic_ack_edge,
	.irq_set_affinity	= dmar_msi_set_affinity,
	.irq_retrigger		= apic_retrigger_irq,
	.flags			= IRQCHIP_SKIP_SET_WAKE,
};

int arch_setup_dmar_msi(unsigned int irq)
{
	int ret;
	struct msi_msg msg;

	ret = msi_compose_msg(NULL, irq, &msg, -1);
	if (ret < 0)
		return ret;
	dmar_msi_write(irq, &msg);
	irq_set_chip_and_handler_name(irq, &dmar_msi_type, handle_edge_irq,
				      "edge");
	return 0;
}
#endif

/*
 * MSI message composition
 */
#ifdef CONFIG_HPET_TIMER

static int hpet_msi_set_affinity(struct irq_data *data,
				 const struct cpumask *mask, bool force)
{
	struct irq_cfg *cfg = irqd_cfg(data);
	struct msi_msg msg;
	unsigned int dest;
	int ret;

	ret = apic_set_affinity(data, mask, &dest);
	if (ret)
		return ret;

	hpet_msi_read(data->handler_data, &msg);

	msg.data &= ~MSI_DATA_VECTOR_MASK;
	msg.data |= MSI_DATA_VECTOR(cfg->vector);
	msg.address_lo &= ~MSI_ADDR_DEST_ID_MASK;
	msg.address_lo |= MSI_ADDR_DEST_ID(dest);

	hpet_msi_write(data->handler_data, &msg);

	return IRQ_SET_MASK_OK_NOCOPY;
}

static struct irq_chip hpet_msi_type = {
	.name = "HPET_MSI",
	.irq_unmask = hpet_msi_unmask,
	.irq_mask = hpet_msi_mask,
	.irq_ack = apic_ack_edge,
	.irq_set_affinity = hpet_msi_set_affinity,
	.irq_retrigger = apic_retrigger_irq,
	.flags = IRQCHIP_SKIP_SET_WAKE,
};

int default_setup_hpet_msi(unsigned int irq, unsigned int id)
{
	struct irq_chip *chip = &hpet_msi_type;
	struct msi_msg msg;
	int ret;

	ret = msi_compose_msg(NULL, irq, &msg, id);
	if (ret < 0)
		return ret;

	hpet_msi_write(irq_get_handler_data(irq), &msg);
	irq_set_status_flags(irq, IRQ_MOVE_PCNTXT);
	setup_remapped_irq(irq, irq_cfg(irq), chip);

	irq_set_chip_and_handler_name(irq, chip, handle_edge_irq, "edge");
	return 0;
}
#endif
