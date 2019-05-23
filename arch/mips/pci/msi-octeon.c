/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2005-2012 Cavium Inc.
 */
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/msi.h>

#include <asm/octeon/octeon.h>
#include <asm/octeon/cvmx-npi-defs.h>
#include <asm/octeon/cvmx-pci-defs.h>
#include <asm/octeon/cvmx-npei-defs.h>
#include <asm/octeon/cvmx-sli-defs.h>
#include <asm/octeon/cvmx-pexp-defs.h>
#include <asm/octeon/cvmx-sli-defs.h>
#include <asm/octeon/cvmx-ciu2-defs.h>
#include <asm/octeon/pci-octeon.h>

/* MSI major block number (8 MSBs of intsn) */
#define MSI_BLOCK_NUMBER	0x1e

#define MSI_IRQ_SIZE		256

/*
 * Data to save in the chip_data field of the irq description.
 */
struct msi_chip_data {
	int msi;
	int hwmsi;
};

/*
 * Each bit in msi_free_irq_bitmap represents a MSI interrupt that is
 * in use. Each node requires its own set of bits.
 */
static DECLARE_BITMAP(msi_free_irq_bitmap[CVMX_MAX_NODES], MSI_IRQ_SIZE);

/*
 * This lock controls updates to msi_free_irq_bitmap.
 */
static DEFINE_SPINLOCK(msi_free_irq_bitmap_lock);

/* MSI to IRQ lookup */
static int msi_to_irq[MSI_IRQ_SIZE];

/**
 * Called when a device no longer needs its MSI interrupts. All
 * MSI interrupts for the device are freed.
 *
 * @irq:    The devices first irq number. There may be multple in sequence.
 */
void arch_teardown_msi_irq(unsigned int irq)
{
	int old;
	int msi;
	int node = 0; /* Must use node device is in. TODO */

	if (octeon_has_feature(OCTEON_FEATURE_CIU3)) {
		struct octeon_ciu_chip_data *cd3 = irq_get_chip_data(irq);
		msi = cd3->intsn & 0xff;
	} else {
		struct msi_chip_data *cd = irq_get_chip_data(irq);
		msi = cd->msi;
	}

	spin_lock(&msi_free_irq_bitmap_lock);
	old = test_and_clear_bit(msi, msi_free_irq_bitmap[node]);
	spin_unlock(&msi_free_irq_bitmap_lock);

	if (!old) {
		WARN(1, "arch_teardown_msi_irq: Attempted to teardown MSI "
		     "interrupt (%d) not in use", irq);
	}
}

static DEFINE_RAW_SPINLOCK(octeon_irq_msi_lock);

static u64 msi_rcv_reg[4];
static u64 msi_ena_reg[4];

/*
 * Up to 256 MSIs are supported. MSIs are allocated sequencially from 0 to 255.
 * The CIU has 4 interrupt lines each supporting 64 MSIs to handle the 256 MSI
 * interrupts.
 * Software might desire to map MSIs to different CIU interrupt lines to share
 * the load. For example, MSI 0 might be mapped to CIU interrupt line 0, MSI 1
 * to CIU interrupt line 1, and so on.
 * Hardware MSIs indicate the CIU interrupt line and the bit within the line a
 * particular MSI is mapped to.
 * These pointers point to the methods that performs the mapping to use.
 */
static int (*octeon_irq_msi_to_hwmsi)(int);
static int (*octeon_irq_hwmsi_to_msi)(int);

/*
 * MSI to hardware MSI linear mapping. No load sharing. First 64 allocated MSIs
 * go to CIU interrupt line 0, next 64 to the next CIU line and so on.
 */
static int octeon_irq_msi_to_hwmsi_linear(int msi)
{
	return msi;
}

static int octeon_irq_hwmsi_to_msi_linear(int hwmsi)
{
	return hwmsi;
}

/*
 * MSI to hardware MSI scatter mapping. MSI interrupt load is spread among all
 * CIU interrupt lines. MSI 0 goes to CIU line 0, MSI 1 to CIU line 1 and so on.
 */
static int octeon_irq_msi_to_hwmsi_scatter(int msi)
{
	return ((msi << 6) & 0xc0) | ((msi >> 2) & 0x3f);
}

static int octeon_irq_hwmsi_to_msi_scatter(int hwmsi)
{
	return (((hwmsi >> 6) & 0x3) | ((hwmsi << 2) & 0xfc));
}

#ifdef CONFIG_SMP

static atomic_t affinity_in_progress[4] = {
	ATOMIC_INIT(1),
	ATOMIC_INIT(1),
	ATOMIC_INIT(1),
	ATOMIC_INIT(1)};

static int octeon_irq_msi_set_affinity_pcie(struct irq_data *data,
					    const struct cpumask *dest,
					    bool force)
{
	struct msi_chip_data *cd = irq_get_chip_data(data->irq);
	int hwmsi = cd->hwmsi;
	int index = (hwmsi >> 6) & 0x3;
	int bit;
	int r;

	/*
	 * If we are in the middle of updating the set, the first call
	 * takes care of everything, do nothing successfully.
	 */
	if (atomic_sub_if_positive(1, affinity_in_progress + index) < 0)
		return 0;

	r = irq_set_affinity(OCTEON_IRQ_PCI_MSI0 + index, dest);

	for (bit = 0; bit < 64; bit++) {
		int msi = octeon_irq_hwmsi_to_msi(64 * index + bit);
		int partner = msi_to_irq[msi];
		if (partner && partner != data->irq)
			irq_set_affinity(partner, dest);
	}
	atomic_add(1, affinity_in_progress + index);
	return r;
}

static int octeon_irq_msi_set_affinity_pci(struct irq_data *data,
					   const struct cpumask *dest,
					   bool force)
{
	struct msi_chip_data *cd = irq_get_chip_data(data->irq);
	int hwmsi = cd->hwmsi;
	int index = hwmsi >> 4;
	int bit;
	int r;

	/*
	 * If we are in the middle of updating the set, the first call
	 * takes care of everything, do nothing successfully.
	 */
	if (atomic_sub_if_positive(1, affinity_in_progress + index) < 0)
		return 0;

	r = irq_set_affinity(OCTEON_IRQ_PCI_MSI0 + index, dest);

	for (bit = 0; bit < 16; bit++) {
		int msi = octeon_irq_hwmsi_to_msi(64 * index + bit);
		int partner = msi_to_irq[msi];
		if (partner && partner != data->irq)
			irq_set_affinity(partner, dest);
	}
	atomic_add(1, affinity_in_progress + index);
	return r;
}
#endif /* CONFIG_SMP */

static void octeon_irq_msi_enable_pcie(struct irq_data *data)
{
	u64 en;
	unsigned long flags;
	struct msi_chip_data *cd = irq_get_chip_data(data->irq);
	int hwmsi = cd->hwmsi;
	int irq_index = hwmsi >> 6;
	int irq_bit = hwmsi & 0x3f;

	raw_spin_lock_irqsave(&octeon_irq_msi_lock, flags);
	en = cvmx_read_csr(msi_ena_reg[irq_index]);
	en |= 1ull << irq_bit;
	cvmx_write_csr(msi_ena_reg[irq_index], en);
	cvmx_read_csr(msi_ena_reg[irq_index]);
	raw_spin_unlock_irqrestore(&octeon_irq_msi_lock, flags);
	unmask_msi_irq(data);
}

static void octeon_irq_msi_disable_pcie(struct irq_data *data)
{
	u64 en;
	unsigned long flags;
	struct msi_chip_data *cd = irq_get_chip_data(data->irq);
	int hwmsi = cd->hwmsi;
	int irq_index = hwmsi >> 6;
	int irq_bit = hwmsi & 0x3f;

	raw_spin_lock_irqsave(&octeon_irq_msi_lock, flags);
	en = cvmx_read_csr(msi_ena_reg[irq_index]);
	en &= ~(1ull << irq_bit);
	cvmx_write_csr(msi_ena_reg[irq_index], en);
	cvmx_read_csr(msi_ena_reg[irq_index]);
	raw_spin_unlock_irqrestore(&octeon_irq_msi_lock, flags);
	mask_msi_irq(data);
}

static struct irq_chip octeon_irq_chip_msi_pcie = {
	.name = "MSI",
	.irq_enable = octeon_irq_msi_enable_pcie,
	.irq_disable = octeon_irq_msi_disable_pcie,
#ifdef CONFIG_SMP
	.irq_set_affinity = octeon_irq_msi_set_affinity_pcie,
#endif
};

static void octeon_irq_msi_enable_pci(struct irq_data *data)
{
	/*
	 * Octeon PCI doesn't have the ability to mask/unmask MSI
	 * interrupts individually. Instead of masking/unmasking them
	 * in groups of 16, we simple assume MSI devices are well
	 * behaved. MSI interrupts are always enable and the ACK is
	 * assumed to be enough
	 */
}

static void octeon_irq_msi_disable_pci(struct irq_data *data)
{
	/* See comment in enable */
}

static struct irq_chip octeon_irq_chip_msi_pci = {
	.name = "MSI",
	.irq_enable = octeon_irq_msi_enable_pci,
	.irq_disable = octeon_irq_msi_disable_pci,
#ifdef CONFIG_SMP
	.irq_set_affinity = octeon_irq_msi_set_affinity_pci,
#endif
};

/**
 * Called when a driver request MSI interrupts instead of the
 * legacy INT A-D. This routine will allocate multiple interrupts
 * for MSI devices that support them. A device can override this by
 * programming the MSI control bits [6:4] before calling
 * pci_enable_msi().
 *
 * @dev:    Device requesting MSI interrupts
 * @desc:   MSI descriptor
 *
 * Returns 0 on success.
 */
int arch_setup_msi_irq(struct pci_dev *dev, struct msi_desc *desc)
{
	struct msi_msg msg;
	int irq;
	int hwirq;
	int msi;
	struct irq_chip *chip;
	struct irq_domain *domain;
	int node = 0; /* Must use the correct node. TODO */

	/*
	 * We're going to search msi_free_irq_bitmap for zero bits. This
	 * represents an MSI interrupt number that isn't in use.
	 */
	spin_lock(&msi_free_irq_bitmap_lock);
	msi = find_next_zero_bit(msi_free_irq_bitmap[node], MSI_IRQ_SIZE, 0);
	if (msi >= MSI_IRQ_SIZE) {
		spin_unlock(&msi_free_irq_bitmap_lock);
		WARN(1, "arch_setup_msi_irq: Unable to find a free MSI "
		     "interrupt");
		return -ENOSPC;
	}

	set_bit(msi, msi_free_irq_bitmap[node]);
	spin_unlock(&msi_free_irq_bitmap_lock);
	msg.data = msi;

	if (octeon_has_feature(OCTEON_FEATURE_CIU3)) {
		/* Get the domain for the msi interrupts */
		domain = octeon_irq_get_block_domain(node, MSI_BLOCK_NUMBER);

		/* Get a irq for the msi intsn (hardware interrupt) */
		hwirq = MSI_BLOCK_NUMBER << 12 | msi;
		irq = irq_create_mapping(domain, hwirq);
		irqd_set_trigger_type(irq_get_irq_data(irq),
				      IRQ_TYPE_EDGE_RISING);
	} else {
		struct msi_chip_data *cd;
		int hwmsi = octeon_irq_msi_to_hwmsi(msi);

		/* Reuse the irq if already assigned to the msi */
		if (msi_to_irq[msi])
			irq = msi_to_irq[msi];
		else {
			cd = kzalloc_node(sizeof(*cd), GFP_KERNEL, node);
			if (!cd)
				return -ENOMEM;
			cd->msi = msi;
			cd->hwmsi = hwmsi;
			irq = irq_alloc_descs(-1, 1, 1, node);
			if (WARN(irq < 0, "arch_setup_msi_irq: Unable to find a free irq\n")) {
				clear_bit(msi, msi_free_irq_bitmap[node]);
				kfree(cd);
				return -ENOSPC;
			}
			msi_to_irq[msi] = irq;

			/* Initialize the irq description */
			if (octeon_dma_bar_type == OCTEON_DMA_BAR_TYPE_PCIE2)
				chip = &octeon_irq_chip_msi_pcie;
			else if (octeon_dma_bar_type == OCTEON_DMA_BAR_TYPE_PCIE)
				chip = &octeon_irq_chip_msi_pcie;
			else
				chip = &octeon_irq_chip_msi_pci;

			irq_set_chip_and_handler(irq, chip, handle_simple_irq);
			irq_set_chip_data(irq, cd);
		}
	}

	switch (octeon_dma_bar_type) {
	case OCTEON_DMA_BAR_TYPE_SMALL:
		/* When not using big bar, Bar 0 is based at 128MB */
		msg.address_lo =
			((128ul << 20) + CVMX_PCI_MSI_RCV) & 0xffffffff;
		msg.address_hi = ((128ul << 20) + CVMX_PCI_MSI_RCV) >> 32;
		break;
	case OCTEON_DMA_BAR_TYPE_BIG:
		/* When using big bar, Bar 0 is based at 0 */
		msg.address_lo = (0 + CVMX_PCI_MSI_RCV) & 0xffffffff;
		msg.address_hi = (0 + CVMX_PCI_MSI_RCV) >> 32;
		break;
	case OCTEON_DMA_BAR_TYPE_PCIE:
		/* When using PCIe, Bar 0 is based at 0 */
		/* FIXME CVMX_NPEI_MSI_RCV* other than 0? */
		msg.address_lo = (0 + CVMX_NPEI_PCIE_MSI_RCV) & 0xffffffff;
		msg.address_hi = (0 + CVMX_NPEI_PCIE_MSI_RCV) >> 32;
		break;
	case OCTEON_DMA_BAR_TYPE_PCIE2:
		/* When using PCIe2, Bar 0 is based at 0 */
		msg.address_lo = (0 + CVMX_SLI_PCIE_MSI_RCV) & 0xffffffff;
		msg.address_hi = (0 + CVMX_SLI_PCIE_MSI_RCV) >> 32;
		break;
	default:
		panic("arch_setup_msi_irq: Invalid octeon_dma_bar_type");
	}

	irq_set_msi_desc(irq, desc);
	write_msi_msg(irq, &msg);
	return 0;
}

/*
 * Called by the interrupt handling code when an MSI interrupt
 * occurs.
 */
static irqreturn_t __octeon_msi_do_interrupt(int index, u64 msi_bits)
{
	int bit;
	int msi;
	int irq;

	bit = fls64(msi_bits);
	if (bit) {
		bit--;
		/* Acknowledge it first. */
		cvmx_write_csr(msi_rcv_reg[index], 1ull << bit);

		msi = octeon_irq_hwmsi_to_msi(bit + 64 * index);
		irq = msi_to_irq[msi];

		generic_handle_irq(irq);
		return IRQ_HANDLED;
	}
	return IRQ_NONE;
}

#define OCTEON_MSI_INT_HANDLER_X(x)					\
static irqreturn_t octeon_msi_interrupt##x(int cpl, void *dev_id)	\
{									\
	u64 msi_bits = cvmx_read_csr(msi_rcv_reg[(x)]);			\
	return __octeon_msi_do_interrupt((x), msi_bits);		\
}

/*
 * Create octeon_msi_interrupt{0-3} function body
 */
OCTEON_MSI_INT_HANDLER_X(0);
OCTEON_MSI_INT_HANDLER_X(1);
OCTEON_MSI_INT_HANDLER_X(2);
OCTEON_MSI_INT_HANDLER_X(3);

static void octeon_irq_msi_ciu3_ack(struct irq_data *data)
{
	u64 csr_addr;
	struct octeon_ciu_chip_data *cd;
	int msi;

	octeon_irq_ciu3_ack(data);

	cd = irq_data_get_irq_chip_data(data);

	/* Acknowledge lsi (msi) interrupt (get the node from the ciu3 addr) */
	msi = cd->intsn & 0xff;
	csr_addr = (cd->ciu3_addr & CVMX_NODE_MASK) | msi_rcv_reg[msi >> 6];
	cvmx_write_csr(csr_addr, 1 << (msi & 0x3f));
}

static void octeon_irq_msi_ciu3_mask_ack(struct irq_data *data)
{
	u64 csr_addr;
	struct octeon_ciu_chip_data *cd;
	int msi;

	octeon_irq_ciu3_mask_ack(data);

	cd = irq_data_get_irq_chip_data(data);

	/* Acknowledge lsi (msi) interrupt (get the node from the ciu3 addr) */
	msi = cd->intsn & 0xff;
	csr_addr = (cd->ciu3_addr & CVMX_NODE_MASK) | msi_rcv_reg[msi >> 6];
	cvmx_write_csr(csr_addr, 1 << (msi & 0x3f));
}

static void octeon_irq_msi_ciu3_enable(struct irq_data *data)
{
	octeon_irq_ciu3_enable(data);
	unmask_msi_irq(data);
}

static void octeon_irq_msi_ciu3_disable(struct irq_data *data)
{
	octeon_irq_ciu3_disable(data);
	mask_msi_irq(data);
}

static struct irq_chip octeon_irq_msi_chip_ciu3 = {
	.name = "MSI-X",
	.irq_enable = octeon_irq_msi_ciu3_enable,
	.irq_disable = octeon_irq_msi_ciu3_disable,
	.irq_ack = octeon_irq_msi_ciu3_ack,
	.irq_mask = octeon_irq_ciu3_mask,
	.irq_mask_ack = octeon_irq_msi_ciu3_mask_ack,
	.irq_unmask = octeon_irq_ciu3_enable,
#ifdef CONFIG_SMP
	.irq_set_affinity = octeon_irq_ciu3_set_affinity,
#endif
};

static int octeon_irq_msi_ciu3_map(struct irq_domain *d,
				   unsigned int virq, irq_hw_number_t hw)
{
	return octeon_irq_ciu3_mapx(d, virq, hw, &octeon_irq_msi_chip_ciu3);
}

struct irq_domain_ops octeon_msi_domain_ciu3_ops = {
	.map = octeon_irq_msi_ciu3_map,
	.unmap = octeon_irq_free_cd,
	.xlate = octeon_irq_ciu3_xlat,
};

/*
 * Initializes the MSI interrupt handling code
 */
int __init octeon_msi_initialize(void)
{
	struct irq_domain *domain;
	u64 msi_map_reg;
	int i;
	int node = 0; /* Must use correct node. TODO */

	/* Clear msi irq bitmap */
	for (i = 0; i < CVMX_MAX_NODES; i++)
		bitmap_zero(msi_free_irq_bitmap[i], MSI_IRQ_SIZE);

	if (octeon_has_feature(OCTEON_FEATURE_CIU3)) {
		/* MSI interrupts use their own domain */
		domain = irq_domain_add_tree(NULL, &octeon_msi_domain_ciu3_ops,
					     octeon_irq_get_ciu3_info(node));
		octeon_irq_add_block_domain(node, MSI_BLOCK_NUMBER, domain);

		/* Registers to acknowledge msi interrupts */
		msi_rcv_reg[0] = CVMX_PEXP_SLI_MSI_RCV0;
		msi_rcv_reg[1] = CVMX_PEXP_SLI_MSI_RCV1;
		msi_rcv_reg[2] = CVMX_PEXP_SLI_MSI_RCV2;
		msi_rcv_reg[3] = CVMX_PEXP_SLI_MSI_RCV3;
		return 0;
	}

	if (octeon_dma_bar_type == OCTEON_DMA_BAR_TYPE_PCIE2) {
		msi_rcv_reg[0] = CVMX_PEXP_SLI_MSI_RCV0;
		msi_rcv_reg[1] = CVMX_PEXP_SLI_MSI_RCV1;
		msi_rcv_reg[2] = CVMX_PEXP_SLI_MSI_RCV2;
		msi_rcv_reg[3] = CVMX_PEXP_SLI_MSI_RCV3;
		msi_ena_reg[0] = CVMX_PEXP_SLI_MSI_ENB0;
		msi_ena_reg[1] = CVMX_PEXP_SLI_MSI_ENB1;
		msi_ena_reg[2] = CVMX_PEXP_SLI_MSI_ENB2;
		msi_ena_reg[3] = CVMX_PEXP_SLI_MSI_ENB3;
		octeon_irq_msi_to_hwmsi = octeon_irq_msi_to_hwmsi_scatter;
		octeon_irq_hwmsi_to_msi = octeon_irq_hwmsi_to_msi_scatter;
		msi_map_reg = CVMX_PEXP_SLI_MSI_WR_MAP;
	} else if (octeon_dma_bar_type == OCTEON_DMA_BAR_TYPE_PCIE) {
		msi_rcv_reg[0] = CVMX_PEXP_NPEI_MSI_RCV0;
		msi_rcv_reg[1] = CVMX_PEXP_NPEI_MSI_RCV1;
		msi_rcv_reg[2] = CVMX_PEXP_NPEI_MSI_RCV2;
		msi_rcv_reg[3] = CVMX_PEXP_NPEI_MSI_RCV3;
		msi_ena_reg[0] = CVMX_PEXP_NPEI_MSI_ENB0;
		msi_ena_reg[1] = CVMX_PEXP_NPEI_MSI_ENB1;
		msi_ena_reg[2] = CVMX_PEXP_NPEI_MSI_ENB2;
		msi_ena_reg[3] = CVMX_PEXP_NPEI_MSI_ENB3;
		octeon_irq_msi_to_hwmsi = octeon_irq_msi_to_hwmsi_scatter;
		octeon_irq_hwmsi_to_msi = octeon_irq_hwmsi_to_msi_scatter;
		msi_map_reg = CVMX_PEXP_NPEI_MSI_WR_MAP;
	} else {
		msi_rcv_reg[0] = CVMX_NPI_NPI_MSI_RCV;
#define INVALID_GENERATE_ADE 0x8700000000000000ULL;
		msi_rcv_reg[1] = INVALID_GENERATE_ADE;
		msi_rcv_reg[2] = INVALID_GENERATE_ADE;
		msi_rcv_reg[3] = INVALID_GENERATE_ADE;
		msi_ena_reg[0] = INVALID_GENERATE_ADE;
		msi_ena_reg[1] = INVALID_GENERATE_ADE;
		msi_ena_reg[2] = INVALID_GENERATE_ADE;
		msi_ena_reg[3] = INVALID_GENERATE_ADE;
		octeon_irq_msi_to_hwmsi = octeon_irq_msi_to_hwmsi_linear;
		octeon_irq_hwmsi_to_msi = octeon_irq_hwmsi_to_msi_linear;
		msi_map_reg = 0;
	}

	if (msi_map_reg) {
		int msi;
		int ciu;
		u64 e;

		for (msi = 0; msi < 256; msi++) {
			ciu = (msi >> 2) | ((msi << 6) & 0xc0);
			e = (ciu << 8) | msi;
			cvmx_write_csr(msi_map_reg, e);
		}
	}

	if (octeon_has_feature(OCTEON_FEATURE_PCIE)) {
		if (request_irq(OCTEON_IRQ_PCI_MSI0, octeon_msi_interrupt0,
				0, "MSI[0:63]", octeon_msi_interrupt0))
			panic("request_irq(OCTEON_IRQ_PCI_MSI0) failed");

		if (request_irq(OCTEON_IRQ_PCI_MSI1, octeon_msi_interrupt1,
				0, "MSI[64:127]", octeon_msi_interrupt1))
			panic("request_irq(OCTEON_IRQ_PCI_MSI1) failed");

		if (request_irq(OCTEON_IRQ_PCI_MSI2, octeon_msi_interrupt2,
				0, "MSI[127:191]", octeon_msi_interrupt2))
			panic("request_irq(OCTEON_IRQ_PCI_MSI2) failed");

		if (request_irq(OCTEON_IRQ_PCI_MSI3, octeon_msi_interrupt3,
				0, "MSI[192:255]", octeon_msi_interrupt3))
			panic("request_irq(OCTEON_IRQ_PCI_MSI3) failed");
	} else if (octeon_is_pci_host()) {
		if (request_irq(OCTEON_IRQ_PCI_MSI0, octeon_msi_interrupt0,
				0, "MSI[0:15]", octeon_msi_interrupt0))
			panic("request_irq(OCTEON_IRQ_PCI_MSI0) failed");

		if (request_irq(OCTEON_IRQ_PCI_MSI1, octeon_msi_interrupt0,
				0, "MSI[16:31]", octeon_msi_interrupt0))
			panic("request_irq(OCTEON_IRQ_PCI_MSI1) failed");

		if (request_irq(OCTEON_IRQ_PCI_MSI2, octeon_msi_interrupt0,
				0, "MSI[32:47]", octeon_msi_interrupt0))
			panic("request_irq(OCTEON_IRQ_PCI_MSI2) failed");

		if (request_irq(OCTEON_IRQ_PCI_MSI3, octeon_msi_interrupt0,
				0, "MSI[48:63]", octeon_msi_interrupt0))
			panic("request_irq(OCTEON_IRQ_PCI_MSI3) failed");
	}
	return 0;
}
