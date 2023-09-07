// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020-2021, Pensando Systems Inc.
 *
 * UIO driver for the device using the GIC interrupts for the Pensando
 * Capri and Elba ASIC. This includes status/error registers.
 *
 * To do:
 * o	Get enable_csr from the "reg" property
 * o	Get enable_mask from the device nodes "interrupts" property
 *
 */

#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/platform_data/uio_dmem_genirq.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uio_driver.h>
#include <linux/atomic.h>
#include <linux/irqchip/irq-pensando.h>

/* Probably should be defined in irq.h, but isn't */
#define NO_IRQ		0

#define MAP_ERROR	(~0)		/* Invalid address */

/*
 * If set, will print a status message from the IRQ handler. This can be
 * very helpful when trying to determine whether the device tree has the
 * correct parent/child structure
 */
#undef PRINT_HANDLER_STATUS

#ifdef PRINT_HANDLER_STATUS
#define handler_status(fmt, ...) pr_err(fmt, ##__VA_ARGS__)
#else
#define handler_status(fmt, ...) do { } while (false)
#endif

/*
 * pengic_platdata - platform data for one UIO device
 * @name:		Name of the driver
 * @reg_type:		Type of register block we're dealing with
 * @flags:
 * @pdev:		Pointer to struct platform_device
 * @n_res:		Number of entries in @res[] used
 * @res:		Struct resource that defines the address and size of
 *			the CSR
 * @node:		Pointer to the open firmware device node for this
 *			device;
 * @enable_mask:	Mask of bits to be set to enable the interrupt(s)
 * @enable_csr:		Virtual address of the pen_ictlr_csr for this child
 * @uio_info:		Pointer to the associated struct uio_info
 * @dev:		Pointer to the struct device for this device
 * @cmd:		Information for the command file
 * @pengic_dir:		Pointer to information about the pengic directory
 *			in which the command file lives
 * @irq:		Kernel interrupt number
 * @disables_lock:	Spin lock protecting the @disables member
 * @disable:		Number of outstanding disables. Incremented for
 *			each disable call, decremented for each enable call
 */
struct pengic_platdata {
	const char		*name;
	enum reg_type		reg_type;
	unsigned long		flags;
	unsigned int		n_res;
	struct resource		res[MAX_UIO_MAPS];
	struct device_node	*node;
	u32			enable_mask;
	struct pen_ictlr_csr	*enable_csr;
	struct uio_info		*uio_info;
	struct device		*dev;
	unsigned int		irq;
};

static void pengic_enable_intr_nolock(struct pengic_platdata *platdata)
{
	struct irq_desc *desc;
	struct irq_data *irq_data;

	desc = irq_to_desc(platdata->irq);
	irq_data = &desc->irq_data;

	switch (platdata->reg_type) {
	case REG_TYPE_CSR:
		pen_irq_unmask_enable_csr_one(irq_data);
		break;

	case REG_TYPE_GRP:
		pen_irq_unmask_enable_grp_one(irq_data);
		break;

	case REG_TYPE_CSRINTR:
		pen_irq_unmask_enable_csrintr_one(irq_data);
		break;

	default:
		pr_err("%pOF: Unknown register type: %d\n",
			platdata->node, platdata->reg_type);
		break;
	}

}

/*
 * Enable the register in the bottom-most interrupt domain controller. We
 * only call the real enable function when we have zero outstanding
 * disables.
 *
 * It's ugly that this calls directly into functions for the interrupt
 * domain controller but it's either that or duplicate code.
 */
static void pengic_enable_intr(struct pengic_platdata *platdata)
{
	pengic_enable_intr_nolock(platdata);
}

static void pengic_disable_intr_nolock(struct pengic_platdata *platdata)
{
	struct irq_desc *desc;
	struct irq_data *irq_data;

	desc = irq_to_desc(platdata->irq);
	irq_data = &desc->irq_data;

	/*
	 * If this is the first disable call, actually do the disable.
	 * Otherwise, we are already disabled and skip the call
	 */
	switch (platdata->reg_type) {
	case REG_TYPE_CSR:
		pen_irq_mask_disable_csr_one(irq_data);
		break;

	case REG_TYPE_GRP:
		pen_irq_mask_disable_grp_one(irq_data);
		break;

	case REG_TYPE_CSRINTR:
		pen_irq_mask_disable_csrintr_one(irq_data);
		break;

	default:
		pr_err("Unknown register type: %d\n",
			platdata->reg_type);
		break;
	}
}

static void pengic_disable_intr(struct pengic_platdata *platdata)
{
	pengic_disable_intr_nolock(platdata);
}

static int pengic_open(struct uio_info *uioinfo, struct inode *inode)
{
	struct pengic_platdata *platdata;
	int ret;

	ret = 0;
	platdata = uioinfo->priv;
	pm_runtime_get_sync(platdata->dev);

	return ret;
}

/*
 * pengic_release - called when the device has no more open file descriptors
 *	and it was enough to use end-of-interrupt handling
 */
static int pengic_release(struct uio_info *uioinfo, struct inode *inode)
{
	struct pengic_platdata *platdata;

	platdata = uioinfo->priv;
	pm_runtime_put_sync(platdata->dev);

	return 0;
}

/*
 * pengic_release_enable - called when the device has no more open file
 *	descriptors when the interrupt had to be disabled in addition to
 *	performing end-of-interrupt processing. This ensures that the
 *	interrupt is enabled on exit.
 */
static int pengic_release_enable(struct uio_info *uioinfo, struct inode *inode)
{
	struct pengic_platdata *platdata;
	int rc;

	platdata = uioinfo->priv;

#ifdef FORCE_ENABLE_ON_RELEASE
	/*
	 * If the interrupt chain is disabled, enable it
	 *
	 * No need to lock here, there is nobody else contending for this
	 * data structure
	 */
	if (platdata->disables != 0)
		pengic_enable_intr_nolock(platdata);
#endif
	rc = pengic_release(uioinfo, inode);

	return rc;
}

/*
 * Read the register where bits are set when interrupts happen. Note that
 * an undefined reg_type will cause a zero to be returned, which will
 * cause an IRQ_NONE to be returned to the caller of the IRQ handler.
 */
static uint32_t pengic_read_status(enum reg_type reg_type, void *p)
{
	uint32_t intr_status;

	switch (reg_type) {
	case REG_TYPE_CSR:
		intr_status = readl(&((struct pen_ictlr_csr *)p)->intreg);
		break;

	case REG_TYPE_GRP:
		intr_status = readl(&((struct pen_ictlr_grp *)p)->intreg);
		break;

	case REG_TYPE_CSRINTR:
		intr_status = readl(&((struct pen_ictlr_csrintr *)p)->intr);
		break;

	default:
		intr_status = 0;	/* Always causes IRQ_NONE */
		break;
	}

	return intr_status;
}

/*
 * Handle an IRQ assuming the default EOI processing is sufficient to
 * renable the interrupt.
 */
static irqreturn_t pengic_handler(int virq, struct uio_info *uioinfo)
{
	struct pengic_platdata *platdata;
	struct irq_desc *irq_desc;
	u32 intr_status, enable_mask;
	irq_hw_number_t hwirq;
	unsigned int i;

	platdata = uioinfo->priv;
	irq_desc = irq_to_desc(virq);
	hwirq = irq_desc->irq_data.hwirq;
	enable_mask = 1 << hwirq;

	for (i = 0; i < platdata->n_res; i++) {
		void *p;

		p = uioinfo->mem[i].internal_addr + uioinfo->mem[i].offs;
		intr_status = pengic_read_status(platdata->reg_type, p);
		if ((intr_status & enable_mask) != 0)
			return IRQ_HANDLED;	/* This is our interrupt */
	}

	return IRQ_NONE;
}

/*
 * Handle an IRQ assuming the default EOI processing is insufficient to
 * renable the interrupt. Instead, the interrupt is disabled here and enabled
 * through the irqcontrol function invoked from userspace via write().
 */
static irqreturn_t pengic_handler_disable(int virq, struct uio_info *uioinfo)
{
	irqreturn_t rc;

	rc = pengic_handler(virq, uioinfo);
	if (rc == IRQ_HANDLED) {
		struct pengic_platdata *platdata;

		platdata = uioinfo->priv;
		pengic_disable_intr(platdata);
	}

	return rc;
}

/* Unmap the first n elements */
static void unmap_asic(struct uio_info *uioinfo, unsigned int n,
		       struct device *dev)
{
	unsigned int i;

	for (i = 0; uioinfo->mem[i].size != 0; i++) {
		struct uio_mem *mem;

		mem = &uioinfo->mem[i];

		if (mem->internal_addr == NULL) {
			dev_warn(dev,
				"mem[%td].internal_addr is unexpectdly NULL\n",
				mem - uioinfo->mem);
		} else {
			iounmap(mem->internal_addr);
			mem->internal_addr = NULL;	/* paranoia */
		}

		if (mem->name == NULL) {
			dev_warn(dev, "mem[%td].name is unexpectdly NULL\n",
				mem - uioinfo->mem);
		} else {
			kfree(mem->name);
			mem->name = NULL;		/* More paranoia */
		}
	}
}

/*
 * Returns the number of resources on success, otherwise a negative errno
 * value
 */
static int map_asic(struct uio_info *uio_info, struct device *dev,
	struct device_node *node, struct resource *res, unsigned int n_res)
{
	unsigned int i;
	int ret;

	for (i = 0; i < n_res; i++) {
		struct uio_mem *mem;
		size_t unrounded_size;
		size_t rounded_size;

		ret = of_address_to_resource(node, i, &res[i]);
		if (ret != 0)
			break;

		mem = &uio_info->mem[i];

		/* Offset with the page in which the device registers reside */
		mem->offs = res[i].start & ~PAGE_MASK;
		/* Physical address, aligned on a page boundary */
		mem->addr = res[i].start - mem->offs;
		if (node->name != NULL)
			mem->name = kstrdup(node->name, GFP_KERNEL);

		/*
		 * Size of an area completely containing the device registers
		 * of interest. Must be multiple of the page size
		 */
		unrounded_size = mem->offs + resource_size(res);
		rounded_size = (unrounded_size + (PAGE_SIZE - 1)) & PAGE_MASK;
		mem->size = rounded_size;

		/* Specify we have physical memory, then map it */
		mem->memtype = UIO_MEM_PHYS;
		mem->internal_addr = ioremap(mem->addr, mem->size);

		if (mem->internal_addr == NULL)
			break;
	}

	return i;
}

static int pengic_irqcontrol(struct uio_info *info, s32 irq_on)
{
	struct pengic_platdata *platdata;

	platdata = info->priv;

	switch (irq_on) {
	case 0:
		pengic_disable_intr(platdata);
		break;

	case 1:
		pengic_enable_intr(platdata);
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static int set_uio_info(struct uio_info *uio_info,
	struct device *dev, struct device_node *node,
	irqreturn_t (*pengic_handler)(int irq, struct uio_info *uioinfo))
{
	const char *dt_name;
	int irq;
	int ret;

	ret = of_property_read_string(node, "name", &dt_name);
	if (ret != 0)
		dt_name = "pengic";
	uio_info->name = kstrdup(dt_name, GFP_KERNEL);
	if (uio_info->name == NULL)
		return -ENOMEM;
	uio_info->version = "0.0.1";

	irq = irq_of_parse_and_map(node, 0);
	if (irq == 0) {
		dev_warn(dev, "no interrupt found for %pOF\n", node);
		uio_info->irq = UIO_IRQ_NONE;
		return -ENXIO;
	}

	uio_info->irq = irq;
	uio_info->irq_flags = IRQF_SHARED;
	uio_info->handler = pengic_handler;
	uio_info->irqcontrol = pengic_irqcontrol;

	return 0;
}

static void free_uio_info(struct uio_info *uio_info, unsigned int n_res,
			  struct device *dev)
{
	if (uio_info->name != NULL) {
		kfree(uio_info->name);
		uio_info->name = NULL;
	}

	uio_info->handler = NULL;
	uio_info->irqcontrol = NULL;
	unmap_asic(uio_info, n_res, dev);
}

static void free_platdata(struct pengic_platdata *platdata)
{
	kfree(platdata);
}

static enum reg_type get_reg_type(struct device_node *node)
{
	const char *reg_type_name;
	int rc;

	rc = of_property_read_string(node, "register-type", &reg_type_name);
	if (rc != 0)
		return REG_TYPE_UNKNOWN;
	if (strcmp(reg_type_name, "csr") == 0)
		return REG_TYPE_CSR;
	if (strcmp(reg_type_name, "group") == 0)
		return REG_TYPE_GRP;
	if (strcmp(reg_type_name, "csr-interrupt") == 0)
		return REG_TYPE_CSRINTR;

	pr_warn("Unknown register type: %s\n", reg_type_name);
	return REG_TYPE_UNKNOWN;
}

static int set_platdata(struct pengic_platdata *platdata,
	const struct uio_info *uioinfo, struct platform_device *pdev)
{
	struct device_node *node;
	int ret;
	u32 fw_param;

	/* Initialize the platform data */

	platdata->node = pdev->dev.of_node;
	platdata->dev = &pdev->dev;
	platdata->name = uioinfo->name;

	platdata->irq = uioinfo->irq;
	node = platdata->node;

	platdata->reg_type = get_reg_type(platdata->node);

	ret = map_asic(platdata->uio_info, platdata->dev, node,
		platdata->res, ARRAY_SIZE(platdata->res));
	if (ret < 0) {
		dev_err(platdata->dev, "can't map ASIC registers\n");
		return ret;
	}

	platdata->n_res = ret;

	/*
	 * Get the interrupt number. This must be the first of a three
	 * element irq_fwspec. Can check "#interrupt-cells" if necessary.
	 */
	ret = of_property_read_u32_index(platdata->node, "interrupts", 2,
		&fw_param);
	if (ret != 0)
		return ret;
	platdata->enable_mask = 1 << fw_param;

	return 0;
}

/*
 * pengic_probe - allocate and initialize state for device
 * @pdev:	Pointer to the platform device
 * @handler_fn:	Pointer to the IRQ handler
 * @release_fn:	Pointer to the release function (called when the last file
 *		descriptor is closed)
 */
static int pengic_probe_common(struct platform_device *pdev,
	irqreturn_t (*handler_fn)(int irq, struct uio_info *uioinfo),
	int (*release_fn)(struct uio_info *uioinfo, struct inode *inode))
{
	struct device_node *node;
	struct pengic_platdata *platdata;
	struct uio_info *uio_info;
	unsigned int i;
	int ret;

	ret = -EINVAL;
	node = pdev->dev.of_node;

	/* Allocate space for the platform-specific data */
	platdata = kzalloc(sizeof(*platdata), GFP_KERNEL);
	if (platdata == NULL)
		return -ENOMEM;

	uio_info = kzalloc(sizeof(*uio_info), GFP_KERNEL);
	if (uio_info == NULL) {
		kfree(platdata);
		return -ENOMEM;
	}

	uio_info->priv = platdata;
	platdata->uio_info = uio_info;

	ret = set_uio_info(uio_info, &pdev->dev, node, handler_fn);
	if (ret != 0)
		goto free_name;

	ret = set_platdata(platdata, uio_info, pdev);
	if (ret != 0)
		goto free_uioinfo;

	platform_set_drvdata(pdev, platdata);
	uio_info->open = pengic_open;
	uio_info->release = release_fn;
	uio_info->priv = platdata;

	/* Map the device */
	if (dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64)) != 0) {
		dev_err(&pdev->dev, "no valid coherent DMA mask");
		goto free_platdata;
	}

	pm_runtime_enable(&pdev->dev);

	/* Ready to be a grown up UIO device now */
	ret = uio_register_device(&pdev->dev, platdata->uio_info);
	if (ret != 0) {
		dev_err(&pdev->dev, "can't register UIO device: ret %d", ret);
		pm_runtime_disable(&pdev->dev);
		goto free_platdata;
	}

	/* Print mapping report */
	for (i = 0; i < platdata->n_res; i++) {
		dev_info(platdata->dev, "0x%llx->%p\n",
			platdata->res[i].start,
			uio_info->mem[i].internal_addr);
	}

	return 0;

free_platdata:
	free_platdata(platdata);

free_uioinfo:
	free_uio_info(uio_info, ARRAY_SIZE(platdata->res), platdata->dev);

free_name:
	kfree(uio_info->name);
	uio_info->name = NULL;

	dev_err(platdata->dev, "probe failed\n");
	return ret;
}

/*
 * pengic_probe - allocate and initialize state for device where normal EOI
 *	processing is sufficient to process an interrupt
 * @pdev:		Pointer to the platform device
 */
int pengic_probe(struct platform_device *pdev)
{
	return pengic_probe_common(pdev, pengic_handler, pengic_release);
}
EXPORT_SYMBOL(pengic_probe);

/*
 * pengic_probe_enable - allocate and initialize state for device where an
 *	explicit call to irq_enable() is required to process an interrupt.
 * @pdev:		Pointer to the platform device
 */
int pengic_probe_enable(struct platform_device *pdev)
{
	return pengic_probe_common(pdev, pengic_handler_disable,
		pengic_release_enable);
}
EXPORT_SYMBOL(pengic_probe_enable);

/*
 * pengic_remove - free UIO-related data structures
 *
 * @pdev:	Pointer to the platform_device structure to remove
 */
int pengic_remove(struct platform_device *pdev)
{
	struct pengic_platdata *platdata;
	struct uio_info *uio_info;
	unsigned int n_res;

	platdata = platform_get_drvdata(pdev);
	uio_info = platdata->uio_info;
	platdata->uio_info = NULL;
	uio_info->priv = NULL;
	n_res = platdata->n_res;

	/* This should not be necessary but it's defensive programing in
	 * case this driver gets called after it has been shutdown
	 */
	platform_set_drvdata(pdev, NULL);

	free_platdata(platdata);
	free_uio_info(uio_info, n_res, &pdev->dev);

	pm_runtime_disable(&pdev->dev);

	return 0;
}
EXPORT_SYMBOL(pengic_remove);

/*
 * pengic_pm_nop - Power management stub that just returns success
 *
 * We leave it to other drivers to handle the device power management
 * operations, if any.
 */
static int pengic_pm_nop(struct device *dev)
{
	return 0;
}

const struct dev_pm_ops pengic_pm_ops = {
	.runtime_suspend = pengic_pm_nop,
	.runtime_resume = pengic_pm_nop,
};
EXPORT_SYMBOL(pengic_pm_ops);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Support userspace I/O for Pensando Ring interrupts");
MODULE_AUTHOR("David VomLehn");
