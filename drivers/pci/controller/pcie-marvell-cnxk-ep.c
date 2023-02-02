// SPDX-License-Identifier: GPL-2.0
/* Marvell OcteonTx2 PEM EP driver
 *
 * Copyright (C) 2022 Marvell.
 */

#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/interrupt.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/uio_driver.h>
#include <linux/miscdevice.h>

#define PEM_EP_DRV_NAME		"marvell-cnxk-ep"

#define PEM_DIS_PORT		0x50ull
#define PEM_CFG                 0x00D8ull
#define PEM_RST_INT             0x0300ull
#define PEM_RST_INT_ENA_W1C     0x0310ull
#define PEM_RST_INT_ENA_W1S     0x0318ull
#define PEM_BAR4_INDEX(x)	(0x700ull | (x << 3))

#define PEM_RST_INT_B_L2        BIT_ULL(2)
#define PEM_RST_INT_B_LINKDOWN  BIT_ULL(1)
#define PEM_RST_INT_B_PERST     BIT_ULL(0)

/* Address valid bit */
#define PEM_BAR4_INDEX_ADDR_V		BIT_ULL(0)
/* Access Cached bit */
#define PEM_BAR4_INDEX_CA		BIT_ULL(3)
#define PEM_BAR4_INDEX_ADDR_IDX(x)	((x) << 4)

#define PEM_BAR4_NUM_INDEX	8
#define PEM_BAR4_INDEX_START	7
#define PEM_BAR4_INDEX_END	13
#define PEM_BAR4_INDEX_SIZE	0x400000ULL
#define PEM_BAR4_INDEX_SHIFT	22
#define PEM_BAR4_INDEX_MEM	((PEM_BAR4_INDEX_END - PEM_BAR4_INDEX_START + 1) \
				 * PEM_BAR4_INDEX_SIZE)
#define PEM_BAR4_INDEX_START_OFFSET (PEM_BAR4_INDEX_START * PEM_BAR4_INDEX_SIZE)
#define PEM_BAR4_INDEX_END_OFFSET (((PEM_BAR4_INDEX_END + 1) * \
				    PEM_BAR4_INDEX_SIZE) - 1)

#define PEM_HW_INST(a)		((a >> 36) & 0xF)

/* Some indexes have specific non-memory uses */
#define PEM_BAR4_INDEX_PTP	14
#define MIO_PTP_BASE_ADDR	0x807000000f00

#define PEM_BAR4_INDEX_RSVD1	15

#define	UIO_PERST_VERSION	"0.1"

struct mv_pem_ep {
	struct device	*dev;
	void __iomem	*base;
	void		*va[PEM_BAR4_NUM_INDEX];
	u8		pem;
	char		uio_name[16];
	struct uio_info	uio_rst_int_perst;
	char		mdev_name[32];
	struct miscdevice mdev;
};

static u64 pem_ep_reg_read(struct mv_pem_ep *pem_ep, u64 offset)
{
	return readq(pem_ep->base + offset);
}

static void pem_ep_reg_write(struct mv_pem_ep *pem_ep, u64 offset, u64 val)
{
	writeq(val, pem_ep->base + offset);
}

static irqreturn_t pem_rst_perst_handler(int irq, struct uio_info *uio_info)
{
	struct mv_pem_ep *pem_ep;
	u64 regval;

	pem_ep = container_of(uio_info, struct mv_pem_ep, uio_rst_int_perst);

	regval = pem_ep_reg_read(pem_ep, PEM_RST_INT);
	if (regval & PEM_RST_INT_B_PERST)
		pem_ep_reg_write(pem_ep, PEM_RST_INT, PEM_RST_INT_B_PERST);
	else
		return IRQ_NONE;

	return IRQ_HANDLED;
}

static int register_perst_uio_dev(struct platform_device *pdev, struct mv_pem_ep *pem_ep)
{
	struct device_node *of_node;
	struct uio_info *uio_info;
	struct device *dev;
	int irq, ret;
	u64 regval;

	dev = &pdev->dev;
	of_node = dev->of_node;

	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return irq;

	uio_info = &pem_ep->uio_rst_int_perst;
	snprintf(pem_ep->uio_name, 16, "PEM%d_PERST", pem_ep->pem);
	uio_info->name = pem_ep->uio_name;
	uio_info->version = UIO_PERST_VERSION;
	uio_info->irq = irq;
	uio_info->irq_flags = IRQF_SHARED;
	uio_info->handler = pem_rst_perst_handler;

	ret = uio_register_device(dev, uio_info);
	if (ret != 0) {
		dev_err(dev, "Error %d registering PERST UIO device\n", ret);
		ret = -ENODEV;
		goto err_exit;
	}

	/* clear all RST interrupt enables */
	pem_ep_reg_write(pem_ep, PEM_RST_INT_ENA_W1C,
			 PEM_RST_INT_B_L2 | PEM_RST_INT_B_LINKDOWN | PEM_RST_INT_B_PERST);

	/* clear RST interrupt status */
	regval = pem_ep_reg_read(pem_ep, PEM_RST_INT);
	pem_ep_reg_write(pem_ep, PEM_RST_INT, regval);

	/* set RST PERST & LINKDOWN interrupt enables */
	pem_ep_reg_write(pem_ep, PEM_RST_INT_ENA_W1S,
			 PEM_RST_INT_B_PERST | PEM_RST_INT_B_LINKDOWN);

	return 0;

err_exit:
	return ret;
}

static int pem_ep_bar_setup(struct mv_pem_ep *pem_ep)
{
	unsigned long order, page;
	phys_addr_t pa;
	uint64_t val;
	int idx, i;

	order = get_order(PEM_BAR4_INDEX_SIZE);

	for (idx = PEM_BAR4_INDEX_START; idx < PEM_BAR4_INDEX_END + 1; idx++) {
		int i;

		/* Each index in BAR4 points to a 4MB region */
		i = idx - PEM_BAR4_INDEX_START;

		page = __get_free_pages(GFP_KERNEL, order);
		memset((char *)page, 0, PAGE_SIZE << order);
		pem_ep->va[i] = (void *)page;
		if (!pem_ep->va[i]) {
			dev_err(pem_ep->dev, "cannot allocate bar mem\n");
			goto err;
		}

		pa = virt_to_phys(pem_ep->va[i]);
		if (pa & (PEM_BAR4_INDEX_SIZE - 1)) {
			dev_err(pem_ep->dev, "paddr not aligned pa:0x%llx\n",
				pa);
			goto err;
		}

		/* IOVA 52:22 is used by hardware */
		val = PEM_BAR4_INDEX_ADDR_IDX(pa >> 22);
		val |= PEM_BAR4_INDEX_ADDR_V;
		pem_ep_reg_write(pem_ep, PEM_BAR4_INDEX(idx), val);
	}
	/* Set up mapping used by host PHC driver, which needs access to
	 * PTP registers on Octeon.  This overrides the generic memory
	 * mapping for this index done above.
	 */
	val = PEM_BAR4_INDEX_ADDR_IDX(MIO_PTP_BASE_ADDR >> 22);
	val |= PEM_BAR4_INDEX_ADDR_V;
	pem_ep_reg_write(pem_ep, PEM_BAR4_INDEX(PEM_BAR4_INDEX_PTP), val);

	/* Clear the PEMX_DIS_PORT[DIS_PORT] */
	pem_ep_reg_write(pem_ep, PEM_DIS_PORT, 1);

	return 0;
err:
	for (i = 0; i < PEM_BAR4_NUM_INDEX; i++) {
		if (pem_ep->va[i])
			free_pages((unsigned long)pem_ep->va[i],
				   get_order(PEM_BAR4_INDEX_SIZE));
		pem_ep->va[i] = NULL;
	}
	return -ENOMEM;
}

static loff_t
memdev_llseek(struct file *file, loff_t offset, int whence)
{
	loff_t npos;

	switch (whence) {
	case SEEK_SET:
		npos = offset;
		break;
	case SEEK_CUR:
		npos = file->f_pos + offset;
		break;
	case SEEK_END:
		npos = PEM_BAR4_INDEX_END_OFFSET + offset;
		break;
	default:
		return -EINVAL;
	}
	if (npos <  0 || npos > PEM_BAR4_INDEX_END_OFFSET)
		return -EINVAL;
	file->f_pos = npos;
	return npos;
}

static ssize_t
memdev_write(struct file *file, const char *buf, size_t count, loff_t *poff)
{
	struct mv_pem_ep *pem_ep;
	struct miscdevice *mdev;
	struct device *dev;
	ssize_t written;
	u64 offset;
	void *va;
	int idx;

	mdev = file->private_data;
	pem_ep = dev_get_drvdata(mdev->parent);
	dev = pem_ep->dev;

	offset = *poff;

	/* make sure the write is inside the bounds */
	if (offset < PEM_BAR4_INDEX_START_OFFSET ||
	    (offset + count) > (PEM_BAR4_INDEX_END_OFFSET)) {
		dev_err(dev, "write not in bounds offset %llu count %lu\n",
			offset, count);
		return -EINVAL;
	}

	/* make sure write does not span across indices */
	if (offset >> PEM_BAR4_INDEX_SHIFT !=
	    (offset + count - 1) >> PEM_BAR4_INDEX_SHIFT) {
		dev_err(dev, "write spans indices offset %llu count %lu\n",
			offset, count);
		return -EINVAL;
	}

	offset -= PEM_BAR4_INDEX_START_OFFSET;
	idx = offset / PEM_BAR4_INDEX_SIZE;
	offset %= PEM_BAR4_INDEX_SIZE;
	va = pem_ep->va[idx];
	if (!va) {
		dev_err(dev, "write error invalid idx %d offset %llu\n", idx,
			offset);
		return -EFAULT;
	}
	va += offset;

	if (copy_from_user(va, buf, count)) {
		dev_err(dev, "copy_from_user error\n");
		return -EFAULT;
	}
	written = count;
	*poff += written;
	return written;
}

static ssize_t
memdev_read(struct file *file, char *buf, size_t count, loff_t *poff)
{
	struct mv_pem_ep *pem_ep;
	struct miscdevice *mdev;
	struct device *dev;
	ssize_t read;
	u64 offset;
	void *va;
	int idx;

	mdev = file->private_data;
	pem_ep = dev_get_drvdata(mdev->parent);
	dev = pem_ep->dev;

	offset = *poff;
	/* make sure the read is inside the bounds */
	if (offset < PEM_BAR4_INDEX_START_OFFSET ||
	    (offset + count) > (PEM_BAR4_INDEX_END_OFFSET)) {
		dev_err(dev, "read not in bounds offset %llu count %lu\n",
			offset, count);
		return -EINVAL;
	}

	/* make sure read does not span across indices */
	if (offset >> PEM_BAR4_INDEX_SHIFT !=
	    (offset + count - 1) >> PEM_BAR4_INDEX_SHIFT) {
		dev_err(dev, "read spans indices offset %llu count %lu\n",
			offset, count);
		return -EINVAL;
	}

	offset -= PEM_BAR4_INDEX_START_OFFSET;
	idx = offset / PEM_BAR4_INDEX_SIZE;
	offset %= PEM_BAR4_INDEX_SIZE;
	va = pem_ep->va[idx];
	if (!va) {
		dev_err(dev, "write error invalid idx %d offset %llu\n", idx,
			offset);
		return -EFAULT;
	}
	va += offset;

	if (copy_to_user(buf, va, count)) {
		dev_err(dev, "copy_to_user error\n");
		return -EFAULT;
	}
	read = count;
	*poff += read;
	return read;
}

static int
memdev_open(struct inode *inode, struct file *filp)
{
	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;

	return 0;
}

static int
memdev_release(struct inode *inode, struct file *filp)
{
	return 0;
}

static const struct file_operations memdev_fops = {
	.owner   = THIS_MODULE,
	.llseek  = memdev_llseek,
	.read    = memdev_read,
	.write   = memdev_write,
	.open    = memdev_open,
	.release = memdev_release,
};

static int
mem_file_setup(struct mv_pem_ep *pem_ep)
{
	struct miscdevice *mdev;
	int ret;

	mdev = &pem_ep->mdev;
	mdev->minor = MISC_DYNAMIC_MINOR;
	snprintf(pem_ep->mdev_name, 32, "pem%d_ep_bar4_mem", pem_ep->pem);
	mdev->name = pem_ep->mdev_name;
	mdev->fops = &memdev_fops;
	mdev->parent = pem_ep->dev;
	ret = misc_register(mdev);
	return ret;
}

static int pem_ep_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct mv_pem_ep *pem_ep;
	struct resource *res;
	int i, ret = 0;

	pem_ep = devm_kzalloc(dev, sizeof(*pem_ep), GFP_KERNEL);
	if (!pem_ep)
		return -ENOMEM;

	pem_ep->dev = dev;
	platform_set_drvdata(pdev, pem_ep);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	pem_ep->pem = PEM_HW_INST(res->start);
	pem_ep->base = ioremap(res->start, resource_size(res));
	if (IS_ERR(pem_ep->base)) {
		dev_err(dev, "error in mapping PEM EP base\n");
		return PTR_ERR(pem_ep->base);
	}

	ret = pem_ep_bar_setup(pem_ep);
	if (ret < 0) {
		dev_err(dev, "Error setting up EP BAR ret=%d\n", ret);
		goto err_exit;
	}

	ret = mem_file_setup(pem_ep);
	if (ret < 0) {
		dev_err(dev, "Error setting up mem access file ret=%d\n", ret);
		goto err_bar_setup;
	}

	/* register the PERST interrupt UIO device */
	ret = register_perst_uio_dev(pdev, pem_ep);
	if (ret < 0) {
		dev_err(dev, "Error registering UIO PERST device\n");
		goto err_mem_file_setup;
	}
	return 0;

err_mem_file_setup:
	misc_deregister(&pem_ep->mdev);
err_bar_setup:
	for (i = 0; i < PEM_BAR4_NUM_INDEX; i++) {
		if (pem_ep->va[i])
			free_pages((unsigned long)pem_ep->va[i],
				   get_order(PEM_BAR4_INDEX_SIZE));
	}
err_exit:
	devm_kfree(dev, pem_ep);
	return ret;
}

static int pem_ep_remove(struct platform_device *pdev)
{
	struct mv_pem_ep *pem_ep = platform_get_drvdata(pdev);
	struct device *dev = &pdev->dev;
	int i;

	pr_info("Removing %s driver\n", PEM_EP_DRV_NAME);

	misc_deregister(&pem_ep->mdev);
	for (i = 0; i < PEM_BAR4_NUM_INDEX; i++) {
		if (pem_ep->va[i])
			free_pages((unsigned long)pem_ep->va[i],
				   get_order(PEM_BAR4_INDEX_SIZE));
	}

	uio_unregister_device(&pem_ep->uio_rst_int_perst);
	devm_kfree(dev, pem_ep);

	return 0;
}

static const struct of_device_id pem_ep_of_match[] = {
	{ .compatible = "marvell,octeontx2-pem-ep", },
	{ .compatible = "marvell,cn10k-pem-ep", },
	{ },
};
MODULE_DEVICE_TABLE(of, pem_ep_of_match);

static const struct platform_device_id pem_ep_pdev_match[] = {
	{ .name = PEM_EP_DRV_NAME, },
	{},
};
MODULE_DEVICE_TABLE(platform, pem_ep_pdev_match);

static struct platform_driver pem_ep_driver = {
	.driver = {
		.name = PEM_EP_DRV_NAME,
		.of_match_table = pem_ep_of_match,
	},
	.probe = pem_ep_probe,
	.remove = pem_ep_remove,
	.id_table = pem_ep_pdev_match,
};

module_platform_driver(pem_ep_driver);

MODULE_DESCRIPTION("OcteonTX2 PEM EP Driver");
MODULE_AUTHOR("Marvell International Ltd.");
MODULE_LICENSE("GPL v2");
