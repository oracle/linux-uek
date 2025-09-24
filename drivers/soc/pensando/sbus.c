/*
 * Copyright (c) 2022, Pensando Systems Inc.
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/io.h>
#include <linux/spinlock.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/delay.h>
#include <linux/arm-smccc.h>
#include <asm/ptrace.h>

#define MAX_DEVICES			4
#define SBUS_SBUS_RST			0x20
#define SBUS_SBUS_WR			0x21
#define SBUS_SBUS_RD			0x22
#define SBUS_INDIR_DATA_ADDR_LSB	8
#define SBUS_INDIR_DATA_COMMAND_LSB	16

/* Refer Pensando BL31 Function Registry.docx */
#define PEN_SBUS_SMC_CALL_FID       0xC200000B

enum pen_sbus_smc_sub_fid {
    PEN_SBUS_SMC_REG_READ = 0,
    PEN_SBUS_SMC_REG_WRITE = 1,
};

enum pen_sbus_smc_err_codes {
    PEN_SBUS_SMC_ERR_NONE = 0,
    PEN_SBUS_SMC_ERR_INVALID = -1,
    PEN_SBUS_SMC_ERR_UNSUPPORTED = -2,
};

static dev_t sbus_dev;
static struct class *dev_class;
static int dev_inst;

struct sbus_ioctl_args {
	u32 sbus_rcvr_addr;
	u32 sbus_data_addr;
	u32 sbus_data;
};

struct sbus_reg_ops {
	void (*write)(void __iomem *addr, uint32_t val);
	uint32_t (*read)(void __iomem *addr);
};

struct sbusdev_info {
	struct platform_device *pdev;
	void __iomem *sbus_indir;
	void __iomem *sbus_dhs;
	spinlock_t sbus_lock;
	struct cdev cdev;
	struct sbus_reg_ops *rops;
};

#define SBUS_WRITE	_IOW('a', 'a', struct sbus_ioctl_args)
#define SBUS_READ	_IOWR('a', 'b', struct sbus_ioctl_args)
#define SBUS_RESET	_IOW('a', 'c', struct sbus_ioctl_args)

static int sbus_drv_open(struct inode *inode, struct file *file)
{
	struct sbusdev_info *sbus_ring;	/* device information */

	sbus_ring = container_of(inode->i_cdev, struct sbusdev_info, cdev);
	file->private_data = sbus_ring;
	pr_debug("Device File Opened...!!\n");
	return 0;
}

static void reg_write(void __iomem *addr, uint32_t val)
{
	iowrite32(val, addr);
}

static uint32_t reg_read(void __iomem *addr)
{
	return ioread32(addr);
}

static void reg_smc_write(void __iomem *addr, uint32_t val)
{
	struct arm_smccc_res res = {0};

	arm_smccc_smc(PEN_SBUS_SMC_CALL_FID,
		      PEN_SBUS_SMC_REG_WRITE, (uint64_t)addr,
		      val, 0, 0, 0, 0, &res);

	if (res.a0 != PEN_SBUS_SMC_ERR_NONE) {
		pr_err("pensando-sbus: failed to write data! ret=%d\n", (int)res.a0);
	}
}

static uint32_t reg_smc_read(void __iomem *addr)
{
	struct arm_smccc_res res = {0};

	arm_smccc_smc(PEN_SBUS_SMC_CALL_FID,
		      PEN_SBUS_SMC_REG_READ, (uint64_t)addr,
		      0, 0, 0, 0, 0, &res);

	if (res.a0 != PEN_SBUS_SMC_ERR_NONE) {
		pr_err("pensando-sbus: read failed! ret=%ld\n", res.a0);
		return (uint32_t)-1;
	}

	/* result passed back in a1 reg */
	return (uint32_t)res.a1;
}

static void sbus_write(struct sbus_ioctl_args param,
		       struct sbusdev_info *sbus_ring)
{
	uint32_t sbus_val;

	sbus_val = param.sbus_rcvr_addr |
		(param.sbus_data_addr << SBUS_INDIR_DATA_ADDR_LSB) |
		(SBUS_SBUS_WR << SBUS_INDIR_DATA_COMMAND_LSB);

	pr_debug("sbus_rcvr_addr %d sbus_data_addr %d sbus_data %d\n",
	param.sbus_rcvr_addr, param.sbus_data_addr, param.sbus_data);

	spin_lock(&sbus_ring->sbus_lock);

	sbus_ring->rops->write(sbus_ring->sbus_indir, sbus_val);
	sbus_ring->rops->write(sbus_ring->sbus_dhs, param.sbus_data);

	spin_unlock(&sbus_ring->sbus_lock);
}

static uint32_t sbus_read(struct sbus_ioctl_args param,
			  struct sbusdev_info *sbus_ring)
{
	uint32_t sbus_val, val;

	sbus_val = param.sbus_rcvr_addr |
		(param.sbus_data_addr << SBUS_INDIR_DATA_ADDR_LSB) |
		(SBUS_SBUS_RD << SBUS_INDIR_DATA_COMMAND_LSB);

	pr_debug("sbus_rcvr_addr %d sbus_data_addr %d\n",
		param.sbus_rcvr_addr, param.sbus_data_addr);

	spin_lock(&sbus_ring->sbus_lock);

	sbus_ring->rops->write(sbus_ring->sbus_indir, sbus_val);
	val = sbus_ring->rops->read(sbus_ring->sbus_dhs);

	spin_unlock(&sbus_ring->sbus_lock);

	return val;
}

static void sbus_reset(struct sbus_ioctl_args param,
		       struct sbusdev_info *sbus_ring)
{
	uint32_t sbus_val;

	sbus_val = param.sbus_rcvr_addr |
		(param.sbus_data_addr << SBUS_INDIR_DATA_ADDR_LSB) |
		(SBUS_SBUS_RST << SBUS_INDIR_DATA_COMMAND_LSB);

	pr_debug("sbus_rcvr_addr %d sbus_data_addr %d\n",
		param.sbus_rcvr_addr, param.sbus_data_addr);

	spin_lock(&sbus_ring->sbus_lock);

	sbus_ring->rops->write(sbus_ring->sbus_indir, sbus_val);
	sbus_ring->rops->write(sbus_ring->sbus_dhs, 0);

	spin_unlock(&sbus_ring->sbus_lock);
}

/*
 * This function will be called when we write IOCTL on the Device file
 */
static long sbus_drv_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	struct sbusdev_info *sbus_ring = file->private_data;
	struct sbus_ioctl_args param_ioctl;

	switch (cmd) {
	case SBUS_WRITE:
		if (copy_from_user
			(&param_ioctl, (struct sbus_ioctl_args *)arg,
			sizeof(struct sbus_ioctl_args))) {
			return -EFAULT;
		}
		sbus_write(param_ioctl, sbus_ring);
		break;
	case SBUS_READ:
		if (copy_from_user
			(&param_ioctl, (struct sbus_ioctl_args *)arg,
			sizeof(struct sbus_ioctl_args))) {
			return -EFAULT;
		}
		param_ioctl.sbus_data = sbus_read(param_ioctl, sbus_ring);
		if (copy_to_user
			((struct sbus_ioctl_args *)arg, &param_ioctl,
			sizeof(struct sbus_ioctl_args))) {
			return -EFAULT;
		}
		break;
	case SBUS_RESET:
		if (copy_from_user
			(&param_ioctl, (struct sbus_ioctl_args *)arg,
			sizeof(struct sbus_ioctl_args))) {
			return -EFAULT;
		}
		sbus_reset(param_ioctl, sbus_ring);
		break;
	default:
		return -ENOTTY;
	}

	return 0;
}

/*
 * File operation structure
 */
static const struct file_operations fops = {
	.open = sbus_drv_open,
	.owner = THIS_MODULE,
	.unlocked_ioctl = sbus_drv_ioctl,
};

/*
 * Register operation structure (non-secure)
 */
static struct sbus_reg_ops ns_rops = {
	.read = reg_read,
	.write = reg_write,
};

/*
 * Register operation structure (secure)
 */
static struct sbus_reg_ops sec_rops = {
	.read = reg_smc_read,
	.write = reg_smc_write,
};

static int of_get_secure_mode(void)
{
	struct device_node *of_secure_mode;
	int enable = 0;

	/* Get secure mode from OF */
	of_secure_mode = of_find_node_by_path("/secure_mode");
	if (of_secure_mode) {
		if (of_property_read_u32(of_secure_mode, "enable", &enable)) {
			return 0; /* non-secure */
		} else {
			return enable;
		}
	}
	return 0; /* non-secure */
}

/*
 * Module Init function
 */
static int sbus_probe(struct platform_device *pdev)
{
	int major, sbus_ring_num;
	dev_t device;
	struct device *dev = &pdev->dev;
	struct resource *res;
	struct sbusdev_info *sbus_ring;
	void __iomem *sbus_indir;
	int is_secure = 0;

	if (dev_inst > MAX_DEVICES-1)
		return -ENODEV;

	if (of_property_read_u32(pdev->dev.of_node, "sbus-ring-num",
				&sbus_ring_num)) {
		pr_debug("missing sbus-ring-num in device tree\n");
		return -EINVAL;
	}

	sbus_ring = devm_kzalloc(dev, sizeof(*sbus_ring), GFP_KERNEL);
	if (!sbus_ring)
		return -ENOMEM;

	sbus_ring->pdev = pdev;
	platform_set_drvdata(pdev, sbus_ring);

	is_secure = of_get_secure_mode();
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (is_secure) {
		sbus_indir = (void __iomem *)res->start;
	} else {
		sbus_indir = (void __iomem *)devm_ioremap_resource(dev, res);
		if (IS_ERR(sbus_indir)) {
			dev_err(dev, "Cannot remap sbus reg addresses.\n");
			return PTR_ERR(sbus_indir);
		}
	}
	sbus_ring->sbus_indir = sbus_indir;
	sbus_ring->sbus_dhs = (void __iomem *)(sbus_ring->sbus_indir + 0x4);

	spin_lock_init(&sbus_ring->sbus_lock);

	pr_debug("sbus_indir %p sbus_dhs %p\n",
			sbus_ring->sbus_indir, sbus_ring->sbus_dhs);

	if (dev_inst == 0) {
		/* Allocating Major number & reserving minor numbers */
		if ((alloc_chrdev_region
			(&sbus_dev, 0, MAX_DEVICES, "pensbus_dev")) < 0) {
			pr_err("Cannot allocate major number\n");
			return -1;
		}
		pr_debug("Major = %d Minor = %d \n", MAJOR(sbus_dev),
			MINOR(sbus_dev));

		/* Creating struct class */
		dev_class = class_create(THIS_MODULE, "sbus_class");
		if (dev_class == NULL) {
			pr_err("Cannot create the struct class\n");
			goto r_class;
		}
	}

	major = MAJOR(sbus_dev);

	/* Creating cdev structure */
	cdev_init(&sbus_ring->cdev, &fops);
	sbus_ring->cdev.owner = THIS_MODULE;
	sbus_ring->cdev.ops = &fops;

	/* Adding character device to the system */
	device = MKDEV(major, dev_inst);
	if ((cdev_add(&sbus_ring->cdev, device, 1)) < 0) {
		pr_err("Cannot add the device to the system\n");
		goto r_device;
	}

	/* Creating device */
	if ((device_create(dev_class, NULL, device, NULL, "sbus%d",
					sbus_ring_num)) == NULL) {
		pr_err("Cannot create the Device 1\n");
		goto r_device;
	}
	dev_inst++;

	/* Set the reg read/write ops based on secure/non-secure mode of operation */
	if (is_secure) {
		pr_info("pensando-sbus: Using secure ops\n");
		sbus_ring->rops = &sec_rops;
	} else {
		pr_info("pensando-sbus: Using non-secure ops\n");
		sbus_ring->rops = &ns_rops;
	}

	return 0;

r_device:
	if (dev_inst == 0)
		class_destroy(dev_class);
r_class:
	if (dev_inst == 0)
		unregister_chrdev_region(sbus_dev, MAX_DEVICES);

	return -1;
}

/*
 * Module exit function
 */
static int sbus_remove(struct platform_device *pdev)
{
	dev_inst--;

	if (dev_inst == 0) {
		device_destroy(dev_class, sbus_dev);
		class_destroy(dev_class);
		unregister_chrdev_region(sbus_dev, MAX_DEVICES);
		pr_debug("Device Driver Remove...Done!!!\n");
	}

	return 0;
}

static const struct of_device_id sbus_of_match[] = {
	{ .compatible = "pensando,sbus" },
	{ /* end of table */ }
};

static struct platform_driver sbus_driver = {
	.probe = sbus_probe,
	.remove = sbus_remove,
	.driver = {
		.name = "pensando-sbus",
		.owner = THIS_MODULE,
		.of_match_table = sbus_of_match,
	},
};

module_platform_driver(sbus_driver);
