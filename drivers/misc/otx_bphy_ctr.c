/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2016, 2018 Cavium Inc.
 */
#include <linux/init.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/arm-smccc.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/moduleparam.h>
#include <linux/uaccess.h>
#include <linux/mmu_context.h>
#include <linux/ioctl.h>
#include <linux/fs.h>

#define DEVICE_NAME	"otx-bphy-ctr"
#define OTX_IOC_MAGIC	0xF3
#define MAX_IRQ		27

static struct device *otx_device;
static struct class *otx_class;
static struct cdev *otx_cdev;
static dev_t otx_dev;
static DEFINE_SPINLOCK(el3_inthandler_lock);
static int in_use;
static int irq_installed[MAX_IRQ];
static struct thread_info *irq_installed_threads[MAX_IRQ];
static struct task_struct *irq_installed_tasks[MAX_IRQ];

/* SMC definitons */
/* X1 - irq_num, X2 - sp, X3 - cpu, X4 - ttbr0 */
#define OCTEONTX_INSTALL_BPHY_PSM_ERRINT       0xc2000803
/* X1 - irq_num */
#define OCTEONTX_REMOVE_BPHY_PSM_ERRINT        0xc2000804

struct otx_irq_usr_data {
	u64	isr_base;
	u64	sp;
	u64	cpu;
	u64	irq_num;
};


#define OTX_IOC_SET_BPHY_HANDLER \
	_IOW(OTX_IOC_MAGIC, 1, struct otx_irq_usr_data)

#define OTX_IOC_CLR_BPHY_HANDLER \
	_IO(OTX_IOC_MAGIC, 2)

static inline int __install_el3_inthandler(unsigned long irq_num,
					   unsigned long sp,
					   unsigned long cpu,
					   unsigned long ttbr0)
{
	struct arm_smccc_res res;
	unsigned long flags;
	int retval = -1;

	spin_lock_irqsave(&el3_inthandler_lock, flags);

	if (!irq_installed[irq_num]) {
		lock_context(current->group_leader->mm, irq_num);
		arm_smccc_smc(OCTEONTX_INSTALL_BPHY_PSM_ERRINT, irq_num,
			      sp, cpu, ttbr0, 0, 0, 0, &res);
		if (res.a0 == 0) {
			irq_installed[irq_num] = 1;
			irq_installed_threads[irq_num]
				= current_thread_info();
			irq_installed_tasks[irq_num]
				= current->group_leader;
			retval = 0;
		} else {
			unlock_context_by_index(irq_num);
		}
	}
	spin_unlock_irqrestore(&el3_inthandler_lock, flags);
	return retval;
}

static inline int __remove_el3_inthandler(unsigned long irq_num)
{
	struct arm_smccc_res res;
	unsigned long flags;
	unsigned int retval;

	spin_lock_irqsave(&el3_inthandler_lock, flags);

	if (irq_installed[irq_num]) {
		arm_smccc_smc(OCTEONTX_REMOVE_BPHY_PSM_ERRINT, irq_num,
			      0, 0, 0, 0, 0, 0, &res);
		irq_installed[irq_num] = 0;
		irq_installed_threads[irq_num] = NULL;
		irq_installed_tasks[irq_num] = NULL;
		unlock_context_by_index(irq_num);
		retval = 0;
	} else {
		retval = -1;
	}
	spin_unlock_irqrestore(&el3_inthandler_lock, flags);
	return retval;
}

static long otx_dev_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	int err = 0;
	struct otx_irq_usr_data irq_usr;
	u64 irq_ttbr, irq_isr_base, irq_sp, irq_cpu, irq_num;
	int ret;
	//struct task_struct *task = current;

	if (!in_use)
		return -EINVAL;

	if (_IOC_TYPE(cmd) != OTX_IOC_MAGIC)
		return -ENOTTY;

	if (_IOC_DIR(cmd) & _IOC_READ)
		err = !access_ok(VERIFY_WRITE, (void __user *)arg,
				 _IOC_SIZE(cmd));
	else if (_IOC_TYPE(cmd) & _IOC_WRITE)
		err = !access_ok(VERIFY_READ, (void __user *)arg,
				 _IOC_SIZE(cmd));

	if (err)
		return -EFAULT;

	switch (cmd) {
	case OTX_IOC_SET_BPHY_HANDLER: /*Install ISR handler*/
		ret = copy_from_user(&irq_usr, (void *)arg, _IOC_SIZE(cmd));
		if (irq_usr.irq_num >= MAX_IRQ)
			return -EINVAL;
		if (ret)
			return -EFAULT;
		irq_ttbr = 0;
		//TODO: reserve a asid to avoid asid rollovers
		asm volatile("mrs %0, ttbr0_el1\n\t" : "=r"(irq_ttbr));
		irq_isr_base = irq_usr.isr_base;
		irq_sp = irq_usr.sp;
		irq_cpu = irq_usr.cpu;
		irq_num = irq_usr.irq_num;
		ret = __install_el3_inthandler(irq_num, irq_sp,
					       irq_cpu, irq_isr_base);
		if (ret != 0)
			return -EEXIST;
		break;
	case OTX_IOC_CLR_BPHY_HANDLER: /*Clear ISR handler*/
		irq_usr.irq_num = arg;
		if (irq_usr.irq_num >= MAX_IRQ)
			return -EINVAL;
		ret = __remove_el3_inthandler(irq_usr.irq_num);
		if (ret != 0)
			return -ENOENT;
		break;
	default:
		return -ENOTTY;
	}
	return 0;
}

static void cleanup_el3_irqs(struct task_struct *task)
{
	int i;

	for (i = 0; i < MAX_IRQ; i++) {
		if (irq_installed[i] &&
		    irq_installed_tasks[i] &&
		    (irq_installed_tasks[i] == task)) {
			pr_alert("Exiting, removing handler for BPHY IRQ %d\n",
				 i);
			__remove_el3_inthandler(i);
			pr_alert("Exited, removed handler for BPHY IRQ %d\n",
				 i);
		} else {
			if (irq_installed[i] &&
			    (irq_installed_threads[i]
			     == current_thread_info()))
				pr_alert("Exiting, thread info matches, not removing handler for BPHY IRQ %d\n", i);
		}
	}
}

static int otx_dev_open(struct inode *inode, struct file *fp)
{
	in_use = 1;
	return 0;
}

static int otx_dev_release(struct inode *inode, struct file *fp)
{
	if (in_use == 0)
		return -EINVAL;
	in_use = 0;
	return 0;
}

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = otx_dev_open,
	.release = otx_dev_release,
	.unlocked_ioctl = otx_dev_ioctl
};

static int __init otx_ctr_dev_init(void)
{
	int err = 0;

	/* create a character device */
	err = alloc_chrdev_region(&otx_dev, 1, 1, DEVICE_NAME);
	if (err != 0) {
		pr_err("Failed to create device: %d\n", err);
		goto alloc_chrdev_err;
	}

	otx_cdev = cdev_alloc();
	if (!otx_cdev) {
		err = -ENODEV;
		goto cdev_alloc_err;
	}

	cdev_init(otx_cdev, &fops);
	err = cdev_add(otx_cdev, otx_dev, 1);
	if (err < 0) {
		err = -ENODEV;
		goto cdev_add_err;
	}

	/* create new class for sysfs*/
	otx_class = class_create(THIS_MODULE, DEVICE_NAME);
	if (IS_ERR(otx_class)) {
		err = -ENODEV;
		goto class_create_err;
	}

	otx_device = device_create(otx_class, NULL, otx_dev, NULL,
				     DEVICE_NAME);
	if (IS_ERR(otx_device)) {
		err = -ENODEV;
		goto device_create_err;
	}

	/* Register task cleanup handler */
	err = task_cleanup_handler_add(cleanup_el3_irqs);
	if (err != 0) {
		dev_err(otx_device, "Failed to register cleanup handler: %d\n", err);
		goto cleanup_handler_err;
	}

	return err;

device_create_err:
	class_destroy(otx_class);

class_create_err:
cdev_add_err:
	cdev_del(otx_cdev);
cdev_alloc_err:
	unregister_chrdev_region(otx_dev, 1);
alloc_chrdev_err:
	task_cleanup_handler_remove(cleanup_el3_irqs);
cleanup_handler_err:
	return err;
}

static void __exit otx_ctr_dev_exit(void)
{
	device_destroy(otx_class, otx_dev);
	class_destroy(otx_class);
	cdev_del(otx_cdev);
	unregister_chrdev_region(otx_dev, 1);

	task_cleanup_handler_remove(cleanup_el3_irqs);
}

module_init(otx_ctr_dev_init);
module_exit(otx_ctr_dev_exit);

MODULE_DESCRIPTION("Marvell OTX Control Device Driver");
MODULE_LICENSE("GPL");
