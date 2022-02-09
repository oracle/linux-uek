// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2020-2021, Pensando Systems Inc.
 *
 * UIO common driver for MSIX interrupts for Pensando system.
 *
 * As you read this, remember that it is the common portion of what will
 * generally be many drivers. As such, functions like the probe() function have
 * to deal with contention, which code that is one-per-driver do not. This
 * makes things a bit more complex.
 *
 * The second complexity is that we have an asynchronous callback from MSIX.
 * Since we don't now the context of that call, we pre-allocate the
 * needed data structures from a context known to be suitable for memory
 * allocation. When the callback is called, it simply dequeues the memory
 * and puts it on an "in use" list. When the probe() function needs to
 * allocate its platform data, it just uses one of the structures on the
 * in use list.
 */

#include <linux/platform_data/uio_dmem_genirq.h>
#include <linux/platform_device.h>

#include <linux/atomic.h>
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/msi.h>
#include <linux/of_address.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/uio_driver.h>
#include <linux/wait.h>

/* Optionally add attributes */
#define ADD_ATTRS
#undef ENABLE_STORE

#ifdef ADD_ATTRS
#define to_penmsi_dir(kobjp) container_of(kobjp, struct penmsi_dir, kobj)
#endif

/*
 * devdata - information for a UIO device
 * @pdev:		Pointer to the struct platform_device
 * @platdata:		Pointer to the containing struct platdata
 * @have_msi_index:	Indicates that @msi_index is valid
 * @msi_index:		Index used to match descriptors with data
 * @open:		Flag indicating whether this device is open
 * @msi_msg:		MSI address and data information
 * @list		Item in a list of allocated devdata items;
 * @penmsi_dir:		Pointer to information about the penmsi directory
 *			in which the command file lives
 */
struct devdata {
	struct uio_info		uio_info;
	struct platdata		*platdata;
	bool			have_msi_msg;
	bool			have_msi_desc;
	u16			msi_index;
	bool			open;
	struct msi_msg		msi_msg;
#ifdef ADD_ATTRS
	struct penmsi_dir	*penmsi_dir;
#endif
};

/*
 * Per platform device
 * @pdev:		Associated platform device
 * @n_pending:		Remaining number of devdata items we are waiting for
 * @n_irqs:		Number of IRQs being supported
 * @n_valid:		Number of struct devdata items initialized for use
 * @devdata:		Array of struct devdata items
 */
struct platdata {
	struct platform_device	*pdev;
	unsigned int		n_pending;
	size_t			n_irqs;
	unsigned int		n_valid;
	struct devdata		devdatas[];
};
/*
 * @penmsi_sem:		Protects the @init_platdata pointer and allocation of
 *			MSI IRQs
 * @init_platdata:	Pointer to the platdata currently being initialized.
 *			This is only valid while @penmsi_sem is held
 */
static DEFINE_SEMAPHORE(penmsi_sem);
static DECLARE_WAIT_QUEUE_HEAD(penmsi_wq_head);
static DEFINE_SPINLOCK(penmsi_lock);
static struct platdata *init_platdata;
static unsigned int num_uio_devs;

#ifdef ADD_ATTRS
struct penmsi_dir {
	struct kobject	kobj;
	struct msi_msg	*msi_msg;
	size_t		msi_size;
};

struct msi {
	int			counter;
	struct penmsi_dir	*penmsi_dir;
};

static ssize_t msi_show(struct msi_msg *msi_msg, char *buf)
{
	memcpy(buf, msi_msg, sizeof(*msi_msg));
	return sizeof(*msi_msg);
}

#ifdef ENABLE_STORE
static ssize_t msi_store(struct msi_msg *msi_msg, const char *buf,
			 size_t size)
{
	if (size != sizeof(*msi_msg))
		return -EINVAL;

	memcpy(msi_msg, buf, sizeof(*msi_msg));
	return sizeof(*msi_msg);
}
#else
static ssize_t msi_store(struct msi_msg *msi_msg, const char *buf,
			 size_t size)
{
	return -EOPNOTSUPP;
}
#endif

struct msi_sysfs_entry {
	struct attribute attr;
	ssize_t (*show)(struct msi_msg *msg, char *buf);
	ssize_t (*store)(struct msi_msg *msg, const char *buf, size_t sz);
};

static struct msi_sysfs_entry msi_attribute =
	__ATTR(msi, 0600, msi_show, msi_store);

static struct attribute *attrs[] = {
	&msi_attribute.attr,
	NULL,	/* need to NULL terminate the list of attributes */
};

static void penmsi_rel(struct kobject *kobj)
{
	struct penmsi_dir *penmsi_dir = to_penmsi_dir(kobj);

	kfree(penmsi_dir);
}

static ssize_t penmsi_show(struct kobject *kobj, struct attribute *attr,
			     char *buf)
{
	struct penmsi_dir *penmsi_dir = to_penmsi_dir(kobj);
	struct msi_msg *msi_msg = penmsi_dir->msi_msg;
	struct msi_sysfs_entry *entry;

	entry = container_of(attr, struct msi_sysfs_entry, attr);

	if (entry->show == NULL)
		return -EOPNOTSUPP;
	return entry->show(msi_msg, buf);
}

#ifdef ENABLE_STORE
static ssize_t penmsi_store(struct kobject *kobj, struct attribute *attr,
	const char *buf, size_t size)
{
	struct penmsi_dir *penmsi_dir = to_penmsi_dir(kobj);
	struct msi *msi = penmsi_dir->msi;
	struct msi_sysfs_entry *entry;

	entry = container_of(attr, struct msi_sysfs_entry, attr);

	if (entry->show == NULL)
		return -EOPNOTSUPP;

	return entry->store(msi, buf, size);
}
#else
static ssize_t penmsi_store(struct kobject *kobj, struct attribute *attr,
	const char *buf, size_t size)
{
	return -EOPNOTSUPP;
}
#endif

static const struct sysfs_ops penmsi_sysfs_ops = {
	.show = penmsi_show,
	.store = penmsi_store,
};

static struct kobj_type penmsi_attr_type = {
	.release	= penmsi_rel,
	.sysfs_ops	= &penmsi_sysfs_ops,
	.default_attrs	= attrs,
};

static int add_attr(struct devdata *devdata)
{
	struct penmsi_dir *penmsi_dir;
	struct uio_device *uio_dev;
	int ret;

	/*
	 * Create a kobject for the directory in which the command interface
	 * lives
	 */
	uio_dev = devdata->uio_info.uio_dev;

	/* Allocate storage for the command file */
	penmsi_dir = kzalloc(sizeof(*penmsi_dir), GFP_KERNEL);
	if (penmsi_dir == NULL)
		return -ENOMEM;
	devdata->penmsi_dir = penmsi_dir;
	devdata->penmsi_dir->msi_msg = &devdata->msi_msg;
	devdata->penmsi_dir->msi_size = sizeof(devdata->msi_msg);
	kobject_init(&devdata->penmsi_dir->kobj, &penmsi_attr_type);

	ret = kobject_add(&devdata->penmsi_dir->kobj, &uio_dev->dev.kobj,
		"pensando");
	if (ret != 0)
		goto remove_penmsi_dir;

	ret = kobject_uevent(&devdata->penmsi_dir->kobj, KOBJ_ADD);
	if (ret != 0)
		goto remove_penmsi_dir;

	return 0;

remove_penmsi_dir:
	kobject_put(&devdata->penmsi_dir->kobj);
	kfree(devdata->penmsi_dir);
	devdata->penmsi_dir = NULL;

	dev_err(&uio_dev->dev, "error creating sysfiles (%d)\n", ret);
	return -EIO;
}

static void del_attr(struct devdata *devdata)
{
	kobject_put(&devdata->penmsi_dir->kobj);
	devdata->penmsi_dir = NULL;
}

static int adorn_with_attrs(struct devdata *devdata)
{
	int rc;

	rc = add_attr(devdata);
	if (rc != 0) {
		dev_err(&devdata->platdata->pdev->dev, "%s failed: %d\n",
			__func__, rc);
		goto remove_attrs;
	}

	return 0;

remove_attrs:
	del_attr(devdata);
	return rc;

}

static void del_attrs(struct platdata *platdata)
{
	unsigned int i;

	for (i = 0; i < platdata->n_irqs; i++)
		del_attr(&platdata->devdatas[i]);
}
#else
static inline int add_attr(struct devdata *devdata) { return 0; }
static inline void del_attr(struct devdata *devdata) { }
static inline void del_attrs(struct platdata *platdata) { }
#endif

static int penmsi_open(struct uio_info *uio_info, struct inode *inode)
{
	struct platdata *platdata;
	struct devdata *devdata;
	int ret;

	devdata = uio_info->priv;
	if (devdata->open)
		return -EBUSY;
	devdata->open = true;
	ret = 0;

	platdata = devdata->platdata;
	pm_runtime_get_sync(&platdata->pdev->dev);

	return ret;
}

static int penmsi_release(struct uio_info *uio_info, struct inode *inode)
{
	struct devdata *devdata;

	devdata = uio_info->priv;
	devdata->open = false;
	pm_runtime_put_sync(&devdata->platdata->pdev->dev);

	return 0;
}


/*
 * The interrupt is edge triggered, so if we don't do anything and just
 * return, nothing bad will happen. Yes, this is a bit unusual but
 * it's useful.
 */
static irqreturn_t penmsi_handler(int irq, struct uio_info *uio_info)
{
	return IRQ_HANDLED;
}

static void decrement_pending(struct platdata *platdata)
{
	platdata->n_pending--;
	if (platdata->n_pending == 0)
		up(&penmsi_sem);
}

/*
 * MSI callback function.
 * stores the information it was passed, and queues it on the inuse list.
 *
 */
static void penmsi_callback(struct msi_desc *desc, struct msi_msg *msg)
{
	struct devdata *devdata;
	struct platdata *platdata;
	unsigned long flags;

	platdata = init_platdata;
	devdata = &platdata->devdatas[desc->platform.msi_index];
	devdata->msi_msg = *msg;

	spin_lock_irqsave(&penmsi_lock, flags);
	devdata->have_msi_msg = true;

	if (devdata->have_msi_desc)
		decrement_pending(platdata);
	spin_unlock_irqrestore(&penmsi_lock, flags);
}

/*
 * Remove the device completely
 * @pdev:	Pointer to the struct platform_device we're using
 */
int penmsi_remove(struct platform_device *pdev)
{
	struct platdata *platdata;
	unsigned int i;

	platdata = platform_get_drvdata(pdev);
	platform_msi_domain_free_irqs(&pdev->dev);
	del_attrs(platdata);

	// FIXME: this needs to use n_valid
	for (i = 0; i < platdata->n_irqs; i++) {
		struct devdata *devdata;
		struct uio_info *uio_info;

		devdata = &platdata->devdatas[i];
		uio_info = &devdata->uio_info;
		uio_unregister_device(uio_info);
		kfree(uio_info->name);

		/*
		 * We're cheating with this, skip all the rest of the UIOs
		 * so we don't free anything we shouldn't. This is going to
		 * result in a memory leak.
		 */
		break;
	}

	kfree(platdata);

	return 0;
}
EXPORT_SYMBOL(penmsi_remove);

static int penmsi_probe_one(struct devdata *devdata,
	struct platform_device *pdev, struct msi_desc *desc)
{
	struct uio_info *uio_info;
	const char *dt_name;
	char name_buf[32];
	int rc;

	uio_info = &devdata->uio_info;

	rc = of_property_read_string(pdev->dev.of_node, "name", &dt_name);
	if (rc != 0)
		dt_name = "penmsiX";
	snprintf(name_buf, sizeof(name_buf), "%s.%u", dt_name, num_uio_devs);
	num_uio_devs++;
	uio_info->name = kstrdup(name_buf, GFP_KERNEL);
	if (uio_info->name == NULL)
		return -ENOMEM;

	/*
	 * Only take one interrupt because UIO won't let us pass more than
	 * that
	 */
	uio_info->priv = devdata;
	uio_info->version = "0.1";
	uio_info->open = penmsi_open;
	uio_info->release = penmsi_release;
	uio_info->handler = penmsi_handler;
	uio_info->irq = desc->irq;
	uio_info->irq_flags = IRQF_SHARED;

	/* Ready to be a grown up UIO device now */
	rc = uio_register_device(&pdev->dev, uio_info);
	if (rc != 0) {
		dev_err(&pdev->dev, "can't register UIO device");
		goto free_name;
	}

	rc = adorn_with_attrs(devdata);
	if (rc != 0)
		goto unregister_uio;

	return 0;

unregister_uio:
	uio_unregister_device(uio_info);

free_name:
	kfree(uio_info->name);
	uio_info->name = NULL;

	return rc;
}

/*
 * Allocate a struct platdata with all of its devdata structures.
 *
 * Returns the a pointer to the allocated platdata on success, NULL otherwise
 */
static struct platdata *alloc_devdatas(unsigned int n)
{
	unsigned int i;
	struct platdata *platdata;

	platdata = kzalloc(offsetof(struct platdata, devdatas[n]), GFP_KERNEL);
	if (platdata == NULL)
		return platdata;

	for (i = 0; i < n; i++)
		platdata->devdatas[i].platdata = platdata;

	platdata->n_pending = n;
	platdata->n_irqs = n;

	return platdata;
}

/*
 * penmsi_probe - allocate and initialize state for device
 */
int penmsi_probe(struct platform_device *pdev)
{
	struct msi_desc *desc;
	struct platdata *platdata;
	struct devdata *devdata;
	u32 num_interrupts;
	int rc;

	num_uio_devs = 0;
	rc = of_property_read_u32(pdev->dev.of_node, "num-interrupts",
		&num_interrupts);
	if (rc != 0) {
		dev_err(&pdev->dev, "num-interrupts property missing\n");
		return rc;
	}
	if (num_interrupts == 0) {
		dev_err(&pdev->dev, "num-interrupts property must be >0\n");
		return -EINVAL;
	}

	platdata = alloc_devdatas(num_interrupts);
	platform_set_drvdata(pdev, platdata);
	platdata->n_irqs = num_interrupts;
	platdata->pdev = pdev;

	/* Due to the way MSI passes back information, we want to allocate
	 * MSI IRQs one at a time.
	 */
	down(&penmsi_sem);
	init_platdata = platdata;

	/* Kick off work that should result in calling the callback */
	rc = platform_msi_domain_alloc_irqs(&pdev->dev, num_interrupts,
		penmsi_callback);
	if (rc != 0) {
		dev_err(&pdev->dev,
			"platform_msi_domain_alloc_irqs failed: %d\n", rc);
		goto up_sem;
	}

	for_each_msi_entry(desc, &pdev->dev) {
		unsigned long flags;

		devdata = &platdata->devdatas[desc->platform.msi_index];
		spin_lock_irqsave(&penmsi_lock, flags);
		devdata->have_msi_desc = true;
		if (devdata->have_msi_msg)
			decrement_pending(platdata);
		spin_unlock_irqrestore(&penmsi_lock, flags);
		rc = penmsi_probe_one(devdata, pdev, desc);
		if (rc != 0)
			goto free_msis;
	}

	init_platdata = NULL;		// Don't use this again
	up(&penmsi_sem);

	/* Map the device */
	rc = dma_set_coherent_mask(&pdev->dev, DMA_BIT_MASK(64));
	if (rc != 0) {
		dev_err(&pdev->dev, "no valid coherent DMA mask");
		goto free_msis;
	}

	pm_runtime_enable(&pdev->dev);

	return 0;

free_msis:
	platform_msi_domain_free_irqs(&pdev->dev);

up_sem:
	up(&penmsi_sem);
	kfree(platdata);
	return rc;

}
EXPORT_SYMBOL(penmsi_probe);

/*
 * penmsi_pm_nop - Power management stub that just returns success
 *
 * We leave it to other drivers to handle the device power management
 * operations, if any.
 */
static int penmsi_pm_nop(struct device *dev)
{
	return 0;
}

const struct dev_pm_ops penmsi_pm_ops = {
	.runtime_suspend = penmsi_pm_nop,
	.runtime_resume = penmsi_pm_nop,
};
EXPORT_SYMBOL(penmsi_pm_ops);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Support userspace I/O for Pensando MSIX interrupts");
MODULE_AUTHOR("David VomLehn");
