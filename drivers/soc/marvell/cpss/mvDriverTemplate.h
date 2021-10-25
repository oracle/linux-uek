/*******************************************************************************
Copyright (C) Marvell International Ltd. and its affiliates

This software file (the "File") is owned and distributed by Marvell
International Ltd. and/or its affiliates ("Marvell") under the following
alternative licensing terms.  Once you have made an election to distribute the
File under one of the following license alternatives, please (i) delete this
introductory statement regarding license alternatives, (ii) delete the two
license alternatives that you have not elected to use and (iii) preserve the
Marvell copyright notice above.


********************************************************************************
Marvell GPL License Option

If you received this File from Marvell, you may opt to use, redistribute and/or
modify this File in accordance with the terms and conditions of the General
Public License Version 2, June 1991 (the "GPL License"), a copy of which is
available along with the File in the license.txt file or by writing to the Free
Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 or
on the worldwide web at http://www.gnu.org/licenses/gpl.txt.

THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE IMPLIED
WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY
DISCLAIMED.  The GPL License provides additional details about this warranty
disclaimer.
********************************************************************************
* @file mvDriverTemplate.h
*
* @brief Character device wrappers
*
*******************************************************************************/
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/slab.h>

/*
 * Character device context, created by mvchrdev_init and use as argument for
 * function mvchrdev_cleanup
 */
struct mvchrdev_ctx {
	struct class *class;
	struct device *dev;
	struct cdev cdev;
	int major;
	int minor;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,69)
static char *mvchrdev_devnode(struct device *dev, umode_t *mode)
#else /* < 3.4.69 */
static char *mvchrdev_devnode(struct device *dev, mode_t *mode)
#endif /* < 3.4.69 */
{
	return kasprintf(GFP_KERNEL, "%s", dev->kobj.name);
}
#endif /* >= 2.6.32 */

static void mvchrdev_cleanup(struct mvchrdev_ctx *ctx)
{
	if (!ctx)
		return;

	dev_info(ctx->dev, "Device destroyed, major %d, minor %d\n", ctx->major,
		 ctx->minor);

	device_destroy(ctx->class, MKDEV(ctx->major, ctx->minor));
	class_destroy(ctx->class);
	cdev_del(&ctx->cdev);

	unregister_chrdev_region(MKDEV(ctx->major, ctx->minor), 1);

	kfree(ctx);
}

static struct mvchrdev_ctx *mvchrdev_init(const char *name,
					  const struct file_operations *fops)
{
	struct mvchrdev_ctx *ctx;
	int rc = 0;
	dev_t dev;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (unlikely(!ctx))
		return NULL;

	rc = alloc_chrdev_region(&dev, 1, 1, name);
	if (rc) {
		pr_err("%s: Fail to allocate chrdev region (%d)\n", name, rc);
		goto err_free;
	}

	ctx->major = MAJOR(dev);
	ctx->minor = MINOR(dev);

	cdev_init(&ctx->cdev, fops);
	ctx->cdev.owner = THIS_MODULE;
	rc = cdev_add(&ctx->cdev, dev, 2);
	if (rc) {
		pr_err("%s: Fail to add chrdev (%d)\n", name, rc);
		goto err_unreg_drv;
	}

	ctx->class = class_create(THIS_MODULE, name);
	if (IS_ERR(ctx->class)) {
		pr_err("%s: Fail to create class (%d)\n", name, rc);
		goto err_del_cdev;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
	ctx->class->devnode = mvchrdev_devnode;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	ctx->dev = device_create(ctx->class, NULL, dev, NULL, name);
#else
	ctx->dev = device_create(ctx->class, NULL, dev, name);
#endif

	dev_info(ctx->dev, "Device created, major %d, minor %d\n", ctx->major,
		 ctx->minor);

	return ctx;

err_del_cdev:
	cdev_del(&ctx->cdev);

err_unreg_drv:
	unregister_chrdev_region(dev, 1);

err_free:
	kfree(ctx);

	return NULL;
}

MODULE_LICENSE("GPL");
