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
* mvDriverTemplate.h
*
* DESCRIPTION:
*       Driver template: includes
*       Requirements before include:
*           MV_DRV_NAME     - driver name, for example "mvDmaDrv"
*           MV_DRV_MAJOR    - device major number
*           MV_DRV_MINOR    - device minor number
*           MV_DRV_FOPS     - file_operations structure
*
*           Optional:
*               MV_DRV_PREINIT   - static int MV_DRV_PREINIT(void);
*               MV_DRV_POSTINIT  - static void MV_DRV_POSTINIT(void);
*               MV_DRV_RELEASE   - static void MV_DRV_RELEASE(void);
*
* USAGE:
*       Kernel module command line parameters
*           major=<num>     - Set device node major number. If 0 passes
*                             then allocate devica major dynamically
*           minor=<num>     - Set device node minor number
*
* DEPENDENCIES:
*
*       $Revision: 1 $
*******************************************************************************/
#include <linux/uaccess.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/slab.h>

MODULE_VERSION("CPSS_4.3.4_005");

static int                  major = 0;
static int                  minor = MV_DRV_MINOR;
static struct cdev          mvDrv_cdev;
static struct class*        mvDrv_class;
static struct device*       mvDrv_device;

static struct file_operations MV_DRV_FOPS;
#ifdef MV_DRV_PREINIT
static int MV_DRV_PREINIT(void);
#endif
#ifdef MV_DRV_POSTINIT
static void MV_DRV_POSTINIT(void);
#endif
#ifdef MV_DRV_RELEASE
static void MV_DRV_RELEASE(void);
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,4,69)
static char *mvDrv_devnode(struct device *dev, umode_t *mode)
#else /* < 3.4.69 */
static char *mvDrv_devnode(struct device *dev, mode_t *mode)
#endif /* < 3.4.69 */
{
	return kasprintf(GFP_KERNEL, "%s", dev->kobj.name);
}
#endif /* >= 2.6.32 */

static void mvDrv_cleanup(void)
{
#ifdef MV_DRV_RELEASE
	MV_DRV_RELEASE();
#endif

	device_destroy(mvDrv_class, MKDEV(major, minor));
	class_destroy(mvDrv_class);
	cdev_del(&mvDrv_cdev);

	unregister_chrdev_region(MKDEV(major, minor), 1);
}

static int mvDrv_init(void)
{
	int result = 0;
	dev_t dev;

#ifdef MV_DRV_PREINIT
	result = MV_DRV_PREINIT();
	if (result < 0)
		return result;
#endif

	/* first thing register the device at OS */
	if (major != 0) {
		/* Register your major. */
		dev = MKDEV(major, minor);
		result = register_chrdev_region(dev, 1, MV_DRV_NAME);
	} else {
		/* get dynamic major */
		result = alloc_chrdev_region(&dev, minor, 1, MV_DRV_NAME);
		if (result == 0) {
			major = MAJOR(dev);
			minor = MINOR(dev);
			printk("Got dynamic major for " MV_DRV_NAME ": %d\n", major);
		}
	}
	if (result < 0) {
		printk(MV_DRV_NAME "_init: register_chrdev_region err= %d\n", result);
		return result;
	}

	cdev_init(&mvDrv_cdev, &MV_DRV_FOPS);
	mvDrv_cdev.owner = THIS_MODULE;
	result = cdev_add(&mvDrv_cdev, dev, 1);
	if (result) {
		printk(MV_DRV_NAME "_init: cdev_add err= %d\n", result);
error_region:
		unregister_chrdev_region(dev, 1);
		return result;
	}
	mvDrv_class = class_create(THIS_MODULE, MV_DRV_NAME);
	if (IS_ERR(mvDrv_class)) {
		printk(KERN_ERR "Error creating " MV_DRV_NAME " class.\n");
		cdev_del(&mvDrv_cdev);
		result = PTR_ERR(mvDrv_class);
		goto error_region;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,32)
	mvDrv_class->devnode = mvDrv_devnode;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)
	mvDrv_device = device_create(mvDrv_class, NULL, dev, NULL, MV_DRV_NAME);
#else
	mvDrv_device = device_create(mvDrv_class, NULL, dev, MV_DRV_NAME);
#endif

#ifdef MV_DRV_POSTINIT
	MV_DRV_POSTINIT();
#endif

	printk(KERN_DEBUG "device " MV_DRV_NAME " created, major=%d minor=%d\n", major, minor);

	return 0;
}

module_init(mvDrv_init);
module_exit(mvDrv_cleanup);

module_param(major, int, S_IRUGO);
module_param(minor, int, S_IRUGO);

MODULE_AUTHOR("Marvell Semi.");
MODULE_LICENSE("GPL");
