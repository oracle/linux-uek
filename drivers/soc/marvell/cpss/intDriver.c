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
* intDriver.c
*
* DESCRIPTION:
*       mvIntDrv - A simple driver which passes interrupts to user-space
*                  Usage:
*                     fd=open("/dev/mvIntDrv",O_RDWR);
*                     write(fd, "eI", 2)    will enable irq I (0..255)
*                     write(fd, "dI", 2)    will disable irq I (0..255)
*                     write(fd, "EIIII", 5) will enable irq I (0..0xffffffff)
*                     write(fd, "DIIII", 5) will disable irq I (0..0xffffffff)
*                     write(fd, "mBDF",4)   will enable MSI interrupts
*                                           Here B=PCI bus (binary)
*                                           Here D=PCI device (binary)
*                                           Here F=PCI device functin (binary)
*                     write(fd, "MddBDF",6) will enable MSI interrupts
*                                           Here dd=PCI domain, LE
*                                           Here B=PCI bus (binary)
*                                           Here D=PCI device (binary)
*                                           Here F=PCI device functin (binary)
*                     X=write(fd, "cI", 2) will connect irq I (0..255)
*                     X=write(fd, "CIIII", 5) will connect irq I (0..0xffffffff)
*
*                     read(fd,NULL,X) will wait for irq
*
*******************************************************************************/
#define MV_DRV_NAME     "mvIntDrv"
#include "mvDriverTemplate.h"

#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/list.h>

/* Character device context */
static struct mvchrdev_ctx *chrdrv_ctx;

static int mvIntDrvNumOpened = 0;

struct interrupt_slot {
	int			used;
	atomic_t		depth; /* keep track of enable/disable */
	unsigned int		irq;
	struct semaphore	sem; /* The semaphore on which the user waits */
	struct semaphore	close_sem; /* Sync disconnect with read */
	struct tasklet_struct	tasklet;
};

/* To hold list of devices we enabled MSI on */
struct mvintdrv_pci_dev {
	struct list_head list;
	struct pci_dev *pdev;
};

struct mvintdrv_file_priv {
	struct list_head msi_enabled_pdevs;
};

#define MAX_INTERRUPTS 32
static struct interrupt_slot mvIntDrv_slots[MAX_INTERRUPTS];

static int find_interrupt_slot(unsigned int irq, bool warn)
{
	struct interrupt_slot *sl;
	int slot;

	for (slot = 0; slot < MAX_INTERRUPTS; slot++) {
		sl = &(mvIntDrv_slots[slot]);
		if (sl->irq == irq)
			return slot;
	}

	if (warn)
		printk(KERN_WARNING "%s: No slot allocated for IRQ %d\n",
		       MV_DRV_NAME, irq);

	return -ENOENT;
}

static irqreturn_t prestera_tl_ISR(int irq, void *tl)
{
	int slot = find_interrupt_slot(irq, true);
	struct interrupt_slot *sl = &(mvIntDrv_slots[slot]);

	BUG_ON(!sl);

	atomic_dec(&sl->depth);
	/* Disable the interrupt vector */
	disable_irq_nosync(irq);
	/* Enqueue the PP task BH in the tasklet */
	tasklet_hi_schedule((struct tasklet_struct *)tl);

	return IRQ_HANDLED;
}

void mvPresteraBh(unsigned long data)
{
	/* Awake any reading process */
	up(&((struct interrupt_slot *)data)->sem);
}

/**
 *	alloc_interrupt_slot - Allocate interupt slot
 *	@irq: Interrupt number
 *
 *	Allocates and initialize interupt slot
 *
 *	Returns the index of the entry in interrupts array
 */
static unsigned int alloc_interrupt_slot(unsigned int irq)
{
	struct interrupt_slot *sl;
	int slot;

	for (slot = 0; slot < MAX_INTERRUPTS; slot++)
		if (!mvIntDrv_slots[slot].used) {
			sl = &(mvIntDrv_slots[slot]);
			sl->used = 1;
			sl->irq = irq;
			sema_init(&sl->sem, 0);
			sema_init(&sl->close_sem, 0);
			up(&sl->close_sem);
			tasklet_init(&sl->tasklet, mvPresteraBh,
				     (unsigned long)sl);
			if (request_irq(irq, prestera_tl_ISR, IRQF_SHARED,
					MV_DRV_NAME, (void *)&sl->tasklet))
				panic("Can not assign IRQ %u to mvIntDrv\n",
				      irq);
			atomic_set(&sl->depth, -1);
			disable_irq(irq);
			return slot;
		}

	return MAX_INTERRUPTS;
}

static void synch_irq_state(struct interrupt_slot *sl)
{
	while (atomic_read(&sl->depth) < 0) {
		atomic_inc(&sl->depth);
		enable_irq(sl->irq);
	}
	while (atomic_read(&sl->depth)) {
		atomic_dec(&sl->depth);
		disable_irq(sl->irq);
	}
}

/**
 *	free_interrupt_slot - Free interupt slot
 *	@slot: Index of an entry in interrupt array to free
 *
 *	Undoes all the steps of slot allocation
 *
 *	Note: This function assumes sl->irq is in "disable" state
 */
static void free_interrupt_slot(int slot)
{
	struct interrupt_slot *sl = &(mvIntDrv_slots[slot]);

	down(&sl->close_sem);
	/* In inconsistent state (ex race between disable_irq in ISR and
	   disable_irq in release event) synch to stable state before freeing
	   the IRQ */
	synch_irq_state(sl);
	up(&sl->close_sem);
	free_irq(sl->irq, (void*)&(sl->tasklet));
	tasklet_kill(&(sl->tasklet));
	sl->used = 0;
	sl->irq = 0;
}

static int intConnect(unsigned int irq)
{
	int slot;

	slot = find_interrupt_slot(irq, false);
	if (slot != -ENOENT) {
		printk(KERN_ERR "%s: irq number %d already connected\n",
		       MV_DRV_NAME, irq);
		return -EINVAL;
	}

	slot = alloc_interrupt_slot(irq);
	if (unlikely(slot == MAX_INTERRUPTS)) {
		printk(KERN_ERR "%s: no free slots\n", __func__);
		return -EFAULT;
	}

	printk(KERN_DEBUG "%s: connected IRQ - %u slot %d\n", __func__, irq,
	       slot);

	return slot + 1;
}

static int intDisConnect(unsigned int irq)
{
	int slot;

	slot = find_interrupt_slot(irq, true);
	if (slot == -ENOENT)
		return -EINVAL;

	/*
	 * free_interrupt_slot assumes that IRQ state is disabled so userspace
	 * must ensure this before triggering disconnect
	 */
	free_interrupt_slot(slot);
	printk(KERN_DEBUG "%s: disconnected IRQ - %u slot %d\n", __func__, irq,
	       slot);

	return slot;
}

static int mvintdrv_pdev_enable_msi(struct pci_dev *pdev)
{
	int rc;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
	dev_info(&pdev->dev, "Enabling MSI, legacy IRQ number is %d\n",
		 pci_irq_vector(pdev, 0));
#else
	dev_info(&pdev->dev, "Enabling MSI, legacy IRQ number is %d\n",
		 pdev->irq);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
	rc = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_ALL_TYPES);
	rc = rc >= 1 ? 0 : -1;
#else
	rc = pci_enable_msi(pdev);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
	dev_info(&pdev->dev, "MSI IRQ number is %d\n", (rc < 0) ? -1 :
		 pci_irq_vector(pdev, 0));
#else
	dev_info(&pdev->dev, "MSI IRQ number is %d\n", (rc < 0) ? -1 :
		 pdev->irq);
#endif

	return rc;
}

static int mvintdrv_enable_msi(struct file *f, int domain, unsigned int bus,
			       unsigned int dev, unsigned int func)
{
#ifdef CONFIG_PCI_MSI
	struct mvintdrv_pci_dev *mv_pdev;
	struct pci_dev *pdev;

	pdev = pci_get_domain_bus_and_slot(domain, bus, PCI_DEVFN(dev, func));
	if (pdev) {
		struct mvintdrv_file_priv *priv;
		int rc;

		priv = (struct mvintdrv_file_priv *)f->private_data;
		if (pci_dev_msi_enabled(pdev)) {
			printk(KERN_DEBUG "%s: MSI already enabled\n",
			       MV_DRV_NAME);
			pci_dev_put(pdev);
			return 0;
		}

		rc = mvintdrv_pdev_enable_msi(pdev);
		if (!rc) {
			/*
			 * Add to global list so we can disable MSI on driver
			 * driver exit
			 */
			mv_pdev = kmalloc(sizeof(*mv_pdev), GFP_KERNEL);
			mv_pdev->pdev = pdev;
			list_add(&mv_pdev->list, &priv->msi_enabled_pdevs);
		} else {
			pci_dev_put(pdev);
		}

		return rc;
	} else {
		printk(KERN_ERR "%s: Fail to find PCI device\n", MV_DRV_NAME);
		return -EINVAL;
	}
#else
	printk(KERN_ERR "%s: MSI requested however CONFIG_PCI_MSI is not enabled in the kernel build\n",
	       MV_DRV_NAME);
	return -EIO;
#endif
}

/**
 * Call the proper function to disable MSI according to kernel version in use
 */
static void mvintdrv_pdev_disable_msi(struct pci_dev *pdev)
{
	dev_info(&pdev->dev, "Disabling MSI\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,9,0)
	pci_free_irq_vectors(pdev);
#else
	pci_disable_msi(pdev);
#endif
}

/**
 * Disable MSI for all devices of a given file descriptor, called when file
 * descriptor is closed
 */
static void mvintdrv_disable_msi_devs(struct file *f)
{
#ifdef CONFIG_PCI_MSI
	struct mvintdrv_file_priv *priv =
		(struct mvintdrv_file_priv *)f->private_data;
	struct list_head *p, *q;

	list_for_each_safe(p, q, &(priv->msi_enabled_pdevs)) {
		struct mvintdrv_pci_dev *mv_pdev;
		mv_pdev = list_entry(p, struct mvintdrv_pci_dev, list);
		mvintdrv_pdev_disable_msi(mv_pdev->pdev);
		pci_dev_put(mv_pdev->pdev);
		list_del(p);
		kfree(mv_pdev);
	}
#endif
}

/**
 * Disable MSI for device identified by DBDF
 */
static int mvintdrv_disable_msi(int domain, unsigned int bus, unsigned int dev,
				unsigned int func)
{
#ifdef CONFIG_PCI_MSI
	struct pci_dev *pdev;

	pdev = pci_get_domain_bus_and_slot(domain, bus, PCI_DEVFN(dev, func));
	if (pdev) {
		mvintdrv_pdev_disable_msi(pdev);
		pci_dev_put(pdev);
		return 0;
	} else {
		printk(KERN_ERR "%s: Fail to find PCI device %d:%d:%d.%d\n",
		       MV_DRV_NAME, domain, bus, dev, func);
		return -EINVAL;
	}
#else
	printk(KERN_ERR "%s: MSI requested however CONFIG_PCI_MSI is not enabled in the kernel build\n",
	       MV_DRV_NAME);
	return -EIO;
#endif
}

static ssize_t mvIntDrv_write(struct file *f, const char *buf, size_t siz, loff_t *off)
{
	struct interrupt_slot *sl;
	unsigned int irq = -1;
	char cmdBuf[6];
	int slot;

	/* Write 2 bytes:
	 * 'c' intNo       - connect interrupt, returns slot+1
	 * 'd' intNo       - disable interrupt
	 * 'e' intNo       - enable interrupt
	 * 'q' intNo       - query interrupt, whether other drivers are still
	 *                   attached to it
	 * 'C' i i i i     - connect interrupt, returns slot+1
	 * 'R' i i i i     - remove interrupt, returns slot+1
	 * 'D' i i i i     - disable interrupt
	 * 'E' i i i i     - enable interrupt
	 * 'Q' i i i i     - query interrupt, whether other drivers are still
	 *                   attached to it
	 * 'm' bus, dev func - enable MSI interrupts for pci device
	 * 'M' domain, bus, dev func - enable MSI interrupts for pci device
	 * 's' bus, dev func - disable MSI interrupts for pci device
	 * 'S' domain, bus, dev func - disable MSI interrupts for pci device
	 *
	 * return <!0 - error, slot for connect, 0 for enable/disable, 0/1 for Q
	 * (query) */

	if (copy_from_user(cmdBuf, buf, ((siz < 6) ? siz : 6))) {
		printk(KERN_ERR "%s: EFAULT\n", __func__);
		return -EFAULT;
	}

	switch (cmdBuf[0]) {
	case 'c':
		/* Fall through */
	case 'd':
		/* Fall through */
	case 'e':
		/* Fall through */
	case 'r':
		/* Fall through */
	case 'q':
		irq = (unsigned int)cmdBuf[1];
		break;
	case 'C':
		/* Fall through */
	case 'D':
		/* Fall through */
	case 'E':
		/* Fall through */
	case 'R':
		/* Fall through */
	case 'Q':
		memcpy(&irq, cmdBuf + 1, 4);
		break;
	}

	printk(KERN_DEBUG "%s: %c(%d, %d, %d)\n", MV_DRV_NAME, cmdBuf[0],
	       cmdBuf[1], cmdBuf[2], cmdBuf[3]);

	if (cmdBuf[0] == 'c' || cmdBuf[0] == 'C')
		return intConnect(irq);

	if (cmdBuf[0] == 'r' || cmdBuf[0] == 'R')
		return intDisConnect(irq);

	if (cmdBuf[0] == 'd' || cmdBuf[0] == 'D') {
		slot = find_interrupt_slot(irq, true);
		if (slot == -ENOENT)
			return -EINVAL;
		sl = &(mvIntDrv_slots[slot]);
		atomic_dec(&sl->depth);
		disable_irq(irq);
		return 0;
	}

	if (cmdBuf[0] == 'e' || cmdBuf[0] == 'E') {
		slot = find_interrupt_slot(irq, true);
		if (slot == -ENOENT)
			return -EINVAL;
		sl = &(mvIntDrv_slots[slot]);
		atomic_inc(&sl->depth);
		enable_irq(irq);
		return 0;
	}

	if (cmdBuf[0] == 'm')
		return mvintdrv_enable_msi(f, 0, (unsigned)cmdBuf[1],
					   (unsigned)cmdBuf[2],
					   (unsigned)cmdBuf[3]);

	if (cmdBuf[0] == 'M')
		return mvintdrv_enable_msi(f, (((cmdBuf[2]<<8)&0xff00) |
					   (cmdBuf[1]&0xff)),
					   (unsigned)cmdBuf[3],
					   (unsigned)cmdBuf[4],
					   (unsigned)cmdBuf[5]);

	if (cmdBuf[0] == 's')
		return mvintdrv_disable_msi(0, (unsigned)cmdBuf[1],
					    (unsigned)cmdBuf[2],
					    (unsigned)cmdBuf[3]);

	if (cmdBuf[0] == 'S')
		return mvintdrv_disable_msi((((cmdBuf[2]<<8)&0xff00) |
					   (cmdBuf[1]&0xff)),
					   (unsigned)cmdBuf[3],
					   (unsigned)cmdBuf[4],
					   (unsigned)cmdBuf[5]);

	if (cmdBuf[0] == 'q' || cmdBuf[0] == 'Q')
		return find_interrupt_slot(irq, false) != -ENOENT;

	printk(KERN_ERR "%s: Invalid command '%c'\n", MV_DRV_NAME, cmdBuf[0]);

	return -EINVAL;
}

static ssize_t mvIntDrv_read(struct file *f, char *buf, size_t siz, loff_t *off)
{
	struct interrupt_slot *sl;
	int slot = (int)siz - 1;

	if (slot < 0 || slot >= MAX_INTERRUPTS)
		return -EINVAL;

	sl = &(mvIntDrv_slots[slot]);
	if (!sl->used)
		return -EINVAL;

	/* Enable the interrupt vector */
	atomic_inc(&sl->depth);
	enable_irq(sl->irq);

	if (down_interruptible(&sl->sem)) {
		down(&sl->close_sem);
		atomic_dec(&sl->depth);
		disable_irq(sl->irq);
		up(&sl->close_sem);
		return -EINTR;
	}

	return 0;
}

static int mvIntDrv_open(struct inode *inode, struct file *file)
{
	struct mvintdrv_file_priv *priv;

	mvIntDrvNumOpened++;

	priv = kmalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	INIT_LIST_HEAD(&priv->msi_enabled_pdevs);

	file->private_data = priv;

	return 0;
}

static int mvIntDrv_release(struct inode *inode, struct file *file)
{
	mvIntDrvNumOpened--;
	if (!mvIntDrvNumOpened) {
		/* Cleanup */
		int slot;
		struct interrupt_slot *sl;

		for (slot = 0; slot < MAX_INTERRUPTS; slot++) {
			sl = &(mvIntDrv_slots[slot]);
			if (!sl->used)
				continue;
			/* free_interrupt_slot assumes that IRQ state is disabled and we are cool
			 * with that since in both cases, waiting for interrupt or servicing an
			 * interrupt - IRQ is disabled.
			 * In abnormal case where the process dies while waiting for interrupt,
			 * the down_interruptible will exits and disable_irq will be called. On
			 * the other hand, the ISR function make sure the IRQ is disabled while
			 * servicing an interrupt */
			free_interrupt_slot(slot);
		}
	}

	mvintdrv_disable_msi_devs(file);

	kfree(file->private_data);

	return 0;
}

static struct file_operations mvIntDrv_fops = {
	.read = mvIntDrv_read,
	.write = mvIntDrv_write,
	.open = mvIntDrv_open,
	.release = mvIntDrv_release /* A.K.A close */
};

void mvintdrv_exit(void)
{
	mvchrdev_cleanup(chrdrv_ctx);
}

int mvintdrv_init(void)
{
	chrdrv_ctx = mvchrdev_init(MV_DRV_NAME, &mvIntDrv_fops);
	if (!chrdrv_ctx)
		return -EIO;

	memset(mvIntDrv_slots, 0, sizeof(mvIntDrv_slots));

	return 0;
}
