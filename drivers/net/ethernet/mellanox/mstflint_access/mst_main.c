/*
 * Copyright (c) 2011-2014 Mellanox Technologies, Inc. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/io.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
#include <linux/uaccess.h>
#else
#include <asm/uaccess.h>
#endif
#include <linux/pci.h>
#include <linux/fs.h>
#include "mst_kernel.h"


/****************************************************/
MODULE_AUTHOR("Mahmoud Hasan");
MODULE_DESCRIPTION("MST Module");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION " ("DRV_RELDATE")");


/****************************************************/
/* globals variables */
static const char mst_driver_version[] =  DRV_VERSION;
static const char mst_driver_string[]	= "Mellanox Technologies Software Tools Driver";

LIST_HEAD(mst_devices);

static struct pci_device_id mst_livefish_pci_table[] = {
	{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 0x01f6) }, 	/* MT27500 [ConnectX-3 Flash Recovery] */
	{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 0x01f8) }, 	/* MT27520 [ConnectX-3 Pro Flash Recovery] */
	{ 0, }
};

static struct pci_device_id mst_bar1_pci_table[] = {
	{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 0x01011) }, 	/* MT27600 [ConnectX-IB] */
	{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 0x01ff) }, 	/* MT27600 [ConnectX-IB Flash Recovery] */
	{ 0, }
};

static struct pci_device_id supported_pci_devices[] = {
	{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 4099) }, 	/* MT27600 [ConnectX-IB] */
	{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 4103) }, 	/* MT27600 [ConnectX-IB Flash Recovery] */
	{ 0, }
};


/****************************************************/
static int mst_open(struct inode *inode, struct file *file)
{
	struct mst_file_data *md = NULL;

	 md = kmalloc(sizeof(struct mst_connectx_wa), GFP_KERNEL);
	 if (!md) {
		 return -ERESTARTSYS;
	 }

	 memset(md, 0, sizeof(struct mst_connectx_wa));

	 file->private_data = md;

	 return 0;
}


/****************************************************/
static int mst_release(struct inode *inode, struct file *file)
{
	int res						= 0;
	struct mst_dev_data *dev	= NULL;
	struct mst_dev_data *cur	= NULL;
	unsigned int slot_mask;
	struct mst_connectx_wa *md 	= file->private_data;

	/*
	 * make sure the device is available since it
	 * could be removed by hotplug event
	 * if available grab its lock
	 */
	list_for_each_entry(cur, &mst_devices, list) {
		if (cur->major == imajor(inode)) {
			dev = cur;
			mutex_lock(&dev->lock);
			break;
		}
	}

	if (!dev) {
		mst_err("failed to find device with major=%d\n",
				imajor(inode));
				res = -ENODEV;
				goto out;
	}

	slot_mask = ~(1 << (md->connectx_wa_slot_p1 - 1));
	dev->connectx_wa_slots &= slot_mask;

	/*
	 * mst_info("CONNECTX_WA: Released slot %u. Current slots: %02x\n",
	 * 			md->connectx_wa_slot_p1 - 1, dev->connectx_wa_slots);
	 */
	md->connectx_wa_slot_p1 = 0;
	mutex_unlock(&dev->lock);

	kfree(file->private_data);
	file->private_data = NULL;

out:
	return res;
}


/****************************************************/
static ssize_t mst_read(struct file *file, char *buf, size_t count,
			loff_t *f_pos)
{
	mst_err("not implemented\n");
	return 0;
}


/****************************************************/
static ssize_t mst_write(struct file *file, const char *buf, size_t count,
			 loff_t *f_pos)
{
	mst_err("not implemented\n");
	return 0;
}


/****************************************************/
static inline void print_opcode(void)
{
	mst_info("MST_PARAMS=%lx\n", MST_PARAMS);

	mst_info("PCICONF_READ4=%lx\n", PCICONF_READ4);
	mst_info("PCICONF_WRITE4=%lx\n", PCICONF_WRITE4);
	mst_info("PCIMEM_READ4=%lx\n",	PCIMEM_READ4);
	mst_info("PCIMEM_WRITE4=%lx\n", PCIMEM_WRITE4);

	mst_info("PCIMEM_READ_BLOCK=%lx\n", PCIMEM_READ_BLOCK);
	mst_info("PCIMEM_WRITE_BLOCK=%lx\n", PCIMEM_WRITE_BLOCK);

	mst_info("PCICONF_INIT=%lx\n", PCICONF_INIT);
	mst_info("PCICONF_STOP=%x\n", PCICONF_STOP);

	mst_info("PCIMEM_INIT=%lx\n", PCIMEM_INIT);
	mst_info("PCIMEM_STOP=%x\n", PCIMEM_STOP);

	mst_info("PCI_CONNECTX_WA=%lx\n", PCI_CONNECTX_WA);

	mst_info("PCICONF_VPD_READ4=%lx\n", PCICONF_VPD_READ4);
	mst_info("PCICONF_VPD_WRITE4=%lx\n", PCICONF_VPD_WRITE4);
}


/****************************************************/
/*
 * mst_ioctl
 *
 * @opcode:
 *  MST_PARAMS - get the device parameters
 *
 *  PCICONF_READ4     - read 4 bytes from configuration space
 *  PCICONF_WRITE4    - write 4 bytes to configuration space
 *  PCIMEM_READ4      - read 4 bytes from memory access
 *  PCIMEM_WRITE4     - write 4 bytes to memory access
 *
 *  PCIMEM_READ_BLOCK - read a block of data from pci memory,
 *			size is expressed as num of unsigned integers
 *  PCIMEM_WRITE_BLOCK - write a block of data to pci memory,
 *			size is expressed as num of unsigned integers

 *  PCICONF_INIT       - initialize a new PCICONF device
 *  PCICONF_STOP       - stop a PCICONF device
 *
 *  PCIMEM_INIT        - initialize a new PCIMEM device
 *  PCIMEM_STOP        - stop a PCIMEM device
 *
 *  PCI_CONNECTX_WA      - connectx workaround for
 *           pci reads passing writes
 *
 * RETURN VALUE:
 *   0 upon success
 *   -EINVAL if opcode is invalid
 *   -ENODEV if device is not initialized
 *   -EPERM  if operation does not match device type
 *   -EFAULT if there was a problem with hardware operation
 *
 */
static int mst_ioctl(struct inode *inode, struct file *file,
		     unsigned int opcode, unsigned long input)
{

	int res						= 0;
	struct mst_dev_data *dev	= NULL;
	struct mst_dev_data *cur	= NULL;
	void *user_buf				= (void *)input;

	/*
	 * In MEM mapped data flow there is no need to lock the semaphore.
	 * Since the HW handles the requests in PCI level thus no need
	 * for serializing (HW is capable of handling parallel requests)
	 */
#define IS_LOCK_NEEDED(dev) \
	(!(dev->type == PCIMEM && \
	(opcode == MST_READ4 || opcode == MST_WRITE4)))

	/*
	 * make sure the device is available since it
	 * could be removed by hotplug event
	 * if available grab its lock
	 */
	list_for_each_entry(cur, &mst_devices, list) {
		if (cur->major == imajor(inode)) {
			dev = cur;
			if (IS_LOCK_NEEDED(dev))
				mutex_lock(&dev->lock);
			break;
		}
	}

	if (!dev) {
		mst_err("failed to find device with major=%d\n",
		       imajor(inode));
		res = -ENODEV;
		goto fin_err;
	}


	switch (opcode) {
	case MST_PARAMS: {
		struct mst_params paramst;

		if (!dev->initialized) {
			mst_err("device is not initialized\n");
			res = -ENODEV;
			goto fin;
		}

		paramst.domain 				= pci_domain_nr(dev->pci_dev->bus);
		paramst.bus 				= dev->pci_dev->bus->number;
		paramst.slot 				= PCI_SLOT(dev->pci_dev->devfn);
		paramst.func				= PCI_FUNC(dev->pci_dev->devfn);
		paramst.bar 				= dev->bar;
		paramst.device 				= dev->pci_dev->device;
		paramst.vendor				= dev->pci_dev->vendor;
		paramst.subsystem_device 	= dev->pci_dev->subsystem_device;
		paramst.subsystem_vendor	= dev->pci_dev->subsystem_vendor;

		if (copy_to_user(user_buf, &paramst, sizeof(struct mst_params))) {
			res = -EFAULT;
			goto fin;
		}
		break;
	}

	case MST_READ4: {
		u32 out;
		u32 *dataout = NULL;
		struct mst_read4_st readst;

		if (!dev->initialized) {
			mst_err("device is not initialized\n");
			res = -ENODEV;
			goto fin;
		}

		if (copy_from_user(&readst, user_buf, sizeof(struct mst_read4_st))) {
			res = -EFAULT;
			goto fin;
		}

		switch (dev->type) {
		case PCICONF:
			/* write the wanted address to addr register */
			res = pci_write_config_dword(dev->pci_dev, dev->addr_reg, readst.offset);
			if (res) {
				mst_err("pci_write_config_dword failed\n");
				goto fin;
			}

			/* read the result from data register */
			res = pci_read_config_dword(dev->pci_dev, dev->data_reg, &out);
			if (res) {
				mst_err("pci_read_config_dword failed\n");
				goto fin;
			}
			break;

		case PCIMEM:
			if ((readst.offset + sizeof(u32)) > MST_MEMORY_SIZE) {
				mst_err("accesing invalid address\n");
				res = -EINVAL;
				goto fin;
			}

			/* read from hardware */
			out = ioread32(dev->hw_addr + readst.offset);

			/* endianness conversion - we noticed that we need to swap always */
                        be32_to_cpus(&out);
                        out = cpu_to_le32(out);
			break;
		}

		/* retrieve to user */
		dataout = &((struct mst_read4_st *)user_buf)->data;
		if (copy_to_user(dataout, &out, sizeof(u32))) {
			res = -EFAULT;
			goto fin;
		}
		break;
	}

	case MST_WRITE4: {
		struct mst_write4_st writest;

		if (!dev->initialized) {
			mst_err("device is not initialized\n");
			res = -ENODEV;
			goto fin;
		}

		if (copy_from_user(&writest, user_buf, sizeof(struct mst_write4_st))) {
			res = -EFAULT;
			goto fin;
		}

		switch (dev->type) {
		case PCICONF:
			/* write the destination address to addr register */
			res = pci_write_config_dword(dev->pci_dev, dev->addr_reg, writest.offset);
			if (res) {
				mst_err("pci_write_config_dword failed\n");
				goto fin;
			}

			/* write the data to data register */
			res = pci_write_config_dword(dev->pci_dev, dev->data_reg, writest.data);
			if (res) {
				mst_err("pci_write_config_dword failed\n");
				goto fin;
			}
			break;

		case PCIMEM:
			if ((writest.offset + sizeof(u32)) > MST_MEMORY_SIZE) {
				mst_err("Accesing invalid address\n");
				res = -EINVAL;
				goto fin;
			}

			/* endianness conversion - we noticed that we need to swap always */
			cpu_to_be32s(&(writest.data));
                        writest.data = cpu_to_le32(writest.data);

			/* write to hardware */
			iowrite32(writest.data, dev->hw_addr + writest.offset);
			break;
		}

		break;
	}

	case PCIMEM_READ_BLOCK: {
		int i			= 0;
		u32 *data		= NULL;
		u32 *dataout	= NULL;
		struct mst_read_block_st readst;

		if (!dev->initialized) {
			mst_err("device is not initialized\n");
			res = -ENODEV;
			goto fin;
		}

		if (dev->type != PCIMEM) {
			mst_err("wrong type for device\n");
			res = -EPERM;
			goto fin;
		}

		if (copy_from_user(&readst, user_buf, sizeof(struct mst_read_block_st))) {
			res = -EFAULT;
			goto fin;
		}

		if (readst.size % sizeof(u32)) {
			mst_err("invalid size. size should be in bytes and devide sizeof(u32)\n");
			res = -EINVAL;
			goto fin;
		}

		if ((readst.offset + readst.size) > MST_MEMORY_SIZE) {
			mst_err("accesing invalid address\n");
			res = -EINVAL;
			goto fin;
		}

		data = kzalloc(readst.size, GFP_KERNEL);
		if (!data) {
			res = -ENOMEM;
			goto fin;
		}

		/* read from hardware */
		memcpy_fromio(data, dev->hw_addr + readst.offset, readst.size);

		/* endianness conversion */
		for (i = 0; i < (readst.size / sizeof(u32)); ++i)
		       be32_to_cpus(&(data[i]));

		/* retrieve to user */
		dataout = ((struct mst_read_block_st *)user_buf)->data;
		if (copy_to_user(dataout, data, readst.size)) {
			res = -EFAULT;
			kfree(data);
			goto fin;
		}

		kfree(data);
		break;
	}

	case PCIMEM_WRITE_BLOCK: {
		int i = 0;
		struct mst_write_block_st writest;

		if (!dev->initialized) {
			mst_err("device is not initialized\n");
			res = -ENODEV;
			goto fin;
		}

		if (dev->type != PCIMEM) {
			mst_err("wrong type for device\n");
			res = -EPERM;
			goto fin;
		}

		if (copy_from_user(&writest, user_buf, sizeof(struct mst_write_block_st))) {
			res = -EFAULT;
			goto fin;
		}

		if (writest.size % sizeof(u32)) {
			mst_err("invalid size. size should be in bytes and devide sizeof(u32)\n");
			res = -EINVAL;
			goto fin;
		}

		if ((writest.offset + writest.size) > MST_MEMORY_SIZE) {
			mst_err("accesing invalid address\n");
			res = -EINVAL;
			goto fin;
		}

		/* endianness conversion */
		for (i = 0; i < (writest.size / sizeof(u32)) ; ++i)
			cpu_to_be32s(&(writest.data[i]));

		/* write to hardware */
		memcpy_toio(dev->hw_addr + writest.offset, writest.data, writest.size);

		break;
	}

	case PCICONF_INIT: {
		struct mst_pciconf_init_st initst;

		if (dev->initialized) {
			mst_err("device already initialized\n");
			res = ENODEV;
			goto fin;
		}

		if (dev->type != PCICONF) {
			mst_err("wrong type for device\n");
			res = -EPERM;
			goto fin;
		}


		if (copy_from_user(&initst, user_buf, sizeof(struct mst_pciconf_init_st))) {
			res = -EFAULT;
			goto fin;
		}

		dev->addr_reg = initst.addr_reg;
		dev->data_reg = initst.data_reg;
		dev->initialized = 1;
		break;
	}

	case PCICONF_STOP: {
		if (!dev->initialized) {
			mst_err("device is not initialized\n");
			res = -ENODEV;
			goto fin;
		}

		if (dev->type != PCICONF) {
			mst_err("wrong type for device\n");
			res = -EPERM;
			goto fin;
		}

		dev->initialized = 0;
		break;
	}


	case PCIMEM_INIT: {
		struct mst_mem_init_st initst;
		unsigned long resource_start;

		if (dev->initialized) {
			mst_err("device already initialized\n");
			res = ENODEV;
			goto fin;
		}

		if (dev->type != PCIMEM) {
			mst_err("wrong type for device\n");
			res = -EPERM;
			goto fin;
		}

		if (copy_from_user(&initst, user_buf, sizeof(struct mst_mem_init_st))) {
			res = -EFAULT;
			goto fin;
		}

		/* unmap previously mapped device if it was not stopped properly */
		if (dev->hw_addr) {
			iounmap(cur->hw_addr);
			dev->hw_addr = NULL;
		}

		dev->bar = initst.bar;
		resource_start = pci_resource_start(dev->pci_dev, dev->bar);

		dev->hw_addr = ioremap(resource_start, MST_MEMORY_SIZE);

		if (dev->hw_addr <= 0) {
			mst_err("could not map device memory\n");
			res = -EFAULT;
			goto fin;
		}

		dev->initialized = 1;
		break;
	}

	case PCIMEM_STOP: {
		if (!dev->initialized) {
			mst_err("device is not initialized\n");
			res = -ENODEV;
			goto fin;
		}

		if (dev->type != PCIMEM) {
			mst_err("wrong type for device\n");
			res = -EPERM;
			goto fin;
		}

		if (cur->hw_addr)
			iounmap(cur->hw_addr);

		cur->hw_addr = NULL;
		dev->initialized = 0;
		break;
	}

	case PCI_CONNECTX_WA: {
		struct mst_connectx_wa *md = file->private_data;
		unsigned int slot_mask;

		if (!dev->initialized) {
			mst_err("device is not initialized\n");
			res = -ENODEV;
			goto fin;
		}

		/* slot exists */
		if (md->connectx_wa_slot_p1) {
			mst_err("slot exits for file %s, slot:0x%x\n",
					dev->name, md->connectx_wa_slot_p1);
			res = -EPERM;
			goto fin;
		}

		/* find first un(set) bit. and remember the slot */
		md->connectx_wa_slot_p1 = ffs(~dev->connectx_wa_slots);
		if (md->connectx_wa_slot_p1 == 0 || md->connectx_wa_slot_p1 > CONNECTX_WA_SIZE) {
			res = -ENOLCK;
			goto fin;
		}

		slot_mask = 1 << (md->connectx_wa_slot_p1 - 1);
		/* set the slot as taken */
		dev->connectx_wa_slots |= slot_mask;

		/*
		 * mst_info("CONNECTX_WA: Took slot %u. Current slots: %02x\n",
		 * 			md->connectx_wa_slot_p1 - 1, dev->connectx_wa_slots);
		 */
		if (copy_to_user(user_buf, md, sizeof(struct mst_connectx_wa))) {
			res = -EFAULT;
			goto fin;
		}
		break;
	}

	case PCICONF_VPD_READ4: {
		u32 out;
		u32 *dataout = NULL;
		struct mst_vpd_read4_st readst;

		if (!dev->initialized) {
			mst_err("device is not initialized\n");
			res = ENODEV;
			goto fin;
		}

		if (dev->type != PCICONF) {
			mst_err("wrong type for device\n");
			res = -EPERM;
			goto fin;
		}

		if (copy_from_user(&readst, user_buf, sizeof(struct mst_vpd_read4_st))) {
			res = -EFAULT;
			goto fin;
		}

		res = pci_read4_vpd(dev, readst.timeout, readst.offset, &out);
		if (res) {
			goto fin;
		}

		/* retrieve to user - we noticed that we need to swap always */
		dataout = &((struct mst_vpd_read4_st *)user_buf)->data;
                out = le32_to_cpu(out);
		if (copy_to_user(dataout, &out, sizeof(u32))) {
			res = -EFAULT;
			goto fin;
		}
		break;
	}

	case PCICONF_VPD_WRITE4: {
		struct mst_vpd_write4_st writest;

		if (!dev->initialized) {
			mst_err("device is not initialized\n");
			res = ENODEV;
			goto fin;
		}

		if (dev->type != PCICONF) {
			mst_err("wrong type for device\n");
			res = -EPERM;
			goto fin;
		}

		if (copy_from_user(&writest, user_buf, sizeof(struct mst_vpd_write4_st))) {
			res = -EFAULT;
			goto fin;
		}
                writest.data = le32_to_cpu(writest.data);
		res = pci_write4_vpd(dev, writest.timeout, writest.offset, writest.data);
		if (res) {
			goto fin;
		}
		break;
	}

	default: {
		mst_err("incorrect opcode = %x available opcodes:\n", opcode);
		print_opcode();
		res = -EINVAL;
		break;
	}
	}

fin:
	if (IS_LOCK_NEEDED(dev))
		mutex_unlock(&dev->lock);
fin_err:
	return res;
}

#if HAVE_COMPAT_IOCTL
static long compat_ioctl (struct file *f, unsigned int o, unsigned long d)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
    struct inode *n = f->f_dentry->d_inode;
#else
    struct inode *n = f->f_path.dentry->d_inode;
#endif
	return mst_ioctl(n, f, o, d);
}
#endif

#ifdef HAVE_UNLOCKED_IOCTL
static long unlocked_ioctl (struct file *f, unsigned int o, unsigned long d)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
    struct inode *n = f->f_dentry->d_inode;
#else
    struct inode *n = f->f_path.dentry->d_inode;
#endif

	return mst_ioctl(n, f, o, d);
}
#endif

/****************************************************/
static inline const char *dev_type_to_str(enum dev_type type)
{
	switch (type) {
	case PCICONF:
		return "PCICONF";
	case PCIMEM:
		return "PCIMEM";
	default:
		return "UNKNOWN";
	}
}


/****************************************************/
static const struct file_operations mst_fops = {
	.read		= mst_read,
	.write		= mst_write,

#ifdef HAVE_UNLOCKED_IOCTL
	.unlocked_ioctl = unlocked_ioctl,
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
	.ioctl          = mst_ioctl,
#endif

#if HAVE_COMPAT_IOCTL
	.compat_ioctl   = compat_ioctl,
#endif

	.open		= mst_open,
	.release	= mst_release,
	.owner		= THIS_MODULE,
};

static struct mst_dev_data *mst_device_create(enum dev_type type,
		struct pci_dev *pdev)
{
	struct mst_dev_data *dev = NULL;
        char dbdf[20];

	dev = kzalloc(sizeof(struct mst_dev_data), GFP_KERNEL);
	if (!dev) {
		mst_err("failed allocating new %s device with id=0x%x\n",
				dev_type_to_str(type),
				pdev->device);
		return NULL;
	}

        sprintf(dbdf, "%4.4x:%2.2x:%2.2x.%1.1x", pci_domain_nr(pdev->bus), pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
	switch (type) {
	case PCICONF:
		dev->addr_reg	= MST_CONF_ADDR_REG;
		dev->data_reg	= MST_CONF_DATA_REG;
		dev->bar	= 0;		/* invalid */
		dev->hw_addr	= NULL;		/* invalid */
		snprintf(dev->name,
				MST_NAME_SIZE,
				"%s" MST_PCICONF_DEVICE_NAME,
                                dbdf);
		break;
	case PCIMEM:
		dev->addr_reg	= 0;		/* invalid */
		dev->data_reg	= 0;		/* invalid */
		dev->bar 	= pci_match_id(mst_bar1_pci_table, pdev) ? 1 : 0;
		dev->hw_addr 	= ioremap(pci_resource_start(pdev, dev->bar),
				MST_MEMORY_SIZE);
		if (dev->hw_addr <= 0) {
			mst_err("could not map device memory\n");
			goto out;
		}

		snprintf(dev->name,
				MST_NAME_SIZE,
				"%s" MST_PCIMEM_DEVICE_NAME,
				dbdf);
		break;
	default:
		mst_err("failed to %s, unknown device type 0x%x\n",
				__func__, dev->type);
		goto out;
	}

	dev->type			= type;
	dev->pci_dev		= pdev;
	mutex_init(&dev->lock);

	dev->vpd_cap_addr = pci_find_capability(pdev, PCI_CAP_ID_VPD);

    if (alloc_chrdev_region(&dev->my_dev, 0, 1, dev->name)) {
        mst_err("failed to allocate chrdev_region\n");
    }
    if ( (dev->cl = class_create( THIS_MODULE, dev->name ) ) == NULL ) {
        printk(KERN_ALERT "Class creation failed\n");
        unregister_chrdev_region(dev->my_dev, 1);
        goto out;
    }

    if( device_create(dev->cl, NULL, dev->my_dev, NULL, dev->name) == NULL) {
        printk(KERN_ALERT "Device creation failed\n");
        class_destroy(dev->cl);
        unregister_chrdev_region(dev->my_dev , 1);
        goto out;
    }

    dev->major = MAJOR(dev->my_dev);
    cdev_init(&dev->mcdev, &mst_fops);
    cdev_add(&dev->mcdev, dev->my_dev, 1); //TODO check if cdev_add fails

	dev->initialized = 1;
	list_add_tail(&dev->list, &mst_devices);

	return dev;
out:
	kfree(dev);
	return NULL;
}


static void mst_device_destroy(struct mst_dev_data *dev)
{
	if (dev->hw_addr) {
		iounmap(dev->hw_addr);
	}

        cdev_del(&dev->mcdev);
        device_destroy(dev->cl, dev->my_dev);
        class_destroy(dev->cl);
        unregister_chrdev_region(dev->my_dev, 1);
	list_del(&dev->list);
	kfree(dev);
}



/****************************************************/
static int __init mst_init(void)
{
	int device_exists			= 0;
	struct pci_dev  *pdev		= NULL;
	struct mst_dev_data *dev	= NULL;
	struct mst_dev_data *cur	= NULL;

	mst_info("%s - version %s\n", mst_driver_string, mst_driver_version);

	while ((pdev = pci_get_device(MST_MELLANOX_PCI_VENDOR, PCI_ANY_ID, pdev)) != NULL) {
        if (!pci_match_id(supported_pci_devices, pdev) && !pci_match_id(mst_livefish_pci_table, pdev)) {
            continue;
        }
		device_exists = 0;
		list_for_each_entry(cur, &mst_devices, list) {
			if (cur->pci_dev->bus->number == pdev->bus->number) {
				device_exists = 1;	/* device already exists */
				break;
			}
		}
		if (device_exists) {
			continue;
		}

		/* skip virtual fucntion */
		if (PCI_FUNC(pdev->devfn)) {
			continue;
		}

		/* found new device */
		mst_info("found device - "
				"domain=0x%x, bus=0x%x, slot=0x%x, func=0x%x, vendor=0x%x, device=0x%x\n",
				pci_domain_nr(pdev->bus),
				pdev->bus->number,
				PCI_SLOT(pdev->devfn),
				PCI_FUNC(pdev->devfn),
				pdev->vendor,
				pdev->device);

		/* create PCICONF for this device */
		dev = mst_device_create(PCICONF, pdev);
		if (!dev) {
			mst_err("failed to mst_device_create\n");
			continue; /* PCICONF creation failed, no point creating a PCIMEM device */
		}

		/*
		 * for livefish devices we only allocate PCICONF
		 * for non livefish both PCICONF and PCIMEM
		 */
		if (!pci_match_id(mst_livefish_pci_table, pdev)) {
			/* create new mst_device for PCIMEM */
			dev = mst_device_create(PCIMEM, pdev);
			if (!dev) {
				mst_err("failed to mst_device_create\n");
				continue;
			}
		}
	}

	return 0;
}

static void __exit mst_cleanup(void)
{
	struct mst_dev_data *cur, *temp;

	/* free all mst_devices */
	list_for_each_entry_safe(cur, temp, &mst_devices, list) {
		mst_device_destroy(cur);
	}
}


/****************************************************/
module_init(mst_init);
module_exit(mst_cleanup);
