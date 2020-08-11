// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2018, Mellanox Technologies inc.  All rights reserved.
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <asm/io.h>
#if KERNEL_VERSION(2, 6, 18) <= LINUX_VERSION_CODE
#include <linux/uaccess.h>
#else
#include <asm/uaccess.h>
#endif
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/delay.h>
#include "mst_kernel.h"

/****************************************************/
MODULE_AUTHOR("Mahmoud Hasan");
MODULE_DESCRIPTION("MST Module");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION " ("DRV_RELDATE")");

/****************************************************/
/* globals variables */
static const char mst_driver_version[] = DRV_VERSION;
static const char mst_driver_string[] =
		"Mellanox Technologies Software Tools Driver";

LIST_HEAD(mst_devices);

static struct pci_device_id mst_livefish_pci_table[] = { { PCI_DEVICE(
		MST_MELLANOX_PCI_VENDOR, 0x01f6) }, /* MT27500 [ConnectX-3 Flash Recovery] */
		{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 0x01f8) }, /* MT27520 [ConnectX-3 Pro Flash Recovery] */
		{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 0x01ff) }, /* MT27520 [ConnectX-IB Flash Recovery] */
		{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 0x0209) }, /* MT27520 [ConnectX-4 Flash Recovery] */
		{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 0x020b) }, /* MT27520 [ConnectX-4Lx Flash Recovery] */
		{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 0x020d) }, /* MT27520 [ConnectX-5 Flash Recovery] */
		{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 0x020f) }, /* MT27520 [ConnectX-6 Flash Recovery] */
		{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 0x0212) }, /* MT27520 [ConnectX-6DX Flash Recovery] */
		{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 0x0211) }, /* MT27520 [BlueField Flash Recovery] */
		{ 0, } };

static struct pci_device_id mst_bar_pci_table[] = { { PCI_DEVICE(
		MST_MELLANOX_PCI_VENDOR, 4099) }, /* MT27600 [ConnectX-3] */
		{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 4103) }, /* MT27600 [ConnectX-3Pro] */
		{ 0, } };

static struct pci_device_id supported_pci_devices[] = { { PCI_DEVICE(
		MST_MELLANOX_PCI_VENDOR, 4099) }, /* MT27600 [ConnectX-3] */
		{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 4103) }, /* MT27600 [ConnectX-3Pro] */
		{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 4113) }, /* MT27600 [ConnectX-IB] */
		{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 4115) }, /* MT27600 [ConnectX-4] */
		{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 4117) }, /* MT27600 [ConnectX-4Lx] */
		{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 4119) }, /* MT27600 [ConnectX-5] */
		{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 4121) }, /* MT27600 [ConnectX-5EX] */
		{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 4123) }, /* MT27600 [ConnectX-6] */
		{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 4125) }, /* MT27600 [ConnectX-6DX] */
		{ PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 41682) }, /* MT27600 [BlueField] */
		{ 0, } };

/****************** VSEC SUPPORT ********************/

// BIT Slicing macros
#define ONES32(size)                    ((size)?(0xffffffff>>(32-(size))):0)
#define MASK32(offset, size)             (ONES32(size)<<(offset))

#define EXTRACT_C(source, offset, size)   ((((unsigned int)(source))>>(offset)) & ONES32(size))
#define EXTRACT(src, start, len)          (((len) == 32)?(src):EXTRACT_C(src, start, len))

#define MERGE_C(rsrc1, rsrc2, start, len)  ((((rsrc2)<<(start)) & (MASK32((start), (len)))) | ((rsrc1) & (~MASK32((start), (len)))))
#define MERGE(rsrc1, rsrc2, start, len)    (((len) == 32)?(rsrc2):MERGE_C(rsrc1, rsrc2, start, len))

/* Allow minor numbers 0-255 */
#define MAXMINOR 256
#define BUFFER_SIZE 256
#define MLNX_VENDOR_SPECIFIC_CAP_ID 0x9
#define CRSPACE_DOMAIN 0x2
#define AS_ICMD      0x3
#define AS_CR_SPACE  0x2
#define AS_SEMAPHORE 0xa

/* PCI address space related enum*/
enum {
	PCI_CAP_PTR = 0x34, PCI_HDR_SIZE = 0x40, PCI_EXT_SPACE_ADDR = 0xff,

	PCI_CTRL_OFFSET = 0x4, // for space / semaphore / auto-increment bit
	PCI_COUNTER_OFFSET = 0x8,
	PCI_SEMAPHORE_OFFSET = 0xc,
	PCI_ADDR_OFFSET = 0x10,
	PCI_DATA_OFFSET = 0x14,

	PCI_FLAG_BIT_OFFS = 31,

	PCI_SPACE_BIT_OFFS = 0,
	PCI_SPACE_BIT_LEN = 16,

	PCI_STATUS_BIT_OFFS = 29,
	PCI_STATUS_BIT_LEN = 3,
};

/* Mellanox vendor specific enum */
enum {
	CAP_ID = 0x9, IFC_MAX_RETRIES = 0x10000, SEM_MAX_RETRIES = 0x1000
};

/* PCI operation enum(read or write)*/
enum {
	READ_OP = 0, WRITE_OP = 1,
};

/* VSEC space status enum*/
enum {
	SS_UNINITIALIZED = 0,
	SS_ALL_SPACES_SUPPORTED = 1,
	SS_NOT_ALL_SPACES_SUPPORTED = 2
};

// VSEC supported macro
#define VSEC_FULLY_SUPPORTED(dev) (((dev)->vendor_specific_cap) && ((dev)->spaces_support_status == SS_ALL_SPACES_SUPPORTED))

static int _vendor_specific_sem(struct mst_dev_data *dev, int state)
{
	u32 lock_val;
	u32 counter = 0;
	int retries = 0;
	int ret;

	if (!state) { // unlock
		ret = pci_write_config_dword(dev->pci_dev,
				dev->vendor_specific_cap + PCI_SEMAPHORE_OFFSET, 0);
		if (ret)
			return ret;
	} else { // lock
		do {
			if (retries > SEM_MAX_RETRIES)
				return -1;
			// read semaphore untill 0x0
			ret = pci_read_config_dword(dev->pci_dev,
					dev->vendor_specific_cap + PCI_SEMAPHORE_OFFSET, &lock_val);
			if (ret)
				return ret;

			if (lock_val) { //semaphore is taken
				retries++;
				udelay(1000); // wait for current op to end
				continue;
			}
			//read ticket
			ret = pci_read_config_dword(dev->pci_dev,
					dev->vendor_specific_cap + PCI_COUNTER_OFFSET, &counter);
			if (ret)
				return ret;
			//write ticket to semaphore dword
			ret = pci_write_config_dword(dev->pci_dev,
					dev->vendor_specific_cap + PCI_SEMAPHORE_OFFSET, counter);
			if (ret)
				return ret;
			// read back semaphore make sure ticket == semaphore else repeat
			ret = pci_read_config_dword(dev->pci_dev,
					dev->vendor_specific_cap + PCI_SEMAPHORE_OFFSET, &lock_val);
			if (ret)
				return ret;
			retries++;
		} while (counter != lock_val);
	}
	return 0;
}

static int _wait_on_flag(struct mst_dev_data *dev, u8 expected_val)
{
	int retries = 0;
	int ret;
	u32 flag;

	do {
		if (retries > IFC_MAX_RETRIES)
			return -1;

		ret = pci_read_config_dword(dev->pci_dev,
				dev->vendor_specific_cap + PCI_ADDR_OFFSET, &flag);
		if (ret)
			return ret;

		flag = EXTRACT(flag, PCI_FLAG_BIT_OFFS, 1);
		retries++;
		if ((retries & 0xf) == 0) { // dont sleep always
			//usleep_range(1,5);
		}
	} while (flag != expected_val);
	return 0;
}

static int _set_addr_space(struct mst_dev_data *dev, u16 space)
{
	// read modify write
	u32 val;
	int ret;

	ret = pci_read_config_dword(dev->pci_dev,
			dev->vendor_specific_cap + PCI_CTRL_OFFSET, &val);
	if (ret)
		return ret;
	val = MERGE(val, space, PCI_SPACE_BIT_OFFS, PCI_SPACE_BIT_LEN);
	ret = pci_write_config_dword(dev->pci_dev,
			dev->vendor_specific_cap + PCI_CTRL_OFFSET, val);
	if (ret)
		return ret;
	// read status and make sure space is supported
	ret = pci_read_config_dword(dev->pci_dev,
			dev->vendor_specific_cap + PCI_CTRL_OFFSET, &val);
	if (ret)
		return ret;

	if (EXTRACT(val, PCI_STATUS_BIT_OFFS, PCI_STATUS_BIT_LEN) == 0) {
		//      mst_err("CRSPACE %d is not supported !\n", space);
		return -1;
	}
	//  mst_err("CRSPACE %d is supported !\n", space);
	return 0;
}

static int _pciconf_rw(struct mst_dev_data *dev, unsigned int offset, u32 *data,
		int rw)
{
	int ret = 0;
	u32 address = offset;

	//last 2 bits must be zero as we only allow 30 bits addresses
	if (EXTRACT(address, 30, 2))
		return -1;

	address = MERGE(address, (rw ? 1 : 0), PCI_FLAG_BIT_OFFS, 1);
	if (rw == WRITE_OP) {
		// write data
		ret = pci_write_config_dword(dev->pci_dev,
				dev->vendor_specific_cap + PCI_DATA_OFFSET, *data);
		if (ret)
			return ret;
		// write address
		ret = pci_write_config_dword(dev->pci_dev,
				dev->vendor_specific_cap + PCI_ADDR_OFFSET, address);
		if (ret)
			return ret;
		// wait on flag
		ret = _wait_on_flag(dev, 0);
	} else {
		// write address
		ret = pci_write_config_dword(dev->pci_dev,
				dev->vendor_specific_cap + PCI_ADDR_OFFSET, address);
		if (ret)
			return ret;
		// wait on flag
		ret = _wait_on_flag(dev, 1);
		// read data
		ret = pci_read_config_dword(dev->pci_dev,
				dev->vendor_specific_cap + PCI_DATA_OFFSET, data);
		if (ret)
			return ret;
	}
	return ret;
}

static int _send_pci_cmd_int(struct mst_dev_data *dev, int space,
		unsigned int offset, u32 *data, int rw)
{
	int ret = 0;

	// take semaphore
	ret = _vendor_specific_sem(dev, 1);
	if (ret)
		return ret;
	// set address space
	ret = _set_addr_space(dev, space);
	if (ret)
		goto cleanup;
	// read/write the data
	ret = _pciconf_rw(dev, offset, data, rw);
cleanup:
	// clear semaphore
	_vendor_specific_sem(dev, 0);
	return ret;
}

static int _block_op(struct mst_dev_data *dev, int space, unsigned int offset,
		int size, u32 *data, int rw)
{
	int i;
	int ret = 0;
	int wrote_or_read = size;

	if (size % 4)
		return -1;
	// lock semaphore and set address space
	ret = _vendor_specific_sem(dev, 1);
	if (ret)
		return -1;
	// set address space
	ret = _set_addr_space(dev, space);
	if (ret) {
		wrote_or_read = -1;
		goto cleanup;
	}

	for (i = 0; i < size; i += 4) {
		if (_pciconf_rw(dev, offset + i, &(data[(i >> 2)]), rw)) {
			wrote_or_read = i;
			goto cleanup;
		}
	}
cleanup:
	_vendor_specific_sem(dev, 0);
	return wrote_or_read;
}

static int write4_vsec(struct mst_dev_data *dev, int addresss_domain,
		unsigned int offset, unsigned int data)
{
	int ret;

	ret = _send_pci_cmd_int(dev, addresss_domain, offset, &data, WRITE_OP);
	if (ret)
		return -1;
	return 0;
}

static int read4_vsec(struct mst_dev_data *dev, int address_space,
		unsigned int offset, unsigned int *data)
{
	int ret;
	//mst_info("Read from VSEC: offset: %#x\n", offset);
	ret = _send_pci_cmd_int(dev, address_space, offset, data, READ_OP);
	if (ret)
		return -1;
	return 0;
}

static int pciconf_read4_legacy(struct mst_dev_data *dev, unsigned int offset,
		unsigned int *data)
{
	int res = 0;
	unsigned int new_offset = offset;
	//mst_info("pciconf_read4_legacy: offset: %#x\n", offset);
	if (dev->type != PCICONF)
		return -1;
	if (dev->wo_addr)
		new_offset |= 0x1;
	/* write the wanted address to addr register */
	res = pci_write_config_dword(dev->pci_dev, dev->addr_reg, new_offset);
	if (res) {
		mst_err("pci_write_config_dword failed\n");
		return res;
	}

	/* read the result from data register */
	res = pci_read_config_dword(dev->pci_dev, dev->data_reg, data);
	if (res) {
		mst_err("pci_read_config_dword failed\n");
		return res;
	}
	return 0;
}

static int pciconf_write4_legacy(struct mst_dev_data *dev, unsigned int offset,
		unsigned int data)
{
	int res = 0;

	if (dev->type != PCICONF)
		return -1;
	if (dev->wo_addr) {
		/*
		 * Write operation with new WO GW
		 * 1. Write data
		 * 2. Write address
		 */

		/* write the data to data register */
		res = pci_write_config_dword(dev->pci_dev, dev->data_reg, data);
		if (res) {
			mst_err("pci_write_config_dword failed\n");
			return res;
		}
		/* write the destination address to addr register */
		res = pci_write_config_dword(dev->pci_dev, dev->addr_reg, offset);
		if (res) {
			mst_err("pci_write_config_dword failed\n");
			return res;
		}

	} else {
		/* write the destination address to addr register */
		res = pci_write_config_dword(dev->pci_dev, dev->addr_reg, offset);
		if (res) {
			mst_err("pci_write_conflig_dword failed\n");
			return res;
		}

		/* write the data to data register */
		res = pci_write_config_dword(dev->pci_dev, dev->data_reg, data);
		if (res) {
			mst_err("pci_write_config_dword failed\n");
			return res;
		}
	}
	return 0;
}

static int write4_block_vsec(struct mst_dev_data *dev, int address_space,
		unsigned int offset, int size, u32 *data)
{
	//    mst_info("HERE %#x %#x %#x\n", address_space, offset, *data);
	return _block_op(dev, address_space, offset, size, data, WRITE_OP);
}

static int read4_block_vsec(struct mst_dev_data *dev, int address_space,
		unsigned int offset, int size, u32 *data)
{
	//    mst_info("HERE %#x %#x %#x\n", address_space, offset, *data);
	return _block_op(dev, address_space, offset, size, data, READ_OP);
}

static int get_space_support_status(struct mst_dev_data *dev)
{
	int ret;
	//    printk("[MST] Checking if the Vendor CAP %d supports the SPACES in devices\n", vend_cap);
	if ((!dev->vendor_specific_cap) || (!dev->pci_dev))
		return 0;
	if (dev->spaces_support_status != SS_UNINITIALIZED)
		return 0;
	// take semaphore
	ret = _vendor_specific_sem(dev, 1);
	if (ret) {
		mst_err("Failed to lock VSEC semaphore\n");
		return 1;
	}

    if (_set_addr_space(dev, AS_CR_SPACE)) {
        capability_support_info_message(dev, CR_SPACE);
        dev->spaces_support_status = SS_NOT_ALL_SPACES_SUPPORTED;
    }
    else if (_set_addr_space(dev, AS_ICMD)) {
        capability_support_info_message(dev, ICMD);
        dev->spaces_support_status = SS_NOT_ALL_SPACES_SUPPORTED;
	}
    else if (_set_addr_space(dev, AS_SEMAPHORE)) {
        capability_support_info_message(dev, SEMAPHORE);
		dev->spaces_support_status = SS_NOT_ALL_SPACES_SUPPORTED;
	} else {
		dev->spaces_support_status = SS_ALL_SPACES_SUPPORTED;
	}

	// clear semaphore
	_vendor_specific_sem(dev, 0);
	return 0;
}

/********** WO GW ************/

#define WO_REG_ADDR_DATA 0xbadacce5
#define DEVID_OFFSET     0xf0014
static int is_wo_gw(struct pci_dev *pcidev, unsigned int addr_reg)
{
	int ret;
	unsigned int data = 0;

	ret = pci_write_config_dword(pcidev, addr_reg, DEVID_OFFSET);
	if (ret)
		return 0;
	ret = pci_read_config_dword(pcidev, addr_reg, &data);
	if (ret)
		return 0;
	if (data == WO_REG_ADDR_DATA)
		return 1;
	return 0;
}

/****************************************************/
static int mst_open(struct inode *inode, struct file *file)
{
	struct mst_file_data *md = NULL;

	md = kmalloc(sizeof(struct mst_connectx_wa), GFP_KERNEL);
	if (!md)
		return -ERESTARTSYS;

	memset(md, 0, sizeof(struct mst_connectx_wa));

	file->private_data = md;

	return 0;
}

/****************************************************/
static int mst_release(struct inode *inode, struct file *file)
{
	int res = 0;
	struct mst_dev_data *dev = NULL;
	struct mst_dev_data *cur = NULL;
	unsigned int slot_mask;
	struct mst_connectx_wa *md = file->private_data;

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
	 *			md->connectx_wa_slot_p1 - 1, dev->connectx_wa_slots);
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
	mst_info("PCIMEM_READ4=%lx\n", PCIMEM_READ4);
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

	int res = 0;
	struct mst_dev_data *dev = NULL;
	struct mst_dev_data *cur = NULL;
	void *user_buf = (void *) input;

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
		// best effort : try to get space spport status if we fail assume we got vsec support.
		get_space_support_status(dev);
		paramst.domain = pci_domain_nr(dev->pci_dev->bus);
		paramst.bus = dev->pci_dev->bus->number;
		paramst.slot = PCI_SLOT(dev->pci_dev->devfn);
		paramst.func = PCI_FUNC(dev->pci_dev->devfn);
		paramst.bar = dev->bar;
		paramst.device = dev->pci_dev->device;
		paramst.vendor = dev->pci_dev->vendor;
		paramst.subsystem_device = dev->pci_dev->subsystem_device;
		paramst.subsystem_vendor = dev->pci_dev->subsystem_vendor;
		if (dev->vendor_specific_cap &&
				(dev->spaces_support_status == SS_ALL_SPACES_SUPPORTED ||
						dev->spaces_support_status == SS_UNINITIALIZED)) {
			// assume supported if SS_UNINITIALIZED (since semaphore is locked)
			paramst.vendor_specific_cap = dev->vendor_specific_cap;
		} else {
			paramst.vendor_specific_cap = 0;
		}
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
			if (get_space_support_status(dev)) {
				res = -EBUSY;
				goto fin;
			}

			if (VSEC_FULLY_SUPPORTED(dev))
				res = read4_vsec(dev, readst.address_space, readst.offset, &out);
			else
				res = pciconf_read4_legacy(dev, readst.offset, &out);
			if (res)
				goto fin;
			break;

		case PCIMEM:
			if ((readst.offset + sizeof(u32)) > MST_MEMORY_SIZE) {
				mst_err("accessing invalid address\n");
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
			if (get_space_support_status(dev)) {
				res = -EBUSY;
				goto fin;
			}
			if (VSEC_FULLY_SUPPORTED(dev))
				res = write4_vsec(dev, writest.address_space, writest.offset, writest.data);
			else
				res = pciconf_write4_legacy(dev, writest.offset, writest.data);
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
		int i = 0;
		u32 *data = NULL;
		u32 *dataout = NULL;
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
			mst_err("invalid size. size should be in bytes and divide sizeof(u32)\n");
			res = -EINVAL;
			goto fin;
		}

		if ((readst.offset + readst.size) > MST_MEMORY_SIZE) {
			mst_err("accessing invalid address\n");
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
			mst_err("invalid size. size should be in bytes and divide sizeof(u32)\n");
			res = -EINVAL;
			goto fin;
		}

		if ((writest.offset + writest.size) > MST_MEMORY_SIZE) {
			mst_err("accessing invalid address\n");
			res = -EINVAL;
			goto fin;
		}

		/* endianness conversion */
		for (i = 0; i < (writest.size / sizeof(u32)); ++i)
			cpu_to_be32s(&(writest.data[i]));

		/* write to hardware */
		memcpy_toio(dev->hw_addr + writest.offset, writest.data, writest.size);

		break;
	}

	case PCICONF_READ4_BUFFER:
	{
		struct mst_read4_buffer_st read4_buf;
		struct mst_read4_buffer_st *rb_udata = (struct mst_read4_buffer_st *)user_buf;

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

		if (get_space_support_status(dev)) {
			res = -EBUSY;
			goto fin;
		}

		if (dev->spaces_support_status != SS_ALL_SPACES_SUPPORTED) {
			res = -EOPNOTSUPP;
			goto fin;
		}

		if (copy_from_user(&read4_buf, user_buf, sizeof(read4_buf))) {
			res = -EFAULT;
			goto fin;
		}

		res = read4_block_vsec(dev, read4_buf.address_space, read4_buf.offset, read4_buf.size, read4_buf.data);
		if (res != read4_buf.size)
			goto fin;

		res = copy_to_user(rb_udata, &read4_buf, sizeof(read4_buf)) ? -EFAULT : read4_buf.size;
		goto fin;
	}
	case PCICONF_WRITE4_BUFFER:
	{
		struct mst_write4_buffer_st write4_buf;
		struct mst_write4_buffer_st *wb_udata = (struct mst_write4_buffer_st *)user_buf;

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

		if (get_space_support_status(dev)) {
			res = -EBUSY;
			goto fin;
		}

		if (dev->spaces_support_status != SS_ALL_SPACES_SUPPORTED) {
			res = -EOPNOTSUPP;
			goto fin;
		}

		if (copy_from_user(&write4_buf, user_buf, sizeof(write4_buf))) {
			res = -EFAULT;
			goto fin;
		}

		res = write4_block_vsec(dev, write4_buf.address_space, write4_buf.offset, write4_buf.size, write4_buf.data);
		if (res != write4_buf.size)
			goto fin;

		res = copy_to_user(wb_udata, &write4_buf, sizeof(write4_buf)) ? -EFAULT : write4_buf.size;
		goto fin;
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

		dev->wo_addr = is_wo_gw(dev->pci_dev, initst.addr_reg);
		dev->vendor_specific_cap = pci_find_capability(dev->pci_dev,
				MLNX_VENDOR_SPECIFIC_CAP_ID);
		//mst_info("VSEC SUPP: %#x\n", dev->vendor_specific_cap);
		dev->spaces_support_status = SS_UNINITIALIZED; // init on first op

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

		if (!dev->hw_addr) {
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
		 *			md->connectx_wa_slot_p1 - 1, dev->connectx_wa_slots);
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
		if (res)
			goto fin;

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
		if (res)
			goto fin;
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
static long compat_ioctl(struct file *f, unsigned int o, unsigned long d)
{
#if KERNEL_VERSION(3, 18, 0) > LINUX_VERSION_CODE
	struct inode *n = f->f_dentry->d_inode;
#else
	struct inode *n = f->f_path.dentry->d_inode;
#endif
	return mst_ioctl(n, f, o, d);
}
#endif

#ifdef HAVE_UNLOCKED_IOCTL
static long unlocked_ioctl(struct file *f, unsigned int o, unsigned long d)
{
#if KERNEL_VERSION(3, 18, 0) > LINUX_VERSION_CODE
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
static const struct file_operations mst_fops = { .read = mst_read, .write =
		mst_write,

#ifdef HAVE_UNLOCKED_IOCTL
		.unlocked_ioctl = unlocked_ioctl,
#endif

#if KERNEL_VERSION(2, 6, 35) > LINUX_VERSION_CODE
		.ioctl = mst_ioctl,
#endif

#if HAVE_COMPAT_IOCTL
		.compat_ioctl = compat_ioctl,
#endif

		.open = mst_open, .release = mst_release, .owner = THIS_MODULE, };

static struct mst_dev_data *mst_device_create(enum dev_type type,
		struct pci_dev *pdev)
{
	struct mst_dev_data *dev = NULL;
	char dbdf[20];

	dev = kzalloc(sizeof(struct mst_dev_data), GFP_KERNEL);
	if (!dev)
		return NULL;

	sprintf(dbdf, "%4.4x:%2.2x:%2.2x.%1.1x", pci_domain_nr(pdev->bus),
			pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
	switch (type) {
	case PCICONF:
		dev->addr_reg = MST_CONF_ADDR_REG;
		dev->data_reg = MST_CONF_DATA_REG;
		dev->bar = 0; /* invalid */
		dev->hw_addr = NULL; /* invalid */
		snprintf(dev->name,
				MST_NAME_SIZE, "%s" MST_PCICONF_DEVICE_NAME, dbdf);

		break;
	case PCIMEM:
		dev->addr_reg = 0; /* invalid */
		dev->data_reg = 0; /* invalid */
		dev->bar = 0;
		dev->hw_addr = ioremap(pci_resource_start(pdev, dev->bar),
				MST_MEMORY_SIZE);
		if (!dev->hw_addr) {
			mst_err("could not map device memory, BAR: %x\n", dev->bar);
			goto out;
		}

		snprintf(dev->name,
				MST_NAME_SIZE, "%s" MST_PCIMEM_DEVICE_NAME, dbdf);
		break;
	default:
		mst_err("failed to %s, unknown device type 0x%x\n",
				__func__, dev->type);
		goto out;
	}

	dev->type = type;
	dev->pci_dev = pdev;
	mutex_init(&dev->lock);

	dev->vpd_cap_addr = pci_find_capability(pdev, PCI_CAP_ID_VPD);

	if (alloc_chrdev_region(&dev->my_dev, 0, 1, dev->name))
		mst_err("failed to allocate chrdev_region\n");
	dev->cl = class_create(dev->name);
	if (dev->cl == NULL) {
		pr_alert("Class creation failed\n");
		unregister_chrdev_region(dev->my_dev, 1);
		goto out;
	}

	if (device_create(dev->cl, NULL, dev->my_dev, NULL, dev->name) == NULL) {
		pr_alert("Device creation failed\n");
		class_destroy(dev->cl);
		unregister_chrdev_region(dev->my_dev, 1);
		goto out;
	}

	dev->major = MAJOR(dev->my_dev);
	cdev_init(&dev->mcdev, &mst_fops);
	cdev_add(&dev->mcdev, dev->my_dev, 1); //TODO check if cdev_add fails

	if (type == PCICONF) {
		/*
		 * Initialize 5th Gen attributes
		 */
		dev->wo_addr = is_wo_gw(dev->pci_dev, MST_CONF_ADDR_REG);
		dev->vendor_specific_cap = pci_find_capability(dev->pci_dev,
				MLNX_VENDOR_SPECIFIC_CAP_ID);
		//mst_info("VSEC SUPP: %#x\n", dev->vendor_specific_cap);
		dev->spaces_support_status = SS_UNINITIALIZED; // init on first op
	}
	dev->initialized = 1;
	list_add_tail(&dev->list, &mst_devices);

	return dev;
out:
	kfree(dev);
	return NULL;
}

static void mst_device_destroy(struct mst_dev_data *dev)
{
	if (dev->hw_addr)
		iounmap(dev->hw_addr);

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
	struct pci_dev  *pdev		= NULL;
	struct mst_dev_data *dev	= NULL;

	mst_info("%s - version %s\n", mst_driver_string, mst_driver_version);

	while ((pdev = pci_get_device(MST_MELLANOX_PCI_VENDOR, PCI_ANY_ID, pdev)) != NULL) {
		if (!pci_match_id(supported_pci_devices, pdev) && !pci_match_id(mst_livefish_pci_table, pdev))
			continue;

		if (pdev->is_virtfn)
		    continue;

		/* found new device */
		mst_info(
				"found device - domain=0x%x, bus=0x%x, slot=0x%x, func=0x%x, vendor=0x%x, device=0x%x\n",
				pci_domain_nr(pdev->bus), pdev->bus->number, PCI_SLOT(pdev->devfn),
				PCI_FUNC(pdev->devfn), pdev->vendor, pdev->device);

		/* create PCICONF for this device */
		dev = mst_device_create(PCICONF, pdev);
		if (!dev)
			mst_err("failed to mst_device_create\n"); continue; /* PCICONF creation failed, no point creating a PCIMEM device */

		/*
		 * for livefish devices we only allocate PCICONF
		 * for non livefish both PCICONF and PCIMEM
		 */
		if (!pci_match_id(mst_livefish_pci_table, pdev) && pci_match_id(mst_bar_pci_table, pdev)) {
			/* create new mst_device for PCIMEM */
			dev = mst_device_create(PCIMEM, pdev);
			if (!dev) {
				mst_err(
						"failed to mst_device_create\n");
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
