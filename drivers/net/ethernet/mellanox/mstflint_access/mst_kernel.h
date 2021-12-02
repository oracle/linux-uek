/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2018-2021 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 */

#ifndef _MST_KERNEL_H_
#define _MST_KERNEL_H_


/****************************************************/
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <asm/uaccess.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/io.h>
#include <linux/byteorder/generic.h>
#include<linux/cdev.h>

#include "mst.h"


/****************************************************/
#define DRV_VERSION		"2.0.0"
#define DRV_RELDATE		"Nov-27-2012"


/****************************************************/
/* defines */
#define MST_NAME_SIZE				30
#define MST_PREFIX					"  MST::  "

#define MST_DEVICE_PREFIX		"mt"
#define MST_PCICONF_DEVICE_NAME     "_mstconf"
#define MST_PCIMEM_DEVICE_NAME      "_mstcr"

#define MST_MELLANOX_PCI_VENDOR		0x15b3

#define MST_CONF_ADDR_REG			88
#define MST_CONF_DATA_REG			92

#define MST_VPD_DEFAULT_TOUT		2000	/* milli seconds */

#define mst_err(format, arg...)	\
	pr_err("%s: %s %d: " format, MST_PREFIX, __func__, __LINE__, ## arg)
#define mst_info(format, arg...)	\
	pr_info("%s: %s %d: " format, MST_PREFIX, __func__, __LINE__, ## arg)

#define capability_support_info_message(dev, capability) \
    mst_info("Device 0x%x (%x:%x:%x.%x) doesn't support %s capability.\n", \
        dev->pci_dev->device,pci_domain_nr(dev->pci_dev->bus), \
        dev->pci_dev->bus->number, PCI_SLOT(dev->pci_dev->devfn), \
        PCI_FUNC(dev->pci_dev->devfn), #capability);



/****************************************************/
/* new types */
enum dev_type {
	PCICONF,
	PCIMEM
};

struct dma_page {
    struct page** page_list;
    dma_addr_t dma_addr[PCICONF_MAX_PAGES_SIZE];
};

struct mst_dev_data {
	int					addr_reg;				/* PCICONF address register */
	int					data_reg;				/* PCICONF data register */
	int                 wo_addr;
	unsigned int		bar;					/* PCIMEM bar */
	void				*hw_addr;				/* PCIMEM memory start */
	char				name[MST_NAME_SIZE];	/* name of character device */
	enum dev_type		type;					/* type of device */
	struct pci_dev      *pci_dev;				/* device pci struct in kernel */
	struct list_head	list;					/* list of mst_devices */
	struct mutex		lock;					/* device lock */
	int					vpd_cap_addr;			/* addr VPD capability */
	int					major;					/* device major number */
	int					initialized;			/* indicate if init done */

	dev_t               my_dev;
	struct cdev         mcdev;
	struct class        *cl;

	unsigned char		connectx_wa_slots;		/* wa for pci bug */
    /* Vendor specific capability address */
	int vendor_specific_cap;
    /* status on VSEC supported spaces*/
	int spaces_support_status;

    // Allocated pages for the user space.
    struct dma_page dma_page;
};


/****************************************************/
int pci_read4_vpd(struct mst_dev_data *dev, unsigned int timeout,
		unsigned int offset, u32 *buf);

int pci_write4_vpd(struct mst_dev_data *dev, unsigned int timeout,
		unsigned int offset, u32 buf);


#endif	/* _MST_KERNEL_H_ */
