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
	printk(KERN_ERR "%s: %s %d: " format, MST_PREFIX, __func__, __LINE__, ## arg)
#define mst_info(format, arg...)	\
	printk(KERN_INFO "%s: %s %d: " format, MST_PREFIX, __func__, __LINE__, ## arg)


/****************************************************/
/* new types */
enum dev_type {
	PCICONF,
	PCIMEM
};

struct mst_dev_data {
	int					addr_reg;				/* PCICONF address register */
	int					data_reg;				/* PCICONF data register */
    int                 wo_addr;
	unsigned int		bar;					/* PCIMEM bar */
	void				*hw_addr;				/* PCIMEM memory start */
	char				name[MST_NAME_SIZE];	/* name of character device */
	enum dev_type		type;					/* type of device */
	struct pci_dev		*pci_dev;				/* device pci struct in kernel */
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
};


/****************************************************/
int pci_read4_vpd(struct mst_dev_data *dev, unsigned int timeout,
		unsigned offset, u32 *buf);

int pci_write4_vpd(struct mst_dev_data *dev, unsigned int timeout,
		unsigned offset, u32 buf);


#endif	/* _MST_KERNEL_H_ */


