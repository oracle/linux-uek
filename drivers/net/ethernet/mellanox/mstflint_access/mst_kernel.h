/*
 * Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
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
#include <linux/cdev.h>

#include "mst.h"

/****************************************************/
#define DRV_VERSION "2.0.0"
#define DRV_RELDATE "Nov-27-2012"

/****************************************************/
/* defines */
#define MST_NAME_SIZE 30
#define MST_PREFIX "  MST::  "

#define MST_DEVICE_PREFIX "mt"
#define MST_PCICONF_DEVICE_NAME "_mstconf"
#define MST_PCIMEM_DEVICE_NAME "_mstcr"

#define MST_MELLANOX_PCI_VENDOR 0x15b3

#define MST_CONF_ADDR_REG 88
#define MST_CONF_DATA_REG 92

#define FUNCTIONAL_VSC 0
#define RECOVERY_VSC 2
#define RECOVERY_VSC_OFFSET_IN_CONFIG_SPACE 0x54 // Agreed with FW to keep the VSC offset always in 0x54 in recovery mode(LF/Late LF in CX8,QTM3 and above)

#define ADDRESS_OUT_OF_RANGE 0x3 // syndrome_code value

#define MST_VPD_DEFAULT_TOUT 2000 /* milli seconds */

#define mst_err(format, arg...) pr_err("%s: %s %d: " format, MST_PREFIX, __func__, __LINE__, ##arg)
#define mst_info(format, arg...) pr_info("%s: %s %d: " format, MST_PREFIX, __func__, __LINE__, ##arg)

#define capability_support_info_message(dev, capability)                                                 \
    mst_info("Device 0x%x (%x:%x:%x.%x) doesn't support %s capability.\n", dev->pci_dev->device,         \
             pci_domain_nr(dev->pci_dev->bus), dev->pci_dev->bus->number, PCI_SLOT(dev->pci_dev->devfn), \
             PCI_FUNC(dev->pci_dev->devfn), #capability);

#define CHECK_PCI_READ_ERROR(error, address) \
        if (error) { \
                printk(KERN_ERR "Failed to read from address: %x\n", address); \
                goto ReturnOnFinished; \
        }

#define CHECK_PCI_WRITE_ERROR(error, address, data) \
        if (error) { \
                printk(KERN_ERR "Failed to write to address: %x, data: %x\n", address, data); \
                goto ReturnOnFinished; \
        }

#define CHECK_ERROR(error) \
    if (error) { \
            goto ReturnOnFinished; \
    }

/****************************************************/
/* new types */
enum dev_type
{
    PCICONF,
    PCIMEM
};

struct dma_page
{
    struct page** page_list;
    dma_addr_t dma_addr[PCICONF_MAX_PAGES_SIZE];
};

struct mst_dev_data
{
    int addr_reg; /* PCICONF address register */
    int data_reg; /* PCICONF data register */
    int wo_addr;
    unsigned int bar;         /* PCIMEM bar */
    void* hw_addr;            /* PCIMEM memory start */
    char name[MST_NAME_SIZE]; /* name of character device */
    enum dev_type type;       /* type of device */
    struct pci_dev* pci_dev;  /* device pci struct in kernel */
    struct list_head list;    /* list of mst_devices */
    struct mutex lock;        /* device lock */
    int vpd_cap_addr;         /* addr VPD capability */
    int major;                /* device major number */
    int initialized;          /* indicate if init done */

    dev_t my_dev;
    struct cdev mcdev;
    struct class* cl;

    unsigned char connectx_wa_slots; /* wa for pci bug */
                                     /* Vendor specific capability address */
    int functional_vsc_offset;
    unsigned int recovery_vsc_offset; // For LF and Late LF in CX8, QTM3 and above
    /* status on FUNCTIONAL VSC supported spaces*/
    int spaces_support_status;
    int pci_vsec_space_fully_supported; /* For pciconf interface in CX8 and above, where PCI and CORE have different VSC spaces.*/

    // Allocated pages for the user space.
    struct dma_page dma_page;
};

/****************************************************/
int pci_read4_vpd(struct mst_dev_data* dev, unsigned int timeout, unsigned int offset, u32* buf);

int pci_write4_vpd(struct mst_dev_data* dev, unsigned int timeout, unsigned int offset, u32 buf);

#endif /* _MST_KERNEL_H_ */
