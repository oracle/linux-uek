/*
 * Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
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
#if KERNEL_VERSION(2, 6, 18) <= LINUX_VERSION_CODE
#include <linux/uaccess.h>
#else
#include <asm/uaccess.h>
#endif
#include <linux/pci.h>
#include <linux/fs.h>
#include <linux/delay.h>
#include <linux/completion.h>
#include <linux/kthread.h>
#include "mst_kernel.h"

#include <linux/device/class.h>

#if defined(class_create) && !defined(CONFIG_HAVE_CLASS_CREATE_1_ARG)
/* old macro version */
#define MY_CLASS_CREATE(name) class_create(THIS_MODULE, name)
#else
/* new function version */
#define MY_CLASS_CREATE(name) class_create(name)
#endif

/****************************************************/
MODULE_AUTHOR("Mahmoud Hasan");
MODULE_DESCRIPTION("MST Module");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION " (" DRV_RELDATE ")");

/****************************************************/
/* globals variables */
static const char mst_driver_version[] = DRV_VERSION;
static const char mst_driver_string[] = "Mellanox Technologies Software Tools Driver";

/* Forward declarations */
int pci_reset_bus_in_parallel(struct pci_dev* pci_device_prime, struct pci_dev* pci_device_aux);
int nnt_pci_reset_bus_in_parallel(struct pci_dev* pci_device_1, struct pci_dev* pci_device_2);
int hot_reset_pcie_switch(struct hot_reset_pcie_switch* info);
static int hot_reset_thread_fn(void* data);

#define DRIVER_NAME "mstflint_access"
struct reset_thread_data
{
    struct pci_dev* pdev;
    int error;
    struct completion done;
};

LIST_HEAD(mst_devices);

// PCI Device IDs.
#define CONNECTX3_PCI_ID 4099
#define CONNECTX3PRO_PCI_ID 4103
#define CONNECTIB_PCI_ID 4113
#define CONNECTX4_PCI_ID 4115
#define CONNECTX4LX_PCI_ID 4117
#define CONNECTX5_PCI_ID 4119
#define CONNECTX5EX_PCI_ID 4121
#define CONNECTX6_PCI_ID 4123
#define CONNECTX6DX_PCI_ID 4125
#define CONNECTX6LX_PCI_ID 4127
#define CONNECTX7_PCI_ID 4129
#define CONNECTX7_RMA_PCI_ID 537
#define CONNECTX8_PCI_ID 4131
#define CONNECTX8_BRIDGE_PCI_ID 6525
#define CONNECTX9_PCI_ID 4133
#define CONNECTX9_BRIDGE_PCI_ID 6526
#define CONNECTX10_PCI_ID 4135
#define SCHRODINGER_PCI_ID 6518
#define FREYSA_PCI_ID 6521
#define BLUEFIELD_PCI_ID 41682
#define BLUEFIELD2_PCI_ID 41686
#define BLUEFIELD_DPU_AUX_PCI_ID 49873
#define BLUEFIELD3_PCI_ID 41692
#define BLUEFIELD3_RMA_PCI_ID 541
#define BLUEFIELD4_CRYPTO_ENABLED_PCI_ID     41693
#define BLUEFIELD4_CRYPTO_DISABLED_PCI_ID    41694
#define BLUEFIELD4_NETWORK_CONTROLLER_PCI_ID 41695
#define BLUEFIELD4_MANAGMENT_INTERFACE_PCI_ID 49878
#define BLUEFIELD4_PCI_ID 41695
#define SWITCHIB_PCI_ID 52000
#define SWITCHIB2_PCI_ID 53000
#define QUANTUM_PCI_ID 54000
#define QUANTUM2_PCI_ID 54002
#define QUANTUM2_RMA_PCI_ID 600
#define QUANTUM3_PCI_ID 54004
#define QUANTUM3_RMA_PCI_ID 604
#define NVLINK6_SWITCH_PCI_ID 54008
#define NVLINK6_SWITCH_RMA_PCI_ID 633
#define SPECTRUM_PCI_ID 52100
#define SPECTRUM2_PCI_ID 53100
#define SPECTRUM3_PCI_ID 53104
#define SPECTRUM4_PCI_ID 53120
#define SPECTRUM4_RMA_PCI_ID 597
#define SPECTRUM5_PCI_ID 53122
#define SPECTRUM6_PCI_ID 53124
#define GB100_PCI_ID 10496
#define GR100_PCI_ID 12288
#define GR150_PCI_ID 13440

#define LF_SPECTRUM_PCI_ID 0x249
#define LF_SWITCHIB2_PCI_ID 0x24b
#define LF_SWITCHIB_PCI_ID 0x247
#define LF_CONNECTX4_PCI_ID 0x209
#define LF_CONNECTX4LX_PCI_ID 0x20b
#define LF_CONNECTX5_PCI_ID 0x20d
#define LF_CONNECTX6_PCI_ID 0x20f
#define LF_CONNECTX6DX_PCI_ID 0x212
#define LF_CONNECTX6LX_PCI_ID 0x216
#define LF_CONNECTX7_PCI_ID 0x218
#define LF_CONNECTX8_PCI_ID 0x21e
#define LF_CONNECTX9_PCI_ID 0x224
#define LF_CONNECTX9_BRIDGE_PCI_ID 0x228
#define LF_CONNECTX8_BRIDGE_PCI_ID 0x222
#define LF_QUANTUM_PCI_ID 0x24d
#define LF_QUANTUM2_PCI_ID 0x257
#define LF_QUANTUM3_PCI_ID 0x25b
#define LF_NVLINK6_SWITCH_PCI_ID 0x278
#define LF_SPECTRUM2_PCI_ID 0x24e
#define LF_SPECTRUM3_PCI_ID 0x250
#define LF_SPECTRUM4_PCI_ID 0x254
#define LF_SPECTRUM5_PCI_ID 0x270
#define LF_SPECTRUM6_PCI_ID 0x274
#define LF_SPECTRUM6_IB_PCI_ID 0x276
#define LF_BLUEFIELD_PCI_ID 0x211
#define LF_BLUEFIELD2_PCI_ID 0x214
#define LF_BLUEFIELD3_PCI_ID 0x21c
#define LF_BLUEFIELD4_PCI_ID 0x220

static struct pci_device_id mst_livefish_pci_table[] = {{PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_SPECTRUM_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_SWITCHIB2_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_SWITCHIB_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_CONNECTX4_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_CONNECTX4LX_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_CONNECTX5_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_CONNECTX6_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_CONNECTX6DX_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_CONNECTX6LX_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_CONNECTX7_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_CONNECTX8_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_CONNECTX8_BRIDGE_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_CONNECTX9_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_CONNECTX9_BRIDGE_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_QUANTUM_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_QUANTUM2_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_QUANTUM3_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_NVLINK6_SWITCH_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_SPECTRUM2_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_SPECTRUM3_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_SPECTRUM4_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_SPECTRUM5_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_SPECTRUM6_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_SPECTRUM6_IB_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_BLUEFIELD_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_BLUEFIELD2_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_BLUEFIELD3_PCI_ID)},
                                                        {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, LF_BLUEFIELD4_PCI_ID)},
                                                        {0}};

static struct pci_device_id mst_bar_pci_table[] = {{PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 4099)}, /* MT 27600 [ConnectX-3] */
                                                   {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, 4103)}, /* MT27600 [ConnectX-3Pro] */
                                                   {
                                                     0,
                                                   }};

static struct pci_device_id supported_pci_devices[] = {{PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, CONNECTX3_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, CONNECTX3PRO_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, CONNECTIB_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, CONNECTX4_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, CONNECTX4LX_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, CONNECTX5_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, CONNECTX5EX_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, CONNECTX6_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, CONNECTX6DX_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, CONNECTX6LX_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, CONNECTX7_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, CONNECTX7_RMA_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, CONNECTX8_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, CONNECTX8_BRIDGE_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, CONNECTX9_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, CONNECTX9_BRIDGE_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, CONNECTX10_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, SCHRODINGER_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, FREYSA_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, CONNECTX8_BRIDGE_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, BLUEFIELD_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, BLUEFIELD2_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, BLUEFIELD_DPU_AUX_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, BLUEFIELD3_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, BLUEFIELD3_RMA_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, BLUEFIELD4_CRYPTO_ENABLED_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, BLUEFIELD4_CRYPTO_DISABLED_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, BLUEFIELD4_NETWORK_CONTROLLER_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, BLUEFIELD4_MANAGMENT_INTERFACE_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, SWITCHIB_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, SWITCHIB2_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, QUANTUM_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, QUANTUM2_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, QUANTUM2_RMA_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, QUANTUM3_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, QUANTUM3_RMA_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, NVLINK6_SWITCH_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, NVLINK6_SWITCH_RMA_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, SPECTRUM_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, SPECTRUM2_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, SPECTRUM3_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, SPECTRUM4_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, SPECTRUM4_RMA_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, SPECTRUM5_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, SPECTRUM6_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, GB100_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, GR100_PCI_ID)},
                                                       {PCI_DEVICE(MST_MELLANOX_PCI_VENDOR, GR150_PCI_ID)},
                                                       {0}};

/****************** VSEC SUPPORT ********************/

/* BIT Slicing macros */
#define ONES32(size) ((size) ? (0xffffffff >> (32 - (size))) : 0)
#define MASK32(offset, size) (ONES32(size) << (offset))

#define EXTRACT_C(source, offset, size) ((((unsigned int)(source)) >> (offset)) & ONES32(size))
#define EXTRACT(src, start, len) (((len) == 32) ? (src) : EXTRACT_C(src, start, len))

#define MERGE_C(rsrc1, rsrc2, start, len) ((((rsrc2) << (start)) & (MASK32((start), (len)))) | ((rsrc1) & (~MASK32((start), (len)))))
#define MERGE(rsrc1, rsrc2, start, len) (((len) == 32) ? (rsrc2) : MERGE_C(rsrc1, rsrc2, start, len))

/* Allow minor numbers 0-255 */
#define MAXMINOR 256
#define BUFFER_SIZE 256
#define VENDOR_SPECIFIC_CAP_ID 0x9
#define CRSPACE_DOMAIN 0x2

typedef enum
{
    AS_ICMD_EXT = 0x1,
    AS_CR_SPACE = 0x2,
    AS_ICMD = 0x3,
    AS_NODNIC_INIT_SEG = 0x4,
    AS_EXPANSION_ROM = 0x5,
    AS_ND_CRSPACE = 0x6,
    AS_SCAN_CRSPACE = 0x7,
    AS_SEMAPHORE = 0xa,
    AS_RECOVERY = 0Xc,
    AS_MAC = 0xf,
    AS_PCI_ICMD = 0x101,
    AS_PCI_CRSPACE = 0x102,
    AS_PCI_ALL_ICMD = 0x103,
    AS_PCI_SCAN_CRSPACE = 0x107,
    AS_PCI_GLOBAL_SEMAPHORE = 0x10a,
    AS_END
} address_space_t;

/* Mellanox VSC */
#define MLX_VSC_TYPE_OFFSET 24
#define MLX_VSC_TYPE_LEN 8
#define FUNCTIONAL_VSC 0
#define RECOVERY_VSC 2

/* PCI FUNCTIONAL VSC address space related enum*/
enum
{
    PCI_CAP_PTR = 0x34,
    PCI_HDR_SIZE = 0x40,
    PCI_EXT_SPACE_ADDR = 0xff,

    PCI_CTRL_OFFSET = 0x4, /* for space / semaphore / auto-increment bit */
    PCI_COUNTER_OFFSET = 0x8,
    PCI_SEMAPHORE_OFFSET = 0xc,
    PCI_ADDR_OFFSET = 0x10,
    PCI_DATA_OFFSET = 0x14,

    PCI_FLAG_BIT_OFFS = 31,

    PCI_SPACE_BIT_OFFS = 0,
    PCI_SPACE_BIT_LEN = 16,

    PCI_STATUS_BIT_OFFS = 29,
    PCI_STATUS_BIT_LEN = 3,

    PCI_SYNDROME_BIT_OFFSET = 30,
    PCI_SYNDROME_BIT_LEN = 1,
    PCI_SYNDROME_CODE_BIT_OFFSET = 24,
    PCI_SYNDROME_CODE_BIT_LEN = 4,
};

/* Mellanox vendor specific enum */
enum
{
    CAP_ID = 0x9,
    IFC_MAX_RETRIES = 0x10000,
    SEM_MAX_RETRIES = 0x1000
};

/* PCI operation enum(read or write)*/
enum
{
    READ_OP = 0,
    WRITE_OP = 1,
};

/* VSEC space status enum*/
enum
{
    SS_UNINITIALIZED = 0,
    SS_ALL_SPACES_SUPPORTED = 1,
    SS_NOT_ALL_SPACES_SUPPORTED = 2
};

/* VSEC supported macro */
#define VSEC_FULLY_SUPPORTED(dev) (((dev)->functional_vsc_offset) && ((dev)->spaces_support_status == SS_ALL_SPACES_SUPPORTED))

static void swap_pci_address_space(int* address_space)
{
    switch (*address_space)
    {
        case AS_ICMD_EXT:
            *address_space = AS_PCI_ICMD;
            fallthrough;

        case AS_ND_CRSPACE:
            fallthrough;
        case AS_CR_SPACE:
            *address_space = AS_PCI_CRSPACE;
            fallthrough;

        case AS_ICMD:
            *address_space = AS_PCI_ALL_ICMD;
            break;

        case AS_SCAN_CRSPACE:
            *address_space = AS_PCI_SCAN_CRSPACE;
            break;

        case AS_SEMAPHORE:
            *address_space = AS_PCI_GLOBAL_SEMAPHORE;
            break;

        case AS_PCI_ICMD:
            *address_space = AS_ICMD_EXT;
            break;

        case AS_PCI_CRSPACE:
            *address_space = AS_CR_SPACE;
            break;

        case AS_PCI_ALL_ICMD:
            *address_space = AS_ICMD;
            break;

        case AS_PCI_SCAN_CRSPACE:
            *address_space = AS_SCAN_CRSPACE;
            break;

        case AS_PCI_GLOBAL_SEMAPHORE:
            *address_space = AS_SEMAPHORE;
            break;

        default:
            printk(KERN_ERR "MTCR: swap_pci_address_space: no address_space found: %x\n", *address_space);
            return;
    }

    printk(KERN_ERR "address_space swapped to: 0x%x\n", *address_space);
}

int nnt_pci_reset_bus_in_parallel(struct pci_dev* pci_device_1, struct pci_dev* pci_device_2)
{
    int error = 0;
    struct task_struct* thread1 = NULL;
    struct task_struct* thread2 = NULL;
    struct reset_thread_data data1 = {0};
    struct reset_thread_data data2 = {0};

    init_completion(&data1.done);
    init_completion(&data2.done);
    data1.pdev = pci_device_1;
    data2.pdev = pci_device_2;

    thread1 = kthread_create(hot_reset_thread_fn, &data1, "pci_device_1");
    if (IS_ERR(thread1))
    {
        printk(KERN_ERR "%s | Failed to create reset thread 1 (pci_device_1)\n", DRIVER_NAME);
        error = PTR_ERR(thread1);
        goto cleanup;
    }

    thread2 = kthread_create(hot_reset_thread_fn, &data2, "pci_device_2");
    if (IS_ERR(thread2))
    {
        printk(KERN_ERR "%s | Failed to create reset thread 2 (pci_device_2)\n", DRIVER_NAME);
        error = PTR_ERR(thread2);
        goto cleanup;
    }
    wake_up_process(thread1);
    wake_up_process(thread2);

    wait_for_completion(&data1.done);
    wait_for_completion(&data2.done);

    if (data1.error || data2.error)
    {
        error = 1;
    }

cleanup:
    return error;
}

static int nnt_pci_reset_bus(struct pci_dev* pci_device)
{
    int error = 0;
    printk(KERN_INFO "%s | Resetting the PCIe device: %4.4x:%2.2x:%2.2x.%1.1x\n", DRIVER_NAME, pci_domain_nr(pci_device->bus), pci_device->bus->number, PCI_SLOT(pci_device->devfn),
           PCI_FUNC(pci_device->devfn));

#ifdef PCI_DEVICE_DATA
    error = pci_reset_bus(pci_device);
#else
    error = pci_reset_bus(pci_device->bus);
#endif

    if (error)
    {
        printk(KERN_ERR "%s | pci_reset_bus failed with error code: %d, pci device: %4.4x:%2.2x:%2.2x.%1.1x\n", DRIVER_NAME, error, pci_domain_nr(pci_device->bus), pci_device->bus->number,
               PCI_SLOT(pci_device->devfn), PCI_FUNC(pci_device->devfn));
    }
    else
    {
        printk(KERN_INFO "%s | pci_reset_bus succeeded, pci device: %4.4x:%2.2x:%2.2x.%1.1x\n", DRIVER_NAME, pci_domain_nr(pci_device->bus), pci_device->bus->number, PCI_SLOT(pci_device->devfn),
               PCI_FUNC(pci_device->devfn));
    }

    return error;
}

static int hot_reset_thread_fn(void* data)
{
    struct reset_thread_data* thread_data = (struct reset_thread_data*)data;
    struct pci_dev* pci_device = thread_data->pdev;
    int error = 0;

    error = nnt_pci_reset_bus(pci_device);

    thread_data->error = error;
    complete(&thread_data->done);
    return 0;
}

int hot_reset_pcie_switch(struct hot_reset_pcie_switch* info)
{
    struct pci_dev* pdev_bus_device_1;
    struct pci_dev* pdev_bus_device_2;

    printk(KERN_INFO "%s | got hot reset ioctl request\n", DRIVER_NAME);
    printk(KERN_INFO "%s | device_1: %4.4x:%2.2x:%2.2x.%1.1x\n", DRIVER_NAME, info->device_1.domain, info->device_1.bus, info->device_1.device, info->device_1.function);
    if (info->in_parallel)
    {
        printk(KERN_INFO "%s | device_2: %4.4x:%2.2x:%2.2x.%1.1x\n", DRIVER_NAME, info->device_2.domain, info->device_2.bus, info->device_2.device, info->device_2.function);
    }

    // Retrieve the PCI device corresponding to info.bus
    pdev_bus_device_1 = pci_get_domain_bus_and_slot(info->device_1.domain, info->device_1.bus, PCI_DEVFN(info->device_1.device, info->device_1.function));
    if (!pdev_bus_device_1)
    {
        printk(KERN_ERR "%s | Failed to get PCI device: %4.4x:%2.2x:%2.2x.%1.1x\n", DRIVER_NAME, info->device_1.domain, info->device_1.bus, info->device_1.device, info->device_1.function);
        return -ENODEV;
    }

    if (info->in_parallel)
    {
        pdev_bus_device_2 = pci_get_domain_bus_and_slot(info->device_2.domain, info->device_2.bus, PCI_DEVFN(info->device_2.device, info->device_2.function));
        if (!pdev_bus_device_2)
        {
            printk(KERN_ERR "%s | Failed to get PCI device: %4.4x:%2.2x:%2.2x.%1.1x\n", DRIVER_NAME, info->device_2.domain, info->device_2.bus, info->device_2.device, info->device_2.function);
            return -ENODEV;
        }

        return nnt_pci_reset_bus_in_parallel(pdev_bus_device_1, pdev_bus_device_2);
    }
    else
    {
        return nnt_pci_reset_bus(pdev_bus_device_1);
    }
}

static int get_syndrome_code(struct mst_dev_data* dev, u_int8_t* syndrome_code)
{
    /* In case syndrome is set, if syndrome_code is 0x3 (address_out_of_range), return the syndrome_code, so that the */
    /* ioctl will fail and then we'll retry with PCI space. */
    int error = 0;
    unsigned int syndrome = 0;

    *syndrome_code = 0;
    error = pci_read_config_dword(dev->pci_dev, dev->addr_reg, &syndrome); /* addr_reg should be vsec+0x10 */
    CHECK_PCI_READ_ERROR(error, dev->addr_reg);                            /* dev->addr_reg equivalent in MFT: nnt_device->pciconf_device.address_offset */
    syndrome = EXTRACT(syndrome, PCI_SYNDROME_BIT_OFFSET, PCI_SYNDROME_BIT_LEN);
    if (syndrome)
    {
        unsigned int control_offset = dev->functional_vsc_offset + PCI_CTRL_OFFSET;
        unsigned int syndrome_code_dword = 0;

        /* Read value from control offset. */
        error = pci_read_config_dword(dev->pci_dev, control_offset, &syndrome_code_dword);
        CHECK_PCI_READ_ERROR(error, control_offset);

        *syndrome_code = EXTRACT(syndrome_code_dword, PCI_SYNDROME_CODE_BIT_OFFSET, PCI_SYNDROME_CODE_BIT_LEN);
    }
ReturnOnFinished:
    return error;
}

static int _update_vsc_type(struct mst_dev_data* dev)
{
    unsigned int vsc_first_dword;
    u_int8_t vsc_type = 0;
    int ret = pci_read_config_dword(dev->pci_dev, dev->functional_vsc_offset, &vsc_first_dword);

    if (ret)
    {
        return ret;
    }
    vsc_type = EXTRACT(vsc_first_dword, MLX_VSC_TYPE_OFFSET, MLX_VSC_TYPE_LEN);
    if (vsc_type == RECOVERY_VSC)
    {
        dev->recovery_vsc_offset = dev->functional_vsc_offset;
        dev->functional_vsc_offset = 0;
    }
    return 0;
}

static int _vendor_specific_sem(struct mst_dev_data* dev, int state)
{
    u32 lock_val;
    u32 counter = 0;
    int retries = 0;
    int ret;

    if (!state)
    { /* unlock */
        ret = pci_write_config_dword(dev->pci_dev, dev->functional_vsc_offset + PCI_SEMAPHORE_OFFSET, 0);
        if (ret)
        {
            return ret;
        }
    }
    else
    { /* lock */
        do
        {
            if (retries > SEM_MAX_RETRIES)
            {
                return -1;
            }
            /* read semaphore untill 0x0 */
            ret = pci_read_config_dword(dev->pci_dev, dev->functional_vsc_offset + PCI_SEMAPHORE_OFFSET, &lock_val);
            if (ret)
            {
                return ret;
            }

            if (lock_val)
            { /* semaphore is taken */
                retries++;
                udelay(1000); /* wait for current op to end */
                continue;
            }
            /* read ticket */
            ret = pci_read_config_dword(dev->pci_dev, dev->functional_vsc_offset + PCI_COUNTER_OFFSET, &counter);
            if (ret)
            {
                return ret;
            }
            /* write ticket to semaphore dword */
            ret = pci_write_config_dword(dev->pci_dev, dev->functional_vsc_offset + PCI_SEMAPHORE_OFFSET, counter);
            if (ret)
            {
                return ret;
            }
            /* read back semaphore make sure ticket == semaphore else repeat */
            ret = pci_read_config_dword(dev->pci_dev, dev->functional_vsc_offset + PCI_SEMAPHORE_OFFSET, &lock_val);
            if (ret)
            {
                return ret;
            }
            retries++;
        } while (counter != lock_val);
    }
    return 0;
}

static int _wait_on_flag(struct mst_dev_data* dev, u8 expected_val)
{
    int retries = 0;
    int ret;
    u32 flag;

    do
    {
        if (retries > IFC_MAX_RETRIES)
        {
            return -1;
        }

        ret = pci_read_config_dword(dev->pci_dev, dev->functional_vsc_offset + PCI_ADDR_OFFSET, &flag);
        if (ret)
        {
            return ret;
        }

        flag = EXTRACT(flag, PCI_FLAG_BIT_OFFS, 1);
        retries++;
        if ((retries & 0xf) == 0)
        { /* dont sleep always */
            /* usleep_range(1,5); */
        }
    } while (flag != expected_val);
    return 0;
}

static int _set_addr_space(struct mst_dev_data* dev, u16 space)
{
    /* read modify write */
    u32 val;
    int ret;

    ret = pci_read_config_dword(dev->pci_dev, dev->functional_vsc_offset + PCI_CTRL_OFFSET, &val);
    if (ret)
    {
        return ret;
    }
    val = MERGE(val, space, PCI_SPACE_BIT_OFFS, PCI_SPACE_BIT_LEN);
    ret = pci_write_config_dword(dev->pci_dev, dev->functional_vsc_offset + PCI_CTRL_OFFSET, val);
    if (ret)
    {
        return ret;
    }
    /* read status and make sure space is supported */
    ret = pci_read_config_dword(dev->pci_dev, dev->functional_vsc_offset + PCI_CTRL_OFFSET, &val);
    if (ret)
    {
        return ret;
    }

    if (EXTRACT(val, PCI_STATUS_BIT_OFFS, PCI_STATUS_BIT_LEN) == 0)
    {
        /*      mst_err("CRSPACE %d is not supported !\n", space); */
        return -1;
    }
    /*  mst_err("CRSPACE %d is supported !\n", space); */
    return 0;
}

static int _pciconf_rw(struct mst_dev_data* dev, unsigned int offset, u32* data, int rw)
{
    int ret = 0;
    u32 address = offset;

    /* last 2 bits must be zero as we only allow 30 bits addresses */
    if (EXTRACT(address, 30, 2))
    {
        return -1;
    }

    address = MERGE(address, (rw ? 1 : 0), PCI_FLAG_BIT_OFFS, 1);
    if (rw == WRITE_OP)
    {
        /* write data */
        ret = pci_write_config_dword(dev->pci_dev, dev->functional_vsc_offset + PCI_DATA_OFFSET, *data);
        if (ret)
        {
            return ret;
        }
        /* write address */
        ret = pci_write_config_dword(dev->pci_dev, dev->functional_vsc_offset + PCI_ADDR_OFFSET, address);
        if (ret)
        {
            return ret;
        }
        /* wait on flag */
        ret = _wait_on_flag(dev, 0);
    }
    else
    {
        /* write address */
        ret = pci_write_config_dword(dev->pci_dev, dev->functional_vsc_offset + PCI_ADDR_OFFSET, address);
        if (ret)
        {
            return ret;
        }
        /* wait on flag */
        ret = _wait_on_flag(dev, 1);
        /* read data */
        ret = pci_read_config_dword(dev->pci_dev, dev->functional_vsc_offset + PCI_DATA_OFFSET, data);
        if (ret)
        {
            return ret;
        }
    }

    return ret;
}

static int _send_pci_cmd_int(struct mst_dev_data* dev, int space, unsigned int offset, u32* data, int rw)
{
    int ret = 0;

    /* take semaphore */
    ret = _vendor_specific_sem(dev, 1);
    if (ret)
    {
        return ret;
    }
    /* set address space */
    ret = _set_addr_space(dev, space);
    if (ret)
    {
        goto cleanup;
    }
    /* read/write the data */
    ret = _pciconf_rw(dev, offset, data, rw);
cleanup:
    /* clear semaphore */
    _vendor_specific_sem(dev, 0);
    return ret;
}

static int _block_op(struct mst_dev_data* dev, int space, unsigned int offset, int size, u32* data, int rw)
{
    int i;
    int ret = 0;
    int wrote_or_read = size;

    if (size % 4)
    {
        return -1;
    }
    /* lock semaphore and set address space */
    ret = _vendor_specific_sem(dev, 1);
    if (ret)
    {
        return -1;
    }
    /* set address space */
    ret = _set_addr_space(dev, space);
    if (ret)
    {
        wrote_or_read = -1;
        goto cleanup;
    }

    for (i = 0; i < size; i += 4)
    {
        if (_pciconf_rw(dev, offset + i, &(data[(i >> 2)]), rw))
        {
            wrote_or_read = i;
            goto cleanup;
        }
    }

cleanup:
    _vendor_specific_sem(dev, 0);
    return wrote_or_read;
}

static int write4_vsec(struct mst_dev_data* dev, int address_space, unsigned int offset, unsigned int data)
{
    int rc;

    rc = _send_pci_cmd_int(dev, address_space, offset, &data, WRITE_OP);

    if (rc)
    { /* OPERATIONAL error */
        return -1;
    }

    /* Support PCI space */
    if (dev->pci_vsec_space_fully_supported == 1)
    {
        u_int8_t syndrome_code = 0;
        if (get_syndrome_code(dev, &syndrome_code))
        { /* OPERATIONAL failure before retry */
            printk(KERN_ERR "Reading syndrome failed, aborting\n");
            return -1;
        }
        else if (syndrome_code == ADDRESS_OUT_OF_RANGE)
        { /* LOGICAL failure */
            printk(KERN_ERR "write4_vsec: _send_pci_cmd_int failed (syndrome is set and syndrome_code is ADDRESS_OUT_OF_RANGE) when trying to access address_space: 0x%x at offset: 0x%x\n",
                   address_space,
                   offset);

            swap_pci_address_space(&address_space);
            rc = _send_pci_cmd_int(dev, address_space, offset, &data, WRITE_OP);

            if (rc)
            { /* OPERATIONAL failure after retry */
                printk(KERN_ERR "write4_vsec: _send_pci_cmd_int failed (OPERATIONAL error), after retry, when trying to access address_space: 0x%x at offset: 0x%x\n", address_space, offset);
                return -1;
            }
            if (get_syndrome_code(dev, &syndrome_code))
            { /* OPERATIONAL failure after retry */
                printk(KERN_ERR "Reading syndrome failed, aborting\n");
                return -1;
            }
            else if (syndrome_code == ADDRESS_OUT_OF_RANGE)
            { /* LOGICAL failure after retry */
                printk(KERN_ERR
                       "write4_vsec: _send_pci_cmd_int failed (syndrome is set and syndrome_code is ADDRESS_OUT_OF_RANGE), after retry, when trying to access address_space: 0x%x at offset: 0x%x\n",
                       address_space,
                       offset);
                return -1;
            }
            else
            { /* LOGICAL and OPERATIONAL success after retry */
                printk(KERN_ERR "write4_vsec: _send_pci_cmd_int, after retry, successfully accessed address_space: 0x%x at offset: 0x%x\n", address_space, offset);
                return 0;
            }
        }
        else
        { /* OPERATIONAL and LOGICAL success */
            return 0;
        }
    }

    return 0; /* OPERATIONAL and LOGICAL success (PCI VSC address_spaces not supported) */
}

static int read4_vsec(struct mst_dev_data* dev, int address_space, unsigned int offset, unsigned int* data)
{
    int rc;

    /* mst_info("Read from VSEC: offset: %#x\n", offset); */
    rc = _send_pci_cmd_int(dev, address_space, offset, data, READ_OP);

    if (rc)
    { /* OPERATIONAL error */
        return -1;
    }

    /* Support PCI space */
    if (dev->pci_vsec_space_fully_supported == 1)
    {
        u_int8_t syndrome_code = 0;
        if (get_syndrome_code(dev, &syndrome_code))
        { /* OPERATIONAL failure before retry */
            printk(KERN_ERR "Reading syndrome failed, aborting\n");
            return -1;
        }
        else if (syndrome_code == ADDRESS_OUT_OF_RANGE)
        { /* LOGICAL failure */
            printk(KERN_ERR "read4_vsec: _send_pci_cmd_int failed (syndrome is set and syndrome_code is ADDRESS_OUT_OF_RANGE) when trying to access address_space: 0x%x at offset: 0x%x\n",
                   address_space,
                   offset);

            swap_pci_address_space(&address_space);
            rc = _send_pci_cmd_int(dev, address_space, offset, data, READ_OP);

            if (rc)
            { /* OPERATIONAL failure after retry */
                printk(KERN_ERR "read4_vsec: _send_pci_cmd_int failed (OPERATIONAL error), after retry, when trying to access address_space: 0x%x at offset: 0x%x\n", address_space, offset);
                return -1;
            }
            if (get_syndrome_code(dev, &syndrome_code))
            { /* OPERATIONAL failure after retry */
                printk(KERN_ERR "Reading syndrome failed, aborting\n");
                return -1;
            }
            else if (syndrome_code == ADDRESS_OUT_OF_RANGE)
            { /* LOGICAL failure after retry */
                printk(KERN_ERR
                       "read4_vsec: _send_pci_cmd_int failed (syndrome is set and syndrome_code is ADDRESS_OUT_OF_RANGE), after retry, when trying to access address_space: 0x%x at offset: 0x%x\n",
                       address_space,
                       offset);
                return -1;
            }
            else
            { /* LOGICAL and OPERATIONAL success after retry */
                printk(KERN_ERR "read4_vsec: _send_pci_cmd_int, after retry, successfully accessed address_space: 0x%x at offset: 0x%x\n", address_space, offset);
                return 0;
            }
        }
        else
        { /* OPERATIONAL and LOGICAL success */
            return 0;
        }
    }

    return 0; /* OPERATIONAL and LOGICAL success (PCI VSC address_spaces not supported) */
}

static int pciconf_read4_legacy(struct mst_dev_data* dev, unsigned int offset, unsigned int* data)
{
    int res = 0;
    unsigned int new_offset = offset;

    /* mst_info("pciconf_read4_legacy: offset: %#x\n", offset); */
    if (dev->type != PCICONF)
    {
        return -1;
    }
    if (dev->wo_addr)
    {
        new_offset |= 0x1;
    }
    /* write the wanted address to addr register */
    res = pci_write_config_dword(dev->pci_dev, dev->addr_reg, new_offset);
    if (res)
    {
        mst_err("pci_write_config_dword failed\n");
        return res;
    }

    /* read the result from data register */
    res = pci_read_config_dword(dev->pci_dev, dev->data_reg, data);
    if (res)
    {
        mst_err("pci_read_config_dword failed\n");
        return res;
    }
    return 0;
}

static int pciconf_write4_legacy(struct mst_dev_data* dev, unsigned int offset, unsigned int data)
{
    int res = 0;

    if (dev->type != PCICONF)
    {
        return -1;
    }
    if (dev->wo_addr)
    {
        /*
         * Write operation with new WO GW
         * 1. Write data
         * 2. Write address
         */

        /* write the data to data register */
        res = pci_write_config_dword(dev->pci_dev, dev->data_reg, data);
        if (res)
        {
            mst_err("pci_write_config_dword failed\n");
            return res;
        }
        /* write the destination address to addr register */
        res = pci_write_config_dword(dev->pci_dev, dev->addr_reg, offset);
        if (res)
        {
            mst_err("pci_write_config_dword failed\n");
            return res;
        }
    }
    else
    {
        /* write the destination address to addr register */
        res = pci_write_config_dword(dev->pci_dev, dev->addr_reg, offset);
        if (res)
        {
            mst_err("pci_write_conflig_dword failed\n");
            return res;
        }

        /* write the data to data register */
        res = pci_write_config_dword(dev->pci_dev, dev->data_reg, data);
        if (res)
        {
            mst_err("pci_write_config_dword failed\n");
            return res;
        }
    }
    return 0;
}

static int write4_block_vsec(struct mst_dev_data* dev, int address_space, unsigned int offset, int size, u32* data)
{
    /*    mst_info("HERE %#x %#x %#x\n", address_space, offset, *data); */
    return _block_op(dev, address_space, offset, size, data, WRITE_OP);
}

static int read4_block_vsec(struct mst_dev_data* dev, int address_space, unsigned int offset, int size, u32* data)
{
    /*    mst_info("HERE %#x %#x %#x\n", address_space, offset, *data); */
    return _block_op(dev, address_space, offset, size, data, READ_OP);
}

static int get_space_support_status(struct mst_dev_data* dev)
{
    int ret = 0;

    /* If VSC is of type RECOVERY, all the spaces are not supported */
    if (dev->functional_vsc_offset == RECOVERY_VSC)
    {
        dev->spaces_support_status = SS_NOT_ALL_SPACES_SUPPORTED;
        return 0;
    }
    /*    printk("[MST] Checking if the Vendor CAP %d supports the SPACES in devices\n", vend_cap); */
    if ((!dev->functional_vsc_offset) || (!dev->pci_dev))
    {
        return 0;
    }
    if (dev->spaces_support_status != SS_UNINITIALIZED)
    {
        return 0;
    }
    /* take semaphore */
    ret = _vendor_specific_sem(dev, 1);
    if (ret)
    {
        mst_err("Failed to lock VSEC semaphore\n");
        return 1;
    }
    else if (_set_addr_space(dev, AS_CR_SPACE))
    {
        capability_support_info_message(dev, CR_SPACE);
        dev->spaces_support_status = SS_NOT_ALL_SPACES_SUPPORTED;
    }
    else if (_set_addr_space(dev, AS_ICMD))
    {
        capability_support_info_message(dev, ICMD);
        dev->spaces_support_status = SS_NOT_ALL_SPACES_SUPPORTED;
    }
    else if (_set_addr_space(dev, AS_SEMAPHORE))
    {
        capability_support_info_message(dev, SEMAPHORE);
        dev->spaces_support_status = SS_NOT_ALL_SPACES_SUPPORTED;
    }
    else
    {
        dev->spaces_support_status = SS_ALL_SPACES_SUPPORTED;
    }
    if (_set_addr_space(dev, AS_RECOVERY))
    {
        capability_support_info_message(dev, RECOVERY); /* this space is supported only for ConnectX8, Quantum3 and above. For recovery from Zombiefish mode. */
    }
    if (!_set_addr_space(dev, AS_PCI_CRSPACE) && !_set_addr_space(dev, AS_PCI_ICMD) && !_set_addr_space(dev, AS_PCI_GLOBAL_SEMAPHORE))
    {
        dev->pci_vsec_space_fully_supported = 1; /* Support PCI space */
    }

    /* clear semaphore */
    _vendor_specific_sem(dev, 0);
    return 0;
}

/********** WO GW ************/

#define WO_REG_ADDR_DATA 0xbadacce5
#define DEVID_OFFSET 0xf0014
static int is_wo_gw(struct pci_dev* pcidev, unsigned int addr_reg)
{
    int ret;
    unsigned int data = 0;

    ret = pci_write_config_dword(pcidev, addr_reg, DEVID_OFFSET);
    if (ret)
    {
        return 0;
    }
    ret = pci_read_config_dword(pcidev, addr_reg, &data);
    if (ret)
    {
        return 0;
    }
    if (data == WO_REG_ADDR_DATA)
    {
        return 1;
    }
    return 0;
}

/****************************************************/
static int mst_open(struct inode* inode, struct file* file)
{
    struct mst_file_data* md = NULL;

    md = kmalloc(sizeof(struct mst_connectx_wa), GFP_KERNEL);
    if (!md)
    {
        return -ERESTARTSYS;
    }

    memset(md, 0, sizeof(struct mst_connectx_wa));

    file->private_data = md;

    return 0;
}

/****************************************************/
static int mst_release(struct inode* inode, struct file* file)
{
    int res = 0;
    struct mst_dev_data* dev = NULL;
    struct mst_dev_data* cur = NULL;
    unsigned int slot_mask;
    struct mst_connectx_wa* md = file->private_data;

    /*
     * make sure the device is available since it
     * could be removed by hotplug event
     * if available grab its lock
     */
    list_for_each_entry(cur, &mst_devices, list)
    {
        if (cur->major == imajor(inode))
        {
            dev = cur;
            mutex_lock(&dev->lock);
            break;
        }
    }

    if (!dev)
    {
        mst_err("failed to find device with major=%d\n", imajor(inode));
        res = -ENODEV;
        goto out;
    }

    if (md->connectx_wa_slot_p1 != 0)
    {
        slot_mask = ~(1 << (md->connectx_wa_slot_p1 - 1));
        dev->connectx_wa_slots &= slot_mask;
    }

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

static int page_pin(struct mst_dev_data* dev, struct page_info_st* page_info)
{
    unsigned long page_pointer_start = page_info->page_pointer_start;
    unsigned int page_amount = page_info->page_amount;
    unsigned int pages_size = page_amount * PAGE_SIZE;
    unsigned long end_of_buffer = page_pointer_start + pages_size;
    unsigned int gup_flags = FOLL_WRITE;
    int page_mapped_counter = 0;
    int page_counter = 0;
    int total_pinned = 0;

    /* If the combination of the addr and size requested for this memory */
    /* region causes an integer overflow, return error. */
    if (((end_of_buffer) < page_pointer_start) || (PAGE_ALIGN(end_of_buffer) < (end_of_buffer)) || (page_amount < 1))
    {
        return -EINVAL;
    }

    /* Check if we allow locking memory. */
    if (!can_do_mlock())
    {
        return -EPERM;
    }

    /* Allocate the page list. */
    dev->dma_page.page_list = kcalloc(page_amount, sizeof(struct page*), GFP_KERNEL);
    if (!dev->dma_page.page_list)
    {
        return -ENOMEM;
    }

    /* Go over the user memory buffer and pin user pages in memory. */
    while (total_pinned < page_amount)
    {
        /* Save the current number of pages to pin */
        int num_pages = page_amount - total_pinned;

        /* Save the current pointer to the right offset. */
        uint64_t current_ptr = page_pointer_start + (total_pinned * PAGE_SIZE);

        /* Save the current page. */
        struct page** current_pages = dev->dma_page.page_list + total_pinned;

        /* Attempt to pin user pages in memory. */
        /* Returns number of pages pinned - this may be fewer than the number requested */
        /*   or -errno in case of error. */
        int pinned_pages = get_user_pages_fast(current_ptr, num_pages, gup_flags, current_pages);
        if (pinned_pages < 1)
        {
            kfree(dev->dma_page.page_list);
            return -EFAULT;
        }

        /* When the parameter 'inter_iommu' is on, we need to set up */
        /* a mapping on a pages in order to access the physical address */
        while (page_mapped_counter < pinned_pages)
        {
            int current_page = total_pinned + page_mapped_counter;

            /* Get the dma address. */
            dev->dma_page.dma_addr[current_page] = dma_map_page(&dev->pci_dev->dev, current_pages[current_page], 0, PAGE_SIZE, DMA_BIDIRECTIONAL);
            /* Do we get a valid dma address ? */
            if (dma_mapping_error(&dev->pci_dev->dev, dev->dma_page.dma_addr[current_page]))
            {
                printk(KERN_ERR "Failed to get DMA addresses\n");
                return -EINVAL;
            }

            page_info->page_address_array[current_page].dma_address = dev->dma_page.dma_addr[current_page];

            page_mapped_counter++;
        }

        /* Advance the memory that already pinned. */
        total_pinned += pinned_pages;
    }

    /* There is a page that not pinned in the kernel space ? */
    if (total_pinned != page_amount)
    {
        return -EFAULT;
    }

    /* Print the pages to the dmesg. */
    for (page_counter = 0; page_counter < page_amount; page_counter++)
    {
        printk(KERN_INFO "Page address structure number: %d, device: %04x:%02x:%02x.%0x\n", page_counter, pci_domain_nr(dev->pci_dev->bus), dev->pci_dev->bus->number, PCI_SLOT(dev->pci_dev->devfn),
               PCI_FUNC(dev->pci_dev->devfn));
    }

    return 0;
}

static int page_unpin(struct mst_dev_data* dev, struct page_info_st* page_info)
{
    int page_counter;

    /* Check if the page list is allocated. */
    if (!dev || !dev->dma_page.page_list)
    {
        return -EINVAL;
    }

    /* Deallocate the pages. */
    for (page_counter = 0; page_counter < page_info->page_amount; page_counter++)
    {
        /* DMA activity is finished. */
        dma_unmap_page(&dev->pci_dev->dev, dev->dma_page.dma_addr[page_counter], PAGE_SIZE, DMA_BIDIRECTIONAL);

        /* Release the page list. */
        set_page_dirty(dev->dma_page.page_list[page_counter]);
        put_page(dev->dma_page.page_list[page_counter]);
        dev->dma_page.page_list[page_counter] = NULL;
        dev->dma_page.dma_addr[page_counter] = 0;

        printk(KERN_INFO "Page structure number: %d was released. device:%04x:%02x:%02x.%0x\n", page_counter, pci_domain_nr(dev->pci_dev->bus), dev->pci_dev->bus->number,
               PCI_SLOT(dev->pci_dev->devfn), PCI_FUNC(dev->pci_dev->devfn));
    }

    /* All the pages are clean. */
    dev->dma_page.page_list = NULL;

    return 0;
}

static int read_dword_from_config_space(struct mst_dev_data* dev, struct read_dword_from_config_space* read_from_cspace)
{
    int ret = 0;

    /* take semaphore */
    ret = _vendor_specific_sem(dev, 1);
    if (ret)
    {
        return ret;
    }

    /* Read dword from config space */
    ret = pci_read_config_dword(dev->pci_dev, read_from_cspace->offset, &read_from_cspace->data);
    if (ret)
    {
        goto cleanup;
    }

cleanup:
    /* clear semaphore */
    _vendor_specific_sem(dev, 0);
    return ret;
}

/****************************************************/
static ssize_t mst_read(struct file* file, char* buf, size_t count, loff_t* f_pos)
{
    mst_err("not implemented\n");
    return 0;
}

/****************************************************/
static ssize_t mst_write(struct file* file, const char* buf, size_t count, loff_t* f_pos)
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
 *
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
static int mst_ioctl(struct inode* inode, struct file* file, unsigned int opcode, unsigned long input)
{
    int res = 0;
    struct mst_dev_data* dev = NULL;
    struct mst_dev_data* cur = NULL;
    void* user_buf = (void*)input;

    /*
     * In MEM mapped data flow there is no need to lock the semaphore.
     * Since the HW handles the requests in PCI level thus no need
     * for serializing (HW is capable of handling parallel requests)
     */
#define IS_LOCK_NEEDED(dev) (!(dev->type == PCIMEM && (opcode == MST_READ4 || opcode == MST_WRITE4)))

    /*
     * make sure the device is available since it
     * could be removed by hotplug event
     * if available grab its lock
     */
    list_for_each_entry(cur, &mst_devices, list)
    {
        if (cur->major == imajor(inode))
        {
            dev = cur;
            if (IS_LOCK_NEEDED(dev))
            {
                mutex_lock(&dev->lock);
            }
            break;
        }
    }

    if (!dev)
    {
        mst_err("failed to find device with major=%d\n", imajor(inode));
        res = -ENODEV;
        goto fin_err;
    }

    switch (opcode)
    {
        case MST_PARAMS:
        {
            struct mst_params paramst;

            if (!dev->initialized)
            {
                mst_err("device is not initialized\n");
                res = -ENODEV;
                goto fin;
            }
            /* best effort : try to get space spport status if we fail assume we got vsec support. */
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
            if (dev->functional_vsc_offset && ((dev->spaces_support_status == SS_ALL_SPACES_SUPPORTED) || (dev->spaces_support_status == SS_UNINITIALIZED)))
            {
                /* assume supported if SS_UNINITIALIZED (since semaphore is locked) */
                paramst.functional_vsc_offset = dev->functional_vsc_offset;
            }
            else
            {
                paramst.functional_vsc_offset = 0;
            }
            if (copy_to_user(user_buf, &paramst, sizeof(struct mst_params)))
            {
                res = -EFAULT;
                goto fin;
            }
            break;
        }

        case MST_READ4:
        {
            u32 out;
            u32* dataout = NULL;
            struct mst_read4_st readst;

            if (!dev->initialized)
            {
                mst_err("device is not initialized\n");
                res = -ENODEV;
                goto fin;
            }

            if (copy_from_user(&readst, user_buf, sizeof(struct mst_read4_st)))
            {
                res = -EFAULT;
                goto fin;
            }

            switch (dev->type)
            {
                case PCICONF:
                    if (get_space_support_status(dev))
                    {
                        res = -EBUSY;
                        goto fin;
                    }

                    if (VSEC_FULLY_SUPPORTED(dev))
                    {
                        res = read4_vsec(dev, readst.address_space, readst.offset, &out);
                    }
                    else
                    {
                        res = pciconf_read4_legacy(dev, readst.offset, &out);
                    }
                    if (res)
                    {
                        goto fin;
                    }
                    break;

                case PCIMEM:
                    if ((readst.offset + sizeof(u32)) > MST_MEMORY_SIZE)
                    {
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
            dataout = &((struct mst_read4_st*)user_buf)->data;
            if (copy_to_user(dataout, &out, sizeof(u32)))
            {
                res = -EFAULT;
                goto fin;
            }
            break;
        }

        case MST_WRITE4:
        {
            struct mst_write4_st writest;

            if (!dev->initialized)
            {
                mst_err("device is not initialized\n");
                res = -ENODEV;
                goto fin;
            }

            if (copy_from_user(&writest, user_buf, sizeof(struct mst_write4_st)))
            {
                res = -EFAULT;
                goto fin;
            }

            switch (dev->type)
            {
                case PCICONF:
                    if (get_space_support_status(dev))
                    {
                        res = -EBUSY;
                        goto fin;
                    }
                    if (VSEC_FULLY_SUPPORTED(dev))
                    {
                        res = write4_vsec(dev, writest.address_space, writest.offset, writest.data);
                    }
                    else
                    {
                        res = pciconf_write4_legacy(dev, writest.offset, writest.data);
                    }
                    break;

                case PCIMEM:
                    if ((writest.offset + sizeof(u32)) > MST_MEMORY_SIZE)
                    {
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

        case PCIMEM_READ_BLOCK:
        {
            int i = 0;
            u32* data = NULL;
            u32* dataout = NULL;
            struct mst_read_block_st readst;

            if (!dev->initialized)
            {
                mst_err("device is not initialized\n");
                res = -ENODEV;
                goto fin;
            }

            if (dev->type != PCIMEM)
            {
                mst_err("wrong type for device\n");
                res = -EPERM;
                goto fin;
            }

            if (copy_from_user(&readst, user_buf, sizeof(struct mst_read_block_st)))
            {
                res = -EFAULT;
                goto fin;
            }

            if (readst.size % sizeof(u32))
            {
                mst_err("invalid size. size should be in bytes and divide sizeof(u32)\n");
                res = -EINVAL;
                goto fin;
            }

            if ((readst.offset + readst.size) > MST_MEMORY_SIZE)
            {
                mst_err("accessing invalid address\n");
                res = -EINVAL;
                goto fin;
            }

            data = kzalloc(readst.size, GFP_KERNEL);
            if (!data)
            {
                res = -ENOMEM;
                goto fin;
            }

            /* read from hardware */
            memcpy_fromio(data, dev->hw_addr + readst.offset, readst.size);

            /* endianness conversion */
            for (i = 0; i < (readst.size / sizeof(u32)); ++i)
            {
                be32_to_cpus(&(data[i]));
            }

            /* retrieve to user */
            dataout = ((struct mst_read_block_st*)user_buf)->data;
            if (copy_to_user(dataout, data, readst.size))
            {
                res = -EFAULT;
                kfree(data);
                goto fin;
            }

            kfree(data);
            break;
        }

        case PCIMEM_WRITE_BLOCK:
        {
            int i = 0;
            struct mst_write_block_st writest;

            if (!dev->initialized)
            {
                mst_err("device is not initialized\n");
                res = -ENODEV;
                goto fin;
            }

            if (dev->type != PCIMEM)
            {
                mst_err("wrong type for device\n");
                res = -EPERM;
                goto fin;
            }

            if (copy_from_user(&writest, user_buf, sizeof(struct mst_write_block_st)))
            {
                res = -EFAULT;
                goto fin;
            }

            if (writest.size % sizeof(u32))
            {
                mst_err("invalid size. size should be in bytes and divide sizeof(u32)\n");
                res = -EINVAL;
                goto fin;
            }

            if ((writest.offset + writest.size) > MST_MEMORY_SIZE)
            {
                mst_err("accessing invalid address\n");
                res = -EINVAL;
                goto fin;
            }

            /* endianness conversion */
            for (i = 0; i < (writest.size / sizeof(u32)); ++i)
            {
                cpu_to_be32s(&(writest.data[i]));
            }

            /* write to hardware */
            memcpy_toio(dev->hw_addr + writest.offset, writest.data, writest.size);

            break;
        }

        case PCICONF_READ4_BUFFER:
        {
            struct mst_read4_buffer_st read4_buf;
            struct mst_read4_buffer_st* rb_udata = (struct mst_read4_buffer_st*)user_buf;

            if (!dev->initialized)
            {
                mst_err("device is not initialized\n");
                res = -ENODEV;
                goto fin;
            }

            if (dev->type != PCICONF)
            {
                mst_err("wrong type for device\n");
                res = -EPERM;
                goto fin;
            }

            if (get_space_support_status(dev))
            {
                res = -EBUSY;
                goto fin;
            }

            if (dev->spaces_support_status != SS_ALL_SPACES_SUPPORTED)
            {
                res = -EOPNOTSUPP;
                goto fin;
            }

            if (copy_from_user(&read4_buf, user_buf, sizeof(read4_buf)))
            {
                res = -EFAULT;
                goto fin;
            }

            res = read4_block_vsec(dev, read4_buf.address_space, read4_buf.offset, read4_buf.size, read4_buf.data);
            if (res != read4_buf.size)
            {
                goto fin;
            }

            res = copy_to_user(rb_udata, &read4_buf, sizeof(read4_buf)) ? -EFAULT : read4_buf.size;
            goto fin;
        }

        case PCICONF_WRITE4_BUFFER:
        {
            struct mst_write4_buffer_st write4_buf;
            struct mst_write4_buffer_st* wb_udata = (struct mst_write4_buffer_st*)user_buf;

            if (!dev->initialized)
            {
                mst_err("device is not initialized\n");
                res = -ENODEV;
                goto fin;
            }

            if (dev->type != PCICONF)
            {
                mst_err("wrong type for device\n");
                res = -EPERM;
                goto fin;
            }

            if (get_space_support_status(dev))
            {
                res = -EBUSY;
                goto fin;
            }

            if (dev->spaces_support_status != SS_ALL_SPACES_SUPPORTED)
            {
                res = -EOPNOTSUPP;
                goto fin;
            }

            if (copy_from_user(&write4_buf, user_buf, sizeof(write4_buf)))
            {
                res = -EFAULT;
                goto fin;
            }

            res = write4_block_vsec(dev, write4_buf.address_space, write4_buf.offset, write4_buf.size, write4_buf.data);
            if (res != write4_buf.size)
            {
                goto fin;
            }

            res = copy_to_user(wb_udata, &write4_buf, sizeof(write4_buf)) ? -EFAULT : write4_buf.size;
            goto fin;
        }

        case PCICONF_INIT:
        {
            struct mst_pciconf_init_st initst;

            if (dev->initialized)
            {
                mst_err("device already initialized\n");
                res = ENODEV;
                goto fin;
            }

            if (dev->type != PCICONF)
            {
                mst_err("wrong type for device\n");
                res = -EPERM;
                goto fin;
            }

            if (copy_from_user(&initst, user_buf, sizeof(struct mst_pciconf_init_st)))
            {
                res = -EFAULT;
                goto fin;
            }

            dev->addr_reg = initst.addr_reg;
            dev->data_reg = initst.data_reg;

            dev->wo_addr = is_wo_gw(dev->pci_dev, initst.addr_reg);
            dev->functional_vsc_offset = pci_find_capability(dev->pci_dev, VENDOR_SPECIFIC_CAP_ID);
            _update_vsc_type(dev);
            /* mst_info("dev->functional_vsc_offset: %#x. dev->recovery_vsc_offset: %#x dev->wo_addr:%d.\n", dev->functional_vsc_offset, dev->recovery_vsc_offset, dev->wo_addr); */

            /* mst_info("FUNCTIONAL VSC SUPP: %#x\n", dev->functional_vsc_offset); */
            dev->spaces_support_status = SS_UNINITIALIZED; /* init on first op */

            dev->initialized = 1;
            break;
        }

        case PCICONF_STOP:
            if (!dev->initialized)
            {
                mst_err("device is not initialized\n");
                res = -ENODEV;
                goto fin;
            }

            if (dev->type != PCICONF)
            {
                mst_err("wrong type for device\n");
                res = -EPERM;
                goto fin;
            }

            dev->initialized = 0;
            break;

        case PCIMEM_INIT:
        {
            struct mst_mem_init_st initst;
            unsigned long resource_start;

            if (dev->initialized)
            {
                mst_err("device already initialized\n");
                res = ENODEV;
                goto fin;
            }

            if (dev->type != PCIMEM)
            {
                mst_err("wrong type for device\n");
                res = -EPERM;
                goto fin;
            }

            if (copy_from_user(&initst, user_buf, sizeof(struct mst_mem_init_st)))
            {
                res = -EFAULT;
                goto fin;
            }

            /* unmap previously mapped device if it was not stopped properly */
            if (dev->hw_addr)
            {
                iounmap(cur->hw_addr);
                dev->hw_addr = NULL;
            }

            dev->bar = initst.bar;
            resource_start = pci_resource_start(dev->pci_dev, dev->bar);

            dev->hw_addr = ioremap(resource_start, MST_MEMORY_SIZE);

            if (!dev->hw_addr)
            {
                mst_err("could not map device memory\n");
                res = -EFAULT;
                goto fin;
            }

            dev->initialized = 1;
            break;
        }

        case PCIMEM_STOP:
            if (!dev->initialized)
            {
                mst_err("device is not initialized\n");
                res = -ENODEV;
                goto fin;
            }

            if (dev->type != PCIMEM)
            {
                mst_err("wrong type for device\n");
                res = -EPERM;
                goto fin;
            }

            if (cur->hw_addr)
            {
                iounmap(cur->hw_addr);
            }

            cur->hw_addr = NULL;
            dev->initialized = 0;
            break;

        case PCI_CONNECTX_WA:
        {
            struct mst_connectx_wa* md = file->private_data;
            unsigned int slot_mask;

            if (!dev->initialized)
            {
                mst_err("device is not initialized\n");
                res = -ENODEV;
                goto fin;
            }

            /* slot exists */
            if (md->connectx_wa_slot_p1)
            {
                mst_err("slot exits for file %s, slot:0x%x\n", dev->name, md->connectx_wa_slot_p1);
                res = -EPERM;
                goto fin;
            }

            /* find first un(set) bit. and remember the slot */
            md->connectx_wa_slot_p1 = ffs(~dev->connectx_wa_slots);
            if ((md->connectx_wa_slot_p1 == 0) || (md->connectx_wa_slot_p1 > CONNECTX_WA_SIZE))
            {
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
            if (copy_to_user(user_buf, md, sizeof(struct mst_connectx_wa)))
            {
                res = -EFAULT;
                goto fin;
            }
            break;
        }

        case PCICONF_VPD_READ4:
        {
            u32 out;
            u32* dataout = NULL;
            struct mst_vpd_read4_st readst;

            if (!dev->initialized)
            {
                mst_err("device is not initialized\n");
                res = ENODEV;
                goto fin;
            }

            if (dev->type != PCICONF)
            {
                mst_err("wrong type for device\n");
                res = -EPERM;
                goto fin;
            }

            if (copy_from_user(&readst, user_buf, sizeof(struct mst_vpd_read4_st)))
            {
                res = -EFAULT;
                goto fin;
            }

            res = pci_read4_vpd(dev, readst.timeout, readst.offset, &out);
            if (res)
            {
                goto fin;
            }

            /* retrieve to user - we noticed that we need to swap always */
            dataout = &((struct mst_vpd_read4_st*)user_buf)->data;
            out = le32_to_cpu(out);
            if (copy_to_user(dataout, &out, sizeof(u32)))
            {
                res = -EFAULT;
                goto fin;
            }
            break;
        }

        case PCICONF_VPD_WRITE4:
        {
            struct mst_vpd_write4_st writest;

            if (!dev->initialized)
            {
                mst_err("device is not initialized\n");
                res = ENODEV;
                goto fin;
            }

            if (dev->type != PCICONF)
            {
                mst_err("wrong type for device\n");
                res = -EPERM;
                goto fin;
            }

            if (copy_from_user(&writest, user_buf, sizeof(struct mst_vpd_write4_st)))
            {
                res = -EFAULT;
                goto fin;
            }
            writest.data = le32_to_cpu(writest.data);
            res = pci_write4_vpd(dev, writest.timeout, writest.offset, writest.data);
            if (res)
            {
                goto fin;
            }
            break;
        }

        case PCICONF_GET_DMA_PAGES:
        case PCICONF_RELEASE_DMA_PAGES:
        {
            struct page_info_st page_info;

            /* Device validation. */
            if (!dev->initialized || !dev->pci_dev)
            {
                res = -ENOTTY;
                goto fin;
            }

            /* Copy the page info structure from the user space. */
            if (copy_from_user(&page_info, user_buf, sizeof(struct page_info_st)))
            {
                res = -EFAULT;
                goto fin;
            }

            if (opcode == PCICONF_GET_DMA_PAGES)
            {
                res = page_pin(dev, &page_info);
                if (res)
                {
                    goto fin;
                }

                /* Return the physical address to the user. */
                if (copy_to_user(user_buf, &page_info, sizeof(struct page_info_st)) != 0)
                {
                    res = -EFAULT;
                    goto fin;
                }
            }
            else
            {
                res = page_unpin(dev, &page_info);
            }

            break;
        }

        case PCICONF_READ_DWORD_FROM_CONFIG_SPACE:
        {
            struct read_dword_from_config_space read_from_cspace;

            /* Device validation. */
            if (!dev->initialized || !dev->pci_dev)
            {
                res = -ENOTTY;
                goto fin;
            }

            /* Copy the page info structure from the user space. */
            if (copy_from_user(&read_from_cspace, user_buf, sizeof(struct read_dword_from_config_space)))
            {
                res = -EFAULT;
                goto fin;
            }

            res = read_dword_from_config_space(dev, &read_from_cspace);
            if (res)
            {
                goto fin;
            }
            /* Return the physical address to the user. */
            if (copy_to_user(user_buf, &read_from_cspace, sizeof(struct read_dword_from_config_space)) != 0)
            {
                res = -EFAULT;
                goto fin;
            }

            break;
        }
        case PCICONF_HOT_RESET:
        {
            struct hot_reset_pcie_switch hot_reset;
            if (copy_from_user(&hot_reset, user_buf, sizeof(struct hot_reset_pcie_switch)))
            {
                res = -EFAULT;
                goto fin;
            }
            res = hot_reset_pcie_switch(&hot_reset);
            break;
        }

        default:
            print_opcode();
            res = -EINVAL;
            break;
    }

fin:
    if (IS_LOCK_NEEDED(dev))
    {
        mutex_unlock(&dev->lock);
    }
fin_err:
    return res;
}

static long unlocked_ioctl(struct file* f, unsigned int o, unsigned long d)
{
#if KERNEL_VERSION(3, 18, 0) > LINUX_VERSION_CODE
    struct inode* n = f->f_dentry->d_inode;
#else
    struct inode* n = f->f_path.dentry->d_inode;
#endif

    return mst_ioctl(n, f, o, d);
}

/****************************************************/
static inline const char* dev_type_to_str(enum dev_type type)
{
    switch (type)
    {
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
  .read = mst_read,
  .write = mst_write,
  .unlocked_ioctl = unlocked_ioctl,
  .open = mst_open,
  .release = mst_release,
  .owner = THIS_MODULE,
};

static struct mst_dev_data* mst_device_create(enum dev_type type, struct pci_dev* pdev)
{
    struct mst_dev_data* dev = NULL;
    char dbdf[20];

    dev = kzalloc(sizeof(struct mst_dev_data), GFP_KERNEL);
    if (!dev)
    {
        return NULL;
    }

    sprintf(dbdf, "%4.4x:%2.2x:%2.2x.%1.1x", pci_domain_nr(pdev->bus), pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
    switch (type)
    {
        case PCICONF:
            dev->addr_reg = MST_CONF_ADDR_REG;
            dev->data_reg = MST_CONF_DATA_REG;
            dev->bar = 0;        /* invalid */
            dev->hw_addr = NULL; /* invalid */
            snprintf(dev->name, MST_NAME_SIZE, "%s" MST_PCICONF_DEVICE_NAME, dbdf);

            break;

        case PCIMEM:
            dev->addr_reg = 0; /* invalid */
            dev->data_reg = 0; /* invalid */
            dev->bar = 0;
            dev->hw_addr = ioremap(pci_resource_start(pdev, dev->bar), MST_MEMORY_SIZE);
            if (!dev->hw_addr)
            {
                mst_err("could not map device memory, BAR: %x\n", dev->bar);
                goto out;
            }

            snprintf(dev->name, MST_NAME_SIZE, "%s" MST_PCIMEM_DEVICE_NAME, dbdf);
            break;

        default:
            mst_err("failed to %s, unknown device type 0x%x\n", __func__, dev->type);
            goto out;
    }

    dev->type = type;
    dev->pci_dev = pdev;
    mutex_init(&dev->lock);

    dev->vpd_cap_addr = pci_find_capability(pdev, PCI_CAP_ID_VPD);

    if (alloc_chrdev_region(&dev->my_dev, 0, 1, dev->name))
    {
        mst_err("failed to allocate chrdev_region\n");
    }
    dev->cl = MY_CLASS_CREATE(dev->name);
    if (dev->cl == NULL)
    {
        pr_alert("Class creation failed\n");
        unregister_chrdev_region(dev->my_dev, 1);
        goto out;
    }

    if (device_create(dev->cl, NULL, dev->my_dev, NULL, dev->name) == NULL)
    {
        pr_alert("Device creation failed\n");
        class_destroy(dev->cl);
        unregister_chrdev_region(dev->my_dev, 1);
        goto out;
    }

    dev->major = MAJOR(dev->my_dev);
    cdev_init(&dev->mcdev, &mst_fops);
    cdev_add(&dev->mcdev, dev->my_dev, 1); /* TODO check if cdev_add fails */

    if (type == PCICONF)
    {
        /*
         * Initialize 5th Gen attributes
         */
        dev->wo_addr = is_wo_gw(dev->pci_dev, MST_CONF_ADDR_REG);
        dev->functional_vsc_offset = pci_find_capability(dev->pci_dev, VENDOR_SPECIFIC_CAP_ID);
        _update_vsc_type(dev);
        /* mst_info("dev->functional_vsc_offset: %#x. dev->recovery_vsc_offset: %#x dev->wo_addr:%d.\n", dev->functional_vsc_offset, dev->recovery_vsc_offset, dev->wo_addr); */

        /* mst_info("FUNCTIONAL VSC SUPP: %#x\n", dev->functional_vsc_offset); */
        dev->spaces_support_status = SS_UNINITIALIZED; /* init on first op */
    }
    dev->initialized = 1;
    list_add_tail(&dev->list, &mst_devices);

    return dev;
out:
    kfree(dev);
    return NULL;
}

static void mst_device_destroy(struct mst_dev_data* dev)
{
    if (dev->hw_addr)
    {
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
    struct pci_dev* pdev = NULL;
    struct mst_dev_data* dev = NULL;

    mst_info("%s - version %s\n", mst_driver_string, mst_driver_version);

    while ((pdev = pci_get_device(MST_MELLANOX_PCI_VENDOR, PCI_ANY_ID, pdev)) != NULL)
    {
        if (!pci_match_id(supported_pci_devices, pdev) && !pci_match_id(mst_livefish_pci_table, pdev))
        {
            continue;
        }

        if (pdev->is_virtfn)
        {
            continue;
        }

        /* found new device */
        mst_info("found device - domain=0x%x, bus=0x%x, slot=0x%x, func=0x%x, vendor=0x%x, device=0x%x\n", pci_domain_nr(pdev->bus), pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn),
                 pdev->vendor, pdev->device);

        /* create PCICONF for this device */
        dev = mst_device_create(PCICONF, pdev);
        if (!dev)
        {
            mst_err("failed to mst_device_create\n");
            continue; /* PCICONF creation failed, no point creating a PCIMEM device */
        }

        /*
         * for livefish devices we only allocate PCICONF
         * for non livefish both PCICONF and PCIMEM
         */
        if (!pci_match_id(mst_livefish_pci_table, pdev) && pci_match_id(mst_bar_pci_table, pdev))
        {
            /* create new mst_device for PCIMEM */
            dev = mst_device_create(PCIMEM, pdev);
            if (!dev)
            {
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
    list_for_each_entry_safe(cur, temp, &mst_devices, list)
    {
        mst_device_destroy(cur);
    }
}

/****************************************************/
module_init(mst_init);
module_exit(mst_cleanup);
