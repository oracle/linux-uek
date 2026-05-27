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
#ifndef _MST_H_
#define _MST_H_

#include <linux/ioctl.h>

/****************************************************/
#define MST_MEMORY_SIZE (1024 * 1024)
#define MST_BLOCK_SIZE 64

#define MST_PARAMS_MAGIC 0xD0
#define MST_BYTE_ACCESS_MAGIC 0xD1
#define MST_BLOCK_ACCESS_MAGIC 0xD2
#define MST_PCICONF_MAGIC 0xD3
#define MST_PCIMEM_MAGIC 0xD4
#define MST_CONNECTX_WA_MAGIC 0xD5
#define MST_VPD_MAGIC 0xD6

#define PCICONF_MAX_BUFFER_SIZE 256
#define PCICONF_MAX_PAGES_SIZE 32
/****************************************************/
/* GET PARAMS */
#define MST_PARAMS _IOR(MST_PARAMS_MAGIC, 1, struct mst_params)

struct mst_params
{
    unsigned int domain;
    unsigned int bus;
    unsigned int slot;
    unsigned int func;
    unsigned int bar;
    unsigned int device;
    unsigned int vendor;
    unsigned int subsystem_device;
    unsigned int subsystem_vendor;
    unsigned int functional_vsc_offset;
};

typedef uint32_t u32;

/****************************************************/
/* BYTE ACCESS */
#define MST_READ4 _IOR(MST_BYTE_ACCESS_MAGIC, 1, struct mst_read4_st)

struct mst_read4_st
{
    unsigned int address_space;
    unsigned int offset;
    unsigned int data; /*OUT*/
};

#define MST_WRITE4 _IOW(MST_BYTE_ACCESS_MAGIC, 2, struct mst_write4_st)

struct mst_write4_st
{
    unsigned int address_space;
    unsigned int offset;
    unsigned int data;
};

#define PCICONF_READ4 MST_READ4
#define PCICONF_WRITE4 MST_WRITE4
#define PCIMEM_READ4 MST_READ4
#define PCIMEM_WRITE4 MST_WRITE4

/****************************************************/
/* BLOCK ACCESS */
#define PCIMEM_READ_BLOCK _IOR(MST_BLOCK_ACCESS_MAGIC, 1, struct mst_read_block_st)

struct mst_read_block_st
{
    unsigned int offset;
    unsigned int size;        /* in bytes */
    u32 data[MST_BLOCK_SIZE]; /* OUT */
};

#define PCIMEM_WRITE_BLOCK _IOW(MST_BLOCK_ACCESS_MAGIC, 2, struct mst_write_block_st)

struct mst_write_block_st
{
    unsigned int offset;
    unsigned int size; /* in bytes */
    u32 data[MST_BLOCK_SIZE];
};

#define PCICONF_READ4_BUFFER _IOR(MST_BLOCK_ACCESS_MAGIC, 3, struct mst_read4_buffer_st)
#define PCICONF_READ4_BUFFER_EX _IOR(MST_BLOCK_ACCESS_MAGIC, 3, struct mst_read4_buffer_st)
// We support backward compatibility.
// There is a known bug with PCICONF_READ4_BUFFER ioctl and data may be corrupted.
#define PCICONF_READ4_BUFFER_BC _IOR(MST_BLOCK_ACCESS_MAGIC, 3, struct mst_read4_st)
struct mst_read4_buffer_st
{
    unsigned int address_space;
    unsigned int offset;
    int size;
    unsigned int data[PCICONF_MAX_BUFFER_SIZE / 4]; /*OUT*/
};

#define PCICONF_WRITE4_BUFFER _IOW(MST_BLOCK_ACCESS_MAGIC, 4, struct mst_write4_buffer_st)
struct mst_write4_buffer_st
{
    unsigned int address_space;
    unsigned int offset;
    int size;
    unsigned int data[PCICONF_MAX_BUFFER_SIZE / 4]; /*IN*/
};
/****************************************************/
/*
 * INIT / STOP Conf Access
 * Used to change conf registers on the fly,
 * by default we set the conf register to default values
 */
#define PCICONF_INIT _IOC(_IOC_NONE, MST_PCICONF_MAGIC, 1, sizeof(struct mst_pciconf_init_st))

struct mst_pciconf_init_st
{
    unsigned int domain;
    unsigned int bus;
    unsigned int devfn;
    /* Byte offsets in configuration space */
    unsigned int addr_reg;
    unsigned int data_reg;
};

#define PCICONF_STOP _IOC(_IOC_NONE, MST_PCICONF_MAGIC, 2, 0)

/****************************************************/
/*
 * INIT / STOP Memory Access
 * Used to change bar number and map the new bar on the fly,
 * by default we set and map bar to default bar number per device
 */
#define PCIMEM_INIT _IOC(_IOC_NONE, MST_PCIMEM_MAGIC, 1, sizeof(struct mst_mem_init_st))

struct mst_mem_init_st
{
    unsigned int bar;
};

#define PCIMEM_STOP _IOC(_IOC_NONE, MST_PCIMEM_MAGIC, 2, 0)

/****************************************************/
/* CONNECTX ORDERING WA */
#define CONNECTX_WA_BASE 0xf0384 /* SEM BASE ADDR. SEM 0xf0380 is reserved for external tools usage. */
#define CONNECTX_WA_SIZE 3       /* Size in entries */

#define PCI_CONNECTX_WA _IOR(MST_CONNECTX_WA_MAGIC, 1, u_int32_t)

struct mst_connectx_wa
{
    u32 connectx_wa_slot_p1; /* connectx used slot plus 1. zero means unused */
};

/****************************************************/
/* VPD ACCESS */
#define PCICONF_VPD_READ4 _IOR(MST_VPD_MAGIC, 1, struct mst_vpd_read4_st)
struct mst_vpd_read4_st
{
    unsigned int offset;  /* IN - must be aligned to DWORD */
    unsigned int timeout; /* IN - timeout in milliseconds or zero for default timeout */
    u32 data;             /* OUT */
};

#define PCICONF_VPD_WRITE4 _IOW(MST_VPD_MAGIC, 2, struct mst_vpd_write4_st)
struct mst_vpd_write4_st
{
    unsigned int offset;  /* IN - must be aligned to DWORD */
    unsigned int timeout; /* IN - timeout in milliseconds or zero for default timeout */
    u32 data;             /* IN */
};

#define PCICONF_GET_DMA_PAGES _IOR(MST_PCICONF_MAGIC, 13, struct page_info_st)
#define PCICONF_RELEASE_DMA_PAGES _IOR(MST_PCICONF_MAGIC, 14, struct page_info_st)

struct page_address_st
{
    u_int64_t dma_address;
    u_int64_t virtual_address;
};

struct page_info_st
{
    unsigned int page_amount;
    unsigned long page_pointer_start;
    struct page_address_st page_address_array[PCICONF_MAX_PAGES_SIZE];
};

#define PCICONF_READ_DWORD_FROM_CONFIG_SPACE _IOR(MST_PCICONF_MAGIC, 15, struct read_dword_from_config_space)
struct read_dword_from_config_space
{
    unsigned int offset;
    unsigned int data;
};

#define PCICONF_HOT_RESET _IOR(MST_PCICONF_MAGIC, 16, struct hot_reset_pcie_switch)

struct dbdf
{
    int domain;
    int bus;
    int device;
    int function;
};

struct hot_reset_pcie_switch
{
    struct dbdf device_1;
    struct dbdf device_2;
    bool in_parallel;
};

#endif /* _MST_H_ */
