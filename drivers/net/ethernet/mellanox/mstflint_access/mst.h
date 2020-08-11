/* SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB */
/*
 * Copyright (c) 2018 Mellanox Technologies. All rights reserved.
 */

#ifndef _MST_H_
#define _MST_H_

#include <linux/ioctl.h>


/****************************************************/
#define MST_MEMORY_SIZE				(1024*1024)
#define MST_BLOCK_SIZE				64

#define MST_PARAMS_MAGIC			0xD0
#define MST_BYTE_ACCESS_MAGIC		0xD1
#define MST_BLOCK_ACCESS_MAGIC		0xD2
#define MST_PCICONF_MAGIC			0xD3
#define MST_PCIMEM_MAGIC			0xD4
#define MST_CONNECTX_WA_MAGIC		0xD5
#define MST_VPD_MAGIC				0xD6


#define PCICONF_MAX_BUFFER_SIZE     256
/****************************************************/
/* GET PARAMS */
#define MST_PARAMS _IOR(MST_PARAMS_MAGIC, 1, struct mst_params)

struct mst_params {
	unsigned int domain;
	unsigned int bus;
	unsigned int slot;
	unsigned int func;
	unsigned int bar;
	unsigned int device;
	unsigned int vendor;
	unsigned int subsystem_device;
	unsigned int subsystem_vendor;
	unsigned int vendor_specific_cap;
};

typedef uint32_t u32;

/****************************************************/
/* BYTE ACCESS */
#define MST_READ4 _IOR(MST_BYTE_ACCESS_MAGIC, 1, struct mst_read4_st)

struct mst_read4_st {
	unsigned int address_space;
	unsigned int offset;
	unsigned int data; /*OUT*/
};


#define MST_WRITE4 _IOW(MST_BYTE_ACCESS_MAGIC, 2, struct mst_write4_st)

struct mst_write4_st {
	unsigned int address_space;
	unsigned int offset;
	unsigned int data;
};


#define PCICONF_READ4	MST_READ4
#define PCICONF_WRITE4	MST_WRITE4
#define PCIMEM_READ4	MST_READ4
#define PCIMEM_WRITE4	MST_WRITE4


/****************************************************/
/* BLOCK ACCESS */
#define PCIMEM_READ_BLOCK _IOR(MST_BLOCK_ACCESS_MAGIC, 1, struct mst_read_block_st)

struct mst_read_block_st {
	unsigned int offset;
	unsigned int size;			/* in bytes */
	u32 data[MST_BLOCK_SIZE];		/* OUT */
};


#define PCIMEM_WRITE_BLOCK _IOW(MST_BLOCK_ACCESS_MAGIC, 2, struct mst_write_block_st)

struct mst_write_block_st {
	unsigned int offset;
	unsigned int size;			/* in bytes */
	u32 data[MST_BLOCK_SIZE];
};


#define PCICONF_READ4_BUFFER  _IOR(MST_BLOCK_ACCESS_MAGIC, 3, struct mst_read4_buffer_st)
#define PCICONF_READ4_BUFFER_EX  _IOR(MST_BLOCK_ACCESS_MAGIC, 3, struct mst_read4_buffer_st)
struct mst_read4_buffer_st {
	unsigned int address_space;
	unsigned int offset;
	int size;
	unsigned int data[PCICONF_MAX_BUFFER_SIZE/4]; /*OUT*/
};

#define PCICONF_WRITE4_BUFFER _IOW(MST_BLOCK_ACCESS_MAGIC, 4, struct mst_write4_buffer_st)
struct mst_write4_buffer_st {
	unsigned int address_space;
	unsigned int offset;
	int size;
	unsigned int data[PCICONF_MAX_BUFFER_SIZE/4]; /*IN*/
};
/****************************************************/
/*
 * INIT / STOP Conf Access
 * Used to change conf registers on the fly,
 * by default we set the conf register to default values
 */
#define PCICONF_INIT _IOC(_IOC_NONE, MST_PCICONF_MAGIC, 1, \
			  sizeof(struct mst_pciconf_init_st))

struct mst_pciconf_init_st {
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
#define PCIMEM_INIT _IOC(_IOC_NONE, MST_PCIMEM_MAGIC, 1, \
			 sizeof(struct mst_mem_init_st))

struct mst_mem_init_st {
	unsigned int bar;
};


#define PCIMEM_STOP _IOC(_IOC_NONE, MST_PCIMEM_MAGIC, 2, 0)


/****************************************************/
/* CONNECTX ORDERING WA */
#define CONNECTX_WA_BASE 0xf0384	/* SEM BASE ADDR. SEM 0xf0380 is reserved for external tools usage. */
#define CONNECTX_WA_SIZE 3			/* Size in entries */

#define PCI_CONNECTX_WA _IOR(MST_CONNECTX_WA_MAGIC, 1, u_int32_t)

struct mst_connectx_wa {
	u32 connectx_wa_slot_p1;	/* connectx used slot plus 1. zero means unused */
};


/****************************************************/
/* VPD ACCESS */
#define PCICONF_VPD_READ4 _IOR(MST_VPD_MAGIC, 1, struct mst_vpd_read4_st)
struct mst_vpd_read4_st {
	unsigned int offset;	/* IN - must be aligned to DWORD */
	unsigned int timeout;	/* IN - timeout in milliseconds or zero for default timeout */
	u32 data;				/* OUT */

};

#define PCICONF_VPD_WRITE4 _IOW(MST_VPD_MAGIC, 2, struct mst_vpd_write4_st)
struct mst_vpd_write4_st {
	unsigned int offset;	/* IN - must be aligned to DWORD */
	unsigned int timeout;	/* IN - timeout in milliseconds or zero for default timeout */
	u32 data;				/* IN */
};


#endif /* _MST_H_ */
