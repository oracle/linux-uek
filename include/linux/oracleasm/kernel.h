/*
 * NAME
 *	kernel.h - Kernel definitions for ASM library structures.
 *
 * AUTHOR
 * 	Joel Becker <joel.becker@oracle.com>
 *
 * DESCRIPTION
 *      This file contains the kernel definitions of various structures
 *      used by the Oracle Automatic Storage Managment userspace
 *      library.
 *
 * MODIFIED   (YYYY/MM/DD)
 *      2004/01/02 - Joel Becker <joel.becker@oracle.com>
 *              Initial LGPL header.
 *
 * Copyright (c) 2002-2004 Oracle Corporation.  All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License, version 2 as published by the Free Software Foundation.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have recieved a copy of the GNU General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

/*
 * This file describes structures that are private to the Linux kernel
 * module for asmlib.  See asmlib.h for field descriptions.
 *
 * THESE STRUCTURS MUST BE ABI COMPATIBLE WITH THE asmlib.h
 * DEFINITION!!!
*/


#ifndef _ORACLEASM_KERNEL_H
#define _ORACLEASM_KERNEL_H

#ifdef __KERNEL__

/*
 * ASM Defines
 */

/* i/o status bits */
#define ASM_BUSY         0x0001 /* too busy to process */
#define ASM_SUBMITTED    0x0002 /* request submitted for processing */
#define ASM_COMPLETED    0x0004 /* request completed */
#define ASM_FREE         0x0008 /* memory is free */
#define ASM_CANCELLED    0x0010 /* request cancelled */
#define ASM_ERROR        0x0020 /* request failed with an error */
#define ASM_WARN         0x0040 /* a future request may fail */
#define ASM_PARTIAL      0x0080 /* only a partial transfer */
#define ASM_BADKEY       0x0100 /* disk key mismatch */
#define ASM_BAD_DATA     0x0200 /* I/O was not allowed by the fence key */
#define ASM_LOCAL_ERROR  0x0400 /* error is local to this host */

/* special timeout values */
#define    ASM_NOWAIT    0x0            /* return as soon as possible */
#define    ASM_WAIT      0xffffffff     /* never timeout */

/* status flags indicating reasons for return */
#define    ASM_IO_POSTED    0x1         /* posted to run by OS */
#define    ASM_IO_TIMEOUT   0x2         /* timeout */
#define    ASM_IO_WAITED    0x4         /* wait list complete */
#define    ASM_IO_FULL      0x8         /* completion list full */
#define    ASM_IO_IDLE      0x10        /* no more active I/O */

/* I/O operations */
#define ASM_NOOP        0x00    /* no-op to key check or pass a hint */
#define ASM_READ        0x01    /* Read data from disk */
#define ASM_WRITE       0x02    /* write data to disk */
/* 0x03 is unused */
#define ASM_COPY        0x03    /* copy data from one location to another */
#define ASM_GETKEY      0x04    /* get value of one or more disk keys */
#define ASM_SETKEY      0x05    /* set value of one or more disk keys */



/*
 * Disk/Fence Keys - (unused as yet)
 */
typedef struct _asm_check asm_check;
struct _asm_check
{
	__u32		key_num_asm_check;
	__u32		spare1_asm_check;
	__u64		key_mask_asm_check;
	__u64		key_value_asm_check;
	__u64		error_key_asm_check;
};


/*
 * I/O control block
 */
typedef struct _asm_ioc32 asm_ioc32;
struct _asm_ioc32 {
	__u32		ccount_asm_ioc;
	__s32		error_asm_ioc;
	__s32		warn_asm_ioc;
	__u32		elaptime_asm_ioc;
	__u16		status_asm_ioc;
	__u16		flags_asm_ioc;
	__u8		operation_asm_ioc;
	__u8		priority_asm_ioc;
	__u16		hint_asm_ioc;
	__u64   	disk_asm_ioc;
	__u64		first_asm_ioc;
	__u32		rcount_asm_ioc;
	__u16		xor_asm_ioc;
	__u16		abs_asm_ioc;
	__u32		abn_offset_asm_ioc;
	__u32		abn_asm_ioc;
	__u32		abn_mask_asm_ioc;
	__u32		spare1_asm_ioc;
	__u64		tag_asm_ioc;
	__u64		reserved_asm_ioc;
	__u32		buffer_asm_ioc;
	__u32		check_asm_ioc;
};

#if BITS_PER_LONG == 32
# define asm_ioc asm_ioc32
#else
# if BITS_PER_LONG == 64
#  define asm_ioc asm_ioc64
typedef struct _asm_ioc64 asm_ioc64;
struct _asm_ioc64 {
	__u32		ccount_asm_ioc;
	__s32		error_asm_ioc;
	__s32		warn_asm_ioc;
	__u32		elaptime_asm_ioc;
	__u16		status_asm_ioc;
	__u16		flags_asm_ioc;
	__u8		operation_asm_ioc;
	__u8		priority_asm_ioc;
	__u16		hint_asm_ioc;
	__u64   	disk_asm_ioc;
	__u64		first_asm_ioc;
	__u32		rcount_asm_ioc;
	__u16		xor_asm_ioc;
	__u16		abs_asm_ioc;
	__u32		abn_offset_asm_ioc;
	__u32		abn_asm_ioc;
	__u32		abn_mask_asm_ioc;
	__u32		spare1_asm_ioc;
	__u64		tag_asm_ioc;
	__u64		reserved_asm_ioc;
	__u64		buffer_asm_ioc;
	__u64		check_asm_ioc;
};
# else
#  error Invalid bits per long (BITS_PER_LONG)
# endif  /* BITS_PER_LONG == 64 */
#endif  /* BITS_PER_LONG == 32 */

#endif  /* __KERNEL__ */

#endif  /* _ORACLEASM_KERNEL */


