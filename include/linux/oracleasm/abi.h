/*
 * NAME
 *	abi.h - ASM library userspace to kernelspace ABI.
 *
 * AUTHOR
 * 	Joel Becker <joel.becker@oracle.com>
 *
 * DESCRIPTION
 * 	This file describes the ABI used by the Oracle Automatic
 * 	Storage Management library to communicate with the associated
 * 	kernel driver.
 *
 * MODIFIED   (YYYY/MM/DD)
 *      2004/08/19 - Joel Becker <joel.becker@oracle.com>
 *      	Start working on the V2 ABI.
 *      2004/01/02 - Joel Becker <joel.becker@oracle.com>
 *              Initial LGPL header.
 *
 * Copyright (c) 2002-2004 Oracle Corporation.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *      - Neither the name of Oracle Corporation nor the names of its
 *        contributors may be used to endorse or promote products
 *        derived from this software without specific prior written
 *        permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Alternatively, the contents of this file may be used under the terms
 * of the GNU General Public License version 2 (the "GPL") distributed
 * with this softwarere in the file COPYING.GPL, in which case the
 * provisions of the GPL are applicable instead of the above. 
 *
 * If you wish to allow the use of your version of this file only under
 * the terms of the GPL and not to allow others to use your version of
 * this file under the license above, indicate your decision by deleting
 * the provisions above and replace them with the notice and other
 * provisions required by the GPL.  If you do not delete the provisions
 * above, a recipient may use your version of this file under the above
 * license or the GPL.
 */


/*
 * This file is internal to the implementation of the Oracle ASM
 * library on Linux.  This file presumes the definitions in asmlib.h
 * and oratypes.h
 */


#ifndef _ORACLEASM_ABI_H
#define _ORACLEASM_ABI_H


/*
 * Defines
 */

#define ASM_ABI_VERSION_V2		2UL
#define ASM_ABI_VERSION			ASM_ABI_VERSION_V2

enum asm_abi_magic {
	ASMFS_MAGIC			= 0x958459f6,
	ASM_ABI_MAGIC			= 0x41534DU,
	ASM_INTEGRITY_MAGIC		= 0x444958,
	ASM_INTEGRITY_TAG		= 0x4F52,
};

/*
 * Enums
 */

enum asm_operation_types
{
	ASMOP_NONE = 0,
	ASMOP_QUERY_VERSION,
	ASMOP_GET_IID,
	ASMOP_CHECK_IID,
	ASMOP_QUERY_DISK,
#define ASM_LAST_TRANSACTION_OP ASMOP_QUERY_DISK
	ASMOP_OPEN_DISK,
	ASMOP_CLOSE_DISK,
	ASMOP_IO32,
	ASMOP_IO64,
	ASM_NUM_OPERATIONS  /* This must always be last */
};

/* Users of the commands should always use ASMOP_IO */
#if BITS_PER_LONG == 32
# define ASMOP_IO ASMOP_IO32
#else
# if BITS_PER_LONG == 64
#  define ASMOP_IO ASMOP_IO64
# else
#  error Invalid number of bits (BITS_PER_LONG)
# endif  /* BITS_PER_LONG == 64 */
#endif  /* BITS_PER_LONG == 32 */

/*
 * Structures
 */

struct oracleasm_abi_info
{
/*00*/	__u32				ai_magic;	/* ASM_ABI_MAGIC */
	__u16				ai_version;	/* ABI version */
	__u16				ai_type;	/* Type of operation */
	__u32				ai_size;	/* Size of passed struct */
	__u32				ai_status;	/* Did it succeed */
/*10*/	
};

/*
 * These are __u64 to handle 32<->64 pointer stuff.
 */
struct oracleasm_io_v2
{
/*00*/	struct oracleasm_abi_info	io_abi;		/* ABI info */
/*10*/	__u64				io_handle;	/* asm_ctx */
	__u64				io_requests;	/* asm_ioc ** */
/*20*/	__u64				io_waitreqs;	/* asm_ioc ** */
	__u64				io_completions;	/* asm_ioc ** */
/*30*/	__u64				io_timeout;	/* struct timespec * */
	__u64				io_statusp;	/* __u32 * */
/*40*/	__u32				io_reqlen;
	__u32				io_waitlen;
	__u32				io_complen;
	__u32				io_pad1;	/* Pad to 64bit aligned size */
/*50*/
};

struct oracleasm_integrity_v2
{
	__u32				it_magic;
	__u8				it_format;
	__u8				it_flags;
	__u16				it_bytes;
	__u64				it_buf;
};

enum oracleasm_integrity_handling_flags {
	ASM_IFLAG_REMAPPED		= 1,	/* PI has been remapped */
	ASM_IFLAG_IP_CHECKSUM		= 2,	/* IP checksum instead of CRC */
};

struct oracleasm_query_disk_v2
{
/*00*/	struct oracleasm_abi_info	qd_abi;
/*10*/	__u32				qd_fd;
	__u32				qd_max_sectors;
	__u32				qd_hardsect_size;
	__u32				qd_feature;
/*20*/
};

enum oracleasm_feature_integrity {
	ASM_IMODE_NONE			= 0,	/* 00: No data integrity */
	ASM_IMODE_512_512		= 1,	/* 01: lbs = 512, asmbs = 512 */
	ASM_IMODE_512_4K		= 2,	/* 02: lbs = 512, asmbs = 4KB */
	ASM_IMODE_4K_4K			= 3,	/* 03: lbs = 4KB, asmbs = 4KB */
	ASM_IMODE_MASK			= 3,	/* Interleaving mode mask */
	ASM_IFMT_IP_CHECKSUM		= 4,	/* 0: T10 CRC, 1: IP checksum */
	ASM_INTEGRITY_HANDLE_MASK	= 7,	/* Integrity handle mask */
	ASM_INTEGRITY_QDF_MASK		= 0xff, /* Querydisk feature mask */
};

struct oracleasm_open_disk_v2
{
/*00*/	struct oracleasm_abi_info	od_abi;
/*10*/	__u32				od_fd;
	__u32				od_pad1;
	__u64				od_handle;
/*20*/	
};

struct oracleasm_close_disk_v2
{
/*00*/	struct oracleasm_abi_info	cd_abi;
/*10*/	__u64				cd_handle;
/*18*/
};

struct oracleasm_get_iid_v2
{
/*00*/	struct oracleasm_abi_info	gi_abi;
/*10*/	__u64				gi_iid;
/*18*/
};

#endif  /* _ORACLEASM_ABI_H */

