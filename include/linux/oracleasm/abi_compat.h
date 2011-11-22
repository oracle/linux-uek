/*
 * NAME
 *	abi_compat.h - Older ASM library userspace to kernelspace ABIs.
 *
 * AUTHOR
 * 	Joel Becker <joel.becker@oracle.com>
 *
 * DESCRIPTION
 * 	This file describes the older ABIs used by the Oracle Automatic
 * 	Storage Management library to communicate with the associated
 * 	kernel driver.
 *
 * MODIFIED   (YYYY/MM/DD)
 *      2004/08/19 - Joel Becker <joel.becker@oracle.com>
 *      	Compat version.
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


#ifndef _ORACLEASM_ABI_COMPAT_H
#define _ORACLEASM_ABI_COMPAT_H


/*
 * Structures
 */

/*
 * These are __u64 to handle 32<->64 pointer stuff.
 */
struct oracleasm_io_v1
{
    __u64               io_handle;	/* asm_ctx */
    __u64               io_requests;	/* asm_ioc ** */
    __u64               io_waitreqs;	/* asm_ioc ** */
    __u64               io_completions;	/* asm_ioc ** */
    __u64               io_timeout;	/* struct timespec * */
    __u64               io_statusp;	/* __u32 * */
    __u32               io_reqlen;
    __u32               io_waitlen;
    __u32               io_complen;
    __u32               io_pad1;	/* Pad to 64bit aligned size */
};

struct oracleasm_disk_query_v1
{
    __u64 dq_rdev;
    __u64 dq_maxio;  /* gcc padding is lame */
};

#define ASM_ABI_VERSION_V1	1UL
struct oracleasm_get_iid_v1
{
    __u64 gi_iid;
    __u64 gi_version;  /* gcc padding is lame */
};



/*
 * ioctls
 */
#define ASM_IOCTL_BASE          0xFD

/* ioctls on /dev/oracleasm */
#define ASMIOC_GETIID           _IOR(ASM_IOCTL_BASE, 0, struct oracleasm_get_iid_v1)
#define ASMIOC_CHECKIID         _IOWR(ASM_IOCTL_BASE, 1, struct oracleasm_get_iid_v1)

/* ioctls on /dev/oracleasm/<iid> */
#define ASMIOC_QUERYDISK        _IOWR(ASM_IOCTL_BASE, 2, struct oracleasm_disk_query_v1)
#define ASMIOC_OPENDISK		_IOWR(ASM_IOCTL_BASE, 3, struct oracleasm_disk_query_v1)
#define ASMIOC_CLOSEDISK	_IOW(ASM_IOCTL_BASE, 4, struct oracleasm_disk_query_v1)


/*
 * We have separate ioctls so we *know* when the pointers are 32bit
 * or 64bit.
 * 
 * All userspace callers should use ASMIOC_IODISK.
 */
#define ASMIOC_IODISK32         _IOWR(ASM_IOCTL_BASE, 5, struct oracleasm_io_v1)

#if BITS_PER_LONG == 32
# define ASMIOC_IODISK ASMIOC_IODISK32
#else
# if BITS_PER_LONG == 64
#  define ASMIOC_IODISK64         _IOWR(ASM_IOCTL_BASE, 6, struct oracleasm_io_v1)
#  define ASMIOC_IODISK ASMIOC_IODISK64
# else
#  error Invalid number of bits (BITS_PER_LONG)
# endif  /* BITS_PER_LONG == 64 */
#endif  /* BITS_PER_LONG == 32 */


/* ioctl for testing */
#define ASMIOC_DUMP             _IO(ASM_IOCTL_BASE, 16)


#endif  /* _ORACLEASM_ABI_COMPAT_H */

