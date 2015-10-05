/*
 * NAME
 *	error.h - Oracle ASM library internal error header.
 *
 * AUTHOR
 * 	Joel Becker <joel.becker@oracle.com>
 *
 * DESCRIPTION
 *      This file contains the internal error code mappings for the
 *      Oracle Automatic Storage Managment userspace library.
 *
 * MODIFIED   (YYYY/MM/DD)
 *      2004/01/02 - Joel Becker <joel.becker@oracle.com>
 *              Initial LGPL header.
 *      2005/09/14 - Joel Becker <joel.becker@oracle.com>
 *              Make NODEV a nonfatal error.
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



#ifndef _ORACLEASM_ERROR_H
#define _ORACLEASM_ERROR_H

/*
 * Error codes.  Positive means runtime error, negative means software
 * error.  See asmlib.c for the description strings.
 */
enum _ASMErrors
{
    ASM_ERR_INSTALL     = -5,   /* Driver not installed */
    ASM_ERR_FAULT       = -4,   /* Invalid address */
    ASM_ERR_NODEV_OLD   = -3,   /* Old invalid device */
    ASM_ERR_BADIID      = -2,   /* Invalid IID */
    ASM_ERR_INVAL       = -1,   /* Invalid argument */
    ASM_ERR_NONE        = 0,    /* No error */
    ASM_ERR_PERM	= 1,	/* Operation not permitted */
    ASM_ERR_NOMEM	= 2,	/* Out of memory */
    ASM_ERR_IO          = 3,    /* I/O error */
    ASM_ERR_DSCVR       = 4,    /* Bad discovery string */
    ASM_ERR_NODEV       = 5,    /* Invalid device */
    ASM_ERR_INTEGRITY	= 6,	/* Data integrity error */
};

#endif  /* _ORACLEASM_ERROR_H */
