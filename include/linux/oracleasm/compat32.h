/*
 * NAME
 *	compat32.h - ASM library 32<->64bit compatibilty support.
 *
 * AUTHOR
 * 	Joel Becker <joel.becker@oracle.com>
 *
 * DESCRIPTION
 *      This file contains helpers for supporting 32bit, 64bit, and 
 *      32bit-on-64bit implementations of the Oracle Automatic Storage
 *      Management library.
 *
 * MODIFIED   (YYYY/MM/DD)
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
 * This file is an internal header to the asmlib implementation on
 * Linux.  This file presumes the definitions in asmlib.h and
 * oratypes.h.
 */


#ifndef _ORACLEASM_COMPAT32_H
#define _ORACLEASM_COMPAT32_H

#include <linux/version.h>

/*
 * This is ugly.  SIZEOF_UNSIGNED_LONG comes from autoconf.
 * Do you have a better way?  I chose not to hand-cook an autoconf
 * test because I'm lazy and it doesn't seem significantly better.
 */
#ifndef BITS_PER_LONG
# if SIZEOF_UNSIGNED_LONG == 4
#  define BITS_PER_LONG 32
# else
#  if SIZEOF_UNSIGNED_LONG == 8
#   define BITS_PER_LONG 64
#  else
#   error Unknown size of unsigned long (SIZEOF_UNSIGNED_LONG)
#  endif  /* SIZEOF_UNSIGNED_LONG == 8 */
# endif  /* SIZEOF_UNSIGNED_LONG == 4 */
#endif  /* BITS_PER_LONG */

/*
 * Handle the ID sizes
 */
#define HIGH_UB4(_ub8)          ((unsigned long)(((_ub8) >> 32) & 0xFFFFFFFFULL))
#define LOW_UB4(_ub8)           ((unsigned long)((_ub8) & 0xFFFFFFFFULL))

#endif  /* _ORACLEASM_COMPAT32_H */

